pub mod anytls;
pub mod http_proxy;
pub mod socks5;
pub mod ss;
pub mod trojan;
pub mod vless;
pub mod ws_stream;

use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::UdpSocket,
    sync::OnceCell,
};
use url::Url;

use crate::{
    addr::{HostName, TargetAddr},
    dns::FakeIpDnsEngine,
    platform::socket_protect::protected_udp_bind,
};

pub trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send + Sync {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + Sync> AsyncStream for T {}

pub type BoxedStream = Box<dyn AsyncStream>;

/// Persistent bidirectional UDP NAT session over an outbound proxy or direct socket.
/// Preserves NAT port bindings and avoids per-datagram handshakes for multi-packet flows (QUIC/HTTP3, WebRTC, gaming).
#[async_trait]
pub trait OutboundUdpSession: Send + Sync {
    async fn send_to(&self, payload: &[u8], target: &TargetAddr) -> io::Result<()>;
    async fn recv_from(&self) -> io::Result<(Vec<u8>, TargetAddr)>;
}

#[async_trait]
pub trait OutboundHandler: std::any::Any + Send + Sync {
    fn name(&self) -> &str;
    fn protocol(&self) -> &'static str;
    fn exit_category(&self) -> &'static str {
        "PROXY"
    }
    fn remote_endpoint(&self, target: &TargetAddr) -> String {
        target.to_string()
    }
    fn udp_supported(&self) -> bool {
        false
    }

    /// Evict cached TCP/TLS connection pools bound to stale interfaces on network switch.
    /// Returns the number of pooled/multiplexed sessions closed.
    fn on_network_change(&self) -> usize {
        0
    }

    /// Toggle battery-saving low-power mode (e.g. Android screen-off / Doze) on pooled session reapers.
    fn set_low_power_mode(&self, _enabled: bool) {}

    /// Proactively pre-warm proxy server DNS and/or multiplexed session pools (`target_sessions`).
    async fn preconnect(&self, _target_sessions: usize) -> io::Result<()> {
        Ok(())
    }

    async fn connect_tcp(&self, target: &TargetAddr) -> io::Result<BoxedStream>;

    /// Open a stateful multi-datagram UDP session over this outbound.
    async fn open_udp_session(&self) -> io::Result<Box<dyn OutboundUdpSession>> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!(
                "stateful UDP session not supported on outbound '{}'",
                self.name()
            ),
        ))
    }

    /// Exchange a single UDP datagram through this outbound (used by one-shot probes & tests).
    async fn exchange_udp(
        &self,
        target: &TargetAddr,
        payload: &[u8],
        timeout: Duration,
    ) -> io::Result<Vec<u8>> {
        let sess = self.open_udp_session().await?;
        sess.send_to(payload, target).await?;
        let (resp, _src) = tokio::time::timeout(timeout, sess.recv_from())
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "UDP exchange timed out"))??;
        Ok(resp)
    }

    /// Perform an end-to-end HTTP HEAD latency test through this outbound proxy tunnel.
    /// Defaults to full-handshake measurement (`unified_delay = false`); `Router` invokes
    /// `latency_test_with_mode(..., self.unified_delay())`.
    async fn latency_test(&self, test_url: &str, timeout: Duration) -> io::Result<u64> {
        self.latency_test_with_mode(test_url, timeout, false).await
    }

    /// Perform an HTTP HEAD latency test through this outbound proxy tunnel.
    /// When `unified_delay` is `true` (Mihomo `unified-delay` semantics), establishes the
    /// proxy/TLS tunnel and warms end-to-end keep-alive first so cold DNS, TCP, TLS, and
    /// auth handshakes do not skew node RTT comparisons.
    async fn latency_test_with_mode(
        &self,
        test_url: &str,
        timeout: Duration,
        unified_delay: bool,
    ) -> io::Result<u64> {
        let parsed = Url::parse(test_url).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid test URL: {e}"),
            )
        })?;
        let host = parsed.host_str().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "missing host in test URL")
        })?;
        let is_https = parsed.scheme() == "https";
        let port = parsed.port().unwrap_or(if is_https { 443 } else { 80 });
        let path = match parsed.query() {
            Some(q) => format!("{}?{q}", parsed.path()),
            None => {
                let p = parsed.path();
                if p.is_empty() {
                    "/".to_string()
                } else {
                    p.to_string()
                }
            }
        };
        let target = TargetAddr::new_domain(host, port)?;

        let connect_started = Instant::now();
        tokio::time::timeout(timeout, async {
            let mut stream = self.connect_tcp(&target).await?;
            if is_https {
                let tls_cfg = crate::crypto::tls::build_tls_client_config(false, &[], &[])?;
                let sni = crate::crypto::tls::parse_server_name(host)?;
                let connector = tokio_rustls::TlsConnector::from(tls_cfg);
                let mut tls_stream = connector.connect(sni, stream).await?;
                measure_http_head_latency(
                    &mut tls_stream,
                    host,
                    &path,
                    unified_delay,
                    connect_started,
                )
                .await
            } else {
                measure_http_head_latency(&mut stream, host, &path, unified_delay, connect_started)
                    .await
            }
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "latency probe timed out"))?
    }
}

async fn measure_http_head_latency<S>(
    stream: &mut S,
    host: &str,
    path: &str,
    unified_delay: bool,
    connect_started: Instant,
) -> io::Result<u64>
where
    S: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    if !unified_delay {
        let req = format!(
            "HEAD {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: rust-clash/{}\r\nConnection: close\r\n\r\n",
            env!("CARGO_PKG_VERSION")
        );
        stream.write_all(req.as_bytes()).await?;
        stream.flush().await?;
        let mut resp = [0u8; 32];
        let n = stream.read(&mut resp).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "empty response during HTTP latency probe",
            ));
        }
        return Ok(connect_started.elapsed().as_millis().max(1) as u64);
    }

    // `unified-delay: true` (Mihomo-compatible):
    // 1. Warmup HEAD #1 over keep-alive (triggers lazy proxy->origin dial if not yet connected)
    let req1 = format!(
        "HEAD {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: rust-clash/{}\r\nConnection: keep-alive\r\n\r\n",
        env!("CARGO_PKG_VERSION")
    );
    let t1_started = Instant::now();
    stream.write_all(req1.as_bytes()).await?;
    stream.flush().await?;

    let mut hdr_buf = Vec::with_capacity(512);
    let mut chunk = [0u8; 512];
    let mut t1_ms: Option<u64> = None;
    let mut hdr_end: Option<usize> = None;
    while hdr_buf.len() < 8192 {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        if t1_ms.is_none() {
            t1_ms = Some(t1_started.elapsed().as_millis().max(1) as u64);
        }
        hdr_buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = hdr_buf.windows(4).position(|w| w == b"\r\n\r\n") {
            hdr_end = Some(pos);
            break;
        }
    }

    let Some(first_rtt_ms) = t1_ms else {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "empty response during unified-delay probe",
        ));
    };

    let can_reuse_keepalive = if let Some(pos) = hdr_end
        && pos + 4 == hdr_buf.len()
        && let Ok(head_text) = std::str::from_utf8(&hdr_buf[..pos])
    {
        let lower = head_text.to_ascii_lowercase();
        lower.starts_with("http/1.1 ") && !lower.contains("connection: close")
    } else {
        false
    };

    if !can_reuse_keepalive {
        return Ok(first_rtt_ms);
    }

    // 2. Measured HEAD #2 over the established end-to-end tunnel (pure 1-RTT payload latency)
    let req2 = format!(
        "HEAD {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: rust-clash/{}\r\nConnection: close\r\n\r\n",
        env!("CARGO_PKG_VERSION")
    );
    let t2_started = Instant::now();
    if stream.write_all(req2.as_bytes()).await.is_ok() && stream.flush().await.is_ok() {
        let mut resp2 = [0u8; 32];
        if let Ok(n) = stream.read(&mut resp2).await
            && n > 0
        {
            return Ok(t2_started.elapsed().as_millis().max(1) as u64);
        }
    }

    Ok(first_rtt_ms)
}

/// Built-in `DIRECT` outbound connecting straight to the target host/IP via `SocketProtector`.
/// When paired with a `FakeIpDnsEngine`, resolves domains through configured upstream
/// `direct-nameserver` / `nameserver`s and rejects any `198.18.0.0/15` Fake-IP so `DIRECT` can never self-loop.
#[derive(Clone)]
pub struct DirectOutbound {
    name: String,
    dns: Option<Arc<FakeIpDnsEngine>>,
}

impl DirectOutbound {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            dns: None,
        }
    }

    pub fn with_dns(name: impl Into<String>, dns: Arc<FakeIpDnsEngine>) -> Self {
        Self {
            name: name.into(),
            dns: Some(dns),
        }
    }

    pub async fn resolve_target_addrs(&self, target: &TargetAddr) -> io::Result<Vec<SocketAddr>> {
        match &target.host {
            HostName::Ip(ip) => {
                if let Some(dns) = &self.dns
                    && dns.is_fake_ip(*ip)
                {
                    return Err(io::Error::new(
                        io::ErrorKind::HostUnreachable,
                        format!("refusing to dial Fake-IP {ip} via DIRECT outbound"),
                    ));
                }
                Ok(vec![SocketAddr::new(*ip, target.port)])
            }
            HostName::Domain(domain) => {
                if let Some(dns) = &self.dns {
                    let ips = dns
                        .resolve_direct_ips(domain)
                        .await
                        .map_err(|e| e.into_io())?;
                    return Ok(ips
                        .into_iter()
                        .map(|ip| SocketAddr::new(ip, target.port))
                        .collect());
                }
                let addrs =
                    crate::router::geodata::resolve_host_bypassing_fake_ip(domain, target.port)
                        .await
                        .map_err(|e| e.into_io())?
                        .into_iter()
                        .filter(|sa| !is_rfc2544_benchmark_ip(sa.ip()))
                        .collect::<Vec<_>>();
                if addrs.is_empty() {
                    return Err(io::Error::new(
                        io::ErrorKind::HostUnreachable,
                        format!("DNS lookup returned no usable addresses for '{domain}'"),
                    ));
                }
                Ok(addrs)
            }
        }
    }
}

struct DirectUdpSession {
    direct: DirectOutbound,
    sock_v4: OnceCell<Arc<UdpSocket>>,
    sock_v6: OnceCell<Arc<UdpSocket>>,
    ready_notify: tokio::sync::Notify,
}

impl DirectUdpSession {
    fn new(direct: DirectOutbound) -> Self {
        Self {
            direct,
            sock_v4: OnceCell::new(),
            sock_v6: OnceCell::new(),
            ready_notify: tokio::sync::Notify::new(),
        }
    }

    async fn socket_for(&self, remote: SocketAddr) -> io::Result<&Arc<UdpSocket>> {
        if remote.is_ipv4() {
            let created = self.sock_v4.get().is_none();
            let sock = self
                .sock_v4
                .get_or_try_init(|| async {
                    let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
                    let s = protected_udp_bind(bind, Some(remote))?;
                    Ok::<Arc<UdpSocket>, io::Error>(Arc::new(s))
                })
                .await?;
            if created {
                self.ready_notify.notify_waiters();
            }
            Ok(sock)
        } else {
            let created = self.sock_v6.get().is_none();
            let sock = self
                .sock_v6
                .get_or_try_init(|| async {
                    let bind = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0);
                    let s = protected_udp_bind(bind, Some(remote))?;
                    Ok::<Arc<UdpSocket>, io::Error>(Arc::new(s))
                })
                .await?;
            if created {
                self.ready_notify.notify_waiters();
            }
            Ok(sock)
        }
    }
}

#[async_trait]
impl OutboundUdpSession for DirectUdpSession {
    async fn send_to(&self, payload: &[u8], target: &TargetAddr) -> io::Result<()> {
        let remote = *self
            .direct
            .resolve_target_addrs(target)
            .await?
            .first()
            .ok_or_else(|| io::Error::new(io::ErrorKind::HostUnreachable, "DNS lookup empty"))?;
        let sock = self.socket_for(remote).await?;
        sock.send_to(payload, remote).await?;
        Ok(())
    }

    async fn recv_from(&self) -> io::Result<(Vec<u8>, TargetAddr)> {
        loop {
            let v4 = self.sock_v4.get().cloned();
            let v6 = self.sock_v6.get().cloned();
            match (v4, v6) {
                (Some(s4), Some(s6)) => {
                    let mut b4 = vec![0u8; 65535];
                    let mut b6 = vec![0u8; 65535];
                    tokio::select! {
                        res = s4.recv_from(&mut b4) => {
                            let (n, peer) = res?;
                            b4.truncate(n);
                            return Ok((b4, TargetAddr::from(peer)));
                        }
                        res = s6.recv_from(&mut b6) => {
                            let (n, peer) = res?;
                            b6.truncate(n);
                            return Ok((b6, TargetAddr::from(peer)));
                        }
                    }
                }
                (Some(s4), None) => {
                    let mut b4 = vec![0u8; 65535];
                    let notified = self.ready_notify.notified();
                    tokio::select! {
                        res = s4.recv_from(&mut b4) => {
                            let (n, peer) = res?;
                            b4.truncate(n);
                            return Ok((b4, TargetAddr::from(peer)));
                        }
                        _ = notified => continue,
                    }
                }
                (None, Some(s6)) => {
                    let mut b6 = vec![0u8; 65535];
                    let notified = self.ready_notify.notified();
                    tokio::select! {
                        res = s6.recv_from(&mut b6) => {
                            let (n, peer) = res?;
                            b6.truncate(n);
                            return Ok((b6, TargetAddr::from(peer)));
                        }
                        _ = notified => continue,
                    }
                }
                (None, None) => {
                    self.ready_notify.notified().await;
                }
            }
        }
    }
}

fn is_rfc2544_benchmark_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.octets()[0] == 198 && (v4.octets()[1] & 0xFE) == 18,
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .is_some_and(|v4| v4.octets()[0] == 198 && (v4.octets()[1] & 0xFE) == 18),
    }
}

impl Default for DirectOutbound {
    fn default() -> Self {
        Self::new("DIRECT")
    }
}

#[async_trait]
impl OutboundHandler for DirectOutbound {
    fn name(&self) -> &str {
        &self.name
    }

    fn protocol(&self) -> &'static str {
        "Direct"
    }

    fn exit_category(&self) -> &'static str {
        "DIRECT"
    }

    fn remote_endpoint(&self, target: &TargetAddr) -> String {
        target.to_string()
    }

    fn udp_supported(&self) -> bool {
        true
    }

    async fn connect_tcp(&self, target: &TargetAddr) -> io::Result<BoxedStream> {
        let addrs = self.resolve_target_addrs(target).await?;
        let stream =
            crate::platform::socket_protect::connect_protected_addrs_happy_eyeballs(&addrs).await?;
        Ok(Box::new(stream))
    }

    async fn open_udp_session(&self) -> io::Result<Box<dyn OutboundUdpSession>> {
        Ok(Box::new(DirectUdpSession::new(self.clone())))
    }

    async fn exchange_udp(
        &self,
        target: &TargetAddr,
        payload: &[u8],
        timeout: Duration,
    ) -> io::Result<Vec<u8>> {
        let remote = *self
            .resolve_target_addrs(target)
            .await?
            .first()
            .ok_or_else(|| io::Error::new(io::ErrorKind::HostUnreachable, "DNS lookup empty"))?;
        let bind_addr = if remote.is_ipv4() {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
        } else {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
        };
        let sock = protected_udp_bind(bind_addr, Some(remote))?;
        sock.connect(remote).await?;
        sock.send(payload).await?;
        let mut buf = vec![0u8; 65535];
        let n = tokio::time::timeout(timeout, sock.recv(&mut buf))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "direct UDP timed out"))??;
        buf.truncate(n);
        Ok(buf)
    }
}

/// Built-in `REJECT` outbound immediately denying connections.
pub struct RejectOutbound {
    name: String,
}

impl RejectOutbound {
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }
}

impl Default for RejectOutbound {
    fn default() -> Self {
        Self::new("REJECT")
    }
}

#[async_trait]
impl OutboundHandler for RejectOutbound {
    fn name(&self) -> &str {
        &self.name
    }

    fn protocol(&self) -> &'static str {
        "Reject"
    }

    fn exit_category(&self) -> &'static str {
        "REJECT"
    }

    fn remote_endpoint(&self, _target: &TargetAddr) -> String {
        "REJECT".to_string()
    }

    async fn connect_tcp(&self, _target: &TargetAddr) -> io::Result<BoxedStream> {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "connection rejected by REJECT outbound",
        ))
    }

    async fn open_udp_session(&self) -> io::Result<Box<dyn OutboundUdpSession>> {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "UDP session rejected by REJECT outbound",
        ))
    }

    async fn exchange_udp(
        &self,
        _target: &TargetAddr,
        _payload: &[u8],
        _timeout: Duration,
    ) -> io::Result<Vec<u8>> {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "UDP datagram rejected by REJECT outbound",
        ))
    }

    async fn latency_test(&self, _test_url: &str, _timeout: Duration) -> io::Result<u64> {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "REJECT outbound cannot pass latency probe",
        ))
    }

    async fn latency_test_with_mode(
        &self,
        test_url: &str,
        timeout: Duration,
        _unified_delay: bool,
    ) -> io::Result<u64> {
        self.latency_test(test_url, timeout).await
    }
}

/// Fail-closed synthetic outbound returned when routing encounters an invalid/cyclic proxy chain
/// or an unmapped Fake-IP, ensuring broken routes NEVER silently fall back to `DIRECT`.
pub struct ErrorOutbound {
    name: String,
    kind: io::ErrorKind,
    message: String,
}

impl ErrorOutbound {
    pub fn new(name: impl Into<String>, kind: io::ErrorKind, message: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            kind,
            message: message.into(),
        }
    }
}

#[async_trait]
impl OutboundHandler for ErrorOutbound {
    fn name(&self) -> &str {
        &self.name
    }

    fn protocol(&self) -> &'static str {
        "Error"
    }

    fn exit_category(&self) -> &'static str {
        "ERROR"
    }

    fn remote_endpoint(&self, _target: &TargetAddr) -> String {
        "ERROR".to_string()
    }

    async fn connect_tcp(&self, _target: &TargetAddr) -> io::Result<BoxedStream> {
        Err(io::Error::new(self.kind, self.message.clone()))
    }

    async fn open_udp_session(&self) -> io::Result<Box<dyn OutboundUdpSession>> {
        Err(io::Error::new(self.kind, self.message.clone()))
    }

    async fn exchange_udp(
        &self,
        _target: &TargetAddr,
        _payload: &[u8],
        _timeout: Duration,
    ) -> io::Result<Vec<u8>> {
        Err(io::Error::new(self.kind, self.message.clone()))
    }

    async fn latency_test(&self, _test_url: &str, _timeout: Duration) -> io::Result<u64> {
        Err(io::Error::new(self.kind, self.message.clone()))
    }

    async fn latency_test_with_mode(
        &self,
        test_url: &str,
        timeout: Duration,
        _unified_delay: bool,
    ) -> io::Result<u64> {
        self.latency_test(test_url, timeout).await
    }
}

pub type DynOutbound = Arc<dyn OutboundHandler>;

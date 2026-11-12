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
pub trait OutboundHandler: Send + Sync {
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

    /// Perform an end-to-end HTTP HEAD/GET latency test through this outbound proxy tunnel.
    async fn latency_test(&self, test_url: &str, timeout: Duration) -> io::Result<u64> {
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

        let started = Instant::now();
        tokio::time::timeout(timeout, async {
            let mut stream = self.connect_tcp(&target).await?;
            if is_https {
                let tls_cfg = crate::crypto::tls::build_tls_client_config(false, &[], &[])?;
                let sni = crate::crypto::tls::parse_server_name(host)?;
                let connector = tokio_rustls::TlsConnector::from(tls_cfg);
                let mut tls_stream = connector.connect(sni, stream).await?;
                let req = format!(
                    "HEAD {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: rust-clash/0.1\r\nConnection: close\r\n\r\n"
                );
                tls_stream.write_all(req.as_bytes()).await?;
                tls_stream.flush().await?;
                let mut resp = [0u8; 32];
                let n = tls_stream.read(&mut resp).await?;
                if n == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "empty response during TLS latency probe",
                    ));
                }
            } else {
                let req = format!(
                    "HEAD {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: rust-clash/0.1\r\nConnection: close\r\n\r\n"
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
            }
            Ok::<u64, io::Error>(started.elapsed().as_millis().max(1) as u64)
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "latency probe timed out"))?
    }
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
}

pub type DynOutbound = Arc<dyn OutboundHandler>;

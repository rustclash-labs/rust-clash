pub mod anytls;
pub mod http_proxy;
pub mod hysteria2;
pub mod quic_common;
pub mod socks5;
pub mod ss;
pub mod trojan;
pub mod tuic;
pub mod vless;
pub mod vmess;
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

use crate::{
    addr::{HostName, TargetAddr},
    dns::FakeIpDnsEngine,
    platform::socket_protect::protected_udp_bind,
};

pub trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send + Sync {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + Sync> AsyncStream for T {}

pub type BoxedStream = Box<dyn AsyncStream>;

pub(crate) const OUTBOUND_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(12);

#[inline]
pub(crate) fn hash_write_prefix(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in bytes {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

#[inline]
pub(crate) fn save_waker_slot(slot: &mut Option<std::task::Waker>, waker: &std::task::Waker) {
    match slot {
        Some(existing) if existing.will_wake(waker) => {}
        _ => *slot = Some(waker.clone()),
    }
}

pub(crate) async fn with_handshake_timeout<T, F>(label: &'static str, fut: F) -> io::Result<T>
where
    F: std::future::Future<Output = io::Result<T>>,
{
    tokio::time::timeout(OUTBOUND_HANDSHAKE_TIMEOUT, fut)
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "{label} timed out after {}s",
                    OUTBOUND_HANDSHAKE_TIMEOUT.as_secs()
                ),
            )
        })?
}

/// Persistent bidirectional UDP NAT session over an outbound proxy or direct socket.
/// Preserves NAT port bindings and avoids per-datagram handshakes for multi-packet flows (QUIC/HTTP3, WebRTC, gaming).
#[async_trait]
pub trait OutboundUdpSession: Send + Sync {
    async fn send_to(&self, payload: &[u8], target: &TargetAddr) -> io::Result<()>;
    async fn recv_from(&self) -> io::Result<(Vec<u8>, TargetAddr)>;
    /// Returns `true` when a `send_to` error is isolated to a single target destination
    /// (e.g. per-domain DNS `NODATA`/`NXDOMAIN` or per-peer ICMP/route unreachability)
    /// rather than a fatal failure of the underlying UDP session/socket itself.
    fn is_target_transient_error(&self, _err: &io::Error) -> bool {
        false
    }
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
    /// Rejects non-`http`/`https` schemes and URL userinfo via `crate::probe::parse_probe_url`.
    /// When `unified_delay` is `true` (Mihomo `unified-delay` semantics), establishes the
    /// proxy/TLS tunnel and warms end-to-end keep-alive first so cold DNS, TCP, TLS, and
    /// auth handshakes do not skew node RTT comparisons.
    async fn latency_test_with_mode(
        &self,
        test_url: &str,
        timeout: Duration,
        unified_delay: bool,
    ) -> io::Result<u64> {
        let (is_https, clean_host, port, path, _sanitized) =
            crate::probe::parse_probe_url(test_url)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
        let target = TargetAddr::new_domain(&clean_host, port)?;
        latency_test_on_target(
            self,
            &target,
            &clean_host,
            port,
            &path,
            is_https,
            timeout,
            unified_delay,
        )
        .await
    }

    /// Perform an SSRF-policy-enforced HTTP HEAD latency test through this outbound.
    /// Validates URL scheme/userinfo/endpoint via `crate::probe::validate_probe_url`, and when
    /// `!allow_private` on a `Direct` outbound targeting a domain, resolves DNS upfront, rejects
    /// any restricted non-whitelisted IP, and dials the validated IP directly (preventing DNS
    /// rebinding TOCTOU) while preserving the original HTTP `Host` header and TLS SNI.
    async fn latency_test_with_policy(
        &self,
        test_url: &str,
        timeout: Duration,
        unified_delay: bool,
        allow_private: bool,
        allowed_private_addrs: &[SocketAddr],
    ) -> crate::error::Result<u64> {
        let (is_https, clean_host, port, path, _sanitized) =
            crate::probe::validate_probe_url(test_url, allow_private, allowed_private_addrs)?;

        if !allow_private
            && self.protocol().eq_ignore_ascii_case("Direct")
            && clean_host.parse::<IpAddr>().is_err()
        {
            let started = Instant::now();
            let dial_ip = if clean_host.eq_ignore_ascii_case("localhost") {
                select_whitelisted_loopback_ip(port, allowed_private_addrs)
            } else {
                let addrs = tokio::time::timeout(
                    timeout,
                    tokio::net::lookup_host((clean_host.as_str(), port)),
                )
                .await
                .map_err(|_| crate::error::ProxyError::Timeout)?
                .map_err(crate::error::ProxyError::Io)?;
                let ips: Vec<IpAddr> = addrs.map(|sa| sa.ip()).collect();
                validate_resolved_probe_ips(&clean_host, port, &ips, allowed_private_addrs)?
            };
            let remaining = timeout.saturating_sub(started.elapsed());
            if remaining.is_zero() {
                return Err(crate::error::ProxyError::Timeout);
            }
            let dial_target = TargetAddr::new_ip(dial_ip, port);
            return latency_test_on_target(
                self,
                &dial_target,
                &clean_host,
                port,
                &path,
                is_https,
                remaining,
                unified_delay,
            )
            .await
            .map_err(crate::error::ProxyError::Io);
        }

        self.latency_test_with_mode(test_url, timeout, unified_delay)
            .await
            .map_err(crate::error::ProxyError::Io)
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn latency_test_on_target<H: OutboundHandler + ?Sized>(
    outbound: &H,
    dial_target: &TargetAddr,
    clean_host: &str,
    port: u16,
    path: &str,
    is_https: bool,
    timeout: Duration,
    unified_delay: bool,
) -> io::Result<u64> {
    let host_hdr = format_http_host_header(clean_host, port, is_https);
    let connect_started = Instant::now();
    tokio::time::timeout(timeout, async {
        let mut stream = outbound.connect_tcp(dial_target).await?;
        if is_https {
            let tls_cfg = crate::crypto::tls::build_tls_client_config(false, &[], &[])?;
            let sni = crate::crypto::tls::parse_server_name(clean_host)?;
            let connector = tokio_rustls::TlsConnector::from(tls_cfg);
            let mut tls_stream = connector.connect(sni, stream).await?;
            measure_http_head_latency(
                &mut tls_stream,
                &host_hdr,
                path,
                unified_delay,
                connect_started,
            )
            .await
        } else {
            measure_http_head_latency(&mut stream, &host_hdr, path, unified_delay, connect_started)
                .await
        }
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "latency probe timed out"))?
}

pub(crate) fn select_whitelisted_loopback_ip(
    port: u16,
    allowed_private_addrs: &[SocketAddr],
) -> IpAddr {
    allowed_private_addrs
        .iter()
        .filter(|sa| sa.port() == port && sa.ip().to_canonical().is_loopback())
        .map(|sa| sa.ip().to_canonical())
        .min_by_key(|ip| if ip.is_ipv4() { 0u8 } else { 1u8 })
        .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST))
}

pub(crate) fn validate_resolved_probe_ips(
    dom: &str,
    port: u16,
    ips: &[IpAddr],
    allowed_private_addrs: &[SocketAddr],
) -> crate::error::Result<IpAddr> {
    if ips.is_empty() {
        return Err(crate::error::ProxyError::Dns(format!(
            "DNS returned no addresses for '{dom}'"
        )));
    }
    for &resolved_ip in ips {
        if crate::probe::is_restricted_probe_ip(resolved_ip)
            && !crate::probe::is_whitelisted_private_addr(resolved_ip, port, allowed_private_addrs)
        {
            return Err(crate::error::ProxyError::Config(format!(
                "DNS resolved '{dom}' to restricted internal/private IP {resolved_ip} (blocked by SSRF protection)"
            )));
        }
    }
    Ok(ips[0])
}

fn format_http_host_header(clean_host: &str, port: u16, is_https: bool) -> String {
    let host_part = if clean_host.parse::<Ipv6Addr>().is_ok() {
        format!("[{clean_host}]")
    } else {
        clean_host.to_string()
    };
    let is_default_port = (is_https && port == 443) || (!is_https && port == 80);
    if is_default_port {
        host_part
    } else {
        format!("{host_part}:{port}")
    }
}

async fn measure_http_head_latency<S>(
    stream: &mut S,
    host_hdr: &str,
    path: &str,
    unified_delay: bool,
    connect_started: Instant,
) -> io::Result<u64>
where
    S: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    if !unified_delay {
        let req = format!(
            "HEAD {path} HTTP/1.1\r\nHost: {host_hdr}\r\nUser-Agent: rust-clash/{}\r\nConnection: close\r\n\r\n",
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
        "HEAD {path} HTTP/1.1\r\nHost: {host_hdr}\r\nUser-Agent: rust-clash/{}\r\nConnection: keep-alive\r\n\r\n",
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
        "HEAD {path} HTTP/1.1\r\nHost: {host_hdr}\r\nUser-Agent: rust-clash/{}\r\nConnection: close\r\n\r\n",
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
                let is_non_unicast = match ip {
                    IpAddr::V4(v4) => v4.is_multicast() || v4.is_broadcast() || v4.is_unspecified(),
                    IpAddr::V6(v6) => v6.is_multicast() || v6.is_unspecified(),
                };
                if is_non_unicast && crate::platform::socket_protect::has_custom_socket_protector()
                {
                    return Err(io::Error::new(
                        io::ErrorKind::AddrNotAvailable,
                        format!(
                            "refusing multicast/broadcast target {ip} via DIRECT while OS TUN is active"
                        ),
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

const DIRECT_UDP_LOCAL_BIND_ERR_PREFIX: &str = "local UDP socket bind failed:";

struct DirectUdpSession {
    direct: DirectOutbound,
    sock_v4: OnceCell<Arc<UdpSocket>>,
    sock_v6: OnceCell<Arc<UdpSocket>>,
    ready_notify: tokio::sync::Notify,
    peer_to_domain: parking_lot::Mutex<lru::LruCache<SocketAddr, TargetAddr>>,
}

impl DirectUdpSession {
    fn new(direct: DirectOutbound) -> Self {
        Self {
            direct,
            sock_v4: OnceCell::new(),
            sock_v6: OnceCell::new(),
            ready_notify: tokio::sync::Notify::new(),
            peer_to_domain: parking_lot::Mutex::new(lru::LruCache::new(
                std::num::NonZeroUsize::new(512).expect("non-zero capacity"),
            )),
        }
    }

    async fn socket_for(&self, remote: SocketAddr) -> io::Result<&Arc<UdpSocket>> {
        if remote.is_ipv4() {
            let did_init = std::sync::atomic::AtomicBool::new(false);
            let sock = self
                .sock_v4
                .get_or_try_init(|| async {
                    let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
                    let s = protected_udp_bind(bind, Some(remote)).map_err(|e| {
                        io::Error::new(e.kind(), format!("{DIRECT_UDP_LOCAL_BIND_ERR_PREFIX} {e}"))
                    })?;
                    did_init.store(true, std::sync::atomic::Ordering::Relaxed);
                    Ok::<Arc<UdpSocket>, io::Error>(Arc::new(s))
                })
                .await?;
            if did_init.load(std::sync::atomic::Ordering::Relaxed) {
                self.ready_notify.notify_waiters();
            }
            Ok(sock)
        } else {
            let did_init = std::sync::atomic::AtomicBool::new(false);
            let sock = self
                .sock_v6
                .get_or_try_init(|| async {
                    let bind = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0);
                    // On IPv4-only kernels (`ipv6.disable=1`), `AF_INET6` socket creation fails
                    // with `EAFNOSUPPORT` / `AddrNotAvailable` — treat that as per-family transient
                    // so IPv4 destinations on the same `DirectUdpSession` remain usable.
                    let s = protected_udp_bind(bind, Some(remote)).map_err(|e| {
                        if crate::platform::socket_protect::is_local_ipv6_unreachable_error(&e) {
                            e
                        } else {
                            io::Error::new(
                                e.kind(),
                                format!("{DIRECT_UDP_LOCAL_BIND_ERR_PREFIX} {e}"),
                            )
                        }
                    })?;
                    did_init.store(true, std::sync::atomic::Ordering::Relaxed);
                    Ok::<Arc<UdpSocket>, io::Error>(Arc::new(s))
                })
                .await?;
            if did_init.load(std::sync::atomic::Ordering::Relaxed) {
                self.ready_notify.notify_waiters();
            }
            Ok(sock)
        }
    }

    fn map_peer_source(&self, peer: SocketAddr) -> TargetAddr {
        self.peer_to_domain
            .lock()
            .get(&peer)
            .cloned()
            .unwrap_or_else(|| TargetAddr::from(peer))
    }
}

fn order_direct_udp_addrs(mut addrs: Vec<SocketAddr>) -> Vec<SocketAddr> {
    if addrs.len() > 1
        && !crate::platform::socket_protect::is_direct_ipv6_reachable()
        && addrs.iter().any(SocketAddr::is_ipv4)
    {
        addrs.sort_by_key(|addr| match addr {
            SocketAddr::V6(v6)
                if crate::platform::socket_protect::is_global_unicast_ipv6(*v6.ip()) =>
            {
                1u8
            }
            _ => 0u8,
        });
    }
    addrs
}

#[async_trait]
impl OutboundUdpSession for DirectUdpSession {
    fn is_target_transient_error(&self, err: &io::Error) -> bool {
        !err.to_string()
            .starts_with(DIRECT_UDP_LOCAL_BIND_ERR_PREFIX)
            && !matches!(
                err.kind(),
                io::ErrorKind::PermissionDenied | io::ErrorKind::OutOfMemory
            )
    }

    async fn send_to(&self, payload: &[u8], target: &TargetAddr) -> io::Result<()> {
        let addrs = order_direct_udp_addrs(self.direct.resolve_target_addrs(target).await?);
        if addrs.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::HostUnreachable,
                "DNS lookup empty",
            ));
        }
        let total = addrs.len();
        let mut last_err: Option<io::Error> = None;
        for (idx, remote_addr) in addrs.into_iter().enumerate() {
            let send_res = match self.socket_for(remote_addr).await {
                Ok(sock) => sock.send_to(payload, remote_addr).await.map(|_| ()),
                Err(err) => Err(err),
            };
            match send_res {
                Ok(()) => {
                    if matches!(target.host, HostName::Domain(_)) {
                        self.peer_to_domain.lock().put(remote_addr, target.clone());
                    }
                    crate::platform::socket_protect::note_direct_addr_connect_result(
                        remote_addr,
                        Ok(()),
                    );
                    return Ok(());
                }
                Err(err) => {
                    crate::platform::socket_protect::note_direct_addr_connect_result(
                        remote_addr,
                        Err(&err),
                    );
                    if idx + 1 < total
                        && crate::platform::socket_protect::is_local_ipv6_unreachable_error(&err)
                    {
                        last_err = Some(err);
                        continue;
                    }
                    return Err(err);
                }
            }
        }
        Err(last_err
            .unwrap_or_else(|| io::Error::new(io::ErrorKind::HostUnreachable, "DNS lookup empty")))
    }

    async fn recv_from(&self) -> io::Result<(Vec<u8>, TargetAddr)> {
        let mut b4 = vec![0u8; 65535];
        let mut b6 = vec![0u8; 65535];
        loop {
            // Pin and enable `ready_notify` BEFORE reading `OnceCell`s so `notify_waiters()`
            // from `socket_for` can never be lost in the window between `.get()` and `.await`.
            let notified = self.ready_notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();

            let v4 = self.sock_v4.get().cloned();
            let v6 = self.sock_v6.get().cloned();
            match (v4, v6) {
                (Some(s4), Some(s6)) => {
                    tokio::select! {
                        res = s4.recv_from(&mut b4) => {
                            match res {
                                Ok((n, peer)) => {
                                    return Ok((b4[..n].to_vec(), self.map_peer_source(peer)));
                                }
                                Err(e) if matches!(
                                    e.kind(),
                                    io::ErrorKind::ConnectionReset
                                        | io::ErrorKind::ConnectionRefused
                                        | io::ErrorKind::Interrupted
                                ) => continue,
                                Err(e) => return Err(e),
                            }
                        }
                        res = s6.recv_from(&mut b6) => {
                            match res {
                                Ok((n, peer)) => {
                                    return Ok((b6[..n].to_vec(), self.map_peer_source(peer)));
                                }
                                Err(e) if matches!(
                                    e.kind(),
                                    io::ErrorKind::ConnectionReset
                                        | io::ErrorKind::ConnectionRefused
                                        | io::ErrorKind::Interrupted
                                ) => continue,
                                Err(e) => return Err(e),
                            }
                        }
                    }
                }
                (Some(s4), None) => {
                    tokio::select! {
                        res = s4.recv_from(&mut b4) => {
                            match res {
                                Ok((n, peer)) => {
                                    return Ok((b4[..n].to_vec(), self.map_peer_source(peer)));
                                }
                                Err(e) if matches!(
                                    e.kind(),
                                    io::ErrorKind::ConnectionReset
                                        | io::ErrorKind::ConnectionRefused
                                        | io::ErrorKind::Interrupted
                                ) => continue,
                                Err(e) => return Err(e),
                            }
                        }
                        _ = &mut notified => continue,
                    }
                }
                (None, Some(s6)) => {
                    tokio::select! {
                        res = s6.recv_from(&mut b6) => {
                            match res {
                                Ok((n, peer)) => {
                                    return Ok((b6[..n].to_vec(), self.map_peer_source(peer)));
                                }
                                Err(e) if matches!(
                                    e.kind(),
                                    io::ErrorKind::ConnectionReset
                                        | io::ErrorKind::ConnectionRefused
                                        | io::ErrorKind::Interrupted
                                ) => continue,
                                Err(e) => return Err(e),
                            }
                        }
                        _ = &mut notified => continue,
                    }
                }
                (None, None) => {
                    notified.await;
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
        let addrs = order_direct_udp_addrs(self.resolve_target_addrs(target).await?);
        if addrs.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::HostUnreachable,
                "DNS lookup empty",
            ));
        }
        let total = addrs.len();
        let mut connected_sock: Option<UdpSocket> = None;
        let mut last_err: Option<io::Error> = None;
        for (idx, remote_addr) in addrs.into_iter().enumerate() {
            let bind_addr = if remote_addr.is_ipv4() {
                SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
            } else {
                SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
            };
            let attempt: io::Result<UdpSocket> = async {
                let sock = protected_udp_bind(bind_addr, Some(remote_addr))?;
                sock.connect(remote_addr).await?;
                sock.send(payload).await?;
                Ok(sock)
            }
            .await;
            match attempt {
                Ok(sock) => {
                    crate::platform::socket_protect::note_direct_addr_connect_result(
                        remote_addr,
                        Ok(()),
                    );
                    connected_sock = Some(sock);
                    break;
                }
                Err(err) => {
                    crate::platform::socket_protect::note_direct_addr_connect_result(
                        remote_addr,
                        Err(&err),
                    );
                    if idx + 1 < total
                        && crate::platform::socket_protect::is_local_ipv6_unreachable_error(&err)
                    {
                        last_err = Some(err);
                        continue;
                    }
                    return Err(err);
                }
            }
        }
        let Some(sock) = connected_sock else {
            return Err(last_err.unwrap_or_else(|| {
                io::Error::new(io::ErrorKind::HostUnreachable, "DNS lookup empty")
            }));
        };
        let mut buf = vec![0u8; 65535];
        let n = tokio::time::timeout(timeout, sock.recv(&mut buf))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "direct UDP timed out"))??;
        buf.truncate(n);
        Ok(buf)
    }

    async fn latency_test_with_policy(
        &self,
        test_url: &str,
        timeout: Duration,
        unified_delay: bool,
        allow_private: bool,
        allowed_private_addrs: &[SocketAddr],
    ) -> crate::error::Result<u64> {
        let (is_https, clean_host, port, path, _sanitized) =
            crate::probe::validate_probe_url(test_url, allow_private, allowed_private_addrs)?;

        if !allow_private && clean_host.parse::<IpAddr>().is_err() {
            let started = Instant::now();
            let dial_ip = if clean_host.eq_ignore_ascii_case("localhost") {
                select_whitelisted_loopback_ip(port, allowed_private_addrs)
            } else if let Some(dns) = &self.dns {
                let ips = tokio::time::timeout(timeout, dns.resolve_direct_ips(&clean_host))
                    .await
                    .map_err(|_| crate::error::ProxyError::Timeout)??;
                validate_resolved_probe_ips(&clean_host, port, &ips, allowed_private_addrs)?
            } else {
                let addrs = tokio::time::timeout(
                    timeout,
                    tokio::net::lookup_host((clean_host.as_str(), port)),
                )
                .await
                .map_err(|_| crate::error::ProxyError::Timeout)?
                .map_err(crate::error::ProxyError::Io)?;
                let ips: Vec<IpAddr> = addrs.map(|sa| sa.ip()).collect();
                validate_resolved_probe_ips(&clean_host, port, &ips, allowed_private_addrs)?
            };
            let remaining = timeout.saturating_sub(started.elapsed());
            if remaining.is_zero() {
                return Err(crate::error::ProxyError::Timeout);
            }
            let dial_target = TargetAddr::new_ip(dial_ip, port);
            return latency_test_on_target(
                self,
                &dial_target,
                &clean_host,
                port,
                &path,
                is_https,
                remaining,
                unified_delay,
            )
            .await
            .map_err(crate::error::ProxyError::Io);
        }

        self.latency_test_with_mode(test_url, timeout, unified_delay)
            .await
            .map_err(crate::error::ProxyError::Io)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_http_host_header_handles_ipv6_ipv4_and_ports() {
        assert_eq!(format_http_host_header("::1", 80, false), "[::1]");
        assert_eq!(format_http_host_header("::1", 8080, false), "[::1]:8080");
        assert_eq!(
            format_http_host_header("2001:db8::1", 443, true),
            "[2001:db8::1]"
        );
        assert_eq!(
            format_http_host_header("2001:db8::1", 8443, true),
            "[2001:db8::1]:8443"
        );
        assert_eq!(format_http_host_header("127.0.0.1", 80, false), "127.0.0.1");
        assert_eq!(
            format_http_host_header("127.0.0.1", 8080, false),
            "127.0.0.1:8080"
        );
        assert_eq!(
            format_http_host_header("example.com", 443, true),
            "example.com"
        );
        assert_eq!(
            format_http_host_header("example.com", 80, true),
            "example.com:80"
        );
    }

    #[tokio::test]
    async fn direct_udp_session_recv_from_never_loses_wakeup_on_lazy_init() {
        let echo_v4 = UdpSocket::bind("127.0.0.1:0").await.expect("bind v4 echo");
        let echo_v4_addr = echo_v4.local_addr().expect("v4 local_addr");
        let echo_v4_task = tokio::spawn(async move {
            let mut buf = [0u8; 256];
            while let Ok((n, peer)) = echo_v4.recv_from(&mut buf).await {
                if &buf[..n] == b"stop" {
                    break;
                }
                let _ = echo_v4.send_to(&buf[..n], peer).await;
            }
        });

        // Case 1: `recv_from` parks in `(None, None)` before `send_to` initializes `sock_v4`.
        let direct = DirectOutbound::default();
        let sess: Arc<Box<dyn OutboundUdpSession>> =
            Arc::new(direct.open_udp_session().await.expect("open_udp_session"));
        let sess_rx = Arc::clone(&sess);
        let recv_handle = tokio::spawn(async move { sess_rx.recv_from().await });
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        sess.send_to(b"hello-v4", &TargetAddr::from(echo_v4_addr))
            .await
            .expect("send_to v4");
        let (payload, src) = tokio::time::timeout(Duration::from_secs(2), recv_handle)
            .await
            .expect("recv_from v4 should wake without timeout")
            .expect("recv_handle join")
            .expect("recv_from v4 ok");
        assert_eq!(payload, b"hello-v4");
        assert_eq!(src, TargetAddr::from(echo_v4_addr));

        // Case 2: `recv_from` parks in `(Some(s4), None)` while `send_to` initializes `sock_v6`.
        if let Ok(echo_v6) = UdpSocket::bind("[::1]:0").await {
            let echo_v6_addr = echo_v6.local_addr().expect("v6 local_addr");
            let echo_v6_task = tokio::spawn(async move {
                let mut buf = [0u8; 256];
                if let Ok((n, peer)) = echo_v6.recv_from(&mut buf).await {
                    let _ = echo_v6.send_to(&buf[..n], peer).await;
                }
            });

            let sess_rx_v6 = Arc::clone(&sess);
            let recv_v6_handle = tokio::spawn(async move { sess_rx_v6.recv_from().await });
            for _ in 0..8 {
                tokio::task::yield_now().await;
            }
            if sess
                .send_to(b"hello-v6", &TargetAddr::from(echo_v6_addr))
                .await
                .is_ok()
            {
                let (v6_payload, v6_src) =
                    tokio::time::timeout(Duration::from_secs(2), recv_v6_handle)
                        .await
                        .expect("recv_from should wake when sock_v6 initializes")
                        .expect("recv_v6 join")
                        .expect("recv_from v6 ok");
                assert_eq!(v6_payload, b"hello-v6");
                assert_eq!(v6_src, TargetAddr::from(echo_v6_addr));
            } else {
                recv_v6_handle.abort();
            }
            echo_v6_task.abort();
        }

        // Case 3: Repeated concurrent races between `recv_from` and first `send_to`.
        for i in 0..24u8 {
            let s: Arc<Box<dyn OutboundUdpSession>> =
                Arc::new(direct.open_udp_session().await.expect("open_udp_session"));
            let s_rx = Arc::clone(&s);
            let msg = [b'r', i];
            let dst = TargetAddr::from(echo_v4_addr);
            let (rx_res, tx_res) = tokio::time::timeout(Duration::from_secs(2), async {
                tokio::join!(s_rx.recv_from(), s.send_to(&msg, &dst))
            })
            .await
            .expect("concurrent recv_from + send_to should not deadlock");
            tx_res.expect("race send_to");
            let (got, _) = rx_res.expect("race recv_from");
            assert_eq!(got, msg);
        }

        let _ = sess.send_to(b"stop", &TargetAddr::from(echo_v4_addr)).await;
        let _ = echo_v4_task.await;
    }

    struct MockCaptureOutbound {
        targets: Arc<parking_lot::Mutex<Vec<TargetAddr>>>,
        requests: Arc<parking_lot::Mutex<Vec<Vec<u8>>>>,
        mode: MockCaptureMode,
    }

    #[derive(Clone, Copy)]
    enum MockCaptureMode {
        Http204KeepAlive,
        TlsCloseOnClientHello,
    }

    #[async_trait]
    impl OutboundHandler for MockCaptureOutbound {
        fn name(&self) -> &str {
            "mock-capture"
        }

        fn protocol(&self) -> &'static str {
            "Mock"
        }

        async fn connect_tcp(&self, target: &TargetAddr) -> io::Result<BoxedStream> {
            self.targets.lock().push(target.clone());
            let (c_io, mut s_io) = tokio::io::duplex(16 * 1024);
            let reqs = Arc::clone(&self.requests);
            let mode = self.mode;
            tokio::spawn(async move {
                match mode {
                    MockCaptureMode::Http204KeepAlive => {
                        for _ in 0..2 {
                            let mut buf = Vec::new();
                            let mut chunk = [0u8; 512];
                            loop {
                                match s_io.read(&mut chunk).await {
                                    Ok(0) | Err(_) => return,
                                    Ok(n) => {
                                        buf.extend_from_slice(&chunk[..n]);
                                        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                                            break;
                                        }
                                    }
                                }
                            }
                            reqs.lock().push(buf);
                            if s_io
                                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                                .await
                                .is_err()
                            {
                                return;
                            }
                        }
                    }
                    MockCaptureMode::TlsCloseOnClientHello => {
                        let mut buf = [0u8; 512];
                        if let Ok(n) = s_io.read(&mut buf).await
                            && n > 0
                        {
                            reqs.lock().push(buf[..n].to_vec());
                        }
                        // Drop `s_io` to trigger clean EOF after ClientHello (proving SNI parsed).
                    }
                }
            });
            Ok(Box::new(c_io))
        }
    }

    #[tokio::test]
    async fn latency_test_with_mode_formats_ipv6_host_and_strips_sni_brackets() {
        let targets = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let requests = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let mock_http = MockCaptureOutbound {
            targets: Arc::clone(&targets),
            requests: Arc::clone(&requests),
            mode: MockCaptureMode::Http204KeepAlive,
        };

        // Default HTTP port 80 -> `Host: [::1]` and `TargetAddr::Ip(::1, 80)`
        let rtt_default = mock_http
            .latency_test_with_mode("http://[::1]/generate_204", Duration::from_secs(2), false)
            .await
            .expect("http ipv6 default port latency");
        assert!(rtt_default >= 1);

        // Non-default HTTP port 18080 with `unified_delay = true` -> `Host: [::1]:18080` on both HEADs
        let rtt_unified = mock_http
            .latency_test_with_mode(
                "http://[::1]:18080/generate_204?probe=1",
                Duration::from_secs(2),
                true,
            )
            .await
            .expect("http ipv6 non-default port unified-delay latency");
        assert!(rtt_unified >= 1);

        {
            let seen_targets = targets.lock();
            assert_eq!(
                seen_targets.as_slice(),
                &[
                    TargetAddr::new_ip(IpAddr::V6(Ipv6Addr::LOCALHOST), 80),
                    TargetAddr::new_ip(IpAddr::V6(Ipv6Addr::LOCALHOST), 18080),
                ]
            );
            let seen_reqs = requests.lock();
            assert_eq!(seen_reqs.len(), 3);
            let req0 = String::from_utf8_lossy(&seen_reqs[0]);
            assert!(req0.starts_with("HEAD /generate_204 HTTP/1.1\r\nHost: [::1]\r\n"));
            let req1 = String::from_utf8_lossy(&seen_reqs[1]);
            assert!(
                req1.starts_with("HEAD /generate_204?probe=1 HTTP/1.1\r\nHost: [::1]:18080\r\n")
            );
            let req2 = String::from_utf8_lossy(&seen_reqs[2]);
            assert!(
                req2.starts_with("HEAD /generate_204?probe=1 HTTP/1.1\r\nHost: [::1]:18080\r\n")
            );
        }

        // HTTPS IPv6 URL -> strips `[` and `]` so `parse_server_name("::1")` succeeds and sends TLS ClientHello
        let tls_targets = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let tls_hellos = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let mock_https = MockCaptureOutbound {
            targets: Arc::clone(&tls_targets),
            requests: Arc::clone(&tls_hellos),
            mode: MockCaptureMode::TlsCloseOnClientHello,
        };
        let err = mock_https
            .latency_test_with_mode(
                "https://[::1]:8443/generate_204",
                Duration::from_secs(2),
                false,
            )
            .await
            .expect_err("closed mock TLS server should fail handshake after ClientHello");
        assert_ne!(
            err.kind(),
            io::ErrorKind::InvalidInput,
            "HTTPS IPv6 probe must not fail with InvalidInput SNI error: {err}"
        );
        assert_eq!(
            tls_targets.lock().as_slice(),
            &[TargetAddr::new_ip(IpAddr::V6(Ipv6Addr::LOCALHOST), 8443)]
        );
        let hellos = tls_hellos.lock();
        assert_eq!(
            hellos.len(),
            1,
            "TLS ClientHello must have been transmitted"
        );
        assert_eq!(hellos[0][0], 0x16, "TLS Handshake record type");
    }

    #[tokio::test]
    async fn latency_test_with_policy_blocks_bad_schemes_userinfo_and_direct_dns_rebinding() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        use crate::{
            config::DnsConfig,
            dns::wire::{DnsAnswerData, DnsQueryPacket, QTYPE_A, QTYPE_AAAA},
        };

        let direct_plain = DirectOutbound::default();
        for bad_url in [
            "ftp://example.com/file",
            "file:///etc/passwd",
            "http://alice:secret@example.com/generate_204",
        ] {
            let err = direct_plain
                .latency_test_with_mode(bad_url, Duration::from_secs(2), false)
                .await
                .expect_err("latency_test_with_mode must reject unsupported scheme/userinfo");
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        }

        // Mock upstream UDP DNS returning restricted IPs for public-looking attacker domains
        let mock_ns = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let mock_ns_addr = mock_ns.local_addr().unwrap();
        let (dns_stop_tx, mut dns_stop_rx) = tokio::sync::watch::channel(false);
        let ns_bg = Arc::clone(&mock_ns);
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            loop {
                tokio::select! {
                    _ = dns_stop_rx.changed() => break,
                    res = ns_bg.recv_from(&mut buf) => {
                        let Ok((n, peer)) = res else { continue };
                        let Ok(pkt) = DnsQueryPacket::parse(&buf[..n]) else { continue };
                        let q = pkt.question.name.to_ascii_lowercase();
                        let resp = match (q.as_str(), pkt.question.qtype) {
                            ("rebind-loopback.attacker.test", QTYPE_A) => pkt.build_response(
                                &buf[..n],
                                0,
                                60,
                                &[DnsAnswerData::A(Ipv4Addr::LOCALHOST)],
                            ),
                            ("rebind-imds.attacker.test", QTYPE_A) => pkt.build_response(
                                &buf[..n],
                                0,
                                60,
                                &[DnsAnswerData::A(Ipv4Addr::new(169, 254, 169, 254))],
                            ),
                            ("rebind-ula.attacker.test", QTYPE_AAAA) => pkt.build_response(
                                &buf[..n],
                                0,
                                60,
                                &[DnsAnswerData::Aaaa("fd00:ec2::254".parse().unwrap())],
                            ),
                            _ => pkt.build_response(&buf[..n], 0, 60, &[]),
                        };
                        let _ = ns_bg.send_to(&resp, peer).await;
                    }
                }
            }
        });

        // Canary TCP listener that MUST NEVER be dialed by DNS-rebound probes,
        // and IS dialed ONLY when explicitly whitelisted.
        let canary = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let canary_addr = canary.local_addr().unwrap();
        let canary_hits = Arc::new(AtomicUsize::new(0));
        let last_host_hdr = Arc::new(parking_lot::Mutex::new(String::new()));
        let hits_bg = Arc::clone(&canary_hits);
        let hdr_bg = Arc::clone(&last_host_hdr);
        let mut canary_stop = dns_stop_tx.subscribe();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = canary_stop.changed() => break,
                    acc = canary.accept() => {
                        let Ok((mut s, _)) = acc else { continue };
                        hits_bg.fetch_add(1, Ordering::SeqCst);
                        let hdr_clone = Arc::clone(&hdr_bg);
                        tokio::spawn(async move {
                            let mut b = [0u8; 512];
                            let n = s.read(&mut b).await.unwrap_or(0);
                            *hdr_clone.lock() = String::from_utf8_lossy(&b[..n]).into_owned();
                            let _ = s.write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n").await;
                        });
                    }
                }
            }
        });

        let dns_cfg = DnsConfig {
            enable: true,
            listen: "127.0.0.1:0".into(),
            ipv6: true,
            nameserver: vec![mock_ns_addr.to_string()],
            direct_nameserver: vec![mock_ns_addr.to_string()],
            ..DnsConfig::default()
        };
        let dns = Arc::new(FakeIpDnsEngine::new(&dns_cfg).unwrap());
        let direct = DirectOutbound::with_dns("DIRECT", dns);

        for rebind_url in [
            format!(
                "http://rebind-loopback.attacker.test:{}/generate_204",
                canary_addr.port()
            ),
            "http://rebind-imds.attacker.test/latest/meta-data/".to_string(),
            "http://rebind-ula.attacker.test/latest/meta-data/".to_string(),
        ] {
            let err = direct
                .latency_test_with_policy(&rebind_url, Duration::from_secs(2), false, false, &[])
                .await
                .expect_err("DNS-rebound restricted IP must be blocked");
            assert!(
                matches!(err, crate::error::ProxyError::Config(_)),
                "expected ProxyError::Config for SSRF DNS rebinding on {rebind_url}, got: {err:?}"
            );
        }
        assert_eq!(
            canary_hits.load(Ordering::SeqCst),
            0,
            "DNS-rebound loopback probe must never connect to canary socket"
        );

        // Whitelisted localhost on exact canary port MUST dial loopback directly while preserving Host header!
        let allowed = [canary_addr];
        let ok_ms = direct
            .latency_test_with_policy(
                &format!("http://localhost:{}/generate_204", canary_addr.port()),
                Duration::from_secs(2),
                false,
                false,
                &allowed,
            )
            .await
            .expect("whitelisted localhost port must succeed");
        assert!(ok_ms >= 1);
        assert_eq!(canary_hits.load(Ordering::SeqCst), 1);
        assert!(
            last_host_hdr
                .lock()
                .contains(&format!("Host: localhost:{}", canary_addr.port())),
            "Host header must preserve original hostname"
        );

        // Different port on localhost MUST still be rejected!
        let err_port = direct
            .latency_test_with_policy(
                &format!(
                    "http://localhost:{}/generate_204",
                    canary_addr.port().wrapping_add(1).max(1)
                ),
                Duration::from_secs(2),
                false,
                false,
                &allowed,
            )
            .await
            .expect_err("non-whitelisted localhost port must be rejected");
        assert!(matches!(err_port, crate::error::ProxyError::Config(_)));

        let _ = dns_stop_tx.send(true);
    }
}

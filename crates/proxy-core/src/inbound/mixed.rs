use std::{
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use base64::{Engine, engine::general_purpose::STANDARD};
use bytes::{BufMut, BytesMut};
use ipnet::IpNet;
use parking_lot::RwLock;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{Semaphore, watch},
    task::{JoinHandle, JoinSet},
};
use url::Url;

use crate::{
    addr::{HostName, TargetAddr},
    error::{ProxyError, Result},
    inbound::sniff::{
        MAX_SNIFF_BYTES, RealIpTlsOverrideGuard, RealIpTlsOverrideTracker, SniffOutcomeWithProto,
        SniffedProtocol, resolve_real_ip_tcp_dial_target, sniff_tcp_protocol,
    },
    outbound::{BoxedStream, OutboundHandler},
    router::Router,
    tracker::{ActiveConnection, TelemetryHub},
};

const MAX_MIXED_CONNECTIONS: usize = 1024;
const MAX_UDP_ASSOC_INFLIGHT: usize = 64;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
const OUTBOUND_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const MIXED_SNIFF_TIMEOUT: Duration = Duration::from_millis(150);

/// Dynamic access-control and authentication policy for the Mixed (HTTP + SOCKS5) inbound listener.
#[derive(Clone, Debug)]
pub struct MixedInboundPolicy {
    pub allow_lan: bool,
    /// Configured `username:password` pairs. When non-empty, both SOCKS5 (`0x02`) and HTTP (`Basic`) require auth.
    pub credentials: Vec<(String, String)>,
    /// Allowed client source CIDRs when `allow_lan` is true. Defaults to RFC1918/CGNAT/ULA/link-local LAN subnets.
    pub lan_allowed_nets: Vec<IpNet>,
    /// Host-local daemon ports (e.g., `external-controller`, `dns.listen`) blocked on loopback/unspecified proxy targets.
    pub blocked_local_ports: Vec<u16>,
}

impl Default for MixedInboundPolicy {
    fn default() -> Self {
        Self {
            allow_lan: false,
            credentials: Vec::new(),
            lan_allowed_nets: default_private_lan_nets(),
            blocked_local_ports: Vec::new(),
        }
    }
}

impl MixedInboundPolicy {
    pub fn from_config(
        allow_lan: bool,
        authentication: &[String],
        lan_allowed_ips: &[String],
    ) -> Result<Self> {
        let mut credentials = Vec::with_capacity(authentication.len());
        for entry in authentication {
            let Some((u, p)) = entry.split_once(':') else {
                return Err(ProxyError::Config(
                    "invalid authentication entry; expected 'username:password'".into(),
                ));
            };
            credentials.push((u.to_string(), p.to_string()));
        }

        let lan_allowed_nets = if lan_allowed_ips.is_empty() {
            default_private_lan_nets()
        } else {
            let mut nets = Vec::with_capacity(lan_allowed_ips.len());
            for raw in lan_allowed_ips {
                let net = raw.parse::<IpNet>().map_err(|e| {
                    ProxyError::Config(format!("invalid lan-allowed-ips CIDR '{raw}': {e}"))
                })?;
                nets.push(net);
            }
            nets
        };

        Ok(Self {
            allow_lan,
            credentials,
            lan_allowed_nets,
            blocked_local_ports: Vec::new(),
        })
    }

    pub fn with_blocked_local_ports(mut self, blocked_local_ports: Vec<u16>) -> Self {
        self.blocked_local_ports = blocked_local_ports;
        self
    }

    pub fn allows_peer(&self, peer_ip: IpAddr) -> bool {
        let ip = canonical_ip(peer_ip);
        if ip.is_loopback() {
            return true;
        }
        if !self.allow_lan {
            return false;
        }
        self.lan_allowed_nets.iter().any(|net| net.contains(&ip))
    }

    pub fn requires_auth(&self) -> bool {
        !self.credentials.is_empty()
    }

    pub fn verify_credentials(&self, username: &str, password: &str) -> bool {
        let mut matched = 0u8;
        for (expected_user, expected_pass) in &self.credentials {
            let u_ok = constant_time_eq(username.as_bytes(), expected_user.as_bytes());
            let p_ok = constant_time_eq(password.as_bytes(), expected_pass.as_bytes());
            matched |= u_ok & p_ok;
        }
        matched == 1
    }
}

fn default_private_lan_nets() -> Vec<IpNet> {
    [
        "10.0.0.0/8",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "100.64.0.0/10",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
    ]
    .into_iter()
    .filter_map(|c| c.parse().ok())
    .collect()
}

pub fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => IpAddr::V4(v4),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> u8 {
    if a.len() != b.len() {
        return 0;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    u8::from(diff == 0)
}

/// Single-port HTTP/HTTPS `CONNECT` + SOCKS5 (TCP `CONNECT` & `UDP ASSOCIATE`) Mixed Inbound
/// with default loopback-only access policy.
pub async fn spawn_mixed_inbound(
    listen_addr: &str,
    router: Arc<RwLock<Arc<Router>>>,
    hub: Arc<TelemetryHub>,
    shutdown: watch::Receiver<bool>,
) -> Result<(SocketAddr, JoinHandle<()>)> {
    let policy = Arc::new(RwLock::new(MixedInboundPolicy::default()));
    spawn_mixed_inbound_with_policy(listen_addr, router, policy, hub, shutdown).await
}

/// Single-port Mixed Inbound with hot-updatable `MixedInboundPolicy` (`allow-lan`, CIDR ACLs, auth)
/// and bounded connection concurrency.
pub async fn spawn_mixed_inbound_with_policy(
    listen_addr: &str,
    router: Arc<RwLock<Arc<Router>>>,
    policy: Arc<RwLock<MixedInboundPolicy>>,
    hub: Arc<TelemetryHub>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(SocketAddr, JoinHandle<()>)> {
    let listener = TcpListener::bind(listen_addr).await.map_err(|e| {
        ProxyError::Io(io::Error::new(
            e.kind(),
            format!("bind mixed {listen_addr}: {e}"),
        ))
    })?;
    let local_addr = listener.local_addr()?;
    let local_mixed_port = local_addr.port();
    let conn_sem = Arc::new(Semaphore::new(MAX_MIXED_CONNECTIONS));

    let handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
                accepted = listener.accept() => {
                    let Ok((tcp, peer)) = accepted else {
                        continue;
                    };
                    let snap_policy = policy.read().clone();
                    if !snap_policy.allows_peer(peer.ip()) {
                        hub.push_log(
                            "warn",
                            format!("[Mixed] Rejected unauthorized peer {peer} (allow-lan={})", snap_policy.allow_lan),
                        );
                        continue;
                    }
                    let Ok(permit) = Arc::clone(&conn_sem).try_acquire_owned() else {
                        hub.push_log(
                            "warn",
                            format!("[Mixed] Connection limit ({MAX_MIXED_CONNECTIONS}) reached; dropping {peer}"),
                        );
                        continue;
                    };

                    let _ = tcp.set_nodelay(true);
                    let router_slot = Arc::clone(&router);
                    let policy_slot = Arc::clone(&policy);
                    let hub_clone = Arc::clone(&hub);
                    let shutdown_conn = shutdown.clone();
                    tokio::spawn(async move {
                        let _permit = permit;
                        if let Err(err) = handle_mixed_conn(
                            tcp,
                            peer,
                            local_mixed_port,
                            router_slot,
                            policy_slot,
                            hub_clone,
                            shutdown_conn,
                        )
                        .await
                        {
                            tracing::debug!("mixed connection from {peer} ended: {err}");
                        }
                    });
                }
            }
        }
    });

    Ok((local_addr, handle))
}

fn is_loopback_or_unspecified_target(target: &TargetAddr) -> bool {
    match &target.host {
        HostName::Ip(ip) => {
            let canon = canonical_ip(*ip);
            canon.is_loopback() || canon.is_unspecified()
        }
        HostName::Domain(domain) => {
            let d = domain.trim().trim_end_matches('.').to_ascii_lowercase();
            if d == "localhost" || d.ends_with(".localhost") {
                return true;
            }
            if let Ok(ip) = d.parse::<IpAddr>() {
                let canon = canonical_ip(ip);
                return canon.is_loopback() || canon.is_unspecified();
            }
            false
        }
    }
}

fn reject_forbidden_proxy_target(
    peer_addr: SocketAddr,
    local_mixed_port: u16,
    policy: &MixedInboundPolicy,
    target: &TargetAddr,
) -> io::Result<()> {
    if !is_loopback_or_unspecified_target(target) {
        return Ok(());
    }
    if !canonical_ip(peer_addr.ip()).is_loopback() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("LAN peer {peer_addr} is forbidden from targeting host-local address {target}"),
        ));
    }
    if (local_mixed_port != 0 && target.port == local_mixed_port)
        || policy.blocked_local_ports.contains(&target.port)
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "proxy self-loop to local daemon port {} ({target}) is forbidden",
                target.port
            ),
        ));
    }
    Ok(())
}

async fn connect_outbound_with_timeout(
    outbound: &dyn OutboundHandler,
    target: &TargetAddr,
    conn: &ActiveConnection,
) -> io::Result<BoxedStream> {
    tokio::select! {
        biased;
        _ = conn.closed() => Err(io::Error::new(
            io::ErrorKind::ConnectionAborted,
            "connection closed by controller during outbound dial",
        )),
        res = tokio::time::timeout(OUTBOUND_CONNECT_TIMEOUT, outbound.connect_tcp(target)) => {
            match res {
                Ok(inner) => inner,
                Err(_) => Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!(
                        "outbound dial+handshake to {target} via '{}' timed out after {}s",
                        outbound.name(),
                        OUTBOUND_CONNECT_TIMEOUT.as_secs()
                    ),
                )),
            }
        }
    }
}

fn record_passive_proxy_delay(router: &Router, outbound: &dyn OutboundHandler, elapsed: Duration) {
    let leaf_outbound = outbound.name();
    if outbound.exit_category() == "PROXY" && !matches!(leaf_outbound, "DIRECT" | "REJECT") {
        router.record_passive_delay_if_stale(
            leaf_outbound,
            elapsed.as_millis().max(1) as u64,
            180_000,
        );
    }
}

async fn handle_mixed_conn(
    mut tcp: TcpStream,
    peer: SocketAddr,
    local_mixed_port: u16,
    router: Arc<RwLock<Arc<Router>>>,
    policy: Arc<RwLock<MixedInboundPolicy>>,
    hub: Arc<TelemetryHub>,
    shutdown: watch::Receiver<bool>,
) -> io::Result<()> {
    let mut first = [0u8; 1];
    let n = tokio::time::timeout(HANDSHAKE_TIMEOUT, tcp.peek(&mut first))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "mixed peek timeout"))??;
    if n == 0 {
        return Ok(());
    }

    if first[0] == 0x05 {
        handle_socks5(
            &mut tcp,
            peer,
            local_mixed_port,
            router,
            policy,
            hub,
            shutdown,
        )
        .await
    } else {
        let current_router = Arc::clone(&router.read());
        let snap_policy = policy.read().clone();
        handle_http_proxy(
            &mut tcp,
            peer,
            local_mixed_port,
            current_router,
            &snap_policy,
            hub,
        )
        .await
    }
}

fn socks5_reply_code_for_io_error(err: &io::Error) -> u8 {
    match err.kind() {
        io::ErrorKind::PermissionDenied => 0x02, // Connection not allowed by ruleset (REJECT)
        io::ErrorKind::NetworkUnreachable => 0x03, // Network unreachable
        io::ErrorKind::HostUnreachable | io::ErrorKind::NotFound => 0x04, // Host unreachable (DNS fail / unmapped Fake-IP)
        io::ErrorKind::ConnectionRefused => 0x05,                         // Connection refused
        io::ErrorKind::TimedOut => 0x06,                                  // TTL / timeout expired
        io::ErrorKind::AddrNotAvailable | io::ErrorKind::InvalidInput => 0x08, // Address type not supported
        _ => 0x01, // General SOCKS server failure
    }
}

fn http_error_response_for_io_error(err: &io::Error) -> &'static [u8] {
    match err.kind() {
        io::ErrorKind::PermissionDenied => {
            b"HTTP/1.1 403 Forbidden\r\nX-Proxy-Error: rejected-by-rule\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        }
        io::ErrorKind::HostUnreachable | io::ErrorKind::NotFound => {
            b"HTTP/1.1 502 Bad Gateway\r\nX-Proxy-Error: dns-resolution-failed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        }
        io::ErrorKind::TimedOut => {
            b"HTTP/1.1 504 Gateway Timeout\r\nX-Proxy-Error: upstream-timeout\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        }
        _ => {
            b"HTTP/1.1 502 Bad Gateway\r\nX-Proxy-Error: proxy-upstream-failed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        }
    }
}

async fn negotiate_socks5_and_read_target(
    tcp: &mut TcpStream,
    policy: &MixedInboundPolicy,
) -> io::Result<(u8, TargetAddr)> {
    let ver = tcp.read_u8().await?;
    if ver != 0x05 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid SOCKS5 version",
        ));
    }

    let nmethods = tcp.read_u8().await? as usize;
    if nmethods == 0 {
        let _ = tcp.write_all(&[0x05, 0xFF]).await;
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "SOCKS5 greeting offered zero authentication methods",
        ));
    }

    let mut methods = vec![0u8; nmethods];
    tcp.read_exact(&mut methods).await?;

    if policy.requires_auth() {
        if !methods.contains(&0x02) {
            let _ = tcp.write_all(&[0x05, 0xFF]).await;
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "SOCKS5 client did not offer RFC 1929 Username/Password authentication (0x02)",
            ));
        }
        tcp.write_all(&[0x05, 0x02]).await?;

        // RFC 1929 Username/Password Subnegotiation (`VER = 0x01`)
        let auth_ver = tcp.read_u8().await?;
        if auth_ver != 0x01 {
            let _ = tcp.write_all(&[0x01, 0x01]).await;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid RFC 1929 auth subnegotiation version",
            ));
        }
        let ulen = tcp.read_u8().await? as usize;
        let mut ubytes = vec![0u8; ulen];
        tcp.read_exact(&mut ubytes).await?;
        let plen = tcp.read_u8().await? as usize;
        let mut pbytes = vec![0u8; plen];
        tcp.read_exact(&mut pbytes).await?;

        let uname = std::str::from_utf8(&ubytes).unwrap_or("");
        let passwd = std::str::from_utf8(&pbytes).unwrap_or("");
        if !policy.verify_credentials(uname, passwd) {
            let _ = tcp.write_all(&[0x01, 0x01]).await;
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "SOCKS5 authentication failed",
            ));
        }
        tcp.write_all(&[0x01, 0x00]).await?;
    } else {
        if !methods.contains(&0x00) {
            let _ = tcp.write_all(&[0x05, 0xFF]).await;
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "SOCKS5 client did not offer No-Auth (0x00)",
            ));
        }
        tcp.write_all(&[0x05, 0x00]).await?;
    }

    let mut req_hdr = [0u8; 3];
    tcp.read_exact(&mut req_hdr).await?;
    if req_hdr[0] != 0x05 || req_hdr[2] != 0x00 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid SOCKS5 request header",
        ));
    }
    let cmd = req_hdr[1];
    let raw_target = TargetAddr::read_socks5(tcp).await?;
    Ok((cmd, raw_target))
}

async fn enforce_post_route_target_policy(
    peer_addr: SocketAddr,
    local_mixed_port: u16,
    policy: &MixedInboundPolicy,
    router: &Router,
    decision: &crate::router::RouteDecision,
) -> io::Result<()> {
    reject_forbidden_proxy_target(peer_addr, local_mixed_port, policy, &decision.target)?;
    if decision.outbound.exit_category() == "DIRECT"
        && let HostName::Domain(domain) = &decision.target.host
    {
        let resolved_ips = match router.dns().resolve_direct_ips(domain).await {
            Ok(ips) => ips,
            Err(_) => {
                crate::router::geodata::resolve_host_bypassing_fake_ip(domain, decision.target.port)
                    .await
                    .map(|sas| sas.into_iter().map(|sa| sa.ip()).collect())
                    .unwrap_or_default()
            }
        };
        for ip in resolved_ips {
            let ip_target = TargetAddr::from(SocketAddr::new(ip, decision.target.port));
            reject_forbidden_proxy_target(peer_addr, local_mixed_port, policy, &ip_target)?;
        }
    }
    Ok(())
}

/// Relay `tcp <-> tracked` while preserving 0-RTT payload coalescing for client-speaks-first
/// protocols (HTTP, TLS) and flushing pending proxy target headers after `15ms` when the client
/// waits for a server banner first (SSH, SMTP, FTP, MySQL).
async fn relay_bidirectional_coalesced(
    tcp: &mut TcpStream,
    tracked: &mut crate::tracker::TrackedStream<BoxedStream>,
    conn_entry: &ActiveConnection,
    already_flushed_initial: bool,
) -> io::Result<()> {
    if !already_flushed_initial {
        tokio::select! {
            biased;
            _ = conn_entry.closed() => return Ok(()),
            res = tcp.readable() => {
                res?;
            }
            () = tokio::time::sleep(Duration::from_millis(15)) => {
                tracked.flush().await?;
            }
        }
    }
    tokio::select! {
        res = tokio::io::copy_bidirectional_with_sizes(tcp, tracked, 64 * 1024, 64 * 1024) => {
            let _ = res?;
        }
        _ = conn_entry.closed() => {}
    }
    Ok(())
}

enum MixedTcpSniffResult {
    EofEmpty,
    Sniffed {
        domain: String,
        protocol: SniffedProtocol,
        payload: Vec<u8>,
    },
    NoDomain {
        payload: Vec<u8>,
    },
}

async fn sniff_tcp_stream_initial_payload(
    tcp: &mut TcpStream,
    initial_bytes: &[u8],
    timeout: Duration,
    allow_tls: bool,
    allow_http: bool,
) -> MixedTcpSniffResult {
    let mut buf = Vec::with_capacity(initial_bytes.len().max(1024));
    if !initial_bytes.is_empty() {
        buf.extend_from_slice(initial_bytes);
        match sniff_tcp_protocol(&buf, allow_tls, allow_http) {
            SniffOutcomeWithProto::Domain { domain, protocol } => {
                return MixedTcpSniffResult::Sniffed {
                    domain,
                    protocol,
                    payload: buf,
                };
            }
            SniffOutcomeWithProto::NoHostname => {
                return MixedTcpSniffResult::NoDomain { payload: buf };
            }
            SniffOutcomeWithProto::NeedMoreBytes => {
                if buf.len() >= MAX_SNIFF_BYTES {
                    return MixedTcpSniffResult::NoDomain { payload: buf };
                }
            }
        }
    }

    let deadline = tokio::time::Instant::now() + timeout;
    let mut tmp = [0u8; 4096];
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return MixedTcpSniffResult::NoDomain { payload: buf };
        }
        let max_read = MAX_SNIFF_BYTES.saturating_sub(buf.len()).min(tmp.len());
        if max_read == 0 {
            return MixedTcpSniffResult::NoDomain { payload: buf };
        }
        match tokio::time::timeout(remaining, tcp.read(&mut tmp[..max_read])).await {
            Ok(Ok(0)) => {
                return if buf.is_empty() {
                    MixedTcpSniffResult::EofEmpty
                } else {
                    MixedTcpSniffResult::NoDomain { payload: buf }
                };
            }
            Ok(Ok(n)) => {
                buf.extend_from_slice(&tmp[..n]);
                match sniff_tcp_protocol(&buf, allow_tls, allow_http) {
                    SniffOutcomeWithProto::Domain { domain, protocol } => {
                        return MixedTcpSniffResult::Sniffed {
                            domain,
                            protocol,
                            payload: buf,
                        };
                    }
                    SniffOutcomeWithProto::NoHostname => {
                        return MixedTcpSniffResult::NoDomain { payload: buf };
                    }
                    SniffOutcomeWithProto::NeedMoreBytes => {
                        if buf.len() >= MAX_SNIFF_BYTES {
                            return MixedTcpSniffResult::NoDomain { payload: buf };
                        }
                    }
                }
            }
            Ok(Err(_)) | Err(_) => {
                return MixedTcpSniffResult::NoDomain { payload: buf };
            }
        }
    }
}

fn resolve_mixed_dial_target(
    raw_target: &TargetAddr,
    decision: &crate::router::RouteDecision,
    sniffer_cfg: &crate::config::SnifferConfig,
    router: &Router,
    sniffed_real_ip: Option<&(String, SniffedProtocol)>,
) -> (TargetAddr, Option<RealIpTlsOverrideTracker>) {
    resolve_real_ip_tcp_dial_target(
        raw_target,
        &decision.target,
        decision.outbound.exit_category(),
        sniffer_cfg,
        router.sniff_override_guard(),
        sniffed_real_ip,
    )
}

struct UdpAssocCleanupGuard {
    udp_task: JoinHandle<()>,
    udp_nat: Arc<crate::inbound::udp_nat::UdpNatManager>,
}

impl Drop for UdpAssocCleanupGuard {
    fn drop(&mut self) {
        self.udp_task.abort();
        let _ = self.udp_nat.shutdown();
    }
}

async fn handle_socks5(
    tcp: &mut TcpStream,
    peer: SocketAddr,
    local_mixed_port: u16,
    router: Arc<RwLock<Arc<Router>>>,
    policy: Arc<RwLock<MixedInboundPolicy>>,
    hub: Arc<TelemetryHub>,
    mut shutdown: watch::Receiver<bool>,
) -> io::Result<()> {
    let handshake_policy = policy.read().clone();
    let (cmd, raw_target) = tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        negotiate_socks5_and_read_target(tcp, &handshake_policy),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "SOCKS5 handshake timed out"))??;

    match cmd {
        0x01 => {
            // TCP CONNECT
            let router = Arc::clone(&router.read());
            let snap_policy = policy.read().clone();
            let policy = &snap_policy;
            if let Err(err) =
                reject_forbidden_proxy_target(peer, local_mixed_port, policy, &raw_target)
            {
                hub.push_log(
                    "warn",
                    format!("[SOCKS5] Blocked forbidden target {raw_target} from {peer}: {err}"),
                );
                let rep = socks5_reply_code_for_io_error(&err);
                let _ = tcp
                    .write_all(&[0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .await;
                return Err(err);
            }

            let sniffer_cfg = router.sniffer();
            let should_sniff_real_ip = raw_target.host.as_ip().is_some_and(|dst_ip| {
                !router.dns().is_fake_ip(dst_ip)
                    && sniffer_cfg.should_sniff_real_ip_tcp(dst_ip, raw_target.port)
            });

            let mut reply_sent = false;
            let mut prefetched_payload = Vec::new();
            let mut sniffed_real_ip: Option<(String, SniffedProtocol)> = None;
            let route_target = if should_sniff_real_ip {
                // Reply with SOCKS5 success so the client immediately transmits its TLS ClientHello
                // or HTTP request for lossless SNI / Host sniffing (parity with TUN inbound).
                tcp.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .await?;
                reply_sent = true;

                let allow_tls = sniffer_cfg.should_sniff_tls_port(raw_target.port);
                let allow_http = sniffer_cfg.should_sniff_http_port(raw_target.port);
                match sniff_tcp_stream_initial_payload(
                    tcp,
                    &[],
                    MIXED_SNIFF_TIMEOUT,
                    allow_tls,
                    allow_http,
                )
                .await
                {
                    MixedTcpSniffResult::EofEmpty => return Ok(()),
                    MixedTcpSniffResult::Sniffed {
                        domain,
                        protocol,
                        payload,
                    } => {
                        prefetched_payload = payload;
                        let target = TargetAddr::new_domain(domain.clone(), raw_target.port)
                            .unwrap_or_else(|_| raw_target.clone());
                        sniffed_real_ip = Some((domain, protocol));
                        target
                    }
                    MixedTcpSniffResult::NoDomain { payload } => {
                        prefetched_payload = payload;
                        raw_target.clone()
                    }
                }
            } else {
                raw_target.clone()
            };

            let decision = router
                .route_async_with_context(
                    Some(peer.ip()),
                    Some(peer),
                    crate::platform::process::SocketTransport::Tcp,
                    &route_target,
                )
                .await;
            if let Err(err) =
                enforce_post_route_target_policy(peer, local_mixed_port, policy, &router, &decision)
                    .await
            {
                hub.push_log(
                    "warn",
                    format!(
                        "[SOCKS5] Blocked forbidden resolved target {} from {peer}: {err}",
                        decision.target
                    ),
                );
                if !reply_sent {
                    let rep = socks5_reply_code_for_io_error(&err);
                    let _ = tcp
                        .write_all(&[0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                        .await;
                }
                return Err(err);
            }
            let (dial_target, sniff_override_tracker) = resolve_mixed_dial_target(
                &raw_target,
                &decision,
                &sniffer_cfg,
                &router,
                sniffed_real_ip.as_ref(),
            );
            let conn_guard = hub.register_connection_with_outbound_guard_sniffed(
                "Mixed(SOCKS5)",
                "tcp",
                Some(peer),
                &decision.target,
                decision.restored_from_fake_ip.map(|ip| ip.to_string()),
                &decision.rule_type,
                &decision.rule_payload,
                decision.chains.clone(),
                decision.outbound.as_ref(),
                sniffed_real_ip.is_some(),
            );
            let conn_entry = Arc::clone(conn_guard.connection());
            let mut sniff_override_guard = sniff_override_tracker.map(|tracker| {
                RealIpTlsOverrideGuard::new(
                    Arc::clone(router.sniff_override_guard()),
                    Arc::clone(&hub),
                    Arc::clone(&conn_entry),
                    tracker,
                )
            });
            hub.push_log(
                "info",
                format!(
                    "[SOCKS5] {} -> {} [{}] via {} ({})",
                    peer,
                    decision.target,
                    decision.rule_type,
                    decision.outbound.name(),
                    decision.outbound.exit_category()
                ),
            );

            let dial_start = Instant::now();
            let outbound_stream = match connect_outbound_with_timeout(
                decision.outbound.as_ref(),
                &dial_target,
                &conn_entry,
            )
            .await
            {
                Ok(s) => s,
                Err(err) => {
                    if let Some(g) = sniff_override_guard.as_mut() {
                        g.mark_dial_failed();
                    }
                    conn_guard.record_failed(&err.to_string());
                    if !reply_sent {
                        let rep = socks5_reply_code_for_io_error(&err);
                        let _ = tcp
                            .write_all(&[0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                            .await;
                    }
                    return Err(err);
                }
            };
            conn_guard.mark_established();
            if let Some(g) = sniff_override_guard.as_mut() {
                g.mark_established();
            }
            record_passive_proxy_delay(&router, decision.outbound.as_ref(), dial_start.elapsed());

            if !reply_sent {
                // Success reply: BND.ADDR 0.0.0.0:0
                tcp.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .await?;
            }
            let mut tracked = conn_guard.into_tracked_stream(outbound_stream);
            let had_prefetched = !prefetched_payload.is_empty();
            if had_prefetched {
                tracked.write_all(&prefetched_payload).await?;
                tracked.flush().await?;
            }

            relay_bidirectional_coalesced(tcp, &mut tracked, &conn_entry, had_prefetched).await
        }
        0x03 => {
            // UDP ASSOCIATE: bind ephemeral relay socket on the local interface facing `peer`
            if *shutdown.borrow() {
                return Ok(());
            }
            let expected_client_ip = canonical_ip(peer.ip());
            if let Some(hint_ip) = raw_target.host.as_ip() {
                let hint_canon = canonical_ip(hint_ip);
                if !hint_canon.is_unspecified() && hint_canon != expected_client_ip {
                    let _ = tcp
                        .write_all(&[0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                        .await;
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        format!(
                            "SOCKS5 UDP ASSOCIATE client hint IP {hint_canon} mismatches TCP peer IP {expected_client_ip}"
                        ),
                    ));
                }
            }
            let initial_port_lock = (raw_target.port != 0).then_some(raw_target.port);

            let local_ip = tcp
                .local_addr()
                .map(|a| canonical_ip(a.ip()))
                .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));
            let udp_sock = Arc::new(UdpSocket::bind(SocketAddr::new(local_ip, 0)).await?);
            let bound = udp_sock.local_addr()?;

            let mut reply = BytesMut::with_capacity(22);
            reply.put_slice(&[0x05, 0x00, 0x00]);
            TargetAddr::from(bound).encode_socks5(&mut reply)?;
            tcp.write_all(&reply).await?;

            let udp_reply_for_sink = Arc::clone(&udp_sock);
            let reply_sem = Arc::new(Semaphore::new(64));
            let udp_nat = crate::inbound::udp_nat::UdpNatManager::new(
                "Mixed(SOCKS5-UDP)",
                64,
                Arc::clone(&hub),
                Arc::new(move |client_udp_addr, return_src_target, resp| {
                    let mut pkt = BytesMut::with_capacity(24 + resp.len());
                    pkt.put_slice(&[0x00, 0x00, 0x00]);
                    if return_src_target.encode_socks5(&mut pkt).is_ok() {
                        pkt.put_slice(&resp);
                        match udp_reply_for_sink.try_send_to(&pkt, client_udp_addr) {
                            Ok(_) => {}
                            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                                if let Ok(permit) = Arc::clone(&reply_sem).try_acquire_owned() {
                                    let sock = Arc::clone(&udp_reply_for_sink);
                                    let pkt_bytes = pkt.freeze();
                                    tokio::spawn(async move {
                                        let _permit = permit;
                                        let _ = sock.send_to(&pkt_bytes, client_udp_addr).await;
                                    });
                                }
                            }
                            Err(_) => {}
                        }
                    }
                }),
            );

            let (udp_done_tx, mut udp_done_rx) = tokio::sync::oneshot::channel::<()>();
            let udp_task = {
                let udp_clone = Arc::clone(&udp_sock);
                let router_slot = Arc::clone(&router);
                let policy_slot = Arc::clone(&policy);
                let inflight_sem = Arc::new(Semaphore::new(MAX_UDP_ASSOC_INFLIGHT));
                let nat_clone = Arc::clone(&udp_nat);
                tokio::spawn(async move {
                    let _done_guard = udp_done_tx;
                    let mut buf = vec![0u8; 65535];
                    let mut locked_client_port: Option<u16> = initial_port_lock;
                    let mut pkt_tasks = JoinSet::<()>::new();
                    while let Ok((n, client_udp_addr)) = udp_clone.recv_from(&mut buf).await {
                        while pkt_tasks.try_join_next().is_some() {}
                        // Strictly enforce source IP association with the authenticated TCP peer!
                        if canonical_ip(client_udp_addr.ip()) != expected_client_ip {
                            continue;
                        }
                        if let Some(expected_port) = locked_client_port
                            && client_udp_addr.port() != expected_port
                        {
                            continue;
                        }
                        // Evaluate the live policy & router on each datagram so hot reloads of
                        // `allow-lan`, CIDR ACLs, `blocked_local_ports`, and routing rules apply
                        // immediately to long-lived SOCKS5 UDP ASSOCIATE sessions.
                        let current_policy = policy_slot.read().clone();
                        if !current_policy.allows_peer(peer.ip()) {
                            tracing::debug!(
                                "[SOCKS5-UDP] terminating association for revoked peer {peer} after policy reload"
                            );
                            let _ = nat_clone.reset_all_sessions();
                            break;
                        }
                        if n < 4 || buf[0] != 0 || buf[1] != 0 || buf[2] != 0 {
                            continue; // Ignore fragmented or malformed SOCKS5 UDP frames
                        }
                        let Ok((raw_dst, hdr_used)) = TargetAddr::decode_socks5_slice(&buf[3..n])
                        else {
                            continue;
                        };
                        if let Err(err) = reject_forbidden_proxy_target(
                            peer,
                            local_mixed_port,
                            &current_policy,
                            &raw_dst,
                        ) {
                            tracing::debug!(
                                "[SOCKS5-UDP] dropped forbidden target {raw_dst} from {peer}: {err}"
                            );
                            continue;
                        }
                        if locked_client_port.is_none() {
                            locked_client_port = Some(client_udp_addr.port());
                        }

                        let current_router = Arc::clone(&router_slot.read());
                        let payload = buf[3 + hdr_used..n].to_vec();
                        let payload = if let HostName::Ip(dst_ip) = raw_dst.host {
                            let raw_dst_sock = SocketAddr::new(dst_ip, raw_dst.port);
                            match nat_clone.try_send_fast(
                                client_udp_addr,
                                raw_dst_sock,
                                current_router.epoch(),
                                payload,
                            ) {
                                Ok(()) => continue,
                                Err(payload) => payload,
                            }
                        } else {
                            payload
                        };

                        let Ok(permit) = Arc::clone(&inflight_sem).try_acquire_owned() else {
                            continue;
                        };

                        let router_for_pkt = current_router;
                        let nat_inner = Arc::clone(&nat_clone);
                        let policy_for_pkt = current_policy;
                        pkt_tasks.spawn(async move {
                            let _permit = permit;
                            let route_epoch = router_for_pkt.epoch();
                            let resolved =
                                crate::inbound::udp_nat::route_udp_datagram_with_quic_sniff(
                                    &router_for_pkt,
                                    client_udp_addr,
                                    &raw_dst,
                                    &payload,
                                )
                                .await;
                            if enforce_post_route_target_policy(
                                peer,
                                local_mixed_port,
                                &policy_for_pkt,
                                &router_for_pkt,
                                &resolved.decision,
                            )
                            .await
                            .is_err()
                            {
                                return;
                            }
                            nat_inner
                                .send_datagram_with_options(
                                    client_udp_addr,
                                    raw_dst,
                                    resolved.decision.restored_from_fake_ip,
                                    resolved.decision.target,
                                    resolved.dial_target,
                                    &resolved.decision.rule_type,
                                    &resolved.decision.rule_payload,
                                    resolved.decision.chains,
                                    resolved.decision.outbound,
                                    payload,
                                    route_epoch,
                                    resolved.sniffed,
                                )
                                .await;
                        });
                    }
                })
            };
            let _cleanup_guard = UdpAssocCleanupGuard { udp_task, udp_nat };

            // Keep UDP association alive until the TCP control stream closes,
            // the mixed inbound shuts down, or `udp_task` terminates.
            if !*shutdown.borrow() {
                let mut drain = [0u8; 64];
                loop {
                    tokio::select! {
                        biased;
                        _ = shutdown.wait_for(|&s| s) => break,
                        _ = &mut udp_done_rx => break,
                        res = tcp.read(&mut drain) => {
                            match res {
                                Ok(0) | Err(_) => break,
                                Ok(_) => continue,
                            }
                        }
                    }
                }
            }
            Ok(())
        }
        other => {
            let _ = tcp
                .write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await;
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("unsupported SOCKS5 command 0x{other:02x}"),
            ))
        }
    }
}

fn check_http_proxy_auth<'a>(
    header_lines: impl Iterator<Item = &'a str>,
    policy: &MixedInboundPolicy,
) -> bool {
    if !policy.requires_auth() {
        return true;
    }
    for line in header_lines {
        if let Some((k, v)) = line.split_once(':')
            && k.trim().eq_ignore_ascii_case("proxy-authorization")
        {
            let v_trim = v.trim();
            let Some(b64) = v_trim
                .strip_prefix("Basic ")
                .or_else(|| v_trim.strip_prefix("basic "))
            else {
                continue;
            };
            if let Ok(decoded) = STANDARD.decode(b64.trim())
                && let Ok(text) = std::str::from_utf8(&decoded)
                && let Some((user, pass)) = text.split_once(':')
                && policy.verify_credentials(user, pass)
            {
                return true;
            }
        }
    }
    false
}

fn parse_host_or_authority_with_default_port(
    raw: &str,
    default_port: u16,
) -> io::Result<TargetAddr> {
    let trimmed = raw.trim();
    if let Some(inner) = trimmed.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
        let v6: std::net::Ipv6Addr = inner.parse().map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid bracketed IPv6 host '{trimmed}': {e}"),
            )
        })?;
        return Ok(TargetAddr::new_ip(IpAddr::V6(v6), default_port));
    }
    if trimmed.contains(':') {
        trimmed.parse()
    } else {
        TargetAddr::new_domain(trimmed, default_port)
    }
}

fn extract_raw_http_origin_path(uri_part: &str) -> String {
    let after_scheme = match uri_part.find("://") {
        Some(idx) => &uri_part[idx + 3..],
        None => uri_part,
    };
    let tail = match after_scheme.find(['/', '?', '#']) {
        Some(idx) => &after_scheme[idx..],
        None => return "/".to_string(),
    };
    let without_frag = match tail.find('#') {
        Some(idx) => &tail[..idx],
        None => tail,
    };
    if without_frag.is_empty() {
        "/".to_string()
    } else if without_frag.starts_with('?') {
        format!("/{without_frag}")
    } else {
        without_frag.to_string()
    }
}

async fn handle_http_proxy(
    tcp: &mut TcpStream,
    peer: SocketAddr,
    local_mixed_port: u16,
    router: Arc<Router>,
    policy: &MixedInboundPolicy,
    hub: Arc<TelemetryHub>,
) -> io::Result<()> {
    let mut req_buf = Vec::with_capacity(2048);
    let mut temp = [0u8; 2048];
    let deadline = tokio::time::Instant::now() + HANDSHAKE_TIMEOUT;
    let header_end = loop {
        if req_buf.len() > 16 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP proxy header exceeds 16 KiB",
            ));
        }
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "HTTP header read timeout",
            ));
        }
        let n = tokio::time::timeout(remaining, tcp.read(&mut temp))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "HTTP header read timeout"))??;
        if n == 0 {
            return Ok(());
        }
        req_buf.extend_from_slice(&temp[..n]);
        if let Some(pos) = find_double_crlf(&req_buf) {
            break pos;
        }
    };

    let header_bytes = &req_buf[..header_end];
    let trailing_body = &req_buf[header_end + 4..];
    let header_text = std::str::from_utf8(header_bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "non-ASCII HTTP header"))?;

    let mut lines = header_text.split("\r\n");
    let req_line = lines
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "empty HTTP request line"))?;
    let mut parts = req_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing HTTP method"))?;
    let uri_part = parts
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing HTTP request URI"))?;
    let version = parts.next().unwrap_or("HTTP/1.1");

    if !check_http_proxy_auth(lines.clone(), policy) {
        let _ = tcp
            .write_all(
                b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"rust-clash\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            )
            .await;
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "HTTP proxy authentication required",
        ));
    }

    if method.eq_ignore_ascii_case("CONNECT") {
        let raw_target = parse_host_or_authority_with_default_port(uri_part, 443)?;
        if let Err(err) = reject_forbidden_proxy_target(peer, local_mixed_port, policy, &raw_target)
        {
            hub.push_log(
                "warn",
                format!("[HTTP-CONNECT] Blocked forbidden target {raw_target} from {peer}: {err}"),
            );
            let _ = tcp.write_all(http_error_response_for_io_error(&err)).await;
            return Err(err);
        }

        let sniffer_cfg = router.sniffer();
        let should_sniff_real_ip = raw_target.host.as_ip().is_some_and(|dst_ip| {
            !router.dns().is_fake_ip(dst_ip)
                && sniffer_cfg.should_sniff_real_ip_tcp(dst_ip, raw_target.port)
        });

        let mut reply_sent = false;
        let mut prefetched_payload = Vec::new();
        let mut sniffed_real_ip: Option<(String, SniffedProtocol)> = None;
        let route_target = if should_sniff_real_ip {
            // Acknowledge CONNECT early so the client sends its TLS ClientHello / HTTP request
            // for lossless SNI / Host sniffing (parity with TUN inbound).
            tcp.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await?;
            reply_sent = true;

            let allow_tls = sniffer_cfg.should_sniff_tls_port(raw_target.port);
            let allow_http = sniffer_cfg.should_sniff_http_port(raw_target.port);
            match sniff_tcp_stream_initial_payload(
                tcp,
                trailing_body,
                MIXED_SNIFF_TIMEOUT,
                allow_tls,
                allow_http,
            )
            .await
            {
                MixedTcpSniffResult::EofEmpty => return Ok(()),
                MixedTcpSniffResult::Sniffed {
                    domain,
                    protocol,
                    payload,
                } => {
                    prefetched_payload = payload;
                    let target = TargetAddr::new_domain(domain.clone(), raw_target.port)
                        .unwrap_or_else(|_| raw_target.clone());
                    sniffed_real_ip = Some((domain, protocol));
                    target
                }
                MixedTcpSniffResult::NoDomain { payload } => {
                    prefetched_payload = payload;
                    raw_target.clone()
                }
            }
        } else {
            if !trailing_body.is_empty() {
                prefetched_payload.extend_from_slice(trailing_body);
            }
            raw_target.clone()
        };

        let decision = router
            .route_async_with_context(
                Some(peer.ip()),
                Some(peer),
                crate::platform::process::SocketTransport::Tcp,
                &route_target,
            )
            .await;
        if let Err(err) =
            enforce_post_route_target_policy(peer, local_mixed_port, policy, &router, &decision)
                .await
        {
            hub.push_log(
                "warn",
                format!(
                    "[HTTP-CONNECT] Blocked forbidden resolved target {} from {peer}: {err}",
                    decision.target
                ),
            );
            if !reply_sent {
                let _ = tcp.write_all(http_error_response_for_io_error(&err)).await;
            }
            return Err(err);
        }
        let (dial_target, sniff_override_tracker) = resolve_mixed_dial_target(
            &raw_target,
            &decision,
            &sniffer_cfg,
            &router,
            sniffed_real_ip.as_ref(),
        );
        let conn_guard = hub.register_connection_with_outbound_guard_sniffed(
            "Mixed(HTTP-CONNECT)",
            "tcp",
            Some(peer),
            &decision.target,
            decision.restored_from_fake_ip.map(|ip| ip.to_string()),
            &decision.rule_type,
            &decision.rule_payload,
            decision.chains.clone(),
            decision.outbound.as_ref(),
            sniffed_real_ip.is_some(),
        );
        let conn_entry = Arc::clone(conn_guard.connection());
        let mut sniff_override_guard = sniff_override_tracker.map(|tracker| {
            RealIpTlsOverrideGuard::new(
                Arc::clone(router.sniff_override_guard()),
                Arc::clone(&hub),
                Arc::clone(&conn_entry),
                tracker,
            )
        });
        hub.push_log(
            "info",
            format!(
                "[HTTP-CONNECT] {} -> {} [{}] via {} ({})",
                peer,
                decision.target,
                decision.rule_type,
                decision.outbound.name(),
                decision.outbound.exit_category()
            ),
        );

        let dial_start = Instant::now();
        let outbound_stream = match connect_outbound_with_timeout(
            decision.outbound.as_ref(),
            &dial_target,
            &conn_entry,
        )
        .await
        {
            Ok(s) => s,
            Err(err) => {
                if let Some(g) = sniff_override_guard.as_mut() {
                    g.mark_dial_failed();
                }
                conn_guard.record_failed(&err.to_string());
                if !reply_sent {
                    let _ = tcp.write_all(http_error_response_for_io_error(&err)).await;
                }
                return Err(err);
            }
        };
        conn_guard.mark_established();
        if let Some(g) = sniff_override_guard.as_mut() {
            g.mark_established();
        }
        record_passive_proxy_delay(&router, decision.outbound.as_ref(), dial_start.elapsed());

        if !reply_sent {
            tcp.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await?;
        }
        let mut tracked = conn_guard.into_tracked_stream(outbound_stream);
        let had_prefetched = !prefetched_payload.is_empty();
        if had_prefetched {
            tracked.write_all(&prefetched_payload).await?;
            tracked.flush().await?;
        }

        relay_bidirectional_coalesced(tcp, &mut tracked, &conn_entry, had_prefetched).await
    } else {
        // Plain HTTP proxy request (e.g. `GET http://example.com/foo HTTP/1.1`)
        if uri_part
            .as_bytes()
            .get(..8)
            .is_some_and(|p| p.eq_ignore_ascii_case(b"https://"))
        {
            let _ = tcp
                .write_all(
                    b"HTTP/1.1 400 Bad Request\r\nX-Proxy-Error: https-uri-requires-connect\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await;
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "plain HTTP proxy request cannot use https:// scheme without CONNECT",
            ));
        }

        let (raw_target, origin_path) = if uri_part
            .as_bytes()
            .get(..7)
            .is_some_and(|p| p.eq_ignore_ascii_case(b"http://"))
        {
            let url = Url::parse(uri_part).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("invalid HTTP proxy URL: {e}"),
                )
            })?;
            let host = url.host_str().ok_or_else(|| {
                io::Error::new(
                    io::Error::other("missing host in HTTP proxy URL").kind(),
                    "missing host in HTTP proxy URL",
                )
            })?;
            let port = url.port_or_known_default().unwrap_or(80);
            let p = extract_raw_http_origin_path(uri_part);
            let clean_host = host.trim_start_matches('[').trim_end_matches(']');
            (TargetAddr::new_domain(clean_host, port)?, p)
        } else {
            // Fallback to Host header
            let mut host_hdr = None;
            for line in lines.clone() {
                if let Some((k, v)) = line.split_once(':')
                    && k.trim().eq_ignore_ascii_case("host")
                {
                    host_hdr = Some(v.trim());
                    break;
                }
            }
            let host_val = host_hdr.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "missing Host header in HTTP request",
                )
            })?;
            let target = parse_host_or_authority_with_default_port(host_val, 80)?;
            (target, uri_part.to_string())
        };

        // Validate HTTP/1.1 framing headers before dialing so CL/TE smuggling or invalid
        // Content-Length / Transfer-Encoding headers are rejected cleanly with 400 Bad Request.
        let mut has_upgrade_header = false;
        let mut conn_has_upgrade_token = false;
        let mut has_transfer_encoding = false;
        let mut last_te_coding: Option<String> = None;
        let mut invalid_transfer_encoding = false;
        let mut content_length: Option<u64> = None;
        let mut nominated_hop_headers: Vec<String> = Vec::new();
        for line in lines.clone() {
            let Some((k, v)) = line.split_once(':') else {
                continue;
            };
            let k_trim = k.trim();
            let v_trim = v.trim();
            if k_trim.eq_ignore_ascii_case("upgrade") && !v_trim.is_empty() {
                has_upgrade_header = true;
            } else if k_trim.eq_ignore_ascii_case("transfer-encoding") {
                has_transfer_encoding = true;
                let mut saw_any = false;
                for coding in v_trim.split(',') {
                    let tok = coding
                        .split(';')
                        .next()
                        .unwrap_or("")
                        .trim()
                        .to_ascii_lowercase();
                    if tok.is_empty() {
                        invalid_transfer_encoding = true;
                    } else {
                        saw_any = true;
                        last_te_coding = Some(tok);
                    }
                }
                if !saw_any {
                    invalid_transfer_encoding = true;
                }
            } else if k_trim.eq_ignore_ascii_case("content-length") {
                let Ok(parsed_len) = v_trim.parse::<u64>() else {
                    let _ = tcp
                        .write_all(
                            b"HTTP/1.1 400 Bad Request\r\nX-Proxy-Error: invalid-content-length\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        )
                        .await;
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid Content-Length in plain HTTP proxy request",
                    ));
                };
                if let Some(prev) = content_length
                    && prev != parsed_len
                {
                    let _ = tcp
                        .write_all(
                            b"HTTP/1.1 400 Bad Request\r\nX-Proxy-Error: conflicting-content-length\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        )
                        .await;
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "conflicting Content-Length headers in plain HTTP proxy request",
                    ));
                }
                content_length = Some(parsed_len);
            } else if k_trim.eq_ignore_ascii_case("connection") {
                for token in v_trim.split(',') {
                    let tok = token.trim().to_ascii_lowercase();
                    if tok == "upgrade" {
                        conn_has_upgrade_token = true;
                    } else if !tok.is_empty() {
                        nominated_hop_headers.push(tok);
                    }
                }
            } else if k_trim.eq_ignore_ascii_case("proxy-connection") {
                for token in v_trim.split(',') {
                    let tok = token.trim().to_ascii_lowercase();
                    if !tok.is_empty() && tok != "upgrade" {
                        nominated_hop_headers.push(tok);
                    }
                }
            }
        }
        if has_transfer_encoding && content_length.is_some() {
            let _ = tcp
                .write_all(
                    b"HTTP/1.1 400 Bad Request\r\nX-Proxy-Error: conflicting-framing\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "rejecting request with both Transfer-Encoding and Content-Length",
            ));
        }
        if has_transfer_encoding
            && (invalid_transfer_encoding || last_te_coding.as_deref() != Some("chunked"))
        {
            let _ = tcp
                .write_all(
                    b"HTTP/1.1 400 Bad Request\r\nX-Proxy-Error: unsupported-transfer-encoding\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "plain HTTP Transfer-Encoding must terminate in chunked",
            ));
        }
        let is_upgrade = has_upgrade_header && conn_has_upgrade_token;

        if let Err(err) = reject_forbidden_proxy_target(peer, local_mixed_port, policy, &raw_target)
        {
            hub.push_log(
                "warn",
                format!("[HTTP] Blocked forbidden target {raw_target} from {peer}: {err}"),
            );
            let _ = tcp.write_all(http_error_response_for_io_error(&err)).await;
            return Err(err);
        }

        let sniffer_cfg = router.sniffer();
        let mut sniffed_real_ip: Option<(String, SniffedProtocol)> = None;
        let route_target = if raw_target.host.as_ip().is_some_and(|dst_ip| {
            !router.dns().is_fake_ip(dst_ip)
                && sniffer_cfg.should_sniff_real_ip_tcp(dst_ip, raw_target.port)
                && sniffer_cfg.should_sniff_http_port(raw_target.port)
        }) {
            match sniff_tcp_protocol(&req_buf[..header_end + 4], false, true) {
                SniffOutcomeWithProto::Domain { domain, protocol } => {
                    let target = TargetAddr::new_domain(domain.clone(), raw_target.port)
                        .unwrap_or_else(|_| raw_target.clone());
                    sniffed_real_ip = Some((domain, protocol));
                    target
                }
                SniffOutcomeWithProto::NeedMoreBytes | SniffOutcomeWithProto::NoHostname => {
                    raw_target.clone()
                }
            }
        } else {
            raw_target.clone()
        };

        let decision = router
            .route_async_with_context(
                Some(peer.ip()),
                Some(peer),
                crate::platform::process::SocketTransport::Tcp,
                &route_target,
            )
            .await;
        if let Err(err) =
            enforce_post_route_target_policy(peer, local_mixed_port, policy, &router, &decision)
                .await
        {
            hub.push_log(
                "warn",
                format!(
                    "[HTTP] Blocked forbidden resolved target {} from {peer}: {err}",
                    decision.target
                ),
            );
            let _ = tcp.write_all(http_error_response_for_io_error(&err)).await;
            return Err(err);
        }
        let (dial_target, _) = resolve_mixed_dial_target(
            &raw_target,
            &decision,
            &sniffer_cfg,
            &router,
            sniffed_real_ip.as_ref(),
        );
        let conn_guard = hub.register_connection_with_outbound_guard_sniffed(
            "Mixed(HTTP)",
            "tcp",
            Some(peer),
            &decision.target,
            decision.restored_from_fake_ip.map(|ip| ip.to_string()),
            &decision.rule_type,
            &decision.rule_payload,
            decision.chains.clone(),
            decision.outbound.as_ref(),
            sniffed_real_ip.is_some(),
        );
        let conn_entry = Arc::clone(conn_guard.connection());
        hub.push_log(
            "info",
            format!(
                "[HTTP] {} -> {} [{}] via {} ({})",
                peer,
                decision.target,
                decision.rule_type,
                decision.outbound.name(),
                decision.outbound.exit_category()
            ),
        );

        let dial_start = Instant::now();
        let outbound_stream = match connect_outbound_with_timeout(
            decision.outbound.as_ref(),
            &dial_target,
            &conn_entry,
        )
        .await
        {
            Ok(s) => s,
            Err(err) => {
                conn_guard.record_failed(&err.to_string());
                let _ = tcp.write_all(http_error_response_for_io_error(&err)).await;
                return Err(err);
            }
        };
        conn_guard.mark_established();
        record_passive_proxy_delay(&router, decision.outbound.as_ref(), dial_start.elapsed());

        let mut rewritten = String::with_capacity(header_text.len() + 32);
        rewritten.push_str(&format!("{method} {origin_path} {version}\r\n"));
        for line in lines {
            if let Some((k, _)) = line.split_once(':') {
                let k_trim = k.trim();
                if k_trim.eq_ignore_ascii_case("proxy-connection")
                    || k_trim.eq_ignore_ascii_case("proxy-authorization")
                    || k_trim.eq_ignore_ascii_case("proxy-authenticate")
                    || k_trim.eq_ignore_ascii_case("connection")
                    || k_trim.eq_ignore_ascii_case("keep-alive")
                    || nominated_hop_headers
                        .iter()
                        .any(|h| k_trim.eq_ignore_ascii_case(h))
                {
                    continue;
                }
                if !is_upgrade
                    && (k_trim.eq_ignore_ascii_case("upgrade")
                        || k_trim.eq_ignore_ascii_case("te")
                        || k_trim.eq_ignore_ascii_case("trailer"))
                {
                    continue;
                }
            }
            rewritten.push_str(line);
            rewritten.push_str("\r\n");
        }
        if is_upgrade {
            rewritten.push_str("Connection: Upgrade\r\n");
        } else {
            rewritten.push_str("Connection: close\r\n");
        }
        rewritten.push_str("\r\n");

        let mut tracked = conn_guard.into_tracked_stream(outbound_stream);
        tracked.write_all(rewritten.as_bytes()).await?;

        if is_upgrade {
            if !trailing_body.is_empty() {
                tracked.write_all(trailing_body).await?;
            }
            tracked.flush().await?;
            tokio::select! {
                res = tokio::io::copy_bidirectional_with_sizes(tcp, &mut tracked, 64 * 1024, 64 * 1024) => {
                    let _ = res?;
                }
                _ = conn_entry.closed() => {}
            }
        } else if has_transfer_encoding {
            // Forward strictly the RFC 9112 §7.1 chunked body up to `0\r\n...\r\n` so pipelined
            // subsequent HTTP requests never leak `Proxy-Authorization` or reach `host1`!
            forward_chunked_request_body(tcp, &mut tracked, trailing_body, &conn_entry).await?;
            relay_http_one_shot_response(tcp, &mut tracked, method, &conn_entry).await?;
        } else {
            // Forward strictly `Content-Length` body bytes (default 0) so pipelined subsequent
            // HTTP requests on the same client TCP socket never leak `Proxy-Authorization` upstream!
            let expected_body = content_length.unwrap_or(0);
            let initial_take = (trailing_body.len() as u64).min(expected_body) as usize;
            if initial_take > 0 {
                tracked.write_all(&trailing_body[..initial_take]).await?;
            }
            let remaining_body = expected_body - initial_take as u64;
            if remaining_body > 0 {
                let mut body_reader = (&mut *tcp).take(remaining_body);
                tokio::select! {
                    biased;
                    _ = conn_entry.closed() => return Ok(()),
                    res = tokio::io::copy(&mut body_reader, &mut tracked) => {
                        let copied = res?;
                        if copied < remaining_body {
                            return Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "client closed before sending full Content-Length body",
                            ));
                        }
                    }
                }
            }
            tracked.flush().await?;
            relay_http_one_shot_response(tcp, &mut tracked, method, &conn_entry).await?;
        }
        Ok(())
    }
}

async fn read_into_chunk_buf(
    tcp: &mut TcpStream,
    buf: &mut BytesMut,
    conn_entry: &ActiveConnection,
) -> io::Result<bool> {
    let mut scratch = [0u8; 4096];
    let n = tokio::select! {
        biased;
        _ = conn_entry.closed() => return Ok(false),
        res = tcp.read(&mut scratch) => res?,
    };
    if n == 0 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "client closed before terminating chunked request body",
        ));
    }
    buf.extend_from_slice(&scratch[..n]);
    Ok(true)
}

async fn forward_chunked_request_body<W>(
    tcp: &mut TcpStream,
    tracked: &mut W,
    trailing_body: &[u8],
    conn_entry: &ActiveConnection,
) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    const MAX_CHUNK_LINE_BYTES: usize = 4096;
    const MAX_TRAILER_BYTES: usize = 16 * 1024;

    let mut buf = BytesMut::from(trailing_body);
    loop {
        let crlf = loop {
            if let Some(pos) = buf.windows(2).position(|w| w == b"\r\n") {
                break pos;
            }
            if buf.len() > MAX_CHUNK_LINE_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "HTTP chunk header line exceeds 4 KiB",
                ));
            }
            if !read_into_chunk_buf(tcp, &mut buf, conn_entry).await? {
                return Ok(());
            }
        };

        let chunk_size = {
            let line_str = std::str::from_utf8(&buf[..crlf]).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "non-ASCII HTTP chunk size line")
            })?;
            let size_hex = line_str.split(';').next().unwrap_or("").trim();
            if size_hex.is_empty() || !size_hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid hex size in HTTP chunked body",
                ));
            }
            u64::from_str_radix(size_hex, 16).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "HTTP chunk size overflow")
            })?
        };

        let header_line = buf.split_to(crlf + 2);
        tracked.write_all(&header_line).await?;

        if chunk_size == 0 {
            let mut trailer_total = 0usize;
            loop {
                let tr_crlf = loop {
                    if let Some(pos) = buf.windows(2).position(|w| w == b"\r\n") {
                        break pos;
                    }
                    if buf.len() > MAX_CHUNK_LINE_BYTES {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "HTTP chunk trailer line exceeds 4 KiB",
                        ));
                    }
                    if !read_into_chunk_buf(tcp, &mut buf, conn_entry).await? {
                        return Ok(());
                    }
                };

                if tr_crlf == 0 {
                    let _ = buf.split_to(2);
                    tracked.write_all(b"\r\n").await?;
                    break;
                }

                trailer_total = trailer_total.saturating_add(tr_crlf + 2);
                if trailer_total > MAX_TRAILER_BYTES {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "HTTP chunk trailers exceed 16 KiB",
                    ));
                }

                let tr_line = buf.split_to(tr_crlf + 2);
                let skip_proxy_trailer = std::str::from_utf8(&tr_line[..tr_crlf])
                    .ok()
                    .and_then(|s| s.split_once(':'))
                    .is_some_and(|(k, _)| {
                        let kt = k.trim();
                        kt.eq_ignore_ascii_case("proxy-authorization")
                            || kt.eq_ignore_ascii_case("proxy-authenticate")
                            || kt.eq_ignore_ascii_case("proxy-connection")
                    });
                if !skip_proxy_trailer {
                    tracked.write_all(&tr_line).await?;
                }
            }
            break;
        }

        let from_buf = (buf.len() as u64).min(chunk_size) as usize;
        if from_buf > 0 {
            let buffered_data = buf.split_to(from_buf);
            tracked.write_all(&buffered_data).await?;
        }
        let mut rem = chunk_size - from_buf as u64;
        if rem > 0 {
            let mut limited = (&mut *tcp).take(rem);
            tokio::select! {
                biased;
                _ = conn_entry.closed() => return Ok(()),
                res = tokio::io::copy(&mut limited, tracked) => {
                    let copied = res?;
                    rem -= copied;
                }
            }
            if rem > 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "client closed during HTTP chunk payload",
                ));
            }
        }

        while buf.len() < 2 {
            if !read_into_chunk_buf(tcp, &mut buf, conn_entry).await? {
                return Ok(());
            }
        }
        if &buf[..2] != b"\r\n" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "missing CRLF after HTTP chunk payload",
            ));
        }
        let _ = buf.split_to(2);
        tracked.write_all(b"\r\n").await?;
    }

    tracked.flush().await
}

async fn relay_http_one_shot_response<S>(
    tcp: &mut TcpStream,
    upstream: &mut S,
    req_method: &str,
    conn_entry: &ActiveConnection,
) -> io::Result<()>
where
    S: AsyncRead + Unpin,
{
    let mut buf = BytesMut::with_capacity(4096);
    loop {
        let hdr_end = loop {
            if let Some(pos) = find_double_crlf(&buf) {
                break Some(pos);
            }
            if buf.len() >= 32 * 1024 {
                break None;
            }
            let mut chunk = [0u8; 4096];
            let n = tokio::select! {
                biased;
                _ = conn_entry.closed() => return Ok(()),
                res = upstream.read(&mut chunk) => res?,
            };
            if n == 0 {
                break None;
            }
            buf.extend_from_slice(&chunk[..n]);
        };

        let Some(hdr_end) = hdr_end else {
            if !buf.is_empty() {
                tcp.write_all(&buf).await?;
                buf.clear();
            }
            tokio::select! {
                biased;
                _ = conn_entry.closed() => return Ok(()),
                res = tokio::io::copy(upstream, tcp) => {
                    let _ = res?;
                }
            }
            let _ = tcp.shutdown().await;
            return Ok(());
        };

        let parsed_hdr = std::str::from_utf8(&buf[..hdr_end]).ok().map(|hdr_str| {
            let mut hdr_lines = hdr_str.split("\r\n");
            let status_line = hdr_lines.next().unwrap_or("");
            let status_code = if status_line.starts_with("HTTP/1.") {
                status_line
                    .split_whitespace()
                    .nth(1)
                    .and_then(|s| s.parse::<u16>().ok())
                    .unwrap_or(0)
            } else {
                0
            };
            if (100..200).contains(&status_code) && status_code != 101 {
                return (status_code, None, false, None, false);
            }
            let mut resp_has_te = false;
            let mut resp_cl: Option<u64> = None;
            let mut resp_cl_conflict = false;
            let mut out_hdr = String::with_capacity(hdr_end + 32);
            out_hdr.push_str(status_line);
            out_hdr.push_str("\r\n");
            for line in hdr_lines {
                if let Some((k, v)) = line.split_once(':') {
                    let k_trim = k.trim();
                    let v_trim = v.trim();
                    if k_trim.eq_ignore_ascii_case("connection")
                        || k_trim.eq_ignore_ascii_case("keep-alive")
                        || k_trim.eq_ignore_ascii_case("proxy-connection")
                    {
                        continue;
                    }
                    if k_trim.eq_ignore_ascii_case("transfer-encoding") {
                        resp_has_te = true;
                    } else if k_trim.eq_ignore_ascii_case("content-length") {
                        match v_trim.parse::<u64>() {
                            Ok(n) => {
                                if let Some(prev) = resp_cl
                                    && prev != n
                                {
                                    resp_cl_conflict = true;
                                }
                                resp_cl = Some(n);
                            }
                            Err(_) => resp_cl_conflict = true,
                        }
                    }
                }
                out_hdr.push_str(line);
                out_hdr.push_str("\r\n");
            }
            out_hdr.push_str("Connection: close\r\n\r\n");
            (
                status_code,
                Some(out_hdr),
                resp_has_te,
                resp_cl,
                resp_cl_conflict,
            )
        });

        let Some((status_code, maybe_out_hdr, resp_has_te, resp_cl, resp_cl_conflict)) = parsed_hdr
        else {
            tcp.write_all(&buf).await?;
            buf.clear();
            tokio::select! {
                biased;
                _ = conn_entry.closed() => return Ok(()),
                res = tokio::io::copy(upstream, tcp) => {
                    let _ = res?;
                }
            }
            let _ = tcp.shutdown().await;
            return Ok(());
        };

        let Some(out_hdr) = maybe_out_hdr else {
            // 1xx informational response (except 101): forward verbatim and continue to final headers
            let block = buf.split_to(hdr_end + 4);
            tcp.write_all(&block).await?;
            tcp.flush().await?;
            continue;
        };

        let _ = buf.split_to(hdr_end + 4);
        tcp.write_all(out_hdr.as_bytes()).await?;

        let bodyless_response =
            req_method.eq_ignore_ascii_case("HEAD") || status_code == 204 || status_code == 304;
        if bodyless_response {
            tcp.flush().await?;
            let _ = tcp.shutdown().await;
            return Ok(());
        }

        if !resp_has_te
            && !resp_cl_conflict
            && let Some(expected_len) = resp_cl
        {
            let from_buf = (buf.len() as u64).min(expected_len) as usize;
            if from_buf > 0 {
                tcp.write_all(&buf[..from_buf]).await?;
            }
            let rem = expected_len - from_buf as u64;
            if rem > 0 {
                let mut limited = upstream.take(rem);
                tokio::select! {
                    biased;
                    _ = conn_entry.closed() => return Ok(()),
                    res = tokio::io::copy(&mut limited, tcp) => {
                        let _ = res?;
                    }
                }
            }
            tcp.flush().await?;
            let _ = tcp.shutdown().await;
            return Ok(());
        }

        if !buf.is_empty() {
            tcp.write_all(&buf).await?;
            buf.clear();
        }
        tokio::select! {
            biased;
            _ = conn_entry.closed() => return Ok(()),
            res = tokio::io::copy(upstream, tcp) => {
                let _ = res?;
            }
        }
        tcp.flush().await?;
        let _ = tcp.shutdown().await;
        return Ok(());
    }
}

fn find_double_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reject_forbidden_proxy_target_blocks_lan_loopback_pivot_and_self_loops() {
        let policy = MixedInboundPolicy::from_config(true, &[], &[])
            .unwrap()
            .with_blocked_local_ports(vec![9090, 1053]);
        let lan_peer: SocketAddr = "192.168.1.25:50123".parse().unwrap();
        let lo_peer: SocketAddr = "127.0.0.1:50124".parse().unwrap();

        // LAN peer cannot pivot to ANY loopback or unspecified address/domain.
        for forbidden in [
            "127.0.0.1:9090".parse::<TargetAddr>().unwrap(),
            "127.0.0.1:8080".parse::<TargetAddr>().unwrap(),
            "127.25.0.1:22".parse::<TargetAddr>().unwrap(),
            "[::1]:9090".parse::<TargetAddr>().unwrap(),
            "0.0.0.0:9090".parse::<TargetAddr>().unwrap(),
            "[::]:80".parse::<TargetAddr>().unwrap(),
            "[::ffff:127.0.0.1]:9090".parse::<TargetAddr>().unwrap(),
            TargetAddr::new_domain("localhost", 9090).unwrap(),
            TargetAddr::new_domain("LOCALHOST.", 3000).unwrap(),
            TargetAddr::new_domain("admin.localhost", 8080).unwrap(),
        ] {
            let err = reject_forbidden_proxy_target(lan_peer, 7890, &policy, &forbidden)
                .expect_err("LAN peer loopback/unspecified pivot must be rejected");
            assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        }

        // LAN peer can still reach normal external targets.
        assert!(
            reject_forbidden_proxy_target(
                lan_peer,
                7890,
                &policy,
                &"93.184.216.34:443".parse().unwrap()
            )
            .is_ok()
        );
        assert!(
            reject_forbidden_proxy_target(
                lan_peer,
                7890,
                &policy,
                &TargetAddr::new_domain("example.com", 443).unwrap()
            )
            .is_ok()
        );

        // Loopback peer is blocked on self mixed port and blocked_local_ports (controller & DNS),
        // while still allowed to reach arbitrary local mock test servers on other ephemeral ports!
        for self_loop in [
            "127.0.0.1:7890".parse::<TargetAddr>().unwrap(),
            "0.0.0.0:7890".parse::<TargetAddr>().unwrap(),
            TargetAddr::new_domain("localhost", 7890).unwrap(),
            "127.0.0.1:9090".parse::<TargetAddr>().unwrap(),
            "[::1]:9090".parse::<TargetAddr>().unwrap(),
            TargetAddr::new_domain("api.localhost", 9090).unwrap(),
            "127.0.0.1:1053".parse::<TargetAddr>().unwrap(),
        ] {
            let err = reject_forbidden_proxy_target(lo_peer, 7890, &policy, &self_loop)
                .expect_err("loopback self-loop / controller port must be rejected");
            assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        }

        assert!(
            reject_forbidden_proxy_target(
                lo_peer,
                7890,
                &policy,
                &"127.0.0.1:43210".parse().unwrap()
            )
            .is_ok(),
            "loopback client must still reach non-daemon local test servers"
        );
    }

    struct LoopbackTestUdpSession {
        sock: UdpSocket,
        dropped: Arc<std::sync::atomic::AtomicBool>,
    }

    impl Drop for LoopbackTestUdpSession {
        fn drop(&mut self) {
            self.dropped
                .store(true, std::sync::atomic::Ordering::Release);
        }
    }

    #[async_trait::async_trait]
    impl crate::outbound::OutboundUdpSession for LoopbackTestUdpSession {
        async fn send_to(&self, payload: &[u8], target: &TargetAddr) -> io::Result<()> {
            let IpAddr::V4(v4) = target.host.as_ip().expect("IPv4 target in test") else {
                unreachable!()
            };
            self.sock
                .send_to(payload, SocketAddr::new(IpAddr::V4(v4), target.port))
                .await?;
            Ok(())
        }

        async fn recv_from(&self) -> io::Result<(Vec<u8>, TargetAddr)> {
            let mut buf = vec![0u8; 2048];
            let (n, peer) = self.sock.recv_from(&mut buf).await?;
            buf.truncate(n);
            Ok((buf, TargetAddr::from(peer)))
        }
    }

    struct LoopbackTestOutbound {
        host_map: std::collections::HashMap<String, SocketAddr>,
        udp_dropped: Arc<std::sync::atomic::AtomicBool>,
    }

    #[async_trait::async_trait]
    impl OutboundHandler for LoopbackTestOutbound {
        fn name(&self) -> &str {
            "test-exit"
        }

        fn protocol(&self) -> &'static str {
            "vless"
        }

        fn udp_supported(&self) -> bool {
            true
        }

        async fn connect_tcp(&self, target: &TargetAddr) -> io::Result<BoxedStream> {
            let key = target.to_string();
            let dst = self
                .host_map
                .get(&key)
                .copied()
                .or_else(|| {
                    target
                        .host
                        .as_ip()
                        .map(|ip| SocketAddr::new(ip, target.port))
                })
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::NotFound, format!("unmapped {key}"))
                })?;
            let stream = TcpStream::connect(dst).await?;
            Ok(Box::new(stream))
        }

        async fn open_udp_session(
            &self,
        ) -> io::Result<Box<dyn crate::outbound::OutboundUdpSession>> {
            let sock = UdpSocket::bind("127.0.0.1:0").await?;
            Ok(Box::new(LoopbackTestUdpSession {
                sock,
                dropped: Arc::clone(&self.udp_dropped),
            }))
        }
    }

    async fn spawn_capturing_http_origin(
        tag: &'static str,
    ) -> (
        SocketAddr,
        Arc<tokio::sync::Mutex<Vec<String>>>,
        JoinHandle<()>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let captured = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let captured_srv = Arc::clone(&captured);

        let jh = tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                let cap = Arc::clone(&captured_srv);
                tokio::spawn(async move {
                    let mut raw = Vec::new();
                    let mut tmp = [0u8; 4096];
                    let hdr_end = loop {
                        let Ok(Ok(n)) =
                            tokio::time::timeout(Duration::from_secs(2), sock.read(&mut tmp)).await
                        else {
                            return;
                        };
                        if n == 0 {
                            return;
                        }
                        raw.extend_from_slice(&tmp[..n]);
                        if let Some(pos) = find_double_crlf(&raw) {
                            break pos;
                        }
                    };

                    let hdr_text = String::from_utf8_lossy(&raw[..hdr_end]).into_owned();
                    let req_line = hdr_text.lines().next().unwrap_or("").to_string();
                    let path = req_line
                        .split_whitespace()
                        .nth(1)
                        .unwrap_or("/")
                        .to_string();

                    let mut cl = 0usize;
                    let mut chunked = false;
                    for line in hdr_text.lines().skip(1) {
                        if let Some((k, v)) = line.split_once(':') {
                            if k.trim().eq_ignore_ascii_case("content-length") {
                                cl = v.trim().parse::<usize>().unwrap_or(0);
                            } else if k.trim().eq_ignore_ascii_case("transfer-encoding")
                                && v.to_ascii_lowercase().contains("chunked")
                            {
                                chunked = true;
                            }
                        }
                    }

                    let body_start = hdr_end + 4;
                    if chunked {
                        while !raw[body_start..].windows(5).any(|w| w == b"0\r\n\r\n") {
                            let Ok(Ok(n)) =
                                tokio::time::timeout(Duration::from_secs(2), sock.read(&mut tmp))
                                    .await
                            else {
                                break;
                            };
                            if n == 0 {
                                break;
                            }
                            raw.extend_from_slice(&tmp[..n]);
                        }
                    } else {
                        while raw.len().saturating_sub(body_start) < cl {
                            let Ok(Ok(n)) =
                                tokio::time::timeout(Duration::from_secs(2), sock.read(&mut tmp))
                                    .await
                            else {
                                break;
                            };
                            if n == 0 {
                                break;
                            }
                            raw.extend_from_slice(&tmp[..n]);
                        }
                    }

                    // Probe briefly to catch any leaked pipelined bytes sent past Request #1's body!
                    if let Ok(Ok(extra)) =
                        tokio::time::timeout(Duration::from_millis(20), sock.read(&mut tmp)).await
                        && extra > 0
                    {
                        raw.extend_from_slice(&tmp[..extra]);
                    }

                    let full_req = String::from_utf8_lossy(&raw).into_owned();
                    let body_str = String::from_utf8_lossy(&raw[body_start..]).into_owned();
                    cap.lock().await.push(full_req);

                    let resp_body = format!("{tag}:{path}:body={body_str}");
                    // Deliberately advertise `Connection: keep-alive` upstream to verify the proxy
                    // rewrites the client-facing response to `Connection: close`.
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n{}",
                        resp_body.len(),
                        resp_body
                    );
                    let _ = sock.write_all(resp.as_bytes()).await;
                    let _ = sock.shutdown().await;
                });
            }
        });

        (addr, captured, jh)
    }

    #[tokio::test]
    async fn plain_http_proxy_isolates_keepalive_pipelining_strips_credentials_and_frames_post_bodies()
     {
        let (h1_addr, h1_reqs, h1_jh) = spawn_capturing_http_origin("host1").await;
        let (h2_addr, h2_reqs, h2_jh) = spawn_capturing_http_origin("host2").await;

        let mut host_map = std::collections::HashMap::new();
        host_map.insert("host1.example:80".to_string(), h1_addr);
        host_map.insert("host2.example:80".to_string(), h2_addr);

        let mut outbounds: std::collections::HashMap<String, crate::outbound::DynOutbound> =
            std::collections::HashMap::new();
        outbounds.insert(
            "test-exit".to_string(),
            Arc::new(LoopbackTestOutbound {
                host_map,
                udp_dropped: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            }),
        );
        let dns = Arc::new(
            crate::dns::FakeIpDnsEngine::new(&crate::config::DnsConfig::default()).unwrap(),
        );
        let router = Arc::new(
            Router::new(
                crate::config::RunMode::Rule,
                outbounds,
                &[],
                &["MATCH,test-exit".to_string()],
                dns,
            )
            .unwrap(),
        );
        let hub = Arc::new(TelemetryHub::new());
        let policy = Arc::new(RwLock::new(
            MixedInboundPolicy::from_config(false, &["alice:s3cr3t".to_string()], &[]).unwrap(),
        ));
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (mixed_addr, mixed_jh) = spawn_mixed_inbound_with_policy(
            "127.0.0.1:0",
            Arc::new(RwLock::new(router)),
            policy,
            hub,
            shutdown_rx,
        )
        .await
        .unwrap();

        let auth_hdr = format!("Basic {}", STANDARD.encode("alice:s3cr3t"));

        // (a) Pipelined GET Request #1 (host1) + GET Request #2 (host2) on the SAME client socket
        {
            let mut client = TcpStream::connect(mixed_addr).await.unwrap();
            let pipelined = format!(
                "GET http://host1.example/one HTTP/1.1\r\nHost: host1.example\r\nProxy-Authorization: {auth_hdr}\r\nConnection: keep-alive\r\n\r\n\
                 GET http://host2.example/two HTTP/1.1\r\nHost: host2.example\r\nProxy-Authorization: {auth_hdr}\r\nConnection: keep-alive\r\n\r\n"
            );
            client.write_all(pipelined.as_bytes()).await.unwrap();

            let mut resp = String::new();
            client.read_to_string(&mut resp).await.unwrap();
            assert!(resp.starts_with("HTTP/1.1 200 OK\r\n"));
            assert!(resp.to_ascii_lowercase().contains("connection: close\r\n"));
            assert!(resp.ends_with("host1:/one:body="));

            let got_h1 = h1_reqs.lock().await.clone();
            assert_eq!(got_h1.len(), 1);
            let r1_lc = got_h1[0].to_ascii_lowercase();
            assert!(got_h1[0].starts_with("GET /one HTTP/1.1\r\n"));
            assert!(r1_lc.contains("connection: close\r\n"));
            assert!(!r1_lc.contains("proxy-authorization"));
            assert!(!got_h1[0].contains("s3cr3t"));
            assert!(!got_h1[0].contains(&auth_hdr));
            assert!(!got_h1[0].contains("/two"));
            assert!(!r1_lc.contains("host2.example"));
            assert!(h2_reqs.lock().await.is_empty());

            // Sequential Request #2 on a fresh connection reaches host2 cleanly without credentials leaking
            let mut client2 = TcpStream::connect(mixed_addr).await.unwrap();
            let req2 = format!(
                "GET http://host2.example/two HTTP/1.1\r\nHost: host2.example\r\nProxy-Authorization: {auth_hdr}\r\n\r\n"
            );
            client2.write_all(req2.as_bytes()).await.unwrap();
            let mut resp2 = String::new();
            client2.read_to_string(&mut resp2).await.unwrap();
            assert!(resp2.ends_with("host2:/two:body="));
            let got_h2 = h2_reqs.lock().await.clone();
            assert_eq!(got_h2.len(), 1);
            assert!(
                !got_h2[0]
                    .to_ascii_lowercase()
                    .contains("proxy-authorization")
            );
        }

        // (b1) POST with Content-Length + pipelined 2nd request on the same socket
        {
            let mut client = TcpStream::connect(mixed_addr).await.unwrap();
            let post_cl = format!(
                "POST http://host1.example/submit HTTP/1.1\r\nHost: host1.example\r\nProxy-Authorization: {auth_hdr}\r\nContent-Length: 11\r\n\r\nhello=world\
                 GET http://host2.example/leaked HTTP/1.1\r\nHost: host2.example\r\nProxy-Authorization: {auth_hdr}\r\n\r\n"
            );
            client.write_all(post_cl.as_bytes()).await.unwrap();
            let mut resp = String::new();
            client.read_to_string(&mut resp).await.unwrap();
            assert!(resp.ends_with("host1:/submit:body=hello=world"));

            let got_h1 = h1_reqs.lock().await.clone();
            assert_eq!(got_h1.len(), 2);
            let post_req = &got_h1[1];
            assert!(post_req.ends_with("\r\n\r\nhello=world"));
            assert!(
                !post_req
                    .to_ascii_lowercase()
                    .contains("proxy-authorization")
            );
            assert!(!post_req.contains("/leaked"));
            assert_eq!(h2_reqs.lock().await.len(), 1);
        }

        // (b2) POST with Transfer-Encoding: chunked + pipelined 2nd request on the same socket
        {
            let mut client = TcpStream::connect(mixed_addr).await.unwrap();
            let post_chunked = format!(
                "POST http://host1.example/chunked HTTP/1.1\r\nHost: host1.example\r\nProxy-Authorization: {auth_hdr}\r\nTransfer-Encoding: chunked\r\n\r\n\
                 5\r\nhello\r\n6\r\n=world\r\n0\r\n\r\n\
                 GET http://host2.example/chunk-leak HTTP/1.1\r\nHost: host2.example\r\nProxy-Authorization: {auth_hdr}\r\n\r\n"
            );
            client.write_all(post_chunked.as_bytes()).await.unwrap();
            let mut resp = String::new();
            client.read_to_string(&mut resp).await.unwrap();
            assert!(resp.contains("host1:/chunked:body=5\r\nhello\r\n6\r\n=world\r\n0\r\n\r\n"));

            let got_h1 = h1_reqs.lock().await.clone();
            assert_eq!(got_h1.len(), 3);
            let chunk_req = &got_h1[2];
            assert!(
                !chunk_req
                    .to_ascii_lowercase()
                    .contains("proxy-authorization")
            );
            assert!(!chunk_req.contains("/chunk-leak"));
            assert_eq!(h2_reqs.lock().await.len(), 1);
        }

        let _ = shutdown_tx.send(true);
        mixed_jh.abort();
        h1_jh.abort();
        h2_jh.abort();
    }

    #[tokio::test]
    async fn socks5_udp_associate_control_close_immediately_stops_flooded_session_and_telemetry() {
        let udp_origin = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let udp_origin_addr = udp_origin.local_addr().unwrap();
        let stop_flood = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop_flood_srv = Arc::clone(&stop_flood);
        let udp_origin_srv = Arc::clone(&udp_origin);

        let flood_srv_jh = tokio::spawn(async move {
            let mut buf = [0u8; 256];
            let Ok((_, proxy_udp_peer)) = udp_origin_srv.recv_from(&mut buf).await else {
                return;
            };
            while !stop_flood_srv.load(std::sync::atomic::Ordering::Relaxed) {
                let _ = udp_origin_srv
                    .send_to(b"active-udp-flood-frame", proxy_udp_peer)
                    .await;
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        });

        let udp_session_dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut outbounds: std::collections::HashMap<String, crate::outbound::DynOutbound> =
            std::collections::HashMap::new();
        outbounds.insert(
            "test-exit".to_string(),
            Arc::new(LoopbackTestOutbound {
                host_map: std::collections::HashMap::new(),
                udp_dropped: Arc::clone(&udp_session_dropped),
            }),
        );
        let dns = Arc::new(
            crate::dns::FakeIpDnsEngine::new(&crate::config::DnsConfig::default()).unwrap(),
        );
        let router = Arc::new(
            Router::new(
                crate::config::RunMode::Rule,
                outbounds,
                &[],
                &["MATCH,test-exit".to_string()],
                dns,
            )
            .unwrap(),
        );
        let hub = Arc::new(TelemetryHub::new());
        let policy = Arc::new(RwLock::new(MixedInboundPolicy::default()));
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (mixed_addr, mixed_jh) = spawn_mixed_inbound_with_policy(
            "127.0.0.1:0",
            Arc::new(RwLock::new(router)),
            policy,
            Arc::clone(&hub),
            shutdown_rx,
        )
        .await
        .unwrap();

        // Open SOCKS5 TCP control connection and request UDP ASSOCIATE (0x03)
        let mut socks_tcp = TcpStream::connect(mixed_addr).await.unwrap();
        socks_tcp.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut greet_resp = [0u8; 2];
        socks_tcp.read_exact(&mut greet_resp).await.unwrap();
        assert_eq!(greet_resp, [0x05, 0x00]);

        socks_tcp
            .write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        let mut assoc_hdr = [0u8; 3];
        socks_tcp.read_exact(&mut assoc_hdr).await.unwrap();
        assert_eq!(assoc_hdr, [0x05, 0x00, 0x00]);
        let relay_target = TargetAddr::read_socks5(&mut socks_tcp).await.unwrap();
        let relay_addr = SocketAddr::new(relay_target.host.as_ip().unwrap(), relay_target.port);

        let client_udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut dgram = BytesMut::new();
        dgram.put_slice(&[0x00, 0x00, 0x00]);
        TargetAddr::from(udp_origin_addr)
            .encode_socks5(&mut dgram)
            .unwrap();
        dgram.put_slice(b"trigger-flood");
        client_udp.send_to(&dgram, relay_addr).await.unwrap();

        // Wait for at least 5 flooded UDP packets to arrive back at the client
        let mut rbuf = [0u8; 256];
        for _ in 0..5 {
            let (n, _) =
                tokio::time::timeout(Duration::from_secs(2), client_udp.recv_from(&mut rbuf))
                    .await
                    .unwrap()
                    .unwrap();
            assert!(n > 10);
        }
        assert_eq!(hub.active_connection_count(), 1);

        // Close the SOCKS5 TCP control stream while remote UDP packets are still actively flooding!
        drop(socks_tcp);

        tokio::time::timeout(Duration::from_millis(300), async {
            while hub.active_connection_count() != 0
                || !udp_session_dropped.load(std::sync::atomic::Ordering::Acquire)
            {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await
        .expect("closing SOCKS5 TCP control stream must immediately tear down UDP sessions and TelemetryHub entries");

        stop_flood.store(true, std::sync::atomic::Ordering::Relaxed);
        let _ = shutdown_tx.send(true);
        mixed_jh.abort();
        let _ = flood_srv_jh.await;
    }

    #[test]
    fn http_proxy_authority_supports_bare_bracketed_ipv6_and_preserves_raw_origin_path() {
        assert_eq!(
            parse_host_or_authority_with_default_port("[2001:db8::1]", 443).unwrap(),
            TargetAddr::new_ip("2001:db8::1".parse().unwrap(), 443)
        );
        assert_eq!(
            parse_host_or_authority_with_default_port("[::1]", 80).unwrap(),
            TargetAddr::new_ip("::1".parse().unwrap(), 80)
        );
        assert_eq!(
            parse_host_or_authority_with_default_port("[::1]:8080", 80).unwrap(),
            TargetAddr::new_ip("::1".parse().unwrap(), 8080)
        );
        assert_eq!(
            parse_host_or_authority_with_default_port("example.com", 443).unwrap(),
            TargetAddr::new_domain("example.com", 443).unwrap()
        );

        assert_eq!(
            extract_raw_http_origin_path("http://s3.example.com/bucket/a%2Fb/../raw?X-Amz-Sig=1+2"),
            "/bucket/a%2Fb/../raw?X-Amz-Sig=1+2"
        );
        assert_eq!(
            extract_raw_http_origin_path("http://[::1]:8080?foo=bar#frag"),
            "/?foo=bar"
        );
        assert_eq!(extract_raw_http_origin_path("http://example.com"), "/");
    }

    struct RecordingProxyOutbound {
        name: &'static str,
        backend_addr: SocketAddr,
        dialed: Arc<parking_lot::Mutex<Vec<TargetAddr>>>,
    }

    #[async_trait::async_trait]
    impl OutboundHandler for RecordingProxyOutbound {
        fn name(&self) -> &str {
            self.name
        }

        fn protocol(&self) -> &'static str {
            "vless"
        }

        async fn connect_tcp(&self, target: &TargetAddr) -> io::Result<BoxedStream> {
            self.dialed.lock().push(target.clone());
            let stream = TcpStream::connect(self.backend_addr).await?;
            Ok(Box::new(stream))
        }
    }

    fn build_test_tls_client_hello(sni: &str, padding_len: usize) -> Vec<u8> {
        let host_bytes = sni.as_bytes();
        let mut sni_ext_body = Vec::new();
        let list_len = (1 + 2 + host_bytes.len()) as u16;
        sni_ext_body.extend_from_slice(&list_len.to_be_bytes());
        sni_ext_body.push(0x00); // host_name
        sni_ext_body.extend_from_slice(&(host_bytes.len() as u16).to_be_bytes());
        sni_ext_body.extend_from_slice(host_bytes);

        let mut exts = Vec::new();
        if padding_len > 0 {
            exts.extend_from_slice(&0x0015u16.to_be_bytes()); // padding ext before SNI (PQ-like)
            exts.extend_from_slice(&(padding_len as u16).to_be_bytes());
            exts.resize(exts.len() + padding_len, 0x00);
        }
        exts.extend_from_slice(&0x0000u16.to_be_bytes()); // server_name
        exts.extend_from_slice(&(sni_ext_body.len() as u16).to_be_bytes());
        exts.extend_from_slice(&sni_ext_body);

        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // TLS 1.2 legacy version
        body.extend_from_slice(&[0x42; 32]); // random
        body.push(0x00); // session_id_len
        body.extend_from_slice(&2u16.to_be_bytes()); // cipher_suites_len
        body.extend_from_slice(&[0x13, 0x01]); // TLS_AES_128_GCM_SHA256
        body.push(0x01); // comp_methods_len
        body.push(0x00); // null compression
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);

        let mut hs = Vec::with_capacity(4 + body.len());
        hs.push(0x01); // ClientHello
        let hs_len = body.len();
        hs.push(((hs_len >> 16) & 0xff) as u8);
        hs.push(((hs_len >> 8) & 0xff) as u8);
        hs.push((hs_len & 0xff) as u8);
        hs.extend_from_slice(&body);

        let mut rec = Vec::with_capacity(5 + hs.len());
        rec.push(0x16); // Handshake
        rec.extend_from_slice(&[0x03, 0x01]); // TLS 1.0 record layer
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    #[tokio::test]
    async fn mixed_real_ip_sniffer_routes_and_overrides_socks5_http_connect_and_plain_http() {
        // Spawn a raw echo backend for TLS streams and a capturing HTTP origin for plain HTTP
        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo_listener.local_addr().unwrap();
        let echo_jh = tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = echo_listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    loop {
                        match s.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if s.write_all(&buf[..n]).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                });
            }
        });

        let (http_origin_addr, captured_http, http_jh) = spawn_capturing_http_origin("SNIFF").await;

        let proxy_dialed = Arc::new(parking_lot::Mutex::new(Vec::<TargetAddr>::new()));
        let http_proxy_dialed = Arc::new(parking_lot::Mutex::new(Vec::<TargetAddr>::new()));
        let fallback_dialed = Arc::new(parking_lot::Mutex::new(Vec::<TargetAddr>::new()));

        let mut outbounds: std::collections::HashMap<String, crate::outbound::DynOutbound> =
            std::collections::HashMap::new();
        outbounds.insert(
            "proxy-tls".to_string(),
            Arc::new(RecordingProxyOutbound {
                name: "proxy-tls",
                backend_addr: echo_addr,
                dialed: Arc::clone(&proxy_dialed),
            }),
        );
        outbounds.insert(
            "proxy-http".to_string(),
            Arc::new(RecordingProxyOutbound {
                name: "proxy-http",
                backend_addr: http_origin_addr,
                dialed: Arc::clone(&http_proxy_dialed),
            }),
        );
        outbounds.insert(
            "fallback".to_string(),
            Arc::new(RecordingProxyOutbound {
                name: "fallback",
                backend_addr: echo_addr,
                dialed: Arc::clone(&fallback_dialed),
            }),
        );

        let dns = Arc::new(
            crate::dns::FakeIpDnsEngine::new(&crate::config::DnsConfig::default()).unwrap(),
        );
        let router = Arc::new(
            Router::new(
                crate::config::RunMode::Rule,
                outbounds,
                &[],
                &[
                    "DOMAIN-SUFFIX,web.sniffed.test,proxy-http".to_string(),
                    "DOMAIN-SUFFIX,sniffed.test,proxy-tls".to_string(),
                    "MATCH,fallback".to_string(),
                ],
                dns,
            )
            .unwrap(),
        );
        let mut sniffer = crate::config::SnifferConfig::default();
        sniffer.skip_domain.push("skip.sniffed.test".to_string());
        router.set_sniffer(sniffer);

        let hub = Arc::new(TelemetryHub::new());
        let policy = Arc::new(RwLock::new(MixedInboundPolicy::default()));
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (mixed_addr, mixed_jh) = spawn_mixed_inbound_with_policy(
            "127.0.0.1:0",
            Arc::new(RwLock::new(router)),
            policy,
            Arc::clone(&hub),
            shutdown_rx,
        )
        .await
        .unwrap();

        // 1. SOCKS5 real public IP (93.184.216.34:443) with 2-chunk PQ-sized TLS ClientHello
        {
            let hello = build_test_tls_client_hello("api.sniffed.test", 1800);
            let mut s = TcpStream::connect(mixed_addr).await.unwrap();
            s.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
            let mut g = [0u8; 2];
            s.read_exact(&mut g).await.unwrap();
            assert_eq!(g, [0x05, 0x00]);
            let mut req = vec![0x05, 0x01, 0x00, 0x01, 93, 184, 216, 34];
            req.extend_from_slice(&443u16.to_be_bytes());
            s.write_all(&req).await.unwrap();
            let mut rep = [0u8; 10];
            s.read_exact(&mut rep).await.unwrap();
            assert_eq!(rep[1], 0x00);

            // Split ClientHello across two writes to verify lossless multi-segment reassembly!
            let split = 900;
            s.write_all(&hello[..split]).await.unwrap();
            tokio::time::sleep(Duration::from_millis(15)).await;
            s.write_all(&hello[split..]).await.unwrap();

            let mut echoed = vec![0u8; hello.len()];
            tokio::time::timeout(Duration::from_secs(2), s.read_exact(&mut echoed))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                echoed, hello,
                "SOCKS5 sniffed ClientHello must be forwarded completely without byte loss"
            );
        }

        // 2. HTTP CONNECT real public IP (93.184.216.34:443) with ~2KB cross-segment PQ ClientHello
        {
            let hello = build_test_tls_client_hello("connect.sniffed.test", 1850);
            assert!(
                hello.len() > 1900,
                "PQ ClientHello test fixture should exceed one 1460B TCP segment"
            );
            let mut s = TcpStream::connect(mixed_addr).await.unwrap();
            s.write_all(b"CONNECT 93.184.216.34:443 HTTP/1.1\r\nHost: 93.184.216.34:443\r\n\r\n")
                .await
                .unwrap();
            let mut resp = vec![0u8; 39];
            s.read_exact(&mut resp).await.unwrap();
            assert!(String::from_utf8_lossy(&resp).starts_with("HTTP/1.1 200"));

            // Split PQ ClientHello across two TCP segments (~1460B + remainder) to verify lossless reassembly.
            let split = 1460;
            s.write_all(&hello[..split]).await.unwrap();
            tokio::time::sleep(Duration::from_millis(15)).await;
            s.write_all(&hello[split..]).await.unwrap();

            let mut echoed = vec![0u8; hello.len()];
            tokio::time::timeout(Duration::from_secs(2), s.read_exact(&mut echoed))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                echoed, hello,
                "HTTP CONNECT ~2KB cross-segment PQ ClientHello must be forwarded losslessly"
            );
        }

        // 3. Plain HTTP GET http://93.184.216.34/check with Host: web.sniffed.test
        {
            let mut s = TcpStream::connect(mixed_addr).await.unwrap();
            s.write_all(
                b"GET http://93.184.216.34/check HTTP/1.1\r\nHost: web.sniffed.test\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();
            let mut resp = Vec::new();
            tokio::time::timeout(Duration::from_secs(2), s.read_to_end(&mut resp))
                .await
                .unwrap()
                .unwrap();
            assert!(String::from_utf8_lossy(&resp).contains("SNIFF:/check:body="));
        }

        // 4. `skip-domain` (`skip.sniffed.test`) routes via DOMAIN-SUFFIX to `proxy-tls`,
        //    but preserves the original IP `93.184.216.34:443` as the remote dial target!
        {
            let hello = build_test_tls_client_hello("skip.sniffed.test", 0);
            let mut s = TcpStream::connect(mixed_addr).await.unwrap();
            s.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
            let mut g = [0u8; 2];
            s.read_exact(&mut g).await.unwrap();
            let mut req = vec![0x05, 0x01, 0x00, 0x01, 93, 184, 216, 34];
            req.extend_from_slice(&443u16.to_be_bytes());
            s.write_all(&req).await.unwrap();
            let mut rep = [0u8; 10];
            s.read_exact(&mut rep).await.unwrap();
            assert_eq!(rep[1], 0x00);

            s.write_all(&hello).await.unwrap();
            let mut echoed = vec![0u8; hello.len()];
            tokio::time::timeout(Duration::from_secs(2), s.read_exact(&mut echoed))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(echoed, hello);
        }

        let tls_targets = proxy_dialed.lock().clone();
        assert_eq!(
            tls_targets,
            vec![
                TargetAddr::new_domain("api.sniffed.test", 443).unwrap(),
                TargetAddr::new_domain("connect.sniffed.test", 443).unwrap(),
                "93.184.216.34:443".parse::<TargetAddr>().unwrap(),
            ],
            "SOCKS5 & HTTP CONNECT should override dial target on SNI, while skip-domain retains original IP"
        );
        let http_targets = http_proxy_dialed.lock().clone();
        assert_eq!(
            http_targets,
            vec![TargetAddr::new_domain("web.sniffed.test", 80).unwrap()],
            "Plain HTTP real-IP request should route & override via Host header"
        );
        assert!(
            fallback_dialed.lock().is_empty(),
            "All sniffed real-IP connections should match DOMAIN-SUFFIX instead of falling through to MATCH"
        );
        assert_eq!(captured_http.lock().await.len(), 1);
        let diags = hub.diagnostics_snapshot(20);
        assert_eq!(
            diags.iter().filter(|d| d.metadata.sniffed).count(),
            4,
            "All 4 real-IP sniffed connections should record metadata.sniffed == true"
        );

        let _ = shutdown_tx.send(true);
        mixed_jh.abort();
        echo_jh.abort();
        http_jh.abort();
    }

    #[tokio::test]
    async fn plain_http_proxy_handles_multibyte_utf8_uri_spanning_scheme_boundaries_without_panic()
    {
        let (origin_addr, captured_reqs, origin_jh) = spawn_capturing_http_origin("utf8").await;

        let mut host_map = std::collections::HashMap::new();
        host_map.insert("utf8.example:80".to_string(), origin_addr);

        let mut outbounds: std::collections::HashMap<String, crate::outbound::DynOutbound> =
            std::collections::HashMap::new();
        outbounds.insert(
            "test-exit".to_string(),
            Arc::new(LoopbackTestOutbound {
                host_map,
                udp_dropped: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            }),
        );
        let dns = Arc::new(
            crate::dns::FakeIpDnsEngine::new(&crate::config::DnsConfig::default()).unwrap(),
        );
        let router = Arc::new(
            Router::new(
                crate::config::RunMode::Rule,
                outbounds,
                &[],
                &["MATCH,test-exit".to_string()],
                dns,
            )
            .unwrap(),
        );
        let hub = Arc::new(TelemetryHub::new());
        let policy = Arc::new(RwLock::new(MixedInboundPolicy::default()));
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (mixed_addr, mixed_jh) = spawn_mixed_inbound_with_policy(
            "127.0.0.1:0",
            Arc::new(RwLock::new(router)),
            policy,
            hub,
            shutdown_rx,
        )
        .await
        .unwrap();

        // Both URIs have multi-byte UTF-8 characters spanning byte indices 7 and/or 8:
        // - "/你好世界/test": byte 0='/', [1..4)='你', [4..7)='好', [7..10)='世' (index 8 inside '世')
        // - "你好世界foo": [0..3)='你', [3..6)='好', [6..9)='世' (both index 7 and 8 inside '世')
        for uri in ["/你好世界/test", "你好世界foo"] {
            let mut client = TcpStream::connect(mixed_addr).await.unwrap();
            let req = format!("GET {uri} HTTP/1.1\r\nHost: utf8.example\r\n\r\n");
            client.write_all(req.as_bytes()).await.unwrap();

            let mut resp = String::new();
            tokio::time::timeout(Duration::from_secs(2), client.read_to_string(&mut resp))
                .await
                .expect("mixed HTTP proxy must not panic or stall on UTF-8 URI")
                .unwrap();
            assert!(
                resp.starts_with("HTTP/1.1 200 OK\r\n"),
                "expected 200 OK for URI '{uri}', got: {resp}"
            );
            assert!(resp.ends_with(&format!("utf8:{uri}:body=")));
        }
        assert_eq!(captured_reqs.lock().await.len(), 2);

        let _ = shutdown_tx.send(true);
        mixed_jh.abort();
        origin_jh.abort();
    }

    #[tokio::test]
    async fn socks5_udp_associate_inbound_shutdown_tears_down_open_session_and_releases_relay_port()
    {
        let udp_origin = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let udp_origin_addr = udp_origin.local_addr().unwrap();
        let udp_origin_srv = Arc::clone(&udp_origin);
        let echo_jh = tokio::spawn(async move {
            let mut buf = [0u8; 256];
            while let Ok((n, peer)) = udp_origin_srv.recv_from(&mut buf).await {
                let _ = udp_origin_srv.send_to(&buf[..n], peer).await;
            }
        });

        let udp_session_dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut outbounds: std::collections::HashMap<String, crate::outbound::DynOutbound> =
            std::collections::HashMap::new();
        outbounds.insert(
            "test-exit".to_string(),
            Arc::new(LoopbackTestOutbound {
                host_map: std::collections::HashMap::new(),
                udp_dropped: Arc::clone(&udp_session_dropped),
            }),
        );
        let dns = Arc::new(
            crate::dns::FakeIpDnsEngine::new(&crate::config::DnsConfig::default()).unwrap(),
        );
        let router = Arc::new(
            Router::new(
                crate::config::RunMode::Rule,
                outbounds,
                &[],
                &["MATCH,test-exit".to_string()],
                dns,
            )
            .unwrap(),
        );
        let hub = Arc::new(TelemetryHub::new());
        let policy = Arc::new(RwLock::new(MixedInboundPolicy::default()));
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (mixed_addr, mixed_jh) = spawn_mixed_inbound_with_policy(
            "127.0.0.1:0",
            Arc::new(RwLock::new(router)),
            policy,
            Arc::clone(&hub),
            shutdown_rx,
        )
        .await
        .unwrap();

        // Open SOCKS5 TCP control connection and establish UDP ASSOCIATE (keep TCP OPEN!)
        let mut socks_tcp = TcpStream::connect(mixed_addr).await.unwrap();
        socks_tcp.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut greet = [0u8; 2];
        socks_tcp.read_exact(&mut greet).await.unwrap();
        assert_eq!(greet, [0x05, 0x00]);

        socks_tcp
            .write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        let mut assoc_hdr = [0u8; 3];
        socks_tcp.read_exact(&mut assoc_hdr).await.unwrap();
        assert_eq!(assoc_hdr, [0x05, 0x00, 0x00]);
        let relay_target = TargetAddr::read_socks5(&mut socks_tcp).await.unwrap();
        let relay_addr = SocketAddr::new(relay_target.host.as_ip().unwrap(), relay_target.port);

        let client_udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut dgram = BytesMut::new();
        dgram.put_slice(&[0x00, 0x00, 0x00]);
        TargetAddr::from(udp_origin_addr)
            .encode_socks5(&mut dgram)
            .unwrap();
        dgram.put_slice(b"ping-before-shutdown");
        client_udp.send_to(&dgram, relay_addr).await.unwrap();

        let mut rbuf = [0u8; 256];
        let (n, _) = tokio::time::timeout(Duration::from_secs(2), client_udp.recv_from(&mut rbuf))
            .await
            .unwrap()
            .unwrap();
        assert!(rbuf[..n].ends_with(b"ping-before-shutdown"));
        assert_eq!(hub.active_connection_count(), 1);

        // Trigger inbound shutdown WITHOUT closing `socks_tcp`.
        shutdown_tx.send(true).unwrap();

        tokio::time::timeout(Duration::from_millis(500), async {
            while hub.active_connection_count() != 0
                || !udp_session_dropped.load(std::sync::atomic::Ordering::Acquire)
            {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("inbound shutdown must tear down open SOCKS5 UDP ASSOCIATE sessions");

        // Control TCP connection must see EOF because the connection handler exited.
        let mut eof_buf = [0u8; 8];
        let eof_n = tokio::time::timeout(Duration::from_millis(500), socks_tcp.read(&mut eof_buf))
            .await
            .expect("TCP control connection should close on inbound shutdown")
            .unwrap();
        assert_eq!(eof_n, 0);

        // The ephemeral UDP relay socket must be dropped so `relay_addr` can be rebound.
        tokio::time::timeout(Duration::from_millis(500), async {
            loop {
                if UdpSocket::bind(relay_addr).await.is_ok() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("UDP ASSOCIATE relay port must be released on inbound shutdown");

        let _ = tokio::time::timeout(Duration::from_secs(1), mixed_jh).await;
        echo_jh.abort();
    }

    struct TaggedEchoUdpSession {
        tag: &'static [u8],
        tx: tokio::sync::mpsc::UnboundedSender<(Vec<u8>, TargetAddr)>,
        rx: tokio::sync::Mutex<tokio::sync::mpsc::UnboundedReceiver<(Vec<u8>, TargetAddr)>>,
    }

    #[async_trait::async_trait]
    impl crate::outbound::OutboundUdpSession for TaggedEchoUdpSession {
        async fn send_to(&self, payload: &[u8], target: &TargetAddr) -> io::Result<()> {
            let mut reply = Vec::with_capacity(self.tag.len() + payload.len());
            reply.extend_from_slice(self.tag);
            reply.extend_from_slice(payload);
            let _ = self.tx.send((reply, target.clone()));
            Ok(())
        }

        async fn recv_from(&self) -> io::Result<(Vec<u8>, TargetAddr)> {
            self.rx
                .lock()
                .await
                .recv()
                .await
                .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "tagged echo closed"))
        }
    }

    struct TaggedEchoOutbound {
        name: &'static str,
        tag: &'static [u8],
        hits: Arc<std::sync::atomic::AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl OutboundHandler for TaggedEchoOutbound {
        fn name(&self) -> &str {
            self.name
        }

        fn protocol(&self) -> &'static str {
            "vless"
        }

        fn udp_supported(&self) -> bool {
            true
        }

        async fn connect_tcp(&self, _target: &TargetAddr) -> io::Result<BoxedStream> {
            Err(io::Error::other("unused"))
        }

        async fn open_udp_session(
            &self,
        ) -> io::Result<Box<dyn crate::outbound::OutboundUdpSession>> {
            self.hits.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
            Ok(Box::new(TaggedEchoUdpSession {
                tag: self.tag,
                tx,
                rx: tokio::sync::Mutex::new(rx),
            }))
        }
    }

    #[tokio::test]
    async fn socks5_udp_associate_hot_reloads_router_and_policy_on_live_session() {
        let dns = Arc::new(
            crate::dns::FakeIpDnsEngine::new(&crate::config::DnsConfig::default()).unwrap(),
        );
        let hits_a = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let hits_b = Arc::new(std::sync::atomic::AtomicUsize::new(0));

        let mut ob_a: std::collections::HashMap<String, crate::outbound::DynOutbound> =
            std::collections::HashMap::new();
        ob_a.insert(
            "exit-a".to_string(),
            Arc::new(TaggedEchoOutbound {
                name: "exit-a",
                tag: b"A:",
                hits: Arc::clone(&hits_a),
            }),
        );
        let router_a = Arc::new(
            Router::new(
                crate::config::RunMode::Rule,
                ob_a,
                &[],
                &["MATCH,exit-a".to_string()],
                Arc::clone(&dns),
            )
            .unwrap(),
        );

        let mut ob_b: std::collections::HashMap<String, crate::outbound::DynOutbound> =
            std::collections::HashMap::new();
        ob_b.insert(
            "exit-b".to_string(),
            Arc::new(TaggedEchoOutbound {
                name: "exit-b",
                tag: b"B:",
                hits: Arc::clone(&hits_b),
            }),
        );
        let router_b = Arc::new(
            Router::new(
                crate::config::RunMode::Rule,
                ob_b,
                &[],
                &["MATCH,exit-b".to_string()],
                dns,
            )
            .unwrap(),
        );
        assert_ne!(router_a.epoch(), router_b.epoch());

        let router_slot = Arc::new(RwLock::new(router_a));
        let policy_slot = Arc::new(RwLock::new(MixedInboundPolicy::default()));
        let hub = Arc::new(TelemetryHub::new());
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (mixed_addr, mixed_jh) = spawn_mixed_inbound_with_policy(
            "127.0.0.1:0",
            Arc::clone(&router_slot),
            Arc::clone(&policy_slot),
            Arc::clone(&hub),
            shutdown_rx,
        )
        .await
        .unwrap();

        // Establish ONE long-lived SOCKS5 UDP ASSOCIATE session.
        let mut socks_tcp = TcpStream::connect(mixed_addr).await.unwrap();
        socks_tcp.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut greet = [0u8; 2];
        socks_tcp.read_exact(&mut greet).await.unwrap();
        assert_eq!(greet, [0x05, 0x00]);
        socks_tcp
            .write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        let mut assoc_hdr = [0u8; 3];
        socks_tcp.read_exact(&mut assoc_hdr).await.unwrap();
        assert_eq!(assoc_hdr, [0x05, 0x00, 0x00]);
        let relay_target = TargetAddr::read_socks5(&mut socks_tcp).await.unwrap();
        let relay_addr = SocketAddr::new(relay_target.host.as_ip().unwrap(), relay_target.port);

        let client_udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target_addr: SocketAddr = "127.0.0.1:45678".parse().unwrap();
        let build_dgram = |payload: &[u8]| {
            let mut d = BytesMut::new();
            d.put_slice(&[0x00, 0x00, 0x00]);
            TargetAddr::from(target_addr).encode_socks5(&mut d).unwrap();
            d.put_slice(payload);
            d
        };

        // 1. Before hot reload, datagram routes via `exit-a` and populates `fast_routes`.
        client_udp
            .send_to(&build_dgram(b"one"), relay_addr)
            .await
            .unwrap();
        let mut rbuf = [0u8; 256];
        let (n1, _) = tokio::time::timeout(Duration::from_secs(2), client_udp.recv_from(&mut rbuf))
            .await
            .unwrap()
            .unwrap();
        assert!(rbuf[..n1].ends_with(b"A:one"));
        assert_eq!(hits_a.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(hits_b.load(std::sync::atomic::Ordering::SeqCst), 0);

        // 2. Hot-swap `*router_slot.write()` while keeping the same SOCKS5 UDP ASSOCIATE open.
        //    Subsequent datagrams to the SAME IP:port must invalidate `fast_routes` via the new
        //    router epoch and immediately route via `exit-b`.
        *router_slot.write() = router_b;
        client_udp
            .send_to(&build_dgram(b"two"), relay_addr)
            .await
            .unwrap();
        let (n2, _) = tokio::time::timeout(Duration::from_secs(2), client_udp.recv_from(&mut rbuf))
            .await
            .unwrap()
            .unwrap();
        assert!(
            rbuf[..n2].ends_with(b"B:two"),
            "hot-reloaded router must immediately reroute existing SOCKS5 UDP ASSOCIATE"
        );
        assert_eq!(hits_b.load(std::sync::atomic::Ordering::SeqCst), 1);

        // 3. Hot-swap `*policy_slot.write()` to block `target_addr.port()` in `blocked_local_ports`.
        //    Even with `fast_routes` hot for `target_addr`, the new policy must block the datagram!
        *policy_slot.write() =
            MixedInboundPolicy::default().with_blocked_local_ports(vec![target_addr.port()]);
        client_udp
            .send_to(&build_dgram(b"three-blocked"), relay_addr)
            .await
            .unwrap();
        let blocked_res =
            tokio::time::timeout(Duration::from_millis(120), client_udp.recv_from(&mut rbuf)).await;
        assert!(
            blocked_res.is_err(),
            "hot-reloaded MixedInboundPolicy must immediately block forbidden UDP targets on live association"
        );

        let _ = shutdown_tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(1), mixed_jh).await;
    }
}

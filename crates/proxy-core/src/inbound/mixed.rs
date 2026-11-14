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
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{Semaphore, watch},
    task::JoinHandle,
};
use url::Url;

use crate::{
    addr::{HostName, TargetAddr},
    error::{ProxyError, Result},
    outbound::{BoxedStream, OutboundHandler},
    router::Router,
    tracker::{ActiveConnection, TelemetryHub},
};

const MAX_MIXED_CONNECTIONS: usize = 1024;
const MAX_UDP_ASSOC_INFLIGHT: usize = 64;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
const OUTBOUND_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

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
                    let current_router = Arc::clone(&router.read());
                    let hub_clone = Arc::clone(&hub);
                    tokio::spawn(async move {
                        let _permit = permit;
                        if let Err(err) = handle_mixed_conn(
                            tcp,
                            peer,
                            local_mixed_port,
                            current_router,
                            snap_policy,
                            hub_clone,
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
    router: Arc<Router>,
    policy: MixedInboundPolicy,
    hub: Arc<TelemetryHub>,
) -> io::Result<()> {
    let mut first = [0u8; 1];
    let n = tokio::time::timeout(HANDSHAKE_TIMEOUT, tcp.peek(&mut first))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "mixed peek timeout"))??;
    if n == 0 {
        return Ok(());
    }

    if first[0] == 0x05 {
        handle_socks5(&mut tcp, peer, local_mixed_port, router, &policy, hub).await
    } else {
        handle_http_proxy(&mut tcp, peer, local_mixed_port, router, &policy, hub).await
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

async fn handle_socks5(
    tcp: &mut TcpStream,
    peer: SocketAddr,
    local_mixed_port: u16,
    router: Arc<Router>,
    policy: &MixedInboundPolicy,
    hub: Arc<TelemetryHub>,
) -> io::Result<()> {
    let (cmd, raw_target) = tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        negotiate_socks5_and_read_target(tcp, policy),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "SOCKS5 handshake timed out"))??;

    match cmd {
        0x01 => {
            // TCP CONNECT
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
            let decision = router
                .route_async_with_context(
                    Some(peer.ip()),
                    Some(peer),
                    crate::platform::process::SocketTransport::Tcp,
                    &raw_target,
                )
                .await;
            if let Err(err) =
                reject_forbidden_proxy_target(peer, local_mixed_port, policy, &decision.target)
            {
                hub.push_log(
                    "warn",
                    format!(
                        "[SOCKS5] Blocked forbidden resolved target {} from {peer}: {err}",
                        decision.target
                    ),
                );
                let rep = socks5_reply_code_for_io_error(&err);
                let _ = tcp
                    .write_all(&[0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .await;
                return Err(err);
            }
            let conn_guard = hub.register_connection_with_outbound_guard(
                "Mixed(SOCKS5)",
                "tcp",
                Some(peer),
                &decision.target,
                decision.restored_from_fake_ip.map(|ip| ip.to_string()),
                &decision.rule_type,
                &decision.rule_payload,
                decision.chains.clone(),
                decision.outbound.as_ref(),
            );
            let conn_entry = Arc::clone(conn_guard.connection());
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
                &decision.target,
                &conn_entry,
            )
            .await
            {
                Ok(s) => s,
                Err(err) => {
                    conn_guard.record_failed(&err.to_string());
                    let rep = socks5_reply_code_for_io_error(&err);
                    let _ = tcp
                        .write_all(&[0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                        .await;
                    return Err(err);
                }
            };
            conn_guard.mark_established();
            record_passive_proxy_delay(&router, decision.outbound.as_ref(), dial_start.elapsed());

            // Success reply: BND.ADDR 0.0.0.0:0
            tcp.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;
            let mut tracked = conn_guard.into_tracked_stream(outbound_stream);

            tokio::select! {
                res = tokio::io::copy_bidirectional_with_sizes(tcp, &mut tracked, 64 * 1024, 64 * 1024) => {
                    let _ = res?;
                }
                _ = conn_entry.closed() => {}
            }
            Ok(())
        }
        0x03 => {
            // UDP ASSOCIATE: bind ephemeral relay socket on the local interface facing `peer`
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
                .map(|a| a.ip())
                .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));
            let udp_sock = Arc::new(UdpSocket::bind(SocketAddr::new(local_ip, 0)).await?);
            let bound = udp_sock.local_addr()?;

            let mut reply = BytesMut::with_capacity(22);
            reply.put_slice(&[0x05, 0x00, 0x00]);
            TargetAddr::from(bound).encode_socks5(&mut reply)?;
            tcp.write_all(&reply).await?;

            let udp_reply_for_sink = Arc::clone(&udp_sock);
            let udp_nat = crate::inbound::udp_nat::UdpNatManager::new(
                "Mixed(SOCKS5-UDP)",
                64,
                Arc::clone(&hub),
                Arc::new(move |client_udp_addr, return_src_target, resp| {
                    let mut pkt = BytesMut::with_capacity(24 + resp.len());
                    pkt.put_slice(&[0x00, 0x00, 0x00]);
                    if return_src_target.encode_socks5(&mut pkt).is_ok() {
                        pkt.put_slice(&resp);
                        let sock = Arc::clone(&udp_reply_for_sink);
                        tokio::spawn(async move {
                            let _ = sock.send_to(&pkt, client_udp_addr).await;
                        });
                    }
                }),
            );

            let udp_task = {
                let udp_clone = Arc::clone(&udp_sock);
                let router_clone = Arc::clone(&router);
                let inflight_sem = Arc::new(Semaphore::new(MAX_UDP_ASSOC_INFLIGHT));
                let nat_clone = Arc::clone(&udp_nat);
                let policy_for_udp = Arc::new(policy.clone());
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 65535];
                    let mut locked_client_port: Option<u16> = initial_port_lock;
                    while let Ok((n, client_udp_addr)) = udp_clone.recv_from(&mut buf).await {
                        // Strictly enforce source IP association with the authenticated TCP peer!
                        if canonical_ip(client_udp_addr.ip()) != expected_client_ip {
                            continue;
                        }
                        if let Some(expected_port) = locked_client_port
                            && client_udp_addr.port() != expected_port
                        {
                            continue;
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
                            &policy_for_udp,
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

                        let payload = buf[3 + hdr_used..n].to_vec();
                        let payload = if let HostName::Ip(dst_ip) = raw_dst.host {
                            let raw_dst_sock = SocketAddr::new(dst_ip, raw_dst.port);
                            match nat_clone.try_send_fast(
                                client_udp_addr,
                                raw_dst_sock,
                                router_clone.epoch(),
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

                        let router_for_pkt = Arc::clone(&router_clone);
                        let nat_inner = Arc::clone(&nat_clone);
                        let policy_for_pkt = Arc::clone(&policy_for_udp);
                        tokio::spawn(async move {
                            let _permit = permit;
                            let route_epoch = router_for_pkt.epoch();
                            let decision = router_for_pkt
                                .route_async_with_context(
                                    Some(client_udp_addr.ip()),
                                    Some(client_udp_addr),
                                    crate::platform::process::SocketTransport::Udp,
                                    &raw_dst,
                                )
                                .await;
                            if reject_forbidden_proxy_target(
                                peer,
                                local_mixed_port,
                                &policy_for_pkt,
                                &decision.target,
                            )
                            .is_err()
                            {
                                return;
                            }
                            nat_inner
                                .send_datagram_with_epoch(
                                    client_udp_addr,
                                    raw_dst,
                                    decision.restored_from_fake_ip,
                                    decision.target,
                                    &decision.rule_type,
                                    &decision.rule_payload,
                                    decision.chains,
                                    decision.outbound,
                                    payload,
                                    route_epoch,
                                )
                                .await;
                        });
                    }
                })
            };

            // Keep UDP association alive until the TCP control stream closes
            let mut drain = [0u8; 64];
            loop {
                match tcp.read(&mut drain).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => continue,
                }
            }
            udp_task.abort();
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
        let raw_target: TargetAddr = if uri_part.contains(':') {
            uri_part.parse()?
        } else {
            TargetAddr::new_domain(uri_part, 443)?
        };
        if let Err(err) = reject_forbidden_proxy_target(peer, local_mixed_port, policy, &raw_target)
        {
            hub.push_log(
                "warn",
                format!("[HTTP-CONNECT] Blocked forbidden target {raw_target} from {peer}: {err}"),
            );
            let _ = tcp.write_all(http_error_response_for_io_error(&err)).await;
            return Err(err);
        }
        let decision = router
            .route_async_with_context(
                Some(peer.ip()),
                Some(peer),
                crate::platform::process::SocketTransport::Tcp,
                &raw_target,
            )
            .await;
        if let Err(err) =
            reject_forbidden_proxy_target(peer, local_mixed_port, policy, &decision.target)
        {
            hub.push_log(
                "warn",
                format!(
                    "[HTTP-CONNECT] Blocked forbidden resolved target {} from {peer}: {err}",
                    decision.target
                ),
            );
            let _ = tcp.write_all(http_error_response_for_io_error(&err)).await;
            return Err(err);
        }
        let conn_guard = hub.register_connection_with_outbound_guard(
            "Mixed(HTTP-CONNECT)",
            "tcp",
            Some(peer),
            &decision.target,
            decision.restored_from_fake_ip.map(|ip| ip.to_string()),
            &decision.rule_type,
            &decision.rule_payload,
            decision.chains.clone(),
            decision.outbound.as_ref(),
        );
        let conn_entry = Arc::clone(conn_guard.connection());
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
            &decision.target,
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

        tcp.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
        let mut tracked = conn_guard.into_tracked_stream(outbound_stream);
        if !trailing_body.is_empty() {
            tracked.write_all(trailing_body).await?;
        }

        tokio::select! {
            res = tokio::io::copy_bidirectional_with_sizes(tcp, &mut tracked, 64 * 1024, 64 * 1024) => {
                let _ = res?;
            }
            _ = conn_entry.closed() => {}
        }
        Ok(())
    } else {
        // Plain HTTP proxy request (e.g. `GET http://example.com/foo HTTP/1.1`)
        let (raw_target, origin_path) =
            if uri_part.starts_with("http://") || uri_part.starts_with("https://") {
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
                let mut p = if url.path().is_empty() {
                    "/".to_string()
                } else {
                    url.path().to_string()
                };
                if let Some(q) = url.query() {
                    p.push('?');
                    p.push_str(q);
                }
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
                let target = if host_val.contains(':') {
                    host_val.parse()?
                } else {
                    TargetAddr::new_domain(host_val, 80)?
                };
                (target, uri_part.to_string())
            };

        if let Err(err) = reject_forbidden_proxy_target(peer, local_mixed_port, policy, &raw_target)
        {
            hub.push_log(
                "warn",
                format!("[HTTP] Blocked forbidden target {raw_target} from {peer}: {err}"),
            );
            let _ = tcp.write_all(http_error_response_for_io_error(&err)).await;
            return Err(err);
        }

        let decision = router
            .route_async_with_context(
                Some(peer.ip()),
                Some(peer),
                crate::platform::process::SocketTransport::Tcp,
                &raw_target,
            )
            .await;
        if let Err(err) =
            reject_forbidden_proxy_target(peer, local_mixed_port, policy, &decision.target)
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
        let conn_guard = hub.register_connection_with_outbound_guard(
            "Mixed(HTTP)",
            "tcp",
            Some(peer),
            &decision.target,
            decision.restored_from_fake_ip.map(|ip| ip.to_string()),
            &decision.rule_type,
            &decision.rule_payload,
            decision.chains.clone(),
            decision.outbound.as_ref(),
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
            &decision.target,
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

        let mut rewritten = String::with_capacity(header_text.len());
        rewritten.push_str(&format!("{method} {origin_path} {version}\r\n"));
        for line in lines {
            if let Some((k, _)) = line.split_once(':') {
                let k_trim = k.trim();
                if k_trim.eq_ignore_ascii_case("proxy-connection")
                    || k_trim.eq_ignore_ascii_case("proxy-authorization")
                {
                    continue;
                }
            }
            rewritten.push_str(line);
            rewritten.push_str("\r\n");
        }
        rewritten.push_str("\r\n");

        let mut tracked = conn_guard.into_tracked_stream(outbound_stream);
        tracked.write_all(rewritten.as_bytes()).await?;
        if !trailing_body.is_empty() {
            tracked.write_all(trailing_body).await?;
        }

        tokio::select! {
            res = tokio::io::copy_bidirectional_with_sizes(tcp, &mut tracked, 64 * 1024, 64 * 1024) => {
                let _ = res?;
            }
            _ = conn_entry.closed() => {}
        }
        Ok(())
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
}

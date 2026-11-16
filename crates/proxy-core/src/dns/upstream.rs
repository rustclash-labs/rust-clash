use std::{
    collections::{HashMap, hash_map::DefaultHasher},
    hash::{Hash, Hasher},
    net::{IpAddr, SocketAddr},
    sync::{
        Arc, LazyLock, Weak,
        atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use bytes::{BufMut, BytesMut};
use dashmap::DashMap;
use parking_lot::Mutex;
use rustls::pki_types::CertificateDer;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    sync::{Mutex as AsyncMutex, mpsc, oneshot},
    task::AbortHandle,
};
use tokio_rustls::{TlsConnector, client::TlsStream};
use url::Url;

use crate::{
    error::{ProxyError, Result},
    platform::socket_protect::{
        current_protector_epoch, protected_tcp_connect_addr, protected_udp_bind,
    },
    tracker::TelemetryHub,
};

const DNS_IO_TIMEOUT: Duration = Duration::from_secs(3);
const DNS_POOLED_IO_TIMEOUT: Duration = Duration::from_millis(1200);
const DNS_TLS_IDLE_TTL: Duration = Duration::from_secs(45);
const MAX_IDLE_TLS_CONNS_PER_KEY: usize = 4;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct TlsDnsPoolKey {
    ns: SocketAddr,
    sni: String,
    skip_cert_verify: bool,
    is_doh: bool,
    extra_ca_hash: u64,
    protector_epoch: u64,
}

type TlsDnsPoolEntry = (Instant, u64, TlsStream<TcpStream>);
type TlsDnsPoolMap = HashMap<TlsDnsPoolKey, Vec<TlsDnsPoolEntry>>;
type H2Slot = Arc<AsyncMutex<Option<Arc<H2DohClient>>>>;

static TLS_DNS_POOL: LazyLock<Mutex<TlsDnsPoolMap>> = LazyLock::new(|| Mutex::new(HashMap::new()));
static H2_DNS_POOL: LazyLock<Mutex<HashMap<TlsDnsPoolKey, H2Slot>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static H2_LIVE_CLIENTS: LazyLock<Mutex<Vec<Weak<H2DohClient>>>> =
    LazyLock::new(|| Mutex::new(Vec::new()));

fn is_tls_pool_entry_fresh(
    stored_mono: Instant,
    stored_wall_ms: u64,
    now_mono: Instant,
    now_wall_ms: u64,
) -> bool {
    now_mono.duration_since(stored_mono) < DNS_TLS_IDLE_TTL
        && now_wall_ms.saturating_sub(stored_wall_ms) < DNS_TLS_IDLE_TTL.as_millis() as u64
}

fn get_h2_slot(key: &TlsDnsPoolKey) -> H2Slot {
    let mut guard = H2_DNS_POOL.lock();
    if guard.len() > 64 {
        guard.retain(|_, slot| {
            slot.try_lock()
                .map(|g| g.as_ref().is_some_and(|c| c.is_reusable()))
                .unwrap_or(true)
        });
    }
    Arc::clone(
        guard
            .entry(key.clone())
            .or_insert_with(|| Arc::new(AsyncMutex::new(None))),
    )
}

fn hash_extra_ca(extra_ca_der: &[CertificateDer<'static>]) -> u64 {
    if extra_ca_der.is_empty() {
        return 0;
    }
    let mut hasher = DefaultHasher::new();
    for cert in extra_ca_der {
        cert.as_ref().hash(&mut hasher);
    }
    hasher.finish()
}

fn pop_idle_tls_stream(key: &TlsDnsPoolKey) -> Option<TlsStream<TcpStream>> {
    let now = Instant::now();
    let now_wall_ms = TelemetryHub::now_ms();
    let mut guard = TLS_DNS_POOL.lock();
    let list = guard.get_mut(key)?;
    while let Some((stored_at, stored_wall_ms, stream)) = list.pop() {
        if is_tls_pool_entry_fresh(stored_at, stored_wall_ms, now, now_wall_ms) {
            return Some(stream);
        }
    }
    None
}

fn push_idle_tls_stream(key: TlsDnsPoolKey, stream: TlsStream<TcpStream>) {
    let now = Instant::now();
    let now_wall_ms = TelemetryHub::now_ms();
    let mut guard = TLS_DNS_POOL.lock();
    if guard.len() > 64 {
        guard.retain(|_, v| {
            v.retain(|(ts, ts_wall, _)| is_tls_pool_entry_fresh(*ts, *ts_wall, now, now_wall_ms));
            !v.is_empty()
        });
    }
    let entry = guard.entry(key).or_default();
    entry.retain(|(ts, ts_wall, _)| is_tls_pool_entry_fresh(*ts, *ts_wall, now, now_wall_ms));
    if entry.len() < MAX_IDLE_TLS_CONNS_PER_KEY {
        entry.push((now, now_wall_ms, stream));
    }
}

/// Proactively evict DoT and DoH (HTTP/1.1 & HTTP/2) pooled connections whose monotonic or
/// wall-clock idle age exceeded `DNS_TLS_IDLE_TTL` (e.g., across Android Doze/suspend transitions).
pub fn reap_expired_dns_upstream_pools() {
    let now_mono = Instant::now();
    let now_wall_ms = TelemetryHub::now_ms();
    {
        let mut tls_guard = TLS_DNS_POOL.lock();
        tls_guard.retain(|_, list| {
            list.retain(|(ts_mono, ts_wall, _)| {
                is_tls_pool_entry_fresh(*ts_mono, *ts_wall, now_mono, now_wall_ms)
            });
            !list.is_empty()
        });
    }
    {
        let mut h2_guard = H2_DNS_POOL.lock();
        h2_guard.retain(|_, slot| {
            slot.try_lock()
                .map(|mut g| {
                    if g.as_ref().is_some_and(|c| !c.is_reusable_at(now_wall_ms)) {
                        *g = None;
                    }
                    g.is_some()
                })
                .unwrap_or(true)
        });
    }
    let live: Vec<Arc<H2DohClient>> = {
        let mut guard = H2_LIVE_CLIENTS.lock();
        guard.retain(|w| w.strong_count() > 0);
        guard.iter().filter_map(|w| w.upgrade()).collect()
    };
    for client in live {
        let _ = client.is_reusable_at(now_wall_ms);
    }
}

/// Evict all pooled DoT/DoH TLS & HTTP/2 upstream sockets (called on network handoff, protector transition, and DNS cache flush).
pub fn clear_dns_upstream_pools() {
    TLS_DNS_POOL.lock().clear();
    H2_DNS_POOL.lock().clear();
    let live: Vec<Arc<H2DohClient>> = {
        let mut guard = H2_LIVE_CLIENTS.lock();
        std::mem::take(&mut *guard)
            .into_iter()
            .filter_map(|w| w.upgrade())
            .collect()
    };
    for client in live {
        client.abort();
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DnsEndpointHost {
    Ip(IpAddr),
    Domain(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DnsUpstream {
    Udp(SocketAddr),
    Tcp(SocketAddr),
    Tls {
        host: DnsEndpointHost,
        port: u16,
        sni: String,
        skip_cert_verify: bool,
    },
    Https {
        host: DnsEndpointHost,
        port: u16,
        sni: String,
        host_header: String,
        path_and_query: String,
        skip_cert_verify: bool,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BootstrapDnsServer {
    Udp(SocketAddr),
    Tcp(SocketAddr),
    Tls {
        sa: SocketAddr,
        sni: String,
        skip_cert_verify: bool,
    },
    Https {
        sa: SocketAddr,
        sni: String,
        host_header: String,
        path_and_query: String,
        skip_cert_verify: bool,
    },
}

fn strip_prefix_ignore_ascii_case<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    if s.len() >= prefix.len()
        && s.is_char_boundary(prefix.len())
        && s[..prefix.len()].eq_ignore_ascii_case(prefix)
    {
        Some(&s[prefix.len()..])
    } else {
        None
    }
}

impl BootstrapDnsServer {
    /// Parse a `default-nameserver` entry. Bootstrap servers MUST specify literal IP addresses
    /// (not domain names) to prevent chicken-and-egg DNS bootstrap loops or OS resolver leaks.
    pub fn parse(raw: &str) -> Result<Self> {
        let trimmed = crate::config::uri::trim_bom_and_controls(raw);
        if strip_prefix_ignore_ascii_case(trimmed, "https://").is_some()
            || strip_prefix_ignore_ascii_case(trimmed, "tls://").is_some()
        {
            match DnsUpstream::parse(trimmed)? {
                DnsUpstream::Tls {
                    host: DnsEndpointHost::Ip(ip),
                    port,
                    sni,
                    skip_cert_verify,
                } => {
                    return Ok(Self::Tls {
                        sa: SocketAddr::new(ip, port),
                        sni,
                        skip_cert_verify,
                    });
                }
                DnsUpstream::Https {
                    host: DnsEndpointHost::Ip(ip),
                    port,
                    sni,
                    host_header,
                    path_and_query,
                    skip_cert_verify,
                } => {
                    return Ok(Self::Https {
                        sa: SocketAddr::new(ip, port),
                        sni,
                        host_header,
                        path_and_query,
                        skip_cert_verify,
                    });
                }
                _ => {
                    return Err(ProxyError::Config(format!(
                        "default-nameserver '{raw}' must use a literal IP address, not a hostname"
                    )));
                }
            }
        }

        let s = trimmed.split('#').next().unwrap_or("").trim();
        if let Some(rest) = strip_prefix_ignore_ascii_case(s, "tcp://") {
            let sa = parse_ip_socket_addr(rest, 53).ok_or_else(|| {
                ProxyError::Config(format!(
                    "default-nameserver '{raw}' must use a literal IP address, not a hostname"
                ))
            })?;
            return Ok(Self::Tcp(sa));
        }
        let rest = strip_prefix_ignore_ascii_case(s, "udp://").unwrap_or(s);
        let sa = parse_ip_socket_addr(rest, 53).ok_or_else(|| {
            ProxyError::Config(format!(
                "default-nameserver '{raw}' must use a literal IP address, not a hostname"
            ))
        })?;
        Ok(Self::Udp(sa))
    }

    pub fn ip(&self) -> IpAddr {
        match self {
            Self::Udp(sa) | Self::Tcp(sa) | Self::Tls { sa, .. } | Self::Https { sa, .. } => {
                sa.ip()
            }
        }
    }

    pub async fn exchange(&self, query: &[u8]) -> Result<Vec<u8>> {
        self.exchange_with_ca(query, &[]).await
    }

    pub async fn exchange_with_ca(
        &self,
        query: &[u8],
        extra_ca_der: &[CertificateDer<'static>],
    ) -> Result<Vec<u8>> {
        match self {
            Self::Udp(sa) => forward_udp_dns_with_tcp_fallback(*sa, query).await,
            Self::Tcp(sa) => forward_tcp_dns(*sa, query).await,
            Self::Tls {
                sa,
                sni,
                skip_cert_verify,
            } => forward_dot_dns(*sa, sni, *skip_cert_verify, extra_ca_der, query).await,
            Self::Https {
                sa,
                sni,
                host_header,
                path_and_query,
                skip_cert_verify,
            } => {
                forward_doh_dns(
                    *sa,
                    sni,
                    host_header,
                    path_and_query,
                    *skip_cert_verify,
                    extra_ca_der,
                    query,
                )
                .await
            }
        }
    }
}

impl DnsUpstream {
    pub fn parse(raw: &str) -> Result<Self> {
        let trimmed = crate::config::uri::trim_bom_and_controls(raw);
        if trimmed.is_empty() {
            return Err(ProxyError::Config("empty DNS upstream entry".into()));
        }

        // Allow `#skip-cert-verify`, `#sni=...`, and `#name-cert-verify=...` fragment modifiers on DoT / DoH URLs
        let (main_part, frag) = match trimmed.split_once('#') {
            Some((a, b)) => (a.trim(), Some(b.trim())),
            None => (trimmed, None),
        };
        let mut skip_cert_verify = false;
        let mut sni_override: Option<String> = None;
        if let Some(f) = frag {
            for kv in f.split('&') {
                let kv = kv.trim();
                if kv.eq_ignore_ascii_case("skip-cert-verify")
                    || kv.eq_ignore_ascii_case("skip-cert-verify=true")
                    || kv.eq_ignore_ascii_case("insecure=1")
                {
                    skip_cert_verify = true;
                } else if let Some((k, v)) = kv.split_once('=')
                    && (k.trim().eq_ignore_ascii_case("sni")
                        || k.trim().eq_ignore_ascii_case("name-cert-verify"))
                    && !v.trim().is_empty()
                {
                    sni_override = Some(v.trim().to_string());
                }
            }
        }

        if let Some(https_rest) = strip_prefix_ignore_ascii_case(main_part, "https://") {
            let normalized_url = format!("https://{https_rest}");
            let parsed = Url::parse(&normalized_url)
                .map_err(|e| ProxyError::Config(format!("invalid DoH URL '{raw}': {e}")))?;
            let host_str = parsed
                .host_str()
                .ok_or_else(|| ProxyError::Config(format!("DoH URL '{raw}' missing host")))?;
            let clean_host = host_str.trim_start_matches('[').trim_end_matches(']');
            let host = if let Ok(ip) = clean_host.parse::<IpAddr>() {
                DnsEndpointHost::Ip(ip)
            } else {
                DnsEndpointHost::Domain(clean_host.to_ascii_lowercase())
            };
            let port = parsed.port_or_known_default().unwrap_or(443);
            let sni = sni_override.unwrap_or_else(|| clean_host.to_string());
            let host_header = if port == 443 {
                host_str.to_string()
            } else {
                format!("{host_str}:{port}")
            };
            let mut path_and_query = if parsed.path().is_empty() || parsed.path() == "/" {
                "/dns-query".to_string()
            } else {
                parsed.path().to_string()
            };
            if let Some(q) = parsed.query() {
                path_and_query.push('?');
                path_and_query.push_str(q);
            }
            return Ok(Self::Https {
                host,
                port,
                sni,
                host_header,
                path_and_query,
                skip_cert_verify,
            });
        }

        if let Some(tls_rest) = strip_prefix_ignore_ascii_case(main_part, "tls://") {
            let clean_rest = tls_rest.trim().trim_end_matches('/');
            if let Ok(IpAddr::V6(v6)) = clean_rest.parse::<IpAddr>() {
                return Ok(Self::Tls {
                    host: DnsEndpointHost::Ip(IpAddr::V6(v6)),
                    port: 853,
                    sni: sni_override.unwrap_or_else(|| v6.to_string()),
                    skip_cert_verify,
                });
            }
            let normalized_url = format!("tls://{tls_rest}");
            let parsed = Url::parse(&normalized_url)
                .map_err(|e| ProxyError::Config(format!("invalid DoT URL '{raw}': {e}")))?;
            let host_str = parsed
                .host_str()
                .ok_or_else(|| ProxyError::Config(format!("DoT URL '{raw}' missing host")))?;
            let clean_host = host_str.trim_start_matches('[').trim_end_matches(']');
            let host = if let Ok(ip) = clean_host.parse::<IpAddr>() {
                DnsEndpointHost::Ip(ip)
            } else {
                DnsEndpointHost::Domain(clean_host.to_ascii_lowercase())
            };
            let port = parsed.port().unwrap_or(853);
            return Ok(Self::Tls {
                host,
                port,
                sni: sni_override.unwrap_or_else(|| clean_host.to_string()),
                skip_cert_verify,
            });
        }

        if let Some(rest) = strip_prefix_ignore_ascii_case(main_part, "tcp://") {
            let sa = parse_ip_socket_addr(rest, 53).ok_or_else(|| {
                ProxyError::Config(format!(
                    "invalid TCP DNS server '{raw}': expected IP[:PORT]"
                ))
            })?;
            return Ok(Self::Tcp(sa));
        }

        let udp_rest = strip_prefix_ignore_ascii_case(main_part, "udp://").unwrap_or(main_part);
        let sa = parse_ip_socket_addr(udp_rest, 53)
            .ok_or_else(|| ProxyError::Config(format!("invalid DNS nameserver '{raw}'")))?;
        Ok(Self::Udp(sa))
    }

    pub fn requires_bootstrap(&self) -> bool {
        matches!(
            self,
            Self::Tls {
                host: DnsEndpointHost::Domain(_),
                ..
            } | Self::Https {
                host: DnsEndpointHost::Domain(_),
                ..
            }
        )
    }

    pub fn literal_socket_addr(&self) -> Option<SocketAddr> {
        match self {
            Self::Udp(sa) | Self::Tcp(sa) => Some(*sa),
            Self::Tls {
                host: DnsEndpointHost::Ip(ip),
                port,
                ..
            }
            | Self::Https {
                host: DnsEndpointHost::Ip(ip),
                port,
                ..
            } => Some(SocketAddr::new(*ip, *port)),
            _ => None,
        }
    }

    pub fn endpoint_host(&self) -> DnsEndpointHost {
        match self {
            Self::Udp(sa) | Self::Tcp(sa) => DnsEndpointHost::Ip(sa.ip()),
            Self::Tls { host, .. } | Self::Https { host, .. } => host.clone(),
        }
    }

    pub async fn exchange(
        &self,
        resolved_ips: &[IpAddr],
        query: &[u8],
        extra_ca_der: &[CertificateDer<'static>],
    ) -> Result<Vec<u8>> {
        match self {
            Self::Udp(sa) => forward_udp_dns_with_tcp_fallback(*sa, query).await,
            Self::Tcp(sa) => forward_tcp_dns(*sa, query).await,
            Self::Tls {
                port,
                sni,
                skip_cert_verify,
                ..
            } => {
                let mut last_err = ProxyError::Dns("no bootstrap IP for DoT server".into());
                for &ip in resolved_ips {
                    match forward_dot_dns(
                        SocketAddr::new(ip, *port),
                        sni,
                        *skip_cert_verify,
                        extra_ca_der,
                        query,
                    )
                    .await
                    {
                        Ok(resp) => return Ok(resp),
                        Err(e) => last_err = e,
                    }
                }
                Err(last_err)
            }
            Self::Https {
                port,
                sni,
                host_header,
                path_and_query,
                skip_cert_verify,
                ..
            } => {
                let mut last_err = ProxyError::Dns("no bootstrap IP for DoH server".into());
                for &ip in resolved_ips {
                    match forward_doh_dns(
                        SocketAddr::new(ip, *port),
                        sni,
                        host_header,
                        path_and_query,
                        *skip_cert_verify,
                        extra_ca_der,
                        query,
                    )
                    .await
                    {
                        Ok(resp) => return Ok(resp),
                        Err(e) => last_err = e,
                    }
                }
                Err(last_err)
            }
        }
    }
}

pub fn parse_ip_socket_addr(s: &str, default_port: u16) -> Option<SocketAddr> {
    let trimmed = s.trim();
    if let Ok(sa) = trimmed.parse::<SocketAddr>() {
        return Some(sa);
    }
    if let Ok(ip) = trimmed.parse::<IpAddr>() {
        return Some(SocketAddr::new(ip, default_port));
    }
    if let Some(ip_inner) = trimmed.strip_prefix('[').and_then(|r| r.strip_suffix(']'))
        && let Ok(ip) = ip_inner.parse::<IpAddr>()
    {
        return Some(SocketAddr::new(ip, default_port));
    }
    None
}

/// Forward a UDP DNS query over a `SocketProtector`-guarded socket, verifying RFC 5452
/// Transaction ID + `QR=1`. If the response has `TC=1` (Truncated), automatically retries
/// over RFC 1035 TCP!
pub async fn forward_udp_dns_with_tcp_fallback(ns: SocketAddr, query: &[u8]) -> Result<Vec<u8>> {
    let resp = forward_udp_dns_raw(ns, query).await?;
    if resp.len() >= 12
        && (resp[2] & 0x02) != 0
        && let Ok(tcp_resp) = forward_tcp_dns(ns, query).await
    {
        return Ok(tcp_resp);
    }
    Ok(resp)
}

async fn forward_udp_dns_raw(ns: SocketAddr, query: &[u8]) -> Result<Vec<u8>> {
    if query.len() < 12 {
        return Err(ProxyError::Dns("DNS query shorter than 12 bytes".into()));
    }
    let expected_id = [query[0], query[1]];
    let expected_query = if u16::from_be_bytes([query[4], query[5]]) >= 1 {
        crate::dns::wire::DnsQueryPacket::parse(query).ok()
    } else {
        None
    };
    let bind_addr: SocketAddr = if ns.is_ipv4() {
        "0.0.0.0:0".parse().expect("valid v4 bind")
    } else {
        "[::]:0".parse().expect("valid v6 bind")
    };
    let sock = protected_udp_bind(bind_addr, Some(ns))?;
    sock.connect(ns).await?;
    sock.send(query).await?;

    let mut buf = vec![0u8; 8192];
    let started = tokio::time::Instant::now();
    let deadline = started + Duration::from_secs(2);
    let mut retry_at = Some(started + Duration::from_millis(650));
    loop {
        let now = tokio::time::Instant::now();
        let remaining = deadline.saturating_duration_since(now);
        if remaining.is_zero() {
            return Err(ProxyError::Timeout);
        }
        let wait_dur = match retry_at {
            Some(rt) => rt.saturating_duration_since(now).min(remaining),
            None => remaining,
        };
        match tokio::time::timeout(wait_dur, sock.recv(&mut buf)).await {
            Err(_) => {
                if retry_at.take().is_some() && tokio::time::Instant::now() < deadline {
                    let _ = sock.send(query).await;
                    continue;
                }
                return Err(ProxyError::Timeout);
            }
            Ok(Err(e)) => return Err(e.into()),
            Ok(Ok(n)) => {
                if n < 12 {
                    continue;
                }
                if (buf[2] & 0x80) == 0 || [buf[0], buf[1]] != expected_id {
                    continue;
                }
                if !dns_questions_match(expected_query.as_ref(), &buf[..n]) {
                    continue;
                }
                return Ok(buf[..n].to_vec());
            }
        }
    }
}

fn dns_questions_match(expected: Option<&crate::dns::wire::DnsQueryPacket>, resp: &[u8]) -> bool {
    if resp.len() < 12 {
        return false;
    }
    let Some(exp) = expected else {
        return true;
    };
    let resp_qdcount = u16::from_be_bytes([resp[4], resp[5]]);
    if resp_qdcount < 1 {
        let resp_ancount = u16::from_be_bytes([resp[6], resp[7]]);
        return resp_ancount == 0;
    }
    let Ok(resp_pkt) = crate::dns::wire::DnsQueryPacket::parse(resp) else {
        return false;
    };
    resp_pkt.question.qtype == exp.question.qtype
        && resp_pkt.question.qclass == exp.question.qclass
        && resp_pkt
            .question
            .name
            .trim_end_matches('.')
            .eq_ignore_ascii_case(exp.question.name.trim_end_matches('.'))
}

/// Forward a DNS query over RFC 1035 TCP (2-byte big-endian length prefix) using `SocketProtector`.
pub async fn forward_tcp_dns(ns: SocketAddr, query: &[u8]) -> Result<Vec<u8>> {
    if query.len() < 12 || query.len() > u16::MAX as usize {
        return Err(ProxyError::Dns("invalid TCP DNS query length".into()));
    }
    tokio::time::timeout(DNS_IO_TIMEOUT, async {
        let mut tcp = protected_tcp_connect_addr(ns).await?;
        exchange_length_prefixed_dns(&mut tcp, query).await
    })
    .await
    .map_err(|_| ProxyError::Timeout)?
}

/// Forward a DNS query over RFC 7858 DNS-over-TLS (`tls://`) using `SocketProtector` and idle TLS pooling.
pub async fn forward_dot_dns(
    ns: SocketAddr,
    sni: &str,
    skip_cert_verify: bool,
    extra_ca_der: &[CertificateDer<'static>],
    query: &[u8],
) -> Result<Vec<u8>> {
    if query.len() < 12 || query.len() > u16::MAX as usize {
        return Err(ProxyError::Dns("invalid DoT query length".into()));
    }
    let pool_key = TlsDnsPoolKey {
        ns,
        sni: sni.to_string(),
        skip_cert_verify,
        is_doh: false,
        extra_ca_hash: hash_extra_ca(extra_ca_der),
        protector_epoch: current_protector_epoch(),
    };

    if let Some(mut pooled) = pop_idle_tls_stream(&pool_key)
        && let Ok(Ok(resp)) = tokio::time::timeout(
            DNS_POOLED_IO_TIMEOUT,
            exchange_length_prefixed_dns(&mut pooled, query),
        )
        .await
    {
        push_idle_tls_stream(pool_key, pooled);
        return Ok(resp);
    }

    let client_cfg =
        crate::crypto::tls::build_tls_client_config(skip_cert_verify, extra_ca_der, &[])?;
    let connector = TlsConnector::from(client_cfg);
    let server_name = crate::crypto::tls::parse_server_name(sni)?;

    tokio::time::timeout(DNS_IO_TIMEOUT, async {
        let tcp = protected_tcp_connect_addr(ns).await?;
        let mut tls = connector.connect(server_name, tcp).await?;
        let resp = exchange_length_prefixed_dns(&mut tls, query).await?;
        push_idle_tls_stream(pool_key, tls);
        Ok(resp)
    })
    .await
    .map_err(|_| ProxyError::Timeout)?
}

async fn exchange_length_prefixed_dns<S>(stream: &mut S, query: &[u8]) -> Result<Vec<u8>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let expected_id = [query[0], query[1]];
    let expected_query = crate::dns::wire::DnsQueryPacket::parse(query).ok();
    let mut frame = BytesMut::with_capacity(2 + query.len());
    frame.put_u16(query.len() as u16);
    frame.put_slice(query);
    stream.write_all(&frame).await?;
    stream.flush().await?;

    let resp_len = stream.read_u16().await? as usize;
    if !(12..=65535).contains(&resp_len) {
        return Err(ProxyError::Dns(format!(
            "invalid length-prefixed DNS response size {resp_len}"
        )));
    }
    let mut resp = vec![0u8; resp_len];
    stream.read_exact(&mut resp).await?;
    if (resp[2] & 0x80) == 0 || [resp[0], resp[1]] != expected_id {
        return Err(ProxyError::Dns(
            "TCP/DoT DNS response failed QR or Transaction-ID validation".into(),
        ));
    }
    if !dns_questions_match(expected_query.as_ref(), &resp) {
        return Err(ProxyError::Dns(
            "TCP/DoT DNS response failed question validation".into(),
        ));
    }
    Ok(resp)
}

async fn exchange_doh_over_stream(
    tls: &mut TlsStream<TcpStream>,
    host_header: &str,
    path_and_query: &str,
    doh_wire: &[u8],
    orig_id: [u8; 2],
) -> Result<(Vec<u8>, bool)> {
    let expected_query = crate::dns::wire::DnsQueryPacket::parse(doh_wire).ok();
    let req_head = format!(
        "POST {path_and_query} HTTP/1.1\r\n\
         Host: {host_header}\r\n\
         User-Agent: rust-clash/{}\r\n\
         Accept: application/dns-message\r\n\
         Content-Type: application/dns-message\r\n\
         Content-Length: {}\r\n\
         Connection: keep-alive\r\n\r\n",
        env!("CARGO_PKG_VERSION"),
        doh_wire.len()
    );
    tls.write_all(req_head.as_bytes()).await?;
    tls.write_all(doh_wire).await?;
    tls.flush().await?;

    let mut raw_http = Vec::with_capacity(1024);
    let mut chunk = [0u8; 2048];
    loop {
        let n = tls.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        raw_http.extend_from_slice(&chunk[..n]);
        if raw_http.len() > 65_536 {
            return Err(ProxyError::Dns("DoH HTTP response exceeded 64 KiB".into()));
        }
        if let Some((parsed, server_closed)) = try_extract_complete_http_body(&raw_http)? {
            let wire = finalize_doh_body(parsed, expected_query.as_ref(), orig_id)?;
            return Ok((wire, !server_closed));
        }
    }

    let body = parse_http_response_body(&raw_http)?;
    let wire = finalize_doh_body(body, expected_query.as_ref(), orig_id)?;
    Ok((wire, false))
}

fn evict_h2_client_from_slot(slot: &H2Slot, target: &Arc<H2DohClient>) {
    if let Ok(mut slot_guard) = slot.try_lock() {
        if slot_guard.as_ref().is_some_and(|c| Arc::ptr_eq(c, target)) {
            *slot_guard = None;
        }
    } else {
        let slot_bg = Arc::clone(slot);
        let target_bg = Arc::clone(target);
        tokio::spawn(async move {
            let mut slot_guard = slot_bg.lock().await;
            if slot_guard
                .as_ref()
                .is_some_and(|c| Arc::ptr_eq(c, &target_bg))
            {
                *slot_guard = None;
            }
        });
    }
}

/// Forward a DNS query over RFC 8484 DNS-over-HTTPS (`POST` `application/dns-message`) using
/// `SocketProtector`, multiplexed HTTP/2 (`h2`) session pooling, and HTTP/1.1 keep-alive fallback.
pub async fn forward_doh_dns(
    ns: SocketAddr,
    sni: &str,
    host_header: &str,
    path_and_query: &str,
    skip_cert_verify: bool,
    extra_ca_der: &[CertificateDer<'static>],
    query: &[u8],
) -> Result<Vec<u8>> {
    forward_doh_dns_with_timeout(
        ns,
        sni,
        host_header,
        path_and_query,
        skip_cert_verify,
        extra_ca_der,
        query,
        DNS_IO_TIMEOUT,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn forward_doh_dns_with_timeout(
    ns: SocketAddr,
    sni: &str,
    host_header: &str,
    path_and_query: &str,
    skip_cert_verify: bool,
    extra_ca_der: &[CertificateDer<'static>],
    query: &[u8],
    io_timeout: Duration,
) -> Result<Vec<u8>> {
    if query.len() < 12 {
        return Err(ProxyError::Dns("invalid DoH query length".into()));
    }
    let orig_id = [query[0], query[1]];
    // RFC 8484 Section 4.1: DoH clients SHOULD set DNS ID = 0 for HTTP cache friendliness;
    // we restore `orig_id` onto the returned DNS wire packet before returning to caller!
    let mut doh_wire = query.to_vec();
    doh_wire[0] = 0;
    doh_wire[1] = 0;
    let expected_query = crate::dns::wire::DnsQueryPacket::parse(&doh_wire).ok();

    let pool_key = TlsDnsPoolKey {
        ns,
        sni: sni.to_string(),
        skip_cert_verify,
        is_doh: true,
        extra_ca_hash: hash_extra_ca(extra_ca_der),
        protector_epoch: current_protector_epoch(),
    };

    let pooled_probe_timeout = io_timeout.min(DNS_POOLED_IO_TIMEOUT);

    // 1. Fast path for HTTP/1.1 keep-alive servers already in `TLS_DNS_POOL`
    if let Some(mut pooled) = pop_idle_tls_stream(&pool_key)
        && let Ok(Ok((resp, reusable))) = tokio::time::timeout(
            pooled_probe_timeout,
            exchange_doh_over_stream(&mut pooled, host_header, path_and_query, &doh_wire, orig_id),
        )
        .await
    {
        if reusable {
            push_idle_tls_stream(pool_key, pooled);
        }
        return Ok(resp);
    }

    let alpn = [b"h2".to_vec(), b"http/1.1".to_vec()];
    let client_cfg =
        crate::crypto::tls::build_tls_client_config(skip_cert_verify, extra_ca_der, &alpn)?;
    let connector = TlsConnector::from(client_cfg);
    let server_name = crate::crypto::tls::parse_server_name(sni)?;

    let h2_slot = get_h2_slot(&pool_key);
    let mut used_h2_client: Option<Arc<H2DohClient>> = None;

    let first_attempt = match tokio::time::timeout(io_timeout, async {
        let mut slot_guard = h2_slot.lock().await;
        if let Some(existing) = slot_guard.as_ref()
            && existing.is_reusable()
        {
            let client = Arc::clone(existing);
            used_h2_client = Some(Arc::clone(&client));
            drop(slot_guard);
            if io_timeout > DNS_POOLED_IO_TIMEOUT {
                return match tokio::time::timeout(
                    DNS_POOLED_IO_TIMEOUT,
                    client.exchange(host_header, path_and_query, &doh_wire),
                )
                .await
                {
                    Ok(outcome) => outcome,
                    Err(_) => {
                        client.mark_closed_on_timeout();
                        evict_h2_client_from_slot(&h2_slot, &client);
                        H2DohOutcome::RetryOnFreshConn
                    }
                };
            }
            return client
                .exchange(host_header, path_and_query, &doh_wire)
                .await;
        }
        *slot_guard = None;

        // Re-check HTTP/1.1 pool in case a sibling caller just populated it
        if let Some(mut pooled) = pop_idle_tls_stream(&pool_key)
            && let Ok(Ok((resp, reusable))) = tokio::time::timeout(
                pooled_probe_timeout,
                exchange_doh_over_stream(
                    &mut pooled,
                    host_header,
                    path_and_query,
                    &doh_wire,
                    orig_id,
                ),
            )
            .await
        {
            drop(slot_guard);
            if reusable {
                push_idle_tls_stream(pool_key.clone(), pooled);
            }
            let mut raw = resp;
            raw[0] = 0;
            raw[1] = 0;
            return H2DohOutcome::Body(raw);
        }

        let tcp = match protected_tcp_connect_addr(ns).await {
            Ok(s) => s,
            Err(e) => return H2DohOutcome::Fatal(ProxyError::Io(e)),
        };
        let mut tls = match connector.connect(server_name.clone(), tcp).await {
            Ok(s) => s,
            Err(e) => return H2DohOutcome::Fatal(ProxyError::Io(e)),
        };

        if tls.get_ref().1.alpn_protocol() == Some(b"h2") {
            let client = H2DohClient::spawn(tls);
            *slot_guard = Some(Arc::clone(&client));
            used_h2_client = Some(Arc::clone(&client));
            drop(slot_guard);
            client
                .exchange(host_header, path_and_query, &doh_wire)
                .await
        } else {
            drop(slot_guard);
            match exchange_doh_over_stream(
                &mut tls,
                host_header,
                path_and_query,
                &doh_wire,
                orig_id,
            )
            .await
            {
                Ok((resp, reusable)) => {
                    if reusable {
                        push_idle_tls_stream(pool_key.clone(), tls);
                    }
                    let mut raw = resp;
                    raw[0] = 0;
                    raw[1] = 0;
                    H2DohOutcome::Body(raw)
                }
                Err(e) => H2DohOutcome::Fatal(e),
            }
        }
    })
    .await
    {
        Ok(outcome) => outcome,
        Err(_) => {
            if let Some(dead_client) = used_h2_client.take() {
                dead_client.mark_closed_on_timeout();
                evict_h2_client_from_slot(&h2_slot, &dead_client);
            }
            return Err(ProxyError::Timeout);
        }
    };

    match first_attempt {
        H2DohOutcome::Body(body) => finalize_doh_body(body, expected_query.as_ref(), orig_id),
        H2DohOutcome::Fatal(err) => {
            if let Some(prev) = used_h2_client.as_ref()
                && !prev.is_reusable()
            {
                evict_h2_client_from_slot(&h2_slot, prev);
            }
            Err(err)
        }
        H2DohOutcome::RetryOnFreshConn => {
            if let Some(prev) = used_h2_client.as_ref()
                && !prev.is_reusable()
            {
                evict_h2_client_from_slot(&h2_slot, prev);
            }
            // Unprocessed stream hit server close / GOAWAY / REFUSED_STREAM: retry once on a fresh connection!
            tokio::time::timeout(io_timeout, async {
                let tcp = protected_tcp_connect_addr(ns).await?;
                let mut tls = connector.connect(server_name, tcp).await?;
                if tls.get_ref().1.alpn_protocol() == Some(b"h2") {
                    exchange_doh_h2_over_stream(
                        &mut tls,
                        host_header,
                        path_and_query,
                        &doh_wire,
                        orig_id,
                    )
                    .await
                } else {
                    let (resp, reusable) = exchange_doh_over_stream(
                        &mut tls,
                        host_header,
                        path_and_query,
                        &doh_wire,
                        orig_id,
                    )
                    .await?;
                    if reusable {
                        push_idle_tls_stream(pool_key, tls);
                    }
                    Ok(resp)
                }
            })
            .await
            .map_err(|_| ProxyError::Timeout)?
        }
    }
}

fn finalize_doh_body(
    mut body: Vec<u8>,
    expected_query: Option<&crate::dns::wire::DnsQueryPacket>,
    orig_id: [u8; 2],
) -> Result<Vec<u8>> {
    if body.len() < 12 || (body[2] & 0x80) == 0 || !dns_questions_match(expected_query, &body) {
        return Err(ProxyError::Dns(
            "invalid DNS wire payload in DoH response".into(),
        ));
    }
    body[0] = orig_id[0];
    body[1] = orig_id[1];
    Ok(body)
}

fn find_header_end(raw: &[u8]) -> Option<usize> {
    raw.windows(4).position(|w| w == b"\r\n\r\n")
}

fn try_extract_complete_http_body(raw: &[u8]) -> Result<Option<(Vec<u8>, bool)>> {
    let Some(hdr_end) = find_header_end(raw) else {
        return Ok(None);
    };
    let head_str = std::str::from_utf8(&raw[..hdr_end])
        .map_err(|_| ProxyError::Dns("invalid UTF-8 in DoH HTTP header".into()))?;
    let mut lines = head_str.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    let status_code = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    if status_code != 200 {
        return Err(ProxyError::Dns(format!(
            "DoH server returned HTTP status {status_code}"
        )));
    }

    let mut content_length: Option<usize> = None;
    let mut is_chunked = false;
    let mut server_closed = status_line.starts_with("HTTP/1.0");
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            let k_trim = k.trim();
            if k_trim.eq_ignore_ascii_case("content-length") {
                content_length = v.trim().parse::<usize>().ok();
            } else if k_trim.eq_ignore_ascii_case("transfer-encoding")
                && v.to_ascii_lowercase().contains("chunked")
            {
                is_chunked = true;
            } else if k_trim.eq_ignore_ascii_case("connection")
                && v.to_ascii_lowercase().contains("close")
            {
                server_closed = true;
            }
        }
    }

    let body_slice = &raw[hdr_end + 4..];
    if let Some(cl) = content_length {
        if body_slice.len() >= cl {
            let exact_end = body_slice.len() == cl;
            return Ok(Some((
                body_slice[..cl].to_vec(),
                server_closed || !exact_end,
            )));
        }
        return Ok(None);
    }
    if is_chunked {
        return Ok(decode_chunked_if_complete(body_slice)?.map(|decoded| (decoded, server_closed)));
    }
    Ok(None)
}

fn parse_http_response_body(raw: &[u8]) -> Result<Vec<u8>> {
    if let Some((done, _)) = try_extract_complete_http_body(raw)? {
        return Ok(done);
    }
    let hdr_end = find_header_end(raw)
        .ok_or_else(|| ProxyError::Dns("incomplete DoH HTTP response headers".into()))?;
    let head_str = std::str::from_utf8(&raw[..hdr_end])
        .map_err(|_| ProxyError::Dns("invalid UTF-8 in DoH HTTP header".into()))?;
    let status_code = head_str
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    if status_code != 200 {
        return Err(ProxyError::Dns(format!(
            "DoH server returned HTTP status {status_code}"
        )));
    }
    Ok(raw[hdr_end + 4..].to_vec())
}

const MAX_DNS_MESSAGE_SIZE: usize = 65_535;

fn decode_chunked_if_complete(mut input: &[u8]) -> Result<Option<Vec<u8>>> {
    let mut out = Vec::new();
    loop {
        let Some(crlf) = input.windows(2).position(|w| w == b"\r\n") else {
            return Ok(None);
        };
        let len_str = std::str::from_utf8(&input[..crlf])
            .map_err(|_| ProxyError::Dns("invalid chunk size header".into()))?
            .split(';')
            .next()
            .unwrap_or("")
            .trim();
        let chunk_len = usize::from_str_radix(len_str, 16)
            .map_err(|_| ProxyError::Dns("invalid hex chunk size".into()))?;
        if chunk_len > MAX_DNS_MESSAGE_SIZE {
            return Err(ProxyError::Dns(
                "DoH chunk exceeds maximum DNS message size".into(),
            ));
        }
        let after_hdr = crlf
            .checked_add(2)
            .ok_or_else(|| ProxyError::Dns("DoH chunk header offset overflow".into()))?;
        input = &input[after_hdr..];
        if chunk_len == 0 {
            if input.len() < 2 {
                return Ok(None);
            }
            return Ok(Some(out));
        }
        let total_len = out
            .len()
            .checked_add(chunk_len)
            .filter(|&n| n <= MAX_DNS_MESSAGE_SIZE)
            .ok_or_else(|| ProxyError::Dns("DoH chunk exceeds maximum DNS message size".into()))?;
        let chunk_end = chunk_len
            .checked_add(2)
            .ok_or_else(|| ProxyError::Dns("DoH chunk exceeds maximum DNS message size".into()))?;
        if input.len() < chunk_end {
            return Ok(None);
        }
        if &input[chunk_len..chunk_end] != b"\r\n" {
            return Err(ProxyError::Dns("invalid DoH chunk delimiter".into()));
        }
        out.reserve(total_len.saturating_sub(out.len()));
        out.extend_from_slice(&input[..chunk_len]);
        input = &input[chunk_end..];
    }
}

const H2_CLIENT_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const H2_FRAME_DATA: u8 = 0x0;
const H2_FRAME_HEADERS: u8 = 0x1;
const H2_FRAME_RST_STREAM: u8 = 0x3;
const H2_FRAME_SETTINGS: u8 = 0x4;
const H2_FRAME_PING: u8 = 0x6;
const H2_FRAME_GOAWAY: u8 = 0x7;
const H2_FRAME_WINDOW_UPDATE: u8 = 0x8;
const H2_FRAME_CONTINUATION: u8 = 0x9;

const H2_FLAG_END_STREAM: u8 = 0x1;
const H2_FLAG_ACK: u8 = 0x1;
const H2_FLAG_END_HEADERS: u8 = 0x4;
const H2_FLAG_PADDED: u8 = 0x8;
const H2_FLAG_PRIORITY: u8 = 0x20;

fn put_h2_frame_header(buf: &mut BytesMut, len: usize, ftype: u8, flags: u8, stream_id: u32) {
    buf.put_u8(((len >> 16) & 0xff) as u8);
    buf.put_u8(((len >> 8) & 0xff) as u8);
    buf.put_u8((len & 0xff) as u8);
    buf.put_u8(ftype);
    buf.put_u8(flags);
    buf.put_u32(stream_id & 0x7fff_ffff);
}

fn put_hpack_int(buf: &mut BytesMut, first_mask: u8, prefix_bits: u8, mut val: usize) {
    let max_prefix = (1usize << prefix_bits) - 1;
    if val < max_prefix {
        buf.put_u8(first_mask | (val as u8));
        return;
    }
    buf.put_u8(first_mask | (max_prefix as u8));
    val -= max_prefix;
    while val >= 128 {
        buf.put_u8(((val & 0x7f) as u8) | 0x80);
        val >>= 7;
    }
    buf.put_u8(val as u8);
}

fn put_hpack_literal_indexed_name(buf: &mut BytesMut, name_index: usize, value: &[u8]) {
    // Literal Header Field without Indexing (0000xxxx, 4-bit prefix)
    put_hpack_int(buf, 0x00, 4, name_index);
    // Raw (non-Huffman) string length (7-bit prefix, H=0)
    put_hpack_int(buf, 0x00, 7, value.len());
    buf.put_slice(value);
}

async fn read_h2_frame<S>(stream: &mut S) -> Result<(u8, u8, u32, Vec<u8>)>
where
    S: AsyncRead + Unpin,
{
    let mut hdr = [0u8; 9];
    stream.read_exact(&mut hdr).await?;
    let len = ((hdr[0] as usize) << 16) | ((hdr[1] as usize) << 8) | (hdr[2] as usize);
    if len > 65_536 {
        return Err(ProxyError::Dns(format!(
            "DoH HTTP/2 frame length {len} exceeds 64 KiB limit"
        )));
    }
    let ftype = hdr[3];
    let flags = hdr[4];
    let stream_id = u32::from_be_bytes([hdr[5], hdr[6], hdr[7], hdr[8]]) & 0x7fff_ffff;
    let mut payload = vec![0u8; len];
    if len > 0 {
        stream.read_exact(&mut payload).await?;
    }
    Ok((ftype, flags, stream_id, payload))
}

fn strip_h2_padding(payload: &[u8], flags: u8) -> Result<&[u8]> {
    if (flags & H2_FLAG_PADDED) == 0 {
        return Ok(payload);
    }
    let Some((&pad_len_u8, rest)) = payload.split_first() else {
        return Err(ProxyError::Dns("truncated padded HTTP/2 frame".into()));
    };
    let pad_len = pad_len_u8 as usize;
    if pad_len > rest.len() {
        return Err(ProxyError::Dns("invalid HTTP/2 frame pad length".into()));
    }
    Ok(&rest[..rest.len() - pad_len])
}

const H2_MAX_STREAMS_PER_CONN: u32 = 512;
const H2_CONN_WINDOW_INCREMENT: u32 = 1_048_576;

enum H2DohOutcome {
    Body(Vec<u8>),
    RetryOnFreshConn,
    Fatal(ProxyError),
}

struct H2StreamAcc {
    seen_final_status: bool,
    body: Vec<u8>,
    tx: oneshot::Sender<H2DohOutcome>,
}

struct PendingStreamGuard<'a> {
    map: &'a DashMap<u32, H2StreamAcc>,
    sid: u32,
    disarmed: bool,
}

impl Drop for PendingStreamGuard<'_> {
    fn drop(&mut self) {
        if !self.disarmed {
            self.map.remove(&self.sid);
        }
    }
}

struct H2DohClient {
    stream_open_lock: Mutex<()>,
    write_tx: mpsc::UnboundedSender<BytesMut>,
    pending: Arc<DashMap<u32, H2StreamAcc>>,
    next_stream_id: AtomicU32,
    max_concurrent: Arc<AtomicU32>,
    last_rx_wall_ms: Arc<AtomicU64>,
    closed: Arc<AtomicBool>,
    reader_abort: AbortHandle,
    writer_abort: AbortHandle,
}

fn encode_doh_h2_request_frames(
    out: &mut BytesMut,
    stream_id: u32,
    host_header: &str,
    path_and_query: &str,
    doh_wire: &[u8],
) {
    let mut hblock = BytesMut::with_capacity(192);
    // `:method: POST` (static index 3 -> 0x83), `:scheme: https` (static index 7 -> 0x87)
    hblock.put_u8(0x83);
    hblock.put_u8(0x87);
    // `:authority` (static index 1), `:path` (static index 4)
    put_hpack_literal_indexed_name(&mut hblock, 1, host_header.as_bytes());
    put_hpack_literal_indexed_name(&mut hblock, 4, path_and_query.as_bytes());
    // `user-agent` (static index 58), `accept` (static index 19), `content-type` (static index 31), `content-length` (static index 28)
    let ua = format!("rust-clash/{}", env!("CARGO_PKG_VERSION"));
    put_hpack_literal_indexed_name(&mut hblock, 58, ua.as_bytes());
    put_hpack_literal_indexed_name(&mut hblock, 19, b"application/dns-message");
    put_hpack_literal_indexed_name(&mut hblock, 31, b"application/dns-message");
    let cl_str = doh_wire.len().to_string();
    put_hpack_literal_indexed_name(&mut hblock, 28, cl_str.as_bytes());

    put_h2_frame_header(
        out,
        hblock.len(),
        H2_FRAME_HEADERS,
        H2_FLAG_END_HEADERS,
        stream_id,
    );
    out.put_slice(&hblock);
    put_h2_frame_header(
        out,
        doh_wire.len(),
        H2_FRAME_DATA,
        H2_FLAG_END_STREAM,
        stream_id,
    );
    out.put_slice(doh_wire);
}

impl H2DohClient {
    fn spawn(tls: TlsStream<TcpStream>) -> Arc<Self> {
        Self::spawn_io(tls)
    }

    fn spawn_io<S>(io: S) -> Arc<Self>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (mut rd, mut wr) = tokio::io::split(io);
        let (write_tx, mut write_rx) = mpsc::unbounded_channel::<BytesMut>();
        let pending: Arc<DashMap<u32, H2StreamAcc>> = Arc::new(DashMap::new());
        let closed = Arc::new(AtomicBool::new(false));
        let max_concurrent = Arc::new(AtomicU32::new(100));
        let last_rx_wall_ms = Arc::new(AtomicU64::new(TelemetryHub::now_ms()));

        // Enqueue HTTP/2 client preface + SETTINGS (HEADER_TABLE_SIZE=0, ENABLE_PUSH=0) + 1 MiB connection WINDOW_UPDATE first
        let mut init_buf = BytesMut::with_capacity(64);
        init_buf.put_slice(H2_CLIENT_PREFACE);
        put_h2_frame_header(&mut init_buf, 12, H2_FRAME_SETTINGS, 0, 0);
        init_buf.put_u16(0x0001);
        init_buf.put_u32(0);
        init_buf.put_u16(0x0002);
        init_buf.put_u32(0);
        put_h2_frame_header(&mut init_buf, 4, H2_FRAME_WINDOW_UPDATE, 0, 0);
        init_buf.put_u32(H2_CONN_WINDOW_INCREMENT);
        let _ = write_tx.send(init_buf);

        let closed_wr = Arc::clone(&closed);
        let writer_jh = tokio::spawn(async move {
            while let Some(mut chunk) = write_rx.recv().await {
                while chunk.len() < 16_384 {
                    match write_rx.try_recv() {
                        Ok(more) => chunk.extend_from_slice(&more),
                        Err(_) => break,
                    }
                }
                if wr.write_all(&chunk).await.is_err() || wr.flush().await.is_err() {
                    closed_wr.store(true, Ordering::Release);
                    break;
                }
            }
        });
        let writer_abort = writer_jh.abort_handle();
        let writer_abort_rd = writer_abort.clone();

        let pending_rd = Arc::clone(&pending);
        let closed_rd = Arc::clone(&closed);
        let max_conc_rd = Arc::clone(&max_concurrent);
        let last_rx_rd = Arc::clone(&last_rx_wall_ms);
        let write_tx_rd = write_tx.clone();

        let reader_jh = tokio::spawn(async move {
            const H2_ERR_REFUSED_STREAM: u32 = 0x7;
            let mut dyn_table: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
            let mut goaway_seen = false;
            let mut goaway_last_sid: Option<u32> = None;
            let mut completed_any_stream = false;
            let fail_err = loop {
                let read_res = tokio::time::timeout(DNS_TLS_IDLE_TTL, read_h2_frame(&mut rd)).await;
                let (ftype, flags, stream_id, payload) = match read_res {
                    Ok(Ok(f)) => {
                        last_rx_rd.store(TelemetryHub::now_ms(), Ordering::Release);
                        f
                    }
                    Ok(Err(e)) => break e,
                    // 45s with zero HTTP/2 frames (even if streams are pending) proves the connection is dead/blackholed.
                    Err(_) => break ProxyError::Timeout,
                };

                match ftype {
                    H2_FRAME_SETTINGS => {
                        if (flags & H2_FLAG_ACK) == 0 {
                            for &[b0, b1, b2, b3, b4, b5] in payload.as_chunks::<6>().0 {
                                let id = u16::from_be_bytes([b0, b1]);
                                let val = u32::from_be_bytes([b2, b3, b4, b5]);
                                if id == 0x0003 {
                                    if val == 0 {
                                        closed_rd.store(true, Ordering::Release);
                                    } else {
                                        max_conc_rd.store(val.min(256), Ordering::Relaxed);
                                    }
                                }
                            }
                            let mut ack = BytesMut::with_capacity(9);
                            put_h2_frame_header(&mut ack, 0, H2_FRAME_SETTINGS, H2_FLAG_ACK, 0);
                            let _ = write_tx_rd.send(ack);
                        }
                    }
                    H2_FRAME_PING => {
                        if (flags & H2_FLAG_ACK) == 0 && payload.len() == 8 {
                            let mut ack = BytesMut::with_capacity(17);
                            put_h2_frame_header(&mut ack, 8, H2_FRAME_PING, H2_FLAG_ACK, 0);
                            ack.put_slice(&payload);
                            let _ = write_tx_rd.send(ack);
                        }
                    }
                    H2_FRAME_WINDOW_UPDATE => {}
                    H2_FRAME_RST_STREAM => {
                        let code = if payload.len() >= 4 {
                            u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]])
                        } else {
                            0
                        };
                        if let Some((sid, acc)) = pending_rd.remove(&stream_id) {
                            let can_retry = !acc.seen_final_status
                                && (sid > 1
                                    || code == H2_ERR_REFUSED_STREAM
                                    || completed_any_stream);
                            let _ = acc.tx.send(if can_retry {
                                H2DohOutcome::RetryOnFreshConn
                            } else {
                                H2DohOutcome::Fatal(ProxyError::Dns(format!(
                                    "DoH HTTP/2 stream {sid} reset by peer (error_code={code})"
                                )))
                            });
                        }
                        if goaway_seen && pending_rd.is_empty() {
                            break ProxyError::Dns("DoH HTTP/2 session closed after GOAWAY".into());
                        }
                    }
                    H2_FRAME_GOAWAY => {
                        closed_rd.store(true, Ordering::Release);
                        goaway_seen = true;
                        let last_sid = if payload.len() >= 8 {
                            u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]])
                                & 0x7fff_ffff
                        } else {
                            0
                        };
                        goaway_last_sid = Some(last_sid);
                        let keys: Vec<u32> = pending_rd
                            .iter()
                            .filter_map(|e| (*e.key() > last_sid).then_some(*e.key()))
                            .collect();
                        for sid in keys {
                            if let Some((_, acc)) = pending_rd.remove(&sid) {
                                // RFC 9113 §6.8: any stream with stream_id > last_stream_id (even sid == 1 when last_sid == 0)
                                // was NOT processed by the server and is safe to retry on a fresh connection.
                                let _ = acc.tx.send(if !acc.seen_final_status {
                                    H2DohOutcome::RetryOnFreshConn
                                } else {
                                    H2DohOutcome::Fatal(ProxyError::Dns(format!(
                                        "DoH HTTP/2 GOAWAY (last_stream_id={last_sid}) before stream {sid}"
                                    )))
                                });
                            }
                        }
                        if pending_rd.is_empty() {
                            break ProxyError::Dns("DoH HTTP/2 session closed by GOAWAY".into());
                        }
                    }
                    H2_FRAME_HEADERS if stream_id > 0 => {
                        let frag_res = strip_h2_padding(&payload, flags).and_then(|mut frag| {
                            if (flags & H2_FLAG_PRIORITY) != 0 {
                                if frag.len() < 5 {
                                    return Err(ProxyError::Dns(
                                        "truncated HTTP/2 PRIORITY in HEADERS frame".into(),
                                    ));
                                }
                                frag = &frag[5..];
                            }
                            Ok(frag.to_vec())
                        });
                        let mut full_hblock = match frag_res {
                            Ok(v) => v,
                            Err(e) => break e,
                        };
                        let stream_ended = (flags & H2_FLAG_END_STREAM) != 0;
                        let mut cur_flags = flags;
                        let mut cont_err = None;
                        while (cur_flags & H2_FLAG_END_HEADERS) == 0 {
                            match tokio::time::timeout(DNS_IO_TIMEOUT, read_h2_frame(&mut rd)).await
                            {
                                Ok(Ok((cont_type, cont_flags, cont_sid, cont_payload))) => {
                                    last_rx_rd.store(TelemetryHub::now_ms(), Ordering::Release);
                                    if cont_type != H2_FRAME_CONTINUATION || cont_sid != stream_id {
                                        cont_err = Some(ProxyError::Dns(
                                            "expected HTTP/2 CONTINUATION frame".into(),
                                        ));
                                        break;
                                    }
                                    if full_hblock.len() + cont_payload.len() > 65_536 {
                                        cont_err = Some(ProxyError::Dns(
                                            "DoH HTTP/2 header block exceeded 64 KiB".into(),
                                        ));
                                        break;
                                    }
                                    full_hblock.extend_from_slice(&cont_payload);
                                    cur_flags = cont_flags;
                                }
                                Ok(Err(e)) => {
                                    cont_err = Some(e);
                                    break;
                                }
                                Err(_) => {
                                    cont_err = Some(ProxyError::Timeout);
                                    break;
                                }
                            }
                        }
                        if let Some(e) = cont_err {
                            break e;
                        }

                        let decoded_status =
                            match hpack_decode_block_status(&full_hblock, &mut dyn_table) {
                                Ok(s) => s,
                                Err(e) => break e,
                            };

                        let mut finish: Option<H2DohOutcome> = None;
                        if let Some(mut entry) = pending_rd.get_mut(&stream_id) {
                            if !entry.seen_final_status {
                                match decoded_status {
                                    Some(s) if (100..200).contains(&s) => {}
                                    Some(200) => {
                                        entry.seen_final_status = true;
                                    }
                                    Some(code) => {
                                        finish = Some(H2DohOutcome::Fatal(ProxyError::Dns(
                                            format!("DoH server returned HTTP status {code}"),
                                        )));
                                    }
                                    None => {
                                        finish = Some(H2DohOutcome::Fatal(ProxyError::Dns(
                                            "DoH HTTP/2 response missing :status header".into(),
                                        )));
                                    }
                                }
                            }
                            if finish.is_none() && stream_ended {
                                if entry.seen_final_status {
                                    finish =
                                        Some(H2DohOutcome::Body(std::mem::take(&mut entry.body)));
                                } else {
                                    finish = Some(H2DohOutcome::Fatal(ProxyError::Dns(
                                        "DoH HTTP/2 stream ended without HTTP 200 headers".into(),
                                    )));
                                }
                            }
                        }
                        if let Some(outcome) = finish
                            && let Some((_, acc)) = pending_rd.remove(&stream_id)
                        {
                            if matches!(outcome, H2DohOutcome::Body(_)) {
                                completed_any_stream = true;
                            }
                            let _ = acc.tx.send(outcome);
                        }
                        if goaway_seen && pending_rd.is_empty() {
                            break ProxyError::Dns("DoH HTTP/2 session closed after GOAWAY".into());
                        }
                    }
                    H2_FRAME_DATA if stream_id > 0 => {
                        let stream_ended = (flags & H2_FLAG_END_STREAM) != 0;
                        if !payload.is_empty() {
                            let inc = payload.len() as u32;
                            let mut wu =
                                BytesMut::with_capacity(if stream_ended { 13 } else { 26 });
                            put_h2_frame_header(&mut wu, 4, H2_FRAME_WINDOW_UPDATE, 0, 0);
                            wu.put_u32(inc);
                            if !stream_ended {
                                put_h2_frame_header(
                                    &mut wu,
                                    4,
                                    H2_FRAME_WINDOW_UPDATE,
                                    0,
                                    stream_id,
                                );
                                wu.put_u32(inc);
                            }
                            let _ = write_tx_rd.send(wu);
                        }

                        let data_slice = match strip_h2_padding(&payload, flags) {
                            Ok(s) => s,
                            Err(e) => break e,
                        };

                        let mut finish: Option<H2DohOutcome> = None;
                        if let Some(mut entry) = pending_rd.get_mut(&stream_id) {
                            if entry.body.len() + data_slice.len() > 65_536 {
                                finish = Some(H2DohOutcome::Fatal(ProxyError::Dns(
                                    "DoH HTTP/2 response body exceeded 64 KiB".into(),
                                )));
                            } else {
                                entry.body.extend_from_slice(data_slice);
                                if stream_ended {
                                    if entry.seen_final_status {
                                        finish = Some(H2DohOutcome::Body(std::mem::take(
                                            &mut entry.body,
                                        )));
                                    } else {
                                        finish = Some(H2DohOutcome::Fatal(ProxyError::Dns(
                                            "DoH HTTP/2 stream ended without HTTP 200".into(),
                                        )));
                                    }
                                }
                            }
                        }
                        if let Some(outcome) = finish
                            && let Some((_, acc)) = pending_rd.remove(&stream_id)
                        {
                            if matches!(outcome, H2DohOutcome::Body(_)) {
                                completed_any_stream = true;
                            }
                            let _ = acc.tx.send(outcome);
                        }
                        if goaway_seen && pending_rd.is_empty() {
                            break ProxyError::Dns("DoH HTTP/2 session closed after GOAWAY".into());
                        }
                    }
                    _ => {}
                }
            };

            closed_rd.store(true, Ordering::Release);
            writer_abort_rd.abort();
            let keys: Vec<u32> = pending_rd.iter().map(|e| *e.key()).collect();
            for sid in keys {
                if let Some((_, acc)) = pending_rd.remove(&sid) {
                    let can_retry = !acc.seen_final_status
                        && (sid > 1
                            || completed_any_stream
                            || goaway_last_sid.is_some_and(|last| sid > last));
                    let _ = acc.tx.send(if can_retry {
                        H2DohOutcome::RetryOnFreshConn
                    } else {
                        let msg = fail_err.to_string();
                        H2DohOutcome::Fatal(ProxyError::Dns(format!(
                            "DoH HTTP/2 connection closed before stream {sid} completed: {msg}"
                        )))
                    });
                }
            }
        });
        let reader_abort = reader_jh.abort_handle();

        let client = Arc::new(Self {
            stream_open_lock: Mutex::new(()),
            write_tx,
            pending,
            next_stream_id: AtomicU32::new(1),
            max_concurrent,
            last_rx_wall_ms,
            closed,
            reader_abort,
            writer_abort,
        });
        {
            let mut live = H2_LIVE_CLIENTS.lock();
            if live.len() > 64 {
                live.retain(|w| w.strong_count() > 0);
            }
            live.push(Arc::downgrade(&client));
        }
        client
    }

    fn is_reusable_at(&self, now_wall_ms: u64) -> bool {
        if self.closed.load(Ordering::Acquire) {
            return false;
        }
        if now_wall_ms.saturating_sub(self.last_rx_wall_ms.load(Ordering::Acquire))
            >= DNS_TLS_IDLE_TTL.as_millis() as u64
        {
            self.abort();
            return false;
        }
        self.next_stream_id.load(Ordering::Relaxed) <= H2_MAX_STREAMS_PER_CONN * 2
            && (self.pending.len() as u32) < self.max_concurrent.load(Ordering::Relaxed)
    }

    fn is_reusable(&self) -> bool {
        self.is_reusable_at(TelemetryHub::now_ms())
    }

    async fn exchange(
        &self,
        host_header: &str,
        path_and_query: &str,
        doh_wire: &[u8],
    ) -> H2DohOutcome {
        let mut req_buf = BytesMut::with_capacity(224 + doh_wire.len());
        let (sid, rx, mut guard) = {
            // Hold non-blocking lock across stream ID assignment + pending registration + write_tx enqueue
            // so HTTP/2 HEADERS frames are strictly emitted in ascending stream ID order (RFC 9113 §5.1.1).
            let _open_guard = self.stream_open_lock.lock();
            if self.closed.load(Ordering::Acquire) {
                return H2DohOutcome::RetryOnFreshConn;
            }
            let sid = self.next_stream_id.fetch_add(2, Ordering::Relaxed);
            if sid > H2_MAX_STREAMS_PER_CONN * 2 + 1 {
                self.closed.store(true, Ordering::Release);
                return if sid > 1 {
                    H2DohOutcome::RetryOnFreshConn
                } else {
                    H2DohOutcome::Fatal(ProxyError::Dns(
                        "DoH HTTP/2 connection stream budget reached".into(),
                    ))
                };
            }

            let (tx, rx) = oneshot::channel();
            self.pending.insert(
                sid,
                H2StreamAcc {
                    seen_final_status: false,
                    body: Vec::with_capacity(256),
                    tx,
                },
            );
            let guard = PendingStreamGuard {
                map: &self.pending,
                sid,
                disarmed: false,
            };

            if self.closed.load(Ordering::Acquire) {
                return H2DohOutcome::RetryOnFreshConn;
            }

            encode_doh_h2_request_frames(&mut req_buf, sid, host_header, path_and_query, doh_wire);
            if self.write_tx.send(req_buf).is_err() {
                self.closed.store(true, Ordering::Release);
                return if sid > 1 {
                    H2DohOutcome::RetryOnFreshConn
                } else {
                    H2DohOutcome::Fatal(ProxyError::Dns("DoH HTTP/2 writer channel closed".into()))
                };
            }
            (sid, rx, guard)
        };

        match rx.await {
            Ok(outcome) => {
                guard.disarmed = true;
                outcome
            }
            Err(_) => {
                guard.disarmed = true;
                if sid > 1 {
                    H2DohOutcome::RetryOnFreshConn
                } else {
                    H2DohOutcome::Fatal(ProxyError::Dns(
                        "DoH HTTP/2 response channel dropped".into(),
                    ))
                }
            }
        }
    }

    fn mark_closed_on_timeout(&self) {
        self.closed.store(true, Ordering::Release);
        self.reader_abort.abort();
        self.writer_abort.abort();
        let keys: Vec<u32> = self.pending.iter().map(|e| *e.key()).collect();
        for sid in keys {
            if let Some((_, acc)) = self.pending.remove(&sid) {
                let _ = acc.tx.send(if sid > 1 && !acc.seen_final_status {
                    H2DohOutcome::RetryOnFreshConn
                } else {
                    H2DohOutcome::Fatal(ProxyError::Timeout)
                });
            }
        }
    }

    fn abort(&self) {
        self.closed.store(true, Ordering::Release);
        self.reader_abort.abort();
        self.writer_abort.abort();
        let keys: Vec<u32> = self.pending.iter().map(|e| *e.key()).collect();
        for sid in keys {
            if let Some((_, acc)) = self.pending.remove(&sid) {
                let _ = acc.tx.send(if !acc.seen_final_status {
                    H2DohOutcome::RetryOnFreshConn
                } else {
                    H2DohOutcome::Fatal(ProxyError::Dns("DoH HTTP/2 pool flushed".into()))
                });
            }
        }
    }
}

impl Drop for H2DohClient {
    fn drop(&mut self) {
        self.reader_abort.abort();
        self.writer_abort.abort();
    }
}

/// Exchange a single RFC 8484 DNS-over-HTTPS `POST` request over an RFC 9113 HTTP/2 stream (`ALPN = h2`).
pub(crate) async fn exchange_doh_h2_over_stream<S>(
    tls: &mut S,
    host_header: &str,
    path_and_query: &str,
    doh_wire: &[u8],
    orig_id: [u8; 2],
) -> Result<Vec<u8>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut hblock = BytesMut::with_capacity(192);
    // `:method: POST` (static index 3 -> 0x83), `:scheme: https` (static index 7 -> 0x87)
    hblock.put_u8(0x83);
    hblock.put_u8(0x87);
    // `:authority` (static index 1), `:path` (static index 4)
    put_hpack_literal_indexed_name(&mut hblock, 1, host_header.as_bytes());
    put_hpack_literal_indexed_name(&mut hblock, 4, path_and_query.as_bytes());
    // `user-agent` (static index 58), `accept` (static index 19), `content-type` (static index 31), `content-length` (static index 28)
    let ua = format!("rust-clash/{}", env!("CARGO_PKG_VERSION"));
    put_hpack_literal_indexed_name(&mut hblock, 58, ua.as_bytes());
    put_hpack_literal_indexed_name(&mut hblock, 19, b"application/dns-message");
    put_hpack_literal_indexed_name(&mut hblock, 31, b"application/dns-message");
    let cl_str = doh_wire.len().to_string();
    put_hpack_literal_indexed_name(&mut hblock, 28, cl_str.as_bytes());

    let mut out = BytesMut::with_capacity(64 + hblock.len() + doh_wire.len());
    out.put_slice(H2_CLIENT_PREFACE);
    // Client SETTINGS: HEADER_TABLE_SIZE (0x1) = 0, ENABLE_PUSH (0x2) = 0
    put_h2_frame_header(&mut out, 12, H2_FRAME_SETTINGS, 0, 0);
    out.put_u16(0x0001);
    out.put_u32(0);
    out.put_u16(0x0002);
    out.put_u32(0);
    // Stream 1 HEADERS (END_HEADERS)
    put_h2_frame_header(
        &mut out,
        hblock.len(),
        H2_FRAME_HEADERS,
        H2_FLAG_END_HEADERS,
        1,
    );
    out.put_slice(&hblock);
    // Stream 1 DATA (END_STREAM)
    put_h2_frame_header(
        &mut out,
        doh_wire.len(),
        H2_FRAME_DATA,
        H2_FLAG_END_STREAM,
        1,
    );
    out.put_slice(doh_wire);

    tls.write_all(&out).await?;
    tls.flush().await?;

    let mut seen_final_status = false;
    let mut body = Vec::with_capacity(512);

    for _ in 0..128 {
        let (ftype, flags, stream_id, payload) = read_h2_frame(tls).await?;
        match ftype {
            H2_FRAME_SETTINGS => {
                if (flags & H2_FLAG_ACK) == 0 {
                    let mut ack = BytesMut::with_capacity(9);
                    put_h2_frame_header(&mut ack, 0, H2_FRAME_SETTINGS, H2_FLAG_ACK, 0);
                    let _ = tls.write_all(&ack).await;
                    let _ = tls.flush().await;
                }
            }
            H2_FRAME_PING => {
                if (flags & H2_FLAG_ACK) == 0 && payload.len() == 8 {
                    let mut ack = BytesMut::with_capacity(17);
                    put_h2_frame_header(&mut ack, 8, H2_FRAME_PING, H2_FLAG_ACK, 0);
                    ack.put_slice(&payload);
                    let _ = tls.write_all(&ack).await;
                    let _ = tls.flush().await;
                }
            }
            H2_FRAME_WINDOW_UPDATE => {}
            H2_FRAME_RST_STREAM if stream_id == 1 => {
                let code = if payload.len() >= 4 {
                    u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]])
                } else {
                    0
                };
                return Err(ProxyError::Dns(format!(
                    "DoH HTTP/2 stream reset by peer (error_code={code})"
                )));
            }
            H2_FRAME_GOAWAY => {
                if payload.len() >= 8 {
                    let last_sid =
                        u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]])
                            & 0x7fff_ffff;
                    if last_sid < 1 {
                        return Err(ProxyError::Dns(
                            "DoH HTTP/2 server sent GOAWAY before processing stream 1".into(),
                        ));
                    }
                }
            }
            H2_FRAME_HEADERS if stream_id == 1 => {
                let mut frag = strip_h2_padding(&payload, flags)?;
                if (flags & H2_FLAG_PRIORITY) != 0 {
                    if frag.len() < 5 {
                        return Err(ProxyError::Dns(
                            "truncated HTTP/2 PRIORITY in HEADERS frame".into(),
                        ));
                    }
                    frag = &frag[5..];
                }
                let stream_ended = (flags & H2_FLAG_END_STREAM) != 0;
                let mut full_hblock = frag.to_vec();
                let mut cur_flags = flags;
                while (cur_flags & H2_FLAG_END_HEADERS) == 0 {
                    let (cont_type, cont_flags, cont_sid, cont_payload) =
                        read_h2_frame(tls).await?;
                    if cont_type != H2_FRAME_CONTINUATION || cont_sid != 1 {
                        return Err(ProxyError::Dns(
                            "expected HTTP/2 CONTINUATION frame on stream 1".into(),
                        ));
                    }
                    if full_hblock.len() + cont_payload.len() > 65_536 {
                        return Err(ProxyError::Dns(
                            "DoH HTTP/2 header block exceeded 64 KiB".into(),
                        ));
                    }
                    full_hblock.extend_from_slice(&cont_payload);
                    cur_flags = cont_flags;
                }
                if !seen_final_status {
                    let status = hpack_extract_status(&full_hblock)?;
                    if (100..200).contains(&status) {
                        // Informational 1xx headers; wait for final response HEADERS
                    } else if status == 200 {
                        seen_final_status = true;
                    } else {
                        return Err(ProxyError::Dns(format!(
                            "DoH server returned HTTP status {status}"
                        )));
                    }
                }
                if stream_ended {
                    break;
                }
            }
            H2_FRAME_DATA if stream_id == 1 => {
                let data_slice = strip_h2_padding(&payload, flags)?;
                if body.len() + data_slice.len() > 65_536 {
                    return Err(ProxyError::Dns(
                        "DoH HTTP/2 response body exceeded 64 KiB".into(),
                    ));
                }
                body.extend_from_slice(data_slice);
                if (flags & H2_FLAG_END_STREAM) != 0 {
                    break;
                }
                if !payload.is_empty() {
                    let inc = payload.len() as u32;
                    let mut wu = BytesMut::with_capacity(26);
                    put_h2_frame_header(&mut wu, 4, H2_FRAME_WINDOW_UPDATE, 0, 0);
                    wu.put_u32(inc);
                    put_h2_frame_header(&mut wu, 4, H2_FRAME_WINDOW_UPDATE, 0, 1);
                    wu.put_u32(inc);
                    let _ = tls.write_all(&wu).await;
                    let _ = tls.flush().await;
                }
            }
            _ => {}
        }
    }

    if !seen_final_status {
        return Err(ProxyError::Dns(
            "DoH HTTP/2 connection ended without HTTP 200 response headers".into(),
        ));
    }
    let mut goaway = BytesMut::with_capacity(17);
    put_h2_frame_header(&mut goaway, 8, H2_FRAME_GOAWAY, 0, 0);
    goaway.put_u32(0);
    goaway.put_u32(0);
    let _ = tls.write_all(&goaway).await;
    let _ = tls.flush().await;

    let expected_query = crate::dns::wire::DnsQueryPacket::parse(doh_wire).ok();
    finalize_doh_body(body, expected_query.as_ref(), orig_id)
}

fn decode_hpack_int(input: &[u8], prefix_bits: u8) -> Result<(usize, usize)> {
    let Some(&first) = input.first() else {
        return Err(ProxyError::Dns("unexpected EOF in HPACK integer".into()));
    };
    let mask = ((1u16 << prefix_bits) - 1) as u8;
    let mut val = (first & mask) as usize;
    if (first & mask) < mask {
        return Ok((val, 1));
    }
    let mut shift = 0u32;
    let mut idx = 1usize;
    loop {
        let Some(&b) = input.get(idx) else {
            return Err(ProxyError::Dns("truncated multi-byte HPACK integer".into()));
        };
        idx += 1;
        if shift > 28 {
            return Err(ProxyError::Dns("HPACK integer overflow".into()));
        }
        val = val
            .checked_add(((b & 0x7f) as usize) << shift)
            .ok_or_else(|| ProxyError::Dns("HPACK integer overflow".into()))?;
        if (b & 0x80) == 0 {
            return Ok((val, idx));
        }
        shift += 7;
    }
}

fn decode_hpack_str(input: &[u8]) -> Result<(Vec<u8>, usize)> {
    let Some(&first) = input.first() else {
        return Err(ProxyError::Dns("unexpected EOF in HPACK string".into()));
    };
    let is_huffman = (first & 0x80) != 0;
    let (slen, hdr_used) = decode_hpack_int(input, 7)?;
    if input.len() < hdr_used + slen {
        return Err(ProxyError::Dns("truncated HPACK string literal".into()));
    }
    let raw = &input[hdr_used..hdr_used + slen];
    let decoded = if is_huffman {
        hpack_huffman_decode(raw)?
    } else {
        raw.to_vec()
    };
    Ok((decoded, hdr_used + slen))
}

fn hpack_decode_block_status(
    mut block: &[u8],
    dyn_table: &mut Vec<(Vec<u8>, Vec<u8>)>,
) -> Result<Option<u16>> {
    let mut status: Option<u16> = None;

    while !block.is_empty() {
        let b0 = block[0];
        if (b0 & 0x80) != 0 {
            // Indexed Header Field (7-bit prefix)
            let (idx, used) = decode_hpack_int(block, 7)?;
            block = &block[used..];
            match idx {
                8 => status = Some(200),
                9 => status = Some(204),
                10 => status = Some(206),
                11 => status = Some(304),
                12 => status = Some(400),
                13 => status = Some(404),
                14 => status = Some(500),
                n if n >= 62 => {
                    let dyn_idx = n - 62;
                    if let Some((k, v)) = dyn_table.get(dyn_idx)
                        && k == b":status"
                        && let Ok(s) = std::str::from_utf8(v)
                        && let Ok(code) = s.trim().parse::<u16>()
                    {
                        status = Some(code);
                    }
                }
                _ => {}
            }
        } else if (b0 & 0xe0) == 0x20 {
            // Dynamic Table Size Update (5-bit prefix)
            let (new_max, used) = decode_hpack_int(block, 5)?;
            if new_max == 0 {
                dyn_table.clear();
            }
            block = &block[used..];
        } else {
            // Literal Header Field:
            // - Incremental Indexing: 01xxxxxx (6-bit prefix)
            // - Without Indexing: 0000xxxx (4-bit prefix)
            // - Never Indexed: 0001xxxx (4-bit prefix)
            let (indexed_insert, prefix_bits) = if (b0 & 0xc0) == 0x40 {
                (true, 6)
            } else {
                (false, 4)
            };
            let (name_idx, used_idx) = decode_hpack_int(block, prefix_bits)?;
            block = &block[used_idx..];

            let name_bytes = if name_idx == 0 {
                let (n, used_n) = decode_hpack_str(block)?;
                block = &block[used_n..];
                n
            } else if (8..=14).contains(&name_idx) {
                b":status".to_vec()
            } else if name_idx >= 62 {
                dyn_table
                    .get(name_idx - 62)
                    .map(|(k, _)| k.clone())
                    .unwrap_or_default()
            } else {
                Vec::new()
            };

            let (val_bytes, used_v) = decode_hpack_str(block)?;
            block = &block[used_v..];

            if name_bytes == b":status"
                && let Ok(s) = std::str::from_utf8(&val_bytes)
                && let Ok(code) = s.trim().parse::<u16>()
            {
                status = Some(code);
            }
            if indexed_insert {
                if dyn_table.len() >= 64 {
                    dyn_table.pop();
                }
                dyn_table.insert(0, (name_bytes, val_bytes));
            }
        }
    }

    Ok(status)
}

fn hpack_extract_status(block: &[u8]) -> Result<u16> {
    let mut dyn_table = Vec::new();
    hpack_decode_block_status(block, &mut dyn_table)?
        .ok_or_else(|| ProxyError::Dns("DoH HTTP/2 response missing :status header".into()))
}

#[derive(Clone, Copy)]
struct HuffNode {
    left: i16,
    right: i16,
    sym: i16,
}

static HPACK_HUFFMAN_TRIE: LazyLock<Vec<HuffNode>> = LazyLock::new(|| {
    let mut nodes = Vec::with_capacity(514);
    nodes.push(HuffNode {
        left: -1,
        right: -1,
        sym: -1,
    });
    for sym in 0..256usize {
        let code = HUFFMAN_CODES[sym];
        let len = HUFFMAN_CODE_LEN[sym];
        let mut cur = 0usize;
        for shift in (0..len).rev() {
            let bit = (code >> shift) & 1;
            let next = if bit == 0 {
                nodes[cur].left
            } else {
                nodes[cur].right
            };
            let child = if next >= 0 {
                next as usize
            } else {
                let idx = nodes.len();
                nodes.push(HuffNode {
                    left: -1,
                    right: -1,
                    sym: -1,
                });
                if bit == 0 {
                    nodes[cur].left = idx as i16;
                } else {
                    nodes[cur].right = idx as i16;
                }
                idx
            };
            cur = child;
        }
        nodes[cur].sym = sym as i16;
    }
    nodes
});

fn hpack_huffman_decode(src: &[u8]) -> Result<Vec<u8>> {
    let trie = &*HPACK_HUFFMAN_TRIE;
    let mut out = Vec::with_capacity(src.len() * 2);
    let mut cur = 0usize;
    let mut bits_in_branch = 0u8;
    let mut branch_all_ones = true;

    for &byte in src {
        for shift in (0..8).rev() {
            let bit = (byte >> shift) & 1;
            if bit == 0 {
                branch_all_ones = false;
            }
            let next = if bit == 0 {
                trie[cur].left
            } else {
                trie[cur].right
            };
            if next < 0 {
                return Err(ProxyError::Dns("invalid HPACK Huffman sequence".into()));
            }
            cur = next as usize;
            bits_in_branch += 1;
            if trie[cur].sym >= 0 {
                out.push(trie[cur].sym as u8);
                cur = 0;
                bits_in_branch = 0;
                branch_all_ones = true;
            }
        }
    }

    if bits_in_branch > 7 || !branch_all_ones {
        return Err(ProxyError::Dns("invalid HPACK Huffman EOS padding".into()));
    }
    Ok(out)
}

// RFC 7541 Appendix B Static Huffman Code Table (symbols 0..=255)
const HUFFMAN_CODES: [u32; 256] = [
    0x1ff8, 0x7fffd8, 0xfffffe2, 0xfffffe3, 0xfffffe4, 0xfffffe5, 0xfffffe6, 0xfffffe7, 0xfffffe8,
    0xffffea, 0x3ffffffc, 0xfffffe9, 0xfffffea, 0x3ffffffd, 0xfffffeb, 0xfffffec, 0xfffffed,
    0xfffffee, 0xfffffef, 0xffffff0, 0xffffff1, 0xffffff2, 0x3ffffffe, 0xffffff3, 0xffffff4,
    0xffffff5, 0xffffff6, 0xffffff7, 0xffffff8, 0xffffff9, 0xffffffa, 0xffffffb, 0x14, 0x3f8,
    0x3f9, 0xffa, 0x1ff9, 0x15, 0xf8, 0x7fa, 0x3fa, 0x3fb, 0xf9, 0x7fb, 0xfa, 0x16, 0x17, 0x18,
    0x0, 0x1, 0x2, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x5c, 0xfb, 0x7ffc, 0x20, 0xffb,
    0x3fc, 0x1ffa, 0x21, 0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
    0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0xfc, 0x73, 0xfd, 0x1ffb, 0x7fff0,
    0x1ffc, 0x3ffc, 0x22, 0x7ffd, 0x3, 0x23, 0x4, 0x24, 0x5, 0x25, 0x26, 0x27, 0x6, 0x74, 0x75,
    0x28, 0x29, 0x2a, 0x7, 0x2b, 0x76, 0x2c, 0x8, 0x9, 0x2d, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7ffe,
    0x7fc, 0x3ffd, 0x1ffd, 0xffffffc, 0xfffe6, 0x3fffd2, 0xfffe7, 0xfffe8, 0x3fffd3, 0x3fffd4,
    0x3fffd5, 0x7fffd9, 0x3fffd6, 0x7fffda, 0x7fffdb, 0x7fffdc, 0x7fffdd, 0x7fffde, 0xffffeb,
    0x7fffdf, 0xffffec, 0xffffed, 0x3fffd7, 0x7fffe0, 0xffffee, 0x7fffe1, 0x7fffe2, 0x7fffe3,
    0x7fffe4, 0x1fffdc, 0x3fffd8, 0x7fffe5, 0x3fffd9, 0x7fffe6, 0x7fffe7, 0xffffef, 0x3fffda,
    0x1fffdd, 0xfffe9, 0x3fffdb, 0x3fffdc, 0x7fffe8, 0x7fffe9, 0x1fffde, 0x7fffea, 0x3fffdd,
    0x3fffde, 0xfffff0, 0x1fffdf, 0x3fffdf, 0x7fffeb, 0x7fffec, 0x1fffe0, 0x1fffe1, 0x3fffe0,
    0x1fffe2, 0x7fffed, 0x3fffe1, 0x7fffee, 0x7fffef, 0xfffea, 0x3fffe2, 0x3fffe3, 0x3fffe4,
    0x7ffff0, 0x3fffe5, 0x3fffe6, 0x7ffff1, 0x3ffffe0, 0x3ffffe1, 0xfffeb, 0x7fff1, 0x3fffe7,
    0x7ffff2, 0x3fffe8, 0x1ffffec, 0x3ffffe2, 0x3ffffe3, 0x3ffffe4, 0x7ffffde, 0x7ffffdf,
    0x3ffffe5, 0xfffff1, 0x1ffffed, 0x7fff2, 0x1fffe3, 0x3ffffe6, 0x7ffffe0, 0x7ffffe1, 0x3ffffe7,
    0x7ffffe2, 0xfffff2, 0x1fffe4, 0x1fffe5, 0x3ffffe8, 0x3ffffe9, 0xffffffd, 0x7ffffe3, 0x7ffffe4,
    0x7ffffe5, 0xfffec, 0xfffff3, 0xfffed, 0x1fffe6, 0x3fffe9, 0x1fffe7, 0x1fffe8, 0x7ffff3,
    0x3fffea, 0x3fffeb, 0x1ffffee, 0x1ffffef, 0xfffff4, 0xfffff5, 0x3ffffea, 0x7ffff4, 0x3ffffeb,
    0x7ffffe6, 0x3ffffec, 0x3ffffed, 0x7ffffe7, 0x7ffffe8, 0x7ffffe9, 0x7ffffea, 0x7ffffeb,
    0xffffffe, 0x7ffffec, 0x7ffffed, 0x7ffffee, 0x7ffffef, 0x7fffff0, 0x3ffffee,
];

const HUFFMAN_CODE_LEN: [u8; 256] = [
    13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 30, 28,
    28, 28, 28, 28, 28, 28, 28, 28, 6, 10, 10, 12, 13, 6, 8, 11, 10, 10, 8, 11, 8, 6, 6, 6, 5, 5,
    5, 6, 6, 6, 6, 6, 6, 6, 7, 8, 15, 6, 12, 10, 13, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7, 8, 7, 8, 13, 19, 13, 14, 6, 15, 5, 6, 5, 6, 5, 6, 6, 6, 5, 7, 7, 6, 6,
    6, 5, 6, 7, 6, 5, 5, 6, 7, 7, 7, 7, 7, 15, 11, 14, 13, 28, 20, 22, 20, 20, 22, 22, 22, 23, 22,
    23, 23, 23, 23, 23, 24, 23, 24, 24, 22, 23, 24, 23, 23, 23, 23, 21, 22, 23, 22, 23, 23, 24, 22,
    21, 20, 22, 22, 23, 23, 21, 23, 22, 22, 24, 21, 22, 23, 23, 21, 21, 22, 21, 23, 22, 23, 23, 20,
    22, 22, 22, 23, 22, 22, 23, 26, 26, 20, 19, 22, 23, 22, 25, 26, 26, 26, 27, 27, 26, 24, 25, 19,
    21, 26, 27, 27, 26, 27, 24, 21, 21, 26, 26, 28, 27, 27, 27, 20, 24, 20, 21, 22, 21, 21, 23, 22,
    22, 25, 25, 24, 24, 26, 23, 26, 27, 26, 26, 27, 27, 27, 27, 27, 28, 27, 27, 27, 27, 27, 26,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc7541_huffman_and_status_decoding_vectors() {
        // RFC 7541 C.4.1 vector: `f1e3 c2e5 f23a 6ba0 ab90 f4ff` -> `www.example.com`
        let rfc_vec = [
            0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
        ];
        assert_eq!(hpack_huffman_decode(&rfc_vec).unwrap(), b"www.example.com");

        // Indexed `:status: 200` (`0x88`) + `content-type: application/dns-message`
        assert_eq!(hpack_extract_status(&[0x88]).unwrap(), 200);

        // Literal `:status` (name idx 8 -> `0x08`) + Huffman `"202"` (`'2'=0x02(5b), '0'=0x00(5b), '2'=0x02(5b)` + 1 pad bit `1` -> `00010_00000_00010_1` = `0x10, 0x05`)
        let lit_huff_202 = [0x08, 0x82, 0x10, 0x05];
        assert_eq!(hpack_extract_status(&lit_huff_202).unwrap(), 202);
    }

    #[test]
    fn bootstrap_dns_accepts_literal_ip_doh_and_rejects_domain() {
        assert!(BootstrapDnsServer::parse("https://198.51.100.10:8080/dns-query").is_ok());
        assert!(BootstrapDnsServer::parse("tls://203.0.113.5:853").is_ok());
        assert!(BootstrapDnsServer::parse("https://doh.example.com/dns-query").is_err());
    }

    #[test]
    fn doh_chunked_decoder_rejects_integer_overflow_and_oversized_chunks() {
        // Wraparound vectors that previously bypassed `input.len() < chunk_len + 2` in 64-bit release
        assert!(decode_chunked_if_complete(b"ffffffffffffffff\r\n\r\n").is_err());
        assert!(decode_chunked_if_complete(b"fffffffffffffffe\r\n").is_err());

        // Single chunk exceeding 65,535-byte DNS maximum
        let err = decode_chunked_if_complete(b"10000\r\n").unwrap_err();
        assert!(
            err.to_string()
                .contains("DoH chunk exceeds maximum DNS message size")
        );

        // Multi-chunk cumulative payload exceeding 65,535 bytes (32768 + 32768 = 65536)
        let mut two_chunks = Vec::new();
        two_chunks.extend_from_slice(b"8000\r\n");
        two_chunks.extend(std::iter::repeat_n(0x41u8, 0x8000));
        two_chunks.extend_from_slice(b"\r\n8000\r\n");
        let cum_err = decode_chunked_if_complete(&two_chunks).unwrap_err();
        assert!(
            cum_err
                .to_string()
                .contains("DoH chunk exceeds maximum DNS message size")
        );

        // Valid chunked DNS payload still decodes cleanly
        let decoded =
            decode_chunked_if_complete(b"4\r\n\x12\x34\x81\x80\r\n2\r\n\x00\x01\r\n0\r\n\r\n")
                .unwrap()
                .unwrap();
        assert_eq!(decoded, vec![0x12, 0x34, 0x81, 0x80, 0x00, 0x01]);
    }

    async fn mock_write_h2_doh_response<S: AsyncWrite + Unpin>(
        io: &mut S,
        stream_id: u32,
        req_payload: &[u8],
        ip: std::net::Ipv4Addr,
    ) {
        let qp = crate::dns::wire::DnsQueryPacket::parse(req_payload).unwrap();
        let dns_resp = qp.build_response(
            req_payload,
            0,
            60,
            &[crate::dns::wire::DnsAnswerData::A(ip)],
        );
        let mut out = BytesMut::with_capacity(32 + dns_resp.len());
        // Indexed `:status: 200` -> 0x88
        put_h2_frame_header(
            &mut out,
            1,
            H2_FRAME_HEADERS,
            H2_FLAG_END_HEADERS,
            stream_id,
        );
        out.put_u8(0x88);
        put_h2_frame_header(
            &mut out,
            dns_resp.len(),
            H2_FRAME_DATA,
            H2_FLAG_END_STREAM,
            stream_id,
        );
        out.put_slice(&dns_resp);
        io.write_all(&out).await.unwrap();
        io.flush().await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn h2_doh_concurrent_exchange_emits_strictly_monotonic_stream_ids() {
        const CONCURRENCY: usize = 32;
        let (client_io, mut server_io) = tokio::io::duplex(256 * 1024);
        let client = H2DohClient::spawn_io(client_io);

        let srv_jh = tokio::spawn(async move {
            let mut preface = [0u8; H2_CLIENT_PREFACE.len()];
            server_io.read_exact(&mut preface).await.unwrap();
            assert_eq!(&preface, H2_CLIENT_PREFACE);

            let mut srv_settings = BytesMut::with_capacity(9);
            put_h2_frame_header(&mut srv_settings, 0, H2_FRAME_SETTINGS, 0, 0);
            server_io.write_all(&srv_settings).await.unwrap();
            server_io.flush().await.unwrap();

            let mut seen_header_sids = Vec::with_capacity(CONCURRENCY);
            let mut answered = 0usize;
            while answered < CONCURRENCY {
                let (ftype, flags, sid, payload) = read_h2_frame(&mut server_io).await.unwrap();
                match ftype {
                    H2_FRAME_HEADERS if sid > 0 => {
                        if let Some(&prev) = seen_header_sids.last() {
                            assert!(
                                sid > prev,
                                "out-of-order HTTP/2 HEADERS stream_id: {sid} after {prev}"
                            );
                        }
                        seen_header_sids.push(sid);
                    }
                    H2_FRAME_DATA if sid > 0 && (flags & H2_FLAG_END_STREAM) != 0 => {
                        mock_write_h2_doh_response(
                            &mut server_io,
                            sid,
                            &payload,
                            std::net::Ipv4Addr::new(93, 184, 216, 34),
                        )
                        .await;
                        answered += 1;
                    }
                    _ => {}
                }
            }
            seen_header_sids
        });

        let barrier = Arc::new(tokio::sync::Barrier::new(CONCURRENCY));
        let mut handles = Vec::with_capacity(CONCURRENCY);
        for i in 0..CONCURRENCY {
            let c = Arc::clone(&client);
            let b = Arc::clone(&barrier);
            handles.push(tokio::spawn(async move {
                let q = crate::dns::wire::build_dns_query(
                    0,
                    &format!("h{i}.example.com"),
                    crate::dns::wire::QTYPE_A,
                );
                b.wait().await;
                match c.exchange("localhost", "/dns-query", &q).await {
                    H2DohOutcome::Body(body) => assert!(body.len() >= 12),
                    other => panic!(
                        "unexpected H2DohOutcome variant: {}",
                        matches!(other, H2DohOutcome::RetryOnFreshConn)
                    ),
                }
            }));
        }

        for h in handles {
            h.await.unwrap();
        }
        let seen_sids = srv_jh.await.unwrap();
        let expected: Vec<u32> = (0..CONCURRENCY as u32).map(|i| i * 2 + 1).collect();
        assert_eq!(seen_sids, expected);
    }

    #[tokio::test]
    async fn h2_doh_goaway_zero_and_reader_teardown_retry_classification() {
        let q =
            crate::dns::wire::build_dns_query(0, "retry.example.com", crate::dns::wire::QTYPE_A);

        // 1. GOAWAY(last_stream_id = 0) before Stream 1 response MUST classify Stream 1 as RetryOnFreshConn
        {
            let (client_io, mut server_io) = tokio::io::duplex(64 * 1024);
            let client = H2DohClient::spawn_io(client_io);
            let srv = tokio::spawn(async move {
                let mut preface = [0u8; H2_CLIENT_PREFACE.len()];
                server_io.read_exact(&mut preface).await.unwrap();
                loop {
                    let (ftype, flags, sid, _) = read_h2_frame(&mut server_io).await.unwrap();
                    if ftype == H2_FRAME_DATA && sid == 1 && (flags & H2_FLAG_END_STREAM) != 0 {
                        let mut goaway = BytesMut::with_capacity(17);
                        put_h2_frame_header(&mut goaway, 8, H2_FRAME_GOAWAY, 0, 0);
                        goaway.put_u32(0); // last_stream_id = 0 -> Stream 1 was NOT processed
                        goaway.put_u32(0); // NO_ERROR
                        server_io.write_all(&goaway).await.unwrap();
                        server_io.flush().await.unwrap();
                        break;
                    }
                }
            });
            assert!(matches!(
                client.exchange("localhost", "/dns-query", &q).await,
                H2DohOutcome::RetryOnFreshConn
            ));
            srv.await.unwrap();
        }

        // 2. Brand-new connection immediate EOF with zero completed streams on Stream 1 -> Fatal (no dead-server retry loop)
        {
            let (client_io, server_io) = tokio::io::duplex(64 * 1024);
            drop(server_io);
            let client = H2DohClient::spawn_io(client_io);
            assert!(matches!(
                client.exchange("localhost", "/dns-query", &q).await,
                H2DohOutcome::Fatal(_)
            ));
        }

        // 3. Reused connection (after Stream 1 succeeded) hitting abrupt EOF on Stream 3 -> RetryOnFreshConn
        {
            let (client_io, mut server_io) = tokio::io::duplex(64 * 1024);
            let client = H2DohClient::spawn_io(client_io);
            let srv = tokio::spawn(async move {
                let mut preface = [0u8; H2_CLIENT_PREFACE.len()];
                server_io.read_exact(&mut preface).await.unwrap();
                loop {
                    let (ftype, flags, sid, payload) = read_h2_frame(&mut server_io).await.unwrap();
                    if ftype == H2_FRAME_DATA && sid == 1 && (flags & H2_FLAG_END_STREAM) != 0 {
                        mock_write_h2_doh_response(
                            &mut server_io,
                            1,
                            &payload,
                            std::net::Ipv4Addr::new(1, 1, 1, 1),
                        )
                        .await;
                    } else if ftype == H2_FRAME_HEADERS && sid == 3 {
                        // Simulate abrupt TCP reset/EOF before Stream 3 gets any response
                        break;
                    }
                }
            });
            assert!(matches!(
                client.exchange("localhost", "/dns-query", &q).await,
                H2DohOutcome::Body(_)
            ));
            assert!(matches!(
                client.exchange("localhost", "/dns-query", &q).await,
                H2DohOutcome::RetryOnFreshConn
            ));
            srv.await.unwrap();
        }
    }

    #[tokio::test]
    async fn doh_timeout_immediately_evicts_blackholed_h2_client_from_pool() {
        use std::sync::atomic::AtomicUsize;

        let (server_cfg, cert_der) = crate::crypto::tls::generate_self_signed_server_config(
            &["localhost".to_string()],
            &[b"h2".to_vec()],
        )
        .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(server_cfg);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ns = listener.local_addr().unwrap();
        let accepted_conns = Arc::new(AtomicUsize::new(0));
        let accepted_srv = Arc::clone(&accepted_conns);

        let srv_jh = tokio::spawn(async move {
            // Connection #1: answers Stream 1, then blackholes Stream 3 forever
            let (tcp1, _) = listener.accept().await.unwrap();
            accepted_srv.fetch_add(1, Ordering::SeqCst);
            let mut tls1 = acceptor.accept(tcp1).await.unwrap();
            let h1 = tokio::spawn(async move {
                let mut preface = [0u8; H2_CLIENT_PREFACE.len()];
                tls1.read_exact(&mut preface).await.unwrap();
                let mut srv_settings = BytesMut::with_capacity(9);
                put_h2_frame_header(&mut srv_settings, 0, H2_FRAME_SETTINGS, 0, 0);
                tls1.write_all(&srv_settings).await.unwrap();
                tls1.flush().await.unwrap();
                loop {
                    let Ok((ftype, flags, sid, payload)) = read_h2_frame(&mut tls1).await else {
                        break;
                    };
                    if ftype == H2_FRAME_DATA && sid == 1 && (flags & H2_FLAG_END_STREAM) != 0 {
                        mock_write_h2_doh_response(
                            &mut tls1,
                            1,
                            &payload,
                            std::net::Ipv4Addr::new(198, 51, 100, 1),
                        )
                        .await;
                    } else if ftype == H2_FRAME_DATA
                        && sid == 3
                        && (flags & H2_FLAG_END_STREAM) != 0
                    {
                        // Blackhole: keep TCP/TLS socket open without ever replying
                        tokio::time::sleep(Duration::from_secs(30)).await;
                        break;
                    }
                }
            });

            // Connection #2: healthy replacement connection after pool eviction
            let (tcp2, _) = listener.accept().await.unwrap();
            accepted_srv.fetch_add(1, Ordering::SeqCst);
            let mut tls2 = acceptor.accept(tcp2).await.unwrap();
            let mut preface = [0u8; H2_CLIENT_PREFACE.len()];
            tls2.read_exact(&mut preface).await.unwrap();
            let mut srv_settings = BytesMut::with_capacity(9);
            put_h2_frame_header(&mut srv_settings, 0, H2_FRAME_SETTINGS, 0, 0);
            tls2.write_all(&srv_settings).await.unwrap();
            tls2.flush().await.unwrap();
            loop {
                let Ok((ftype, flags, sid, payload)) = read_h2_frame(&mut tls2).await else {
                    break;
                };
                if ftype == H2_FRAME_DATA && sid == 1 && (flags & H2_FLAG_END_STREAM) != 0 {
                    mock_write_h2_doh_response(
                        &mut tls2,
                        1,
                        &payload,
                        std::net::Ipv4Addr::new(198, 51, 100, 2),
                    )
                    .await;
                    break;
                }
            }
            h1.abort();
        });

        let extra_ca = [cert_der];
        let q1 =
            crate::dns::wire::build_dns_query(0x1111, "one.example", crate::dns::wire::QTYPE_A);
        let r1 = forward_doh_dns_with_timeout(
            ns,
            "localhost",
            "localhost",
            "/dns-query",
            false,
            &extra_ca,
            &q1,
            Duration::from_secs(2),
        )
        .await
        .unwrap();
        assert_eq!([r1[0], r1[1]], [0x11, 0x11]);
        assert_eq!(accepted_conns.load(Ordering::SeqCst), 1);

        let pool_key = TlsDnsPoolKey {
            ns,
            sni: "localhost".to_string(),
            skip_cert_verify: false,
            is_doh: true,
            extra_ca_hash: hash_extra_ca(&extra_ca),
            protector_epoch: current_protector_epoch(),
        };
        let slot = get_h2_slot(&pool_key);
        let pooled_conn1 = slot.lock().await.clone().expect("conn1 must be pooled");
        assert!(pooled_conn1.is_reusable());

        // Query 2 hits blackhole on Connection #1 and times out after 120ms
        let q2 =
            crate::dns::wire::build_dns_query(0x2222, "two.example", crate::dns::wire::QTYPE_A);
        let err = forward_doh_dns_with_timeout(
            ns,
            "localhost",
            "localhost",
            "/dns-query",
            false,
            &extra_ca,
            &q2,
            Duration::from_millis(120),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, ProxyError::Timeout));

        // Blackholed client MUST be marked closed AND evicted from H2_DNS_POOL immediately!
        assert!(!pooled_conn1.is_reusable());
        assert!(slot.lock().await.is_none());

        // Query 3 immediately dials fresh Connection #2 instead of stalling on blackholed Connection #1
        let q3 =
            crate::dns::wire::build_dns_query(0x3333, "three.example", crate::dns::wire::QTYPE_A);
        let r3 = forward_doh_dns_with_timeout(
            ns,
            "localhost",
            "localhost",
            "/dns-query",
            false,
            &extra_ca,
            &q3,
            Duration::from_secs(2),
        )
        .await
        .unwrap();
        assert_eq!([r3[0], r3[1]], [0x33, 0x33]);
        assert_eq!(accepted_conns.load(Ordering::SeqCst), 2);
        let meta = crate::dns::wire::extract_dns_response_meta(&r3).unwrap();
        assert_eq!(
            meta.answers,
            vec![crate::dns::wire::DnsAnswerData::A(std::net::Ipv4Addr::new(
                198, 51, 100, 2
            ))]
        );

        srv_jh.await.unwrap();
    }

    #[tokio::test]
    async fn udp_dns_retransmits_at_650ms_when_initial_packet_is_dropped() {
        let server_sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let ns = server_sock.local_addr().unwrap();
        let received_packets = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let received_clone = std::sync::Arc::clone(&received_packets);

        let srv_jh = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            // 1st packet: simulate cellular RRC wake-up packet loss (drop silently)
            let (_n1, _peer1) = server_sock.recv_from(&mut buf).await.unwrap();
            received_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);

            // 2nd packet (650ms retransmit): answer cleanly
            let (n2, peer2) = server_sock.recv_from(&mut buf).await.unwrap();
            received_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let parsed = crate::dns::wire::DnsQueryPacket::parse(&buf[..n2]).unwrap();
            let reply = parsed.build_response(
                &buf[..n2],
                0,
                60,
                &[crate::dns::wire::DnsAnswerData::A(std::net::Ipv4Addr::new(
                    203, 0, 113, 77,
                ))],
            );
            server_sock.send_to(&reply, peer2).await.unwrap();
        });

        let query = crate::dns::wire::build_dns_query(
            0x7788,
            "rrc-wakeup.example.com",
            crate::dns::wire::QTYPE_A,
        );
        let t0 = tokio::time::Instant::now();
        let resp = forward_udp_dns_with_tcp_fallback(ns, &query)
            .await
            .expect("650ms UDP retransmit should recover dropped initial packet");
        let elapsed = t0.elapsed();

        assert_eq!(
            received_packets.load(std::sync::atomic::Ordering::SeqCst),
            2
        );
        assert!(
            elapsed >= Duration::from_millis(600) && elapsed < Duration::from_millis(1600),
            "expected recovery around 650ms, got {elapsed:?}"
        );
        let meta = crate::dns::wire::extract_dns_response_meta(&resp).unwrap();
        assert_eq!(
            meta.answers,
            vec![crate::dns::wire::DnsAnswerData::A(std::net::Ipv4Addr::new(
                203, 0, 113, 77
            ))]
        );

        srv_jh.await.unwrap();
    }

    #[tokio::test]
    async fn tls_and_h2_dns_pools_evict_wall_clock_expired_sessions_across_suspend() {
        let mono_now = Instant::now();
        let base_wall = 1_700_000_000_000u64;

        // 1. `is_tls_pool_entry_fresh` checks both monotonic and wall-clock idle TTL (45s)
        assert!(is_tls_pool_entry_fresh(
            mono_now,
            base_wall,
            mono_now,
            base_wall + 44_999
        ));
        // Monotonic froze at `mono_now`, but wall-clock advanced 45s across Android suspend -> expired!
        assert!(!is_tls_pool_entry_fresh(
            mono_now,
            base_wall,
            mono_now,
            base_wall + 45_000
        ));

        // 2. `H2DohClient::is_reusable_at` aborts and rejects sessions whose wall-clock idle age >= 45s
        let (client_io, _server_io) = tokio::io::duplex(16 * 1024);
        let client = H2DohClient::spawn_io(client_io);
        let spawned_wall = client.last_rx_wall_ms.load(Ordering::Acquire);
        assert!(client.is_reusable_at(spawned_wall + 10_000));
        assert!(!client.is_reusable_at(spawned_wall + 45_000));
        // Once aborted by wall-clock expiry, `closed` stays true even if queried again.
        assert!(client.closed.load(Ordering::Acquire));
        assert!(!client.is_reusable_at(spawned_wall + 1_000));
    }
}

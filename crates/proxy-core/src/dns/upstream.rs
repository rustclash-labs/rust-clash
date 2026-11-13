use std::{
    collections::{HashMap, hash_map::DefaultHasher},
    hash::{Hash, Hasher},
    net::{IpAddr, SocketAddr},
    sync::LazyLock,
    time::{Duration, Instant},
};

use bytes::{BufMut, BytesMut};
use parking_lot::Mutex;
use rustls::pki_types::CertificateDer;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
};
use tokio_rustls::{TlsConnector, client::TlsStream};
use url::Url;

use crate::{
    error::{ProxyError, Result},
    platform::socket_protect::{protected_tcp_connect_addr, protected_udp_bind},
};

const DNS_IO_TIMEOUT: Duration = Duration::from_secs(3);
const DNS_TLS_IDLE_TTL: Duration = Duration::from_secs(45);
const MAX_IDLE_TLS_CONNS_PER_KEY: usize = 4;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct TlsDnsPoolKey {
    ns: SocketAddr,
    sni: String,
    skip_cert_verify: bool,
    is_doh: bool,
    extra_ca_hash: u64,
}

type TlsDnsPoolEntry = (Instant, TlsStream<TcpStream>);
type TlsDnsPoolMap = HashMap<TlsDnsPoolKey, Vec<TlsDnsPoolEntry>>;

static TLS_DNS_POOL: LazyLock<Mutex<TlsDnsPoolMap>> = LazyLock::new(|| Mutex::new(HashMap::new()));

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
    let mut guard = TLS_DNS_POOL.lock();
    let list = guard.get_mut(key)?;
    while let Some((stored_at, stream)) = list.pop() {
        if now.duration_since(stored_at) < DNS_TLS_IDLE_TTL {
            return Some(stream);
        }
    }
    None
}

fn push_idle_tls_stream(key: TlsDnsPoolKey, stream: TlsStream<TcpStream>) {
    let now = Instant::now();
    let mut guard = TLS_DNS_POOL.lock();
    if guard.len() > 64 {
        guard.retain(|_, v| {
            v.retain(|(ts, _)| now.duration_since(*ts) < DNS_TLS_IDLE_TTL);
            !v.is_empty()
        });
    }
    let entry = guard.entry(key).or_default();
    entry.retain(|(ts, _)| now.duration_since(*ts) < DNS_TLS_IDLE_TTL);
    if entry.len() < MAX_IDLE_TLS_CONNS_PER_KEY {
        entry.push((now, stream));
    }
}

/// Evict all pooled DoT/DoH TLS upstream sockets (called on network handoff and DNS cache flush).
pub fn clear_dns_upstream_pools() {
    TLS_DNS_POOL.lock().clear();
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DnsEndpointHost {
    Ip(IpAddr),
    Domain(String),
}

#[derive(Clone, Debug)]
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

#[derive(Clone, Debug)]
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
    let bind_addr: SocketAddr = if ns.is_ipv4() {
        "0.0.0.0:0".parse().expect("valid v4 bind")
    } else {
        "[::]:0".parse().expect("valid v6 bind")
    };
    let sock = protected_udp_bind(bind_addr, Some(ns))?;
    sock.connect(ns).await?;
    sock.send(query).await?;

    let mut buf = vec![0u8; 4096];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(ProxyError::Timeout);
        }
        let n = tokio::time::timeout(remaining, sock.recv(&mut buf))
            .await
            .map_err(|_| ProxyError::Timeout)??;
        if n < 12 {
            continue;
        }
        if (buf[2] & 0x80) == 0 || [buf[0], buf[1]] != expected_id {
            continue;
        }
        return Ok(buf[..n].to_vec());
    }
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
    };

    if let Some(mut pooled) = pop_idle_tls_stream(&pool_key)
        && let Ok(Ok(resp)) = tokio::time::timeout(
            DNS_IO_TIMEOUT,
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
    Ok(resp)
}

async fn exchange_doh_over_stream(
    tls: &mut TlsStream<TcpStream>,
    host_header: &str,
    path_and_query: &str,
    doh_wire: &[u8],
    orig_id: [u8; 2],
) -> Result<(Vec<u8>, bool)> {
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
            let wire = finalize_doh_body(parsed, orig_id)?;
            return Ok((wire, !server_closed));
        }
    }

    let body = parse_http_response_body(&raw_http)?;
    let wire = finalize_doh_body(body, orig_id)?;
    Ok((wire, false))
}

/// Forward a DNS query over RFC 8484 DNS-over-HTTPS (`POST` `application/dns-message`) using `SocketProtector` and HTTP/1.1 keep-alive pooling.
pub async fn forward_doh_dns(
    ns: SocketAddr,
    sni: &str,
    host_header: &str,
    path_and_query: &str,
    skip_cert_verify: bool,
    extra_ca_der: &[CertificateDer<'static>],
    query: &[u8],
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

    let pool_key = TlsDnsPoolKey {
        ns,
        sni: sni.to_string(),
        skip_cert_verify,
        is_doh: true,
        extra_ca_hash: hash_extra_ca(extra_ca_der),
    };

    if let Some(mut pooled) = pop_idle_tls_stream(&pool_key)
        && let Ok(Ok((resp, reusable))) = tokio::time::timeout(
            DNS_IO_TIMEOUT,
            exchange_doh_over_stream(&mut pooled, host_header, path_and_query, &doh_wire, orig_id),
        )
        .await
    {
        if reusable {
            push_idle_tls_stream(pool_key, pooled);
        }
        return Ok(resp);
    }

    let alpn = [b"http/1.1".to_vec(), b"h2".to_vec()];
    let client_cfg =
        crate::crypto::tls::build_tls_client_config(skip_cert_verify, extra_ca_der, &alpn)?;
    let connector = TlsConnector::from(client_cfg);
    let server_name = crate::crypto::tls::parse_server_name(sni)?;

    tokio::time::timeout(DNS_IO_TIMEOUT, async {
        let tcp = protected_tcp_connect_addr(ns).await?;
        let mut tls = connector.connect(server_name, tcp).await?;
        if tls.get_ref().1.alpn_protocol() == Some(b"h2") {
            exchange_doh_h2_over_stream(&mut tls, host_header, path_and_query, &doh_wire, orig_id)
                .await
        } else {
            let (resp, reusable) =
                exchange_doh_over_stream(&mut tls, host_header, path_and_query, &doh_wire, orig_id)
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

fn finalize_doh_body(mut body: Vec<u8>, orig_id: [u8; 2]) -> Result<Vec<u8>> {
    if body.len() < 12 || (body[2] & 0x80) == 0 {
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
        input = &input[crlf + 2..];
        if chunk_len == 0 {
            if input.len() < 2 {
                return Ok(None);
            }
            return Ok(Some(out));
        }
        if input.len() < chunk_len + 2 {
            return Ok(None);
        }
        out.extend_from_slice(&input[..chunk_len]);
        input = &input[chunk_len + 2..];
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

    finalize_doh_body(body, orig_id)
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

fn hpack_extract_status(mut block: &[u8]) -> Result<u16> {
    let mut status: Option<u16> = None;
    let mut dyn_table: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();

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
            let (_new_max, used) = decode_hpack_int(block, 5)?;
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
            if indexed_insert && dyn_table.len() < 64 {
                dyn_table.insert(0, (name_bytes, val_bytes));
            }
        }
    }

    status.ok_or_else(|| ProxyError::Dns("DoH HTTP/2 response missing :status header".into()))
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
}

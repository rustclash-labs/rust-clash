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
}

impl BootstrapDnsServer {
    /// Parse a `default-nameserver` entry. Bootstrap servers MUST specify literal IP addresses
    /// (not domain names) to prevent chicken-and-egg DNS bootstrap loops or OS resolver leaks.
    pub fn parse(raw: &str) -> Result<Self> {
        let s = raw.trim().split('#').next().unwrap_or("").trim();
        if let Some(rest) = s.strip_prefix("tcp://") {
            let sa = parse_ip_socket_addr(rest, 53).ok_or_else(|| {
                ProxyError::Config(format!(
                    "default-nameserver '{raw}' must use a literal IP address, not a hostname"
                ))
            })?;
            return Ok(Self::Tcp(sa));
        }
        let rest = s.strip_prefix("udp://").unwrap_or(s);
        let sa = parse_ip_socket_addr(rest, 53).ok_or_else(|| {
            ProxyError::Config(format!(
                "default-nameserver '{raw}' must use a literal IP address, not a hostname"
            ))
        })?;
        Ok(Self::Udp(sa))
    }

    pub fn ip(&self) -> IpAddr {
        match self {
            Self::Udp(sa) | Self::Tcp(sa) => sa.ip(),
        }
    }

    pub async fn exchange(&self, query: &[u8]) -> Result<Vec<u8>> {
        match *self {
            Self::Udp(sa) => forward_udp_dns_with_tcp_fallback(sa, query).await,
            Self::Tcp(sa) => forward_tcp_dns(sa, query).await,
        }
    }
}

impl DnsUpstream {
    pub fn parse(raw: &str) -> Result<Self> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(ProxyError::Config("empty DNS upstream entry".into()));
        }

        // Allow `#skip-cert-verify` fragment modifier on DoT / DoH URLs for testing / private PKI
        let (main_part, frag) = match trimmed.split_once('#') {
            Some((a, b)) => (a.trim(), Some(b.trim())),
            None => (trimmed, None),
        };
        let skip_cert_verify = frag.is_some_and(|f| {
            f.split('&').any(|kv| {
                kv.eq_ignore_ascii_case("skip-cert-verify")
                    || kv.eq_ignore_ascii_case("skip-cert-verify=true")
                    || kv.eq_ignore_ascii_case("insecure=1")
            })
        });

        if main_part.starts_with("https://") {
            let parsed = Url::parse(main_part)
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
            let sni = clean_host.to_string();
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

        if main_part.starts_with("tls://") {
            let parsed = Url::parse(main_part)
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
                sni: clean_host.to_string(),
                skip_cert_verify,
            });
        }

        if let Some(rest) = main_part.strip_prefix("tcp://") {
            let sa = parse_ip_socket_addr(rest, 53).ok_or_else(|| {
                ProxyError::Config(format!(
                    "invalid TCP DNS server '{raw}': expected IP[:PORT]"
                ))
            })?;
            return Ok(Self::Tcp(sa));
        }

        let udp_rest = main_part.strip_prefix("udp://").unwrap_or(main_part);
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

    let alpn = [b"http/1.1".to_vec()];
    let client_cfg =
        crate::crypto::tls::build_tls_client_config(skip_cert_verify, extra_ca_der, &alpn)?;
    let connector = TlsConnector::from(client_cfg);
    let server_name = crate::crypto::tls::parse_server_name(sni)?;

    tokio::time::timeout(DNS_IO_TIMEOUT, async {
        let tcp = protected_tcp_connect_addr(ns).await?;
        let mut tls = connector.connect(server_name, tcp).await?;
        let (resp, reusable) =
            exchange_doh_over_stream(&mut tls, host_header, path_and_query, &doh_wire, orig_id)
                .await?;
        if reusable {
            push_idle_tls_stream(pool_key, tls);
        }
        Ok(resp)
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

use std::{
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use futures_util::future::join_all;
use rustls::{ProtocolVersion, pki_types::CertificateDer};
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::Semaphore,
};
use tokio_rustls::TlsConnector;
use url::Url;

use crate::{
    addr::{HostName, TargetAddr},
    config::{ClashConfig, uri::redact_sensitive_text},
    crypto::tls::{build_tls_client_config, parse_server_name},
    dns::wire::{QTYPE_A, build_dns_query},
    error::{ProxyError, Result},
    router::Router,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeVerdict {
    /// HTTP 2xx / 3xx — endpoint responded normally
    Reachable,
    /// HTTP 400 / 401 / 404 / 405 — TLS & origin unblocked, API credentials required (account quota unverified)
    AuthRequired,
    /// HTTP 429 — TLS & origin reachable, but shared exit IP or endpoint is rate-limited
    RateLimited,
    /// HTTP 403 / 451 or Cloudflare `cf-mitigated: challenge` — geo-restricted or WAF-blocked
    BlockedOrChallenged,
    /// HTTP 5xx — upstream server error
    ServerError,
    /// DNS, TCP/Tunnel, TLS, or HTTP read failed / timed out
    Unreachable,
}

impl ProbeVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reachable => "reachable",
            Self::AuthRequired => "auth_required",
            Self::RateLimited => "rate_limited",
            Self::BlockedOrChallenged => "blocked_or_challenged",
            Self::ServerError => "server_error",
            Self::Unreachable => "unreachable",
        }
    }

    /// True when transport, TLS, and upstream geo/WAF checks passed without rate-limiting (`2xx`/`3xx`/`AuthRequired`).
    pub fn is_egress_unblocked(self) -> bool {
        matches!(self, Self::Reachable | Self::AuthRequired)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct UdpProbeResult {
    /// `"verified"`, `"blackholed"`, or `"unsupported"`
    pub status: String,
    pub configured_udp: bool,
    pub target: Option<String>,
    pub rtt_ms: Option<f64>,
    pub detail: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct WaterfallProbeReport {
    pub requested_proxy: String,
    pub effective_outbound: String,
    pub protocol: String,
    pub chains: Vec<String>,
    pub url: String,
    pub target_host: String,
    pub target_port: u16,
    pub remote_dns: bool,
    pub dns_mode: String,
    pub dns_resolve_ms: Option<f64>,
    pub tunnel_connect_ms: Option<f64>,
    pub tls_handshake_ms: Option<f64>,
    pub http_ttfb_ms: Option<f64>,
    /// Strictly the TCP/TLS/HTTP waterfall latency (never inflated by parallel UDP probing).
    pub total_ms: f64,
    /// Total wall-clock duration including any concurrent UDP probe wait.
    #[serde(default)]
    pub overall_probe_duration_ms: f64,
    pub tls_version: Option<String>,
    pub alpn: Option<String>,
    pub http_status: Option<u16>,
    pub server_header: Option<String>,
    pub cf_mitigated: bool,
    pub verdict: ProbeVerdict,
    pub failed_stage: Option<String>,
    pub note: String,
    pub error: Option<String>,
    pub udp_probe: Option<UdpProbeResult>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatrixEndpointSpec {
    pub id: String,
    pub label: String,
    pub category: String,
    pub url: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EndpointMatrixItem {
    pub id: String,
    pub label: String,
    pub category: String,
    pub report: WaterfallProbeReport,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EndpointMatrixReport {
    pub requested_proxy: String,
    pub effective_outbound: String,
    pub protocol: String,
    pub chains: Vec<String>,
    pub reachable_count: usize,
    pub auth_required_count: usize,
    pub rate_limited_count: usize,
    pub blocked_count: usize,
    pub unreachable_count: usize,
    pub ai_egress_unblocked: bool,
    pub ai_status_note: String,
    pub udp_probe: UdpProbeResult,
    pub items: Vec<EndpointMatrixItem>,
}

#[derive(Clone, Copy)]
pub struct ProbeOptions<'a> {
    pub extra_ca_der: &'a [CertificateDer<'static>],
    pub check_udp: bool,
    pub udp_dns_target: Option<&'a str>,
    pub timeout: Duration,
    /// When `false` (default), loopback, RFC1918 private, link-local, CGNAT, ULA, and cloud-IMDS targets are rejected.
    pub allow_private_targets: bool,
    /// Exact `(ip, port)` exceptions permitted even when `allow_private_targets == false` (used for built-in `--demo` sandbox).
    pub allowed_private_addrs: &'a [SocketAddr],
}

impl<'a> Default for ProbeOptions<'a> {
    fn default() -> Self {
        Self {
            extra_ca_der: &[],
            check_udp: false,
            udp_dns_target: None,
            timeout: Duration::from_secs(5),
            allow_private_targets: false,
            allowed_private_addrs: &[],
        }
    }
}

/// Returns `true` if `raw_ip` belongs to loopback, private, link-local / cloud metadata (`169.254.0.0/16`),
/// CGNAT (`100.64.0.0/10`), Fake-IP/benchmarking (`198.18.0.0/15`), IPv6 ULA (`fc00::/7`), multicast,
/// unspecified, documentation, or reserved ranges (including IPv4-mapped IPv6 equivalents).
pub fn is_restricted_probe_ip(raw_ip: IpAddr) -> bool {
    match raw_ip.to_canonical() {
        IpAddr::V4(v4) => {
            let oct = v4.octets();
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_documentation()
                || (oct[0] == 100 && (oct[1] & 0b1100_0000) == 64) // RFC 6598 CGNAT 100.64.0.0/10
                || (oct[0] == 198 && (oct[1] == 18 || oct[1] == 19)) // Fake-IP / RFC 2544 198.18.0.0/15
                || (oct[0] == 192 && oct[1] == 0 && oct[2] == 0) // IETF 192.0.0.0/24
                || oct[0] >= 240 // Class E reserved
        }
        IpAddr::V6(v6) => {
            let seg = v6.segments();
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (seg[0] & 0xfe00) == 0xfc00 // Unique Local fc00::/7 (incl. fd00:ec2::254)
                || (seg[0] & 0xffc0) == 0xfe80 // Link-Local fe80::/10
                || (seg[0] == 0x2001 && seg[1] == 0x0db8) // Documentation 2001:db8::/32
        }
    }
}

/// Returns `true` if `host` is a loopback, mDNS, or cloud-metadata internal hostname.
pub fn is_restricted_probe_hostname(host: &str) -> bool {
    let h = host
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim_end_matches('.')
        .to_ascii_lowercase();
    h == "localhost"
        || h.ends_with(".localhost")
        || h.ends_with(".local")
        || h.ends_with(".internal")
        || h == "metadata"
        || h == "instance-data"
}

fn is_whitelisted_private_addr(ip: IpAddr, port: u16, allowed: &[SocketAddr]) -> bool {
    let canon = ip.to_canonical();
    allowed
        .iter()
        .any(|sa| sa.port() == port && sa.ip().to_canonical() == canon)
}

pub fn validate_probe_endpoint(
    host: &str,
    port: u16,
    allow_private: bool,
    allowed_addrs: &[SocketAddr],
) -> Result<()> {
    if allow_private {
        return Ok(());
    }
    let clean = host.trim().trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = clean.parse::<IpAddr>() {
        if is_whitelisted_private_addr(ip, port, allowed_addrs) {
            return Ok(());
        }
        if is_restricted_probe_ip(ip) {
            return Err(ProxyError::Config(format!(
                "probe target '{clean}:{port}' is a loopback, private, link-local, or cloud-metadata address (blocked by SSRF protection)"
            )));
        }
        return Ok(());
    }
    if clean.eq_ignore_ascii_case("localhost")
        && allowed_addrs
            .iter()
            .any(|sa| sa.port() == port && sa.ip().is_loopback())
    {
        return Ok(());
    }
    if is_restricted_probe_hostname(clean) {
        return Err(ProxyError::Config(format!(
            "probe target '{clean}:{port}' uses a restricted local/internal hostname (blocked by SSRF protection)"
        )));
    }
    Ok(())
}

fn round_ms(d: Duration) -> f64 {
    (d.as_secs_f64() * 1000.0 * 100.0).round() / 100.0
}

fn format_tls_version(v: Option<ProtocolVersion>) -> Option<String> {
    match v {
        Some(ProtocolVersion::TLSv1_3) => Some("TLSv1.3".to_string()),
        Some(ProtocolVersion::TLSv1_2) => Some("TLSv1.2".to_string()),
        Some(other) => Some(format!("{other:?}")),
        None => None,
    }
}

fn parse_probe_url(raw_url: &str) -> Result<(bool, String, u16, String, String)> {
    let parsed = Url::parse(raw_url.trim())
        .map_err(|e| ProxyError::Config(format!("invalid probe URL: {e}")))?;
    let is_https = match parsed.scheme() {
        "https" => true,
        "http" => false,
        other => {
            return Err(ProxyError::Config(format!(
                "unsupported probe URL scheme '{other}' (only http:// and https:// are allowed)"
            )));
        }
    };
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(ProxyError::Config(
            "probe URL must not contain userinfo credentials".into(),
        ));
    }
    let raw_host = parsed
        .host_str()
        .ok_or_else(|| ProxyError::Config("probe URL is missing host".into()))?;
    let clean_host = raw_host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_string();
    let default_port = if is_https { 443 } else { 80 };
    let port = parsed.port().unwrap_or(default_port);
    let path = match parsed.query() {
        Some(q) => format!(
            "{}?{q}",
            if parsed.path().is_empty() {
                "/"
            } else {
                parsed.path()
            }
        ),
        None => {
            if parsed.path().is_empty() {
                "/".to_string()
            } else {
                parsed.path().to_string()
            }
        }
    };
    let host_header = if parsed.port().is_some() {
        format!("{raw_host}:{port}")
    } else {
        raw_host.to_string()
    };
    let sanitized_url = format!(
        "{}://{}{}",
        parsed.scheme(),
        host_header,
        if parsed.path().is_empty() {
            "/"
        } else {
            parsed.path()
        }
    );
    Ok((is_https, clean_host, port, path, sanitized_url))
}

struct ParsedHttpHead {
    status: u16,
    cf_mitigated: bool,
    server: Option<String>,
}

async fn read_http_response_head<S: tokio::io::AsyncRead + Unpin>(
    stream: &mut S,
) -> io::Result<(Duration, ParsedHttpHead)> {
    let ttfb_start = Instant::now();
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 512];
    let mut first_byte_elapsed: Option<Duration> = None;

    while buf.len() < 4096 {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        if first_byte_elapsed.is_none() {
            first_byte_elapsed = Some(ttfb_start.elapsed());
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }

    let Some(ttfb) = first_byte_elapsed else {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "connection closed before HTTP response status line",
        ));
    };

    let head_end = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + 4)
        .unwrap_or(buf.len());
    let text = String::from_utf8_lossy(&buf[..head_end]);
    let mut lines = text.lines();
    let status_line = lines.next().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing HTTP response status line",
        )
    })?;
    let mut parts = status_line.split_whitespace();
    let proto = parts.next().unwrap_or("");
    if !proto.starts_with("HTTP/") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "upstream did not return a valid HTTP/1.x status line",
        ));
    }
    let status: u16 = parts
        .next()
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid HTTP status code"))?;

    let mut cf_mitigated = false;
    let mut server = None;
    for hdr in lines {
        let trimmed = hdr.trim();
        if trimmed.is_empty() {
            break;
        }
        if let Some((k, v)) = trimmed.split_once(':') {
            let kl = k.trim().to_ascii_lowercase();
            let val = v.trim();
            if kl == "cf-mitigated" && val.to_ascii_lowercase().contains("challenge") {
                cf_mitigated = true;
            } else if kl == "server" && !val.is_empty() {
                server = Some(val.chars().take(48).collect());
            }
        }
    }

    Ok((
        ttfb,
        ParsedHttpHead {
            status,
            cf_mitigated,
            server,
        },
    ))
}

fn classify_http_verdict(head: &ParsedHttpHead) -> (ProbeVerdict, String) {
    if head.cf_mitigated {
        return (
            ProbeVerdict::BlockedOrChallenged,
            format!(
                "HTTP {} with Cloudflare challenge (`cf-mitigated: challenge`) — exit IP is flagged or challenged",
                head.status
            ),
        );
    }
    match head.status {
        204 => (
            ProbeVerdict::Reachable,
            "HTTP 204 No Content — captive-portal & tunnel health verified".to_string(),
        ),
        200..=299 => (
            ProbeVerdict::Reachable,
            format!("HTTP {} OK — origin reachable without block", head.status),
        ),
        300..=399 => (
            ProbeVerdict::Reachable,
            format!("HTTP {} Redirect — origin reachable", head.status),
        ),
        401 => (
            ProbeVerdict::AuthRequired,
            "HTTP 401 Auth Required — TLS & origin unblocked; API key/account quota requires authenticated call"
                .to_string(),
        ),
        400 | 404 | 405 => (
            ProbeVerdict::AuthRequired,
            format!(
                "HTTP {} from API origin — TLS & network path unblocked (API auth/method required)",
                head.status
            ),
        ),
        429 => (
            ProbeVerdict::RateLimited,
            "HTTP 429 Rate Limited — TLS reached origin, but shared exit IP or endpoint is rate-limited"
                .to_string(),
        ),
        403 | 451 => (
            ProbeVerdict::BlockedOrChallenged,
            format!(
                "HTTP {} — exit IP appears geo-restricted or blocked by upstream WAF",
                head.status
            ),
        ),
        500..=599 => (
            ProbeVerdict::ServerError,
            format!("HTTP {} — upstream server error", head.status),
        ),
        other => (
            ProbeVerdict::Reachable,
            format!("HTTP {other} response received"),
        ),
    }
}

/// Probe real UDP datagram relay capability over `outbound` using an RFC 1035 DNS query.
pub async fn probe_outbound_udp(
    outbound: &Arc<dyn crate::outbound::OutboundHandler>,
    udp_dns_target: Option<&str>,
    timeout: Duration,
) -> UdpProbeResult {
    probe_outbound_udp_with_policy(outbound, udp_dns_target, timeout, false, &[]).await
}

pub async fn probe_outbound_udp_with_policy(
    outbound: &Arc<dyn crate::outbound::OutboundHandler>,
    udp_dns_target: Option<&str>,
    timeout: Duration,
    allow_private_targets: bool,
    allowed_private_addrs: &[SocketAddr],
) -> UdpProbeResult {
    if !outbound.udp_supported() {
        return UdpProbeResult {
            status: "unsupported".to_string(),
            configured_udp: false,
            target: None,
            rtt_ms: None,
            detail: format!(
                "Outbound '{}' ({}) does not enable UDP relay (`udp: false` or HTTP-only)",
                outbound.name(),
                outbound.protocol()
            ),
        };
    }

    let raw_target = udp_dns_target
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("1.1.1.1:53");
    let parsed_target = match raw_target.parse::<TargetAddr>() {
        Ok(t) => t,
        Err(e) => {
            return UdpProbeResult {
                status: "blackholed".to_string(),
                configured_udp: true,
                target: Some(raw_target.to_string()),
                rtt_ms: None,
                detail: format!("Invalid UDP probe target '{raw_target}': {e}"),
            };
        }
    };

    let target_host_str = match &parsed_target.host {
        HostName::Ip(ip) => ip.to_string(),
        HostName::Domain(d) => d.clone(),
    };
    if let Err(ssrf_err) = validate_probe_endpoint(
        &target_host_str,
        parsed_target.port,
        allow_private_targets,
        allowed_private_addrs,
    ) {
        return UdpProbeResult {
            status: "blocked".to_string(),
            configured_udp: true,
            target: Some(parsed_target.to_string()),
            rtt_ms: None,
            detail: redact_sensitive_text(&ssrf_err.to_string()),
        };
    }

    let txid: u16 = 0x5A3C;
    let pkt = build_dns_query(txid, "example.com", QTYPE_A);
    let started = Instant::now();
    let bounded = timeout.min(Duration::from_millis(3500));

    match outbound.exchange_udp(&parsed_target, &pkt, bounded).await {
        Ok(resp) if resp.len() >= 12 && u16::from_be_bytes([resp[0], resp[1]]) == txid => {
            let ms = round_ms(started.elapsed());
            UdpProbeResult {
                status: "verified".to_string(),
                configured_udp: true,
                target: Some(parsed_target.to_string()),
                rtt_ms: Some(ms),
                detail: format!(
                    "UDP DNS relay verified ({}B reply in {ms:.1}ms)",
                    resp.len()
                ),
            }
        }
        Ok(resp) => UdpProbeResult {
            status: "blackholed".to_string(),
            configured_udp: true,
            target: Some(parsed_target.to_string()),
            rtt_ms: None,
            detail: format!(
                "UDP packet returned malformed DNS header ({} bytes)",
                resp.len()
            ),
        },
        Err(err) => UdpProbeResult {
            status: "blackholed".to_string(),
            configured_udp: true,
            target: Some(parsed_target.to_string()),
            rtt_ms: None,
            detail: format!(
                "Node advertises `udp: true` but UDP relay failed: {}",
                redact_sensitive_text(&err.to_string())
            ),
        },
    }
}

/// Execute a Surge-style per-stage timing waterfall probe (`DNS -> Tunnel Connect -> TLS Handshake -> HTTP TTFB`)
/// and optional UDP verification through a specific proxy node or group.
pub async fn probe_target_waterfall(
    router: &Router,
    config: &ClashConfig,
    proxy_or_group: &str,
    raw_url: &str,
    opts: ProbeOptions<'_>,
) -> Result<WaterfallProbeReport> {
    let (is_https, host_str, port, path_and_query, sanitized_url) = parse_probe_url(raw_url)?;
    validate_probe_endpoint(
        &host_str,
        port,
        opts.allow_private_targets,
        opts.allowed_private_addrs,
    )?;

    let target = match host_str.parse::<IpAddr>() {
        Ok(ip) => TargetAddr::new_ip(ip, port),
        Err(_) => TargetAddr::new_domain(&host_str, port)?,
    };

    let (outbound, chains) = router.resolve_chain(proxy_or_group, &target);
    if outbound.name() == "ROUTING-ERROR" {
        return Err(ProxyError::Routing(format!(
            "proxy or group '{proxy_or_group}' not found"
        )));
    }
    if outbound.exit_category() == "REJECT" {
        return Ok(WaterfallProbeReport {
            requested_proxy: proxy_or_group.to_string(),
            effective_outbound: outbound.name().to_string(),
            protocol: outbound.protocol().to_string(),
            chains,
            url: sanitized_url,
            target_host: host_str,
            target_port: port,
            remote_dns: false,
            dns_mode: "rejected".to_string(),
            dns_resolve_ms: None,
            tunnel_connect_ms: None,
            tls_handshake_ms: None,
            http_ttfb_ms: None,
            total_ms: 0.0,
            overall_probe_duration_ms: 0.0,
            tls_version: None,
            alpn: None,
            http_status: None,
            server_header: None,
            cf_mitigated: false,
            verdict: ProbeVerdict::Unreachable,
            failed_stage: Some("policy_reject".to_string()),
            note: "Target outbound resolves to REJECT".to_string(),
            error: Some("Rejected by policy".to_string()),
            udp_probe: None,
        });
    }

    let overall_start = Instant::now();
    let is_proxy_exit = outbound.exit_category() == "PROXY";
    let mut dns_resolve_ms: Option<f64> = None;
    let mut tunnel_connect_ms: Option<f64> = None;
    let mut tls_handshake_ms: Option<f64> = None;
    let mut http_ttfb_ms: Option<f64> = None;
    let mut tls_version: Option<String> = None;
    let mut alpn: Option<String> = None;
    let mut http_status: Option<u16> = None;
    let mut server_header: Option<String> = None;
    let mut cf_mitigated = false;
    let mut failed_stage: Option<String> = None;
    let mut err_msg: Option<String> = None;

    let (remote_dns, dns_mode) = if is_proxy_exit {
        match &target.host {
            HostName::Domain(_) => (true, "remote-tunnel-dns".to_string()),
            HostName::Ip(_) => (false, "literal-ip".to_string()),
        }
    } else {
        match &target.host {
            HostName::Domain(d) if d.eq_ignore_ascii_case("localhost") => {
                (false, "loopback".to_string())
            }
            HostName::Domain(_) => (false, "direct-local-dns".to_string()),
            HostName::Ip(_) => (false, "literal-ip".to_string()),
        }
    };

    let udp_fut = async {
        if opts.check_udp {
            Some(
                probe_outbound_udp_with_policy(
                    &outbound,
                    opts.udp_dns_target,
                    opts.timeout,
                    opts.allow_private_targets,
                    opts.allowed_private_addrs,
                )
                .await,
            )
        } else {
            None
        }
    };

    let tcp_waterfall_fut = async {
        // Stage 1: DNS Resolution (either proxy server bootstrap DNS or DIRECT target DNS)
        let dial_target = if is_proxy_exit {
            let proxy_server_opt = config
                .proxies
                .iter()
                .find(|p| p.name() == outbound.name())
                .map(|p| p.server_port().0.to_string());

            if let Some(srv) = proxy_server_opt {
                if srv.parse::<IpAddr>().is_ok() || srv.eq_ignore_ascii_case("localhost") {
                    dns_resolve_ms = Some(0.0);
                } else {
                    let t0 = Instant::now();
                    if let Err(e) = router.dns().resolve_proxy_server_ips(&srv).await {
                        failed_stage = Some("dns".to_string());
                        return Err(e.into_io());
                    }
                    dns_resolve_ms = Some(round_ms(t0.elapsed()));
                }
            } else {
                dns_resolve_ms = Some(0.0);
            }
            target.clone()
        } else {
            match &target.host {
                HostName::Ip(_) => {
                    dns_resolve_ms = Some(0.0);
                    target.clone()
                }
                HostName::Domain(dom) if dom.eq_ignore_ascii_case("localhost") => {
                    dns_resolve_ms = Some(0.0);
                    TargetAddr::new_ip(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
                }
                HostName::Domain(dom) => {
                    let t0 = Instant::now();
                    match router.dns().resolve_direct_ips(dom).await {
                        Ok(ips) if !ips.is_empty() => {
                            dns_resolve_ms = Some(round_ms(t0.elapsed()));
                            if !opts.allow_private_targets {
                                for &resolved_ip in &ips {
                                    if is_restricted_probe_ip(resolved_ip)
                                        && !is_whitelisted_private_addr(
                                            resolved_ip,
                                            port,
                                            opts.allowed_private_addrs,
                                        )
                                    {
                                        failed_stage = Some("dns".to_string());
                                        return Err(io::Error::new(
                                            io::ErrorKind::PermissionDenied,
                                            format!(
                                                "DNS resolved '{dom}' to restricted internal/private IP {resolved_ip} (blocked by SSRF protection)"
                                            ),
                                        ));
                                    }
                                }
                            }
                            TargetAddr::new_ip(ips[0], port)
                        }
                        Ok(_) => {
                            failed_stage = Some("dns".to_string());
                            return Err(io::Error::new(
                                io::ErrorKind::HostUnreachable,
                                format!("DNS returned no addresses for '{dom}'"),
                            ));
                        }
                        Err(e) => {
                            failed_stage = Some("dns".to_string());
                            return Err(e.into_io());
                        }
                    }
                }
            }
        };

        // Stage 2: TCP + Outbound Tunnel Handshake
        let t_conn = Instant::now();
        let mut stream = match outbound.connect_tcp(&dial_target).await {
            Ok(s) => {
                tunnel_connect_ms = Some(round_ms(t_conn.elapsed()));
                s
            }
            Err(e) => {
                failed_stage = Some("tunnel_connect".to_string());
                return Err(e);
            }
        };

        let host_hdr = if (is_https && port == 443) || (!is_https && port == 80) {
            host_str.clone()
        } else {
            format!("{host_str}:{port}")
        };
        let req_bytes = format!(
            "GET {path_and_query} HTTP/1.1\r\nHost: {host_hdr}\r\nUser-Agent: rust-clash/{}\r\nAccept: application/json, text/plain, */*\r\nConnection: close\r\n\r\n",
            env!("CARGO_PKG_VERSION")
        );

        if is_https {
            // Stage 3: End-to-End TLS Handshake over Tunnel
            let tls_cfg =
                build_tls_client_config(false, opts.extra_ca_der, &[b"http/1.1".to_vec()])?;
            let sni = parse_server_name(&host_str)?;
            let connector = TlsConnector::from(tls_cfg);
            let t_tls = Instant::now();
            let mut tls_stream = match connector.connect(sni, stream).await {
                Ok(ts) => {
                    tls_handshake_ms = Some(round_ms(t_tls.elapsed()));
                    ts
                }
                Err(e) => {
                    failed_stage = Some("tls_handshake".to_string());
                    return Err(e);
                }
            };

            let (_, conn_info) = tls_stream.get_ref();
            tls_version = format_tls_version(conn_info.protocol_version());
            alpn = conn_info
                .alpn_protocol()
                .map(|p| String::from_utf8_lossy(p).to_string());

            // Stage 4: HTTP Request & TTFB
            if let Err(e) = tls_stream.write_all(req_bytes.as_bytes()).await {
                failed_stage = Some("http_ttfb".to_string());
                return Err(e);
            }
            let _ = tls_stream.flush().await;
            match read_http_response_head(&mut tls_stream).await {
                Ok((ttfb_dur, head)) => {
                    http_ttfb_ms = Some(round_ms(ttfb_dur));
                    Ok(head)
                }
                Err(e) => {
                    failed_stage = Some("http_ttfb".to_string());
                    Err(e)
                }
            }
        } else {
            // Plain HTTP Stage 4: HTTP Request & TTFB
            if let Err(e) = stream.write_all(req_bytes.as_bytes()).await {
                failed_stage = Some("http_ttfb".to_string());
                return Err(e);
            }
            let _ = stream.flush().await;
            match read_http_response_head(&mut stream).await {
                Ok((ttfb_dur, head)) => {
                    http_ttfb_ms = Some(round_ms(ttfb_dur));
                    Ok(head)
                }
                Err(e) => {
                    failed_stage = Some("http_ttfb".to_string());
                    Err(e)
                }
            }
        }
    };

    // Measure TCP/HTTP waterfall duration strictly inside its own future so slow/blackholed
    // parallel UDP checks never inflate `total_ms` or pollute `router.delays()` (`URLTest`).
    let tcp_timed_fut = async {
        let tcp_start = Instant::now();
        let res = tokio::time::timeout(opts.timeout, tcp_waterfall_fut).await;
        (round_ms(tcp_start.elapsed()), res)
    };

    let ((total_ms, waterfall_res), udp_probe) = tokio::join!(tcp_timed_fut, udp_fut);
    let overall_probe_duration_ms = round_ms(overall_start.elapsed());

    let (verdict, note) = match waterfall_res {
        Ok(Ok(head)) => {
            http_status = Some(head.status);
            cf_mitigated = head.cf_mitigated;
            server_header = head.server.clone();
            let recorded_ms = (total_ms.round() as u64).max(1);
            router.delays().record(outbound.name(), recorded_ms);
            if proxy_or_group != outbound.name() {
                router.delays().record(proxy_or_group, recorded_ms);
            }
            classify_http_verdict(&head)
        }
        Ok(Err(io_err)) => {
            let stage = failed_stage
                .clone()
                .unwrap_or_else(|| "tunnel_connect".to_string());
            let clean = redact_sensitive_text(&io_err.to_string());
            err_msg = Some(clean.clone());
            (
                ProbeVerdict::Unreachable,
                format!("Failed at `{stage}` stage: {clean}"),
            )
        }
        Err(_) => {
            let stage = if dns_resolve_ms.is_none() {
                "dns"
            } else if tunnel_connect_ms.is_none() {
                "tunnel_connect"
            } else if is_https && tls_handshake_ms.is_none() {
                "tls_handshake"
            } else {
                "http_ttfb"
            };
            failed_stage = Some(stage.to_string());
            let msg = format!(
                "Timed out after {}ms during `{stage}` stage",
                opts.timeout.as_millis()
            );
            err_msg = Some(msg.clone());
            (ProbeVerdict::Unreachable, msg)
        }
    };

    Ok(WaterfallProbeReport {
        requested_proxy: proxy_or_group.to_string(),
        effective_outbound: outbound.name().to_string(),
        protocol: outbound.protocol().to_string(),
        chains,
        url: sanitized_url,
        target_host: host_str,
        target_port: port,
        remote_dns,
        dns_mode,
        dns_resolve_ms,
        tunnel_connect_ms,
        tls_handshake_ms,
        http_ttfb_ms,
        total_ms,
        overall_probe_duration_ms,
        tls_version,
        alpn,
        http_status,
        server_header,
        cf_mitigated,
        verdict,
        failed_stage,
        note,
        error: err_msg,
        udp_probe,
    })
}

/// Return the default curated AI & Developer Endpoint Matrix targets.
pub fn default_matrix_targets(demo_http_origin: Option<&str>) -> Vec<MatrixEndpointSpec> {
    let mut list = Vec::new();
    if let Some(origin) = demo_http_origin.filter(|s| !s.trim().is_empty()) {
        list.push(MatrixEndpointSpec {
            id: "demo-sandbox".to_string(),
            label: "Demo Loopback Origin".to_string(),
            category: "sandbox".to_string(),
            url: format!("{}/generate_204", origin.trim_end_matches('/')),
        });
    }
    list.extend([
        MatrixEndpointSpec {
            id: "cloudflare-204".to_string(),
            label: "Cloudflare Edge (204)".to_string(),
            category: "connectivity".to_string(),
            url: "http://cp.cloudflare.com/generate_204".to_string(),
        },
        MatrixEndpointSpec {
            id: "github-api".to_string(),
            label: "GitHub API".to_string(),
            category: "developer".to_string(),
            url: "https://api.github.com/".to_string(),
        },
        MatrixEndpointSpec {
            id: "openai-api".to_string(),
            label: "OpenAI API".to_string(),
            category: "ai".to_string(),
            url: "https://api.openai.com/v1/models".to_string(),
        },
        MatrixEndpointSpec {
            id: "anthropic-claude".to_string(),
            label: "Anthropic Claude API".to_string(),
            category: "ai".to_string(),
            url: "https://api.anthropic.com/v1/messages".to_string(),
        },
        MatrixEndpointSpec {
            id: "google-gemini".to_string(),
            label: "Google Gemini API".to_string(),
            category: "ai".to_string(),
            url: "https://generativelanguage.googleapis.com/".to_string(),
        },
    ]);
    list
}

/// Probe multiple AI & Developer endpoints concurrently + verify real UDP tunnel relay for `proxy_or_group`.
pub async fn probe_endpoint_matrix(
    router: &Router,
    config: &ClashConfig,
    proxy_or_group: &str,
    targets: Vec<MatrixEndpointSpec>,
    opts: ProbeOptions<'_>,
) -> Result<EndpointMatrixReport> {
    let dummy_target = TargetAddr::new_domain("example.com", 443)?;
    let (outbound, chains) = router.resolve_chain(proxy_or_group, &dummy_target);
    if outbound.name() == "ROUTING-ERROR" {
        return Err(ProxyError::Routing(format!(
            "proxy or group '{proxy_or_group}' not found"
        )));
    }

    let sem = Arc::new(Semaphore::new(6));
    let futs = targets.into_iter().map(|spec| {
        let sem_c = Arc::clone(&sem);
        async move {
            let _permit = sem_c.acquire().await.ok();
            let sub_opts = ProbeOptions {
                extra_ca_der: opts.extra_ca_der,
                check_udp: false,
                udp_dns_target: None,
                timeout: opts.timeout,
                allow_private_targets: opts.allow_private_targets,
                allowed_private_addrs: opts.allowed_private_addrs,
            };
            let report =
                probe_target_waterfall(router, config, proxy_or_group, &spec.url, sub_opts).await?;
            Ok::<EndpointMatrixItem, ProxyError>(EndpointMatrixItem {
                id: spec.id,
                label: spec.label,
                category: spec.category,
                report,
            })
        }
    });

    let (results, udp_probe) = tokio::join!(
        join_all(futs),
        probe_outbound_udp_with_policy(
            &outbound,
            opts.udp_dns_target,
            opts.timeout,
            opts.allow_private_targets,
            opts.allowed_private_addrs,
        )
    );

    let mut items = Vec::with_capacity(results.len());
    for res in results {
        items.push(res?);
    }

    let reachable_count = items
        .iter()
        .filter(|i| i.report.verdict.is_egress_unblocked())
        .count();
    let auth_required_count = items
        .iter()
        .filter(|i| i.report.verdict == ProbeVerdict::AuthRequired)
        .count();
    let rate_limited_count = items
        .iter()
        .filter(|i| i.report.verdict == ProbeVerdict::RateLimited)
        .count();
    let blocked_count = items
        .iter()
        .filter(|i| i.report.verdict == ProbeVerdict::BlockedOrChallenged)
        .count();
    let unreachable_count = items
        .iter()
        .filter(|i| {
            matches!(
                i.report.verdict,
                ProbeVerdict::Unreachable | ProbeVerdict::ServerError
            )
        })
        .count();

    let ai_items: Vec<&EndpointMatrixItem> = items.iter().filter(|i| i.category == "ai").collect();
    let ai_egress_unblocked = !ai_items.is_empty()
        && ai_items
            .iter()
            .all(|i| i.report.verdict.is_egress_unblocked());
    let ai_rate_limited = ai_items
        .iter()
        .filter(|i| i.report.verdict == ProbeVerdict::RateLimited)
        .count();
    let ai_blocked = ai_items
        .iter()
        .filter(|i| i.report.verdict == ProbeVerdict::BlockedOrChallenged)
        .count();

    let ai_status_note = if ai_items.is_empty() {
        "No AI endpoints included in matrix".to_string()
    } else if ai_egress_unblocked {
        "Transport & TLS unblocked across all AI origins (authenticated API key/quota not tested)"
            .to_string()
    } else if ai_blocked > 0 {
        format!("{ai_blocked} AI origin(s) geo-restricted or WAF-challenged (HTTP 403/451)")
    } else if ai_rate_limited > 0 {
        format!("{ai_rate_limited} AI origin(s) rate-limited (HTTP 429 on shared exit IP)")
    } else {
        "1 or more AI origins failed transport/TLS reachability".to_string()
    };

    Ok(EndpointMatrixReport {
        requested_proxy: proxy_or_group.to_string(),
        effective_outbound: outbound.name().to_string(),
        protocol: outbound.protocol().to_string(),
        chains,
        reachable_count,
        auth_required_count,
        rate_limited_count,
        blocked_count,
        unreachable_count,
        ai_egress_unblocked,
        ai_status_note,
        udp_probe,
        items,
    })
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SiteTakeoverContext {
    pub core_running: bool,
    pub sysproxy_enabled: bool,
    pub tun_enabled: bool,
    /// `"desktop"`, `"android"`, or `"cli"`
    pub platform_hint: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SiteStageCheck {
    /// `"route"`, `"takeover"`, `"dns"`, `"tcp_tunnel"`, `"tls"`, `"http"`, `"udp"`
    pub stage: String,
    /// `"ok"`, `"warn"`, `"fail"`, `"skipped"`
    pub status: String,
    pub label_zh: String,
    pub label_en: String,
    pub detail_zh: String,
    pub detail_en: String,
    pub latency_ms: Option<f64>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SiteDiagnosisReport {
    pub input: String,
    pub normalized_url: String,
    pub target_host: String,
    pub target_port: u16,
    pub checked_at_ms: u64,
    pub mode: String,
    pub matched_rule: String,
    pub rule_type: String,
    pub rule_payload: String,
    /// Ordered from entry group -> leaf node for human readability (e.g. `["🚀 Proxy", "JP-01"]`)
    pub route_flow: Vec<String>,
    /// Raw Clash-compatible chains (`leaf -> group`)
    pub chains: Vec<String>,
    pub effective_outbound: String,
    pub protocol: String,
    /// `"PROXY"`, `"DIRECT"`, or `"REJECT"`
    pub exit_type: String,
    pub proxy_node_count: usize,
    pub takeover: SiteTakeoverContext,
    /// `"reachable"`, `"reachable_takeover_off"`, `"rule_rejected"`, `"no_proxy_nodes"`,
    /// `"direct_unreachable"`, `"dns_failed"`, `"node_tunnel_failed"`, `"tls_handshake_failed"`,
    /// `"http_failed"`, `"blocked_or_challenged"`, `"rate_limited"`, `"server_error"`, `"routing_error"`
    pub diagnosis_code: String,
    /// `"ok"`, `"warning"`, or `"error"`
    pub severity: String,
    pub headline_zh: String,
    pub headline_en: String,
    pub summary_zh: String,
    pub summary_en: String,
    pub route_summary_zh: String,
    pub route_summary_en: String,
    pub actions_zh: Vec<String>,
    pub actions_en: Vec<String>,
    /// `"switch_node"`, `"enable_takeover"`, `"switch_mode_rule"`, `"import_profile"`, `"check_rules"`, or `None`
    pub suggested_action_kind: Option<String>,
    pub stage_checks: Vec<SiteStageCheck>,
    pub waterfall: Option<WaterfallProbeReport>,
}

/// Normalize a user-supplied website domain, `host:port`, or full `http(s)://` URL into
/// `(probe_url, route_target)`.
pub fn normalize_site_check_input(raw_input: &str) -> Result<(String, TargetAddr)> {
    let trimmed = raw_input.trim();
    if trimmed.is_empty() {
        return Err(ProxyError::Config(
            "请输入要检测的网站域名或网址（例如 chatgpt.com）".to_string(),
        ));
    }

    let candidate_url = if trimmed.contains("://") {
        trimmed.to_string()
    } else if let Ok(ip) = trimmed.parse::<IpAddr>() {
        match ip {
            IpAddr::V4(v4) => format!("https://{v4}/"),
            IpAddr::V6(v6) => format!("https://[{v6}]/"),
        }
    } else if let Some((host_part, rest)) = trimmed.split_once('/') {
        let scheme = if host_part.ends_with(":80") {
            "http"
        } else {
            "https"
        };
        format!("{scheme}://{host_part}/{rest}")
    } else if trimmed.ends_with(":80") {
        format!("http://{trimmed}/")
    } else {
        format!("https://{trimmed}/")
    };

    let (_is_https, host_str, port, _path_and_query, sanitized_url) =
        parse_probe_url(&candidate_url)?;
    let target = match host_str.parse::<IpAddr>() {
        Ok(ip) => TargetAddr::new_ip(ip, port),
        Err(_) => TargetAddr::new_domain(&host_str, port)?,
    };
    Ok((sanitized_url, target))
}

fn format_mode_label_zh(mode: &str) -> &'static str {
    match mode {
        "global" => "全局代理 (Global)",
        "direct" => "全局直连 (Direct)",
        _ => "智能分流 (Rule)",
    }
}

fn format_mode_label_en(mode: &str) -> &'static str {
    match mode {
        "global" => "Global Proxy",
        "direct" => "Global Direct",
        _ => "Rule Split",
    }
}

/// Unified user-oriented website diagnostic: evaluates live routing rules for `raw_input`,
/// runs a stage-isolated waterfall probe (`DNS -> TCP/Tunnel -> TLS -> HTTP TTFB` + UDP when supported)
/// along the matched outbound (skipping network traffic if rejected by policy), and translates the
/// outcome into plain-language bilingual explanations and concrete remediation steps.
pub async fn diagnose_site(
    router: &Router,
    config: &ClashConfig,
    raw_input: &str,
    takeover: SiteTakeoverContext,
    opts: ProbeOptions<'_>,
) -> Result<SiteDiagnosisReport> {
    let (normalized_url, route_target) = normalize_site_check_input(raw_input)?;
    let host_str = match &route_target.host {
        HostName::Ip(ip) => ip.to_string(),
        HostName::Domain(d) => d.clone(),
    };
    let port = route_target.port;

    validate_probe_endpoint(
        &host_str,
        port,
        opts.allow_private_targets,
        opts.allowed_private_addrs,
    )?;

    let checked_at_ms = crate::tracker::TelemetryHub::now_ms();
    let preview = router.preview_route_with_dns(&route_target).await;
    let mode_str = router.mode().as_str().to_string();
    let (rule_type, rule_payload) = match router.mode() {
        crate::config::RunMode::Direct => ("Mode".to_string(), "Direct".to_string()),
        crate::config::RunMode::Global => ("Mode".to_string(), "Global".to_string()),
        crate::config::RunMode::Rule => {
            if let Some(rest) = preview
                .matched_rule
                .split_once(' ')
                .map(|x| x.1)
                .filter(|s| !s.starts_with('('))
            {
                let mut parts = rest.splitn(3, ',');
                let rt = parts.next().unwrap_or("RULE").to_string();
                let second = parts.next().unwrap_or("");
                let third = parts.next();
                if third.is_some() {
                    (rt, second.to_string())
                } else {
                    (rt, String::new())
                }
            } else {
                ("ImplicitReject".to_string(), "no-matching-rule".to_string())
            }
        }
    };

    let chains = preview.chains.clone();
    let mut route_flow: Vec<String> = chains.iter().rev().cloned().collect();
    if route_flow.is_empty() {
        route_flow.push(preview.effective_outbound.clone());
    }
    let effective_outbound = preview.effective_outbound.clone();
    let exit_type = preview.exit_type.clone();
    let protocol = router
        .outbound(&effective_outbound)
        .map(|o| o.protocol().to_string())
        .unwrap_or_else(|| exit_type.to_ascii_lowercase());
    let proxy_node_count = config.proxies.len();

    let rule_desc_zh = if rule_payload.is_empty() {
        rule_type.clone()
    } else {
        format!("{rule_type} ({rule_payload})")
    };
    let flow_arrow = route_flow.join(" → ");
    let route_summary_zh = format!(
        "{} · 命中 {} → {}",
        format_mode_label_zh(&mode_str),
        rule_desc_zh,
        flow_arrow
    );
    let route_summary_en = format!(
        "{} · Matched {} → {}",
        format_mode_label_en(&mode_str),
        rule_desc_zh,
        flow_arrow
    );

    let takeover_active = takeover.sysproxy_enabled || takeover.tun_enabled;
    let takeover_stage = if !takeover.core_running {
        SiteStageCheck {
            stage: "takeover".to_string(),
            status: "warn".to_string(),
            label_zh: "系统流量接管".to_string(),
            label_en: "System Takeover".to_string(),
            detail_zh: if takeover.platform_hint == "android" {
                "VPN 尚未开启（当前仅使用配置离线测试节点连通性）".to_string()
            } else {
                "代理内核或系统接管尚未启用".to_string()
            },
            detail_en: if takeover.platform_hint == "android" {
                "VPN is currently off (testing route & node directly)".to_string()
            } else {
                "Core or system takeover is currently off".to_string()
            },
            latency_ms: None,
        }
    } else if takeover_active {
        let mode_detail_zh = match (takeover.sysproxy_enabled, takeover.tun_enabled) {
            (true, true) => "系统代理 + TUN 已启用",
            (true, false) => "系统代理已启用",
            (false, true) => "TUN / VPN 网卡接管已启用",
            (false, false) => "未启用",
        };
        let mode_detail_en = match (takeover.sysproxy_enabled, takeover.tun_enabled) {
            (true, true) => "System Proxy + TUN enabled",
            (true, false) => "System Proxy enabled",
            (false, true) => "TUN / VPN takeover enabled",
            (false, false) => "Off",
        };
        SiteStageCheck {
            stage: "takeover".to_string(),
            status: "ok".to_string(),
            label_zh: "系统流量接管".to_string(),
            label_en: "System Takeover".to_string(),
            detail_zh: mode_detail_zh.to_string(),
            detail_en: mode_detail_en.to_string(),
            latency_ms: None,
        }
    } else {
        SiteStageCheck {
            stage: "takeover".to_string(),
            status: "warn".to_string(),
            label_zh: "系统流量接管".to_string(),
            label_en: "System Takeover".to_string(),
            detail_zh: "未开启系统代理或 TUN/VPN（浏览器默认不会走代理端口）".to_string(),
            detail_en:
                "System Proxy and TUN/VPN are both off (browsers bypass RustClash by default)"
                    .to_string(),
            latency_ms: None,
        }
    };

    // Early Case 1: Routing error
    if effective_outbound == "ROUTING-ERROR" || effective_outbound == "UNMAPPED-FAKE-IP" {
        return Ok(SiteDiagnosisReport {
            input: raw_input.trim().to_string(),
            normalized_url,
            target_host: host_str,
            target_port: port,
            checked_at_ms,
            mode: mode_str,
            matched_rule: preview.matched_rule,
            rule_type,
            rule_payload,
            route_flow,
            chains,
            effective_outbound,
            protocol,
            exit_type,
            proxy_node_count,
            takeover,
            diagnosis_code: "routing_error".to_string(),
            severity: "error".to_string(),
            headline_zh: "分流策略组引用异常，无法选出可用出口".to_string(),
            headline_en: "Routing group chain error — no valid outbound resolved".to_string(),
            summary_zh: "当前配置中的策略组引用了不存在的节点或存在循环引用，RustClash 已按安全策略拒绝静默直连回退。".to_string(),
            summary_en: "The matched proxy-group references a missing node or cyclic group; fail-closed protection blocked silent direct fallback.".to_string(),
            route_summary_zh,
            route_summary_en,
            actions_zh: vec![
                "前往「配置」页面刷新订阅或重新导入完整配置文件。".to_string(),
                "前往「工具 → 配置防火墙」查看具体策略组告警。".to_string(),
            ],
            actions_en: vec![
                "Refresh your subscription or re-import the profile under Profiles.".to_string(),
                "Run Config Firewall Audit under Tools to inspect broken group references.".to_string(),
            ],
            suggested_action_kind: Some("import_profile".to_string()),
            stage_checks: vec![
                SiteStageCheck {
                    stage: "route".to_string(),
                    status: "fail".to_string(),
                    label_zh: "分流规则匹配".to_string(),
                    label_en: "Route Match".to_string(),
                    detail_zh: "策略组链路解析失败".to_string(),
                    detail_en: "Proxy-group chain resolution failed".to_string(),
                    latency_ms: None,
                },
                takeover_stage,
            ],
            waterfall: None,
        });
    }

    // Early Case 2: Rejected by rule (`REJECT`)
    if exit_type == "REJECT" {
        return Ok(SiteDiagnosisReport {
            input: raw_input.trim().to_string(),
            normalized_url,
            target_host: host_str.clone(),
            target_port: port,
            checked_at_ms,
            mode: mode_str,
            matched_rule: preview.matched_rule.clone(),
            rule_type,
            rule_payload,
            route_flow,
            chains,
            effective_outbound,
            protocol,
            exit_type,
            proxy_node_count,
            takeover,
            diagnosis_code: "rule_rejected".to_string(),
            severity: "error".to_string(),
            headline_zh: "该网站被当前分流规则直接拦截 (REJECT)".to_string(),
            headline_en: "Blocked by local routing rule (REJECT)".to_string(),
            summary_zh: format!(
                "分流规则 `{}` 将 `{}` 指向了 REJECT（常见于广告拦截规则、自定义屏蔽规则或缺少兜底 MATCH 规则），请求在本地即被阻断，未发往代理节点。",
                preview.matched_rule, host_str
            ),
            summary_en: format!(
                "Rule `{}` routed `{}` to REJECT before any network packet left your device.",
                preview.matched_rule, host_str
            ),
            route_summary_zh,
            route_summary_en,
            actions_zh: vec![
                format!(
                    "如属误拦，可在「自定义规则」顶部添加 `DOMAIN-SUFFIX,{host_str},🚀 Proxy` 放行。"
                ),
                "检查当前是否选用了过于激进的去广告规则集，或临时切换为「全局代理 (Global)」验证。"
                    .to_string(),
            ],
            actions_en: vec![
                format!(
                    "If blocked unintentionally, add `DOMAIN-SUFFIX,{host_str},🚀 Proxy` at the top of Custom Rules."
                ),
                "Check ad-block rulesets or temporarily test in Global Proxy mode.".to_string(),
            ],
            suggested_action_kind: Some("check_rules".to_string()),
            stage_checks: vec![
                SiteStageCheck {
                    stage: "route".to_string(),
                    status: "fail".to_string(),
                    label_zh: "分流规则匹配".to_string(),
                    label_en: "Route Match".to_string(),
                    detail_zh: format!("命中拦截规则 `{}` → REJECT", preview.matched_rule),
                    detail_en: format!("Matched `{}` → REJECT", preview.matched_rule),
                    latency_ms: None,
                },
                takeover_stage,
            ],
            waterfall: None,
        });
    }

    // Run waterfall probe through the entry group or concrete outbound resolved by the router
    let probe_entry = route_flow
        .first()
        .cloned()
        .unwrap_or_else(|| effective_outbound.clone());
    let wf = probe_target_waterfall(router, config, &probe_entry, &normalized_url, opts).await?;

    let mut stage_checks = Vec::with_capacity(6);
    stage_checks.push(SiteStageCheck {
        stage: "route".to_string(),
        status: if exit_type == "DIRECT" && mode_str == "direct" {
            "warn".to_string()
        } else {
            "ok".to_string()
        },
        label_zh: "分流规则匹配".to_string(),
        label_en: "Route Match".to_string(),
        detail_zh: route_summary_zh.clone(),
        detail_en: route_summary_en.clone(),
        latency_ms: None,
    });
    stage_checks.push(takeover_stage);

    // DNS stage
    if wf.failed_stage.as_deref() == Some("dns") {
        stage_checks.push(SiteStageCheck {
            stage: "dns".to_string(),
            status: "fail".to_string(),
            label_zh: "DNS 解析".to_string(),
            label_en: "DNS Resolution".to_string(),
            detail_zh: wf
                .error
                .clone()
                .unwrap_or_else(|| "DNS 解析失败".to_string()),
            detail_en: wf
                .error
                .clone()
                .unwrap_or_else(|| "DNS resolution failed".to_string()),
            latency_ms: wf.dns_resolve_ms,
        });
    } else {
        let dns_ms = wf.dns_resolve_ms.unwrap_or(0.0);
        let dns_detail_zh = if wf.remote_dns {
            format!("远端隧道无泄露解析（节点解析耗时 {dns_ms:.0} ms）")
        } else {
            format!("本地解析正常（{dns_ms:.0} ms）")
        };
        let dns_detail_en = if wf.remote_dns {
            format!("Remote tunnel DNS (bootstrap {dns_ms:.0} ms)")
        } else {
            format!("Local DNS resolved ({dns_ms:.0} ms)")
        };
        stage_checks.push(SiteStageCheck {
            stage: "dns".to_string(),
            status: "ok".to_string(),
            label_zh: "DNS 解析".to_string(),
            label_en: "DNS Resolution".to_string(),
            detail_zh: dns_detail_zh,
            detail_en: dns_detail_en,
            latency_ms: wf.dns_resolve_ms,
        });
    }

    // TCP / Tunnel stage
    if let Some(ms) = wf.tunnel_connect_ms {
        stage_checks.push(SiteStageCheck {
            stage: "tcp_tunnel".to_string(),
            status: "ok".to_string(),
            label_zh: if exit_type == "PROXY" {
                "代理节点 TCP 建连".to_string()
            } else {
                "本地直连 TCP 建连".to_string()
            },
            label_en: if exit_type == "PROXY" {
                "Proxy TCP Tunnel".to_string()
            } else {
                "Direct TCP Connect".to_string()
            },
            detail_zh: format!("建连成功（{} · {ms:.0} ms）", wf.effective_outbound),
            detail_en: format!("Connected via {} ({ms:.0} ms)", wf.effective_outbound),
            latency_ms: Some(ms),
        });
    } else if wf.failed_stage.as_deref() == Some("tunnel_connect") {
        stage_checks.push(SiteStageCheck {
            stage: "tcp_tunnel".to_string(),
            status: "fail".to_string(),
            label_zh: if exit_type == "PROXY" {
                "代理节点 TCP 建连".to_string()
            } else {
                "本地直连 TCP 建连".to_string()
            },
            label_en: if exit_type == "PROXY" {
                "Proxy TCP Tunnel".to_string()
            } else {
                "Direct TCP Connect".to_string()
            },
            detail_zh: wf
                .error
                .clone()
                .unwrap_or_else(|| "连接超时或被重置".to_string()),
            detail_en: wf
                .error
                .clone()
                .unwrap_or_else(|| "Connection timed out or reset".to_string()),
            latency_ms: None,
        });
    }

    // TLS stage (when HTTPS)
    if normalized_url.starts_with("https://") {
        if let Some(ms) = wf.tls_handshake_ms {
            let ver = wf.tls_version.as_deref().unwrap_or("TLS");
            stage_checks.push(SiteStageCheck {
                stage: "tls".to_string(),
                status: "ok".to_string(),
                label_zh: "TLS 安全握手".to_string(),
                label_en: "TLS Handshake".to_string(),
                detail_zh: format!("{ver} 握手成功（{ms:.0} ms）"),
                detail_en: format!("{ver} handshake succeeded ({ms:.0} ms)"),
                latency_ms: Some(ms),
            });
        } else if wf.failed_stage.as_deref() == Some("tls_handshake") {
            stage_checks.push(SiteStageCheck {
                stage: "tls".to_string(),
                status: "fail".to_string(),
                label_zh: "TLS 安全握手".to_string(),
                label_en: "TLS Handshake".to_string(),
                detail_zh: wf
                    .error
                    .clone()
                    .unwrap_or_else(|| "TLS 握手失败或被阻断".to_string()),
                detail_en: wf
                    .error
                    .clone()
                    .unwrap_or_else(|| "TLS handshake failed".to_string()),
                latency_ms: None,
            });
        }
    }

    // HTTP response stage
    if let Some(status) = wf.http_status {
        let http_stage_status = match wf.verdict {
            ProbeVerdict::Reachable | ProbeVerdict::AuthRequired => "ok",
            ProbeVerdict::RateLimited | ProbeVerdict::BlockedOrChallenged => "warn",
            ProbeVerdict::ServerError | ProbeVerdict::Unreachable => "fail",
        };
        let ms = wf.http_ttfb_ms.unwrap_or(0.0);
        stage_checks.push(SiteStageCheck {
            stage: "http".to_string(),
            status: http_stage_status.to_string(),
            label_zh: "网站 HTTP 响应".to_string(),
            label_en: "HTTP Response".to_string(),
            detail_zh: if wf.cf_mitigated {
                format!("HTTP {status}（触发 Cloudflare 盾/验证拦截 · {ms:.0} ms）")
            } else {
                format!("HTTP {status}（首字节 {ms:.0} ms）")
            },
            detail_en: if wf.cf_mitigated {
                format!("HTTP {status} (Cloudflare challenge · {ms:.0} ms)")
            } else {
                format!("HTTP {status} (TTFB {ms:.0} ms)")
            },
            latency_ms: wf.http_ttfb_ms,
        });
    } else if wf.failed_stage.as_deref() == Some("http_ttfb") {
        stage_checks.push(SiteStageCheck {
            stage: "http".to_string(),
            status: "fail".to_string(),
            label_zh: "网站 HTTP 响应".to_string(),
            label_en: "HTTP Response".to_string(),
            detail_zh: wf
                .error
                .clone()
                .unwrap_or_else(|| "等待网站响应超时或连接被关闭".to_string()),
            detail_en: wf
                .error
                .clone()
                .unwrap_or_else(|| "Timed out or closed before HTTP status".to_string()),
            latency_ms: None,
        });
    }

    if let Some(ref udp) = wf.udp_probe {
        let st = match udp.status.as_str() {
            "verified" => "ok",
            "blackholed" => "warn",
            _ => "skipped",
        };
        stage_checks.push(SiteStageCheck {
            stage: "udp".to_string(),
            status: st.to_string(),
            label_zh: "UDP / QUIC 转发".to_string(),
            label_en: "UDP / QUIC Relay".to_string(),
            detail_zh: match udp.status.as_str() {
                "verified" => format!("UDP 转发正常（{:.0} ms）", udp.rtt_ms.unwrap_or(0.0)),
                "blackholed" => {
                    "节点声明支持 UDP 但实测丢包（可能影响浏览器 HTTP/3 QUIC）".to_string()
                }
                _ => "当前出口未开启 UDP 转发（仅走 TCP）".to_string(),
            },
            detail_en: udp.detail.clone(),
            latency_ms: udp.rtt_ms,
        });
    }

    // Derive human-friendly diagnosis & actions
    let udp_blackholed = wf
        .udp_probe
        .as_ref()
        .is_some_and(|u| u.status == "blackholed");

    let (
        diagnosis_code,
        severity,
        headline_zh,
        headline_en,
        summary_zh,
        summary_en,
        mut actions_zh,
        mut actions_en,
        suggested_action_kind,
    ) = match wf.verdict {
        ProbeVerdict::Reachable | ProbeVerdict::AuthRequired => {
            if exit_type == "PROXY" && (!takeover.core_running || !takeover_active) {
                (
                    "reachable_takeover_off".to_string(),
                    "warning".to_string(),
                    "代理节点本身可连通该网站，但系统流量接管尚未开启".to_string(),
                    "Proxy node reaches this site, but System Proxy / VPN is currently OFF"
                        .to_string(),
                    format!(
                        "通过出口 `{}` 访问 `{}` 实测连通（总耗时 {:.0} ms），说明节点与分流规则均正常；但当前未开启「系统代理」或「TUN / VPN 接管」，浏览器请求没有经过 RustClash。",
                        wf.effective_outbound, host_str, wf.total_ms
                    ),
                    format!(
                        "Probing `{}` via `{}` succeeded in {:.0} ms, confirming your node and routing rules work — however System Proxy / VPN takeover is off, so browser traffic bypasses RustClash.",
                        host_str, wf.effective_outbound, wf.total_ms
                    ),
                    vec![
                        "返回首页打开主连接开关（启用系统代理或 TUN / VPN 接管），然后再刷新网页。".to_string(),
                        "如果浏览器安装了独立代理扩展（如 SwitchyOmega），请确认它指向本地混合端口或切换为系统代理。".to_string(),
                    ],
                    vec![
                        "Turn on the main connection toggle on the Dashboard (System Proxy or TUN / VPN) and reload the site.".to_string(),
                        "Check browser proxy extensions (e.g. SwitchyOmega) to ensure they use System Proxy or the local Mixed Port.".to_string(),
                    ],
                    Some("enable_takeover".to_string()),
                )
            } else {
                (
                    "reachable".to_string(),
                    "ok".to_string(),
                    format!(
                        "分流与网络连通正常（{:.0} ms）",
                        wf.total_ms
                    ),
                    format!(
                        "Routing and connectivity verified ({:.0} ms)",
                        wf.total_ms
                    ),
                    format!(
                        "DNS、{}与 TLS/HTTP 握手均已通过（出口 `{}`，总耗时 {:.0} ms）。",
                        if exit_type == "PROXY" { "代理隧道" } else { "本地直连" },
                        wf.effective_outbound,
                        wf.total_ms
                    ),
                    format!(
                        "DNS, {} connect, and TLS/HTTP succeeded via `{}` in {:.0} ms.",
                        if exit_type == "PROXY" { "proxy tunnel" } else { "direct" },
                        wf.effective_outbound,
                        wf.total_ms
                    ),
                    vec![
                        "如果浏览器仍打不开，请无痕窗口重试，或检查浏览器是否安装了冲突的代理插件 / 安全 DNS 设置。".to_string(),
                    ],
                    vec![
                        "If your browser still fails, retry in a private window or check conflicting browser proxy / DoH extensions.".to_string(),
                    ],
                    None,
                )
            }
        }
        ProbeVerdict::BlockedOrChallenged => (
            "blocked_or_challenged".to_string(),
            "warning".to_string(),
            "网络隧道已连通，但当前节点出口 IP 被目标网站限制或盾拦截".to_string(),
            "Tunnel connected, but exit IP is geo-restricted or WAF-challenged".to_string(),
            format!(
                "节点 `{}` 的 DNS、TCP 与 TLS 握手均正常，但 `{}` 返回了 HTTP {}（地区风控或 Cloudflare 机房 IP 验证），并非本地断网。",
                wf.effective_outbound,
                host_str,
                wf.http_status.unwrap_or(403)
            ),
            format!(
                "DNS, TCP, and TLS succeeded via `{}`, but `{}` returned HTTP {} (geo-restriction or WAF challenge on this exit IP).",
                wf.effective_outbound,
                host_str,
                wf.http_status.unwrap_or(403)
            ),
            vec![
                "切换到支持该服务的地区节点（如日本、新加坡、美国等纯净度更高的节点）后重新检测。".to_string(),
                "若所有节点均触发 403，说明订阅商共享出口 IP 段被目标站点风控。".to_string(),
            ],
            vec![
                "Switch to a proxy node in a supported region with a cleaner exit IP (e.g. JP, SG, US) and re-test.".to_string(),
                "If multiple nodes return 403, the provider's shared datacenter subnet may be flagged by the site.".to_string(),
            ],
            Some("switch_node".to_string()),
        ),
        ProbeVerdict::RateLimited => (
            "rate_limited".to_string(),
            "warning".to_string(),
            "节点连通正常，但共享出口 IP 触发了目标网站限流 (HTTP 429)".to_string(),
            "Tunnel healthy, but shared exit IP is rate-limited (HTTP 429)".to_string(),
            format!(
                "已成功建立到 `{}` 的加密连接，但节点 `{}` 的出口 IP 当前请求过于频繁，被返回 HTTP 429。",
                host_str, wf.effective_outbound
            ),
            format!(
                "TLS reached `{}` via `{}`, but the shared exit IP received HTTP 429 Too Many Requests.",
                host_str, wf.effective_outbound
            ),
            vec![
                "切换到负载较低的其他代理节点，然后重新检测。".to_string(),
            ],
            vec![
                "Switch to a less crowded proxy node and retry.".to_string(),
            ],
            Some("switch_node".to_string()),
        ),
        ProbeVerdict::ServerError => (
            "server_error".to_string(),
            "warning".to_string(),
            format!(
                "代理链路正常，但目标网站自身返回服务端错误 (HTTP {})",
                wf.http_status.unwrap_or(502)
            ),
            format!(
                "Tunnel healthy, but upstream website returned HTTP {}",
                wf.http_status.unwrap_or(502)
            ),
            format!(
                "通过 `{}` 已成功握手到达 `{}`，故障位于目标网站上游服务器（HTTP 5xx），通常不是代理配置问题。",
                wf.effective_outbound, host_str
            ),
            format!(
                "Reached `{}` over TLS via `{}`, but the origin server returned HTTP 5xx.",
                host_str, wf.effective_outbound
            ),
            vec![
                "稍后重试，或切换另一个地区的节点排除 CDN 边缘节点故障。".to_string(),
            ],
            vec![
                "Retry shortly, or switch regions in case a specific CDN edge is degraded.".to_string(),
            ],
            None,
        ),
        ProbeVerdict::Unreachable => {
            if proxy_node_count == 0 {
                (
                    "no_proxy_nodes".to_string(),
                    "error".to_string(),
                    "尚未导入任何代理节点，流量只能走本地直连".to_string(),
                    "No proxy nodes imported — traffic can only use local DIRECT".to_string(),
                    format!(
                        "当前配置中没有可用代理节点（节点数为 0），访问 `{}` 只能尝试本地直连 (`DIRECT`) 并连接失败。",
                        host_str
                    ),
                    format!(
                        "Zero proxy nodes are configured; `{}` fell back to local DIRECT and failed to connect.",
                        host_str
                    ),
                    vec![
                        "前往「配置 / 订阅」页面导入有效的订阅链接、节点分享链接或 YAML 配置。".to_string(),
                    ],
                    vec![
                        "Import a subscription URL, share links, or Clash YAML under Profiles.".to_string(),
                    ],
                    Some("import_profile".to_string()),
                )
            } else if exit_type == "DIRECT" {
                let is_direct_mode = mode_str == "direct";
                (
                    "direct_unreachable".to_string(),
                    "error".to_string(),
                    if is_direct_mode {
                        "当前处于「全局直连」模式，未走代理且本地直连失败".to_string()
                    } else {
                        "分流规则判定为本地直连 (DIRECT)，但本地网络无法连接该网站".to_string()
                    },
                    if is_direct_mode {
                        "Global Direct mode is active — site bypassed proxy and failed locally"
                            .to_string()
                    } else {
                        "Routed to DIRECT by rule, and local network cannot reach this site"
                            .to_string()
                    },
                    if is_direct_mode {
                        format!(
                            "当前路由模式为「全局直连 (Direct)」，访问 `{}` 不会经过任何代理节点，本地网络在 `{}` 阶段连接失败。",
                            host_str,
                            wf.failed_stage.as_deref().unwrap_or("tunnel_connect")
                        )
                    } else {
                        format!(
                            "规则 `{}` 将 `{}` 分流到了本地直连 (`DIRECT`)，而本地网络无法直接访问该网站。",
                            preview.matched_rule, host_str
                        )
                    },
                    if is_direct_mode {
                        format!(
                            "Routing mode is set to Direct, so `{}` bypassed all proxy nodes and failed on your local network.",
                            host_str
                        )
                    } else {
                        format!(
                            "Rule `{}` sent `{}` to DIRECT, which could not reach the target from your local network.",
                            preview.matched_rule, host_str
                        )
                    },
                    if is_direct_mode {
                        vec![
                            "将路由模式切换回「智能分流 (Rule)」或「全局代理 (Global)」，然后重新检测。".to_string(),
                        ]
                    } else {
                        vec![
                            format!("在「自定义规则」中添加 `DOMAIN-SUFFIX,{host_str},🚀 Proxy`，让该网站走代理节点。"),
                            "或临时切换为「全局代理 (Global)」模式确认代理节点是否可正常打开该网站。".to_string(),
                        ]
                    },
                    if is_direct_mode {
                        vec![
                            "Switch routing mode to Rule or Global and test again.".to_string(),
                        ]
                    } else {
                        vec![
                            format!("Add `DOMAIN-SUFFIX,{host_str},🚀 Proxy` in Custom Rules so this site uses your proxy."),
                            "Or switch temporarily to Global mode to verify reachability via proxy.".to_string(),
                        ]
                    },
                    Some(if is_direct_mode {
                        "switch_mode_rule".to_string()
                    } else {
                        "check_rules".to_string()
                    }),
                )
            } else {
                match wf.failed_stage.as_deref() {
                    Some("dns") => (
                        "dns_failed".to_string(),
                        "error".to_string(),
                        "无法解析代理节点服务器域名 (DNS 失败)".to_string(),
                        "DNS failed while resolving the proxy server address".to_string(),
                        format!(
                            "在连接节点 `{}` 之前，本地上游 DNS 无法解析该节点服务器的域名（{}）。",
                            wf.effective_outbound,
                            wf.error.as_deref().unwrap_or("DNS 错误")
                        ),
                        format!(
                            "Local bootstrap DNS could not resolve the server hostname for proxy node `{}` ({}).",
                            wf.effective_outbound,
                            wf.error.as_deref().unwrap_or("DNS error")
                        ),
                        vec![
                            "切换其他节点测试（当前节点域名可能已失效或被本地运营商 DNS 污染）。".to_string(),
                            "检查本地网络连接，或在「工具 → DNS」中清空 DNS 缓存后重试。".to_string(),
                        ],
                        vec![
                            "Switch to another node (this node's hostname may have expired or been poisoned).".to_string(),
                            "Check local internet access or flush the DNS cache under Tools.".to_string(),
                        ],
                        Some("switch_node".to_string()),
                    ),
                    Some("tls_handshake") => (
                        "tls_handshake_failed".to_string(),
                        "error".to_string(),
                        "DNS 与代理 TCP 建连正常，但目标网站 TLS 握手失败".to_string(),
                        "DNS and proxy TCP connected, but TLS handshake failed".to_string(),
                        format!(
                            "节点 `{}` 已完成 TCP 隧道建连（{:.0} ms），但在与 `{}` 进行 TLS 加密握手时失败或被重置（{}）。",
                            wf.effective_outbound,
                            wf.tunnel_connect_ms.unwrap_or(0.0),
                            host_str,
                            wf.error.as_deref().unwrap_or("TLS 握手中断")
                        ),
                        format!(
                            "Proxy tunnel `{}` connected in {:.0} ms, but the end-to-end TLS handshake with `{}` failed ({}).",
                            wf.effective_outbound,
                            wf.tunnel_connect_ms.unwrap_or(0.0),
                            host_str,
                            wf.error.as_deref().unwrap_or("TLS error")
                        ),
                        vec![
                            "优先尝试切换到另一个代理节点，然后重新检测（常见于节点远端出口阻断或伪装配置异常）。".to_string(),
                            "确认设备系统时间是否准确（时间偏差过大会导致 TLS 证书校验失败）。".to_string(),
                        ],
                        vec![
                            "Switch to another proxy node and re-test (often caused by upstream egress interference or node misconfiguration).".to_string(),
                            "Verify your device clock is accurate so TLS certificate validation succeeds.".to_string(),
                        ],
                        Some("switch_node".to_string()),
                    ),
                    Some("http_ttfb") => (
                        "http_failed".to_string(),
                        "error".to_string(),
                        "TLS 握手已完成，但等待网站首字节响应超时或中断".to_string(),
                        "TLS succeeded, but HTTP response timed out or closed early".to_string(),
                        format!(
                            "节点 `{}` 已建立加密连接，但 `{}` 迟迟未返回 HTTP 数据或中途断开（{}）。",
                            wf.effective_outbound,
                            host_str,
                            wf.error.as_deref().unwrap_or("读取响应失败")
                        ),
                        format!(
                            "TLS handshake via `{}` completed, but reading the HTTP response from `{}` failed ({}).",
                            wf.effective_outbound,
                            host_str,
                            wf.error.as_deref().unwrap_or("HTTP read error")
                        ),
                        vec![
                            "尝试切换更稳定的代理节点后重新检测。".to_string(),
                            "若使用 TUN 模式，可检查 MTU 设置是否过大导致大包分片丢包。".to_string(),
                        ],
                        vec![
                            "Switch to a lower-loss proxy node and re-test.".to_string(),
                            "If using TUN mode, check whether MTU issues are dropping larger packets.".to_string(),
                        ],
                        Some("switch_node".to_string()),
                    ),
                    _ => (
                        "node_tunnel_failed".to_string(),
                        "error".to_string(),
                        format!("代理节点 `{}` 无法建立连接（超时或不可达）", wf.effective_outbound),
                        format!("Proxy node `{}` failed to connect", wf.effective_outbound),
                        format!(
                            "分流规则已正确将 `{}` 指向代理节点 `{}`（{}），但与该节点的隧道建连失败（{}）。",
                            host_str,
                            wf.effective_outbound,
                            wf.protocol,
                            wf.error.as_deref().unwrap_or("连接超时")
                        ),
                        format!(
                            "Routing sent `{}` to `{}` ({}), but establishing the proxy tunnel failed ({}).",
                            host_str,
                            wf.effective_outbound,
                            wf.protocol,
                            wf.error.as_deref().unwrap_or("timeout")
                        ),
                        vec![
                            "切换到其他延迟正常的代理节点，然后重新检测。".to_string(),
                            "前往「配置」页面更新订阅，获取最新节点地址与端口。".to_string(),
                        ],
                        vec![
                            "Switch to another responsive proxy node and re-test.".to_string(),
                            "Refresh your subscription under Profiles in case node endpoints changed.".to_string(),
                        ],
                        Some("switch_node".to_string()),
                    ),
                }
            }
        }
    };

    if udp_blackholed
        && matches!(
            diagnosis_code.as_str(),
            "reachable" | "reachable_takeover_off"
        )
    {
        actions_zh.push(
            "注意：该节点声明支持 UDP 但实测 UDP 丢包；若在 TUN 模式下浏览器开启 HTTP/3 (QUIC) 出现偶发卡顿，可换用 UDP 正常的节点或在浏览器关闭 QUIC。".to_string(),
        );
        actions_en.push(
            "Note: This node drops UDP packets despite `udp: true`; if HTTP/3 (QUIC) stalls in TUN mode, switch nodes or disable QUIC in your browser.".to_string(),
        );
    }

    Ok(SiteDiagnosisReport {
        input: raw_input.trim().to_string(),
        normalized_url,
        target_host: host_str,
        target_port: port,
        checked_at_ms,
        mode: mode_str,
        matched_rule: preview.matched_rule,
        rule_type,
        rule_payload,
        route_flow,
        chains,
        effective_outbound,
        protocol,
        exit_type,
        proxy_node_count,
        takeover,
        diagnosis_code,
        severity,
        headline_zh,
        headline_en,
        summary_zh,
        summary_en,
        route_summary_zh,
        route_summary_en,
        actions_zh,
        actions_en,
        suggested_action_kind,
        stage_checks,
        waterfall: Some(wf),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use tokio::net::{TcpListener, TcpStream, UdpSocket};
    use tokio_rustls::TlsAcceptor;

    use crate::{
        config::{DnsConfig, RunMode},
        crypto::tls::generate_self_signed_server_config,
        dns::FakeIpDnsEngine,
        engine::build_outbounds_with_dns,
    };

    #[tokio::test]
    async fn waterfall_probe_measures_tls_ttfb_udp_and_detects_403_geo_block() {
        // 1. Spawn local self-signed HTTPS origin serving `/v1/models` -> 401 (API reachable)
        //    and `/blocked` -> 403 with `cf-mitigated: challenge` (geo/WAF blocked)
        let (srv_tls, ca_der) = generate_self_signed_server_config(
            &["localhost".to_string(), "127.0.0.1".to_string()],
            &[b"http/1.1".to_vec()],
        )
        .unwrap();
        let acceptor = TlsAcceptor::from(srv_tls);
        let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let https_addr = tcp_listener.local_addr().unwrap();

        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = tcp_listener.accept().await else {
                    break;
                };
                let acc = acceptor.clone();
                tokio::spawn(async move {
                    let Ok(mut tls) = acc.accept(stream).await else {
                        return;
                    };
                    let mut req = [0u8; 1024];
                    let Ok(n) = tls.read(&mut req).await else {
                        return;
                    };
                    let text = String::from_utf8_lossy(&req[..n]);
                    let resp = if text.starts_with("GET /blocked ") {
                        "HTTP/1.1 403 Forbidden\r\nServer: cloudflare\r\ncf-mitigated: challenge\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    } else {
                        "HTTP/1.1 401 Unauthorized\r\nServer: api-gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    };
                    let _ = tls.write_all(resp.as_bytes()).await;
                    let _ = tls.shutdown().await;
                });
            }
        });

        // 2. Spawn minimal local UDP DNS echo responder echoing transaction ID
        let udp_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_addr = udp_sock.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            while let Ok((n, peer)) = udp_sock.recv_from(&mut buf).await {
                if n >= 12 {
                    let mut reply = buf[..n].to_vec();
                    reply[2] = 0x81;
                    reply[3] = 0x80;
                    let _ = udp_sock.send_to(&reply, peer).await;
                }
            }
        });

        let cfg = ClashConfig::default();
        let dns = Arc::new(FakeIpDnsEngine::new(&DnsConfig::default()).unwrap());
        let router = Router::new(RunMode::Rule, HashMap::new(), &[], &cfg.rules, dns).unwrap();
        let ca_slice = [ca_der];
        let udp_target_str = udp_addr.to_string();

        // Probe unblocked API endpoint (`401` -> AuthRequired + TLSv1.3 + UDP verified!)
        let ok_url = format!("https://localhost:{}/v1/models", https_addr.port());
        let ok_rep = probe_target_waterfall(
            &router,
            &cfg,
            "DIRECT",
            &ok_url,
            ProbeOptions {
                extra_ca_der: &ca_slice,
                check_udp: true,
                udp_dns_target: Some(&udp_target_str),
                timeout: Duration::from_secs(3),
                allow_private_targets: true,
                allowed_private_addrs: &[],
            },
        )
        .await
        .unwrap();

        assert_eq!(ok_rep.verdict, ProbeVerdict::AuthRequired);
        assert!(ok_rep.verdict.is_egress_unblocked());
        assert_eq!(ok_rep.http_status, Some(401));
        assert_eq!(ok_rep.tls_version.as_deref(), Some("TLSv1.3"));
        assert!(ok_rep.tunnel_connect_ms.is_some());
        assert!(ok_rep.tls_handshake_ms.is_some());
        assert!(ok_rep.http_ttfb_ms.is_some());
        assert_eq!(
            ok_rep.udp_probe.as_ref().map(|u| u.status.as_str()),
            Some("verified")
        );

        // Probe WAF/Geo-blocked endpoint (`403` + `cf-mitigated: challenge` -> BlockedOrChallenged)
        let blocked_url = format!("https://localhost:{}/blocked", https_addr.port());
        let blocked_rep = probe_target_waterfall(
            &router,
            &cfg,
            "DIRECT",
            &blocked_url,
            ProbeOptions {
                extra_ca_der: &ca_slice,
                check_udp: false,
                udp_dns_target: None,
                timeout: Duration::from_secs(3),
                allow_private_targets: true,
                allowed_private_addrs: &[],
            },
        )
        .await
        .unwrap();

        assert_eq!(blocked_rep.verdict, ProbeVerdict::BlockedOrChallenged);
        assert_eq!(blocked_rep.http_status, Some(403));
        assert!(blocked_rep.cf_mitigated);
    }

    #[tokio::test]
    async fn slow_udp_probe_does_not_inflate_tcp_total_ms_and_429_is_not_ai_unblocked() {
        let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let http_addr = tcp_listener.local_addr().unwrap();

        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = tcp_listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut req = [0u8; 1024];
                    let Ok(n) = stream.read(&mut req).await else {
                        return;
                    };
                    let text = String::from_utf8_lossy(&req[..n]);
                    let resp = if text.starts_with("GET /ratelimited ") {
                        "HTTP/1.1 429 Too Many Requests\r\nServer: openai-edge\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    } else {
                        "HTTP/1.1 204 No Content\r\nServer: fast-origin\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    };
                    let _ = stream.write_all(resp.as_bytes()).await;
                    let _ = stream.shutdown().await;
                });
            }
        });

        // Bind a UDP socket that never replies so UDP relay probe hits full timeout (~250ms).
        let _blackhole_udp_guard = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let blackhole_udp_addr = _blackhole_udp_guard.local_addr().unwrap().to_string();

        let cfg = ClashConfig::default();
        let dns = Arc::new(FakeIpDnsEngine::new(&DnsConfig::default()).unwrap());
        let router = Router::new(RunMode::Rule, HashMap::new(), &[], &cfg.rules, dns).unwrap();

        let fast_url = format!("http://{http_addr}/fast");
        let rep = probe_target_waterfall(
            &router,
            &cfg,
            "DIRECT",
            &fast_url,
            ProbeOptions {
                extra_ca_der: &[],
                check_udp: true,
                udp_dns_target: Some(&blackhole_udp_addr),
                timeout: Duration::from_millis(600),
                allow_private_targets: true,
                allowed_private_addrs: &[],
            },
        )
        .await
        .unwrap();

        assert_eq!(rep.verdict, ProbeVerdict::Reachable);
        assert_eq!(
            rep.udp_probe.as_ref().map(|u| u.status.as_str()),
            Some("blackholed")
        );
        assert!(
            rep.overall_probe_duration_ms >= 500.0,
            "overall elapsed should reflect parallel UDP timeout: {}",
            rep.overall_probe_duration_ms
        );
        assert!(
            rep.total_ms < 450.0,
            "TCP waterfall total_ms ({}) must not be polluted by slow UDP timeout ({})",
            rep.total_ms,
            rep.overall_probe_duration_ms
        );
        assert!(
            router.delays().latest_delay("DIRECT").unwrap_or(999) < 450,
            "recorded node delay must reflect TCP waterfall only"
        );

        // Verify HTTP 429 on an AI endpoint produces RateLimited and ai_egress_unblocked == false
        let matrix = probe_endpoint_matrix(
            &router,
            &cfg,
            "DIRECT",
            vec![MatrixEndpointSpec {
                id: "openai-api".to_string(),
                label: "OpenAI API".to_string(),
                category: "ai".to_string(),
                url: format!("http://{http_addr}/ratelimited"),
            }],
            ProbeOptions {
                extra_ca_der: &[],
                check_udp: false,
                udp_dns_target: None,
                timeout: Duration::from_secs(2),
                allow_private_targets: true,
                allowed_private_addrs: &[],
            },
        )
        .await
        .unwrap();

        assert_eq!(matrix.rate_limited_count, 1);
        assert_eq!(matrix.items[0].report.verdict, ProbeVerdict::RateLimited);
        assert!(!matrix.ai_egress_unblocked);
        assert!(matrix.ai_status_note.contains("429"));
    }

    #[tokio::test]
    async fn ssrf_guard_blocks_private_loopback_and_metadata_targets_by_default() {
        let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let demo_addr = tcp_listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = tcp_listener.accept().await {
                let mut buf = [0u8; 256];
                let _ = stream.read(&mut buf).await;
                let _ = stream
                    .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    .await;
            }
        });

        let cfg = ClashConfig::default();
        let dns = Arc::new(FakeIpDnsEngine::new(&DnsConfig::default()).unwrap());
        let router = Router::new(RunMode::Rule, HashMap::new(), &[], &cfg.rules, dns).unwrap();

        let blocked_targets = [
            "http://127.0.0.1:8080/admin",
            "http://localhost:8080/",
            "http://[::1]:8080/",
            "http://192.168.1.1/",
            "http://10.0.0.1/",
            "http://172.16.0.1/",
            "http://100.64.0.1/",
            "http://198.18.0.1/",
            "http://169.254.169.254/latest/meta-data/",
            "http://[::ffff:169.254.169.254]/latest/meta-data/",
            "http://[fd00:ec2::254]/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://printer.local/",
        ];

        for bad_url in blocked_targets {
            let err =
                probe_target_waterfall(&router, &cfg, "DIRECT", bad_url, ProbeOptions::default())
                    .await
                    .expect_err(&format!("expected SSRF guard to block {bad_url}"));
            assert!(
                err.to_string().contains("blocked by SSRF protection"),
                "unexpected error for {bad_url}: {err}"
            );
        }

        // Exact sandbox port allowlist permits `--demo` origin without opening arbitrary localhost ports
        let allow_slice = [demo_addr];
        let allowed_demo = probe_target_waterfall(
            &router,
            &cfg,
            "DIRECT",
            &format!("http://{demo_addr}/generate_204"),
            ProbeOptions {
                allowed_private_addrs: &allow_slice,
                ..ProbeOptions::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(allowed_demo.verdict, ProbeVerdict::Reachable);

        let other_port = demo_addr.port().wrapping_add(1);
        let other_err = probe_target_waterfall(
            &router,
            &cfg,
            "DIRECT",
            &format!("http://127.0.0.1:{other_port}/"),
            ProbeOptions {
                allowed_private_addrs: &allow_slice,
                ..ProbeOptions::default()
            },
        )
        .await
        .expect_err("non-demo loopback port must still be blocked");
        assert!(other_err.to_string().contains("blocked by SSRF protection"));
    }

    #[test]
    fn normalize_site_check_input_handles_bare_domains_ports_and_urls() {
        let (url1, t1) = normalize_site_check_input("chatgpt.com").unwrap();
        assert_eq!(url1, "https://chatgpt.com/");
        assert_eq!(t1.to_string(), "chatgpt.com:443");

        let (url2, t2) = normalize_site_check_input("  https://claude.ai/chats?x=1 ").unwrap();
        assert_eq!(url2, "https://claude.ai/chats");
        assert_eq!(t2.to_string(), "claude.ai:443");

        let (url3, t3) = normalize_site_check_input("neverssl.com:80").unwrap();
        assert_eq!(url3, "http://neverssl.com/");
        assert_eq!(t3.to_string(), "neverssl.com:80");

        assert!(normalize_site_check_input("   ").is_err());
    }

    #[tokio::test]
    async fn diagnose_site_classifies_reject_takeover_off_403_and_no_proxy_nodes() {
        // Spawn local HTTP test server
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    let Ok(n) = stream.read(&mut buf).await else {
                        return;
                    };
                    let req = String::from_utf8_lossy(&buf[..n]);
                    let resp = if req.starts_with("GET /geo ") {
                        "HTTP/1.1 403 Forbidden\r\ncf-mitigated: challenge\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    } else {
                        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
                    };
                    let _ = stream.write_all(resp.as_bytes()).await;
                    let _ = stream.shutdown().await;
                });
            }
        });

        // 1. Rule REJECT should short-circuit without network packets
        let reject_cfg = ClashConfig {
            rules: vec![
                "DOMAIN-SUFFIX,ads.example.com,REJECT".to_string(),
                "MATCH,DIRECT".to_string(),
            ],
            ..ClashConfig::default()
        };
        let dns = Arc::new(FakeIpDnsEngine::new(&DnsConfig::default()).unwrap());
        let reject_router =
            Router::new(RunMode::Rule, HashMap::new(), &[], &reject_cfg.rules, dns).unwrap();
        let rej_rep = diagnose_site(
            &reject_router,
            &reject_cfg,
            "ads.example.com",
            SiteTakeoverContext {
                core_running: true,
                sysproxy_enabled: true,
                tun_enabled: false,
                platform_hint: "desktop".to_string(),
            },
            ProbeOptions::default(),
        )
        .await
        .unwrap();
        assert_eq!(rej_rep.diagnosis_code, "rule_rejected");
        assert_eq!(rej_rep.exit_type, "REJECT");
        assert!(rej_rep.waterfall.is_none());

        // 2. Zero proxy nodes + unreachable target -> `no_proxy_nodes`
        let closed_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let closed_port = closed_listener.local_addr().unwrap().port();
        drop(closed_listener);

        let no_nodes_rep = diagnose_site(
            &reject_router,
            &reject_cfg,
            &format!("http://127.0.0.1:{closed_port}/"),
            SiteTakeoverContext {
                core_running: true,
                sysproxy_enabled: true,
                tun_enabled: false,
                platform_hint: "desktop".to_string(),
            },
            ProbeOptions {
                allow_private_targets: true,
                timeout: Duration::from_millis(500),
                ..ProbeOptions::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(no_nodes_rep.diagnosis_code, "no_proxy_nodes");
        assert_eq!(
            no_nodes_rep.suggested_action_kind.as_deref(),
            Some("import_profile")
        );

        // 3. Spawn a tiny HTTP CONNECT proxy so we can test real PROXY exit (`reachable_takeover_off` + `blocked_or_challenged`)
        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut client, _)) = proxy_listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    let Ok(n) = client.read(&mut buf).await else {
                        return;
                    };
                    let head = String::from_utf8_lossy(&buf[..n]);
                    let Some(first) = head.lines().next() else {
                        return;
                    };
                    let Some(target_authority) = first.split_whitespace().nth(1) else {
                        return;
                    };
                    let Ok(mut upstream) = TcpStream::connect(target_authority).await else {
                        return;
                    };
                    let _ = client
                        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                        .await;
                    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
                });
            }
        });

        let proxy_cfg = ClashConfig::from_yaml_str(&format!(
            "mode: rule\nproxies:\n  - name: Test-HTTP-Node\n    type: http\n    server: 127.0.0.1\n    port: {}\nproxy-groups:\n  - name: \"🚀 Proxy\"\n    type: select\n    proxies:\n      - Test-HTTP-Node\nrules:\n  - MATCH,🚀 Proxy\n",
            proxy_addr.port()
        ))
        .unwrap();
        let dns2 = Arc::new(FakeIpDnsEngine::new(&DnsConfig::default()).unwrap());
        let outbounds =
            build_outbounds_with_dns(&proxy_cfg.proxies, &[], Some(Arc::clone(&dns2))).unwrap();
        let proxy_router = Router::new(
            RunMode::Rule,
            outbounds,
            &proxy_cfg.proxy_groups,
            &proxy_cfg.rules,
            dns2,
        )
        .unwrap();

        // Takeover OFF -> warns user that System Proxy / TUN is off!
        let takeover_off_rep = diagnose_site(
            &proxy_router,
            &proxy_cfg,
            &format!("http://{addr}/ok"),
            SiteTakeoverContext {
                core_running: true,
                sysproxy_enabled: false,
                tun_enabled: false,
                platform_hint: "desktop".to_string(),
            },
            ProbeOptions {
                allow_private_targets: true,
                timeout: Duration::from_secs(2),
                ..ProbeOptions::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(takeover_off_rep.diagnosis_code, "reachable_takeover_off");
        assert_eq!(takeover_off_rep.severity, "warning");
        assert_eq!(
            takeover_off_rep.suggested_action_kind.as_deref(),
            Some("enable_takeover")
        );

        // Takeover ON -> `reachable` (`ok`)
        let takeover_on_rep = diagnose_site(
            &proxy_router,
            &proxy_cfg,
            &format!("http://{addr}/ok"),
            SiteTakeoverContext {
                core_running: true,
                sysproxy_enabled: true,
                tun_enabled: false,
                platform_hint: "desktop".to_string(),
            },
            ProbeOptions {
                allow_private_targets: true,
                timeout: Duration::from_secs(2),
                ..ProbeOptions::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(takeover_on_rep.diagnosis_code, "reachable");
        assert_eq!(takeover_on_rep.severity, "ok");

        // HTTP 403 challenge -> `blocked_or_challenged`
        let geo_rep = diagnose_site(
            &proxy_router,
            &proxy_cfg,
            &format!("http://{addr}/geo"),
            SiteTakeoverContext {
                core_running: true,
                sysproxy_enabled: true,
                tun_enabled: false,
                platform_hint: "desktop".to_string(),
            },
            ProbeOptions {
                allow_private_targets: true,
                timeout: Duration::from_secs(2),
                ..ProbeOptions::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(geo_rep.diagnosis_code, "blocked_or_challenged");
        assert_eq!(
            geo_rep.suggested_action_kind.as_deref(),
            Some("switch_node")
        );
    }
}

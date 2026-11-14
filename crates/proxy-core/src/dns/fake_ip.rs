use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    num::NonZeroUsize,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use bytes::{BufMut, BytesMut};
use dashmap::{DashMap, mapref::entry::Entry};
use ipnet::Ipv4Net;
use lru::LruCache;
use parking_lot::Mutex;
use rustls::pki_types::CertificateDer;
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{Semaphore, watch},
    task::JoinHandle,
};

use crate::{
    addr::{HostName, TargetAddr},
    config::DnsConfig,
    dns::{
        upstream::{BootstrapDnsServer, DnsEndpointHost, DnsUpstream, clear_dns_upstream_pools},
        wire::{
            DnsAnswerData, DnsQueryPacket, QTYPE_A, QTYPE_AAAA, QTYPE_HTTPS, QTYPE_PTR, QTYPE_SVCB,
            build_dns_query, extract_dns_response_meta, extract_ip_answers,
        },
    },
    error::{ProxyError, Result},
};

const MIN_POSITIVE_TTL_SECS: u64 = 5;
const MAX_POSITIVE_TTL_SECS: u64 = 3600;
const MIN_NEGATIVE_TTL_SECS: u64 = 5;
const MAX_NEGATIVE_TTL_SECS: u64 = 60;
const MAX_CONCURRENT_DNS_UDP_TASKS: usize = 256;
const MAX_CONCURRENT_DNS_TCP_CONNS: usize = 128;
const MAX_PERSISTED_FAKE_IP_ENTRIES: usize = 2048;
const MAX_FAKE_IP_PERSIST_AGE_MS: u64 = 7 * 24 * 60 * 60 * 1000;

struct InflightLookupGuard<'a> {
    map: &'a DashMap<String, watch::Sender<bool>>,
    key: String,
    tx: watch::Sender<bool>,
}

impl Drop for InflightLookupGuard<'_> {
    fn drop(&mut self) {
        self.map.remove(&self.key);
        let _ = self.tx.send(true);
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FakeIpEntry {
    pub ip: String,
    pub domain: String,
}

#[derive(Serialize, Deserialize)]
struct PersistedFakeIpState {
    version: u32,
    fake_ip_range: String,
    saved_at_epoch_ms: u64,
    entries: Vec<FakeIpEntry>,
}

fn current_epoch_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
pub struct DnsTelemetrySnapshot {
    pub total_queries: u64,
    pub fake_ip_hits: u64,
    pub cache_hits: u64,
    #[serde(default)]
    pub suppressed_queries: u64,
    #[serde(default)]
    pub nxdomain_hits: u64,
    pub upstream_queries: u64,
    pub upstream_errors: u64,
    pub upstream_avg_ms: u64,
    pub upstream_max_ms: u64,
    pub active_fake_ip_entries: usize,
}

#[derive(Clone, Debug, Default)]
pub struct PositiveDnsCacheSeed {
    pub(crate) proxy_entries: Vec<(String, Instant, Vec<IpAddr>)>,
    pub(crate) bootstrap_entries: Vec<(String, Instant, Vec<IpAddr>)>,
}

impl PositiveDnsCacheSeed {
    pub fn is_empty(&self) -> bool {
        self.proxy_entries.is_empty() && self.bootstrap_entries.is_empty()
    }
}

#[derive(Clone, Debug)]
enum CachedIpResolution {
    Positive {
        expires_at: Instant,
        ips: Vec<IpAddr>,
    },
    Negative {
        expires_at: Instant,
        nxdomain: bool,
    },
}

#[derive(Clone, Debug)]
struct CachedWirePacket {
    expires_at: Instant,
    wire: Vec<u8>,
}

struct PoolInner {
    ip_to_domain: LruCache<Ipv4Addr, String>,
    domain_to_ip: HashMap<String, Ipv4Addr>,
    cursor: u32,
    start_host: u32,
    end_host: u32,
}

impl PoolInner {
    fn new(net: Ipv4Net, capacity: usize) -> Self {
        let net_u32 = u32::from(net.network());
        let bcast_u32 = u32::from(net.broadcast());
        // Skip .0 (network) and .1 (local TUN adapter IP); reserve (bcast - 1) for TUN peer DNS IP
        let start_host = (net_u32.saturating_add(2)).min(bcast_u32);
        let end_host = bcast_u32.saturating_sub(2).max(start_host);
        Self {
            ip_to_domain: LruCache::new(
                NonZeroUsize::new(capacity.max(64)).expect("non-zero capacity"),
            ),
            domain_to_ip: HashMap::with_capacity(capacity.min(4096)),
            cursor: start_host,
            start_host,
            end_host,
        }
    }

    fn get_or_assign(&mut self, domain: &str) -> Ipv4Addr {
        let normalized = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        if let Some(&existing_ip) = self.domain_to_ip.get(&normalized) {
            if self.ip_to_domain.get(&existing_ip) == Some(&normalized) {
                return existing_ip;
            }
            self.domain_to_ip.remove(&normalized);
        }

        let total_span = (self.end_host - self.start_host + 1) as usize;
        let mut chosen = None;
        for _ in 0..total_span.min(8) {
            let candidate = Ipv4Addr::from(self.cursor);
            self.cursor = if self.cursor >= self.end_host {
                self.start_host
            } else {
                self.cursor + 1
            };
            if !self.ip_to_domain.contains(&candidate) {
                chosen = Some(candidate);
                break;
            }
        }

        let ip = match chosen {
            Some(ip) => ip,
            None => {
                if let Some((evicted_ip, evicted_domain)) = self.ip_to_domain.pop_lru() {
                    self.domain_to_ip.remove(&evicted_domain);
                    evicted_ip
                } else {
                    let fallback = Ipv4Addr::from(self.cursor);
                    self.cursor = if self.cursor >= self.end_host {
                        self.start_host
                    } else {
                        self.cursor + 1
                    };
                    fallback
                }
            }
        };

        if let Some((_evicted_ip, evicted_domain)) = self.ip_to_domain.push(ip, normalized.clone())
            && evicted_domain != normalized
        {
            self.domain_to_ip.remove(&evicted_domain);
        }
        self.domain_to_ip.insert(normalized, ip);
        ip
    }

    fn insert_preserved(&mut self, ip: Ipv4Addr, domain: &str, net: Ipv4Net) -> bool {
        let ip_u32 = u32::from(ip);
        if !net.contains(&ip) || ip_u32 < self.start_host || ip_u32 > self.end_host {
            return false;
        }
        let normalized = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        if normalized.is_empty() {
            return false;
        }
        if let Some(prev_ip) = self.domain_to_ip.remove(&normalized)
            && prev_ip != ip
        {
            self.ip_to_domain.pop(&prev_ip);
        }
        if let Some((_evicted_ip, evicted_domain)) = self.ip_to_domain.push(ip, normalized.clone())
            && evicted_domain != normalized
        {
            self.domain_to_ip.remove(&evicted_domain);
        }
        self.domain_to_ip.insert(normalized, ip);
        if ip_u32 >= self.cursor {
            self.cursor = if ip_u32 >= self.end_host {
                self.start_host
            } else {
                ip_u32 + 1
            };
        }
        true
    }

    fn lookup_domain(&mut self, ip: Ipv4Addr) -> Option<String> {
        self.ip_to_domain.get(&ip).cloned()
    }

    fn lookup_ip(&mut self, domain: &str) -> Option<Ipv4Addr> {
        let normalized = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        let ip = *self.domain_to_ip.get(&normalized)?;
        if self.ip_to_domain.get(&ip) == Some(&normalized) {
            Some(ip)
        } else {
            self.domain_to_ip.remove(&normalized);
            None
        }
    }

    fn snapshot(&self) -> Vec<FakeIpEntry> {
        self.ip_to_domain
            .iter()
            .map(|(ip, domain)| FakeIpEntry {
                ip: ip.to_string(),
                domain: domain.clone(),
            })
            .collect()
    }
}

#[derive(Clone, Debug)]
struct CompiledHostsRule {
    pattern: String,
    ips: Vec<IpAddr>,
}

#[derive(Clone, Debug)]
struct CompiledPolicyRule {
    pattern: String,
    upstreams: Vec<DnsUpstream>,
}

fn label_glob_matches(text: &str, pat: &str) -> bool {
    if pat == "*" {
        return !text.is_empty();
    }
    if !pat.contains('*') {
        return text == pat;
    }
    let tb = text.as_bytes();
    let pb = pat.as_bytes();
    let (mut ti, mut pi) = (0usize, 0usize);
    let mut star_pi: Option<usize> = None;
    let mut match_ti = 0usize;

    while ti < tb.len() {
        if pi < pb.len() && pb[pi] == tb[ti] {
            ti += 1;
            pi += 1;
        } else if pi < pb.len() && pb[pi] == b'*' {
            star_pi = Some(pi);
            match_ti = ti;
            pi += 1;
        } else if let Some(sp) = star_pi {
            pi = sp + 1;
            match_ti += 1;
            ti = match_ti;
        } else {
            return false;
        }
    }
    while pi < pb.len() && pb[pi] == b'*' {
        pi += 1;
    }
    pi == pb.len()
}

fn labels_match_glob_slice(domain_labels: &[&str], pat_labels: &[&str]) -> bool {
    if domain_labels.len() != pat_labels.len() {
        return false;
    }
    domain_labels
        .iter()
        .zip(pat_labels.iter())
        .all(|(d, p)| label_glob_matches(d, p))
}

/// Split a Clash/Mihomo pattern key (which may be comma-separated, such as
/// `"+.internal.corp,+.edge.corp"` or `"geosite:cn,private"`), preserving the `"geosite:"`
/// prefix for bare subsequent category tokens.
pub(crate) fn split_clash_pattern_list(raw_key: &str) -> Vec<String> {
    let trimmed = raw_key.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    if !trimmed.contains(',') {
        return vec![trimmed.to_string()];
    }
    let mut out = Vec::new();
    let mut inherit_geosite = false;
    for (idx, part) in trimmed.split(',').enumerate() {
        let tok = part.trim();
        if tok.is_empty() {
            continue;
        }
        if idx == 0
            && tok.len() > 8
            && tok.is_char_boundary(8)
            && tok[..8].eq_ignore_ascii_case("geosite:")
        {
            inherit_geosite = true;
            out.push(tok.to_string());
        } else if inherit_geosite
            && !tok.contains(':')
            && !tok.contains('.')
            && !tok.contains('*')
            && !tok.contains('+')
        {
            out.push(format!("geosite:{tok}"));
        } else {
            out.push(tok.to_string());
        }
    }
    out
}

/// Match `domain` against a single Clash/Mihomo domain pattern, returning a specificity score
/// (`Exact > Multi-label Wildcard > Suffix (+./.) > GeoSite > Catch-All`) when matched.
pub fn domain_matches_clash_pattern(domain: &str, raw_pat: &str) -> Option<u32> {
    let d = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    if d.is_empty() {
        return None;
    }
    let p = raw_pat.trim().trim_end_matches('.').to_ascii_lowercase();
    if p.is_empty() {
        return None;
    }
    if p == "*" || p == "+" || p == "+.*" {
        return Some(100);
    }
    if let Some(rest) = p.strip_prefix("geosite:") {
        let cat = rest.trim();
        if cat.is_empty() {
            return None;
        }
        if let Some(builtin) = crate::router::geosite_data::lookup_builtin_geosite(cat)
            && crate::router::geodata::matches_geosite_dynamic(cat, builtin, &d)
        {
            return Some(1000 + (cat.len().min(128) as u32));
        }
        return None;
    }
    if let Some(suffix) = p.strip_prefix("+.") {
        if suffix.is_empty() {
            return None;
        }
        if !suffix.contains('*') {
            if d == suffix || d.ends_with(&format!(".{suffix}")) {
                let labels = suffix.bytes().filter(|&b| b == b'.').count() as u32 + 1;
                return Some(2000 + labels * 64 + (suffix.len().min(255) as u32));
            }
            return None;
        }
        let d_labels: Vec<&str> = d.split('.').collect();
        let s_labels: Vec<&str> = suffix.split('.').collect();
        if d_labels.len() >= s_labels.len()
            && labels_match_glob_slice(&d_labels[d_labels.len() - s_labels.len()..], &s_labels)
        {
            let lit_labels = s_labels.iter().filter(|&&l| !l.contains('*')).count() as u32;
            return Some(2000 + lit_labels * 64 + (suffix.len().min(255) as u32));
        }
        return None;
    }
    if let Some(suffix) = p.strip_prefix('.') {
        if suffix.is_empty() {
            return None;
        }
        let d_labels: Vec<&str> = d.split('.').collect();
        let s_labels: Vec<&str> = suffix.split('.').collect();
        if d_labels.len() > s_labels.len()
            && labels_match_glob_slice(&d_labels[d_labels.len() - s_labels.len()..], &s_labels)
        {
            let lit_labels = s_labels.iter().filter(|&&l| !l.contains('*')).count() as u32;
            return Some(2000 + lit_labels * 64 + (suffix.len().min(255) as u32));
        }
        return None;
    }
    if p.contains('*') {
        let d_labels: Vec<&str> = d.split('.').collect();
        let p_labels: Vec<&str> = p.split('.').collect();
        if labels_match_glob_slice(&d_labels, &p_labels) {
            let lit_labels = p_labels.iter().filter(|&&l| !l.contains('*')).count() as u32;
            return Some(3000 + lit_labels * 64 + (p.len().min(255) as u32));
        }
        return None;
    }
    if d == p {
        return Some(4000 + (p.len().min(255) as u32));
    }
    None
}

/// Check whether `domain` matches any pattern in a (possibly comma-separated) Clash pattern string.
pub fn domain_matches_any_clash_pattern(domain: &str, raw_key: &str) -> bool {
    split_clash_pattern_list(raw_key)
        .iter()
        .any(|pat| domain_matches_clash_pattern(domain, pat).is_some())
}

/// Production Multi-Transport DNS Engine supporting:
/// - `fake-ip` (`198.18.0.0/15`) and `redir-host` / `normal` (Real-IP) modes
/// - `udp://` (with RFC 1035 `TC=1` -> TCP fallback), `tcp://`, `tls://` (DoT), and `https://` (DoH RFC 8484 HTTP/1.1 + HTTP/2)
/// - Clash Meta / Mihomo `nameserver-policy`, `proxy-server-nameserver`, `proxy-server-nameserver-policy`, and static `hosts`
/// - Strict literal-IP `default-nameserver` bootstrap separation (preventing OS resolver leaks)
/// - Configurable `dns.ipv6` policy
/// - TTL-aware positive & negative (`NXDOMAIN` / `NODATA`) caching + explicit `flush_cache()` invalidation
/// - Local UDP and TCP DNS listeners
pub struct FakeIpDnsEngine {
    enabled: bool,
    fake_ip_mode: bool,
    ipv6: bool,
    use_hosts: bool,
    direct_nameserver_follow_policy: bool,
    enhanced_mode: String,
    net: Ipv4Net,
    filters: Vec<String>,
    hosts_rules: Vec<CompiledHostsRule>,
    bootstrap_servers: Vec<BootstrapDnsServer>,
    proxy_upstreams: Vec<DnsUpstream>,
    proxy_policy_rules: Vec<CompiledPolicyRule>,
    direct_upstreams: Vec<DnsUpstream>,
    upstreams: Vec<DnsUpstream>,
    fallbacks: Vec<DnsUpstream>,
    policy_rules: Vec<CompiledPolicyRule>,
    literal_nameservers: Vec<SocketAddr>,
    extra_ca_der: Vec<CertificateDer<'static>>,
    pool: Mutex<PoolInner>,
    real_ip_cache: Mutex<LruCache<String, CachedIpResolution>>,
    direct_ip_cache: Mutex<LruCache<String, CachedIpResolution>>,
    proxy_ip_cache: Mutex<LruCache<String, CachedIpResolution>>,
    packet_cache: Mutex<LruCache<(String, u16), CachedWirePacket>>,
    bootstrap_cache: Mutex<LruCache<String, (Instant, Vec<IpAddr>)>>,
    inflight_real: DashMap<String, watch::Sender<bool>>,
    inflight_direct: DashMap<String, watch::Sender<bool>>,
    inflight_proxy: DashMap<String, watch::Sender<bool>>,
    inflight_bootstrap: DashMap<String, watch::Sender<bool>>,
    total_queries: AtomicU64,
    fake_ip_hits: AtomicU64,
    cache_hits: AtomicU64,
    suppressed_queries: AtomicU64,
    nxdomain_hits: AtomicU64,
    upstream_queries: AtomicU64,
    upstream_errors: AtomicU64,
    upstream_total_ms: AtomicU64,
    upstream_max_ms: AtomicU64,
}

impl FakeIpDnsEngine {
    pub fn new(cfg: &DnsConfig) -> Result<Self> {
        Self::with_extra_ca(cfg, &[])
    }

    pub fn with_extra_ca(
        cfg: &DnsConfig,
        extra_ca_der: &[CertificateDer<'static>],
    ) -> Result<Self> {
        let net = cfg.parsed_fake_ip_net()?;
        let raw_mode = cfg.enhanced_mode.trim().to_ascii_lowercase();
        let mode_lc = match raw_mode.as_str() {
            "mapping" => "fake-ip".to_string(),
            "passthrough" | "hosts" | "" => "normal".to_string(),
            "fake-ip" | "redir-host" | "normal" => raw_mode,
            _ => {
                return Err(ProxyError::Config(format!(
                    "unsupported dns.enhanced-mode '{}' (expected 'fake-ip', 'redir-host', or 'normal')",
                    cfg.enhanced_mode
                )));
            }
        };
        let fake_ip_mode = mode_lc == "fake-ip";

        let mut hosts_rules = Vec::new();
        let mut sorted_hosts_keys: Vec<&String> = cfg.hosts.keys().collect();
        sorted_hosts_keys.sort();
        for raw_key in sorted_hosts_keys {
            let Some(ip_strs) = cfg.hosts.get(raw_key) else {
                continue;
            };
            let mut ips = Vec::new();
            for s in ip_strs {
                if s.trim().is_empty() {
                    continue;
                }
                let ip = crate::config::parse_hosts_ip_entry(s).ok_or_else(|| {
                    ProxyError::Config(format!("invalid IP address '{s}' in hosts for '{raw_key}'"))
                })?;
                if !net.contains(&match ip {
                    IpAddr::V4(v4) => v4,
                    IpAddr::V6(v6) => v6.to_ipv4_mapped().unwrap_or(Ipv4Addr::UNSPECIFIED),
                }) && !ips.contains(&ip)
                {
                    ips.push(ip);
                }
            }
            if ips.is_empty() {
                continue;
            }
            for pat in split_clash_pattern_list(raw_key) {
                hosts_rules.push(CompiledHostsRule {
                    pattern: pat,
                    ips: ips.clone(),
                });
            }
        }

        let mut bootstrap_servers = Vec::new();
        for b in &cfg.default_nameserver {
            if !b.trim().is_empty() {
                bootstrap_servers.push(BootstrapDnsServer::parse(b)?);
            }
        }

        let mut literal_nameservers = Vec::new();
        let mut record_literal_ns = |up: &DnsUpstream| {
            if let Some(sa) = up.literal_socket_addr()
                && !literal_nameservers.contains(&sa)
            {
                literal_nameservers.push(sa);
            }
        };

        let mut proxy_upstreams = Vec::new();
        for ns in &cfg.proxy_server_nameserver {
            if ns.trim().is_empty() {
                continue;
            }
            let parsed = DnsUpstream::parse(ns)?;
            record_literal_ns(&parsed);
            proxy_upstreams.push(parsed);
        }

        let mut direct_upstreams = Vec::new();
        for dns_str in &cfg.direct_nameserver {
            if dns_str.trim().is_empty() {
                continue;
            }
            let parsed = DnsUpstream::parse(dns_str)?;
            record_literal_ns(&parsed);
            direct_upstreams.push(parsed);
        }

        let mut upstreams = Vec::new();
        for ns in &cfg.nameserver {
            if ns.trim().is_empty() {
                continue;
            }
            let parsed = DnsUpstream::parse(ns)?;
            record_literal_ns(&parsed);
            upstreams.push(parsed);
        }

        let mut fallbacks = Vec::new();
        for fb in &cfg.fallback {
            if fb.trim().is_empty() {
                continue;
            }
            let parsed = DnsUpstream::parse(fb)?;
            record_literal_ns(&parsed);
            fallbacks.push(parsed);
        }

        let compile_policy_map = |policy_map: &HashMap<String, Vec<String>>,
                                  record_ns: &mut dyn FnMut(&DnsUpstream)|
         -> Result<Vec<CompiledPolicyRule>> {
            let mut keys: Vec<&String> = policy_map.keys().collect();
            keys.sort();
            let mut compiled = Vec::new();
            for raw_key in keys {
                let Some(ns_list) = policy_map.get(raw_key) else {
                    continue;
                };
                let mut ups = Vec::new();
                for ns in ns_list {
                    if ns.trim().is_empty() {
                        continue;
                    }
                    let parsed = DnsUpstream::parse(ns)?;
                    record_ns(&parsed);
                    ups.push(parsed);
                }
                if ups.is_empty() {
                    continue;
                }
                for pat in split_clash_pattern_list(raw_key) {
                    compiled.push(CompiledPolicyRule {
                        pattern: pat,
                        upstreams: ups.clone(),
                    });
                }
            }
            Ok(compiled)
        };

        let policy_rules = compile_policy_map(&cfg.nameserver_policy, &mut record_literal_ns)?;
        let proxy_policy_rules =
            compile_policy_map(&cfg.proxy_server_nameserver_policy, &mut record_literal_ns)?;

        let host_covered_by_static_hosts = |domain: &str| -> bool {
            cfg.use_hosts
                && hosts_rules
                    .iter()
                    .any(|r| domain_matches_clash_pattern(domain, &r.pattern).is_some())
        };

        let upstream_needs_bootstrap = |u: &DnsUpstream| -> bool {
            if !u.requires_bootstrap() {
                return false;
            }
            match u.endpoint_host() {
                DnsEndpointHost::Ip(_) => false,
                DnsEndpointHost::Domain(ref d) => {
                    d != "localhost" && !host_covered_by_static_hosts(d)
                }
            }
        };

        // Enforce strict bootstrap separation: if any DoT/DoH upstream uses a domain hostname
        // not statically resolved via `hosts`, `default-nameserver` MUST contain at least one literal-IP bootstrap server!
        let any_needs_bootstrap = proxy_upstreams.iter().any(&upstream_needs_bootstrap)
            || direct_upstreams.iter().any(&upstream_needs_bootstrap)
            || upstreams.iter().any(&upstream_needs_bootstrap)
            || fallbacks.iter().any(&upstream_needs_bootstrap)
            || policy_rules
                .iter()
                .flat_map(|r| r.upstreams.iter())
                .any(&upstream_needs_bootstrap)
            || proxy_policy_rules
                .iter()
                .flat_map(|r| r.upstreams.iter())
                .any(&upstream_needs_bootstrap);

        if any_needs_bootstrap && bootstrap_servers.is_empty() {
            return Err(ProxyError::Config(
                "DoH/DoT hostname in dns.nameserver/fallback requires at least one literal-IP dns.default-nameserver".into(),
            ));
        }

        Ok(Self {
            enabled: cfg.enable,
            fake_ip_mode,
            ipv6: cfg.ipv6,
            use_hosts: cfg.use_hosts,
            direct_nameserver_follow_policy: cfg.direct_nameserver_follow_policy,
            enhanced_mode: mode_lc,
            net,
            filters: cfg.fake_ip_filter.clone(),
            hosts_rules,
            bootstrap_servers,
            proxy_upstreams,
            proxy_policy_rules,
            direct_upstreams,
            upstreams,
            fallbacks,
            policy_rules,
            literal_nameservers,
            extra_ca_der: extra_ca_der.to_vec(),
            pool: Mutex::new(PoolInner::new(net, 16_384)),
            real_ip_cache: Mutex::new(LruCache::new(
                NonZeroUsize::new(4096).expect("non-zero cache size"),
            )),
            direct_ip_cache: Mutex::new(LruCache::new(
                NonZeroUsize::new(4096).expect("non-zero cache size"),
            )),
            proxy_ip_cache: Mutex::new(LruCache::new(
                NonZeroUsize::new(1024).expect("non-zero cache size"),
            )),
            packet_cache: Mutex::new(LruCache::new(
                NonZeroUsize::new(4096).expect("non-zero cache size"),
            )),
            bootstrap_cache: Mutex::new(LruCache::new(
                NonZeroUsize::new(256).expect("non-zero cache size"),
            )),
            inflight_real: DashMap::new(),
            inflight_direct: DashMap::new(),
            inflight_proxy: DashMap::new(),
            inflight_bootstrap: DashMap::new(),
            total_queries: AtomicU64::new(0),
            fake_ip_hits: AtomicU64::new(0),
            cache_hits: AtomicU64::new(0),
            suppressed_queries: AtomicU64::new(0),
            nxdomain_hits: AtomicU64::new(0),
            upstream_queries: AtomicU64::new(0),
            upstream_errors: AtomicU64::new(0),
            upstream_total_ms: AtomicU64::new(0),
            upstream_max_ms: AtomicU64::new(0),
        })
    }

    /// Preserve active Fake-IP <-> domain mappings across a config hot-reload when `fake-ip-range` matches.
    pub fn import_entries_from(&self, prev: &FakeIpDnsEngine) {
        self.total_queries
            .store(prev.total_queries(), Ordering::Relaxed);
        self.fake_ip_hits
            .store(prev.fake_ip_hits.load(Ordering::Relaxed), Ordering::Relaxed);
        self.cache_hits
            .store(prev.cache_hits.load(Ordering::Relaxed), Ordering::Relaxed);
        self.suppressed_queries.store(
            prev.suppressed_queries.load(Ordering::Relaxed),
            Ordering::Relaxed,
        );
        self.nxdomain_hits.store(
            prev.nxdomain_hits.load(Ordering::Relaxed),
            Ordering::Relaxed,
        );
        self.upstream_queries.store(
            prev.upstream_queries.load(Ordering::Relaxed),
            Ordering::Relaxed,
        );
        self.upstream_errors.store(
            prev.upstream_errors.load(Ordering::Relaxed),
            Ordering::Relaxed,
        );
        self.upstream_total_ms.store(
            prev.upstream_total_ms.load(Ordering::Relaxed),
            Ordering::Relaxed,
        );
        self.upstream_max_ms.store(
            prev.upstream_max_ms.load(Ordering::Relaxed),
            Ordering::Relaxed,
        );
        if prev.net != self.net {
            return;
        }
        let entries = prev.entries_snapshot();
        let mut guard = self.pool.lock();
        for entry in entries.into_iter().rev() {
            if let Ok(v4) = entry.ip.parse::<Ipv4Addr>()
                && !self.should_bypass_fake_ip(&entry.domain)
            {
                let _ = guard.insert_preserved(v4, &entry.domain, self.net);
            }
        }
    }

    /// Export non-expired positive `proxy_ip_cache` and `bootstrap_cache` entries (e.g. from an offline
    /// Android latency-test router right before starting the VPN engine with identical DNS config).
    pub fn export_positive_proxy_cache_seed(&self) -> PositiveDnsCacheSeed {
        let now = Instant::now();
        let proxy_entries = self
            .proxy_ip_cache
            .lock()
            .iter()
            .filter_map(|(k, v)| match v {
                CachedIpResolution::Positive { expires_at, ips }
                    if *expires_at > now && !ips.is_empty() =>
                {
                    Some((k.clone(), *expires_at, ips.clone()))
                }
                _ => None,
            })
            .collect();
        let bootstrap_entries = self
            .bootstrap_cache
            .lock()
            .iter()
            .filter(|(_, (expires_at, ips))| *expires_at > now && !ips.is_empty())
            .map(|(k, (expires_at, ips))| (k.clone(), *expires_at, ips.clone()))
            .collect();
        PositiveDnsCacheSeed {
            proxy_entries,
            bootstrap_entries,
        }
    }

    /// Seed non-expired positive `proxy_ip_cache` and `bootstrap_cache` entries from a prior verified engine.
    pub fn seed_positive_proxy_cache(&self, seed: PositiveDnsCacheSeed) {
        let now = Instant::now();
        if !seed.bootstrap_entries.is_empty() {
            let mut bguard = self.bootstrap_cache.lock();
            for (domain, expires_at, ips) in seed.bootstrap_entries.into_iter().rev() {
                if expires_at <= now || bguard.contains(&domain) {
                    continue;
                }
                let valid: Vec<IpAddr> = ips
                    .into_iter()
                    .filter(|ip| (!ip.is_ipv6() || self.ipv6) && !self.is_fake_ip(*ip))
                    .collect();
                if !valid.is_empty() {
                    bguard.put(domain, (expires_at, valid));
                }
            }
        }
        if !seed.proxy_entries.is_empty() {
            let mut pguard = self.proxy_ip_cache.lock();
            for (domain, expires_at, ips) in seed.proxy_entries.into_iter().rev() {
                if expires_at <= now || pguard.contains(&domain) {
                    continue;
                }
                let mut valid: Vec<IpAddr> = ips
                    .iter()
                    .copied()
                    .filter(|ip| (!ip.is_ipv6() || self.ipv6) && !self.is_fake_ip(*ip))
                    .collect();
                if valid.is_empty() {
                    valid = ips.into_iter().filter(|ip| !self.is_fake_ip(*ip)).collect();
                }
                if !valid.is_empty() {
                    pguard.put(
                        domain,
                        CachedIpResolution::Positive {
                            expires_at,
                            ips: valid,
                        },
                    );
                }
            }
        }
    }

    /// Proactively warm or refresh `proxy_ip_cache` for a proxy server hostname when missing or `< 25s` TTL remains.
    /// Preserves any still-unexpired positive entry if a proactive refresh encounters a transient network error.
    pub async fn prewarm_proxy_server_ips(&self, host: &str) -> Result<Vec<IpAddr>> {
        let clean = host
            .trim()
            .trim_matches(|c| c == '[' || c == ']')
            .trim_end_matches('.')
            .to_ascii_lowercase();
        if clean.is_empty()
            || clean.parse::<IpAddr>().is_ok()
            || clean == "localhost"
            || self.lookup_static_hosts_for_endpoint(&clean).is_some()
        {
            return self.resolve_proxy_server_ips(host).await;
        }

        let now = Instant::now();
        let fallback_entry = {
            let mut guard = self.proxy_ip_cache.lock();
            match guard.get(&clean).cloned() {
                Some(CachedIpResolution::Positive { expires_at, ips }) => {
                    if expires_at.saturating_duration_since(now) > Duration::from_secs(25) {
                        return Ok(ips);
                    }
                    guard.pop(&clean);
                    (expires_at > now).then_some((expires_at, ips))
                }
                Some(CachedIpResolution::Negative { .. }) => {
                    guard.pop(&clean);
                    None
                }
                None => None,
            }
        };

        match self.resolve_proxy_server_ips(host).await {
            Ok(ips) => Ok(ips),
            Err(e) => {
                if let Some((expires_at, ips)) = fallback_entry
                    && Instant::now() < expires_at
                {
                    let mut guard = self.proxy_ip_cache.lock();
                    if !guard.contains(&clean) {
                        guard.put(
                            clean,
                            CachedIpResolution::Positive {
                                expires_at,
                                ips: ips.clone(),
                            },
                        );
                    }
                    return Ok(ips);
                }
                Err(e)
            }
        }
    }

    /// Flush positive/negative DNS resolution caches, wire packet caches, and pooled DoT/DoH sockets.
    pub fn flush_cache(&self) {
        self.real_ip_cache.lock().clear();
        self.direct_ip_cache.lock().clear();
        self.proxy_ip_cache.lock().clear();
        self.packet_cache.lock().clear();
        self.bootstrap_cache.lock().clear();
        clear_dns_upstream_pools();
    }

    pub fn cached_record_count(&self) -> usize {
        self.real_ip_cache.lock().len()
            + self.direct_ip_cache.lock().len()
            + self.proxy_ip_cache.lock().len()
            + self.packet_cache.lock().len()
    }

    pub fn fake_ip_net(&self) -> Ipv4Net {
        self.net
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn is_fake_ip_mode(&self) -> bool {
        self.enabled && self.fake_ip_mode
    }

    pub fn ipv6_enabled(&self) -> bool {
        self.ipv6
    }

    pub fn enhanced_mode(&self) -> &str {
        &self.enhanced_mode
    }

    pub fn nameservers(&self) -> &[SocketAddr] {
        &self.literal_nameservers
    }

    /// Return all literal upstream & bootstrap DNS IPs so OS TUN routes can explicitly exclude them.
    pub fn upstream_bypass_ips(&self) -> Vec<IpAddr> {
        let mut out = Vec::new();
        for b in &self.bootstrap_servers {
            if !self.is_fake_ip(b.ip()) && !out.contains(&b.ip()) {
                out.push(b.ip());
            }
        }
        for sa in &self.literal_nameservers {
            if !self.is_fake_ip(sa.ip()) && !out.contains(&sa.ip()) {
                out.push(sa.ip());
            }
        }
        out
    }

    pub fn gateway_ipv4(&self) -> Ipv4Addr {
        Ipv4Addr::from(u32::from(self.net.network()).saturating_add(1))
    }

    pub fn is_fake_ip(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => self.net.contains(&v4),
            IpAddr::V6(v6) => v6.to_ipv4_mapped().is_some_and(|v4| self.net.contains(&v4)),
        }
    }

    pub fn should_bypass_fake_ip(&self, domain: &str) -> bool {
        let d = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        if d.is_empty() || d.parse::<IpAddr>().is_ok() {
            return true;
        }
        if self.use_hosts && self.lookup_static_hosts_raw(&d).is_some() {
            return true;
        }
        self.filters
            .iter()
            .any(|pat| domain_matches_any_clash_pattern(&d, pat))
    }

    fn lookup_static_hosts_raw(&self, normalized: &str) -> Option<&[IpAddr]> {
        if !self.use_hosts || self.hosts_rules.is_empty() {
            return None;
        }
        let mut best: Option<(u32, &str, &[IpAddr])> = None;
        for rule in &self.hosts_rules {
            if let Some(score) = domain_matches_clash_pattern(normalized, &rule.pattern) {
                let replace = match best {
                    None => true,
                    Some((best_score, best_pat, _)) => {
                        score > best_score
                            || (score == best_score && rule.pattern.as_str() < best_pat)
                    }
                };
                if replace {
                    best = Some((score, rule.pattern.as_str(), rule.ips.as_slice()));
                }
            }
        }
        best.map(|(_, _, ips)| ips)
    }

    fn lookup_static_hosts_filtered(&self, normalized: &str) -> Option<Vec<IpAddr>> {
        let raw = self.lookup_static_hosts_raw(normalized)?;
        let filtered: Vec<IpAddr> = raw
            .iter()
            .copied()
            .filter(|ip| (!ip.is_ipv6() || self.ipv6) && !self.is_fake_ip(*ip))
            .collect();
        if filtered.is_empty() {
            None
        } else {
            Some(filtered)
        }
    }

    fn lookup_static_hosts_for_endpoint(&self, normalized: &str) -> Option<Vec<IpAddr>> {
        let raw = self.lookup_static_hosts_raw(normalized)?;
        let mut preferred: Vec<IpAddr> = raw
            .iter()
            .copied()
            .filter(|ip| (!ip.is_ipv6() || self.ipv6) && !self.is_fake_ip(*ip))
            .collect();
        if preferred.is_empty() {
            preferred = raw
                .iter()
                .copied()
                .filter(|ip| !self.is_fake_ip(*ip))
                .collect();
        }
        if preferred.is_empty() {
            None
        } else {
            Some(preferred)
        }
    }

    fn matching_policy_upstreams<'a>(
        rules: &'a [CompiledPolicyRule],
        normalized: &str,
    ) -> Option<&'a [DnsUpstream]> {
        if rules.is_empty() {
            return None;
        }
        let mut best: Option<(u32, &'a str, &'a [DnsUpstream])> = None;
        for rule in rules {
            if let Some(score) = domain_matches_clash_pattern(normalized, &rule.pattern) {
                let replace = match best {
                    None => true,
                    Some((best_score, best_pat, _)) => {
                        score > best_score
                            || (score == best_score && rule.pattern.as_str() < best_pat)
                    }
                };
                if replace {
                    best = Some((score, rule.pattern.as_str(), rule.upstreams.as_slice()));
                }
            }
        }
        best.map(|(_, _, ups)| ups)
    }

    pub fn assign_fake_ip(&self, domain: &str) -> Ipv4Addr {
        self.pool.lock().get_or_assign(domain)
    }

    pub fn lookup_domain(&self, ip: IpAddr) -> Option<String> {
        match ip {
            IpAddr::V4(v4) if self.net.contains(&v4) => self.pool.lock().lookup_domain(v4),
            IpAddr::V6(v6) => v6
                .to_ipv4_mapped()
                .filter(|v4| self.net.contains(v4))
                .and_then(|v4| self.pool.lock().lookup_domain(v4)),
            _ => None,
        }
    }

    pub fn lookup_ip(&self, domain: &str) -> Option<Ipv4Addr> {
        self.pool.lock().lookup_ip(domain)
    }

    pub fn restore_target(&self, target: &TargetAddr) -> (TargetAddr, Option<Ipv4Addr>) {
        let maybe_v4 = match target.host {
            HostName::Ip(IpAddr::V4(v4)) if self.net.contains(&v4) => Some(v4),
            HostName::Ip(IpAddr::V6(v6)) => v6.to_ipv4_mapped().filter(|v4| self.net.contains(v4)),
            _ => None,
        };
        if let Some(v4) = maybe_v4
            && let Some(domain) = self.pool.lock().lookup_domain(v4)
            && let Ok(restored) = TargetAddr::new_domain(domain, target.port)
        {
            return (restored, Some(v4));
        }
        (target.clone(), None)
    }

    pub fn is_unmapped_fake_ip(&self, target: &TargetAddr) -> bool {
        let maybe_v4 = match target.host {
            HostName::Ip(IpAddr::V4(v4)) if self.net.contains(&v4) => Some(v4),
            HostName::Ip(IpAddr::V6(v6)) => v6.to_ipv4_mapped().filter(|v4| self.net.contains(v4)),
            _ => None,
        };
        if let Some(v4) = maybe_v4 {
            return self.pool.lock().lookup_domain(v4).is_none();
        }
        false
    }

    fn lookup_cached_ips(
        cache: &Mutex<LruCache<String, CachedIpResolution>>,
        normalized: &str,
    ) -> Option<Result<Vec<IpAddr>>> {
        let cached = cache.lock().get(normalized).cloned()?;
        match cached {
            CachedIpResolution::Positive { expires_at, ips } if Instant::now() < expires_at => {
                Some(Ok(ips))
            }
            CachedIpResolution::Negative {
                expires_at,
                nxdomain,
            } if Instant::now() < expires_at => Some(if nxdomain {
                Err(ProxyError::Dns(format!(
                    "DNS NXDOMAIN (cached) for '{normalized}'"
                )))
            } else {
                Err(ProxyError::Dns(format!(
                    "DNS NODATA (cached) for '{normalized}'"
                )))
            }),
            _ => None,
        }
    }

    async fn query_bootstrap_qtype(&self, domain: &str, qtype: u16) -> Option<(u64, Vec<IpAddr>)> {
        let query = build_dns_query(rand::random(), domain, qtype);
        for bs in &self.bootstrap_servers {
            if self.is_fake_ip(bs.ip()) {
                continue;
            }
            if let Ok(resp) = bs.exchange_with_ca(&query, &self.extra_ca_der).await
                && let Ok(meta) = extract_dns_response_meta(&resp)
                && meta.rcode == 0
            {
                let ttl = meta
                    .min_ttl
                    .map_or(300u64, |t| u64::from(t).clamp(10, 3600));
                let mut found = Vec::new();
                for ans in meta.answers {
                    match ans {
                        DnsAnswerData::A(v4) => {
                            let ip = IpAddr::V4(v4);
                            if !self.is_fake_ip(ip) && !found.contains(&ip) {
                                found.push(ip);
                            }
                        }
                        DnsAnswerData::Aaaa(v6) => {
                            let ip = IpAddr::V6(v6);
                            if !self.is_fake_ip(ip) && !found.contains(&ip) {
                                found.push(ip);
                            }
                        }
                        DnsAnswerData::Txt(_) => {}
                    }
                }
                return Some((ttl, found));
            }
        }
        None
    }

    /// Resolve a DoT/DoH server's hostname strictly using static `hosts` (when `use-hosts: true`)
    /// or literal-IP `default-nameserver`s (never touching OS `getaddrinfo`, preventing DNS leaks and recursive TUN loops).
    async fn resolve_bootstrap_host(&self, host: &DnsEndpointHost) -> Result<Vec<IpAddr>> {
        match host {
            DnsEndpointHost::Ip(ip) => {
                if self.is_fake_ip(*ip) {
                    return Err(ProxyError::Dns(format!(
                        "refusing Fake-IP {ip} as upstream DNS endpoint"
                    )));
                }
                Ok(vec![*ip])
            }
            DnsEndpointHost::Domain(domain) => {
                let norm = domain.trim().trim_end_matches('.').to_ascii_lowercase();
                if norm == "localhost" {
                    return Ok(vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]);
                }
                if let Some(static_ips) = self.lookup_static_hosts_for_endpoint(&norm) {
                    return Ok(static_ips);
                }
                if let Some((expires_at, ips)) = self.bootstrap_cache.lock().get(&norm).cloned()
                    && Instant::now() < expires_at
                {
                    return Ok(ips);
                }

                let _inflight_guard = {
                    let waiter = match self.inflight_bootstrap.entry(norm.clone()) {
                        Entry::Occupied(occ) => Err(occ.get().subscribe()),
                        Entry::Vacant(vac) => {
                            let (tx, _rx) = watch::channel(false);
                            vac.insert(tx.clone());
                            Ok(InflightLookupGuard {
                                map: &self.inflight_bootstrap,
                                key: norm.clone(),
                                tx,
                            })
                        }
                    };
                    match waiter {
                        Ok(guard) => Some(guard),
                        Err(mut rx) => {
                            let _ = tokio::time::timeout(
                                Duration::from_secs(4),
                                rx.wait_for(|&done| done),
                            )
                            .await;
                            if let Some((expires_at, ips)) =
                                self.bootstrap_cache.lock().get(&norm).cloned()
                                && Instant::now() < expires_at
                            {
                                return Ok(ips);
                            }
                            None
                        }
                    }
                };

                if let Some((expires_at, ips)) = self.bootstrap_cache.lock().get(&norm).cloned()
                    && Instant::now() < expires_at
                {
                    return Ok(ips);
                }

                let (res_a, res_aaaa) = if self.ipv6 {
                    tokio::join!(
                        self.query_bootstrap_qtype(&norm, QTYPE_A),
                        self.query_bootstrap_qtype(&norm, QTYPE_AAAA)
                    )
                } else {
                    (self.query_bootstrap_qtype(&norm, QTYPE_A).await, None)
                };

                let mut ips = Vec::new();
                let mut min_ttl = 300u64;
                for (ttl, list) in [res_a, res_aaaa].into_iter().flatten() {
                    min_ttl = min_ttl.min(ttl);
                    for ip in list {
                        if !ips.contains(&ip) {
                            ips.push(ip);
                        }
                    }
                }

                if ips.is_empty() {
                    return Err(ProxyError::Dns(format!(
                        "default-nameserver bootstrap failed for DoH/DoT host '{domain}'"
                    )));
                }

                self.bootstrap_cache.lock().put(
                    norm,
                    (Instant::now() + Duration::from_secs(min_ttl), ips.clone()),
                );
                Ok(ips)
            }
        }
    }

    async fn exchange_single_upstream(
        &self,
        upstream: &DnsUpstream,
        raw_query: &[u8],
    ) -> Result<Vec<u8>> {
        let ips = Box::pin(self.resolve_bootstrap_host(&upstream.endpoint_host())).await?;
        Box::pin(upstream.exchange(&ips, raw_query, &self.extra_ca_der)).await
    }

    async fn exchange_with_upstream_slice(
        &self,
        slice: &[DnsUpstream],
        raw_query: &[u8],
    ) -> Result<Vec<u8>> {
        self.upstream_queries.fetch_add(1, Ordering::Relaxed);
        let started = Instant::now();
        let record_ok = |resp: Vec<u8>| -> Result<Vec<u8>> {
            let ms = started.elapsed().as_millis() as u64;
            self.upstream_total_ms.fetch_add(ms, Ordering::Relaxed);
            self.upstream_max_ms.fetch_max(ms, Ordering::Relaxed);
            Ok(resp)
        };

        let mut last_err = ProxyError::Dns("no DNS upstreams configured".into());
        let remaining = if slice.len() >= 2
            && matches!(
                (&slice[0], &slice[1]),
                (DnsUpstream::Udp(_), DnsUpstream::Udp(_))
            ) {
            let mut fut0 = Box::pin(self.exchange_single_upstream(&slice[0], raw_query));
            let mut hedge_delay = std::pin::pin!(tokio::time::sleep(Duration::from_millis(250)));

            tokio::select! {
                res0 = &mut fut0 => {
                    match res0 {
                        Ok(resp) => return record_ok(resp),
                        Err(_e0) => match Box::pin(self.exchange_single_upstream(&slice[1], raw_query)).await {
                            Ok(resp) => return record_ok(resp),
                            Err(e1) => last_err = e1,
                        },
                    }
                }
                _ = &mut hedge_delay => {
                    let mut fut1 = Box::pin(self.exchange_single_upstream(&slice[1], raw_query));
                    tokio::select! {
                        res0 = &mut fut0 => {
                            match res0 {
                                Ok(resp) => return record_ok(resp),
                                Err(_e0) => match fut1.await {
                                    Ok(resp) => return record_ok(resp),
                                    Err(e1) => last_err = e1,
                                },
                            }
                        }
                        res1 = &mut fut1 => {
                            match res1 {
                                Ok(resp) => return record_ok(resp),
                                Err(e1) => match fut0.await {
                                    Ok(resp) => return record_ok(resp),
                                    Err(_e0) => last_err = e1,
                                },
                            }
                        }
                    }
                }
            }
            &slice[2..]
        } else {
            slice
        };

        for upstream in remaining {
            match Box::pin(self.exchange_single_upstream(upstream, raw_query)).await {
                Ok(resp) => return record_ok(resp),
                Err(e) => last_err = e,
            }
        }
        self.upstream_errors.fetch_add(1, Ordering::Relaxed);
        Err(last_err)
    }

    async fn exchange_with_upstreams(&self, raw_query: &[u8]) -> Result<Vec<u8>> {
        match self
            .exchange_with_upstream_slice(&self.upstreams, raw_query)
            .await
        {
            Ok(resp) => Ok(resp),
            Err(primary_err) => {
                if self.fallbacks.is_empty() {
                    Err(primary_err)
                } else {
                    self.exchange_with_upstream_slice(&self.fallbacks, raw_query)
                        .await
                }
            }
        }
    }

    async fn query_slice_qtype(
        &self,
        slice: &[DnsUpstream],
        normalized: &str,
        qtype: u16,
    ) -> Option<crate::dns::wire::DnsResponseMeta> {
        let query = build_dns_query(rand::random(), normalized, qtype);
        let resp = self
            .exchange_with_upstream_slice(slice, &query)
            .await
            .ok()?;
        extract_dns_response_meta(&resp).ok()
    }

    async fn query_upstream_qtype(
        &self,
        normalized: &str,
        qtype: u16,
    ) -> Option<crate::dns::wire::DnsResponseMeta> {
        let query = build_dns_query(rand::random(), normalized, qtype);
        let resp = self.exchange_with_upstreams(&query).await.ok()?;
        extract_dns_response_meta(&resp).ok()
    }

    fn collect_ips_from_metas(
        &self,
        metas: [Option<crate::dns::wire::DnsResponseMeta>; 2],
    ) -> (Vec<IpAddr>, Option<u64>, Option<u64>, bool, bool) {
        let mut resolved = Vec::new();
        let mut saw_nxdomain = false;
        let mut saw_nodata = false;
        let mut min_pos_ttl: Option<u64> = None;
        let mut min_neg_ttl: Option<u64> = None;

        for meta in metas.into_iter().flatten() {
            if meta.rcode == 3 {
                saw_nxdomain = true;
                let neg_t = u64::from(meta.min_ttl.unwrap_or(30))
                    .clamp(MIN_NEGATIVE_TTL_SECS, MAX_NEGATIVE_TTL_SECS);
                min_neg_ttl = Some(min_neg_ttl.map_or(neg_t, |c| c.min(neg_t)));
            } else if meta.rcode == 0 {
                if meta.answers.is_empty() {
                    saw_nodata = true;
                    let neg_t = u64::from(meta.min_ttl.unwrap_or(15))
                        .clamp(MIN_NEGATIVE_TTL_SECS, MAX_NEGATIVE_TTL_SECS);
                    min_neg_ttl = Some(min_neg_ttl.map_or(neg_t, |c| c.min(neg_t)));
                } else {
                    let pos_t = u64::from(meta.min_ttl.unwrap_or(60))
                        .clamp(MIN_POSITIVE_TTL_SECS, MAX_POSITIVE_TTL_SECS);
                    min_pos_ttl = Some(min_pos_ttl.map_or(pos_t, |c| c.min(pos_t)));
                    for ans in meta.answers {
                        match ans {
                            DnsAnswerData::A(v4) => {
                                let ip = IpAddr::V4(v4);
                                if !self.is_fake_ip(ip) && !resolved.contains(&ip) {
                                    resolved.push(ip);
                                }
                            }
                            DnsAnswerData::Aaaa(v6) if self.ipv6 => {
                                let ip = IpAddr::V6(v6);
                                if !self.is_fake_ip(ip) && !resolved.contains(&ip) {
                                    resolved.push(ip);
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
        (resolved, min_pos_ttl, min_neg_ttl, saw_nxdomain, saw_nodata)
    }

    async fn query_slice_ips(
        &self,
        slice: &[DnsUpstream],
        normalized: &str,
    ) -> (Vec<IpAddr>, Option<u64>, Option<u64>, bool, bool) {
        let metas = if self.ipv6 {
            let (m_a, m_aaaa) = tokio::join!(
                self.query_slice_qtype(slice, normalized, QTYPE_A),
                self.query_slice_qtype(slice, normalized, QTYPE_AAAA)
            );
            [m_a, m_aaaa]
        } else {
            [
                self.query_slice_qtype(slice, normalized, QTYPE_A).await,
                None,
            ]
        };
        self.collect_ips_from_metas(metas)
    }

    /// Resolve a domain name to real IPv4 (and IPv6 if `dns.ipv6: true`) addresses via static `hosts`,
    /// `nameserver-policy`, or configured `nameserver` / `fallback` upstreams with TTL-aware positive
    /// and negative caching and singleflight coalescing.
    /// Never falls back to OS `lookup_host` when `nameserver`s are configured.
    pub async fn resolve_real_ips(&self, domain: &str) -> Result<Vec<IpAddr>> {
        let normalized = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        if normalized.is_empty() {
            return Err(ProxyError::Dns("cannot resolve empty domain".into()));
        }
        if let Ok(ip) = normalized.parse::<IpAddr>() {
            if self.is_fake_ip(ip) {
                return Err(ProxyError::Dns(format!(
                    "refusing to treat Fake-IP {ip} as real upstream address"
                )));
            }
            return Ok(vec![ip]);
        }
        if normalized == "localhost" {
            return if self.ipv6 {
                Ok(vec![
                    IpAddr::V4(Ipv4Addr::LOCALHOST),
                    IpAddr::V6(Ipv6Addr::LOCALHOST),
                ])
            } else {
                Ok(vec![IpAddr::V4(Ipv4Addr::LOCALHOST)])
            };
        }
        if let Some(static_ips) = self.lookup_static_hosts_filtered(&normalized) {
            return Ok(static_ips);
        }

        if let Some(cached) = Self::lookup_cached_ips(&self.real_ip_cache, &normalized) {
            self.cache_hits.fetch_add(1, Ordering::Relaxed);
            return cached;
        }

        let _inflight_guard = {
            let waiter = match self.inflight_real.entry(normalized.clone()) {
                Entry::Occupied(occ) => Err(occ.get().subscribe()),
                Entry::Vacant(vac) => {
                    let (tx, _rx) = watch::channel(false);
                    vac.insert(tx.clone());
                    Ok(InflightLookupGuard {
                        map: &self.inflight_real,
                        key: normalized.clone(),
                        tx,
                    })
                }
            };
            match waiter {
                Ok(guard) => Some(guard),
                Err(mut rx) => {
                    let _ = tokio::time::timeout(Duration::from_secs(4), rx.wait_for(|&done| done))
                        .await;
                    if let Some(cached) = Self::lookup_cached_ips(&self.real_ip_cache, &normalized)
                    {
                        return cached;
                    }
                    None
                }
            }
        };

        if let Some(cached) = Self::lookup_cached_ips(&self.real_ip_cache, &normalized) {
            return cached;
        }

        let (mut resolved, min_pos_ttl, min_neg_ttl, saw_nxdomain, saw_nodata) =
            if let Some(policy_ups) =
                Self::matching_policy_upstreams(&self.policy_rules, &normalized)
            {
                self.query_slice_ips(policy_ups, &normalized).await
            } else if !self.upstreams.is_empty() || !self.fallbacks.is_empty() {
                let metas = if self.ipv6 {
                    let (m_a, m_aaaa) = tokio::join!(
                        self.query_upstream_qtype(&normalized, QTYPE_A),
                        self.query_upstream_qtype(&normalized, QTYPE_AAAA)
                    );
                    [m_a, m_aaaa]
                } else {
                    [self.query_upstream_qtype(&normalized, QTYPE_A).await, None]
                };
                self.collect_ips_from_metas(metas)
            } else {
                (Vec::new(), None, None, false, false)
            };

        if resolved.is_empty()
            && !self.enabled
            && self.upstreams.is_empty()
            && self.fallbacks.is_empty()
            && Self::matching_policy_upstreams(&self.policy_rules, &normalized).is_none()
        {
            // Only when the DNS engine itself is explicitly disabled (`dns.enable: false`) and no
            // upstreams were provided, allow system lookup while still filtering Fake-IPs.
            if let Ok(Ok(iter)) = tokio::time::timeout(
                Duration::from_secs(2),
                tokio::net::lookup_host((normalized.as_str(), 0)),
            )
            .await
            {
                for sa in iter {
                    let ip = sa.ip();
                    if (!ip.is_ipv6() || self.ipv6)
                        && !self.is_fake_ip(ip)
                        && !resolved.contains(&ip)
                    {
                        resolved.push(ip);
                    }
                }
            }
        }

        if resolved.is_empty() {
            if saw_nxdomain || saw_nodata {
                let ttl = min_neg_ttl.unwrap_or(15);
                self.real_ip_cache.lock().put(
                    normalized.clone(),
                    CachedIpResolution::Negative {
                        expires_at: Instant::now() + Duration::from_secs(ttl),
                        nxdomain: saw_nxdomain,
                    },
                );
            }
            if saw_nxdomain {
                return Err(ProxyError::Dns(format!("DNS NXDOMAIN for '{normalized}'")));
            }
            return Err(ProxyError::Dns(format!(
                "DNS resolution failed for '{normalized}'"
            )));
        }

        let ttl = min_pos_ttl.unwrap_or(60);
        self.real_ip_cache.lock().put(
            normalized,
            CachedIpResolution::Positive {
                expires_at: Instant::now() + Duration::from_secs(ttl),
                ips: resolved.clone(),
            },
        );
        Ok(resolved)
    }

    /// Resolve a domain name for `DIRECT` outbound dialing and `GEOIP,CN` rule matching.
    /// Honors static `hosts` and (when `direct-nameserver-follow-policy: true`, the default)
    /// `nameserver-policy` before `dns.direct-nameserver`, falling back cleanly to `resolve_real_ips`.
    pub async fn resolve_direct_ips(&self, domain: &str) -> Result<Vec<IpAddr>> {
        let normalized = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        if normalized.is_empty() {
            return Err(ProxyError::Dns("cannot resolve empty domain".into()));
        }
        if let Ok(ip) = normalized.parse::<IpAddr>() {
            if self.is_fake_ip(ip) {
                return Err(ProxyError::Dns(format!(
                    "refusing to treat Fake-IP {ip} as real direct address"
                )));
            }
            return Ok(vec![ip]);
        }
        if normalized == "localhost" {
            return if self.ipv6 {
                Ok(vec![
                    IpAddr::V4(Ipv4Addr::LOCALHOST),
                    IpAddr::V6(Ipv6Addr::LOCALHOST),
                ])
            } else {
                Ok(vec![IpAddr::V4(Ipv4Addr::LOCALHOST)])
            };
        }
        if let Some(static_ips) = self.lookup_static_hosts_filtered(&normalized) {
            return Ok(static_ips);
        }
        if self.direct_upstreams.is_empty()
            || (self.direct_nameserver_follow_policy
                && Self::matching_policy_upstreams(&self.policy_rules, &normalized).is_some())
        {
            return self.resolve_real_ips(domain).await;
        }

        if let Some(cached) = Self::lookup_cached_ips(&self.direct_ip_cache, &normalized) {
            self.cache_hits.fetch_add(1, Ordering::Relaxed);
            return cached;
        }

        let inflight_guard = {
            let waiter = match self.inflight_direct.entry(normalized.clone()) {
                Entry::Occupied(occ) => Err(occ.get().subscribe()),
                Entry::Vacant(vac) => {
                    let (tx, _rx) = watch::channel(false);
                    vac.insert(tx.clone());
                    Ok(InflightLookupGuard {
                        map: &self.inflight_direct,
                        key: normalized.clone(),
                        tx,
                    })
                }
            };
            match waiter {
                Ok(guard) => Some(guard),
                Err(mut rx) => {
                    let _ = tokio::time::timeout(Duration::from_secs(4), rx.wait_for(|&done| done))
                        .await;
                    if let Some(cached) =
                        Self::lookup_cached_ips(&self.direct_ip_cache, &normalized)
                    {
                        return cached;
                    }
                    return self.resolve_real_ips(domain).await;
                }
            }
        };

        if let Some(cached) = Self::lookup_cached_ips(&self.direct_ip_cache, &normalized) {
            return cached;
        }

        let (resolved, min_pos_ttl, min_neg_ttl, saw_nxdomain, saw_nodata) = self
            .query_slice_ips(&self.direct_upstreams, &normalized)
            .await;

        if !resolved.is_empty() {
            let ttl = min_pos_ttl.unwrap_or(60);
            self.direct_ip_cache.lock().put(
                normalized,
                CachedIpResolution::Positive {
                    expires_at: Instant::now() + Duration::from_secs(ttl),
                    ips: resolved.clone(),
                },
            );
            return Ok(resolved);
        }

        if saw_nxdomain || saw_nodata {
            let neg_ttl_secs = min_neg_ttl.unwrap_or(5).clamp(2, 60);
            self.direct_ip_cache.lock().put(
                normalized.clone(),
                CachedIpResolution::Negative {
                    expires_at: Instant::now() + Duration::from_secs(neg_ttl_secs),
                    nxdomain: saw_nxdomain,
                },
            );
            drop(inflight_guard);
            return Err(ProxyError::Dns(if saw_nxdomain {
                format!("DNS NXDOMAIN for '{normalized}'")
            } else {
                format!("DNS resolution failed for '{normalized}'")
            }));
        }

        drop(inflight_guard);
        self.resolve_real_ips(domain).await
    }

    /// Resolve a domain-based proxy node server hostname (`server: hk01.example.com`)
    /// honoring Clash Meta / Mihomo split-horizon DNS hierarchy:
    /// 1. Static `hosts` (when `use-hosts: true`)
    /// 2. `proxy-server-nameserver-policy`
    /// 3. `proxy-server-nameserver`
    /// 4. `nameserver-policy`
    /// 5. `nameserver` / `fallback` & `direct-nameserver`
    /// 6. `default-nameserver` -> OS fallback (while strictly rejecting Fake-IPs)
    pub async fn resolve_proxy_server_ips(&self, host: &str) -> Result<Vec<IpAddr>> {
        let clean = host
            .trim()
            .trim_start_matches('[')
            .trim_end_matches(']')
            .trim_end_matches('.')
            .to_ascii_lowercase();
        if clean.is_empty() {
            return Err(ProxyError::Dns("proxy server host cannot be empty".into()));
        }
        if let Ok(ip) = clean.parse::<IpAddr>() {
            if self.is_fake_ip(ip) {
                return Err(ProxyError::Dns(format!(
                    "proxy server address {ip} falls inside Fake-IP range {}",
                    self.net
                )));
            }
            return Ok(vec![ip]);
        }
        if clean == "localhost" {
            return Ok(vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]);
        }
        if let Some(static_ips) = self.lookup_static_hosts_for_endpoint(&clean) {
            return Ok(static_ips);
        }

        if let Some(cached) = Self::lookup_cached_ips(&self.proxy_ip_cache, &clean) {
            self.cache_hits.fetch_add(1, Ordering::Relaxed);
            return cached;
        }

        let _inflight_guard = {
            let waiter = match self.inflight_proxy.entry(clean.clone()) {
                Entry::Occupied(occ) => Err(occ.get().subscribe()),
                Entry::Vacant(vac) => {
                    let (tx, _rx) = watch::channel(false);
                    vac.insert(tx.clone());
                    Ok(InflightLookupGuard {
                        map: &self.inflight_proxy,
                        key: clean.clone(),
                        tx,
                    })
                }
            };
            match waiter {
                Ok(guard) => Some(guard),
                Err(mut rx) => {
                    let _ = tokio::time::timeout(Duration::from_secs(4), rx.wait_for(|&done| done))
                        .await;
                    if let Some(cached) = Self::lookup_cached_ips(&self.proxy_ip_cache, &clean) {
                        return cached;
                    }
                    None
                }
            }
        };

        if let Some(cached) = Self::lookup_cached_ips(&self.proxy_ip_cache, &clean) {
            return cached;
        }

        let cache_and_return = |ips: Vec<IpAddr>, ttl_opt: Option<u64>| -> Result<Vec<IpAddr>> {
            let ttl = ttl_opt.unwrap_or(60);
            self.proxy_ip_cache.lock().put(
                clean.clone(),
                CachedIpResolution::Positive {
                    expires_at: Instant::now() + Duration::from_secs(ttl),
                    ips: ips.clone(),
                },
            );
            Ok(ips)
        };

        // 1. Dedicated `proxy-server-nameserver-policy`
        if let Some(ps_pol) = Self::matching_policy_upstreams(&self.proxy_policy_rules, &clean) {
            let (ips, pos_ttl, neg_ttl, saw_nx, saw_nodata) =
                self.query_slice_ips(ps_pol, &clean).await;
            if !ips.is_empty() {
                return cache_and_return(ips, pos_ttl);
            }
            if saw_nx || saw_nodata {
                self.proxy_ip_cache.lock().put(
                    clean.clone(),
                    CachedIpResolution::Negative {
                        expires_at: Instant::now() + Duration::from_secs(neg_ttl.unwrap_or(15)),
                        nxdomain: saw_nx,
                    },
                );
            }
            return Err(ProxyError::Dns(format!(
                "proxy-server-nameserver-policy DNS resolution failed for '{clean}'"
            )));
        }

        // 2. Dedicated `proxy-server-nameserver`
        if !self.proxy_upstreams.is_empty() {
            let (ips, pos_ttl, neg_ttl, saw_nx, saw_nodata) =
                self.query_slice_ips(&self.proxy_upstreams, &clean).await;
            if !ips.is_empty() {
                return cache_and_return(ips, pos_ttl);
            }
            if saw_nx || saw_nodata {
                self.proxy_ip_cache.lock().put(
                    clean.clone(),
                    CachedIpResolution::Negative {
                        expires_at: Instant::now() + Duration::from_secs(neg_ttl.unwrap_or(15)),
                        nxdomain: saw_nx,
                    },
                );
            }
            return Err(ProxyError::Dns(format!(
                "proxy-server-nameserver DNS resolution failed for '{clean}'"
            )));
        }

        // 3. Domain-scoped `nameserver-policy` (used by subscriptions with self-hosted DoH/DoT!)
        if let Some(pol) = Self::matching_policy_upstreams(&self.policy_rules, &clean) {
            let (ips, pos_ttl, neg_ttl, saw_nx, saw_nodata) =
                self.query_slice_ips(pol, &clean).await;
            if !ips.is_empty() {
                return cache_and_return(ips, pos_ttl);
            }
            if saw_nx || saw_nodata {
                self.proxy_ip_cache.lock().put(
                    clean.clone(),
                    CachedIpResolution::Negative {
                        expires_at: Instant::now() + Duration::from_secs(neg_ttl.unwrap_or(15)),
                        nxdomain: saw_nx,
                    },
                );
            }
            return Err(ProxyError::Dns(
                "nameserver-policy DNS resolution failed for proxy server".into(),
            ));
        }

        // 4. Configured `nameserver` / `fallback` & `direct-nameserver`
        if let Ok(ips) = self.resolve_real_ips(&clean).await
            && !ips.is_empty()
        {
            return cache_and_return(ips, Some(60));
        }
        if !self.direct_upstreams.is_empty()
            && let Ok(ips) = self.resolve_direct_ips(&clean).await
            && !ips.is_empty()
        {
            return cache_and_return(ips, Some(60));
        }

        // 5. Literal-IP `default-nameserver` bootstrap & OS fallback bypassing Fake-IP
        if let Ok(ips) = self
            .resolve_bootstrap_host(&DnsEndpointHost::Domain(clean.clone()))
            .await
            && !ips.is_empty()
        {
            return cache_and_return(ips, Some(60));
        }

        let addrs = crate::router::geodata::resolve_host_bypassing_fake_ip(&clean, 0).await?;
        let ips: Vec<IpAddr> = addrs
            .into_iter()
            .map(|sa| sa.ip())
            .filter(|ip| !self.is_fake_ip(*ip))
            .collect();
        if ips.is_empty() {
            return Err(ProxyError::Dns(
                "unable to resolve real IP for proxy server".into(),
            ));
        }
        cache_and_return(ips, Some(60))
    }

    pub fn entries_snapshot(&self) -> Vec<FakeIpEntry> {
        self.pool.lock().snapshot()
    }

    pub fn entry_count(&self) -> usize {
        self.pool.lock().ip_to_domain.len()
    }

    /// Persist up to `2048` MRU Fake-IP <-> domain mappings atomically via a sibling `.json.tmp` file.
    pub fn save_to_path(&self, path: &std::path::Path) -> std::io::Result<usize> {
        let mut entries = self.entries_snapshot();
        entries.truncate(MAX_PERSISTED_FAKE_IP_ENTRIES);
        let saved_count = entries.len();
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)?;
        }
        let payload = PersistedFakeIpState {
            version: 1,
            fake_ip_range: self.net.to_string(),
            saved_at_epoch_ms: current_epoch_ms(),
            entries,
        };
        let encoded = serde_json::to_vec(&payload).map_err(std::io::Error::other)?;
        let tmp_path = path.with_extension("json.tmp");
        std::fs::write(&tmp_path, &encoded)?;
        if let Err(err) = std::fs::rename(&tmp_path, path) {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(err);
        }
        Ok(saved_count)
    }

    /// Restore persisted Fake-IP <-> domain mappings from `path`, preserving MRU order and
    /// skipping missing/corrupt files, mismatched `fake-ip-range`, entries older than 7 days, or bypassed domains.
    pub fn load_from_path(&self, path: &std::path::Path) -> usize {
        let Ok(raw) = std::fs::read(path) else {
            return 0;
        };
        let Ok(parsed) = serde_json::from_slice::<PersistedFakeIpState>(&raw) else {
            return 0;
        };
        if parsed.version != 1 || parsed.fake_ip_range != self.net.to_string() {
            return 0;
        }
        let now_ms = current_epoch_ms();
        if now_ms > parsed.saved_at_epoch_ms
            && (now_ms - parsed.saved_at_epoch_ms) > MAX_FAKE_IP_PERSIST_AGE_MS
        {
            return 0;
        }
        let mut loaded = 0usize;
        let mut guard = self.pool.lock();
        for entry in parsed.entries.into_iter().rev() {
            if let Ok(v4) = entry.ip.parse::<Ipv4Addr>()
                && !self.should_bypass_fake_ip(&entry.domain)
                && guard.insert_preserved(v4, &entry.domain, self.net)
            {
                loaded += 1;
            }
        }
        loaded
    }

    pub fn total_queries(&self) -> u64 {
        self.total_queries.load(Ordering::Relaxed)
    }

    pub fn telemetry_snapshot(&self) -> DnsTelemetrySnapshot {
        let up_q = self.upstream_queries.load(Ordering::Relaxed);
        let up_err = self.upstream_errors.load(Ordering::Relaxed);
        let up_ok = up_q.saturating_sub(up_err);
        let total_ms = self.upstream_total_ms.load(Ordering::Relaxed);
        let avg_ms = total_ms.checked_div(up_ok).unwrap_or(0);
        DnsTelemetrySnapshot {
            total_queries: self.total_queries.load(Ordering::Relaxed),
            fake_ip_hits: self.fake_ip_hits.load(Ordering::Relaxed),
            cache_hits: self.cache_hits.load(Ordering::Relaxed),
            suppressed_queries: self.suppressed_queries.load(Ordering::Relaxed),
            nxdomain_hits: self.nxdomain_hits.load(Ordering::Relaxed),
            upstream_queries: up_q,
            upstream_errors: up_err,
            upstream_avg_ms: avg_ms,
            upstream_max_ms: self.upstream_max_ms.load(Ordering::Relaxed),
            active_fake_ip_entries: self.entry_count(),
        }
    }

    fn has_cached_nxdomain(&self, normalized: &str) -> bool {
        let now = Instant::now();
        let in_direct = matches!(
            self.direct_ip_cache.lock().peek(normalized),
            Some(CachedIpResolution::Negative {
                expires_at,
                nxdomain: true,
            }) if *expires_at > now
        );
        if in_direct {
            return true;
        }
        matches!(
            self.real_ip_cache.lock().peek(normalized),
            Some(CachedIpResolution::Negative {
                expires_at,
                nxdomain: true,
            }) if *expires_at > now
        )
    }

    /// Process a raw RFC 1035 DNS request packet, returning the encoded DNS response packet.
    pub async fn handle_dns_packet(&self, raw_query: &[u8]) -> Result<Vec<u8>> {
        self.total_queries.fetch_add(1, Ordering::Relaxed);
        let query = DnsQueryPacket::parse(raw_query)?;
        let domain = query.question.name.as_str();
        let normalized = domain.trim().trim_end_matches('.').to_ascii_lowercase();

        // Built-in localhost resolution
        if normalized == "localhost" {
            self.cache_hits.fetch_add(1, Ordering::Relaxed);
            return match query.question.qtype {
                QTYPE_A => Ok(query.build_response(
                    raw_query,
                    0,
                    60,
                    &[DnsAnswerData::A(Ipv4Addr::LOCALHOST)],
                )),
                QTYPE_AAAA if self.ipv6 => Ok(query.build_response(
                    raw_query,
                    0,
                    60,
                    &[DnsAnswerData::Aaaa(Ipv6Addr::LOCALHOST)],
                )),
                _ => Ok(query.build_response(raw_query, 0, 60, &[])),
            };
        }

        // Enforce `dns.ipv6: false` across ALL modes so IPv6 queries never leak or stall Happy-Eyeballs
        if !self.ipv6 && query.question.qtype == QTYPE_AAAA {
            self.suppressed_queries.fetch_add(1, Ordering::Relaxed);
            return Ok(query.build_response(raw_query, 0, 5, &[]));
        }

        // Static `hosts` lookup takes precedence before Fake-IP allocation (matching Clash Meta / Mihomo)
        if let Some(static_ips) = self.lookup_static_hosts_raw(&normalized) {
            self.cache_hits.fetch_add(1, Ordering::Relaxed);
            return match query.question.qtype {
                QTYPE_A => {
                    let answers: Vec<DnsAnswerData> = static_ips
                        .iter()
                        .filter_map(|ip| match ip {
                            IpAddr::V4(v4) if !self.is_fake_ip(*ip) => Some(DnsAnswerData::A(*v4)),
                            _ => None,
                        })
                        .collect();
                    Ok(query.build_response(raw_query, 0, 60, &answers))
                }
                QTYPE_AAAA => {
                    let answers: Vec<DnsAnswerData> = static_ips
                        .iter()
                        .filter_map(|ip| match ip {
                            IpAddr::V6(v6) if self.ipv6 && !self.is_fake_ip(*ip) => {
                                Some(DnsAnswerData::Aaaa(*v6))
                            }
                            _ => None,
                        })
                        .collect();
                    Ok(query.build_response(raw_query, 0, 60, &answers))
                }
                _ => Ok(query.build_response(raw_query, 0, 60, &[])),
            };
        }

        if self.enabled
            && self.fake_ip_mode
            && query.question.qtype == QTYPE_PTR
            && let Some(v4) = parse_in_addr_arpa_v4(&normalized)
            && self.is_fake_ip(IpAddr::V4(v4))
        {
            if let Some(host) = self.lookup_domain(IpAddr::V4(v4)) {
                self.fake_ip_hits.fetch_add(1, Ordering::Relaxed);
                return Ok(query.build_ptr_response(raw_query, 1, &host));
            }
            self.cache_hits.fetch_add(1, Ordering::Relaxed);
            self.nxdomain_hits.fetch_add(1, Ordering::Relaxed);
            return Ok(query.build_response(raw_query, 3, 1, &[]));
        }

        if self.enabled && self.fake_ip_mode && !self.should_bypass_fake_ip(&normalized) {
            match query.question.qtype {
                QTYPE_A | QTYPE_AAAA | QTYPE_SVCB | QTYPE_HTTPS
                    if self.has_cached_nxdomain(&normalized) =>
                {
                    self.cache_hits.fetch_add(1, Ordering::Relaxed);
                    self.nxdomain_hits.fetch_add(1, Ordering::Relaxed);
                    return Ok(query.build_response(raw_query, 3, 5, &[]));
                }
                QTYPE_A => {
                    self.fake_ip_hits.fetch_add(1, Ordering::Relaxed);
                    let fake_ip = self.assign_fake_ip(&normalized);
                    return Ok(query.build_response(
                        raw_query,
                        0,
                        1, // 1s TTL prevents stale OS DNS cache across restarts
                        &[DnsAnswerData::A(fake_ip)],
                    ));
                }
                QTYPE_AAAA | QTYPE_SVCB | QTYPE_HTTPS => {
                    self.fake_ip_hits.fetch_add(1, Ordering::Relaxed);
                    return Ok(query.build_response(raw_query, 0, 1, &[]));
                }
                _ => {}
            }
        }

        // Check TTL-aware wire packet cache (`redir-host` / `normal` / bypassed domains)
        let cache_key = (normalized.clone(), query.question.qtype);
        if let Some(cached) = self.packet_cache.lock().get(&cache_key).cloned()
            && Instant::now() < cached.expires_at
            && cached.wire.len() >= 12
        {
            self.cache_hits.fetch_add(1, Ordering::Relaxed);
            let mut hit = cached.wire;
            hit[0] = raw_query[0];
            hit[1] = raw_query[1];
            return Ok(hit);
        }

        let upstream_res = if let Some(pol_ups) =
            Self::matching_policy_upstreams(&self.policy_rules, &normalized)
        {
            self.exchange_with_upstream_slice(pol_ups, raw_query).await
        } else {
            self.exchange_with_upstreams(raw_query).await
        };

        if let Ok(resp) = upstream_res {
            if let Ok(meta) = extract_dns_response_meta(&resp) {
                if meta.rcode == 0 && !meta.answers.is_empty() {
                    let ttl = u64::from(meta.min_ttl.unwrap_or(60))
                        .clamp(MIN_POSITIVE_TTL_SECS, MAX_POSITIVE_TTL_SECS);
                    self.packet_cache.lock().put(
                        cache_key,
                        CachedWirePacket {
                            expires_at: Instant::now() + Duration::from_secs(ttl),
                            wire: resp.clone(),
                        },
                    );
                } else if meta.rcode == 3 || (meta.rcode == 0 && meta.answers.is_empty()) {
                    let ttl = u64::from(meta.min_ttl.unwrap_or(30))
                        .clamp(MIN_NEGATIVE_TTL_SECS, MAX_NEGATIVE_TTL_SECS);
                    self.packet_cache.lock().put(
                        cache_key,
                        CachedWirePacket {
                            expires_at: Instant::now() + Duration::from_secs(ttl),
                            wire: resp.clone(),
                        },
                    );
                }
            }
            return Ok(resp);
        }

        // Return SERVFAIL (2) if no upstream responded
        Ok(query.build_response(raw_query, 2, 0, &[]))
    }

    /// High-level helper for `/dns/query?name=...&type=...` API endpoint.
    pub async fn query_records(&self, domain: &str, qtype: u16) -> Result<Vec<String>> {
        let tx_id: u16 = rand::random();
        let pkt = build_dns_query(tx_id, domain, qtype);
        let resp = self.handle_dns_packet(&pkt).await?;
        let answers = extract_ip_answers(&resp)?;
        Ok(answers
            .into_iter()
            .map(|a| match a {
                DnsAnswerData::A(v4) => v4.to_string(),
                DnsAnswerData::Aaaa(v6) => v6.to_string(),
                DnsAnswerData::Txt(t) => t,
            })
            .collect())
    }

    /// Spawn a local UDP DNS server listening on `listen_addr` with bounded concurrency.
    pub async fn spawn_udp_server(
        self: Arc<Self>,
        listen_addr: &str,
        mut shutdown: watch::Receiver<bool>,
    ) -> Result<(SocketAddr, JoinHandle<()>)> {
        let sock = Arc::new(
            UdpSocket::bind(listen_addr)
                .await
                .map_err(|e| ProxyError::Dns(format!("bind DNS UDP {listen_addr} failed: {e}")))?,
        );
        let local_addr = sock.local_addr()?;
        let sem = Arc::new(Semaphore::new(MAX_CONCURRENT_DNS_UDP_TASKS));

        let handle = tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                tokio::select! {
                    changed = shutdown.changed() => {
                        if changed.is_err() || *shutdown.borrow() {
                            break;
                        }
                    }
                    recv_res = sock.recv_from(&mut buf) => {
                        let Ok((n, peer)) = recv_res else {
                            continue;
                        };
                        let Ok(permit) = Arc::clone(&sem).try_acquire_owned() else {
                            continue;
                        };
                        let req = buf[..n].to_vec();
                        let engine = Arc::clone(&self);
                        let sock_clone = Arc::clone(&sock);
                        tokio::spawn(async move {
                            let _permit = permit;
                            if let Ok(resp) = engine.handle_dns_packet(&req).await {
                                let _ = sock_clone.send_to(&resp, peer).await;
                            }
                        });
                    }
                }
            }
        });

        Ok((local_addr, handle))
    }

    /// Spawn a local RFC 1035 TCP DNS server (2-byte length-prefixed messages) on `listen_addr`.
    pub async fn spawn_tcp_server(
        self: Arc<Self>,
        listen_addr: &str,
        mut shutdown: watch::Receiver<bool>,
    ) -> Result<(SocketAddr, JoinHandle<()>)> {
        let listener = TcpListener::bind(listen_addr)
            .await
            .map_err(|e| ProxyError::Dns(format!("bind DNS TCP {listen_addr} failed: {e}")))?;
        let local_addr = listener.local_addr()?;
        let sem = Arc::new(Semaphore::new(MAX_CONCURRENT_DNS_TCP_CONNS));

        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    changed = shutdown.changed() => {
                        if changed.is_err() || *shutdown.borrow() {
                            break;
                        }
                    }
                    accepted = listener.accept() => {
                        let Ok((stream, _peer)) = accepted else {
                            continue;
                        };
                        let Ok(permit) = Arc::clone(&sem).try_acquire_owned() else {
                            continue;
                        };
                        let engine = Arc::clone(&self);
                        tokio::spawn(async move {
                            let _permit = permit;
                            let _ = handle_local_tcp_dns_conn(engine, stream).await;
                        });
                    }
                }
            }
        });

        Ok((local_addr, handle))
    }
}

async fn handle_local_tcp_dns_conn(
    engine: Arc<FakeIpDnsEngine>,
    mut stream: TcpStream,
) -> Result<()> {
    let _ = stream.set_nodelay(true);
    for _ in 0..32 {
        let len = match tokio::time::timeout(Duration::from_secs(5), stream.read_u16()).await {
            Ok(Ok(l)) if (12..=8192).contains(&l) => l as usize,
            _ => break,
        };
        let mut req = vec![0u8; len];
        if tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut req))
            .await
            .is_err()
        {
            break;
        }
        let resp = engine.handle_dns_packet(&req).await?;
        if resp.len() > u16::MAX as usize {
            break;
        }
        let mut out = BytesMut::with_capacity(2 + resp.len());
        out.put_u16(resp.len() as u16);
        out.put_slice(&resp);
        if tokio::time::timeout(Duration::from_secs(5), stream.write_all(&out))
            .await
            .is_err()
        {
            break;
        }
    }
    Ok(())
}

fn parse_in_addr_arpa_v4(normalized: &str) -> Option<Ipv4Addr> {
    let prefix = normalized.strip_suffix(".in-addr.arpa")?;
    let mut octets = [0u8; 4];
    let mut parts = prefix.split('.');
    for slot in octets.iter_mut().rev() {
        let part = parts.next()?;
        *slot = part.parse::<u8>().ok()?;
    }
    if parts.next().is_some() {
        return None;
    }
    Some(Ipv4Addr::from(octets))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::wire::{
        QCLASS_IN, QTYPE_MX, QTYPE_TXT, decode_domain_name, dns_response_rcode, encode_domain_name,
    };

    #[tokio::test]
    async fn fake_ip_allocates_deterministic_ip_and_restores_domain() {
        let engine = FakeIpDnsEngine::new(&DnsConfig::default()).unwrap();

        let q1 = build_dns_query(0x42, "api.github.com", QTYPE_A);
        let r1 = engine.handle_dns_packet(&q1).await.unwrap();
        let ips = extract_ip_answers(&r1).unwrap();
        assert_eq!(ips.len(), 1);
        let DnsAnswerData::A(fake_ip) = ips[0] else {
            panic!("expected IPv4 answer");
        };
        assert!(engine.is_fake_ip(IpAddr::V4(fake_ip)));
        assert_eq!(fake_ip, Ipv4Addr::new(198, 18, 0, 2));

        // AAAA query returns empty NOERROR so Happy-Eyeballs picks IPv4 Fake-IP immediately
        let q_aaaa = build_dns_query(0x43, "api.github.com", QTYPE_AAAA);
        let r_aaaa = engine.handle_dns_packet(&q_aaaa).await.unwrap();
        assert!(extract_ip_answers(&r_aaaa).unwrap().is_empty());

        // Reverse restore_target converts 198.18.0.2:443 -> api.github.com:443
        let raw_target = TargetAddr::new_ip(IpAddr::V4(fake_ip), 443);
        let (restored, orig_v4) = engine.restore_target(&raw_target);
        assert_eq!(orig_v4, Some(fake_ip));
        assert_eq!(restored.to_string(), "api.github.com:443");

        // Unmapped Fake-IP detection
        let unmapped = TargetAddr::new_ip(IpAddr::V4(Ipv4Addr::new(198, 18, 9, 9)), 443);
        assert!(engine.is_unmapped_fake_ip(&unmapped));
        assert!(!engine.is_unmapped_fake_ip(&raw_target));

        // Bypass filter check (*.lan, localhost)
        assert!(engine.should_bypass_fake_ip("router.lan"));
        assert!(engine.should_bypass_fake_ip("www.msftconnecttest.com"));
        assert!(!engine.should_bypass_fake_ip("openai.com"));
    }

    #[tokio::test]
    async fn fake_ip_handles_ptr_and_forwards_txt_mx_upstream() {
        let upstream_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_sock.local_addr().unwrap();

        let upstream_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            for _ in 0..2 {
                let (n, peer) = upstream_sock.recv_from(&mut buf).await.unwrap();
                let req = &buf[..n];
                let parsed = DnsQueryPacket::parse(req).unwrap();
                let resp = match parsed.question.qtype {
                    QTYPE_TXT => parsed.build_response(
                        req,
                        0,
                        120,
                        &[DnsAnswerData::Txt("v=spf1 -all".to_string())],
                    ),
                    QTYPE_MX => {
                        let mut mx_rdata = BytesMut::new();
                        mx_rdata.put_u16(10);
                        encode_domain_name("mx1.example.com", &mut mx_rdata);

                        let mut out = BytesMut::new();
                        out.put_u16(parsed.id);
                        out.put_u16(0x8180);
                        out.put_u16(1);
                        out.put_u16(1);
                        out.put_u16(0);
                        out.put_u16(0);
                        out.put_slice(&req[12..parsed.question.end_offset]);
                        out.put_u16(0xC00C);
                        out.put_u16(QTYPE_MX);
                        out.put_u16(QCLASS_IN);
                        out.put_u32(120);
                        out.put_u16(mx_rdata.len() as u16);
                        out.put_slice(&mx_rdata);
                        out.to_vec()
                    }
                    other => panic!("unexpected upstream qtype {other}"),
                };
                upstream_sock.send_to(&resp, peer).await.unwrap();
            }
        });

        let cfg = DnsConfig {
            nameserver: vec![upstream_addr.to_string()],
            fallback: Vec::new(),
            ..DnsConfig::default()
        };
        let engine = FakeIpDnsEngine::new(&cfg).unwrap();

        // 1. A query allocates Fake-IP 198.18.0.2 and increments fake_ip_hits -> 1
        let q_a = build_dns_query(0x1001, "mail.example.com", QTYPE_A);
        let r_a = engine.handle_dns_packet(&q_a).await.unwrap();
        assert_eq!(
            extract_ip_answers(&r_a).unwrap(),
            vec![DnsAnswerData::A(Ipv4Addr::new(198, 18, 0, 2))]
        );
        assert_eq!(engine.fake_ip_hits.load(Ordering::Relaxed), 1);

        // 2. PTR query for 2.0.18.198.in-addr.arpa resolves locally to mail.example.com -> hits = 2
        let q_ptr = build_dns_query(0x1002, "2.0.18.198.in-addr.arpa", QTYPE_PTR);
        let r_ptr = engine.handle_dns_packet(&q_ptr).await.unwrap();
        let ptr_q = DnsQueryPacket::parse(&r_ptr).unwrap();
        assert_eq!(u16::from_be_bytes([r_ptr[6], r_ptr[7]]), 1); // ANCOUNT == 1
        let rdata_offset = ptr_q.question.end_offset + 12; // 2B ptr + 2B type + 2B class + 4B ttl + 2B rdlen
        let (ptr_target, _) = decode_domain_name(&r_ptr, rdata_offset).unwrap();
        assert_eq!(ptr_target, "mail.example.com");
        assert_eq!(engine.fake_ip_hits.load(Ordering::Relaxed), 2);

        // 3. TXT and MX queries are NOT swallowed as empty NOERROR by Fake-IP and forward upstream
        let q_txt = build_dns_query(0x1003, "mail.example.com", QTYPE_TXT);
        let r_txt = engine.handle_dns_packet(&q_txt).await.unwrap();
        assert_eq!(u16::from_be_bytes([r_txt[6], r_txt[7]]), 1);
        assert_eq!(engine.fake_ip_hits.load(Ordering::Relaxed), 2);

        let q_mx = build_dns_query(0x1004, "mail.example.com", QTYPE_MX);
        let r_mx = engine.handle_dns_packet(&q_mx).await.unwrap();
        assert_eq!(u16::from_be_bytes([r_mx[6], r_mx[7]]), 1);
        assert_eq!(engine.fake_ip_hits.load(Ordering::Relaxed), 2);

        upstream_task.await.unwrap();
    }

    #[test]
    fn fake_ip_pool_eviction_keeps_bidirectional_maps_consistent() {
        let net: Ipv4Net = "198.18.0.0/29".parse().unwrap();
        let mut pool = PoolInner::new(net, 64);
        for i in 0..20 {
            let domain = format!("host-{i}.example.com");
            let ip = pool.get_or_assign(&domain);
            assert_eq!(pool.lookup_domain(ip).as_deref(), Some(domain.as_str()));
            assert_eq!(pool.lookup_ip(&domain), Some(ip));
        }
        assert_eq!(pool.domain_to_ip.len(), pool.ip_to_domain.len());
        for (domain, &ip) in &pool.domain_to_ip {
            assert_eq!(pool.ip_to_domain.peek(&ip), Some(domain));
        }
    }

    #[tokio::test]
    async fn resolve_direct_ips_caches_nxdomain_without_falling_back_to_real_ips() {
        let direct_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let direct_addr = direct_sock.local_addr().unwrap();
        let real_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let real_addr = real_sock.local_addr().unwrap();

        let direct_hits = Arc::new(AtomicU64::new(0));
        let real_hits = Arc::new(AtomicU64::new(0));

        let direct_hits_bg = Arc::clone(&direct_hits);
        let direct_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            while let Ok((n, peer)) = direct_sock.recv_from(&mut buf).await {
                direct_hits_bg.fetch_add(1, Ordering::Relaxed);
                let req = &buf[..n];
                let parsed = DnsQueryPacket::parse(req).unwrap();
                let resp = parsed.build_response(req, 3, 30, &[]);
                let _ = direct_sock.send_to(&resp, peer).await;
            }
        });

        let real_hits_bg = Arc::clone(&real_hits);
        let real_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            while let Ok((n, peer)) = real_sock.recv_from(&mut buf).await {
                real_hits_bg.fetch_add(1, Ordering::Relaxed);
                let req = &buf[..n];
                let parsed = DnsQueryPacket::parse(req).unwrap();
                let resp = parsed.build_response(
                    req,
                    0,
                    60,
                    &[DnsAnswerData::A(Ipv4Addr::new(198, 51, 100, 42))],
                );
                let _ = real_sock.send_to(&resp, peer).await;
            }
        });

        let cfg = DnsConfig {
            ipv6: false,
            direct_nameserver: vec![direct_addr.to_string()],
            nameserver: vec![real_addr.to_string()],
            fallback: Vec::new(),
            ..DnsConfig::default()
        };
        let engine = FakeIpDnsEngine::new(&cfg).unwrap();

        let err1 = engine
            .resolve_direct_ips("missing-cn.example.test")
            .await
            .unwrap_err()
            .to_string();
        assert!(err1.contains("NXDOMAIN"), "unexpected error: {err1}");
        assert_eq!(direct_hits.load(Ordering::Relaxed), 1);
        assert_eq!(
            real_hits.load(Ordering::Relaxed),
            0,
            "authoritative NXDOMAIN from direct-nameserver must not leak to nameserver"
        );

        // Second lookup must hit direct_ip_cache without re-querying direct_sock or real_sock
        let err2 = engine
            .resolve_direct_ips("missing-cn.example.test")
            .await
            .unwrap_err()
            .to_string();
        assert!(err2.contains("NXDOMAIN"), "unexpected cached error: {err2}");
        assert_eq!(direct_hits.load(Ordering::Relaxed), 1);
        assert_eq!(real_hits.load(Ordering::Relaxed), 0);

        direct_task.abort();
        real_task.abort();
    }

    #[tokio::test]
    async fn fake_ip_short_circuits_cached_nxdomain_and_assigns_fake_ip_otherwise() {
        let nx_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let nx_addr = nx_sock.local_addr().unwrap();

        let nx_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            while let Ok((n, peer)) = nx_sock.recv_from(&mut buf).await {
                let req = &buf[..n];
                let parsed = DnsQueryPacket::parse(req).unwrap();
                let resp = parsed.build_response(req, 3, 30, &[]);
                let _ = nx_sock.send_to(&resp, peer).await;
            }
        });

        let mut policy = HashMap::new();
        policy.insert(
            "+.real-nx.example.test".to_string(),
            vec![nx_addr.to_string()],
        );
        let cfg = DnsConfig {
            ipv6: false,
            direct_nameserver: vec![nx_addr.to_string()],
            nameserver: vec![nx_addr.to_string()],
            nameserver_policy: policy,
            fallback: Vec::new(),
            ..DnsConfig::default()
        };
        let engine = FakeIpDnsEngine::new(&cfg).unwrap();

        // Populate direct_ip_cache and real_ip_cache with active NXDOMAIN entries
        assert!(
            engine
                .resolve_direct_ips("dead1.example.test")
                .await
                .is_err()
        );
        assert!(
            engine
                .resolve_real_ips("sub.real-nx.example.test")
                .await
                .is_err()
        );

        // Fake-IP DNS packet handler must return RCODE=3 (NXDOMAIN) for both cached NXDOMAINs
        let q_dead1 = build_dns_query(0x2001, "dead1.example.test", QTYPE_A);
        let r_dead1 = engine.handle_dns_packet(&q_dead1).await.unwrap();
        assert_eq!(dns_response_rcode(&r_dead1).unwrap(), 3);
        assert!(extract_ip_answers(&r_dead1).unwrap().is_empty());

        let q_dead2 = build_dns_query(0x2002, "sub.real-nx.example.test", QTYPE_A);
        let r_dead2 = engine.handle_dns_packet(&q_dead2).await.unwrap();
        assert_eq!(dns_response_rcode(&r_dead2).unwrap(), 3);

        // Normal domain without cached NXDOMAIN still receives a Fake-IP
        let q_ok = build_dns_query(0x2003, "healthy.example.test", QTYPE_A);
        let r_ok = engine.handle_dns_packet(&q_ok).await.unwrap();
        assert_eq!(dns_response_rcode(&r_ok).unwrap(), 0);
        let answers = extract_ip_answers(&r_ok).unwrap();
        assert_eq!(
            answers,
            vec![DnsAnswerData::A(Ipv4Addr::new(198, 18, 0, 2))]
        );

        let snap = engine.telemetry_snapshot();
        assert_eq!(snap.nxdomain_hits, 2);

        // Also verify proxy server DNS error string scrubs sensitive proxy hostname
        let proxy_err = engine
            .resolve_proxy_server_ips("secret-node.real-nx.example.test")
            .await
            .unwrap_err()
            .to_string();
        assert!(!proxy_err.contains("secret-node.real-nx.example.test"));

        nx_task.abort();
    }

    #[test]
    fn save_and_load_from_path_round_trips_fake_ip_mappings_across_restart() {
        let persist_path = std::env::temp_dir().join(format!(
            "rust-clash-fakeip-persist-{:032x}.json",
            rand::random::<u128>()
        ));

        let engine1 = FakeIpDnsEngine::new(&DnsConfig::default()).unwrap();
        let ip_a = engine1.assign_fake_ip("alpha.example.com");
        let ip_b = engine1.assign_fake_ip("beta.example.com");
        let ip_c = engine1.assign_fake_ip("gamma.example.com");
        // Touch alpha so MRU order is: alpha, gamma, beta
        assert_eq!(engine1.assign_fake_ip("alpha.example.com"), ip_a);

        let saved = engine1.save_to_path(&persist_path).unwrap();
        assert_eq!(saved, 3);

        let engine2 = FakeIpDnsEngine::new(&DnsConfig::default()).unwrap();
        let loaded = engine2.load_from_path(&persist_path);
        assert_eq!(loaded, 3);

        // MRU order preserved immediately on load (alpha is first in snapshot before lookups mutate recency)
        let snap = engine2.entries_snapshot();
        assert_eq!(snap.len(), 3);
        assert_eq!(snap[0].domain, "alpha.example.com");
        assert_eq!(snap[1].domain, "gamma.example.com");
        assert_eq!(snap[2].domain, "beta.example.com");

        assert_eq!(engine2.lookup_ip("alpha.example.com"), Some(ip_a));
        assert_eq!(engine2.lookup_ip("beta.example.com"), Some(ip_b));
        assert_eq!(engine2.lookup_ip("gamma.example.com"), Some(ip_c));
        assert_eq!(
            engine2.lookup_domain(IpAddr::V4(ip_b)).as_deref(),
            Some("beta.example.com")
        );

        // Subsequent new assignment advances cursor past restored IPs without collision
        let ip_d = engine2.assign_fake_ip("delta.example.com");
        assert_ne!(ip_d, ip_a);
        assert_ne!(ip_d, ip_b);
        assert_ne!(ip_d, ip_c);
        assert_eq!(engine2.assign_fake_ip("alpha.example.com"), ip_a);

        let _ = std::fs::remove_file(&persist_path);
    }
}

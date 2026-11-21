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
    sync::{Notify, Semaphore, watch},
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
            patch_cached_dns_wire_response,
        },
    },
    error::{ProxyError, Result},
};

const MIN_POSITIVE_TTL_SECS: u64 = 5;
const MAX_POSITIVE_TTL_SECS: u64 = 3600;
const MIN_NEGATIVE_TTL_SECS: u64 = 5;
const MAX_NEGATIVE_TTL_SECS: u64 = 60;
const MIN_NXDOMAIN_TTL_SECS: u64 = 60;
const DEFAULT_NXDOMAIN_TTL_SECS: u64 = 180;
const MAX_NXDOMAIN_TTL_SECS: u64 = 600;
const SERVFAIL_NEGATIVE_TTL_SECS: u64 = 2;
const STALE_IF_ERROR_MAX_AGE_SECS: u64 = 1800;
const STALE_IF_ERROR_GRACE_TTL_SECS: u64 = 15;
const FAKE_IP_TRANSIENT_FAILURE_PACE_MS: u64 = 80;
const MAX_CONCURRENT_DNS_UDP_TASKS: usize = 256;
const MAX_CONCURRENT_DNS_TCP_CONNS: usize = 128;
const MAX_PERSISTED_FAKE_IP_ENTRIES: usize = 2048;
const MAX_FAKE_IP_PERSIST_AGE_MS: u64 = 7 * 24 * 60 * 60 * 1000;

fn compute_negative_ttl_secs(min_neg_ttl: Option<u64>, nxdomain: bool) -> u64 {
    if nxdomain {
        min_neg_ttl
            .unwrap_or(DEFAULT_NXDOMAIN_TTL_SECS)
            .clamp(MIN_NXDOMAIN_TTL_SECS, MAX_NXDOMAIN_TTL_SECS)
    } else {
        min_neg_ttl
            .unwrap_or(5)
            .clamp(MIN_NEGATIVE_TTL_SECS, MAX_NEGATIVE_TTL_SECS)
    }
}

#[derive(Clone, Debug)]
enum InflightOutcome {
    Pending,
    Resolved(std::result::Result<Vec<IpAddr>, String>),
    Cancelled,
}

type InflightKey = (u64, String, bool);
type InflightMap = DashMap<InflightKey, watch::Sender<InflightOutcome>>;

struct InflightLookupGuard<'a> {
    map: &'a InflightMap,
    key: InflightKey,
    tx: watch::Sender<InflightOutcome>,
    completed: bool,
}

impl<'a> InflightLookupGuard<'a> {
    fn acquire(
        map: &'a InflightMap,
        key: InflightKey,
    ) -> std::result::Result<Self, watch::Receiver<InflightOutcome>> {
        match map.entry(key.clone()) {
            Entry::Occupied(occ) => Err(occ.get().subscribe()),
            Entry::Vacant(vac) => {
                let (tx, _rx) = watch::channel(InflightOutcome::Pending);
                vac.insert(tx.clone());
                Ok(Self {
                    map,
                    key,
                    tx,
                    completed: false,
                })
            }
        }
    }

    fn finish(mut self, res: &Result<Vec<IpAddr>>) {
        self.completed = true;
        self.map.remove(&self.key);
        let outcome = match res {
            Ok(ips) => InflightOutcome::Resolved(Ok(ips.clone())),
            Err(ProxyError::Dns(msg)) => InflightOutcome::Resolved(Err(msg.clone())),
            Err(err) => InflightOutcome::Resolved(Err(err.to_string())),
        };
        let _ = self.tx.send(outcome);
    }
}

impl Drop for InflightLookupGuard<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.map.remove(&self.key);
            let _ = self.tx.send(InflightOutcome::Cancelled);
        }
    }
}

async fn wait_for_inflight_outcome(
    rx: &mut watch::Receiver<InflightOutcome>,
) -> Option<Result<Vec<IpAddr>>> {
    let wait_res = tokio::time::timeout(
        Duration::from_secs(10),
        rx.wait_for(|state| !matches!(state, InflightOutcome::Pending)),
    )
    .await;
    let Ok(Ok(state_ref)) = wait_res else {
        return None;
    };
    match &*state_ref {
        InflightOutcome::Resolved(Ok(ips)) => Some(Ok(ips.clone())),
        InflightOutcome::Resolved(Err(msg)) => Some(Err(ProxyError::Dns(msg.clone()))),
        InflightOutcome::Pending | InflightOutcome::Cancelled => None,
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
    pub resolver_cache_hits: u64,
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
    pub(crate) proxy_entries: Vec<(String, Instant, u64, Vec<IpAddr>)>,
    pub(crate) bootstrap_entries: Vec<(String, Instant, u64, Vec<IpAddr>)>,
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
        expires_wall_ms: u64,
        stale_until: Instant,
        stale_until_wall_ms: u64,
        ips: Vec<IpAddr>,
    },
    Negative {
        expires_at: Instant,
        expires_wall_ms: u64,
        nxdomain: bool,
    },
    TransientFailure {
        expires_at: Instant,
        expires_wall_ms: u64,
    },
}

impl CachedIpResolution {
    fn new_positive(ttl_secs: u64, ips: Vec<IpAddr>) -> Self {
        let now_mono = Instant::now();
        let now_wall = current_epoch_ms();
        let expires_at = now_mono + Duration::from_secs(ttl_secs);
        let expires_wall_ms = now_wall.saturating_add(ttl_secs.saturating_mul(1_000));
        let stale_until = expires_at + Duration::from_secs(STALE_IF_ERROR_MAX_AGE_SECS);
        let stale_until_wall_ms =
            expires_wall_ms.saturating_add(STALE_IF_ERROR_MAX_AGE_SECS * 1_000);
        Self::Positive {
            expires_at,
            expires_wall_ms,
            stale_until,
            stale_until_wall_ms,
            ips,
        }
    }

    fn new_negative(ttl_secs: u64, nxdomain: bool) -> Self {
        let now_mono = Instant::now();
        let now_wall = current_epoch_ms();
        Self::Negative {
            expires_at: now_mono + Duration::from_secs(ttl_secs),
            expires_wall_ms: now_wall.saturating_add(ttl_secs.saturating_mul(1_000)),
            nxdomain,
        }
    }

    fn new_transient_failure() -> Self {
        let now_mono = Instant::now();
        let now_wall = current_epoch_ms();
        Self::TransientFailure {
            expires_at: now_mono + Duration::from_secs(SERVFAIL_NEGATIVE_TTL_SECS),
            expires_wall_ms: now_wall.saturating_add(SERVFAIL_NEGATIVE_TTL_SECS * 1_000),
        }
    }
}

#[derive(Clone, Debug)]
struct CachedWirePacket {
    inserted_at: Instant,
    inserted_wall_ms: u64,
    expires_at: Instant,
    expires_wall_ms: u64,
    wire: Vec<u8>,
}

impl CachedWirePacket {
    fn new(ttl_secs: u64, wire: Vec<u8>) -> Self {
        let now_mono = Instant::now();
        let now_wall = current_epoch_ms();
        Self {
            inserted_at: now_mono,
            inserted_wall_ms: now_wall,
            expires_at: now_mono + Duration::from_secs(ttl_secs),
            expires_wall_ms: now_wall.saturating_add(ttl_secs.saturating_mul(1_000)),
            wire,
        }
    }
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

    fn get_or_assign(&mut self, domain: &str) -> (Ipv4Addr, bool) {
        let normalized = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        if let Some(&existing_ip) = self.domain_to_ip.get(&normalized) {
            if self.ip_to_domain.get(&existing_ip) == Some(&normalized) {
                return (existing_ip, false);
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
                    if self.domain_to_ip.get(&evicted_domain) == Some(&evicted_ip) {
                        self.domain_to_ip.remove(&evicted_domain);
                    }
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

        if let Some((evicted_ip, evicted_domain)) = self.ip_to_domain.push(ip, normalized.clone())
            && evicted_domain != normalized
            && self.domain_to_ip.get(&evicted_domain) == Some(&evicted_ip)
        {
            self.domain_to_ip.remove(&evicted_domain);
        }
        self.domain_to_ip.insert(normalized, ip);
        (ip, true)
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
        if let Some((evicted_ip, evicted_domain)) = self.ip_to_domain.push(ip, normalized.clone())
            && evicted_domain != normalized
            && self.domain_to_ip.get(&evicted_domain) == Some(&evicted_ip)
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

    fn recover_unmapped(&mut self, ip: Ipv4Addr, domain: &str, net: Ipv4Net) -> bool {
        let ip_u32 = u32::from(ip);
        if !net.contains(&ip) || ip_u32 < self.start_host || ip_u32 > self.end_host {
            return false;
        }
        if self.ip_to_domain.contains(&ip) {
            return false;
        }
        let Some(normalized) = crate::inbound::sniff::normalize_valid_hostname(domain) else {
            return false;
        };
        if let Some((evicted_ip, evicted_domain)) = self.ip_to_domain.push(ip, normalized.clone())
            && self.domain_to_ip.get(&evicted_domain) == Some(&evicted_ip)
        {
            self.domain_to_ip.remove(&evicted_domain);
        }
        self.domain_to_ip.entry(normalized).or_insert(ip);
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
    if p == "+" || p == "+.*" {
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

type BootstrapCacheEntry = (Instant, u64, Vec<IpAddr>);

const UPSTREAM_429_COOLDOWN_MS: u64 = 15_000;
const UPSTREAM_TIMEOUT_COOLDOWN_MS: u64 = 30_000;

#[derive(Clone, Debug, Default)]
struct UpstreamHealthState {
    consecutive_failures: u32,
    cooldown_until_mono: Option<Instant>,
    cooldown_until_wall_ms: u64,
}

impl UpstreamHealthState {
    fn is_cooled_down(&self, now_mono: Instant, now_wall_ms: u64) -> bool {
        self.cooldown_until_mono
            .is_some_and(|until| now_mono < until && now_wall_ms < self.cooldown_until_wall_ms)
    }
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
    packet_cache: Mutex<LruCache<(String, u16, u16), CachedWirePacket>>,
    bootstrap_cache: Mutex<LruCache<String, BootstrapCacheEntry>>,
    upstream_health: DashMap<DnsUpstream, UpstreamHealthState>,
    inflight_real: InflightMap,
    inflight_direct: InflightMap,
    inflight_proxy: InflightMap,
    inflight_bootstrap: InflightMap,
    cache_epoch: AtomicU64,
    total_queries: AtomicU64,
    fake_ip_hits: AtomicU64,
    cache_hits: AtomicU64,
    resolver_cache_hits: AtomicU64,
    suppressed_queries: AtomicU64,
    nxdomain_hits: AtomicU64,
    upstream_queries: AtomicU64,
    upstream_errors: AtomicU64,
    upstream_total_ms: AtomicU64,
    upstream_max_ms: AtomicU64,
    dirty_revision: AtomicU64,
    persisted_revision: AtomicU64,
    save_lock: Mutex<()>,
    assignment_notify: Arc<Notify>,
    #[cfg(test)]
    system_dns_provider: Mutex<Option<TestSystemDnsProvider>>,
    #[cfg(test)]
    system_dns_test_cache: Mutex<Option<(u64, Vec<SocketAddr>)>>,
}

#[cfg(test)]
type TestSystemDnsProvider = Arc<dyn Fn() -> Vec<SocketAddr> + Send + Sync>;

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
                let parsed = BootstrapDnsServer::parse(b)?;
                if !bootstrap_servers.contains(&parsed) {
                    bootstrap_servers.push(parsed);
                }
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
            if !proxy_upstreams.contains(&parsed) {
                proxy_upstreams.push(parsed);
            }
        }

        let mut direct_upstreams = Vec::new();
        for dns_str in &cfg.direct_nameserver {
            if dns_str.trim().is_empty() {
                continue;
            }
            let parsed = DnsUpstream::parse(dns_str)?;
            record_literal_ns(&parsed);
            if !direct_upstreams.contains(&parsed) {
                direct_upstreams.push(parsed);
            }
        }

        let mut upstreams = Vec::new();
        for ns in &cfg.nameserver {
            if ns.trim().is_empty() {
                continue;
            }
            let parsed = DnsUpstream::parse(ns)?;
            record_literal_ns(&parsed);
            if !upstreams.contains(&parsed) {
                upstreams.push(parsed);
            }
        }

        let mut fallbacks = Vec::new();
        for fb in &cfg.fallback {
            if fb.trim().is_empty() {
                continue;
            }
            let parsed = DnsUpstream::parse(fb)?;
            record_literal_ns(&parsed);
            if !fallbacks.contains(&parsed) {
                fallbacks.push(parsed);
            }
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
                    if !ups.contains(&parsed) {
                        ups.push(parsed);
                    }
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
                DnsEndpointHost::Ip(_) | DnsEndpointHost::System => false,
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
            upstream_health: DashMap::new(),
            inflight_real: DashMap::new(),
            inflight_direct: DashMap::new(),
            inflight_proxy: DashMap::new(),
            inflight_bootstrap: DashMap::new(),
            cache_epoch: AtomicU64::new(0),
            total_queries: AtomicU64::new(0),
            fake_ip_hits: AtomicU64::new(0),
            cache_hits: AtomicU64::new(0),
            resolver_cache_hits: AtomicU64::new(0),
            suppressed_queries: AtomicU64::new(0),
            nxdomain_hits: AtomicU64::new(0),
            upstream_queries: AtomicU64::new(0),
            upstream_errors: AtomicU64::new(0),
            upstream_total_ms: AtomicU64::new(0),
            upstream_max_ms: AtomicU64::new(0),
            dirty_revision: AtomicU64::new(0),
            persisted_revision: AtomicU64::new(0),
            save_lock: Mutex::new(()),
            assignment_notify: Arc::new(Notify::new()),
            #[cfg(test)]
            system_dns_provider: Mutex::new(None),
            #[cfg(test)]
            system_dns_test_cache: Mutex::new(None),
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
        self.resolver_cache_hits.store(
            prev.resolver_cache_hits.load(Ordering::Relaxed),
            Ordering::Relaxed,
        );
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
        let prev_unpersisted = prev.has_unpersisted_entries();
        let entries = prev.entries_snapshot();
        {
            let mut guard = self.pool.lock();
            for entry in entries.into_iter().rev() {
                if let Ok(v4) = entry.ip.parse::<Ipv4Addr>()
                    && !self.should_bypass_fake_ip(&entry.domain)
                {
                    let _ = guard.insert_preserved(v4, &entry.domain, self.net);
                }
            }
            if prev_unpersisted {
                self.dirty_revision.fetch_add(1, Ordering::AcqRel);
            }
        }
        if prev_unpersisted {
            self.assignment_notify.notify_one();
        }
    }

    /// Export non-expired positive `proxy_ip_cache` and `bootstrap_cache` entries (e.g. from an offline
    /// Android latency-test router right before starting the VPN engine with identical DNS config).
    pub fn export_positive_proxy_cache_seed(&self) -> PositiveDnsCacheSeed {
        let now = Instant::now();
        let now_wall = current_epoch_ms();
        let proxy_entries = self
            .proxy_ip_cache
            .lock()
            .iter()
            .filter_map(|(k, v)| match v {
                CachedIpResolution::Positive {
                    expires_at,
                    expires_wall_ms,
                    ips,
                    ..
                } if *expires_at > now && *expires_wall_ms > now_wall && !ips.is_empty() => {
                    Some((k.clone(), *expires_at, *expires_wall_ms, ips.clone()))
                }
                _ => None,
            })
            .collect();
        let bootstrap_entries = self
            .bootstrap_cache
            .lock()
            .iter()
            .filter(|(_, (expires_at, expires_wall_ms, ips))| {
                *expires_at > now && *expires_wall_ms > now_wall && !ips.is_empty()
            })
            .map(|(k, (expires_at, expires_wall_ms, ips))| {
                (k.clone(), *expires_at, *expires_wall_ms, ips.clone())
            })
            .collect();
        PositiveDnsCacheSeed {
            proxy_entries,
            bootstrap_entries,
        }
    }

    /// Seed non-expired positive `proxy_ip_cache` and `bootstrap_cache` entries from a prior verified engine.
    pub fn seed_positive_proxy_cache(&self, seed: PositiveDnsCacheSeed) {
        let now = Instant::now();
        let now_wall = current_epoch_ms();
        let want_ipv6 = self.direct_ipv6_enabled();
        if !seed.bootstrap_entries.is_empty() {
            let mut bguard = self.bootstrap_cache.lock();
            for (domain, expires_at, expires_wall_ms, ips) in
                seed.bootstrap_entries.into_iter().rev()
            {
                if expires_at <= now || expires_wall_ms <= now_wall || bguard.contains(&domain) {
                    continue;
                }
                let valid: Vec<IpAddr> = ips
                    .into_iter()
                    .filter(|ip| (!ip.is_ipv6() || want_ipv6) && !self.is_fake_ip(*ip))
                    .collect();
                if !valid.is_empty() {
                    bguard.put(domain, (expires_at, expires_wall_ms, valid));
                }
            }
        }
        if !seed.proxy_entries.is_empty() {
            let mut pguard = self.proxy_ip_cache.lock();
            for (domain, expires_at, expires_wall_ms, ips) in seed.proxy_entries.into_iter().rev() {
                if expires_at <= now || expires_wall_ms <= now_wall || pguard.contains(&domain) {
                    continue;
                }
                let mut valid: Vec<IpAddr> = ips
                    .iter()
                    .copied()
                    .filter(|ip| (!ip.is_ipv6() || want_ipv6) && !self.is_fake_ip(*ip))
                    .collect();
                if valid.is_empty() {
                    valid = ips.into_iter().filter(|ip| !self.is_fake_ip(*ip)).collect();
                }
                if !valid.is_empty() {
                    pguard.put(
                        domain,
                        CachedIpResolution::Positive {
                            expires_at,
                            expires_wall_ms,
                            stale_until: expires_at
                                + Duration::from_secs(STALE_IF_ERROR_MAX_AGE_SECS),
                            stale_until_wall_ms: expires_wall_ms
                                .saturating_add(STALE_IF_ERROR_MAX_AGE_SECS * 1_000),
                            ips: valid,
                        },
                    );
                }
            }
        }
    }

    /// Proactively warm or refresh `proxy_ip_cache` for a proxy server hostname when missing or `< 25s` TTL remains.
    /// Preserves any still-usable positive entry if a proactive refresh encounters a transient network error.
    pub async fn prewarm_proxy_server_ips(&self, host: &str) -> Result<Vec<IpAddr>> {
        let want_ipv6 = self.direct_ipv6_enabled();
        let clean = host
            .trim()
            .trim_matches(|c| c == '[' || c == ']')
            .trim_end_matches('.')
            .to_ascii_lowercase();
        if clean.is_empty()
            || clean.parse::<IpAddr>().is_ok()
            || clean == "localhost"
            || self
                .lookup_static_hosts_for_endpoint(&clean, want_ipv6)
                .is_some()
        {
            return self.resolve_proxy_server_ips(host).await;
        }

        let now = Instant::now();
        let now_wall = current_epoch_ms();
        let fallback_entry = {
            let mut guard = self.proxy_ip_cache.lock();
            match guard.get(&clean).cloned() {
                Some(CachedIpResolution::Positive {
                    expires_at,
                    expires_wall_ms,
                    stale_until,
                    stale_until_wall_ms,
                    ips,
                }) => {
                    if expires_at.saturating_duration_since(now) > Duration::from_secs(25)
                        && expires_wall_ms.saturating_sub(now_wall) > 25_000
                    {
                        if want_ipv6 {
                            return Ok(ips);
                        }
                        let v4_only: Vec<IpAddr> =
                            ips.iter().copied().filter(IpAddr::is_ipv4).collect();
                        if !v4_only.is_empty() {
                            return Ok(v4_only);
                        }
                    }
                    guard.pop(&clean);
                    (stale_until > now && stale_until_wall_ms > now_wall).then_some((
                        expires_at,
                        expires_wall_ms,
                        stale_until,
                        stale_until_wall_ms,
                        ips,
                    ))
                }
                Some(
                    CachedIpResolution::Negative { .. }
                    | CachedIpResolution::TransientFailure { .. },
                ) => {
                    guard.pop(&clean);
                    None
                }
                None => None,
            }
        };

        let start_epoch = self.current_cache_epoch();
        match self.resolve_proxy_server_ips(host).await {
            Ok(ips) => Ok(ips),
            Err(e) => {
                let now_after = Instant::now();
                let now_wall_after = current_epoch_ms();
                if let Some((expires_at, expires_wall_ms, stale_until, stale_until_wall_ms, ips)) =
                    fallback_entry
                    && now_after < stale_until
                    && now_wall_after < stale_until_wall_ms
                {
                    let restored_expires = expires_at.max(
                        (now_after + Duration::from_secs(STALE_IF_ERROR_GRACE_TTL_SECS))
                            .min(stale_until),
                    );
                    let restored_expires_wall_ms = expires_wall_ms.max(
                        now_wall_after
                            .saturating_add(STALE_IF_ERROR_GRACE_TTL_SECS * 1_000)
                            .min(stale_until_wall_ms),
                    );
                    let mut guard = self.proxy_ip_cache.lock();
                    if self.cache_epoch.load(Ordering::Acquire) == start_epoch
                        && !matches!(
                            guard.peek(&clean),
                            Some(
                                CachedIpResolution::Positive { .. }
                                    | CachedIpResolution::Negative { .. }
                            )
                        )
                    {
                        guard.put(
                            clean,
                            CachedIpResolution::Positive {
                                expires_at: restored_expires,
                                expires_wall_ms: restored_expires_wall_ms,
                                stale_until,
                                stale_until_wall_ms,
                                ips: ips.clone(),
                            },
                        );
                        return Ok(ips);
                    }
                }
                Err(e)
            }
        }
    }

    #[inline]
    pub fn current_cache_epoch(&self) -> u64 {
        self.cache_epoch.load(Ordering::Acquire)
    }

    fn put_ip_cache_if_epoch(
        &self,
        cache: &Mutex<LruCache<String, CachedIpResolution>>,
        expected_epoch: u64,
        key: String,
        entry: CachedIpResolution,
    ) {
        let mut guard = cache.lock();
        if self.cache_epoch.load(Ordering::Acquire) == expected_epoch {
            guard.put(key, entry);
        }
    }

    fn put_packet_cache_if_epoch(
        &self,
        expected_epoch: u64,
        key: (String, u16, u16),
        entry: CachedWirePacket,
    ) {
        let mut guard = self.packet_cache.lock();
        if self.cache_epoch.load(Ordering::Acquire) == expected_epoch {
            guard.put(key, entry);
        }
    }

    fn put_bootstrap_cache_if_epoch(
        &self,
        expected_epoch: u64,
        key: String,
        entry: BootstrapCacheEntry,
    ) {
        let mut guard = self.bootstrap_cache.lock();
        if self.cache_epoch.load(Ordering::Acquire) == expected_epoch {
            guard.put(key, entry);
        }
    }

    /// Clear engine-local positive/negative DNS caches without evicting process-wide DoT/DoH pools.
    /// Increments `cache_epoch` BEFORE acquiring cache locks so in-flight queries from the previous
    /// network generation cannot write stale results back or coalesce with new queries, while keeping
    /// Fake-IP <-> domain mappings in `self.pool` intact.
    pub fn clear_local_caches(&self) {
        self.cache_epoch.fetch_add(1, Ordering::SeqCst);
        self.real_ip_cache.lock().clear();
        self.direct_ip_cache.lock().clear();
        self.proxy_ip_cache.lock().clear();
        self.packet_cache.lock().clear();
        self.bootstrap_cache.lock().clear();
        self.upstream_health.clear();
        #[cfg(test)]
        {
            *self.system_dns_test_cache.lock() = None;
        }
    }

    #[cfg(test)]
    pub fn set_system_dns_provider_for_test<F>(&self, provider: F)
    where
        F: Fn() -> Vec<SocketAddr> + Send + Sync + 'static,
    {
        *self.system_dns_provider.lock() = Some(Arc::new(provider));
        *self.system_dns_test_cache.lock() = None;
    }

    fn resolve_effective_system_dns_servers(&self) -> Vec<SocketAddr> {
        #[cfg(test)]
        {
            let provider = self.system_dns_provider.lock().clone();
            if let Some(prov) = provider {
                let epoch = self.current_cache_epoch();
                {
                    let guard = self.system_dns_test_cache.lock();
                    if let Some((cached_epoch, ref servers)) = *guard
                        && cached_epoch == epoch
                    {
                        return servers.clone();
                    }
                }
                let servers = prov();
                *self.system_dns_test_cache.lock() = Some((epoch, servers.clone()));
                return servers;
            }
        }
        crate::dns::upstream::resolve_system_dns_servers(Some(self.net))
    }

    /// Flush positive/negative DNS resolution caches, wire packet caches, and pooled DoT/DoH sockets.
    pub fn flush_cache(&self) {
        self.clear_local_caches();
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

    #[inline]
    fn direct_ipv6_enabled(&self) -> bool {
        self.ipv6 && crate::platform::socket_protect::is_direct_ipv6_reachable()
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

    fn lookup_static_hosts_filtered(
        &self,
        normalized: &str,
        want_ipv6: bool,
    ) -> Option<Vec<IpAddr>> {
        let raw = self.lookup_static_hosts_raw(normalized)?;
        let filtered: Vec<IpAddr> = raw
            .iter()
            .copied()
            .filter(|ip| (!ip.is_ipv6() || want_ipv6) && !self.is_fake_ip(*ip))
            .collect();
        if filtered.is_empty() {
            None
        } else {
            Some(filtered)
        }
    }

    fn lookup_static_hosts_for_endpoint(
        &self,
        normalized: &str,
        want_ipv6: bool,
    ) -> Option<Vec<IpAddr>> {
        let raw = self.lookup_static_hosts_raw(normalized)?;
        let mut preferred: Vec<IpAddr> = raw
            .iter()
            .copied()
            .filter(|ip| (!ip.is_ipv6() || want_ipv6) && !self.is_fake_ip(*ip))
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
        let (ip, newly_inserted) = {
            let mut guard = self.pool.lock();
            let res = guard.get_or_assign(domain);
            if res.1 {
                self.dirty_revision.fetch_add(1, Ordering::AcqRel);
            }
            res
        };
        if newly_inserted {
            self.assignment_notify.notify_one();
        }
        ip
    }

    /// Re-associate an unmapped Fake-IP inside `fake-ip-range` with a recovered hostname
    /// (for example from TLS ClientHello SNI or HTTP Host) without overwriting existing entries
    /// or corrupting an already-assigned primary Fake-IP for that domain.
    pub fn recover_unmapped_fake_ip(&self, ip: Ipv4Addr, domain: &str) -> bool {
        let recovered = {
            let mut guard = self.pool.lock();
            let ok = guard.recover_unmapped(ip, domain, self.net);
            if ok {
                self.dirty_revision.fetch_add(1, Ordering::AcqRel);
            }
            ok
        };
        if recovered {
            self.assignment_notify.notify_one();
        }
        recovered
    }

    pub fn has_unpersisted_entries(&self) -> bool {
        self.dirty_revision.load(Ordering::Acquire)
            > self.persisted_revision.load(Ordering::Acquire)
    }

    pub fn assignment_notify(&self) -> Arc<Notify> {
        Arc::clone(&self.assignment_notify)
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

    fn lookup_cached_ips_with_pace(
        cache: &Mutex<LruCache<String, CachedIpResolution>>,
        normalized: &str,
        want_ipv6: bool,
        allow_ipv6_fallback: bool,
        pace_transient_failure: bool,
    ) -> (Option<Result<Vec<IpAddr>>>, Option<Duration>) {
        Self::lookup_cached_ips_with_pace_at(
            cache,
            normalized,
            want_ipv6,
            allow_ipv6_fallback,
            pace_transient_failure,
            Instant::now(),
            current_epoch_ms(),
        )
    }

    fn lookup_cached_ips_with_pace_at(
        cache: &Mutex<LruCache<String, CachedIpResolution>>,
        normalized: &str,
        want_ipv6: bool,
        allow_ipv6_fallback: bool,
        pace_transient_failure: bool,
        now: Instant,
        now_wall_ms: u64,
    ) -> (Option<Result<Vec<IpAddr>>>, Option<Duration>) {
        let Some(cached) = cache.lock().get(normalized).cloned() else {
            return (None, None);
        };
        match cached {
            CachedIpResolution::Positive {
                expires_at,
                expires_wall_ms,
                ips,
                ..
            } if now < expires_at && now_wall_ms < expires_wall_ms => {
                let res = if want_ipv6 {
                    Ok(ips)
                } else {
                    let v4_only: Vec<IpAddr> =
                        ips.iter().copied().filter(IpAddr::is_ipv4).collect();
                    if !v4_only.is_empty() {
                        Ok(v4_only)
                    } else if allow_ipv6_fallback && !ips.is_empty() {
                        Ok(ips)
                    } else {
                        Err(ProxyError::Dns(format!(
                            "DNS NODATA (cached IPv4) for '{normalized}'"
                        )))
                    }
                };
                (Some(res), None)
            }
            CachedIpResolution::Negative {
                expires_at,
                expires_wall_ms,
                nxdomain,
            } if now < expires_at && now_wall_ms < expires_wall_ms => (
                Some(if nxdomain {
                    Err(ProxyError::Dns(format!(
                        "DNS NXDOMAIN (cached) for '{normalized}'"
                    )))
                } else {
                    Err(ProxyError::Dns(format!(
                        "DNS NODATA (cached) for '{normalized}'"
                    )))
                }),
                None,
            ),
            CachedIpResolution::TransientFailure {
                expires_at,
                expires_wall_ms,
            } if now < expires_at && now_wall_ms < expires_wall_ms => {
                let delay = pace_transient_failure.then(|| {
                    let rem_mono = expires_at.saturating_duration_since(now);
                    let rem_wall =
                        Duration::from_millis(expires_wall_ms.saturating_sub(now_wall_ms));
                    rem_mono
                        .min(rem_wall)
                        .min(Duration::from_millis(FAKE_IP_TRANSIENT_FAILURE_PACE_MS))
                });
                (
                    Some(Err(ProxyError::Dns(format!(
                        "DNS SERVFAIL (cached) for '{normalized}'"
                    )))),
                    delay,
                )
            }
            _ => (None, None),
        }
    }

    fn lookup_cached_ips(
        cache: &Mutex<LruCache<String, CachedIpResolution>>,
        normalized: &str,
        want_ipv6: bool,
        allow_ipv6_fallback: bool,
    ) -> Option<Result<Vec<IpAddr>>> {
        Self::lookup_cached_ips_with_pace(cache, normalized, want_ipv6, allow_ipv6_fallback, false)
            .0
    }

    async fn lookup_cached_ips_paced(
        &self,
        cache: &Mutex<LruCache<String, CachedIpResolution>>,
        normalized: &str,
        want_ipv6: bool,
        allow_ipv6_fallback: bool,
    ) -> Option<Result<Vec<IpAddr>>> {
        let (outcome, delay) = Self::lookup_cached_ips_with_pace(
            cache,
            normalized,
            want_ipv6,
            allow_ipv6_fallback,
            self.is_fake_ip_mode(),
        );
        if let Some(d) = delay
            && !d.is_zero()
        {
            tokio::time::sleep(d).await;
        }
        outcome
    }

    /// RFC 8767 `stale-if-error` (`serve-expired`): when a refresh fails transiently (timeout /
    /// `SERVFAIL` / `REFUSED`, never authoritative `NXDOMAIN` or `NODATA`), serve a previously
    /// verified positive resolution within `STALE_IF_ERROR_MAX_AGE_SECS` and grant a brief grace TTL.
    fn try_serve_stale_on_error(
        cache: &Mutex<LruCache<String, CachedIpResolution>>,
        normalized: &str,
        want_ipv6: bool,
        allow_ipv6_fallback: bool,
    ) -> Option<Vec<IpAddr>> {
        Self::try_serve_stale_on_error_at(
            cache,
            normalized,
            want_ipv6,
            allow_ipv6_fallback,
            Instant::now(),
            current_epoch_ms(),
        )
    }

    fn try_serve_stale_on_error_at(
        cache: &Mutex<LruCache<String, CachedIpResolution>>,
        normalized: &str,
        want_ipv6: bool,
        allow_ipv6_fallback: bool,
        now: Instant,
        now_wall_ms: u64,
    ) -> Option<Vec<IpAddr>> {
        let mut guard = cache.lock();
        let (stale_until, stale_until_wall_ms, ips) = match guard.peek(normalized) {
            Some(CachedIpResolution::Positive {
                stale_until,
                stale_until_wall_ms,
                ips,
                ..
            }) if now < *stale_until && now_wall_ms < *stale_until_wall_ms => {
                (*stale_until, *stale_until_wall_ms, ips.clone())
            }
            _ => return None,
        };
        let usable = if want_ipv6 {
            ips.clone()
        } else {
            let v4_only: Vec<IpAddr> = ips.iter().copied().filter(IpAddr::is_ipv4).collect();
            if !v4_only.is_empty() {
                v4_only
            } else if allow_ipv6_fallback && !ips.is_empty() {
                ips.clone()
            } else {
                return None;
            }
        };
        if usable.is_empty() {
            return None;
        }
        let grace_expires =
            (now + Duration::from_secs(STALE_IF_ERROR_GRACE_TTL_SECS)).min(stale_until);
        let grace_expires_wall_ms = now_wall_ms
            .saturating_add(STALE_IF_ERROR_GRACE_TTL_SECS * 1_000)
            .min(stale_until_wall_ms);
        guard.put(
            normalized.to_string(),
            CachedIpResolution::Positive {
                expires_at: grace_expires,
                expires_wall_ms: grace_expires_wall_ms,
                stale_until,
                stale_until_wall_ms,
                ips,
            },
        );
        Some(usable)
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
            DnsEndpointHost::System => Ok(Vec::new()),
            DnsEndpointHost::Ip(ip) => {
                if self.is_fake_ip(*ip) {
                    return Err(ProxyError::Dns(format!(
                        "refusing Fake-IP {ip} as upstream DNS endpoint"
                    )));
                }
                Ok(vec![*ip])
            }
            DnsEndpointHost::Domain(domain) => {
                let want_ipv6 = self.direct_ipv6_enabled();
                let norm = domain.trim().trim_end_matches('.').to_ascii_lowercase();
                if norm == "localhost" {
                    return Ok(vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]);
                }
                if let Some(static_ips) = self.lookup_static_hosts_for_endpoint(&norm, want_ipv6) {
                    return Ok(static_ips);
                }
                let filter_bootstrap_ips = |ips: Vec<IpAddr>| -> Option<Vec<IpAddr>> {
                    if want_ipv6 {
                        return (!ips.is_empty()).then_some(ips);
                    }
                    let v4_only: Vec<IpAddr> = ips.into_iter().filter(IpAddr::is_ipv4).collect();
                    (!v4_only.is_empty()).then_some(v4_only)
                };
                if let Some((expires_at, expires_wall_ms, ips)) =
                    self.bootstrap_cache.lock().get(&norm).cloned()
                    && Instant::now() < expires_at
                    && current_epoch_ms() < expires_wall_ms
                    && let Some(valid) = filter_bootstrap_ips(ips)
                {
                    return Ok(valid);
                }

                let mut start_epoch = self.current_cache_epoch();
                let inflight_guard = match InflightLookupGuard::acquire(
                    &self.inflight_bootstrap,
                    (start_epoch, norm.clone(), want_ipv6),
                ) {
                    Ok(guard) => Some(guard),
                    Err(mut rx) => {
                        if let Some(outcome) = wait_for_inflight_outcome(&mut rx).await
                            && self.current_cache_epoch() == start_epoch
                        {
                            return outcome;
                        }
                        start_epoch = self.current_cache_epoch();
                        if let Some((expires_at, expires_wall_ms, ips)) =
                            self.bootstrap_cache.lock().get(&norm).cloned()
                            && Instant::now() < expires_at
                            && current_epoch_ms() < expires_wall_ms
                            && let Some(valid) = filter_bootstrap_ips(ips)
                        {
                            return Ok(valid);
                        }
                        None
                    }
                };

                if let Some((expires_at, expires_wall_ms, ips)) =
                    self.bootstrap_cache.lock().get(&norm).cloned()
                    && Instant::now() < expires_at
                    && current_epoch_ms() < expires_wall_ms
                    && let Some(valid) = filter_bootstrap_ips(ips)
                {
                    let res = Ok(valid);
                    if let Some(g) = inflight_guard {
                        g.finish(&res);
                    }
                    return res;
                }

                let (res_a, res_aaaa) = if want_ipv6 {
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
                        if (!ip.is_ipv6() || want_ipv6) && !ips.contains(&ip) {
                            ips.push(ip);
                        }
                    }
                }

                if ips.is_empty() {
                    let res = Err(ProxyError::Dns(format!(
                        "default-nameserver bootstrap failed for DoH/DoT host '{domain}'"
                    )));
                    if let Some(g) = inflight_guard {
                        g.finish(&res);
                    }
                    return res;
                }

                self.put_bootstrap_cache_if_epoch(
                    start_epoch,
                    norm,
                    (
                        Instant::now() + Duration::from_secs(min_ttl),
                        current_epoch_ms().saturating_add(min_ttl.saturating_mul(1_000)),
                        ips.clone(),
                    ),
                );
                let res = Ok(ips);
                if let Some(g) = inflight_guard {
                    g.finish(&res);
                }
                res
            }
        }
    }

    fn record_upstream_outcome(
        &self,
        upstream: &DnsUpstream,
        res: &Result<Vec<u8>>,
        expected_epoch: u64,
    ) {
        match res {
            Ok(_) => {
                self.upstream_health.remove(upstream);
            }
            Err(err) => {
                if self.current_cache_epoch() != expected_epoch {
                    return;
                }
                let is_429 = matches!(err, ProxyError::Dns(msg) if msg.contains("HTTP status 429"));
                let is_transport_fail = matches!(err, ProxyError::Timeout | ProxyError::Io(_));
                if !is_429 && !is_transport_fail {
                    return;
                }
                if self.upstream_health.len() > 128 {
                    let now_m = Instant::now();
                    let now_w = current_epoch_ms();
                    self.upstream_health
                        .retain(|_, st| st.is_cooled_down(now_m, now_w));
                }
                let mut entry = self.upstream_health.entry(upstream.clone()).or_default();
                entry.consecutive_failures = entry.consecutive_failures.saturating_add(1);
                if is_429 {
                    entry.cooldown_until_mono =
                        Some(Instant::now() + Duration::from_millis(UPSTREAM_429_COOLDOWN_MS));
                    entry.cooldown_until_wall_ms =
                        current_epoch_ms().saturating_add(UPSTREAM_429_COOLDOWN_MS);
                } else if entry.consecutive_failures >= 2 {
                    entry.cooldown_until_mono =
                        Some(Instant::now() + Duration::from_millis(UPSTREAM_TIMEOUT_COOLDOWN_MS));
                    entry.cooldown_until_wall_ms =
                        current_epoch_ms().saturating_add(UPSTREAM_TIMEOUT_COOLDOWN_MS);
                }
            }
        }
    }

    async fn exchange_single_upstream(
        &self,
        upstream: &DnsUpstream,
        raw_query: &[u8],
    ) -> Result<Vec<u8>> {
        let start_epoch = self.current_cache_epoch();
        let outcome = async {
            let resp = if matches!(upstream, DnsUpstream::System) {
                let servers = self.resolve_effective_system_dns_servers();
                Box::pin(crate::dns::upstream::exchange_system_dns_servers(
                    &servers, raw_query,
                ))
                .await?
            } else {
                let ips = Box::pin(self.resolve_bootstrap_host(&upstream.endpoint_host())).await?;
                Box::pin(upstream.exchange(&ips, raw_query, &self.extra_ca_der)).await?
            };
            if let Some(&flags_hi) = resp.get(2)
                && (flags_hi & 0x02) != 0
            {
                return Err(ProxyError::Dns(
                    "upstream DNS response remained truncated (TC=1)".into(),
                ));
            }
            if let Some(&flags_lo) = resp.get(3) {
                let rcode = flags_lo & 0x0F;
                if rcode == 2 || rcode == 5 {
                    return Err(ProxyError::Dns(format!(
                        "upstream DNS returned RCODE {rcode}"
                    )));
                }
            }
            Ok(resp)
        }
        .await;
        self.record_upstream_outcome(upstream, &outcome, start_epoch);
        outcome
    }

    async fn exchange_hedged_pair(
        &self,
        u0: &DnsUpstream,
        u1: &DnsUpstream,
        raw_query: &[u8],
        stagger: Duration,
    ) -> Result<Vec<u8>> {
        let mut fut0 = Box::pin(self.exchange_single_upstream(u0, raw_query));
        let mut hedge_delay = std::pin::pin!(tokio::time::sleep(stagger));

        tokio::select! {
            res0 = &mut fut0 => {
                match res0 {
                    Ok(resp) => Ok(resp),
                    Err(_e0) => Box::pin(self.exchange_single_upstream(u1, raw_query)).await,
                }
            }
            _ = &mut hedge_delay => {
                let mut fut1 = Box::pin(self.exchange_single_upstream(u1, raw_query));
                tokio::select! {
                    res0 = &mut fut0 => {
                        match res0 {
                            Ok(resp) => Ok(resp),
                            Err(_e0) => fut1.await,
                        }
                    }
                    res1 = &mut fut1 => {
                        match res1 {
                            Ok(resp) => Ok(resp),
                            Err(e1) => match fut0.await {
                                Ok(resp) => Ok(resp),
                                Err(_e0) => Err(e1),
                            },
                        }
                    }
                }
            }
        }
    }

    async fn exchange_upstream_refs(
        &self,
        refs: &[&DnsUpstream],
        raw_query: &[u8],
    ) -> Result<Vec<u8>> {
        let mut last_err = ProxyError::Dns("no DNS upstreams configured".into());
        let mut remaining = refs;
        // Hedge up to three consecutive upstream pairs (e.g. `[UDP1, UDP2, DoH1, DoH2, DoT1, DoT2]`
        // in `direct-nameserver` / `nameserver`) so port-53 blackholes or rate-limited DoH servers
        // never serialize into cascading timeouts inside the 15s dial budget.
        for pair_idx in 0..3 {
            if remaining.len() < 2 {
                break;
            }
            let stagger = if pair_idx == 0
                && matches!(
                    (remaining[0], remaining[1]),
                    (DnsUpstream::Udp(_), DnsUpstream::Udp(_))
                ) {
                Duration::from_millis(250)
            } else {
                Duration::from_millis(350)
            };
            match self
                .exchange_hedged_pair(remaining[0], remaining[1], raw_query, stagger)
                .await
            {
                Ok(resp) => return Ok(resp),
                Err(e) => {
                    last_err = e;
                    remaining = &remaining[2..];
                }
            }
        }

        for upstream in remaining {
            match Box::pin(self.exchange_single_upstream(upstream, raw_query)).await {
                Ok(resp) => return Ok(resp),
                Err(e) => last_err = e,
            }
        }
        Err(last_err)
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

        let now_mono = Instant::now();
        let now_wall = current_epoch_ms();
        let mut healthy: Vec<&DnsUpstream> = Vec::with_capacity(slice.len());
        let mut cooled: Vec<&DnsUpstream> = Vec::new();
        for u in slice {
            if self
                .upstream_health
                .get(u)
                .is_some_and(|st| st.is_cooled_down(now_mono, now_wall))
            {
                cooled.push(u);
            } else {
                healthy.push(u);
            }
        }

        let mut last_err = ProxyError::Dns("no DNS upstreams configured".into());
        if !healthy.is_empty() {
            match self.exchange_upstream_refs(&healthy, raw_query).await {
                Ok(resp) => return record_ok(resp),
                Err(e) => last_err = e,
            }
        }
        // Fallback safety net: if every healthy upstream failed (or all upstreams are currently
        // cooled down), still attempt the cooled-down upstreams so we never starve or fail early.
        if !cooled.is_empty() {
            match self.exchange_upstream_refs(&cooled, raw_query).await {
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
    ) -> (Option<crate::dns::wire::DnsResponseMeta>, Option<String>) {
        let query = build_dns_query(rand::random(), normalized, qtype);
        match self.exchange_with_upstream_slice(slice, &query).await {
            Ok(resp) => match extract_dns_response_meta(&resp) {
                Ok(meta) => (Some(meta), None),
                Err(e) => (None, Some(e.to_string())),
            },
            Err(e) => (None, Some(e.to_string())),
        }
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
        want_ipv6: bool,
    ) -> (
        Vec<IpAddr>,
        Option<u64>,
        Option<u64>,
        bool,
        bool,
        Vec<String>,
    ) {
        let mut resolved = Vec::new();
        let mut cnames = Vec::new();
        let mut saw_nxdomain = false;
        let mut saw_nodata = false;
        let mut min_pos_ttl: Option<u64> = None;
        let mut min_neg_ttl: Option<u64> = None;

        for meta in metas.into_iter().flatten() {
            if meta.truncated {
                continue;
            }
            if meta.rcode == 3 {
                saw_nxdomain = true;
                if let Some(t) = meta.min_ttl {
                    let neg_t = if t == 0 {
                        0
                    } else {
                        u64::from(t).clamp(MIN_NXDOMAIN_TTL_SECS, MAX_NXDOMAIN_TTL_SECS)
                    };
                    min_neg_ttl = Some(min_neg_ttl.map_or(neg_t, |c| c.min(neg_t)));
                }
            } else if meta.rcode == 0 {
                for cname in meta.cname_targets {
                    let norm_c = cname.trim().trim_end_matches('.').to_ascii_lowercase();
                    if !norm_c.is_empty() && !cnames.contains(&norm_c) {
                        cnames.push(norm_c);
                    }
                }
                if meta.answers.is_empty() {
                    if cnames.is_empty() {
                        saw_nodata = true;
                        if let Some(t) = meta.min_ttl {
                            let neg_t = if t == 0 {
                                0
                            } else {
                                u64::from(t).clamp(MIN_NEGATIVE_TTL_SECS, MAX_NEGATIVE_TTL_SECS)
                            };
                            min_neg_ttl = Some(min_neg_ttl.map_or(neg_t, |c| c.min(neg_t)));
                        }
                    } else if let Some(t) = meta.min_ttl {
                        let pos_t = if t == 0 {
                            0
                        } else {
                            u64::from(t).clamp(MIN_POSITIVE_TTL_SECS, MAX_POSITIVE_TTL_SECS)
                        };
                        min_pos_ttl = Some(min_pos_ttl.map_or(pos_t, |c| c.min(pos_t)));
                    }
                } else {
                    let pos_t = match meta.min_ttl {
                        Some(0) => 0,
                        other => u64::from(other.unwrap_or(60))
                            .clamp(MIN_POSITIVE_TTL_SECS, MAX_POSITIVE_TTL_SECS),
                    };
                    min_pos_ttl = Some(min_pos_ttl.map_or(pos_t, |c| c.min(pos_t)));
                    for ans in meta.answers {
                        match ans {
                            DnsAnswerData::A(v4) => {
                                let ip = IpAddr::V4(v4);
                                if !self.is_fake_ip(ip) && !resolved.contains(&ip) {
                                    resolved.push(ip);
                                }
                            }
                            DnsAnswerData::Aaaa(v6) if want_ipv6 => {
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
        (
            resolved,
            min_pos_ttl,
            min_neg_ttl,
            saw_nxdomain,
            saw_nodata,
            cnames,
        )
    }

    async fn query_slice_ips(
        &self,
        slice: &[DnsUpstream],
        normalized: &str,
        want_ipv6: bool,
    ) -> (
        Vec<IpAddr>,
        Option<u64>,
        Option<u64>,
        bool,
        bool,
        Option<String>,
    ) {
        let mut current = normalized.to_string();
        let mut visited = std::collections::HashSet::with_capacity(6);
        visited.insert(current.clone());
        let mut agg_pos_ttl: Option<u64> = None;

        for _ in 0..5 {
            let (metas, err_detail) = if want_ipv6 {
                let ((m_a, e_a), (m_aaaa, e_aaaa)) = tokio::join!(
                    self.query_slice_qtype(slice, &current, QTYPE_A),
                    self.query_slice_qtype(slice, &current, QTYPE_AAAA)
                );
                ([m_a, m_aaaa], e_a.or(e_aaaa))
            } else {
                let (m_a, e_a) = self.query_slice_qtype(slice, &current, QTYPE_A).await;
                ([m_a, None], e_a)
            };
            let (resolved, pos_ttl, neg_ttl, saw_nx, saw_nodata, cnames) =
                self.collect_ips_from_metas(metas, want_ipv6);
            if let Some(pt) = pos_ttl {
                agg_pos_ttl = Some(agg_pos_ttl.map_or(pt, |c| c.min(pt)));
            }
            if !resolved.is_empty() {
                return (
                    resolved,
                    agg_pos_ttl,
                    neg_ttl,
                    saw_nx,
                    saw_nodata,
                    err_detail,
                );
            }
            if let Some(next_cname) = cnames.into_iter().find(|c| visited.insert(c.clone())) {
                if let Some(static_ips) = self.lookup_static_hosts_filtered(&next_cname, want_ipv6)
                    && !static_ips.is_empty()
                {
                    return (static_ips, agg_pos_ttl, None, false, false, None);
                }
                current = next_cname;
                continue;
            }
            return (
                resolved,
                agg_pos_ttl,
                neg_ttl,
                saw_nx,
                saw_nodata,
                err_detail,
            );
        }
        (Vec::new(), agg_pos_ttl, None, false, false, None)
    }

    async fn query_upstream_ips(
        &self,
        normalized: &str,
        want_ipv6: bool,
    ) -> (Vec<IpAddr>, Option<u64>, Option<u64>, bool, bool) {
        let mut current = normalized.to_string();
        let mut visited = std::collections::HashSet::with_capacity(6);
        visited.insert(current.clone());
        let mut agg_pos_ttl: Option<u64> = None;

        for _ in 0..5 {
            let metas = if want_ipv6 {
                let (m_a, m_aaaa) = tokio::join!(
                    self.query_upstream_qtype(&current, QTYPE_A),
                    self.query_upstream_qtype(&current, QTYPE_AAAA)
                );
                [m_a, m_aaaa]
            } else {
                [self.query_upstream_qtype(&current, QTYPE_A).await, None]
            };
            let (resolved, pos_ttl, neg_ttl, saw_nx, saw_nodata, cnames) =
                self.collect_ips_from_metas(metas, want_ipv6);
            if let Some(pt) = pos_ttl {
                agg_pos_ttl = Some(agg_pos_ttl.map_or(pt, |c| c.min(pt)));
            }
            if !resolved.is_empty() {
                return (resolved, agg_pos_ttl, neg_ttl, saw_nx, saw_nodata);
            }
            if let Some(next_cname) = cnames.into_iter().find(|c| visited.insert(c.clone())) {
                if let Some(static_ips) = self.lookup_static_hosts_filtered(&next_cname, want_ipv6)
                    && !static_ips.is_empty()
                {
                    return (static_ips, agg_pos_ttl, None, false, false);
                }
                if let Some(policy_ups) =
                    Self::matching_policy_upstreams(&self.policy_rules, &next_cname)
                {
                    let (r, p, n, nx, nd, _) = self
                        .query_slice_ips(policy_ups, &next_cname, want_ipv6)
                        .await;
                    let merged_p = match (agg_pos_ttl, p) {
                        (Some(a), Some(b)) => Some(a.min(b)),
                        (a, b) => a.or(b),
                    };
                    return (r, merged_p, n, nx, nd);
                }
                current = next_cname;
                continue;
            }
            return (resolved, agg_pos_ttl, neg_ttl, saw_nx, saw_nodata);
        }
        (Vec::new(), agg_pos_ttl, None, false, false)
    }

    /// Resolve a domain name to real IPv4 (and IPv6 if `dns.ipv6: true` and direct IPv6 is reachable)
    /// addresses via static `hosts`, `nameserver-policy`, or configured `nameserver` / `fallback`
    /// upstreams with TTL-aware positive and negative caching and singleflight coalescing.
    /// Never falls back to OS `lookup_host` when `nameserver`s are configured.
    pub async fn resolve_real_ips(&self, domain: &str) -> Result<Vec<IpAddr>> {
        self.resolve_real_ips_inner(domain, self.direct_ipv6_enabled())
            .await
    }

    async fn resolve_real_ips_inner(&self, domain: &str, want_ipv6: bool) -> Result<Vec<IpAddr>> {
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
            return if want_ipv6 {
                Ok(vec![
                    IpAddr::V4(Ipv4Addr::LOCALHOST),
                    IpAddr::V6(Ipv6Addr::LOCALHOST),
                ])
            } else {
                Ok(vec![IpAddr::V4(Ipv4Addr::LOCALHOST)])
            };
        }
        if let Some(static_ips) = self.lookup_static_hosts_filtered(&normalized, want_ipv6) {
            return Ok(static_ips);
        }

        if let Some(cached) = self
            .lookup_cached_ips_paced(&self.real_ip_cache, &normalized, want_ipv6, false)
            .await
        {
            self.resolver_cache_hits.fetch_add(1, Ordering::Relaxed);
            return cached;
        }

        let mut start_epoch = self.current_cache_epoch();
        let inflight_guard = match InflightLookupGuard::acquire(
            &self.inflight_real,
            (start_epoch, normalized.clone(), want_ipv6),
        ) {
            Ok(guard) => Some(guard),
            Err(mut rx) => {
                if let Some(outcome) = wait_for_inflight_outcome(&mut rx).await
                    && self.current_cache_epoch() == start_epoch
                {
                    return outcome;
                }
                start_epoch = self.current_cache_epoch();
                if let Some(cached) =
                    Self::lookup_cached_ips(&self.real_ip_cache, &normalized, want_ipv6, false)
                {
                    return cached;
                }
                None
            }
        };

        if let Some(cached) =
            Self::lookup_cached_ips(&self.real_ip_cache, &normalized, want_ipv6, false)
        {
            if let Some(g) = inflight_guard {
                g.finish(&cached);
            }
            return cached;
        }

        let (mut resolved, min_pos_ttl, min_neg_ttl, saw_nxdomain, saw_nodata) =
            if let Some(policy_ups) =
                Self::matching_policy_upstreams(&self.policy_rules, &normalized)
            {
                let (r, p, n, nx, nd, _) = self
                    .query_slice_ips(policy_ups, &normalized, want_ipv6)
                    .await;
                (r, p, n, nx, nd)
            } else if !self.upstreams.is_empty() || !self.fallbacks.is_empty() {
                self.query_upstream_ips(&normalized, want_ipv6).await
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
                    if (!ip.is_ipv6() || want_ipv6)
                        && !self.is_fake_ip(ip)
                        && !resolved.contains(&ip)
                    {
                        resolved.push(ip);
                    }
                }
            }
        }

        if resolved.is_empty() {
            let is_nxdomain = saw_nxdomain && !saw_nodata;
            if saw_nxdomain || saw_nodata {
                let ttl = compute_negative_ttl_secs(min_neg_ttl, is_nxdomain);
                self.put_ip_cache_if_epoch(
                    &self.real_ip_cache,
                    start_epoch,
                    normalized.clone(),
                    CachedIpResolution::new_negative(ttl, is_nxdomain),
                );
            } else {
                if let Some(stale_ips) = Self::try_serve_stale_on_error(
                    &self.real_ip_cache,
                    &normalized,
                    want_ipv6,
                    false,
                ) {
                    self.resolver_cache_hits.fetch_add(1, Ordering::Relaxed);
                    let res = Ok(stale_ips);
                    if let Some(g) = inflight_guard {
                        g.finish(&res);
                    }
                    return res;
                }
                self.put_ip_cache_if_epoch(
                    &self.real_ip_cache,
                    start_epoch,
                    normalized.clone(),
                    CachedIpResolution::new_transient_failure(),
                );
            }
            let res = if is_nxdomain {
                Err(ProxyError::Dns(format!("DNS NXDOMAIN for '{normalized}'")))
            } else {
                Err(ProxyError::Dns(format!(
                    "DNS resolution failed for '{normalized}'"
                )))
            };
            if let Some(g) = inflight_guard {
                g.finish(&res);
            }
            return res;
        }

        if min_pos_ttl != Some(0) {
            let ttl = min_pos_ttl.unwrap_or(60);
            self.put_ip_cache_if_epoch(
                &self.real_ip_cache,
                start_epoch,
                normalized,
                CachedIpResolution::new_positive(ttl, resolved.clone()),
            );
        }
        let res = Ok(resolved);
        if let Some(g) = inflight_guard {
            g.finish(&res);
        }
        res
    }

    /// Resolve a domain name for `DIRECT` outbound dialing and `GEOIP,CN` rule matching.
    /// Honors static `hosts` and (when `direct-nameserver-follow-policy: true`, the default)
    /// `nameserver-policy` before `dns.direct-nameserver` (delegating to `resolve_real_ips` only when `direct-nameserver` is unset).
    pub async fn resolve_direct_ips(&self, domain: &str) -> Result<Vec<IpAddr>> {
        let want_ipv6 = self.direct_ipv6_enabled();
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
            return if want_ipv6 {
                Ok(vec![
                    IpAddr::V4(Ipv4Addr::LOCALHOST),
                    IpAddr::V6(Ipv6Addr::LOCALHOST),
                ])
            } else {
                Ok(vec![IpAddr::V4(Ipv4Addr::LOCALHOST)])
            };
        }
        if let Some(static_ips) = self.lookup_static_hosts_filtered(&normalized, want_ipv6) {
            return Ok(static_ips);
        }
        if self.direct_upstreams.is_empty()
            || (self.direct_nameserver_follow_policy
                && Self::matching_policy_upstreams(&self.policy_rules, &normalized).is_some())
        {
            return self.resolve_real_ips_inner(domain, want_ipv6).await;
        }

        if let Some(cached) = self
            .lookup_cached_ips_paced(&self.direct_ip_cache, &normalized, want_ipv6, false)
            .await
        {
            self.resolver_cache_hits.fetch_add(1, Ordering::Relaxed);
            return cached;
        }

        let mut start_epoch = self.current_cache_epoch();
        let inflight_guard = match InflightLookupGuard::acquire(
            &self.inflight_direct,
            (start_epoch, normalized.clone(), want_ipv6),
        ) {
            Ok(guard) => Some(guard),
            Err(mut rx) => {
                if let Some(outcome) = wait_for_inflight_outcome(&mut rx).await
                    && self.current_cache_epoch() == start_epoch
                {
                    return outcome;
                }
                start_epoch = self.current_cache_epoch();
                if let Some(cached) =
                    Self::lookup_cached_ips(&self.direct_ip_cache, &normalized, want_ipv6, false)
                {
                    return cached;
                }
                None
            }
        };

        if let Some(cached) =
            Self::lookup_cached_ips(&self.direct_ip_cache, &normalized, want_ipv6, false)
        {
            if let Some(g) = inflight_guard {
                g.finish(&cached);
            }
            return cached;
        }

        let (resolved, min_pos_ttl, min_neg_ttl, saw_nxdomain, saw_nodata, err_detail) = self
            .query_slice_ips(&self.direct_upstreams, &normalized, want_ipv6)
            .await;

        if !resolved.is_empty() {
            if min_pos_ttl != Some(0) {
                let ttl = min_pos_ttl.unwrap_or(60);
                self.put_ip_cache_if_epoch(
                    &self.direct_ip_cache,
                    start_epoch,
                    normalized,
                    CachedIpResolution::new_positive(ttl, resolved.clone()),
                );
            }
            let res = Ok(resolved);
            if let Some(g) = inflight_guard {
                g.finish(&res);
            }
            return res;
        }

        if saw_nxdomain || saw_nodata {
            let is_nxdomain = saw_nxdomain && !saw_nodata;
            let neg_ttl_secs = compute_negative_ttl_secs(min_neg_ttl, is_nxdomain);
            self.put_ip_cache_if_epoch(
                &self.direct_ip_cache,
                start_epoch,
                normalized.clone(),
                CachedIpResolution::new_negative(neg_ttl_secs, is_nxdomain),
            );
            let res = Err(ProxyError::Dns(if is_nxdomain {
                format!("DNS NXDOMAIN for '{normalized}'")
            } else {
                format!("DNS resolution failed for '{normalized}'")
            }));
            if let Some(g) = inflight_guard {
                g.finish(&res);
            }
            return res;
        }

        if let Some(stale_ips) =
            Self::try_serve_stale_on_error(&self.direct_ip_cache, &normalized, want_ipv6, false)
        {
            self.resolver_cache_hits.fetch_add(1, Ordering::Relaxed);
            let res = Ok(stale_ips);
            if let Some(g) = inflight_guard {
                g.finish(&res);
            }
            return res;
        }

        if !err_detail
            .as_deref()
            .is_some_and(|d| d.contains("HTTP status 429"))
        {
            self.put_ip_cache_if_epoch(
                &self.direct_ip_cache,
                start_epoch,
                normalized.clone(),
                CachedIpResolution::new_transient_failure(),
            );
        }
        let suffix = err_detail.map_or_else(String::new, |d| format!(" ({d})"));
        let res = Err(ProxyError::Dns(format!(
            "direct-nameserver DNS resolution failed for '{normalized}'{suffix}"
        )));
        if let Some(g) = inflight_guard {
            g.finish(&res);
        }
        res
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
        let want_ipv6 = self.direct_ipv6_enabled();
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
        if let Some(static_ips) = self.lookup_static_hosts_for_endpoint(&clean, want_ipv6) {
            return Ok(static_ips);
        }

        if let Some(cached) = self
            .lookup_cached_ips_paced(&self.proxy_ip_cache, &clean, want_ipv6, true)
            .await
        {
            self.resolver_cache_hits.fetch_add(1, Ordering::Relaxed);
            return cached;
        }

        let mut start_epoch = self.current_cache_epoch();
        let inflight_guard = match InflightLookupGuard::acquire(
            &self.inflight_proxy,
            (start_epoch, clean.clone(), want_ipv6),
        ) {
            Ok(guard) => Some(guard),
            Err(mut rx) => {
                if let Some(outcome) = wait_for_inflight_outcome(&mut rx).await
                    && self.current_cache_epoch() == start_epoch
                {
                    return outcome;
                }
                start_epoch = self.current_cache_epoch();
                if let Some(cached) =
                    Self::lookup_cached_ips(&self.proxy_ip_cache, &clean, want_ipv6, true)
                {
                    return cached;
                }
                None
            }
        };

        if let Some(cached) = Self::lookup_cached_ips(&self.proxy_ip_cache, &clean, want_ipv6, true)
        {
            if let Some(g) = inflight_guard {
                g.finish(&cached);
            }
            return cached;
        }

        let res = async {
            let cache_and_return =
                |ips: Vec<IpAddr>, ttl_opt: Option<u64>| -> Result<Vec<IpAddr>> {
                    if ttl_opt != Some(0) {
                        let ttl = ttl_opt.unwrap_or(60);
                        self.put_ip_cache_if_epoch(
                            &self.proxy_ip_cache,
                            start_epoch,
                            clean.clone(),
                            CachedIpResolution::new_positive(ttl, ips.clone()),
                        );
                    }
                    Ok(ips)
                };

            // 1. Dedicated `proxy-server-nameserver-policy`
            if let Some(ps_pol) = Self::matching_policy_upstreams(&self.proxy_policy_rules, &clean)
            {
                let (ips, pos_ttl, neg_ttl, saw_nx, saw_nodata, err_detail) =
                    self.query_slice_ips(ps_pol, &clean, want_ipv6).await;
                if !ips.is_empty() {
                    return cache_and_return(ips, pos_ttl);
                }
                if saw_nx || saw_nodata {
                    let is_nx = saw_nx && !saw_nodata;
                    let ttl = compute_negative_ttl_secs(neg_ttl, is_nx);
                    self.put_ip_cache_if_epoch(
                        &self.proxy_ip_cache,
                        start_epoch,
                        clean.clone(),
                        CachedIpResolution::new_negative(ttl, is_nx),
                    );
                } else {
                    if let Some(stale_ips) = Self::try_serve_stale_on_error(
                        &self.proxy_ip_cache,
                        &clean,
                        want_ipv6,
                        true,
                    ) {
                        self.resolver_cache_hits.fetch_add(1, Ordering::Relaxed);
                        return Ok(stale_ips);
                    }
                    self.put_ip_cache_if_epoch(
                        &self.proxy_ip_cache,
                        start_epoch,
                        clean.clone(),
                        CachedIpResolution::new_transient_failure(),
                    );
                }
                let suffix = err_detail.map_or_else(String::new, |d| format!(" ({d})"));
                return Err(ProxyError::Dns(format!(
                    "proxy-server-nameserver-policy DNS resolution failed for '{clean}'{suffix}"
                )));
            }

            // 2. Dedicated `proxy-server-nameserver`
            if !self.proxy_upstreams.is_empty() {
                let (ips, pos_ttl, neg_ttl, saw_nx, saw_nodata, err_detail) = self
                    .query_slice_ips(&self.proxy_upstreams, &clean, want_ipv6)
                    .await;
                if !ips.is_empty() {
                    return cache_and_return(ips, pos_ttl);
                }
                if saw_nx || saw_nodata {
                    let is_nx = saw_nx && !saw_nodata;
                    let ttl = compute_negative_ttl_secs(neg_ttl, is_nx);
                    self.put_ip_cache_if_epoch(
                        &self.proxy_ip_cache,
                        start_epoch,
                        clean.clone(),
                        CachedIpResolution::new_negative(ttl, is_nx),
                    );
                } else {
                    if let Some(stale_ips) = Self::try_serve_stale_on_error(
                        &self.proxy_ip_cache,
                        &clean,
                        want_ipv6,
                        true,
                    ) {
                        self.resolver_cache_hits.fetch_add(1, Ordering::Relaxed);
                        return Ok(stale_ips);
                    }
                    self.put_ip_cache_if_epoch(
                        &self.proxy_ip_cache,
                        start_epoch,
                        clean.clone(),
                        CachedIpResolution::new_transient_failure(),
                    );
                }
                let suffix = err_detail.map_or_else(String::new, |d| format!(" ({d})"));
                return Err(ProxyError::Dns(format!(
                    "proxy-server-nameserver DNS resolution failed for '{clean}'{suffix}"
                )));
            }

            // 3. Domain-scoped `nameserver-policy` (used by subscriptions with self-hosted DoH/DoT!)
            if let Some(pol) = Self::matching_policy_upstreams(&self.policy_rules, &clean) {
                let (ips, pos_ttl, neg_ttl, saw_nx, saw_nodata, err_detail) =
                    self.query_slice_ips(pol, &clean, want_ipv6).await;
                if !ips.is_empty() {
                    return cache_and_return(ips, pos_ttl);
                }
                if saw_nx || saw_nodata {
                    let is_nx = saw_nx && !saw_nodata;
                    let ttl = compute_negative_ttl_secs(neg_ttl, is_nx);
                    self.put_ip_cache_if_epoch(
                        &self.proxy_ip_cache,
                        start_epoch,
                        clean.clone(),
                        CachedIpResolution::new_negative(ttl, is_nx),
                    );
                } else {
                    if let Some(stale_ips) = Self::try_serve_stale_on_error(
                        &self.proxy_ip_cache,
                        &clean,
                        want_ipv6,
                        true,
                    ) {
                        self.resolver_cache_hits.fetch_add(1, Ordering::Relaxed);
                        return Ok(stale_ips);
                    }
                    self.put_ip_cache_if_epoch(
                        &self.proxy_ip_cache,
                        start_epoch,
                        clean.clone(),
                        CachedIpResolution::new_transient_failure(),
                    );
                }
                let suffix = err_detail.map_or_else(String::new, |d| format!(" ({d})"));
                return Err(ProxyError::Dns(format!(
                    "nameserver-policy DNS resolution failed for proxy server{suffix}"
                )));
            }

            // 4. Configured `nameserver` / `fallback` & `direct-nameserver`
            if let Ok(ips) = self.resolve_real_ips_inner(&clean, want_ipv6).await
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
            let mut ips: Vec<IpAddr> = addrs
                .iter()
                .map(|sa| sa.ip())
                .filter(|ip| (!ip.is_ipv6() || want_ipv6) && !self.is_fake_ip(*ip))
                .collect();
            if ips.is_empty() {
                ips = addrs
                    .into_iter()
                    .map(|sa| sa.ip())
                    .filter(|ip| !self.is_fake_ip(*ip))
                    .collect();
            }
            if ips.is_empty() {
                return Err(ProxyError::Dns(
                    "unable to resolve real IP for proxy server".into(),
                ));
            }
            cache_and_return(ips, Some(60))
        }
        .await;

        let res = match res {
            Ok(ips) => Ok(ips),
            Err(e) => {
                let authoritative_neg = matches!(
                    self.proxy_ip_cache.lock().peek(&clean),
                    Some(CachedIpResolution::Negative { .. })
                );
                if !authoritative_neg
                    && let Some(stale_ips) = Self::try_serve_stale_on_error(
                        &self.proxy_ip_cache,
                        &clean,
                        want_ipv6,
                        true,
                    )
                {
                    self.resolver_cache_hits.fetch_add(1, Ordering::Relaxed);
                    Ok(stale_ips)
                } else {
                    Err(e)
                }
            }
        };

        if let Some(g) = inflight_guard {
            g.finish(&res);
        }
        res
    }

    pub fn entries_snapshot(&self) -> Vec<FakeIpEntry> {
        self.pool.lock().snapshot()
    }

    pub fn entry_count(&self) -> usize {
        self.pool.lock().ip_to_domain.len()
    }

    /// Persist up to `2048` MRU Fake-IP <-> domain mappings atomically via a unique sibling `.tmp.<pid>.<seq>` file.
    pub fn save_to_path(&self, path: &std::path::Path) -> std::io::Result<usize> {
        static SAVE_TMP_SEQ: AtomicU64 = AtomicU64::new(0);
        let _save_guard = self.save_lock.lock();
        let (rev, mut entries) = {
            let guard = self.pool.lock();
            (
                self.dirty_revision.load(Ordering::Acquire),
                guard.snapshot(),
            )
        };
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
        let seq = SAVE_TMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let mut tmp_os = path.as_os_str().to_os_string();
        tmp_os.push(format!(".tmp.{}.{seq}", std::process::id()));
        let tmp_path = std::path::PathBuf::from(tmp_os);
        #[cfg(unix)]
        {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp_path)?;
            if let Err(err) = f.write_all(&encoded) {
                drop(f);
                let _ = std::fs::remove_file(&tmp_path);
                return Err(err);
            }
        }
        #[cfg(not(unix))]
        {
            if let Err(err) = std::fs::write(&tmp_path, &encoded) {
                let _ = std::fs::remove_file(&tmp_path);
                return Err(err);
            }
        }
        if let Err(err) = std::fs::rename(&tmp_path, path) {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(err);
        }
        self.persisted_revision.fetch_max(rev, Ordering::AcqRel);
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
        {
            let mut guard = self.pool.lock();
            for entry in parsed.entries.into_iter().rev() {
                if let Ok(v4) = entry.ip.parse::<Ipv4Addr>()
                    && !self.should_bypass_fake_ip(&entry.domain)
                    && guard.insert_preserved(v4, &entry.domain, self.net)
                {
                    loaded += 1;
                }
            }
            let rev = self.dirty_revision.load(Ordering::Acquire);
            self.persisted_revision.fetch_max(rev, Ordering::AcqRel);
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
            resolver_cache_hits: self.resolver_cache_hits.load(Ordering::Relaxed),
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
        let now_wall = current_epoch_ms();
        let in_direct = matches!(
            self.direct_ip_cache.lock().peek(normalized),
            Some(CachedIpResolution::Negative {
                expires_at,
                expires_wall_ms,
                nxdomain: true,
            }) if *expires_at > now && *expires_wall_ms > now_wall
        );
        if in_direct {
            return true;
        }
        matches!(
            self.real_ip_cache.lock().peek(normalized),
            Some(CachedIpResolution::Negative {
                expires_at,
                expires_wall_ms,
                nxdomain: true,
            }) if *expires_at > now && *expires_wall_ms > now_wall
        )
    }

    /// Returns `true` when `direct_ip_cache` (populated only for domains already routed to `DIRECT`)
    /// holds an unexpired `NODATA` entry or an IPv6-only entry with zero IPv4 addresses.
    /// Deliberately never inspects `real_ip_cache` so poisoned empty `A` responses on `nameserver`
    /// cannot suppress Fake-IP synthesis for proxied domains.
    fn has_cached_direct_nodata(&self, normalized: &str) -> bool {
        let now = Instant::now();
        let now_wall = current_epoch_ms();
        match self.direct_ip_cache.lock().peek(normalized) {
            Some(CachedIpResolution::Negative {
                expires_at,
                expires_wall_ms,
                nxdomain: false,
            }) => *expires_at > now && *expires_wall_ms > now_wall,
            Some(CachedIpResolution::Positive {
                expires_at,
                expires_wall_ms,
                ips,
                ..
            }) => {
                *expires_at > now && *expires_wall_ms > now_wall && !ips.iter().any(IpAddr::is_ipv4)
            }
            _ => false,
        }
    }

    /// Process a raw RFC 1035 DNS request packet, returning the encoded DNS response packet.
    pub async fn handle_dns_packet(&self, raw_query: &[u8]) -> Result<Vec<u8>> {
        self.total_queries.fetch_add(1, Ordering::Relaxed);
        let query = DnsQueryPacket::parse(raw_query)?;
        let domain = query.question.name.as_str();
        let normalized = domain.trim().trim_end_matches('.').to_ascii_lowercase();

        // Built-in RFC 6761 localhost resolution (`localhost` and `*.localhost`)
        if normalized == "localhost" || normalized.ends_with(".localhost") {
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

        // Built-in RFC 6761 `.invalid` and malformed literal SDK hostnames (`"null"`, `"undefined"`):
        // return instant local NXDOMAIN (RCODE=3) without allocating Fake-IP or leaking upstream.
        if normalized.is_empty()
            || normalized == "invalid"
            || normalized.ends_with(".invalid")
            || normalized == "null"
            || normalized == "undefined"
        {
            self.cache_hits.fetch_add(1, Ordering::Relaxed);
            self.nxdomain_hits.fetch_add(1, Ordering::Relaxed);
            return Ok(query.build_response(raw_query, 3, 60, &[]));
        }

        // Enforce `dns.ipv6: false` across ALL modes so IPv6/HTTPS-hint queries never leak or stall Happy-Eyeballs
        if !self.ipv6 && matches!(query.question.qtype, QTYPE_AAAA | QTYPE_SVCB | QTYPE_HTTPS) {
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

        let bypass_fake =
            !self.enabled || !self.fake_ip_mode || self.should_bypass_fake_ip(&normalized);
        if !bypass_fake {
            match query.question.qtype {
                QTYPE_A | QTYPE_AAAA | QTYPE_SVCB | QTYPE_HTTPS
                    if self.has_cached_nxdomain(&normalized) =>
                {
                    self.cache_hits.fetch_add(1, Ordering::Relaxed);
                    self.nxdomain_hits.fetch_add(1, Ordering::Relaxed);
                    return Ok(query.build_response(raw_query, 3, 5, &[]));
                }
                QTYPE_A
                    if !self.direct_ipv6_enabled()
                        && self.has_cached_direct_nodata(&normalized) =>
                {
                    self.cache_hits.fetch_add(1, Ordering::Relaxed);
                    return Ok(query.build_response(raw_query, 0, 5, &[]));
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
        } else if matches!(query.question.qtype, QTYPE_AAAA | QTYPE_SVCB | QTYPE_HTTPS)
            && !crate::platform::socket_protect::is_direct_ipv6_reachable()
        {
            // Suppress real-IP AAAA and HTTPS/SVCB (`ipv6hint`) queries when direct physical IPv6
            // egress is unreachable so apps never receive unreachable global IPv6 hints or stall.
            self.suppressed_queries.fetch_add(1, Ordering::Relaxed);
            return Ok(query.build_response(raw_query, 0, 5, &[]));
        }

        // Check TTL-aware wire packet cache (`redir-host` / `normal` / bypassed domains)
        let cache_key = (
            normalized.clone(),
            query.question.qtype,
            query.question.qclass,
        );
        let now = Instant::now();
        let now_wall = current_epoch_ms();
        if let Some(cached) = self.packet_cache.lock().get(&cache_key).cloned()
            && now < cached.expires_at
            && now_wall < cached.expires_wall_ms
            && cached.wire.len() >= 12
        {
            self.cache_hits.fetch_add(1, Ordering::Relaxed);
            let mono_secs = now.saturating_duration_since(cached.inserted_at).as_secs();
            let wall_secs = now_wall.saturating_sub(cached.inserted_wall_ms) / 1_000;
            let elapsed_secs = mono_secs.max(wall_secs).min(u32::MAX as u64) as u32;
            return Ok(patch_cached_dns_wire_response(
                &cached.wire,
                raw_query,
                &query,
                elapsed_secs,
            ));
        }

        let start_epoch = self.current_cache_epoch();
        let upstream_res = if let Some(pol_ups) =
            Self::matching_policy_upstreams(&self.policy_rules, &normalized)
        {
            self.exchange_with_upstream_slice(pol_ups, raw_query).await
        } else {
            self.exchange_with_upstreams(raw_query).await
        };

        if let Ok(resp) = upstream_res {
            if let Ok(meta) = extract_dns_response_meta(&resp)
                && !meta.truncated
            {
                if meta.rcode == 0 && meta.ancount > 0 {
                    if meta.min_ttl != Some(0) {
                        let ttl = u64::from(meta.min_ttl.unwrap_or(60))
                            .clamp(MIN_POSITIVE_TTL_SECS, MAX_POSITIVE_TTL_SECS);
                        self.put_packet_cache_if_epoch(
                            start_epoch,
                            cache_key,
                            CachedWirePacket::new(ttl, resp.clone()),
                        );
                    }
                } else if meta.rcode == 3 || (meta.rcode == 0 && meta.ancount == 0) {
                    if meta.min_ttl != Some(0) {
                        let ttl =
                            compute_negative_ttl_secs(meta.min_ttl.map(u64::from), meta.rcode == 3);
                        self.put_packet_cache_if_epoch(
                            start_epoch,
                            cache_key,
                            CachedWirePacket::new(ttl, resp.clone()),
                        );
                    }
                } else if meta.rcode == 2 || meta.rcode == 5 {
                    self.put_packet_cache_if_epoch(
                        start_epoch,
                        cache_key,
                        CachedWirePacket::new(SERVFAIL_NEGATIVE_TTL_SECS, resp.clone()),
                    );
                }
            }
            return Ok(resp);
        }

        // Return SERVFAIL (2) if no upstream responded, caching briefly to suppress retry storms
        // ONLY if `cache_epoch` did not advance during the failed upstream attempt.
        let servfail_resp = query.build_response(raw_query, 2, 0, &[]);
        self.put_packet_cache_if_epoch(
            start_epoch,
            cache_key,
            CachedWirePacket::new(SERVFAIL_NEGATIVE_TTL_SECS, servfail_resp.clone()),
        );
        Ok(servfail_resp)
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
            let (ip, newly_inserted) = pool.get_or_assign(&domain);
            assert!(newly_inserted);
            assert_eq!(pool.get_or_assign(&domain), (ip, false));
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
        let snap = engine.telemetry_snapshot();
        assert_eq!(snap.resolver_cache_hits, 1);
        assert_eq!(snap.cache_hits, 0);

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

    fn build_negative_response_with_optional_soa(
        req: &[u8],
        rcode: u8,
        soa_ttl: Option<u32>,
    ) -> Vec<u8> {
        let parsed = DnsQueryPacket::parse(req).unwrap();
        let Some(ttl) = soa_ttl else {
            return parsed.build_response(req, rcode, 0, &[]);
        };
        let mut rdata = BytesMut::new();
        encode_domain_name("ns1.example.test", &mut rdata);
        encode_domain_name("hostmaster.example.test", &mut rdata);
        rdata.put_u32(1);
        rdata.put_u32(3600);
        rdata.put_u32(600);
        rdata.put_u32(86_400);
        rdata.put_u32(ttl);

        let mut out = BytesMut::new();
        out.put_u16(parsed.id);
        out.put_u16(0x8180 | u16::from(rcode & 0x0F));
        out.put_u16(1); // QDCOUNT
        out.put_u16(0); // ANCOUNT
        out.put_u16(1); // NSCOUNT
        out.put_u16(0); // ARCOUNT
        out.put_slice(&req[12..parsed.question.end_offset]);
        encode_domain_name("example.test", &mut out);
        out.put_u16(6); // TYPE = SOA
        out.put_u16(QCLASS_IN);
        out.put_u32(ttl);
        out.put_u16(rdata.len() as u16);
        out.put_slice(&rdata);
        out.to_vec()
    }

    #[tokio::test]
    async fn negative_cache_ttl_distinguishes_nxdomain_from_nodata() {
        let upstream_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_sock.local_addr().unwrap();

        let upstream_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            while let Ok((n, peer)) = upstream_sock.recv_from(&mut buf).await {
                let req = &buf[..n];
                let parsed = DnsQueryPacket::parse(req).unwrap();
                let qname = parsed.question.name.to_ascii_lowercase();
                let resp = match qname.as_str() {
                    "nx-no-soa.example.test" => {
                        build_negative_response_with_optional_soa(req, 3, None)
                    }
                    "nx-soa-900.example.test" => {
                        build_negative_response_with_optional_soa(req, 3, Some(900))
                    }
                    "nx-soa-10.example.test" => {
                        build_negative_response_with_optional_soa(req, 3, Some(10))
                    }
                    "nx-soa-120.example.test" => {
                        build_negative_response_with_optional_soa(req, 3, Some(120))
                    }
                    "nodata-no-soa.example.test" => {
                        build_negative_response_with_optional_soa(req, 0, None)
                    }
                    "nodata-soa-900.example.test" => {
                        build_negative_response_with_optional_soa(req, 0, Some(900))
                    }
                    other => panic!("unexpected query domain {other}"),
                };
                let _ = upstream_sock.send_to(&resp, peer).await;
            }
        });

        let cfg = DnsConfig {
            ipv6: false,
            direct_nameserver: vec![upstream_addr.to_string()],
            nameserver: vec![upstream_addr.to_string()],
            fallback: Vec::new(),
            ..DnsConfig::default()
        };
        let engine = FakeIpDnsEngine::new(&cfg).unwrap();

        let assert_neg_ttl = |cache: &Mutex<LruCache<String, CachedIpResolution>>,
                              domain: &str,
                              before: Instant,
                              after: Instant,
                              expected_secs: u64,
                              expected_nx: bool| {
            let entry = cache
                .lock()
                .peek(domain)
                .cloned()
                .unwrap_or_else(|| panic!("missing negative cache entry for {domain}"));
            match entry {
                CachedIpResolution::Negative {
                    expires_at,
                    nxdomain,
                    ..
                } => {
                    assert_eq!(nxdomain, expected_nx, "nxdomain mismatch for {domain}");
                    let dur = Duration::from_secs(expected_secs);
                    assert!(
                        expires_at >= before + dur && expires_at <= after + dur,
                        "expected {expected_secs}s negative TTL for {domain}, got {:?}",
                        expires_at.saturating_duration_since(before)
                    );
                }
                other => panic!("expected Negative cache entry for {domain}, got {other:?}"),
            }
        };

        // 1. NXDOMAIN without SOA -> caches for 180s (DEFAULT_NXDOMAIN_TTL_SECS)
        let before = Instant::now();
        assert!(
            engine
                .resolve_real_ips("nx-no-soa.example.test")
                .await
                .is_err()
        );
        let after = Instant::now();
        assert_neg_ttl(
            &engine.real_ip_cache,
            "nx-no-soa.example.test",
            before,
            after,
            180,
            true,
        );

        // 2. NXDOMAIN with SOA TTL 900s -> clamped to 600s (MAX_NXDOMAIN_TTL_SECS)
        let before = Instant::now();
        assert!(
            engine
                .resolve_direct_ips("nx-soa-900.example.test")
                .await
                .is_err()
        );
        let after = Instant::now();
        assert_neg_ttl(
            &engine.direct_ip_cache,
            "nx-soa-900.example.test",
            before,
            after,
            600,
            true,
        );

        // 3a. NXDOMAIN with ultra-short SOA TTL 10s (e.g. telemetry/SDK retry domains)
        //     -> clamped up to 60s (MIN_NXDOMAIN_TTL_SECS) to suppress upstream NXDOMAIN storms
        let before = Instant::now();
        assert!(
            engine
                .resolve_direct_ips("nx-soa-10.example.test")
                .await
                .is_err()
        );
        let after = Instant::now();
        assert_neg_ttl(
            &engine.direct_ip_cache,
            "nx-soa-10.example.test",
            before,
            after,
            60,
            true,
        );

        // 3b. NXDOMAIN with SOA TTL 120s -> honors 120s SOA TTL within [60, 600]
        let before = Instant::now();
        assert!(
            engine
                .resolve_real_ips("nx-soa-120.example.test")
                .await
                .is_err()
        );
        let after = Instant::now();
        assert_neg_ttl(
            &engine.real_ip_cache,
            "nx-soa-120.example.test",
            before,
            after,
            120,
            true,
        );

        // 4. RCODE=0 empty NODATA without SOA -> caches for 5s, capped <= 60s
        let before = Instant::now();
        assert!(
            engine
                .resolve_real_ips("nodata-no-soa.example.test")
                .await
                .is_err()
        );
        let after = Instant::now();
        assert_neg_ttl(
            &engine.real_ip_cache,
            "nodata-no-soa.example.test",
            before,
            after,
            5,
            false,
        );

        // 5. RCODE=0 empty NODATA with SOA TTL 900s -> capped at 60s (MAX_NEGATIVE_TTL_SECS)
        let before = Instant::now();
        assert!(
            engine
                .resolve_direct_ips("nodata-soa-900.example.test")
                .await
                .is_err()
        );
        let after = Instant::now();
        assert_neg_ttl(
            &engine.direct_ip_cache,
            "nodata-soa-900.example.test",
            before,
            after,
            60,
            false,
        );

        // 6. Wire packet_cache in normal mode also honors 60s..600s NXDOMAIN vs 5s..60s NODATA
        let normal_cfg = DnsConfig {
            enhanced_mode: "normal".to_string(),
            ..cfg
        };
        let normal_engine = FakeIpDnsEngine::new(&normal_cfg).unwrap();
        for (domain, expected_secs) in [
            ("nx-no-soa.example.test", 180u64),
            ("nx-soa-10.example.test", 60u64),
            ("nx-soa-900.example.test", 600u64),
            ("nodata-soa-900.example.test", 60u64),
        ] {
            let q = build_dns_query(0x3100, domain, QTYPE_A);
            let before = Instant::now();
            let _ = normal_engine.handle_dns_packet(&q).await.unwrap();
            let after = Instant::now();
            let cached = normal_engine
                .packet_cache
                .lock()
                .peek(&(domain.to_string(), QTYPE_A, crate::dns::wire::QCLASS_IN))
                .cloned()
                .unwrap_or_else(|| panic!("missing packet_cache entry for {domain}"));
            let dur = Duration::from_secs(expected_secs);
            assert!(
                cached.expires_at >= before + dur && cached.expires_at <= after + dur,
                "expected {expected_secs}s packet_cache TTL for {domain}, got {:?}",
                cached.expires_at.saturating_duration_since(before)
            );
        }

        upstream_task.abort();
    }

    #[tokio::test]
    async fn resolver_cache_hits_stays_separate_from_client_packet_cache_hits() {
        let upstream_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_sock.local_addr().unwrap();

        let upstream_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            while let Ok((n, peer)) = upstream_sock.recv_from(&mut buf).await {
                let req = &buf[..n];
                let parsed = DnsQueryPacket::parse(req).unwrap();
                let resp = parsed.build_response(
                    req,
                    0,
                    60,
                    &[DnsAnswerData::A(Ipv4Addr::new(203, 0, 113, 10))],
                );
                let _ = upstream_sock.send_to(&resp, peer).await;
            }
        });

        let cfg = DnsConfig {
            ipv6: false,
            direct_nameserver: vec![upstream_addr.to_string()],
            nameserver: vec![upstream_addr.to_string()],
            proxy_server_nameserver: vec![upstream_addr.to_string()],
            fallback: Vec::new(),
            ..DnsConfig::default()
        };
        let engine = FakeIpDnsEngine::new(&cfg).unwrap();

        assert_eq!(
            engine
                .resolve_real_ips("real.example.test")
                .await
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            engine
                .resolve_real_ips("real.example.test")
                .await
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            engine
                .resolve_direct_ips("direct.example.test")
                .await
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            engine
                .resolve_direct_ips("direct.example.test")
                .await
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            engine
                .resolve_proxy_server_ips("proxy-node.example.test")
                .await
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            engine
                .resolve_proxy_server_ips("proxy-node.example.test")
                .await
                .unwrap()
                .len(),
            1
        );

        let snap_after_resolvers = engine.telemetry_snapshot();
        assert_eq!(snap_after_resolvers.total_queries, 0);
        assert_eq!(snap_after_resolvers.cache_hits, 0);
        assert_eq!(snap_after_resolvers.resolver_cache_hits, 3);

        // Client DNS packet query increments total_queries and cache_hits without touching resolver_cache_hits
        let q_local = build_dns_query(0x4100, "localhost", QTYPE_A);
        let _ = engine.handle_dns_packet(&q_local).await.unwrap();
        let snap_after_pkt = engine.telemetry_snapshot();
        assert_eq!(snap_after_pkt.total_queries, 1);
        assert_eq!(snap_after_pkt.cache_hits, 1);
        assert_eq!(snap_after_pkt.resolver_cache_hits, 3);

        upstream_task.abort();
    }

    #[tokio::test]
    async fn fake_ip_dirty_tracking_transitions_across_assign_save_load_and_hot_reload() {
        let persist_path = std::env::temp_dir().join(format!(
            "rust-clash-fakeip-dirty-{:032x}.json",
            rand::random::<u128>()
        ));

        let engine1 = FakeIpDnsEngine::new(&DnsConfig::default()).unwrap();
        assert!(!engine1.has_unpersisted_entries());

        let notify = engine1.assignment_notify();
        let ip_a = engine1.assign_fake_ip("a.example.com");
        assert!(engine1.has_unpersisted_entries());
        tokio::time::timeout(Duration::from_millis(100), notify.notified())
            .await
            .expect("first Fake-IP assignment must notify background persistence");

        let rev_after_first = engine1.dirty_revision.load(Ordering::Acquire);
        assert_eq!(rev_after_first, 1);

        // Repeat lookup/assignment for an already mapped domain must not bump dirty_revision or notify
        assert_eq!(engine1.assign_fake_ip("a.example.com"), ip_a);
        assert_eq!(
            engine1.dirty_revision.load(Ordering::Acquire),
            rev_after_first
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(10), notify.notified())
                .await
                .is_err()
        );

        // Saving marks persisted_revision == dirty_revision -> has_unpersisted_entries() becomes false
        assert_eq!(engine1.save_to_path(&persist_path).unwrap(), 1);
        assert!(!engine1.has_unpersisted_entries());

        // Loading into a fresh engine keeps has_unpersisted_entries() == false
        let engine2 = FakeIpDnsEngine::new(&DnsConfig::default()).unwrap();
        assert_eq!(engine2.load_from_path(&persist_path), 1);
        assert!(!engine2.has_unpersisted_entries());
        assert_eq!(engine2.assign_fake_ip("a.example.com"), ip_a);
        assert!(!engine2.has_unpersisted_entries());

        // Assigning a new domain marks engine2 dirty, and hot-reloading into engine3 preserves dirty status
        let _ip_b = engine2.assign_fake_ip("b.example.com");
        assert!(engine2.has_unpersisted_entries());

        let engine3 = FakeIpDnsEngine::new(&DnsConfig::default()).unwrap();
        engine3.import_entries_from(&engine2);
        assert!(engine3.has_unpersisted_entries());

        let _ = std::fs::remove_file(&persist_path);
    }

    #[test]
    fn ipv4_only_underlying_network_uses_single_stack_a_fast_path_and_suppresses_bypass_aaaa() {
        let _ipv6_guard = crate::platform::socket_protect::lock_ipv6_reachability_for_test();
        crate::platform::socket_protect::set_os_underlying_ipv6_available(Some(false));

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let upstream_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
            let upstream_addr = upstream_sock.local_addr().unwrap();
            let a_queries = Arc::new(AtomicU64::new(0));
            let aaaa_queries = Arc::new(AtomicU64::new(0));

            let sock_bg = Arc::clone(&upstream_sock);
            let a_bg = Arc::clone(&a_queries);
            let aaaa_bg = Arc::clone(&aaaa_queries);
            let upstream_task = tokio::spawn(async move {
                let mut buf = [0u8; 512];
                while let Ok((n, peer)) = sock_bg.recv_from(&mut buf).await {
                    let req = buf[..n].to_vec();
                    let parsed = DnsQueryPacket::parse(&req).unwrap();
                    match parsed.question.qtype {
                        QTYPE_A => {
                            a_bg.fetch_add(1, Ordering::Relaxed);
                            let resp = parsed.build_response(
                                &req,
                                0,
                                60,
                                &[DnsAnswerData::A(Ipv4Addr::new(203, 0, 113, 88))],
                            );
                            let _ = sock_bg.send_to(&resp, peer).await;
                        }
                        QTYPE_AAAA => {
                            aaaa_bg.fetch_add(1, Ordering::Relaxed);
                            let sock_slow = Arc::clone(&sock_bg);
                            tokio::spawn(async move {
                                tokio::time::sleep(Duration::from_millis(1200)).await;
                                let resp = parsed.build_response(
                                    &req,
                                    0,
                                    60,
                                    &[DnsAnswerData::Aaaa("2409:8c1e:75b0::88".parse().unwrap())],
                                );
                                let _ = sock_slow.send_to(&resp, peer).await;
                            });
                        }
                        _ => {
                            let resp = parsed.build_response(&req, 0, 60, &[]);
                            let _ = sock_bg.send_to(&resp, peer).await;
                        }
                    }
                }
            });

            let mut filters = DnsConfig::default().fake_ip_filter;
            filters.push("+.cn".to_string());
            let cfg = DnsConfig {
                ipv6: true,
                fake_ip_filter: filters,
                direct_nameserver: vec![upstream_addr.to_string()],
                nameserver: vec![upstream_addr.to_string()],
                proxy_server_nameserver: vec![upstream_addr.to_string()],
                fallback: Vec::new(),
                ..DnsConfig::default()
            };
            let engine = FakeIpDnsEngine::new(&cfg).unwrap();

            // 1. Direct, proxy-server, and real-IP resolvers send ONLY QTYPE_A (0 QTYPE_AAAA) without stalling
            let t0 = Instant::now();
            let direct_ips = engine.resolve_direct_ips("ws.xiaoheihe.cn").await.unwrap();
            assert!(
                t0.elapsed() < Duration::from_millis(500),
                "resolve_direct_ips stalled on IPv4-only network: {:?}",
                t0.elapsed()
            );
            assert_eq!(direct_ips, vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 88))]);
            assert_eq!(a_queries.load(Ordering::Relaxed), 1);
            assert_eq!(aaaa_queries.load(Ordering::Relaxed), 0);

            let t1 = Instant::now();
            let proxy_ips = engine
                .resolve_proxy_server_ips("hk01.node.example.test")
                .await
                .unwrap();
            assert!(t1.elapsed() < Duration::from_millis(500));
            assert_eq!(proxy_ips, vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 88))]);
            assert_eq!(a_queries.load(Ordering::Relaxed), 2);
            assert_eq!(aaaa_queries.load(Ordering::Relaxed), 0);

            let real_ips = engine.resolve_real_ips("geo.example.test").await.unwrap();
            assert_eq!(real_ips, vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 88))]);
            assert_eq!(a_queries.load(Ordering::Relaxed), 3);
            assert_eq!(aaaa_queries.load(Ordering::Relaxed), 0);

            // Empty direct_nameserver delegation into resolve_real_ips_inner also stays single-stack QTYPE_A
            let delegated_cfg = DnsConfig {
                ipv6: true,
                direct_nameserver: Vec::new(),
                nameserver: vec![upstream_addr.to_string()],
                fallback: Vec::new(),
                ..DnsConfig::default()
            };
            let delegated_engine = FakeIpDnsEngine::new(&delegated_cfg).unwrap();
            let delegated_ips = delegated_engine
                .resolve_direct_ips("delegated.cn")
                .await
                .unwrap();
            assert_eq!(
                delegated_ips,
                vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 88))]
            );
            assert_eq!(a_queries.load(Ordering::Relaxed), 4);
            assert_eq!(aaaa_queries.load(Ordering::Relaxed), 0);

            // Pre-existing dual-stack positive cache entry filters out unreachable IPv6 when !want_ipv6
            engine.direct_ip_cache.lock().put(
                "dual-cached.cn".to_string(),
                CachedIpResolution::new_positive(
                    60,
                    vec![
                        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 88)),
                        IpAddr::V6("2409:8c1e:75b0::88".parse().unwrap()),
                    ],
                ),
            );
            let cached_ips = engine.resolve_direct_ips("dual-cached.cn").await.unwrap();
            assert_eq!(cached_ips, vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 88))]);
            assert_eq!(a_queries.load(Ordering::Relaxed), 4);

            // 2. Client AAAA query for fake-ip-filter bypassed domain is suppressed locally (NOERROR, 0 upstream queries)
            let q_bypass_aaaa = build_dns_query(0x5101, "ws.xiaoheihe.cn", QTYPE_AAAA);
            let r_bypass_aaaa = engine.handle_dns_packet(&q_bypass_aaaa).await.unwrap();
            assert_eq!(dns_response_rcode(&r_bypass_aaaa).unwrap(), 0);
            assert!(extract_ip_answers(&r_bypass_aaaa).unwrap().is_empty());
            assert_eq!(engine.telemetry_snapshot().suppressed_queries, 1);
            assert_eq!(a_queries.load(Ordering::Relaxed), 4);
            assert_eq!(aaaa_queries.load(Ordering::Relaxed), 0);

            // Bypassed QTYPE_A still resolves real IPv4 upstream normally
            let q_bypass_a = build_dns_query(0x5102, "ws.xiaoheihe.cn", QTYPE_A);
            let r_bypass_a = engine.handle_dns_packet(&q_bypass_a).await.unwrap();
            assert_eq!(
                extract_ip_answers(&r_bypass_a).unwrap(),
                vec![DnsAnswerData::A(Ipv4Addr::new(203, 0, 113, 88))]
            );
            assert_eq!(a_queries.load(Ordering::Relaxed), 5);
            assert_eq!(aaaa_queries.load(Ordering::Relaxed), 0);

            // Non-bypassed proxied domain still receives normal Fake-IP synthesis without incrementing suppressed_queries
            let q_proxy_a = build_dns_query(0x5103, "www.google.com", QTYPE_A);
            let r_proxy_a = engine.handle_dns_packet(&q_proxy_a).await.unwrap();
            assert_eq!(
                extract_ip_answers(&r_proxy_a).unwrap(),
                vec![DnsAnswerData::A(Ipv4Addr::new(198, 18, 0, 2))]
            );
            let q_proxy_aaaa = build_dns_query(0x5104, "www.google.com", QTYPE_AAAA);
            let r_proxy_aaaa = engine.handle_dns_packet(&q_proxy_aaaa).await.unwrap();
            assert_eq!(dns_response_rcode(&r_proxy_aaaa).unwrap(), 0);
            assert!(extract_ip_answers(&r_proxy_aaaa).unwrap().is_empty());

            let snap = engine.telemetry_snapshot();
            assert_eq!(snap.fake_ip_hits, 2);
            assert_eq!(snap.suppressed_queries, 1);
            assert_eq!(a_queries.load(Ordering::Relaxed), 5);
            assert_eq!(aaaa_queries.load(Ordering::Relaxed), 0);

            upstream_task.abort();
        });
    }

    #[tokio::test]
    async fn servfail_negative_cache_suppresses_immediate_retry_storms() {
        use std::sync::atomic::AtomicUsize;

        let upstream_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_sock.local_addr().unwrap();
        let hits = Arc::new(AtomicUsize::new(0));
        let hits_srv = Arc::clone(&hits);

        let srv_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            while let Ok((n, peer)) = upstream_sock.recv_from(&mut buf).await {
                hits_srv.fetch_add(1, Ordering::Relaxed);
                if let Ok(qp) = DnsQueryPacket::parse(&buf[..n]) {
                    let resp = qp.build_response(&buf[..n], 2, 0, &[]);
                    let _ = upstream_sock.send_to(&resp, peer).await;
                }
            }
        });

        let cfg = DnsConfig {
            enable: true,
            ipv6: false,
            enhanced_mode: "normal".to_string(),
            default_nameserver: vec![upstream_addr.to_string()],
            nameserver: vec![format!("udp://{upstream_addr}")],
            direct_nameserver: vec![format!("udp://{upstream_addr}")],
            ..DnsConfig::default()
        };
        let engine = FakeIpDnsEngine::new(&cfg).unwrap();

        // First lookup hits upstream and caches SERVFAIL negative entry briefly
        assert!(
            engine
                .resolve_direct_ips("broken-upstream.example")
                .await
                .is_err()
        );
        let first_hits = hits.load(Ordering::Relaxed);
        assert!(first_hits >= 1);

        // Immediate burst of retries hits the negative cache instead of hammering upstream
        for _ in 0..5 {
            assert!(
                engine
                    .resolve_direct_ips("broken-upstream.example")
                    .await
                    .is_err()
            );
        }
        assert_eq!(hits.load(Ordering::Relaxed), first_hits);

        // Explicit flush_cache clears the negative cache immediately
        engine.flush_cache();
        assert!(
            engine
                .resolve_direct_ips("broken-upstream.example")
                .await
                .is_err()
        );
        assert!(hits.load(Ordering::Relaxed) > first_hits);

        srv_task.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_save_to_path_never_corrupts_state_or_leaks_temp_files() {
        let test_dir = std::env::temp_dir().join(format!(
            "rustclash_fakeip_save_race_{}_{}",
            std::process::id(),
            current_epoch_ms()
        ));
        std::fs::create_dir_all(&test_dir).unwrap();
        let cache_path = test_dir.join("fake_ip_state.json");

        let engine = Arc::new(FakeIpDnsEngine::new(&DnsConfig::default()).unwrap());

        // Phase 1: Interleave concurrent Fake-IP allocations with 12 concurrent blocking save_to_path callers
        let mut alloc_handles = Vec::new();
        for i in 0..120usize {
            let eng = Arc::clone(&engine);
            alloc_handles.push(tokio::spawn(async move {
                let q = build_dns_query(i as u16, &format!("host-{i}.concurrent.example"), QTYPE_A);
                eng.handle_dns_packet(&q).await.unwrap();
            }));
        }

        let barrier = Arc::new(std::sync::Barrier::new(12));
        let mut save_handles = Vec::new();
        for _ in 0..12 {
            let eng = Arc::clone(&engine);
            let p = cache_path.clone();
            let b = Arc::clone(&barrier);
            save_handles.push(tokio::task::spawn_blocking(move || {
                b.wait();
                for _ in 0..20 {
                    eng.save_to_path(&p).unwrap();
                }
            }));
        }

        for h in alloc_handles {
            h.await.unwrap();
        }
        for h in save_handles {
            h.await.unwrap();
        }

        // Phase 2: All 120 entries are now in the pool; hammer save_to_path concurrently from two engines sharing the path
        let engine2 = Arc::new(FakeIpDnsEngine::new(&DnsConfig::default()).unwrap());
        engine2.import_entries_from(&engine);
        let barrier2 = Arc::new(std::sync::Barrier::new(8));
        let mut save_handles2 = Vec::new();
        for idx in 0..8 {
            let eng = if idx % 2 == 0 {
                Arc::clone(&engine)
            } else {
                Arc::clone(&engine2)
            };
            let p = cache_path.clone();
            let b = Arc::clone(&barrier2);
            save_handles2.push(tokio::task::spawn_blocking(move || {
                b.wait();
                for _ in 0..15 {
                    assert_eq!(eng.save_to_path(&p).unwrap(), 120);
                }
            }));
        }
        for h in save_handles2 {
            h.await.unwrap();
        }

        let restored = FakeIpDnsEngine::new(&DnsConfig::default()).unwrap();
        assert_eq!(restored.load_from_path(&cache_path), 120);

        // Phase 3: Rename failure (target path is an existing directory) MUST clean up its unique .tmp file
        let dir_target = test_dir.join("cannot_overwrite_dir.json");
        std::fs::create_dir_all(&dir_target).unwrap();
        assert!(engine.save_to_path(&dir_target).is_err());

        let leftover_tmps: Vec<_> = std::fs::read_dir(&test_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|name| name.contains(".tmp."))
            .collect();
        assert!(
            leftover_tmps.is_empty(),
            "leftover temp files found: {leftover_tmps:?}"
        );

        let _ = std::fs::remove_dir_all(&test_dir);
    }

    #[tokio::test]
    async fn handle_dns_packet_resolves_subdomain_localhost_and_short_circuits_invalid_or_null() {
        // Point nameserver to an unroutable port that never answers so any upstream leak fails/stalls
        let dead_udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dead_addr = dead_udp.local_addr().unwrap();
        let cfg = DnsConfig {
            ipv6: true,
            nameserver: vec![dead_addr.to_string()],
            fallback: Vec::new(),
            ..Default::default()
        };

        let engine = FakeIpDnsEngine::new(&cfg).unwrap();

        // 1. `tauri.localhost` resolves locally to 127.0.0.1 / ::1 without upstream traffic
        let q_local_a = build_dns_query(0x4101, "tauri.localhost", QTYPE_A);
        let resp_local_a = engine.handle_dns_packet(&q_local_a).await.unwrap();
        let meta_local_a = crate::dns::wire::extract_dns_response_meta(&resp_local_a).unwrap();
        assert_eq!(meta_local_a.rcode, 0);
        assert_eq!(
            meta_local_a.answers,
            vec![DnsAnswerData::A(Ipv4Addr::LOCALHOST)]
        );

        let q_local_aaaa = build_dns_query(0x4102, "api.localhost", QTYPE_AAAA);
        let resp_local_aaaa = engine.handle_dns_packet(&q_local_aaaa).await.unwrap();
        let meta_local_aaaa =
            crate::dns::wire::extract_dns_response_meta(&resp_local_aaaa).unwrap();
        assert_eq!(meta_local_aaaa.rcode, 0);
        assert_eq!(
            meta_local_aaaa.answers,
            vec![DnsAnswerData::Aaaa(Ipv6Addr::LOCALHOST)]
        );

        // 2. `"null"`, `"undefined"`, and `"*.invalid"` immediately return local NXDOMAIN (rcode=3)
        //    with zero Fake-IP allocations and zero upstream queries.
        for (idx, bad_host) in ["null", "undefined", "invalid", "sub-blocked.invalid"]
            .into_iter()
            .enumerate()
        {
            let q = build_dns_query(0x4200 + idx as u16, bad_host, QTYPE_A);
            let resp = engine.handle_dns_packet(&q).await.unwrap();
            let meta = crate::dns::wire::extract_dns_response_meta(&resp).unwrap();
            assert_eq!(meta.rcode, 3, "expected NXDOMAIN for {bad_host}");
            assert!(meta.answers.is_empty());
        }

        let snap = engine.telemetry_snapshot();
        assert_eq!(snap.active_fake_ip_entries, 0);
        assert_eq!(snap.upstream_queries, 0);
        assert_eq!(snap.nxdomain_hits, 4);
    }

    #[tokio::test]
    async fn stale_if_error_serves_expired_positive_on_transient_failure_but_never_overrides_nxdomain_or_flush()
     {
        use std::sync::atomic::AtomicU8;

        // Mode 0 = NOERROR (203.0.113.77), 2 = SERVFAIL, 3 = NXDOMAIN
        let mode = Arc::new(AtomicU8::new(0));
        let mode_srv = Arc::clone(&mode);
        let upstream_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_sock.local_addr().unwrap();

        let srv_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            while let Ok((n, peer)) = upstream_sock.recv_from(&mut buf).await {
                if let Ok(qp) = DnsQueryPacket::parse(&buf[..n]) {
                    let cur = mode_srv.load(Ordering::Relaxed);
                    let resp = if cur == 0 {
                        qp.build_response(
                            &buf[..n],
                            0,
                            5,
                            &[DnsAnswerData::A(Ipv4Addr::new(203, 0, 113, 77))],
                        )
                    } else {
                        qp.build_response(&buf[..n], cur, 30, &[])
                    };
                    let _ = upstream_sock.send_to(&resp, peer).await;
                }
            }
        });

        let cfg = DnsConfig {
            enable: true,
            ipv6: false,
            enhanced_mode: "fake-ip".to_string(),
            default_nameserver: vec![upstream_addr.to_string()],
            nameserver: vec![format!("udp://{upstream_addr}")],
            direct_nameserver: vec![format!("udp://{upstream_addr}")],
            ..DnsConfig::default()
        };
        let engine = FakeIpDnsEngine::new(&cfg).unwrap();

        // 1. Seed positive cache via normal resolution
        let initial = engine
            .resolve_direct_ips("t2.xiaohongshu.com")
            .await
            .unwrap();
        assert_eq!(initial, vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 77))]);

        // Expire normal TTL while keeping `stale_until` valid (simulating 30s CDN TTL expiring 10s before a 5G stall)
        {
            let mut guard = engine.direct_ip_cache.lock();
            if let Some(CachedIpResolution::Positive { expires_at, .. }) =
                guard.get_mut("t2.xiaohongshu.com")
            {
                *expires_at = Instant::now() - Duration::from_secs(1);
            }
        }

        // 2. Transient upstream failure (SERVFAIL / radio stall) MUST serve the recent positive IP via RFC 8767 stale-if-error
        mode.store(2, Ordering::Relaxed);
        let stale_served = engine
            .resolve_direct_ips("t2.xiaohongshu.com")
            .await
            .expect("stale-if-error should serve recent positive IP on transient failure");
        assert_eq!(
            stale_served,
            vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 77))]
        );

        // 3. Authoritative NXDOMAIN MUST NOT serve stale — it must evict positive cache and return NXDOMAIN
        {
            let mut guard = engine.direct_ip_cache.lock();
            if let Some(CachedIpResolution::Positive { expires_at, .. }) =
                guard.get_mut("t2.xiaohongshu.com")
            {
                *expires_at = Instant::now() - Duration::from_secs(1);
            }
        }
        mode.store(3, Ordering::Relaxed);
        let nx_err = engine
            .resolve_direct_ips("t2.xiaohongshu.com")
            .await
            .expect_err("NXDOMAIN must never serve stale positive IPs");
        assert!(
            nx_err.to_string().contains("NXDOMAIN"),
            "unexpected error: {nx_err}"
        );

        // 4. `flush_cache()` (network handoff) clears stale entries so old carrier IPs are never served
        mode.store(0, Ordering::Relaxed);
        engine.flush_cache();
        let reseeded = engine
            .resolve_direct_ips("wetype.weixin.qq.com")
            .await
            .unwrap();
        assert_eq!(reseeded, vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 77))]);
        engine.flush_cache();
        mode.store(2, Ordering::Relaxed);
        assert!(
            engine
                .resolve_direct_ips("wetype.weixin.qq.com")
                .await
                .is_err()
        );

        srv_task.abort();
    }

    #[tokio::test]
    async fn singleflight_followers_receive_identical_error_without_double_dns_error_prefix() {
        let upstream_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_sock.local_addr().unwrap();

        let srv_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            while let Ok((n, peer)) = upstream_sock.recv_from(&mut buf).await {
                let req = buf[..n].to_vec();
                if let Ok(qp) = DnsQueryPacket::parse(&req) {
                    tokio::time::sleep(Duration::from_millis(80)).await;
                    let resp = qp.build_response(&req, 2, 0, &[]);
                    let _ = upstream_sock.send_to(&resp, peer).await;
                }
            }
        });

        let cfg = DnsConfig {
            enable: true,
            ipv6: false,
            enhanced_mode: "fake-ip".to_string(),
            default_nameserver: vec![upstream_addr.to_string()],
            nameserver: vec![format!("udp://{upstream_addr}")],
            direct_nameserver: vec![format!("udp://{upstream_addr}")],
            ..DnsConfig::default()
        };
        let engine = Arc::new(FakeIpDnsEngine::new(&cfg).unwrap());

        let mut tasks = Vec::new();
        for _ in 0..4 {
            let eng = Arc::clone(&engine);
            tasks.push(tokio::spawn(async move {
                eng.resolve_direct_ips("singleflight-fail.example")
                    .await
                    .expect_err("expected failure")
                    .to_string()
            }));
        }

        let mut errs = Vec::new();
        for t in tasks {
            errs.push(t.await.unwrap());
        }
        let first = &errs[0];
        assert!(
            !first.contains("DNS error: DNS error:"),
            "unexpected double prefix: {first}"
        );
        for e in &errs[1..] {
            assert_eq!(
                e, first,
                "singleflight follower error diverged from leader error"
            );
        }

        srv_task.abort();
    }

    #[tokio::test]
    async fn fake_ip_mode_transient_failure_cache_paces_tight_retry_loops() {
        let upstream_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_sock.local_addr().unwrap();

        let srv_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            while let Ok((n, peer)) = upstream_sock.recv_from(&mut buf).await {
                if let Ok(qp) = DnsQueryPacket::parse(&buf[..n]) {
                    let resp = qp.build_response(&buf[..n], 2, 0, &[]);
                    let _ = upstream_sock.send_to(&resp, peer).await;
                }
            }
        });

        let cfg = DnsConfig {
            enable: true,
            ipv6: false,
            enhanced_mode: "fake-ip".to_string(),
            default_nameserver: vec![upstream_addr.to_string()],
            nameserver: vec![format!("udp://{upstream_addr}")],
            direct_nameserver: vec![format!("udp://{upstream_addr}")],
            ..DnsConfig::default()
        };
        let engine = FakeIpDnsEngine::new(&cfg).unwrap();

        // Cold-cache transient failure populates TransientFailure entry
        assert!(
            engine
                .resolve_direct_ips("cold-offline.example")
                .await
                .is_err()
        );

        // Immediate retry in fake-ip mode must be paced rather than spinning in 0ms
        let t0 = Instant::now();
        assert!(
            engine
                .resolve_direct_ips("cold-offline.example")
                .await
                .is_err()
        );
        assert!(
            t0.elapsed() >= Duration::from_millis(50),
            "expected Fake-IP TransientFailure pacing, got {:?}",
            t0.elapsed()
        );

        srv_task.abort();
    }

    #[test]
    fn recover_unmapped_fake_ip_preserves_existing_and_validates_inputs() {
        let engine = FakeIpDnsEngine::new(&DnsConfig::default()).unwrap();
        let active_ip = engine.assign_fake_ip("primary.example.com");

        // Never overwrite an already-mapped Fake-IP
        assert!(!engine.recover_unmapped_fake_ip(active_ip, "hijack.example.com"));
        assert_eq!(
            engine.lookup_domain(IpAddr::V4(active_ip)).as_deref(),
            Some("primary.example.com")
        );

        // Reject reserved TUN addresses (.0, .1), outside-range IPs, and invalid hostnames
        assert!(!engine.recover_unmapped_fake_ip(Ipv4Addr::new(198, 18, 0, 1), "bad.example.com"));
        assert!(!engine.recover_unmapped_fake_ip(Ipv4Addr::new(8, 8, 8, 8), "bad.example.com"));
        let stale_ip = Ipv4Addr::new(198, 18, 9, 55);
        assert!(!engine.recover_unmapped_fake_ip(stale_ip, "198.18.1.2"));
        assert!(!engine.recover_unmapped_fake_ip(stale_ip, "localhost"));

        // Recovering a stale Fake-IP aliases the domain in ip_to_domain while keeping primary IP
        assert!(engine.recover_unmapped_fake_ip(stale_ip, "Primary.Example.COM."));
        assert_eq!(
            engine.lookup_domain(IpAddr::V4(stale_ip)).as_deref(),
            Some("primary.example.com")
        );
        assert_eq!(engine.lookup_ip("primary.example.com"), Some(active_ip));
        assert!(engine.has_unpersisted_entries());
    }

    #[tokio::test]
    async fn cname_only_chasing_ttl_zero_bypass_tc_failover_and_https_suppression() {
        use crate::dns::wire::{QCLASS_IN, QTYPE_CNAME, QTYPE_TXT, encode_domain_name};
        use bytes::{BufMut, BytesMut};

        // Primary upstream returns unrecovered TC=1 on UDP (and no TCP listener) for `tc.example.test`,
        // CNAME-only `alias.example.test -> hop2.example.test -> final.example.test`,
        // TTL=0 for `zero-ttl.example.test`, and TXT TTL=600 for `spf.example.test`.
        let bad_udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let bad_addr = bad_udp.local_addr().unwrap();
        let good_udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let good_addr = good_udp.local_addr().unwrap();

        let bad_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            while let Ok((n, peer)) = bad_udp.recv_from(&mut buf).await {
                if let Ok(qp) = DnsQueryPacket::parse(&buf[..n])
                    && qp.question.name == "tc.example.test"
                {
                    let tc = crate::dns::wire::build_truncated_dns_header(&buf[..n], &qp);
                    let _ = bad_udp.send_to(&tc, peer).await;
                }
            }
        });

        let zero_ttl_hits = Arc::new(AtomicU64::new(0));
        let zero_ttl_bg = Arc::clone(&zero_ttl_hits);
        let good_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            while let Ok((n, peer)) = good_udp.recv_from(&mut buf).await {
                let req = &buf[..n];
                let Ok(qp) = DnsQueryPacket::parse(req) else {
                    continue;
                };
                match (qp.question.name.as_str(), qp.question.qtype) {
                    ("tc.example.test", QTYPE_A) => {
                        let resp = qp.build_response(
                            req,
                            0,
                            120,
                            &[DnsAnswerData::A(Ipv4Addr::new(198, 51, 100, 77))],
                        );
                        let _ = good_udp.send_to(&resp, peer).await;
                    }
                    ("alias.example.test", QTYPE_A) => {
                        let mut pkt = BytesMut::new();
                        pkt.put_u16(qp.id);
                        pkt.put_u16(0x8180);
                        pkt.put_u16(1);
                        pkt.put_u16(1);
                        pkt.put_u16(0);
                        pkt.put_u16(0);
                        pkt.put_slice(&req[12..qp.question.end_offset]);
                        encode_domain_name("alias.example.test", &mut pkt);
                        pkt.put_u16(QTYPE_CNAME);
                        pkt.put_u16(QCLASS_IN);
                        pkt.put_u32(120);
                        let mut rdata = BytesMut::new();
                        encode_domain_name("final.example.test", &mut rdata);
                        pkt.put_u16(rdata.len() as u16);
                        pkt.put_slice(&rdata);
                        let _ = good_udp.send_to(&pkt, peer).await;
                    }
                    ("final.example.test", QTYPE_A) => {
                        let resp = qp.build_response(
                            req,
                            0,
                            90,
                            &[DnsAnswerData::A(Ipv4Addr::new(203, 0, 113, 200))],
                        );
                        let _ = good_udp.send_to(&resp, peer).await;
                    }
                    ("zero-ttl.example.test", QTYPE_A) => {
                        let c = zero_ttl_bg.fetch_add(1, Ordering::Relaxed);
                        let resp = qp.build_response(
                            req,
                            0,
                            0,
                            &[DnsAnswerData::A(Ipv4Addr::new(203, 0, 113, (10 + c) as u8))],
                        );
                        let _ = good_udp.send_to(&resp, peer).await;
                    }
                    ("spf.example.test", QTYPE_TXT) => {
                        let mut pkt = BytesMut::new();
                        pkt.put_u16(qp.id);
                        pkt.put_u16(0x8180);
                        pkt.put_u16(1);
                        pkt.put_u16(1);
                        pkt.put_u16(0);
                        pkt.put_u16(0);
                        pkt.put_slice(&req[12..qp.question.end_offset]);
                        encode_domain_name("spf.example.test", &mut pkt);
                        pkt.put_u16(QTYPE_TXT);
                        pkt.put_u16(QCLASS_IN);
                        pkt.put_u32(600);
                        let txt = [8u8, b'v', b'=', b's', b'p', b'f', b'1', b' ', b'~'];
                        pkt.put_u16(txt.len() as u16);
                        pkt.put_slice(&txt);
                        let _ = good_udp.send_to(&pkt, peer).await;
                    }
                    _ => {
                        let resp = qp.build_response(req, 0, 60, &[]);
                        let _ = good_udp.send_to(&resp, peer).await;
                    }
                }
            }
        });

        let cfg = DnsConfig {
            ipv6: false,
            nameserver: vec![bad_addr.to_string(), good_addr.to_string()],
            direct_nameserver: vec![good_addr.to_string()],
            fallback: Vec::new(),
            ..DnsConfig::default()
        };
        let engine = FakeIpDnsEngine::new(&cfg).unwrap();

        // 1. Unrecovered TC=1 on `bad_addr` fails over cleanly to `good_addr`
        let tc_ips = engine.resolve_real_ips("tc.example.test").await.unwrap();
        assert_eq!(tc_ips, vec![IpAddr::V4(Ipv4Addr::new(198, 51, 100, 77))]);

        // 2. CNAME-only response chases target (`alias.example.test -> final.example.test`)
        let cname_ips = engine
            .resolve_direct_ips("alias.example.test")
            .await
            .unwrap();
        assert_eq!(cname_ips, vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 200))]);

        // 3. TTL=0 response is NOT stored in positive cache (second call hits upstream again)
        let z1 = engine
            .resolve_direct_ips("zero-ttl.example.test")
            .await
            .unwrap();
        let z2 = engine
            .resolve_direct_ips("zero-ttl.example.test")
            .await
            .unwrap();
        assert_eq!(z1, vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))]);
        assert_eq!(z2, vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 11))]);
        assert_eq!(zero_ttl_hits.load(Ordering::Relaxed), 2);

        // 4. QTYPE_HTTPS & QTYPE_SVCB are suppressed when `ipv6 == false`
        let q_https = build_dns_query(0x7001, "www.cloudflare.com", QTYPE_HTTPS);
        let r_https = engine.handle_dns_packet(&q_https).await.unwrap();
        assert_eq!(dns_response_rcode(&r_https).unwrap(), 0);
        assert_eq!(extract_dns_response_meta(&r_https).unwrap().ancount, 0);
        assert_eq!(engine.telemetry_snapshot().suppressed_queries, 1);

        // 5. QTYPE_TXT positive caching uses positive TTL (~600s, not negative <=60s) and preserves DNS-0x20 casing on hit
        let q_txt1 = build_dns_query(0x7010, "spf.example.test", QTYPE_TXT);
        let before = Instant::now();
        let _ = engine.handle_dns_packet(&q_txt1).await.unwrap();
        let cached_txt = engine
            .packet_cache
            .lock()
            .peek(&("spf.example.test".to_string(), QTYPE_TXT, QCLASS_IN))
            .cloned()
            .expect("TXT response must be cached");
        assert!(
            cached_txt.expires_at.saturating_duration_since(before) >= Duration::from_secs(500),
            "TXT positive response should use positive TTL, not 60s negative TTL"
        );

        let q_txt_0x20 = build_dns_query(0x7011, "SpF.ExAmPlE.TeSt", QTYPE_TXT);
        let r_txt_0x20 = engine.handle_dns_packet(&q_txt_0x20).await.unwrap();
        assert_eq!(u16::from_be_bytes([r_txt_0x20[0], r_txt_0x20[1]]), 0x7011);
        assert_eq!(&r_txt_0x20[12..30], &q_txt_0x20[12..30]);

        bad_task.abort();
        good_task.abort();
    }

    #[test]
    fn wall_clock_dns_cache_expiry_and_stale_if_error_window_across_suspend() {
        let cache: Mutex<LruCache<String, CachedIpResolution>> =
            Mutex::new(LruCache::new(NonZeroUsize::new(16).unwrap()));
        let mono_now = Instant::now();
        let base_wall = 1_700_000_000_000u64;
        let expected_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 99));

        cache.lock().put(
            "cdn.example.cn".to_string(),
            CachedIpResolution::Positive {
                expires_at: mono_now + Duration::from_secs(60),
                expires_wall_ms: base_wall + 60_000,
                stale_until: mono_now + Duration::from_secs(60 + STALE_IF_ERROR_MAX_AGE_SECS),
                stale_until_wall_ms: base_wall + (60 + STALE_IF_ERROR_MAX_AGE_SECS) * 1_000,
                ips: vec![expected_ip],
            },
        );

        // 1. Fresh before 60s wall-clock
        let hit = FakeIpDnsEngine::lookup_cached_ips_with_pace_at(
            &cache,
            "cdn.example.cn",
            false,
            false,
            false,
            mono_now,
            base_wall + 30_000,
        )
        .0;
        assert_eq!(hit.unwrap().unwrap(), vec![expected_ip]);

        // 2. Monotonic clock froze during 5-minute Android suspend (`mono_now`), wall-clock +300s:
        // normal positive lookup MUST treat entry as expired so fresh CDN IPs are fetched!
        let expired = FakeIpDnsEngine::lookup_cached_ips_with_pace_at(
            &cache,
            "cdn.example.cn",
            false,
            false,
            false,
            mono_now,
            base_wall + 300_000,
        )
        .0;
        assert!(expired.is_none());

        // 3. Within the 30m RFC 8767 `stale-if-error` wall-clock window (+300s < 1860s), transient
        // cellular wake-up error still rescues the cached IP with a 15s grace TTL.
        let rescued = FakeIpDnsEngine::try_serve_stale_on_error_at(
            &cache,
            "cdn.example.cn",
            false,
            false,
            mono_now,
            base_wall + 300_000,
        );
        assert_eq!(rescued, Some(vec![expected_ip]));

        // 4. Past the 30m wall-clock window (+2000s > 1860s), `stale-if-error` also refuses the entry.
        let too_stale = FakeIpDnsEngine::try_serve_stale_on_error_at(
            &cache,
            "cdn.example.cn",
            false,
            false,
            mono_now,
            base_wall + 2_000_000,
        );
        assert!(too_stale.is_none());
    }

    #[tokio::test]
    async fn four_upstream_slice_hedges_fallback_pair_when_third_upstream_stalls() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // Upstreams 1 & 2: UDP servers returning SERVFAIL immediately (simulating failed/rejected port-53 pair)
        let udp1 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp2 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr1 = udp1.local_addr().unwrap();
        let addr2 = udp2.local_addr().unwrap();
        let spawn_servfail_udp = |sock: UdpSocket| {
            tokio::spawn(async move {
                let mut buf = [0u8; 512];
                while let Ok((n, peer)) = sock.recv_from(&mut buf).await {
                    if let Ok(qp) = DnsQueryPacket::parse(&buf[..n]) {
                        let resp = qp.build_response(&buf[..n], 2, 0, &[]);
                        let _ = sock.send_to(&resp, peer).await;
                    }
                }
            })
        };
        let u1_task = spawn_servfail_udp(udp1);
        let u2_task = spawn_servfail_udp(udp2);

        // Upstream 3: stalled TCP DNS server (accepts TCP, never replies -> would stall 3s without hedging)
        let tcp_stalled = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr3 = tcp_stalled.local_addr().unwrap();
        let u3_task = tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((stream, _)) = tcp_stalled.accept().await {
                held.push(stream);
            }
        });

        // Upstream 4: healthy TCP DNS server answering immediately
        let tcp_good = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr4 = tcp_good.local_addr().unwrap();
        let u4_task = tokio::spawn(async move {
            while let Ok((mut stream, _)) = tcp_good.accept().await {
                let Ok(len) = stream.read_u16().await else {
                    continue;
                };
                let mut qbuf = vec![0u8; len as usize];
                if stream.read_exact(&mut qbuf).await.is_err() {
                    continue;
                }
                let qp = DnsQueryPacket::parse(&qbuf).unwrap();
                let wire = qp.build_response(
                    &qbuf,
                    0,
                    60,
                    &[DnsAnswerData::A(Ipv4Addr::new(203, 0, 113, 44))],
                );
                let _ = stream.write_u16(wire.len() as u16).await;
                let _ = stream.write_all(&wire).await;
                let _ = stream.flush().await;
            }
        });

        let cfg = DnsConfig {
            enable: true,
            enhanced_mode: "fake-ip".to_string(),
            direct_nameserver: vec![
                addr1.to_string(),
                addr2.to_string(),
                format!("tcp://{addr3}"),
                format!("tcp://{addr4}"),
            ],
            ..Default::default()
        };
        let engine = FakeIpDnsEngine::new(&cfg).unwrap();

        let t0 = Instant::now();
        let ips = engine
            .resolve_direct_ips("hedged-fallback.cn")
            .await
            .expect("4th upstream should win via 350ms second-pair hedge");
        let elapsed = t0.elapsed();

        assert_eq!(ips, vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 44))]);
        assert!(
            elapsed >= Duration::from_millis(300) && elapsed < Duration::from_millis(1500),
            "expected ~350ms hedged fallback recovery instead of 3s stall, got {elapsed:?}"
        );

        u1_task.abort();
        u2_task.abort();
        u3_task.abort();
        u4_task.abort();
    }

    #[tokio::test]
    async fn dead_udp_upstreams_enter_cooldown_and_bypass_waterfall_for_subsequent_queries() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // Two TCP upstreams that immediately reset/refuse (simulating dead primary transports)
        // followed by a fast healthy TCP DNS server.
        let l1 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead1 = l1.local_addr().unwrap();
        drop(l1); // closed port -> immediate ConnectionRefused Io error

        let l2 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead2 = l2.local_addr().unwrap();
        drop(l2);

        let good_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let good_addr = good_listener.local_addr().unwrap();
        let good_hits = Arc::new(AtomicU64::new(0));
        let good_hits_bg = Arc::clone(&good_hits);
        let good_task = tokio::spawn(async move {
            while let Ok((mut stream, _)) = good_listener.accept().await {
                good_hits_bg.fetch_add(1, Ordering::SeqCst);
                let Ok(len) = stream.read_u16().await else {
                    continue;
                };
                let mut qbuf = vec![0u8; len as usize];
                if stream.read_exact(&mut qbuf).await.is_err() {
                    continue;
                }
                let Ok(parsed) = DnsQueryPacket::parse(&qbuf) else {
                    continue;
                };
                let wire = parsed.build_response(
                    &qbuf,
                    0,
                    60,
                    &[DnsAnswerData::A(Ipv4Addr::new(198, 51, 100, 88))],
                );
                let _ = stream.write_u16(wire.len() as u16).await;
                let _ = stream.write_all(&wire).await;
                let _ = stream.flush().await;
            }
        });

        let cfg = DnsConfig {
            enable: true,
            enhanced_mode: "fake-ip".to_string(),
            direct_nameserver: vec![
                format!("tcp://{dead1}"),
                format!("tcp://{dead2}"),
                format!("tcp://{good_addr}"),
            ],
            ..Default::default()
        };
        let engine = FakeIpDnsEngine::new(&cfg).unwrap();

        // First two distinct domain lookups observe 2 consecutive failures on dead1 & dead2 -> enter 30s cooldown
        assert_eq!(
            engine.resolve_direct_ips("wake1.cn").await.unwrap(),
            vec![IpAddr::V4(Ipv4Addr::new(198, 51, 100, 88))]
        );
        assert_eq!(
            engine.resolve_direct_ips("wake2.cn").await.unwrap(),
            vec![IpAddr::V4(Ipv4Addr::new(198, 51, 100, 88))]
        );

        let now_m = Instant::now();
        let now_w = current_epoch_ms();
        let parsed_dead1 = DnsUpstream::parse(&format!("tcp://{dead1}")).unwrap();
        let parsed_dead2 = DnsUpstream::parse(&format!("tcp://{dead2}")).unwrap();
        assert!(
            engine
                .upstream_health
                .get(&parsed_dead1)
                .is_some_and(|s| s.is_cooled_down(now_m, now_w))
        );
        assert!(
            engine
                .upstream_health
                .get(&parsed_dead2)
                .is_some_and(|s| s.is_cooled_down(now_m, now_w))
        );

        // 3rd lookup goes directly to `good_addr` in a few milliseconds
        let t0 = Instant::now();
        assert_eq!(
            engine.resolve_direct_ips("wake3.cn").await.unwrap(),
            vec![IpAddr::V4(Ipv4Addr::new(198, 51, 100, 88))]
        );
        assert!(t0.elapsed() < Duration::from_millis(200));
        assert_eq!(good_hits.load(Ordering::SeqCst), 3);

        // Network handoff / cache flush resets upstream health cooldowns immediately
        engine.clear_local_caches();
        assert!(engine.upstream_health.is_empty());

        good_task.abort();
    }

    #[test]
    fn doh_429_immediately_cools_down_upstream_without_waiting_for_second_failure() {
        let cfg = DnsConfig {
            enable: true,
            enhanced_mode: "fake-ip".to_string(),
            direct_nameserver: crate::config::default_smart_cn_direct_nameservers(),
            ..Default::default()
        };
        let engine = FakeIpDnsEngine::new(&cfg).unwrap();
        assert_eq!(engine.direct_upstreams.len(), 6);

        let doh_primary = DnsUpstream::parse("https://223.5.5.5/dns-query").unwrap();
        engine.record_upstream_outcome(
            &doh_primary,
            &Err(ProxyError::Dns(
                "DoH server returned HTTP status 429".into(),
            )),
            engine.current_cache_epoch(),
        );

        let now_m = Instant::now();
        let now_w = current_epoch_ms();
        assert!(
            engine
                .upstream_health
                .get(&doh_primary)
                .is_some_and(|s| s.is_cooled_down(now_m, now_w)),
            "first HTTP 429 must immediately place DoH upstream into 15s cooldown"
        );
        // After 15s wall-clock jump (e.g. across brief sleep), cooldown expires automatically
        assert!(
            !engine
                .upstream_health
                .get(&doh_primary)
                .unwrap()
                .is_cooled_down(now_m, now_w + UPSTREAM_429_COOLDOWN_MS)
        );
    }

    #[tokio::test]
    async fn flush_cache_isolates_inflight_queries_and_blocks_stale_writeback_while_preserving_fake_ip()
     {
        use std::sync::atomic::AtomicUsize;

        let upstream_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let upstream_addr = upstream_sock.local_addr().unwrap();

        let direct_a_queries = Arc::new(AtomicUsize::new(0));
        let packet_queries = Arc::new(AtomicUsize::new(0));
        let (q1_arrived_tx, q1_arrived_rx) = tokio::sync::oneshot::channel();
        let (release_q1_tx, release_q1_rx) = tokio::sync::oneshot::channel();
        let (pkt1_arrived_tx, pkt1_arrived_rx) = tokio::sync::oneshot::channel();
        let (release_pkt1_tx, release_pkt1_rx) = tokio::sync::oneshot::channel();

        let q1_arrived_opt = Arc::new(Mutex::new(Some(q1_arrived_tx)));
        let release_q1_opt = Arc::new(tokio::sync::Mutex::new(Some(release_q1_rx)));
        let pkt1_arrived_opt = Arc::new(Mutex::new(Some(pkt1_arrived_tx)));
        let release_pkt1_opt = Arc::new(tokio::sync::Mutex::new(Some(release_pkt1_rx)));

        let srv_sock = Arc::clone(&upstream_sock);
        let direct_cnt = Arc::clone(&direct_a_queries);
        let pkt_cnt = Arc::clone(&packet_queries);
        let srv_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            while let Ok((n, peer)) = srv_sock.recv_from(&mut buf).await {
                let req = buf[..n].to_vec();
                let parsed = DnsQueryPacket::parse(&req).unwrap();
                let sock_tx = Arc::clone(&srv_sock);
                let qname = parsed.question.name.to_ascii_lowercase();
                let qtype = parsed.question.qtype;

                if qname == "race.example.com" {
                    if qtype == QTYPE_AAAA {
                        let empty = parsed.build_response(&req, 0, 120, &[]);
                        let _ = sock_tx.send_to(&empty, peer).await;
                        continue;
                    }
                    let seq = direct_cnt.fetch_add(1, Ordering::SeqCst);
                    let arrived = Arc::clone(&q1_arrived_opt);
                    let release = Arc::clone(&release_q1_opt);
                    tokio::spawn(async move {
                        if seq == 0 {
                            if let Some(tx) = arrived.lock().take() {
                                let _ = tx.send(());
                            }
                            if let Some(rx) = release.lock().await.take() {
                                let _ = rx.await;
                            }
                            // Stale pre-switch network response (198.51.100.10) arriving AFTER flush_cache()
                            let stale_resp = parsed.build_response(
                                &req,
                                0,
                                300,
                                &[DnsAnswerData::A(Ipv4Addr::new(198, 51, 100, 10))],
                            );
                            let _ = sock_tx.send_to(&stale_resp, peer).await;
                        } else {
                            // Fresh post-switch network response (203.0.113.99)
                            let fresh_resp = parsed.build_response(
                                &req,
                                0,
                                300,
                                &[DnsAnswerData::A(Ipv4Addr::new(203, 0, 113, 99))],
                            );
                            let _ = sock_tx.send_to(&fresh_resp, peer).await;
                        }
                    });
                } else if qname == "portal.lan" && qtype == QTYPE_A {
                    let seq = pkt_cnt.fetch_add(1, Ordering::SeqCst);
                    let arrived = Arc::clone(&pkt1_arrived_opt);
                    let release = Arc::clone(&release_pkt1_opt);
                    tokio::spawn(async move {
                        if seq == 0 {
                            if let Some(tx) = arrived.lock().take() {
                                let _ = tx.send(());
                            }
                            if let Some(rx) = release.lock().await.take() {
                                let _ = rx.await;
                            }
                            // Stale pre-switch NXDOMAIN (`rcode = 3`) arriving AFTER flush_cache()
                            let stale_nx = parsed.build_response(&req, 3, 120, &[]);
                            let _ = sock_tx.send_to(&stale_nx, peer).await;
                        } else {
                            // Fresh post-switch positive response (203.0.113.77)
                            let fresh_resp = parsed.build_response(
                                &req,
                                0,
                                300,
                                &[DnsAnswerData::A(Ipv4Addr::new(203, 0, 113, 77))],
                            );
                            let _ = sock_tx.send_to(&fresh_resp, peer).await;
                        }
                    });
                }
            }
        });

        let cfg = DnsConfig {
            enable: true,
            ipv6: false,
            enhanced_mode: "fake-ip".to_string(),
            default_nameserver: vec![upstream_addr.to_string()],
            nameserver: vec![upstream_addr.to_string()],
            direct_nameserver: vec![upstream_addr.to_string()],
            fallback: Vec::new(),
            ..DnsConfig::default()
        };
        let engine = Arc::new(FakeIpDnsEngine::new(&cfg).unwrap());

        // Assign a Fake-IP before network switch; it MUST survive `flush_cache()`.
        let pre_switch_fip = engine.assign_fake_ip("race.example.com");

        // 1. Launch pre-switch `resolve_direct_ips("race.example.com")` and `handle_dns_packet("portal.lan")`
        //    (`*.lan` matches default `fake_ip_filter`, exercising `packet_cache` + `real_ip_cache`).
        let eng_q1 = Arc::clone(&engine);
        let pre_direct_task =
            tokio::spawn(async move { eng_q1.resolve_direct_ips("race.example.com").await });

        let eng_p1 = Arc::clone(&engine);
        let pre_pkt_task = tokio::spawn(async move {
            let wire = build_dns_query(0x6101, "portal.lan", QTYPE_A);
            eng_p1.handle_dns_packet(&wire).await
        });

        tokio::time::timeout(Duration::from_secs(2), q1_arrived_rx)
            .await
            .expect("pre-switch direct query must reach upstream")
            .unwrap();
        tokio::time::timeout(Duration::from_secs(2), pkt1_arrived_rx)
            .await
            .expect("pre-switch bypassed packet query must reach upstream")
            .unwrap();

        // 2. Simulate Wi-Fi -> 5G handover (`flush_cache()`) while both pre-switch queries are still in flight!
        engine.flush_cache();
        assert_eq!(
            engine.lookup_domain(IpAddr::V4(pre_switch_fip)).as_deref(),
            Some("race.example.com"),
            "Fake-IP <-> domain bidirectional mapping must remain intact across flush_cache()"
        );
        assert_eq!(engine.assign_fake_ip("race.example.com"), pre_switch_fip);

        // 3. Post-switch queries for the SAME domains MUST NOT piggyback on the stalled pre-switch
        //    `InflightLookupGuard` and must resolve fresh 5G answers immediately.
        let post_direct = tokio::time::timeout(
            Duration::from_secs(2),
            engine.resolve_direct_ips("race.example.com"),
        )
        .await
        .expect("post-switch query must not wait on stalled pre-switch inflight lookup")
        .unwrap();
        assert_eq!(
            post_direct,
            vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 99))]
        );
        assert_eq!(direct_a_queries.load(Ordering::SeqCst), 2);

        let post_pkt_wire = build_dns_query(0x6102, "portal.lan", QTYPE_A);
        let post_pkt_resp = tokio::time::timeout(
            Duration::from_secs(2),
            engine.handle_dns_packet(&post_pkt_wire),
        )
        .await
        .expect("post-switch bypassed DNS packet must resolve immediately")
        .unwrap();
        assert_eq!(dns_response_rcode(&post_pkt_resp).unwrap(), 0);
        assert_eq!(
            extract_ip_answers(&post_pkt_resp).unwrap(),
            vec![DnsAnswerData::A(Ipv4Addr::new(203, 0, 113, 77))]
        );
        assert_eq!(packet_queries.load(Ordering::SeqCst), 2);

        // 4. Release the delayed pre-switch responses (`198.51.100.10` and `NXDOMAIN`) and verify
        //    they CANNOT overwrite or poison the post-switch caches!
        let _ = release_q1_tx.send(());
        let _ = release_pkt1_tx.send(());
        let pre_direct_res = pre_direct_task.await.unwrap().unwrap();
        assert_eq!(
            pre_direct_res,
            vec![IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10))]
        );
        let pre_pkt_res = pre_pkt_task.await.unwrap().unwrap();
        assert_eq!(dns_response_rcode(&pre_pkt_res).unwrap(), 3);

        // Subsequent lookups hit the post-switch cache (no extra upstream queries, fresh IPs preserved!)
        let cached_direct = engine.resolve_direct_ips("race.example.com").await.unwrap();
        assert_eq!(
            cached_direct,
            vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 99))],
            "late pre-switch response must not overwrite post-switch direct_ip_cache"
        );
        assert_eq!(direct_a_queries.load(Ordering::SeqCst), 2);

        let cached_pkt_wire = build_dns_query(0x6103, "portal.lan", QTYPE_A);
        let cached_pkt_resp = engine.handle_dns_packet(&cached_pkt_wire).await.unwrap();
        assert_eq!(dns_response_rcode(&cached_pkt_resp).unwrap(), 0);
        assert_eq!(
            extract_ip_answers(&cached_pkt_resp).unwrap(),
            vec![DnsAnswerData::A(Ipv4Addr::new(203, 0, 113, 77))],
            "late pre-switch NXDOMAIN must not poison post-switch packet_cache"
        );
        assert_eq!(packet_queries.load(Ordering::SeqCst), 2);

        srv_task.abort();
    }

    #[tokio::test]
    async fn system_and_dhcp_system_upstreams_resolve_policy_direct_and_refresh_on_flush() {
        use std::sync::atomic::AtomicUsize;

        // Spawn two mock physical/DHCP UDP DNS servers representing Network A (Wi-Fi) and Network B (Ethernet).
        let spawn_mock_dns = |ip_v4: Ipv4Addr| async move {
            let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let addr = sock.local_addr().unwrap();
            let hits = Arc::new(AtomicUsize::new(0));
            let hits_c = Arc::clone(&hits);
            let task = tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                loop {
                    let Ok((n, peer)) = sock.recv_from(&mut buf).await else {
                        break;
                    };
                    hits_c.fetch_add(1, Ordering::SeqCst);
                    if let Ok(parsed) = DnsQueryPacket::parse(&buf[..n]) {
                        let ans = if parsed.question.qtype == QTYPE_A {
                            vec![DnsAnswerData::A(ip_v4)]
                        } else {
                            Vec::new()
                        };
                        let resp = parsed.build_response(&buf[..n], 0, 60, &ans);
                        let _ = sock.send_to(&resp, peer).await;
                    }
                }
            });
            (addr, hits, task)
        };

        let (dns_net_a, hits_a, task_a) = spawn_mock_dns(Ipv4Addr::new(10, 20, 30, 1)).await;
        let (dns_net_b, hits_b, task_b) = spawn_mock_dns(Ipv4Addr::new(10, 20, 30, 2)).await;
        let (dns_public, hits_pub, task_pub) =
            spawn_mock_dns(Ipv4Addr::new(93, 184, 216, 34)).await;

        let yaml = format!(
            r#"
dns:
  enable: true
  enhanced-mode: fake-ip
  ipv6: false
  direct-nameserver: system
  direct-nameserver-follow-policy: true
  nameserver:
    - "{dns_public}"
  nameserver-policy:
    "+.bestechnic.com": system
    "+.lan": dhcp://system
    "+.local":
      - system
"#
        );
        let cfg = crate::config::ClashConfig::from_yaml_str(&yaml).unwrap();
        let engine = FakeIpDnsEngine::new(&cfg.dns).unwrap();

        let active_server = Arc::new(Mutex::new(dns_net_a));
        let active_clone = Arc::clone(&active_server);
        engine.set_system_dns_provider_for_test(move || vec![*active_clone.lock()]);

        // 1. `nameserver-policy` `+.bestechnic.com: system` and `+.lan: dhcp://system` hit Network A physical DNS.
        let bes_ips = engine.resolve_real_ips("erp.bestechnic.com").await.unwrap();
        assert_eq!(bes_ips, vec![IpAddr::V4(Ipv4Addr::new(10, 20, 30, 1))]);
        let lan_ips = engine.resolve_real_ips("nas.lan").await.unwrap();
        assert_eq!(lan_ips, vec![IpAddr::V4(Ipv4Addr::new(10, 20, 30, 1))]);
        let local_ips = engine.resolve_real_ips("printer.local").await.unwrap();
        assert_eq!(local_ips, vec![IpAddr::V4(Ipv4Addr::new(10, 20, 30, 1))]);
        assert_eq!(hits_a.load(Ordering::SeqCst), 3);
        assert_eq!(hits_pub.load(Ordering::SeqCst), 0);

        // 2. `direct-nameserver: system` (scalar form) also uses physical DNS for non-policy DIRECT domains.
        let direct_ips = engine
            .resolve_direct_ips("direct.example.org")
            .await
            .unwrap();
        assert_eq!(direct_ips, vec![IpAddr::V4(Ipv4Addr::new(10, 20, 30, 1))]);
        assert_eq!(hits_a.load(Ordering::SeqCst), 4);
        assert_eq!(hits_pub.load(Ordering::SeqCst), 0);

        // 3. Non-policy `resolve_real_ips` still uses public `nameserver`.
        let pub_ips = engine.resolve_real_ips("public.example.org").await.unwrap();
        assert_eq!(pub_ips, vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]);
        assert_eq!(hits_pub.load(Ordering::SeqCst), 1);

        // 4. Simulate network switch to Network B + `flush_cache()` -> refreshes physical DNS server list!
        *active_server.lock() = dns_net_b;
        engine.flush_cache();

        let bes_after = engine.resolve_real_ips("erp.bestechnic.com").await.unwrap();
        assert_eq!(bes_after, vec![IpAddr::V4(Ipv4Addr::new(10, 20, 30, 2))]);
        assert_eq!(hits_b.load(Ordering::SeqCst), 1);

        task_a.abort();
        task_b.abort();
        task_pub.abort();
    }
}

pub mod geodata;
pub mod geoip_data;
pub mod geosite_data;
pub mod groups;
pub mod mmdb;
pub mod rules;
pub mod ruleset;

use std::{
    collections::{HashMap, HashSet},
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use futures_util::stream::{FuturesUnordered, StreamExt};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;

use crate::{
    addr::TargetAddr,
    config::{
        ProxyGroupConfig, ProxyGroupType, RuleProviderConfig, RunMode, SnifferConfig,
        validate_groups_and_rules_with_context,
    },
    dns::FakeIpDnsEngine,
    error::{ProxyError, Result},
    outbound::{DirectOutbound, DynOutbound, ErrorOutbound, RejectOutbound},
    platform::process::SocketTransport,
    router::{
        groups::{DelayStore, ProxyGroup, ProxyInfoSnapshot},
        mmdb::MmdbReader,
        rules::{CompiledRule, RuleMatcher, RuleSnapshot},
        ruleset::build_rule_sets_with_state_dir,
    },
};

static ROUTER_EPOCH_SEQ: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectiveOutboundSummary {
    pub mode: RunMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub primary_group: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected_member: Option<String>,
    pub effective_outbound: String,
    pub effective_protocol: String,
    pub chains: Vec<String>,
}

pub struct RouteDecision {
    pub target: TargetAddr,
    pub restored_from_fake_ip: Option<Ipv4Addr>,
    pub rule_type: String,
    pub rule_payload: String,
    /// Ordered from leaf outbound -> ... -> top-level group (Mihomo `chains` convention).
    pub chains: Vec<String>,
    pub outbound: DynOutbound,
}

#[derive(Clone, Debug)]
pub struct RouteSimulationPreview {
    pub matched_rule: String,
    pub chains: Vec<String>,
    pub effective_outbound: String,
    pub exit_type: String,
    pub triggered_dns_rule: Option<String>,
    pub ip_rules_skipped_without_dns: bool,
}

/// Fast-path O(1) exact + O(labels) suffix index over `DOMAIN` and `DOMAIN-SUFFIX` rules
/// preserving 100% identical top-to-bottom rule priority semantics!
struct FastRuleIndex {
    exact_domain: HashMap<String, usize>,
    suffix_domain: HashMap<String, usize>,
    /// Strictly ascending rule indices for all rules that are NOT `Domain` or `DomainSuffix`.
    non_indexed_rules: Vec<usize>,
}

impl FastRuleIndex {
    fn build(rules: &[CompiledRule]) -> Self {
        let mut exact_domain = HashMap::new();
        let mut suffix_domain = HashMap::new();
        let mut non_indexed_rules = Vec::new();

        for (idx, rule) in rules.iter().enumerate() {
            match &rule.matcher {
                RuleMatcher::Domain(d) => {
                    exact_domain.entry(d.clone()).or_insert(idx);
                }
                RuleMatcher::DomainSuffix(suf) => {
                    suffix_domain.entry(suf.clone()).or_insert(idx);
                }
                _ => {
                    non_indexed_rules.push(idx);
                }
            }
        }

        Self {
            exact_domain,
            suffix_domain,
            non_indexed_rules,
        }
    }

    /// Return the earliest rule index matching `domain` among `Domain` and `DomainSuffix` rules
    /// in O(1) + O(labels) hash lookups.
    fn earliest_domain_match(&self, raw_domain: &str) -> Option<usize> {
        let lower = raw_domain.trim().trim_end_matches('.').to_ascii_lowercase();
        if lower.is_empty() {
            return None;
        }
        let mut best: Option<usize> = self.exact_domain.get(&lower).copied();

        let mut cursor = lower.as_str();
        loop {
            if let Some(&idx) = self.suffix_domain.get(cursor) {
                best = Some(best.map_or(idx, |b| b.min(idx)));
            }
            match cursor.split_once('.') {
                Some((_, rest)) if !rest.is_empty() => cursor = rest,
                _ => break,
            }
        }
        best
    }
}

pub struct Router {
    mode: RwLock<RunMode>,
    epoch: AtomicU64,
    unified_delay: AtomicBool,
    tun_dns_hijack: AtomicBool,
    low_power_mode: AtomicBool,
    sniffer: RwLock<SnifferConfig>,
    outbounds: HashMap<String, DynOutbound>,
    groups: HashMap<String, Arc<ProxyGroup>>,
    group_order: Vec<String>,
    rules: Vec<CompiledRule>,
    rule_index: FastRuleIndex,
    dns: Arc<FakeIpDnsEngine>,
    delays: Arc<DelayStore>,
}

impl Router {
    pub fn new(
        initial_mode: RunMode,
        outbounds: HashMap<String, DynOutbound>,
        group_configs: &[ProxyGroupConfig],
        rule_lines: &[String],
        dns: Arc<FakeIpDnsEngine>,
    ) -> Result<Self> {
        Self::with_providers_and_mmdb(
            initial_mode,
            outbounds,
            group_configs,
            rule_lines,
            &HashMap::new(),
            None,
            dns,
        )
    }

    pub fn with_providers_and_mmdb(
        initial_mode: RunMode,
        outbounds: HashMap<String, DynOutbound>,
        group_configs: &[ProxyGroupConfig],
        rule_lines: &[String],
        rule_providers: &HashMap<String, RuleProviderConfig>,
        mmdb: Option<Arc<MmdbReader>>,
        dns: Arc<FakeIpDnsEngine>,
    ) -> Result<Self> {
        Self::with_providers_mmdb_and_state_dir(
            initial_mode,
            outbounds,
            group_configs,
            rule_lines,
            rule_providers,
            mmdb,
            None,
            dns,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn with_providers_mmdb_and_state_dir(
        initial_mode: RunMode,
        mut outbounds: HashMap<String, DynOutbound>,
        group_configs: &[ProxyGroupConfig],
        rule_lines: &[String],
        rule_providers: &HashMap<String, RuleProviderConfig>,
        mmdb: Option<Arc<MmdbReader>>,
        state_dir: Option<&Path>,
        dns: Arc<FakeIpDnsEngine>,
    ) -> Result<Self> {
        outbounds.insert(
            "DIRECT".to_string(),
            Arc::new(DirectOutbound::with_dns("DIRECT", Arc::clone(&dns))),
        );
        outbounds
            .entry("REJECT".to_string())
            .or_insert_with(|| Arc::new(RejectOutbound::default()));

        let concrete_set: HashSet<String> = outbounds
            .keys()
            .filter(|k| *k != "DIRECT" && *k != "REJECT")
            .cloned()
            .collect();

        let compiled_rule_sets =
            build_rule_sets_with_state_dir(rule_providers, mmdb.as_ref(), state_dir)?;
        validate_groups_and_rules_with_context(
            &concrete_set,
            group_configs,
            rule_lines,
            Some(rule_providers),
            mmdb.is_some(),
        )?;

        let mut groups = HashMap::new();
        let mut group_order = Vec::new();
        for gcfg in group_configs {
            let grp = Arc::new(ProxyGroup::from_config(gcfg));
            group_order.push(gcfg.name.clone());
            groups.insert(gcfg.name.clone(), grp);
        }

        if !groups.contains_key("GLOBAL") {
            let mut global_members: Vec<String> = group_order.clone();
            let mut concrete_names: Vec<String> = concrete_set.into_iter().collect();
            concrete_names.sort();
            global_members.extend(concrete_names);
            global_members.push("DIRECT".to_string());
            global_members.push("REJECT".to_string());

            let global_cfg = ProxyGroupConfig {
                name: "GLOBAL".to_string(),
                group_type: ProxyGroupType::Select,
                proxies: global_members,
                url: "http://www.gstatic.com/generate_204".to_string(),
                interval: 300,
                tolerance: 50,
                strategy: None,
            };
            groups.insert(
                "GLOBAL".to_string(),
                Arc::new(ProxyGroup::from_config(&global_cfg)),
            );
            group_order.push("GLOBAL".to_string());
        }

        let mut rules = Vec::with_capacity(rule_lines.len());
        for line in rule_lines {
            if !line.trim().is_empty() && !line.trim().starts_with('#') {
                rules.push(CompiledRule::parse_with_context(
                    line,
                    mmdb.as_ref(),
                    Some(&compiled_rule_sets),
                )?);
            }
        }
        let rule_index = FastRuleIndex::build(&rules);

        Ok(Self {
            mode: RwLock::new(initial_mode),
            epoch: AtomicU64::new(ROUTER_EPOCH_SEQ.fetch_add(1, Ordering::Relaxed)),
            unified_delay: AtomicBool::new(true),
            tun_dns_hijack: AtomicBool::new(true),
            low_power_mode: AtomicBool::new(false),
            sniffer: RwLock::new(SnifferConfig::default()),
            outbounds,
            groups,
            group_order,
            rules,
            rule_index,
            dns,
            delays: Arc::new(DelayStore::default()),
        })
    }

    pub fn epoch(&self) -> u64 {
        self.epoch.load(Ordering::Acquire)
    }

    pub fn bump_epoch(&self) {
        self.epoch.store(
            ROUTER_EPOCH_SEQ.fetch_add(1, Ordering::Relaxed),
            Ordering::Release,
        );
    }

    pub fn seed_delay_if_absent(&self, name: &str, delay_ms: u64) {
        self.delays.seed_if_absent(name, delay_ms);
    }

    pub fn latest_delay_age_ms(&self, name: &str) -> Option<u64> {
        self.delays.latest_delay_age_ms(name)
    }

    pub fn record_passive_delay_if_stale(&self, name: &str, rtt_ms: u64, max_age_ms: u64) {
        // Screen-off background push heartbeats (e.g. FCM/mtalk) dial from cellular RRC-IDLE
        // and systematically incur +150–350ms radio paging overhead. Preserve the existing
        // interactive baseline while low_power_mode is active; interactive dials refresh it.
        if max_age_ms > 0 && self.is_low_power_mode() && self.delays.latest_delay(name).is_some() {
            return;
        }
        self.delays
            .record_passive_if_stale(name, rtt_ms, max_age_ms);
    }

    pub fn mode(&self) -> RunMode {
        *self.mode.read()
    }

    pub fn set_mode(&self, mode: RunMode) {
        *self.mode.write() = mode;
        self.bump_epoch();
    }

    pub fn unified_delay(&self) -> bool {
        self.unified_delay.load(Ordering::Relaxed)
    }

    pub fn set_unified_delay(&self, enabled: bool) {
        self.unified_delay.store(enabled, Ordering::Relaxed);
    }

    pub fn tun_dns_hijack(&self) -> bool {
        self.tun_dns_hijack.load(Ordering::Relaxed)
    }

    pub fn set_tun_dns_hijack(&self, enabled: bool) {
        self.tun_dns_hijack.store(enabled, Ordering::Relaxed);
    }

    pub fn sniffer(&self) -> SnifferConfig {
        self.sniffer.read().clone()
    }

    pub fn set_sniffer(&self, cfg: SnifferConfig) {
        *self.sniffer.write() = cfg;
    }

    pub fn is_low_power_mode(&self) -> bool {
        self.low_power_mode.load(Ordering::Acquire)
    }

    pub fn set_low_power_mode(&self, enabled: bool) {
        self.low_power_mode.store(enabled, Ordering::Release);
        for ob in self.outbounds.values() {
            ob.set_low_power_mode(enabled);
        }
    }

    /// Pre-warm DNS and/or idle multiplexed sessions for the current effective primary outbound.
    /// Returns `Ok(true)` if a concrete `"PROXY"` outbound was pre-warmed, or `Ok(false)` when
    /// running in `Direct` mode or when the effective primary outbound is `DIRECT`/`REJECT`/`ERROR`.
    pub async fn preconnect_primary(&self, target_sessions: usize) -> Result<bool> {
        if target_sessions == 0 || self.mode() == RunMode::Direct {
            return Ok(false);
        }
        let eff = self.effective_primary_outbound();
        let Some(ob) = self.outbounds.get(&eff.effective_outbound).cloned() else {
            return Ok(false);
        };
        if ob.exit_category() != "PROXY" {
            return Ok(false);
        }
        ob.preconnect(target_sessions)
            .await
            .map_err(ProxyError::Io)?;
        Ok(true)
    }

    pub fn outbound(&self, name: &str) -> Option<Arc<dyn crate::outbound::OutboundHandler>> {
        self.outbounds.get(name).cloned()
    }

    pub fn dns(&self) -> &Arc<FakeIpDnsEngine> {
        &self.dns
    }

    pub fn delays(&self) -> &Arc<DelayStore> {
        &self.delays
    }

    /// Flush DNS positive/negative caches and notify all concrete outbounds to evict
    /// pooled/multiplexed sockets bound to a previous network interface.
    pub fn notify_network_change(&self) -> usize {
        crate::platform::socket_protect::reset_direct_ipv6_reachability();
        self.dns.flush_cache();
        self.bump_epoch();
        self.outbounds.values().map(|o| o.on_network_change()).sum()
    }

    /// Tear down router-scoped DNS caches and outbound socket pools on engine shutdown
    /// without mutating process-wide socket reachability or shared DoT/DoH upstream pools.
    pub fn shutdown_cleanup(&self) -> usize {
        self.dns.clear_local_caches();
        self.bump_epoch();
        self.outbounds.values().map(|o| o.on_network_change()).sum()
    }

    /// Synchronously evaluate whether raw IP target `dst` routes to an outbound whose
    /// `exit_category() == "DIRECT"` without mutating rule hit counters or performing async I/O.
    pub fn will_route_ip_direct(
        &self,
        src_addr: SocketAddr,
        transport: SocketTransport,
        dst: SocketAddr,
    ) -> bool {
        let raw_target = TargetAddr::from(dst);
        if self.dns.is_unmapped_fake_ip(&raw_target) {
            return false;
        }
        let (target, _) = self.dns.restore_target(&raw_target);
        let entry_target: &str = match self.mode() {
            RunMode::Direct => "DIRECT",
            RunMode::Global => "GLOBAL",
            RunMode::Rule => {
                let mut best_idx = target
                    .host
                    .as_domain()
                    .and_then(|d| self.rule_index.earliest_domain_match(d));

                for &idx in &self.rule_index.non_indexed_rules {
                    if best_idx.is_some_and(|b| idx >= b) {
                        break;
                    }
                    if self.rules[idx].matches_full(
                        Some(src_addr.ip()),
                        Some(src_addr),
                        transport,
                        &target,
                        &[],
                    ) {
                        best_idx = Some(idx);
                        break;
                    }
                }

                if let Some(winner_idx) = best_idx {
                    self.rules[winner_idx].target.as_str()
                } else {
                    "REJECT"
                }
            }
        };

        let (outbound, _) = self.resolve_chain(entry_target, &target);
        outbound.exit_category() == "DIRECT"
    }

    /// Synchronous routing path (evaluates using O(1)/O(labels) domain index without blocking DNS lookups).
    pub fn route(&self, src_ip: Option<IpAddr>, raw_target: &TargetAddr) -> RouteDecision {
        if self.dns.is_unmapped_fake_ip(raw_target) {
            return self.unmapped_fake_ip_decision(raw_target);
        }
        let (target, restored_from_fake_ip) = self.dns.restore_target(raw_target);
        let mode = self.mode();

        let (rule_type, rule_payload, entry_target) = match mode {
            RunMode::Direct => (
                "Mode".to_string(),
                "Direct".to_string(),
                "DIRECT".to_string(),
            ),
            RunMode::Global => (
                "Mode".to_string(),
                "Global".to_string(),
                "GLOBAL".to_string(),
            ),
            RunMode::Rule => {
                let mut best_idx = target
                    .host
                    .as_domain()
                    .and_then(|d| self.rule_index.earliest_domain_match(d));

                for &idx in &self.rule_index.non_indexed_rules {
                    if best_idx.is_some_and(|b| idx >= b) {
                        break;
                    }
                    if self.rules[idx].matches(src_ip, &target) {
                        best_idx = Some(idx);
                        break;
                    }
                }

                if let Some(winner_idx) = best_idx {
                    let rule = &self.rules[winner_idx];
                    rule.record_hit();
                    (
                        rule.rule_type_str().to_string(),
                        rule.payload_str(),
                        rule.target.clone(),
                    )
                } else {
                    (
                        "ImplicitReject".to_string(),
                        "no-matching-rule".to_string(),
                        "REJECT".to_string(),
                    )
                }
            }
        };

        let (outbound, chains) = self.resolve_chain(&entry_target, &target);
        RouteDecision {
            target,
            restored_from_fake_ip,
            rule_type,
            rule_payload,
            chains,
            outbound,
        }
    }

    /// Full asynchronous routing path (preserving existing signature for callers without full `SocketAddr`).
    pub async fn route_async(
        &self,
        src_ip: Option<IpAddr>,
        raw_target: &TargetAddr,
    ) -> RouteDecision {
        self.route_async_with_context(src_ip, None, SocketTransport::Tcp, raw_target)
            .await
    }

    /// Full asynchronous routing path with optional local socket `(src_addr, transport)` context
    /// for native OS `PROCESS-NAME` / `PROCESS-PATH` matching, O(1)/O(labels) domain index fast-path,
    /// lazy once-per-packet IP rule resolution, and fail-closed group chain evaluation.
    pub async fn route_async_with_context(
        &self,
        src_ip: Option<IpAddr>,
        src_addr: Option<SocketAddr>,
        transport: SocketTransport,
        raw_target: &TargetAddr,
    ) -> RouteDecision {
        if self.dns.is_unmapped_fake_ip(raw_target) {
            return self.unmapped_fake_ip_decision(raw_target);
        }
        let (target, restored_from_fake_ip) = self.dns.restore_target(raw_target);
        let eff_src_ip = src_ip.or_else(|| src_addr.map(|sa| sa.ip()));
        let mode = self.mode();

        let (rule_type, rule_payload, entry_target) = match mode {
            RunMode::Direct => (
                "Mode".to_string(),
                "Direct".to_string(),
                "DIRECT".to_string(),
            ),
            RunMode::Global => (
                "Mode".to_string(),
                "Global".to_string(),
                "GLOBAL".to_string(),
            ),
            RunMode::Rule => {
                let mut best_idx = target
                    .host
                    .as_domain()
                    .and_then(|d| self.rule_index.earliest_domain_match(d));
                let mut resolved_ips: Option<Vec<IpAddr>> = None;

                for &idx in &self.rule_index.non_indexed_rules {
                    // Crucial fast-path: if an indexed `DOMAIN` or `DOMAIN-SUFFIX` rule already matched
                    // at an earlier rule index `b <= idx`, stop immediately — preserving exact rule order
                    // AND avoiding unnecessary DNS lookups for later `GEOIP` / `IP-CIDR` rules!
                    if best_idx.is_some_and(|b| idx >= b) {
                        break;
                    }
                    let rule = &self.rules[idx];
                    if let Some(domain) = target.host.as_domain()
                        && rule.requires_ip_resolution()
                        && resolved_ips.is_none()
                    {
                        // Resolve via encrypted `nameserver`/`fallback` with Singleflight + TTL cache
                        // rather than plaintext domestic `direct-nameserver`, preventing DNS leaks for
                        // foreign domains and avoiding poisoning `direct_ip_cache`.
                        let ips = self.dns.resolve_real_ips(domain).await.unwrap_or_default();
                        resolved_ips = Some(ips);
                    }
                    let ips_slice = resolved_ips.as_deref().unwrap_or(&[]);
                    if rule.matches_full(eff_src_ip, src_addr, transport, &target, ips_slice) {
                        best_idx = Some(idx);
                        break;
                    }
                }

                if let Some(winner_idx) = best_idx {
                    let rule = &self.rules[winner_idx];
                    rule.record_hit();
                    (
                        rule.rule_type_str().to_string(),
                        rule.payload_str(),
                        rule.target.clone(),
                    )
                } else {
                    (
                        "ImplicitReject".to_string(),
                        "no-matching-rule".to_string(),
                        "REJECT".to_string(),
                    )
                }
            }
        };

        let (outbound, chains) = self.resolve_chain(&entry_target, &target);
        RouteDecision {
            target,
            restored_from_fake_ip,
            rule_type,
            rule_payload,
            chains,
            outbound,
        }
    }

    /// Side-effect-free route preview using live runtime `mode`, real loaded GeoIP/RuleSets,
    /// and live `Selector` / `URLTest` / `Fallback` group selections without emitting DNS packets
    /// or mutating rule hit counters.
    pub fn preview_route_no_dns(&self, raw_target: &TargetAddr) -> RouteSimulationPreview {
        self.preview_route_inner(raw_target, None)
    }

    /// Side-effect-free route preview (no rule hit counter mutation) that also resolves domain IPs
    /// via configured `dns.nameserver` when an unmatched domain encounters an IP-dependent rule.
    pub async fn preview_route_with_dns(&self, raw_target: &TargetAddr) -> RouteSimulationPreview {
        let (target, _) = self.dns.restore_target(raw_target);
        if self.mode() == RunMode::Rule
            && let Some(domain) = target.host.as_domain()
        {
            let best_domain_idx = self.rule_index.earliest_domain_match(domain);
            let needs_ip = self
                .rule_index
                .non_indexed_rules
                .iter()
                .copied()
                .take_while(|&idx| best_domain_idx.is_none_or(|b| idx < b))
                .any(|idx| self.rules[idx].requires_ip_resolution());
            if needs_ip {
                let ips = self.dns.resolve_real_ips(domain).await.unwrap_or_default();
                return self.preview_route_inner(raw_target, Some(&ips));
            }
        }
        self.preview_route_inner(raw_target, Some(&[]))
    }

    fn preview_route_inner(
        &self,
        raw_target: &TargetAddr,
        resolved_ips: Option<&[IpAddr]>,
    ) -> RouteSimulationPreview {
        let (target, _) = self.dns.restore_target(raw_target);
        let is_domain = target.host.as_domain().is_some();
        let mode = self.mode();

        let (matched_rule, entry_target, triggered_dns_rule, ip_rules_skipped_without_dns) =
            match mode {
                RunMode::Direct => (
                    "Mode(direct)".to_string(),
                    "DIRECT".to_string(),
                    None,
                    false,
                ),
                RunMode::Global => (
                    "Mode(global)".to_string(),
                    "GLOBAL".to_string(),
                    None,
                    false,
                ),
                RunMode::Rule => {
                    let mut best_idx = target
                        .host
                        .as_domain()
                        .and_then(|d| self.rule_index.earliest_domain_match(d));
                    let mut triggered_dns: Option<String> = None;
                    let mut skipped_ip_without_dns = false;

                    for &idx in &self.rule_index.non_indexed_rules {
                        if best_idx.is_some_and(|b| idx >= b) {
                            break;
                        }
                        let rule = &self.rules[idx];
                        if is_domain && rule.requires_ip_resolution() {
                            if triggered_dns.is_none() {
                                triggered_dns = Some(Self::format_compiled_rule_label(idx, rule));
                            }
                            if resolved_ips.is_none() {
                                skipped_ip_without_dns = true;
                            }
                        }
                        let ips_slice = resolved_ips.unwrap_or(&[]);
                        if rule.matches_full(None, None, SocketTransport::Tcp, &target, ips_slice) {
                            best_idx = Some(idx);
                            break;
                        }
                    }

                    if let Some(winner_idx) = best_idx {
                        let rule = &self.rules[winner_idx];
                        (
                            Self::format_compiled_rule_label(winner_idx, rule),
                            rule.target.clone(),
                            triggered_dns,
                            skipped_ip_without_dns,
                        )
                    } else {
                        (
                            "ImplicitReject (no matching rule)".to_string(),
                            "REJECT".to_string(),
                            triggered_dns,
                            skipped_ip_without_dns,
                        )
                    }
                }
            };

        let (outbound, chains) = self.resolve_chain_preview(&entry_target);
        RouteSimulationPreview {
            matched_rule,
            chains,
            effective_outbound: outbound.name().to_string(),
            exit_type: outbound.exit_category().to_string(),
            triggered_dns_rule,
            ip_rules_skipped_without_dns,
        }
    }

    fn format_compiled_rule_label(idx: usize, rule: &CompiledRule) -> String {
        let payload = rule.payload_str();
        if payload.is_empty() {
            format!(
                "rules[{}] {},{}",
                idx + 1,
                rule.rule_type_str(),
                rule.target
            )
        } else {
            format!(
                "rules[{}] {},{},{}",
                idx + 1,
                rule.rule_type_str(),
                payload,
                rule.target
            )
        }
    }

    fn unmapped_fake_ip_decision(&self, raw_target: &TargetAddr) -> RouteDecision {
        let msg = format!(
            "target {} is an unmapped or expired Fake-IP inside {}; please re-resolve DNS",
            raw_target,
            self.dns.fake_ip_net()
        );
        let err_ob: DynOutbound = Arc::new(ErrorOutbound::new(
            "UNMAPPED-FAKE-IP",
            io::ErrorKind::HostUnreachable,
            msg,
        ));
        RouteDecision {
            target: raw_target.clone(),
            restored_from_fake_ip: None,
            rule_type: "FakeIpMiss".to_string(),
            rule_payload: self.dns.fake_ip_net().to_string(),
            chains: vec!["UNMAPPED-FAKE-IP".to_string()],
            outbound: err_ob,
        }
    }

    /// Resolve a target outbound or group chain to a concrete leaf `DynOutbound`.
    /// Strictly forbids silent `DIRECT` fallback: any cycle, depth overflow, or unknown node
    /// fails closed with `ErrorKind::PermissionDenied`.
    pub fn resolve_chain(
        &self,
        start_name: &str,
        target: &TargetAddr,
    ) -> (DynOutbound, Vec<String>) {
        let mut path = Vec::with_capacity(4);
        let mut visited = HashSet::with_capacity(8);
        let mut cur = start_name.to_string();

        for _ in 0..16 {
            if !visited.insert(cur.clone()) {
                tracing::error!(
                    "proxy-group cycle detected at '{}' while resolving chain {:?}",
                    cur,
                    path
                );
                let fail_ob: DynOutbound = Arc::new(ErrorOutbound::new(
                    "ROUTING-ERROR",
                    io::ErrorKind::PermissionDenied,
                    format!(
                        "cyclic proxy-group reference at '{cur}'; refusing implicit DIRECT fallback"
                    ),
                ));
                path.push("ROUTING-ERROR".to_string());
                path.reverse();
                return (fail_ob, path);
            }

            path.push(cur.clone());
            if let Some(outbound) = self.outbounds.get(&cur) {
                path.reverse();
                return (Arc::clone(outbound), path);
            }
            if let Some(group) = self.groups.get(&cur) {
                cur = group.pick_member(target, &self.delays);
                continue;
            }

            tracing::error!(
                "unknown proxy or group '{}' in routing chain {:?}",
                cur,
                path
            );
            let fail_ob: DynOutbound = Arc::new(ErrorOutbound::new(
                "ROUTING-ERROR",
                io::ErrorKind::PermissionDenied,
                format!("unknown proxy or group '{cur}'; refusing implicit DIRECT fallback"),
            ));
            path.push("ROUTING-ERROR".to_string());
            path.reverse();
            return (fail_ob, path);
        }

        tracing::error!("proxy-group resolution depth exceeded 16 hops: {:?}", path);
        let fail_ob: DynOutbound = Arc::new(ErrorOutbound::new(
            "ROUTING-ERROR",
            io::ErrorKind::PermissionDenied,
            "proxy-group chain exceeded maximum depth (16); refusing implicit DIRECT fallback",
        ));
        path.push("ROUTING-ERROR".to_string());
        path.reverse();
        (fail_ob, path)
    }

    pub fn resolve_chain_preview(&self, start_name: &str) -> (DynOutbound, Vec<String>) {
        let mut path = Vec::with_capacity(4);
        let mut visited = HashSet::with_capacity(8);
        let mut cur = start_name.to_string();

        for _ in 0..16 {
            if !visited.insert(cur.clone()) {
                let fail_ob: DynOutbound = Arc::new(ErrorOutbound::new(
                    "ROUTING-ERROR",
                    io::ErrorKind::PermissionDenied,
                    format!("cyclic proxy-group reference at '{cur}'"),
                ));
                path.push("ROUTING-ERROR".to_string());
                path.reverse();
                return (fail_ob, path);
            }
            path.push(cur.clone());
            if let Some(outbound) = self.outbounds.get(&cur) {
                path.reverse();
                return (Arc::clone(outbound), path);
            }
            if let Some(group) = self.groups.get(&cur) {
                cur = group.peek_member(&self.delays);
                continue;
            }
            let fail_ob: DynOutbound = Arc::new(ErrorOutbound::new(
                "ROUTING-ERROR",
                io::ErrorKind::PermissionDenied,
                format!("unknown proxy or group '{cur}'"),
            ));
            path.push("ROUTING-ERROR".to_string());
            path.reverse();
            return (fail_ob, path);
        }

        let fail_ob: DynOutbound = Arc::new(ErrorOutbound::new(
            "ROUTING-ERROR",
            io::ErrorKind::PermissionDenied,
            "proxy-group chain exceeded maximum depth (16)",
        ));
        path.push("ROUTING-ERROR".to_string());
        path.reverse();
        (fail_ob, path)
    }

    pub fn select_group(&self, group_name: &str, proxy_name: &str) -> Result<()> {
        let grp = self
            .groups
            .get(group_name)
            .ok_or_else(|| ProxyError::Routing(format!("proxy group '{group_name}' not found")))?;
        grp.select_manual(proxy_name)?;
        self.sync_selector_delays();
        self.bump_epoch();
        Ok(())
    }

    /// Return the current effective leaf outbound name for `group_name` (if the group exists).
    pub fn effective_outbound_for_group(&self, group_name: &str) -> Option<String> {
        if !self.groups.contains_key(group_name) {
            return None;
        }
        let (ob, _) = self.resolve_chain_preview(group_name);
        Some(ob.name().to_string())
    }

    /// Walk nested `ProxyGroup`s (up to 16 hops, cycle-guarded) via `pick_member` to resolve
    /// `member` to its effective concrete `DynOutbound`, returning `None` on cycle, depth
    /// overflow, or unknown proxy/group name.
    pub fn resolve_member_outbound(
        &self,
        member: &str,
        target: &TargetAddr,
    ) -> Option<DynOutbound> {
        let mut visited = HashSet::with_capacity(8);
        let mut cur = member.to_string();
        for _ in 0..16 {
            if !visited.insert(cur.clone()) {
                return None;
            }
            if let Some(outbound) = self.outbounds.get(&cur) {
                return Some(Arc::clone(outbound));
            }
            let group = self.groups.get(&cur)?;
            cur = group.pick_member(target, &self.delays);
        }
        None
    }

    /// Side-effect-free counterpart to [`Self::resolve_member_outbound`] using `peek_member`.
    pub fn peek_member_outbound(&self, member: &str) -> Option<DynOutbound> {
        let mut visited = HashSet::with_capacity(8);
        let mut cur = member.to_string();
        for _ in 0..16 {
            if !visited.insert(cur.clone()) {
                return None;
            }
            if let Some(outbound) = self.outbounds.get(&cur) {
                return Some(Arc::clone(outbound));
            }
            let group = self.groups.get(&cur)?;
            cur = group.peek_member(&self.delays);
        }
        None
    }

    /// Compute the effective latency (in ms) of a concrete outbound or nested `ProxyGroup`
    /// from `DelayStore` (up to 16 hops, cycle-guarded). Returns `None` if unprobed, cyclic,
    /// or if the active/candidate path failed its most recent probe.
    pub fn effective_member_delay(&self, member: &str) -> Option<u64> {
        let mut visited = HashSet::with_capacity(8);
        self.effective_member_delay_inner(member, &mut visited, 0)
    }

    fn effective_member_delay_inner(
        &self,
        member: &str,
        visited: &mut HashSet<String>,
        depth: usize,
    ) -> Option<u64> {
        if depth >= 16 || !visited.insert(member.to_string()) {
            return None;
        }
        let res = if self.outbounds.contains_key(member) {
            self.delays.latest_delay(member)
        } else if let Some(grp) = self.groups.get(member) {
            if self.delays.is_known_failed(member) && grp.group_type != ProxyGroupType::Select {
                None
            } else {
                match grp.group_type {
                    ProxyGroupType::Select | ProxyGroupType::UrlTest | ProxyGroupType::Fallback => {
                        let chosen = grp.current();
                        self.effective_member_delay_inner(&chosen, visited, depth + 1)
                    }
                    ProxyGroupType::LoadBalance => {
                        let peeked = grp.peek_member(&self.delays);
                        if let Some(ms) =
                            self.effective_member_delay_inner(&peeked, visited, depth + 1)
                        {
                            Some(ms)
                        } else {
                            grp.members
                                .iter()
                                .filter_map(|m| {
                                    self.effective_member_delay_inner(m, visited, depth + 1)
                                })
                                .min()
                        }
                    }
                }
            }
        } else {
            None
        };
        visited.remove(member);
        res
    }

    fn is_member_known_failed(&self, member: &str) -> bool {
        let mut visited = HashSet::with_capacity(8);
        self.is_member_known_failed_inner(member, &mut visited, 0)
    }

    fn is_member_known_failed_inner(
        &self,
        member: &str,
        visited: &mut HashSet<String>,
        depth: usize,
    ) -> bool {
        if depth >= 16 || !visited.insert(member.to_string()) {
            return false;
        }
        let failed = if self.outbounds.contains_key(member) {
            self.delays.is_known_failed(member)
        } else if let Some(grp) = self.groups.get(member) {
            match grp.group_type {
                ProxyGroupType::Select => {
                    let chosen = grp.current();
                    self.is_member_known_failed_inner(&chosen, visited, depth + 1)
                }
                ProxyGroupType::UrlTest | ProxyGroupType::Fallback => {
                    self.delays.is_known_failed(member)
                        || self.is_member_known_failed_inner(&grp.current(), visited, depth + 1)
                }
                ProxyGroupType::LoadBalance => {
                    self.delays.is_known_failed(member)
                        || (!grp.members.is_empty()
                            && grp
                                .members
                                .iter()
                                .all(|m| self.is_member_known_failed_inner(m, visited, depth + 1)))
                }
            }
        } else {
            false
        };
        visited.remove(member);
        failed
    }

    fn sync_selector_delays(&self) {
        for name in &self.group_order {
            if let Some(grp) = self.groups.get(name)
                && grp.group_type == ProxyGroupType::Select
            {
                let chosen = grp.current();
                if let Some(ms) = self.effective_member_delay(&chosen) {
                    self.delays.record(name, ms);
                } else if self.is_member_known_failed(&chosen) {
                    self.delays.record_failure(name);
                } else {
                    self.delays.clear(name);
                }
            }
        }
    }

    pub fn manual_selections_snapshot(&self) -> HashMap<String, String> {
        let mut out = HashMap::new();
        for (name, grp) in &self.groups {
            if grp.group_type == ProxyGroupType::Select {
                out.insert(name.clone(), grp.current());
            }
        }
        out
    }

    pub fn apply_saved_selections(&self, saved: &HashMap<String, String>) {
        let mut applied = false;
        for (group_name, chosen) in saved {
            if let Some(grp) = self.groups.get(group_name)
                && grp.group_type == ProxyGroupType::Select
                && grp.select_manual(chosen).is_ok()
            {
                applied = true;
            }
        }
        if applied || !saved.is_empty() {
            self.sync_selector_delays();
            self.bump_epoch();
        }
    }

    pub fn import_delays_from(&self, prev: &Router) {
        let mut valid_names: HashSet<String> = self.outbounds.keys().cloned().collect();
        valid_names.extend(self.groups.keys().cloned());
        self.delays.import_from(&prev.delays, &valid_names);
        self.sync_selector_delays();
    }

    pub fn effective_primary_outbound(&self) -> EffectiveOutboundSummary {
        let mode = self.mode();
        match mode {
            RunMode::Direct => EffectiveOutboundSummary {
                mode,
                primary_group: None,
                selected_member: None,
                effective_outbound: "DIRECT".to_string(),
                effective_protocol: "Direct".to_string(),
                chains: vec!["DIRECT".to_string()],
            },
            RunMode::Global => {
                let selected_member = self.groups.get("GLOBAL").map(|g| g.current());
                let (ob, chains) = self.resolve_chain_preview("GLOBAL");
                EffectiveOutboundSummary {
                    mode,
                    primary_group: Some("GLOBAL".to_string()),
                    selected_member,
                    effective_outbound: ob.name().to_string(),
                    effective_protocol: ob.protocol().to_string(),
                    chains,
                }
            }
            RunMode::Rule => {
                let match_target = self
                    .rules
                    .iter()
                    .find(|r| matches!(r.matcher, RuleMatcher::Match))
                    .map(|r| r.target.clone());

                let entry = match_target.or_else(|| {
                    self.group_order
                        .iter()
                        .find(|g| g.as_str() != "GLOBAL")
                        .cloned()
                });

                match entry {
                    Some(target_name) => {
                        if let Some(grp) = self.groups.get(&target_name) {
                            let selected_member = Some(grp.current());
                            let (ob, chains) = self.resolve_chain_preview(&target_name);
                            EffectiveOutboundSummary {
                                mode,
                                primary_group: Some(target_name),
                                selected_member,
                                effective_outbound: ob.name().to_string(),
                                effective_protocol: ob.protocol().to_string(),
                                chains,
                            }
                        } else {
                            let (ob, chains) = self.resolve_chain_preview(&target_name);
                            EffectiveOutboundSummary {
                                mode,
                                primary_group: None,
                                selected_member: None,
                                effective_outbound: ob.name().to_string(),
                                effective_protocol: ob.protocol().to_string(),
                                chains,
                            }
                        }
                    }
                    None => EffectiveOutboundSummary {
                        mode,
                        primary_group: None,
                        selected_member: None,
                        effective_outbound: "REJECT".to_string(),
                        effective_protocol: "Reject".to_string(),
                        chains: vec!["REJECT".to_string()],
                    },
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn visit_probe_group_graph(
        &self,
        grp: &Arc<ProxyGroup>,
        inherited_url: &str,
        override_url: Option<&str>,
        expand_selectors: bool,
        depth: usize,
        visiting: &mut HashSet<String>,
        visited: &mut HashSet<String>,
        effective_urls: &mut HashMap<String, String>,
        unique_probes: &mut HashSet<(String, String)>,
        topo_groups: &mut Vec<Arc<ProxyGroup>>,
    ) {
        if depth >= 16 || visited.contains(&grp.name) || !visiting.insert(grp.name.clone()) {
            return;
        }

        let probe_url = match override_url {
            Some(explicit) => explicit.to_string(),
            None => match grp.group_type {
                ProxyGroupType::Select => inherited_url.to_string(),
                ProxyGroupType::UrlTest
                | ProxyGroupType::Fallback
                | ProxyGroupType::LoadBalance => grp.test_url.clone(),
            },
        };
        effective_urls.insert(grp.name.clone(), probe_url.clone());

        if grp.group_type == ProxyGroupType::Select && !expand_selectors {
            let cur = grp.current();
            if self.outbounds.contains_key(&cur) {
                unique_probes.insert((cur, probe_url));
            } else if let Some(sub_grp) = self.groups.get(&cur) {
                self.visit_probe_group_graph(
                    sub_grp,
                    &probe_url,
                    override_url,
                    expand_selectors,
                    depth + 1,
                    visiting,
                    visited,
                    effective_urls,
                    unique_probes,
                    topo_groups,
                );
            }
        } else {
            for member in &grp.members {
                if self.outbounds.contains_key(member) {
                    unique_probes.insert((member.clone(), probe_url.clone()));
                } else if let Some(sub_grp) = self.groups.get(member) {
                    self.visit_probe_group_graph(
                        sub_grp,
                        &probe_url,
                        override_url,
                        expand_selectors,
                        depth + 1,
                        visiting,
                        visited,
                        effective_urls,
                        unique_probes,
                        topo_groups,
                    );
                }
            }
        }

        visiting.remove(&grp.name);
        visited.insert(grp.name.clone());
        topo_groups.push(Arc::clone(grp));
    }

    async fn probe_concrete_outbound_with_policy(
        &self,
        outbound: &DynOutbound,
        probe_url: &str,
        timeout: Duration,
        unified: bool,
        allow_private: bool,
        allowed_private_addrs: &[SocketAddr],
    ) -> Result<u64> {
        let (is_https, clean_host, port, path, _sanitized) =
            crate::probe::validate_probe_url(probe_url, allow_private, allowed_private_addrs)?;

        if !allow_private
            && outbound.protocol().eq_ignore_ascii_case("Direct")
            && clean_host.parse::<IpAddr>().is_err()
        {
            let started = Instant::now();
            let dial_ip = if clean_host.eq_ignore_ascii_case("localhost") {
                crate::outbound::select_whitelisted_loopback_ip(port, allowed_private_addrs)
            } else {
                let ips = tokio::time::timeout(timeout, self.dns.resolve_direct_ips(&clean_host))
                    .await
                    .map_err(|_| ProxyError::Timeout)??;
                crate::outbound::validate_resolved_probe_ips(
                    &clean_host,
                    port,
                    &ips,
                    allowed_private_addrs,
                )?
            };
            let remaining = timeout.saturating_sub(started.elapsed());
            if remaining.is_zero() {
                return Err(ProxyError::Timeout);
            }
            let dial_target = TargetAddr::new_ip(dial_ip, port);
            return crate::outbound::latency_test_on_target(
                outbound.as_ref(),
                &dial_target,
                &clean_host,
                port,
                &path,
                is_https,
                remaining,
                unified,
            )
            .await
            .map_err(ProxyError::Io);
        }

        outbound
            .latency_test_with_policy(
                probe_url,
                timeout,
                unified,
                allow_private,
                allowed_private_addrs,
            )
            .await
    }

    async fn run_concrete_probes_with_policy(
        &self,
        unique_probes: HashSet<(String, String)>,
        timeout: Duration,
        allow_private: bool,
        allowed_private_addrs: &[SocketAddr],
    ) -> Result<HashMap<(String, String), Option<u64>>> {
        for (_, probe_url) in &unique_probes {
            let _ =
                crate::probe::validate_probe_url(probe_url, allow_private, allowed_private_addrs)?;
        }

        let unified = self.unified_delay();
        let sem = Arc::new(Semaphore::new(16));
        let mut futs = FuturesUnordered::new();
        for (member, probe_url) in unique_probes {
            let outbound_opt = self.outbounds.get(&member).cloned();
            let sem_clone = Arc::clone(&sem);
            futs.push(async move {
                let Some(outbound) = outbound_opt else {
                    return ((member, probe_url), Ok(None));
                };
                let _permit = sem_clone.acquire().await.ok();
                match self
                    .probe_concrete_outbound_with_policy(
                        &outbound,
                        &probe_url,
                        timeout,
                        unified,
                        allow_private,
                        allowed_private_addrs,
                    )
                    .await
                {
                    Ok(ms) => ((member, probe_url), Ok(Some(ms))),
                    Err(ProxyError::Config(msg)) => {
                        ((member, probe_url), Err(ProxyError::Config(msg)))
                    }
                    Err(_) => ((member, probe_url), Ok(None)),
                }
            });
        }

        let mut results: HashMap<(String, String), Option<u64>> = HashMap::new();
        while let Some((key, outcome)) = futs.next().await {
            match outcome {
                Ok(val) => {
                    results.insert(key, val);
                }
                Err(err) => {
                    // Policy/SSRF rejection: abort remaining probes immediately without
                    // poisoning recorded delays.
                    return Err(err);
                }
            }
        }

        let mut member_best: HashMap<&str, Option<u64>> = HashMap::new();
        for ((member, _), val) in &results {
            if self.outbounds.contains_key(member) {
                member_best
                    .entry(member.as_str())
                    .and_modify(|cur| {
                        if let Some(ms) = *val {
                            *cur = Some(cur.map_or(ms, |prev| prev.min(ms)));
                        }
                    })
                    .or_insert(*val);
            }
        }
        for (member, val) in member_best {
            match val {
                Some(ms) => self.delays.record(member, ms),
                None => self.delays.record_failure(member),
            }
        }
        Ok(results)
    }

    async fn run_concrete_probes(
        &self,
        unique_probes: HashSet<(String, String)>,
        timeout: Duration,
    ) -> HashMap<(String, String), Option<u64>> {
        self.run_concrete_probes_with_policy(unique_probes, timeout, true, &[])
            .await
            .unwrap_or_default()
    }

    fn evaluate_topo_groups_bottom_up(
        &self,
        topo_groups: &[Arc<ProxyGroup>],
        effective_urls: &HashMap<String, String>,
        probe_results: &HashMap<(String, String), Option<u64>>,
        evaluated_at: Instant,
    ) -> HashMap<String, Option<u64>> {
        let mut group_results: HashMap<String, Option<u64>> =
            HashMap::with_capacity(topo_groups.len());

        for grp in topo_groups {
            let Some(probe_url) = effective_urls.get(&grp.name) else {
                continue;
            };
            let mut group_map = HashMap::with_capacity(grp.members.len());
            for member in &grp.members {
                let val = if self.outbounds.contains_key(member) {
                    probe_results
                        .get(&(member.clone(), probe_url.clone()))
                        .copied()
                        .flatten()
                } else {
                    match group_results.get(member) {
                        Some(&res) => res,
                        None => self.effective_member_delay(member),
                    }
                };
                group_map.insert(member.clone(), val);
            }

            grp.mark_evaluated(evaluated_at);
            grp.apply_probe_results(&group_map, &self.delays);

            let effective_delay = match grp.group_type {
                ProxyGroupType::Select | ProxyGroupType::UrlTest | ProxyGroupType::Fallback => {
                    group_map.get(&grp.current()).copied().flatten()
                }
                ProxyGroupType::LoadBalance => {
                    let peeked = grp.peek_member(&self.delays);
                    group_map
                        .get(&peeked)
                        .copied()
                        .flatten()
                        .or_else(|| group_map.values().flatten().copied().min())
                }
            };
            group_results.insert(grp.name.clone(), effective_delay);
        }

        group_results
    }

    fn collect_topo_auto_groups(&self) -> Vec<Arc<ProxyGroup>> {
        fn visit(
            grp: &Arc<ProxyGroup>,
            groups: &HashMap<String, Arc<ProxyGroup>>,
            depth: usize,
            visiting: &mut HashSet<String>,
            visited: &mut HashSet<String>,
            out: &mut Vec<Arc<ProxyGroup>>,
        ) {
            if depth >= 16 || visited.contains(&grp.name) || !visiting.insert(grp.name.clone()) {
                return;
            }
            for member in &grp.members {
                if let Some(sub) = groups.get(member) {
                    visit(sub, groups, depth + 1, visiting, visited, out);
                }
            }
            visiting.remove(&grp.name);
            visited.insert(grp.name.clone());
            if matches!(
                grp.group_type,
                ProxyGroupType::UrlTest | ProxyGroupType::Fallback | ProxyGroupType::LoadBalance
            ) {
                out.push(Arc::clone(grp));
            }
        }

        let mut visiting = HashSet::new();
        let mut visited = HashSet::new();
        let mut out = Vec::new();
        for name in &self.group_order {
            if let Some(grp) = self.groups.get(name) {
                visit(grp, &self.groups, 0, &mut visiting, &mut visited, &mut out);
            }
        }
        out
    }

    fn reconcile_auto_groups_from_delays(&self) -> bool {
        let mut changed = false;
        for grp in self.collect_topo_auto_groups() {
            let mut map = HashMap::with_capacity(grp.members.len());
            for member in &grp.members {
                map.insert(member.clone(), self.effective_member_delay(member));
            }
            let prev = grp.current();
            let eff = grp.update_selection_from_probes(&map);
            if grp.current() != prev {
                changed = true;
            }
            if let Some(ms) = eff {
                if self.delays.is_known_failed(&grp.name) {
                    changed = true;
                }
                self.delays.record(&grp.name, ms);
            } else if !grp.members.is_empty()
                && grp.members.iter().all(|m| self.is_member_known_failed(m))
            {
                self.delays.record_failure(&grp.name);
            } else if self.delays.latest_delay(&grp.name).is_some() {
                self.delays.clear(&grp.name);
                changed = true;
            }
        }
        changed
    }

    pub async fn test_delay(&self, name: &str, url: &str, timeout: Duration) -> Result<u64> {
        self.test_delay_with_policy(name, url, timeout, true, &[])
            .await
    }

    pub async fn test_delay_with_policy(
        &self,
        name: &str,
        url: &str,
        timeout: Duration,
        allow_private: bool,
        allowed_private_addrs: &[SocketAddr],
    ) -> Result<u64> {
        let _ = crate::probe::validate_probe_url(url, allow_private, allowed_private_addrs)?;

        let unified = self.unified_delay();
        if let Some(outbound) = self.outbounds.get(name) {
            let was_alive = self.delays.latest_delay(name).is_some();
            match self
                .probe_concrete_outbound_with_policy(
                    outbound,
                    url,
                    timeout,
                    unified,
                    allow_private,
                    allowed_private_addrs,
                )
                .await
            {
                Ok(ms) => {
                    self.delays.record(name, ms);
                    let group_changed = self.reconcile_auto_groups_from_delays();
                    self.sync_selector_delays();
                    if !was_alive || group_changed {
                        self.bump_epoch();
                    }
                    return Ok(ms);
                }
                Err(ProxyError::Config(msg)) => {
                    return Err(ProxyError::Config(msg));
                }
                Err(e) => {
                    self.delays.record_failure(name);
                    let group_changed = self.reconcile_auto_groups_from_delays();
                    self.sync_selector_delays();
                    if was_alive || group_changed {
                        self.bump_epoch();
                    }
                    return Err(e);
                }
            }
        }
        if let Some(group) = self.groups.get(name) {
            let mut visiting = HashSet::new();
            let mut visited = HashSet::new();
            let mut effective_urls = HashMap::new();
            let mut unique_probes = HashSet::new();
            let mut topo_groups = Vec::new();

            self.visit_probe_group_graph(
                group,
                url,
                Some(url),
                true,
                0,
                &mut visiting,
                &mut visited,
                &mut effective_urls,
                &mut unique_probes,
                &mut topo_groups,
            );

            let probe_results = self
                .run_concrete_probes_with_policy(
                    unique_probes,
                    timeout,
                    allow_private,
                    allowed_private_addrs,
                )
                .await?;
            let evaluated_at = Instant::now();
            let group_results = self.evaluate_topo_groups_bottom_up(
                &topo_groups,
                &effective_urls,
                &probe_results,
                evaluated_at,
            );
            self.sync_selector_delays();
            self.bump_epoch();

            if let Some(Some(ms)) = group_results.get(name) {
                return Ok(*ms);
            }
            self.delays.record_failure(name);
            return Err(ProxyError::Timeout);
        }
        Err(ProxyError::Routing(format!(
            "proxy or group '{name}' not found"
        )))
    }

    pub async fn refresh_auto_groups(&self, timeout: Duration) {
        self.refresh_due_auto_groups(timeout, true).await;
    }

    /// Probe due automatic proxy groups (`URLTest`, `Fallback`, and `LoadBalance`), recursively
    /// expanding nested sub-groups, probing unique `(concrete_outbound, test_url)` targets once
    /// concurrently (bounded to 16), and applying results bottom-up in topological post-order
    /// (children before parents) so parent groups always observe freshly updated sub-group delays.
    pub async fn refresh_due_auto_groups(&self, timeout: Duration, force_all: bool) {
        let now = Instant::now();
        let mut seed_groups: Vec<Arc<ProxyGroup>> = Vec::new();

        for name in &self.group_order {
            if let Some(grp) = self.groups.get(name)
                && matches!(
                    grp.group_type,
                    ProxyGroupType::UrlTest
                        | ProxyGroupType::Fallback
                        | ProxyGroupType::LoadBalance
                )
                && (force_all || grp.is_due_for_periodic_probe(now))
            {
                seed_groups.push(Arc::clone(grp));
            }
        }

        if seed_groups.is_empty() {
            return;
        }

        let mut visiting = HashSet::new();
        let mut visited = HashSet::new();
        let mut effective_urls = HashMap::new();
        let mut unique_probes = HashSet::new();
        let mut topo_groups = Vec::new();

        for grp in &seed_groups {
            self.visit_probe_group_graph(
                grp,
                &grp.test_url,
                None,
                false,
                0,
                &mut visiting,
                &mut visited,
                &mut effective_urls,
                &mut unique_probes,
                &mut topo_groups,
            );
        }

        let probe_results = self.run_concrete_probes(unique_probes, timeout).await;
        let evaluated_at = Instant::now();
        let _ = self.evaluate_topo_groups_bottom_up(
            &topo_groups,
            &effective_urls,
            &probe_results,
            evaluated_at,
        );
        self.sync_selector_delays();
        self.bump_epoch();
    }

    pub fn group_order(&self) -> &[String] {
        &self.group_order
    }

    /// Return proxy groups in exact YAML `group_order`, followed by concrete
    /// outbounds (`DIRECT`, `REJECT`, then alphabetically sorted nodes) so
    /// `GET /proxies` with `serde_json`'s `preserve_order` is 100% deterministic
    /// across requests and never shuffles groups in the UI.
    pub fn proxies_snapshot_ordered(&self) -> Vec<(String, ProxyInfoSnapshot)> {
        let mut out = Vec::with_capacity(self.group_order.len() + self.outbounds.len());
        let mut emitted = HashSet::with_capacity(self.group_order.len() + self.outbounds.len());

        for name in &self.group_order {
            if let Some(grp) = self.groups.get(name) {
                let mut snap = grp.snapshot(&self.delays);
                let (leaf_ob, chains) = self.resolve_chain_preview(name);
                snap.udp = leaf_ob.udp_supported();
                snap.effective_outbound = Some(leaf_ob.name().to_string());
                snap.effective_protocol = Some(leaf_ob.protocol().to_string());
                snap.chains = Some(chains);
                emitted.insert(name.as_str());
                out.push((name.clone(), snap));
            }
        }

        let mut outbound_names: Vec<&String> = self
            .outbounds
            .keys()
            .filter(|name| !emitted.contains(name.as_str()))
            .collect();
        outbound_names.sort_by(|a, b| {
            let rank = |s: &str| match s {
                "DIRECT" => 0u8,
                "REJECT" => 1u8,
                _ => 2u8,
            };
            rank(a.as_str())
                .cmp(&rank(b.as_str()))
                .then_with(|| a.cmp(b))
        });

        for name in outbound_names {
            if let Some(ob) = self.outbounds.get(name) {
                out.push((
                    name.clone(),
                    ProxyInfoSnapshot {
                        name: name.clone(),
                        proxy_type: ob.protocol().to_string(),
                        udp: ob.udp_supported(),
                        now: None,
                        all: None,
                        effective_outbound: Some(name.clone()),
                        effective_protocol: Some(ob.protocol().to_string()),
                        chains: Some(vec![name.clone()]),
                        history: self.delays.history(name),
                    },
                ));
            }
        }
        out
    }

    pub fn proxies_snapshot(&self) -> HashMap<String, ProxyInfoSnapshot> {
        self.proxies_snapshot_ordered().into_iter().collect()
    }

    pub fn rules_snapshot(&self) -> Vec<RuleSnapshot> {
        self.rules.iter().map(|r| r.snapshot()).collect()
    }

    pub fn concrete_outbound(&self, name: &str) -> Option<DynOutbound> {
        self.outbounds.get(name).cloned()
    }

    /// Return a concrete `"PROXY"` outbound suitable for control-plane HTTPS fallback
    /// (subscription refresh & GeoData mirror downloads when direct egress is blocked).
    /// Returns `None` in `Direct` mode or when no concrete proxy node is configured.
    pub fn fallback_proxy_outbound(&self) -> Option<DynOutbound> {
        if self.mode() == RunMode::Direct {
            return None;
        }
        let eff = self.effective_primary_outbound();
        if let Some(ob) = self.outbounds.get(&eff.effective_outbound)
            && ob.exit_category() == "PROXY"
        {
            return Some(Arc::clone(ob));
        }
        let (global_ob, _) = self.resolve_chain_preview("GLOBAL");
        if global_ob.exit_category() == "PROXY" {
            return Some(global_ob);
        }
        for grp_name in &self.group_order {
            let (ob, _) = self.resolve_chain_preview(grp_name);
            if ob.exit_category() == "PROXY" {
                return Some(ob);
            }
        }
        self.outbounds
            .values()
            .find(|ob| ob.exit_category() == "PROXY")
            .cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DnsConfig;

    #[tokio::test]
    async fn resolve_chain_and_unmatched_rules_fail_closed_never_direct() {
        let dns = Arc::new(FakeIpDnsEngine::new(&DnsConfig::default()).unwrap());
        let rules = vec!["DOMAIN,only-this.example.com,DIRECT".to_string()];
        let router = Router::new(RunMode::Rule, HashMap::new(), &[], &rules, dns).unwrap();

        let target = TargetAddr::new_domain("unmatched.example.org", 443).unwrap();
        let sync_dec = router.route(None, &target);
        assert_eq!(sync_dec.outbound.name(), "REJECT");
        assert_eq!(sync_dec.rule_type, "ImplicitReject");

        let async_dec = router.route_async(None, &target).await;
        assert_eq!(async_dec.outbound.name(), "REJECT");

        let (ghost_ob, ghost_chain) = router.resolve_chain("NON_EXISTENT_PROXY", &target);
        assert_eq!(ghost_ob.name(), "ROUTING-ERROR");
        assert_eq!(ghost_chain[0], "ROUTING-ERROR");
        let err = ghost_ob.connect_tcp(&target).await.err().unwrap();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    }

    #[tokio::test]
    async fn fast_domain_index_preserves_exact_rule_priority_with_50k_rules() {
        let dns = Arc::new(FakeIpDnsEngine::new(&DnsConfig::default()).unwrap());
        let mut rules = Vec::with_capacity(50_010);
        // Rule 0: non-indexed keyword rule before 50,000 domain rules!
        rules.push("DOMAIN-KEYWORD,override-first,REJECT".to_string());
        for i in 0..25_000 {
            rules.push(format!("DOMAIN,host-{i}.bench.test,DIRECT"));
            rules.push(format!("DOMAIN-SUFFIX,zone-{i}.bench.test,DIRECT"));
        }
        rules.push("MATCH,REJECT".to_string());

        let router = Router::new(RunMode::Rule, HashMap::new(), &[], &rules, dns).unwrap();

        // `override-first.zone-42.bench.test` matches BOTH Rule 0 (`DOMAIN-KEYWORD` -> REJECT)
        // AND Rule 86 (`DOMAIN-SUFFIX,zone-42.bench.test` -> DIRECT). Rule 0 MUST win!
        let d_override = router
            .route_async(
                None,
                &TargetAddr::new_domain("override-first.zone-42.bench.test", 443).unwrap(),
            )
            .await;
        assert_eq!(d_override.rule_type, "DomainKeyword");
        assert_eq!(d_override.outbound.name(), "REJECT");

        // `api.zone-24999.bench.test` hits the O(labels) suffix index -> DIRECT in microseconds!
        let d_suffix = router
            .route_async(
                None,
                &TargetAddr::new_domain("api.zone-24999.bench.test", 443).unwrap(),
            )
            .await;
        assert_eq!(d_suffix.rule_type, "DomainSuffix");
        assert_eq!(d_suffix.outbound.name(), "DIRECT");
    }

    #[test]
    fn router_epoch_and_delay_helpers_advance_monotonically() {
        let dns = Arc::new(FakeIpDnsEngine::new(&DnsConfig::default()).unwrap());
        let grp = ProxyGroupConfig {
            name: "PROXY".to_string(),
            group_type: ProxyGroupType::Select,
            proxies: vec!["DIRECT".to_string(), "REJECT".to_string()],
            url: "http://www.gstatic.com/generate_204".to_string(),
            interval: 300,
            tolerance: 50,
            strategy: None,
        };
        let rules = vec!["MATCH,PROXY".to_string()];
        let router = Router::new(RunMode::Rule, HashMap::new(), &[grp], &rules, dns).unwrap();

        let e0 = router.epoch();
        assert!(e0 > 0);
        router.set_mode(RunMode::Global);
        let e1 = router.epoch();
        assert!(e1 > e0);
        router.select_group("PROXY", "REJECT").unwrap();
        let e2 = router.epoch();
        assert!(e2 > e1);

        assert!(router.latest_delay_age_ms("DIRECT").is_none());
        router.seed_delay_if_absent("DIRECT", 42);
        assert_eq!(router.delays().latest_delay("DIRECT"), Some(42));
        assert!(router.latest_delay_age_ms("DIRECT").is_some());
        router.seed_delay_if_absent("DIRECT", 99);
        assert_eq!(router.delays().latest_delay("DIRECT"), Some(42));
        router.record_passive_delay_if_stale("DIRECT", 21, 0);
        assert_eq!(router.delays().latest_delay("DIRECT"), Some(21));

        // Screen-off low_power_mode preserves an existing node delay against RRC-idle heartbeat spikes,
        // while still allowing an unseeded node to record its first measurement and resuming normal
        // passive refreshes once interactive again.
        let sleep_at_least = |min_elapsed: Duration| {
            let start = Instant::now();
            while start.elapsed() < min_elapsed {
                let remaining = min_elapsed.saturating_sub(start.elapsed());
                std::thread::sleep(remaining.max(Duration::from_millis(1)));
            }
        };
        router.delays().record("SG-01", 105);
        router.set_low_power_mode(true);
        assert!(router.is_low_power_mode());
        sleep_at_least(Duration::from_millis(2));
        router.record_passive_delay_if_stale("SG-01", 456, 1);
        assert_eq!(router.delays().latest_delay("SG-01"), Some(105));
        router.record_passive_delay_if_stale("SG-UNSEEDED", 180, 1);
        assert_eq!(router.delays().latest_delay("SG-UNSEEDED"), Some(180));

        router.set_low_power_mode(false);
        assert!(!router.is_low_power_mode());
        sleep_at_least(Duration::from_millis(2));
        router.record_passive_delay_if_stale("SG-01", 112, 1);
        assert_eq!(router.delays().latest_delay("SG-01"), Some(112));
    }

    struct MockProbeOutbound {
        name: String,
        delay_ms: Arc<AtomicU64>,
        probes: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl MockProbeOutbound {
        #[allow(clippy::new_ret_no_self)]
        fn new(
            name: &str,
            initial_ms: u64,
        ) -> (
            DynOutbound,
            Arc<AtomicU64>,
            Arc<std::sync::atomic::AtomicUsize>,
        ) {
            let delay_ms = Arc::new(AtomicU64::new(initial_ms));
            let probes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let ob: DynOutbound = Arc::new(Self {
                name: name.to_string(),
                delay_ms: Arc::clone(&delay_ms),
                probes: Arc::clone(&probes),
            });
            (ob, delay_ms, probes)
        }
    }

    #[async_trait::async_trait]
    impl crate::outbound::OutboundHandler for MockProbeOutbound {
        fn name(&self) -> &str {
            &self.name
        }

        fn protocol(&self) -> &'static str {
            "Shadowsocks"
        }

        async fn connect_tcp(
            &self,
            _target: &TargetAddr,
        ) -> io::Result<crate::outbound::BoxedStream> {
            Err(io::Error::new(io::ErrorKind::Unsupported, "mock outbound"))
        }

        async fn latency_test_with_mode(
            &self,
            _test_url: &str,
            _timeout: Duration,
            _unified_delay: bool,
        ) -> io::Result<u64> {
            self.probes.fetch_add(1, Ordering::SeqCst);
            let ms = self.delay_ms.load(Ordering::SeqCst);
            if ms == 0 {
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "simulated node outage",
                ))
            } else {
                Ok(ms)
            }
        }
    }

    async fn spawn_local_204_origin() -> (
        String,
        tokio::sync::watch::Sender<bool>,
        tokio::task::JoinHandle<()>,
    ) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (stop_tx, mut stop_rx) = tokio::sync::watch::channel(false);
        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    changed = stop_rx.changed() => {
                        if changed.is_err() || *stop_rx.borrow() {
                            break;
                        }
                    }
                    accepted = listener.accept() => {
                        let Ok((mut tcp, _)) = accepted else {
                            continue;
                        };
                        tokio::spawn(async move {
                            let mut buf = [0u8; 512];
                            let _ = tcp.read(&mut buf).await;
                            let _ = tcp
                                .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                                .await;
                        });
                    }
                }
            }
        });
        (format!("http://{addr}/generate_204"), stop_tx, handle)
    }

    #[tokio::test]
    async fn nested_fallback_group_preserves_healthy_subgroup_clears_stale_delay_on_outage_and_recovers()
     {
        let (probe_url, stop_tx, origin_jh) = spawn_local_204_origin().await;
        let dns = Arc::new(FakeIpDnsEngine::new(&DnsConfig::default()).unwrap());

        let (hk1_ob, hk1_ms, hk1_probes) = MockProbeOutbound::new("hk-1", 55);
        let (hk2_ob, hk2_ms, hk2_probes) = MockProbeOutbound::new("hk-2", 35);
        let mut outbounds = HashMap::new();
        outbounds.insert("hk-1".to_string(), hk1_ob);
        outbounds.insert("hk-2".to_string(), hk2_ob);

        // Intentionally place parent `Region-Fallback` BEFORE child `HK-Auto` in `proxy_groups`
        // AND give parent a shorter interval (10s) than child (300s)!
        let groups = vec![
            ProxyGroupConfig {
                name: "Region-Fallback".to_string(),
                group_type: ProxyGroupType::Fallback,
                proxies: vec!["HK-Auto".to_string(), "DIRECT".to_string()],
                url: probe_url.clone(),
                interval: 10,
                tolerance: 50,
                strategy: None,
            },
            ProxyGroupConfig {
                name: "HK-Auto".to_string(),
                group_type: ProxyGroupType::UrlTest,
                proxies: vec!["hk-1".to_string(), "hk-2".to_string()],
                url: probe_url.clone(),
                interval: 300,
                tolerance: 10,
                strategy: None,
            },
        ];
        let rules = vec!["MATCH,Region-Fallback".to_string()];
        let router = Router::new(RunMode::Rule, outbounds, &groups, &rules, dns).unwrap();

        // 1. Initial refresh: `HK-Auto` is healthy (hk-2=35ms), so `Region-Fallback` MUST select `HK-Auto` (NOT `DIRECT`!)
        router.refresh_auto_groups(Duration::from_secs(2)).await;
        assert_eq!(hk1_probes.load(Ordering::SeqCst), 1);
        assert_eq!(hk2_probes.load(Ordering::SeqCst), 1);
        assert_eq!(router.delays().latest_delay("HK-Auto"), Some(35));
        assert_eq!(router.effective_member_delay("HK-Auto"), Some(35));
        assert_eq!(router.delays().latest_delay("Region-Fallback"), Some(35));
        assert_eq!(
            router
                .effective_outbound_for_group("Region-Fallback")
                .as_deref(),
            Some("hk-2")
        );
        let probe_target = TargetAddr::new_domain("example.com", 443).unwrap();
        assert_eq!(
            router
                .resolve_member_outbound("Region-Fallback", &probe_target)
                .unwrap()
                .name(),
            "hk-2"
        );

        // 2. `hk-2` dies while `hk-1` (55ms) stays healthy, and ONLY parent `Region-Fallback` is due (`force_all = false`):
        //    `refresh_due_auto_groups` must still refresh child `HK-Auto` bottom-up -> `hk-1`, NEVER failing over to `DIRECT`!
        hk2_ms.store(0, Ordering::SeqCst);
        router
            .groups
            .get("Region-Fallback")
            .unwrap()
            .mark_evaluated(Instant::now() - Duration::from_secs(20));
        router
            .refresh_due_auto_groups(Duration::from_secs(2), false)
            .await;
        assert_eq!(router.delays().latest_delay("HK-Auto"), Some(55));
        assert_eq!(
            router
                .effective_outbound_for_group("Region-Fallback")
                .as_deref(),
            Some("hk-1")
        );

        // 3. Total `HK-Auto` outage (`hk-1` and `hk-2` both dead):
        //    `HK-Auto` MUST clear its stale 55ms delay (`None`), and `Region-Fallback` MUST fail over to `DIRECT`!
        hk1_ms.store(0, Ordering::SeqCst);
        router.refresh_auto_groups(Duration::from_secs(2)).await;
        assert_eq!(router.delays().latest_delay("HK-Auto"), None);
        assert!(router.delays().is_known_failed("HK-Auto"));
        assert_eq!(router.effective_member_delay("HK-Auto"), None);
        assert_eq!(
            router
                .effective_outbound_for_group("Region-Fallback")
                .as_deref(),
            Some("DIRECT")
        );
        assert!(router.delays().latest_delay("Region-Fallback").is_some());

        // 4. `hk-2` recovers (42ms): `HK-Auto` and `Region-Fallback` MUST automatically recover from `DIRECT` back to `HK-Auto`!
        hk2_ms.store(42, Ordering::SeqCst);
        router.refresh_auto_groups(Duration::from_secs(2)).await;
        assert_eq!(router.delays().latest_delay("HK-Auto"), Some(42));
        assert_eq!(router.delays().latest_delay("Region-Fallback"), Some(42));
        assert_eq!(
            router
                .effective_outbound_for_group("Region-Fallback")
                .as_deref(),
            Some("hk-2")
        );

        let _ = stop_tx.send(true);
        let _ = origin_jh.await;
    }

    #[tokio::test]
    async fn test_delay_on_nested_groups_reports_selected_path_rtt_and_never_leaks_direct_rtt_on_dead_selector()
     {
        let (probe_url, stop_tx, origin_jh) = spawn_local_204_origin().await;
        let dns = Arc::new(FakeIpDnsEngine::new(&DnsConfig::default()).unwrap());

        let (hk1_ob, hk1_ms, _) = MockProbeOutbound::new("hk-1", 0);
        let (hk2_ob, hk2_ms, _) = MockProbeOutbound::new("hk-2", 68);
        let (jp1_ob, jp1_ms, _) = MockProbeOutbound::new("jp-1", 110);
        let mut outbounds = HashMap::new();
        outbounds.insert("hk-1".to_string(), hk1_ob);
        outbounds.insert("hk-2".to_string(), hk2_ob);
        outbounds.insert("jp-1".to_string(), jp1_ob);

        let groups = vec![
            ProxyGroupConfig {
                name: "HK-Auto".to_string(),
                group_type: ProxyGroupType::UrlTest,
                proxies: vec!["hk-1".to_string(), "hk-2".to_string()],
                url: probe_url.clone(),
                interval: 60,
                tolerance: 15,
                strategy: None,
            },
            ProxyGroupConfig {
                name: "JP-Auto".to_string(),
                group_type: ProxyGroupType::UrlTest,
                proxies: vec!["jp-1".to_string()],
                url: probe_url.clone(),
                interval: 60,
                tolerance: 15,
                strategy: None,
            },
            ProxyGroupConfig {
                name: "Region-Fallback".to_string(),
                group_type: ProxyGroupType::Fallback,
                proxies: vec![
                    "HK-Auto".to_string(),
                    "JP-Auto".to_string(),
                    "DIRECT".to_string(),
                ],
                url: probe_url.clone(),
                interval: 60,
                tolerance: 50,
                strategy: None,
            },
        ];
        let rules = vec!["MATCH,Region-Fallback".to_string()];
        let router = Router::new(RunMode::Global, outbounds, &groups, &rules, dns).unwrap();
        router.select_group("GLOBAL", "HK-Auto").unwrap();

        // 1. Healthy `HK-Auto` (`hk-2` = 68ms) while `DIRECT` is ~1ms:
        //    Both `GLOBAL` (Select -> HK-Auto) and `Region-Fallback` MUST report 68ms (NOT 504 Timeout and NOT DIRECT's ~1ms!)
        let global_ms = router
            .test_delay("GLOBAL", &probe_url, Duration::from_secs(2))
            .await
            .expect("GLOBAL -> HK-Auto should succeed");
        assert_eq!(global_ms, 68);
        assert_eq!(router.delays().latest_delay("GLOBAL"), Some(68));

        let fb_ms = router
            .test_delay("Region-Fallback", &probe_url, Duration::from_secs(2))
            .await
            .expect("Region-Fallback should succeed via HK-Auto");
        assert_eq!(fb_ms, 68);
        assert_eq!(
            router
                .effective_outbound_for_group("Region-Fallback")
                .as_deref(),
            Some("hk-2")
        );

        // 2. Kill `HK-Auto` completely (`hk-1` = 0, `hk-2` = 0) while `JP-Auto` (110ms) and `DIRECT` (~1ms) are alive:
        //    - `GLOBAL` (`Select` with `HK-Auto` selected) MUST return `Err(ProxyError::Timeout)` and clear stale 68ms delay!
        //    - `Region-Fallback` (`Fallback`) MUST fail over to `JP-Auto` and return 110ms!
        hk1_ms.store(0, Ordering::SeqCst);
        hk2_ms.store(0, Ordering::SeqCst);
        let global_err = router
            .test_delay("GLOBAL", &probe_url, Duration::from_secs(2))
            .await
            .expect_err("Select group with dead selected sub-group must NOT report DIRECT's RTT");
        assert!(matches!(global_err, ProxyError::Timeout));
        assert_eq!(router.delays().latest_delay("HK-Auto"), None);
        assert_eq!(router.delays().latest_delay("GLOBAL"), None);

        let fb_failover_ms = router
            .test_delay("Region-Fallback", &probe_url, Duration::from_secs(2))
            .await
            .expect("Region-Fallback should fail over to JP-Auto");
        assert_eq!(fb_failover_ms, 110);
        assert_eq!(
            router
                .effective_outbound_for_group("Region-Fallback")
                .as_deref(),
            Some("jp-1")
        );

        // 3. Kill `JP-Auto` (`jp-1` = 0) as well: `Region-Fallback` fails over to `DIRECT`
        jp1_ms.store(0, Ordering::SeqCst);
        let fb_direct_ms = router
            .test_delay("Region-Fallback", &probe_url, Duration::from_secs(2))
            .await
            .expect("Region-Fallback should fail over to DIRECT");
        assert!((1..68).contains(&fb_direct_ms));
        assert_eq!(router.delays().latest_delay("JP-Auto"), None);
        assert_eq!(
            router
                .effective_outbound_for_group("Region-Fallback")
                .as_deref(),
            Some("DIRECT")
        );
        assert!(router.proxies_snapshot()["Region-Fallback"].udp);

        // 4. Revive `hk-2` (45ms) and run a single-node `test_delay("hk-2")`:
        //    `HK-Auto` (`UrlTest`), `Region-Fallback` (`Fallback`), and `GLOBAL` (`Select` -> `HK-Auto`)
        //    must all reconcile immediately without needing a full group probe!
        hk2_ms.store(45, Ordering::SeqCst);
        let single_ms = router
            .test_delay("hk-2", &probe_url, Duration::from_secs(2))
            .await
            .expect("single-node test_delay on hk-2 should succeed");
        assert_eq!(single_ms, 45);
        assert_eq!(router.delays().latest_delay("HK-Auto"), Some(45));
        assert_eq!(router.delays().latest_delay("GLOBAL"), Some(45));
        assert_eq!(
            router
                .effective_outbound_for_group("Region-Fallback")
                .as_deref(),
            Some("hk-2")
        );

        let _ = stop_tx.send(true);
        let _ = origin_jh.await;
    }

    #[test]
    fn proxies_snapshot_ordered_preserves_yaml_group_order_deterministically() {
        let dns = Arc::new(FakeIpDnsEngine::new(&DnsConfig::default()).unwrap());
        let mk_group = |name: &str, members: &[&str]| ProxyGroupConfig {
            name: name.to_string(),
            group_type: ProxyGroupType::Select,
            proxies: members.iter().map(|s| (*s).to_string()).collect(),
            url: "http://www.gstatic.com/generate_204".to_string(),
            interval: 300,
            tolerance: 50,
            strategy: None,
        };
        let group_cfgs = vec![
            mk_group("🚀 节点选择", &["DIRECT", "REJECT"]),
            mk_group("Steam工坊", &["🚀 节点选择", "DIRECT"]),
            mk_group("电报信息", &["🚀 节点选择", "DIRECT"]),
            mk_group("Google", &["🚀 节点选择", "DIRECT"]),
        ];
        let rules = vec!["MATCH,🚀 节点选择".to_string()];
        let router = Router::new(RunMode::Rule, HashMap::new(), &group_cfgs, &rules, dns).unwrap();

        let expected_groups = vec![
            "🚀 节点选择".to_string(),
            "Steam工坊".to_string(),
            "电报信息".to_string(),
            "Google".to_string(),
            "GLOBAL".to_string(),
        ];
        assert_eq!(router.group_order(), expected_groups.as_slice());

        // Verify repeated snapshots never shuffle keys (unlike random-seeded HashMap)
        for _ in 0..8 {
            let ordered = router.proxies_snapshot_ordered();
            let group_keys: Vec<String> = ordered
                .iter()
                .filter(|(_, info)| info.all.is_some())
                .map(|(k, _)| k.clone())
                .collect();
            assert_eq!(group_keys, expected_groups);
        }
    }
}

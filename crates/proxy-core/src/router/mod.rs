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
    sync::Arc,
    time::{Duration, Instant},
};

use futures_util::future::join_all;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;

use crate::{
    addr::TargetAddr,
    config::{
        ProxyGroupConfig, ProxyGroupType, RuleProviderConfig, RunMode,
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
    unified_delay: std::sync::atomic::AtomicBool,
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
            unified_delay: std::sync::atomic::AtomicBool::new(true),
            outbounds,
            groups,
            group_order,
            rules,
            rule_index,
            dns,
            delays: Arc::new(DelayStore::default()),
        })
    }

    pub fn mode(&self) -> RunMode {
        *self.mode.read()
    }

    pub fn set_mode(&self, mode: RunMode) {
        *self.mode.write() = mode;
    }

    pub fn unified_delay(&self) -> bool {
        self.unified_delay
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn set_unified_delay(&self, enabled: bool) {
        self.unified_delay
            .store(enabled, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn set_low_power_mode(&self, enabled: bool) {
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
        self.dns.flush_cache();
        self.outbounds.values().map(|o| o.on_network_change()).sum()
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
        grp.select_manual(proxy_name)
    }

    /// Return the current effective leaf outbound name for `group_name` (if the group exists).
    pub fn effective_outbound_for_group(&self, group_name: &str) -> Option<String> {
        if !self.groups.contains_key(group_name) {
            return None;
        }
        let (ob, _) = self.resolve_chain_preview(group_name);
        Some(ob.name().to_string())
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
        for (group_name, chosen) in saved {
            if let Some(grp) = self.groups.get(group_name)
                && grp.group_type == ProxyGroupType::Select
            {
                let _ = grp.select_manual(chosen);
            }
        }
    }

    pub fn import_delays_from(&self, prev: &Router) {
        let mut valid_names: HashSet<String> = self.outbounds.keys().cloned().collect();
        valid_names.extend(self.groups.keys().cloned());
        self.delays.import_from(&prev.delays, &valid_names);
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

    pub async fn test_delay(&self, name: &str, url: &str, timeout: Duration) -> Result<u64> {
        let unified = self.unified_delay();
        if let Some(outbound) = self.outbounds.get(name) {
            match outbound.latency_test_with_mode(url, timeout, unified).await {
                Ok(ms) => {
                    self.delays.record(name, ms);
                    return Ok(ms);
                }
                Err(e) => {
                    self.delays.record_failure(name);
                    return Err(ProxyError::Io(e));
                }
            }
        }
        if let Some(group) = self.groups.get(name) {
            let map = group
                .evaluate_health_with_mode(
                    &self.outbounds,
                    &self.delays,
                    Some(url),
                    timeout,
                    unified,
                )
                .await;
            let chosen = group.current();
            if let Some(Some(ms)) = map.get(&chosen) {
                self.delays.record(name, *ms);
                return Ok(*ms);
            }
            if let Some(ms) = map.values().flatten().copied().min() {
                self.delays.record(name, ms);
                return Ok(ms);
            }
            return Err(ProxyError::Timeout);
        }
        Err(ProxyError::Routing(format!(
            "proxy or group '{name}' not found"
        )))
    }

    pub async fn refresh_auto_groups(&self, timeout: Duration) {
        self.refresh_due_auto_groups(timeout, true).await;
    }

    /// Probe due automatic proxy groups (`URLTest`, `Fallback`, and `LoadBalance`), deduplicating
    /// identical `(member_name, test_url)` probes across groups and bounding concurrency to 16.
    pub async fn refresh_due_auto_groups(&self, timeout: Duration, force_all: bool) {
        let now = Instant::now();
        let mut due_groups: Vec<Arc<ProxyGroup>> = Vec::new();
        let mut unique_probes: HashSet<(String, String)> = HashSet::new();

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
                for member in &grp.members {
                    if self.outbounds.contains_key(member) {
                        unique_probes.insert((member.clone(), grp.test_url.clone()));
                    }
                }
                due_groups.push(Arc::clone(grp));
            }
        }

        if due_groups.is_empty() {
            return;
        }

        let unified = self.unified_delay();
        let sem = Arc::new(Semaphore::new(16));
        let delays = &self.delays;
        let futs = unique_probes.into_iter().map(|(member, url)| {
            let outbound_opt = self.outbounds.get(&member).cloned();
            let sem_clone = Arc::clone(&sem);
            async move {
                let Some(outbound) = outbound_opt else {
                    return ((member, url), None);
                };
                let _permit = sem_clone.acquire().await.ok();
                match outbound
                    .latency_test_with_mode(&url, timeout, unified)
                    .await
                {
                    Ok(ms) => {
                        delays.record(&member, ms);
                        ((member, url), Some(ms))
                    }
                    Err(_) => {
                        delays.record_failure(&member);
                        ((member, url), None)
                    }
                }
            }
        });

        let probe_results: HashMap<(String, String), Option<u64>> =
            join_all(futs).await.into_iter().collect();
        let evaluated_at = Instant::now();

        for grp in due_groups {
            let mut group_map = HashMap::with_capacity(grp.members.len());
            for member in &grp.members {
                let val = probe_results
                    .get(&(member.clone(), grp.test_url.clone()))
                    .copied()
                    .flatten();
                group_map.insert(member.clone(), val);
            }
            grp.mark_evaluated(evaluated_at);
            grp.apply_probe_results(&group_map, &self.delays);
        }
    }

    pub fn proxies_snapshot(&self) -> HashMap<String, ProxyInfoSnapshot> {
        let mut map = HashMap::new();
        for (name, ob) in &self.outbounds {
            map.insert(
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
            );
        }
        for name in &self.group_order {
            if let Some(grp) = self.groups.get(name) {
                let mut snap = grp.snapshot(&self.delays);
                let (leaf_ob, chains) = self.resolve_chain_preview(name);
                snap.effective_outbound = Some(leaf_ob.name().to_string());
                snap.effective_protocol = Some(leaf_ob.protocol().to_string());
                snap.chains = Some(chains);
                map.insert(name.clone(), snap);
            }
        }
        map
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
}

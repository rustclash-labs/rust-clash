use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
    sync::Arc,
};

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::{
    addr::TargetAddr,
    config::{ClashConfig, ProxyGroupConfig, ProxyNodeConfig, RunMode, uri::redact_sensitive_text},
    dns::upstream::DnsUpstream,
    router::{
        RouteSimulationPreview, Router,
        mmdb::{MmdbReader, build_synthetic_country_mmdb},
        rules::{CompiledRule, RuleMatcher},
        ruleset::build_rule_sets_with_state_dir,
    },
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuditSeverity {
    Info,
    Low,
    Medium,
    High,
}

impl AuditSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditSeverityCounts {
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditFinding {
    pub code: String,
    pub severity: AuditSeverity,
    pub category: String,
    pub title: String,
    pub location: String,
    pub detail: String,
    pub remediation: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeakSimulationRow {
    pub label: String,
    pub category: String,
    pub target: String,
    pub matched_rule: String,
    pub chains: Vec<String>,
    pub effective_outbound: String,
    pub exit_type: String,
    pub triggered_local_dns_by_rule: Option<String>,
    #[serde(default)]
    pub ip_rules_skipped_without_dns: bool,
    pub dns_strategy: String,
    pub risk_level: String,
    pub note: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigAuditReport {
    pub score: u8,
    pub grade: String,
    pub mode: RunMode,
    /// `"static_first_member_estimate"`, `"live_router_selection"`, or `"live_router_with_dns"`
    #[serde(default)]
    pub simulation_basis: String,
    pub proxy_count: usize,
    pub group_count: usize,
    pub rule_count: usize,
    pub counts: AuditSeverityCounts,
    pub findings: Vec<AuditFinding>,
    pub leak_matrix: Vec<LeakSimulationRow>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyDiffEntry {
    pub name: String,
    pub protocol: String,
    pub server: String,
    pub port: u16,
    pub tls: bool,
    pub skip_cert_verify: bool,
    pub udp: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyChangeEntry {
    pub name: String,
    pub changes: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigDiffSummary {
    pub score_before: u8,
    pub grade_before: String,
    pub score_after: u8,
    pub grade_after: String,
    pub added_proxies: Vec<ProxyDiffEntry>,
    pub removed_proxies: Vec<String>,
    pub changed_proxies: Vec<ProxyChangeEntry>,
    pub newly_insecure_nodes: Vec<String>,
    pub dns_changed: bool,
    pub dns_changes: Vec<String>,
    pub rules_prev_count: usize,
    pub rules_next_count: usize,
    pub rules_added_count: usize,
    pub rules_removed_count: usize,
    pub rules_added_sample: Vec<String>,
    pub rules_removed_sample: Vec<String>,
}

struct IndexedCompiledRule {
    line_num: usize,
    raw: String,
    compiled: CompiledRule,
}

fn is_loopback_server(server: &str) -> bool {
    let trimmed = server.trim().trim_start_matches('[').trim_end_matches(']');
    if trimmed.eq_ignore_ascii_case("localhost") {
        return true;
    }
    trimmed.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

fn is_non_loopback_listen(listen: &str) -> bool {
    let trimmed = listen.trim();
    if trimmed.is_empty() {
        return false;
    }
    if trimmed.starts_with(':') {
        return false;
    }
    if let Ok(sa) = trimmed.parse::<std::net::SocketAddr>() {
        return !sa.ip().is_loopback();
    }
    if let Some((host, _port)) = trimmed.rsplit_once(':') {
        return !is_loopback_server(host);
    }
    !is_loopback_server(trimmed)
}

fn node_tls_and_skip_verify(node: &ProxyNodeConfig) -> (bool, bool, bool) {
    match node {
        ProxyNodeConfig::Ss { .. } => (true, false, false),
        ProxyNodeConfig::Anytls {
            skip_cert_verify, ..
        } => (true, *skip_cert_verify, false),
        ProxyNodeConfig::Trojan {
            tls,
            skip_cert_verify,
            ..
        } => (*tls, *skip_cert_verify, !*tls),
        ProxyNodeConfig::Vless {
            tls,
            encryption,
            skip_cert_verify,
            ..
        } => {
            let has_pq_or_enc =
                !encryption.trim().is_empty() && !encryption.trim().eq_ignore_ascii_case("none");
            let encrypted = *tls || has_pq_or_enc;
            (encrypted, *skip_cert_verify && *tls, !encrypted)
        }
        ProxyNodeConfig::Socks5 {
            tls,
            skip_cert_verify,
            ..
        }
        | ProxyNodeConfig::Http {
            tls,
            skip_cert_verify,
            ..
        } => (*tls, *skip_cert_verify && *tls, !*tls),
    }
}

fn node_udp_enabled(node: &ProxyNodeConfig) -> bool {
    match node {
        ProxyNodeConfig::Ss { udp, .. }
        | ProxyNodeConfig::Vless { udp, .. }
        | ProxyNodeConfig::Anytls { udp, .. }
        | ProxyNodeConfig::Trojan { udp, .. }
        | ProxyNodeConfig::Socks5 { udp, .. } => *udp,
        ProxyNodeConfig::Http { .. } => false,
    }
}

fn summarize_proxy_diff_entry(node: &ProxyNodeConfig) -> ProxyDiffEntry {
    let (server, port) = node.server_port();
    let (encrypted, skip_cert_verify, _) = node_tls_and_skip_verify(node);
    ProxyDiffEntry {
        name: node.name().to_string(),
        protocol: node.protocol_label().to_string(),
        server: server.to_string(),
        port,
        tls: encrypted,
        skip_cert_verify,
        udp: node_udp_enabled(node),
    }
}

fn credentials_differ(a: &ProxyNodeConfig, b: &ProxyNodeConfig) -> bool {
    match (a, b) {
        (ProxyNodeConfig::Ss { password: pa, .. }, ProxyNodeConfig::Ss { password: pb, .. })
        | (
            ProxyNodeConfig::Anytls { password: pa, .. },
            ProxyNodeConfig::Anytls { password: pb, .. },
        )
        | (
            ProxyNodeConfig::Trojan { password: pa, .. },
            ProxyNodeConfig::Trojan { password: pb, .. },
        ) => pa != pb,
        (
            ProxyNodeConfig::Vless {
                uuid: ua,
                encryption: ea,
                ..
            },
            ProxyNodeConfig::Vless {
                uuid: ub,
                encryption: eb,
                ..
            },
        ) => ua != ub || ea != eb,
        (
            ProxyNodeConfig::Socks5 {
                username: ua,
                password: pa,
                ..
            },
            ProxyNodeConfig::Socks5 {
                username: ub,
                password: pb,
                ..
            },
        )
        | (
            ProxyNodeConfig::Http {
                username: ua,
                password: pa,
                ..
            },
            ProxyNodeConfig::Http {
                username: ub,
                password: pb,
                ..
            },
        ) => ua != ub || pa != pb,
        _ => true,
    }
}

fn domain_matches_suffix(domain: &str, suffix: &str) -> bool {
    domain.eq_ignore_ascii_case(suffix)
        || (domain.len() > suffix.len()
            && domain.to_ascii_lowercase().ends_with(suffix)
            && domain.as_bytes()[domain.len() - suffix.len() - 1] == b'.')
}

fn net_contains_net(outer: &IpNet, inner: &IpNet) -> bool {
    match (outer, inner) {
        (IpNet::V4(o), IpNet::V4(i)) => o.contains(i),
        (IpNet::V6(o), IpNet::V6(i)) => o.contains(i),
        _ => false,
    }
}

fn resolve_static_chain(
    start: &str,
    concrete_nodes: &HashMap<&str, &ProxyNodeConfig>,
    groups: &HashMap<&str, &ProxyGroupConfig>,
) -> (String, String, Vec<String>) {
    let mut visited = HashSet::with_capacity(8);
    let mut chain = Vec::with_capacity(4);
    let mut cur = start.to_string();

    for _ in 0..16 {
        if !visited.insert(cur.clone()) {
            chain.push("ROUTING-ERROR".to_string());
            chain.reverse();
            return ("ROUTING-ERROR".to_string(), "REJECT".to_string(), chain);
        }
        chain.push(cur.clone());
        if cur == "DIRECT" {
            chain.reverse();
            return ("DIRECT".to_string(), "DIRECT".to_string(), chain);
        }
        if cur == "REJECT" {
            chain.reverse();
            return ("REJECT".to_string(), "REJECT".to_string(), chain);
        }
        if let Some(node) = concrete_nodes.get(cur.as_str()) {
            chain.reverse();
            return (node.name().to_string(), "PROXY".to_string(), chain);
        }
        if cur == "GLOBAL" {
            if let Some(first_grp) = groups.values().next() {
                cur = first_grp.name.clone();
                continue;
            }
            if let Some(first_node) = concrete_nodes.values().next() {
                cur = first_node.name().to_string();
                continue;
            }
            cur = "DIRECT".to_string();
            continue;
        }
        if let Some(grp) = groups.get(cur.as_str()) {
            if let Some(first_member) = grp.proxies.first() {
                cur = first_member.clone();
                continue;
            }
            chain.push("DIRECT".to_string());
            chain.reverse();
            return ("DIRECT".to_string(), "DIRECT".to_string(), chain);
        }
        chain.push("ROUTING-ERROR".to_string());
        chain.reverse();
        return ("ROUTING-ERROR".to_string(), "REJECT".to_string(), chain);
    }

    chain.push("ROUTING-ERROR".to_string());
    chain.reverse();
    ("ROUTING-ERROR".to_string(), "REJECT".to_string(), chain)
}

fn grade_for_score(score: u8) -> &'static str {
    match score {
        92..=100 => "A",
        80..=91 => "B",
        65..=79 => "C",
        50..=64 => "D",
        _ => "F",
    }
}

/// Run static security, rule-compiler shadowing, and offline split-DNS route simulation against `cfg`.
/// Guaranteed offline (0 network packets) and strictly redacted (0 credentials in output).
pub fn audit_config(cfg: &ClashConfig) -> ConfigAuditReport {
    audit_config_with_router(cfg, None)
}

/// Run config security & rule-compiler audit using live `Router` group selections (`Selector` `now`,
/// `URLTest`/`Fallback` lowest-RTT winners, active `RunMode`, and loaded GeoIP/RuleSets) when provided,
/// without emitting unsolicited DNS queries.
pub fn audit_config_with_router(cfg: &ClashConfig, router: Option<&Router>) -> ConfigAuditReport {
    audit_config_inner(cfg, router, None)
}

/// Run config audit against a live `Router`, optionally resolving unmatched domain IPs via configured
/// `dns.nameserver` (`resolve_dns = true`) to verify `GEOIP` / `IP-CIDR` rules dynamically.
pub async fn audit_config_live(
    cfg: &ClashConfig,
    router: &Router,
    resolve_dns: bool,
) -> ConfigAuditReport {
    if !resolve_dns {
        return audit_config_inner(cfg, Some(router), None);
    }
    let mut precomputed = HashMap::new();
    for (_, _, raw_target) in SIM_SPECS {
        if let Ok(target) = raw_target.parse::<TargetAddr>() {
            let preview = router.preview_route_with_dns(&target).await;
            precomputed.insert(raw_target, preview);
        }
    }
    audit_config_inner(cfg, Some(router), Some(precomputed))
}

const SIM_SPECS: [(&str, &str, &str); 7] = [
    ("Private LAN Gateway", "private-lan", "192.168.1.1:443"),
    (
        "Domestic Gov / Banking",
        "cn-sensitive",
        "www.icbc.com.cn:443",
    ),
    ("Domestic CN Portal", "cn-web", "www.baidu.com:443"),
    ("GitHub Developer", "intl-dev", "github.com:443"),
    ("OpenAI API", "ai-api", "api.openai.com:443"),
    ("Anthropic Claude API", "ai-api", "api.anthropic.com:443"),
    (
        "Google Gemini API",
        "ai-api",
        "generativelanguage.googleapis.com:443",
    ),
];

fn audit_config_inner(
    cfg: &ClashConfig,
    router: Option<&Router>,
    live_dns_previews: Option<HashMap<&'static str, RouteSimulationPreview>>,
) -> ConfigAuditReport {
    let mut findings: Vec<AuditFinding> = Vec::new();
    let effective_mode = router.map(|r| r.mode()).unwrap_or(cfg.mode);

    // 1. Outbound Node Security Checks (`SEC-*`)
    for node in &cfg.proxies {
        let name = node.name();
        let (server, port) = node.server_port();
        let (_, skip_cert_verify, is_plaintext) = node_tls_and_skip_verify(node);

        if skip_cert_verify {
            findings.push(AuditFinding {
                code: "SEC-TLS-SKIP-VERIFY".to_string(),
                severity: AuditSeverity::High,
                category: "Outbound TLS".to_string(),
                title: format!("Proxy node '{name}' disables TLS certificate verification"),
                location: format!("proxies[{name}] ({server}:{port})"),
                detail: format!(
                    "Node '{name}' ({}) sets `skip-cert-verify: true`, allowing an on-path attacker or rogue gateway to intercept tunnel traffic via a forged certificate.",
                    node.protocol_label()
                ),
                remediation: "Set `skip-cert-verify: false` and configure a valid `sni`/`servername` matching a CA-issued certificate.".to_string(),
            });
        }

        if is_plaintext && !is_loopback_server(server) {
            findings.push(AuditFinding {
                code: "SEC-PLAINTEXT-NODE".to_string(),
                severity: AuditSeverity::High,
                category: "Outbound Transport".to_string(),
                title: format!("Proxy node '{name}' transmits unencrypted traffic over WAN"),
                location: format!("proxies[{name}] ({server}:{port})"),
                detail: format!(
                    "Node '{name}' ({}) targets non-loopback server '{server}:{port}' without TLS or Post-Quantum/AEAD tunnel encryption.",
                    node.protocol_label()
                ),
                remediation: "Enable `tls: true` (or use SS-2022, Trojan, AnyTLS v2, or VLESS `mlkem768x25519plus` encryption) for non-loopback nodes.".to_string(),
            });
        }
    }

    // 2. Controller & Inbound Exposure Checks (`SEC-*`)
    let has_secret = cfg.secret.as_ref().is_some_and(|s| !s.trim().is_empty());
    if is_non_loopback_listen(&cfg.external_controller) && !has_secret {
        findings.push(AuditFinding {
            code: "SEC-CONTROLLER-NO-SECRET".to_string(),
            severity: AuditSeverity::High,
            category: "Control Plane".to_string(),
            title: "External controller bound to non-loopback address without `secret`".to_string(),
            location: format!("external-controller ({})", cfg.external_controller),
            detail: format!(
                "`external-controller` is set to '{}' without a Bearer `secret`. While rust-clash fails closed (HTTP 403) for remote peers without a secret, explicit controller secrets should always be configured.",
                cfg.external_controller
            ),
            remediation: "Bind `external-controller` to `127.0.0.1:9090` or configure a strong random `secret`.".to_string(),
        });
    }

    let exposed_inbound = cfg.allow_lan
        || cfg.bind_address.trim() == "*"
        || cfg.bind_address.trim() == "0.0.0.0"
        || cfg.bind_address.trim() == "::";
    if exposed_inbound && cfg.authentication.is_empty() {
        findings.push(AuditFinding {
            code: "SEC-ALLOW-LAN-UNAUTHENTICATED".to_string(),
            severity: AuditSeverity::Medium,
            category: "Inbound Access".to_string(),
            title: "LAN proxy inbound enabled without `authentication` credentials".to_string(),
            location: format!(
                "allow-lan={} / bind-address={}",
                cfg.allow_lan, cfg.bind_address
            ),
            detail: "Any device on the local network segment (or allowed CIDR) can route traffic through `mixed-port` without HTTP/SOCKS5 credentials.".to_string(),
            remediation: "Set `allow-lan: false` when not sharing on LAN, or add `authentication: [\"user:strong-pass\"]` and `lan-allowed-ips`.".to_string(),
        });
    }

    // 3. DNS Posture Checks (`DNS-*`)
    let enhanced_lc = cfg.dns.enhanced_mode.trim().to_ascii_lowercase();
    let is_fake_ip = enhanced_lc == "fake-ip";
    let parsed_upstreams: Vec<DnsUpstream> = cfg
        .dns
        .nameserver
        .iter()
        .chain(cfg.dns.proxy_server_nameserver.iter())
        .chain(cfg.dns.fallback.iter())
        .chain(cfg.dns.nameserver_policy.values().flatten())
        .chain(cfg.dns.proxy_server_nameserver_policy.values().flatten())
        .filter(|s| !s.trim().is_empty())
        .filter_map(|s| DnsUpstream::parse(s).ok())
        .collect();
    let has_encrypted_dns = parsed_upstreams
        .iter()
        .any(|u| matches!(u, DnsUpstream::Https { .. } | DnsUpstream::Tls { .. }));
    let all_upstreams_encrypted = cfg.dns.enable
        && !parsed_upstreams.is_empty()
        && parsed_upstreams
            .iter()
            .all(|u| matches!(u, DnsUpstream::Https { .. } | DnsUpstream::Tls { .. }));

    if !cfg.dns.enable && effective_mode == RunMode::Rule {
        findings.push(AuditFinding {
            code: "DNS-DISABLED-IN-RULE-MODE".to_string(),
            severity: AuditSeverity::Medium,
            category: "DNS Privacy".to_string(),
            title: "DNS engine is disabled (`dns.enable: false`) in `rule` mode".to_string(),
            location: "dns.enable".to_string(),
            detail: "Disabling the built-in DNS engine prevents Fake-IP mapping and split-DNS anti-leak protection during TUN or system DNS takeover.".to_string(),
            remediation: "Set `dns.enable: true` and `dns.enhanced-mode: fake-ip`.".to_string(),
        });
    } else if cfg.dns.enable && !has_encrypted_dns {
        let sev = if is_fake_ip {
            AuditSeverity::Low
        } else {
            AuditSeverity::Medium
        };
        findings.push(AuditFinding {
            code: "DNS-NO-ENCRYPTED-UPSTREAM".to_string(),
            severity: sev,
            category: "DNS Privacy".to_string(),
            title: "No encrypted DoH/DoT upstream configured in `dns.nameserver`".to_string(),
            location: "dns.nameserver".to_string(),
            detail: if is_fake_ip {
                "All configured `dns.nameserver` entries use UDP/TCP `:53`. Fake-IP still shields proxied domains over SOCKS5/TUN, but local real-IP rule resolution uses plaintext DNS.".to_string()
            } else {
                "Plaintext `:53` nameservers without `fake-ip` expose queried domains to ISP DNS inspection and poisoning.".to_string()
            },
            remediation: "Add an encrypted DoH/DoT resolver (e.g. `https://dns.alidns.com/dns-query` or `https://cloudflare-dns.com/dns-query`) alongside `default-nameserver` bootstrap IPs.".to_string(),
        });
    }

    // 4. Compile Rules for Static Linter (`Clippy for Clash`) + Offline Fallback Simulation
    let dummy_mmdb = {
        let blob = build_synthetic_country_mmdb(&[]);
        MmdbReader::from_bytes(blob).ok().map(Arc::new)
    };
    let compiled_rule_sets =
        build_rule_sets_with_state_dir(&cfg.rule_providers, dummy_mmdb.as_ref(), None).ok();

    let mut indexed_rules: Vec<IndexedCompiledRule> = Vec::new();
    for (i, raw_line) in cfg.rules.iter().enumerate() {
        let trimmed = raw_line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        match CompiledRule::parse_with_context(
            trimmed,
            dummy_mmdb.as_ref(),
            compiled_rule_sets.as_ref(),
        ) {
            Ok(compiled) => indexed_rules.push(IndexedCompiledRule {
                line_num: i + 1,
                raw: redact_sensitive_text(trimmed),
                compiled,
            }),
            Err(err) => {
                findings.push(AuditFinding {
                    code: "RULE-PARSE-ERROR".to_string(),
                    severity: AuditSeverity::High,
                    category: "Rule Compiler".to_string(),
                    title: format!("Invalid routing rule at rules[{}]", i + 1),
                    location: format!("rules[{}]", i + 1),
                    detail: redact_sensitive_text(&err.to_string()),
                    remediation: "Fix or remove the malformed rule entry.".to_string(),
                });
            }
        }
    }

    // 4a. Unreachable after `MATCH`, missing `MATCH`, implicit DNS resolve (`no-resolve`), and shadowing
    let first_match_pos = indexed_rules
        .iter()
        .position(|r| matches!(r.compiled.matcher, RuleMatcher::Match));

    if effective_mode == RunMode::Rule && !indexed_rules.is_empty() && first_match_pos.is_none() {
        findings.push(AuditFinding {
            code: "RULE-MISSING-MATCH".to_string(),
            severity: AuditSeverity::Medium,
            category: "Rule Compiler".to_string(),
            title: "Rule list has no terminal `MATCH` fallback rule".to_string(),
            location: "rules (end)".to_string(),
            detail: "Without a final `MATCH,<PROXY|DIRECT>` rule, rust-clash fails closed (`ImplicitReject`) and drops any unmatched destination.".to_string(),
            remediation: "Append `MATCH,PROXY` (or `MATCH,DIRECT`) as the last rule.".to_string(),
        });
    }

    if let Some(m_pos) = first_match_pos
        && m_pos + 1 < indexed_rules.len()
    {
        let dead_count = indexed_rules.len() - (m_pos + 1);
        let first_dead = &indexed_rules[m_pos + 1];
        let match_rule = &indexed_rules[m_pos];
        findings.push(AuditFinding {
            code: "RULE-DEAD-AFTER-MATCH".to_string(),
            severity: AuditSeverity::Medium,
            category: "Rule Compiler".to_string(),
            title: format!(
                "{dead_count} unreachable dead rule(s) placed after `{}`",
                match_rule.raw
            ),
            location: format!(
                "rules[{}] (after rules[{}])",
                first_dead.line_num, match_rule.line_num
            ),
            detail: format!(
                "Rule `{}` (and {} subsequent rule(s)) can never execute because `MATCH` at rules[{}] unconditionally matches every packet first.",
                first_dead.raw,
                dead_count.saturating_sub(1),
                match_rule.line_num
            ),
            remediation: "Move specific rules above the final `MATCH` rule or delete obsolete trailing rules.".to_string(),
        });
    }

    let active_slice_end = first_match_pos
        .map(|p| p + 1)
        .unwrap_or(indexed_rules.len());
    let active_rules = &indexed_rules[..active_slice_end];

    // Check implicit DNS resolution (`IP-CIDR` / `GEOIP` / `RULE-SET` without `no-resolve`)
    let mut implicit_resolve_rules: Vec<(usize, String)> = Vec::new();
    for r in active_rules {
        if r.compiled.requires_ip_resolution() {
            implicit_resolve_rules.push((r.line_num, r.raw.clone()));
        }
    }
    if !implicit_resolve_rules.is_empty() {
        let count = implicit_resolve_rules.len();
        let sample: Vec<String> = implicit_resolve_rules
            .iter()
            .take(3)
            .map(|(ln, raw)| format!("rules[{ln}] `{raw}`"))
            .collect();
        let (sev, title, detail) = if all_upstreams_encrypted {
            (
                AuditSeverity::Medium,
                format!(
                    "{count} IP/GeoIP rule(s) omit `no-resolve`, causing pre-route DoH/DoT lookup latency"
                ),
                format!(
                    "{} forces `Router` to resolve unmatched domains via configured DoH/DoT `dns.nameserver` before tunnel dial — avoiding plaintext `:53` DNS, but adding 20–200ms pre-routing RTT and exposing queried hostnames to the upstream DoH/DoT resolver.",
                    sample.join(", ")
                ),
            )
        } else {
            (
                AuditSeverity::High,
                format!(
                    "{count} IP/GeoIP rule(s) omit `no-resolve` with plaintext `:53` DNS upstream"
                ),
                format!(
                    "{} triggers `dns.nameserver` resolution (which includes plaintext UDP/TCP `:53`) for unmatched domains before `MATCH` — causing plaintext DNS exposure and 20–200ms pre-routing latency.",
                    sample.join(", ")
                ),
            )
        };
        findings.push(AuditFinding {
            code: "DNS-IMPLICIT-RESOLVE".to_string(),
            severity: sev,
            category: "DNS Privacy & Latency".to_string(),
            title,
            location: format!("rules[{}]", implicit_resolve_rules[0].0),
            detail,
            remediation: "Append `,no-resolve` to `IP-CIDR`, `IP-CIDR6`, and `GEOIP` rules (e.g. `GEOIP,CN,DIRECT,no-resolve`) and rely on `GEOSITE` for domain split-tunneling.".to_string(),
        });
    }

    // Check duplicate & shadowed rules across `active_rules`
    let mut seen_exact_keys: HashMap<String, (usize, String)> = HashMap::new();
    let mut prior_suffixes: Vec<(String, usize, String)> = Vec::new();
    let mut prior_keywords: Vec<(String, usize, String)> = Vec::new();
    let mut prior_cidrs: Vec<(IpNet, bool, usize, String)> = Vec::new();
    let mut duplicate_count = 0usize;
    let mut shadowed_domain_count = 0usize;
    let mut shadowed_cidr_count = 0usize;

    for r in active_rules {
        let exact_key = match &r.compiled.matcher {
            RuleMatcher::Domain(d) => Some(format!("DOMAIN:{d}")),
            RuleMatcher::DomainSuffix(s) => Some(format!("DOMAIN-SUFFIX:{s}")),
            RuleMatcher::DomainKeyword(k) => Some(format!("DOMAIN-KEYWORD:{k}")),
            RuleMatcher::DomainRegex { raw, .. } => Some(format!("DOMAIN-REGEX:{raw}")),
            RuleMatcher::GeoSite { category, .. } => {
                Some(format!("GEOSITE:{}", category.to_ascii_lowercase()))
            }
            RuleMatcher::RuleSet { provider_name, .. } => Some(format!("RULE-SET:{provider_name}")),
            RuleMatcher::ProcessName(p) => Some(format!("PROCESS-NAME:{}", p.to_ascii_lowercase())),
            RuleMatcher::ProcessPath(p) => Some(format!("PROCESS-PATH:{p}")),
            RuleMatcher::IpCidr { net, .. } => Some(format!("IP-CIDR:{net}")),
            RuleMatcher::SrcIpCidr(net) => Some(format!("SRC-IP-CIDR:{net}")),
            RuleMatcher::DstPort { raw, .. } => Some(format!("DST-PORT:{raw}")),
            RuleMatcher::SrcPort { raw, .. } => Some(format!("SRC-PORT:{raw}")),
            RuleMatcher::Network(net) => Some(format!("NETWORK:{net:?}")),
            RuleMatcher::GeoIp { code, .. } => Some(format!("GEOIP:{code}")),
            RuleMatcher::Match => None,
        };

        if let Some(key) = exact_key {
            if let Some((prev_ln, prev_raw)) = seen_exact_keys.get(&key) {
                duplicate_count += 1;
                if duplicate_count <= 4 {
                    findings.push(AuditFinding {
                        code: "RULE-DUPLICATE".to_string(),
                        severity: AuditSeverity::Low,
                        category: "Rule Compiler".to_string(),
                        title: format!("Duplicate rule at rules[{}] is never reached", r.line_num),
                        location: format!("rules[{}] (duplicates rules[{prev_ln}])", r.line_num),
                        detail: format!(
                            "`{}` has the exact same matcher as earlier `{prev_raw}` at rules[{prev_ln}].",
                            r.raw
                        ),
                        remediation: format!("Remove the redundant rule at rules[{}].", r.line_num),
                    });
                }
                continue;
            }
            seen_exact_keys.insert(key, (r.line_num, r.raw.clone()));
        }

        match &r.compiled.matcher {
            RuleMatcher::Domain(dom) => {
                let shadowed_by = prior_suffixes
                    .iter()
                    .find(|(suf, _, _)| domain_matches_suffix(dom, suf))
                    .map(|(_, ln, raw)| (*ln, raw.clone()))
                    .or_else(|| {
                        prior_keywords
                            .iter()
                            .find(|(kw, _, _)| dom.contains(kw.as_str()))
                            .map(|(_, ln, raw)| (*ln, raw.clone()))
                    });
                if let Some((prev_ln, prev_raw)) = shadowed_by {
                    shadowed_domain_count += 1;
                    if shadowed_domain_count <= 4 {
                        findings.push(AuditFinding {
                            code: "RULE-SHADOWED-DOMAIN".to_string(),
                            severity: AuditSeverity::Medium,
                            category: "Rule Compiler".to_string(),
                            title: format!(
                                "Specific domain rule `{}` is shadowed by broader earlier rule",
                                r.raw
                            ),
                            location: format!(
                                "rules[{}] (shadowed by rules[{prev_ln}])",
                                r.line_num
                            ),
                            detail: format!(
                                "`{}` can never take effect because broader rule `{prev_raw}` at rules[{prev_ln}] matches '{dom}' first.",
                                r.raw
                            ),
                            remediation: format!(
                                "Move `{}` above rules[{prev_ln}] if it is intended as a specific override.",
                                r.raw
                            ),
                        });
                    }
                }
            }
            RuleMatcher::DomainSuffix(suf) => {
                let shadowed_by = prior_suffixes
                    .iter()
                    .find(|(prev_suf, _, _)| domain_matches_suffix(suf, prev_suf))
                    .map(|(_, ln, raw)| (*ln, raw.clone()))
                    .or_else(|| {
                        prior_keywords
                            .iter()
                            .find(|(kw, _, _)| suf.contains(kw.as_str()))
                            .map(|(_, ln, raw)| (*ln, raw.clone()))
                    });
                if let Some((prev_ln, prev_raw)) = shadowed_by {
                    shadowed_domain_count += 1;
                    if shadowed_domain_count <= 4 {
                        findings.push(AuditFinding {
                            code: "RULE-SHADOWED-DOMAIN".to_string(),
                            severity: AuditSeverity::Medium,
                            category: "Rule Compiler".to_string(),
                            title: format!(
                                "Domain suffix rule `{}` is shadowed by broader earlier rule",
                                r.raw
                            ),
                            location: format!(
                                "rules[{}] (shadowed by rules[{prev_ln}])",
                                r.line_num
                            ),
                            detail: format!(
                                "Every host matching `DOMAIN-SUFFIX,{suf}` already matches `{prev_raw}` at rules[{prev_ln}].",
                            ),
                            remediation: format!(
                                "Place narrower suffix `{}` before `{prev_raw}` (rules[{prev_ln}]).",
                                r.raw
                            ),
                        });
                    }
                }
                prior_suffixes.push((suf.clone(), r.line_num, r.raw.clone()));
            }
            RuleMatcher::DomainKeyword(kw) => {
                if let Some((_, prev_ln, prev_raw)) = prior_keywords
                    .iter()
                    .find(|(prev_kw, _, _)| kw.contains(prev_kw.as_str()))
                {
                    shadowed_domain_count += 1;
                    if shadowed_domain_count <= 4 {
                        findings.push(AuditFinding {
                            code: "RULE-SHADOWED-DOMAIN".to_string(),
                            severity: AuditSeverity::Medium,
                            category: "Rule Compiler".to_string(),
                            title: format!(
                                "Keyword rule `{}` is shadowed by shorter keyword rule",
                                r.raw
                            ),
                            location: format!(
                                "rules[{}] (shadowed by rules[{prev_ln}])",
                                r.line_num
                            ),
                            detail: format!(
                                "Any domain containing '{kw}' already contains the earlier keyword in `{prev_raw}` at rules[{prev_ln}].",
                            ),
                            remediation: format!(
                                "Place more specific keyword `{}` above rules[{prev_ln}].",
                                r.raw
                            ),
                        });
                    }
                }
                prior_keywords.push((kw.clone(), r.line_num, r.raw.clone()));
            }
            RuleMatcher::IpCidr { net, no_resolve } => {
                if let Some((_, _, prev_ln, prev_raw)) =
                    prior_cidrs.iter().find(|(prev_net, prev_nr, _, _)| {
                        net_contains_net(prev_net, net) && (!*prev_nr || *no_resolve)
                    })
                {
                    shadowed_cidr_count += 1;
                    if shadowed_cidr_count <= 4 {
                        findings.push(AuditFinding {
                            code: "RULE-SHADOWED-CIDR".to_string(),
                            severity: AuditSeverity::Medium,
                            category: "Rule Compiler".to_string(),
                            title: format!(
                                "Subnet rule `{}` is shadowed by broader supernet",
                                r.raw
                            ),
                            location: format!(
                                "rules[{}] (shadowed by rules[{prev_ln}])",
                                r.line_num
                            ),
                            detail: format!(
                                "Subnet `{net}` is completely contained inside earlier `{prev_raw}` at rules[{prev_ln}].",
                            ),
                            remediation: format!(
                                "Move narrower subnet `{}` above rules[{prev_ln}].",
                                r.raw
                            ),
                        });
                    }
                }
                prior_cidrs.push((*net, *no_resolve, r.line_num, r.raw.clone()));
            }
            _ => {}
        }
    }

    // 5. Split-Tunnel & DNS Route Simulation Matrix
    let simulation_basis = if live_dns_previews.is_some() {
        "live_router_with_dns".to_string()
    } else if router.is_some() {
        "live_router_selection".to_string()
    } else {
        "static_first_member_estimate".to_string()
    };

    let concrete_map: HashMap<&str, &ProxyNodeConfig> =
        cfg.proxies.iter().map(|n| (n.name(), n)).collect();
    let group_map: HashMap<&str, &ProxyGroupConfig> = cfg
        .proxy_groups
        .iter()
        .map(|g| (g.name.as_str(), g))
        .collect();

    let has_remote_proxies = cfg
        .proxies
        .iter()
        .any(|p| !is_loopback_server(p.server_port().0));
    let mut leak_matrix = Vec::with_capacity(SIM_SPECS.len());

    for (label, category, raw_target) in SIM_SPECS {
        let Ok(target) = raw_target.parse::<TargetAddr>() else {
            continue;
        };
        let is_domain = target.host.as_domain().is_some();

        let (
            matched_rule_label,
            effective_outbound,
            exit_type,
            chains,
            triggered_dns_rule,
            ip_rules_skipped_without_dns,
        ) = if let Some(preview) = live_dns_previews
            .as_ref()
            .and_then(|m| m.get(raw_target))
            .cloned()
            .or_else(|| router.map(|r| r.preview_route_no_dns(&target)))
        {
            (
                preview.matched_rule,
                preview.effective_outbound,
                preview.exit_type,
                preview.chains,
                preview.triggered_dns_rule,
                preview.ip_rules_skipped_without_dns,
            )
        } else {
            let (matched_rule_label, entry_target, triggered_dns_rule) = match effective_mode {
                RunMode::Direct => ("Mode(direct)".to_string(), "DIRECT".to_string(), None),
                RunMode::Global => ("Mode(global)".to_string(), "GLOBAL".to_string(), None),
                RunMode::Rule => {
                    let mut earliest_indexed: Option<usize> = None;
                    if is_domain {
                        for (pos, ir) in indexed_rules.iter().enumerate() {
                            if matches!(
                                ir.compiled.matcher,
                                RuleMatcher::Domain(_) | RuleMatcher::DomainSuffix(_)
                            ) && ir.compiled.matches(None, &target)
                            {
                                earliest_indexed = Some(pos);
                                break;
                            }
                        }
                    }

                    let mut triggered_dns: Option<String> = None;
                    let mut winner_pos: Option<usize> = earliest_indexed;

                    for (pos, ir) in indexed_rules.iter().enumerate() {
                        if winner_pos.is_some_and(|w| pos >= w) {
                            break;
                        }
                        if matches!(
                            ir.compiled.matcher,
                            RuleMatcher::Domain(_) | RuleMatcher::DomainSuffix(_)
                        ) {
                            continue;
                        }
                        if is_domain
                            && ir.compiled.requires_ip_resolution()
                            && triggered_dns.is_none()
                        {
                            triggered_dns = Some(format!("rules[{}] {}", ir.line_num, ir.raw));
                        }
                        if ir.compiled.matches(None, &target) {
                            winner_pos = Some(pos);
                            break;
                        }
                    }

                    if let Some(w) = winner_pos {
                        let ir = &indexed_rules[w];
                        (
                            format!("rules[{}] {}", ir.line_num, ir.raw),
                            ir.compiled.target.clone(),
                            triggered_dns,
                        )
                    } else {
                        (
                            "ImplicitReject (no matching rule)".to_string(),
                            "REJECT".to_string(),
                            triggered_dns,
                        )
                    }
                }
            };

            let skipped_ip_without_dns = is_domain && triggered_dns_rule.is_some();
            let (effective_outbound, exit_type, chains) =
                resolve_static_chain(&entry_target, &concrete_map, &group_map);
            (
                matched_rule_label,
                effective_outbound,
                exit_type,
                chains,
                triggered_dns_rule,
                skipped_ip_without_dns,
            )
        };

        let dns_strategy = if !is_domain {
            "Literal IP (no DNS lookup)".to_string()
        } else if let Some(ref ip_rule) = triggered_dns_rule {
            if all_upstreams_encrypted {
                format!("Pre-route Encrypted DoH/DoT Lookup ({ip_rule})")
            } else {
                format!("Pre-route Plaintext DNS Lookup ({ip_rule})")
            }
        } else if exit_type == "PROXY" {
            if cfg.dns.enable && is_fake_ip {
                "Predicted: Fake-IP + Remote Tunnel DNS".to_string()
            } else {
                "Predicted: Remote Tunnel Hostname Dial (verify client DNS)".to_string()
            }
        } else if exit_type == "DIRECT" {
            if !cfg.dns.direct_nameserver.is_empty() {
                "Direct Domestic Split-DNS (`direct-nameserver`)".to_string()
            } else {
                "Direct Resolver (`nameserver`)".to_string()
            }
        } else {
            "Blocked before connect (`REJECT`)".to_string()
        };

        let (risk_level, mut note) = match category {
            "private-lan" if exit_type == "PROXY" => (
                "high".to_string(),
                "Private RFC1918 LAN traffic is routed into a proxy tunnel instead of DIRECT!"
                    .to_string(),
            ),
            "cn-sensitive" if exit_type == "PROXY" && effective_mode == RunMode::Rule && has_remote_proxies => (
                "warning".to_string(),
                "Domestic banking/gov domain routes through remote proxy in Rule mode; verify subscription rules are not hijacking CN traffic."
                    .to_string(),
            ),
            "intl-dev" | "ai-api" if triggered_dns_rule.is_some() => (
                "warning".to_string(),
                if all_upstreams_encrypted {
                    "International/AI domain triggers pre-route DoH/DoT IP lookup before matching; append `,no-resolve` to IP/GeoIP rules to avoid extra RTT and resolver metadata exposure."
                        .to_string()
                } else {
                    "International/AI domain triggers plaintext pre-route DNS lookup before matching; append `,no-resolve` to IP/GeoIP rules."
                        .to_string()
                },
            ),
            "intl-dev" | "ai-api" if exit_type == "DIRECT" && !cfg.proxies.is_empty() && effective_mode != RunMode::Direct => (
                "warning".to_string(),
                "International/AI endpoint exits DIRECT despite configured proxy nodes."
                    .to_string(),
            ),
            _ => (
                "ok".to_string(),
                format!("Predicted route ({simulation_basis}); use Route Explain or Waterfall Probe for live runtime verification."),
            ),
        };

        if ip_rules_skipped_without_dns {
            note.push_str(
                " [Offline preview did not resolve domain IPs for IP/GeoIP rules; run Live DNS Verify to evaluate resolved IPs.]",
            );
        }

        if category == "private-lan" && exit_type == "PROXY" && effective_mode == RunMode::Rule {
            findings.push(AuditFinding {
                code: "RULE-PRIVATE-LAN-HIJACK".to_string(),
                severity: AuditSeverity::High,
                category: "Split-Tunnel Safety".to_string(),
                title: "Private LAN IP (`192.168.1.1`) routes to `PROXY` instead of `DIRECT`".to_string(),
                location: matched_rule_label.clone(),
                detail: format!(
                    "`192.168.1.1:443` matched `{matched_rule_label}` -> `{effective_outbound}` (`PROXY`), which breaks local LAN access and exposes private subnet requests to the proxy server."
                ),
                remediation: "Add `GEOIP,PRIVATE,DIRECT,no-resolve` (or RFC1918 `IP-CIDR` `DIRECT,no-resolve` rules) near the top of `rules`.".to_string(),
            });
        }

        leak_matrix.push(LeakSimulationRow {
            label: label.to_string(),
            category: category.to_string(),
            target: raw_target.to_string(),
            matched_rule: matched_rule_label,
            chains,
            effective_outbound,
            exit_type,
            triggered_local_dns_by_rule: triggered_dns_rule,
            ip_rules_skipped_without_dns,
            dns_strategy,
            risk_level,
            note,
        });
    }

    // Sort findings by severity descending (High -> Medium -> Low -> Info)
    findings.sort_by_key(|a| std::cmp::Reverse(a.severity));

    let mut counts = AuditSeverityCounts::default();
    let mut penalty: u16 = 0;
    for f in &findings {
        match f.severity {
            AuditSeverity::High => {
                counts.high += 1;
                penalty = penalty.saturating_add(22);
            }
            AuditSeverity::Medium => {
                counts.medium += 1;
                penalty = penalty.saturating_add(10);
            }
            AuditSeverity::Low => {
                counts.low += 1;
                penalty = penalty.saturating_add(3);
            }
            AuditSeverity::Info => {
                counts.info += 1;
            }
        }
    }

    let score = 100u8.saturating_sub(penalty.min(100) as u8);
    let grade = grade_for_score(score).to_string();

    ConfigAuditReport {
        score,
        grade,
        mode: effective_mode,
        simulation_basis,
        proxy_count: cfg.proxies.len(),
        group_count: cfg.proxy_groups.len(),
        rule_count: indexed_rules.len(),
        counts,
        findings,
        leak_matrix,
    }
}

/// Compute a strictly credential-redacted security & routing diff between two `ClashConfig` snapshots
/// (designed for subscription refresh inspection and before/after profile comparison).
pub fn diff_configs(prev: &ClashConfig, next: &ClashConfig) -> ConfigDiffSummary {
    let audit_prev = audit_config(prev);
    let audit_next = audit_config(next);

    let prev_map: HashMap<&str, &ProxyNodeConfig> =
        prev.proxies.iter().map(|n| (n.name(), n)).collect();
    let next_map: HashMap<&str, &ProxyNodeConfig> =
        next.proxies.iter().map(|n| (n.name(), n)).collect();

    let mut added_proxies = Vec::new();
    let mut changed_proxies = Vec::new();
    let mut newly_insecure_nodes = Vec::new();

    for node in &next.proxies {
        let name = node.name();
        let (_, next_skip, next_plain) = node_tls_and_skip_verify(node);
        let next_wan_plain = next_plain && !is_loopback_server(node.server_port().0);

        match prev_map.get(name) {
            None => {
                added_proxies.push(summarize_proxy_diff_entry(node));
                if next_skip || next_wan_plain {
                    newly_insecure_nodes.push(name.to_string());
                }
            }
            Some(old_node) => {
                let mut changes = Vec::new();
                if old_node.protocol_label() != node.protocol_label() {
                    changes.push(format!(
                        "protocol: {} -> {}",
                        old_node.protocol_label(),
                        node.protocol_label()
                    ));
                }
                let (old_srv, old_port) = old_node.server_port();
                let (new_srv, new_port) = node.server_port();
                if old_srv != new_srv || old_port != new_port {
                    changes.push(format!(
                        "endpoint: {old_srv}:{old_port} -> {new_srv}:{new_port}"
                    ));
                }
                let (old_enc, old_skip, old_plain) = node_tls_and_skip_verify(old_node);
                let (new_enc, _, _) = node_tls_and_skip_verify(node);
                if old_enc != new_enc {
                    changes.push(format!("encrypted: {old_enc} -> {new_enc}"));
                }
                if old_skip != next_skip {
                    changes.push(format!("skip-cert-verify: {old_skip} -> {next_skip}"));
                }
                if node_udp_enabled(old_node) != node_udp_enabled(node) {
                    changes.push(format!(
                        "udp: {} -> {}",
                        node_udp_enabled(old_node),
                        node_udp_enabled(node)
                    ));
                }
                if credentials_differ(old_node, node) {
                    changes.push("credentials rotated (redacted)".to_string());
                }

                let old_wan_plain = old_plain && !is_loopback_server(old_srv);
                if (!old_skip && next_skip) || (!old_wan_plain && next_wan_plain) {
                    newly_insecure_nodes.push(name.to_string());
                }
                if !changes.is_empty() {
                    changed_proxies.push(ProxyChangeEntry {
                        name: name.to_string(),
                        changes,
                    });
                }
            }
        }
    }

    let mut removed_proxies = Vec::new();
    for old_node in &prev.proxies {
        if !next_map.contains_key(old_node.name()) {
            removed_proxies.push(old_node.name().to_string());
        }
    }

    let mut dns_changes = Vec::new();
    if prev.dns.enable != next.dns.enable {
        dns_changes.push(format!(
            "dns.enable: {} -> {}",
            prev.dns.enable, next.dns.enable
        ));
    }
    if prev.dns.enhanced_mode != next.dns.enhanced_mode {
        dns_changes.push(format!(
            "dns.enhanced-mode: {} -> {}",
            prev.dns.enhanced_mode, next.dns.enhanced_mode
        ));
    }
    if prev.dns.nameserver != next.dns.nameserver {
        dns_changes.push(format!(
            "dns.nameserver: {:?} -> {:?}",
            prev.dns.nameserver, next.dns.nameserver
        ));
    }
    if prev.dns.direct_nameserver != next.dns.direct_nameserver {
        dns_changes.push(format!(
            "dns.direct-nameserver: {:?} -> {:?}",
            prev.dns.direct_nameserver, next.dns.direct_nameserver
        ));
    }
    if prev.dns.fallback != next.dns.fallback {
        dns_changes.push(format!(
            "dns.fallback: {:?} -> {:?}",
            prev.dns.fallback, next.dns.fallback
        ));
    }
    if prev.dns.proxy_server_nameserver != next.dns.proxy_server_nameserver {
        dns_changes.push(format!(
            "dns.proxy-server-nameserver: {:?} -> {:?}",
            prev.dns.proxy_server_nameserver, next.dns.proxy_server_nameserver
        ));
    }
    if prev.dns.nameserver_policy != next.dns.nameserver_policy {
        dns_changes.push(format!(
            "dns.nameserver-policy: {} rule(s) -> {} rule(s)",
            prev.dns.nameserver_policy.len(),
            next.dns.nameserver_policy.len()
        ));
    }
    if prev.dns_with_merged_hosts().hosts != next.dns_with_merged_hosts().hosts {
        dns_changes.push(format!(
            "hosts: {} entry(s) -> {} entry(s)",
            prev.dns_with_merged_hosts().hosts.len(),
            next.dns_with_merged_hosts().hosts.len()
        ));
    }

    let prev_rules: Vec<String> = prev
        .rules
        .iter()
        .map(|r| r.trim())
        .filter(|r| !r.is_empty() && !r.starts_with('#'))
        .map(redact_sensitive_text)
        .collect();
    let next_rules: Vec<String> = next
        .rules
        .iter()
        .map(|r| r.trim())
        .filter(|r| !r.is_empty() && !r.starts_with('#'))
        .map(redact_sensitive_text)
        .collect();

    let prev_rule_set: HashSet<&str> = prev_rules.iter().map(String::as_str).collect();
    let next_rule_set: HashSet<&str> = next_rules.iter().map(String::as_str).collect();

    let added_rules_all: Vec<String> = next_rules
        .iter()
        .filter(|r| !prev_rule_set.contains(r.as_str()))
        .cloned()
        .collect();
    let removed_rules_all: Vec<String> = prev_rules
        .iter()
        .filter(|r| !next_rule_set.contains(r.as_str()))
        .cloned()
        .collect();

    ConfigDiffSummary {
        score_before: audit_prev.score,
        grade_before: audit_prev.grade,
        score_after: audit_next.score,
        grade_after: audit_next.grade,
        added_proxies,
        removed_proxies,
        changed_proxies,
        newly_insecure_nodes,
        dns_changed: !dns_changes.is_empty(),
        dns_changes,
        rules_prev_count: prev_rules.len(),
        rules_next_count: next_rules.len(),
        rules_added_count: added_rules_all.len(),
        rules_removed_count: removed_rules_all.len(),
        rules_added_sample: added_rules_all.into_iter().take(10).collect(),
        rules_removed_sample: removed_rules_all.into_iter().take(10).collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starter_config_passes_high_security_audit_without_critical_issues() {
        let cfg = ClashConfig::from_yaml_str(&ClashConfig::default_starter_yaml()).unwrap();
        let report = audit_config(&cfg);
        assert_eq!(report.counts.high, 0);
        assert_eq!(report.counts.medium, 0);
        assert!(report.score >= 95, "expected A grade, got {}", report.score);
        assert_eq!(report.grade, "A");

        let lan_row = report
            .leak_matrix
            .iter()
            .find(|r| r.category == "private-lan")
            .unwrap();
        assert_eq!(lan_row.exit_type, "DIRECT");
        assert_eq!(lan_row.risk_level, "ok");
    }

    #[test]
    fn detects_skip_cert_verify_shadowing_dead_rules_implicit_dns_and_lan_hijack() {
        let yaml = r#"
mixed-port: 7890
allow-lan: true
external-controller: 0.0.0.0:9090
mode: rule
proxies:
  - name: Rogue-Trojan
    type: trojan
    server: edge.example.net
    port: 443
    password: ultra-secret-trojan-pass-9999
    skip-cert-verify: true
  - name: Plain-SOCKS
    type: socks5
    server: 198.51.100.42
    port: 1080
    username: alice
    password: super-secret-socks-password
    tls: false
proxy-groups:
  - name: PROXY
    type: select
    proxies:
      - Rogue-Trojan
      - Plain-SOCKS
rules:
  - DOMAIN-SUFFIX,example.com,PROXY
  - DOMAIN,api.example.com,DIRECT
  - DOMAIN-KEYWORD,google,PROXY
  - DOMAIN-SUFFIX,googleapis.com,DIRECT
  - IP-CIDR,10.0.0.0/8,DIRECT,no-resolve
  - IP-CIDR,10.1.0.0/16,PROXY,no-resolve
  - GEOIP,CN,DIRECT
  - MATCH,PROXY
  - DOMAIN,dead-after-match.example.org,DIRECT
"#;
        let cfg = ClashConfig::from_yaml_str(yaml).unwrap();
        let report = audit_config(&cfg);
        let serialized = serde_json::to_string(&report).unwrap();

        // Strictly zero secret leakage
        assert!(!serialized.contains("ultra-secret-trojan-pass-9999"));
        assert!(!serialized.contains("super-secret-socks-password"));

        let codes: HashSet<&str> = report.findings.iter().map(|f| f.code.as_str()).collect();
        assert!(codes.contains("SEC-TLS-SKIP-VERIFY"));
        assert!(codes.contains("SEC-PLAINTEXT-NODE"));
        assert!(codes.contains("SEC-CONTROLLER-NO-SECRET"));
        assert!(codes.contains("SEC-ALLOW-LAN-UNAUTHENTICATED"));
        assert!(codes.contains("DNS-IMPLICIT-RESOLVE"));
        assert!(codes.contains("RULE-SHADOWED-DOMAIN"));
        assert!(codes.contains("RULE-SHADOWED-CIDR"));
        assert!(codes.contains("RULE-DEAD-AFTER-MATCH"));
        assert!(codes.contains("RULE-PRIVATE-LAN-HIJACK"));
        assert!(report.score < 50);
        assert_eq!(report.grade, "F");
    }

    #[test]
    fn config_diff_redacts_secrets_and_flags_newly_insecure_nodes() {
        let prev = ClashConfig::from_yaml_str(
            r#"
proxies:
  - name: HK-Node
    type: trojan
    server: hk1.example.com
    port: 443
    password: old-secret-password-1111
    skip-cert-verify: false
proxy-groups:
  - name: PROXY
    type: select
    proxies: [HK-Node, DIRECT]
rules:
  - GEOIP,PRIVATE,DIRECT,no-resolve
  - MATCH,PROXY
"#,
        )
        .unwrap();

        let next = ClashConfig::from_yaml_str(
            r#"
proxies:
  - name: HK-Node
    type: trojan
    server: hk2.example.com
    port: 8443
    password: new-secret-password-2222
    skip-cert-verify: true
  - name: US-New
    type: socks5
    server: 203.0.113.9
    port: 1080
    password: socks-secret-password-3333
    tls: false
proxy-groups:
  - name: PROXY
    type: select
    proxies: [HK-Node, US-New, DIRECT]
rules:
  - MATCH,PROXY
"#,
        )
        .unwrap();

        let diff = diff_configs(&prev, &next);
        let json = serde_json::to_string(&diff).unwrap();
        assert!(!json.contains("old-secret-password-1111"));
        assert!(!json.contains("new-secret-password-2222"));
        assert!(!json.contains("socks-secret-password-3333"));

        assert_eq!(diff.added_proxies.len(), 1);
        assert_eq!(diff.added_proxies[0].name, "US-New");
        assert_eq!(diff.changed_proxies.len(), 1);
        assert_eq!(diff.changed_proxies[0].name, "HK-Node");
        assert!(diff.newly_insecure_nodes.contains(&"HK-Node".to_string()));
        assert!(diff.newly_insecure_nodes.contains(&"US-New".to_string()));
        assert!(diff.score_after < diff.score_before);
    }

    #[test]
    fn live_router_audit_reflects_manual_selection_and_separates_doh_vs_plaintext_no_resolve() {
        let doh_yaml = r#"
mode: rule
dns:
  enable: true
  enhanced-mode: fake-ip
  nameserver:
    - https://cloudflare-dns.com/dns-query
  default-nameserver:
    - 1.1.1.1:53
proxies:
  - name: HK-Node
    type: trojan
    server: hk.example.com
    port: 443
    password: redacted-test-password-0001
    skip-cert-verify: false
proxy-groups:
  - name: PROXY
    type: select
    proxies: [DIRECT, HK-Node]
rules:
  - IP-CIDR,192.168.0.0/16,DIRECT,no-resolve
  - GEOIP,CN,DIRECT
  - MATCH,PROXY
"#;
        let cfg = ClashConfig::from_yaml_str(doh_yaml).unwrap();

        // 1. Offline static audit uses first listed member (`DIRECT`) and marks DoH `DNS-IMPLICIT-RESOLVE` as Medium
        let static_rep = audit_config(&cfg);
        assert_eq!(static_rep.simulation_basis, "static_first_member_estimate");
        let static_openai = static_rep
            .leak_matrix
            .iter()
            .find(|r| r.target == "api.openai.com:443")
            .unwrap();
        assert_eq!(static_openai.effective_outbound, "DIRECT");
        assert!(static_openai.ip_rules_skipped_without_dns);
        let doh_finding = static_rep
            .findings
            .iter()
            .find(|f| f.code == "DNS-IMPLICIT-RESOLVE")
            .unwrap();
        assert_eq!(doh_finding.severity, AuditSeverity::Medium);

        // 2. Live Router after selecting `HK-Node` accurately reflects `HK-Node` instead of first member `DIRECT`!
        let router = crate::engine::ProxyEngine::build_standalone_router(&cfg).unwrap();
        router.select_group("PROXY", "HK-Node").unwrap();
        let live_rep = audit_config_with_router(&cfg, Some(&router));
        assert_eq!(live_rep.simulation_basis, "live_router_selection");
        let live_openai = live_rep
            .leak_matrix
            .iter()
            .find(|r| r.target == "api.openai.com:443")
            .unwrap();
        assert_eq!(live_openai.effective_outbound, "HK-Node");
        assert_eq!(live_openai.exit_type, "PROXY");

        // 3. Plaintext `:53` nameserver elevates missing `no-resolve` to High severity
        let mut plain_cfg = cfg.clone();
        plain_cfg.dns.nameserver = vec!["223.5.5.5:53".to_string()];
        let plain_rep = audit_config(&plain_cfg);
        let plain_finding = plain_rep
            .findings
            .iter()
            .find(|f| f.code == "DNS-IMPLICIT-RESOLVE")
            .unwrap();
        assert_eq!(plain_finding.severity, AuditSeverity::High);
    }
}

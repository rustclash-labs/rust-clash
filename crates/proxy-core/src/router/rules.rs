use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use ipnet::IpNet;
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::{
    addr::TargetAddr,
    error::{ProxyError, Result},
    platform::process::{SocketTransport, find_local_process},
    router::{
        geodata::{current_geodata, matches_geoip_dynamic, matches_geosite_dynamic},
        geoip_data::{GeoIpMatcher, lookup_builtin_geoip},
        geosite_data::{GeoSiteMatcher, lookup_builtin_geosite},
        mmdb::MmdbReader,
        ruleset::RuleSetMatcher,
    },
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RuleSnapshot {
    #[serde(rename = "type")]
    pub rule_type: String,
    pub payload: String,
    pub proxy: String,
    pub hits: u64,
}

#[derive(Clone)]
pub enum RuleMatcher {
    Domain(String),
    DomainSuffix(String),
    DomainKeyword(String),
    DomainRegex {
        raw: String,
        regex: Regex,
    },
    GeoSite {
        category: String,
        matcher: &'static GeoSiteMatcher,
    },
    RuleSet {
        provider_name: String,
        matcher: Option<Arc<RuleSetMatcher>>,
        no_resolve: bool,
    },
    ProcessName(String),
    ProcessPath(String),
    IpCidr {
        net: IpNet,
        no_resolve: bool,
    },
    SrcIpCidr(IpNet),
    DstPort {
        raw: String,
        ranges: Vec<(u16, u16)>,
    },
    SrcPort {
        raw: String,
        ranges: Vec<(u16, u16)>,
    },
    Network(SocketTransport),
    GeoIp {
        code: String,
        builtin: Option<&'static GeoIpMatcher>,
        mmdb: Option<Arc<MmdbReader>>,
        no_resolve: bool,
    },
    Match,
}

impl std::fmt::Debug for RuleMatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Domain(s) => f.debug_tuple("Domain").field(s).finish(),
            Self::DomainSuffix(s) => f.debug_tuple("DomainSuffix").field(s).finish(),
            Self::DomainKeyword(s) => f.debug_tuple("DomainKeyword").field(s).finish(),
            Self::DomainRegex { raw, .. } => {
                f.debug_struct("DomainRegex").field("raw", raw).finish()
            }
            Self::GeoSite { category, .. } => f
                .debug_struct("GeoSite")
                .field("category", category)
                .finish(),
            Self::RuleSet {
                provider_name,
                no_resolve,
                ..
            } => f
                .debug_struct("RuleSet")
                .field("provider_name", provider_name)
                .field("no_resolve", no_resolve)
                .finish(),
            Self::ProcessName(p) => f.debug_tuple("ProcessName").field(p).finish(),
            Self::ProcessPath(p) => f.debug_tuple("ProcessPath").field(p).finish(),
            Self::IpCidr { net, no_resolve } => f
                .debug_struct("IpCidr")
                .field("net", net)
                .field("no_resolve", no_resolve)
                .finish(),
            Self::SrcIpCidr(net) => f.debug_tuple("SrcIpCidr").field(net).finish(),
            Self::DstPort { raw, .. } => f.debug_struct("DstPort").field("raw", raw).finish(),
            Self::SrcPort { raw, .. } => f.debug_struct("SrcPort").field("raw", raw).finish(),
            Self::Network(t) => f.debug_tuple("Network").field(t).finish(),
            Self::GeoIp {
                code, no_resolve, ..
            } => f
                .debug_struct("GeoIp")
                .field("code", code)
                .field("no_resolve", no_resolve)
                .finish(),
            Self::Match => write!(f, "Match"),
        }
    }
}

pub struct CompiledRule {
    pub matcher: RuleMatcher,
    pub target: String,
    hits: AtomicU64,
}

fn normalize_builtin_rule_target(raw: &str) -> String {
    if raw.eq_ignore_ascii_case("DIRECT") || raw.eq_ignore_ascii_case("COMPATIBLE") {
        "DIRECT".to_string()
    } else if raw.eq_ignore_ascii_case("REJECT")
        || raw.eq_ignore_ascii_case("REJECT-DROP")
        || raw.eq_ignore_ascii_case("REJECT-TINYGIF")
    {
        "REJECT".to_string()
    } else if raw.eq_ignore_ascii_case("GLOBAL") {
        "GLOBAL".to_string()
    } else {
        raw.to_string()
    }
}

fn parse_ip_net_or_host(raw: &str) -> std::result::Result<IpNet, ipnet::AddrParseError> {
    raw.parse::<IpNet>()
        .or_else(|e| raw.parse::<IpAddr>().map(IpNet::from).map_err(|_| e))
}

impl CompiledRule {
    pub fn parse(line: &str) -> Result<Self> {
        Self::parse_with_context(line, None, None)
    }

    pub fn parse_with_context(
        line: &str,
        mmdb: Option<&Arc<MmdbReader>>,
        rule_sets: Option<&HashMap<String, Arc<RuleSetMatcher>>>,
    ) -> Result<Self> {
        let trimmed = crate::config::uri::trim_bom_and_controls(line);
        let parts: Vec<&str> = trimmed.split(',').map(|s| s.trim()).collect();
        if parts.len() < 2 {
            return Err(ProxyError::Config(format!(
                "invalid rule syntax: '{trimmed}'"
            )));
        }

        let kind = parts[0].to_ascii_uppercase();
        if kind == "MATCH" || kind == "FINAL" {
            let raw_target = if parts.len() >= 3 && parts[1].trim().is_empty() {
                parts[2].trim()
            } else {
                parts[1].trim()
            };
            if raw_target.is_empty() {
                return Err(ProxyError::Config(format!(
                    "rule '{trimmed}' has empty target"
                )));
            }
            return Ok(Self {
                matcher: RuleMatcher::Match,
                target: normalize_builtin_rule_target(raw_target),
                hits: AtomicU64::new(0),
            });
        }

        if parts.len() < 3 {
            return Err(ProxyError::Config(format!(
                "rule '{trimmed}' requires TYPE,PAYLOAD,TARGET"
            )));
        }

        let payload = parts[1].trim();
        let raw_target = parts[2].trim();
        if raw_target.is_empty() {
            return Err(ProxyError::Config(format!(
                "rule '{trimmed}' has empty target"
            )));
        }
        let target = normalize_builtin_rule_target(raw_target);

        let mut no_resolve = false;
        for &opt in &parts[3..] {
            if opt.is_empty() {
                continue;
            }
            if opt.eq_ignore_ascii_case("no-resolve") {
                no_resolve = true;
            } else {
                return Err(ProxyError::Config(format!(
                    "unsupported rule option '{opt}' in '{trimmed}'"
                )));
            }
        }

        let matcher = match kind.as_str() {
            "DOMAIN" => RuleMatcher::Domain(payload.trim_end_matches('.').to_ascii_lowercase()),
            "DOMAIN-SUFFIX" => RuleMatcher::DomainSuffix(
                payload
                    .trim_start_matches('.')
                    .trim_end_matches('.')
                    .to_ascii_lowercase(),
            ),
            "DOMAIN-KEYWORD" => RuleMatcher::DomainKeyword(payload.to_ascii_lowercase()),
            "DOMAIN-REGEX" => {
                let regex = Regex::new(payload).map_err(|e| {
                    ProxyError::Config(format!("invalid DOMAIN-REGEX '{payload}': {e}"))
                })?;
                RuleMatcher::DomainRegex {
                    raw: payload.to_string(),
                    regex,
                }
            }
            "GEOSITE" => {
                let norm_cat = payload.trim().to_ascii_lowercase();
                let Some(gs_matcher) = lookup_builtin_geosite(&norm_cat) else {
                    return Err(ProxyError::Config(format!(
                        "unsupported or unknown GEOSITE category '{payload}' in rule '{trimmed}'"
                    )));
                };
                RuleMatcher::GeoSite {
                    category: norm_cat,
                    matcher: gs_matcher,
                }
            }
            "RULE-SET" => {
                if payload.is_empty() {
                    return Err(ProxyError::Config(format!(
                        "RULE-SET name cannot be empty in '{trimmed}'"
                    )));
                }
                let resolved_matcher = if let Some(sets) = rule_sets {
                    let Some(m) = sets.get(payload) else {
                        return Err(ProxyError::Config(format!(
                            "RULE-SET '{payload}' not found in rule-providers (in rule '{trimmed}')"
                        )));
                    };
                    Some(Arc::clone(m))
                } else {
                    None
                };
                RuleMatcher::RuleSet {
                    provider_name: payload.to_string(),
                    matcher: resolved_matcher,
                    no_resolve,
                }
            }
            "PROCESS-NAME" => {
                if payload.is_empty() {
                    return Err(ProxyError::Config(format!(
                        "PROCESS-NAME cannot be empty in '{trimmed}'"
                    )));
                }
                RuleMatcher::ProcessName(payload.to_string())
            }
            "PROCESS-PATH" => {
                if payload.is_empty() {
                    return Err(ProxyError::Config(format!(
                        "PROCESS-PATH cannot be empty in '{trimmed}'"
                    )));
                }
                RuleMatcher::ProcessPath(payload.to_string())
            }
            "IP-CIDR" | "IP-CIDR6" => {
                let net = parse_ip_net_or_host(payload)
                    .map_err(|e| ProxyError::Config(format!("invalid {kind} '{payload}': {e}")))?;
                RuleMatcher::IpCidr { net, no_resolve }
            }
            "SRC-IP-CIDR" => {
                let net = parse_ip_net_or_host(payload).map_err(|e| {
                    ProxyError::Config(format!("invalid SRC-IP-CIDR '{payload}': {e}"))
                })?;
                RuleMatcher::SrcIpCidr(net)
            }
            "DST-PORT" => {
                let ranges = parse_port_ranges(payload)?;
                RuleMatcher::DstPort {
                    raw: payload.to_string(),
                    ranges,
                }
            }
            "SRC-PORT" => {
                let ranges = parse_port_ranges(payload)?;
                RuleMatcher::SrcPort {
                    raw: payload.to_string(),
                    ranges,
                }
            }
            "NETWORK" => match payload.to_ascii_lowercase().as_str() {
                "tcp" => RuleMatcher::Network(SocketTransport::Tcp),
                "udp" => RuleMatcher::Network(SocketTransport::Udp),
                other => {
                    return Err(ProxyError::Config(format!(
                        "invalid NETWORK '{other}' in '{trimmed}' (expected tcp or udp)"
                    )));
                }
            },
            "GEOIP" => {
                let code = payload.to_ascii_uppercase();
                let builtin = lookup_builtin_geoip(&code);
                let has_any_mmdb = mmdb.is_some() || current_geodata().mmdb.is_some();
                if builtin.is_none() && !has_any_mmdb {
                    return Err(ProxyError::Config(format!(
                        "unsupported or unknown GEOIP code '{code}' in rule '{trimmed}'"
                    )));
                }
                if builtin.is_none() && (code.len() < 2 || code.len() > 16) {
                    return Err(ProxyError::Config(format!(
                        "invalid GEOIP code '{code}' in rule '{trimmed}'"
                    )));
                }
                RuleMatcher::GeoIp {
                    code,
                    builtin,
                    mmdb: mmdb.cloned(),
                    no_resolve,
                }
            }
            other => {
                return Err(ProxyError::Config(format!(
                    "unsupported rule type '{other}' in '{trimmed}'"
                )));
            }
        };

        Ok(Self {
            matcher,
            target,
            hits: AtomicU64::new(0),
        })
    }

    /// Returns `true` if evaluating this rule against a domain target requires resolving
    /// the domain to IP addresses (`IP-CIDR` / `IP-CIDR6` / `GEOIP` / `RULE-SET[ipcidr]` without `no-resolve`).
    pub fn requires_ip_resolution(&self) -> bool {
        match &self.matcher {
            RuleMatcher::IpCidr { no_resolve, .. } | RuleMatcher::GeoIp { no_resolve, .. } => {
                !*no_resolve
            }
            RuleMatcher::RuleSet {
                matcher: Some(m),
                no_resolve,
                ..
            } => m.requires_ip_resolution(*no_resolve),
            _ => false,
        }
    }

    pub fn matches(&self, src_ip: Option<IpAddr>, target: &TargetAddr) -> bool {
        self.matches_with_resolved_ips(src_ip, target, &[])
    }

    pub fn matches_with_resolved_ips(
        &self,
        src_ip: Option<IpAddr>,
        target: &TargetAddr,
        resolved_ips: &[IpAddr],
    ) -> bool {
        self.matches_full(src_ip, None, SocketTransport::Tcp, target, resolved_ips)
    }

    pub fn matches_full(
        &self,
        src_ip: Option<IpAddr>,
        src_addr: Option<SocketAddr>,
        transport: SocketTransport,
        target: &TargetAddr,
        resolved_ips: &[IpAddr],
    ) -> bool {
        match &self.matcher {
            RuleMatcher::Domain(d) => target
                .host
                .as_domain()
                .is_some_and(|host| host.eq_ignore_ascii_case(d)),
            RuleMatcher::DomainSuffix(suffix) => target.host.as_domain().is_some_and(|host| {
                host.eq_ignore_ascii_case(suffix)
                    || (host.len() > suffix.len()
                        && host.to_ascii_lowercase().ends_with(suffix.as_str())
                        && host.as_bytes()[host.len() - suffix.len() - 1] == b'.')
            }),
            RuleMatcher::DomainKeyword(kw) => target
                .host
                .as_domain()
                .is_some_and(|host| host.to_ascii_lowercase().contains(kw.as_str())),
            RuleMatcher::DomainRegex { regex, .. } => target
                .host
                .as_domain()
                .is_some_and(|host| regex.is_match(host)),
            RuleMatcher::GeoSite { category, matcher } => target
                .host
                .as_domain()
                .is_some_and(|host| matches_geosite_dynamic(category, matcher, host)),
            RuleMatcher::RuleSet {
                matcher: Some(m),
                no_resolve,
                ..
            } => m.matches(
                src_ip,
                src_addr,
                transport,
                target,
                resolved_ips,
                *no_resolve,
            ),
            RuleMatcher::RuleSet { matcher: None, .. } => false,
            RuleMatcher::ProcessName(expected_name) => src_addr
                .and_then(|sa| find_local_process(transport, sa))
                .is_some_and(|info| info.matches_name(expected_name)),
            RuleMatcher::ProcessPath(expected_path) => src_addr
                .and_then(|sa| find_local_process(transport, sa))
                .is_some_and(|info| info.matches_path(expected_path)),
            RuleMatcher::IpCidr { net, no_resolve } => {
                if let Some(ip) = target.host.as_ip() {
                    net.contains(&ip)
                } else if !*no_resolve {
                    resolved_ips.iter().any(|ip| net.contains(ip))
                } else {
                    false
                }
            }
            RuleMatcher::SrcIpCidr(net) => src_ip
                .or_else(|| src_addr.map(|sa| sa.ip()))
                .is_some_and(|ip| net.contains(&ip)),
            RuleMatcher::DstPort { ranges, .. } => ranges
                .iter()
                .any(|(lo, hi)| target.port >= *lo && target.port <= *hi),
            RuleMatcher::SrcPort { ranges, .. } => src_addr.is_some_and(|sa| {
                ranges
                    .iter()
                    .any(|(lo, hi)| sa.port() >= *lo && sa.port() <= *hi)
            }),
            RuleMatcher::Network(expected) => transport == *expected,
            RuleMatcher::GeoIp {
                code,
                builtin,
                mmdb,
                no_resolve,
            } => {
                let ip_matches = |ip: IpAddr| -> bool {
                    matches_geoip_dynamic(code, *builtin, mmdb.as_ref(), ip)
                };
                if let Some(ip) = target.host.as_ip() {
                    ip_matches(ip)
                } else if !*no_resolve {
                    resolved_ips.iter().copied().any(ip_matches)
                } else {
                    false
                }
            }
            RuleMatcher::Match => true,
        }
    }

    pub fn record_hit(&self) {
        self.hits.fetch_add(1, Ordering::Relaxed);
    }

    pub fn rule_type_str(&self) -> &'static str {
        match &self.matcher {
            RuleMatcher::Domain(_) => "Domain",
            RuleMatcher::DomainSuffix(_) => "DomainSuffix",
            RuleMatcher::DomainKeyword(_) => "DomainKeyword",
            RuleMatcher::DomainRegex { .. } => "DomainRegex",
            RuleMatcher::GeoSite { .. } => "GeoSite",
            RuleMatcher::RuleSet { .. } => "RuleSet",
            RuleMatcher::ProcessName(_) => "ProcessName",
            RuleMatcher::ProcessPath(_) => "ProcessPath",
            RuleMatcher::IpCidr { .. } => "IPCIDR",
            RuleMatcher::SrcIpCidr(_) => "SrcIPCIDR",
            RuleMatcher::DstPort { .. } => "DstPort",
            RuleMatcher::SrcPort { .. } => "SrcPort",
            RuleMatcher::Network(_) => "Network",
            RuleMatcher::GeoIp { .. } => "GeoIP",
            RuleMatcher::Match => "Match",
        }
    }

    pub fn payload_str(&self) -> String {
        match &self.matcher {
            RuleMatcher::Domain(s)
            | RuleMatcher::DomainSuffix(s)
            | RuleMatcher::DomainKeyword(s)
            | RuleMatcher::ProcessName(s)
            | RuleMatcher::ProcessPath(s) => s.clone(),
            RuleMatcher::DomainRegex { raw, .. } => raw.clone(),
            RuleMatcher::GeoSite { category, .. } => category.clone(),
            RuleMatcher::RuleSet { provider_name, .. } => provider_name.clone(),
            RuleMatcher::IpCidr { net, .. } | RuleMatcher::SrcIpCidr(net) => net.to_string(),
            RuleMatcher::DstPort { raw, .. } | RuleMatcher::SrcPort { raw, .. } => raw.clone(),
            RuleMatcher::Network(SocketTransport::Tcp) => "tcp".to_string(),
            RuleMatcher::Network(SocketTransport::Udp) => "udp".to_string(),
            RuleMatcher::GeoIp { code, .. } => code.clone(),
            RuleMatcher::Match => String::new(),
        }
    }

    pub fn snapshot(&self) -> RuleSnapshot {
        RuleSnapshot {
            rule_type: self.rule_type_str().to_string(),
            payload: self.payload_str(),
            proxy: self.target.clone(),
            hits: self.hits.load(Ordering::Relaxed),
        }
    }
}

fn parse_port_ranges(spec: &str) -> Result<Vec<(u16, u16)>> {
    let mut ranges = Vec::new();
    for token in spec.split('/') {
        let token = token.trim();
        if let Some((a, b)) = token.split_once('-') {
            let lo: u16 = a
                .trim()
                .parse()
                .map_err(|_| ProxyError::Config(format!("invalid port '{a}'")))?;
            let hi: u16 = b
                .trim()
                .parse()
                .map_err(|_| ProxyError::Config(format!("invalid port '{b}'")))?;
            ranges.push((lo.min(hi), lo.max(hi)));
        } else {
            let p: u16 = token
                .parse()
                .map_err(|_| ProxyError::Config(format!("invalid port '{token}'")))?;
            ranges.push((p, p));
        }
    }
    Ok(ranges)
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    #[test]
    fn geoip_cn_excludes_non_cn_apac_allocations_and_rejects_unknown_code() {
        let cn_rule = CompiledRule::parse("GEOIP,CN,DIRECT").unwrap();
        for cn_ip in [
            Ipv4Addr::new(223, 5, 5, 5),
            Ipv4Addr::new(119, 29, 29, 29),
            Ipv4Addr::new(114, 114, 114, 114),
            Ipv4Addr::new(180, 76, 76, 76),
        ] {
            assert!(
                cn_rule.matches(None, &TargetAddr::new_ip(IpAddr::V4(cn_ip), 443)),
                "expected {cn_ip} to match GEOIP,CN"
            );
        }

        for non_cn_ip in [
            Ipv4Addr::new(14, 8, 0, 1),
            Ipv4Addr::new(27, 80, 0, 1),
            Ipv4Addr::new(49, 207, 0, 1),
            Ipv4Addr::new(58, 152, 0, 1),
            Ipv4Addr::new(60, 248, 0, 1),
            Ipv4Addr::new(101, 127, 0, 1),
            Ipv4Addr::new(106, 128, 0, 1),
            Ipv4Addr::new(114, 32, 0, 1),
            Ipv4Addr::new(118, 200, 0, 1),
            Ipv4Addr::new(8, 8, 8, 8),
            Ipv4Addr::new(1, 1, 1, 1),
        ] {
            assert!(
                !cn_rule.matches(None, &TargetAddr::new_ip(IpAddr::V4(non_cn_ip), 443)),
                "expected {non_cn_ip} NOT to match GEOIP,CN"
            );
        }

        assert!(CompiledRule::parse("GEOIP,NONEXISTENT,DIRECT").is_err());
    }
}

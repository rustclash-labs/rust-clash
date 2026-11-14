use std::{
    collections::{HashMap, HashSet},
    fs::{self, OpenOptions},
    io::Write,
    net::IpAddr,
    path::{Path, PathBuf},
    sync::{Arc, Weak},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use parking_lot::{Mutex, RwLock};
use rustls::pki_types::CertificateDer;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio_rustls::TlsConnector;
use url::Url;
use uuid::Uuid;

use crate::{
    addr::TargetAddr,
    config::{
        ClashConfig, ProxyGroupConfig, ProxyGroupType, ProxyNodeConfig, RunMode, SkippedProxyEntry,
        uri::{
            is_proxy_uri_token, parse_subscription_uris, parse_subscription_uris_best_effort,
            proxy_node_dedup_key, redact_sensitive_text, try_decode_base64_uri_list,
        },
    },
    crypto::tls::build_tls_client_config,
    dns::FakeIpDnsEngine,
    engine::build_outbounds,
    error::{ProxyError, Result},
    outbound::DynOutbound,
    platform::{keystore::SecretVault, socket_protect::global_socket_protector},
    router::Router,
};

const INDEX_FILE: &str = "profiles_index.json";
const MAX_SUBSCRIPTION_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProfileKind {
    Starter,
    LocalYaml,
    ShareUris,
    Subscription,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ImportInputKind {
    ShareUris,
    Base64UriList,
    ClashYaml,
    HttpsSubscriptionUrl,
}

impl ImportInputKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ShareUris => "share-uris",
            Self::Base64UriList => "base64-uri-list",
            Self::ClashYaml => "clash-yaml",
            Self::HttpsSubscriptionUrl => "https-subscription-url",
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct NodeMutationReport {
    pub input_kind: Option<ImportInputKind>,
    pub added_nodes: Vec<String>,
    pub updated_node: Option<String>,
    pub removed_nodes: Vec<String>,
    pub skipped_duplicates: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub skipped_unsupported: Vec<SkippedProxyEntry>,
    pub total_nodes: usize,
    pub selected_groups: HashMap<String, String>,
    #[serde(skip)]
    pub config: ClashConfig,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RulePreset {
    /// Managed default split-tunneling template (`GEOSITE,private/cn` + `GEOIP,PRIVATE/CN` -> `DIRECT`, international -> `PROXY`).
    SmartCn,
    /// User-supplied or edited custom rule list (never automatically overwritten).
    Custom,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RoutingPresetChoice {
    /// `mode: rule` + managed `smart-cn` split-tunneling template (国内直连 / 国外代理).
    SmartCn,
    /// `mode: global` (全局代理 — preserves underlying rule list).
    Global,
    /// `mode: direct` (全局直连 — preserves underlying rule list).
    Direct,
    /// `mode: rule` + user custom rules (`custom`).
    Custom,
}

impl RoutingPresetChoice {
    pub fn parse_str(raw: &str) -> Result<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "smart-cn" | "smart_cn" | "smart" | "rule-smart-cn" => Ok(Self::SmartCn),
            "global" => Ok(Self::Global),
            "direct" => Ok(Self::Direct),
            "custom" | "rule" | "rule-custom" => Ok(Self::Custom),
            other => Err(ProxyError::Config(format!(
                "unsupported routing preset '{other}' (expected 'smart-cn', 'global', 'direct', or 'custom')"
            ))),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::SmartCn => "smart-cn",
            Self::Global => "global",
            Self::Direct => "direct",
            Self::Custom => "custom",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RoutingPresetSnapshot {
    pub active_choice: RoutingPresetChoice,
    pub mode: RunMode,
    pub rule_preset: RulePreset,
    pub primary_group: String,
    pub rule_count: usize,
    pub has_custom_rules_backup: bool,
    pub selected_groups: HashMap<String, String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubscriptionUserInfo {
    pub upload_bytes: u64,
    pub download_bytes: u64,
    pub total_bytes: Option<u64>,
    pub expire_unix_secs: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProfileMetadata {
    pub id: String,
    pub name: String,
    pub kind: ProfileKind,
    /// Strictly redacted URL (`https://host/***REDACTED***`) safe for UI, logs, and diagnostics.
    pub subscription_url_redacted: Option<String>,
    pub auto_update_interval_secs: Option<u64>,
    pub last_updated_ms: u64,
    pub last_error: Option<String>,
    pub userinfo: Option<SubscriptionUserInfo>,
    pub proxy_count: usize,
    #[serde(default)]
    pub manual_proxy_count: usize,
    #[serde(default)]
    pub group_count: usize,
    pub rule_count: usize,
    #[serde(default)]
    pub last_skipped_count: usize,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub selected_groups: HashMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_preset: Option<RulePreset>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub custom_rules_backup: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct ProfileSettingsPatch {
    pub name: Option<String>,
    /// `None` = leave unchanged; `Some(None)` or `Some(Some(0))` = disable auto-update; `Some(Some(secs))` = set interval (clamp minimum to 60s).
    #[serde(default, deserialize_with = "deserialize_optional_nullable_u64")]
    pub auto_update_interval_secs: Option<Option<u64>>,
}

fn deserialize_optional_nullable_u64<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<Option<u64>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(Some(Option::<u64>::deserialize(deserializer)?))
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct ManualNodesOverlay {
    #[serde(default)]
    proxies: Vec<ProxyNodeConfig>,
    /// Optional mapping of proxy_name -> list of group names the manual node was attached to
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    group_attachments: HashMap<String, Vec<String>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProfileIndex {
    pub active_profile_id: String,
    #[serde(default)]
    pub onboarding_completed: bool,
    /// Set once `<= v0.3.6` selector defaults that skipped leading `"DIRECT"` / `"REJECT"`
    /// members (e.g. `📺 Bilibili: [DIRECT, 🚀 节点选择, ...]`) have been restored to `proxies[0]`.
    #[serde(default)]
    pub selection_defaults_v2: bool,
    pub profiles: Vec<ProfileMetadata>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ProfilesSnapshot {
    pub active_profile_id: String,
    pub onboarding_completed: bool,
    pub secret_backend: String,
    pub profiles: Vec<ProfileMetadata>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct CreateProfileSpec {
    pub name: String,
    pub yaml: Option<String>,
    pub uris: Option<String>,
    pub subscription_url: Option<String>,
    pub auto_update_interval_secs: Option<u64>,
    #[serde(default = "default_activate_true")]
    pub activate: bool,
}

fn default_activate_true() -> bool {
    true
}

/// Redact subscription URL credentials, query tokens (`?token=...`), and secret path segments.
pub fn redact_subscription_url(raw: &str) -> String {
    let Ok(parsed) = Url::parse(raw.trim()) else {
        return "***REDACTED_URL***".to_string();
    };
    let scheme = parsed.scheme();
    let Some(host) = parsed.host_str() else {
        return "***REDACTED_URL***".to_string();
    };
    let port_suffix = parsed.port().map(|p| format!(":{p}")).unwrap_or_default();
    let has_sensitive_tail =
        parsed.query().is_some() || (parsed.path() != "/" && !parsed.path().is_empty());
    if has_sensitive_tail {
        format!("{scheme}://{host}{port_suffix}/***REDACTED***")
    } else {
        format!("{scheme}://{host}{port_suffix}/")
    }
}

/// Parse standard Clash / SIP008 `Subscription-Userinfo` HTTP header:
/// `upload=1234; download=5678; total=10737418240; expire=1893456000`
pub fn parse_subscription_userinfo(raw_header: &str) -> Option<SubscriptionUserInfo> {
    let mut upload = None;
    let mut download = None;
    let mut total = None;
    let mut expire = None;

    for part in raw_header.split(';') {
        let Some((k, v)) = part.split_once('=') else {
            continue;
        };
        let key = k.trim().to_ascii_lowercase();
        let val = v.trim().parse::<u64>().ok();
        match key.as_str() {
            "upload" => upload = val,
            "download" => download = val,
            "total" => total = val,
            "expire" => expire = val.filter(|&ts| ts > 0),
            _ => {}
        }
    }

    if upload.is_none() && download.is_none() && total.is_none() && expire.is_none() {
        return None;
    }

    Some(SubscriptionUserInfo {
        upload_bytes: upload.unwrap_or(0),
        download_bytes: download.unwrap_or(0),
        total_bytes: total,
        expire_unix_secs: expire,
    })
}

fn trim_bom_and_controls_str(s: &str) -> &str {
    s.trim_matches(|c: char| c == '\u{feff}' || c.is_whitespace() || c.is_control())
}

fn looks_like_clash_yaml(text: &str) -> bool {
    let trimmed = trim_bom_and_controls_str(text);
    if trimmed.contains("proxies:")
        || trimmed.contains("proxy-groups:")
        || trimmed.contains("rules:")
        || trimmed.contains("mixed-port:")
        || trimmed.contains("rule-providers:")
        || trimmed.contains("\"proxies\":")
        || trimmed.contains("\"proxy-groups\":")
    {
        return true;
    }
    trimmed.lines().any(|line| {
        let l = trim_bom_and_controls_str(line);
        l.starts_with("Proxy:")
            || l.starts_with("Proxy Group:")
            || l.starts_with("Rule:")
            || l.starts_with("Rule Provider:")
            || l.starts_with("socks-port:")
    })
}

fn extract_json_panel_error_message(
    obj: &serde_json::Map<String, serde_json::Value>,
) -> Option<String> {
    let is_error_flag = obj.get("status").and_then(|v| v.as_str()).is_some_and(|s| {
        matches!(
            s.trim().to_ascii_lowercase().as_str(),
            "error" | "fail" | "failed" | "false" | "unauthorized" | "forbidden"
        )
    }) || obj.get("success").and_then(|v| v.as_bool()) == Some(false)
        || obj.get("ok").and_then(|v| v.as_bool()) == Some(false)
        || obj.get("ret").and_then(|v| v.as_i64()) == Some(0)
        || obj
            .get("code")
            .and_then(|v| v.as_i64())
            .is_some_and(|c| c != 0 && c != 200);

    let msg_val = obj
        .get("message")
        .or_else(|| obj.get("msg"))
        .or_else(|| obj.get("error"))
        .or_else(|| obj.get("detail"))
        .or_else(|| obj.get("reason"));

    let raw_msg = match msg_val {
        Some(serde_json::Value::String(s)) if !s.trim().is_empty() => Some(s.trim().to_string()),
        Some(serde_json::Value::Object(inner)) => inner
            .get("message")
            .or_else(|| inner.get("msg"))
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToOwned::to_owned),
        _ => None,
    };

    if is_error_flag || (raw_msg.is_some() && obj.len() <= 4 && !obj.contains_key("proxies")) {
        let detail =
            raw_msg.unwrap_or_else(|| "request rejected by subscription panel".to_string());
        let safe = redact_sensitive_text(&detail);
        let bounded: String = safe.chars().take(160).collect();
        return Some(bounded);
    }
    None
}

fn detect_non_proxy_payload_error(text: &str) -> Option<ProxyError> {
    let trimmed = trim_bom_and_controls_str(text);
    if trimmed.is_empty() {
        return None;
    }

    let head_lower: String = trimmed
        .chars()
        .take(1024)
        .collect::<String>()
        .to_ascii_lowercase();
    if head_lower.starts_with("<!doctype html")
        || head_lower.starts_with("<html")
        || head_lower.starts_with("<head")
        || head_lower.starts_with("<body")
        || head_lower.starts_with("<?xml")
        || (head_lower.contains("<html") && head_lower.contains("</html>"))
        || (head_lower.contains("<title>") && head_lower.contains("</title>"))
    {
        if head_lower.contains("cloudflare")
            || head_lower.contains("attention required")
            || head_lower.contains("just a moment")
            || head_lower.contains("cf-ray")
            || head_lower.contains("cf-chl")
        {
            return Some(ProxyError::Config(
                "subscription returned an HTML challenge/error page (Cloudflare protection) instead of proxy nodes; try refreshing over a direct network or pasting Clash YAML / share links directly".into(),
            ));
        }
        return Some(ProxyError::Config(
            "subscription returned an HTML webpage instead of Clash YAML or proxy share links (check whether the subscription URL requires login or has expired)".into(),
        ));
    }

    if trimmed.starts_with('{')
        && let Ok(serde_json::Value::Object(obj)) =
            serde_json::from_str::<serde_json::Value>(trimmed)
    {
        if obj.contains_key("proxies")
            || obj.contains_key("Proxy")
            || obj.contains_key("proxy-groups")
            || obj.contains_key("Proxy Group")
        {
            return None;
        }
        if let Some(panel_msg) = extract_json_panel_error_message(&obj) {
            return Some(ProxyError::Config(format!(
                "subscription panel returned an error: {panel_msg}"
            )));
        }
        if obj.contains_key("outbounds")
            && (obj.contains_key("inbounds")
                || obj.contains_key("route")
                || obj.contains_key("routing"))
        {
            return Some(ProxyError::Config(
                "detected Sing-box / V2Ray JSON config; RustClash expects Clash / Mihomo YAML or share links (ss://, vless://, trojan://, anytls://, socks5://, http://)".into(),
            ));
        }
    }

    None
}

fn extract_clash_deeplink_target(line: &str) -> Option<String> {
    let trimmed = trim_bom_and_controls_str(line);
    if !trimmed.to_ascii_lowercase().starts_with("clash://") {
        return None;
    }
    let parsed = Url::parse(trimmed).ok()?;
    for (k, v) in parsed.query_pairs() {
        let val = trim_bom_and_controls_str(&v);
        if k.eq_ignore_ascii_case("url") && !val.is_empty() {
            return Some(val.to_string());
        }
    }
    None
}

/// Unified input classifier distinguishing Share URIs, Base64 URI lists, Clash YAML, and HTTPS Subscription URLs.
pub fn classify_import_input(raw: &str) -> Result<(ImportInputKind, String)> {
    let trimmed = trim_bom_and_controls_str(raw);
    if trimmed.is_empty() {
        return Err(ProxyError::Config("import input cannot be empty".into()));
    }

    let active_lines: Vec<&str> = trimmed
        .lines()
        .map(trim_bom_and_controls_str)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();

    if active_lines.is_empty() {
        return Err(ProxyError::Config("import input cannot be empty".into()));
    }

    if active_lines.len() == 1 {
        let single = active_lines[0];
        if let Some(extracted_url) = extract_clash_deeplink_target(single) {
            return classify_import_input(&extracted_url);
        }
        let lower = single.to_ascii_lowercase();
        if lower.starts_with("https://") || lower.starts_with("http://") {
            let parsed = Url::parse(single)
                .map_err(|_| ProxyError::Config("invalid subscription URL format".into()))?;
            let host = parsed
                .host_str()
                .ok_or_else(|| ProxyError::Config("subscription URL missing host".into()))?;
            if parsed.scheme().eq_ignore_ascii_case("http") && !is_loopback_host(host) {
                return Err(ProxyError::Config(
                    "cleartext http:// subscriptions are rejected for security; use https://"
                        .into(),
                ));
            }
            return Ok((ImportInputKind::HttpsSubscriptionUrl, single.to_string()));
        }
    }

    if active_lines.iter().all(|l| {
        (l.matches("://").count() == 1 && is_proxy_uri_token(l))
            || l.split_whitespace().all(is_proxy_uri_token)
    }) {
        return Ok((ImportInputKind::ShareUris, trimmed.to_string()));
    }

    if let Some(err) = detect_non_proxy_payload_error(trimmed) {
        return Err(err);
    }

    if let Some(decoded_uris) = try_decode_base64_uri_list(trimmed) {
        return Ok((ImportInputKind::Base64UriList, decoded_uris));
    }

    if looks_like_clash_yaml(trimmed) {
        return Ok((ImportInputKind::ClashYaml, trimmed.to_string()));
    }

    // Also support Base64-encoded Clash YAML payloads (and surface Base64-wrapped panel errors)
    let compact: String = trimmed
        .chars()
        .filter(|c| !c.is_whitespace() && !c.is_control() && *c != '\u{feff}')
        .collect();
    let stripped = compact.trim_end_matches('=');
    if !stripped.is_empty() {
        use base64::{
            Engine,
            engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD},
        };
        if let Some(bytes) = STANDARD_NO_PAD
            .decode(stripped)
            .ok()
            .or_else(|| URL_SAFE_NO_PAD.decode(stripped).ok())
            && let Ok(decoded_str) = String::from_utf8(bytes)
        {
            let clean_decoded = trim_bom_and_controls_str(&decoded_str);
            if let Some(err) = detect_non_proxy_payload_error(clean_decoded) {
                return Err(err);
            }
            if looks_like_clash_yaml(clean_decoded) {
                return Ok((ImportInputKind::ClashYaml, clean_decoded.to_string()));
            }
        }
    }

    Err(ProxyError::Config(
        "unrecognized import format: expected ss://, vless://, trojan://, anytls://, socks5://, or http-proxy:// share link(s), Base64 URI list, Clash YAML, or https:// subscription URL"
            .into(),
    ))
}

/// Compute Clash/Mihomo-compliant `Select` group selections for a `ClashConfig`:
/// - Preserves any valid existing selection in `existing` (including explicit `"DIRECT"` / `"REJECT"`).
/// - Defaults unselected `Select` groups to `g.proxies[0]` (`proxies.first()`), matching standard
///   Clash / Mihomo semantics so policy groups like `📺 Bilibili: [DIRECT, 🚀 节点选择, ...]` or
///   `🛑 AdBlock: [REJECT, DIRECT]` default to `DIRECT` / `REJECT` as authored by the subscription.
pub fn default_selected_groups_for_config(
    cfg: &ClashConfig,
    existing: &HashMap<String, String>,
) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let has_concrete = !cfg.proxies.is_empty();
    let valid_global_targets: HashSet<&str> = cfg
        .proxies
        .iter()
        .map(|p| p.name())
        .chain(cfg.proxy_groups.iter().map(|g| g.name.as_str()))
        .chain(["DIRECT", "REJECT"])
        .collect();

    for g in &cfg.proxy_groups {
        if g.group_type != ProxyGroupType::Select {
            continue;
        }
        if let Some(prev) = existing.get(&g.name)
            && g.proxies.contains(prev)
        {
            out.insert(g.name.clone(), prev.clone());
            continue;
        }
        if let Some(first) = g.proxies.first() {
            out.insert(g.name.clone(), first.clone());
        }
    }

    if let Some(prev_global) = existing.get("GLOBAL")
        && valid_global_targets.contains(prev_global.as_str())
    {
        out.insert("GLOBAL".to_string(), prev_global.clone());
    } else if has_concrete {
        let primary = primary_proxy_group_for_config(cfg);
        if valid_global_targets.contains(primary.as_str()) && primary != "DIRECT" {
            out.insert("GLOBAL".to_string(), primary);
        } else if let Some(first_node) = cfg.proxies.first() {
            out.insert("GLOBAL".to_string(), first_node.name().to_string());
        }
    }

    out
}

/// Determine the primary outbound selector group name for a `ClashConfig`.
pub fn primary_proxy_group_for_config(cfg: &ClashConfig) -> String {
    for preferred in ["PROXY", "🚀 Proxy", "Proxy"] {
        if cfg.proxy_groups.iter().any(|g| g.name == preferred) {
            return preferred.to_string();
        }
    }
    if let Some(sel) = cfg
        .proxy_groups
        .iter()
        .find(|g| g.group_type == ProxyGroupType::Select)
    {
        return sel.name.clone();
    }
    if let Some(first_grp) = cfg.proxy_groups.first() {
        return first_grp.name.clone();
    }
    if !cfg.proxies.is_empty() {
        return "PROXY".to_string();
    }
    "DIRECT".to_string()
}

fn active_trimmed_rules(rules: &[String]) -> Vec<String> {
    rules
        .iter()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty() && !s.starts_with('#'))
        .map(ToOwned::to_owned)
        .collect()
}

/// Check whether `cfg` uses the managed `smart-cn` split-tunneling rule template.
pub fn is_smart_cn_rule_list(cfg: &ClashConfig) -> bool {
    if !cfg.rule_providers.is_empty() {
        return false;
    }
    let active = active_trimmed_rules(&cfg.rules);
    let mut candidates = vec![
        primary_proxy_group_for_config(cfg),
        "PROXY".to_string(),
        "🚀 Proxy".to_string(),
        "DIRECT".to_string(),
    ];
    for g in &cfg.proxy_groups {
        if !candidates.contains(&g.name) {
            candidates.push(g.name.clone());
        }
    }
    candidates
        .into_iter()
        .any(|grp| active == ClashConfig::smart_cn_rules_for_group(&grp))
}

/// Classify a `ClashConfig`'s rule list as either `RulePreset::SmartCn` or `RulePreset::Custom`.
pub fn classify_rule_preset(cfg: &ClashConfig) -> RulePreset {
    if is_smart_cn_rule_list(cfg) {
        RulePreset::SmartCn
    } else {
        RulePreset::Custom
    }
}

/// Detect ONLY untouched legacy minimal starter rule lists from <= v0.2.1 so they can be
/// safely upgraded to `smart-cn` without EVER touching user-customized or subscription rule lists.
fn detect_untouched_legacy_starter_group(cfg: &ClashConfig) -> Option<String> {
    if !cfg.rule_providers.is_empty() {
        return None;
    }
    let active = active_trimmed_rules(&cfg.rules);

    for grp in ["PROXY", "DIRECT", "🚀 Proxy"] {
        let legacy_starter = vec![
            "DOMAIN-SUFFIX,local,DIRECT".to_string(),
            "IP-CIDR,127.0.0.0/8,DIRECT,no-resolve".to_string(),
            "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve".to_string(),
            "IP-CIDR,172.16.0.0/12,DIRECT,no-resolve".to_string(),
            "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve".to_string(),
            format!("MATCH,{grp}"),
        ];
        if active == legacy_starter {
            let effective_grp =
                if grp == "DIRECT" && cfg.proxy_groups.iter().any(|g| g.name == "PROXY") {
                    "PROXY".to_string()
                } else {
                    grp.to_string()
                };
            return Some(effective_grp);
        }

        let legacy_synth = vec![
            "IP-CIDR,127.0.0.0/8,DIRECT,no-resolve".to_string(),
            "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve".to_string(),
            "IP-CIDR,172.16.0.0/12,DIRECT,no-resolve".to_string(),
            "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve".to_string(),
            "GEOIP,CN,DIRECT".to_string(),
            format!("MATCH,{grp}"),
        ];
        if active == legacy_synth {
            return Some(grp.to_string());
        }
    }
    None
}

/// Dry-run validate a `ClashConfig` (including DNS, Outbounds, ProxyGroups, and Rule compilation)
/// so broken profiles can never overwrite working `.yaml` files.
pub fn validate_profile_config(
    cfg: &ClashConfig,
    extra_ca_der: &[CertificateDer<'static>],
) -> Result<(usize, usize)> {
    cfg.validate()?;
    let dns = Arc::new(FakeIpDnsEngine::with_extra_ca(
        &cfg.dns_with_merged_hosts(),
        extra_ca_der,
    )?);
    let outbounds = build_outbounds(&cfg.proxies, extra_ca_der)?;
    let router = Router::with_providers_and_mmdb(
        cfg.mode,
        outbounds,
        &cfg.proxy_groups,
        &cfg.rules,
        &cfg.rule_providers,
        None,
        dns,
    )?;
    Ok((cfg.proxies.len(), router.rules_snapshot().len()))
}

fn build_synthesized_config_from_nodes(mut nodes: Vec<ProxyNodeConfig>) -> Result<ClashConfig> {
    let mut cfg = ClashConfig::from_yaml_str(&ClashConfig::default_starter_yaml())?;
    let mut taken = collect_taken_names(&cfg);
    let mut node_names: Vec<String> = Vec::with_capacity(nodes.len());
    for n in &mut nodes {
        let unique = uniquify_node_name(n.name().trim(), &taken);
        n.set_name(unique.clone());
        taken.insert(unique.clone());
        node_names.push(unique);
    }

    let mut select_members = node_names.clone();
    select_members.push("DIRECT".to_string());

    cfg.proxies = nodes;
    cfg.proxy_groups = vec![
        ProxyGroupConfig {
            name: "🚀 Proxy".to_string(),
            group_type: ProxyGroupType::Select,
            proxies: select_members,
            url: String::new(),
            interval: 300,
            tolerance: 50,
            strategy: None,
        },
        ProxyGroupConfig {
            name: "⚡ Auto-Best".to_string(),
            group_type: ProxyGroupType::UrlTest,
            proxies: if node_names.is_empty() {
                vec!["DIRECT".to_string()]
            } else {
                node_names
            },
            url: "http://www.gstatic.com/generate_204".to_string(),
            interval: 300,
            tolerance: 50,
            strategy: None,
        },
    ];
    cfg.rules = ClashConfig::smart_cn_rules_for_group("🚀 Proxy");
    Ok(cfg)
}

/// Synthesize a complete, validated `ClashConfig` from `ss://`, `vless://`, `trojan://`, `anytls://`,
/// `socks5://`, or `http-proxy://` share URIs (strict mode).
pub fn synthesize_config_from_uris(uris_payload: &str) -> Result<ClashConfig> {
    let nodes: Vec<ProxyNodeConfig> = parse_subscription_uris(uris_payload)?;
    build_synthesized_config_from_nodes(nodes)
}

/// Synthesize a complete, validated `ClashConfig` from share URIs with mixed-subscription sanitization
/// (skipping unsupported/malformed links into `SkippedProxyEntry` when `>= 1` valid node exists).
pub fn synthesize_config_from_uris_sanitized(
    uris_payload: &str,
) -> Result<(ClashConfig, Vec<SkippedProxyEntry>)> {
    let (nodes, skipped) = parse_subscription_uris_best_effort(uris_payload)?;
    let cfg = build_synthesized_config_from_nodes(nodes)?;
    Ok((cfg, skipped))
}

/// Parse a subscription response body as either full Clash Meta YAML or Base64/plain share URIs.
pub fn parse_subscription_payload(
    raw_body: &str,
    extra_ca_der: &[CertificateDer<'static>],
) -> Result<(ClashConfig, String)> {
    let (cfg, yaml, _) = parse_subscription_payload_sanitized(raw_body, extra_ca_der)?;
    Ok((cfg, yaml))
}

/// Parse a subscription response body with mixed-subscription sanitization, skipping unsupported
/// protocol entries when `>= 1` valid node remains and failing closed when `0` valid nodes remain.
pub fn parse_subscription_payload_sanitized(
    raw_body: &str,
    extra_ca_der: &[CertificateDer<'static>],
) -> Result<(ClashConfig, String, Vec<SkippedProxyEntry>)> {
    let (kind, normalized) = classify_import_input(raw_body)?;
    match kind {
        ImportInputKind::ClashYaml => {
            let (mut cfg, skipped) = ClashConfig::from_yaml_str_sanitized(&normalized)?;
            cfg.secret = None;
            cfg.allow_lan = false;
            cfg.bind_address = "127.0.0.1".to_string();
            cfg.lan_allowed_ips.clear();
            cfg.authentication.clear();
            cfg.tun.enable = false;
            cfg.external_controller = crate::config::sanitize_loopback_external_controller(
                &cfg.external_controller,
                cfg.mixed_port,
            );
            if cfg.proxies.is_empty() {
                let detail = if skipped.is_empty() {
                    "subscription Clash YAML contains 0 proxy nodes".to_string()
                } else {
                    format!(
                        "subscription Clash YAML contains 0 supported proxy nodes ({} unsupported/invalid entries skipped)",
                        skipped.len()
                    )
                };
                return Err(ProxyError::Config(detail));
            }
            validate_profile_config(&cfg, extra_ca_der)?;
            let persisted_yaml = cfg.to_yaml_string()?;
            Ok((cfg, persisted_yaml, skipped))
        }
        ImportInputKind::ShareUris | ImportInputKind::Base64UriList => {
            let (mut cfg, skipped) = synthesize_config_from_uris_sanitized(&normalized)?;
            cfg.secret = None;
            cfg.allow_lan = false;
            cfg.bind_address = "127.0.0.1".to_string();
            cfg.lan_allowed_ips.clear();
            cfg.authentication.clear();
            cfg.tun.enable = false;
            cfg.external_controller = crate::config::sanitize_loopback_external_controller(
                &cfg.external_controller,
                cfg.mixed_port,
            );
            validate_profile_config(&cfg, extra_ca_der)?;
            let yaml = cfg.to_yaml_string()?;
            Ok((cfg, yaml, skipped))
        }
        ImportInputKind::HttpsSubscriptionUrl => Err(ProxyError::Config(
            "subscription payload unexpectedly contained another URL instead of nodes or YAML"
                .into(),
        )),
    }
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Persistent Profile & HTTPS Subscription Manager with OS `SecretVault` credential protection
/// and atomic `.bak` rollback on failed updates.
pub struct ProfileManager {
    profiles_dir: PathBuf,
    vault: SecretVault,
    extra_ca_der: Vec<CertificateDer<'static>>,
    index: Mutex<ProfileIndex>,
    last_attempt_ms: Mutex<HashMap<String, u64>>,
    router_slot: RwLock<Option<Weak<RwLock<Arc<Router>>>>>,
}

impl ProfileManager {
    pub fn open_or_init(state_dir: &Path) -> Result<Arc<Self>> {
        Self::open_or_init_with_ca(state_dir, Vec::new())
    }

    pub fn open_or_init_with_ca(
        state_dir: &Path,
        extra_ca_der: Vec<CertificateDer<'static>>,
    ) -> Result<Arc<Self>> {
        let profiles_dir = state_dir.join("profiles");
        fs::create_dir_all(&profiles_dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Err(e) = fs::set_permissions(&profiles_dir, fs::Permissions::from_mode(0o700)) {
                tracing::warn!(
                    "failed setting 0700 permissions on '{}': {e}",
                    profiles_dir.display()
                );
            }
        }

        let vault = SecretVault::new(state_dir);
        let index_path = profiles_dir.join(INDEX_FILE);

        let index = if index_path.exists() {
            let raw = fs::read_to_string(&index_path)?;
            let mut idx = serde_json::from_str::<ProfileIndex>(&raw).map_err(|e| {
                ProxyError::Config(format!(
                    "corrupt profile index '{}': {e}",
                    index_path.display()
                ))
            })?;

            // Non-destructive one-time metadata backfill & untouched starter upgrade:
            // ONLY upgrades untouched <= v0.2.1 minimal starter rule lists; NEVER modifies user custom YAML/rules.
            let mut dirty = false;
            for p in &mut idx.profiles {
                let sanitized = sanitize_profile_id(&p.id);
                let yaml_path = profiles_dir.join(format!("{sanitized}.yaml"));
                let overlay_path = profiles_dir.join(format!("{sanitized}.manual.yaml"));
                let expected_manual = read_manual_overlay_from_path(&overlay_path).proxies.len();
                if p.manual_proxy_count != expected_manual {
                    p.manual_proxy_count = expected_manual;
                    dirty = true;
                }
                if let Ok(mut cfg) = ClashConfig::from_file(&yaml_path) {
                    if p.group_count != cfg.proxy_groups.len() {
                        p.group_count = cfg.proxy_groups.len();
                        dirty = true;
                    }
                    if p.rule_preset == Some(RulePreset::Custom) {
                        continue;
                    }
                    let can_upgrade_legacy =
                        matches!(p.kind, ProfileKind::Starter | ProfileKind::ShareUris)
                            || p.rule_preset == Some(RulePreset::SmartCn);
                    if can_upgrade_legacy
                        && let Some(target_grp) = detect_untouched_legacy_starter_group(&cfg)
                    {
                        cfg.rules = ClashConfig::smart_cn_rules_for_group(&target_grp);
                        if cfg.dns.direct_nameserver.is_empty() {
                            cfg.dns.direct_nameserver =
                                vec!["223.5.5.5:53".to_string(), "119.29.29.29:53".to_string()];
                        }
                        if cfg.dns.nameserver
                            == vec!["1.1.1.1:53".to_string(), "8.8.8.8:53".to_string()]
                        {
                            cfg.dns.nameserver = vec![
                                "223.5.5.5:53".to_string(),
                                "119.29.29.29:53".to_string(),
                                "https://dns.alidns.com/dns-query".to_string(),
                                "1.1.1.1:53".to_string(),
                            ];
                        }
                        if let Ok((_, rule_count)) = validate_profile_config(&cfg, &extra_ca_der)
                            && let Ok(new_yaml) = cfg.to_yaml_string()
                            && write_atomic_with_backup(&yaml_path, &new_yaml).is_ok()
                        {
                            p.rule_count = rule_count;
                            p.group_count = cfg.proxy_groups.len();
                            p.rule_preset = Some(RulePreset::SmartCn);
                            p.selected_groups =
                                default_selected_groups_for_config(&cfg, &p.selected_groups);
                            dirty = true;
                            continue;
                        }
                    }
                    if p.rule_preset.is_some() {
                        continue;
                    }

                    let detected = classify_rule_preset(&cfg);
                    p.rule_preset = Some(detected);
                    if detected == RulePreset::Custom && p.custom_rules_backup.is_empty() {
                        p.custom_rules_backup = cfg.rules.clone();
                    }
                    dirty = true;
                }
            }
            if !idx.selection_defaults_v2 {
                for p in &mut idx.profiles {
                    let sanitized = sanitize_profile_id(&p.id);
                    let yaml_path = profiles_dir.join(format!("{sanitized}.yaml"));
                    if let Ok(cfg) = ClashConfig::from_file(&yaml_path) {
                        for g in &cfg.proxy_groups {
                            if g.group_type != ProxyGroupType::Select {
                                continue;
                            }
                            if let Some(first) = g.proxies.first()
                                && matches!(first.as_str(), "DIRECT" | "REJECT")
                                && let Some(legacy_forced) = g
                                    .proxies
                                    .iter()
                                    .find(|m| m.as_str() != "DIRECT" && m.as_str() != "REJECT")
                                && p.selected_groups.get(&g.name) == Some(legacy_forced)
                            {
                                p.selected_groups.insert(g.name.clone(), first.clone());
                            }
                        }
                    }
                }
                idx.selection_defaults_v2 = true;
                dirty = true;
            }
            if dirty && let Err(e) = save_index_atomic(&index_path, &idx) {
                tracing::warn!(
                    "failed saving migrated profile index '{}': {e}",
                    index_path.display()
                );
            }
            idx
        } else {
            let starter_id = "starter-default".to_string();
            let starter_yaml = ClashConfig::default_starter_yaml();
            let starter_cfg = ClashConfig::from_yaml_str(&starter_yaml)?;
            let (proxy_count, rule_count) = validate_profile_config(&starter_cfg, &extra_ca_der)?;
            write_atomic_with_backup(
                &profiles_dir.join(format!("{starter_id}.yaml")),
                &starter_yaml,
            )?;

            let idx = ProfileIndex {
                active_profile_id: starter_id.clone(),
                onboarding_completed: false,
                selection_defaults_v2: true,
                profiles: vec![ProfileMetadata {
                    id: starter_id,
                    name: "Starter Profile (Smart CN)".to_string(),
                    kind: ProfileKind::Starter,
                    subscription_url_redacted: None,
                    auto_update_interval_secs: None,
                    last_updated_ms: now_unix_ms(),
                    last_error: None,
                    userinfo: None,
                    proxy_count,
                    manual_proxy_count: 0,
                    group_count: starter_cfg.proxy_groups.len(),
                    rule_count,
                    last_skipped_count: 0,
                    selected_groups: default_selected_groups_for_config(
                        &starter_cfg,
                        &HashMap::new(),
                    ),
                    rule_preset: Some(RulePreset::SmartCn),
                    custom_rules_backup: Vec::new(),
                }],
            };
            save_index_atomic(&index_path, &idx)?;
            idx
        };

        Ok(Arc::new(Self {
            profiles_dir,
            vault,
            extra_ca_der,
            index: Mutex::new(index),
            last_attempt_ms: Mutex::new(HashMap::new()),
            router_slot: RwLock::new(None),
        }))
    }

    pub fn attach_router_slot(&self, slot: Weak<RwLock<Arc<Router>>>) {
        *self.router_slot.write() = Some(slot);
    }

    fn fallback_proxy_outbound(&self) -> Option<DynOutbound> {
        let weak = self.router_slot.read().clone()?;
        let slot = weak.upgrade()?;
        let router = Arc::clone(&slot.read());
        router.fallback_proxy_outbound()
    }

    pub fn state_dir(&self) -> PathBuf {
        self.profiles_dir
            .parent()
            .unwrap_or(&self.profiles_dir)
            .to_path_buf()
    }

    pub fn active_profile_id(&self) -> String {
        self.index.lock().active_profile_id.clone()
    }

    pub fn active_selected_groups(&self) -> HashMap<String, String> {
        let idx = self.index.lock();
        idx.profiles
            .iter()
            .find(|p| p.id == idx.active_profile_id)
            .map(|p| p.selected_groups.clone())
            .unwrap_or_default()
    }

    pub fn snapshot(&self) -> ProfilesSnapshot {
        let idx = self.index.lock().clone();
        ProfilesSnapshot {
            active_profile_id: idx.active_profile_id,
            onboarding_completed: idx.onboarding_completed,
            secret_backend: self.vault.backend_name().to_string(),
            profiles: idx.profiles,
        }
    }

    pub fn active_profile_path(&self) -> PathBuf {
        let id = self.index.lock().active_profile_id.clone();
        self.profile_yaml_path(&id)
    }

    pub fn load_active_config(&self) -> Result<(ClashConfig, PathBuf)> {
        let path = self.active_profile_path();
        if !path.exists() {
            let starter = ClashConfig::default_starter_yaml();
            write_atomic_with_backup(&path, &starter)?;
        }
        let cfg = ClashConfig::from_file(&path)?;
        Ok((cfg, path))
    }

    pub fn load_profile_config_by_id(&self, id: &str) -> Option<ClashConfig> {
        let path = self.profile_yaml_path(id);
        ClashConfig::from_file(&path).ok()
    }

    pub fn list_active_nodes_redacted(&self) -> Result<Vec<ProxyNodeConfig>> {
        let (cfg, _) = self.load_active_config()?;
        Ok(cfg
            .proxies
            .iter()
            .map(ProxyNodeConfig::redacted_clone)
            .collect())
    }

    pub fn save_group_selection(&self, group_name: &str, proxy_name: &str) -> Result<()> {
        let (cfg, _) = self.load_active_config()?;
        if group_name == "GLOBAL" {
            let valid = cfg.proxies.iter().any(|p| p.name() == proxy_name)
                || cfg.proxy_groups.iter().any(|g| g.name == proxy_name)
                || matches!(proxy_name, "DIRECT" | "REJECT");
            if !valid {
                return Err(ProxyError::Routing(format!(
                    "proxy '{proxy_name}' is not a valid member of 'GLOBAL'"
                )));
            }
        } else {
            let grp = cfg
                .proxy_groups
                .iter()
                .find(|g| g.name == group_name)
                .ok_or_else(|| {
                    ProxyError::Routing(format!("proxy group '{group_name}' not found"))
                })?;
            if grp.group_type != ProxyGroupType::Select {
                return Err(ProxyError::Routing(format!(
                    "proxy group '{group_name}' is type {:?}, not Selector",
                    grp.group_type
                )));
            }
            if !grp.proxies.iter().any(|m| m == proxy_name) {
                return Err(ProxyError::Routing(format!(
                    "proxy '{proxy_name}' is not a member of group '{group_name}'"
                )));
            }
        }

        let mut idx = self.index.lock();
        let active_id = idx.active_profile_id.clone();
        if let Some(p) = idx.profiles.iter_mut().find(|p| p.id == active_id) {
            p.selected_groups
                .insert(group_name.to_string(), proxy_name.to_string());
        }
        save_index_atomic(&self.profiles_dir.join(INDEX_FILE), &idx)
    }

    pub fn save_active_mode(&self, mode: RunMode) -> Result<()> {
        let (mut cfg, path) = self.load_active_config()?;
        if cfg.mode == mode {
            return Ok(());
        }
        cfg.mode = mode;
        let yaml = cfg.to_yaml_string()?;
        write_atomic_with_backup(&path, &yaml)
    }

    pub fn routing_snapshot(&self) -> Result<RoutingPresetSnapshot> {
        let (cfg, _) = self.load_active_config()?;
        Ok(self.routing_snapshot_for_config(&cfg))
    }

    pub fn routing_snapshot_for_config(&self, cfg: &ClashConfig) -> RoutingPresetSnapshot {
        let idx = self.index.lock();
        let active_meta = idx.profiles.iter().find(|p| p.id == idx.active_profile_id);
        let rule_preset = active_meta
            .and_then(|p| p.rule_preset)
            .unwrap_or_else(|| classify_rule_preset(cfg));
        let has_custom_rules_backup =
            active_meta.is_some_and(|p| !p.custom_rules_backup.is_empty());
        let selected_groups = active_meta
            .map(|p| p.selected_groups.clone())
            .unwrap_or_default();
        let active_choice = match cfg.mode {
            RunMode::Global => RoutingPresetChoice::Global,
            RunMode::Direct => RoutingPresetChoice::Direct,
            RunMode::Rule => match rule_preset {
                RulePreset::SmartCn => RoutingPresetChoice::SmartCn,
                RulePreset::Custom => RoutingPresetChoice::Custom,
            },
        };
        RoutingPresetSnapshot {
            active_choice,
            mode: cfg.mode,
            rule_preset,
            primary_group: primary_proxy_group_for_config(cfg),
            rule_count: active_trimmed_rules(&cfg.rules).len(),
            has_custom_rules_backup,
            selected_groups,
        }
    }

    /// Return the active custom rules list (or the backed-up custom rules when currently on `smart-cn`,
    /// falling back to the active config rules as an editable starting point).
    pub fn custom_rules_snapshot(&self) -> Result<Vec<String>> {
        let (cfg, _) = self.load_active_config()?;
        let (preset_opt, backup) = {
            let idx = self.index.lock();
            let meta = idx.profiles.iter().find(|p| p.id == idx.active_profile_id);
            (
                meta.and_then(|p| p.rule_preset),
                meta.map(|p| p.custom_rules_backup.clone())
                    .unwrap_or_default(),
            )
        };
        let rule_preset = preset_opt.unwrap_or_else(|| classify_rule_preset(&cfg));
        if rule_preset == RulePreset::Custom {
            Ok(cfg.rules)
        } else if !backup.is_empty() {
            Ok(backup)
        } else {
            Ok(cfg.rules)
        }
    }

    /// Switch between the 4 user-facing routing presets (`smart-cn`, `global`, `direct`, `custom`),
    /// backing up any existing custom rules before applying `smart-cn` and restoring them when
    /// switching back to `custom`.
    pub fn apply_routing_preset(
        &self,
        choice: RoutingPresetChoice,
    ) -> Result<(RoutingPresetSnapshot, ClashConfig)> {
        let (mut cfg, path) = self.load_active_config()?;
        let (current_preset, mut backup, prev_sel) = {
            let idx = self.index.lock();
            let meta = idx.profiles.iter().find(|p| p.id == idx.active_profile_id);
            (
                meta.and_then(|p| p.rule_preset)
                    .unwrap_or_else(|| classify_rule_preset(&cfg)),
                meta.map(|p| p.custom_rules_backup.clone())
                    .unwrap_or_default(),
                meta.map(|p| p.selected_groups.clone()).unwrap_or_default(),
            )
        };

        let next_preset = match choice {
            RoutingPresetChoice::SmartCn => {
                if current_preset == RulePreset::Custom && !is_smart_cn_rule_list(&cfg) {
                    backup = cfg.rules.clone();
                }
                if cfg.proxy_groups.is_empty() {
                    let mut proxies: Vec<String> =
                        cfg.proxies.iter().map(|n| n.name().to_string()).collect();
                    proxies.push("DIRECT".to_string());
                    cfg.proxy_groups.push(ProxyGroupConfig {
                        name: "PROXY".to_string(),
                        group_type: ProxyGroupType::Select,
                        proxies,
                        url: "http://www.gstatic.com/generate_204".to_string(),
                        interval: 300,
                        tolerance: 50,
                        strategy: None,
                    });
                }
                let primary = primary_proxy_group_for_config(&cfg);
                cfg.mode = RunMode::Rule;
                cfg.rules = ClashConfig::smart_cn_rules_for_group(&primary);
                if cfg.dns.direct_nameserver.is_empty() {
                    cfg.dns.direct_nameserver =
                        vec!["223.5.5.5:53".to_string(), "119.29.29.29:53".to_string()];
                }
                RulePreset::SmartCn
            }
            RoutingPresetChoice::Global => {
                cfg.mode = RunMode::Global;
                current_preset
            }
            RoutingPresetChoice::Direct => {
                cfg.mode = RunMode::Direct;
                current_preset
            }
            RoutingPresetChoice::Custom => {
                cfg.mode = RunMode::Rule;
                if current_preset == RulePreset::SmartCn && !backup.is_empty() {
                    cfg.rules = backup.clone();
                }
                RulePreset::Custom
            }
        };

        let (proxy_count, rule_count) = validate_profile_config(&cfg, &self.extra_ca_der)
            .map_err(|e| ProxyError::config_clean(redact_sensitive_text(&e.to_string())))?;
        let yaml = cfg.to_yaml_string()?;
        write_atomic_with_backup(&path, &yaml)?;

        let normalized_sel = default_selected_groups_for_config(&cfg, &prev_sel);
        {
            let mut idx = self.index.lock();
            let active_id = idx.active_profile_id.clone();
            if let Some(p) = idx.profiles.iter_mut().find(|p| p.id == active_id) {
                p.proxy_count = proxy_count;
                p.group_count = cfg.proxy_groups.len();
                p.rule_count = rule_count;
                if p.kind != ProfileKind::Subscription {
                    p.last_updated_ms = now_unix_ms();
                }
                p.last_error = None;
                p.rule_preset = Some(next_preset);
                p.custom_rules_backup = backup;
                p.selected_groups = normalized_sel;
            }
            save_index_atomic(&self.profiles_dir.join(INDEX_FILE), &idx)?;
        }

        let snap = self.routing_snapshot()?;
        Ok((snap, cfg))
    }

    /// Replace the active profile's rule list with validated user custom rules (`RulePreset::Custom`).
    pub fn save_custom_rules(
        &self,
        rules: Vec<String>,
    ) -> Result<(RoutingPresetSnapshot, ClashConfig)> {
        let cleaned: Vec<String> = rules
            .into_iter()
            .map(|r| r.trim().to_string())
            .filter(|r| !r.is_empty())
            .collect();
        if cleaned.is_empty() {
            return Err(ProxyError::Config(
                "custom rules list cannot be empty (include at least a final MATCH rule)".into(),
            ));
        }

        let (mut cfg, path) = self.load_active_config()?;
        cfg.mode = RunMode::Rule;
        cfg.rules = cleaned.clone();

        let (proxy_count, rule_count) = validate_profile_config(&cfg, &self.extra_ca_der)
            .map_err(|e| ProxyError::config_clean(redact_sensitive_text(&e.to_string())))?;
        let yaml = cfg.to_yaml_string()?;
        write_atomic_with_backup(&path, &yaml)?;

        {
            let mut idx = self.index.lock();
            let active_id = idx.active_profile_id.clone();
            if let Some(p) = idx.profiles.iter_mut().find(|p| p.id == active_id) {
                p.proxy_count = proxy_count;
                p.group_count = cfg.proxy_groups.len();
                p.rule_count = rule_count;
                if p.kind != ProfileKind::Subscription {
                    p.last_updated_ms = now_unix_ms();
                }
                p.last_error = None;
                p.rule_preset = Some(RulePreset::Custom);
                p.custom_rules_backup = cleaned;
                p.selected_groups = default_selected_groups_for_config(&cfg, &p.selected_groups);
            }
            save_index_atomic(&self.profiles_dir.join(INDEX_FILE), &idx)?;
        }

        let snap = self.routing_snapshot()?;
        Ok((snap, cfg))
    }

    pub fn persist_active_yaml(
        &self,
        cfg: &ClashConfig,
        raw_yaml_override: Option<&str>,
        selections_hint: Option<&HashMap<String, String>>,
    ) -> Result<HashMap<String, String>> {
        let (proxy_count, rule_count) = validate_profile_config(cfg, &self.extra_ca_der)?;
        let yaml = match raw_yaml_override {
            Some(s) => s.to_string(),
            None => cfg.to_yaml_string()?,
        };
        let active_id = self.active_profile_id();
        let path = self.profile_yaml_path(&active_id);
        write_atomic_with_backup(&path, &yaml)?;
        let detected_preset = classify_rule_preset(cfg);

        let mut overlay = self.load_manual_overlay(&active_id);
        if !overlay.proxies.is_empty() {
            let mut synced_proxies = Vec::with_capacity(overlay.proxies.len());
            let mut synced_attachments = HashMap::new();
            for existing_manual in &overlay.proxies {
                if let Some(in_cfg) = cfg
                    .proxies
                    .iter()
                    .find(|n| n.name() == existing_manual.name())
                {
                    let mut updated = in_cfg.clone();
                    updated.restore_credentials_from(existing_manual);
                    let groups = collect_group_attachments_for_node(cfg, updated.name());
                    if !groups.is_empty() {
                        synced_attachments.insert(updated.name().to_string(), groups);
                    }
                    synced_proxies.push(updated);
                }
            }
            overlay.proxies = synced_proxies;
            overlay.group_attachments = synced_attachments;
            self.save_manual_overlay(&active_id, &overlay)?;
        }
        let manual_proxy_count = overlay.proxies.len();

        let mut idx = self.index.lock();
        let mut final_selections = HashMap::new();
        if let Some(p) = idx.profiles.iter_mut().find(|p| p.id == active_id) {
            let mut merged = p.selected_groups.clone();
            if let Some(hint) = selections_hint {
                for (k, v) in hint {
                    merged.insert(k.clone(), v.clone());
                }
            }
            let normalized = default_selected_groups_for_config(cfg, &merged);
            p.selected_groups = normalized.clone();
            p.proxy_count = proxy_count;
            p.group_count = cfg.proxy_groups.len();
            p.manual_proxy_count = manual_proxy_count;
            p.rule_count = rule_count;
            if p.kind != ProfileKind::Subscription {
                p.last_updated_ms = now_unix_ms();
            }
            p.last_error = None;
            p.rule_preset = Some(detected_preset);
            if detected_preset == RulePreset::Custom {
                p.custom_rules_backup = cfg.rules.clone();
            }
            final_selections = normalized;
        }
        if proxy_count > 0 {
            idx.onboarding_completed = true;
        }
        save_index_atomic(&self.profiles_dir.join(INDEX_FILE), &idx)?;
        Ok(final_selections)
    }

    /// Import one or multiple share URIs (or Base64 URI list) into the currently active persistent profile,
    /// skipping unsupported/malformed links when `>= 1` valid node exists, placing concrete nodes BEFORE `DIRECT`,
    /// and automatically switching `Select` groups off `DIRECT`.
    pub fn import_nodes_to_active(
        &self,
        raw_uris_or_b64: &str,
        deduplicate: bool,
        auto_select: bool,
    ) -> Result<NodeMutationReport> {
        let (kind, normalized_payload) = classify_import_input(raw_uris_or_b64)
            .map_err(|e| ProxyError::config_clean(redact_sensitive_text(&e.to_string())))?;
        if !matches!(
            kind,
            ImportInputKind::ShareUris | ImportInputKind::Base64UriList
        ) {
            return Err(ProxyError::Config(format!(
                "expected share link(s) or Base64 URI list, got '{}'",
                kind.as_str()
            )));
        }

        let (parsed_nodes, skipped_unsupported) =
            parse_subscription_uris_best_effort(&normalized_payload)
                .map_err(|e| ProxyError::config_clean(redact_sensitive_text(&e.to_string())))?;

        let (mut cfg, path) = self.load_active_config()?;
        let mut existing_dedup: HashMap<String, String> = cfg
            .proxies
            .iter()
            .map(|n| (proxy_node_dedup_key(n), n.name().to_string()))
            .collect();

        let mut taken_names = collect_taken_names(&cfg);
        let mut added_names = Vec::new();
        let mut skipped_duplicates = 0usize;
        let mut first_matched_existing: Option<String> = None;

        for mut node in parsed_nodes {
            let dkey = proxy_node_dedup_key(&node);
            if deduplicate && let Some(existing_name) = existing_dedup.get(&dkey) {
                skipped_duplicates += 1;
                if first_matched_existing.is_none() {
                    first_matched_existing = Some(existing_name.clone());
                }
                continue;
            }
            let unique_name = uniquify_node_name(node.name().trim(), &taken_names);
            node.set_name(unique_name.clone());
            taken_names.insert(unique_name.clone());
            existing_dedup.insert(dkey, unique_name.clone());
            added_names.push(unique_name);
            cfg.proxies.push(node);
        }

        let preferred_target = added_names.first().cloned().or(first_matched_existing);

        let mut selected_groups = self.active_selected_groups();
        attach_nodes_and_update_selections(
            &mut cfg,
            &added_names,
            &mut selected_groups,
            preferred_target.as_deref(),
            auto_select,
        );

        let (proxy_count, rule_count) = validate_profile_config(&cfg, &self.extra_ca_der)
            .map_err(|e| ProxyError::config_clean(redact_sensitive_text(&e.to_string())))?;
        let yaml = cfg.to_yaml_string()?;
        write_atomic_with_backup(&path, &yaml)?;

        let active_id = self.active_profile_id();
        let mut overlay = self.load_manual_overlay(&active_id);
        for added_name in &added_names {
            if let Some(node_cfg) = cfg.proxies.iter().find(|n| n.name() == added_name) {
                if let Some(existing) = overlay.proxies.iter_mut().find(|n| n.name() == added_name)
                {
                    *existing = node_cfg.clone();
                } else {
                    overlay.proxies.push(node_cfg.clone());
                }
                let groups = collect_group_attachments_for_node(&cfg, added_name);
                if !groups.is_empty() {
                    overlay.group_attachments.insert(added_name.clone(), groups);
                }
            }
        }
        self.save_manual_overlay(&active_id, &overlay)?;
        let manual_proxy_count = overlay.proxies.len();

        {
            let mut idx = self.index.lock();
            if let Some(p) = idx.profiles.iter_mut().find(|p| p.id == active_id) {
                if p.kind == ProfileKind::Starter && proxy_count > 0 {
                    p.kind = ProfileKind::ShareUris;
                }
                p.proxy_count = proxy_count;
                p.group_count = cfg.proxy_groups.len();
                p.manual_proxy_count = manual_proxy_count;
                p.rule_count = rule_count;
                p.last_skipped_count = skipped_unsupported.len();
                // Preserve subscription refresh clock when manually importing nodes onto a Subscription profile!
                if p.kind != ProfileKind::Subscription {
                    p.last_updated_ms = now_unix_ms();
                }
                p.last_error = None;
                p.selected_groups = selected_groups.clone();
            }
            if proxy_count > 0 {
                idx.onboarding_completed = true;
            }
            save_index_atomic(&self.profiles_dir.join(INDEX_FILE), &idx)?;
        }

        Ok(NodeMutationReport {
            input_kind: Some(kind),
            added_nodes: added_names,
            updated_node: None,
            removed_nodes: Vec::new(),
            skipped_duplicates,
            skipped_unsupported,
            total_nodes: cfg.proxies.len(),
            selected_groups,
            config: cfg,
        })
    }

    /// Unified import entrypoint supporting all 4 user input types:
    /// `ShareUris`, `Base64UriList`, `ClashYaml`, and `HttpsSubscriptionUrl`.
    /// Strictly transactional: on any parse, validation, or network error, existing profile files
    /// and selections remain 100% untouched and all secrets/tokens are scrubbed from errors.
    pub async fn import_unified_input(
        &self,
        raw_input: &str,
        profile_name_hint: Option<&str>,
        deduplicate: bool,
        auto_select: bool,
    ) -> Result<NodeMutationReport> {
        self.import_unified_input_with_options(
            raw_input,
            profile_name_hint,
            deduplicate,
            auto_select,
            None,
        )
        .await
    }

    /// Unified import entrypoint with optional explicit subscription `auto_update_interval_secs`
    /// (`Some(0)` disables periodic auto-update, `Some(secs)` clamps to `>= 60s`, `None` uses default `3600s`).
    pub async fn import_unified_input_with_options(
        &self,
        raw_input: &str,
        profile_name_hint: Option<&str>,
        deduplicate: bool,
        auto_select: bool,
        auto_update_interval_secs: Option<u64>,
    ) -> Result<NodeMutationReport> {
        let (kind, normalized) = classify_import_input(raw_input)
            .map_err(|e| ProxyError::config_clean(redact_sensitive_text(&e.to_string())))?;

        match kind {
            ImportInputKind::ShareUris | ImportInputKind::Base64UriList => {
                self.import_nodes_to_active(raw_input, deduplicate, auto_select)
            }
            ImportInputKind::ClashYaml => {
                let (mut cfg, skipped_unsupported) =
                    ClashConfig::from_yaml_str_sanitized(&normalized).map_err(|e| {
                        ProxyError::config_clean(redact_sensitive_text(&e.to_string()))
                    })?;
                // Sanitize external template `tun.enable` so non-Admin cold restarts never fail on Wintun.
                cfg.tun.enable = false;
                let mut skipped_duplicates = 0usize;
                if deduplicate {
                    let (removed, _) = deduplicate_config_in_place(&mut cfg, &mut HashMap::new());
                    skipped_duplicates = removed.len();
                }
                let (proxy_count, rule_count) = validate_profile_config(&cfg, &self.extra_ca_der)
                    .map_err(|e| {
                    ProxyError::config_clean(redact_sensitive_text(&e.to_string()))
                })?;
                let added_nodes: Vec<String> =
                    cfg.proxies.iter().map(|n| n.name().to_string()).collect();

                if let Some(name_hint) = profile_name_hint.map(str::trim).filter(|s| !s.is_empty())
                {
                    let yaml_out = cfg.to_yaml_string()?;
                    let (mut meta, _, _) = self
                        .create_profile_detailed(CreateProfileSpec {
                            name: name_hint.to_string(),
                            yaml: Some(yaml_out),
                            uris: None,
                            subscription_url: None,
                            auto_update_interval_secs: None,
                            activate: true,
                        })
                        .await?;
                    if !skipped_unsupported.is_empty() {
                        meta.last_skipped_count = skipped_unsupported.len();
                        let mut idx = self.index.lock();
                        if let Some(p) = idx.profiles.iter_mut().find(|p| p.id == meta.id) {
                            p.last_skipped_count = skipped_unsupported.len();
                            if let Err(e) =
                                save_index_atomic(&self.profiles_dir.join(INDEX_FILE), &idx)
                            {
                                tracing::warn!("failed saving profile index skipped count: {e}");
                            }
                        }
                    }
                    return Ok(NodeMutationReport {
                        input_kind: Some(ImportInputKind::ClashYaml),
                        added_nodes,
                        updated_node: None,
                        removed_nodes: Vec::new(),
                        skipped_duplicates,
                        skipped_unsupported,
                        total_nodes: cfg.proxies.len(),
                        selected_groups: meta.selected_groups,
                        config: cfg,
                    });
                }

                let active_id = self.active_profile_id();
                let was_empty_starter = {
                    let idx = self.index.lock();
                    idx.profiles
                        .iter()
                        .find(|p| p.id == active_id)
                        .is_some_and(|p| p.proxy_count == 0)
                };
                let prev_sel = if auto_select || was_empty_starter {
                    HashMap::new()
                } else {
                    self.active_selected_groups()
                };
                let selected_groups = default_selected_groups_for_config(&cfg, &prev_sel);
                let detected_preset = classify_rule_preset(&cfg);
                let yaml_out = cfg.to_yaml_string()?;
                let path = self.profile_yaml_path(&active_id);
                write_atomic_with_backup(&path, &yaml_out)?;
                self.save_manual_overlay(&active_id, &ManualNodesOverlay::default())?;

                {
                    let mut idx = self.index.lock();
                    if let Some(p) = idx.profiles.iter_mut().find(|p| p.id == active_id) {
                        if p.kind == ProfileKind::Starter {
                            p.kind = ProfileKind::LocalYaml;
                        }
                        p.proxy_count = proxy_count;
                        p.group_count = cfg.proxy_groups.len();
                        p.manual_proxy_count = 0;
                        p.rule_count = rule_count;
                        p.last_skipped_count = skipped_unsupported.len();
                        p.last_updated_ms = now_unix_ms();
                        p.last_error = None;
                        p.rule_preset = Some(detected_preset);
                        if detected_preset == RulePreset::Custom {
                            p.custom_rules_backup = cfg.rules.clone();
                        }
                        p.selected_groups = selected_groups.clone();
                    }
                    if proxy_count > 0 {
                        idx.onboarding_completed = true;
                    }
                    save_index_atomic(&self.profiles_dir.join(INDEX_FILE), &idx)?;
                }

                Ok(NodeMutationReport {
                    input_kind: Some(ImportInputKind::ClashYaml),
                    added_nodes,
                    updated_node: None,
                    removed_nodes: Vec::new(),
                    skipped_duplicates,
                    skipped_unsupported,
                    total_nodes: cfg.proxies.len(),
                    selected_groups,
                    config: cfg,
                })
            }
            ImportInputKind::HttpsSubscriptionUrl => {
                let sub_name = profile_name_hint
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(ToOwned::to_owned)
                    .unwrap_or_else(|| {
                        Url::parse(&normalized)
                            .ok()
                            .and_then(|u| match u.host() {
                                Some(url::Host::Ipv4(_)) | Some(url::Host::Ipv6(_)) => None,
                                Some(url::Host::Domain(h)) => {
                                    let clean = h.trim_start_matches('[').trim_end_matches(']');
                                    if clean.parse::<IpAddr>().is_ok() {
                                        None
                                    } else {
                                        Some(format!("Sub ({h})"))
                                    }
                                }
                                None => None,
                            })
                            .unwrap_or_else(|| "HTTPS Subscription".to_string())
                    });

                let effective_interval = match auto_update_interval_secs {
                    None => Some(3600),
                    Some(0) => None,
                    Some(secs) => Some(secs.max(60)),
                };

                let (meta, activated_cfg, skipped_unsupported) = self
                    .create_profile_detailed(CreateProfileSpec {
                        name: sub_name,
                        yaml: None,
                        uris: None,
                        subscription_url: Some(normalized.clone()),
                        auto_update_interval_secs: effective_interval,
                        activate: true,
                    })
                    .await
                    .map_err(|e| {
                        let safe = redact_sensitive_text(&e.to_string())
                            .replace(&normalized, "***REDACTED_URL***");
                        ProxyError::config_clean(safe)
                    })?;

                let cfg = activated_cfg.unwrap_or_else(|| self.load_active_config().unwrap().0);
                let added_nodes: Vec<String> =
                    cfg.proxies.iter().map(|n| n.name().to_string()).collect();
                Ok(NodeMutationReport {
                    input_kind: Some(ImportInputKind::HttpsSubscriptionUrl),
                    added_nodes,
                    updated_node: None,
                    removed_nodes: Vec::new(),
                    skipped_duplicates: 0,
                    skipped_unsupported,
                    total_nodes: cfg.proxies.len(),
                    selected_groups: meta.selected_groups,
                    config: cfg,
                })
            }
        }
    }

    /// Add a new node, or edit / rename an existing node (`original_name = Some("OldName")`),
    /// preserving redacted credentials when unchanged and cascading renames across groups, rules, and selections.
    pub fn upsert_node_in_active(
        &self,
        original_name: Option<&str>,
        mut node: ProxyNodeConfig,
        auto_select: bool,
    ) -> Result<NodeMutationReport> {
        let new_name = node.name().trim().to_string();
        if new_name.is_empty() {
            return Err(ProxyError::Config("node name cannot be empty".into()));
        }
        if matches!(
            new_name.to_ascii_uppercase().as_str(),
            "DIRECT" | "REJECT" | "GLOBAL"
        ) {
            return Err(ProxyError::Config(format!(
                "'{new_name}' is a reserved built-in routing name"
            )));
        }
        node.set_name(new_name.clone());

        let (mut cfg, path) = self.load_active_config()?;
        let mut selected_groups = self.active_selected_groups();
        let mut added_nodes = Vec::new();
        let mut updated_node = None;
        let cleaned_orig = original_name
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToOwned::to_owned);

        if let Some(ref orig_raw) = cleaned_orig {
            let pos = cfg
                .proxies
                .iter()
                .position(|p| p.name() == orig_raw)
                .ok_or_else(|| ProxyError::Config(format!("node '{orig_raw}' not found")))?;

            if new_name != *orig_raw {
                let collision = cfg
                    .proxies
                    .iter()
                    .enumerate()
                    .any(|(i, p)| i != pos && p.name() == new_name)
                    || cfg.proxy_groups.iter().any(|g| g.name == new_name);
                if collision {
                    return Err(ProxyError::Config(format!(
                        "another proxy or group named '{new_name}' already exists"
                    )));
                }
            }

            node.restore_credentials_from(&cfg.proxies[pos]);
            cfg.proxies[pos] = node;

            if new_name != *orig_raw {
                cascade_rename_reference(&mut cfg, &mut selected_groups, orig_raw, &new_name);
            }

            attach_nodes_and_update_selections(
                &mut cfg,
                std::slice::from_ref(&new_name),
                &mut selected_groups,
                Some(&new_name),
                auto_select,
            );
            updated_node = Some(new_name.clone());
        } else {
            let taken = collect_taken_names(&cfg);
            if taken.contains(&new_name) {
                return Err(ProxyError::Config(format!(
                    "a proxy or group named '{new_name}' already exists"
                )));
            }
            cfg.proxies.push(node);
            attach_nodes_and_update_selections(
                &mut cfg,
                std::slice::from_ref(&new_name),
                &mut selected_groups,
                Some(&new_name),
                auto_select,
            );
            added_nodes.push(new_name.clone());
        }

        let (proxy_count, rule_count) = validate_profile_config(&cfg, &self.extra_ca_der)
            .map_err(|e| ProxyError::config_clean(redact_sensitive_text(&e.to_string())))?;
        let yaml = cfg.to_yaml_string()?;
        write_atomic_with_backup(&path, &yaml)?;

        let (active_id, is_sub) = {
            let idx = self.index.lock();
            let id = idx.active_profile_id.clone();
            let is_sub = idx
                .profiles
                .iter()
                .find(|p| p.id == id)
                .is_some_and(|p| p.kind == ProfileKind::Subscription);
            (id, is_sub)
        };
        let mut overlay = self.load_manual_overlay(&active_id);
        let should_track_in_overlay = match &cleaned_orig {
            Some(orig_raw) => overlay.proxies.iter().any(|p| p.name() == orig_raw) || is_sub,
            None => true,
        };
        if should_track_in_overlay
            && let Some(saved_node) = cfg.proxies.iter().find(|p| p.name() == new_name)
        {
            if let Some(ref orig_raw) = cleaned_orig {
                overlay.proxies.retain(|p| p.name() != orig_raw);
                overlay.group_attachments.remove(orig_raw);
            }
            if let Some(existing) = overlay.proxies.iter_mut().find(|p| p.name() == new_name) {
                *existing = saved_node.clone();
            } else {
                overlay.proxies.push(saved_node.clone());
            }
            let groups = collect_group_attachments_for_node(&cfg, &new_name);
            if !groups.is_empty() {
                overlay.group_attachments.insert(new_name.clone(), groups);
            }
            self.save_manual_overlay(&active_id, &overlay)?;
        }
        let manual_proxy_count = overlay.proxies.len();

        {
            let mut idx = self.index.lock();
            if let Some(p) = idx.profiles.iter_mut().find(|p| p.id == active_id) {
                if p.kind == ProfileKind::Starter && proxy_count > 0 {
                    p.kind = ProfileKind::LocalYaml;
                }
                p.proxy_count = proxy_count;
                p.group_count = cfg.proxy_groups.len();
                p.manual_proxy_count = manual_proxy_count;
                p.rule_count = rule_count;
                if p.kind != ProfileKind::Subscription {
                    p.last_updated_ms = now_unix_ms();
                }
                p.last_error = None;
                p.selected_groups = selected_groups.clone();
            }
            if proxy_count > 0 {
                idx.onboarding_completed = true;
            }
            save_index_atomic(&self.profiles_dir.join(INDEX_FILE), &idx)?;
        }

        Ok(NodeMutationReport {
            input_kind: None,
            added_nodes,
            updated_node,
            removed_nodes: Vec::new(),
            skipped_duplicates: 0,
            skipped_unsupported: Vec::new(),
            total_nodes: cfg.proxies.len(),
            selected_groups,
            config: cfg,
        })
    }

    pub fn delete_node_from_active(&self, target_name: &str) -> Result<NodeMutationReport> {
        let clean_target = target_name.trim();
        let (mut cfg, path) = self.load_active_config()?;
        let pos = cfg
            .proxies
            .iter()
            .position(|p| p.name() == clean_target)
            .ok_or_else(|| ProxyError::Config(format!("node '{clean_target}' not found")))?;

        for rule_line in &cfg.rules {
            if rule_targets_name(rule_line, clean_target) {
                return Err(ProxyError::Config(format!(
                    "cannot delete node '{clean_target}' because custom rule '{}' directly targets it; update that rule first",
                    rule_line.trim()
                )));
            }
        }

        cfg.proxies.remove(pos);
        for g in &mut cfg.proxy_groups {
            g.proxies.retain(|m| m != clean_target);
            if g.proxies.is_empty() {
                g.proxies.push("DIRECT".to_string());
            }
        }

        let mut prev_sel = self.active_selected_groups();
        prev_sel.retain(|_, v| v != clean_target);
        let selected_groups = default_selected_groups_for_config(&cfg, &prev_sel);

        let (proxy_count, rule_count) = validate_profile_config(&cfg, &self.extra_ca_der)
            .map_err(|e| ProxyError::config_clean(redact_sensitive_text(&e.to_string())))?;
        let yaml = cfg.to_yaml_string()?;
        write_atomic_with_backup(&path, &yaml)?;

        let active_id = self.active_profile_id();
        let mut overlay = self.load_manual_overlay(&active_id);
        let before_len = overlay.proxies.len();
        overlay.proxies.retain(|p| p.name() != clean_target);
        overlay.group_attachments.remove(clean_target);
        if overlay.proxies.len() != before_len {
            self.save_manual_overlay(&active_id, &overlay)?;
        }
        let manual_proxy_count = overlay.proxies.len();

        {
            let mut idx = self.index.lock();
            if let Some(p) = idx.profiles.iter_mut().find(|p| p.id == active_id) {
                p.proxy_count = proxy_count;
                p.group_count = cfg.proxy_groups.len();
                p.manual_proxy_count = manual_proxy_count;
                p.rule_count = rule_count;
                if p.kind != ProfileKind::Subscription {
                    p.last_updated_ms = now_unix_ms();
                }
                p.last_error = None;
                p.selected_groups = selected_groups.clone();
            }
            save_index_atomic(&self.profiles_dir.join(INDEX_FILE), &idx)?;
        }

        Ok(NodeMutationReport {
            input_kind: None,
            added_nodes: Vec::new(),
            updated_node: None,
            removed_nodes: vec![clean_target.to_string()],
            skipped_duplicates: 0,
            skipped_unsupported: Vec::new(),
            total_nodes: cfg.proxies.len(),
            selected_groups,
            config: cfg,
        })
    }

    pub fn deduplicate_active_nodes(&self) -> Result<NodeMutationReport> {
        let (mut cfg, path) = self.load_active_config()?;
        let mut prev_sel = self.active_selected_groups();
        let (removed_nodes, _) = deduplicate_config_in_place(&mut cfg, &mut prev_sel);
        let selected_groups = default_selected_groups_for_config(&cfg, &prev_sel);

        let (proxy_count, rule_count) = validate_profile_config(&cfg, &self.extra_ca_der)
            .map_err(|e| ProxyError::config_clean(redact_sensitive_text(&e.to_string())))?;
        let yaml = cfg.to_yaml_string()?;
        write_atomic_with_backup(&path, &yaml)?;

        let active_id = self.active_profile_id();
        let mut overlay = self.load_manual_overlay(&active_id);
        if !removed_nodes.is_empty() && !overlay.proxies.is_empty() {
            let removed_set: HashSet<&str> = removed_nodes.iter().map(String::as_str).collect();
            overlay.proxies.retain(|p| !removed_set.contains(p.name()));
            overlay
                .group_attachments
                .retain(|k, _| !removed_set.contains(k.as_str()));
            self.save_manual_overlay(&active_id, &overlay)?;
        }
        let manual_proxy_count = overlay.proxies.len();

        {
            let mut idx = self.index.lock();
            if let Some(p) = idx.profiles.iter_mut().find(|p| p.id == active_id) {
                p.proxy_count = proxy_count;
                p.group_count = cfg.proxy_groups.len();
                p.manual_proxy_count = manual_proxy_count;
                p.rule_count = rule_count;
                if p.kind != ProfileKind::Subscription {
                    p.last_updated_ms = now_unix_ms();
                }
                p.last_error = None;
                p.selected_groups = selected_groups.clone();
            }
            save_index_atomic(&self.profiles_dir.join(INDEX_FILE), &idx)?;
        }

        let skipped_duplicates = removed_nodes.len();
        Ok(NodeMutationReport {
            input_kind: None,
            added_nodes: Vec::new(),
            updated_node: None,
            removed_nodes,
            skipped_duplicates,
            skipped_unsupported: Vec::new(),
            total_nodes: cfg.proxies.len(),
            selected_groups,
            config: cfg,
        })
    }

    pub fn load_profile_yaml(&self, id: &str) -> Result<String> {
        let path = self.profile_yaml_path(id);
        if !path.exists() {
            return Err(ProxyError::Config(format!("profile '{id}' not found")));
        }
        Ok(fs::read_to_string(path)?)
    }

    pub fn set_active_profile(&self, id: &str) -> Result<ClashConfig> {
        {
            let idx = self.index.lock();
            if !idx.profiles.iter().any(|p| p.id == id) {
                return Err(ProxyError::Config(format!("profile '{id}' does not exist")));
            }
        }
        let yaml = self.load_profile_yaml(id)?;
        let cfg = ClashConfig::from_yaml_str(&yaml)?;
        validate_profile_config(&cfg, &self.extra_ca_der)?;
        let manual_proxy_count = self.load_manual_overlay(id).proxies.len();

        {
            let mut idx = self.index.lock();
            idx.active_profile_id = id.to_string();
            if let Some(p) = idx.profiles.iter_mut().find(|p| p.id == id) {
                p.group_count = cfg.proxy_groups.len();
                p.manual_proxy_count = manual_proxy_count;
                p.selected_groups = default_selected_groups_for_config(&cfg, &p.selected_groups);
            }
            if !cfg.proxies.is_empty() {
                idx.onboarding_completed = true;
            }
            save_index_atomic(&self.profiles_dir.join(INDEX_FILE), &idx)?;
        }
        Ok(cfg)
    }

    pub fn update_profile_settings(
        &self,
        id: &str,
        patch: ProfileSettingsPatch,
    ) -> Result<ProfileMetadata> {
        let cleaned_name = match patch.name {
            Some(raw) => {
                let trimmed = raw.trim().to_string();
                if trimmed.is_empty() {
                    return Err(ProxyError::Config("profile name cannot be empty".into()));
                }
                Some(trimmed)
            }
            None => None,
        };

        let updated = {
            let mut idx = self.index.lock();
            let p = idx
                .profiles
                .iter_mut()
                .find(|p| p.id == id)
                .ok_or_else(|| ProxyError::Config(format!("profile '{id}' not found")))?;
            if let Some(new_name) = cleaned_name {
                p.name = new_name;
            }
            if let Some(interval_opt) = patch.auto_update_interval_secs {
                p.auto_update_interval_secs = match interval_opt {
                    None | Some(0) => None,
                    Some(secs) => Some(secs.max(60)),
                };
            }
            let cloned = p.clone();
            save_index_atomic(&self.profiles_dir.join(INDEX_FILE), &idx)?;
            cloned
        };
        if patch.auto_update_interval_secs.is_some() {
            self.last_attempt_ms.lock().remove(id);
        }
        Ok(updated)
    }

    pub async fn create_profile(
        &self,
        spec: CreateProfileSpec,
    ) -> Result<(ProfileMetadata, Option<ClashConfig>)> {
        let (meta, cfg, _) = self.create_profile_detailed(spec).await?;
        Ok((meta, cfg))
    }

    pub async fn create_profile_detailed(
        &self,
        spec: CreateProfileSpec,
    ) -> Result<(ProfileMetadata, Option<ClashConfig>, Vec<SkippedProxyEntry>)> {
        let clean_name = spec.name.trim();
        if clean_name.is_empty() {
            return Err(ProxyError::Config("profile name cannot be empty".into()));
        }

        let id = format!("prof-{}", &Uuid::new_v4().simple().to_string()[..12]);
        let fallback_proxy = self.fallback_proxy_outbound();
        let (kind, cfg, yaml_str, redacted_url, userinfo, skipped_unsupported) =
            if let Some(raw_sub_url) = spec.subscription_url.as_deref().map(str::trim)
                && !raw_sub_url.is_empty()
            {
                let (body, uinfo) = fetch_subscription_http_with_proxy(
                    raw_sub_url,
                    &self.extra_ca_der,
                    fallback_proxy.as_ref(),
                )
                .await
                .map_err(|e| {
                    let safe = redact_sensitive_text(&e.to_string())
                        .replace(raw_sub_url, "***REDACTED_URL***");
                    ProxyError::config_clean(safe)
                })?;
                let (parsed_cfg, normalized_yaml, skipped) =
                    parse_subscription_payload_sanitized(&body, &self.extra_ca_der).map_err(
                        |e| ProxyError::config_clean(redact_sensitive_text(&e.to_string())),
                    )?;
                self.vault
                    .put_secret(&Self::sub_vault_key(&id), raw_sub_url)
                    .map_err(ProxyError::Io)?;
                (
                    ProfileKind::Subscription,
                    parsed_cfg,
                    normalized_yaml,
                    Some(redact_subscription_url(raw_sub_url)),
                    uinfo,
                    skipped,
                )
            } else if let Some(raw_uris) = spec.uris.as_deref().map(str::trim)
                && !raw_uris.is_empty()
            {
                let (parsed_cfg, skipped) = synthesize_config_from_uris_sanitized(raw_uris)
                    .map_err(|e| ProxyError::config_clean(redact_sensitive_text(&e.to_string())))?;
                let yaml = parsed_cfg.to_yaml_string()?;
                (
                    ProfileKind::ShareUris,
                    parsed_cfg,
                    yaml,
                    None,
                    None,
                    skipped,
                )
            } else if let Some(raw_yaml) = spec.yaml.as_deref().map(str::trim)
                && !raw_yaml.is_empty()
            {
                let (mut parsed_cfg, skipped) = ClashConfig::from_yaml_str_sanitized(raw_yaml)
                    .map_err(|e| ProxyError::config_clean(redact_sensitive_text(&e.to_string())))?;
                parsed_cfg.tun.enable = false;
                let persisted_yaml = parsed_cfg.to_yaml_string()?;
                (
                    ProfileKind::LocalYaml,
                    parsed_cfg,
                    persisted_yaml,
                    None,
                    None,
                    skipped,
                )
            } else {
                return Err(ProxyError::Config(
                    "must provide one of 'subscription_url', 'uris', or 'yaml'".into(),
                ));
            };

        let (proxy_count, rule_count) = validate_profile_config(&cfg, &self.extra_ca_der)
            .map_err(|e| ProxyError::config_clean(redact_sensitive_text(&e.to_string())))?;
        write_atomic_with_backup(&self.profile_yaml_path(&id), &yaml_str)?;

        let selected_groups = default_selected_groups_for_config(&cfg, &HashMap::new());
        let detected_preset = classify_rule_preset(&cfg);
        let custom_rules_backup = if detected_preset == RulePreset::Custom {
            cfg.rules.clone()
        } else {
            Vec::new()
        };
        let meta = ProfileMetadata {
            id: id.clone(),
            name: clean_name.to_string(),
            kind,
            subscription_url_redacted: redacted_url,
            auto_update_interval_secs: match spec.auto_update_interval_secs {
                None | Some(0) => None,
                Some(secs) => Some(secs.max(60)),
            },
            last_updated_ms: now_unix_ms(),
            last_error: None,
            userinfo,
            proxy_count,
            manual_proxy_count: 0,
            group_count: cfg.proxy_groups.len(),
            rule_count,
            last_skipped_count: skipped_unsupported.len(),
            selected_groups,
            rule_preset: Some(detected_preset),
            custom_rules_backup,
        };

        {
            let mut idx = self.index.lock();
            idx.profiles.push(meta.clone());
            if spec.activate {
                idx.active_profile_id = id;
            }
            if proxy_count > 0 {
                idx.onboarding_completed = true;
            }
            save_index_atomic(&self.profiles_dir.join(INDEX_FILE), &idx)?;
        }

        let activated_cfg = if spec.activate { Some(cfg) } else { None };
        Ok((meta, activated_cfg, skipped_unsupported))
    }

    /// Refresh an HTTPS subscription profile.
    /// If download or validation fails, the existing `<id>.yaml` is NEVER overwritten and `last_error` is recorded.
    /// Any user-added manual nodes stored in `<id>.manual.yaml` are merged back before validation and persistence.
    pub async fn refresh_subscription(
        &self,
        id: &str,
    ) -> Result<(ProfileMetadata, ClashConfig, bool)> {
        let exists = {
            let idx = self.index.lock();
            idx.profiles
                .iter()
                .find(|p| p.id == id)
                .cloned()
                .ok_or_else(|| ProxyError::Config(format!("profile '{id}' not found")))?
        };
        if exists.kind != ProfileKind::Subscription {
            return Err(ProxyError::Config(format!(
                "profile '{}' is not an HTTPS subscription profile",
                exists.name
            )));
        }

        let raw_url = self
            .vault
            .get_secret(&Self::sub_vault_key(id))
            .map_err(ProxyError::Io)?
            .ok_or_else(|| {
                ProxyError::Config(format!(
                    "subscription URL missing from OS SecretVault for profile '{id}'"
                ))
            })?;

        let fallback_proxy = self.fallback_proxy_outbound();
        let outcome: Result<(
            ClashConfig,
            String,
            Option<SubscriptionUserInfo>,
            Vec<SkippedProxyEntry>,
        )> = async {
            let (body, uinfo) = fetch_subscription_http_with_proxy(
                &raw_url,
                &self.extra_ca_der,
                fallback_proxy.as_ref(),
            )
            .await?;
            let (cfg, yaml, skipped) =
                parse_subscription_payload_sanitized(&body, &self.extra_ca_der)?;
            Ok((cfg, yaml, uinfo, skipped))
        }
        .await;

        match outcome {
            Ok((mut cfg, mut yaml, uinfo, skipped)) => {
                let overlay = self.load_manual_overlay(id);
                if !overlay.proxies.is_empty() {
                    let mut manual_names = Vec::with_capacity(overlay.proxies.len());
                    for manual_node in &overlay.proxies {
                        if let Some(pos) = cfg
                            .proxies
                            .iter()
                            .position(|p| p.name() == manual_node.name())
                        {
                            cfg.proxies[pos] = manual_node.clone();
                        } else {
                            cfg.proxies.push(manual_node.clone());
                        }
                        manual_names.push(manual_node.name().to_string());
                    }
                    attach_nodes_and_update_selections(
                        &mut cfg,
                        &manual_names,
                        &mut HashMap::new(),
                        None,
                        false,
                    );
                    for (m_name, extra_groups) in &overlay.group_attachments {
                        for grp_name in extra_groups {
                            if let Some(grp) =
                                cfg.proxy_groups.iter_mut().find(|g| &g.name == grp_name)
                                && !grp.proxies.iter().any(|m| m == m_name)
                            {
                                insert_before_builtins(&mut grp.proxies, m_name);
                            }
                        }
                    }
                    yaml = serde_saphyr::to_string(&cfg).map_err(|e| {
                        ProxyError::Config(format!(
                            "failed to serialize merged subscription YAML: {e}"
                        ))
                    })?;
                }
                let manual_proxy_count = overlay.proxies.len();

                let (proxy_count, rule_count) = validate_profile_config(&cfg, &self.extra_ca_der)?;
                write_atomic_with_backup(&self.profile_yaml_path(id), &yaml)?;
                self.last_attempt_ms.lock().remove(id);

                let live_router_sel = self
                    .router_slot
                    .read()
                    .as_ref()
                    .and_then(|w| w.upgrade())
                    .map(|slot| slot.read().manual_selections_snapshot())
                    .unwrap_or_default();

                let detected_preset = classify_rule_preset(&cfg);
                let mut idx = self.index.lock();
                let is_active = idx.active_profile_id == id;
                let mut updated_meta = None;
                for p in &mut idx.profiles {
                    if p.id == id {
                        let mut prev_selected = p.selected_groups.clone();
                        if is_active {
                            for (k, v) in &live_router_sel {
                                prev_selected.insert(k.clone(), v.clone());
                            }
                        }
                        p.last_updated_ms = now_unix_ms();
                        p.last_error = None;
                        p.proxy_count = proxy_count;
                        p.group_count = cfg.proxy_groups.len();
                        p.manual_proxy_count = manual_proxy_count;
                        p.rule_count = rule_count;
                        p.last_skipped_count = skipped.len();
                        p.rule_preset = Some(detected_preset);
                        if detected_preset == RulePreset::Custom {
                            p.custom_rules_backup = cfg.rules.clone();
                        }
                        p.selected_groups =
                            default_selected_groups_for_config(&cfg, &prev_selected);
                        if uinfo.is_some() {
                            p.userinfo = uinfo.clone();
                        }
                        updated_meta = Some(p.clone());
                        break;
                    }
                }
                save_index_atomic(&self.profiles_dir.join(INDEX_FILE), &idx)?;
                Ok((updated_meta.unwrap_or(exists), cfg, is_active))
            }
            Err(err) => {
                self.last_attempt_ms
                    .lock()
                    .insert(id.to_string(), now_unix_ms());
                let cleaned_err = ProxyError::config_clean(
                    redact_sensitive_text(&err.to_string()).replace(&raw_url, "***REDACTED_URL***"),
                );
                let safe_err = cleaned_err.to_string();
                let mut idx = self.index.lock();
                for p in &mut idx.profiles {
                    if p.id == id {
                        p.last_error = Some(safe_err.clone());
                        break;
                    }
                }
                if let Err(e) = save_index_atomic(&self.profiles_dir.join(INDEX_FILE), &idx) {
                    tracing::warn!("failed saving subscription error state to index: {e}");
                }
                Err(cleaned_err)
            }
        }
    }

    /// Return IDs of active subscription profiles whose `auto_update_interval_secs` has elapsed,
    /// skipping inactive or disabled (`None` / `0`) profiles and applying a 10-minute backoff after failures.
    pub fn due_auto_update_ids(&self) -> Vec<String> {
        const FAILURE_BACKOFF_MS: u64 = 10 * 60 * 1000;
        let now_ms = now_unix_ms();
        let attempts = self.last_attempt_ms.lock().clone();
        let idx = self.index.lock();
        let active_id = idx.active_profile_id.as_str();
        idx.profiles
            .iter()
            .filter(|p| p.kind == ProfileKind::Subscription && p.id == active_id)
            .filter_map(|p| {
                let secs = p.auto_update_interval_secs?;
                if secs == 0 {
                    return None;
                }
                if let Some(&last_try) = attempts.get(&p.id)
                    && now_ms.saturating_sub(last_try) < FAILURE_BACKOFF_MS
                {
                    return None;
                }
                let interval_ms = secs.saturating_mul(1000);
                if interval_ms > 0 && now_ms.saturating_sub(p.last_updated_ms) >= interval_ms {
                    Some(p.id.clone())
                } else {
                    None
                }
            })
            .collect()
    }

    pub fn delete_profile(&self, id: &str) -> Result<()> {
        {
            let mut idx = self.index.lock();
            if idx.active_profile_id == id {
                return Err(ProxyError::Config(
                    "cannot delete the currently active profile; activate another profile first"
                        .into(),
                ));
            }
            let before = idx.profiles.len();
            idx.profiles.retain(|p| p.id != id);
            if idx.profiles.len() == before {
                return Err(ProxyError::Config(format!("profile '{id}' not found")));
            }
            save_index_atomic(&self.profiles_dir.join(INDEX_FILE), &idx)?;
        }
        self.last_attempt_ms.lock().remove(id);
        let _ = self.vault.delete_secret(&Self::sub_vault_key(id));
        let _ = fs::remove_file(self.profile_yaml_path(id));
        let _ = fs::remove_file(self.profile_yaml_path(id).with_extension("yaml.bak"));
        let overlay_path = self.manual_overlay_path(id);
        let _ = fs::remove_file(&overlay_path);
        let _ = fs::remove_file(overlay_path.with_extension("yaml.bak"));
        Ok(())
    }

    fn profile_yaml_path(&self, id: &str) -> PathBuf {
        let sanitized = sanitize_profile_id(id);
        self.profiles_dir.join(format!("{sanitized}.yaml"))
    }

    fn manual_overlay_path(&self, id: &str) -> PathBuf {
        let sanitized = sanitize_profile_id(id);
        self.profiles_dir.join(format!("{sanitized}.manual.yaml"))
    }

    fn load_manual_overlay(&self, id: &str) -> ManualNodesOverlay {
        read_manual_overlay_from_path(&self.manual_overlay_path(id))
    }

    fn save_manual_overlay(&self, id: &str, overlay: &ManualNodesOverlay) -> Result<()> {
        let path = self.manual_overlay_path(id);
        if overlay.proxies.is_empty() {
            let _ = fs::remove_file(&path);
            let _ = fs::remove_file(path.with_extension("yaml.bak"));
            return Ok(());
        }
        let mut cleaned = overlay.clone();
        let valid_names: HashSet<&str> = cleaned.proxies.iter().map(|p| p.name()).collect();
        cleaned
            .group_attachments
            .retain(|k, v| valid_names.contains(k.as_str()) && !v.is_empty());
        let yaml = serde_saphyr::to_string(&cleaned).map_err(|e| {
            ProxyError::Config(format!("failed to serialize manual nodes overlay: {e}"))
        })?;
        write_atomic_with_backup(&path, &yaml)
    }

    fn sub_vault_key(id: &str) -> String {
        format!("subscription_url:{id}")
    }
}

fn sanitize_profile_id(id: &str) -> String {
    id.chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .collect()
}

fn read_manual_overlay_from_path(path: &Path) -> ManualNodesOverlay {
    for candidate in [path.to_path_buf(), path.with_extension("yaml.bak")] {
        if let Ok(raw) = fs::read_to_string(&candidate)
            && !raw.trim().is_empty()
            && let Ok(parsed) = serde_saphyr::from_str::<ManualNodesOverlay>(&raw)
        {
            return parsed;
        }
    }
    ManualNodesOverlay::default()
}

fn collect_group_attachments_for_node(cfg: &ClashConfig, node_name: &str) -> Vec<String> {
    cfg.proxy_groups
        .iter()
        .filter(|g| g.proxies.iter().any(|m| m == node_name))
        .map(|g| g.name.clone())
        .collect()
}

fn collect_taken_names(cfg: &ClashConfig) -> HashSet<String> {
    let mut set = HashSet::new();
    for builtin in ["DIRECT", "REJECT", "GLOBAL"] {
        set.insert(builtin.to_string());
    }
    for p in &cfg.proxies {
        set.insert(p.name().to_string());
    }
    for g in &cfg.proxy_groups {
        set.insert(g.name.clone());
    }
    set
}

fn uniquify_node_name(desired: &str, taken: &HashSet<String>) -> String {
    let base = if desired.is_empty() {
        "ProxyNode"
    } else {
        desired
    };
    if !taken.contains(base) {
        return base.to_string();
    }
    let mut suffix = 2usize;
    loop {
        let candidate = format!("{base}-{suffix}");
        if !taken.contains(&candidate) {
            return candidate;
        }
        suffix += 1;
    }
}

fn insert_before_builtins(members: &mut Vec<String>, new_name: &str) {
    if members.iter().any(|m| m == new_name) {
        return;
    }
    if let Some(pos) = members.iter().position(|m| m == "DIRECT" || m == "REJECT") {
        members.insert(pos, new_name.to_string());
    } else {
        members.push(new_name.to_string());
    }
}

fn attach_nodes_and_update_selections(
    cfg: &mut ClashConfig,
    node_names: &[String],
    selected_groups: &mut HashMap<String, String>,
    preferred_select_node: Option<&str>,
    auto_select: bool,
) {
    let mut builtin_only_groups = HashSet::new();
    if cfg.proxy_groups.is_empty() {
        builtin_only_groups.insert("PROXY".to_string());
        let mut proxies: Vec<String> = node_names.to_vec();
        proxies.push("DIRECT".to_string());
        cfg.proxy_groups.push(ProxyGroupConfig {
            name: "PROXY".to_string(),
            group_type: ProxyGroupType::Select,
            proxies,
            url: "http://www.gstatic.com/generate_204".to_string(),
            interval: 300,
            tolerance: 50,
            strategy: None,
        });
        for line in &mut cfg.rules {
            if line.trim().eq_ignore_ascii_case("MATCH,DIRECT") {
                *line = "MATCH,PROXY".to_string();
            }
        }
    } else {
        for g in &mut cfg.proxy_groups {
            let had_only_builtins = g.proxies.iter().all(|m| m == "DIRECT" || m == "REJECT");
            if had_only_builtins {
                builtin_only_groups.insert(g.name.clone());
            }
            let starts_with_intentional_builtin = !had_only_builtins
                && matches!(
                    g.proxies.first().map(String::as_str),
                    Some("DIRECT" | "REJECT")
                );
            for n in node_names {
                if starts_with_intentional_builtin {
                    if !g.proxies.iter().any(|m| m == n) {
                        g.proxies.push(n.clone());
                    }
                } else {
                    insert_before_builtins(&mut g.proxies, n);
                }
            }
            if matches!(
                g.group_type,
                ProxyGroupType::UrlTest | ProxyGroupType::Fallback
            ) && g.proxies.iter().any(|m| m != "DIRECT" && m != "REJECT")
            {
                g.proxies.retain(|m| m != "DIRECT" && m != "REJECT");
            }
        }
    }

    let has_concrete = !cfg.proxies.is_empty();
    let primary_group = primary_proxy_group_for_config(cfg);
    for g in &cfg.proxy_groups {
        if g.group_type != ProxyGroupType::Select {
            continue;
        }
        let is_primary = g.name == primary_group;
        let had_only_builtins = builtin_only_groups.contains(&g.name);
        let current = selected_groups
            .get(&g.name)
            .filter(|m| g.proxies.contains(*m))
            .cloned();

        if auto_select
            && (is_primary || had_only_builtins)
            && let Some(pref) = preferred_select_node
            && g.proxies.iter().any(|m| m == pref)
        {
            selected_groups.insert(g.name.clone(), pref.to_string());
            continue;
        }

        match current {
            Some(cur) if !(has_concrete && had_only_builtins && cur == "DIRECT") => {
                selected_groups.insert(g.name.clone(), cur);
            }
            _ => {
                if (is_primary || had_only_builtins)
                    && let Some(pref) = preferred_select_node
                    && g.proxies.iter().any(|m| m == pref)
                {
                    selected_groups.insert(g.name.clone(), pref.to_string());
                } else if let Some(first) = g.proxies.first() {
                    selected_groups.insert(g.name.clone(), first.clone());
                }
            }
        }
    }

    if has_concrete {
        let global_cur = selected_groups.get("GLOBAL").map(String::as_str);
        if global_cur.is_none() || (global_cur == Some("DIRECT") && !builtin_only_groups.is_empty())
        {
            if primary_group != "DIRECT" {
                selected_groups.insert("GLOBAL".to_string(), primary_group);
            } else if let Some(pref) = preferred_select_node {
                selected_groups.insert("GLOBAL".to_string(), pref.to_string());
            } else if let Some(first_node) = cfg.proxies.first() {
                selected_groups.insert("GLOBAL".to_string(), first_node.name().to_string());
            }
        }
    }
}

fn rule_targets_name(rule_line: &str, target_name: &str) -> bool {
    let trimmed = rule_line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return false;
    }
    let parts: Vec<&str> = trimmed.split(',').map(str::trim).collect();
    if parts.len() == 2
        && (parts[0].eq_ignore_ascii_case("MATCH") || parts[0].eq_ignore_ascii_case("FINAL"))
    {
        return parts[1] == target_name;
    }
    if parts.len() >= 3 {
        return parts[2] == target_name;
    }
    false
}

fn cascade_rename_reference(
    cfg: &mut ClashConfig,
    selected_groups: &mut HashMap<String, String>,
    old_name: &str,
    new_name: &str,
) {
    for g in &mut cfg.proxy_groups {
        let mut deduped = Vec::with_capacity(g.proxies.len());
        for m in &g.proxies {
            let mapped = if m == old_name {
                new_name.to_string()
            } else {
                m.clone()
            };
            if !deduped.contains(&mapped) {
                deduped.push(mapped);
            }
        }
        g.proxies = deduped;
    }

    for line in &mut cfg.rules {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let mut parts: Vec<String> = trimmed.split(',').map(|s| s.trim().to_string()).collect();
        if parts.len() == 2
            && (parts[0].eq_ignore_ascii_case("MATCH") || parts[0].eq_ignore_ascii_case("FINAL"))
            && parts[1] == old_name
        {
            parts[1] = new_name.to_string();
            *line = parts.join(",");
        } else if parts.len() >= 3 && parts[2] == old_name {
            parts[2] = new_name.to_string();
            *line = parts.join(",");
        }
    }

    for val in selected_groups.values_mut() {
        if val == old_name {
            *val = new_name.to_string();
        }
    }
}

fn deduplicate_config_in_place(
    cfg: &mut ClashConfig,
    selected_groups: &mut HashMap<String, String>,
) -> (Vec<String>, HashMap<String, String>) {
    let mut seen_keys: HashMap<String, String> = HashMap::new();
    let mut kept_proxies = Vec::with_capacity(cfg.proxies.len());
    let mut removed_names = Vec::new();
    let mut alias_to_canonical: HashMap<String, String> = HashMap::new();

    for node in cfg.proxies.drain(..) {
        let key = proxy_node_dedup_key(&node);
        if let Some(canonical_name) = seen_keys.get(&key) {
            let dup_name = node.name().to_string();
            removed_names.push(dup_name.clone());
            alias_to_canonical.insert(dup_name, canonical_name.clone());
        } else {
            seen_keys.insert(key, node.name().to_string());
            kept_proxies.push(node);
        }
    }
    cfg.proxies = kept_proxies;

    for (dup_name, canonical_name) in &alias_to_canonical {
        cascade_rename_reference(cfg, selected_groups, dup_name, canonical_name);
    }

    (removed_names, alias_to_canonical)
}

static ATOMIC_TMP_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

fn write_atomic_with_backup(target: &Path, content: &str) -> Result<()> {
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent)?;
    }
    let seq = ATOMIC_TMP_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let tmp = target.with_extension(format!("yaml.tmp.{}.{seq}", std::process::id()));
    {
        let mut opts = OpenOptions::new();
        opts.create(true).write(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Err(e) = f.set_permissions(fs::Permissions::from_mode(0o600)) {
                tracing::warn!(
                    "failed setting 0600 permissions on '{}': {e}",
                    tmp.display()
                );
            }
        }
        f.write_all(content.as_bytes())?;
        f.sync_all()?;
    }
    if target.exists() {
        let bak = target.with_extension("yaml.bak");
        if fs::copy(target, &bak).is_ok() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(&bak, fs::Permissions::from_mode(0o600));
            }
        }
    }
    fs::rename(&tmp, target)?;
    Ok(())
}

fn save_index_atomic(index_path: &Path, index: &ProfileIndex) -> Result<()> {
    let seq = ATOMIC_TMP_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let tmp = index_path.with_extension(format!("json.tmp.{}.{seq}", std::process::id()));
    let bytes = serde_json::to_vec_pretty(index)
        .map_err(|e| ProxyError::Config(format!("serialize profile index: {e}")))?;
    {
        let mut opts = OpenOptions::new();
        opts.create(true).write(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Err(e) = f.set_permissions(fs::Permissions::from_mode(0o600)) {
                tracing::warn!(
                    "failed setting 0600 permissions on '{}': {e}",
                    tmp.display()
                );
            }
        }
        f.write_all(&bytes)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, index_path)?;
    Ok(())
}

fn is_loopback_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    let clean = host.trim_start_matches('[').trim_end_matches(']');
    clean.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

async fn connect_protected_tcp(host: &str, port: u16) -> Result<tokio::net::TcpStream> {
    let addrs = crate::router::geodata::resolve_host_bypassing_fake_ip(host, port).await?;
    if addrs.is_empty() {
        return Err(ProxyError::Config(
            "unable to resolve subscription host".into(),
        ));
    }

    let mut last_err = None;
    for target in addrs {
        let domain = if target.is_ipv6() {
            socket2::Domain::IPV6
        } else {
            socket2::Domain::IPV4
        };
        let sock =
            match socket2::Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP))
            {
                Ok(s) => s,
                Err(e) => {
                    last_err = Some(ProxyError::Io(e));
                    continue;
                }
            };
        if let Err(e) = sock.set_nonblocking(true) {
            last_err = Some(ProxyError::Io(e));
            continue;
        }
        let _ = sock.set_nodelay(true);
        if let Err(e) = global_socket_protector().protect_tcp(&sock, target) {
            last_err = Some(ProxyError::Io(e));
            continue;
        }
        let t_sock = tokio::net::TcpSocket::from_std_stream(sock.into());
        match tokio::time::timeout(Duration::from_secs(10), t_sock.connect(target)).await {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(e)) => last_err = Some(ProxyError::Io(e)),
            Err(_) => {
                last_err = Some(ProxyError::Config(
                    "subscription TCP connect timed out".into(),
                ))
            }
        }
    }

    Err(last_err
        .unwrap_or_else(|| ProxyError::Config("failed connecting to subscription server".into())))
}

/// Fetch a subscription URL via `rustls` HTTPS (with strict certificate verification; cleartext
/// `http://` is permitted ONLY for `127.0.0.1` / `localhost` loopback providers and hermetic tests).
pub async fn fetch_subscription_http(
    raw_url: &str,
    extra_ca_der: &[CertificateDer<'static>],
) -> Result<(String, Option<SubscriptionUserInfo>)> {
    fetch_subscription_http_with_proxy(raw_url, extra_ca_der, None).await
}

/// Fetch a subscription URL via `rustls` HTTPS with automatic fallback through an active concrete
/// proxy outbound (preserving end-to-end TLS certificate verification) when direct egress fails
/// on non-loopback HTTPS hosts.
pub async fn fetch_subscription_http_with_proxy(
    raw_url: &str,
    extra_ca_der: &[CertificateDer<'static>],
    fallback_proxy: Option<&DynOutbound>,
) -> Result<(String, Option<SubscriptionUserInfo>)> {
    let mut current = Url::parse(raw_url.trim())
        .map_err(|e| ProxyError::Config(format!("invalid subscription URL: {e}")))?;

    for _redirect_hop in 0..=3 {
        let scheme = current.scheme().to_ascii_lowercase();
        let host = current
            .host_str()
            .ok_or_else(|| ProxyError::Config("subscription URL missing host".into()))?
            .to_string();

        let is_https = match scheme.as_str() {
            "https" => true,
            "http" if is_loopback_host(&host) => false,
            "http" => {
                return Err(ProxyError::Config(
                    "cleartext http:// subscriptions are rejected for security; use https://"
                        .into(),
                ));
            }
            other => {
                return Err(ProxyError::Config(format!(
                    "unsupported subscription URL scheme '{other}'"
                )));
            }
        };

        let port = current
            .port_or_known_default()
            .unwrap_or(if is_https { 443 } else { 80 });
        let mut path_and_query = current.path().to_string();
        if path_and_query.is_empty() {
            path_and_query.push('/');
        }
        if let Some(q) = current.query() {
            path_and_query.push('?');
            path_and_query.push_str(q);
        }

        let host_header = if (is_https && port == 443) || (!is_https && port == 80) {
            host.clone()
        } else {
            format!("{host}:{port}")
        };

        let req_bytes = format!(
            "GET {path_and_query} HTTP/1.1\r\nHost: {host_header}\r\nUser-Agent: rust-clash/{} Clash.Meta/1.18 mihomo/1.18\r\nAccept: */*\r\nAccept-Encoding: gzip, identity\r\nConnection: close\r\n\r\n",
            env!("CARGO_PKG_VERSION")
        );

        let direct_attempt: Result<Vec<u8>> = async {
            let tcp = connect_protected_tcp(&host, port).await?;
            if is_https {
                exchange_sub_https_over_stream(tcp, &host, &req_bytes, extra_ca_der).await
            } else {
                let mut tcp = tcp;
                tcp.write_all(req_bytes.as_bytes())
                    .await
                    .map_err(ProxyError::Io)?;
                read_bounded_stream(&mut tcp).await
            }
        }
        .await;

        let raw_resp = match direct_attempt {
            Ok(bytes) => bytes,
            Err(direct_err) => {
                if is_https
                    && !is_loopback_host(&host)
                    && let Some(proxy_ob) = fallback_proxy
                {
                    let target = TargetAddr::new_domain(&host, port).or_else(|_| {
                        let clean = host.trim_start_matches('[').trim_end_matches(']');
                        clean
                            .parse::<IpAddr>()
                            .map(|ip| TargetAddr::new_ip(ip, port))
                            .map_err(|_| {
                                ProxyError::Config("invalid subscription target host".into())
                            })
                    })?;
                    match tokio::time::timeout(
                        Duration::from_secs(10),
                        proxy_ob.connect_tcp(&target),
                    )
                    .await
                    {
                        Ok(Ok(proxy_stream)) => {
                            match exchange_sub_https_over_stream(
                                proxy_stream,
                                &host,
                                &req_bytes,
                                extra_ca_der,
                            )
                            .await
                            {
                                Ok(bytes) => bytes,
                                Err(_) => return Err(direct_err),
                            }
                        }
                        _ => return Err(direct_err),
                    }
                } else {
                    return Err(direct_err);
                }
            }
        };

        let (status, headers, body_bytes_raw) = parse_http11_response(&raw_resp)?;
        if matches!(status, 301 | 302 | 307 | 308) {
            let loc = headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("location"))
                .map(|(_, v)| v.as_str())
                .ok_or_else(|| {
                    ProxyError::Config(format!("HTTP {status} redirect missing Location header"))
                })?;
            let next_url = current
                .join(loc)
                .map_err(|e| ProxyError::Config(format!("invalid redirect Location: {e}")))?;
            if is_https && next_url.scheme().eq_ignore_ascii_case("http") {
                return Err(ProxyError::Config(
                    "refusing HTTPS-to-HTTP downgrade redirect on subscription URL".into(),
                ));
            }
            current = next_url;
            continue;
        }

        let body_bytes = maybe_decompress_http_body(&headers, body_bytes_raw)?;

        if !(200..300).contains(&status) {
            if let Ok(err_body) = std::str::from_utf8(&body_bytes) {
                let trimmed_err = trim_bom_and_controls_str(err_body);
                if trimmed_err.starts_with('{')
                    && let Ok(serde_json::Value::Object(obj)) =
                        serde_json::from_str::<serde_json::Value>(trimmed_err)
                    && let Some(msg) = extract_json_panel_error_message(&obj)
                {
                    return Err(ProxyError::Config(format!(
                        "subscription server returned HTTP {status}: {msg}"
                    )));
                }
                let lower_err: String = trimmed_err
                    .chars()
                    .take(512)
                    .collect::<String>()
                    .to_ascii_lowercase();
                if lower_err.contains("cloudflare") || lower_err.contains("cf-ray") {
                    return Err(ProxyError::Config(format!(
                        "subscription server returned HTTP {status} (Cloudflare challenge/error page)"
                    )));
                }
            }
            return Err(ProxyError::Config(format!(
                "subscription server returned HTTP {status}"
            )));
        }

        let userinfo = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("subscription-userinfo"))
            .and_then(|(_, v)| parse_subscription_userinfo(v));

        let body_text = String::from_utf8(body_bytes).map_err(|e| {
            ProxyError::Config(format!("subscription response is not valid UTF-8: {e}"))
        })?;
        if trim_bom_and_controls_str(&body_text).is_empty() {
            return Err(ProxyError::Config(format!(
                "subscription server returned an empty response body (HTTP {status}); check whether your subscription token is valid or has active nodes"
            )));
        }
        return Ok((body_text, userinfo));
    }

    Err(ProxyError::Config(
        "too many HTTP redirects while fetching subscription".into(),
    ))
}

fn maybe_decompress_http_body(headers: &HttpHeaderList, body: Vec<u8>) -> Result<Vec<u8>> {
    let has_gzip_header = headers.iter().any(|(k, v)| {
        k.eq_ignore_ascii_case("content-encoding")
            && (v.to_ascii_lowercase().contains("gzip")
                || v.to_ascii_lowercase().contains("x-gzip"))
    });
    let has_gzip_magic = body.len() >= 2 && body[0] == 0x1f && body[1] == 0x8b;
    if !has_gzip_header && !has_gzip_magic {
        return Ok(body);
    }

    use std::io::Read;
    let decoder = flate2::read::GzDecoder::new(body.as_slice());
    let mut limited = decoder.take((MAX_SUBSCRIPTION_BYTES + 1) as u64);
    let mut decompressed = Vec::new();
    limited.read_to_end(&mut decompressed).map_err(|e| {
        if has_gzip_header {
            ProxyError::Config(format!(
                "failed decompressing gzip subscription payload: {e}"
            ))
        } else {
            ProxyError::Config("subscription response is binary/non-UTF-8 data".into())
        }
    })?;
    if decompressed.len() > MAX_SUBSCRIPTION_BYTES {
        return Err(ProxyError::Config(
            "decompressed subscription payload exceeds 8 MiB safety limit".into(),
        ));
    }
    Ok(decompressed)
}

async fn exchange_sub_https_over_stream<S>(
    stream: S,
    host: &str,
    req_bytes: &str,
    extra_ca_der: &[CertificateDer<'static>],
) -> Result<Vec<u8>>
where
    S: AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let tls_cfg = build_tls_client_config(false, extra_ca_der, &[b"http/1.1".to_vec()])
        .map_err(|e| ProxyError::Config(format!("subscription TLS config failed: {e}")))?;
    let connector = TlsConnector::from(tls_cfg);
    let clean_host = host.trim_start_matches('[').trim_end_matches(']');
    let server_name = rustls::pki_types::ServerName::try_from(clean_host.to_string())
        .map_err(|e| ProxyError::Config(format!("invalid subscription TLS server name: {e}")))?;
    let mut tls_stream = tokio::time::timeout(
        Duration::from_secs(10),
        connector.connect(server_name, stream),
    )
    .await
    .map_err(|_| ProxyError::Config("subscription TLS handshake timed out".into()))?
    .map_err(|e| ProxyError::Config(format!("subscription TLS verify failed: {e}")))?;
    tls_stream
        .write_all(req_bytes.as_bytes())
        .await
        .map_err(ProxyError::Io)?;
    read_bounded_stream(&mut tls_stream).await
}

async fn read_bounded_stream<S: AsyncRead + Unpin>(stream: &mut S) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(8192);
    let mut chunk = [0u8; 16384];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(ProxyError::Config(
                "subscription download timed out".to_string(),
            ));
        }
        let n = tokio::time::timeout(remaining, stream.read(&mut chunk))
            .await
            .map_err(|_| ProxyError::Config("subscription download timed out".into()))?
            .map_err(ProxyError::Io)?;
        if n == 0 {
            break;
        }
        if out.len() + n > MAX_SUBSCRIPTION_BYTES {
            return Err(ProxyError::Config(
                "subscription payload exceeds 8 MiB safety limit".into(),
            ));
        }
        out.extend_from_slice(&chunk[..n]);
    }
    Ok(out)
}

type HttpHeaderList = Vec<(String, String)>;

fn parse_http11_response(raw: &[u8]) -> Result<(u16, HttpHeaderList, Vec<u8>)> {
    let Some(hdr_end) = raw.windows(4).position(|w| w == b"\r\n\r\n") else {
        return Err(ProxyError::Config(
            "malformed HTTP response from subscription server".into(),
        ));
    };
    let head_str = std::str::from_utf8(&raw[..hdr_end]).map_err(|_| {
        ProxyError::Config("non-ASCII HTTP headers in subscription response".into())
    })?;
    let mut lines = head_str.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| ProxyError::Config("missing HTTP status line".into()))?;
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| ProxyError::Config(format!("invalid HTTP status line '{status_line}'")))?;

    let mut headers = Vec::new();
    let mut is_chunked = false;
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            let key = k.trim().to_string();
            let val = v.trim().to_string();
            if key.eq_ignore_ascii_case("transfer-encoding")
                && val.to_ascii_lowercase().contains("chunked")
            {
                is_chunked = true;
            }
            headers.push((key, val));
        }
    }

    let body_raw = &raw[hdr_end + 4..];
    let body = if is_chunked {
        decode_chunked_body(body_raw)?
    } else {
        body_raw.to_vec()
    };
    Ok((status, headers, body))
}

fn decode_chunked_body(mut input: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    while let Some(crlf) = input.windows(2).position(|w| w == b"\r\n") {
        let len_str = std::str::from_utf8(&input[..crlf])
            .unwrap_or("")
            .split(';')
            .next()
            .unwrap_or("")
            .trim();
        let chunk_len = usize::from_str_radix(len_str, 16)
            .map_err(|_| ProxyError::Config("invalid chunked transfer length".into()))?;
        input = &input[crlf + 2..];
        if chunk_len == 0 {
            break;
        }
        if input.len() < chunk_len + 2 {
            return Err(ProxyError::Config("truncated chunked HTTP response".into()));
        }
        out.extend_from_slice(&input[..chunk_len]);
        input = &input[chunk_len + 2..];
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::tls::generate_self_signed_server_config;
    use base64::{Engine, engine::general_purpose::STANDARD};
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    #[test]
    fn url_redaction_and_userinfo_parsing_work() {
        let raw = "https://user:pass@sub.example.com:8443/api/v1/sub?token=secret123&flag=clash";
        let red = redact_subscription_url(raw);
        assert_eq!(red, "https://sub.example.com:8443/***REDACTED***");
        assert!(!red.contains("secret123"));
        assert!(!red.contains("pass"));

        let info = parse_subscription_userinfo(
            "upload=1048576; download=5242880; total=10737418240; expire=1900000000",
        )
        .unwrap();
        assert_eq!(info.upload_bytes, 1_048_576);
        assert_eq!(info.download_bytes, 5_242_880);
        assert_eq!(info.total_bytes, Some(10_737_418_240));
        assert_eq!(info.expire_unix_secs, Some(1_900_000_000));
    }

    #[tokio::test]
    async fn https_subscription_import_refresh_and_failed_update_rollback() {
        let dir = std::env::temp_dir().join(format!("rc-profile-test-{}", Uuid::new_v4()));

        // Reject remote cleartext HTTP
        let cleartext_err =
            fetch_subscription_http("http://insecure.example.com/sub?token=abc", &[])
                .await
                .unwrap_err();
        assert!(cleartext_err.to_string().contains("https://"));

        // Spin up a real local TLS 1.3 HTTPS subscription server with self-signed CA!
        let (server_tls_cfg, ca_der) =
            generate_self_signed_server_config(&["localhost".into(), "127.0.0.1".into()], &[])
                .unwrap();
        let acceptor = TlsAcceptor::from(server_tls_cfg);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let psk = STANDARD.encode([0x33u8; 32]);
        let valid_uri = format!(
            "ss://{}@127.0.0.1:8388#Sub-SS2022-Node",
            STANDARD.encode(format!("2022-blake3-aes-256-gcm:{psk}"))
        );
        let b64_sub = STANDARD.encode(&valid_uri);

        let serve_corrupt = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let serve_corrupt_srv = Arc::clone(&serve_corrupt);
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let acc = acceptor.clone();
                let body_good = b64_sub.clone();
                let corrupt = serve_corrupt_srv.load(std::sync::atomic::Ordering::Acquire);
                tokio::spawn(async move {
                    let Ok(mut tls) = acc.accept(tcp).await else {
                        return;
                    };
                    let mut req_buf = [0u8; 2048];
                    let _ = tls.read(&mut req_buf).await;
                    let body = if corrupt {
                        "proxies:\n  - invalid_broken_yaml: [unclosed".to_string()
                    } else {
                        body_good
                    };
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nSubscription-Userinfo: upload=2048; download=8192; total=1048576; expire=1999999999\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = tls.write_all(resp.as_bytes()).await;
                    let _ = tls.shutdown().await;
                });
            }
        });

        let mgr = ProfileManager::open_or_init_with_ca(&dir, vec![ca_der]).unwrap();
        assert_eq!(mgr.snapshot().profiles.len(), 1); // Starter profile

        let sub_url = format!("https://localhost:{}/sub?token=secret-tok-777", addr.port());
        let (meta, active_cfg) = mgr
            .create_profile(CreateProfileSpec {
                name: "Test TLS Subscription".into(),
                yaml: None,
                uris: None,
                subscription_url: Some(sub_url.clone()),
                auto_update_interval_secs: Some(3600),
                activate: true,
            })
            .await
            .unwrap();

        assert_eq!(meta.kind, ProfileKind::Subscription);
        assert_eq!(meta.proxy_count, 1);
        assert!(
            !meta
                .subscription_url_redacted
                .as_deref()
                .unwrap()
                .contains("secret-tok-777"),
            "token must be redacted in metadata"
        );
        assert_eq!(meta.userinfo.as_ref().unwrap().download_bytes, 8192);
        assert_eq!(active_cfg.unwrap().proxies.len(), 1);

        // Now flip server to return corrupt YAML and verify refresh FAILS cleanly while preserving working YAML on disk!
        serve_corrupt.store(true, std::sync::atomic::Ordering::Release);
        let refresh_err = mgr.refresh_subscription(&meta.id).await.unwrap_err();
        assert!(
            !refresh_err.to_string().contains("secret-tok-777"),
            "error message must never leak raw token"
        );
        let preserved_cfg = mgr.load_active_config().unwrap().0;
        assert_eq!(
            preserved_cfg.proxies.len(),
            1,
            "corrupt subscription refresh must leave existing profile intact"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn v2board_clash_yaml_subscription_quirks_and_single_error_prefix() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let dir = std::env::temp_dir().join(format!(
            "rustclash-v2board-compat-{}",
            Uuid::new_v4().simple()
        ));
        let (server_tls_cfg, ca_der) =
            generate_self_signed_server_config(&["localhost".into(), "127.0.0.1".into()], &[])
                .unwrap();
        let acceptor = TlsAcceptor::from(server_tls_cfg);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Realistic V2Board / Xboard / Subconverter / Mihomo subscription YAML containing:
        // - TitleCase `mode: Rule` (exact failure trigger from V2Board `default.clash.yaml`)
        // - Legacy `port: "7890"` without `mixed-port`, Go `:9090` / `:53` listeners, `tun: { mtu: 0 }`
        // - `dns` with `enhanced-mode: FAKE-IP`, `default-nameserver: [system]`, and `dhcp://en0`
        // - Nodes with mixed-case `type: AnyTLS` / `Shadowsocks`, stringified `port: "443"` and `udp: "true"`
        // - Groups with `type: Select` / `URL-Test`, `include-all: true`, and an empty regional filter group (`HK`)
        // - Rules with `IP-ASN`, `DST-PORT,...,REJECT-DROP`, and 3-part `MATCH,,Proxy`
        let v2board_yaml = r#"
port: "7890"
allow-lan: "false"
mode: Rule
log-level: silent
external-controller: :9090
tun:
  enable: "false"
  stack: system
  dns-hijack:
    - any:53
    - tcp://any:53
  inet6-address:
    - fdfe:dcba:9876::1/126
  mtu: 0
dns:
  enable: true
  listen: :53
  enhanced-mode: FAKE-IP
  default-nameserver:
    - 223.5.5.5#DIRECT
    - system
  nameserver:
    - https://doh.pub/dns-query
    - dhcp://en0
proxies:
  - name: gz-po0-sg-lg
    type: AnyTLS
    server: sg.example.com
    port: "443"
    password: secret-anytls-password
    sni: sg.example.com
    alpn: h2,http/1.1
    udp: "true"
  - name: legacy-ss-node
    type: Shadowsocks
    server: ss.example.com
    port: "8388"
    cipher: 2022-BLAKE3-AES-128-GCM
    password: MDEyMzQ1Njc4OWFiY2RlZg==
proxy-groups:
  - name: Proxy
    type: Select
    proxies:
      - Auto
      - HK-Empty
      - gz-po0-sg-lg
      - COMPATIBLE
  - name: Auto
    type: URL-Test
    include-all: true
    url: http://www.gstatic.com/generate_204
    interval: "300"
  - name: HK-Empty
    type: Select
    include-all: true
    filter: "(?i)HK|HongKong"
rules:
  - IP-ASN,13335,Proxy,no-resolve
  - DST-PORT,443,REJECT-DROP
  - DOMAIN-SUFFIX,google.com,Proxy
  - MATCH,,Proxy
"#
        .to_string();

        let serve_bad = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let serve_bad_srv = serve_bad.clone();
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let acc = acceptor.clone();
                let good = v2board_yaml.clone();
                let bad = serve_bad_srv.load(std::sync::atomic::Ordering::Acquire);
                tokio::spawn(async move {
                    let Ok(mut tls) = acc.accept(tcp).await else {
                        return;
                    };
                    let mut req_buf = [0u8; 2048];
                    let _ = tls.read(&mut req_buf).await;
                    let body = if bad {
                        "mode: Rule\nproxies:\n  - broken: [unclosed".to_string()
                    } else {
                        good
                    };
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/yaml; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = tls.write_all(resp.as_bytes()).await;
                    let _ = tls.shutdown().await;
                });
            }
        });

        let mgr = ProfileManager::open_or_init_with_ca(&dir, vec![ca_der]).unwrap();
        let sub_url = format!(
            "https://localhost:{}/api/v1/client/subscribe?token=secret-sub-tok",
            addr.port()
        );

        let report = mgr
            .import_unified_input(&sub_url, None, true, true)
            .await
            .expect("V2Board Clash YAML subscription must import cleanly");

        assert_eq!(report.total_nodes, 2);
        assert_eq!(report.config.mode, RunMode::Rule);
        assert_eq!(report.config.mixed_port, 7890);

        // Reload from disk via strict `ClashConfig::from_file` (`load_active_config`) to guarantee
        // subsequent app restarts never fail on persisted subscription YAML.
        let (reloaded, _) = mgr
            .load_active_config()
            .expect("persisted subscription YAML must pass strict reload");
        assert_eq!(reloaded.proxies.len(), 2);
        assert_eq!(reloaded.mode, RunMode::Rule);

        // Verify failed unified subscription import never stacks "Configuration error: " multiple times.
        serve_bad.store(true, std::sync::atomic::Ordering::Release);
        let bad_err = mgr
            .import_unified_input(&sub_url, Some("BrokenSub"), true, true)
            .await
            .unwrap_err()
            .to_string();
        assert!(
            bad_err.starts_with("Configuration error: "),
            "expected Configuration error prefix, got: {bad_err}"
        );
        assert!(
            !bad_err.contains("Configuration error: Configuration error:"),
            "must not duplicate Configuration error prefix: {bad_err}"
        );
        assert!(
            !bad_err.contains("secret-sub-tok"),
            "must redact token in error: {bad_err}"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn select_group_defaults_honor_leading_direct_reject_and_migrate_v036_index() {
        let dir = std::env::temp_dir().join(format!("rc-select-defaults-{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();

        let sub_yaml = r#"
mixed-port: 7890
mode: rule
dns:
  enable: true
  nameserver:
    - 223.5.5.5:53
proxies:
  - name: HK-Node-1x
    type: anytls
    server: hk.example.com
    port: 443
    password: dummy-password-hk
  - name: JP-Node-3x
    type: anytls
    server: jp.example.com
    port: 443
    password: dummy-password-jp
proxy-groups:
  - name: "🚀 节点选择"
    type: select
    proxies:
      - HK-Node-1x
      - JP-Node-3x
  - name: "🎥 NETFLIX"
    type: select
    proxies:
      - "🚀 节点选择"
      - DIRECT
      - HK-Node-1x
  - name: "📺 Bilibili"
    type: select
    proxies:
      - DIRECT
      - "🚀 节点选择"
      - HK-Node-1x
      - JP-Node-3x
  - name: "🛑 广告拦截"
    type: select
    proxies:
      - REJECT
      - DIRECT
rules:
  - DOMAIN-SUFFIX,bilibili.com,📺 Bilibili
  - DOMAIN-SUFFIX,netflix.com,🎥 NETFLIX
  - DOMAIN-SUFFIX,ad.example.com,🛑 广告拦截
  - MATCH,🚀 节点选择
"#;

        let mgr = ProfileManager::open_or_init(&dir).unwrap();
        let report = mgr
            .import_unified_input(sub_yaml, Some("MultiGroupSub"), true, true)
            .await
            .unwrap();

        assert_eq!(
            report
                .selected_groups
                .get("🚀 节点选择")
                .map(String::as_str),
            Some("HK-Node-1x")
        );
        assert_eq!(
            report.selected_groups.get("🎥 NETFLIX").map(String::as_str),
            Some("🚀 节点选择")
        );
        assert_eq!(
            report
                .selected_groups
                .get("📺 Bilibili")
                .map(String::as_str),
            Some("DIRECT"),
            "select group with leading DIRECT must default to DIRECT, never skip to proxy group"
        );
        assert_eq!(
            report
                .selected_groups
                .get("🛑 广告拦截")
                .map(String::as_str),
            Some("REJECT"),
            "select group with leading REJECT must default to REJECT"
        );

        // Verify Router::explain_route routes www.bilibili.com to DIRECT!
        let dns = Arc::new(crate::dns::FakeIpDnsEngine::new(&report.config.dns).unwrap());
        let outbounds = crate::engine::build_outbounds_with_dns(
            &report.config.proxies,
            &[],
            Some(Arc::clone(&dns)),
        )
        .unwrap();
        let router = Router::with_providers_mmdb_and_state_dir(
            report.config.mode,
            outbounds,
            &report.config.proxy_groups,
            &report.config.rules,
            &report.config.rule_providers,
            None,
            None,
            dns,
        )
        .unwrap();
        router.apply_saved_selections(&mgr.active_selected_groups());
        let target = crate::addr::TargetAddr::new_domain("www.bilibili.com", 443).unwrap();
        let decision = router.route_async(None, &target).await;
        assert_eq!(decision.outbound.exit_category(), "DIRECT");
        assert_eq!(decision.outbound.name(), "DIRECT");
        assert_eq!(decision.chains, vec!["DIRECT", "📺 Bilibili"]);

        // Simulate a <= v0.3.6 `profiles_index.json` (without `selection_defaults_v2`) where
        // `📺 Bilibili` had been auto-forced to `"🚀 节点选择"` while user picked `JP-Node-3x`
        // in `"🚀 节点选择"`.
        let active_id = mgr.active_profile_id();
        drop(mgr);
        let index_path = dir.join("profiles").join(INDEX_FILE);
        let mut idx_val: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&index_path).unwrap()).unwrap();
        idx_val
            .as_object_mut()
            .unwrap()
            .remove("selection_defaults_v2");
        for p in idx_val["profiles"].as_array_mut().unwrap() {
            if p["id"].as_str() == Some(&active_id) {
                p["selected_groups"]["🚀 节点选择"] = serde_json::json!("JP-Node-3x");
                p["selected_groups"]["📺 Bilibili"] = serde_json::json!("🚀 节点选择");
                p["selected_groups"]["🛑 广告拦截"] = serde_json::json!("🚀 节点选择");
            }
        }
        fs::write(&index_path, serde_json::to_string_pretty(&idx_val).unwrap()).unwrap();

        let mgr_migrated = ProfileManager::open_or_init(&dir).unwrap();
        let healed = mgr_migrated.active_selected_groups();
        assert_eq!(
            healed.get("🚀 节点选择").map(String::as_str),
            Some("JP-Node-3x"),
            "user node selection in primary group must remain untouched across migration"
        );
        assert_eq!(
            healed.get("📺 Bilibili").map(String::as_str),
            Some("DIRECT"),
            "one-time migration must restore leading DIRECT default on <= v0.3.6 profiles"
        );

        // Once migrated (`selection_defaults_v2 == true`), an intentional manual switch of
        // `📺 Bilibili` to `JP-Node-3x` (or back to `DIRECT`) MUST persist across restarts!
        mgr_migrated
            .save_group_selection("📺 Bilibili", "JP-Node-3x")
            .unwrap();
        drop(mgr_migrated);
        let mgr_reopened = ProfileManager::open_or_init(&dir).unwrap();
        assert_eq!(
            mgr_reopened
                .active_selected_groups()
                .get("📺 Bilibili")
                .map(String::as_str),
            Some("JP-Node-3x")
        );
        mgr_reopened
            .save_group_selection("📺 Bilibili", "DIRECT")
            .unwrap();
        drop(mgr_reopened);
        let mgr_reopened2 = ProfileManager::open_or_init(&dir).unwrap();
        assert_eq!(
            mgr_reopened2
                .active_selected_groups()
                .get("📺 Bilibili")
                .map(String::as_str),
            Some("DIRECT")
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn active_only_due_auto_update_and_legacy_smart_cn_migration_work() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let dir = std::env::temp_dir().join(format!("rc-active-due-mig-{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();

        // Spin up local TLS server with self-signed CA on 127.0.0.1 (IP literal) and localhost (domain)
        let (server_tls_cfg, ca_der) =
            generate_self_signed_server_config(&["localhost".into(), "127.0.0.1".into()], &[])
                .unwrap();
        let acceptor = TlsAcceptor::from(server_tls_cfg);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let psk = STANDARD.encode([0x44u8; 32]);
        let valid_uri = format!(
            "ss://{}@127.0.0.1:8388#Due-Node",
            STANDARD.encode(format!("2022-blake3-aes-256-gcm:{psk}"))
        );
        let b64_sub = STANDARD.encode(&valid_uri);
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let acc = acceptor.clone();
                let body = b64_sub.clone();
                tokio::spawn(async move {
                    let Ok(mut tls) = acc.accept(tcp).await else {
                        return;
                    };
                    let mut req_buf = [0u8; 2048];
                    let _ = tls.read(&mut req_buf).await;
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = tls.write_all(resp.as_bytes()).await;
                    let _ = tls.shutdown().await;
                });
            }
        });

        let mgr = ProfileManager::open_or_init_with_ca(&dir, vec![ca_der]).unwrap();
        let ip_sub_url = format!("https://127.0.0.1:{}/sub?token=t1", addr.port());
        let dom_sub_url = format!("https://localhost:{}/sub?token=t2", addr.port());

        // Import unnamed IP-host subscription -> must default to "HTTPS Subscription" (never raw IP)
        mgr.import_unified_input_with_options(&ip_sub_url, None, true, true, Some(60))
            .await
            .unwrap();
        let ip_prof = mgr
            .snapshot()
            .profiles
            .into_iter()
            .find(|p| p.id == mgr.active_profile_id())
            .unwrap();
        assert_eq!(ip_prof.name, "HTTPS Subscription");

        // Import unnamed domain-host subscription -> becomes active
        mgr.import_unified_input_with_options(&dom_sub_url, None, true, true, Some(60))
            .await
            .unwrap();
        let dom_prof = mgr
            .snapshot()
            .profiles
            .into_iter()
            .find(|p| p.id == mgr.active_profile_id())
            .unwrap();
        assert_eq!(dom_prof.name, "Sub (localhost)");

        // Backdate BOTH subscriptions so both are overdue, while only `dom_prof` is active
        {
            let mut idx = mgr.index.lock();
            for p in &mut idx.profiles {
                if p.kind == ProfileKind::Subscription {
                    p.last_updated_ms = 1;
                }
            }
        }
        assert_eq!(
            mgr.due_auto_update_ids(),
            vec![dom_prof.id.clone()],
            "due_auto_update_ids must return ONLY the active subscription and skip overdue inactive subscriptions"
        );

        // Switch active profile to starter -> neither subscription is active, so due list is empty!
        let starter_id = mgr
            .snapshot()
            .profiles
            .into_iter()
            .find(|p| p.kind == ProfileKind::Starter)
            .unwrap()
            .id;
        mgr.set_active_profile(&starter_id).unwrap();
        assert!(
            mgr.due_auto_update_ids().is_empty(),
            "inactive subscriptions must not be scheduled when starter profile is active"
        );

        // Switch active profile to `ip_prof` -> now only `ip_prof` is returned!
        mgr.set_active_profile(&ip_prof.id).unwrap();
        assert_eq!(mgr.due_auto_update_ids(), vec![ip_prof.id.clone()]);

        // Verify legacy <= v0.2.1 `GEOIP,CN,DIRECT` starter rules migrate to zero-leak `smart-cn`
        mgr.set_active_profile(&starter_id).unwrap();
        let starter_yaml_path = mgr.profile_yaml_path(&starter_id);
        drop(mgr);

        let mut legacy_cfg = ClashConfig::from_file(&starter_yaml_path).unwrap();
        legacy_cfg.rules = vec![
            "IP-CIDR,127.0.0.0/8,DIRECT,no-resolve".to_string(),
            "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve".to_string(),
            "IP-CIDR,172.16.0.0/12,DIRECT,no-resolve".to_string(),
            "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve".to_string(),
            "GEOIP,CN,DIRECT".to_string(),
            "MATCH,PROXY".to_string(),
        ];
        fs::write(&starter_yaml_path, legacy_cfg.to_yaml_string().unwrap()).unwrap();

        let mgr_upgraded = ProfileManager::open_or_init(&dir).unwrap();
        let (upgraded_cfg, _) = mgr_upgraded.load_active_config().unwrap();
        assert_eq!(
            upgraded_cfg.rules,
            ClashConfig::smart_cn_rules_for_group("PROXY"),
            "untouched legacy starter rules must migrate to zero-leak smart-cn on open_or_init"
        );

        let _ = fs::remove_dir_all(&dir);
    }
}

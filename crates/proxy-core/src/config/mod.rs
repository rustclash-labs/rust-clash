pub mod uri;

use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, SocketAddr},
    path::Path,
};

use ipnet::{IpNet, Ipv4Net};
use serde::{Deserialize, Serialize};

use crate::{
    dns::upstream::{BootstrapDnsServer, DnsUpstream},
    error::{ProxyError, Result},
    router::rules::CompiledRule,
};

pub const REDACTED_SECRET: &str = "***REDACTED***";

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RunMode {
    #[default]
    Rule,
    Global,
    Direct,
}

impl<'de> Deserialize<'de> for RunMode {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        match raw.trim().to_ascii_lowercase().as_str() {
            "" | "rule" | "script" => Ok(Self::Rule),
            "global" => Ok(Self::Global),
            "direct" => Ok(Self::Direct),
            other => Err(serde::de::Error::custom(format!(
                "unknown mode `{other}`, expected one of `rule`, `global`, `direct`"
            ))),
        }
    }
}

impl RunMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Rule => "rule",
            Self::Global => "global",
            Self::Direct => "direct",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct RuleProviderConfig {
    #[serde(rename = "type", default = "default_provider_type")]
    pub provider_type: String,
    #[serde(default = "default_provider_behavior")]
    pub behavior: String,
    #[serde(default = "default_provider_format")]
    pub format: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default = "default_provider_interval")]
    pub interval: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub payload: Vec<String>,
}

fn default_provider_type() -> String {
    "http".to_string()
}

fn default_provider_behavior() -> String {
    "domain".to_string()
}

fn default_provider_format() -> String {
    "yaml".to_string()
}

fn default_provider_interval() -> u64 {
    86_400
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ClashConfig {
    #[serde(default = "default_mixed_port")]
    pub mixed_port: u16,

    #[serde(default = "default_bind_address")]
    pub bind_address: String,

    #[serde(default)]
    pub allow_lan: bool,

    /// Optional `username:password` credentials enforced on Mixed Inbound (HTTP & SOCKS5).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authentication: Vec<String>,

    /// Optional CIDR allowlist enforced when `allow-lan: true`. When empty, defaults to private/LAN ranges.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub lan_allowed_ips: Vec<String>,

    #[serde(default)]
    pub mode: RunMode,

    #[serde(default = "default_log_level")]
    pub log_level: String,

    #[serde(default = "default_external_controller")]
    pub external_controller: String,

    #[serde(default)]
    pub secret: Option<String>,

    #[serde(default = "default_unified_delay", alias = "unified_delay")]
    pub unified_delay: bool,

    #[serde(default)]
    pub geodata_mode: bool,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mmdb_path: Option<String>,

    #[serde(default)]
    pub dns: DnsConfig,

    #[serde(
        default,
        skip_serializing_if = "HashMap::is_empty",
        deserialize_with = "deserialize_string_or_vec_map"
    )]
    pub hosts: HashMap<String, Vec<String>>,

    #[serde(default)]
    pub tun: TunConfig,

    #[serde(default)]
    pub proxies: Vec<ProxyNodeConfig>,

    #[serde(default)]
    pub proxy_groups: Vec<ProxyGroupConfig>,

    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub rule_providers: HashMap<String, RuleProviderConfig>,

    #[serde(default)]
    pub rules: Vec<String>,
}

fn default_mixed_port() -> u16 {
    7890
}

fn default_bind_address() -> String {
    "127.0.0.1".to_string()
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_external_controller() -> String {
    "127.0.0.1:9090".to_string()
}

fn default_unified_delay() -> bool {
    true
}

impl Default for ClashConfig {
    fn default() -> Self {
        Self {
            mixed_port: default_mixed_port(),
            bind_address: default_bind_address(),
            allow_lan: false,
            authentication: Vec::new(),
            lan_allowed_ips: Vec::new(),
            mode: RunMode::Rule,
            log_level: default_log_level(),
            external_controller: default_external_controller(),
            secret: None,
            unified_delay: default_unified_delay(),
            geodata_mode: false,
            mmdb_path: None,
            dns: DnsConfig::default(),
            hosts: HashMap::new(),
            tun: TunConfig::default(),
            proxies: Vec::new(),
            proxy_groups: Vec::new(),
            rule_providers: HashMap::new(),
            rules: vec!["MATCH,DIRECT".to_string()],
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkippedProxyEntry {
    pub name: String,
    pub protocol: String,
    pub reason: String,
}

pub(crate) type YamlValue = serde_json::Value;
pub(crate) type YamlMap = serde_json::Map<String, serde_json::Value>;

struct YamlJsonDoc(YamlValue);

impl<'de> Deserialize<'de> for YamlJsonDoc {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct YamlJsonVisitor;

        impl<'de> serde::de::Visitor<'de> for YamlJsonVisitor {
            type Value = YamlJsonDoc;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("any valid YAML value")
            }

            fn visit_bool<E>(self, v: bool) -> std::result::Result<Self::Value, E> {
                Ok(YamlJsonDoc(YamlValue::Bool(v)))
            }

            fn visit_i64<E>(self, v: i64) -> std::result::Result<Self::Value, E> {
                Ok(YamlJsonDoc(YamlValue::Number(v.into())))
            }

            fn visit_i128<E>(self, v: i128) -> std::result::Result<Self::Value, E> {
                if let Ok(n) = i64::try_from(v) {
                    Ok(YamlJsonDoc(YamlValue::Number(n.into())))
                } else {
                    Ok(YamlJsonDoc(YamlValue::String(v.to_string())))
                }
            }

            fn visit_u64<E>(self, v: u64) -> std::result::Result<Self::Value, E> {
                Ok(YamlJsonDoc(YamlValue::Number(v.into())))
            }

            fn visit_u128<E>(self, v: u128) -> std::result::Result<Self::Value, E> {
                if let Ok(n) = u64::try_from(v) {
                    Ok(YamlJsonDoc(YamlValue::Number(n.into())))
                } else {
                    Ok(YamlJsonDoc(YamlValue::String(v.to_string())))
                }
            }

            fn visit_f64<E>(self, v: f64) -> std::result::Result<Self::Value, E> {
                Ok(YamlJsonDoc(
                    serde_json::Number::from_f64(v)
                        .map(YamlValue::Number)
                        .unwrap_or_else(|| YamlValue::String(v.to_string())),
                ))
            }

            fn visit_str<E>(self, v: &str) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(YamlJsonDoc(YamlValue::String(v.to_owned())))
            }

            fn visit_string<E>(self, v: String) -> std::result::Result<Self::Value, E> {
                Ok(YamlJsonDoc(YamlValue::String(v)))
            }

            fn visit_bytes<E>(self, v: &[u8]) -> std::result::Result<Self::Value, E> {
                Ok(YamlJsonDoc(YamlValue::String(
                    String::from_utf8_lossy(v).into_owned(),
                )))
            }

            fn visit_byte_buf<E>(self, v: Vec<u8>) -> std::result::Result<Self::Value, E> {
                let s = String::from_utf8(v)
                    .unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned());
                Ok(YamlJsonDoc(YamlValue::String(s)))
            }

            fn visit_none<E>(self) -> std::result::Result<Self::Value, E> {
                Ok(YamlJsonDoc(YamlValue::Null))
            }

            fn visit_some<D2>(self, deserializer: D2) -> std::result::Result<Self::Value, D2::Error>
            where
                D2: serde::Deserializer<'de>,
            {
                deserializer.deserialize_any(self)
            }

            fn visit_unit<E>(self) -> std::result::Result<Self::Value, E> {
                Ok(YamlJsonDoc(YamlValue::Null))
            }

            fn visit_newtype_struct<D2>(
                self,
                deserializer: D2,
            ) -> std::result::Result<Self::Value, D2::Error>
            where
                D2: serde::Deserializer<'de>,
            {
                deserializer.deserialize_any(self)
            }

            fn visit_seq<A>(self, mut access: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut vec = Vec::with_capacity(access.size_hint().unwrap_or(0).min(1024));
                while let Some(elem) = access.next_element::<YamlJsonDoc>()? {
                    vec.push(elem.0);
                }
                Ok(YamlJsonDoc(YamlValue::Array(vec)))
            }

            fn visit_map<A>(self, mut access: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let mut map = YamlMap::with_capacity(access.size_hint().unwrap_or(0).min(1024));
                while let Some((k, v)) = access.next_entry::<YamlJsonDoc, YamlJsonDoc>()? {
                    let key_str = match k.0 {
                        YamlValue::String(s) => s,
                        YamlValue::Number(n) => n.to_string(),
                        YamlValue::Bool(b) => b.to_string(),
                        YamlValue::Null | YamlValue::Array(_) | YamlValue::Object(_) => continue,
                    };
                    map.insert(key_str, v.0);
                }
                Ok(YamlJsonDoc(YamlValue::Object(map)))
            }
        }

        deserializer.deserialize_any(YamlJsonVisitor)
    }
}

fn clash_yaml_parse_options() -> serde_saphyr::Options {
    serde_saphyr::options! {
        budget: serde_saphyr::budget! {
            max_depth: 64,
            max_documents: 32,
            max_nodes: 100_000,
            max_events: 250_000,
            max_aliases: 10_000,
            max_anchors: 10_000,
            max_merge_keys: 10_000,
            max_recorded_anchor_events: 200_000,
            max_recorded_anchor_bytes: 16 * 1024 * 1024,
            max_total_scalar_bytes: 16 * 1024 * 1024,
            enforce_alias_anchor_ratio: false,
        },
        alias_limits: serde_saphyr::alias_limits! {
            max_total_replayed_events: 200_000,
            max_replay_stack_depth: 32,
        },
        duplicate_keys: serde_saphyr::DuplicateKeyPolicy::LastWins,
        merge_keys: serde_saphyr::MergeKeyPolicy::Merge,
        strict_booleans: true,
        leading_zero_numbers_as_strings: true,
        non_finite_float_policy: serde_saphyr::NonFiniteFloatPolicy::AsString,
        with_snippet: false,
        crop_radius: 0,
    }
}

pub(crate) fn parse_yaml_value_with_merges(yaml: &str) -> Result<YamlValue> {
    let trimmed = uri::trim_bom_and_controls(yaml);
    let cleaned: std::borrow::Cow<'_, str> = if trimmed.contains('\0') {
        std::borrow::Cow::Owned(trimmed.replace('\0', ""))
    } else {
        std::borrow::Cow::Borrowed(trimmed)
    };

    let docs = serde_saphyr::from_multiple_with_options::<YamlJsonDoc>(
        &cleaned,
        clash_yaml_parse_options(),
    )
    .map_err(|e| {
        ProxyError::Config(format!(
            "YAML parse error: {}",
            uri::redact_sensitive_text(&e.to_string())
        ))
    })?;

    let mut first_mapping: Option<YamlValue> = None;
    let mut first_non_null: Option<YamlValue> = None;
    for YamlJsonDoc(val) in docs {
        if val.is_null() {
            continue;
        }
        if val.is_object() {
            first_mapping = Some(val);
            break;
        }
        if first_non_null.is_none() {
            first_non_null = Some(val);
        }
    }

    let mut root = first_mapping.or(first_non_null).unwrap_or(YamlValue::Null);
    let mut budget = 100_000usize;
    resolve_yaml_merge_keys(&mut root, 0, &mut budget)?;
    Ok(root)
}

fn resolve_yaml_merge_keys(val: &mut YamlValue, depth: usize, budget: &mut usize) -> Result<()> {
    if depth > 64 {
        return Err(ProxyError::Config(
            "YAML nesting depth exceeds safety limit (64)".into(),
        ));
    }
    *budget = budget.saturating_sub(1);
    if *budget == 0 {
        return Err(ProxyError::Config(
            "YAML anchor/merge complexity exceeds safety limit".into(),
        ));
    }

    match val {
        YamlValue::Array(seq) => {
            for item in seq.iter_mut() {
                resolve_yaml_merge_keys(item, depth + 1, budget)?;
            }
        }
        YamlValue::Object(map) => {
            for (_, v) in map.iter_mut() {
                resolve_yaml_merge_keys(v, depth + 1, budget)?;
            }
            if let Some(merge_val) = map.swap_remove("<<") {
                match merge_val {
                    YamlValue::Object(src_map) => {
                        for (k, v) in src_map {
                            if !map.contains_key(&k) {
                                map.insert(k, v);
                            }
                        }
                    }
                    YamlValue::Array(seq) => {
                        for elem in seq {
                            if let YamlValue::Object(src_map) = elem {
                                for (k, v) in src_map {
                                    if !map.contains_key(&k) {
                                        map.insert(k, v);
                                    }
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        _ => {}
    }
    Ok(())
}

impl ClashConfig {
    pub fn from_yaml_str(yaml: &str) -> Result<Self> {
        let cfg = Self::from_yaml_str_unchecked(yaml)?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn from_yaml_str_unchecked(yaml: &str) -> Result<Self> {
        let mut root = parse_yaml_value_with_merges(yaml)?;
        let YamlValue::Object(ref mut map) = root else {
            return Err(ProxyError::Config(
                "YAML configuration root must be a key-value mapping".into(),
            ));
        };
        normalize_clash_yaml_root_mapping(map, false);
        validate_raw_yaml_proxies(map)?;
        expand_proxy_groups_yaml(map, false);
        let mut cfg: Self = serde_path_to_error::deserialize(root).map_err(|e| {
            let path = e.path().to_string();
            let detail = uri::redact_sensitive_text(&e.inner().to_string());
            if path.is_empty() || path == "." {
                ProxyError::Config(format!("YAML parse error: {detail}"))
            } else {
                ProxyError::Config(format!(
                    "YAML parse error at '{}': {detail}",
                    uri::redact_sensitive_text(&path)
                ))
            }
        })?;
        cfg.sync_root_hosts_into_dns();
        Ok(cfg)
    }

    pub fn sync_root_hosts_into_dns(&mut self) {
        for (k, v) in &self.hosts {
            self.dns.hosts.entry(k.clone()).or_insert_with(|| v.clone());
        }
    }

    pub fn dns_with_merged_hosts(&self) -> DnsConfig {
        if self.hosts.is_empty() {
            return self.dns.clone();
        }
        let mut merged = self.dns.clone();
        for (k, v) in &self.hosts {
            merged.hosts.entry(k.clone()).or_insert_with(|| v.clone());
        }
        merged
    }

    /// Parse a Clash YAML profile with best-effort sanitization for mixed multi-protocol subscriptions:
    /// - Unsupported or malformed individual `proxies` entries are collected into `Vec<SkippedProxyEntry>`
    ///   (with all secrets scrubbed) and pruned from `proxy-groups` / rules when `>= 1` valid proxy node remains.
    /// - Common V2Board / Xboard / Subconverter / Mihomo subscription conventions (`mode: Rule`,
    ///   `tun.dns-hijack` sequences, `tun.inet6-address` sequences, `include-all`, empty regional filter groups,
    ///   unsupported rule types, `:53` / `:9090` listeners) are normalized into valid `ClashConfig` structures.
    /// - If `skipped` is non-empty and `0` valid proxy nodes remain, fails closed with the redacted error!
    pub fn from_yaml_str_sanitized(yaml: &str) -> Result<(Self, Vec<SkippedProxyEntry>)> {
        let mut root = parse_yaml_value_with_merges(yaml)?;
        let YamlValue::Object(ref mut map) = root else {
            return Err(ProxyError::Config(
                "YAML configuration root must be a key-value mapping".into(),
            ));
        };

        normalize_clash_yaml_root_mapping(map, true);

        let mut skipped = Vec::new();
        let mut first_err: Option<ProxyError> = None;
        let mut skipped_names = HashSet::new();

        if let Some(proxies_val) = map.get("proxies").cloned()
            && !proxies_val.is_null()
        {
            let YamlValue::Array(seq) = proxies_val else {
                return Err(ProxyError::Config(
                    "'proxies' field in YAML must be a list".into(),
                ));
            };
            let mut kept_seq = Vec::with_capacity(seq.len());
            for (idx, item) in seq.into_iter().enumerate() {
                match validate_and_parse_single_yaml_proxy(idx, &item) {
                    Ok(_) => kept_seq.push(item),
                    Err((entry, err)) => {
                        skipped_names.insert(entry.name.clone());
                        skipped.push(entry);
                        if first_err.is_none() {
                            first_err = Some(err);
                        }
                    }
                }
            }
            for kept_item in &kept_seq {
                if let Some(pmap) = kept_item.as_object()
                    && let Some(kept_name) = yaml_str_field(pmap, "name")
                {
                    skipped_names.remove(kept_name.trim());
                }
            }
            if !skipped.is_empty() && kept_seq.is_empty() {
                if skipped.len() == 1 {
                    return Err(first_err.unwrap_or_else(|| {
                        ProxyError::Config("no supported proxy nodes found in YAML profile".into())
                    }));
                }
                let mut protos: Vec<String> = Vec::new();
                for s in &skipped {
                    if !protos.contains(&s.protocol) {
                        protos.push(s.protocol.clone());
                    }
                }
                let first_reason = first_err
                    .map(|e| e.to_string())
                    .unwrap_or_else(|| "unsupported node configuration".to_string());
                return Err(ProxyError::Config(format!(
                    "no supported proxy nodes found ({} entries skipped, protocols: {}; first reason: {})",
                    skipped.len(),
                    protos.join(", "),
                    uri::redact_sensitive_text(
                        first_reason
                            .strip_prefix("Configuration error: ")
                            .unwrap_or(&first_reason)
                    )
                )));
            }
            map.insert(yaml_key("proxies"), YamlValue::Array(kept_seq));
        }

        expand_proxy_groups_yaml(map, true);

        let mut cfg: Self = serde_path_to_error::deserialize(root).map_err(|e| {
            let path = e.path().to_string();
            let detail = uri::redact_sensitive_text(&e.inner().to_string());
            if path.is_empty() || path == "." {
                ProxyError::Config(format!("YAML parse error: {detail}"))
            } else {
                ProxyError::Config(format!(
                    "YAML parse error at '{}': {detail}",
                    uri::redact_sensitive_text(&path)
                ))
            }
        })?;

        cfg.sync_root_hosts_into_dns();
        sanitize_subscription_groups_and_rules(&mut cfg, &skipped_names);

        cfg.validate()?;
        Ok((cfg, skipped))
    }

    pub fn from_file(path: impl AsRef<Path>) -> Result<Self> {
        let raw = std::fs::read_to_string(path.as_ref()).map_err(|e| {
            ProxyError::Config(format!(
                "failed reading config {}: {e}",
                path.as_ref().display()
            ))
        })?;
        Self::from_yaml_str(&raw)
    }

    pub fn to_yaml_string(&self) -> Result<String> {
        serde_saphyr::to_string(self)
            .map_err(|e| ProxyError::Config(format!("YAML serialize error: {e}")))
    }

    /// Ensures `self.secret` contains a non-empty controller secret, generating a
    /// 256-bit OS CSPRNG hex secret if `self.secret` is `None` or whitespace-only.
    pub fn ensure_ephemeral_secret(&mut self) -> String {
        if let Some(existing) = self
            .secret
            .as_ref()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
        {
            let normalized = existing.to_string();
            self.secret = Some(normalized.clone());
            return normalized;
        }
        let secret = crate::api::generate_ephemeral_secret();
        self.secret = Some(secret.clone());
        secret
    }

    /// Managed default split-tunneling rule template (`smart-cn`):
    /// - LAN / mDNS domains (`local`, `lan`, `home.arpa`) & private IPs -> `DIRECT`
    /// - Known international websites (`GEOSITE,geolocation-!cn`) -> `<primary_group>` (0 local DNS leak!)
    /// - Domestic CN websites (`GEOSITE,cn`) & literal CN IPs (`GEOIP,CN,DIRECT,no-resolve`) -> `DIRECT`
    /// - Remaining unmatched traffic -> `<primary_group>` (domain forwarded encrypted, 0 local DNS leak!)
    pub fn smart_cn_rules_for_group(primary_group: &str) -> Vec<String> {
        let g = if primary_group.trim().is_empty() {
            "PROXY"
        } else {
            primary_group.trim()
        };
        vec![
            "DOMAIN-SUFFIX,local,DIRECT".to_string(),
            "DOMAIN-SUFFIX,lan,DIRECT".to_string(),
            "DOMAIN-SUFFIX,home.arpa,DIRECT".to_string(),
            "GEOIP,PRIVATE,DIRECT,no-resolve".to_string(),
            format!("GEOSITE,geolocation-!cn,{g}"),
            "GEOSITE,cn,DIRECT".to_string(),
            "GEOIP,CN,DIRECT,no-resolve".to_string(),
            format!("MATCH,{g}"),
        ]
    }

    /// Clean, self-contained Real-User starter configuration with Mainland-reachable direct DNS
    /// and domestic-direct / international-proxy (`smart-cn`) split-tunneling rules.
    pub fn default_starter_yaml() -> String {
        r#"mixed-port: 7890
bind-address: 127.0.0.1
allow-lan: false
mode: rule
log-level: info
external-controller: 127.0.0.1:9090
dns:
  enable: true
  ipv6: false
  listen: 127.0.0.1:0
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/15
  default-nameserver:
    - 223.5.5.5:53
    - 119.29.29.29:53
    - 1.1.1.1:53
  direct-nameserver:
    - 223.5.5.5:53
    - 119.29.29.29:53
  nameserver:
    - 223.5.5.5:53
    - 119.29.29.29:53
    - 1.1.1.1:53
tun:
  enable: false
  device: Clash
  mtu: 1500
  auto-route: true
  strict-route: false
  ipv6: false
proxies: []
proxy-groups:
  - name: PROXY
    type: select
    proxies:
      - DIRECT
rules:
  - DOMAIN-SUFFIX,local,DIRECT
  - DOMAIN-SUFFIX,lan,DIRECT
  - DOMAIN-SUFFIX,home.arpa,DIRECT
  - GEOIP,PRIVATE,DIRECT,no-resolve
  - GEOSITE,geolocation-!cn,PROXY
  - GEOSITE,cn,DIRECT
  - GEOIP,CN,DIRECT,no-resolve
  - MATCH,PROXY
"#
        .to_string()
    }

    pub fn redacted(&self) -> Self {
        let mut copy = self.clone();
        if copy.secret.as_ref().is_some_and(|s| !s.is_empty()) {
            copy.secret = Some(REDACTED_SECRET.to_string());
        }
        copy.authentication = copy
            .authentication
            .iter()
            .map(|entry| match entry.split_once(':') {
                Some((user, _)) => format!("{user}:{REDACTED_SECRET}"),
                None => REDACTED_SECRET.to_string(),
            })
            .collect();
        for node in &mut copy.proxies {
            *node = node.redacted_clone();
        }
        for prov in copy.rule_providers.values_mut() {
            if let Some(ref mut u) = prov.url
                && let Ok(mut parsed) = url::Url::parse(u)
            {
                let mut changed = false;
                if !parsed.username().is_empty() || parsed.password().is_some() {
                    let _ = parsed.set_password(Some(REDACTED_SECRET));
                    changed = true;
                }
                if parsed.query().is_some() {
                    let pairs: Vec<(String, String)> = parsed
                        .query_pairs()
                        .map(|(k, v)| (k.into_owned(), v.into_owned()))
                        .collect();
                    if pairs
                        .iter()
                        .any(|(k, v)| !v.is_empty() && is_sensitive_url_query_key(k))
                    {
                        {
                            let mut qp = parsed.query_pairs_mut();
                            qp.clear();
                            for (k, v) in pairs {
                                if !v.is_empty() && is_sensitive_url_query_key(&k) {
                                    qp.append_pair(&k, REDACTED_SECRET);
                                } else {
                                    qp.append_pair(&k, &v);
                                }
                            }
                        }
                        changed = true;
                    }
                }
                if changed {
                    *u = parsed.to_string();
                }
            }
        }
        copy
    }

    pub fn restore_redacted_from(&mut self, prev: &ClashConfig) {
        if self.secret.as_deref() == Some(REDACTED_SECRET) {
            self.secret = prev.secret.clone();
        }
        for entry in &mut self.authentication {
            if let Some((user, pass)) = entry.split_once(':')
                && pass == REDACTED_SECRET
                && let Some(orig) = prev
                    .authentication
                    .iter()
                    .find(|p| p.split_once(':').is_some_and(|(u, _)| u == user))
            {
                *entry = orig.clone();
            }
        }
        for node in &mut self.proxies {
            if let Some(prev_node) = prev.proxies.iter().find(|p| p.name() == node.name()) {
                node.restore_credentials_from(prev_node);
            }
        }
        for (k, prov) in &mut self.rule_providers {
            if prov
                .url
                .as_deref()
                .is_some_and(url_contains_redacted_placeholder)
                && let Some(prev_prov) = prev.rule_providers.get(k)
            {
                prov.url = prev_prov.url.clone();
            }
        }
    }

    pub fn validate(&self) -> Result<()> {
        let bind_trimmed = self.bind_address.trim();
        if bind_trimmed != "*" && bind_trimmed.parse::<IpAddr>().is_err() {
            return Err(ProxyError::Config(format!(
                "invalid bind-address '{}': expected IP address or '*'",
                self.bind_address
            )));
        }

        if self.mixed_port > 0
            && let Ok(ec_addr) = self.external_controller.trim().parse::<SocketAddr>()
            && ec_addr.port() == self.mixed_port
        {
            return Err(ProxyError::Config(format!(
                "mixed-port ({}) cannot be the same as external-controller port ({})",
                self.mixed_port, self.mixed_port
            )));
        }

        for auth in &self.authentication {
            let Some((user, _pass)) = auth.split_once(':') else {
                return Err(ProxyError::Config(
                    "authentication entry must be formatted as 'username:password'".into(),
                ));
            };
            if user.trim().is_empty() {
                return Err(ProxyError::Config(
                    "authentication username cannot be empty".into(),
                ));
            }
        }

        for cidr in &self.lan_allowed_ips {
            cidr.parse::<IpNet>().map_err(|e| {
                ProxyError::Config(format!("invalid lan-allowed-ips CIDR '{cidr}': {e}"))
            })?;
        }

        if !(576..=65535).contains(&self.tun.mtu) {
            return Err(ProxyError::Config(format!(
                "invalid tun.mtu {}: must be between 576 and 65535",
                self.tun.mtu
            )));
        }
        if let Some(ref v6_cidr) = self.tun.inet6_address {
            v6_cidr.parse::<ipnet::Ipv6Net>().map_err(|e| {
                ProxyError::Config(format!("invalid tun.inet6-address '{v6_cidr}': {e}"))
            })?;
        }

        self.dns.validate_with_extra_hosts(&self.hosts)?;

        let has_mmdb = if let Some(ref p) = self.mmdb_path {
            if !Path::new(p).is_file() {
                return Err(ProxyError::Config(format!(
                    "mmdb-path '{p}' does not exist or is not a file"
                )));
            }
            true
        } else {
            false
        };

        for (pname, pcfg) in &self.rule_providers {
            if pname.trim().is_empty() {
                return Err(ProxyError::Config(
                    "rule-provider name cannot be empty".into(),
                ));
            }
            let pt = pcfg.provider_type.trim().to_ascii_lowercase();
            if !matches!(pt.as_str(), "inline" | "file" | "http") {
                return Err(ProxyError::Config(format!(
                    "rule-provider '{pname}' has unsupported type '{}'",
                    pcfg.provider_type
                )));
            }
            let beh = pcfg.behavior.trim().to_ascii_lowercase();
            if !matches!(beh.as_str(), "domain" | "ipcidr" | "classical") {
                return Err(ProxyError::Config(format!(
                    "rule-provider '{pname}' has unsupported behavior '{}'",
                    pcfg.behavior
                )));
            }
            if let Some(ref raw_path) = pcfg.path {
                validate_rule_provider_path(pname, &pt, raw_path)?;
            }
        }

        let mut seen = HashSet::new();
        for builtin in ["DIRECT", "REJECT", "GLOBAL"] {
            seen.insert(builtin.to_string());
        }

        let mut concrete_names = HashSet::new();
        for p in &self.proxies {
            let name = p.name().trim();
            if name.is_empty() {
                return Err(ProxyError::Config("proxy name cannot be empty".into()));
            }
            if !seen.insert(name.to_string()) {
                return Err(ProxyError::Config(format!(
                    "duplicate proxy or reserved name: {name}"
                )));
            }
            validate_single_proxy_node(p)?;
            concrete_names.insert(name.to_string());
        }

        for g in &self.proxy_groups {
            let name = g.name.trim();
            if name.is_empty() {
                return Err(ProxyError::Config(
                    "proxy-group name cannot be empty".into(),
                ));
            }
            if !seen.insert(name.to_string()) {
                return Err(ProxyError::Config(format!(
                    "duplicate proxy-group name: {name}"
                )));
            }
            if g.proxies.is_empty() {
                return Err(ProxyError::Config(format!(
                    "proxy-group '{name}' must reference at least one proxy"
                )));
            }
        }

        validate_groups_and_rules_with_context(
            &concrete_names,
            &self.proxy_groups,
            &self.rules,
            Some(&self.rule_providers),
            has_mmdb,
        )
    }
}

fn validate_single_proxy_node(p: &ProxyNodeConfig) -> Result<()> {
    let name = p.name().trim();
    if name.is_empty() {
        return Err(ProxyError::Config("proxy name cannot be empty".into()));
    }
    let (srv, port) = p.server_port();
    if srv.trim().is_empty() {
        return Err(ProxyError::Config(format!(
            "proxy '{name}' server address cannot be empty"
        )));
    }
    if port == 0 {
        return Err(ProxyError::Config(format!(
            "proxy '{name}' port must be between 1 and 65535"
        )));
    }
    match p {
        ProxyNodeConfig::Ss {
            cipher, password, ..
        } => {
            let kind = crate::outbound::ss::crypto::SsCipherKind::parse(cipher.trim())?;
            if password.is_empty() || password == REDACTED_SECRET {
                return Err(ProxyError::Config(format!(
                    "Shadowsocks proxy '{name}' password cannot be empty or redacted"
                )));
            }
            kind.master_key(password).map_err(|_| {
                ProxyError::Config(format!(
                    "Shadowsocks proxy '{name}' has an invalid password/PSK for cipher '{}'",
                    cipher.trim()
                ))
            })?;
        }
        ProxyNodeConfig::Vless {
            uuid,
            encryption,
            flow,
            network,
            ..
        } => {
            if *uuid == uuid::Uuid::nil() {
                return Err(ProxyError::Config(format!(
                    "VLESS proxy '{name}' UUID cannot be nil (00000000-0000-0000-0000-000000000000)"
                )));
            }
            if let Some(net) = network {
                let n = net.trim();
                if !n.is_empty()
                    && !n.eq_ignore_ascii_case("tcp")
                    && !n.eq_ignore_ascii_case("raw")
                    && !n.eq_ignore_ascii_case("ws")
                {
                    return Err(ProxyError::Config(format!(
                        "VLESS proxy '{name}' specifies unsupported network '{n}' (supported: tcp, ws)"
                    )));
                }
            }
            if let Some(flow) = flow {
                let f = flow.trim();
                if !f.is_empty() && !f.eq_ignore_ascii_case("none") {
                    return Err(ProxyError::Config(format!(
                        "VLESS proxy '{name}' specifies unsupported flow '{f}' (XTLS/Vision flows are not supported; use standard TLS or mlkem768x25519plus encryption)"
                    )));
                }
            }
            if encryption == REDACTED_SECRET {
                return Err(ProxyError::Config(format!(
                    "VLESS proxy '{name}' encryption credential cannot remain redacted"
                )));
            }
            let enc = encryption.trim();
            if !enc.is_empty() && !enc.eq_ignore_ascii_case("none") {
                crate::outbound::vless::encryption::config::parse_client_encryption(enc).map_err(
                    |_| {
                        ProxyError::Config(format!(
                            "VLESS proxy '{name}' has an invalid or unsupported VLESS encryption parameter"
                        ))
                    },
                )?;
            }
        }
        ProxyNodeConfig::Anytls { password, .. } => {
            if password.is_empty() || password == REDACTED_SECRET {
                return Err(ProxyError::Config(format!(
                    "AnyTLS proxy '{name}' password cannot be empty or redacted"
                )));
            }
        }
        ProxyNodeConfig::Trojan {
            password, network, ..
        } => {
            if password.is_empty() || password == REDACTED_SECRET {
                return Err(ProxyError::Config(format!(
                    "Trojan proxy '{name}' password cannot be empty or redacted"
                )));
            }
            if let Some(net) = network {
                let n = net.trim();
                if !n.is_empty() && !n.eq_ignore_ascii_case("tcp") && !n.eq_ignore_ascii_case("ws")
                {
                    return Err(ProxyError::Config(format!(
                        "Trojan proxy '{name}' specifies unsupported network '{n}' (supported: tcp, ws)"
                    )));
                }
            }
        }
        ProxyNodeConfig::Socks5 { password, .. } | ProxyNodeConfig::Http { password, .. } => {
            if password.as_deref() == Some(REDACTED_SECRET) {
                return Err(ProxyError::Config(format!(
                    "proxy '{name}' password cannot remain redacted"
                )));
            }
        }
    }
    Ok(())
}

fn yaml_key(k: &str) -> String {
    k.to_string()
}

fn strip_null_entries(map: &mut YamlMap) {
    map.retain(|_, v| !v.is_null());
}

fn coerce_yaml_u64(val: &mut YamlValue) {
    match val {
        YamlValue::String(s) => {
            let trimmed = s.trim();
            if let Ok(n) = trimmed.parse::<u64>() {
                *val = YamlValue::Number(n.into());
            } else if let Some(num_part) = trimmed.strip_suffix('s')
                && let Ok(n) = num_part.trim().parse::<u64>()
            {
                *val = YamlValue::Number(n.into());
            }
        }
        YamlValue::Number(n) => {
            if n.as_u64().is_none()
                && let Some(f) = n.as_f64()
                && f.is_finite()
                && f >= 0.0
                && f <= (u64::MAX as f64)
                && f.fract() == 0.0
            {
                *val = YamlValue::Number((f as u64).into());
            }
        }
        _ => {}
    }
}

fn coerce_yaml_string(val: &mut YamlValue) {
    match val {
        YamlValue::Number(n) => {
            *val = YamlValue::String(n.to_string());
        }
        YamlValue::Bool(b) => {
            *val = YamlValue::String(b.to_string());
        }
        _ => {}
    }
}

fn coerce_yaml_bool(val: &mut YamlValue) {
    match val {
        YamlValue::String(s) => match s.trim().to_ascii_lowercase().as_str() {
            "true" | "1" | "yes" | "on" => *val = YamlValue::Bool(true),
            "false" | "0" | "no" | "off" | "none" | "" => *val = YamlValue::Bool(false),
            _ => {}
        },
        YamlValue::Number(n) => match n.as_u64() {
            Some(1) => *val = YamlValue::Bool(true),
            Some(0) => *val = YamlValue::Bool(false),
            _ => {}
        },
        _ => {}
    }
}

fn sanitize_yaml_string_seq(val: &mut YamlValue) {
    match val {
        YamlValue::String(s) => {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                *val = YamlValue::Array(Vec::new());
            } else {
                *val = YamlValue::Array(vec![YamlValue::String(trimmed.to_string())]);
            }
        }
        YamlValue::Array(seq) => {
            seq.retain(|item| !item.is_null());
            for item in seq.iter_mut() {
                coerce_yaml_string(item);
            }
        }
        _ => {}
    }
}

fn normalize_yaml_dns_hijack(val: &mut YamlValue) {
    match val {
        YamlValue::Bool(_) => {}
        YamlValue::Array(seq) => {
            let enabled = !seq.is_empty() && !seq.iter().all(yaml_value_is_effectively_empty);
            *val = YamlValue::Bool(enabled);
        }
        YamlValue::String(s) => {
            let low = s.trim().to_ascii_lowercase();
            let enabled = !matches!(low.as_str(), "" | "false" | "0" | "no" | "off" | "none");
            *val = YamlValue::Bool(enabled);
        }
        YamlValue::Number(n) => {
            *val = YamlValue::Bool(n.as_u64() != Some(0));
        }
        _ => {}
    }
}

fn normalize_go_host_port(raw: &str, default_addr: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return default_addr.to_string();
    }
    if let Some(port_str) = trimmed.strip_prefix(':')
        && port_str.trim().parse::<u16>().is_ok()
    {
        return format!("127.0.0.1:{}", port_str.trim());
    }
    trimmed.to_string()
}

fn normalize_proxy_yaml_item(item: &mut YamlValue) {
    let YamlValue::Object(pmap) = item else {
        return;
    };
    strip_null_entries(pmap);

    for str_k in [
        "name",
        "type",
        "server",
        "cipher",
        "password",
        "uuid",
        "encryption",
        "servername",
        "sni",
        "peer",
        "flow",
        "network",
        "transport",
        "username",
        "security",
        "ws-path",
    ] {
        if let Some(v) = pmap.get_mut(str_k) {
            coerce_yaml_string(v);
        }
    }
    if let Some(YamlValue::String(u)) = pmap.get_mut("uuid") {
        *u = u.trim().to_string();
    }
    if let Some(YamlValue::String(srv)) = pmap.get_mut("server") {
        let clean = srv
            .trim()
            .trim_start_matches('[')
            .trim_end_matches(']')
            .trim();
        *srv = clean.to_string();
    }

    let mut force_tls_default = false;
    let mut proto_lc = String::new();
    if let Some(YamlValue::String(t)) = pmap.get_mut("type") {
        let low = t.trim().to_ascii_lowercase();
        let mapped = match low.as_str() {
            "shadowsocks" => "ss",
            "socks" => "socks5",
            "https" => {
                force_tls_default = true;
                "http"
            }
            other => other,
        };
        proto_lc = mapped.to_string();
        *t = mapped.to_string();
    }
    if proto_lc == "vless"
        && !pmap.contains_key("tls")
        && yaml_str_field(pmap, "security").is_some_and(|s| s.trim().eq_ignore_ascii_case("tls"))
    {
        force_tls_default = true;
    }
    if force_tls_default && !pmap.contains_key("tls") {
        pmap.insert(yaml_key("tls"), YamlValue::Bool(true));
    }

    // Map legacy `peer` into SNI if neither `sni` nor `servername` is set
    if let Some(peer_val) = pmap.remove("peer")
        && !pmap.contains_key("sni")
        && !pmap.contains_key("servername")
        && peer_val.as_str().is_some_and(|s| !s.trim().is_empty())
    {
        pmap.insert(yaml_key("sni"), peer_val);
    }

    // Canonicalize alias pairs so serde never fails with `duplicate field` when both exist
    if pmap.contains_key("network") && pmap.contains_key("transport") {
        let transport_val = pmap.remove("transport");
        let net_empty = yaml_str_field(pmap, "network").is_none_or(|s| s.trim().is_empty());
        if net_empty && let Some(tv) = transport_val {
            pmap.insert(yaml_key("network"), tv);
        }
    }
    if proto_lc == "vless" {
        if pmap.contains_key("servername") && pmap.contains_key("sni") {
            let sni_val = pmap.remove("sni");
            let srv_empty = yaml_str_field(pmap, "servername").is_none_or(|s| s.trim().is_empty());
            if srv_empty && let Some(sv) = sni_val {
                pmap.insert(yaml_key("servername"), sv);
            }
        }
    } else if pmap.contains_key("sni") && pmap.contains_key("servername") {
        let srv_val = pmap.remove("servername");
        let sni_empty = yaml_str_field(pmap, "sni").is_none_or(|s| s.trim().is_empty());
        if sni_empty && let Some(sv) = srv_val {
            pmap.insert(yaml_key("sni"), sv);
        }
    }

    // Map legacy `allow-insecure` / `allowInsecure` / `insecure` -> `skip-cert-verify`
    for insecure_alias in ["allow-insecure", "allowInsecure", "insecure"] {
        if let Some(alias_val) = pmap.remove(insecure_alias)
            && !pmap.contains_key("skip-cert-verify")
        {
            pmap.insert(yaml_key("skip-cert-verify"), alias_val);
        }
    }

    // Map legacy top-level `ws-path` / `ws-headers` into `ws-opts`
    let legacy_ws_path = pmap.remove("ws-path");
    let legacy_ws_headers = pmap.remove("ws-headers");
    if !pmap.contains_key("ws-opts") && (legacy_ws_path.is_some() || legacy_ws_headers.is_some()) {
        let mut wmap = YamlMap::new();
        if let Some(p) = legacy_ws_path {
            wmap.insert(yaml_key("path"), p);
        }
        if let Some(h) = legacy_ws_headers {
            wmap.insert(yaml_key("headers"), h);
        }
        pmap.insert(yaml_key("ws-opts"), YamlValue::Object(wmap));
    }

    for num_k in [
        "port",
        "idle-session-check-interval",
        "idle-session-timeout",
        "min-idle-session",
    ] {
        if let Some(v) = pmap.get_mut(num_k) {
            coerce_yaml_u64(v);
        }
    }
    if let Some(YamlValue::String(s)) = pmap.get_mut("tls")
        && s.trim().eq_ignore_ascii_case("tls")
    {
        *pmap.get_mut("tls").unwrap() = YamlValue::Bool(true);
    }
    for bool_k in ["udp", "tls", "skip-cert-verify"] {
        if let Some(v) = pmap.get_mut(bool_k) {
            coerce_yaml_bool(v);
            if !v.is_boolean() {
                pmap.remove(bool_k);
            }
        }
    }
    if let Some(alpn_val) = pmap.get_mut("alpn") {
        match alpn_val {
            YamlValue::Bool(false) => {
                *alpn_val = YamlValue::Array(Vec::new());
            }
            YamlValue::String(s) => {
                let items: Vec<YamlValue> = s
                    .split(',')
                    .map(str::trim)
                    .filter(|p| !p.is_empty())
                    .map(|p| YamlValue::String(p.to_string()))
                    .collect();
                *alpn_val = YamlValue::Array(items);
            }
            YamlValue::Array(_) => {
                sanitize_yaml_string_seq(alpn_val);
            }
            _ => {}
        }
    }
    if let Some(YamlValue::Object(hmap)) = pmap.get_mut("headers") {
        strip_null_entries(hmap);
        for (_, hv) in hmap.iter_mut() {
            if let YamlValue::Array(seq) = hv
                && let Some(first) = seq.first().cloned()
            {
                *hv = first;
            }
            coerce_yaml_string(hv);
        }
    }
    if let Some(YamlValue::Object(wmap)) = pmap.get_mut("ws-opts") {
        strip_null_entries(wmap);
        for str_k in ["path", "early-data-header-name"] {
            if let Some(v) = wmap.get_mut(str_k) {
                coerce_yaml_string(v);
            }
        }
        if let Some(ed_val) = wmap.get_mut("max-early-data") {
            coerce_yaml_u64(ed_val);
        }
        if let Some(YamlValue::Object(hmap)) = wmap.get_mut("headers") {
            strip_null_entries(hmap);
            for (_, hv) in hmap.iter_mut() {
                if let YamlValue::Array(seq) = hv
                    && let Some(first) = seq.first().cloned()
                {
                    *hv = first;
                }
                coerce_yaml_string(hv);
            }
        }
    }
}

fn expand_proxy_groups_yaml(map: &mut YamlMap, lenient_subscription: bool) {
    let concrete_nodes: Vec<(String, String)> = map
        .get("proxies")
        .and_then(YamlValue::as_array)
        .map(|seq| {
            seq.iter()
                .filter_map(|v| v.as_object())
                .filter_map(|m| {
                    let name = yaml_str_field(m, "name")?.trim();
                    if name.is_empty() {
                        return None;
                    }
                    let proto = yaml_str_field(m, "type")
                        .unwrap_or("")
                        .trim()
                        .to_ascii_lowercase();
                    Some((name.to_owned(), proto))
                })
                .collect()
        })
        .unwrap_or_default();

    let Some(YamlValue::Array(gseq)) = map.get_mut("proxy-groups") else {
        return;
    };
    gseq.retain(|g| !g.is_null());

    for gval in gseq.iter_mut() {
        let YamlValue::Object(gmap) = gval else {
            continue;
        };
        strip_null_entries(gmap);
        for str_k in [
            "name",
            "type",
            "url",
            "strategy",
            "filter",
            "exclude-filter",
            "exclude-type",
        ] {
            if let Some(v) = gmap.get_mut(str_k) {
                coerce_yaml_string(v);
            }
        }
        if lenient_subscription {
            let valid_gtype = yaml_str_field(gmap, "type").is_some_and(|raw| {
                let norm: String = raw
                    .trim()
                    .chars()
                    .filter(|c| *c != '-' && *c != '_')
                    .map(|c| c.to_ascii_lowercase())
                    .collect();
                matches!(
                    norm.as_str(),
                    "select"
                        | "selector"
                        | "relay"
                        | "urltest"
                        | "smart"
                        | "fallback"
                        | "loadbalance"
                )
            });
            if !valid_gtype {
                gmap.insert(yaml_key("type"), YamlValue::String("select".into()));
            }
        }
        for num_k in ["interval", "tolerance"] {
            if let Some(v) = gmap.get_mut(num_k) {
                coerce_yaml_u64(v);
                if lenient_subscription && v.as_u64().is_none() {
                    gmap.remove(num_k);
                }
            }
        }
        for inc_k in [
            "include-all",
            "include-all-proxies",
            "include-all-providers",
        ] {
            if let Some(v) = gmap.get_mut(inc_k) {
                coerce_yaml_bool(v);
            }
        }
        let include_all = gmap
            .get("include-all")
            .and_then(YamlValue::as_bool)
            .unwrap_or(false)
            || gmap
                .get("include-all-proxies")
                .and_then(YamlValue::as_bool)
                .unwrap_or(false)
            || gmap
                .get("include-all-providers")
                .and_then(YamlValue::as_bool)
                .unwrap_or(false);

        let filter_re = yaml_str_field(gmap, "filter")
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .and_then(|pat| regex::Regex::new(pat).ok());
        let exclude_re = yaml_str_field(gmap, "exclude-filter")
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .and_then(|pat| regex::Regex::new(pat).ok());
        let exclude_types: HashSet<String> = yaml_str_field(gmap, "exclude-type")
            .map(|s| {
                s.split('|')
                    .map(|p| p.trim().to_ascii_lowercase())
                    .filter(|p| !p.is_empty())
                    .collect()
            })
            .unwrap_or_default();

        if let Some(p_val) = gmap.get_mut("proxies") {
            sanitize_yaml_string_seq(p_val);
        }
        if let Some(YamlValue::Array(pseq)) = gmap.get_mut("proxies") {
            for elem in pseq.iter_mut() {
                if let YamlValue::String(s) = elem {
                    let t = s.trim();
                    if t.eq_ignore_ascii_case("DIRECT") || t.eq_ignore_ascii_case("COMPATIBLE") {
                        *s = "DIRECT".to_string();
                    } else if t.eq_ignore_ascii_case("REJECT")
                        || t.eq_ignore_ascii_case("REJECT-DROP")
                        || t.eq_ignore_ascii_case("REJECT-TINYGIF")
                    {
                        *s = "REJECT".to_string();
                    }
                }
            }
        }

        let has_explicit_proxies = gmap
            .get("proxies")
            .and_then(YamlValue::as_array)
            .is_some_and(|s| !s.is_empty());
        let has_use = gmap
            .get("use")
            .and_then(YamlValue::as_array)
            .is_some_and(|s| !s.is_empty());
        let should_expand = include_all
            || (lenient_subscription
                && !has_explicit_proxies
                && (filter_re.is_some()
                    || exclude_re.is_some()
                    || !exclude_types.is_empty()
                    || has_use));

        if should_expand {
            let mut list = match gmap.remove("proxies") {
                Some(YamlValue::Array(seq)) => seq,
                _ => Vec::new(),
            };
            let mut existing: HashSet<String> = list
                .iter()
                .filter_map(YamlValue::as_str)
                .map(ToOwned::to_owned)
                .collect();
            for (cname, cproto) in &concrete_nodes {
                if !exclude_types.is_empty() && exclude_types.contains(cproto) {
                    continue;
                }
                if let Some(ref re) = filter_re
                    && !re.is_match(cname)
                {
                    continue;
                }
                if let Some(ref ex) = exclude_re
                    && ex.is_match(cname)
                {
                    continue;
                }
                if existing.insert(cname.clone()) {
                    list.push(YamlValue::String(cname.clone()));
                }
            }
            gmap.insert(yaml_key("proxies"), YamlValue::Array(list));
        }
    }
}

fn normalize_clash_yaml_root_mapping(map: &mut YamlMap, lenient_subscription: bool) {
    strip_null_entries(map);

    // Alias legacy Clash root keys (`Proxy`, `Proxy Group`, `Rule`, `Rule Provider`)
    for (legacy_key, modern_key) in [
        ("Proxy", "proxies"),
        ("Proxy Group", "proxy-groups"),
        ("Rule", "rules"),
        ("Rule Provider", "rule-providers"),
    ] {
        if let Some(legacy_val) = map.remove(legacy_key)
            && !map.contains_key(modern_key)
        {
            map.insert(yaml_key(modern_key), legacy_val);
        }
    }

    for num_k in ["mixed-port", "port", "socks-port"] {
        if let Some(v) = map.get_mut(num_k) {
            coerce_yaml_u64(v);
        }
    }
    let mixed_missing_or_zero = match map.get("mixed-port") {
        None => true,
        Some(YamlValue::Number(n)) => n.as_u64() == Some(0),
        _ => false,
    };
    let fallback_port = map
        .get("port")
        .and_then(YamlValue::as_u64)
        .filter(|p| (1..=65535).contains(p))
        .or_else(|| {
            map.get("socks-port")
                .and_then(YamlValue::as_u64)
                .filter(|p| (1..=65535).contains(p))
        });
    if mixed_missing_or_zero && let Some(p) = fallback_port {
        map.insert(yaml_key("mixed-port"), YamlValue::Number(p.into()));
    } else if lenient_subscription
        && let Some(mp) = map.get("mixed-port")
        && mp.as_u64().is_none_or(|p| p == 0 || p > 65535)
    {
        map.remove("mixed-port");
    }

    for bool_k in ["allow-lan", "geodata-mode"] {
        if let Some(v) = map.get_mut(bool_k) {
            coerce_yaml_bool(v);
            if lenient_subscription && !v.is_boolean() {
                map.remove(bool_k);
            }
        }
    }

    for str_k in ["bind-address", "log-level", "secret", "mmdb-path", "mode"] {
        if let Some(v) = map.get_mut(str_k) {
            coerce_yaml_string(v);
        }
    }
    if lenient_subscription
        && let Some(mval) = map.get("mode")
        && mval.as_str().is_none_or(|s| {
            !matches!(
                s.trim().to_ascii_lowercase().as_str(),
                "" | "rule" | "script" | "global" | "direct"
            )
        })
    {
        map.insert(yaml_key("mode"), YamlValue::String("rule".into()));
    }

    if let Some(YamlValue::String(b)) = map.get_mut("bind-address") {
        let bt = b.trim();
        if bt.is_empty() {
            *b = "*".to_string();
        } else if bt == "[::]" {
            *b = "::".to_string();
        } else if bt.eq_ignore_ascii_case("localhost")
            || (lenient_subscription && bt != "*" && bt.parse::<IpAddr>().is_err())
        {
            *b = "127.0.0.1".to_string();
        }
    } else if lenient_subscription && map.contains_key("bind-address") {
        map.remove("bind-address");
    }
    match map.get_mut("external-controller") {
        Some(YamlValue::Bool(false)) => {
            map.remove("external-controller");
        }
        Some(YamlValue::Number(n)) => {
            if let Some(port) = n.as_u64()
                && (1..=65535).contains(&port)
            {
                map.insert(
                    yaml_key("external-controller"),
                    YamlValue::String(format!("127.0.0.1:{port}")),
                );
            } else if lenient_subscription {
                map.remove("external-controller");
            }
        }
        Some(YamlValue::String(ec)) => {
            let normalized = normalize_go_host_port(ec, "127.0.0.1:9090");
            if lenient_subscription && normalized.parse::<SocketAddr>().is_err() {
                *ec = "127.0.0.1:9090".to_string();
            } else {
                *ec = normalized;
            }
        }
        Some(_) if lenient_subscription => {
            map.remove("external-controller");
        }
        _ => {}
    }

    for seq_k in ["authentication", "lan-allowed-ips", "rules"] {
        if let Some(v) = map.get_mut(seq_k) {
            sanitize_yaml_string_seq(v);
        }
    }
    if let Some(YamlValue::Array(cidrs)) = map.get_mut("lan-allowed-ips") {
        for item in cidrs.iter_mut() {
            if let YamlValue::String(s) = item {
                let t = s.trim();
                if t.parse::<IpNet>().is_err()
                    && let Ok(ip) = t.parse::<IpAddr>()
                {
                    *s = match ip {
                        IpAddr::V4(v4) => format!("{v4}/32"),
                        IpAddr::V6(v6) => format!("{v6}/128"),
                    };
                }
            }
        }
        if lenient_subscription {
            cidrs.retain(|v| {
                v.as_str()
                    .is_some_and(|s| s.trim().parse::<IpNet>().is_ok())
            });
        }
    }

    normalize_yaml_string_list_map(map, "hosts", lenient_subscription, |s| {
        parse_hosts_ip_entry(s).is_some()
    });

    if let Some(YamlValue::Object(dmap)) = map.get_mut("dns") {
        strip_null_entries(dmap);
        match dmap.get("listen").cloned() {
            Some(YamlValue::Bool(false)) => {
                dmap.insert(yaml_key("enable"), YamlValue::Bool(false));
                dmap.remove("listen");
            }
            Some(YamlValue::Number(n)) => {
                if let Some(port) = n.as_u64()
                    && (1..=65535).contains(&port)
                {
                    dmap.insert(
                        yaml_key("listen"),
                        YamlValue::String(format!("127.0.0.1:{port}")),
                    );
                } else if lenient_subscription {
                    dmap.remove("listen");
                }
            }
            _ => {}
        }
        for bool_k in [
            "enable",
            "ipv6",
            "use-hosts",
            "direct-nameserver-follow-policy",
        ] {
            if let Some(v) = dmap.get_mut(bool_k) {
                coerce_yaml_bool(v);
                if lenient_subscription && !v.is_boolean() {
                    dmap.remove(bool_k);
                }
            }
        }
        if let Some(YamlValue::String(listen)) = dmap.get_mut("listen") {
            let normalized = normalize_go_host_port(listen, "127.0.0.1:1053");
            if lenient_subscription && normalized.parse::<SocketAddr>().is_err() {
                *listen = "127.0.0.1:1053".to_string();
            } else {
                *listen = normalized;
            }
        }
        if let Some(em_val) = dmap.get_mut("enhanced-mode") {
            coerce_yaml_string(em_val);
            if let YamlValue::String(em) = em_val {
                let low = em.trim().to_ascii_lowercase();
                match low.as_str() {
                    "mapping" => *em = "fake-ip".to_string(),
                    "passthrough" => *em = "normal".to_string(),
                    "fake-ip" | "redir-host" | "normal" | "hosts" | "" => *em = low,
                    _ if lenient_subscription => *em = "fake-ip".to_string(),
                    _ => {}
                }
            }
        }
        if let Some(YamlValue::Array(seq)) = dmap.get("fake-ip-range").cloned() {
            let preferred_v4 = seq
                .iter()
                .filter_map(YamlValue::as_str)
                .map(str::trim)
                .find(|s| s.parse::<Ipv4Net>().is_ok())
                .map(ToOwned::to_owned);
            let first_any = seq
                .iter()
                .filter_map(YamlValue::as_str)
                .map(str::trim)
                .find(|s| !s.is_empty())
                .map(ToOwned::to_owned);
            if let Some(chosen) = preferred_v4.or(first_any) {
                dmap.insert(yaml_key("fake-ip-range"), YamlValue::String(chosen));
            } else {
                dmap.remove("fake-ip-range");
            }
        }
        if let Some(YamlValue::String(s)) = dmap.get_mut("fake-ip-range") {
            let trimmed = s.trim();
            if trimmed.is_empty() || (lenient_subscription && trimmed.parse::<Ipv4Net>().is_err()) {
                *s = default_fake_ip_range();
            }
        } else if lenient_subscription && dmap.contains_key("fake-ip-range") {
            dmap.remove("fake-ip-range");
        }
        for seq_k in [
            "fake-ip-filter",
            "default-nameserver",
            "direct-nameserver",
            "proxy-server-nameserver",
            "nameserver",
            "fallback",
        ] {
            if let Some(v) = dmap.get_mut(seq_k) {
                sanitize_yaml_string_seq(v);
            }
        }
        normalize_yaml_string_list_map(dmap, "hosts", lenient_subscription, |s| {
            parse_hosts_ip_entry(s).is_some()
        });
        normalize_yaml_string_list_map(dmap, "nameserver-policy", lenient_subscription, |s| {
            DnsUpstream::parse(s).is_ok()
        });
        normalize_yaml_string_list_map(
            dmap,
            "proxy-server-nameserver-policy",
            lenient_subscription,
            |s| DnsUpstream::parse(s).is_ok(),
        );
        if lenient_subscription {
            if let Some(YamlValue::Array(seq)) = dmap.get_mut("default-nameserver") {
                seq.retain(|v| {
                    v.as_str()
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .is_some_and(|s| BootstrapDnsServer::parse(s).is_ok())
                });
            }
            for ns_k in [
                "nameserver",
                "direct-nameserver",
                "proxy-server-nameserver",
                "fallback",
            ] {
                if let Some(YamlValue::Array(seq)) = dmap.get_mut(ns_k) {
                    seq.retain(|v| {
                        v.as_str()
                            .map(str::trim)
                            .filter(|s| !s.is_empty())
                            .is_some_and(|s| DnsUpstream::parse(s).is_ok())
                    });
                }
            }
            if let Some(YamlValue::Array(seq)) = dmap.get_mut("nameserver")
                && seq.is_empty()
            {
                *seq = vec![
                    YamlValue::String("223.5.5.5:53".to_string()),
                    YamlValue::String("119.29.29.29:53".to_string()),
                    YamlValue::String("1.1.1.1:53".to_string()),
                ];
            }
            let seq_needs_bootstrap = [
                "nameserver",
                "direct-nameserver",
                "proxy-server-nameserver",
                "fallback",
            ]
            .iter()
            .filter_map(|&k| dmap.get(k).and_then(YamlValue::as_array))
            .flatten()
            .filter_map(YamlValue::as_str)
            .any(|s| DnsUpstream::parse(s).is_ok_and(|u| u.requires_bootstrap()));
            let policy_needs_bootstrap = ["nameserver-policy", "proxy-server-nameserver-policy"]
                .iter()
                .filter_map(|&k| dmap.get(k).and_then(YamlValue::as_object))
                .flat_map(|m| m.values())
                .filter_map(YamlValue::as_array)
                .flatten()
                .filter_map(YamlValue::as_str)
                .any(|s| DnsUpstream::parse(s).is_ok_and(|u| u.requires_bootstrap()));
            let needs_bootstrap = seq_needs_bootstrap || policy_needs_bootstrap;
            let has_bootstrap = match dmap.get("default-nameserver") {
                None => true, // serde default provides 1.1.1.1:53, 8.8.8.8:53
                Some(YamlValue::Array(seq)) => !seq.is_empty(),
                _ => false,
            };
            if needs_bootstrap && !has_bootstrap {
                dmap.insert(
                    yaml_key("default-nameserver"),
                    YamlValue::Array(vec![
                        YamlValue::String("223.5.5.5:53".to_string()),
                        YamlValue::String("119.29.29.29:53".to_string()),
                        YamlValue::String("1.1.1.1:53".to_string()),
                    ]),
                );
            }
        }
    }

    if let Some(YamlValue::Object(tmap)) = map.get_mut("tun") {
        strip_null_entries(tmap);
        if let Some(dh) = tmap.get_mut("dns-hijack") {
            normalize_yaml_dns_hijack(dh);
            if lenient_subscription && !dh.is_boolean() {
                tmap.remove("dns-hijack");
            }
        }
        if let Some(inet6_val) = tmap.get("inet6-address").cloned() {
            match inet6_val {
                YamlValue::Array(seq) => {
                    let first = seq
                        .iter()
                        .find_map(YamlValue::as_str)
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(ToOwned::to_owned);
                    if let Some(cidr) = first {
                        if lenient_subscription && cidr.parse::<ipnet::Ipv6Net>().is_err() {
                            tmap.remove("inet6-address");
                        } else {
                            tmap.insert(yaml_key("inet6-address"), YamlValue::String(cidr));
                        }
                    } else {
                        tmap.remove("inet6-address");
                    }
                }
                YamlValue::String(s) => {
                    let trimmed = s.trim();
                    if trimmed.is_empty()
                        || (lenient_subscription && trimmed.parse::<ipnet::Ipv6Net>().is_err())
                    {
                        tmap.remove("inet6-address");
                    } else {
                        tmap.insert(
                            yaml_key("inet6-address"),
                            YamlValue::String(trimmed.to_string()),
                        );
                    }
                }
                _ if lenient_subscription => {
                    tmap.remove("inet6-address");
                }
                _ => {}
            }
        }
        for bool_k in [
            "enable",
            "auto-route",
            "auto-detect-interface",
            "strict-route",
            "ipv6",
        ] {
            if let Some(v) = tmap.get_mut(bool_k) {
                coerce_yaml_bool(v);
                if lenient_subscription && !v.is_boolean() {
                    tmap.remove(bool_k);
                }
            }
        }
        for str_k in ["stack", "device", "wintun-path"] {
            if let Some(v) = tmap.get_mut(str_k) {
                coerce_yaml_string(v);
            }
        }
        if let Some(v) = tmap.get_mut("mtu") {
            coerce_yaml_u64(v);
            if lenient_subscription && v.as_u64().is_none() {
                tmap.remove("mtu");
            }
        }
    }

    if let Some(YamlValue::Object(rpmap)) = map.get_mut("rule-providers") {
        strip_null_entries(rpmap);
        if lenient_subscription {
            rpmap.retain(|_, v| v.is_object());
        }
        for (_, pval) in rpmap.iter_mut() {
            let YamlValue::Object(pm) = pval else {
                continue;
            };
            strip_null_entries(pm);
            if let Some(v) = pm.get_mut("interval") {
                coerce_yaml_u64(v);
                if lenient_subscription && v.as_u64().is_none() {
                    pm.remove("interval");
                }
            }
            for str_k in ["type", "behavior", "format", "path", "url"] {
                if let Some(v) = pm.get_mut(str_k) {
                    coerce_yaml_string(v);
                }
            }
            if let Some(payload_val) = pm.get_mut("payload") {
                sanitize_yaml_string_seq(payload_val);
            }
            if !pm.contains_key("type") {
                let inferred = if pm.contains_key("url") {
                    "http"
                } else if pm.contains_key("payload") {
                    "inline"
                } else {
                    "file"
                };
                pm.insert(yaml_key("type"), YamlValue::String(inferred.into()));
            }
        }
    }

    if let Some(YamlValue::Array(seq)) = map.get_mut("proxies") {
        seq.retain(|item| !item.is_null());
        for item in seq.iter_mut() {
            normalize_proxy_yaml_item(item);
        }
    }
}

fn break_subscription_group_cycles(groups: &mut [ProxyGroupConfig], remaining_concrete: &[String]) {
    let idx_by_name: HashMap<String, usize> = groups
        .iter()
        .enumerate()
        .map(|(i, g)| (g.name.clone(), i))
        .collect();
    let mut color: Vec<u8> = vec![0; groups.len()];

    fn dfs_prune(
        u: usize,
        groups: &mut [ProxyGroupConfig],
        idx_by_name: &HashMap<String, usize>,
        color: &mut [u8],
    ) {
        color[u] = 1;
        let mut i = 0usize;
        while i < groups[u].proxies.len() {
            let member = groups[u].proxies[i].clone();
            if let Some(&v) = idx_by_name.get(&member) {
                if color[v] == 1 {
                    // Back-edge creating a cycle: prune this edge
                    groups[u].proxies.remove(i);
                    continue;
                } else if color[v] == 0 {
                    dfs_prune(v, groups, idx_by_name, color);
                }
            }
            i += 1;
        }
        color[u] = 2;
    }

    for start in 0..groups.len() {
        if color[start] == 0 {
            dfs_prune(start, groups, &idx_by_name, &mut color);
        }
    }

    for g in groups.iter_mut() {
        if g.proxies.is_empty() {
            if !remaining_concrete.is_empty() {
                g.proxies = remaining_concrete.to_vec();
            } else {
                g.proxies.push("DIRECT".to_string());
            }
        }
    }
}

fn is_sensitive_url_query_key(key: &str) -> bool {
    matches!(
        key.trim().to_ascii_lowercase().as_str(),
        "token"
            | "secret"
            | "key"
            | "password"
            | "auth"
            | "access_token"
            | "passkey"
            | "apikey"
            | "api_key"
            | "sig"
            | "signature"
    )
}

fn url_contains_redacted_placeholder(url: &str) -> bool {
    url.contains(REDACTED_SECRET)
        || url.contains("%2A%2A%2AREDACTED%2A%2A%2A")
        || url.contains("%2a%2a%2aredacted%2a%2a%2a")
}

fn validate_rule_provider_path(pname: &str, pt: &str, raw_path: &str) -> Result<()> {
    if raw_path.chars().any(|c| c.is_control()) {
        return Err(ProxyError::Config(format!(
            "rule-provider '{pname}' path contains control or null bytes"
        )));
    }
    let has_parent_traversal = Path::new(raw_path)
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
        || raw_path.split(['/', '\\']).any(|seg| seg == "..");
    if has_parent_traversal {
        return Err(ProxyError::Config(format!(
            "rule-provider '{pname}' path '{raw_path}' must not contain parent-directory ('..') traversal"
        )));
    }
    if pt == "http" && !raw_path.is_empty() {
        let trimmed = raw_path.trim();
        let p_obj = Path::new(trimmed);
        let has_root_or_prefix = trimmed.is_empty()
            || Path::new(raw_path).is_absolute()
            || p_obj.is_absolute()
            || trimmed.starts_with('/')
            || trimmed.starts_with('\\')
            || (trimmed.len() >= 2
                && trimmed.as_bytes()[0].is_ascii_alphabetic()
                && trimmed.as_bytes()[1] == b':')
            || p_obj.components().any(|c| {
                matches!(
                    c,
                    std::path::Component::RootDir
                        | std::path::Component::Prefix(_)
                        | std::path::Component::ParentDir
                )
            });
        if has_root_or_prefix {
            return Err(ProxyError::Config(format!(
                "http rule-provider '{pname}' path '{raw_path}' must be a confined relative path"
            )));
        }
    }
    Ok(())
}

pub(crate) fn sanitize_loopback_external_controller(raw: &str, mixed_port: u16) -> String {
    let trimmed = raw.trim();
    let parsed_port = trimmed
        .parse::<SocketAddr>()
        .ok()
        .map(|sa| sa.port())
        .or_else(|| {
            trimmed
                .rsplit_once(':')
                .and_then(|(_, p)| p.trim().parse::<u16>().ok())
        })
        .filter(|p| *p > 0);
    let mut port = parsed_port.unwrap_or(9090);
    if mixed_port > 0 && port == mixed_port {
        port = if mixed_port == 9090 { 9091 } else { 9090 };
    }
    format!("127.0.0.1:{port}")
}

fn sanitize_subscription_groups_and_rules(cfg: &mut ClashConfig, skipped_names: &HashSet<String>) {
    // Neutralize dangerous listener, authentication, secret, and privilege-escalation fields
    // from untrusted remote subscription payloads.
    cfg.secret = None;
    cfg.allow_lan = false;
    cfg.bind_address = "127.0.0.1".to_string();
    cfg.lan_allowed_ips.clear();
    cfg.authentication.clear();
    cfg.tun.enable = false;

    if !(576..=65535).contains(&cfg.tun.mtu) {
        cfg.tun.mtu = 1500;
    }
    if cfg
        .mmdb_path
        .as_deref()
        .is_some_and(|p| !Path::new(p).is_file())
    {
        cfg.mmdb_path = None;
    }
    cfg.external_controller =
        sanitize_loopback_external_controller(&cfg.external_controller, cfg.mixed_port);

    // 0. Uniquify duplicate or reserved node names in `proxies` and deduplicate colliding `proxy-groups`
    let mut used_names: HashSet<String> = [
        "DIRECT".to_string(),
        "REJECT".to_string(),
        "GLOBAL".to_string(),
    ]
    .into_iter()
    .collect();
    let mut duplicate_aliases: HashMap<String, Vec<String>> = HashMap::new();
    for proxy in &mut cfg.proxies {
        let orig = proxy.name().trim().to_string();
        let base = if orig.is_empty() {
            "Node".to_string()
        } else {
            orig.clone()
        };
        if used_names.insert(base.clone())
            && !matches!(
                base.to_ascii_uppercase().as_str(),
                "DIRECT" | "REJECT" | "GLOBAL"
            )
        {
            if proxy.name() != base {
                proxy.set_name(base);
            }
        } else {
            let mut suffix = 2usize;
            let unique = loop {
                let candidate = format!("{base}-{suffix}");
                if used_names.insert(candidate.clone()) {
                    break candidate;
                }
                suffix += 1;
            };
            proxy.set_name(unique.clone());
            if !orig.is_empty() {
                duplicate_aliases.entry(orig).or_default().push(unique);
            }
        }
    }

    cfg.proxy_groups.retain_mut(|g| {
        let clean = g.name.trim().to_string();
        if clean.is_empty()
            || matches!(
                clean.to_ascii_uppercase().as_str(),
                "DIRECT" | "REJECT" | "GLOBAL"
            )
            || !used_names.insert(clean.clone())
        {
            return false;
        }
        g.name = clean;
        if !duplicate_aliases.is_empty() {
            let mut expanded = Vec::with_capacity(g.proxies.len());
            let mut seen_members = HashSet::new();
            for m in &g.proxies {
                if seen_members.insert(m.clone()) {
                    expanded.push(m.clone());
                }
                if let Some(extras) = duplicate_aliases.get(m) {
                    for extra in extras {
                        if seen_members.insert(extra.clone()) {
                            expanded.push(extra.clone());
                        }
                    }
                }
            }
            g.proxies = expanded;
        }
        true
    });

    // 1. Prune unsupported, local-filesystem (`file`), or broken rule-providers;
    // strip custom `path` on `http` providers so remote subscriptions always cache inside `<state_dir>/rulesets/`.
    cfg.rule_providers.retain(|pname, pcfg| {
        if pname.trim().is_empty() {
            return false;
        }
        let pt = pcfg.provider_type.trim().to_ascii_lowercase();
        let beh = pcfg.behavior.trim().to_ascii_lowercase();
        let fmt = pcfg.format.trim().to_ascii_lowercase();
        if !matches!(pt.as_str(), "inline" | "file" | "http")
            || !matches!(beh.as_str(), "domain" | "ipcidr" | "classical")
            || fmt == "mrs"
        {
            return false;
        }
        match pt.as_str() {
            "file" => false,
            "http" => {
                pcfg.path = None;
                let valid_url = pcfg.url.as_deref().is_some_and(|u| {
                    let ul = u.trim().to_ascii_lowercase();
                    (ul.starts_with("https://") || ul.starts_with("http://"))
                        && url::Url::parse(u.trim()).is_ok()
                });
                valid_url || !pcfg.payload.is_empty()
            }
            "inline" => {
                crate::router::ruleset::RuleSetMatcher::compile(pname, &beh, &pcfg.payload, None)
                    .is_ok()
            }
            _ => false,
        }
    });

    let remaining_concrete: Vec<String> =
        cfg.proxies.iter().map(|p| p.name().to_string()).collect();
    let known_group_names: HashSet<String> =
        cfg.proxy_groups.iter().map(|g| g.name.clone()).collect();
    let known_concrete_set: HashSet<String> = remaining_concrete.iter().cloned().collect();

    // 2. Prune skipped or dangling proxy-provider references from proxy-groups and heal empty/cyclic groups
    for g in &mut cfg.proxy_groups {
        let self_name = g.name.clone();
        g.proxies.retain(|m| {
            m != &self_name
                && !skipped_names.contains(m)
                && (m == "DIRECT"
                    || m == "REJECT"
                    || known_concrete_set.contains(m)
                    || known_group_names.contains(m))
        });
        if g.proxies.is_empty() {
            if !remaining_concrete.is_empty() {
                g.proxies = remaining_concrete.clone();
            } else {
                g.proxies.push("DIRECT".to_string());
            }
        }
    }
    break_subscription_group_cycles(&mut cfg.proxy_groups, &remaining_concrete);

    let fallback_target = cfg
        .proxy_groups
        .first()
        .map(|g| g.name.clone())
        .or_else(|| remaining_concrete.first().cloned())
        .unwrap_or_else(|| "DIRECT".to_string());

    let mut valid_rule_targets: HashSet<String> = known_concrete_set;
    valid_rule_targets.extend(known_group_names);
    valid_rule_targets.insert("DIRECT".to_string());
    valid_rule_targets.insert("REJECT".to_string());
    valid_rule_targets.insert("GLOBAL".to_string());

    let had_non_empty_rules = cfg
        .rules
        .iter()
        .any(|l| !l.trim().is_empty() && !l.trim().starts_with('#'));

    let dummy_mmdb = if let Some(ref p) = cfg.mmdb_path
        && Path::new(p).is_file()
    {
        let blob = crate::router::mmdb::build_synthetic_country_mmdb(&[]);
        crate::router::mmdb::MmdbReader::from_bytes(blob)
            .ok()
            .map(std::sync::Arc::new)
    } else {
        None
    };

    let mut sanitized_rules = Vec::with_capacity(cfg.rules.len());
    for line in &cfg.rules {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let mut rewritten = trimmed.to_string();
        let mut parts: Vec<String> = trimmed.split(',').map(|s| s.trim().to_string()).collect();
        if parts.len() == 2
            && (parts[0].eq_ignore_ascii_case("MATCH") || parts[0].eq_ignore_ascii_case("FINAL"))
            && skipped_names.contains(&parts[1])
        {
            parts[1] = fallback_target.clone();
            rewritten = parts.join(",");
        } else if parts.len() >= 3
            && (parts[0].eq_ignore_ascii_case("MATCH") || parts[0].eq_ignore_ascii_case("FINAL"))
            && parts[1].is_empty()
            && skipped_names.contains(&parts[2])
        {
            parts[2] = fallback_target.clone();
            rewritten = format!("{},{}", parts[0], parts[2]);
        } else if parts.len() >= 3 && skipped_names.contains(&parts[2]) {
            parts[2] = fallback_target.clone();
            rewritten = parts.join(",");
        }

        let Ok(compiled) = CompiledRule::parse_with_context(&rewritten, dummy_mmdb.as_ref(), None)
        else {
            continue;
        };
        if let crate::router::rules::RuleMatcher::RuleSet {
            ref provider_name, ..
        } = compiled.matcher
            && !cfg.rule_providers.contains_key(provider_name)
        {
            continue;
        }
        if !valid_rule_targets.contains(compiled.target.as_str()) {
            if matches!(compiled.matcher, crate::router::rules::RuleMatcher::Match) {
                sanitized_rules.push(format!("MATCH,{fallback_target}"));
            }
            continue;
        }
        sanitized_rules.push(rewritten);
    }

    if sanitized_rules.is_empty() && (had_non_empty_rules || !cfg.proxies.is_empty()) {
        sanitized_rules.push(format!("MATCH,{fallback_target}"));
    }
    cfg.rules = sanitized_rules;
}

fn yaml_str_field<'a>(map: &'a YamlMap, key: &str) -> Option<&'a str> {
    map.get(key).and_then(YamlValue::as_str)
}

fn yaml_value_is_effectively_empty(val: &YamlValue) -> bool {
    match val {
        YamlValue::Null => true,
        YamlValue::Bool(b) => !*b,
        YamlValue::String(s) => s.trim().is_empty(),
        YamlValue::Array(seq) => seq.is_empty() || seq.iter().all(yaml_value_is_effectively_empty),
        YamlValue::Object(m) => m.is_empty() || m.values().all(yaml_value_is_effectively_empty),
        _ => false,
    }
}

fn yaml_has_non_null_key(map: &YamlMap, key: &str) -> bool {
    map.get(key)
        .is_some_and(|v| !yaml_value_is_effectively_empty(v))
}

fn validate_raw_yaml_proxy_mapping(
    idx: usize,
    item: &YamlValue,
) -> std::result::Result<(), (SkippedProxyEntry, ProxyError)> {
    let fallback_name = format!("proxies[{idx}]");
    let YamlValue::Object(pmap) = item else {
        let err = ProxyError::Config(format!("proxies[{idx}] must be a YAML mapping"));
        return Err((
            SkippedProxyEntry {
                name: fallback_name,
                protocol: "unknown".to_string(),
                reason: err.to_string(),
            },
            err,
        ));
    };

    let name = yaml_str_field(pmap, "name")
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(&fallback_name)
        .to_string();
    let ptype = yaml_str_field(pmap, "type").map(str::trim).unwrap_or("");
    let ptype_lc = ptype.to_ascii_lowercase();

    let fail = |msg: String| -> (SkippedProxyEntry, ProxyError) {
        let redacted = uri::redact_sensitive_text(&msg);
        (
            SkippedProxyEntry {
                name: name.clone(),
                protocol: if ptype_lc.is_empty() {
                    "unknown".to_string()
                } else {
                    ptype_lc.clone()
                },
                reason: redacted.clone(),
            },
            ProxyError::Config(redacted),
        )
    };

    match ptype_lc.as_str() {
        "vless" => {
            for net_key in ["network", "transport"] {
                if let Some(net) = yaml_str_field(pmap, net_key) {
                    let n = net.trim();
                    if !n.is_empty()
                        && !n.eq_ignore_ascii_case("tcp")
                        && !n.eq_ignore_ascii_case("raw")
                        && !n.eq_ignore_ascii_case("ws")
                    {
                        return Err(fail(format!(
                            "VLESS proxy '{name}' specifies unsupported {net_key} '{n}' (gRPC/HTTPUpgrade transports are not supported; supported: tcp, ws)"
                        )));
                    }
                }
            }
            if let Some(sec) = yaml_str_field(pmap, "security") {
                let s = sec.trim();
                if !s.is_empty()
                    && !s.eq_ignore_ascii_case("none")
                    && !s.eq_ignore_ascii_case("tls")
                {
                    if s.eq_ignore_ascii_case("reality") {
                        return Err(fail(format!(
                            "VLESS proxy '{name}' uses security 'reality', which is not supported (supported: none, tls, or VLESS PQ encryption)"
                        )));
                    }
                    return Err(fail(format!(
                        "VLESS proxy '{name}' uses unsupported security '{s}' (supported: none, tls)"
                    )));
                }
            }
            for unsupported_key in [
                "reality-opts",
                "grpc-opts",
                "h2-opts",
                "http-opts",
                "v2ray-http-upgrade",
                "smux",
                "ech-opts",
                "public-key",
                "short-id",
                "spider-x",
            ] {
                if yaml_has_non_null_key(pmap, unsupported_key) {
                    return Err(fail(format!(
                        "VLESS proxy '{name}' includes unsupported option '{unsupported_key}' (gRPC, REALITY, and Multiplex transports are not supported)"
                    )));
                }
            }
        }
        "ss" => {
            for unsupported_key in ["plugin", "plugin-opts", "smux", "v2ray-plugin"] {
                if yaml_has_non_null_key(pmap, unsupported_key) {
                    return Err(fail(format!(
                        "Shadowsocks proxy '{name}' includes unsupported option '{unsupported_key}' (SIP003 plugins and smux are not supported)"
                    )));
                }
            }
        }
        "anytls" => {
            if let Some(net) = yaml_str_field(pmap, "network") {
                let n = net.trim();
                if !n.is_empty() && !n.eq_ignore_ascii_case("tcp") {
                    return Err(fail(format!(
                        "AnyTLS proxy '{name}' specifies unsupported network '{n}' (only TCP is supported)"
                    )));
                }
            }
            for unsupported_key in ["ws-opts", "grpc-opts", "h2-opts", "reality-opts"] {
                if yaml_has_non_null_key(pmap, unsupported_key) {
                    return Err(fail(format!(
                        "AnyTLS proxy '{name}' includes unsupported option '{unsupported_key}'"
                    )));
                }
            }
        }
        "trojan" => {
            for net_key in ["network", "transport"] {
                if let Some(net) = yaml_str_field(pmap, net_key) {
                    let n = net.trim();
                    if !n.is_empty()
                        && !n.eq_ignore_ascii_case("tcp")
                        && !n.eq_ignore_ascii_case("ws")
                    {
                        return Err(fail(format!(
                            "Trojan proxy '{name}' specifies unsupported {net_key} '{n}' (supported: tcp, ws)"
                        )));
                    }
                }
            }
            for unsupported_key in [
                "grpc-opts",
                "reality-opts",
                "ss-opts",
                "smux",
                "v2ray-http-upgrade",
            ] {
                if yaml_has_non_null_key(pmap, unsupported_key) {
                    return Err(fail(format!(
                        "Trojan proxy '{name}' includes unsupported option '{unsupported_key}'"
                    )));
                }
            }
        }
        "socks5" | "http" => {
            for unsupported_key in ["smux", "ws-opts", "grpc-opts", "reality-opts"] {
                if yaml_has_non_null_key(pmap, unsupported_key) {
                    return Err(fail(format!(
                        "{ptype_lc} proxy '{name}' includes unsupported option '{unsupported_key}'"
                    )));
                }
            }
        }
        other => {
            return Err(fail(format!(
                "proxy '{name}' uses unsupported protocol type '{other}' (supported: ss, vless, anytls, trojan, socks5, http)"
            )));
        }
    }
    Ok(())
}

fn validate_and_parse_single_yaml_proxy(
    idx: usize,
    item: &YamlValue,
) -> std::result::Result<ProxyNodeConfig, (SkippedProxyEntry, ProxyError)> {
    validate_raw_yaml_proxy_mapping(idx, item)?;
    let fallback_name = format!("proxies[{idx}]");
    let (name, proto) = match item {
        YamlValue::Object(pmap) => (
            yaml_str_field(pmap, "name")
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .unwrap_or(&fallback_name)
                .to_string(),
            yaml_str_field(pmap, "type")
                .map(|s| s.trim().to_ascii_lowercase())
                .unwrap_or_else(|| "unknown".to_string()),
        ),
        _ => (fallback_name, "unknown".to_string()),
    };
    let node: ProxyNodeConfig = serde_path_to_error::deserialize(item.clone()).map_err(|e| {
        let path = e.path().to_string();
        let detail = uri::redact_sensitive_text(&e.inner().to_string());
        let redacted = if path.is_empty() || path == "." {
            format!("YAML proxy '{name}' parse error: {detail}")
        } else {
            format!(
                "YAML proxy '{name}' parse error at '{}': {detail}",
                uri::redact_sensitive_text(&path)
            )
        };
        (
            SkippedProxyEntry {
                name: name.clone(),
                protocol: proto.clone(),
                reason: redacted.clone(),
            },
            ProxyError::Config(redacted),
        )
    })?;
    if let Err(err) = validate_single_proxy_node(&node) {
        let redacted = uri::redact_sensitive_text(&err.to_string());
        return Err((
            SkippedProxyEntry {
                name,
                protocol: proto,
                reason: redacted.clone(),
            },
            ProxyError::Config(redacted),
        ));
    }
    Ok(node)
}

fn validate_raw_yaml_proxies(root_map: &YamlMap) -> Result<()> {
    let Some(proxies_val) = root_map.get("proxies") else {
        return Ok(());
    };
    if proxies_val.is_null() {
        return Ok(());
    };
    let YamlValue::Array(seq) = proxies_val else {
        return Err(ProxyError::Config(
            "'proxies' field in YAML must be a list".into(),
        ));
    };

    for (idx, item) in seq.iter().enumerate() {
        validate_raw_yaml_proxy_mapping(idx, item).map_err(|(_, err)| err)?;
    }
    Ok(())
}

pub fn validate_groups_and_rules(
    concrete_outbounds: &HashSet<String>,
    proxy_groups: &[ProxyGroupConfig],
    rule_lines: &[String],
) -> Result<()> {
    validate_groups_and_rules_with_context(
        concrete_outbounds,
        proxy_groups,
        rule_lines,
        None,
        false,
    )
}

pub fn validate_groups_and_rules_with_context(
    concrete_outbounds: &HashSet<String>,
    proxy_groups: &[ProxyGroupConfig],
    rule_lines: &[String],
    rule_providers: Option<&HashMap<String, RuleProviderConfig>>,
    has_mmdb: bool,
) -> Result<()> {
    let mut valid_group_members: HashSet<&str> = HashSet::new();
    valid_group_members.insert("DIRECT");
    valid_group_members.insert("REJECT");
    for name in concrete_outbounds {
        valid_group_members.insert(name.as_str());
    }
    for g in proxy_groups {
        valid_group_members.insert(g.name.as_str());
    }

    let mut group_map: HashMap<&str, &[String]> = HashMap::with_capacity(proxy_groups.len());
    for g in proxy_groups {
        if g.proxies.is_empty() {
            return Err(ProxyError::Config(format!(
                "proxy-group '{}' must reference at least one proxy",
                g.name
            )));
        }
        for member in &g.proxies {
            if !valid_group_members.contains(member.as_str()) {
                return Err(ProxyError::Config(format!(
                    "proxy-group '{}' references unknown proxy or group '{member}'",
                    g.name
                )));
            }
        }
        group_map.insert(g.name.as_str(), g.proxies.as_slice());
    }

    let mut color: HashMap<&str, u8> = HashMap::with_capacity(proxy_groups.len());
    let mut stack: Vec<&str> = Vec::new();
    for g in proxy_groups {
        if color.get(g.name.as_str()).copied().unwrap_or(0) == 0 {
            dfs_check_group_cycle(g.name.as_str(), &group_map, &mut color, &mut stack)?;
        }
    }

    let mut valid_rule_targets = valid_group_members;
    valid_rule_targets.insert("GLOBAL");

    // When `has_mmdb` is true, pass a minimal dummy MmdbReader so arbitrary ISO codes validate cleanly
    let dummy_mmdb = if has_mmdb {
        let blob = crate::router::mmdb::build_synthetic_country_mmdb(&[]);
        crate::router::mmdb::MmdbReader::from_bytes(blob)
            .ok()
            .map(std::sync::Arc::new)
    } else {
        None
    };

    for line in rule_lines {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let compiled = CompiledRule::parse_with_context(trimmed, dummy_mmdb.as_ref(), None)?;
        if let crate::router::rules::RuleMatcher::RuleSet {
            ref provider_name, ..
        } = compiled.matcher
            && let Some(provs) = rule_providers
            && !provs.contains_key(provider_name)
        {
            return Err(ProxyError::Config(format!(
                "rule '{trimmed}' references undefined rule-provider '{provider_name}'"
            )));
        }
        if !valid_rule_targets.contains(compiled.target.as_str()) {
            return Err(ProxyError::Config(format!(
                "rule '{trimmed}' references unknown target '{}'",
                compiled.target
            )));
        }
    }

    Ok(())
}

fn dfs_check_group_cycle<'a>(
    node: &'a str,
    adj: &HashMap<&'a str, &'a [String]>,
    color: &mut HashMap<&'a str, u8>,
    stack: &mut Vec<&'a str>,
) -> Result<()> {
    color.insert(node, 1);
    stack.push(node);

    if let Some(members) = adj.get(node) {
        for member in *members {
            let m = member.as_str();
            if !adj.contains_key(m) {
                continue;
            }
            match color.get(m).copied().unwrap_or(0) {
                1 => {
                    let start_idx = stack.iter().position(|&x| x == m).unwrap_or(0);
                    let mut cycle_chain: Vec<&str> = stack[start_idx..].to_vec();
                    cycle_chain.push(m);
                    return Err(ProxyError::Config(format!(
                        "cyclic proxy-group reference detected: {}",
                        cycle_chain.join(" -> ")
                    )));
                }
                0 => {
                    dfs_check_group_cycle(m, adj, color, stack)?;
                }
                _ => {}
            }
        }
    }

    stack.pop();
    color.insert(node, 2);
    Ok(())
}

pub(crate) fn parse_hosts_ip_entry(raw: &str) -> Option<IpAddr> {
    let clean = raw
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim();
    if clean.is_empty() {
        return None;
    }
    clean.parse::<IpAddr>().ok()
}

fn normalize_yaml_string_list_map(
    parent: &mut YamlMap,
    key: &str,
    lenient_subscription: bool,
    filter_fn: impl Fn(&str) -> bool,
) {
    let Some(raw_val) = parent.remove(key) else {
        return;
    };
    match raw_val {
        YamlValue::Null => {}
        YamlValue::Object(mut m) => {
            strip_null_entries(&mut m);
            let mut cleaned = YamlMap::new();
            for (k, mut v) in m {
                let k_str = k.trim();
                if k_str.is_empty() {
                    continue;
                }
                sanitize_yaml_string_seq(&mut v);
                if let YamlValue::Array(ref mut seq) = v {
                    for item in seq.iter_mut() {
                        if let YamlValue::String(s) = item {
                            *s = s.trim().to_string();
                        }
                    }
                    seq.retain(|item| item.as_str().is_some_and(|s| !s.is_empty()));
                    if lenient_subscription {
                        seq.retain(|item| item.as_str().is_some_and(&filter_fn));
                    }
                    if !seq.is_empty() {
                        cleaned.insert(yaml_key(k_str), v);
                    }
                } else if !lenient_subscription {
                    cleaned.insert(yaml_key(k_str), v);
                }
            }
            if !cleaned.is_empty() {
                parent.insert(yaml_key(key), YamlValue::Object(cleaned));
            }
        }
        other if !lenient_subscription => {
            parent.insert(yaml_key(key), other);
        }
        _ => {}
    }
}

fn is_true(v: &bool) -> bool {
    *v
}

fn deserialize_string_or_vec_map<'de, D>(
    deserializer: D,
) -> std::result::Result<HashMap<String, Vec<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OneOrMany {
        Null,
        One(String),
        Many(Vec<String>),
    }

    let raw: Option<HashMap<String, OneOrMany>> = Option::deserialize(deserializer)?;
    let mut out = HashMap::new();
    if let Some(map) = raw {
        for (k, v) in map {
            let key = k.trim().to_string();
            if key.is_empty() {
                continue;
            }
            let list: Vec<String> = match v {
                OneOrMany::Null => Vec::new(),
                OneOrMany::One(s) => {
                    let t = s.trim();
                    if t.is_empty() {
                        Vec::new()
                    } else {
                        vec![t.to_string()]
                    }
                }
                OneOrMany::Many(seq) => seq
                    .into_iter()
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect(),
            };
            if !list.is_empty() {
                out.insert(key, list);
            }
        }
    }
    Ok(out)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct DnsConfig {
    #[serde(default = "default_true")]
    pub enable: bool,

    #[serde(default = "default_dns_listen")]
    pub listen: String,

    #[serde(default)]
    pub ipv6: bool,

    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    pub use_hosts: bool,

    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    pub direct_nameserver_follow_policy: bool,

    #[serde(default = "default_enhanced_mode")]
    pub enhanced_mode: String,

    #[serde(default = "default_fake_ip_range")]
    pub fake_ip_range: String,

    #[serde(default = "default_fake_ip_filter")]
    pub fake_ip_filter: Vec<String>,

    #[serde(default = "default_bootstrap_nameservers")]
    pub default_nameserver: Vec<String>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub direct_nameserver: Vec<String>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proxy_server_nameserver: Vec<String>,

    #[serde(
        default,
        skip_serializing_if = "HashMap::is_empty",
        deserialize_with = "deserialize_string_or_vec_map"
    )]
    pub proxy_server_nameserver_policy: HashMap<String, Vec<String>>,

    #[serde(default = "default_nameservers")]
    pub nameserver: Vec<String>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fallback: Vec<String>,

    #[serde(
        default,
        skip_serializing_if = "HashMap::is_empty",
        deserialize_with = "deserialize_string_or_vec_map"
    )]
    pub nameserver_policy: HashMap<String, Vec<String>>,

    #[serde(
        default,
        skip_serializing_if = "HashMap::is_empty",
        deserialize_with = "deserialize_string_or_vec_map"
    )]
    pub hosts: HashMap<String, Vec<String>>,
}

fn default_true() -> bool {
    true
}

fn default_dns_listen() -> String {
    "127.0.0.1:1053".to_string()
}

fn default_enhanced_mode() -> String {
    "fake-ip".to_string()
}

fn default_fake_ip_range() -> String {
    "198.18.0.0/15".to_string()
}

fn default_fake_ip_filter() -> Vec<String> {
    vec![
        "localhost".to_string(),
        "*.lan".to_string(),
        "*.local".to_string(),
        "+.msftconnecttest.com".to_string(),
        "+.msftncsi.com".to_string(),
    ]
}

fn default_bootstrap_nameservers() -> Vec<String> {
    vec!["1.1.1.1:53".to_string(), "8.8.8.8:53".to_string()]
}

fn default_nameservers() -> Vec<String> {
    vec!["1.1.1.1:53".to_string(), "8.8.8.8:53".to_string()]
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            enable: true,
            listen: default_dns_listen(),
            ipv6: false,
            use_hosts: true,
            direct_nameserver_follow_policy: true,
            enhanced_mode: default_enhanced_mode(),
            fake_ip_range: default_fake_ip_range(),
            fake_ip_filter: default_fake_ip_filter(),
            default_nameserver: default_bootstrap_nameservers(),
            direct_nameserver: Vec::new(),
            proxy_server_nameserver: Vec::new(),
            proxy_server_nameserver_policy: HashMap::new(),
            nameserver: default_nameservers(),
            fallback: Vec::new(),
            nameserver_policy: HashMap::new(),
            hosts: HashMap::new(),
        }
    }
}

impl DnsConfig {
    pub fn parsed_fake_ip_net(&self) -> Result<Ipv4Net> {
        self.fake_ip_range
            .parse::<Ipv4Net>()
            .map(|net| net.trunc())
            .map_err(|e| {
                ProxyError::Config(format!(
                    "invalid fake-ip-range '{}': {e}",
                    self.fake_ip_range
                ))
            })
    }

    pub fn validate(&self) -> Result<()> {
        self.validate_with_extra_hosts(&HashMap::new())
    }

    pub fn validate_with_extra_hosts(
        &self,
        extra_hosts: &HashMap<String, Vec<String>>,
    ) -> Result<()> {
        let _ = self.parsed_fake_ip_net()?;
        if self.enable && self.listen.trim().parse::<SocketAddr>().is_err() {
            return Err(ProxyError::Config(format!(
                "invalid dns.listen '{}': expected IP:PORT",
                self.listen
            )));
        }
        let mode_lc = self.enhanced_mode.trim().to_ascii_lowercase();
        if !matches!(
            mode_lc.as_str(),
            "fake-ip" | "redir-host" | "normal" | "hosts" | "mapping" | "passthrough" | ""
        ) {
            return Err(ProxyError::Config(format!(
                "unsupported dns.enhanced-mode '{}'",
                self.enhanced_mode
            )));
        }

        for (pat, ips) in self.hosts.iter().chain(extra_hosts.iter()) {
            if pat.trim().is_empty() {
                return Err(ProxyError::Config(
                    "hosts domain pattern cannot be empty".into(),
                ));
            }
            for ip_str in ips {
                if !ip_str.trim().is_empty() && parse_hosts_ip_entry(ip_str).is_none() {
                    return Err(ProxyError::Config(format!(
                        "invalid IP address '{ip_str}' in hosts for '{pat}'"
                    )));
                }
            }
        }

        let mut bootstraps = Vec::new();
        for b in &self.default_nameserver {
            if !b.trim().is_empty() {
                bootstraps.push(BootstrapDnsServer::parse(b)?);
            }
        }

        let host_covered_by_static_hosts = |domain: &str| -> bool {
            if !self.use_hosts {
                return false;
            }
            self.hosts
                .iter()
                .chain(extra_hosts.iter())
                .filter(|(_, ips)| ips.iter().any(|s| parse_hosts_ip_entry(s).is_some()))
                .any(|(pat, _)| crate::dns::fake_ip::domain_matches_any_clash_pattern(domain, pat))
        };

        let mut needs_bootstrap = false;
        let all_upstreams = self
            .nameserver
            .iter()
            .chain(self.direct_nameserver.iter())
            .chain(self.proxy_server_nameserver.iter())
            .chain(self.fallback.iter())
            .chain(self.nameserver_policy.values().flatten())
            .chain(self.proxy_server_nameserver_policy.values().flatten());

        for ns in all_upstreams {
            if !ns.trim().is_empty() {
                let up = DnsUpstream::parse(ns)?;
                if up.requires_bootstrap() {
                    let covered = match up.endpoint_host() {
                        crate::dns::upstream::DnsEndpointHost::Domain(ref d) => {
                            d == "localhost" || host_covered_by_static_hosts(d)
                        }
                        crate::dns::upstream::DnsEndpointHost::Ip(_) => true,
                    };
                    if !covered {
                        needs_bootstrap = true;
                    }
                }
            }
        }
        if needs_bootstrap && bootstraps.is_empty() {
            return Err(ProxyError::Config(
                "DoH/DoT hostname in dns.nameserver/fallback requires at least one literal-IP dns.default-nameserver".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct TunConfig {
    #[serde(default)]
    pub enable: bool,

    #[serde(default = "default_tun_stack")]
    pub stack: String,

    #[serde(default = "default_tun_device")]
    pub device: String,

    #[serde(default = "default_true")]
    pub auto_route: bool,

    #[serde(default = "default_true")]
    pub auto_detect_interface: bool,

    #[serde(default = "default_true", deserialize_with = "deserialize_dns_hijack")]
    pub dns_hijack: bool,

    #[serde(default)]
    pub strict_route: bool,

    #[serde(default)]
    pub ipv6: bool,

    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_inet6_address"
    )]
    pub inet6_address: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wintun_path: Option<String>,

    #[serde(default = "default_tun_mtu")]
    pub mtu: usize,
}

fn deserialize_dns_hijack<'de, D>(deserializer: D) -> std::result::Result<bool, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum DnsHijackRepr {
        Bool(bool),
        Seq(Vec<YamlValue>),
        Str(String),
        Num(i64),
    }

    match Option::<DnsHijackRepr>::deserialize(deserializer)? {
        None => Ok(true),
        Some(DnsHijackRepr::Bool(b)) => Ok(b),
        Some(DnsHijackRepr::Seq(seq)) => {
            Ok(!seq.is_empty() && !seq.iter().all(yaml_value_is_effectively_empty))
        }
        Some(DnsHijackRepr::Str(s)) => {
            let low = s.trim().to_ascii_lowercase();
            Ok(!matches!(
                low.as_str(),
                "" | "false" | "0" | "no" | "off" | "none"
            ))
        }
        Some(DnsHijackRepr::Num(n)) => Ok(n != 0),
    }
}

fn deserialize_inet6_address<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Inet6AddrRepr {
        Str(String),
        Seq(Vec<String>),
    }

    match Option::<Inet6AddrRepr>::deserialize(deserializer)? {
        None => Ok(None),
        Some(Inet6AddrRepr::Str(s)) => {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                Ok(None)
            } else {
                Ok(Some(trimmed.to_string()))
            }
        }
        Some(Inet6AddrRepr::Seq(seq)) => Ok(seq
            .into_iter()
            .map(|s| s.trim().to_string())
            .find(|s| !s.is_empty())),
    }
}

fn default_tun_stack() -> String {
    "smoltcp".to_string()
}

fn default_tun_device() -> String {
    "utun-clash0".to_string()
}

fn default_tun_mtu() -> usize {
    1500
}

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            enable: false,
            stack: default_tun_stack(),
            device: default_tun_device(),
            auto_route: true,
            auto_detect_interface: true,
            dns_hijack: true,
            strict_route: false,
            ipv6: false,
            inet6_address: None,
            wintun_path: None,
            mtu: default_tun_mtu(),
        }
    }
}

fn default_vless_encryption() -> String {
    "none".to_string()
}

fn default_idle_check_secs() -> u64 {
    30
}

fn default_idle_timeout_secs() -> u64 {
    60
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum ProxyNodeConfig {
    Ss {
        name: String,
        server: String,
        port: u16,
        cipher: String,
        password: String,
        #[serde(default = "default_true")]
        udp: bool,
    },
    Vless {
        name: String,
        server: String,
        port: u16,
        uuid: uuid::Uuid,
        #[serde(default = "default_vless_encryption")]
        encryption: String,
        #[serde(default)]
        tls: bool,
        #[serde(default, alias = "sni")]
        servername: Option<String>,
        #[serde(default, rename = "skip-cert-verify")]
        skip_cert_verify: bool,
        #[serde(default)]
        alpn: Vec<String>,
        #[serde(default)]
        flow: Option<String>,
        #[serde(default, alias = "transport", skip_serializing_if = "Option::is_none")]
        network: Option<String>,
        #[serde(default, rename = "ws-opts", skip_serializing_if = "Option::is_none")]
        ws_opts: Option<crate::outbound::ws_stream::WsTransportConfig>,
        #[serde(default = "default_true")]
        udp: bool,
    },
    Anytls {
        name: String,
        server: String,
        port: u16,
        password: String,
        #[serde(default, alias = "servername")]
        sni: Option<String>,
        #[serde(default, rename = "skip-cert-verify")]
        skip_cert_verify: bool,
        #[serde(default)]
        alpn: Vec<String>,
        #[serde(
            default = "default_idle_check_secs",
            rename = "idle-session-check-interval"
        )]
        idle_session_check_interval: u64,
        #[serde(default = "default_idle_timeout_secs", rename = "idle-session-timeout")]
        idle_session_timeout: u64,
        #[serde(default, rename = "min-idle-session")]
        min_idle_session: usize,
        #[serde(default = "default_true")]
        udp: bool,
    },
    Trojan {
        name: String,
        server: String,
        port: u16,
        password: String,
        #[serde(default = "default_true")]
        tls: bool,
        #[serde(default, alias = "servername")]
        sni: Option<String>,
        #[serde(default, rename = "skip-cert-verify")]
        skip_cert_verify: bool,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        alpn: Vec<String>,
        #[serde(default, alias = "transport", skip_serializing_if = "Option::is_none")]
        network: Option<String>,
        #[serde(default, rename = "ws-opts", skip_serializing_if = "Option::is_none")]
        ws_opts: Option<crate::outbound::ws_stream::WsTransportConfig>,
        #[serde(default = "default_true")]
        udp: bool,
    },
    Socks5 {
        name: String,
        server: String,
        port: u16,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        username: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        password: Option<String>,
        #[serde(default)]
        tls: bool,
        #[serde(default, alias = "servername", skip_serializing_if = "Option::is_none")]
        sni: Option<String>,
        #[serde(default, rename = "skip-cert-verify")]
        skip_cert_verify: bool,
        #[serde(default = "default_true")]
        udp: bool,
    },
    Http {
        name: String,
        server: String,
        port: u16,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        username: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        password: Option<String>,
        #[serde(default)]
        tls: bool,
        #[serde(default, alias = "servername", skip_serializing_if = "Option::is_none")]
        sni: Option<String>,
        #[serde(default, rename = "skip-cert-verify")]
        skip_cert_verify: bool,
        #[serde(default, skip_serializing_if = "HashMap::is_empty")]
        headers: HashMap<String, String>,
    },
}

impl ProxyNodeConfig {
    pub fn name(&self) -> &str {
        match self {
            Self::Ss { name, .. }
            | Self::Vless { name, .. }
            | Self::Anytls { name, .. }
            | Self::Trojan { name, .. }
            | Self::Socks5 { name, .. }
            | Self::Http { name, .. } => name,
        }
    }

    pub fn set_name(&mut self, new_name: String) {
        match self {
            Self::Ss { name, .. }
            | Self::Vless { name, .. }
            | Self::Anytls { name, .. }
            | Self::Trojan { name, .. }
            | Self::Socks5 { name, .. }
            | Self::Http { name, .. } => {
                *name = new_name;
            }
        }
    }

    pub fn server_port(&self) -> (&str, u16) {
        match self {
            Self::Ss { server, port, .. }
            | Self::Vless { server, port, .. }
            | Self::Anytls { server, port, .. }
            | Self::Trojan { server, port, .. }
            | Self::Socks5 { server, port, .. }
            | Self::Http { server, port, .. } => (server.as_str(), *port),
        }
    }

    pub fn effective_ws_opts(&self) -> Option<crate::outbound::ws_stream::WsTransportConfig> {
        match self {
            Self::Vless {
                network, ws_opts, ..
            }
            | Self::Trojan {
                network, ws_opts, ..
            } => {
                let is_ws = network
                    .as_deref()
                    .is_some_and(|n| n.trim().eq_ignore_ascii_case("ws"))
                    || ws_opts.is_some();
                if is_ws {
                    Some(ws_opts.clone().unwrap_or_default())
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    pub fn protocol_label(&self) -> &'static str {
        match self {
            Self::Ss { cipher, .. } => {
                if cipher.trim().to_ascii_lowercase().starts_with("2022-") {
                    "Shadowsocks-2022"
                } else {
                    "Shadowsocks"
                }
            }
            Self::Vless { encryption, .. } => {
                if encryption != "none" && !encryption.is_empty() {
                    "VLESS+Encryption"
                } else if self.effective_ws_opts().is_some() {
                    "VLESS+WS"
                } else {
                    "VLESS"
                }
            }
            Self::Anytls { .. } => "AnyTLS-v2",
            Self::Trojan { .. } => {
                if self.effective_ws_opts().is_some() {
                    "Trojan+WS"
                } else {
                    "Trojan"
                }
            }
            Self::Socks5 { .. } => "SOCKS5",
            Self::Http { tls, .. } => {
                if *tls {
                    "HTTPS"
                } else {
                    "HTTP"
                }
            }
        }
    }

    pub fn redacted_clone(&self) -> Self {
        let mut copy = self.clone();
        match &mut copy {
            Self::Ss { password, .. }
            | Self::Anytls { password, .. }
            | Self::Trojan { password, .. } => {
                *password = REDACTED_SECRET.to_string();
            }
            Self::Vless {
                uuid, encryption, ..
            } => {
                *uuid = uuid::Uuid::nil();
                if encryption != "none" && !encryption.is_empty() {
                    *encryption = REDACTED_SECRET.to_string();
                }
            }
            Self::Socks5 { password, .. } => {
                if let Some(p) = password
                    && !p.is_empty()
                {
                    *p = REDACTED_SECRET.to_string();
                }
            }
            Self::Http {
                password, headers, ..
            } => {
                if let Some(p) = password
                    && !p.is_empty()
                {
                    *p = REDACTED_SECRET.to_string();
                }
                for v in headers.values_mut() {
                    *v = REDACTED_SECRET.to_string();
                }
            }
        }
        copy
    }

    /// Restore redacted credentials from an existing concrete node (even if renamed).
    pub fn restore_credentials_from(&mut self, prev: &ProxyNodeConfig) {
        match (self, prev) {
            (
                Self::Ss { password, .. },
                Self::Ss {
                    password: orig_pass,
                    ..
                },
            ) if password == REDACTED_SECRET => {
                *password = orig_pass.clone();
            }
            (
                Self::Vless {
                    uuid, encryption, ..
                },
                Self::Vless {
                    uuid: orig_uuid,
                    encryption: orig_enc,
                    ..
                },
            ) => {
                if *uuid == uuid::Uuid::nil() {
                    *uuid = *orig_uuid;
                }
                if encryption == REDACTED_SECRET {
                    *encryption = orig_enc.clone();
                }
            }
            (
                Self::Anytls { password, .. },
                Self::Anytls {
                    password: orig_pass,
                    ..
                },
            ) if password == REDACTED_SECRET => {
                *password = orig_pass.clone();
            }
            (
                Self::Trojan { password, .. },
                Self::Trojan {
                    password: orig_pass,
                    ..
                },
            ) if password == REDACTED_SECRET => {
                *password = orig_pass.clone();
            }
            (
                Self::Socks5 { password, .. },
                Self::Socks5 {
                    password: orig_pass,
                    ..
                },
            ) if password.as_deref() == Some(REDACTED_SECRET) => {
                *password = orig_pass.clone();
            }
            (
                Self::Http {
                    password, headers, ..
                },
                Self::Http {
                    password: orig_pass,
                    headers: orig_headers,
                    ..
                },
            ) => {
                if password.as_deref() == Some(REDACTED_SECRET) {
                    *password = orig_pass.clone();
                }
                for (hk, hv) in headers.iter_mut() {
                    if hv == REDACTED_SECRET
                        && let Some(orig_val) = orig_headers.get(hk).or_else(|| {
                            orig_headers
                                .iter()
                                .find(|(ok, _)| ok.eq_ignore_ascii_case(hk))
                                .map(|(_, ov)| ov)
                        })
                    {
                        *hv = orig_val.clone();
                    }
                }
            }
            _ => {}
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProxyGroupType {
    Select,
    UrlTest,
    Fallback,
    LoadBalance,
}

impl<'de> Deserialize<'de> for ProxyGroupType {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        let normalized: String = raw
            .trim()
            .chars()
            .filter(|c| *c != '-' && *c != '_')
            .map(|c| c.to_ascii_lowercase())
            .collect();
        match normalized.as_str() {
            "select" | "selector" | "relay" => Ok(Self::Select),
            "urltest" | "smart" => Ok(Self::UrlTest),
            "fallback" => Ok(Self::Fallback),
            "loadbalance" => Ok(Self::LoadBalance),
            _ => Err(serde::de::Error::custom(format!(
                "unknown proxy-group type `{}`, expected `select`, `url-test`, `fallback`, or `load-balance`",
                raw.trim()
            ))),
        }
    }
}

impl ProxyGroupType {
    pub fn as_clash_type(self) -> &'static str {
        match self {
            Self::Select => "Selector",
            Self::UrlTest => "URLTest",
            Self::Fallback => "Fallback",
            Self::LoadBalance => "LoadBalance",
        }
    }
}

fn default_test_url() -> String {
    "http://www.gstatic.com/generate_204".to_string()
}

fn default_test_interval() -> u64 {
    300
}

fn default_tolerance() -> u64 {
    50
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ProxyGroupConfig {
    pub name: String,
    #[serde(rename = "type")]
    pub group_type: ProxyGroupType,
    #[serde(default)]
    pub proxies: Vec<String>,
    #[serde(default = "default_test_url")]
    pub url: String,
    #[serde(default = "default_test_interval")]
    pub interval: u64,
    #[serde(default = "default_tolerance")]
    pub tolerance: u64,
    #[serde(default)]
    pub strategy: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_rejects_unknown_group_members_unknown_rule_targets_and_group_cycles() {
        let bad_member = r#"
proxy-groups:
  - name: Proxy
    type: select
    proxies: [GhostNode]
rules:
  - MATCH,Proxy
"#;
        assert!(ClashConfig::from_yaml_str(bad_member).is_err());

        let self_cycle = r#"
proxy-groups:
  - name: LoopA
    type: select
    proxies: [LoopA]
rules:
  - MATCH,LoopA
"#;
        let err_self = ClashConfig::from_yaml_str(self_cycle)
            .unwrap_err()
            .to_string();
        assert!(err_self.contains("cyclic proxy-group"));

        let two_hop_cycle = r#"
proxy-groups:
  - name: GroupA
    type: select
    proxies: [GroupB]
  - name: GroupB
    type: url-test
    proxies: [GroupA]
rules:
  - MATCH,GroupA
"#;
        let err_two = ClashConfig::from_yaml_str(two_hop_cycle)
            .unwrap_err()
            .to_string();
        assert!(err_two.contains("GroupA -> GroupB -> GroupA"));

        let bad_rule_target = r#"
rules:
  - DOMAIN-SUFFIX,example.com,NoSuchGroup
  - MATCH,DIRECT
"#;
        assert!(ClashConfig::from_yaml_str(bad_rule_target).is_err());

        // DoH hostname without literal-IP default-nameserver must be rejected!
        let missing_bootstrap = r#"
dns:
  enable: true
  default-nameserver: []
  nameserver:
    - https://dns.google/dns-query
rules:
  - MATCH,DIRECT
"#;
        assert!(ClashConfig::from_yaml_str(missing_bootstrap).is_err());

        // Hostname inside default-nameserver must be rejected!
        let hostname_bootstrap = r#"
dns:
  enable: true
  default-nameserver:
    - dns.google
  nameserver:
    - https://dns.google/dns-query
rules:
  - MATCH,DIRECT
"#;
        assert!(ClashConfig::from_yaml_str(hostname_bootstrap).is_err());
    }

    #[test]
    fn yaml_accepts_ws_trojan_socks5_http_and_rejects_grpc_reality_without_leaking_secrets() {
        let supported_yaml = r#"
proxies:
  - name: WS-VLESS
    type: vless
    server: ws.example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    tls: true
    network: ws
    ws-opts:
      path: /vless?ed=2048
      headers:
        Host: cdn.example.com
  - name: HK-Trojan
    type: trojan
    server: tj.example.com
    port: 443
    password: trojan-secret-password
    sni: tj.example.com
  - name: Local-SOCKS5
    type: socks5
    server: 127.0.0.1
    port: 1080
    username: alice
    password: secret
  - name: Corp-HTTP
    type: http
    server: 127.0.0.1
    port: 8080
    tls: true
rules:
  - MATCH,DIRECT
"#;
        let parsed = ClashConfig::from_yaml_str(supported_yaml).expect("supported protocols");
        assert_eq!(parsed.proxies.len(), 4);
        assert_eq!(parsed.proxies[0].protocol_label(), "VLESS+WS");
        assert_eq!(parsed.proxies[1].protocol_label(), "Trojan");
        assert_eq!(parsed.proxies[2].protocol_label(), "SOCKS5");
        assert_eq!(parsed.proxies[3].protocol_label(), "HTTPS");

        let grpc_yaml = r#"
proxies:
  - name: GRPC-VLESS
    type: vless
    server: grpc.example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    network: grpc
    grpc-opts:
      grpc-service-name: gun
rules:
  - MATCH,DIRECT
"#;
        let err_grpc = ClashConfig::from_yaml_str(grpc_yaml)
            .unwrap_err()
            .to_string();
        assert!(err_grpc.contains("network 'grpc'"), "got: {err_grpc}");

        let reality_yaml = r#"
proxies:
  - name: REALITY-VLESS
    type: vless
    server: reality.example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    reality-opts:
      public-key: SUPER_SECRET_REALITY_PBK_999
      short-id: deadbeef
rules:
  - MATCH,DIRECT
"#;
        let err_reality = ClashConfig::from_yaml_str(reality_yaml)
            .unwrap_err()
            .to_string();
        assert!(err_reality.contains("reality-opts"), "got: {err_reality}");
        assert!(
            !err_reality.contains("SUPER_SECRET_REALITY_PBK_999"),
            "must not leak reality key: {err_reality}"
        );
        // Single unsupported node in sanitized mode must ALSO fail closed!
        assert!(ClashConfig::from_yaml_str_sanitized(reality_yaml).is_err());

        // Mixed YAML with supported + unsupported nodes prunes skipped nodes and succeeds!
        let mixed_yaml = r#"
proxies:
  - name: Good-Trojan
    type: trojan
    server: tj.example.com
    port: 443
    password: secret-trojan-pass
  - name: Bad-VMess
    type: vmess
    server: vm.example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
  - name: Bad-Hy2
    type: hysteria2
    server: hy2.example.com
    port: 443
    password: secret-hy2-pass
proxy-groups:
  - name: PROXY
    type: select
    proxies: [Good-Trojan, Bad-VMess, Bad-Hy2]
rules:
  - MATCH,PROXY
"#;
        let (sanitized, skipped) =
            ClashConfig::from_yaml_str_sanitized(mixed_yaml).expect("mixed YAML sanitized");
        assert_eq!(sanitized.proxies.len(), 1);
        assert_eq!(sanitized.proxies[0].name(), "Good-Trojan");
        assert_eq!(sanitized.proxy_groups[0].proxies, vec!["Good-Trojan"]);
        assert_eq!(skipped.len(), 2);

        let scalar_secret = "ss://SUPER_SECRET_RAW_SCALAR_PASS@example.com:8388";
        let err_scalar = ClashConfig::from_yaml_str(scalar_secret)
            .unwrap_err()
            .to_string();
        assert!(
            !err_scalar.contains("SUPER_SECRET_RAW_SCALAR_PASS"),
            "scalar yaml error leaked secret: {err_scalar}"
        );
    }

    #[test]
    fn mihomo_and_v2board_tun_sequences_nulls_numeric_scalars_and_duplicate_names_parse_cleanly() {
        let mihomo_yaml = r#"
port: 7890
mixed-port: 0
allow-lan: "true"
bind-address: ""
mode: Rule
log-level: ~
secret: 987654
external-controller: :9090
lan-allowed-ips:
  - 192.168.1.10
  - 10.0.0.0/8
dns:
  enable: "1"
  listen: :1053
  ipv6: ~
  enhanced-mode: mapping
  fake-ip-range:
    - 198.18.0.0/15
  default-nameserver:
    - 223.5.5.5#DIRECT
  nameserver:
    - https://doh.pub/dns-query
tun:
  enable: true
  stack: ~
  dns-hijack:
    - any:53
    - tcp://any:53
  inet6-address:
    - fdfe:dcba:9876::1/126
  mtu: 1400.0
proxies:
  - name: 10086
    type: trojan
    server: tj1.example.com
    port: "443"
    password: 12345678
    alpn: false
    udp: "true"
    skip-cert-verify: ~
  - name: HK-Dup
    type: trojan
    server: hk1.example.com
    port: 443
    password: pass-one
  - name: HK-Dup
    type: trojan
    server: hk2.example.com
    port: 443
    password: pass-two
proxy-groups:
  - name: Proxy
    type: smart
    url: ~
    interval: 300.0
    proxies:
      - 10086
      - HK-Dup
rule-providers:
  reject_list:
    behavior: domain
    url: https://example.com/reject.yaml
    path: ./ruleset/reject.yaml
rules:
  - RULE-SET,reject_list,REJECT
  - MATCH,Proxy
"#;

        let (sanitized, skipped) = ClashConfig::from_yaml_str_sanitized(mihomo_yaml)
            .expect("Mihomo/V2Board YAML with tun.dns-hijack sequence must parse cleanly");
        assert!(skipped.is_empty(), "unexpected skipped: {skipped:?}");
        assert!(sanitized.tun.dns_hijack);
        assert!(!sanitized.tun.enable);
        assert_eq!(
            sanitized.tun.inet6_address.as_deref(),
            Some("fdfe:dcba:9876::1/126")
        );
        assert_eq!(sanitized.tun.mtu, 1400);
        assert_eq!(sanitized.mixed_port, 7890);
        assert!(sanitized.secret.is_none());
        assert!(!sanitized.allow_lan);
        assert_eq!(sanitized.bind_address, "127.0.0.1");
        assert!(sanitized.lan_allowed_ips.is_empty());
        assert_eq!(sanitized.external_controller, "127.0.0.1:9090");
        assert_eq!(sanitized.proxies.len(), 3);
        assert_eq!(sanitized.proxies[0].name(), "10086");
        assert_eq!(sanitized.proxies[1].name(), "HK-Dup");
        assert_eq!(sanitized.proxies[2].name(), "HK-Dup-2");
        assert_eq!(
            sanitized.proxy_groups[0].proxies,
            vec!["10086", "HK-Dup", "HK-Dup-2"]
        );
        assert_eq!(
            sanitized.rule_providers["reject_list"].provider_type,
            "http"
        );
        assert!(sanitized.rule_providers["reject_list"].path.is_none());

        // Persisted YAML must also pass strict `ClashConfig::from_yaml_str` reload!
        let persisted = sanitized.to_yaml_string().expect("serialize sanitized");
        let reloaded =
            ClashConfig::from_yaml_str(&persisted).expect("strict reload of persisted YAML");
        assert!(reloaded.tun.dns_hijack);
        assert_eq!(reloaded.proxies.len(), 3);

        // Direct strict `from_yaml_str` must ALSO accept `tun.dns-hijack`, `tun.inet6-address` sequences,
        // and numeric `secret` scalars when proxy names are already unique:
        let strict_mihomo = r#"
secret: 987654
tun:
  enable: true
  dns-hijack:
    - any:53
    - tcp://any:53
  inet6-address:
    - fdfe:dcba:9876::1/126
rules:
  - MATCH,DIRECT
"#;
        let strict_cfg =
            ClashConfig::from_yaml_str(strict_mihomo).expect("strict tun sequence parse");
        assert_eq!(strict_cfg.secret.as_deref(), Some("987654"));
        assert!(strict_cfg.tun.dns_hijack);
        assert_eq!(
            strict_cfg.tun.inet6_address.as_deref(),
            Some("fdfe:dcba:9876::1/126")
        );

        // Empty `dns-hijack: []` maps to `false`
        let empty_hijack = "tun:\n  dns-hijack: []\nrules:\n  - MATCH,DIRECT\n";
        let empty_cfg = ClashConfig::from_yaml_str(empty_hijack).expect("empty dns-hijack seq");
        assert!(!empty_cfg.tun.dns_hijack);

        // Truly invalid type in strict mode pinpoints the exact field path via serde_path_to_error!
        let bad_type_yaml = "mixed-port:\n  - not-a-port\nrules:\n  - MATCH,DIRECT\n";
        let bad_err = ClashConfig::from_yaml_str(bad_type_yaml)
            .unwrap_err()
            .to_string();
        assert!(
            bad_err.contains("mixed-port"),
            "expected field path in YAML parse error, got: {bad_err}"
        );
    }

    #[test]
    fn rule_provider_path_validation_and_subscription_sanitization_enforce_confinement() {
        let abs_http = r#"
rule-providers:
  evil_http:
    type: http
    behavior: domain
    url: https://example.com/rules.yaml
    path: /tmp/evil_cron
rules:
  - MATCH,DIRECT
"#;
        assert!(ClashConfig::from_yaml_str(abs_http).is_err());

        let traversal_http = r#"
rule-providers:
  trav_http:
    type: http
    behavior: domain
    url: https://example.com/rules.yaml
    path: ../../.bashrc
rules:
  - MATCH,DIRECT
"#;
        assert!(ClashConfig::from_yaml_str(traversal_http).is_err());

        let traversal_file = r#"
rule-providers:
  trav_file:
    type: file
    behavior: domain
    path: ../outside.yaml
rules:
  - MATCH,DIRECT
"#;
        assert!(ClashConfig::from_yaml_str(traversal_file).is_err());

        let sub_yaml = r#"
mixed-port: 9090
allow-lan: true
bind-address: 0.0.0.0
external-controller: 0.0.0.0:9090
secret: attacker-secret
authentication:
  - admin:pass123
tun:
  enable: true
proxies:
  - name: Node1
    type: trojan
    server: n1.example.com
    port: 443
    password: p1
rule-providers:
  local_leak:
    type: file
    behavior: domain
    path: /etc/hosts
  remote_ok:
    type: http
    behavior: domain
    url: https://example.com/list.yaml
    path: /tmp/pwn.sh
rules:
  - RULE-SET,local_leak,DIRECT
  - RULE-SET,remote_ok,REJECT
  - MATCH,Node1
"#;
        let (sanitized, _) =
            ClashConfig::from_yaml_str_sanitized(sub_yaml).expect("sanitized subscription");
        assert!(sanitized.secret.is_none());
        assert!(!sanitized.allow_lan);
        assert_eq!(sanitized.bind_address, "127.0.0.1");
        assert!(sanitized.authentication.is_empty());
        assert!(!sanitized.tun.enable);
        assert_eq!(sanitized.mixed_port, 9090);
        assert_eq!(sanitized.external_controller, "127.0.0.1:9091");
        assert!(!sanitized.rule_providers.contains_key("local_leak"));
        assert!(sanitized.rule_providers["remote_ok"].path.is_none());
    }

    #[test]
    fn redacted_config_masks_query_tokens_and_http_proxy_headers_and_restores_cleanly() {
        let raw_yaml = r#"
secret: super-secret-ctrl
proxies:
  - name: Corp-Proxy
    type: http
    server: proxy.corp.internal
    port: 8443
    tls: true
    headers:
      Proxy-Authorization: Basic dXNlcjpzZWNyZXQ=
      X-Api-Token: tok_live_999
rule-providers:
  priv_rules:
    type: http
    behavior: domain
    url: https://rules.example.com/list.yaml?token=sub_tok_123&format=yaml&sig=deadbeef
rules:
  - MATCH,Corp-Proxy
"#;
        let orig = ClashConfig::from_yaml_str(raw_yaml).expect("parse original");
        let redacted = orig.redacted();
        let redacted_yaml = redacted.to_yaml_string().expect("serialize redacted");
        assert!(!redacted_yaml.contains("super-secret-ctrl"));
        assert!(!redacted_yaml.contains("dXNlcjpzZWNyZXQ="));
        assert!(!redacted_yaml.contains("tok_live_999"));
        assert!(!redacted_yaml.contains("sub_tok_123"));
        assert!(!redacted_yaml.contains("deadbeef"));
        assert!(redacted_yaml.contains("format=yaml"));

        let mut roundtrip = ClashConfig::from_yaml_str(&redacted_yaml).expect("parse redacted");
        roundtrip.restore_redacted_from(&orig);
        assert_eq!(roundtrip.secret, orig.secret);
        assert_eq!(
            roundtrip.rule_providers["priv_rules"].url,
            orig.rule_providers["priv_rules"].url
        );
        match (&roundtrip.proxies[0], &orig.proxies[0]) {
            (
                ProxyNodeConfig::Http { headers: h_new, .. },
                ProxyNodeConfig::Http { headers: h_old, .. },
            ) => assert_eq!(h_new, h_old),
            _ => panic!("expected Http proxy node"),
        }
    }
}

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
    #[serde(rename = "type")]
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

    #[serde(default)]
    pub geodata_mode: bool,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mmdb_path: Option<String>,

    #[serde(default)]
    pub dns: DnsConfig,

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
            geodata_mode: false,
            mmdb_path: None,
            dns: DnsConfig::default(),
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

impl ClashConfig {
    pub fn from_yaml_str(yaml: &str) -> Result<Self> {
        let cfg = Self::from_yaml_str_unchecked(yaml)?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn from_yaml_str_unchecked(yaml: &str) -> Result<Self> {
        let mut root: serde_yml::Value = serde_yml::from_str(yaml).map_err(|e| {
            ProxyError::Config(format!(
                "YAML parse error: {}",
                uri::redact_sensitive_text(&e.to_string())
            ))
        })?;
        let serde_yml::Value::Mapping(ref mut map) = root else {
            return Err(ProxyError::Config(
                "YAML configuration root must be a key-value mapping".into(),
            ));
        };
        normalize_clash_yaml_root_mapping(map, false);
        validate_raw_yaml_proxies(map)?;
        expand_proxy_groups_yaml(map);
        serde_yml::from_value(root).map_err(|e| {
            ProxyError::Config(format!(
                "YAML parse error: {}",
                uri::redact_sensitive_text(&e.to_string())
            ))
        })
    }

    /// Parse a Clash YAML profile with best-effort sanitization for mixed multi-protocol subscriptions:
    /// - Unsupported or malformed individual `proxies` entries are collected into `Vec<SkippedProxyEntry>`
    ///   (with all secrets scrubbed) and pruned from `proxy-groups` / rules when `>= 1` valid proxy node remains.
    /// - Common V2Board / Xboard / Subconverter / Mihomo subscription conventions (`mode: Rule`,
    ///   `include-all`, empty regional filter groups, unsupported rule types, `:53` / `:9090` listeners)
    ///   are normalized into valid `ClashConfig` structures.
    /// - If `skipped` is non-empty and `0` valid proxy nodes remain, fails closed with the redacted error!
    pub fn from_yaml_str_sanitized(yaml: &str) -> Result<(Self, Vec<SkippedProxyEntry>)> {
        let mut root: serde_yml::Value = serde_yml::from_str(yaml).map_err(|e| {
            ProxyError::Config(format!(
                "YAML parse error: {}",
                uri::redact_sensitive_text(&e.to_string())
            ))
        })?;
        let serde_yml::Value::Mapping(ref mut map) = root else {
            return Err(ProxyError::Config(
                "YAML configuration root must be a key-value mapping".into(),
            ));
        };

        normalize_clash_yaml_root_mapping(map, true);

        let mut skipped = Vec::new();
        let mut first_err: Option<ProxyError> = None;
        let mut skipped_names = HashSet::new();

        let proxies_key = serde_yml::Value::String("proxies".to_string());
        if let Some(proxies_val) = map.get(&proxies_key).cloned()
            && !proxies_val.is_null()
        {
            let serde_yml::Value::Sequence(seq) = proxies_val else {
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
            if !skipped.is_empty() && kept_seq.is_empty() {
                return Err(first_err.unwrap_or_else(|| {
                    ProxyError::Config("no supported proxy nodes found in YAML profile".into())
                }));
            }
            map.insert(proxies_key, serde_yml::Value::Sequence(kept_seq));
        }

        expand_proxy_groups_yaml(map);

        let mut cfg: Self = serde_yml::from_value(root).map_err(|e| {
            ProxyError::Config(format!(
                "YAML parse error: {}",
                uri::redact_sensitive_text(&e.to_string())
            ))
        })?;

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
        serde_yml::to_string(self)
            .map_err(|e| ProxyError::Config(format!("YAML serialize error: {e}")))
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
                && (!parsed.username().is_empty() || parsed.password().is_some())
            {
                let _ = parsed.set_password(Some(REDACTED_SECRET));
                *u = parsed.to_string();
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
                .is_some_and(|u| u.contains(REDACTED_SECRET))
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

        self.dns.validate()?;

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

fn yaml_key(k: &str) -> serde_yml::Value {
    serde_yml::Value::String(k.to_string())
}

fn coerce_yaml_u64(val: &mut serde_yml::Value) {
    if let serde_yml::Value::String(s) = val
        && let Ok(n) = s.trim().parse::<u64>()
    {
        *val = serde_yml::Value::Number(n.into());
    }
}

fn coerce_yaml_bool(val: &mut serde_yml::Value) {
    match val {
        serde_yml::Value::String(s) => match s.trim().to_ascii_lowercase().as_str() {
            "true" | "1" | "yes" => *val = serde_yml::Value::Bool(true),
            "false" | "0" | "no" => *val = serde_yml::Value::Bool(false),
            _ => {}
        },
        serde_yml::Value::Number(n) => match n.as_u64() {
            Some(1) => *val = serde_yml::Value::Bool(true),
            Some(0) => *val = serde_yml::Value::Bool(false),
            _ => {}
        },
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

fn normalize_proxy_yaml_item(item: &mut serde_yml::Value) {
    let serde_yml::Value::Mapping(pmap) = item else {
        return;
    };

    let mut force_tls_default = false;
    if let Some(serde_yml::Value::String(t)) = pmap.get_mut("type") {
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
        *t = mapped.to_string();
    }
    if force_tls_default && matches!(pmap.get("tls"), None | Some(serde_yml::Value::Null)) {
        pmap.insert(yaml_key("tls"), serde_yml::Value::Bool(true));
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
    for bool_k in ["udp", "tls", "skip-cert-verify"] {
        if let Some(v) = pmap.get_mut(bool_k) {
            coerce_yaml_bool(v);
        }
    }
    if let Some(alpn_val) = pmap.get_mut("alpn") {
        match alpn_val {
            serde_yml::Value::Null => {
                *alpn_val = serde_yml::Value::Sequence(Vec::new());
            }
            serde_yml::Value::String(s) => {
                let items: Vec<serde_yml::Value> = s
                    .split(',')
                    .map(str::trim)
                    .filter(|p| !p.is_empty())
                    .map(|p| serde_yml::Value::String(p.to_string()))
                    .collect();
                *alpn_val = serde_yml::Value::Sequence(items);
            }
            _ => {}
        }
    }
    if let Some(serde_yml::Value::Mapping(wmap)) = pmap.get_mut("ws-opts")
        && let Some(ed_val) = wmap.get_mut("max-early-data")
    {
        coerce_yaml_u64(ed_val);
    }
}

fn expand_proxy_groups_yaml(map: &mut serde_yml::Mapping) {
    let concrete_names: Vec<String> = map
        .get("proxies")
        .and_then(serde_yml::Value::as_sequence)
        .map(|seq| {
            seq.iter()
                .filter_map(|v| v.as_mapping())
                .filter_map(|m| yaml_str_field(m, "name"))
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default();

    let Some(serde_yml::Value::Sequence(gseq)) = map.get_mut("proxy-groups") else {
        return;
    };

    for gval in gseq.iter_mut() {
        let serde_yml::Value::Mapping(gmap) = gval else {
            continue;
        };
        for num_k in ["interval", "tolerance"] {
            if let Some(v) = gmap.get_mut(num_k) {
                coerce_yaml_u64(v);
            }
        }
        if matches!(gmap.get("url"), Some(serde_yml::Value::Null)) {
            gmap.remove("url");
        }
        for inc_k in ["include-all", "include-all-proxies"] {
            if let Some(v) = gmap.get_mut(inc_k) {
                coerce_yaml_bool(v);
            }
        }
        let include_all = gmap
            .get("include-all")
            .and_then(serde_yml::Value::as_bool)
            .unwrap_or(false)
            || gmap
                .get("include-all-proxies")
                .and_then(serde_yml::Value::as_bool)
                .unwrap_or(false);

        let filter_re = yaml_str_field(gmap, "filter")
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .and_then(|pat| regex::Regex::new(pat).ok());
        let exclude_re = yaml_str_field(gmap, "exclude-filter")
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .and_then(|pat| regex::Regex::new(pat).ok());

        if matches!(gmap.get("proxies"), Some(serde_yml::Value::Null)) {
            gmap.remove("proxies");
        }
        if let Some(serde_yml::Value::Sequence(pseq)) = gmap.get_mut("proxies") {
            for elem in pseq.iter_mut() {
                if let serde_yml::Value::String(s) = elem {
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

        if include_all {
            let mut list = match gmap.remove("proxies") {
                Some(serde_yml::Value::Sequence(seq)) => seq,
                _ => Vec::new(),
            };
            let mut existing: HashSet<String> = list
                .iter()
                .filter_map(serde_yml::Value::as_str)
                .map(ToOwned::to_owned)
                .collect();
            for cname in &concrete_names {
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
                    list.push(serde_yml::Value::String(cname.clone()));
                }
            }
            gmap.insert(yaml_key("proxies"), serde_yml::Value::Sequence(list));
        }
    }
}

fn normalize_clash_yaml_root_mapping(map: &mut serde_yml::Mapping, lenient_subscription: bool) {
    for null_default_k in [
        "mode",
        "log-level",
        "bind-address",
        "external-controller",
        "dns",
        "tun",
    ] {
        if matches!(map.get(null_default_k), Some(serde_yml::Value::Null)) {
            map.remove(null_default_k);
        }
    }

    for num_k in ["mixed-port", "port"] {
        if let Some(v) = map.get_mut(num_k) {
            coerce_yaml_u64(v);
        }
    }
    let mixed_missing_or_zero = match map.get("mixed-port") {
        None | Some(serde_yml::Value::Null) => true,
        Some(serde_yml::Value::Number(n)) => n.as_u64() == Some(0),
        _ => false,
    };
    if mixed_missing_or_zero
        && map.get("mixed-port").is_none()
        && let Some(p) = map.get("port").and_then(serde_yml::Value::as_u64)
        && (1..=65535).contains(&p)
    {
        map.insert(yaml_key("mixed-port"), serde_yml::Value::Number(p.into()));
    }

    for bool_k in ["allow-lan", "geodata-mode"] {
        if let Some(v) = map.get_mut(bool_k) {
            coerce_yaml_bool(v);
        }
    }

    if let Some(serde_yml::Value::String(b)) = map.get_mut("bind-address")
        && b.trim().is_empty()
    {
        *b = "*".to_string();
    }
    if let Some(serde_yml::Value::String(ec)) = map.get_mut("external-controller") {
        *ec = normalize_go_host_port(ec, "127.0.0.1:9090");
    }

    if let Some(serde_yml::Value::Mapping(dmap)) = map.get_mut("dns") {
        for bool_k in ["enable", "ipv6"] {
            if let Some(v) = dmap.get_mut(bool_k) {
                coerce_yaml_bool(v);
            }
        }
        if matches!(dmap.get("listen"), Some(serde_yml::Value::Null)) {
            dmap.remove("listen");
        }
        if let Some(serde_yml::Value::String(listen)) = dmap.get_mut("listen") {
            *listen = normalize_go_host_port(listen, "127.0.0.1:1053");
        }
        if lenient_subscription {
            if let Some(serde_yml::Value::Sequence(seq)) = dmap.get_mut("default-nameserver") {
                seq.retain(|v| {
                    v.as_str()
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .is_some_and(|s| BootstrapDnsServer::parse(s).is_ok())
                });
            }
            for ns_k in ["nameserver", "direct-nameserver", "fallback"] {
                if let Some(serde_yml::Value::Sequence(seq)) = dmap.get_mut(ns_k) {
                    seq.retain(|v| {
                        v.as_str()
                            .map(str::trim)
                            .filter(|s| !s.is_empty())
                            .is_some_and(|s| DnsUpstream::parse(s).is_ok())
                    });
                }
            }
            if let Some(serde_yml::Value::Sequence(seq)) = dmap.get_mut("nameserver")
                && seq.is_empty()
            {
                *seq = vec![
                    serde_yml::Value::String("223.5.5.5:53".to_string()),
                    serde_yml::Value::String("119.29.29.29:53".to_string()),
                    serde_yml::Value::String("1.1.1.1:53".to_string()),
                ];
            }
            let needs_bootstrap = ["nameserver", "direct-nameserver", "fallback"]
                .iter()
                .filter_map(|&k| dmap.get(k).and_then(serde_yml::Value::as_sequence))
                .flatten()
                .filter_map(serde_yml::Value::as_str)
                .any(|s| DnsUpstream::parse(s).is_ok_and(|u| u.requires_bootstrap()));
            let has_bootstrap = match dmap.get("default-nameserver") {
                None => true, // serde default provides 1.1.1.1:53, 8.8.8.8:53
                Some(serde_yml::Value::Sequence(seq)) => !seq.is_empty(),
                _ => false,
            };
            if needs_bootstrap && !has_bootstrap {
                dmap.insert(
                    yaml_key("default-nameserver"),
                    serde_yml::Value::Sequence(vec![
                        serde_yml::Value::String("223.5.5.5:53".to_string()),
                        serde_yml::Value::String("119.29.29.29:53".to_string()),
                        serde_yml::Value::String("1.1.1.1:53".to_string()),
                    ]),
                );
            }
        }
    }

    if let Some(serde_yml::Value::Mapping(tmap)) = map.get_mut("tun") {
        for bool_k in [
            "enable",
            "auto-route",
            "auto-detect-interface",
            "dns-hijack",
            "strict-route",
            "ipv6",
        ] {
            if let Some(v) = tmap.get_mut(bool_k) {
                coerce_yaml_bool(v);
            }
        }
        if let Some(v) = tmap.get_mut("mtu") {
            coerce_yaml_u64(v);
        }
    }

    if let Some(serde_yml::Value::Sequence(seq)) = map.get_mut("proxies") {
        for item in seq.iter_mut() {
            normalize_proxy_yaml_item(item);
        }
    }
}

fn sanitize_subscription_groups_and_rules(cfg: &mut ClashConfig, skipped_names: &HashSet<String>) {
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

    // 1. Prune unsupported rule-provider types/behaviors/formats (e.g. binary `mrs`)
    cfg.rule_providers.retain(|pname, pcfg| {
        !pname.trim().is_empty()
            && matches!(
                pcfg.provider_type.trim().to_ascii_lowercase().as_str(),
                "inline" | "file" | "http"
            )
            && matches!(
                pcfg.behavior.trim().to_ascii_lowercase().as_str(),
                "domain" | "ipcidr" | "classical"
            )
            && !pcfg.format.trim().eq_ignore_ascii_case("mrs")
    });

    let remaining_concrete: Vec<String> =
        cfg.proxies.iter().map(|p| p.name().to_string()).collect();
    let known_group_names: HashSet<String> =
        cfg.proxy_groups.iter().map(|g| g.name.clone()).collect();
    let known_concrete_set: HashSet<String> = remaining_concrete.iter().cloned().collect();

    // 2. Prune skipped or dangling proxy-provider references from proxy-groups and heal empty groups
    for g in &mut cfg.proxy_groups {
        g.proxies.retain(|m| {
            !skipped_names.contains(m)
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

fn yaml_str_field<'a>(map: &'a serde_yml::Mapping, key: &str) -> Option<&'a str> {
    map.get(serde_yml::Value::String(key.to_string()))
        .and_then(serde_yml::Value::as_str)
}

fn yaml_value_is_effectively_empty(val: &serde_yml::Value) -> bool {
    match val {
        serde_yml::Value::Null => true,
        serde_yml::Value::Bool(b) => !*b,
        serde_yml::Value::String(s) => s.trim().is_empty(),
        serde_yml::Value::Sequence(seq) => {
            seq.is_empty() || seq.iter().all(yaml_value_is_effectively_empty)
        }
        serde_yml::Value::Mapping(m) => {
            m.is_empty() || m.values().all(yaml_value_is_effectively_empty)
        }
        _ => false,
    }
}

fn yaml_has_non_null_key(map: &serde_yml::Mapping, key: &str) -> bool {
    map.get(serde_yml::Value::String(key.to_string()))
        .is_some_and(|v| !yaml_value_is_effectively_empty(v))
}

fn validate_raw_yaml_proxy_mapping(
    idx: usize,
    item: &serde_yml::Value,
) -> std::result::Result<(), (SkippedProxyEntry, ProxyError)> {
    let fallback_name = format!("proxies[{idx}]");
    let serde_yml::Value::Mapping(pmap) = item else {
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
    item: &serde_yml::Value,
) -> std::result::Result<ProxyNodeConfig, (SkippedProxyEntry, ProxyError)> {
    validate_raw_yaml_proxy_mapping(idx, item)?;
    let fallback_name = format!("proxies[{idx}]");
    let (name, proto) = match item {
        serde_yml::Value::Mapping(pmap) => (
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
    let node: ProxyNodeConfig = serde_yml::from_value(item.clone()).map_err(|e| {
        let redacted = format!(
            "YAML proxy '{name}' parse error: {}",
            uri::redact_sensitive_text(&e.to_string())
        );
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

fn validate_raw_yaml_proxies(root_map: &serde_yml::Mapping) -> Result<()> {
    let Some(proxies_val) = root_map.get(serde_yml::Value::String("proxies".to_string())) else {
        return Ok(());
    };
    if proxies_val.is_null() {
        return Ok(());
    };
    let serde_yml::Value::Sequence(seq) = proxies_val else {
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct DnsConfig {
    #[serde(default = "default_true")]
    pub enable: bool,

    #[serde(default = "default_dns_listen")]
    pub listen: String,

    #[serde(default)]
    pub ipv6: bool,

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

    #[serde(default = "default_nameservers")]
    pub nameserver: Vec<String>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fallback: Vec<String>,
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
            enhanced_mode: default_enhanced_mode(),
            fake_ip_range: default_fake_ip_range(),
            fake_ip_filter: default_fake_ip_filter(),
            default_nameserver: default_bootstrap_nameservers(),
            direct_nameserver: Vec::new(),
            nameserver: default_nameservers(),
            fallback: Vec::new(),
        }
    }
}

impl DnsConfig {
    pub fn parsed_fake_ip_net(&self) -> Result<Ipv4Net> {
        self.fake_ip_range.parse::<Ipv4Net>().map_err(|e| {
            ProxyError::Config(format!(
                "invalid fake-ip-range '{}': {e}",
                self.fake_ip_range
            ))
        })
    }

    pub fn validate(&self) -> Result<()> {
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
            "fake-ip" | "redir-host" | "normal" | "hosts" | ""
        ) {
            return Err(ProxyError::Config(format!(
                "unsupported dns.enhanced-mode '{}'",
                self.enhanced_mode
            )));
        }

        let mut bootstraps = Vec::new();
        for b in &self.default_nameserver {
            if !b.trim().is_empty() {
                bootstraps.push(BootstrapDnsServer::parse(b)?);
            }
        }
        let mut needs_bootstrap = false;
        for ns in self
            .nameserver
            .iter()
            .chain(self.direct_nameserver.iter())
            .chain(self.fallback.iter())
        {
            if !ns.trim().is_empty() {
                let up = DnsUpstream::parse(ns)?;
                if up.requires_bootstrap() {
                    needs_bootstrap = true;
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

    #[serde(default = "default_true")]
    pub dns_hijack: bool,

    #[serde(default)]
    pub strict_route: bool,

    #[serde(default)]
    pub ipv6: bool,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inet6_address: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wintun_path: Option<String>,

    #[serde(default = "default_tun_mtu")]
    pub mtu: usize,
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
            Self::Socks5 { password, .. } | Self::Http { password, .. } => {
                if let Some(p) = password
                    && !p.is_empty()
                {
                    *p = REDACTED_SECRET.to_string();
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
                Self::Http { password, .. },
                Self::Http {
                    password: orig_pass,
                    ..
                },
            ) if password.as_deref() == Some(REDACTED_SECRET) => {
                *password = orig_pass.clone();
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
            "urltest" => Ok(Self::UrlTest),
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
}

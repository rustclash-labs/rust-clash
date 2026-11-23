use std::{path::PathBuf, time::Duration};

use anyhow::{Context, Result, anyhow};
use proxy_core::{
    api::parse_explain_target,
    audit::audit_config,
    config::{ClashConfig, uri::redact_sensitive_text},
    engine::ProxyEngine,
    probe::{ProbeOptions, default_matrix_targets, probe_endpoint_matrix, probe_target_waterfall},
};
use serde_json::{Value, json};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
};

#[derive(Clone, Debug)]
pub struct McpServerOptions {
    pub config_path: Option<PathBuf>,
    pub controller: Option<String>,
    pub secret: Option<String>,
    pub allow_mutations: bool,
    pub include_network_metadata: bool,
}

#[derive(Clone, Debug)]
pub struct ControllerClient {
    pub host_port: String,
    pub secret: Option<String>,
}

impl ControllerClient {
    pub fn new(raw: &str, secret: Option<String>) -> Result<Self> {
        let trimmed = raw.trim();
        let stripped = trimmed
            .strip_prefix("http://")
            .or_else(|| trimmed.strip_prefix("https://"))
            .unwrap_or(trimmed)
            .trim_end_matches('/');
        if stripped.is_empty() || stripped.contains('/') || stripped.contains('@') {
            return Err(anyhow!(
                "invalid controller address '{trimmed}' (expected host:port, e.g. 127.0.0.1:9090)"
            ));
        }
        Ok(Self {
            host_port: stripped.to_string(),
            secret: secret.filter(|s| !s.is_empty()),
        })
    }

    /// Perform a lightweight HTTP/1.0 JSON request against the local `rust-clash` controller.
    /// Using HTTP/1.0 guarantees non-chunked responses closed cleanly on EOF by Hyper/Axum.
    pub async fn request_json(
        &self,
        method: &str,
        path_and_query: &str,
        body: Option<&Value>,
        timeout: Duration,
    ) -> Result<(u16, Value)> {
        let connect_fut = TcpStream::connect(&self.host_port);
        let mut stream =
            tokio::time::timeout(Duration::from_millis(1500).min(timeout), connect_fut)
                .await
                .map_err(|_| anyhow!("controller connect timeout ({})", self.host_port))?
                .with_context(|| format!("connect controller {}", self.host_port))?;
        let _ = stream.set_nodelay(true);

        let body_bytes = match body {
            Some(v) => serde_json::to_vec(v)?,
            None => Vec::new(),
        };

        let mut req = format!(
            "{method} {path_and_query} HTTP/1.0\r\nHost: {}\r\nAccept: application/json\r\nConnection: close\r\n",
            self.host_port
        );
        if let Some(ref sec) = self.secret {
            req.push_str(&format!("Authorization: Bearer {sec}\r\n"));
        }
        if body.is_some() {
            req.push_str(&format!(
                "Content-Type: application/json\r\nContent-Length: {}\r\n",
                body_bytes.len()
            ));
        }
        req.push_str("\r\n");

        let io_fut = async {
            stream.write_all(req.as_bytes()).await?;
            if !body_bytes.is_empty() {
                stream.write_all(&body_bytes).await?;
            }
            stream.flush().await?;

            let mut resp = Vec::with_capacity(4096);
            let mut limited = (&mut stream).take(4 * 1024 * 1024);
            limited.read_to_end(&mut resp).await?;
            Ok::<Vec<u8>, std::io::Error>(resp)
        };

        let raw_resp = tokio::time::timeout(timeout, io_fut)
            .await
            .map_err(|_| anyhow!("controller HTTP timeout on {method} {path_and_query}"))??;

        let header_end = raw_resp
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .ok_or_else(|| anyhow!("malformed HTTP response from controller"))?;
        let head_str = String::from_utf8_lossy(&raw_resp[..header_end]);
        let status_line = head_str.lines().next().unwrap_or("");
        let status_code = status_line
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse::<u16>().ok())
            .ok_or_else(|| anyhow!("invalid HTTP status line from controller"))?;

        let payload = &raw_resp[header_end + 4..];
        if payload.iter().all(|b| b.is_ascii_whitespace()) {
            return Ok((status_code, json!({})));
        }
        let parsed: Value = serde_json::from_slice(payload).unwrap_or_else(|_| {
            json!({
                "raw": redact_sensitive_text(&String::from_utf8_lossy(payload)),
            })
        });
        Ok((status_code, parsed))
    }
}

pub fn load_cli_or_profile_config(config_path: Option<&PathBuf>) -> Result<(ClashConfig, String)> {
    let state_dir = proxy_core::platform::recovery::default_state_dir();
    load_cli_or_profile_config_in_state_dir(config_path, &state_dir)
}

fn load_cli_or_profile_config_in_state_dir(
    config_path: Option<&PathBuf>,
    state_dir: &std::path::Path,
) -> Result<(ClashConfig, String)> {
    if let Some(path) = config_path {
        let cfg = ClashConfig::from_file(path)
            .with_context(|| format!("failed to load config '{}'", path.display()))?;
        return Ok((cfg, format!("file:{}", path.display())));
    }
    let mgr = proxy_core::profile::ProfileManager::open_or_init(state_dir)?;
    let (cfg, active_path) = mgr.load_active_config()?;
    Ok((cfg, format!("profile:{}", active_path.display())))
}

fn normalize_controller_host_port(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    let stripped = trimmed
        .strip_prefix("http://")
        .or_else(|| trimmed.strip_prefix("https://"))
        .unwrap_or(trimmed)
        .trim_end_matches('/');
    if stripped.is_empty() || stripped.contains('/') || stripped.contains('@') {
        return None;
    }
    if let Some(rest) = stripped.strip_prefix("0.0.0.0:") {
        return Some(format!("127.0.0.1:{rest}"));
    }
    if let Some(rest) = stripped.strip_prefix("[::]:") {
        return Some(format!("[::1]:{rest}"));
    }
    if let Some(rest) = stripped.strip_prefix("localhost:") {
        return Some(format!("127.0.0.1:{rest}"));
    }
    Some(stripped.to_string())
}

fn same_loopback_endpoint(a: &str, b: &str) -> bool {
    let Some(na) = normalize_controller_host_port(a) else {
        return false;
    };
    let Some(nb) = normalize_controller_host_port(b) else {
        return false;
    };
    let (Ok(sa), Ok(sb)) = (
        na.parse::<std::net::SocketAddr>(),
        nb.parse::<std::net::SocketAddr>(),
    ) else {
        return false;
    };
    if sa.port() != sb.port() {
        return false;
    }
    let canon = |ip: std::net::IpAddr| match ip {
        std::net::IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(std::net::IpAddr::V4)
            .unwrap_or(std::net::IpAddr::V6(v6)),
        std::net::IpAddr::V4(v4) => std::net::IpAddr::V4(v4),
    };
    let ca = canon(sa.ip());
    let cb = canon(sb.ip());
    ca.is_loopback() && cb.is_loopback() && ca == cb
}

pub fn resolve_controller_clients_in_state_dir(
    state_dir: &std::path::Path,
    explicit_controller: Option<&str>,
    explicit_secret: Option<&str>,
    fallback_cfg: Option<&ClashConfig>,
) -> Vec<ControllerClient> {
    let env_secret = std::env::var("RUST_CLASH_SECRET")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let explicit_or_env_secret = explicit_secret
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
        .or(env_secret);
    let cfg_secret = fallback_cfg
        .and_then(|c| c.secret.as_deref())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string);
    let discovery = proxy_core::platform::recovery::read_controller_discovery(state_dir);

    let mut out = Vec::new();
    let mut push_unique = |host: &str, secret: Option<String>| {
        if let Ok(client) = ControllerClient::new(host, secret)
            && !out.iter().any(|existing: &ControllerClient| {
                existing.host_port == client.host_port && existing.secret == client.secret
            })
        {
            out.push(client);
        }
    };

    if let Some(explicit_raw) = explicit_controller.map(str::trim).filter(|s| !s.is_empty()) {
        let host = normalize_controller_host_port(explicit_raw)
            .unwrap_or_else(|| explicit_raw.to_string());
        // Only reuse the local runtime discovery secret when the caller explicitly targets
        // the exact same loopback endpoint (never leak the local secret to another host/port).
        let matching_discovery_secret = discovery
            .as_ref()
            .filter(|ep| same_loopback_endpoint(&host, &ep.addr))
            .and_then(|ep| ep.secret.clone());
        let secret = explicit_or_env_secret
            .or(matching_discovery_secret)
            .or(cfg_secret);
        push_unique(&host, secret);
        return out;
    }

    // 1. Live runtime discovery file written by desktop / CLI daemon (handles ephemeral secret & fallback port)
    if let Some(ep) = discovery {
        let secret = explicit_or_env_secret.clone().or(ep.secret);
        push_unique(&ep.addr, secret);
    }

    // 2. Fallback to active config external-controller or default 127.0.0.1:9090
    let fallback_raw = fallback_cfg
        .map(|c| c.external_controller.trim())
        .filter(|s| !s.is_empty())
        .unwrap_or("127.0.0.1:9090");
    let fallback_host = normalize_controller_host_port(fallback_raw)
        .unwrap_or_else(|| "127.0.0.1:9090".to_string());
    let fallback_secret = explicit_or_env_secret.or(cfg_secret);
    push_unique(&fallback_host, fallback_secret);

    out
}

pub fn resolve_controller_clients(
    explicit_controller: Option<&str>,
    explicit_secret: Option<&str>,
    fallback_cfg: Option<&ClashConfig>,
) -> Vec<ControllerClient> {
    let state_dir = proxy_core::platform::recovery::default_state_dir();
    resolve_controller_clients_in_state_dir(
        &state_dir,
        explicit_controller,
        explicit_secret,
        fallback_cfg,
    )
}

pub(crate) enum LiveControllerOutcome {
    Response {
        client: ControllerClient,
        status: u16,
        body: Value,
    },
    AuthRejected {
        status: u16,
    },
    Unreachable,
}

pub(crate) async fn request_live_controller_json(
    clients: &[ControllerClient],
    method: &str,
    path_and_query: &str,
    body: Option<&Value>,
    timeout: Duration,
) -> LiveControllerOutcome {
    let mut auth_rejected: Option<u16> = None;
    for client in clients {
        match client
            .request_json(method, path_and_query, body, timeout)
            .await
        {
            Ok((status, _)) if matches!(status, 401 | 403) => {
                if auth_rejected.is_none() {
                    auth_rejected = Some(status);
                }
            }
            Ok((status, resp)) => {
                return LiveControllerOutcome::Response {
                    client: client.clone(),
                    status,
                    body: resp,
                };
            }
            Err(_) => {
                // Stale discovery endpoint or dead port — smoothly try next candidate.
            }
        }
    }
    match auth_rejected {
        Some(status) => LiveControllerOutcome::AuthRejected { status },
        None => LiveControllerOutcome::Unreachable,
    }
}

pub(crate) fn auth_rejected_note(status: u16) -> String {
    let label = if status == 401 {
        "Unauthorized"
    } else {
        "Forbidden"
    };
    format!(
        "Live rust-clash controller rejected authentication (HTTP {status} {label}); showing offline profile snapshot. Check --secret / RUST_CLASH_SECRET, or restart rust-clash-desktop to refresh its runtime controller discovery file."
    )
}

pub fn url_encode_component(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for b in raw.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn sanitize_source_label(src: &str, include_network_metadata: bool) -> String {
    if include_network_metadata {
        return src.to_string();
    }
    if let Some(rest) = src.strip_prefix("file:") {
        let name = std::path::Path::new(rest)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("config.yaml");
        format!("file:{name}")
    } else if src.starts_with("profile:") {
        "profile:active".to_string()
    } else {
        src.to_string()
    }
}

fn has_yaml_extension_and_stem(path: &std::path::Path) -> bool {
    let has_yaml_ext = path
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case("yaml") || ext.eq_ignore_ascii_case("yml"));
    let has_stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .is_some_and(|s| !s.is_empty());
    has_yaml_ext && has_stem
}

fn validate_audit_config_path(raw: &str) -> std::result::Result<PathBuf, &'static str> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.chars().any(|c| c.is_control()) {
        return Err("invalid config_path: path must not be empty or contain control characters");
    }
    if trimmed.split(['/', '\\']).any(|seg| seg == "..") {
        return Err("invalid config_path: parent directory traversal ('..') is forbidden");
    }
    let path = PathBuf::from(trimmed);
    if path
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err("invalid config_path: parent directory traversal ('..') is forbidden");
    }
    if !has_yaml_extension_and_stem(&path) {
        return Err("invalid config_path: only '.yaml' or '.yml' configuration files are allowed");
    }

    let sym_meta = std::fs::symlink_metadata(&path)
        .map_err(|_| "failed to load config_path: file does not exist or is unreadable")?;
    if sym_meta.file_type().is_symlink() {
        return Err("invalid config_path: symbolic links are forbidden");
    }
    if !sym_meta.file_type().is_file() {
        return Err("invalid config_path: target must be a regular '.yaml' or '.yml' file");
    }

    let canon = std::fs::canonicalize(&path)
        .map_err(|_| "failed to load config_path: file does not exist or is unreadable")?;
    if !has_yaml_extension_and_stem(&canon) {
        return Err(
            "invalid config_path: canonicalized target must be a '.yaml' or '.yml' configuration file",
        );
    }
    let canon_meta = std::fs::metadata(&canon)
        .map_err(|_| "failed to load config_path: file does not exist or is unreadable")?;
    if !canon_meta.is_file() {
        return Err("invalid config_path: target must be a regular '.yaml' or '.yml' file");
    }
    Ok(canon)
}

fn sanitize_audit_file_error(path: &std::path::Path) -> &'static str {
    match std::fs::symlink_metadata(path) {
        Err(_) => "failed to load config_path: file does not exist or is unreadable",
        Ok(meta) if meta.file_type().is_symlink() => {
            "invalid config_path: symbolic links are forbidden"
        }
        Ok(meta) if !meta.file_type().is_file() => {
            "invalid config_path: target must be a regular '.yaml' or '.yml' file"
        }
        Ok(_) => {
            "failed to parse or validate Clash YAML at config_path (syntax or schema error; raw file contents redacted)"
        }
    }
}

fn looks_like_ip_or_sockaddr_token(tok: &str) -> bool {
    if tok.is_empty() {
        return false;
    }
    if tok.parse::<std::net::IpAddr>().is_ok() || tok.parse::<std::net::SocketAddr>().is_ok() {
        return true;
    }
    if let Some(inner) = tok.strip_prefix('[').and_then(|s| s.strip_suffix(']'))
        && inner.parse::<std::net::IpAddr>().is_ok()
    {
        return true;
    }
    false
}

fn scrub_text_network_tokens(raw: &str, extra_needles: &[String]) -> String {
    let mut out = redact_sensitive_text(raw);
    let mut sorted_needles: Vec<&str> = extra_needles
        .iter()
        .map(String::as_str)
        .filter(|s| !s.is_empty() && *s != "<redacted>" && *s != "[endpoint-redacted]")
        .collect();
    sorted_needles.sort_by_key(|s| std::cmp::Reverse(s.len()));
    sorted_needles.dedup();
    for needle in sorted_needles {
        out = out.replace(needle, "<redacted>");
    }

    let mut rebuilt = String::with_capacity(out.len());
    for chunk in out.split_inclusive(char::is_whitespace) {
        let ws_idx = chunk.find(char::is_whitespace).unwrap_or(chunk.len());
        let (word, trailing_ws) = chunk.split_at(ws_idx);
        let core = word.trim_matches(|c: char| {
            matches!(
                c,
                '\'' | '"' | '`' | '(' | ')' | ',' | ';' | '.' | '<' | '>'
            )
        });
        if !core.is_empty() && looks_like_ip_or_sockaddr_token(core) {
            rebuilt.push_str(&word.replacen(core, "<redacted>", 1));
        } else {
            rebuilt.push_str(word);
        }
        rebuilt.push_str(trailing_ws);
    }
    rebuilt
}

fn scrub_quoted_audit_endpoints(raw: &str) -> String {
    let mut out = raw.to_string();
    for marker in ["server '", "set to '"] {
        let mut search_from = 0usize;
        while let Some(rel_idx) = out[search_from..].find(marker) {
            let val_start = search_from + rel_idx + marker.len();
            if let Some(end_rel) = out[val_start..].find('\'') {
                let val_end = val_start + end_rel;
                out.replace_range(val_start..val_end, "<redacted>");
                search_from = val_start + "<redacted>".len() + 1;
            } else {
                break;
            }
        }
    }
    out
}

fn scrub_audit_payload(payload: &mut Value, include_network_metadata: bool) {
    if include_network_metadata {
        payload["metadata_privacy_mode"] = json!("full");
        return;
    }
    payload["metadata_privacy_mode"] = json!(
        "redacted (proxy server endpoints hidden by default; relaunch with --include-network-metadata to expose)"
    );
    if payload.get("controller").is_some() && !payload["controller"].is_null() {
        payload["controller"] = json!("<redacted>");
    }
    if let Some(src) = payload.get("source").and_then(|v| v.as_str())
        && src.starts_with("live_controller:")
    {
        payload["source"] = json!("live_controller:<redacted>");
    }

    if let Some(findings) = payload
        .get_mut("audit")
        .and_then(|a| a.get_mut("findings"))
        .and_then(|f| f.as_array_mut())
    {
        for finding in findings {
            let mut extracted_needles: Vec<String> = Vec::new();

            if let Some(loc) = finding
                .get("location")
                .and_then(|v| v.as_str())
                .map(str::to_string)
            {
                if loc.starts_with("proxies[")
                    && let Some(paren_idx) = loc.find(" (")
                {
                    let inner = loc[paren_idx + 2..].trim_end_matches(')');
                    if !inner.is_empty() {
                        extracted_needles.push(inner.to_string());
                    }
                    let scrubbed_loc = format!("{} ([endpoint-redacted])", &loc[..paren_idx]);
                    finding["location"] = json!(scrubbed_loc);
                } else if let Some(rest) = loc.strip_prefix("external-controller (") {
                    let inner = rest.trim_end_matches(')');
                    if !inner.is_empty() {
                        extracted_needles.push(inner.to_string());
                    }
                    finding["location"] = json!("external-controller (<redacted>)");
                } else if let Some(bind_idx) = loc.find("bind-address=") {
                    let bind_val = loc[bind_idx + "bind-address=".len()..].trim();
                    if !matches!(bind_val, "" | "*" | "0.0.0.0" | "::" | "[::]") {
                        extracted_needles.push(bind_val.to_string());
                        let scrubbed_loc = format!("{}bind-address=<redacted>", &loc[..bind_idx]);
                        finding["location"] = json!(scrubbed_loc);
                    }
                }
            }

            if let Some(detail) = finding
                .get("detail")
                .and_then(|v| v.as_str())
                .map(str::to_string)
            {
                let after_quotes = scrub_quoted_audit_endpoints(&detail);
                let scrubbed_detail = scrub_text_network_tokens(&after_quotes, &extracted_needles);
                finding["detail"] = json!(scrubbed_detail);
            }
        }
    }

    if let Some(diff) = payload.get_mut("diff").and_then(|d| d.as_object_mut()) {
        if let Some(added) = diff.get_mut("added_proxies").and_then(|a| a.as_array_mut()) {
            for p in added {
                if p.get("server").is_some() {
                    p["server"] = json!("[endpoint-redacted]");
                }
                if p.get("port").is_some() {
                    p["port"] = json!("<redacted>");
                }
            }
        }
        if let Some(changed) = diff
            .get_mut("changed_proxies")
            .and_then(|c| c.as_array_mut())
        {
            for p in changed {
                if let Some(changes) = p.get_mut("changes").and_then(|ch| ch.as_array_mut()) {
                    for entry in changes {
                        if let Some(s) = entry.as_str()
                            && s.starts_with("endpoint:")
                        {
                            *entry = json!("endpoint: [redacted]");
                        }
                    }
                }
            }
        }
    }
}

fn collect_waterfall_needles(report: &Value, needles: &mut Vec<String>) {
    for key in [
        "requested_proxy",
        "effective_outbound",
        "url",
        "target_host",
        "server_header",
    ] {
        if let Some(s) = report.get(key).and_then(|v| v.as_str())
            && !s.is_empty()
        {
            needles.push(s.to_string());
        }
    }
    if let (Some(host), Some(port)) = (
        report.get("target_host").and_then(|v| v.as_str()),
        report.get("target_port").and_then(|v| v.as_u64()),
    ) && !host.is_empty()
    {
        needles.push(format!("{host}:{port}"));
    }
    if let Some(chains) = report.get("chains").and_then(|v| v.as_array()) {
        for ch in chains {
            if let Some(s) = ch.as_str()
                && !s.is_empty()
            {
                needles.push(s.to_string());
            }
        }
    }
    if let Some(udp_target) = report
        .get("udp_probe")
        .and_then(|u| u.get("target"))
        .and_then(|v| v.as_str())
        && !udp_target.is_empty()
    {
        needles.push(udp_target.to_string());
    }
}

fn scrub_waterfall_report_in_place(report: &mut Value, extra_needles: &[String]) {
    let mut needles = extra_needles.to_vec();
    collect_waterfall_needles(report, &mut needles);

    let Some(obj) = report.as_object_mut() else {
        return;
    };

    if obj.contains_key("chains") {
        obj.insert("chains".to_string(), json!(["<redacted>"]));
    }
    for key in [
        "requested_proxy",
        "effective_outbound",
        "url",
        "target_host",
        "target_port",
    ] {
        if obj.contains_key(key) {
            obj.insert(key.to_string(), json!("<redacted>"));
        }
    }
    if let Some(sh) = obj.get_mut("server_header")
        && !sh.is_null()
    {
        *sh = json!("<redacted>");
    }
    for text_key in ["note", "error"] {
        if let Some(s) = obj
            .get(text_key)
            .and_then(|v| v.as_str())
            .map(str::to_string)
        {
            obj.insert(
                text_key.to_string(),
                json!(scrub_text_network_tokens(&s, &needles)),
            );
        }
    }
    if let Some(udp_obj) = obj.get_mut("udp_probe").and_then(|u| u.as_object_mut()) {
        if let Some(tgt) = udp_obj.get_mut("target")
            && !tgt.is_null()
        {
            *tgt = json!("<redacted>");
        }
        if let Some(det) = udp_obj
            .get("detail")
            .and_then(|v| v.as_str())
            .map(str::to_string)
        {
            udp_obj.insert(
                "detail".to_string(),
                json!(scrub_text_network_tokens(&det, &needles)),
            );
        }
    }
}

fn scrub_waterfall_payload(
    payload: &mut Value,
    include_network_metadata: bool,
    extra_needles: &[String],
) {
    if include_network_metadata {
        if let Some(obj) = payload.as_object_mut() {
            obj.insert("metadata_privacy_mode".to_string(), json!("full"));
        }
        return;
    }
    scrub_waterfall_report_in_place(payload, extra_needles);
    if let Some(obj) = payload.as_object_mut() {
        obj.insert("metadata_privacy_mode".to_string(), json!("redacted"));
    }
}

fn scrub_matrix_payload(
    payload: &mut Value,
    include_network_metadata: bool,
    extra_needles: &[String],
) {
    if include_network_metadata {
        if let Some(obj) = payload.as_object_mut() {
            obj.insert("metadata_privacy_mode".to_string(), json!("full"));
        }
        return;
    }

    let mut needles = extra_needles.to_vec();
    for key in ["requested_proxy", "effective_outbound"] {
        if let Some(s) = payload.get(key).and_then(|v| v.as_str())
            && !s.is_empty()
        {
            needles.push(s.to_string());
        }
    }
    if let Some(chains) = payload.get("chains").and_then(|v| v.as_array()) {
        for ch in chains {
            if let Some(s) = ch.as_str()
                && !s.is_empty()
            {
                needles.push(s.to_string());
            }
        }
    }
    if let Some(udp_tgt) = payload
        .get("udp_probe")
        .and_then(|u| u.get("target"))
        .and_then(|v| v.as_str())
        && !udp_tgt.is_empty()
    {
        needles.push(udp_tgt.to_string());
    }
    if let Some(items) = payload.get("items").and_then(|v| v.as_array()) {
        for item in items {
            if let Some(u) = item.get("url").and_then(|v| v.as_str())
                && !u.is_empty()
            {
                needles.push(u.to_string());
            }
            if let Some(rep) = item.get("report") {
                collect_waterfall_needles(rep, &mut needles);
            }
        }
    }

    let Some(obj) = payload.as_object_mut() else {
        return;
    };
    obj.insert("metadata_privacy_mode".to_string(), json!("redacted"));
    if obj.contains_key("chains") {
        obj.insert("chains".to_string(), json!(["<redacted>"]));
    }
    for key in ["requested_proxy", "effective_outbound"] {
        if obj.contains_key(key) {
            obj.insert(key.to_string(), json!("<redacted>"));
        }
    }
    if let Some(note) = obj
        .get("ai_status_note")
        .and_then(|v| v.as_str())
        .map(str::to_string)
    {
        obj.insert(
            "ai_status_note".to_string(),
            json!(scrub_text_network_tokens(&note, &needles)),
        );
    }
    if let Some(udp_obj) = obj.get_mut("udp_probe").and_then(|u| u.as_object_mut()) {
        if let Some(tgt) = udp_obj.get_mut("target")
            && !tgt.is_null()
        {
            *tgt = json!("<redacted>");
        }
        if let Some(det) = udp_obj
            .get("detail")
            .and_then(|v| v.as_str())
            .map(str::to_string)
        {
            udp_obj.insert(
                "detail".to_string(),
                json!(scrub_text_network_tokens(&det, &needles)),
            );
        }
    }
    if let Some(items) = obj.get_mut("items").and_then(|v| v.as_array_mut()) {
        for item in items {
            if let Some(item_obj) = item.as_object_mut() {
                if item_obj.contains_key("url") {
                    item_obj.insert("url".to_string(), json!("<redacted>"));
                }
                if let Some(rep) = item_obj.get_mut("report") {
                    scrub_waterfall_report_in_place(rep, &needles);
                }
            }
        }
    }
}

fn scrub_probe_error_payload(
    payload: &mut Value,
    include_network_metadata: bool,
    extra_needles: &[String],
) {
    if include_network_metadata {
        return;
    }
    if let Some(obj) = payload.as_object_mut() {
        for key in ["error", "message", "detail", "raw"] {
            if let Some(s) = obj.get(key).and_then(|v| v.as_str()).map(str::to_string) {
                obj.insert(
                    key.to_string(),
                    json!(scrub_text_network_tokens(&s, extra_needles)),
                );
            }
        }
    }
}

fn scrub_explain_payload(payload: &mut Value, include_network_metadata: bool) {
    if include_network_metadata {
        payload["metadata_privacy_mode"] = json!("full");
        return;
    }
    payload["metadata_privacy_mode"] = json!("redacted");
    if payload.get("exit_type").and_then(|v| v.as_str()) == Some("PROXY") {
        payload["remote_endpoint"] = json!(
            "[redacted-by-default; relaunch `rust-clash mcp --include-network-metadata` to expose proxy server endpoint]"
        );
    }
}

fn scrub_diagnostic_entries(entries: &mut Value, include_network_metadata: bool) {
    if include_network_metadata {
        return;
    }
    let Some(arr) = entries.as_array_mut() else {
        return;
    };
    for item in arr {
        let orig_host = item
            .get("metadata")
            .and_then(|m| m.get("host"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let orig_dst_ip = item
            .get("metadata")
            .and_then(|m| m.get("destination_ip"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let orig_remote = item
            .get("remote_endpoint")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        if item.get("remote_endpoint").is_some() {
            item["remote_endpoint"] = json!("[redacted-by-default]");
        }
        if let Some(meta) = item.get_mut("metadata").and_then(|m| m.as_object_mut()) {
            meta.insert("host".to_string(), json!("[redacted-destination-host]"));
            meta.insert("destination_ip".to_string(), Value::Null);
            meta.insert("source".to_string(), json!("[redacted-client-source]"));
            meta.insert("fake_ip".to_string(), Value::Null);
        }
        if let Some(err_str) = item.get("error").and_then(|e| e.as_str()) {
            let mut cleaned = err_str.to_string();
            for needle in [&orig_host, &orig_dst_ip, &orig_remote] {
                if !needle.is_empty() {
                    cleaned = cleaned.replace(needle, "[redacted]");
                }
            }
            item["error"] = json!(cleaned);
        }
    }
}

fn summarize_recent_connections(entries: &[Value]) -> Value {
    let mut active = 0usize;
    let mut connecting = 0usize;
    let mut closed = 0usize;
    let mut failed = 0usize;
    let mut by_exit: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    let mut by_network: std::collections::BTreeMap<String, usize> =
        std::collections::BTreeMap::new();
    let mut by_rule_type: std::collections::BTreeMap<String, usize> =
        std::collections::BTreeMap::new();
    let mut zero_download_tcp_count = 0usize;
    let mut tun_fake_ip_count = 0usize;
    let mut tun_real_ip_count = 0usize;
    let mut sniffer_hit_count = 0usize;

    for item in entries {
        match item.get("status").and_then(|v| v.as_str()).unwrap_or("") {
            "active" => active += 1,
            "connecting" => connecting += 1,
            "closed" => closed += 1,
            "failed" => failed += 1,
            _ => {}
        }
        let exit = item
            .get("exit_type")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .unwrap_or("UNKNOWN");
        *by_exit.entry(exit.to_string()).or_insert(0) += 1;

        let rule_type = item
            .get("rule")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .unwrap_or("UNKNOWN");
        *by_rule_type.entry(rule_type.to_string()).or_insert(0) += 1;

        let net = item
            .get("metadata")
            .and_then(|m| m.get("network"))
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .unwrap_or("unknown");
        *by_network.entry(net.to_string()).or_insert(0) += 1;

        let upload = item.get("upload").and_then(|v| v.as_u64()).unwrap_or(0);
        let download = item.get("download").and_then(|v| v.as_u64()).unwrap_or(0);
        if net.eq_ignore_ascii_case("tcp") && upload > 0 && download == 0 {
            zero_download_tcp_count += 1;
        }

        if item
            .get("metadata")
            .and_then(|m| m.get("sniffed"))
            .and_then(|v| v.as_bool())
            == Some(true)
        {
            sniffer_hit_count += 1;
        }

        let inbound = item
            .get("metadata")
            .and_then(|m| m.get("type").or_else(|| m.get("inbound")))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if inbound.starts_with("TUN") {
            let has_fake_ip = item
                .get("metadata")
                .and_then(|m| m.get("fake_ip"))
                .and_then(|v| v.as_str())
                .is_some_and(|s| !s.is_empty());
            if has_fake_ip {
                tun_fake_ip_count += 1;
            } else {
                tun_real_ip_count += 1;
            }
        }
    }

    json!({
        "sampled_count": entries.len(),
        "by_status": {
            "active": active,
            "connecting": connecting,
            "closed": closed,
            "failed": failed,
        },
        "by_exit_type": by_exit,
        "by_network": by_network,
        "by_rule_type": by_rule_type,
        "zero_download_tcp_count": zero_download_tcp_count,
        "tun_fake_ip_count": tun_fake_ip_count,
        "tun_real_ip_count": tun_real_ip_count,
        "sniffer_hit_count": sniffer_hit_count,
    })
}

fn redact_network_tokens_in_log(text: &str) -> String {
    text.split_whitespace()
        .map(|tok| {
            // Preserve `[...]` brackets on the first pass so bracketed IPv6 SocketAddrs such as
            // `[2001:db8::1]:443` parse cleanly via `SocketAddr::parse`.
            let outer = tok.trim_matches(|c: char| {
                matches!(c, '(' | ')' | ',' | ';' | '\'' | '"' | '<' | '>')
            });
            let inner = outer.trim_matches(|c: char| matches!(c, '[' | ']'));
            let is_domain_port = |s: &str| -> bool {
                s.contains('.')
                    && s.contains(':')
                    && s.rsplit_once(':')
                        .is_some_and(|(h, p)| !h.is_empty() && p.parse::<u16>().is_ok())
            };
            let looks_like_endpoint = outer.parse::<std::net::SocketAddr>().is_ok()
                || outer.parse::<std::net::IpAddr>().is_ok()
                || inner.parse::<std::net::SocketAddr>().is_ok()
                || inner.parse::<std::net::IpAddr>().is_ok()
                || outer.starts_with("http://")
                || outer.starts_with("https://")
                || inner.starts_with("http://")
                || inner.starts_with("https://")
                || is_domain_port(outer)
                || is_domain_port(inner);
            if looks_like_endpoint {
                "[redacted-endpoint]"
            } else {
                tok
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LogFilterLevel {
    Error,
    Warn,
    Info,
    All,
}

impl LogFilterLevel {
    fn parse(raw: &str) -> std::result::Result<Self, String> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "error" | "err" => Ok(Self::Error),
            "warn" | "warning" => Ok(Self::Warn),
            "info" => Ok(Self::Info),
            "all" => Ok(Self::All),
            other => Err(format!(
                "invalid log level '{other}': expected one of 'error', 'warn', 'info', or 'all'"
            )),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warn => "warn",
            Self::Info => "info",
            Self::All => "all",
        }
    }

    fn matches(self, entry_level: &str) -> bool {
        match self {
            Self::Error => matches!(entry_level, "error" | "err"),
            Self::Warn => matches!(entry_level, "warn" | "warning" | "error" | "err"),
            Self::Info => matches!(entry_level, "info" | "warn" | "warning" | "error" | "err"),
            Self::All => true,
        }
    }
}

fn extract_recent_logs_filtered(
    logs_val: Option<&Value>,
    filter_level: LogFilterLevel,
    limit: usize,
    include_network_metadata: bool,
) -> Value {
    let Some(arr) = logs_val
        .and_then(|v| v.get("logs"))
        .and_then(|v| v.as_array())
    else {
        return json!([]);
    };
    let cap = limit.clamp(1, 100);
    let mut out = Vec::new();
    for entry in arr.iter().rev() {
        let level = entry
            .get("type")
            .or_else(|| entry.get("level"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        if !filter_level.matches(&level) {
            continue;
        }
        let raw_msg = entry.get("payload").and_then(|v| v.as_str()).unwrap_or("");
        let secret_safe = redact_sensitive_text(raw_msg);
        let msg = if include_network_metadata {
            secret_safe
        } else {
            redact_network_tokens_in_log(&secret_safe)
        };
        out.push(json!({
            "timestamp_ms": entry.get("timestamp_ms"),
            "level": level,
            "payload": msg,
        }));
        if out.len() >= cap {
            break;
        }
    }
    Value::Array(out)
}

fn extract_recent_warn_error_logs(
    logs_val: Option<&Value>,
    limit: usize,
    include_network_metadata: bool,
) -> Value {
    extract_recent_logs_filtered(
        logs_val,
        LogFilterLevel::Warn,
        limit,
        include_network_metadata,
    )
}

fn build_tools_list(allow_mutations: bool) -> Vec<Value> {
    let mut tools = vec![
        json!({
            "name": "audit_config_security",
            "description": "Run static config security audit, rule shadowing/dead-rule linter, and Split-DNS route simulator. Credentials are strictly redacted; pass `config_path` to audit a local YAML file without placing secrets into LLM prompt context.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "config_path": {
                        "type": "string",
                        "description": "Optional local filesystem path to a Clash YAML file to audit on disk (and diff against active config) without sending credentials through LLM context. Omit to audit the active configuration."
                    },
                    "resolve_dns": {
                        "type": "boolean",
                        "description": "When auditing the live daemon without `config_path`, optionally resolve domain IPs via configured DNS to evaluate IP-CIDR/GEOIP rules (default false)."
                    }
                },
                "additionalProperties": false
            }
        }),
        json!({
            "name": "explain_route",
            "description": "Deterministically trace how a target domain, IP, Fake-IP (`198.18.x.x`), or `host:port` is routed across rules, policy groups, and leaf outbound protocols.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target domain, IP, or host:port (e.g. 'api.anthropic.com:443' or '192.168.1.1')"
                    },
                    "src_ip": {
                        "type": "string",
                        "description": "Optional client source IP for SRC-IP-CIDR rules"
                    }
                },
                "required": ["target"],
                "additionalProperties": false
            }
        }),
        json!({
            "name": "probe_waterfall",
            "description": "Execute a Surge-grade per-stage timing waterfall probe (DNS -> Tunnel Connect -> TLS Handshake -> HTTP TTFB + parallel UDP DNS relay verification) on public endpoints (private/loopback/metadata targets blocked by SSRF guard).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "proxy": {
                        "type": "string",
                        "description": "Proxy node or group name (defaults to primary group or 'DIRECT')"
                    },
                    "url": {
                        "type": "string",
                        "description": "Public HTTP or HTTPS target URL (e.g. 'https://api.openai.com/v1/models')"
                    },
                    "timeout_ms": {
                        "type": "integer",
                        "description": "Probe timeout in milliseconds (300..=20000, default 5000)"
                    },
                    "check_udp": {
                        "type": "boolean",
                        "description": "Also verify real UDP datagram relay over the resolved leaf outbound (default true)"
                    }
                },
                "additionalProperties": false
            }
        }),
        json!({
            "name": "probe_ai_matrix",
            "description": "Probe AI & developer endpoints (Cloudflare Edge, GitHub API, OpenAI API, Anthropic Claude API, Google Gemini API) plus UDP relay readiness, distinguishing AuthRequired (401), RateLimited (429), and BlockedOrChallenged (403/451).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "proxy": {
                        "type": "string",
                        "description": "Proxy node or group name (defaults to primary group or 'DIRECT')"
                    },
                    "timeout_ms": {
                        "type": "integer",
                        "description": "Per-endpoint timeout in milliseconds (500..=15000, default 4500)"
                    }
                },
                "additionalProperties": false
            }
        }),
        json!({
            "name": "get_proxy_status",
            "description": "Return credential-redacted active proxy status, routing mode, effective outbound chain, selector group states, privacy-filtered recent connection failure diagnostics, rule/sniffer distribution summary, and recent warnings/errors.",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "additionalProperties": false
            }
        }),
        json!({
            "name": "get_recent_logs",
            "description": "Return credential- and endpoint-redacted recent daemon logs filtered by minimum severity (`error`, `warn`, `info`, or `all`). Launch `rust-clash mcp --include-network-metadata` to retain raw network endpoints.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "level": {
                        "type": "string",
                        "enum": ["error", "warn", "info", "all"],
                        "description": "Minimum severity filter: 'error', 'warn' (warn+error, default), 'info' (info+warn+error), or 'all'."
                    },
                    "limit": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 100,
                        "description": "Maximum number of newest log entries to return (default 30, max 100)."
                    }
                },
                "additionalProperties": false
            }
        }),
    ];

    if allow_mutations {
        tools.push(json!({
            "name": "switch_proxy_selector",
            "description": "Switch a `Selector` proxy group to a specific member node or policy on the running `rust-clash` daemon (enabled via `--allow-mutations`).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "group": {
                        "type": "string",
                        "description": "Selector group name (e.g. 'PROXY' or '🚀 Proxy')"
                    },
                    "proxy": {
                        "type": "string",
                        "description": "Member node or sub-group name to select"
                    }
                },
                "required": ["group", "proxy"],
                "additionalProperties": false
            }
        }));
    }

    tools
}

fn mcp_tool_result(payload: &Value, is_error: bool) -> Value {
    let pretty = serde_json::to_string_pretty(payload).unwrap_or_else(|_| "{}".to_string());
    let scrubbed = redact_sensitive_text(&pretty);
    json!({
        "content": [
            {
                "type": "text",
                "text": scrubbed
            }
        ],
        "isError": is_error
    })
}

async fn pick_default_proxy_name(clients: &[ControllerClient], cfg: &ClashConfig) -> String {
    if let LiveControllerOutcome::Response {
        status: 200,
        body: val,
        ..
    } = request_live_controller_json(
        clients,
        "GET",
        "/proxies",
        None,
        Duration::from_millis(1500),
    )
    .await
        && let Some(pg) = val
            .get("effective-outbound")
            .and_then(|e| e.get("primary_group"))
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
    {
        return pg.to_string();
    }
    if let Some(first_grp) = cfg.proxy_groups.first() {
        return first_grp.name.clone();
    }
    if let Some(first_node) = cfg.proxies.first() {
        return first_node.name().to_string();
    }
    "DIRECT".to_string()
}

async fn execute_tool_call(name: &str, args: &Value, opts: &McpServerOptions) -> Value {
    let state_dir = proxy_core::platform::recovery::default_state_dir();
    execute_tool_call_with_state_dir(name, args, opts, &state_dir).await
}

async fn execute_tool_call_with_state_dir(
    name: &str,
    args: &Value,
    opts: &McpServerOptions,
    state_dir: &std::path::Path,
) -> Value {
    let loaded = load_cli_or_profile_config_in_state_dir(opts.config_path.as_ref(), state_dir);
    let fallback_cfg = loaded.as_ref().ok().map(|(c, _)| c);
    let ctrl_clients = resolve_controller_clients_in_state_dir(
        state_dir,
        opts.controller.as_deref(),
        opts.secret.as_deref(),
        fallback_cfg,
    );

    match name {
        "audit_config_security" => {
            if args.get("yaml").is_some() {
                return mcp_tool_result(
                    &json!({
                        "error": "Security policy: passing raw `yaml` text in MCP tool arguments is disabled so node passwords/UUIDs never enter LLM context prior to redaction. Pass a local `config_path` instead, or omit arguments to audit the active configuration."
                    }),
                    true,
                );
            }

            let draft_path = args
                .get("config_path")
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty());
            let resolve_dns = args
                .get("resolve_dns")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            if let Some(path_str) = draft_path {
                let path_buf = match validate_audit_config_path(path_str) {
                    Ok(p) => p,
                    Err(reason) => {
                        return mcp_tool_result(&json!({ "error": reason }), true);
                    }
                };
                match ClashConfig::from_file(&path_buf) {
                    Ok(draft_cfg) => {
                        let report = audit_config(&draft_cfg);
                        let diff = fallback_cfg
                            .map(|base| proxy_core::audit::diff_configs(base, &draft_cfg));
                        let src = sanitize_source_label(
                            &format!("file:{}", path_buf.display()),
                            opts.include_network_metadata,
                        );
                        let mut out = json!({
                            "source": src,
                            "controller": draft_cfg.external_controller,
                            "audit": report,
                            "diff": diff,
                        });
                        scrub_audit_payload(&mut out, opts.include_network_metadata);
                        mcp_tool_result(&out, false)
                    }
                    Err(_) => mcp_tool_result(
                        &json!({ "error": sanitize_audit_file_error(&path_buf) }),
                        true,
                    ),
                }
            } else {
                let audit_endpoint = if resolve_dns {
                    "/diagnostics/audit?resolve_dns=true"
                } else {
                    "/diagnostics/audit"
                };
                let auth_rejected_status = match request_live_controller_json(
                    &ctrl_clients,
                    "GET",
                    audit_endpoint,
                    None,
                    Duration::from_secs(6),
                )
                .await
                {
                    LiveControllerOutcome::Response {
                        client: c,
                        status: 200,
                        body: resp,
                    } => {
                        let mut out = json!({
                            "source": format!("live_controller:{}", c.host_port),
                            "controller": c.host_port,
                            "audit": resp,
                        });
                        scrub_audit_payload(&mut out, opts.include_network_metadata);
                        return mcp_tool_result(&out, false);
                    }
                    LiveControllerOutcome::AuthRejected { status } => Some(status),
                    _ => None,
                };

                match loaded {
                    Ok((cfg, src)) => {
                        let report = audit_config(&cfg);
                        let mut out = json!({
                            "source": sanitize_source_label(&src, opts.include_network_metadata),
                            "controller": cfg.external_controller,
                            "audit": report,
                        });
                        if let Some(status) = auth_rejected_status
                            && let Some(obj) = out.as_object_mut()
                        {
                            obj.insert("auth_error".to_string(), json!(true));
                            obj.insert("http_status".to_string(), json!(status));
                            obj.insert("note".to_string(), json!(auth_rejected_note(status)));
                        }
                        scrub_audit_payload(&mut out, opts.include_network_metadata);
                        mcp_tool_result(&out, false)
                    }
                    Err(e) => mcp_tool_result(
                        &json!({ "error": redact_sensitive_text(&e.to_string()) }),
                        true,
                    ),
                }
            }
        }

        "explain_route" => {
            let Some(raw_target) = args
                .get("target")
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
            else {
                return mcp_tool_result(
                    &json!({ "error": "missing required string parameter 'target'" }),
                    true,
                );
            };
            let raw_src = args
                .get("src_ip")
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty());

            let mut pq = format!("/rules/explain?target={}", url_encode_component(raw_target));
            if let Some(sip) = raw_src {
                pq.push_str(&format!("&src_ip={}", url_encode_component(sip)));
            }
            let auth_rejected_status = match request_live_controller_json(
                &ctrl_clients,
                "GET",
                &pq,
                None,
                Duration::from_secs(4),
            )
            .await
            {
                LiveControllerOutcome::Response {
                    status,
                    body: mut resp,
                    ..
                } if (200..300).contains(&status) => {
                    scrub_explain_payload(&mut resp, opts.include_network_metadata);
                    return mcp_tool_result(&resp, false);
                }
                LiveControllerOutcome::AuthRejected { status } => Some(status),
                _ => None,
            };

            let (cfg, src_label) = match loaded {
                Ok(pair) => pair,
                Err(e) => {
                    return mcp_tool_result(
                        &json!({ "error": redact_sensitive_text(&e.to_string()) }),
                        true,
                    );
                }
            };
            let target = match parse_explain_target(raw_target) {
                Ok(t) => t,
                Err(msg) => return mcp_tool_result(&json!({ "error": msg }), true),
            };
            let src_ip = match raw_src {
                Some(s) => match s.parse::<std::net::IpAddr>() {
                    Ok(ip) => Some(ip),
                    Err(e) => {
                        return mcp_tool_result(
                            &json!({ "error": format!("invalid src_ip: {e}") }),
                            true,
                        );
                    }
                },
                None => None,
            };
            match ProxyEngine::build_standalone_router(&cfg) {
                Ok(router) => {
                    let decision = router.route_async(src_ip, &target).await;
                    let mut out = json!({
                        "source": sanitize_source_label(&src_label, opts.include_network_metadata),
                        "input": raw_target,
                        "normalized_target": decision.target.to_string(),
                        "restored_from_fake_ip": decision.restored_from_fake_ip.map(|ip| ip.to_string()),
                        "mode": router.mode(),
                        "rule_type": decision.rule_type,
                        "rule_payload": decision.rule_payload,
                        "chains": decision.chains,
                        "outbound": decision.outbound.name(),
                        "protocol": decision.outbound.protocol(),
                        "exit_type": decision.outbound.exit_category(),
                        "remote_endpoint": decision.outbound.remote_endpoint(&decision.target),
                    });
                    if let Some(status) = auth_rejected_status
                        && let Some(obj) = out.as_object_mut()
                    {
                        obj.insert("auth_error".to_string(), json!(true));
                        obj.insert("http_status".to_string(), json!(status));
                        obj.insert("note".to_string(), json!(auth_rejected_note(status)));
                    }
                    scrub_explain_payload(&mut out, opts.include_network_metadata);
                    mcp_tool_result(&out, false)
                }
                Err(e) => mcp_tool_result(
                    &json!({ "error": redact_sensitive_text(&e.to_string()) }),
                    true,
                ),
            }
        }

        "probe_waterfall" => {
            let url = args
                .get("url")
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .unwrap_or("https://api.github.com/");
            let timeout_ms = args
                .get("timeout_ms")
                .and_then(|v| v.as_u64())
                .unwrap_or(5000)
                .clamp(300, 20_000);
            let check_udp = args
                .get("check_udp")
                .and_then(|v| v.as_bool())
                .unwrap_or(true);

            let default_cfg = fallback_cfg.cloned().unwrap_or_default();
            let proxy_name = match args
                .get("proxy")
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                Some(explicit) => explicit.to_string(),
                None => pick_default_proxy_name(&ctrl_clients, &default_cfg).await,
            };
            let req_needles = vec![proxy_name.clone(), url.to_string()];

            let path = format!("/proxies/{}/probe", url_encode_component(&proxy_name));
            if let LiveControllerOutcome::Response {
                status,
                body: mut resp,
                ..
            } = request_live_controller_json(
                &ctrl_clients,
                "POST",
                &path,
                Some(&json!({
                    "url": url,
                    "timeout_ms": timeout_ms,
                    "check_udp": check_udp,
                })),
                Duration::from_millis(timeout_ms + 5000),
            )
            .await
            {
                if (200..300).contains(&status) {
                    scrub_waterfall_payload(&mut resp, opts.include_network_metadata, &req_needles);
                    return mcp_tool_result(&resp, false);
                }
                if matches!(status, 400 | 404 | 429) {
                    scrub_probe_error_payload(
                        &mut resp,
                        opts.include_network_metadata,
                        &req_needles,
                    );
                    return mcp_tool_result(&resp, true);
                }
            }

            let cfg = match loaded {
                Ok((c, _)) => c,
                Err(_) => ClashConfig::default(),
            };
            match ProxyEngine::build_standalone_router(&cfg) {
                Ok(router) => {
                    let probe_opts = ProbeOptions {
                        timeout: Duration::from_millis(timeout_ms),
                        check_udp,
                        udp_dns_target: None,
                        extra_ca_der: &[],
                        allow_private_targets: false,
                        allowed_private_addrs: &[],
                    };
                    match probe_target_waterfall(&router, &cfg, &proxy_name, url, probe_opts).await
                    {
                        Ok(report) => {
                            let mut val = json!(report);
                            scrub_waterfall_payload(
                                &mut val,
                                opts.include_network_metadata,
                                &req_needles,
                            );
                            mcp_tool_result(&val, false)
                        }
                        Err(e) => {
                            let err_msg = if opts.include_network_metadata {
                                redact_sensitive_text(&e.to_string())
                            } else {
                                scrub_text_network_tokens(&e.to_string(), &req_needles)
                            };
                            mcp_tool_result(&json!({ "error": err_msg }), true)
                        }
                    }
                }
                Err(e) => {
                    let err_msg = if opts.include_network_metadata {
                        redact_sensitive_text(&e.to_string())
                    } else {
                        scrub_text_network_tokens(&e.to_string(), &req_needles)
                    };
                    mcp_tool_result(&json!({ "error": err_msg }), true)
                }
            }
        }

        "probe_ai_matrix" => {
            let timeout_ms = args
                .get("timeout_ms")
                .and_then(|v| v.as_u64())
                .unwrap_or(4500)
                .clamp(500, 15_000);
            let default_cfg = fallback_cfg.cloned().unwrap_or_default();
            let proxy_name = match args
                .get("proxy")
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                Some(explicit) => explicit.to_string(),
                None => pick_default_proxy_name(&ctrl_clients, &default_cfg).await,
            };
            let req_needles = vec![proxy_name.clone()];

            let path = format!("/proxies/{}/matrix", url_encode_component(&proxy_name));
            if let LiveControllerOutcome::Response {
                status,
                body: mut resp,
                ..
            } = request_live_controller_json(
                &ctrl_clients,
                "POST",
                &path,
                Some(&json!({ "timeout_ms": timeout_ms })),
                Duration::from_millis(timeout_ms * 2 + 6000),
            )
            .await
            {
                if (200..300).contains(&status) {
                    scrub_matrix_payload(&mut resp, opts.include_network_metadata, &req_needles);
                    return mcp_tool_result(&resp, false);
                }
                if matches!(status, 400 | 404 | 429) {
                    scrub_probe_error_payload(
                        &mut resp,
                        opts.include_network_metadata,
                        &req_needles,
                    );
                    return mcp_tool_result(&resp, true);
                }
            }

            let cfg = match loaded {
                Ok((c, _)) => c,
                Err(_) => ClashConfig::default(),
            };
            match ProxyEngine::build_standalone_router(&cfg) {
                Ok(router) => {
                    let probe_opts = ProbeOptions {
                        timeout: Duration::from_millis(timeout_ms),
                        check_udp: true,
                        udp_dns_target: None,
                        extra_ca_der: &[],
                        allow_private_targets: false,
                        allowed_private_addrs: &[],
                    };
                    match probe_endpoint_matrix(
                        &router,
                        &cfg,
                        &proxy_name,
                        default_matrix_targets(None),
                        probe_opts,
                    )
                    .await
                    {
                        Ok(report) => {
                            let mut val = json!(report);
                            scrub_matrix_payload(
                                &mut val,
                                opts.include_network_metadata,
                                &req_needles,
                            );
                            mcp_tool_result(&val, false)
                        }
                        Err(e) => {
                            let err_msg = if opts.include_network_metadata {
                                redact_sensitive_text(&e.to_string())
                            } else {
                                scrub_text_network_tokens(&e.to_string(), &req_needles)
                            };
                            mcp_tool_result(&json!({ "error": err_msg }), true)
                        }
                    }
                }
                Err(e) => {
                    let err_msg = if opts.include_network_metadata {
                        redact_sensitive_text(&e.to_string())
                    } else {
                        scrub_text_network_tokens(&e.to_string(), &req_needles)
                    };
                    mcp_tool_result(&json!({ "error": err_msg }), true)
                }
            }
        }

        "get_proxy_status" => {
            let auth_rejected_status = match request_live_controller_json(
                &ctrl_clients,
                "GET",
                "/proxies",
                None,
                Duration::from_secs(3),
            )
            .await
            {
                LiveControllerOutcome::Response {
                    client: c,
                    status: 200,
                    body: proxies_val,
                } => {
                    let cfg_val = c
                        .request_json("GET", "/configs", None, Duration::from_secs(2))
                        .await
                        .ok()
                        .and_then(|(st, v)| (st == 200).then_some(v));
                    let failed_diag_val = c
                        .request_json(
                            "GET",
                            "/connections/diagnostics?limit=15&failed_only=true",
                            None,
                            Duration::from_secs(2),
                        )
                        .await
                        .ok()
                        .and_then(|(st, v)| (st == 200).then_some(v));
                    let recent_all_val = c
                        .request_json(
                            "GET",
                            "/connections/diagnostics?limit=50",
                            None,
                            Duration::from_secs(2),
                        )
                        .await
                        .ok()
                        .and_then(|(st, v)| (st == 200).then_some(v));
                    let logs_val = c
                        .request_json("GET", "/logs?level=warn", None, Duration::from_secs(2))
                        .await
                        .ok()
                        .and_then(|(st, v)| (st == 200).then_some(v));

                    let mut groups_summary = Vec::new();
                    if let Some(map) = proxies_val.get("proxies").and_then(|v| v.as_object()) {
                        for (k, info) in map {
                            let ty = info.get("type").and_then(|v| v.as_str()).unwrap_or("");
                            if matches!(ty, "Selector" | "URLTest" | "Fallback" | "LoadBalance") {
                                groups_summary.push(json!({
                                    "name": k,
                                    "type": ty,
                                    "now": info.get("now"),
                                    "effective_outbound": info.get("effective_outbound"),
                                    "effective_protocol": info.get("effective_protocol"),
                                    "member_count": info.get("all").and_then(|a| a.as_array()).map(|a| a.len()).unwrap_or(0),
                                }));
                            }
                        }
                    }

                    // Strictly retain only genuinely failed/errored entries in `recent_failure_diagnostics`
                    // (even if connected to an older controller build that ignores `failed_only=true`).
                    let mut recent_failures = Value::Array(
                        failed_diag_val
                            .and_then(|d| d.get("diagnostics").and_then(|v| v.as_array()).cloned())
                            .unwrap_or_default()
                            .into_iter()
                            .filter(|item| {
                                item.get("status").and_then(|v| v.as_str()) == Some("failed")
                                    || item.get("error").is_some_and(|v| !v.is_null())
                            })
                            .take(15)
                            .collect(),
                    );
                    scrub_diagnostic_entries(&mut recent_failures, opts.include_network_metadata);

                    let recent_all_entries = recent_all_val
                        .and_then(|d| d.get("diagnostics").and_then(|v| v.as_array()).cloned())
                        .unwrap_or_default();
                    let recent_connections_summary =
                        summarize_recent_connections(&recent_all_entries);

                    let recent_warn_error_logs = extract_recent_warn_error_logs(
                        logs_val.as_ref(),
                        10,
                        opts.include_network_metadata,
                    );

                    let mut tun_val = cfg_val.as_ref().and_then(|v| v.get("tun").cloned());
                    if !opts.include_network_metadata
                        && let Some(health) = tun_val
                            .as_mut()
                            .and_then(|t| t.get_mut("health"))
                            .and_then(|h| h.as_object_mut())
                    {
                        if health
                            .get("default_egress_gateway")
                            .is_some_and(|v| !v.is_null())
                        {
                            health
                                .insert("default_egress_gateway".to_string(), json!("<redacted>"));
                        }
                        if health
                            .get("default_egress_iface")
                            .is_some_and(|v| !v.is_null())
                        {
                            health.insert("default_egress_iface".to_string(), json!("<redacted>"));
                        }
                    }

                    return mcp_tool_result(
                        &json!({
                            "daemon_connected": true,
                            "metadata_privacy_mode": if opts.include_network_metadata { "full" } else { "redacted" },
                            "controller": if opts.include_network_metadata { json!(c.host_port) } else { json!("<redacted>") },
                            "mode": cfg_val.as_ref().and_then(|v| v.get("mode")),
                            "mixed_port": cfg_val.as_ref().and_then(|v| v.get("mixed-port")),
                            "tun": tun_val,
                            "effective_outbound": proxies_val.get("effective-outbound"),
                            "groups": groups_summary,
                            "recent_failure_diagnostics": recent_failures,
                            "recent_connections_summary": recent_connections_summary,
                            "recent_warn_error_logs": recent_warn_error_logs,
                        }),
                        false,
                    );
                }
                LiveControllerOutcome::AuthRejected { status } => Some(status),
                _ => None,
            };

            match loaded {
                Ok((cfg, src)) => match ProxyEngine::build_standalone_router(&cfg) {
                    Ok(router) => {
                        let note = match auth_rejected_status {
                            Some(status) => auth_rejected_note(status),
                            None => "No live rust-clash controller responded; showing offline profile snapshot.".to_string(),
                        };
                        let mut out = json!({
                            "daemon_connected": false,
                            "metadata_privacy_mode": if opts.include_network_metadata { "full" } else { "redacted" },
                            "controller": if opts.include_network_metadata { json!(cfg.external_controller) } else { json!("<redacted>") },
                            "source": sanitize_source_label(&src, opts.include_network_metadata),
                            "mode": cfg.mode,
                            "mixed_port": cfg.mixed_port,
                            "node_count": cfg.proxies.len(),
                            "effective_outbound": router.effective_primary_outbound(),
                            "note": note,
                        });
                        if let Some(status) = auth_rejected_status
                            && let Some(obj) = out.as_object_mut()
                        {
                            obj.insert("auth_error".to_string(), json!(true));
                            obj.insert("http_status".to_string(), json!(status));
                        }
                        mcp_tool_result(&out, false)
                    }
                    Err(e) => mcp_tool_result(
                        &json!({ "error": redact_sensitive_text(&e.to_string()) }),
                        true,
                    ),
                },
                Err(e) => mcp_tool_result(
                    &json!({ "error": redact_sensitive_text(&e.to_string()) }),
                    true,
                ),
            }
        }

        "get_recent_logs" => {
            let parsed_level = match args.get("level") {
                None | Some(Value::Null) => LogFilterLevel::Warn,
                Some(Value::String(raw)) => match LogFilterLevel::parse(raw) {
                    Ok(lv) => lv,
                    Err(msg) => return mcp_tool_result(&json!({ "error": msg }), true),
                },
                Some(_) => {
                    return mcp_tool_result(
                        &json!({ "error": "invalid 'level': expected string ('error', 'warn', 'info', or 'all')" }),
                        true,
                    );
                }
            };
            let limit = match args.get("limit") {
                None | Some(Value::Null) => 30usize,
                Some(v) => match v.as_u64() {
                    Some(n) => (n as usize).clamp(1, 100),
                    None => {
                        return mcp_tool_result(
                            &json!({ "error": "invalid 'limit': expected integer between 1 and 100" }),
                            true,
                        );
                    }
                },
            };

            let path = format!("/logs?level={}", parsed_level.as_str());
            match request_live_controller_json(
                &ctrl_clients,
                "GET",
                &path,
                None,
                Duration::from_secs(2),
            )
            .await
            {
                LiveControllerOutcome::Response {
                    client: c,
                    status: 200,
                    body: logs_val,
                } => {
                    let logs = extract_recent_logs_filtered(
                        Some(&logs_val),
                        parsed_level,
                        limit,
                        opts.include_network_metadata,
                    );
                    let count = logs.as_array().map_or(0, Vec::len);
                    mcp_tool_result(
                        &json!({
                            "daemon_connected": true,
                            "metadata_privacy_mode": if opts.include_network_metadata { "full" } else { "redacted" },
                            "controller": if opts.include_network_metadata { json!(c.host_port) } else { json!("<redacted>") },
                            "level": parsed_level.as_str(),
                            "limit": limit,
                            "count": count,
                            "logs": logs,
                        }),
                        false,
                    )
                }
                LiveControllerOutcome::AuthRejected { status } => mcp_tool_result(
                    &json!({
                        "daemon_connected": false,
                        "auth_error": true,
                        "http_status": status,
                        "error": auth_rejected_note(status),
                    }),
                    true,
                ),
                LiveControllerOutcome::Response { status, .. } => mcp_tool_result(
                    &json!({
                        "daemon_connected": false,
                        "http_status": status,
                        "error": format!("Live controller returned HTTP {status} for {path}"),
                    }),
                    true,
                ),
                LiveControllerOutcome::Unreachable => mcp_tool_result(
                    &json!({
                        "daemon_connected": false,
                        "error": "No live rust-clash controller responded; recent runtime logs require a running daemon.",
                    }),
                    true,
                ),
            }
        }

        "switch_proxy_selector" => {
            if !opts.allow_mutations {
                return mcp_tool_result(
                    &json!({
                        "error": "Mutation blocked: `rust-clash mcp` runs in strict read-only mode by default. Relaunch with `rust-clash mcp --allow-mutations` to allow switching Selector groups."
                    }),
                    true,
                );
            }
            let Some(group) = args
                .get("group")
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
            else {
                return mcp_tool_result(
                    &json!({ "error": "missing required string parameter 'group'" }),
                    true,
                );
            };
            let Some(proxy) = args
                .get("proxy")
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
            else {
                return mcp_tool_result(
                    &json!({ "error": "missing required string parameter 'proxy'" }),
                    true,
                );
            };
            if ctrl_clients.is_empty() {
                return mcp_tool_result(
                    &json!({ "error": "no controller configured to switch live Selector group" }),
                    true,
                );
            }

            let path = format!("/proxies/{}", url_encode_component(group));
            match request_live_controller_json(
                &ctrl_clients,
                "PUT",
                &path,
                Some(&json!({ "name": proxy })),
                Duration::from_secs(4),
            )
            .await
            {
                LiveControllerOutcome::Response { status, .. } if (200..300).contains(&status) => {
                    mcp_tool_result(
                        &json!({
                            "ok": true,
                            "group": group,
                            "selected": proxy,
                        }),
                        false,
                    )
                }
                LiveControllerOutcome::Response {
                    status,
                    body: err_val,
                    ..
                } => mcp_tool_result(
                    &json!({
                        "ok": false,
                        "http_status": status,
                        "detail": err_val,
                    }),
                    true,
                ),
                LiveControllerOutcome::AuthRejected { status } => mcp_tool_result(
                    &json!({
                        "ok": false,
                        "auth_error": true,
                        "http_status": status,
                        "error": format!(
                            "Live rust-clash controller rejected authentication (HTTP {status}). Check --secret / RUST_CLASH_SECRET or restart rust-clash-desktop."
                        ),
                    }),
                    true,
                ),
                LiveControllerOutcome::Unreachable => mcp_tool_result(
                    &json!({
                        "error": "No live rust-clash controller responded to switch Selector group."
                    }),
                    true,
                ),
            }
        }

        unknown => mcp_tool_result(
            &json!({ "error": format!("unknown MCP tool '{unknown}'") }),
            true,
        ),
    }
}

pub async fn handle_mcp_request(req: &Value, opts: &McpServerOptions) -> Option<Value> {
    if let Some(batch) = req.as_array() {
        if batch.is_empty() {
            return Some(json!({
                "jsonrpc": "2.0",
                "id": Value::Null,
                "error": {
                    "code": -32600,
                    "message": "Invalid Request: empty JSON-RPC batch"
                }
            }));
        }
        let mut handles = Vec::with_capacity(batch.len());
        for item in batch {
            let item_cloned = item.clone();
            let opts_cloned = opts.clone();
            handles.push(tokio::spawn(async move {
                handle_single_mcp_request(&item_cloned, &opts_cloned).await
            }));
        }
        let mut responses = Vec::with_capacity(handles.len());
        for handle in handles {
            if let Ok(Some(resp)) = handle.await {
                responses.push(resp);
            }
        }
        return if responses.is_empty() {
            None
        } else {
            Some(Value::Array(responses))
        };
    }

    handle_single_mcp_request(req, opts).await
}

fn is_valid_jsonrpc_id(v: &Value) -> bool {
    v.is_string() || v.is_number() || v.is_null()
}

fn frame_contains_mutation(req: &Value) -> bool {
    let check_obj = |v: &Value| -> bool {
        v.get("method").and_then(|m| m.as_str()) == Some("tools/call")
            && v.get("params")
                .and_then(|p| p.get("name"))
                .and_then(|n| n.as_str())
                == Some("switch_proxy_selector")
    };
    if let Some(arr) = req.as_array() {
        arr.iter().any(check_obj)
    } else {
        check_obj(req)
    }
}

async fn handle_single_mcp_request(req: &Value, opts: &McpServerOptions) -> Option<Value> {
    let Some(obj) = req.as_object() else {
        return Some(json!({
            "jsonrpc": "2.0",
            "id": Value::Null,
            "error": {
                "code": -32600,
                "message": "Invalid Request: expected JSON-RPC request object"
            }
        }));
    };

    let raw_id = obj.get("id");
    if let Some(id_val) = raw_id
        && !is_valid_jsonrpc_id(id_val)
    {
        return Some(json!({
            "jsonrpc": "2.0",
            "id": Value::Null,
            "error": {
                "code": -32600,
                "message": "Invalid Request: 'id' must be a string, number, or null"
            }
        }));
    }
    let id = raw_id.cloned();

    if obj.get("jsonrpc").and_then(|v| v.as_str()) != Some("2.0") {
        return Some(json!({
            "jsonrpc": "2.0",
            "id": id.unwrap_or(Value::Null),
            "error": {
                "code": -32600,
                "message": "Invalid Request: jsonrpc version must be '2.0'"
            }
        }));
    }

    let Some(method) = obj
        .get("method")
        .and_then(|m| m.as_str())
        .filter(|s| !s.is_empty())
    else {
        return Some(json!({
            "jsonrpc": "2.0",
            "id": id.unwrap_or(Value::Null),
            "error": {
                "code": -32600,
                "message": "Invalid Request: missing or non-string 'method'"
            }
        }));
    };

    if let Some(p) = obj.get("params")
        && !(p.is_object() || p.is_array() || p.is_null())
    {
        return Some(json!({
            "jsonrpc": "2.0",
            "id": id.unwrap_or(Value::Null),
            "error": {
                "code": -32600,
                "message": "Invalid Request: 'params' must be structured (object or array)"
            }
        }));
    }

    // Valid notifications omit `id` and must not receive a JSON-RPC response.
    let req_id = id?;

    let params = obj.get("params").unwrap_or(&Value::Null);

    match method {
        "initialize" => {
            let client_ver = params
                .get("protocolVersion")
                .and_then(|v| v.as_str())
                .filter(|s| !s.trim().is_empty())
                .unwrap_or("2024-11-05");
            let negotiated = match client_ver {
                "2025-06-18" | "2025-03-26" | "2024-11-05" => client_ver,
                _ => "2024-11-05",
            };
            Some(json!({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": negotiated,
                    "capabilities": {
                        "tools": {
                            "listChanged": false
                        }
                    },
                    "serverInfo": {
                        "name": "rust-clash",
                        "version": env!("CARGO_PKG_VERSION")
                    },
                    "instructions": "Credential-Redacted Glass-Box Proxy MCP server for rust-clash. Node passwords, UUIDs, private keys, and Bearer secrets are redacted; proxy server endpoints and destination metadata are also hidden by default unless launched with `--include-network-metadata`. Never paste raw YAML secrets into tool arguments—pass `config_path` to `audit_config_security` instead."
                }
            }))
        }
        "ping" => Some(json!({
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {}
        })),
        "tools/list" => Some(json!({
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "tools": build_tools_list(opts.allow_mutations)
            }
        })),
        "resources/list" => Some(json!({
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "resources": []
            }
        })),
        "prompts/list" => Some(json!({
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "prompts": []
            }
        })),
        "tools/call" => {
            let Some(tool_name) = params.get("name").and_then(|v| v.as_str()) else {
                return Some(json!({
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": -32602,
                        "message": "Invalid params: missing tool 'name'"
                    }
                }));
            };
            let args = params
                .get("arguments")
                .cloned()
                .unwrap_or_else(|| json!({}));
            let result = execute_tool_call(tool_name, &args, opts).await;
            Some(json!({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": result
            }))
        }
        _ => Some(json!({
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {
                "code": -32601,
                "message": format!("Method not found: {method}")
            }
        })),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FrameMode {
    NewlineJson,
    ContentLength,
}

const MAX_MCP_FRAME_BYTES: usize = 8 * 1024 * 1024;
const MAX_MCP_LINE_BYTES: usize = MAX_MCP_FRAME_BYTES + 1024;
const MAX_MCP_HEADER_LINE_BYTES: usize = 16 * 1024;
const MAX_MCP_HEADER_LINES: usize = 64;

fn is_rfc7230_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

fn looks_like_header_line(line: &str) -> bool {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('{') || trimmed.starts_with('[') {
        return false;
    }
    let Some((name, _val)) = trimmed.split_once(':') else {
        return false;
    };
    let name = name.trim();
    !name.is_empty() && name.bytes().all(is_rfc7230_tchar)
}

/// Pure synchronous parser for buffered MCP frames (both header-framed `Content-Length`
/// and `NewlineJson`). Only drains `buf` once a complete frame is available (except for
/// completed leading whitespace-only lines), guaranteeing cancel safety across arbitrary
/// `tokio::select!` cancellations of `McpFrameReader::read_next_frame`.
fn try_parse_buffered_frame(
    buf: &mut Vec<u8>,
    last_mode: &mut FrameMode,
    eof: bool,
) -> Result<Option<(Value, FrameMode)>> {
    // Discard any completed leading empty / whitespace-only lines (`\r\n`, `\n`, spaces).
    while let Some(nl) = buf.iter().position(|&b| b == b'\n') {
        if nl > MAX_MCP_LINE_BYTES {
            return Err(anyhow!(
                "MCP input line exceeds maximum allowed size ({MAX_MCP_LINE_BYTES} bytes)"
            ));
        }
        if buf[..nl].iter().all(|b| b.is_ascii_whitespace()) {
            buf.drain(..=nl);
        } else {
            break;
        }
    }

    let Some(first_nl) = buf.iter().position(|&b| b == b'\n') else {
        if buf.len() > MAX_MCP_LINE_BYTES {
            return Err(anyhow!(
                "MCP input line exceeds maximum allowed size ({MAX_MCP_LINE_BYTES} bytes)"
            ));
        }
        if !eof {
            return Ok(None);
        }
        if buf.iter().all(|b| b.is_ascii_whitespace()) {
            buf.clear();
            return Ok(None);
        }
        let line_str = std::str::from_utf8(buf).context("MCP input is not valid UTF-8")?;
        if looks_like_header_line(line_str) {
            *last_mode = FrameMode::ContentLength;
            return Err(anyhow!("unexpected EOF while reading MCP headers"));
        }
        *last_mode = FrameMode::NewlineJson;
        let val: Value =
            serde_json::from_str(line_str.trim()).context("invalid JSON-RPC line on stdin")?;
        buf.clear();
        return Ok(Some((val, FrameMode::NewlineJson)));
    };

    if first_nl > MAX_MCP_LINE_BYTES {
        return Err(anyhow!(
            "MCP input line exceeds maximum allowed size ({MAX_MCP_LINE_BYTES} bytes)"
        ));
    }

    let first_line =
        std::str::from_utf8(&buf[..first_nl]).context("MCP input is not valid UTF-8")?;

    if !looks_like_header_line(first_line) {
        *last_mode = FrameMode::NewlineJson;
        let parsed = serde_json::from_str::<Value>(first_line.trim())
            .context("invalid JSON-RPC line on stdin");
        buf.drain(..=first_nl);
        return Ok(Some((parsed?, FrameMode::NewlineJson)));
    }

    // Header-framed LSP/MCP message (`Content-Length`, `Content-Type`, etc. in any order).
    *last_mode = FrameMode::ContentLength;
    let mut cursor = 0usize;
    let mut header_count = 0usize;
    let mut content_length: Option<usize> = None;

    let body_start = loop {
        let remaining = &buf[cursor..];
        let Some(rel_nl) = remaining.iter().position(|&b| b == b'\n') else {
            if remaining.len() > MAX_MCP_HEADER_LINE_BYTES {
                return Err(anyhow!(
                    "MCP header line exceeds maximum allowed size ({MAX_MCP_HEADER_LINE_BYTES} bytes)"
                ));
            }
            if eof {
                return Err(anyhow!("unexpected EOF while reading MCP headers"));
            }
            return Ok(None);
        };

        if rel_nl > MAX_MCP_HEADER_LINE_BYTES {
            return Err(anyhow!(
                "MCP header line exceeds maximum allowed size ({MAX_MCP_HEADER_LINE_BYTES} bytes)"
            ));
        }

        let line_str = std::str::from_utf8(&remaining[..rel_nl])
            .context("MCP header line is not valid UTF-8")?;
        let trimmed = line_str.trim();
        cursor += rel_nl + 1;

        // Blank separator line (`\r\n` or `\n`) ends the header block.
        if trimmed.is_empty() {
            break cursor;
        }

        header_count += 1;
        if header_count > MAX_MCP_HEADER_LINES {
            return Err(anyhow!(
                "MCP frame exceeded maximum header count ({MAX_MCP_HEADER_LINES})"
            ));
        }

        let Some((raw_name, raw_val)) = trimmed.split_once(':') else {
            return Err(anyhow!("malformed header line in MCP frame"));
        };
        let name = raw_name.trim();
        if name.is_empty() || !name.bytes().all(is_rfc7230_tchar) {
            return Err(anyhow!("invalid header name in MCP frame"));
        }

        if name.eq_ignore_ascii_case("content-length") {
            let val_trimmed = raw_val.trim();
            if val_trimmed.is_empty() || !val_trimmed.bytes().all(|b| b.is_ascii_digit()) {
                return Err(anyhow!("invalid Content-Length header in MCP stream"));
            }
            let parsed: usize = val_trimmed
                .parse()
                .context("invalid Content-Length header in MCP stream")?;
            if parsed > MAX_MCP_FRAME_BYTES {
                return Err(anyhow!("MCP frame exceeds 8 MiB safety cap"));
            }
            if let Some(prev) = content_length {
                if prev != parsed {
                    return Err(anyhow!(
                        "conflicting duplicate Content-Length headers in MCP frame"
                    ));
                }
            } else {
                content_length = Some(parsed);
            }
        }
    };

    let Some(content_len) = content_length else {
        return Err(anyhow!("missing Content-Length header in MCP frame"));
    };

    let frame_end = body_start
        .checked_add(content_len)
        .ok_or_else(|| anyhow!("MCP frame size overflow"))?;

    if buf.len() < frame_end {
        if eof {
            return Err(anyhow!(
                "unexpected EOF while reading MCP Content-Length body (expected {content_len} bytes, got {})",
                buf.len().saturating_sub(body_start)
            ));
        }
        return Ok(None);
    }

    let parsed = serde_json::from_slice::<Value>(&buf[body_start..frame_end])
        .context("invalid JSON in Content-Length MCP frame");
    buf.drain(..frame_end);
    Ok(Some((parsed?, FrameMode::ContentLength)))
}

/// Stateful, cancel-safe MCP stream reader backed by an owned `Vec<u8>` buffer
/// and Tokio's cancel-safe `AsyncReadExt::read_buf`.
struct McpFrameReader<R> {
    inner: R,
    buf: Vec<u8>,
    last_mode: FrameMode,
    eof: bool,
}

impl<R: AsyncRead + Unpin> McpFrameReader<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            buf: Vec::with_capacity(4096),
            last_mode: FrameMode::NewlineJson,
            eof: false,
        }
    }

    fn last_mode(&self) -> FrameMode {
        self.last_mode
    }

    /// Reads the next complete MCP frame.
    ///
    /// Cancel safety: 100% cancel-safe for use inside `tokio::select!`. Bytes read
    /// from `self.inner` are accumulated in `self.buf` via `AsyncReadExt::read_buf`
    /// and are only drained once a full frame has been parsed.
    async fn read_next_frame(&mut self) -> Result<Option<(Value, FrameMode)>> {
        loop {
            if let Some(frame) =
                try_parse_buffered_frame(&mut self.buf, &mut self.last_mode, self.eof)?
            {
                if self.buf.is_empty() && self.buf.capacity() > 64 * 1024 {
                    self.buf = Vec::with_capacity(16 * 1024);
                }
                return Ok(Some(frame));
            }
            if self.eof {
                return Ok(None);
            }
            if self.buf.capacity().saturating_sub(self.buf.len()) < 4096 {
                self.buf.reserve(4096);
            }
            let n = self.inner.read_buf(&mut self.buf).await?;
            if n == 0 {
                self.eof = true;
            }
        }
    }
}

async fn write_encoded_mcp_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    encoded: &[u8],
    mode: FrameMode,
) -> Result<()> {
    match mode {
        FrameMode::NewlineJson => {
            writer.write_all(encoded).await?;
            writer.write_all(b"\n").await?;
        }
        FrameMode::ContentLength => {
            let hdr = format!("Content-Length: {}\r\n\r\n", encoded.len());
            writer.write_all(hdr.as_bytes()).await?;
            writer.write_all(encoded).await?;
        }
    }
    writer.flush().await?;
    Ok(())
}

async fn write_mcp_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    resp: &Value,
    mode: FrameMode,
) -> Result<()> {
    let encoded = serde_json::to_vec(resp)?;
    write_encoded_mcp_frame(writer, &encoded, mode).await
}

pub async fn serve_mcp_io<R, W>(input: R, mut output: W, opts: McpServerOptions) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut reader = McpFrameReader::new(input);
    let (resp_tx, mut resp_rx) = tokio::sync::mpsc::unbounded_channel::<(Vec<u8>, FrameMode)>();
    let mut tasks = tokio::task::JoinSet::new();

    loop {
        tokio::select! {
            biased;
            Some((encoded, mode)) = resp_rx.recv() => {
                write_encoded_mcp_frame(&mut output, &encoded, mode).await?;
            }
            Some(_done) = tasks.join_next(), if !tasks.is_empty() => {}
            frame_res = reader.read_next_frame() => {
                match frame_res {
                    Ok(Some((req, mode))) => {
                        if frame_contains_mutation(&req) {
                            while !tasks.is_empty() {
                                tokio::select! {
                                    Some((encoded, m)) = resp_rx.recv() => {
                                        write_encoded_mcp_frame(&mut output, &encoded, m).await?;
                                    }
                                    Some(_) = tasks.join_next() => {}
                                }
                            }
                            while let Ok((encoded, m)) = resp_rx.try_recv() {
                                write_encoded_mcp_frame(&mut output, &encoded, m).await?;
                            }
                            if let Some(resp) = handle_mcp_request(&req, &opts).await {
                                write_mcp_frame(&mut output, &resp, mode).await?;
                            }
                        } else {
                            let tx = resp_tx.clone();
                            let task_opts = opts.clone();
                            tasks.spawn(async move {
                                if let Some(resp) = handle_mcp_request(&req, &task_opts).await
                                    && let Ok(encoded) = serde_json::to_vec(&resp)
                                {
                                    let _ = tx.send((encoded, mode));
                                }
                            });
                        }
                    }
                    Ok(None) => break,
                    Err(err) => {
                        let err_resp = json!({
                            "jsonrpc": "2.0",
                            "id": Value::Null,
                            "error": {
                                "code": -32700,
                                "message": format!("Parse error: {}", redact_sensitive_text(&err.to_string()))
                            }
                        });
                        write_mcp_frame(&mut output, &err_resp, reader.last_mode()).await?;
                        return Ok(());
                    }
                }
            }
        }
    }

    drop(resp_tx);
    while !tasks.is_empty() {
        tokio::select! {
            Some((encoded, mode)) = resp_rx.recv() => {
                write_encoded_mcp_frame(&mut output, &encoded, mode).await?;
            }
            Some(_) = tasks.join_next() => {}
        }
    }
    while let Some((encoded, mode)) = resp_rx.recv().await {
        write_encoded_mcp_frame(&mut output, &encoded, mode).await?;
    }
    Ok(())
}

pub async fn run_mcp_stdio(opts: McpServerOptions) -> Result<()> {
    serve_mcp_io(tokio::io::stdin(), tokio::io::stdout(), opts).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use proxy_core::api::spawn_api_server;
    use std::sync::Arc;
    use tokio::io::{AsyncBufReadExt, BufReader};
    use tokio::sync::watch;

    #[tokio::test]
    async fn mcp_initialize_and_tools_list_respects_read_only_guard() {
        let ro_opts = McpServerOptions {
            config_path: None,
            controller: Some("127.0.0.1:1".to_string()),
            secret: None,
            allow_mutations: false,
            include_network_metadata: false,
        };

        let init_resp = handle_mcp_request(
            &json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": { "protocolVersion": "2024-11-05" }
            }),
            &ro_opts,
        )
        .await
        .expect("initialize returns response");
        assert_eq!(init_resp["result"]["serverInfo"]["name"], "rust-clash");
        assert!(
            init_resp["result"]["instructions"]
                .as_str()
                .unwrap()
                .contains("Credential-Redacted")
        );

        // Notification returns None
        assert!(
            handle_mcp_request(
                &json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
                &ro_opts
            )
            .await
            .is_none()
        );

        let list_ro = handle_mcp_request(
            &json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" }),
            &ro_opts,
        )
        .await
        .unwrap();
        let ro_tools = list_ro["result"]["tools"].as_array().unwrap();
        let ro_names: Vec<&str> = ro_tools
            .iter()
            .filter_map(|t| t.get("name").and_then(|n| n.as_str()))
            .collect();
        assert!(ro_names.contains(&"audit_config_security"));
        assert!(ro_names.contains(&"explain_route"));
        assert!(ro_names.contains(&"probe_waterfall"));
        assert!(ro_names.contains(&"probe_ai_matrix"));
        assert!(ro_names.contains(&"get_proxy_status"));
        assert!(ro_names.contains(&"get_recent_logs"));
        assert!(!ro_names.contains(&"switch_proxy_selector"));

        // Verify raw `yaml` is excluded from audit_config_security schema
        let audit_tool = ro_tools
            .iter()
            .find(|t| t["name"] == "audit_config_security")
            .unwrap();
        assert!(
            audit_tool["inputSchema"]["properties"]
                .get("yaml")
                .is_none()
        );
        assert!(
            audit_tool["inputSchema"]["properties"]
                .get("config_path")
                .is_some()
        );

        // Calling audit_config_security with raw `yaml` is rejected cleanly
        let raw_yaml_rejected = handle_mcp_request(
            &json!({
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "audit_config_security",
                    "arguments": { "yaml": "mixed-port: 7890\n" }
                }
            }),
            &ro_opts,
        )
        .await
        .unwrap();
        assert_eq!(raw_yaml_rejected["result"]["isError"], true);

        // Calling switch_proxy_selector in read-only mode is rejected cleanly
        let blocked = handle_mcp_request(
            &json!({
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {
                    "name": "switch_proxy_selector",
                    "arguments": { "group": "PROXY", "proxy": "DIRECT" }
                }
            }),
            &ro_opts,
        )
        .await
        .unwrap();
        assert_eq!(blocked["result"]["isError"], true);
    }

    #[tokio::test]
    async fn mcp_audit_and_explain_redact_credentials_and_network_metadata_by_default() {
        let super_secret_pw = "UltraSecretTrojanCredential998877!";
        let proxy_server_ip = "198.51.100.10";
        let yaml = format!(
            r#"
mixed-port: 0
mode: rule
external-controller: 127.0.0.1:0
secret: ctrl-token-abc
dns:
  enable: true
  listen: 127.0.0.1:0
  enhanced-mode: fake-ip
  nameserver:
    - https://cloudflare-dns.com/dns-query
  default-nameserver:
    - 1.1.1.1:53
proxies:
  - name: Node-A
    type: trojan
    server: {proxy_server_ip}
    port: 443
    password: {super_secret_pw}
    sni: example.com
    skip-cert-verify: true
proxy-groups:
  - name: PROXY
    type: select
    proxies:
      - Node-A
      - DIRECT
rules:
  - DOMAIN-SUFFIX,anthropic.com,PROXY
  - MATCH,DIRECT
"#
        );

        let cfg = ClashConfig::from_yaml_str(&yaml).unwrap();
        let engine = ProxyEngine::start(cfg).await.unwrap();
        let (stop_tx, stop_rx) = watch::channel(false);
        let (api_addr, _api_task) = spawn_api_server("127.0.0.1:0", Arc::clone(&engine), stop_rx)
            .await
            .unwrap();

        // 1. Default privacy mode (`include_network_metadata: false`): hides BOTH secrets AND proxy server IP
        let privacy_opts = McpServerOptions {
            config_path: None,
            controller: Some(api_addr.to_string()),
            secret: Some("ctrl-token-abc".to_string()),
            allow_mutations: true,
            include_network_metadata: false,
        };

        let input_lines = [
            json!({
                "jsonrpc": "2.0",
                "id": 10,
                "method": "tools/call",
                "params": { "name": "audit_config_security", "arguments": {} }
            })
            .to_string(),
            json!({
                "jsonrpc": "2.0",
                "id": 11,
                "method": "tools/call",
                "params": { "name": "explain_route", "arguments": { "target": "api.anthropic.com:443" } }
            })
            .to_string(),
            json!({
                "jsonrpc": "2.0",
                "id": 12,
                "method": "tools/call",
                "params": { "name": "switch_proxy_selector", "arguments": { "group": "PROXY", "proxy": "DIRECT" } }
            })
            .to_string(),
            json!({
                "jsonrpc": "2.0",
                "id": 13,
                "method": "tools/call",
                "params": { "name": "get_proxy_status", "arguments": {} }
            })
            .to_string(),
        ]
        .join("\n")
            + "\n";

        let mut out_buf = Vec::new();
        serve_mcp_io(
            std::io::Cursor::new(input_lines.into_bytes()),
            &mut out_buf,
            privacy_opts.clone(),
        )
        .await
        .unwrap();

        let out_str = String::from_utf8(out_buf).unwrap();
        assert!(
            !out_str.contains(super_secret_pw) && !out_str.contains("ctrl-token-abc"),
            "MCP output must NEVER leak node credentials or controller secrets: {out_str}"
        );
        assert!(
            !out_str.contains(proxy_server_ip),
            "Default MCP privacy mode must hide proxy server IP ({proxy_server_ip}): {out_str}"
        );

        assert!(
            !out_str.contains(&api_addr.to_string()),
            "Default MCP privacy mode must redact controller host:port ({api_addr}): {out_str}"
        );

        let frames: Vec<Value> = out_str
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(frames.len(), 4);
        let by_id = |target_id: i64| -> &Value {
            frames
                .iter()
                .find(|f| f["id"] == target_id)
                .unwrap_or_else(|| panic!("missing response frame for id={target_id}: {out_str}"))
        };

        let f10 = by_id(10);
        assert_eq!(f10["result"]["isError"], false);
        let f10_text = f10["result"]["content"][0]["text"].as_str().unwrap();
        assert!(f10_text.contains("SEC-TLS-SKIP-VERIFY"));
        assert!(f10_text.contains("\"controller\": \"<redacted>\""));

        let f11 = by_id(11);
        assert!(
            f11["result"]["content"][0]["text"]
                .as_str()
                .unwrap()
                .contains("Node-A")
        );

        let f12 = by_id(12);
        assert_eq!(f12["result"]["isError"], false);

        let f13 = by_id(13);
        let f13_text = f13["result"]["content"][0]["text"].as_str().unwrap();
        assert!(f13_text.contains("\"now\": \"DIRECT\""));
        assert!(f13_text.contains("\"controller\": \"<redacted>\""));

        // 2. Opt-in `--include-network-metadata` exposes proxy server IP while STILL redacting credentials!
        let _ = handle_mcp_request(
            &json!({
                "jsonrpc": "2.0",
                "id": 20,
                "method": "tools/call",
                "params": { "name": "switch_proxy_selector", "arguments": { "group": "PROXY", "proxy": "Node-A" } }
            }),
            &privacy_opts,
        )
        .await;

        let full_meta_opts = McpServerOptions {
            include_network_metadata: true,
            ..privacy_opts
        };
        let explain_full = handle_mcp_request(
            &json!({
                "jsonrpc": "2.0",
                "id": 21,
                "method": "tools/call",
                "params": { "name": "explain_route", "arguments": { "target": "api.anthropic.com:443" } }
            }),
            &full_meta_opts,
        )
        .await
        .unwrap();
        let explain_text = explain_full["result"]["content"][0]["text"]
            .as_str()
            .unwrap();
        assert!(explain_text.contains(proxy_server_ip));
        assert!(!explain_text.contains(super_secret_pw));

        let _ = stop_tx.send(true);
        engine.shutdown();
    }

    #[tokio::test]
    async fn mcp_audit_config_path_blocks_traversal_non_yaml_symlinks_and_redacts_parse_errors() {
        let ro_opts = McpServerOptions {
            config_path: None,
            controller: Some("127.0.0.1:1".to_string()),
            secret: None,
            allow_mutations: false,
            include_network_metadata: false,
        };

        for bad_path in [
            "../secret.yaml",
            "configs/../../etc/shadow.yaml",
            "..\\windows\\win.yml",
            "/etc/passwd",
            "/tmp/credentials.json",
            ".yaml",
        ] {
            let resp = handle_mcp_request(
                &json!({
                    "jsonrpc": "2.0",
                    "id": 91,
                    "method": "tools/call",
                    "params": {
                        "name": "audit_config_security",
                        "arguments": { "config_path": bad_path }
                    }
                }),
                &ro_opts,
            )
            .await
            .unwrap();
            assert_eq!(
                resp["result"]["isError"], true,
                "expected bad config_path '{bad_path}' to be rejected"
            );
        }

        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();

        #[cfg(unix)]
        {
            let real_yaml = std::env::temp_dir()
                .join(format!("rc-mcp-real-{}-{nanos}.yaml", std::process::id()));
            let symlink_yaml = std::env::temp_dir()
                .join(format!("rc-mcp-link-{}-{nanos}.yaml", std::process::id()));
            std::fs::write(&real_yaml, "mixed-port: 7890\nrules:\n  - MATCH,DIRECT\n").unwrap();
            std::os::unix::fs::symlink(&real_yaml, &symlink_yaml).unwrap();

            let sym_resp = handle_mcp_request(
                &json!({
                    "jsonrpc": "2.0",
                    "id": 93,
                    "method": "tools/call",
                    "params": {
                        "name": "audit_config_security",
                        "arguments": { "config_path": symlink_yaml.to_string_lossy() }
                    }
                }),
                &ro_opts,
            )
            .await
            .unwrap();
            let _ = std::fs::remove_file(&symlink_yaml);
            let _ = std::fs::remove_file(&real_yaml);
            assert_eq!(
                sym_resp["result"]["isError"], true,
                "symlink config_path must be rejected: {sym_resp}"
            );
        }

        let secret_marker = "TOP_SECRET_ARBITRARY_FILE_CONTENT_991122";
        let fake_yaml_path = std::env::temp_dir().join(format!(
            "rc-mcp-non-yaml-{}-{nanos}.yaml",
            std::process::id()
        ));
        std::fs::write(
            &fake_yaml_path,
            format!("{{{secret_marker}: [unclosed_non_yaml_secret_line\n"),
        )
        .unwrap();

        let parse_fail_resp = handle_mcp_request(
            &json!({
                "jsonrpc": "2.0",
                "id": 92,
                "method": "tools/call",
                "params": {
                    "name": "audit_config_security",
                    "arguments": { "config_path": fake_yaml_path.to_string_lossy() }
                }
            }),
            &ro_opts,
        )
        .await
        .unwrap();
        let _ = std::fs::remove_file(&fake_yaml_path);

        assert_eq!(parse_fail_resp["result"]["isError"], true);
        let serialized = parse_fail_resp.to_string();
        assert!(
            !serialized.contains(secret_marker),
            "parse failure must never echo arbitrary file contents back to MCP caller: {serialized}"
        );
    }

    #[tokio::test]
    async fn mcp_redacts_network_metadata_on_probe_waterfall_probe_ai_matrix_and_audit_details() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let draft_yaml_path = std::env::temp_dir().join(format!(
            "rc-mcp-audit-detail-{}-{nanos}.yaml",
            std::process::id()
        ));
        let plaintext_srv = "tyo-plain.secret-edge.example";
        let lan_ctrl = "192.168.77.88:9095";
        std::fs::write(
            &draft_yaml_path,
            format!(
                r#"
mixed-port: 7890
allow-lan: true
bind-address: 192.168.77.88
external-controller: {lan_ctrl}
proxies:
  - name: Plain-HTTP
    type: http
    server: {plaintext_srv}
    port: 8080
    tls: false
rules:
  - MATCH,Plain-HTTP
"#
            ),
        )
        .unwrap();

        // Mock HTTP controller returning realistic probe_waterfall and probe_ai_matrix payloads
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mock_addr = listener.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    let n = sock.read(&mut buf).await.unwrap_or(0);
                    let req_head = String::from_utf8_lossy(&buf[..n]);
                    let body_json = if req_head.contains("/probe") {
                        json!({
                            "requested_proxy": "🚀 VIP-Group",
                            "effective_outbound": "HK-Secret-Node-01",
                            "protocol": "vless",
                            "chains": ["🚀 VIP-Group", "HK-Secret-Node-01"],
                            "url": "https://internal.corp.example:8443/health",
                            "target_host": "internal.corp.example",
                            "target_port": 8443,
                            "remote_dns": true,
                            "dns_mode": "remote",
                            "total_ms": 48.2,
                            "overall_probe_duration_ms": 50.1,
                            "http_status": 200,
                            "server_header": "nginx-private-gw/1.25",
                            "cf_mitigated": false,
                            "verdict": "reachable",
                            "note": "Connected via HK-Secret-Node-01 to internal.corp.example (10.20.30.40:8443)",
                            "error": "transient warning from 192.168.99.1",
                            "udp_probe": {
                                "status": "verified",
                                "configured_udp": true,
                                "target": "1.1.1.1:53",
                                "rtt_ms": 19.4,
                                "detail": "UDP DNS response from 1.1.1.1:53 via HK-Secret-Node-01"
                            }
                        })
                    } else {
                        json!({
                            "requested_proxy": "🚀 VIP-Group",
                            "effective_outbound": "HK-Secret-Node-01",
                            "protocol": "vless",
                            "chains": ["🚀 VIP-Group", "HK-Secret-Node-01"],
                            "reachable_count": 1,
                            "auth_required_count": 0,
                            "rate_limited_count": 0,
                            "blocked_count": 0,
                            "unreachable_count": 0,
                            "ai_egress_unblocked": true,
                            "ai_status_note": "AI endpoints reachable via HK-Secret-Node-01 (exit 203.0.113.200)",
                            "udp_probe": {
                                "status": "verified",
                                "configured_udp": true,
                                "target": "8.8.8.8:53",
                                "rtt_ms": 21.0,
                                "detail": "UDP verified against 8.8.8.8:53"
                            },
                            "items": [
                                {
                                    "id": "openai",
                                    "label": "OpenAI API",
                                    "category": "ai",
                                    "report": {
                                        "requested_proxy": "🚀 VIP-Group",
                                        "effective_outbound": "HK-Secret-Node-01",
                                        "protocol": "vless",
                                        "chains": ["🚀 VIP-Group", "HK-Secret-Node-01"],
                                        "url": "https://api.openai.com/v1/models",
                                        "target_host": "api.openai.com",
                                        "target_port": 443,
                                        "remote_dns": true,
                                        "dns_mode": "remote",
                                        "total_ms": 88.0,
                                        "overall_probe_duration_ms": 88.0,
                                        "http_status": 401,
                                        "server_header": "cloudflare-edge-secret",
                                        "cf_mitigated": false,
                                        "verdict": "auth_required",
                                        "note": "HTTP 401 from api.openai.com via 10.99.88.77",
                                        "error": Value::Null,
                                        "udp_probe": Value::Null
                                    }
                                }
                            ]
                        })
                    };
                    let body_bytes = serde_json::to_vec(&body_json).unwrap();
                    let resp = format!(
                        "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
                        body_bytes.len()
                    );
                    let _ = sock.write_all(resp.as_bytes()).await;
                    let _ = sock.write_all(&body_bytes).await;
                });
            }
        });

        let redacted_opts = McpServerOptions {
            config_path: None,
            controller: Some(mock_addr.to_string()),
            secret: None,
            allow_mutations: false,
            include_network_metadata: false,
        };

        // 1. Audit config security redacts server host:port, controller, and bind-address in both location & detail
        let audit_resp = handle_mcp_request(
            &json!({
                "jsonrpc": "2.0",
                "id": 201,
                "method": "tools/call",
                "params": {
                    "name": "audit_config_security",
                    "arguments": { "config_path": draft_yaml_path.to_string_lossy() }
                }
            }),
            &redacted_opts,
        )
        .await
        .unwrap();
        let _ = std::fs::remove_file(&draft_yaml_path);
        let audit_text = audit_resp["result"]["content"][0]["text"].as_str().unwrap();
        assert!(audit_text.contains("SEC-PLAINTEXT-NODE"));
        assert!(audit_text.contains("SEC-CONTROLLER-NO-SECRET"));
        assert!(audit_text.contains("\"controller\": \"<redacted>\""));
        for leaked in [plaintext_srv, "8080", lan_ctrl, "192.168.77.88"] {
            assert!(
                !audit_text.contains(leaked),
                "audit_config_security leaked '{leaked}' when !include_network_metadata: {audit_text}"
            );
        }

        // 2. probe_waterfall redacts chains, proxy names, URL/host/port, server_header, udp_probe.target, and IPs in note/error/detail
        let wf_resp = handle_mcp_request(
            &json!({
                "jsonrpc": "2.0",
                "id": 202,
                "method": "tools/call",
                "params": {
                    "name": "probe_waterfall",
                    "arguments": {
                        "proxy": "🚀 VIP-Group",
                        "url": "https://internal.corp.example:8443/health"
                    }
                }
            }),
            &redacted_opts,
        )
        .await
        .unwrap();
        let wf_text = wf_resp["result"]["content"][0]["text"].as_str().unwrap();
        for leaked in [
            "VIP-Group",
            "HK-Secret-Node-01",
            "internal.corp.example",
            "8443",
            "nginx-private-gw",
            "1.1.1.1",
            "10.20.30.40",
            "192.168.99.1",
        ] {
            assert!(
                !wf_text.contains(leaked),
                "probe_waterfall leaked '{leaked}' when !include_network_metadata: {wf_text}"
            );
        }

        // 3. probe_ai_matrix redacts top-level & nested item fields + private/public IPs in notes
        let mx_resp = handle_mcp_request(
            &json!({
                "jsonrpc": "2.0",
                "id": 203,
                "method": "tools/call",
                "params": {
                    "name": "probe_ai_matrix",
                    "arguments": { "proxy": "🚀 VIP-Group" }
                }
            }),
            &redacted_opts,
        )
        .await
        .unwrap();
        let mx_text = mx_resp["result"]["content"][0]["text"].as_str().unwrap();
        for leaked in [
            "VIP-Group",
            "HK-Secret-Node-01",
            "api.openai.com",
            "cloudflare-edge-secret",
            "8.8.8.8",
            "203.0.113.200",
            "10.99.88.77",
        ] {
            assert!(
                !mx_text.contains(leaked),
                "probe_ai_matrix leaked '{leaked}' when !include_network_metadata: {mx_text}"
            );
        }

        server_task.abort();
    }

    #[tokio::test]
    async fn mcp_invalid_jsonrpc_primitives_return_32600_and_slow_probe_does_not_hol_block_ping() {
        let ro_opts = McpServerOptions {
            config_path: None,
            controller: Some("127.0.0.1:1".to_string()),
            secret: None,
            allow_mutations: false,
            include_network_metadata: false,
        };

        // 1. Non-object primitives (`42`, `"str"`, `true`, `null`), empty batch `[]`, and method-less `{ "jsonrpc": "2.0" }`
        // MUST return JSON-RPC `-32600 Invalid Request` with `id: null` and never be silently dropped.
        let invalid_lines = [
            "42",
            "\"str\"",
            "true",
            "null",
            "[]",
            "{\"jsonrpc\":\"2.0\"}",
        ]
        .join("\n")
            + "\n";
        let mut invalid_out = Vec::new();
        serve_mcp_io(
            std::io::Cursor::new(invalid_lines.into_bytes()),
            &mut invalid_out,
            ro_opts,
        )
        .await
        .unwrap();
        let invalid_frames: Vec<Value> = String::from_utf8(invalid_out)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(invalid_frames.len(), 6);
        for f in &invalid_frames {
            assert_eq!(f["error"]["code"], -32600, "unexpected frame: {f}");
            assert!(
                f["id"].is_null(),
                "expected id: null on invalid request: {f}"
            );
        }

        // 2. Concurrent dispatch: a slow in-flight `probe_waterfall` MUST NOT head-of-line block `ping` or `notifications/cancelled`.
        let slow_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let slow_addr = slow_listener.local_addr().unwrap();
        let (probe_started_tx, probe_started_rx) = tokio::sync::oneshot::channel::<()>();
        let (release_probe_tx, release_probe_rx) = tokio::sync::oneshot::channel::<()>();

        let slow_ctrl_task = tokio::spawn(async move {
            let (mut sock, _) = slow_listener.accept().await.unwrap();
            let mut req_buf = vec![0u8; 2048];
            let _ = sock.read(&mut req_buf).await;
            let _ = probe_started_tx.send(());
            let _ = release_probe_rx.await;
            let body = serde_json::to_vec(&json!({
                "requested_proxy": "DIRECT",
                "effective_outbound": "DIRECT",
                "protocol": "direct",
                "chains": ["DIRECT"],
                "url": "https://example.com/",
                "target_host": "example.com",
                "target_port": 443,
                "remote_dns": false,
                "dns_mode": "local",
                "total_ms": 12.0,
                "overall_probe_duration_ms": 12.0,
                "verdict": "reachable",
                "cf_mitigated": false,
                "note": "ok"
            }))
            .unwrap();
            let head = format!(
                "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
                body.len()
            );
            let _ = sock.write_all(head.as_bytes()).await;
            let _ = sock.write_all(&body).await;
        });

        let (mut client_in, server_in) = tokio::io::duplex(16 * 1024);
        let (server_out, client_out) = tokio::io::duplex(16 * 1024);
        let conc_opts = McpServerOptions {
            config_path: None,
            controller: Some(slow_addr.to_string()),
            secret: None,
            allow_mutations: false,
            include_network_metadata: false,
        };
        let mcp_task = tokio::spawn(async move {
            serve_mcp_io(server_in, server_out, conc_opts)
                .await
                .unwrap();
        });

        let mut out_reader = BufReader::new(client_out);

        // Send slow `probe_waterfall` (id=100)
        let slow_req = json!({
            "jsonrpc": "2.0",
            "id": 100,
            "method": "tools/call",
            "params": {
                "name": "probe_waterfall",
                "arguments": { "proxy": "DIRECT", "url": "https://example.com/", "timeout_ms": 5000 }
            }
        })
        .to_string()
            + "\n";
        client_in.write_all(slow_req.as_bytes()).await.unwrap();
        client_in.flush().await.unwrap();

        // Wait until the mock controller confirms `probe_waterfall` is actively blocked on I/O
        tokio::time::timeout(Duration::from_secs(2), probe_started_rx)
            .await
            .expect("probe_waterfall started")
            .unwrap();

        // Now send `notifications/cancelled` + `ping` (id=101) while `probe_waterfall` is still blocked!
        let fast_frames = format!(
            "{}\n{}\n",
            json!({
                "jsonrpc": "2.0",
                "method": "notifications/cancelled",
                "params": { "requestId": 100, "reason": "user cancelled" }
            }),
            json!({
                "jsonrpc": "2.0",
                "id": 101,
                "method": "ping"
            })
        );
        client_in.write_all(fast_frames.as_bytes()).await.unwrap();
        client_in.flush().await.unwrap();

        // `ping` response (id=101) MUST arrive immediately without waiting for `release_probe_tx`!
        let mut first_line = String::new();
        tokio::time::timeout(
            Duration::from_millis(500),
            out_reader.read_line(&mut first_line),
        )
        .await
        .expect("ping must not be head-of-line blocked by slow probe_waterfall")
        .unwrap();
        let first_val: Value = serde_json::from_str(first_line.trim()).unwrap();
        assert_eq!(first_val["id"], 101);

        // Release slow `probe_waterfall` and verify id=100 completes cleanly
        let _ = release_probe_tx.send(());
        let mut second_line = String::new();
        tokio::time::timeout(
            Duration::from_secs(2),
            out_reader.read_line(&mut second_line),
        )
        .await
        .expect("slow probe response arrives after release")
        .unwrap();
        let second_val: Value = serde_json::from_str(second_line.trim()).unwrap();
        assert_eq!(second_val["id"], 100);

        drop(client_in);
        mcp_task.await.unwrap();
        slow_ctrl_task.await.unwrap();
    }

    #[tokio::test]
    async fn mcp_validates_jsonrpc_version_supports_batches_and_preserves_content_length_error_framing()
     {
        let ro_opts = McpServerOptions {
            config_path: None,
            controller: Some("127.0.0.1:1".to_string()),
            secret: None,
            allow_mutations: false,
            include_network_metadata: false,
        };

        // 1. Missing or wrong `jsonrpc` version returns -32600 Invalid Request
        let bad_ver = handle_mcp_request(&json!({"id": 7, "method": "ping"}), &ro_opts)
            .await
            .unwrap();
        assert_eq!(bad_ver["error"]["code"], -32600);
        assert_eq!(bad_ver["id"], 7);

        // 2. JSON-RPC 2.0 batch request omits notifications and returns array of responses
        let batch_resp = handle_mcp_request(
            &json!([
                {"jsonrpc": "2.0", "method": "notifications/initialized"},
                {"jsonrpc": "2.0", "id": 10, "method": "ping"},
                {"jsonrpc": "2.0", "id": 11, "method": "prompts/list"}
            ]),
            &ro_opts,
        )
        .await
        .unwrap();
        let arr = batch_resp.as_array().expect("batch array response");
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0]["id"], 10);
        assert_eq!(arr[1]["id"], 11);

        // 3. Mixed-case `CONTENT-LENGTH:` header with malformed JSON replies using `Content-Length:` framing!
        let malformed_body = b"{invalid-json";
        let raw_in = format!(
            "CONTENT-LENGTH: {}\r\nContent-Type: application/vscode-jsonrpc; charset=utf-8\r\n\r\n",
            malformed_body.len()
        );
        let mut input_bytes = raw_in.into_bytes();
        input_bytes.extend_from_slice(malformed_body);

        let mut out_bytes = Vec::new();
        serve_mcp_io(std::io::Cursor::new(input_bytes), &mut out_bytes, ro_opts)
            .await
            .unwrap();
        let out_str = String::from_utf8(out_bytes).unwrap();
        assert!(
            out_str.starts_with("Content-Length: "),
            "parse error on Content-Length stream must preserve Content-Length framing, got: {out_str}"
        );
        assert!(out_str.contains("-32700"));
    }

    #[tokio::test]
    async fn mcp_auto_discovers_ephemeral_secret_and_random_port_without_leaking_secret() {
        let state_dir = std::env::temp_dir()
            .join(format!("rc-mcp-discovery-live-{}", std::process::id()))
            .join(format!(
                "{}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
        std::fs::create_dir_all(&state_dir).unwrap();

        // Active profile YAML deliberately omits `secret:` (standard subscription scenario)
        let mut cfg = ClashConfig::from_yaml_str(&ClashConfig::default_starter_yaml()).unwrap();
        cfg.mixed_port = 0;
        cfg.dns.listen = "127.0.0.1:0".to_string();
        cfg.tun.enable = false;
        cfg.secret = None;
        let ephemeral_secret = cfg.ensure_ephemeral_secret();
        assert!(!ephemeral_secret.is_empty());

        let engine = ProxyEngine::start_with_state_dir(cfg, state_dir.clone())
            .await
            .expect("engine starts");
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let (bound_addr, api_task) = proxy_core::api::spawn_api_server(
            "127.0.0.1:0",
            std::sync::Arc::clone(&engine),
            shutdown_rx,
        )
        .await
        .expect("ephemeral port API binds");
        engine
            .publish_controller_discovery(state_dir.clone(), bound_addr)
            .expect("discovery file written");

        let opts = McpServerOptions {
            config_path: None,
            controller: None,
            secret: None,
            allow_mutations: false,
            include_network_metadata: false,
        };

        let status_res =
            execute_tool_call_with_state_dir("get_proxy_status", &json!({}), &opts, &state_dir)
                .await;
        let text = status_res["content"][0]["text"].as_str().unwrap();
        assert!(
            !text.contains(&ephemeral_secret),
            "ephemeral secret MUST never leak into MCP tool output"
        );
        let parsed: Value = serde_json::from_str(text).unwrap();
        assert_eq!(parsed["daemon_connected"], true);
        assert_eq!(parsed["controller"], "<redacted>");

        // Also verify `explain_route` seamlessly connects to the live controller
        let explain_res = execute_tool_call_with_state_dir(
            "explain_route",
            &json!({ "target": "example.com:443" }),
            &opts,
            &state_dir,
        )
        .await;
        let explain_text = explain_res["content"][0]["text"].as_str().unwrap();
        assert!(!explain_text.contains(&ephemeral_secret));
        let explain_val: Value = serde_json::from_str(explain_text).unwrap();
        assert!(explain_val.get("auth_error").is_none());

        // Shutdown cleanly removes the PID-owned discovery file
        let _ = shutdown_tx.send(true);
        engine.shutdown_async().await;
        let _ = tokio::time::timeout(Duration::from_secs(2), api_task).await;
        assert!(
            proxy_core::platform::recovery::read_controller_discovery(&state_dir).is_none(),
            "graceful shutdown must remove PID-owned controller discovery file"
        );

        let _ = std::fs::remove_dir_all(&state_dir);
    }

    #[tokio::test]
    async fn mcp_degrades_gracefully_when_discovery_file_is_stale_or_dead() {
        let state_dir = std::env::temp_dir().join(format!(
            "rc-mcp-discovery-stale-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&state_dir).unwrap();

        // Bind then immediately drop a loopback TCP port so we guarantee a dead port
        let dead_port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let stale_ep = proxy_core::platform::recovery::ControllerRuntimeEndpoint {
            pid: 999_999,
            addr: format!("127.0.0.1:{dead_port}"),
            secret: Some("stale-secret-dead-daemon".to_string()),
        };
        proxy_core::platform::recovery::write_controller_discovery(&state_dir, &stale_ep).unwrap();

        // Write a config whose external-controller also points to the dead port
        let cfg_path = state_dir.join("offline.yaml");
        let yaml = format!(
            "mixed-port: 0\nexternal-controller: 127.0.0.1:{dead_port}\nmode: rule\nrules:\n  - MATCH,DIRECT\n"
        );
        std::fs::write(&cfg_path, yaml).unwrap();

        let opts = McpServerOptions {
            config_path: Some(cfg_path),
            controller: None,
            secret: None,
            allow_mutations: false,
            include_network_metadata: false,
        };

        let status_res =
            execute_tool_call_with_state_dir("get_proxy_status", &json!({}), &opts, &state_dir)
                .await;
        assert_eq!(status_res["isError"], false);
        let text = status_res["content"][0]["text"].as_str().unwrap();
        assert!(!text.contains("stale-secret-dead-daemon"));
        let parsed: Value = serde_json::from_str(text).unwrap();
        assert_eq!(parsed["daemon_connected"], false);
        assert!(parsed.get("auth_error").is_none());
        assert!(
            parsed["note"]
                .as_str()
                .unwrap_or("")
                .contains("No live rust-clash controller responded")
        );

        let _ = std::fs::remove_dir_all(&state_dir);
    }

    #[tokio::test]
    async fn mcp_reports_clear_401_auth_error_without_echoing_secret_or_controller() {
        let state_dir = std::env::temp_dir().join(format!(
            "rc-mcp-discovery-401-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&state_dir).unwrap();

        let mut cfg = ClashConfig::from_yaml_str(&ClashConfig::default_starter_yaml()).unwrap();
        cfg.mixed_port = 0;
        cfg.dns.listen = "127.0.0.1:0".to_string();
        cfg.tun.enable = false;
        cfg.secret = None;
        let real_secret = cfg.ensure_ephemeral_secret();

        let engine = ProxyEngine::start_with_state_dir(cfg, state_dir.clone())
            .await
            .expect("engine starts");
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let (bound_addr, api_task) = proxy_core::api::spawn_api_server(
            "127.0.0.1:0",
            std::sync::Arc::clone(&engine),
            shutdown_rx,
        )
        .await
        .expect("api binds");
        engine
            .publish_controller_discovery(state_dir.clone(), bound_addr)
            .expect("discovery written");

        let wrong_secret = "wrong-super-secret-token-xyz987";
        let opts = McpServerOptions {
            config_path: None,
            controller: None,
            secret: Some(wrong_secret.to_string()),
            allow_mutations: false,
            include_network_metadata: false,
        };

        let status_res =
            execute_tool_call_with_state_dir("get_proxy_status", &json!({}), &opts, &state_dir)
                .await;
        let text = status_res["content"][0]["text"].as_str().unwrap();
        assert!(!text.contains(&real_secret), "must not leak real secret");
        assert!(!text.contains(wrong_secret), "must not echo wrong secret");
        assert!(
            !text.contains(&bound_addr.to_string()),
            "must not leak live controller address in redacted mode"
        );
        let parsed: Value = serde_json::from_str(text).unwrap();
        assert_eq!(parsed["daemon_connected"], false);
        assert_eq!(parsed["auth_error"], true);
        assert_eq!(parsed["http_status"], 401);
        assert!(
            parsed["note"]
                .as_str()
                .unwrap_or("")
                .contains("401 Unauthorized")
        );

        let _ = shutdown_tx.send(true);
        engine.shutdown_async().await;
        let _ = tokio::time::timeout(Duration::from_secs(2), api_task).await;
        let _ = std::fs::remove_dir_all(&state_dir);
    }

    #[test]
    fn mcp_explicit_controller_does_not_leak_local_discovery_secret_to_other_endpoints() {
        let state_dir = std::env::temp_dir().join(format!(
            "rc-mcp-discovery-iso-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&state_dir).unwrap();

        let local_ep = proxy_core::platform::recovery::ControllerRuntimeEndpoint {
            pid: std::process::id(),
            addr: "127.0.0.1:19090".to_string(),
            secret: Some("local-desktop-secret".to_string()),
        };
        proxy_core::platform::recovery::write_controller_discovery(&state_dir, &local_ep).unwrap();

        // Explicit --controller pointing to a DIFFERENT port must NOT receive local discovery secret
        let other_clients = resolve_controller_clients_in_state_dir(
            &state_dir,
            Some("127.0.0.1:19999"),
            None,
            None,
        );
        assert_eq!(other_clients.len(), 1);
        assert_eq!(other_clients[0].host_port, "127.0.0.1:19999");
        assert_eq!(other_clients[0].secret, None);

        // Explicit --controller matching the SAME local loopback port (including localhost alias) reuses it cleanly
        let same_clients = resolve_controller_clients_in_state_dir(
            &state_dir,
            Some("http://localhost:19090/"),
            None,
            None,
        );
        assert_eq!(same_clients.len(), 1);
        assert_eq!(same_clients[0].host_port, "127.0.0.1:19090");
        assert_eq!(
            same_clients[0].secret.as_deref(),
            Some("local-desktop-secret")
        );

        let _ = std::fs::remove_dir_all(&state_dir);
    }

    #[tokio::test]
    async fn mcp_get_proxy_status_isolates_failed_diagnostics_and_summarizes_anomalies() {
        let state_dir = std::env::temp_dir().join(format!(
            "rc-mcp-failed-only-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&state_dir).unwrap();

        let mut cfg = proxy_core::config::ClashConfig {
            mixed_port: 0,
            external_controller: "127.0.0.1:0".to_string(),
            secret: None,
            ..Default::default()
        };
        cfg.dns.listen = "127.0.0.1:0".to_string();
        cfg.tun.enable = false;
        cfg.ensure_ephemeral_secret();

        let engine = proxy_core::engine::ProxyEngine::start_with_state_dir(cfg, state_dir.clone())
            .await
            .expect("start engine");

        let hub = engine.hub();
        let direct_ob = proxy_core::outbound::DirectOutbound::new("DIRECT");
        // 1. Seed 2 failed connections FIRST
        for idx in 0..2u16 {
            let target =
                proxy_core::addr::TargetAddr::new_domain(format!("broken{idx}.example.com"), 443)
                    .unwrap();
            let guard = hub.register_connection_with_outbound_guard(
                "TUN(smoltcp)",
                "tcp",
                None,
                &target,
                None,
                "MATCH",
                "",
                vec!["PROXY".to_string()],
                &direct_ob,
            );
            guard.record_failed("outbound dial+handshake timed out");
        }

        // 2. Flood 20 normal closed connections + 1 zero-download active TCP TUN connection AFTER
        //    the failures so naive `/connections/diagnostics?limit=15` would completely hide them!
        for idx in 0..20u16 {
            let target =
                proxy_core::addr::TargetAddr::new_domain(format!("ok{idx}.example.com"), 443)
                    .unwrap();
            let guard = hub.register_connection_with_outbound_guard(
                "TUN(smoltcp)",
                "tcp",
                None,
                &target,
                Some(format!("198.18.0.{}", 10 + idx)),
                "GEOSITE",
                "cn",
                vec!["DIRECT".to_string()],
                &direct_ob,
            );
            guard.mark_established();
            hub.record_upload(guard.connection(), 512);
            hub.record_download(guard.connection(), 4096);
            drop(guard);
        }
        let stall_target = proxy_core::addr::TargetAddr::new_ip("31.13.73.1".parse().unwrap(), 443);
        let stall_guard = hub.register_connection_with_outbound_guard(
            "TUN(smoltcp)",
            "tcp",
            None,
            &stall_target,
            None,
            "MATCH",
            "",
            vec!["PROXY".to_string()],
            &direct_ob,
        );
        stall_guard.mark_established();
        hub.record_upload(stall_guard.connection(), 2048);

        hub.push_log(
            "info",
            "routine info message should not appear in warn/error",
        );
        hub.push_log(
            "warn",
            "Wintun dial warning toward 31.13.73.1:443 with secret=super-secret-xyz",
        );

        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let (bound_addr, api_task) =
            proxy_core::api::spawn_api_server("127.0.0.1:0", engine.clone(), shutdown_rx)
                .await
                .expect("spawn api server");
        engine
            .publish_controller_discovery(state_dir.clone(), bound_addr)
            .expect("write controller discovery");

        let opts = McpServerOptions {
            config_path: None,
            controller: None,
            secret: None,
            allow_mutations: false,
            include_network_metadata: false,
        };
        let res =
            execute_tool_call_with_state_dir("get_proxy_status", &json!({}), &opts, &state_dir)
                .await;
        let text = res["content"][0]["text"].as_str().unwrap();
        assert!(!text.contains("super-secret-xyz"));
        assert!(!text.contains("31.13.73.1"));

        let parsed: Value = serde_json::from_str(text).unwrap();
        assert_eq!(parsed["daemon_connected"], true);

        let failures = parsed["recent_failure_diagnostics"].as_array().unwrap();
        assert_eq!(
            failures.len(),
            2,
            "recent_failure_diagnostics must contain ONLY the 2 real failures, not routine closed connections: {failures:?}"
        );
        for item in failures {
            assert_eq!(item["status"], "failed");
            assert!(item["error"].as_str().is_some());
        }

        let summary = &parsed["recent_connections_summary"];
        assert_eq!(summary["zero_download_tcp_count"], 1);
        assert_eq!(summary["tun_fake_ip_count"], 20);
        assert_eq!(summary["tun_real_ip_count"], 3); // 2 failed + 1 stalled real-IP

        let warn_logs = parsed["recent_warn_error_logs"].as_array().unwrap();
        assert!(
            warn_logs.iter().any(|l| {
                l["level"] == "warn"
                    && l["payload"]
                        .as_str()
                        .unwrap_or("")
                        .contains("[redacted-endpoint]")
            }),
            "recent_warn_error_logs must surface redacted warn/error entries: {warn_logs:?}"
        );
        assert!(
            warn_logs.iter().all(|l| l["level"] != "info"),
            "routine info logs must not pollute recent_warn_error_logs"
        );

        drop(stall_guard);
        let _ = shutdown_tx.send(true);
        engine.shutdown_async().await;
        let _ = tokio::time::timeout(Duration::from_secs(2), api_task).await;
        let _ = std::fs::remove_dir_all(&state_dir);
    }

    #[tokio::test]
    async fn get_proxy_status_includes_load_balance_groups() {
        let state_dir =
            std::env::temp_dir().join(format!("rustclash-mcp-lb-group-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&state_dir).unwrap();

        let yaml = r#"
mixed-port: 0
external-controller: ""
mode: rule
proxies:
  - name: node-a
    type: ss
    server: 198.51.100.11
    port: 8388
    cipher: aes-128-gcm
    password: pass-a
  - name: node-b
    type: ss
    server: 198.51.100.12
    port: 8388
    cipher: aes-128-gcm
    password: pass-b
proxy-groups:
  - name: LB-POOL
    type: load-balance
    strategy: consistent-hashing
    proxies:
      - node-a
      - node-b
rules:
  - MATCH,LB-POOL
"#;
        let mut cfg = ClashConfig::from_yaml_str(yaml).unwrap();
        cfg.dns.enable = false;
        let engine = ProxyEngine::start_with_state_dir(cfg, state_dir.clone())
            .await
            .unwrap();

        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let (bound_addr, api_task) =
            proxy_core::api::spawn_api_server("127.0.0.1:0", engine.clone(), shutdown_rx)
                .await
                .expect("spawn api server");
        engine
            .publish_controller_discovery(state_dir.clone(), bound_addr)
            .expect("write controller discovery");

        let opts = McpServerOptions {
            config_path: None,
            controller: None,
            secret: None,
            allow_mutations: false,
            include_network_metadata: false,
        };
        let res =
            execute_tool_call_with_state_dir("get_proxy_status", &json!({}), &opts, &state_dir)
                .await;
        let text = res["content"][0]["text"].as_str().unwrap();
        let parsed: Value = serde_json::from_str(text).unwrap();
        let groups = parsed["groups"].as_array().expect("groups array");
        assert!(
            groups.iter().any(|g| g["name"] == "LB-POOL"
                && g["type"] == "LoadBalance"
                && g["member_count"] == 2),
            "get_proxy_status must include LoadBalance groups: {groups:?}"
        );

        let _ = shutdown_tx.send(true);
        engine.shutdown_async().await;
        let _ = tokio::time::timeout(Duration::from_secs(2), api_task).await;
        let _ = std::fs::remove_dir_all(&state_dir);
    }

    #[tokio::test]
    async fn get_proxy_status_reports_by_rule_type_and_sniffer_hit_count_without_leaking_hosts() {
        let state_dir = std::env::temp_dir().join(format!(
            "rustclash-mcp-sniffer-summary-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&state_dir).unwrap();

        let mut cfg = ClashConfig::from_yaml_str(
            r#"
mixed-port: 0
external-controller: ""
mode: rule
rules:
  - MATCH,DIRECT
"#,
        )
        .unwrap();
        cfg.dns.enable = false;
        let engine = ProxyEngine::start_with_state_dir(cfg, state_dir.clone())
            .await
            .unwrap();

        let hub = engine.hub();
        let direct_ob = proxy_core::outbound::DirectOutbound::new("DIRECT");

        // 1. Sniffed TUN TCP real-IP -> DomainSuffix
        let sniffed_tcp_target =
            proxy_core::addr::TargetAddr::new_domain("claude.secret-test.example", 443).unwrap();
        let g1 = hub.register_connection_with_outbound_guard_sniffed(
            "TUN(smoltcp)",
            "tcp",
            None,
            &sniffed_tcp_target,
            None,
            "DomainSuffix",
            "secret-test.example",
            vec!["PROXY".to_string()],
            &direct_ob,
            true,
        );
        g1.mark_established();
        hub.record_download(g1.connection(), 1024);
        drop(g1);

        // 2. Sniffed TUN UDP QUIC real-IP -> GeoSite
        let sniffed_udp_target =
            proxy_core::addr::TargetAddr::new_domain("quic.secret-test.example", 443).unwrap();
        let g2 = hub.register_connection_with_outbound_guard_sniffed(
            "TUN(smoltcp)",
            "udp",
            None,
            &sniffed_udp_target,
            None,
            "GeoSite",
            "google",
            vec!["PROXY".to_string()],
            &direct_ob,
            true,
        );
        g2.mark_established();
        hub.record_download(g2.connection(), 2048);
        drop(g2);

        // 3. Unsniffed Fake-IP TUN TCP -> GeoSite
        let fake_ip_target =
            proxy_core::addr::TargetAddr::new_domain("www.baidu.com", 443).unwrap();
        let g3 = hub.register_connection_with_outbound_guard_sniffed(
            "TUN(smoltcp)",
            "tcp",
            None,
            &fake_ip_target,
            Some("198.18.0.42".to_string()),
            "GeoSite",
            "cn",
            vec!["DIRECT".to_string()],
            &direct_ob,
            false,
        );
        g3.mark_established();
        hub.record_download(g3.connection(), 4096);
        drop(g3);

        // 4. Unsniffed real-IP -> GeoIP
        let raw_ip_target =
            proxy_core::addr::TargetAddr::new_ip("198.51.100.55".parse().unwrap(), 80);
        let g4 = hub.register_connection_with_outbound_guard_sniffed(
            "TUN(smoltcp)",
            "tcp",
            None,
            &raw_ip_target,
            None,
            "GeoIP",
            "CN",
            vec!["DIRECT".to_string()],
            &direct_ob,
            false,
        );
        g4.mark_established();
        hub.record_download(g4.connection(), 512);
        drop(g4);

        // 5. Unsniffed mixed inbound -> Match
        let match_target =
            proxy_core::addr::TargetAddr::new_domain("fallback.example.org", 443).unwrap();
        let g5 = hub.register_connection_with_outbound_guard_sniffed(
            "HTTP CONNECT",
            "tcp",
            None,
            &match_target,
            None,
            "Match",
            "",
            vec!["PROXY".to_string()],
            &direct_ob,
            false,
        );
        g5.mark_established();
        hub.record_download(g5.connection(), 256);
        drop(g5);

        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let (bound_addr, api_task) =
            proxy_core::api::spawn_api_server("127.0.0.1:0", engine.clone(), shutdown_rx)
                .await
                .expect("spawn api server");
        engine
            .publish_controller_discovery(state_dir.clone(), bound_addr)
            .expect("write controller discovery");

        let opts = McpServerOptions {
            config_path: None,
            controller: None,
            secret: None,
            allow_mutations: false,
            include_network_metadata: false,
        };
        let res =
            execute_tool_call_with_state_dir("get_proxy_status", &json!({}), &opts, &state_dir)
                .await;
        assert_eq!(res["isError"], false);
        let text = res["content"][0]["text"].as_str().unwrap();
        assert!(
            !text.contains("claude.secret-test.example")
                && !text.contains("quic.secret-test.example")
                && !text.contains("198.51.100.55"),
            "default privacy mode must not expose sniffed domains or target IPs: {text}"
        );

        let parsed: Value = serde_json::from_str(text).unwrap();
        let summary = &parsed["recent_connections_summary"];
        assert_eq!(summary["sampled_count"], 5);
        assert_eq!(summary["sniffer_hit_count"], 2);
        assert_eq!(summary["tun_fake_ip_count"], 1);
        assert_eq!(summary["tun_real_ip_count"], 3);
        assert_eq!(summary["by_rule_type"]["GeoSite"], 2);
        assert_eq!(summary["by_rule_type"]["DomainSuffix"], 1);
        assert_eq!(summary["by_rule_type"]["GeoIP"], 1);
        assert_eq!(summary["by_rule_type"]["Match"], 1);

        let _ = shutdown_tx.send(true);
        engine.shutdown_async().await;
        let _ = tokio::time::timeout(Duration::from_secs(2), api_task).await;
        let _ = std::fs::remove_dir_all(&state_dir);
    }

    #[tokio::test]
    async fn get_recent_logs_filters_levels_clamps_limit_retains_warnings_and_redacts_endpoints() {
        let state_dir =
            std::env::temp_dir().join(format!("rustclash-mcp-logs-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&state_dir).unwrap();

        let mut cfg = ClashConfig::from_yaml_str(
            r#"
mixed-port: 0
external-controller: ""
mode: rule
rules:
  - MATCH,DIRECT
"#,
        )
        .unwrap();
        cfg.dns.enable = false;
        let engine = ProxyEngine::start_with_state_dir(cfg, state_dir.clone())
            .await
            .unwrap();

        let hub = engine.hub();
        hub.push_log(
            "error",
            "Upstream dial failed to 198.51.100.77:443 and [2001:db8::1]:443 with password=SuperSecretPw123",
        );
        hub.push_log(
            "warn",
            "Slow handshake to secret.corp.example:8443 via https://internal.example/api?token=Tok9988",
        );
        // Flood routine info logs (>250) to verify warn/error entries survive in important_logs().
        for idx in 0..260 {
            hub.push_log(
                "info",
                format!("Routine info log #{idx} targeting 203.0.113.10:80"),
            );
        }

        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let (bound_addr, api_task) =
            proxy_core::api::spawn_api_server("127.0.0.1:0", engine.clone(), shutdown_rx)
                .await
                .expect("spawn api server");
        engine
            .publish_controller_discovery(state_dir.clone(), bound_addr)
            .expect("write controller discovery");

        let redacted_opts = McpServerOptions {
            config_path: None,
            controller: None,
            secret: None,
            allow_mutations: false,
            include_network_metadata: false,
        };

        // 1. Default call (`level: warn`, `limit: 30`): surfaces warn + error even after 260 info logs,
        // and redacts BOTH credentials AND IPv4 / bracketed IPv6 / host:port / URLs.
        let warn_res = execute_tool_call_with_state_dir(
            "get_recent_logs",
            &json!({}),
            &redacted_opts,
            &state_dir,
        )
        .await;
        assert_eq!(warn_res["isError"], false);
        let warn_text = warn_res["content"][0]["text"].as_str().unwrap();
        assert!(!warn_text.contains("SuperSecretPw123"));
        assert!(!warn_text.contains("Tok9988"));
        assert!(!warn_text.contains("198.51.100.77"));
        assert!(!warn_text.contains("2001:db8::1"));
        assert!(!warn_text.contains("secret.corp.example"));
        assert!(!warn_text.contains("internal.example"));
        assert!(!warn_text.contains(&bound_addr.to_string()));

        let warn_parsed: Value = serde_json::from_str(warn_text).unwrap();
        assert_eq!(warn_parsed["daemon_connected"], true);
        assert_eq!(warn_parsed["level"], "warn");
        assert_eq!(warn_parsed["limit"], 30);
        assert_eq!(warn_parsed["controller"], "<redacted>");
        let warn_logs = warn_parsed["logs"].as_array().unwrap();
        assert!(warn_logs.len() >= 2);
        assert!(warn_logs.iter().all(|l| l["level"] != "info"));
        assert!(warn_logs.iter().any(|l| {
            l["level"] == "error"
                && l["payload"]
                    .as_str()
                    .unwrap_or("")
                    .contains("[redacted-endpoint]")
        }));

        // 2. `level: error` returns only error entries.
        let err_res = execute_tool_call_with_state_dir(
            "get_recent_logs",
            &json!({ "level": "error" }),
            &redacted_opts,
            &state_dir,
        )
        .await;
        assert_eq!(err_res["isError"], false);
        let err_parsed: Value =
            serde_json::from_str(err_res["content"][0]["text"].as_str().unwrap()).unwrap();
        let err_logs = err_parsed["logs"].as_array().unwrap();
        assert!(!err_logs.is_empty());
        assert!(err_logs.iter().all(|l| l["level"] == "error"));

        // 3. `level: all` with `limit: 500` clamps limit to 100 and returns info logs with endpoints redacted.
        let all_res = execute_tool_call_with_state_dir(
            "get_recent_logs",
            &json!({ "level": "all", "limit": 500 }),
            &redacted_opts,
            &state_dir,
        )
        .await;
        assert_eq!(all_res["isError"], false);
        let all_text = all_res["content"][0]["text"].as_str().unwrap();
        assert!(!all_text.contains("203.0.113.10"));
        let all_parsed: Value = serde_json::from_str(all_text).unwrap();
        assert_eq!(all_parsed["limit"], 100);
        assert_eq!(all_parsed["count"], 100);
        assert!(
            all_parsed["logs"]
                .as_array()
                .unwrap()
                .iter()
                .any(|l| l["level"] == "info")
        );

        // 4. Invalid level returns `isError: true`.
        let bad_res = execute_tool_call_with_state_dir(
            "get_recent_logs",
            &json!({ "level": "verbose" }),
            &redacted_opts,
            &state_dir,
        )
        .await;
        assert_eq!(bad_res["isError"], true);

        // 5. `--include-network-metadata` retains endpoints while STILL redacting secrets.
        let full_opts = McpServerOptions {
            include_network_metadata: true,
            ..redacted_opts
        };
        let full_res = execute_tool_call_with_state_dir(
            "get_recent_logs",
            &json!({ "level": "warn", "limit": 10 }),
            &full_opts,
            &state_dir,
        )
        .await;
        assert_eq!(full_res["isError"], false);
        let full_text = full_res["content"][0]["text"].as_str().unwrap();
        assert!(full_text.contains("198.51.100.77:443"));
        assert!(full_text.contains("[2001:db8::1]:443"));
        assert!(full_text.contains("secret.corp.example:8443"));
        assert!(!full_text.contains("SuperSecretPw123"));
        assert!(!full_text.contains("Tok9988"));

        let _ = shutdown_tx.send(true);
        engine.shutdown_async().await;
        let _ = tokio::time::timeout(Duration::from_secs(2), api_task).await;
        let _ = std::fs::remove_dir_all(&state_dir);
    }

    #[tokio::test]
    async fn mcp_frame_reader_is_cancel_safe_under_repeated_timeout_mid_header_and_body() {
        let (mut writer, reader_io) = tokio::io::duplex(256);

        let payload1 = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "ping",
            "params": { "note": "节点-🚀-cancel-safe-header-and-body" }
        });
        let body1 = serde_json::to_vec(&payload1).unwrap();
        let mut frame1 = format!(
            "\r\nContent-Type: application/vscode-jsonrpc; charset=utf-8\r\nContent-Length: {}\r\n\r\n",
            body1.len()
        )
        .into_bytes();
        frame1.extend_from_slice(&body1);

        let payload2 = json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "ping",
            "params": { "note": "换行JSON-流式取消安全" }
        });
        let mut frame2 = serde_json::to_vec(&payload2).unwrap();
        frame2.push(b'\n');

        let drip_task = tokio::spawn(async move {
            for b in frame1.into_iter().chain(frame2.into_iter()) {
                writer.write_all(&[b]).await.unwrap();
                writer.flush().await.unwrap();
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        });

        let mut frame_reader = McpFrameReader::new(reader_io);
        let mut total_cancellations = 0usize;

        async fn read_with_cancellations(
            reader: &mut McpFrameReader<tokio::io::DuplexStream>,
        ) -> (Option<(Value, FrameMode)>, usize) {
            let mut cancels = 0usize;
            loop {
                match tokio::time::timeout(Duration::from_millis(1), reader.read_next_frame()).await
                {
                    Ok(res) => return (res.unwrap(), cancels),
                    Err(_) => {
                        cancels += 1;
                    }
                }
            }
        }

        let (f1, c1) = read_with_cancellations(&mut frame_reader).await;
        total_cancellations += c1;
        let (v1, m1) = f1.expect("first frame parsed");
        assert_eq!(m1, FrameMode::ContentLength);
        assert_eq!(v1, payload1);

        let (f2, c2) = read_with_cancellations(&mut frame_reader).await;
        total_cancellations += c2;
        let (v2, m2) = f2.expect("second frame parsed");
        assert_eq!(m2, FrameMode::NewlineJson);
        assert_eq!(v2, payload2);

        assert!(
            total_cancellations >= 10,
            "test must exercise repeated mid-frame cancellations (observed {total_cancellations})"
        );

        let (eof_frame, _) = read_with_cancellations(&mut frame_reader).await;
        assert!(eof_frame.is_none(), "expected clean EOF after both frames");
        drip_task.await.unwrap();
    }

    async fn run_serve_mcp_io_cancel_safety_case(use_content_length: bool) {
        let slow_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let slow_addr = slow_listener.local_addr().unwrap();
        let (probe_started_tx, probe_started_rx) = tokio::sync::oneshot::channel::<()>();
        let (release_probe_tx, release_probe_rx) = tokio::sync::oneshot::channel::<()>();

        let slow_ctrl_task = tokio::spawn(async move {
            let (mut sock, _) = slow_listener.accept().await.unwrap();
            let mut req_buf = vec![0u8; 2048];
            let _ = sock.read(&mut req_buf).await;
            let _ = probe_started_tx.send(());
            let _ = release_probe_rx.await;
            let body = serde_json::to_vec(&json!({
                "requested_proxy": "DIRECT",
                "effective_outbound": "DIRECT",
                "protocol": "direct",
                "chains": ["DIRECT"],
                "url": "https://example.com/",
                "target_host": "example.com",
                "target_port": 443,
                "remote_dns": false,
                "dns_mode": "local",
                "total_ms": 10.0,
                "overall_probe_duration_ms": 10.0,
                "verdict": "reachable",
                "cf_mitigated": false,
                "note": "ok"
            }))
            .unwrap();
            let head = format!(
                "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
                body.len()
            );
            let _ = sock.write_all(head.as_bytes()).await;
            let _ = sock.write_all(&body).await;
        });

        let encode_req = |val: &Value, content_type_first: bool| -> Vec<u8> {
            let body = serde_json::to_vec(val).unwrap();
            if use_content_length {
                let hdr = if content_type_first {
                    format!(
                        "Content-Type: application/vscode-jsonrpc; charset=utf-8\r\nContent-Length: {}\r\n\r\n",
                        body.len()
                    )
                } else {
                    format!("Content-Length: {}\r\n\r\n", body.len())
                };
                let mut out = hdr.into_bytes();
                out.extend_from_slice(&body);
                out
            } else {
                let mut out = body;
                out.push(b'\n');
                out
            }
        };

        let (mut client_in, server_in) = tokio::io::duplex(4096);
        let (server_out, client_out) = tokio::io::duplex(16 * 1024);
        let opts = McpServerOptions {
            config_path: None,
            controller: Some(slow_addr.to_string()),
            secret: None,
            allow_mutations: false,
            include_network_metadata: false,
        };
        let mcp_task = tokio::spawn(async move {
            serve_mcp_io(server_in, server_out, opts).await.unwrap();
        });

        // 1. Send slow read-only request (id=501) so `resp_rx` will fire mid-read of request 2.
        let req1 = json!({
            "jsonrpc": "2.0",
            "id": 501,
            "method": "tools/call",
            "params": {
                "name": "probe_waterfall",
                "arguments": { "proxy": "DIRECT", "url": "https://example.com/", "timeout_ms": 5000 }
            }
        });
        client_in
            .write_all(&encode_req(&req1, false))
            .await
            .unwrap();
        client_in.flush().await.unwrap();

        tokio::time::timeout(Duration::from_secs(2), probe_started_rx)
            .await
            .expect("slow request started")
            .unwrap();

        // 2. Drip the first half of request 2 (id=502) byte-by-byte so `read_next_frame()`
        //    has partially buffered request 2 and is awaiting more bytes.
        let req2 = json!({
            "jsonrpc": "2.0",
            "id": 502,
            "method": "ping"
        });
        let req2_bytes = encode_req(&req2, true);
        let split_at = req2_bytes.len() / 2;
        for &b in &req2_bytes[..split_at] {
            client_in.write_all(&[b]).await.unwrap();
            client_in.flush().await.unwrap();
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        // Let `serve_mcp_io` consume the first half into `McpFrameReader.buf` and park on `read_buf`.
        tokio::time::sleep(Duration::from_millis(15)).await;

        // 3. Release request 1 so `resp_rx.recv()` wins `tokio::select!` and CANCELS `read_next_frame()`!
        let _ = release_probe_tx.send(());

        let mut resp_reader = McpFrameReader::new(client_out);
        let (first_resp, first_mode) =
            tokio::time::timeout(Duration::from_secs(2), resp_reader.read_next_frame())
                .await
                .expect("request 1 response arrives while request 2 is half-sent")
                .unwrap()
                .expect("request 1 frame present");
        assert_eq!(
            first_mode,
            if use_content_length {
                FrameMode::ContentLength
            } else {
                FrameMode::NewlineJson
            }
        );
        assert_eq!(first_resp["id"], 501);
        assert!(
            first_resp.get("error").is_none(),
            "unexpected error on request 1: {first_resp}"
        );

        // 4. Now drip the remaining bytes of request 2 one byte every 1ms.
        for &b in &req2_bytes[split_at..] {
            client_in.write_all(&[b]).await.unwrap();
            client_in.flush().await.unwrap();
            tokio::time::sleep(Duration::from_millis(1)).await;
        }

        let (second_resp, second_mode) =
            tokio::time::timeout(Duration::from_secs(2), resp_reader.read_next_frame())
                .await
                .expect("request 2 response arrives with zero desync / -32700")
                .unwrap()
                .expect("request 2 frame present");
        assert_eq!(
            second_mode,
            if use_content_length {
                FrameMode::ContentLength
            } else {
                FrameMode::NewlineJson
            }
        );
        assert_eq!(second_resp["id"], 502);
        assert!(
            second_resp.get("error").is_none(),
            "must never produce -32700 parse error after select! cancellation: {second_resp}"
        );
        assert!(second_resp.get("result").is_some());

        drop(client_in);
        mcp_task.await.unwrap();
        slow_ctrl_task.await.unwrap();
    }

    #[tokio::test]
    async fn mcp_serve_io_survives_select_cancellation_mid_frame_in_both_framing_modes() {
        run_serve_mcp_io_cancel_safety_case(true).await;
        run_serve_mcp_io_cancel_safety_case(false).await;
    }

    #[tokio::test]
    async fn mcp_accepts_content_type_and_custom_headers_in_any_order_and_rejects_invalid_headers()
    {
        let ro_opts = McpServerOptions {
            config_path: None,
            controller: Some("127.0.0.1:1".to_string()),
            secret: None,
            allow_mutations: false,
            include_network_metadata: false,
        };

        // 1. `Content-Type` BEFORE `Content-Length`, custom headers around `Content-Length`,
        //    LF-only headers, and identical duplicate `Content-Length` all dispatch cleanly!
        let b1 = serde_json::to_vec(&json!({"jsonrpc": "2.0", "id": 1, "method": "ping"})).unwrap();
        let b2 = serde_json::to_vec(&json!({"jsonrpc": "2.0", "id": 2, "method": "ping"})).unwrap();
        let b3 = serde_json::to_vec(&json!({"jsonrpc": "2.0", "id": 3, "method": "ping"})).unwrap();
        let b4 = serde_json::to_vec(&json!({"jsonrpc": "2.0", "id": 4, "method": "ping"})).unwrap();

        let mut stream = Vec::new();
        stream.extend_from_slice(
            format!(
                "Content-Type: application/vscode-jsonrpc; charset=utf-8\r\nContent-Length: {}\r\n\r\n",
                b1.len()
            )
            .as_bytes(),
        );
        stream.extend_from_slice(&b1);

        stream.extend_from_slice(
            format!(
                "X-Custom: foo\r\nContent-Length: {}\r\nContent-Type: application/json\r\n\r\n",
                b2.len()
            )
            .as_bytes(),
        );
        stream.extend_from_slice(&b2);

        // LF-only header block
        stream.extend_from_slice(
            format!(
                "\nContent-Type: application/json\nContent-Length: {}\n\n",
                b3.len()
            )
            .as_bytes(),
        );
        stream.extend_from_slice(&b3);

        // Identical duplicate Content-Length
        stream.extend_from_slice(
            format!(
                "Content-Length: {}\r\nContent-Length: {}\r\n\r\n",
                b4.len(),
                b4.len()
            )
            .as_bytes(),
        );
        stream.extend_from_slice(&b4);

        let mut out_bytes = Vec::new();
        serve_mcp_io(
            std::io::Cursor::new(stream),
            &mut out_bytes,
            ro_opts.clone(),
        )
        .await
        .unwrap();

        let mut resp_reader = McpFrameReader::new(std::io::Cursor::new(out_bytes));
        let mut seen_ids = Vec::new();
        while let Some((val, mode)) = resp_reader.read_next_frame().await.unwrap() {
            assert_eq!(mode, FrameMode::ContentLength);
            assert!(val.get("error").is_none(), "unexpected error: {val}");
            seen_ids.push(val["id"].as_i64().unwrap());
        }
        seen_ids.sort_unstable();
        assert_eq!(seen_ids, vec![1, 2, 3, 4]);

        // 2. Header block missing `Content-Length` returns clean -32700 parse error with Content-Length framing.
        let missing_cl =
            b"Content-Type: application/vscode-jsonrpc; charset=utf-8\r\n\r\n{}".to_vec();
        let mut missing_out = Vec::new();
        serve_mcp_io(
            std::io::Cursor::new(missing_cl),
            &mut missing_out,
            ro_opts.clone(),
        )
        .await
        .unwrap();
        let missing_str = String::from_utf8(missing_out).unwrap();
        assert!(
            missing_str.starts_with("Content-Length: "),
            "missing Content-Length error must preserve Content-Length framing: {missing_str}"
        );
        assert!(missing_str.contains("-32700"));
        assert!(missing_str.contains("missing Content-Length"));

        // 3. Conflicting duplicate `Content-Length` returns clean -32700 parse error.
        let conflict_cl = b"Content-Length: 2\r\nContent-Length: 4\r\n\r\n{}".to_vec();
        let mut conflict_out = Vec::new();
        serve_mcp_io(
            std::io::Cursor::new(conflict_cl),
            &mut conflict_out,
            ro_opts.clone(),
        )
        .await
        .unwrap();
        let conflict_str = String::from_utf8(conflict_out).unwrap();
        assert!(conflict_str.starts_with("Content-Length: "));
        assert!(conflict_str.contains("-32700"));
        assert!(conflict_str.contains("conflicting duplicate Content-Length"));

        // 4. Signed / non-numeric / oversized `Content-Length` and truncated body on EOF all return clean errors.
        for bad_input in [
            b"Content-Length: +2\r\n\r\n{}".as_slice(),
            b"Content-Length: abc\r\n\r\n{}".as_slice(),
            b"Content-Length: 99999999\r\n\r\n".as_slice(),
            b"Content-Length: 20\r\n\r\n{\"partial\":".as_slice(),
        ] {
            let mut mode = FrameMode::NewlineJson;
            let mut buf = bad_input.to_vec();
            let err = try_parse_buffered_frame(&mut buf, &mut mode, true)
                .expect_err("expected malformed/truncated header frame to fail");
            assert_eq!(mode, FrameMode::ContentLength);
            assert!(
                !err.to_string().is_empty(),
                "error message must not be empty"
            );
        }

        // 5. Trailing NewlineJson without trailing `\n` at EOF still parses cleanly.
        let no_nl = b"{\"jsonrpc\":\"2.0\",\"id\":77,\"method\":\"ping\"}".to_vec();
        let mut no_nl_out = Vec::new();
        serve_mcp_io(std::io::Cursor::new(no_nl), &mut no_nl_out, ro_opts)
            .await
            .unwrap();
        let no_nl_val: Value =
            serde_json::from_str(String::from_utf8(no_nl_out).unwrap().trim()).unwrap();
        assert_eq!(no_nl_val["id"], 77);
        assert!(no_nl_val.get("result").is_some());
    }
}

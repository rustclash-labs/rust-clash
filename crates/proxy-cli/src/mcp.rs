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
    io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader},
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

pub fn resolve_controller_client(
    explicit_controller: Option<&str>,
    explicit_secret: Option<&str>,
    fallback_cfg: Option<&ClashConfig>,
) -> Option<ControllerClient> {
    let state_dir = proxy_core::platform::recovery::default_state_dir();
    resolve_controller_clients_in_state_dir(
        &state_dir,
        explicit_controller,
        explicit_secret,
        fallback_cfg,
    )
    .into_iter()
    .next()
}

enum LiveControllerOutcome {
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

async fn request_live_controller_json(
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

fn auth_rejected_note(status: u16) -> String {
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
            "description": "Return credential-redacted active proxy status, routing mode, effective outbound chain, selector group states, and privacy-filtered recent connection failure diagnostics.",
            "inputSchema": {
                "type": "object",
                "properties": {},
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
                    let diag_val = c
                        .request_json(
                            "GET",
                            "/connections/diagnostics?limit=15",
                            None,
                            Duration::from_secs(2),
                        )
                        .await
                        .ok()
                        .and_then(|(st, v)| (st == 200).then_some(v));

                    let mut groups_summary = Vec::new();
                    if let Some(map) = proxies_val.get("proxies").and_then(|v| v.as_object()) {
                        for (k, info) in map {
                            let ty = info.get("type").and_then(|v| v.as_str()).unwrap_or("");
                            if matches!(ty, "Selector" | "URLTest" | "Fallback") {
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

                    let mut recent_diags = diag_val
                        .and_then(|d| d.get("diagnostics").cloned())
                        .unwrap_or_else(|| json!([]));
                    scrub_diagnostic_entries(&mut recent_diags, opts.include_network_metadata);

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
                            "recent_failure_diagnostics": recent_diags,
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

async fn read_bounded_line<R: AsyncRead + Unpin>(
    reader: &mut BufReader<R>,
    buf: &mut String,
    max_bytes: usize,
) -> Result<usize> {
    buf.clear();
    let mut limited = (&mut *reader).take((max_bytes + 1) as u64);
    let n = limited.read_line(buf).await?;
    if n > max_bytes && !buf.ends_with('\n') {
        return Err(anyhow!(
            "MCP input line exceeds maximum allowed size ({max_bytes} bytes)"
        ));
    }
    Ok(n)
}

async fn read_next_mcp_frame<R: AsyncRead + Unpin>(
    reader: &mut BufReader<R>,
    last_mode: &mut FrameMode,
) -> Result<Option<(Value, FrameMode)>> {
    let mut line = String::new();
    loop {
        let n = read_bounded_line(reader, &mut line, MAX_MCP_LINE_BYTES).await?;
        if n == 0 {
            return Ok(None);
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        if let Some((hdr_name, hdr_val)) = trimmed.split_once(':')
            && hdr_name.trim().eq_ignore_ascii_case("content-length")
        {
            *last_mode = FrameMode::ContentLength;
            let content_len: usize = hdr_val
                .trim()
                .parse()
                .context("invalid Content-Length header in MCP stream")?;
            if content_len > MAX_MCP_FRAME_BYTES {
                return Err(anyhow!("MCP frame exceeds 8 MiB safety cap"));
            }
            // Consume remaining headers up to blank line with bounded header count and length.
            let mut header_count = 1usize;
            loop {
                let mut hdr = String::new();
                let hn = read_bounded_line(reader, &mut hdr, MAX_MCP_HEADER_LINE_BYTES).await?;
                if hn == 0 || hdr.trim().is_empty() {
                    break;
                }
                header_count += 1;
                if header_count > MAX_MCP_HEADER_LINES {
                    return Err(anyhow!(
                        "MCP frame exceeded maximum header count ({MAX_MCP_HEADER_LINES})"
                    ));
                }
            }
            let mut body = vec![0u8; content_len];
            reader.read_exact(&mut body).await?;
            let val: Value = serde_json::from_slice(&body)
                .context("invalid JSON in Content-Length MCP frame")?;
            return Ok(Some((val, FrameMode::ContentLength)));
        }

        *last_mode = FrameMode::NewlineJson;
        let val: Value = serde_json::from_str(trimmed).context("invalid JSON-RPC line on stdin")?;
        return Ok(Some((val, FrameMode::NewlineJson)));
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
    let mut reader = BufReader::new(input);
    let mut last_mode = FrameMode::NewlineJson;
    let (resp_tx, mut resp_rx) = tokio::sync::mpsc::unbounded_channel::<(Vec<u8>, FrameMode)>();
    let mut tasks = tokio::task::JoinSet::new();

    loop {
        tokio::select! {
            biased;
            Some((encoded, mode)) = resp_rx.recv() => {
                write_encoded_mcp_frame(&mut output, &encoded, mode).await?;
            }
            Some(_done) = tasks.join_next(), if !tasks.is_empty() => {}
            frame_res = read_next_mcp_frame(&mut reader, &mut last_mode) => {
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
                        write_mcp_frame(&mut output, &err_resp, last_mode).await?;
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
}

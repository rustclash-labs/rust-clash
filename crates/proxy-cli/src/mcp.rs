use std::{path::PathBuf, time::Duration};

use anyhow::{Context, Result, anyhow};
use proxy_core::{
    api::parse_explain_target,
    audit::audit_config,
    config::{
        ClashConfig,
        uri::{
            contains_endpoint_url_scheme, has_endpoint_url_scheme_prefix, redact_sensitive_text,
        },
    },
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

        let mut req_buf = req.into_bytes();
        if !body_bytes.is_empty() {
            req_buf.extend_from_slice(&body_bytes);
        }

        let io_fut = async {
            stream.write_all(&req_buf).await?;
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
    let mgr = proxy_core::profile::ProfileManager::open_or_init(state_dir)
        .context("failed to initialize active profile state (raw details redacted)")?;
    let active_path = mgr.active_profile_path();
    let (cfg, active_path) = mgr
        .load_active_config()
        .with_context(|| sanitize_active_profile_error(&active_path))?;
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

fn sanitize_active_profile_error(path: &std::path::Path) -> &'static str {
    match std::fs::metadata(path) {
        Err(_) => "failed to load active profile: file does not exist or is unreadable",
        Ok(meta) if !meta.file_type().is_file() => {
            "invalid active profile: target must be a regular '.yaml' or '.yml' file"
        }
        Ok(_) => {
            "failed to parse or validate active profile Clash YAML (syntax or schema error; raw file contents redacted)"
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
                '\'' | '"' | '`' | '(' | ')' | '{' | '}' | ',' | ';' | '.' | '<' | '>'
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
    let mut cur = raw.to_string();
    for marker in ["server '", "set to '"] {
        let mut next = String::with_capacity(cur.len());
        let mut cursor = 0usize;
        let mut changed = false;
        while let Some(rel_idx) = cur[cursor..].find(marker) {
            let val_start = cursor + rel_idx + marker.len();
            if let Some(end_rel) = cur[val_start..].find('\'') {
                let val_end = val_start + end_rel;
                next.push_str(&cur[cursor..val_start]);
                next.push_str("<redacted>");
                next.push('\'');
                cursor = val_end + 1;
                changed = true;
            } else {
                break;
            }
        }
        if changed {
            next.push_str(&cur[cursor..]);
            cur = next;
        }
    }
    cur
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
                    && let Some(sep_idx) = loc.rfind("] (")
                    && !loc.ends_with(']')
                {
                    let paren_idx = sep_idx + 1;
                    let raw_inner = &loc[paren_idx + 2..];
                    let inner = raw_inner.strip_suffix(')').unwrap_or(raw_inner);
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
    fn trim_punct(s: &str) -> &str {
        s.trim_matches(|c: char| {
            matches!(
                c,
                '(' | ')' | '{' | '}' | ',' | ';' | '\'' | '"' | '`' | '<' | '>' | '.' | '\\' | '!'
            )
        })
    }

    let is_domain_port = |s: &str| -> bool {
        let Some((raw_host, port)) = s.rsplit_once(':') else {
            return false;
        };
        if port.is_empty()
            || !port.bytes().all(|b| b.is_ascii_digit())
            || port.parse::<u16>().is_err()
        {
            return false;
        }
        let host = raw_host.strip_suffix('.').unwrap_or(raw_host);
        !host.is_empty()
            && host.contains('.')
            && !host.starts_with('.')
            && !host.starts_with('-')
            && !host.ends_with('-')
            && !host.contains("..")
            && host.bytes().any(|b| b.is_ascii_alphabetic())
            && host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_'))
    };

    let matches_endpoint_core = |s: &str| -> bool {
        if s.is_empty() {
            return false;
        }
        let check_atom = |atom: &str| -> bool {
            if atom.is_empty() {
                return false;
            }
            let head = atom.split(['/', '?', '#']).next().unwrap_or(atom);
            atom.parse::<std::net::SocketAddr>().is_ok()
                || atom.parse::<std::net::IpAddr>().is_ok()
                || head.parse::<std::net::SocketAddr>().is_ok()
                || head.parse::<std::net::IpAddr>().is_ok()
                || has_endpoint_url_scheme_prefix(atom)
                || is_domain_port(atom)
                || is_domain_port(head)
        };
        // Preserve `[...]` brackets on the first pass so bracketed IPv6 SocketAddrs such as
        // `[2001:db8::1]:443` and `[::1]:8080` parse cleanly via `SocketAddr::parse`.
        if check_atom(s) {
            return true;
        }
        if let Some(unwrapped) = s.strip_prefix('[').and_then(|t| t.strip_suffix(']'))
            && check_atom(unwrapped)
        {
            return true;
        }
        let inner = s.trim_matches(|c: char| matches!(c, '[' | ']'));
        inner != s && check_atom(inner)
    };

    let matches_endpoint = |raw: &str| -> bool {
        let outer = trim_punct(raw);
        if matches_endpoint_core(outer) {
            return true;
        }
        // Handle trailing colon (e.g. `10.20.30.40:443:`, `secret-node.corp:8443:`) without
        // disturbing valid IPv6 addresses ending in `::` (already matched above).
        if !outer.ends_with("::")
            && let Some(without_colon) = outer.strip_suffix(':')
            && matches_endpoint_core(trim_punct(without_colon))
        {
            return true;
        }
        // Handle arrow-suffixed tokens like `10.20.30.40->DIRECT` after splitting on `>`.
        if let Some(without_dash) = outer.strip_suffix('-')
            && matches_endpoint_core(trim_punct(without_dash))
        {
            return true;
        }
        false
    };

    let token_has_endpoint = |tok: &str| -> bool {
        if matches_endpoint(tok) || contains_endpoint_url_scheme(tok) {
            return true;
        }
        // Linearly inspect structural sub-tokens inside JSON / parenthesized / key=value /
        // comma-separated log tokens so embedded IP/host:port metadata cannot leak.
        for part in tok.split(|c: char| {
            matches!(
                c,
                '(' | ')' | '{' | '}' | ',' | ';' | '\'' | '"' | '`' | '<' | '>' | '=' | '\\'
            )
        }) {
            if part.is_empty() {
                continue;
            }
            if matches_endpoint(part) {
                return true;
            }
            if let Some((prefix, rest)) = part.split_once(':')
                && !prefix.is_empty()
                && prefix
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
                && matches_endpoint(rest)
            {
                return true;
            }
        }
        false
    };

    text.split_whitespace()
        .map(|tok| {
            if token_has_endpoint(tok) {
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

fn redact_json_value(value: &Value) -> Value {
    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) => value.clone(),
        Value::String(s) => Value::String(redact_sensitive_text(s)),
        Value::Array(items) => Value::Array(items.iter().map(redact_json_value).collect()),
        Value::Object(map) => {
            let entries: Vec<(String, &Value)> = map
                .iter()
                .map(|(k, v)| (redact_sensitive_text(k), v))
                .collect();
            let mut out = serde_json::Map::with_capacity(map.len());
            let mut reserved: Option<std::collections::HashSet<&str>> = None;
            let mut next_suffix: std::collections::HashMap<&str, usize> =
                std::collections::HashMap::new();
            for (base_key, v) in &entries {
                let key = if !out.contains_key(base_key.as_str()) {
                    base_key.clone()
                } else {
                    let reserved_set = reserved
                        .get_or_insert_with(|| entries.iter().map(|(k, _)| k.as_str()).collect());
                    let suffix = next_suffix.entry(base_key.as_str()).or_insert(2);
                    loop {
                        let candidate = format!("{base_key}#{}", *suffix);
                        *suffix += 1;
                        if !out.contains_key(&candidate)
                            && !reserved_set.contains(candidate.as_str())
                        {
                            break candidate;
                        }
                    }
                };
                out.insert(key, redact_json_value(v));
            }
            Value::Object(out)
        }
    }
}

fn mcp_tool_result(payload: &Value, is_error: bool) -> Value {
    let redacted = redact_json_value(payload);
    let scrubbed = serde_json::to_string_pretty(&redacted).unwrap_or_else(|_| "{}".to_string());
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
                "message": format!("Method not found: {}", redact_sensitive_text(method))
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
        let f10_parsed: Value = serde_json::from_str(f10_text)
            .expect("audit_config_security output must be valid JSON");
        assert_eq!(f10_parsed["controller"], "<redacted>");
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
        let audit_parsed: Value = serde_json::from_str(audit_text)
            .expect("audit_config_security output must be valid JSON");
        assert_eq!(audit_parsed["controller"], "<redacted>");
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

    #[tokio::test]
    async fn mcp_audit_config_security_diff_with_doh_urls_produces_valid_redacted_json() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let tmp_root = std::env::temp_dir().join(format!(
            "rc-mcp-audit-doh-diff-{}-{nanos}",
            std::process::id()
        ));
        let state_dir = tmp_root.join("state");
        std::fs::create_dir_all(&state_dir).unwrap();

        let draft_yaml_path = tmp_root.join("draft.yaml");
        std::fs::write(
            &draft_yaml_path,
            r#"
mixed-port: 7890
external-controller: 127.0.0.1:9090
dns:
  enable: true
  nameserver:
    - https://user:secretpass@doh.example.com/dns-query?token=tok123
  direct-nameserver:
    - 127.0.0.1:5353
rules:
  - MATCH,DIRECT
"#,
        )
        .unwrap();

        let opts = McpServerOptions {
            config_path: None,
            controller: Some("127.0.0.1:1".to_string()),
            secret: None,
            allow_mutations: false,
            include_network_metadata: false,
        };

        let res = execute_tool_call_with_state_dir(
            "audit_config_security",
            &json!({ "config_path": draft_yaml_path.to_string_lossy() }),
            &opts,
            &state_dir,
        )
        .await;
        let _ = std::fs::remove_dir_all(&tmp_root);

        assert_eq!(res["isError"], false, "unexpected tool error: {res}");
        let text = res["content"][0]["text"]
            .as_str()
            .expect("content[0].text string");
        let parsed: Value = serde_json::from_str(text).unwrap_or_else(|err| {
            panic!("audit_config_security returned invalid JSON ({err}): {text}")
        });

        assert_eq!(parsed["diff"]["dns_changed"], true);
        let dns_changes = parsed["diff"]["dns_changes"]
            .as_array()
            .expect("diff.dns_changes must be an array");
        assert!(
            !dns_changes.is_empty(),
            "expected diff.dns_changes entries comparing starter DoH URLs to draft: {parsed}"
        );
        let joined_dns_changes = dns_changes
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            joined_dns_changes.contains("https://***REDACTED***"),
            "starter IP DoH URL should be redacted in diff.dns_changes: {joined_dns_changes}"
        );
        assert!(
            joined_dns_changes.contains("https://doh.example.com/***REDACTED***"),
            "draft authenticated DoH URL should be host-preserved & path/creds redacted: {joined_dns_changes}"
        );

        for forbidden in [
            "secretpass",
            "tok123",
            "user:secretpass",
            "223.5.5.5/dns-query",
            "1.12.12.12/dns-query",
        ] {
            assert!(
                !text.contains(forbidden),
                "audit_config_security leaked '{forbidden}': {text}"
            );
        }
    }

    #[test]
    fn mcp_tool_result_preserves_valid_json_for_escaped_quotes_urls_kv_and_serde_string_markers() {
        let mut dynamic_map = serde_json::Map::new();
        dynamic_map.insert(
            "vless://11111111-1111-4111-8111-111111111111@secret-a.example:443?pbk=PUB_KEY_A#n1"
                .to_string(),
            json!("first_entry"),
        );
        dynamic_map.insert(
            "vless://22222222-2222-4222-8222-222222222222@secret-b.example:443?pbk=PUB_KEY_B#n2"
                .to_string(),
            json!("second_entry"),
        );
        dynamic_map.insert(
            "vless://33333333-3333-4333-8333-333333333333@secret-c.example:443?pbk=PUB_KEY_C#n3"
                .to_string(),
            json!("third_entry"),
        );

        let mut uuid_collision_map = serde_json::Map::new();
        uuid_collision_map.insert(
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_string(),
            json!("uuid_one"),
        );
        uuid_collision_map.insert(
            "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb".to_string(),
            json!("uuid_two"),
        );
        uuid_collision_map.insert("***REDACTED***#2".to_string(), json!("literal_reserved"));

        let payload = json!({
            "dns_debug": "dns.nameserver: [\"https://223.5.5.5/dns-query\", \"1.1.1.1:53\"]",
            "vless_debug": "node [\"vless://12345678-1234-4321-abcd-998877665544@edge.secret.example:443?pbk=REALITY_PBK_99#tag\"]",
            "kv_quote": "err key=TOP_SECRET_KV\" trailing",
            "pq_quote": "pq \"mlkem768x25519plus.native.0rtt.SECRET_PQ_TOKEN\" done",
            "hint": "expected string ",
            "next_after_hint": "must_survive_intact",
            "serde_err": "invalid type: string \"secret_val\", expected u16",
            "unclosed_backtick": "unterminated string `foo",
            "later_backtick": "pass `config_path` instead",
            "dynamic_map": Value::Object(dynamic_map),
            "uuid_collision_map": Value::Object(uuid_collision_map),
            "primitives": [null, true, 42, "plain_ok"]
        });

        let tool_res = mcp_tool_result(&payload, false);
        assert_eq!(tool_res["isError"], false);
        let raw_text = tool_res["content"][0]["text"]
            .as_str()
            .expect("content[0].text string");

        let parsed: Value = serde_json::from_str(raw_text).unwrap_or_else(|err| {
            panic!("mcp_tool_result emitted invalid JSON ({err}): {raw_text}")
        });

        assert_eq!(
            parsed["dns_debug"],
            "dns.nameserver: [\"https://***REDACTED***\", \"1.1.1.1:53\"]"
        );
        assert_eq!(parsed["vless_debug"], "node [\"vless://***REDACTED***\"]");
        assert_eq!(parsed["kv_quote"], "err key=***REDACTED***\" trailing");
        assert_eq!(
            parsed["pq_quote"],
            "pq \"mlkem768x25519plus.***REDACTED***\" done"
        );
        assert_eq!(parsed["hint"], "expected string ");
        assert_eq!(parsed["next_after_hint"], "must_survive_intact");
        assert_eq!(
            parsed["serde_err"],
            "invalid type: string \"***REDACTED***\", expected u16"
        );
        assert_eq!(parsed["unclosed_backtick"], "unterminated string `foo");
        assert_eq!(parsed["later_backtick"], "pass `config_path` instead");
        assert_eq!(parsed["primitives"], json!([null, true, 42, "plain_ok"]));

        let dyn_obj = parsed["dynamic_map"]
            .as_object()
            .expect("dynamic_map object");
        assert_eq!(
            dyn_obj.len(),
            3,
            "all colliding redacted keys must be preserved without overwriting: {dyn_obj:?}"
        );
        assert_eq!(
            dyn_obj.get("vless://***REDACTED***"),
            Some(&json!("first_entry"))
        );
        assert_eq!(
            dyn_obj.get("vless://***REDACTED***#2"),
            Some(&json!("second_entry"))
        );
        assert_eq!(
            dyn_obj.get("vless://***REDACTED***#3"),
            Some(&json!("third_entry"))
        );

        let uuid_obj = parsed["uuid_collision_map"]
            .as_object()
            .expect("uuid_collision_map object");
        assert_eq!(
            uuid_obj.len(),
            3,
            "colliding UUID keys must not overwrite pre-existing literal #2 key: {uuid_obj:?}"
        );
        assert_eq!(uuid_obj.get("***REDACTED***"), Some(&json!("uuid_one")));
        assert_eq!(uuid_obj.get("***REDACTED***#3"), Some(&json!("uuid_two")));
        assert_eq!(
            uuid_obj.get("***REDACTED***#2"),
            Some(&json!("literal_reserved"))
        );

        for secret in [
            "223.5.5.5/dns-query",
            "12345678-1234-4321-abcd-998877665544",
            "edge.secret.example",
            "REALITY_PBK_99",
            "TOP_SECRET_KV",
            "SECRET_PQ_TOKEN",
            "secret_val",
            "11111111-1111-4111-8111-111111111111",
            "22222222-2222-4222-8222-222222222222",
            "33333333-3333-4333-8333-333333333333",
            "secret-a.example",
            "secret-b.example",
            "secret-c.example",
            "PUB_KEY_A",
            "PUB_KEY_B",
            "PUB_KEY_C",
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        ] {
            assert!(
                !raw_text.contains(secret),
                "mcp_tool_result leaked secret '{secret}': {raw_text}"
            );
        }
    }

    #[tokio::test]
    async fn mcp_unknown_method_error_redacts_sensitive_uri() {
        let ro_opts = McpServerOptions {
            config_path: None,
            controller: Some("127.0.0.1:1".to_string()),
            secret: None,
            allow_mutations: false,
            include_network_metadata: false,
        };

        let resp = handle_mcp_request(
            &json!({
                "jsonrpc": "2.0",
                "id": 6,
                "method": "vless://55555555-6666-4777-8888-999999999999@method-secret.example:443?pbk=METHOD_PBK_SEC#m"
            }),
            &ro_opts,
        )
        .await
        .expect("unknown method returns JSON-RPC error response");

        assert_eq!(resp["id"], 6);
        assert_eq!(resp["error"]["code"], -32601);
        let msg = resp["error"]["message"]
            .as_str()
            .expect("error.message string");
        assert!(
            msg.starts_with("Method not found: "),
            "unexpected -32601 message prefix: {msg}"
        );
        assert!(
            msg.contains("vless://***REDACTED***"),
            "expected redacted vless URI in -32601 error message: {msg}"
        );

        let serialized = serde_json::to_string(&resp).unwrap();
        for secret in [
            "55555555-6666-4777-8888-999999999999",
            "method-secret.example",
            "METHOD_PBK_SEC",
        ] {
            assert!(
                !serialized.contains(secret),
                "-32601 error leaked secret '{secret}': {serialized}"
            );
        }
    }

    #[test]
    fn scrub_audit_payload_preserves_parenthetical_proxy_names_and_handles_edge_cases() {
        let mut payload = json!({
            "audit": {
                "findings": [
                    {
                        "code": "SEC-PLAINTEXT-NODE",
                        "location": "proxies[My Node (Premium HK)] (198.51.100.19:1080)",
                        "detail": "Node 'My Node (Premium HK)' (socks5) targets non-loopback server '198.51.100.19:1080' and raw 198.51.100.19:1080 without TLS."
                    },
                    {
                        "code": "SEC-PLAINTEXT-NODE",
                        "location": "proxies[Edge (US West)] (edge.secret.internal:1080)",
                        "detail": "Node 'Edge (US West)' (socks5) connects directly to edge.secret.internal:1080 without TLS."
                    },
                    {
                        "code": "SEC-CUSTOM-NO-ENDPOINT",
                        "location": "proxies[My Node (Premium HK)]",
                        "detail": "Node 'My Node (Premium HK)' has a config warning."
                    },
                    {
                        "code": "SEC-CUSTOM-UNCLOSED-NAME",
                        "location": "proxies[My Node (unclosed]",
                        "detail": "Node 'My Node (unclosed' has a config warning."
                    },
                    {
                        "code": "SEC-CUSTOM-TRUNCATED-ENDPOINT",
                        "location": "proxies[My Node (Premium HK)] (198.51.100.20:1080",
                        "detail": "Node 'My Node (Premium HK)' targets 198.51.100.20:1080 without TLS."
                    },
                    {
                        "code": "SEC-CUSTOM-BRACKET-IN-NAME",
                        "location": "proxies[a] (b]",
                        "detail": "Node 'a] (b' has a config warning."
                    }
                ]
            }
        });

        scrub_audit_payload(&mut payload, false);
        let findings = payload["audit"]["findings"].as_array().unwrap();

        // 1. Parenthetical proxy name + IP endpoint
        assert_eq!(
            findings[0]["location"],
            "proxies[My Node (Premium HK)] ([endpoint-redacted])"
        );
        let d0 = findings[0]["detail"].as_str().unwrap();
        assert!(
            d0.contains("My Node (Premium HK)"),
            "proxy name must be preserved in detail: {d0}"
        );
        assert!(
            !d0.contains("198.51.100.19"),
            "endpoint IP must be redacted in detail: {d0}"
        );

        // 2. Parenthetical proxy name + hostname endpoint (unquoted in detail)
        assert_eq!(
            findings[1]["location"],
            "proxies[Edge (US West)] ([endpoint-redacted])"
        );
        let d1 = findings[1]["detail"].as_str().unwrap();
        assert!(
            d1.contains("Edge (US West)"),
            "proxy name must be preserved in detail: {d1}"
        );
        assert!(
            !d1.contains("edge.secret.internal"),
            "extracted hostname endpoint needle must be redacted in detail: {d1}"
        );

        // 3. Parenthetical proxy name without trailing endpoint
        assert_eq!(findings[2]["location"], "proxies[My Node (Premium HK)]");
        assert_eq!(
            findings[2]["detail"],
            "Node 'My Node (Premium HK)' has a config warning."
        );

        // 4. Unclosed paren inside proxy name without trailing endpoint
        assert_eq!(findings[3]["location"], "proxies[My Node (unclosed]");
        assert_eq!(
            findings[3]["detail"],
            "Node 'My Node (unclosed' has a config warning."
        );

        // 5. Truncated endpoint missing trailing ')' fails closed while preserving proxy name
        assert_eq!(
            findings[4]["location"],
            "proxies[My Node (Premium HK)] ([endpoint-redacted])"
        );
        let d4 = findings[4]["detail"].as_str().unwrap();
        assert!(
            d4.contains("My Node (Premium HK)"),
            "proxy name must be preserved in detail: {d4}"
        );
        assert!(
            !d4.contains("198.51.100.20"),
            "truncated endpoint IP must be redacted in detail: {d4}"
        );

        // 6. Proxy name containing `] (` with no endpoint stays untouched
        assert_eq!(findings[5]["location"], "proxies[a] (b]");
        assert_eq!(findings[5]["detail"], "Node 'a] (b' has a config warning.");
    }

    #[tokio::test]
    async fn mcp_audit_config_security_redacts_delimiter_bearing_authenticated_doh_urls() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let tmp_root = std::env::temp_dir().join(format!(
            "rc-mcp-audit-doh-delims-{}-{nanos}",
            std::process::id()
        ));
        let state_dir = tmp_root.join("state");
        std::fs::create_dir_all(&state_dir).unwrap();

        let draft_yaml_path = tmp_root.join("draft.yaml");
        std::fs::write(
            &draft_yaml_path,
            r#"
mixed-port: 7890
dns:
  enable: true
  nameserver:
    - 'https://user:p"QuotePassSecret@doh.example.com/dns-query?token=TokQuoteSecret'
    - "https://user:p'SQuotePassSecret@doh.example.com/dns-query?token=TokSQuoteSecret"
    - 'https://user:p)ParenPassSecret@doh.example.com/dns-query?token=TokParenSecret'
    - 'https://user:p,CommaPassSecret@doh.example.com/dns-query?token=TokCommaSecret'
    - 'https://user:p;SemiPassSecret@doh.example.com/dns-query?token=TokSemiSecret'
    - 'https://doh.example.com/dns-query?q="QuoteQuerySecret"&x=1'
    - 'https://doh.example.com/dns-query?q=a\BackslashQuerySecret&x=1'
rules:
  - MATCH,DIRECT
"#,
        )
        .unwrap();

        let opts = McpServerOptions {
            config_path: None,
            controller: Some("127.0.0.1:1".to_string()),
            secret: None,
            allow_mutations: false,
            include_network_metadata: false,
        };

        let res = execute_tool_call_with_state_dir(
            "audit_config_security",
            &json!({ "config_path": draft_yaml_path.to_string_lossy() }),
            &opts,
            &state_dir,
        )
        .await;
        let _ = std::fs::remove_dir_all(&tmp_root);

        assert_eq!(res["isError"], false, "unexpected tool error: {res}");
        let text = res["content"][0]["text"]
            .as_str()
            .expect("content[0].text string");
        let parsed: Value = serde_json::from_str(text).unwrap_or_else(|err| {
            panic!("audit_config_security returned invalid JSON ({err}): {text}")
        });

        assert_eq!(parsed["diff"]["dns_changed"], true);
        let dns_changes = parsed["diff"]["dns_changes"]
            .as_array()
            .expect("diff.dns_changes must be an array");
        assert!(
            !dns_changes.is_empty(),
            "expected diff.dns_changes comparing starter DoH URLs to draft: {parsed}"
        );

        for forbidden in [
            "QuotePassSecret",
            "SQuotePassSecret",
            "ParenPassSecret",
            "CommaPassSecret",
            "SemiPassSecret",
            "QuoteQuerySecret",
            "BackslashQuerySecret",
            "TokQuoteSecret",
            "TokSQuoteSecret",
            "TokParenSecret",
            "TokCommaSecret",
            "TokSemiSecret",
        ] {
            assert!(
                !text.contains(forbidden),
                "audit_config_security leaked secret '{forbidden}': {text}"
            );
        }
    }

    #[tokio::test]
    async fn mcp_audit_config_security_redacts_private_doh_dot_paths_and_tab_whatwg_urls_across_all_dns_lists()
     {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let tmp_root = std::env::temp_dir().join(format!(
            "rc-mcp-audit-b2-paths-{}-{nanos}",
            std::process::id()
        ));
        let state_dir = tmp_root.join("state");
        std::fs::create_dir_all(&state_dir).unwrap();

        let draft_yaml_path = tmp_root.join("draft.yaml");
        std::fs::write(
            &draft_yaml_path,
            r#"
mixed-port: 7890
dns:
  enable: true
  default-nameserver:
    - 223.5.5.5
  nameserver:
    - "https://dns.nextdns.io/a1b2c3/Alice's MacBook (Work)"
    - "https://dns.nextdns.io/NextDnsProfileSecret99/MyPrivateDevice"
    - "https://d.adguard-dns.com/dns-query/AdGuardClientSecret88"
    - 'https://doh.corp.example/dns-query/tok"QuotePathSecret'
    - 'https://doh.corp.example/dns-query/tok)ParenPathSecret'
    - 'https://doh.corp.example/dns-query/tok,CommaPathSecret'
    - 'https://doh.corp.example/dns-query/tok;SemiPathSecret'
    - 'https://doh.example.com/dns-query/tok PathSpaceSecret'
    - 'tls://dot.corp.example:853/DotSecretPathToken'
    - "https://\t/tabsecuser:8080\\tabsecpass@doh.example/dns-query"
    - "https://\t/tabquser:8080\\tabqpass@doh.example/dns-query?token=TabQTok"
    - https://cloudflare-dns.com/dns-query
    - https://dns.google/resolve
    - tls://1.1.1.1:853
  direct-nameserver:
    - "https://dns.nextdns.io/d4e5f6/Bob's Phone (Private)"
    - "https://d.adguard-dns.com/dns-query/DirectAdGuardSecret77"
  fallback:
    - 'https://doh.corp.example/dns-query/fb)FallbackPathSecret'
    - 'tls://dot-fb.corp.example:853/FallbackDotSecret66'
    - "https://\t/fbtabuser:8080\\fbtabpass@doh.example/dns-query"
  proxy-server-nameserver:
    - 'https://doh.corp.example/dns-query/pns;ProxyNsPathSecret'
    - "https://dns.nextdns.io/pns987/Carol's Tablet (Secret)"
    - 'tls://dot-pns.corp.example:853/ProxyNsDotSecret55'
rules:
  - MATCH,DIRECT
"#,
        )
        .unwrap();

        let mut outputs = Vec::new();
        for include_network_metadata in [false, true] {
            let opts = McpServerOptions {
                config_path: None,
                controller: Some("127.0.0.1:1".to_string()),
                secret: None,
                allow_mutations: false,
                include_network_metadata,
            };
            let res = execute_tool_call_with_state_dir(
                "audit_config_security",
                &json!({ "config_path": draft_yaml_path.to_string_lossy() }),
                &opts,
                &state_dir,
            )
            .await;
            outputs.push((include_network_metadata, res));
        }
        let _ = std::fs::remove_dir_all(&tmp_root);

        for (include_network_metadata, res) in outputs {
            assert_eq!(
                res["isError"], false,
                "unexpected tool error (include_network_metadata={include_network_metadata}): {res}"
            );
            let text = res["content"][0]["text"]
                .as_str()
                .expect("content[0].text string");
            let parsed: Value = serde_json::from_str(text).unwrap_or_else(|err| {
                panic!(
                    "audit_config_security returned invalid JSON (include_network_metadata={include_network_metadata}, {err}): {text}"
                )
            });

            assert_eq!(parsed["diff"]["dns_changed"], true);
            let dns_changes = parsed["diff"]["dns_changes"]
                .as_array()
                .expect("diff.dns_changes must be an array");
            let entries: Vec<&str> = dns_changes.iter().filter_map(Value::as_str).collect();
            for field_prefix in [
                "dns.nameserver:",
                "dns.direct-nameserver:",
                "dns.fallback:",
                "dns.proxy-server-nameserver:",
            ] {
                assert!(
                    entries.iter().any(|entry| entry.starts_with(field_prefix)),
                    "missing {field_prefix} in diff.dns_changes: {entries:?}"
                );
            }

            let joined_dns_changes = entries.join("\n");
            let diff_json = serde_json::to_string(&parsed["diff"]).unwrap();

            assert!(
                joined_dns_changes.contains("***REDACTED***"),
                "expected ***REDACTED*** marker in diff.dns_changes: {joined_dns_changes}"
            );
            assert!(
                joined_dns_changes.contains("***REDACTED_URL***"),
                "expected ***REDACTED_URL*** marker for space/tab URLs in diff.dns_changes: {joined_dns_changes}"
            );
            assert!(
                joined_dns_changes.contains("https://dns.nextdns.io/***REDACTED***"),
                "non-whitespace NextDNS URL should redact path while preserving host: {joined_dns_changes}"
            );
            assert!(
                joined_dns_changes.contains("https://d.adguard-dns.com/***REDACTED***"),
                "AdGuard Private DNS URL should redact client path while preserving host: {joined_dns_changes}"
            );
            assert!(
                joined_dns_changes.contains("https://doh.corp.example/***REDACTED***"),
                "delimiter-bearing DoH URLs should redact path while preserving host: {joined_dns_changes}"
            );
            assert!(
                joined_dns_changes.contains("tls://dot.corp.example:853/***REDACTED***")
                    || joined_dns_changes.contains("tls://***REDACTED***"),
                "DoT tls:// path URL should be redacted in diff.dns_changes: {joined_dns_changes}"
            );
            assert!(
                joined_dns_changes.contains("https://cloudflare-dns.com/dns-query")
                    || joined_dns_changes.contains("https://cloudflare-dns.com/***REDACTED***"),
                "clean Cloudflare DoH upstream should appear cleanly in diff.dns_changes: {joined_dns_changes}"
            );
            assert!(
                joined_dns_changes.contains("https://dns.google/resolve")
                    || joined_dns_changes.contains("https://dns.google/***REDACTED***"),
                "clean Google DoH upstream should appear cleanly in diff.dns_changes: {joined_dns_changes}"
            );
            assert!(
                joined_dns_changes.contains("tls://1.1.1.1:853")
                    || joined_dns_changes.contains("tls://***REDACTED***"),
                "clean public DoT upstream should appear cleanly in diff.dns_changes: {joined_dns_changes}"
            );

            for forbidden in [
                "a1b2c3",
                "Alice",
                "MacBook",
                "Work",
                "d4e5f6",
                "Bob",
                "Phone",
                "Private",
                "NextDnsProfileSecret99",
                "MyPrivateDevice",
                "AdGuardClientSecret88",
                "DirectAdGuardSecret77",
                "QuotePathSecret",
                "ParenPathSecret",
                "CommaPathSecret",
                "SemiPathSecret",
                "PathSpaceSecret",
                "DotSecretPathToken",
                "FallbackPathSecret",
                "FallbackDotSecret66",
                "ProxyNsPathSecret",
                "pns987",
                "Carol",
                "Tablet",
                "Secret",
                "ProxyNsDotSecret55",
                "tabsecuser",
                "tabsecpass",
                "tabquser",
                "tabqpass",
                "TabQTok",
                "fbtabuser",
                "fbtabpass",
            ] {
                assert!(
                    !diff_json.contains(forbidden),
                    "diff leaked secret substring '{forbidden}' (include_network_metadata={include_network_metadata}): {diff_json}"
                );
            }

            // Also verify none of the unique secret tokens appear anywhere in the entire MCP response.
            for forbidden in [
                "a1b2c3",
                "Alice",
                "MacBook",
                "(Work)",
                "d4e5f6",
                "Bob",
                "Phone",
                "(Private)",
                "NextDnsProfileSecret99",
                "MyPrivateDevice",
                "AdGuardClientSecret88",
                "DirectAdGuardSecret77",
                "QuotePathSecret",
                "ParenPathSecret",
                "CommaPathSecret",
                "SemiPathSecret",
                "PathSpaceSecret",
                "DotSecretPathToken",
                "FallbackPathSecret",
                "FallbackDotSecret66",
                "ProxyNsPathSecret",
                "pns987",
                "Carol",
                "Tablet",
                "(Secret)",
                "ProxyNsDotSecret55",
                "tabsecuser",
                "tabsecpass",
                "tabquser",
                "tabqpass",
                "TabQTok",
                "fbtabuser",
                "fbtabpass",
            ] {
                assert!(
                    !text.contains(forbidden),
                    "audit_config_security leaked secret '{forbidden}' (include_network_metadata={include_network_metadata}): {text}"
                );
            }
        }
    }

    #[tokio::test]
    async fn mcp_audit_config_security_detects_private_dns_path_token_rotation_and_preserves_clean_public_upstreams()
     {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let tmp_root = std::env::temp_dir().join(format!(
            "rc-mcp-audit-b2-rotate-{}-{nanos}",
            std::process::id()
        ));
        let state_dir = tmp_root.join("state");
        std::fs::create_dir_all(&state_dir).unwrap();

        // 1. Path-token-only rotation across all 4 DNS lists: active vs candidate differ ONLY in path tokens.
        let active_rot_path = tmp_root.join("active_rotate.yaml");
        let candidate_rot_path = tmp_root.join("candidate_rotate.yaml");
        std::fs::write(
            &active_rot_path,
            r#"
mixed-port: 7890
dns:
  enable: true
  default-nameserver:
    - 223.5.5.5
  nameserver:
    - "https://dns.nextdns.io/OldNextDnsTok111/OldDeviceAlpha"
    - "https://d.adguard-dns.com/dns-query/OldAdGuardTok111"
  direct-nameserver:
    - "https://dns.nextdns.io/OldDirTok333/Alice's MacBook (OfficeOld)"
  fallback:
    - 'tls://dot.corp.example:853/OldFallbackDotTok555'
  proxy-server-nameserver:
    - "https://d.adguard-dns.com/dns-query/OldProxyNsTok777"
rules:
  - MATCH,DIRECT
"#,
        )
        .unwrap();
        std::fs::write(
            &candidate_rot_path,
            r#"
mixed-port: 7890
dns:
  enable: true
  default-nameserver:
    - 223.5.5.5
  nameserver:
    - "https://dns.nextdns.io/NewNextDnsTok222/NewDeviceBeta"
    - "https://d.adguard-dns.com/dns-query/NewAdGuardTok222"
  direct-nameserver:
    - "https://dns.nextdns.io/NewDirTok444/Bob's Phone (HomeNew)"
  fallback:
    - 'tls://dot.corp.example:853/NewFallbackDotTok666'
  proxy-server-nameserver:
    - "https://d.adguard-dns.com/dns-query/NewProxyNsTok888"
rules:
  - MATCH,DIRECT
"#,
        )
        .unwrap();

        let rot_opts = McpServerOptions {
            config_path: Some(active_rot_path),
            controller: Some("127.0.0.1:1".to_string()),
            secret: None,
            allow_mutations: false,
            include_network_metadata: false,
        };
        let rot_res = execute_tool_call_with_state_dir(
            "audit_config_security",
            &json!({ "config_path": candidate_rot_path.to_string_lossy() }),
            &rot_opts,
            &state_dir,
        )
        .await;

        // 2. Clean public upstreams diff: verify Cloudflare DoH, Google DoH, and public DoT preserve valid JSON without fail-closed redaction.
        let active_clean_path = tmp_root.join("active_clean.yaml");
        let candidate_clean_path = tmp_root.join("candidate_clean.yaml");
        std::fs::write(
            &active_clean_path,
            r#"
mixed-port: 7890
dns:
  enable: true
  default-nameserver:
    - 223.5.5.5
  nameserver:
    - 1.1.1.1:53
rules:
  - MATCH,DIRECT
"#,
        )
        .unwrap();
        std::fs::write(
            &candidate_clean_path,
            r#"
mixed-port: 7890
dns:
  enable: true
  default-nameserver:
    - 223.5.5.5
  nameserver:
    - https://cloudflare-dns.com/dns-query
    - https://dns.google/resolve
    - tls://1.1.1.1:853
rules:
  - MATCH,DIRECT
"#,
        )
        .unwrap();

        let clean_opts = McpServerOptions {
            config_path: Some(active_clean_path),
            controller: Some("127.0.0.1:1".to_string()),
            secret: None,
            allow_mutations: false,
            include_network_metadata: false,
        };
        let clean_res = execute_tool_call_with_state_dir(
            "audit_config_security",
            &json!({ "config_path": candidate_clean_path.to_string_lossy() }),
            &clean_opts,
            &state_dir,
        )
        .await;
        let _ = std::fs::remove_dir_all(&tmp_root);

        // Assertions for (1) path-token-only rotation
        assert_eq!(
            rot_res["isError"], false,
            "unexpected tool error: {rot_res}"
        );
        let rot_text = rot_res["content"][0]["text"]
            .as_str()
            .expect("content[0].text string");
        let rot_parsed: Value = serde_json::from_str(rot_text).unwrap_or_else(|err| {
            panic!("path-token rotation returned invalid JSON ({err}): {rot_text}")
        });
        assert_eq!(
            rot_parsed["diff"]["dns_changed"], true,
            "path-token-only rotation must set dns_changed=true: {rot_parsed}"
        );
        let rot_entries: Vec<&str> = rot_parsed["diff"]["dns_changes"]
            .as_array()
            .expect("diff.dns_changes array")
            .iter()
            .filter_map(Value::as_str)
            .collect();
        for field_prefix in [
            "dns.nameserver:",
            "dns.direct-nameserver:",
            "dns.fallback:",
            "dns.proxy-server-nameserver:",
        ] {
            assert!(
                rot_entries.iter().any(|e| e.starts_with(field_prefix)),
                "path-token rotation must report {field_prefix} change: {rot_entries:?}"
            );
        }
        let rot_joined = rot_entries.join("\n");
        assert!(
            rot_joined.contains("https://dns.nextdns.io/***REDACTED***"),
            "rotated NextDNS URL should show host-preserved redaction: {rot_joined}"
        );
        assert!(
            rot_joined.contains("https://d.adguard-dns.com/***REDACTED***"),
            "rotated AdGuard URL should show host-preserved redaction: {rot_joined}"
        );
        assert!(
            rot_joined.contains("***REDACTED_URL***"),
            "rotated space-bearing NextDNS URL should fail closed to ***REDACTED_URL***: {rot_joined}"
        );
        assert!(
            rot_joined.contains("tls://dot.corp.example:853/***REDACTED***")
                || rot_joined.contains("tls://***REDACTED***"),
            "rotated DoT tls:// path URL should show redaction marker: {rot_joined}"
        );
        for forbidden in [
            "OldNextDnsTok111",
            "OldDeviceAlpha",
            "NewNextDnsTok222",
            "NewDeviceBeta",
            "OldAdGuardTok111",
            "NewAdGuardTok222",
            "OldDirTok333",
            "Alice",
            "MacBook",
            "OfficeOld",
            "NewDirTok444",
            "Bob",
            "Phone",
            "HomeNew",
            "OldFallbackDotTok555",
            "NewFallbackDotTok666",
            "OldProxyNsTok777",
            "NewProxyNsTok888",
        ] {
            assert!(
                !rot_text.contains(forbidden),
                "path-token rotation leaked secret '{forbidden}': {rot_text}"
            );
        }

        // Assertions for (2) clean public upstreams
        assert_eq!(
            clean_res["isError"], false,
            "unexpected tool error for clean public upstreams: {clean_res}"
        );
        let clean_text = clean_res["content"][0]["text"]
            .as_str()
            .expect("content[0].text string");
        let clean_parsed: Value = serde_json::from_str(clean_text).unwrap_or_else(|err| {
            panic!("clean public upstreams returned invalid JSON ({err}): {clean_text}")
        });
        assert_eq!(clean_parsed["diff"]["dns_changed"], true);
        let clean_joined = clean_parsed["diff"]["dns_changes"]
            .as_array()
            .expect("diff.dns_changes array")
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            clean_joined.contains("dns.nameserver:"),
            "expected dns.nameserver diff entry: {clean_joined}"
        );
        assert!(
            !clean_joined.contains("***REDACTED_URL***"),
            "clean public upstreams must not fail closed to ***REDACTED_URL***: {clean_joined}"
        );
        assert!(
            clean_joined.contains("https://cloudflare-dns.com/dns-query")
                || clean_joined.contains("https://cloudflare-dns.com/***REDACTED***"),
            "clean Cloudflare DoH upstream must remain intact: {clean_joined}"
        );
        assert!(
            clean_joined.contains("https://dns.google/resolve")
                || clean_joined.contains("https://dns.google/***REDACTED***"),
            "clean Google DoH upstream must remain intact: {clean_joined}"
        );
        assert!(
            clean_joined.contains("tls://1.1.1.1:853")
                || clean_joined.contains("tls://***REDACTED***"),
            "clean public DoT upstream must remain intact: {clean_joined}"
        );
    }

    #[test]
    fn mcp_tool_result_preserves_valid_json_for_redacted_doh_dot_dns_changes() {
        let mut payload = json!({
            "source": "file:draft.yaml",
            "controller": "127.0.0.1:9090",
            "audit": { "findings": [] },
            "diff": {
                "dns_changed": true,
                "dns_changes": [
                    "dns.nameserver: [\"1.1.1.1:53\"] -> [\"https://dns.nextdns.io/***REDACTED***\", \"https://d.adguard-dns.com/***REDACTED***\", \"tls://dot.corp.example:853/***REDACTED***\", \"***REDACTED_URL***\"]",
                    "dns.direct-nameserver: [] -> [\"https://cloudflare-dns.com/dns-query\", \"https://dns.google/resolve\", \"tls://1.1.1.1:853\"]"
                ]
            }
        });
        scrub_audit_payload(&mut payload, false);
        let tool_res = mcp_tool_result(&payload, false);
        assert_eq!(tool_res["isError"], false);

        let raw_text = tool_res["content"][0]["text"]
            .as_str()
            .expect("content[0].text string");
        let parsed: Value = serde_json::from_str(raw_text).unwrap_or_else(|err| {
            panic!("mcp_tool_result produced invalid JSON ({err}): {raw_text}")
        });
        let changes = parsed["diff"]["dns_changes"]
            .as_array()
            .expect("diff.dns_changes array");
        assert_eq!(changes.len(), 2);

        let ns = changes[0].as_str().unwrap();
        assert!(
            ns.contains("https://dns.nextdns.io/***REDACTED***"),
            "pre-redacted NextDNS entry must survive idempotently: {ns}"
        );
        assert!(
            ns.contains("https://d.adguard-dns.com/***REDACTED***"),
            "pre-redacted AdGuard entry must survive idempotently: {ns}"
        );
        assert!(
            ns.contains("tls://dot.corp.example:853/***REDACTED***")
                || ns.contains("tls://***REDACTED***"),
            "pre-redacted DoT entry must remain cleanly redacted: {ns}"
        );
        assert!(
            ns.contains("***REDACTED_URL***"),
            "fail-closed ***REDACTED_URL*** marker must survive intact: {ns}"
        );

        let direct_ns = changes[1].as_str().unwrap();
        assert!(
            !direct_ns.contains("***REDACTED_URL***"),
            "clean public upstreams must not turn into ***REDACTED_URL***: {direct_ns}"
        );
        assert!(
            direct_ns.contains("https://cloudflare-dns.com/dns-query")
                || direct_ns.contains("https://cloudflare-dns.com/***REDACTED***"),
            "Cloudflare DoH entry must survive cleanly: {direct_ns}"
        );
        assert!(
            direct_ns.contains("https://dns.google/resolve")
                || direct_ns.contains("https://dns.google/***REDACTED***"),
            "Google DoH entry must survive cleanly: {direct_ns}"
        );
        assert!(
            direct_ns.contains("tls://1.1.1.1:853") || direct_ns.contains("tls://***REDACTED***"),
            "public DoT entry must survive cleanly: {direct_ns}"
        );
    }

    #[test]
    fn mcp_b3_redact_network_tokens_in_log_redacts_dot_doq_doh3_case_insensitively() {
        let log_line = concat!(
            "dial tls://dotu:LogDotPass999@dot.corp.example:853/LogDotPath000 ",
            "TLS://dot-upper.corp.example:853/UpDotPath ",
            "quic://quicu:LogQuicPass888@doq.corp.example:853/LogQuicPath777 ",
            "QUIC://doq-upper.corp.example:853/UpQuicPath ",
            "h3://h3u:LogH3Pass666@h3.corp.example/LogH3Path555 ",
            "H3://h3-upper.corp.example/UpH3Path ",
            "doq://doqu:LogDoqPass444@doq2.corp.example:853/LogDoqPath333 ",
            "DOQ://doq2-upper.corp.example:853/UpDoqPath ",
            "(HTTP://plain.corp.example/PlainPath), ",
            "`HTTPS://doh.corp.example/dns-query/DohPath` ",
            "upstream=tls://kv.corp.example:853/KvDotPath ",
            "[tls://[2001:db8::1]:853/V6DotPath] ",
            "password=***REDACTED*** ok"
        );

        let redacted = redact_network_tokens_in_log(log_line);
        assert_eq!(
            redacted,
            concat!(
                "dial [redacted-endpoint] [redacted-endpoint] [redacted-endpoint] ",
                "[redacted-endpoint] [redacted-endpoint] [redacted-endpoint] ",
                "[redacted-endpoint] [redacted-endpoint] [redacted-endpoint] ",
                "[redacted-endpoint] [redacted-endpoint] [redacted-endpoint] ",
                "password=***REDACTED*** ok"
            )
        );

        for forbidden in [
            "dotu",
            "LogDotPass999",
            "dot.corp.example",
            "LogDotPath000",
            "dot-upper.corp.example",
            "UpDotPath",
            "quicu",
            "LogQuicPass888",
            "doq.corp.example",
            "LogQuicPath777",
            "doq-upper.corp.example",
            "UpQuicPath",
            "h3u",
            "LogH3Pass666",
            "h3.corp.example",
            "LogH3Path555",
            "h3-upper.corp.example",
            "UpH3Path",
            "doqu",
            "LogDoqPass444",
            "doq2.corp.example",
            "LogDoqPath333",
            "doq2-upper.corp.example",
            "UpDoqPath",
            "plain.corp.example",
            "PlainPath",
            "doh.corp.example",
            "DohPath",
            "kv.corp.example",
            "KvDotPath",
            "2001:db8::1",
            "V6DotPath",
            "853",
        ] {
            assert!(
                !redacted.contains(forbidden),
                "redact_network_tokens_in_log leaked '{forbidden}': {redacted}"
            );
        }

        // Verify `extract_recent_logs_filtered` in default redacted mode emits `[redacted-endpoint]`
        // with 0 host/port/credential/path leaks, and in full metadata mode still leaks 0 creds/paths.
        let logs_val = json!({
            "logs": [
                {
                    "timestamp_ms": 1,
                    "type": "warn",
                    "payload": "dot tls://dotu:LogDotPass999@dot.corp.example:853/LogDotPath000 quic quic://quicu:LogQuicPass888@doq.corp.example:853/LogQuicPath777 h3 h3://h3u:LogH3Pass666@h3.corp.example/LogH3Path555 doq doq://doqu:LogDoqPass444@doq2.corp.example:853/LogDoqPath333"
                }
            ]
        });

        let default_logs =
            extract_recent_logs_filtered(Some(&logs_val), LogFilterLevel::Warn, 10, false);
        let default_payload = default_logs[0]["payload"]
            .as_str()
            .expect("redacted log payload");
        assert!(
            default_payload.contains("[redacted-endpoint]"),
            "expected [redacted-endpoint] in default privacy mode: {default_payload}"
        );
        for forbidden in [
            "dotu",
            "LogDotPass999",
            "dot.corp.example",
            "LogDotPath000",
            "quicu",
            "LogQuicPass888",
            "doq.corp.example",
            "LogQuicPath777",
            "h3u",
            "LogH3Pass666",
            "h3.corp.example",
            "LogH3Path555",
            "doqu",
            "LogDoqPass444",
            "doq2.corp.example",
            "LogDoqPath333",
            "853",
        ] {
            assert!(
                !default_payload.contains(forbidden),
                "default get_recent_logs leaked '{forbidden}': {default_payload}"
            );
        }
    }

    #[tokio::test]
    async fn mcp_b3_redacts_dot_doq_doh3_across_methods_tools_controller_and_rule_linter() {
        let ro_opts = McpServerOptions {
            config_path: None,
            controller: Some("127.0.0.1:1".to_string()),
            secret: None,
            allow_mutations: false,
            include_network_metadata: false,
        };

        // 1. `-32601` unknown `method` across `tls://`, `quic://`, `h3://`, `doq://` (and uppercase)
        let method_cases: &[(&str, &[&str])] = &[
            (
                "tls://dotuser:DotPassSecret99@dot.corp.example:853/DotPathSecret88",
                &["dotuser", "DotPassSecret99", "DotPathSecret88"],
            ),
            (
                "TLS://updotuser:UpDotPassSecret99@dot.corp.example:853/UpDotPathSecret88",
                &["updotuser", "UpDotPassSecret99", "UpDotPathSecret88"],
            ),
            (
                "quic://quicuser:QuicPassSecret77@doq.corp.example:853/QuicPathSecret66",
                &["quicuser", "QuicPassSecret77", "QuicPathSecret66"],
            ),
            (
                "h3://h3user:H3PassSecret55@h3.corp.example/H3PathSecret44",
                &["h3user", "H3PassSecret55", "H3PathSecret44"],
            ),
            (
                "doq://doquser:DoqPassSecret33@doq.corp.example:853/DoqPathSecret22",
                &["doquser", "DoqPassSecret33", "DoqPathSecret22"],
            ),
        ];

        for (idx, (method, secrets)) in method_cases.iter().enumerate() {
            let resp = handle_mcp_request(
                &json!({
                    "jsonrpc": "2.0",
                    "id": 300 + idx,
                    "method": method
                }),
                &ro_opts,
            )
            .await
            .expect("unknown method returns JSON-RPC error");
            assert_eq!(resp["error"]["code"], -32601);
            let serialized = serde_json::to_string(&resp).unwrap();
            let msg = resp["error"]["message"].as_str().unwrap();
            assert!(
                msg.contains("***REDACTED***") || msg.contains("***REDACTED_URL***"),
                "expected redaction marker in -32601 error for '{method}': {msg}"
            );
            for secret in *secrets {
                assert!(
                    !serialized.contains(secret),
                    "-32601 error leaked '{secret}' for '{method}': {serialized}"
                );
            }
        }

        // 2. `mcp_tool_result` controller payload redaction
        let controller_payload = json!({
            "status_note": "tls://dotu:CtrlDotPass444@dot.corp.example:853/CtrlDotPath555",
            "probe_note": "fail quic://quicu:ProbeQuicPass@doq.corp:853/ProbeQuicPath",
            "rule_payload": "h3://h3u:ExplainH3Pass@h3.corp/ExplainH3Path",
            "put_error": "PUT fail doq://doqu:PutDoqPass@doq.corp:853/PutDoqPath",
            "audit": {
                "raw": "ERR tls://u:RawAuditDotPass@dot.corp:853/RawAuditDotPath"
            }
        });
        let tool_res = mcp_tool_result(&controller_payload, false);
        assert_eq!(tool_res["isError"], false);
        let tool_text = tool_res["content"][0]["text"].as_str().unwrap();
        let parsed_tool: Value = serde_json::from_str(tool_text)
            .unwrap_or_else(|e| panic!("mcp_tool_result emitted invalid JSON ({e}): {tool_text}"));
        assert!(parsed_tool.is_object());
        for secret in [
            "dotu",
            "CtrlDotPass444",
            "CtrlDotPath555",
            "quicu",
            "ProbeQuicPass",
            "ProbeQuicPath",
            "h3u",
            "ExplainH3Pass",
            "ExplainH3Path",
            "doqu",
            "PutDoqPass",
            "PutDoqPath",
            "RawAuditDotPass",
            "RawAuditDotPath",
        ] {
            assert!(
                !tool_text.contains(secret),
                "mcp_tool_result leaked '{secret}': {tool_text}"
            );
        }

        // 3. Unknown MCP tool name (`tools/call`)
        for (tool_name, secrets) in [
            (
                "tls://u:UnknownToolDotPass@dot.corp:853/UnknownToolDotPath",
                &["UnknownToolDotPass", "UnknownToolDotPath"][..],
            ),
            (
                "quic://u:UnknownToolQuicPass@doq.corp:853/UnknownToolQuicPath",
                &["UnknownToolQuicPass", "UnknownToolQuicPath"][..],
            ),
            (
                "h3://u:UnknownToolH3Pass@h3.corp/UnknownToolH3Path",
                &["UnknownToolH3Pass", "UnknownToolH3Path"][..],
            ),
            (
                "doq://u:UnknownToolDoqPass@doq.corp:853/UnknownToolDoqPath",
                &["UnknownToolDoqPass", "UnknownToolDoqPath"][..],
            ),
        ] {
            let resp = handle_mcp_request(
                &json!({
                    "jsonrpc": "2.0",
                    "id": 350,
                    "method": "tools/call",
                    "params": { "name": tool_name, "arguments": {} }
                }),
                &ro_opts,
            )
            .await
            .expect("unknown tool returns JSON-RPC result");
            assert_eq!(resp["result"]["isError"], true);
            let text = resp["result"]["content"][0]["text"].as_str().unwrap();
            let _: Value = serde_json::from_str(text)
                .unwrap_or_else(|e| panic!("unknown tool emitted invalid JSON ({e}): {text}"));
            for secret in secrets {
                assert!(
                    !text.contains(secret),
                    "unknown MCP tool leaked '{secret}': {text}"
                );
            }
        }

        // 4. `audit_config_security` rule-linter findings (`RULE-SHADOWED-DOMAIN` & `RULE-DEAD-AFTER-MATCH`)
        //    plus clean `tls://1.1.1.1:853` preserved in `diff.dns_changes`.
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let tmp_root =
            std::env::temp_dir().join(format!("rc-mcp-b3-rules-{}-{nanos}", std::process::id()));
        let state_dir = tmp_root.join("state");
        std::fs::create_dir_all(&state_dir).unwrap();

        let base_yaml_path = tmp_root.join("base.yaml");
        let candidate_yaml_path = tmp_root.join("candidate.yaml");
        std::fs::write(
            &base_yaml_path,
            r#"
mixed-port: 7890
dns:
  enable: true
  default-nameserver:
    - 223.5.5.5
  nameserver:
    - 1.1.1.1:53
rules:
  - MATCH,DIRECT
"#,
        )
        .unwrap();
        std::fs::write(
            &candidate_yaml_path,
            r#"
mixed-port: 7890
dns:
  enable: true
  default-nameserver:
    - 223.5.5.5
  nameserver:
    - tls://1.1.1.1:853
    - tls://dns.quad9.net:853
rules:
  - DOMAIN-KEYWORD,corp,DIRECT
  - DOMAIN-KEYWORD,tls://u:ShadowDotPass@dot.corp:853/ShadowDotPath,DIRECT
  - DOMAIN-KEYWORD,quic://u:ShadowQuicPass@doq.corp:853/ShadowQuicPath,DIRECT
  - DOMAIN-KEYWORD,h3://u:ShadowH3Pass@h3.corp/ShadowH3Path,DIRECT
  - DOMAIN-KEYWORD,doq://u:ShadowDoqPass@doq.corp:853/ShadowDoqPath,DIRECT
  - MATCH,DIRECT
  - DOMAIN-KEYWORD,tls://u:DeadDotPass@dot.corp:853/DeadDotPath,DIRECT
"#,
        )
        .unwrap();

        let audit_opts = McpServerOptions {
            config_path: Some(base_yaml_path),
            controller: Some("127.0.0.1:1".to_string()),
            secret: None,
            allow_mutations: false,
            include_network_metadata: false,
        };
        let audit_res = execute_tool_call_with_state_dir(
            "audit_config_security",
            &json!({ "config_path": candidate_yaml_path.to_string_lossy() }),
            &audit_opts,
            &state_dir,
        )
        .await;
        let _ = std::fs::remove_dir_all(&tmp_root);

        assert_eq!(audit_res["isError"], false, "unexpected error: {audit_res}");
        let audit_text = audit_res["content"][0]["text"].as_str().unwrap();
        let audit_parsed: Value = serde_json::from_str(audit_text)
            .unwrap_or_else(|e| panic!("audit_config_security invalid JSON ({e}): {audit_text}"));
        let findings = audit_parsed["audit"]["findings"]
            .as_array()
            .expect("audit.findings array");
        assert!(
            findings.iter().any(|f| f["code"] == "RULE-SHADOWED-DOMAIN"),
            "expected RULE-SHADOWED-DOMAIN finding: {findings:?}"
        );
        assert!(
            findings
                .iter()
                .any(|f| f["code"] == "RULE-DEAD-AFTER-MATCH"),
            "expected RULE-DEAD-AFTER-MATCH finding: {findings:?}"
        );

        let audit_lower = audit_text.to_ascii_lowercase();
        for secret in [
            "ShadowDotPass",
            "ShadowDotPath",
            "ShadowQuicPass",
            "ShadowQuicPath",
            "ShadowH3Pass",
            "ShadowH3Path",
            "ShadowDoqPass",
            "ShadowDoqPath",
            "DeadDotPass",
            "DeadDotPath",
        ] {
            assert!(
                !audit_text.contains(secret) && !audit_lower.contains(&secret.to_ascii_lowercase()),
                "audit_config_security rule linter leaked '{secret}': {audit_text}"
            );
        }

        assert_eq!(audit_parsed["diff"]["dns_changed"], true);
        let dns_changes = audit_parsed["diff"]["dns_changes"]
            .as_array()
            .expect("diff.dns_changes array")
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            !dns_changes.contains("***REDACTED_URL***"),
            "clean public DoT upstreams must not fail closed to ***REDACTED_URL***: {dns_changes}"
        );
        assert!(
            dns_changes.contains("tls://1.1.1.1:853")
                || dns_changes.contains("tls://***REDACTED***"),
            "clean tls://1.1.1.1:853 must remain intact in diff.dns_changes: {dns_changes}"
        );
        assert!(
            dns_changes.contains("tls://dns.quad9.net:853")
                || dns_changes.contains("tls://***REDACTED***"),
            "clean tls://dns.quad9.net:853 must remain intact in diff.dns_changes: {dns_changes}"
        );

        // 5. Full-metadata `extract_recent_logs_filtered` must still redact credentials/paths on
        //    `tls://`, `quic://`, `h3://`, `doq://` via `redact_sensitive_text`.
        let logs_val = json!({
            "logs": [
                {
                    "timestamp_ms": 1,
                    "type": "warn",
                    "payload": "dot tls://dotu:LogDotPass999@dot.corp.example:853/LogDotPath000 quic quic://quicu:LogQuicPass888@doq.corp.example:853/LogQuicPath777 h3 h3://h3u:LogH3Pass666@h3.corp.example/LogH3Path555 doq doq://doqu:LogDoqPass444@doq2.corp.example:853/LogDoqPath333"
                }
            ]
        });
        let full_logs =
            extract_recent_logs_filtered(Some(&logs_val), LogFilterLevel::Warn, 10, true);
        let full_payload = full_logs[0]["payload"].as_str().expect("full log payload");
        for secret in [
            "dotu",
            "LogDotPass999",
            "LogDotPath000",
            "quicu",
            "LogQuicPass888",
            "LogQuicPath777",
            "h3u",
            "LogH3Pass666",
            "LogH3Path555",
            "doqu",
            "LogDoqPass444",
            "LogDoqPath333",
        ] {
            assert!(
                !full_payload.contains(secret),
                "full-metadata get_recent_logs leaked credential/path '{secret}': {full_payload}"
            );
        }
    }

    #[tokio::test]
    async fn mcp_b4_redacts_mid_authority_and_scheme_whatwg_tabs_and_tabbed_proxy_uris() {
        let ro_opts = McpServerOptions {
            config_path: None,
            controller: Some("127.0.0.1:1".to_string()),
            secret: None,
            allow_mutations: false,
            include_network_metadata: false,
        };

        let cases: &[(&str, &[&str])] = &[
            (
                "https://u\tser:8080\\InnerTabPass@doh.example/dns-query",
                &["InnerTabPass"],
            ),
            (
                "https://user\t:TabColonPass@doh.example/dns-query",
                &["TabColonPass"],
            ),
            (
                "https://user:8080\t\\TabBsPass@doh.example/dns-query",
                &["TabBsPass"],
            ),
            (
                "https://\t/u\tser:8080\\DoubleTabPass@doh.example/dns-query",
                &["DoubleTabPass"],
            ),
            (
                "https://user\r:CrColonPass@doh.example/dns-query",
                &["CrColonPass"],
            ),
            (
                "https://user\n:LfColonPass@doh.example/dns-query",
                &["LfColonPass"],
            ),
            (
                "https://dns.nextdns.io/a1b2c3\t/TabNextDnsDevice",
                &["a1b2c3", "TabNextDnsDevice"],
            ),
            (
                "https:\t//user:8080\\SchemeTabPass@doh.example/dns-query",
                &["SchemeTabPass"],
            ),
            (
                "http:\t//user:HttpSchemeTabPass@doh.example/dns-query",
                &["HttpSchemeTabPass"],
            ),
            (
                "ss://\tYWVzLTI1Ni1nY206U2VjcmV0U3NQYXNz==",
                &["YWVzLTI1Ni1nY206U2VjcmV0U3NQYXNz"],
            ),
            (
                "vmess://\teyJhZGQiOiIxLjIuMy40IiwiaWQiOiJWbWVzc1NlY3JldCJ9",
                &["eyJhZGQiOiIxLjIuMy40IiwiaWQiOiJWbWVzc1NlY3JldCJ9"],
            ),
        ];

        // 1. `-32601` unknown `method`
        for (idx, (method, secrets)) in cases.iter().enumerate() {
            let resp = handle_mcp_request(
                &json!({
                    "jsonrpc": "2.0",
                    "id": 400 + idx,
                    "method": method
                }),
                &ro_opts,
            )
            .await
            .expect("unknown method returns JSON-RPC error");
            assert_eq!(resp["error"]["code"], -32601);
            let serialized = serde_json::to_string(&resp).unwrap();
            for secret in *secrets {
                assert!(
                    !serialized.contains(secret),
                    "-32601 leaked B4 secret '{secret}' for '{method}': {serialized}"
                );
            }
        }

        // 2. `mcp_tool_result` (both values and object keys)
        let mut map = serde_json::Map::new();
        for (idx, (sample, _)) in cases.iter().enumerate() {
            map.insert(format!("val_{idx}"), json!(format!("note {sample} end")));
            map.insert((*sample).to_string(), json!(format!("key_{idx}")));
        }
        let tool_res = mcp_tool_result(&Value::Object(map), false);
        assert_eq!(tool_res["isError"], false);
        let text = tool_res["content"][0]["text"].as_str().unwrap();
        let parsed: Value = serde_json::from_str(text)
            .unwrap_or_else(|e| panic!("mcp_tool_result produced invalid JSON ({e}): {text}"));
        assert!(parsed.is_object());
        for (_, secrets) in cases {
            for secret in *secrets {
                assert!(
                    !text.contains(secret),
                    "mcp_tool_result leaked B4 secret '{secret}': {text}"
                );
            }
        }
    }

    #[tokio::test]
    async fn mcp_b5_active_profile_load_errors_are_sanitized_across_all_offline_tools() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let tmp_root = std::env::temp_dir().join(format!(
            "rc-mcp-b5-active-err-{}-{nanos}",
            std::process::id()
        ));
        let state_dir = tmp_root.join("state");
        std::fs::create_dir_all(&state_dir).unwrap();

        let mgr = proxy_core::profile::ProfileManager::open_or_init(&state_dir)
            .expect("initialize profile manager");
        let active_path = mgr.active_profile_path();

        let invalid_cases: &[(&str, &str, &[&str])] = &[
            (
                "default-ns-delim-doh",
                r#"
mixed-port: 7890
dns:
  enable: true
  default-nameserver:
    - 'https://u:p)BootParenPass@doh.example/dns-query'
  nameserver:
    - 1.1.1.1:53
rules:
  - MATCH,DIRECT
"#,
                &["BootParenPass", "doh.example"],
            ),
            (
                "default-ns-nextdns-space-tail",
                r#"
mixed-port: 7890
dns:
  enable: true
  default-nameserver:
    - "https://dns.nextdns.io/ActiveNextDnsId/Alice's MacBook (Work)"
  nameserver:
    - 1.1.1.1:53
rules:
  - MATCH,DIRECT
"#,
                &["ActiveNextDnsId", "Alice", "MacBook", "Work"],
            ),
            (
                "default-ns-tls-creds",
                r#"
mixed-port: 7890
dns:
  enable: true
  default-nameserver:
    - 'tls://dotuser:BootDotPass@dot.corp.example:853/BootDotPath'
  nameserver:
    - 1.1.1.1:53
rules:
  - MATCH,DIRECT
"#,
                &["dotuser", "BootDotPass", "BootDotPath", "dot.corp.example"],
            ),
            (
                "default-ns-mid-tab",
                "mixed-port: 7890\ndns:\n  enable: true\n  default-nameserver:\n    - \"https://u\\tser:8080\\\\BootInnerTabPass@doh.example/dns-query\"\n  nameserver:\n    - 1.1.1.1:53\nrules:\n  - MATCH,DIRECT\n",
                &["BootInnerTabPass", "doh.example"],
            ),
            (
                "nameserver-delim-doh",
                r#"
mixed-port: 7890
dns:
  enable: true
  nameserver:
    - 'https://doh.corp.example:99999/tok)ActiveParenErrPass'
rules:
  - MATCH,DIRECT
"#,
                &["ActiveParenErrPass", "doh.corp.example"],
            ),
            (
                "nameserver-space-doh",
                r#"
mixed-port: 7890
dns:
  enable: true
  nameserver:
    - 'https://doh.corp.example:99999/tok ActiveSpaceErrPass'
rules:
  - MATCH,DIRECT
"#,
                &["ActiveSpaceErrPass", "doh.corp.example"],
            ),
            (
                "nameserver-tls-bad-port",
                r#"
mixed-port: 7890
dns:
  enable: true
  nameserver:
    - 'tls://dotuser:ActiveDotErrPass@dot.corp.example:99999/ActiveDotErrPath'
rules:
  - MATCH,DIRECT
"#,
                &[
                    "dotuser",
                    "ActiveDotErrPass",
                    "ActiveDotErrPath",
                    "dot.corp.example",
                ],
            ),
            (
                "nameserver-quic-creds",
                r#"
mixed-port: 7890
dns:
  enable: true
  nameserver:
    - 'quic://quicuser:ActiveQuicErrPass@doq.corp.example:853/ActiveQuicErrPath'
rules:
  - MATCH,DIRECT
"#,
                &[
                    "quicuser",
                    "ActiveQuicErrPass",
                    "ActiveQuicErrPath",
                    "doq.corp.example",
                ],
            ),
            (
                "nameserver-mid-tab-bad-port",
                "mixed-port: 7890\ndns:\n  enable: true\n  nameserver:\n    - \"https://u\\tser:ActiveTabErrPass@doh.example:99999/dns-query\"\nrules:\n  - MATCH,DIRECT\n",
                &["ActiveTabErrPass", "doh.example"],
            ),
            (
                "raw-yaml-syntax-secret",
                "{ActiveRawYamlSecret999: [unclosed_yaml_secret_line\n",
                &["ActiveRawYamlSecret999", "unclosed_yaml_secret_line"],
            ),
        ];

        let mut results = Vec::new();
        for (label, yaml, secrets) in invalid_cases {
            std::fs::write(&active_path, yaml).unwrap();
            for include_network_metadata in [false, true] {
                let opts = McpServerOptions {
                    config_path: None,
                    controller: Some("127.0.0.1:1".to_string()),
                    secret: None,
                    allow_mutations: false,
                    include_network_metadata,
                };
                for (tool, args) in [
                    ("audit_config_security", json!({})),
                    ("get_proxy_status", json!({})),
                    ("explain_route", json!({ "target": "example.com:443" })),
                ] {
                    let res =
                        execute_tool_call_with_state_dir(tool, &args, &opts, &state_dir).await;
                    results.push((*label, tool, include_network_metadata, *secrets, res));
                }
            }
        }

        // Also verify `ProfileManager::open_or_init` failures (e.g. non-directory state path)
        // never leak filesystem path segments or raw OS errors into MCP tool output.
        let bad_state_file = tmp_root.join("SecretStateDirPath999");
        std::fs::write(&bad_state_file, "not-a-directory").unwrap();
        let bad_state_opts = McpServerOptions {
            config_path: None,
            controller: Some("127.0.0.1:1".to_string()),
            secret: None,
            allow_mutations: false,
            include_network_metadata: false,
        };
        for (tool, args) in [
            ("audit_config_security", json!({})),
            ("get_proxy_status", json!({})),
            ("explain_route", json!({ "target": "example.com:443" })),
        ] {
            let res =
                execute_tool_call_with_state_dir(tool, &args, &bad_state_opts, &bad_state_file)
                    .await;
            results.push((
                "bad-state-dir-init",
                tool,
                false,
                &["SecretStateDirPath999"],
                res,
            ));
        }

        let _ = std::fs::remove_dir_all(&tmp_root);

        for (label, tool, include_network_metadata, secrets, res) in results {
            assert_eq!(
                res["isError"], true,
                "{label}/{tool} (include_network_metadata={include_network_metadata}) must return isError=true: {res}"
            );
            let text = res["content"][0]["text"]
                .as_str()
                .expect("content[0].text string");
            let parsed: Value = serde_json::from_str(text)
                .unwrap_or_else(|e| panic!("{label}/{tool} returned invalid JSON ({e}): {text}"));
            let err_msg = parsed["error"].as_str().unwrap_or("");
            assert!(
                err_msg.contains("active profile") && err_msg.contains("redacted"),
                "{label}/{tool} must emit sanitized active-profile load error, got: {err_msg}"
            );
            for secret in secrets {
                assert!(
                    !text.contains(secret),
                    "{label}/{tool} (include_network_metadata={include_network_metadata}) leaked '{secret}': {text}"
                );
            }
        }
    }

    #[tokio::test]
    async fn mcp_b5_audit_config_security_redacts_non_scheme_dns_fragments_and_bom() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let tmp_root =
            std::env::temp_dir().join(format!("rc-mcp-b5-dns-frag-{}-{nanos}", std::process::id()));
        let state_dir = tmp_root.join("state");
        std::fs::create_dir_all(&state_dir).unwrap();

        let draft_yaml_path = tmp_root.join("draft_frag.yaml");
        let yaml = format!(
            concat!(
                "mixed-port: 7890\n",
                "dns:\n",
                "  enable: true\n",
                "  default-nameserver:\n",
                "    - 223.5.5.5\n",
                "  nameserver:\n",
                "    - \"1.1.1.1:53#sni=SecretUdpSniHost.corp\"\n",
                "    - \"1.1.1.1:53#UdpFragSecretToken99\"\n",
                "    - \"system#SystemFragSecret88\"\n",
                "    - \"1.1.1.1:53 # Alice's MacBook (Work) UdpSpaceSecret\"\n",
                "    - \"{}1.1.1.1:53#BomUdpSecret\"\n",
                "    - tls://1.1.1.1:853\n",
                "rules:\n",
                "  - MATCH,DIRECT\n",
            ),
            '\u{feff}'
        );
        std::fs::write(&draft_yaml_path, yaml).unwrap();

        let mut outputs = Vec::new();
        for include_network_metadata in [false, true] {
            let opts = McpServerOptions {
                config_path: None,
                controller: Some("127.0.0.1:1".to_string()),
                secret: None,
                allow_mutations: false,
                include_network_metadata,
            };
            let res = execute_tool_call_with_state_dir(
                "audit_config_security",
                &json!({ "config_path": draft_yaml_path.to_string_lossy() }),
                &opts,
                &state_dir,
            )
            .await;
            outputs.push((include_network_metadata, res));
        }
        let _ = std::fs::remove_dir_all(&tmp_root);

        for (include_network_metadata, res) in outputs {
            assert_eq!(
                res["isError"], false,
                "valid non-scheme DNS #fragment config must succeed (include_network_metadata={include_network_metadata}): {res}"
            );
            let text = res["content"][0]["text"]
                .as_str()
                .expect("content[0].text string");
            let parsed: Value = serde_json::from_str(text).unwrap_or_else(|e| {
                panic!("audit_config_security returned invalid JSON ({e}): {text}")
            });
            assert_eq!(parsed["diff"]["dns_changed"], true);
            let dns_changes = parsed["diff"]["dns_changes"]
                .as_array()
                .expect("diff.dns_changes array")
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join("\n");
            assert!(
                dns_changes.contains("dns.nameserver:"),
                "expected dns.nameserver diff entry: {dns_changes}"
            );
            assert!(
                dns_changes.contains("tls://1.1.1.1:853")
                    || dns_changes.contains("tls://***REDACTED***"),
                "clean tls://1.1.1.1:853 should remain cleanly represented: {dns_changes}"
            );

            for forbidden in [
                "SecretUdpSniHost.corp",
                "SecretUdpSniHost",
                "UdpFragSecretToken99",
                "SystemFragSecret88",
                "Alice",
                "MacBook",
                "Work",
                "UdpSpaceSecret",
                "BomUdpSecret",
            ] {
                assert!(
                    !text.contains(forbidden),
                    "audit_config_security leaked non-scheme DNS fragment '{forbidden}' (include_network_metadata={include_network_metadata}): {text}"
                );
            }
        }
    }

    #[tokio::test]
    async fn mcp_m1_unknown_method_and_tool_result_redact_quoted_authorization_tokens() {
        let ro_opts = McpServerOptions {
            config_path: None,
            controller: Some("127.0.0.1:1".to_string()),
            secret: None,
            allow_mutations: false,
            include_network_metadata: false,
        };

        let cases: &[(&str, &str)] = &[
            (
                r#"Authorization: Bearer "QuotedBearerSecret789""#,
                "QuotedBearerSecret789",
            ),
            (
                r#"Authorization: Basic "QuotedBasicSecret456""#,
                "QuotedBasicSecret456",
            ),
            (
                "Authorization: Bearer 'SingleQuotedBearer123'",
                "SingleQuotedBearer123",
            ),
            (
                "Authorization: Basic `TickQuotedBasic321`",
                "TickQuotedBasic321",
            ),
        ];

        for (idx, (method, secret)) in cases.iter().enumerate() {
            let resp = handle_mcp_request(
                &json!({
                    "jsonrpc": "2.0",
                    "id": 600 + idx,
                    "method": method
                }),
                &ro_opts,
            )
            .await
            .expect("unknown method returns JSON-RPC error");
            assert_eq!(resp["error"]["code"], -32601);
            let serialized = serde_json::to_string(&resp).unwrap();
            let parsed_back: Value = serde_json::from_str(&serialized).unwrap();
            let msg = parsed_back["error"]["message"].as_str().unwrap();
            assert!(
                msg.contains("***REDACTED***"),
                "expected ***REDACTED*** in -32601 message for '{method}': {msg}"
            );
            assert!(
                !serialized.contains(secret),
                "-32601 leaked quoted auth secret '{secret}': {serialized}"
            );
        }

        let tool_res = mcp_tool_result(
            &json!({
                "bearer_dq": r#"Authorization: Bearer "QuotedBearerSecret789""#,
                "basic_dq": r#"Authorization: Basic "QuotedBasicSecret456""#,
                "bearer_sq": "Authorization: Bearer 'SingleQuotedBearer123'",
                "basic_bt": "Authorization: Basic `TickQuotedBasic321`"
            }),
            false,
        );
        let text = tool_res["content"][0]["text"].as_str().unwrap();
        let _: Value = serde_json::from_str(text)
            .unwrap_or_else(|e| panic!("mcp_tool_result returned invalid JSON ({e}): {text}"));
        for (_, secret) in cases {
            assert!(
                !text.contains(secret),
                "mcp_tool_result leaked quoted auth secret '{secret}': {text}"
            );
        }
    }

    #[tokio::test]
    async fn mcp_b6_backslash_and_tabbed_scheme_and_local_scrubbers_scale_linearly() {
        let ro_opts = McpServerOptions {
            config_path: None,
            controller: Some("127.0.0.1:1".to_string()),
            secret: None,
            allow_mutations: false,
            include_network_metadata: false,
        };

        let patterns = [
            "https:\\\\a\t",
            "http:\\\\a\t",
            "https:\t\\\\a\t",
            "https:\t\\\\[a]\t",
        ];

        for (idx, pattern) in patterns.iter().enumerate() {
            let repeats = (32 * 1024) / pattern.len();
            let payload = pattern.repeat(repeats);

            let t0 = std::time::Instant::now();
            let resp = handle_mcp_request(
                &json!({
                    "jsonrpc": "2.0",
                    "id": 700 + idx,
                    "method": payload
                }),
                &ro_opts,
            )
            .await
            .expect("unknown method returns JSON-RPC error");
            let method_elapsed = t0.elapsed();
            assert_eq!(resp["error"]["code"], -32601);
            let serialized = serde_json::to_string(&resp).unwrap();
            let _: Value = serde_json::from_str(&serialized).unwrap_or_else(|e| {
                panic!("B6 -32601 emitted invalid JSON ({e}) for pattern {pattern:?}")
            });
            assert!(
                method_elapsed < Duration::from_secs(3),
                "B6 -32601 scaling regressed for {pattern:?}: took {method_elapsed:?}"
            );

            let t1 = std::time::Instant::now();
            let tool_res = mcp_tool_result(&json!({ "status_note": payload }), false);
            let tool_elapsed = t1.elapsed();
            let text = tool_res["content"][0]["text"].as_str().unwrap();
            let _: Value = serde_json::from_str(text).unwrap_or_else(|e| {
                panic!("B6 mcp_tool_result emitted invalid JSON ({e}) for pattern {pattern:?}")
            });
            assert!(
                tool_elapsed < Duration::from_secs(3),
                "B6 mcp_tool_result scaling regressed for {pattern:?}: took {tool_elapsed:?}"
            );
        }

        // Verify `scrub_quoted_audit_endpoints` and `redact_network_tokens_in_log` also stay
        // strictly linear on large repeated inputs.
        let repeated_audit = "server '198.51.100.9:443' ".repeat(3000);
        let t_audit = std::time::Instant::now();
        let scrubbed_audit = scrub_quoted_audit_endpoints(&repeated_audit);
        let audit_elapsed = t_audit.elapsed();
        assert!(
            !scrubbed_audit.contains("198.51.100.9"),
            "scrub_quoted_audit_endpoints leaked IP on repeated input"
        );
        assert!(
            scrubbed_audit.contains("server '<redacted>'"),
            "scrub_quoted_audit_endpoints did not emit <redacted>"
        );
        assert!(
            audit_elapsed < Duration::from_secs(2),
            "scrub_quoted_audit_endpoints scaling regressed: took {audit_elapsed:?}"
        );

        let repeated_logs =
            r#"{"url":"https://secret-edge.corp:8443/v1"} 10.20.30.40. err:tls://dot.corp:853/p "#
                .repeat(1000);
        let t_logs = std::time::Instant::now();
        let scrubbed_logs = redact_network_tokens_in_log(&repeated_logs);
        let logs_elapsed = t_logs.elapsed();
        for forbidden in ["secret-edge.corp", "10.20.30.40", "dot.corp", "8443", "853"] {
            assert!(
                !scrubbed_logs.contains(forbidden),
                "redact_network_tokens_in_log leaked '{forbidden}' on large input"
            );
        }
        assert!(
            logs_elapsed < Duration::from_secs(2),
            "redact_network_tokens_in_log scaling regressed: took {logs_elapsed:?}"
        );
    }

    #[tokio::test]
    async fn mcp_b7_redacts_quoted_and_json_escaped_kv_secrets_across_all_surfaces() {
        let ro_opts = McpServerOptions {
            config_path: None,
            controller: Some("127.0.0.1:1".to_string()),
            secret: None,
            allow_mutations: false,
            include_network_metadata: false,
        };

        let cases: &[(&str, &str, &[&str])] = &[
            (
                r#"level=warn msg="auth fail" password="QuotedKvPassword999""#,
                r#"password="***REDACTED***""#,
                &["QuotedKvPassword999"],
            ),
            (
                "level=warn token='SingleKvToken888'",
                "token='***REDACTED***'",
                &["SingleKvToken888"],
            ),
            (
                "level=warn api_key=`BacktickKvApiKey777`",
                "api_key=`***REDACTED***`",
                &["BacktickKvApiKey777"],
            ),
            (
                r#"{"msg":"fail secret=\"JsonEscapedKvSecret666\""}"#,
                r#"secret=\"***REDACTED***\""#,
                &["JsonEscapedKvSecret666"],
            ),
            (
                r#"{"msg":"fail secret=\"part1\\\"part2\""}"#,
                r#"secret=\"***REDACTED***\""#,
                &["part1", "part2"],
            ),
            (
                r#"private_key="QuotedPrivKey555" pbk="QuotedPbk444""#,
                r#"private_key="***REDACTED***" pbk="***REDACTED***""#,
                &["QuotedPrivKey555", "QuotedPbk444"],
            ),
        ];

        // 1. `-32601` unknown `method`
        for (idx, (sample, expected_frag, secrets)) in cases.iter().enumerate() {
            let resp = handle_mcp_request(
                &json!({
                    "jsonrpc": "2.0",
                    "id": 750 + idx,
                    "method": sample
                }),
                &ro_opts,
            )
            .await
            .expect("unknown method returns JSON-RPC error");
            assert_eq!(resp["error"]["code"], -32601);
            let serialized = serde_json::to_string(&resp).unwrap();
            let parsed_back: Value = serde_json::from_str(&serialized).unwrap();
            let msg = parsed_back["error"]["message"].as_str().unwrap();
            assert!(
                msg.contains(expected_frag),
                "-32601 did not redact inside quotes as '{expected_frag}': {msg}"
            );
            for secret in *secrets {
                assert!(
                    !serialized.contains(secret),
                    "-32601 leaked B7 secret '{secret}': {serialized}"
                );
            }
        }

        // 2. `mcp_tool_result` (values & object keys)
        let mut obj = serde_json::Map::new();
        for (idx, (sample, _, _)) in cases.iter().enumerate() {
            obj.insert(format!("field_{idx}"), json!(sample));
            obj.insert((*sample).to_string(), json!(idx));
        }
        let tool_res = mcp_tool_result(&Value::Object(obj), false);
        let text = tool_res["content"][0]["text"].as_str().unwrap();
        let parsed: Value = serde_json::from_str(text)
            .unwrap_or_else(|e| panic!("B7 mcp_tool_result invalid JSON ({e}): {text}"));
        assert!(parsed.is_object());
        for (_, _, secrets) in cases {
            for secret in *secrets {
                assert!(
                    !text.contains(secret),
                    "B7 mcp_tool_result leaked '{secret}': {text}"
                );
            }
        }

        // 3. `extract_recent_logs_filtered` in BOTH privacy modes
        let logs_val = json!({
            "logs": [
                {
                    "timestamp_ms": 1,
                    "type": "warn",
                    "payload": r#"auth failed password="QuotedKvPassword999" token='SingleKvToken888' api_key=`BacktickKvApiKey777` secret=\"JsonEscapedKvSecret666\" secret=\"part1\\\"part2\" private_key="QuotedPrivKey555" pbk="QuotedPbk444""#
                }
            ]
        });
        for include_network_metadata in [false, true] {
            let logs = extract_recent_logs_filtered(
                Some(&logs_val),
                LogFilterLevel::Warn,
                10,
                include_network_metadata,
            );
            let payload = logs[0]["payload"].as_str().unwrap();
            for secret in [
                "QuotedKvPassword999",
                "SingleKvToken888",
                "BacktickKvApiKey777",
                "JsonEscapedKvSecret666",
                "part1",
                "part2",
                "QuotedPrivKey555",
                "QuotedPbk444",
            ] {
                assert!(
                    !payload.contains(secret),
                    "B7 get_recent_logs (include_network_metadata={include_network_metadata}) leaked '{secret}': {payload}"
                );
            }
        }

        // 4. Unknown MCP tool name and `get_recent_logs` invalid `level` error
        let unknown_tool_resp = handle_mcp_request(
            &json!({
                "jsonrpc": "2.0",
                "id": 760,
                "method": "tools/call",
                "params": {
                    "name": r#"tool password="UnknownToolKvPass99""#,
                    "arguments": {}
                }
            }),
            &ro_opts,
        )
        .await
        .expect("unknown tool returns JSON-RPC response");
        assert_eq!(unknown_tool_resp["result"]["isError"], true);
        let unknown_text = unknown_tool_resp["result"]["content"][0]["text"]
            .as_str()
            .unwrap();
        let _: Value = serde_json::from_str(unknown_text).unwrap();
        assert!(
            !unknown_text.contains("UnknownToolKvPass99"),
            "B7 unknown tool leaked secret: {unknown_text}"
        );

        let bad_level_resp = handle_mcp_request(
            &json!({
                "jsonrpc": "2.0",
                "id": 761,
                "method": "tools/call",
                "params": {
                    "name": "get_recent_logs",
                    "arguments": { "level": r#"password="LvlErrKvSecret99""# }
                }
            }),
            &ro_opts,
        )
        .await
        .expect("invalid level returns JSON-RPC response");
        assert_eq!(bad_level_resp["result"]["isError"], true);
        let bad_level_text = bad_level_resp["result"]["content"][0]["text"]
            .as_str()
            .unwrap();
        let _: Value = serde_json::from_str(bad_level_text).unwrap();
        assert!(
            !bad_level_text
                .to_ascii_lowercase()
                .contains("lvlerrkvsecret99"),
            "B7 invalid log level leaked secret: {bad_level_text}"
        );

        // 5. `audit_config_security` rule-linter (`RULE-SHADOWED-DOMAIN` & `RULE-DEAD-AFTER-MATCH`)
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let tmp_root =
            std::env::temp_dir().join(format!("rc-mcp-b7-rules-{}-{nanos}", std::process::id()));
        let state_dir = tmp_root.join("state");
        std::fs::create_dir_all(&state_dir).unwrap();
        let candidate_yaml_path = tmp_root.join("candidate_b7.yaml");
        std::fs::write(
            &candidate_yaml_path,
            r#"
mixed-port: 7890
dns:
  enable: true
  nameserver:
    - 1.1.1.1:53
rules:
  - DOMAIN-KEYWORD,corp,DIRECT
  - 'DOMAIN-KEYWORD,corp password="RuleKvPass99" token=''RuleSingleTok88'',DIRECT'
  - MATCH,DIRECT
  - 'DOMAIN-KEYWORD,dead secret="RuleDeadKvSec99" pbk="RuleDeadPbk77",DIRECT'
"#,
        )
        .unwrap();

        let audit_res = execute_tool_call_with_state_dir(
            "audit_config_security",
            &json!({ "config_path": candidate_yaml_path.to_string_lossy() }),
            &ro_opts,
            &state_dir,
        )
        .await;
        let _ = std::fs::remove_dir_all(&tmp_root);

        assert_eq!(audit_res["isError"], false, "unexpected error: {audit_res}");
        let audit_text = audit_res["content"][0]["text"].as_str().unwrap();
        let audit_parsed: Value = serde_json::from_str(audit_text).unwrap();
        let findings = audit_parsed["audit"]["findings"].as_array().unwrap();
        assert!(
            findings.iter().any(|f| f["code"] == "RULE-SHADOWED-DOMAIN"),
            "expected RULE-SHADOWED-DOMAIN finding: {findings:?}"
        );
        assert!(
            findings
                .iter()
                .any(|f| f["code"] == "RULE-DEAD-AFTER-MATCH"),
            "expected RULE-DEAD-AFTER-MATCH finding: {findings:?}"
        );
        for secret in [
            "RuleKvPass99",
            "RuleSingleTok88",
            "RuleDeadKvSec99",
            "RuleDeadPbk77",
        ] {
            assert!(
                !audit_text
                    .to_ascii_lowercase()
                    .contains(&secret.to_ascii_lowercase()),
                "B7 audit_config_security rule linter leaked '{secret}': {audit_text}"
            );
        }
    }

    #[tokio::test]
    async fn mcp_b8_redacts_whatwg_whitespace_and_ws_wss_schemes_across_all_surfaces() {
        let ro_opts = McpServerOptions {
            config_path: None,
            controller: Some("127.0.0.1:1".to_string()),
            secret: None,
            allow_mutations: false,
            include_network_metadata: false,
        };

        let cases: &[(&str, &[&str])] = &[
            (
                "https://dns.nextdns.io/\ta1b2c3/RootSlashTabSecret",
                &["a1b2c3", "RootSlashTabSecret"],
            ),
            (
                "https://dns.nextdns.io/\ra1b2c3/RootSlashCrSecret",
                &["a1b2c3", "RootSlashCrSecret"],
            ),
            (
                "tls://dot.corp.example:853/\tDotRootTabSecret",
                &["DotRootTabSecret"],
            ),
            (
                "https://dns.nextdns.io/a1b2c3/\nLfAfterSlashSecret",
                &["a1b2c3", "LfAfterSlashSecret"],
            ),
            (
                "https://dns.nextdns.io/a1b2c3/\tdev=EqAfterSlashSecret",
                &["a1b2c3", "EqAfterSlashSecret"],
            ),
            (
                "https://doh\t.example/a1b2c3/HostMidTabSecret",
                &["a1b2c3", "HostMidTabSecret"],
            ),
            (
                "tls://dot\t.corp.example:853/DotHostTabSecret",
                &["DotHostTabSecret"],
            ),
            (
                "https://dns.nextdns.io/a1\tb2c3/MidSegTabSecret",
                &["b2c3", "MidSegTabSecret"],
            ),
            (
                "https://doh.example/dns-query?token=abc\tQueryMidTabSecret",
                &["QueryMidTabSecret"],
            ),
            (
                "ws://wsuser:WsPlainPass99@ws.corp.example:80/WsPlainPath88",
                &["wsuser", "WsPlainPass99", "WsPlainPath88"],
            ),
            (
                "wss://wssuser:WssPlainPass99@ws.corp.example:443/WssPlainPath88",
                &["wssuser", "WssPlainPass99", "WssPlainPath88"],
            ),
            (
                "ws\ts://wsuser:WssTabPass99@ws.corp.example:443/WssTabPath88",
                &["wsuser", "WssTabPass99", "WssTabPath88"],
            ),
        ];

        // 1. `-32601` unknown `method`
        for (idx, (sample, secrets)) in cases.iter().enumerate() {
            let resp = handle_mcp_request(
                &json!({
                    "jsonrpc": "2.0",
                    "id": 800 + idx,
                    "method": sample
                }),
                &ro_opts,
            )
            .await
            .expect("unknown method returns JSON-RPC error");
            assert_eq!(resp["error"]["code"], -32601);
            let serialized = serde_json::to_string(&resp).unwrap();
            let _: Value = serde_json::from_str(&serialized).unwrap();
            for secret in *secrets {
                assert!(
                    !serialized.contains(secret),
                    "B8 -32601 leaked '{secret}' for {sample:?}: {serialized}"
                );
            }
        }

        // 2. `mcp_tool_result` (values & keys)
        let mut map = serde_json::Map::new();
        for (idx, (sample, _)) in cases.iter().enumerate() {
            map.insert(format!("v_{idx}"), json!(format!("dial {sample} done")));
            map.insert((*sample).to_string(), json!(idx));
        }
        let tool_res = mcp_tool_result(&Value::Object(map), false);
        let text = tool_res["content"][0]["text"].as_str().unwrap();
        let parsed: Value = serde_json::from_str(text)
            .unwrap_or_else(|e| panic!("B8 mcp_tool_result invalid JSON ({e}): {text}"));
        assert!(parsed.is_object());
        for (_, secrets) in cases {
            for secret in *secrets {
                assert!(
                    !text.contains(secret),
                    "B8 mcp_tool_result leaked '{secret}': {text}"
                );
            }
        }

        // 3. `extract_recent_logs_filtered` in BOTH default redacted and full metadata modes
        let log_entries: Vec<Value> = cases
            .iter()
            .enumerate()
            .map(|(i, (sample, _))| {
                json!({
                    "timestamp_ms": i + 1,
                    "type": "warn",
                    "payload": format!("upstream {sample} failed")
                })
            })
            .collect();
        let logs_val = json!({ "logs": log_entries });
        for include_network_metadata in [false, true] {
            let logs = extract_recent_logs_filtered(
                Some(&logs_val),
                LogFilterLevel::Warn,
                30,
                include_network_metadata,
            );
            let logs_json = serde_json::to_string(&logs).unwrap();
            for (_, secrets) in cases {
                for secret in *secrets {
                    assert!(
                        !logs_json.contains(secret),
                        "B8 get_recent_logs (include_network_metadata={include_network_metadata}) leaked '{secret}': {logs_json}"
                    );
                }
            }
            if !include_network_metadata {
                assert!(
                    !logs_json.contains("ws.corp.example"),
                    "B8 default redacted logs leaked ws/wss host: {logs_json}"
                );
            }
        }

        // 4. Offline `explain_route` with root-slash `\t` target URL + `audit_config_security`
        //    rule-linter with WHATWG tab and ws/wss rules.
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let tmp_root =
            std::env::temp_dir().join(format!("rc-mcp-b8-e2e-{}-{nanos}", std::process::id()));
        let state_dir = tmp_root.join("state");
        std::fs::create_dir_all(&state_dir).unwrap();
        let cfg_path = tmp_root.join("b8.yaml");
        std::fs::write(
            &cfg_path,
            concat!(
                "mixed-port: 7890\n",
                "dns:\n",
                "  enable: true\n",
                "  nameserver:\n",
                "    - 1.1.1.1:53\n",
                "rules:\n",
                "  - DOMAIN-KEYWORD,corp,DIRECT\n",
                "  - \"DOMAIN-KEYWORD,https://dns.nextdns.io/\\ta1b2c3/RuleRootTabSec corp,DIRECT\"\n",
                "  - \"DOMAIN-KEYWORD,https://doh\\t.example/a1b2c3/RuleHostTabSec corp,DIRECT\"\n",
                "  - \"DOMAIN-KEYWORD,ws://wsuser:RuleWsPass99@ws.corp.example:80/RuleWsPath88,DIRECT\"\n",
                "  - MATCH,DIRECT\n",
                "  - \"DOMAIN-KEYWORD,wss://wssuser:DeadWssPass99@ws.corp.example:443/DeadWssPath88,DIRECT\"\n",
            ),
        )
        .unwrap();

        let explain_opts = McpServerOptions {
            config_path: Some(cfg_path.clone()),
            controller: Some("127.0.0.1:1".to_string()),
            secret: None,
            allow_mutations: false,
            include_network_metadata: false,
        };
        let explain_res = execute_tool_call_with_state_dir(
            "explain_route",
            &json!({ "target": "https://dns.nextdns.io/\ta1b2c3/TgtTabSecret99" }),
            &explain_opts,
            &state_dir,
        )
        .await;
        assert_eq!(
            explain_res["isError"], false,
            "unexpected explain_route error: {explain_res}"
        );
        let explain_text = explain_res["content"][0]["text"].as_str().unwrap();
        let explain_parsed: Value = serde_json::from_str(explain_text).unwrap();
        assert_eq!(explain_parsed["normalized_target"], "dns.nextdns.io:443");
        for secret in ["a1b2c3", "TgtTabSecret99"] {
            assert!(
                !explain_text.contains(secret),
                "B8 explain_route leaked '{secret}': {explain_text}"
            );
        }

        let audit_res = execute_tool_call_with_state_dir(
            "audit_config_security",
            &json!({ "config_path": cfg_path.to_string_lossy() }),
            &ro_opts,
            &state_dir,
        )
        .await;
        let _ = std::fs::remove_dir_all(&tmp_root);

        assert_eq!(
            audit_res["isError"], false,
            "unexpected audit error: {audit_res}"
        );
        let audit_text = audit_res["content"][0]["text"].as_str().unwrap();
        let audit_parsed: Value = serde_json::from_str(audit_text).unwrap();
        let findings = audit_parsed["audit"]["findings"].as_array().unwrap();
        assert!(
            findings.iter().any(|f| f["code"] == "RULE-SHADOWED-DOMAIN"),
            "expected RULE-SHADOWED-DOMAIN finding: {findings:?}"
        );
        assert!(
            findings
                .iter()
                .any(|f| f["code"] == "RULE-DEAD-AFTER-MATCH"),
            "expected RULE-DEAD-AFTER-MATCH finding: {findings:?}"
        );
        let audit_lower = audit_text.to_ascii_lowercase();
        for secret in [
            "RuleRootTabSec",
            "RuleHostTabSec",
            "RuleWsPass99",
            "RuleWsPath88",
            "DeadWssPass99",
            "DeadWssPath88",
        ] {
            assert!(
                !audit_text.contains(secret) && !audit_lower.contains(&secret.to_ascii_lowercase()),
                "B8 audit_config_security rule linter leaked '{secret}': {audit_text}"
            );
        }
    }

    #[tokio::test]
    async fn mcp_m2_redacts_log_metadata_punctuation_and_json_authorization_headers() {
        // Part 1: Default redacted mode (`include_network_metadata: false`) log metadata scrubbing
        // for JSON-wrapped URLs, trailing-dot IPs & host:ports, prefixed/braced/parenthesized
        // endpoints, bracketed IPv6 SocketAddrs, and UTF-8 surrounding prose.
        let logs_val = json!({
            "logs": [
                {
                    "timestamp_ms": 1,
                    "type": "warn",
                    "payload": r#"{"url":"https://secret-edge.corp:8443/v1"} connect 10.20.30.40. dial secret-node.corp:8443."#
                },
                {
                    "timestamp_ms": 2,
                    "type": "warn",
                    "payload": "err:tls://dot.corp.example:853/path dial(tls://dot2.corp.example:853/p) {tls://dot3.corp.example:853/p}"
                },
                {
                    "timestamp_ms": 3,
                    "type": "warn",
                    "payload": r#"[2001:db8::1]:443 [::1]:8080 [2001:db8::2]:443. {[::1]:9090} {"ip":"10.20.30.41"} {"host":"node2.corp:8443"} dial(10.20.30.42:443) err:10.20.30.43 10.20.30.44:443: {\"ip\":\"10.20.30.45\"} 连接失败 err:tls://utf8-dot.corp:853/p"#
                },
                {
                    "timestamp_ms": 4,
                    "type": "warn",
                    "payload": r#"version v0.5.15. done. password=***REDACTED*** {"status":"ok","code":200,"version":"v0.5.15."} elapsed=12.5ms 2026-11-24T09:57:16Z 1.2.3. 完成."#
                }
            ]
        });

        let redacted_logs =
            extract_recent_logs_filtered(Some(&logs_val), LogFilterLevel::Warn, 10, false);
        let arr = redacted_logs.as_array().expect("logs array");
        assert_eq!(arr.len(), 4);

        // Entries are returned newest-first (`timestamp_ms` 4, 3, 2, 1).
        let benign_payload = arr[0]["payload"].as_str().unwrap();
        assert_eq!(
            benign_payload,
            r#"version v0.5.15. done. password=***REDACTED*** {"status":"ok","code":200,"version":"v0.5.15."} elapsed=12.5ms 2026-11-24T09:57:16Z 1.2.3. 完成."#,
            "benign prose/version/JSON status tokens must not be falsely redacted"
        );

        let all_redacted = arr[1..]
            .iter()
            .map(|e| e["payload"].as_str().unwrap())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            all_redacted.contains("[redacted-endpoint]"),
            "expected [redacted-endpoint] markers in redacted logs: {all_redacted}"
        );
        assert!(
            all_redacted.contains("连接失败"),
            "UTF-8 prose around endpoints must be preserved cleanly: {all_redacted}"
        );
        for forbidden in [
            "secret-edge.corp",
            "10.20.30.40",
            "10.20.30.41",
            "10.20.30.42",
            "10.20.30.43",
            "10.20.30.44",
            "10.20.30.45",
            "secret-node.corp",
            "node2.corp",
            "8443",
            "dot.corp.example",
            "dot2.corp.example",
            "dot3.corp.example",
            "utf8-dot.corp",
            "853",
            "2001:db8::1",
            "2001:db8::2",
            "::1",
            "8080",
            "9090",
        ] {
            assert!(
                !all_redacted.contains(forbidden),
                "M2 default-mode log redaction leaked '{forbidden}': {all_redacted}"
            );
        }

        // Part 2: JSON-serialized `"Authorization": "Bearer ..."` / `"Basic ..."` and
        // double-escaped `Authorization: Bearer \"part1\\\"EscapedInnerBearer777\"`.
        let ro_opts = McpServerOptions {
            config_path: None,
            controller: Some("127.0.0.1:1".to_string()),
            secret: None,
            allow_mutations: false,
            include_network_metadata: false,
        };
        let auth_cases: &[(&str, &[&str])] = &[
            (
                r#"{"Authorization": "Bearer JsonObjBearerSecret999"}"#,
                &["JsonObjBearerSecret999"],
            ),
            (
                r#"{"Authorization": "Basic JsonObjBasicSecret888"}"#,
                &["JsonObjBasicSecret888"],
            ),
            (
                r#"Authorization: Bearer \"part1\\\"EscapedInnerBearer777\""#,
                &["part1", "EscapedInnerBearer777"],
            ),
        ];

        for (idx, (sample, secrets)) in auth_cases.iter().enumerate() {
            let resp = handle_mcp_request(
                &json!({
                    "jsonrpc": "2.0",
                    "id": 850 + idx,
                    "method": sample
                }),
                &ro_opts,
            )
            .await
            .expect("unknown method returns JSON-RPC error");
            assert_eq!(resp["error"]["code"], -32601);
            let serialized = serde_json::to_string(&resp).unwrap();
            let parsed_back: Value = serde_json::from_str(&serialized).unwrap();
            let msg = parsed_back["error"]["message"].as_str().unwrap();
            assert!(
                msg.contains("***REDACTED***"),
                "M2 -32601 did not redact Authorization header for {sample:?}: {msg}"
            );
            for secret in *secrets {
                assert!(
                    !serialized.contains(secret),
                    "M2 -32601 leaked '{secret}' for {sample:?}: {serialized}"
                );
            }
        }

        let tool_res = mcp_tool_result(
            &json!({
                "json_bearer": r#"{"Authorization": "Bearer JsonObjBearerSecret999"}"#,
                "json_basic": r#"{"Authorization": "Basic JsonObjBasicSecret888"}"#,
                "escaped_inner": r#"Authorization: Bearer \"part1\\\"EscapedInnerBearer777\""#,
            }),
            false,
        );
        let tool_text = tool_res["content"][0]["text"].as_str().unwrap();
        let _: Value = serde_json::from_str(tool_text)
            .unwrap_or_else(|e| panic!("M2 mcp_tool_result invalid JSON ({e}): {tool_text}"));
        for (_, secrets) in auth_cases {
            for secret in *secrets {
                assert!(
                    !tool_text.contains(secret),
                    "M2 mcp_tool_result leaked '{secret}': {tool_text}"
                );
            }
        }

        let auth_logs_val = json!({
            "logs": [
                {
                    "timestamp_ms": 1,
                    "type": "warn",
                    "payload": r#"hdr {"Authorization": "Bearer JsonObjBearerSecret999"} {"Authorization": "Basic JsonObjBasicSecret888"} Authorization: Bearer \"part1\\\"EscapedInnerBearer777\""#
                }
            ]
        });
        for include_network_metadata in [false, true] {
            let auth_logs = extract_recent_logs_filtered(
                Some(&auth_logs_val),
                LogFilterLevel::Warn,
                10,
                include_network_metadata,
            );
            let payload = auth_logs[0]["payload"].as_str().unwrap();
            for (_, secrets) in auth_cases {
                for secret in *secrets {
                    assert!(
                        !payload.contains(secret),
                        "M2 get_recent_logs (include_network_metadata={include_network_metadata}) leaked '{secret}': {payload}"
                    );
                }
            }
        }
    }
}

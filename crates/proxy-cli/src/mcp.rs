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
    if let Some(path) = config_path {
        let cfg = ClashConfig::from_file(path)
            .with_context(|| format!("failed to load config '{}'", path.display()))?;
        return Ok((cfg, format!("file:{}", path.display())));
    }
    let state_dir = proxy_core::platform::recovery::default_state_dir();
    let mgr = proxy_core::profile::ProfileManager::open_or_init(&state_dir)?;
    let (cfg, active_path) = mgr.load_active_config()?;
    Ok((cfg, format!("profile:{}", active_path.display())))
}

pub fn resolve_controller_client(
    explicit_controller: Option<&str>,
    explicit_secret: Option<&str>,
    fallback_cfg: Option<&ClashConfig>,
) -> Option<ControllerClient> {
    let raw_ctrl = explicit_controller
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .or_else(|| {
            fallback_cfg
                .map(|c| c.external_controller.trim())
                .filter(|s| !s.is_empty())
        })
        .unwrap_or("127.0.0.1:9090");

    let normalized_host = if let Some(rest) = raw_ctrl.strip_prefix("0.0.0.0:") {
        format!("127.0.0.1:{rest}")
    } else if let Some(rest) = raw_ctrl.strip_prefix("[::]:") {
        format!("[::1]:{rest}")
    } else {
        raw_ctrl.to_string()
    };

    let secret = explicit_secret
        .map(str::to_string)
        .filter(|s| !s.is_empty())
        .or_else(|| {
            std::env::var("RUST_CLASH_SECRET")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        })
        .or_else(|| {
            fallback_cfg
                .and_then(|c| c.secret.clone())
                .filter(|s| !s.is_empty())
        });

    ControllerClient::new(&normalized_host, secret).ok()
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
    let has_yaml_ext = path
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case("yaml") || ext.eq_ignore_ascii_case("yml"));
    let has_stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .is_some_and(|s| !s.is_empty());
    if !has_yaml_ext || !has_stem {
        return Err("invalid config_path: only '.yaml' or '.yml' configuration files are allowed");
    }
    if let Ok(meta) = std::fs::metadata(&path)
        && !meta.is_file()
    {
        return Err("invalid config_path: target must be a regular '.yaml' or '.yml' file");
    }
    Ok(path)
}

fn sanitize_audit_file_error(path: &std::path::Path) -> &'static str {
    match std::fs::metadata(path) {
        Err(_) => "failed to load config_path: file does not exist or is unreadable",
        Ok(meta) if !meta.is_file() => {
            "invalid config_path: target must be a regular '.yaml' or '.yml' file"
        }
        Ok(_) => {
            "failed to parse or validate Clash YAML at config_path (syntax or schema error; raw file contents redacted)"
        }
    }
}

fn scrub_audit_payload(payload: &mut Value, include_network_metadata: bool) {
    if include_network_metadata {
        payload["metadata_privacy_mode"] = json!("full");
        return;
    }
    payload["metadata_privacy_mode"] = json!(
        "redacted (proxy server endpoints hidden by default; relaunch with --include-network-metadata to expose)"
    );

    if let Some(findings) = payload
        .get_mut("audit")
        .and_then(|a| a.get_mut("findings"))
        .and_then(|f| f.as_array_mut())
    {
        for finding in findings {
            if let Some(loc) = finding.get("location").and_then(|v| v.as_str())
                && loc.starts_with("proxies[")
                && let Some(paren_idx) = loc.find(" (")
            {
                let scrubbed_loc = format!("{} ([endpoint-redacted])", &loc[..paren_idx]);
                finding["location"] = json!(scrubbed_loc);
            }
        }
    }

    if let Some(diff) = payload.get_mut("diff").and_then(|d| d.as_object_mut()) {
        if let Some(added) = diff.get_mut("added_proxies").and_then(|a| a.as_array_mut()) {
            for p in added {
                if p.get("server").is_some() {
                    p["server"] = json!("[endpoint-redacted]");
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

async fn pick_default_proxy_name(ctrl: Option<&ControllerClient>, cfg: &ClashConfig) -> String {
    if let Some(c) = ctrl
        && let Ok((200, val)) = c
            .request_json("GET", "/proxies", None, Duration::from_millis(1500))
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
    let loaded = load_cli_or_profile_config(opts.config_path.as_ref());
    let fallback_cfg = loaded.as_ref().ok().map(|(c, _)| c);
    let ctrl = resolve_controller_client(
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
                if let Some(ref c) = ctrl
                    && let Ok((200, resp)) = c
                        .request_json("GET", audit_endpoint, None, Duration::from_secs(6))
                        .await
                {
                    let mut out = json!({
                        "source": format!("live_controller:{}", c.host_port),
                        "audit": resp,
                    });
                    scrub_audit_payload(&mut out, opts.include_network_metadata);
                    return mcp_tool_result(&out, false);
                }

                match loaded {
                    Ok((cfg, src)) => {
                        let report = audit_config(&cfg);
                        let mut out = json!({
                            "source": sanitize_source_label(&src, opts.include_network_metadata),
                            "audit": report,
                        });
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

            if let Some(ref c) = ctrl {
                let mut pq = format!("/rules/explain?target={}", url_encode_component(raw_target));
                if let Some(sip) = raw_src {
                    pq.push_str(&format!("&src_ip={}", url_encode_component(sip)));
                }
                if let Ok((status, mut resp)) = c
                    .request_json("GET", &pq, None, Duration::from_secs(4))
                    .await
                    && (200..300).contains(&status)
                {
                    scrub_explain_payload(&mut resp, opts.include_network_metadata);
                    return mcp_tool_result(&resp, false);
                }
            }

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
                None => pick_default_proxy_name(ctrl.as_ref(), &default_cfg).await,
            };

            if let Some(ref c) = ctrl {
                let path = format!("/proxies/{}/probe", url_encode_component(&proxy_name));
                if let Ok((status, resp)) = c
                    .request_json(
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
                        return mcp_tool_result(&resp, false);
                    }
                    if matches!(status, 400 | 404 | 429) {
                        return mcp_tool_result(&resp, true);
                    }
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
                        Ok(report) => mcp_tool_result(&json!(report), false),
                        Err(e) => mcp_tool_result(
                            &json!({ "error": redact_sensitive_text(&e.to_string()) }),
                            true,
                        ),
                    }
                }
                Err(e) => mcp_tool_result(
                    &json!({ "error": redact_sensitive_text(&e.to_string()) }),
                    true,
                ),
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
                None => pick_default_proxy_name(ctrl.as_ref(), &default_cfg).await,
            };

            if let Some(ref c) = ctrl {
                let path = format!("/proxies/{}/matrix", url_encode_component(&proxy_name));
                if let Ok((status, resp)) = c
                    .request_json(
                        "POST",
                        &path,
                        Some(&json!({ "timeout_ms": timeout_ms })),
                        Duration::from_millis(timeout_ms * 2 + 6000),
                    )
                    .await
                {
                    if (200..300).contains(&status) {
                        return mcp_tool_result(&resp, false);
                    }
                    if matches!(status, 400 | 404 | 429) {
                        return mcp_tool_result(&resp, true);
                    }
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
                        Ok(report) => mcp_tool_result(&json!(report), false),
                        Err(e) => mcp_tool_result(
                            &json!({ "error": redact_sensitive_text(&e.to_string()) }),
                            true,
                        ),
                    }
                }
                Err(e) => mcp_tool_result(
                    &json!({ "error": redact_sensitive_text(&e.to_string()) }),
                    true,
                ),
            }
        }

        "get_proxy_status" => {
            if let Some(ref c) = ctrl
                && let Ok((200, proxies_val)) = c
                    .request_json("GET", "/proxies", None, Duration::from_secs(3))
                    .await
            {
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

                return mcp_tool_result(
                    &json!({
                        "daemon_connected": true,
                        "metadata_privacy_mode": if opts.include_network_metadata { "full" } else { "redacted" },
                        "controller": c.host_port,
                        "mode": cfg_val.as_ref().and_then(|v| v.get("mode")),
                        "mixed_port": cfg_val.as_ref().and_then(|v| v.get("mixed-port")),
                        "tun": cfg_val.as_ref().and_then(|v| v.get("tun")),
                        "effective_outbound": proxies_val.get("effective-outbound"),
                        "groups": groups_summary,
                        "recent_failure_diagnostics": recent_diags,
                    }),
                    false,
                );
            }

            match loaded {
                Ok((cfg, src)) => match ProxyEngine::build_standalone_router(&cfg) {
                    Ok(router) => mcp_tool_result(
                        &json!({
                            "daemon_connected": false,
                            "metadata_privacy_mode": if opts.include_network_metadata { "full" } else { "redacted" },
                            "source": sanitize_source_label(&src, opts.include_network_metadata),
                            "mode": cfg.mode,
                            "mixed_port": cfg.mixed_port,
                            "node_count": cfg.proxies.len(),
                            "effective_outbound": router.effective_primary_outbound(),
                            "note": "No live rust-clash controller responded; showing offline profile snapshot."
                        }),
                        false,
                    ),
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
            let Some(ref c) = ctrl else {
                return mcp_tool_result(
                    &json!({ "error": "no controller configured to switch live Selector group" }),
                    true,
                );
            };

            let path = format!("/proxies/{}", url_encode_component(group));
            match c
                .request_json(
                    "PUT",
                    &path,
                    Some(&json!({ "name": proxy })),
                    Duration::from_secs(4),
                )
                .await
            {
                Ok((status, _)) if (200..300).contains(&status) => mcp_tool_result(
                    &json!({
                        "ok": true,
                        "group": group,
                        "selected": proxy,
                    }),
                    false,
                ),
                Ok((status, err_val)) => mcp_tool_result(
                    &json!({
                        "ok": false,
                        "http_status": status,
                        "detail": err_val,
                    }),
                    true,
                ),
                Err(e) => mcp_tool_result(
                    &json!({ "error": redact_sensitive_text(&e.to_string()) }),
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
    let id = req.get("id").cloned();
    let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");

    // Notifications do not carry an `id` and must not receive a JSON-RPC response.
    let req_id = id?;

    if method.is_empty() {
        return Some(json!({
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {
                "code": -32600,
                "message": "Invalid Request: missing method"
            }
        }));
    }

    let params = req.get("params").unwrap_or(&Value::Null);

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

async fn read_next_mcp_frame<R: AsyncRead + Unpin>(
    reader: &mut BufReader<R>,
) -> Result<Option<(Value, FrameMode)>> {
    let mut line = String::new();
    loop {
        line.clear();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            return Ok(None);
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        if let Some(rest) = trimmed
            .strip_prefix("Content-Length:")
            .or_else(|| trimmed.strip_prefix("content-length:"))
        {
            let content_len: usize = rest
                .trim()
                .parse()
                .context("invalid Content-Length header in MCP stream")?;
            if content_len > 8 * 1024 * 1024 {
                return Err(anyhow!("MCP frame exceeds 8 MiB safety cap"));
            }
            // Consume remaining headers up to blank line.
            loop {
                let mut hdr = String::new();
                let hn = reader.read_line(&mut hdr).await?;
                if hn == 0 || hdr.trim().is_empty() {
                    break;
                }
            }
            let mut body = vec![0u8; content_len];
            reader.read_exact(&mut body).await?;
            let val: Value = serde_json::from_slice(&body)
                .context("invalid JSON in Content-Length MCP frame")?;
            return Ok(Some((val, FrameMode::ContentLength)));
        }

        let val: Value = serde_json::from_str(trimmed).context("invalid JSON-RPC line on stdin")?;
        return Ok(Some((val, FrameMode::NewlineJson)));
    }
}

async fn write_mcp_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    resp: &Value,
    mode: FrameMode,
) -> Result<()> {
    let encoded = serde_json::to_vec(resp)?;
    match mode {
        FrameMode::NewlineJson => {
            writer.write_all(&encoded).await?;
            writer.write_all(b"\n").await?;
        }
        FrameMode::ContentLength => {
            let hdr = format!("Content-Length: {}\r\n\r\n", encoded.len());
            writer.write_all(hdr.as_bytes()).await?;
            writer.write_all(&encoded).await?;
        }
    }
    writer.flush().await?;
    Ok(())
}

pub async fn serve_mcp_io<R, W>(input: R, mut output: W, opts: McpServerOptions) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut reader = BufReader::new(input);
    loop {
        match read_next_mcp_frame(&mut reader).await {
            Ok(Some((req, mode))) => {
                if let Some(resp) = handle_mcp_request(&req, &opts).await {
                    write_mcp_frame(&mut output, &resp, mode).await?;
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
                write_mcp_frame(&mut output, &err_resp, FrameMode::NewlineJson).await?;
                break;
            }
        }
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

        let frames: Vec<Value> = out_str
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(frames.len(), 4);
        assert_eq!(frames[0]["result"]["isError"], false);
        assert!(
            frames[0]["result"]["content"][0]["text"]
                .as_str()
                .unwrap()
                .contains("SEC-TLS-SKIP-VERIFY")
        );
        assert!(
            frames[1]["result"]["content"][0]["text"]
                .as_str()
                .unwrap()
                .contains("Node-A")
        );
        assert_eq!(frames[2]["result"]["isError"], false);
        assert!(
            frames[3]["result"]["content"][0]["text"]
                .as_str()
                .unwrap()
                .contains("\"now\": \"DIRECT\"")
        );

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
    async fn mcp_audit_config_path_blocks_traversal_non_yaml_and_redacts_parse_errors() {
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
}

pub mod embedded;

use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use axum::{
    Json, Router as AxumRouter,
    extract::{
        ConnectInfo, Path, Query, Request, State,
        ws::{Message, WebSocket, WebSocketUpgrade, rejection::WebSocketUpgradeRejection},
    },
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, post, put},
};
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::watch,
    task::JoinHandle,
};

use crate::{
    api::embedded::serve_embedded_spa,
    config::{ClashConfig, ProxyNodeConfig, REDACTED_SECRET, RunMode, uri::export_proxy_uri},
    dns::wire::{
        DnsAnswerData, QTYPE_A, QTYPE_AAAA, build_dns_query, dns_response_rcode, extract_ip_answers,
    },
    engine::ProxyEngine,
    error::{ProxyError, Result},
    inbound::mixed::canonical_ip,
    outbound::vless::encryption::{config::XorMode, generate_vless_encryption_pair},
    platform::{
        autostart::AutostartManager,
        sysproxy::{disable_system_proxy, enable_system_proxy, query_sysproxy_status},
    },
    profile::{CreateProfileSpec, ProfileManager},
    tracker::TelemetryHub,
};

#[derive(Clone)]
pub struct ApiState {
    pub engine: Arc<ProxyEngine>,
    pub bound_addr: SocketAddr,
}

pub fn build_api_router(engine: Arc<ProxyEngine>) -> AxumRouter {
    let fallback_addr = engine
        .config_snapshot()
        .external_controller
        .parse::<SocketAddr>()
        .unwrap_or_else(|_| SocketAddr::from(([127, 0, 0, 1], 9090)));
    build_api_router_with_addr(engine, fallback_addr)
}

pub fn build_api_router_with_addr(engine: Arc<ProxyEngine>, bound_addr: SocketAddr) -> AxumRouter {
    let api_state = ApiState {
        engine: Arc::clone(&engine),
        bound_addr,
    };

    AxumRouter::new()
        .route("/version", get(get_version))
        .route(
            "/configs",
            get(get_configs).patch(patch_configs).put(put_configs),
        )
        .route("/configs/raw", get(get_raw_yaml))
        .route("/proxies", get(get_proxies))
        .route(
            "/proxies/{name}",
            get(get_proxy_by_name).put(select_proxy_in_group),
        )
        .route("/proxies/{name}/delay", get(get_proxy_delay))
        .route(
            "/proxies/{name}/probe",
            post(post_proxy_waterfall_probe_api),
        )
        .route(
            "/proxies/{name}/matrix",
            post(post_proxy_endpoint_matrix_api),
        )
        .route("/rules", get(get_rules))
        .route("/rules/explain", get(explain_rule_api))
        .route(
            "/routing/preset",
            get(get_routing_preset_api).put(put_routing_preset_api),
        )
        .route(
            "/routing/custom-rules",
            get(get_routing_custom_rules_api).put(put_routing_custom_rules_api),
        )
        .route("/geodata", get(get_geodata_status_api))
        .route("/geodata/status", get(get_geodata_status_api))
        .route("/geodata/update", post(post_geodata_update_api))
        .route(
            "/connections",
            get(get_or_ws_connections).delete(close_all_connections),
        )
        .route(
            "/connections/diagnostics",
            get(get_connection_diagnostics_api).delete(clear_connection_diagnostics_api),
        )
        .route("/connections/{id}", delete(close_single_connection))
        .route("/dns/query", get(query_dns_api))
        .route("/dns/fakeip", get(get_fakeip_pool))
        .route("/dns/flush", post(flush_dns_cache_api))
        .route("/cache/fakeip/flush", post(flush_dns_cache_api))
        .route("/tun/status", get(get_tun_status))
        .route("/sysproxy", get(get_sysproxy_api).patch(patch_sysproxy_api))
        .route(
            "/autostart",
            get(get_autostart_api).patch(patch_autostart_api),
        )
        .route(
            "/profiles",
            get(get_profiles_api).post(post_create_profile_api),
        )
        .route("/profiles/import", post(post_import_uris))
        .route(
            "/profiles/active/nodes",
            get(get_active_nodes_api).post(post_create_active_node_api),
        )
        .route(
            "/profiles/active/nodes/deduplicate",
            post(post_deduplicate_active_nodes_api),
        )
        .route(
            "/profiles/active/nodes/{name}",
            put(put_update_active_node_api).delete(delete_active_node_api),
        )
        .route("/profiles/{id}", delete(delete_profile_api))
        .route("/profiles/{id}/activate", put(put_activate_profile_api))
        .route("/profiles/{id}/refresh", post(post_refresh_profile_api))
        .route("/demo/toggle", post(post_demo_toggle_api))
        .route("/diagnostics/export", get(get_diagnostics_export_api))
        .route(
            "/diagnostics/audit",
            get(get_diagnostics_audit_api).post(post_diagnostics_audit_api),
        )
        .route("/tools/vless-keypair", post(post_vless_keypair))
        .route("/tools/benchmark", post(post_live_benchmark))
        .route("/traffic", get(get_or_ws_traffic))
        .route("/memory", get(get_or_ws_memory))
        .route("/logs", get(get_or_ws_logs))
        .fallback(serve_embedded_spa)
        .layer(middleware::from_fn_with_state(
            api_state,
            security_and_auth_middleware,
        ))
        .with_state(engine)
}

/// Spawn the Axum Mihomo-compatible REST + WebSocket Control Plane & Embedded Web UI server.
pub async fn spawn_api_server(
    listen_addr: &str,
    engine: Arc<ProxyEngine>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(SocketAddr, JoinHandle<()>)> {
    let listener = TcpListener::bind(listen_addr).await?;
    let bound = listener.local_addr()?;

    let has_secret = engine
        .config_snapshot()
        .secret
        .as_ref()
        .is_some_and(|s| !s.is_empty());
    if !canonical_ip(bound.ip()).is_loopback() && !has_secret {
        engine.hub().push_log(
            "warn",
            format!(
                "Control API bound to non-loopback {bound} without a configured 'secret'; non-loopback API requests will be rejected (403)"
            ),
        );
    }

    engine.hub().push_log(
        "info",
        format!("Control API & Embedded Web Console listening on http://{bound}"),
    );
    let app = build_api_router_with_addr(engine, bound);

    let handle = tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(async move {
            let _ = shutdown.changed().await;
        })
        .await;
    });

    Ok((bound, handle))
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn is_api_endpoint_path(path: &str) -> bool {
    matches!(
        path,
        "/version"
            | "/configs"
            | "/configs/raw"
            | "/proxies"
            | "/rules"
            | "/rules/explain"
            | "/connections"
            | "/dns/query"
            | "/dns/fakeip"
            | "/dns/flush"
            | "/cache/fakeip/flush"
            | "/tun/status"
            | "/sysproxy"
            | "/autostart"
            | "/profiles"
            | "/profiles/import"
            | "/geodata"
            | "/demo/toggle"
            | "/diagnostics/export"
            | "/tools/vless-keypair"
            | "/tools/benchmark"
            | "/traffic"
            | "/memory"
            | "/logs"
    ) || path.starts_with("/proxies/")
        || path.starts_with("/connections/")
        || path.starts_with("/profiles/")
        || path.starts_with("/geodata/")
        || path.starts_with("/routing/")
        || path.starts_with("/diagnostics/")
}

fn is_ws_endpoint_path(path: &str) -> bool {
    matches!(path, "/traffic" | "/memory" | "/logs" | "/connections")
}

fn percent_decode_query_val(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let Ok(hex_str) = std::str::from_utf8(&bytes[i + 1..i + 3])
            && let Ok(val) = u8::from_str_radix(hex_str, 16)
        {
            out.push(val);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(out).unwrap_or_else(|_| raw.to_string())
}

fn is_websocket_upgrade(headers: &HeaderMap) -> bool {
    headers
        .get(header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("websocket"))
}

fn extract_host_without_port(raw_host: &str) -> &str {
    let trimmed = raw_host.trim();
    if let Some(rest) = trimmed.strip_prefix('[')
        && let Some((v6, _)) = rest.split_once(']')
    {
        return v6;
    }
    if trimmed.matches(':').count() == 1
        && let Some((host, _port)) = trimmed.rsplit_once(':')
    {
        return host;
    }
    trimmed
}

fn is_allowed_host_header(
    headers: &HeaderMap,
    bound_addr: SocketAddr,
    has_configured_secret: bool,
    has_valid_secret: bool,
) -> bool {
    let Some(raw_host) = headers.get(header::HOST).and_then(|v| v.to_str().ok()) else {
        return false;
    };
    let host = extract_host_without_port(raw_host);
    if host.eq_ignore_ascii_case("localhost")
        || host.eq_ignore_ascii_case("tauri.localhost")
        || host == "127.0.0.1"
        || host == "::1"
    {
        return true;
    }

    let bound_ip = canonical_ip(bound_addr.ip());
    if !bound_ip.is_unspecified() && host.parse::<IpAddr>().ok().map(canonical_ip) == Some(bound_ip)
    {
        return true;
    }
    if bound_ip.is_unspecified() && has_configured_secret && host.parse::<IpAddr>().is_ok() {
        return true;
    }
    has_valid_secret
}

/// Returns `true` ONLY for the embedded Web Console served from the exact bound controller port
/// or the Tauri 2 Desktop WebView origins (`tauri://localhost`, `http(s)://tauri.localhost`).
fn is_trusted_ui_origin(origin: &str, bound_addr: SocketAddr) -> bool {
    let o = origin.trim().trim_end_matches('/');
    if o.eq_ignore_ascii_case("tauri://localhost")
        || o.eq_ignore_ascii_case("http://tauri.localhost")
        || o.eq_ignore_ascii_case("https://tauri.localhost")
    {
        return true;
    }

    let port = bound_addr.port();
    let candidates = [
        format!("http://127.0.0.1:{port}"),
        format!("http://localhost:{port}"),
        format!("http://[::1]:{port}"),
    ];
    if candidates.iter().any(|c| o.eq_ignore_ascii_case(c)) {
        return true;
    }
    if port == 80
        && (o.eq_ignore_ascii_case("http://127.0.0.1")
            || o.eq_ignore_ascii_case("http://localhost")
            || o.eq_ignore_ascii_case("http://[::1]"))
    {
        return true;
    }

    let bound_ip = canonical_ip(bound_addr.ip());
    if !bound_ip.is_loopback() && !bound_ip.is_unspecified() {
        let lan_origin = match bound_ip {
            IpAddr::V4(v4) => format!("http://{v4}:{port}"),
            IpAddr::V6(v6) => format!("http://[{v6}]:{port}"),
        };
        if o.eq_ignore_ascii_case(&lan_origin) {
            return true;
        }
    }
    false
}

fn verify_request_secret(req: &Request, expected_secret: &str) -> bool {
    if let Some(auth_val) = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        && let Some(token) = auth_val
            .strip_prefix("Bearer ")
            .or_else(|| auth_val.strip_prefix("bearer "))
    {
        let trimmed = token.trim();
        if constant_time_eq(trimmed.as_bytes(), expected_secret.as_bytes()) {
            return true;
        }
    }

    // Allow `?token=` or `?secret=` query parameter strictly for WebSocket upgrade handshakes
    // on `/traffic`, `/memory`, `/logs`, and `/connections` (Mihomo / Yacd / MetaCubeXD compatibility).
    let path = req.uri().path();
    if is_ws_endpoint_path(path)
        && is_websocket_upgrade(req.headers())
        && let Some(query) = req.uri().query()
    {
        for pair in query.split('&') {
            if let Some((k, v)) = pair.split_once('=')
                && (k == "secret" || k == "token")
            {
                let decoded = percent_decode_query_val(v);
                if constant_time_eq(v.as_bytes(), expected_secret.as_bytes())
                    || constant_time_eq(decoded.as_bytes(), expected_secret.as_bytes())
                {
                    return true;
                }
            }
        }
    }

    false
}

fn attach_cors_headers(resp: &mut Response, allowed_origin: Option<&str>) {
    if let Some(origin_str) = allowed_origin
        && let Ok(val) = HeaderValue::from_str(origin_str)
    {
        let headers = resp.headers_mut();
        headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, val);
        headers.insert(
            header::ACCESS_CONTROL_ALLOW_METHODS,
            HeaderValue::from_static("GET, POST, PUT, PATCH, DELETE, OPTIONS"),
        );
        headers.insert(
            header::ACCESS_CONTROL_ALLOW_HEADERS,
            HeaderValue::from_static("authorization, content-type"),
        );
        headers.insert(
            header::ACCESS_CONTROL_MAX_AGE,
            HeaderValue::from_static("600"),
        );
        headers.insert(header::VARY, HeaderValue::from_static("Origin"));
    }
}

async fn security_and_auth_middleware(
    State(state): State<ApiState>,
    req: Request,
    next: Next,
) -> Response {
    let configured_secret = state
        .engine
        .config_snapshot()
        .secret
        .filter(|s| !s.is_empty());
    let has_configured_secret = configured_secret.is_some();
    let has_valid_secret = configured_secret
        .as_deref()
        .is_some_and(|sec| verify_request_secret(&req, sec));

    // 1. Anti-DNS-Rebinding: reject untrusted `Host` headers on ALL endpoints (including UI shell)
    if !is_allowed_host_header(
        req.headers(),
        state.bound_addr,
        has_configured_secret,
        has_valid_secret,
    ) {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "message": "Forbidden: untrusted Host header (DNS rebinding protection)"
            })),
        )
            .into_response();
    }

    let path = req.uri().path();
    let is_api = is_api_endpoint_path(path);
    let peer_addr = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0);
    let is_remote_peer = peer_addr.is_some_and(|sa| !canonical_ip(sa.ip()).is_loopback());

    let origin_opt = req
        .headers()
        .get(header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let origin_is_trusted = origin_opt
        .as_deref()
        .is_some_and(|o| is_trusted_ui_origin(o, state.bound_addr));

    // 2. Handle CORS preflight (`OPTIONS`) strictly
    if req.method() == Method::OPTIONS {
        let asks_for_auth_hdr = req
            .headers()
            .get(header::ACCESS_CONTROL_REQUEST_HEADERS)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|h| h.to_ascii_lowercase().contains("authorization"));

        if origin_is_trusted || (has_configured_secret && asks_for_auth_hdr) {
            let mut resp = StatusCode::NO_CONTENT.into_response();
            attach_cors_headers(&mut resp, origin_opt.as_deref());
            return resp;
        }
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "message": "Forbidden: cross-origin preflight rejected" })),
        )
            .into_response();
    }

    // 3. Allow static SPA shell (`/`, `/assets/*`) to load so browser can render login / dashboard,
    //    unless remote access is attempted when no `secret` is configured at all.
    if !is_api {
        if is_remote_peer && !has_configured_secret {
            return (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "message": "Forbidden: remote controller access requires a configured secret"
                })),
            )
                .into_response();
        }
        return next.run(req).await;
    }

    // 4. Remote client protection on API & WebSocket endpoints:
    //    Non-loopback peers are NEVER permitted without a configured & verified Bearer `secret`.
    if is_remote_peer {
        if !has_configured_secret {
            return (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "message": "Forbidden: remote controller access requires a configured secret"
                })),
            )
                .into_response();
        }
        if !has_valid_secret {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({
                    "message": "Unauthorized: invalid or missing Bearer secret"
                })),
            )
                .into_response();
        }
    }

    // 5. Unauthorized local webpage & cross-site CSRF protection (`Origin` + `Sec-Fetch-Site`):
    //    Blocks `https://evil.example`, `http://localhost:3000`, `Origin: null`, etc. unless
    //    authenticated with a non-empty configured Bearer `secret`.
    if let Some(ref origin) = origin_opt {
        if !origin_is_trusted && !has_valid_secret {
            return (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "message": format!("Forbidden: untrusted Origin '{origin}'")
                })),
            )
                .into_response();
        }
    } else if let Some(sec_fetch_site) = req
        .headers()
        .get("sec-fetch-site")
        .and_then(|v| v.to_str().ok())
    {
        let sfs = sec_fetch_site.trim().to_ascii_lowercase();
        if sfs != "same-origin" && sfs != "none" && !has_valid_secret {
            return (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "message": format!("Forbidden: cross-origin browser fetch rejected (Sec-Fetch-Site={sfs})")
                })),
            )
                .into_response();
        }
    }

    // 6. Enforce Bearer `secret` when configured (for loopback CLI, same-origin Web UI, & Tauri)
    if has_configured_secret && !has_valid_secret {
        let mut resp = (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({
                "message": "Unauthorized: invalid or missing Bearer secret"
            })),
        )
            .into_response();
        if origin_is_trusted {
            attach_cors_headers(&mut resp, origin_opt.as_deref());
        }
        return resp;
    }

    let allowed_cors = if origin_is_trusted || has_valid_secret {
        origin_opt
    } else {
        None
    };

    let mut resp = next.run(req).await;
    attach_cors_headers(&mut resp, allowed_cors.as_deref());
    resp
}

async fn get_version() -> impl IntoResponse {
    Json(serde_json::json!({
        "version": format!("rust-clash v{}", env!("CARGO_PKG_VERSION")),
        "meta": true,
        "premium": true,
        "features": [
            "shadowsocks-aead",
            "shadowsocks-2022-sip022",
            "vless-mlkem768x25519plus-0rtt",
            "vless-ws-0rtt",
            "trojan-tls-ws",
            "anytls-v2-padding-mux",
            "socks5-http-outbound",
            "happy-eyeballs-rfc8305",
            "fake-ip-dns-198.18.0.0/15",
            "smoltcp-userspace-tun",
            "config-firewall-audit",
            "waterfall-probe",
            "ai-endpoint-matrix",
            "mcp-stdio-server"
        ]
    }))
}

async fn get_tun_status(State(engine): State<Arc<ProxyEngine>>) -> impl IntoResponse {
    Json(engine.tun_health())
}

async fn get_configs(State(engine): State<Arc<ProxyEngine>>) -> impl IntoResponse {
    let cfg = engine.config_snapshot();
    let dns_bound = engine.dns_addr();
    let tun_health = engine.tun_health();
    Json(serde_json::json!({
        "port": 0,
        "socks-port": 0,
        "redir-port": 0,
        "tproxy-port": 0,
        "mixed-port": engine.mixed_addr().port(),
        "mixed-listen": engine.mixed_addr().to_string(),
        "dns-listen": dns_bound.map(|a| a.to_string()),
        "allow-lan": cfg.allow_lan,
        "lan-allowed-ips": cfg.lan_allowed_ips,
        "authentication-enabled": !cfg.authentication.is_empty(),
        "secret-configured": cfg.secret.as_ref().is_some_and(|s| !s.is_empty()),
        "bind-address": cfg.bind_address,
        "mode": cfg.mode.as_str(),
        "log-level": cfg.log_level,
        "ipv6": cfg.dns.ipv6,
        "tun": {
            "enable": engine.is_tun_active(),
            "virtual-enable": engine.is_virtual_tun_active(),
            "runtime-mode": engine.tun_mode().as_str(),
            "os-attached": engine.is_tun_active(),
            "stack": cfg.tun.stack,
            "device": cfg.tun.device,
            "auto-route": cfg.tun.auto_route,
            "strict-route": cfg.tun.strict_route,
            "ipv6": cfg.tun.ipv6,
            "mtu": cfg.tun.mtu,
            "last-error": engine.last_tun_error(),
            "health": tun_health,
        },
        "dns": {
            "enable": dns_bound.is_some(),
            "configured-enable": cfg.dns.enable,
            "enhanced-mode": cfg.dns.enhanced_mode,
            "ipv6": cfg.dns.ipv6,
            "fake-ip-range": cfg.dns.fake_ip_range,
            "fake-ip-entries": engine.router().dns().entry_count(),
        },
        "sysproxy": query_sysproxy_status(&engine.state_dir()),
        "autostart": AutostartManager::new().status(),
        "demo": engine.demo_info(),
        "effective-outbound": engine.router().effective_primary_outbound(),
    }))
}

#[derive(Deserialize)]
struct PatchConfigReq {
    mode: Option<RunMode>,
    #[serde(rename = "allow-lan")]
    allow_lan: Option<bool>,
    #[serde(rename = "log-level")]
    log_level: Option<String>,
    tun: Option<PatchTunReq>,
}

#[derive(Deserialize)]
struct PatchTunReq {
    enable: Option<bool>,
    #[serde(rename = "strict-route")]
    strict_route: Option<bool>,
    ipv6: Option<bool>,
}

async fn patch_configs(
    State(engine): State<Arc<ProxyEngine>>,
    Json(patch): Json<PatchConfigReq>,
) -> Response {
    if let Some(mode) = patch.mode {
        engine.set_mode(mode);
    }
    if let Some(level) = patch.log_level {
        engine.set_log_level(level);
    }
    if let Some(allow_lan) = patch.allow_lan
        && let Err(err) = engine.set_allow_lan(allow_lan).await
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "message": err.to_string() })),
        )
            .into_response();
    }
    if let Some(tun) = patch.tun
        && (tun.enable.is_some() || tun.strict_route.is_some() || tun.ipv6.is_some())
        && let Err(err) = engine
            .update_tun_options(tun.enable, tun.strict_route, tun.ipv6)
            .await
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "message": err.to_string() })),
        )
            .into_response();
    }
    StatusCode::NO_CONTENT.into_response()
}

#[derive(Deserialize)]
struct PutConfigsReq {
    path: Option<String>,
    payload: Option<String>,
}

async fn put_configs(
    State(engine): State<Arc<ProxyEngine>>,
    Json(req): Json<PutConfigsReq>,
) -> Response {
    let result = if let Some(payload) = req.payload {
        engine.reload_yaml(&payload).await
    } else if let Some(path) = req.path {
        engine.reload_from_config_path(&path).await
    } else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "message": "either 'payload' (YAML string) or 'path' must be provided"
            })),
        )
            .into_response();
    };

    match result {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(ProxyError::Routing(msg)) => (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "message": msg })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "message": e.to_string() })),
        )
            .into_response(),
    }
}

#[derive(Deserialize, Default)]
struct RawYamlQuery {
    #[serde(default)]
    include_sensitive: bool,
}

async fn get_raw_yaml(
    State(engine): State<Arc<ProxyEngine>>,
    Query(query): Query<RawYamlQuery>,
) -> Response {
    let cfg = engine.config_snapshot();
    if query.include_sensitive {
        let has_secret = cfg.secret.as_ref().is_some_and(|s| !s.is_empty());
        if !has_secret {
            return (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "message": "Revealing unredacted credentials via HTTP API requires a configured controller 'secret'"
                })),
            )
                .into_response();
        }
        let exported_uris: Vec<String> = cfg.proxies.iter().map(export_proxy_uri).collect();
        return Json(serde_json::json!({
            "yaml": engine.raw_yaml(),
            "uris": exported_uris,
            "redacted": false,
        }))
        .into_response();
    }

    let redacted_cfg = cfg.redacted();
    let redacted_uris: Vec<String> = redacted_cfg.proxies.iter().map(export_proxy_uri).collect();
    Json(serde_json::json!({
        "yaml": engine.redacted_yaml(),
        "uris": redacted_uris,
        "redacted": true,
    }))
    .into_response()
}

async fn get_proxies(State(engine): State<Arc<ProxyEngine>>) -> impl IntoResponse {
    let router = engine.router();
    let proxies = router.proxies_snapshot();
    let effective = router.effective_primary_outbound();
    Json(serde_json::json!({
        "proxies": proxies,
        "effective-outbound": effective,
    }))
}

async fn get_proxy_by_name(
    State(engine): State<Arc<ProxyEngine>>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    let proxies = engine.router().proxies_snapshot();
    match proxies.get(&name) {
        Some(info) => (StatusCode::OK, Json(serde_json::to_value(info).unwrap())).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "message": format!("proxy '{name}' not found") })),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
struct SelectProxyReq {
    name: String,
}

async fn select_proxy_in_group(
    State(engine): State<Arc<ProxyEngine>>,
    Path(group_name): Path<String>,
    Json(req): Json<SelectProxyReq>,
) -> impl IntoResponse {
    match engine.select_group_and_persist(&group_name, &req.name) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(err) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "message": err.to_string() })),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
struct DelayQuery {
    url: Option<String>,
    #[serde(default = "default_delay_timeout_ms")]
    timeout: u64,
}

fn default_delay_timeout_ms() -> u64 {
    5000
}

async fn get_proxy_delay(
    State(engine): State<Arc<ProxyEngine>>,
    Path(name): Path<String>,
    Query(q): Query<DelayQuery>,
) -> impl IntoResponse {
    let default_url = {
        let d = engine.demo_info();
        if d.enabled && !d.http_benchmark_origin.is_empty() {
            format!("{}/generate_204", d.http_benchmark_origin)
        } else {
            "http://www.gstatic.com/generate_204".to_string()
        }
    };
    let probe_url = q.url.as_deref().unwrap_or(&default_url);
    let timeout = Duration::from_millis(q.timeout.clamp(200, 15_000));

    match engine.router().test_delay(&name, probe_url, timeout).await {
        Ok(delay) => (StatusCode::OK, Json(serde_json::json!({ "delay": delay }))).into_response(),
        Err(err) => (
            StatusCode::GATEWAY_TIMEOUT,
            Json(serde_json::json!({ "message": err.to_string() })),
        )
            .into_response(),
    }
}

async fn get_rules(State(engine): State<Arc<ProxyEngine>>) -> impl IntoResponse {
    let rules = engine.router().rules_snapshot();
    Json(serde_json::json!({ "rules": rules }))
}

fn connections_snapshot_json(engine: &ProxyEngine) -> serde_json::Value {
    let (up_total, down_total) = engine.hub().totals();
    let conns = engine.hub().list_connections();
    serde_json::json!({
        "downloadTotal": down_total,
        "uploadTotal": up_total,
        "connections": conns,
        "memory": read_process_rss_bytes(),
    })
}

async fn get_or_ws_connections(
    ws_res: std::result::Result<WebSocketUpgrade, WebSocketUpgradeRejection>,
    State(engine): State<Arc<ProxyEngine>>,
) -> Response {
    match ws_res {
        Ok(ws) => ws.on_upgrade(move |socket| stream_connections_ws(socket, engine)),
        Err(_) => Json(connections_snapshot_json(&engine)).into_response(),
    }
}

async fn stream_connections_ws(mut socket: WebSocket, engine: Arc<ProxyEngine>) {
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        interval.tick().await;
        let msg = connections_snapshot_json(&engine).to_string();
        if socket.send(Message::Text(msg.into())).await.is_err() {
            break;
        }
    }
}

async fn close_all_connections(State(engine): State<Arc<ProxyEngine>>) -> impl IntoResponse {
    let closed = engine.hub().close_all_connections();
    engine
        .hub()
        .push_log("info", format!("Closed {closed} active connection(s)"));
    StatusCode::NO_CONTENT
}

async fn close_single_connection(
    State(engine): State<Arc<ProxyEngine>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if engine.hub().close_connection(&id) {
        StatusCode::NO_CONTENT.into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "message": "connection not found" })),
        )
            .into_response()
    }
}

#[derive(Deserialize)]
struct DiagnosticsQuery {
    #[serde(default = "default_diagnostics_limit")]
    limit: usize,
}

fn default_diagnostics_limit() -> usize {
    150
}

async fn get_connection_diagnostics_api(
    State(engine): State<Arc<ProxyEngine>>,
    Query(q): Query<DiagnosticsQuery>,
) -> impl IntoResponse {
    let entries = engine.hub().diagnostics_snapshot(q.limit);
    Json(serde_json::json!({
        "diagnostics": entries,
    }))
}

async fn clear_connection_diagnostics_api(
    State(engine): State<Arc<ProxyEngine>>,
) -> impl IntoResponse {
    engine.hub().clear_diagnostics();
    StatusCode::NO_CONTENT
}

async fn get_geodata_status_api(State(engine): State<Arc<ProxyEngine>>) -> impl IntoResponse {
    Json(engine.geodata_status())
}

async fn post_geodata_update_api(State(engine): State<Arc<ProxyEngine>>) -> impl IntoResponse {
    match engine.update_geodata().await {
        Ok(status) => (StatusCode::OK, Json(serde_json::json!(status))).into_response(),
        Err(err) => (
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({ "message": err.to_string() })),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
struct SetRoutingPresetReq {
    preset: String,
}

#[derive(Deserialize)]
struct SaveCustomRulesReq {
    rules: Vec<String>,
}

async fn get_routing_preset_api(State(engine): State<Arc<ProxyEngine>>) -> impl IntoResponse {
    match engine
        .ensure_profile_manager()
        .and_then(|mgr| mgr.routing_snapshot())
    {
        Ok(snap) => (StatusCode::OK, Json(serde_json::json!(snap))).into_response(),
        Err(err) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "message": err.to_string() })),
        )
            .into_response(),
    }
}

async fn put_routing_preset_api(
    State(engine): State<Arc<ProxyEngine>>,
    Json(req): Json<SetRoutingPresetReq>,
) -> impl IntoResponse {
    let choice = match crate::profile::RoutingPresetChoice::parse_str(&req.preset) {
        Ok(c) => c,
        Err(err) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "message": err.to_string() })),
            )
                .into_response();
        }
    };
    let mgr = match engine.ensure_profile_manager() {
        Ok(m) => m,
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "message": err.to_string() })),
            )
                .into_response();
        }
    };
    match mgr.apply_routing_preset(choice) {
        Ok((snap, cfg)) => {
            if let Err(err) = engine
                .activate_profile_config_with_selections(cfg, Some(&snap.selected_groups))
                .await
            {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({ "message": err.to_string() })),
                )
                    .into_response();
            }
            (StatusCode::OK, Json(serde_json::json!(snap))).into_response()
        }
        Err(err) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "message": err.to_string() })),
        )
            .into_response(),
    }
}

async fn get_routing_custom_rules_api(State(engine): State<Arc<ProxyEngine>>) -> impl IntoResponse {
    match engine
        .ensure_profile_manager()
        .and_then(|mgr| mgr.custom_rules_snapshot())
    {
        Ok(rules) => (StatusCode::OK, Json(serde_json::json!({ "rules": rules }))).into_response(),
        Err(err) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "message": err.to_string() })),
        )
            .into_response(),
    }
}

async fn put_routing_custom_rules_api(
    State(engine): State<Arc<ProxyEngine>>,
    Json(req): Json<SaveCustomRulesReq>,
) -> impl IntoResponse {
    let mgr = match engine.ensure_profile_manager() {
        Ok(m) => m,
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "message": err.to_string() })),
            )
                .into_response();
        }
    };
    match mgr.save_custom_rules(req.rules) {
        Ok((snap, cfg)) => {
            if let Err(err) = engine
                .activate_profile_config_with_selections(cfg, Some(&snap.selected_groups))
                .await
            {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({ "message": err.to_string() })),
                )
                    .into_response();
            }
            (StatusCode::OK, Json(serde_json::json!(snap))).into_response()
        }
        Err(err) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "message": err.to_string() })),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
struct DnsApiQuery {
    name: String,
    #[serde(rename = "type", default = "default_dns_qtype")]
    qtype: String,
}

fn default_dns_qtype() -> String {
    "A".to_string()
}

async fn query_dns_api(
    State(engine): State<Arc<ProxyEngine>>,
    Query(q): Query<DnsApiQuery>,
) -> impl IntoResponse {
    let qt = match q.qtype.to_ascii_uppercase().as_str() {
        "AAAA" | "28" => QTYPE_AAAA,
        _ => QTYPE_A,
    };
    let wire_req = build_dns_query(0x1337, &q.name, qt);
    let dns = Arc::clone(engine.router().dns());
    match dns.handle_dns_packet(&wire_req).await {
        Ok(wire_resp) => {
            let status_rcode = dns_response_rcode(&wire_resp).unwrap_or(0);
            let answers = extract_ip_answers(&wire_resp).unwrap_or_default();
            let formatted: Vec<serde_json::Value> = answers
                .into_iter()
                .map(|a| match a {
                    DnsAnswerData::A(v4) => serde_json::json!({
                        "type": "A",
                        "data": v4.to_string(),
                        "is_fake_ip": dns.is_fake_ip(std::net::IpAddr::V4(v4)),
                        "restored_domain": dns.lookup_domain(std::net::IpAddr::V4(v4)),
                    }),
                    DnsAnswerData::Aaaa(v6) => serde_json::json!({
                        "type": "AAAA",
                        "data": v6.to_string(),
                        "is_fake_ip": false,
                    }),
                    DnsAnswerData::Txt(txt) => serde_json::json!({
                        "type": "TXT",
                        "data": txt,
                        "is_fake_ip": false,
                    }),
                })
                .collect();
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "Status": status_rcode,
                    "Question": { "name": q.name, "type": q.qtype.to_ascii_uppercase() },
                    "bypass_fake_ip": dns.should_bypass_fake_ip(&q.name),
                    "Answer": formatted,
                })),
            )
                .into_response()
        }
        Err(err) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "message": err.to_string() })),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
struct ExplainRuleQuery {
    target: String,
    src_ip: Option<String>,
}

pub fn parse_explain_target(raw: &str) -> std::result::Result<crate::addr::TargetAddr, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("target parameter cannot be empty".to_string());
    }
    if let Ok(t) = trimmed.parse::<crate::addr::TargetAddr>() {
        return Ok(t);
    }
    if let Ok(ip) = trimmed.parse::<IpAddr>() {
        return Ok(crate::addr::TargetAddr::new_ip(ip, 443));
    }
    format!("{trimmed}:443")
        .parse::<crate::addr::TargetAddr>()
        .map_err(|e| e.to_string())
}

async fn explain_rule_api(
    State(engine): State<Arc<ProxyEngine>>,
    Query(q): Query<ExplainRuleQuery>,
) -> impl IntoResponse {
    let target = match parse_explain_target(&q.target) {
        Ok(t) => t,
        Err(msg) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "message": msg })),
            )
                .into_response();
        }
    };
    let src_ip = match q.src_ip.as_deref() {
        Some(s) if !s.trim().is_empty() => match s.trim().parse::<IpAddr>() {
            Ok(ip) => Some(ip),
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({ "message": format!("invalid src_ip: {e}") })),
                )
                    .into_response();
            }
        },
        _ => None,
    };

    let router = engine.router();
    let decision = router.route_async(src_ip, &target).await;
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "input": q.target,
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
        })),
    )
        .into_response()
}

async fn flush_dns_cache_api(State(engine): State<Arc<ProxyEngine>>) -> impl IntoResponse {
    engine.router().dns().flush_cache();
    engine
        .hub()
        .push_log("info", "Flushed DNS positive and negative caches");
    Json(serde_json::json!({
        "flushed": true,
        "cached_records": engine.router().dns().cached_record_count(),
    }))
}

async fn get_fakeip_pool(State(engine): State<Arc<ProxyEngine>>) -> impl IntoResponse {
    let dns = Arc::clone(engine.router().dns());
    let entries = dns.entries_snapshot();
    Json(serde_json::json!({
        "cidr": dns.fake_ip_net().to_string(),
        "gateway": dns.gateway_ipv4().to_string(),
        "enhanced_mode": dns.enhanced_mode(),
        "cached_records": dns.cached_record_count(),
        "count": entries.len(),
        "entries": entries,
    }))
}

#[derive(Deserialize)]
struct KeygenReq {
    #[serde(default = "default_keygen_mode")]
    mode: String,
    #[serde(default = "default_true_bool")]
    zero_rtt: bool,
    #[serde(default = "default_true_bool")]
    post_quantum: bool,
}

fn default_keygen_mode() -> String {
    "native".to_string()
}

fn default_true_bool() -> bool {
    true
}

async fn post_vless_keypair(Json(req): Json<KeygenReq>) -> impl IntoResponse {
    let Ok(xor_mode) = XorMode::parse(&req.mode) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "message": "mode must be 'native', 'xorpub', or 'random'"
            })),
        )
            .into_response();
    };

    match generate_vless_encryption_pair(xor_mode, req.zero_rtt, req.post_quantum) {
        Ok(pair) => {
            let sample_uuid = uuid::Uuid::new_v4();
            let client_yaml = format!(
                "- name: VLESS-PQ-{}\n  type: vless\n  server: your-server.example.com\n  port: 443\n  uuid: {sample_uuid}\n  encryption: {}\n  udp: true",
                pair.mode, pair.encryption
            );
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "mode": pair.mode,
                    "rtt": pair.rtt,
                    "uuid": sample_uuid,
                    "encryption": pair.encryption,
                    "decryption": pair.decryption,
                    "x25519_public_key": pair.x25519_public_key,
                    "mlkem768_encapsulation_key_bytes": pair.mlkem768_client_bytes,
                    "client_yaml_snippet": client_yaml,
                })),
            )
                .into_response()
        }
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "message": err.to_string() })),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
struct ImportUrisReq {
    uris: String,
    #[serde(default = "default_true_bool")]
    apply: bool,
    #[serde(default = "default_true_bool")]
    deduplicate: bool,
    #[serde(default = "default_true_bool")]
    auto_select: bool,
    #[serde(default)]
    profile_name: Option<String>,
}

fn summarize_node_redacted(node: &ProxyNodeConfig) -> serde_json::Value {
    match node {
        ProxyNodeConfig::Ss {
            name,
            server,
            port,
            cipher,
            udp,
            ..
        } => serde_json::json!({
            "name": name,
            "type": "ss",
            "server": server,
            "port": port,
            "cipher": cipher,
            "udp": udp,
        }),
        ProxyNodeConfig::Vless {
            name,
            server,
            port,
            tls,
            udp,
            ..
        } => {
            let transport = if node.effective_ws_opts().is_some() {
                "ws"
            } else {
                "tcp"
            };
            serde_json::json!({
                "name": name,
                "type": "vless",
                "server": server,
                "port": port,
                "tls": tls,
                "network": transport,
                "udp": udp,
            })
        }
        ProxyNodeConfig::Anytls {
            name,
            server,
            port,
            sni,
            udp,
            ..
        } => serde_json::json!({
            "name": name,
            "type": "anytls",
            "server": server,
            "port": port,
            "sni": sni,
            "udp": udp,
        }),
        ProxyNodeConfig::Trojan {
            name,
            server,
            port,
            tls,
            sni,
            udp,
            ..
        } => {
            let transport = if node.effective_ws_opts().is_some() {
                "ws"
            } else {
                "tcp"
            };
            serde_json::json!({
                "name": name,
                "type": "trojan",
                "server": server,
                "port": port,
                "tls": tls,
                "sni": sni,
                "network": transport,
                "udp": udp,
            })
        }
        ProxyNodeConfig::Socks5 {
            name,
            server,
            port,
            tls,
            udp,
            ..
        } => serde_json::json!({
            "name": name,
            "type": "socks5",
            "server": server,
            "port": port,
            "tls": tls,
            "udp": udp,
        }),
        ProxyNodeConfig::Http {
            name,
            server,
            port,
            tls,
            ..
        } => serde_json::json!({
            "name": name,
            "type": "http",
            "server": server,
            "port": port,
            "tls": tls,
            "udp": false,
        }),
    }
}

async fn post_import_uris(
    State(engine): State<Arc<ProxyEngine>>,
    Json(req): Json<ImportUrisReq>,
) -> impl IntoResponse {
    if req.apply {
        match engine
            .import_unified_live(
                &req.uris,
                req.profile_name.as_deref(),
                req.deduplicate,
                req.auto_select,
            )
            .await
        {
            Ok(report) => {
                let added_set: std::collections::HashSet<&str> =
                    report.added_nodes.iter().map(String::as_str).collect();
                let mut nodes: Vec<_> = report
                    .config
                    .proxies
                    .iter()
                    .filter(|n| added_set.contains(n.name()))
                    .map(summarize_node_redacted)
                    .collect();
                if nodes.is_empty() {
                    nodes = report
                        .config
                        .proxies
                        .iter()
                        .map(summarize_node_redacted)
                        .collect();
                }
                let eff = engine.router().effective_primary_outbound();
                (
                    StatusCode::OK,
                    Json(serde_json::json!({
                        "applied": true,
                        "input-kind": report.input_kind,
                        "count": report.added_nodes.len(),
                        "added-nodes": report.added_nodes,
                        "skipped-duplicates": report.skipped_duplicates,
                        "skipped-unsupported": report.skipped_unsupported,
                        "total-nodes": report.total_nodes,
                        "nodes": nodes,
                        "selected-groups": report.selected_groups,
                        "effective-outbound": eff,
                    })),
                )
                    .into_response()
            }
            Err(e) => {
                let safe_msg = crate::config::uri::redact_sensitive_text(&e.to_string());
                (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({ "message": safe_msg })),
                )
                    .into_response()
            }
        }
    } else {
        match crate::profile::classify_import_input(&req.uris) {
            Ok((kind, normalized)) => {
                let preview_res: Result<(
                    Vec<ProxyNodeConfig>,
                    Vec<crate::config::SkippedProxyEntry>,
                )> = match kind {
                    crate::profile::ImportInputKind::ShareUris
                    | crate::profile::ImportInputKind::Base64UriList => {
                        crate::config::uri::parse_subscription_uris_best_effort(&normalized)
                    }
                    crate::profile::ImportInputKind::ClashYaml => {
                        ClashConfig::from_yaml_str_sanitized(&normalized)
                            .map(|(c, skipped)| (c.proxies, skipped))
                    }
                    crate::profile::ImportInputKind::HttpsSubscriptionUrl => {
                        Ok((Vec::new(), Vec::new()))
                    }
                };
                match preview_res {
                    Ok((nodes, skipped)) => {
                        let summaries: Vec<_> = nodes.iter().map(summarize_node_redacted).collect();
                        (
                            StatusCode::OK,
                            Json(serde_json::json!({
                                "applied": false,
                                "input-kind": kind,
                                "count": summaries.len(),
                                "skipped-unsupported": skipped,
                                "nodes": summaries,
                            })),
                        )
                            .into_response()
                    }
                    Err(e) => {
                        let safe_msg = crate::config::uri::redact_sensitive_text(&e.to_string());
                        (
                            StatusCode::BAD_REQUEST,
                            Json(serde_json::json!({ "message": safe_msg })),
                        )
                            .into_response()
                    }
                }
            }
            Err(e) => {
                let safe_msg = crate::config::uri::redact_sensitive_text(&e.to_string());
                (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({ "message": safe_msg })),
                )
                    .into_response()
            }
        }
    }
}

#[derive(Deserialize)]
struct BenchmarkReq {
    #[serde(default = "default_bench_streams")]
    streams: usize,
    #[serde(default = "default_bench_payload_bytes")]
    payload_bytes: usize,
}

fn default_bench_streams() -> usize {
    4
}

fn default_bench_payload_bytes() -> usize {
    262_144
}

#[derive(Serialize)]
struct BenchmarkResult {
    streams: usize,
    total_bytes: usize,
    elapsed_ms: f64,
    throughput_mbps: f64,
    active_proxy_group_selection: Option<String>,
}

/// Drives real SOCKS5 + Fake-IP traffic through the Mixed Inbound port against the local Demo origin
/// so users can benchmark SS-2022, VLESS+PQ, and AnyTLS v2 live from the Web Console!
async fn post_live_benchmark(
    State(engine): State<Arc<ProxyEngine>>,
    Json(req): Json<BenchmarkReq>,
) -> impl IntoResponse {
    let demo = engine.demo_info();
    if !demo.enabled {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "message": "Live loopback benchmark requires --demo cluster mode"
            })),
        )
            .into_response();
    }

    let origin_str = demo
        .http_benchmark_origin
        .strip_prefix("http://")
        .unwrap_or(&demo.http_benchmark_origin);
    let Ok(origin_addr) = origin_str.parse::<SocketAddr>() else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "message": "invalid demo origin address" })),
        )
            .into_response();
    };

    let streams = req.streams.clamp(1, 16);
    let per_stream_bytes = req.payload_bytes.clamp(4096, 2 * 1024 * 1024);
    let mixed_addr = engine.mixed_addr();
    let mixed_auth = engine
        .config_snapshot()
        .authentication
        .first()
        .and_then(|s| {
            s.split_once(':')
                .map(|(u, p)| (u.to_string(), p.to_string()))
        });

    let fake_ip = engine.router().dns().assign_fake_ip("localhost");

    let start = Instant::now();
    let mut handles = Vec::with_capacity(streams);
    for _ in 0..streams {
        let auth_pair = mixed_auth.clone();
        handles.push(tokio::spawn(async move {
            let mut s = TcpStream::connect(mixed_addr).await?;
            let _ = s.set_nodelay(true);
            if let Some((user, pass)) = auth_pair {
                s.write_all(&[0x05, 0x01, 0x02]).await?;
                let mut greet = [0u8; 2];
                s.read_exact(&mut greet).await?;
                if greet != [0x05, 0x02] {
                    return Err(std::io::Error::other("SOCKS5 auth method rejected"));
                }
                let ub = user.as_bytes();
                let pb = pass.as_bytes();
                let mut sub = Vec::with_capacity(3 + ub.len() + pb.len());
                sub.push(0x01);
                sub.push(ub.len() as u8);
                sub.extend_from_slice(ub);
                sub.push(pb.len() as u8);
                sub.extend_from_slice(pb);
                s.write_all(&sub).await?;
                let mut auth_rep = [0u8; 2];
                s.read_exact(&mut auth_rep).await?;
                if auth_rep[1] != 0x00 {
                    return Err(std::io::Error::other("SOCKS5 RFC1929 auth failed"));
                }
            } else {
                s.write_all(&[0x05, 0x01, 0x00]).await?;
                let mut greet = [0u8; 2];
                s.read_exact(&mut greet).await?;
            }
            let mut conn_req = Vec::with_capacity(10);
            conn_req.extend_from_slice(&[0x05, 0x01, 0x00, 0x01]);
            conn_req.extend_from_slice(&fake_ip.octets());
            conn_req.extend_from_slice(&origin_addr.port().to_be_bytes());
            s.write_all(&conn_req).await?;
            let mut reply = [0u8; 10];
            s.read_exact(&mut reply).await?;
            if reply[1] != 0x00 {
                return Err(std::io::Error::other("SOCKS5 connect failed"));
            }

            let http_get = format!(
                "GET /bytes?n={per_stream_bytes} HTTP/1.1\r\nHost: localhost:{}\r\nConnection: close\r\n\r\n",
                origin_addr.port()
            );
            s.write_all(http_get.as_bytes()).await?;
            let mut resp = Vec::with_capacity(per_stream_bytes + 256);
            s.read_to_end(&mut resp).await?;
            Ok::<usize, std::io::Error>(resp.len())
        }));
    }

    let mut total_bytes = 0usize;
    for h in handles {
        match h.await {
            Ok(Ok(n)) => total_bytes += n,
            Ok(Err(e)) => {
                return (
                    StatusCode::BAD_GATEWAY,
                    Json(serde_json::json!({ "message": format!("benchmark stream failed: {e}") })),
                )
                    .into_response();
            }
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({ "message": format!("benchmark join error: {e}") })),
                )
                    .into_response();
            }
        }
    }

    let elapsed = start.elapsed();
    engine.hub().sample_tick();

    let elapsed_ms = elapsed.as_secs_f64() * 1000.0;
    let throughput_mbps = if elapsed.as_secs_f64() > 0.0 {
        (total_bytes as f64 * 8.0) / (elapsed.as_secs_f64() * 1_000_000.0)
    } else {
        0.0
    };
    let active_sel = engine
        .router()
        .proxies_snapshot()
        .get("🚀 Proxy")
        .and_then(|g| g.now.clone());

    (
        StatusCode::OK,
        Json(BenchmarkResult {
            streams,
            total_bytes,
            elapsed_ms,
            throughput_mbps,
            active_proxy_group_selection: active_sel,
        }),
    )
        .into_response()
}

async fn get_or_ws_traffic(
    ws_res: std::result::Result<WebSocketUpgrade, WebSocketUpgradeRejection>,
    State(engine): State<Arc<ProxyEngine>>,
) -> Response {
    match ws_res {
        Ok(ws) => ws.on_upgrade(move |socket| stream_traffic_ws(socket, engine)),
        Err(_) => {
            let history = engine.hub().traffic_history();
            let latest = history.last().copied().unwrap_or_default();
            Json(serde_json::json!({
                "up": latest.up,
                "down": latest.down,
                "total_up": latest.total_up,
                "total_down": latest.total_down,
                "history": history,
            }))
            .into_response()
        }
    }
}

async fn stream_traffic_ws(mut socket: WebSocket, engine: Arc<ProxyEngine>) {
    let mut rx = engine.hub().subscribe_traffic();
    loop {
        match rx.recv().await {
            Ok(point) => {
                let Ok(text) = serde_json::to_string(&point) else {
                    continue;
                };
                if socket.send(Message::Text(text.into())).await.is_err() {
                    break;
                }
            }
            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
        }
    }
}

async fn get_or_ws_memory(
    ws_res: std::result::Result<WebSocketUpgrade, WebSocketUpgradeRejection>,
) -> Response {
    match ws_res {
        Ok(ws) => ws.on_upgrade(stream_memory_ws),
        Err(_) => Json(serde_json::json!({
            "inuse": read_process_rss_bytes(),
            "oslimit": 0u64,
        }))
        .into_response(),
    }
}

async fn stream_memory_ws(mut socket: WebSocket) {
    let mut interval = tokio::time::interval(Duration::from_secs(2));
    loop {
        interval.tick().await;
        let msg = serde_json::json!({
            "inuse": read_process_rss_bytes(),
            "oslimit": 0u64,
        })
        .to_string();
        if socket.send(Message::Text(msg.into())).await.is_err() {
            break;
        }
    }
}

async fn get_or_ws_logs(
    ws_res: std::result::Result<WebSocketUpgrade, WebSocketUpgradeRejection>,
    State(engine): State<Arc<ProxyEngine>>,
) -> Response {
    match ws_res {
        Ok(ws) => ws.on_upgrade(move |socket| stream_logs_ws(socket, engine)),
        Err(_) => {
            let logs = engine.hub().recent_logs();
            Json(serde_json::json!({ "logs": logs })).into_response()
        }
    }
}

async fn stream_logs_ws(mut socket: WebSocket, engine: Arc<ProxyEngine>) {
    for entry in engine.hub().recent_logs() {
        if let Ok(text) = serde_json::to_string(&entry)
            && socket.send(Message::Text(text.into())).await.is_err()
        {
            return;
        }
    }
    let mut rx = engine.hub().subscribe_logs();
    loop {
        match rx.recv().await {
            Ok(entry) => {
                if let Ok(text) = serde_json::to_string(&entry)
                    && socket.send(Message::Text(text.into())).await.is_err()
                {
                    break;
                }
            }
            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
        }
    }
}

pub fn read_process_rss_bytes() -> u64 {
    #[cfg(target_os = "linux")]
    {
        if let Ok(statm) = std::fs::read_to_string("/proc/self/statm")
            && let Some(rss_pages_str) = statm.split_whitespace().nth(1)
            && let Ok(pages) = rss_pages_str.parse::<u64>()
        {
            return pages.saturating_mul(4096);
        }
    }
    0
}

fn ensure_profile_manager(engine: &Arc<ProxyEngine>) -> Result<Arc<ProfileManager>> {
    engine.ensure_profile_manager()
}

#[derive(Deserialize)]
struct UpsertNodeReq {
    node: ProxyNodeConfig,
    #[serde(default = "default_true_bool")]
    auto_select: bool,
}

fn node_mutation_response(
    engine: &Arc<ProxyEngine>,
    mgr: &ProfileManager,
    report: crate::profile::NodeMutationReport,
) -> Response {
    let nodes = mgr.list_active_nodes_redacted().unwrap_or_default();
    let eff = engine.router().effective_primary_outbound();
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "active-profile-id": mgr.active_profile_id(),
            "nodes": nodes,
            "added-nodes": report.added_nodes,
            "updated-node": report.updated_node,
            "removed-nodes": report.removed_nodes,
            "skipped-duplicates": report.skipped_duplicates,
            "total-nodes": report.total_nodes,
            "selected-groups": engine.router().manual_selections_snapshot(),
            "effective-outbound": eff,
        })),
    )
        .into_response()
}

async fn get_active_nodes_api(State(engine): State<Arc<ProxyEngine>>) -> Response {
    let mgr = match ensure_profile_manager(&engine) {
        Ok(m) => m,
        Err(e) => {
            let safe_msg = crate::config::uri::redact_sensitive_text(&e.to_string());
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "message": safe_msg })),
            )
                .into_response();
        }
    };
    match mgr.list_active_nodes_redacted() {
        Ok(nodes) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "active-profile-id": mgr.active_profile_id(),
                "nodes": nodes,
                "selected-groups": engine.router().manual_selections_snapshot(),
                "effective-outbound": engine.router().effective_primary_outbound(),
            })),
        )
            .into_response(),
        Err(e) => {
            let safe_msg = crate::config::uri::redact_sensitive_text(&e.to_string());
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "message": safe_msg })),
            )
                .into_response()
        }
    }
}

async fn post_create_active_node_api(
    State(engine): State<Arc<ProxyEngine>>,
    Json(raw_body): Json<serde_json::Value>,
) -> Response {
    let req: UpsertNodeReq = match serde_json::from_value(raw_body) {
        Ok(r) => r,
        Err(e) => {
            let safe_msg = crate::config::uri::redact_sensitive_text(&e.to_string());
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "message": format!("invalid node payload: {safe_msg}") })),
            )
                .into_response();
        }
    };
    let mgr = match ensure_profile_manager(&engine) {
        Ok(m) => m,
        Err(e) => {
            let safe_msg = crate::config::uri::redact_sensitive_text(&e.to_string());
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "message": safe_msg })),
            )
                .into_response();
        }
    };
    match engine
        .upsert_node_live(None, req.node, req.auto_select)
        .await
    {
        Ok(report) => node_mutation_response(&engine, &mgr, report),
        Err(e) => {
            let safe_msg = crate::config::uri::redact_sensitive_text(&e.to_string());
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "message": safe_msg })),
            )
                .into_response()
        }
    }
}

async fn put_update_active_node_api(
    State(engine): State<Arc<ProxyEngine>>,
    Path(name): Path<String>,
    Json(raw_body): Json<serde_json::Value>,
) -> Response {
    let auto_select_present = raw_body.get("auto_select").is_some();
    let mut req: UpsertNodeReq = match serde_json::from_value(raw_body) {
        Ok(r) => r,
        Err(e) => {
            let safe_msg = crate::config::uri::redact_sensitive_text(&e.to_string());
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "message": format!("invalid node payload: {safe_msg}") })),
            )
                .into_response();
        }
    };
    if !auto_select_present {
        req.auto_select = false;
    }
    let mgr = match ensure_profile_manager(&engine) {
        Ok(m) => m,
        Err(e) => {
            let safe_msg = crate::config::uri::redact_sensitive_text(&e.to_string());
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "message": safe_msg })),
            )
                .into_response();
        }
    };
    match engine
        .upsert_node_live(Some(&name), req.node, req.auto_select)
        .await
    {
        Ok(report) => node_mutation_response(&engine, &mgr, report),
        Err(e) => {
            let safe_msg = crate::config::uri::redact_sensitive_text(&e.to_string());
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "message": safe_msg })),
            )
                .into_response()
        }
    }
}

async fn delete_active_node_api(
    State(engine): State<Arc<ProxyEngine>>,
    Path(name): Path<String>,
) -> Response {
    let mgr = match ensure_profile_manager(&engine) {
        Ok(m) => m,
        Err(e) => {
            let safe_msg = crate::config::uri::redact_sensitive_text(&e.to_string());
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "message": safe_msg })),
            )
                .into_response();
        }
    };
    match engine.delete_node_live(&name).await {
        Ok(report) => node_mutation_response(&engine, &mgr, report),
        Err(e) => {
            let safe_msg = crate::config::uri::redact_sensitive_text(&e.to_string());
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "message": safe_msg })),
            )
                .into_response()
        }
    }
}

async fn post_deduplicate_active_nodes_api(State(engine): State<Arc<ProxyEngine>>) -> Response {
    let mgr = match ensure_profile_manager(&engine) {
        Ok(m) => m,
        Err(e) => {
            let safe_msg = crate::config::uri::redact_sensitive_text(&e.to_string());
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "message": safe_msg })),
            )
                .into_response();
        }
    };
    match engine.deduplicate_nodes_live().await {
        Ok(report) => node_mutation_response(&engine, &mgr, report),
        Err(e) => {
            let safe_msg = crate::config::uri::redact_sensitive_text(&e.to_string());
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "message": safe_msg })),
            )
                .into_response()
        }
    }
}

async fn get_profiles_api(State(engine): State<Arc<ProxyEngine>>) -> Response {
    match ensure_profile_manager(&engine) {
        Ok(mgr) => (StatusCode::OK, Json(mgr.snapshot())).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "message": crate::config::uri::redact_sensitive_text(&e.to_string()) })),
        )
            .into_response(),
    }
}

async fn post_create_profile_api(
    State(engine): State<Arc<ProxyEngine>>,
    Json(spec): Json<CreateProfileSpec>,
) -> Response {
    let mgr = match ensure_profile_manager(&engine) {
        Ok(m) => m,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "message": crate::config::uri::redact_sensitive_text(&e.to_string()) })),
            )
                .into_response();
        }
    };

    match mgr.create_profile_detailed(spec).await {
        Ok((meta, maybe_cfg, skipped_unsupported)) => {
            if let Some(cfg) = maybe_cfg
                && let Err(err) = engine
                    .activate_profile_config_with_selections(cfg, Some(&meta.selected_groups))
                    .await
            {
                let safe_err = crate::config::uri::redact_sensitive_text(&err.to_string());
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "message": format!("profile saved as '{}', but runtime activation failed: {safe_err}", meta.id)
                    })),
                )
                    .into_response();
            }
            engine.hub().push_log(
                "info",
                format!(
                    "Created profile '{}' ({} proxy nodes)",
                    meta.name, meta.proxy_count
                ),
            );
            (
                StatusCode::CREATED,
                Json(serde_json::json!({
                    "profile": meta,
                    "skipped-unsupported": skipped_unsupported,
                    "snapshot": mgr.snapshot(),
                })),
            )
                .into_response()
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "message": crate::config::uri::redact_sensitive_text(&e.to_string()) })),
        )
            .into_response(),
    }
}

async fn put_activate_profile_api(
    State(engine): State<Arc<ProxyEngine>>,
    Path(id): Path<String>,
) -> Response {
    let mgr = match ensure_profile_manager(&engine) {
        Ok(m) => m,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "message": crate::config::uri::redact_sensitive_text(&e.to_string()) })),
            )
                .into_response();
        }
    };

    match mgr.set_active_profile(&id) {
        Ok(cfg) => {
            let sel = mgr.active_selected_groups();
            match engine
                .activate_profile_config_with_selections(cfg, Some(&sel))
                .await
            {
                Ok(()) => {
                    engine
                        .hub()
                        .push_log("info", format!("Activated profile '{id}'"));
                    (StatusCode::OK, Json(mgr.snapshot())).into_response()
                }
                Err(e) => (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({ "message": crate::config::uri::redact_sensitive_text(&e.to_string()) })),
                )
                    .into_response(),
            }
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "message": crate::config::uri::redact_sensitive_text(&e.to_string()) })),
        )
            .into_response(),
    }
}

async fn post_refresh_profile_api(
    State(engine): State<Arc<ProxyEngine>>,
    Path(id): Path<String>,
) -> Response {
    let mgr = match ensure_profile_manager(&engine) {
        Ok(m) => m,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "message": crate::config::uri::redact_sensitive_text(&e.to_string()) })),
            )
                .into_response();
        }
    };

    let prev_cfg_opt = mgr.load_profile_config_by_id(&id);

    match mgr.refresh_subscription(&id).await {
        Ok((meta, cfg, is_active)) => {
            let diff_opt = prev_cfg_opt
                .as_ref()
                .map(|prev| crate::audit::diff_configs(prev, &cfg));
            let audit = crate::audit::audit_config(&cfg);

            if is_active
                && !engine.demo_info().enabled
                && let Err(e) = engine
                    .activate_profile_config_with_selections(cfg, Some(&meta.selected_groups))
                    .await
            {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({ "message": crate::config::uri::redact_sensitive_text(&e.to_string()) })),
                )
                    .into_response();
            }
            engine.hub().push_log(
                "info",
                format!(
                    "Refreshed subscription '{}' ({} nodes, security grade {} {}/100)",
                    meta.name, meta.proxy_count, audit.grade, audit.score
                ),
            );
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "profile": meta,
                    "snapshot": mgr.snapshot(),
                    "diff": diff_opt,
                    "audit_score": audit.score,
                    "audit_grade": audit.grade,
                })),
            )
                .into_response()
        }
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({ "message": crate::config::uri::redact_sensitive_text(&e.to_string()) })),
        )
            .into_response(),
    }
}

async fn delete_profile_api(
    State(engine): State<Arc<ProxyEngine>>,
    Path(id): Path<String>,
) -> Response {
    let mgr = match ensure_profile_manager(&engine) {
        Ok(m) => m,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "message": crate::config::uri::redact_sensitive_text(&e.to_string()) })),
            )
                .into_response();
        }
    };

    match mgr.delete_profile(&id) {
        Ok(()) => {
            engine
                .hub()
                .push_log("info", format!("Deleted profile '{id}'"));
            (StatusCode::OK, Json(mgr.snapshot())).into_response()
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "message": crate::config::uri::redact_sensitive_text(&e.to_string()) })),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
struct DemoToggleReq {
    enable: bool,
}

async fn post_demo_toggle_api(
    State(engine): State<Arc<ProxyEngine>>,
    Json(req): Json<DemoToggleReq>,
) -> Response {
    let _ = ensure_profile_manager(&engine);
    match engine.set_demo_sandbox(req.enable).await {
        Ok(()) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "demo": engine.demo_info(),
                "mode": engine.config_snapshot().mode.as_str(),
            })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "message": crate::config::uri::redact_sensitive_text(&e.to_string()) })),
        )
            .into_response(),
    }
}

async fn get_sysproxy_api(State(engine): State<Arc<ProxyEngine>>) -> impl IntoResponse {
    Json(query_sysproxy_status(&engine.state_dir()))
}

#[derive(Deserialize)]
struct PatchSysProxyReq {
    enable: bool,
    bypass: Option<Vec<String>>,
}

async fn patch_sysproxy_api(
    State(engine): State<Arc<ProxyEngine>>,
    Json(req): Json<PatchSysProxyReq>,
) -> Response {
    let state_dir = engine.state_dir();
    if req.enable {
        let port = engine.mixed_addr().port();
        let bypass = req.bypass.unwrap_or_default();
        match enable_system_proxy("127.0.0.1", port, &bypass, &state_dir) {
            Ok(status) => {
                engine.hub().push_log(
                    "info",
                    format!("Enabled OS System Proxy -> 127.0.0.1:{port}"),
                );
                (StatusCode::OK, Json(status)).into_response()
            }
            Err(e) => (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "message": e.to_string() })),
            )
                .into_response(),
        }
    } else {
        match disable_system_proxy(&state_dir) {
            Ok(status) => {
                engine
                    .hub()
                    .push_log("info", "Restored original OS System Proxy settings");
                (StatusCode::OK, Json(status)).into_response()
            }
            Err(e) => (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "message": e.to_string() })),
            )
                .into_response(),
        }
    }
}

async fn get_autostart_api() -> impl IntoResponse {
    Json(AutostartManager::new().status())
}

#[derive(Deserialize)]
struct PatchAutostartReq {
    enable: bool,
}

async fn patch_autostart_api(
    State(engine): State<Arc<ProxyEngine>>,
    Json(req): Json<PatchAutostartReq>,
) -> Response {
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "message": format!("cannot resolve executable path: {e}") })),
            )
                .into_response();
        }
    };
    let mgr = AutostartManager::new();
    match mgr.set_enabled(req.enable, &exe, &[]) {
        Ok(()) => {
            engine.hub().push_log(
                "info",
                format!("Updated Start-at-Login autostart -> {}", req.enable),
            );
            (StatusCode::OK, Json(mgr.status())).into_response()
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "message": e.to_string() })),
        )
            .into_response(),
    }
}

fn scrub_sensitive_substrings(raw: &str, known_secrets: &[String]) -> String {
    let mut out = raw.to_string();
    for sec in known_secrets {
        if sec.len() >= 4 {
            out = out.replace(sec, "***REDACTED***");
        }
    }
    for scheme in [
        "ss://",
        "vless://",
        "trojan://",
        "anytls://",
        "socks5://",
        "socks5h://",
        "socks://",
        "http-proxy://",
        "https-proxy://",
        "https://",
        "http://",
    ] {
        let mut cursor = 0usize;
        while let Some(rel) = out[cursor..].find(scheme) {
            let start = cursor + rel;
            let end = out[start..]
                .find(|c: char| c.is_whitespace() || c == '"' || c == '\'' || c == ')')
                .map(|len| start + len)
                .unwrap_or(out.len());
            let candidate = &out[start..end];
            let replacement = if scheme == "http://" || scheme == "https://" {
                crate::profile::redact_subscription_url(candidate)
            } else {
                format!("{scheme}***REDACTED***")
            };
            out.replace_range(start..end, &replacement);
            cursor = start + replacement.len();
        }
    }
    crate::config::uri::redact_sensitive_text(&out)
}

async fn get_diagnostics_export_api(State(engine): State<Arc<ProxyEngine>>) -> impl IntoResponse {
    let cfg = engine.config_snapshot();
    let mut known_secrets = Vec::new();
    if let Some(ref s) = cfg.secret
        && !s.is_empty()
    {
        known_secrets.push(s.clone());
    }
    for auth in &cfg.authentication {
        known_secrets.push(auth.clone());
        if let Some((_, pass)) = auth.split_once(':') {
            known_secrets.push(pass.to_string());
        }
    }
    for p in &cfg.proxies {
        match p {
            ProxyNodeConfig::Ss { password, .. }
            | ProxyNodeConfig::Anytls { password, .. }
            | ProxyNodeConfig::Trojan { password, .. } => {
                if !password.is_empty() && password != REDACTED_SECRET {
                    known_secrets.push(password.clone());
                }
            }
            ProxyNodeConfig::Vless {
                uuid, encryption, ..
            } => {
                known_secrets.push(uuid.to_string());
                if !encryption.is_empty() && encryption != "none" && encryption != REDACTED_SECRET {
                    known_secrets.push(encryption.clone());
                }
            }
            ProxyNodeConfig::Socks5 { password, .. } => {
                if let Some(pass) = password
                    && !pass.is_empty()
                    && pass != REDACTED_SECRET
                {
                    known_secrets.push(pass.clone());
                }
            }
            ProxyNodeConfig::Http {
                password, headers, ..
            } => {
                if let Some(pass) = password
                    && !pass.is_empty()
                    && pass != REDACTED_SECRET
                {
                    known_secrets.push(pass.clone());
                }
                for (k, v) in headers {
                    let kl = k.to_ascii_lowercase();
                    if (kl.contains("auth") || kl.contains("token") || kl.contains("cookie"))
                        && !v.is_empty()
                        && v != REDACTED_SECRET
                    {
                        known_secrets.push(v.clone());
                    }
                }
            }
        }
    }

    let profiles = ensure_profile_manager(&engine).ok().map(|m| m.snapshot());
    let router = engine.router();
    let dns = router.dns();
    let logs_redacted: Vec<serde_json::Value> = engine
        .hub()
        .recent_logs()
        .into_iter()
        .map(|l| {
            serde_json::json!({
                "timestamp_ms": l.timestamp_ms,
                "level": l.level,
                "payload": scrub_sensitive_substrings(&l.payload, &known_secrets),
            })
        })
        .collect();

    Json(serde_json::json!({
        "product": "rust-clash",
        "version": env!("CARGO_PKG_VERSION"),
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "exported_at_ms": TelemetryHub::now_ms(),
        "mixed_listen": engine.mixed_addr().to_string(),
        "dns_listen": engine.dns_addr().map(|a| a.to_string()),
        "mode": cfg.mode.as_str(),
        "demo_sandbox_active": engine.demo_info().enabled,
        "config_redacted_yaml": scrub_sensitive_substrings(&engine.redacted_yaml(), &known_secrets),
        "tun_health": engine.tun_health(),
        "sysproxy": query_sysproxy_status(&engine.state_dir()),
        "autostart": AutostartManager::new().status(),
        "profiles": profiles,
        "dns_stats": {
            "enhanced_mode": dns.enhanced_mode(),
            "fake_ip_cidr": dns.fake_ip_net().to_string(),
            "fake_ip_entries": dns.entry_count(),
            "cached_records": dns.cached_record_count(),
        },
        "recent_logs": logs_redacted,
    }))
}

#[derive(Deserialize, Default)]
struct AuditQuery {
    #[serde(default)]
    resolve_dns: bool,
}

async fn get_diagnostics_audit_api(
    State(engine): State<Arc<ProxyEngine>>,
    Query(query): Query<AuditQuery>,
) -> impl IntoResponse {
    let cfg = engine.config_snapshot();
    let router = engine.router();
    let report = crate::audit::audit_config_live(&cfg, &router, query.resolve_dns).await;
    Json(report)
}

#[derive(Deserialize, Default)]
struct PostAuditReq {
    yaml: Option<String>,
    #[serde(default)]
    diff_against_active: bool,
    #[serde(default)]
    resolve_dns: bool,
}

async fn post_diagnostics_audit_api(
    State(engine): State<Arc<ProxyEngine>>,
    Json(req): Json<PostAuditReq>,
) -> Response {
    let active_cfg = engine.config_snapshot();
    let has_draft_yaml = req
        .yaml
        .as_deref()
        .is_some_and(|raw| !raw.trim().is_empty());
    let target_cfg = match req.yaml.as_deref() {
        Some(raw) if !raw.trim().is_empty() => match ClashConfig::from_yaml_str_sanitized(raw) {
            Ok((mut parsed, _skipped)) => {
                parsed.restore_redacted_from(&active_cfg);
                parsed
            }
            Err(e) => {
                let safe_err = crate::config::uri::redact_sensitive_text(&e.to_string());
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({ "message": safe_err })),
                )
                    .into_response();
            }
        },
        _ => active_cfg.clone(),
    };

    let audit = if has_draft_yaml {
        crate::audit::audit_config(&target_cfg)
    } else {
        let router = engine.router();
        crate::audit::audit_config_live(&target_cfg, &router, req.resolve_dns).await
    };
    let diff = if req.diff_against_active && has_draft_yaml {
        Some(crate::audit::diff_configs(&active_cfg, &target_cfg))
    } else {
        None
    };

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "audit": audit,
            "diff": diff,
        })),
    )
        .into_response()
}

/// Global concurrency guard preventing diagnostic probe endpoints from being abused
/// for concurrent connection exhaustion.
static PROBE_API_SEMAPHORE: std::sync::LazyLock<tokio::sync::Semaphore> =
    std::sync::LazyLock::new(|| tokio::sync::Semaphore::new(4));

fn demo_allowed_private_addrs(engine: &ProxyEngine) -> Vec<SocketAddr> {
    let demo = engine.demo_info();
    if !demo.enabled {
        return Vec::new();
    }
    let mut allowed = Vec::new();
    if !demo.http_benchmark_origin.is_empty()
        && let Ok(parsed) = url::Url::parse(&demo.http_benchmark_origin)
        && let Some(raw_host) = parsed.host_str()
        && let Some(port) = parsed.port_or_known_default()
    {
        let clean = raw_host.trim_start_matches('[').trim_end_matches(']');
        if let Ok(ip) = clean.parse::<IpAddr>() {
            allowed.push(SocketAddr::new(canonical_ip(ip), port));
        } else if clean.eq_ignore_ascii_case("localhost") {
            allowed.push(SocketAddr::from(([127, 0, 0, 1], port)));
            allowed.push(SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], port)));
        }
    }
    if let Some(dns_addr) = engine.dns_addr() {
        allowed.push(SocketAddr::new(
            canonical_ip(dns_addr.ip()),
            dns_addr.port(),
        ));
    }
    allowed
}

#[derive(Deserialize, Default)]
struct WaterfallProbeReq {
    url: Option<String>,
    #[serde(default = "default_true_bool")]
    check_udp: bool,
    udp_dns_target: Option<String>,
    #[serde(default = "default_delay_timeout_ms", alias = "timeout_ms")]
    timeout: u64,
}

async fn post_proxy_waterfall_probe_api(
    State(engine): State<Arc<ProxyEngine>>,
    Path(name): Path<String>,
    Json(req): Json<WaterfallProbeReq>,
) -> Response {
    let Ok(_permit) = PROBE_API_SEMAPHORE.try_acquire() else {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({
                "message": "Too many concurrent diagnostic probes in flight (max 4); retry shortly."
            })),
        )
            .into_response();
    };

    let demo = engine.demo_info();
    let default_url = if demo.enabled && !demo.http_benchmark_origin.is_empty() {
        format!("{}/generate_204", demo.http_benchmark_origin)
    } else {
        "https://api.github.com/".to_string()
    };
    let probe_url = req
        .url
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(&default_url);

    let fallback_demo_udp = if demo.enabled {
        engine.dns_addr().map(|a| a.to_string())
    } else {
        None
    };
    let udp_target_ref = req
        .udp_dns_target
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .or(fallback_demo_udp.as_deref());

    let allowed_private = demo_allowed_private_addrs(&engine);
    let router = engine.router();
    let cfg = engine.config_snapshot();
    let extra_ca = engine.extra_ca_der();
    let timeout = Duration::from_millis(req.timeout.clamp(200, 15_000));

    match crate::probe::probe_target_waterfall(
        &router,
        &cfg,
        &name,
        probe_url,
        crate::probe::ProbeOptions {
            extra_ca_der: &extra_ca,
            check_udp: req.check_udp,
            udp_dns_target: udp_target_ref,
            timeout,
            allow_private_targets: false,
            allowed_private_addrs: &allowed_private,
        },
    )
    .await
    {
        Ok(report) => (StatusCode::OK, Json(report)).into_response(),
        Err(ProxyError::Routing(msg)) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "message": crate::config::uri::redact_sensitive_text(&msg) })),
        )
            .into_response(),
        Err(err) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "message": crate::config::uri::redact_sensitive_text(&err.to_string()) })),
        )
            .into_response(),
    }
}

#[derive(Deserialize, Default)]
struct EndpointMatrixReq {
    targets: Option<Vec<crate::probe::MatrixEndpointSpec>>,
    udp_dns_target: Option<String>,
    #[serde(default = "default_delay_timeout_ms", alias = "timeout_ms")]
    timeout: u64,
}

async fn post_proxy_endpoint_matrix_api(
    State(engine): State<Arc<ProxyEngine>>,
    Path(name): Path<String>,
    Json(req): Json<EndpointMatrixReq>,
) -> Response {
    let Ok(_permit) = PROBE_API_SEMAPHORE.try_acquire() else {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({
                "message": "Too many concurrent diagnostic probes in flight (max 4); retry shortly."
            })),
        )
            .into_response();
    };

    let demo = engine.demo_info();
    let demo_origin = if demo.enabled && !demo.http_benchmark_origin.is_empty() {
        Some(demo.http_benchmark_origin.as_str())
    } else {
        None
    };
    let targets = match req.targets {
        Some(list) if !list.is_empty() => list.into_iter().take(12).collect(),
        _ => crate::probe::default_matrix_targets(demo_origin),
    };

    let fallback_demo_udp = if demo.enabled {
        engine.dns_addr().map(|a| a.to_string())
    } else {
        None
    };
    let udp_target_ref = req
        .udp_dns_target
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .or(fallback_demo_udp.as_deref());

    let allowed_private = demo_allowed_private_addrs(&engine);
    let router = engine.router();
    let cfg = engine.config_snapshot();
    let extra_ca = engine.extra_ca_der();
    let timeout = Duration::from_millis(req.timeout.clamp(200, 15_000));

    match crate::probe::probe_endpoint_matrix(
        &router,
        &cfg,
        &name,
        targets,
        crate::probe::ProbeOptions {
            extra_ca_der: &extra_ca,
            check_udp: true,
            udp_dns_target: udp_target_ref,
            timeout,
            allow_private_targets: false,
            allowed_private_addrs: &allowed_private,
        },
    )
    .await
    {
        Ok(report) => (StatusCode::OK, Json(report)).into_response(),
        Err(ProxyError::Routing(msg)) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "message": crate::config::uri::redact_sensitive_text(&msg) })),
        )
            .into_response(),
        Err(err) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "message": crate::config::uri::redact_sensitive_text(&err.to_string()) })),
        )
            .into_response(),
    }
}

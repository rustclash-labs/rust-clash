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
        build_dns_query, dns_response_rcode, extract_dns_display_answers, format_qtype_name,
        parse_qtype_str,
    },
    engine::ProxyEngine,
    error::{ProxyError, Result},
    inbound::mixed::canonical_ip,
    outbound::vless::encryption::{config::XorMode, generate_vless_encryption_pair},
    platform::{
        autostart::AutostartManager,
        sysproxy::{disable_system_proxy, enable_system_proxy, query_sysproxy_status},
    },
    profile::{CreateProfileSpec, ProfileManager, ProfileSettingsPatch},
    tracker::TelemetryHub,
};

/// Generates a 256-bit (32-byte, 64 lowercase hex characters) controller secret
/// directly from the OS CSPRNG (`rand::rng()`).
pub fn generate_ephemeral_secret() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Returns the engine's current controller secret if non-empty, or generates a fresh
/// 256-bit OS CSPRNG hex secret.
pub fn ensure_controller_secret(engine: &ProxyEngine) -> String {
    engine
        .config_snapshot()
        .secret
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .unwrap_or_else(generate_ephemeral_secret)
}

#[derive(Clone)]
pub struct ApiState {
    pub engine: Arc<ProxyEngine>,
    pub bound_addr: SocketAddr,
    pub started_with_secret: bool,
}

#[derive(Clone, Copy, Debug, Default)]
struct ControllerSecretContext {
    started_with_secret: bool,
    has_valid_secret: bool,
}

#[derive(Clone)]
struct WsShutdownWatch(Option<watch::Receiver<bool>>);

pub fn build_api_router(engine: Arc<ProxyEngine>) -> AxumRouter {
    let fallback_addr = engine
        .config_snapshot()
        .external_controller
        .parse::<SocketAddr>()
        .unwrap_or_else(|_| SocketAddr::from(([127, 0, 0, 1], 9090)));
    build_api_router_with_addr(engine, fallback_addr)
}

pub fn build_api_router_with_addr(engine: Arc<ProxyEngine>, bound_addr: SocketAddr) -> AxumRouter {
    build_api_router_with_addr_and_shutdown(engine, bound_addr, None)
}

fn build_api_router_with_addr_and_shutdown(
    engine: Arc<ProxyEngine>,
    bound_addr: SocketAddr,
    api_shutdown: Option<watch::Receiver<bool>>,
) -> AxumRouter {
    let started_with_secret = engine
        .config_snapshot()
        .secret
        .as_ref()
        .is_some_and(|s| !s.trim().is_empty());
    let api_state = ApiState {
        engine: Arc::clone(&engine),
        bound_addr,
        started_with_secret,
    };

    AxumRouter::new()
        .route("/version", get(get_version))
        .route(
            "/configs",
            get(get_configs).patch(patch_configs).put(put_configs),
        )
        .route("/configs/raw", get(get_raw_yaml).put(put_configs))
        .route("/proxies", get(get_proxies))
        .route(
            "/proxies/{name}",
            get(get_proxy_by_name).put(select_proxy_in_group),
        )
        .route("/proxies/{name}/delay", get(get_proxy_delay))
        .route("/group/{name}/delay", get(get_group_delay))
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
        .route(
            "/profiles/{id}",
            delete(delete_profile_api).patch(patch_profile_settings_api),
        )
        .route(
            "/profiles/{id}/raw",
            get(get_profile_raw_yaml_api).put(put_profile_raw_yaml_api),
        )
        .route("/profiles/{id}/activate", put(put_activate_profile_api))
        .route("/profiles/{id}/refresh", post(post_refresh_profile_api))
        .route("/demo/toggle", post(post_demo_toggle_api))
        .route("/diagnostics/export", get(get_diagnostics_export_api))
        .route(
            "/diagnostics/audit",
            get(get_diagnostics_audit_api).post(post_diagnostics_audit_api),
        )
        .route(
            "/diagnostics/site-check",
            post(post_diagnostics_site_check_api),
        )
        .route("/tools/ip", get(get_exit_ip_api))
        .route("/tools/vless-keypair", post(post_vless_keypair))
        .route("/tools/benchmark", post(post_live_benchmark))
        .route("/traffic", get(get_or_ws_traffic))
        .route("/memory", get(get_or_ws_memory))
        .route("/logs", get(get_or_ws_logs))
        .fallback(serve_embedded_spa)
        .layer(axum::extract::DefaultBodyLimit::max(10 * 1024 * 1024))
        .layer(axum::extract::Extension(WsShutdownWatch(api_shutdown)))
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
        .is_some_and(|s| !s.trim().is_empty());
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
    let app = build_api_router_with_addr_and_shutdown(engine, bound, Some(shutdown.clone()));

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
            | "/group"
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
            | "/tools/ip"
            | "/tools/vless-keypair"
            | "/tools/benchmark"
            | "/traffic"
            | "/memory"
            | "/logs"
    ) || path.starts_with("/proxies/")
        || path.starts_with("/group/")
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
    mut req: Request,
    next: Next,
) -> Response {
    let configured_secret = state
        .engine
        .config_snapshot()
        .secret
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let has_configured_secret = configured_secret.is_some();
    let has_valid_secret = configured_secret
        .as_deref()
        .is_some_and(|sec| verify_request_secret(&req, sec));

    let path = req.uri().path();
    let is_api = is_api_endpoint_path(path);
    let is_static_spa_read = !is_api
        && !is_websocket_upgrade(req.headers())
        && matches!(*req.method(), Method::GET | Method::HEAD);
    let asks_for_auth_hdr = req.method() == Method::OPTIONS
        && req
            .headers()
            .get(header::ACCESS_CONTROL_REQUEST_HEADERS)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|h| h.to_ascii_lowercase().contains("authorization"));
    let has_nonempty_host = req
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|h| !extract_host_without_port(h).is_empty());

    // 1. Anti-DNS-Rebinding: reject untrusted `Host` headers on all unauthenticated API/WS endpoints,
    //    while allowing static embedded SPA `GET`/`HEAD` routes (`/`, `/index.html`, `/assets/*`)
    //    over LAN hostnames (e.g. `router.local:9090`) so browsers can load the login shell.
    let allow_lan_hostname_bypass =
        has_nonempty_host && (is_static_spa_read || (has_configured_secret && asks_for_auth_hdr));
    if !allow_lan_hostname_bypass
        && !is_allowed_host_header(
            req.headers(),
            state.bound_addr,
            has_configured_secret,
            has_valid_secret,
        )
    {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "message": "Forbidden: untrusted Host header (DNS rebinding protection)"
            })),
        )
            .into_response();
    }

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

    req.extensions_mut().insert(ControllerSecretContext {
        started_with_secret: state.started_with_secret,
        has_valid_secret,
    });

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
            "site-doctor",
            "mcp-stdio-server"
        ]
    }))
}

async fn get_tun_status(State(engine): State<Arc<ProxyEngine>>) -> impl IntoResponse {
    Json(engine.tun_health())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LanIpv4Candidate {
    Preferred(std::net::Ipv4Addr),
    LinkLocalFallback(std::net::Ipv4Addr),
    Rejected,
}

fn classify_lan_ipv4_candidate(ip: IpAddr, fake_ip_net: ipnet::Ipv4Net) -> LanIpv4Candidate {
    let IpAddr::V4(v4) = ip else {
        return LanIpv4Candidate::Rejected;
    };
    if v4.is_unspecified()
        || v4.is_loopback()
        || v4.is_multicast()
        || v4.is_broadcast()
        || fake_ip_net.contains(&v4)
    {
        return LanIpv4Candidate::Rejected;
    }
    if v4.is_link_local() {
        return LanIpv4Candidate::LinkLocalFallback(v4);
    }
    LanIpv4Candidate::Preferred(v4)
}

fn select_lan_ipv4_candidate<I>(candidates: I, fake_ip_net: ipnet::Ipv4Net) -> Option<String>
where
    I: IntoIterator<Item = IpAddr>,
{
    let mut link_local_fallback: Option<std::net::Ipv4Addr> = None;
    for ip in candidates {
        match classify_lan_ipv4_candidate(ip, fake_ip_net) {
            LanIpv4Candidate::Preferred(v4) => return Some(v4.to_string()),
            LanIpv4Candidate::LinkLocalFallback(v4) => {
                link_local_fallback.get_or_insert(v4);
            }
            LanIpv4Candidate::Rejected => {}
        }
    }
    link_local_fallback.map(|ip| ip.to_string())
}

fn detect_primary_lan_ipv4_with_protector(
    fake_ip_net: ipnet::Ipv4Net,
    protector: &dyn crate::platform::socket_protect::SocketProtector,
) -> Option<String> {
    const PROBE_TARGETS: [SocketAddr; 2] = [
        SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(223, 5, 5, 5)), 53),
        SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 100, 1)), 80),
    ];
    let mut probed_locals = Vec::with_capacity(PROBE_TARGETS.len());
    for probe_addr in PROBE_TARGETS {
        let Ok(sock) = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        ) else {
            continue;
        };
        if protector.protect_udp(&sock, Some(probe_addr)).is_err() {
            continue;
        }
        let bind_addr = SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0);
        if sock.bind(&bind_addr.into()).is_err() {
            continue;
        }
        if sock.connect(&probe_addr.into()).is_err() {
            continue;
        }
        if let Ok(local) = sock.local_addr()
            && let Some(local_v4) = local.as_socket_ipv4()
        {
            let ip = IpAddr::V4(*local_v4.ip());
            if matches!(
                classify_lan_ipv4_candidate(ip, fake_ip_net),
                LanIpv4Candidate::Preferred(_)
            ) {
                return Some(local_v4.ip().to_string());
            }
            probed_locals.push(ip);
        }
    }
    select_lan_ipv4_candidate(probed_locals, fake_ip_net)
}

fn detect_primary_lan_ipv4(fake_ip_net: ipnet::Ipv4Net) -> Option<String> {
    let protector = crate::platform::socket_protect::global_socket_protector();
    detect_primary_lan_ipv4_with_protector(fake_ip_net, protector.as_ref())
}

async fn get_configs(State(engine): State<Arc<ProxyEngine>>) -> impl IntoResponse {
    let cfg = engine.config_snapshot();
    let router = engine.router();
    let dns_bound = engine.dns_addr();
    let tun_health = engine.tun_health();
    let tun_ip = if engine.is_tun_active() || engine.is_virtual_tun_active() {
        tun_health
            .ipv4_cidr
            .as_deref()
            .and_then(|s| s.split('/').next())
            .filter(|s| !s.is_empty())
            .map(ToOwned::to_owned)
            .or_else(|| Some(router.dns().gateway_ipv4().to_string()))
    } else {
        None
    };
    let lan_ip = detect_primary_lan_ipv4(router.dns().fake_ip_net());
    let rss_bytes = read_process_rss_bytes();
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
        "secret-configured": cfg.secret.as_ref().is_some_and(|s| !s.trim().is_empty()),
        "bind-address": cfg.bind_address,
        "mode": cfg.mode.as_str(),
        "unified-delay": cfg.unified_delay,
        "log-level": cfg.log_level,
        "ipv6": cfg.dns.ipv6,
        "started-at-ms": engine.hub().started_at_ms(),
        "uptime-secs": engine.hub().uptime_secs(),
        "tun-ip": tun_ip,
        "lan-ip": lan_ip,
        "intranet-ip": lan_ip,
        "rule-count": router.rules_snapshot().len(),
        "proxy-count": cfg.proxies.len(),
        "group-count": cfg.proxy_groups.len(),
        "process-rss-bytes": (rss_bytes > 0).then_some(rss_bytes),
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
            "route-exclude-address": cfg.tun.route_exclude_address,
            "last-error": engine.last_tun_error(),
            "health": tun_health,
        },
        "dns": {
            "enable": dns_bound.is_some(),
            "configured-enable": cfg.dns.enable,
            "enhanced-mode": cfg.dns.enhanced_mode,
            "ipv6": cfg.dns.ipv6,
            "fake-ip-range": cfg.dns.fake_ip_range,
            "fake-ip-entries": router.dns().entry_count(),
            "total-queries": router.dns().total_queries(),
        },
        "sysproxy": query_sysproxy_status(&engine.state_dir()),
        "autostart": AutostartManager::new().status(),
        "demo": engine.demo_info(),
        "effective-outbound": router.effective_primary_outbound(),
    }))
}

#[derive(Deserialize)]
struct PatchConfigReq {
    mode: Option<RunMode>,
    #[serde(rename = "unified-delay", alias = "unified_delay")]
    unified_delay: Option<bool>,
    #[serde(rename = "allow-lan", alias = "allow_lan")]
    allow_lan: Option<bool>,
    #[serde(rename = "mixed-port", alias = "mixed_port")]
    mixed_port: Option<u16>,
    ipv6: Option<bool>,
    #[serde(rename = "log-level", alias = "log_level")]
    log_level: Option<String>,
    tun: Option<PatchTunReq>,
}

#[derive(Deserialize)]
struct PatchTunReq {
    enable: Option<bool>,
    #[serde(rename = "strict-route", alias = "strict_route")]
    strict_route: Option<bool>,
    ipv6: Option<bool>,
    #[serde(rename = "route-exclude-address", alias = "route_exclude_address")]
    route_exclude_address: Option<Vec<String>>,
}

async fn patch_configs(
    State(engine): State<Arc<ProxyEngine>>,
    Json(patch): Json<PatchConfigReq>,
) -> Response {
    if patch.mixed_port == Some(0) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "message": "mixed-port must be between 1 and 65535" })),
        )
            .into_response();
    }
    if let Some(mode) = patch.mode {
        engine.set_mode(mode);
    }
    if let Some(unified_delay) = patch.unified_delay {
        engine.set_unified_delay(unified_delay);
    }
    if let Some(level) = patch.log_level {
        engine.set_log_level(level);
    }
    let (tun_enable, tun_strict_route, tun_ipv6, tun_route_exclude_address) = match patch.tun {
        Some(t) => (t.enable, t.strict_route, t.ipv6, t.route_exclude_address),
        None => (None, None, None, None),
    };
    if (patch.allow_lan.is_some()
        || patch.mixed_port.is_some()
        || patch.ipv6.is_some()
        || tun_enable.is_some()
        || tun_strict_route.is_some()
        || tun_ipv6.is_some()
        || tun_route_exclude_address.is_some())
        && let Err(err) = engine
            .apply_config_patch_with_tun_exclude(
                patch.allow_lan,
                patch.mixed_port,
                patch.ipv6,
                tun_enable,
                tun_strict_route,
                tun_ipv6,
                tun_route_exclude_address,
            )
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
    #[serde(alias = "yaml")]
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
    auth_ctx: Option<axum::extract::Extension<ControllerSecretContext>>,
    Query(query): Query<RawYamlQuery>,
) -> Response {
    let cfg = engine.config_snapshot();
    if query.include_sensitive {
        let ctx = auth_ctx.map(|e| e.0).unwrap_or_default();
        let has_secret = cfg.secret.as_ref().is_some_and(|s| !s.trim().is_empty());
        if !ctx.started_with_secret || !has_secret || !ctx.has_valid_secret {
            return (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "message": "Revealing unredacted credentials via HTTP API requires a controller 'secret' configured at server startup and a valid Bearer token"
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
    let ordered = router.proxies_snapshot_ordered();
    let mut proxies_map = serde_json::Map::with_capacity(ordered.len());
    for (name, info) in ordered {
        if let Ok(val) = serde_json::to_value(info) {
            proxies_map.insert(name, val);
        }
    }
    let effective = router.effective_primary_outbound();
    Json(serde_json::json!({
        "proxies": serde_json::Value::Object(proxies_map),
        "group-order": router.group_order(),
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
    let probe_url = q
        .url
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(&default_url);
    let allowed_private = demo_allowed_private_addrs(&engine);
    if let Err(err) = crate::probe::validate_probe_url(probe_url, false, &allowed_private) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "message": crate::config::uri::redact_sensitive_text(&err.to_string())
            })),
        )
            .into_response();
    }
    let timeout = Duration::from_millis(q.timeout.clamp(200, 15_000));

    match engine
        .router()
        .test_delay_with_policy(&name, probe_url, timeout, false, &allowed_private)
        .await
    {
        Ok(delay) => (StatusCode::OK, Json(serde_json::json!({ "delay": delay }))).into_response(),
        Err(ProxyError::Config(msg)) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "message": crate::config::uri::redact_sensitive_text(&msg)
            })),
        )
            .into_response(),
        Err(ProxyError::Routing(msg)) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "message": crate::config::uri::redact_sensitive_text(&msg)
            })),
        )
            .into_response(),
        Err(err) => (
            StatusCode::GATEWAY_TIMEOUT,
            Json(serde_json::json!({
                "message": crate::config::uri::redact_sensitive_text(&err.to_string())
            })),
        )
            .into_response(),
    }
}

async fn get_group_delay(
    State(engine): State<Arc<ProxyEngine>>,
    Path(name): Path<String>,
    Query(q): Query<DelayQuery>,
) -> Response {
    let default_url = {
        let d = engine.demo_info();
        if d.enabled && !d.http_benchmark_origin.is_empty() {
            format!("{}/generate_204", d.http_benchmark_origin)
        } else {
            "http://www.gstatic.com/generate_204".to_string()
        }
    };
    let probe_url = q
        .url
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(&default_url);
    let allowed_private = demo_allowed_private_addrs(&engine);
    if let Err(err) = crate::probe::validate_probe_url(probe_url, false, &allowed_private) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "message": crate::config::uri::redact_sensitive_text(&err.to_string())
            })),
        )
            .into_response();
    }

    let router = engine.router();
    let Some(members) = router
        .proxies_snapshot()
        .get(&name)
        .and_then(|snap| snap.all.clone())
    else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "message": format!("proxy group '{name}' not found") })),
        )
            .into_response();
    };

    let timeout = Duration::from_millis(q.timeout.clamp(200, 15_000));

    match router
        .test_delay_with_policy(&name, probe_url, timeout, false, &allowed_private)
        .await
    {
        Ok(_) => {}
        Err(ProxyError::Config(msg)) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "message": crate::config::uri::redact_sensitive_text(&msg)
                })),
            )
                .into_response();
        }
        Err(ProxyError::Routing(msg)) => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({
                    "message": crate::config::uri::redact_sensitive_text(&msg)
                })),
            )
                .into_response();
        }
        Err(_) => {}
    }

    let mut alive_delays = serde_json::Map::with_capacity(members.len());
    for member in members {
        if let Some(ms) = router.effective_member_delay(&member) {
            alive_delays.insert(member, serde_json::Value::from(ms));
        }
    }
    (
        StatusCode::OK,
        Json(serde_json::Value::Object(alive_delays)),
    )
        .into_response()
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
        "totalConnections": engine.hub().total_connections(),
        "connections": conns,
        "memory": read_process_rss_bytes(),
    })
}

const WS_SEND_TIMEOUT: Duration = Duration::from_secs(5);

async fn ws_send_text_bounded(socket: &mut WebSocket, text: String) -> bool {
    matches!(
        tokio::time::timeout(WS_SEND_TIMEOUT, socket.send(Message::Text(text.into()))).await,
        Ok(Ok(()))
    )
}

async fn handle_ws_inbound_frame(
    socket: &mut WebSocket,
    frame: Option<std::result::Result<Message, axum::Error>>,
) -> bool {
    match frame {
        None | Some(Err(_)) | Some(Ok(Message::Close(_))) => false,
        Some(Ok(Message::Ping(payload))) => matches!(
            tokio::time::timeout(WS_SEND_TIMEOUT, socket.send(Message::Pong(payload))).await,
            Ok(Ok(()))
        ),
        Some(Ok(_)) => true,
    }
}

async fn wait_ws_shutdown(
    eng_stop: &mut watch::Receiver<bool>,
    api_stop: &mut Option<watch::Receiver<bool>>,
) {
    if *eng_stop.borrow() || api_stop.as_ref().is_some_and(|rx| *rx.borrow()) {
        return;
    }
    match api_stop {
        Some(srv_rx) => {
            tokio::select! {
                _ = eng_stop.changed() => {}
                _ = srv_rx.changed() => {}
            }
        }
        None => {
            let _ = eng_stop.changed().await;
        }
    }
}

async fn get_or_ws_connections(
    ws_res: std::result::Result<WebSocketUpgrade, WebSocketUpgradeRejection>,
    ws_stop: Option<axum::extract::Extension<WsShutdownWatch>>,
    State(engine): State<Arc<ProxyEngine>>,
) -> Response {
    let api_stop = ws_stop.and_then(|e| e.0.0);
    match ws_res {
        Ok(ws) => ws.on_upgrade(move |socket| stream_connections_ws(socket, engine, api_stop)),
        Err(_) => Json(connections_snapshot_json(&engine)).into_response(),
    }
}

async fn stream_connections_ws(
    mut socket: WebSocket,
    engine: Arc<ProxyEngine>,
    mut api_stop: Option<watch::Receiver<bool>>,
) {
    let mut eng_stop = engine.subscribe_shutdown();
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = wait_ws_shutdown(&mut eng_stop, &mut api_stop) => break,
            inbound = socket.recv() => {
                if !handle_ws_inbound_frame(&mut socket, inbound).await {
                    break;
                }
            }
            _ = interval.tick() => {
                let msg = connections_snapshot_json(&engine).to_string();
                if !ws_send_text_bounded(&mut socket, msg).await {
                    break;
                }
            }
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
    #[serde(default)]
    failed_only: bool,
}

fn default_diagnostics_limit() -> usize {
    150
}

async fn get_connection_diagnostics_api(
    State(engine): State<Arc<ProxyEngine>>,
    Query(q): Query<DiagnosticsQuery>,
) -> impl IntoResponse {
    let entries = if q.failed_only {
        engine.hub().failed_diagnostics_snapshot(q.limit)
    } else {
        engine.hub().diagnostics_snapshot(q.limit)
    };
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
    let checkpoint = mgr.capture_checkpoint();
    match mgr.apply_routing_preset(choice) {
        Ok((snap, cfg)) => {
            if let Err(err) = engine
                .activate_profile_config_with_selections(cfg, Some(&snap.selected_groups))
                .await
            {
                mgr.restore_checkpoint(checkpoint);
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({ "message": err.to_string() })),
                )
                    .into_response();
            }
            (StatusCode::OK, Json(serde_json::json!(snap))).into_response()
        }
        Err(err) => {
            mgr.restore_checkpoint(checkpoint);
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "message": err.to_string() })),
            )
                .into_response()
        }
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
    let checkpoint = mgr.capture_checkpoint();
    match mgr.save_custom_rules(req.rules) {
        Ok((snap, cfg)) => {
            if let Err(err) = engine
                .activate_profile_config_with_selections(cfg, Some(&snap.selected_groups))
                .await
            {
                mgr.restore_checkpoint(checkpoint);
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({ "message": err.to_string() })),
                )
                    .into_response();
            }
            (StatusCode::OK, Json(serde_json::json!(snap))).into_response()
        }
        Err(err) => {
            mgr.restore_checkpoint(checkpoint);
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "message": err.to_string() })),
            )
                .into_response()
        }
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
    let Some(qt) = parse_qtype_str(&q.qtype) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "message": format!("unsupported DNS record type '{}'", q.qtype)
            })),
        )
            .into_response();
    };
    let wire_req = build_dns_query(0x1337, &q.name, qt);
    let dns = Arc::clone(engine.router().dns());
    match dns.handle_dns_packet(&wire_req).await {
        Ok(wire_resp) => {
            let status_rcode = dns_response_rcode(&wire_resp).unwrap_or(0);
            let answers = extract_dns_display_answers(&wire_resp).unwrap_or_default();
            let formatted: Vec<serde_json::Value> = answers
                .into_iter()
                .map(|(rec_type, data)| {
                    if rec_type == "A"
                        && let Ok(v4) = data.parse::<std::net::Ipv4Addr>()
                    {
                        serde_json::json!({
                            "type": rec_type,
                            "data": data,
                            "is_fake_ip": dns.is_fake_ip(std::net::IpAddr::V4(v4)),
                            "restored_domain": dns.lookup_domain(std::net::IpAddr::V4(v4)),
                        })
                    } else {
                        serde_json::json!({
                            "type": rec_type,
                            "data": data,
                            "is_fake_ip": false,
                        })
                    }
                })
                .collect();
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "Status": status_rcode,
                    "Question": { "name": q.name, "type": format_qtype_name(qt) },
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
    if trimmed.contains("://") {
        let parsed_url =
            url::Url::parse(trimmed).map_err(|e| format!("invalid target URL: {e}"))?;
        let host = parsed_url
            .host_str()
            .ok_or_else(|| "target URL is missing host".to_string())?;
        let clean_host = host
            .strip_prefix('[')
            .and_then(|s| s.strip_suffix(']'))
            .unwrap_or(host);
        let default_port = match parsed_url.scheme().to_ascii_lowercase().as_str() {
            "http" | "ws" => 80,
            _ => 443,
        };
        let port = parsed_url.port().unwrap_or(default_port);
        if let Ok(ip) = clean_host.parse::<IpAddr>() {
            return Ok(crate::addr::TargetAddr::new_ip(ip, port));
        }
        return crate::addr::TargetAddr::new_domain(clean_host, port).map_err(|e| e.to_string());
    }
    let authority = match trimmed.find(['/', '?', '#']) {
        Some(idx) => trimmed[..idx].trim(),
        None => trimmed,
    };
    if authority.is_empty() {
        return Err("target host cannot be empty".to_string());
    }
    if let Some(inner) = authority
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        && let Ok(v6) = inner.parse::<std::net::Ipv6Addr>()
    {
        return Ok(crate::addr::TargetAddr::new_ip(IpAddr::V6(v6), 443));
    }
    if let Ok(t) = authority.parse::<crate::addr::TargetAddr>() {
        return Ok(t);
    }
    if let Ok(ip) = authority.parse::<IpAddr>() {
        return Ok(crate::addr::TargetAddr::new_ip(ip, 443));
    }
    format!("{authority}:443")
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
    engine.flush_dns();
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
        "total_queries": dns.total_queries(),
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
    #[serde(default)]
    auto_update_interval_secs: Option<u64>,
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
            flow,
            reality_opts,
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
                "tls": *tls || reality_opts.is_some(),
                "reality": reality_opts.is_some(),
                "flow": flow,
                "network": transport,
                "udp": udp,
            })
        }
        ProxyNodeConfig::Vmess {
            name,
            server,
            port,
            cipher,
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
                "type": "vmess",
                "server": server,
                "port": port,
                "cipher": cipher,
                "tls": tls,
                "network": transport,
                "udp": udp,
            })
        }
        ProxyNodeConfig::Hysteria2 {
            name,
            server,
            port,
            ports,
            obfs,
            sni,
            udp,
            ..
        } => serde_json::json!({
            "name": name,
            "type": "hysteria2",
            "server": server,
            "port": port,
            "ports": ports,
            "obfs": obfs,
            "sni": sni,
            "udp": udp,
        }),
        ProxyNodeConfig::Tuic {
            name,
            server,
            port,
            udp_relay_mode,
            congestion_controller,
            sni,
            udp,
            ..
        } => serde_json::json!({
            "name": name,
            "type": "tuic",
            "server": server,
            "port": port,
            "udp-relay-mode": udp_relay_mode,
            "congestion-controller": congestion_controller,
            "sni": sni,
            "udp": udp,
        }),
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
        let prev_snap = engine.config_snapshot();
        let prev_is_ephemeral = prev_snap.is_ephemeral_secret;
        let prev_secret = prev_snap.secret.filter(|s| !s.trim().is_empty());
        match engine
            .import_unified_live_with_options(
                &req.uris,
                req.profile_name.as_deref(),
                req.deduplicate,
                req.auto_select,
                req.auto_update_interval_secs,
            )
            .await
        {
            Ok(report) => {
                if let Some(sec) = prev_secret
                    && engine
                        .config_snapshot()
                        .secret
                        .as_deref()
                        .unwrap_or("")
                        .trim()
                        .is_empty()
                    && !engine.demo_info().enabled
                {
                    let mut live_cfg = engine.config_snapshot();
                    live_cfg.secret = Some(sec);
                    live_cfg.is_ephemeral_secret = prev_is_ephemeral;
                    let _ = engine
                        .activate_profile_config_with_selections(
                            live_cfg,
                            Some(&report.selected_groups),
                        )
                        .await;
                }
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
                let active_profile_id = engine.profile_manager().map(|m| m.active_profile_id());
                (
                    StatusCode::OK,
                    Json(serde_json::json!({
                        "applied": true,
                        "active-profile-id": active_profile_id,
                        "input-kind": report.input_kind,
                        "count": report.added_nodes.len(),
                        "added-nodes": report.added_nodes,
                        "skipped-duplicates": report.skipped_duplicates,
                        "skipped-unsupported": report.skipped_unsupported,
                        "rule-sanitization": report.rule_sanitization,
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
                    Option<crate::config::RuleSanitizationReport>,
                )> = match kind {
                    crate::profile::ImportInputKind::ShareUris
                    | crate::profile::ImportInputKind::Base64UriList => {
                        crate::config::uri::parse_subscription_uris_best_effort(&normalized)
                            .map(|(nodes, skipped)| (nodes, skipped, None))
                    }
                    crate::profile::ImportInputKind::ClashYaml => {
                        ClashConfig::from_yaml_str_sanitized_with_report(&normalized)
                            .map(|(c, skipped, r_rep)| (c.proxies, skipped, Some(r_rep)))
                    }
                    crate::profile::ImportInputKind::HttpsSubscriptionUrl => {
                        Ok((Vec::new(), Vec::new(), None))
                    }
                };
                match preview_res {
                    Ok((nodes, skipped, rule_sanitization)) => {
                        let summaries: Vec<_> = nodes.iter().map(summarize_node_redacted).collect();
                        (
                            StatusCode::OK,
                            Json(serde_json::json!({
                                "applied": false,
                                "input-kind": kind,
                                "count": summaries.len(),
                                "skipped-unsupported": skipped,
                                "rule-sanitization": rule_sanitization,
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
    ws_stop: Option<axum::extract::Extension<WsShutdownWatch>>,
    State(engine): State<Arc<ProxyEngine>>,
) -> Response {
    let api_stop = ws_stop.and_then(|e| e.0.0);
    match ws_res {
        Ok(ws) => ws.on_upgrade(move |socket| stream_traffic_ws(socket, engine, api_stop)),
        Err(_) => {
            let history = engine.hub().traffic_history();
            let latest = history.last().cloned().unwrap_or_default();
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

async fn stream_traffic_ws(
    mut socket: WebSocket,
    engine: Arc<ProxyEngine>,
    mut api_stop: Option<watch::Receiver<bool>>,
) {
    let mut eng_stop = engine.subscribe_shutdown();
    let mut rx = engine.hub().subscribe_traffic();
    loop {
        tokio::select! {
            _ = wait_ws_shutdown(&mut eng_stop, &mut api_stop) => break,
            inbound = socket.recv() => {
                if !handle_ws_inbound_frame(&mut socket, inbound).await {
                    break;
                }
            }
            item = rx.recv() => {
                match item {
                    Ok(point) => {
                        let Ok(text) = serde_json::to_string(&point) else {
                            continue;
                        };
                        if !ws_send_text_bounded(&mut socket, text).await {
                            break;
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        }
    }
}

async fn get_or_ws_memory(
    ws_res: std::result::Result<WebSocketUpgrade, WebSocketUpgradeRejection>,
    ws_stop: Option<axum::extract::Extension<WsShutdownWatch>>,
    State(engine): State<Arc<ProxyEngine>>,
) -> Response {
    let api_stop = ws_stop.and_then(|e| e.0.0);
    match ws_res {
        Ok(ws) => ws.on_upgrade(move |socket| stream_memory_ws(socket, engine, api_stop)),
        Err(_) => Json(serde_json::json!({
            "inuse": read_process_rss_bytes(),
            "oslimit": 0u64,
        }))
        .into_response(),
    }
}

async fn stream_memory_ws(
    mut socket: WebSocket,
    engine: Arc<ProxyEngine>,
    mut api_stop: Option<watch::Receiver<bool>>,
) {
    let mut eng_stop = engine.subscribe_shutdown();
    let mut interval = tokio::time::interval(Duration::from_secs(2));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = wait_ws_shutdown(&mut eng_stop, &mut api_stop) => break,
            inbound = socket.recv() => {
                if !handle_ws_inbound_frame(&mut socket, inbound).await {
                    break;
                }
            }
            _ = interval.tick() => {
                let msg = serde_json::json!({
                    "inuse": read_process_rss_bytes(),
                    "oslimit": 0u64,
                })
                .to_string();
                if !ws_send_text_bounded(&mut socket, msg).await {
                    break;
                }
            }
        }
    }
}

#[derive(Deserialize, Default)]
struct LogsQuery {
    level: Option<String>,
}

const MAX_LOG_WS_OVERLAP_DEDUP: usize = 256;

fn log_entry_matches_level(entry: &crate::tracker::LogEntry, level_norm: Option<&str>) -> bool {
    let entry_lvl = entry.level.trim().to_ascii_lowercase();
    match level_norm {
        Some("silent" | "off" | "none") => false,
        Some("error" | "err") => matches!(entry_lvl.as_str(), "error" | "err"),
        Some("warn" | "warning") => {
            matches!(entry_lvl.as_str(), "warn" | "warning" | "error" | "err")
        }
        Some("info") => !matches!(entry_lvl.as_str(), "debug" | "trace"),
        _ => true,
    }
}

fn snapshot_logs_for_level(
    hub: &TelemetryHub,
    level_norm: Option<&str>,
) -> Vec<crate::tracker::LogEntry> {
    let base = match level_norm {
        Some("silent" | "off" | "none") => return Vec::new(),
        Some("error" | "err" | "warn" | "warning") => hub.important_logs(),
        _ => hub.recent_logs(),
    };
    base.into_iter()
        .filter(|entry| log_entry_matches_level(entry, level_norm))
        .collect()
}

#[derive(Default)]
struct LogSnapshotDedup {
    seen: std::collections::VecDeque<(u64, String, String)>,
    max_ts: u64,
}

impl LogSnapshotDedup {
    fn record_sent(&mut self, entry: &crate::tracker::LogEntry) {
        if entry.timestamp_ms > self.max_ts {
            self.max_ts = entry.timestamp_ms;
        }
        if self.seen.len() >= MAX_LOG_WS_OVERLAP_DEDUP {
            self.seen.pop_front();
        }
        self.seen.push_back((
            entry.timestamp_ms,
            entry.level.clone(),
            entry.payload.clone(),
        ));
    }

    fn consume_if_duplicate(&mut self, entry: &crate::tracker::LogEntry) -> bool {
        if self.seen.is_empty() || entry.timestamp_ms > self.max_ts {
            return false;
        }
        if let Some(pos) = self.seen.iter().position(|(ts, lvl, payload)| {
            *ts == entry.timestamp_ms && lvl == &entry.level && payload == &entry.payload
        }) {
            self.seen.remove(pos);
            return true;
        }
        false
    }
}

async fn get_or_ws_logs(
    ws_res: std::result::Result<WebSocketUpgrade, WebSocketUpgradeRejection>,
    ws_stop: Option<axum::extract::Extension<WsShutdownWatch>>,
    Query(query): Query<LogsQuery>,
    State(engine): State<Arc<ProxyEngine>>,
) -> Response {
    let api_stop = ws_stop.and_then(|e| e.0.0);
    let level_norm = query
        .level
        .as_deref()
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty());
    match ws_res {
        Ok(ws) => ws.on_upgrade(move |socket| stream_logs_ws(socket, engine, api_stop, level_norm)),
        Err(_) => {
            let logs = snapshot_logs_for_level(engine.hub(), level_norm.as_deref());
            Json(serde_json::json!({ "logs": logs })).into_response()
        }
    }
}

async fn stream_logs_ws(
    mut socket: WebSocket,
    engine: Arc<ProxyEngine>,
    mut api_stop: Option<watch::Receiver<bool>>,
    level_norm: Option<String>,
) {
    let mut eng_stop = engine.subscribe_shutdown();
    // Subscribe BEFORE snapshotting so no log emitted while reading or sending the initial
    // backlog can fall into a subscribe gap; `LogSnapshotDedup` suppresses boundary overlap.
    let mut rx = engine.hub().subscribe_logs();
    let snapshot = snapshot_logs_for_level(engine.hub(), level_norm.as_deref());
    let mut dedup = LogSnapshotDedup::default();
    for entry in snapshot {
        if *eng_stop.borrow() || api_stop.as_ref().is_some_and(|rx| *rx.borrow()) {
            return;
        }
        dedup.record_sent(&entry);
        if let Ok(text) = serde_json::to_string(&entry)
            && !ws_send_text_bounded(&mut socket, text).await
        {
            return;
        }
    }
    loop {
        tokio::select! {
            _ = wait_ws_shutdown(&mut eng_stop, &mut api_stop) => break,
            inbound = socket.recv() => {
                if !handle_ws_inbound_frame(&mut socket, inbound).await {
                    break;
                }
            }
            item = rx.recv() => {
                match item {
                    Ok(entry) => {
                        if !log_entry_matches_level(&entry, level_norm.as_deref()) {
                            continue;
                        }
                        if dedup.consume_if_duplicate(&entry) {
                            continue;
                        }
                        if let Ok(text) = serde_json::to_string(&entry)
                            && !ws_send_text_bounded(&mut socket, text).await
                        {
                            break;
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        }
    }
}

pub fn parse_proc_status_anon_rss_bytes(status_text: &str) -> Option<u64> {
    for line in status_text.lines() {
        if let Some(rest) = line.strip_prefix("RssAnon:")
            && let Some(kb_str) = rest.split_whitespace().next()
            && let Ok(kb) = kb_str.parse::<u64>()
        {
            return Some(kb.saturating_mul(1024));
        }
    }
    None
}

pub fn read_process_total_vmrss_bytes() -> u64 {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        if let Ok(statm) = std::fs::read_to_string("/proc/self/statm")
            && let Some(rss_pages_str) = statm.split_whitespace().nth(1)
            && let Ok(pages) = rss_pages_str.parse::<u64>()
        {
            // SAFETY: `sysconf(_SC_PAGESIZE)` has no memory-safety preconditions.
            let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
            let page_bytes = if page_size > 0 {
                page_size as u64
            } else {
                4096
            };
            pages.saturating_mul(page_bytes)
        } else {
            0
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        read_process_rss_bytes()
    }
}

/// Read the process's private memory footprint (`RssAnon` on Linux/Android so shared Zygote
/// framework files and GPU `RssShmem` buffers do not inflate reported VPN kernel memory,
/// falling back to total `VmRSS` if `RssAnon` is unavailable).
pub fn read_process_rss_bytes() -> u64 {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        if let Ok(status) = std::fs::read_to_string("/proc/self/status")
            && let Some(anon_bytes) = parse_proc_status_anon_rss_bytes(&status)
            && anon_bytes > 0
        {
            anon_bytes
        } else {
            read_process_total_vmrss_bytes()
        }
    }
    #[cfg(target_os = "macos")]
    {
        // SAFETY: `info` is zero-initialized and passed with its exact byte size to `proc_pidinfo`.
        unsafe {
            let mut info: libc::proc_taskinfo = std::mem::zeroed();
            let size = std::mem::size_of::<libc::proc_taskinfo>() as libc::c_int;
            let ret = libc::proc_pidinfo(
                libc::getpid(),
                libc::PROC_PIDTASKINFO,
                0,
                (&raw mut info).cast::<libc::c_void>(),
                size,
            );
            if ret == size {
                return info.pti_resident_size;
            }
        }
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::System::{
            ProcessStatus::{K32GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS},
            Threading::GetCurrentProcess,
        };
        // SAFETY: `GetCurrentProcess` returns a valid pseudo-handle and `pmc` is zero-initialized
        // with `cb` set to its exact byte size.
        unsafe {
            let mut pmc: PROCESS_MEMORY_COUNTERS = std::mem::zeroed();
            pmc.cb = std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
            if K32GetProcessMemoryInfo(GetCurrentProcess(), &mut pmc, pmc.cb) != 0 {
                return pmc.WorkingSetSize as u64;
            }
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
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

    let prev_snap = engine.config_snapshot();
    let prev_is_ephemeral = prev_snap.is_ephemeral_secret;
    let prev_secret = prev_snap.secret.filter(|s| !s.trim().is_empty());
    let checkpoint = mgr.capture_checkpoint();

    match mgr.create_profile_full(spec).await {
        Ok((meta, maybe_cfg, skipped_unsupported, rule_sanitization)) => {
            let mode_for_warn = maybe_cfg.as_ref().map(|c| c.mode).unwrap_or(RunMode::Rule);
            if let Some(mut cfg) = maybe_cfg {
                if cfg.secret.as_deref().unwrap_or("").trim().is_empty() {
                    cfg.secret = prev_secret;
                    cfg.is_ephemeral_secret = prev_is_ephemeral;
                }
                if let Err(err) = engine
                    .activate_profile_config_with_selections(cfg, Some(&meta.selected_groups))
                    .await
                {
                    mgr.restore_checkpoint(checkpoint);
                    let safe_err = crate::config::uri::redact_sensitive_text(&err.to_string());
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({
                            "message": format!("profile activation failed and was rolled back: {safe_err}")
                        })),
                    )
                        .into_response();
                }
            }
            engine.hub().push_log(
                "info",
                format!(
                    "Created profile '{}' ({} proxy nodes)",
                    meta.name, meta.proxy_count
                ),
            );
            if let Some(ref rep) = rule_sanitization
                && let Some(warn_msg) = rep.warning_summary(mode_for_warn)
            {
                engine
                    .hub()
                    .push_log("warn", format!("[Profile '{}'] {warn_msg}", meta.name));
            }
            (
                StatusCode::CREATED,
                Json(serde_json::json!({
                    "profile": meta,
                    "skipped-unsupported": skipped_unsupported,
                    "rule-sanitization": rule_sanitization,
                    "snapshot": mgr.snapshot(),
                })),
            )
                .into_response()
        }
        Err(e) => {
            mgr.restore_checkpoint(checkpoint);
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "message": crate::config::uri::redact_sensitive_text(&e.to_string()) })),
            )
                .into_response()
        }
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

    let prev_snap = engine.config_snapshot();
    let prev_is_ephemeral = prev_snap.is_ephemeral_secret;
    let prev_secret = prev_snap.secret.filter(|s| !s.trim().is_empty());
    let checkpoint = mgr.capture_checkpoint();

    match mgr.set_active_profile(&id) {
        Ok(mut cfg) => {
            if cfg.secret.as_deref().unwrap_or("").trim().is_empty() {
                cfg.secret = prev_secret;
                cfg.is_ephemeral_secret = prev_is_ephemeral;
            }
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
                Err(e) => {
                    mgr.restore_checkpoint(checkpoint);
                    (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({ "message": crate::config::uri::redact_sensitive_text(&e.to_string()) })),
                    )
                        .into_response()
                }
            }
        }
        Err(e) => {
            mgr.restore_checkpoint(checkpoint);
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "message": crate::config::uri::redact_sensitive_text(&e.to_string()) })),
            )
                .into_response()
        }
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
    let prev_snap = engine.config_snapshot();
    let prev_is_ephemeral = prev_snap.is_ephemeral_secret;
    let prev_secret = prev_snap.secret.filter(|s| !s.trim().is_empty());
    let checkpoint = mgr.capture_checkpoint();

    match mgr.refresh_subscription_with_report(&id).await {
        Ok((meta, mut cfg, is_active, rule_sanitization)) => {
            let diff_opt = prev_cfg_opt
                .as_ref()
                .map(|prev| crate::audit::diff_configs(prev, &cfg));
            let audit = crate::audit::audit_config(&cfg);
            let cfg_mode = cfg.mode;

            if is_active && !engine.demo_info().enabled {
                if cfg.secret.as_deref().unwrap_or("").trim().is_empty() {
                    cfg.secret = prev_secret;
                    cfg.is_ephemeral_secret = prev_is_ephemeral;
                }
                if let Err(e) = engine
                    .activate_profile_config_with_selections(cfg, Some(&meta.selected_groups))
                    .await
                {
                    mgr.restore_checkpoint(checkpoint);
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({ "message": crate::config::uri::redact_sensitive_text(&e.to_string()) })),
                    )
                        .into_response();
                }
            }
            engine.hub().push_log(
                "info",
                format!(
                    "Refreshed subscription '{}' ({} nodes, security grade {} {}/100)",
                    meta.name, meta.proxy_count, audit.grade, audit.score
                ),
            );
            if let Some(ref rep) = rule_sanitization
                && let Some(warn_msg) = rep.warning_summary(cfg_mode)
            {
                engine
                    .hub()
                    .push_log("warn", format!("[Profile '{}'] {warn_msg}", meta.name));
            }
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "profile": meta,
                    "rule-sanitization": rule_sanitization,
                    "snapshot": mgr.snapshot(),
                    "diff": diff_opt,
                    "audit_score": audit.score,
                    "audit_grade": audit.grade,
                })),
            )
                .into_response()
        }
        Err(e) => {
            mgr.restore_checkpoint(checkpoint);
            (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({ "message": crate::config::uri::redact_sensitive_text(&e.to_string()) })),
            )
                .into_response()
        }
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

async fn patch_profile_settings_api(
    State(engine): State<Arc<ProxyEngine>>,
    Path(id): Path<String>,
    Json(patch): Json<ProfileSettingsPatch>,
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

    match mgr.update_profile_settings(&id, patch) {
        Ok(meta) => {
            engine.hub().push_log(
                "info",
                format!(
                    "Updated profile settings for '{}' (auto_update_interval_secs={:?})",
                    meta.name, meta.auto_update_interval_secs
                ),
            );
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "profile": meta,
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

async fn get_profile_raw_yaml_api(
    State(engine): State<Arc<ProxyEngine>>,
    Path(id): Path<String>,
    auth_ctx: Option<axum::extract::Extension<ControllerSecretContext>>,
    Query(query): Query<RawYamlQuery>,
) -> Response {
    let mgr = match ensure_profile_manager(&engine) {
        Ok(m) => m,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "message": crate::config::uri::redact_sensitive_text(&e.to_string())
                })),
            )
                .into_response();
        }
    };

    let Some(cfg) = mgr.load_profile_config_by_id(&id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "message": format!("profile '{id}' not found") })),
        )
            .into_response();
    };

    if query.include_sensitive {
        let ctx = auth_ctx.map(|e| e.0).unwrap_or_default();
        let live_cfg = engine.config_snapshot();
        let has_secret = live_cfg
            .secret
            .as_ref()
            .is_some_and(|s| !s.trim().is_empty());
        if !ctx.started_with_secret || !has_secret || !ctx.has_valid_secret {
            return (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "message": "Revealing unredacted credentials via HTTP API requires a controller 'secret' configured at server startup and a valid Bearer token"
                })),
            )
                .into_response();
        }
        let yaml = match cfg.to_yaml_string() {
            Ok(y) => y,
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({
                        "message": crate::config::uri::redact_sensitive_text(&e.to_string())
                    })),
                )
                    .into_response();
            }
        };
        let exported_uris: Vec<String> = cfg.proxies.iter().map(export_proxy_uri).collect();
        return Json(serde_json::json!({
            "id": id,
            "active": mgr.active_profile_id() == id,
            "yaml": yaml,
            "uris": exported_uris,
            "redacted": false,
        }))
        .into_response();
    }

    let redacted_cfg = cfg.redacted();
    let redacted_yaml = match redacted_cfg.to_yaml_string() {
        Ok(y) => y,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "message": crate::config::uri::redact_sensitive_text(&e.to_string())
                })),
            )
                .into_response();
        }
    };
    let redacted_uris: Vec<String> = redacted_cfg.proxies.iter().map(export_proxy_uri).collect();
    Json(serde_json::json!({
        "id": id,
        "active": mgr.active_profile_id() == id,
        "yaml": redacted_yaml,
        "uris": redacted_uris,
        "redacted": true,
    }))
    .into_response()
}

#[derive(Deserialize)]
struct PutProfileRawYamlReq {
    #[serde(alias = "yaml")]
    payload: String,
}

async fn put_profile_raw_yaml_api(
    State(engine): State<Arc<ProxyEngine>>,
    Path(id): Path<String>,
    Json(req): Json<PutProfileRawYamlReq>,
) -> Response {
    let mgr = match ensure_profile_manager(&engine) {
        Ok(m) => m,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "message": crate::config::uri::redact_sensitive_text(&e.to_string())
                })),
            )
                .into_response();
        }
    };

    let Some(prev_cfg) = mgr.load_profile_config_by_id(&id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "message": format!("profile '{id}' not found") })),
        )
            .into_response();
    };

    if mgr.active_profile_id() == id && !engine.demo_info().enabled {
        let checkpoint = mgr.capture_checkpoint();
        return match engine.reload_yaml(&req.payload).await {
            Ok(()) => (StatusCode::OK, Json(mgr.snapshot())).into_response(),
            Err(ProxyError::Routing(msg)) => {
                mgr.restore_checkpoint(checkpoint);
                (
                    StatusCode::FORBIDDEN,
                    Json(serde_json::json!({ "message": crate::config::uri::redact_sensitive_text(&msg) })),
                )
                    .into_response()
            }
            Err(e) => {
                mgr.restore_checkpoint(checkpoint);
                (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({ "message": crate::config::uri::redact_sensitive_text(&e.to_string()) })),
                )
                    .into_response()
            }
        };
    }

    let mut parsed = match ClashConfig::from_yaml_str_unchecked(&req.payload) {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "message": crate::config::uri::redact_sensitive_text(&e.to_string())
                })),
            )
                .into_response();
        }
    };
    parsed.restore_redacted_from(&prev_cfg);
    parsed.normalize_secret();
    if let Err(e) = parsed.validate() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "message": crate::config::uri::redact_sensitive_text(&e.to_string())
            })),
        )
            .into_response();
    }
    match mgr.persist_profile_yaml(&id, &parsed, None, None) {
        Ok(_) => {
            engine
                .hub()
                .push_log("info", format!("Saved raw YAML for profile '{id}'"));
            (StatusCode::OK, Json(mgr.snapshot())).into_response()
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "message": crate::config::uri::redact_sensitive_text(&e.to_string())
            })),
        )
            .into_response(),
    }
}

#[derive(Deserialize, Default)]
struct ExitIpQuery {
    #[serde(default)]
    refresh: Option<String>,
}

static EXIT_IP_CACHE: std::sync::LazyLock<
    parking_lot::Mutex<Option<(String, Instant, serde_json::Value)>>,
> = std::sync::LazyLock::new(|| parking_lot::Mutex::new(None));

async fn get_exit_ip_api(
    State(engine): State<Arc<ProxyEngine>>,
    Query(q): Query<ExitIpQuery>,
) -> Response {
    let now_ms = TelemetryHub::now_ms();
    let cfg = engine.config_snapshot();
    let router = engine.router();
    let eff = router.effective_primary_outbound();
    let force_refresh = q
        .refresh
        .as_deref()
        .is_some_and(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes"));

    if engine.demo_info().enabled {
        return (
            StatusCode::OK,
            Json(serde_json::json!({
                "ok": true,
                "ip": "198.51.100.42",
                "country": "Demo Sandbox",
                "country_code": "SG",
                "isp": "RustClash Loopback Sandbox",
                "organization": "RustClash Loopback Sandbox",
                "asn": "AS64512",
                "ip_type": "Sandbox",
                "node_type": "Sandbox",
                "quality": "Sandbox",
                "latency_ms": 18,
                "outbound": eff.effective_outbound,
                "via_outbound": eff.effective_outbound,
                "protocol": eff.effective_protocol,
                "checked_at_ms": now_ms,
                "cached": false,
            })),
        )
            .into_response();
    }

    if eff.effective_outbound.eq_ignore_ascii_case("REJECT")
        || eff.effective_outbound.starts_with("ERROR")
    {
        return (
            StatusCode::OK,
            Json(serde_json::json!({
                "ok": false,
                "ip": "--",
                "country": "Blocked",
                "country_code": "",
                "isp": eff.effective_outbound,
                "organization": eff.effective_outbound,
                "asn": "",
                "ip_type": "Blocked",
                "node_type": "Blocked",
                "quality": serde_json::Value::Null,
                "outbound": eff.effective_outbound,
                "via_outbound": eff.effective_outbound,
                "protocol": eff.effective_protocol,
                "checked_at_ms": now_ms,
                "cached": false,
            })),
        )
            .into_response();
    }

    let outbound_opt = router.concrete_outbound(&eff.effective_outbound);
    let probe_ref = crate::addr::TargetAddr::new_ip(IpAddr::from([1, 1, 1, 1]), 443);
    let outbound_ep = outbound_opt
        .as_ref()
        .map(|ob| ob.remote_endpoint(&probe_ref))
        .unwrap_or_default();
    let cache_key = format!(
        "{}:{}:{}",
        cfg.mode.as_str(),
        eff.effective_outbound,
        outbound_ep
    );
    if !force_refresh
        && let Some((cached_key, ts, mut cached_val)) = EXIT_IP_CACHE.lock().clone()
        && cached_key == cache_key
        && ts.elapsed() < Duration::from_secs(30)
    {
        if let Some(obj) = cached_val.as_object_mut() {
            obj.insert("cached".to_string(), serde_json::Value::Bool(true));
        }
        return (StatusCode::OK, Json(cached_val)).into_response();
    }

    let extra_ca = engine.extra_ca_der();
    let probe_start = Instant::now();
    if let Some(outbound) = outbound_opt
        && let Ok(Some(probe)) = tokio::time::timeout(
            Duration::from_millis(6000),
            crate::probe::probe_exit_ip_via_outbound(outbound.as_ref(), &extra_ca),
        )
        .await
    {
        let latency_ms = probe_start.elapsed().as_millis() as u64;
        let fresh_now = TelemetryHub::now_ms();
        let payload = serde_json::json!({
            "ok": true,
            "ip": probe.ip,
            "country": probe.country,
            "country_code": probe.country_code,
            "isp": probe.isp,
            "organization": probe.isp,
            "asn": probe.asn,
            "ip_type": probe.ip_type,
            "node_type": probe.ip_type,
            "quality": serde_json::Value::Null,
            "latency_ms": latency_ms,
            "outbound": eff.effective_outbound,
            "via_outbound": eff.effective_outbound,
            "protocol": eff.effective_protocol,
            "checked_at_ms": fresh_now,
            "cached": false,
        });
        *EXIT_IP_CACHE.lock() = Some((cache_key, Instant::now(), payload.clone()));
        return (StatusCode::OK, Json(payload)).into_response();
    }

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": false,
            "ip": "--",
            "country": "Offline",
            "country_code": "",
            "isp": "Unreachable",
            "organization": "",
            "asn": "",
            "ip_type": "Unknown",
            "node_type": "",
            "outbound": eff.effective_outbound,
            "via_outbound": eff.effective_outbound,
            "protocol": eff.effective_protocol,
            "checked_at_ms": TelemetryHub::now_ms(),
            "cached": false,
        })),
    )
        .into_response()
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

/// Compute the target proxy host to configure in the OS System Proxy for `cfg`.
pub fn effective_sysproxy_host(cfg: &ClashConfig) -> String {
    if cfg.allow_lan {
        return "127.0.0.1".to_string();
    }
    let trimmed = cfg.bind_address.trim();
    match trimmed {
        "" | "*" | "0.0.0.0" | "::" | "[::]" | "127.0.0.1" => "127.0.0.1".to_string(),
        "::1" | "[::1]" => "::1".to_string(),
        other if other.eq_ignore_ascii_case("localhost") => "127.0.0.1".to_string(),
        other => other
            .strip_prefix('[')
            .and_then(|s| s.strip_suffix(']'))
            .unwrap_or(other)
            .to_string(),
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
        let cfg = engine.config_snapshot();
        let host = effective_sysproxy_host(&cfg);
        let port = engine.mixed_addr().port();
        let bypass = req.bypass.unwrap_or_default();
        match enable_system_proxy(&host, port, &bypass, &state_dir) {
            Ok(status) => {
                engine
                    .hub()
                    .push_log("info", format!("Enabled OS System Proxy -> {host}:{port}"));
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

const REDACTED_URL_PLACEHOLDER: &str = "***REDACTED_URL***";

fn find_placeholder_spans(s: &str) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'*' {
            let rest = &s[i..];
            if rest.starts_with(REDACTED_URL_PLACEHOLDER) {
                spans.push((i, i + REDACTED_URL_PLACEHOLDER.len()));
                i += REDACTED_URL_PLACEHOLDER.len();
                continue;
            }
            if rest.starts_with(REDACTED_SECRET) {
                spans.push((i, i + REDACTED_SECRET.len()));
                i += REDACTED_SECRET.len();
                continue;
            }
        }
        i += 1;
    }
    spans
}

fn kmp_find_all_matches(
    haystack: &[u8],
    needle: &[u8],
    base_offset: usize,
    out: &mut Vec<(usize, usize)>,
) {
    let m = needle.len();
    if m == 0 || haystack.len() < m {
        return;
    }
    let mut lps = vec![0usize; m];
    let mut len = 0usize;
    let mut i = 1usize;
    while i < m {
        if needle[i] == needle[len] {
            len += 1;
            lps[i] = len;
            i += 1;
        } else if len != 0 {
            len = lps[len - 1];
        } else {
            lps[i] = 0;
            i += 1;
        }
    }
    let mut j = 0usize;
    for (idx, &b) in haystack.iter().enumerate() {
        while j > 0 && b != needle[j] {
            j = lps[j - 1];
        }
        if b == needle[j] {
            j += 1;
            if j == m {
                let match_start = base_offset + idx + 1 - m;
                out.push((match_start, match_start + m));
                j = lps[j - 1];
            }
        }
    }
}

fn merge_overlapping_spans(mut spans: Vec<(usize, usize)>) -> Vec<(usize, usize)> {
    if spans.len() <= 1 {
        return spans;
    }
    spans.sort_unstable();
    let mut merged: Vec<(usize, usize)> = Vec::with_capacity(spans.len());
    for (s, e) in spans {
        if let Some(last) = merged.last_mut()
            && s < last.1
        {
            if e > last.1 {
                last.1 = e;
            }
            continue;
        }
        merged.push((s, e));
    }
    merged
}

fn is_placeholder_superstring_secret(sec: &str) -> bool {
    (sec.contains(REDACTED_SECRET) || sec.contains(REDACTED_URL_PLACEHOLDER))
        && sec != REDACTED_SECRET
        && sec != REDACTED_URL_PLACEHOLDER
}

fn find_secret_spans_outside_placeholders(s: &str, eligible: &[&str]) -> Vec<(usize, usize)> {
    if s.len() < 4 || eligible.is_empty() {
        return Vec::new();
    }
    let placeholders = find_placeholder_spans(s);
    let mut raw_matches = Vec::new();

    // 1. Strict-superstring secrets that themselves contain `***REDACTED***` or
    //    `***REDACTED_URL***` (e.g. `pre-***REDACTED***-INNER_SECRET`) must match directly
    //    against `s` because no single non-placeholder gap can contain them. Because they are
    //    strictly longer than bare placeholders, they never corrupt emitted placeholders.
    for &sec in eligible {
        if !is_placeholder_superstring_secret(sec) || sec.len() > s.len() {
            continue;
        }
        let Some(first) = s.find(sec) else {
            continue;
        };
        if first + sec.len() == s.len() {
            raw_matches.push((first, first + sec.len()));
        } else {
            kmp_find_all_matches(
                &s.as_bytes()[first..],
                sec.as_bytes(),
                first,
                &mut raw_matches,
            );
        }
    }

    // 2. Ordinary secrets match strictly inside non-placeholder gaps so short secrets like
    //    `****`, `REDACTED`, `_URL`, or `***R` never damage emitted placeholders.
    let mut gap_start = 0usize;
    for (p_start, p_end) in placeholders
        .into_iter()
        .chain(std::iter::once((s.len(), s.len())))
    {
        if p_start > gap_start {
            let gap = &s[gap_start..p_start];
            if gap.len() >= 4 {
                for &sec in eligible {
                    if is_placeholder_superstring_secret(sec) || sec.len() > gap.len() {
                        continue;
                    }
                    let Some(first) = gap.find(sec) else {
                        continue;
                    };
                    if first + sec.len() == gap.len() {
                        raw_matches.push((gap_start + first, gap_start + first + sec.len()));
                    } else {
                        kmp_find_all_matches(
                            &gap.as_bytes()[first..],
                            sec.as_bytes(),
                            gap_start + first,
                            &mut raw_matches,
                        );
                    }
                }
            }
        }
        gap_start = p_end;
    }
    merge_overlapping_spans(raw_matches)
}

fn has_secret_outside_placeholders(s: &str, eligible: &[&str]) -> bool {
    if s.len() < 4 || eligible.is_empty() {
        return false;
    }
    if eligible.iter().any(|&sec| {
        is_placeholder_superstring_secret(sec) && sec.len() <= s.len() && s.contains(sec)
    }) {
        return true;
    }
    let placeholders = find_placeholder_spans(s);
    let mut gap_start = 0usize;
    for (p_start, p_end) in placeholders
        .into_iter()
        .chain(std::iter::once((s.len(), s.len())))
    {
        if p_start > gap_start {
            let gap = &s[gap_start..p_start];
            if gap.len() >= 4
                && eligible.iter().any(|&sec| {
                    !is_placeholder_superstring_secret(sec)
                        && sec.len() <= gap.len()
                        && gap.contains(sec)
                })
            {
                return true;
            }
        }
        gap_start = p_end;
    }
    false
}

enum ScrubEvent {
    Structured {
        start: usize,
        end: usize,
        replacement: String,
    },
    Secret {
        start: usize,
        end: usize,
    },
}

impl ScrubEvent {
    fn span(&self) -> (usize, usize) {
        match self {
            Self::Structured { start, end, .. } | Self::Secret { start, end } => (*start, *end),
        }
    }
}

fn find_placeholder_superstring_spans(s: &str, eligible: &[&str]) -> Vec<(usize, usize)> {
    let mut raw_matches = Vec::new();
    for &sec in eligible {
        if !is_placeholder_superstring_secret(sec) || sec.len() > s.len() {
            continue;
        }
        let Some(first) = s.find(sec) else {
            continue;
        };
        if first + sec.len() == s.len() {
            raw_matches.push((first, first + sec.len()));
        } else {
            kmp_find_all_matches(
                &s.as_bytes()[first..],
                sec.as_bytes(),
                first,
                &mut raw_matches,
            );
        }
    }
    merge_overlapping_spans(raw_matches)
}

fn map_base_spans_to_raw(
    pieces: &[crate::config::uri::RedactPiece],
    raw: &str,
    base_spans: &[(usize, usize)],
) -> Vec<(usize, usize)> {
    if pieces.is_empty() || base_spans.is_empty() {
        return Vec::new();
    }
    let mut base_bounds: Vec<(usize, usize)> = Vec::with_capacity(pieces.len());
    let mut off = 0usize;
    for p in pieces {
        let len = p.text(raw).len();
        base_bounds.push((off, off + len));
        off += len;
    }

    let mut out = Vec::with_capacity(base_spans.len());
    let mut pi_start = 0usize;
    let mut pi_end = 0usize;
    for &(bs, be) in base_spans {
        while pi_start + 1 < pieces.len() && base_bounds[pi_start].1 <= bs {
            pi_start += 1;
        }
        if pi_end < pi_start {
            pi_end = pi_start;
        }
        while pi_end + 1 < pieces.len() && base_bounds[pi_end].1 < be {
            pi_end += 1;
        }
        let p_start = &pieces[pi_start];
        let raw_start = if p_start.replacement.is_none() {
            p_start.raw_start + (bs - base_bounds[pi_start].0)
        } else {
            p_start.raw_start
        };
        let p_end = &pieces[pi_end];
        let raw_end = if p_end.replacement.is_none() {
            p_end.raw_start + (be - base_bounds[pi_end].0)
        } else {
            p_end.raw_end
        };
        if raw_start < raw_end {
            out.push((raw_start, raw_end));
        }
    }
    out
}

fn scrub_sensitive_substrings_once(raw: &str, eligible: &[&str]) -> (String, bool) {
    let pieces = crate::config::uri::redact_sensitive_text_pieces(raw);
    let mut secret_spans = find_secret_spans_outside_placeholders(raw, eligible);

    // If any configured secret is a placeholder superstring (e.g. `pre-***REDACTED***-x`),
    // also match it against the structurally-redacted text and map any newly materialized spans
    // back to `raw` byte coordinates BEFORE prefix-unblocking runs. This prevents chained
    // `pre-<uuid>-xtoken=Secret` inputs from destroying `token` before `pre-***REDACTED***-x`
    // unblocks `token=`.
    if eligible
        .iter()
        .any(|&sec| is_placeholder_superstring_secret(sec))
        && pieces.iter().any(|p| p.replacement.is_some())
    {
        let total_len: usize = pieces.iter().map(|p| p.text(raw).len()).sum();
        let mut base_text = String::with_capacity(total_len);
        for p in &pieces {
            base_text.push_str(p.text(raw));
        }
        let base_ph_spans = find_placeholder_superstring_spans(&base_text, eligible);
        if !base_ph_spans.is_empty() {
            let mapped = map_base_spans_to_raw(&pieces, raw, &base_ph_spans);
            if !mapped.is_empty() {
                secret_spans.extend(mapped);
                secret_spans = merge_overlapping_spans(secret_spans);
            }
        }
    }

    let mut base_structured: Vec<(usize, usize, String)> = pieces
        .into_iter()
        .filter_map(|p| p.replacement.map(|rep| (p.raw_start, p.raw_end, rep)))
        .collect();

    // Second-order prefix-shadowing & trailing-hex UUID unblocker (two disjoint O(N) buffers):
    // 1. `wb_masked_bytes`: mask ONLY prefix-blocked `WordBoundary` triggers (`token=`, `key=`,
    //    `Authorization:`, ...) using a single monotone `active_word_val_end` across ALL
    //    `secret_spans`. Because UUID boundaries are NEVER written into `wb_masked_bytes`, a
    //    UUID-adjacent secret can never inject a space mid-KV/Auth value, fixed-length UUIDs
    //    never suppress a following `WordBoundary` trigger, and nested secrets inside an active
    //    KV/Auth value cannot truncate the outer value scan.
    // 2. `uuid_masked_bytes`: mask ONLY leading and trailing ASCII hex bytes adjacent to 36-char
    //    UUIDs covered by `secret_spans`, then run `find_non_nil_uuid_edits` and retain only
    //    UUID spans not already covered by `base_structured` or `wb_structured`.
    // Every sweep uses strictly monotone non-backtracking pointers -> guaranteed O(N).
    let mut extra_structured: Vec<(usize, usize, String)> = Vec::new();
    if !secret_spans.is_empty() {
        let trigger_spans = crate::config::uri::find_structural_trigger_spans(raw);
        if !trigger_spans.is_empty() {
            let raw_bytes = raw.as_bytes();
            let wb_triggers: Vec<crate::config::uri::StructuralTriggerSpan> = trigger_spans
                .iter()
                .copied()
                .filter(|t| {
                    t.kind == crate::config::uri::StructuralTriggerKind::WordBoundary
                        && t.is_prefix_blocked
                })
                .collect();
            let uuid_triggers: Vec<crate::config::uri::StructuralTriggerSpan> = trigger_spans
                .iter()
                .copied()
                .filter(|t| t.kind == crate::config::uri::StructuralTriggerKind::Uuid)
                .collect();

            if !wb_triggers.is_empty() {
                let lower = raw.to_ascii_lowercase();
                let mut wb_masked_bytes: Option<Vec<u8>> = None;
                let mut wi = 0usize;
                let mut active_word_val_end = 0usize;
                let mut last_unblocked_wb_end: Option<usize> = None;
                let mut parity = crate::config::uri::LineQuoteParity::default();
                let mut no_close_quote_until = [0usize; 3];
                for &(s, e) in &secret_spans {
                    while wi < wb_triggers.len() && wb_triggers[wi].start <= s {
                        wi += 1;
                    }
                    while wi < wb_triggers.len() && wb_triggers[wi].start <= e {
                        let t = wb_triggers[wi];
                        wi += 1;
                        let block_pos = t.start - 1;
                        // Skip triggers nested inside an active unblocked KV/Auth value, as well as
                        // inner KV suffixes sharing the exact same `t.end` already unblocked by an
                        // outer KV key (e.g. `access_token=` -> `token=`).
                        if block_pos < active_word_val_end || last_unblocked_wb_end == Some(t.end) {
                            continue;
                        }
                        let buf = wb_masked_bytes.get_or_insert_with(|| raw_bytes.to_vec());
                        buf[block_pos] = b' ';
                        parity.advance_to(raw_bytes, t.end);
                        let val_end = crate::config::uri::scan_word_boundary_trigger_value_end(
                            raw,
                            &lower,
                            t,
                            parity.open_quotes(),
                            &mut no_close_quote_until,
                        );
                        active_word_val_end = active_word_val_end.max(val_end.max(t.end));
                        last_unblocked_wb_end = Some(t.end);
                    }
                }

                if let Some(buf) = wb_masked_bytes {
                    let wb_masked = String::from_utf8(buf).expect(
                        "masking ASCII word-boundary bytes with ASCII spaces preserves UTF-8",
                    );
                    let wb_structured: Vec<(usize, usize, String)> =
                        crate::config::uri::redact_sensitive_text_pieces(&wb_masked)
                            .into_iter()
                            .filter_map(|p| p.replacement.map(|rep| (p.raw_start, p.raw_end, rep)))
                            .collect();

                    // Keep newly revealed, strictly wider, or strictly stronger (same-span upgrade
                    // over a non-full-placeholder base entry, e.g. `***REDACTED***&next=1` over
                    // `https://host&next=1`) entries from `wb_structured`.
                    let is_full_placeholder =
                        |rep: &str| rep == REDACTED_SECRET || rep == REDACTED_URL_PLACEHOLDER;
                    let mut bi = 0usize;
                    for (ms, me, mrep) in wb_structured {
                        while bi < base_structured.len() && base_structured[bi].1 <= ms {
                            bi += 1;
                        }
                        let upgraded_same_span = bi < base_structured.len()
                            && base_structured[bi].0 == ms
                            && base_structured[bi].1 == me
                            && mrep != base_structured[bi].2
                            && !is_full_placeholder(&base_structured[bi].2);
                        let covered_by_base = bi < base_structured.len()
                            && base_structured[bi].0 <= ms
                            && me <= base_structured[bi].1
                            && !upgraded_same_span;
                        if !covered_by_base {
                            extra_structured.push((ms, me, mrep));
                        }
                    }
                    if !extra_structured.is_empty() {
                        let mut mi = 0usize;
                        base_structured.retain(|&(bs, be, _)| {
                            while mi < extra_structured.len() && extra_structured[mi].1 <= bs {
                                mi += 1;
                            }
                            !(mi < extra_structured.len()
                                && extra_structured[mi].0 <= bs
                                && be <= extra_structured[mi].1)
                        });
                    }
                }
            }

            if !uuid_triggers.is_empty() {
                let mut uuid_masked_bytes: Option<Vec<u8>> = None;
                let mut u_lead = 0usize;
                let mut u_trail = 0usize;
                for &(s, e) in &secret_spans {
                    while u_lead < uuid_triggers.len() && uuid_triggers[u_lead].start <= s {
                        u_lead += 1;
                    }
                    while u_lead < uuid_triggers.len() && uuid_triggers[u_lead].start <= e {
                        let u = uuid_triggers[u_lead];
                        u_lead += 1;
                        if u.is_prefix_blocked {
                            let buf = uuid_masked_bytes.get_or_insert_with(|| raw_bytes.to_vec());
                            buf[u.start - 1] = b' ';
                        }
                    }
                    while u_trail < uuid_triggers.len() && uuid_triggers[u_trail].end < s {
                        u_trail += 1;
                    }
                    while u_trail < uuid_triggers.len() && uuid_triggers[u_trail].end < e {
                        let te = uuid_triggers[u_trail].end;
                        u_trail += 1;
                        if te < raw_bytes.len() && raw_bytes[te].is_ascii_hexdigit() {
                            let buf = uuid_masked_bytes.get_or_insert_with(|| raw_bytes.to_vec());
                            buf[te] = b' ';
                        }
                    }
                }

                if let Some(buf) = uuid_masked_bytes {
                    let uuid_masked = String::from_utf8(buf).expect(
                        "masking ASCII hex boundary bytes with ASCII spaces preserves UTF-8",
                    );
                    let uuid_edits = crate::config::uri::find_non_nil_uuid_edits(&uuid_masked);
                    let mut bi = 0usize;
                    let mut ei = 0usize;
                    let mut uuid_extra = Vec::new();
                    for (us, ue, urep) in uuid_edits {
                        while bi < base_structured.len() && base_structured[bi].1 <= us {
                            bi += 1;
                        }
                        let covered_by_base = bi < base_structured.len()
                            && base_structured[bi].0 <= us
                            && ue <= base_structured[bi].1;
                        while ei < extra_structured.len() && extra_structured[ei].1 <= us {
                            ei += 1;
                        }
                        let covered_by_extra = ei < extra_structured.len()
                            && extra_structured[ei].0 <= us
                            && ue <= extra_structured[ei].1;
                        if !covered_by_base && !covered_by_extra {
                            uuid_extra.push((us, ue, urep));
                        }
                    }
                    extra_structured.extend(uuid_extra);
                }
            }
        }
    }

    let mut events =
        Vec::with_capacity(base_structured.len() + extra_structured.len() + secret_spans.len());
    for (start, end, replacement) in base_structured.into_iter().chain(extra_structured) {
        events.push(ScrubEvent::Structured {
            start,
            end,
            replacement,
        });
    }
    for (start, end) in secret_spans {
        events.push(ScrubEvent::Secret { start, end });
    }

    if events.is_empty() {
        return (raw.to_string(), false);
    }

    events.sort_by_key(ScrubEvent::span);

    // Merge overlapping structured redactions and known-secret spans on `raw`'s coordinates.
    // Non-overlapping structured redactions preserve their exact replacement (e.g.
    // `https://host/***REDACTED***`), while any known-secret overlap expands to redact the
    // complete union interval so compound secrets and contextual prefixes can never leak.
    struct MergedCluster {
        start: usize,
        end: usize,
        replacement: String,
        is_partial_structured: bool,
    }

    let mut clusters: Vec<MergedCluster> = Vec::with_capacity(events.len());
    let mut iter = events.into_iter().peekable();
    while let Some(first) = iter.next() {
        let (cluster_start, mut cluster_end) = first.span();
        let mut structured_count = 0usize;
        let mut secret_count = 0usize;
        let mut single_structured: Option<(usize, usize, String)> = None;

        match first {
            ScrubEvent::Structured {
                start,
                end,
                replacement,
            } => {
                structured_count = 1;
                single_structured = Some((start, end, replacement));
            }
            ScrubEvent::Secret { .. } => {
                secret_count = 1;
            }
        }

        while let Some(next) = iter.peek() {
            let (ns, ne) = next.span();
            let overlaps = ns < cluster_end || (ns == cluster_end && ns == ne);
            if !overlaps {
                break;
            }
            let ev = iter.next().unwrap();
            if ne > cluster_end {
                cluster_end = ne;
            }
            match ev {
                ScrubEvent::Structured {
                    start,
                    end,
                    replacement,
                } => {
                    structured_count += 1;
                    if structured_count == 1 {
                        single_structured = Some((start, end, replacement));
                    } else {
                        single_structured = None;
                    }
                }
                ScrubEvent::Secret { .. } => {
                    secret_count += 1;
                }
            }
        }

        let (replacement, is_partial_structured) = if structured_count == 1 && secret_count == 0 {
            let (_, _, rep) = single_structured.unwrap();
            let is_pure_placeholder = rep == REDACTED_SECRET || rep == REDACTED_URL_PLACEHOLDER;
            if !is_pure_placeholder && has_secret_outside_placeholders(&rep, eligible) {
                (REDACTED_SECRET.to_string(), false)
            } else {
                (rep, !is_pure_placeholder)
            }
        } else if structured_count == 1
            && let Some((ss, se, rep)) = single_structured
            && rep == REDACTED_URL_PLACEHOLDER
            && ss == cluster_start
            && se == cluster_end
        {
            (REDACTED_URL_PLACEHOLDER.to_string(), false)
        } else {
            (REDACTED_SECRET.to_string(), false)
        };

        clusters.push(MergedCluster {
            start: cluster_start,
            end: cluster_end,
            replacement,
            is_partial_structured,
        });
    }

    let mut out = String::with_capacity(raw.len());
    let mut partial_out_spans: Vec<(usize, usize)> = Vec::new();
    let mut cursor = 0usize;
    for c in clusters {
        out.push_str(&raw[cursor..c.start]);
        let out_start = out.len();
        out.push_str(&c.replacement);
        let out_end = out.len();
        if c.is_partial_structured {
            partial_out_spans.push((out_start, out_end));
        }
        cursor = c.end;
    }
    out.push_str(&raw[cursor..]);

    // Second-order canonicalization guard: if a structured URL canonicalization (e.g. lowercasing
    // `HTTPS://` or normalizing default port) combined with adjacent literal text to form an
    // eligible secret, upgrade the entire union with any overlapped partial structured span to
    // `REDACTED_SECRET` so we never splice placeholders mid-URL.
    let leftover = find_secret_spans_outside_placeholders(&out, eligible);
    if !leftover.is_empty() {
        let mut to_redact = leftover.clone();
        let mut li = 0usize;
        for &(ps, pe) in &partial_out_spans {
            while li < leftover.len() && leftover[li].1 <= ps {
                li += 1;
            }
            if li < leftover.len() && leftover[li].0 < pe {
                to_redact.push((ps, pe));
            }
        }
        let merged = merge_overlapping_spans(to_redact);
        let mut scrubbed = String::with_capacity(out.len());
        let mut pos = 0usize;
        for (s, e) in merged {
            scrubbed.push_str(&out[pos..s]);
            scrubbed.push_str(REDACTED_SECRET);
            pos = e;
        }
        scrubbed.push_str(&out[pos..]);
        out = scrubbed;
    }

    let changed = out != raw;
    (out, changed)
}

fn scrub_sensitive_substrings(raw: &str, known_secrets: &[String]) -> String {
    let mut eligible: Vec<&str> = known_secrets
        .iter()
        .map(String::as_str)
        .filter(|sec| sec.len() >= 4 && *sec != REDACTED_SECRET && *sec != REDACTED_URL_PLACEHOLDER)
        .collect();
    if eligible.is_empty() {
        return crate::config::uri::redact_sensitive_text(raw);
    }
    eligible.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
    eligible.dedup();

    // Bounded fixed-point iteration ensures even second-order boundary exposures (e.g. scrubbing a
    // secret prefix glued directly onto `token=...` or a UUID) converge in strictly O(N) time and
    // guarantee mathematical idempotency `f(f(x)) == f(x)` for all inputs and secret sets.
    let (mut cur, mut changed) = scrub_sensitive_substrings_once(raw, &eligible);
    for _ in 0..3 {
        if !changed {
            break;
        }
        let (next, next_changed) = scrub_sensitive_substrings_once(&cur, &eligible);
        cur = next;
        changed = next_changed;
    }
    cur
}

async fn get_diagnostics_export_api(State(engine): State<Arc<ProxyEngine>>) -> impl IntoResponse {
    let cfg = engine.config_snapshot();
    let mut known_secrets = Vec::new();
    if let Some(ref s) = cfg.secret
        && !s.trim().is_empty()
    {
        known_secrets.push(s.trim().to_string());
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
                uuid,
                encryption,
                reality_opts,
                ..
            } => {
                known_secrets.push(uuid.to_string());
                if !encryption.is_empty() && encryption != "none" && encryption != REDACTED_SECRET {
                    known_secrets.push(encryption.clone());
                }
                if let Some(ro) = reality_opts {
                    if !ro.public_key.is_empty() && ro.public_key != REDACTED_SECRET {
                        known_secrets.push(ro.public_key.clone());
                    }
                    if let Some(ref sid) = ro.short_id
                        && !sid.is_empty()
                        && sid != REDACTED_SECRET
                    {
                        known_secrets.push(sid.clone());
                    }
                }
            }
            ProxyNodeConfig::Vmess { uuid, .. } => {
                known_secrets.push(uuid.to_string());
            }
            ProxyNodeConfig::Hysteria2 {
                password,
                obfs_password,
                ..
            } => {
                if !password.is_empty() && password != REDACTED_SECRET {
                    known_secrets.push(password.clone());
                }
                if let Some(opw) = obfs_password
                    && !opw.is_empty()
                    && opw != REDACTED_SECRET
                {
                    known_secrets.push(opw.clone());
                }
            }
            ProxyNodeConfig::Tuic { uuid, password, .. } => {
                known_secrets.push(uuid.to_string());
                if !password.is_empty() && password != REDACTED_SECRET {
                    known_secrets.push(password.clone());
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
                for v in headers.values() {
                    if !v.is_empty() && v != REDACTED_SECRET {
                        known_secrets.push(v.clone());
                    }
                }
            }
        }
    }
    for prov in cfg.rule_providers.values() {
        if let Some(ref raw_url) = prov.url
            && let Ok(parsed) = url::Url::parse(raw_url)
        {
            if let Some(pw) = parsed.password()
                && !pw.is_empty()
                && pw != REDACTED_SECRET
            {
                known_secrets.push(pw.to_string());
            }
            for (_, v) in parsed.query_pairs() {
                if !v.is_empty() && v.as_ref() != REDACTED_SECRET && v.len() >= 6 {
                    known_secrets.push(v.into_owned());
                }
            }
        }
    }

    let profiles = ensure_profile_manager(&engine).ok().map(|m| {
        let mut snap = m.snapshot();
        for p in &mut snap.profiles {
            p.name = scrub_sensitive_substrings(&p.name, &known_secrets);
            if let Some(url) = p.subscription_url_redacted.take() {
                p.subscription_url_redacted =
                    Some(scrub_sensitive_substrings(&url, &known_secrets));
            }
            if let Some(err) = p.last_error.take() {
                p.last_error = Some(scrub_sensitive_substrings(&err, &known_secrets));
            }
            if let Some(target) = p.match_only_fallback_target.take() {
                p.match_only_fallback_target =
                    Some(scrub_sensitive_substrings(&target, &known_secrets));
            }
            p.selected_groups = std::mem::take(&mut p.selected_groups)
                .into_iter()
                .map(|(k, v)| {
                    (
                        scrub_sensitive_substrings(&k, &known_secrets),
                        scrub_sensitive_substrings(&v, &known_secrets),
                    )
                })
                .collect();
            p.custom_rules_backup = std::mem::take(&mut p.custom_rules_backup)
                .into_iter()
                .map(|rule| scrub_sensitive_substrings(&rule, &known_secrets))
                .collect();
        }
        snap
    });
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

    let recent_all = engine.hub().diagnostics_snapshot(100);
    let mut active_cnt = 0usize;
    let mut connecting_cnt = 0usize;
    let mut closed_cnt = 0usize;
    let mut failed_cnt = 0usize;
    let mut by_exit: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    let mut by_network: std::collections::BTreeMap<String, usize> =
        std::collections::BTreeMap::new();
    let mut zero_download_tcp_count = 0usize;
    let mut tun_fake_ip_count = 0usize;
    let mut tun_real_ip_count = 0usize;
    for entry in &recent_all {
        match entry.status.as_str() {
            "active" => active_cnt += 1,
            "connecting" => connecting_cnt += 1,
            "closed" => closed_cnt += 1,
            "failed" => failed_cnt += 1,
            _ => {}
        }
        let exit_key = if entry.exit_type.is_empty() {
            "UNKNOWN"
        } else {
            entry.exit_type.as_str()
        };
        *by_exit.entry(exit_key.to_string()).or_insert(0) += 1;
        let net_key = if entry.metadata.network.is_empty() {
            "unknown"
        } else {
            entry.metadata.network.as_str()
        };
        *by_network.entry(net_key.to_string()).or_insert(0) += 1;
        if net_key.eq_ignore_ascii_case("tcp") && entry.upload > 0 && entry.download == 0 {
            zero_download_tcp_count += 1;
        }
        if entry.metadata.inbound_type.starts_with("TUN") {
            if entry
                .metadata
                .fake_ip
                .as_deref()
                .is_some_and(|s| !s.is_empty())
            {
                tun_fake_ip_count += 1;
            } else {
                tun_real_ip_count += 1;
            }
        }
    }
    let recent_connections_summary = serde_json::json!({
        "sampled_count": recent_all.len(),
        "active": active_cnt,
        "connecting": connecting_cnt,
        "closed": closed_cnt,
        "failed": failed_cnt,
        "by_exit": by_exit,
        "by_network": by_network,
        "zero_download_tcp_count": zero_download_tcp_count,
        "tun_fake_ip_count": tun_fake_ip_count,
        "tun_real_ip_count": tun_real_ip_count,
    });

    let failed_diagnostics_redacted: Vec<serde_json::Value> = engine
        .hub()
        .failed_diagnostics_snapshot(50)
        .into_iter()
        .map(|mut d| {
            d.metadata.host = scrub_sensitive_substrings(&d.metadata.host, &known_secrets);
            d.metadata.source = scrub_sensitive_substrings(&d.metadata.source, &known_secrets);
            if let Some(ip) = d.metadata.destination_ip.take() {
                d.metadata.destination_ip = Some(scrub_sensitive_substrings(&ip, &known_secrets));
            }
            if let Some(fip) = d.metadata.fake_ip.take() {
                d.metadata.fake_ip = Some(scrub_sensitive_substrings(&fip, &known_secrets));
            }
            if let Some(proc_name) = d.metadata.process.take() {
                d.metadata.process = Some(scrub_sensitive_substrings(&proc_name, &known_secrets));
            }
            d.rule_payload = scrub_sensitive_substrings(&d.rule_payload, &known_secrets);
            d.effective_outbound =
                scrub_sensitive_substrings(&d.effective_outbound, &known_secrets);
            d.remote_endpoint = scrub_sensitive_substrings(&d.remote_endpoint, &known_secrets);
            d.chains = d
                .chains
                .into_iter()
                .map(|c| scrub_sensitive_substrings(&c, &known_secrets))
                .collect();
            if let Some(err) = d.error.take() {
                d.error = Some(scrub_sensitive_substrings(&err, &known_secrets));
            }
            serde_json::to_value(d).unwrap_or(serde_json::Value::Null)
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
        "recent_connections_summary": recent_connections_summary,
        "failed_diagnostics": failed_diagnostics_redacted,
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
        Some(raw) if !raw.trim().is_empty() => match ClashConfig::from_yaml_str(raw)
            .or_else(|_| ClashConfig::from_yaml_str_sanitized(raw).map(|(c, _)| c))
        {
            Ok(mut parsed) => {
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

/// Returns the exact loopback `(ip, port)` endpoints permitted for HTTP/HTTPS probe URLs
/// in built-in `--demo` sandbox mode (`demo.http_benchmark_origin` ONLY — never `engine.dns_addr()`).
pub fn demo_allowed_private_addrs(engine: &ProxyEngine) -> Vec<SocketAddr> {
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
    allowed
}

/// Returns the exact loopback `(ip, port)` endpoint permitted strictly for UDP DNS probes
/// in built-in `--demo` sandbox mode (`engine.dns_addr()` ONLY).
pub fn demo_allowed_udp_private_addrs(engine: &ProxyEngine) -> Vec<SocketAddr> {
    let demo = engine.demo_info();
    if !demo.enabled {
        return Vec::new();
    }
    let mut allowed = Vec::new();
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
    let allowed_private_udp = demo_allowed_udp_private_addrs(&engine);
    let router = engine.router();
    let cfg = engine.config_snapshot();
    let extra_ca = engine.extra_ca_der();
    let timeout = Duration::from_millis(req.timeout.clamp(200, 15_000));

    match crate::probe::probe_target_waterfall_with_udp_allowlist(
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
        &allowed_private_udp,
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
    let allowed_private_udp = demo_allowed_udp_private_addrs(&engine);
    let router = engine.router();
    let cfg = engine.config_snapshot();
    let extra_ca = engine.extra_ca_der();
    let timeout = Duration::from_millis(req.timeout.clamp(200, 15_000));

    match crate::probe::probe_endpoint_matrix_with_udp_allowlist(
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
        &allowed_private_udp,
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

#[derive(Deserialize)]
struct SiteCheckReq {
    target: String,
    #[serde(default = "default_true_bool")]
    check_udp: bool,
    udp_dns_target: Option<String>,
    #[serde(default = "default_delay_timeout_ms", alias = "timeout_ms")]
    timeout: u64,
}

async fn post_diagnostics_site_check_api(
    State(engine): State<Arc<ProxyEngine>>,
    Json(req): Json<SiteCheckReq>,
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

    let sysproxy = query_sysproxy_status(&engine.state_dir());
    let takeover = crate::probe::SiteTakeoverContext {
        core_running: true,
        sysproxy_enabled: sysproxy.enabled,
        tun_enabled: engine.is_tun_active() || engine.is_virtual_tun_active(),
        platform_hint: "desktop".to_string(),
    };

    let allowed_private = demo_allowed_private_addrs(&engine);
    let allowed_private_udp = demo_allowed_udp_private_addrs(&engine);
    let router = engine.router();
    let cfg = engine.config_snapshot();
    let extra_ca = engine.extra_ca_der();
    let timeout = Duration::from_millis(req.timeout.clamp(300, 15_000));

    match crate::probe::diagnose_site_with_udp_allowlist(
        &router,
        &cfg,
        &req.target,
        takeover,
        crate::probe::ProbeOptions {
            extra_ca_der: &extra_ca,
            check_udp: req.check_udp,
            udp_dns_target: udp_target_ref,
            timeout,
            allow_private_targets: false,
            allowed_private_addrs: &allowed_private,
        },
        &allowed_private_udp,
    )
    .await
    {
        Ok(report) => (StatusCode::OK, Json(report)).into_response(),
        Err(err) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "message": crate::config::uri::redact_sensitive_text(&err.to_string())
            })),
        )
            .into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probe::extract_http_response_body_str;

    #[test]
    fn parse_proc_status_extracts_rss_anon_in_bytes() {
        let sample = "\
Name:\trustclash
VmPeak:\t4250000 kB
VmRSS:\t  392400 kB
RssAnon:\t   51200 kB
RssFile:\t  251100 kB
RssShmem:\t   90100 kB
";
        assert_eq!(
            parse_proc_status_anon_rss_bytes(sample),
            Some(51_200 * 1024)
        );
        assert_eq!(parse_proc_status_anon_rss_bytes("VmRSS:\t1200 kB\n"), None);

        let rss = read_process_rss_bytes();
        let total = read_process_total_vmrss_bytes();
        assert!(rss > 0);
        assert!(total >= rss || total > 0);
    }

    #[tokio::test]
    async fn profile_raw_yaml_endpoints_and_ws_graceful_shutdown() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let tmp_dir =
            std::env::temp_dir().join(format!("rc-api-prof-raw-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&tmp_dir).unwrap();
        let prof_mgr =
            crate::profile::ProfileManager::open_or_init(&tmp_dir).expect("init profile manager");

        let yaml_a = "\
mixed-port: 0
mode: rule
dns:
  enable: false
proxies:
  - name: Node-A
    type: ss
    server: 198.51.100.10
    port: 8388
    cipher: aes-256-gcm
    password: secret-password-a
proxy-groups:
  - name: PROXY
    type: select
    proxies: [Node-A, DIRECT]
rules:
  - MATCH,PROXY
";
        let yaml_b = "\
mixed-port: 0
mode: rule
dns:
  enable: false
proxies:
  - name: Node-B
    type: ss
    server: 198.51.100.20
    port: 8388
    cipher: aes-256-gcm
    password: secret-password-b
proxy-groups:
  - name: PROXY
    type: select
    proxies: [Node-B, DIRECT]
rules:
  - MATCH,PROXY
";

        let (meta_a, _, _) = prof_mgr
            .create_profile_detailed(crate::profile::CreateProfileSpec {
                name: "Profile A".to_string(),
                yaml: Some(yaml_a.to_string()),
                uris: None,
                subscription_url: None,
                auto_update_interval_secs: None,
                activate: true,
            })
            .await
            .unwrap();
        let (meta_b, _, _) = prof_mgr
            .create_profile_detailed(crate::profile::CreateProfileSpec {
                name: "Profile B".to_string(),
                yaml: Some(yaml_b.to_string()),
                uris: None,
                subscription_url: None,
                auto_update_interval_secs: None,
                activate: false,
            })
            .await
            .unwrap();

        let cfg_a = ClashConfig::from_yaml_str(yaml_a).unwrap();
        let engine = ProxyEngine::start_with_state_dir(cfg_a, tmp_dir.clone())
            .await
            .expect("start engine");
        engine.attach_profile_manager(Arc::clone(&prof_mgr));

        let (stop_tx, stop_rx) = watch::channel(false);
        let (bound, server_handle) = spawn_api_server("127.0.0.1:0", Arc::clone(&engine), stop_rx)
            .await
            .expect("spawn api server");

        // Open a live /traffic WebSocket stream so we also verify graceful shutdown doesn't hang!
        let (mut ws_stream, _) = tokio_tungstenite::connect_async(format!("ws://{bound}/traffic"))
            .await
            .expect("connect /traffic ws");

        // 1. GET /profiles/{id}/raw on inactive Profile B returns redacted YAML without changing active Profile A
        let mut get_conn = tokio::net::TcpStream::connect(bound).await.unwrap();
        let get_http = format!(
            "GET /profiles/{}/raw HTTP/1.1\r\nHost: {bound}\r\nConnection: close\r\n\r\n",
            meta_b.id
        );
        get_conn.write_all(get_http.as_bytes()).await.unwrap();
        let mut get_raw = Vec::new();
        get_conn.read_to_end(&mut get_raw).await.unwrap();
        let get_body = extract_http_response_body_str(&get_raw).unwrap();
        let get_json: serde_json::Value = serde_json::from_str(&get_body).unwrap();
        assert_eq!(get_json["active"], false);
        assert_eq!(get_json["redacted"], true);
        let redacted_b = get_json["yaml"].as_str().unwrap();
        assert!(redacted_b.contains("Node-B"));
        assert!(!redacted_b.contains("secret-password-b"));
        assert_eq!(prof_mgr.snapshot().active_profile_id, meta_a.id);

        // 2. PUT /profiles/{id}/raw updates inactive Profile B (restoring redacted secret!) while keeping Profile A active
        let updated_b = redacted_b.replace("port: 8388", "port: 9443");
        let put_payload = serde_json::json!({ "payload": updated_b }).to_string();
        let mut put_conn = tokio::net::TcpStream::connect(bound).await.unwrap();
        let put_http = format!(
            "PUT /profiles/{}/raw HTTP/1.1\r\nHost: {bound}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            meta_b.id,
            put_payload.len(),
            put_payload
        );
        put_conn.write_all(put_http.as_bytes()).await.unwrap();
        let mut put_raw = Vec::new();
        put_conn.read_to_end(&mut put_raw).await.unwrap();
        assert!(String::from_utf8_lossy(&put_raw).starts_with("HTTP/1.1 200"));
        assert_eq!(prof_mgr.snapshot().active_profile_id, meta_a.id);

        let saved_cfg_b = prof_mgr
            .load_profile_config_by_id(&meta_b.id)
            .expect("load updated Profile B");
        assert_eq!(saved_cfg_b.proxies[0].name(), "Node-B");
        match &saved_cfg_b.proxies[0] {
            crate::config::ProxyNodeConfig::Ss { port, password, .. } => {
                assert_eq!(*port, 9443);
                assert_eq!(password, "secret-password-b");
            }
            other => panic!("unexpected node variant: {other:?}"),
        }

        // 3. Trigger API shutdown while ws_stream is open — server_handle must exit promptly (< 2s)
        let _ = stop_tx.send(true);
        tokio::time::timeout(Duration::from_secs(2), server_handle)
            .await
            .expect("API server with active WebSocket must shut down cleanly within 2s")
            .unwrap();
        let _ = ws_stream.close(None).await;

        engine.shutdown();
        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[tokio::test]
    async fn patch_configs_rebinds_mixed_port_toggles_ipv6_allows_lan_spa_and_serves_group_delay() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let tmp_dir = std::env::temp_dir().join(format!("rc-api-patch-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&tmp_dir).unwrap();

        let yaml = "\
mixed-port: 0
mode: rule
ipv6: true
dns:
  enable: false
  ipv6: true
proxies: []
proxy-groups:
  - name: PROXY
    type: select
    proxies: [DIRECT]
rules:
  - MATCH,PROXY
";
        let cfg = ClashConfig::from_yaml_str(yaml).unwrap();
        let engine = ProxyEngine::start_with_state_dir(cfg, tmp_dir.clone())
            .await
            .expect("start engine");
        let initial_mixed_port = engine.mixed_addr().port();

        let probe_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_new_port = probe_listener.local_addr().unwrap().port();
        drop(probe_listener);

        let (stop_tx, stop_rx) = watch::channel(false);
        let (bound, server_handle) = spawn_api_server("127.0.0.1:0", Arc::clone(&engine), stop_rx)
            .await
            .expect("spawn api server");

        // 1. Unauthenticated LAN hostname (`router.local`) is permitted on static SPA `GET /` (#20)
        //    but rejected with 403 on unauthenticated API routes (DNS-rebinding defense preserved).
        let mut spa_conn = tokio::net::TcpStream::connect(bound).await.unwrap();
        spa_conn
            .write_all(
                format!(
                    "GET / HTTP/1.1\r\nHost: router.local:{}\r\nConnection: close\r\n\r\n",
                    bound.port()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut spa_raw = Vec::new();
        spa_conn.read_to_end(&mut spa_raw).await.unwrap();
        let spa_head = String::from_utf8_lossy(&spa_raw);
        assert!(
            spa_head.starts_with("HTTP/1.1 200"),
            "LAN hostname GET / should serve SPA shell, got: {spa_head}"
        );

        let mut rebind_conn = tokio::net::TcpStream::connect(bound).await.unwrap();
        rebind_conn
            .write_all(
                format!(
                    "GET /configs HTTP/1.1\r\nHost: router.local:{}\r\nConnection: close\r\n\r\n",
                    bound.port()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut rebind_raw = Vec::new();
        rebind_conn.read_to_end(&mut rebind_raw).await.unwrap();
        assert!(String::from_utf8_lossy(&rebind_raw).starts_with("HTTP/1.1 403"));

        // 2. PATCH /configs updates `mixed-port` and top-level `ipv6` live (#18a)
        let patch_body = serde_json::json!({
            "mixed-port": target_new_port,
            "ipv6": false,
            "tun": { "ipv6": false }
        })
        .to_string();
        let mut patch_conn = tokio::net::TcpStream::connect(bound).await.unwrap();
        patch_conn
            .write_all(
                format!(
                    "PATCH /configs HTTP/1.1\r\nHost: {bound}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    patch_body.len(),
                    patch_body
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut patch_raw = Vec::new();
        patch_conn.read_to_end(&mut patch_raw).await.unwrap();
        assert!(
            String::from_utf8_lossy(&patch_raw).starts_with("HTTP/1.1 204"),
            "PATCH /configs failed: {}",
            String::from_utf8_lossy(&patch_raw)
        );
        assert_eq!(engine.mixed_addr().port(), target_new_port);
        assert_ne!(engine.mixed_addr().port(), initial_mixed_port);
        assert!(!engine.config_snapshot().dns.ipv6);
        assert!(!engine.config_snapshot().tun.ipv6);

        // 3. Non-demo HTTP GET /group/PROXY/delay against loopback MUST be blocked with 400 (SSRF),
        //    while internal hermetic `router.test_delay` still probes the local mock server cleanly.
        let bench_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let bench_addr = bench_listener.local_addr().unwrap();
        let bench_hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let bench_hits_bg = Arc::clone(&bench_hits);
        tokio::spawn(async move {
            while let Ok((mut s, _)) = bench_listener.accept().await {
                bench_hits_bg.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let mut b = [0u8; 512];
                let _ = s.read(&mut b).await;
                let _ = s
                    .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                    .await;
            }
        });
        let mut grp_conn = tokio::net::TcpStream::connect(bound).await.unwrap();
        grp_conn
            .write_all(
                format!(
                    "GET /group/PROXY/delay?url=http%3A%2F%2F127.0.0.1%3A{}%2Fgenerate_204&timeout=2000 HTTP/1.1\r\nHost: {bound}\r\nConnection: close\r\n\r\n",
                    bench_addr.port()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut grp_raw = Vec::new();
        grp_conn.read_to_end(&mut grp_raw).await.unwrap();
        assert!(
            String::from_utf8_lossy(&grp_raw).starts_with("HTTP/1.1 400"),
            "non-demo loopback /group/PROXY/delay must return 400 SSRF error: {}",
            String::from_utf8_lossy(&grp_raw)
        );
        assert_eq!(
            bench_hits.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "blocked SSRF delay probe must never dial loopback target"
        );

        let local_url = format!("http://127.0.0.1:{}/generate_204", bench_addr.port());
        let internal_ms = engine
            .router()
            .test_delay("PROXY", &local_url, Duration::from_secs(2))
            .await
            .expect("hermetic internal router.test_delay must still work");
        assert!(internal_ms >= 1);
        assert!(engine.router().effective_member_delay("DIRECT").is_some());

        let _ = stop_tx.send(true);
        let _ = server_handle.await;
        engine.shutdown();
        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn parse_explain_target_accepts_full_urls_paths_and_bracketed_ipv6() {
        assert_eq!(
            parse_explain_target("https://chatgpt.com/g/g-123?foo=bar")
                .unwrap()
                .to_string(),
            "chatgpt.com:443"
        );
        assert_eq!(
            parse_explain_target("http://example.com/healthz")
                .unwrap()
                .to_string(),
            "example.com:80"
        );
        assert_eq!(
            parse_explain_target("http://[::1]:8080/api/v1")
                .unwrap()
                .to_string(),
            "[::1]:8080"
        );
        assert_eq!(
            parse_explain_target("[2606:4700:4700::1111]")
                .unwrap()
                .to_string(),
            "[2606:4700:4700::1111]:443"
        );
        assert_eq!(
            parse_explain_target("github.com/rust-lang/rust")
                .unwrap()
                .to_string(),
            "github.com:443"
        );
        assert_eq!(
            parse_explain_target("1.1.1.1").unwrap().to_string(),
            "1.1.1.1:443"
        );
    }

    #[tokio::test]
    async fn diagnostics_export_includes_redacted_failed_diagnostics_and_summary() {
        let tmp_dir = std::env::temp_dir().join(format!(
            "rustclash-api-diag-export-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&tmp_dir).unwrap();
        let yaml = "mixed-port: 0\nexternal-controller: \"\"\nsecret: \"super-secret-token-99\"\nmode: rule\nproxies:\n  - name: demo-ss\n    type: ss\n    server: 198.51.100.20\n    port: 8388\n    cipher: aes-128-gcm\n    password: \"ss-secret-pass-42\"\nrules:\n  - MATCH,DIRECT\n";
        let mut cfg = ClashConfig::from_yaml_str(yaml).unwrap();
        cfg.dns.enable = false;
        let engine = ProxyEngine::start_with_state_dir(cfg, tmp_dir.clone())
            .await
            .unwrap();

        // Register a failed diagnostic whose error accidentally mentions a secret substring
        let target = crate::addr::TargetAddr::new_domain("fail.example.test", 443).unwrap();
        let g = engine.hub().register_connection_guard(
            "Mixed(SOCKS5)",
            "tcp",
            None,
            &target,
            None,
            "MATCH",
            "",
            vec!["demo-ss".to_string()],
        );
        g.record_failed("auth failed with ss-secret-pass-42 and super-secret-token-99");

        let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
        let (bound, server_handle) = spawn_api_server("127.0.0.1:0", Arc::clone(&engine), stop_rx)
            .await
            .unwrap();

        let mut conn = tokio::net::TcpStream::connect(bound).await.unwrap();
        conn.write_all(
            format!(
                "GET /diagnostics/export HTTP/1.1\r\nHost: {bound}\r\nAuthorization: Bearer super-secret-token-99\r\nConnection: close\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
        let mut raw = Vec::new();
        conn.read_to_end(&mut raw).await.unwrap();
        assert!(String::from_utf8_lossy(&raw).starts_with("HTTP/1.1 200"));
        let body = extract_http_response_body_str(&raw).unwrap();
        assert!(
            !body.contains("ss-secret-pass-42") && !body.contains("super-secret-token-99"),
            "export bundle must never leak secrets in failed_diagnostics"
        );
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        let failed = parsed["failed_diagnostics"]
            .as_array()
            .expect("failed_diagnostics array");
        assert_eq!(failed.len(), 1);
        assert_eq!(failed[0]["metadata"]["host"], "fail.example.test");
        assert_eq!(failed[0]["status"], "failed");
        assert!(
            failed[0]["error"]
                .as_str()
                .is_some_and(|e| e.contains("auth failed")),
            "redacted error context must be preserved"
        );
        assert_eq!(parsed["recent_connections_summary"]["failed"], 1);
        assert_eq!(parsed["recent_connections_summary"]["sampled_count"], 1);

        let _ = stop_tx.send(true);
        let _ = server_handle.await;
        engine.shutdown();
        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[tokio::test]
    async fn delay_endpoints_enforce_ssrf_dns_rebinding_and_demo_whitelist() {
        use std::{
            net::Ipv4Addr,
            sync::atomic::{AtomicUsize, Ordering},
        };
        use tokio::net::UdpSocket;

        use crate::dns::wire::{DnsAnswerData, DnsQueryPacket, QTYPE_A};

        let tmp_dir =
            std::env::temp_dir().join(format!("rustclash-api-delay-ssrf-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&tmp_dir).unwrap();

        // Canary TCP listener that MUST NEVER be dialed by blocked delay probes
        let canary = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let canary_addr = canary.local_addr().unwrap();
        let canary_hits = Arc::new(AtomicUsize::new(0));
        let canary_hits_bg = Arc::clone(&canary_hits);
        let (bg_stop_tx, mut bg_stop_rx) = tokio::sync::watch::channel(false);
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = bg_stop_rx.changed() => break,
                    acc = canary.accept() => {
                        let Ok((mut s, _)) = acc else { continue };
                        canary_hits_bg.fetch_add(1, Ordering::SeqCst);
                        let _ = s
                            .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                            .await;
                    }
                }
            }
        });

        // Mock upstream DNS resolving attacker domains to loopback & IMDS
        let mock_ns = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let mock_ns_addr = mock_ns.local_addr().unwrap();
        let ns_bg = Arc::clone(&mock_ns);
        let mut ns_stop = bg_stop_tx.subscribe();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            loop {
                tokio::select! {
                    _ = ns_stop.changed() => break,
                    res = ns_bg.recv_from(&mut buf) => {
                        let Ok((n, peer)) = res else { continue };
                        let Ok(pkt) = DnsQueryPacket::parse(&buf[..n]) else { continue };
                        let q = pkt.question.name.to_ascii_lowercase();
                        let resp = match (q.as_str(), pkt.question.qtype) {
                            ("rebind-loopback.attacker.test", QTYPE_A) => pkt.build_response(
                                &buf[..n],
                                0,
                                60,
                                &[DnsAnswerData::A(Ipv4Addr::LOCALHOST)],
                            ),
                            ("rebind-imds.attacker.test", QTYPE_A) => pkt.build_response(
                                &buf[..n],
                                0,
                                60,
                                &[DnsAnswerData::A(Ipv4Addr::new(169, 254, 169, 254))],
                            ),
                            _ => pkt.build_response(&buf[..n], 0, 60, &[]),
                        };
                        let _ = ns_bg.send_to(&resp, peer).await;
                    }
                }
            }
        });

        let yaml = format!(
            "mixed-port: 0\nexternal-controller: \"\"\nmode: rule\ndns:\n  enable: true\n  listen: 127.0.0.1:0\n  nameserver:\n    - \"{mock_ns_addr}\"\n  direct-nameserver:\n    - \"{mock_ns_addr}\"\nproxy-groups:\n  - name: PROXY\n    type: select\n    proxies: [DIRECT]\nrules:\n  - MATCH,PROXY\n"
        );
        let cfg = ClashConfig::from_yaml_str(&yaml).unwrap();
        let engine = ProxyEngine::start_with_state_dir(cfg, tmp_dir.clone())
            .await
            .unwrap();
        // Pre-seed healthy delay on DIRECT and verify SSRF rejections NEVER poison it!
        engine.router().delays().record("DIRECT", 19);

        let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
        let (bound, server_handle) = spawn_api_server("127.0.0.1:0", Arc::clone(&engine), stop_rx)
            .await
            .unwrap();

        async fn send_get(addr: SocketAddr, path: &str) -> (u16, String) {
            let mut conn = tokio::net::TcpStream::connect(addr).await.unwrap();
            conn.write_all(
                format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n")
                    .as_bytes(),
            )
            .await
            .unwrap();
            let mut raw = Vec::new();
            conn.read_to_end(&mut raw).await.unwrap();
            let text = String::from_utf8_lossy(&raw).into_owned();
            let status = text
                .lines()
                .next()
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|s| s.parse::<u16>().ok())
                .unwrap_or(0);
            let body = extract_http_response_body_str(&raw).unwrap_or_default();
            (status, body)
        }

        let ssrf_urls = [
            format!("http://127.0.0.1:{}/generate_204", canary_addr.port()),
            format!("http://localhost:{}/generate_204", canary_addr.port()),
            "http://0.1.2.3/generate_204".to_string(),
            "http://[::127.0.0.1]/generate_204".to_string(),
            "http://[::ffff:0:127.0.0.1]/generate_204".to_string(),
            "http://[fec0::1]/generate_204".to_string(),
            "http://[100::1]/generate_204".to_string(),
            "http://169.254.169.254/latest/meta-data/".to_string(),
            "http://10.0.0.1/admin".to_string(),
            "http://[fd00:ec2::254]/latest/meta-data/".to_string(),
            "ftp://example.com/file".to_string(),
            "http://alice:supersecret99@example.com/generate_204".to_string(),
            format!(
                "http://rebind-loopback.attacker.test:{}/generate_204",
                canary_addr.port()
            ),
            "http://rebind-imds.attacker.test/latest/meta-data/".to_string(),
        ];

        for raw_target in &ssrf_urls {
            let encoded =
                url::form_urlencoded::byte_serialize(raw_target.as_bytes()).collect::<String>();
            for endpoint in [
                format!("/proxies/DIRECT/delay?url={encoded}&timeout=2000"),
                format!("/group/PROXY/delay?url={encoded}&timeout=2000"),
            ] {
                let (code, body) = send_get(bound, &endpoint).await;
                assert_eq!(
                    code, 400,
                    "expected 400 Bad Request for SSRF target {raw_target} on {endpoint}, got {code}: {body}"
                );
                assert!(
                    !body.contains("supersecret99"),
                    "error response must redact userinfo secrets: {body}"
                );
            }
        }
        assert_eq!(
            canary_hits.load(Ordering::SeqCst),
            0,
            "blocked SSRF probes must never connect to canary socket"
        );
        assert_eq!(
            engine.router().delays().latest_delay("DIRECT"),
            Some(19),
            "SSRF 400 rejection must not poison recorded healthy delay"
        );

        // Unknown proxy with valid public URL returns 404 Not Found
        let (nf_code, _) = send_get(
            bound,
            "/proxies/NO_SUCH_PROXY/delay?url=http%3A%2F%2Fwww.gstatic.com%2Fgenerate_204&timeout=1000",
        )
        .await;
        assert_eq!(nf_code, 404);

        let _ = stop_tx.send(true);
        let _ = server_handle.await;
        engine.shutdown();

        // Demo mode: whitelisted benchmark origin succeeds (200), while disallowed localhost canary port is blocked (400)!
        let demo_engine = ProxyEngine::start_demo(
            Some(0),
            Some("127.0.0.1:0".into()),
            Some("127.0.0.1:0".into()),
        )
        .await
        .unwrap();
        let (demo_stop_tx, demo_stop_rx) = tokio::sync::watch::channel(false);
        let (demo_bound, demo_srv) =
            spawn_api_server("127.0.0.1:0", Arc::clone(&demo_engine), demo_stop_rx)
                .await
                .unwrap();

        async fn send_post_json(addr: SocketAddr, path: &str, body: &str) -> (u16, String) {
            let mut conn = tokio::net::TcpStream::connect(addr).await.unwrap();
            conn.write_all(
                format!(
                    "POST {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
            let mut raw = Vec::new();
            conn.read_to_end(&mut raw).await.unwrap();
            let text = String::from_utf8_lossy(&raw).into_owned();
            let status = text
                .lines()
                .next()
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|s| s.parse::<u16>().ok())
                .unwrap_or(0);
            let resp_body = extract_http_response_body_str(&raw).unwrap_or_default();
            (status, resp_body)
        }

        let demo_dns_addr = demo_engine.dns_addr().expect("demo engine has DNS port");
        let demo_http_allow = demo_allowed_private_addrs(&demo_engine);
        let demo_udp_allow = demo_allowed_udp_private_addrs(&demo_engine);
        assert!(
            !demo_http_allow.contains(&demo_dns_addr),
            "demo_allowed_private_addrs must NEVER include engine.dns_addr()"
        );
        assert!(
            demo_udp_allow.contains(&demo_dns_addr),
            "demo_allowed_udp_private_addrs must include engine.dns_addr()"
        );

        let demo_origin = demo_engine.demo_info().http_benchmark_origin;
        let allowed_url = format!("{demo_origin}/generate_204");
        let allowed_enc =
            url::form_urlencoded::byte_serialize(allowed_url.as_bytes()).collect::<String>();
        let (ok_code, ok_body) = send_get(
            demo_bound,
            &format!("/proxies/DIRECT/delay?url={allowed_enc}&timeout=3000"),
        )
        .await;
        assert_eq!(
            ok_code, 200,
            "Demo whitelisted benchmark origin must return 200: {ok_body}"
        );

        // Demo mode MUST reject HTTP probes targeting `engine.dns_addr()` across `/delay`, `/group/.../delay`,
        // `/probe`, and `/diagnostics/site-check` (`400 Bad Request`).
        let demo_group = demo_engine
            .config_snapshot()
            .proxy_groups
            .first()
            .expect("demo config has a proxy group")
            .name
            .clone();
        let demo_group_enc =
            url::form_urlencoded::byte_serialize(demo_group.as_bytes()).collect::<String>();
        for dns_http_url in [
            format!("http://127.0.0.1:{}/", demo_dns_addr.port()),
            format!("http://localhost:{}/", demo_dns_addr.port()),
        ] {
            let dns_enc =
                url::form_urlencoded::byte_serialize(dns_http_url.as_bytes()).collect::<String>();
            for ep in [
                format!("/proxies/DIRECT/delay?url={dns_enc}&timeout=1000"),
                format!("/group/{demo_group_enc}/delay?url={dns_enc}&timeout=1000"),
            ] {
                let (code, body) = send_get(demo_bound, &ep).await;
                assert_eq!(
                    code, 400,
                    "Demo HTTP delay must block engine.dns_addr() ({dns_http_url}) on {ep}, got {code}: {body}"
                );
            }
            let probe_body = serde_json::json!({
                "url": dns_http_url,
                "check_udp": false,
                "timeout": 1000
            })
            .to_string();
            let (probe_code, probe_resp) =
                send_post_json(demo_bound, "/proxies/DIRECT/probe", &probe_body).await;
            assert_eq!(
                probe_code, 400,
                "Demo POST /proxies/DIRECT/probe must block engine.dns_addr() ({dns_http_url}), got {probe_code}: {probe_resp}"
            );
            let site_body = serde_json::json!({
                "target": dns_http_url,
                "check_udp": false,
                "timeout": 1000
            })
            .to_string();
            let (site_code, site_resp) =
                send_post_json(demo_bound, "/diagnostics/site-check", &site_body).await;
            assert_eq!(
                site_code, 400,
                "Demo POST /diagnostics/site-check must block engine.dns_addr() ({dns_http_url}), got {site_code}: {site_resp}"
            );
        }

        // Demo waterfall probe against whitelisted `demo.http_benchmark_origin` with `check_udp: true`
        // MUST STILL succeed on BOTH HTTP AND Demo UDP DNS probing!
        let ok_probe_body = serde_json::json!({
            "url": allowed_url,
            "check_udp": true,
            "timeout": 3000
        })
        .to_string();
        let (ok_probe_code, ok_probe_resp) =
            send_post_json(demo_bound, "/proxies/DIRECT/probe", &ok_probe_body).await;
        assert_eq!(
            ok_probe_code, 200,
            "Demo waterfall probe with HTTP origin + UDP DNS must return 200: {ok_probe_resp}"
        );
        let ok_probe_json: serde_json::Value = serde_json::from_str(&ok_probe_resp).unwrap();
        assert_eq!(ok_probe_json["verdict"], "reachable");
        assert_eq!(ok_probe_json["udp_probe"]["status"], "verified");

        let disallowed_demo_url = format!("http://127.0.0.1:{}/generate_204", canary_addr.port());
        let disallowed_enc = url::form_urlencoded::byte_serialize(disallowed_demo_url.as_bytes())
            .collect::<String>();
        let (bad_demo_code, bad_demo_body) = send_get(
            demo_bound,
            &format!("/proxies/DIRECT/delay?url={disallowed_enc}&timeout=2000"),
        )
        .await;
        assert_eq!(
            bad_demo_code, 400,
            "Demo mode must still reject non-whitelisted localhost ports with 400: {bad_demo_body}"
        );
        assert_eq!(canary_hits.load(Ordering::SeqCst), 0);

        let _ = demo_stop_tx.send(true);
        let _ = demo_srv.await;
        demo_engine.shutdown();
        let _ = bg_stop_tx.send(true);
        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn detect_primary_lan_ipv4_protects_udp_and_rejects_fake_ip_and_link_local() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let fake_net: ipnet::Ipv4Net = "198.18.0.0/15".parse().unwrap();
        let custom_fake_net: ipnet::Ipv4Net = "100.64.0.0/16".parse().unwrap();

        // 1. Fake-IP TUN addresses, loopback, unspecified, multicast, broadcast, and IPv6 are rejected.
        assert_eq!(
            select_lan_ipv4_candidate(
                [
                    "198.18.0.1".parse().unwrap(),
                    "198.19.255.254".parse().unwrap(),
                    "127.0.0.1".parse().unwrap(),
                    "0.0.0.0".parse().unwrap(),
                    "224.0.0.1".parse().unwrap(),
                    "255.255.255.255".parse().unwrap(),
                    "fe80::1".parse().unwrap(),
                ],
                fake_net
            ),
            None
        );

        // Custom `fake-ip-range` is also rejected.
        assert_eq!(
            select_lan_ipv4_candidate(
                [
                    "100.64.0.1".parse().unwrap(),
                    "192.168.50.12".parse().unwrap(),
                ],
                custom_fake_net
            ),
            Some("192.168.50.12".to_string())
        );

        // 2. Link-local `169.254.0.0/16` is bypassed when a normal LAN IPv4 exists,
        //    and only returned when it is the sole usable fallback.
        assert_eq!(
            select_lan_ipv4_candidate(
                [
                    "198.18.0.1".parse().unwrap(),
                    "169.254.42.7".parse().unwrap(),
                    "10.0.0.23".parse().unwrap(),
                ],
                fake_net
            ),
            Some("10.0.0.23".to_string())
        );
        assert_eq!(
            select_lan_ipv4_candidate(
                [
                    "198.18.0.1".parse().unwrap(),
                    "169.254.42.7".parse().unwrap(),
                ],
                fake_net
            ),
            Some("169.254.42.7".to_string())
        );

        // 3. `detect_primary_lan_ipv4_with_protector` invokes `protect_udp` with `Some(probe_addr)`
        //    BEFORE `connect()`, and refuses to bypass a failing protector.
        struct RejectingProtector {
            udp_calls: AtomicUsize,
            hints: parking_lot::Mutex<Vec<Option<SocketAddr>>>,
        }
        impl crate::platform::socket_protect::SocketProtector for RejectingProtector {
            fn protect_tcp(
                &self,
                _sock: &socket2::Socket,
                _remote: SocketAddr,
            ) -> std::io::Result<()> {
                Ok(())
            }
            fn protect_udp(
                &self,
                _sock: &socket2::Socket,
                remote_hint: Option<SocketAddr>,
            ) -> std::io::Result<()> {
                self.udp_calls.fetch_add(1, Ordering::SeqCst);
                self.hints.lock().push(remote_hint);
                Err(std::io::Error::new(
                    std::io::ErrorKind::NetworkUnreachable,
                    "blocked in test",
                ))
            }
            fn description(&self) -> String {
                "test-reject".to_string()
            }
        }

        let reject_prot = RejectingProtector {
            udp_calls: AtomicUsize::new(0),
            hints: parking_lot::Mutex::new(Vec::new()),
        };
        assert_eq!(
            detect_primary_lan_ipv4_with_protector(fake_net, &reject_prot),
            None
        );
        assert_eq!(reject_prot.udp_calls.load(Ordering::SeqCst), 2);
        let hints = reject_prot.hints.lock().clone();
        assert_eq!(
            hints,
            vec![
                Some("223.5.5.5:53".parse().unwrap()),
                Some("198.51.100.1:80".parse().unwrap()),
            ]
        );

        // With an allowing counting protector, `protect_udp` is called at least once and any
        // returned IP never lies inside `fake_ip_net`.
        let counting = crate::platform::socket_protect::CallbackSocketProtector::counting(
            "test-lan-probe",
            false,
        );
        let detected = detect_primary_lan_ipv4_with_protector(fake_net, &counting);
        assert!(counting.udp_count() >= 1);
        if let Some(ip_str) = detected {
            let v4: std::net::Ipv4Addr = ip_str.parse().unwrap();
            assert!(!fake_net.contains(&v4));
            assert!(!v4.is_loopback());
            assert!(!v4.is_unspecified());
        }
    }

    #[test]
    fn log_level_filter_and_snapshot_overlap_dedup_preserve_order_without_duplicates() {
        let mk = |ts: u64, level: &str, payload: &str| crate::tracker::LogEntry {
            timestamp_ms: ts,
            level: level.to_string(),
            payload: payload.to_string(),
        };

        let dbg = mk(10, "debug", "d");
        let inf = mk(11, "info", "i");
        let wrn = mk(12, "warn", "w");
        let err = mk(13, "error", "e");

        assert!(log_entry_matches_level(&err, Some("error")));
        assert!(!log_entry_matches_level(&wrn, Some("error")));
        assert!(!log_entry_matches_level(&inf, Some("error")));

        assert!(log_entry_matches_level(&err, Some("warn")));
        assert!(log_entry_matches_level(&wrn, Some("warn")));
        assert!(!log_entry_matches_level(&inf, Some("warn")));
        assert!(!log_entry_matches_level(&dbg, Some("warn")));

        assert!(log_entry_matches_level(&inf, Some("info")));
        assert!(log_entry_matches_level(&wrn, Some("info")));
        assert!(!log_entry_matches_level(&dbg, Some("info")));

        assert!(log_entry_matches_level(&dbg, Some("debug")));
        assert!(log_entry_matches_level(&dbg, None));
        assert!(!log_entry_matches_level(&err, Some("silent")));

        let mut dedup = LogSnapshotDedup::default();
        let snap1 = mk(100, "warn", "overlap-1");
        let snap2 = mk(101, "error", "overlap-2");
        dedup.record_sent(&snap1);
        dedup.record_sent(&snap2);

        // Out-of-order overlap entries from broadcast channel are each suppressed exactly once.
        assert!(dedup.consume_if_duplicate(&snap2));
        assert!(dedup.consume_if_duplicate(&snap1));
        // A genuine subsequent repeat after consuming the snapshot occurrence is NOT suppressed.
        assert!(!dedup.consume_if_duplicate(&snap2));
        // Entries with newer timestamps pass straight through.
        assert!(!dedup.consume_if_duplicate(&mk(102, "warn", "live-new")));
    }

    #[tokio::test]
    async fn post_dns_flush_bumps_router_epoch_and_removes_persisted_fake_ip_cache() {
        let tmp_dir =
            std::env::temp_dir().join(format!("rc-api-dns-flush-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&tmp_dir).unwrap();

        let cfg = ClashConfig::from_yaml_str(
            r#"
mixed-port: 0
external-controller: "127.0.0.1:0"
mode: rule
dns:
  enable: false
  enhanced-mode: fake-ip
proxies: []
proxy-groups:
  - name: PROXY
    type: select
    proxies: [DIRECT]
rules:
  - MATCH,DIRECT
"#,
        )
        .unwrap();
        let engine = ProxyEngine::start_with_state_dir(cfg, tmp_dir.clone())
            .await
            .unwrap();
        let cache_file = tmp_dir.join("fake_ip_cache.json");
        std::fs::write(&cache_file, b"{}").unwrap();
        assert!(cache_file.exists());

        let (stop_tx, stop_rx) = watch::channel(false);
        let (api_addr, api_task) = spawn_api_server("127.0.0.1:0", Arc::clone(&engine), stop_rx)
            .await
            .unwrap();

        let epoch_before = engine.router().epoch();
        let mut s = TcpStream::connect(api_addr).await.unwrap();
        let req = format!(
            "POST /dns/flush HTTP/1.1\r\nHost: {api_addr}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
        s.write_all(req.as_bytes()).await.unwrap();
        let mut raw = Vec::new();
        s.read_to_end(&mut raw).await.unwrap();
        let text = String::from_utf8_lossy(&raw);
        assert!(
            text.starts_with("HTTP/1.1 200"),
            "unexpected response: {text}"
        );
        assert!(text.contains(r#""flushed":true"#));

        let epoch_after = engine.router().epoch();
        assert!(
            epoch_after > epoch_before,
            "POST /dns/flush must bump router epoch (before={epoch_before}, after={epoch_after})"
        );
        assert!(
            !cache_file.exists(),
            "POST /dns/flush must delete persisted fake_ip_cache.json"
        );

        let _ = stop_tx.send(true);
        let _ = api_task.await;
        engine.shutdown();
        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn scrub_sensitive_substrings_preserves_inline_delimiters_and_redacts_secrets_and_all_schemes()
    {
        let known_secrets = vec!["my-controller-secret-99".to_string(), "ab".to_string()];

        // Inline YAML sequence `[https://223.5.5.5/dns-query]` preserves closing `]`
        let yaml_inline = "nameserver: [https://223.5.5.5/dns-query, 1.1.1.1:53]";
        let scrubbed_yaml = scrub_sensitive_substrings(yaml_inline, &known_secrets);
        assert_eq!(
            scrubbed_yaml,
            "nameserver: [https://***REDACTED***, 1.1.1.1:53]"
        );

        // JSON-escaped authenticated URL preserves `\"`
        let json_escaped = r#"err: \"https://user:pass@host/path?k=v\""#;
        let scrubbed_json = scrub_sensitive_substrings(json_escaped, &known_secrets);
        assert_eq!(scrubbed_json, r#"err: \"https://host/***REDACTED***\""#);
        assert!(!scrubbed_json.contains("user") && !scrubbed_json.contains("pass"));

        // Known secrets (>= 4 chars) plus all URI schemes (including vmess/hy2/tuic/uppercase HTTPS)
        let mixed = "secret=my-controller-secret-99 \
            [vmess://SECRET_VMESS@vm.example:443] \
            {hy2://HY2PASS@hy2.example:443?obfs-password=OBFS} \
            (tuic://12345678-1234-4321-abcd-998877665544:TUICPASS@tuic.example:8443) \
            HTTPS://203.0.113.9/sub?token=UPTOK \
            HTTPS://alice:s3cr3t@sub.example.com/feed?token=UPTOK2;";
        let scrubbed_mixed = scrub_sensitive_substrings(mixed, &known_secrets);

        for leaked in [
            "my-controller-secret-99",
            "SECRET_VMESS",
            "HY2PASS",
            "OBFS",
            "12345678-1234-4321-abcd-998877665544",
            "TUICPASS",
            "203.0.113.9",
            "UPTOK",
            "alice",
            "s3cr3t",
            "UPTOK2",
        ] {
            assert!(
                !scrubbed_mixed.contains(leaked),
                "secret '{leaked}' leaked in scrubbed output: {scrubbed_mixed}"
            );
        }
        assert!(scrubbed_mixed.contains("[vmess://***REDACTED***]"));
        assert!(scrubbed_mixed.contains("{hy2://***REDACTED***}"));
        assert!(scrubbed_mixed.contains("(tuic://***REDACTED***)"));
        assert!(scrubbed_mixed.contains("https://***REDACTED***"));
        assert!(scrubbed_mixed.contains("https://sub.example.com/***REDACTED***;"));
        // Idempotent
        assert_eq!(
            scrub_sensitive_substrings(&scrubbed_mixed, &known_secrets),
            scrubbed_mixed
        );
    }

    #[test]
    fn scrub_sensitive_substrings_resists_secret_prefix_shadowing_and_redaction_self_corruption() {
        let known_secrets: Vec<String> = [
            "pass",
            "https",
            "REDACTED",
            "_URL",
            "super_secret_token_999",
            "super_secret",
        ]
        .into_iter()
        .map(String::from)
        .collect();

        // 1. `pass` must not destroy `password=` before structural KV redaction runs
        let kv_out =
            scrub_sensitive_substrings("password=SUPER_SECRET_PASSWORD_999", &known_secrets);
        assert!(
            !kv_out.contains("SUPER_SECRET_PASSWORD_999"),
            "password value leaked: {kv_out}"
        );
        assert!(
            !kv_out.contains("******REDACTED******"),
            "placeholder self-corruption detected: {kv_out}"
        );
        assert_eq!(scrub_sensitive_substrings(&kv_out, &known_secrets), kv_out);

        // 2. `https` must not destroy `https://` before structural URL/IP redaction runs
        let url_out = scrub_sensitive_substrings(
            "url=https://alice:ALICE_REAL_PASS@203.0.113.55/secret?token=TOK999",
            &known_secrets,
        );
        for leaked in ["alice", "ALICE_REAL_PASS", "203.0.113.55", "TOK999"] {
            assert!(
                !url_out.contains(leaked),
                "URL secret '{leaked}' leaked: {url_out}"
            );
        }
        assert!(!url_out.contains("******REDACTED******"));
        assert_eq!(
            scrub_sensitive_substrings(&url_out, &known_secrets),
            url_out
        );

        // 3. Inline DoH IP URLs still scrub non-loopback IP even when `https` is a known secret
        let doh_out =
            scrub_sensitive_substrings("[https://223.5.5.5/dns-query, 1.1.1.1:53]", &known_secrets);
        assert!(
            !doh_out.contains("223.5.5.5") && !doh_out.contains("dns-query"),
            "DoH IP/path leaked: {doh_out}"
        );
        assert!(doh_out.contains("1.1.1.1:53"));
        assert!(!doh_out.contains("******REDACTED******"));
        assert_eq!(
            scrub_sensitive_substrings(&doh_out, &known_secrets),
            doh_out
        );

        // 4. Standalone secret (and longer secret shadowed by shorter prefix) redacts completely
        let standalone_out =
            scrub_sensitive_substrings("token_ref=super_secret_token_999", &known_secrets);
        assert_eq!(standalone_out, "token_ref=***REDACTED***");
        assert!(!standalone_out.contains("super_secret") && !standalone_out.contains("_token_999"));
        assert_eq!(
            scrub_sensitive_substrings(&standalone_out, &known_secrets),
            standalone_out
        );

        // 5. `***REDACTED_URL***` must not be corrupted by `REDACTED` or `_URL` in known_secrets
        let bad_url_out = scrub_sensitive_substrings(
            r#"failed https://user:p\ass@edge.example/sub"#,
            &known_secrets,
        );
        assert_eq!(bad_url_out, "failed ***REDACTED_URL***");
        assert!(!bad_url_out.contains("******REDACTED******"));
        assert_eq!(
            scrub_sensitive_substrings(&bad_url_out, &known_secrets),
            bad_url_out
        );
    }

    #[test]
    fn scrub_sensitive_substrings_scrubs_compound_secrets_and_guarantees_strict_idempotency() {
        // 1. Compound configured secrets (Challenger 1 live Cookie / X-Auth / Trojan UUID-tail
        //    vectors plus contextual prefix and partial-UUID suffix secrets)
        let compound_secrets: Vec<String> = [
            "sid=aaa111;session=SUPER_SECRET_COOKIE_888",
            "token=part1&extra=SUPER_SECRET_EXTRA_777",
            "token",
            "pre-12345678-1234-4321-abcd-998877665544-REAL_UUID_TAIL",
            "part2&tail=CONTEXTUAL_SECRET_666",
            "998877665544-PARTIAL_UUID_TAIL",
        ]
        .into_iter()
        .map(String::from)
        .collect();

        let compound_cases: [(&str, &[&str]); 5] = [
            (
                "upstream rejected Cookie: sid=aaa111;session=SUPER_SECRET_COOKIE_888",
                &["aaa111", "SUPER_SECRET_COOKIE_888", "session="],
            ),
            (
                "upstream rejected X-Auth: token=part1&extra=SUPER_SECRET_EXTRA_777",
                &["part1", "SUPER_SECRET_EXTRA_777", "extra="],
            ),
            (
                "trojan err: pre-12345678-1234-4321-abcd-998877665544-REAL_UUID_TAIL",
                &[
                    "12345678-1234-4321-abcd-998877665544",
                    "REAL_UUID_TAIL",
                    "pre-",
                ],
            ),
            (
                "upstream rejected X-Auth: token=part2&tail=CONTEXTUAL_SECRET_666",
                &["part2", "CONTEXTUAL_SECRET_666"],
            ),
            (
                "trojan err: 12345678-1234-4321-abcd-998877665544-PARTIAL_UUID_TAIL",
                &["12345678-1234-4321-abcd-998877665544", "PARTIAL_UUID_TAIL"],
            ),
        ];

        for (input, forbidden) in compound_cases {
            let p1 = scrub_sensitive_substrings(input, &compound_secrets);
            let p2 = scrub_sensitive_substrings(&p1, &compound_secrets);
            let p3 = scrub_sensitive_substrings(&p2, &compound_secrets);
            for secret in forbidden {
                assert!(
                    !p1.contains(secret),
                    "compound secret fragment '{secret}' leaked in '{p1}' (from '{input}')"
                );
            }
            assert_eq!(p2, p1, "f(f(x)) != f(x) for '{input}'");
            assert_eq!(p3, p1, "f(f(f(x))) != f(x) for '{input}'");
        }

        // 2. Zero prefix shadowing across URL, Authorization Bearer, and KV token
        let prefix_secrets: Vec<String> = ["pass", "https", "token", "bearer"]
            .into_iter()
            .map(String::from)
            .collect();
        let prefix_cases: [(&str, &[&str]); 3] = [
            (
                "https://user:Secret99@host/path",
                &["user", "Secret99", "/path"],
            ),
            ("Authorization: Bearer SuperSecret99", &["SuperSecret99"]),
            ("url?token=SuperSecret99", &["SuperSecret99"]),
        ];
        for (input, forbidden) in prefix_cases {
            let p1 = scrub_sensitive_substrings(input, &prefix_secrets);
            let p2 = scrub_sensitive_substrings(&p1, &prefix_secrets);
            for secret in forbidden {
                assert!(
                    !p1.contains(secret),
                    "prefix-shadowed secret '{secret}' leaked in '{p1}' (from '{input}')"
                );
            }
            assert_eq!(p2, p1, "f(f(x)) != f(x) for '{input}'");
        }

        // 3. Zero placeholder corruption & strict idempotency with `"****"` and placeholder fragments
        let star_secrets: Vec<String> = [
            "****",
            "REDACTED",
            "_URL",
            "***R",
            "***REDACTED***",
            "***REDACTED_URL***",
            "secret_long_123",
            "foo_",
            "foo_https",
            "https://sub.example.com",
            "sub.",
            "aaaa",
        ]
        .into_iter()
        .map(String::from)
        .collect();

        let idempotent_cases = [
            r"*https://user:p\ass@edge.example/sub",
            r"**https://user:p\ass@edge.example/sub",
            r"***https://user:p\ass@edge.example/sub",
            r"****https://user:p\ass@edge.example/sub",
            r"*****https://user:p\ass@edge.example/sub",
            "*secret_long_123*",
            "*secret_long_123***",
            "***REDACTED***",
            "***REDACTED_URL***",
            "foo_token=BarSecret99",
            "foo_HTTPS://user:pass@host.example/secret",
            "https://user:pass@sub.example.com/secret",
            "aaaa12345678-1234-4321-abcd-998877665544",
        ];

        for input in idempotent_cases {
            let p1 = scrub_sensitive_substrings(input, &star_secrets);
            let p2 = scrub_sensitive_substrings(&p1, &star_secrets);
            let p3 = scrub_sensitive_substrings(&p2, &star_secrets);
            assert!(
                !p1.contains("REDACTED***REDACTED_URL")
                    && !p1.contains("REDACTED***REDACTED***REDACTED"),
                "corrupted placeholder detected in '{p1}' (from '{input}')"
            );
            assert_eq!(
                p2, p1,
                "f(f(x)) != f(x) for '{input}': p1='{p1}', p2='{p2}'"
            );
            assert_eq!(p3, p1, "f(f(f(x))) != f(x) for '{input}'");
        }

        // Verify intact placeholder retention on star-adjacent inputs
        assert_eq!(
            scrub_sensitive_substrings(r"*https://user:p\ass@edge.example/sub", &star_secrets),
            "****REDACTED_URL***"
        );
        assert_eq!(
            scrub_sensitive_substrings(r"**https://user:p\ass@edge.example/sub", &star_secrets),
            "*****REDACTED_URL***"
        );
        assert_eq!(
            scrub_sensitive_substrings(r"****https://user:p\ass@edge.example/sub", &star_secrets),
            "***REDACTED******REDACTED_URL***"
        );
        assert_eq!(
            scrub_sensitive_substrings("*secret_long_123*", &star_secrets),
            "****REDACTED****"
        );
        assert_eq!(
            scrub_sensitive_substrings("***REDACTED***", &star_secrets),
            "***REDACTED***"
        );
        assert_eq!(
            scrub_sensitive_substrings("***REDACTED_URL***", &star_secrets),
            "***REDACTED_URL***"
        );
        assert!(
            !scrub_sensitive_substrings("foo_token=BarSecret99", &star_secrets)
                .contains("BarSecret99")
        );
        assert!(
            !scrub_sensitive_substrings("aaaa12345678-1234-4321-abcd-998877665544", &star_secrets)
                .contains("12345678")
        );

        // Multi-byte UTF-8 safety & idempotency
        let utf8_secrets = vec![
            "密码🔥".to_string(),
            "中文密码123".to_string(),
            "秘密值".to_string(),
        ];
        let utf8_in =
            "错误：https://用户:密码🔥@doh.example/dns-query 令牌=秘密值 token=中文密码123";
        let utf8_p1 = scrub_sensitive_substrings(utf8_in, &utf8_secrets);
        let utf8_p2 = scrub_sensitive_substrings(&utf8_p1, &utf8_secrets);
        assert!(
            !utf8_p1.contains("密码🔥")
                && !utf8_p1.contains("秘密值")
                && !utf8_p1.contains("中文密码123")
        );
        assert_eq!(utf8_p2, utf8_p1);

        // 4. Linear O(N) performance on long self-overlapping secret & backslash inputs
        let long_a = "a".repeat(50_000);
        let long_bs = format!("https://example.com/{}x", "\\".repeat(50_000));
        let started = std::time::Instant::now();
        assert_eq!(
            scrub_sensitive_substrings(&long_a, &star_secrets),
            "***REDACTED***"
        );
        assert_eq!(
            scrub_sensitive_substrings(&long_bs, &star_secrets),
            "https://example.com/***REDACTED***"
        );
        assert!(
            started.elapsed() < std::time::Duration::from_secs(2),
            "scrub_sensitive_substrings must scale linearly in O(N)"
        );
    }

    #[test]
    fn scrub_sensitive_substrings_fixes_uuid_host_case_second_order_prefix_shadowing_and_placeholder_secrets()
     {
        let empty_secrets: Vec<String> = Vec::new();
        let normal_secrets = vec!["MyNormalTrojanPassword99".to_string()];
        let shadowing_secrets: Vec<String> = ["foo_", "token", "pass", "https", "word", "bar_"]
            .into_iter()
            .map(String::from)
            .collect();

        // 1. UUID in URL hostname keeps canonical uppercase `***REDACTED***` on Pass 1..3
        //    under BOTH empty `known_secrets` AND normal configured secrets.
        for secrets in [&empty_secrets, &normal_secrets] {
            for (input, expected) in [
                (
                    "[D2] dial https://12345678-1234-4321-abcd-998877665544.example/secret-path",
                    "[D2] dial https://***REDACTED***.example/***REDACTED***",
                ),
                (
                    "[D2] dial https://12345678-1234-4321-abcd-998877665544/a",
                    "[D2] dial https://***REDACTED***/***REDACTED***",
                ),
            ] {
                let p1 = scrub_sensitive_substrings(input, secrets);
                let p2 = scrub_sensitive_substrings(&p1, secrets);
                let p3 = scrub_sensitive_substrings(&p2, secrets);
                assert_eq!(p1, expected, "unexpected p1 for '{input}'");
                assert!(
                    !p1.contains("***redacted***"),
                    "corrupted lowercase placeholder in '{p1}'"
                );
                assert_eq!(p2, p1, "f(f(x)) != f(x) for '{input}'");
                assert_eq!(p3, p1, "f(f(f(x))) != f(x) for '{input}'");
            }
        }

        // 2. `<uuid>token=...` under BOTH empty `known_secrets` AND shadowing secrets
        for secrets in [&empty_secrets, &shadowing_secrets] {
            let input = "[D2] 12345678-1234-4321-abcd-998877665544token=EmptyCfgSecret999";
            let p1 = scrub_sensitive_substrings(input, secrets);
            let p2 = scrub_sensitive_substrings(&p1, secrets);
            let p3 = scrub_sensitive_substrings(&p2, secrets);
            assert!(
                !p1.contains("EmptyCfgSecret999") && !p1.contains("12345678"),
                "leaked UUID or token in '{p1}'"
            );
            assert_eq!(p2, p1, "f(f(x)) != f(x) for '{input}'");
            assert_eq!(p3, p1, "f(f(f(x))) != f(x) for '{input}'");
        }

        // 3. Second-order prefix shadowing (`foo_token=...`, `foo_password=...`, `foo_https://...`,
        //    mid-keyword secret `"word"`, value-prefix secret `"bar_"`, UUID-tail value)
        let second_order_cases: [(&str, &[&str]); 7] = [
            (
                "[D3-1] 12345678-1234-4321-abcd-998877665544token=UuidGluedTokSecret99",
                &["12345678", "UuidGluedTokSecret99"],
            ),
            (
                "[D3-2] 12345678-1234-4321-abcd-998877665544password=UuidGluedPassSecret99",
                &["12345678", "UuidGluedPassSecret99"],
            ),
            (
                "[D3-3] foo_token=FooGluedTokSecret99",
                &["foo_", "token", "FooGluedTokSecret99"],
            ),
            (
                "[D3-4] foo_password=FooGluedPassSecret99",
                &["foo_", "pass", "word", "FooGluedPassSecret99"],
            ),
            (
                "[D3-5] foo_https://u:Secret99@h/x",
                &["foo_", "https", "Secret99"],
            ),
            (
                "[D3-6] foo_token=bar_TailSecret88",
                &["foo_", "token", "bar_", "TailSecret88"],
            ),
            (
                "[D3-7] foo_token=12345678-1234-4321-abcd-998877665544-GluedUuidTail77",
                &["foo_", "token", "12345678", "GluedUuidTail77"],
            ),
        ];
        for (input, forbidden) in second_order_cases {
            let p1 = scrub_sensitive_substrings(input, &shadowing_secrets);
            let p2 = scrub_sensitive_substrings(&p1, &shadowing_secrets);
            let p3 = scrub_sensitive_substrings(&p2, &shadowing_secrets);
            for secret in forbidden {
                assert!(
                    !p1.contains(secret),
                    "second-order shadowed secret '{secret}' leaked in '{p1}' (from '{input}')"
                );
            }
            assert_eq!(p2, p1, "f(f(x)) != f(x) for '{input}'");
            assert_eq!(p3, p1, "f(f(f(x))) != f(x) for '{input}'");
        }

        // Preserve unrelated clean URL host readability alongside second-order unblocking
        let mixed = "dial https://sub.example.com/a foo_token=MixedSecret77";
        let mixed_secrets = vec!["foo_".to_string(), "token".to_string()];
        let mp1 = scrub_sensitive_substrings(mixed, &mixed_secrets);
        assert!(
            mp1.starts_with("dial https://sub.example.com/***REDACTED*** "),
            "unrelated URL host readability should be preserved: {mp1}"
        );
        assert!(!mp1.contains("MixedSecret77"));
        assert_eq!(scrub_sensitive_substrings(&mp1, &mixed_secrets), mp1);

        // 4. Placeholder-containing configured secrets scrub completely while keeping
        //    `"****"` / `"REDACTED"` / `"_URL"` / `"***R"` placeholder protection intact.
        let ph_secrets: Vec<String> = [
            "pre-***REDACTED***-INNER_PH_SECRET99",
            "***REDACTED_URL***-SUFFIX_SECRET88",
            "****",
            "REDACTED",
            "_URL",
            "***R",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        for (input, expected, forbidden) in [
            (
                "auth err: pre-***REDACTED***-INNER_PH_SECRET99",
                "auth err: ***REDACTED***",
                "INNER_PH_SECRET99",
            ),
            (
                "url err: ***REDACTED_URL***-SUFFIX_SECRET88",
                "url err: ***REDACTED***",
                "SUFFIX_SECRET88",
            ),
        ] {
            let p1 = scrub_sensitive_substrings(input, &ph_secrets);
            let p2 = scrub_sensitive_substrings(&p1, &ph_secrets);
            let p3 = scrub_sensitive_substrings(&p2, &ph_secrets);
            assert_eq!(p1, expected);
            assert!(!p1.contains(forbidden));
            assert_eq!(p2, p1);
            assert_eq!(p3, p1);
        }
        assert_eq!(
            scrub_sensitive_substrings(r"*https://user:p\ass@edge.example/sub", &ph_secrets),
            "****REDACTED_URL***"
        );
    }

    #[test]
    fn scrub_sensitive_substrings_unblocks_nested_kv_trailing_hex_uuid_and_chained_placeholder_secrets()
     {
        let secrets: Vec<String> = [
            "access_",
            "token",
            "obfs_",
            "obfs",
            "pass",
            "api_",
            "public_",
            "private_",
            "key=",
            "12345678",
            "aaaa",
            "pre-***REDACTED***-x",
            "前缀-***REDACTED***-中",
        ]
        .into_iter()
        .map(String::from)
        .collect();

        let cases: [(&str, &[&str]); 9] = [
            (
                "xaccess_token=NestedTokSecret99",
                &["access_", "token", "NestedTokSecret99"],
            ),
            (
                "xobfs_password=NestedPassSecret99",
                &["obfs_", "pass", "NestedPassSecret99"],
            ),
            (
                "xobfspassword=NestedObfsSecret99",
                &["obfs", "pass", "NestedObfsSecret99"],
            ),
            ("xapi_key=NestedKeySecret99", &["api_", "NestedKeySecret99"]),
            (
                "xpublic_key=NestedPubSecret99",
                &["public_", "NestedPubSecret99"],
            ),
            (
                "xprivate_key=NestedPrivSecret99",
                &["private_", "NestedPrivSecret99"],
            ),
            (
                "12345678-1234-4321-abcd-998877665544aaaa",
                &["12345678", "998877665544", "aaaa"],
            ),
            (
                "pre-12345678-1234-4321-abcd-998877665544-xtoken=ChainedPhSecret99",
                &["12345678", "998877665544", "token", "ChainedPhSecret99"],
            ),
            (
                "前缀-12345678-1234-4321-abcd-998877665544-中token=ChainedUtf8Secret99",
                &["12345678", "998877665544", "token", "ChainedUtf8Secret99"],
            ),
        ];

        for (input, forbidden) in cases {
            let p1 = scrub_sensitive_substrings(input, &secrets);
            let p2 = scrub_sensitive_substrings(&p1, &secrets);
            let p3 = scrub_sensitive_substrings(&p2, &secrets);
            for secret in forbidden {
                assert!(
                    !p1.contains(secret),
                    "leaked '{secret}' in '{p1}' (from '{input}')"
                );
            }
            assert!(
                !p1.contains("***redacted***"),
                "corrupted lowercase placeholder in '{p1}'"
            );
            assert_eq!(p2, p1, "f(f(x)) != f(x) for '{input}'");
            assert_eq!(p3, p1, "f(f(f(x))) != f(x) for '{input}'");
        }
    }

    #[test]
    fn scrub_sensitive_substrings_preserves_unblocked_keywords_before_uuids_and_urls() {
        let cases: [(&str, &[&str], &[&str]); 12] = [
            (
                "xapi_key=12345678-1234-4321-abcd-998877665544-TailSecret99",
                &["api_", "key="],
                &["api_", "key=", "12345678", "TailSecret99"],
            ),
            (
                "foo_token=22222222-3333-4444-5555-666666666666-TokTailSec88",
                &["foo_", "token="],
                &["foo_", "token=", "22222222", "TokTailSec88"],
            ),
            (
                "xaccess_token=33333333-4444-5555-6666-777777777777-AccTailSec77",
                &["xaccess_token="],
                &["access_token", "33333333", "AccTailSec77"],
            ),
            (
                "xapi_key=https://SecretHost99.example",
                &["api_", "key="],
                &["api_", "key=", "SecretHost99", "secrethost99", "https://"],
            ),
            (
                "xapi_key=http://LeakHost99.example/",
                &["api_", "key="],
                &["api_", "key=", "LeakHost99", "leakhost99", "http://"],
            ),
            (
                r#"xapi_key="https://QuotedHost99.example/p""#,
                &["api_", "key="],
                &["api_", "key=", "QuotedHost99", "quotedhost99", "https://"],
            ),
            (
                "xtoken=12345678-1234-4321-abcd-998877665544-TailSecret99",
                &["xtoken=1234"],
                &["token", "12345678", "TailSecret99"],
            ),
            (
                "xtoken=aaaa12345678-1234-4321-abcd-998877665544-TailSecret99",
                &["xtoken=aaaa"],
                &["token", "aaaa", "12345678", "TailSecret99"],
            ),
            (
                "xAuthorization: Bearer 12345678-1234-4321-abcd-998877665544-TailSecret99",
                &["xAuthorization: Bearer 1234"],
                &["Authorization", "12345678", "TailSecret99"],
            ),
            (
                "pre-12345678-1234-4321-abcd-998877665544-xapi_key=12345678-1234-4321-abcd-998877665544-TailSecret99",
                &["pre-***REDACTED***-x", "api_", "key="],
                &["api_", "key=", "12345678", "TailSecret99"],
            ),
            (
                "xtoken=Sec1 xpassword=Sec2",
                &["xtoken=Sec1 x", "pass"],
                &["Sec1", "Sec2", "pass"],
            ),
            (
                "xtoken=foo&xpassword=AmpSecret99",
                &["xtoken=foo&x", "pass"],
                &["AmpSecret99", "pass"],
            ),
        ];

        for (input, raw_secrets, forbidden) in cases {
            let secrets: Vec<String> = raw_secrets.iter().map(|s| (*s).to_string()).collect();
            let p1 = scrub_sensitive_substrings(input, &secrets);
            let p2 = scrub_sensitive_substrings(&p1, &secrets);
            let p3 = scrub_sensitive_substrings(&p2, &secrets);
            for secret in forbidden {
                assert!(
                    !p1.contains(secret),
                    "leaked '{secret}' in '{p1}' (input='{input}', secrets={raw_secrets:?})"
                );
            }
            assert!(
                !p1.contains("***redacted***"),
                "corrupted lowercase placeholder in '{p1}'"
            );
            assert_eq!(p2, p1, "f(f(x)) != f(x) for '{input}'");
            assert_eq!(p3, p1, "f(f(f(x))) != f(x) for '{input}'");
        }

        // Benign TSV bare-host rows remain strictly uncorrupted through the 3-pass export scrubber
        let normal_secrets = vec!["MyNormalTrojanPassword99".to_string()];
        for benign in [
            "[LIVE] https://a.com\tcol2",
            "[LIVE] http://example.com\t200\tOK",
            "[LIVE] ws://a.com\tcol2",
            "[LIVE] wss://a.com\tcol2",
        ] {
            let p1 = scrub_sensitive_substrings(benign, &normal_secrets);
            let p2 = scrub_sensitive_substrings(&p1, &normal_secrets);
            let p3 = scrub_sensitive_substrings(&p2, &normal_secrets);
            assert_eq!(p1, benign, "benign TSV row must remain intact: {benign:?}");
            assert_eq!(p2, p1);
            assert_eq!(p3, p1);
        }
    }

    #[test]
    fn scrub_sensitive_substrings_decouples_word_boundary_and_uuid_buffers_with_monotone_value_tracking()
     {
        // Covers ALL Wave 6 Reviewer 2 (N_A1..N_A8), Challenger 1 (D2 #1..#9), and
        // Challenger 2 (D1 #1..#7) live-reproduced credential-leak vectors.
        let cases: [(&str, &[&str], &[&str]); 25] = [
            // R2 N_A1..N_A4 (cross-secret & single-secret UUID boundary inside KV / Authorization)
            (
                "DOMAIN-KEYWORD,N_A1 xtoken=aaaa12345678-1234-4321-abcd-998877665544-NewLeadHexTail99,DIRECT",
                &["xtoken=", "aaaa"],
                &["aaaa", "12345678", "NewLeadHexTail99"],
            ),
            (
                "DOMAIN-KEYWORD,N_A2 xaccess_token=12345678-1234-4321-abcd-998877665544aaaa-NewTrailHexTail99,DIRECT",
                &["xaccess_token=", "aaaa"],
                &["aaaa", "12345678", "NewTrailHexTail99"],
            ),
            (
                "DOMAIN-KEYWORD,N_A3 xtoken=12345678-1234-4321-abcd-998877665544aaaa-NewSingleTrailTail99,DIRECT",
                &["xtoken=12345678-1234-4321-abcd-998877665544aaaa"],
                &["12345678", "aaaa", "NewSingleTrailTail99"],
            ),
            (
                "DOMAIN-KEYWORD,N_A4 xAuthorization: Bearer aaaa12345678-1234-4321-abcd-998877665544-NewAuthHexTail99,DIRECT",
                &["xAuthorization: Bearer ", "aaaa"],
                &["aaaa", "12345678", "NewAuthHexTail99"],
            ),
            // R2 N_A5 (same-span upgrade with `&next=1` query tail & path variant)
            (
                "DOMAIN-KEYWORD,N_A5 xapi_key=https://NewAmpHost99.example&next=1,DIRECT",
                &["api_", "key="],
                &["api_", "key=", "NewAmpHost99", "newamphost99"],
            ),
            (
                "DOMAIN-KEYWORD,N_A5_path xapi_key=https://NewAmpHost99.example/p&next=1,DIRECT",
                &["api_", "key="],
                &["api_", "key=", "NewAmpHost99", "newamphost99"],
            ),
            // R2 N_A7 & N_A8 (`#` and quote KV separators)
            (
                "DOMAIN-KEYWORD,N_A7 xtoken=Sec1#xpassword=NewHashPassSec99,DIRECT",
                &["xtoken=Sec1#x", "pass"],
                &["Sec1", "NewHashPassSec99"],
            ),
            (
                r#"DOMAIN-KEYWORD,N_A8 xtoken="Sec1"xpassword=NewQuotePassSec99,DIRECT"#,
                &[r#"xtoken="Sec1"x"#, "pass"],
                &["Sec1", "NewQuotePassSec99"],
            ),
            // C1 D2 #2..#9 (split-secret UUID lead/trail, Uuid -> WordBoundary, quoted/# chained)
            (
                "xtoken=Zaaaa12345678-1234-4321-abcd-998877665544-TailSecret99",
                &["xtoken=", "aaaa"],
                &["aaaa", "12345678", "TailSecret99"],
            ),
            (
                "xtoken=12345678-1234-4321-abcd-998877665544aaaa-TailSecret99",
                &["xtoken=", "aaaa"],
                &["aaaa", "12345678", "TailSecret99"],
            ),
            (
                "xAuthorization: Bearer aaaa12345678-1234-4321-abcd-998877665544-TailSecret99",
                &["xAuthorization:", "aaaa"],
                &["aaaa", "12345678", "TailSecret99"],
            ),
            (
                "xAuthorization: Bearer 12345678-1234-4321-abcd-998877665544aaaa-TailSecret99",
                &["xAuthorization:", "aaaa"],
                &["aaaa", "12345678", "TailSecret99"],
            ),
            (
                "aaaa11111111-2222-3333-4444-555555555555api_key=TailSecret99",
                &["aaaa11111111-2222-3333-4444-555555555555api_key="],
                &["11111111", "api_key", "TailSecret99"],
            ),
            (
                "aaaa11111111-2222-3333-4444-555555555555xtoken=TailSecret99",
                &["aaaa11111111-2222-3333-4444-555555555555xtoken="],
                &["11111111", "xtoken", "TailSecret99"],
            ),
            (
                "aaaa11111111-2222-3333-4444-555555555555auth=TailSecret99",
                &["aaaa11111111-2222-3333-4444-555555555555auth="],
                &["11111111", "auth", "TailSecret99"],
            ),
            (
                r#"xkey="secret"xtoken=TailSecret99"#,
                &[r#"xkey="secret"xtoken="#],
                &["secret", "TailSecret99"],
            ),
            (
                "xkey=val#xtoken=TailSecret99",
                &["xkey=val#xtoken="],
                &["TailSecret99"],
            ),
            // C2 D1 #1..#7 (cross-secret UUID + cross-secret inline quoted KV split + single-secret)
            (
                "DOMAIN-KEYWORD,xtoken=z_aaaa22222222-3333-4444-5555-666666666666-AdvTokLeadTail77,DIRECT",
                &["xtoken=", "aaaa"],
                &["aaaa", "22222222", "AdvTokLeadTail77"],
            ),
            (
                "DOMAIN-KEYWORD,xtoken=22222222-3333-4444-5555-666666666666bbbb-AdvTokTrailTail66,DIRECT",
                &["xtoken=", "bbbb"],
                &["bbbb", "22222222", "AdvTokTrailTail66"],
            ),
            (
                "DOMAIN-KEYWORD,xapi_key=z_aaaa11111111-2222-3333-4444-555555555555-AdvApiLeadTail99,DIRECT",
                &["api_", "key=", "aaaa"],
                &["api_", "key=", "aaaa", "11111111", "AdvApiLeadTail99"],
            ),
            (
                "DOMAIN-KEYWORD,xapi_key=11111111-2222-3333-4444-555555555555bbbb-AdvApiTrailTail88,DIRECT",
                &["api_", "key=", "bbbb"],
                &["api_", "key=", "bbbb", "11111111", "AdvApiTrailTail88"],
            ),
            (
                r#"DOMAIN-KEYWORD,xtoken=foo_xkey="a"-AdvQuotedSplitTail55,DIRECT"#,
                &["xtoken=", "foo_x"],
                &["xtoken=", "foo_x", "AdvQuotedSplitTail55"],
            ),
            (
                r#"DOMAIN-KEYWORD,xtoken=foo_xkey="a"-AdvQuotedSplitTail55,DIRECT"#,
                &["xtoken=", "foo_x", "key="],
                &["xtoken=", "foo_x", "key=", "AdvQuotedSplitTail55"],
            ),
            (
                "DOMAIN-KEYWORD,xAuthorization: Bearer z_aaaa33333333-4444-5555-6666-777777777777-AdvAuthLeadTail44,DIRECT",
                &["xAuthorization:", "aaaa"],
                &["aaaa", "33333333", "AdvAuthLeadTail44"],
            ),
            (
                r#"xtoken="q" xapi_key=Sec2 & xtoken=a&xpassword=Sec3"#,
                &["xtoken=", "xapi_key=", "xpassword="],
                &["Sec2", "Sec3"],
            ),
        ];

        for (input, raw_secrets, forbidden) in cases {
            let secrets: Vec<String> = raw_secrets.iter().map(|s| (*s).to_string()).collect();
            let p1 = scrub_sensitive_substrings(input, &secrets);
            let p2 = scrub_sensitive_substrings(&p1, &secrets);
            let p3 = scrub_sensitive_substrings(&p2, &secrets);
            for secret in forbidden {
                assert!(
                    !p1.contains(secret),
                    "leaked '{secret}' in '{p1}' (input='{input}', secrets={raw_secrets:?})"
                );
            }
            assert!(
                !p1.contains("***redacted***"),
                "corrupted lowercase placeholder in '{p1}'"
            );
            assert_eq!(p2, p1, "f(f(x)) != f(x) for '{input}'");
            assert_eq!(p3, p1, "f(f(f(x))) != f(x) for '{input}'");
        }

        // Verify N_A5 keeps `&next=1` intact while redacting `https://NewAmpHost99.example`
        let na5 = scrub_sensitive_substrings(
            "DOMAIN-KEYWORD,N_A5 xapi_key=https://NewAmpHost99.example&next=1,DIRECT",
            &["api_".to_string(), "key=".to_string()],
        );
        assert!(
            na5.contains("&next=1"),
            "non-secret query sibling lost: {na5}"
        );
        assert!(!na5.to_ascii_lowercase().contains("newamphost99"));
    }

    #[tokio::test]
    async fn diagnostics_export_scrubs_profiles_custom_rules_backup_and_preserves_benign_metadata()
    {
        let tmp_dir = std::env::temp_dir().join(format!(
            "rustclash-api-diag-profiles-scrub-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&tmp_dir).unwrap();
        let yaml = r#"mixed-port: 0
external-controller: ""
secret: "export-ctrl-secret-99"
mode: rule
proxies:
  - name: "HK (Fast) [VIP]"
    type: trojan
    server: edge.example.test
    port: 443
    password: "xtoken="
  - name: "US-Backup"
    type: trojan
    server: us.example.test
    port: 443
    password: "aaaa"
  - name: "JP-Backup"
    type: trojan
    server: jp.example.test
    port: 443
    password: "foo_x"
  - name: "SG-Backup"
    type: trojan
    server: sg.example.test
    port: 443
    password: "api_"
  - name: "TW-Backup"
    type: trojan
    server: tw.example.test
    port: 443
    password: "key="
proxy-groups:
  - name: "PROXY"
    type: select
    proxies:
      - "HK (Fast) [VIP]"
      - "US-Backup"
rules:
  - 'DOMAIN-KEYWORD,xtoken=aaaa12345678-1234-4321-abcd-998877665544-ProfileBackupLeak99,DIRECT'
  - 'DOMAIN-KEYWORD,xtoken=foo_xkey="a"-ProfileQuotedLeak88,DIRECT'
  - 'DOMAIN-KEYWORD,xapi_key=https://ProfileAmpHost77.example&next=1,DIRECT'
  - "DOMAIN-KEYWORD,https://a.com\tcol2,DIRECT"
  - MATCH,DIRECT
"#;
        let mut cfg = ClashConfig::from_yaml_str(yaml).unwrap();
        cfg.dns.enable = false;
        let engine = ProxyEngine::start_with_state_dir(cfg, tmp_dir.clone())
            .await
            .unwrap();

        let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
        let (bound, server_handle) = spawn_api_server("127.0.0.1:0", Arc::clone(&engine), stop_rx)
            .await
            .unwrap();

        let mut conn = tokio::net::TcpStream::connect(bound).await.unwrap();
        conn.write_all(
            format!(
                "GET /diagnostics/export HTTP/1.1\r\nHost: {bound}\r\nAuthorization: Bearer export-ctrl-secret-99\r\nConnection: close\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
        let mut raw = Vec::new();
        conn.read_to_end(&mut raw).await.unwrap();
        assert!(String::from_utf8_lossy(&raw).starts_with("HTTP/1.1 200"));
        let body = extract_http_response_body_str(&raw).unwrap();

        // ZERO plaintext secrets anywhere in the ENTIRE diagnostics export JSON (both
        // `config_redacted_yaml` AND `profiles.profiles[].custom_rules_backup`)!
        for leaked in [
            "export-ctrl-secret-99",
            "ProfileBackupLeak99",
            "ProfileQuotedLeak88",
            "ProfileAmpHost77",
            "profileamphost77",
            "12345678-1234-4321-abcd-998877665544",
        ] {
            assert!(
                !body.contains(leaked),
                "secret '{leaked}' leaked in GET /diagnostics/export body: {body}"
            );
        }

        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        let profiles = parsed["profiles"]["profiles"]
            .as_array()
            .expect("profiles.profiles array");
        assert!(
            !profiles.is_empty(),
            "expected seeded starter profile in diagnostics export"
        );
        let backup_rules = profiles[0]["custom_rules_backup"]
            .as_array()
            .expect("custom_rules_backup array");
        assert!(
            backup_rules
                .iter()
                .any(|r| r.as_str() == Some("DOMAIN-KEYWORD,https://a.com\tcol2,DIRECT")),
            "benign TSV rule should stay intact in custom_rules_backup: {backup_rules:?}"
        );
        assert!(
            backup_rules
                .iter()
                .any(|r| r.as_str() == Some("MATCH,DIRECT")),
            "MATCH,DIRECT should stay intact in custom_rules_backup: {backup_rules:?}"
        );
        // Normal selected_groups proxy/group names stay intact
        if let Some(sel) = profiles[0]["selected_groups"].as_object()
            && let Some(proxy_sel) = sel.get("PROXY")
        {
            assert_eq!(proxy_sel.as_str(), Some("HK (Fast) [VIP]"));
        }

        let _ = stop_tx.send(true);
        let _ = server_handle.await;
        engine.shutdown();
        let _ = std::fs::remove_dir_all(&tmp_dir);
    }
}

use std::{net::SocketAddr, sync::Arc, time::Duration};

use proxy_core::{api::spawn_api_server, engine::ProxyEngine};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::watch,
};

async fn raw_http_request(
    addr: SocketAddr,
    method: &str,
    path: &str,
    bearer: Option<&str>,
    json_body: Option<&str>,
) -> (u16, String) {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let body = json_body.unwrap_or("");
    let auth_hdr = bearer
        .map(|t| format!("Authorization: Bearer {t}\r\n"))
        .unwrap_or_default();
    let content_hdr = if json_body.is_some() {
        format!(
            "Content-Type: application/json\r\nContent-Length: {}\r\n",
            body.len()
        )
    } else {
        String::new()
    };
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: {addr}\r\n{auth_hdr}{content_hdr}Connection: close\r\n\r\n{body}"
    );
    stream.write_all(req.as_bytes()).await.unwrap();
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await.unwrap();
    let text = String::from_utf8_lossy(&raw).into_owned();
    let (hdr_part, body_part) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let status_code = hdr_part
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    (status_code, body_part.to_string())
}

#[tokio::test]
async fn control_plane_rest_ws_benchmark_and_embedded_ui_e2e() {
    let engine = ProxyEngine::start_demo(
        Some(0),
        Some("127.0.0.1:0".into()),
        Some("127.0.0.1:0".into()),
    )
    .await
    .unwrap();

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (api_addr, _api_task) = spawn_api_server("127.0.0.1:0", Arc::clone(&engine), shutdown_rx)
        .await
        .unwrap();

    // 1. Embedded SPA `/` serves compiled production `index.html`
    let (code, html) = raw_http_request(api_addr, "GET", "/", None, None).await;
    assert_eq!(code, 200);
    assert!(html.contains("<div id=\"root\">"));

    // 2. `/version` & `/configs`
    let (code, ver_body) = raw_http_request(api_addr, "GET", "/version", None, None).await;
    assert_eq!(code, 200);
    let ver_json: serde_json::Value = serde_json::from_str(&ver_body).unwrap();
    assert_eq!(ver_json["meta"], true);

    // 3. Switch mode via `PATCH /configs` -> `global` -> `rule`
    let (code, _) = raw_http_request(
        api_addr,
        "PATCH",
        "/configs",
        None,
        Some(r#"{"mode":"global"}"#),
    )
    .await;
    assert_eq!(code, 204);
    let (_, cfg_body) = raw_http_request(api_addr, "GET", "/configs", None, None).await;
    assert!(cfg_body.contains(r#""mode":"global""#));
    let _ = raw_http_request(
        api_addr,
        "PATCH",
        "/configs",
        None,
        Some(r#"{"mode":"rule"}"#),
    )
    .await;

    // 4. Probe proxy latency via `GET /proxies/{name}/delay` across ALL 3 flagship protocol families!
    for node in [
        "TYO-VLESS-PQ-Native-0RTT",
        "LAX-AnyTLS-v2-MuxPool",
        "HK-SS2022-Blake3-AES256",
    ] {
        let path = format!("/proxies/{node}/delay?timeout=4000");
        let (code, delay_body) = raw_http_request(api_addr, "GET", &path, None, None).await;
        assert_eq!(code, 200, "delay probe failed for {node}: {delay_body}");
        let dj: serde_json::Value = serde_json::from_str(&delay_body).unwrap();
        assert!(dj["delay"].as_u64().unwrap() >= 1);
    }

    // 5. Select active proxy in `🚀 Proxy` and run live multi-stream stress benchmark (`POST /tools/benchmark`)!
    let (code, _) = raw_http_request(
        api_addr,
        "PUT",
        "/proxies/%F0%9F%9A%80%20Proxy",
        None,
        Some(r#"{"name":"LAX-AnyTLS-v2-MuxPool"}"#),
    )
    .await;
    assert_eq!(code, 204);

    let (code, bench_body) = raw_http_request(
        api_addr,
        "POST",
        "/tools/benchmark",
        None,
        Some(r#"{"streams":3,"payload_bytes":65536}"#),
    )
    .await;
    assert_eq!(code, 200, "benchmark failed: {bench_body}");
    let bj: serde_json::Value = serde_json::from_str(&bench_body).unwrap();
    assert!(bj["total_bytes"].as_u64().unwrap() >= 3 * 65536);

    // 6. Verify Post-Quantum keygen API (`POST /tools/vless-keypair`) & Fake-IP DNS API (`GET /dns/query`)
    let (code, kp_body) = raw_http_request(
        api_addr,
        "POST",
        "/tools/vless-keypair",
        None,
        Some(r#"{"mode":"random","zero_rtt":true,"post_quantum":true}"#),
    )
    .await;
    assert_eq!(code, 200);
    let kpj: serde_json::Value = serde_json::from_str(&kp_body).unwrap();
    assert!(
        kpj["encryption"]
            .as_str()
            .unwrap()
            .starts_with("mlkem768x25519plus.random.0rtt.")
    );
    assert_eq!(kpj["mlkem768_encapsulation_key_bytes"], 1184);

    let (code, dns_body) = raw_http_request(
        api_addr,
        "GET",
        "/dns/query?name=anthropic.com&type=A",
        None,
        None,
    )
    .await;
    assert_eq!(code, 200);
    assert!(dns_body.contains("198.18."));

    // 7. Verify RFC 6455 WebSocket upgrade on `/traffic` streams live JSON frames!
    let mut ws_tcp = TcpStream::connect(api_addr).await.unwrap();
    let ws_handshake = format!(
        "GET /traffic HTTP/1.1\r\n\
         Host: {api_addr}\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
         Sec-WebSocket-Version: 13\r\n\r\n"
    );
    ws_tcp.write_all(ws_handshake.as_bytes()).await.unwrap();
    let mut ws_buf = [0u8; 2048];
    let n = tokio::time::timeout(Duration::from_secs(3), ws_tcp.read(&mut ws_buf))
        .await
        .unwrap()
        .unwrap();
    let resp_str = String::from_utf8_lossy(&ws_buf[..n]);
    assert!(resp_str.starts_with("HTTP/1.1 101 Switching Protocols"));

    // Trigger a telemetry tick and read the WebSocket text frame (`0x81`)
    engine.hub().sample_tick();
    let frame_n = tokio::time::timeout(Duration::from_secs(3), ws_tcp.read(&mut ws_buf))
        .await
        .unwrap()
        .unwrap();
    assert!(frame_n > 2 && ws_buf[0] == 0x81);

    // 8. Verify `/connections` REST + WebSocket upgrade and routing/geodata/diagnostics endpoints
    let (code, conn_body) = raw_http_request(api_addr, "GET", "/connections", None, None).await;
    assert_eq!(code, 200);
    assert!(conn_body.contains("\"connections\""));

    let mut conn_ws = TcpStream::connect(api_addr).await.unwrap();
    let conn_ws_req = format!(
        "GET /connections HTTP/1.1\r\n\
         Host: {api_addr}\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
         Sec-WebSocket-Version: 13\r\n\r\n"
    );
    conn_ws.write_all(conn_ws_req.as_bytes()).await.unwrap();
    let mut cbuf = [0u8; 4096];
    let mut total_read = 0usize;
    while total_read < 200 {
        let n = tokio::time::timeout(
            Duration::from_secs(3),
            conn_ws.read(&mut cbuf[total_read..]),
        )
        .await
        .unwrap()
        .unwrap();
        if n == 0 {
            break;
        }
        total_read += n;
        let s = String::from_utf8_lossy(&cbuf[..total_read]);
        if s.contains("101 Switching Protocols") && s.contains("\"connections\"") {
            break;
        }
    }
    let combined = String::from_utf8_lossy(&cbuf[..total_read]);
    assert!(combined.starts_with("HTTP/1.1 101 Switching Protocols"));
    assert!(combined.contains("\"connections\""));

    let (code, geo_body) = raw_http_request(api_addr, "GET", "/geodata", None, None).await;
    assert_eq!(code, 200);
    assert!(geo_body.contains("\"geosite_cn_entries\""));

    let (code, diag_body) =
        raw_http_request(api_addr, "GET", "/connections/diagnostics", None, None).await;
    assert_eq!(code, 200);
    assert!(diag_body.contains("\"diagnostics\""));

    let _ = shutdown_tx.send(true);
    engine.shutdown();
}

#[tokio::test]
async fn control_plane_ws_token_query_auth_and_custom_rules_e2e() {
    let state_dir = std::env::temp_dir().join(format!(
        "rust-clash-api-e2e-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&state_dir).unwrap();
    let yaml = r#"
mixed-port: 0
external-controller: "127.0.0.1:0"
secret: "s3cr3t-t0k3n!"
mode: rule
dns:
  enable: false
proxies:
  - name: "Trojan-WS-Node"
    type: trojan
    server: "edge.example.com"
    port: 443
    password: "pass"
    network: ws
    ws-opts:
      path: "/ws"
proxy-groups:
  - name: "PROXY"
    type: select
    proxies: ["Trojan-WS-Node", "DIRECT"]
rules:
  - "MATCH,PROXY"
"#;
    let cfg = proxy_core::config::ClashConfig::from_yaml_str(yaml).unwrap();
    let engine = ProxyEngine::start_with_state_dir(cfg, state_dir.clone())
        .await
        .unwrap();

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (api_addr, _api_task) = spawn_api_server("127.0.0.1:0", Arc::clone(&engine), shutdown_rx)
        .await
        .unwrap();

    // Unauthenticated REST & wrong `?token=` WS upgrade must be rejected with 401
    let (code, _) = raw_http_request(api_addr, "GET", "/connections", None, None).await;
    assert_eq!(code, 401);

    let mut bad_ws = TcpStream::connect(api_addr).await.unwrap();
    let bad_req = format!(
        "GET /connections?token=wrong HTTP/1.1\r\n\
         Host: {api_addr}\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
         Sec-WebSocket-Version: 13\r\n\r\n"
    );
    bad_ws.write_all(bad_req.as_bytes()).await.unwrap();
    let mut buf = [0u8; 2048];
    let n = tokio::time::timeout(Duration::from_secs(3), bad_ws.read(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert!(String::from_utf8_lossy(&buf[..n]).starts_with("HTTP/1.1 401"));

    // Percent-encoded `?token=s3cr3t-t0k3n%21` WebSocket upgrade on `/connections` succeeds!
    let mut ok_ws = TcpStream::connect(api_addr).await.unwrap();
    let ok_req = format!(
        "GET /connections?token=s3cr3t-t0k3n%21 HTTP/1.1\r\n\
         Host: {api_addr}\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
         Sec-WebSocket-Version: 13\r\n\r\n"
    );
    ok_ws.write_all(ok_req.as_bytes()).await.unwrap();
    let n = tokio::time::timeout(Duration::from_secs(3), ok_ws.read(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert!(String::from_utf8_lossy(&buf[..n]).starts_with("HTTP/1.1 101 Switching Protocols"));

    // Verify `PUT /routing/custom-rules` + `GET /routing/custom-rules` with Bearer auth
    let (code, _) = raw_http_request(
        api_addr,
        "PUT",
        "/routing/custom-rules",
        Some("s3cr3t-t0k3n!"),
        Some(r#"{"rules":["DOMAIN-SUFFIX,openai.com,PROXY","MATCH,DIRECT"]}"#),
    )
    .await;
    assert_eq!(code, 200);

    let (code, rules_body) = raw_http_request(
        api_addr,
        "GET",
        "/routing/custom-rules",
        Some("s3cr3t-t0k3n!"),
        None,
    )
    .await;
    assert_eq!(code, 200);
    assert!(rules_body.contains("DOMAIN-SUFFIX,openai.com,PROXY"));

    let _ = shutdown_tx.send(true);
    engine.shutdown();
    let _ = std::fs::remove_dir_all(&state_dir);
}

#[tokio::test]
async fn control_plane_audit_diff_waterfall_and_matrix_e2e() {
    let engine = ProxyEngine::start_demo(
        Some(0),
        Some("127.0.0.1:0".to_string()),
        Some("127.0.0.1:0".to_string()),
    )
    .await
    .unwrap();
    let demo_origin = engine.demo_info().http_benchmark_origin.clone();
    assert!(!demo_origin.is_empty());

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (api_addr, _api_task) = spawn_api_server("127.0.0.1:0", Arc::clone(&engine), shutdown_rx)
        .await
        .unwrap();

    // 1. GET /diagnostics/audit
    let (code, audit_body) =
        raw_http_request(api_addr, "GET", "/diagnostics/audit", None, None).await;
    assert_eq!(code, 200, "GET /diagnostics/audit body: {audit_body}");
    let audit_val: serde_json::Value = serde_json::from_str(&audit_body).unwrap();
    assert!(audit_val["score"].as_u64().is_some());
    assert_eq!(audit_val["simulation_basis"], "live_router_selection");
    assert!(audit_val["leak_matrix"].as_array().unwrap().len() >= 5);

    // 2. POST /diagnostics/audit with draft YAML introducing insecure node + secret
    let draft_secret = "NeverLeakThisDraftPassword887766!";
    let draft_payload = serde_json::json!({
        "diff_against_active": true,
        "yaml": format!(
            "mixed-port: 7890\nmode: rule\ndns:\n  enable: true\n  enhanced-mode: fake-ip\n  nameserver:\n    - 1.1.1.1:53\nproxies:\n  - name: Risky-Trojan\n    type: trojan\n    server: 198.51.100.77\n    port: 443\n    password: {draft_secret}\n    skip-cert-verify: true\nproxy-groups:\n  - name: PROXY\n    type: select\n    proxies: [Risky-Trojan, DIRECT]\nrules:\n  - IP-CIDR,10.0.0.0/8,DIRECT\n  - MATCH,PROXY\n"
        )
    });
    let (code, diff_body) = raw_http_request(
        api_addr,
        "POST",
        "/diagnostics/audit",
        None,
        Some(&draft_payload.to_string()),
    )
    .await;
    assert_eq!(code, 200, "POST /diagnostics/audit body: {diff_body}");
    assert!(
        !diff_body.contains(draft_secret),
        "Draft audit/diff response must never leak raw credentials"
    );
    let diff_val: serde_json::Value = serde_json::from_str(&diff_body).unwrap();
    assert!(
        diff_val["diff"]["newly_insecure_nodes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|n| n.as_str() == Some("Risky-Trojan"))
    );

    // 3. POST /proxies/{name}/probe through real Demo SS-2022 / VLESS+PQ / AnyTLS cluster + UDP check
    let probe_payload = serde_json::json!({
        "url": format!("{demo_origin}/generate_204"),
        "check_udp": true,
        "timeout_ms": 4000
    });
    let (code, probe_body) = raw_http_request(
        api_addr,
        "POST",
        "/proxies/%F0%9F%9A%80%20Proxy/probe",
        None,
        Some(&probe_payload.to_string()),
    )
    .await;
    assert_eq!(code, 200, "POST /proxies/.../probe body: {probe_body}");
    let probe_val: serde_json::Value = serde_json::from_str(&probe_body).unwrap();
    assert_eq!(probe_val["verdict"], "reachable");
    assert_eq!(probe_val["http_status"], 204);
    assert!(probe_val["tunnel_connect_ms"].as_f64().is_some());
    assert!(probe_val["http_ttfb_ms"].as_f64().is_some());
    assert!(probe_val["overall_probe_duration_ms"].as_f64().is_some());
    assert_eq!(probe_val["udp_probe"]["status"], "verified");

    // 4. POST /proxies/{name}/matrix with demo sandbox loopback targets
    let matrix_payload = serde_json::json!({
        "timeout_ms": 4000,
        "targets": [
            {
                "id": "demo-204",
                "label": "Demo 204",
                "category": "sandbox",
                "url": format!("{demo_origin}/generate_204")
            },
            {
                "id": "demo-echo",
                "label": "Demo Echo",
                "category": "ai",
                "url": format!("{demo_origin}/echo")
            }
        ]
    });
    let (code, matrix_body) = raw_http_request(
        api_addr,
        "POST",
        "/proxies/%F0%9F%9A%80%20Proxy/matrix",
        None,
        Some(&matrix_payload.to_string()),
    )
    .await;
    assert_eq!(code, 200, "POST /proxies/.../matrix body: {matrix_body}");
    let matrix_val: serde_json::Value = serde_json::from_str(&matrix_body).unwrap();
    assert_eq!(matrix_val["reachable_count"], 2);
    assert_eq!(matrix_val["ai_egress_unblocked"], true);
    assert_eq!(matrix_val["udp_probe"]["status"], "verified");

    // 5. SSRF guard rejects non-demo localhost, private LAN, and cloud metadata probe URLs over HTTP API
    for bad_url in [
        "http://169.254.169.254/latest/meta-data/",
        "http://127.0.0.1:9/internal",
        "http://192.168.1.1/admin",
    ] {
        let ssrf_payload = serde_json::json!({
            "url": bad_url,
            "check_udp": false,
            "timeout_ms": 1500
        });
        let (bad_code, bad_body) = raw_http_request(
            api_addr,
            "POST",
            "/proxies/%F0%9F%9A%80%20Proxy/probe",
            None,
            Some(&ssrf_payload.to_string()),
        )
        .await;
        assert_eq!(
            bad_code, 400,
            "Expected HTTP 400 SSRF block for {bad_url}: {bad_body}"
        );
        assert!(
            bad_body.contains("blocked by SSRF protection"),
            "Expected SSRF message for {bad_url}: {bad_body}"
        );
    }

    // 6. POST /diagnostics/site-check (Site Doctor) + GET /configs real RSS
    let (_, cfgs_body) = raw_http_request(api_addr, "GET", "/configs", None, None).await;
    let cfgs_val: serde_json::Value = serde_json::from_str(&cfgs_body).unwrap();
    assert!(
        cfgs_val["process-rss-bytes"].as_u64().unwrap_or(0) > 0,
        "GET /configs must expose real process-rss-bytes"
    );

    let site_ok_payload = serde_json::json!({
        "target": format!("{demo_origin}/generate_204"),
        "check_udp": true,
        "timeout_ms": 4000
    });
    let (site_code, site_body) = raw_http_request(
        api_addr,
        "POST",
        "/diagnostics/site-check",
        None,
        Some(&site_ok_payload.to_string()),
    )
    .await;
    assert_eq!(
        site_code, 200,
        "POST /diagnostics/site-check body: {site_body}"
    );
    let site_val: serde_json::Value = serde_json::from_str(&site_body).unwrap();
    assert!(
        matches!(
            site_val["diagnosis_code"].as_str(),
            Some("reachable" | "reachable_takeover_off")
        ),
        "unexpected site diagnosis_code: {site_val}"
    );
    assert!(!site_val["headline_zh"].as_str().unwrap_or("").is_empty());
    assert!(!site_val["stage_checks"].as_array().unwrap().is_empty());

    let site_ssrf_payload = serde_json::json!({
        "target": "http://169.254.169.254/latest/meta-data/",
        "check_udp": false,
        "timeout_ms": 1500
    });
    let (site_bad_code, site_bad_body) = raw_http_request(
        api_addr,
        "POST",
        "/diagnostics/site-check",
        None,
        Some(&site_ssrf_payload.to_string()),
    )
    .await;
    assert_eq!(site_bad_code, 400);
    assert!(site_bad_body.contains("blocked by SSRF protection"));

    let _ = shutdown_tx.send(true);
    engine.shutdown();
}

async fn connect_ws_and_read_header(
    addr: SocketAddr,
    path_and_query: &str,
) -> (TcpStream, Vec<u8>) {
    let mut tcp = TcpStream::connect(addr).await.unwrap();
    let req = format!(
        "GET {path_and_query} HTTP/1.1\r\n\
         Host: {addr}\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
         Sec-WebSocket-Version: 13\r\n\r\n"
    );
    tcp.write_all(req.as_bytes()).await.unwrap();
    let mut raw = Vec::new();
    let mut tmp = [0u8; 2048];
    let hdr_end = loop {
        let n = tokio::time::timeout(Duration::from_secs(3), tcp.read(&mut tmp))
            .await
            .unwrap()
            .unwrap();
        assert!(n > 0, "unexpected EOF waiting for WS 101 response");
        raw.extend_from_slice(&tmp[..n]);
        if let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos;
        }
    };
    let head = String::from_utf8_lossy(&raw[..hdr_end]);
    assert!(
        head.starts_with("HTTP/1.1 101 Switching Protocols"),
        "expected WS 101, got: {head}"
    );
    let leftover = raw[hdr_end + 4..].to_vec();
    (tcp, leftover)
}

async fn read_next_ws_text_frame(
    tcp: &mut TcpStream,
    buf: &mut Vec<u8>,
    timeout: Duration,
) -> Option<String> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if buf.len() >= 2 {
            let opcode = buf[0] & 0x0f;
            let masked = (buf[1] & 0x80) != 0;
            let len_code = (buf[1] & 0x7f) as usize;
            let (payload_len, mut hdr_len) = if len_code <= 125 {
                (len_code, 2usize)
            } else if len_code == 126 {
                if buf.len() < 4 {
                    (0, usize::MAX)
                } else {
                    (u16::from_be_bytes([buf[2], buf[3]]) as usize, 4usize)
                }
            } else if buf.len() < 10 {
                (0, usize::MAX)
            } else {
                (
                    u64::from_be_bytes(buf[2..10].try_into().unwrap()) as usize,
                    10usize,
                )
            };
            if hdr_len != usize::MAX {
                if masked {
                    hdr_len += 4;
                }
                if buf.len() >= hdr_len + payload_len {
                    let payload = buf[hdr_len..hdr_len + payload_len].to_vec();
                    buf.drain(..hdr_len + payload_len);
                    if opcode == 0x1 {
                        return Some(String::from_utf8_lossy(&payload).into_owned());
                    }
                    if opcode == 0x8 {
                        return None;
                    }
                    continue;
                }
            }
        }
        let rem = deadline.saturating_duration_since(tokio::time::Instant::now());
        if rem.is_zero() {
            return None;
        }
        let mut tmp = [0u8; 4096];
        match tokio::time::timeout(rem, tcp.read(&mut tmp)).await {
            Ok(Ok(0)) | Err(_) => return None,
            Ok(Ok(n)) => buf.extend_from_slice(&tmp[..n]),
            Ok(Err(_)) => return None,
        }
    }
}

#[tokio::test]
async fn ws_logs_level_filtering_and_zero_drop_snapshot_subscribe_e2e() {
    let state_dir = std::env::temp_dir().join(format!(
        "rust-clash-ws-logs-e2e-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&state_dir).unwrap();

    let yaml = r#"
mixed-port: 0
external-controller: "127.0.0.1:0"
log-level: debug
mode: rule
dns:
  enable: false
proxies: []
proxy-groups:
  - name: "PROXY"
    type: select
    proxies: ["DIRECT"]
rules:
  - "MATCH,DIRECT"
"#;
    let cfg = proxy_core::config::ClashConfig::from_yaml_str(yaml).unwrap();
    let engine = ProxyEngine::start_with_state_dir(cfg, state_dir.clone())
        .await
        .unwrap();
    engine.hub().clear_logs();

    // Seed snapshot backlog with mixed severities (including warn/error before info noise).
    engine.hub().push_log("debug", "snap-debug-0");
    engine.hub().push_log("info", "snap-info-0");
    engine.hub().push_log("warn", "snap-warn-0");
    engine.hub().push_log("error", "snap-error-0");
    for i in 0..12 {
        engine.hub().push_log("info", format!("snap-info-fill-{i}"));
    }

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (api_addr, _api_task) = spawn_api_server("127.0.0.1:0", Arc::clone(&engine), shutdown_rx)
        .await
        .unwrap();

    // 1. Connect WS `/logs?level=warn` while concurrently emitting a burst of mixed logs across
    //    the handshake/snapshot boundary. Every warn/error must arrive with ZERO drops, ZERO dupes,
    //    and ZERO info/debug leakage!
    let burst_engine = Arc::clone(&engine);
    let burst_task = tokio::spawn(async move {
        for i in 0..25 {
            burst_engine
                .hub()
                .push_log("debug", format!("burst-debug-{i}"));
            burst_engine
                .hub()
                .push_log("info", format!("burst-info-{i}"));
            burst_engine
                .hub()
                .push_log("warn", format!("burst-warn-{i}"));
            burst_engine
                .hub()
                .push_log("error", format!("burst-error-{i}"));
            tokio::task::yield_now().await;
        }
    });

    let (mut ws_warn, mut ws_warn_buf) =
        connect_ws_and_read_header(api_addr, "/logs?level=warn").await;
    burst_task.await.unwrap();

    // Emit one final sentinel error after burst completes so we know when all queued entries arrived.
    engine.hub().push_log("error", "burst-sentinel-end");

    let mut received_warn_payloads = Vec::new();
    while let Some(frame) =
        read_next_ws_text_frame(&mut ws_warn, &mut ws_warn_buf, Duration::from_secs(3)).await
    {
        let entry: serde_json::Value = serde_json::from_str(&frame).unwrap();
        let lvl = entry["type"].as_str().unwrap();
        let payload = entry["payload"].as_str().unwrap().to_string();
        assert!(
            matches!(lvl, "warn" | "warning" | "error" | "err"),
            "WS /logs?level=warn leaked non-warn/error entry: {frame}"
        );
        received_warn_payloads.push(payload.clone());
        if payload == "burst-sentinel-end" {
            break;
        }
    }

    // Verify all expected snapshot + burst warn/error items arrived once (zero drops, zero duplicates).
    let mut expected = vec![
        "snap-warn-0".to_string(),
        "snap-error-0".to_string(),
        "burst-sentinel-end".to_string(),
    ];
    for i in 0..25 {
        expected.push(format!("burst-warn-{i}"));
        expected.push(format!("burst-error-{i}"));
    }
    for exp in &expected {
        let count = received_warn_payloads.iter().filter(|p| *p == exp).count();
        assert_eq!(
            count, 1,
            "expected '{exp}' exactly once on WS /logs?level=warn, got {count} (all={received_warn_payloads:?})"
        );
    }

    // 2. Verify WS `/logs?level=error` filters out `warn`, `info`, and `debug`.
    let (mut ws_err, mut ws_err_buf) =
        connect_ws_and_read_header(api_addr, "/logs?level=error").await;
    engine.hub().push_log("warn", "err-only-should-skip-warn");
    engine.hub().push_log("info", "err-only-should-skip-info");
    engine.hub().push_log("error", "err-only-sentinel");

    let mut saw_err_sentinel = false;
    while let Some(frame) =
        read_next_ws_text_frame(&mut ws_err, &mut ws_err_buf, Duration::from_secs(3)).await
    {
        let entry: serde_json::Value = serde_json::from_str(&frame).unwrap();
        let lvl = entry["type"].as_str().unwrap();
        let payload = entry["payload"].as_str().unwrap();
        assert!(
            matches!(lvl, "error" | "err"),
            "WS /logs?level=error leaked non-error entry: {frame}"
        );
        if payload == "err-only-sentinel" {
            saw_err_sentinel = true;
            break;
        }
    }
    assert!(
        saw_err_sentinel,
        "missing err-only-sentinel on WS /logs?level=error"
    );

    let _ = shutdown_tx.send(true);
    engine.shutdown();
    let _ = std::fs::remove_dir_all(&state_dir);
}

#[tokio::test]
async fn online_country_mmdb_update_applies_immediately_without_router_rebuild_e2e() {
    use proxy_core::{
        addr::TargetAddr,
        router::{
            geodata::{GeoDataset, GeoUpdateUrls, current_geodata, install_live_geodata},
            mmdb::{MmdbReader, build_synthetic_country_mmdb},
        },
    };
    use tokio::net::TcpListener;

    struct LiveGeodataRestoreGuard(Arc<GeoDataset>);
    impl Drop for LiveGeodataRestoreGuard {
        fn drop(&mut self) {
            install_live_geodata(Arc::clone(&self.0));
        }
    }
    let _restore = LiveGeodataRestoreGuard(current_geodata());

    let state_dir = std::env::temp_dir().join(format!(
        "rust-clash-live-mmdb-e2e-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let geodata_dir = state_dir.join("geodata");
    std::fs::create_dir_all(&geodata_dir).unwrap();

    // 1. Seed startup `state_dir/geodata/Country.mmdb` mapping `198.51.100.0/24 -> JP`.
    let mmdb_jp_bytes = build_synthetic_country_mmdb(&[("198.51.100.0/24".parse().unwrap(), "JP")]);
    let mmdb_sg_bytes = build_synthetic_country_mmdb(&[("198.51.100.0/24".parse().unwrap(), "SG")]);
    let mmdb_de_bytes = build_synthetic_country_mmdb(&[("198.51.100.0/24".parse().unwrap(), "DE")]);
    std::fs::write(geodata_dir.join("Country.mmdb"), &mmdb_jp_bytes).unwrap();

    let base_yaml = r#"
mixed-port: 0
external-controller: "127.0.0.1:0"
mode: rule
dns:
  enable: false
proxies:
  - name: "Node-JP"
    type: socks5
    server: "127.0.0.1"
    port: 1081
  - name: "Node-SG"
    type: socks5
    server: "127.0.0.1"
    port: 1082
proxy-groups:
  - name: "PROXY"
    type: select
    proxies: ["Node-JP", "Node-SG", "DIRECT"]
rules:
  - "GEOIP,JP,Node-JP,no-resolve"
  - "GEOIP,SG,Node-SG,no-resolve"
  - "MATCH,DIRECT"
"#;
    let cfg = proxy_core::config::ClashConfig::from_yaml_str(base_yaml).unwrap();
    assert!(cfg.mmdb_path.is_none());

    let engine = ProxyEngine::start_with_state_dir(cfg.clone(), state_dir.clone())
        .await
        .unwrap();
    let router_before = engine.router();
    let target = TargetAddr::new_ip("198.51.100.42".parse().unwrap(), 443);

    // Startup persisted `Country.mmdb` resolves `198.51.100.42` to `JP` -> `Node-JP`.
    let d1 = router_before.route_async(None, &target).await;
    assert_eq!(d1.outbound.name(), "Node-JP");

    // 2. Serve a local HTTP mock GeoData mirror delivering updated `Country.mmdb` (`SG`) and run
    //    `GeoDataManager::update_from_urls` WITHOUT rebuilding or reloading the router!
    let mirror_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mirror_addr = mirror_listener.local_addr().unwrap();
    let mmdb_sg_srv = mmdb_sg_bytes.clone();
    let mirror_task = tokio::spawn(async move {
        while let Ok((mut s, _)) = mirror_listener.accept().await {
            let mmdb_payload = mmdb_sg_srv.clone();
            tokio::spawn(async move {
                let mut req_buf = [0u8; 2048];
                let Ok(n) = s.read(&mut req_buf).await else {
                    return;
                };
                let req_str = String::from_utf8_lossy(&req_buf[..n]);
                let first_line = req_str.lines().next().unwrap_or("");
                let path = first_line.split_whitespace().nth(1).unwrap_or("/");
                let body: Vec<u8> = match path {
                    "/direct.txt" => b"domain:example.cn\n".to_vec(),
                    "/proxy.txt" => b"domain:example.org\n".to_vec(),
                    "/cncidr.txt" => b"223.5.5.0/24\n".to_vec(),
                    "/Country.mmdb" => mmdb_payload,
                    _ => Vec::new(),
                };
                let hdr = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = s.write_all(hdr.as_bytes()).await;
                let _ = s.write_all(&body).await;
            });
        }
    });

    let epoch_before = router_before.epoch();
    let gm = engine.geodata_manager().expect("geodata manager present");
    let urls = GeoUpdateUrls {
        label: "local-mmdb-test".to_string(),
        geosite_cn_url: format!("http://{mirror_addr}/direct.txt"),
        geosite_non_cn_url: format!("http://{mirror_addr}/proxy.txt"),
        geoip_cn_url: format!("http://{mirror_addr}/cncidr.txt"),
        mmdb_url: Some(format!("http://{mirror_addr}/Country.mmdb")),
    };
    let status = gm.update_from_urls(&urls).await.unwrap();
    assert!(status.mmdb_present);

    // The EXACT same pre-existing `router_before` immediately routes `198.51.100.42` to `Node-SG`!
    assert!(
        router_before.epoch() > epoch_before,
        "GeoDataManager update must bump attached router epoch"
    );
    let d2 = router_before.route_async(None, &target).await;
    assert_eq!(
        d2.outbound.name(),
        "Node-SG",
        "online Country.mmdb update must take effect immediately without router rebuild"
    );

    // 3. Hot-reload via `reload_yaml` (exercising `transition_config_locked`) must also keep
    //    `rule_mmdb == None` so subsequent live `Country.mmdb` updates apply immediately!
    engine.reload_yaml(base_yaml).await.unwrap();
    let router_reloaded = engine.router();
    assert_eq!(
        router_reloaded
            .route_async(None, &target)
            .await
            .outbound
            .name(),
        "Node-SG"
    );
    let cur = current_geodata();
    install_live_geodata(Arc::new(GeoDataset {
        geosite_cn: cur.geosite_cn.clone(),
        geosite_non_cn: cur.geosite_non_cn.clone(),
        geoip_cn: cur.geoip_cn.clone(),
        mmdb: Some(Arc::new(MmdbReader::from_bytes(mmdb_de_bytes).unwrap())),
        using_persisted_data: true,
    }));
    assert_eq!(
        router_reloaded
            .route_async(None, &target)
            .await
            .outbound
            .name(),
        "DIRECT",
        "post-reload router must dynamically pick up live Country.mmdb updates"
    );

    // 4. Standalone router (`build_standalone_router`) also tracks `LIVE_GEODATA` dynamically.
    let standalone = ProxyEngine::build_standalone_router(&cfg).unwrap();
    assert_eq!(
        standalone.route_async(None, &target).await.outbound.name(),
        "DIRECT"
    );
    install_live_geodata(Arc::new(GeoDataset {
        geosite_cn: cur.geosite_cn.clone(),
        geosite_non_cn: cur.geosite_non_cn.clone(),
        geoip_cn: cur.geoip_cn.clone(),
        mmdb: Some(Arc::new(MmdbReader::from_bytes(mmdb_sg_bytes).unwrap())),
        using_persisted_data: true,
    }));
    assert_eq!(
        standalone.route_async(None, &target).await.outbound.name(),
        "Node-SG"
    );

    // 5. Explicit `cfg.mmdb_path` continues to take precedence over `LIVE_GEODATA` (`SG`).
    let explicit_mmdb_path = state_dir.join("explicit-jp.mmdb");
    std::fs::write(&explicit_mmdb_path, &mmdb_jp_bytes).unwrap();
    let mut explicit_cfg = cfg;
    explicit_cfg.mmdb_path = Some(explicit_mmdb_path.display().to_string());
    let explicit_router = ProxyEngine::build_standalone_router(&explicit_cfg).unwrap();
    assert_eq!(
        explicit_router
            .route_async(None, &target)
            .await
            .outbound
            .name(),
        "Node-JP",
        "explicit cfg.mmdb_path must override LIVE_GEODATA"
    );

    mirror_task.abort();
    engine.shutdown();
    let _ = std::fs::remove_dir_all(&state_dir);
}

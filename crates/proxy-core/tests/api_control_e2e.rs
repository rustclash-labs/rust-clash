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

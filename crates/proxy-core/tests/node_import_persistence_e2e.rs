use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use proxy_core::{
    api::spawn_api_server,
    crypto::tls::generate_self_signed_server_config,
    engine::ProxyEngine,
    outbound::{
        anytls::{AnyTlsServerConfig, padding::PaddingScheme, spawn_anytls_server},
        ss::spawn_ss_server,
        vless::{
            VlessServerConfig,
            encryption::{config::XorMode, generate_vless_encryption_pair},
            spawn_vless_server,
        },
    },
    profile::ProfileManager,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::watch,
};
use uuid::Uuid;

async fn api_request(
    addr: SocketAddr,
    method: &str,
    path: &str,
    secret: Option<&str>,
    body: Option<&str>,
) -> (u16, String) {
    let mut stream = TcpStream::connect(addr).await.expect("connect control API");
    let payload = body.unwrap_or("");
    let auth_hdr = secret
        .map(|s| format!("Authorization: Bearer {s}\r\n"))
        .unwrap_or_default();
    let req = if body.is_some() {
        format!(
            "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n{auth_hdr}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
            addr.port(),
            payload.len()
        )
    } else {
        format!(
            "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n{auth_hdr}Connection: close\r\n\r\n",
            addr.port()
        )
    };
    stream.write_all(req.as_bytes()).await.expect("write http");
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await.expect("read http");
    let text = String::from_utf8_lossy(&raw).into_owned();
    let (head, resp_body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let status = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    (status, resp_body.to_string())
}

async fn http_get_via_mixed_proxy(
    mixed_addr: SocketAddr,
    origin_port: u16,
    path: &str,
) -> (u16, String) {
    let mut stream = TcpStream::connect(mixed_addr)
        .await
        .expect("connect mixed inbound");
    // Use domain `localhost` so Rule mode bypasses `IP-CIDR,127.0.0.0/8,DIRECT,no-resolve`
    // and routes through `MATCH,PROXY` -> selected proxy node!
    let req = format!(
        "GET http://localhost:{origin_port}{path} HTTP/1.1\r\nHost: localhost:{origin_port}\r\nConnection: close\r\n\r\n"
    );
    stream
        .write_all(req.as_bytes())
        .await
        .expect("write mixed http req");
    let mut raw = Vec::new();
    stream
        .read_to_end(&mut raw)
        .await
        .expect("read mixed http resp");
    let text = String::from_utf8_lossy(&raw).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let status = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    (status, body.to_string())
}

async fn spawn_origin_http_server(
    mut shutdown: watch::Receiver<bool>,
) -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_clone = Arc::clone(&hits);

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = shutdown.changed() => break,
                res = listener.accept() => {
                    let Ok((mut sock, _)) = res else { continue };
                    let h = Arc::clone(&hits_clone);
                    tokio::spawn(async move {
                        let mut buf = [0u8; 4096];
                        let Ok(n) = sock.read(&mut buf).await else { return };
                        if n == 0 {
                            return;
                        }
                        h.fetch_add(1, Ordering::Relaxed);
                        let req = String::from_utf8_lossy(&buf[..n]);
                        let resp = if req.starts_with("GET /generate_204") || req.starts_with("HEAD /generate_204") {
                            "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string()
                        } else {
                            let body = "rust-clash-node-e2e-ok";
                            format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                                body.len()
                            )
                        };
                        let _ = sock.write_all(resp.as_bytes()).await;
                        let _ = sock.shutdown().await;
                    });
                }
            }
        }
    });

    (addr, hits)
}

#[tokio::test]
async fn blank_app_import_save_select_connect_edit_hot_reload_and_restart_e2e() {
    let state_dir = std::env::temp_dir().join(format!("rc-node-ux-e2e-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&state_dir).unwrap();

    let (srv_stop_tx, srv_stop_rx) = watch::channel(false);
    let (origin_addr, origin_hits) = spawn_origin_http_server(srv_stop_rx.clone()).await;

    // 1. Spawn real local SS-2022, VLESS+PQ, and AnyTLS v2 outbound servers
    let ss_psk = STANDARD.encode([0x42u8; 32]);
    let (ss_addr, _ss_task) = spawn_ss_server(
        "127.0.0.1:0",
        "2022-blake3-aes-256-gcm",
        &ss_psk,
        srv_stop_rx.clone(),
    )
    .await
    .expect("spawn_ss_server");

    let vless_uuid = Uuid::new_v4();
    let vless_pq = generate_vless_encryption_pair(XorMode::Native, true, true).unwrap();
    let (vless_addr, _vless_task) = spawn_vless_server(
        VlessServerConfig {
            listen_addr: "127.0.0.1:0".into(),
            allowed_uuid: vless_uuid,
            decryption: vless_pq.decryption.clone(),
            tls_config: None,
        },
        srv_stop_rx.clone(),
    )
    .await
    .expect("spawn_vless_server");

    let anytls_pass = "anytls-secret-998877";
    let (anytls_tls, _anytls_ca) = generate_self_signed_server_config(
        &["anytls.example.local".into(), "127.0.0.1".into()],
        &[b"h2".to_vec()],
    )
    .unwrap();
    let (anytls_addr, _anytls_task) = spawn_anytls_server(
        AnyTlsServerConfig {
            listen_addr: "127.0.0.1:0".into(),
            password: anytls_pass.into(),
            tls_config: anytls_tls,
            padding_scheme: PaddingScheme::default(),
        },
        srv_stop_rx.clone(),
    )
    .await
    .expect("spawn_anytls_server");

    let ctrl_secret = "e2e-ctrl-secret-776655";

    // 2. BOOT #1: Blank application startup from empty `state_dir`
    let mgr1 = ProfileManager::open_or_init(&state_dir).expect("open_or_init blank state_dir");
    let (mut boot1_cfg, _) = mgr1
        .load_active_config()
        .expect("load blank starter config");
    assert!(
        boot1_cfg.proxies.is_empty(),
        "blank app must start with 0 nodes"
    );
    boot1_cfg.mixed_port = 0;
    boot1_cfg.dns.listen = "127.0.0.1:0".into();
    boot1_cfg.external_controller = "127.0.0.1:0".into();
    boot1_cfg.secret = Some(ctrl_secret.into());

    let engine1 = ProxyEngine::start_with_state_dir(boot1_cfg, state_dir.clone())
        .await
        .expect("start blank ProxyEngine");
    engine1.attach_profile_manager(Arc::clone(&mgr1));

    let (api1_stop_tx, api1_stop_rx) = watch::channel(false);
    let (api1_addr, _api1_task) =
        spawn_api_server("127.0.0.1:0", Arc::clone(&engine1), api1_stop_rx)
            .await
            .expect("spawn API #1");

    // Verify blank app reports `effective-outbound` == `DIRECT` and 0 saved nodes
    let (st_init_proxies, body_init_proxies) =
        api_request(api1_addr, "GET", "/proxies", Some(ctrl_secret), None).await;
    assert_eq!(st_init_proxies, 200);
    let init_proxies_json: serde_json::Value = serde_json::from_str(&body_init_proxies).unwrap();
    assert_eq!(
        init_proxies_json["effective-outbound"]["effective_outbound"],
        "DIRECT"
    );

    let (st_init_nodes, body_init_nodes) = api_request(
        api1_addr,
        "GET",
        "/profiles/active/nodes",
        Some(ctrl_secret),
        None,
    )
    .await;
    assert_eq!(st_init_nodes, 200);
    let init_nodes_json: serde_json::Value = serde_json::from_str(&body_init_nodes).unwrap();
    assert_eq!(init_nodes_json["nodes"].as_array().unwrap().len(), 0);

    // 3. Paste multi-line `ss://`, `vless://`, `anytls://` share links via `POST /profiles/import`
    let ss_userinfo = URL_SAFE_NO_PAD.encode(format!("2022-blake3-aes-256-gcm:{ss_psk}"));
    let ss_link = format!("ss://{ss_userinfo}@127.0.0.1:{}#SS-Tokyo", ss_addr.port());
    let vless_link = format!(
        "vless://{vless_uuid}@127.0.0.1:{}?security=none&encryption={}#VLESS-Frankfurt",
        vless_addr.port(),
        vless_pq.encryption
    );
    let anytls_link = format!(
        "anytls://{anytls_pass}@127.0.0.1:{}?sni=anytls.example.local&insecure=1#AnyTLS-Singapore",
        anytls_addr.port()
    );
    let multi_paste = format!("{ss_link}\n{vless_link}\n{anytls_link}");

    let import_body = serde_json::json!({
        "uris": multi_paste,
        "apply": true,
        "deduplicate": true,
        "auto_select": true
    })
    .to_string();
    let (st_imp, body_imp) = api_request(
        api1_addr,
        "POST",
        "/profiles/import",
        Some(ctrl_secret),
        Some(&import_body),
    )
    .await;
    assert_eq!(st_imp, 200, "import share links failed: {body_imp}");
    let imp_json: serde_json::Value = serde_json::from_str(&body_imp).unwrap();
    assert_eq!(imp_json["applied"], true);
    assert_eq!(imp_json["input-kind"], "share-uris");
    assert_eq!(imp_json["count"], 3);
    assert_eq!(imp_json["total-nodes"], 3);
    // Deliverable 4: PROXY group must automatically switch off DIRECT onto the imported concrete node!
    assert_eq!(imp_json["selected-groups"]["PROXY"], "SS-Tokyo");
    assert_eq!(
        imp_json["effective-outbound"]["effective_outbound"],
        "SS-Tokyo"
    );
    assert!(!body_imp.contains(&ss_psk));
    assert!(!body_imp.contains(&vless_uuid.to_string()));
    assert!(!body_imp.contains(anytls_pass));

    // Verify immediate live connectivity through auto-selected `SS-Tokyo`
    let (st_http_ss, body_http_ss) =
        http_get_via_mixed_proxy(engine1.mixed_addr(), origin_addr.port(), "/hello").await;
    assert_eq!(st_http_ss, 200);
    assert_eq!(body_http_ss, "rust-clash-node-e2e-ok");
    assert!(origin_hits.load(Ordering::Relaxed) >= 1);

    // 4. Import Base64-encoded subscription containing 1 duplicate + 1 new node
    let ss_extra_psk = STANDARD.encode([0x55u8; 32]);
    let ss_extra_userinfo =
        URL_SAFE_NO_PAD.encode(format!("2022-blake3-aes-256-gcm:{ss_extra_psk}"));
    let b64_raw = format!(
        "ss://{ss_userinfo}@127.0.0.1:{}#SS-Tokyo-Duplicate\nss://{ss_extra_userinfo}@127.0.0.1:{}#SS-Extra",
        ss_addr.port(),
        ss_addr.port()
    );
    let b64_payload = STANDARD.encode(b64_raw);
    let import_b64_body = serde_json::json!({
        "uris": b64_payload,
        "apply": true,
        "deduplicate": true,
        "auto_select": true
    })
    .to_string();
    let (st_b64, body_b64) = api_request(
        api1_addr,
        "POST",
        "/profiles/import",
        Some(ctrl_secret),
        Some(&import_b64_body),
    )
    .await;
    assert_eq!(st_b64, 200, "base64 import failed: {body_b64}");
    let b64_json: serde_json::Value = serde_json::from_str(&body_b64).unwrap();
    assert_eq!(b64_json["input-kind"], "base64-uri-list");
    assert_eq!(b64_json["skipped-duplicates"], 1);
    assert_eq!(b64_json["count"], 1);
    assert_eq!(b64_json["total-nodes"], 4);

    // 5. Select `AnyTLS-Singapore`, verify effective outbound, delay probe, and live tunnel
    let (st_sel_any, _) = api_request(
        api1_addr,
        "PUT",
        "/proxies/PROXY",
        Some(ctrl_secret),
        Some(r#"{"name":"AnyTLS-Singapore"}"#),
    )
    .await;
    assert_eq!(st_sel_any, 204);

    let (st_http_any, body_http_any) =
        http_get_via_mixed_proxy(engine1.mixed_addr(), origin_addr.port(), "/hello").await;
    assert_eq!(st_http_any, 200);
    assert_eq!(body_http_any, "rust-clash-node-e2e-ok");

    // 6. Select `VLESS-Frankfurt`, probe RTT delay, and verify live PQ tunnel
    let (st_sel_vless, _) = api_request(
        api1_addr,
        "PUT",
        "/proxies/PROXY",
        Some(ctrl_secret),
        Some(r#"{"name":"VLESS-Frankfurt"}"#),
    )
    .await;
    assert_eq!(st_sel_vless, 204);

    let delay_path = format!(
        "/proxies/VLESS-Frankfurt/delay?url=http://localhost:{}/generate_204&timeout=3000",
        origin_addr.port()
    );
    let (st_delay, body_delay) =
        api_request(api1_addr, "GET", &delay_path, Some(ctrl_secret), None).await;
    assert_eq!(st_delay, 200, "VLESS delay probe failed: {body_delay}");

    let (st_http_vless, body_http_vless) =
        http_get_via_mixed_proxy(engine1.mixed_addr(), origin_addr.port(), "/hello").await;
    assert_eq!(st_http_vless, 200);
    assert_eq!(body_http_vless, "rust-clash-node-e2e-ok");

    let (st_explain, body_explain) = api_request(
        api1_addr,
        "GET",
        &format!("/rules/explain?target=localhost:{}", origin_addr.port()),
        Some(ctrl_secret),
        None,
    )
    .await;
    assert_eq!(st_explain, 200);
    let explain_json: serde_json::Value = serde_json::from_str(&body_explain).unwrap();
    assert_eq!(explain_json["outbound"], "VLESS-Frankfurt");

    // 7. Rename & edit the currently selected `VLESS-Frankfurt` -> `VLESS-Frankfurt-Renamed`
    //    passing REDACTED credentials from `GET /profiles/active/nodes`!
    let (_, active_nodes_str) = api_request(
        api1_addr,
        "GET",
        "/profiles/active/nodes",
        Some(ctrl_secret),
        None,
    )
    .await;
    assert!(!active_nodes_str.contains(&ss_psk));
    assert!(!active_nodes_str.contains(&vless_uuid.to_string()));
    assert!(!active_nodes_str.contains(&vless_pq.encryption));
    assert!(!active_nodes_str.contains(anytls_pass));

    let active_nodes_val: serde_json::Value = serde_json::from_str(&active_nodes_str).unwrap();
    let mut vless_redacted_obj = active_nodes_val["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|n| n["name"] == "VLESS-Frankfurt")
        .expect("find VLESS-Frankfurt in active nodes")
        .clone();
    assert_eq!(
        vless_redacted_obj["uuid"],
        "00000000-0000-0000-0000-000000000000"
    );
    assert_eq!(vless_redacted_obj["encryption"], "***REDACTED***");
    vless_redacted_obj["name"] = serde_json::Value::String("VLESS-Frankfurt-Renamed".into());

    let rename_body = serde_json::json!({
        "node": vless_redacted_obj
    })
    .to_string();
    let (st_ren, body_ren) = api_request(
        api1_addr,
        "PUT",
        "/profiles/active/nodes/VLESS-Frankfurt",
        Some(ctrl_secret),
        Some(&rename_body),
    )
    .await;
    assert_eq!(st_ren, 200, "rename node failed: {body_ren}");
    let ren_json: serde_json::Value = serde_json::from_str(&body_ren).unwrap();
    assert_eq!(ren_json["updated-node"], "VLESS-Frankfurt-Renamed");
    assert_eq!(
        ren_json["selected-groups"]["PROXY"],
        "VLESS-Frankfurt-Renamed"
    );
    assert_eq!(
        ren_json["effective-outbound"]["effective_outbound"],
        "VLESS-Frankfurt-Renamed"
    );

    // Live tunnel MUST still work after rename with redacted credential preservation!
    let (st_http_renamed, body_http_renamed) =
        http_get_via_mixed_proxy(engine1.mixed_addr(), origin_addr.port(), "/hello").await;
    assert_eq!(st_http_renamed, 200);
    assert_eq!(body_http_renamed, "rust-clash-node-e2e-ok");

    // 8. Test manual node creation + `POST /profiles/active/nodes/deduplicate` + `DELETE /profiles/active/nodes/{name}`
    let dup_create_body = serde_json::json!({
        "node": {
            "type": "ss",
            "name": "SS-Tokyo-Manual-Clone",
            "server": "127.0.0.1",
            "port": ss_addr.port(),
            "cipher": "2022-blake3-aes-256-gcm",
            "password": ss_psk,
            "udp": true
        },
        "auto_select": false
    })
    .to_string();
    let (st_dup_add, body_dup_add) = api_request(
        api1_addr,
        "POST",
        "/profiles/active/nodes",
        Some(ctrl_secret),
        Some(&dup_create_body),
    )
    .await;
    assert_eq!(st_dup_add, 200, "manual create failed: {body_dup_add}");

    let (st_dedup, body_dedup) = api_request(
        api1_addr,
        "POST",
        "/profiles/active/nodes/deduplicate",
        Some(ctrl_secret),
        Some("{}"),
    )
    .await;
    assert_eq!(st_dedup, 200, "deduplicate failed: {body_dedup}");
    let dedup_json: serde_json::Value = serde_json::from_str(&body_dedup).unwrap();
    assert_eq!(
        dedup_json["removed-nodes"],
        serde_json::json!(["SS-Tokyo-Manual-Clone"])
    );
    assert_eq!(
        dedup_json["effective-outbound"]["effective_outbound"],
        "VLESS-Frankfurt-Renamed"
    );

    let (st_del, body_del) = api_request(
        api1_addr,
        "DELETE",
        "/profiles/active/nodes/SS-Extra",
        Some(ctrl_secret),
        None,
    )
    .await;
    assert_eq!(st_del, 200, "delete node failed: {body_del}");
    let del_json: serde_json::Value = serde_json::from_str(&body_del).unwrap();
    assert_eq!(del_json["total-nodes"], 3);
    assert_eq!(
        del_json["effective-outbound"]["effective_outbound"],
        "VLESS-Frankfurt-Renamed"
    );

    // 9. Hot-Reload (`PUT /configs` with redacted YAML from `GET /configs/raw`)
    //    MUST preserve all 3 nodes, unredacted credentials, AND `VLESS-Frankfurt-Renamed` selection!
    let (st_raw, body_raw) =
        api_request(api1_addr, "GET", "/configs/raw", Some(ctrl_secret), None).await;
    assert_eq!(st_raw, 200);
    let raw_json: serde_json::Value = serde_json::from_str(&body_raw).unwrap();
    let redacted_yaml = raw_json["yaml"].as_str().unwrap();
    assert!(redacted_yaml.contains("***REDACTED***"));

    let put_cfg_body = serde_json::json!({ "payload": redacted_yaml }).to_string();
    let (st_reload, body_reload) = api_request(
        api1_addr,
        "PUT",
        "/configs",
        Some(ctrl_secret),
        Some(&put_cfg_body),
    )
    .await;
    assert_eq!(st_reload, 204, "hot-reload failed: {body_reload}");

    let (_, proxies_after_reload_str) =
        api_request(api1_addr, "GET", "/proxies", Some(ctrl_secret), None).await;
    let proxies_after_reload: serde_json::Value =
        serde_json::from_str(&proxies_after_reload_str).unwrap();
    assert_eq!(
        proxies_after_reload["proxies"]["PROXY"]["now"],
        "VLESS-Frankfurt-Renamed"
    );
    assert_eq!(
        proxies_after_reload["effective-outbound"]["effective_outbound"],
        "VLESS-Frankfurt-Renamed"
    );

    let (st_http_after_reload, body_http_after_reload) =
        http_get_via_mixed_proxy(engine1.mixed_addr(), origin_addr.port(), "/hello").await;
    assert_eq!(st_http_after_reload, 200);
    assert_eq!(body_http_after_reload, "rust-clash-node-e2e-ok");

    // 10. FULL APP RESTART: Shut down Boot #1 completely, then start Boot #2 from `state_dir`!
    let _ = api1_stop_tx.send(true);
    engine1.shutdown();
    drop(engine1);
    drop(mgr1);

    let mgr2 =
        ProfileManager::open_or_init(&state_dir).expect("reopen ProfileManager after restart");
    let (mut boot2_cfg, _) = mgr2
        .load_active_config()
        .expect("load persisted active config after restart");
    assert_eq!(
        boot2_cfg.proxies.len(),
        3,
        "all 3 nodes must persist on disk across app restart"
    );
    boot2_cfg.mixed_port = 0;
    boot2_cfg.dns.listen = "127.0.0.1:0".into();
    boot2_cfg.external_controller = "127.0.0.1:0".into();
    boot2_cfg.secret = Some(ctrl_secret.into());

    let engine2 = ProxyEngine::start_with_state_dir(boot2_cfg, state_dir.clone())
        .await
        .expect("start ProxyEngine #2 after restart");
    engine2.attach_profile_manager(Arc::clone(&mgr2));

    let (api2_stop_tx, api2_stop_rx) = watch::channel(false);
    let (api2_addr, _api2_task) =
        spawn_api_server("127.0.0.1:0", Arc::clone(&engine2), api2_stop_rx)
            .await
            .expect("spawn API #2");

    let (st_boot2_proxies, body_boot2_proxies) =
        api_request(api2_addr, "GET", "/proxies", Some(ctrl_secret), None).await;
    assert_eq!(st_boot2_proxies, 200);
    let boot2_proxies: serde_json::Value = serde_json::from_str(&body_boot2_proxies).unwrap();
    assert_eq!(
        boot2_proxies["proxies"]["PROXY"]["now"], "VLESS-Frankfurt-Renamed",
        "selected proxy node MUST persist across full app restart"
    );
    assert_eq!(
        boot2_proxies["effective-outbound"]["effective_outbound"],
        "VLESS-Frankfurt-Renamed"
    );

    let (st_boot2_http, body_boot2_http) =
        http_get_via_mixed_proxy(engine2.mixed_addr(), origin_addr.port(), "/hello").await;
    assert_eq!(st_boot2_http, 200);
    assert_eq!(body_boot2_http, "rust-clash-node-e2e-ok");

    let _ = api2_stop_tx.send(true);
    engine2.shutdown();
    let _ = srv_stop_tx.send(true);
    let _ = std::fs::remove_dir_all(&state_dir);
}

#[tokio::test]
async fn strict_vless_rejection_and_zero_secret_leak_on_failed_imports_e2e() {
    let state_dir = std::env::temp_dir().join(format!("rc-strict-sec-e2e-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&state_dir).unwrap();

    let (srv_stop_tx, srv_stop_rx) = watch::channel(false);
    let (origin_addr, _) = spawn_origin_http_server(srv_stop_rx.clone()).await;

    let ss_psk = STANDARD.encode([0x77u8; 32]);
    let (ss_addr, _ss_task) = spawn_ss_server(
        "127.0.0.1:0",
        "2022-blake3-aes-256-gcm",
        &ss_psk,
        srv_stop_rx.clone(),
    )
    .await
    .unwrap();

    let ctrl_secret = "strict-ctrl-secret-443322";
    let mgr = ProfileManager::open_or_init(&state_dir).unwrap();
    let (mut cfg, _) = mgr.load_active_config().unwrap();
    cfg.mixed_port = 0;
    cfg.dns.listen = "127.0.0.1:0".into();
    cfg.external_controller = "127.0.0.1:0".into();
    cfg.secret = Some(ctrl_secret.into());

    let engine = ProxyEngine::start_with_state_dir(cfg, state_dir.clone())
        .await
        .unwrap();
    engine.attach_profile_manager(Arc::clone(&mgr));

    let (api_stop_tx, api_stop_rx) = watch::channel(false);
    let (api_addr, _api_task) = spawn_api_server("127.0.0.1:0", Arc::clone(&engine), api_stop_rx)
        .await
        .unwrap();

    // Seed 1 valid working node (`SS-Safe-Active`)
    let valid_userinfo = URL_SAFE_NO_PAD.encode(format!("2022-blake3-aes-256-gcm:{ss_psk}"));
    let seed_link = format!(
        "ss://{valid_userinfo}@127.0.0.1:{}#SS-Safe-Active",
        ss_addr.port()
    );
    let (st_seed, _) = api_request(
        api_addr,
        "POST",
        "/profiles/import",
        Some(ctrl_secret),
        Some(&serde_json::json!({ "uris": seed_link, "apply": true }).to_string()),
    )
    .await;
    assert_eq!(st_seed, 200);

    // Sentinel secrets that MUST NEVER appear in any error message, log, or diagnostic bundle
    let secret_uuid = "11111111-2222-3333-4444-555555555555";
    let secret_pbk = "ULTRA_SECRET_PBK_987654321";
    let secret_pass = "ULTRA_SECRET_PASS_123456789";
    let secret_sub_tok = "ULTRA_SECRET_SUB_TOKEN_555666";
    let forbidden_markers = [
        secret_uuid,
        secret_pbk,
        secret_pass,
        secret_sub_tok,
        &ss_psk,
    ];

    let invalid_import_payloads = vec![
        // VLESS XHTTP (unsupported transport)
        format!("vless://{secret_uuid}@example.com:443?type=xhttp&path=/xhttp#Bad-XHTTP"),
        // VLESS gRPC
        format!("vless://{secret_uuid}@example.com:443?type=grpc&serviceName=gun#Bad-GRPC"),
        // VLESS HTTPUpgrade
        format!("vless://{secret_uuid}@example.com:443?type=httpupgrade#Bad-HTTPUpgrade"),
        // VLESS REALITY + pbk/sid
        format!("vless://{secret_uuid}@example.com:443?security=reality&pbk={secret_pbk}&sid=abcd#Bad-REALITY"),
        // VLESS XTLS Vision flow
        format!("vless://{secret_uuid}@example.com:443?security=tls&flow=xtls-rprx-vision#Bad-Flow"),
        // Base64-encoded unsupported VLESS REALITY link
        STANDARD.encode(format!(
            "vless://{secret_uuid}@example.com:443?security=reality&pbk={secret_pbk}#Bad-B64-Reality"
        )),
        // Clash YAML with unsupported VLESS `reality-opts`
        format!(
            "mixed-port: 7890\nproxies:\n  - name: Bad-YAML-VLESS\n    type: vless\n    server: example.com\n    port: 443\n    uuid: {secret_uuid}\n    network: ws\n    reality-opts:\n      public-key: {secret_pbk}\nproxy-groups:\n  - name: PROXY\n    type: select\n    proxies: [Bad-YAML-VLESS]\nrules:\n  - MATCH,PROXY\n"
        ),
        // Malformed SS link with secret password
        format!("ss://2022-blake3-aes-256-gcm:{secret_pass}@example.com:99999#Bad-Port"),
        // Plain HTTP subscription with secret token (rejected: HTTPS required)
        format!("http://sub.example.com/api/v1/client/subscribe?token={secret_sub_tok}"),
        // Unreachable HTTPS subscription with secret token
        format!("https://127.0.0.1:1/api/v1/client/subscribe?token={secret_sub_tok}"),
    ];

    for bad_input in &invalid_import_payloads {
        let req_body = serde_json::json!({
            "uris": bad_input,
            "apply": true
        })
        .to_string();
        let (st, err_body) = api_request(
            api_addr,
            "POST",
            "/profiles/import",
            Some(ctrl_secret),
            Some(&req_body),
        )
        .await;
        assert!(
            (400..500).contains(&st),
            "invalid payload must fail with 4xx (got {st}): {err_body}"
        );
        for marker in &forbidden_markers {
            assert!(
                !err_body.contains(marker),
                "SECRET LEAKED in /profiles/import error response: marker={marker}, body={err_body}"
            );
        }
    }

    // Also verify `PUT /configs` rejects unsupported VLESS YAML without leaking secrets or breaking live config
    let bad_yaml = format!(
        "mixed-port: 0\nproxies:\n  - name: Bad-WS\n    type: vless\n    server: example.com\n    port: 443\n    uuid: {secret_uuid}\n    network: grpc\nproxy-groups:\n  - name: PROXY\n    type: select\n    proxies: [Bad-WS]\nrules:\n  - MATCH,PROXY\n"
    );
    let (st_put_bad, body_put_bad) = api_request(
        api_addr,
        "PUT",
        "/configs",
        Some(ctrl_secret),
        Some(&serde_json::json!({ "payload": bad_yaml }).to_string()),
    )
    .await;
    assert_eq!(st_put_bad, 400);
    for marker in &forbidden_markers {
        assert!(!body_put_bad.contains(marker));
    }

    // Also verify `POST /profiles/active/nodes` rejects VLESS `flow: xtls-rprx-vision`
    let bad_node_json = serde_json::json!({
        "node": {
            "type": "vless",
            "name": "Bad-Node-Vision",
            "server": "example.com",
            "port": 443,
            "uuid": secret_uuid,
            "encryption": "none",
            "flow": "xtls-rprx-vision",
            "tls": true
        }
    })
    .to_string();
    let (st_node_bad, body_node_bad) = api_request(
        api_addr,
        "POST",
        "/profiles/active/nodes",
        Some(ctrl_secret),
        Some(&bad_node_json),
    )
    .await;
    assert_eq!(st_node_bad, 400);
    for marker in &forbidden_markers {
        assert!(!body_node_bad.contains(marker));
    }

    // Verify `/logs` and `/diagnostics/export` contain ZERO sentinel secrets
    let (_, logs_body) = api_request(api_addr, "GET", "/logs", Some(ctrl_secret), None).await;
    let (_, diag_body) = api_request(
        api_addr,
        "GET",
        "/diagnostics/export",
        Some(ctrl_secret),
        None,
    )
    .await;
    for marker in &forbidden_markers {
        assert!(
            !logs_body.contains(marker),
            "SECRET LEAKED in /logs: {marker}"
        );
        assert!(
            !diag_body.contains(marker),
            "SECRET LEAKED in /diagnostics/export: {marker}"
        );
    }

    // Verify existing `SS-Safe-Active` configuration & live connectivity were NEVER corrupted!
    let (_, proxies_str) = api_request(api_addr, "GET", "/proxies", Some(ctrl_secret), None).await;
    let proxies_json: serde_json::Value = serde_json::from_str(&proxies_str).unwrap();
    assert_eq!(
        proxies_json["effective-outbound"]["effective_outbound"],
        "SS-Safe-Active"
    );
    let (st_http, body_http) =
        http_get_via_mixed_proxy(engine.mixed_addr(), origin_addr.port(), "/hello").await;
    assert_eq!(st_http, 200);
    assert_eq!(body_http, "rust-clash-node-e2e-ok");

    let _ = api_stop_tx.send(true);
    engine.shutdown();
    let _ = srv_stop_tx.send(true);
    let _ = std::fs::remove_dir_all(&state_dir);
}

/// Phase 2 E2E: Live loopback relay verification for `Trojan` (TLS + WS), `VLESS+WS` (`?ed=2048` 0-RTT),
/// `SOCKS5` (RFC 1929 auth), `HTTP CONNECT` (Basic Auth), mixed-subscription sanitization
/// (`skipped-unsupported`), and proxy-assisted HTTPS subscription fetch fallback!
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn trojan_vless_ws_socks5_http_and_mixed_subscription_sanitization_e2e() {
    use proxy_core::{
        crypto::tls::generate_self_signed_server_config,
        outbound::{
            http_proxy::{HttpConnectServerConfig, spawn_http_connect_server},
            socks5::{Socks5ServerConfig, spawn_socks5_server},
            trojan::{TrojanServerConfig, spawn_trojan_server},
            vless::{VlessServerConfig, spawn_vless_ws_server},
        },
        profile::fetch_subscription_http_with_proxy,
    };
    use tokio_rustls::TlsAcceptor;

    let state_dir = std::env::temp_dir().join(format!("rc-phase2-e2e-{}", Uuid::new_v4()));
    let (srv_stop_tx, srv_stop_rx) = watch::channel(false);
    let (origin_addr, _origin_hits) = spawn_origin_http_server(srv_stop_rx.clone()).await;

    // 1. Trojan over TLS + WebSocket (`/trojan-ws`)
    let (trojan_tls, _trojan_ca) = generate_self_signed_server_config(
        &["localhost".into(), "127.0.0.1".into()],
        &[b"http/1.1".to_vec()],
    )
    .unwrap();
    let trojan_pass = "trojan-phase2-secret-pass";
    let (trojan_ws_addr, _t_trojan) = spawn_trojan_server(
        TrojanServerConfig {
            listen_addr: "127.0.0.1:0".into(),
            password: trojan_pass.into(),
            tls_config: Some(trojan_tls),
            ws_path: Some("/trojan-ws".into()),
        },
        srv_stop_rx.clone(),
    )
    .await
    .unwrap();

    // 2. VLESS over WebSocket (`/vless-ws`, supports `?ed=2048` 0-RTT early data)
    let vless_uuid = Uuid::new_v4();
    let (vless_ws_addr, _t_vless_ws) = spawn_vless_ws_server(
        VlessServerConfig {
            listen_addr: "127.0.0.1:0".into(),
            allowed_uuid: vless_uuid,
            decryption: "none".into(),
            tls_config: None,
        },
        "/vless-ws".into(),
        srv_stop_rx.clone(),
    )
    .await
    .unwrap();

    // 3. SOCKS5 with RFC 1929 username/password + UDP ASSOCIATE
    let (socks5_addr, _t_socks5) = spawn_socks5_server(
        Socks5ServerConfig {
            listen_addr: "127.0.0.1:0".into(),
            credentials: Some(("s5user".into(), "s5secret".into())),
        },
        srv_stop_rx.clone(),
    )
    .await
    .unwrap();

    // 4. HTTP CONNECT with Basic Auth
    let (http_proxy_addr, _t_http) = spawn_http_connect_server(
        HttpConnectServerConfig {
            listen_addr: "127.0.0.1:0".into(),
            credentials: Some(("huser".into(), "hsecret".into())),
        },
        srv_stop_rx.clone(),
    )
    .await
    .unwrap();

    // Boot clean starter engine + REST API
    let ctrl_secret = "phase2-ctrl-secret";
    let mgr = ProfileManager::open_or_init(&state_dir).unwrap();
    let (mut cfg, _) = mgr.load_active_config().unwrap();
    cfg.mixed_port = 0;
    cfg.dns.enable = false;
    cfg.secret = Some(ctrl_secret.to_string());

    let engine = ProxyEngine::start_with_state_dir(cfg, state_dir.clone())
        .await
        .unwrap();
    engine.attach_profile_manager(Arc::clone(&mgr));
    let (api_stop_tx, api_stop_rx) = watch::channel(false);
    let (api_addr, _api_task) = spawn_api_server("127.0.0.1:0", Arc::clone(&engine), api_stop_rx)
        .await
        .unwrap();

    // 5. Import a MIXED Base64 subscription containing 4 valid protocols + 2 unsupported links (`vmess://`, `hysteria2://`)!
    let leaked_vmess_secret = "VMESS_SUPER_SECRET_999";
    let leaked_hy2_secret = "HY2_SUPER_SECRET_888";
    let mixed_uris = [
        format!(
            "trojan://{trojan_pass}@127.0.0.1:{}?security=tls&sni=localhost&allowInsecure=1&type=ws&path=%2Ftrojan-ws%3Fed%3D2048&host=cdn.local#Trojan WS 0RTT",
            trojan_ws_addr.port()
        ),
        format!(
            "vless://{vless_uuid}@127.0.0.1:{}?encryption=none&security=none&type=ws&path=%2Fvless-ws%3Fed%3D2048#VLESS WS 0RTT",
            vless_ws_addr.port()
        ),
        format!(
            "socks5://s5user:s5secret@127.0.0.1:{}#SOCKS5 Auth",
            socks5_addr.port()
        ),
        format!(
            "http-proxy://huser:hsecret@127.0.0.1:{}#HTTP Connect",
            http_proxy_addr.port()
        ),
        format!("vmess://{leaked_vmess_secret}@bad.example.com:443#Unsupported VMess"),
        format!("hysteria2://{leaked_hy2_secret}@bad.example.com:443#Unsupported Hy2"),
    ]
    .join("\n");
    let mixed_b64 = STANDARD.encode(&mixed_uris);

    let (st_imp, imp_body) = api_request(
        api_addr,
        "POST",
        "/profiles/import",
        Some(ctrl_secret),
        Some(
            &serde_json::json!({
                "uris": mixed_b64,
                "apply": true,
                "auto_select": true
            })
            .to_string(),
        ),
    )
    .await;
    assert_eq!(st_imp, 200, "mixed subscription must succeed: {imp_body}");
    assert!(!imp_body.contains(leaked_vmess_secret));
    assert!(!imp_body.contains(leaked_hy2_secret));
    let imp_json: serde_json::Value = serde_json::from_str(&imp_body).unwrap();
    assert_eq!(imp_json["count"], 4);
    assert_eq!(imp_json["skipped-unsupported"].as_array().unwrap().len(), 2);

    // 6. Select each of the 4 newly added protocols in `PROXY` and relay real HTTP traffic end-to-end!
    for node_name in [
        "Trojan WS 0RTT",
        "VLESS WS 0RTT",
        "SOCKS5 Auth",
        "HTTP Connect",
    ] {
        let (st_sel, sel_body) = api_request(
            api_addr,
            "PUT",
            "/proxies/PROXY",
            Some(ctrl_secret),
            Some(&serde_json::json!({ "name": node_name }).to_string()),
        )
        .await;
        assert_eq!(st_sel, 204, "select {node_name} failed: {sel_body}");

        let (st_http, body_http) =
            http_get_via_mixed_proxy(engine.mixed_addr(), origin_addr.port(), "/hello").await;
        assert_eq!(st_http, 200, "{node_name} relay HTTP status");
        assert_eq!(
            body_http, "rust-clash-node-e2e-ok",
            "{node_name} relay body"
        );
    }

    // 7. Mixed Clash YAML import: keeps valid Trojan/SOCKS5/HTTP, skips `type: tuic`, prunes group ref!
    let mixed_yaml = format!(
        r#"mixed-port: 0
mode: rule
proxies:
  - name: YAML-SOCKS5
    type: socks5
    server: 127.0.0.1
    port: {}
    username: s5user
    password: s5secret
  - name: YAML-TUIC-Unsupported
    type: tuic
    server: example.com
    port: 443
    token: {leaked_hy2_secret}
proxy-groups:
  - name: PROXY
    type: select
    proxies:
      - YAML-TUIC-Unsupported
      - YAML-SOCKS5
rules:
  - MATCH,PROXY
"#,
        socks5_addr.port()
    );
    let (st_yaml, yaml_body) = api_request(
        api_addr,
        "POST",
        "/profiles/import",
        Some(ctrl_secret),
        Some(&serde_json::json!({ "uris": mixed_yaml, "apply": true }).to_string()),
    )
    .await;
    assert_eq!(
        st_yaml, 200,
        "mixed YAML must sanitize cleanly: {yaml_body}"
    );
    assert!(!yaml_body.contains(leaked_hy2_secret));
    let yaml_json: serde_json::Value = serde_json::from_str(&yaml_body).unwrap();
    assert_eq!(yaml_json["count"], 1);
    assert_eq!(
        yaml_json["skipped-unsupported"].as_array().unwrap().len(),
        1
    );
    let (st_http2, body_http2) =
        http_get_via_mixed_proxy(engine.mixed_addr(), origin_addr.port(), "/hello").await;
    assert_eq!(st_http2, 200);
    assert_eq!(body_http2, "rust-clash-node-e2e-ok");

    // 8. Proxy-assisted HTTPS subscription fetch fallback when direct DNS/TCP fails on non-loopback host!
    // Spin up a local TLS HTTPS server presenting cert for `sub-blocked.invalid`, and a custom proxy
    // outbound that tunnels `sub-blocked.invalid:443` to that local TLS server!
    let (sub_tls, sub_ca) = generate_self_signed_server_config(
        &["sub-blocked.invalid".into()],
        &[b"http/1.1".to_vec()],
    )
    .unwrap();
    let sub_acceptor = TlsAcceptor::from(sub_tls);
    let sub_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let sub_local_addr = sub_listener.local_addr().unwrap();
    tokio::spawn(async move {
        if let Ok((tcp, _)) = sub_listener.accept().await
            && let Ok(mut tls) = sub_acceptor.accept(tcp).await
        {
            let mut buf = [0u8; 1024];
            let _ = tls.read(&mut buf).await;
            let payload = "socks5://s5user:s5secret@127.0.0.1:1080#Fallback-Sub-Node";
            let resp = format!(
                "HTTP/1.1 200 OK\r\nSubscription-Userinfo: upload=100; download=200; total=1000\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                payload.len(),
                payload
            );
            let _ = tls.write_all(resp.as_bytes()).await;
            let _ = tls.shutdown().await;
        }
    });

    // Custom Tunnel Outbound mapping `sub-blocked.invalid` -> `sub_local_addr`
    struct SubTunnelProxy(SocketAddr);
    #[async_trait::async_trait]
    impl proxy_core::outbound::OutboundHandler for SubTunnelProxy {
        fn name(&self) -> &str {
            "SubTunnel"
        }
        fn protocol(&self) -> &'static str {
            "socks5"
        }
        async fn connect_tcp(
            &self,
            _target: &proxy_core::addr::TargetAddr,
        ) -> std::io::Result<proxy_core::outbound::BoxedStream> {
            let s = tokio::net::TcpStream::connect(self.0).await?;
            Ok(Box::new(s))
        }
    }

    // Direct fetch MUST fail (`sub-blocked.invalid` cannot resolve directly), whereas proxy-assisted fetch MUST succeed with end-to-end TLS verification!
    assert!(
        fetch_subscription_http_with_proxy(
            "https://sub-blocked.invalid/api/sub?token=sec",
            std::slice::from_ref(&sub_ca),
            None,
        )
        .await
        .is_err()
    );
    let tunnel_ob: proxy_core::outbound::DynOutbound = Arc::new(SubTunnelProxy(sub_local_addr));
    let (fetched_body, fetched_uinfo) = fetch_subscription_http_with_proxy(
        "https://sub-blocked.invalid/api/sub?token=sec",
        std::slice::from_ref(&sub_ca),
        Some(&tunnel_ob),
    )
    .await
    .unwrap();
    assert!(fetched_body.contains("Fallback-Sub-Node"));
    assert_eq!(fetched_uinfo.unwrap().download_bytes, 200);

    let _ = api_stop_tx.send(true);
    engine.shutdown();
    let _ = srv_stop_tx.send(true);
    let _ = std::fs::remove_dir_all(&state_dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn subscription_manual_node_overlay_auto_update_patch_and_telemetry_api_e2e() {
    use std::sync::atomic::AtomicBool;
    use tokio_rustls::TlsAcceptor;

    let state_dir = std::env::temp_dir().join(format!("rc-sub-overlay-e2e-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&state_dir).unwrap();

    let (srv_stop_tx, srv_stop_rx) = watch::channel(false);
    let (origin_addr, _) = spawn_origin_http_server(srv_stop_rx.clone()).await;

    let ss_remote_psk = STANDARD.encode([0x31u8; 32]);
    let (ss_remote_addr, _ss_remote_task) = spawn_ss_server(
        "127.0.0.1:0",
        "2022-blake3-aes-256-gcm",
        &ss_remote_psk,
        srv_stop_rx.clone(),
    )
    .await
    .unwrap();

    let ss_manual_psk = STANDARD.encode([0x63u8; 32]);
    let (ss_manual_addr, _ss_manual_task) = spawn_ss_server(
        "127.0.0.1:0",
        "2022-blake3-aes-256-gcm",
        &ss_manual_psk,
        srv_stop_rx.clone(),
    )
    .await
    .unwrap();

    // Dynamic TLS 1.3 HTTPS subscription server with `tun.enable: true` in remote YAML
    let (server_tls, ca_der) =
        generate_self_signed_server_config(&["localhost".into(), "127.0.0.1".into()], &[]).unwrap();
    let acceptor = TlsAcceptor::from(server_tls);
    let sub_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let sub_addr = sub_listener.local_addr().unwrap();

    let sub_yaml_v1 = format!(
        r#"mixed-port: 7890
mode: rule
tun:
  enable: true
  stack: system
  auto-route: true
proxies:
  - name: Remote-Node-A
    type: ss
    server: 127.0.0.1
    port: {port}
    cipher: 2022-blake3-aes-256-gcm
    password: "{psk}"
    udp: true
  - name: Remote-Node-B
    type: ss
    server: 127.0.0.1
    port: {port}
    cipher: 2022-blake3-aes-256-gcm
    password: "{psk}"
    udp: true
proxy-groups:
  - name: PROXY
    type: select
    proxies:
      - Remote-Node-A
      - Remote-Node-B
      - DIRECT
rules:
  - MATCH,PROXY
"#,
        port = ss_remote_addr.port(),
        psk = ss_remote_psk,
    );

    let sub_yaml_v2 = format!(
        r#"mixed-port: 7890
mode: rule
tun:
  enable: true
  stack: system
  auto-route: true
proxies:
  - name: Remote-Node-C
    type: ss
    server: 127.0.0.1
    port: {port}
    cipher: 2022-blake3-aes-256-gcm
    password: "{psk}"
    udp: true
proxy-groups:
  - name: PROXY
    type: select
    proxies:
      - Remote-Node-C
      - DIRECT
rules:
  - MATCH,PROXY
"#,
        port = ss_remote_addr.port(),
        psk = ss_remote_psk,
    );

    let served_yaml = Arc::new(parking_lot::Mutex::new(sub_yaml_v1));
    let fail_sub_fetch = Arc::new(AtomicBool::new(false));
    {
        let served_yaml_bg = Arc::clone(&served_yaml);
        let fail_sub_bg = Arc::clone(&fail_sub_fetch);
        let mut stop_bg = srv_stop_rx.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = stop_bg.changed() => break,
                    acc_res = sub_listener.accept() => {
                        let Ok((tcp, _)) = acc_res else { break };
                        let acc = acceptor.clone();
                        let body = served_yaml_bg.lock().clone();
                        let should_fail = fail_sub_bg.load(Ordering::Acquire);
                        tokio::spawn(async move {
                            if let Ok(mut tls) = acc.accept(tcp).await {
                                let mut buf = [0u8; 2048];
                                let _ = tls.read(&mut buf).await;
                                let resp = if should_fail {
                                    "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 13\r\nConnection: close\r\n\r\nupstream down".to_string()
                                } else {
                                    format!(
                                        "HTTP/1.1 200 OK\r\nContent-Type: text/yaml\r\nSubscription-Userinfo: upload=1024; download=2048; total=10485760\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                        body.len(),
                                        body
                                    )
                                };
                                let _ = tls.write_all(resp.as_bytes()).await;
                                let _ = tls.shutdown().await;
                            }
                        });
                    }
                }
            }
        });
    }

    let ctrl_secret = "overlay-ctrl-secret-224466";
    let mgr = ProfileManager::open_or_init_with_ca(&state_dir, vec![ca_der]).unwrap();
    let (mut boot_cfg, _) = mgr.load_active_config().unwrap();
    boot_cfg.mixed_port = 0;
    boot_cfg.dns.listen = "127.0.0.1:0".into();
    boot_cfg.external_controller = "127.0.0.1:0".into();
    boot_cfg.secret = Some(ctrl_secret.into());

    let engine = ProxyEngine::start_with_state_dir(boot_cfg, state_dir.clone())
        .await
        .unwrap();
    engine.attach_profile_manager(Arc::clone(&mgr));

    let (api_stop_tx, api_stop_rx) = watch::channel(false);
    let (api_addr, _api_task) = spawn_api_server("127.0.0.1:0", Arc::clone(&engine), api_stop_rx)
        .await
        .unwrap();

    // 1. Import HTTPS subscription via `POST /profiles/import` with custom `auto_update_interval_secs: 7200`
    let sub_secret_tok = "SUB_SECRET_TOKEN_889900";
    let sub_url = format!(
        "https://localhost:{}/api/v1/subscribe?token={sub_secret_tok}",
        sub_addr.port()
    );
    let (st_sub_imp, body_sub_imp) = api_request(
        api_addr,
        "POST",
        "/profiles/import",
        Some(ctrl_secret),
        Some(
            &serde_json::json!({
                "uris": sub_url,
                "apply": true,
                "auto_update_interval_secs": 7200
            })
            .to_string(),
        ),
    )
    .await;
    assert_eq!(
        st_sub_imp, 200,
        "HTTPS subscription import failed: {body_sub_imp}"
    );
    let sub_imp_json: serde_json::Value = serde_json::from_str(&body_sub_imp).unwrap();
    let sub_id = sub_imp_json["active-profile-id"]
        .as_str()
        .expect("active-profile-id in import response")
        .to_string();
    assert_eq!(sub_imp_json["total-nodes"], 2);

    // Verify imported `tun.enable: true` from external subscription YAML was sanitized to `false` on disk!
    let (disk_cfg_v1, _) = mgr.load_active_config().unwrap();
    assert!(
        !disk_cfg_v1.tun.enable,
        "imported external subscription YAML must sanitize tun.enable to false on disk"
    );

    let (_, profiles_init_str) =
        api_request(api_addr, "GET", "/profiles", Some(ctrl_secret), None).await;
    let profiles_init_json: serde_json::Value = serde_json::from_str(&profiles_init_str).unwrap();
    let sub_meta_init = profiles_init_json["profiles"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["id"] == sub_id)
        .unwrap();
    assert_eq!(sub_meta_init["auto_update_interval_secs"], 7200);
    assert_eq!(sub_meta_init["manual_proxy_count"], 0);
    assert_eq!(sub_meta_init["group_count"], 1);
    let initial_sub_updated_ms = sub_meta_init["last_updated_ms"].as_u64().unwrap();

    // 2. Add 2 manual nodes on top of the active subscription (1 via share URI, 1 via POST /profiles/active/nodes)
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    let manual_userinfo =
        URL_SAFE_NO_PAD.encode(format!("2022-blake3-aes-256-gcm:{ss_manual_psk}"));
    let manual_ss_uri = format!(
        "ss://{manual_userinfo}@127.0.0.1:{}#Manual-SS-Custom",
        ss_manual_addr.port()
    );
    let (st_add_uri, body_add_uri) = api_request(
        api_addr,
        "POST",
        "/profiles/import",
        Some(ctrl_secret),
        Some(
            &serde_json::json!({
                "uris": manual_ss_uri,
                "apply": true,
                "auto_select": true
            })
            .to_string(),
        ),
    )
    .await;
    assert_eq!(st_add_uri, 200, "manual URI import failed: {body_add_uri}");

    let socks_manual_pass = "SOCKS_MANUAL_PASS_445566";
    let (st_add_form, body_add_form) = api_request(
        api_addr,
        "POST",
        "/profiles/active/nodes",
        Some(ctrl_secret),
        Some(
            &serde_json::json!({
                "node": {
                    "type": "socks5",
                    "name": "Manual-SOCKS5-Custom",
                    "server": "127.0.0.1",
                    "port": 10808,
                    "username": "muser",
                    "password": socks_manual_pass,
                    "udp": true
                },
                "auto_select": false
            })
            .to_string(),
        ),
    )
    .await;
    assert_eq!(
        st_add_form, 200,
        "manual node create failed: {body_add_form}"
    );

    // Select `Manual-SS-Custom` in `PROXY` and verify live HTTP relay works
    let (st_sel_man, _) = api_request(
        api_addr,
        "PUT",
        "/proxies/PROXY",
        Some(ctrl_secret),
        Some(r#"{"name":"Manual-SS-Custom"}"#),
    )
    .await;
    assert_eq!(st_sel_man, 204);

    let (st_http_man1, body_http_man1) =
        http_get_via_mixed_proxy(engine.mixed_addr(), origin_addr.port(), "/hello").await;
    assert_eq!(st_http_man1, 200);
    assert_eq!(body_http_man1, "rust-clash-node-e2e-ok");

    // Verify manual node additions updated `manual_proxy_count == 2` WITHOUT skewing subscription `last_updated_ms`!
    let (_, profiles_after_manual_str) =
        api_request(api_addr, "GET", "/profiles", Some(ctrl_secret), None).await;
    let profiles_after_manual: serde_json::Value =
        serde_json::from_str(&profiles_after_manual_str).unwrap();
    let sub_meta_after_manual = profiles_after_manual["profiles"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["id"] == sub_id)
        .unwrap();
    assert_eq!(sub_meta_after_manual["manual_proxy_count"], 2);
    assert_eq!(sub_meta_after_manual["proxy_count"], 4);
    assert_eq!(
        sub_meta_after_manual["last_updated_ms"].as_u64().unwrap(),
        initial_sub_updated_ms,
        "manual node edits must NOT overwrite subscription last_updated_ms"
    );

    // 3. Remote subscription updates from v1 (`Remote-Node-A`, `Remote-Node-B`) -> v2 (`Remote-Node-C`).
    //    Trigger `POST /profiles/{sub_id}/refresh` and verify manual nodes + `Manual-SS-Custom` selection survive!
    *served_yaml.lock() = sub_yaml_v2;
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    let (st_ref1, body_ref1) = api_request(
        api_addr,
        "POST",
        &format!("/profiles/{sub_id}/refresh"),
        Some(ctrl_secret),
        Some("{}"),
    )
    .await;
    assert_eq!(st_ref1, 200, "subscription refresh #1 failed: {body_ref1}");
    let ref1_json: serde_json::Value = serde_json::from_str(&body_ref1).unwrap();
    assert_eq!(ref1_json["profile"]["manual_proxy_count"], 2);
    assert_eq!(
        ref1_json["profile"]["proxy_count"], 3,
        "expected Remote-Node-C + 2 preserved manual nodes"
    );
    assert!(ref1_json["profile"]["last_updated_ms"].as_u64().unwrap() >= initial_sub_updated_ms);

    let (disk_cfg_v2, _) = mgr.load_active_config().unwrap();
    assert!(
        !disk_cfg_v2.tun.enable,
        "refreshed subscription YAML must also sanitize tun.enable to false"
    );
    let disk_names: Vec<&str> = disk_cfg_v2.proxies.iter().map(|p| p.name()).collect();
    assert!(disk_names.contains(&"Remote-Node-C"));
    assert!(!disk_names.contains(&"Remote-Node-A"));
    assert!(disk_names.contains(&"Manual-SS-Custom"));
    assert!(disk_names.contains(&"Manual-SOCKS5-Custom"));

    // Verify `PROXY` group STILL has `Manual-SS-Custom` selected and live traffic still flows!
    let (_, proxies_after_ref1_str) =
        api_request(api_addr, "GET", "/proxies", Some(ctrl_secret), None).await;
    let proxies_after_ref1: serde_json::Value =
        serde_json::from_str(&proxies_after_ref1_str).unwrap();
    assert_eq!(
        proxies_after_ref1["proxies"]["PROXY"]["now"], "Manual-SS-Custom",
        "manual node selection in PROXY must be 100% preserved across subscription refresh"
    );
    assert_eq!(
        proxies_after_ref1["effective-outbound"]["effective_outbound"],
        "Manual-SS-Custom"
    );
    let (st_http_man2, body_http_man2) =
        http_get_via_mixed_proxy(engine.mixed_addr(), origin_addr.port(), "/hello").await;
    assert_eq!(st_http_man2, 200);
    assert_eq!(body_http_man2, "rust-clash-node-e2e-ok");

    // 4. Delete `Manual-SOCKS5-Custom`, then refresh subscription again -> deleted manual node MUST NOT resurrect!
    let (st_del_man, body_del_man) = api_request(
        api_addr,
        "DELETE",
        "/profiles/active/nodes/Manual-SOCKS5-Custom",
        Some(ctrl_secret),
        None,
    )
    .await;
    assert_eq!(st_del_man, 200, "delete manual node failed: {body_del_man}");

    let (st_ref2, body_ref2) = api_request(
        api_addr,
        "POST",
        &format!("/profiles/{sub_id}/refresh"),
        Some(ctrl_secret),
        Some("{}"),
    )
    .await;
    assert_eq!(st_ref2, 200, "subscription refresh #2 failed: {body_ref2}");
    let ref2_json: serde_json::Value = serde_json::from_str(&body_ref2).unwrap();
    assert_eq!(ref2_json["profile"]["manual_proxy_count"], 1);
    assert_eq!(ref2_json["profile"]["proxy_count"], 2);
    let (disk_cfg_v3, _) = mgr.load_active_config().unwrap();
    let disk_names_v3: Vec<&str> = disk_cfg_v3.proxies.iter().map(|p| p.name()).collect();
    assert!(disk_names_v3.contains(&"Remote-Node-C"));
    assert!(disk_names_v3.contains(&"Manual-SS-Custom"));
    assert!(
        !disk_names_v3.contains(&"Manual-SOCKS5-Custom"),
        "deleted manual node must NOT resurrect on subsequent subscription refresh"
    );

    // 5. Test `PATCH /profiles/{id}` (rename + disable auto-update `0`/`null` + clamp `< 60` -> `60`) & failure backoff
    let (st_patch_off, body_patch_off) = api_request(
        api_addr,
        "PATCH",
        &format!("/profiles/{sub_id}"),
        Some(ctrl_secret),
        Some(r#"{"name":"主力订阅-保护测试","auto_update_interval_secs":0}"#),
    )
    .await;
    assert_eq!(st_patch_off, 200, "PATCH disable failed: {body_patch_off}");
    let patch_off_json: serde_json::Value = serde_json::from_str(&body_patch_off).unwrap();
    assert_eq!(patch_off_json["profile"]["name"], "主力订阅-保护测试");
    assert!(patch_off_json["profile"]["auto_update_interval_secs"].is_null());
    assert!(mgr.due_auto_update_ids().is_empty());

    let (st_patch_clamp, body_patch_clamp) = api_request(
        api_addr,
        "PATCH",
        &format!("/profiles/{sub_id}"),
        Some(ctrl_secret),
        Some(r#"{"auto_update_interval_secs":15}"#),
    )
    .await;
    assert_eq!(
        st_patch_clamp, 200,
        "PATCH clamp failed: {body_patch_clamp}"
    );
    let patch_clamp_json: serde_json::Value = serde_json::from_str(&body_patch_clamp).unwrap();
    assert_eq!(patch_clamp_json["profile"]["auto_update_interval_secs"], 60);

    // Simulate failed refresh and verify `due_auto_update_ids()` enforces 10-minute backoff
    fail_sub_fetch.store(true, Ordering::Release);
    assert!(mgr.refresh_subscription(&sub_id).await.is_err());
    assert!(
        mgr.due_auto_update_ids().is_empty(),
        "failed subscription refresh must enter 10-minute backoff and not immediately re-trigger"
    );
    fail_sub_fetch.store(false, Ordering::Release);

    // 6. Verify enriched telemetry & exit IP endpoints (`GET /configs`, `/connections`, `/dns/fakeip`, `/tools/ip`)
    let (st_cfgs, body_cfgs) =
        api_request(api_addr, "GET", "/configs", Some(ctrl_secret), None).await;
    assert_eq!(st_cfgs, 200);
    let cfgs_json: serde_json::Value = serde_json::from_str(&body_cfgs).unwrap();
    assert!(cfgs_json["started-at-ms"].as_u64().unwrap() > 0);
    assert!(cfgs_json["uptime-secs"].is_u64());
    assert_eq!(cfgs_json["proxy-count"], 2);
    assert_eq!(cfgs_json["group-count"], 1);
    assert!(cfgs_json["rule-count"].as_u64().unwrap() >= 1);
    assert!(cfgs_json["dns"]["total-queries"].is_u64());

    let (st_conns, body_conns) =
        api_request(api_addr, "GET", "/connections", Some(ctrl_secret), None).await;
    assert_eq!(st_conns, 200);
    let conns_json: serde_json::Value = serde_json::from_str(&body_conns).unwrap();
    assert!(conns_json["totalConnections"].as_u64().unwrap() >= 1);

    let (st_fip, body_fip) =
        api_request(api_addr, "GET", "/dns/fakeip", Some(ctrl_secret), None).await;
    assert_eq!(st_fip, 200);
    let fip_json: serde_json::Value = serde_json::from_str(&body_fip).unwrap();
    assert!(fip_json["total_queries"].is_u64());

    let (st_ip, body_ip) = api_request(api_addr, "GET", "/tools/ip", Some(ctrl_secret), None).await;
    assert_eq!(st_ip, 200, "GET /tools/ip must always return 200 JSON");
    let ip_json: serde_json::Value = serde_json::from_str(&body_ip).unwrap();
    assert!(ip_json["ok"].is_boolean());
    assert!(ip_json["ip"].is_string());
    assert!(ip_json["country"].is_string());
    assert!(ip_json["isp"].is_string());
    assert!(ip_json["ip_type"].is_string());
    assert_eq!(ip_json["outbound"], "Manual-SS-Custom");
    assert!(ip_json["checked_at_ms"].as_u64().unwrap() > 0);

    // 7. Strict secret redaction audit across `/profiles`, `/logs`, `/diagnostics/export`, and `profiles_index.json`
    let (_, profs_final_body) =
        api_request(api_addr, "GET", "/profiles", Some(ctrl_secret), None).await;
    let (_, diag_final_body) = api_request(
        api_addr,
        "GET",
        "/diagnostics/export",
        Some(ctrl_secret),
        None,
    )
    .await;
    let index_raw = std::fs::read_to_string(state_dir.join("profiles").join("profiles_index.json"))
        .expect("read profiles_index.json");
    for secret_marker in [
        sub_secret_tok,
        ss_remote_psk.as_str(),
        ss_manual_psk.as_str(),
        socks_manual_pass,
    ] {
        assert!(
            !profs_final_body.contains(secret_marker),
            "SECRET LEAKED in GET /profiles: {secret_marker}"
        );
        assert!(
            !diag_final_body.contains(secret_marker),
            "SECRET LEAKED in GET /diagnostics/export: {secret_marker}"
        );
        assert!(
            !index_raw.contains(secret_marker),
            "SECRET LEAKED in profiles_index.json: {secret_marker}"
        );
    }

    let _ = api_stop_tx.send(true);
    engine.shutdown();
    let _ = srv_stop_tx.send(true);
    let _ = std::fs::remove_dir_all(&state_dir);
}

use std::{net::SocketAddr, sync::Arc};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use proxy_core::{
    api::spawn_api_server,
    config::{ProxyGroupConfig, ProxyGroupType, ProxyNodeConfig, RunMode},
    crypto::tls::generate_self_signed_server_config,
    engine::ProxyEngine,
    profile::ProfileManager,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::watch,
};
use tokio_rustls::TlsAcceptor;
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

#[tokio::test]
async fn real_user_mode_profiles_demo_toggle_and_zero_leak_diagnostics_e2e() {
    let tmp_dir = std::env::temp_dir().join(format!("rc-m5-e2e-{}", Uuid::new_v4()));
    let autostart_dir = tmp_dir.join("autostart");
    std::fs::create_dir_all(&autostart_dir).unwrap();

    // 1. Spin up a real TLS 1.3 subscription server with a sensitive query token & Subscription-Userinfo
    let (server_tls, ca_der) =
        generate_self_signed_server_config(&["localhost".into(), "127.0.0.1".into()], &[]).unwrap();
    let acceptor = TlsAcceptor::from(server_tls);
    let sub_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let sub_addr = sub_listener.local_addr().unwrap();

    let raw_ss_psk = STANDARD.encode([0x5au8; 32]);
    let raw_vless_uuid = Uuid::new_v4();
    let sub_uris = format!(
        "ss://{}@127.0.0.1:18388#M5-SS2022\nvless://{}@127.0.0.1:18443?security=none#M5-VLESS",
        STANDARD.encode(format!("2022-blake3-aes-256-gcm:{raw_ss_psk}")),
        raw_vless_uuid
    );
    let sub_b64 = STANDARD.encode(&sub_uris);

    tokio::spawn(async move {
        while let Ok((tcp, _)) = sub_listener.accept().await {
            let acc = acceptor.clone();
            let payload = sub_b64.clone();
            tokio::spawn(async move {
                if let Ok(mut tls) = acc.accept(tcp).await {
                    let mut buf = [0u8; 2048];
                    let _ = tls.read(&mut buf).await;
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nSubscription-Userinfo: upload=4096; download=16384; total=1073741824; expire=1999999999\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        payload.len(),
                        payload
                    );
                    let _ = tls.write_all(resp.as_bytes()).await;
                    let _ = tls.shutdown().await;
                }
            });
        }
    });

    // 2. Start ProxyEngine in Real User Mode with controller secret & Mixed authentication
    let mgr = ProfileManager::open_or_init_with_ca(&tmp_dir, vec![ca_der]).unwrap();
    let (mut starter_cfg, _) = mgr.load_active_config().unwrap();
    starter_cfg.mixed_port = 0;
    starter_cfg.dns.listen = "127.0.0.1:0".into();
    starter_cfg.external_controller = "127.0.0.1:0".into();
    let ctrl_secret = "ctrl-secret-super-998877";
    let mix_pass = "mix-pass-ultra-665544";
    starter_cfg.secret = Some(ctrl_secret.to_string());
    starter_cfg.authentication = vec![format!("alice:{mix_pass}")];
    starter_cfg.proxies = vec![ProxyNodeConfig::Ss {
        name: "Initial-SS".into(),
        server: "127.0.0.1".into(),
        port: 19999,
        cipher: "chacha20-ietf-poly1305".into(),
        password: "init-node-secret-554433".into(),
        udp: true,
    }];
    starter_cfg.proxy_groups = vec![ProxyGroupConfig {
        name: "PROXY".into(),
        group_type: ProxyGroupType::Select,
        proxies: vec!["Initial-SS".into(), "DIRECT".into()],
        url: String::new(),
        interval: 300,
        tolerance: 50,
        strategy: None,
    }];
    starter_cfg.mode = RunMode::Rule;
    starter_cfg.rules = vec!["MATCH,DIRECT".into()];

    let engine = ProxyEngine::start_with_state_dir(starter_cfg, tmp_dir.clone())
        .await
        .expect("start Real User Mode engine");
    engine.attach_profile_manager(Arc::clone(&mgr));

    let (stop_tx, stop_rx) = watch::channel(false);
    let (api_addr, _api_task) = spawn_api_server("127.0.0.1:0", Arc::clone(&engine), stop_rx)
        .await
        .expect("spawn API server");

    // Unauthenticated call to /profiles must be rejected (401)
    let (st_unauth, _) = api_request(api_addr, "GET", "/profiles", None, None).await;
    assert_eq!(st_unauth, 401);

    // 3. Create & activate HTTPS subscription profile via POST /profiles
    let sub_token = "sub-secret-token-112233";
    let create_body = serde_json::json!({
        "name": "Production HTTPS Sub",
        "subscription_url": format!("https://localhost:{}/api/v1/sub?token={sub_token}", sub_addr.port()),
        "auto_update_interval_secs": 3600,
        "activate": true
    })
    .to_string();
    let (st_create, body_create) = api_request(
        api_addr,
        "POST",
        "/profiles",
        Some(ctrl_secret),
        Some(&create_body),
    )
    .await;
    assert_eq!(st_create, 201, "create profile failed: {body_create}");
    let created_json: serde_json::Value = serde_json::from_str(&body_create).unwrap();
    let prof_id = created_json["profile"]["id"].as_str().unwrap().to_string();
    assert_eq!(created_json["profile"]["proxy_count"], 2);
    assert_eq!(
        created_json["snapshot"]["onboarding_completed"], true,
        "onboarding must mark completed once real nodes are imported"
    );

    // Refresh subscription via POST /profiles/{id}/refresh
    let (st_ref, body_ref) = api_request(
        api_addr,
        "POST",
        &format!("/profiles/{prof_id}/refresh"),
        Some(ctrl_secret),
        Some("{}"),
    )
    .await;
    assert_eq!(st_ref, 200, "refresh failed: {body_ref}");

    // 4. Switch into Demo Sandbox via POST /demo/toggle and back to Real User Mode seamlessly!
    let (st_demo_on, body_demo_on) = api_request(
        api_addr,
        "POST",
        "/demo/toggle",
        Some(ctrl_secret),
        Some(r#"{"enable":true}"#),
    )
    .await;
    assert_eq!(st_demo_on, 200, "demo on failed: {body_demo_on}");
    assert!(engine.demo_info().enabled);

    let (st_demo_off, body_demo_off) = api_request(
        api_addr,
        "POST",
        "/demo/toggle",
        Some(ctrl_secret),
        Some(r#"{"enable":false}"#),
    )
    .await;
    assert_eq!(st_demo_off, 200, "demo off failed: {body_demo_off}");
    assert!(!engine.demo_info().enabled);
    assert_eq!(
        engine.config_snapshot().proxies.len(),
        2,
        "exiting Demo Sandbox must restore active user profile nodes"
    );

    // 5. Inject a freeform log containing raw credentials & subscription URL, then verify GET /diagnostics/export redacts 100%!
    engine.hub().push_log(
        "warn",
        format!(
            "Simulated error fetching https://localhost:{}/api/v1/sub?token={sub_token} with {raw_ss_psk}",
            sub_addr.port()
        ),
    );
    let (st_diag, body_diag) = api_request(
        api_addr,
        "GET",
        "/diagnostics/export",
        Some(ctrl_secret),
        None,
    )
    .await;
    assert_eq!(st_diag, 200);
    for forbidden in [
        ctrl_secret,
        mix_pass,
        sub_token,
        &raw_ss_psk,
        &raw_vless_uuid.to_string(),
    ] {
        assert!(
            !body_diag.contains(forbidden),
            "SECURITY VIOLATION: diagnostic export leaked sensitive token '{forbidden}'!\nPayload:\n{body_diag}"
        );
    }
    let diag_json: serde_json::Value = serde_json::from_str(&body_diag).unwrap();
    assert_eq!(diag_json["product"], "rust-clash");
    assert!(diag_json["tun_health"]["platform"].is_string());
    assert!(diag_json["sysproxy"]["backend"].is_string());

    // 6. Activate starter profile so we can delete the created subscription profile cleanly
    let (st_act, _) = api_request(
        api_addr,
        "PUT",
        "/profiles/starter-default/activate",
        Some(ctrl_secret),
        Some("{}"),
    )
    .await;
    assert_eq!(st_act, 200);
    let (st_del, _) = api_request(
        api_addr,
        "DELETE",
        &format!("/profiles/{prof_id}"),
        Some(ctrl_secret),
        None,
    )
    .await;
    assert_eq!(st_del, 200);

    let _ = stop_tx.send(true);
    engine.shutdown();
    let _ = std::fs::remove_dir_all(&tmp_dir);
}

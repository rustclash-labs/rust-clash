use std::{
    collections::{HashMap, VecDeque},
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use base64::{Engine, engine::general_purpose::STANDARD};
use parking_lot::RwLock;
use proxy_core::{
    addr::TargetAddr,
    api::spawn_api_server,
    config::{ClashConfig, DnsConfig, RunMode},
    dns::{
        FakeIpDnsEngine,
        wire::{DnsAnswerData, DnsQueryPacket, QTYPE_A, build_dns_query, extract_ip_answers},
    },
    engine::ProxyEngine,
    inbound::{
        mixed::{MixedInboundPolicy, spawn_mixed_inbound_with_policy},
        tun::{build_ipv4_udp_packet, build_ipv6_udp_packet, spawn_userspace_tun},
    },
    outbound::{
        DynOutbound,
        ss::{ShadowsocksOutbound, spawn_ss_server},
    },
    router::Router,
    tracker::TelemetryHub,
};
use smoltcp::{
    iface::{Config as IfaceConfig, Interface, SocketSet},
    phy::{ChecksumCapabilities, Device, DeviceCapabilities, Medium, RxToken, TxToken},
    socket::tcp,
    time::Instant as SmolInstant,
    wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint, Ipv4Packet, Ipv6Packet, UdpPacket},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::watch,
};

async fn raw_http_with_headers(
    addr: SocketAddr,
    method: &str,
    path: &str,
    host_header: &str,
    extra_headers: &[(&str, &str)],
    body: Option<&str>,
) -> (u16, String, String) {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let payload = body.unwrap_or("");
    let mut hdrs = String::new();
    for (k, v) in extra_headers {
        hdrs.push_str(&format!("{k}: {v}\r\n"));
    }
    if body.is_some() {
        hdrs.push_str(&format!(
            "Content-Type: application/json\r\nContent-Length: {}\r\n",
            payload.len()
        ));
    }
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: {host_header}\r\n{hdrs}Connection: close\r\n\r\n{payload}"
    );
    stream.write_all(req.as_bytes()).await.unwrap();
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await.unwrap();
    let text = String::from_utf8_lossy(&raw).into_owned();
    let (hdr_part, body_part) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let code = hdr_part
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    (code, hdr_part.to_string(), body_part.to_string())
}

#[tokio::test]
async fn routing_safety_rejects_cycles_unknown_targets_and_never_falls_back_to_direct() {
    // 1. Unknown group member must fail config validation
    let bad_member_yaml = r#"
mode: rule
proxy-groups:
  - name: BadGroup
    type: select
    proxies: [GhostNode]
rules:
  - MATCH,BadGroup
"#;
    assert!(
        ClashConfig::from_yaml_str(bad_member_yaml).is_err(),
        "unknown group member must be rejected"
    );

    // 2. Mutual proxy-group cycle (`GroupA -> GroupB -> GroupA`) must fail config validation
    let cycle_yaml = r#"
mode: rule
proxy-groups:
  - name: GroupA
    type: select
    proxies: [GroupB]
  - name: GroupB
    type: url-test
    proxies: [GroupA]
rules:
  - MATCH,GroupA
"#;
    let err_msg = ClashConfig::from_yaml_str(cycle_yaml)
        .unwrap_err()
        .to_string();
    assert!(
        err_msg.contains("cyclic proxy-group"),
        "expected cycle error, got: {err_msg}"
    );

    // 3. Unknown rule target and unknown GEOIP country code must fail config validation
    let bad_rule_yaml = r#"
mode: rule
rules:
  - DOMAIN,example.com,NonExistentOutbound
"#;
    assert!(ClashConfig::from_yaml_str(bad_rule_yaml).is_err());

    let bad_geoip_yaml = r#"
mode: rule
rules:
  - GEOIP,ATLANTIS,DIRECT
"#;
    assert!(ClashConfig::from_yaml_str(bad_geoip_yaml).is_err());

    // 4. `Router::resolve_chain` on unknown target MUST return `ROUTING-ERROR` (`PermissionDenied`), NEVER `DIRECT`!
    let dns = Arc::new(FakeIpDnsEngine::new(&DnsConfig::default()).unwrap());
    let rules = vec!["DOMAIN,allowed.example.com,DIRECT".to_string()];
    let router = Router::new(RunMode::Rule, HashMap::new(), &[], &rules, dns).unwrap();

    let probe_target = TargetAddr::new_domain("example.com", 443).unwrap();
    let (unknown_ob, chain) = router.resolve_chain("NON_EXISTENT_OUTBOUND", &probe_target);
    assert_eq!(unknown_ob.name(), "ROUTING-ERROR");
    assert_ne!(unknown_ob.protocol(), "Direct");
    assert!(chain.iter().any(|c| c == "ROUTING-ERROR"));
    let conn_err = match unknown_ob.connect_tcp(&probe_target).await {
        Ok(_) => panic!("unknown outbound must fail closed"),
        Err(e) => e,
    };
    assert_eq!(conn_err.kind(), io::ErrorKind::PermissionDenied);

    // 5. Unmatched traffic in `Rule` mode without a `MATCH` rule MUST fail closed to `REJECT`,
    //    never silently connecting directly to a live TCP target!
    let (hit_counter, target_listener) = (
        Arc::new(AtomicUsize::new(0)),
        TcpListener::bind("127.0.0.1:0").await.unwrap(),
    );
    let target_addr = target_listener.local_addr().unwrap();
    let hit_clone = Arc::clone(&hit_counter);
    tokio::spawn(async move {
        if target_listener.accept().await.is_ok() {
            hit_clone.fetch_add(1, Ordering::SeqCst);
        }
    });

    let decision = router
        .route_async(None, &TargetAddr::from(target_addr))
        .await;
    assert_eq!(decision.outbound.name(), "REJECT");
    let err = match decision
        .outbound
        .connect_tcp(&TargetAddr::from(target_addr))
        .await
    {
        Ok(_) => panic!("unmatched Rule-mode traffic must be rejected, not connected"),
        Err(e) => e,
    };
    assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert_eq!(
        hit_counter.load(Ordering::SeqCst),
        0,
        "target server must NEVER receive a direct connection when no rule matched"
    );
}

#[tokio::test]
async fn control_api_csrf_dns_rebinding_secret_ws_auth_and_redaction() {
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
    let valid_host = api_addr.to_string();

    // 1. DNS Rebinding protection: untrusted `Host` header rejected with 403 even on `/` and `/configs`
    let (code, _, _) = raw_http_with_headers(
        api_addr,
        "GET",
        "/configs",
        "evil.rebind.attacker:9090",
        &[],
        None,
    )
    .await;
    assert_eq!(code, 403, "DNS rebinding Host header must be blocked");

    // 2. Malicious remote website (`Origin: https://evil.example`) and unauthorized local app on another port
    //    (`Origin: http://localhost:3000`) MUST be blocked with 403 and receive NO CORS allow header!
    for untrusted_origin in [
        "https://evil.example",
        "http://localhost:3000",
        "http://127.0.0.1:8080",
        "null",
    ] {
        let (code, hdrs, _) = raw_http_with_headers(
            api_addr,
            "GET",
            "/configs",
            &valid_host,
            &[("Origin", untrusted_origin)],
            None,
        )
        .await;
        assert_eq!(
            code, 403,
            "untrusted Origin {untrusted_origin} must be rejected"
        );
        assert!(
            !hdrs
                .to_ascii_lowercase()
                .contains("access-control-allow-origin"),
            "must not emit CORS allow header for {untrusted_origin}"
        );

        let (opt_code, opt_hdrs, _) = raw_http_with_headers(
            api_addr,
            "OPTIONS",
            "/configs",
            &valid_host,
            &[
                ("Origin", untrusted_origin),
                ("Access-Control-Request-Method", "PATCH"),
            ],
            None,
        )
        .await;
        assert_eq!(opt_code, 403);
        assert!(
            !opt_hdrs
                .to_ascii_lowercase()
                .contains("access-control-allow-origin")
        );
    }

    // 3. Cross-port / cross-site browser simple GET without `Origin` (`Sec-Fetch-Site: same-site` / `cross-site`) -> 403
    for bad_sfs in ["cross-site", "same-site"] {
        let (code, _, _) = raw_http_with_headers(
            api_addr,
            "GET",
            "/proxies",
            &valid_host,
            &[("Sec-Fetch-Site", bad_sfs)],
            None,
        )
        .await;
        assert_eq!(
            code, 403,
            "Sec-Fetch-Site={bad_sfs} without trusted Origin must be blocked"
        );
    }

    // 4. Legitimate Web Console (`http://127.0.0.1:<api_port>`) and Tauri Desktop (`tauri://localhost`, `http://tauri.localhost`) succeed!
    let same_origin = format!("http://127.0.0.1:{}", api_addr.port());
    for trusted_origin in [
        same_origin.as_str(),
        "tauri://localhost",
        "http://tauri.localhost",
    ] {
        let (code, hdrs, _) = raw_http_with_headers(
            api_addr,
            "GET",
            "/version",
            &valid_host,
            &[("Origin", trusted_origin), ("Sec-Fetch-Site", "cross-site")],
            None,
        )
        .await;
        assert_eq!(
            code, 200,
            "trusted UI origin {trusted_origin} must remain functional"
        );
        assert!(hdrs.to_ascii_lowercase().contains(&format!(
            "access-control-allow-origin: {}",
            trusted_origin.to_ascii_lowercase()
        )));
    }

    // 5. Arbitrary file read via `PUT /configs {"path": "/etc/hosts"}` MUST be rejected with 403 Forbidden!
    let (code, _, body) = raw_http_with_headers(
        api_addr,
        "PUT",
        "/configs",
        &valid_host,
        &[],
        Some(r#"{"path":"/etc/hosts"}"#),
    )
    .await;
    assert_eq!(
        code, 403,
        "PUT /configs with arbitrary path must return 403, got {code}: {body}"
    );

    // 6. `GET /configs/raw` redacts credentials by default AND roundtrips safely through `PUT /configs`!
    let (code, _, raw_body) =
        raw_http_with_headers(api_addr, "GET", "/configs/raw", &valid_host, &[], None).await;
    assert_eq!(code, 200);
    let raw_json: serde_json::Value = serde_json::from_str(&raw_body).unwrap();
    let redacted_yaml = raw_json["yaml"].as_str().unwrap();
    assert_eq!(raw_json["redacted"], true);
    assert!(redacted_yaml.contains("***REDACTED***"));
    assert!(
        !redacted_yaml.contains("anytls-v2-flagship-key")
            && !redacted_yaml.contains("rust-clash-chacha-secret-2026"),
        "cleartext proxy passwords must NEVER appear in redacted /configs/raw"
    );

    // Hot-reload that redacted YAML and verify proxy delay probe still works (credentials preserved!)
    let reload_req = serde_json::json!({ "payload": redacted_yaml }).to_string();
    let (code, _, err_txt) = raw_http_with_headers(
        api_addr,
        "PUT",
        "/configs",
        &valid_host,
        &[],
        Some(&reload_req),
    )
    .await;
    assert_eq!(
        code, 204,
        "hot-reload of redacted YAML must succeed: {err_txt}"
    );

    let (delay_code, _, _) = raw_http_with_headers(
        api_addr,
        "GET",
        "/proxies/LAX-AnyTLS-v2-MuxPool/delay?timeout=3000",
        &valid_host,
        &[],
        None,
    )
    .await;
    assert_eq!(
        delay_code, 200,
        "AnyTLS node password must remain intact after reloading redacted YAML"
    );

    // 7. Configure a Bearer `secret` via hot-reload and verify REST + WebSocket enforcement!
    let with_secret_yaml = redacted_yaml.replace("secret: null", "secret: super-secret-2026");
    let put_sec = serde_json::json!({ "payload": with_secret_yaml }).to_string();
    let (code, _, _) = raw_http_with_headers(
        api_addr,
        "PUT",
        "/configs",
        &valid_host,
        &[],
        Some(&put_sec),
    )
    .await;
    assert_eq!(code, 204);

    // Without Bearer token -> 401
    let (code_no_auth, _, _) =
        raw_http_with_headers(api_addr, "GET", "/configs", &valid_host, &[], None).await;
    assert_eq!(code_no_auth, 401);

    // With wrong Bearer token -> 401
    let (code_bad_auth, _, _) = raw_http_with_headers(
        api_addr,
        "GET",
        "/configs",
        &valid_host,
        &[("Authorization", "Bearer wrong-token")],
        None,
    )
    .await;
    assert_eq!(code_bad_auth, 401);

    // With valid Bearer token -> 200
    let (code_ok_auth, _, _) = raw_http_with_headers(
        api_addr,
        "GET",
        "/configs",
        &valid_host,
        &[("Authorization", "Bearer super-secret-2026")],
        None,
    )
    .await;
    assert_eq!(code_ok_auth, 200);

    // WebSocket `/traffic` without secret -> 401; with `?secret=super-secret-2026` -> 101!
    {
        let mut ws_unauth = TcpStream::connect(api_addr).await.unwrap();
        let req = format!(
            "GET /traffic HTTP/1.1\r\nHost: {valid_host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
        );
        ws_unauth.write_all(req.as_bytes()).await.unwrap();
        let mut buf = [0u8; 512];
        let n = ws_unauth.read(&mut buf).await.unwrap();
        assert!(String::from_utf8_lossy(&buf[..n]).starts_with("HTTP/1.1 401"));
    }
    {
        let mut ws_auth = TcpStream::connect(api_addr).await.unwrap();
        let req = format!(
            "GET /traffic?secret=super-secret-2026 HTTP/1.1\r\nHost: {valid_host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
        );
        ws_auth.write_all(req.as_bytes()).await.unwrap();
        let mut buf = [0u8; 512];
        let n = ws_auth.read(&mut buf).await.unwrap();
        assert!(String::from_utf8_lossy(&buf[..n]).starts_with("HTTP/1.1 101"));
    }

    let _ = shutdown_tx.send(true);
    engine.shutdown();
}

#[tokio::test]
async fn mixed_inbound_socks5_auth_negotiation_udp_associate_acl_and_error_codes() {
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // Local TCP + UDP echo origins
    let tcp_origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tcp_origin_addr = tcp_origin.local_addr().unwrap();
    let mut tcp_stop = shutdown_rx.clone();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = tcp_stop.changed() => break,
                acc = tcp_origin.accept() => {
                    let Ok((mut s, _)) = acc else { continue };
                    tokio::spawn(async move {
                        let mut b = [0u8; 1024];
                        let n = s.read(&mut b).await.unwrap_or(0);
                        if n > 0 {
                            let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK").await;
                        }
                    });
                }
            }
        }
    });

    let udp_origin = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let udp_origin_addr = udp_origin.local_addr().unwrap();
    let udp_hit_count = Arc::new(AtomicUsize::new(0));
    let udp_hits_bg = Arc::clone(&udp_hit_count);
    let mut udp_stop = shutdown_rx.clone();
    tokio::spawn(async move {
        let mut b = [0u8; 2048];
        loop {
            tokio::select! {
                _ = udp_stop.changed() => break,
                r = udp_origin.recv_from(&mut b) => {
                    let Ok((n, peer)) = r else { continue };
                    udp_hits_bg.fetch_add(1, Ordering::SeqCst);
                    let mut out = b"ECHO:".to_vec();
                    out.extend_from_slice(&b[..n]);
                    let _ = udp_origin.send_to(&out, peer).await;
                }
            }
        }
    });

    let dns = Arc::new(FakeIpDnsEngine::new(&DnsConfig::default()).unwrap());
    let rules = vec![
        "DOMAIN,blocked.test,REJECT".to_string(),
        "MATCH,DIRECT".to_string(),
    ];
    let router = Arc::new(Router::new(RunMode::Rule, HashMap::new(), &[], &rules, dns).unwrap());
    let router_slot = Arc::new(RwLock::new(router));
    let hub = Arc::new(TelemetryHub::new());

    // Part A: No-Auth listener — verify strict SOCKS5 method negotiation & distinct error codes
    let noauth_policy = Arc::new(RwLock::new(MixedInboundPolicy::default()));
    let (mixed_noauth, _t1) = spawn_mixed_inbound_with_policy(
        "127.0.0.1:0",
        Arc::clone(&router_slot),
        noauth_policy,
        Arc::clone(&hub),
        shutdown_rx.clone(),
    )
    .await
    .unwrap();

    // A1: `nmethods = 0` (`[0x05, 0x00]`) MUST be rejected with `[0x05, 0xFF]`
    {
        let mut s = TcpStream::connect(mixed_noauth).await.unwrap();
        s.write_all(&[0x05, 0x00]).await.unwrap();
        let mut rep = [0u8; 2];
        s.read_exact(&mut rep).await.unwrap();
        assert_eq!(rep, [0x05, 0xFF], "nmethods=0 must never return No-Auth");
    }

    // A2: Client offering ONLY `0x02` when server expects `0x00` MUST receive `[0x05, 0xFF]`
    {
        let mut s = TcpStream::connect(mixed_noauth).await.unwrap();
        s.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
        let mut rep = [0u8; 2];
        s.read_exact(&mut rep).await.unwrap();
        assert_eq!(
            rep,
            [0x05, 0xFF],
            "must not select 0x00 when client did not offer 0x00"
        );
    }

    // A3: Distinct error semantics — `REJECT` -> HTTP 403 & SOCKS5 `0x02`; unmapped Fake-IP -> HTTP 502 & SOCKS5 `0x04`
    {
        let mut s = TcpStream::connect(mixed_noauth).await.unwrap();
        s.write_all(b"CONNECT blocked.test:443 HTTP/1.1\r\nHost: blocked.test:443\r\n\r\n")
            .await
            .unwrap();
        let mut buf = [0u8; 256];
        let n = s.read(&mut buf).await.unwrap();
        let txt = String::from_utf8_lossy(&buf[..n]);
        assert!(
            txt.starts_with("HTTP/1.1 403"),
            "expected 403 for REJECT, got: {txt}"
        );
    }
    {
        let mut s = TcpStream::connect(mixed_noauth).await.unwrap();
        s.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut g = [0u8; 2];
        s.read_exact(&mut g).await.unwrap();
        // SOCKS5 CONNECT to `blocked.test:443`
        let host = b"blocked.test";
        let mut req = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
        req.extend_from_slice(host);
        req.extend_from_slice(&443u16.to_be_bytes());
        s.write_all(&req).await.unwrap();
        let mut rep = [0u8; 10];
        s.read_exact(&mut rep).await.unwrap();
        assert_eq!(rep[1], 0x02, "SOCKS5 REJECT must return REP=0x02");
    }
    {
        // Unmapped Fake-IP `198.18.200.200:80` -> DNS failure (`502` on HTTP, `0x04` on SOCKS5)
        let mut s = TcpStream::connect(mixed_noauth).await.unwrap();
        s.write_all(b"CONNECT 198.18.200.200:80 HTTP/1.1\r\nHost: 198.18.200.200:80\r\n\r\n")
            .await
            .unwrap();
        let mut buf = [0u8; 256];
        let n = s.read(&mut buf).await.unwrap();
        let txt = String::from_utf8_lossy(&buf[..n]);
        assert!(txt.starts_with("HTTP/1.1 502"));
        assert!(txt.contains("dns-resolution-failed"));
    }
    {
        let mut s = TcpStream::connect(mixed_noauth).await.unwrap();
        s.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut g = [0u8; 2];
        s.read_exact(&mut g).await.unwrap();
        let mut req = vec![0x05, 0x01, 0x00, 0x01, 198, 18, 200, 200];
        req.extend_from_slice(&80u16.to_be_bytes());
        s.write_all(&req).await.unwrap();
        let mut rep = [0u8; 10];
        s.read_exact(&mut rep).await.unwrap();
        assert_eq!(
            rep[1], 0x04,
            "unmapped Fake-IP / DNS failure must return SOCKS5 REP=0x04"
        );
    }

    // A4: SOCKS5 `UDP ASSOCIATE` client source port locking
    {
        let mut ctrl = TcpStream::connect(mixed_noauth).await.unwrap();
        ctrl.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut g = [0u8; 2];
        ctrl.read_exact(&mut g).await.unwrap();

        let legit_udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let legit_port = legit_udp.local_addr().unwrap().port();
        // Associate explicitly with `127.0.0.1:<legit_port>`
        let mut assoc_req = vec![0x05, 0x03, 0x00, 0x01, 127, 0, 0, 1];
        assoc_req.extend_from_slice(&legit_port.to_be_bytes());
        ctrl.write_all(&assoc_req).await.unwrap();
        let mut rep = [0u8; 10];
        ctrl.read_exact(&mut rep).await.unwrap();
        assert_eq!(rep[1], 0x00);
        let relay_port = u16::from_be_bytes([rep[8], rep[9]]);
        let relay_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), relay_port);

        let mut s5_dgram = vec![0x00, 0x00, 0x00, 0x01, 127, 0, 0, 1];
        s5_dgram.extend_from_slice(&udp_origin_addr.port().to_be_bytes());
        s5_dgram.extend_from_slice(b"legit-ping");

        // Unauthorized local socket on a DIFFERENT port tries to abuse `relay_addr` -> MUST BE DROPPED!
        let attacker_udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        attacker_udp.send_to(&s5_dgram, relay_addr).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            udp_hit_count.load(Ordering::SeqCst),
            0,
            "UDP datagram from unauthorized port must be dropped before reaching target"
        );

        // Authorized `legit_udp` succeeds!
        legit_udp.send_to(&s5_dgram, relay_addr).await.unwrap();
        let mut rbuf = [0u8; 256];
        let (rn, _) = tokio::time::timeout(Duration::from_secs(2), legit_udp.recv_from(&mut rbuf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&rbuf[10..rn], b"ECHO:legit-ping");
        assert_eq!(udp_hit_count.load(Ordering::SeqCst), 1);
    }

    // Part B: Authenticated Mixed Inbound (`authentication: ["alice:s3cr3t"]`)
    let auth_policy = Arc::new(RwLock::new(
        MixedInboundPolicy::from_config(false, &["alice:s3cr3t".to_string()], &[]).unwrap(),
    ));
    let (mixed_auth, _t2) = spawn_mixed_inbound_with_policy(
        "127.0.0.1:0",
        Arc::clone(&router_slot),
        auth_policy,
        Arc::clone(&hub),
        shutdown_rx.clone(),
    )
    .await
    .unwrap();

    // B1: SOCKS5 offering No-Auth (`0x00`) when credentials are required -> `[0x05, 0xFF]`
    {
        let mut s = TcpStream::connect(mixed_auth).await.unwrap();
        s.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut rep = [0u8; 2];
        s.read_exact(&mut rep).await.unwrap();
        assert_eq!(rep, [0x05, 0xFF]);
    }

    // B2: SOCKS5 RFC 1929 `0x02` wrong password -> `[0x01, 0x01]`; right password -> `[0x01, 0x00]` + relay!
    {
        let mut s = TcpStream::connect(mixed_auth).await.unwrap();
        s.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
        let mut g = [0u8; 2];
        s.read_exact(&mut g).await.unwrap();
        assert_eq!(g, [0x05, 0x02]);
        s.write_all(b"\x01\x05alice\x05wrong").await.unwrap();
        let mut ar = [0u8; 2];
        s.read_exact(&mut ar).await.unwrap();
        assert_eq!(ar, [0x01, 0x01]);
    }
    {
        let mut s = TcpStream::connect(mixed_auth).await.unwrap();
        s.write_all(&[0x05, 0x02, 0x00, 0x02]).await.unwrap();
        let mut g = [0u8; 2];
        s.read_exact(&mut g).await.unwrap();
        assert_eq!(g, [0x05, 0x02]);
        s.write_all(b"\x01\x05alice\x06s3cr3t").await.unwrap();
        let mut ar = [0u8; 2];
        s.read_exact(&mut ar).await.unwrap();
        assert_eq!(ar, [0x01, 0x00]);
    }

    // B3: HTTP Proxy `407 Proxy Authentication Required` without header, `200 OK` with Basic auth!
    {
        let mut s = TcpStream::connect(mixed_auth).await.unwrap();
        let req = format!(
            "GET http://127.0.0.1:{}/ HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
            tcp_origin_addr.port(),
            tcp_origin_addr.port()
        );
        s.write_all(req.as_bytes()).await.unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).await.unwrap();
        assert!(out.starts_with("HTTP/1.1 407"));
    }
    {
        let mut s = TcpStream::connect(mixed_auth).await.unwrap();
        let b64 = STANDARD.encode("alice:s3cr3t");
        let req = format!(
            "GET http://127.0.0.1:{}/ HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nProxy-Authorization: Basic {b64}\r\nConnection: close\r\n\r\n",
            tcp_origin_addr.port(),
            tcp_origin_addr.port()
        );
        s.write_all(req.as_bytes()).await.unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).await.unwrap();
        assert!(out.starts_with("HTTP/1.1 200 OK"));
    }

    let _ = shutdown_tx.send(true);
}

struct GuestTunDev {
    rx: VecDeque<Vec<u8>>,
    tx: VecDeque<Vec<u8>>,
}
struct GRx(Vec<u8>);
impl RxToken for GRx {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}
struct GTx<'a>(&'a mut VecDeque<Vec<u8>>);
impl TxToken for GTx<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut b = vec![0u8; len];
        let r = f(&mut b);
        self.0.push_back(b);
        r
    }
}
impl Device for GuestTunDev {
    type RxToken<'a> = GRx;
    type TxToken<'a> = GTx<'a>;
    fn receive(&mut self, _ts: SmolInstant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let p = self.rx.pop_front()?;
        Some((GRx(p), GTx(&mut self.tx)))
    }
    fn transmit(&mut self, _ts: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(GTx(&mut self.tx))
    }
    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = 1500;
        caps.checksum = ChecksumCapabilities::default();
        caps
    }
}

#[tokio::test]
async fn tun_ipv6_dns_hijack_general_udp_forwarding_and_tcp_reject_rst() {
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // Local IPv4 & IPv6 UDP echo servers for non-53 general UDP TUN relay test
    let udp4 = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let udp4_addr = udp4.local_addr().unwrap();
    let mut stop4 = shutdown_rx.clone();
    tokio::spawn(async move {
        let mut b = [0u8; 2048];
        loop {
            tokio::select! {
                _ = stop4.changed() => break,
                r = udp4.recv_from(&mut b) => {
                    let Ok((n, peer)) = r else { continue };
                    let mut reply = b"TUN-UDP4:".to_vec();
                    reply.extend_from_slice(&b[..n]);
                    let _ = udp4.send_to(&reply, peer).await;
                }
            }
        }
    });

    let udp6_opt = UdpSocket::bind("[::1]:0").await.ok().map(Arc::new);
    let udp6_port = udp6_opt.as_ref().map(|s| s.local_addr().unwrap().port());
    if let Some(udp6) = udp6_opt {
        let mut stop6 = shutdown_rx.clone();
        tokio::spawn(async move {
            let mut b = [0u8; 2048];
            loop {
                tokio::select! {
                    _ = stop6.changed() => break,
                    r = udp6.recv_from(&mut b) => {
                        let Ok((n, peer)) = r else { continue };
                        let mut reply = b"TUN-UDP6:".to_vec();
                        reply.extend_from_slice(&b[..n]);
                        let _ = udp6.send_to(&reply, peer).await;
                    }
                }
            }
        });
    }

    let dns = Arc::new(FakeIpDnsEngine::new(&DnsConfig::default()).unwrap());
    let blocked_fake_ip = dns.assign_fake_ip("blocked.tun.example");

    let rules = vec![
        "DOMAIN,blocked.tun.example,REJECT".to_string(),
        "MATCH,DIRECT".to_string(),
    ];
    let router = Arc::new(Router::new(RunMode::Rule, HashMap::new(), &[], &rules, dns).unwrap());
    let router_slot = Arc::new(RwLock::new(router));
    let hub = Arc::new(TelemetryHub::new());

    let (mut vtun, _tun_task) = spawn_userspace_tun(1500, router_slot, hub, shutdown_rx.clone());

    // 1. IPv6 `:53` UDP DNS Hijack
    let dns_q = build_dns_query(0x4242, "claude.ai", QTYPE_A);
    let v6_dns_pkt = build_ipv6_udp_packet(
        "fd00::2".parse::<Ipv6Addr>().unwrap(),
        53001,
        "2606:4700:4700::1111".parse::<Ipv6Addr>().unwrap(),
        53,
        &dns_q,
    )
    .unwrap();
    vtun.ingress_tx.send(v6_dns_pkt).await.unwrap();

    let v6_dns_resp = tokio::time::timeout(Duration::from_secs(2), vtun.egress_rx.recv())
        .await
        .expect("IPv6 DNS hijack timeout")
        .unwrap();
    let ip6 = Ipv6Packet::new_checked(&v6_dns_resp).unwrap();
    assert_eq!(
        ip6.src_addr(),
        "2606:4700:4700::1111".parse::<Ipv6Addr>().unwrap()
    );
    let udp6_pkt = UdpPacket::new_checked(ip6.payload()).unwrap();
    let ans = extract_ip_answers(udp6_pkt.payload()).unwrap();
    assert!(matches!(ans[0], DnsAnswerData::A(_)));

    // 2. General non-53 IPv4 UDP forwarding + response packet encapsulation!
    let v4_udp_pkt = build_ipv4_udp_packet(
        Ipv4Addr::new(10, 0, 0, 2),
        55000,
        Ipv4Addr::LOCALHOST,
        udp4_addr.port(),
        b"quic-datagram-v4",
    )
    .unwrap();
    vtun.ingress_tx.send(v4_udp_pkt).await.unwrap();

    let v4_udp_resp = tokio::time::timeout(Duration::from_secs(2), vtun.egress_rx.recv())
        .await
        .expect("TUN general IPv4 UDP relay timeout")
        .unwrap();
    let ip4_r = Ipv4Packet::new_checked(&v4_udp_resp).unwrap();
    assert_eq!(ip4_r.src_addr(), Ipv4Addr::LOCALHOST);
    assert_eq!(ip4_r.dst_addr(), Ipv4Addr::new(10, 0, 0, 2));
    let udp4_r = UdpPacket::new_checked(ip4_r.payload()).unwrap();
    assert_eq!(udp4_r.src_port(), udp4_addr.port());
    assert_eq!(udp4_r.dst_port(), 55000);
    assert_eq!(udp4_r.payload(), b"TUN-UDP4:quic-datagram-v4");

    // 3. General non-53 IPv6 UDP forwarding + response packet encapsulation!
    if let Some(port6) = udp6_port {
        let v6_udp_pkt = build_ipv6_udp_packet(
            "fd00::2".parse::<Ipv6Addr>().unwrap(),
            55006,
            Ipv6Addr::LOCALHOST,
            port6,
            b"quic-datagram-v6",
        )
        .unwrap();
        vtun.ingress_tx.send(v6_udp_pkt).await.unwrap();

        let v6_udp_resp = tokio::time::timeout(Duration::from_secs(2), vtun.egress_rx.recv())
            .await
            .expect("TUN general IPv6 UDP relay timeout")
            .unwrap();
        let ip6_r = Ipv6Packet::new_checked(&v6_udp_resp).unwrap();
        assert_eq!(ip6_r.src_addr(), Ipv6Addr::LOCALHOST);
        let udp6_r = UdpPacket::new_checked(ip6_r.payload()).unwrap();
        assert_eq!(udp6_r.payload(), b"TUN-UDP6:quic-datagram-v6");
    }

    // 4. TCP connection to a `REJECT` destination via `smoltcp` TUN MUST receive immediate `TCP RST` (`Closed`)!
    let mut guest_dev = GuestTunDev {
        rx: VecDeque::new(),
        tx: VecDeque::new(),
    };
    let mut cfg = IfaceConfig::new(HardwareAddress::Ip);
    cfg.random_seed = 0xCAFE_BABE;
    let boot = std::time::Instant::now();
    let now_smol = || SmolInstant::from_micros(boot.elapsed().as_micros() as i64);

    let mut guest_iface = Interface::new(cfg, &mut guest_dev, now_smol());
    guest_iface.update_ip_addrs(|addrs| {
        let _ = addrs.push(IpCidr::new(IpAddress::Ipv4(Ipv4Addr::new(10, 0, 0, 2)), 24));
    });
    let _ = guest_iface
        .routes_mut()
        .add_default_ipv4_route(Ipv4Addr::new(10, 0, 0, 1));

    let mut guest_sockets = SocketSet::new(vec![]);
    let guest_tcp = tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0u8; 16384]),
        tcp::SocketBuffer::new(vec![0u8; 16384]),
    );
    let guest_handle = guest_sockets.add(guest_tcp);
    guest_sockets
        .get_mut::<tcp::Socket>(guest_handle)
        .connect(
            guest_iface.context(),
            IpEndpoint::new(IpAddress::Ipv4(blocked_fake_ip), 443),
            51234,
        )
        .unwrap();

    let mut observed_closed_after_rst = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    while tokio::time::Instant::now() < deadline {
        let _ = guest_iface.poll(now_smol(), &mut guest_dev, &mut guest_sockets);
        while let Some(pkt) = guest_dev.tx.pop_front() {
            vtun.ingress_tx.send(pkt).await.unwrap();
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
        while let Ok(pkt) = vtun.egress_rx.try_recv() {
            guest_dev.rx.push_back(pkt);
        }
        let _ = guest_iface.poll(now_smol(), &mut guest_dev, &mut guest_sockets);
        let state = guest_sockets.get::<tcp::Socket>(guest_handle).state();
        if state == tcp::State::Closed {
            observed_closed_after_rst = true;
            break;
        }
    }
    assert!(
        observed_closed_after_rst,
        "TUN TCP connection to REJECT target must promptly abort with TCP RST -> Closed"
    );

    let _ = shutdown_tx.send(true);
}

#[tokio::test]
async fn hot_reload_rebinds_ports_preserves_fake_ip_and_rolls_back_on_failure() {
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
    let host_hdr = api_addr.to_string();

    // Verify Demo does NOT falsely claim OS TUN is enabled on startup!
    assert!(!engine.is_tun_active());
    let (_, _, initial_cfg_json) =
        raw_http_with_headers(api_addr, "GET", "/configs", &host_hdr, &[], None).await;
    let parsed_init: serde_json::Value = serde_json::from_str(&initial_cfg_json).unwrap();
    assert_eq!(parsed_init["tun"]["enable"], false);
    assert_eq!(parsed_init["tun"]["os-attached"], false);

    // If running without root / CAP_NET_ADMIN (or on macOS/Windows), `PATCH /configs {"tun":{"enable":true}}`
    // MUST fail honestly (`400`) and keep `tun.enable == false`!
    let is_root = {
        #[cfg(target_os = "linux")]
        {
            unsafe { libc::geteuid() == 0 }
        }
        #[cfg(not(target_os = "linux"))]
        {
            false
        }
    };
    if !is_root {
        let (tun_code, _, _) = raw_http_with_headers(
            api_addr,
            "PATCH",
            "/configs",
            &host_hdr,
            &[],
            Some(r#"{"tun":{"enable":true}}"#),
        )
        .await;
        assert_eq!(
            tun_code, 400,
            "unprivileged / unsupported OS TUN activation must return 400"
        );
        assert!(!engine.is_tun_active());
    }

    // 1. Allocate a Fake-IP on initial UDP DNS port
    let dns1 = engine.dns_addr().unwrap();
    let udp_cli = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    udp_cli
        .send_to(
            &build_dns_query(0x7777, "preserved.github.com", QTYPE_A),
            dns1,
        )
        .await
        .unwrap();
    let mut dbuf = [0u8; 512];
    let (dn, _) = udp_cli.recv_from(&mut dbuf).await.unwrap();
    let DnsAnswerData::A(preserved_fip) = extract_ip_answers(&dbuf[..dn]).unwrap()[0] else {
        panic!("expected A record");
    };

    // Reserve two fresh free ports (probing both UDP & TCP for DNS so Windows Hyper-V TCP excluded ranges are skipped)
    let probe_mixed = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let new_mixed_port = probe_mixed.local_addr().unwrap().port();
    let mut held_udp_probes = Vec::new();
    let new_dns_addr = loop {
        let probe_udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let candidate = probe_udp.local_addr().unwrap();
        if candidate.port() != new_mixed_port
            && let Ok(probe_dns_tcp) = TcpListener::bind(candidate).await
        {
            drop(probe_dns_tcp);
            drop(probe_udp);
            break candidate;
        }
        held_udp_probes.push(probe_udp);
    };
    drop(held_udp_probes);
    drop(probe_mixed);

    // 2. Hot-reload onto `new_mixed_port` + `new_dns_addr`!
    let mut updated_cfg = engine.config_snapshot();
    updated_cfg.mixed_port = new_mixed_port;
    updated_cfg.dns.listen = new_dns_addr.to_string();
    engine
        .reload_yaml(&updated_cfg.to_yaml_string().unwrap())
        .await
        .unwrap();

    assert_eq!(engine.mixed_addr().port(), new_mixed_port);
    assert_eq!(engine.dns_addr(), Some(new_dns_addr));
    // Verify `preserved_fip` allocated BEFORE reload was preserved in the new `FakeIpDnsEngine`!
    assert_eq!(
        engine
            .router()
            .dns()
            .lookup_domain(IpAddr::V4(preserved_fip))
            .as_deref(),
        Some("preserved.github.com")
    );

    // Verify new UDP DNS listener allocates Fake-IPs directly into the live reloaded Router!
    udp_cli
        .send_to(
            &build_dns_query(0x8888, "after-reload.openai.com", QTYPE_A),
            new_dns_addr,
        )
        .await
        .unwrap();
    let (dn2, _) = udp_cli.recv_from(&mut dbuf).await.unwrap();
    let DnsAnswerData::A(after_fip) = extract_ip_answers(&dbuf[..dn2]).unwrap()[0] else {
        panic!("expected A record");
    };
    assert_eq!(
        engine
            .router()
            .dns()
            .lookup_domain(IpAddr::V4(after_fip))
            .as_deref(),
        Some("after-reload.openai.com")
    );

    // 3. Rollback test: occupy a TCP port with an external listener, then attempt hot-reload onto that occupied port!
    let occupied_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let occupied_port = occupied_listener.local_addr().unwrap().port();

    let mut colliding_cfg = engine.config_snapshot();
    colliding_cfg.mixed_port = occupied_port;
    let reload_err = engine
        .reload_yaml(&colliding_cfg.to_yaml_string().unwrap())
        .await;
    assert!(
        reload_err.is_err(),
        "hot-reload to an already occupied port must return Err"
    );

    // Previous `new_mixed_port` MUST still be bound and serving real benchmark traffic without interruption!
    assert_eq!(engine.mixed_addr().port(), new_mixed_port);
    let (bench_code, _, _) = raw_http_with_headers(
        api_addr,
        "POST",
        "/tools/benchmark",
        &host_hdr,
        &[],
        Some(r#"{"streams":2,"payload_bytes":16384}"#),
    )
    .await;
    assert_eq!(
        bench_code, 200,
        "previous Mixed listener must stay alive after failed hot-reload"
    );

    drop(occupied_listener);
    let _ = shutdown_tx.send(true);
    engine.shutdown();
}

#[tokio::test]
async fn dns_ip_rule_resolution_no_resolve_and_accurate_geoip() {
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // Mock upstream authoritative UDP DNS server
    let mock_ns = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let mock_ns_addr = mock_ns.local_addr().unwrap();
    let ns_queries = Arc::new(AtomicUsize::new(0));
    let ns_queries_bg = Arc::clone(&ns_queries);
    let mut ns_stop = shutdown_rx.clone();

    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        loop {
            tokio::select! {
                _ = ns_stop.changed() => break,
                res = mock_ns.recv_from(&mut buf) => {
                    let Ok((n, peer)) = res else { continue };
                    let Ok(pkt) = DnsQueryPacket::parse(&buf[..n]) else { continue };
                    ns_queries_bg.fetch_add(1, Ordering::SeqCst);
                    if pkt.question.qtype == QTYPE_A {
                        let qlow = pkt.question.name.to_ascii_lowercase();
                        let ip = match qlow.as_str() {
                            // Mainland China IP (Alibaba Cloud / AliDNS)
                            "portal.cn-service.test" => Some(Ipv4Addr::new(223, 5, 5, 5)),
                            // APNIC Japan block (`1.0.16.0/20`) — previously misclassified as CN under `/8`!
                            "tokyo.apnic.test" => Some(Ipv4Addr::new(1, 0, 16, 8)),
                            _ => None,
                        };
                        let resp = match ip {
                            Some(v4) => pkt.build_response(&buf[..n], 0, 60, &[DnsAnswerData::A(v4)]),
                            None => pkt.build_response(&buf[..n], 3, 60, &[]),
                        };
                        let _ = mock_ns.send_to(&resp, peer).await;
                    } else {
                        let resp = pkt.build_response(&buf[..n], 0, 60, &[]);
                        let _ = mock_ns.send_to(&resp, peer).await;
                    }
                }
            }
        }
    });

    // Spawn a real SS-2022 proxy outbound to distinguish Proxy vs DIRECT routing
    let psk = STANDARD.encode([0x55u8; 32]);
    let (ss_addr, _ss_task) = spawn_ss_server(
        "127.0.0.1:0",
        "2022-blake3-aes-256-gcm",
        &psk,
        shutdown_rx.clone(),
    )
    .await
    .unwrap();
    let ss_ob: DynOutbound = Arc::new(
        ShadowsocksOutbound::new(
            "JP-SS2022",
            "127.0.0.1",
            ss_addr.port(),
            "2022-blake3-aes-256-gcm",
            &psk,
            true,
        )
        .unwrap(),
    );
    let mut outbounds = HashMap::new();
    outbounds.insert("JP-SS2022".to_string(), ss_ob);

    let dns_cfg = DnsConfig {
        enable: true,
        listen: "127.0.0.1:0".into(),
        enhanced_mode: "fake-ip".into(),
        fake_ip_range: "198.18.0.0/15".into(),
        fake_ip_filter: vec![],
        nameserver: vec![mock_ns_addr.to_string()],
        ..DnsConfig::default()
    };
    let dns = Arc::new(FakeIpDnsEngine::new(&dns_cfg).unwrap());

    // Rules:
    // 1. `IP-CIDR,9.9.9.0/24,REJECT,no-resolve` -> MUST NOT trigger DNS resolution for domains!
    // 2. `GEOIP,CN,DIRECT` -> resolves domain via `mock_ns` and matches `223.5.5.5` (CN), NOT `1.0.16.8` (JP)!
    // 3. `IP-CIDR,1.0.16.0/20,JP-SS2022` -> matches resolved `1.0.16.8`!
    // 4. `MATCH,REJECT`
    let rules = vec![
        "IP-CIDR,9.9.9.0/24,REJECT,no-resolve".to_string(),
        "DOMAIN,no-dns-needed.test,JP-SS2022".to_string(),
        "GEOIP,CN,DIRECT".to_string(),
        "IP-CIDR,1.0.16.0/20,JP-SS2022".to_string(),
        "MATCH,REJECT".to_string(),
    ];
    let router = Router::new(RunMode::Rule, outbounds, &[], &rules, Arc::clone(&dns)).unwrap();

    // Case 1: `no-dns-needed.test` sits AFTER `IP-CIDR,...,no-resolve` -> ZERO DNS queries should be sent!
    let d1 = router
        .route_async(
            None,
            &TargetAddr::new_domain("no-dns-needed.test", 443).unwrap(),
        )
        .await;
    assert_eq!(d1.outbound.name(), "JP-SS2022");
    assert_eq!(
        ns_queries.load(Ordering::SeqCst),
        0,
        "rule with ,no-resolve must NEVER trigger upstream DNS queries"
    );

    // Case 2: Domain `portal.cn-service.test` (and its Fake-IP!) resolves to `223.5.5.5` -> matches `GEOIP,CN` -> `DIRECT`!
    let fip_cn = dns.assign_fake_ip("portal.cn-service.test");
    let d2 = router
        .route_async(
            None,
            &TargetAddr::from(SocketAddr::new(IpAddr::V4(fip_cn), 443)),
        )
        .await;
    assert_eq!(d2.rule_type, "GeoIP");
    assert_eq!(d2.rule_payload, "CN");
    assert_eq!(d2.outbound.name(), "DIRECT");
    assert!(ns_queries.load(Ordering::SeqCst) >= 1);

    // Case 3: Domain `tokyo.apnic.test` resolves to `1.0.16.8` -> MUST NOT match `GEOIP,CN` -> matches `IP-CIDR,1.0.16.0/20` -> `JP-SS2022`!
    let d3 = router
        .route_async(
            None,
            &TargetAddr::new_domain("tokyo.apnic.test", 443).unwrap(),
        )
        .await;
    assert_eq!(
        d3.rule_type, "IPCIDR",
        "APNIC Japan 1.0.16.8 must not falsely match GEOIP,CN"
    );
    assert_eq!(d3.outbound.name(), "JP-SS2022");

    let _ = shutdown_tx.send(true);
}

#[tokio::test]
async fn subscription_rce_secret_wipe_and_controller_self_bounce_are_blocked_e2e() {
    use proxy_core::profile::parse_subscription_payload_sanitized;
    use proxy_core::router::ruleset::resolve_confined_http_provider_path;

    let state_dir = std::env::temp_dir().join(format!("rc-sec-p0-e2e-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&state_dir).unwrap();

    // 1. P0-1: `resolve_confined_http_provider_path` and `ClashConfig::validate` block traversal & absolute paths
    assert!(
        resolve_confined_http_provider_path(&state_dir, "evil", Some("../../.bashrc"), "text")
            .is_err()
    );
    assert!(
        resolve_confined_http_provider_path(&state_dir, "evil", Some("/tmp/pwned.sh"), "text")
            .is_err()
    );
    let bad_provider_yaml = r#"
rule-providers:
  evil:
    type: http
    behavior: domain
    format: text
    url: https://example.com/rules.txt
    path: /tmp/evil_outside_state_dir.txt
rules:
  - RULE-SET,evil,DIRECT
  - MATCH,DIRECT
"#;
    assert!(
        ClashConfig::from_yaml_str(bad_provider_yaml).is_err(),
        "HTTP rule-provider with path outside state_dir must fail validation"
    );

    // 2. P0-4: Malicious/Subconverter subscription with `secret: ""`, `allow-lan: true`, `file` provider,
    //    and `http` provider custom `path` is sanitized on import AND never wipes live controller secret!
    let hostile_sub = r#"
mixed-port: 7890
allow-lan: true
bind-address: "0.0.0.0"
external-controller: 0.0.0.0:9090
secret: ""
proxies:
  - name: "Sub-SOCKS"
    type: socks5
    server: 127.0.0.1
    port: 10808
proxy-groups:
  - name: "Proxy"
    type: select
    proxies: ["Sub-SOCKS", "DIRECT"]
rule-providers:
  probe-etc:
    type: file
    behavior: domain
    format: text
    path: /etc/hosts
  remote-list:
    type: http
    behavior: domain
    format: text
    url: https://example.com/domains.txt
    path: ../../../.bashrc
rules:
  - RULE-SET,probe-etc,Proxy
  - RULE-SET,remote-list,Proxy
  - MATCH,DIRECT
"#;
    let (sanitized_cfg, _, _) = parse_subscription_payload_sanitized(hostile_sub, &[]).unwrap();
    assert!(!sanitized_cfg.allow_lan);
    assert_eq!(sanitized_cfg.bind_address, "127.0.0.1");
    assert_eq!(sanitized_cfg.external_controller, "127.0.0.1:9090");
    assert!(sanitized_cfg.secret.is_none());
    assert!(!sanitized_cfg.rule_providers.contains_key("probe-etc"));
    assert_eq!(
        sanitized_cfg.rule_providers["remote-list"].path, None,
        "remote subscription HTTP rule-provider path must be stripped"
    );

    // Start live engine with an initial secret and verify profile activation with `secret: Some("")`
    // and `allow_lan: true` preserves the daemon's secret and `allow_lan = false`!
    let mut base_cfg = ClashConfig {
        mixed_port: 0,
        secret: Some("initial-daemon-secret-999".to_string()),
        allow_lan: false,
        ..Default::default()
    };
    base_cfg.dns.enable = false;

    // Bind ephemeral port first to know controller port so engine blocks self-bounce to controller
    let probe_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let reserved_ctrl_port = probe_listener.local_addr().unwrap().port();
    drop(probe_listener);
    base_cfg.external_controller = format!("127.0.0.1:{reserved_ctrl_port}");

    let engine = ProxyEngine::start_with_state_dir(base_cfg, state_dir.clone())
        .await
        .unwrap();
    let (stop_tx, stop_rx) = watch::channel(false);
    let (ctrl_addr, _api_task) = spawn_api_server(
        &format!("127.0.0.1:{reserved_ctrl_port}"),
        Arc::clone(&engine),
        stop_rx,
    )
    .await
    .unwrap();

    let mut raw_override_attempt = sanitized_cfg.clone();
    raw_override_attempt.secret = Some(String::new());
    raw_override_attempt.allow_lan = true;
    engine
        .activate_profile_config_with_selections(raw_override_attempt, None)
        .await
        .unwrap();
    let snap_after = engine.config_snapshot();
    assert_eq!(
        snap_after.secret.as_deref(),
        Some("initial-daemon-secret-999"),
        "profile activation must never wipe or overwrite active controller secret"
    );
    assert!(
        !snap_after.allow_lan,
        "profile activation must never enable allow_lan"
    );

    // 3. P0-3: Attempting to proxy to the controller port (`127.0.0.1:<ctrl_port>`) via MixedInbound is rejected (403)!
    let mixed_addr = engine.mixed_addr();
    let mut proxy_conn = TcpStream::connect(mixed_addr).await.unwrap();
    let bounce_req = format!(
        "GET http://127.0.0.1:{}/version HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
        ctrl_addr.port(),
        ctrl_addr.port()
    );
    proxy_conn.write_all(bounce_req.as_bytes()).await.unwrap();
    let mut bounce_resp = Vec::new();
    proxy_conn.read_to_end(&mut bounce_resp).await.unwrap();
    let bounce_str = String::from_utf8_lossy(&bounce_resp);
    assert!(
        bounce_str.starts_with("HTTP/1.1 403"),
        "MixedInbound must block self-bounce to controller port, got: {bounce_str}"
    );

    let _ = stop_tx.send(true);
    engine.shutdown();
    let _ = std::fs::remove_dir_all(&state_dir);
}

#[tokio::test]
async fn ssrf_delay_endpoints_geodata_subscription_and_file_ruleset_confinement_e2e() {
    use proxy_core::{
        profile::fetch_subscription_http_with_proxy,
        router::{
            geodata::fetch_http_bytes_protected_with_proxy,
            ruleset::resolve_confined_file_provider_path,
        },
    };

    let state_dir =
        std::env::temp_dir().join(format!("rc-sec-m2-ssrf-e2e-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&state_dir).unwrap();

    // 1. Canary loopback HTTP server that MUST NEVER receive any SSRF probe
    let canary = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let canary_addr = canary.local_addr().unwrap();
    let canary_hits = Arc::new(AtomicUsize::new(0));
    let canary_hits_bg = Arc::clone(&canary_hits);
    let (bg_stop_tx, mut bg_stop_rx) = watch::channel(false);
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

    // Mock upstream DNS resolving attacker domain -> 127.0.0.1 and 169.254.169.254
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
                        ("rebind-direct.e2e.test", QTYPE_A) => pkt.build_response(
                            &buf[..n],
                            0,
                            60,
                            &[DnsAnswerData::A(Ipv4Addr::LOCALHOST)],
                        ),
                        ("rebind-meta.e2e.test", QTYPE_A) => pkt.build_response(
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

    // 2. Non-demo engine: `/proxies/DIRECT/delay` & `/group/PROXY/delay` MUST return 400 on SSRF/rebinding
    let base_yaml = format!(
        r#"
mixed-port: 0
external-controller: 127.0.0.1:0
mode: rule
dns:
  enable: true
  listen: 127.0.0.1:0
  nameserver:
    - "{mock_ns_addr}"
  direct-nameserver:
    - "{mock_ns_addr}"
proxy-groups:
  - name: PROXY
    type: select
    proxies: [DIRECT]
rules:
  - MATCH,PROXY
"#
    );
    let cfg = ClashConfig::from_yaml_str(&base_yaml).unwrap();
    let engine = ProxyEngine::start_with_state_dir(cfg, state_dir.clone())
        .await
        .unwrap();
    let (api_stop_tx, api_stop_rx) = watch::channel(false);
    let (api_addr, _api_task) = spawn_api_server("127.0.0.1:0", Arc::clone(&engine), api_stop_rx)
        .await
        .unwrap();
    let host_hdr = api_addr.to_string();

    for raw_target in [
        format!("http://127.0.0.1:{}/generate_204", canary_addr.port()),
        format!("http://localhost:{}/generate_204", canary_addr.port()),
        "http://0.1.2.3/generate_204".to_string(),
        "http://[::127.0.0.1]/generate_204".to_string(),
        "http://[::ffff:0:127.0.0.1]/generate_204".to_string(),
        "http://[fec0::1]/generate_204".to_string(),
        "http://[100::1]/generate_204".to_string(),
        "http://169.254.169.254/latest/meta-data/".to_string(),
        "http://10.0.0.1/".to_string(),
        "http://[fd00:ec2::254]/".to_string(),
        "ftp://example.com/file".to_string(),
        "http://u:p@example.com/generate_204".to_string(),
        format!(
            "http://rebind-direct.e2e.test:{}/generate_204",
            canary_addr.port()
        ),
        "http://rebind-meta.e2e.test/latest/meta-data/".to_string(),
    ] {
        let enc: String = raw_target
            .bytes()
            .map(|b| match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    (b as char).to_string()
                }
                _ => format!("%{b:02X}"),
            })
            .collect();
        for path in [
            format!("/proxies/DIRECT/delay?url={enc}&timeout=2000"),
            format!("/group/PROXY/delay?url={enc}&timeout=2000"),
        ] {
            let (code, _, body) =
                raw_http_with_headers(api_addr, "GET", &path, &host_hdr, &[], None).await;
            assert_eq!(
                code, 400,
                "SSRF delay target {raw_target} on {path} must return 400, got {code}: {body}"
            );
        }
    }
    assert_eq!(canary_hits.load(Ordering::SeqCst), 0);

    // 3. `PUT /configs` MUST reject `file` rule-provider pointing to `/etc/passwd` AND must NEVER
    //    echo contents of confined malformed files in error responses!
    let etc_passwd_yaml = r#"
mode: rule
rule-providers:
  leak:
    type: file
    behavior: ipcidr
    format: text
    path: /etc/passwd
rules:
  - RULE-SET,leak,DIRECT
  - MATCH,DIRECT
"#;
    let put_etc = serde_json::json!({ "payload": etc_passwd_yaml }).to_string();
    let (etc_code, _, etc_body) =
        raw_http_with_headers(api_addr, "PUT", "/configs", &host_hdr, &[], Some(&put_etc)).await;
    assert_eq!(
        etc_code, 400,
        "PUT /configs with /etc/passwd file rule-provider must fail with 400: {etc_body}"
    );
    assert!(!etc_body.contains("root:x:0:0"));

    // Write a confined file inside state_dir with a secret sentinel line and verify `PUT /configs`
    // error for invalid `ipcidr` NEVER echoes the sentinel line!
    let sentinel = "SECRET_CANARY_LINE_DO_NOT_ECHO_777";
    std::fs::write(state_dir.join("bad_cidrs.txt"), format!("{sentinel}\n")).unwrap();
    let echo_test_yaml = r#"
mode: rule
rule-providers:
  bad-cidrs:
    type: file
    behavior: ipcidr
    format: text
    path: bad_cidrs.txt
rules:
  - RULE-SET,bad-cidrs,DIRECT
  - MATCH,DIRECT
"#;
    let put_echo = serde_json::json!({ "payload": echo_test_yaml }).to_string();
    let (echo_code, _, echo_body) =
        raw_http_with_headers(api_addr, "PUT", "/configs", &host_hdr, &[], Some(&put_echo)).await;
    assert_eq!(echo_code, 400);
    assert!(
        !echo_body.contains(sentinel),
        "PUT /configs rule-provider error must never echo raw file content: {echo_body}"
    );
    assert!(resolve_confined_file_provider_path(Some(&state_dir), "leak", "/etc/passwd").is_err());

    // Relative backslash rule-provider path MUST be rejected by ClashConfig::from_yaml_str too.
    let backslash_provider_yaml = r#"
mode: rule
rule-providers:
  bs:
    type: file
    behavior: domain
    path: "sub\\backslash.yaml"
rules:
  - MATCH,DIRECT
"#;
    assert!(
        ClashConfig::from_yaml_str(backslash_provider_yaml).is_err(),
        "relative backslash rule-provider path must be rejected during config validation"
    );

    let _ = api_stop_tx.send(true);
    engine.shutdown();

    // 4. Demo mode: allowed benchmark port + UDP DNS succeed, while engine.dns_addr() over HTTP
    //    and disallowed localhost canary port return 400!
    let demo_engine = ProxyEngine::start_demo(
        Some(0),
        Some("127.0.0.1:0".into()),
        Some("127.0.0.1:0".into()),
    )
    .await
    .unwrap();
    let (demo_stop_tx, demo_stop_rx) = watch::channel(false);
    let (demo_api_addr, _demo_api_task) =
        spawn_api_server("127.0.0.1:0", Arc::clone(&demo_engine), demo_stop_rx)
            .await
            .unwrap();
    let demo_host = demo_api_addr.to_string();
    let demo_origin = demo_engine.demo_info().http_benchmark_origin;
    let demo_dns_addr = demo_engine.dns_addr().expect("demo engine has DNS port");
    let ok_demo_path = format!(
        "/proxies/DIRECT/delay?url={}%2Fgenerate_204&timeout=3000",
        demo_origin.replace(':', "%3A").replace('/', "%2F")
    );
    let (ok_demo_code, _, ok_demo_body) =
        raw_http_with_headers(demo_api_addr, "GET", &ok_demo_path, &demo_host, &[], None).await;
    assert_eq!(
        ok_demo_code, 200,
        "Demo benchmark port must succeed: {ok_demo_body}"
    );

    // Demo HTTP delay, group delay, waterfall probe, matrix probe, and site-check MUST reject `engine.dns_addr()`!
    let demo_group = demo_engine
        .config_snapshot()
        .proxy_groups
        .first()
        .expect("demo config has proxy group")
        .name
        .clone();
    let demo_group_enc: String = demo_group
        .bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect();
    for dns_http_url in [
        format!("http://127.0.0.1:{}/", demo_dns_addr.port()),
        format!("http://localhost:{}/", demo_dns_addr.port()),
    ] {
        let dns_enc: String = dns_http_url
            .bytes()
            .map(|b| match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    (b as char).to_string()
                }
                _ => format!("%{b:02X}"),
            })
            .collect();
        for delay_path in [
            format!("/proxies/DIRECT/delay?url={dns_enc}&timeout=1000"),
            format!("/group/{demo_group_enc}/delay?url={dns_enc}&timeout=1000"),
        ] {
            let (code, _, body) =
                raw_http_with_headers(demo_api_addr, "GET", &delay_path, &demo_host, &[], None)
                    .await;
            assert_eq!(
                code, 400,
                "Demo delay must reject engine.dns_addr() ({dns_http_url}) on {delay_path}, got {code}: {body}"
            );
        }

        let probe_payload = serde_json::json!({
            "url": dns_http_url,
            "check_udp": false,
            "timeout": 1000
        })
        .to_string();
        let (probe_code, _, probe_body) = raw_http_with_headers(
            demo_api_addr,
            "POST",
            "/proxies/DIRECT/probe",
            &demo_host,
            &[],
            Some(&probe_payload),
        )
        .await;
        assert_eq!(
            probe_code, 400,
            "Demo /probe must reject engine.dns_addr() ({dns_http_url}), got {probe_code}: {probe_body}"
        );

        let matrix_payload = serde_json::json!({
            "targets": [{
                "id": "evil-dns",
                "label": "DNS TCP",
                "category": "test",
                "url": dns_http_url
            }],
            "timeout": 1000
        })
        .to_string();
        let (matrix_code, _, matrix_body) = raw_http_with_headers(
            demo_api_addr,
            "POST",
            "/proxies/DIRECT/matrix",
            &demo_host,
            &[],
            Some(&matrix_payload),
        )
        .await;
        assert_eq!(
            matrix_code, 400,
            "Demo /matrix must reject engine.dns_addr() ({dns_http_url}), got {matrix_code}: {matrix_body}"
        );

        let site_payload = serde_json::json!({
            "target": dns_http_url,
            "check_udp": false,
            "timeout": 1000
        })
        .to_string();
        let (site_code, _, site_body) = raw_http_with_headers(
            demo_api_addr,
            "POST",
            "/diagnostics/site-check",
            &demo_host,
            &[],
            Some(&site_payload),
        )
        .await;
        assert_eq!(
            site_code, 400,
            "Demo /diagnostics/site-check must reject engine.dns_addr() ({dns_http_url}), got {site_code}: {site_body}"
        );
    }

    // Demo `/probe` and `/matrix` against `demo.http_benchmark_origin` MUST STILL pass BOTH HTTP and Demo UDP DNS!
    let ok_demo_probe_payload = serde_json::json!({
        "url": format!("{demo_origin}/generate_204"),
        "check_udp": true,
        "timeout": 3000
    })
    .to_string();
    let (ok_probe_code, _, ok_probe_body) = raw_http_with_headers(
        demo_api_addr,
        "POST",
        "/proxies/DIRECT/probe",
        &demo_host,
        &[],
        Some(&ok_demo_probe_payload),
    )
    .await;
    assert_eq!(
        ok_probe_code, 200,
        "Demo /probe against benchmark origin + UDP DNS must return 200: {ok_probe_body}"
    );
    let ok_probe_json: serde_json::Value = serde_json::from_str(&ok_probe_body).unwrap();
    assert_eq!(ok_probe_json["verdict"], "reachable");
    assert_eq!(ok_probe_json["udp_probe"]["status"], "verified");

    let ok_demo_matrix_payload = serde_json::json!({
        "targets": [{
            "id": "demo-origin",
            "label": "Demo Benchmark",
            "category": "sandbox",
            "url": format!("{demo_origin}/generate_204")
        }],
        "timeout": 3000
    })
    .to_string();
    let (ok_matrix_code, _, ok_matrix_body) = raw_http_with_headers(
        demo_api_addr,
        "POST",
        "/proxies/DIRECT/matrix",
        &demo_host,
        &[],
        Some(&ok_demo_matrix_payload),
    )
    .await;
    assert_eq!(
        ok_matrix_code, 200,
        "Demo /matrix against benchmark origin + UDP DNS must return 200: {ok_matrix_body}"
    );
    let ok_matrix_json: serde_json::Value = serde_json::from_str(&ok_matrix_body).unwrap();
    assert_eq!(ok_matrix_json["reachable_count"], 1);
    assert_eq!(ok_matrix_json["udp_probe"]["status"], "verified");

    let bad_demo_path = format!(
        "/proxies/DIRECT/delay?url=http%3A%2F%2F127.0.0.1%3A{}%2Fgenerate_204&timeout=2000",
        canary_addr.port()
    );
    let (bad_demo_code, _, bad_demo_body) =
        raw_http_with_headers(demo_api_addr, "GET", &bad_demo_path, &demo_host, &[], None).await;
    assert_eq!(
        bad_demo_code, 400,
        "Demo mode must block non-whitelisted localhost port: {bad_demo_body}"
    );
    assert_eq!(canary_hits.load(Ordering::SeqCst), 0);

    let _ = demo_stop_tx.send(true);
    demo_engine.shutdown();

    // 5. GeoData & Subscription fetchers NEVER invoke fallback_proxy or dial traps when blocked by SSRF or userinfo!
    struct CountingProxy(Arc<AtomicUsize>);
    #[async_trait::async_trait]
    impl proxy_core::outbound::OutboundHandler for CountingProxy {
        fn name(&self) -> &str {
            "CountingE2EProxy"
        }
        fn protocol(&self) -> &'static str {
            "socks5"
        }
        async fn connect_tcp(
            &self,
            _target: &TargetAddr,
        ) -> io::Result<proxy_core::outbound::BoxedStream> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Err(io::Error::new(io::ErrorKind::ConnectionRefused, "refused"))
        }
    }
    let proxy_hits = Arc::new(AtomicUsize::new(0));
    let counting_ob: DynOutbound = Arc::new(CountingProxy(Arc::clone(&proxy_hits)));
    let loopback_userinfo = format!("http://user:pass@127.0.0.1:{}/", canary_addr.port());
    for bad_remote in [
        loopback_userinfo.as_str(),
        "https://user:pass@example.com/data",
        "https://0.1.2.3/data",
        "https://[::127.0.0.1]/data",
        "https://[::ffff:0:127.0.0.1]/data",
        "https://[fec0::1]/data",
        "https://[100::1]/data",
        "https://10.0.0.1/data",
        "https://169.254.169.254/latest/meta-data/",
        "https://[fd00:ec2::254]/latest/meta-data/",
        "https://metadata.google.internal/computeMetadata/v1/",
    ] {
        assert!(
            fetch_http_bytes_protected_with_proxy(bad_remote, &[], Some(&counting_ob))
                .await
                .is_err(),
            "GeoData must reject {bad_remote}"
        );
        assert!(
            fetch_subscription_http_with_proxy(bad_remote, &[], Some(&counting_ob))
                .await
                .is_err(),
            "Subscription must reject {bad_remote}"
        );
    }
    assert_eq!(
        proxy_hits.load(Ordering::SeqCst),
        0,
        "SSRF/userinfo-blocked GeoData and subscription URLs must NEVER fall back through proxy"
    );
    assert_eq!(
        canary_hits.load(Ordering::SeqCst),
        0,
        "userinfo loopback URL must NEVER reach canary server"
    );

    let _ = bg_stop_tx.send(true);
    let _ = std::fs::remove_dir_all(&state_dir);
}

use std::{collections::HashMap, net::IpAddr, sync::Arc};

use axum::{Router as AxumRouter, routing::get};
use parking_lot::RwLock;
use proxy_core::{
    config::{DnsConfig, ProxyGroupConfig, ProxyGroupType, RunMode},
    dns::{
        FakeIpDnsEngine,
        wire::{DnsAnswerData, QTYPE_A, build_dns_query, extract_ip_answers},
    },
    inbound::mixed::spawn_mixed_inbound,
    outbound::{
        DynOutbound,
        vless::{
            VlessOutbound, VlessOutboundConfig, VlessServerConfig,
            encryption::{config::XorMode, generate_vless_encryption_pair},
            spawn_vless_server,
        },
    },
    router::Router,
    tracker::TelemetryHub,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::watch,
};
use uuid::Uuid;

#[tokio::test]
async fn fake_ip_dns_mixed_inbound_and_rule_engine_end_to_end() {
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // 1. Local HTTP origin server
    let origin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_addr = origin_listener.local_addr().unwrap();
    let app = AxumRouter::new().route("/hello", get(|| async { "HELLO-FROM-ORIGIN" }));
    let mut origin_stop = shutdown_rx.clone();
    tokio::spawn(async move {
        let _ = axum::serve(origin_listener, app)
            .with_graceful_shutdown(async move {
                let _ = origin_stop.changed().await;
            })
            .await;
    });

    // 2. Local VLESS+PQ server
    let uuid = Uuid::new_v4();
    let pq = generate_vless_encryption_pair(XorMode::Native, true, true).unwrap();
    let (vless_addr, _vless_task) = spawn_vless_server(
        VlessServerConfig {
            listen_addr: "127.0.0.1:0".into(),
            allowed_uuid: uuid,
            decryption: pq.decryption,
            tls_config: None,
        },
        shutdown_rx.clone(),
    )
    .await
    .unwrap();

    let vless_ob = Arc::new(
        VlessOutbound::new(VlessOutboundConfig {
            name: "PQ-Node".into(),
            server: "127.0.0.1".into(),
            port: vless_addr.port(),
            uuid,
            encryption: pq.encryption,
            tls: false,
            servername: None,
            skip_cert_verify: false,
            alpn: vec![],
            extra_ca_der: vec![],
            udp: true,
        })
        .unwrap(),
    );

    // 3. Fake-IP DNS server (empty filter so even `localhost` can be tested via assign_fake_ip, plus UDP DNS query test)
    let dns_cfg = DnsConfig {
        enable: true,
        listen: "127.0.0.1:0".into(),
        enhanced_mode: "fake-ip".into(),
        fake_ip_range: "198.18.0.0/15".into(),
        fake_ip_filter: vec!["*.lan".into()],
        nameserver: vec![],
        ..DnsConfig::default()
    };
    let dns_engine = Arc::new(FakeIpDnsEngine::new(&dns_cfg).unwrap());
    let (dns_bound, _dns_task) = Arc::clone(&dns_engine)
        .spawn_udp_server("127.0.0.1:0", shutdown_rx.clone())
        .await
        .unwrap();

    // Verify real UDP DNS query returns Fake-IP 198.18.0.2 for `api.github.com`
    let udp_cli = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let q_pkt = build_dns_query(0x99, "api.github.com", QTYPE_A);
    udp_cli.send_to(&q_pkt, dns_bound).await.unwrap();
    let mut dns_buf = [0u8; 512];
    let (n, _) = udp_cli.recv_from(&mut dns_buf).await.unwrap();
    let answers = extract_ip_answers(&dns_buf[..n]).unwrap();
    let DnsAnswerData::A(github_fake_ip) = answers[0] else {
        panic!("expected A record");
    };
    assert!(dns_engine.is_fake_ip(IpAddr::V4(github_fake_ip)));

    // Also map a Fake-IP for `"localhost"` so the VLESS outbound server can connect to `localhost:<origin_port>`!
    let localhost_fake_ip = dns_engine.assign_fake_ip("localhost");

    // 4. Router with `DOMAIN`, `DOMAIN-SUFFIX`, and `MATCH` rules
    let mut outbounds: HashMap<String, DynOutbound> = HashMap::new();
    outbounds.insert("PQ-Node".into(), vless_ob);
    let groups = vec![ProxyGroupConfig {
        name: "ProxyGroup".into(),
        group_type: ProxyGroupType::Select,
        proxies: vec!["PQ-Node".into(), "DIRECT".into()],
        url: format!("http://{origin_addr}/hello"),
        interval: 60,
        tolerance: 30,
        strategy: None,
    }];
    let rules = vec![
        "DOMAIN,blocked.example.com,REJECT".to_string(),
        "DOMAIN,localhost,ProxyGroup".to_string(),
        "MATCH,DIRECT".to_string(),
    ];
    let router =
        Arc::new(Router::new(RunMode::Rule, outbounds, &groups, &rules, dns_engine).unwrap());
    let router_slot = Arc::new(RwLock::new(Arc::clone(&router)));
    let hub = Arc::new(TelemetryHub::new());

    let (mixed_addr, _mixed_task) = spawn_mixed_inbound(
        "127.0.0.1:0",
        Arc::clone(&router_slot),
        Arc::clone(&hub),
        shutdown_rx.clone(),
    )
    .await
    .unwrap();

    // Test A: SOCKS5 TCP CONNECT to Fake-IP `localhost_fake_ip:<origin_port>` -> restores `localhost` -> matches `DOMAIN,localhost,ProxyGroup` -> tunnels via VLESS+PQ!
    {
        let mut s = TcpStream::connect(mixed_addr).await.unwrap();
        s.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut greet = [0u8; 2];
        s.read_exact(&mut greet).await.unwrap();
        assert_eq!(greet, [0x05, 0x00]);

        let mut req = vec![0x05, 0x01, 0x00, 0x01];
        req.extend_from_slice(&localhost_fake_ip.octets());
        req.extend_from_slice(&origin_addr.port().to_be_bytes());
        s.write_all(&req).await.unwrap();
        let mut rep = [0u8; 10];
        s.read_exact(&mut rep).await.unwrap();
        assert_eq!(rep[1], 0x00);

        s.write_all(b"GET /hello HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut http_resp = String::new();
        s.read_to_string(&mut http_resp).await.unwrap();
        assert!(http_resp.contains("HELLO-FROM-ORIGIN"));
    }

    // Verify rule hit counter incremented!
    let rule_snaps = router.rules_snapshot();
    assert_eq!(rule_snaps[1].hits, 1);

    // Test B: HTTP `CONNECT` tunnel over the exact same Mixed Inbound port!
    {
        let mut s = TcpStream::connect(mixed_addr).await.unwrap();
        let connect_cmd = format!(
            "CONNECT {localhost_fake_ip}:{} HTTP/1.1\r\nHost: {localhost_fake_ip}:{}\r\n\r\n",
            origin_addr.port(),
            origin_addr.port()
        );
        s.write_all(connect_cmd.as_bytes()).await.unwrap();
        let mut buf = [0u8; 128];
        let n = s.read(&mut buf).await.unwrap();
        let status_line = String::from_utf8_lossy(&buf[..n]);
        assert!(
            status_line.contains("200 Connection Established"),
            "unexpected HTTP CONNECT reply: {status_line}"
        );

        s.write_all(b"GET /hello HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut http_resp = String::new();
        s.read_to_string(&mut http_resp).await.unwrap();
        assert!(http_resp.contains("HELLO-FROM-ORIGIN"));
    }
    assert_eq!(router.rules_snapshot()[1].hits, 2);

    // Test C: Plain HTTP Proxy request (`GET http://... HTTP/1.1`) over Mixed Inbound!
    {
        let mut s = TcpStream::connect(mixed_addr).await.unwrap();
        let plain_http = format!(
            "GET http://localhost:{}/hello HTTP/1.1\r\nHost: localhost:{}\r\nConnection: close\r\n\r\n",
            origin_addr.port(),
            origin_addr.port()
        );
        s.write_all(plain_http.as_bytes()).await.unwrap();
        let mut http_resp = String::new();
        s.read_to_string(&mut http_resp).await.unwrap();
        assert!(http_resp.contains("HELLO-FROM-ORIGIN"));
    }
    assert_eq!(router.rules_snapshot()[1].hits, 3);

    let _ = shutdown_tx.send(true);
}

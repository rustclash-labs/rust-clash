use std::{sync::Arc, time::Duration};

use base64::{Engine, engine::general_purpose::STANDARD};
use proxy_core::{
    addr::TargetAddr,
    crypto::tls::generate_self_signed_server_config,
    outbound::{
        OutboundHandler,
        anytls::{
            AnyTlsOutbound, AnyTlsOutboundConfig, AnyTlsServerConfig, padding::PaddingScheme,
            spawn_anytls_server,
        },
        ss::{ShadowsocksOutbound, spawn_ss_server},
        vless::{
            VlessOutbound, VlessOutboundConfig, VlessServerConfig,
            encryption::{config::XorMode, generate_vless_encryption_pair},
            spawn_vless_server,
        },
    },
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
    sync::watch,
};
use uuid::Uuid;

async fn spawn_echo_servers(
    mut shutdown: watch::Receiver<bool>,
) -> (std::net::SocketAddr, std::net::SocketAddr) {
    let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tcp_addr = tcp_listener.local_addr().unwrap();
    let mut tcp_stop = shutdown.clone();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = tcp_stop.changed() => break,
                res = tcp_listener.accept() => {
                    let Ok((mut sock, _)) = res else { continue };
                    tokio::spawn(async move {
                        let mut buf = vec![0u8; 32 * 1024];
                        while let Ok(n) = sock.read(&mut buf).await {
                            if n == 0 || sock.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    });
                }
            }
        }
    });

    let udp_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let udp_addr = udp_sock.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            tokio::select! {
                _ = shutdown.changed() => break,
                res = udp_sock.recv_from(&mut buf) => {
                    let Ok((n, peer)) = res else { continue };
                    let mut reply = b"UDP-ECHO:".to_vec();
                    reply.extend_from_slice(&buf[..n]);
                    let _ = udp_sock.send_to(&reply, peer).await;
                }
            }
        }
    });

    (tcp_addr, udp_addr)
}

#[tokio::test]
async fn shadowsocks_aead_and_ss2022_tcp_and_udp_roundtrip() {
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (tcp_echo, udp_echo) = spawn_echo_servers(shutdown_rx.clone()).await;

    let cases = [
        ("aes-128-gcm", "legacy-pass-128".to_string()),
        ("aes-256-gcm", "legacy-pass-256".to_string()),
        ("chacha20-ietf-poly1305", "legacy-pass-chacha".to_string()),
        ("2022-blake3-aes-128-gcm", STANDARD.encode([0x11u8; 16])),
        ("2022-blake3-aes-256-gcm", STANDARD.encode([0x22u8; 32])),
        (
            "2022-blake3-chacha20-poly1305",
            STANDARD.encode([0x33u8; 32]),
        ),
    ];

    let tcp_target = TargetAddr::from(tcp_echo);
    let udp_target = TargetAddr::from(udp_echo);

    for (cipher, password) in cases {
        let (srv_addr, _srv_task) =
            spawn_ss_server("127.0.0.1:0", cipher, &password, shutdown_rx.clone())
                .await
                .expect("spawn_ss_server");

        let client = ShadowsocksOutbound::new(
            format!("test-{cipher}"),
            "127.0.0.1",
            srv_addr.port(),
            cipher,
            &password,
            true,
        )
        .expect("ShadowsocksOutbound::new");

        // 1. Multi-chunk 128 KB TCP echo integrity test
        let mut stream = client
            .connect_tcp(&tcp_target)
            .await
            .expect("SS TCP connect");
        let payload: Vec<u8> = (0..131_072).map(|i| ((i * 73 + 19) & 0xFF) as u8).collect();
        stream.write_all(&payload).await.expect("SS TCP write");
        stream.flush().await.expect("SS TCP flush");

        let mut echoed = vec![0u8; payload.len()];
        stream
            .read_exact(&mut echoed)
            .await
            .expect("SS TCP read_exact");
        assert_eq!(echoed, payload, "TCP payload mismatch for cipher {cipher}");

        // 2. UDP datagram roundtrip test
        let udp_msg = format!("hello-udp-over-{cipher}");
        let udp_resp = client
            .exchange_udp(&udp_target, udp_msg.as_bytes(), Duration::from_secs(3))
            .await
            .expect("SS UDP exchange");
        assert_eq!(
            udp_resp,
            format!("UDP-ECHO:{udp_msg}").into_bytes(),
            "UDP payload mismatch for cipher {cipher}"
        );
    }

    let _ = shutdown_tx.send(true);
}

#[tokio::test]
async fn vless_mlkem768x25519plus_all_modes_1rtt_0rtt_and_udp() {
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (tcp_echo, udp_echo) = spawn_echo_servers(shutdown_rx.clone()).await;
    let tcp_target = TargetAddr::from(tcp_echo);
    let udp_target = TargetAddr::from(udp_echo);

    for (mode, enable_0rtt) in [
        (XorMode::Native, true),
        (XorMode::XorPub, false),
        (XorMode::Random, true),
    ] {
        let uuid = Uuid::new_v4();
        let pair = generate_vless_encryption_pair(mode, enable_0rtt, true).unwrap();

        let (srv_addr, _srv_task) = spawn_vless_server(
            VlessServerConfig {
                listen_addr: "127.0.0.1:0".into(),
                allowed_uuid: uuid,
                decryption: pair.decryption.clone(),
                tls_config: None,
            },
            shutdown_rx.clone(),
        )
        .await
        .expect("spawn_vless_server");

        let outbound = VlessOutbound::new(VlessOutboundConfig {
            name: format!("vless-{}", mode.as_str()),
            server: "127.0.0.1".into(),
            port: srv_addr.port(),
            uuid,
            encryption: pair.encryption.clone(),
            tls: false,
            servername: None,
            skip_cert_verify: false,
            alpn: vec![],
            extra_ca_der: vec![],
            udp: true,
        })
        .expect("VlessOutbound::new");

        assert!(!outbound.has_valid_0rtt_ticket());

        // Connection #1: Full 1-RTT Post-Quantum (X25519 + ML-KEM-768) handshake
        {
            let mut s1 = outbound
                .connect_tcp(&tcp_target)
                .await
                .expect("VLESS 1-RTT connect");
            let data1: Vec<u8> = (0..98_304).map(|i| ((i * 29 + 7) & 0xFF) as u8).collect();
            s1.write_all(&data1).await.unwrap();
            s1.flush().await.unwrap();
            let mut recv1 = vec![0u8; data1.len()];
            s1.read_exact(&mut recv1).await.unwrap();
            assert_eq!(
                recv1,
                data1,
                "1-RTT data mismatch in mode {}",
                mode.as_str()
            );
        }

        if enable_0rtt {
            assert!(
                outbound.has_valid_0rtt_ticket(),
                "0-RTT ticket must be cached after 1-RTT handshake in mode {}",
                mode.as_str()
            );

            // Connection #2: Exercises 0-RTT Session Ticket Resumption!
            let mut s2 = outbound
                .connect_tcp(&tcp_target)
                .await
                .expect("VLESS 0-RTT connect");
            let data2: Vec<u8> = (0..65_536).map(|i| ((i * 53 + 11) & 0xFF) as u8).collect();
            s2.write_all(&data2).await.unwrap();
            s2.flush().await.unwrap();
            let mut recv2 = vec![0u8; data2.len()];
            s2.read_exact(&mut recv2).await.unwrap();
            assert_eq!(
                recv2,
                data2,
                "0-RTT data mismatch in mode {}",
                mode.as_str()
            );
        }

        // VLESS UDP framing over encrypted PQ stream
        let udp_resp = outbound
            .exchange_udp(&udp_target, b"vless-pq-udp-ping", Duration::from_secs(3))
            .await
            .expect("VLESS UDP exchange");
        assert_eq!(udp_resp, b"UDP-ECHO:vless-pq-udp-ping");
    }

    let _ = shutdown_tx.send(true);
}

#[tokio::test]
async fn anytls_v2_dynamic_padding_and_lifo_session_pool_reuse() {
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (tcp_echo, _udp_echo) = spawn_echo_servers(shutdown_rx.clone()).await;
    let tcp_target = TargetAddr::from(tcp_echo);

    let (server_tls_cfg, ca_der) = generate_self_signed_server_config(
        &["anytls.test.local".to_string(), "127.0.0.1".to_string()],
        &[b"h2".to_vec()],
    )
    .unwrap();

    // Custom server PaddingScheme including `'c'` check-stop rule so server pushes `cmdUpdatePaddingScheme`!
    let custom_scheme_text =
        "stop=6\n0=20-60\n1=80-200\n2=200-350,c,400-700\n3=300-600\n4=300-600\n5=300-600";
    let server_scheme = PaddingScheme::parse(custom_scheme_text).unwrap();
    let expected_server_md5 = server_scheme.md5_hex().to_string();

    let (srv_addr, _srv_task) = spawn_anytls_server(
        AnyTlsServerConfig {
            listen_addr: "127.0.0.1:0".into(),
            password: "anytls-super-secret".into(),
            tls_config: server_tls_cfg,
            padding_scheme: server_scheme,
        },
        shutdown_rx.clone(),
    )
    .await
    .unwrap();

    let client = AnyTlsOutbound::new(AnyTlsOutboundConfig {
        name: "anytls-node".into(),
        server: "127.0.0.1".into(),
        port: srv_addr.port(),
        password: "anytls-super-secret".into(),
        sni: "anytls.test.local".into(),
        skip_cert_verify: false,
        alpn: vec![b"h2".to_vec()],
        extra_ca_der: vec![ca_der],
        idle_session_check_interval: Duration::from_secs(30),
        idle_session_timeout: Duration::from_secs(60),
        min_idle_session: 2,
        udp: true,
    })
    .unwrap();

    // Hold two concurrent streams open to force creation of Session #1 and Session #2
    let mut st_a = client.connect_anytls_stream(&tcp_target).await.unwrap();
    let mut st_b = client.connect_anytls_stream(&tcp_target).await.unwrap();
    assert_eq!(st_a.session_seq(), 1);
    assert_eq!(st_b.session_seq(), 2);

    st_a.write_all(b"stream-A-payload").await.unwrap();
    st_b.write_all(b"stream-B-payload").await.unwrap();
    let mut out_a = [0u8; 16];
    let mut out_b = [0u8; 16];
    st_a.read_exact(&mut out_a).await.unwrap();
    st_b.read_exact(&mut out_b).await.unwrap();
    assert_eq!(&out_a, b"stream-A-payload");
    assert_eq!(&out_b, b"stream-B-payload");

    // Verify dynamic `cmdUpdatePaddingScheme` updated client's MD5!
    assert_eq!(client.current_padding_md5(), expected_server_md5);

    // Drop Session #1 first, then Session #2 -> both enter idle pool (`idle_count() == 2`)
    drop(st_a);
    drop(st_b);
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(client.pool().idle_count(), 2);

    // Open a 3rd stream -> LIFO `SessionPool` MUST reuse highest-Seq Session #2 (`stream_id == 2`)!
    let mut st_c = client.connect_anytls_stream(&tcp_target).await.unwrap();
    assert_eq!(
        st_c.session_seq(),
        2,
        "AnyTLS SessionPool must pick highest-Seq idle session (LIFO)"
    );
    assert_eq!(st_c.stream_id(), 2);

    let big: Vec<u8> = (0..65_536).map(|i| (i & 0xFF) as u8).collect();
    st_c.write_all(&big).await.unwrap();
    let mut big_echo = vec![0u8; big.len()];
    st_c.read_exact(&mut big_echo).await.unwrap();
    assert_eq!(big_echo, big);
    drop(st_c);

    let _ = shutdown_tx.send(true);
}

/// Verifies:
/// 1. Stateful persistent `OutboundUdpSession` handles 1-to-N QUIC-like multi-datagram server bursts
///    while preserving exact NAT client source port across Direct, Shadowsocks-2022, VLESS+PQ, and AnyTLS v2!
/// 2. `SocketProtector` (`CallbackSocketProtector`) intercepts 100% of outbound TCP & UDP sockets!
#[tokio::test]
async fn stateful_quic_burst_udp_sessions_and_socket_protector_e2e() {
    use proxy_core::platform::socket_protect::{
        CallbackSocketProtector, SocketProtector, clear_global_socket_protector,
        set_global_socket_protector,
    };
    use std::sync::Arc;

    let protector = Arc::new(CallbackSocketProtector::counting("test-vpn-protect", true));
    set_global_socket_protector(protector.clone());

    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);

    // Spawn a QUIC-flight-style UDP server: for each client datagram, replies with 3 separate datagrams
    // embedding the observed client NAT port so we prove NAT port persistence across multiple flights!
    let quic_srv = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let quic_addr = quic_srv.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => break,
                res = quic_srv.recv_from(&mut buf) => {
                    let Ok((n, peer)) = res else { break };
                    let req = String::from_utf8_lossy(&buf[..n]).into_owned();
                    for flight in 0..3 {
                        let pkt = format!("PORT={}:FLIGHT={flight}:REQ={req}", peer.port());
                        let _ = quic_srv.send_to(pkt.as_bytes(), peer).await;
                    }
                }
            }
        }
    });

    let psk = STANDARD.encode([0x55u8; 32]);
    let (ss_addr, _ss_task) = spawn_ss_server(
        "127.0.0.1:0",
        "2022-blake3-aes-256-gcm",
        &psk,
        shutdown_tx.subscribe(),
    )
    .await
    .unwrap();
    let ss_out: Arc<dyn OutboundHandler> = Arc::new(
        ShadowsocksOutbound::new(
            "ss2022-udp",
            "127.0.0.1",
            ss_addr.port(),
            "2022-blake3-aes-256-gcm",
            &psk,
            true,
        )
        .unwrap(),
    );

    let uuid = Uuid::new_v4();
    let pair = generate_vless_encryption_pair(XorMode::Native, true, false).unwrap();
    let (vless_addr, _vless_task) = spawn_vless_server(
        VlessServerConfig {
            listen_addr: "127.0.0.1:0".into(),
            allowed_uuid: uuid,
            decryption: pair.decryption,
            tls_config: None,
        },
        shutdown_tx.subscribe(),
    )
    .await
    .unwrap();
    let vless_out: Arc<dyn OutboundHandler> = Arc::new(
        VlessOutbound::new(VlessOutboundConfig {
            name: "vless-pq-udp".into(),
            server: "127.0.0.1".into(),
            port: vless_addr.port(),
            uuid,
            encryption: pair.encryption,
            tls: false,
            servername: None,
            skip_cert_verify: false,
            alpn: vec![],
            extra_ca_der: vec![],
            udp: true,
        })
        .unwrap(),
    );

    let (tls_cfg, ca_der) =
        generate_self_signed_server_config(&["127.0.0.1".to_string()], &[]).unwrap();
    let (anytls_addr, _anytls_task) = spawn_anytls_server(
        AnyTlsServerConfig {
            listen_addr: "127.0.0.1:0".into(),
            password: "uot-pw".into(),
            tls_config: tls_cfg,
            padding_scheme: PaddingScheme::default(),
        },
        shutdown_tx.subscribe(),
    )
    .await
    .unwrap();
    let anytls_out: Arc<dyn OutboundHandler> = Arc::new(
        AnyTlsOutbound::new(AnyTlsOutboundConfig {
            name: "anytls-uot".into(),
            server: "127.0.0.1".into(),
            port: anytls_addr.port(),
            password: "uot-pw".into(),
            sni: "127.0.0.1".into(),
            skip_cert_verify: false,
            alpn: vec![],
            extra_ca_der: vec![ca_der],
            idle_session_check_interval: Duration::from_secs(30),
            idle_session_timeout: Duration::from_secs(60),
            min_idle_session: 1,
            udp: true,
        })
        .unwrap(),
    );

    let direct_out: Arc<dyn OutboundHandler> =
        Arc::new(proxy_core::outbound::DirectOutbound::default());
    let target = TargetAddr::from(quic_addr);

    for ob in [direct_out, ss_out, vless_out, anytls_out] {
        let sess = ob.open_udp_session().await.unwrap();
        let mut observed_nat_port: Option<String> = None;

        for round in 0..2 {
            let msg = format!("quic-chlo-{round}");
            sess.send_to(msg.as_bytes(), &target).await.unwrap();
            for expected_flight in 0..3 {
                let (resp, _src) = tokio::time::timeout(Duration::from_secs(5), sess.recv_from())
                    .await
                    .unwrap_or_else(|_| {
                        panic!(
                            "timeout on {} round {round} flight {expected_flight}",
                            ob.name()
                        )
                    })
                    .unwrap();
                let text = String::from_utf8(resp).unwrap();
                let port_part = text
                    .strip_prefix("PORT=")
                    .and_then(|s| s.split(':').next())
                    .expect("PORT=... prefix")
                    .to_string();
                if let Some(ref prev_port) = observed_nat_port {
                    assert_eq!(
                        &port_part,
                        prev_port,
                        "NAT port changed across multi-packet flight on {}!",
                        ob.name()
                    );
                } else {
                    observed_nat_port = Some(port_part);
                }
                assert!(
                    text.ends_with(&format!("FLIGHT={expected_flight}:REQ={msg}")),
                    "unexpected flight body '{text}' on {}",
                    ob.name()
                );
            }
        }
    }

    assert!(
        protector.tcp_count() >= 2 && protector.udp_count() >= 2,
        "SocketProtector must be invoked on outbound TCP & UDP sockets (got {})",
        protector.description()
    );
    clear_global_socket_protector();
    let _ = shutdown_tx.send(true);
}

async fn socks5_tcp_echo(
    socks_addr: std::net::SocketAddr,
    target: std::net::SocketAddr,
    payload: &[u8],
) -> Vec<u8> {
    let mut s = tokio::net::TcpStream::connect(socks_addr)
        .await
        .expect("connect MixedInbound SOCKS5");
    s.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut m = [0u8; 2];
    s.read_exact(&mut m).await.unwrap();
    assert_eq!(m, [0x05, 0x00]);

    let std::net::SocketAddr::V4(v4) = target else {
        panic!("expected IPv4 target");
    };
    let mut req = Vec::with_capacity(10);
    req.extend_from_slice(&[0x05, 0x01, 0x00, 0x01]);
    req.extend_from_slice(&v4.ip().octets());
    req.extend_from_slice(&v4.port().to_be_bytes());
    s.write_all(&req).await.unwrap();

    let mut hdr = [0u8; 10];
    s.read_exact(&mut hdr).await.unwrap();
    assert_eq!(hdr[0], 0x05);
    assert_eq!(hdr[1], 0x00, "SOCKS5 CONNECT failed: 0x{:02x}", hdr[1]);

    s.write_all(payload).await.unwrap();
    s.flush().await.unwrap();
    let mut out = vec![0u8; payload.len()];
    s.read_exact(&mut out).await.unwrap();
    out
}

async fn socks5_udp_echo(
    socks_addr: std::net::SocketAddr,
    target: std::net::SocketAddr,
    payload: &[u8],
) -> Vec<u8> {
    let mut ctrl = tokio::net::TcpStream::connect(socks_addr)
        .await
        .expect("connect MixedInbound SOCKS5 UDP control");
    ctrl.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut m = [0u8; 2];
    ctrl.read_exact(&mut m).await.unwrap();
    assert_eq!(m, [0x05, 0x00]);

    ctrl.write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await
        .unwrap();
    let mut hdr = [0u8; 10];
    ctrl.read_exact(&mut hdr).await.unwrap();
    assert_eq!(hdr[0], 0x05);
    assert_eq!(
        hdr[1], 0x00,
        "SOCKS5 UDP ASSOCIATE failed: 0x{:02x}",
        hdr[1]
    );
    let ip = std::net::Ipv4Addr::new(hdr[4], hdr[5], hdr[6], hdr[7]);
    let port = u16::from_be_bytes([hdr[8], hdr[9]]);
    let relay_ip = if ip.is_unspecified() {
        std::net::Ipv4Addr::LOCALHOST
    } else {
        ip
    };
    let relay_addr = std::net::SocketAddr::from((relay_ip, port));

    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let std::net::SocketAddr::V4(v4) = target else {
        panic!("expected IPv4 target");
    };
    let mut pkt = Vec::with_capacity(10 + payload.len());
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
    pkt.extend_from_slice(&v4.ip().octets());
    pkt.extend_from_slice(&v4.port().to_be_bytes());
    pkt.extend_from_slice(payload);
    udp.send_to(&pkt, relay_addr).await.unwrap();

    let mut resp = vec![0u8; 65535];
    let (n, _) = tokio::time::timeout(Duration::from_secs(5), udp.recv_from(&mut resp))
        .await
        .expect("SOCKS5 UDP echo timeout")
        .unwrap();
    assert!(n >= 10 && resp[2] == 0x00);
    drop(ctrl);
    resp[10..n].to_vec()
}

async fn start_global_engine_with_uris(uris: &[String]) -> Arc<proxy_core::engine::ProxyEngine> {
    use proxy_core::config::{
        ClashConfig, ProxyGroupConfig, ProxyGroupType, RunMode,
        uri::{export_proxy_uri, parse_proxy_uri, parse_subscription_uris},
    };

    let joined = uris.join("\n");
    let nodes = parse_subscription_uris(&joined).expect("parse_subscription_uris");
    assert_eq!(nodes.len(), uris.len());

    for node in &nodes {
        let exported = export_proxy_uri(node);
        let reparsed = parse_proxy_uri(&exported).expect("re-parse exported URI");
        assert_eq!(reparsed.name(), node.name());
    }

    let names: Vec<String> = nodes.iter().map(|n| n.name().to_string()).collect();
    let mut cfg = ClashConfig {
        mixed_port: 0,
        mode: RunMode::Global,
        proxies: nodes,
        proxy_groups: vec![ProxyGroupConfig {
            name: "PROXY".into(),
            group_type: ProxyGroupType::Select,
            proxies: names,
            url: "http://www.gstatic.com/generate_204".into(),
            interval: 300,
            tolerance: 50,
            strategy: None,
        }],
        rules: vec!["MATCH,PROXY".into()],
        ..Default::default()
    };
    cfg.dns.listen = "127.0.0.1:0".into();

    proxy_core::engine::ProxyEngine::start(cfg)
        .await
        .expect("start ProxyEngine")
}

#[tokio::test]
async fn vmess_aead_tcp_ws_tls_and_udp_full_stack_e2e() {
    use proxy_core::outbound::{
        vmess::{VmessOutbound, VmessOutboundConfig, crypto::VmessSecurity, spawn_vmess_server},
        ws_stream::WsTransportConfig,
    };

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (tcp_echo, udp_echo) = spawn_echo_servers(shutdown_rx.clone()).await;

    let uuid = Uuid::new_v4();
    let plain_srv = spawn_vmess_server("127.0.0.1:0".parse().unwrap(), uuid, None, None)
        .await
        .expect("spawn_vmess_server plain");

    let sni = "vmess.e2e.local";
    let (tls_cfg, ca_der) = generate_self_signed_server_config(
        &[sni.to_string(), "127.0.0.1".to_string()],
        &[b"http/1.1".to_vec()],
    )
    .unwrap();
    let ws_tls_srv = spawn_vmess_server(
        "127.0.0.1:0".parse().unwrap(),
        uuid,
        Some(tls_cfg),
        Some("/vmess-ws".into()),
    )
    .await
    .expect("spawn_vmess_server ws+tls");

    // 1. Direct verified-CA (`skip_cert_verify: false`) VMess WS+TLS + Early Data check
    let verified_client = VmessOutbound::new_with_transport(
        VmessOutboundConfig {
            name: "vmess-verified-ws".into(),
            server: "127.0.0.1".into(),
            port: ws_tls_srv.listen_addr.port(),
            uuid,
            security: VmessSecurity::Chacha20Poly1305,
            global_padding: true,
            tls: true,
            servername: Some(sni.into()),
            skip_cert_verify: false,
            alpn: vec![b"http/1.1".to_vec()],
            extra_ca_der: vec![ca_der],
            udp: true,
        },
        Some(WsTransportConfig {
            path: "/vmess-ws".into(),
            headers: std::collections::HashMap::from([("Host".into(), sni.into())]),
            max_early_data: Some(2048),
            early_data_header_name: Some("Sec-WebSocket-Protocol".into()),
        }),
        None,
    )
    .unwrap();
    let mut s = verified_client
        .connect_tcp(&TargetAddr::from(tcp_echo))
        .await
        .unwrap();
    s.write_all(b"vmess-verified-early-data").await.unwrap();
    s.flush().await.unwrap();
    let mut buf = [0u8; 25];
    s.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"vmess-verified-early-data");
    drop(s);

    // 2. Full-stack URI -> ProxyEngine -> MixedInbound (v2rayN Base64-JSON + standard vmess:// URI)
    let v2rayn_json = serde_json::json!({
        "v": "2",
        "ps": "vmess-aes-tcp",
        "add": "127.0.0.1",
        "port": plain_srv.listen_addr.port().to_string(),
        "id": uuid.to_string(),
        "aid": "0",
        "scy": "aes-128-gcm",
        "net": "tcp",
        "type": "none",
        "tls": ""
    });
    let uri_tcp = format!("vmess://{}", STANDARD.encode(v2rayn_json.to_string()));
    let uri_ws = format!(
        "vmess://{uuid}@127.0.0.1:{}?encryption=chacha20-poly1305&type=ws&path=%2Fvmess-ws%3Fed%3D2048&host={sni}&security=tls&sni={sni}&allowInsecure=1#vmess-chacha-ws",
        ws_tls_srv.listen_addr.port()
    );

    let engine = start_global_engine_with_uris(&[uri_tcp, uri_ws]).await;
    let mixed = engine.mixed_addr();
    let big_payload: Vec<u8> = (0..131_072).map(|i| ((i * 41 + 7) & 0xFF) as u8).collect();

    for node_name in ["vmess-aes-tcp", "vmess-chacha-ws"] {
        engine.router().select_group("GLOBAL", node_name).unwrap();
        let echoed = socks5_tcp_echo(mixed, tcp_echo, &big_payload).await;
        assert_eq!(
            echoed, big_payload,
            "VMess full-stack TCP mismatch on {node_name}"
        );

        let udp_msg = format!("vmess-fullstack-udp-{node_name}");
        let udp_echoed = socks5_udp_echo(mixed, udp_echo, udp_msg.as_bytes()).await;
        assert_eq!(
            udp_echoed,
            format!("UDP-ECHO:{udp_msg}").into_bytes(),
            "VMess full-stack UDP mismatch on {node_name}"
        );
    }

    engine.shutdown_async().await;
    plain_srv.shutdown().await;
    ws_tls_srv.shutdown().await;
    let _ = shutdown_tx.send(true);
}

#[tokio::test]
async fn vless_reality_xtls_vision_inner_tls13_splice_http_and_xudp_full_stack_e2e() {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use proxy_core::outbound::vless::{
        VlessRealityServerConfig, spawn_vless_reality_vision_server,
    };
    use tokio_rustls::{TlsAcceptor, TlsConnector};
    use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519Secret};

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (tcp_echo, udp_echo) = spawn_echo_servers(shutdown_rx.clone()).await;

    // Also spawn a real TLS 1.3 origin echo server so `xtls-rprx-vision` detects inner TLS 1.3
    // and transitions into `CMD_PADDING_DIRECT` zero-copy splice mode!
    let inner_sni = "inner-origin.vision.local";
    let (inner_tls_srv_cfg, inner_ca_der) = generate_self_signed_server_config(
        &[inner_sni.to_string(), "127.0.0.1".to_string()],
        &[b"h2".to_vec()],
    )
    .unwrap();
    let inner_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let inner_tls_addr = inner_listener.local_addr().unwrap();
    let inner_acceptor = TlsAcceptor::from(inner_tls_srv_cfg);
    let mut inner_stop = shutdown_rx.clone();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = inner_stop.changed() => break,
                res = inner_listener.accept() => {
                    let Ok((tcp, _)) = res else { continue };
                    let acceptor = inner_acceptor.clone();
                    tokio::spawn(async move {
                        let Ok(mut tls) = acceptor.accept(tcp).await else { return };
                        let mut buf = vec![0u8; 32 * 1024];
                        while let Ok(n) = tls.read(&mut buf).await {
                            if n == 0 || tls.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    });
                }
            }
        }
    });

    let uuid = Uuid::new_v4();
    let priv_bytes = [0x5Au8; 32];
    let secret = X25519Secret::from(priv_bytes);
    let pub_b64 = URL_SAFE_NO_PAD.encode(X25519PublicKey::from(&secret).as_bytes());
    let short_id = [0xde, 0xad, 0xbe, 0xef, 0x01, 0x23, 0x45, 0x67];
    let sid_hex = hex::encode(short_id);
    let reality_sni = "www.microsoft.com";

    let (reality_addr, _reality_task) = spawn_vless_reality_vision_server(
        VlessRealityServerConfig {
            listen_addr: "127.0.0.1:0".into(),
            allowed_uuid: uuid,
            reality_private_key: priv_bytes,
            reality_short_id: short_id,
            reality_server_name: reality_sni.into(),
        },
        shutdown_rx.clone(),
    )
    .await
    .expect("spawn_vless_reality_vision_server");

    let uri = format!(
        "vless://{uuid}@127.0.0.1:{}?security=reality&encryption=none&pbk={pub_b64}&sid={sid_hex}&sni={reality_sni}&fp=chrome&flow=xtls-rprx-vision#vless-reality-vision",
        reality_addr.port()
    );
    let engine = start_global_engine_with_uris(&[uri]).await;
    let mixed = engine.mixed_addr();

    // 1. Plain HTTP/TCP payload over Vision (`CMD_PADDING_CONTINUE` -> `CMD_PADDING_END`)
    let plain_payload: Vec<u8> = (0..65_536).map(|i| ((i * 31 + 3) & 0xFF) as u8).collect();
    let plain_echo = socks5_tcp_echo(mixed, tcp_echo, &plain_payload).await;
    assert_eq!(
        plain_echo, plain_payload,
        "VLESS REALITY Vision plain TCP mismatch"
    );

    // 2. Nested TLS 1.3 handshake over Vision (`CMD_PADDING_DIRECT` splice!)
    let mut socks_stream = tokio::net::TcpStream::connect(mixed).await.unwrap();
    socks_stream.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut m = [0u8; 2];
    socks_stream.read_exact(&mut m).await.unwrap();
    assert_eq!(m, [0x05, 0x00]);
    let std::net::SocketAddr::V4(v4) = inner_tls_addr else {
        unreachable!();
    };
    let mut req = vec![0x05, 0x01, 0x00, 0x01];
    req.extend_from_slice(&v4.ip().octets());
    req.extend_from_slice(&v4.port().to_be_bytes());
    socks_stream.write_all(&req).await.unwrap();
    let mut rep = [0u8; 10];
    socks_stream.read_exact(&mut rep).await.unwrap();
    assert_eq!(rep[1], 0x00);

    let inner_client_cfg =
        proxy_core::crypto::tls::build_tls_client_config(false, &[inner_ca_der], &[b"h2".to_vec()])
            .unwrap();
    let connector = TlsConnector::from(inner_client_cfg);
    let sni_name = proxy_core::crypto::tls::parse_server_name(inner_sni).unwrap();
    let mut nested_tls = connector
        .connect(sni_name, socks_stream)
        .await
        .expect("nested TLS 1.3 handshake through VLESS REALITY Vision");
    let splice_payload: Vec<u8> = (0..131_072).map(|i| ((i * 67 + 19) & 0xFF) as u8).collect();
    nested_tls.write_all(&splice_payload).await.unwrap();
    nested_tls.flush().await.unwrap();
    let mut splice_echo = vec![0u8; splice_payload.len()];
    nested_tls.read_exact(&mut splice_echo).await.unwrap();
    assert_eq!(
        splice_echo, splice_payload,
        "VLESS REALITY Vision nested TLS 1.3 splice mismatch"
    );
    drop(nested_tls);

    // 3. XUDP (`v1.mux.cool:666`) UDP datagrams over Vision + REALITY
    for seq in 0..3 {
        let msg = format!("xudp-over-reality-vision-{seq}");
        let echoed = socks5_udp_echo(mixed, udp_echo, msg.as_bytes()).await;
        assert_eq!(echoed, format!("UDP-ECHO:{msg}").into_bytes());
    }

    engine.shutdown_async().await;
    let _ = shutdown_tx.send(true);
}

#[tokio::test]
async fn hysteria2_plain_salamander_mport_and_fragmented_udp_full_stack_e2e() {
    use proxy_core::outbound::hysteria2::{
        Hysteria2Outbound, Hysteria2OutboundConfig, spawn_hysteria2_server,
    };

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (tcp_echo, udp_echo) = spawn_echo_servers(shutdown_rx.clone()).await;

    let sni = "hy2.e2e.local";
    let (tls_plain, ca_plain) = generate_self_signed_server_config(
        &[sni.to_string(), "127.0.0.1".to_string()],
        &[b"h3".to_vec()],
    )
    .unwrap();
    let (tls_obfs, _ca_obfs) = generate_self_signed_server_config(
        &[sni.to_string(), "127.0.0.1".to_string()],
        &[b"h3".to_vec()],
    )
    .unwrap();

    let hy2_pass = "hy2-auth-secret-2026";
    let obfs_pass = "salamander-psk-2026";

    let srv_plain = spawn_hysteria2_server(
        "127.0.0.1:0".parse().unwrap(),
        hy2_pass.into(),
        tls_plain,
        None,
    )
    .await
    .expect("spawn_hysteria2_server plain");

    let srv_obfs = spawn_hysteria2_server(
        "127.0.0.1:0".parse().unwrap(),
        hy2_pass.into(),
        tls_obfs,
        Some(obfs_pass.into()),
    )
    .await
    .expect("spawn_hysteria2_server salamander");

    // 1. Direct verified-CA (`skip_cert_verify: false`) + port-hopping (`ports` single-port range) check
    let p = srv_plain.listen_addr.port();
    let verified_hy2 = Hysteria2Outbound::new(Hysteria2OutboundConfig {
        name: "hy2-verified".into(),
        server: "127.0.0.1".into(),
        port: 1, // deliberately unused primary port so `ports` range hopping MUST be used!
        ports: Some(format!("{p}-{p}")),
        password: hy2_pass.into(),
        obfs_salamander_password: None,
        up_bytes_per_sec: 50_000_000,
        down_bytes_per_sec: 200_000_000,
        servername: Some(sni.into()),
        skip_cert_verify: false,
        alpn: vec![b"h3".to_vec()],
        extra_ca_der: vec![ca_plain],
        udp: true,
    })
    .unwrap();
    let mut s = verified_hy2
        .connect_tcp(&TargetAddr::from(tcp_echo))
        .await
        .unwrap();
    s.write_all(b"hy2-mport-verified").await.unwrap();
    s.flush().await.unwrap();
    let mut r = [0u8; 18];
    s.read_exact(&mut r).await.unwrap();
    assert_eq!(&r, b"hy2-mport-verified");
    drop(s);

    // 2. Full-stack URI -> ProxyEngine -> MixedInbound (plain mport + Salamander obfs + >3KB fragmented UDP)
    let uri_plain = format!(
        "hysteria2://{hy2_pass}@127.0.0.1:1?mport={p}-{p}&sni={sni}&insecure=1#hy2-plain-mport"
    );
    let uri_obfs = format!(
        "hy2://{hy2_pass}@127.0.0.1:{}?obfs=salamander&obfs-password={obfs_pass}&sni={sni}&insecure=1#hy2-salamander",
        srv_obfs.listen_addr.port()
    );

    let engine = start_global_engine_with_uris(&[uri_plain, uri_obfs]).await;
    let mixed = engine.mixed_addr();
    let tcp_payload: Vec<u8> = (0..131_072).map(|i| ((i * 59 + 11) & 0xFF) as u8).collect();
    // 3600-byte UDP datagram forces 4-way fragmentation & reassembly across HY2_MAX_UDP_DATAGRAM_WIRE (1150B)!
    let large_udp: Vec<u8> = (0..3600).map(|i| ((i * 17 + 5) & 0xFF) as u8).collect();

    for node_name in ["hy2-plain-mport", "hy2-salamander"] {
        engine.router().select_group("GLOBAL", node_name).unwrap();
        let echoed = socks5_tcp_echo(mixed, tcp_echo, &tcp_payload).await;
        assert_eq!(
            echoed, tcp_payload,
            "Hy2 full-stack TCP mismatch on {node_name}"
        );

        let udp_echoed = socks5_udp_echo(mixed, udp_echo, &large_udp).await;
        let mut expected_udp = b"UDP-ECHO:".to_vec();
        expected_udp.extend_from_slice(&large_udp);
        assert_eq!(
            udp_echoed, expected_udp,
            "Hy2 fragmented 3600B UDP mismatch on {node_name}"
        );
    }

    engine.shutdown_async().await;
    srv_plain.shutdown().await;
    srv_obfs.shutdown().await;
    let _ = shutdown_tx.send(true);
}

#[tokio::test]
async fn tuic_v5_zero_rtt_tcp_and_native_plus_quic_stream_fragmented_udp_full_stack_e2e() {
    use proxy_core::outbound::{
        quic_common::QuicCongestionControl,
        tuic::{TuicOutbound, TuicOutboundConfig, TuicUdpRelayMode, spawn_tuic_server},
    };

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (tcp_echo, udp_echo) = spawn_echo_servers(shutdown_rx.clone()).await;

    let sni = "tuic.e2e.local";
    let (tls_cfg, ca_der) = generate_self_signed_server_config(
        &[sni.to_string(), "127.0.0.1".to_string()],
        &[b"h3".to_vec()],
    )
    .unwrap();

    let uuid = Uuid::new_v4();
    let password = "tuic-v5-exporter-secret";

    let srv = spawn_tuic_server(
        "127.0.0.1:0".parse().unwrap(),
        uuid,
        password.into(),
        tls_cfg,
    )
    .await
    .expect("spawn_tuic_server");

    // 1. Direct verified-CA (`skip_cert_verify: false`) TUIC v5 check
    let verified_tuic = TuicOutbound::new(TuicOutboundConfig {
        name: "tuic-verified".into(),
        server: "127.0.0.1".into(),
        port: srv.listen_addr.port(),
        uuid,
        password: password.into(),
        udp_relay_mode: TuicUdpRelayMode::Native,
        congestion_control: QuicCongestionControl::Bbr,
        zero_rtt_handshake: true,
        disable_sni: false,
        heartbeat_interval: Duration::from_secs(10),
        servername: Some(sni.into()),
        skip_cert_verify: false,
        alpn: vec![b"h3".to_vec()],
        extra_ca_der: vec![ca_der],
        udp: true,
    })
    .unwrap();
    let mut s = verified_tuic
        .connect_tcp(&TargetAddr::from(tcp_echo))
        .await
        .unwrap();
    s.write_all(b"tuic-v5-verified-0rtt").await.unwrap();
    s.flush().await.unwrap();
    let mut r = [0u8; 21];
    s.read_exact(&mut r).await.unwrap();
    assert_eq!(&r, b"tuic-v5-verified-0rtt");
    drop(s);

    // 2. Full-stack URI -> ProxyEngine -> MixedInbound (`native` datagrams & `quic` uni-streams + >3KB UDP fragmentation)
    let port = srv.listen_addr.port();
    let uri_native = format!(
        "tuic://{uuid}:{password}@127.0.0.1:{port}?sni={sni}&alpn=h3&udp_relay_mode=native&congestion_control=bbr&zero_rtt_handshake=1&allow_insecure=1#tuic-native"
    );
    let uri_quic = format!(
        "tuic://{uuid}:{password}@127.0.0.1:{port}?sni={sni}&alpn=h3&udp_relay_mode=quic&congestion_control=cubic&allow_insecure=1#tuic-quic-stream"
    );

    let engine = start_global_engine_with_uris(&[uri_native, uri_quic]).await;
    let mixed = engine.mixed_addr();
    let tcp_payload: Vec<u8> = (0..131_072).map(|i| ((i * 71 + 13) & 0xFF) as u8).collect();
    let large_udp: Vec<u8> = (0..3500).map(|i| ((i * 23 + 9) & 0xFF) as u8).collect();

    for node_name in ["tuic-native", "tuic-quic-stream"] {
        engine.router().select_group("GLOBAL", node_name).unwrap();
        let echoed = socks5_tcp_echo(mixed, tcp_echo, &tcp_payload).await;
        assert_eq!(
            echoed, tcp_payload,
            "TUIC v5 full-stack TCP mismatch on {node_name}"
        );

        let udp_echoed = socks5_udp_echo(mixed, udp_echo, &large_udp).await;
        let mut expected_udp = b"UDP-ECHO:".to_vec();
        expected_udp.extend_from_slice(&large_udp);
        assert_eq!(
            udp_echoed, expected_udp,
            "TUIC v5 fragmented 3500B UDP mismatch on {node_name}"
        );
    }

    engine.shutdown_async().await;
    srv.shutdown().await;
    let _ = shutdown_tx.send(true);
}

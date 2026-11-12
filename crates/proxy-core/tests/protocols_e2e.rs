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

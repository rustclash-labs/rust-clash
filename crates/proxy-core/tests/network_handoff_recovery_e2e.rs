use std::{
    collections::{HashMap, VecDeque},
    net::{Ipv4Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use base64::{Engine, engine::general_purpose::STANDARD};
use proxy_core::{
    addr::TargetAddr,
    config::{ClashConfig, ProxyNodeConfig, RunMode, TunConfig},
    crypto::tls::generate_self_signed_server_config,
    inbound::tun::build_ipv4_udp_packet,
    outbound::{
        DynOutbound,
        anytls::{
            AnyTlsOutbound, AnyTlsOutboundConfig, AnyTlsServerConfig, padding::PaddingScheme,
            spawn_anytls_server,
        },
    },
    router::Router,
};
use smoltcp::{
    iface::{Config as IfaceConfig, Interface, SocketSet},
    phy::{ChecksumCapabilities, Device, DeviceCapabilities, Medium, RxToken, TxToken},
    socket::tcp,
    time::Instant as SmolInstant,
    wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint, Ipv4Packet, UdpPacket},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
    sync::watch,
};

struct GuestDevice {
    rx: VecDeque<Vec<u8>>,
    tx: VecDeque<Vec<u8>>,
}

struct GuestRx(Vec<u8>);
impl RxToken for GuestRx {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

struct GuestTx<'a>(&'a mut VecDeque<Vec<u8>>);
impl TxToken for GuestTx<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut b = vec![0u8; len];
        let r = f(&mut b);
        self.0.push_back(b);
        r
    }
}

impl Device for GuestDevice {
    type RxToken<'a> = GuestRx;
    type TxToken<'a> = GuestTx<'a>;

    fn receive(&mut self, _ts: SmolInstant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let pkt = self.rx.pop_front()?;
        Some((GuestRx(pkt), GuestTx(&mut self.tx)))
    }

    fn transmit(&mut self, _ts: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(GuestTx(&mut self.tx))
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
async fn anytls_session_pool_and_active_streams_recover_cleanly_across_network_handoff() {
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // 1. Spawn TCP echo origin that counts distinct accepted TCP connections
    let accepted_origins = Arc::new(AtomicUsize::new(0));
    let accepted_clone = Arc::clone(&accepted_origins);
    let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tcp_echo_addr = tcp_listener.local_addr().unwrap();
    let mut stop_echo = shutdown_rx.clone();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = stop_echo.changed() => break,
                res = tcp_listener.accept() => {
                    let Ok((mut sock, _)) = res else { continue };
                    accepted_clone.fetch_add(1, Ordering::Relaxed);
                    tokio::spawn(async move {
                        let mut buf = vec![0u8; 16 * 1024];
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

    // 2. Spawn AnyTLS v2 server
    let (server_tls_cfg, ca_der) = generate_self_signed_server_config(
        &["anytls.handoff.local".to_string(), "127.0.0.1".to_string()],
        &[b"h2".to_vec()],
    )
    .unwrap();
    let (srv_addr, _srv_task) = spawn_anytls_server(
        AnyTlsServerConfig {
            listen_addr: "127.0.0.1:0".into(),
            password: "handoff-secret-password".into(),
            tls_config: server_tls_cfg,
            padding_scheme: PaddingScheme::default(),
        },
        shutdown_rx.clone(),
    )
    .await
    .unwrap();

    let client = Arc::new(
        AnyTlsOutbound::new(AnyTlsOutboundConfig {
            name: "anytls-handoff".into(),
            server: "127.0.0.1".into(),
            port: srv_addr.port(),
            password: "handoff-secret-password".into(),
            sni: "anytls.handoff.local".into(),
            skip_cert_verify: false,
            alpn: vec![b"h2".to_vec()],
            extra_ca_der: vec![ca_der],
            idle_session_check_interval: Duration::from_secs(30),
            idle_session_timeout: Duration::from_secs(60),
            min_idle_session: 2,
            udp: true,
        })
        .unwrap(),
    );

    let dns = Arc::new(proxy_core::dns::FakeIpDnsEngine::new(&Default::default()).unwrap());
    let mut outbounds: HashMap<String, DynOutbound> = HashMap::new();
    outbounds.insert("anytls-handoff".to_string(), client.clone());
    let router = Router::new(
        RunMode::Rule,
        outbounds,
        &[],
        &["MATCH,anytls-handoff".to_string()],
        dns,
    )
    .unwrap();

    let target = TargetAddr::from(tcp_echo_addr);

    // 3. Open 3 concurrent AnyTLS streams:
    //    - Drop 2 so `idle_count() == 2` (warm TLS session pool on old Wi-Fi interface)
    //    - Keep `st_active` open across the simulated Wi-Fi -> Cellular handoff!
    let mut st_1 = client.connect_anytls_stream(&target).await.unwrap();
    let st_2 = client.connect_anytls_stream(&target).await.unwrap();
    let mut st_active = client.connect_anytls_stream(&target).await.unwrap();
    assert_eq!(st_1.session_seq(), 1);
    assert_eq!(st_2.session_seq(), 2);
    assert_eq!(st_active.session_seq(), 3);

    st_1.write_all(b"warm-1").await.unwrap();
    let mut warm_echo = [0u8; 6];
    st_1.read_exact(&mut warm_echo).await.unwrap();
    assert_eq!(&warm_echo, b"warm-1");

    st_active.write_all(b"pre-handoff").await.unwrap();
    let mut pre_echo = [0u8; 11];
    st_active.read_exact(&mut pre_echo).await.unwrap();
    assert_eq!(&pre_echo, b"pre-handoff");

    drop(st_1);
    drop(st_2);
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(
        client.pool().idle_count(),
        2,
        "2 warm sessions must be pooled before handoff"
    );

    // 4. Trigger network handoff (`Router::notify_network_change`)!
    let evicted = router.notify_network_change();
    assert_eq!(
        evicted, 3,
        "must evict 2 idle TLS sessions AND abort 1 active live TLS session"
    );
    assert_eq!(
        client.pool().idle_count(),
        0,
        "idle TLS pool must be empty immediately after handoff"
    );

    // 5. Verify in-flight `st_active` does NOT hang for 60s: read fails promptly with error/EOF!
    let mut tmp = [0u8; 16];
    let read_res = tokio::time::timeout(Duration::from_millis(500), st_active.read(&mut tmp))
        .await
        .expect("in-flight AnyTLS stream must fail immediately on handoff, never hang");
    assert!(
        read_res.is_err() || matches!(read_res, Ok(0)),
        "expected broken/EOF stream after network handoff, got {read_res:?}"
    );

    // 6. Drop `st_active` AFTER handoff -> Epoch guard MUST prevent pre-handoff session from
    //    re-entering the post-handoff `idle` pool!
    drop(st_active);
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(
        client.pool().idle_count(),
        0,
        "pre-handoff stream dropped after network change must NEVER poison idle pool"
    );

    // 7. Open a new post-handoff AnyTLS stream -> must dial a brand-new TLS socket (`seq == 4`)
    //    and transfer 32 KB cleanly!
    let mut st_post = client.connect_anytls_stream(&target).await.unwrap();
    assert!(
        st_post.session_seq() >= 4,
        "post-handoff stream must establish a fresh TLS session, got seq={}",
        st_post.session_seq()
    );
    let payload: Vec<u8> = (0..32_768).map(|i| ((i * 37 + 11) & 0xFF) as u8).collect();
    st_post.write_all(&payload).await.unwrap();
    let mut echoed = vec![0u8; payload.len()];
    st_post.read_exact(&mut echoed).await.unwrap();
    assert_eq!(echoed, payload);

    // Dropping `st_post` (created in the new epoch!) MUST return cleanly to the idle pool!
    drop(st_post);
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(client.pool().idle_count(), 1);

    let _ = shutdown_tx.send(true);
}

#[tokio::test]
async fn proxy_engine_notify_network_change_recovers_tun_udp_nat_and_tcp_sessions() {
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // 1. Spawn UDP echo server that records packet sequence numbers
    let udp_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let udp_origin_addr = udp_sock.local_addr().unwrap();
    let mut udp_stop = shutdown_rx.clone();
    let udp_srv = Arc::clone(&udp_sock);
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            tokio::select! {
                _ = udp_stop.changed() => break,
                res = udp_srv.recv_from(&mut buf) => {
                    let Ok((n, peer)) = res else { continue };
                    let mut reply = b"UDP-ACK:".to_vec();
                    reply.extend_from_slice(&buf[..n]);
                    let _ = udp_srv.send_to(&reply, peer).await;
                }
            }
        }
    });

    // 2. Spawn TCP server where connection #1 stays open ("stalled long-lived stream") and
    //    subsequent connections echo immediately ("recovered cellular stream").
    let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tcp_origin_addr = tcp_listener.local_addr().unwrap();
    let conn_counter = Arc::new(AtomicUsize::new(0));
    let conn_counter_srv = Arc::clone(&conn_counter);
    let mut tcp_stop = shutdown_rx.clone();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = tcp_stop.changed() => break,
                res = tcp_listener.accept() => {
                    let Ok((mut sock, _)) = res else { continue };
                    let idx = conn_counter_srv.fetch_add(1, Ordering::SeqCst) + 1;
                    let mut hold_stop = tcp_stop.clone();
                    tokio::spawn(async move {
                        let mut buf = [0u8; 4096];
                        let n = sock.read(&mut buf).await.unwrap_or(0);
                        if n == 0 {
                            return;
                        }
                        if idx == 1 {
                            // Send initial greeting, then hold socket open until client/engine aborts!
                            let _ = sock.write_all(b"CONN1-ESTABLISHED").await;
                            let _ = hold_stop.changed().await;
                        } else {
                            let mut out = format!("CONN{idx}-OK:").into_bytes();
                            out.extend_from_slice(&buf[..n]);
                            let _ = sock.write_all(&out).await;
                            let _ = sock.shutdown().await;
                        }
                    });
                }
            }
        }
    });

    // 3. Spawn local SS-2022 proxy server (supports both TCP and UDP relay)
    let ss_password = STANDARD.encode([0x55u8; 16]);
    let (ss_addr, _ss_task) = proxy_core::outbound::ss::spawn_ss_server(
        "127.0.0.1:0",
        "2022-blake3-aes-128-gcm",
        &ss_password,
        shutdown_rx.clone(),
    )
    .await
    .unwrap();

    // 4. Start full `ProxyEngine` with Virtual `smoltcp` TUN enabled
    let mut cfg = ClashConfig {
        mixed_port: 0,
        tun: TunConfig {
            enable: true,
            stack: "smoltcp".to_string(),
            device: "utun-handoff-test".to_string(),
            auto_route: false,
            strict_route: false,
            auto_detect_interface: false,
            mtu: 1500,
            ipv6: false,
            inet6_address: None,
            wintun_path: None,
            ..TunConfig::default()
        },
        proxies: vec![ProxyNodeConfig::Ss {
            name: "SS2022-HANDOFF".to_string(),
            server: "127.0.0.1".to_string(),
            port: ss_addr.port(),
            cipher: "2022-blake3-aes-128-gcm".to_string(),
            password: ss_password,
            udp: true,
        }],
        proxy_groups: vec![],
        rules: vec!["MATCH,SS2022-HANDOFF".to_string()],
        ..ClashConfig::default()
    };
    cfg.dns.enable = false;

    let tmp_state = std::env::temp_dir().join(format!(
        "rust-clash-handoff-test-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&tmp_state).unwrap();
    let engine = proxy_core::engine::ProxyEngine::start_with_state_dir(cfg, tmp_state.clone())
        .await
        .unwrap();
    let mut vtun = engine
        .take_virtual_tun_handle()
        .expect("virtual TUN handle must be present");

    // Helper: setup guest smoltcp stack (`198.18.0.10/16`)
    let mut guest_dev = GuestDevice {
        rx: VecDeque::new(),
        tx: VecDeque::new(),
    };
    let mut iface_cfg = IfaceConfig::new(HardwareAddress::Ip);
    iface_cfg.random_seed = 0xCAFE_BABE;
    let mut guest_iface = Interface::new(iface_cfg, &mut guest_dev, SmolInstant::now());
    guest_iface.update_ip_addrs(|addrs| {
        let _ = addrs.push(IpCidr::new(IpAddress::v4(198, 18, 0, 10), 16));
    });
    let _ = guest_iface
        .routes_mut()
        .add_default_ipv4_route(Ipv4Addr::new(198, 18, 0, 1));
    let mut sockets = SocketSet::new(vec![]);

    // 5. Establish guest TCP connection #1 AND guest UDP NAT session `(198.18.0.10:53000)`!
    let tcp1 = tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0u8; 16384]),
        tcp::SocketBuffer::new(vec![0u8; 16384]),
    );
    let h_tcp1 = sockets.add(tcp1);
    {
        let sock = sockets.get_mut::<tcp::Socket>(h_tcp1);
        sock.connect(
            guest_iface.context(),
            IpEndpoint::new(IpAddress::v4(127, 0, 0, 1), tcp_origin_addr.port()),
            51000,
        )
        .unwrap();
    }

    // Also inject an L3 UDP packet from `198.18.0.10:53000 -> 127.0.0.1:<udp_origin_port>`
    let guest_udp_src = SocketAddr::new(Ipv4Addr::new(198, 18, 0, 10).into(), 53000);
    let udp_pkt_1 = build_ipv4_udp_packet(
        Ipv4Addr::new(198, 18, 0, 10),
        53000,
        Ipv4Addr::new(127, 0, 0, 1),
        udp_origin_addr.port(),
        b"wifi-pkt-1",
    )
    .unwrap();
    vtun.ingress_tx.send(udp_pkt_1).await.unwrap();

    let mut got_conn1_greeting = false;
    let mut got_udp1_reply = false;
    let mut tcp1_sent = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);

    while (!got_conn1_greeting || !got_udp1_reply) && tokio::time::Instant::now() < deadline {
        guest_iface.poll(SmolInstant::now(), &mut guest_dev, &mut sockets);
        {
            let sock = sockets.get_mut::<tcp::Socket>(h_tcp1);
            if sock.can_send() && !tcp1_sent {
                sock.send_slice(b"hello-conn1").unwrap();
                tcp1_sent = true;
            }
            if sock.can_recv() {
                let mut tmp = [0u8; 256];
                let n = sock.recv_slice(&mut tmp).unwrap();
                if &tmp[..n] == b"CONN1-ESTABLISHED" {
                    got_conn1_greeting = true;
                }
            }
        }
        guest_iface.poll(SmolInstant::now(), &mut guest_dev, &mut sockets);
        while let Some(pkt) = guest_dev.tx.pop_front() {
            vtun.ingress_tx.send(pkt).await.unwrap();
        }
        if let Ok(Some(pkt)) =
            tokio::time::timeout(Duration::from_millis(15), vtun.egress_rx.recv()).await
        {
            // Check if this packet is our UDP reply to port 53000 or TCP packet for guest_iface
            if let Ok(ip4) = Ipv4Packet::new_checked(&pkt)
                && ip4.next_header() == smoltcp::wire::IpProtocol::Udp
                && let Ok(udp) = UdpPacket::new_checked(ip4.payload())
                && udp.dst_port() == 53000
            {
                assert_eq!(udp.payload(), b"UDP-ACK:wifi-pkt-1");
                got_udp1_reply = true;
            } else {
                guest_dev.rx.push_back(pkt);
            }
        }
    }
    assert!(got_conn1_greeting, "TCP connection #1 must establish");
    assert!(
        got_udp1_reply,
        "UDP NAT session #1 must echo before handoff"
    );
    assert!(
        engine.hub().list_connections().len() >= 2,
        "both TCP #1 and UDP NAT session must be tracked as active before handoff"
    );

    // 6. Simulate Android Wi-Fi -> Cellular handoff via `engine.notify_network_change()`!
    let report = engine.notify_network_change();
    assert!(
        report.reset_udp_nat_sessions >= 1,
        "must synchronously reset active UDP NAT session, got {report:?}"
    );
    assert!(
        report.closed_active_connections >= 1,
        "must close remaining active TCP connections, got {report:?}"
    );
    assert!(report.dns_cache_flushed);

    // 7. IMMEDIATELY send a post-handoff UDP packet from the EXACT SAME `(198.18.0.10:53000)`:
    //    - Must NOT drop the first packet on a stale closed channel!
    //    - Wait 80ms so the old UDP session's background task finishes, then send a 2nd post-handoff
    //      UDP packet to prove `remove_if` + `Arc::ptr_eq` prevented ABA eviction of the new session!
    let _ = guest_udp_src;
    for (seq_label, delay_before_ms) in [("cell-pkt-1", 0u64), ("cell-pkt-2", 80u64)] {
        if delay_before_ms > 0 {
            tokio::time::sleep(Duration::from_millis(delay_before_ms)).await;
        }
        let pkt = build_ipv4_udp_packet(
            Ipv4Addr::new(198, 18, 0, 10),
            53000,
            Ipv4Addr::new(127, 0, 0, 1),
            udp_origin_addr.port(),
            seq_label.as_bytes(),
        )
        .unwrap();
        vtun.ingress_tx.send(pkt).await.unwrap();

        let mut got_udp_reply = false;
        let sub_deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        while !got_udp_reply && tokio::time::Instant::now() < sub_deadline {
            if let Ok(Some(epkt)) =
                tokio::time::timeout(Duration::from_millis(20), vtun.egress_rx.recv()).await
            {
                if let Ok(ip4) = Ipv4Packet::new_checked(&epkt)
                    && ip4.next_header() == smoltcp::wire::IpProtocol::Udp
                    && let Ok(udp) = UdpPacket::new_checked(ip4.payload())
                    && udp.dst_port() == 53000
                {
                    let expected = format!("UDP-ACK:{seq_label}");
                    assert_eq!(udp.payload(), expected.as_bytes());
                    got_udp_reply = true;
                } else {
                    guest_dev.rx.push_back(epkt);
                }
            }
        }
        assert!(
            got_udp_reply,
            "post-handoff UDP packet '{seq_label}' must succeed immediately without drop or ABA eviction"
        );
    }

    // 8. Verify guest TCP connection #1 was aborted (`RST` / closed) AND guest TCP connection #2
    //    succeeds immediately over the recovered stack!
    let tcp2 = tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0u8; 16384]),
        tcp::SocketBuffer::new(vec![0u8; 16384]),
    );
    let h_tcp2 = sockets.add(tcp2);
    {
        let sock2 = sockets.get_mut::<tcp::Socket>(h_tcp2);
        sock2
            .connect(
                guest_iface.context(),
                IpEndpoint::new(IpAddress::v4(127, 0, 0, 1), tcp_origin_addr.port()),
                51001,
            )
            .unwrap();
    }

    let mut tcp1_terminated = false;
    let mut tcp2_sent = false;
    let mut tcp2_resp = Vec::new();
    let deadline2 = tokio::time::Instant::now() + Duration::from_secs(5);
    while (!tcp1_terminated || tcp2_resp != b"CONN2-OK:hello-after-handoff")
        && tokio::time::Instant::now() < deadline2
    {
        guest_iface.poll(SmolInstant::now(), &mut guest_dev, &mut sockets);
        {
            let s1 = sockets.get_mut::<tcp::Socket>(h_tcp1);
            if !s1.is_active() || matches!(s1.state(), tcp::State::CloseWait | tcp::State::Closed) {
                tcp1_terminated = true;
            }
        }
        {
            let s2 = sockets.get_mut::<tcp::Socket>(h_tcp2);
            if s2.can_send() && !tcp2_sent {
                s2.send_slice(b"hello-after-handoff").unwrap();
                tcp2_sent = true;
            }
            if s2.can_recv() {
                let mut tmp = [0u8; 256];
                let n = s2.recv_slice(&mut tmp).unwrap();
                tcp2_resp.extend_from_slice(&tmp[..n]);
            }
        }
        guest_iface.poll(SmolInstant::now(), &mut guest_dev, &mut sockets);
        while let Some(pkt) = guest_dev.tx.pop_front() {
            vtun.ingress_tx.send(pkt).await.unwrap();
        }
        if let Ok(Some(pkt)) =
            tokio::time::timeout(Duration::from_millis(15), vtun.egress_rx.recv()).await
        {
            guest_dev.rx.push_back(pkt);
        }
    }

    assert!(
        tcp1_terminated,
        "pre-handoff smoltcp TCP stream must receive RST/FIN abort upon notify_network_change"
    );
    assert_eq!(
        String::from_utf8_lossy(&tcp2_resp),
        "CONN2-OK:hello-after-handoff"
    );

    engine.shutdown();
    let _ = std::fs::remove_dir_all(&tmp_state);
    let _ = shutdown_tx.send(true);
}

use std::{
    collections::{HashMap, VecDeque},
    net::Ipv4Addr,
    sync::Arc,
    time::Duration,
};

use parking_lot::RwLock;
use proxy_core::{
    config::{DnsConfig, RunMode},
    dns::{
        FakeIpDnsEngine,
        wire::{DnsAnswerData, QTYPE_A, build_dns_query, extract_ip_answers},
    },
    inbound::tun::{build_ipv4_udp_packet, spawn_userspace_tun},
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
use smoltcp::{
    iface::{Config as IfaceConfig, Interface, SocketSet},
    phy::{ChecksumCapabilities, Device, DeviceCapabilities, Medium, RxToken, TxToken},
    socket::tcp,
    time::Instant as SmolInstant,
    wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint, Ipv4Packet, UdpPacket},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::watch,
};
use uuid::Uuid;

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
async fn smoltcp_userspace_tun_dns_hijack_and_tcp_fake_ip_relay() {
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // 1. Local TCP echo origin
    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo_listener.local_addr().unwrap();
    let mut echo_stop = shutdown_rx.clone();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = echo_stop.changed() => break,
                accepted = echo_listener.accept() => {
                    let Ok((mut s, _)) = accepted else { continue };
                    tokio::spawn(async move {
                        let mut buf = [0u8; 4096];
                        let n = s.read(&mut buf).await.unwrap_or(0);
                        if n > 0 {
                            let mut out = b"TUN-ORIGIN-OK:".to_vec();
                            out.extend_from_slice(&buf[..n]);
                            let _ = s.write_all(&out).await;
                        }
                    });
                }
            }
        }
    });

    // 2. Local VLESS+PQ server
    let uuid = Uuid::new_v4();
    let pq = generate_vless_encryption_pair(XorMode::XorPub, true, true).unwrap();
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

    let vless_ob: DynOutbound = Arc::new(
        VlessOutbound::new(VlessOutboundConfig {
            name: "TUN-VLESS-PQ".into(),
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

    let dns_engine = Arc::new(FakeIpDnsEngine::new(&DnsConfig::default()).unwrap());
    let mut outbounds = HashMap::new();
    outbounds.insert("TUN-VLESS-PQ".to_string(), vless_ob);
    let rules = vec![
        "DOMAIN,localhost,TUN-VLESS-PQ".to_string(),
        "MATCH,DIRECT".to_string(),
    ];
    let router = Arc::new(
        Router::new(
            RunMode::Rule,
            outbounds,
            &[],
            &rules,
            Arc::clone(&dns_engine),
        )
        .unwrap(),
    );
    let router_slot = Arc::new(RwLock::new(router));
    let hub = Arc::new(TelemetryHub::new());

    let (mut vtun, _tun_task) = spawn_userspace_tun(1500, router_slot, hub, shutdown_rx.clone());

    // Part 1: Verify `any:53` UDP DNS Hijack over raw IPv4 packets!
    let dns_wire = build_dns_query(0xABCD, "openai.com", QTYPE_A);
    let raw_udp_pkt = build_ipv4_udp_packet(
        Ipv4Addr::new(10, 0, 0, 2),
        54321,
        Ipv4Addr::new(8, 8, 8, 8),
        53,
        &dns_wire,
    )
    .unwrap();
    vtun.ingress_tx.send(raw_udp_pkt).await.unwrap();

    let dns_reply_pkt = tokio::time::timeout(Duration::from_secs(2), vtun.egress_rx.recv())
        .await
        .expect("TUN DNS hijack timeout")
        .expect("TUN egress packet");
    let ip4 = Ipv4Packet::new_checked(&dns_reply_pkt).unwrap();
    assert_eq!(ip4.src_addr(), Ipv4Addr::new(8, 8, 8, 8));
    assert_eq!(ip4.dst_addr(), Ipv4Addr::new(10, 0, 0, 2));
    let udp = UdpPacket::new_checked(ip4.payload()).unwrap();
    let answers = extract_ip_answers(udp.payload()).unwrap();
    assert!(matches!(answers[0], DnsAnswerData::A(_)));

    // Part 2: Full Raw IPv4 TCP 3-Way Handshake + Payload Relay via Guest `smoltcp` TCP Socket!
    // Assign Fake-IP for `"localhost"` so `198.18.0.x:<echo_port>` restores `"localhost:<echo_port>"`
    let fake_ip = dns_engine.assign_fake_ip("localhost");

    let mut guest_dev = GuestDevice {
        rx: VecDeque::new(),
        tx: VecDeque::new(),
    };
    let mut cfg = IfaceConfig::new(HardwareAddress::Ip);
    cfg.random_seed = 0x1234_5678;
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
        tcp::SocketBuffer::new(vec![0u8; 32768]),
        tcp::SocketBuffer::new(vec![0u8; 32768]),
    );
    let guest_handle = guest_sockets.add(guest_tcp);

    {
        let sock = guest_sockets.get_mut::<tcp::Socket>(guest_handle);
        sock.connect(
            guest_iface.context(),
            IpEndpoint::new(IpAddress::Ipv4(fake_ip), echo_addr.port()),
            49152,
        )
        .unwrap();
    }

    let mut sent_payload = false;
    let mut received_reply = Vec::new();

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while tokio::time::Instant::now() < deadline {
        let _ = guest_iface.poll(now_smol(), &mut guest_dev, &mut guest_sockets);
        while let Some(out_pkt) = guest_dev.tx.pop_front() {
            vtun.ingress_tx.send(out_pkt).await.unwrap();
        }

        tokio::time::sleep(Duration::from_millis(8)).await;
        while let Ok(in_pkt) = vtun.egress_rx.try_recv() {
            guest_dev.rx.push_back(in_pkt);
        }
        let _ = guest_iface.poll(now_smol(), &mut guest_dev, &mut guest_sockets);

        let sock = guest_sockets.get_mut::<tcp::Socket>(guest_handle);
        if sock.can_send() && !sent_payload {
            sock.send_slice(b"raw-l3-tun-packet-payload").unwrap();
            sent_payload = true;
        }
        if sock.can_recv() {
            let _ = sock.recv(|data| {
                received_reply.extend_from_slice(data);
                (data.len(), ())
            });
            if received_reply.starts_with(b"TUN-ORIGIN-OK:") {
                break;
            }
        }
    }

    assert_eq!(
        received_reply, b"TUN-ORIGIN-OK:raw-l3-tun-packet-payload",
        "Expected full raw IPv4 TCP roundtrip through smoltcp TUN -> Fake-IP -> VLESS-PQ -> Origin"
    );

    let _ = shutdown_tx.send(true);
}

fn build_chrome_pq_client_hello(sni: &str, key_share_len: usize) -> Vec<u8> {
    let mut exts = Vec::new();
    // Large X25519MLKEM768 key_share extension preceding SNI so SNI sits past byte 1460
    exts.extend_from_slice(&0x0033u16.to_be_bytes());
    exts.extend_from_slice(&(key_share_len as u16).to_be_bytes());
    exts.resize(exts.len() + key_share_len, 0x42);

    let name_bytes = sni.as_bytes();
    let list_len = 1 + 2 + name_bytes.len();
    let mut ext_sni = Vec::with_capacity(2 + list_len);
    ext_sni.extend_from_slice(&(list_len as u16).to_be_bytes());
    ext_sni.push(0x00);
    ext_sni.extend_from_slice(&(name_bytes.len() as u16).to_be_bytes());
    ext_sni.extend_from_slice(name_bytes);
    exts.extend_from_slice(&0x0000u16.to_be_bytes());
    exts.extend_from_slice(&(ext_sni.len() as u16).to_be_bytes());
    exts.extend_from_slice(&ext_sni);

    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]);
    body.extend_from_slice(&[0xAA; 32]);
    body.push(32);
    body.extend_from_slice(&[0xBB; 32]);
    body.extend_from_slice(&4u16.to_be_bytes());
    body.extend_from_slice(&[0x13, 0x01, 0x13, 0x02]);
    body.push(0x01);
    body.push(0x00);
    body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    body.extend_from_slice(&exts);

    let mut hs = Vec::new();
    hs.push(0x01);
    let hs_len = body.len();
    hs.push(((hs_len >> 16) & 0xff) as u8);
    hs.push(((hs_len >> 8) & 0xff) as u8);
    hs.push((hs_len & 0xff) as u8);
    hs.extend_from_slice(&body);

    let mut record = Vec::with_capacity(5 + hs.len());
    record.push(0x16);
    record.extend_from_slice(&[0x03, 0x01]);
    record.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    record.extend_from_slice(&hs);
    record
}

#[tokio::test]
async fn smoltcp_tun_real_ip_sni_override_two_segment_pq_client_hello_over_vless_encryption() {
    use proxy_core::{addr::TargetAddr, outbound::vless::encryption::ServerEncryption};

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let pq_hello = build_chrome_pq_client_hello("linux.do", 1950);
    assert!(
        pq_hello.len() > 2000,
        "Chrome PQ ClientHello must exceed single 1460B TCP MSS segment: {}",
        pq_hello.len()
    );
    let expected_len = pq_hello.len();

    // 1. Real local VLESS + Post-Quantum Encryption server that decrypts VLESS+Encryption,
    //    records the exact VLESS target address (verifying SNI override replaced the poisoned IP!),
    //    reads the entire ~2060B ClientHello without truncation, and sends a response back!
    let uuid = Uuid::new_v4();
    let pq = generate_vless_encryption_pair(XorMode::XorPub, true, true).unwrap();
    let server_enc = Arc::new(ServerEncryption::new(&pq.decryption).unwrap());
    let vless_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let vless_addr = vless_listener.local_addr().unwrap();
    let (vless_observed_tx, vless_observed_rx) =
        tokio::sync::oneshot::channel::<(String, Vec<u8>)>();

    let server_enc_task = Arc::clone(&server_enc);
    tokio::spawn(async move {
        let Ok((tcp, _)) = vless_listener.accept().await else {
            return;
        };
        let mut stream = server_enc_task.accept(Box::new(tcp)).await.unwrap();
        let ver = stream.read_u8().await.unwrap();
        assert_eq!(ver, 0x00);
        let mut got_uuid = [0u8; 16];
        stream.read_exact(&mut got_uuid).await.unwrap();
        assert_eq!(Uuid::from_bytes(got_uuid), uuid);
        let addons_len = stream.read_u8().await.unwrap() as usize;
        if addons_len > 0 {
            let mut addons = vec![0u8; addons_len];
            stream.read_exact(&mut addons).await.unwrap();
        }
        let cmd = stream.read_u8().await.unwrap();
        assert_eq!(cmd, 0x01); // VLESS TCP
        let target = TargetAddr::read_vless(&mut stream).await.unwrap();

        let mut received = Vec::with_capacity(expected_len);
        let mut chunk = [0u8; 4096];
        while received.len() < expected_len {
            match stream.read(&mut chunk).await {
                Ok(0) | Err(_) => break,
                Ok(n) => received.extend_from_slice(&chunk[..n]),
            }
        }
        let _ = vless_observed_tx.send((target.to_string(), received));

        // Send VLESS response header `[0x00, 0x00]` + simulated TLS ServerHello reply
        let _ = stream.write_all(&[0x00, 0x00]).await;
        let _ = stream.write_all(b"VLESS-PQ-TLS-SERVER-OK").await;
        let _ = stream.flush().await;
        let _ = stream.shutdown().await;
    });

    // 2. Wire real VlessOutbound (PQ encryption enabled) + Router with DOMAIN-SUFFIX rule ONLY
    let vless_ob: DynOutbound = Arc::new(
        VlessOutbound::new(VlessOutboundConfig {
            name: "TUN-VLESS-PQ".into(),
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

    let dns_engine = Arc::new(FakeIpDnsEngine::new(&DnsConfig::default()).unwrap());
    let mut outbounds = HashMap::new();
    outbounds.insert("TUN-VLESS-PQ".to_string(), vless_ob);
    let rules = vec![
        "DOMAIN-SUFFIX,linux.do,TUN-VLESS-PQ".to_string(),
        "MATCH,REJECT".to_string(),
    ];
    let router = Arc::new(
        Router::new(
            RunMode::Rule,
            outbounds,
            &[],
            &rules,
            Arc::clone(&dns_engine),
        )
        .unwrap(),
    );
    let router_slot = Arc::new(RwLock::new(router));
    let hub = Arc::new(TelemetryHub::new());
    let (mut vtun, _tun_task) =
        spawn_userspace_tun(1500, router_slot, Arc::clone(&hub), shutdown_rx.clone());

    // 3. Guest `smoltcp` TCP client (MTU 1500 -> automatically fragments ~2060B ClientHello into 2 TCP segments!)
    //    connects directly to poisoned public IP `31.13.73.1:443` (bypassing Fake-IP!)
    let mut guest_dev = GuestDevice {
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
        tcp::SocketBuffer::new(vec![0u8; 32768]),
        tcp::SocketBuffer::new(vec![0u8; 32768]),
    );
    let guest_handle = guest_sockets.add(guest_tcp);
    {
        let sock = guest_sockets.get_mut::<tcp::Socket>(guest_handle);
        sock.connect(
            guest_iface.context(),
            IpEndpoint::new(IpAddress::Ipv4(Ipv4Addr::new(31, 13, 73, 1)), 443),
            51443,
        )
        .unwrap();
    }

    let mut sent_offset = 0usize;
    let mut received_reply = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(6);
    while tokio::time::Instant::now() < deadline {
        let _ = guest_iface.poll(now_smol(), &mut guest_dev, &mut guest_sockets);
        while let Some(out_pkt) = guest_dev.tx.pop_front() {
            vtun.ingress_tx.send(out_pkt).await.unwrap();
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
        while let Ok(in_pkt) = vtun.egress_rx.try_recv() {
            guest_dev.rx.push_back(in_pkt);
        }
        let _ = guest_iface.poll(now_smol(), &mut guest_dev, &mut guest_sockets);

        let sock = guest_sockets.get_mut::<tcp::Socket>(guest_handle);
        if sock.can_send() && sent_offset < pq_hello.len() {
            let n = sock.send_slice(&pq_hello[sent_offset..]).unwrap();
            sent_offset += n;
        }
        if sock.can_recv() {
            let _ = sock.recv(|data| {
                received_reply.extend_from_slice(data);
                (data.len(), ())
            });
            if received_reply == b"VLESS-PQ-TLS-SERVER-OK" {
                break;
            }
        }
    }

    let (observed_target, observed_payload) =
        tokio::time::timeout(Duration::from_secs(3), vless_observed_rx)
            .await
            .expect("VLESS+PQ server must receive sniffed request")
            .unwrap();
    assert_eq!(
        observed_target, "linux.do:443",
        "VLESS+PQ outbound must dial sniffed SNI domain rather than poisoned IP 31.13.73.1:443"
    );
    assert_eq!(
        observed_payload, pq_hello,
        "2-segment ~2KB Chrome PQ ClientHello must arrive completely intact across smoltcp + SNI sniff + VLESS+PQ"
    );
    assert_eq!(
        received_reply, b"VLESS-PQ-TLS-SERVER-OK",
        "Client must receive non-zero download response (never stall at download: 0)"
    );

    let _ = shutdown_tx.send(true);
}

#[tokio::test]
async fn smoltcp_tun_high_backpressure_multi_mb_upload_zero_window_reorder_retransmit_stress() {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use async_trait::async_trait;
    use proxy_core::{
        addr::TargetAddr,
        outbound::{BoxedStream, OutboundHandler},
    };
    use smoltcp::wire::TcpPacket;

    // 3 MiB + odd tail (777 bytes) to exercise both multi-MB streaming and odd-byte window-scale edges
    const TOTAL_UPLOAD_BYTES: usize = 3 * 1024 * 1024 + 777;

    let mut payload = Vec::with_capacity(TOTAL_UPLOAD_BYTES);
    let mut state: u32 = 0x1357_9BDF;
    for _ in 0..TOTAL_UPLOAD_BYTES {
        state = state.wrapping_mul(1664525).wrapping_add(1013904223);
        payload.push((state >> 24) as u8);
    }
    let expected_hash = blake3::hash(&payload).to_hex().to_string();

    struct ThrottledUploadOutbound {
        expected_len: usize,
        received_bytes: Arc<AtomicUsize>,
        release_initial_stall: Arc<AtomicBool>,
    }

    #[async_trait]
    impl OutboundHandler for ThrottledUploadOutbound {
        fn name(&self) -> &str {
            "THROTTLED-UPLOAD"
        }

        fn protocol(&self) -> &'static str {
            "mock-throttled"
        }

        async fn connect_tcp(&self, _target: &TargetAddr) -> std::io::Result<BoxedStream> {
            // Small duplex buffer forces `writer_fut` to block immediately, saturating both
            // `to_remote_tx` (64 slots) and `smoltcp`'s 64 KiB RX buffer -> real TCP zero-window!
            let (client_side, mut server_side) = tokio::io::duplex(8 * 1024);
            let expected_len = self.expected_len;
            let received_bytes = Arc::clone(&self.received_bytes);
            let release_initial_stall = Arc::clone(&self.release_initial_stall);

            tokio::spawn(async move {
                // Phase 1: Wait until the TUN stack advertises zero-window (or max 500ms) so we
                // deterministically saturate both `to_remote_tx` and `smoltcp`'s 64 KiB RX buffer.
                let stall_deadline = tokio::time::Instant::now() + Duration::from_millis(500);
                while !release_initial_stall.load(Ordering::Acquire)
                    && tokio::time::Instant::now() < stall_deadline
                {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                // Hold full saturation slightly longer to elicit zero-window probes / dup ACKs
                tokio::time::sleep(Duration::from_millis(40)).await;

                let mut hasher = blake3::Hasher::new();
                let mut total = 0usize;
                let mut buf = vec![0u8; 4099]; // odd read chunk size
                let mut throttled_pause_bucket = 0usize;

                while total < expected_len {
                    match server_side.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            hasher.update(&buf[..n]);
                            total += n;
                            received_bytes.store(total, Ordering::Release);

                            // Phase 2 (first ~2.0 MiB): pace reads with periodic backpressure pauses
                            // to force repeated zero-window <-> window-update cycles.
                            // Phase 3 (final ~1.0 MiB): drain unthrottled to verify full throughput recovery.
                            if total < 2 * 1024 * 1024 {
                                throttled_pause_bucket += n;
                                if throttled_pause_bucket >= 192 * 1024 {
                                    throttled_pause_bucket = 0;
                                    tokio::time::sleep(Duration::from_millis(25)).await;
                                } else if throttled_pause_bucket % (32 * 1024) < n {
                                    tokio::time::sleep(Duration::from_millis(1)).await;
                                }
                            }
                        }
                    }
                }

                let digest = hasher.finalize().to_hex().to_string();
                let reply = format!("UPLOAD-OK:{total}:{digest}");
                let _ = server_side.write_all(reply.as_bytes()).await;
                let _ = server_side.flush().await;
                let _ = server_side.shutdown().await;
            });

            Ok(Box::new(client_side))
        }
    }

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let received_bytes = Arc::new(AtomicUsize::new(0));
    let release_initial_stall = Arc::new(AtomicBool::new(false));
    let throttled_ob: DynOutbound = Arc::new(ThrottledUploadOutbound {
        expected_len: TOTAL_UPLOAD_BYTES,
        received_bytes: Arc::clone(&received_bytes),
        release_initial_stall: Arc::clone(&release_initial_stall),
    });

    let dns_engine = Arc::new(FakeIpDnsEngine::new(&DnsConfig::default()).unwrap());
    let mut outbounds = HashMap::new();
    outbounds.insert("THROTTLED-UPLOAD".to_string(), throttled_ob);
    let rules = vec!["MATCH,THROTTLED-UPLOAD".to_string()];
    let router = Arc::new(
        Router::new(
            RunMode::Rule,
            outbounds,
            &[],
            &rules,
            Arc::clone(&dns_engine),
        )
        .unwrap(),
    );
    let router_slot = Arc::new(RwLock::new(router));
    let hub = Arc::new(TelemetryHub::new());
    let (mut vtun, tun_task) =
        spawn_userspace_tun(1500, router_slot, Arc::clone(&hub), shutdown_rx.clone());

    let mut guest_dev = GuestDevice {
        rx: VecDeque::new(),
        tx: VecDeque::new(),
    };
    let mut cfg = IfaceConfig::new(HardwareAddress::Ip);
    cfg.random_seed = 0x5151_A5A5;
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
    // Large guest TX buffer (128 KiB) + 64 KiB RX buffer negotiates RFC 1323 window scaling
    let mut guest_tcp = tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0u8; 64 * 1024]),
        tcp::SocketBuffer::new(vec![0u8; 128 * 1024]),
    );
    guest_tcp.set_nagle_enabled(false);
    let guest_handle = guest_sockets.add(guest_tcp);
    {
        let sock = guest_sockets.get_mut::<tcp::Socket>(guest_handle);
        sock.connect(
            guest_iface.context(),
            IpEndpoint::new(IpAddress::Ipv4(Ipv4Addr::new(198, 51, 100, 42)), 8443),
            54321,
        )
        .unwrap();
    }

    let mut sent_offset = 0usize;
    let mut fin_sent = false;
    let mut received_reply = Vec::new();
    let mut data_pkt_idx = 0usize;
    let mut held_reorder: Option<(Vec<u8>, u8)> = None;
    let mut reordered_count = 0usize;
    let mut duplicated_count = 0usize;
    let mut dropped_count = 0usize;
    let mut zero_window_count = 0usize;
    let mut window_reopen_count = 0usize;
    let mut prev_window_was_zero = false;
    let mut dup_ack_count = 0usize;
    let mut last_ack_num: Option<u32> = None;
    let mut phase3_started_at: Option<tokio::time::Instant> = None;

    let deadline = tokio::time::Instant::now() + Duration::from_secs(25);
    while tokio::time::Instant::now() < deadline {
        let _ = guest_iface.poll(now_smol(), &mut guest_dev, &mut guest_sockets);

        // Feed guest -> TUN packets while deterministically injecting out-of-order delivery,
        // duplicate segments, and controlled packet drops to exercise retransmission & SACK.
        let mut forwarded_any = false;
        while let Some(out_pkt) = guest_dev.tx.pop_front() {
            forwarded_any = true;
            let is_pure_data_pkt = Ipv4Packet::new_checked(&out_pkt)
                .ok()
                .and_then(|ip| TcpPacket::new_checked(ip.payload()).ok())
                .is_some_and(|tcp| {
                    !tcp.syn() && !tcp.fin() && !tcp.rst() && !tcp.payload().is_empty()
                });

            if is_pure_data_pkt {
                data_pkt_idx += 1;

                // Controlled drop (up to 6 drops across the upload) to force real TCP retransmit
                if dropped_count < 6 && data_pkt_idx % 211 == 17 {
                    dropped_count += 1;
                    continue;
                }

                // Hold 1 packet back by 2 packets to force out-of-order RX + duplicate ACK
                if held_reorder.is_none() && data_pkt_idx % 37 == 5 {
                    held_reorder = Some((out_pkt, 2));
                    continue;
                }

                // Duplicate selected packets to stress out-of-window / already-ACKed RX handling
                if data_pkt_idx % 53 == 11 {
                    duplicated_count += 1;
                    let _ = vtun.ingress_tx.send(out_pkt.clone()).await;
                }
            }

            vtun.ingress_tx.send(out_pkt).await.unwrap();

            if let Some((held_pkt, remaining)) = held_reorder.take() {
                if remaining <= 1 {
                    reordered_count += 1;
                    vtun.ingress_tx.send(held_pkt).await.unwrap();
                } else {
                    held_reorder = Some((held_pkt, remaining - 1));
                }
            }
        }

        // Flush any held out-of-order packet once guest finishes pushing a burst
        if !forwarded_any && let Some((held_pkt, _)) = held_reorder.take() {
            reordered_count += 1;
            vtun.ingress_tx.send(held_pkt).await.unwrap();
        }

        // Drain TUN -> guest packets and observe TCP receive-window transitions & duplicate ACKs
        let mut received_egress = false;
        while let Ok(in_pkt) = vtun.egress_rx.try_recv() {
            received_egress = true;
            if let Ok(ip) = Ipv4Packet::new_checked(&in_pkt)
                && let Ok(tcp_pkt) = TcpPacket::new_checked(ip.payload())
                && tcp_pkt.ack()
                && !tcp_pkt.syn()
            {
                let win = tcp_pkt.window_len();
                if win == 0 {
                    zero_window_count += 1;
                    prev_window_was_zero = true;
                    release_initial_stall.store(true, Ordering::Release);
                } else if prev_window_was_zero {
                    window_reopen_count += 1;
                    prev_window_was_zero = false;
                }
                let ack = tcp_pkt.ack_number().0 as u32;
                if last_ack_num == Some(ack) && tcp_pkt.payload().is_empty() {
                    dup_ack_count += 1;
                }
                last_ack_num = Some(ack);
            }
            guest_dev.rx.push_back(in_pkt);
        }

        let _ = guest_iface.poll(now_smol(), &mut guest_dev, &mut guest_sockets);

        let sock = guest_sockets.get_mut::<tcp::Socket>(guest_handle);
        if sock.can_send() && sent_offset < payload.len() {
            // Alternate odd write sizes (4099 / 1459 / 16381) so segment boundaries never stay even
            let step = match (sent_offset / 4099) % 3 {
                0 => 4099,
                1 => 1459,
                _ => 16381,
            };
            let end = (sent_offset + step).min(payload.len());
            let n = sock.send_slice(&payload[sent_offset..end]).unwrap();
            sent_offset += n;
            if sent_offset >= 2 * 1024 * 1024 && phase3_started_at.is_none() {
                phase3_started_at = Some(tokio::time::Instant::now());
            }
        } else if sent_offset == payload.len() && !fin_sent && sock.send_queue() == 0 {
            sock.close();
            fin_sent = true;
        }

        if sock.can_recv() {
            let _ = sock.recv(|data| {
                received_reply.extend_from_slice(data);
                (data.len(), ())
            });
            if received_reply.len()
                >= format!("UPLOAD-OK:{TOTAL_UPLOAD_BYTES}:{expected_hash}").len()
            {
                break;
            }
        }

        if !forwarded_any && !received_egress {
            tokio::time::sleep(Duration::from_millis(1)).await;
        } else {
            tokio::task::yield_now().await;
        }
    }

    let expected_reply = format!("UPLOAD-OK:{TOTAL_UPLOAD_BYTES}:{expected_hash}");
    assert_eq!(
        String::from_utf8_lossy(&received_reply),
        expected_reply,
        "Full ~3 MiB upload must arrive bit-for-bit intact under heavy backpressure (sent={sent_offset}/{TOTAL_UPLOAD_BYTES}, received_by_outbound={}, zero_win={zero_window_count}, reopen={window_reopen_count}, dup_ack={dup_ack_count}, reordered={reordered_count}, dup_pkt={duplicated_count}, dropped={dropped_count})",
        received_bytes.load(Ordering::Acquire)
    );
    assert!(
        zero_window_count > 0,
        "stress test must saturate smoltcp RX buffer and trigger zero-window advertisements"
    );
    assert!(
        window_reopen_count > 0,
        "stress test must observe TCP receive window reopening after zero-window backpressure"
    );
    assert!(
        reordered_count > 0 && duplicated_count > 0 && dropped_count > 0 && dup_ack_count > 0,
        "stress test must exercise out-of-order ({reordered_count}), duplicate packets ({duplicated_count}), drops ({dropped_count}), and duplicate ACKs ({dup_ack_count})"
    );
    if let Some(t3) = phase3_started_at {
        assert!(
            t3.elapsed() < Duration::from_secs(10),
            "throughput must recover promptly once outbound throttling lifts (phase 3 took {:?})",
            t3.elapsed()
        );
    }

    let panic_logs: Vec<_> = hub
        .recent_logs()
        .into_iter()
        .filter(|entry| {
            entry.level == "error"
                && (entry.payload.contains("Isolated smoltcp panic")
                    || entry.payload.contains("Isolated panic in TCP flow"))
        })
        .collect();
    assert!(
        panic_logs.is_empty(),
        "smoltcp 0.14 must complete high-backpressure upload with ZERO isolated panics, got: {panic_logs:?}"
    );
    assert!(
        !tun_task.is_finished(),
        "TUN event loop task must remain healthy and running after high-backpressure upload"
    );

    let _ = shutdown_tx.send(true);
    tokio::time::timeout(Duration::from_secs(2), tun_task)
        .await
        .expect("TUN task must exit promptly on shutdown")
        .expect("TUN task must exit cleanly without panicking");
}

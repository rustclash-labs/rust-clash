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

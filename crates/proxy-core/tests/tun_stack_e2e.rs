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

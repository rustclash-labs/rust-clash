use std::{
    collections::{HashMap, VecDeque},
    fs,
    net::{Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

use bytes::{BufMut, BytesMut};
use parking_lot::Mutex;
use proxy_core::{
    addr::TargetAddr,
    api::spawn_api_server,
    config::{ClashConfig, RunMode},
    dns::wire::{DnsAnswerData, DnsQueryPacket, QTYPE_A, build_dns_query, extract_ip_answers},
    engine::ProxyEngine,
    inbound::tun::{VirtualTunHandle, build_ipv4_udp_packet},
    outbound::vless::{VLESS_CMD_TCP, VLESS_CMD_UDP},
    platform::socket_protect::{
        CallbackSocketProtector, clear_global_socket_protector, set_global_socket_protector,
    },
    profile::{ProfileManager, RoutingPresetChoice, RulePreset},
    router::geodata::{GeoDataManager, GeoDataset, GeoUpdateUrls, install_live_geodata},
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
    net::{TcpListener, TcpStream, UdpSocket},
    sync::watch,
};
use uuid::Uuid;

/// Serialize global `SocketProtector` and `LIVE_GEODATA` mutations across tests in this binary.
static SPLIT_TUNNEL_E2E_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct TempTestDir {
    path: PathBuf,
}

impl TempTestDir {
    fn new(prefix: &str) -> Self {
        let path = std::env::temp_dir().join(format!("rust-clash-{prefix}-{}", Uuid::new_v4()));
        fs::create_dir_all(&path).expect("create TempTestDir");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempTestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

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

async fn api_request(
    addr: SocketAddr,
    method: &str,
    path: &str,
    secret: &str,
    body: Option<&str>,
) -> (u16, String) {
    let mut stream = TcpStream::connect(addr).await.expect("connect control API");
    let payload = body.unwrap_or("");
    let req = if body.is_some() {
        format!(
            "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nAuthorization: Bearer {secret}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
            addr.port(),
            payload.len()
        )
    } else {
        format!(
            "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nAuthorization: Bearer {secret}\r\nConnection: close\r\n\r\n",
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

/// Spawn a local UDP authoritative DNS server representing Mainland Direct DNS (`223.5.5.5` / `119.29.29.29`).
/// Records every queried QNAME so tests can prove:
/// 1. Domestic domains (`www.baidu.com`, `www.bilibili.com`) & proxy server hostnames (`hk-node.proxy.test`)
///    ARE resolved cleanly via protected sockets.
/// 2. International domains (`www.google.com`, `www.youtube.com`, `unknown-foreign-app.io`) are NEVER
///    leaked to local Mainland DNS in `smart-cn` mode!
async fn spawn_authoritative_direct_dns(
    records: Arc<Mutex<HashMap<String, Ipv4Addr>>>,
    mut shutdown: watch::Receiver<bool>,
) -> (SocketAddr, Arc<Mutex<Vec<String>>>) {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    let queries = Arc::new(Mutex::new(Vec::new()));
    let queries_clone = Arc::clone(&queries);

    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        loop {
            tokio::select! {
                _ = shutdown.changed() => break,
                recv = sock.recv_from(&mut buf) => {
                    let Ok((n, peer)) = recv else { continue };
                    let Ok(pkt) = DnsQueryPacket::parse(&buf[..n]) else { continue };
                    let qname = pkt.question.name.trim_end_matches('.').to_ascii_lowercase();
                    queries_clone.lock().push(qname.clone());

                    let resp = if pkt.question.qtype == QTYPE_A {
                        if let Some(&v4) = records.lock().get(&qname) {
                            pkt.build_response(&buf[..n], 0, 60, &[DnsAnswerData::A(v4)])
                        } else {
                            pkt.build_response(&buf[..n], 3, 60, &[])
                        }
                    } else {
                        pkt.build_response(&buf[..n], 0, 60, &[])
                    };
                    let _ = sock.send_to(&resp, peer).await;
                }
            }
        }
    });

    (addr, queries)
}

async fn spawn_tagged_tcp_origin(
    tag: &'static str,
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
                accepted = listener.accept() => {
                    let Ok((mut stream, _)) = accepted else { continue };
                    let h = Arc::clone(&hits_clone);
                    tokio::spawn(async move {
                        let mut buf = [0u8; 4096];
                        let n = stream.read(&mut buf).await.unwrap_or(0);
                        if n > 0 {
                            h.fetch_add(1, Ordering::Relaxed);
                            let mut out = format!("{tag}:").into_bytes();
                            out.extend_from_slice(&buf[..n]);
                            let _ = stream.write_all(&out).await;
                            let _ = stream.shutdown().await;
                        }
                    });
                }
            }
        }
    });

    (addr, hits)
}

async fn spawn_tagged_udp_origin(
    tag: &'static str,
    mut shutdown: watch::Receiver<bool>,
) -> (SocketAddr, Arc<AtomicUsize>) {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_clone = Arc::clone(&hits);

    tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        loop {
            tokio::select! {
                _ = shutdown.changed() => break,
                recv = sock.recv_from(&mut buf) => {
                    let Ok((n, peer)) = recv else { continue };
                    hits_clone.fetch_add(1, Ordering::Relaxed);
                    let mut out = format!("{tag}:").into_bytes();
                    out.extend_from_slice(&buf[..n]);
                    let _ = sock.send_to(&out, peer).await;
                }
            }
        }
    });

    (addr, hits)
}

struct RecordingVlessServerStats {
    tcp_hits: AtomicUsize,
    udp_hits: AtomicUsize,
    tcp_targets: Mutex<Vec<TargetAddr>>,
    udp_targets: Mutex<Vec<TargetAddr>>,
}

/// Real VLESS v0 wire-protocol proxy server that authenticates client UUID, records the exact
/// wire-decoded `TargetAddr` (proving domain names are preserved inside the encrypted tunnel
/// rather than leaking or sending Fake-IPs), and relays TCP/UDP to local origin `127.0.0.1:<target.port>`.
async fn spawn_recording_vless_server(
    expected_uuid: Uuid,
    mut shutdown: watch::Receiver<bool>,
) -> (SocketAddr, Arc<RecordingVlessServerStats>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bound = listener.local_addr().unwrap();
    let stats = Arc::new(RecordingVlessServerStats {
        tcp_hits: AtomicUsize::new(0),
        udp_hits: AtomicUsize::new(0),
        tcp_targets: Mutex::new(Vec::new()),
        udp_targets: Mutex::new(Vec::new()),
    });
    let stats_clone = Arc::clone(&stats);

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = shutdown.changed() => break,
                accepted = listener.accept() => {
                    let Ok((mut stream, _)) = accepted else { continue };
                    let _ = stream.set_nodelay(true);
                    let st = Arc::clone(&stats_clone);
                    tokio::spawn(async move {
                        let Ok(ver) = stream.read_u8().await else { return };
                        if ver != 0x00 {
                            return;
                        }
                        let mut uuid_bytes = [0u8; 16];
                        if stream.read_exact(&mut uuid_bytes).await.is_err() {
                            return;
                        }
                        if Uuid::from_bytes(uuid_bytes) != expected_uuid {
                            return;
                        }
                        let Ok(addons_len) = stream.read_u8().await else { return };
                        if addons_len > 0 {
                            let mut skip = vec![0u8; addons_len as usize];
                            if stream.read_exact(&mut skip).await.is_err() {
                                return;
                            }
                        }
                        let Ok(cmd) = stream.read_u8().await else { return };
                        let Ok(target) = TargetAddr::read_vless(&mut stream).await else { return };
                        let local_origin = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), target.port);

                        match cmd {
                            VLESS_CMD_TCP => {
                                st.tcp_hits.fetch_add(1, Ordering::Relaxed);
                                st.tcp_targets.lock().push(target);
                                let Ok(mut upstream) = TcpStream::connect(local_origin).await else {
                                    return;
                                };
                                if stream.write_all(&[0x00, 0x00]).await.is_err() {
                                    return;
                                }
                                let _ = tokio::io::copy_bidirectional(&mut stream, &mut upstream).await;
                            }
                            VLESS_CMD_UDP => {
                                st.udp_hits.fetch_add(1, Ordering::Relaxed);
                                st.udp_targets.lock().push(target);
                                let Ok(udp) = UdpSocket::bind("127.0.0.1:0").await else { return };
                                let udp = Arc::new(udp);
                                let udp_rx = Arc::clone(&udp);
                                let (mut rd, mut wr) = tokio::io::split(stream);

                                let c2u = async move {
                                    while let Ok(plen) = rd.read_u16().await {
                                        let mut dgram = vec![0u8; plen as usize];
                                        if rd.read_exact(&mut dgram).await.is_err() {
                                            break;
                                        }
                                        let _ = udp.send_to(&dgram, local_origin).await;
                                    }
                                };
                                let u2c = async move {
                                    let mut hdr_sent = false;
                                    let mut rbuf = [0u8; 4096];
                                    while let Ok(Ok((n, _))) =
                                        tokio::time::timeout(Duration::from_secs(5), udp_rx.recv_from(&mut rbuf)).await
                                    {
                                        let mut out = BytesMut::with_capacity(4 + n);
                                        if !hdr_sent {
                                            out.put_slice(&[0x00, 0x00]);
                                            hdr_sent = true;
                                        }
                                        out.put_u16(n as u16);
                                        out.put_slice(&rbuf[..n]);
                                        if wr.write_all(&out).await.is_err() || wr.flush().await.is_err() {
                                            break;
                                        }
                                    }
                                };
                                tokio::select! {
                                    _ = c2u => {}
                                    _ = u2c => {}
                                }
                            }
                            _ => {}
                        }
                    });
                }
            }
        }
    });

    (bound, stats)
}

async fn tun_dns_resolve_fake_ip(vtun: &mut VirtualTunHandle, id: u16, domain: &str) -> Ipv4Addr {
    let q = build_dns_query(id, domain, QTYPE_A);
    let pkt = build_ipv4_udp_packet(
        Ipv4Addr::new(198, 18, 0, 2),
        53000 + (id % 1000),
        Ipv4Addr::new(198, 18, 0, 1),
        53,
        &q,
    )
    .expect("build UDP DNS packet");
    vtun.ingress_tx
        .send(pkt)
        .await
        .expect("send DNS packet into TUN");

    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    while tokio::time::Instant::now() < deadline {
        let maybe_pkt =
            tokio::time::timeout(Duration::from_millis(400), vtun.egress_rx.recv()).await;
        let Ok(Some(egress)) = maybe_pkt else {
            continue;
        };
        let Ok(ip4) = Ipv4Packet::new_checked(&egress) else {
            continue;
        };
        if ip4.next_header() != smoltcp::wire::IpProtocol::Udp {
            continue;
        }
        let Ok(udp) = UdpPacket::new_checked(ip4.payload()) else {
            continue;
        };
        if udp.src_port() != 53 {
            continue;
        }
        let Ok(answers) = extract_ip_answers(udp.payload()) else {
            continue;
        };
        for ans in answers {
            if let DnsAnswerData::A(v4) = ans {
                return v4;
            }
        }
    }
    panic!("timed out waiting for TUN Fake-IP DNS response for {domain}");
}

async fn tun_tcp_roundtrip(
    vtun: &mut VirtualTunHandle,
    dst_ip: Ipv4Addr,
    dst_port: u16,
    local_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut guest_dev = GuestDevice {
        rx: VecDeque::new(),
        tx: VecDeque::new(),
    };
    let mut cfg = IfaceConfig::new(HardwareAddress::Ip);
    cfg.random_seed = 0x9000_0000 + u64::from(local_port);
    let boot = std::time::Instant::now();
    let now_smol = || SmolInstant::from_micros(boot.elapsed().as_micros() as i64);

    let mut guest_iface = Interface::new(cfg, &mut guest_dev, now_smol());
    guest_iface.update_ip_addrs(|addrs| {
        let _ = addrs.push(IpCidr::new(
            IpAddress::Ipv4(Ipv4Addr::new(198, 18, 0, 2)),
            15,
        ));
    });
    let _ = guest_iface
        .routes_mut()
        .add_default_ipv4_route(Ipv4Addr::new(198, 18, 0, 1));

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
            IpEndpoint::new(IpAddress::Ipv4(dst_ip), dst_port),
            local_port,
        )
        .expect("guest TCP connect");
    }

    let mut sent = false;
    let mut received = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(6);

    while tokio::time::Instant::now() < deadline {
        let _ = guest_iface.poll(now_smol(), &mut guest_dev, &mut guest_sockets);
        while let Some(out_pkt) = guest_dev.tx.pop_front() {
            vtun.ingress_tx.send(out_pkt).await.expect("send TUN L3");
        }

        tokio::time::sleep(Duration::from_millis(8)).await;
        while let Ok(in_pkt) = vtun.egress_rx.try_recv() {
            guest_dev.rx.push_back(in_pkt);
        }
        let _ = guest_iface.poll(now_smol(), &mut guest_dev, &mut guest_sockets);

        let sock = guest_sockets.get_mut::<tcp::Socket>(guest_handle);
        if sock.can_send() && !sent {
            sock.send_slice(payload).expect("guest TCP send");
            sent = true;
        }
        if sock.can_recv() {
            let _ = sock.recv(|data| {
                received.extend_from_slice(data);
                (data.len(), ())
            });
        }
        if !received.is_empty() {
            sock.close();
            let _ = guest_iface.poll(now_smol(), &mut guest_dev, &mut guest_sockets);
            while let Some(out_pkt) = guest_dev.tx.pop_front() {
                let _ = vtun.ingress_tx.send(out_pkt).await;
            }
            break;
        }
    }

    assert!(
        !received.is_empty(),
        "timed out waiting for TUN TCP response from {dst_ip}:{dst_port}"
    );
    received
}

async fn tun_udp_roundtrip(
    vtun: &mut VirtualTunHandle,
    dst_ip: Ipv4Addr,
    dst_port: u16,
    local_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let pkt = build_ipv4_udp_packet(
        Ipv4Addr::new(198, 18, 0, 2),
        local_port,
        dst_ip,
        dst_port,
        payload,
    )
    .expect("build TUN UDP datagram");
    vtun.ingress_tx
        .send(pkt)
        .await
        .expect("inject TUN UDP datagram");

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while tokio::time::Instant::now() < deadline {
        let maybe_pkt =
            tokio::time::timeout(Duration::from_millis(400), vtun.egress_rx.recv()).await;
        let Ok(Some(egress)) = maybe_pkt else {
            continue;
        };
        let Ok(ip4) = Ipv4Packet::new_checked(&egress) else {
            continue;
        };
        if ip4.next_header() != smoltcp::wire::IpProtocol::Udp || ip4.src_addr() != dst_ip {
            continue;
        }
        let Ok(udp) = UdpPacket::new_checked(ip4.payload()) else {
            continue;
        };
        if udp.src_port() == dst_port && udp.dst_port() == local_port {
            return udp.payload().to_vec();
        }
    }
    panic!("timed out waiting for TUN UDP reply from {dst_ip}:{dst_port}");
}

#[tokio::test]
async fn real_l3_smoltcp_tun_split_tunneling_tcp_udp_fake_ip_and_diagnostics_e2e() {
    let _serial = SPLIT_TUNNEL_E2E_LOCK.lock().await;
    install_live_geodata(Arc::new(GeoDataset::builtin_only()));

    let protector = Arc::new(CallbackSocketProtector::counting(
        "android-vpn-protect-e2e",
        true,
    ));
    set_global_socket_protector(protector.clone());

    let (stop_tx, stop_rx) = watch::channel(false);

    // 1. Authoritative Mainland Direct DNS (`223.5.5.5` stand-in)
    let dns_records = Arc::new(Mutex::new(HashMap::from([
        ("hk-node.proxy.test".to_string(), Ipv4Addr::LOCALHOST),
        ("jp-node.proxy.test".to_string(), Ipv4Addr::LOCALHOST),
        ("www.baidu.com".to_string(), Ipv4Addr::LOCALHOST),
        ("www.bilibili.com".to_string(), Ipv4Addr::LOCALHOST),
        ("m.taobao.com".to_string(), Ipv4Addr::LOCALHOST),
    ])));
    let (cn_dns_addr, cn_dns_queries) =
        spawn_authoritative_direct_dns(Arc::clone(&dns_records), stop_rx.clone()).await;

    // 2. Separate Domestic & International TCP + UDP Origins
    let (cn_tcp_addr, cn_tcp_hits) =
        spawn_tagged_tcp_origin("CN-DIRECT-TCP", stop_rx.clone()).await;
    let (cn_udp_addr, cn_udp_hits) =
        spawn_tagged_udp_origin("CN-DIRECT-UDP", stop_rx.clone()).await;
    let (intl_tcp_addr, intl_tcp_hits) =
        spawn_tagged_tcp_origin("INTL-ORIGIN-TCP", stop_rx.clone()).await;
    let (intl_udp_addr, intl_udp_hits) =
        spawn_tagged_udp_origin("INTL-ORIGIN-UDP", stop_rx.clone()).await;

    // 3. Two Real Wire-Protocol VLESS v0 Proxy Servers (`Node-HK` & `Node-JP`)
    // Both configured with DOMAIN server names (`hk-node.proxy.test`, `jp-node.proxy.test`) to verify
    // bootstrap DNS resolution via protected sockets with ZERO Fake-IP self-routing loop!
    let hk_uuid = Uuid::new_v4();
    let jp_uuid = Uuid::new_v4();
    let (hk_addr, hk_stats) = spawn_recording_vless_server(hk_uuid, stop_rx.clone()).await;
    let (jp_addr, jp_stats) = spawn_recording_vless_server(jp_uuid, stop_rx.clone()).await;

    // 4. Initialize fresh ProfileManager (`Starter Profile (Smart CN)`), import Node-HK + Node-JP
    let temp = TempTestDir::new("split-tun");
    let state_dir = temp.path().to_path_buf();
    let mgr = ProfileManager::open_or_init(&state_dir).expect("init ProfileManager");

    let snap0 = mgr.routing_snapshot().expect("initial routing snapshot");
    assert_eq!(snap0.active_choice, RoutingPresetChoice::SmartCn);
    assert_eq!(snap0.mode, RunMode::Rule);
    assert_eq!(snap0.rule_preset, RulePreset::SmartCn);

    let uris = format!(
        "vless://{hk_uuid}@hk-node.proxy.test:{}?security=none&encryption=none#Node-HK\n\
         vless://{jp_uuid}@jp-node.proxy.test:{}?security=none&encryption=none#Node-JP",
        hk_addr.port(),
        jp_addr.port()
    );
    let imp = mgr
        .import_nodes_to_active(&uris, true, true)
        .expect("import VLESS nodes into starter profile");
    assert_eq!(
        imp.selected_groups.get("PROXY").map(String::as_str),
        Some("Node-HK")
    );

    // Point `default-nameserver` & `direct-nameserver` to our local Mainland DNS stand-in,
    // and enable Virtual `smoltcp` L3 TUN (`tun.enable = true`, `tun.auto_route = false`,
    // identical packet path to Android VpnService)!
    let ctrl_secret = "split-tunnel-e2e-secret";
    let (mut boot_cfg, boot_path) = mgr.load_active_config().expect("load active config");
    boot_cfg.mixed_port = 0;
    boot_cfg.external_controller = "127.0.0.1:0".into();
    boot_cfg.secret = Some(ctrl_secret.into());
    boot_cfg.dns.listen = "127.0.0.1:0".into();
    boot_cfg.dns.default_nameserver = vec![cn_dns_addr.to_string()];
    boot_cfg.dns.direct_nameserver = vec![cn_dns_addr.to_string()];
    boot_cfg.dns.nameserver = vec![cn_dns_addr.to_string()];
    boot_cfg.tun.enable = true;
    boot_cfg.tun.auto_route = false;
    fs::write(&boot_path, boot_cfg.to_yaml_string().unwrap()).unwrap();

    let engine = ProxyEngine::start_with_state_dir(boot_cfg, state_dir.clone())
        .await
        .expect("start ProxyEngine with Virtual TUN");
    engine.attach_profile_manager(Arc::clone(&mgr));
    for (g, p) in mgr.active_selected_groups() {
        let _ = engine.select_group_and_persist(&g, &p);
    }

    let mut vtun = engine
        .take_virtual_tun_handle()
        .expect("VirtualTunHandle must be active");

    let (api_stop_tx, api_stop_rx) = watch::channel(false);
    let (api_addr, _api_task) = spawn_api_server("127.0.0.1:0", Arc::clone(&engine), api_stop_rx)
        .await
        .expect("spawn control API");

    // =========================================================================
    // STEP A: Default `smart-cn` Split-Tunneling over Real L3 `smoltcp` TUN
    // =========================================================================
    let fip_baidu = tun_dns_resolve_fake_ip(&mut vtun, 0x1001, "www.baidu.com").await;
    let fip_bilibili = tun_dns_resolve_fake_ip(&mut vtun, 0x1002, "www.bilibili.com").await;
    let fip_google = tun_dns_resolve_fake_ip(&mut vtun, 0x1003, "www.google.com").await;
    let fip_youtube = tun_dns_resolve_fake_ip(&mut vtun, 0x1004, "www.youtube.com").await;
    let fip_unknown_intl =
        tun_dns_resolve_fake_ip(&mut vtun, 0x1005, "unknown-foreign-app.io").await;

    for fip in [
        fip_baidu,
        fip_bilibili,
        fip_google,
        fip_youtube,
        fip_unknown_intl,
    ] {
        assert_eq!(fip.octets()[0], 198);
        assert!(fip.octets()[1] == 18 || fip.octets()[1] == 19);
    }

    // Clear startup health-check DNS queries before measuring live user traffic DNS behavior
    cn_dns_queries.lock().clear();
    let tcp_prot_before = protector.tcp_count();
    let udp_prot_before = protector.udp_count();

    // A1. Domestic TCP (`www.baidu.com`) -> MUST go `DIRECT` (0 proxy hits, resolved via `direct-nameserver`)!
    let resp_baidu = tun_tcp_roundtrip(
        &mut vtun,
        fip_baidu,
        cn_tcp_addr.port(),
        50101,
        b"hello-baidu",
    )
    .await;
    assert_eq!(resp_baidu, b"CN-DIRECT-TCP:hello-baidu");
    assert_eq!(cn_tcp_hits.load(Ordering::Relaxed), 1);
    assert_eq!(
        hk_stats.tcp_hits.load(Ordering::Relaxed),
        0,
        "domestic www.baidu.com MUST NOT traverse proxy in smart-cn mode!"
    );

    // A2. International TCP (`www.google.com`) -> MUST traverse `Node-HK` with wire domain `"www.google.com"`!
    let resp_google = tun_tcp_roundtrip(
        &mut vtun,
        fip_google,
        intl_tcp_addr.port(),
        50102,
        b"hello-google",
    )
    .await;
    assert_eq!(resp_google, b"INTL-ORIGIN-TCP:hello-google");
    assert_eq!(intl_tcp_hits.load(Ordering::Relaxed), 1);
    assert_eq!(hk_stats.tcp_hits.load(Ordering::Relaxed), 1);
    assert_eq!(
        hk_stats.tcp_targets.lock().last(),
        Some(&TargetAddr::new_domain("www.google.com", intl_tcp_addr.port()).unwrap()),
        "Fake-IP MUST be restored to original domain and sent encrypted to VLESS server"
    );

    // A3. Uncategorized foreign domain (`unknown-foreign-app.io`) -> MUST hit `MATCH,PROXY` WITHOUT
    // querying domestic `223.5.5.5` DNS (zero local DNS leak, zero Mainland DNS poisoning)!
    let resp_unknown = tun_tcp_roundtrip(
        &mut vtun,
        fip_unknown_intl,
        intl_tcp_addr.port(),
        50103,
        b"hello-startup",
    )
    .await;
    assert_eq!(resp_unknown, b"INTL-ORIGIN-TCP:hello-startup");
    assert_eq!(hk_stats.tcp_hits.load(Ordering::Relaxed), 2);

    // A4. Domestic UDP (`www.bilibili.com`) -> MUST go `DIRECT`!
    let resp_bili_udp = tun_udp_roundtrip(
        &mut vtun,
        fip_bilibili,
        cn_udp_addr.port(),
        51101,
        b"danmaku-cn",
    )
    .await;
    assert_eq!(resp_bili_udp, b"CN-DIRECT-UDP:danmaku-cn");
    assert_eq!(cn_udp_hits.load(Ordering::Relaxed), 1);
    assert_eq!(hk_stats.udp_hits.load(Ordering::Relaxed), 0);

    // A5. International UDP (`www.youtube.com`) -> MUST traverse `Node-HK` VLESS UDP with domain `"www.youtube.com"`!
    let resp_yt_udp = tun_udp_roundtrip(
        &mut vtun,
        fip_youtube,
        intl_udp_addr.port(),
        51102,
        b"quic-intl",
    )
    .await;
    assert_eq!(resp_yt_udp, b"INTL-ORIGIN-UDP:quic-intl");
    assert_eq!(intl_udp_hits.load(Ordering::Relaxed), 1);
    assert_eq!(hk_stats.udp_hits.load(Ordering::Relaxed), 1);
    assert_eq!(
        hk_stats.udp_targets.lock().last(),
        Some(&TargetAddr::new_domain("www.youtube.com", intl_udp_addr.port()).unwrap())
    );

    // Verify ZERO local DNS leak for all international domains while domestic + proxy bootstrap resolved cleanly!
    {
        let observed_dns = cn_dns_queries.lock().clone();
        assert!(
            observed_dns.iter().any(|q| q == "www.baidu.com"),
            "expected domestic www.baidu.com to resolve via direct-nameserver, got {observed_dns:?}"
        );
        assert!(
            observed_dns.iter().any(|q| q == "www.bilibili.com"),
            "expected domestic www.bilibili.com to resolve via direct-nameserver, got {observed_dns:?}"
        );
        for forbidden in [
            "www.google.com",
            "www.youtube.com",
            "unknown-foreign-app.io",
        ] {
            assert!(
                !observed_dns.iter().any(|q| q == forbidden),
                "DNS LEAK DETECTED: foreign domain '{forbidden}' was queried against Mainland direct DNS! ({observed_dns:?})"
            );
        }
    }

    // Verify `VpnService.protect(fd)` (`SocketProtector`) protected BOTH TCP and UDP sockets!
    assert!(
        protector.tcp_count() >= tcp_prot_before + 3,
        "expected SocketProtector to protect both DIRECT and VLESS TCP sockets"
    );
    assert!(
        protector.udp_count() > udp_prot_before,
        "expected SocketProtector to protect DIRECT UDP + DNS sockets"
    );

    // Verify IPv4 & IPv6 GeoIP/GeoSite routing decisions via `/rules/explain`
    for (target_q, expected_exit, expected_ob) in [
        ("114.114.114.114:443", "DIRECT", "DIRECT"),
        ("[2400:3200::1]:443", "DIRECT", "DIRECT"),
        ("192.168.1.1:80", "DIRECT", "DIRECT"),
        ("[fd00::1234]:80", "DIRECT", "DIRECT"),
        ("8.8.8.8:443", "PROXY", "Node-HK"),
        ("[2606:4700:4700::1111]:443", "PROXY", "Node-HK"),
    ] {
        let path = format!("/rules/explain?target={target_q}");
        let (st, body) = api_request(api_addr, "GET", &path, ctrl_secret, None).await;
        assert_eq!(st, 200, "explain {target_q} failed: {body}");
        let ex: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(
            ex["exit_type"], expected_exit,
            "mismatch for {target_q}: {ex}"
        );
        assert_eq!(ex["outbound"], expected_ob, "mismatch for {target_q}: {ex}");
    }

    // Verify Connection-Level Diagnostics (`GET /connections/diagnostics`)!
    let (st_diag, body_diag) = api_request(
        api_addr,
        "GET",
        "/connections/diagnostics",
        ctrl_secret,
        None,
    )
    .await;
    assert_eq!(st_diag, 200);
    let diag_json: serde_json::Value = serde_json::from_str(&body_diag).unwrap();
    let entries = diag_json["diagnostics"]
        .as_array()
        .expect("diagnostics array");
    let baidu_diag = entries
        .iter()
        .find(|e| e["metadata"]["host"].as_str() == Some("www.baidu.com"))
        .expect("diagnostics must contain www.baidu.com");
    assert_eq!(baidu_diag["exit_type"], "DIRECT");
    assert_eq!(baidu_diag["effective_outbound"], "DIRECT");
    assert!(
        baidu_diag["rule"]
            .as_str()
            .unwrap_or("")
            .to_ascii_lowercase()
            .contains("geosite"),
        "expected GeoSite rule in baidu_diag: {baidu_diag}"
    );

    let google_diag = entries
        .iter()
        .find(|e| e["metadata"]["host"].as_str() == Some("www.google.com"))
        .expect("diagnostics must contain www.google.com");
    assert_eq!(google_diag["exit_type"], "PROXY");
    assert_eq!(google_diag["effective_outbound"], "Node-HK");
    assert_eq!(google_diag["effective_protocol"], "VLESS");
    assert!(
        google_diag["remote_endpoint"]
            .as_str()
            .unwrap_or("")
            .contains("hk-node.proxy.test"),
        "expected remote_endpoint to report proxy node endpoint, got {google_diag}"
    );

    // =========================================================================
    // STEP B: Live Routing Preset Switch (`Global` -> `Direct` -> `SmartCn`)
    //         WITHOUT dropping Virtual TUN!
    // =========================================================================
    // B1. Switch to `global` (`全局代理`): `www.baidu.com` MUST now traverse `Node-HK`!
    let (st_glob, body_glob) = api_request(
        api_addr,
        "PUT",
        "/routing/preset",
        ctrl_secret,
        Some(r#"{"preset":"global"}"#),
    )
    .await;
    assert_eq!(st_glob, 200, "switch to global failed: {body_glob}");
    assert!(
        engine.is_virtual_tun_active(),
        "Virtual TUN must remain seamlessly active across preset changes!"
    );

    let hk_before_global = hk_stats.tcp_hits.load(Ordering::Relaxed);
    let resp_baidu_global = tun_tcp_roundtrip(
        &mut vtun,
        fip_baidu,
        cn_tcp_addr.port(),
        50201,
        b"baidu-via-global-proxy",
    )
    .await;
    assert_eq!(resp_baidu_global, b"CN-DIRECT-TCP:baidu-via-global-proxy");
    assert_eq!(
        hk_stats.tcp_hits.load(Ordering::Relaxed),
        hk_before_global + 1,
        "in Global mode, even domestic www.baidu.com MUST traverse Node-HK!"
    );

    // B2. Switch to `direct` (`全局直连`): `www.google.com` MUST now connect `DIRECT`!
    dns_records
        .lock()
        .insert("www.google.com".to_string(), Ipv4Addr::LOCALHOST);
    let (st_dir, body_dir) = api_request(
        api_addr,
        "PUT",
        "/routing/preset",
        ctrl_secret,
        Some(r#"{"preset":"direct"}"#),
    )
    .await;
    assert_eq!(st_dir, 200, "switch to direct failed: {body_dir}");
    let hk_before_direct = hk_stats.tcp_hits.load(Ordering::Relaxed);
    let resp_google_direct = tun_tcp_roundtrip(
        &mut vtun,
        fip_google,
        intl_tcp_addr.port(),
        50202,
        b"google-via-direct",
    )
    .await;
    assert_eq!(resp_google_direct, b"INTL-ORIGIN-TCP:google-via-direct");
    assert_eq!(
        hk_stats.tcp_hits.load(Ordering::Relaxed),
        hk_before_direct,
        "in Direct mode, www.google.com MUST bypass proxy!"
    );
    dns_records.lock().remove("www.google.com");

    // B3. Switch back to `smart-cn` (`智能分流`)!
    let (st_scn, body_scn) = api_request(
        api_addr,
        "PUT",
        "/routing/preset",
        ctrl_secret,
        Some(r#"{"preset":"smart-cn"}"#),
    )
    .await;
    assert_eq!(st_scn, 200, "restore smart-cn failed: {body_scn}");

    // Note: hot-reload creates a fresh FakeIpDnsEngine instance, so re-resolve Fake-IPs via TUN DNS
    // (exactly like real client apps do after DNS cache flush) and verify split-tunneling is back!
    let fip_baidu_scn = tun_dns_resolve_fake_ip(&mut vtun, 0x1801, "www.baidu.com").await;
    let fip_google_scn = tun_dns_resolve_fake_ip(&mut vtun, 0x1802, "www.google.com").await;
    let hk_before_scn = hk_stats.tcp_hits.load(Ordering::Relaxed);
    let _ = tun_tcp_roundtrip(
        &mut vtun,
        fip_baidu_scn,
        cn_tcp_addr.port(),
        50203,
        b"cn-again",
    )
    .await;
    assert_eq!(hk_stats.tcp_hits.load(Ordering::Relaxed), hk_before_scn);
    let _ = tun_tcp_roundtrip(
        &mut vtun,
        fip_google_scn,
        intl_tcp_addr.port(),
        50204,
        b"intl-again",
    )
    .await;
    assert_eq!(hk_stats.tcp_hits.load(Ordering::Relaxed), hk_before_scn + 1);

    // =========================================================================
    // STEP C: Live Node Switch (`Node-HK -> Node-JP`) + Wi-Fi/Cellular Handoff
    // =========================================================================
    let (st_sel, body_sel) = api_request(
        api_addr,
        "PUT",
        "/proxies/PROXY",
        ctrl_secret,
        Some(r#"{"name":"Node-JP"}"#),
    )
    .await;
    assert_eq!(st_sel, 204, "select Node-JP failed: {body_sel}");

    let handoff = engine.notify_network_change();
    assert!(handoff.dns_cache_flushed);

    // Re-resolve Fake-IP after network handoff DNS flush and verify traffic shifts to `Node-JP`!
    let fip_google_after = tun_dns_resolve_fake_ip(&mut vtun, 0x2001, "www.google.com").await;
    let hk_before_jp = hk_stats.tcp_hits.load(Ordering::Relaxed);
    let resp_jp = tun_tcp_roundtrip(
        &mut vtun,
        fip_google_after,
        intl_tcp_addr.port(),
        50301,
        b"after-handoff-jp",
    )
    .await;
    assert_eq!(resp_jp, b"INTL-ORIGIN-TCP:after-handoff-jp");
    assert_eq!(hk_stats.tcp_hits.load(Ordering::Relaxed), hk_before_jp);
    assert_eq!(jp_stats.tcp_hits.load(Ordering::Relaxed), 1);

    let _ = api_stop_tx.send(true);
    engine.shutdown();
    let _ = stop_tx.send(true);
    clear_global_socket_protector();
}

#[tokio::test]
async fn custom_rules_preservation_legacy_starter_upgrade_and_geodata_lifecycle_e2e() {
    let _serial = SPLIT_TUNNEL_E2E_LOCK.lock().await;
    clear_global_socket_protector();
    install_live_geodata(Arc::new(GeoDataset::builtin_only()));

    // =========================================================================
    // PART A: Untouched <= v0.2.1 6-line Starter Profile Auto-Upgrades to `smart-cn`
    // =========================================================================
    let dir_legacy = TempTestDir::new("legacy-starter");
    let profiles_legacy = dir_legacy.path().join("profiles");
    fs::create_dir_all(&profiles_legacy).unwrap();
    let v021_starter_yaml = r#"mixed-port: 7890
mode: rule
dns:
  enable: true
  enhanced-mode: fake-ip
  nameserver:
    - 1.1.1.1:53
    - 8.8.8.8:53
proxies: []
proxy-groups:
  - name: PROXY
    type: select
    proxies:
      - DIRECT
rules:
  - DOMAIN-SUFFIX,local,DIRECT
  - IP-CIDR,127.0.0.0/8,DIRECT,no-resolve
  - IP-CIDR,10.0.0.0/8,DIRECT,no-resolve
  - IP-CIDR,172.16.0.0/12,DIRECT,no-resolve
  - IP-CIDR,192.168.0.0/16,DIRECT,no-resolve
  - MATCH,PROXY
"#;
    fs::write(
        profiles_legacy.join("starter-default.yaml"),
        v021_starter_yaml,
    )
    .unwrap();
    fs::write(
        profiles_legacy.join("profiles_index.json"),
        serde_json::json!({
            "active_profile_id": "starter-default",
            "onboarding_completed": false,
            "profiles": [{
                "id": "starter-default",
                "name": "Default Starter",
                "kind": "starter",
                "last_updated_ms": 1700000000000u64,
                "proxy_count": 0,
                "rule_count": 6,
                "selected_groups": {"PROXY": "DIRECT"}
            }]
        })
        .to_string(),
    )
    .unwrap();

    let mgr_legacy = ProfileManager::open_or_init(dir_legacy.path()).unwrap();
    let snap_legacy = mgr_legacy.routing_snapshot().unwrap();
    assert_eq!(snap_legacy.rule_preset, RulePreset::SmartCn);
    assert_eq!(snap_legacy.active_choice, RoutingPresetChoice::SmartCn);
    let (upgraded_cfg, _) = mgr_legacy.load_active_config().unwrap();
    assert!(upgraded_cfg.rules.iter().any(|r| r == "GEOSITE,cn,DIRECT"));
    assert!(
        upgraded_cfg
            .rules
            .iter()
            .any(|r| r == "GEOSITE,geolocation-!cn,PROXY")
    );
    assert!(
        upgraded_cfg
            .dns
            .direct_nameserver
            .contains(&"223.5.5.5:53".to_string())
    );
    assert!(
        upgraded_cfg
            .dns
            .nameserver
            .contains(&"https://dns.alidns.com/dns-query".to_string()),
        "legacy 1.1.1.1/8.8.8.8 starter nameservers must upgrade to Mainland-reachable DNS"
    );

    // =========================================================================
    // PART B & C: Existing User Custom Rules Are NEVER Overwritten on Upgrade,
    //             Node Import, Restart, or `Custom -> SmartCn -> Custom` Roundtrip!
    // =========================================================================
    let dir_custom = TempTestDir::new("custom-rules");
    let profiles_custom = dir_custom.path().join("profiles");
    fs::create_dir_all(&profiles_custom).unwrap();
    let custom_uuid = Uuid::new_v4();
    let custom_yaml = format!(
        r#"mixed-port: 7890
mode: rule
dns:
  enable: true
  enhanced-mode: fake-ip
  nameserver:
    - 223.5.5.5:53
proxies:
  - name: Corp-Gateway
    type: vless
    server: 127.0.0.1
    port: 18443
    uuid: "{custom_uuid}"
    tls: false
    udp: true
proxy-groups:
  - name: PROXY
    type: select
    proxies:
      - Corp-Gateway
      - DIRECT
rules:
  - DOMAIN-SUFFIX,intranet.corp.example,DIRECT
  - DOMAIN-KEYWORD,workday,Corp-Gateway
  - IP-CIDR,10.88.0.0/16,Corp-Gateway,no-resolve
  - MATCH,DIRECT
"#
    );
    fs::write(profiles_custom.join("user-custom.yaml"), &custom_yaml).unwrap();
    fs::write(
        profiles_custom.join("profiles_index.json"),
        serde_json::json!({
            "active_profile_id": "user-custom",
            "onboarding_completed": true,
            "profiles": [{
                "id": "user-custom",
                "name": "My Corporate Rules",
                "kind": "local-yaml",
                "last_updated_ms": 1700000000000u64,
                "proxy_count": 1,
                "rule_count": 4,
                "selected_groups": {"PROXY": "Corp-Gateway"}
            }]
        })
        .to_string(),
    )
    .unwrap();

    let expected_custom_rules = vec![
        "DOMAIN-SUFFIX,intranet.corp.example,DIRECT".to_string(),
        "DOMAIN-KEYWORD,workday,Corp-Gateway".to_string(),
        "IP-CIDR,10.88.0.0/16,Corp-Gateway,no-resolve".to_string(),
        "MATCH,DIRECT".to_string(),
    ];

    let mgr_custom = ProfileManager::open_or_init(dir_custom.path()).unwrap();
    let snap_custom = mgr_custom.routing_snapshot().unwrap();
    assert_eq!(snap_custom.rule_preset, RulePreset::Custom);
    assert_eq!(snap_custom.active_choice, RoutingPresetChoice::Custom);
    assert!(snap_custom.has_custom_rules_backup);
    assert_eq!(
        mgr_custom.load_active_config().unwrap().0.rules,
        expected_custom_rules
    );

    // Import an extra node -> custom rules MUST STILL remain untouched!
    let extra_uuid = Uuid::new_v4();
    mgr_custom
        .import_nodes_to_active(
            &format!("vless://{extra_uuid}@127.0.0.1:19443?security=none#Extra-Node"),
            true,
            false,
        )
        .unwrap();
    assert_eq!(
        mgr_custom.load_active_config().unwrap().0.rules,
        expected_custom_rules
    );

    // Switch `Custom -> SmartCn`, then back `SmartCn -> Custom` -> exact custom rules restored!
    let (snap_scn, cfg_scn) = mgr_custom
        .apply_routing_preset(RoutingPresetChoice::SmartCn)
        .unwrap();
    assert_eq!(snap_scn.active_choice, RoutingPresetChoice::SmartCn);
    assert!(cfg_scn.rules.iter().any(|r| r == "GEOSITE,cn,DIRECT"));
    assert!(snap_scn.has_custom_rules_backup);

    let (snap_restored, cfg_restored) = mgr_custom
        .apply_routing_preset(RoutingPresetChoice::Custom)
        .unwrap();
    assert_eq!(snap_restored.active_choice, RoutingPresetChoice::Custom);
    assert_eq!(
        cfg_restored.rules, expected_custom_rules,
        "switching back from SmartCn to Custom MUST restore user's exact custom rules!"
    );

    // =========================================================================
    // PART D: `GeoDataManager` Download, Dynamic Overlay, Failure Preservation,
    //         Expiration Tracking & Disk Persistence Across Restarts
    // =========================================================================
    let fail_mode = Arc::new(AtomicBool::new(false));
    let fail_mode_srv = Arc::clone(&fail_mode);
    let (geo_stop_tx, mut geo_stop_rx) = watch::channel(false);
    let geo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let geo_srv_addr = geo_listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = geo_stop_rx.changed() => break,
                accepted = geo_listener.accept() => {
                    let Ok((mut s, _)) = accepted else { continue };
                    let fail = fail_mode_srv.load(Ordering::Relaxed);
                    tokio::spawn(async move {
                        let mut buf = [0u8; 2048];
                        let n = s.read(&mut buf).await.unwrap_or(0);
                        let req = String::from_utf8_lossy(&buf[..n]);
                        let path = req.lines().next().and_then(|l| l.split_whitespace().nth(1)).unwrap_or("/");
                        if fail {
                            let resp = "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 11\r\nConnection: close\r\n\r\nmirror down";
                            let _ = s.write_all(resp.as_bytes()).await;
                            return;
                        }
                        let body = match path {
                            "/direct.txt" => "payload:\n  - '+.newly-launched-cn-bank.org'\n  - 'DOMAIN,exact-cn-gov.example'\n",
                            "/proxy.txt" => "payload:\n  - '+.newly-launched-ai-lab.org'\n",
                            "/cncidr.txt" => "payload:\n  - '203.0.113.0/24'\n  - '2001:db8:8888::/48'\n",
                            _ => "",
                        };
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        );
                        let _ = s.write_all(resp.as_bytes()).await;
                    });
                }
            }
        }
    });

    let geo_dir = TempTestDir::new("geodata-mgr");
    let geodata = GeoDataManager::new(geo_dir.path(), Vec::new());
    assert!(geodata.status().builtin_fallback_active);

    let test_urls = GeoUpdateUrls {
        label: "local-geodata-mirror".to_string(),
        geosite_cn_url: format!("http://{geo_srv_addr}/direct.txt"),
        geosite_non_cn_url: format!("http://{geo_srv_addr}/proxy.txt"),
        geoip_cn_url: format!("http://{geo_srv_addr}/cncidr.txt"),
        mmdb_url: None,
    };

    let st_ok = geodata
        .update_from_urls(&test_urls)
        .await
        .expect("GeoData HTTP download must succeed");
    assert!(st_ok.using_persisted_data);
    assert!(!st_ok.builtin_fallback_active);
    assert!(!st_ok.is_expired);
    assert_eq!(st_ok.source_label, "local-geodata-mirror");

    // Verify dynamic live rule evaluation immediately picks up newly downloaded CN & Non-CN entries!
    let mut cfg_eval = ClashConfig::from_yaml_str(&ClashConfig::default_starter_yaml()).unwrap();
    cfg_eval.mixed_port = 0;
    cfg_eval.dns.listen = "127.0.0.1:0".into();
    let dead_secret_uuid = Uuid::parse_str("12345678-1234-5678-9abc-def012345678").unwrap();
    let mgr_eval_dir = TempTestDir::new("geodata-eval");
    let mgr_eval = ProfileManager::open_or_init(mgr_eval_dir.path()).unwrap();
    // Copy persisted geodata into `mgr_eval_dir` so `ProxyEngine` loads persisted GeoData on boot!
    fs::create_dir_all(mgr_eval_dir.path().join("geodata")).unwrap();
    for entry in fs::read_dir(geo_dir.path().join("geodata")).unwrap() {
        let entry = entry.unwrap();
        fs::copy(
            entry.path(),
            mgr_eval_dir.path().join("geodata").join(entry.file_name()),
        )
        .unwrap();
    }
    mgr_eval
        .import_nodes_to_active(
            &format!("vless://{dead_secret_uuid}@127.0.0.1:1?security=none#Dead-VLESS"),
            true,
            true,
        )
        .unwrap();
    let (mut dead_cfg, _) = mgr_eval.load_active_config().unwrap();
    dead_cfg.mixed_port = 0;
    dead_cfg.dns.listen = "127.0.0.1:0".into();

    let engine_eval =
        ProxyEngine::start_with_state_dir(dead_cfg, mgr_eval_dir.path().to_path_buf())
            .await
            .unwrap();
    engine_eval.attach_profile_manager(Arc::clone(&mgr_eval));
    let _ = engine_eval.select_group_and_persist("PROXY", "Dead-VLESS");

    let r = engine_eval.router();
    let d_new_cn = r
        .route_async(
            None,
            &TargetAddr::new_domain("app.newly-launched-cn-bank.org", 443).unwrap(),
        )
        .await;
    assert_eq!(d_new_cn.outbound.name(), "DIRECT");

    let d_new_intl = r
        .route_async(
            None,
            &TargetAddr::new_domain("api.newly-launched-ai-lab.org", 443).unwrap(),
        )
        .await;
    assert_eq!(d_new_intl.outbound.name(), "Dead-VLESS");

    let d_new_cn_ip4 = r
        .route_async(
            None,
            &TargetAddr::new_ip("203.0.113.42".parse().unwrap(), 443),
        )
        .await;
    assert_eq!(d_new_cn_ip4.outbound.name(), "DIRECT");

    let d_new_cn_ip6 = r
        .route_async(
            None,
            &TargetAddr::new_ip("2001:db8:8888::1".parse().unwrap(), 443),
        )
        .await;
    assert_eq!(d_new_cn_ip6.outbound.name(), "DIRECT");

    // Simulate GeoData mirror failure (HTTP 503): must return error AND preserve existing rules!
    fail_mode.store(true, Ordering::Relaxed);
    let err_upd = geodata.update_from_urls(&test_urls).await;
    assert!(
        err_upd.is_err(),
        "HTTP 503 GeoData update must return error"
    );
    let st_after_fail = geodata.status();
    assert!(
        st_after_fail.using_persisted_data,
        "failed GeoData update MUST preserve previously persisted dataset!"
    );
    assert!(st_after_fail.last_error.is_some());
    assert_eq!(
        r.route_async(
            None,
            &TargetAddr::new_domain("app.newly-launched-cn-bank.org", 443).unwrap(),
        )
        .await
        .outbound
        .name(),
        "DIRECT"
    );

    // Simulate restart + TTL expiration: update with 1s TTL, reopen offline, and verify `is_expired = true`
    fail_mode.store(false, Ordering::Relaxed);
    let geo_ttl_dir = TempTestDir::new("geodata-ttl");
    let geodata_valid_ttl = GeoDataManager::with_ttl(geo_ttl_dir.path(), 30_000, Vec::new());
    geodata_valid_ttl
        .update_from_urls(&test_urls)
        .await
        .unwrap();
    let geodata_restarted = GeoDataManager::with_ttl(geo_ttl_dir.path(), 30_000, Vec::new());
    assert!(geodata_restarted.status().using_persisted_data);
    assert!(!geodata_restarted.status().is_expired);

    let geodata_short_ttl = GeoDataManager::with_ttl(geo_ttl_dir.path(), 1_000, Vec::new());
    geodata_short_ttl
        .update_from_urls(&test_urls)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    let geodata_expired = GeoDataManager::with_ttl(geo_ttl_dir.path(), 1_000, Vec::new());
    assert!(geodata_expired.status().using_persisted_data);
    assert!(geodata_expired.status().is_expired);

    // =========================================================================
    // PART E: Failed Outbound Connection Records `status = "failed"` & Redacted Reason
    // =========================================================================
    let mut mixed_conn = TcpStream::connect(engine_eval.mixed_addr()).await.unwrap();
    mixed_conn
        .write_all(b"CONNECT www.google.com:443 HTTP/1.1\r\nHost: www.google.com:443\r\n\r\n")
        .await
        .unwrap();
    let mut fail_resp = [0u8; 512];
    let _ = mixed_conn.read(&mut fail_resp).await;

    let mut failed_entry_opt = None;
    for _ in 0..100 {
        let diags = engine_eval.hub().diagnostics_snapshot(50);
        if let Some(found) = diags
            .into_iter()
            .find(|d| d.metadata.host == "www.google.com" && d.metadata.destination_port == 443)
        {
            failed_entry_opt = Some(found);
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let failed_entry =
        failed_entry_opt.expect("failed proxy connection must appear in diagnostics");
    assert_eq!(failed_entry.status, "failed");
    assert_eq!(failed_entry.exit_type, "PROXY");
    assert_eq!(failed_entry.effective_outbound, "Dead-VLESS");
    let err_msg = failed_entry
        .error
        .as_deref()
        .expect("failed diagnostic must carry failure reason");
    assert!(!err_msg.is_empty());
    assert!(
        !err_msg.contains(&dead_secret_uuid.to_string()),
        "diagnostic error must never leak node UUID/secrets: {err_msg}"
    );

    engine_eval.shutdown();
    let _ = geo_stop_tx.send(true);
    install_live_geodata(Arc::new(GeoDataset::builtin_only()));
}

#[tokio::test]
async fn smart_cn_routes_google_via_proxy_even_when_geosite_cn_lists_gstatic_or_gvt2_and_migrates_v045_profile()
 {
    let _serial = SPLIT_TUNNEL_E2E_LOCK.lock().await;
    clear_global_socket_protector();
    install_live_geodata(Arc::new(GeoDataset::builtin_only()));

    let dir = TempTestDir::new("v045-google-smartcn");
    let profiles_dir = dir.path().join("profiles");
    fs::create_dir_all(&profiles_dir).unwrap();

    let node_uuid = Uuid::new_v4();
    let v045_yaml = format!(
        r#"mixed-port: 0
mode: rule
dns:
  enable: true
  enhanced-mode: fake-ip
  listen: 127.0.0.1:0
  nameserver:
    - 223.5.5.5:53
proxies:
  - name: Node-HK
    type: vless
    server: 127.0.0.1
    port: 1
    uuid: "{node_uuid}"
    tls: false
    udp: true
proxy-groups:
  - name: PROXY
    type: select
    proxies:
      - Node-HK
      - DIRECT
rules:
  - DOMAIN-SUFFIX,local,DIRECT
  - DOMAIN-SUFFIX,lan,DIRECT
  - DOMAIN-SUFFIX,home.arpa,DIRECT
  - GEOIP,PRIVATE,DIRECT,no-resolve
  - GEOSITE,geolocation-!cn,PROXY
  - GEOSITE,cn,DIRECT
  - GEOIP,CN,DIRECT,no-resolve
  - MATCH,PROXY
"#
    );
    fs::write(profiles_dir.join("starter-default.yaml"), &v045_yaml).unwrap();
    fs::write(
        profiles_dir.join("profiles_index.json"),
        serde_json::json!({
            "active_profile_id": "starter-default",
            "onboarding_completed": true,
            "selection_defaults_v2": true,
            "profiles": [{
                "id": "starter-default",
                "name": "Starter Profile (Smart CN)",
                "kind": "share-uris",
                "last_updated_ms": 1700000000000u64,
                "proxy_count": 1,
                "group_count": 1,
                "rule_count": 8,
                "selected_groups": {"PROXY": "Node-HK"},
                "rule_preset": "smart-cn"
            }]
        })
        .to_string(),
    )
    .unwrap();

    // 1. Verify v0.4.5 8-rule `smart-cn` profile auto-upgrades to 9-rule template on `open_or_init`
    let mgr = ProfileManager::open_or_init(dir.path()).unwrap();
    let snap = mgr.routing_snapshot().unwrap();
    assert_eq!(snap.rule_preset, RulePreset::SmartCn);
    assert_eq!(snap.rule_count, 9);
    let (mut cfg, _) = mgr.load_active_config().unwrap();
    assert_eq!(cfg.rules, ClashConfig::smart_cn_rules_for_group("PROXY"));

    // 2. Simulate Loyalsoldier `direct.txt` (`geosite_cn`) containing `gstatic.com`, `gvt2.com`,
    //    `googleapis.com`, and `doubleclick.net` in `LIVE_GEODATA`
    let base = GeoDataset::builtin_only();
    let direct_override = proxy_core::router::geosite_data::GeoSiteMatcher::from_rule_text(
        "payload:\n  - '+.gstatic.com'\n  - '+.gvt2.com'\n  - '+.googleapis.com'\n  - '+.doubleclick.net'\n  - '+.baidu.com'\n  - '+.qq.com'\n",
    );
    let poisoned_geodata = Arc::new(GeoDataset {
        geosite_cn: base.geosite_cn.merged_with(&direct_override),
        geosite_non_cn: base.geosite_non_cn,
        geoip_cn: base.geoip_cn,
        mmdb: None,
        using_persisted_data: true,
    });

    cfg.mixed_port = 0;
    cfg.external_controller = "127.0.0.1:0".into();
    cfg.dns.listen = "127.0.0.1:0".into();
    let engine = ProxyEngine::start_with_state_dir(cfg, dir.path().to_path_buf())
        .await
        .unwrap();
    engine.attach_profile_manager(Arc::clone(&mgr));
    let _ = engine.select_group_and_persist("PROXY", "Node-HK");
    // Install AFTER `start_with_state_dir` (which initializes `GeoDataManager` from `state_dir`)
    install_live_geodata(poisoned_geodata);

    let router = engine.router();
    for google_host in [
        "beacons.gcp.gvt2.com",
        "www.gstatic.com",
        "clientservices.googleapis.com",
        "googleads.g.doubleclick.net",
    ] {
        let decision = router
            .route_async(None, &TargetAddr::new_domain(google_host, 443).unwrap())
            .await;
        assert_eq!(
            decision.outbound.name(),
            "Node-HK",
            "Google ecosystem domain '{google_host}' MUST route via PROXY even when geosite_cn lists it"
        );
    }

    for cn_host in ["www.baidu.com", "www.qq.com"] {
        let decision = router
            .route_async(None, &TargetAddr::new_domain(cn_host, 443).unwrap())
            .await;
        assert_eq!(
            decision.outbound.name(),
            "DIRECT",
            "Domestic CN domain '{cn_host}' MUST continue routing DIRECT"
        );
    }

    engine.shutdown();
    install_live_geodata(Arc::new(GeoDataset::builtin_only()));
}

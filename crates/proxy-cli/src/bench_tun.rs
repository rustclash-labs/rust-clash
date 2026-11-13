use std::{
    collections::VecDeque,
    net::Ipv4Addr,
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use proxy_core::{
    config::{
        ClashConfig, DnsConfig, ProxyGroupConfig, ProxyGroupType, ProxyNodeConfig, RunMode,
        TunConfig,
    },
    dns::wire::{QTYPE_A, build_dns_query},
    engine::ProxyEngine,
    inbound::tun::{VirtualTunHandle, build_ipv4_udp_packet},
};
use smoltcp::{
    iface::{Config as IfaceConfig, Interface, SocketHandle, SocketSet},
    phy::{ChecksumCapabilities, Device, DeviceCapabilities, Medium, RxToken, TxToken},
    socket::tcp,
    time::Instant as SmolInstant,
    wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpProtocol, Ipv4Packet, UdpPacket},
};

pub struct BenchTunArgs {
    pub ss_port: u16,
    pub ss_password: String,
    pub tcp_origin_port: u16,
    pub udp_origin_port: u16,
    pub dns_origin_port: u16,
    pub mtu: usize,
    pub single_stream_bytes: u32,
    pub per_multi_stream_bytes: u32,
    pub multi_streams: usize,
}

struct GuestIpDevice {
    mtu: usize,
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

impl Device for GuestIpDevice {
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
        caps.max_transmission_unit = self.mtu;
        caps.checksum = ChecksumCapabilities::default();
        caps
    }
}

fn read_self_rss_mib() -> f64 {
    #[cfg(target_os = "linux")]
    {
        if let Ok(statm) = std::fs::read_to_string("/proc/self/statm")
            && let Some(rss_str) = statm.split_whitespace().nth(1)
            && let Ok(pages) = rss_str.parse::<u64>()
        {
            // SAFETY: `sysconf(_SC_PAGESIZE)` is thread-safe with no preconditions.
            let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) }.max(4096) as u64;
            return (pages * page_size) as f64 / (1024.0 * 1024.0);
        }
    }
    0.0
}

fn percentile(sorted: &[f64], pct: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = (sorted.len() - 1) as f64 * (pct / 100.0);
    let lo = idx.floor() as usize;
    let hi = (lo + 1).min(sorted.len() - 1);
    let frac = idx - lo as f64;
    sorted[lo] * (1.0 - frac) + sorted[hi] * frac
}

fn round3(v: f64) -> f64 {
    (v * 1000.0).round() / 1000.0
}

fn round2(v: f64) -> f64 {
    (v * 100.0).round() / 100.0
}

fn round1(v: f64) -> f64 {
    (v * 10.0).round() / 10.0
}

async fn pump_guest_step(
    guest_iface: &mut Interface,
    guest_dev: &mut GuestIpDevice,
    guest_sockets: &mut SocketSet<'_>,
    vtun: &mut VirtualTunHandle,
    now_smol: impl Fn() -> SmolInstant,
) -> Result<()> {
    let _ = guest_iface.poll(now_smol(), guest_dev, guest_sockets);

    while let Some(pkt) = guest_dev.tx.pop_front() {
        match vtun.ingress_tx.try_send(pkt) {
            Ok(()) => {}
            Err(tokio::sync::mpsc::error::TrySendError::Full(returned)) => {
                guest_dev.tx.push_front(returned);
                while let Ok(epkt) = vtun.egress_rx.try_recv() {
                    guest_dev.rx.push_back(epkt);
                }
                tokio::task::yield_now().await;
                break;
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                anyhow::bail!("userspace TUN ingress channel closed unexpectedly");
            }
        }
    }

    let mut received_any = false;
    while let Ok(epkt) = vtun.egress_rx.try_recv() {
        guest_dev.rx.push_back(epkt);
        received_any = true;
    }

    if !received_any && guest_dev.tx.is_empty() && guest_dev.rx.is_empty() {
        let wait_dur = guest_iface
            .poll_delay(now_smol(), guest_sockets)
            .map(|d| Duration::from_micros(d.total_micros()))
            .unwrap_or(Duration::from_millis(2))
            .min(Duration::from_millis(2));
        if wait_dur.is_zero() {
            tokio::task::yield_now().await;
        } else if let Ok(Some(epkt)) = tokio::time::timeout(wait_dur, vtun.egress_rx.recv()).await {
            guest_dev.rx.push_back(epkt);
        }
        while let Ok(epkt) = vtun.egress_rx.try_recv() {
            guest_dev.rx.push_back(epkt);
        }
    } else {
        tokio::task::yield_now().await;
    }

    let _ = guest_iface.poll(now_smol(), guest_dev, guest_sockets);
    Ok(())
}

struct StreamState {
    handle: SocketHandle,
    req_sent: bool,
    target_bytes: usize,
    received_bytes: usize,
}

#[allow(clippy::too_many_arguments)]
async fn run_tun_bulk_streams(
    guest_iface: &mut Interface,
    guest_dev: &mut GuestIpDevice,
    guest_sockets: &mut SocketSet<'_>,
    vtun: &mut VirtualTunHandle,
    tcp_origin_port: u16,
    base_local_port: u16,
    stream_count: usize,
    bytes_per_stream: u32,
    peak_rss_mib: &mut f64,
    now_smol: impl Fn() -> SmolInstant,
) -> Result<(usize, Duration)> {
    let mut streams = Vec::with_capacity(stream_count);
    for i in 0..stream_count {
        let sock = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0u8; 256 * 1024]),
            tcp::SocketBuffer::new(vec![0u8; 64 * 1024]),
        );
        let h = guest_sockets.add(sock);
        {
            let s = guest_sockets.get_mut::<tcp::Socket>(h);
            s.set_nagle_enabled(false);
            s.connect(
                guest_iface.context(),
                IpEndpoint::new(IpAddress::v4(127, 0, 0, 1), tcp_origin_port),
                base_local_port + i as u16,
            )
            .context("guest smoltcp connect failed")?;
        }
        streams.push(StreamState {
            handle: h,
            req_sent: false,
            target_bytes: bytes_per_stream as usize,
            received_bytes: 0,
        });
    }

    let mut req_cmd = [0u8; 5];
    req_cmd[0] = b'D';
    req_cmd[1..5].copy_from_slice(&bytes_per_stream.to_be_bytes());

    let t0 = Instant::now();
    let deadline = t0 + Duration::from_secs(30);
    let mut iter_count = 0usize;

    loop {
        if Instant::now() > deadline {
            anyhow::bail!("TUN bulk TCP stream benchmark timed out");
        }
        pump_guest_step(guest_iface, guest_dev, guest_sockets, vtun, &now_smol).await?;

        iter_count += 1;
        if iter_count.is_multiple_of(32) {
            *peak_rss_mib = peak_rss_mib.max(read_self_rss_mib());
        }

        let mut all_done = true;
        for st in &mut streams {
            let s = guest_sockets.get_mut::<tcp::Socket>(st.handle);
            if !st.req_sent && s.can_send() {
                let n = s.send_slice(&req_cmd).unwrap_or(0);
                if n == req_cmd.len() {
                    st.req_sent = true;
                }
            }
            while s.can_recv() && st.received_bytes < st.target_bytes {
                let _ = s.recv(|data| {
                    let take = data.len().min(st.target_bytes - st.received_bytes);
                    st.received_bytes += take;
                    (take, ())
                });
            }
            if st.received_bytes < st.target_bytes {
                all_done = false;
            } else if s.is_open() {
                s.close();
            }
        }

        if all_done {
            break;
        }
    }

    let elapsed = t0.elapsed();
    let total_received: usize = streams.iter().map(|s| s.received_bytes).sum();
    for st in streams {
        let s = guest_sockets.get_mut::<tcp::Socket>(st.handle);
        s.abort();
        guest_sockets.remove(st.handle);
    }
    let _ = pump_guest_step(guest_iface, guest_dev, guest_sockets, vtun, &now_smol).await;
    while vtun.egress_rx.try_recv().is_ok() {}
    guest_dev.rx.clear();
    guest_dev.tx.clear();

    Ok((total_received, elapsed))
}

pub async fn run_tun_benchmark(args: BenchTunArgs) -> Result<()> {
    let cfg = ClashConfig {
        mixed_port: 0,
        allow_lan: false,
        lan_allowed_ips: Vec::new(),
        authentication: Vec::new(),
        bind_address: "127.0.0.1".into(),
        mode: RunMode::Rule,
        log_level: "error".into(),
        external_controller: "127.0.0.1:0".into(),
        secret: None,
        geodata_mode: false,
        mmdb_path: None,
        hosts: std::collections::HashMap::new(),
        dns: DnsConfig {
            enable: true,
            listen: "127.0.0.1:0".into(),
            ipv6: false,
            enhanced_mode: "redir-host".into(),
            fake_ip_range: "198.18.0.1/15".into(),
            fake_ip_filter: Vec::new(),
            default_nameserver: vec![format!("127.0.0.1:{}", args.dns_origin_port)],
            direct_nameserver: vec![format!("127.0.0.1:{}", args.dns_origin_port)],
            nameserver: vec![format!("127.0.0.1:{}", args.dns_origin_port)],
            fallback: Vec::new(),
            ..Default::default()
        },
        tun: TunConfig {
            enable: true,
            stack: "smoltcp".into(),
            device: "ClashBench0".into(),
            auto_route: false,
            auto_detect_interface: false,
            dns_hijack: true,
            strict_route: false,
            ipv6: false,
            inet6_address: None,
            wintun_path: None,
            mtu: args.mtu,
        },
        proxies: vec![ProxyNodeConfig::Ss {
            name: "Bench-SS2022".into(),
            server: "127.0.0.1".into(),
            port: args.ss_port,
            cipher: "2022-blake3-aes-256-gcm".into(),
            password: args.ss_password,
            udp: true,
        }],
        proxy_groups: vec![ProxyGroupConfig {
            name: "PROXY".into(),
            group_type: ProxyGroupType::Select,
            proxies: vec!["Bench-SS2022".into()],
            url: String::new(),
            interval: 300,
            tolerance: 50,
            strategy: None,
        }],
        rule_providers: Default::default(),
        rules: vec!["MATCH,Bench-SS2022".into()],
    };

    let tmp_state = std::env::temp_dir().join(format!(
        "rust-clash-bench-tun-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&tmp_state)?;

    let engine = ProxyEngine::start_with_state_dir(cfg, tmp_state.clone()).await?;
    let mut vtun = engine
        .take_virtual_tun_handle()
        .context("VirtualTunHandle unavailable on benchmark engine")?;

    let idle_rss_mib = read_self_rss_mib();
    let mut peak_rss_mib = idle_rss_mib;

    let mut guest_dev = GuestIpDevice {
        mtu: args.mtu,
        rx: VecDeque::with_capacity(256),
        tx: VecDeque::with_capacity(256),
    };
    let mut iface_cfg = IfaceConfig::new(HardwareAddress::Ip);
    iface_cfg.random_seed = 0x5EED_CAFE_2026_u64;
    let boot = Instant::now();
    let now_smol = || SmolInstant::from_micros(boot.elapsed().as_micros() as i64);

    let client_ip = Ipv4Addr::new(10, 250, 0, 2);
    let mut guest_iface = Interface::new(iface_cfg, &mut guest_dev, now_smol());
    guest_iface.update_ip_addrs(|addrs| {
        let _ = addrs.push(IpCidr::new(IpAddress::Ipv4(client_ip), 24));
    });
    let _ = guest_iface
        .routes_mut()
        .add_default_ipv4_route(Ipv4Addr::new(10, 250, 0, 1));
    let mut guest_sockets = SocketSet::new(vec![]);

    // 1. Warmup 1 connection (64 KiB)
    let _ = run_tun_bulk_streams(
        &mut guest_iface,
        &mut guest_dev,
        &mut guest_sockets,
        &mut vtun,
        args.tcp_origin_port,
        40_000,
        1,
        65_536,
        &mut peak_rss_mib,
        now_smol,
    )
    .await?;

    // 2. Single-stream L3 TUN TCP encrypted throughput
    let (got_1, dt_1) = run_tun_bulk_streams(
        &mut guest_iface,
        &mut guest_dev,
        &mut guest_sockets,
        &mut vtun,
        args.tcp_origin_port,
        41_000,
        1,
        args.single_stream_bytes,
        &mut peak_rss_mib,
        now_smol,
    )
    .await?;
    let tcp_1stream_mbps = (got_1 as f64 * 8.0) / (dt_1.as_secs_f64() * 1_000_000.0);

    // 3. Multi-stream concurrent L3 TUN TCP encrypted throughput
    let (got_m, dt_m) = run_tun_bulk_streams(
        &mut guest_iface,
        &mut guest_dev,
        &mut guest_sockets,
        &mut vtun,
        args.tcp_origin_port,
        42_000,
        args.multi_streams,
        args.per_multi_stream_bytes,
        &mut peak_rss_mib,
        now_smol,
    )
    .await?;
    let tcp_multistream_mbps = (got_m as f64 * 8.0) / (dt_m.as_secs_f64() * 1_000_000.0);

    // 4. Sequential L3 TUN TCP 3-way SYN/SYN-ACK/ACK handshake + 64B encrypted echo RTT (100 iterations)
    let mut setup_ms = Vec::with_capacity(100);
    let mut echo_ms = Vec::with_capacity(100);
    let mut echo_req = [b'E'; 65];
    echo_req[1..].fill(b'T');

    for idx in 0..100u16 {
        let sock = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0u8; 16 * 1024]),
            tcp::SocketBuffer::new(vec![0u8; 16 * 1024]),
        );
        let h = guest_sockets.add(sock);
        let c_t0 = Instant::now();
        {
            let s = guest_sockets.get_mut::<tcp::Socket>(h);
            s.set_nagle_enabled(false);
            s.connect(
                guest_iface.context(),
                IpEndpoint::new(IpAddress::v4(127, 0, 0, 1), args.tcp_origin_port),
                45_000 + idx,
            )?;
        }

        let deadline = c_t0 + Duration::from_secs(5);
        while Instant::now() < deadline {
            pump_guest_step(
                &mut guest_iface,
                &mut guest_dev,
                &mut guest_sockets,
                &mut vtun,
                now_smol,
            )
            .await?;
            let s = guest_sockets.get_mut::<tcp::Socket>(h);
            if s.can_send() {
                break;
            }
        }
        setup_ms.push(c_t0.elapsed().as_secs_f64() * 1000.0);

        let e_t0 = Instant::now();
        {
            let s = guest_sockets.get_mut::<tcp::Socket>(h);
            let sent = s.send_slice(&echo_req).unwrap_or(0);
            anyhow::ensure!(sent == echo_req.len(), "short TUN echo write");
        }
        let mut recv_buf = Vec::with_capacity(64);
        while Instant::now() < deadline && recv_buf.len() < 64 {
            pump_guest_step(
                &mut guest_iface,
                &mut guest_dev,
                &mut guest_sockets,
                &mut vtun,
                now_smol,
            )
            .await?;
            let s = guest_sockets.get_mut::<tcp::Socket>(h);
            if s.can_recv() {
                let _ = s.recv(|d| {
                    let take = d.len().min(64 - recv_buf.len());
                    recv_buf.extend_from_slice(&d[..take]);
                    (take, ())
                });
            }
        }
        anyhow::ensure!(recv_buf.len() == 64 && recv_buf.iter().all(|&b| b == b'T'));
        echo_ms.push(e_t0.elapsed().as_secs_f64() * 1000.0);

        let s = guest_sockets.get_mut::<tcp::Socket>(h);
        s.abort();
        guest_sockets.remove(h);
        let _ = pump_guest_step(
            &mut guest_iface,
            &mut guest_dev,
            &mut guest_sockets,
            &mut vtun,
            now_smol,
        )
        .await;
    }
    while vtun.egress_rx.try_recv().is_ok() {}
    setup_ms.sort_by(|a, b| a.partial_cmp(b).unwrap());
    echo_ms.sort_by(|a, b| a.partial_cmp(b).unwrap());

    // 5. L3 IPv4+UDP Stateful NAT Relay -> SS-2022 UDP -> Origin (400 datagrams)
    let udp_total = 400u32;
    let mut udp_received = 0u32;
    let mut udp_rtts_ms = Vec::with_capacity(udp_total as usize);
    let udp_t0 = Instant::now();
    for seq in 0..udp_total {
        let mut payload = Vec::with_capacity(64);
        payload.extend_from_slice(&seq.to_be_bytes());
        payload.resize(64, b'U');
        let pkt = build_ipv4_udp_packet(
            client_ip,
            52_000,
            Ipv4Addr::new(127, 0, 0, 1),
            args.udp_origin_port,
            &payload,
        )
        .context("build L3 UDP packet")?;
        let p_t0 = Instant::now();
        vtun.ingress_tx.send(pkt).await?;

        let wait_deadline = Instant::now() + Duration::from_millis(250);
        while Instant::now() < wait_deadline {
            let rem = wait_deadline.saturating_duration_since(Instant::now());
            let Ok(Some(epkt)) = tokio::time::timeout(rem, vtun.egress_rx.recv()).await else {
                break;
            };
            if let Ok(ip4) = Ipv4Packet::new_checked(&epkt)
                && ip4.next_header() == IpProtocol::Udp
                && let Ok(udp) = UdpPacket::new_checked(ip4.payload())
                && udp.dst_port() == 52_000
                && udp.payload() == payload.as_slice()
            {
                udp_received += 1;
                udp_rtts_ms.push(p_t0.elapsed().as_secs_f64() * 1000.0);
                break;
            }
        }
    }
    let udp_elapsed = udp_t0.elapsed().as_secs_f64().max(1e-6);
    let udp_loss_pct = ((udp_total - udp_received) as f64 / udp_total as f64) * 100.0;
    let udp_pps = udp_received as f64 / udp_elapsed;
    udp_rtts_ms.sort_by(|a, b| a.partial_cmp(b).unwrap());

    // 6. L3 IPv4 `:53` In-Band DNS Hijack Latency (100 uncached + 200 cached = 300 queries)
    let mut dns_all_ms = Vec::with_capacity(300);
    let mut dns_cached_ms = Vec::with_capacity(200);
    for i in 0..300u16 {
        let domain = if i < 100 {
            format!("tun-dns-{i}.example.com")
        } else {
            "tun-dns-0.example.com".to_string()
        };
        let q = build_dns_query(0x7000 + i, &domain, QTYPE_A);
        let pkt = build_ipv4_udp_packet(client_ip, 53_100, Ipv4Addr::new(1, 1, 1, 1), 53, &q)
            .context("build L3 DNS packet")?;
        let d_t0 = Instant::now();
        vtun.ingress_tx.send(pkt).await?;
        if let Ok(Some(epkt)) =
            tokio::time::timeout(Duration::from_secs(1), vtun.egress_rx.recv()).await
            && let Ok(ip4) = Ipv4Packet::new_checked(&epkt)
            && ip4.next_header() == IpProtocol::Udp
            && let Ok(udp) = UdpPacket::new_checked(ip4.payload())
            && udp.src_port() == 53
            && udp.payload().len() >= 12
        {
            let dt_ms = d_t0.elapsed().as_secs_f64() * 1000.0;
            dns_all_ms.push(dt_ms);
            if i >= 100 {
                dns_cached_ms.push(dt_ms);
            }
        }
    }
    dns_all_ms.sort_by(|a, b| a.partial_cmp(b).unwrap());
    dns_cached_ms.sort_by(|a, b| a.partial_cmp(b).unwrap());
    peak_rss_mib = peak_rss_mib.max(read_self_rss_mib());

    engine.shutdown();
    let _ = std::fs::remove_dir_all(&tmp_state);

    let out = serde_json::json!({
        "stack": format!("smoltcp-l3-tun (MTU {}) -> SS-2022", args.mtu),
        "mtu": args.mtu,
        "multi_streams": args.multi_streams,
        "idle_rss_mib": round2(idle_rss_mib),
        "peak_rss_mib": round2(peak_rss_mib),
        "tcp_1stream_mbps": round1(tcp_1stream_mbps),
        "tcp_multistream_mbps": round1(tcp_multistream_mbps),
        "conn_setup_p50_ms": round3(percentile(&setup_ms, 50.0)),
        "conn_setup_p95_ms": round3(percentile(&setup_ms, 95.0)),
        "proxy_rtt_p50_ms": round3(percentile(&echo_ms, 50.0)),
        "proxy_rtt_p95_ms": round3(percentile(&echo_ms, 95.0)),
        "udp_loss_pct": round2(udp_loss_pct),
        "udp_pps": udp_pps.round(),
        "udp_rtt_p50_ms": round3(percentile(&udp_rtts_ms, 50.0)),
        "udp_rtt_p95_ms": round3(percentile(&udp_rtts_ms, 95.0)),
        "dns_hijack_p50_ms": round3(percentile(&dns_all_ms, 50.0)),
        "dns_hijack_p95_ms": round3(percentile(&dns_all_ms, 95.0)),
        "dns_hijack_cached_p50_ms": round3(percentile(&dns_cached_ms, 50.0)),
    });
    println!("{}", serde_json::to_string(&out)?);
    Ok(())
}

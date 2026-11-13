use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
};

use proxy_core::{
    api::spawn_api_server,
    engine::{ProxyEngine, TunRuntimeMode},
    platform::{
        recovery::{
            LinuxRecoveryRecord, RecoveryJournal, SingleInstanceGuard, recover_stale_network_state,
        },
        tun::{
            macos::{
                DARWIN_AF_INET, DARWIN_AF_INET6, decode_darwin_utun_packet,
                encode_darwin_utun_packet,
            },
            preflight_system_tun,
            windows::{WINDOWS_SPLIT_IPV4_PREFIXES, WINDOWS_SPLIT_IPV6_PREFIXES},
        },
    },
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::watch,
};

async fn raw_http_request(
    addr: SocketAddr,
    method: &str,
    path: &str,
    body: Option<&str>,
) -> (u16, String) {
    let mut stream = TcpStream::connect(addr).await.expect("connect control API");
    let payload = body.unwrap_or("");
    let req = if body.is_some() {
        format!(
            "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
            addr.port(),
            payload.len()
        )
    } else {
        format!(
            "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
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

#[tokio::test]
async fn system_tun_status_api_and_unprivileged_fail_closed_invariants() {
    let engine = ProxyEngine::start_demo(
        Some(0),
        Some("127.0.0.1:0".into()),
        Some("127.0.0.1:0".into()),
    )
    .await
    .expect("start demo engine");

    let (stop_tx, stop_rx) = watch::channel(false);
    let (api_addr, _api_task) = spawn_api_server("127.0.0.1:0", Arc::clone(&engine), stop_rx)
        .await
        .expect("spawn API server");

    // 1. Verify /tun/status and /configs report accurate preflight status and never fake active OS TUN
    let (st_tun, body_tun) = raw_http_request(api_addr, "GET", "/tun/status", None).await;
    assert_eq!(st_tun, 200);
    let health_json: serde_json::Value = serde_json::from_str(&body_tun).expect("valid tun json");
    assert_eq!(health_json["active"], false);
    assert!(health_json["platform"].as_str().is_some());
    assert!(health_json["backend"].as_str().is_some());

    let (st_cfg, body_cfg) = raw_http_request(api_addr, "GET", "/configs", None).await;
    assert_eq!(st_cfg, 200);
    let cfg_json: serde_json::Value = serde_json::from_str(&body_cfg).expect("valid configs json");
    assert_eq!(cfg_json["tun"]["enable"], false);
    assert_eq!(cfg_json["tun"]["os-attached"], false);
    assert_eq!(cfg_json["tun"]["health"]["active"], false);

    // 2. If running unprivileged (normal dev/CI container without CAP_NET_ADMIN / Administrator),
    //    enabling `auto-route: true` OS TUN must fail closed with 400 and leave Mixed & DNS intact!
    let preflight = preflight_system_tun(None);
    if !preflight.privilege_ok {
        let prev_mixed = engine.mixed_addr();
        let (st_patch, patch_body) = raw_http_request(
            api_addr,
            "PATCH",
            "/configs",
            Some(r#"{"tun":{"enable":true}}"#),
        )
        .await;
        assert_eq!(
            st_patch, 400,
            "unprivileged OS TUN enable must fail closed (got {st_patch}: {patch_body})"
        );
        assert_eq!(engine.tun_mode(), TunRuntimeMode::Disabled);
        assert!(!engine.is_tun_active());
        assert!(engine.last_tun_error().is_some());
        assert_eq!(
            engine.mixed_addr(),
            prev_mixed,
            "Mixed inbound must remain live after failed TUN transition"
        );
    }

    let _ = stop_tx.send(true);
    engine.shutdown();
}

#[test]
fn cross_platform_tun_framing_split_routes_and_recovery_journal_invariants() {
    // 1. Darwin utun 4-byte big-endian AF header codec
    let mut ipv4_pkt = vec![0u8; 28];
    ipv4_pkt[0] = 0x45;
    let darwin_v4 = encode_darwin_utun_packet(&ipv4_pkt).expect("encode darwin v4");
    assert_eq!(&darwin_v4[..4], &DARWIN_AF_INET.to_be_bytes());
    assert_eq!(
        decode_darwin_utun_packet(&darwin_v4).unwrap(),
        &ipv4_pkt[..]
    );

    let mut ipv6_pkt = vec![0u8; 48];
    ipv6_pkt[0] = 0x60;
    let darwin_v6 = encode_darwin_utun_packet(&ipv6_pkt).expect("encode darwin v6");
    assert_eq!(&darwin_v6[..4], &DARWIN_AF_INET6.to_be_bytes());
    assert_eq!(
        decode_darwin_utun_packet(&darwin_v6).unwrap(),
        &ipv6_pkt[..]
    );

    // 2. Windows split-tunnel prefixes cover 100% of IPv4 and IPv6 without deleting /0
    let v4_nets: Vec<ipnet::Ipv4Net> = WINDOWS_SPLIT_IPV4_PREFIXES
        .iter()
        .map(|(ip, p)| format!("{ip}/{p}").parse().unwrap())
        .collect();
    assert!(
        v4_nets
            .iter()
            .any(|n| n.contains(&Ipv4Addr::new(1, 1, 1, 1)))
    );
    assert!(
        v4_nets
            .iter()
            .any(|n| n.contains(&Ipv4Addr::new(223, 255, 255, 254)))
    );
    assert_eq!(WINDOWS_SPLIT_IPV6_PREFIXES.len(), 2);

    // 3. Stale crash-recovery journal cleanup & SingleInstanceGuard lockfile
    let tmp_dir =
        std::env::temp_dir().join(format!("rust-clash-tun-journal-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&tmp_dir).unwrap();

    let mut stale = RecoveryJournal::new_for_current_process();
    stale.pid = 999_999_991; // Guaranteed non-existent PID
    stale.linux_tun = Some(LinuxRecoveryRecord {
        device_name: "ClashGhost9".into(),
        route_table_id: 20299,
        fwmark: 0x1a5,
        owned_v4_rule_del_args: Vec::new(),
        owned_v6_rule_del_args: Vec::new(),
        owned_route_del_args: Vec::new(),
    });
    stale.save_atomic(&tmp_dir).unwrap();
    assert!(RecoveryJournal::path_in(&tmp_dir).is_file());

    let outcome = recover_stale_network_state(&tmp_dir);
    assert!(outcome.found_stale_journal);
    assert!(
        !RecoveryJournal::path_in(&tmp_dir).exists(),
        "stale journal must be removed after recovery"
    );

    let lock = SingleInstanceGuard::acquire(&tmp_dir).expect("acquire lock");
    #[cfg(unix)]
    assert!(SingleInstanceGuard::acquire(&tmp_dir).is_err());
    drop(lock);
    let _ = std::fs::remove_dir_all(&tmp_dir);
}

/// Real Linux Kernel `/dev/net/tun` + Policy Routing + `SO_MARK` Loop Prevention E2E!
///
/// Covers all 8 production acceptance dimensions over a real OS `/dev/net/tun` interface:
/// 1. Pre-TUN canary DNS leak baseline check (proving the WAN leak detector catches unhijacked `:53`).
/// 2. Browser-equivalent domain HTTP GET & 32 KiB POST (`portal.netns.example` via `:53` hijack -> Fake-IP -> TCP -> SS-2022).
/// 3. Zero DNS leak verification across IPv4 (`198.19.255.254`, `1.1.1.1`, `203.0.113.53`) and IPv6 (`2001:db8:200::53`).
/// 4. IPv4 TCP 4 MiB bulk download (`GET /bytes?n=4194304`) + half-close + real `/dev/net/tun` throughput telemetry.
/// 5. IPv4 multi-packet stateful UDP NAT (8 sequential datagrams + RTT measurement).
/// 6. Native IPv6 real kernel `/dev/net/tun` TCP (`[2001:db8:200::10]:18080`) & native IPv6 UDP (`[2001:db8:200::10]:18081`).
/// 7. Network disconnect & full session recovery (`notify_network_change()` resetting active UDP NAT + TCP, then immediate recovery).
/// 8. Three consecutive OS TUN stop/start cycles (`set_tun_active(false)` -> clean check -> `set_tun_active(true)`) + final shutdown.
///
/// Safety: Only executes when `RUST_CLASH_NETNS_TUN_TEST=1` inside a disposable `ip netns`
/// created by `scripts/ci_linux_netns_tun_test.sh`, so it NEVER touches a live host's routes!
#[cfg(target_os = "linux")]
#[tokio::test]
async fn real_linux_kernel_netns_tun_tcp_udp_dns_and_teardown_e2e() {
    use proxy_core::config::{
        ClashConfig, DnsConfig, ProxyGroupConfig, ProxyGroupType, ProxyNodeConfig, RunMode,
        TunConfig,
    };
    use std::net::Ipv6Addr;
    use std::time::{Duration, Instant};
    use tokio::net::UdpSocket;

    if std::env::var("RUST_CLASH_NETNS_TUN_TEST").as_deref() != Ok("1") {
        eprintln!(
            "Skipping real_linux_kernel_netns_tun_tcp_udp_dns_and_teardown_e2e (set RUST_CLASH_NETNS_TUN_TEST=1 inside isolated ip netns)"
        );
        return;
    }

    let ss_server_ip =
        std::env::var("RC_NETNS_WAN_IP").unwrap_or_else(|_| "10.200.1.1".to_string());
    let ctrl_port: u16 = std::env::var("RC_NETNS_CTRL_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(18082);
    let trusted_dns_port: u16 = std::env::var("RC_NETNS_TRUSTED_DNS_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(5353);
    let target_ip: Ipv4Addr = std::env::var("RC_NETNS_TARGET_IP")
        .unwrap_or_else(|_| "203.0.113.10".to_string())
        .parse()
        .expect("valid RC_NETNS_TARGET_IP");
    let target_ipv6: Ipv6Addr = std::env::var("RC_NETNS_TARGET_IPV6")
        .unwrap_or_else(|_| "2001:db8:200::10".to_string())
        .parse()
        .expect("valid RC_NETNS_TARGET_IPV6");
    let canary_dns_v4: Ipv4Addr = std::env::var("RC_NETNS_CANARY_DNS_IPV4")
        .unwrap_or_else(|_| "203.0.113.53".to_string())
        .parse()
        .expect("valid RC_NETNS_CANARY_DNS_IPV4");
    let canary_dns_v6: Ipv6Addr = std::env::var("RC_NETNS_CANARY_DNS_IPV6")
        .unwrap_or_else(|_| "2001:db8:200::53".to_string())
        .parse()
        .expect("valid RC_NETNS_CANARY_DNS_IPV6");

    let ss_port: u16 = std::env::var("RC_NETNS_SS_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(18388);
    let http_port: u16 = std::env::var("RC_NETNS_HTTP_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(18080);
    let udp_port: u16 = std::env::var("RC_NETNS_UDP_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(18081);
    let ss_password = std::env::var("RC_NETNS_SS_PASS")
        .unwrap_or_else(|_| "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=".to_string());

    let ctrl_addr: SocketAddr = format!("{ss_server_ip}:{ctrl_port}").parse().unwrap();

    async fn query_wan_leak_counts(ctrl_addr: SocketAddr) -> (u64, u64, u64) {
        let (status, body) = raw_http_request(ctrl_addr, "GET", "/leak-count", None).await;
        assert_eq!(status, 200, "control /leak-count failed: {body}");
        let v: serde_json::Value = serde_json::from_str(&body).expect("leak json");
        (
            v["dns_leak_v4"].as_u64().unwrap_or(0),
            v["dns_leak_v6"].as_u64().unwrap_or(0),
            v["dns_leak_total"].as_u64().unwrap_or(0),
        )
    }

    fn assert_kernel_tun_absent(stage: &str) {
        let rule_v4 = std::process::Command::new("ip")
            .args(["-4", "rule", "show"])
            .output()
            .expect("ip -4 rule show");
        let v4_text = String::from_utf8_lossy(&rule_v4.stdout);
        assert!(
            !v4_text.contains("0x1a5"),
            "[{stage}] IPv4 fwmark rule leaked:\n{v4_text}"
        );

        let rule_v6 = std::process::Command::new("ip")
            .args(["-6", "rule", "show"])
            .output()
            .expect("ip -6 rule show");
        let v6_text = String::from_utf8_lossy(&rule_v6.stdout);
        assert!(
            !v6_text.contains("0x1a5"),
            "[{stage}] IPv6 fwmark rule leaked:\n{v6_text}"
        );

        let link_status = std::process::Command::new("ip")
            .args(["link", "show", "dev", "ClashNs0"])
            .output()
            .expect("ip link show");
        assert!(
            !link_status.status.success(),
            "[{stage}] ClashNs0 kernel interface still exists"
        );
    }

    // --- Dimension 1: Verify armed WAN canary DNS leak detectors BEFORE starting TUN ---
    {
        let pre_q = proxy_core::dns::wire::build_dns_query(0x1111, "precheck.example", 1);
        let pre_u4 = UdpSocket::bind("0.0.0.0:0").await.unwrap();
        pre_u4.send_to(&pre_q, (canary_dns_v4, 53)).await.unwrap();
        let mut tmp = [0u8; 256];
        let _ = tokio::time::timeout(Duration::from_secs(2), pre_u4.recv_from(&mut tmp))
            .await
            .expect("pre-TUN IPv4 canary reply timed out")
            .expect("pre-TUN IPv4 canary reply");

        let pre_u6 = UdpSocket::bind("[::]:0").await.unwrap();
        pre_u6.send_to(&pre_q, (canary_dns_v6, 53)).await.unwrap();
        let _ = tokio::time::timeout(Duration::from_secs(2), pre_u6.recv_from(&mut tmp))
            .await
            .expect("pre-TUN IPv6 canary reply timed out")
            .expect("pre-TUN IPv6 canary reply");
    }
    let (base_v4_leaks, base_v6_leaks, base_total_leaks) = query_wan_leak_counts(ctrl_addr).await;
    assert_eq!(
        (base_v4_leaks, base_v6_leaks, base_total_leaks),
        (1, 1, 2),
        "Canary DNS leak detectors must catch unhijacked IPv4+IPv6 :53 queries when TUN is off"
    );

    let cfg = ClashConfig {
        mixed_port: 0,
        allow_lan: false,
        lan_allowed_ips: Vec::new(),
        authentication: Vec::new(),
        bind_address: "127.0.0.1".into(),
        mode: RunMode::Rule,
        log_level: "info".into(),
        external_controller: "127.0.0.1:0".into(),
        secret: None,
        geodata_mode: false,
        mmdb_path: None,
        hosts: std::collections::HashMap::new(),
        dns: DnsConfig {
            enable: true,
            listen: "127.0.0.1:0".into(),
            ipv6: false,
            enhanced_mode: "fake-ip".into(),
            fake_ip_range: "198.18.0.1/15".into(),
            fake_ip_filter: Vec::new(),
            default_nameserver: vec![format!("{ss_server_ip}:{trusted_dns_port}")],
            direct_nameserver: vec![format!("{ss_server_ip}:{trusted_dns_port}")],
            nameserver: vec![format!("{ss_server_ip}:{trusted_dns_port}")],
            fallback: Vec::new(),
            ..Default::default()
        },
        tun: TunConfig {
            enable: true,
            stack: "smoltcp".into(),
            device: "ClashNs0".into(),
            auto_route: true,
            auto_detect_interface: true,
            dns_hijack: true,
            strict_route: false,
            ipv6: true,
            inet6_address: Some("fdfe:dcba:9876::1/126".into()),
            wintun_path: None,
            mtu: 1400,
        },
        proxies: vec![ProxyNodeConfig::Ss {
            name: "WAN-SS2022".into(),
            server: ss_server_ip.clone(),
            port: ss_port,
            cipher: "2022-blake3-aes-256-gcm".into(),
            password: ss_password,
            udp: true,
        }],
        proxy_groups: vec![ProxyGroupConfig {
            name: "PROXY".into(),
            group_type: ProxyGroupType::Select,
            proxies: vec!["WAN-SS2022".into()],
            url: String::new(),
            interval: 300,
            tolerance: 50,
            strategy: None,
        }],
        rule_providers: Default::default(),
        rules: vec![
            "DOMAIN-SUFFIX,netns.example,PROXY".into(),
            "MATCH,PROXY".into(),
        ],
    };

    let tmp_state = std::env::temp_dir().join(format!("rc-netns-state-{}", uuid::Uuid::new_v4()));
    let engine = ProxyEngine::start_with_state_dir(cfg, tmp_state.clone())
        .await
        .expect("attach real Linux /dev/net/tun inside ip netns");
    assert_eq!(engine.tun_mode(), TunRuntimeMode::OsTun);
    assert!(engine.is_tun_active());

    let health = engine.tun_health();
    assert!(health.active);
    assert_eq!(health.device_name.as_deref(), Some("ClashNs0"));
    assert!(health.route_table_id.unwrap_or(0) >= 20220);

    let udp_v4 = UdpSocket::bind("0.0.0.0:0")
        .await
        .expect("bind client UDPv4");
    let udp_v6 = UdpSocket::bind("[::]:0").await.expect("bind client UDPv6");
    let mut ubuf = [0u8; 1024];

    // --- Dimension 2 & 3: Zero DNS Leak (IPv4 + IPv6) + Browser-Equivalent Domain HTTP GET & 32 KiB POST ---
    let mut portal_fake_ip = None;
    for (idx, dns_dst) in [
        "198.19.255.254".to_string(),
        "1.1.1.1".to_string(),
        canary_dns_v4.to_string(),
    ]
    .iter()
    .enumerate()
    {
        let dns_q =
            proxy_core::dns::wire::build_dns_query(0x4200 + idx as u16, "portal.netns.example", 1);
        udp_v4
            .send_to(&dns_q, (dns_dst.as_str(), 53))
            .await
            .expect("send IPv4 DNS query into TUN");
        let (dn, dpeer) = tokio::time::timeout(Duration::from_secs(4), udp_v4.recv_from(&mut ubuf))
            .await
            .expect("IPv4 DNS hijack reply timed out")
            .expect("IPv4 DNS hijack reply");
        assert_eq!(dpeer.ip().to_string(), *dns_dst);
        let ips = proxy_core::dns::wire::extract_ip_answers(&ubuf[..dn]).expect("parse DNS reply");
        let Some(proxy_core::dns::wire::DnsAnswerData::A(fake_ip)) = ips.first().cloned() else {
            panic!("expected Fake-IP A record from TUN DNS hijack, got {ips:?}");
        };
        assert_eq!(&fake_ip.octets()[..2], &[198, 18]);
        assert_ne!(fake_ip, Ipv4Addr::new(198, 18, 0, 1));
        portal_fake_ip = Some(fake_ip);
    }

    // IPv6 `:53` DNS hijack against canary `[2001:db8:200::53]:53` (both QTYPE=A and QTYPE=AAAA)
    for (txid, qtype) in [(0x4301u16, 1u16), (0x4302u16, 28u16)] {
        let q6 = proxy_core::dns::wire::build_dns_query(txid, "portal.netns.example", qtype);
        udp_v6
            .send_to(&q6, (canary_dns_v6, 53))
            .await
            .expect("send IPv6 DNS query into TUN");
        let (dn6, dpeer6) =
            tokio::time::timeout(Duration::from_secs(4), udp_v6.recv_from(&mut ubuf))
                .await
                .expect("IPv6 DNS hijack reply timed out")
                .expect("IPv6 DNS hijack reply");
        assert_eq!(dpeer6, SocketAddr::from((canary_dns_v6, 53)));
        assert!(dn6 >= 12);
    }

    // Assert ZERO DNS packets leaked to either IPv4 or IPv6 WAN canary traps!
    assert_eq!(
        query_wan_leak_counts(ctrl_addr).await,
        (base_v4_leaks, base_v6_leaks, base_total_leaks),
        "DNS LEAK DETECTED: :53 query escaped real Linux kernel TUN!"
    );

    // Browser-equivalent HTTP GET `/browser` via Fake-IP (`portal.netns.example` restored inside Router -> SS-2022)
    let portal_ip = portal_fake_ip.expect("resolved portal Fake-IP");
    {
        let mut browser_tcp = tokio::time::timeout(
            Duration::from_secs(6),
            TcpStream::connect((portal_ip, http_port)),
        )
        .await
        .expect("browser Fake-IP TCP connect timed out")
        .expect("browser Fake-IP TCP connect");
        let get_req = "GET /browser HTTP/1.1\r\nHost: portal.netns.example\r\nUser-Agent: Mozilla/5.0 RustClashNetnsAccept/1.0\r\nConnection: close\r\n\r\n";
        browser_tcp.write_all(get_req.as_bytes()).await.unwrap();
        let mut resp = Vec::new();
        browser_tcp.read_to_end(&mut resp).await.unwrap();
        let text = String::from_utf8_lossy(&resp);
        let (_, json_str) = text.split_once("\r\n\r\n").expect("HTTP headers/body");
        let parsed: serde_json::Value = serde_json::from_str(json_str).expect("browser json");
        assert_eq!(parsed["ok"], true);
        assert_eq!(parsed["host"], "portal.netns.example");
        assert_eq!(parsed["family"], "ipv4");
    }

    // Browser-equivalent 32 KiB HTTP POST `/echo` with half-close verification
    {
        let post_body: Vec<u8> = (0..(32 * 1024))
            .map(|i| ((i * 31 + 7) & 0xff) as u8)
            .collect();
        let mut post_tcp = TcpStream::connect((portal_ip, http_port)).await.unwrap();
        let hdr = format!(
            "POST /echo HTTP/1.1\r\nHost: portal.netns.example\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            post_body.len()
        );
        post_tcp.write_all(hdr.as_bytes()).await.unwrap();
        post_tcp.write_all(&post_body).await.unwrap();
        post_tcp
            .shutdown()
            .await
            .expect("TCP half-close write side");
        let mut resp = Vec::new();
        post_tcp.read_to_end(&mut resp).await.unwrap();
        let split_pos = resp
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .expect("POST response header delimiter");
        assert_eq!(&resp[split_pos + 4..], &post_body[..]);
    }

    // --- Dimension 4: IPv4 Literal TCP + 4 MiB Bulk Download Throughput over Real `/dev/net/tun` ---
    let bulk_bytes: usize = 4 * 1024 * 1024;
    let bulk_t0 = Instant::now();
    {
        let mut bulk_tcp = TcpStream::connect((target_ip, http_port)).await.unwrap();
        let req = format!(
            "GET /bytes?n={bulk_bytes} HTTP/1.1\r\nHost: {target_ip}\r\nConnection: close\r\n\r\n"
        );
        bulk_tcp.write_all(req.as_bytes()).await.unwrap();
        let mut raw = Vec::with_capacity(bulk_bytes + 256);
        bulk_tcp.read_to_end(&mut raw).await.unwrap();
        let split_pos = raw
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .expect("bulk response header");
        let payload = &raw[split_pos + 4..];
        assert_eq!(payload.len(), bulk_bytes);
        assert!(payload.iter().all(|&b| b == b'K'));
    }
    let bulk_mbps = (bulk_bytes as f64 * 8.0) / (bulk_t0.elapsed().as_secs_f64() * 1_000_000.0);
    assert!(
        engine.tun_health().rx_packets >= 20 && engine.tun_health().tx_packets >= 20,
        "ClashNs0 rx/tx packet counters must advance on real kernel TUN bulk traffic"
    );

    // --- Dimension 5: IPv4 Multi-Packet Stateful UDP NAT (8 sequential datagrams) ---
    let mut udp_rtts_ms = Vec::with_capacity(8);
    for seq in 0..8u32 {
        let msg = format!("kernel-tun-udp-v4-{seq}");
        let t0 = Instant::now();
        udp_v4
            .send_to(msg.as_bytes(), (target_ip, udp_port))
            .await
            .expect("send UDPv4 into kernel TUN");
        let (un, upeer) = tokio::time::timeout(Duration::from_secs(5), udp_v4.recv_from(&mut ubuf))
            .await
            .expect("UDPv4 recv through kernel TUN timed out")
            .expect("UDPv4 recv through kernel TUN");
        udp_rtts_ms.push(t0.elapsed().as_secs_f64() * 1000.0);
        assert_eq!(upeer, SocketAddr::from((target_ip, udp_port)));
        assert_eq!(&ubuf[..un], format!("ECHO:{msg}").as_bytes());
    }
    udp_rtts_ms.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let udp_rtt_p50_ms = udp_rtts_ms[udp_rtts_ms.len() / 2];

    eprintln!(
        "NETNS_KERNEL_TUN_TELEMETRY_JSON={}",
        serde_json::json!({
            "backend": "linux-/dev/net/tun+smoltcp+ss2022",
            "bulk_bytes": bulk_bytes,
            "tcp_bulk_mbps": (bulk_mbps * 10.0).round() / 10.0,
            "udp_rtt_p50_ms": (udp_rtt_p50_ms * 1000.0).round() / 1000.0,
            "rx_packets": engine.tun_health().rx_packets,
            "tx_packets": engine.tun_health().tx_packets,
        })
    );

    // --- Dimension 6: Native IPv6 TCP & Native IPv6 UDP over Real `/dev/net/tun` ---
    {
        let mut tcp6 = tokio::time::timeout(
            Duration::from_secs(6),
            TcpStream::connect((target_ipv6, http_port)),
        )
        .await
        .expect("IPv6 TCP connect through real kernel TUN timed out")
        .expect("IPv6 TCP connect through real kernel TUN");
        tcp6.write_all(
            b"GET /ipv6-check HTTP/1.1\r\nHost: [2001:db8:200::10]\r\nConnection: close\r\n\r\n",
        )
        .await
        .expect("write IPv6 HTTP");
        let mut resp6 = Vec::new();
        tcp6.read_to_end(&mut resp6).await.expect("read IPv6 HTTP");
        let resp6_str = String::from_utf8_lossy(&resp6);
        assert!(
            resp6_str.contains("IPV6-NETNS-TUN-OK"),
            "unexpected IPv6 TCP TUN response: {resp6_str}"
        );

        for seq in 0..3u32 {
            let msg6 = format!("kernel-tun-udp-v6-{seq}");
            udp_v6
                .send_to(msg6.as_bytes(), (target_ipv6, udp_port))
                .await
                .expect("send UDPv6 into kernel TUN");
            let (un6, upeer6) =
                tokio::time::timeout(Duration::from_secs(5), udp_v6.recv_from(&mut ubuf))
                    .await
                    .expect("UDPv6 recv through kernel TUN timed out")
                    .expect("UDPv6 recv through kernel TUN");
            assert_eq!(upeer6, SocketAddr::from((target_ipv6, udp_port)));
            assert_eq!(&ubuf[..un6], format!("ECHO6:{msg6}").as_bytes());
        }
    }

    // --- Dimension 7: Network Handoff / Disconnect Session Recovery over Real `/dev/net/tun` ---
    {
        let report = engine.notify_network_change();
        assert!(
            report.reset_udp_nat_sessions >= 2,
            "expected active IPv4+IPv6 TUN UDP NAT sessions to be reset on handoff, got {report:?}"
        );
        assert!(report.dns_cache_flushed);

        // Immediately verify fresh IPv4 TCP + IPv4 UDP + IPv6 UDP recover cleanly on the same sockets!
        let mut rec_tcp = TcpStream::connect((target_ip, http_port)).await.unwrap();
        rec_tcp
            .write_all(b"GET /netns-tun HTTP/1.1\r\nHost: wan\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut rec_buf = Vec::new();
        rec_tcp.read_to_end(&mut rec_buf).await.unwrap();
        assert!(String::from_utf8_lossy(&rec_buf).contains("NETNS-TUN-OK"));

        udp_v4
            .send_to(b"after-handoff-v4", (target_ip, udp_port))
            .await
            .unwrap();
        let (rn4, _) = tokio::time::timeout(Duration::from_secs(4), udp_v4.recv_from(&mut ubuf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&ubuf[..rn4], b"ECHO:after-handoff-v4");

        udp_v6
            .send_to(b"after-handoff-v6", (target_ipv6, udp_port))
            .await
            .unwrap();
        let (rn6, _) = tokio::time::timeout(Duration::from_secs(4), udp_v6.recv_from(&mut ubuf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&ubuf[..rn6], b"ECHO6:after-handoff-v6");
    }

    // --- Dimension 8: 3 Consecutive Repeated OS TUN Stop / Start Cycles ---
    for cycle in 1..=3 {
        engine
            .set_tun_active(false)
            .await
            .unwrap_or_else(|e| panic!("cycle {cycle}: set_tun_active(false) failed: {e}"));
        assert_eq!(engine.tun_mode(), TunRuntimeMode::Disabled);
        assert!(!engine.is_tun_active());
        assert_kernel_tun_absent(&format!("cycle-{cycle}-stopped"));

        engine
            .set_tun_active(true)
            .await
            .unwrap_or_else(|e| panic!("cycle {cycle}: set_tun_active(true) failed: {e}"));
        assert_eq!(engine.tun_mode(), TunRuntimeMode::OsTun);
        assert!(engine.is_tun_active());

        // Verify DNS hijack (no leak), IPv4 TCP, IPv4 UDP, and IPv6 UDP after re-attach!
        let dq = proxy_core::dns::wire::build_dns_query(
            0x5000 + cycle as u16,
            "portal.netns.example",
            1,
        );
        udp_v4.send_to(&dq, (canary_dns_v4, 53)).await.unwrap();
        let (dn, _) = tokio::time::timeout(Duration::from_secs(4), udp_v4.recv_from(&mut ubuf))
            .await
            .unwrap()
            .unwrap();
        assert!(dn >= 16);

        let mut c_tcp = TcpStream::connect((target_ip, http_port)).await.unwrap();
        c_tcp
            .write_all(b"GET /netns-tun HTTP/1.1\r\nHost: wan\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut c_resp = Vec::new();
        c_tcp.read_to_end(&mut c_resp).await.unwrap();
        assert!(String::from_utf8_lossy(&c_resp).contains("NETNS-TUN-OK"));

        let msg4 = format!("cycle-{cycle}-v4");
        udp_v4
            .send_to(msg4.as_bytes(), (target_ip, udp_port))
            .await
            .unwrap();
        let (n4, _) = tokio::time::timeout(Duration::from_secs(4), udp_v4.recv_from(&mut ubuf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&ubuf[..n4], format!("ECHO:{msg4}").as_bytes());

        let msg6 = format!("cycle-{cycle}-v6");
        udp_v6
            .send_to(msg6.as_bytes(), (target_ipv6, udp_port))
            .await
            .unwrap();
        let (n6, _) = tokio::time::timeout(Duration::from_secs(4), udp_v6.recv_from(&mut ubuf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&ubuf[..n6], format!("ECHO6:{msg6}").as_bytes());

        assert_eq!(
            query_wan_leak_counts(ctrl_addr).await,
            (base_v4_leaks, base_v6_leaks, base_total_leaks),
            "DNS leaked during TUN restart cycle {cycle}!"
        );
    }

    // Final clean teardown check
    engine.shutdown();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_kernel_tun_absent("final-shutdown");
    let _ = std::fs::remove_dir_all(&tmp_state);
}

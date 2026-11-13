use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use proxy_core::{
    config::{ClashConfig, DnsConfig},
    crypto::tls::generate_self_signed_server_config,
    dns::{
        FakeIpDnsEngine,
        upstream::BootstrapDnsServer,
        wire::{
            DnsAnswerData, DnsQueryPacket, QTYPE_A, build_dns_query, dns_response_rcode,
            extract_ip_answers,
        },
    },
    engine::ProxyEngine,
    outbound::anytls::{AnyTlsServerConfig, padding::PaddingScheme, spawn_anytls_server},
    profile::{ProfileManager, RoutingPresetChoice},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::watch,
};
use tokio_rustls::TlsAcceptor;
use uuid::Uuid;

const H2_CLIENT_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

fn push_h2_frame(out: &mut Vec<u8>, ftype: u8, flags: u8, stream_id: u32, payload: &[u8]) {
    let len = payload.len();
    out.push(((len >> 16) & 0xff) as u8);
    out.push(((len >> 8) & 0xff) as u8);
    out.push((len & 0xff) as u8);
    out.push(ftype);
    out.push(flags);
    out.extend_from_slice(&(stream_id & 0x7fff_ffff).to_be_bytes());
    out.extend_from_slice(payload);
}

async fn spawn_http_origin_server(mut shutdown: watch::Receiver<bool>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = shutdown.changed() => break,
                acc = listener.accept() => {
                    let Ok((mut sock, _)) = acc else { break };
                    tokio::spawn(async move {
                        let mut req = Vec::with_capacity(1024);
                        let mut tmp = [0u8; 1024];
                        loop {
                            let Ok(n) = sock.read(&mut tmp).await else { return };
                            if n == 0 { return; }
                            req.extend_from_slice(&tmp[..n]);
                            if req.windows(4).any(|w| w == b"\r\n\r\n") {
                                break;
                            }
                        }
                        let head = String::from_utf8_lossy(&req);
                        let resp = if head.starts_with("GET /generate_204 ") {
                            "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                                .to_string()
                        } else {
                            let body = "hello-over-self-hosted-doh-anytls";
                            format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                body.len(),
                                body
                            )
                        };
                        let _ = sock.write_all(resp.as_bytes()).await;
                        let _ = sock.shutdown().await;
                    });
                }
            }
        }
    });
    addr
}

/// Spawn a strict RFC 9113 HTTP/2 (`ALPN = h2` ONLY) DNS-over-HTTPS server on `127.0.0.1:0`.
async fn spawn_h2_only_doh_server(
    mut shutdown: watch::Receiver<bool>,
    records: HashMap<String, Ipv4Addr>,
) -> (
    SocketAddr,
    Arc<AtomicUsize>,
    rustls_pki_types::CertificateDer<'static>,
) {
    let (tls_cfg, ca_der) = generate_self_signed_server_config(
        &["127.0.0.1".to_string(), "localhost".to_string()],
        &[b"h2".to_vec()],
    )
    .expect("generate h2-only DoH TLS server config");
    let acceptor = TlsAcceptor::from(tls_cfg);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bound = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_bg = Arc::clone(&hits);

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = shutdown.changed() => break,
                acc = listener.accept() => {
                    let Ok((tcp, _)) = acc else { break };
                    let acceptor = acceptor.clone();
                    let hits_conn = Arc::clone(&hits_bg);
                    let records_conn = records.clone();
                    tokio::spawn(async move {
                        let Ok(mut tls) = acceptor.accept(tcp).await else { return };
                        assert_eq!(
                            tls.get_ref().1.alpn_protocol(),
                            Some(b"h2".as_slice()),
                            "DoH client must negotiate HTTP/2 ALPN when server requires h2"
                        );

                        let mut preface = [0u8; 24];
                        if tls.read_exact(&mut preface).await.is_err() || preface != H2_CLIENT_PREFACE {
                            return;
                        }

                        // Send server SETTINGS + PING frames to exercise client frame state machine
                        let mut greet = Vec::with_capacity(32);
                        push_h2_frame(&mut greet, 0x4, 0x0, 0, &[]);
                        push_h2_frame(&mut greet, 0x6, 0x0, 0, b"rustclsh");
                        if tls.write_all(&greet).await.is_err() || tls.flush().await.is_err() {
                            return;
                        }

                        let mut req_body = Vec::new();
                        loop {
                            let mut hdr = [0u8; 9];
                            if tls.read_exact(&mut hdr).await.is_err() {
                                return;
                            }
                            let flen = ((hdr[0] as usize) << 16) | ((hdr[1] as usize) << 8) | (hdr[2] as usize);
                            let ftype = hdr[3];
                            let flags = hdr[4];
                            let sid = u32::from_be_bytes([hdr[5], hdr[6], hdr[7], hdr[8]]) & 0x7fff_ffff;
                            let mut payload = vec![0u8; flen];
                            if flen > 0 && tls.read_exact(&mut payload).await.is_err() {
                                return;
                            }
                            if ftype == 0x4 && (flags & 0x1) == 0 {
                                let mut ack = Vec::with_capacity(9);
                                push_h2_frame(&mut ack, 0x4, 0x1, 0, &[]);
                                let _ = tls.write_all(&ack).await;
                                let _ = tls.flush().await;
                            } else if ftype == 0x0 && sid == 1 {
                                req_body.extend_from_slice(&payload);
                                if (flags & 0x1) != 0 {
                                    break;
                                }
                            }
                        }

                        if req_body.len() < 12 {
                            return;
                        }
                        // RFC 8484 Section 4.1: client zeros DNS wire ID in HTTP request
                        assert_eq!([req_body[0], req_body[1]], [0, 0]);

                        let Ok(q) = DnsQueryPacket::parse(&req_body) else { return };
                        let req_idx = hits_conn.fetch_add(1, Ordering::Relaxed);
                        let wire_resp = match (records_conn.get(q.question.name.as_str()), q.question.qtype) {
                            (Some(&ip), QTYPE_A) => {
                                q.build_response(&req_body, 0, 120, &[DnsAnswerData::A(ip)])
                            }
                            (Some(_), _) => q.build_response(&req_body, 0, 120, &[]),
                            (None, _) => q.build_response(&req_body, 3, 60, &[]),
                        };

                        // Alternate between HPACK indexed `:status: 200` (`0x88`) and
                        // literal `:status` (`0x08`) + RFC 7541 Huffman `"200"` (`0x82, 0x10, 0x01`)
                        let hpack_headers: &[u8] = if req_idx.is_multiple_of(2) {
                            &[0x08, 0x82, 0x10, 0x01]
                        } else {
                            &[0x88]
                        };

                        let mut out = Vec::with_capacity(32 + wire_resp.len());
                        push_h2_frame(&mut out, 0x1, 0x4, 1, hpack_headers); // HEADERS | END_HEADERS
                        push_h2_frame(&mut out, 0x0, 0x1, 1, &wire_resp); // DATA | END_STREAM
                        let _ = tls.write_all(&out).await;
                        let _ = tls.flush().await;
                    });
                }
            }
        }
    });

    (bound, hits, ca_der)
}

/// Spawn a TCP listener that immediately resets/closes accepted connections to deterministically
/// simulate a dead primary DoH server without ephemeral port reuse races.
async fn spawn_dead_tcp_endpoint(mut shutdown: watch::Receiver<bool>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = shutdown.changed() => break,
                acc = listener.accept() => {
                    let Ok((sock, _)) = acc else { break };
                    drop(sock);
                }
            }
        }
    });
    addr
}

async fn http_get_via_connect_proxy(
    proxy_addr: SocketAddr,
    target_host: &str,
    target_port: u16,
    path: &str,
) -> String {
    let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
    let connect_req = format!(
        "CONNECT {target_host}:{target_port} HTTP/1.1\r\nHost: {target_host}:{target_port}\r\n\r\n"
    );
    stream.write_all(connect_req.as_bytes()).await.unwrap();
    let mut buf = Vec::with_capacity(256);
    let mut tmp = [0u8; 256];
    loop {
        let n = stream.read(&mut tmp).await.unwrap();
        assert!(n > 0, "unexpected EOF waiting for HTTP CONNECT 200");
        buf.extend_from_slice(&tmp[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    let connect_head = String::from_utf8_lossy(&buf);
    assert!(
        connect_head.starts_with("HTTP/1.1 200"),
        "expected CONNECT 200, got: {connect_head}"
    );

    let get_req =
        format!("GET {path} HTTP/1.1\r\nHost: {target_host}\r\nConnection: close\r\n\r\n");
    stream.write_all(get_req.as_bytes()).await.unwrap();
    let mut raw_resp = Vec::new();
    stream.read_to_end(&mut raw_resp).await.unwrap();
    let text = String::from_utf8_lossy(&raw_resp);
    let (_, body) = text
        .split_once("\r\n\r\n")
        .expect("HTTP response body separator");
    body.to_string()
}

#[tokio::test]
async fn self_hosted_h2_doh_nameserver_policy_resolves_anytls_nodes_and_survives_sanitized_import_and_smart_cn()
 {
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // 1. Local HTTP 204 & payload origin server
    let origin_addr = spawn_http_origin_server(shutdown_rx.clone()).await;

    // 2. Real AnyTLS v2 outbound server on `127.0.0.1:0`
    let (anytls_tls_cfg, _anytls_ca) = generate_self_signed_server_config(
        &[
            "sni.private-edge.example.com".to_string(),
            "127.0.0.1".to_string(),
        ],
        &[b"h2".to_vec(), b"http/1.1".to_vec()],
    )
    .unwrap();
    let anytls_password = "synthetic-anytls-pass-01";
    let (anytls_addr, _anytls_task) = spawn_anytls_server(
        AnyTlsServerConfig {
            listen_addr: "127.0.0.1:0".into(),
            password: anytls_password.into(),
            tls_config: anytls_tls_cfg,
            padding_scheme: PaddingScheme::default(),
        },
        shutdown_rx.clone(),
    )
    .await
    .expect("spawn_anytls_server");

    // 3. Dead primary DoH server + live secondary HTTP/2 (`h2`-only) self-hosted DoH server on custom port
    let dead_doh_addr = spawn_dead_tcp_endpoint(shutdown_rx.clone()).await;
    let mut authoritative_records = HashMap::new();
    authoritative_records.insert(
        "hk01.private-edge.example.com".to_string(),
        Ipv4Addr::LOCALHOST,
    );
    authoritative_records.insert(
        "portal.corp-split.example.com".to_string(),
        Ipv4Addr::LOCALHOST,
    );
    let (live_h2_doh_addr, h2_doh_hits, _doh_ca) =
        spawn_h2_only_doh_server(shutdown_rx.clone(), authoritative_records).await;

    // 4. Poisoned public UDP DNS server (`default-nameserver`, `nameserver`, `fallback`)
    // returning blackhole `198.51.100.254` and tracking any leaked private-domain queries!
    let public_udp = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let public_dns_addr = public_udp.local_addr().unwrap();
    let poisoned_private_leaks = Arc::new(AtomicUsize::new(0));
    {
        let sock = Arc::clone(&public_udp);
        let leaks = Arc::clone(&poisoned_private_leaks);
        let mut rx = shutdown_rx.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            loop {
                tokio::select! {
                    _ = rx.changed() => break,
                    recv = sock.recv_from(&mut buf) => {
                        let Ok((n, peer)) = recv else { break };
                        let raw = &buf[..n];
                        if let Ok(q) = DnsQueryPacket::parse(raw) {
                            let qn = q.question.name.as_str();
                            if qn.ends_with("private-edge.example.com")
                                || qn.ends_with("corp-split.example.com")
                            {
                                leaks.fetch_add(1, Ordering::Relaxed);
                            }
                            let resp = if q.question.qtype == QTYPE_A {
                                // `origin.remote-app.example.com` resolves to `127.0.0.1` only at AnyTLS server side,
                                // while poisoned public DNS returns blackhole `198.51.100.254`!
                                q.build_response(
                                    raw,
                                    0,
                                    60,
                                    &[DnsAnswerData::A(Ipv4Addr::new(198, 51, 100, 254))],
                                )
                            } else {
                                q.build_response(raw, 0, 60, &[])
                            };
                            let _ = sock.send_to(&resp, peer).await;
                        }
                    }
                }
            }
        });
    }

    // 5. Realistic mixed Clash Meta YAML subscription:
    //    - `fake-ip-range: 198.18.0.1/16` (non-zero host bits `.1`)
    //    - multi-wildcard `fake-ip-filter` (`+.stun.*.*`, `xbox.*.*.microsoft.com`, `*.*.xboxlive.com`, `time.*.com`)
    //    - `nameserver-policy` with dead primary + live h2 secondary DoH on custom port
    //    - 1 supported `anytls` node + 1 unsupported `vless` Reality node (forcing sanitized `to_yaml_string()` persistence!)
    let dead_doh_url = format!("https://{dead_doh_addr}/dns-query#skip-cert-verify=true");
    let live_doh_url = format!("https://{live_h2_doh_addr}/dns-query#skip-cert-verify=true");
    let url_204 = format!("http://127.0.0.1:{}/generate_204", origin_addr.port());

    let sub_yaml = format!(
        r#"mixed-port: 0
allow-lan: false
mode: rule
log-level: info
external-controller: 127.0.0.1:0
dns:
  enable: true
  ipv6: false
  listen: 127.0.0.1:0
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  fake-ip-filter:
    - '*.lan'
    - '+.stun.*.*'
    - '+.stun.*.*.*'
    - 'xbox.*.*.microsoft.com'
    - '*.*.xboxlive.com'
    - 'time.*.com'
  default-nameserver:
    - {public_dns_addr}
  nameserver:
    - {public_dns_addr}
  fallback:
    - {public_dns_addr}
  nameserver-policy:
    '*.private-edge.example.com':
      - '{dead_doh_url}'
      - '{live_doh_url}'
    '+.corp-split.example.com': '{live_doh_url}'
proxies:
  - name: 'HK-01-SelfHostedDNS'
    type: anytls
    server: hk01.private-edge.example.com
    port: {anytls_port}
    password: '{anytls_password}'
    sni: sni.private-edge.example.com
    alpn:
      - h2
      - http/1.1
    skip-cert-verify: true
    udp: true
  - name: 'Unsupported-Reality-Node'
    type: vless
    server: reality.private-edge.example.com
    port: 443
    uuid: 00000000-0000-4000-8000-000000000001
    tls: true
    flow: xtls-rprx-vision
    servername: www.example.com
    reality-opts:
      public-key: dGVzdC1wdWJsaWMta2V5LXRlc3QtcHVibGljLWtleS0
      short-id: 01020304
proxy-groups:
  - name: '🚀 节点选择'
    type: select
    proxies:
      - '♻️ 自动选择'
      - 'HK-01-SelfHostedDNS'
      - DIRECT
  - name: '♻️ 自动选择'
    type: url-test
    proxies:
      - 'HK-01-SelfHostedDNS'
    url: '{url_204}'
    interval: 300
rules:
  - DOMAIN-SUFFIX,corp-split.example.com,DIRECT
  - MATCH,🚀 节点选择
"#,
        anytls_port = anytls_addr.port(),
    );

    let state_dir = std::env::temp_dir().join(format!("rust-clash-dns-policy-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&state_dir).unwrap();
    let pm = ProfileManager::open_or_init(&state_dir).expect("ProfileManager::open_or_init");
    let import_report = pm
        .import_unified_input(&sub_yaml, Some("SelfHosted-DoH-Sub"), true, true)
        .await
        .expect("sanitized mixed subscription import must succeed");

    assert_eq!(import_report.total_nodes, 1);
    assert_eq!(import_report.skipped_unsupported.len(), 1);

    // Reload persisted YAML from disk to prove `to_yaml_string()` preserved `nameserver-policy`!
    let (mut reloaded_cfg, _) = pm.load_active_config().expect("load_active_config");
    assert_eq!(reloaded_cfg.dns.nameserver_policy.len(), 2);
    assert_eq!(
        reloaded_cfg.dns.parsed_fake_ip_net().unwrap().to_string(),
        "198.18.0.0/16",
        "fake-ip-range 198.18.0.1/16 must canonicalize host bits to 198.18.0.0/16"
    );

    reloaded_cfg.mixed_port = 0;
    reloaded_cfg.dns.listen = "127.0.0.1:0".to_string();
    let engine = ProxyEngine::start_with_state_dir(reloaded_cfg, state_dir.clone())
        .await
        .expect("ProxyEngine::start_with_state_dir");
    engine.attach_profile_manager(Arc::clone(&pm));

    // Verify multi-wildcard `fake-ip-filter` patterns via FakeIpDnsEngine
    {
        let router_snap = engine.router();
        let dns = router_snap.dns();
        assert!(dns.should_bypass_fake_ip("turn.stun.example.com"));
        assert!(dns.should_bypass_fake_ip("a.b.stun.us.example.com"));
        assert!(dns.should_bypass_fake_ip("xbox.prod.west.microsoft.com"));
        assert!(dns.should_bypass_fake_ip("auth.title.xboxlive.com"));
        assert!(dns.should_bypass_fake_ip("time.apple.com"));
        assert!(!dns.should_bypass_fake_ip("127.0.0.1.sslip.io"));
        assert!(
            dns.upstream_bypass_ips()
                .contains(&IpAddr::V4(Ipv4Addr::LOCALHOST)),
            "literal policy DoH server IPs must be included in TUN upstream_bypass_ips"
        );
    }

    // Latency probe (`test_delay`) must resolve `hk01.private-edge.example.com` via h2 DoH (failing over past dead primary!)
    let rtt_ms = engine
        .router()
        .test_delay("HK-01-SelfHostedDNS", &url_204, Duration::from_secs(5))
        .await
        .expect("AnyTLS node latency probe via self-hosted h2 DoH must succeed");
    assert!(rtt_ms < 5_000);
    assert_eq!(
        poisoned_private_leaks.load(Ordering::Relaxed),
        0,
        "private proxy hostname must NEVER leak to generic/default UDP DNS"
    );
    assert!(h2_doh_hits.load(Ordering::Relaxed) >= 1);

    // End-to-end proxied traffic through `HK-01-SelfHostedDNS` (`AnyTLS`)
    let proxied_body = http_get_via_connect_proxy(
        engine.mixed_addr(),
        "127.0.0.1",
        origin_addr.port(),
        "/hello",
    )
    .await;
    assert_eq!(proxied_body, "hello-over-self-hosted-doh-anytls");

    // End-to-end `DIRECT` split-horizon domain (`portal.corp-split.example.com`) resolved via `nameserver-policy`
    let direct_body = http_get_via_connect_proxy(
        engine.mixed_addr(),
        "portal.corp-split.example.com",
        origin_addr.port(),
        "/hello",
    )
    .await;
    assert_eq!(direct_body, "hello-over-self-hosted-doh-anytls");
    assert_eq!(
        poisoned_private_leaks.load(Ordering::Relaxed),
        0,
        "DIRECT domain matching nameserver-policy must not hit poisoned generic DNS"
    );
    assert!(h2_doh_hits.load(Ordering::Relaxed) >= 2);

    // Switch routing preset to `Smart CN` (which populates `direct-nameserver` with public IPs)
    // and verify `nameserver-policy` STILL wins for proxy node resolution after cache flush!
    let (_snap, mut smart_cfg) = pm
        .apply_routing_preset(RoutingPresetChoice::SmartCn)
        .expect("apply_routing_preset(SmartCn)");
    assert!(!smart_cfg.dns.direct_nameserver.is_empty());
    assert_eq!(smart_cfg.dns.nameserver_policy.len(), 2);
    smart_cfg.mixed_port = 0;
    smart_cfg.dns.listen = "127.0.0.1:0".to_string();
    engine
        .activate_profile_config(smart_cfg)
        .await
        .expect("activate_profile_config(SmartCn)");
    engine.notify_network_change();

    let hits_before_smart_probe = h2_doh_hits.load(Ordering::Relaxed);
    let rtt_after_smart = engine
        .router()
        .test_delay("HK-01-SelfHostedDNS", &url_204, Duration::from_secs(5))
        .await
        .expect("AnyTLS probe must still succeed under Smart CN preset");
    assert!(rtt_after_smart < 5_000);
    assert!(
        h2_doh_hits.load(Ordering::Relaxed) > hits_before_smart_probe,
        "flushed proxy IP cache must re-query self-hosted h2 DoH server"
    );
    assert_eq!(poisoned_private_leaks.load(Ordering::Relaxed), 0);

    engine.shutdown();
    let _ = shutdown_tx.send(true);
    let _ = std::fs::remove_dir_all(&state_dir);
}

#[tokio::test]
async fn verified_ip_doh_and_proxy_server_nameserver_and_static_hosts_and_geosite_policy_hierarchy()
{
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // Spawn verified literal-IP HTTP/2 DoH server (NO `#skip-cert-verify`, verified via IP SAN CA!)
    let mut doh_records = HashMap::new();
    doh_records.insert(
        "vip.edge.example.com".to_string(),
        Ipv4Addr::new(203, 0, 113, 11),
    );
    doh_records.insert(
        "boot-verified.example.com".to_string(),
        Ipv4Addr::new(198, 51, 100, 77),
    );
    let (verified_h2_addr, verified_h2_hits, doh_ca_der) =
        spawn_h2_only_doh_server(shutdown_rx.clone(), doh_records).await;

    // Verify `BootstrapDnsServer` supports verified literal-IP DoH (`https://127.0.0.1:<port>/dns-query`)
    let boot_doh =
        BootstrapDnsServer::parse(&format!("https://{verified_h2_addr}/dns-query")).unwrap();
    let boot_q = build_dns_query(0x4242, "boot-verified.example.com", QTYPE_A);
    let boot_resp = boot_doh
        .exchange_with_ca(&boot_q, std::slice::from_ref(&doh_ca_der))
        .await
        .expect("BootstrapDnsServer verified literal-IP h2 DoH exchange");
    assert_eq!(
        extract_ip_answers(&boot_resp).unwrap(),
        vec![DnsAnswerData::A(Ipv4Addr::new(198, 51, 100, 77))]
    );

    // Spawn 3 distinct UDP DNS upstreams to prove exact Mihomo resolution hierarchy:
    // - `proxy_ns` (`proxy-server-nameserver`) -> `std.edge.example.com` = `203.0.113.22`
    // - `cn_policy_ns` (`nameserver-policy` `geosite:cn,private`) -> `www.baidu.com` = `203.0.113.88`
    // - `direct_ns` (`direct-nameserver`) -> `www.baidu.com` = `203.0.113.77`
    // - `generic_ns` (`nameserver`) -> `www.github.com` = `198.51.100.99`, `www.baidu.com` = `198.51.100.250`
    let spawn_udp_map = |map: HashMap<&'static str, Ipv4Addr>| {
        let mut rx = shutdown_rx.clone();
        async move {
            let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
            let addr = sock.local_addr().unwrap();
            let sock_bg = Arc::clone(&sock);
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                loop {
                    tokio::select! {
                        _ = rx.changed() => break,
                        recv = sock_bg.recv_from(&mut buf) => {
                            let Ok((n, peer)) = recv else { break };
                            let raw = &buf[..n];
                            if let Ok(q) = DnsQueryPacket::parse(raw) {
                                let resp = match (map.get(q.question.name.as_str()), q.question.qtype) {
                                    (Some(&ip), QTYPE_A) => q.build_response(raw, 0, 120, &[DnsAnswerData::A(ip)]),
                                    _ => q.build_response(raw, 3, 60, &[]),
                                };
                                let _ = sock_bg.send_to(&resp, peer).await;
                            }
                        }
                    }
                }
            });
            addr
        }
    };

    let proxy_ns = spawn_udp_map(HashMap::from([(
        "std.edge.example.com",
        Ipv4Addr::new(203, 0, 113, 22),
    )]))
    .await;
    let cn_policy_ns = spawn_udp_map(HashMap::from([(
        "www.baidu.com",
        Ipv4Addr::new(203, 0, 113, 88),
    )]))
    .await;
    let direct_ns = spawn_udp_map(HashMap::from([(
        "www.baidu.com",
        Ipv4Addr::new(203, 0, 113, 77),
    )]))
    .await;
    let generic_ns = spawn_udp_map(HashMap::from([
        ("www.github.com", Ipv4Addr::new(198, 51, 100, 99)),
        ("www.baidu.com", Ipv4Addr::new(198, 51, 100, 250)),
    ]))
    .await;

    let yaml = format!(
        r#"mixed-port: 0
mode: rule
hosts:
  router.local.lan: 10.0.0.1
  '+.corp.internal':
    - 10.10.0.8
    - 10.10.0.9
dns:
  enable: true
  ipv6: false
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  use-hosts: true
  direct-nameserver-follow-policy: true
  default-nameserver:
    - {generic_ns}
  direct-nameserver:
    - {direct_ns}
  proxy-server-nameserver:
    - {proxy_ns}
  proxy-server-nameserver-policy:
    'vip.edge.example.com':
      - 'https://{verified_h2_addr}/dns-query'
  nameserver-policy:
    'geosite:cn,private': '{cn_policy_ns}'
  nameserver:
    - {generic_ns}
proxies:
  - name: 'dummy-ss'
    type: ss
    server: 127.0.0.1
    port: 8388
    cipher: chacha20-ietf-poly1305
    password: pass
rules:
  - MATCH,DIRECT
"#
    );

    let cfg = ClashConfig::from_yaml_str(&yaml).expect("parse root hosts + DNS policies YAML");
    let merged_dns = cfg.dns_with_merged_hosts();
    let dns = FakeIpDnsEngine::with_extra_ca(&merged_dns, std::slice::from_ref(&doh_ca_der))
        .expect("build FakeIpDnsEngine with merged hosts & policies");

    // 1. Static `hosts` MUST take precedence over `fake-ip` synthesis when `use-hosts: true`!
    let hosts_pkt = dns
        .handle_dns_packet(&build_dns_query(0x1001, "api.corp.internal", QTYPE_A))
        .await
        .unwrap();
    assert_eq!(dns_response_rcode(&hosts_pkt).unwrap(), 0);
    assert_eq!(
        extract_ip_answers(&hosts_pkt).unwrap(),
        vec![
            DnsAnswerData::A(Ipv4Addr::new(10, 10, 0, 8)),
            DnsAnswerData::A(Ipv4Addr::new(10, 10, 0, 9)),
        ]
    );
    assert_eq!(
        dns.resolve_proxy_server_ips("router.local.lan")
            .await
            .unwrap(),
        vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))]
    );

    // 2. When `use-hosts: false`, `api.corp.internal` allocates a Fake-IP in `198.18.0.0/16`!
    let mut no_hosts_dns_cfg: DnsConfig = merged_dns.clone();
    no_hosts_dns_cfg.use_hosts = false;
    let dns_no_hosts =
        FakeIpDnsEngine::with_extra_ca(&no_hosts_dns_cfg, std::slice::from_ref(&doh_ca_der))
            .unwrap();
    let fake_pkt = dns_no_hosts
        .handle_dns_packet(&build_dns_query(0x1002, "api.corp.internal", QTYPE_A))
        .await
        .unwrap();
    let fake_ans = extract_ip_answers(&fake_pkt).unwrap();
    assert_eq!(fake_ans.len(), 1);
    assert!(
        matches!(fake_ans[0], DnsAnswerData::A(v4) if v4.octets()[0..2] == [198, 18]),
        "expected Fake-IP when use-hosts=false, got {:?}",
        fake_ans
    );

    // 3. `proxy-server-nameserver-policy` hits verified literal-IP h2 DoH first (`vip.edge.example.com` -> `203.0.113.11`),
    //    and falls back to second policy entry (`proxy_ns`) when first returns NXDOMAIN (`std.edge.example.com` -> `203.0.113.22`)!
    let vip_ips = dns
        .resolve_proxy_server_ips("vip.edge.example.com")
        .await
        .unwrap();
    assert_eq!(vip_ips, vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 11))]);
    assert!(verified_h2_hits.load(Ordering::Relaxed) >= 2);

    let std_ips = dns
        .resolve_proxy_server_ips("std.edge.example.com")
        .await
        .unwrap();
    assert_eq!(std_ips, vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 22))]);

    // 4. `geosite:cn,private` in `nameserver-policy` routes `www.baidu.com` to `cn_policy_ns` (`203.0.113.88`),
    //    while `www.github.com` uses generic `nameserver` (`198.51.100.99`).
    assert_eq!(
        dns.resolve_real_ips("www.baidu.com").await.unwrap(),
        vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 88))]
    );
    assert_eq!(
        dns.resolve_real_ips("www.github.com").await.unwrap(),
        vec![IpAddr::V4(Ipv4Addr::new(198, 51, 100, 99))]
    );

    // 5. `direct-nameserver-follow-policy: true` vs `false`
    dns.flush_cache();
    assert_eq!(
        dns.resolve_direct_ips("www.baidu.com").await.unwrap(),
        vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 88))],
        "direct-nameserver-follow-policy=true must consult nameserver-policy before direct-nameserver"
    );

    let mut no_follow_cfg = merged_dns.clone();
    no_follow_cfg.direct_nameserver_follow_policy = false;
    let dns_no_follow =
        FakeIpDnsEngine::with_extra_ca(&no_follow_cfg, std::slice::from_ref(&doh_ca_der)).unwrap();
    assert_eq!(
        dns_no_follow
            .resolve_direct_ips("www.baidu.com")
            .await
            .unwrap(),
        vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 77))],
        "direct-nameserver-follow-policy=false must prefer direct-nameserver over nameserver-policy"
    );

    let _ = shutdown_tx.send(true);
}

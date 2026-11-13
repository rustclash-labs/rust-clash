use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use proxy_core::{
    api::spawn_api_server,
    config::{ClashConfig, DnsConfig},
    dns::{
        FakeIpDnsEngine,
        wire::{
            DnsAnswerData, DnsQueryPacket, QTYPE_A, QTYPE_AAAA, build_dns_query,
            dns_response_rcode, extract_ip_answers,
        },
    },
    engine::ProxyEngine,
    router::mmdb::build_synthetic_country_mmdb,
};
use rustls::ServerConfig;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::watch,
};
use tokio_rustls::TlsAcceptor;

const RCODE_NXDOMAIN: u8 = 3;

fn generate_test_tls_identity(sans: &[&str]) -> (CertificateDer<'static>, Arc<ServerConfig>) {
    let ck = rcgen::generate_simple_self_signed(
        sans.iter().map(|s| (*s).to_string()).collect::<Vec<_>>(),
    )
    .expect("rcgen self-signed certificate");
    let cert_der = ck.cert.der().clone();
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.key_pair.serialize_der()));

    let server_cfg = ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("TLS versions")
    .with_no_client_auth()
    .with_single_cert(vec![cert_der.clone()], key_der)
    .expect("single cert");

    (cert_der, Arc::new(server_cfg))
}

fn answer_authoritative_dns(req: &[u8]) -> Option<Vec<u8>> {
    let q = DnsQueryPacket::parse(req).ok()?;
    let resp = match (q.question.name.as_str(), q.question.qtype) {
        ("doh-target.example.test", QTYPE_A) => q.build_response(
            req,
            0,
            120,
            &[DnsAnswerData::A(Ipv4Addr::new(198, 51, 100, 10))],
        ),
        ("doh-target.example.test", QTYPE_AAAA) => q.build_response(
            req,
            0,
            120,
            &[DnsAnswerData::Aaaa(
                "2001:db8::88".parse::<Ipv6Addr>().unwrap(),
            )],
        ),
        ("dot-target.example.test", QTYPE_A) => q.build_response(
            req,
            0,
            120,
            &[DnsAnswerData::A(Ipv4Addr::new(203, 0, 113, 25))],
        ),
        ("trunc-target.example.test", QTYPE_A) => q.build_response(
            req,
            0,
            120,
            &[DnsAnswerData::A(Ipv4Addr::new(203, 0, 113, 77))],
        ),
        ("missing.example.test", _) => q.build_response(req, RCODE_NXDOMAIN, 60, &[]),
        _ => q.build_response(req, 0, 60, &[]),
    };
    Some(resp)
}

#[tokio::test]
async fn dns_doh_dot_tcp_truncation_bootstrap_and_caching_e2e() {
    // 1. Bootstrap UDP DNS server (`default-nameserver`) resolving `doh-ns.internal` & `dot-ns.internal` -> 127.0.0.1
    let boot_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let boot_addr = boot_sock.local_addr().unwrap();
    let boot_hits = Arc::new(AtomicUsize::new(0));
    let boot_hits_clone = Arc::clone(&boot_hits);
    let boot_sock_clone = Arc::clone(&boot_sock);
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);

    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => break,
                recv = boot_sock_clone.recv_from(&mut buf) => {
                    let Ok((n, peer)) = recv else { break };
                    let raw = &buf[..n];
                    if let Ok(q) = DnsQueryPacket::parse(raw) {
                        boot_hits_clone.fetch_add(1, Ordering::Relaxed);
                        let resp = match (q.question.name.as_str(), q.question.qtype) {
                            ("doh-ns.internal", QTYPE_A) | ("dot-ns.internal", QTYPE_A) => {
                                q.build_response(raw, 0, 300, &[DnsAnswerData::A(Ipv4Addr::LOCALHOST)])
                            }
                            _ => q.build_response(raw, RCODE_NXDOMAIN, 60, &[]),
                        };
                        let _ = boot_sock_clone.send_to(&resp, peer).await;
                    }
                }
            }
        }
    });

    // 2. Local DoH (`https://doh-ns.internal:<port>/dns-query` RFC 8484 POST) + DoT (`tls://dot-ns.internal:<port>`)
    let (ca_der, tls_cfg) = generate_test_tls_identity(&["doh-ns.internal", "dot-ns.internal"]);
    let doh_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let doh_port = doh_listener.local_addr().unwrap().port();
    let doh_hits = Arc::new(AtomicUsize::new(0));
    let doh_hits_clone = Arc::clone(&doh_hits);
    let doh_acceptor = TlsAcceptor::from(Arc::clone(&tls_cfg));
    let mut doh_shutdown = shutdown_tx.subscribe();

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = doh_shutdown.changed() => break,
                acc = doh_listener.accept() => {
                    let Ok((tcp, _)) = acc else { break };
                    let acceptor = doh_acceptor.clone();
                    let hits = Arc::clone(&doh_hits_clone);
                    tokio::spawn(async move {
                        let Ok(mut tls) = acceptor.accept(tcp).await else { return };
                        let mut req = Vec::with_capacity(2048);
                        let mut tmp = [0u8; 1024];
                        let header_end = loop {
                            let Ok(n) = tls.read(&mut tmp).await else { return };
                            if n == 0 { return; }
                            req.extend_from_slice(&tmp[..n]);
                            if let Some(pos) = req.windows(4).position(|w| w == b"\r\n\r\n") {
                                break pos + 4;
                            }
                        };
                        let hdr_str = String::from_utf8_lossy(&req[..header_end]);
                        assert!(hdr_str.to_ascii_lowercase().contains("application/dns-message"));
                        let content_len = hdr_str
                            .lines()
                            .find_map(|line| {
                                let (k, v) = line.split_once(':')?;
                                if k.trim().eq_ignore_ascii_case("content-length") {
                                    v.trim().parse::<usize>().ok()
                                } else {
                                    None
                                }
                            })
                            .unwrap_or(0);
                        while req.len() < header_end + content_len {
                            let Ok(n) = tls.read(&mut tmp).await else { return };
                            if n == 0 { break; }
                            req.extend_from_slice(&tmp[..n]);
                        }
                        let wire_q = &req[header_end..header_end + content_len];
                        hits.fetch_add(1, Ordering::Relaxed);
                        if let Some(wire_resp) = answer_authoritative_dns(wire_q) {
                            let http_resp = format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                wire_resp.len()
                            );
                            let _ = tls.write_all(http_resp.as_bytes()).await;
                            let _ = tls.write_all(&wire_resp).await;
                            let _ = tls.shutdown().await;
                        }
                    });
                }
            }
        }
    });

    let dot_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dot_port = dot_listener.local_addr().unwrap().port();
    let dot_hits = Arc::new(AtomicUsize::new(0));
    let dot_hits_clone = Arc::clone(&dot_hits);
    let dot_acceptor = TlsAcceptor::from(Arc::clone(&tls_cfg));
    let mut dot_shutdown = shutdown_tx.subscribe();

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = dot_shutdown.changed() => break,
                acc = dot_listener.accept() => {
                    let Ok((tcp, _)) = acc else { break };
                    let acceptor = dot_acceptor.clone();
                    let hits = Arc::clone(&dot_hits_clone);
                    tokio::spawn(async move {
                        let Ok(mut tls) = acceptor.accept(tcp).await else { return };
                        let mut len_buf = [0u8; 2];
                        if tls.read_exact(&mut len_buf).await.is_err() { return; }
                        let qlen = u16::from_be_bytes(len_buf) as usize;
                        let mut wire_q = vec![0u8; qlen];
                        if tls.read_exact(&mut wire_q).await.is_err() { return; }
                        hits.fetch_add(1, Ordering::Relaxed);
                        if let Some(wire_resp) = answer_authoritative_dns(&wire_q) {
                            let rlen = (wire_resp.len() as u16).to_be_bytes();
                            let _ = tls.write_all(&rlen).await;
                            let _ = tls.write_all(&wire_resp).await;
                            let _ = tls.shutdown().await;
                        }
                    });
                }
            }
        }
    });

    // 3. UDP `TC=1` + TCP DNS server on identical port proving RFC 1035 automatic UDP truncation retry over TCP!
    let trunc_tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let trunc_addr = trunc_tcp.local_addr().unwrap();
    let trunc_udp = Arc::new(UdpSocket::bind(trunc_addr).await.unwrap());
    let trunc_udp_hits = Arc::new(AtomicUsize::new(0));
    let trunc_tcp_hits = Arc::new(AtomicUsize::new(0));

    {
        let udp = Arc::clone(&trunc_udp);
        let hits = Arc::clone(&trunc_udp_hits);
        let mut rx = shutdown_tx.subscribe();
        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            loop {
                tokio::select! {
                    _ = rx.changed() => break,
                    recv = udp.recv_from(&mut buf) => {
                        let Ok((n, peer)) = recv else { break };
                        let raw = &buf[..n];
                        if let Ok(q) = DnsQueryPacket::parse(raw) {
                            hits.fetch_add(1, Ordering::Relaxed);
                            let mut tc_resp = q.build_response(raw, 0, 60, &[]);
                            tc_resp[2] |= 0x02; // TC=1 Truncated bit
                            let _ = udp.send_to(&tc_resp, peer).await;
                        }
                    }
                }
            }
        });
    }
    {
        let hits = Arc::clone(&trunc_tcp_hits);
        let mut rx = shutdown_tx.subscribe();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = rx.changed() => break,
                    acc = trunc_tcp.accept() => {
                        let Ok((mut s, _)) = acc else { break };
                        let hits = Arc::clone(&hits);
                        tokio::spawn(async move {
                            let mut len_buf = [0u8; 2];
                            if s.read_exact(&mut len_buf).await.is_err() { return; }
                            let qlen = u16::from_be_bytes(len_buf) as usize;
                            let mut q = vec![0u8; qlen];
                            if s.read_exact(&mut q).await.is_err() { return; }
                            hits.fetch_add(1, Ordering::Relaxed);
                            if let Some(resp) = answer_authoritative_dns(&q) {
                                let _ = s.write_all(&(resp.len() as u16).to_be_bytes()).await;
                                let _ = s.write_all(&resp).await;
                            }
                        });
                    }
                }
            }
        });
    }

    // 4. Test DoH + bootstrap + `redir-host` (Real-IP) + `ipv6: false` + positive/negative TTL cache + `flush_cache()`!
    let doh_cfg = DnsConfig {
        enable: true,
        listen: "127.0.0.1:0".to_string(),
        ipv6: false,
        enhanced_mode: "redir-host".to_string(),
        fake_ip_range: "198.18.0.1/16".to_string(),
        fake_ip_filter: vec![],
        default_nameserver: vec![boot_addr.to_string()],
        direct_nameserver: vec![],
        nameserver: vec![format!("https://doh-ns.internal:{doh_port}/dns-query")],
        fallback: vec![],
        ..Default::default()
    };
    let doh_dns =
        Arc::new(FakeIpDnsEngine::with_extra_ca(&doh_cfg, std::slice::from_ref(&ca_der)).unwrap());

    let ips_first = doh_dns
        .resolve_real_ips("doh-target.example.test")
        .await
        .unwrap();
    assert_eq!(ips_first, vec![IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10))]);
    assert!(
        boot_hits.load(Ordering::Relaxed) >= 1,
        "DoH hostname must be resolved via default-nameserver"
    );
    let hits_after_first = doh_hits.load(Ordering::Relaxed);
    assert_eq!(hits_after_first, 1);

    // Second lookup MUST hit positive TTL cache without contacting DoH server!
    let ips_cached = doh_dns
        .resolve_real_ips("doh-target.example.test")
        .await
        .unwrap();
    assert_eq!(ips_cached, ips_first);
    assert_eq!(
        doh_hits.load(Ordering::Relaxed),
        hits_after_first,
        "positive TTL cache must serve repeat lookup"
    );

    // `dns.ipv6: false` MUST synthesize empty NOERROR for AAAA without contacting upstream!
    let aaaa_pkt = doh_dns
        .handle_dns_packet(&build_dns_query(
            0x2222,
            "doh-target.example.test",
            QTYPE_AAAA,
        ))
        .await
        .unwrap();
    assert_eq!(dns_response_rcode(&aaaa_pkt).unwrap(), 0);
    assert!(extract_ip_answers(&aaaa_pkt).unwrap().is_empty());
    assert_eq!(
        doh_hits.load(Ordering::Relaxed),
        hits_after_first,
        "ipv6: false must not query upstream for AAAA"
    );

    // Negative `NXDOMAIN` caching: query `missing.example.test` twice -> upstream hit only once!
    let nx1 = doh_dns
        .resolve_real_ips("missing.example.test")
        .await
        .unwrap_err();
    assert!(nx1.to_string().contains("NXDOMAIN"));
    let hits_after_nx1 = doh_hits.load(Ordering::Relaxed);
    assert_eq!(hits_after_nx1, hits_after_first + 1);
    let nx2 = doh_dns
        .resolve_real_ips("missing.example.test")
        .await
        .unwrap_err();
    assert!(nx2.to_string().contains("cached"));
    assert_eq!(
        doh_hits.load(Ordering::Relaxed),
        hits_after_nx1,
        "NXDOMAIN negative cache must suppress repeat lookup"
    );

    // `flush_cache()` MUST invalidate cached entries so next query hits upstream again!
    doh_dns.flush_cache();
    assert_eq!(doh_dns.cached_record_count(), 0);
    let ips_post_flush = doh_dns
        .resolve_real_ips("doh-target.example.test")
        .await
        .unwrap();
    assert_eq!(ips_post_flush, ips_first);
    assert_eq!(doh_hits.load(Ordering::Relaxed), hits_after_nx1 + 1);

    // 5. Test `dns.ipv6: true` over DoT (`tls://`) + local TCP DNS server!
    let ipv6_dot_cfg = DnsConfig {
        enable: true,
        listen: "127.0.0.1:0".to_string(),
        ipv6: true,
        enhanced_mode: "normal".to_string(),
        fake_ip_range: "198.18.0.1/16".to_string(),
        fake_ip_filter: vec![],
        default_nameserver: vec![boot_addr.to_string()],
        direct_nameserver: vec![],
        nameserver: vec![format!("tls://dot-ns.internal:{dot_port}")],
        fallback: vec![format!("https://doh-ns.internal:{doh_port}/dns-query")],
        ..Default::default()
    };
    let dot_dns = Arc::new(FakeIpDnsEngine::with_extra_ca(&ipv6_dot_cfg, &[ca_der]).unwrap());
    let dot_ips = dot_dns
        .resolve_real_ips("dot-target.example.test")
        .await
        .unwrap();
    assert!(dot_ips.contains(&IpAddr::V4(Ipv4Addr::new(203, 0, 113, 25))));
    assert!(
        dot_hits.load(Ordering::Relaxed) >= 1,
        "DoT upstream must be queried"
    );

    // Spawn local TCP DNS listener and query it with RFC 1035 2-byte length prefix!
    let (local_dns_tcp_addr, _local_dns_tcp_task) = Arc::clone(&dot_dns)
        .spawn_tcp_server("127.0.0.1:0", shutdown_tx.subscribe())
        .await
        .unwrap();
    let mut client_tcp = TcpStream::connect(local_dns_tcp_addr).await.unwrap();
    let wire_q = build_dns_query(0x4444, "dot-target.example.test", QTYPE_A);
    client_tcp
        .write_all(&(wire_q.len() as u16).to_be_bytes())
        .await
        .unwrap();
    client_tcp.write_all(&wire_q).await.unwrap();
    let mut rlen_buf = [0u8; 2];
    client_tcp.read_exact(&mut rlen_buf).await.unwrap();
    let mut rbody = vec![0u8; u16::from_be_bytes(rlen_buf) as usize];
    client_tcp.read_exact(&mut rbody).await.unwrap();
    let tcp_answers = extract_ip_answers(&rbody).unwrap();
    assert_eq!(
        tcp_answers,
        vec![DnsAnswerData::A(Ipv4Addr::new(203, 0, 113, 25))]
    );

    // 6. Test UDP `TC=1` truncation automatic fallback to TCP!
    let trunc_cfg = DnsConfig {
        enable: true,
        listen: "127.0.0.1:0".to_string(),
        ipv6: false,
        enhanced_mode: "redir-host".to_string(),
        fake_ip_range: "198.18.0.1/16".to_string(),
        fake_ip_filter: vec![],
        default_nameserver: vec![trunc_addr.to_string()],
        direct_nameserver: vec![],
        nameserver: vec![format!("udp://{trunc_addr}")],
        fallback: vec![],
        ..Default::default()
    };
    let trunc_dns = FakeIpDnsEngine::new(&trunc_cfg).unwrap();
    let trunc_ips = trunc_dns
        .resolve_real_ips("trunc-target.example.test")
        .await
        .unwrap();
    assert_eq!(trunc_ips, vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 77))]);
    assert_eq!(
        trunc_udp_hits.load(Ordering::Relaxed),
        1,
        "UDP queried first"
    );
    assert_eq!(
        trunc_tcp_hits.load(Ordering::Relaxed),
        1,
        "TC=1 response must automatically retry over TCP"
    );

    let _ = shutdown_tx.send(true);
}

#[tokio::test]
async fn router_geosite_ruleset_mmdb_process_name_and_explain_api_e2e() {
    let temp_dir = std::env::temp_dir().join(format!("rust-clash-m2-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&temp_dir).unwrap();

    // 1. Write synthetic MaxMind `.mmdb` file with IPv4 (`198.51.100.0/24 -> JP`) and IPv6 (`2001:db8:abcd::/48 -> SG`)
    let mmdb_path = temp_dir.join("Country-test.mmdb");
    let mmdb_bytes = build_synthetic_country_mmdb(&[
        ("198.51.100.0/24".parse().unwrap(), "JP"),
        ("2001:db8:abcd::/48".parse().unwrap(), "SG"),
    ]);
    std::fs::write(&mmdb_path, mmdb_bytes).unwrap();

    // 2. Write local `file` rule-provider (`behavior: domain`)
    let ruleset_path = temp_dir.join("corp_domains.yaml");
    std::fs::write(
        &ruleset_path,
        "payload:\n  - '+.corp.example'\n  - 'portal.internal.test'\n",
    )
    .unwrap();

    // 3. Spawn a local TCP echo server to prove live `PROCESS-NAME` socket resolution over Mixed SOCKS5!
    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo_listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = echo_listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 64];
                if let Ok(n) = s.read(&mut buf).await {
                    let _ = s.write_all(&buf[..n]).await;
                }
            });
        }
    });

    let current_exe_name = std::env::current_exe()
        .unwrap()
        .file_name()
        .unwrap()
        .to_string_lossy()
        .to_string();

    let yaml = format!(
        r#"
mixed-port: 0
allow-lan: false
mode: rule
external-controller: 127.0.0.1:0
mmdb-path: "{mmdb}"
dns:
  enable: true
  listen: 127.0.0.1:0
  enhanced-mode: fake-ip
  default-nameserver:
    - 127.0.0.1:53
  nameserver:
    - 127.0.0.1:53
rule-providers:
  corp-domains:
    type: file
    behavior: domain
    format: yaml
    path: "{ruleset}"
  blocked-cidrs:
    type: inline
    behavior: ipcidr
    payload:
      - "192.0.2.0/24"
rules:
  - GEOSITE,openai,DIRECT
  - RULE-SET,corp-domains,DIRECT
  - RULE-SET,blocked-cidrs,REJECT
  - GEOIP,JP,DIRECT,no-resolve
  - GEOIP,SG,DIRECT,no-resolve
  - PROCESS-NAME,{exe},DIRECT
  - MATCH,REJECT
"#,
        mmdb = mmdb_path.display().to_string().replace('\\', "/"),
        ruleset = ruleset_path.display().to_string().replace('\\', "/"),
        exe = current_exe_name,
    );

    let cfg = ClashConfig::from_yaml_str(&yaml).expect("valid Milestone 2 config");
    let engine = ProxyEngine::start(cfg).await.expect("start engine");
    let (api_stop_tx, api_stop_rx) = watch::channel(false);
    let (api_addr, _api_handle) = spawn_api_server("127.0.0.1:0", Arc::clone(&engine), api_stop_rx)
        .await
        .expect("spawn API");
    let mixed_addr = engine.mixed_addr();

    async fn api_request(addr: SocketAddr, method: &str, path: &str) -> (u16, serde_json::Value) {
        let mut s = TcpStream::connect(addr).await.unwrap();
        let req = format!(
            "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
            addr.port()
        );
        s.write_all(req.as_bytes()).await.unwrap();
        let mut resp = Vec::new();
        s.read_to_end(&mut resp).await.unwrap();
        let text = String::from_utf8_lossy(&resp);
        let (hdr, body) = text.split_once("\r\n\r\n").unwrap();
        let code: u16 = hdr
            .lines()
            .next()
            .unwrap()
            .split_whitespace()
            .nth(1)
            .unwrap()
            .parse()
            .unwrap();
        let json: serde_json::Value = serde_json::from_str(body.trim()).unwrap_or_default();
        (code, json)
    }

    // Verify `GEOSITE,openai,DIRECT` via `/rules/explain`
    let (code, j_geosite) =
        api_request(api_addr, "GET", "/rules/explain?target=api.openai.com:443").await;
    assert_eq!(code, 200);
    assert_eq!(j_geosite["rule_type"], "GeoSite");
    assert_eq!(j_geosite["outbound"], "DIRECT");

    // Verify `RULE-SET,corp-domains,DIRECT`
    let (code, j_rset) = api_request(
        api_addr,
        "GET",
        "/rules/explain?target=intranet.corp.example:8443",
    )
    .await;
    assert_eq!(code, 200);
    assert_eq!(j_rset["rule_type"], "RuleSet");
    assert_eq!(j_rset["rule_payload"], "corp-domains");
    assert_eq!(j_rset["outbound"], "DIRECT");

    // Verify `RULE-SET,blocked-cidrs,REJECT`
    let (code, j_blocked) =
        api_request(api_addr, "GET", "/rules/explain?target=192.0.2.99:443").await;
    assert_eq!(code, 200);
    assert_eq!(j_blocked["rule_type"], "RuleSet");
    assert_eq!(j_blocked["outbound"], "REJECT");

    // Verify `.mmdb` IPv4 `GEOIP,JP,DIRECT` & IPv6 `GEOIP,SG,DIRECT`
    let (code, j_jp) =
        api_request(api_addr, "GET", "/rules/explain?target=198.51.100.42:443").await;
    assert_eq!(code, 200);
    assert_eq!(j_jp["rule_type"], "GeoIP");
    assert_eq!(j_jp["rule_payload"], "JP");
    assert_eq!(j_jp["outbound"], "DIRECT");

    let (code, j_sg) = api_request(
        api_addr,
        "GET",
        "/rules/explain?target=[2001:db8:abcd::1]:443",
    )
    .await;
    assert_eq!(code, 200);
    assert_eq!(j_sg["rule_type"], "GeoIP");
    assert_eq!(j_sg["rule_payload"], "SG");
    assert_eq!(j_sg["outbound"], "DIRECT");

    // Verify `POST /dns/flush`
    let (code, j_flush) = api_request(api_addr, "POST", "/dns/flush").await;
    assert_eq!(code, 200);
    assert_eq!(j_flush["flushed"], true);

    // Verify LIVE `PROCESS-NAME` matching through Mixed SOCKS5 Inbound!
    let mut socks = TcpStream::connect(mixed_addr).await.unwrap();
    socks.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut greet = [0u8; 2];
    socks.read_exact(&mut greet).await.unwrap();
    assert_eq!(greet, [0x05, 0x00]);

    let mut conn_req = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1];
    conn_req.extend_from_slice(&echo_addr.port().to_be_bytes());
    socks.write_all(&conn_req).await.unwrap();
    let mut rep = [0u8; 10];
    socks.read_exact(&mut rep).await.unwrap();
    assert_eq!(
        rep[1], 0x00,
        "PROCESS-NAME rule must match live client socket and permit SOCKS5 CONNECT"
    );
    socks.write_all(b"proc-match-ok").await.unwrap();
    let mut echoed = [0u8; 13];
    socks.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"proc-match-ok");

    let _ = api_stop_tx.send(true);
    engine.shutdown();
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[tokio::test]
async fn transactional_reload_restores_stopped_tun_and_ports_on_late_stage_bind_failure() {
    let initial_yaml = r#"
mixed-port: 0
allow-lan: false
mode: direct
external-controller: 127.0.0.1:0
dns:
  enable: true
  listen: 127.0.0.1:0
  enhanced-mode: fake-ip
  default-nameserver:
    - 127.0.0.1:53
  nameserver:
    - 127.0.0.1:53
tun:
  enable: true
  stack: gvisor
  auto-route: false
  mtu: 1500
rules:
  - MATCH,DIRECT
"#;

    let cfg = ClashConfig::from_yaml_str(initial_yaml).unwrap();
    let engine = ProxyEngine::start(cfg).await.unwrap();

    let mixed_port = engine.mixed_addr().port();
    let dns_port = engine
        .dns_addr()
        .expect("ephemeral DNS UDP+TCP listener must bind")
        .port();
    assert_ne!(mixed_port, 0);
    assert_ne!(dns_port, 0);
    assert!(engine.is_virtual_tun_active());
    assert_eq!(engine.config_snapshot().tun.mtu, 1500);

    // Occupy a TCP port AND a UDP port to force late-stage bind failures AFTER Stage 2 stops the old TUN!
    let occupied_tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bad_mixed_port = occupied_tcp.local_addr().unwrap().port();

    // Case A: Stage 2 stops TUN (`mtu: 1400` != `1500`), then Stage 3 (`mixed-port` bind) FAILS!
    let bad_mixed_yaml = format!(
        r#"
mixed-port: {bad_mixed_port}
allow-lan: false
mode: direct
external-controller: 127.0.0.1:0
dns:
  enable: true
  listen: 127.0.0.1:{dns_port}
  enhanced-mode: fake-ip
  default-nameserver:
    - 127.0.0.1:53
  nameserver:
    - 127.0.0.1:53
tun:
  enable: true
  stack: gvisor
  auto-route: false
  mtu: 1400
rules:
  - MATCH,DIRECT
"#
    );
    let err_a = engine.reload_yaml(&bad_mixed_yaml).await;
    assert!(
        err_a.is_err(),
        "reload_yaml must fail when new mixed-port is occupied"
    );
    assert!(
        engine.is_virtual_tun_active(),
        "transactional rollback MUST restore previously running virtual TUN after Stage 3 Mixed bind failure"
    );
    assert_eq!(engine.config_snapshot().tun.mtu, 1500);
    assert_eq!(engine.mixed_addr().port(), mixed_port);

    // Case B: Stage 2 stops TUN (`mtu: 1400`), Stage 3 rebinds Mixed to a new valid ephemeral port, then Stage 4 (`dns.listen` bind) FAILS!
    let occupied_udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let bad_dns_port = occupied_udp.local_addr().unwrap().port();

    let bad_dns_yaml = format!(
        r#"
mixed-port: 0
allow-lan: false
mode: direct
external-controller: 127.0.0.1:0
dns:
  enable: true
  listen: 127.0.0.1:{bad_dns_port}
  enhanced-mode: fake-ip
  default-nameserver:
    - 127.0.0.1:53
  nameserver:
    - 127.0.0.1:53
tun:
  enable: true
  stack: gvisor
  auto-route: false
  mtu: 1400
rules:
  - MATCH,DIRECT
"#
    );
    let err_b = engine.reload_yaml(&bad_dns_yaml).await;
    assert!(
        err_b.is_err(),
        "reload_yaml must fail when new dns.listen port is occupied"
    );
    assert!(
        engine.is_virtual_tun_active(),
        "transactional rollback MUST restore previously running virtual TUN after Stage 4 DNS bind failure"
    );
    assert_eq!(engine.config_snapshot().tun.mtu, 1500);
    assert_eq!(engine.mixed_addr().port(), mixed_port);
    assert_eq!(engine.dns_addr().unwrap().port(), dns_port);

    // Verify original DNS UDP listener STILL answers Fake-IP queries after both rollbacks!
    let client_udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let q = build_dns_query(0x7777, "rollback-check.example.com", QTYPE_A);
    client_udp
        .send_to(&q, SocketAddr::from(([127, 0, 0, 1], dns_port)))
        .await
        .unwrap();
    let mut rbuf = [0u8; 512];
    let (rn, _) = tokio::time::timeout(Duration::from_secs(2), client_udp.recv_from(&mut rbuf))
        .await
        .expect("DNS response after rollback")
        .unwrap();
    let answers = extract_ip_answers(&rbuf[..rn]).unwrap();
    assert_eq!(answers.len(), 1);

    engine.shutdown();
}

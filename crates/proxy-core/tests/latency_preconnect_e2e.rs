use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use proxy_core::{
    api::spawn_api_server,
    config::{ClashConfig, DnsConfig, ProxyGroupConfig, ProxyGroupType, ProxyNodeConfig, RunMode},
    crypto::tls::generate_self_signed_server_config,
    dns::{
        FakeIpDnsEngine,
        wire::{DnsAnswerData, DnsQueryPacket, QTYPE_A},
    },
    engine::{PreconnectPolicy, ProxyEngine},
    outbound::anytls::{
        AnyTlsOutbound, AnyTlsServerConfig, padding::PaddingScheme, spawn_anytls_server,
    },
    platform::socket_protect::clear_global_socket_protector,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::watch,
};
use tokio_rustls::TlsAcceptor;
use uuid::Uuid;

const H2_CLIENT_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

struct TempStateDir {
    path: PathBuf,
}

impl TempStateDir {
    fn new(prefix: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("rustclash-{prefix}-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("create temp state dir");
        Self { path: dir }
    }
}

impl Drop for TempStateDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

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

/// Spawn an HTTP/1.1 origin server that simulates `first_connect_delay` on each new TCP connection
/// (e.g. cold proxy/TLS setup), then serves subsequent requests on the same Keep-Alive connection
/// instantaneously (`< 1ms`), or optionally closes after the first response (`keep_alive = false`).
async fn spawn_cold_start_http_origin(
    mut shutdown: watch::Receiver<bool>,
    first_connect_delay: Duration,
    keep_alive: bool,
) -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let total_reqs = Arc::new(AtomicUsize::new(0));
    let total_reqs_bg = Arc::clone(&total_reqs);

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = shutdown.changed() => break,
                acc = listener.accept() => {
                    let Ok((mut sock, _)) = acc else { break };
                    let reqs_counter = Arc::clone(&total_reqs_bg);
                    tokio::spawn(async move {
                        if !first_connect_delay.is_zero() {
                            tokio::time::sleep(first_connect_delay).await;
                        }
                        let mut buf = Vec::with_capacity(1024);
                        let mut tmp = [0u8; 512];
                        loop {
                            while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                                let Ok(n) = sock.read(&mut tmp).await else { return };
                                if n == 0 {
                                    return;
                                }
                                buf.extend_from_slice(&tmp[..n]);
                            }
                            let hdr_end = buf.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
                            let req_head = String::from_utf8_lossy(&buf[..hdr_end]).to_string();
                            buf.drain(..hdr_end);
                            reqs_counter.fetch_add(1, Ordering::Relaxed);

                            let is_head = req_head.starts_with("HEAD ");
                            let conn_hdr = if keep_alive { "keep-alive" } else { "close" };
                            let resp = if req_head.contains("/generate_204 ") {
                                format!(
                                    "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: {conn_hdr}\r\n\r\n"
                                )
                            } else {
                                let body = "preconnect-ok";
                                if is_head {
                                    format!(
                                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: {conn_hdr}\r\n\r\n",
                                        body.len()
                                    )
                                } else {
                                    format!(
                                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: {conn_hdr}\r\n\r\n{}",
                                        body.len(),
                                        body
                                    )
                                }
                            };
                            if sock.write_all(resp.as_bytes()).await.is_err()
                                || sock.flush().await.is_err()
                            {
                                return;
                            }
                            if !keep_alive || req_head.to_ascii_lowercase().contains("connection: close") {
                                let _ = sock.shutdown().await;
                                return;
                            }
                        }
                    });
                }
            }
        }
    });

    (addr, total_reqs)
}

async fn spawn_udp_dns_server(
    mut shutdown: watch::Receiver<bool>,
    records: HashMap<String, Ipv4Addr>,
) -> (SocketAddr, Arc<AtomicUsize>) {
    let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr = sock.local_addr().unwrap();
    let queries = Arc::new(AtomicUsize::new(0));
    let queries_bg = Arc::clone(&queries);

    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        loop {
            tokio::select! {
                _ = shutdown.changed() => break,
                recv = sock.recv_from(&mut buf) => {
                    let Ok((n, peer)) = recv else { break };
                    let pkt = &buf[..n];
                    let Ok(q) = DnsQueryPacket::parse(pkt) else { continue };
                    queries_bg.fetch_add(1, Ordering::Relaxed);
                    let resp = match (records.get(q.question.name.as_str()), q.question.qtype) {
                        (Some(&ip), QTYPE_A) => {
                            q.build_response(pkt, 0, 180, &[DnsAnswerData::A(ip)])
                        }
                        (Some(_), _) => q.build_response(pkt, 0, 180, &[]),
                        (None, _) => q.build_response(pkt, 3, 60, &[]),
                    };
                    let _ = sock.send_to(&resp, peer).await;
                }
            }
        }
    });

    (addr, queries)
}

/// Spawn a multi-stream RFC 9113 HTTP/2 (`ALPN = h2`) DoH server supporting concurrent multiplexed
/// streams on a single TLS 1.3 connection and counting accepted TLS handshakes vs total DoH queries.
async fn spawn_multiplexed_h2_doh_server(
    mut shutdown: watch::Receiver<bool>,
    records: HashMap<String, Ipv4Addr>,
    per_stream_delay: Duration,
) -> (
    SocketAddr,
    Arc<AtomicUsize>,
    Arc<AtomicUsize>,
    rustls_pki_types::CertificateDer<'static>,
) {
    let (tls_cfg, ca_der) = generate_self_signed_server_config(
        &[
            "doh.pool.example.com".to_string(),
            "127.0.0.1".to_string(),
            "localhost".to_string(),
        ],
        &[b"h2".to_vec()],
    )
    .expect("generate multiplexed h2 DoH server TLS config");
    let acceptor = TlsAcceptor::from(tls_cfg);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bound = listener.local_addr().unwrap();
    let tls_handshakes = Arc::new(AtomicUsize::new(0));
    let doh_queries = Arc::new(AtomicUsize::new(0));

    let hs_bg = Arc::clone(&tls_handshakes);
    let q_bg = Arc::clone(&doh_queries);

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = shutdown.changed() => break,
                acc = listener.accept() => {
                    let Ok((tcp, _)) = acc else { break };
                    let acceptor = acceptor.clone();
                    let hs_conn = Arc::clone(&hs_bg);
                    let q_conn = Arc::clone(&q_bg);
                    let records_conn = records.clone();
                    tokio::spawn(async move {
                        let Ok(tls) = acceptor.accept(tcp).await else { return };
                        assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
                        hs_conn.fetch_add(1, Ordering::SeqCst);

                        let (mut rd, mut wr) = tokio::io::split(tls);
                        let mut preface = [0u8; 24];
                        if rd.read_exact(&mut preface).await.is_err() || preface != H2_CLIENT_PREFACE {
                            return;
                        }

                        let (frame_tx, mut frame_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
                        let writer_task = tokio::spawn(async move {
                            // Advertise SETTINGS_MAX_CONCURRENT_STREAMS = 64
                            let mut greet = Vec::with_capacity(32);
                            let mut settings_payload = Vec::with_capacity(6);
                            settings_payload.extend_from_slice(&3u16.to_be_bytes());
                            settings_payload.extend_from_slice(&64u32.to_be_bytes());
                            push_h2_frame(&mut greet, 0x4, 0x0, 0, &settings_payload);
                            if wr.write_all(&greet).await.is_err() || wr.flush().await.is_err() {
                                return;
                            }
                            while let Some(chunk) = frame_rx.recv().await {
                                if wr.write_all(&chunk).await.is_err() || wr.flush().await.is_err() {
                                    break;
                                }
                            }
                        });

                        let mut stream_bodies: HashMap<u32, Vec<u8>> = HashMap::new();
                        loop {
                            let mut hdr = [0u8; 9];
                            if rd.read_exact(&mut hdr).await.is_err() {
                                break;
                            }
                            let flen = ((hdr[0] as usize) << 16)
                                | ((hdr[1] as usize) << 8)
                                | (hdr[2] as usize);
                            let ftype = hdr[3];
                            let flags = hdr[4];
                            let sid =
                                u32::from_be_bytes([hdr[5], hdr[6], hdr[7], hdr[8]]) & 0x7fff_ffff;
                            let mut payload = vec![0u8; flen];
                            if flen > 0 && rd.read_exact(&mut payload).await.is_err() {
                                break;
                            }

                            match ftype {
                                0x4 if (flags & 0x1) == 0 => {
                                    let mut ack = Vec::with_capacity(9);
                                    push_h2_frame(&mut ack, 0x4, 0x1, 0, &[]);
                                    let _ = frame_tx.send(ack);
                                }
                                0x6 if (flags & 0x1) == 0 && payload.len() == 8 => {
                                    let mut ack = Vec::with_capacity(17);
                                    push_h2_frame(&mut ack, 0x6, 0x1, 0, &payload);
                                    let _ = frame_tx.send(ack);
                                }
                                0x1 if sid > 0 => {
                                    stream_bodies.entry(sid).or_default();
                                }
                                0x0 if sid > 0 => {
                                    let entry = stream_bodies.entry(sid).or_default();
                                    entry.extend_from_slice(&payload);
                                    if !payload.is_empty() {
                                        let mut wu = Vec::with_capacity(26);
                                        let inc = (payload.len() as u32).to_be_bytes();
                                        push_h2_frame(&mut wu, 0x8, 0x0, 0, &inc);
                                        push_h2_frame(&mut wu, 0x8, 0x0, sid, &inc);
                                        let _ = frame_tx.send(wu);
                                    }
                                    if (flags & 0x1) != 0 {
                                        let req_body = stream_bodies.remove(&sid).unwrap_or_default();
                                        let tx = frame_tx.clone();
                                        let recs = records_conn.clone();
                                        let qc = Arc::clone(&q_conn);
                                        tokio::spawn(async move {
                                            if !per_stream_delay.is_zero() {
                                                tokio::time::sleep(per_stream_delay).await;
                                            }
                                            let Ok(q) = DnsQueryPacket::parse(&req_body) else {
                                                return;
                                            };
                                            qc.fetch_add(1, Ordering::Relaxed);
                                            let wire_resp = match (
                                                recs.get(q.question.name.as_str()),
                                                q.question.qtype,
                                            ) {
                                                (Some(&ip), QTYPE_A) => q.build_response(
                                                    &req_body,
                                                    0,
                                                    180,
                                                    &[DnsAnswerData::A(ip)],
                                                ),
                                                (Some(_), _) => {
                                                    q.build_response(&req_body, 0, 180, &[])
                                                }
                                                (None, _) => {
                                                    q.build_response(&req_body, 3, 60, &[])
                                                }
                                            };
                                            let mut out = Vec::with_capacity(32 + wire_resp.len());
                                            push_h2_frame(&mut out, 0x1, 0x4, sid, &[0x88]);
                                            push_h2_frame(&mut out, 0x0, 0x1, sid, &wire_resp);
                                            let _ = tx.send(out);
                                        });
                                    }
                                }
                                _ => {}
                            }
                        }
                        writer_task.abort();
                    });
                }
            }
        }
    });

    (bound, tls_handshakes, doh_queries, ca_der)
}

async fn raw_http_request(
    addr: SocketAddr,
    method: &str,
    path: &str,
    body: Option<&str>,
) -> (u16, String) {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let req = match body {
        Some(b) => format!(
            "{method} {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{b}",
            b.len()
        ),
        None => format!("{method} {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n"),
    };
    stream.write_all(req.as_bytes()).await.unwrap();
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await.unwrap();
    let text = String::from_utf8_lossy(&raw);
    let (head, resp_body) = text.split_once("\r\n\r\n").expect("HTTP header separator");
    let status = head
        .lines()
        .next()
        .unwrap_or_default()
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    (status, resp_body.to_string())
}

#[tokio::test]
async fn unified_delay_eliminates_cold_handshake_skew_and_toggles_via_api() {
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (keepalive_origin, ka_reqs) =
        spawn_cold_start_http_origin(shutdown_rx.clone(), Duration::from_millis(140), true).await;
    let (close_origin, close_reqs) =
        spawn_cold_start_http_origin(shutdown_rx.clone(), Duration::from_millis(90), false).await;

    let (ss_addr, _ss_task) = proxy_core::outbound::ss::spawn_ss_server(
        "127.0.0.1:0",
        "chacha20-ietf-poly1305",
        "test-unified-delay-pass",
        shutdown_rx.clone(),
    )
    .await
    .unwrap();

    let tmp = TempStateDir::new("unified-delay");
    let cfg = ClashConfig {
        mixed_port: 0,
        unified_delay: true,
        dns: DnsConfig {
            enable: false,
            ..Default::default()
        },
        proxies: vec![ProxyNodeConfig::Ss {
            name: "SS-UNIFIED".into(),
            server: "127.0.0.1".into(),
            port: ss_addr.port(),
            cipher: "chacha20-ietf-poly1305".into(),
            password: "test-unified-delay-pass".into(),
            udp: true,
        }],
        rules: vec!["MATCH,SS-UNIFIED".into()],
        ..Default::default()
    };

    let engine = ProxyEngine::start_with_options(
        cfg,
        tmp.path.clone(),
        PreconnectPolicy::Disabled,
        None,
        None,
    )
    .await
    .unwrap();

    let ka_url = format!("http://{keepalive_origin}/generate_204");

    // 1. Default `unified-delay: true`: HEAD #1 absorbs the 140ms cold connection setup,
    //    and HEAD #2 measures pure 1-RTT payload latency (< 60ms on localhost).
    let warm_ms = engine
        .router()
        .test_delay("SS-UNIFIED", &ka_url, Duration::from_secs(3))
        .await
        .expect("unified-delay probe should succeed");
    assert!(
        warm_ms < 75,
        "expected unified-delay HEAD #2 RTT < 75ms (excluding 140ms cold setup), got {warm_ms}ms"
    );
    assert_eq!(
        ka_reqs.load(Ordering::Relaxed),
        2,
        "unified-delay must issue warm-up HEAD #1 + measured HEAD #2 on Keep-Alive origin"
    );

    // 2. Fallback safety: if origin sends `Connection: close`, `unified-delay: true` gracefully
    //    returns HEAD #1 RTT rather than failing on closed socket!
    let close_url = format!("http://{close_origin}/generate_204");
    let fallback_ms = engine
        .router()
        .test_delay("SS-UNIFIED", &close_url, Duration::from_secs(3))
        .await
        .expect("Connection: close origin must still succeed via fallback");
    assert!(
        fallback_ms >= 80,
        "fallback RTT should reflect HEAD #1 (>= 80ms), got {fallback_ms}ms"
    );
    assert_eq!(close_reqs.load(Ordering::Relaxed), 1);

    // 3. Verify `/configs` GET + PATCH toggles `unified-delay` live at runtime!
    let (api_stop_tx, api_stop_rx) = watch::channel(false);
    let (api_addr, _api_task) = spawn_api_server("127.0.0.1:0", Arc::clone(&engine), api_stop_rx)
        .await
        .unwrap();

    let (st_get, body_get) = raw_http_request(api_addr, "GET", "/configs", None).await;
    assert_eq!(st_get, 200);
    let json_get: serde_json::Value = serde_json::from_str(&body_get).unwrap();
    assert_eq!(json_get["unified-delay"], true);

    let (st_patch, _) = raw_http_request(
        api_addr,
        "PATCH",
        "/configs",
        Some(r#"{"unified-delay":false}"#),
    )
    .await;
    assert_eq!(st_patch, 204);
    assert!(!engine.router().unified_delay());

    let cold_ms = engine
        .router()
        .test_delay("SS-UNIFIED", &ka_url, Duration::from_secs(3))
        .await
        .expect("cold-delay probe should succeed");
    assert!(
        cold_ms >= 130,
        "with unified-delay=false, measured delay must include 140ms cold setup, got {cold_ms}ms"
    );

    let _ = api_stop_tx.send(true);
    engine.shutdown();
    let _ = shutdown_tx.send(true);
}

#[tokio::test]
async fn h2_doh_multiplexing_pool_shares_single_tls_connection_across_16_concurrent_queries() {
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let mut doh_records = HashMap::new();
    for i in 0..16u8 {
        doh_records.insert(
            format!("node-{i}.edge.example.com"),
            Ipv4Addr::new(198, 51, 100, 10 + i),
        );
    }
    doh_records.insert(
        "post-epoch.edge.example.com".to_string(),
        Ipv4Addr::new(198, 51, 100, 99),
    );

    // Hold each stream for 30ms so all 16 concurrent queries overlap simultaneously in flight!
    let (doh_addr, tls_handshakes, doh_queries, doh_ca_der) = spawn_multiplexed_h2_doh_server(
        shutdown_rx.clone(),
        doh_records,
        Duration::from_millis(30),
    )
    .await;

    let mut bootstrap_records = HashMap::new();
    bootstrap_records.insert("doh.pool.example.com".to_string(), Ipv4Addr::LOCALHOST);
    let (bootstrap_addr, bootstrap_queries) =
        spawn_udp_dns_server(shutdown_rx.clone(), bootstrap_records).await;

    let dns_cfg = DnsConfig {
        enable: true,
        ipv6: false,
        enhanced_mode: "fake-ip".to_string(),
        default_nameserver: vec![bootstrap_addr.to_string()],
        nameserver: vec![format!(
            "https://doh.pool.example.com:{}/dns-query",
            doh_addr.port()
        )],
        proxy_server_nameserver: vec![format!(
            "https://doh.pool.example.com:{}/dns-query",
            doh_addr.port()
        )],
        ..Default::default()
    };
    let dns = Arc::new(FakeIpDnsEngine::with_extra_ca(&dns_cfg, &[doh_ca_der]).unwrap());

    let started = Instant::now();
    let mut set = tokio::task::JoinSet::new();
    for i in 0..16u8 {
        let dns_c = Arc::clone(&dns);
        set.spawn(async move {
            let host = format!("node-{i}.edge.example.com");
            let ips = dns_c
                .resolve_proxy_server_ips(&host)
                .await
                .expect("concurrent h2 DoH query must succeed");
            (i, ips)
        });
    }

    while let Some(res) = set.join_next().await {
        let (i, ips) = res.unwrap();
        assert_eq!(ips, vec![IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10 + i))]);
    }
    let elapsed = started.elapsed();

    assert_eq!(
        doh_queries.load(Ordering::SeqCst),
        16,
        "all 16 distinct proxy hostnames must be resolved via DoH"
    );
    assert_eq!(
        tls_handshakes.load(Ordering::SeqCst),
        1,
        "16 concurrent DoH queries must multiplex over a SINGLE HTTP/2 TLS handshake"
    );
    assert_eq!(
        bootstrap_queries.load(Ordering::SeqCst),
        1,
        "DoH hostname bootstrap resolution must also coalesce to 1 UDP query"
    );
    assert!(
        elapsed < Duration::from_millis(400),
        "multiplexed 16x30ms DoH queries should complete in parallel (~30-80ms), took {elapsed:?}"
    );

    // Bumping SocketProtector epoch must isolate/evict pooled sockets and establish a fresh connection!
    clear_global_socket_protector();
    let post_ips = dns
        .resolve_proxy_server_ips("post-epoch.edge.example.com")
        .await
        .expect("post-epoch DoH query should succeed on fresh connection");
    assert_eq!(post_ips, vec![IpAddr::V4(Ipv4Addr::new(198, 51, 100, 99))]);
    assert_eq!(
        tls_handshakes.load(Ordering::SeqCst),
        2,
        "protector epoch bump must force a fresh TLS connection instead of reusing pre-epoch socket"
    );

    let _ = shutdown_tx.send(true);
}

#[tokio::test]
async fn smart_preconnect_policy_desktop_vs_mobile_and_low_power_zero_hz() {
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (origin_addr, _origin_reqs) =
        spawn_cold_start_http_origin(shutdown_rx.clone(), Duration::ZERO, false).await;

    let (anytls_tls_cfg, anytls_ca_der) = generate_self_signed_server_config(
        &[
            "gw.preconnect.example.com".to_string(),
            "127.0.0.1".to_string(),
            "localhost".to_string(),
        ],
        &[],
    )
    .unwrap();
    let (anytls_addr, _anytls_task) = spawn_anytls_server(
        AnyTlsServerConfig {
            listen_addr: "127.0.0.1:0".into(),
            password: "preconnect-anytls-secret".into(),
            tls_config: anytls_tls_cfg,
            padding_scheme: PaddingScheme::default(),
        },
        shutdown_rx.clone(),
    )
    .await
    .unwrap();

    let mut dns_records = HashMap::new();
    dns_records.insert("gw.preconnect.example.com".to_string(), Ipv4Addr::LOCALHOST);
    let (dns_addr, dns_queries) = spawn_udp_dns_server(shutdown_rx.clone(), dns_records).await;

    let make_cfg = || ClashConfig {
        mixed_port: 0,
        mode: RunMode::Rule,
        dns: DnsConfig {
            enable: true,
            ipv6: false,
            listen: "127.0.0.1:0".into(),
            nameserver: vec![dns_addr.to_string()],
            proxy_server_nameserver: vec![dns_addr.to_string()],
            ..Default::default()
        },
        proxies: vec![ProxyNodeConfig::Anytls {
            name: "ANYTLS-PRIMARY".into(),
            server: "gw.preconnect.example.com".into(),
            port: anytls_addr.port(),
            password: "preconnect-anytls-secret".into(),
            sni: Some("gw.preconnect.example.com".into()),
            skip_cert_verify: true,
            alpn: vec![],
            udp: true,
            idle_session_check_interval: 30,
            idle_session_timeout: 60,
            min_idle_session: 0,
        }],
        proxy_groups: vec![ProxyGroupConfig {
            name: "PROXY".into(),
            group_type: ProxyGroupType::Select,
            proxies: vec!["ANYTLS-PRIMARY".into()],
            url: format!("http://{origin_addr}/generate_204"),
            interval: 300,
            tolerance: 50,
            strategy: None,
        }],
        rules: vec!["MATCH,PROXY".into()],
        ..Default::default()
    };

    // --- Part A: Desktop Policy (`target_sessions = 2`) ---
    let tmp_desktop = TempStateDir::new("preconnect-desktop");
    let desktop_engine = ProxyEngine::start_with_options(
        make_cfg(),
        tmp_desktop.path.clone(),
        PreconnectPolicy::Desktop,
        None,
        None,
    )
    .await
    .unwrap();
    let _ = &anytls_ca_der;

    let ob_arc = desktop_engine
        .router()
        .outbound("ANYTLS-PRIMARY")
        .expect("ANYTLS-PRIMARY outbound");
    let anytls_ob = (ob_arc.as_ref() as &dyn std::any::Any)
        .downcast_ref::<AnyTlsOutbound>()
        .expect("downcast AnyTlsOutbound");

    let deadline = Instant::now() + Duration::from_secs(3);
    while anytls_ob.pool().idle_count() < 2 && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(
        anytls_ob.pool().idle_count(),
        2,
        "Desktop PreconnectPolicy must proactively warm 2 verified AnyTLS v2 idle sessions before any client connects"
    );
    assert_eq!(
        dns_queries.load(Ordering::Relaxed),
        1,
        "preconnect must resolve & cache proxy server DNS once"
    );
    assert_eq!(anytls_ob.pool().reuse_count(), 0);

    // First client request through Mixed Inbound MUST reuse a pre-warmed AnyTLS v2 session (0 handshake wait)!
    let mixed_addr = desktop_engine.mixed_addr();
    let mut client = TcpStream::connect(mixed_addr).await.unwrap();
    let connect_req = format!("CONNECT {origin_addr} HTTP/1.1\r\nHost: {origin_addr}\r\n\r\n");
    client.write_all(connect_req.as_bytes()).await.unwrap();
    let mut cbuf = [0u8; 128];
    let cn = client.read(&mut cbuf).await.unwrap();
    assert!(String::from_utf8_lossy(&cbuf[..cn]).starts_with("HTTP/1.1 200"));
    client
        .write_all(
            format!("GET /hello HTTP/1.1\r\nHost: {origin_addr}\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
    let mut resp = Vec::new();
    client.read_to_end(&mut resp).await.unwrap();
    assert!(String::from_utf8_lossy(&resp).ends_with("preconnect-ok"));
    assert!(
        anytls_ob.pool().reuse_count() >= 1,
        "first user stream must immediately reuse a pre-warmed AnyTLS v2 session"
    );
    desktop_engine.shutdown();

    // --- Part B: Mobile Policy (`target_sessions = 1`, 0 Hz when screen off, wake on screen on) ---
    let tmp_mobile = TempStateDir::new("preconnect-mobile");
    let mobile_engine = ProxyEngine::start_with_options(
        make_cfg(),
        tmp_mobile.path.clone(),
        PreconnectPolicy::Mobile,
        None,
        None,
    )
    .await
    .unwrap();

    let mob_arc = mobile_engine
        .router()
        .outbound("ANYTLS-PRIMARY")
        .expect("mobile ANYTLS-PRIMARY outbound");
    let mob_anytls = (mob_arc.as_ref() as &dyn std::any::Any)
        .downcast_ref::<AnyTlsOutbound>()
        .expect("downcast mobile AnyTlsOutbound");

    let mob_deadline = Instant::now() + Duration::from_secs(3);
    while mob_anytls.pool().idle_count() < 1 && Instant::now() < mob_deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    tokio::time::sleep(Duration::from_millis(80)).await;
    assert_eq!(
        mob_anytls.pool().idle_count(),
        1,
        "Mobile PreconnectPolicy must warm strictly 1 idle session (battery-aware)"
    );

    // Enter Android screen-off / Doze low-power mode -> propagates to AnyTlsSessionPool (`0 Hz`)
    mobile_engine.set_low_power_mode(true);
    assert!(mobile_engine.is_low_power_mode());
    assert!(mob_anytls.pool().is_low_power_mode());

    // Evict sessions while in low-power mode and confirm ZERO background preconnect occurs while parked
    mob_anytls.pool().on_network_change();
    assert_eq!(mob_anytls.pool().idle_count(), 0);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        mob_anytls.pool().idle_count(),
        0,
        "while low_power_mode is true, Mobile preconnect and AnyTLS reaper must stay parked at 0 Hz"
    );

    // Screen turns back on (`set_low_power_mode(false)`) -> immediately wakes & prewarms 1 session!
    mobile_engine.set_low_power_mode(false);
    assert!(!mob_anytls.pool().is_low_power_mode());
    let wake_deadline = Instant::now() + Duration::from_secs(3);
    while mob_anytls.pool().idle_count() < 1 && Instant::now() < wake_deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(
        mob_anytls.pool().idle_count(),
        1,
        "screen-on transition must wake Mobile preconnect and warm 1 ready AnyTLS session"
    );

    mobile_engine.shutdown();
    let _ = shutdown_tx.send(true);
}

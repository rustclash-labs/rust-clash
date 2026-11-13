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
use bytes::{BufMut, BytesMut};
use parking_lot::RwLock;
use proxy_core::{
    addr::TargetAddr,
    config::{ClashConfig, DnsConfig, ProxyGroupConfig, ProxyGroupType, RunMode},
    crypto::tls::generate_self_signed_server_config,
    dns::{
        FakeIpDnsEngine,
        wire::{DnsAnswerData, DnsQueryPacket, QTYPE_A, build_dns_query, extract_ip_answers},
    },
    engine::ProxyEngine,
    inbound::{tun::spawn_userspace_tun, udp_nat::UdpNatManager},
    outbound::{
        BoxedStream, DynOutbound, OutboundHandler,
        socks5::{Socks5Outbound, Socks5OutboundConfig},
        ss::spawn_ss_server,
        trojan::{
            TROJAN_CMD_UDP, TrojanOutbound, TrojanOutboundConfig, encode_trojan_udp_packet,
            read_trojan_udp_packet, trojan_password_hex,
        },
        vless::{VLESS_CMD_UDP, VlessOutbound, VlessOutboundConfig},
        ws_stream::{WsTransportConfig, accept_ws_stream, connect_ws_stream},
    },
    profile::{CreateProfileSpec, ProfileManager},
    router::Router,
    tracker::TelemetryHub,
};
use smoltcp::{
    iface::{Config as IfaceConfig, Interface, SocketSet},
    phy::{ChecksumCapabilities, Device, DeviceCapabilities, Medium, RxToken, TxToken},
    socket::tcp,
    time::Instant as SmolInstant,
    wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{mpsc, watch},
};
use tokio_rustls::TlsAcceptor;
use uuid::Uuid;

struct TempDirGuard(std::path::PathBuf);

impl TempDirGuard {
    fn new(prefix: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("{prefix}-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("create temp state dir");
        Self(dir)
    }

    fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
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

// ============================================================================
// 1. SOCKS5 UDP ASSOCIATE RFC 1928 Hardening & Control TCP EOF Supervision
// ============================================================================
#[tokio::test]
async fn repro_socks5_udp_rejects_spoofed_peer_rsv_frag_malformed_and_detects_ctrl_eof() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let srv_addr = listener.local_addr().unwrap();

    let relay_udp = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let relay_addr = relay_udp.local_addr().unwrap();
    let attacker_udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    let (drop_ctrl_tx, mut drop_ctrl_rx) = mpsc::channel::<()>(1);
    let relay_for_srv = relay_addr;
    tokio::spawn(async move {
        let (mut tcp, _) = listener.accept().await.unwrap();
        let ver = tcp.read_u8().await.unwrap();
        assert_eq!(ver, 0x05);
        let nmethods = tcp.read_u8().await.unwrap() as usize;
        let mut methods = vec![0u8; nmethods];
        tcp.read_exact(&mut methods).await.unwrap();
        tcp.write_all(&[0x05, 0x00]).await.unwrap();

        // Read UDP ASSOCIATE request: 0x05 0x03 0x00 + ATYP/ADDR/PORT
        let mut cmd_hdr = [0u8; 3];
        tcp.read_exact(&mut cmd_hdr).await.unwrap();
        assert_eq!(cmd_hdr[1], 0x03);
        let _dst = TargetAddr::read_socks5(&mut tcp).await.unwrap();

        let mut reply = BytesMut::with_capacity(16);
        reply.put_slice(&[0x05, 0x00, 0x00]);
        TargetAddr::from(relay_for_srv)
            .encode_socks5(&mut reply)
            .unwrap();
        tcp.write_all(&reply).await.unwrap();
        tcp.flush().await.unwrap();

        // Hold TCP control connection open until test signals EOF
        let _ = drop_ctrl_rx.recv().await;
        drop(tcp);
    });

    let outbound = Socks5Outbound::new(Socks5OutboundConfig {
        name: "socks5-hardened".into(),
        server: "127.0.0.1".into(),
        port: srv_addr.port(),
        username: None,
        password: None,
        tls: false,
        sni: None,
        skip_cert_verify: false,
        extra_ca_der: vec![],
        udp: true,
    })
    .unwrap();

    let sess = outbound.open_udp_session().await.unwrap();
    let target = TargetAddr::from(SocketAddr::from(([127, 0, 0, 1], 8080)));
    sess.send_to(b"hello-socks5-udp", &target).await.unwrap();

    let mut srv_buf = [0u8; 2048];
    let (n, client_udp_addr) =
        tokio::time::timeout(Duration::from_secs(2), relay_udp.recv_from(&mut srv_buf))
            .await
            .unwrap()
            .unwrap();
    assert!(n > 10);

    // (a) Spoofed source address packet (from `attacker_udp` != `relay_addr`)
    let mut spoof_pkt = vec![0x00, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x1f, 0x90];
    spoof_pkt.extend_from_slice(b"SPOOFED-PAYLOAD");
    attacker_udp
        .send_to(&spoof_pkt, client_udp_addr)
        .await
        .unwrap();

    // (b) Non-zero RSV bytes from legitimate relay
    let mut bad_rsv = vec![0x00, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x1f, 0x90];
    bad_rsv.extend_from_slice(b"BAD-RSV");
    relay_udp.send_to(&bad_rsv, client_udp_addr).await.unwrap();

    // (c) Fragmented SOCKS5 UDP frame (FRAG = 1) from legitimate relay
    let mut bad_frag = vec![0x00, 0x00, 0x01, 0x01, 127, 0, 0, 1, 0x1f, 0x90];
    bad_frag.extend_from_slice(b"BAD-FRAG");
    relay_udp.send_to(&bad_frag, client_udp_addr).await.unwrap();

    // (d) Malformed ATYP (0x99) from legitimate relay — must drop datagram without killing session!
    relay_udp
        .send_to(&[0x00, 0x00, 0x00, 0x99, 0xde, 0xad], client_udp_addr)
        .await
        .unwrap();

    // (e) Valid RFC 1928 reply from legitimate relay
    let mut valid_pkt = vec![0x00, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x1f, 0x90];
    valid_pkt.extend_from_slice(b"LEGITIMATE-REPLY");
    relay_udp
        .send_to(&valid_pkt, client_udp_addr)
        .await
        .unwrap();

    let (got_payload, got_src) = tokio::time::timeout(Duration::from_secs(2), sess.recv_from())
        .await
        .expect("recv_from timed out")
        .expect("recv_from failed");
    assert_eq!(got_payload, b"LEGITIMATE-REPLY");
    assert_eq!(got_src, target);

    // Now close the TCP control connection from the server side; `recv_from()` must unblock immediately!
    let _ = drop_ctrl_tx.send(()).await;
    let eof_res = tokio::time::timeout(Duration::from_secs(2), sess.recv_from())
        .await
        .expect("Socks5UdpSession::recv_from hung instead of detecting TCP control EOF!");
    assert!(
        eof_res.is_err(),
        "expected UnexpectedEof when SOCKS5 TCP control stream closes"
    );
}

// ============================================================================
// 2. Trojan UDP Remote Stream EOF Immediate Wakeup & UdpNatManager Recovery
// ============================================================================
#[tokio::test]
async fn repro_trojan_udp_remote_eof_unblocks_recv_from_and_rebuilds_nat() {
    let password = "trojan-eof-test-secret";
    let expected_hex = trojan_password_hex(password);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let srv_addr = listener.local_addr().unwrap();
    let accepted_conns = Arc::new(AtomicUsize::new(0));
    let accepted_clone = Arc::clone(&accepted_conns);

    tokio::spawn(async move {
        while let Ok((mut tcp, _)) = listener.accept().await {
            let conn_idx = accepted_clone.fetch_add(1, Ordering::SeqCst) + 1;
            tokio::spawn(async move {
                let mut hex = [0u8; 56];
                if tcp.read_exact(&mut hex).await.is_err() || hex != expected_hex {
                    return;
                }
                let mut crlf = [0u8; 2];
                let _ = tcp.read_exact(&mut crlf).await;
                let cmd = tcp.read_u8().await.unwrap_or(0);
                if cmd != TROJAN_CMD_UDP {
                    return;
                }
                let _ = TargetAddr::read_socks5(&mut tcp).await;
                let _ = tcp.read_exact(&mut crlf).await;

                // Reply to the first UDP datagram, then if conn_idx <= 2 close immediately!
                if let Ok((dgram, dst)) = read_trojan_udp_packet(&mut tcp).await {
                    let mut reply_payload = format!("TROJAN-CONN-{conn_idx}:").into_bytes();
                    reply_payload.extend_from_slice(&dgram);
                    let mut out = BytesMut::new();
                    encode_trojan_udp_packet(&dst, &reply_payload, &mut out).unwrap();
                    let _ = tcp.write_all(&out).await;
                    let _ = tcp.flush().await;
                }
                if conn_idx <= 2 {
                    let _ = tcp.shutdown().await;
                    return;
                }
                // Keep 3rd+ connection alive
                while let Ok((dgram, dst)) = read_trojan_udp_packet(&mut tcp).await {
                    let mut reply_payload = format!("TROJAN-CONN-{conn_idx}:").into_bytes();
                    reply_payload.extend_from_slice(&dgram);
                    let mut out = BytesMut::new();
                    encode_trojan_udp_packet(&dst, &reply_payload, &mut out).unwrap();
                    if tcp.write_all(&out).await.is_err() {
                        break;
                    }
                }
            });
        }
    });

    let trojan = Arc::new(
        TrojanOutbound::new(TrojanOutboundConfig {
            name: "trojan-udp-eof".into(),
            server: "127.0.0.1".into(),
            port: srv_addr.port(),
            password: password.into(),
            tls: false,
            sni: None,
            skip_cert_verify: false,
            alpn: vec![],
            extra_ca_der: vec![],
            ws_opts: None,
            udp: true,
        })
        .unwrap(),
    );
    let target = TargetAddr::from(SocketAddr::from(([127, 0, 0, 1], 5353)));

    // Part A: Direct `OutboundUdpSession::recv_from()` must unblock promptly on remote EOF (not 60s!)
    let sess = trojan.open_udp_session().await.unwrap();
    sess.send_to(b"one", &target).await.unwrap();
    let (r1, _) = tokio::time::timeout(Duration::from_secs(2), sess.recv_from())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(r1, b"TROJAN-CONN-1:one");

    let eof_res = tokio::time::timeout(Duration::from_secs(2), sess.recv_from())
        .await
        .expect("TrojanUdpSession::recv_from hung instead of unblocking on remote EOF!");
    assert!(eof_res.is_err());
    drop(sess);

    // Part B: `UdpNatManager` must tear down the closed session and transparently rebuild on next packet!
    let hub = Arc::new(TelemetryHub::new());
    let (reply_tx, mut reply_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let nat = UdpNatManager::new(
        "TestNat",
        16,
        Arc::clone(&hub),
        Arc::new(move |_cli, _src, data| {
            let _ = reply_tx.send(data);
        }),
    );
    let client_src: SocketAddr = "127.0.0.1:41000".parse().unwrap();
    let dyn_ob: DynOutbound = trojan;

    nat.send_datagram(
        client_src,
        target.clone(),
        None,
        target.clone(),
        "MATCH",
        "",
        vec!["trojan-udp-eof".into()],
        Arc::clone(&dyn_ob),
        b"nat-1".to_vec(),
    )
    .await;
    let nat_r1 = tokio::time::timeout(Duration::from_secs(2), reply_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(nat_r1, b"TROJAN-CONN-2:nat-1");

    // Wait until server connection #2 FIN propagates and UdpNatManager tears down the active NAT entry
    for _ in 0..100 {
        if hub.active_connection_count() == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    nat.send_datagram(
        client_src,
        target.clone(),
        None,
        target.clone(),
        "MATCH",
        "",
        vec!["trojan-udp-eof".into()],
        dyn_ob,
        b"nat-2".to_vec(),
    )
    .await;
    let nat_r2 = tokio::time::timeout(Duration::from_secs(2), reply_rx.recv())
        .await
        .expect("UdpNatManager failed to rebuild Trojan UDP session after remote EOF")
        .unwrap();
    assert_eq!(nat_r2, b"TROJAN-CONN-3:nat-2");
    assert!(accepted_conns.load(Ordering::SeqCst) >= 3);
}

// ============================================================================
// 3. VLESS XUDP Remote Stream EOF Immediate Wakeup & Auto-Reconnect
// ============================================================================
#[tokio::test]
async fn repro_vless_udp_remote_eof_unblocks_recv_from() {
    let uuid = Uuid::new_v4();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let srv_addr = listener.local_addr().unwrap();
    let accepted = Arc::new(AtomicUsize::new(0));
    let accepted_clone = Arc::clone(&accepted);

    tokio::spawn(async move {
        while let Ok((mut tcp, _)) = listener.accept().await {
            let conn_no = accepted_clone.fetch_add(1, Ordering::SeqCst) + 1;
            let expected_uuid = uuid;
            tokio::spawn(async move {
                let ver = tcp.read_u8().await.unwrap_or(0xff);
                if ver != 0x00 {
                    return;
                }
                let mut uid = [0u8; 16];
                if tcp.read_exact(&mut uid).await.is_err() || uid != *expected_uuid.as_bytes() {
                    return;
                }
                let addons_len = tcp.read_u8().await.unwrap_or(0) as usize;
                if addons_len > 0 {
                    let mut skip = vec![0u8; addons_len];
                    let _ = tcp.read_exact(&mut skip).await;
                }
                let cmd = tcp.read_u8().await.unwrap_or(0);
                assert_eq!(cmd, VLESS_CMD_UDP);
                let _dst = TargetAddr::read_vless(&mut tcp).await.unwrap();

                // Read 1st VLESS UDP frame: [u16 len][payload]
                let payload_len = tcp.read_u16().await.unwrap() as usize;
                let mut payload = vec![0u8; payload_len];
                tcp.read_exact(&mut payload).await.unwrap();

                let mut resp_payload = format!("VLESS-UDP-{conn_no}:").into_bytes();
                resp_payload.extend_from_slice(&payload);

                let mut out = BytesMut::new();
                out.put_slice(&[0x00, 0x00]); // VLESS response header
                out.put_u16(resp_payload.len() as u16);
                out.put_slice(&resp_payload);
                tcp.write_all(&out).await.unwrap();
                tcp.flush().await.unwrap();

                // Close connection #1 right after first datagram!
                if conn_no == 1 {
                    let _ = tcp.shutdown().await;
                } else {
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
            });
        }
    });

    let vless = VlessOutbound::new(VlessOutboundConfig {
        name: "vless-udp-eof".into(),
        server: "127.0.0.1".into(),
        port: srv_addr.port(),
        uuid,
        encryption: "none".into(),
        tls: false,
        servername: None,
        skip_cert_verify: false,
        alpn: vec![],
        extra_ca_der: vec![],
        udp: true,
    })
    .unwrap();

    let target = TargetAddr::from(SocketAddr::from(([127, 0, 0, 1], 9999)));
    let sess = vless.open_udp_session().await.unwrap();
    sess.send_to(b"pkt-1", &target).await.unwrap();
    let (r1, _) = tokio::time::timeout(Duration::from_secs(2), sess.recv_from())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(r1, b"VLESS-UDP-1:pkt-1");

    // Must immediately return EOF error rather than hanging 60s!
    let eof_res = tokio::time::timeout(Duration::from_secs(2), sess.recv_from())
        .await
        .expect("VlessUdpSession::recv_from hung instead of unblocking on remote EOF!");
    assert!(eof_res.is_err());

    // Subsequent send_to on the same VlessUdpSession transparently opens stream #2!
    sess.send_to(b"pkt-2", &target).await.unwrap();
    let (r2, _) = tokio::time::timeout(Duration::from_secs(2), sess.recv_from())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(r2, b"VLESS-UDP-2:pkt-2");
    assert_eq!(accepted.load(Ordering::SeqCst), 2);
}

// ============================================================================
// 4. WebSocket 0-RTT Early-Data Large Coalesced Write, Backpressure & Error State
// ============================================================================
#[tokio::test]
async fn repro_ws_early_data_large_coalesced_write_backpressure_handshake_err_and_clean_close() {
    // Part A: Coalesced 256 KiB single `write_all` over `?ed=2048` (exceeding 2048-byte early-data header)
    let ws_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ws_addr = ws_listener.local_addr().unwrap();

    let server_task = tokio::spawn(async move {
        let (tcp, _) = ws_listener.accept().await.unwrap();
        let mut ws_stream = accept_ws_stream(Box::new(tcp), Some("/ws")).await.unwrap();
        let mut received = Vec::with_capacity(256 * 1024);
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            let n = ws_stream.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            received.extend_from_slice(&buf[..n]);
            if received.len() == 256 * 1024 {
                ws_stream.write_all(b"WS-256KB-ACK").await.unwrap();
                ws_stream.flush().await.unwrap();
            }
        }
        received
    });

    let tcp_cli: BoxedStream = Box::new(TcpStream::connect(ws_addr).await.unwrap());
    let ws_cfg = WsTransportConfig {
        path: "/ws?ed=2048".into(),
        headers: HashMap::new(),
        max_early_data: None,
        early_data_header_name: None,
    };
    let mut cli_ws = connect_ws_stream(tcp_cli, "127.0.0.1", ws_addr.port(), false, &ws_cfg)
        .await
        .unwrap();

    let big_payload: Vec<u8> = (0..(256 * 1024))
        .map(|i| ((i * 73 + 19) & 0xFF) as u8)
        .collect();
    cli_ws.write_all(&big_payload).await.unwrap();
    // Deliberately read BEFORE explicit flush() to verify opportunistic flush prevents deadlock!
    let mut ack = [0u8; 12];
    cli_ws.read_exact(&mut ack).await.unwrap();
    assert_eq!(&ack, b"WS-256KB-ACK");
    cli_ws.shutdown().await.unwrap();

    let server_received = tokio::time::timeout(Duration::from_secs(3), server_task)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(server_received, big_payload);

    // Part B: Failed HTTP Upgrade (403 Forbidden) transitions to `LazyEarlyDataState::Failed`
    // and NEVER panics when polled again for write / read / flush / shutdown!
    let reject_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let reject_addr = reject_listener.local_addr().unwrap();
    tokio::spawn(async move {
        if let Ok((mut s, _)) = reject_listener.accept().await {
            let mut req_buf = [0u8; 2048];
            let _ = s.read(&mut req_buf).await;
            let _ = s
                .write_all(
                    b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await;
            let _ = s.shutdown().await;
        }
    });

    let tcp_bad: BoxedStream = Box::new(TcpStream::connect(reject_addr).await.unwrap());
    let mut bad_ws = connect_ws_stream(tcp_bad, "127.0.0.1", reject_addr.port(), false, &ws_cfg)
        .await
        .unwrap();

    // First write consumes <= 2048 into early-data handshake; flush/read observes 403 error
    let _ = bad_ws.write_all(b"early-payload-trigger").await;
    assert!(bad_ws.flush().await.is_err());
    // Subsequent calls MUST return clean `io::Error` without panicking on a completed handshake Future!
    assert!(bad_ws.write(b"retry-after-fail").await.is_err());
    let mut tmp = [0u8; 16];
    assert!(bad_ws.read(&mut tmp).await.is_err());
    assert!(bad_ws.flush().await.is_err());
    assert!(bad_ws.shutdown().await.is_ok());

    // Part C: `tokio::io::split(LazyWsEarlyDataStream)` across two concurrent spawned tasks
    // (as used by `TrojanUdpSession` / `VlessUdpSession`) never steals wakers during `Handshaking`!
    let split_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let split_addr = split_listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (tcp, _) = split_listener.accept().await.unwrap();
        // Delay 30ms before completing WS upgrade so both client read & write tasks contend on `Handshaking`
        tokio::time::sleep(Duration::from_millis(30)).await;
        let mut ws_srv = accept_ws_stream(Box::new(tcp), Some("/ws")).await.unwrap();
        let mut req = [0u8; 10];
        ws_srv.read_exact(&mut req).await.unwrap();
        assert_eq!(&req, b"SPLIT-PING");
        ws_srv.write_all(b"SPLIT-PONG").await.unwrap();
        ws_srv.flush().await.unwrap();
    });

    let tcp_split: BoxedStream = Box::new(TcpStream::connect(split_addr).await.unwrap());
    let split_ws = connect_ws_stream(tcp_split, "127.0.0.1", split_addr.port(), false, &ws_cfg)
        .await
        .unwrap();
    let (mut rd_half, mut wr_half) = tokio::io::split(split_ws);
    let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();
    let wr_task = tokio::spawn(async move {
        wr_half.write_all(b"SPLIT-PING").await.unwrap();
        wr_half.flush().await.unwrap();
        // Keep wr_half parked until rd_task completes, just like UDP writer_handle waiting on mpsc!
        let _ = done_rx.await;
    });
    let rd_task = tokio::spawn(async move {
        let mut out = [0u8; 10];
        rd_half.read_exact(&mut out).await.unwrap();
        out
    });
    let pong = tokio::time::timeout(Duration::from_secs(2), rd_task)
        .await
        .expect("split reader task deadlocked due to waker stealing!")
        .unwrap();
    assert_eq!(&pong, b"SPLIT-PONG");
    let _ = done_tx.send(());
    let _ = wr_task.await;
}

// ============================================================================
// 5. GEOIP / IP-CIDR Rule Resolution Never Leaks to `direct-nameserver`
// ============================================================================
#[tokio::test]
async fn regression_geoip_rule_without_no_resolve_never_queries_direct_nameserver_or_poisons_direct()
 {
    let direct_dns_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let direct_dns_addr = direct_dns_sock.local_addr().unwrap();
    let direct_hits = Arc::new(AtomicUsize::new(0));
    let direct_hits_srv = Arc::clone(&direct_hits);

    // Poisoning mock domestic DNS: answers EVERY query with CN IP `223.5.5.5`!
    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        while let Ok((n, peer)) = direct_dns_sock.recv_from(&mut buf).await {
            direct_hits_srv.fetch_add(1, Ordering::SeqCst);
            if let Ok(q) = DnsQueryPacket::parse(&buf[..n]) {
                let ans = if q.question.qtype == QTYPE_A {
                    vec![DnsAnswerData::A(Ipv4Addr::new(223, 5, 5, 5))]
                } else {
                    vec![]
                };
                let resp = q.build_response(&buf[..n], 0, 60, &ans);
                let _ = direct_dns_sock.send_to(&resp, peer).await;
            }
        }
    });

    let trusted_dns_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let trusted_dns_addr = trusted_dns_sock.local_addr().unwrap();
    let trusted_hits = Arc::new(AtomicUsize::new(0));
    let trusted_hits_srv = Arc::clone(&trusted_hits);

    // Trusted upstream DNS: returns US IP `8.8.8.8` for foreign host, CN IP `223.5.5.5` for CN host
    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        while let Ok((n, peer)) = trusted_dns_sock.recv_from(&mut buf).await {
            trusted_hits_srv.fetch_add(1, Ordering::SeqCst);
            if let Ok(q) = DnsQueryPacket::parse(&buf[..n]) {
                let ip = if q.question.name.contains("cn-portal") {
                    Ipv4Addr::new(223, 5, 5, 5)
                } else {
                    Ipv4Addr::new(8, 8, 8, 8)
                };
                let ans = if q.question.qtype == QTYPE_A {
                    vec![DnsAnswerData::A(ip)]
                } else {
                    vec![]
                };
                let resp = q.build_response(&buf[..n], 0, 60, &ans);
                let _ = trusted_dns_sock.send_to(&resp, peer).await;
            }
        }
    });

    let dns_cfg = DnsConfig {
        enable: true,
        ipv6: false,
        enhanced_mode: "fake-ip".into(),
        nameserver: vec![trusted_dns_addr.to_string()],
        direct_nameserver: vec![direct_dns_addr.to_string()],
        default_nameserver: vec![trusted_dns_addr.to_string()],
        ..DnsConfig::default()
    };
    let dns = Arc::new(FakeIpDnsEngine::new(&dns_cfg).unwrap());

    let proxy_ob: DynOutbound = Arc::new(
        Socks5Outbound::new(Socks5OutboundConfig {
            name: "PROXY-NODE".into(),
            server: "127.0.0.1".into(),
            port: 1080,
            username: None,
            password: None,
            tls: false,
            sni: None,
            skip_cert_verify: false,
            extra_ca_der: vec![],
            udp: true,
        })
        .unwrap(),
    );
    let mut outbounds = HashMap::new();
    outbounds.insert("PROXY-NODE".to_string(), proxy_ob);

    // Note: `GEOIP,CN,DIRECT` WITHOUT `no-resolve`!
    let rules = vec![
        "GEOIP,CN,DIRECT".to_string(),
        "MATCH,PROXY-NODE".to_string(),
    ];
    let router = Router::new(RunMode::Rule, outbounds, &[], &rules, dns).unwrap();

    let foreign_target = TargetAddr::new_domain("foreign-service.example.org", 443).unwrap();
    let dec_foreign = router.route_async(None, &foreign_target).await;
    assert_eq!(
        direct_hits.load(Ordering::SeqCst),
        0,
        "GEOIP rule must NEVER leak foreign domains to plaintext direct-nameserver"
    );
    assert!(trusted_hits.load(Ordering::SeqCst) >= 1);
    assert_eq!(
        dec_foreign.outbound.name(),
        "PROXY-NODE",
        "foreign domain must NOT be poisoned into DIRECT"
    );

    let cn_target = TargetAddr::new_domain("cn-portal.example.org", 443).unwrap();
    let dec_cn = router.route_async(None, &cn_target).await;
    assert_eq!(direct_hits.load(Ordering::SeqCst), 0);
    assert_eq!(dec_cn.outbound.name(), "DIRECT");
}

// ============================================================================
// 6. Switching Select Group Closes Stale Proxy Streams While Keeping DIRECT Alive
// ============================================================================
#[tokio::test]
async fn regression_select_group_closes_stale_proxy_connections_while_keeping_direct_alive() {
    let (stop_tx, stop_rx) = watch::channel(false);

    // Persistent interactive echo server
    let origin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_addr = origin_listener.local_addr().unwrap();
    let mut origin_stop = stop_rx.clone();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = origin_stop.changed() => break,
                accepted = origin_listener.accept() => {
                    let Ok((mut s, _)) = accepted else { continue };
                    tokio::spawn(async move {
                        let mut buf = [0u8; 1024];
                        while let Ok(n) = s.read(&mut buf).await {
                            if n == 0 || s.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    });
                }
            }
        }
    });

    let psk_a = STANDARD.encode([0x11u8; 32]);
    let psk_b = STANDARD.encode([0x22u8; 32]);
    let (ss_a_addr, _t_a) = spawn_ss_server(
        "127.0.0.1:0",
        "2022-blake3-aes-256-gcm",
        &psk_a,
        stop_rx.clone(),
    )
    .await
    .unwrap();
    let (ss_b_addr, _t_b) = spawn_ss_server(
        "127.0.0.1:0",
        "2022-blake3-aes-256-gcm",
        &psk_b,
        stop_rx.clone(),
    )
    .await
    .unwrap();

    let yaml = format!(
        r#"
mixed-port: 0
mode: rule
log-level: info
dns:
  enable: false
proxies:
  - name: "Node-A"
    type: ss
    server: "127.0.0.1"
    port: {port_a}
    cipher: "2022-blake3-aes-256-gcm"
    password: "{psk_a}"
  - name: "Node-B"
    type: ss
    server: "127.0.0.1"
    port: {port_b}
    cipher: "2022-blake3-aes-256-gcm"
    password: "{psk_b}"
proxy-groups:
  - name: "PROXY"
    type: select
    proxies: ["Node-A", "Node-B", "DIRECT"]
rules:
  - DOMAIN,localhost,DIRECT
  - MATCH,PROXY
"#,
        port_a = ss_a_addr.port(),
        port_b = ss_b_addr.port(),
    );

    let tmp = TempDirGuard::new("group-migrate-test");
    let cfg = ClashConfig::from_yaml_str(&yaml).unwrap();
    let engine = ProxyEngine::start_with_state_dir(cfg, tmp.path().to_path_buf())
        .await
        .unwrap();
    let mixed_port = engine.mixed_addr().port();

    // Open long-lived proxy connection (`127.0.0.1:<origin_port>` -> `MATCH,PROXY` -> `Node-A`)
    let mut proxy_conn = TcpStream::connect(("127.0.0.1", mixed_port)).await.unwrap();
    let connect_proxy = format!(
        "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
        origin_addr.port(),
        origin_addr.port()
    );
    proxy_conn
        .write_all(connect_proxy.as_bytes())
        .await
        .unwrap();
    let mut resp_buf = [0u8; 128];
    let n = proxy_conn.read(&mut resp_buf).await.unwrap();
    assert!(std::str::from_utf8(&resp_buf[..n]).unwrap().contains("200"));
    proxy_conn.write_all(b"via-node-a").await.unwrap();
    let mut echo_a = [0u8; 10];
    proxy_conn.read_exact(&mut echo_a).await.unwrap();
    assert_eq!(&echo_a, b"via-node-a");

    // Open long-lived DIRECT connection (`localhost:<origin_port>` -> `DOMAIN,localhost,DIRECT`)
    let mut direct_conn = TcpStream::connect(("127.0.0.1", mixed_port)).await.unwrap();
    let connect_direct = format!(
        "CONNECT localhost:{} HTTP/1.1\r\nHost: localhost:{}\r\n\r\n",
        origin_addr.port(),
        origin_addr.port()
    );
    direct_conn
        .write_all(connect_direct.as_bytes())
        .await
        .unwrap();
    let n2 = direct_conn.read(&mut resp_buf).await.unwrap();
    assert!(
        std::str::from_utf8(&resp_buf[..n2])
            .unwrap()
            .contains("200")
    );
    direct_conn.write_all(b"via-direct-1").await.unwrap();
    let mut echo_d1 = [0u8; 12];
    direct_conn.read_exact(&mut echo_d1).await.unwrap();
    assert_eq!(&echo_d1, b"via-direct-1");

    assert_eq!(engine.hub().active_connection_count(), 2);

    // Switch `PROXY` from `Node-A` -> `Node-B`
    engine.select_group_and_persist("PROXY", "Node-B").unwrap();

    // Stale `Node-A` connection MUST close promptly (< 500ms)!
    let mut closed_probe = [0u8; 16];
    let stale_read = tokio::time::timeout(
        Duration::from_millis(500),
        proxy_conn.read(&mut closed_probe),
    )
    .await
    .expect("stale proxy connection was NOT closed after group switch!");
    assert!(
        matches!(stale_read, Ok(0) | Err(_)),
        "expected EOF/reset on stale Node-A stream, got {stale_read:?}"
    );

    // Meanwhile, `DIRECT` connection MUST remain completely alive!
    direct_conn.write_all(b"via-direct-2").await.unwrap();
    let mut echo_d2 = [0u8; 12];
    direct_conn.read_exact(&mut echo_d2).await.unwrap();
    assert_eq!(&echo_d2, b"via-direct-2");

    engine.shutdown();
    let _ = stop_tx.send(true);
}

// ============================================================================
// 7. Subscription Refresh Fails Closed on Empty or Unsupported-Only Payloads
// ============================================================================
#[tokio::test]
async fn regression_subscription_refresh_empty_or_unsupported_only_preserves_working_profile() {
    let (tls_cfg, ca_der) =
        generate_self_signed_server_config(&["127.0.0.1".into(), "localhost".into()], &[]).unwrap();
    let acceptor = TlsAcceptor::from(tls_cfg);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let srv_addr = listener.local_addr().unwrap();

    let psk = STANDARD.encode([0x55u8; 32]);
    let good_yaml = format!(
        r#"
proxies:
  - name: "HK-Working"
    type: ss
    server: "127.0.0.1"
    port: 8388
    cipher: "2022-blake3-aes-256-gcm"
    password: "{psk}"
  - name: "SG-Working"
    type: socks5
    server: "127.0.0.1"
    port: 1080
proxy-groups:
  - name: "PROXY"
    type: select
    proxies: ["HK-Working", "SG-Working", "DIRECT"]
rules:
  - MATCH,PROXY
"#
    );
    let empty_yaml = "proxies: []\nproxy-groups:\n  - name: PROXY\n    type: select\n    proxies: [DIRECT]\nrules:\n  - MATCH,DIRECT\n".to_string();
    let unsupported_only_yaml = r#"
proxies:
  - name: "Only-Unsupported-1"
    type: tuic
    server: "1.2.3.4"
    port: 443
  - name: "Only-Unsupported-2"
    type: wireguard
    server: "1.2.3.5"
    port: 51820
rules:
  - MATCH,DIRECT
"#
    .to_string();

    let served_body = Arc::new(RwLock::new(good_yaml));
    let body_for_srv = Arc::clone(&served_body);
    let (stop_tx, mut stop_rx) = watch::channel(false);

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = stop_rx.changed() => break,
                accepted = listener.accept() => {
                    let Ok((tcp, _)) = accepted else { continue };
                    let acc = acceptor.clone();
                    let body = body_for_srv.read().clone();
                    tokio::spawn(async move {
                        let Ok(mut tls) = acc.accept(tcp).await else { return };
                        let mut req = [0u8; 2048];
                        let _ = tls.read(&mut req).await;
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: text/yaml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        let _ = tls.write_all(resp.as_bytes()).await;
                        let _ = tls.shutdown().await;
                    });
                }
            }
        }
    });

    let tmp = TempDirGuard::new("sub-empty-guard");
    let mgr = ProfileManager::open_or_init_with_ca(tmp.path(), vec![ca_der]).unwrap();
    let sub_url = format!("https://127.0.0.1:{}/sub", srv_addr.port());

    let (meta, _, _) = mgr
        .create_profile_detailed(CreateProfileSpec {
            name: "ProdSub".into(),
            subscription_url: Some(sub_url),
            uris: None,
            yaml: None,
            auto_update_interval_secs: Some(3600),
            activate: true,
        })
        .await
        .unwrap();
    assert_eq!(meta.proxy_count, 2);
    mgr.save_group_selection("PROXY", "SG-Working").unwrap();

    // Case 1: Upstream temporarily returns `proxies: []` -> must fail closed and preserve working config!
    *served_body.write() = empty_yaml;
    let err_empty = mgr.refresh_subscription(&meta.id).await;
    assert!(
        err_empty.is_err(),
        "refresh_subscription must reject 0-node Clash YAML"
    );
    let (preserved_1, _) = mgr.load_active_config().unwrap();
    assert_eq!(preserved_1.proxies.len(), 2);
    assert_eq!(
        mgr.active_selected_groups()
            .get("PROXY")
            .map(String::as_str),
        Some("SG-Working")
    );

    // Case 2: Upstream returns ONLY unsupported protocols -> sanitized down to 0 valid nodes -> must fail closed!
    *served_body.write() = unsupported_only_yaml;
    let err_unsup = mgr.refresh_subscription(&meta.id).await;
    assert!(
        err_unsup.is_err(),
        "refresh_subscription must reject unsupported-only Clash YAML"
    );
    let (preserved_2, _) = mgr.load_active_config().unwrap();
    assert_eq!(preserved_2.proxies.len(), 2);
    assert_eq!(preserved_2.proxies[0].name(), "HK-Working");

    let _ = stop_tx.send(true);
}

// ============================================================================
// 8. Virtual TUN TCP Port 53 (DNS-over-TCP) Hijack Prevents UNMAPPED-FAKE-IP
// ============================================================================
#[tokio::test]
async fn regression_virtual_tun_tcp_port_53_dns_hijack_prevents_fake_ip_expired_reject() {
    let (stop_tx, stop_rx) = watch::channel(false);
    let dns_engine = Arc::new(FakeIpDnsEngine::new(&DnsConfig::default()).unwrap());
    let rules = vec!["MATCH,DIRECT".to_string()];
    let router = Arc::new(
        Router::new(
            RunMode::Rule,
            HashMap::new(),
            &[],
            &rules,
            Arc::clone(&dns_engine),
        )
        .unwrap(),
    );
    let router_slot = Arc::new(RwLock::new(Arc::clone(&router)));
    let hub = Arc::new(TelemetryHub::new());

    let (mut vtun, _tun_task) = spawn_userspace_tun(1500, router_slot, hub, stop_rx);

    let mut guest_dev = GuestDevice {
        rx: VecDeque::new(),
        tx: VecDeque::new(),
    };
    let mut cfg = IfaceConfig::new(HardwareAddress::Ip);
    cfg.random_seed = 0x9988_7766;
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

    // Connect TCP to Android VPN virtual DNS `198.18.0.2:53` (an UNMAPPED Fake-IP inside `198.18.0.0/15`!)
    {
        let sock = guest_sockets.get_mut::<tcp::Socket>(guest_handle);
        sock.connect(
            guest_iface.context(),
            IpEndpoint::new(IpAddress::Ipv4(Ipv4Addr::new(198, 18, 0, 2)), 53),
            51234,
        )
        .unwrap();
    }

    // Build two pipelined RFC 1035/7766 length-prefixed DNS queries in a single TCP stream
    let q1 = build_dns_query(0x1111, "tcp-dns-one.example.com", QTYPE_A);
    let q2 = build_dns_query(0x2222, "tcp-dns-two.example.com", QTYPE_A);
    let mut tcp_dns_payload = Vec::with_capacity(4 + q1.len() + q2.len());
    tcp_dns_payload.extend_from_slice(&(q1.len() as u16).to_be_bytes());
    tcp_dns_payload.extend_from_slice(&q1);
    tcp_dns_payload.extend_from_slice(&(q2.len() as u16).to_be_bytes());
    tcp_dns_payload.extend_from_slice(&q2);

    let mut sent = false;
    let mut rx_stream = Vec::new();
    let mut parsed_ips = Vec::new();

    let deadline = tokio::time::Instant::now() + Duration::from_secs(4);
    while tokio::time::Instant::now() < deadline {
        let _ = guest_iface.poll(now_smol(), &mut guest_dev, &mut guest_sockets);
        while let Some(out_pkt) = guest_dev.tx.pop_front() {
            vtun.ingress_tx.send(out_pkt).await.unwrap();
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
        while let Ok(in_pkt) = vtun.egress_rx.try_recv() {
            guest_dev.rx.push_back(in_pkt);
        }
        let _ = guest_iface.poll(now_smol(), &mut guest_dev, &mut guest_sockets);

        let sock = guest_sockets.get_mut::<tcp::Socket>(guest_handle);
        if sock.can_send() && !sent {
            sock.send_slice(&tcp_dns_payload).unwrap();
            sent = true;
        }
        if sock.can_recv() {
            let _ = sock.recv(|data| {
                rx_stream.extend_from_slice(data);
                (data.len(), ())
            });
            while rx_stream.len() >= 2 {
                let rlen = u16::from_be_bytes([rx_stream[0], rx_stream[1]]) as usize;
                if rx_stream.len() < 2 + rlen {
                    break;
                }
                let msg = rx_stream[2..2 + rlen].to_vec();
                rx_stream.drain(..2 + rlen);
                let answers = extract_ip_answers(&msg).unwrap();
                if let Some(DnsAnswerData::A(v4)) = answers.first() {
                    parsed_ips.push(*v4);
                }
            }
            if parsed_ips.len() == 2 {
                break;
            }
        }
    }

    assert_eq!(
        parsed_ips.len(),
        2,
        "expected 2 pipelined DNS-over-TCP Fake-IP answers from 198.18.0.2:53"
    );
    let dec = router
        .route_async(
            None,
            &TargetAddr::from(SocketAddr::from((parsed_ips[0], 443))),
        )
        .await;
    assert_eq!(dec.target.host.to_string(), "tcp-dns-one.example.com");
    assert_ne!(dec.outbound.name(), "UNMAPPED-FAKE-IP");

    let _ = stop_tx.send(true);
}

// ============================================================================
// 9. Low-Power Mode Parks Background Timers at 0 Hz Without Dropping Traffic
// ============================================================================
#[tokio::test]
async fn regression_low_power_mode_parks_timers_without_interrupting_push_or_downloads() {
    let (stop_tx, mut stop_rx) = watch::channel(false);
    let push_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let push_addr = push_listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = stop_rx.changed() => break,
                accepted = push_listener.accept() => {
                    let Ok((mut s, _)) = accepted else { continue };
                    tokio::spawn(async move {
                        let mut buf = [0u8; 4096];
                        while let Ok(n) = s.read(&mut buf).await {
                            if n == 0 || s.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    });
                }
            }
        }
    });

    let cfg = ClashConfig {
        mixed_port: 0,
        dns: DnsConfig {
            enable: false,
            ..Default::default()
        },
        mode: RunMode::Direct,
        proxy_groups: vec![ProxyGroupConfig {
            name: "AUTO".into(),
            group_type: ProxyGroupType::UrlTest,
            proxies: vec!["DIRECT".into()],
            url: "http://127.0.0.1:1/generate_204".into(),
            interval: 60,
            tolerance: 50,
            strategy: None,
        }],
        ..Default::default()
    };

    let tmp = TempDirGuard::new("low-power-0hz");
    let engine = ProxyEngine::start_with_state_dir(cfg, tmp.path().to_path_buf())
        .await
        .unwrap();
    let mixed_port = engine.mixed_addr().port();

    // 1. Open active push/download stream BEFORE entering low-power mode
    let mut stream = TcpStream::connect(("127.0.0.1", mixed_port)).await.unwrap();
    let connect_req = format!(
        "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
        push_addr.port(),
        push_addr.port()
    );
    stream.write_all(connect_req.as_bytes()).await.unwrap();
    let mut hdr = [0u8; 128];
    let n = stream.read(&mut hdr).await.unwrap();
    assert!(std::str::from_utf8(&hdr[..n]).unwrap().contains("200"));

    // Enable low-power mode (Android screen-off); active push/download MUST NOT be interrupted!
    engine.set_low_power_mode(true);
    assert!(engine.is_low_power_mode());

    stream.write_all(b"screen-off-push-frame").await.unwrap();
    let mut echoed = [0u8; 21];
    stream.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"screen-off-push-frame");

    // 2. Close active connection so active_connection_count() == 0, wait until unsampled traffic
    //    and the zero-delta sample flush into `is_telemetry_parked() == true`, then verify true `0 Hz`!
    drop(stream);
    for _ in 0..150 {
        if engine.hub().active_connection_count() == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(engine.hub().active_connection_count(), 0);

    for _ in 0..250 {
        if engine.hub().is_telemetry_parked() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        engine.hub().is_telemetry_parked(),
        "telemetry sampler must enter parked 0 Hz state once idle in low_power_mode"
    );

    let parked_ticks = engine.hub().sample_tick_count();
    tokio::time::sleep(Duration::from_millis(1250)).await;
    assert_eq!(
        engine.hub().sample_tick_count(),
        parked_ticks,
        "expected 0 telemetry wakeups (true 0 Hz) while idle in low_power_mode"
    );
    assert!(engine.hub().is_telemetry_parked());

    // 3. Exiting low-power mode (screen-on) immediately wakes the sampler and resumes ticks!
    engine.set_low_power_mode(false);
    for _ in 0..200 {
        if engine.hub().sample_tick_count() > parked_ticks {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        engine.hub().sample_tick_count() > parked_ticks,
        "expected telemetry sampler to wake immediately upon exiting low_power_mode"
    );

    engine.shutdown();
    let _ = stop_tx.send(true);
}

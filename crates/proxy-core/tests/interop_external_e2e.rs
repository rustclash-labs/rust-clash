use std::{
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    path::{Path, PathBuf},
    process::Stdio,
    sync::Arc,
    time::Duration,
};

use base64::{Engine, engine::general_purpose::STANDARD};
use proxy_core::{
    addr::TargetAddr,
    crypto::tls::generate_self_signed_server_config,
    outbound::{
        OutboundHandler,
        anytls::{
            AnyTlsOutbound, AnyTlsOutboundConfig, AnyTlsServerConfig, padding::PaddingScheme,
            spawn_anytls_server,
        },
        http_proxy::{
            HttpConnectServerConfig, HttpOutbound, HttpOutboundConfig, spawn_http_connect_server,
        },
        socks5::{Socks5Outbound, Socks5OutboundConfig, Socks5ServerConfig, spawn_socks5_server},
        ss::{ShadowsocksOutbound, spawn_ss_server},
        trojan::{TrojanOutbound, TrojanOutboundConfig, TrojanServerConfig, spawn_trojan_server},
        vless::{
            VlessOutbound, VlessOutboundConfig, VlessServerConfig,
            encryption::{config::XorMode, generate_vless_encryption_pair},
            spawn_vless_server, spawn_vless_ws_server,
        },
        ws_stream::WsTransportConfig,
    },
};
use serde_json::json;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    process::{Child, Command},
    sync::watch,
};
use uuid::Uuid;

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.start_kill();
    }
}

struct TempDirGuard(PathBuf);

impl TempDirGuard {
    fn new(prefix: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("{prefix}-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        Self(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn interop_bin_dir() -> PathBuf {
    std::env::var("RUST_CLASH_INTEROP_BIN_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/tmp/interop-bins"))
}

fn require_external_interop() -> bool {
    std::env::var("RUST_CLASH_REQUIRE_EXTERNAL_INTEROP")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

fn resolve_bin(rel: &str) -> Option<PathBuf> {
    let candidate = interop_bin_dir().join(rel);
    if candidate.is_file() {
        return Some(candidate);
    }
    if require_external_interop() {
        panic!(
            "Required external interop binary missing at {} (RUST_CLASH_REQUIRE_EXTERNAL_INTEROP=1)",
            candidate.display()
        );
    }
    eprintln!(
        "Skipping external interop test because reference binary is absent at {}",
        candidate.display()
    );
    None
}

fn reserve_free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

fn clean_loopback_command(bin: &Path) -> Command {
    let mut cmd = Command::new(bin);
    cmd.kill_on_drop(true)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_remove("HTTP_PROXY")
        .env_remove("HTTPS_PROXY")
        .env_remove("ALL_PROXY")
        .env_remove("http_proxy")
        .env_remove("https_proxy")
        .env_remove("all_proxy")
        .env("NO_PROXY", "127.0.0.1,localhost");
    cmd
}

async fn wait_tcp_ready(port: u16, guard: &mut ChildGuard, label: &str) {
    let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port));
    for _ in 0..80 {
        if let Ok(Some(status)) = guard.0.try_wait() {
            let mut out = String::new();
            let mut err = String::new();
            if let Some(mut s) = guard.0.stdout.take() {
                let _ = s.read_to_string(&mut out).await;
            }
            if let Some(mut s) = guard.0.stderr.take() {
                let _ = s.read_to_string(&mut err).await;
            }
            panic!("{label} exited prematurely with {status}.\nstdout:\n{out}\nstderr:\n{err}");
        }
        if TcpStream::connect(addr).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("{label} failed to listen on 127.0.0.1:{port} within 4s");
}

async fn spawn_echo_servers(mut shutdown: watch::Receiver<bool>) -> (SocketAddr, SocketAddr) {
    let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tcp_addr = tcp_listener.local_addr().unwrap();
    let mut tcp_stop = shutdown.clone();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = tcp_stop.changed() => break,
                res = tcp_listener.accept() => {
                    let Ok((mut sock, _)) = res else { continue };
                    tokio::spawn(async move {
                        let mut buf = vec![0u8; 32 * 1024];
                        while let Ok(n) = sock.read(&mut buf).await {
                            if n == 0 || sock.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    });
                }
            }
        }
    });

    let udp_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let udp_addr = udp_sock.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            tokio::select! {
                _ = shutdown.changed() => break,
                res = udp_sock.recv_from(&mut buf) => {
                    let Ok((n, peer)) = res else { continue };
                    let mut reply = b"EXT-UDP-ECHO:".to_vec();
                    reply.extend_from_slice(&buf[..n]);
                    let _ = udp_sock.send_to(&reply, peer).await;
                }
            }
        }
    });

    (tcp_addr, udp_addr)
}

async fn socks5_tcp_roundtrip(socks_port: u16, target: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut s = TcpStream::connect(("127.0.0.1", socks_port))
        .await
        .expect("connect local SOCKS5");
    s.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut method_reply = [0u8; 2];
    s.read_exact(&mut method_reply).await.unwrap();
    assert_eq!(method_reply, [0x05, 0x00]);

    let SocketAddr::V4(v4) = target else {
        panic!("expected IPv4 echo target");
    };
    let mut req = Vec::with_capacity(10);
    req.extend_from_slice(&[0x05, 0x01, 0x00, 0x01]);
    req.extend_from_slice(&v4.ip().octets());
    req.extend_from_slice(&v4.port().to_be_bytes());
    s.write_all(&req).await.unwrap();

    let mut hdr = [0u8; 4];
    s.read_exact(&mut hdr).await.unwrap();
    assert_eq!(hdr[0], 0x05);
    assert_eq!(
        hdr[1], 0x00,
        "SOCKS5 CONNECT failed with reply 0x{:02x}",
        hdr[1]
    );
    let tail_len = match hdr[3] {
        0x01 => 4 + 2,
        0x04 => 16 + 2,
        0x03 => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l).await.unwrap();
            l[0] as usize + 2
        }
        other => panic!("unexpected SOCKS5 atyp {other}"),
    };
    let mut tail = vec![0u8; tail_len];
    s.read_exact(&mut tail).await.unwrap();

    s.write_all(payload).await.unwrap();
    s.flush().await.unwrap();

    let mut out = vec![0u8; payload.len()];
    s.read_exact(&mut out).await.unwrap();
    out
}

async fn socks5_udp_roundtrip(socks_port: u16, target: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut ctrl = TcpStream::connect(("127.0.0.1", socks_port))
        .await
        .expect("connect SOCKS5 TCP control");
    ctrl.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut method_reply = [0u8; 2];
    ctrl.read_exact(&mut method_reply).await.unwrap();
    assert_eq!(method_reply, [0x05, 0x00]);

    // UDP ASSOCIATE with 0.0.0.0:0
    ctrl.write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await
        .unwrap();
    let mut hdr = [0u8; 4];
    ctrl.read_exact(&mut hdr).await.unwrap();
    assert_eq!(hdr[0], 0x05);
    assert_eq!(
        hdr[1], 0x00,
        "SOCKS5 UDP ASSOCIATE failed with reply 0x{:02x}",
        hdr[1]
    );
    let relay_addr = match hdr[3] {
        0x01 => {
            let mut ip_port = [0u8; 6];
            ctrl.read_exact(&mut ip_port).await.unwrap();
            let ip = Ipv4Addr::new(ip_port[0], ip_port[1], ip_port[2], ip_port[3]);
            let port = u16::from_be_bytes([ip_port[4], ip_port[5]]);
            let relay_ip = if ip.is_unspecified() {
                Ipv4Addr::LOCALHOST
            } else {
                ip
            };
            SocketAddr::V4(SocketAddrV4::new(relay_ip, port))
        }
        other => panic!("unexpected UDP ASSOCIATE atyp {other}"),
    };

    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let SocketAddr::V4(v4) = target else {
        panic!("expected IPv4 UDP target");
    };
    let mut pkt = Vec::with_capacity(10 + payload.len());
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
    pkt.extend_from_slice(&v4.ip().octets());
    pkt.extend_from_slice(&v4.port().to_be_bytes());
    pkt.extend_from_slice(payload);

    udp.send_to(&pkt, relay_addr).await.unwrap();

    let mut resp = vec![0u8; 65535];
    let (n, _) = tokio::time::timeout(Duration::from_secs(5), udp.recv_from(&mut resp))
        .await
        .expect("SOCKS5 UDP response timeout")
        .unwrap();
    assert!(n >= 10 && resp[2] == 0x00);
    let hdr_len = match resp[3] {
        0x01 => 10,
        0x04 => 22,
        0x03 => 4 + 1 + resp[4] as usize + 2,
        other => panic!("unexpected SOCKS5 UDP resp atyp {other}"),
    };
    drop(ctrl);
    resp[hdr_len..n].to_vec()
}

fn der_to_pem_cert(der: &[u8]) -> String {
    let b64 = STANDARD.encode(der);
    let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap());
        pem.push('\n');
    }
    pem.push_str("-----END CERTIFICATE-----\n");
    pem
}

fn parse_xray_vlessenc_output(text: &str) -> Vec<(String, String, String)> {
    // Returns Vec<(label, encryption, decryption)>
    let mut pairs = Vec::new();
    let mut current_label = String::new();
    let mut current_dec = None::<String>;
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("Authentication:") {
            current_label = rest.trim().to_string();
            current_dec = None;
        } else if trimmed.starts_with("\"decryption\":") {
            let val = trimmed
                .split('"')
                .nth(3)
                .expect("decryption value in xray vlessenc")
                .to_string();
            current_dec = Some(val);
        } else if trimmed.starts_with("\"encryption\":") {
            let enc = trimmed
                .split('"')
                .nth(3)
                .expect("encryption value in xray vlessenc")
                .to_string();
            if let Some(dec) = current_dec.take() {
                pairs.push((current_label.clone(), enc, dec));
            }
        }
    }
    pairs
}

#[tokio::test]
async fn interop_shadowsocks_2022_bidirectional_with_shadowsocks_rust() {
    let Some(ssserver_bin) = resolve_bin("ssserver") else {
        return;
    };
    let Some(sslocal_bin) = resolve_bin("sslocal") else {
        return;
    };

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (tcp_echo, udp_echo) = spawn_echo_servers(shutdown_rx.clone()).await;
    let tcp_target = TargetAddr::from(tcp_echo);
    let udp_target = TargetAddr::from(udp_echo);

    let ciphers = [
        ("2022-blake3-aes-256-gcm", STANDARD.encode([0x42u8; 32])),
        (
            "2022-blake3-chacha20-poly1305",
            STANDARD.encode([0x7Au8; 32]),
        ),
    ];

    for (cipher, psk) in ciphers {
        // =====================================================================
        // Direction A: rust-clash ShadowsocksOutbound -> official `ssserver`
        // =====================================================================
        let ext_srv_port = reserve_free_port();
        let mut ext_srv = ChildGuard(
            clean_loopback_command(&ssserver_bin)
                .args([
                    "-s",
                    &format!("127.0.0.1:{ext_srv_port}"),
                    "-k",
                    &psk,
                    "-m",
                    cipher,
                    "-U",
                ])
                .spawn()
                .expect("spawn ssserver"),
        );
        wait_tcp_ready(ext_srv_port, &mut ext_srv, "ssserver").await;

        let our_client = ShadowsocksOutbound::new(
            format!("interop-ss-out-{cipher}"),
            "127.0.0.1",
            ext_srv_port,
            cipher,
            &psk,
            true,
        )
        .expect("ShadowsocksOutbound::new");

        let mut stream = our_client
            .connect_tcp(&tcp_target)
            .await
            .expect("rust-clash -> ssserver TCP connect");
        let payload: Vec<u8> = (0..131_072).map(|i| ((i * 61 + 17) & 0xFF) as u8).collect();
        stream.write_all(&payload).await.unwrap();
        stream.flush().await.unwrap();
        let mut echoed = vec![0u8; payload.len()];
        stream.read_exact(&mut echoed).await.unwrap();
        assert_eq!(
            echoed, payload,
            "rust-clash -> ssserver TCP mismatch ({cipher})"
        );

        let udp_msg = format!("ss2022-client-to-ssserver-{cipher}");
        let udp_resp = our_client
            .exchange_udp(&udp_target, udp_msg.as_bytes(), Duration::from_secs(5))
            .await
            .expect("rust-clash -> ssserver UDP exchange");
        assert_eq!(
            udp_resp,
            format!("EXT-UDP-ECHO:{udp_msg}").into_bytes(),
            "rust-clash -> ssserver UDP mismatch ({cipher})"
        );
        drop(ext_srv);

        // =====================================================================
        // Direction B: official `sslocal` -> rust-clash `spawn_ss_server`
        // =====================================================================
        let (our_srv_addr, _our_srv_task) =
            spawn_ss_server("127.0.0.1:0", cipher, &psk, shutdown_rx.clone())
                .await
                .expect("spawn_ss_server");

        let ext_socks_port = reserve_free_port();
        let mut ext_client = ChildGuard(
            clean_loopback_command(&sslocal_bin)
                .args([
                    "-b",
                    &format!("127.0.0.1:{ext_socks_port}"),
                    "-s",
                    &our_srv_addr.to_string(),
                    "-k",
                    &psk,
                    "-m",
                    cipher,
                    "-U",
                ])
                .spawn()
                .expect("spawn sslocal"),
        );
        wait_tcp_ready(ext_socks_port, &mut ext_client, "sslocal").await;

        let echoed_b = socks5_tcp_roundtrip(ext_socks_port, tcp_echo, &payload).await;
        assert_eq!(
            echoed_b, payload,
            "sslocal -> rust-clash TCP mismatch ({cipher})"
        );

        let udp_msg_b = format!("sslocal-to-rust-clash-{cipher}");
        let udp_resp_b = socks5_udp_roundtrip(ext_socks_port, udp_echo, udp_msg_b.as_bytes()).await;
        assert_eq!(
            udp_resp_b,
            format!("EXT-UDP-ECHO:{udp_msg_b}").into_bytes(),
            "sslocal -> rust-clash UDP mismatch ({cipher})"
        );
        drop(ext_client);
    }

    let _ = shutdown_tx.send(true);
}

#[tokio::test]
async fn interop_vless_mlkem768x25519plus_bidirectional_with_xray_core() {
    let Some(xray_bin) = resolve_bin("xray/xray") else {
        return;
    };

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (tcp_echo, udp_echo) = spawn_echo_servers(shutdown_rx.clone()).await;
    let tcp_target = TargetAddr::from(tcp_echo);
    let udp_target = TargetAddr::from(udp_echo);

    // 1. Collect official `xray vlessenc` key pairs (both X25519 and Post-Quantum ML-KEM-768)
    let vlessenc_out = clean_loopback_command(&xray_bin)
        .arg("vlessenc")
        .output()
        .await
        .expect("run xray vlessenc");
    assert!(
        vlessenc_out.status.success(),
        "xray vlessenc failed: {}",
        String::from_utf8_lossy(&vlessenc_out.stderr)
    );
    let parsed_xray_pairs =
        parse_xray_vlessenc_output(&String::from_utf8_lossy(&vlessenc_out.stdout));
    assert!(
        parsed_xray_pairs.len() >= 2,
        "expected both X25519 and ML-KEM-768 pairs from xray vlessenc, got {parsed_xray_pairs:?}"
    );

    // 2. Also test pairs generated by rust-clash's `generate_vless_encryption_pair` across all 3 XorModes!
    let mut all_cases: Vec<(String, String, String, bool)> = parsed_xray_pairs
        .into_iter()
        .map(|(label, enc, dec)| (format!("xray-vlessenc ({label})"), enc, dec, true))
        .collect();

    for (mode, enable_0rtt) in [
        (XorMode::Native, true),
        (XorMode::XorPub, false),
        (XorMode::Random, true),
    ] {
        let p = generate_vless_encryption_pair(mode, enable_0rtt, true).unwrap();
        all_cases.push((
            format!("rust-clash-hybrid-{}-{}", mode.as_str(), p.rtt),
            p.encryption,
            p.decryption,
            enable_0rtt,
        ));
    }

    let tmp_dir = TempDirGuard::new("xray-interop");

    for (idx, (case_label, encryption, decryption, expect_0rtt)) in
        all_cases.into_iter().enumerate()
    {
        let uuid = Uuid::new_v4();
        let payload1: Vec<u8> = (0..98_304)
            .map(|i| ((i * 37 + idx + 5) & 0xFF) as u8)
            .collect();
        let payload2: Vec<u8> = (0..65_536)
            .map(|i| ((i * 53 + idx + 9) & 0xFF) as u8)
            .collect();

        // =====================================================================
        // Direction A: rust-clash `VlessOutbound` -> official `xray` Server
        // =====================================================================
        let xray_srv_port = reserve_free_port();
        let srv_cfg_path = tmp_dir.path().join(format!("xray_srv_{idx}.json"));
        let srv_cfg = json!({
            "log": { "loglevel": "warning" },
            "inbounds": [{
                "listen": "127.0.0.1",
                "port": xray_srv_port,
                "protocol": "vless",
                "settings": {
                    "clients": [{ "id": uuid.to_string() }],
                    "decryption": decryption
                }
            }],
            "outbounds": [{
                "protocol": "freedom",
                "settings": {
                    "finalRules": [{ "action": "allow" }]
                }
            }]
        });
        std::fs::write(&srv_cfg_path, serde_json::to_vec_pretty(&srv_cfg).unwrap()).unwrap();

        let mut xray_srv = ChildGuard(
            clean_loopback_command(&xray_bin)
                .args(["run", "-c", srv_cfg_path.to_str().unwrap()])
                .spawn()
                .expect("spawn xray server"),
        );
        wait_tcp_ready(
            xray_srv_port,
            &mut xray_srv,
            &format!("xray server [{case_label}]"),
        )
        .await;

        let our_vless = VlessOutbound::new(VlessOutboundConfig {
            name: format!("vless-out-{idx}"),
            server: "127.0.0.1".into(),
            port: xray_srv_port,
            uuid,
            encryption: encryption.clone(),
            tls: false,
            servername: None,
            skip_cert_verify: false,
            alpn: vec![],
            extra_ca_der: vec![],
            udp: true,
        })
        .unwrap();

        // Connection #1: 1-RTT full handshake
        {
            let mut s1 = our_vless
                .connect_tcp(&tcp_target)
                .await
                .unwrap_or_else(|e| {
                    panic!("rust-clash -> xray 1-RTT connect failed [{case_label}]: {e}")
                });
            s1.write_all(&payload1).await.unwrap();
            s1.flush().await.unwrap();
            let mut recv1 = vec![0u8; payload1.len()];
            if let Err(e) = s1.read_exact(&mut recv1).await {
                tokio::time::sleep(Duration::from_millis(100)).await;
                let _ = xray_srv.0.start_kill();
                let mut out = String::new();
                let mut err = String::new();
                if let Some(mut s) = xray_srv.0.stdout.take() {
                    let _ = s.read_to_string(&mut out).await;
                }
                if let Some(mut s) = xray_srv.0.stderr.take() {
                    let _ = s.read_to_string(&mut err).await;
                }
                panic!(
                    "rust-clash -> xray 1-RTT read failed [{case_label}]: {e}\nxray stdout:\n{out}\nxray stderr:\n{err}"
                );
            }
            assert_eq!(
                recv1, payload1,
                "rust-clash -> xray 1-RTT mismatch [{case_label}]"
            );
        }

        if expect_0rtt {
            assert!(
                our_vless.has_valid_0rtt_ticket(),
                "expected 0-RTT session ticket from official xray server [{case_label}]"
            );
            // Connection #2: 0-RTT ticket resumption against official xray server!
            let mut s2 = our_vless
                .connect_tcp(&tcp_target)
                .await
                .unwrap_or_else(|e| {
                    panic!("rust-clash -> xray 0-RTT connect failed [{case_label}]: {e}")
                });
            s2.write_all(&payload2).await.unwrap();
            s2.flush().await.unwrap();
            let mut recv2 = vec![0u8; payload2.len()];
            s2.read_exact(&mut recv2).await.unwrap_or_else(|e| {
                panic!("rust-clash -> xray 0-RTT read failed [{case_label}]: {e}")
            });
            assert_eq!(
                recv2, payload2,
                "rust-clash -> xray 0-RTT mismatch [{case_label}]"
            );
        }

        // VLESS UDP datagram framing against official xray server
        let udp_ping = format!("vless-to-xray-udp-{idx}");
        let udp_reply = our_vless
            .exchange_udp(&udp_target, udp_ping.as_bytes(), Duration::from_secs(5))
            .await
            .unwrap_or_else(|e| panic!("rust-clash -> xray UDP failed [{case_label}]: {e}"));
        assert_eq!(
            udp_reply,
            format!("EXT-UDP-ECHO:{udp_ping}").into_bytes(),
            "rust-clash -> xray UDP mismatch [{case_label}]"
        );
        drop(xray_srv);

        // =====================================================================
        // Direction B: official `xray` Client -> rust-clash `spawn_vless_server`
        // =====================================================================
        let (our_srv_addr, _our_srv_task) = spawn_vless_server(
            VlessServerConfig {
                listen_addr: "127.0.0.1:0".into(),
                allowed_uuid: uuid,
                decryption: decryption.clone(),
                tls_config: None,
            },
            shutdown_rx.clone(),
        )
        .await
        .expect("spawn_vless_server");

        let xray_socks_port = reserve_free_port();
        let cli_cfg_path = tmp_dir.path().join(format!("xray_cli_{idx}.json"));
        let cli_cfg = json!({
            "log": { "loglevel": "warning" },
            "inbounds": [{
                "listen": "127.0.0.1",
                "port": xray_socks_port,
                "protocol": "socks",
                "settings": { "udp": true }
            }],
            "outbounds": [{
                "protocol": "vless",
                "settings": {
                    "vnext": [{
                        "address": "127.0.0.1",
                        "port": our_srv_addr.port(),
                        "users": [{
                            "id": uuid.to_string(),
                            "encryption": encryption
                        }]
                    }]
                }
            }]
        });
        std::fs::write(&cli_cfg_path, serde_json::to_vec_pretty(&cli_cfg).unwrap()).unwrap();

        let mut xray_cli = ChildGuard(
            clean_loopback_command(&xray_bin)
                .args(["run", "-c", cli_cfg_path.to_str().unwrap()])
                .spawn()
                .expect("spawn xray client"),
        );
        wait_tcp_ready(
            xray_socks_port,
            &mut xray_cli,
            &format!("xray client [{case_label}]"),
        )
        .await;

        // Connection #1 (1-RTT from xray client) + Connection #2 (0-RTT ticket resumption from xray client!)
        let recv_b1 = socks5_tcp_roundtrip(xray_socks_port, tcp_echo, &payload1).await;
        assert_eq!(
            recv_b1, payload1,
            "xray -> rust-clash #1 mismatch [{case_label}]"
        );
        let recv_b2 = socks5_tcp_roundtrip(xray_socks_port, tcp_echo, &payload2).await;
        assert_eq!(
            recv_b2, payload2,
            "xray -> rust-clash #2 mismatch [{case_label}]"
        );

        // VLESS UDP from official xray client -> rust-clash VLESS server!
        let udp_ping_b = format!("xray-to-vless-udp-{idx}");
        let udp_reply_b =
            socks5_udp_roundtrip(xray_socks_port, udp_echo, udp_ping_b.as_bytes()).await;
        assert_eq!(
            udp_reply_b,
            format!("EXT-UDP-ECHO:{udp_ping_b}").into_bytes(),
            "xray -> rust-clash UDP mismatch [{case_label}]"
        );
        drop(xray_cli);
    }

    let _ = shutdown_tx.send(true);
}

#[tokio::test]
async fn interop_anytls_bidirectional_with_anytls_go() {
    let Some(anytls_srv_bin) = resolve_bin("anytls/anytls-server") else {
        return;
    };
    let Some(anytls_cli_bin) = resolve_bin("anytls/anytls-client") else {
        return;
    };

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (tcp_echo, udp_echo) = spawn_echo_servers(shutdown_rx.clone()).await;
    let tcp_target = TargetAddr::from(tcp_echo);
    let udp_target = TargetAddr::from(udp_echo);
    let password = "anytls-interop-secret-2026";

    // =========================================================================
    // Direction A: rust-clash `AnyTlsOutbound` -> official `anytls-server` (Go)
    // =========================================================================
    let ext_srv_port = reserve_free_port();
    let mut ext_srv = ChildGuard(
        clean_loopback_command(&anytls_srv_bin)
            .args(["-l", &format!("127.0.0.1:{ext_srv_port}"), "-p", password])
            .spawn()
            .expect("spawn anytls-server"),
    );
    wait_tcp_ready(ext_srv_port, &mut ext_srv, "anytls-server").await;

    let our_client = AnyTlsOutbound::new(AnyTlsOutboundConfig {
        name: "anytls-to-go".into(),
        server: "127.0.0.1".into(),
        port: ext_srv_port,
        password: password.into(),
        sni: "example.com".into(),
        skip_cert_verify: true, // official `anytls-server` auto-generates an ephemeral self-signed cert
        alpn: vec![],
        extra_ca_der: vec![],
        idle_session_check_interval: Duration::from_secs(30),
        idle_session_timeout: Duration::from_secs(60),
        min_idle_session: 2,
        udp: true,
    })
    .unwrap();

    // Open two concurrent streams, then reuse pooled session for a 128 KB stream
    let mut st1 = our_client
        .connect_anytls_stream(&tcp_target)
        .await
        .expect("rust-clash -> anytls-server stream #1");
    let mut st2 = our_client
        .connect_anytls_stream(&tcp_target)
        .await
        .expect("rust-clash -> anytls-server stream #2");

    st1.write_all(b"hello-go-anytls-1").await.unwrap();
    st2.write_all(b"hello-go-anytls-2").await.unwrap();
    let mut r1 = [0u8; 17];
    let mut r2 = [0u8; 17];
    st1.read_exact(&mut r1).await.unwrap();
    st2.read_exact(&mut r2).await.unwrap();
    assert_eq!(&r1, b"hello-go-anytls-1");
    assert_eq!(&r2, b"hello-go-anytls-2");

    drop(st1);
    drop(st2);
    tokio::time::sleep(Duration::from_millis(30)).await;

    let mut st3 = our_client
        .connect_anytls_stream(&tcp_target)
        .await
        .expect("rust-clash -> anytls-server reused session stream #3");
    assert_eq!(
        st3.stream_id(),
        2,
        "must multiplex stream #2 on idle Go session"
    );
    let payload: Vec<u8> = (0..131_072).map(|i| ((i * 43 + 13) & 0xFF) as u8).collect();
    st3.write_all(&payload).await.unwrap();
    st3.flush().await.unwrap();
    let mut echoed = vec![0u8; payload.len()];
    st3.read_exact(&mut echoed).await.unwrap();
    assert_eq!(
        echoed, payload,
        "rust-clash -> anytls-server 128KB mismatch"
    );
    drop(st3);

    // Direction A UDP: both `exchange_udp` (isConnect=1) and multi-packet `open_udp_session` (isConnect=0)
    let udp_one = our_client
        .exchange_udp(&udp_target, b"anytls-uot-connect1", Duration::from_secs(5))
        .await
        .expect("rust-clash -> anytls-server UoT v2 connected UDP");
    assert_eq!(udp_one, b"EXT-UDP-ECHO:anytls-uot-connect1");

    let udp_sess = our_client
        .open_udp_session()
        .await
        .expect("rust-clash -> anytls-server UoT v2 stateful UDP session");
    for seq in 0..4 {
        let msg = format!("anytls-stateful-pkt-{seq}");
        udp_sess
            .send_to(msg.as_bytes(), &udp_target)
            .await
            .expect("AnyTLS UoT send_to");
        let (resp, _src) = tokio::time::timeout(Duration::from_secs(5), udp_sess.recv_from())
            .await
            .expect("AnyTLS UoT recv_from timeout")
            .expect("AnyTLS UoT recv_from");
        assert_eq!(resp, format!("EXT-UDP-ECHO:{msg}").into_bytes());
    }
    drop(udp_sess);
    drop(ext_srv);

    // =========================================================================
    // Direction B: official `anytls-client` (Go) -> rust-clash `spawn_anytls_server`
    // =========================================================================
    let (server_tls_cfg, ca_der) = generate_self_signed_server_config(
        &["anytls.interop.local".to_string(), "127.0.0.1".to_string()],
        &[],
    )
    .unwrap();
    let custom_scheme = PaddingScheme::parse(
        "stop=6\n0=20-50\n1=60-180\n2=150-300,c,350-600\n3=200-500\n4=200-500\n5=200-500",
    )
    .unwrap();

    let (our_srv_addr, _our_srv_task) = spawn_anytls_server(
        AnyTlsServerConfig {
            listen_addr: "127.0.0.1:0".into(),
            password: password.into(),
            tls_config: server_tls_cfg,
            padding_scheme: custom_scheme,
        },
        shutdown_rx.clone(),
    )
    .await
    .unwrap();

    let cert_dir = TempDirGuard::new("anytls-interop");
    let ca_pem_path = cert_dir.path().join("anytls_ca.pem");
    std::fs::write(&ca_pem_path, der_to_pem_cert(ca_der.as_ref())).unwrap();

    let ext_socks_port = reserve_free_port();
    let mut ext_cli = ChildGuard(
        clean_loopback_command(&anytls_cli_bin)
            .env("SSL_CERT_FILE", &ca_pem_path)
            .args([
                "-l",
                &format!("127.0.0.1:{ext_socks_port}"),
                "-s",
                &our_srv_addr.to_string(),
                "-p",
                password,
                "-sni",
                "anytls.interop.local",
            ])
            .spawn()
            .expect("spawn anytls-client"),
    );
    wait_tcp_ready(ext_socks_port, &mut ext_cli, "anytls-client").await;

    // Sequential & multiplexed TCP + SOCKS5 UDP ASSOCIATE (`sp.v2.udp-over-tcp.arpa`) through Go `anytls-client` -> rust-clash server
    let echoed_b1 = socks5_tcp_roundtrip(ext_socks_port, tcp_echo, &payload).await;
    assert_eq!(
        echoed_b1, payload,
        "anytls-client -> rust-clash stream #1 128KB mismatch"
    );
    let echoed_b2 = socks5_tcp_roundtrip(
        ext_socks_port,
        tcp_echo,
        b"second-reused-stream-over-go-client",
    )
    .await;
    assert_eq!(echoed_b2, b"second-reused-stream-over-go-client");

    let udp_b =
        socks5_udp_roundtrip(ext_socks_port, udp_echo, b"go-anytls-client-udp-to-rust").await;
    assert_eq!(udp_b, b"EXT-UDP-ECHO:go-anytls-client-udp-to-rust");
    drop(ext_cli);

    let _ = shutdown_tx.send(true);
}

fn write_ephemeral_pem_cert(
    dir: &Path,
    prefix: &str,
    sans: &[&str],
) -> (PathBuf, PathBuf, rustls::pki_types::CertificateDer<'static>) {
    let names: Vec<String> = sans.iter().map(|s| (*s).to_string()).collect();
    let certified = rcgen::generate_simple_self_signed(names).expect("rcgen cert");
    let cert_path = dir.join(format!("{prefix}_cert.pem"));
    let key_path = dir.join(format!("{prefix}_key.pem"));
    std::fs::write(&cert_path, certified.cert.pem()).expect("write cert pem");
    std::fs::write(&key_path, certified.key_pair.serialize_pem()).expect("write key pem");
    (cert_path, key_path, certified.cert.der().clone())
}

#[tokio::test]
async fn interop_trojan_tls_ws_and_udp_with_xray_server() {
    let Some(xray_bin) = resolve_bin("xray/xray") else {
        return;
    };

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (tcp_echo, udp_echo) = spawn_echo_servers(shutdown_rx.clone()).await;
    let tcp_target = TargetAddr::from(tcp_echo);
    let udp_target = TargetAddr::from(udp_echo);
    let password = "trojan-xray-interop-2026-secret";
    let sni = "trojan.interop.local";

    let tmp_dir = TempDirGuard::new("xray-trojan-interop");
    let (cert_pem_path, key_pem_path, ca_der) =
        write_ephemeral_pem_cert(tmp_dir.path(), "trojan_xray", &[sni, "127.0.0.1"]);

    // =========================================================================
    // Direction A: rust-clash `TrojanOutbound` (TLS + WS?ed=2048 + UDP) -> `xray`
    // =========================================================================
    let xray_tls_port = reserve_free_port();
    let xray_ws_port = reserve_free_port();
    let srv_cfg_path = tmp_dir.path().join("xray_trojan_srv.json");
    let srv_cfg = json!({
        "log": { "loglevel": "warning" },
        "inbounds": [
            {
                "listen": "127.0.0.1",
                "port": xray_tls_port,
                "protocol": "trojan",
                "settings": {
                    "clients": [{ "password": password }]
                },
                "streamSettings": {
                    "network": "tcp",
                    "security": "tls",
                    "tlsSettings": {
                        "certificates": [{
                            "certificateFile": cert_pem_path.to_str().unwrap(),
                            "keyFile": key_pem_path.to_str().unwrap()
                        }]
                    }
                }
            },
            {
                "listen": "127.0.0.1",
                "port": xray_ws_port,
                "protocol": "trojan",
                "settings": {
                    "clients": [{ "password": password }]
                },
                "streamSettings": {
                    "network": "ws",
                    "security": "tls",
                    "tlsSettings": {
                        "certificates": [{
                            "certificateFile": cert_pem_path.to_str().unwrap(),
                            "keyFile": key_pem_path.to_str().unwrap()
                        }]
                    },
                    "wsSettings": {
                        "path": "/trojan-ws?ed=2048"
                    }
                }
            }
        ],
        "outbounds": [{
            "protocol": "freedom",
            "settings": {
                "finalRules": [{ "action": "allow" }]
            }
        }]
    });
    std::fs::write(&srv_cfg_path, serde_json::to_vec_pretty(&srv_cfg).unwrap()).unwrap();

    let mut xray_srv = ChildGuard(
        clean_loopback_command(&xray_bin)
            .args(["run", "-c", srv_cfg_path.to_str().unwrap()])
            .spawn()
            .expect("spawn xray trojan server"),
    );
    wait_tcp_ready(xray_tls_port, &mut xray_srv, "xray trojan-tls server").await;
    wait_tcp_ready(xray_ws_port, &mut xray_srv, "xray trojan-ws server").await;

    let payload: Vec<u8> = (0..131_072).map(|i| ((i * 29 + 7) & 0xFF) as u8).collect();

    for (label, port, ws_opts) in [
        ("trojan-tls", xray_tls_port, None),
        (
            "trojan-ws-tls-ed2048",
            xray_ws_port,
            Some(WsTransportConfig {
                path: "/trojan-ws?ed=2048".into(),
                headers: std::collections::HashMap::from([("Host".into(), sni.into())]),
                max_early_data: Some(2048),
                early_data_header_name: Some("Sec-WebSocket-Protocol".into()),
            }),
        ),
    ] {
        let our_trojan = TrojanOutbound::new(TrojanOutboundConfig {
            name: label.into(),
            server: "127.0.0.1".into(),
            port,
            password: password.into(),
            tls: true,
            sni: Some(sni.into()),
            skip_cert_verify: false,
            alpn: vec![],
            extra_ca_der: vec![ca_der.clone()],
            ws_opts,
            udp: true,
        })
        .unwrap();

        let mut st = our_trojan
            .connect_tcp(&tcp_target)
            .await
            .unwrap_or_else(|e| panic!("rust-clash -> xray {label} TCP connect failed: {e}"));
        st.write_all(&payload).await.unwrap();
        st.flush().await.unwrap();
        let mut echoed = vec![0u8; payload.len()];
        st.read_exact(&mut echoed)
            .await
            .unwrap_or_else(|e| panic!("rust-clash -> xray {label} TCP read failed: {e}"));
        assert_eq!(echoed, payload, "{label} 128KB TCP mismatch");

        let udp_sess = our_trojan.open_udp_session().await.unwrap();
        for seq in 0..3 {
            let msg = format!("trojan-{label}-udp-{seq}");
            udp_sess.send_to(msg.as_bytes(), &udp_target).await.unwrap();
            let (resp, src) = tokio::time::timeout(Duration::from_secs(5), udp_sess.recv_from())
                .await
                .expect("Trojan -> xray UDP timeout")
                .expect("Trojan -> xray UDP recv");
            assert_eq!(resp, format!("EXT-UDP-ECHO:{msg}").into_bytes());
            assert_eq!(src, udp_target);
        }
    }
    drop(xray_srv);

    // =========================================================================
    // Direction B: official `xray` Trojan Client -> `spawn_trojan_server` (TLS & WS)
    // =========================================================================
    let (our_tls_cfg, our_ca_der) =
        generate_self_signed_server_config(&[sni.to_string(), "127.0.0.1".to_string()], &[])
            .unwrap();
    let our_cert_pin = hex::encode(aws_lc_rs::digest::digest(
        &aws_lc_rs::digest::SHA256,
        our_ca_der.as_ref(),
    ));

    for (mode_label, ws_path) in [
        ("tls-raw", None),
        ("tls-ws-ed2048", Some("/trojan-srv-ws".to_string())),
    ] {
        let (our_srv_addr, _srv_handle) = spawn_trojan_server(
            TrojanServerConfig {
                listen_addr: "127.0.0.1:0".into(),
                password: password.into(),
                tls_config: Some(Arc::clone(&our_tls_cfg)),
                ws_path: ws_path.clone(),
            },
            shutdown_rx.clone(),
        )
        .await
        .unwrap();

        let stream_settings = if ws_path.is_some() {
            json!({
                "network": "ws",
                "security": "tls",
                "tlsSettings": {
                    "serverName": sni,
                    "pinnedPeerCertSha256": our_cert_pin
                },
                "wsSettings": { "path": "/trojan-srv-ws?ed=2048" }
            })
        } else {
            json!({
                "network": "tcp",
                "security": "tls",
                "tlsSettings": {
                    "serverName": sni,
                    "pinnedPeerCertSha256": our_cert_pin
                }
            })
        };

        let xray_socks_port = reserve_free_port();
        let cli_cfg_path = tmp_dir
            .path()
            .join(format!("xray_trojan_cli_{mode_label}.json"));
        let cli_cfg = json!({
            "log": { "loglevel": "warning" },
            "inbounds": [{
                "listen": "127.0.0.1",
                "port": xray_socks_port,
                "protocol": "socks",
                "settings": { "udp": true }
            }],
            "outbounds": [{
                "protocol": "trojan",
                "settings": {
                    "servers": [{
                        "address": "127.0.0.1",
                        "port": our_srv_addr.port(),
                        "password": password
                    }]
                },
                "streamSettings": stream_settings
            }]
        });
        std::fs::write(&cli_cfg_path, serde_json::to_vec_pretty(&cli_cfg).unwrap()).unwrap();

        let mut xray_cli = ChildGuard(
            clean_loopback_command(&xray_bin)
                .args(["run", "-c", cli_cfg_path.to_str().unwrap()])
                .spawn()
                .expect("spawn xray trojan client"),
        );
        wait_tcp_ready(
            xray_socks_port,
            &mut xray_cli,
            &format!("xray trojan client [{mode_label}]"),
        )
        .await;

        let recv_tcp = socks5_tcp_roundtrip(xray_socks_port, tcp_echo, &payload).await;
        assert_eq!(
            recv_tcp, payload,
            "xray -> spawn_trojan_server [{mode_label}] TCP mismatch"
        );
        let udp_msg = format!("xray-trojan-cli-udp-{mode_label}");
        let recv_udp = socks5_udp_roundtrip(xray_socks_port, udp_echo, udp_msg.as_bytes()).await;
        assert_eq!(
            recv_udp,
            format!("EXT-UDP-ECHO:{udp_msg}").into_bytes(),
            "xray -> spawn_trojan_server [{mode_label}] UDP mismatch"
        );
        drop(xray_cli);
    }

    let _ = shutdown_tx.send(true);
}

#[tokio::test]
async fn interop_vless_ws_and_early_data_2048_with_xray_server() {
    let Some(xray_bin) = resolve_bin("xray/xray") else {
        return;
    };

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (tcp_echo, udp_echo) = spawn_echo_servers(shutdown_rx.clone()).await;
    let tcp_target = TargetAddr::from(tcp_echo);
    let udp_target = TargetAddr::from(udp_echo);
    let uuid = Uuid::new_v4();
    let sni = "vless-ws.interop.local";

    let tmp_dir = TempDirGuard::new("xray-vless-ws-interop");
    let (cert_pem_path, key_pem_path, ca_der) =
        write_ephemeral_pem_cert(tmp_dir.path(), "vless_ws", &[sni, "127.0.0.1"]);

    // =========================================================================
    // Direction A: rust-clash `VlessOutbound` (WS `?ed=2048` + TLS) -> `xray`
    // =========================================================================
    let xray_srv_port = reserve_free_port();
    let srv_cfg_path = tmp_dir.path().join("xray_vless_ws_srv.json");
    let srv_cfg = json!({
        "log": { "loglevel": "warning" },
        "inbounds": [{
            "listen": "127.0.0.1",
            "port": xray_srv_port,
            "protocol": "vless",
            "settings": {
                "clients": [{ "id": uuid.to_string() }],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "ws",
                "security": "tls",
                "tlsSettings": {
                    "certificates": [{
                        "certificateFile": cert_pem_path.to_str().unwrap(),
                        "keyFile": key_pem_path.to_str().unwrap()
                    }]
                },
                "wsSettings": {
                    "path": "/vless-ws?ed=2048"
                }
            }
        }],
        "outbounds": [{
            "protocol": "freedom",
            "settings": {
                "finalRules": [{ "action": "allow" }]
            }
        }]
    });
    std::fs::write(&srv_cfg_path, serde_json::to_vec_pretty(&srv_cfg).unwrap()).unwrap();

    let mut xray_srv = ChildGuard(
        clean_loopback_command(&xray_bin)
            .args(["run", "-c", srv_cfg_path.to_str().unwrap()])
            .spawn()
            .expect("spawn xray vless+ws server"),
    );
    wait_tcp_ready(xray_srv_port, &mut xray_srv, "xray vless+ws server").await;

    let our_vless_ws = VlessOutbound::new_with_transport(
        VlessOutboundConfig {
            name: "vless-ws-ed2048".into(),
            server: "127.0.0.1".into(),
            port: xray_srv_port,
            uuid,
            encryption: "none".into(),
            tls: true,
            servername: Some(sni.into()),
            skip_cert_verify: false,
            alpn: vec![b"http/1.1".to_vec()],
            extra_ca_der: vec![ca_der],
            udp: true,
        },
        Some(WsTransportConfig {
            path: "/vless-ws?ed=2048".into(),
            headers: std::collections::HashMap::from([("Host".into(), sni.into())]),
            max_early_data: Some(2048),
            early_data_header_name: Some("Sec-WebSocket-Protocol".into()),
        }),
        None,
    )
    .unwrap();

    // Case 1: Small payload (< 2048B) — 100% fits inside 0-RTT `Sec-WebSocket-Protocol` early data
    {
        let small = b"vless-ws-0rtt-small-request-piggybacked-in-sec-websocket-protocol";
        let mut s1 = our_vless_ws
            .connect_tcp(&tcp_target)
            .await
            .expect("VLESS+WS ?ed=2048 small connect");
        s1.write_all(small).await.unwrap();
        s1.flush().await.unwrap();
        let mut echoed = vec![0u8; small.len()];
        s1.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, small);
    }

    // Case 2: Large single-buffer coalesced write (128 KiB >> 2048B) — first 2048B carried in
    // `Sec-WebSocket-Protocol`, remainder streamed via `Connected` WebSocket frames with backpressure!
    let big_payload: Vec<u8> = (0..131_072).map(|i| ((i * 71 + 19) & 0xFF) as u8).collect();
    {
        let mut s2 = our_vless_ws
            .connect_tcp(&tcp_target)
            .await
            .expect("VLESS+WS ?ed=2048 large connect");
        s2.write_all(&big_payload).await.unwrap();
        s2.flush().await.unwrap();
        let mut echoed = vec![0u8; big_payload.len()];
        s2.read_exact(&mut echoed).await.unwrap();
        assert_eq!(echoed, big_payload, "VLESS+WS ?ed=2048 128KB mismatch");
    }

    // Case 3: VLESS UDP over WebSocket `?ed=2048` + TLS
    let udp_sess = our_vless_ws.open_udp_session().await.unwrap();
    for seq in 0..3 {
        let msg = format!("vless-ws-ed2048-udp-{seq}");
        udp_sess.send_to(msg.as_bytes(), &udp_target).await.unwrap();
        let (resp, _) = tokio::time::timeout(Duration::from_secs(5), udp_sess.recv_from())
            .await
            .expect("VLESS+WS UDP timeout")
            .expect("VLESS+WS UDP recv");
        assert_eq!(resp, format!("EXT-UDP-ECHO:{msg}").into_bytes());
    }
    drop(udp_sess);
    drop(xray_srv);

    // =========================================================================
    // Direction B: official `xray` VLESS+WS `?ed=2048` Client -> `spawn_vless_ws_server`
    // =========================================================================
    let (our_tls_cfg, our_ca_der) = generate_self_signed_server_config(
        &[sni.to_string(), "127.0.0.1".to_string()],
        &[b"http/1.1".to_vec()],
    )
    .unwrap();
    let our_cert_pin = hex::encode(aws_lc_rs::digest::digest(
        &aws_lc_rs::digest::SHA256,
        our_ca_der.as_ref(),
    ));

    let (our_srv_addr, _our_srv_task) = spawn_vless_ws_server(
        VlessServerConfig {
            listen_addr: "127.0.0.1:0".into(),
            allowed_uuid: uuid,
            decryption: "none".into(),
            tls_config: Some(our_tls_cfg),
        },
        "/vless-ws".into(),
        shutdown_rx.clone(),
    )
    .await
    .unwrap();

    let xray_socks_port = reserve_free_port();
    let cli_cfg_path = tmp_dir.path().join("xray_vless_ws_cli.json");
    let cli_cfg = json!({
        "log": { "loglevel": "warning" },
        "inbounds": [{
            "listen": "127.0.0.1",
            "port": xray_socks_port,
            "protocol": "socks",
            "settings": { "udp": true }
        }],
        "outbounds": [{
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": "127.0.0.1",
                    "port": our_srv_addr.port(),
                    "users": [{
                        "id": uuid.to_string(),
                        "encryption": "none"
                    }]
                }]
            },
            "streamSettings": {
                "network": "ws",
                "security": "tls",
                "tlsSettings": {
                    "serverName": sni,
                    "alpn": ["http/1.1"],
                    "pinnedPeerCertSha256": our_cert_pin
                },
                "wsSettings": {
                    "path": "/vless-ws?ed=2048"
                }
            }
        }]
    });
    std::fs::write(&cli_cfg_path, serde_json::to_vec_pretty(&cli_cfg).unwrap()).unwrap();

    let mut xray_cli = ChildGuard(
        clean_loopback_command(&xray_bin)
            .args(["run", "-c", cli_cfg_path.to_str().unwrap()])
            .spawn()
            .expect("spawn xray vless+ws client"),
    );
    wait_tcp_ready(xray_socks_port, &mut xray_cli, "xray vless+ws client").await;

    let echoed_small =
        socks5_tcp_roundtrip(xray_socks_port, tcp_echo, b"xray-ed2048-to-rust-server").await;
    assert_eq!(echoed_small, b"xray-ed2048-to-rust-server");
    let echoed_big = socks5_tcp_roundtrip(xray_socks_port, tcp_echo, &big_payload).await;
    assert_eq!(
        echoed_big, big_payload,
        "xray -> spawn_vless_ws_server 128KB mismatch"
    );
    let echoed_udp =
        socks5_udp_roundtrip(xray_socks_port, udp_echo, b"xray-vless-ws-ed2048-udp").await;
    assert_eq!(echoed_udp, b"EXT-UDP-ECHO:xray-vless-ws-ed2048-udp");
    drop(xray_cli);

    let _ = shutdown_tx.send(true);
}

#[tokio::test]
async fn interop_socks5_auth_tcp_and_udp_with_xray_server() {
    let Some(xray_bin) = resolve_bin("xray/xray") else {
        return;
    };

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (tcp_echo, udp_echo) = spawn_echo_servers(shutdown_rx.clone()).await;
    let tcp_target = TargetAddr::from(tcp_echo);
    let udp_target = TargetAddr::from(udp_echo);
    let username = "socks-user-2026";
    let password = "socks-pass-!@#$-2026";

    let tmp_dir = TempDirGuard::new("xray-socks5-interop");

    // =========================================================================
    // Direction A: rust-clash `Socks5Outbound` (RFC 1929 Auth + UDP) -> `xray`
    // =========================================================================
    let xray_srv_port = reserve_free_port();
    let srv_cfg_path = tmp_dir.path().join("xray_socks5_srv.json");
    let srv_cfg = json!({
        "log": { "loglevel": "warning" },
        "inbounds": [{
            "listen": "127.0.0.1",
            "port": xray_srv_port,
            "protocol": "socks",
            "settings": {
                "auth": "password",
                "accounts": [{
                    "user": username,
                    "pass": password
                }],
                "udp": true
            }
        }],
        "outbounds": [{
            "protocol": "freedom",
            "settings": {
                "finalRules": [{ "action": "allow" }]
            }
        }]
    });
    std::fs::write(&srv_cfg_path, serde_json::to_vec_pretty(&srv_cfg).unwrap()).unwrap();

    let mut xray_srv = ChildGuard(
        clean_loopback_command(&xray_bin)
            .args(["run", "-c", srv_cfg_path.to_str().unwrap()])
            .spawn()
            .expect("spawn xray socks5 server"),
    );
    wait_tcp_ready(xray_srv_port, &mut xray_srv, "xray socks5 server").await;

    // Negative check: wrong credentials must fail cleanly
    let bad_socks = Socks5Outbound::new(Socks5OutboundConfig {
        name: "socks5-bad-auth".into(),
        server: "127.0.0.1".into(),
        port: xray_srv_port,
        username: Some(username.into()),
        password: Some("wrong-password".into()),
        tls: false,
        sni: None,
        skip_cert_verify: false,
        extra_ca_der: vec![],
        udp: true,
    })
    .unwrap();
    assert!(
        bad_socks.connect_tcp(&tcp_target).await.is_err(),
        "wrong SOCKS5 password must be rejected by xray"
    );

    let our_socks = Socks5Outbound::new(Socks5OutboundConfig {
        name: "socks5-auth".into(),
        server: "127.0.0.1".into(),
        port: xray_srv_port,
        username: Some(username.into()),
        password: Some(password.into()),
        tls: false,
        sni: None,
        skip_cert_verify: false,
        extra_ca_der: vec![],
        udp: true,
    })
    .unwrap();

    let payload: Vec<u8> = (0..131_072).map(|i| ((i * 83 + 11) & 0xFF) as u8).collect();
    let mut st = our_socks
        .connect_tcp(&tcp_target)
        .await
        .expect("Socks5Outbound -> xray TCP connect");
    st.write_all(&payload).await.unwrap();
    st.flush().await.unwrap();
    let mut echoed = vec![0u8; payload.len()];
    st.read_exact(&mut echoed).await.unwrap();
    assert_eq!(echoed, payload, "Socks5Outbound -> xray 128KB mismatch");

    let udp_sess = our_socks
        .open_udp_session()
        .await
        .expect("Socks5Outbound -> xray UDP ASSOCIATE");
    for seq in 0..4 {
        let msg = format!("socks5-auth-udp-{seq}");
        udp_sess.send_to(msg.as_bytes(), &udp_target).await.unwrap();
        let (resp, src) = tokio::time::timeout(Duration::from_secs(5), udp_sess.recv_from())
            .await
            .expect("SOCKS5 UDP timeout")
            .expect("SOCKS5 UDP recv");
        assert_eq!(resp, format!("EXT-UDP-ECHO:{msg}").into_bytes());
        assert_eq!(src, udp_target);
    }
    drop(udp_sess);
    drop(xray_srv);

    // =========================================================================
    // Direction B: official `xray` SOCKS5 Outbound -> `spawn_socks5_server`
    // =========================================================================
    let (our_srv_addr, _our_srv_task) = spawn_socks5_server(
        Socks5ServerConfig {
            listen_addr: "127.0.0.1:0".into(),
            credentials: Some((username.into(), password.into())),
        },
        shutdown_rx.clone(),
    )
    .await
    .unwrap();

    let xray_socks_port = reserve_free_port();
    let cli_cfg_path = tmp_dir.path().join("xray_socks5_cli.json");
    let cli_cfg = json!({
        "log": { "loglevel": "warning" },
        "inbounds": [{
            "listen": "127.0.0.1",
            "port": xray_socks_port,
            "protocol": "socks",
            "settings": { "udp": true }
        }],
        "outbounds": [{
            "protocol": "socks",
            "settings": {
                "servers": [{
                    "address": "127.0.0.1",
                    "port": our_srv_addr.port(),
                    "users": [{
                        "user": username,
                        "pass": password
                    }]
                }]
            }
        }]
    });
    std::fs::write(&cli_cfg_path, serde_json::to_vec_pretty(&cli_cfg).unwrap()).unwrap();

    let mut xray_cli = ChildGuard(
        clean_loopback_command(&xray_bin)
            .args(["run", "-c", cli_cfg_path.to_str().unwrap()])
            .spawn()
            .expect("spawn xray socks5 client"),
    );
    wait_tcp_ready(xray_socks_port, &mut xray_cli, "xray socks5 client").await;

    let recv_b = socks5_tcp_roundtrip(xray_socks_port, tcp_echo, &payload).await;
    assert_eq!(
        recv_b, payload,
        "xray -> spawn_socks5_server 128KB mismatch"
    );
    let recv_udp_b = socks5_udp_roundtrip(xray_socks_port, udp_echo, b"xray-socks5-out-udp").await;
    assert_eq!(recv_udp_b, b"EXT-UDP-ECHO:xray-socks5-out-udp");
    drop(xray_cli);

    let _ = shutdown_tx.send(true);
}

#[tokio::test]
async fn interop_http_connect_plain_tls_and_auth_with_xray_server() {
    let Some(xray_bin) = resolve_bin("xray/xray") else {
        return;
    };

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (tcp_echo, _udp_echo) = spawn_echo_servers(shutdown_rx.clone()).await;
    let tcp_target = TargetAddr::from(tcp_echo);
    let username = "http-proxy-user";
    let password = "http-proxy-secret-2026";
    let sni = "https-proxy.interop.local";

    let tmp_dir = TempDirGuard::new("xray-http-interop");
    let (cert_pem_path, key_pem_path, ca_der) =
        write_ephemeral_pem_cert(tmp_dir.path(), "https_proxy", &[sni, "127.0.0.1"]);

    // =========================================================================
    // Direction A: rust-clash `HttpOutbound` (Plain & HTTPS+BasicAuth) -> `xray`
    // =========================================================================
    let xray_plain_port = reserve_free_port();
    let xray_tls_auth_port = reserve_free_port();
    let srv_cfg_path = tmp_dir.path().join("xray_http_srv.json");
    let srv_cfg = json!({
        "log": { "loglevel": "warning" },
        "inbounds": [
            {
                "listen": "127.0.0.1",
                "port": xray_plain_port,
                "protocol": "http",
                "settings": {}
            },
            {
                "listen": "127.0.0.1",
                "port": xray_tls_auth_port,
                "protocol": "http",
                "settings": {
                    "accounts": [{
                        "user": username,
                        "pass": password
                    }]
                },
                "streamSettings": {
                    "network": "tcp",
                    "security": "tls",
                    "tlsSettings": {
                        "certificates": [{
                            "certificateFile": cert_pem_path.to_str().unwrap(),
                            "keyFile": key_pem_path.to_str().unwrap()
                        }]
                    }
                }
            }
        ],
        "outbounds": [{
            "protocol": "freedom",
            "settings": {
                "finalRules": [{ "action": "allow" }]
            }
        }]
    });
    std::fs::write(&srv_cfg_path, serde_json::to_vec_pretty(&srv_cfg).unwrap()).unwrap();

    let mut xray_srv = ChildGuard(
        clean_loopback_command(&xray_bin)
            .args(["run", "-c", srv_cfg_path.to_str().unwrap()])
            .spawn()
            .expect("spawn xray http server"),
    );
    wait_tcp_ready(xray_plain_port, &mut xray_srv, "xray http plain server").await;
    wait_tcp_ready(xray_tls_auth_port, &mut xray_srv, "xray https+auth server").await;

    let payload: Vec<u8> = (0..131_072).map(|i| ((i * 97 + 23) & 0xFF) as u8).collect();

    // A1: Plain HTTP CONNECT
    let plain_http = HttpOutbound::new(HttpOutboundConfig {
        name: "http-plain".into(),
        server: "127.0.0.1".into(),
        port: xray_plain_port,
        username: None,
        password: None,
        tls: false,
        sni: None,
        skip_cert_verify: false,
        extra_ca_der: vec![],
        headers: Default::default(),
    })
    .unwrap();
    let mut s_plain = plain_http
        .connect_tcp(&tcp_target)
        .await
        .expect("HttpOutbound plain -> xray");
    s_plain.write_all(&payload).await.unwrap();
    s_plain.flush().await.unwrap();
    let mut echoed_plain = vec![0u8; payload.len()];
    s_plain.read_exact(&mut echoed_plain).await.unwrap();
    assert_eq!(echoed_plain, payload, "HTTP plain 128KB mismatch");

    // Negative check: wrong Basic Auth against HTTPS proxy must return PermissionDenied (407)
    let bad_https = HttpOutbound::new(HttpOutboundConfig {
        name: "https-bad-auth".into(),
        server: "127.0.0.1".into(),
        port: xray_tls_auth_port,
        username: Some(username.into()),
        password: Some("wrong-secret".into()),
        tls: true,
        sni: Some(sni.into()),
        skip_cert_verify: false,
        extra_ca_der: vec![ca_der.clone()],
        headers: Default::default(),
    })
    .unwrap();
    let bad_err = bad_https
        .connect_tcp(&tcp_target)
        .await
        .err()
        .expect("wrong HTTP Basic Auth must fail");
    assert_eq!(bad_err.kind(), std::io::ErrorKind::PermissionDenied);

    // A2: HTTPS CONNECT + Basic Auth + verified X.509 certificate
    let auth_https = HttpOutbound::new(HttpOutboundConfig {
        name: "https-auth".into(),
        server: "127.0.0.1".into(),
        port: xray_tls_auth_port,
        username: Some(username.into()),
        password: Some(password.into()),
        tls: true,
        sni: Some(sni.into()),
        skip_cert_verify: false,
        extra_ca_der: vec![ca_der],
        headers: std::collections::HashMap::from([(
            "X-Interop-Client".to_string(),
            "rust-clash".to_string(),
        )]),
    })
    .unwrap();
    let mut s_tls = auth_https
        .connect_tcp(&tcp_target)
        .await
        .expect("HttpOutbound HTTPS+Auth -> xray");
    s_tls.write_all(&payload).await.unwrap();
    s_tls.flush().await.unwrap();
    let mut echoed_tls = vec![0u8; payload.len()];
    s_tls.read_exact(&mut echoed_tls).await.unwrap();
    assert_eq!(echoed_tls, payload, "HTTPS+Auth 128KB mismatch");
    drop(xray_srv);

    // =========================================================================
    // Direction B: official `xray` HTTP Outbound -> `spawn_http_connect_server`
    // =========================================================================
    let (our_srv_addr, _our_srv_task) = spawn_http_connect_server(
        HttpConnectServerConfig {
            listen_addr: "127.0.0.1:0".into(),
            credentials: Some((username.into(), password.into())),
        },
        shutdown_rx.clone(),
    )
    .await
    .unwrap();

    let xray_socks_port = reserve_free_port();
    let cli_cfg_path = tmp_dir.path().join("xray_http_cli.json");
    let cli_cfg = json!({
        "log": { "loglevel": "warning" },
        "inbounds": [{
            "listen": "127.0.0.1",
            "port": xray_socks_port,
            "protocol": "socks",
            "settings": { "udp": false }
        }],
        "outbounds": [{
            "protocol": "http",
            "settings": {
                "servers": [{
                    "address": "127.0.0.1",
                    "port": our_srv_addr.port(),
                    "users": [{
                        "user": username,
                        "pass": password
                    }]
                }]
            }
        }]
    });
    std::fs::write(&cli_cfg_path, serde_json::to_vec_pretty(&cli_cfg).unwrap()).unwrap();

    let mut xray_cli = ChildGuard(
        clean_loopback_command(&xray_bin)
            .args(["run", "-c", cli_cfg_path.to_str().unwrap()])
            .spawn()
            .expect("spawn xray http client"),
    );
    wait_tcp_ready(xray_socks_port, &mut xray_cli, "xray http client").await;

    let recv_b = socks5_tcp_roundtrip(xray_socks_port, tcp_echo, &payload).await;
    assert_eq!(
        recv_b, payload,
        "xray -> spawn_http_connect_server 128KB mismatch"
    );
    drop(xray_cli);

    let _ = shutdown_tx.send(true);
}

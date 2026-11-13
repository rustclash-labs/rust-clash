use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use axum::{
    Json, Router as AxumRouter, extract::Query, http::StatusCode, response::IntoResponse,
    routing::get,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use parking_lot::{Mutex, RwLock};
use rustls::pki_types::CertificateDer;
use serde::{Deserialize, Serialize};
use tokio::{
    net::{TcpListener, UdpSocket},
    sync::{Mutex as AsyncMutex, Semaphore, watch},
    task::JoinHandle,
};
use uuid::Uuid;

use crate::{
    config::{
        ClashConfig, DnsConfig, ProxyGroupConfig, ProxyGroupType, ProxyNodeConfig, REDACTED_SECRET,
        RunMode, TunConfig,
    },
    crypto::tls::generate_self_signed_server_config,
    dns::FakeIpDnsEngine,
    error::{ProxyError, Result},
    inbound::{
        mixed::{MixedInboundPolicy, spawn_mixed_inbound_with_policy},
        tun::{OsTunGuard, VirtualTunHandle, attach_os_tun_with_spec, spawn_userspace_tun},
    },
    outbound::{
        DirectOutbound, DynOutbound, RejectOutbound,
        anytls::{
            AnyTlsOutbound, AnyTlsOutboundConfig, AnyTlsServerConfig, padding::PaddingScheme,
            spawn_anytls_server,
        },
        http_proxy::{HttpOutbound, HttpOutboundConfig},
        socks5::{Socks5Outbound, Socks5OutboundConfig},
        ss::{ShadowsocksOutbound, spawn_ss_server},
        trojan::{TrojanOutbound, TrojanOutboundConfig},
        vless::{
            VlessOutbound, VlessOutboundConfig, VlessServerConfig,
            encryption::{config::XorMode, generate_vless_encryption_pair},
            spawn_vless_server,
        },
    },
    platform::{
        recovery::{default_state_dir, recover_stale_network_state},
        tun::{DEFAULT_TUN_IPV6_CIDR, TunHealthSnapshot, TunLaunchSpec, preflight_system_tun},
    },
    router::Router,
    tracker::TelemetryHub,
};

/// Build concrete `DynOutbound` instances from `ClashConfig::proxies`.
pub fn build_outbounds(
    nodes: &[ProxyNodeConfig],
    extra_ca_der: &[CertificateDer<'static>],
) -> Result<HashMap<String, DynOutbound>> {
    build_outbounds_with_dns(nodes, extra_ca_der, None)
}

/// Build concrete `DynOutbound` instances wired to `FakeIpDnsEngine` so `DIRECT` domain
/// resolution uses Mainland-safe `direct-nameserver` and domain-based proxy servers resolve
/// via protected bootstrap DNS without Fake-IP self-loops.
pub fn build_outbounds_with_dns(
    nodes: &[ProxyNodeConfig],
    extra_ca_der: &[CertificateDer<'static>],
    dns: Option<Arc<FakeIpDnsEngine>>,
) -> Result<HashMap<String, DynOutbound>> {
    let mut map: HashMap<String, DynOutbound> = HashMap::new();
    let direct_ob = match &dns {
        Some(d) => DirectOutbound::with_dns("DIRECT", Arc::clone(d)),
        None => DirectOutbound::default(),
    };
    map.insert("DIRECT".to_string(), Arc::new(direct_ob));
    map.insert("REJECT".to_string(), Arc::new(RejectOutbound::default()));

    for node in nodes {
        let ws_opts = node.effective_ws_opts();
        match node {
            ProxyNodeConfig::Ss {
                name,
                server,
                port,
                cipher,
                password,
                udp,
            } => {
                let ob = ShadowsocksOutbound::new(name, server, *port, cipher, password, *udp)
                    .map_err(|e| ProxyError::Config(format!("SS node '{name}': {e}")))?
                    .with_dns(dns.clone());
                map.insert(name.clone(), Arc::new(ob));
            }
            ProxyNodeConfig::Vless {
                name,
                server,
                port,
                uuid,
                encryption,
                tls,
                servername,
                skip_cert_verify,
                alpn,
                flow,
                network: _,
                ws_opts: _,
                udp,
            } => {
                if let Some(f) = flow.as_deref().map(str::trim)
                    && !f.is_empty()
                    && !f.eq_ignore_ascii_case("none")
                {
                    return Err(ProxyError::Config(format!(
                        "VLESS node '{name}': unsupported flow '{f}'"
                    )));
                }
                let alpn_bytes = alpn.iter().map(|s| s.as_bytes().to_vec()).collect();
                let ob = VlessOutbound::new_with_transport(
                    VlessOutboundConfig {
                        name: name.clone(),
                        server: server.clone(),
                        port: *port,
                        uuid: *uuid,
                        encryption: encryption.clone(),
                        tls: *tls,
                        servername: servername.clone(),
                        skip_cert_verify: *skip_cert_verify,
                        alpn: alpn_bytes,
                        extra_ca_der: extra_ca_der.to_vec(),
                        udp: *udp,
                    },
                    ws_opts,
                    dns.clone(),
                )
                .map_err(|e| ProxyError::Config(format!("VLESS node '{name}': {e}")))?;
                map.insert(name.clone(), Arc::new(ob));
            }
            ProxyNodeConfig::Anytls {
                name,
                server,
                port,
                password,
                sni,
                skip_cert_verify,
                alpn,
                idle_session_check_interval,
                idle_session_timeout,
                min_idle_session,
                udp,
            } => {
                let alpn_bytes = alpn.iter().map(|s| s.as_bytes().to_vec()).collect();
                let ob = AnyTlsOutbound::new(AnyTlsOutboundConfig {
                    name: name.clone(),
                    server: server.clone(),
                    port: *port,
                    password: password.clone(),
                    sni: sni.clone().unwrap_or_else(|| server.clone()),
                    skip_cert_verify: *skip_cert_verify,
                    alpn: alpn_bytes,
                    extra_ca_der: extra_ca_der.to_vec(),
                    idle_session_check_interval: Duration::from_secs(
                        (*idle_session_check_interval).max(5),
                    ),
                    idle_session_timeout: Duration::from_secs((*idle_session_timeout).max(10)),
                    min_idle_session: *min_idle_session,
                    udp: *udp,
                })
                .map_err(|e| ProxyError::Config(format!("AnyTLS node '{name}': {e}")))?
                .with_dns(dns.clone());
                map.insert(name.clone(), Arc::new(ob));
            }
            ProxyNodeConfig::Trojan {
                name,
                server,
                port,
                password,
                tls,
                sni,
                skip_cert_verify,
                alpn,
                network: _,
                ws_opts: _,
                udp,
            } => {
                let alpn_bytes = alpn.iter().map(|s| s.as_bytes().to_vec()).collect();
                let ob = TrojanOutbound::new_with_dns(
                    TrojanOutboundConfig {
                        name: name.clone(),
                        server: server.clone(),
                        port: *port,
                        password: password.clone(),
                        tls: *tls,
                        sni: sni.clone(),
                        skip_cert_verify: *skip_cert_verify,
                        alpn: alpn_bytes,
                        ws_opts,
                        extra_ca_der: extra_ca_der.to_vec(),
                        udp: *udp,
                    },
                    dns.clone(),
                )
                .map_err(|e| ProxyError::Config(format!("Trojan node '{name}': {e}")))?;
                map.insert(name.clone(), Arc::new(ob));
            }
            ProxyNodeConfig::Socks5 {
                name,
                server,
                port,
                username,
                password,
                tls,
                sni,
                skip_cert_verify,
                udp,
            } => {
                let ob = Socks5Outbound::new_with_dns(
                    Socks5OutboundConfig {
                        name: name.clone(),
                        server: server.clone(),
                        port: *port,
                        username: username.clone(),
                        password: password.clone(),
                        tls: *tls,
                        sni: sni.clone(),
                        skip_cert_verify: *skip_cert_verify,
                        extra_ca_der: extra_ca_der.to_vec(),
                        udp: *udp,
                    },
                    dns.clone(),
                )
                .map_err(|e| ProxyError::Config(format!("SOCKS5 node '{name}': {e}")))?;
                map.insert(name.clone(), Arc::new(ob));
            }
            ProxyNodeConfig::Http {
                name,
                server,
                port,
                username,
                password,
                tls,
                sni,
                skip_cert_verify,
                headers,
            } => {
                let ob = HttpOutbound::new_with_dns(
                    HttpOutboundConfig {
                        name: name.clone(),
                        server: server.clone(),
                        port: *port,
                        username: username.clone(),
                        password: password.clone(),
                        tls: *tls,
                        sni: sni.clone(),
                        skip_cert_verify: *skip_cert_verify,
                        headers: headers.clone(),
                        extra_ca_der: extra_ca_der.to_vec(),
                    },
                    dns.clone(),
                )
                .map_err(|e| ProxyError::Config(format!("HTTP proxy node '{name}': {e}")))?;
                map.insert(name.clone(), Arc::new(ob));
            }
        }
    }

    Ok(map)
}

/// Self-contained local loopback protocol server cluster for instant live showcase,
/// latency testing, and high-throughput encryption benchmarking out-of-the-box!
pub struct DemoCluster {
    pub http_target_addr: SocketAddr,
    pub ss2022_addr: SocketAddr,
    pub ss_chacha_addr: SocketAddr,
    pub vless_pq_native_0rtt_addr: SocketAddr,
    pub vless_pq_xorpub_1rtt_addr: SocketAddr,
    pub vless_pq_random_0rtt_addr: SocketAddr,
    pub anytls_v2_addr: SocketAddr,
    pub trusted_ca_der: CertificateDer<'static>,
    shutdown_tx: watch::Sender<bool>,
    _tasks: Vec<JoinHandle<()>>,
}

#[derive(Deserialize)]
struct BytesQuery {
    #[serde(default = "default_bench_bytes")]
    n: usize,
}

fn default_bench_bytes() -> usize {
    262_144
}

impl DemoCluster {
    /// Start real local SS-2022, SS-ChaCha20, VLESS+PQ (`native.0rtt`, `xorpub.1rtt`, `random.0rtt`),
    /// AnyTLS v2, and HTTP benchmark/echo/204 servers on `127.0.0.1:0`.
    pub async fn start() -> Result<(Self, ClashConfig)> {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let mut tasks = Vec::new();

        // 1. Local HTTP 204 / Echo / Throughput Benchmark target server
        let http_listener = TcpListener::bind("127.0.0.1:0").await?;
        let http_target_addr = http_listener.local_addr()?;
        let mut http_stop = shutdown_rx.clone();
        let app = AxumRouter::new()
            .route("/generate_204", get(|| async { StatusCode::NO_CONTENT }))
            .route(
                "/echo",
                get(|| async {
                    Json(serde_json::json!({
                        "service": "rust-clash-demo-origin",
                        "ok": true,
                        "timestamp_ms": TelemetryHub::now_ms(),
                    }))
                })
                .post(|body: axum::body::Bytes| async move {
                    (
                        StatusCode::OK,
                        [("content-type", "application/octet-stream")],
                        body,
                    )
                }),
            )
            .route(
                "/bytes",
                get(|Query(q): Query<BytesQuery>| async move {
                    let size = q.n.clamp(64, 4 * 1024 * 1024);
                    let mut payload = vec![0u8; size];
                    for (idx, b) in payload.iter_mut().enumerate() {
                        *b = (idx.wrapping_mul(31).wrapping_add(17) & 0xFF) as u8;
                    }
                    (
                        StatusCode::OK,
                        [("content-type", "application/octet-stream")],
                        payload,
                    )
                        .into_response()
                }),
            );
        tasks.push(tokio::spawn(async move {
            let _ = axum::serve(http_listener, app)
                .with_graceful_shutdown(async move {
                    let _ = http_stop.changed().await;
                })
                .await;
        }));

        // 2. Shadowsocks-2022 (`2022-blake3-aes-256-gcm` requires 32-byte base64 PSK)
        let ss2022_psk = STANDARD.encode([0x42u8; 32]);
        let (ss2022_addr, t_ss2022) = spawn_ss_server(
            "127.0.0.1:0",
            "2022-blake3-aes-256-gcm",
            &ss2022_psk,
            shutdown_rx.clone(),
        )
        .await?;
        tasks.push(t_ss2022);

        // 3. Shadowsocks Legacy AEAD (`chacha20-ietf-poly1305`)
        let ss_chacha_pass = "rust-clash-chacha-secret-2026";
        let (ss_chacha_addr, t_sschacha) = spawn_ss_server(
            "127.0.0.1:0",
            "chacha20-ietf-poly1305",
            ss_chacha_pass,
            shutdown_rx.clone(),
        )
        .await?;
        tasks.push(t_sschacha);

        // 4. VLESS + PQ Encryption (`mlkem768x25519plus.native.0rtt`)
        let vless_uuid = Uuid::new_v4();
        let pq_native = generate_vless_encryption_pair(XorMode::Native, true, true)?;
        let (vless_pq_native_0rtt_addr, t_vn) = spawn_vless_server(
            VlessServerConfig {
                listen_addr: "127.0.0.1:0".to_string(),
                allowed_uuid: vless_uuid,
                decryption: pq_native.decryption.clone(),
                tls_config: None,
            },
            shutdown_rx.clone(),
        )
        .await?;
        tasks.push(t_vn);

        // 5. VLESS + PQ Encryption (`mlkem768x25519plus.xorpub.1rtt`)
        let pq_xorpub = generate_vless_encryption_pair(XorMode::XorPub, false, true)?;
        let (vless_pq_xorpub_1rtt_addr, t_vx) = spawn_vless_server(
            VlessServerConfig {
                listen_addr: "127.0.0.1:0".to_string(),
                allowed_uuid: vless_uuid,
                decryption: pq_xorpub.decryption.clone(),
                tls_config: None,
            },
            shutdown_rx.clone(),
        )
        .await?;
        tasks.push(t_vx);

        // 6. VLESS + PQ Encryption (`mlkem768x25519plus.random.0rtt`)
        let pq_random = generate_vless_encryption_pair(XorMode::Random, true, true)?;
        let (vless_pq_random_0rtt_addr, t_vr) = spawn_vless_server(
            VlessServerConfig {
                listen_addr: "127.0.0.1:0".to_string(),
                allowed_uuid: vless_uuid,
                decryption: pq_random.decryption.clone(),
                tls_config: None,
            },
            shutdown_rx.clone(),
        )
        .await?;
        tasks.push(t_vr);

        // 7. AnyTLS v2 Server (TLS 1.3 + SHA-256 + dynamic padding scheme + session multiplexing)
        let (tls_server_cfg, cert_der) = generate_self_signed_server_config(
            &[
                "anytls.rust-clash.local".to_string(),
                "localhost".to_string(),
                "127.0.0.1".to_string(),
            ],
            &[b"h2".to_vec(), b"http/1.1".to_vec()],
        )?;
        let anytls_pass = "anytls-v2-flagship-key";
        let custom_scheme = PaddingScheme::parse(
            "stop=8\n0=30-100\n1=100-400\n2=400-500,c,500-1000\n3=500-1000\n4=500-1000\n5=500-1000\n6=500-1000\n7=500-1000",
        )
        .map_err(|e| ProxyError::Config(format!("demo padding scheme: {e}")))?;
        let (anytls_v2_addr, t_anytls) = spawn_anytls_server(
            AnyTlsServerConfig {
                listen_addr: "127.0.0.1:0".to_string(),
                password: anytls_pass.to_string(),
                tls_config: tls_server_cfg,
                padding_scheme: custom_scheme,
            },
            shutdown_rx.clone(),
        )
        .await?;
        tasks.push(t_anytls);

        let health_url = format!("http://{http_target_addr}/generate_204");
        let n_ss2022 = "HK-SS2022-Blake3-AES256".to_string();
        let n_sschacha = "SG-SS-ChaCha20-Poly1305".to_string();
        let n_vless_nat = "TYO-VLESS-PQ-Native-0RTT".to_string();
        let n_vless_xor = "SJC-VLESS-PQ-XorPub-1RTT".to_string();
        let n_vless_rnd = "FRA-VLESS-PQ-Random-0RTT".to_string();
        let n_anytls = "LAX-AnyTLS-v2-MuxPool".to_string();

        let all_nodes = vec![
            n_vless_nat.clone(),
            n_anytls.clone(),
            n_ss2022.clone(),
            n_vless_xor.clone(),
            n_vless_rnd.clone(),
            n_sschacha.clone(),
        ];

        let cfg = ClashConfig {
            mixed_port: 7890,
            bind_address: "127.0.0.1".to_string(),
            allow_lan: false,
            authentication: Vec::new(),
            lan_allowed_ips: Vec::new(),
            mode: RunMode::Rule,
            unified_delay: true,
            log_level: "info".to_string(),
            external_controller: "127.0.0.1:9090".to_string(),
            secret: None,
            geodata_mode: false,
            mmdb_path: None,
            hosts: HashMap::new(),
            dns: DnsConfig {
                enable: true,
                listen: "127.0.0.1:1053".to_string(),
                ipv6: false,
                enhanced_mode: "fake-ip".to_string(),
                fake_ip_range: "198.18.0.0/15".to_string(),
                fake_ip_filter: vec![
                    "localhost".to_string(),
                    "*.lan".to_string(),
                    "+.msftconnecttest.com".to_string(),
                ],
                default_nameserver: vec!["1.1.1.1:53".to_string(), "8.8.8.8:53".to_string()],
                direct_nameserver: vec!["223.5.5.5:53".to_string(), "119.29.29.29:53".to_string()],
                nameserver: vec!["1.1.1.1:53".to_string(), "8.8.8.8:53".to_string()],
                fallback: Vec::new(),
                ..Default::default()
            },
            // Default `tun.enable` to `false` with `auto_route: true` so we NEVER falsely report
            // system TUN as active unless an OS TUN interface is genuinely attached!
            tun: TunConfig {
                enable: false,
                stack: "smoltcp".to_string(),
                device: "utun-clash0".to_string(),
                auto_route: true,
                auto_detect_interface: true,
                dns_hijack: true,
                strict_route: false,
                ipv6: false,
                inet6_address: None,
                wintun_path: None,
                mtu: 1500,
            },
            proxies: vec![
                ProxyNodeConfig::Vless {
                    name: n_vless_nat.clone(),
                    server: "127.0.0.1".to_string(),
                    port: vless_pq_native_0rtt_addr.port(),
                    uuid: vless_uuid,
                    encryption: pq_native.encryption,
                    tls: false,
                    servername: None,
                    skip_cert_verify: false,
                    alpn: vec![],
                    flow: None,
                    network: None,
                    ws_opts: None,
                    udp: true,
                },
                ProxyNodeConfig::Anytls {
                    name: n_anytls.clone(),
                    server: "127.0.0.1".to_string(),
                    port: anytls_v2_addr.port(),
                    password: anytls_pass.to_string(),
                    sni: Some("anytls.rust-clash.local".to_string()),
                    skip_cert_verify: false,
                    alpn: vec!["h2".to_string(), "http/1.1".to_string()],
                    idle_session_check_interval: 15,
                    idle_session_timeout: 60,
                    min_idle_session: 2,
                    udp: false,
                },
                ProxyNodeConfig::Ss {
                    name: n_ss2022.clone(),
                    server: "127.0.0.1".to_string(),
                    port: ss2022_addr.port(),
                    cipher: "2022-blake3-aes-256-gcm".to_string(),
                    password: ss2022_psk,
                    udp: true,
                },
                ProxyNodeConfig::Vless {
                    name: n_vless_xor.clone(),
                    server: "127.0.0.1".to_string(),
                    port: vless_pq_xorpub_1rtt_addr.port(),
                    uuid: vless_uuid,
                    encryption: pq_xorpub.encryption,
                    tls: false,
                    servername: None,
                    skip_cert_verify: false,
                    alpn: vec![],
                    flow: None,
                    network: None,
                    ws_opts: None,
                    udp: true,
                },
                ProxyNodeConfig::Vless {
                    name: n_vless_rnd.clone(),
                    server: "127.0.0.1".to_string(),
                    port: vless_pq_random_0rtt_addr.port(),
                    uuid: vless_uuid,
                    encryption: pq_random.encryption,
                    tls: false,
                    servername: None,
                    skip_cert_verify: false,
                    alpn: vec![],
                    flow: None,
                    network: None,
                    ws_opts: None,
                    udp: true,
                },
                ProxyNodeConfig::Ss {
                    name: n_sschacha.clone(),
                    server: "127.0.0.1".to_string(),
                    port: ss_chacha_addr.port(),
                    cipher: "chacha20-ietf-poly1305".to_string(),
                    password: ss_chacha_pass.to_string(),
                    udp: true,
                },
            ],
            proxy_groups: vec![
                ProxyGroupConfig {
                    name: "🚀 Proxy".to_string(),
                    group_type: ProxyGroupType::Select,
                    proxies: {
                        let mut p = vec!["⚡ Auto-Best".to_string(), "🛡️ Fallback-PQ".to_string()];
                        p.extend(all_nodes.clone());
                        p.push("DIRECT".to_string());
                        p
                    },
                    url: health_url.clone(),
                    interval: 60,
                    tolerance: 30,
                    strategy: None,
                },
                ProxyGroupConfig {
                    name: "⚡ Auto-Best".to_string(),
                    group_type: ProxyGroupType::UrlTest,
                    proxies: all_nodes.clone(),
                    url: health_url.clone(),
                    interval: 30,
                    tolerance: 25,
                    strategy: None,
                },
                ProxyGroupConfig {
                    name: "🛡️ Fallback-PQ".to_string(),
                    group_type: ProxyGroupType::Fallback,
                    proxies: vec![n_vless_nat, n_vless_rnd, n_vless_xor, n_anytls, n_ss2022],
                    url: health_url.clone(),
                    interval: 30,
                    tolerance: 50,
                    strategy: None,
                },
                ProxyGroupConfig {
                    name: "⚖️ Balance-MultiProto".to_string(),
                    group_type: ProxyGroupType::LoadBalance,
                    proxies: all_nodes,
                    url: health_url,
                    interval: 60,
                    tolerance: 50,
                    strategy: Some("round-robin".to_string()),
                },
            ],
            rule_providers: HashMap::new(),
            rules: vec![
                format!("DST-PORT,{},🚀 Proxy", http_target_addr.port()),
                "DOMAIN-SUFFIX,anthropic.com,🚀 Proxy".to_string(),
                "DOMAIN-SUFFIX,openai.com,🚀 Proxy".to_string(),
                "DOMAIN-SUFFIX,github.com,🚀 Proxy".to_string(),
                "DOMAIN-SUFFIX,googleapis.com,⚡ Auto-Best".to_string(),
                "DOMAIN-KEYWORD,google,⚡ Auto-Best".to_string(),
                "DOMAIN-SUFFIX,ads.example.com,REJECT".to_string(),
                "GEOIP,CLOUDFLARE,🛡️ Fallback-PQ".to_string(),
                "GEOIP,TELEGRAM,🚀 Proxy".to_string(),
                "GEOIP,CN,DIRECT".to_string(),
                "IP-CIDR,10.0.0.0/8,DIRECT".to_string(),
                "MATCH,🚀 Proxy".to_string(),
            ],
        };

        Ok((
            Self {
                http_target_addr,
                ss2022_addr,
                ss_chacha_addr,
                vless_pq_native_0rtt_addr,
                vless_pq_xorpub_1rtt_addr,
                vless_pq_random_0rtt_addr,
                anytls_v2_addr,
                trusted_ca_der: cert_der,
                shutdown_tx,
                _tasks: tasks,
            },
            cfg,
        ))
    }

    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
    }
}

impl Drop for DemoCluster {
    fn drop(&mut self) {
        let _ = self.shutdown_tx.send(true);
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct DemoClusterInfo {
    pub enabled: bool,
    pub http_benchmark_origin: String,
    pub endpoints: HashMap<String, String>,
}

/// Real runtime state of the `smoltcp` TUN subsystem.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum TunRuntimeMode {
    /// TUN subsystem is stopped.
    Disabled,
    /// In-process L3 packet channel mode (`auto-route: false`, no OS network interface attached).
    Virtual,
    /// Attached to a real OS kernel TUN interface with configured IP/MTU/routes (`auto-route: true`).
    OsTun,
}

impl TunRuntimeMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::Virtual => "virtual",
            Self::OsTun => "os-tun",
        }
    }
}

struct MixedService {
    listen_spec: String,
    bound_addr: SocketAddr,
    shutdown_tx: watch::Sender<bool>,
    task: JoinHandle<()>,
}

impl MixedService {
    async fn stop(self) {
        let _ = self.shutdown_tx.send(true);
        let _ = self.task.await;
    }
}

struct DnsService {
    listen_spec: String,
    bound_addr: SocketAddr,
    shutdown_tx: watch::Sender<bool>,
    udp_task: JoinHandle<()>,
    tcp_task: JoinHandle<()>,
}

impl DnsService {
    async fn stop(self) {
        let _ = self.shutdown_tx.send(true);
        let _ = self.udp_task.await;
        let _ = self.tcp_task.await;
    }
}

struct TunService {
    config: TunConfig,
    mode: TunRuntimeMode,
    shutdown_tx: watch::Sender<bool>,
    task: JoinHandle<()>,
    os_guard: Option<Arc<OsTunGuard>>,
}

impl TunService {
    async fn stop(mut self) {
        // Stop OS TUN session first so reader/writer threads terminate and kernel routes are restored cleanly
        if let Some(guard) = self.os_guard.take() {
            guard.stop_now();
        }
        let _ = self.shutdown_tx.send(true);
        let _ = self.task.await;
    }
}

struct RuntimeServices {
    mixed: MixedService,
    dns: Option<DnsService>,
    tun: Option<TunService>,
}

fn mixed_listen_spec(cfg: &ClashConfig) -> String {
    let bind_host = if cfg.allow_lan || cfg.bind_address.trim() == "*" {
        "0.0.0.0"
    } else {
        cfg.bind_address.trim()
    };
    format!("{bind_host}:{}", cfg.mixed_port)
}

fn collect_bypass_ips(cfg: &ClashConfig, dns: &FakeIpDnsEngine) -> Vec<IpAddr> {
    let mut ips = Vec::new();
    for node in &cfg.proxies {
        let (srv, _) = node.server_port();
        let srv = srv.trim();
        if let Ok(ip) = srv.parse::<IpAddr>()
            && !ips.contains(&ip)
        {
            ips.push(ip);
        }
    }
    for ns_ip in dns.upstream_bypass_ips() {
        if !ips.contains(&ns_ip) {
            ips.push(ns_ip);
        }
    }
    ips
}

fn load_optional_mmdb(cfg: &ClashConfig) -> Result<Option<Arc<crate::router::mmdb::MmdbReader>>> {
    if let Some(ref p) = cfg.mmdb_path
        && !p.trim().is_empty()
    {
        let reader = crate::router::mmdb::MmdbReader::from_file(p.trim())?;
        return Ok(Some(Arc::new(reader)));
    }
    Ok(None)
}

async fn spawn_dynamic_dns_server(
    listen_addr: &str,
    router_slot: Arc<RwLock<Arc<Router>>>,
    shutdown: watch::Receiver<bool>,
) -> Result<(SocketAddr, JoinHandle<()>, JoinHandle<()>)> {
    let is_ephemeral = listen_addr
        .parse::<SocketAddr>()
        .is_ok_and(|addr| addr.port() == 0);
    let max_attempts = if is_ephemeral { 16 } else { 1 };
    let mut held_udp = Vec::new();
    let mut bound_pair = None;
    let mut last_tcp_err = None;
    for _ in 0..max_attempts {
        let candidate_udp = UdpSocket::bind(listen_addr).await.map_err(|e| {
            ProxyError::Io(std::io::Error::new(
                e.kind(),
                format!("bind DNS UDP {listen_addr}: {e}"),
            ))
        })?;
        let candidate_bound = candidate_udp.local_addr()?;
        match TcpListener::bind(candidate_bound).await {
            Ok(tcp) => {
                bound_pair = Some((Arc::new(candidate_udp), candidate_bound, tcp));
                break;
            }
            Err(e) => {
                last_tcp_err = Some((candidate_bound, e));
                held_udp.push(candidate_udp);
            }
        }
    }
    drop(held_udp);
    let (sock, bound, tcp_listener) = match bound_pair {
        Some(pair) => pair,
        None => {
            let (failed_bound, e) = last_tcp_err.expect("at least one DNS bind attempt ran");
            return Err(ProxyError::Io(std::io::Error::new(
                e.kind(),
                format!("bind DNS TCP {failed_bound}: {e}"),
            )));
        }
    };

    let inflight_udp = Arc::new(Semaphore::new(256));
    let mut udp_shutdown = shutdown.clone();
    let router_udp = Arc::clone(&router_slot);
    let udp_handle = tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            tokio::select! {
                changed = udp_shutdown.changed() => {
                    if changed.is_err() || *udp_shutdown.borrow() {
                        break;
                    }
                }
                recv_res = sock.recv_from(&mut buf) => {
                    let Ok((n, peer)) = recv_res else {
                        continue;
                    };
                    let Ok(permit) = Arc::clone(&inflight_udp).try_acquire_owned() else {
                        continue;
                    };
                    let pkt = buf[..n].to_vec();
                    let sock_clone = Arc::clone(&sock);
                    let dns_engine = Arc::clone(router_udp.read().dns());
                    tokio::spawn(async move {
                        let _permit = permit;
                        if let Ok(resp) = dns_engine.handle_dns_packet(&pkt).await {
                            let _ = sock_clone.send_to(&resp, peer).await;
                        }
                    });
                }
            }
        }
    });

    let inflight_tcp = Arc::new(Semaphore::new(128));
    let mut tcp_shutdown = shutdown;
    let router_tcp = router_slot;
    let tcp_handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                changed = tcp_shutdown.changed() => {
                    if changed.is_err() || *tcp_shutdown.borrow() {
                        break;
                    }
                }
                accepted = tcp_listener.accept() => {
                    let Ok((mut stream, _peer)) = accepted else {
                        continue;
                    };
                    let Ok(permit) = Arc::clone(&inflight_tcp).try_acquire_owned() else {
                        continue;
                    };
                    let router_conn = Arc::clone(&router_tcp);
                    tokio::spawn(async move {
                        use bytes::{BufMut, BytesMut};
                        use tokio::io::{AsyncReadExt, AsyncWriteExt};
                        let _permit = permit;
                        let _ = stream.set_nodelay(true);
                        for _ in 0..32 {
                            let len = match tokio::time::timeout(
                                Duration::from_secs(5),
                                stream.read_u16(),
                            )
                            .await
                            {
                                Ok(Ok(l)) if (12..=8192).contains(&l) => l as usize,
                                _ => break,
                            };
                            let mut req = vec![0u8; len];
                            if tokio::time::timeout(
                                Duration::from_secs(5),
                                stream.read_exact(&mut req),
                            )
                            .await
                            .is_err()
                            {
                                break;
                            }
                            let dns_engine = Arc::clone(router_conn.read().dns());
                            let Ok(resp) = dns_engine.handle_dns_packet(&req).await else {
                                break;
                            };
                            if resp.len() > u16::MAX as usize {
                                break;
                            }
                            let mut frame = BytesMut::with_capacity(2 + resp.len());
                            frame.put_u16(resp.len() as u16);
                            frame.put_slice(&resp);
                            if tokio::time::timeout(
                                Duration::from_secs(5),
                                stream.write_all(&frame),
                            )
                            .await
                            .is_err()
                            {
                                break;
                            }
                        }
                    });
                }
            }
        }
    });

    Ok((bound, udp_handle, tcp_handle))
}

/// Summary of sockets and cached state reset during a network interface handoff.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct NetworkChangeReport {
    pub closed_active_connections: usize,
    pub reset_udp_nat_sessions: usize,
    pub evicted_tls_sessions: usize,
    pub dns_cache_flushed: bool,
}

fn execute_network_change_reset(router: &Router, hub: &TelemetryHub) -> NetworkChangeReport {
    let reset_udp_nat_sessions = hub.reset_udp_nat_sessions();
    let evicted_tls_sessions = router.notify_network_change();
    let closed_active_connections = hub.close_all_connections();
    hub.push_log(
        "info",
        format!(
            "[Network] Interface handoff recovery: closed_connections={closed_active_connections}, reset_udp_nat={reset_udp_nat_sessions}, evicted_tls_pool={evicted_tls_sessions}, dns_flushed=true"
        ),
    );
    NetworkChangeReport {
        closed_active_connections,
        reset_udp_nat_sessions,
        evicted_tls_sessions,
        dns_cache_flushed: true,
    }
}

fn start_tun_service(
    cfg: &ClashConfig,
    dns: &Arc<FakeIpDnsEngine>,
    local_dns_addr: Option<SocketAddr>,
    router_slot: Arc<RwLock<Arc<Router>>>,
    hub: Arc<TelemetryHub>,
    preconnect_wake: Arc<tokio::sync::Notify>,
    state_dir: PathBuf,
) -> std::result::Result<(TunService, Option<VirtualTunHandle>), std::io::Error> {
    let (tun_stop_tx, tun_stop_rx) = watch::channel(false);
    let (vtun, t_tun) = spawn_userspace_tun(
        cfg.tun.mtu,
        Arc::clone(&router_slot),
        Arc::clone(&hub),
        tun_stop_rx,
    );

    if cfg.tun.auto_route {
        let bypass_ips = collect_bypass_ips(cfg, dns);
        let fake_ip_net = dns.fake_ip_net();
        let gw_v4 = dns.gateway_ipv4();
        let tun_ipv4_cidr =
            ipnet::Ipv4Net::new(gw_v4, fake_ip_net.prefix_len()).unwrap_or(fake_ip_net);
        let tun_ipv6_cidr = cfg
            .tun
            .inet6_address
            .as_deref()
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| {
                DEFAULT_TUN_IPV6_CIDR
                    .parse()
                    .expect("valid default IPv6 CIDR")
            });
        let enable_ipv6 = cfg.tun.ipv6 || cfg.tun.inet6_address.is_some();

        let router_for_hook = Arc::clone(&router_slot);
        let hub_for_hook = Arc::clone(&hub);
        let pc_wake_for_hook = Arc::clone(&preconnect_wake);
        let net_change_hook: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
            let r = Arc::clone(&router_for_hook.read());
            let _ = execute_network_change_reset(&r, &hub_for_hook);
            pc_wake_for_hook.notify_one();
        });

        let spec = TunLaunchSpec {
            device_name: cfg.tun.device.clone(),
            mtu: cfg.tun.mtu,
            auto_route: cfg.tun.auto_route,
            strict_route: cfg.tun.strict_route,
            enable_ipv6,
            auto_detect_interface: cfg.tun.auto_detect_interface,
            fake_ip_net,
            tun_ipv4_cidr,
            tun_ipv6_cidr,
            bypass_ips,
            local_dns_addr,
            wintun_dll_path: cfg.tun.wintun_path.as_ref().map(PathBuf::from),
            state_dir,
            dns_engine: Some(Arc::clone(dns)),
            network_change_hook: Some(net_change_hook),
        };

        match attach_os_tun_with_spec(spec, vtun) {
            Ok(guard) => {
                hub.push_log(
                    "info",
                    format!(
                        "Attached smoltcp TUN stack to OS interface '{}' (MTU {}, strict_route={})",
                        cfg.tun.device, cfg.tun.mtu, cfg.tun.strict_route
                    ),
                );
                Ok((
                    TunService {
                        config: cfg.tun.clone(),
                        mode: TunRuntimeMode::OsTun,
                        shutdown_tx: tun_stop_tx,
                        task: t_tun,
                        os_guard: Some(Arc::new(guard)),
                    },
                    None,
                ))
            }
            Err(err) => {
                let _ = tun_stop_tx.send(true);
                t_tun.abort();
                Err(err)
            }
        }
    } else {
        hub.push_log(
            "info",
            format!(
                "Userspace smoltcp TUN stack ({}, MTU {}) active in virtual packet mode",
                cfg.tun.stack, cfg.tun.mtu
            ),
        );
        Ok((
            TunService {
                config: cfg.tun.clone(),
                mode: TunRuntimeMode::Virtual,
                shutdown_tx: tun_stop_tx,
                task: t_tun,
                os_guard: None,
            },
            Some(vtun),
        ))
    }
}

/// Platform-aware preconnection and DNS pre-warming policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PreconnectPolicy {
    /// Desktop (`Windows`, `macOS`, `Linux`): keeps `2` warm multiplexed AnyTLS v2 sessions
    /// and proactively refreshes proxy server DNS on a 20s replenish loop.
    Desktop,
    /// Mobile (`Android`): event-driven one-shot 1-session prewarm ONLY on VPN start,
    /// manual node switch, network handoff, or screen-on; zero periodic timer (`0 Hz` idle).
    Mobile,
    /// Completely disable proactive preconnection.
    Disabled,
}

impl PreconnectPolicy {
    pub fn platform_default() -> Self {
        #[cfg(target_os = "android")]
        {
            Self::Mobile
        }
        #[cfg(not(target_os = "android"))]
        {
            Self::Desktop
        }
    }

    pub fn target_sessions(self) -> usize {
        match self {
            Self::Desktop => 2,
            Self::Mobile => 1,
            Self::Disabled => 0,
        }
    }
}

/// Top-level `rust-clash` runtime engine managing Mixed Inbound, Fake-IP DNS,
/// `smoltcp` Userspace/OS TUN, `Router`, hot-reloadable `ClashConfig`, and `TelemetryHub`.
pub struct ProxyEngine {
    config: RwLock<ClashConfig>,
    raw_yaml: RwLock<String>,
    config_path: Option<PathBuf>,
    router: Arc<RwLock<Arc<Router>>>,
    mixed_policy: Arc<RwLock<MixedInboundPolicy>>,
    services: AsyncMutex<RuntimeServices>,
    hub: Arc<TelemetryHub>,
    mixed_addr: RwLock<SocketAddr>,
    dns_addr: RwLock<Option<SocketAddr>>,
    tun_mode: RwLock<TunRuntimeMode>,
    active_os_tun: RwLock<Option<Arc<OsTunGuard>>>,
    last_tun_error: RwLock<Option<String>>,
    virtual_tun: Mutex<Option<VirtualTunHandle>>,
    state_dir: RwLock<PathBuf>,
    saved_selections: RwLock<HashMap<String, String>>,
    profile_manager: RwLock<Option<Arc<crate::profile::ProfileManager>>>,
    geodata_manager: RwLock<Option<Arc<crate::router::geodata::GeoDataManager>>>,
    extra_ca_der: RwLock<Vec<CertificateDer<'static>>>,
    demo_cluster: RwLock<Option<DemoCluster>>,
    preconnect_policy: RwLock<PreconnectPolicy>,
    preconnect_wake: Arc<tokio::sync::Notify>,
    low_power_mode: Arc<std::sync::atomic::AtomicBool>,
    low_power_wake: Arc<tokio::sync::Notify>,
    shutdown_tx: watch::Sender<bool>,
    _bg_tasks: Mutex<Vec<JoinHandle<()>>>,
}

impl ProxyEngine {
    pub async fn start(cfg: ClashConfig) -> Result<Arc<Self>> {
        Self::start_internal(cfg, None, None, default_state_dir()).await
    }

    pub async fn start_with_state_dir(cfg: ClashConfig, state_dir: PathBuf) -> Result<Arc<Self>> {
        Self::start_internal(cfg, None, None, state_dir).await
    }

    pub async fn start_with_options(
        cfg: ClashConfig,
        state_dir: PathBuf,
        preconnect_policy: PreconnectPolicy,
        dns_seed: Option<crate::dns::PositiveDnsCacheSeed>,
        initial_selections: Option<HashMap<String, String>>,
    ) -> Result<Arc<Self>> {
        Self::start_internal_with_options(
            cfg,
            None,
            None,
            state_dir,
            preconnect_policy,
            dns_seed,
            initial_selections,
        )
        .await
    }

    pub async fn start_with_path(
        cfg: ClashConfig,
        config_path: Option<PathBuf>,
    ) -> Result<Arc<Self>> {
        Self::start_internal(cfg, None, config_path, default_state_dir()).await
    }

    pub async fn start_from_file(path: impl AsRef<Path>) -> Result<Arc<Self>> {
        let p = path.as_ref().to_path_buf();
        let cfg = ClashConfig::from_file(&p)?;
        Self::start_internal(cfg, None, Some(p), default_state_dir()).await
    }

    pub async fn start_demo(
        override_mixed_port: Option<u16>,
        override_controller: Option<String>,
        override_dns_listen: Option<String>,
    ) -> Result<Arc<Self>> {
        let (demo, mut cfg) = DemoCluster::start().await?;
        if let Some(mp) = override_mixed_port {
            cfg.mixed_port = mp;
        }
        if let Some(ctrl) = override_controller {
            cfg.external_controller = ctrl;
        }
        if let Some(dns_l) = override_dns_listen {
            cfg.dns.listen = dns_l;
        }
        Self::start_internal(cfg, Some(demo), None, default_state_dir()).await
    }

    /// Build a standalone [`Router`] + [`FakeIpDnsEngine`] + outbounds from `cfg` without binding
    /// any local inbound ports or OS TUN interfaces. Used by `rust-clash probe` and `rust-clash mcp`
    /// when querying configs offline or when no daemon controller is running.
    pub fn build_standalone_router(cfg: &ClashConfig) -> Result<Arc<Router>> {
        cfg.validate()?;
        let state_dir = default_state_dir();
        let extra_ca_der: Vec<CertificateDer<'static>> = Vec::new();
        let geodata_mgr = crate::router::geodata::GeoDataManager::new(&state_dir, Vec::new());
        let dns_engine = Arc::new(FakeIpDnsEngine::with_extra_ca(
            &cfg.dns_with_merged_hosts(),
            &extra_ca_der,
        )?);
        let outbounds =
            build_outbounds_with_dns(&cfg.proxies, &extra_ca_der, Some(Arc::clone(&dns_engine)))?;
        let mmdb = match load_optional_mmdb(cfg)? {
            Some(explicit) => Some(explicit),
            None => geodata_mgr.mmdb_reader(),
        };
        let router = Router::with_providers_mmdb_and_state_dir(
            cfg.mode,
            outbounds,
            &cfg.proxy_groups,
            &cfg.rules,
            &cfg.rule_providers,
            mmdb,
            Some(&state_dir),
            dns_engine,
        )?;
        router.set_unified_delay(cfg.unified_delay);
        Ok(Arc::new(router))
    }

    async fn start_internal(
        cfg: ClashConfig,
        demo_cluster: Option<DemoCluster>,
        config_path: Option<PathBuf>,
        state_dir: PathBuf,
    ) -> Result<Arc<Self>> {
        Self::start_internal_with_options(
            cfg,
            demo_cluster,
            config_path,
            state_dir,
            PreconnectPolicy::platform_default(),
            None,
            None,
        )
        .await
    }

    async fn start_internal_with_options(
        mut cfg: ClashConfig,
        demo_cluster: Option<DemoCluster>,
        config_path: Option<PathBuf>,
        state_dir: PathBuf,
        preconnect_policy: PreconnectPolicy,
        dns_seed: Option<crate::dns::PositiveDnsCacheSeed>,
        initial_selections: Option<HashMap<String, String>>,
    ) -> Result<Arc<Self>> {
        cfg.validate()?;
        let canonical_cfg_path = config_path.map(|p| std::fs::canonicalize(&p).unwrap_or(p));
        let extra_ca_der: Vec<CertificateDer<'static>> = demo_cluster
            .as_ref()
            .map(|d| vec![d.trusted_ca_der.clone()])
            .unwrap_or_default();

        let geodata_mgr = Some(Arc::new(crate::router::geodata::GeoDataManager::new(
            &state_dir,
            extra_ca_der.clone(),
        )));

        let policy = MixedInboundPolicy::from_config(
            cfg.allow_lan,
            &cfg.authentication,
            &cfg.lan_allowed_ips,
        )?;
        let mixed_policy = Arc::new(RwLock::new(policy));

        let dns_engine = Arc::new(FakeIpDnsEngine::with_extra_ca(
            &cfg.dns_with_merged_hosts(),
            &extra_ca_der,
        )?);
        if let Some(seed) = dns_seed {
            dns_engine.seed_positive_proxy_cache(seed);
        }
        let outbounds =
            build_outbounds_with_dns(&cfg.proxies, &extra_ca_der, Some(Arc::clone(&dns_engine)))?;
        let mmdb = match load_optional_mmdb(&cfg)? {
            Some(explicit) => Some(explicit),
            None => geodata_mgr.as_ref().and_then(|g| g.mmdb_reader()),
        };
        let initial_router = Arc::new(Router::with_providers_mmdb_and_state_dir(
            cfg.mode,
            outbounds,
            &cfg.proxy_groups,
            &cfg.rules,
            &cfg.rule_providers,
            mmdb,
            Some(&state_dir),
            Arc::clone(&dns_engine),
        )?);
        initial_router.set_unified_delay(cfg.unified_delay);
        if let Some(ref sel) = initial_selections {
            initial_router.apply_saved_selections(sel);
        }
        let router_slot = Arc::new(RwLock::new(Arc::clone(&initial_router)));
        if let Some(ref gm) = geodata_mgr {
            gm.attach_router_slot(Arc::downgrade(&router_slot));
        }
        let hub = Arc::new(TelemetryHub::new());
        hub.set_log_level(&cfg.log_level);
        let preconnect_wake = Arc::new(tokio::sync::Notify::new());
        let recovered = recover_stale_network_state(&state_dir);
        if !recovered.actions_executed.is_empty() {
            hub.push_log(
                "warn",
                format!(
                    "Recovered {} stale OS network journal rule(s) from prior unclean exit",
                    recovered.actions_executed.len()
                ),
            );
        }
        for w in &recovered.warnings {
            hub.push_log("warn", format!("Stale recovery journal warning: {w}"));
        }

        // 1. Mixed HTTP / SOCKS5 Inbound
        let mixed_spec_initial = mixed_listen_spec(&cfg);
        let (mixed_stop_tx, mixed_stop_rx) = watch::channel(false);
        let (mixed_bound, mixed_task) = spawn_mixed_inbound_with_policy(
            &mixed_spec_initial,
            Arc::clone(&router_slot),
            Arc::clone(&mixed_policy),
            Arc::clone(&hub),
            mixed_stop_rx,
        )
        .await?;
        if cfg.mixed_port == 0 {
            cfg.mixed_port = mixed_bound.port();
        }
        let mixed_service = MixedService {
            listen_spec: mixed_listen_spec(&cfg),
            bound_addr: mixed_bound,
            shutdown_tx: mixed_stop_tx,
            task: mixed_task,
        };
        hub.push_log(
            "info",
            format!("Mixed HTTP/SOCKS5 inbound listening on {mixed_bound}"),
        );

        // 2. Dynamic UDP + TCP DNS Server
        let (dns_service, dns_bound_opt) = if cfg.dns.enable {
            let (dns_stop_tx, dns_stop_rx) = watch::channel(false);
            match spawn_dynamic_dns_server(&cfg.dns.listen, Arc::clone(&router_slot), dns_stop_rx)
                .await
            {
                Ok((bound, t_udp, t_tcp)) => {
                    cfg.dns.listen = bound.to_string();
                    hub.push_log(
                        "info",
                        format!(
                            "DNS server (UDP+TCP, mode={}) listening on {bound} (pool {})",
                            cfg.dns.enhanced_mode, cfg.dns.fake_ip_range
                        ),
                    );
                    (
                        Some(DnsService {
                            listen_spec: cfg.dns.listen.clone(),
                            bound_addr: bound,
                            shutdown_tx: dns_stop_tx,
                            udp_task: t_udp,
                            tcp_task: t_tcp,
                        }),
                        Some(bound),
                    )
                }
                Err(err) => {
                    cfg.dns.enable = false;
                    hub.push_log(
                        "warn",
                        format!("DNS bind skipped ({err}); dns.enable set to false"),
                    );
                    (None, None)
                }
            }
        } else {
            (None, None)
        };

        // 3. Userspace / OS `smoltcp` TUN stack
        let mut virtual_tun_opt = None;
        let mut initial_os_tun = None;
        let mut last_tun_err = None;
        let (tun_service, initial_tun_mode) = if cfg.tun.enable {
            match start_tun_service(
                &cfg,
                &dns_engine,
                dns_bound_opt,
                Arc::clone(&router_slot),
                Arc::clone(&hub),
                Arc::clone(&preconnect_wake),
                state_dir.clone(),
            ) {
                Ok((svc, vtun_opt)) => {
                    let m = svc.mode;
                    initial_os_tun = svc.os_guard.clone();
                    virtual_tun_opt = vtun_opt;
                    (Some(svc), m)
                }
                Err(err) => {
                    mixed_service.stop().await;
                    if let Some(d) = dns_service {
                        d.stop().await;
                    }
                    let msg = format!(
                        "failed to initialize TUN '{}' (auto-route={}): {err}",
                        cfg.tun.device, cfg.tun.auto_route
                    );
                    last_tun_err = Some(msg.clone());
                    let _ = last_tun_err;
                    return Err(ProxyError::Io(std::io::Error::new(err.kind(), msg)));
                }
            }
        } else {
            (None, TunRuntimeMode::Disabled)
        };

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let low_power_mode = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let low_power_wake = Arc::new(tokio::sync::Notify::new());
        let mut bg_tasks = Vec::new();

        // 4. 1Hz Telemetry sampler task (parks at true 0 Hz when in low-power mode & completely idle)
        let hub_tick = Arc::clone(&hub);
        let lp_tick = Arc::clone(&low_power_mode);
        let lp_wake_tick = Arc::clone(&low_power_wake);
        let mut tick_stop = shutdown_rx.clone();
        bg_tasks.push(tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(1));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let mut last_was_nonzero = true;
            loop {
                if lp_tick.load(std::sync::atomic::Ordering::SeqCst)
                    && hub_tick.active_connection_count() == 0
                    && !last_was_nonzero
                    && !hub_tick.has_unsampled_traffic()
                {
                    let wake_lp = lp_wake_tick.notified();
                    let wake_act = hub_tick.activity_notified();
                    tokio::pin!(wake_lp);
                    tokio::pin!(wake_act);
                    wake_lp.as_mut().enable();
                    wake_act.as_mut().enable();
                    if lp_tick.load(std::sync::atomic::Ordering::SeqCst)
                        && hub_tick.active_connection_count() == 0
                        && !last_was_nonzero
                        && !hub_tick.has_unsampled_traffic()
                    {
                        hub_tick.set_telemetry_parked(true);
                        tokio::select! {
                            changed = tick_stop.changed() => {
                                hub_tick.set_telemetry_parked(false);
                                if changed.is_err() || *tick_stop.borrow() {
                                    break;
                                }
                            }
                            _ = &mut wake_lp => {}
                            _ = &mut wake_act => {}
                        }
                        hub_tick.set_telemetry_parked(false);
                        interval.reset_immediately();
                        continue;
                    }
                }

                tokio::select! {
                    changed = tick_stop.changed() => {
                        if changed.is_err() || *tick_stop.borrow() {
                            break;
                        }
                    }
                    _ = interval.tick() => {
                        if lp_tick.load(std::sync::atomic::Ordering::SeqCst)
                            && hub_tick.active_connection_count() == 0
                            && !last_was_nonzero
                            && !hub_tick.has_unsampled_traffic()
                        {
                            continue;
                        }
                        let pt = hub_tick.sample_tick();
                        last_was_nonzero = pt.up > 0 || pt.down > 0;
                    }
                }
            }
        }));

        // 5. Initial & periodic automatic proxy-group health check task (parks at 0 Hz in low-power mode)
        let router_bg = Arc::clone(&router_slot);
        let hub_bg = Arc::clone(&hub);
        let lp_bg = Arc::clone(&low_power_mode);
        let lp_wake_bg = Arc::clone(&low_power_wake);
        let pc_wake_bg = Arc::clone(&preconnect_wake);
        let mut bg_stop = shutdown_rx.clone();
        bg_tasks.push(tokio::spawn(async move {
            let r0 = Arc::clone(&router_bg.read());
            let prev_eff = r0.effective_primary_outbound().effective_outbound;
            r0.refresh_auto_groups(Duration::from_secs(3)).await;
            if r0.effective_primary_outbound().effective_outbound != prev_eff {
                pc_wake_bg.notify_one();
            }
            hub_bg.push_log(
                "info",
                "Initial URLTest / Fallback / LoadBalance latency probe completed",
            );

            let mut interval = tokio::time::interval(Duration::from_secs(15));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            interval.tick().await;
            loop {
                if lp_bg.load(std::sync::atomic::Ordering::SeqCst) {
                    let wake_lp = lp_wake_bg.notified();
                    tokio::pin!(wake_lp);
                    wake_lp.as_mut().enable();
                    if lp_bg.load(std::sync::atomic::Ordering::SeqCst) {
                        tokio::select! {
                            changed = bg_stop.changed() => {
                                if changed.is_err() || *bg_stop.borrow() {
                                    break;
                                }
                            }
                            _ = &mut wake_lp => {}
                        }
                        let r = Arc::clone(&router_bg.read());
                        r.refresh_due_auto_groups(Duration::from_secs(4), false)
                            .await;
                        interval.reset();
                        continue;
                    }
                }

                tokio::select! {
                    changed = bg_stop.changed() => {
                        if changed.is_err() || *bg_stop.borrow() {
                            break;
                        }
                    }
                    _ = interval.tick() => {
                        if lp_bg.load(std::sync::atomic::Ordering::SeqCst) {
                            continue;
                        }
                        let r = Arc::clone(&router_bg.read());
                        let before = r.effective_primary_outbound().effective_outbound;
                        r.refresh_due_auto_groups(Duration::from_secs(4), false).await;
                        if r.effective_primary_outbound().effective_outbound != before {
                            pc_wake_bg.notify_one();
                        }
                    }
                }
            }
        }));

        if let Some(d) = &demo_cluster {
            hub.push_log(
                "info",
                format!(
                    "Demo multi-protocol cluster active (SS-2022={}, VLESS+PQ-0RTT={}, AnyTLS-v2={}, Origin={})",
                    d.ss2022_addr,
                    d.vless_pq_native_0rtt_addr,
                    d.anytls_v2_addr,
                    d.http_target_addr
                ),
            );
        }

        let raw_yaml = cfg.to_yaml_string().unwrap_or_default();
        let engine = Arc::new(Self {
            config: RwLock::new(cfg),
            raw_yaml: RwLock::new(raw_yaml),
            config_path: canonical_cfg_path,
            router: router_slot,
            mixed_policy,
            services: AsyncMutex::new(RuntimeServices {
                mixed: mixed_service,
                dns: dns_service,
                tun: tun_service,
            }),
            hub,
            mixed_addr: RwLock::new(mixed_bound),
            dns_addr: RwLock::new(dns_bound_opt),
            tun_mode: RwLock::new(initial_tun_mode),
            active_os_tun: RwLock::new(initial_os_tun),
            last_tun_error: RwLock::new(last_tun_err),
            virtual_tun: Mutex::new(virtual_tun_opt),
            state_dir: RwLock::new(state_dir),
            saved_selections: RwLock::new(initial_selections.unwrap_or_default()),
            profile_manager: RwLock::new(None),
            geodata_manager: RwLock::new(geodata_mgr),
            extra_ca_der: RwLock::new(extra_ca_der),
            demo_cluster: RwLock::new(demo_cluster),
            preconnect_policy: RwLock::new(preconnect_policy),
            preconnect_wake,
            low_power_mode,
            low_power_wake,
            shutdown_tx,
            _bg_tasks: Mutex::new(bg_tasks),
        });
        Self::spawn_http_rule_providers_task(&engine);
        Self::spawn_preconnect_task(&engine);
        Ok(engine)
    }

    pub fn config_snapshot(&self) -> ClashConfig {
        self.config.read().clone()
    }

    pub fn config_path(&self) -> Option<&Path> {
        self.config_path.as_deref()
    }

    pub fn raw_yaml(&self) -> String {
        self.raw_yaml.read().clone()
    }

    pub fn redacted_yaml(&self) -> String {
        self.config
            .read()
            .redacted()
            .to_yaml_string()
            .unwrap_or_default()
    }

    pub fn router(&self) -> Arc<Router> {
        Arc::clone(&self.router.read())
    }

    pub fn router_slot(&self) -> &Arc<RwLock<Arc<Router>>> {
        &self.router
    }

    pub fn hub(&self) -> &Arc<TelemetryHub> {
        &self.hub
    }

    pub fn mixed_addr(&self) -> SocketAddr {
        *self.mixed_addr.read()
    }

    pub fn dns_addr(&self) -> Option<SocketAddr> {
        *self.dns_addr.read()
    }

    pub fn extra_ca_der(&self) -> Vec<CertificateDer<'static>> {
        self.extra_ca_der.read().clone()
    }

    pub fn tun_mode(&self) -> TunRuntimeMode {
        *self.tun_mode.read()
    }

    pub fn is_tun_active(&self) -> bool {
        self.tun_mode() == TunRuntimeMode::OsTun
    }

    pub fn is_virtual_tun_active(&self) -> bool {
        self.tun_mode() == TunRuntimeMode::Virtual
    }

    pub fn last_tun_error(&self) -> Option<String> {
        self.last_tun_error.read().clone()
    }

    /// Return real-time OS TUN driver, adapter, route, DNS, privilege, and loop-protection status.
    pub fn tun_health(&self) -> TunHealthSnapshot {
        if let Some(guard) = self.active_os_tun.read().clone()
            && let Some(mut snap) = guard.health()
        {
            if snap.last_error.is_none() {
                snap.last_error = self.last_tun_error();
            }
            return snap;
        }
        let cfg = self.config.read();
        let mut snap = preflight_system_tun(cfg.tun.wintun_path.as_deref().map(Path::new));
        snap.last_error = self.last_tun_error();
        if self.is_virtual_tun_active() {
            snap.device_name = Some(format!("{} (virtual)", cfg.tun.device));
        }
        snap
    }

    pub fn take_virtual_tun_handle(&self) -> Option<VirtualTunHandle> {
        self.virtual_tun.lock().take()
    }

    /// Perform full session recovery across an OS network handoff (e.g. Android Wi-Fi <-> Cellular,
    /// macOS `NEPacketTunnelProvider.wake()`, or desktop default-gateway change):
    /// synchronously resets UDP NAT tables, evicts pooled AnyTLS/TLS sockets, flushes DNS caches,
    /// aborts in-flight TCP streams, and triggers primary outbound pre-warming on the new link.
    pub fn notify_network_change(&self) -> NetworkChangeReport {
        let report = execute_network_change_reset(&self.router(), &self.hub);
        self.trigger_preconnect();
        report
    }

    pub fn preconnect_policy(&self) -> PreconnectPolicy {
        *self.preconnect_policy.read()
    }

    pub fn set_preconnect_policy(&self, policy: PreconnectPolicy) {
        let mut guard = self.preconnect_policy.write();
        if *guard != policy {
            *guard = policy;
            drop(guard);
            self.trigger_preconnect();
        }
    }

    pub fn trigger_preconnect(&self) {
        self.preconnect_wake.notify_one();
    }

    pub fn set_unified_delay(&self, enabled: bool) {
        {
            let mut cfg = self.config.write();
            cfg.unified_delay = enabled;
            if let Ok(y) = cfg.to_yaml_string() {
                *self.raw_yaml.write() = y;
            }
        }
        self.router().set_unified_delay(enabled);
        self.hub
            .push_log("info", format!("Updated unified-delay to {enabled}"));
    }

    pub fn set_mode(&self, mode: RunMode) {
        {
            let mut cfg = self.config.write();
            cfg.mode = mode;
            if let Ok(y) = cfg.to_yaml_string() {
                *self.raw_yaml.write() = y;
            }
        }
        self.router().set_mode(mode);
        self.trigger_preconnect();
        if self.demo_cluster.read().is_none()
            && let Some(mgr) = self.profile_manager()
        {
            let _ = mgr.save_active_mode(mode);
        }
        self.hub.push_log(
            "info",
            format!("Switched routing mode to '{}'", mode.as_str()),
        );
    }

    pub fn select_group_and_persist(&self, group_name: &str, proxy_name: &str) -> Result<()> {
        let router = self.router();
        let prev_eff = router.effective_outbound_for_group(group_name);
        router.select_group(group_name, proxy_name)?;
        let new_eff = router.effective_outbound_for_group(group_name);
        self.saved_selections
            .write()
            .insert(group_name.to_string(), proxy_name.to_string());
        if self.demo_cluster.read().is_none()
            && let Some(mgr) = self.profile_manager()
        {
            let _ = mgr.save_group_selection(group_name, proxy_name);
        }
        let closed_stale = if let Some(ref target_eff) = new_eff
            && prev_eff.as_deref() != Some(target_eff.as_str())
        {
            self.hub.close_connections_for_group(group_name, target_eff)
        } else {
            0
        };
        if prev_eff != new_eff {
            self.trigger_preconnect();
        }
        self.hub.push_log(
            "info",
            format!(
                "Selected outbound '{proxy_name}' in group '{group_name}' (migrated {closed_stale} active connection(s))"
            ),
        );
        Ok(())
    }

    fn spawn_preconnect_task(engine: &Arc<Self>) {
        let weak_eng = Arc::downgrade(engine);
        let mut stop_rx = engine.shutdown_tx.subscribe();
        let lp = Arc::clone(&engine.low_power_mode);
        let lp_wake = Arc::clone(&engine.low_power_wake);
        let pc_wake = Arc::clone(&engine.preconnect_wake);

        let handle = tokio::spawn(async move {
            let mut pending_immediate = true;
            let mut interval = tokio::time::interval(Duration::from_secs(20));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            interval.tick().await;

            loop {
                let Some(eng) = weak_eng.upgrade() else {
                    break;
                };
                let policy = eng.preconnect_policy();
                let is_lp = lp.load(std::sync::atomic::Ordering::SeqCst);
                drop(eng);

                if is_lp || policy == PreconnectPolicy::Disabled {
                    let wake_lp = lp_wake.notified();
                    tokio::pin!(wake_lp);
                    wake_lp.as_mut().enable();
                    let wake_pc = pc_wake.notified();
                    tokio::pin!(wake_pc);
                    wake_pc.as_mut().enable();
                    let still_parked = weak_eng.upgrade().is_none_or(|e| {
                        lp.load(std::sync::atomic::Ordering::SeqCst)
                            || e.preconnect_policy() == PreconnectPolicy::Disabled
                    });
                    if still_parked {
                        tokio::select! {
                            changed = stop_rx.changed() => {
                                if changed.is_err() || *stop_rx.borrow() {
                                    break;
                                }
                            }
                            _ = &mut wake_lp => {
                                pending_immediate = true;
                            }
                            _ = &mut wake_pc => {
                                pending_immediate = true;
                            }
                        }
                        interval.reset();
                        continue;
                    }
                }

                if pending_immediate {
                    pending_immediate = false;
                    if let Some(eng) = weak_eng.upgrade()
                        && !lp.load(std::sync::atomic::Ordering::SeqCst)
                    {
                        let target = eng.preconnect_policy().target_sessions();
                        if target > 0 {
                            let router = eng.router();
                            let _ = tokio::time::timeout(
                                Duration::from_secs(6),
                                router.preconnect_primary(target),
                            )
                            .await;
                        }
                    }
                }

                let Some(eng) = weak_eng.upgrade() else {
                    break;
                };
                let policy = eng.preconnect_policy();
                drop(eng);

                match policy {
                    PreconnectPolicy::Disabled => {
                        continue;
                    }
                    PreconnectPolicy::Mobile => {
                        tokio::select! {
                            changed = stop_rx.changed() => {
                                if changed.is_err() || *stop_rx.borrow() {
                                    break;
                                }
                            }
                            _ = pc_wake.notified() => {
                                pending_immediate = true;
                            }
                        }
                    }
                    PreconnectPolicy::Desktop => {
                        tokio::select! {
                            changed = stop_rx.changed() => {
                                if changed.is_err() || *stop_rx.borrow() {
                                    break;
                                }
                            }
                            _ = pc_wake.notified() => {
                                pending_immediate = true;
                                interval.reset();
                            }
                            _ = interval.tick() => {
                                if !lp.load(std::sync::atomic::Ordering::SeqCst)
                                    && let Some(eng) = weak_eng.upgrade()
                                {
                                    let router = eng.router();
                                    let _ = tokio::time::timeout(
                                        Duration::from_secs(6),
                                        router.preconnect_primary(2),
                                    )
                                    .await;
                                }
                            }
                        }
                    }
                }
            }
        });
        engine._bg_tasks.lock().push(handle);
    }

    fn spawn_http_rule_providers_task(engine: &Arc<Self>) {
        let weak_eng = Arc::downgrade(engine);
        let mut stop_rx = engine.shutdown_tx.subscribe();
        let lp = Arc::clone(&engine.low_power_mode);
        let lp_wake = Arc::clone(&engine.low_power_wake);

        let handle = tokio::spawn(async move {
            // Initial check shortly after startup if any `http` rule-provider is configured
            tokio::select! {
                changed = stop_rx.changed() => {
                    if changed.is_err() || *stop_rx.borrow() {
                        return;
                    }
                }
                _ = tokio::time::sleep(Duration::from_secs(1)) => {}
            }

            let mut interval = tokio::time::interval(Duration::from_secs(300));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                if lp.load(std::sync::atomic::Ordering::SeqCst) {
                    let wake = lp_wake.notified();
                    tokio::pin!(wake);
                    wake.as_mut().enable();
                    if lp.load(std::sync::atomic::Ordering::SeqCst) {
                        tokio::select! {
                            changed = stop_rx.changed() => {
                                if changed.is_err() || *stop_rx.borrow() {
                                    break;
                                }
                            }
                            _ = &mut wake => {}
                        }
                        interval.reset();
                        continue;
                    }
                }

                if let Some(eng) = weak_eng.upgrade()
                    && !lp.load(std::sync::atomic::Ordering::SeqCst)
                {
                    let cfg = eng.config_snapshot();
                    let has_http = cfg
                        .rule_providers
                        .values()
                        .any(|p| p.provider_type.trim().eq_ignore_ascii_case("http"));
                    if has_http {
                        let fallback_proxy = eng.router().fallback_proxy_outbound();
                        let extra_ca = eng.extra_ca_der.read().clone();
                        let state_dir = eng.state_dir();
                        let updated = crate::router::ruleset::refresh_http_rule_providers(
                            &cfg.rule_providers,
                            &state_dir,
                            &extra_ca,
                            fallback_proxy.as_ref(),
                            false,
                        )
                        .await;
                        if updated > 0 {
                            let cur_cfg = eng.config_snapshot();
                            if eng.apply_config_transition(cur_cfg, None).await.is_ok() {
                                eng.hub.push_log(
                                    "info",
                                    format!(
                                        "Refreshed {updated} HTTP rule-provider(s) and hot-reloaded router"
                                    ),
                                );
                            }
                        }
                    }
                } else if weak_eng.strong_count() == 0 {
                    break;
                }

                tokio::select! {
                    changed = stop_rx.changed() => {
                        if changed.is_err() || *stop_rx.borrow() {
                            break;
                        }
                    }
                    _ = interval.tick() => {}
                }
            }
        });
        engine._bg_tasks.lock().push(handle);
    }

    pub fn set_low_power_mode(&self, enabled: bool) {
        self.router().set_low_power_mode(enabled);
        let prev = self
            .low_power_mode
            .swap(enabled, std::sync::atomic::Ordering::SeqCst);
        if prev != enabled {
            self.low_power_wake.notify_waiters();
            if prev && !enabled {
                self.trigger_preconnect();
            }
        }
    }

    pub fn is_low_power_mode(&self) -> bool {
        self.low_power_mode
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    pub fn set_log_level(&self, level: String) {
        {
            let mut cfg = self.config.write();
            cfg.log_level = level.clone();
            if let Ok(y) = cfg.to_yaml_string() {
                *self.raw_yaml.write() = y;
            }
        }
        self.hub
            .push_log("info", format!("Updated log-level to '{level}'"));
        self.hub.set_log_level(&level);
    }

    pub async fn set_allow_lan(&self, allow: bool) -> Result<()> {
        let mut cfg = self.config.read().clone();
        if cfg.mixed_port == 0 {
            cfg.mixed_port = self.mixed_addr().port();
        }
        cfg.allow_lan = allow;
        self.apply_config_transition(cfg, None).await?;
        self.hub
            .push_log("info", format!("Updated allow-lan to {allow}"));
        Ok(())
    }

    pub async fn set_tun_active(&self, enabled: bool) -> Result<()> {
        self.update_tun_options(Some(enabled), None, None).await
    }

    pub async fn update_tun_options(
        &self,
        enabled: Option<bool>,
        strict_route: Option<bool>,
        ipv6: Option<bool>,
    ) -> Result<()> {
        let mut cfg = self.config.read().clone();
        if let Some(en) = enabled {
            cfg.tun.enable = en;
        }
        if let Some(sr) = strict_route {
            cfg.tun.strict_route = sr;
        }
        if let Some(v6) = ipv6 {
            cfg.tun.ipv6 = v6;
        }
        self.apply_config_transition(cfg, None).await?;
        let snap = self.config.read();
        self.hub.push_log(
            "info",
            format!(
                "TUN runtime updated: enable={}, strict-route={}, ipv6={}, mode={}",
                snap.tun.enable,
                snap.tun.strict_route,
                snap.tun.ipv6,
                self.tun_mode().as_str()
            ),
        );
        Ok(())
    }

    pub fn state_dir(&self) -> PathBuf {
        self.state_dir.read().clone()
    }

    pub fn set_state_dir_for_test(&self, dir: PathBuf) {
        *self.state_dir.write() = dir;
    }

    pub fn profile_manager(&self) -> Option<Arc<crate::profile::ProfileManager>> {
        self.profile_manager.read().clone()
    }

    pub fn ensure_profile_manager(self: &Arc<Self>) -> Result<Arc<crate::profile::ProfileManager>> {
        if let Some(existing) = self.profile_manager() {
            return Ok(existing);
        }
        let ca_for_profiles = if self.demo_cluster.read().is_some() {
            Vec::new()
        } else {
            self.extra_ca_der.read().clone()
        };
        let mgr = crate::profile::ProfileManager::open_or_init_with_ca(
            &self.state_dir(),
            ca_for_profiles,
        )?;
        if self.demo_cluster.read().is_none() {
            let cur_cfg = self.config.read().clone();
            if !cur_cfg.proxies.is_empty()
                && let Ok((disk_cfg, _)) = mgr.load_active_config()
                && disk_cfg.proxies.is_empty()
            {
                let live_sel = self.router().manual_selections_snapshot();
                let _ = mgr.persist_active_yaml(&cur_cfg, None, Some(&live_sel));
            }
        }
        self.attach_profile_manager(Arc::clone(&mgr));
        Ok(mgr)
    }

    pub fn geodata_manager(&self) -> Option<Arc<crate::router::geodata::GeoDataManager>> {
        if let Some(existing) = self.geodata_manager.read().clone() {
            return Some(existing);
        }
        let ca = if self.demo_cluster.read().is_some() {
            Vec::new()
        } else {
            self.extra_ca_der.read().clone()
        };
        let created = Arc::new(crate::router::geodata::GeoDataManager::new(
            self.state_dir(),
            ca,
        ));
        created.attach_router_slot(Arc::downgrade(&self.router));
        *self.geodata_manager.write() = Some(Arc::clone(&created));
        Some(created)
    }

    pub fn geodata_status(&self) -> crate::router::geodata::GeoDataStatus {
        match self.geodata_manager() {
            Some(gm) => gm.status(),
            None => crate::router::geodata::GeoDataManager::builtin_status(),
        }
    }

    pub async fn update_geodata(&self) -> Result<crate::router::geodata::GeoDataStatus> {
        let gm = self
            .geodata_manager()
            .ok_or_else(|| ProxyError::Config("GeoDataManager unavailable".into()))?;
        let status = gm.update_default_mirrors().await?;
        self.hub.push_log(
            "info",
            format!(
                "[GeoData] Updated split-tunneling rule databases (source={}, cn_domains={}, intl_domains={}, cn_cidrs={}, mmdb={})",
                status.source_label,
                status.geosite_cn_entries,
                status.geosite_non_cn_entries,
                status.geoip_cn_ranges,
                status.mmdb_present
            ),
        );
        Ok(status)
    }

    /// Attach a persistent `ProfileManager`, apply its saved proxy selections, and spawn its periodic background subscription & GeoData auto-refresh loop.
    pub fn attach_profile_manager(self: &Arc<Self>, mgr: Arc<crate::profile::ProfileManager>) {
        let already_attached = self.profile_manager.read().is_some();
        mgr.attach_router_slot(Arc::downgrade(&self.router));
        let new_dir = mgr.state_dir();
        if *self.state_dir.read() != new_dir {
            *self.state_dir.write() = new_dir.clone();
            let ca = if self.demo_cluster.read().is_some() {
                Vec::new()
            } else {
                self.extra_ca_der.read().clone()
            };
            let gm = Arc::new(crate::router::geodata::GeoDataManager::new(&new_dir, ca));
            gm.attach_router_slot(Arc::downgrade(&self.router));
            *self.geodata_manager.write() = Some(gm);
        }
        *self.profile_manager.write() = Some(Arc::clone(&mgr));
        if self.demo_cluster.read().is_none() {
            let prof_sel = mgr.active_selected_groups();
            if !prof_sel.is_empty() {
                let prev_eff = self
                    .router()
                    .effective_primary_outbound()
                    .effective_outbound;
                self.router().apply_saved_selections(&prof_sel);
                let mut saved = self.saved_selections.write();
                for (k, v) in prof_sel {
                    saved.insert(k, v);
                }
                drop(saved);
                if self
                    .router()
                    .effective_primary_outbound()
                    .effective_outbound
                    != prev_eff
                {
                    self.trigger_preconnect();
                }
            }
        }
        if already_attached {
            return;
        }
        let weak_eng = Arc::downgrade(self);
        let mut stop_rx = self.shutdown_tx.subscribe();

        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            interval.tick().await;
            let mut ticks: u64 = 0;
            loop {
                tokio::select! {
                    changed = stop_rx.changed() => {
                        if changed.is_err() || *stop_rx.borrow() {
                            break;
                        }
                    }
                    _ = interval.tick() => {
                        ticks = ticks.wrapping_add(1);
                        let Some(eng) = weak_eng.upgrade() else {
                            break;
                        };
                        let due_ids = mgr.due_auto_update_ids();
                        for id in due_ids {
                            match mgr.refresh_subscription(&id).await {
                                Ok((meta, cfg, is_active)) => {
                                    eng.hub.push_log(
                                        "info",
                                        format!("Auto-updated subscription profile '{}' ({} nodes)", meta.name, meta.proxy_count),
                                    );
                                    if is_active && eng.demo_cluster.read().is_none() {
                                        let _ = eng.activate_profile_config_with_selections(cfg, Some(&meta.selected_groups)).await;
                                    }
                                }
                                Err(err) => {
                                    eng.hub.push_log(
                                        "warn",
                                        format!("Subscription auto-update failed for '{id}': {err}"),
                                    );
                                }
                            }
                        }
                        // Check cached GeoData staleness every 6 hours when previously downloaded
                        if ticks.is_multiple_of(720)
                            && let Some(gm) = eng.geodata_manager()
                            && gm.status().last_updated_ms > 0
                        {
                            let _ = gm.refresh_if_expired().await;
                        }
                    }
                }
            }
        });

        self._bg_tasks.lock().push(handle);
    }

    /// Activate a `ClashConfig` from `ProfileManager`, cleanly exiting Demo Sandbox if active and
    /// preserving the active Control API session (`external_controller`, `secret`, `cors_allowed_origins`)
    /// and bound Mixed port so desktop/web clients and OS System Proxy never lose connectivity.
    pub async fn activate_profile_config(&self, new_cfg: ClashConfig) -> Result<()> {
        let sel = self.profile_manager().map(|m| m.active_selected_groups());
        self.activate_profile_config_with_selections(new_cfg, sel.as_ref())
            .await
    }

    pub async fn activate_profile_config_with_selections(
        &self,
        mut new_cfg: ClashConfig,
        explicit_selections: Option<&HashMap<String, String>>,
    ) -> Result<()> {
        let prev = self.config.read().clone();
        new_cfg.external_controller = prev.external_controller;
        if new_cfg.secret.is_none() {
            new_cfg.secret = prev.secret;
        }
        new_cfg.mixed_port = self.mixed_addr().port();
        if !prev.dns.enable {
            new_cfg.dns.enable = false;
        } else {
            new_cfg.dns.listen = prev.dns.listen;
        }
        new_cfg.tun = prev.tun;

        let old_demo = self.demo_cluster.write().take();
        if old_demo.is_some() {
            self.extra_ca_der.write().clear();
        }

        let raw_yaml = new_cfg.to_yaml_string().ok();
        if let Err(err) = self
            .apply_config_transition_with_selections(new_cfg, raw_yaml, explicit_selections)
            .await
        {
            if let Some(d) = old_demo {
                *self.extra_ca_der.write() = vec![d.trusted_ca_der.clone()];
                *self.demo_cluster.write() = Some(d);
            }
            return Err(err);
        }

        if let Some(d) = old_demo {
            d.shutdown();
            self.hub.push_log(
                "info",
                "Exited Demo Sandbox and activated real user profile",
            );
        }
        Ok(())
    }

    /// Toggle the built-in self-contained Multi-Protocol Demo Sandbox cluster at runtime!
    /// When disabled (`enable = false`), cleanly shuts down all loopback demo servers and
    /// restores the user's active `ProfileManager` profile (or clean Starter profile).
    pub async fn set_demo_sandbox(&self, enable: bool) -> Result<()> {
        if enable {
            if self.demo_cluster.read().is_some() {
                return Ok(());
            }
            let (demo, mut demo_cfg) = DemoCluster::start().await?;
            let prev = self.config.read().clone();
            demo_cfg.external_controller = prev.external_controller;
            demo_cfg.secret = prev.secret;
            demo_cfg.mixed_port = self.mixed_addr().port();
            demo_cfg.dns.listen = prev.dns.listen;
            demo_cfg.tun = prev.tun;

            let prev_ca = std::mem::replace(
                &mut *self.extra_ca_der.write(),
                vec![demo.trusted_ca_der.clone()],
            );
            let raw_yaml = demo_cfg.to_yaml_string().ok();
            if let Err(err) = self.apply_config_transition(demo_cfg, raw_yaml).await {
                *self.extra_ca_der.write() = prev_ca;
                demo.shutdown();
                return Err(err);
            }
            *self.demo_cluster.write() = Some(demo);
            self.hub.push_log(
                "info",
                "Enabled built-in Multi-Protocol Demo Sandbox cluster",
            );
            Ok(())
        } else {
            if self.demo_cluster.read().is_none() {
                return Ok(());
            }
            let target_cfg = if let Some(mgr) = self.profile_manager() {
                mgr.load_active_config()?.0
            } else {
                ClashConfig::from_yaml_str(&ClashConfig::default_starter_yaml())?
            };
            self.activate_profile_config(target_cfg).await
        }
    }

    pub fn demo_info(&self) -> DemoClusterInfo {
        match &*self.demo_cluster.read() {
            Some(d) => {
                let mut endpoints = HashMap::new();
                endpoints.insert("SS-2022 (BLAKE3-AES256)".into(), d.ss2022_addr.to_string());
                endpoints.insert("SS-AEAD (ChaCha20)".into(), d.ss_chacha_addr.to_string());
                endpoints.insert(
                    "VLESS+PQ (native.0rtt)".into(),
                    d.vless_pq_native_0rtt_addr.to_string(),
                );
                endpoints.insert(
                    "VLESS+PQ (xorpub.1rtt)".into(),
                    d.vless_pq_xorpub_1rtt_addr.to_string(),
                );
                endpoints.insert(
                    "VLESS+PQ (random.0rtt)".into(),
                    d.vless_pq_random_0rtt_addr.to_string(),
                );
                endpoints.insert(
                    "AnyTLS v2 (TLS1.3 Mux)".into(),
                    d.anytls_v2_addr.to_string(),
                );
                DemoClusterInfo {
                    enabled: true,
                    http_benchmark_origin: format!("http://{}", d.http_target_addr),
                    endpoints,
                }
            }
            None => DemoClusterInfo {
                enabled: false,
                http_benchmark_origin: String::new(),
                endpoints: HashMap::new(),
            },
        }
    }

    pub async fn reload_from_config_path(&self, requested_path: &str) -> Result<()> {
        let Some(allowed_path) = &self.config_path else {
            return Err(ProxyError::Routing(
                "reloading by filesystem path is disabled when started without --config".into(),
            ));
        };
        let req_canon = std::fs::canonicalize(requested_path).map_err(|e| {
            ProxyError::Routing(format!(
                "refusing inaccessible or invalid config path '{requested_path}': {e}"
            ))
        })?;
        let allowed_canon =
            std::fs::canonicalize(allowed_path).unwrap_or_else(|_| allowed_path.clone());
        if req_canon != allowed_canon {
            return Err(ProxyError::Routing(format!(
                "refusing arbitrary file read '{requested_path}'; only configured path '{}' is allowed",
                allowed_canon.display()
            )));
        }
        let yaml_text = std::fs::read_to_string(&req_canon).map_err(|e| {
            ProxyError::Config(format!("failed reading '{}': {e}", req_canon.display()))
        })?;
        self.reload_yaml(&yaml_text).await
    }

    pub async fn reload_yaml(&self, yaml_text: &str) -> Result<()> {
        let mut new_cfg = ClashConfig::from_yaml_str_unchecked(yaml_text).map_err(|e| {
            ProxyError::Config(crate::config::uri::redact_sensitive_text(&e.to_string()))
        })?;
        let had_redacted = yaml_text.contains(REDACTED_SECRET);
        {
            let prev = self.config.read();
            new_cfg.restore_redacted_from(&prev);
        }
        let raw_override = if had_redacted {
            None
        } else {
            Some(yaml_text.to_string())
        };
        self.apply_config_transition(new_cfg, raw_override)
            .await
            .map_err(|e| match e {
                ProxyError::Config(msg) => {
                    ProxyError::Config(crate::config::uri::redact_sensitive_text(&msg))
                }
                other => other,
            })?;
        if self.demo_cluster.read().is_none()
            && let Some(mgr) = self.profile_manager()
        {
            let cur_cfg = self.config.read().clone();
            let cur_sel = self.router().manual_selections_snapshot();
            let _ = mgr.persist_active_yaml(&cur_cfg, None, Some(&cur_sel));
        }
        self.hub
            .push_log("info", "Hot-reloaded YAML configuration successfully");
        Ok(())
    }

    async fn restore_stopped_tun(
        &self,
        services: &mut RuntimeServices,
        pending_new_tun: Option<(TunService, Option<VirtualTunHandle>)>,
        stopped_old_tun_cfg: Option<TunConfig>,
    ) {
        if let Some((new_tun, _)) = pending_new_tun {
            new_tun.stop().await;
        }
        if let Some(prev_tun_cfg) = stopped_old_tun_cfg {
            let mut prev_cfg = self.config.read().clone();
            prev_cfg.tun = prev_tun_cfg;
            let local_dns = services.dns.as_ref().map(|d| d.bound_addr);
            if let Ok((restored, vtun)) = start_tun_service(
                &prev_cfg,
                self.router.read().dns(),
                local_dns,
                Arc::clone(&self.router),
                Arc::clone(&self.hub),
                Arc::clone(&self.preconnect_wake),
                self.state_dir(),
            ) {
                *self.tun_mode.write() = restored.mode;
                *self.active_os_tun.write() = restored.os_guard.clone();
                *self.virtual_tun.lock() = vtun;
                services.tun = Some(restored);
            } else {
                *self.tun_mode.write() = TunRuntimeMode::Disabled;
                *self.active_os_tun.write() = None;
                self.config.write().tun.enable = false;
            }
        }
    }

    async fn apply_config_transition(
        &self,
        new_cfg: ClashConfig,
        raw_yaml_override: Option<String>,
    ) -> Result<()> {
        self.apply_config_transition_with_selections(new_cfg, raw_yaml_override, None)
            .await
    }

    async fn apply_config_transition_with_selections(
        &self,
        mut new_cfg: ClashConfig,
        raw_yaml_override: Option<String>,
        explicit_selections: Option<&HashMap<String, String>>,
    ) -> Result<()> {
        let mut services = self.services.lock().await;

        // 1. Validate config and construct new Policy + DNS + Outbounds + MMDB + Router BEFORE touching live listeners!
        new_cfg.validate()?;
        let prev_had_concrete = !self.config.read().proxies.is_empty();
        let prev_router = Arc::clone(&self.router.read());
        let extra_ca = self.extra_ca_der.read().clone();
        let new_policy = MixedInboundPolicy::from_config(
            new_cfg.allow_lan,
            &new_cfg.authentication,
            &new_cfg.lan_allowed_ips,
        )?;
        let new_dns = Arc::new(FakeIpDnsEngine::with_extra_ca(
            &new_cfg.dns_with_merged_hosts(),
            &extra_ca,
        )?);
        new_dns.import_entries_from(prev_router.dns());
        let new_outbounds =
            build_outbounds_with_dns(&new_cfg.proxies, &extra_ca, Some(Arc::clone(&new_dns)))?;
        let mmdb = match load_optional_mmdb(&new_cfg)? {
            Some(explicit) => Some(explicit),
            None => self.geodata_manager().and_then(|g| g.mmdb_reader()),
        };
        let cur_state_dir = self.state_dir();
        let new_router = Arc::new(Router::with_providers_mmdb_and_state_dir(
            new_cfg.mode,
            new_outbounds,
            &new_cfg.proxy_groups,
            &new_cfg.rules,
            &new_cfg.rule_providers,
            mmdb,
            Some(&cur_state_dir),
            Arc::clone(&new_dns),
        )?);
        new_router.set_unified_delay(new_cfg.unified_delay);
        new_router.set_low_power_mode(self.is_low_power_mode());
        new_router.import_delays_from(&prev_router);

        let mut carried_selections = prev_router.manual_selections_snapshot();
        for (k, v) in self.saved_selections.read().iter() {
            carried_selections
                .entry(k.clone())
                .or_insert_with(|| v.clone());
        }
        if !prev_had_concrete && !new_cfg.proxies.is_empty() {
            carried_selections.retain(|_, v| v != "DIRECT");
        }
        if let Some(explicit) = explicit_selections {
            for (k, v) in explicit {
                carried_selections.insert(k.clone(), v.clone());
            }
        }
        new_router.apply_saved_selections(&carried_selections);

        let target_mixed_spec = mixed_listen_spec(&new_cfg);
        let need_mixed_rebind = services.mixed.listen_spec != target_mixed_spec;
        let need_dns_change = match &services.dns {
            Some(d) => !new_cfg.dns.enable || d.listen_spec != new_cfg.dns.listen,
            None => new_cfg.dns.enable,
        };
        // Keep an active virtual packet bridge (e.g. Android VpnService / macOS NEPacketTunnelProvider)
        // alive across live profile/rule/node reloads when MTU and virtual mode remain unchanged!
        let preserve_virtual_tun = matches!(
            &services.tun,
            Some(t)
                if t.mode == TunRuntimeMode::Virtual
                    && new_cfg.tun.enable
                    && !new_cfg.tun.auto_route
                    && t.config.mtu == new_cfg.tun.mtu
        );
        let need_tun_change = if preserve_virtual_tun {
            false
        } else {
            match &services.tun {
                Some(t) => !new_cfg.tun.enable || t.config != new_cfg.tun,
                None => new_cfg.tun.enable,
            }
        };

        // 2. Apply TUN transition with full rollback record (`stopped_old_tun_cfg`)
        let mut pending_new_tun: Option<(TunService, Option<VirtualTunHandle>)> = None;
        let mut stopped_old_tun_cfg: Option<TunConfig> = None;
        if preserve_virtual_tun {
            if let Some(existing_tun) = services.tun.as_mut() {
                existing_tun.config = new_cfg.tun.clone();
            }
        } else if need_tun_change {
            if let Some(old_tun) = services.tun.take() {
                stopped_old_tun_cfg = Some(old_tun.config.clone());
                old_tun.stop().await;
                *self.active_os_tun.write() = None;
                *self.virtual_tun.lock() = None;
                *self.tun_mode.write() = TunRuntimeMode::Disabled;
            }
            if new_cfg.tun.enable {
                let local_dns = services.dns.as_ref().map(|d| d.bound_addr);
                match start_tun_service(
                    &new_cfg,
                    &new_dns,
                    local_dns,
                    Arc::clone(&self.router),
                    Arc::clone(&self.hub),
                    Arc::clone(&self.preconnect_wake),
                    self.state_dir(),
                ) {
                    Ok(started) => {
                        *self.last_tun_error.write() = None;
                        pending_new_tun = Some(started);
                    }
                    Err(err) => {
                        let msg = format!(
                            "failed to enable TUN '{}' (auto-route={}): {err}",
                            new_cfg.tun.device, new_cfg.tun.auto_route
                        );
                        *self.last_tun_error.write() = Some(msg.clone());
                        self.restore_stopped_tun(&mut services, None, stopped_old_tun_cfg)
                            .await;
                        self.hub.push_log("error", &msg);
                        return Err(ProxyError::Io(std::io::Error::new(err.kind(), msg)));
                    }
                }
            } else {
                *self.last_tun_error.write() = None;
            }
        }

        // 3. Rebind Mixed Inbound if port / bind-address / allow-lan changed
        let prev_mixed_spec = services.mixed.listen_spec.clone();
        let mut mixed_was_rebound = false;
        if need_mixed_rebind {
            let same_port =
                new_cfg.mixed_port != 0 && services.mixed.bound_addr.port() == new_cfg.mixed_port;
            if !same_port {
                let (m_tx, m_rx) = watch::channel(false);
                match spawn_mixed_inbound_with_policy(
                    &target_mixed_spec,
                    Arc::clone(&self.router),
                    Arc::clone(&self.mixed_policy),
                    Arc::clone(&self.hub),
                    m_rx,
                )
                .await
                {
                    Ok((bound, task)) => {
                        if new_cfg.mixed_port == 0 {
                            new_cfg.mixed_port = bound.port();
                        }
                        let new_svc = MixedService {
                            listen_spec: mixed_listen_spec(&new_cfg),
                            bound_addr: bound,
                            shutdown_tx: m_tx,
                            task,
                        };
                        let old_svc = std::mem::replace(&mut services.mixed, new_svc);
                        old_svc.stop().await;
                        mixed_was_rebound = true;
                    }
                    Err(err) => {
                        self.restore_stopped_tun(
                            &mut services,
                            pending_new_tun,
                            stopped_old_tun_cfg,
                        )
                        .await;
                        return Err(err);
                    }
                }
            } else {
                let placeholder_tx = watch::channel(false).0;
                let old_svc = std::mem::replace(
                    &mut services.mixed,
                    MixedService {
                        listen_spec: String::new(),
                        bound_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
                        shutdown_tx: placeholder_tx,
                        task: tokio::spawn(async {}),
                    },
                );
                let fallback_spec = old_svc.bound_addr.to_string();
                old_svc.stop().await;

                let (m_tx, m_rx) = watch::channel(false);
                match spawn_mixed_inbound_with_policy(
                    &target_mixed_spec,
                    Arc::clone(&self.router),
                    Arc::clone(&self.mixed_policy),
                    Arc::clone(&self.hub),
                    m_rx,
                )
                .await
                {
                    Ok((bound, task)) => {
                        services.mixed = MixedService {
                            listen_spec: mixed_listen_spec(&new_cfg),
                            bound_addr: bound,
                            shutdown_tx: m_tx,
                            task,
                        };
                        mixed_was_rebound = true;
                    }
                    Err(err) => {
                        let (rb_tx, rb_rx) = watch::channel(false);
                        if let Ok((rb_bound, rb_task)) = spawn_mixed_inbound_with_policy(
                            &prev_mixed_spec,
                            Arc::clone(&self.router),
                            Arc::clone(&self.mixed_policy),
                            Arc::clone(&self.hub),
                            rb_rx,
                        )
                        .await
                        {
                            services.mixed = MixedService {
                                listen_spec: prev_mixed_spec,
                                bound_addr: rb_bound,
                                shutdown_tx: rb_tx,
                                task: rb_task,
                            };
                        } else {
                            let (rb_tx2, rb_rx2) = watch::channel(false);
                            if let Ok((rb_bound, rb_task)) = spawn_mixed_inbound_with_policy(
                                &fallback_spec,
                                Arc::clone(&self.router),
                                Arc::clone(&self.mixed_policy),
                                Arc::clone(&self.hub),
                                rb_rx2,
                            )
                            .await
                            {
                                services.mixed = MixedService {
                                    listen_spec: fallback_spec,
                                    bound_addr: rb_bound,
                                    shutdown_tx: rb_tx2,
                                    task: rb_task,
                                };
                            }
                        }
                        self.restore_stopped_tun(
                            &mut services,
                            pending_new_tun,
                            stopped_old_tun_cfg,
                        )
                        .await;
                        return Err(err);
                    }
                }
            }
            self.hub.push_log(
                "info",
                format!(
                    "Rebound Mixed HTTP/SOCKS5 inbound to {}",
                    services.mixed.bound_addr
                ),
            );
        }

        // 4. Rebind or toggle UDP+TCP DNS Server if `dns.enable` or `dns.listen` changed
        if need_dns_change {
            if !new_cfg.dns.enable {
                if let Some(old_dns) = services.dns.take() {
                    old_dns.stop().await;
                    self.hub.push_log("info", "Stopped DNS server");
                }
            } else {
                let target_dns_port = new_cfg
                    .dns
                    .listen
                    .parse::<SocketAddr>()
                    .map(|a| a.port())
                    .unwrap_or(0);
                let same_dns_port = target_dns_port != 0
                    && services
                        .dns
                        .as_ref()
                        .is_some_and(|d| d.bound_addr.port() == target_dns_port);

                if !same_dns_port {
                    let (d_tx, d_rx) = watch::channel(false);
                    match spawn_dynamic_dns_server(
                        &new_cfg.dns.listen,
                        Arc::clone(&self.router),
                        d_rx,
                    )
                    .await
                    {
                        Ok((bound, t_udp, t_tcp)) => {
                            new_cfg.dns.listen = bound.to_string();
                            if let Some(old_dns) = services.dns.take() {
                                old_dns.stop().await;
                            }
                            services.dns = Some(DnsService {
                                listen_spec: new_cfg.dns.listen.clone(),
                                bound_addr: bound,
                                shutdown_tx: d_tx,
                                udp_task: t_udp,
                                tcp_task: t_tcp,
                            });
                            self.hub
                                .push_log("info", format!("Rebound UDP+TCP DNS to {bound}"));
                        }
                        Err(err) => {
                            if mixed_was_rebound {
                                let (rb_tx, rb_rx) = watch::channel(false);
                                if let Ok((rb_bound, rb_task)) = spawn_mixed_inbound_with_policy(
                                    &prev_mixed_spec,
                                    Arc::clone(&self.router),
                                    Arc::clone(&self.mixed_policy),
                                    Arc::clone(&self.hub),
                                    rb_rx,
                                )
                                .await
                                {
                                    let cur = std::mem::replace(
                                        &mut services.mixed,
                                        MixedService {
                                            listen_spec: prev_mixed_spec,
                                            bound_addr: rb_bound,
                                            shutdown_tx: rb_tx,
                                            task: rb_task,
                                        },
                                    );
                                    cur.stop().await;
                                }
                            }
                            self.restore_stopped_tun(
                                &mut services,
                                pending_new_tun,
                                stopped_old_tun_cfg,
                            )
                            .await;
                            return Err(err);
                        }
                    }
                } else {
                    let prev_dns_opt = services.dns.take();
                    let prev_dns_spec = prev_dns_opt.as_ref().map(|d| d.listen_spec.clone());
                    if let Some(old_dns) = prev_dns_opt {
                        old_dns.stop().await;
                    }
                    let (d_tx, d_rx) = watch::channel(false);
                    match spawn_dynamic_dns_server(
                        &new_cfg.dns.listen,
                        Arc::clone(&self.router),
                        d_rx,
                    )
                    .await
                    {
                        Ok((bound, t_udp, t_tcp)) => {
                            new_cfg.dns.listen = bound.to_string();
                            services.dns = Some(DnsService {
                                listen_spec: new_cfg.dns.listen.clone(),
                                bound_addr: bound,
                                shutdown_tx: d_tx,
                                udp_task: t_udp,
                                tcp_task: t_tcp,
                            });
                        }
                        Err(err) => {
                            if let Some(prev_spec) = prev_dns_spec {
                                let (rb_tx, rb_rx) = watch::channel(false);
                                if let Ok((rb_bound, rb_udp, rb_tcp)) = spawn_dynamic_dns_server(
                                    &prev_spec,
                                    Arc::clone(&self.router),
                                    rb_rx,
                                )
                                .await
                                {
                                    services.dns = Some(DnsService {
                                        listen_spec: prev_spec,
                                        bound_addr: rb_bound,
                                        shutdown_tx: rb_tx,
                                        udp_task: rb_udp,
                                        tcp_task: rb_tcp,
                                    });
                                }
                            }
                            if mixed_was_rebound {
                                let (rb_tx, rb_rx) = watch::channel(false);
                                if let Ok((rb_bound, rb_task)) = spawn_mixed_inbound_with_policy(
                                    &prev_mixed_spec,
                                    Arc::clone(&self.router),
                                    Arc::clone(&self.mixed_policy),
                                    Arc::clone(&self.hub),
                                    rb_rx,
                                )
                                .await
                                {
                                    let cur = std::mem::replace(
                                        &mut services.mixed,
                                        MixedService {
                                            listen_spec: prev_mixed_spec,
                                            bound_addr: rb_bound,
                                            shutdown_tx: rb_tx,
                                            task: rb_task,
                                        },
                                    );
                                    cur.stop().await;
                                }
                            }
                            self.restore_stopped_tun(
                                &mut services,
                                pending_new_tun,
                                stopped_old_tun_cfg,
                            )
                            .await;
                            return Err(err);
                        }
                    }
                }
            }
        }

        // 5. Commit TUN + Policy + Router + Runtime Addresses + Config Snapshot atomically
        if let Some((new_tun_svc, vtun_opt)) = pending_new_tun {
            *self.virtual_tun.lock() = vtun_opt;
            *self.active_os_tun.write() = new_tun_svc.os_guard.clone();
            services.tun = Some(new_tun_svc);
        }
        let final_mixed_addr = services.mixed.bound_addr;
        let final_dns_addr = services.dns.as_ref().map(|d| d.bound_addr);
        let final_tun_mode = services
            .tun
            .as_ref()
            .map(|t| t.mode)
            .unwrap_or(TunRuntimeMode::Disabled);

        *self.mixed_policy.write() = new_policy;
        *self.router.write() = Arc::clone(&new_router);
        *self.saved_selections.write() = new_router.manual_selections_snapshot();
        *self.mixed_addr.write() = final_mixed_addr;
        *self.dns_addr.write() = final_dns_addr;
        *self.tun_mode.write() = final_tun_mode;

        let yaml_to_store = match raw_yaml_override {
            Some(raw) => raw,
            None => new_cfg.to_yaml_string()?,
        };
        self.hub.set_log_level(&new_cfg.log_level);
        *self.config.write() = new_cfg;
        *self.raw_yaml.write() = yaml_to_store;

        drop(services);
        self.trigger_preconnect();

        let pc_wake = Arc::clone(&self.preconnect_wake);
        tokio::spawn(async move {
            let before = new_router.effective_primary_outbound().effective_outbound;
            new_router.refresh_auto_groups(Duration::from_secs(3)).await;
            if new_router.effective_primary_outbound().effective_outbound != before {
                pc_wake.notify_one();
            }
        });
        Ok(())
    }

    pub async fn import_unified_live(
        self: &Arc<Self>,
        raw_input: &str,
        profile_name_hint: Option<&str>,
        deduplicate: bool,
        auto_select: bool,
    ) -> Result<crate::profile::NodeMutationReport> {
        let mgr = self.ensure_profile_manager()?;
        let report = mgr
            .import_unified_input(raw_input, profile_name_hint, deduplicate, auto_select)
            .await?;
        self.activate_profile_config_with_selections(
            report.config.clone(),
            Some(&report.selected_groups),
        )
        .await?;
        let eff = self.router().effective_primary_outbound();
        self.hub.push_log(
            "info",
            format!(
                "Imported {} node(s) ({} skipped duplicate, {} skipped unsupported), active outbound: {} ({})",
                report.added_nodes.len(),
                report.skipped_duplicates,
                report.skipped_unsupported.len(),
                eff.effective_outbound,
                eff.effective_protocol
            ),
        );
        Ok(report)
    }

    pub async fn upsert_node_live(
        self: &Arc<Self>,
        original_name: Option<&str>,
        node: ProxyNodeConfig,
        auto_select: bool,
    ) -> Result<crate::profile::NodeMutationReport> {
        let mgr = self.ensure_profile_manager()?;
        let report = mgr.upsert_node_in_active(original_name, node, auto_select)?;
        self.activate_profile_config_with_selections(
            report.config.clone(),
            Some(&report.selected_groups),
        )
        .await?;
        let action = if original_name.is_some() {
            "Updated"
        } else {
            "Added"
        };
        let node_label = report
            .updated_node
            .as_deref()
            .or_else(|| report.added_nodes.first().map(String::as_str))
            .unwrap_or("node");
        self.hub
            .push_log("info", format!("{action} proxy node '{node_label}'"));
        Ok(report)
    }

    pub async fn delete_node_live(
        self: &Arc<Self>,
        target_name: &str,
    ) -> Result<crate::profile::NodeMutationReport> {
        let mgr = self.ensure_profile_manager()?;
        let report = mgr.delete_node_from_active(target_name)?;
        self.activate_profile_config_with_selections(
            report.config.clone(),
            Some(&report.selected_groups),
        )
        .await?;
        self.hub.push_log(
            "info",
            format!("Deleted proxy node '{}'", target_name.trim()),
        );
        Ok(report)
    }

    pub async fn deduplicate_nodes_live(
        self: &Arc<Self>,
    ) -> Result<crate::profile::NodeMutationReport> {
        let mgr = self.ensure_profile_manager()?;
        let report = mgr.deduplicate_active_nodes()?;
        self.activate_profile_config_with_selections(
            report.config.clone(),
            Some(&report.selected_groups),
        )
        .await?;
        self.hub.push_log(
            "info",
            format!(
                "Deduplicated active profile: removed {} duplicate node(s)",
                report.removed_nodes.len()
            ),
        );
        Ok(report)
    }

    /// Import `ss://`, `vless://`, `anytls://` share links or Base64 subscription into the live engine
    /// and persist to the active profile.
    pub async fn import_uris_live(
        self: &Arc<Self>,
        raw_uris: &str,
    ) -> Result<Vec<ProxyNodeConfig>> {
        let report = self.import_unified_live(raw_uris, None, true, true).await?;
        let added_set: std::collections::HashSet<&str> =
            report.added_nodes.iter().map(String::as_str).collect();
        let mut out: Vec<ProxyNodeConfig> = report
            .config
            .proxies
            .iter()
            .filter(|n| added_set.contains(n.name()))
            .cloned()
            .collect();
        if out.is_empty() {
            out = report.config.proxies;
        }
        Ok(out)
    }

    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
        if let Some(os_guard) = self.active_os_tun.write().take() {
            os_guard.stop_now();
        }
        if let Ok(mut guard) = self.services.try_lock() {
            let _ = guard.mixed.shutdown_tx.send(true);
            if let Some(d) = &guard.dns {
                let _ = d.shutdown_tx.send(true);
            }
            if let Some(mut t) = guard.tun.take() {
                if let Some(os_g) = t.os_guard.take() {
                    os_g.stop_now();
                }
                let _ = t.shutdown_tx.send(true);
            }
        }
        if let Some(d) = self.demo_cluster.write().take() {
            d.shutdown();
        }
        let state_dir = self.state_dir();
        if crate::platform::sysproxy::query_sysproxy_status(&state_dir).enabled {
            let _ = crate::platform::sysproxy::disable_system_proxy(&state_dir);
        }
    }
}

impl Drop for ProxyEngine {
    fn drop(&mut self) {
        self.shutdown();
    }
}

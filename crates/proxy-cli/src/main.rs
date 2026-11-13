use std::{path::PathBuf, sync::Arc, time::Duration};

mod bench_tun;
mod mcp;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use proxy_core::{
    api::spawn_api_server,
    config::{ClashConfig, uri::parse_subscription_uris},
    crypto::tls::generate_self_signed_server_config,
    engine::ProxyEngine,
    outbound::{
        anytls::{AnyTlsServerConfig, padding::PaddingScheme, spawn_anytls_server},
        ss::spawn_ss_server,
        vless::{
            VlessServerConfig,
            encryption::{config::XorMode, generate_vless_encryption_pair},
            spawn_vless_server,
        },
    },
};
use tokio::sync::watch;
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

#[derive(Parser)]
#[command(
    name = "rust-clash",
    version,
    about = "Pure-Rust Multi-Protocol Proxy Engine (SS-2022, VLESS+PQ mlkem768x25519plus, AnyTLS v2, Fake-IP DNS, smoltcp TUN & Web Console)"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the rust-clash proxy daemon and embedded Web Console
    Run {
        /// Path to Clash Meta (Mihomo) compatible YAML configuration file
        #[arg(short, long)]
        config: Option<PathBuf>,

        /// Launch built-in multi-protocol local loopback server cluster (SS-2022, VLESS+PQ 0-RTT/1-RTT, AnyTLS v2)
        #[arg(long)]
        demo: bool,

        /// Override Mixed (HTTP + SOCKS5) inbound port
        #[arg(long)]
        mixed_port: Option<u16>,

        /// Override External Controller & Web UI listen address (e.g. 127.0.0.1:9090)
        #[arg(long)]
        controller: Option<String>,

        /// Override Fake-IP UDP DNS listen address (e.g. 127.0.0.1:1053)
        #[arg(long)]
        dns_listen: Option<String>,
    },

    /// Narrowly scoped privileged TUN helper mode (validates config, verifies OS TUN privileges, and runs with automatic journal rollback)
    ElevatedTunHelper {
        /// Path to validated Clash Meta (Mihomo) YAML configuration file
        #[arg(short, long)]
        config: PathBuf,
    },

    /// Check system TUN driver, privilege, and crash-recovery readiness as JSON
    TunCheck {
        /// Optional explicit path to signed wintun.dll on Windows
        #[arg(long)]
        wintun_path: Option<PathBuf>,
    },

    /// Validate a Clash YAML configuration file and compile all routing rules
    Check {
        /// Path to YAML configuration file
        #[arg(short, long)]
        config: PathBuf,
    },

    /// Generate Xray-compatible Post-Quantum Hybrid VLESS (`mlkem768x25519plus`) encryption/decryption keys
    KeygenVless {
        /// Header obfuscation mode: native, xorpub, or random
        #[arg(long, default_value = "native")]
        mode: String,

        /// Enable 0-RTT session ticket resumption (default: true)
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
        zero_rtt: bool,

        /// Include ML-KEM-768 Post-Quantum key alongside X25519 (default: true)
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
        pq: bool,

        /// Emit machine-readable JSON output
        #[arg(long)]
        json: bool,
    },

    /// Parse `ss://`, `vless://`, or `anytls://` share URIs (or Base64 subscription) into Clash YAML
    ParseUri {
        /// Share URI string or Base64 subscription payload
        input: String,
    },

    /// Generate a starter Clash Meta YAML config with SS-2022, VLESS+PQ, and AnyTLS v2 templates
    InitConfig {
        /// Output file path (prints to stdout if omitted)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Benchmark the L3 `smoltcp` TUN packet stack against an external Shadowsocks-2022 server and emit JSON metrics
    BenchTun {
        #[arg(long)]
        ss_port: u16,
        #[arg(long)]
        ss_password: String,
        #[arg(long)]
        tcp_origin_port: u16,
        #[arg(long)]
        udp_origin_port: u16,
        #[arg(long)]
        dns_origin_port: u16,
        #[arg(long, default_value_t = 1500)]
        mtu: usize,
        #[arg(long, default_value_t = 16 * 1024 * 1024)]
        single_stream_bytes: u32,
        #[arg(long, default_value_t = 8 * 1024 * 1024)]
        per_multi_stream_bytes: u32,
        #[arg(long, default_value_t = 4)]
        multi_streams: usize,
    },

    /// Run `Clippy for Clash` static config security audit, rule shadowing linter, and Split-DNS route simulator
    Audit {
        /// Optional path to Clash YAML file (audits active profile if omitted)
        #[arg(short, long)]
        config: Option<PathBuf>,

        /// Exit with non-zero code if any HIGH or MEDIUM severity issue is detected
        #[arg(long)]
        strict: bool,

        /// Emit machine-readable JSON report
        #[arg(long)]
        json: bool,
    },

    /// Run a Surge-grade per-stage timing waterfall probe (`DNS -> Tunnel -> TLS -> HTTP TTFB`) or AI Endpoint Readiness Matrix
    Probe {
        /// Optional path to Clash YAML file (uses live controller or active profile if omitted)
        #[arg(short, long)]
        config: Option<PathBuf>,

        /// Optional controller host:port (e.g. 127.0.0.1:9090)
        #[arg(long)]
        controller: Option<String>,

        /// Optional controller Bearer secret
        #[arg(long)]
        secret: Option<String>,

        /// Proxy node or group name (defaults to primary group or DIRECT)
        #[arg(short, long)]
        proxy: Option<String>,

        /// Target HTTP/HTTPS URL for single-target waterfall probe
        #[arg(short, long, default_value = "https://api.github.com/")]
        url: String,

        /// Run the full AI & Developer Endpoint Readiness Matrix instead of a single URL
        #[arg(long)]
        matrix: bool,

        /// Verify real UDP datagram relay (DNS echo) on the leaf outbound
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
        udp: bool,

        /// Explicitly allow probing loopback, RFC1918 private LAN, or link-local targets (blocked by SSRF guard by default)
        #[arg(long)]
        allow_private_targets: bool,

        /// Probe timeout in milliseconds
        #[arg(long, default_value_t = 5000)]
        timeout_ms: u64,

        /// Emit machine-readable JSON report
        #[arg(long)]
        json: bool,
    },

    /// Start the built-in credential-redacted Model Context Protocol (MCP) JSON-RPC 2.0 `stdio` server for AI coding agents
    Mcp {
        /// Optional path to Clash YAML file for offline fallback
        #[arg(short, long)]
        config: Option<PathBuf>,

        /// Optional running `rust-clash` controller host:port (auto-detects config or 127.0.0.1:9090)
        #[arg(long)]
        controller: Option<String>,

        /// Optional controller Bearer secret
        #[arg(long)]
        secret: Option<String>,

        /// Allow AI agent to switch Selector proxy groups (`switch_proxy_selector`); read-only by default
        #[arg(long)]
        allow_mutations: bool,

        /// Opt in to sharing proxy server endpoints and destination host metadata with the MCP client (redacted by default)
        #[arg(long)]
        include_network_metadata: bool,
    },

    /// Run a standalone protocol server (Shadowsocks / SS-2022, VLESS+PQ, or AnyTLS v2)
    Server {
        #[command(subcommand)]
        proto: ServerCommands,
    },
}

#[derive(Subcommand)]
enum ServerCommands {
    /// Run a Shadowsocks AEAD or Shadowsocks-2022 TCP+UDP server
    Ss {
        #[arg(short, long, default_value = "0.0.0.0:8388")]
        listen: String,
        #[arg(short, long, default_value = "2022-blake3-aes-256-gcm")]
        cipher: String,
        #[arg(short, long)]
        password: String,
    },
    /// Run a VLESS v0 + `mlkem768x25519plus` Post-Quantum server
    Vless {
        #[arg(short, long, default_value = "0.0.0.0:8443")]
        listen: String,
        #[arg(short, long)]
        uuid: Uuid,
        #[arg(short, long, default_value = "none")]
        decryption: String,
    },
    /// Run an AnyTLS v2 TLS multiplexing server with dynamic padding scheme
    Anytls {
        #[arg(short, long, default_value = "0.0.0.0:8444")]
        listen: String,
        #[arg(short, long)]
        password: String,
        #[arg(long, default_value = "localhost")]
        sni: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let stderr_tracing = matches!(
        &cli.command,
        Some(Commands::Mcp { .. })
            | Some(Commands::Audit { json: true, .. })
            | Some(Commands::Probe { json: true, .. })
            | Some(Commands::KeygenVless { json: true, .. })
            | Some(Commands::TunCheck { .. })
    );
    init_tracing(stderr_tracing);

    match cli.command.unwrap_or(Commands::Run {
        config: None,
        demo: false,
        mixed_port: None,
        controller: None,
        dns_listen: None,
    }) {
        Commands::Run {
            config,
            demo,
            mixed_port,
            controller,
            dns_listen,
        } => {
            let state_dir = proxy_core::platform::recovery::default_state_dir();
            let _instance_guard = if !demo {
                Some(
                    proxy_core::platform::recovery::SingleInstanceGuard::acquire(&state_dir)
                        .context("another rust-clash daemon instance is already running")?,
                )
            } else {
                None
            };

            let engine: Arc<ProxyEngine> = if demo {
                let eng =
                    ProxyEngine::start_demo(mixed_port, controller.clone(), dns_listen).await?;
                if let Ok(profile_mgr) =
                    proxy_core::profile::ProfileManager::open_or_init(&state_dir)
                {
                    eng.attach_profile_manager(profile_mgr);
                }
                eng
            } else if let Some(path) = config {
                let mut cfg = ClashConfig::from_file(&path)?;
                if let Some(mp) = mixed_port {
                    cfg.mixed_port = mp;
                }
                if let Some(ctrl) = &controller {
                    cfg.external_controller = ctrl.clone();
                }
                if let Some(dl) = dns_listen {
                    cfg.dns.listen = dl;
                }
                ProxyEngine::start_with_path(cfg, Some(path)).await?
            } else {
                let profile_mgr = proxy_core::profile::ProfileManager::open_or_init(&state_dir)?;
                let (mut cfg, active_path) = profile_mgr.load_active_config()?;
                if let Some(mp) = mixed_port {
                    cfg.mixed_port = mp;
                }
                if let Some(ctrl) = &controller {
                    cfg.external_controller = ctrl.clone();
                }
                if let Some(dl) = dns_listen {
                    cfg.dns.listen = dl;
                }
                let eng = ProxyEngine::start_with_path(cfg, Some(active_path)).await?;
                eng.attach_profile_manager(profile_mgr);
                eng
            };

            let ctrl_listen = engine.config_snapshot().external_controller;
            let (shutdown_tx, shutdown_rx) = watch::channel(false);
            let (api_addr, _api_task) =
                spawn_api_server(&ctrl_listen, Arc::clone(&engine), shutdown_rx).await?;

            println!("================================================================");
            println!("  rust-clash v{} is running!", env!("CARGO_PKG_VERSION"));
            println!("  Mixed Inbound (HTTP / SOCKS5) : {}", engine.mixed_addr());
            if let Some(dns_a) = engine.dns_addr() {
                println!("  DNS Server (UDP + TCP)        : {dns_a}");
            }
            println!(
                "  TUN Runtime Mode              : {}",
                engine.tun_mode().as_str()
            );
            println!("  Web Console & Control API     : http://{api_addr}");
            println!("================================================================");

            tokio::signal::ctrl_c()
                .await
                .context("failed waiting for Ctrl-C signal")?;
            tracing::info!("Shutting down rust-clash...");
            let _ = shutdown_tx.send(true);
            engine.shutdown();
            tokio::time::sleep(Duration::from_millis(80)).await;
        }

        Commands::ElevatedTunHelper { config } => {
            let state_dir = proxy_core::platform::recovery::default_state_dir();
            let _instance_guard =
                proxy_core::platform::recovery::SingleInstanceGuard::acquire(&state_dir)
                    .context("another rust-clash instance is already holding the TUN lock")?;
            let canon = std::fs::canonicalize(&config)
                .with_context(|| format!("invalid config path '{}'", config.display()))?;
            let mut cfg = ClashConfig::from_file(&canon)?;
            let preflight = proxy_core::platform::tun::preflight_system_tun(
                cfg.tun.wintun_path.as_deref().map(std::path::Path::new),
            );
            if !preflight.privilege_ok {
                anyhow::bail!(
                    "elevated-tun-helper requires OS network privilege: {}",
                    preflight
                        .privilege_hint
                        .as_deref()
                        .unwrap_or("insufficient privileges")
                );
            }
            cfg.tun.enable = true;
            cfg.tun.auto_route = true;
            let engine = ProxyEngine::start_with_path(cfg, Some(canon)).await?;
            let ctrl_listen = engine.config_snapshot().external_controller;
            let (shutdown_tx, shutdown_rx) = watch::channel(false);
            let (_api_addr, _api_task) =
                spawn_api_server(&ctrl_listen, Arc::clone(&engine), shutdown_rx).await?;
            tokio::signal::ctrl_c()
                .await
                .context("failed waiting for Ctrl-C signal")?;
            let _ = shutdown_tx.send(true);
            engine.shutdown();
            tokio::time::sleep(Duration::from_millis(80)).await;
        }

        Commands::TunCheck { wintun_path } => {
            let snap = proxy_core::platform::tun::preflight_system_tun(wintun_path.as_deref());
            println!("{}", serde_json::to_string_pretty(&snap)?);
        }

        Commands::Check { config } => {
            let cfg = ClashConfig::from_file(&config)?;
            let dns = Arc::new(proxy_core::dns::FakeIpDnsEngine::new(
                &cfg.dns_with_merged_hosts(),
            )?);
            let outbounds = proxy_core::engine::build_outbounds_with_dns(
                &cfg.proxies,
                &[],
                Some(Arc::clone(&dns)),
            )?;
            let mmdb = match cfg.mmdb_path.as_deref() {
                Some(path) => Some(Arc::new(proxy_core::router::mmdb::MmdbReader::from_file(
                    path,
                )?)),
                None => None,
            };
            let router = proxy_core::router::Router::with_providers_and_mmdb(
                cfg.mode,
                outbounds,
                &cfg.proxy_groups,
                &cfg.rules,
                &cfg.rule_providers,
                mmdb,
                dns,
            )?;
            println!(
                "Configuration OK: {} proxies, {} groups, {} rule-providers, {} compiled rules (mode: {})",
                cfg.proxies.len(),
                cfg.proxy_groups.len(),
                cfg.rule_providers.len(),
                router.rules_snapshot().len(),
                cfg.mode.as_str()
            );
        }

        Commands::KeygenVless {
            mode,
            zero_rtt,
            pq,
            json,
        } => {
            let xor_mode = XorMode::parse(&mode).map_err(|_| {
                anyhow::anyhow!("invalid mode '{mode}'; expected native, xorpub, or random")
            })?;
            let pair = generate_vless_encryption_pair(xor_mode, zero_rtt, pq)?;
            let uuid = Uuid::new_v4();
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "uuid": uuid,
                        "mode": pair.mode,
                        "rtt": pair.rtt,
                        "encryption": pair.encryption,
                        "decryption": pair.decryption,
                        "x25519_public_key": pair.x25519_public_key,
                        "mlkem768_client_bytes": pair.mlkem768_client_bytes,
                    }))?
                );
            } else {
                println!("# Xray / rust-clash VLESS Post-Quantum Hybrid Keypair");
                println!("UUID              : {uuid}");
                println!("Mode / RTT        : {} / {}", pair.mode, pair.rtt);
                println!("X25519 Public Key : {}", pair.x25519_public_key);
                println!("ML-KEM-768 Bytes  : {}", pair.mlkem768_client_bytes);
                println!("\n# Client `encryption` (Clash YAML / Xray outbound):");
                println!("{}", pair.encryption);
                println!("\n# Server `decryption` (rust-clash server / Xray inbound):");
                println!("{}", pair.decryption);
            }
        }

        Commands::ParseUri { input } => {
            let nodes = parse_subscription_uris(&input)?;
            let wrapper = serde_json::json!({ "proxies": nodes });
            let yaml = serde_yml::to_string(&wrapper)?;
            print!("{yaml}");
        }

        Commands::InitConfig { output } => {
            let pair = generate_vless_encryption_pair(XorMode::XorPub, true, true)?;
            let sample = build_sample_yaml(&pair.encryption);
            if let Some(path) = output {
                std::fs::write(&path, &sample)
                    .with_context(|| format!("failed writing {}", path.display()))?;
                println!("Wrote starter configuration to {}", path.display());
            } else {
                print!("{sample}");
            }
        }

        Commands::BenchTun {
            ss_port,
            ss_password,
            tcp_origin_port,
            udp_origin_port,
            dns_origin_port,
            mtu,
            single_stream_bytes,
            per_multi_stream_bytes,
            multi_streams,
        } => {
            bench_tun::run_tun_benchmark(bench_tun::BenchTunArgs {
                ss_port,
                ss_password,
                tcp_origin_port,
                udp_origin_port,
                dns_origin_port,
                mtu,
                single_stream_bytes,
                per_multi_stream_bytes,
                multi_streams,
            })
            .await?;
        }

        Commands::Server { proto } => {
            let (shutdown_tx, shutdown_rx) = watch::channel(false);
            match proto {
                ServerCommands::Ss {
                    listen,
                    cipher,
                    password,
                } => {
                    let (bound, _h) =
                        spawn_ss_server(&listen, &cipher, &password, shutdown_rx).await?;
                    println!("Shadowsocks ({cipher}) TCP+UDP server listening on {bound}");
                }
                ServerCommands::Vless {
                    listen,
                    uuid,
                    decryption,
                } => {
                    let (bound, _h) = spawn_vless_server(
                        VlessServerConfig {
                            listen_addr: listen,
                            allowed_uuid: uuid,
                            decryption,
                            tls_config: None,
                        },
                        shutdown_rx,
                    )
                    .await?;
                    println!("VLESS server (UUID {uuid}) listening on {bound}");
                }
                ServerCommands::Anytls {
                    listen,
                    password,
                    sni,
                } => {
                    let (tls_cfg, _) = generate_self_signed_server_config(
                        &[sni.clone(), "localhost".into(), "127.0.0.1".into()],
                        &[b"h2".to_vec(), b"http/1.1".to_vec()],
                    )?;
                    let (bound, _h) = spawn_anytls_server(
                        AnyTlsServerConfig {
                            listen_addr: listen,
                            password,
                            tls_config: tls_cfg,
                            padding_scheme: PaddingScheme::default(),
                        },
                        shutdown_rx,
                    )
                    .await?;
                    println!("AnyTLS v2 server (self-signed SNI={sni}) listening on {bound}");
                }
            }
            tokio::signal::ctrl_c().await?;
            let _ = shutdown_tx.send(true);
        }

        Commands::Audit {
            config,
            strict,
            json,
        } => {
            let (cfg, src) = mcp::load_cli_or_profile_config(config.as_ref())?;
            let report = proxy_core::audit::audit_config(&cfg);
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "source": src,
                        "audit": report,
                    }))?
                );
            } else {
                print_audit_report(&src, &report);
            }
            if strict && (report.counts.high > 0 || report.counts.medium > 0) {
                anyhow::bail!(
                    "strict audit failed: {} HIGH and {} MEDIUM issue(s) found (score {}/100, grade {})",
                    report.counts.high,
                    report.counts.medium,
                    report.score,
                    report.grade
                );
            }
        }

        Commands::Probe {
            config,
            controller,
            secret,
            proxy,
            url,
            matrix,
            udp,
            allow_private_targets,
            timeout_ms,
            json,
        } => {
            let loaded = mcp::load_cli_or_profile_config(config.as_ref());
            let fallback_cfg = loaded.as_ref().ok().map(|(c, _)| c);
            let ctrl = mcp::resolve_controller_client(
                controller.as_deref(),
                secret.as_deref(),
                fallback_cfg,
            );
            let clamped_timeout = timeout_ms.clamp(300, 20_000);
            let cfg_for_fallback = loaded.map(|(c, _)| c).unwrap_or_default();

            let target_proxy = match proxy.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
                Some(p) => p.to_string(),
                None => {
                    if let Some(first_grp) = cfg_for_fallback.proxy_groups.first() {
                        first_grp.name.clone()
                    } else if let Some(first_node) = cfg_for_fallback.proxies.first() {
                        first_node.name().to_string()
                    } else {
                        "DIRECT".to_string()
                    }
                }
            };

            if matrix {
                let mut live_report: Option<proxy_core::probe::EndpointMatrixReport> = None;
                if !allow_private_targets
                    && config.is_none()
                    && let Some(ref c) = ctrl
                {
                    let path = format!(
                        "/proxies/{}/matrix",
                        mcp::url_encode_component(&target_proxy)
                    );
                    if let Ok((200, val)) = c
                        .request_json(
                            "POST",
                            &path,
                            Some(&serde_json::json!({ "timeout_ms": clamped_timeout })),
                            Duration::from_millis(clamped_timeout * 2 + 6000),
                        )
                        .await
                    {
                        live_report = serde_json::from_value(val).ok();
                    }
                }

                let report = match live_report {
                    Some(r) => r,
                    None => {
                        let router = ProxyEngine::build_standalone_router(&cfg_for_fallback)?;
                        let opts = proxy_core::probe::ProbeOptions {
                            timeout: Duration::from_millis(clamped_timeout),
                            check_udp: true,
                            udp_dns_target: None,
                            extra_ca_der: &[],
                            allow_private_targets,
                            allowed_private_addrs: &[],
                        };
                        proxy_core::probe::probe_endpoint_matrix(
                            &router,
                            &cfg_for_fallback,
                            &target_proxy,
                            proxy_core::probe::default_matrix_targets(None),
                            opts,
                        )
                        .await?
                    }
                };

                if json {
                    println!("{}", serde_json::to_string_pretty(&report)?);
                } else {
                    print_matrix_report(&report);
                }
            } else {
                let mut live_report: Option<proxy_core::probe::WaterfallProbeReport> = None;
                if !allow_private_targets
                    && config.is_none()
                    && let Some(ref c) = ctrl
                {
                    let path = format!(
                        "/proxies/{}/probe",
                        mcp::url_encode_component(&target_proxy)
                    );
                    if let Ok((200, val)) = c
                        .request_json(
                            "POST",
                            &path,
                            Some(&serde_json::json!({
                                "url": url,
                                "timeout_ms": clamped_timeout,
                                "check_udp": udp,
                            })),
                            Duration::from_millis(clamped_timeout + 5000),
                        )
                        .await
                    {
                        live_report = serde_json::from_value(val).ok();
                    }
                }

                let report = match live_report {
                    Some(r) => r,
                    None => {
                        let router = ProxyEngine::build_standalone_router(&cfg_for_fallback)?;
                        let opts = proxy_core::probe::ProbeOptions {
                            timeout: Duration::from_millis(clamped_timeout),
                            check_udp: udp,
                            udp_dns_target: None,
                            extra_ca_der: &[],
                            allow_private_targets,
                            allowed_private_addrs: &[],
                        };
                        proxy_core::probe::probe_target_waterfall(
                            &router,
                            &cfg_for_fallback,
                            &target_proxy,
                            &url,
                            opts,
                        )
                        .await?
                    }
                };

                if json {
                    println!("{}", serde_json::to_string_pretty(&report)?);
                } else {
                    print_waterfall_report(&report);
                }
            }
        }

        Commands::Mcp {
            config,
            controller,
            secret,
            allow_mutations,
            include_network_metadata,
        } => {
            mcp::run_mcp_stdio(mcp::McpServerOptions {
                config_path: config,
                controller,
                secret,
                allow_mutations,
                include_network_metadata,
            })
            .await?;
        }
    }

    Ok(())
}

fn print_audit_report(src: &str, report: &proxy_core::audit::ConfigAuditReport) {
    println!("================================================================");
    println!("  rust-clash Static Config Audit & Route Simulator");
    println!("  Source : {src}");
    println!("  Basis  : {}", report.simulation_basis);
    println!(
        "  Score  : {}/100 (Grade {}) — HIGH: {}, MEDIUM: {}, LOW: {}, INFO: {}",
        report.score,
        report.grade,
        report.counts.high,
        report.counts.medium,
        report.counts.low,
        report.counts.info
    );
    println!("================================================================");

    if report.findings.is_empty() {
        println!(
            "  [PASS] No static config security, rule-shadowing, or implicit DNS issues detected."
        );
    } else {
        println!("\nFindings ({}):", report.findings.len());
        for f in &report.findings {
            let sev = match f.severity {
                proxy_core::audit::AuditSeverity::High => "HIGH  ",
                proxy_core::audit::AuditSeverity::Medium => "MEDIUM",
                proxy_core::audit::AuditSeverity::Low => "LOW   ",
                proxy_core::audit::AuditSeverity::Info => "INFO  ",
            };
            println!("  [{sev}] {} ({}) — {}", f.code, f.location, f.title);
            println!("           Fix: {}", f.remediation);
        }
    }

    println!(
        "\nSplit-Tunnel & Implicit DNS Route Simulation ({}):",
        report.simulation_basis
    );
    for row in &report.leak_matrix {
        println!(
            "  - {:<36} -> {:<16} [{}] ({}) => {}",
            row.target,
            row.effective_outbound,
            row.matched_rule,
            row.dns_strategy,
            row.risk_level.to_ascii_uppercase()
        );
    }
}

fn print_waterfall_report(r: &proxy_core::probe::WaterfallProbeReport) {
    println!("================================================================");
    println!("  rust-clash Per-Stage Timing Waterfall Probe");
    println!(
        "  Proxy   : {} -> {} ({})",
        r.requested_proxy, r.effective_outbound, r.protocol
    );
    println!("  Target  : {}", r.url);
    println!(
        "  Verdict : {:?}{}",
        r.verdict,
        r.failed_stage
            .as_ref()
            .map(|s| format!(" (failed at {s})"))
            .unwrap_or_default()
    );
    println!("================================================================");
    println!(
        "  1. DNS Resolve     : {}",
        r.dns_resolve_ms
            .map(|v| format!("{v:.2} ms"))
            .unwrap_or_else(|| "n/a (proxied domain / literal IP)".to_string())
    );
    println!(
        "  2. Tunnel Connect  : {}",
        r.tunnel_connect_ms
            .map(|v| format!("{v:.2} ms"))
            .unwrap_or_else(|| "-".to_string())
    );
    println!(
        "  3. TLS Handshake   : {}{}",
        r.tls_handshake_ms
            .map(|v| format!("{v:.2} ms"))
            .unwrap_or_else(|| "n/a".to_string()),
        r.tls_version
            .as_ref()
            .map(|v| format!(
                " ({}{})",
                v,
                r.alpn
                    .as_ref()
                    .map(|a| format!(", ALPN={a}"))
                    .unwrap_or_default()
            ))
            .unwrap_or_default()
    );
    println!(
        "  4. HTTP TTFB       : {}{}",
        r.http_ttfb_ms
            .map(|v| format!("{v:.2} ms"))
            .unwrap_or_else(|| "-".to_string()),
        r.http_status
            .map(|code| format!(
                " [HTTP {}{}]",
                code,
                if r.cf_mitigated { ", cf-mitigated" } else { "" }
            ))
            .unwrap_or_default()
    );
    println!("  TCP Waterfall Total: {:.2} ms", r.total_ms);
    if (r.overall_probe_duration_ms - r.total_ms).abs() > 1.0 {
        println!(
            "  Overall Probe Time : {:.2} ms (includes parallel UDP check)",
            r.overall_probe_duration_ms
        );
    }
    if let Some(ref udp) = r.udp_probe {
        println!(
            "  UDP Relay Check    : {} ({})",
            udp.status.to_ascii_uppercase(),
            udp.detail
        );
    }
    println!("  Diagnosis          : {}", r.note);
}

fn print_matrix_report(m: &proxy_core::probe::EndpointMatrixReport) {
    println!("================================================================");
    println!("  rust-clash AI & Developer Endpoint Readiness Matrix");
    println!(
        "  Proxy       : {} -> {} ({})",
        m.requested_proxy, m.effective_outbound, m.protocol
    );
    println!(
        "  Unblocked   : {}/{} (AuthReq: {}) | RateLimited(429): {} | Blocked/WAF: {} | AI Egress Unblocked: {}",
        m.reachable_count,
        m.items.len(),
        m.auth_required_count,
        m.rate_limited_count,
        m.blocked_count,
        if m.ai_egress_unblocked { "YES" } else { "NO" }
    );
    println!("  AI Note     : {}", m.ai_status_note);
    println!(
        "  UDP Relay   : {} ({})",
        m.udp_probe.status.to_ascii_uppercase(),
        m.udp_probe.detail
    );
    println!("================================================================");
    for item in &m.items {
        let p = &item.report;
        let status_str = p
            .http_status
            .map(|c| format!("HTTP {c}"))
            .or_else(|| p.failed_stage.clone())
            .unwrap_or_else(|| "-".to_string());
        println!(
            "  [{:<21}] {:<24} {:<10} total={:>6.1}ms (tun={} tls={} ttfb={})",
            format!("{:?}", p.verdict),
            item.label,
            status_str,
            p.total_ms,
            p.tunnel_connect_ms
                .map(|v| format!("{v:.0}ms"))
                .unwrap_or_else(|| "-".into()),
            p.tls_handshake_ms
                .map(|v| format!("{v:.0}ms"))
                .unwrap_or_else(|| "-".into()),
            p.http_ttfb_ms
                .map(|v| format!("{v:.0}ms"))
                .unwrap_or_else(|| "-".into()),
        );
    }
}

fn init_tracing(stderr_only: bool) {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,smoltcp=warn"));
    if stderr_only {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_target(false)
            .with_writer(std::io::stderr)
            .compact()
            .try_init();
    } else {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_target(false)
            .compact()
            .try_init();
    }
}

fn build_sample_yaml(vless_enc: &str) -> String {
    format!(
        r#"mixed-port: 7890
allow-lan: false
bind-address: 127.0.0.1
mode: rule
log-level: info
external-controller: 127.0.0.1:9090

dns:
  enable: true
  listen: 127.0.0.1:1053
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.0/15
  fake-ip-filter:
    - localhost
    - "*.lan"
    - "+.msftconnecttest.com"
  default-nameserver:
    - 1.1.1.1:53
    - 223.5.5.5:53
  nameserver:
    - https://cloudflare-dns.com/dns-query
    - https://dns.alidns.com/dns-query

tun:
  enable: false
  stack: smoltcp
  device: utun-clash0
  auto-route: false
  mtu: 1500

proxies:
  - name: TYO-VLESS-PQ-0RTT
    type: vless
    server: tyo.example.com
    port: 443
    uuid: {}
    encryption: {}
    udp: true

  - name: HK-SS2022-AES256
    type: ss
    server: hk.example.com
    port: 8388
    cipher: 2022-blake3-aes-256-gcm
    password: QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI=
    udp: true

  - name: LAX-AnyTLS-v2
    type: anytls
    server: lax.example.com
    port: 443
    password: replace-with-anytls-password
    sni: lax.example.com
    idle-session-check-interval: 30
    idle-session-timeout: 60
    min-idle-session: 1

proxy-groups:
  - name: 🚀 Proxy
    type: select
    proxies:
      - ⚡ Auto-Best
      - TYO-VLESS-PQ-0RTT
      - HK-SS2022-AES256
      - LAX-AnyTLS-v2
      - DIRECT

  - name: ⚡ Auto-Best
    type: url-test
    proxies:
      - TYO-VLESS-PQ-0RTT
      - HK-SS2022-AES256
      - LAX-AnyTLS-v2
    url: http://www.gstatic.com/generate_204
    interval: 120
    tolerance: 30

rules:
  - DOMAIN-SUFFIX,anthropic.com,🚀 Proxy
  - DOMAIN-SUFFIX,github.com,🚀 Proxy
  - DOMAIN-KEYWORD,google,⚡ Auto-Best
  - GEOSITE,cn,DIRECT
  - GEOIP,PRIVATE,DIRECT,no-resolve
  - GEOIP,CN,DIRECT,no-resolve
  - MATCH,🚀 Proxy
"#,
        Uuid::new_v4(),
        vless_enc
    )
}

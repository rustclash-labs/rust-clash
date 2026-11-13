use std::{
    collections::HashMap,
    net::SocketAddr,
    path::Path,
    sync::{
        Arc, LazyLock, Once,
        atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering},
    },
    time::Duration,
};
#[cfg(unix)]
use std::{
    io,
    os::fd::{FromRawFd, OwnedFd},
};

use jni::{
    JNIEnv, JavaVM,
    objects::{GlobalRef, JClass, JObject, JString},
    sys::{JNI_FALSE, JNI_TRUE, jboolean, jint, jlong, jstring},
};
#[cfg(unix)]
use jni::{
    signature::{Primitive, ReturnType},
    sys::jvalue,
};
use parking_lot::Mutex;
use proxy_core::{
    api::{parse_explain_target, read_process_rss_bytes, spawn_api_server},
    config::{
        ClashConfig, ProxyGroupType, ProxyNodeConfig, REDACTED_SECRET, RunMode,
        uri::redact_sensitive_text,
    },
    dns::FakeIpDnsEngine,
    engine::{NetworkChangeReport, ProxyEngine, build_outbounds_with_dns},
    platform::socket_protect::{clear_global_socket_protector, set_global_socket_protector},
    profile::{
        NodeMutationReport, ProfileManager, RoutingPresetChoice, default_selected_groups_for_config,
    },
    router::{EffectiveOutboundSummary, Router, geodata::GeoDataManager},
};
use tokio::sync::watch;

use crate::fd_bridge::CallbackSocketProtector;
#[cfg(unix)]
use crate::fd_bridge::UnixPacketFdBridge;

static INIT_LOG: Once = Once::new();
static OFFLINE_DELAY_CACHE: LazyLock<Mutex<HashMap<String, u64>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn ensure_tracing_initialized() {
    INIT_LOG.call_once(|| {
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .without_time()
            .try_init();
    });
}

struct AndroidVpnRuntime {
    runtime: tokio::runtime::Runtime,
    engine: Arc<ProxyEngine>,
    api_addr: SocketAddr,
    api_secret: String,
    api_stop_tx: watch::Sender<bool>,
    #[cfg(unix)]
    fd_bridge: Option<UnixPacketFdBridge>,
    protector: Arc<CallbackSocketProtector>,
    network_transitions: AtomicU64,
    last_network_handle: AtomicI64,
    has_network_baseline: AtomicBool,
    is_wifi: AtomicBool,
}

static ANDROID_RUNTIME: Mutex<Option<AndroidVpnRuntime>> = Mutex::new(None);
/// Serializes offline `ProfileManager::open_or_init` mutations so concurrent JNI calls never race on `profiles_index.json`.
static OFFLINE_PROFILE_LOCK: Mutex<()> = Mutex::new(());

fn sync_delays_from_router(router: &Router) {
    let snap = router.proxies_snapshot();
    let mut cache = OFFLINE_DELAY_CACHE.lock();
    for (name, info) in snap {
        if let Some(last) = info.history.last() {
            cache.insert(name, last.delay);
        }
    }
}

fn seed_delays_into_router(router: &Router) {
    let cache = OFFLINE_DELAY_CACHE.lock();
    for (name, &delay) in cache.iter() {
        if delay > 0 {
            router.delays().record(name, delay);
        }
    }
}

fn collect_delays_map_from_router(router: &Router) -> HashMap<String, u64> {
    let mut out = OFFLINE_DELAY_CACHE.lock().clone();
    for (name, info) in router.proxies_snapshot() {
        if let Some(last) = info.history.last() {
            out.insert(name, last.delay);
        }
    }
    out
}

fn generate_ephemeral_api_secret() -> String {
    // 192 bits of OS CSPRNG entropy -> 48 hex chars
    let mut raw = [0u8; 24];
    getrandom_bytes(&mut raw);
    let mut out = String::with_capacity(48);
    for b in raw {
        use std::fmt::Write;
        let _ = write!(&mut out, "{b:02x}");
    }
    out
}

fn getrandom_bytes(buf: &mut [u8]) {
    #[cfg(unix)]
    {
        use std::io::Read;
        if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
            let _ = f.read_exact(buf);
            return;
        }
    }
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        .to_le_bytes();
    for (i, b) in buf.iter_mut().enumerate() {
        *b = nanos[i % nanos.len()] ^ ((i as u8).wrapping_mul(0x9e));
    }
}

fn jstring_to_rust(env: &mut JNIEnv<'_>, s: &JString<'_>) -> Result<String, String> {
    if s.is_null() {
        return Ok(String::new());
    }
    env.get_string(s)
        .map(Into::into)
        .map_err(|e| format!("JNI string read error: {e}"))
}

fn rust_to_jstring<'a>(env: &mut JNIEnv<'a>, s: &str) -> jstring {
    match env.new_string(s) {
        Ok(js) => js.into_raw(),
        Err(_) => ptr::null_jstring(),
    }
}

mod ptr {
    use jni::sys::jstring;
    pub const fn null_jstring() -> jstring {
        std::ptr::null_mut()
    }
}

fn build_android_socket_protector(
    env: &mut JNIEnv<'_>,
    jvm: Arc<JavaVM>,
    vpn_service: &JObject<'_>,
    vpn_service_ref: GlobalRef,
) -> Result<Arc<CallbackSocketProtector>, String> {
    #[cfg(unix)]
    {
        let cls = env
            .get_object_class(vpn_service)
            .map_err(|e| format!("get_object_class(vpnService) failed: {e}"))?;
        let protect_mid = env
            .get_method_id(cls, "protectSocket", "(I)Z")
            .map_err(|e| format!("get_method_id(protectSocket) failed: {e}"))?;

        Ok(Arc::new(CallbackSocketProtector::new_unix(
            "android-vpn-protect",
            false,
            move |fd: i32| {
                let invoke_protect = |jenv: &mut JNIEnv<'_>| -> io::Result<bool> {
                    let res = unsafe {
                        jenv.call_method_unchecked(
                            &vpn_service_ref,
                            protect_mid,
                            ReturnType::Primitive(Primitive::Boolean),
                            &[jvalue { i: fd }],
                        )
                    }
                    .map_err(|e| {
                        io::Error::other(format!("JNI call protectSocket({fd}) failed: {e}"))
                    })?;
                    res.z()
                        .map_err(|e| io::Error::other(format!("JNI boolean decode failed: {e}")))
                };

                let ok = match jvm.get_env() {
                    Ok(mut jenv) => invoke_protect(&mut jenv)?,
                    Err(_) => {
                        let mut guard = jvm.attach_current_thread().map_err(|e| {
                            io::Error::other(format!("JNI attach_current_thread failed: {e}"))
                        })?;
                        invoke_protect(&mut guard)?
                    }
                };
                if !ok {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        format!(
                            "Android VpnService.protect({fd}) returned false — refusing unprotected outbound socket to prevent VPN loop"
                        ),
                    ));
                }
                Ok(())
            },
        )))
    }
    #[cfg(not(unix))]
    {
        let _ = (env, jvm, vpn_service, vpn_service_ref);
        Ok(Arc::new(CallbackSocketProtector::counting(
            "android-vpn-protect",
            false,
        )))
    }
}

fn stop_existing_locked(slot: &mut Option<AndroidVpnRuntime>) {
    #[allow(unused_mut)]
    if let Some(mut prev) = slot.take() {
        sync_delays_from_router(&prev.engine.router());
        #[cfg(unix)]
        if let Some(mut fb) = prev.fd_bridge.take() {
            fb.stop();
        }
        let _ = prev.api_stop_tx.send(true);
        prev.engine.shutdown();
        clear_global_socket_protector();
        prev.runtime.shutdown_timeout(Duration::from_millis(300));
    }
}

fn build_offline_router(
    cfg: &ClashConfig,
    saved_selections: &HashMap<String, String>,
    state_dir: Option<&Path>,
) -> Result<(Router, proxy_core::router::geodata::GeoDataStatus), String> {
    let normalized = default_selected_groups_for_config(cfg, saved_selections);
    let (mmdb_opt, geo_status) = if let Some(dir) = state_dir {
        let gm = GeoDataManager::new(dir, Vec::new());
        (gm.mmdb_reader(), gm.status())
    } else {
        (None, GeoDataManager::builtin_status())
    };
    let dns = Arc::new(
        FakeIpDnsEngine::new(&cfg.dns_with_merged_hosts())
            .map_err(|e| redact_sensitive_text(&e.to_string()))?,
    );
    let outbounds = build_outbounds_with_dns(&cfg.proxies, &[], Some(Arc::clone(&dns)))
        .map_err(|e| redact_sensitive_text(&e.to_string()))?;
    let router = Router::with_providers_mmdb_and_state_dir(
        cfg.mode,
        outbounds,
        &cfg.proxy_groups,
        &cfg.rules,
        &cfg.rule_providers,
        mmdb_opt,
        state_dir,
        dns,
    )
    .map_err(|e| redact_sensitive_text(&e.to_string()))?;
    router.apply_saved_selections(&normalized);
    seed_delays_into_router(&router);
    Ok((router, geo_status))
}

fn compute_offline_effective_summary(
    cfg: &ClashConfig,
    saved_selections: &HashMap<String, String>,
    state_dir: Option<&Path>,
) -> EffectiveOutboundSummary {
    if let Ok((router, _)) = build_offline_router(cfg, saved_selections, state_dir) {
        return router.effective_primary_outbound();
    }
    EffectiveOutboundSummary {
        mode: cfg.mode,
        primary_group: cfg.proxy_groups.first().map(|g| g.name.clone()),
        selected_member: None,
        effective_outbound: "DIRECT".to_string(),
        effective_protocol: "DIRECT".to_string(),
        chains: vec!["DIRECT".to_string()],
    }
}

fn build_ordered_groups_json(cfg: &ClashConfig, router: &Router) -> Vec<serde_json::Value> {
    let snap = router.proxies_snapshot();
    let mut ordered_names: Vec<String> = cfg.proxy_groups.iter().map(|g| g.name.clone()).collect();
    if !ordered_names.iter().any(|n| n == "GLOBAL") && snap.contains_key("GLOBAL") {
        ordered_names.push("GLOBAL".to_string());
    }
    let mut out = Vec::with_capacity(ordered_names.len());
    for name in ordered_names {
        if let Some(info) = snap.get(&name) {
            out.push(serde_json::json!({
                "name": info.name,
                "type": info.proxy_type,
                "now": info.now,
                "all": info.all.clone().unwrap_or_default(),
                "effectiveOutbound": info.effective_outbound,
                "effectiveProtocol": info.effective_protocol,
                "chains": info.chains.clone().unwrap_or_default(),
            }));
        }
    }
    out
}

fn primary_selector_group_name(cfg: &ClashConfig) -> String {
    cfg.proxy_groups
        .iter()
        .find(|g| {
            g.group_type == ProxyGroupType::Select && (g.name == "PROXY" || g.name == "🚀 Proxy")
        })
        .or_else(|| {
            cfg.proxy_groups
                .iter()
                .find(|g| g.group_type == ProxyGroupType::Select)
        })
        .map(|g| g.name.clone())
        .unwrap_or_else(|| "PROXY".to_string())
}

fn live_handle_and_engine() -> Option<(tokio::runtime::Handle, Arc<ProxyEngine>)> {
    let guard = ANDROID_RUNTIME.lock();
    guard
        .as_ref()
        .map(|rt| (rt.runtime.handle().clone(), Arc::clone(&rt.engine)))
}

/// Pure-Rust core implementation of `nativeStartVpn` (backwards-compatible wrapper without explicit `state_dir`).
pub fn start_android_vpn_core(
    #[cfg(unix)] owned_tun_fd: Option<OwnedFd>,
    yaml_str: &str,
    is_demo: bool,
    protector: Arc<CallbackSocketProtector>,
) -> Result<serde_json::Value, String> {
    start_android_vpn_with_state_dir(
        #[cfg(unix)]
        owned_tun_fd,
        None,
        yaml_str,
        is_demo,
        protector,
    )
}

/// Pure-Rust core implementation of `nativeStartVpnWithStateDir` with strict RAII `OwnedFd` ownership
/// and persistent `ProfileManager` state restoration.
///
/// Guarantees:
/// - `owned_tun_fd` is owned from entry: ANY failure drops `owned_tun_fd` deterministically (`close(fd)`)
///   AND rolls back any partially started `ProxyEngine`, `SocketProtector`, and Tokio runtime.
/// - When `state_dir` is supplied, opens `ProfileManager::open_or_init(state_dir)`, restores all
///   saved nodes and group selections (`selected_groups`), and attaches `ProfileManager` to the live
///   engine so changes made while VPN is running persist across restarts.
pub fn start_android_vpn_with_state_dir(
    #[cfg(unix)] owned_tun_fd: Option<OwnedFd>,
    state_dir: Option<&Path>,
    yaml_str: &str,
    is_demo: bool,
    protector: Arc<CallbackSocketProtector>,
) -> Result<serde_json::Value, String> {
    start_android_vpn_with_state_dir_and_jvm(
        #[cfg(unix)]
        owned_tun_fd,
        state_dir,
        yaml_str,
        is_demo,
        protector,
        None,
    )
}

fn start_android_vpn_with_state_dir_and_jvm(
    #[cfg(unix)] owned_tun_fd: Option<OwnedFd>,
    state_dir: Option<&Path>,
    yaml_str: &str,
    is_demo: bool,
    protector: Arc<CallbackSocketProtector>,
    jvm: Option<Arc<JavaVM>>,
) -> Result<serde_json::Value, String> {
    let mut guard = ANDROID_RUNTIME.lock();
    stop_existing_locked(&mut guard);

    // 1. Install `VpnService.protect(fd)` global SocketProtector BEFORE starting ProxyEngine!
    set_global_socket_protector(Arc::clone(&protector) as _);

    let mut rt_builder = tokio::runtime::Builder::new_multi_thread();
    rt_builder
        .worker_threads(4)
        .enable_all()
        .thread_name("rc-android-tokio");
    if let Some(jvm_for_workers) = jvm {
        rt_builder.on_thread_start(move || {
            let _ = jvm_for_workers.attach_current_thread_as_daemon();
        });
    }

    let rt = match rt_builder.build() {
        Ok(r) => r,
        Err(e) => {
            clear_global_socket_protector();
            // `owned_tun_fd` drops here via RAII -> `close(fd)` guaranteed!
            return Err(format!("Tokio runtime init failed: {e}"));
        }
    };

    let ephemeral_secret = generate_ephemeral_api_secret();

    let startup_res = rt.block_on(async {
        let eng = if is_demo {
            let e = ProxyEngine::start_demo(
                Some(0),
                Some("127.0.0.1:0".into()),
                Some("127.0.0.1:0".into()),
            )
            .await
            .map_err(|e| format!("start_demo failed: {e}"))?;
            let mut cfg = e.config_snapshot();
            cfg.tun.enable = true;
            cfg.tun.auto_route = false;
            cfg.tun.ipv6 = true;
            cfg.secret = Some(ephemeral_secret.clone());
            let yaml = match cfg.to_yaml_string() {
                Ok(y) => y,
                Err(err) => {
                    e.shutdown();
                    return Err(format!("serialize demo yaml: {err}"));
                }
            };
            if let Err(err) = e.reload_yaml(&yaml).await {
                e.shutdown();
                return Err(format!("enable demo virtual tun: {err}"));
            }
            if let Some(dir) = state_dir
                && let Ok(mgr) = ProfileManager::open_or_init(dir)
            {
                e.attach_profile_manager(mgr);
            }
            e
        } else if let Some(dir) = state_dir {
            let mgr = ProfileManager::open_or_init(dir)
                .map_err(|e| redact_sensitive_text(&format!("profile storage init failed: {e}")))?;
            let (mut cfg, _) = mgr
                .load_active_config()
                .map_err(|e| redact_sensitive_text(&format!("load active profile failed: {e}")))?;

            // Migrate legacy Keystore YAML if ProfileManager is still on untouched 0-node starter
            if cfg.proxies.is_empty() && !yaml_str.trim().is_empty() {
                let migrated = mgr
                    .import_unified_input(yaml_str, Some("Migrated Profile"), true, true)
                    .await
                    .map_err(|e| redact_sensitive_text(&format!("invalid profile: {e}")))?;
                cfg = migrated.config;
            }

            cfg.mixed_port = 0;
            cfg.dns.listen = "127.0.0.1:0".to_string();
            cfg.tun.enable = true;
            cfg.tun.auto_route = false;
            cfg.tun.ipv6 = true;
            if cfg.secret.as_ref().is_none_or(|s| s.trim().is_empty()) {
                cfg.secret = Some(ephemeral_secret.clone());
            }

            let e = ProxyEngine::start_with_state_dir(cfg, dir.to_path_buf())
                .await
                .map_err(|e| redact_sensitive_text(&format!("ProxyEngine start failed: {e}")))?;
            e.attach_profile_manager(mgr);
            e
        } else {
            let mut cfg = if yaml_str.trim().is_empty() {
                ClashConfig::from_yaml_str(&ClashConfig::default_starter_yaml())
                    .map_err(|e| format!("starter yaml error: {e}"))?
            } else {
                ClashConfig::from_yaml_str(yaml_str)
                    .map_err(|e| redact_sensitive_text(&format!("invalid YAML profile: {e}")))?
            };
            cfg.tun.enable = true;
            cfg.tun.auto_route = false;
            cfg.tun.ipv6 = true;
            if cfg.secret.as_ref().is_none_or(|s| s.trim().is_empty()) {
                cfg.secret = Some(ephemeral_secret.clone());
            }
            ProxyEngine::start(cfg)
                .await
                .map_err(|e| redact_sensitive_text(&format!("ProxyEngine start failed: {e}")))?
        };

        let sec = eng
            .config_snapshot()
            .secret
            .unwrap_or_else(|| ephemeral_secret.clone());
        let (stop_tx, stop_rx) = watch::channel(false);
        let (bound_api, _api_task) = spawn_api_server("127.0.0.1:0", Arc::clone(&eng), stop_rx)
            .await
            .map_err(|e| {
                eng.shutdown();
                format!("spawn_api_server failed: {e}")
            })?;
        Ok::<_, String>((eng, sec, bound_api, stop_tx))
    });

    let (engine, active_secret, api_addr, api_stop_tx) = match startup_res {
        Ok(tuple) => tuple,
        Err(err) => {
            clear_global_socket_protector();
            rt.shutdown_timeout(Duration::from_millis(250));
            // `owned_tun_fd` drops here via RAII -> `close(fd)` guaranteed!
            return Err(redact_sensitive_text(&err));
        }
    };

    seed_delays_into_router(&engine.router());

    // 2. Attach Android's established `VpnService` `OwnedFd` to `VirtualTunHandle`
    #[cfg(unix)]
    let fd_bridge = if let Some(tun_owned) = owned_tun_fd {
        let Some(vtun) = engine.take_virtual_tun_handle() else {
            drop(tun_owned);
            let _ = api_stop_tx.send(true);
            engine.shutdown();
            clear_global_socket_protector();
            rt.shutdown_timeout(Duration::from_millis(250));
            return Err("virtual smoltcp handle missing for Android VPN fd".to_string());
        };
        match UnixPacketFdBridge::attach_owned_fd(tun_owned, vtun) {
            Ok(b) => Some(b),
            Err(e) => {
                // `tun_owned` was already consumed and closed by `attach_owned_fd`!
                let _ = api_stop_tx.send(true);
                engine.shutdown();
                clear_global_socket_protector();
                rt.shutdown_timeout(Duration::from_millis(250));
                return Err(format!("failed attaching Android VpnService fd: {e}"));
            }
        }
    } else {
        None
    };

    let mixed_port = engine.mixed_addr().port();
    let dns_listen = engine.dns_addr().map(|a| a.to_string());
    let eff = engine.router().effective_primary_outbound();

    *guard = Some(AndroidVpnRuntime {
        runtime: rt,
        engine,
        api_addr,
        api_secret: active_secret.clone(),
        api_stop_tx,
        #[cfg(unix)]
        fd_bridge,
        protector,
        network_transitions: AtomicU64::new(0),
        last_network_handle: AtomicI64::new(0),
        has_network_baseline: AtomicBool::new(false),
        is_wifi: AtomicBool::new(true),
    });

    Ok(serde_json::json!({
        "ok": true,
        "apiUrl": format!("http://{api_addr}"),
        "apiPort": api_addr.port(),
        "apiSecret": active_secret,
        "mixedPort": mixed_port,
        "dnsListen": dns_listen,
        "effectiveOutbound": eff.effective_outbound,
        "effectiveProtocol": eff.effective_protocol,
    }))
}

/// Pure-Rust core implementation of `nativeStopVpn` (used by user stop, `onRevoke()`, and `onDestroy()`).
pub fn stop_android_vpn_core() -> bool {
    let mut guard = ANDROID_RUNTIME.lock();
    let was_active = guard.is_some();
    stop_existing_locked(&mut guard);
    was_active
}

/// Pure-Rust core implementation of `nativeNotifyNetworkChanged`.
pub fn notify_android_network_changed_core(
    network_handle: i64,
    is_wifi: bool,
) -> Option<NetworkChangeReport> {
    let guard = ANDROID_RUNTIME.lock();
    let rt = guard.as_ref()?;

    let had_baseline = rt.has_network_baseline.swap(true, Ordering::AcqRel);
    let prev_handle = rt
        .last_network_handle
        .swap(network_handle, Ordering::AcqRel);
    let prev_wifi = rt.is_wifi.swap(is_wifi, Ordering::AcqRel);

    if !had_baseline && network_handle != 0 {
        return Some(NetworkChangeReport {
            closed_active_connections: 0,
            reset_udp_nat_sessions: 0,
            evicted_tls_sessions: 0,
            dns_cache_flushed: false,
        });
    }

    if prev_handle != network_handle || prev_wifi != is_wifi {
        rt.network_transitions.fetch_add(1, Ordering::Relaxed);
        let report = rt.engine.notify_network_change();
        rt.engine.hub().push_log(
            "info",
            format!(
                "Android network handoff (handle {prev_handle} -> {network_handle}, wifi={is_wifi}): closed_tcp={}, reset_udp_nat={}, evicted_tls_pool={}",
                report.closed_active_connections,
                report.reset_udp_nat_sessions,
                report.evicted_tls_sessions
            ),
        );
        return Some(report);
    }

    Some(NetworkChangeReport {
        closed_active_connections: 0,
        reset_udp_nat_sessions: 0,
        evicted_tls_sessions: 0,
        dns_cache_flushed: false,
    })
}

/// Pure-Rust core status snapshot for `nativeGetStatusJson` and lifecycle tests.
pub fn android_status_json_core() -> serde_json::Value {
    let guard = ANDROID_RUNTIME.lock();
    if let Some(rt) = guard.as_ref() {
        let (up_rate, down_rate) = rt
            .engine
            .hub()
            .traffic_history()
            .last()
            .map(|p| (p.up, p.down))
            .unwrap_or((0, 0));
        let (up_total, down_total) = rt.engine.hub().totals();
        #[cfg(unix)]
        let (rx_pkts, tx_pkts) = rt
            .fd_bridge
            .as_ref()
            .map(|b| (b.rx_packets(), b.tx_packets()))
            .unwrap_or((0, 0));
        #[cfg(not(unix))]
        let (rx_pkts, tx_pkts) = (0u64, 0u64);
        let router = rt.engine.router();
        let eff = router.effective_primary_outbound();
        let active_delay = router.delays().latest_delay(&eff.effective_outbound);

        serde_json::json!({
            "running": true,
            "demoActive": rt.engine.demo_info().enabled,
            "mode": router.mode().as_str(),
            "effectiveOutbound": eff.effective_outbound,
            "effectiveProtocol": eff.effective_protocol,
            "effectiveDelayMs": active_delay,
            "apiUrl": format!("http://{}", rt.api_addr),
            "apiSecret": rt.api_secret,
            "mixedPort": rt.engine.mixed_addr().port(),
            "upRate": up_rate,
            "downRate": down_rate,
            "upTotal": up_total,
            "downTotal": down_total,
            "rssBytes": read_process_rss_bytes(),
            "activeConnections": rt.engine.hub().active_connection_count(),
            "fakeIpEntries": router.dns().entry_count(),
            "protectedSockets": rt.protector.tcp_count() + rt.protector.udp_count(),
            "tunRxPackets": rx_pkts,
            "tunTxPackets": tx_pkts,
            "networkTransitions": rt.network_transitions.load(Ordering::Relaxed),
            "isWifi": rt.is_wifi.load(Ordering::Acquire),
        })
    } else {
        serde_json::json!({
            "running": false,
        })
    }
}

fn build_android_mutation_json(
    mgr: &ProfileManager,
    report: &NodeMutationReport,
    vpn_running: bool,
    live_eff: Option<EffectiveOutboundSummary>,
) -> serde_json::Value {
    let redacted_nodes = mgr.list_active_nodes_redacted().unwrap_or_default();
    let state_dir = mgr.state_dir();
    let eff = live_eff.unwrap_or_else(|| {
        compute_offline_effective_summary(&report.config, &report.selected_groups, Some(&state_dir))
    });
    let primary_grp = primary_selector_group_name(&report.config);
    serde_json::json!({
        "ok": true,
        "vpnRunning": vpn_running,
        "activeProfileId": mgr.active_profile_id(),
        "inputKind": report.input_kind,
        "count": report.added_nodes.len(),
        "addedNodes": report.added_nodes,
        "updatedNode": report.updated_node,
        "removedNodes": report.removed_nodes,
        "skippedDuplicates": report.skipped_duplicates,
        "skippedUnsupported": report.skipped_unsupported,
        "totalNodes": report.total_nodes,
        "primaryGroup": primary_grp,
        "selectedGroups": report.selected_groups,
        "effectiveOutbound": eff.effective_outbound,
        "effectiveProtocol": eff.effective_protocol,
        "nodes": redacted_nodes,
    })
}

/// Offline + Live unified snapshot of saved nodes, groups, routing preset, rules, GeoData, delays,
/// active profile, and effective outbound.
pub fn android_node_manager_snapshot_core(state_dir: &Path) -> Result<serde_json::Value, String> {
    if let Some((_, engine)) = live_handle_and_engine() {
        let mgr = engine
            .ensure_profile_manager()
            .map_err(|e| redact_sensitive_text(&e.to_string()))?;
        let demo_active = engine.demo_info().enabled;
        let cfg = engine.config_snapshot();
        let nodes: Vec<ProxyNodeConfig> = if demo_active {
            cfg.proxies
                .iter()
                .map(ProxyNodeConfig::redacted_clone)
                .collect()
        } else {
            mgr.list_active_nodes_redacted()
                .map_err(|e| redact_sensitive_text(&e.to_string()))?
        };
        let router = engine.router();
        sync_delays_from_router(&router);
        let eff = router.effective_primary_outbound();
        let groups = build_ordered_groups_json(&cfg, &router);
        let delays = collect_delays_map_from_router(&router);
        let rules = router.rules_snapshot();
        let routing = mgr.routing_snapshot().ok();
        let geodata = engine.geodata_status();
        return Ok(serde_json::json!({
            "ok": true,
            "vpnRunning": true,
            "demoActive": demo_active,
            "activeProfileId": mgr.active_profile_id(),
            "mode": router.mode().as_str(),
            "primaryGroup": primary_selector_group_name(&cfg),
            "selectedGroups": router.manual_selections_snapshot(),
            "effectiveOutbound": eff.effective_outbound,
            "effectiveProtocol": eff.effective_protocol,
            "nodes": nodes,
            "groups": groups,
            "delays": delays,
            "rules": rules,
            "routing": routing,
            "geodata": geodata,
        }));
    }

    let mgr = ProfileManager::open_or_init(state_dir)
        .map_err(|e| redact_sensitive_text(&e.to_string()))?;
    let (cfg, _) = mgr
        .load_active_config()
        .map_err(|e| redact_sensitive_text(&e.to_string()))?;
    let saved_sel = mgr.active_selected_groups();
    let normalized_sel = default_selected_groups_for_config(&cfg, &saved_sel);
    let nodes: Vec<ProxyNodeConfig> = cfg
        .proxies
        .iter()
        .map(ProxyNodeConfig::redacted_clone)
        .collect();
    let routing = mgr.routing_snapshot().ok();

    let (eff, groups, delays, rules, geodata) =
        match build_offline_router(&cfg, &normalized_sel, Some(state_dir)) {
            Ok((router, geo)) => {
                let eff = router.effective_primary_outbound();
                let groups = build_ordered_groups_json(&cfg, &router);
                let delays = collect_delays_map_from_router(&router);
                let rules = router.rules_snapshot();
                (eff, groups, delays, rules, geo)
            }
            Err(_) => {
                let gm = GeoDataManager::new(state_dir, Vec::new());
                (
                    compute_offline_effective_summary(&cfg, &normalized_sel, Some(state_dir)),
                    Vec::new(),
                    OFFLINE_DELAY_CACHE.lock().clone(),
                    Vec::new(),
                    gm.status(),
                )
            }
        };

    Ok(serde_json::json!({
        "ok": true,
        "vpnRunning": false,
        "demoActive": false,
        "activeProfileId": mgr.active_profile_id(),
        "mode": cfg.mode.as_str(),
        "primaryGroup": primary_selector_group_name(&cfg),
        "selectedGroups": normalized_sel,
        "effectiveOutbound": eff.effective_outbound,
        "effectiveProtocol": eff.effective_protocol,
        "nodes": nodes,
        "groups": groups,
        "delays": delays,
        "rules": rules,
        "routing": routing,
        "geodata": geodata,
    }))
}

/// Offline + Live unified import for `ss://`, `vless://`, `anytls://`, Base64 subscriptions,
/// Clash YAML, `clash://install-config?url=...`, and `https://` subscription URLs.
pub fn android_import_unified_core(
    state_dir: &Path,
    raw_input: &str,
    deduplicate: bool,
    auto_select: bool,
) -> Result<serde_json::Value, String> {
    if let Some((handle, engine)) = live_handle_and_engine() {
        let mgr = engine
            .ensure_profile_manager()
            .map_err(|e| redact_sensitive_text(&e.to_string()))?;
        let report = handle
            .block_on(engine.import_unified_live(raw_input, None, deduplicate, auto_select))
            .map_err(|e| redact_sensitive_text(&e.to_string()))?;
        let eff = engine.router().effective_primary_outbound();
        return Ok(build_android_mutation_json(&mgr, &report, true, Some(eff)));
    }

    let _offline_guard = OFFLINE_PROFILE_LOCK.lock();
    let mgr = ProfileManager::open_or_init(state_dir)
        .map_err(|e| redact_sensitive_text(&e.to_string()))?;
    let temp_rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("Tokio init failed: {e}"))?;
    let report = temp_rt
        .block_on(mgr.import_unified_input(raw_input, None, deduplicate, auto_select))
        .map_err(|e| redact_sensitive_text(&e.to_string()))?;
    Ok(build_android_mutation_json(&mgr, &report, false, None))
}

/// Offline + Live persistent proxy selection in any `Select` group (`PROXY`, `🚀 Proxy`, etc.).
pub fn android_select_proxy_persisted_core(
    state_dir: &Path,
    group_name: &str,
    proxy_name: &str,
) -> Result<serde_json::Value, String> {
    if let Some((_, engine)) = live_handle_and_engine() {
        let _ = engine
            .ensure_profile_manager()
            .map_err(|e| redact_sensitive_text(&e.to_string()))?;
        engine
            .select_group_and_persist(group_name, proxy_name)
            .map_err(|e| redact_sensitive_text(&e.to_string()))?;
        return android_node_manager_snapshot_core(state_dir);
    }

    {
        let _offline_guard = OFFLINE_PROFILE_LOCK.lock();
        let mgr = ProfileManager::open_or_init(state_dir)
            .map_err(|e| redact_sensitive_text(&e.to_string()))?;
        mgr.save_group_selection(group_name, proxy_name)
            .map_err(|e| redact_sensitive_text(&e.to_string()))?;
    }
    android_node_manager_snapshot_core(state_dir)
}

/// Offline + Live create / edit / rename of a concrete proxy node.
pub fn android_upsert_node_core(
    state_dir: &Path,
    original_name: Option<&str>,
    node_json: &str,
    auto_select: bool,
) -> Result<serde_json::Value, String> {
    let node: ProxyNodeConfig = serde_json::from_str(node_json)
        .map_err(|e| redact_sensitive_text(&format!("invalid node JSON: {e}")))?;

    if let Some((handle, engine)) = live_handle_and_engine() {
        let mgr = engine
            .ensure_profile_manager()
            .map_err(|e| redact_sensitive_text(&e.to_string()))?;
        let report = handle
            .block_on(engine.upsert_node_live(original_name, node, auto_select))
            .map_err(|e| redact_sensitive_text(&e.to_string()))?;
        let eff = engine.router().effective_primary_outbound();
        return Ok(build_android_mutation_json(&mgr, &report, true, Some(eff)));
    }

    let _offline_guard = OFFLINE_PROFILE_LOCK.lock();
    let mgr = ProfileManager::open_or_init(state_dir)
        .map_err(|e| redact_sensitive_text(&e.to_string()))?;
    let report = mgr
        .upsert_node_in_active(original_name, node, auto_select)
        .map_err(|e| redact_sensitive_text(&e.to_string()))?;
    Ok(build_android_mutation_json(&mgr, &report, false, None))
}

/// Offline + Live deletion of a concrete proxy node.
pub fn android_delete_node_core(
    state_dir: &Path,
    target_name: &str,
) -> Result<serde_json::Value, String> {
    if let Some((handle, engine)) = live_handle_and_engine() {
        let mgr = engine
            .ensure_profile_manager()
            .map_err(|e| redact_sensitive_text(&e.to_string()))?;
        let report = handle
            .block_on(engine.delete_node_live(target_name))
            .map_err(|e| redact_sensitive_text(&e.to_string()))?;
        let eff = engine.router().effective_primary_outbound();
        return Ok(build_android_mutation_json(&mgr, &report, true, Some(eff)));
    }

    let _offline_guard = OFFLINE_PROFILE_LOCK.lock();
    let mgr = ProfileManager::open_or_init(state_dir)
        .map_err(|e| redact_sensitive_text(&e.to_string()))?;
    let report = mgr
        .delete_node_from_active(target_name)
        .map_err(|e| redact_sensitive_text(&e.to_string()))?;
    Ok(build_android_mutation_json(&mgr, &report, false, None))
}

/// Offline + Live deduplication of saved proxy nodes.
pub fn android_deduplicate_nodes_core(state_dir: &Path) -> Result<serde_json::Value, String> {
    if let Some((handle, engine)) = live_handle_and_engine() {
        let mgr = engine
            .ensure_profile_manager()
            .map_err(|e| redact_sensitive_text(&e.to_string()))?;
        let report = handle
            .block_on(engine.deduplicate_nodes_live())
            .map_err(|e| redact_sensitive_text(&e.to_string()))?;
        let eff = engine.router().effective_primary_outbound();
        return Ok(build_android_mutation_json(&mgr, &report, true, Some(eff)));
    }

    let _offline_guard = OFFLINE_PROFILE_LOCK.lock();
    let mgr = ProfileManager::open_or_init(state_dir)
        .map_err(|e| redact_sensitive_text(&e.to_string()))?;
    let report = mgr
        .deduplicate_active_nodes()
        .map_err(|e| redact_sensitive_text(&e.to_string()))?;
    Ok(build_android_mutation_json(&mgr, &report, false, None))
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_rustclashlabs_rustclash_vpn_NativeBridge_nativeStartVpn<
    'local,
>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    vpn_service: JObject<'local>,
    tun_fd: jint,
    yaml_config: JString<'local>,
    demo_mode: jboolean,
) -> jstring {
    ensure_tracing_initialized();

    #[cfg(unix)]
    let owned_tun_fd: Result<Option<OwnedFd>, String> = if tun_fd >= 0 {
        Ok(Some(unsafe { OwnedFd::from_raw_fd(tun_fd) }))
    } else if tun_fd == -1 {
        Ok(None)
    } else {
        Err(format!("invalid negative Android TUN fd: {tun_fd}"))
    };

    #[cfg(not(unix))]
    let _ = tun_fd;

    let res = (|| -> Result<serde_json::Value, String> {
        #[cfg(unix)]
        let tun_raii = owned_tun_fd?;

        let yaml_str = jstring_to_rust(&mut env, &yaml_config)?;
        let jvm = Arc::new(
            env.get_java_vm()
                .map_err(|e| format!("get_java_vm failed: {e}"))?,
        );
        let vpn_global = env
            .new_global_ref(&vpn_service)
            .map_err(|e| format!("new_global_ref(vpnService) failed: {e}"))?;

        let protector =
            build_android_socket_protector(&mut env, Arc::clone(&jvm), &vpn_service, vpn_global)?;
        start_android_vpn_with_state_dir_and_jvm(
            #[cfg(unix)]
            tun_raii,
            None,
            &yaml_str,
            demo_mode == JNI_TRUE,
            protector,
            Some(jvm),
        )
    })();

    let out = match res {
        Ok(v) => v.to_string(),
        Err(err) => serde_json::json!({
            "ok": false,
            "error": redact_sensitive_text(&err),
        })
        .to_string(),
    };
    rust_to_jstring(&mut env, &out)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_rustclashlabs_rustclash_vpn_NativeBridge_nativeStartVpnWithStateDir<
    'local,
>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    vpn_service: JObject<'local>,
    tun_fd: jint,
    state_dir_jstr: JString<'local>,
    yaml_config: JString<'local>,
    demo_mode: jboolean,
) -> jstring {
    ensure_tracing_initialized();

    // CRITICAL RAII STEP: Immediately claim ownership of detached `tun_fd >= 0` BEFORE any `?` return!
    #[cfg(unix)]
    let owned_tun_fd: Result<Option<OwnedFd>, String> = if tun_fd >= 0 {
        Ok(Some(unsafe { OwnedFd::from_raw_fd(tun_fd) }))
    } else if tun_fd == -1 {
        Ok(None)
    } else {
        Err(format!("invalid negative Android TUN fd: {tun_fd}"))
    };

    #[cfg(not(unix))]
    let _ = tun_fd;

    let res = (|| -> Result<serde_json::Value, String> {
        #[cfg(unix)]
        let tun_raii = owned_tun_fd?;

        let state_dir_raw = jstring_to_rust(&mut env, &state_dir_jstr)?;
        let yaml_str = jstring_to_rust(&mut env, &yaml_config)?;
        let jvm = Arc::new(
            env.get_java_vm()
                .map_err(|e| format!("get_java_vm failed: {e}"))?,
        );
        let vpn_global = env
            .new_global_ref(&vpn_service)
            .map_err(|e| format!("new_global_ref(vpnService) failed: {e}"))?;

        let protector =
            build_android_socket_protector(&mut env, Arc::clone(&jvm), &vpn_service, vpn_global)?;
        let opt_dir = if state_dir_raw.trim().is_empty() {
            None
        } else {
            Some(Path::new(state_dir_raw.trim()))
        };
        start_android_vpn_with_state_dir_and_jvm(
            #[cfg(unix)]
            tun_raii,
            opt_dir,
            &yaml_str,
            demo_mode == JNI_TRUE,
            protector,
            Some(jvm),
        )
    })();

    let out = match res {
        Ok(v) => v.to_string(),
        Err(err) => serde_json::json!({
            "ok": false,
            "error": redact_sensitive_text(&err),
        })
        .to_string(),
    };
    rust_to_jstring(&mut env, &out)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_rustclashlabs_rustclash_vpn_NativeBridge_nativeStopVpn(
    _env: JNIEnv<'_>,
    _class: JClass<'_>,
) -> jboolean {
    if stop_android_vpn_core() {
        JNI_TRUE
    } else {
        JNI_FALSE
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_rustclashlabs_rustclash_vpn_NativeBridge_nativeNotifyNetworkChanged(
    _env: JNIEnv<'_>,
    _class: JClass<'_>,
    network_handle: jlong,
    is_wifi: jboolean,
) -> jboolean {
    if notify_android_network_changed_core(network_handle, is_wifi == JNI_TRUE).is_some() {
        JNI_TRUE
    } else {
        JNI_FALSE
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_rustclashlabs_rustclash_vpn_NativeBridge_nativeGetStatusJson(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
) -> jstring {
    let payload = android_status_json_core();
    rust_to_jstring(&mut env, &payload.to_string())
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_rustclashlabs_rustclash_vpn_NativeBridge_nativeGetNodeManagerSnapshot<
    'local,
>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    state_dir_jstr: JString<'local>,
) -> jstring {
    ensure_tracing_initialized();
    let res = (|| -> Result<serde_json::Value, String> {
        let dir = jstring_to_rust(&mut env, &state_dir_jstr)?;
        android_node_manager_snapshot_core(Path::new(dir.trim()))
    })();
    let out = match res {
        Ok(v) => v.to_string(),
        Err(e) => {
            serde_json::json!({ "ok": false, "error": redact_sensitive_text(&e) }).to_string()
        }
    };
    rust_to_jstring(&mut env, &out)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_rustclashlabs_rustclash_vpn_NativeBridge_nativeImportUnifiedPayload<
    'local,
>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    state_dir_jstr: JString<'local>,
    payload_jstr: JString<'local>,
    deduplicate: jboolean,
    auto_select: jboolean,
) -> jstring {
    ensure_tracing_initialized();
    let res = (|| -> Result<serde_json::Value, String> {
        let dir = jstring_to_rust(&mut env, &state_dir_jstr)?;
        let payload = jstring_to_rust(&mut env, &payload_jstr)?;
        android_import_unified_core(
            Path::new(dir.trim()),
            &payload,
            deduplicate == JNI_TRUE,
            auto_select == JNI_TRUE,
        )
    })();
    let out = match res {
        Ok(v) => v.to_string(),
        Err(e) => {
            serde_json::json!({ "ok": false, "error": redact_sensitive_text(&e) }).to_string()
        }
    };
    rust_to_jstring(&mut env, &out)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_rustclashlabs_rustclash_vpn_NativeBridge_nativeSelectProxyPersisted<
    'local,
>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    state_dir_jstr: JString<'local>,
    group_name_jstr: JString<'local>,
    proxy_name_jstr: JString<'local>,
) -> jstring {
    ensure_tracing_initialized();
    let res = (|| -> Result<serde_json::Value, String> {
        let dir = jstring_to_rust(&mut env, &state_dir_jstr)?;
        let grp = jstring_to_rust(&mut env, &group_name_jstr)?;
        let prx = jstring_to_rust(&mut env, &proxy_name_jstr)?;
        android_select_proxy_persisted_core(Path::new(dir.trim()), &grp, &prx)
    })();
    let out = match res {
        Ok(v) => v.to_string(),
        Err(e) => {
            serde_json::json!({ "ok": false, "error": redact_sensitive_text(&e) }).to_string()
        }
    };
    rust_to_jstring(&mut env, &out)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_rustclashlabs_rustclash_vpn_NativeBridge_nativeUpsertNodeJson<
    'local,
>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    state_dir_jstr: JString<'local>,
    original_name_jstr: JString<'local>,
    node_json_jstr: JString<'local>,
    auto_select: jboolean,
) -> jstring {
    ensure_tracing_initialized();
    let res = (|| -> Result<serde_json::Value, String> {
        let dir = jstring_to_rust(&mut env, &state_dir_jstr)?;
        let orig = jstring_to_rust(&mut env, &original_name_jstr)?;
        let node_json = jstring_to_rust(&mut env, &node_json_jstr)?;
        let orig_opt = if orig.trim().is_empty() {
            None
        } else {
            Some(orig.trim())
        };
        android_upsert_node_core(
            Path::new(dir.trim()),
            orig_opt,
            &node_json,
            auto_select == JNI_TRUE,
        )
    })();
    let out = match res {
        Ok(v) => v.to_string(),
        Err(e) => {
            serde_json::json!({ "ok": false, "error": redact_sensitive_text(&e) }).to_string()
        }
    };
    rust_to_jstring(&mut env, &out)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_rustclashlabs_rustclash_vpn_NativeBridge_nativeDeleteNodePersisted<
    'local,
>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    state_dir_jstr: JString<'local>,
    node_name_jstr: JString<'local>,
) -> jstring {
    ensure_tracing_initialized();
    let res = (|| -> Result<serde_json::Value, String> {
        let dir = jstring_to_rust(&mut env, &state_dir_jstr)?;
        let name = jstring_to_rust(&mut env, &node_name_jstr)?;
        android_delete_node_core(Path::new(dir.trim()), &name)
    })();
    let out = match res {
        Ok(v) => v.to_string(),
        Err(e) => {
            serde_json::json!({ "ok": false, "error": redact_sensitive_text(&e) }).to_string()
        }
    };
    rust_to_jstring(&mut env, &out)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_rustclashlabs_rustclash_vpn_NativeBridge_nativeDeduplicateNodesPersisted<
    'local,
>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    state_dir_jstr: JString<'local>,
) -> jstring {
    ensure_tracing_initialized();
    let res = (|| -> Result<serde_json::Value, String> {
        let dir = jstring_to_rust(&mut env, &state_dir_jstr)?;
        android_deduplicate_nodes_core(Path::new(dir.trim()))
    })();
    let out = match res {
        Ok(v) => v.to_string(),
        Err(e) => {
            serde_json::json!({ "ok": false, "error": redact_sensitive_text(&e) }).to_string()
        }
    };
    rust_to_jstring(&mut env, &out)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_rustclashlabs_rustclash_vpn_NativeBridge_nativeSwitchMode<
    'local,
>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    mode_str: JString<'local>,
) -> jboolean {
    let Ok(m_raw) = jstring_to_rust(&mut env, &mode_str) else {
        return JNI_FALSE;
    };
    let mode = match m_raw.trim().to_ascii_lowercase().as_str() {
        "global" => RunMode::Global,
        "direct" => RunMode::Direct,
        "rule" => RunMode::Rule,
        _ => return JNI_FALSE,
    };
    if let Some((_, engine)) = live_handle_and_engine() {
        engine.set_mode(mode);
        JNI_TRUE
    } else {
        JNI_FALSE
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_rustclashlabs_rustclash_vpn_NativeBridge_nativeSelectProxy<
    'local,
>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    group_name: JString<'local>,
    proxy_name: JString<'local>,
) -> jboolean {
    let (Ok(grp), Ok(prx)) = (
        jstring_to_rust(&mut env, &group_name),
        jstring_to_rust(&mut env, &proxy_name),
    ) else {
        return JNI_FALSE;
    };
    let Some((_, engine)) = live_handle_and_engine() else {
        return JNI_FALSE;
    };
    if engine.select_group_and_persist(&grp, &prx).is_ok() {
        JNI_TRUE
    } else {
        JNI_FALSE
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_rustclashlabs_rustclash_vpn_NativeBridge_nativeReloadConfig<
    'local,
>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    yaml_config: JString<'local>,
) -> jstring {
    let res = (|| -> Result<(), String> {
        let yaml = jstring_to_rust(&mut env, &yaml_config)?;
        let (handle, engine, api_secret) = {
            let guard = ANDROID_RUNTIME.lock();
            let rt = guard
                .as_ref()
                .ok_or_else(|| "VPN engine is not running".to_string())?;
            (
                rt.runtime.handle().clone(),
                Arc::clone(&rt.engine),
                rt.api_secret.clone(),
            )
        };
        let prev = engine.config_snapshot();
        let mut parsed = ClashConfig::from_yaml_str_unchecked(&yaml)
            .map_err(|e| redact_sensitive_text(&e.to_string()))?;
        parsed.restore_redacted_from(&prev);
        parsed.tun = prev.tun;
        parsed.tun.enable = true;
        parsed.tun.auto_route = false;
        if parsed.secret.as_ref().is_none_or(|s| s.trim().is_empty()) {
            parsed.secret = Some(api_secret);
        }
        let merged = parsed
            .to_yaml_string()
            .map_err(|e| redact_sensitive_text(&e.to_string()))?;
        handle
            .block_on(engine.reload_yaml(&merged))
            .map_err(|e| redact_sensitive_text(&e.to_string()))
    })();
    let out = match res {
        Ok(()) => serde_json::json!({ "ok": true }).to_string(),
        Err(e) => {
            serde_json::json!({ "ok": false, "error": redact_sensitive_text(&e) }).to_string()
        }
    };
    rust_to_jstring(&mut env, &out)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_rustclashlabs_rustclash_vpn_NativeBridge_nativeImportUris<
    'local,
>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    uris_payload: JString<'local>,
) -> jstring {
    let res = (|| -> Result<usize, String> {
        let raw = jstring_to_rust(&mut env, &uris_payload)?;
        let (handle, engine) =
            live_handle_and_engine().ok_or_else(|| "VPN engine is not running".to_string())?;
        let nodes = handle
            .block_on(engine.import_uris_live(&raw))
            .map_err(|e| redact_sensitive_text(&e.to_string()))?;
        Ok(nodes.len())
    })();
    let out = match res {
        Ok(count) => serde_json::json!({ "ok": true, "imported": count }).to_string(),
        Err(e) => {
            serde_json::json!({ "ok": false, "error": redact_sensitive_text(&e) }).to_string()
        }
    };
    rust_to_jstring(&mut env, &out)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_rustclashlabs_rustclash_vpn_NativeBridge_nativeFlushDns(
    _env: JNIEnv<'_>,
    _class: JClass<'_>,
) -> jboolean {
    if let Some((_, engine)) = live_handle_and_engine() {
        engine.router().dns().flush_cache();
        JNI_TRUE
    } else {
        JNI_FALSE
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_rustclashlabs_rustclash_vpn_NativeBridge_nativeExplainRule<
    'local,
>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    target_jstr: JString<'local>,
    network_jstr: JString<'local>,
) -> jstring {
    let res = (|| -> Result<serde_json::Value, String> {
        let target_raw = jstring_to_rust(&mut env, &target_jstr)?;
        let net_raw = jstring_to_rust(&mut env, &network_jstr)?;
        let _ = net_raw;
        let (handle, engine) =
            live_handle_and_engine().ok_or_else(|| "VPN engine is not running".to_string())?;
        let target = parse_explain_target(&target_raw)?;
        let router = engine.router();
        let decision = handle.block_on(router.route_async(None, &target));
        Ok(serde_json::json!({
            "ok": true,
            "input": target_raw,
            "normalized_target": decision.target.to_string(),
            "restored_from_fake_ip": decision.restored_from_fake_ip.map(|ip| ip.to_string()),
            "mode": router.mode(),
            "rule_type": decision.rule_type,
            "rule_payload": decision.rule_payload,
            "chains": decision.chains,
            "outbound": decision.outbound.name(),
            "protocol": decision.outbound.protocol(),
            "exit_type": decision.outbound.exit_category(),
            "remote_endpoint": decision.outbound.remote_endpoint(&decision.target),
        }))
    })();
    let out = match res {
        Ok(v) => v.to_string(),
        Err(e) => {
            serde_json::json!({ "ok": false, "error": redact_sensitive_text(&e) }).to_string()
        }
    };
    rust_to_jstring(&mut env, &out)
}

/// Live + recent connection-level diagnostics (`connecting`, `active`, `closed`, `failed`)
/// exposing target domain, Fake-IP restoration, matched rule, outbound node, exit type, and redacted errors.
pub fn android_get_diagnostics_core(limit: usize) -> serde_json::Value {
    let capped = limit.clamp(1, 500);
    if let Some((_, engine)) = live_handle_and_engine() {
        let entries = engine.hub().diagnostics_snapshot(capped);
        serde_json::json!({
            "ok": true,
            "vpnRunning": true,
            "diagnostics": entries,
        })
    } else {
        serde_json::json!({
            "ok": true,
            "vpnRunning": false,
            "diagnostics": [],
        })
    }
}

pub fn android_clear_diagnostics_core() -> bool {
    if let Some((_, engine)) = live_handle_and_engine() {
        engine.hub().clear_diagnostics();
        true
    } else {
        false
    }
}

/// Offline + Live routing preset snapshot (`smart-cn`, `global`, `direct`, `custom`).
pub fn android_get_routing_snapshot_core(state_dir: &Path) -> Result<serde_json::Value, String> {
    if let Some((_, engine)) = live_handle_and_engine() {
        let mgr = engine
            .ensure_profile_manager()
            .map_err(|e| redact_sensitive_text(&e.to_string()))?;
        let snap = mgr
            .routing_snapshot()
            .map_err(|e| redact_sensitive_text(&e.to_string()))?;
        return Ok(serde_json::json!({
            "ok": true,
            "vpnRunning": true,
            "routing": snap,
        }));
    }
    let mgr = ProfileManager::open_or_init(state_dir)
        .map_err(|e| redact_sensitive_text(&e.to_string()))?;
    let snap = mgr
        .routing_snapshot()
        .map_err(|e| redact_sensitive_text(&e.to_string()))?;
    Ok(serde_json::json!({
        "ok": true,
        "vpnRunning": false,
        "routing": snap,
    }))
}

/// Switch between the 4 routing presets (`smart-cn`, `global`, `direct`, `custom`) offline or live,
/// automatically backing up & restoring user custom rules without destructive overwrite.
pub fn android_set_routing_preset_core(
    state_dir: &Path,
    preset_str: &str,
) -> Result<serde_json::Value, String> {
    let choice = RoutingPresetChoice::parse_str(preset_str)
        .map_err(|e| redact_sensitive_text(&e.to_string()))?;

    if let Some((handle, engine)) = live_handle_and_engine() {
        if engine.demo_info().enabled {
            match choice {
                RoutingPresetChoice::Global => engine.set_mode(RunMode::Global),
                RoutingPresetChoice::Direct => engine.set_mode(RunMode::Direct),
                RoutingPresetChoice::SmartCn | RoutingPresetChoice::Custom => {
                    engine.set_mode(RunMode::Rule)
                }
            }
            return android_node_manager_snapshot_core(state_dir);
        }
        let mgr = engine
            .ensure_profile_manager()
            .map_err(|e| redact_sensitive_text(&e.to_string()))?;
        let (snap, cfg) = mgr
            .apply_routing_preset(choice)
            .map_err(|e| redact_sensitive_text(&e.to_string()))?;
        handle
            .block_on(
                engine.activate_profile_config_with_selections(cfg, Some(&snap.selected_groups)),
            )
            .map_err(|e| redact_sensitive_text(&e.to_string()))?;
        return android_node_manager_snapshot_core(state_dir);
    }

    let mgr = ProfileManager::open_or_init(state_dir)
        .map_err(|e| redact_sensitive_text(&e.to_string()))?;
    let _ = mgr
        .apply_routing_preset(choice)
        .map_err(|e| redact_sensitive_text(&e.to_string()))?;
    android_node_manager_snapshot_core(state_dir)
}

fn parse_custom_rules_input(raw: &str) -> Vec<String> {
    let trimmed = raw.trim();
    if trimmed.starts_with('[')
        && let Ok(list) = serde_json::from_str::<Vec<String>>(trimmed)
    {
        return list;
    }
    raw.lines()
        .map(|l| l.trim().trim_start_matches("- ").trim().to_string())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect()
}

/// Save validated user custom rules (`RulePreset::Custom`) offline or live.
pub fn android_save_custom_rules_core(
    state_dir: &Path,
    rules_payload: &str,
) -> Result<serde_json::Value, String> {
    let rules = parse_custom_rules_input(rules_payload);
    if let Some((handle, engine)) = live_handle_and_engine() {
        let mgr = engine
            .ensure_profile_manager()
            .map_err(|e| redact_sensitive_text(&e.to_string()))?;
        let (snap, cfg) = mgr
            .save_custom_rules(rules)
            .map_err(|e| redact_sensitive_text(&e.to_string()))?;
        handle
            .block_on(
                engine.activate_profile_config_with_selections(cfg, Some(&snap.selected_groups)),
            )
            .map_err(|e| redact_sensitive_text(&e.to_string()))?;
        return android_node_manager_snapshot_core(state_dir);
    }

    let mgr = ProfileManager::open_or_init(state_dir)
        .map_err(|e| redact_sensitive_text(&e.to_string()))?;
    let _ = mgr
        .save_custom_rules(rules)
        .map_err(|e| redact_sensitive_text(&e.to_string()))?;
    android_node_manager_snapshot_core(state_dir)
}

/// Query GeoSite / GeoIP database status (persisted cache vs built-in baseline, entry counts, expiration).
pub fn android_geodata_status_core(state_dir: &Path) -> Result<serde_json::Value, String> {
    if let Some((_, engine)) = live_handle_and_engine() {
        let st = engine.geodata_status();
        return Ok(serde_json::json!({
            "ok": true,
            "geodata": st,
        }));
    }
    let gm = GeoDataManager::new(state_dir, Vec::new());
    Ok(serde_json::json!({
        "ok": true,
        "geodata": gm.status(),
    }))
}

/// Trigger an immediate GeoSite / GeoIP rule database update across mirrors (preserving existing data on failure).
pub fn android_update_geodata_core(state_dir: &Path) -> Result<serde_json::Value, String> {
    if let Some((handle, engine)) = live_handle_and_engine() {
        let st = handle
            .block_on(engine.update_geodata())
            .map_err(|e| redact_sensitive_text(&e.to_string()))?;
        return Ok(serde_json::json!({
            "ok": true,
            "geodata": st,
        }));
    }

    let gm = GeoDataManager::new(state_dir, Vec::new());
    let temp_rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("Tokio init failed: {e}"))?;
    let st = temp_rt
        .block_on(gm.update_default_mirrors())
        .map_err(|e| redact_sensitive_text(&e.to_string()))?;
    Ok(serde_json::json!({
        "ok": true,
        "geodata": st,
    }))
}

/// Offline + Live rule-matching explainer (`www.baidu.com`, `www.google.com`, `114.114.114.114`, etc.).
pub fn android_explain_rule_with_state_dir_core(
    state_dir: &Path,
    target_raw: &str,
) -> Result<serde_json::Value, String> {
    let target = parse_explain_target(target_raw)?;
    if let Some((handle, engine)) = live_handle_and_engine() {
        let router = engine.router();
        let decision = handle.block_on(router.route_async(None, &target));
        return Ok(serde_json::json!({
            "ok": true,
            "vpnRunning": true,
            "input": target_raw,
            "normalized_target": decision.target.to_string(),
            "restored_from_fake_ip": decision.restored_from_fake_ip.map(|ip| ip.to_string()),
            "mode": router.mode(),
            "rule_type": decision.rule_type,
            "rule_payload": decision.rule_payload,
            "chains": decision.chains,
            "outbound": decision.outbound.name(),
            "protocol": decision.outbound.protocol(),
            "exit_type": decision.outbound.exit_category(),
            "remote_endpoint": decision.outbound.remote_endpoint(&decision.target),
        }));
    }

    let mgr = ProfileManager::open_or_init(state_dir)
        .map_err(|e| redact_sensitive_text(&e.to_string()))?;
    let (cfg, _) = mgr
        .load_active_config()
        .map_err(|e| redact_sensitive_text(&e.to_string()))?;
    let saved_sel = mgr.active_selected_groups();
    let (router, _) = build_offline_router(&cfg, &saved_sel, Some(state_dir))?;
    let temp_rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("Tokio init failed: {e}"))?;
    let decision = temp_rt.block_on(router.route_async(None, &target));
    Ok(serde_json::json!({
        "ok": true,
        "vpnRunning": false,
        "input": target_raw,
        "normalized_target": decision.target.to_string(),
        "restored_from_fake_ip": decision.restored_from_fake_ip.map(|ip| ip.to_string()),
        "mode": router.mode(),
        "rule_type": decision.rule_type,
        "rule_payload": decision.rule_payload,
        "chains": decision.chains,
        "outbound": decision.outbound.name(),
        "protocol": decision.outbound.protocol(),
        "exit_type": decision.outbound.exit_category(),
        "remote_endpoint": decision.outbound.remote_endpoint(&decision.target),
    }))
}

async fn run_router_latency_probe(
    router: Arc<Router>,
    node_names: Vec<String>,
    target_name: Option<String>,
    probe_url: String,
    timeout: Duration,
) -> usize {
    if let Some(single) = target_name {
        let _ = router.test_delay(&single, &probe_url, timeout).await;
        1
    } else {
        let count = node_names.len();
        let sem = Arc::new(tokio::sync::Semaphore::new(16));
        let mut set = tokio::task::JoinSet::new();
        for name in node_names {
            let r = Arc::clone(&router);
            let u = probe_url.clone();
            let sem_clone = Arc::clone(&sem);
            set.spawn(async move {
                let _permit = sem_clone.acquire().await.ok();
                let _ = r.test_delay(&name, &u, timeout).await;
            });
        }
        while set.join_next().await.is_some() {}
        router.refresh_auto_groups(timeout).await;
        count
    }
}

/// Offline + Live latency probe for a single node/group or all saved concrete nodes.
pub fn android_test_latency_core(
    state_dir: &Path,
    target_name: Option<&str>,
    probe_url: Option<&str>,
    timeout_ms: u64,
) -> Result<serde_json::Value, String> {
    let clean_target = target_name
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned);
    let timeout = Duration::from_millis(timeout_ms.clamp(300, 12_000));

    if let Some((handle, engine)) = live_handle_and_engine() {
        let default_url = {
            let d = engine.demo_info();
            if d.enabled && !d.http_benchmark_origin.is_empty() {
                format!("{}/generate_204", d.http_benchmark_origin)
            } else {
                "http://www.gstatic.com/generate_204".to_string()
            }
        };
        let url = probe_url
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToOwned::to_owned)
            .unwrap_or(default_url);
        let cfg = engine.config_snapshot();
        let node_names: Vec<String> = cfg.proxies.iter().map(|p| p.name().to_string()).collect();
        let router = engine.router();
        let tested = handle.block_on(run_router_latency_probe(
            Arc::clone(&router),
            node_names,
            clean_target,
            url,
            timeout,
        ));
        sync_delays_from_router(&router);
        let delays = collect_delays_map_from_router(&router);
        return Ok(serde_json::json!({
            "ok": true,
            "tested": tested,
            "delays": delays,
        }));
    }

    let mgr = ProfileManager::open_or_init(state_dir)
        .map_err(|e| redact_sensitive_text(&e.to_string()))?;
    let (cfg, _) = mgr
        .load_active_config()
        .map_err(|e| redact_sensitive_text(&e.to_string()))?;
    let saved_sel = mgr.active_selected_groups();
    let (router_raw, _) = build_offline_router(&cfg, &saved_sel, Some(state_dir))?;
    let router = Arc::new(router_raw);
    let node_names: Vec<String> = cfg.proxies.iter().map(|p| p.name().to_string()).collect();
    let url = probe_url
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("http://www.gstatic.com/generate_204")
        .to_string();

    let temp_rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(|e| format!("Tokio init failed: {e}"))?;
    let tested = temp_rt.block_on(run_router_latency_probe(
        Arc::clone(&router),
        node_names,
        clean_target,
        url,
        timeout,
    ));
    sync_delays_from_router(&router);
    let delays = collect_delays_map_from_router(&router);
    Ok(serde_json::json!({
        "ok": true,
        "tested": tested,
        "delays": delays,
    }))
}

/// Offline + Live snapshot of all saved profiles in `ProfileManager`.
pub fn android_profiles_snapshot_core(state_dir: &Path) -> Result<serde_json::Value, String> {
    if let Some((_, engine)) = live_handle_and_engine() {
        let mgr = engine
            .ensure_profile_manager()
            .map_err(|e| redact_sensitive_text(&e.to_string()))?;
        let snap = mgr.snapshot();
        return Ok(serde_json::json!({
            "ok": true,
            "vpnRunning": true,
            "profilesSnapshot": snap,
        }));
    }
    let mgr = ProfileManager::open_or_init(state_dir)
        .map_err(|e| redact_sensitive_text(&e.to_string()))?;
    let snap = mgr.snapshot();
    Ok(serde_json::json!({
        "ok": true,
        "vpnRunning": false,
        "profilesSnapshot": snap,
    }))
}

/// Switch active profile offline or live (preserving Android virtual TUN fd bridge).
pub fn android_activate_profile_core(
    state_dir: &Path,
    profile_id: &str,
) -> Result<serde_json::Value, String> {
    if let Some((handle, engine)) = live_handle_and_engine() {
        let mgr = engine
            .ensure_profile_manager()
            .map_err(|e| redact_sensitive_text(&e.to_string()))?;
        let cfg = mgr
            .set_active_profile(profile_id)
            .map_err(|e| redact_sensitive_text(&e.to_string()))?;
        let sel = mgr.active_selected_groups();
        handle
            .block_on(engine.activate_profile_config_with_selections(cfg, Some(&sel)))
            .map_err(|e| redact_sensitive_text(&e.to_string()))?;
        return android_profiles_snapshot_core(state_dir);
    }
    {
        let _offline_guard = OFFLINE_PROFILE_LOCK.lock();
        let mgr = ProfileManager::open_or_init(state_dir)
            .map_err(|e| redact_sensitive_text(&e.to_string()))?;
        let _ = mgr
            .set_active_profile(profile_id)
            .map_err(|e| redact_sensitive_text(&e.to_string()))?;
    }
    android_profiles_snapshot_core(state_dir)
}

/// Delete a non-active profile offline or live.
pub fn android_delete_profile_core(
    state_dir: &Path,
    profile_id: &str,
) -> Result<serde_json::Value, String> {
    if let Some((_, engine)) = live_handle_and_engine() {
        let mgr = engine
            .ensure_profile_manager()
            .map_err(|e| redact_sensitive_text(&e.to_string()))?;
        mgr.delete_profile(profile_id)
            .map_err(|e| redact_sensitive_text(&e.to_string()))?;
        return android_profiles_snapshot_core(state_dir);
    }
    {
        let _offline_guard = OFFLINE_PROFILE_LOCK.lock();
        let mgr = ProfileManager::open_or_init(state_dir)
            .map_err(|e| redact_sensitive_text(&e.to_string()))?;
        mgr.delete_profile(profile_id)
            .map_err(|e| redact_sensitive_text(&e.to_string()))?;
    }
    android_profiles_snapshot_core(state_dir)
}

/// Refresh an HTTPS subscription profile offline or live (preserving existing YAML on failure).
pub fn android_refresh_profile_core(
    state_dir: &Path,
    profile_id: &str,
) -> Result<serde_json::Value, String> {
    if let Some((handle, engine)) = live_handle_and_engine() {
        let mgr = engine
            .ensure_profile_manager()
            .map_err(|e| redact_sensitive_text(&e.to_string()))?;
        let (meta, cfg, is_active) = handle
            .block_on(mgr.refresh_subscription(profile_id))
            .map_err(|e| redact_sensitive_text(&e.to_string()))?;
        if is_active && !engine.demo_info().enabled {
            handle
                .block_on(
                    engine
                        .activate_profile_config_with_selections(cfg, Some(&meta.selected_groups)),
                )
                .map_err(|e| redact_sensitive_text(&e.to_string()))?;
        }
        return android_profiles_snapshot_core(state_dir);
    }

    {
        let _offline_guard = OFFLINE_PROFILE_LOCK.lock();
        let mgr = ProfileManager::open_or_init(state_dir)
            .map_err(|e| redact_sensitive_text(&e.to_string()))?;
        let temp_rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| format!("Tokio init failed: {e}"))?;
        let _ = temp_rt
            .block_on(mgr.refresh_subscription(profile_id))
            .map_err(|e| redact_sensitive_text(&e.to_string()))?;
    }
    android_profiles_snapshot_core(state_dir)
}

/// Retrieve the active profile's redacted YAML + rules list offline or live.
pub fn android_get_active_yaml_core(state_dir: &Path) -> Result<serde_json::Value, String> {
    if let Some((_, engine)) = live_handle_and_engine() {
        let mgr = engine
            .ensure_profile_manager()
            .map_err(|e| redact_sensitive_text(&e.to_string()))?;
        let (cfg, _) = mgr
            .load_active_config()
            .map_err(|e| redact_sensitive_text(&e.to_string()))?;
        let redacted_yaml = cfg
            .redacted()
            .to_yaml_string()
            .map_err(|e| redact_sensitive_text(&e.to_string()))?;
        let routing = mgr.routing_snapshot().ok();
        return Ok(serde_json::json!({
            "ok": true,
            "activeProfileId": mgr.active_profile_id(),
            "yaml": redacted_yaml,
            "rules": cfg.rules,
            "routing": routing,
        }));
    }

    let mgr = ProfileManager::open_or_init(state_dir)
        .map_err(|e| redact_sensitive_text(&e.to_string()))?;
    let (cfg, _) = mgr
        .load_active_config()
        .map_err(|e| redact_sensitive_text(&e.to_string()))?;
    let redacted_yaml = cfg
        .redacted()
        .to_yaml_string()
        .map_err(|e| redact_sensitive_text(&e.to_string()))?;
    let routing = mgr.routing_snapshot().ok();
    Ok(serde_json::json!({
        "ok": true,
        "activeProfileId": mgr.active_profile_id(),
        "yaml": redacted_yaml,
        "rules": cfg.rules,
        "routing": routing,
    }))
}

/// Save edited YAML into the active profile offline or live, safely restoring `***REDACTED***`
/// node credentials from the existing active profile and preserving custom rules.
pub fn android_save_active_yaml_core(
    state_dir: &Path,
    yaml_text: &str,
) -> Result<serde_json::Value, String> {
    if let Some((handle, engine)) = live_handle_and_engine() {
        let mgr = engine
            .ensure_profile_manager()
            .map_err(|e| redact_sensitive_text(&e.to_string()))?;
        let (prev_disk_cfg, _) = mgr
            .load_active_config()
            .map_err(|e| redact_sensitive_text(&e.to_string()))?;
        let mut parsed = ClashConfig::from_yaml_str_unchecked(yaml_text)
            .map_err(|e| redact_sensitive_text(&e.to_string()))?;
        parsed.restore_redacted_from(&prev_disk_cfg);
        let raw_override = if yaml_text.contains(REDACTED_SECRET) {
            None
        } else {
            Some(yaml_text)
        };
        let sel = mgr
            .persist_active_yaml(&parsed, raw_override, None)
            .map_err(|e| redact_sensitive_text(&e.to_string()))?;
        if !engine.demo_info().enabled {
            handle
                .block_on(engine.activate_profile_config_with_selections(parsed, Some(&sel)))
                .map_err(|e| redact_sensitive_text(&e.to_string()))?;
        }
        return android_node_manager_snapshot_core(state_dir);
    }

    {
        let _offline_guard = OFFLINE_PROFILE_LOCK.lock();
        let mgr = ProfileManager::open_or_init(state_dir)
            .map_err(|e| redact_sensitive_text(&e.to_string()))?;
        let (prev_disk_cfg, _) = mgr
            .load_active_config()
            .map_err(|e| redact_sensitive_text(&e.to_string()))?;
        let mut parsed = ClashConfig::from_yaml_str_unchecked(yaml_text)
            .map_err(|e| redact_sensitive_text(&e.to_string()))?;
        parsed.restore_redacted_from(&prev_disk_cfg);
        let raw_override = if yaml_text.contains(REDACTED_SECRET) {
            None
        } else {
            Some(yaml_text)
        };
        let _ = mgr
            .persist_active_yaml(&parsed, raw_override, None)
            .map_err(|e| redact_sensitive_text(&e.to_string()))?;
    }
    android_node_manager_snapshot_core(state_dir)
}

/// Toggle the built-in self-contained Multi-Protocol Demo Sandbox while VPN is running.
pub fn android_set_demo_sandbox_core(enable: bool) -> Result<serde_json::Value, String> {
    let (handle, engine) =
        live_handle_and_engine().ok_or_else(|| "VPN engine is not running".to_string())?;
    handle
        .block_on(engine.set_demo_sandbox(enable))
        .map_err(|e| redact_sensitive_text(&e.to_string()))?;
    Ok(serde_json::json!({
        "ok": true,
        "demoActive": engine.demo_info().enabled,
    }))
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_rustclashlabs_rustclash_vpn_NativeBridge_nativeGetDiagnosticsJson(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    limit: jint,
) -> jstring {
    let lim = if limit <= 0 { 150usize } else { limit as usize };
    let payload = android_get_diagnostics_core(lim);
    rust_to_jstring(&mut env, &payload.to_string())
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_rustclashlabs_rustclash_vpn_NativeBridge_nativeClearDiagnostics(
    _env: JNIEnv<'_>,
    _class: JClass<'_>,
) -> jboolean {
    if android_clear_diagnostics_core() {
        JNI_TRUE
    } else {
        JNI_FALSE
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_rustclashlabs_rustclash_vpn_NativeBridge_nativeGetRoutingSnapshotJson<
    'local,
>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    state_dir_jstr: JString<'local>,
) -> jstring {
    ensure_tracing_initialized();
    let res = (|| -> Result<serde_json::Value, String> {
        let dir = jstring_to_rust(&mut env, &state_dir_jstr)?;
        android_get_routing_snapshot_core(Path::new(dir.trim()))
    })();
    let out = match res {
        Ok(v) => v.to_string(),
        Err(e) => {
            serde_json::json!({ "ok": false, "error": redact_sensitive_text(&e) }).to_string()
        }
    };
    rust_to_jstring(&mut env, &out)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_rustclashlabs_rustclash_vpn_NativeBridge_nativeSetRoutingPresetJson<
    'local,
>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    state_dir_jstr: JString<'local>,
    preset_jstr: JString<'local>,
) -> jstring {
    ensure_tracing_initialized();
    let res = (|| -> Result<serde_json::Value, String> {
        let dir = jstring_to_rust(&mut env, &state_dir_jstr)?;
        let preset = jstring_to_rust(&mut env, &preset_jstr)?;
        android_set_routing_preset_core(Path::new(dir.trim()), &preset)
    })();
    let out = match res {
        Ok(v) => v.to_string(),
        Err(e) => {
            serde_json::json!({ "ok": false, "error": redact_sensitive_text(&e) }).to_string()
        }
    };
    rust_to_jstring(&mut env, &out)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_rustclashlabs_rustclash_vpn_NativeBridge_nativeSaveCustomRulesJson<
    'local,
>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    state_dir_jstr: JString<'local>,
    rules_jstr: JString<'local>,
) -> jstring {
    ensure_tracing_initialized();
    let res = (|| -> Result<serde_json::Value, String> {
        let dir = jstring_to_rust(&mut env, &state_dir_jstr)?;
        let rules = jstring_to_rust(&mut env, &rules_jstr)?;
        android_save_custom_rules_core(Path::new(dir.trim()), &rules)
    })();
    let out = match res {
        Ok(v) => v.to_string(),
        Err(e) => {
            serde_json::json!({ "ok": false, "error": redact_sensitive_text(&e) }).to_string()
        }
    };
    rust_to_jstring(&mut env, &out)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_rustclashlabs_rustclash_vpn_NativeBridge_nativeGetGeoDataStatusJson<
    'local,
>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    state_dir_jstr: JString<'local>,
) -> jstring {
    ensure_tracing_initialized();
    let res = (|| -> Result<serde_json::Value, String> {
        let dir = jstring_to_rust(&mut env, &state_dir_jstr)?;
        android_geodata_status_core(Path::new(dir.trim()))
    })();
    let out = match res {
        Ok(v) => v.to_string(),
        Err(e) => {
            serde_json::json!({ "ok": false, "error": redact_sensitive_text(&e) }).to_string()
        }
    };
    rust_to_jstring(&mut env, &out)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_rustclashlabs_rustclash_vpn_NativeBridge_nativeUpdateGeoDataJson<
    'local,
>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    state_dir_jstr: JString<'local>,
) -> jstring {
    ensure_tracing_initialized();
    let res = (|| -> Result<serde_json::Value, String> {
        let dir = jstring_to_rust(&mut env, &state_dir_jstr)?;
        android_update_geodata_core(Path::new(dir.trim()))
    })();
    let out = match res {
        Ok(v) => v.to_string(),
        Err(e) => {
            serde_json::json!({ "ok": false, "error": redact_sensitive_text(&e) }).to_string()
        }
    };
    rust_to_jstring(&mut env, &out)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_rustclashlabs_rustclash_vpn_NativeBridge_nativeExplainRuleWithStateDirJson<
    'local,
>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    state_dir_jstr: JString<'local>,
    target_jstr: JString<'local>,
) -> jstring {
    ensure_tracing_initialized();
    let res = (|| -> Result<serde_json::Value, String> {
        let dir = jstring_to_rust(&mut env, &state_dir_jstr)?;
        let target = jstring_to_rust(&mut env, &target_jstr)?;
        android_explain_rule_with_state_dir_core(Path::new(dir.trim()), &target)
    })();
    let out = match res {
        Ok(v) => v.to_string(),
        Err(e) => {
            serde_json::json!({ "ok": false, "error": redact_sensitive_text(&e) }).to_string()
        }
    };
    rust_to_jstring(&mut env, &out)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_rustclashlabs_rustclash_vpn_NativeBridge_nativeTestLatencyJson<
    'local,
>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    state_dir_jstr: JString<'local>,
    target_name_jstr: JString<'local>,
    probe_url_jstr: JString<'local>,
    timeout_ms: jlong,
) -> jstring {
    ensure_tracing_initialized();
    let res = (|| -> Result<serde_json::Value, String> {
        let dir = jstring_to_rust(&mut env, &state_dir_jstr)?;
        let target_name = jstring_to_rust(&mut env, &target_name_jstr)?;
        let probe_url = jstring_to_rust(&mut env, &probe_url_jstr)?;
        let t_ms = if timeout_ms <= 0 {
            4000u64
        } else {
            timeout_ms as u64
        };
        android_test_latency_core(
            Path::new(dir.trim()),
            Some(target_name.as_str()),
            Some(probe_url.as_str()),
            t_ms,
        )
    })();
    let out = match res {
        Ok(v) => v.to_string(),
        Err(e) => {
            serde_json::json!({ "ok": false, "error": redact_sensitive_text(&e) }).to_string()
        }
    };
    rust_to_jstring(&mut env, &out)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_rustclashlabs_rustclash_vpn_NativeBridge_nativeGetProfilesSnapshotJson<
    'local,
>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    state_dir_jstr: JString<'local>,
) -> jstring {
    ensure_tracing_initialized();
    let res = (|| -> Result<serde_json::Value, String> {
        let dir = jstring_to_rust(&mut env, &state_dir_jstr)?;
        android_profiles_snapshot_core(Path::new(dir.trim()))
    })();
    let out = match res {
        Ok(v) => v.to_string(),
        Err(e) => {
            serde_json::json!({ "ok": false, "error": redact_sensitive_text(&e) }).to_string()
        }
    };
    rust_to_jstring(&mut env, &out)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_rustclashlabs_rustclash_vpn_NativeBridge_nativeActivateProfileJson<
    'local,
>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    state_dir_jstr: JString<'local>,
    profile_id_jstr: JString<'local>,
) -> jstring {
    ensure_tracing_initialized();
    let res = (|| -> Result<serde_json::Value, String> {
        let dir = jstring_to_rust(&mut env, &state_dir_jstr)?;
        let id = jstring_to_rust(&mut env, &profile_id_jstr)?;
        android_activate_profile_core(Path::new(dir.trim()), id.trim())
    })();
    let out = match res {
        Ok(v) => v.to_string(),
        Err(e) => {
            serde_json::json!({ "ok": false, "error": redact_sensitive_text(&e) }).to_string()
        }
    };
    rust_to_jstring(&mut env, &out)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_rustclashlabs_rustclash_vpn_NativeBridge_nativeDeleteProfileJson<
    'local,
>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    state_dir_jstr: JString<'local>,
    profile_id_jstr: JString<'local>,
) -> jstring {
    ensure_tracing_initialized();
    let res = (|| -> Result<serde_json::Value, String> {
        let dir = jstring_to_rust(&mut env, &state_dir_jstr)?;
        let id = jstring_to_rust(&mut env, &profile_id_jstr)?;
        android_delete_profile_core(Path::new(dir.trim()), id.trim())
    })();
    let out = match res {
        Ok(v) => v.to_string(),
        Err(e) => {
            serde_json::json!({ "ok": false, "error": redact_sensitive_text(&e) }).to_string()
        }
    };
    rust_to_jstring(&mut env, &out)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_rustclashlabs_rustclash_vpn_NativeBridge_nativeRefreshProfileJson<
    'local,
>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    state_dir_jstr: JString<'local>,
    profile_id_jstr: JString<'local>,
) -> jstring {
    ensure_tracing_initialized();
    let res = (|| -> Result<serde_json::Value, String> {
        let dir = jstring_to_rust(&mut env, &state_dir_jstr)?;
        let id = jstring_to_rust(&mut env, &profile_id_jstr)?;
        android_refresh_profile_core(Path::new(dir.trim()), id.trim())
    })();
    let out = match res {
        Ok(v) => v.to_string(),
        Err(e) => {
            serde_json::json!({ "ok": false, "error": redact_sensitive_text(&e) }).to_string()
        }
    };
    rust_to_jstring(&mut env, &out)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_rustclashlabs_rustclash_vpn_NativeBridge_nativeGetActiveYamlJson<
    'local,
>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    state_dir_jstr: JString<'local>,
) -> jstring {
    ensure_tracing_initialized();
    let res = (|| -> Result<serde_json::Value, String> {
        let dir = jstring_to_rust(&mut env, &state_dir_jstr)?;
        android_get_active_yaml_core(Path::new(dir.trim()))
    })();
    let out = match res {
        Ok(v) => v.to_string(),
        Err(e) => {
            serde_json::json!({ "ok": false, "error": redact_sensitive_text(&e) }).to_string()
        }
    };
    rust_to_jstring(&mut env, &out)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_rustclashlabs_rustclash_vpn_NativeBridge_nativeSaveActiveYamlJson<
    'local,
>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    state_dir_jstr: JString<'local>,
    yaml_jstr: JString<'local>,
) -> jstring {
    ensure_tracing_initialized();
    let res = (|| -> Result<serde_json::Value, String> {
        let dir = jstring_to_rust(&mut env, &state_dir_jstr)?;
        let yaml = jstring_to_rust(&mut env, &yaml_jstr)?;
        android_save_active_yaml_core(Path::new(dir.trim()), &yaml)
    })();
    let out = match res {
        Ok(v) => v.to_string(),
        Err(e) => {
            serde_json::json!({ "ok": false, "error": redact_sensitive_text(&e) }).to_string()
        }
    };
    rust_to_jstring(&mut env, &out)
}

/// Toggle low-power / screen-off Doze battery saver mode on the live Android `ProxyEngine`.
pub fn android_set_low_power_mode_core(enabled: bool) -> bool {
    if let Some((_, engine)) = live_handle_and_engine() {
        engine.set_low_power_mode(enabled);
        true
    } else {
        false
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_rustclashlabs_rustclash_vpn_NativeBridge_nativeSetLowPowerMode(
    _env: JNIEnv<'_>,
    _class: JClass<'_>,
    enable: jboolean,
) -> jboolean {
    if android_set_low_power_mode_core(enable == JNI_TRUE) {
        JNI_TRUE
    } else {
        JNI_FALSE
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_rustclashlabs_rustclash_vpn_NativeBridge_nativeSetDemoSandboxJson(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    enable: jboolean,
) -> jstring {
    ensure_tracing_initialized();
    let out = match android_set_demo_sandbox_core(enable == JNI_TRUE) {
        Ok(v) => v.to_string(),
        Err(e) => {
            serde_json::json!({ "ok": false, "error": redact_sensitive_text(&e) }).to_string()
        }
    };
    rust_to_jstring(&mut env, &out)
}

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
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
    api::{parse_explain_target, read_process_rss_bytes, read_process_total_vmrss_bytes},
    config::{
        ClashConfig, ProxyGroupType, ProxyNodeConfig, REDACTED_SECRET, RunMode,
        uri::redact_sensitive_text,
    },
    dns::{FakeIpDnsEngine, PositiveDnsCacheSeed},
    engine::{NetworkChangeReport, PreconnectPolicy, ProxyEngine, build_outbounds_with_dns},
    platform::socket_protect::{clear_global_socket_protector, set_global_socket_protector},
    profile::{
        NodeMutationReport, ProfileManager, RoutingPresetChoice, default_selected_groups_for_config,
    },
    router::{EffectiveOutboundSummary, Router, geodata::GeoDataManager},
};

use crate::fd_bridge::CallbackSocketProtector;
#[cfg(unix)]
use crate::fd_bridge::UnixPacketFdBridge;

static INIT_LOG: Once = Once::new();
static OFFLINE_DELAY_CACHE: LazyLock<Mutex<HashMap<String, u64>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

struct CachedOfflineRouter {
    state_dir: Option<PathBuf>,
    config_fp: u64,
    dns_fp: u64,
    geodata_status: proxy_core::router::geodata::GeoDataStatus,
    router: Option<Arc<Router>>,
    runtime: Option<Arc<tokio::runtime::Runtime>>,
}

impl Drop for CachedOfflineRouter {
    fn drop(&mut self) {
        if let Some(r) = self.router.take() {
            r.set_low_power_mode(true);
            drop(r);
        }
        if let Some(rt_arc) = self.runtime.take()
            && let Ok(rt) = Arc::try_unwrap(rt_arc)
        {
            rt.shutdown_timeout(Duration::from_millis(150));
        }
    }
}

static OFFLINE_ROUTER_CACHE: LazyLock<Mutex<Option<CachedOfflineRouter>>> =
    LazyLock::new(|| Mutex::new(None));

fn clear_offline_router_cache() {
    let prev = OFFLINE_ROUTER_CACHE.lock().take();
    drop(prev);
}

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
    #[cfg(unix)]
    fd_bridge: Option<UnixPacketFdBridge>,
    protector: Arc<CallbackSocketProtector>,
    network_transitions: AtomicU64,
    last_network_handle: AtomicI64,
    has_network_baseline: AtomicBool,
    is_wifi: AtomicBool,
    has_ipv6: AtomicBool,
}

/// Fast, microsecond-only pointer swap lock for reading/installing the active `AndroidVpnRuntime`.
/// Never held across `rt.block_on(...)`, network fetches, `fd_bridge.stop()`, or `shutdown_timeout`.
static ANDROID_RUNTIME: Mutex<Option<AndroidVpnRuntime>> = Mutex::new(None);
/// Serializes `start_android_vpn_*` and `stop_android_vpn_*` lifecycle transitions outside `ANDROID_RUNTIME`.
static LIFECYCLE_LOCK: Mutex<()> = Mutex::new(());
/// Incremented by `stop_android_vpn_core()` before waiting on `LIFECYCLE_LOCK` so a concurrent stop
/// request cancels an in-flight `start_android_vpn_*` instead of installing a stale runtime.
static STOP_GENERATION: AtomicU64 = AtomicU64::new(0);
/// Persists Android debug diagnostic mode across VPN start/restart cycles within the process.
static ANDROID_DEBUG_LOGGING: AtomicBool = AtomicBool::new(false);
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

const DEFAULT_PROBE_URL: &str = "http://www.gstatic.com/generate_204";
const STALE_ACTIVE_DELAY_MAX_AGE_MS: u64 = 300_000;

fn seed_delays_into_router(router: &Router) {
    let cache = OFFLINE_DELAY_CACHE.lock();
    for (name, &delay) in cache.iter() {
        if delay > 0 {
            router.seed_delay_if_absent(name, delay);
        }
    }
}

fn maybe_spawn_active_leaf_delay_probe(
    handle: &tokio::runtime::Handle,
    engine: &Arc<ProxyEngine>,
    stale_after_ms: Option<u64>,
) {
    if engine.is_demo_sandbox() {
        return;
    }
    let router = engine.router();
    let leaf = router.effective_primary_outbound().effective_outbound;
    if leaf.is_empty() || leaf.eq_ignore_ascii_case("DIRECT") || leaf.eq_ignore_ascii_case("REJECT")
    {
        return;
    }
    let age = router.latest_delay_age_ms(&leaf);
    let should_probe = match stale_after_ms {
        None => age.is_none(),
        Some(max_age) => age.is_none_or(|a| a >= max_age),
    };
    if should_probe {
        handle.spawn(async move {
            if router
                .test_delay(&leaf, DEFAULT_PROBE_URL, Duration::from_millis(4000))
                .await
                .is_ok()
            {
                sync_delays_from_router(&router);
            }
        });
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
    rand::RngCore::fill_bytes(&mut rand::rng(), &mut raw);
    let mut out = String::with_capacity(48);
    for b in raw {
        use std::fmt::Write;
        let _ = write!(&mut out, "{b:02x}");
    }
    out
}

fn enforce_android_local_only_config(cfg: &mut ClashConfig) {
    cfg.allow_lan = false;
    cfg.bind_address = "127.0.0.1".to_string();
    cfg.lan_allowed_ips.clear();
    cfg.authentication.clear();
}

fn needs_local_only_sanitization(cfg: &ClashConfig) -> bool {
    cfg.allow_lan
        || cfg.bind_address != "127.0.0.1"
        || !cfg.lan_allowed_ips.is_empty()
        || !cfg.authentication.is_empty()
}

fn yaml_mentions_listener_exposure(yaml_text: &str) -> bool {
    let lower = yaml_text.to_ascii_lowercase();
    lower.contains("allow-lan")
        || lower.contains("allow_lan")
        || lower.contains("bind-address")
        || lower.contains("bind_address")
        || lower.contains("lan-allowed-ips")
        || lower.contains("lan_allowed_ips")
        || lower.contains("authentication")
}

fn clear_pending_jni_exception(env: &mut JNIEnv<'_>) -> bool {
    if env.exception_check().unwrap_or(false) {
        let _ = env.exception_clear();
        true
    } else {
        false
    }
}

fn jstring_to_rust(env: &mut JNIEnv<'_>, s: &JString<'_>) -> Result<String, String> {
    if s.is_null() {
        return Ok(String::new());
    }
    match env.get_string(s) {
        Ok(val) => Ok(val.into()),
        Err(e) => {
            clear_pending_jni_exception(env);
            Err(format!("JNI string read error: {e}"))
        }
    }
}

fn rust_to_jstring<'a>(env: &mut JNIEnv<'a>, s: &str) -> jstring {
    match env.new_string(s) {
        Ok(js) => js.into_raw(),
        Err(_) => {
            clear_pending_jni_exception(env);
            ptr::null_jstring()
        }
    }
}

fn jni_json_guarded<'local, F>(mut env: JNIEnv<'local>, f: F) -> jstring
where
    F: FnOnce(&mut JNIEnv<'local>) -> Result<serde_json::Value, String>,
{
    let out = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(&mut env))) {
        Ok(Ok(val)) => val.to_string(),
        Ok(Err(err)) => serde_json::json!({
            "ok": false,
            "error": redact_sensitive_text(&err),
        })
        .to_string(),
        Err(_) => {
            clear_pending_jni_exception(&mut env);
            serde_json::json!({
                "ok": false,
                "error": "internal Rust JNI panic",
            })
            .to_string()
        }
    };
    rust_to_jstring(&mut env, &out)
}

fn jni_bool_guarded<F>(f: F) -> jboolean
where
    F: FnOnce() -> bool,
{
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(true) => JNI_TRUE,
        Ok(false) | Err(_) => JNI_FALSE,
    }
}

fn jni_bool_env_guarded<'local, F>(mut env: JNIEnv<'local>, f: F) -> jboolean
where
    F: FnOnce(&mut JNIEnv<'local>) -> bool,
{
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(&mut env))) {
        Ok(true) => JNI_TRUE,
        Ok(false) => JNI_FALSE,
        Err(_) => {
            clear_pending_jni_exception(&mut env);
            JNI_FALSE
        }
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
        let cls = env.get_object_class(vpn_service).map_err(|e| {
            clear_pending_jni_exception(env);
            format!("get_object_class(vpnService) failed: {e}")
        })?;
        let protect_mid = env
            .get_method_id(cls, "protectSocket", "(I)Z")
            .map_err(|e| {
                clear_pending_jni_exception(env);
                format!("get_method_id(protectSocket) failed: {e}")
            })?;

        Ok(Arc::new(CallbackSocketProtector::new_unix(
            "android-vpn-protect",
            false,
            move |fd: i32| {
                let invoke_protect = |jenv: &mut JNIEnv<'_>| -> io::Result<bool> {
                    // SAFETY: `vpn_service_ref` is a live `GlobalRef` to the `VpnService` object
                    // from which `protect_mid` (`protectSocket(I)Z`) was looked up, and the single
                    // `jint` argument matches `(I)Z` with primitive `Boolean` return type.
                    let call_res = unsafe {
                        jenv.call_method_unchecked(
                            &vpn_service_ref,
                            protect_mid,
                            ReturnType::Primitive(Primitive::Boolean),
                            &[jvalue { i: fd }],
                        )
                    };
                    if jenv.exception_check().unwrap_or(false) {
                        let _ = jenv.exception_clear();
                        return Err(io::Error::other(format!(
                            "JNI call protectSocket({fd}) threw a Java exception (cleared)"
                        )));
                    }
                    let res = match call_res {
                        Ok(v) => v,
                        Err(jni::errors::Error::JavaException) => {
                            let _ = jenv.exception_clear();
                            return Err(io::Error::other(format!(
                                "JNI call protectSocket({fd}) threw JavaException (cleared)"
                            )));
                        }
                        Err(e) => {
                            let _ = jenv.exception_clear();
                            return Err(io::Error::other(format!(
                                "JNI call protectSocket({fd}) failed: {e}"
                            )));
                        }
                    };
                    res.z().map_err(|e| {
                        let _ = jenv.exception_clear();
                        io::Error::other(format!("JNI boolean decode failed: {e}"))
                    })
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

fn shutdown_runtime_outside_lock(#[allow(unused_mut)] mut prev: AndroidVpnRuntime) {
    sync_delays_from_router(&prev.engine.router());
    #[cfg(unix)]
    if let Some(mut fb) = prev.fd_bridge.take() {
        fb.stop();
    }
    prev.engine.shutdown();
    clear_global_socket_protector();
    proxy_core::platform::socket_protect::set_os_underlying_ipv6_available(None);
    prev.runtime.shutdown_timeout(Duration::from_millis(300));
}

fn hash_canonical_json(val: &serde_json::Value, hasher: &mut impl std::hash::Hasher) {
    use std::hash::Hash;
    match val {
        serde_json::Value::Null => 0u8.hash(hasher),
        serde_json::Value::Bool(b) => {
            1u8.hash(hasher);
            b.hash(hasher);
        }
        serde_json::Value::Number(n) => {
            2u8.hash(hasher);
            n.to_string().hash(hasher);
        }
        serde_json::Value::String(s) => {
            3u8.hash(hasher);
            s.hash(hasher);
        }
        serde_json::Value::Array(arr) => {
            4u8.hash(hasher);
            arr.len().hash(hasher);
            for item in arr {
                hash_canonical_json(item, hasher);
            }
        }
        serde_json::Value::Object(map) => {
            5u8.hash(hasher);
            map.len().hash(hasher);
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_unstable();
            for k in keys {
                k.hash(hasher);
                if let Some(v) = map.get(k) {
                    hash_canonical_json(v, hasher);
                }
            }
        }
    }
}

fn dns_config_fingerprint(cfg: &ClashConfig) -> u64 {
    use std::hash::Hasher;
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    let mut dns = cfg.dns_with_merged_hosts();
    dns.listen.clear();
    dns.ipv6 = false;
    if let Ok(val) = serde_json::to_value(&dns) {
        hash_canonical_json(&val, &mut hasher);
    }
    hasher.finish()
}

fn offline_config_fingerprint(cfg: &ClashConfig, state_dir: Option<&Path>) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    state_dir.hash(&mut hasher);
    if let Ok(val) = serde_json::to_value(cfg) {
        hash_canonical_json(&val, &mut hasher);
    }
    hasher.finish()
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
    router.set_unified_delay(cfg.unified_delay);
    router.set_low_power_mode(true);
    router.apply_saved_selections(&normalized);
    seed_delays_into_router(&router);
    Ok((router, geo_status))
}

fn get_or_build_offline_router(
    cfg: &ClashConfig,
    saved_selections: &HashMap<String, String>,
    state_dir: Option<&Path>,
) -> Result<
    (
        Arc<Router>,
        proxy_core::router::geodata::GeoDataStatus,
        Arc<tokio::runtime::Runtime>,
    ),
    String,
> {
    let normalized = default_selected_groups_for_config(cfg, saved_selections);
    let config_fp = offline_config_fingerprint(cfg, state_dir);
    let state_dir_buf = state_dir.map(Path::to_path_buf);

    {
        let guard = OFFLINE_ROUTER_CACHE.lock();
        if let Some(cached) = guard.as_ref()
            && cached.state_dir == state_dir_buf
            && cached.config_fp == config_fp
            && let (Some(router), Some(runtime)) = (&cached.router, &cached.runtime)
        {
            router.set_mode(cfg.mode);
            router.set_unified_delay(cfg.unified_delay);
            router.apply_saved_selections(&normalized);
            seed_delays_into_router(router);
            return Ok((
                Arc::clone(router),
                cached.geodata_status.clone(),
                Arc::clone(runtime),
            ));
        }
    }

    let runtime = Arc::new(
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .thread_name("rc-android-offline")
            .build()
            .map_err(|e| format!("Tokio init failed: {e}"))?,
    );
    let (router_raw, geo_status) = {
        let _enter = runtime.enter();
        build_offline_router(cfg, &normalized, state_dir)?
    };
    let router = Arc::new(router_raw);
    let dns_fp = dns_config_fingerprint(cfg);

    let prev = {
        let mut guard = OFFLINE_ROUTER_CACHE.lock();
        guard.replace(CachedOfflineRouter {
            state_dir: state_dir_buf,
            config_fp,
            dns_fp,
            geodata_status: geo_status.clone(),
            router: Some(Arc::clone(&router)),
            runtime: Some(Arc::clone(&runtime)),
        })
    };
    drop(prev);

    Ok((router, geo_status, runtime))
}

fn compute_offline_effective_summary(
    cfg: &ClashConfig,
    saved_selections: &HashMap<String, String>,
    state_dir: Option<&Path>,
) -> EffectiveOutboundSummary {
    if let Ok((router, _, _)) = get_or_build_offline_router(cfg, saved_selections, state_dir) {
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
    start_android_vpn_with_options(
        #[cfg(unix)]
        owned_tun_fd,
        state_dir,
        yaml_str,
        is_demo,
        true,
        protector,
    )
}

pub fn start_android_vpn_with_options(
    #[cfg(unix)] owned_tun_fd: Option<OwnedFd>,
    state_dir: Option<&Path>,
    yaml_str: &str,
    is_demo: bool,
    enable_ipv6: bool,
    protector: Arc<CallbackSocketProtector>,
) -> Result<serde_json::Value, String> {
    start_android_vpn_with_state_dir_and_jvm(
        #[cfg(unix)]
        owned_tun_fd,
        state_dir,
        yaml_str,
        is_demo,
        enable_ipv6,
        protector,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
fn start_android_vpn_with_state_dir_and_jvm(
    #[cfg(unix)] owned_tun_fd: Option<OwnedFd>,
    state_dir: Option<&Path>,
    yaml_str: &str,
    is_demo: bool,
    enable_ipv6: bool,
    protector: Arc<CallbackSocketProtector>,
    jvm: Option<Arc<JavaVM>>,
) -> Result<serde_json::Value, String> {
    let _lifecycle_guard = LIFECYCLE_LOCK.lock();
    let start_gen = STOP_GENERATION.load(Ordering::Acquire);

    // Swap out any previous runtime under `ANDROID_RUNTIME` in microseconds, then shut down outside it.
    let prev_rt = ANDROID_RUNTIME.lock().take();
    if let Some(prev) = prev_rt {
        shutdown_runtime_outside_lock(prev);
    }

    // Harvest any verified positive proxy/bootstrap DNS cache entries from offline latency testing,
    // and drop the offline router + runtime BEFORE installing the new global SocketProtector so
    // any unprotected offline sockets close cleanly.
    let cached_offline = OFFLINE_ROUTER_CACHE.lock().take();
    let offline_dns_seed: Option<(Option<PathBuf>, u64, PositiveDnsCacheSeed)> =
        cached_offline.as_ref().and_then(|c| {
            c.router.as_ref().map(|r| {
                (
                    c.state_dir.clone(),
                    c.dns_fp,
                    r.dns().export_positive_proxy_cache_seed(),
                )
            })
        });
    drop(cached_offline);
    clear_offline_router_cache();

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
            e.set_preconnect_policy(PreconnectPolicy::Mobile);
            let mut cfg = e.config_snapshot();
            enforce_android_local_only_config(&mut cfg);
            cfg.tun.enable = true;
            cfg.tun.auto_route = false;
            cfg.tun.ipv6 = enable_ipv6;
            cfg.dns.ipv6 = enable_ipv6;
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

            if needs_local_only_sanitization(&cfg) {
                enforce_android_local_only_config(&mut cfg);
                let _ = mgr.persist_active_yaml(&cfg, None, None);
            } else {
                enforce_android_local_only_config(&mut cfg);
            }
            cfg.mixed_port = 0;
            cfg.dns.listen = "127.0.0.1:0".to_string();
            cfg.tun.enable = true;
            cfg.tun.auto_route = false;
            cfg.tun.ipv6 = enable_ipv6;
            cfg.dns.ipv6 = enable_ipv6;
            if cfg.secret.as_ref().is_none_or(|s| s.trim().is_empty()) {
                cfg.secret = Some(ephemeral_secret.clone());
            }

            let target_dns_fp = dns_config_fingerprint(&cfg);
            let matched_seed = offline_dns_seed.and_then(|(s_dir, s_fp, seed)| {
                (s_dir.as_deref() == Some(dir) && s_fp == target_dns_fp).then_some(seed)
            });
            let saved_sel = mgr.active_selected_groups();
            let normalized_sel = default_selected_groups_for_config(&cfg, &saved_sel);

            let e = ProxyEngine::start_with_options(
                cfg,
                dir.to_path_buf(),
                PreconnectPolicy::Mobile,
                matched_seed,
                Some(normalized_sel),
            )
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
            enforce_android_local_only_config(&mut cfg);
            cfg.tun.enable = true;
            cfg.tun.auto_route = false;
            cfg.tun.ipv6 = enable_ipv6;
            cfg.dns.ipv6 = enable_ipv6;
            if cfg.secret.as_ref().is_none_or(|s| s.trim().is_empty()) {
                cfg.secret = Some(ephemeral_secret.clone());
            }
            let target_dns_fp = dns_config_fingerprint(&cfg);
            let e = ProxyEngine::start(cfg)
                .await
                .map_err(|e| redact_sensitive_text(&format!("ProxyEngine start failed: {e}")))?;
            e.set_preconnect_policy(PreconnectPolicy::Mobile);
            if let Some((s_dir, s_fp, seed)) = offline_dns_seed
                && s_dir.is_none()
                && s_fp == target_dns_fp
            {
                e.router().dns().seed_positive_proxy_cache(seed);
                e.trigger_preconnect();
            }
            e
        };

        Ok::<_, String>(eng)
    });

    let engine = match startup_res {
        Ok(eng) => eng,
        Err(err) => {
            clear_global_socket_protector();
            rt.shutdown_timeout(Duration::from_millis(250));
            // `owned_tun_fd` drops here via RAII -> `close(fd)` guaranteed!
            return Err(redact_sensitive_text(&err));
        }
    };

    if STOP_GENERATION.load(Ordering::Acquire) != start_gen {
        engine.shutdown();
        clear_global_socket_protector();
        rt.shutdown_timeout(Duration::from_millis(250));
        // `owned_tun_fd` drops here via RAII -> `close(fd)` guaranteed!
        return Err("VPN startup cancelled by concurrent stop request".to_string());
    }

    seed_delays_into_router(&engine.router());
    if ANDROID_DEBUG_LOGGING.load(Ordering::Acquire) {
        engine.hub().set_debug_mode(true);
    }

    // 2. Attach Android's established `VpnService` `OwnedFd` to `VirtualTunHandle`
    #[cfg(unix)]
    let fd_bridge = if let Some(tun_owned) = owned_tun_fd {
        let Some(vtun) = engine.take_virtual_tun_handle() else {
            drop(tun_owned);
            engine.shutdown();
            clear_global_socket_protector();
            rt.shutdown_timeout(Duration::from_millis(250));
            return Err("virtual smoltcp handle missing for Android VPN fd".to_string());
        };
        match UnixPacketFdBridge::attach_owned_fd(tun_owned, vtun) {
            Ok(b) => Some(b),
            Err(e) => {
                // `tun_owned` was already consumed and closed by `attach_owned_fd`!
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
    let probe_handle = rt.handle().clone();
    let probe_engine = Arc::clone(&engine);

    let candidate = AndroidVpnRuntime {
        runtime: rt,
        engine,
        #[cfg(unix)]
        fd_bridge,
        protector,
        network_transitions: AtomicU64::new(0),
        last_network_handle: AtomicI64::new(0),
        has_network_baseline: AtomicBool::new(false),
        is_wifi: AtomicBool::new(true),
        has_ipv6: AtomicBool::new(true),
    };

    let cancelled = {
        let mut guard = ANDROID_RUNTIME.lock();
        if STOP_GENERATION.load(Ordering::Acquire) != start_gen {
            Some(candidate)
        } else {
            *guard = Some(candidate);
            None
        }
    };
    if let Some(aborted) = cancelled {
        shutdown_runtime_outside_lock(aborted);
        return Err("VPN startup cancelled by concurrent stop request".to_string());
    }

    if !is_demo {
        maybe_spawn_active_leaf_delay_probe(
            &probe_handle,
            &probe_engine,
            Some(STALE_ACTIVE_DELAY_MAX_AGE_MS),
        );
    }

    Ok(serde_json::json!({
        "ok": true,
        "apiUrl": "",
        "apiPort": 0,
        "mixedPort": mixed_port,
        "dnsListen": dns_listen,
        "effectiveOutbound": eff.effective_outbound,
        "effectiveProtocol": eff.effective_protocol,
    }))
}

/// Pure-Rust core implementation of `nativeStopVpn` (used by user stop, `onRevoke()`, and `onDestroy()`).
pub fn stop_android_vpn_core() -> bool {
    STOP_GENERATION.fetch_add(1, Ordering::AcqRel);
    let _lifecycle_guard = LIFECYCLE_LOCK.lock();
    let prev = ANDROID_RUNTIME.lock().take();
    if let Some(rt) = prev {
        shutdown_runtime_outside_lock(rt);
        true
    } else {
        false
    }
}

/// Pure-Rust core implementation of `nativeNotifyNetworkChanged`.
pub fn notify_android_network_changed_core(
    network_handle: i64,
    is_wifi: bool,
) -> Option<NetworkChangeReport> {
    notify_android_network_changed_with_caps_core(network_handle, is_wifi, true)
}

/// Pure-Rust core implementation of `nativeNotifyNetworkChangedWithCaps`.
pub fn notify_android_network_changed_with_caps_core(
    network_handle: i64,
    is_wifi: bool,
    has_ipv6: bool,
) -> Option<NetworkChangeReport> {
    proxy_core::platform::socket_protect::set_os_underlying_ipv6_available(
        if network_handle == 0 {
            None
        } else {
            Some(has_ipv6)
        },
    );

    enum HandoffState {
        Offline,
        NoChange,
        Ipv6Gained(Arc<ProxyEngine>),
        Changed(Arc<ProxyEngine>, i64),
    }

    let state = {
        let guard = ANDROID_RUNTIME.lock();
        if let Some(rt) = guard.as_ref() {
            let had_baseline = rt.has_network_baseline.swap(true, Ordering::AcqRel);
            let prev_handle = rt
                .last_network_handle
                .swap(network_handle, Ordering::AcqRel);
            let prev_wifi = rt.is_wifi.swap(is_wifi, Ordering::AcqRel);
            let prev_ipv6 = rt.has_ipv6.swap(has_ipv6, Ordering::AcqRel);
            if !had_baseline && network_handle != 0 {
                HandoffState::NoChange
            } else if prev_handle != network_handle || prev_wifi != is_wifi {
                rt.network_transitions.fetch_add(1, Ordering::Relaxed);
                HandoffState::Changed(Arc::clone(&rt.engine), prev_handle)
            } else if prev_ipv6 && !has_ipv6 {
                HandoffState::Changed(Arc::clone(&rt.engine), prev_handle)
            } else if !prev_ipv6 && has_ipv6 {
                HandoffState::Ipv6Gained(Arc::clone(&rt.engine))
            } else {
                HandoffState::NoChange
            }
        } else {
            HandoffState::Offline
        }
    };

    match state {
        HandoffState::Offline => {
            clear_offline_router_cache();
            proxy_core::dns::upstream::clear_dns_upstream_pools();
            None
        }
        HandoffState::NoChange => Some(NetworkChangeReport {
            closed_active_connections: 0,
            reset_udp_nat_sessions: 0,
            evicted_tls_sessions: 0,
            dns_cache_flushed: false,
        }),
        HandoffState::Ipv6Gained(engine) => {
            engine.router().dns().flush_cache();
            proxy_core::dns::upstream::clear_dns_upstream_pools();
            engine.hub().push_log(
                "info",
                format!(
                    "Android link gained global IPv6 (handle {network_handle}, wifi={is_wifi}): flushed single-stack DNS cache"
                ),
            );
            Some(NetworkChangeReport {
                closed_active_connections: 0,
                reset_udp_nat_sessions: 0,
                evicted_tls_sessions: 0,
                dns_cache_flushed: true,
            })
        }
        HandoffState::Changed(engine, prev_handle) => {
            let report = engine.notify_network_change();
            engine.hub().push_log(
                "info",
                format!(
                    "Android network handoff (handle {prev_handle} -> {network_handle}, wifi={is_wifi}, ipv6={has_ipv6}): closed_tcp={}, reset_udp_nat={}, evicted_tls_pool={}",
                    report.closed_active_connections,
                    report.reset_udp_nat_sessions,
                    report.evicted_tls_sessions
                ),
            );
            Some(report)
        }
    }
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
            "routerEpoch": router.epoch(),
            "delaysRevision": router.delays().revision(),
            "effectiveOutbound": eff.effective_outbound,
            "effectiveProtocol": eff.effective_protocol,
            "effectiveDelayMs": active_delay,
            "apiUrl": "",
            "apiPort": 0,
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
            "hasIpv6": rt.has_ipv6.load(Ordering::Acquire),
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
        let same_state_dir = engine.state_dir() == state_dir;
        let (nodes, routing): (Vec<ProxyNodeConfig>, _) = if demo_active || same_state_dir {
            let redacted = cfg
                .proxies
                .iter()
                .map(ProxyNodeConfig::redacted_clone)
                .collect();
            let route_snap = if demo_active {
                mgr.routing_snapshot().ok()
            } else {
                Some(mgr.routing_snapshot_for_config(&cfg))
            };
            (redacted, route_snap)
        } else {
            let (disk_cfg, _) = mgr
                .load_active_config()
                .map_err(|e| redact_sensitive_text(&e.to_string()))?;
            let redacted = disk_cfg
                .proxies
                .iter()
                .map(ProxyNodeConfig::redacted_clone)
                .collect();
            let route_snap = Some(mgr.routing_snapshot_for_config(&disk_cfg));
            (redacted, route_snap)
        };
        let router = engine.router();
        sync_delays_from_router(&router);
        let eff = router.effective_primary_outbound();
        let groups = build_ordered_groups_json(&cfg, &router);
        let delays = collect_delays_map_from_router(&router);
        let rules = router.rules_snapshot();
        let geodata = engine.geodata_status();
        return Ok(serde_json::json!({
            "ok": true,
            "vpnRunning": true,
            "demoActive": demo_active,
            "routerEpoch": router.epoch(),
            "delaysRevision": router.delays().revision(),
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
    let routing = Some(mgr.routing_snapshot_for_config(&cfg));

    let (eff, groups, delays, rules, geodata) =
        match get_or_build_offline_router(&cfg, &normalized_sel, Some(state_dir)) {
            Ok((router, geo, _)) => {
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
        "routerEpoch": 0,
        "delaysRevision": 0,
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
        let prev_snap = mgr.snapshot();
        let prev_active_id = prev_snap.active_profile_id;
        let prev_ids: std::collections::HashSet<String> =
            prev_snap.profiles.into_iter().map(|p| p.id).collect();
        let mut report = handle
            .block_on(engine.import_unified_live(raw_input, None, deduplicate, auto_select))
            .map_err(|e| redact_sensitive_text(&e.to_string()))?;
        let after_snap = mgr.snapshot();
        let imported_profile_id = after_snap
            .profiles
            .iter()
            .find(|p| !prev_ids.contains(&p.id))
            .map(|p| p.id.clone())
            .unwrap_or_else(|| after_snap.active_profile_id.clone());
        if (needs_local_only_sanitization(&report.config)
            || needs_local_only_sanitization(&engine.config_snapshot()))
            && mgr.active_profile_id() == imported_profile_id
        {
            enforce_android_local_only_config(&mut report.config);
            let sel = mgr
                .persist_active_yaml(&report.config, None, None)
                .map_err(|e| redact_sensitive_text(&e.to_string()))?;
            if !engine.demo_info().enabled {
                handle
                    .block_on(
                        engine.activate_profile_config_with_selections(
                            report.config.clone(),
                            Some(&sel),
                        ),
                    )
                    .map_err(|e| redact_sensitive_text(&e.to_string()))?;
            }
        } else {
            enforce_android_local_only_config(&mut report.config);
        }
        if !auto_select
            && mgr.active_profile_id() != prev_active_id
            && prev_ids.contains(&prev_active_id)
            && let Ok(mut prev_cfg) = mgr.set_active_profile(&prev_active_id)
        {
            enforce_android_local_only_config(&mut prev_cfg);
            let prev_sel = mgr.active_selected_groups();
            if !engine.demo_info().enabled {
                let _ = handle.block_on(
                    engine.activate_profile_config_with_selections(prev_cfg, Some(&prev_sel)),
                );
            }
        }
        let eff = engine.router().effective_primary_outbound();
        let mut out = build_android_mutation_json(&mgr, &report, true, Some(eff));
        if let Some(obj) = out.as_object_mut() {
            obj.insert(
                "importedProfileId".to_string(),
                serde_json::Value::String(imported_profile_id),
            );
        }
        return Ok(out);
    }

    let _offline_guard = OFFLINE_PROFILE_LOCK.lock();
    let mgr = ProfileManager::open_or_init(state_dir)
        .map_err(|e| redact_sensitive_text(&e.to_string()))?;
    let prev_snap = mgr.snapshot();
    let prev_active_id = prev_snap.active_profile_id;
    let prev_ids: std::collections::HashSet<String> =
        prev_snap.profiles.into_iter().map(|p| p.id).collect();
    let temp_rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("Tokio init failed: {e}"))?;
    let mut report = temp_rt
        .block_on(mgr.import_unified_input(raw_input, None, deduplicate, auto_select))
        .map_err(|e| redact_sensitive_text(&e.to_string()))?;
    let after_snap = mgr.snapshot();
    let imported_profile_id = after_snap
        .profiles
        .iter()
        .find(|p| !prev_ids.contains(&p.id))
        .map(|p| p.id.clone())
        .unwrap_or_else(|| after_snap.active_profile_id.clone());
    if needs_local_only_sanitization(&report.config)
        && mgr.active_profile_id() == imported_profile_id
    {
        enforce_android_local_only_config(&mut report.config);
        let _ = mgr.persist_active_yaml(&report.config, None, None);
    } else {
        enforce_android_local_only_config(&mut report.config);
    }
    if !auto_select
        && mgr.active_profile_id() != prev_active_id
        && prev_ids.contains(&prev_active_id)
        && let Ok(mut prev_cfg) = mgr.set_active_profile(&prev_active_id)
    {
        if needs_local_only_sanitization(&prev_cfg) {
            enforce_android_local_only_config(&mut prev_cfg);
            let _ = mgr.persist_active_yaml(&prev_cfg, None, None);
        } else {
            enforce_android_local_only_config(&mut prev_cfg);
        }
    }
    let offline_eff = if mgr.active_profile_id() != imported_profile_id {
        mgr.load_active_config().ok().map(|(active_cfg, _)| {
            let sel = mgr.active_selected_groups();
            compute_offline_effective_summary(&active_cfg, &sel, Some(state_dir))
        })
    } else {
        None
    };
    let mut out = build_android_mutation_json(&mgr, &report, false, offline_eff);
    if let Some(obj) = out.as_object_mut() {
        obj.insert(
            "importedProfileId".to_string(),
            serde_json::Value::String(imported_profile_id),
        );
    }
    Ok(out)
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
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    vpn_service: JObject<'local>,
    tun_fd: jint,
    yaml_config: JString<'local>,
    demo_mode: jboolean,
) -> jstring {
    ensure_tracing_initialized();

    #[cfg(unix)]
    let owned_tun_fd: Result<Option<OwnedFd>, String> = if tun_fd >= 0 {
        // SAFETY: `tun_fd >= 0` was detached by Kotlin `ParcelFileDescriptor.detachFd()`,
        // transferring exclusive ownership of the open kernel TUN file descriptor to Rust.
        Ok(Some(unsafe { OwnedFd::from_raw_fd(tun_fd) }))
    } else if tun_fd == -1 {
        Ok(None)
    } else {
        Err(format!("invalid negative Android TUN fd: {tun_fd}"))
    };

    #[cfg(not(unix))]
    let _ = tun_fd;

    jni_json_guarded(env, move |env| {
        #[cfg(unix)]
        let tun_raii = owned_tun_fd?;

        let yaml_str = jstring_to_rust(env, &yaml_config)?;
        let jvm = Arc::new(
            env.get_java_vm()
                .map_err(|e| format!("get_java_vm failed: {e}"))?,
        );
        let vpn_global = env.new_global_ref(&vpn_service).map_err(|e| {
            clear_pending_jni_exception(env);
            format!("new_global_ref(vpnService) failed: {e}")
        })?;

        let protector =
            build_android_socket_protector(env, Arc::clone(&jvm), &vpn_service, vpn_global)?;
        start_android_vpn_with_state_dir_and_jvm(
            #[cfg(unix)]
            tun_raii,
            None,
            &yaml_str,
            demo_mode == JNI_TRUE,
            true,
            protector,
            Some(jvm),
        )
    })
}

#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub extern "system" fn Java_io_github_rustclashlabs_rustclash_vpn_NativeBridge_nativeStartVpnWithStateDir<
    'local,
>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    vpn_service: JObject<'local>,
    tun_fd: jint,
    state_dir_jstr: JString<'local>,
    yaml_config: JString<'local>,
    demo_mode: jboolean,
    enable_ipv6: jboolean,
) -> jstring {
    ensure_tracing_initialized();

    // CRITICAL RAII STEP: Immediately claim ownership of detached `tun_fd >= 0` BEFORE any `?` return!
    #[cfg(unix)]
    let owned_tun_fd: Result<Option<OwnedFd>, String> = if tun_fd >= 0 {
        // SAFETY: `tun_fd >= 0` was detached by Kotlin `ParcelFileDescriptor.detachFd()`,
        // transferring exclusive ownership of the open kernel TUN file descriptor to Rust.
        Ok(Some(unsafe { OwnedFd::from_raw_fd(tun_fd) }))
    } else if tun_fd == -1 {
        Ok(None)
    } else {
        Err(format!("invalid negative Android TUN fd: {tun_fd}"))
    };

    #[cfg(not(unix))]
    let _ = tun_fd;

    let enable_ipv6 = enable_ipv6 != JNI_FALSE;

    jni_json_guarded(env, move |env| {
        #[cfg(unix)]
        let tun_raii = owned_tun_fd?;

        let state_dir_raw = jstring_to_rust(env, &state_dir_jstr)?;
        let yaml_str = jstring_to_rust(env, &yaml_config)?;
        let jvm = Arc::new(
            env.get_java_vm()
                .map_err(|e| format!("get_java_vm failed: {e}"))?,
        );
        let vpn_global = env.new_global_ref(&vpn_service).map_err(|e| {
            clear_pending_jni_exception(env);
            format!("new_global_ref(vpnService) failed: {e}")
        })?;

        let protector =
            build_android_socket_protector(env, Arc::clone(&jvm), &vpn_service, vpn_global)?;
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
            enable_ipv6,
            protector,
            Some(jvm),
        )
    })
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_rustclashlabs_rustclash_vpn_NativeBridge_nativeStopVpn(
    _env: JNIEnv<'_>,
    _class: JClass<'_>,
) -> jboolean {
    jni_bool_guarded(stop_android_vpn_core)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_rustclashlabs_rustclash_vpn_NativeBridge_nativeNotifyNetworkChanged(
    _env: JNIEnv<'_>,
    _class: JClass<'_>,
    network_handle: jlong,
    is_wifi: jboolean,
) -> jboolean {
    jni_bool_guarded(|| {
        notify_android_network_changed_core(network_handle, is_wifi == JNI_TRUE).is_some()
    })
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_rustclashlabs_rustclash_vpn_NativeBridge_nativeNotifyNetworkChangedWithCaps(
    _env: JNIEnv<'_>,
    _class: JClass<'_>,
    network_handle: jlong,
    is_wifi: jboolean,
    has_ipv6: jboolean,
) -> jboolean {
    jni_bool_guarded(|| {
        notify_android_network_changed_with_caps_core(
            network_handle,
            is_wifi == JNI_TRUE,
            has_ipv6 == JNI_TRUE,
        )
        .is_some()
    })
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_rustclashlabs_rustclash_vpn_NativeBridge_nativeGetStatusJson(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
) -> jstring {
    let out = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(android_status_json_core))
    {
        Ok(payload) => payload.to_string(),
        Err(_) => "{\"running\":false}".to_string(),
    };
    rust_to_jstring(&mut env, &out)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_rustclashlabs_rustclash_vpn_NativeBridge_nativeGetNodeManagerSnapshot<
    'local,
>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    state_dir_jstr: JString<'local>,
) -> jstring {
    ensure_tracing_initialized();
    jni_json_guarded(env, |env| {
        let dir = jstring_to_rust(env, &state_dir_jstr)?;
        android_node_manager_snapshot_core(Path::new(dir.trim()))
    })
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_rustclashlabs_rustclash_vpn_NativeBridge_nativeImportUnifiedPayload<
    'local,
>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    state_dir_jstr: JString<'local>,
    payload_jstr: JString<'local>,
    deduplicate: jboolean,
    auto_select: jboolean,
) -> jstring {
    ensure_tracing_initialized();
    jni_json_guarded(env, |env| {
        let dir = jstring_to_rust(env, &state_dir_jstr)?;
        let payload = jstring_to_rust(env, &payload_jstr)?;
        android_import_unified_core(
            Path::new(dir.trim()),
            &payload,
            deduplicate == JNI_TRUE,
            auto_select == JNI_TRUE,
        )
    })
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_rustclashlabs_rustclash_vpn_NativeBridge_nativeSelectProxyPersisted<
    'local,
>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    state_dir_jstr: JString<'local>,
    group_name_jstr: JString<'local>,
    proxy_name_jstr: JString<'local>,
) -> jstring {
    ensure_tracing_initialized();
    jni_json_guarded(env, |env| {
        let dir = jstring_to_rust(env, &state_dir_jstr)?;
        let grp = jstring_to_rust(env, &group_name_jstr)?;
        let prx = jstring_to_rust(env, &proxy_name_jstr)?;
        android_select_proxy_persisted_core(Path::new(dir.trim()), &grp, &prx)
    })
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_rustclashlabs_rustclash_vpn_NativeBridge_nativeUpsertNodeJson<
    'local,
>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    state_dir_jstr: JString<'local>,
    original_name_jstr: JString<'local>,
    node_json_jstr: JString<'local>,
    auto_select: jboolean,
) -> jstring {
    ensure_tracing_initialized();
    jni_json_guarded(env, |env| {
        let dir = jstring_to_rust(env, &state_dir_jstr)?;
        let orig = jstring_to_rust(env, &original_name_jstr)?;
        let node_json = jstring_to_rust(env, &node_json_jstr)?;
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
    })
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_rustclashlabs_rustclash_vpn_NativeBridge_nativeDeleteNodePersisted<
    'local,
>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    state_dir_jstr: JString<'local>,
    node_name_jstr: JString<'local>,
) -> jstring {
    ensure_tracing_initialized();
    jni_json_guarded(env, |env| {
        let dir = jstring_to_rust(env, &state_dir_jstr)?;
        let name = jstring_to_rust(env, &node_name_jstr)?;
        android_delete_node_core(Path::new(dir.trim()), &name)
    })
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_rustclashlabs_rustclash_vpn_NativeBridge_nativeDeduplicateNodesPersisted<
    'local,
>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    state_dir_jstr: JString<'local>,
) -> jstring {
    ensure_tracing_initialized();
    jni_json_guarded(env, |env| {
        let dir = jstring_to_rust(env, &state_dir_jstr)?;
        android_deduplicate_nodes_core(Path::new(dir.trim()))
    })
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_rustclashlabs_rustclash_vpn_NativeBridge_nativeSwitchMode<
    'local,
>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    mode_str: JString<'local>,
) -> jboolean {
    jni_bool_env_guarded(env, |env| {
        let Ok(m_raw) = jstring_to_rust(env, &mode_str) else {
            return false;
        };
        let mode = match m_raw.trim().to_ascii_lowercase().as_str() {
            "global" => RunMode::Global,
            "direct" => RunMode::Direct,
            "rule" => RunMode::Rule,
            _ => return false,
        };
        if let Some((_, engine)) = live_handle_and_engine() {
            engine.set_mode(mode);
            true
        } else {
            false
        }
    })
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_rustclashlabs_rustclash_vpn_NativeBridge_nativeSelectProxy<
    'local,
>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    group_name: JString<'local>,
    proxy_name: JString<'local>,
) -> jboolean {
    jni_bool_env_guarded(env, |env| {
        let (Ok(grp), Ok(prx)) = (
            jstring_to_rust(env, &group_name),
            jstring_to_rust(env, &proxy_name),
        ) else {
            return false;
        };
        let Some((_, engine)) = live_handle_and_engine() else {
            return false;
        };
        engine.select_group_and_persist(&grp, &prx).is_ok()
    })
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_rustclashlabs_rustclash_vpn_NativeBridge_nativeReloadConfig<
    'local,
>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    yaml_config: JString<'local>,
) -> jstring {
    jni_json_guarded(env, |env| {
        let yaml = jstring_to_rust(env, &yaml_config)?;
        let (handle, engine) =
            live_handle_and_engine().ok_or_else(|| "VPN engine is not running".to_string())?;
        let prev = engine.config_snapshot();
        let mut parsed = ClashConfig::from_yaml_str_unchecked(&yaml)
            .map_err(|e| redact_sensitive_text(&e.to_string()))?;
        parsed.restore_redacted_from(&prev);
        enforce_android_local_only_config(&mut parsed);
        parsed.dns.ipv6 = prev.dns.ipv6;
        parsed.tun = prev.tun;
        parsed.tun.enable = true;
        parsed.tun.auto_route = false;
        if parsed.secret.as_ref().is_none_or(|s| s.trim().is_empty()) {
            parsed.secret = prev
                .secret
                .clone()
                .filter(|s| !s.trim().is_empty())
                .or_else(|| Some(generate_ephemeral_api_secret()));
        }
        let merged = parsed
            .to_yaml_string()
            .map_err(|e| redact_sensitive_text(&e.to_string()))?;
        handle
            .block_on(engine.reload_yaml(&merged))
            .map_err(|e| redact_sensitive_text(&e.to_string()))?;
        Ok(serde_json::json!({ "ok": true }))
    })
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_rustclashlabs_rustclash_vpn_NativeBridge_nativeImportUris<
    'local,
>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    uris_payload: JString<'local>,
) -> jstring {
    jni_json_guarded(env, |env| {
        let raw = jstring_to_rust(env, &uris_payload)?;
        let (handle, engine) =
            live_handle_and_engine().ok_or_else(|| "VPN engine is not running".to_string())?;
        let nodes = handle
            .block_on(engine.import_uris_live(&raw))
            .map_err(|e| redact_sensitive_text(&e.to_string()))?;
        Ok(serde_json::json!({ "ok": true, "imported": nodes.len() }))
    })
}

pub fn android_flush_dns_core() -> bool {
    let offline_dir = OFFLINE_ROUTER_CACHE
        .lock()
        .as_ref()
        .and_then(|c| c.state_dir.clone());
    clear_offline_router_cache();
    if let Some(dir) = offline_dir
        && !dir.as_os_str().is_empty()
    {
        let _ = std::fs::remove_file(dir.join("fake_ip_cache.json"));
    }
    proxy_core::dns::upstream::clear_dns_upstream_pools();
    if let Some((_, engine)) = live_handle_and_engine() {
        engine.flush_dns();
        true
    } else {
        false
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_rustclashlabs_rustclash_vpn_NativeBridge_nativeFlushDns(
    _env: JNIEnv<'_>,
    _class: JClass<'_>,
) -> jboolean {
    jni_bool_guarded(android_flush_dns_core)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_rustclashlabs_rustclash_vpn_NativeBridge_nativeExplainRule<
    'local,
>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    target_jstr: JString<'local>,
    network_jstr: JString<'local>,
) -> jstring {
    jni_json_guarded(env, |env| {
        let target_raw = jstring_to_rust(env, &target_jstr)?;
        let net_raw = jstring_to_rust(env, &network_jstr)?;
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
    })
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
        let (snap, mut cfg) = mgr
            .apply_routing_preset(choice)
            .map_err(|e| redact_sensitive_text(&e.to_string()))?;
        if needs_local_only_sanitization(&cfg) {
            enforce_android_local_only_config(&mut cfg);
            let _ = mgr.persist_active_yaml(&cfg, None, None);
        } else {
            enforce_android_local_only_config(&mut cfg);
        }
        handle
            .block_on(
                engine.activate_profile_config_with_selections(cfg, Some(&snap.selected_groups)),
            )
            .map_err(|e| redact_sensitive_text(&e.to_string()))?;
        return android_node_manager_snapshot_core(state_dir);
    }

    let mgr = ProfileManager::open_or_init(state_dir)
        .map_err(|e| redact_sensitive_text(&e.to_string()))?;
    let (_, mut cfg) = mgr
        .apply_routing_preset(choice)
        .map_err(|e| redact_sensitive_text(&e.to_string()))?;
    if needs_local_only_sanitization(&cfg) {
        enforce_android_local_only_config(&mut cfg);
        let _ = mgr.persist_active_yaml(&cfg, None, None);
    }
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
        let (snap, mut cfg) = mgr
            .save_custom_rules(rules)
            .map_err(|e| redact_sensitive_text(&e.to_string()))?;
        if needs_local_only_sanitization(&cfg) {
            enforce_android_local_only_config(&mut cfg);
            let _ = mgr.persist_active_yaml(&cfg, None, None);
        } else {
            enforce_android_local_only_config(&mut cfg);
        }
        handle
            .block_on(
                engine.activate_profile_config_with_selections(cfg, Some(&snap.selected_groups)),
            )
            .map_err(|e| redact_sensitive_text(&e.to_string()))?;
        return android_node_manager_snapshot_core(state_dir);
    }

    let mgr = ProfileManager::open_or_init(state_dir)
        .map_err(|e| redact_sensitive_text(&e.to_string()))?;
    let (_, mut cfg) = mgr
        .save_custom_rules(rules)
        .map_err(|e| redact_sensitive_text(&e.to_string()))?;
    if needs_local_only_sanitization(&cfg) {
        enforce_android_local_only_config(&mut cfg);
        let _ = mgr.persist_active_yaml(&cfg, None, None);
    }
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
    clear_offline_router_cache();
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
    let (router, _, runtime) = get_or_build_offline_router(&cfg, &saved_sel, Some(state_dir))?;
    let decision = runtime.block_on(router.route_async(None, &target));
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
    let (router, _, runtime) = get_or_build_offline_router(&cfg, &saved_sel, Some(state_dir))?;
    let node_names: Vec<String> = cfg.proxies.iter().map(|p| p.name().to_string()).collect();
    let url = probe_url
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("http://www.gstatic.com/generate_204")
        .to_string();

    let tested = runtime.block_on(run_router_latency_probe(
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
        let mut cfg = mgr
            .set_active_profile(profile_id)
            .map_err(|e| redact_sensitive_text(&e.to_string()))?;
        if needs_local_only_sanitization(&cfg) {
            enforce_android_local_only_config(&mut cfg);
            let _ = mgr.persist_active_yaml(&cfg, None, None);
        } else {
            enforce_android_local_only_config(&mut cfg);
        }
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
        let mut cfg = mgr
            .set_active_profile(profile_id)
            .map_err(|e| redact_sensitive_text(&e.to_string()))?;
        if needs_local_only_sanitization(&cfg) {
            enforce_android_local_only_config(&mut cfg);
            let _ = mgr.persist_active_yaml(&cfg, None, None);
        }
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
        let prev_cfg = mgr.load_profile_config_by_id(profile_id);
        let (meta, mut cfg, is_active) = handle
            .block_on(mgr.refresh_subscription(profile_id))
            .map_err(|e| redact_sensitive_text(&e.to_string()))?;
        if needs_local_only_sanitization(&cfg) {
            enforce_android_local_only_config(&mut cfg);
            if is_active {
                let _ = mgr.persist_active_yaml(&cfg, None, None);
            }
        } else {
            enforce_android_local_only_config(&mut cfg);
        }
        let diff_opt = prev_cfg
            .as_ref()
            .map(|prev| proxy_core::audit::diff_configs(prev, &cfg));
        let audit = proxy_core::audit::audit_config(&cfg);
        if is_active && !engine.demo_info().enabled {
            handle
                .block_on(
                    engine
                        .activate_profile_config_with_selections(cfg, Some(&meta.selected_groups)),
                )
                .map_err(|e| redact_sensitive_text(&e.to_string()))?;
        }
        let mut base = android_profiles_snapshot_core(state_dir)?;
        if let Some(obj) = base.as_object_mut() {
            obj.insert("refreshedProfile".to_string(), serde_json::json!(meta));
            obj.insert("diff".to_string(), serde_json::json!(diff_opt));
            obj.insert("auditScore".to_string(), serde_json::json!(audit.score));
            obj.insert("auditGrade".to_string(), serde_json::json!(audit.grade));
        }
        return Ok(base);
    }

    let (meta, diff_opt, score, grade) = {
        let _offline_guard = OFFLINE_PROFILE_LOCK.lock();
        let mgr = ProfileManager::open_or_init(state_dir)
            .map_err(|e| redact_sensitive_text(&e.to_string()))?;
        let prev_cfg = mgr.load_profile_config_by_id(profile_id);
        let temp_rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| format!("Tokio init failed: {e}"))?;
        let (meta, mut cfg, is_active) = temp_rt
            .block_on(mgr.refresh_subscription(profile_id))
            .map_err(|e| redact_sensitive_text(&e.to_string()))?;
        if needs_local_only_sanitization(&cfg) {
            enforce_android_local_only_config(&mut cfg);
            if is_active {
                let _ = mgr.persist_active_yaml(&cfg, None, None);
            }
        } else {
            enforce_android_local_only_config(&mut cfg);
        }
        let diff_opt = prev_cfg
            .as_ref()
            .map(|prev| proxy_core::audit::diff_configs(prev, &cfg));
        let audit = proxy_core::audit::audit_config(&cfg);
        (meta, diff_opt, audit.score, audit.grade)
    };
    let mut base = android_profiles_snapshot_core(state_dir)?;
    if let Some(obj) = base.as_object_mut() {
        obj.insert("refreshedProfile".to_string(), serde_json::json!(meta));
        obj.insert("diff".to_string(), serde_json::json!(diff_opt));
        obj.insert("auditScore".to_string(), serde_json::json!(score));
        obj.insert("auditGrade".to_string(), serde_json::json!(grade));
    }
    Ok(base)
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
        enforce_android_local_only_config(&mut parsed);
        let raw_override =
            if yaml_text.contains(REDACTED_SECRET) || yaml_mentions_listener_exposure(yaml_text) {
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
        enforce_android_local_only_config(&mut parsed);
        let raw_override =
            if yaml_text.contains(REDACTED_SECRET) || yaml_mentions_listener_exposure(yaml_text) {
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
    env: JNIEnv<'_>,
    _class: JClass<'_>,
    limit: jint,
) -> jstring {
    jni_json_guarded(env, |_| {
        let lim = if limit <= 0 { 150usize } else { limit as usize };
        Ok(android_get_diagnostics_core(lim))
    })
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_rustclashlabs_rustclash_vpn_NativeBridge_nativeClearDiagnostics(
    _env: JNIEnv<'_>,
    _class: JClass<'_>,
) -> jboolean {
    jni_bool_guarded(android_clear_diagnostics_core)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_rustclashlabs_rustclash_vpn_NativeBridge_nativeGetRoutingSnapshotJson<
    'local,
>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    state_dir_jstr: JString<'local>,
) -> jstring {
    jni_json_guarded(env, |env| {
        ensure_tracing_initialized();
        let dir = jstring_to_rust(env, &state_dir_jstr)?;
        android_get_routing_snapshot_core(Path::new(dir.trim()))
    })
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_rustclashlabs_rustclash_vpn_NativeBridge_nativeSetRoutingPresetJson<
    'local,
>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    state_dir_jstr: JString<'local>,
    preset_jstr: JString<'local>,
) -> jstring {
    jni_json_guarded(env, |env| {
        ensure_tracing_initialized();
        let dir = jstring_to_rust(env, &state_dir_jstr)?;
        let preset = jstring_to_rust(env, &preset_jstr)?;
        android_set_routing_preset_core(Path::new(dir.trim()), &preset)
    })
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_rustclashlabs_rustclash_vpn_NativeBridge_nativeSaveCustomRulesJson<
    'local,
>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    state_dir_jstr: JString<'local>,
    rules_jstr: JString<'local>,
) -> jstring {
    jni_json_guarded(env, |env| {
        ensure_tracing_initialized();
        let dir = jstring_to_rust(env, &state_dir_jstr)?;
        let rules = jstring_to_rust(env, &rules_jstr)?;
        android_save_custom_rules_core(Path::new(dir.trim()), &rules)
    })
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_rustclashlabs_rustclash_vpn_NativeBridge_nativeGetGeoDataStatusJson<
    'local,
>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    state_dir_jstr: JString<'local>,
) -> jstring {
    jni_json_guarded(env, |env| {
        ensure_tracing_initialized();
        let dir = jstring_to_rust(env, &state_dir_jstr)?;
        android_geodata_status_core(Path::new(dir.trim()))
    })
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_rustclashlabs_rustclash_vpn_NativeBridge_nativeUpdateGeoDataJson<
    'local,
>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    state_dir_jstr: JString<'local>,
) -> jstring {
    jni_json_guarded(env, |env| {
        ensure_tracing_initialized();
        let dir = jstring_to_rust(env, &state_dir_jstr)?;
        android_update_geodata_core(Path::new(dir.trim()))
    })
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_rustclashlabs_rustclash_vpn_NativeBridge_nativeExplainRuleWithStateDirJson<
    'local,
>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    state_dir_jstr: JString<'local>,
    target_jstr: JString<'local>,
) -> jstring {
    jni_json_guarded(env, |env| {
        ensure_tracing_initialized();
        let dir = jstring_to_rust(env, &state_dir_jstr)?;
        let target = jstring_to_rust(env, &target_jstr)?;
        android_explain_rule_with_state_dir_core(Path::new(dir.trim()), &target)
    })
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_rustclashlabs_rustclash_vpn_NativeBridge_nativeTestLatencyJson<
    'local,
>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    state_dir_jstr: JString<'local>,
    target_name_jstr: JString<'local>,
    probe_url_jstr: JString<'local>,
    timeout_ms: jlong,
) -> jstring {
    jni_json_guarded(env, |env| {
        ensure_tracing_initialized();
        let dir = jstring_to_rust(env, &state_dir_jstr)?;
        let target_name = jstring_to_rust(env, &target_name_jstr)?;
        let probe_url = jstring_to_rust(env, &probe_url_jstr)?;
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
    })
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_rustclashlabs_rustclash_vpn_NativeBridge_nativeGetProfilesSnapshotJson<
    'local,
>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    state_dir_jstr: JString<'local>,
) -> jstring {
    jni_json_guarded(env, |env| {
        ensure_tracing_initialized();
        let dir = jstring_to_rust(env, &state_dir_jstr)?;
        android_profiles_snapshot_core(Path::new(dir.trim()))
    })
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_rustclashlabs_rustclash_vpn_NativeBridge_nativeActivateProfileJson<
    'local,
>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    state_dir_jstr: JString<'local>,
    profile_id_jstr: JString<'local>,
) -> jstring {
    jni_json_guarded(env, |env| {
        ensure_tracing_initialized();
        let dir = jstring_to_rust(env, &state_dir_jstr)?;
        let id = jstring_to_rust(env, &profile_id_jstr)?;
        android_activate_profile_core(Path::new(dir.trim()), id.trim())
    })
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_rustclashlabs_rustclash_vpn_NativeBridge_nativeDeleteProfileJson<
    'local,
>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    state_dir_jstr: JString<'local>,
    profile_id_jstr: JString<'local>,
) -> jstring {
    jni_json_guarded(env, |env| {
        ensure_tracing_initialized();
        let dir = jstring_to_rust(env, &state_dir_jstr)?;
        let id = jstring_to_rust(env, &profile_id_jstr)?;
        android_delete_profile_core(Path::new(dir.trim()), id.trim())
    })
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_rustclashlabs_rustclash_vpn_NativeBridge_nativeRefreshProfileJson<
    'local,
>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    state_dir_jstr: JString<'local>,
    profile_id_jstr: JString<'local>,
) -> jstring {
    jni_json_guarded(env, |env| {
        ensure_tracing_initialized();
        let dir = jstring_to_rust(env, &state_dir_jstr)?;
        let id = jstring_to_rust(env, &profile_id_jstr)?;
        android_refresh_profile_core(Path::new(dir.trim()), id.trim())
    })
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_rustclashlabs_rustclash_vpn_NativeBridge_nativeGetActiveYamlJson<
    'local,
>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    state_dir_jstr: JString<'local>,
) -> jstring {
    jni_json_guarded(env, |env| {
        ensure_tracing_initialized();
        let dir = jstring_to_rust(env, &state_dir_jstr)?;
        android_get_active_yaml_core(Path::new(dir.trim()))
    })
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_rustclashlabs_rustclash_vpn_NativeBridge_nativeSaveActiveYamlJson<
    'local,
>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    state_dir_jstr: JString<'local>,
    yaml_jstr: JString<'local>,
) -> jstring {
    jni_json_guarded(env, |env| {
        ensure_tracing_initialized();
        let dir = jstring_to_rust(env, &state_dir_jstr)?;
        let yaml = jstring_to_rust(env, &yaml_jstr)?;
        android_save_active_yaml_core(Path::new(dir.trim()), &yaml)
    })
}

/// Toggle low-power / screen-off Doze battery saver mode on the live Android `ProxyEngine`.
pub fn android_set_low_power_mode_core(enabled: bool) -> bool {
    if let Some((handle, engine)) = live_handle_and_engine() {
        engine.set_low_power_mode(enabled);
        if !enabled {
            maybe_spawn_active_leaf_delay_probe(
                &handle,
                &engine,
                Some(STALE_ACTIVE_DELAY_MAX_AGE_MS),
            );
        }
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
    jni_bool_guarded(|| android_set_low_power_mode_core(enable == JNI_TRUE))
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_rustclashlabs_rustclash_vpn_NativeBridge_nativeSetDemoSandboxJson(
    env: JNIEnv<'_>,
    _class: JClass<'_>,
    enable: jboolean,
) -> jstring {
    jni_json_guarded(env, |_| {
        ensure_tracing_initialized();
        android_set_demo_sandbox_core(enable == JNI_TRUE)
    })
}

/// Update profile display name and/or subscription auto-update interval (`None` = unchanged,
/// `Some(None)` / `Some(Some(0))` = disabled, `Some(Some(secs))` = interval >= 60s) offline or live.
pub fn android_update_profile_settings_core(
    state_dir: &Path,
    profile_id: &str,
    name: Option<String>,
    auto_update_interval_secs: Option<Option<u64>>,
) -> Result<serde_json::Value, String> {
    let patch = proxy_core::profile::ProfileSettingsPatch {
        name,
        auto_update_interval_secs,
    };
    if let Some((_, engine)) = live_handle_and_engine() {
        let mgr = engine
            .ensure_profile_manager()
            .map_err(|e| redact_sensitive_text(&e.to_string()))?;
        let meta = mgr
            .update_profile_settings(profile_id, patch)
            .map_err(|e| redact_sensitive_text(&e.to_string()))?;
        return Ok(serde_json::json!({
            "ok": true,
            "vpnRunning": true,
            "profile": meta,
            "profilesSnapshot": mgr.snapshot(),
        }));
    }

    let _offline_guard = OFFLINE_PROFILE_LOCK.lock();
    let mgr = ProfileManager::open_or_init(state_dir)
        .map_err(|e| redact_sensitive_text(&e.to_string()))?;
    let meta = mgr
        .update_profile_settings(profile_id, patch)
        .map_err(|e| redact_sensitive_text(&e.to_string()))?;
    Ok(serde_json::json!({
        "ok": true,
        "vpnRunning": false,
        "profile": meta,
        "profilesSnapshot": mgr.snapshot(),
    }))
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_rustclashlabs_rustclash_vpn_NativeBridge_nativeUpdateProfileSettingsJson<
    'local,
>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    state_dir_jstr: JString<'local>,
    profile_id_jstr: JString<'local>,
    name_jstr: JString<'local>,
    interval_secs: jlong,
) -> jstring {
    jni_json_guarded(env, |env| {
        ensure_tracing_initialized();
        let dir = jstring_to_rust(env, &state_dir_jstr)?;
        let id = jstring_to_rust(env, &profile_id_jstr)?;
        let name_raw = jstring_to_rust(env, &name_jstr)?;
        let name_opt = {
            let t = name_raw.trim();
            if t.is_empty() {
                None
            } else {
                Some(t.to_string())
            }
        };
        let interval_opt = if interval_secs < 0 {
            None
        } else if interval_secs == 0 {
            Some(None)
        } else {
            Some(Some(interval_secs as u64))
        };
        android_update_profile_settings_core(
            Path::new(dir.trim()),
            id.trim(),
            name_opt,
            interval_opt,
        )
    })
}

/// Enable or disable Android debug diagnostic mode offline or live.
pub fn android_set_debug_logging_core(enabled: bool) -> bool {
    let prev = ANDROID_DEBUG_LOGGING.swap(enabled, Ordering::AcqRel);
    if let Some((_, engine)) = live_handle_and_engine() {
        engine.hub().set_debug_mode(enabled);
        if prev != enabled {
            engine.hub().push_log(
                "info",
                if enabled {
                    "[DEBUG] Android diagnostic capture mode enabled"
                } else {
                    "[DEBUG] Android diagnostic capture mode disabled"
                },
            );
        }
    }
    true
}

pub fn android_is_debug_logging_core() -> bool {
    ANDROID_DEBUG_LOGGING.load(Ordering::Acquire)
}

fn percentile_u64(sorted: &[u64], pct: usize) -> Option<u64> {
    if sorted.is_empty() {
        return None;
    }
    let idx = ((sorted.len() - 1) * pct) / 100;
    sorted.get(idx).copied()
}

fn build_redacted_active_profile_summary(
    mgr: &ProfileManager,
) -> (Option<String>, Option<serde_json::Value>) {
    let routing_preset = mgr
        .routing_snapshot()
        .ok()
        .map(|r| r.active_choice.as_str().to_string());
    let snap = mgr.snapshot();
    let active_profile = snap
        .profiles
        .into_iter()
        .find(|p| p.id == snap.active_profile_id)
        .map(|meta| {
            let subscription_host = if meta.subscription_url_redacted.is_some() {
                serde_json::Value::String("<redacted>".to_string())
            } else {
                serde_json::Value::Null
            };
            serde_json::json!({
                "name": redact_sensitive_text(&meta.name),
                "kind": meta.kind,
                "proxyCount": meta.proxy_count,
                "manualProxyCount": meta.manual_proxy_count,
                "groupCount": meta.group_count,
                "ruleCount": meta.rule_count,
                "autoUpdateIntervalSecs": meta.auto_update_interval_secs,
                "lastUpdatedMs": meta.last_updated_ms,
                "subscriptionHost": subscription_host,
                "lastError": meta.last_error.as_deref().map(redact_sensitive_text),
            })
        });
    (routing_preset, active_profile)
}

struct WindowDiagnosticSections {
    carry_over_count: usize,
    window_connections: usize,
    window_tcp: usize,
    window_udp: usize,
    window_failed: usize,
    window_zero_rx: usize,
    window_fake_ip_restored: usize,
    outbound_stats_json: Vec<serde_json::Value>,
    top_domains_json: Vec<serde_json::Value>,
    carry_over_connections_json: Vec<serde_json::Value>,
    failed_connections_json: Vec<serde_json::Value>,
    slow_connections_json: Vec<serde_json::Value>,
    recent_connections_json: Vec<serde_json::Value>,
}

fn build_window_diagnostic_sections(
    conns: &[proxy_core::tracker::ConnectionSnapshot],
    since_epoch_ms: u64,
    until_epoch_ms: u64,
    delays_map: &HashMap<String, u64>,
) -> WindowDiagnosticSections {
    let mut carry_over_count = 0usize;
    let mut carry_over_conns = Vec::new();
    let mut window_conns = Vec::with_capacity(conns.len());
    for c in conns {
        if c.start_epoch_ms < since_epoch_ms {
            if c.status == "active" || c.end_epoch_ms.is_none_or(|end| end >= since_epoch_ms) {
                carry_over_count += 1;
                carry_over_conns.push(c);
            }
        } else if c.start_epoch_ms <= until_epoch_ms {
            window_conns.push(c);
        }
    }

    carry_over_conns.sort_by(|a, b| {
        let a_total = a.upload.saturating_add(a.download);
        let b_total = b.upload.saturating_add(b.download);
        b_total
            .cmp(&a_total)
            .then_with(|| a.start_epoch_ms.cmp(&b.start_epoch_ms))
            .then_with(|| a.id.cmp(&b.id))
    });
    let age_ref_ms = if until_epoch_ms == u64::MAX {
        proxy_core::tracker::TelemetryHub::now_ms()
    } else {
        until_epoch_ms
    };
    let carry_over_connections_json: Vec<serde_json::Value> = carry_over_conns
        .into_iter()
        .take(10)
        .map(|c| {
            let safe_host = redact_sensitive_text(&c.metadata.host);
            let safe_rule = if c.rule_payload.is_empty() {
                redact_sensitive_text(&c.rule)
            } else {
                format!(
                    "{},{}",
                    redact_sensitive_text(&c.rule),
                    redact_sensitive_text(&c.rule_payload)
                )
            };
            serde_json::json!({
                "host": safe_host,
                "port": c.metadata.destination_port,
                "network": c.metadata.network,
                "status": c.status,
                "rule": safe_rule,
                "effectiveOutbound": redact_sensitive_text(&c.effective_outbound),
                "uploadBytes": c.upload,
                "downloadBytes": c.download,
                "ageMs": age_ref_ms.saturating_sub(c.start_epoch_ms),
            })
        })
        .collect();

    let mut window_connections_total = 0usize;
    let mut window_tcp = 0usize;
    let mut window_udp = 0usize;
    let mut window_failed = 0usize;
    let mut window_zero_rx = 0usize;
    let mut window_fake_ip_restored = 0usize;

    #[derive(Default)]
    struct OutboundAgg {
        protocol: String,
        exit_type: String,
        connections: usize,
        failures: usize,
        zero_rx_count: usize,
        upload_bytes: u64,
        download_bytes: u64,
        handshakes: Vec<u64>,
    }

    #[derive(Default)]
    struct DomainAgg {
        connections: usize,
        failures: usize,
        upload_bytes: u64,
        download_bytes: u64,
        primary_rule: String,
        primary_outbound: String,
    }

    let mut by_outbound: HashMap<String, OutboundAgg> = HashMap::new();
    let mut by_domain: HashMap<String, DomainAgg> = HashMap::new();

    for c in &window_conns {
        let weight = c.coalesced_count.max(1) as usize;
        window_connections_total = window_connections_total.saturating_add(weight);
        if c.metadata.network.eq_ignore_ascii_case("udp") {
            window_udp = window_udp.saturating_add(weight);
        } else {
            window_tcp = window_tcp.saturating_add(weight);
        }
        let is_failed = c.status == "failed" || c.error.is_some();
        if is_failed {
            window_failed = window_failed.saturating_add(weight);
        }
        let is_zero_rx = c.status == "closed" && c.download == 0 && c.upload > 0;
        if is_zero_rx {
            window_zero_rx += 1;
        }
        if c.metadata.fake_ip.is_some() {
            window_fake_ip_restored = window_fake_ip_restored.saturating_add(weight);
        }

        let ob_entry = by_outbound.entry(c.effective_outbound.clone()).or_default();
        if ob_entry.protocol.is_empty() {
            ob_entry.protocol.clone_from(&c.effective_protocol);
            ob_entry.exit_type.clone_from(&c.exit_type);
        }
        ob_entry.connections = ob_entry.connections.saturating_add(weight);
        if is_failed {
            ob_entry.failures = ob_entry.failures.saturating_add(weight);
        }
        if is_zero_rx {
            ob_entry.zero_rx_count += 1;
        }
        ob_entry.upload_bytes = ob_entry.upload_bytes.saturating_add(c.upload);
        ob_entry.download_bytes = ob_entry.download_bytes.saturating_add(c.download);
        if c.metadata.network.eq_ignore_ascii_case("tcp")
            && let Some(ms) = c.connect_duration_ms
        {
            ob_entry.handshakes.push(ms);
        }

        let safe_host = redact_sensitive_text(&c.metadata.host);
        let dom_entry = by_domain.entry(safe_host).or_default();
        dom_entry.connections = dom_entry.connections.saturating_add(weight);
        if is_failed {
            dom_entry.failures = dom_entry.failures.saturating_add(weight);
        }
        dom_entry.upload_bytes = dom_entry.upload_bytes.saturating_add(c.upload);
        dom_entry.download_bytes = dom_entry.download_bytes.saturating_add(c.download);
        if dom_entry.primary_rule.is_empty() {
            dom_entry.primary_rule = if c.rule_payload.is_empty() {
                redact_sensitive_text(&c.rule)
            } else {
                format!(
                    "{},{}",
                    redact_sensitive_text(&c.rule),
                    redact_sensitive_text(&c.rule_payload)
                )
            };
            dom_entry.primary_outbound.clone_from(&c.effective_outbound);
        }
    }

    let mut outbound_stats: Vec<(usize, serde_json::Value)> = by_outbound
        .into_iter()
        .map(|(outbound_name, mut agg)| {
            agg.handshakes.sort_unstable();
            let p50 = percentile_u64(&agg.handshakes, 50);
            let p95 = percentile_u64(&agg.handshakes, 95);
            let max_hs = agg.handshakes.last().copied();
            let probe_delay = delays_map.get(&outbound_name).copied();
            let safe_name = redact_sensitive_text(&outbound_name);
            (
                agg.connections,
                serde_json::json!({
                    "outbound": safe_name,
                    "protocol": agg.protocol,
                    "exitType": agg.exit_type,
                    "latestProbeDelayMs": probe_delay,
                    "connections": agg.connections,
                    "failures": agg.failures,
                    "zeroRxCount": agg.zero_rx_count,
                    "handshakeSamples": agg.handshakes.len(),
                    "handshakeP50Ms": p50,
                    "handshakeP95Ms": p95,
                    "handshakeMaxMs": max_hs,
                    "uploadBytes": agg.upload_bytes,
                    "downloadBytes": agg.download_bytes,
                }),
            )
        })
        .collect();
    outbound_stats.sort_by_key(|(cnt, _)| std::cmp::Reverse(*cnt));
    let outbound_stats_json: Vec<serde_json::Value> =
        outbound_stats.into_iter().map(|(_, v)| v).collect();

    struct DomainRanked {
        host: String,
        connections: usize,
        total_bytes: u64,
        json: serde_json::Value,
    }
    let mut ranked_domains: Vec<DomainRanked> = by_domain
        .into_iter()
        .map(|(host, agg)| {
            let total_bytes = agg.upload_bytes.saturating_add(agg.download_bytes);
            let json = serde_json::json!({
                "host": host,
                "connections": agg.connections,
                "failures": agg.failures,
                "uploadBytes": agg.upload_bytes,
                "downloadBytes": agg.download_bytes,
                "primaryRule": agg.primary_rule,
                "primaryOutbound": redact_sensitive_text(&agg.primary_outbound),
            });
            DomainRanked {
                host,
                connections: agg.connections,
                total_bytes,
                json,
            }
        })
        .collect();
    ranked_domains.sort_by(|a, b| {
        b.connections
            .cmp(&a.connections)
            .then_with(|| b.total_bytes.cmp(&a.total_bytes))
            .then_with(|| a.host.cmp(&b.host))
    });
    if ranked_domains.len() > 20 {
        let mut remainder = ranked_domains.split_off(20);
        remainder.retain(|d| d.total_bytes > 0);
        remainder.sort_by(|a, b| {
            b.total_bytes
                .cmp(&a.total_bytes)
                .then_with(|| b.connections.cmp(&a.connections))
                .then_with(|| a.host.cmp(&b.host))
        });
        ranked_domains.extend(remainder.into_iter().take(10));
    }
    let top_domains_json: Vec<serde_json::Value> =
        ranked_domains.into_iter().map(|d| d.json).collect();

    let failed_in_window: Vec<_> = conns
        .iter()
        .filter(|c| {
            (c.error.is_some() || c.status == "failed") && {
                let fail_ts = c.end_epoch_ms.unwrap_or(c.start_epoch_ms);
                fail_ts >= since_epoch_ms && fail_ts <= until_epoch_ms
            }
        })
        .collect();
    let failed_in_window_total: usize = failed_in_window
        .iter()
        .map(|c| c.coalesced_count.max(1) as usize)
        .sum();
    window_failed = window_failed.max(failed_in_window_total);

    let failed_connections_json: Vec<serde_json::Value> = failed_in_window
        .into_iter()
        .take(80)
        .map(|c| {
            serde_json::json!({
                "host": redact_sensitive_text(&c.metadata.host),
                "destinationPort": c.metadata.destination_port,
                "network": c.metadata.network,
                "fakeIp": c.metadata.fake_ip,
                "rule": c.rule,
                "rulePayload": redact_sensitive_text(&c.rule_payload),
                "chains": c.chains.iter().map(|ch| redact_sensitive_text(ch)).collect::<Vec<_>>(),
                "effectiveOutbound": redact_sensitive_text(&c.effective_outbound),
                "effectiveProtocol": c.effective_protocol,
                "exitType": c.exit_type,
                "error": c.error.as_deref().map(redact_sensitive_text),
                "coalescedCount": c.coalesced_count.max(1),
                "startEpochMs": c.start_epoch_ms,
                "endEpochMs": c.end_epoch_ms,
            })
        })
        .collect();

    let mut slow_candidates: Vec<_> = window_conns
        .iter()
        .copied()
        .filter(|c| {
            c.metadata.network.eq_ignore_ascii_case("tcp") && c.connect_duration_ms.is_some()
        })
        .collect();
    slow_candidates.sort_by_key(|c| std::cmp::Reverse(c.connect_duration_ms.unwrap_or(0)));
    let slow_connections_json: Vec<serde_json::Value> = slow_candidates
        .into_iter()
        .take(40)
        .map(|c| {
            serde_json::json!({
                "host": redact_sensitive_text(&c.metadata.host),
                "destinationPort": c.metadata.destination_port,
                "network": c.metadata.network,
                "rule": c.rule,
                "rulePayload": redact_sensitive_text(&c.rule_payload),
                "effectiveOutbound": redact_sensitive_text(&c.effective_outbound),
                "effectiveProtocol": c.effective_protocol,
                "connectDurationMs": c.connect_duration_ms,
                "upload": c.upload,
                "download": c.download,
                "status": c.status,
                "startEpochMs": c.start_epoch_ms,
            })
        })
        .collect();

    let recent_connections_json: Vec<serde_json::Value> = window_conns
        .iter()
        .take(80)
        .map(|c| {
            serde_json::json!({
                "host": redact_sensitive_text(&c.metadata.host),
                "destinationPort": c.metadata.destination_port,
                "network": c.metadata.network,
                "fakeIp": c.metadata.fake_ip,
                "rule": c.rule,
                "rulePayload": redact_sensitive_text(&c.rule_payload),
                "chains": c.chains.iter().map(|ch| redact_sensitive_text(ch)).collect::<Vec<_>>(),
                "effectiveOutbound": redact_sensitive_text(&c.effective_outbound),
                "effectiveProtocol": c.effective_protocol,
                "exitType": c.exit_type,
                "connectDurationMs": c.connect_duration_ms,
                "upload": c.upload,
                "download": c.download,
                "status": c.status,
                "error": c.error.as_deref().map(redact_sensitive_text),
                "coalescedCount": c.coalesced_count.max(1),
                "startEpochMs": c.start_epoch_ms,
            })
        })
        .collect();

    WindowDiagnosticSections {
        carry_over_count,
        window_connections: window_connections_total,
        window_tcp,
        window_udp,
        window_failed,
        window_zero_rx,
        window_fake_ip_restored,
        outbound_stats_json,
        top_domains_json,
        carry_over_connections_json,
        failed_connections_json,
        slow_connections_json,
        recent_connections_json,
    }
}

/// Collect a credential-redacted mobile diagnostic slice (`[since_epoch_ms, now]`) preserving
/// visited domains, Fake-IP restorations, matched routing rules, and node names/protocols/latencies.
pub fn android_collect_debug_snapshot_core(
    state_dir: &Path,
    since_epoch_ms: u64,
) -> Result<serde_json::Value, String> {
    android_collect_debug_snapshot_window_core(state_dir, since_epoch_ms, u64::MAX)
}

/// Collect a credential-redacted mobile diagnostic slice (`[since_epoch_ms, until_epoch_ms]`)
/// filtering out pre-existing carry-over active connections from window statistics and isolating
/// TCP handshake percentiles from local `0ms` UDP socket binds.
pub fn android_collect_debug_snapshot_window_core(
    state_dir: &Path,
    since_epoch_ms: u64,
    until_epoch_ms: u64,
) -> Result<serde_json::Value, String> {
    let captured_at_ms = proxy_core::tracker::TelemetryHub::now_ms();
    let debug_mode = ANDROID_DEBUG_LOGGING.load(Ordering::Acquire);
    let until_json = if until_epoch_ms == u64::MAX {
        serde_json::Value::Null
    } else {
        serde_json::json!(until_epoch_ms)
    };

    let live_ctx = {
        let guard = ANDROID_RUNTIME.lock();
        guard.as_ref().map(|rt| {
            #[cfg(unix)]
            let tun_stats = rt
                .fd_bridge
                .as_ref()
                .map(|b| {
                    (
                        b.rx_packets(),
                        b.tx_packets(),
                        b.rx_bytes(),
                        b.tx_bytes(),
                        b.tx_write_drops(),
                    )
                })
                .unwrap_or((0, 0, 0, 0, 0));
            #[cfg(not(unix))]
            let tun_stats = (0u64, 0u64, 0u64, 0u64, 0u64);
            (
                Arc::clone(&rt.engine),
                tun_stats,
                rt.protector.tcp_count(),
                rt.protector.udp_count(),
                rt.protector.fail_count(),
                rt.network_transitions.load(Ordering::Relaxed),
                rt.is_wifi.load(Ordering::Acquire),
                rt.has_ipv6.load(Ordering::Acquire),
                rt.last_network_handle.load(Ordering::Acquire),
            )
        })
    };

    if let Some((
        engine,
        (rx_pkts, tx_pkts, rx_bytes, tx_bytes, tx_write_drops),
        prot_tcp,
        prot_udp,
        prot_fail,
        network_transitions,
        is_wifi,
        has_ipv6,
        last_network_handle,
    )) = live_ctx
    {
        let hub = engine.hub();
        let router = engine.router();
        sync_delays_from_router(&router);
        let delays_map = collect_delays_map_from_router(&router);
        let eff = router.effective_primary_outbound();
        let active_delay = router.delays().latest_delay(&eff.effective_outbound);

        let (routing_preset, active_profile) = if let Ok(mgr) = engine.ensure_profile_manager() {
            build_redacted_active_profile_summary(&mgr)
        } else if !state_dir.as_os_str().is_empty()
            && let Ok(mgr) = ProfileManager::open_or_init(state_dir)
        {
            build_redacted_active_profile_summary(&mgr)
        } else {
            (None, None)
        };

        let (up_rate, down_rate) = hub
            .traffic_history()
            .last()
            .map(|p| (p.up, p.down))
            .unwrap_or((0, 0));
        let (up_total, down_total) = hub.totals();
        let dns_snap = router.dns().telemetry_snapshot();
        let cache_hits = dns_snap.cache_hits;
        let resolver_cache_hits = dns_snap.resolver_cache_hits;
        let mut dns_json = serde_json::to_value(dns_snap).unwrap_or_default();
        if let Some(obj) = dns_json.as_object_mut() {
            let cache_key = "cacheHits".to_string();
            let resolver_key = "resolverCacheHits".to_string();
            obj.insert(cache_key, serde_json::json!(cache_hits));
            obj.insert(resolver_key, serde_json::json!(resolver_cache_hits));
        }
        let geodata = engine.geodata_status();

        let conns = hub.diagnostics_in_window(since_epoch_ms, until_epoch_ms, 1_500);
        let sections =
            build_window_diagnostic_sections(&conns, since_epoch_ms, until_epoch_ms, &delays_map);

        let mut rules_with_hits: Vec<_> = router
            .rules_snapshot()
            .into_iter()
            .filter(|r| r.hits > 0)
            .collect();
        rules_with_hits.sort_by_key(|r| std::cmp::Reverse(r.hits));
        let top_rules_json: Vec<serde_json::Value> = rules_with_hits
            .into_iter()
            .take(25)
            .map(|r| {
                serde_json::json!({
                    "type": r.rule_type,
                    "payload": redact_sensitive_text(&r.payload),
                    "proxy": redact_sensitive_text(&r.proxy),
                    "hits": r.hits,
                })
            })
            .collect();

        let engine_logs_json: Vec<serde_json::Value> = hub
            .logs_in_window(since_epoch_ms, until_epoch_ms, 400)
            .into_iter()
            .map(|e| {
                serde_json::json!({
                    "timestampMs": e.timestamp_ms,
                    "level": e.level,
                    "payload": redact_sensitive_text(&e.payload),
                })
            })
            .collect();

        return Ok(serde_json::json!({
            "ok": true,
            "vpnRunning": true,
            "debugMode": debug_mode,
            "demoActive": engine.demo_info().enabled,
            "capturedAtMs": captured_at_ms,
            "sinceEpochMs": since_epoch_ms,
            "untilEpochMs": until_json,
            "startedAtMs": hub.started_at_ms(),
            "uptimeSecs": hub.uptime_secs(),
            "telemetryParked": hub.is_telemetry_parked(),
            "rssBytes": read_process_rss_bytes(),
            "vmRssBytes": read_process_total_vmrss_bytes(),
            "mode": router.mode().as_str(),
            "routingPreset": routing_preset,
            "effectiveOutbound": redact_sensitive_text(&eff.effective_outbound),
            "effectiveProtocol": eff.effective_protocol,
            "effectiveDelayMs": active_delay,
            "networkTransitions": network_transitions,
            "isWifi": is_wifi,
            "hasIpv6": has_ipv6,
            "lastNetworkHandle": last_network_handle,
            "activeProfile": active_profile,
            "geodata": geodata,
            "traffic": {
                "upRate": up_rate,
                "downRate": down_rate,
                "upTotal": up_total,
                "downTotal": down_total,
                "activeConnections": hub.active_connection_count(),
                "carryOverActiveConnections": sections.carry_over_count,
                "totalConnections": hub.total_connections(),
                "establishedConnections": hub.established_connections_total(),
                "failedConnections": hub.failed_connections_total(),
                "zeroRxClosedConnections": hub.zero_rx_closed_total(),
            },
            "windowSummary": {
                "connections": sections.window_connections,
                "tcpConnections": sections.window_tcp,
                "udpConnections": sections.window_udp,
                "failedConnections": sections.window_failed,
                "zeroRxClosedConnections": sections.window_zero_rx,
                "fakeIpRestoredConnections": sections.window_fake_ip_restored,
            },
            "tun": {
                "rxPackets": rx_pkts,
                "txPackets": tx_pkts,
                "rxBytes": rx_bytes,
                "txBytes": tx_bytes,
                "txWriteDrops": tx_write_drops,
                "protectedTcpSockets": prot_tcp,
                "protectedUdpSockets": prot_udp,
                "protectFailures": prot_fail,
            },
            "dns": dns_json,
            "outboundStats": sections.outbound_stats_json,
            "topDomains": sections.top_domains_json,
            "carryOverConnections": sections.carry_over_connections_json,
            "topRules": top_rules_json,
            "failedConnections": sections.failed_connections_json,
            "slowConnections": sections.slow_connections_json,
            "recentConnections": sections.recent_connections_json,
            "engineLogs": engine_logs_json,
        }));
    }

    let (mode_str, routing_preset, active_profile, geodata) = if !state_dir.as_os_str().is_empty() {
        let gm = GeoDataManager::new(state_dir, Vec::new());
        if let Ok(mgr) = ProfileManager::open_or_init(state_dir) {
            let mode = mgr
                .load_active_config()
                .map(|(cfg, _)| cfg.mode.as_str().to_string())
                .unwrap_or_else(|_| "rule".to_string());
            let (rp, ap) = build_redacted_active_profile_summary(&mgr);
            (mode, rp, ap, Some(gm.status()))
        } else {
            ("rule".to_string(), None, None, Some(gm.status()))
        }
    } else {
        ("rule".to_string(), None, None, None)
    };

    Ok(serde_json::json!({
        "ok": true,
        "vpnRunning": false,
        "debugMode": debug_mode,
        "demoActive": false,
        "capturedAtMs": captured_at_ms,
        "sinceEpochMs": since_epoch_ms,
        "untilEpochMs": until_json,
        "rssBytes": read_process_rss_bytes(),
        "vmRssBytes": read_process_total_vmrss_bytes(),
        "mode": mode_str,
        "routingPreset": routing_preset,
        "activeProfile": active_profile,
        "geodata": geodata,
        "outboundStats": [],
        "topDomains": [],
        "carryOverConnections": [],
        "topRules": [],
        "failedConnections": [],
        "slowConnections": [],
        "recentConnections": [],
        "engineLogs": [],
    }))
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_rustclashlabs_rustclash_vpn_NativeBridge_nativeSetDebugLogging(
    _env: JNIEnv<'_>,
    _class: JClass<'_>,
    enable: jboolean,
) -> jboolean {
    jni_bool_guarded(|| android_set_debug_logging_core(enable == JNI_TRUE))
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_rustclashlabs_rustclash_vpn_NativeBridge_nativeCollectDebugSnapshotJson<
    'local,
>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    state_dir_jstr: JString<'local>,
    since_epoch_ms: jlong,
    until_epoch_ms: jlong,
) -> jstring {
    jni_json_guarded(env, |env| {
        ensure_tracing_initialized();
        let dir = jstring_to_rust(env, &state_dir_jstr)?;
        let since_u64 = if since_epoch_ms <= 0 {
            0u64
        } else {
            since_epoch_ms as u64
        };
        let until_u64 = if until_epoch_ms <= 0 {
            u64::MAX
        } else {
            until_epoch_ms as u64
        };
        android_collect_debug_snapshot_window_core(Path::new(dir.trim()), since_u64, until_u64)
    })
}

/// Offline + Live unified website diagnostic (`diagnose_site`) for Android Jetpack Compose.
pub fn android_diagnose_site_core(
    state_dir: &Path,
    target_raw: &str,
) -> Result<serde_json::Value, String> {
    if let Some((handle, engine)) = live_handle_and_engine() {
        let demo = engine.demo_info();
        let mut allowed_private = Vec::new();
        if demo.enabled {
            if let Some(authority) = demo
                .http_benchmark_origin
                .trim()
                .strip_prefix("http://")
                .or_else(|| demo.http_benchmark_origin.trim().strip_prefix("https://"))
                .and_then(|rest| rest.split('/').next())
            {
                if let Ok(sock_addr) = authority.parse::<std::net::SocketAddr>() {
                    allowed_private.push(sock_addr);
                } else if let Some(port_str) = authority.strip_prefix("localhost:")
                    && let Ok(port) = port_str.parse::<u16>()
                {
                    allowed_private.push(std::net::SocketAddr::from(([127, 0, 0, 1], port)));
                }
            }
            if let Some(dns_addr) = engine.dns_addr() {
                allowed_private.push(dns_addr);
            }
        }
        let fallback_demo_udp = if demo.enabled {
            engine.dns_addr().map(|a| a.to_string())
        } else {
            None
        };
        let router = engine.router();
        let cfg = engine.config_snapshot();
        let extra_ca = engine.extra_ca_der();
        let takeover = proxy_core::probe::SiteTakeoverContext {
            core_running: true,
            sysproxy_enabled: false,
            tun_enabled: engine.is_tun_active() || engine.is_virtual_tun_active(),
            platform_hint: "android".to_string(),
        };
        let report = handle
            .block_on(proxy_core::probe::diagnose_site(
                &router,
                &cfg,
                target_raw,
                takeover,
                proxy_core::probe::ProbeOptions {
                    extra_ca_der: &extra_ca,
                    check_udp: true,
                    udp_dns_target: fallback_demo_udp.as_deref(),
                    timeout: Duration::from_secs(5),
                    allow_private_targets: false,
                    allowed_private_addrs: &allowed_private,
                },
            ))
            .map_err(|e| redact_sensitive_text(&e.to_string()))?;
        sync_delays_from_router(&router);
        return Ok(serde_json::json!({
            "ok": true,
            "vpnRunning": true,
            "diagnosis": report,
        }));
    }

    let mgr = ProfileManager::open_or_init(state_dir)
        .map_err(|e| redact_sensitive_text(&e.to_string()))?;
    let (cfg, _) = mgr
        .load_active_config()
        .map_err(|e| redact_sensitive_text(&e.to_string()))?;
    let saved_sel = mgr.active_selected_groups();
    let (router, _, runtime) = get_or_build_offline_router(&cfg, &saved_sel, Some(state_dir))?;
    let takeover = proxy_core::probe::SiteTakeoverContext {
        core_running: false,
        sysproxy_enabled: false,
        tun_enabled: false,
        platform_hint: "android".to_string(),
    };
    let report = runtime
        .block_on(proxy_core::probe::diagnose_site(
            &router,
            &cfg,
            target_raw,
            takeover,
            proxy_core::probe::ProbeOptions {
                extra_ca_der: &[],
                check_udp: true,
                udp_dns_target: None,
                timeout: Duration::from_secs(5),
                allow_private_targets: false,
                allowed_private_addrs: &[],
            },
        ))
        .map_err(|e| redact_sensitive_text(&e.to_string()))?;
    sync_delays_from_router(&router);
    Ok(serde_json::json!({
        "ok": true,
        "vpnRunning": false,
        "diagnosis": report,
    }))
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_rustclashlabs_rustclash_vpn_NativeBridge_nativeDiagnoseSiteJson<
    'local,
>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    state_dir_jstr: JString<'local>,
    target_jstr: JString<'local>,
) -> jstring {
    jni_json_guarded(env, |env| {
        ensure_tracing_initialized();
        let dir = jstring_to_rust(env, &state_dir_jstr)?;
        let target = jstring_to_rust(env, &target_jstr)?;
        android_diagnose_site_core(Path::new(dir.trim()), &target)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use proxy_core::{
        profile::ProfileSettingsPatch,
        tracker::{ConnectionMetadata, ConnectionSnapshot},
    };

    #[allow(clippy::too_many_arguments)]
    fn sample_conn(
        id: &str,
        network: &str,
        host: &str,
        outbound: &str,
        start_epoch_ms: u64,
        end_epoch_ms: Option<u64>,
        connect_duration_ms: Option<u64>,
        upload: u64,
        download: u64,
        fake_ip: Option<&str>,
        status: &str,
        error: Option<&str>,
    ) -> ConnectionSnapshot {
        ConnectionSnapshot {
            id: id.to_string(),
            metadata: ConnectionMetadata {
                id: id.to_string(),
                network: network.to_string(),
                inbound_type: "TUN".to_string(),
                source: "198.18.0.1:54321".to_string(),
                destination_ip: None,
                destination_port: 443,
                host: host.to_string(),
                fake_ip: fake_ip.map(ToOwned::to_owned),
                process: None,
            },
            upload,
            download,
            start_epoch_ms,
            chains: vec![outbound.to_string(), "PROXY".to_string()],
            rule: "GEOSITE".to_string(),
            rule_payload: "geolocation-!cn".to_string(),
            effective_outbound: outbound.to_string(),
            effective_protocol: "AnyTLS".to_string(),
            exit_type: "PROXY".to_string(),
            remote_endpoint: "***REDACTED***:443".to_string(),
            status: status.to_string(),
            error: error.map(ToOwned::to_owned),
            end_epoch_ms,
            connect_duration_ms,
            coalesced_count: 1,
        }
    }

    #[test]
    fn window_diagnostic_sections_filters_carry_over_and_isolates_tcp_handshakes() {
        let conns = vec![
            sample_conn(
                "carry-active",
                "tcp",
                "keepalive.example.com",
                "Node-HK",
                1_000,
                None,
                Some(950),
                1_024,
                2_048,
                None,
                "active",
                None,
            ),
            sample_conn(
                "carry-failed-in-window",
                "tcp",
                "api.example.com",
                "Node-HK",
                1_500,
                Some(3_200),
                None,
                0,
                0,
                None,
                "failed",
                Some("Sub (203.0.113.124) reset"),
            ),
            sample_conn(
                "win-udp",
                "udp",
                "quic.example.com",
                "Node-HK",
                2_500,
                None,
                Some(0),
                120,
                240,
                None,
                "active",
                None,
            ),
            sample_conn(
                "win-tcp",
                "tcp",
                "video.example.com",
                "Node-HK",
                3_000,
                Some(4_100),
                Some(185),
                500,
                0,
                Some("198.18.0.42"),
                "closed",
                None,
            ),
            sample_conn(
                "after-window",
                "tcp",
                "late.example.com",
                "Node-HK",
                6_000,
                Some(6_100),
                Some(40),
                10,
                10,
                None,
                "failed",
                Some("post-window error"),
            ),
        ];

        let mut delays = HashMap::new();
        delays.insert("Node-HK".to_string(), 88);

        let sec = build_window_diagnostic_sections(&conns, 2_000, 5_000, &delays);
        assert_eq!(sec.carry_over_count, 2);
        assert_eq!(sec.window_connections, 2);
        assert_eq!(sec.window_tcp, 1);
        assert_eq!(sec.window_udp, 1);
        assert_eq!(sec.window_zero_rx, 1);
        assert_eq!(sec.window_fake_ip_restored, 1);
        assert_eq!(sec.window_failed, 1);

        assert_eq!(sec.outbound_stats_json.len(), 1);
        let ob = &sec.outbound_stats_json[0];
        assert_eq!(ob["outbound"], "Node-HK");
        assert_eq!(ob["connections"], 2);
        assert_eq!(ob["handshakeSamples"], 1);
        assert_eq!(ob["handshakeP50Ms"], 185);
        assert_eq!(ob["handshakeP95Ms"], 185);
        assert_eq!(ob["handshakeMaxMs"], 185);
        assert_eq!(ob["latestProbeDelayMs"], 88);

        assert_eq!(sec.slow_connections_json.len(), 1);
        assert_eq!(sec.slow_connections_json[0]["host"], "video.example.com");

        assert_eq!(sec.failed_connections_json.len(), 1);
        assert_eq!(sec.failed_connections_json[0]["host"], "api.example.com");
        let err_str = sec.failed_connections_json[0]["error"]
            .as_str()
            .unwrap_or_default();
        assert!(!err_str.contains("203.0.113.124"));
        assert!(err_str.contains("***REDACTED***"));
    }

    static UNIT_TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn redacted_active_profile_summary_masks_subscription_host_and_sub_title() {
        let _test_guard = UNIT_TEST_LOCK.lock();
        let _ = stop_android_vpn_core();
        let tmp_dir =
            std::env::temp_dir().join(format!("rustclash-jni-redaction-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&tmp_dir).expect("create temp state dir");

        let mgr = ProfileManager::open_or_init(&tmp_dir).expect("open ProfileManager");
        let starter_id = mgr.active_profile_id();
        let (_, starter_summary) = build_redacted_active_profile_summary(&mgr);
        let starter_json = starter_summary.expect("active starter summary");
        assert!(starter_json["subscriptionHost"].is_null());

        mgr.update_profile_settings(
            &starter_id,
            ProfileSettingsPatch {
                name: Some("Sub (203.0.113.124)".to_string()),
                auto_update_interval_secs: None,
            },
        )
        .expect("rename starter profile");

        let snap = android_collect_debug_snapshot_window_core(&tmp_dir, 1_000, 4_000)
            .expect("collect offline window snapshot");
        assert_eq!(snap["sinceEpochMs"], 1_000);
        assert_eq!(snap["untilEpochMs"], 4_000);
        assert_eq!(snap["activeProfile"]["name"], "Sub (***REDACTED***)");
        assert!(!snap.to_string().contains("203.0.113.124"));

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn start_android_vpn_with_options_syncs_ipv6_and_flush_dns_clears_cache() {
        let _test_guard = UNIT_TEST_LOCK.lock();
        let _ = stop_android_vpn_core();
        let tmp_dir =
            std::env::temp_dir().join(format!("rustclash-jni-ipv6-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&tmp_dir).expect("create temp state dir");
        let protector = Arc::new(CallbackSocketProtector::counting("unit-protect", false));

        // Starter YAML defaults `dns.ipv6` to `false`; enabling Dual-Stack (`enable_ipv6 = true`)
        // must sync both `cfg.tun.ipv6` and `cfg.dns.ipv6` to `true`.
        let starter_yaml = ClashConfig::default_starter_yaml();
        let starter_cfg = ClashConfig::from_yaml_str(&starter_yaml).unwrap();
        assert!(!starter_cfg.dns.ipv6);

        let res_v6 = start_android_vpn_with_options(
            #[cfg(unix)]
            None,
            Some(&tmp_dir),
            "",
            false,
            true,
            Arc::clone(&protector),
        )
        .expect("start_android_vpn_with_options ipv6=true");
        assert_eq!(res_v6["ok"], true);

        let (_, engine_v6) = live_handle_and_engine().expect("live engine v6");
        let cfg_v6 = engine_v6.config_snapshot();
        assert!(cfg_v6.tun.ipv6);
        assert!(cfg_v6.dns.ipv6);
        assert!(engine_v6.router().dns().ipv6_enabled());

        let live_snap = android_collect_debug_snapshot_window_core(&tmp_dir, 0, u64::MAX)
            .expect("collect live window snapshot");
        let snake_hits = live_snap["dns"]["resolver_cache_hits"].as_u64();
        let camel_hits = live_snap["dns"]["resolverCacheHits"].as_u64();
        assert!(snake_hits.is_some());
        assert_eq!(camel_hits, snake_hits);
        drop(engine_v6);

        // Also verify raw YAML (`state_dir = None`) syncs `dns.ipv6` when `enable_ipv6 = true`.
        let yaml = "mixed-port: 0\ndns:\n  enable: true\n  ipv6: false\n  listen: 127.0.0.1:0";
        let res_raw = start_android_vpn_with_options(
            #[cfg(unix)]
            None,
            None,
            yaml,
            false,
            true,
            Arc::clone(&protector),
        )
        .expect("start_android_vpn_with_options raw ipv6=true");
        assert_eq!(res_raw["ok"], true);
        let (_, engine_raw) = live_handle_and_engine().expect("live raw engine");
        let cfg_raw = engine_raw.config_snapshot();
        assert!(cfg_raw.tun.ipv6);
        assert!(cfg_raw.dns.ipv6);
        assert!(engine_raw.router().dns().ipv6_enabled());
        drop(engine_raw);

        // Restarting with `enable_ipv6 = false` forces both `tun.ipv6` and `dns.ipv6` to `false`.
        let res = start_android_vpn_with_options(
            #[cfg(unix)]
            None,
            Some(&tmp_dir),
            "",
            false,
            false,
            protector,
        )
        .expect("start_android_vpn_with_options");
        assert_eq!(res["ok"], true);

        let (_, engine) = live_handle_and_engine().expect("live engine running");
        let cfg = engine.config_snapshot();
        assert!(!cfg.tun.ipv6);
        assert!(!cfg.dns.ipv6);
        assert!(!engine.router().dns().ipv6_enabled());

        let cache_file = tmp_dir.join("fake_ip_cache.json");
        std::fs::write(&cache_file, b"{}").expect("seed dummy fake_ip_cache.json");
        let epoch_before = engine.router().epoch();
        assert!(android_flush_dns_core());
        assert!(engine.router().epoch() > epoch_before);
        assert!(!cache_file.exists());

        drop(engine);
        assert!(stop_android_vpn_core());
        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn live_snapshot_uses_in_memory_config_and_tracks_revisions() {
        let _test_guard = UNIT_TEST_LOCK.lock();
        let _ = stop_android_vpn_core();
        let tmp_dir =
            std::env::temp_dir().join(format!("rustclash-jni-mem-snap-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&tmp_dir).expect("create temp state dir");
        let protector = Arc::new(CallbackSocketProtector::counting("unit-protect", false));

        let res = start_android_vpn_with_options(
            #[cfg(unix)]
            None,
            Some(&tmp_dir),
            "",
            false,
            true,
            protector,
        )
        .expect("start_android_vpn_with_options");
        assert_eq!(res["ok"], true);

        let (_, engine) = live_handle_and_engine().expect("live engine running");
        let mgr = engine.ensure_profile_manager().expect("profile manager");
        let yaml_path = mgr.active_profile_path();
        assert!(yaml_path.exists());

        // Remove on-disk YAML temporarily to prove `android_node_manager_snapshot_core`
        // reads strictly from the live in-memory `ClashConfig` without touching disk!
        let backup_bytes = std::fs::read(&yaml_path).expect("read active yaml");
        std::fs::remove_file(&yaml_path).expect("remove active yaml");

        let snap1 = android_node_manager_snapshot_core(&tmp_dir).expect("in-memory live snapshot");
        let status1 = android_status_json_core();
        assert_eq!(snap1["ok"], true);
        assert_eq!(snap1["vpnRunning"], true);
        assert_eq!(snap1["routerEpoch"], status1["routerEpoch"]);
        assert_eq!(snap1["delaysRevision"], status1["delaysRevision"]);

        // Recording a delay bumps `delaysRevision` in both lightweight status and full snapshot
        let prev_rev = status1["delaysRevision"].as_u64().unwrap_or(0);
        engine.router().delays().record("DIRECT", 12);
        let status2 = android_status_json_core();
        assert!(status2["delaysRevision"].as_u64().unwrap_or(0) > prev_rev);

        std::fs::write(&yaml_path, &backup_bytes).expect("restore active yaml");
        drop(mgr);
        drop(engine);
        assert!(stop_android_vpn_core());
        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn network_handoff_with_caps_tracks_cellular_baseline_wifi_handoff_and_ipv6_loss() {
        let _test_guard = UNIT_TEST_LOCK.lock();
        let _ = stop_android_vpn_core();
        let tmp_dir =
            std::env::temp_dir().join(format!("rustclash-jni-net-caps-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&tmp_dir).expect("create temp state dir");
        let protector = Arc::new(CallbackSocketProtector::counting("unit-protect", false));

        let res = start_android_vpn_with_options(
            #[cfg(unix)]
            None,
            Some(&tmp_dir),
            "",
            false,
            true,
            protector,
        )
        .expect("start_android_vpn_with_options");
        assert_eq!(res["ok"], true);

        // 1. Initial Cellular baseline (handle=101, is_wifi=false, has_ipv6=true):
        //    records true transport & IPv6 state without counting a synthetic transition.
        let base_rep = notify_android_network_changed_with_caps_core(101, false, true)
            .expect("active runtime on initial cellular baseline");
        assert!(!base_rep.dns_cache_flushed);
        let status_cell = android_status_json_core();
        assert_eq!(status_cell["networkTransitions"], 0);
        assert_eq!(status_cell["isWifi"], false);
        assert_eq!(status_cell["hasIpv6"], true);

        // 2. Handoff to IPv4-only Wi-Fi (handle=202, is_wifi=true, has_ipv6=false):
        //    increments networkTransitions to 1, flushes DNS/sockets, updates isWifi & hasIpv6.
        let wifi_rep = notify_android_network_changed_with_caps_core(202, true, false)
            .expect("active runtime on wifi handoff");
        assert!(wifi_rep.dns_cache_flushed);
        let status_wifi = android_status_json_core();
        assert_eq!(status_wifi["networkTransitions"], 1);
        assert_eq!(status_wifi["isWifi"], true);
        assert_eq!(status_wifi["hasIpv6"], false);

        let snap = android_collect_debug_snapshot_window_core(&tmp_dir, 0, u64::MAX)
            .expect("collect live window snapshot");
        assert_eq!(snap["networkTransitions"], 1);
        assert_eq!(snap["isWifi"], true);
        assert_eq!(snap["hasIpv6"], false);
        assert_eq!(snap["lastNetworkHandle"], 202);

        // 3. Gaining IPv6 on same Wi-Fi handle (202, true, true) flushes single-stack DNS cache without tearing down IPv4 sessions
        let gain_v6 = notify_android_network_changed_with_caps_core(202, true, true)
            .expect("active runtime on ipv6 gain");
        assert!(gain_v6.dns_cache_flushed);
        assert_eq!(gain_v6.closed_active_connections, 0);
        let status_v6 = android_status_json_core();
        assert_eq!(status_v6["networkTransitions"], 1);
        assert_eq!(status_v6["hasIpv6"], true);

        // 4. Losing IPv6 on same Wi-Fi handle (202, true, false) flushes stale IPv6 state without bumping transitions
        let lose_v6 = notify_android_network_changed_with_caps_core(202, true, false)
            .expect("active runtime on ipv6 loss");
        assert!(lose_v6.dns_cache_flushed);
        let status_no_v6 = android_status_json_core();
        assert_eq!(status_no_v6["networkTransitions"], 1);
        assert_eq!(status_no_v6["hasIpv6"], false);

        assert!(stop_android_vpn_core());
        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn window_diagnostic_sections_weights_coalesced_failed_connections() {
        let mut coalesced = sample_conn(
            "burst-fail",
            "tcp",
            "api.openai.com",
            "Node-SG",
            2_500,
            Some(2_900),
            None,
            0,
            0,
            Some("198.18.0.42"),
            "failed",
            Some("connection reset by peer"),
        );
        coalesced.coalesced_count = 4;

        let sec = build_window_diagnostic_sections(&[coalesced], 2_000, 5_000, &HashMap::new());
        assert_eq!(sec.window_connections, 4);
        assert_eq!(sec.window_tcp, 4);
        assert_eq!(sec.window_udp, 0);
        assert_eq!(sec.window_failed, 4);
        assert_eq!(sec.window_fake_ip_restored, 4);

        assert_eq!(sec.outbound_stats_json.len(), 1);
        assert_eq!(sec.outbound_stats_json[0]["connections"], 4);
        assert_eq!(sec.outbound_stats_json[0]["failures"], 4);

        assert_eq!(sec.top_domains_json.len(), 1);
        assert_eq!(sec.top_domains_json[0]["connections"], 4);
        assert_eq!(sec.top_domains_json[0]["failures"], 4);

        assert_eq!(sec.failed_connections_json.len(), 1);
        assert_eq!(sec.failed_connections_json[0]["coalescedCount"], 4);

        assert_eq!(sec.recent_connections_json.len(), 1);
        assert_eq!(sec.recent_connections_json[0]["coalescedCount"], 4);
    }

    #[test]
    fn ipv6_gain_on_same_network_handle_flushes_dns_without_closing_active_connections() {
        let _test_guard = UNIT_TEST_LOCK.lock();
        let _ = stop_android_vpn_core();
        let tmp_dir =
            std::env::temp_dir().join(format!("rustclash-jni-ipv6-gain-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&tmp_dir).expect("create temp state dir");
        let protector = Arc::new(CallbackSocketProtector::counting("unit-protect", false));

        let res = start_android_vpn_with_options(
            #[cfg(unix)]
            None,
            Some(&tmp_dir),
            "",
            false,
            true,
            protector,
        )
        .expect("start_android_vpn_with_options");
        assert_eq!(res["ok"], true);

        // Establish IPv4-only Wi-Fi baseline on handle 303.
        let base_rep = notify_android_network_changed_with_caps_core(303, true, false)
            .expect("active runtime on baseline");
        assert!(!base_rep.dns_cache_flushed);

        let (_, engine) = live_handle_and_engine().expect("live engine");
        let target = proxy_core::addr::TargetAddr::new_domain("ipv4.example.com", 443).unwrap();
        let active_conn = engine.hub().register_connection(
            "TUN(smoltcp)",
            "tcp",
            None,
            &target,
            None,
            "MATCH",
            "",
            vec!["DIRECT".to_string()],
        );
        active_conn.mark_established();
        assert_eq!(engine.hub().active_connection_count(), 1);

        // SLAAC Router Advertisement arrives on the same handle (has_ipv6: false -> true):
        // DNS cache must flush while preserving healthy IPv4 connections.
        let gain_rep = notify_android_network_changed_with_caps_core(303, true, true)
            .expect("active runtime on ipv6 gain");
        assert!(gain_rep.dns_cache_flushed);
        assert_eq!(gain_rep.closed_active_connections, 0);
        assert_eq!(gain_rep.reset_udp_nat_sessions, 0);
        assert_eq!(gain_rep.evicted_tls_sessions, 0);
        assert_eq!(engine.hub().active_connection_count(), 1);
        assert!(!active_conn.is_closed());
        assert!(
            engine
                .hub()
                .recent_logs()
                .iter()
                .any(|e| e.payload.contains("Android link gained global IPv6 (handle 303, wifi=true): flushed single-stack DNS cache"))
        );

        engine.hub().unregister_connection(&active_conn.id);
        drop(active_conn);
        drop(engine);
        assert!(stop_android_vpn_core());
        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn window_diagnostic_sections_preserves_high_bandwidth_single_conn_domain_and_reports_carry_over_streams()
     {
        let since_ms = 10_000u64;
        let until_ms = 20_000u64;
        let mut conns = Vec::new();

        // 25 chatty 100-byte domains (conns = 5..=29)
        for i in 0..25usize {
            let host = format!("chatty-{i:02}.example.com");
            let mut c = sample_conn(
                &format!("chatty-{i:02}"),
                "tcp",
                &host,
                "Node-HK",
                since_ms + 100 + i as u64,
                Some(since_ms + 500 + i as u64),
                Some(42),
                60,
                40,
                None,
                "closed",
                None,
            );
            c.coalesced_count = (29 - i) as u64;
            conns.push(c);
        }

        // 8 additional tiny single-connection domains so total unique window domains > 30 (34 total)
        for i in 0..8usize {
            let host = format!("tiny-{i:02}.example.net");
            conns.push(sample_conn(
                &format!("tiny-{i:02}"),
                "tcp",
                &host,
                "DIRECT",
                since_ms + 2_000 + i as u64,
                Some(since_ms + 2_100 + i as u64),
                Some(15),
                10,
                10,
                None,
                "closed",
                None,
            ));
        }

        // 1 single-connection (conns=1) 80 MB heavy upload domain on DIRECT
        let upload_80mb = 80u64 * 1024 * 1024;
        let mut heavy_upload = sample_conn(
            "heavy-upload-1",
            "tcp",
            "upos-sz-upcdn.bilivideo.com",
            "DIRECT",
            since_ms + 3_000,
            Some(since_ms + 8_000),
            Some(28),
            upload_80mb,
            4_096,
            None,
            "closed",
            None,
        );
        heavy_upload.rule = "GeoSite".to_string();
        heavy_upload.rule_payload = "cn".to_string();
        conns.push(heavy_upload);

        // 2 carry-over (start_epoch_ms < since_epoch_ms) high-traffic streams + 1 pre-window already-closed stream
        let mut carry_dl = sample_conn(
            "carry-heavy-dl",
            "tcp",
            "rr1---sn-video.googlevideo.com?token=SECRET_CARRY_HOST_TOKEN",
            "Sub (203.0.113.124)",
            2_000,
            None,
            Some(55),
            512 * 1024,
            38 * 1024 * 1024,
            None,
            "active",
            None,
        );
        carry_dl.rule = "GeoSite".to_string();
        carry_dl.rule_payload = "password=SECRET_RULE_PASS_999".to_string();
        conns.push(carry_dl);

        let mut carry_ul = sample_conn(
            "carry-heavy-ul",
            "udp",
            "live-push.bilivideo.com",
            "DIRECT",
            4_500,
            Some(since_ms + 1_200),
            None,
            15 * 1024 * 1024,
            2 * 1024 * 1024,
            None,
            "closed",
            None,
        );
        carry_ul.rule = "GeoSite".to_string();
        carry_ul.rule_payload = "cn".to_string();
        conns.push(carry_ul);

        // Pre-window closed connection (end < since_ms) should NOT be counted in carryOverConnections
        conns.push(sample_conn(
            "pre-window-expired",
            "tcp",
            "expired.example.org",
            "DIRECT",
            1_000,
            Some(since_ms - 500),
            Some(20),
            99 * 1024 * 1024,
            0,
            None,
            "closed",
            None,
        ));

        let sec = build_window_diagnostic_sections(&conns, since_ms, until_ms, &HashMap::new());

        // 1. Verify topDomains caps at 30 max and includes the conns=1 80 MB upload domain
        assert_eq!(sec.top_domains_json.len(), 30);
        let heavy_dom = sec
            .top_domains_json
            .iter()
            .find(|d| d["host"] == "upos-sz-upcdn.bilivideo.com")
            .expect("80 MB conns=1 upload domain must appear in topDomains");
        assert_eq!(heavy_dom["connections"], 1);
        assert_eq!(heavy_dom["uploadBytes"], upload_80mb);
        assert_eq!(heavy_dom["downloadBytes"], 4_096);
        assert_eq!(heavy_dom["primaryOutbound"], "DIRECT");
        assert_eq!(heavy_dom["primaryRule"], "GeoSite,cn");
        // And it should be the very first entry (#21, index 20) among the top-10-by-bytes additions!
        assert_eq!(
            sec.top_domains_json[20]["host"],
            "upos-sz-upcdn.bilivideo.com"
        );

        // 2. Verify carryOverConnections reports the 2 overlapping carry-over streams sorted by total bytes desc, with redaction
        assert_eq!(sec.carry_over_count, 2);
        assert_eq!(sec.carry_over_connections_json.len(), 2);

        let first_carry = &sec.carry_over_connections_json[0];
        assert_eq!(first_carry["port"], 443);
        assert_eq!(first_carry["network"], "tcp");
        assert_eq!(first_carry["status"], "active");
        assert_eq!(first_carry["uploadBytes"], 512 * 1024);
        assert_eq!(first_carry["downloadBytes"], 38 * 1024 * 1024);
        assert_eq!(first_carry["ageMs"], until_ms - 2_000);
        assert_eq!(first_carry["effectiveOutbound"], "Sub (***REDACTED***)");
        let first_host = first_carry["host"].as_str().unwrap_or_default();
        let first_rule = first_carry["rule"].as_str().unwrap_or_default();
        assert!(!first_host.contains("SECRET_CARRY_HOST_TOKEN"));
        assert!(!first_rule.contains("SECRET_RULE_PASS_999"));
        assert!(first_rule.contains("***REDACTED***"));

        let second_carry = &sec.carry_over_connections_json[1];
        assert_eq!(second_carry["host"], "live-push.bilivideo.com");
        assert_eq!(second_carry["port"], 443);
        assert_eq!(second_carry["network"], "udp");
        assert_eq!(second_carry["status"], "closed");
        assert_eq!(second_carry["rule"], "GeoSite,cn");
        assert_eq!(second_carry["effectiveOutbound"], "DIRECT");
        assert_eq!(second_carry["uploadBytes"], 15 * 1024 * 1024);
        assert_eq!(second_carry["downloadBytes"], 2 * 1024 * 1024);
        assert_eq!(second_carry["ageMs"], until_ms - 4_500);
    }
}

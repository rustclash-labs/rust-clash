use std::{
    fs::{self, OpenOptions},
    io::{self, BufRead, BufReader, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    thread::JoinHandle,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use parking_lot::{Mutex, RwLock};
use proxy_core::{
    api::spawn_api_server,
    config::{ClashConfig, uri::redact_sensitive_text},
    engine::ProxyEngine,
    platform::{
        autostart::{AutostartManager, AutostartStatus},
        recovery::{SingleInstanceGuard, default_state_dir, recover_stale_network_state},
        sysproxy::{SysProxyStatus, query_sysproxy_status},
        tun::preflight_system_tun,
    },
    profile::ProfileManager,
};
use serde::{Deserialize, Serialize};
use tokio::sync::watch;

pub const DESKTOP_IPC_FILENAME: &str = "rust-clash.desktop.ipc";
pub const DESKTOP_PREFS_FILENAME: &str = "desktop_prefs.json";
pub const STARTUP_CRASH_LOG_FILENAME: &str = "startup-crash.log";

const INSTANCE_ACQUIRE_ATTEMPTS: usize = 6;
const INSTANCE_RETRY_DELAY: Duration = Duration::from_millis(250);
const IPC_SOCKET_TIMEOUT: Duration = Duration::from_millis(600);

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

const fn default_close_to_tray() -> bool {
    true
}

/// Persistent desktop UX preferences stored at `state_dir/desktop_prefs.json`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesktopPrefs {
    #[serde(default = "default_close_to_tray")]
    pub close_to_tray: bool,
}

impl Default for DesktopPrefs {
    fn default() -> Self {
        Self {
            close_to_tray: true,
        }
    }
}

impl DesktopPrefs {
    pub fn path_in(state_dir: &Path) -> PathBuf {
        state_dir.join(DESKTOP_PREFS_FILENAME)
    }

    pub fn load_from(state_dir: &Path) -> Self {
        let path = Self::path_in(state_dir);
        let Ok(raw) = fs::read_to_string(&path) else {
            return Self::default();
        };
        if raw.trim().is_empty() {
            return Self::default();
        }
        serde_json::from_str(&raw).unwrap_or_default()
    }

    pub fn save_to(&self, state_dir: &Path) -> io::Result<()> {
        fs::create_dir_all(state_dir)?;
        let final_path = Self::path_in(state_dir);
        let tmp_path = state_dir.join(format!(
            "{DESKTOP_PREFS_FILENAME}.tmp.{}",
            std::process::id()
        ));
        let serialized = serde_json::to_vec_pretty(self).map_err(io::Error::other)?;
        {
            let mut f = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&tmp_path)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = f.set_permissions(fs::Permissions::from_mode(0o600));
            }
            f.write_all(&serialized)?;
            f.sync_all()?;
        }
        fs::rename(&tmp_path, &final_path)?;
        Ok(())
    }
}

/// Loopback wakeup endpoint metadata written to `state_dir/rust-clash.desktop.ipc`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesktopIpcEndpoint {
    pub pid: u32,
    pub port: u16,
    pub token: String,
}

fn generate_ipc_token() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(1);
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    let pid = std::process::id() as u64;
    let stack_entropy = (&seq as *const u64 as usize) as u64;

    fn splitmix64(mut x: u64) -> u64 {
        x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
        x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        x ^ (x >> 31)
    }

    let seed = nanos ^ pid.rotate_left(32) ^ stack_entropy.rotate_left(17) ^ seq;
    let hi = splitmix64(seed);
    let lo = splitmix64(hi ^ seed.rotate_right(19));
    format!("{hi:016x}{lo:016x}")
}

type WakeupCallback = Arc<dyn Fn() + Send + Sync>;

/// Lightweight cross-platform `127.0.0.1:0` IPC server allowing secondary launcher clicks
/// to wake and focus the primary desktop window when minimized or hidden to the system tray.
pub struct DesktopWakeupServer {
    ipc_path: PathBuf,
    local_addr: SocketAddr,
    stop_flag: Arc<AtomicBool>,
    pending_wakeup: Arc<AtomicBool>,
    wakeup_count: Arc<AtomicUsize>,
    callback: Arc<Mutex<Option<WakeupCallback>>>,
    worker: Option<JoinHandle<()>>,
}

impl DesktopWakeupServer {
    pub fn bind_in_state_dir(state_dir: &Path) -> io::Result<Self> {
        fs::create_dir_all(state_dir)?;
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        let local_addr = listener.local_addr()?;
        let token = generate_ipc_token();
        let ipc_path = state_dir.join(DESKTOP_IPC_FILENAME);
        let tmp_path = state_dir.join(format!("{DESKTOP_IPC_FILENAME}.tmp.{}", std::process::id()));

        let endpoint = DesktopIpcEndpoint {
            pid: std::process::id(),
            port: local_addr.port(),
            token: token.clone(),
        };
        let serialized = serde_json::to_vec_pretty(&endpoint).map_err(io::Error::other)?;
        {
            let mut f = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&tmp_path)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = f.set_permissions(fs::Permissions::from_mode(0o600));
            }
            f.write_all(&serialized)?;
            f.sync_all()?;
        }
        fs::rename(&tmp_path, &ipc_path)?;

        let stop_flag = Arc::new(AtomicBool::new(false));
        let pending_wakeup = Arc::new(AtomicBool::new(false));
        let wakeup_count = Arc::new(AtomicUsize::new(0));
        let callback: Arc<Mutex<Option<WakeupCallback>>> = Arc::new(Mutex::new(None));

        let stop_thread = Arc::clone(&stop_flag);
        let pending_thread = Arc::clone(&pending_wakeup);
        let count_thread = Arc::clone(&wakeup_count);
        let cb_thread = Arc::clone(&callback);
        let expected_line = format!("SHOW {token}");

        let worker = std::thread::Builder::new()
            .name("rc-desktop-ipc".to_string())
            .spawn(move || {
                while let Ok((mut stream, _peer)) = listener.accept() {
                    if stop_thread.load(Ordering::Acquire) {
                        break;
                    }
                    let _ = stream.set_read_timeout(Some(IPC_SOCKET_TIMEOUT));
                    let _ = stream.set_write_timeout(Some(IPC_SOCKET_TIMEOUT));

                    let mut line = String::new();
                    let read_ok = {
                        let mut reader = BufReader::new((&mut stream).take(256));
                        reader.read_line(&mut line).is_ok()
                    };
                    if !read_ok {
                        continue;
                    }
                    if line.trim() == expected_line {
                        count_thread.fetch_add(1, Ordering::AcqRel);
                        let registered = cb_thread.lock().clone();
                        if let Some(cb) = registered {
                            cb();
                        } else {
                            pending_thread.store(true, Ordering::Release);
                        }
                        let _ = stream.write_all(b"OK\n");
                        let _ = stream.flush();
                    } else {
                        let _ = stream.write_all(b"ERR\n");
                        let _ = stream.flush();
                    }
                }
            })?;

        Ok(Self {
            ipc_path,
            local_addr,
            stop_flag,
            pending_wakeup,
            wakeup_count,
            callback,
            worker: Some(worker),
        })
    }

    pub fn register_callback<F>(&self, cb: F)
    where
        F: Fn() + Send + Sync + 'static,
    {
        let arc_cb: WakeupCallback = Arc::new(cb);
        *self.callback.lock() = Some(Arc::clone(&arc_cb));
        if self.pending_wakeup.swap(false, Ordering::AcqRel) {
            arc_cb();
        }
    }

    pub fn wakeup_count(&self) -> usize {
        self.wakeup_count.load(Ordering::Acquire)
    }

    pub fn ipc_path(&self) -> &Path {
        &self.ipc_path
    }

    pub fn stop(&mut self) {
        self.stop_flag.store(true, Ordering::Release);
        let _ = fs::remove_file(&self.ipc_path);
        if let Some(worker) = self.worker.take() {
            let _ = TcpStream::connect_timeout(&self.local_addr, Duration::from_millis(50));
            let _ = worker.join();
        }
    }
}

impl Drop for DesktopWakeupServer {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Attempt to wake an already-running primary RustClash Desktop instance via `rust-clash.desktop.ipc`.
/// Returns `true` iff the running instance authenticated the token and replied `"OK"`.
pub fn try_signal_running_instance(state_dir: &Path) -> bool {
    let ipc_path = state_dir.join(DESKTOP_IPC_FILENAME);
    let Ok(raw) = fs::read_to_string(&ipc_path) else {
        return false;
    };
    let Ok(endpoint) = serde_json::from_str::<DesktopIpcEndpoint>(&raw) else {
        return false;
    };
    if endpoint.port == 0 || endpoint.token.trim().is_empty() {
        return false;
    }

    let addr = SocketAddr::from(([127, 0, 0, 1], endpoint.port));
    let Ok(mut stream) = TcpStream::connect_timeout(&addr, IPC_SOCKET_TIMEOUT) else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(IPC_SOCKET_TIMEOUT));
    let _ = stream.set_write_timeout(Some(IPC_SOCKET_TIMEOUT));

    let cmd = format!("SHOW {}\n", endpoint.token);
    if stream.write_all(cmd.as_bytes()).is_err() || stream.flush().is_err() {
        return false;
    }

    let mut resp = String::new();
    let mut reader = BufReader::new(stream.take(64));
    if reader.read_line(&mut resp).is_err() {
        return false;
    }
    resp.trim() == "OK"
}

pub enum InstanceAcquireOutcome {
    Acquired(SingleInstanceGuard),
    SignaledRunning,
}

/// Acquire the single-instance lock in `state_dir`, or if another instance holds the lock:
/// 1. Signal it via `rust-clash.desktop.ipc` so its hidden/minimized window comes to focus.
/// 2. Retry across a brief teardown window (`6 x 250ms = 1.5s`) so closing and immediately
///    re-clicking the desktop icon never fails on a transient shutdown race.
pub fn acquire_or_signal_instance(state_dir: &Path) -> anyhow::Result<InstanceAcquireOutcome> {
    let mut last_lock_err: Option<io::Error> = None;
    for attempt in 0..INSTANCE_ACQUIRE_ATTEMPTS {
        match SingleInstanceGuard::acquire(state_dir) {
            Ok(guard) => return Ok(InstanceAcquireOutcome::Acquired(guard)),
            Err(err) if err.kind() == io::ErrorKind::AddrInUse => {
                if try_signal_running_instance(state_dir) {
                    return Ok(InstanceAcquireOutcome::SignaledRunning);
                }
                last_lock_err = Some(err);
                if attempt + 1 < INSTANCE_ACQUIRE_ATTEMPTS {
                    std::thread::sleep(INSTANCE_RETRY_DELAY);
                }
            }
            Err(err) => {
                return Err(anyhow::anyhow!(
                    "Failed to acquire RustClash single-instance lock in '{}': {err}",
                    state_dir.display()
                ));
            }
        }
    }

    if try_signal_running_instance(state_dir) {
        return Ok(InstanceAcquireOutcome::SignaledRunning);
    }

    match last_lock_err {
        Some(err) => Err(anyhow::anyhow!(
            "RustClash Desktop is already running and did not respond to wakeup IPC: {err}"
        )),
        None => Err(anyhow::anyhow!("RustClash Desktop is already running")),
    }
}

/// Append a timestamped diagnostic entry to `state_dir/startup-crash.log` and return its path.
pub fn write_startup_crash_log(state_dir: &Path, message: &str) -> PathBuf {
    let log_path = state_dir.join(STARTUP_CRASH_LOG_FILENAME);
    let _ = fs::create_dir_all(state_dir);
    let unix_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let safe_msg = redact_sensitive_text(message);
    let line = format!(
        "[unix={unix_secs} pid={} v={}] {safe_msg}\n",
        std::process::id(),
        version()
    );
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(&log_path) {
        let _ = file.write_all(line.as_bytes());
        let _ = file.sync_all();
    }
    log_path
}

#[derive(Clone)]
pub struct DesktopAppState {
    pub engine: Arc<ProxyEngine>,
    pub api_addr: SocketAddr,
    state_dir: PathBuf,
    prefs: Arc<RwLock<DesktopPrefs>>,
    instance_guard: Arc<Mutex<Option<SingleInstanceGuard>>>,
    wakeup_server: Arc<Mutex<Option<DesktopWakeupServer>>>,
    ipc_path: Option<PathBuf>,
    _shutdown_tx: watch::Sender<bool>,
}

#[derive(Serialize)]
pub struct DesktopRuntimeStatus {
    pub version: String,
    pub mixed_listen: String,
    pub dns_listen: Option<String>,
    pub api_base_url: String,
    pub api_secret: Option<String>,
    pub mode: String,
    pub effective_outbound: String,
    pub effective_protocol: String,
    pub demo_mode: bool,
    pub tun_enabled: bool,
    pub close_to_tray: bool,
    pub sysproxy: SysProxyStatus,
    pub autostart: AutostartStatus,
    pub active_connections: usize,
    pub fake_ip_entries: usize,
}

impl DesktopAppState {
    /// Default production launcher: starts in **Real User Mode** backed by persistent `ProfileManager`
    /// (`~/.local/state/rust-clash` / `%LOCALAPPDATA%\rust-clash` / `~/Library/Application Support/rust-clash`),
    /// enforces single-instance lockfile safety, starts the loopback wakeup IPC server, and gracefully
    /// recovers from non-admin TUN configs, busy ports, or malformed user profiles so the GUI always opens.
    pub async fn bootstrap_default() -> anyhow::Result<Self> {
        Self::bootstrap_in_state_dir(default_state_dir()).await
    }

    /// Hermetic production launcher rooted at an explicit `state_dir`.
    pub async fn bootstrap_in_state_dir(state_dir: PathBuf) -> anyhow::Result<Self> {
        let mut last_err: Option<io::Error> = None;
        let mut acquired: Option<SingleInstanceGuard> = None;
        for attempt in 0..INSTANCE_ACQUIRE_ATTEMPTS {
            match SingleInstanceGuard::acquire(&state_dir) {
                Ok(g) => {
                    acquired = Some(g);
                    break;
                }
                Err(e) if e.kind() == io::ErrorKind::AddrInUse => {
                    last_err = Some(e);
                    if attempt + 1 < INSTANCE_ACQUIRE_ATTEMPTS {
                        tokio::time::sleep(INSTANCE_RETRY_DELAY).await;
                    }
                }
                Err(e) => {
                    return Err(anyhow::anyhow!(
                        "Failed to acquire instance lock in '{}': {e}",
                        state_dir.display()
                    ));
                }
            }
        }
        let guard = match acquired {
            Some(g) => g,
            None => {
                let detail = last_err
                    .map(|e| e.to_string())
                    .unwrap_or_else(|| "lock busy".to_string());
                anyhow::bail!("RustClash Desktop is already running: {detail}");
            }
        };
        Self::bootstrap_with_guard(state_dir, guard).await
    }

    async fn bootstrap_with_guard(
        state_dir: PathBuf,
        instance_guard: SingleInstanceGuard,
    ) -> anyhow::Result<Self> {
        let _ = recover_stale_network_state(&state_dir);
        let prefs = DesktopPrefs::load_from(&state_dir);

        let wakeup_srv = DesktopWakeupServer::bind_in_state_dir(&state_dir).ok();
        let ipc_path = wakeup_srv.as_ref().map(|s| s.ipc_path().to_path_buf());

        let mut startup_warnings: Vec<String> = Vec::new();
        let profile_mgr = match ProfileManager::open_or_init(&state_dir) {
            Ok(mgr) => Some(mgr),
            Err(err) => {
                startup_warnings.push(format!(
                    "Profile index recovery warning ({}); starting with safe in-memory defaults.",
                    redact_sensitive_text(&err.to_string())
                ));
                None
            }
        };

        let (mut cfg, active_path) = match &profile_mgr {
            Some(mgr) => match mgr.load_active_config() {
                Ok((loaded_cfg, path)) => (loaded_cfg, Some(path)),
                Err(parse_err) => {
                    startup_warnings.push(format!(
                        "Active profile YAML failed to parse ({}); started with safe default configuration so you can repair your profile.",
                        redact_sensitive_text(&parse_err.to_string())
                    ));
                    let starter_cfg =
                        ClashConfig::from_yaml_str(&ClashConfig::default_starter_yaml())
                            .unwrap_or_default();
                    (starter_cfg, None)
                }
            },
            None => (ClashConfig::default(), None),
        };

        // Prevent non-admin / missing-driver TUN configs from crashing desktop startup!
        if cfg.tun.enable && cfg.tun.auto_route {
            let pf = preflight_system_tun(cfg.tun.wintun_path.as_deref().map(Path::new));
            if pf.backend == "unsupported" || !pf.privilege_ok || !pf.driver_loaded {
                cfg.tun.enable = false;
                let reason = pf
                    .privilege_hint
                    .as_deref()
                    .unwrap_or("OS network elevation or TUN driver unavailable");
                startup_warnings.push(format!(
                    "System TUN auto-start skipped ({reason}); console opened in user-space mode so you can elevate or toggle TUN when ready."
                ));
            }
        }

        let is_default_dir = state_dir == default_state_dir();
        let primary_start = if is_default_dir && active_path.is_some() {
            ProxyEngine::start_with_path(cfg.clone(), active_path).await
        } else {
            ProxyEngine::start_with_state_dir(cfg.clone(), state_dir.clone()).await
        };

        let engine = match primary_start {
            Ok(eng) => eng,
            Err(first_err) => {
                startup_warnings.push(format!(
                    "Primary startup encountered an error ({}); retrying on ephemeral local ports with System TUN disabled.",
                    redact_sensitive_text(&first_err.to_string())
                ));
                cfg.mixed_port = 0;
                cfg.dns.listen = "127.0.0.1:0".to_string();
                cfg.tun.enable = false;
                match ProxyEngine::start_with_state_dir(cfg, state_dir.clone()).await {
                    Ok(eng) => eng,
                    Err(second_err) => {
                        startup_warnings.push(format!(
                            "Profile fallback failed ({}); recovered with clean default configuration so the console can open.",
                            redact_sensitive_text(&second_err.to_string())
                        ));
                        match ProxyEngine::start_with_state_dir(
                            ClashConfig::default(),
                            state_dir.clone(),
                        )
                        .await
                        {
                            Ok(eng) => eng,
                            Err(_) => {
                                let emergency_cfg = ClashConfig {
                                    mixed_port: 0,
                                    dns: proxy_core::config::DnsConfig {
                                        listen: "127.0.0.1:0".to_string(),
                                        ..Default::default()
                                    },
                                    tun: proxy_core::config::TunConfig {
                                        enable: false,
                                        ..Default::default()
                                    },
                                    ..Default::default()
                                };
                                ProxyEngine::start_with_state_dir(emergency_cfg, state_dir.clone())
                                    .await?
                            }
                        }
                    }
                }
            }
        };

        if let Some(mgr) = profile_mgr {
            engine.attach_profile_manager(mgr);
        }
        for warn_msg in startup_warnings {
            tracing::warn!("{warn_msg}");
            engine.hub().push_log("warn", warn_msg);
        }

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let preferred_ctrl = engine.config_snapshot().external_controller;
        let (api_addr, _task) =
            match spawn_api_server(&preferred_ctrl, Arc::clone(&engine), shutdown_rx.clone()).await
            {
                Ok(bound) => bound,
                Err(_) => spawn_api_server("127.0.0.1:0", Arc::clone(&engine), shutdown_rx).await?,
            };

        Ok(Self {
            engine,
            api_addr,
            state_dir,
            prefs: Arc::new(RwLock::new(prefs)),
            instance_guard: Arc::new(Mutex::new(Some(instance_guard))),
            wakeup_server: Arc::new(Mutex::new(wakeup_srv)),
            ipc_path,
            _shutdown_tx: shutdown_tx,
        })
    }

    /// Optional self-contained Multi-Protocol Demo Sandbox launcher (`--demo` or `RUST_CLASH_DEMO=1`).
    pub async fn bootstrap_demo() -> anyhow::Result<Self> {
        let state_dir = default_state_dir();
        let guard = SingleInstanceGuard::acquire(&state_dir).ok();
        Self::bootstrap_demo_with_guard(state_dir, guard).await
    }

    async fn bootstrap_demo_with_guard(
        state_dir: PathBuf,
        instance_guard: Option<SingleInstanceGuard>,
    ) -> anyhow::Result<Self> {
        let prefs = DesktopPrefs::load_from(&state_dir);
        let wakeup_srv = if instance_guard.is_some() {
            DesktopWakeupServer::bind_in_state_dir(&state_dir).ok()
        } else {
            None
        };
        let ipc_path = wakeup_srv.as_ref().map(|s| s.ipc_path().to_path_buf());

        let engine =
            match ProxyEngine::start_demo(Some(7890), Some("127.0.0.1:9090".into()), None).await {
                Ok(eng) => eng,
                Err(_) => {
                    ProxyEngine::start_demo(
                        Some(0),
                        Some("127.0.0.1:0".into()),
                        Some("127.0.0.1:0".into()),
                    )
                    .await?
                }
            };
        if let Ok(profile_mgr) = ProfileManager::open_or_init(&state_dir) {
            engine.attach_profile_manager(profile_mgr);
        }
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (api_addr, _task) = match spawn_api_server(
            "127.0.0.1:9090",
            Arc::clone(&engine),
            shutdown_rx.clone(),
        )
        .await
        {
            Ok(bound) => bound,
            Err(_) => spawn_api_server("127.0.0.1:0", Arc::clone(&engine), shutdown_rx).await?,
        };
        Ok(Self {
            engine,
            api_addr,
            state_dir,
            prefs: Arc::new(RwLock::new(prefs)),
            instance_guard: Arc::new(Mutex::new(instance_guard)),
            wakeup_server: Arc::new(Mutex::new(wakeup_srv)),
            ipc_path,
            _shutdown_tx: shutdown_tx,
        })
    }

    pub fn prefs(&self) -> DesktopPrefs {
        self.prefs.read().clone()
    }

    pub fn set_close_to_tray(&self, close_to_tray: bool) -> io::Result<DesktopPrefs> {
        let updated = DesktopPrefs { close_to_tray };
        updated.save_to(&self.state_dir)?;
        *self.prefs.write() = updated.clone();
        Ok(updated)
    }

    pub fn register_wakeup_callback<F>(&self, cb: F)
    where
        F: Fn() + Send + Sync + 'static,
    {
        if let Some(srv) = self.wakeup_server.lock().as_ref() {
            srv.register_callback(cb);
        }
    }

    pub fn status(&self) -> DesktopRuntimeStatus {
        let cfg = self.engine.config_snapshot();
        let state_dir = self.engine.state_dir();
        let eff = self.engine.router().effective_primary_outbound();
        DesktopRuntimeStatus {
            version: version().to_string(),
            mixed_listen: self.engine.mixed_addr().to_string(),
            dns_listen: self.engine.dns_addr().map(|a| a.to_string()),
            api_base_url: format!("http://{}", self.api_addr),
            api_secret: cfg.secret.filter(|s| !s.is_empty()),
            mode: cfg.mode.as_str().to_string(),
            effective_outbound: eff.effective_outbound,
            effective_protocol: eff.effective_protocol,
            demo_mode: self.engine.demo_info().enabled,
            tun_enabled: self.engine.is_tun_active(),
            close_to_tray: self.prefs().close_to_tray,
            sysproxy: query_sysproxy_status(&state_dir),
            autostart: AutostartManager::new().status(),
            active_connections: self.engine.hub().list_connections().len(),
            fake_ip_entries: self.engine.router().dns().entry_count(),
        }
    }

    /// Idempotently shuts down the wakeup IPC listener, embedded control API server, `ProxyEngine`,
    /// OS TUN routes, OS System Proxy, and deterministically releases `SingleInstanceGuard` + `.ipc`
    /// BEFORE any `app_handle.exit(0)` (`std::process::exit`) call.
    pub fn shutdown(&self) {
        if let Some(ipc_path) = &self.ipc_path {
            let _ = fs::remove_file(ipc_path);
        }
        if let Some(mut srv) = self.wakeup_server.lock().take() {
            srv.stop();
        }
        let _ = self._shutdown_tx.send(true);
        self.engine.shutdown();
        let _ = self.instance_guard.lock().take();
    }
}

/// Unified desktop application entry point handling single-instance wakeup IPC (`rust-clash.desktop.ipc`),
/// close-then-immediately-reopen teardown retries, resilient engine bootstrap, and Tauri / headless execution.
pub fn run_desktop_app(rt: &tokio::runtime::Runtime, use_demo: bool) -> anyhow::Result<()> {
    let state_dir = default_state_dir();
    let guard = match acquire_or_signal_instance(&state_dir)? {
        InstanceAcquireOutcome::SignaledRunning => {
            tracing::info!(
                "Signaled existing RustClash Desktop instance to restore main window; exiting launcher."
            );
            return Ok(());
        }
        InstanceAcquireOutcome::Acquired(guard) => guard,
    };

    let state = if use_demo {
        rt.block_on(DesktopAppState::bootstrap_demo_with_guard(
            state_dir,
            Some(guard),
        ))?
    } else {
        rt.block_on(DesktopAppState::bootstrap_with_guard(state_dir, guard))?
    };

    #[cfg(feature = "desktop")]
    {
        tauri::async_runtime::set(rt.handle().clone());
        run_tauri_window(state)
    }

    #[cfg(not(feature = "desktop"))]
    {
        let status = state.status();
        println!(
            "RustClash Desktop Core v{} running in {} mode",
            status.version,
            if status.demo_mode {
                "Demo Sandbox"
            } else {
                "Real User"
            }
        );
        println!("  Mixed Inbound : {}", status.mixed_listen);
        println!("  Web Console   : {}", status.api_base_url);
        rt.block_on(async {
            let _ = tokio::signal::ctrl_c().await;
        });
        state.shutdown();
        Ok(())
    }
}

/// Parses CLI arguments before single-instance / GUI initialization to detect narrowed
/// `--elevated-tun-helper` / `elevated-tun-helper` execution.
///
/// Supported forms:
/// - `--elevated-tun-helper --config <path>` / `-c <path>`
/// - `--elevated-tun-helper=<path>`
/// - `--elevated-tun-helper <path>`
/// - `elevated-tun-helper --config <path>`
pub fn parse_elevated_tun_helper_args<I, S>(args: I) -> Option<Result<std::path::PathBuf, String>>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let collected: Vec<String> = args.into_iter().map(|s| s.as_ref().to_string()).collect();
    let mut helper_mode = false;
    let mut config_path: Option<std::path::PathBuf> = None;

    let mut idx = 0;
    while idx < collected.len() {
        let arg = collected[idx].as_str();
        if arg == "--elevated-tun-helper" || arg == "elevated-tun-helper" {
            helper_mode = true;
            idx += 1;
            continue;
        }
        if let Some(inline_val) = arg.strip_prefix("--elevated-tun-helper=") {
            helper_mode = true;
            if !inline_val.trim().is_empty() {
                config_path = Some(std::path::PathBuf::from(inline_val.trim()));
            }
            idx += 1;
            continue;
        }
        if helper_mode {
            if arg == "--config" || arg == "-c" {
                if let Some(next_val) = collected.get(idx + 1)
                    && !next_val.trim().is_empty()
                {
                    config_path = Some(std::path::PathBuf::from(next_val.trim()));
                    idx += 2;
                    continue;
                }
                return Some(Err(
                    "--elevated-tun-helper requires a path after --config".to_string()
                ));
            }
            if let Some(inline_cfg) = arg.strip_prefix("--config=") {
                if !inline_cfg.trim().is_empty() {
                    config_path = Some(std::path::PathBuf::from(inline_cfg.trim()));
                }
                idx += 1;
                continue;
            }
            if !arg.starts_with('-') && config_path.is_none() {
                config_path = Some(std::path::PathBuf::from(arg));
            }
        }
        idx += 1;
    }

    if !helper_mode {
        return None;
    }
    match config_path {
        Some(p) => Some(Ok(p)),
        None => Some(Err(
            "--elevated-tun-helper requires --config <yaml_path>".to_string()
        )),
    }
}

/// Runs the narrowly scoped privileged TUN helper before any GUI / single-instance check so
/// helper invocations are never swallowed by a running desktop GUI instance.
pub async fn run_elevated_tun_helper(config_path: &std::path::Path) -> anyhow::Result<()> {
    let canon = std::fs::canonicalize(config_path)
        .map_err(|e| anyhow::anyhow!("invalid config path '{}': {e}", config_path.display()))?;
    let mut cfg = proxy_core::config::ClashConfig::from_file(&canon)?;
    let preflight = preflight_system_tun(cfg.tun.wintun_path.as_deref().map(std::path::Path::new));
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
        match spawn_api_server(&ctrl_listen, Arc::clone(&engine), shutdown_rx.clone()).await {
            Ok(bound) => bound,
            Err(_) => spawn_api_server("127.0.0.1:0", Arc::clone(&engine), shutdown_rx).await?,
        };
    let _ = tokio::signal::ctrl_c().await;
    let _ = shutdown_tx.send(true);
    engine.shutdown();
    tokio::time::sleep(std::time::Duration::from_millis(80)).await;
    Ok(())
}

#[cfg(feature = "desktop")]
mod desktop_ipc {
    use super::*;
    use proxy_core::{
        config::RunMode,
        outbound::vless::encryption::{config::XorMode, generate_vless_encryption_pair},
        platform::sysproxy::{disable_system_proxy, enable_system_proxy},
    };
    use tauri::{
        Emitter, Manager, RunEvent, State, WindowEvent,
        menu::{Menu, MenuItem, PredefinedMenuItem},
        tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    };

    #[tauri::command]
    pub fn get_desktop_status(state: State<'_, DesktopAppState>) -> DesktopRuntimeStatus {
        state.status()
    }

    #[tauri::command]
    pub fn desktop_get_prefs(state: State<'_, DesktopAppState>) -> DesktopPrefs {
        state.prefs()
    }

    #[tauri::command(rename_all = "snake_case")]
    pub fn desktop_set_prefs(
        close_to_tray: bool,
        state: State<'_, DesktopAppState>,
    ) -> Result<DesktopPrefs, String> {
        state
            .set_close_to_tray(close_to_tray)
            .map_err(|e| e.to_string())
    }

    #[tauri::command]
    pub fn switch_run_mode(
        state: State<'_, DesktopAppState>,
        mode: String,
    ) -> Result<String, String> {
        let parsed = match mode.to_ascii_lowercase().as_str() {
            "rule" => RunMode::Rule,
            "global" => RunMode::Global,
            "direct" => RunMode::Direct,
            other => return Err(format!("unknown mode '{other}'")),
        };
        state.engine.set_mode(parsed);
        Ok(parsed.as_str().to_string())
    }

    #[tauri::command]
    pub fn select_group_proxy(
        state: State<'_, DesktopAppState>,
        group: String,
        proxy: String,
    ) -> Result<(), String> {
        state
            .engine
            .select_group_and_persist(&group, &proxy)
            .map_err(|e| redact_sensitive_text(&e.to_string()))
    }

    #[tauri::command]
    pub async fn probe_proxy_delay(
        state: State<'_, DesktopAppState>,
        name: String,
        url: Option<String>,
    ) -> Result<u64, String> {
        let target_url = url.unwrap_or_else(|| "http://www.gstatic.com/generate_204".to_string());
        state
            .engine
            .router()
            .test_delay(&name, &target_url, Duration::from_secs(5))
            .await
            .map_err(|e| redact_sensitive_text(&e.to_string()))
    }

    #[tauri::command]
    pub fn generate_pq_vless_keys(
        mode: String,
        zero_rtt: bool,
    ) -> Result<serde_json::Value, String> {
        let xor_mode = XorMode::parse(&mode)
            .map_err(|_| "mode must be native, xorpub, or random".to_string())?;
        let pair =
            generate_vless_encryption_pair(xor_mode, zero_rtt, true).map_err(|e| e.to_string())?;
        serde_json::to_value(pair).map_err(|e| e.to_string())
    }

    #[tauri::command]
    pub async fn reload_config_yaml(
        state: State<'_, DesktopAppState>,
        yaml: String,
    ) -> Result<(), String> {
        state
            .engine
            .reload_yaml(&yaml)
            .await
            .map_err(|e| redact_sensitive_text(&e.to_string()))
    }

    #[tauri::command]
    pub fn set_system_proxy(
        state: State<'_, DesktopAppState>,
        enable: bool,
    ) -> Result<SysProxyStatus, String> {
        let state_dir = state.engine.state_dir();
        if enable {
            let port = state.engine.mixed_addr().port();
            enable_system_proxy("127.0.0.1", port, &[], &state_dir)
                .map_err(|e| redact_sensitive_text(&e.to_string()))
        } else {
            disable_system_proxy(&state_dir).map_err(|e| redact_sensitive_text(&e.to_string()))
        }
    }

    #[tauri::command]
    pub fn set_start_at_login(enable: bool) -> Result<AutostartStatus, String> {
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        let mgr = AutostartManager::new();
        mgr.set_enabled(enable, &exe, &[])
            .map_err(|e| e.to_string())?;
        Ok(mgr.status())
    }

    pub(crate) fn show_and_focus_main_window<R: tauri::Runtime>(app: &tauri::AppHandle<R>) {
        if let Some(win) = app.get_webview_window("main") {
            let _ = win.set_skip_taskbar(false);
            let _ = win.show();
            let _ = win.unminimize();
            // On Windows, foreground lock prevents background tray processes from stealing focus unless nudged:
            let _ = win.set_always_on_top(true);
            let _ = win.set_focus();
            let _ = win.set_always_on_top(false);
        }
    }

    fn report_tray_error<R: tauri::Runtime>(
        app: &tauri::AppHandle<R>,
        engine: &ProxyEngine,
        context: &str,
        err: impl std::fmt::Display,
    ) {
        let safe_err = redact_sensitive_text(&err.to_string());
        let msg = format!("{context}: {safe_err}");
        tracing::warn!("{msg}");
        engine.hub().push_log("error", msg.clone());
        let _ = app.emit("rust-clash://desktop-error", msg);
        show_and_focus_main_window(app);
    }

    fn setup_system_tray<R: tauri::Runtime>(
        app: &tauri::AppHandle<R>,
        state: DesktopAppState,
    ) -> tauri::Result<()> {
        let show_i = MenuItem::with_id(app, "show", "Show RustClash Console", true, None::<&str>)?;
        let sep1 = PredefinedMenuItem::separator(app)?;
        let mode_rule =
            MenuItem::with_id(app, "mode_rule", "Mode: Rule Routing", true, None::<&str>)?;
        let mode_global =
            MenuItem::with_id(app, "mode_global", "Mode: Global Proxy", true, None::<&str>)?;
        let mode_direct = MenuItem::with_id(
            app,
            "mode_direct",
            "Mode: Direct Bypass",
            true,
            None::<&str>,
        )?;
        let sep2 = PredefinedMenuItem::separator(app)?;
        let sysproxy_i = MenuItem::with_id(
            app,
            "toggle_sysproxy",
            "Toggle OS System Proxy",
            true,
            None::<&str>,
        )?;
        let tun_i = MenuItem::with_id(app, "toggle_tun", "Toggle System TUN", true, None::<&str>)?;
        let sep3 = PredefinedMenuItem::separator(app)?;
        let quit_i = MenuItem::with_id(app, "quit", "Quit RustClash", true, None::<&str>)?;

        let menu = Menu::with_items(
            app,
            &[
                &show_i,
                &sep1,
                &mode_rule,
                &mode_global,
                &mode_direct,
                &sep2,
                &sysproxy_i,
                &tun_i,
                &sep3,
                &quit_i,
            ],
        )?;

        let tray_icon = app
            .default_window_icon()
            .cloned()
            .unwrap_or_else(|| tauri::include_image!("icons/32x32.png"));

        let builder = TrayIconBuilder::with_id("rust-clash-tray")
            .tooltip("RustClash")
            .icon(tray_icon)
            .menu(&menu)
            .show_menu_on_left_click(false)
            .on_menu_event(move |app_handle, event| match event.id.as_ref() {
                "show" => show_and_focus_main_window(app_handle),
                "mode_rule" => state.engine.set_mode(RunMode::Rule),
                "mode_global" => state.engine.set_mode(RunMode::Global),
                "mode_direct" => state.engine.set_mode(RunMode::Direct),
                "toggle_sysproxy" => {
                    let dir = state.engine.state_dir();
                    let result = if query_sysproxy_status(&dir).enabled {
                        disable_system_proxy(&dir)
                    } else {
                        let port = state.engine.mixed_addr().port();
                        enable_system_proxy("127.0.0.1", port, &[], &dir)
                    };
                    if let Err(err) = result {
                        report_tray_error(
                            app_handle,
                            &state.engine,
                            "OS System Proxy toggle failed",
                            err,
                        );
                    }
                }
                "toggle_tun" => {
                    let eng = Arc::clone(&state.engine);
                    let handle_clone = app_handle.clone();
                    let target = !eng.is_tun_active();
                    tauri::async_runtime::spawn(async move {
                        if let Err(err) = eng.set_tun_active(target).await {
                            report_tray_error(
                                &handle_clone,
                                &eng,
                                "System TUN toggle failed (check privilege / helper)",
                                err,
                            );
                        }
                    });
                }
                "quit" => {
                    state.shutdown();
                    app_handle.exit(0);
                }
                _ => {}
            })
            .on_tray_icon_event(|tray, event| {
                if let TrayIconEvent::Click {
                    button: MouseButton::Left,
                    button_state: MouseButtonState::Up,
                    ..
                } = event
                {
                    show_and_focus_main_window(tray.app_handle());
                }
            });

        let _ = builder.build(app)?;
        Ok(())
    }

    pub fn run_tauri_window(app_state: DesktopAppState) -> anyhow::Result<()> {
        let setup_state = app_state.clone();
        let close_state = app_state.clone();
        let exit_state = app_state.clone();
        let tray_active = Arc::new(AtomicBool::new(false));
        let tray_flag_setup = Arc::clone(&tray_active);
        let tray_flag_close = Arc::clone(&tray_active);

        let app = tauri::Builder::default()
            .manage(app_state)
            .setup(move |app| {
                if let Some(win) = app.get_webview_window("main") {
                    let _ = win.set_icon(tauri::include_image!("icons/128x128.png"));
                }

                let wakeup_handle = app.handle().clone();
                setup_state.register_wakeup_callback(move || {
                    let main_handle = wakeup_handle.clone();
                    let _ = wakeup_handle.run_on_main_thread(move || {
                        show_and_focus_main_window(&main_handle);
                    });
                });

                match setup_system_tray(app.handle(), setup_state) {
                    Ok(()) => {
                        tray_flag_setup.store(true, Ordering::Release);
                    }
                    Err(err) => {
                        tray_flag_setup.store(false, Ordering::Release);
                        tracing::warn!(
                            "System tray unavailable ({err}); window close will exit cleanly instead of hiding"
                        );
                    }
                }
                Ok(())
            })
            .on_window_event(move |window, event| {
                // Only hide-to-tray when BOTH system tray registration succeeded AND user prefs enable `close_to_tray`.
                // Otherwise shut down deterministically and let the window close & process exit cleanly.
                if let WindowEvent::CloseRequested { api, .. } = event {
                    if tray_flag_close.load(Ordering::Acquire) && close_state.prefs().close_to_tray
                    {
                        api.prevent_close();
                        let _ = window.hide();
                    } else {
                        close_state.shutdown();
                    }
                }
            })
            .invoke_handler(tauri::generate_handler![
                get_desktop_status,
                desktop_get_prefs,
                desktop_set_prefs,
                switch_run_mode,
                select_group_proxy,
                probe_proxy_delay,
                generate_pq_vless_keys,
                reload_config_yaml,
                set_system_proxy,
                set_start_at_login,
            ])
            .build(tauri::generate_context!())
            .map_err(|e| anyhow::anyhow!("Tauri build error: {e}"))?;

        app.run(move |app_handle, event| match event {
            #[cfg(target_os = "macos")]
            RunEvent::Reopen { .. } => {
                show_and_focus_main_window(app_handle);
            }
            RunEvent::Exit => {
                exit_state.shutdown();
            }
            _ => {
                let _ = app_handle;
            }
        });
        Ok(())
    }
}

#[cfg(feature = "desktop")]
pub use desktop_ipc::run_tauri_window;

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::PathBuf,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::{SystemTime, UNIX_EPOCH},
    };

    use proxy_core::platform::recovery::SingleInstanceGuard;

    use super::{
        DESKTOP_IPC_FILENAME, DESKTOP_PREFS_FILENAME, DesktopAppState, DesktopPrefs,
        DesktopWakeupServer, InstanceAcquireOutcome, acquire_or_signal_instance,
        parse_elevated_tun_helper_args, try_signal_running_instance,
    };

    fn unique_temp_dir(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("rc-tauri-{label}-{}-{nanos}", std::process::id()));
        fs::create_dir_all(&dir).expect("create temp state dir");
        dir
    }

    #[test]
    fn normal_gui_args_return_none() {
        assert!(parse_elevated_tun_helper_args(["--demo"]).is_none());
        assert!(parse_elevated_tun_helper_args(Vec::<String>::new()).is_none());
    }

    #[test]
    fn elevated_helper_parses_flag_and_subcommand_forms() {
        assert_eq!(
            parse_elevated_tun_helper_args([
                "--elevated-tun-helper",
                "--config",
                "/tmp/clash.yaml"
            ]),
            Some(Ok(PathBuf::from("/tmp/clash.yaml")))
        );
        assert_eq!(
            parse_elevated_tun_helper_args(["--elevated-tun-helper=/tmp/inline.yaml"]),
            Some(Ok(PathBuf::from("/tmp/inline.yaml")))
        );
        assert_eq!(
            parse_elevated_tun_helper_args(["elevated-tun-helper", "-c", "/tmp/sub.yaml"]),
            Some(Ok(PathBuf::from("/tmp/sub.yaml")))
        );
        assert!(
            parse_elevated_tun_helper_args(["--elevated-tun-helper"])
                .unwrap()
                .is_err()
        );
    }

    #[test]
    fn desktop_prefs_default_true_and_persist_roundtrip() {
        let temp_dir = unique_temp_dir("prefs");
        let initial = DesktopPrefs::load_from(&temp_dir);
        assert!(initial.close_to_tray, "close_to_tray must default to true");

        let updated = DesktopPrefs {
            close_to_tray: false,
        };
        updated
            .save_to(&temp_dir)
            .expect("persist desktop_prefs.json");
        assert!(temp_dir.join(DESKTOP_PREFS_FILENAME).exists());

        let reloaded = DesktopPrefs::load_from(&temp_dir);
        assert!(!reloaded.close_to_tray);

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn loopback_ipc_wakeup_and_clean_reopen_after_shutdown() {
        let temp_dir = unique_temp_dir("ipc");
        let guard = SingleInstanceGuard::acquire(&temp_dir).expect("acquire primary lock");
        let mut server = DesktopWakeupServer::bind_in_state_dir(&temp_dir).expect("bind ipc");

        let counter = Arc::new(AtomicUsize::new(0));
        let counter_cb = Arc::clone(&counter);
        server.register_callback(move || {
            counter_cb.fetch_add(1, Ordering::SeqCst);
        });

        assert!(temp_dir.join(DESKTOP_IPC_FILENAME).exists());
        assert!(try_signal_running_instance(&temp_dir));
        assert_eq!(server.wakeup_count(), 1);
        assert_eq!(counter.load(Ordering::SeqCst), 1);

        // On Unix (`flock`), a second acquisition in the same state_dir signals the running instance!
        #[cfg(unix)]
        {
            match acquire_or_signal_instance(&temp_dir).expect("signal running instance") {
                InstanceAcquireOutcome::SignaledRunning => {}
                InstanceAcquireOutcome::Acquired(_) => {
                    panic!("expected SignaledRunning while primary lock is held")
                }
            }
            assert_eq!(server.wakeup_count(), 2);
            assert_eq!(counter.load(Ordering::SeqCst), 2);
        }

        // Clean shutdown removes `.ipc` and `.lock` so immediate re-launch succeeds!
        server.stop();
        drop(guard);
        assert!(!temp_dir.join(DESKTOP_IPC_FILENAME).exists());
        assert!(!temp_dir.join("rust-clash.instance.lock").exists());
        assert!(!try_signal_running_instance(&temp_dir));

        let reopened = match acquire_or_signal_instance(&temp_dir).expect("re-open immediately") {
            InstanceAcquireOutcome::Acquired(g) => g,
            InstanceAcquireOutcome::SignaledRunning => {
                panic!("expected fresh primary acquisition after shutdown")
            }
        };
        drop(reopened);
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[tokio::test]
    async fn bootstrap_recovers_corrupt_or_unprivileged_tun_profile_and_releases_locks_on_shutdown()
    {
        let temp_dir = unique_temp_dir("bootstrap");

        // Pre-populate active profile with `tun.enable: true` + `auto-route: true` AND test clean fallback
        let mgr = proxy_core::profile::ProfileManager::open_or_init(&temp_dir)
            .expect("init profile manager");
        let active_yaml = mgr.active_profile_path();
        fs::write(
            &active_yaml,
            "mixed-port: 0\nexternal-controller: 127.0.0.1:0\ndns:\n  enable: true\n  listen: 127.0.0.1:0\ntun:\n  enable: true\n  auto-route: true\nrules:\n  - MATCH,DIRECT\n",
        )
        .expect("write tun-enabled active profile");
        drop(mgr);

        let state = DesktopAppState::bootstrap_in_state_dir(temp_dir.clone())
            .await
            .expect("desktop bootstrap must never brick on unprivileged tun config");

        assert!(temp_dir.join(DESKTOP_IPC_FILENAME).exists());
        assert!(temp_dir.join("rust-clash.instance.lock").exists());
        assert!(state.prefs().close_to_tray);
        state
            .set_close_to_tray(false)
            .expect("toggle close_to_tray to false");
        assert!(!state.prefs().close_to_tray);
        assert!(try_signal_running_instance(&temp_dir));

        state.shutdown();
        assert!(
            !temp_dir.join(DESKTOP_IPC_FILENAME).exists(),
            "shutdown() must remove rust-clash.desktop.ipc"
        );
        assert!(
            !temp_dir.join("rust-clash.instance.lock").exists(),
            "shutdown() must drop SingleInstanceGuard before process exit"
        );

        let reacquired =
            SingleInstanceGuard::acquire(&temp_dir).expect("reacquire lock right after shutdown");
        drop(reacquired);

        // Also verify corrupted active profile YAML recovers cleanly instead of crashing startup!
        fs::write(&active_yaml, "proxies: [unterminated_corrupt_yaml: {{{\n")
            .expect("write corrupt yaml");
        let recovered_state = DesktopAppState::bootstrap_in_state_dir(temp_dir.clone())
            .await
            .expect("desktop bootstrap must recover from corrupt active profile YAML");
        assert!(
            !recovered_state.prefs().close_to_tray,
            "persisted close_to_tray=false must reload across restarts"
        );
        recovered_state.shutdown();

        let _ = fs::remove_dir_all(&temp_dir);
    }
}

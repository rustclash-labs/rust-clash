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
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use parking_lot::{Mutex, RwLock};
use proxy_core::{
    api::{generate_ephemeral_secret, spawn_api_server},
    config::{ClashConfig, uri::redact_sensitive_text},
    engine::ProxyEngine,
    platform::{
        autostart::{AutostartManager, AutostartStatus},
        recovery::{SingleInstanceGuard, default_state_dir, recover_stale_network_state},
        sysproxy::{
            SysProxyStatus, disable_system_proxy, enable_system_proxy, query_sysproxy_status,
        },
        tun::preflight_system_tun,
    },
    profile::ProfileManager,
};
use serde::{Deserialize, Serialize};
use tokio::sync::watch;

pub const DESKTOP_IPC_FILENAME: &str = "rust-clash.desktop.ipc";
pub const DESKTOP_PREFS_FILENAME: &str = "desktop_prefs.json";
pub const STARTUP_CRASH_LOG_FILENAME: &str = "startup-crash.log";

pub const ARG_DEMO: &str = "--demo";
pub const ARG_RELAUNCH_ENABLE_TUN: &str = "--relaunch-enable-tun";
pub const ARG_PRESERVE_SYSPROXY: &str = "--preserve-sysproxy";

const INSTANCE_ACQUIRE_ATTEMPTS: usize = 6;
const INSTANCE_RETRY_DELAY: Duration = Duration::from_millis(250);
const RELAUNCH_LOCK_TIMEOUT: Duration = Duration::from_secs(15);
const RELAUNCH_LOCK_POLL_INTERVAL: Duration = Duration::from_millis(100);
const IPC_SOCKET_TIMEOUT: Duration = Duration::from_millis(600);
const IPC_ACCEPT_TIMEOUT: Duration = Duration::from_secs(2);
const API_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(3);

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Normalizes wildcard listener addresses (`0.0.0.0:port` and `[::]:port`) to `127.0.0.1:port`
/// so local clients and WebView `fetch` / `WebSocket` calls receive a dialable loopback address.
pub fn normalize_local_connect_addr(addr: SocketAddr) -> SocketAddr {
    if addr.ip().is_unspecified() {
        SocketAddr::from(([127, 0, 0, 1], addr.port()))
    } else {
        addr
    }
}

/// Formats a bound `SocketAddr` into a dialable `http://...` base URL, normalizing wildcard
/// addresses (`0.0.0.0` / `[::]`) to `127.0.0.1` and bracket-wrapping explicit IPv6 addresses.
pub fn format_http_base_url(addr: SocketAddr) -> String {
    match normalize_local_connect_addr(addr) {
        SocketAddr::V4(v4) => format!("http://{v4}"),
        SocketAddr::V6(v6) => format!("http://[{}]:{}", v6.ip(), v6.port()),
    }
}

/// Derives the local connectable proxy host for OS System Proxy settings from `allow-lan` and
/// `bind-address` so non-`127.0.0.1` binds (e.g. `::1` or a specific local interface IP) work.
pub fn resolve_sysproxy_connect_host(cfg: &ClashConfig) -> String {
    if cfg.allow_lan {
        return "127.0.0.1".to_string();
    }
    match cfg.bind_address.trim() {
        "" | "*" | "0.0.0.0" | "::" | "[::]" => "127.0.0.1".to_string(),
        "::1" | "[::1]" => "::1".to_string(),
        other => other
            .strip_prefix('[')
            .and_then(|s| s.strip_suffix(']'))
            .unwrap_or(other)
            .to_string(),
    }
}

/// Waits for `SIGINT` (`Ctrl+C`) or, on Unix platforms, `SIGTERM` (`systemctl stop` / `kill <pid>`)
/// so daemon, headless, and helper processes tear down TUN routes, DNS, and OS System Proxy cleanly.
pub async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sigterm) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = sigterm.recv() => {}
                }
            }
            Err(err) => {
                tracing::warn!(
                    "Failed registering SIGTERM handler ({err}); falling back to Ctrl-C only"
                );
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

const fn default_close_to_tray() -> bool {
    true
}

static PREFS_TMP_SEQ: AtomicU64 = AtomicU64::new(1);

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

    fn save_to_with_writer<F>(state_dir: &Path, write_fn: F) -> io::Result<()>
    where
        F: FnOnce(&mut fs::File) -> io::Result<()>,
    {
        fs::create_dir_all(state_dir)?;
        let final_path = Self::path_in(state_dir);

        let (tmp_path, f) = {
            let mut opened = None;
            for _ in 0..8 {
                let seq = PREFS_TMP_SEQ.fetch_add(1, Ordering::Relaxed);
                let candidate = state_dir.join(format!(
                    "{DESKTOP_PREFS_FILENAME}.tmp.{}.{seq}",
                    std::process::id()
                ));
                let mut opts = OpenOptions::new();
                opts.create_new(true).write(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    opts.mode(0o600);
                }
                match opts.open(&candidate) {
                    Ok(file) => {
                        opened = Some((candidate, file));
                        break;
                    }
                    Err(err) if err.kind() == io::ErrorKind::AlreadyExists => continue,
                    Err(err) => return Err(err),
                }
            }
            opened.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "failed to allocate unique temporary file for desktop_prefs.json",
                )
            })?
        };

        let write_res: io::Result<()> = {
            let mut file = f;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Err(err) = file.set_permissions(fs::Permissions::from_mode(0o600)) {
                    tracing::warn!(
                        "Failed setting 0600 permissions on '{}': {err}",
                        tmp_path.display()
                    );
                }
            }
            write_fn(&mut file)
        };
        if let Err(err) = write_res {
            let _ = fs::remove_file(&tmp_path);
            return Err(err);
        }

        #[cfg(windows)]
        let rename_res = {
            let mut last_err = None;
            for attempt in 0..8u32 {
                match fs::rename(&tmp_path, &final_path) {
                    Ok(()) => {
                        last_err = None;
                        break;
                    }
                    Err(err)
                        if attempt < 7
                            && !final_path.is_dir()
                            && (err.kind() == io::ErrorKind::PermissionDenied
                                || matches!(err.raw_os_error(), Some(5 | 32))) =>
                    {
                        last_err = Some(err);
                        std::thread::sleep(Duration::from_millis(2 * u64::from(attempt + 1)));
                    }
                    Err(err) => {
                        last_err = Some(err);
                        break;
                    }
                }
            }
            last_err.map_or(Ok(()), Err)
        };
        #[cfg(not(windows))]
        let rename_res = fs::rename(&tmp_path, &final_path);

        if let Err(err) = rename_res {
            let _ = fs::remove_file(&tmp_path);
            return Err(err);
        }
        Ok(())
    }

    pub fn save_to(&self, state_dir: &Path) -> io::Result<()> {
        let serialized = serde_json::to_vec_pretty(self).map_err(io::Error::other)?;
        Self::save_to_with_writer(state_dir, |file| {
            file.write_all(&serialized)?;
            file.flush()?;
            file.sync_all()?;
            Ok(())
        })
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
    generate_ephemeral_secret()
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
            let mut opts = OpenOptions::new();
            opts.create(true).write(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            let mut f = opts.open(&tmp_path)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Err(err) = f.set_permissions(fs::Permissions::from_mode(0o600)) {
                    tracing::warn!(
                        "Failed setting 0600 permissions on '{}': {err}",
                        tmp_path.display()
                    );
                }
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
                    let _ = stream.set_read_timeout(Some(IPC_ACCEPT_TIMEOUT));
                    let _ = stream.set_write_timeout(Some(IPC_ACCEPT_TIMEOUT));

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
        if self.stop_flag.swap(true, Ordering::AcqRel) {
            return;
        }
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

/// Parsed desktop GUI launch options (including elevated TUN relaunch handoff flags).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DesktopLaunchOptions {
    pub use_demo: bool,
    pub relaunch_enable_tun: bool,
    pub preserve_sysproxy: bool,
}

/// Parse desktop GUI CLI flags (`--demo`, `--relaunch-enable-tun`, `--preserve-sysproxy`).
pub fn parse_desktop_launch_options<I, S>(args: I, demo_env: bool) -> DesktopLaunchOptions
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut opts = DesktopLaunchOptions {
        use_demo: demo_env,
        relaunch_enable_tun: false,
        preserve_sysproxy: false,
    };
    for raw in args {
        match raw.as_ref() {
            ARG_DEMO => opts.use_demo = true,
            ARG_RELAUNCH_ENABLE_TUN => opts.relaunch_enable_tun = true,
            ARG_PRESERVE_SYSPROXY => opts.preserve_sysproxy = true,
            _ => {}
        }
    }
    opts
}

/// Build the strictly allowlisted CLI argument list passed to the elevated relaunch process.
pub fn build_elevated_relaunch_args(opts: &DesktopLaunchOptions) -> Vec<&'static str> {
    let mut args = Vec::with_capacity(3);
    if opts.relaunch_enable_tun {
        args.push(ARG_RELAUNCH_ENABLE_TUN);
    }
    if opts.preserve_sysproxy {
        args.push(ARG_PRESERVE_SYSPROXY);
    }
    if opts.use_demo {
        args.push(ARG_DEMO);
    }
    args
}

/// Strip Windows extended-length verbatim path prefixes (`\\?\C:\...` -> `C:\...`,
/// `\\?\UNC\server\share\...` -> `\\server\share\...`) because `ShellExecuteExW` rejects
/// `\\?\`-prefixed executable paths.
pub fn strip_windows_verbatim_prefix(path: &Path) -> PathBuf {
    let raw = path.to_string_lossy();
    if let Some(unc_tail) = raw.strip_prefix(r"\\?\UNC\") {
        return PathBuf::from(format!(r"\\{unc_tail}"));
    }
    if let Some(drive_tail) = raw.strip_prefix(r"\\?\") {
        return PathBuf::from(drive_tail);
    }
    path.to_path_buf()
}

fn is_transient_lock_contention(err: &io::Error) -> bool {
    if err.kind() == io::ErrorKind::AddrInUse {
        return true;
    }
    #[cfg(windows)]
    {
        // On Windows, `SingleInstanceGuard::drop` unlinks the lockfile before closing the file
        // handle, leaving a brief `STATUS_DELETE_PENDING` window reported as `PermissionDenied`.
        if err.kind() == io::ErrorKind::PermissionDenied {
            return true;
        }
    }
    false
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
            Err(err) if is_transient_lock_contention(&err) => {
                if err.kind() == io::ErrorKind::AddrInUse && try_signal_running_instance(state_dir)
                {
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

/// Acquire the single-instance lock during an elevated TUN relaunch handoff.
///
/// Unlike [`acquire_or_signal_instance`], this **never** signals the exiting non-elevated instance
/// and exits; instead it waits up to `timeout` for the previous instance to tear down its engine
/// and release `SingleInstanceGuard`.
pub fn acquire_instance_for_relaunch(
    state_dir: &Path,
    timeout: Duration,
) -> anyhow::Result<SingleInstanceGuard> {
    let deadline = Instant::now() + timeout;

    loop {
        match SingleInstanceGuard::acquire(state_dir) {
            Ok(guard) => return Ok(guard),
            Err(err) if is_transient_lock_contention(&err) => {
                let now = Instant::now();
                if now >= deadline {
                    return Err(anyhow::anyhow!(
                        "Timed out waiting for the previous RustClash Desktop instance to exit before elevated TUN handoff: {err}"
                    ));
                }
                let remaining = deadline.saturating_duration_since(now);
                std::thread::sleep(remaining.min(RELAUNCH_LOCK_POLL_INTERVAL));
            }
            Err(err) => {
                return Err(anyhow::anyhow!(
                    "Failed to acquire RustClash single-instance lock during elevated relaunch in '{}': {err}",
                    state_dir.display()
                ));
            }
        }
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

struct ShutdownDoneGuard {
    watch_tx: watch::Sender<bool>,
    sync_done: Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
}

impl Drop for ShutdownDoneGuard {
    fn drop(&mut self) {
        let (lock, cvar) = &*self.sync_done;
        {
            let mut done = lock.lock().unwrap_or_else(|e| e.into_inner());
            *done = true;
            cvar.notify_all();
        }
        let _ = self.watch_tx.send_replace(true);
    }
}

#[derive(Clone)]
pub struct DesktopAppState {
    pub engine: Arc<ProxyEngine>,
    pub api_addr: SocketAddr,
    state_dir: PathBuf,
    prefs: Arc<RwLock<DesktopPrefs>>,
    instance_guard: Arc<Mutex<Option<SingleInstanceGuard>>>,
    wakeup_server: Arc<Mutex<Option<DesktopWakeupServer>>>,
    relaunch_in_progress: Arc<AtomicBool>,
    shutdown_started: Arc<AtomicBool>,
    shutdown_done: watch::Sender<bool>,
    shutdown_done_sync: Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
    api_task: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
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
        Self::bootstrap_with_guard_options(state_dir, guard, DesktopLaunchOptions::default()).await
    }

    /// Hermetic production launcher rooted at an explicit `state_dir` with explicit launch options.
    pub async fn bootstrap_in_state_dir_with_options(
        state_dir: PathBuf,
        options: DesktopLaunchOptions,
    ) -> anyhow::Result<Self> {
        let guard = if options.relaunch_enable_tun {
            acquire_instance_for_relaunch(&state_dir, RELAUNCH_LOCK_TIMEOUT)?
        } else {
            let mut last_err: Option<io::Error> = None;
            let mut acquired: Option<SingleInstanceGuard> = None;
            for attempt in 0..INSTANCE_ACQUIRE_ATTEMPTS {
                match SingleInstanceGuard::acquire(&state_dir) {
                    Ok(g) => {
                        acquired = Some(g);
                        break;
                    }
                    Err(e) if is_transient_lock_contention(&e) => {
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
            match acquired {
                Some(g) => g,
                None => {
                    let detail = last_err
                        .map(|e| e.to_string())
                        .unwrap_or_else(|| "lock busy".to_string());
                    anyhow::bail!("RustClash Desktop is already running: {detail}");
                }
            }
        };
        Self::bootstrap_with_guard_options(state_dir, guard, options).await
    }

    async fn bootstrap_with_guard_options(
        state_dir: PathBuf,
        instance_guard: SingleInstanceGuard,
        options: DesktopLaunchOptions,
    ) -> anyhow::Result<Self> {
        let _ = recover_stale_network_state(&state_dir);
        let prefs = DesktopPrefs::load_from(&state_dir);

        let wakeup_srv = DesktopWakeupServer::bind_in_state_dir(&state_dir).ok();

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

        if options.relaunch_enable_tun {
            cfg.tun.enable = true;
            cfg.tun.auto_route = true;
        }

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

        cfg.ensure_ephemeral_secret();

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
                        let mut default_cfg = ClashConfig::default();
                        default_cfg.ensure_ephemeral_secret();
                        match ProxyEngine::start_with_state_dir(default_cfg, state_dir.clone())
                            .await
                        {
                            Ok(eng) => eng,
                            Err(_) => {
                                let mut emergency_cfg = ClashConfig {
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
                                emergency_cfg.ensure_ephemeral_secret();
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
        if options.preserve_sysproxy {
            let port = engine.mixed_addr().port();
            let host = resolve_sysproxy_connect_host(&engine.config_snapshot());
            if let Err(err) = enable_system_proxy(&host, port, &[], &state_dir) {
                startup_warnings.push(format!(
                    "Failed restoring OS System Proxy after elevated relaunch ({}).",
                    redact_sensitive_text(&err.to_string())
                ));
            }
        }
        for warn_msg in startup_warnings {
            tracing::warn!("{warn_msg}");
            engine.hub().push_log("warn", warn_msg);
        }

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (shutdown_done, _) = watch::channel(false);
        let shutdown_done_sync =
            Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
        let preferred_ctrl = engine.config_snapshot().external_controller;
        let (api_addr, api_task) =
            match spawn_api_server(&preferred_ctrl, Arc::clone(&engine), shutdown_rx.clone()).await
            {
                Ok(bound) => bound,
                Err(_) => spawn_api_server("127.0.0.1:0", Arc::clone(&engine), shutdown_rx).await?,
            };
        if let Err(err) = engine.publish_controller_discovery(state_dir.clone(), api_addr) {
            tracing::warn!("Failed writing runtime controller discovery file: {err}");
        }

        Ok(Self {
            engine,
            api_addr,
            state_dir,
            prefs: Arc::new(RwLock::new(prefs)),
            instance_guard: Arc::new(Mutex::new(Some(instance_guard))),
            wakeup_server: Arc::new(Mutex::new(wakeup_srv)),
            relaunch_in_progress: Arc::new(AtomicBool::new(false)),
            shutdown_started: Arc::new(AtomicBool::new(false)),
            shutdown_done,
            shutdown_done_sync,
            api_task: Arc::new(Mutex::new(Some(api_task))),
            _shutdown_tx: shutdown_tx,
        })
    }

    /// Optional self-contained Multi-Protocol Demo Sandbox launcher (`--demo` or `RUST_CLASH_DEMO=1`).
    pub async fn bootstrap_demo() -> anyhow::Result<Self> {
        let state_dir = default_state_dir();
        let guard = SingleInstanceGuard::acquire(&state_dir).ok();
        Self::bootstrap_demo_with_guard_options(
            state_dir,
            guard,
            DesktopLaunchOptions {
                use_demo: true,
                ..Default::default()
            },
        )
        .await
    }

    async fn bootstrap_demo_with_guard_options(
        state_dir: PathBuf,
        instance_guard: Option<SingleInstanceGuard>,
        options: DesktopLaunchOptions,
    ) -> anyhow::Result<Self> {
        let prefs = DesktopPrefs::load_from(&state_dir);
        let wakeup_srv = if instance_guard.is_some() {
            DesktopWakeupServer::bind_in_state_dir(&state_dir).ok()
        } else {
            None
        };

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
        if engine
            .config_snapshot()
            .secret
            .as_deref()
            .is_none_or(|s| s.trim().is_empty())
        {
            let mut demo_cfg = engine.config_snapshot();
            demo_cfg.ensure_ephemeral_secret();
            if let Ok(yaml) = demo_cfg.to_yaml_string() {
                let _ = engine.reload_yaml(&yaml).await;
            }
        }
        if let Ok(profile_mgr) = ProfileManager::open_or_init(&state_dir) {
            engine.attach_profile_manager(profile_mgr);
        }
        if options.relaunch_enable_tun
            && let Err(err) = engine.set_tun_active(true).await
        {
            tracing::warn!(
                "Failed auto-enabling System TUN after elevated demo relaunch: {}",
                redact_sensitive_text(&err.to_string())
            );
        }
        if options.preserve_sysproxy {
            let port = engine.mixed_addr().port();
            let host = resolve_sysproxy_connect_host(&engine.config_snapshot());
            if let Err(err) = enable_system_proxy(&host, port, &[], &state_dir) {
                tracing::warn!(
                    "Failed restoring OS System Proxy after elevated demo relaunch: {}",
                    redact_sensitive_text(&err.to_string())
                );
            }
        }
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (shutdown_done, _) = watch::channel(false);
        let shutdown_done_sync =
            Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
        let (api_addr, api_task) = match spawn_api_server(
            "127.0.0.1:9090",
            Arc::clone(&engine),
            shutdown_rx.clone(),
        )
        .await
        {
            Ok(bound) => bound,
            Err(_) => spawn_api_server("127.0.0.1:0", Arc::clone(&engine), shutdown_rx).await?,
        };
        if instance_guard.is_some()
            && let Err(err) = engine.publish_controller_discovery(state_dir.clone(), api_addr)
        {
            tracing::warn!("Failed writing runtime controller discovery file (demo): {err}");
        }
        Ok(Self {
            engine,
            api_addr,
            state_dir,
            prefs: Arc::new(RwLock::new(prefs)),
            instance_guard: Arc::new(Mutex::new(instance_guard)),
            wakeup_server: Arc::new(Mutex::new(wakeup_srv)),
            relaunch_in_progress: Arc::new(AtomicBool::new(false)),
            shutdown_started: Arc::new(AtomicBool::new(false)),
            shutdown_done,
            shutdown_done_sync,
            api_task: Arc::new(Mutex::new(Some(api_task))),
            _shutdown_tx: shutdown_tx,
        })
    }

    pub fn try_begin_elevated_relaunch(&self) -> bool {
        self.relaunch_in_progress
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    pub fn cancel_elevated_relaunch(&self) {
        self.relaunch_in_progress.store(false, Ordering::Release);
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
            api_base_url: format_http_base_url(self.api_addr),
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

    fn disable_sysproxy_if_enabled(&self) {
        if query_sysproxy_status(&self.state_dir).enabled {
            let _ = disable_system_proxy(&self.state_dir);
        }
        let engine_state_dir = self.engine.state_dir();
        if engine_state_dir != self.state_dir && query_sysproxy_status(&engine_state_dir).enabled {
            let _ = disable_system_proxy(&engine_state_dir);
        }
    }

    fn shutdown_done_guard(&self) -> ShutdownDoneGuard {
        ShutdownDoneGuard {
            watch_tx: self.shutdown_done.clone(),
            sync_done: Arc::clone(&self.shutdown_done_sync),
        }
    }

    fn wait_for_shutdown_done_sync(&self, timeout: Duration) {
        let (lock, cvar) = &*self.shutdown_done_sync;
        let guard = lock.lock().unwrap_or_else(|e| e.into_inner());
        if *guard {
            return;
        }
        let _ = cvar.wait_timeout_while(guard, timeout, |done| !*done);
    }

    /// Idempotently and asynchronously shuts down the wakeup IPC listener, embedded control API
    /// server, OS System Proxy, and `ProxyEngine` (awaiting complete closure of `tun`, `dns`, and
    /// `mixed` sockets), releasing `SingleInstanceGuard` **LAST** so a relaunched elevated instance
    /// never hits `AddrInUse` or loses its newly created `.ipc` file.
    ///
    /// Concurrent callers wait for the active shutdown to complete before returning so exit paths
    /// that immediately invoke `app.exit(0)` (e.g. `SIGTERM` or elevated relaunch) never terminate
    /// the process mid-teardown.
    pub async fn shutdown_async(&self) {
        if self.shutdown_started.swap(true, Ordering::AcqRel) {
            let mut rx = self.shutdown_done.subscribe();
            let _ = tokio::time::timeout(
                API_SHUTDOWN_TIMEOUT + Duration::from_secs(6),
                rx.wait_for(|&done| done),
            )
            .await;
            return;
        }
        let _done_guard = self.shutdown_done_guard();
        let wakeup_srv = self.wakeup_server.lock().take();
        if let Some(mut srv) = wakeup_srv {
            srv.stop();
        }
        let _ = self._shutdown_tx.send(true);
        let api_task = self.api_task.lock().take();
        if let Some(mut handle) = api_task
            && tokio::time::timeout(API_SHUTDOWN_TIMEOUT, &mut handle)
                .await
                .is_err()
        {
            handle.abort();
            let _ = tokio::time::timeout(Duration::from_millis(500), handle).await;
        }
        self.disable_sysproxy_if_enabled();
        self.engine.shutdown_async().await;
        let guard = self.instance_guard.lock().take();
        drop(guard);
        drop(_done_guard);
    }

    /// Idempotently shuts down the wakeup IPC listener, embedded control API server, `ProxyEngine`,
    /// OS TUN routes, OS System Proxy, and deterministically releases `SingleInstanceGuard` + `.ipc`
    /// BEFORE any `app_handle.exit(0)` (`std::process::exit`) call.
    ///
    /// Safe to invoke from synchronous callbacks (`RunEvent::Exit`, `WindowEvent::CloseRequested`,
    /// tray `quit`) both inside and outside a Tokio runtime: if another caller is actively running
    /// `shutdown_async()` or `shutdown()`, this waits for teardown completion before returning on
    /// non-Tokio OS threads and `MultiThread` Tokio runtimes (skipping the blocking wait only on
    /// `CurrentThread` runtimes to prevent single-thread deadlock); repeated calls after completion
    /// return immediately as strict no-ops.
    pub fn shutdown(&self) {
        if self.shutdown_started.swap(true, Ordering::AcqRel) {
            let wait_timeout = API_SHUTDOWN_TIMEOUT + Duration::from_secs(6);
            match tokio::runtime::Handle::try_current() {
                Err(_) => self.wait_for_shutdown_done_sync(wait_timeout),
                Ok(handle)
                    if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread =>
                {
                    tokio::task::block_in_place(|| self.wait_for_shutdown_done_sync(wait_timeout));
                }
                Ok(_) => {}
            }
            return;
        }
        let _done_guard = self.shutdown_done_guard();
        let wakeup_srv = self.wakeup_server.lock().take();
        if let Some(mut srv) = wakeup_srv {
            srv.stop();
        }
        let _ = self._shutdown_tx.send(true);
        if let Some(handle) = self.api_task.lock().take() {
            handle.abort();
        }
        self.disable_sysproxy_if_enabled();
        self.engine.shutdown();
        let guard = self.instance_guard.lock().take();
        drop(guard);
        drop(_done_guard);
    }
}

/// Validates `url` against SSRF rules (whitelisting only the active Demo Sandbox benchmark origin
/// when Demo mode is enabled) and probes latency for outbound `name`.
pub async fn probe_proxy_delay_for_engine(
    engine: &ProxyEngine,
    name: &str,
    url: Option<&str>,
) -> Result<u64, String> {
    let demo = engine.demo_info();
    let default_url = if demo.enabled && !demo.http_benchmark_origin.trim().is_empty() {
        format!(
            "{}/generate_204",
            demo.http_benchmark_origin.trim().trim_end_matches('/')
        )
    } else {
        "http://www.gstatic.com/generate_204".to_string()
    };
    let target_url = url
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(default_url.as_str());
    let allowed = proxy_core::api::demo_allowed_private_addrs(engine);
    proxy_core::probe::validate_probe_url(target_url, false, &allowed)
        .map_err(|e| redact_sensitive_text(&e.to_string()))?;
    engine
        .router()
        .test_delay_with_policy(name, target_url, Duration::from_secs(5), false, &allowed)
        .await
        .map_err(|e| redact_sensitive_text(&e.to_string()))
}

/// Result returned to the desktop UI when requesting an automatic UAC elevated relaunch for TUN.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ElevatedRelaunchOutcome {
    /// One of `"relaunching"`, `"cancelled"`, `"already_elevated"`, or `"unsupported"`.
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[cfg(any(windows, target_os = "macos", target_os = "linux"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ElevatedSpawnOutcome {
    Launched,
    Cancelled,
}

/// POSIX single-quote escaping (`'` -> `'\''`) for shell arguments passed to macOS `osascript`.
pub fn shell_single_quote(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len() + 2);
    out.push('\'');
    for ch in raw.chars() {
        if ch == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

/// Escape an arbitrary string for inclusion inside an AppleScript double-quoted string literal.
pub fn escape_applescript_string(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len() + 8);
    for ch in raw.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            other => out.push(other),
        }
    }
    out
}

/// Build an AppleScript snippet invoking `do shell script ... with administrator privileges`
/// that launches the elevated replacement process detached (`nohup ... &`) while preserving
/// `RUST_CLASH_STATE_DIR` so the root process shares the user's profiles, prefs, and lockfile.
pub fn build_macos_osascript_elevation_script(
    exe_path: &Path,
    state_dir: &Path,
    args: &[&str],
) -> String {
    let mut shell_parts = Vec::with_capacity(args.len() + 4);
    shell_parts.push("nohup".to_string());
    shell_parts.push("/usr/bin/env".to_string());
    shell_parts.push(shell_single_quote(&format!(
        "RUST_CLASH_STATE_DIR={}",
        state_dir.display()
    )));
    shell_parts.push(shell_single_quote(&exe_path.to_string_lossy()));
    for arg in args {
        shell_parts.push(shell_single_quote(arg));
    }
    let shell_cmd = format!("{} >/dev/null 2>&1 &", shell_parts.join(" "));
    format!(
        "do shell script \"{}\" with administrator privileges with prompt \"RustClash needs administrator privileges to enable System TUN.\"",
        escape_applescript_string(&shell_cmd)
    )
}

/// Detect macOS Authorization Services user cancellation from `osascript` stderr (`(-128)` / `User canceled`).
pub fn is_macos_osascript_cancelled(stderr: &str) -> bool {
    let low = stderr.to_ascii_lowercase();
    low.contains("(-128)") || low.contains("user canceled") || low.contains("user cancelled")
}

/// Whitelisted Linux desktop session environment variables forwarded across `pkexec` so the
/// elevated GUI window attaches cleanly to the user's X11 / Wayland display & D-Bus session.
pub const LINUX_GUI_ENV_ALLOWLIST: &[&str] = &[
    "DISPLAY",
    "WAYLAND_DISPLAY",
    "XAUTHORITY",
    "XDG_RUNTIME_DIR",
    "DBUS_SESSION_BUS_ADDRESS",
    "XDG_CURRENT_DESKTOP",
    "XDG_SESSION_TYPE",
    "GDK_BACKEND",
    "WEBKIT_DISABLE_DMABUF_RENDERER",
];

/// Build zero-interpolation argv for `pkexec` on Linux, launching the elevated GUI process
/// detached via `/bin/sh -c 'nohup "$@" >/dev/null 2>&1 &' _ /usr/bin/env ... <exe> <args...>`.
pub fn build_linux_pkexec_elevation_args(
    exe_path: &Path,
    state_dir: &Path,
    desktop_env: &[(String, String)],
    args: &[&str],
) -> Vec<String> {
    let mut out = Vec::with_capacity(desktop_env.len() + args.len() + 8);
    out.push("/bin/sh".to_string());
    out.push("-c".to_string());
    out.push("nohup \"$@\" >/dev/null 2>&1 &".to_string());
    out.push("_".to_string());
    out.push("/usr/bin/env".to_string());
    out.push(format!("RUST_CLASH_STATE_DIR={}", state_dir.display()));
    for (k, v) in desktop_env {
        if !k.is_empty() && !v.is_empty() && !k.contains('=') {
            out.push(format!("{k}={v}"));
        }
    }
    out.push(exe_path.to_string_lossy().into_owned());
    for arg in args {
        out.push((*arg).to_string());
    }
    out
}

/// Detect Polkit `pkexec` user cancellation (exit code `126`).
pub fn is_linux_pkexec_cancelled(exit_code: Option<i32>) -> bool {
    exit_code == Some(126)
}

#[cfg(target_os = "macos")]
fn spawn_elevated_relaunch_macos(
    exe_path: &Path,
    state_dir: &Path,
    args: &[&str],
) -> Result<ElevatedSpawnOutcome, String> {
    let script = build_macos_osascript_elevation_script(exe_path, state_dir, args);
    let out = std::process::Command::new("/usr/bin/osascript")
        .args(["-e", &script])
        .output()
        .map_err(|e| format!("Failed invoking macOS osascript elevation prompt: {e}"))?;
    if out.status.success() {
        return Ok(ElevatedSpawnOutcome::Launched);
    }
    let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
    if is_macos_osascript_cancelled(&stderr) {
        return Ok(ElevatedSpawnOutcome::Cancelled);
    }
    let detail = if stderr.is_empty() {
        format!("exit {}", out.status)
    } else {
        stderr
    };
    Err(format!("macOS administrator elevation failed: {detail}"))
}

#[cfg(target_os = "linux")]
fn resolve_pkexec_binary() -> Option<PathBuf> {
    for candidate in [
        "/usr/bin/pkexec",
        "/bin/pkexec",
        "/usr/local/bin/pkexec",
        "/run/current-system/sw/bin/pkexec",
    ] {
        let p = Path::new(candidate);
        if p.is_file() {
            return Some(p.to_path_buf());
        }
    }
    if let Some(paths) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&paths) {
            if dir.as_os_str().is_empty() {
                continue;
            }
            let p = dir.join("pkexec");
            if p.is_file() {
                return Some(p);
            }
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn has_linux_desktop_session_env() -> bool {
    std::env::var_os("DISPLAY").is_some_and(|v| !v.is_empty())
        || std::env::var_os("WAYLAND_DISPLAY").is_some_and(|v| !v.is_empty())
}

#[cfg(target_os = "linux")]
fn collect_linux_desktop_env() -> Vec<(String, String)> {
    let mut vars = Vec::new();
    for &key in LINUX_GUI_ENV_ALLOWLIST {
        if let Ok(val) = std::env::var(key)
            && !val.trim().is_empty()
        {
            vars.push((key.to_string(), val));
        }
    }
    vars
}

#[cfg(target_os = "linux")]
fn spawn_elevated_relaunch_linux(
    pkexec_bin: &Path,
    exe_path: &Path,
    state_dir: &Path,
    desktop_env: &[(String, String)],
    args: &[&str],
) -> Result<ElevatedSpawnOutcome, String> {
    let pk_args = build_linux_pkexec_elevation_args(exe_path, state_dir, desktop_env, args);
    let out = std::process::Command::new(pkexec_bin)
        .args(&pk_args)
        .output()
        .map_err(|e| format!("Failed invoking Polkit pkexec elevation prompt: {e}"))?;
    if out.status.success() {
        return Ok(ElevatedSpawnOutcome::Launched);
    }
    if is_linux_pkexec_cancelled(out.status.code()) {
        return Ok(ElevatedSpawnOutcome::Cancelled);
    }
    let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
    let detail = if stderr.is_empty() {
        format!("exit {}", out.status)
    } else {
        stderr
    };
    Err(format!("Linux Polkit elevation failed: {detail}"))
}

#[cfg(windows)]
fn to_wide_nul(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(windows)]
fn spawn_elevated_relaunch_windows(
    exe_path: &Path,
    args: &[&str],
) -> Result<ElevatedSpawnOutcome, String> {
    use windows_sys::Win32::{
        Foundation::{ERROR_CANCELLED, GetLastError},
        System::Com::{
            COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE, CoInitializeEx, CoUninitialize,
        },
        UI::{
            Shell::{SEE_MASK_FLAG_NO_UI, SHELLEXECUTEINFOW, ShellExecuteExW},
            WindowsAndMessaging::SW_SHOWNORMAL,
        },
    };

    struct ComInitGuard(bool);
    impl Drop for ComInitGuard {
        fn drop(&mut self) {
            if self.0 {
                // SAFETY: `CoUninitialize` is paired strictly with a preceding `CoInitializeEx`
                // call on the same dedicated OS thread that returned `S_OK` / `S_FALSE` (`hr >= 0`).
                unsafe { CoUninitialize() };
            }
        }
    }

    let clean_exe = strip_windows_verbatim_prefix(exe_path);
    let verb_w = to_wide_nul("runas");
    let file_w = to_wide_nul(&clean_exe.to_string_lossy());
    let params_joined = args.join(" ");
    let params_w = to_wide_nul(&params_joined);
    let dir_w = clean_exe
        .parent()
        .map(|p| to_wide_nul(&p.to_string_lossy()));

    // SAFETY: Initialize STA COM on this dedicated short-lived thread as recommended by MSDN
    // before invoking `ShellExecuteExW`; `ComInitGuard` balances `CoUninitialize` on return.
    let hr = unsafe {
        CoInitializeEx(
            std::ptr::null(),
            (COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE) as u32,
        )
    };
    let _com_guard = ComInitGuard(hr >= 0);

    // SAFETY: `SHELLEXECUTEINFOW` is zero-initialized with `cbSize` set to its exact size, and
    // all UTF-16 NUL-terminated string buffers (`verb_w`, `file_w`, `params_w`, `dir_w`) remain
    // pinned and live for the entire duration of `ShellExecuteExW`.
    let mut info: SHELLEXECUTEINFOW = unsafe { std::mem::zeroed() };
    info.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
    info.fMask = SEE_MASK_FLAG_NO_UI;
    info.lpVerb = verb_w.as_ptr();
    info.lpFile = file_w.as_ptr();
    info.lpParameters = if params_joined.is_empty() {
        std::ptr::null()
    } else {
        params_w.as_ptr()
    };
    info.lpDirectory = dir_w.as_ref().map_or(std::ptr::null(), |buf| buf.as_ptr());
    info.nShow = SW_SHOWNORMAL;

    let ok = unsafe { ShellExecuteExW(&mut info) };
    if ok != 0 {
        return Ok(ElevatedSpawnOutcome::Launched);
    }
    let err_code = unsafe { GetLastError() };
    if err_code == ERROR_CANCELLED {
        return Ok(ElevatedSpawnOutcome::Cancelled);
    }
    Err(format!(
        "Windows UAC elevation launch failed (Win32 error {err_code})"
    ))
}

/// Validates TUN driver/privilege preflight and triggers an OS-native administrator relaunch
/// (Windows UAC `ShellExecuteExW("runas")`, macOS `osascript ... with administrator privileges`,
/// or Linux desktop Polkit `pkexec`) of the current executable with `--relaunch-enable-tun`
/// (and optional `--preserve-sysproxy`).
///
/// Returns `(outcome, should_exit_current_instance)` where `should_exit_current_instance` is
/// `true` strictly for the single call that spawned the elevated replacement process.
pub async fn prepare_and_spawn_elevated_tun_relaunch(
    state: &DesktopAppState,
    preserve_sysproxy: Option<bool>,
) -> Result<(ElevatedRelaunchOutcome, bool), String> {
    let cfg = state.engine.config_snapshot();
    let pf = preflight_system_tun(cfg.tun.wintun_path.as_deref().map(Path::new));
    if pf.privilege_ok {
        return Ok((
            ElevatedRelaunchOutcome {
                status: "already_elevated".to_string(),
                message: None,
            },
            false,
        ));
    }
    if !pf.driver_loaded {
        return Err(pf
            .privilege_hint
            .unwrap_or_else(|| "System TUN driver is unavailable".to_string()));
    }

    #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
    {
        let _ = preserve_sysproxy;
        Ok((
            ElevatedRelaunchOutcome {
                status: "unsupported".to_string(),
                message: pf.privilege_hint,
            },
            false,
        ))
    }

    #[cfg(any(windows, target_os = "macos", target_os = "linux"))]
    {
        #[cfg(target_os = "linux")]
        let pkexec_bin = {
            if !has_linux_desktop_session_env() {
                return Ok((
                    ElevatedRelaunchOutcome {
                        status: "unsupported".to_string(),
                        message: pf.privilege_hint,
                    },
                    false,
                ));
            }
            let Some(bin) = resolve_pkexec_binary() else {
                return Ok((
                    ElevatedRelaunchOutcome {
                        status: "unsupported".to_string(),
                        message: pf.privilege_hint,
                    },
                    false,
                ));
            };
            bin
        };

        if !state.try_begin_elevated_relaunch() {
            return Ok((
                ElevatedRelaunchOutcome {
                    status: "relaunching".to_string(),
                    message: Some("Administrator relaunch is already in progress".to_string()),
                },
                false,
            ));
        }

        let keep_sysproxy = preserve_sysproxy
            .unwrap_or_else(|| query_sysproxy_status(&state.engine.state_dir()).enabled);
        let opts = DesktopLaunchOptions {
            use_demo: state.engine.demo_info().enabled,
            relaunch_enable_tun: true,
            preserve_sysproxy: keep_sysproxy,
        };
        let args = build_elevated_relaunch_args(&opts);
        let exe_path = match std::env::current_exe() {
            Ok(p) => p,
            Err(err) => {
                state.cancel_elevated_relaunch();
                return Err(format!("Failed resolving current executable path: {err}"));
            }
        };
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        let state_dir = state.engine.state_dir();
        #[cfg(target_os = "linux")]
        let desktop_env = collect_linux_desktop_env();

        let (tx, rx) = tokio::sync::oneshot::channel();
        let spawn_res = std::thread::Builder::new()
            .name("rc-elev-relaunch".to_string())
            .spawn(move || {
                #[cfg(windows)]
                let res = spawn_elevated_relaunch_windows(&exe_path, &args);
                #[cfg(target_os = "macos")]
                let res = spawn_elevated_relaunch_macos(&exe_path, &state_dir, &args);
                #[cfg(target_os = "linux")]
                let res = spawn_elevated_relaunch_linux(
                    &pkexec_bin,
                    &exe_path,
                    &state_dir,
                    &desktop_env,
                    &args,
                );
                let _ = tx.send(res);
            });
        if let Err(err) = spawn_res {
            state.cancel_elevated_relaunch();
            return Err(format!(
                "Failed starting administrator elevation worker thread: {err}"
            ));
        }

        match rx.await {
            Ok(Ok(ElevatedSpawnOutcome::Launched)) => Ok((
                ElevatedRelaunchOutcome {
                    status: "relaunching".to_string(),
                    message: None,
                },
                true,
            )),
            Ok(Ok(ElevatedSpawnOutcome::Cancelled)) => {
                state.cancel_elevated_relaunch();
                Ok((
                    ElevatedRelaunchOutcome {
                        status: "cancelled".to_string(),
                        message: None,
                    },
                    false,
                ))
            }
            Ok(Err(err)) => {
                state.cancel_elevated_relaunch();
                Err(err)
            }
            Err(_) => {
                state.cancel_elevated_relaunch();
                Err("Administrator elevation worker thread terminated unexpectedly".to_string())
            }
        }
    }
}

/// Unified desktop application entry point handling single-instance wakeup IPC (`rust-clash.desktop.ipc`),
/// close-then-immediately-reopen teardown retries, resilient engine bootstrap, and Tauri / headless execution.
pub fn run_desktop_app(rt: &tokio::runtime::Runtime, use_demo: bool) -> anyhow::Result<()> {
    run_desktop_app_with_options(
        rt,
        DesktopLaunchOptions {
            use_demo,
            ..Default::default()
        },
    )
}

/// Unified desktop application entry point with explicit [`DesktopLaunchOptions`] (including
/// elevated TUN relaunch handoff `--relaunch-enable-tun` and `--preserve-sysproxy`).
pub fn run_desktop_app_with_options(
    rt: &tokio::runtime::Runtime,
    options: DesktopLaunchOptions,
) -> anyhow::Result<()> {
    let state_dir = default_state_dir();
    let guard = if options.relaunch_enable_tun {
        acquire_instance_for_relaunch(&state_dir, RELAUNCH_LOCK_TIMEOUT)?
    } else {
        match acquire_or_signal_instance(&state_dir)? {
            InstanceAcquireOutcome::SignaledRunning => {
                tracing::info!(
                    "Signaled existing RustClash Desktop instance to restore main window; exiting launcher."
                );
                return Ok(());
            }
            InstanceAcquireOutcome::Acquired(guard) => guard,
        }
    };

    let state = if options.use_demo {
        rt.block_on(DesktopAppState::bootstrap_demo_with_guard_options(
            state_dir,
            Some(guard),
            options,
        ))?
    } else {
        rt.block_on(DesktopAppState::bootstrap_with_guard_options(
            state_dir, guard, options,
        ))?
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
        rt.block_on(wait_for_shutdown_signal());
        rt.block_on(state.shutdown_async());
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

    let state_dir = default_state_dir();
    let instance_guard = SingleInstanceGuard::acquire(&state_dir).map_err(|e| {
        if e.kind() == io::ErrorKind::AddrInUse {
            anyhow::anyhow!(
                "Another RustClash instance is currently running (state directory '{}'). Please close the running non-elevated RustClash instance before starting --elevated-tun-helper.",
                state_dir.display()
            )
        } else {
            anyhow::anyhow!(
                "failed to acquire RustClash single-instance lock in '{}': {e}",
                state_dir.display()
            )
        }
    })?;
    let _ = recover_stale_network_state(&state_dir);

    let generated_ephemeral = cfg.secret.as_deref().is_none_or(|s| s.trim().is_empty());
    cfg.ensure_ephemeral_secret();
    cfg.tun.enable = true;
    cfg.tun.auto_route = true;
    let engine = ProxyEngine::start_with_path(cfg, Some(canon)).await?;
    if let Ok(profile_mgr) = ProfileManager::open_or_init(&state_dir) {
        engine.attach_profile_manager(profile_mgr);
    }
    let ctrl_listen = engine.config_snapshot().external_controller;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (api_addr, mut api_task) =
        match spawn_api_server(&ctrl_listen, Arc::clone(&engine), shutdown_rx.clone()).await {
            Ok(bound) => bound,
            Err(_) => spawn_api_server("127.0.0.1:0", Arc::clone(&engine), shutdown_rx).await?,
        };
    if let Err(err) = engine.publish_controller_discovery(state_dir.clone(), api_addr) {
        tracing::warn!("Failed writing runtime controller discovery file (elevated helper): {err}");
    }
    let api_base_url = format_http_base_url(api_addr);
    tracing::info!(
        mixed_listen = %engine.mixed_addr(),
        api_base_url = %api_base_url,
        ephemeral_secret = generated_ephemeral,
        "RustClash elevated TUN helper listening (Bearer secret active; redacted from logs)"
    );

    wait_for_shutdown_signal().await;
    tracing::info!("Shutting down RustClash elevated TUN helper...");
    let _ = shutdown_tx.send(true);
    if tokio::time::timeout(API_SHUTDOWN_TIMEOUT, &mut api_task)
        .await
        .is_err()
    {
        api_task.abort();
        let _ = tokio::time::timeout(Duration::from_millis(500), api_task).await;
    }
    if query_sysproxy_status(&state_dir).enabled {
        let _ = disable_system_proxy(&state_dir);
    }
    engine.shutdown_async().await;
    drop(instance_guard);
    Ok(())
}

#[cfg(feature = "desktop")]
mod desktop_ipc {
    use super::*;
    use proxy_core::{
        config::RunMode,
        outbound::vless::encryption::{config::XorMode, generate_vless_encryption_pair},
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
        crate::probe_proxy_delay_for_engine(&state.engine, &name, url.as_deref()).await
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
            let host = resolve_sysproxy_connect_host(&state.engine.config_snapshot());
            enable_system_proxy(&host, port, &[], &state_dir)
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

    #[tauri::command(rename_all = "snake_case")]
    pub async fn relaunch_elevated_for_tun(
        app: tauri::AppHandle,
        state: State<'_, DesktopAppState>,
        preserve_sysproxy: Option<bool>,
    ) -> Result<ElevatedRelaunchOutcome, String> {
        let (outcome, should_exit) =
            prepare_and_spawn_elevated_tun_relaunch(state.inner(), preserve_sysproxy).await?;
        if should_exit {
            let exit_state = state.inner().clone();
            let exit_app = app.clone();
            tauri::async_runtime::spawn(async move {
                tokio::time::sleep(Duration::from_millis(120)).await;
                exit_state.shutdown_async().await;
                exit_app.exit(0);
            });
        }
        Ok(outcome)
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
                        let host = resolve_sysproxy_connect_host(&state.engine.config_snapshot());
                        enable_system_proxy(&host, port, &[], &dir)
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
                    let tray_state = state.clone();
                    let eng = Arc::clone(&state.engine);
                    let handle_clone = app_handle.clone();
                    let target = !eng.is_tun_active();
                    tauri::async_runtime::spawn(async move {
                        #[cfg(any(windows, target_os = "macos", target_os = "linux"))]
                        if target {
                            let cfg = eng.config_snapshot();
                            let pf =
                                preflight_system_tun(cfg.tun.wintun_path.as_deref().map(Path::new));
                            if pf.driver_loaded && !pf.privilege_ok {
                                match prepare_and_spawn_elevated_tun_relaunch(&tray_state, None)
                                    .await
                                {
                                    Ok((outcome, should_exit)) => {
                                        if should_exit {
                                            tokio::time::sleep(Duration::from_millis(120)).await;
                                            tray_state.shutdown_async().await;
                                            handle_clone.exit(0);
                                            return;
                                        } else if outcome.status == "cancelled"
                                            || outcome.status == "relaunching"
                                        {
                                            return;
                                        }
                                    }
                                    Err(err) => {
                                        report_tray_error(
                                            &handle_clone,
                                            &eng,
                                            "System TUN administrator relaunch failed",
                                            err,
                                        );
                                        return;
                                    }
                                }
                            }
                        }
                        #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
                        let _ = &tray_state;

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
        let build_err_state = app_state.clone();
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

                #[cfg(unix)]
                {
                    let sigterm_state = setup_state.clone();
                    let sigterm_handle = app.handle().clone();
                    tauri::async_runtime::spawn(async move {
                        match tokio::signal::unix::signal(
                            tokio::signal::unix::SignalKind::terminate(),
                        ) {
                            Ok(mut sigterm) => {
                                if sigterm.recv().await.is_some() {
                                    tracing::info!(
                                        "Received SIGTERM in Desktop GUI; tearing down TUN, DNS, and OS System Proxy before exit"
                                    );
                                    sigterm_state.shutdown_async().await;
                                    sigterm_handle.exit(0);
                                }
                            }
                            Err(err) => {
                                tracing::warn!(
                                    "Failed registering Desktop GUI SIGTERM listener: {err}"
                                );
                            }
                        }
                    });
                }

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
                relaunch_elevated_for_tun,
            ])
            .build(tauri::generate_context!())
            .map_err(move |e| {
                build_err_state.shutdown();
                anyhow::anyhow!("Tauri build error: {e}")
            })?;

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
        net::SocketAddr,
        path::PathBuf,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::{SystemTime, UNIX_EPOCH},
    };

    use proxy_core::{config::ClashConfig, platform::recovery::SingleInstanceGuard};

    use super::{
        DESKTOP_IPC_FILENAME, DESKTOP_PREFS_FILENAME, DesktopAppState, DesktopPrefs,
        DesktopWakeupServer, InstanceAcquireOutcome, acquire_or_signal_instance,
        format_http_base_url, parse_elevated_tun_helper_args, resolve_sysproxy_connect_host,
        try_signal_running_instance,
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
    fn wildcard_and_ipv6_controller_addrs_normalize_to_dialable_urls() {
        let v4_wild: SocketAddr = "0.0.0.0:9090".parse().unwrap();
        assert_eq!(format_http_base_url(v4_wild), "http://127.0.0.1:9090");

        let v6_wild: SocketAddr = "[::]:9090".parse().unwrap();
        assert_eq!(format_http_base_url(v6_wild), "http://127.0.0.1:9090");

        let v6_loopback: SocketAddr = "[::1]:9090".parse().unwrap();
        assert_eq!(format_http_base_url(v6_loopback), "http://[::1]:9090");

        let v4_lan: SocketAddr = "192.168.1.50:9095".parse().unwrap();
        assert_eq!(format_http_base_url(v4_lan), "http://192.168.1.50:9095");
    }

    #[test]
    fn sysproxy_connect_host_respects_allow_lan_and_bind_address() {
        let mut cfg = ClashConfig {
            allow_lan: false,
            bind_address: "127.0.0.1".to_string(),
            ..Default::default()
        };
        assert_eq!(resolve_sysproxy_connect_host(&cfg), "127.0.0.1");

        cfg.bind_address = "*".to_string();
        assert_eq!(resolve_sysproxy_connect_host(&cfg), "127.0.0.1");

        cfg.bind_address = "0.0.0.0".to_string();
        assert_eq!(resolve_sysproxy_connect_host(&cfg), "127.0.0.1");

        cfg.bind_address = "[::]".to_string();
        assert_eq!(resolve_sysproxy_connect_host(&cfg), "127.0.0.1");

        cfg.bind_address = "::1".to_string();
        assert_eq!(resolve_sysproxy_connect_host(&cfg), "::1");

        cfg.bind_address = "[::1]".to_string();
        assert_eq!(resolve_sysproxy_connect_host(&cfg), "::1");

        cfg.bind_address = "127.0.0.2".to_string();
        assert_eq!(resolve_sysproxy_connect_host(&cfg), "127.0.0.2");

        cfg.allow_lan = true;
        cfg.bind_address = "192.168.1.25".to_string();
        assert_eq!(resolve_sysproxy_connect_host(&cfg), "127.0.0.1");
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

        // Clean shutdown removes `.ipc` and releases `.lock` so immediate re-launch succeeds!
        server.stop();
        drop(guard);
        assert!(!temp_dir.join(DESKTOP_IPC_FILENAME).exists());
        #[cfg(not(unix))]
        assert!(!temp_dir.join("rust-clash.instance.lock").exists());
        #[cfg(unix)]
        assert!(temp_dir.join("rust-clash.instance.lock").exists());
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
        let expected_secret = state
            .status()
            .api_secret
            .clone()
            .expect("desktop bootstrap must populate ephemeral api_secret");
        assert!(
            expected_secret.len() == 64 && expected_secret.chars().all(|c| c.is_ascii_hexdigit()),
            "desktop bootstrap must populate a 256-bit ephemeral api_secret when config omits secret"
        );
        let disc = proxy_core::platform::recovery::read_controller_discovery(&temp_dir)
            .expect("desktop bootstrap must publish rust-clash.controller.json");
        assert_eq!(disc.pid, std::process::id());
        assert_eq!(disc.secret.as_deref(), Some(expected_secret.as_str()));
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
            !temp_dir
                .join(proxy_core::platform::recovery::CONTROLLER_DISCOVERY_FILENAME)
                .exists(),
            "shutdown() must remove rust-clash.controller.json"
        );
        #[cfg(not(unix))]
        assert!(
            !temp_dir.join("rust-clash.instance.lock").exists(),
            "shutdown() must drop SingleInstanceGuard before process exit"
        );
        #[cfg(unix)]
        assert!(
            temp_dir.join("rust-clash.instance.lock").exists(),
            "Unix SingleInstanceGuard keeps lockfile inode stable on drop to prevent flock races"
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
            recovered_state
                .status()
                .api_secret
                .as_deref()
                .is_some_and(|s| s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())),
            "fallback recovery bootstrap must also populate a 256-bit ephemeral api_secret"
        );
        assert!(
            !recovered_state.prefs().close_to_tray,
            "persisted close_to_tray=false must reload across restarts"
        );
        recovered_state.shutdown();

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn desktop_launch_options_parses_relaunch_flags_and_builds_allowlisted_args() {
        use super::{
            ARG_DEMO, ARG_PRESERVE_SYSPROXY, ARG_RELAUNCH_ENABLE_TUN, DesktopLaunchOptions,
            build_elevated_relaunch_args, parse_desktop_launch_options,
        };

        let parsed = parse_desktop_launch_options(
            [
                "--relaunch-enable-tun",
                "--preserve-sysproxy",
                "--ignored-extra-arg",
            ],
            false,
        );
        assert_eq!(
            parsed,
            DesktopLaunchOptions {
                use_demo: false,
                relaunch_enable_tun: true,
                preserve_sysproxy: true,
            }
        );
        assert_eq!(
            build_elevated_relaunch_args(&parsed),
            vec![ARG_RELAUNCH_ENABLE_TUN, ARG_PRESERVE_SYSPROXY]
        );

        let demo_parsed = parse_desktop_launch_options(["--relaunch-enable-tun"], true);
        assert!(demo_parsed.use_demo);
        assert_eq!(
            build_elevated_relaunch_args(&demo_parsed),
            vec![ARG_RELAUNCH_ENABLE_TUN, ARG_DEMO]
        );
    }

    #[test]
    fn strip_windows_verbatim_prefix_normalizes_drive_and_unc_paths() {
        use super::strip_windows_verbatim_prefix;
        use std::path::Path;

        assert_eq!(
            strip_windows_verbatim_prefix(Path::new(
                r"\\?\C:\Program Files\RustClash\rust-clash-desktop.exe"
            )),
            PathBuf::from(r"C:\Program Files\RustClash\rust-clash-desktop.exe")
        );
        assert_eq!(
            strip_windows_verbatim_prefix(Path::new(r"\\?\UNC\filesrv\share\rust-clash.exe")),
            PathBuf::from(r"\\filesrv\share\rust-clash.exe")
        );
        assert_eq!(
            strip_windows_verbatim_prefix(Path::new("/usr/local/bin/rust-clash-desktop")),
            PathBuf::from("/usr/local/bin/rust-clash-desktop")
        );
    }

    #[test]
    fn acquire_instance_for_relaunch_waits_for_old_instance_release_without_signaling() {
        use super::acquire_instance_for_relaunch;
        use std::time::Duration;

        let temp_dir = unique_temp_dir("relaunch-handoff");
        let guard = SingleInstanceGuard::acquire(&temp_dir).expect("acquire initial lock");
        let mut server =
            DesktopWakeupServer::bind_in_state_dir(&temp_dir).expect("bind wakeup server");
        let wakeups = Arc::new(AtomicUsize::new(0));
        let wakeups_cb = Arc::clone(&wakeups);
        server.register_callback(move || {
            wakeups_cb.fetch_add(1, Ordering::SeqCst);
        });

        let releaser = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(260));
            server.stop();
            drop(guard);
        });

        let acquired = acquire_instance_for_relaunch(&temp_dir, Duration::from_secs(3))
            .expect("relaunch handoff must wait for old instance and acquire lock");
        releaser.join().expect("join releaser thread");

        assert_eq!(
            wakeups.load(Ordering::SeqCst),
            0,
            "relaunch handoff must NEVER wake-and-exit against the shutting-down non-elevated instance"
        );
        drop(acquired);
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn acquire_instance_for_relaunch_times_out_cleanly_when_lock_stays_held() {
        use super::acquire_instance_for_relaunch;
        use std::time::Duration;

        let temp_dir = unique_temp_dir("relaunch-timeout");
        let _guard = SingleInstanceGuard::acquire(&temp_dir).expect("hold lock");

        let err = match acquire_instance_for_relaunch(&temp_dir, Duration::from_millis(180)) {
            Ok(_) => panic!("must time out cleanly if previous instance never releases lock"),
            Err(err) => err,
        };
        assert!(
            err.to_string().contains("Timed out waiting"),
            "unexpected timeout error: {err}"
        );
        drop(_guard);
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[tokio::test]
    async fn relaunch_enable_tun_without_privilege_safely_opens_in_userspace_mode() {
        use super::{DesktopLaunchOptions, prepare_and_spawn_elevated_tun_relaunch};

        let temp_dir = unique_temp_dir("relaunch-unpriv");
        let mgr = proxy_core::profile::ProfileManager::open_or_init(&temp_dir)
            .expect("init profile manager");
        fs::write(
            mgr.active_profile_path(),
            "mixed-port: 0\nexternal-controller: 127.0.0.1:0\ndns:\n  enable: true\n  listen: 127.0.0.1:0\ntun:\n  enable: false\nrules:\n  - MATCH,DIRECT\n",
        )
        .expect("write profile");
        drop(mgr);

        let state = DesktopAppState::bootstrap_in_state_dir_with_options(
            temp_dir.clone(),
            DesktopLaunchOptions {
                use_demo: false,
                relaunch_enable_tun: true,
                preserve_sysproxy: false,
            },
        )
        .await
        .expect("relaunch_enable_tun must never crash startup when unprivileged");

        assert!(state.try_begin_elevated_relaunch());
        assert!(!state.try_begin_elevated_relaunch());
        state.cancel_elevated_relaunch();
        assert!(state.try_begin_elevated_relaunch());
        state.cancel_elevated_relaunch();

        #[cfg(not(any(windows, target_os = "macos")))]
        {
            // On headless Linux CI (no DISPLAY / WAYLAND_DISPLAY and no CAP_NET_ADMIN), helper
            // returns `unsupported` or `already_elevated` cleanly without spawning pkexec.
            let res = prepare_and_spawn_elevated_tun_relaunch(&state, Some(false)).await;
            if let Ok((outcome, should_exit)) = res {
                assert!(!should_exit);
                assert!(
                    outcome.status == "unsupported" || outcome.status == "already_elevated",
                    "unexpected headless status: {:?}",
                    outcome
                );
            }
        }
        #[cfg(any(windows, target_os = "macos"))]
        {
            let _ = prepare_and_spawn_elevated_tun_relaunch;
        }

        state.shutdown();
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn macos_osascript_and_linux_pkexec_elevation_builders_escape_safely() {
        use super::{
            build_linux_pkexec_elevation_args, build_macos_osascript_elevation_script,
            is_linux_pkexec_cancelled, is_macos_osascript_cancelled,
        };

        let exe = PathBuf::from("/Applications/RustClash 'Beta' \"App\".app/Contents/MacOS/rc");
        let state_dir =
            PathBuf::from("/Users/alice o'brien/Library/Application Support/rust-clash");
        let script = build_macos_osascript_elevation_script(
            &exe,
            &state_dir,
            &["--relaunch-enable-tun", "--preserve-sysproxy"],
        );
        assert!(script.starts_with("do shell script \"nohup /usr/bin/env "));
        assert!(script.contains("with administrator privileges"));
        assert!(script.contains("RUST_CLASH_STATE_DIR="));
        assert!(script.contains("--relaunch-enable-tun"));
        assert!(script.contains("--preserve-sysproxy"));
        assert!(script.contains(">/dev/null 2>&1 &\""));
        // Single quotes and double quotes must be safely escaped for POSIX sh (`'\''`) then AppleScript (`'\\''`, `\"`)
        assert_eq!(super::shell_single_quote("a'b"), "'a'\\''b'");
        assert!(script.contains("'\\\\''"));
        assert!(script.contains("\\\"App\\\""));

        assert!(is_macos_osascript_cancelled(
            "execution error: User canceled. (-128)"
        ));
        assert!(is_macos_osascript_cancelled("User cancelled the dialog"));
        assert!(!is_macos_osascript_cancelled("permission denied"));

        let env_vars = vec![
            ("DISPLAY".to_string(), ":0".to_string()),
            ("XAUTHORITY".to_string(), "/run/user/1000/xauth".to_string()),
        ];
        let pk_args = build_linux_pkexec_elevation_args(
            std::path::Path::new("/opt/rust-clash/rust-clash-desktop"),
            std::path::Path::new("/home/alice/.config/rust-clash"),
            &env_vars,
            &["--relaunch-enable-tun"],
        );
        assert_eq!(pk_args[0], "/bin/sh");
        assert_eq!(pk_args[1], "-c");
        assert_eq!(pk_args[2], "nohup \"$@\" >/dev/null 2>&1 &");
        assert_eq!(pk_args[3], "_");
        assert_eq!(pk_args[4], "/usr/bin/env");
        assert_eq!(
            pk_args[5],
            "RUST_CLASH_STATE_DIR=/home/alice/.config/rust-clash"
        );
        assert!(pk_args.contains(&"DISPLAY=:0".to_string()));
        assert!(pk_args.contains(&"XAUTHORITY=/run/user/1000/xauth".to_string()));
        assert_eq!(
            pk_args[pk_args.len() - 2],
            "/opt/rust-clash/rust-clash-desktop"
        );
        assert_eq!(pk_args[pk_args.len() - 1], "--relaunch-enable-tun");

        assert!(is_linux_pkexec_cancelled(Some(126)));
        assert!(!is_linux_pkexec_cancelled(Some(127)));
        assert!(!is_linux_pkexec_cancelled(Some(0)));
        assert!(!is_linux_pkexec_cancelled(None));
    }

    fn assert_send_sync_clone_static<T: Send + Sync + Clone + 'static>() {}

    fn assert_future_send<F: std::future::Future + Send>(f: F) -> F {
        f
    }

    #[tokio::test]
    async fn double_shutdown_does_not_delete_new_instances_ipc_file() {
        assert_send_sync_clone_static::<DesktopAppState>();

        let temp_dir = unique_temp_dir("double-shutdown-ipc");
        let mgr = proxy_core::profile::ProfileManager::open_or_init(&temp_dir)
            .expect("init profile manager");
        fs::write(
            mgr.active_profile_path(),
            "mixed-port: 0\nexternal-controller: 127.0.0.1:0\ndns:\n  enable: true\n  listen: 127.0.0.1:0\ntun:\n  enable: false\nrules:\n  - MATCH,DIRECT\n",
        )
        .expect("write profile");
        drop(mgr);

        let state = DesktopAppState::bootstrap_in_state_dir(temp_dir.clone())
            .await
            .expect("bootstrap desktop state");
        let ipc_path = temp_dir.join(DESKTOP_IPC_FILENAME);
        assert!(ipc_path.exists(), "initial .ipc file must exist");
        assert!(try_signal_running_instance(&temp_dir));

        // First shutdown cleans up our own .ipc and releases SingleInstanceGuard.
        state.shutdown();
        assert!(
            !ipc_path.exists(),
            "first shutdown() must remove the old instance's .ipc file"
        );
        #[cfg(not(unix))]
        assert!(
            !temp_dir.join("rust-clash.instance.lock").exists(),
            "first shutdown() must release SingleInstanceGuard"
        );
        #[cfg(unix)]
        assert!(
            temp_dir.join("rust-clash.instance.lock").exists(),
            "Unix SingleInstanceGuard keeps lockfile inode stable on drop to prevent flock races"
        );

        // Simulate a newly launched elevated replacement instance acquiring the lock and
        // binding its own wakeup IPC server before the old process's RunEvent::Exit fires.
        let new_guard =
            SingleInstanceGuard::acquire(&temp_dir).expect("new instance acquires lock");
        let mut new_wakeup =
            DesktopWakeupServer::bind_in_state_dir(&temp_dir).expect("new instance binds .ipc");
        let new_ipc_contents = fs::read_to_string(&ipc_path).expect("read new .ipc contents");

        // Second sync shutdown (e.g., RunEvent::Exit) and a subsequent shutdown_async()
        // MUST be strict no-ops, return immediately without hanging, and MUST NOT delete or
        // alter the new instance's .ipc file.
        state.shutdown();
        let post_shutdown_start = std::time::Instant::now();
        assert_future_send(state.shutdown_async()).await;
        assert!(
            post_shutdown_start.elapsed() < std::time::Duration::from_secs(1),
            "repeat shutdown_async() after completed shutdown() must return immediately"
        );

        assert!(
            ipc_path.exists(),
            "second shutdown() must NOT delete a new instance's .ipc file"
        );
        assert_eq!(
            fs::read_to_string(&ipc_path).expect("read preserved .ipc"),
            new_ipc_contents,
            "new instance's .ipc payload must remain untouched"
        );
        assert!(
            try_signal_running_instance(&temp_dir),
            "new instance's wakeup IPC server must remain reachable"
        );
        assert_eq!(new_wakeup.wakeup_count(), 1);

        new_wakeup.stop();
        drop(new_guard);
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[tokio::test]
    async fn shutdown_async_releases_mixed_and_api_ports_before_dropping_instance_guard() {
        use super::acquire_instance_for_relaunch;
        use std::{net::TcpListener, time::Duration};

        let temp_dir = unique_temp_dir("shutdown-async-ports");
        let mgr = proxy_core::profile::ProfileManager::open_or_init(&temp_dir)
            .expect("init profile manager");
        fs::write(
            mgr.active_profile_path(),
            "mixed-port: 0\nexternal-controller: 127.0.0.1:0\ndns:\n  enable: true\n  listen: 127.0.0.1:0\ntun:\n  enable: false\nrules:\n  - MATCH,DIRECT\n",
        )
        .expect("write profile");
        drop(mgr);

        let state = DesktopAppState::bootstrap_in_state_dir(temp_dir.clone())
            .await
            .expect("bootstrap desktop state");
        let mixed_addr = state.engine.mixed_addr();
        let api_addr = state.api_addr;

        // Verify both ports and SingleInstanceGuard are actively held prior to shutdown_async().
        assert!(
            TcpListener::bind(mixed_addr).is_err(),
            "mixed_addr {mixed_addr} must be bound before shutdown_async"
        );
        assert!(
            TcpListener::bind(api_addr).is_err(),
            "api_addr {api_addr} must be bound before shutdown_async"
        );
        assert!(
            SingleInstanceGuard::acquire(&temp_dir).is_err(),
            "SingleInstanceGuard must be held before shutdown_async"
        );

        // Spawn a concurrent handoff waiter simulating the elevated relaunch process:
        // the instant `SingleInstanceGuard` becomes acquirable, BOTH `mixed_addr` and `api_addr`
        // must ALREADY be closed and immediately re-bindable with zero sleep!
        let handoff_dir = temp_dir.clone();
        let handoff_thread = std::thread::spawn(move || {
            let new_guard = acquire_instance_for_relaunch(&handoff_dir, Duration::from_secs(5))
                .expect("handoff process must acquire SingleInstanceGuard after shutdown_async");
            let rebound_mixed = TcpListener::bind(mixed_addr).unwrap_or_else(|err| {
                panic!(
                    "mixed port {mixed_addr} was still busy when SingleInstanceGuard dropped: {err}"
                )
            });
            let rebound_api = TcpListener::bind(api_addr).unwrap_or_else(|err| {
                panic!("api port {api_addr} was still busy when SingleInstanceGuard dropped: {err}")
            });
            drop(rebound_mixed);
            drop(rebound_api);
            let new_wakeup = DesktopWakeupServer::bind_in_state_dir(&handoff_dir)
                .expect("handoff process binds fresh wakeup ipc");
            (new_guard, new_wakeup)
        });

        assert_future_send(state.shutdown_async()).await;

        let (new_guard, mut new_wakeup) = handoff_thread.join().expect("join handoff thread");

        // Re-verify immediate re-binding on the exact mixed and api addresses succeeds cleanly.
        let direct_mixed = TcpListener::bind(mixed_addr)
            .expect("immediate TcpListener::bind on mixed_addr must succeed after shutdown_async");
        let direct_api = TcpListener::bind(api_addr)
            .expect("immediate TcpListener::bind on api_addr must succeed after shutdown_async");
        drop(direct_mixed);
        drop(direct_api);

        // A second shutdown_async() (and sync shutdown()) must be a strict idempotent no-op
        // that returns immediately and leaves the handoff instance's `.ipc` and lock intact.
        let ipc_path = temp_dir.join(DESKTOP_IPC_FILENAME);
        let ipc_before = fs::read_to_string(&ipc_path).expect("handoff .ipc exists");
        let repeat_start = std::time::Instant::now();
        state.shutdown_async().await;
        assert!(
            repeat_start.elapsed() < Duration::from_secs(1),
            "repeat shutdown_async() after completed shutdown_async() must return immediately"
        );
        state.shutdown();
        assert_eq!(
            fs::read_to_string(&ipc_path).expect("handoff .ipc still exists after 2nd shutdown"),
            ipc_before
        );
        assert!(try_signal_running_instance(&temp_dir));

        new_wakeup.stop();
        drop(new_guard);
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_shutdown_async_waits_for_active_shutdown_completion() {
        use std::{
            net::TcpListener,
            time::{Duration, Instant},
        };
        use tokio::io::AsyncWriteExt;

        assert_send_sync_clone_static::<DesktopAppState>();

        let temp_dir = unique_temp_dir("concurrent-shutdown-async");
        let mgr = proxy_core::profile::ProfileManager::open_or_init(&temp_dir)
            .expect("init profile manager");
        fs::write(
            mgr.active_profile_path(),
            "mixed-port: 0\nexternal-controller: 127.0.0.1:0\ndns:\n  enable: true\n  listen: 127.0.0.1:0\ntun:\n  enable: false\nrules:\n  - MATCH,DIRECT\n",
        )
        .expect("write profile");
        drop(mgr);

        let state = DesktopAppState::bootstrap_in_state_dir(temp_dir.clone())
            .await
            .expect("bootstrap desktop state");
        let mixed_addr = state.engine.mixed_addr();
        let api_addr = state.api_addr;
        let secret = state
            .status()
            .api_secret
            .clone()
            .expect("bootstrap populates api secret");

        // Hold an incomplete `PUT /configs` request open on `api_addr` so Caller #1's graceful
        // API server shutdown must wait up to `API_SHUTDOWN_TIMEOUT` before aborting and tearing
        // down `engine` + `SingleInstanceGuard`.
        let mut slow_client = tokio::net::TcpStream::connect(api_addr)
            .await
            .expect("connect to control api");
        let partial_req = format!(
            "PUT /configs HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {secret}\r\nContent-Type: application/json\r\nContent-Length: 1024\r\n\r\n{{\"payload\":"
        );
        slow_client
            .write_all(partial_req.as_bytes())
            .await
            .expect("send incomplete PUT /configs");
        slow_client.flush().await.expect("flush partial request");
        tokio::time::sleep(Duration::from_millis(50)).await;

        let state1 = state.clone();
        let caller1 = tokio::spawn(async move {
            let started = Instant::now();
            assert_future_send(state1.shutdown_async()).await;
            started.elapsed()
        });

        // Wait 150ms so Caller #1 is actively blocked inside `api_task` graceful shutdown.
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(
            SingleInstanceGuard::acquire(&temp_dir).is_err(),
            "SingleInstanceGuard must still be held while Caller #1 is mid-teardown"
        );

        let state2 = state.clone();
        let caller2_start = Instant::now();
        assert_future_send(state2.shutdown_async()).await;
        let caller2_elapsed = caller2_start.elapsed();

        assert!(
            caller2_elapsed >= Duration::from_secs(2),
            "Caller #2 returned prematurely in {caller2_elapsed:?} before Caller #1 finished shutdown"
        );

        // The instant Caller #2 returns, teardown MUST already be complete: SingleInstanceGuard
        // is released, `.ipc` is removed, and both `mixed_addr` and `api_addr` bind immediately
        // with zero AddrInUse.
        let rebound_guard = SingleInstanceGuard::acquire(&temp_dir)
            .expect("SingleInstanceGuard must already be released when Caller #2 returns");
        assert!(
            !temp_dir.join(DESKTOP_IPC_FILENAME).exists(),
            "desktop .ipc must already be removed when Caller #2 returns"
        );
        let rebound_mixed = TcpListener::bind(mixed_addr).unwrap_or_else(|err| {
            panic!("mixed_addr {mixed_addr} was still bound when Caller #2 returned: {err}")
        });
        let rebound_api = TcpListener::bind(api_addr).unwrap_or_else(|err| {
            panic!("api_addr {api_addr} was still bound when Caller #2 returned: {err}")
        });
        drop(rebound_mixed);
        drop(rebound_api);
        drop(rebound_guard);

        let caller1_elapsed = caller1.await.expect("join Caller #1");
        assert!(
            caller1_elapsed >= super::API_SHUTDOWN_TIMEOUT - Duration::from_millis(100),
            "expected Caller #1 to wait for API_SHUTDOWN_TIMEOUT, elapsed={caller1_elapsed:?}"
        );

        // A third shutdown_async() after teardown has completed must return immediately.
        let repeat_start = Instant::now();
        assert_future_send(state.shutdown_async()).await;
        assert!(
            repeat_start.elapsed() < Duration::from_secs(1),
            "post-completion shutdown_async() must return immediately"
        );

        drop(slow_client);
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn sync_shutdown_waits_for_active_shutdown_async_completion() {
        use std::{
            net::TcpListener,
            time::{Duration, Instant},
        };
        use tokio::io::AsyncWriteExt;

        assert_send_sync_clone_static::<DesktopAppState>();

        let temp_dir = unique_temp_dir("sync-waits-for-async-shutdown");
        let mgr = proxy_core::profile::ProfileManager::open_or_init(&temp_dir)
            .expect("init profile manager");
        fs::write(
            mgr.active_profile_path(),
            "mixed-port: 0\nexternal-controller: 127.0.0.1:0\ndns:\n  enable: true\n  listen: 127.0.0.1:0\ntun:\n  enable: false\nrules:\n  - MATCH,DIRECT\n",
        )
        .expect("write profile");
        drop(mgr);

        let state = DesktopAppState::bootstrap_in_state_dir(temp_dir.clone())
            .await
            .expect("bootstrap desktop state");
        let mixed_addr = state.engine.mixed_addr();
        let api_addr = state.api_addr;
        let secret = state
            .status()
            .api_secret
            .clone()
            .expect("bootstrap populates api secret");

        // Hold an incomplete `PUT /configs` request open on `api_addr` so Task #1's graceful
        // API server shutdown waits for `API_SHUTDOWN_TIMEOUT` before aborting and tearing down
        // `engine` + `SingleInstanceGuard`.
        let mut slow_client = tokio::net::TcpStream::connect(api_addr)
            .await
            .expect("connect to control api");
        let partial_req = format!(
            "PUT /configs HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {secret}\r\nContent-Type: application/json\r\nContent-Length: 1024\r\n\r\n{{\"payload\":"
        );
        slow_client
            .write_all(partial_req.as_bytes())
            .await
            .expect("send incomplete PUT /configs");
        slow_client.flush().await.expect("flush partial request");
        tokio::time::sleep(Duration::from_millis(50)).await;

        let state1 = state.clone();
        let caller1 = tokio::spawn(async move {
            let started = Instant::now();
            assert_future_send(state1.shutdown_async()).await;
            started.elapsed()
        });

        // Wait 150ms so Task #1 is actively blocked inside `api_task` graceful shutdown.
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(
            SingleInstanceGuard::acquire(&temp_dir).is_err(),
            "SingleInstanceGuard must still be held while Task #1 is mid-teardown"
        );

        // Spawn a non-Tokio OS thread (matching Tauri's main GUI thread for tray `"quit"` /
        // `CloseRequested`) calling synchronous `state.shutdown()`. The INSTANT it returns,
        // teardown MUST already be complete.
        let os_state = state.clone();
        let os_dir = temp_dir.clone();
        let os_thread = std::thread::spawn(move || {
            let started = Instant::now();
            os_state.shutdown();
            let elapsed = started.elapsed();

            assert!(
                elapsed >= Duration::from_secs(2),
                "OS thread sync shutdown() returned prematurely in {elapsed:?} before shutdown_async() finished"
            );
            let rebound_guard = SingleInstanceGuard::acquire(&os_dir).expect(
                "SingleInstanceGuard must already be released the instant sync shutdown() returns",
            );
            assert!(
                !os_dir.join(DESKTOP_IPC_FILENAME).exists(),
                "desktop .ipc must already be removed the instant sync shutdown() returns"
            );
            let rebound_mixed = TcpListener::bind(mixed_addr).unwrap_or_else(|err| {
                panic!(
                    "mixed_addr {mixed_addr} was still bound the instant sync shutdown() returned: {err}"
                )
            });
            let rebound_api = TcpListener::bind(api_addr).unwrap_or_else(|err| {
                panic!(
                    "api_addr {api_addr} was still bound the instant sync shutdown() returned: {err}"
                )
            });
            drop(rebound_mixed);
            drop(rebound_api);
            drop(rebound_guard);
            elapsed
        });

        // Also verify a MultiThread Tokio worker calling sync `shutdown()` blocks via
        // `block_in_place` until teardown finishes without starving Task #1.
        let mt_state = state.clone();
        let mt_caller = tokio::spawn(async move {
            let started = Instant::now();
            mt_state.shutdown();
            started.elapsed()
        });

        let os_elapsed = tokio::task::spawn_blocking(move || os_thread.join())
            .await
            .expect("join spawn_blocking")
            .expect("OS thread sync shutdown panicked");
        assert!(
            os_elapsed >= Duration::from_secs(2),
            "OS thread sync shutdown() elapsed too short: {os_elapsed:?}"
        );

        let mt_elapsed = mt_caller.await.expect("join MultiThread sync caller");
        assert!(
            mt_elapsed >= Duration::from_secs(2),
            "MultiThread Tokio sync shutdown() returned prematurely in {mt_elapsed:?}"
        );

        let caller1_elapsed = caller1.await.expect("join Task #1");
        assert!(
            caller1_elapsed >= super::API_SHUTDOWN_TIMEOUT - Duration::from_millis(100),
            "expected Task #1 to wait for API_SHUTDOWN_TIMEOUT, elapsed={caller1_elapsed:?}"
        );

        // Post-completion sync `shutdown()` on both a non-Tokio OS thread AND inside Tokio MUST
        // observe `done == true` and complete in `< 50ms`.
        let post_os_state = state.clone();
        let post_os_elapsed = tokio::task::spawn_blocking(move || {
            std::thread::spawn(move || {
                let started = Instant::now();
                post_os_state.shutdown();
                started.elapsed()
            })
            .join()
            .expect("post-completion OS thread panicked")
        })
        .await
        .expect("join post-completion OS check");
        assert!(
            post_os_elapsed < Duration::from_millis(50),
            "post-completion OS thread shutdown() took {post_os_elapsed:?} (expected < 50ms)"
        );

        let post_tokio_state = state.clone();
        let post_tokio_worker_elapsed = tokio::spawn(async move {
            let started = Instant::now();
            post_tokio_state.shutdown();
            started.elapsed()
        })
        .await
        .expect("join post-completion Tokio worker check");
        assert!(
            post_tokio_worker_elapsed < Duration::from_millis(50),
            "post-completion Tokio worker shutdown() took {post_tokio_worker_elapsed:?} (expected < 50ms)"
        );

        let post_direct_start = Instant::now();
        state.shutdown();
        let post_direct_elapsed = post_direct_start.elapsed();
        assert!(
            post_direct_elapsed < Duration::from_millis(50),
            "post-completion Tokio direct shutdown() took {post_direct_elapsed:?} (expected < 50ms)"
        );

        drop(slow_client);
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn sync_shutdown_on_current_thread_runtime_returns_immediately_without_deadlock() {
        use std::time::{Duration, Instant};
        use tokio::io::AsyncWriteExt;

        let temp_dir = unique_temp_dir("current-thread-sync-shutdown");
        let mgr = proxy_core::profile::ProfileManager::open_or_init(&temp_dir)
            .expect("init profile manager");
        fs::write(
            mgr.active_profile_path(),
            "mixed-port: 0\nexternal-controller: 127.0.0.1:0\ndns:\n  enable: true\n  listen: 127.0.0.1:0\ntun:\n  enable: false\nrules:\n  - MATCH,DIRECT\n",
        )
        .expect("write profile");
        drop(mgr);

        let state = DesktopAppState::bootstrap_in_state_dir(temp_dir.clone())
            .await
            .expect("bootstrap desktop state");
        let api_addr = state.api_addr;
        let secret = state
            .status()
            .api_secret
            .clone()
            .expect("bootstrap populates api secret");

        // Keep `api_task` open so `shutdown_async()` stays in-progress while we invoke sync
        // `shutdown()` on the same `CurrentThread` runtime.
        let mut slow_client = tokio::net::TcpStream::connect(api_addr)
            .await
            .expect("connect to control api");
        let partial_req = format!(
            "PUT /configs HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {secret}\r\nContent-Type: application/json\r\nContent-Length: 1024\r\n\r\n{{\"payload\":"
        );
        slow_client
            .write_all(partial_req.as_bytes())
            .await
            .expect("send incomplete PUT /configs");
        slow_client.flush().await.expect("flush partial request");
        tokio::time::sleep(Duration::from_millis(50)).await;

        let state1 = state.clone();
        let caller1 = tokio::spawn(async move {
            assert_future_send(state1.shutdown_async()).await;
        });

        // Yield so `caller1` sets `shutdown_started = true` and suspends waiting on `api_task`.
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(
            SingleInstanceGuard::acquire(&temp_dir).is_err(),
            "SingleInstanceGuard must still be held while CurrentThread shutdown_async() is active"
        );

        // Calling synchronous `state.shutdown()` on a `CurrentThread` runtime while
        // `shutdown_started` is already `true` MUST return immediately without blocking or
        // panicking so `caller1` on the single worker thread is never deadlocked.
        let started = Instant::now();
        state.shutdown();
        let elapsed = started.elapsed();
        assert!(
            elapsed < Duration::from_millis(50),
            "CurrentThread sync shutdown() blocked for {elapsed:?} (must return immediately without deadlock)"
        );

        // `caller1` must still complete cleanly once we yield back to the CurrentThread executor.
        caller1.await.expect("join CurrentThread shutdown_async");

        let reacquired = SingleInstanceGuard::acquire(&temp_dir).expect(
            "SingleInstanceGuard must be released after CurrentThread shutdown_async finishes",
        );
        assert!(!temp_dir.join(DESKTOP_IPC_FILENAME).exists());
        drop(reacquired);

        // Subsequent post-completion sync `shutdown()` on both CurrentThread and an OS thread
        // returns immediately.
        let post_ct_start = Instant::now();
        state.shutdown();
        assert!(
            post_ct_start.elapsed() < Duration::from_millis(50),
            "post-completion CurrentThread shutdown() must return immediately"
        );

        let post_os_state = state.clone();
        let post_os_elapsed = std::thread::spawn(move || {
            let started = Instant::now();
            post_os_state.shutdown();
            started.elapsed()
        })
        .join()
        .expect("join post-completion OS thread");
        assert!(
            post_os_elapsed < Duration::from_millis(50),
            "post-completion OS thread shutdown() took {post_os_elapsed:?} (expected < 50ms)"
        );

        drop(slow_client);
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[tokio::test]
    async fn probe_proxy_delay_for_engine_blocks_ssrf_and_invalid_urls() {
        use super::probe_proxy_delay_for_engine;

        let temp_dir = unique_temp_dir("probe-delay-ssrf");
        let cfg = ClashConfig::from_yaml_str(
            "mixed-port: 0\nexternal-controller: 127.0.0.1:0\ndns:\n  enable: true\n  listen: 127.0.0.1:0\ntun:\n  enable: false\nrules:\n  - MATCH,DIRECT\n",
        )
        .expect("parse minimal config");
        let engine = proxy_core::engine::ProxyEngine::start_with_state_dir(cfg, temp_dir.clone())
            .await
            .expect("start non-demo engine");

        let blocked_urls = [
            "http://127.0.0.1:80/",
            "http://localhost:80/",
            "http://169.254.169.254/latest/meta-data/",
            "http://10.0.0.1/",
            "http://[fd00:ec2::254]/",
            "http://[::127.0.0.1]/",
            "http://[::ffff:0:127.0.0.1]/",
            "http://0.1.2.3/",
            "ftp://example.com/",
            "http://user:pass@example.com/",
        ];
        for url in blocked_urls {
            let err = match assert_future_send(probe_proxy_delay_for_engine(
                &engine,
                "DIRECT",
                Some(url),
            ))
            .await
            {
                Ok(ms) => panic!("probe_proxy_delay_for_engine must reject {url}, got Ok({ms}ms)"),
                Err(err) => err,
            };
            let low = err.to_ascii_lowercase();
            assert!(
                low.contains("ssrf")
                    || low.contains("restricted")
                    || low.contains("blocked")
                    || low.contains("scheme")
                    || low.contains("userinfo"),
                "expected SSRF/validation error for {url}, got: {err}"
            );
            if url.contains("user:pass") {
                assert!(
                    !err.contains("user:pass"),
                    "error message must not echo URL credentials: {err}"
                );
            }
        }

        // Verify Demo Sandbox mode still allows its own whitelisted benchmark origin by default,
        // while still blocking arbitrary loopback/metadata targets and its own local DNS listener!
        engine
            .set_demo_sandbox(true)
            .await
            .expect("enable hermetic demo sandbox");

        let default_delay = probe_proxy_delay_for_engine(&engine, "DIRECT", None)
            .await
            .expect("demo default delay probe must succeed against whitelisted benchmark origin");
        assert!(
            default_delay < 5_000,
            "unexpected demo delay: {default_delay}ms"
        );

        let blank_delay = probe_proxy_delay_for_engine(&engine, "DIRECT", Some("   "))
            .await
            .expect("empty/whitespace URL must fall back to demo default URL");
        assert!(
            blank_delay < 5_000,
            "unexpected demo delay: {blank_delay}ms"
        );

        assert!(
            probe_proxy_delay_for_engine(&engine, "DIRECT", Some("http://127.0.0.1:80/"))
                .await
                .is_err(),
            "non-whitelisted localhost port must still be rejected in Demo mode"
        );
        assert!(
            probe_proxy_delay_for_engine(
                &engine,
                "DIRECT",
                Some("http://169.254.169.254/latest/meta-data/"),
            )
            .await
            .is_err(),
            "IMDS metadata IP must still be rejected in Demo mode"
        );
        let dns_addr = engine
            .dns_addr()
            .expect("demo engine must expose an active local DNS listener");
        let dns_url = format!("http://127.0.0.1:{}/", dns_addr.port());
        let dns_err = probe_proxy_delay_for_engine(&engine, "DIRECT", Some(&dns_url))
            .await
            .expect_err("Demo mode must NOT whitelist engine.dns_addr() for HTTP delay probing");
        let dns_low = dns_err.to_ascii_lowercase();
        assert!(
            dns_low.contains("ssrf")
                || dns_low.contains("restricted")
                || dns_low.contains("blocked"),
            "expected SSRF rejection for Demo DNS listener {dns_url}, got: {dns_err}"
        );

        engine.shutdown_async().await;
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn desktop_prefs_concurrent_save_to_stress_has_no_collisions_or_leftover_tmp_files() {
        use std::sync::Barrier;

        let temp_dir = unique_temp_dir("prefs-concurrent");
        let thread_count = 8usize;
        let saves_per_thread = 30usize;
        let barrier = Arc::new(Barrier::new(thread_count));

        let mut handles = Vec::with_capacity(thread_count);
        for tid in 0..thread_count {
            let dir = temp_dir.clone();
            let b = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                b.wait();
                for iter in 0..saves_per_thread {
                    let prefs = DesktopPrefs {
                        close_to_tray: (tid + iter).is_multiple_of(2),
                    };
                    prefs.save_to(&dir).unwrap_or_else(|err| {
                        panic!("thread {tid} iter {iter} DesktopPrefs::save_to failed: {err}")
                    });
                }
            }));
        }

        for h in handles {
            h.join().expect("concurrent save_to worker panicked");
        }

        let final_path = DesktopPrefs::path_in(&temp_dir);
        let raw = fs::read_to_string(&final_path).expect("read final desktop_prefs.json");
        let parsed: DesktopPrefs =
            serde_json::from_str(&raw).expect("final desktop_prefs.json must be valid JSON");
        assert_eq!(DesktopPrefs::load_from(&temp_dir), parsed);

        let leftovers: Vec<String> = fs::read_dir(&temp_dir)
            .expect("read temp state dir")
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|name| name.contains(".tmp."))
            .collect();
        assert!(
            leftovers.is_empty(),
            "expected zero leftover .tmp.* files after concurrent saves, found: {leftovers:?}"
        );

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn desktop_prefs_save_to_cleans_up_tmp_file_on_write_and_rename_errors() {
        use std::io::Write;

        // 1. Write/sync error must remove the temp file and leave prior valid prefs intact.
        let write_err_dir = unique_temp_dir("prefs-write-err");
        let initial = DesktopPrefs {
            close_to_tray: false,
        };
        initial
            .save_to(&write_err_dir)
            .expect("seed initial valid desktop_prefs.json");

        let write_err = DesktopPrefs::save_to_with_writer(&write_err_dir, |file| {
            file.write_all(b"{\"close_to_tray\":")?;
            Err(std::io::Error::other("simulated disk full"))
        })
        .expect_err("simulated write failure must return Err");
        assert!(write_err.to_string().contains("simulated disk full"));
        assert_eq!(
            DesktopPrefs::load_from(&write_err_dir),
            initial,
            "failed write must preserve previous valid desktop_prefs.json"
        );
        let write_leftovers: Vec<String> = fs::read_dir(&write_err_dir)
            .expect("read write_err_dir")
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|name| name.contains(".tmp."))
            .collect();
        assert!(
            write_leftovers.is_empty(),
            "failed write must not leave orphaned .tmp.* files: {write_leftovers:?}"
        );
        let _ = fs::remove_dir_all(&write_err_dir);

        // 2. Rename error (target path is an existing directory) must clean up the temp file.
        let rename_err_dir = unique_temp_dir("prefs-rename-err");
        let blocking_dir = DesktopPrefs::path_in(&rename_err_dir);
        fs::create_dir(&blocking_dir).expect("create blocking directory at desktop_prefs.json");

        let rename_err = DesktopPrefs {
            close_to_tray: true,
        }
        .save_to(&rename_err_dir)
        .expect_err("rename over existing directory must fail");
        let _ = rename_err;
        assert!(blocking_dir.is_dir());

        let rename_leftovers: Vec<String> = fs::read_dir(&rename_err_dir)
            .expect("read rename_err_dir")
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|name| name.contains(".tmp."))
            .collect();
        assert!(
            rename_leftovers.is_empty(),
            "failed rename must not leave orphaned .tmp.* files: {rename_leftovers:?}"
        );
        let _ = fs::remove_dir_all(&rename_err_dir);
    }

    #[tokio::test]
    async fn bootstrap_demo_without_instance_guard_preserves_existing_controller_discovery() {
        use super::DesktopLaunchOptions;
        use proxy_core::platform::recovery::{
            CONTROLLER_DISCOVERY_FILENAME, ControllerRuntimeEndpoint, read_controller_discovery,
            write_controller_discovery,
        };

        let temp_dir = unique_temp_dir("demo-no-guard-discovery");

        // Simulate a live non-demo daemon holding SingleInstanceGuard, wakeup IPC, and
        // `rust-clash.controller.json` in `state_dir`. Using our own PID makes the post-shutdown
        // assertion even stricter: an erroneous `cleanup_controller_discovery` call would match
        // our PID and delete the file.
        let live_guard =
            SingleInstanceGuard::acquire(&temp_dir).expect("live daemon acquires instance lock");
        let mut live_wakeup = DesktopWakeupServer::bind_in_state_dir(&temp_dir)
            .expect("live daemon binds wakeup ipc");
        let existing_live = ControllerRuntimeEndpoint {
            pid: std::process::id(),
            addr: "127.0.0.1:19090".to_string(),
            secret: Some("live-daemon-secret".to_string()),
        };
        write_controller_discovery(&temp_dir, &existing_live)
            .expect("seed pre-existing live daemon controller discovery");

        let discovery_path = temp_dir.join(CONTROLLER_DISCOVERY_FILENAME);
        let ipc_path = temp_dir.join(DESKTOP_IPC_FILENAME);
        let initial_discovery_bytes =
            fs::read(&discovery_path).expect("read seeded rust-clash.controller.json");
        let initial_ipc_bytes = fs::read(&ipc_path).expect("read seeded rust-clash.desktop.ipc");

        // Mirrors `DesktopAppState::bootstrap_demo()` non-fatal lock acquisition.
        assert!(
            SingleInstanceGuard::acquire(&temp_dir).ok().is_none(),
            "secondary lock acquisition must return None while live daemon holds SingleInstanceGuard"
        );

        let demo_state = DesktopAppState::bootstrap_demo_with_guard_options(
            temp_dir.clone(),
            None,
            DesktopLaunchOptions {
                use_demo: true,
                ..Default::default()
            },
        )
        .await
        .expect("co-located demo bootstrap without instance guard must succeed");

        assert!(demo_state.status().demo_mode);
        assert_eq!(
            fs::read(&discovery_path).expect("read controller discovery while demo is running"),
            initial_discovery_bytes,
            "co-located demo bootstrap must leave rust-clash.controller.json byte-for-byte identical while running"
        );
        assert_eq!(
            read_controller_discovery(&temp_dir),
            Some(existing_live.clone())
        );
        assert_eq!(
            fs::read(&ipc_path).expect("read wakeup ipc while demo is running"),
            initial_ipc_bytes,
            "co-located demo bootstrap must leave rust-clash.desktop.ipc byte-for-byte identical while running"
        );

        // Runtime discovery sync (e.g. YAML reload / secret rotation) must also be a no-op.
        demo_state.engine.sync_controller_discovery();
        assert_eq!(
            fs::read(&discovery_path).expect("read controller discovery after sync"),
            initial_discovery_bytes,
            "co-located demo sync_controller_discovery() must not overwrite rust-clash.controller.json"
        );

        // Synchronous `shutdown()` must leave the live daemon's discovery and IPC files untouched.
        demo_state.shutdown();
        assert!(
            discovery_path.exists(),
            "co-located demo shutdown() must not remove live daemon's rust-clash.controller.json"
        );
        assert_eq!(
            fs::read(&discovery_path).expect("read controller discovery after demo shutdown()"),
            initial_discovery_bytes,
            "co-located demo shutdown() must leave rust-clash.controller.json byte-for-byte identical"
        );
        assert_eq!(
            fs::read(&ipc_path).expect("read wakeup ipc after demo shutdown()"),
            initial_ipc_bytes,
            "co-located demo shutdown() must leave rust-clash.desktop.ipc byte-for-byte identical"
        );

        // Also verify `shutdown_async()` leaves the live daemon's discovery file byte-for-byte identical.
        let demo_state_async = DesktopAppState::bootstrap_demo_with_guard_options(
            temp_dir.clone(),
            None,
            DesktopLaunchOptions {
                use_demo: true,
                ..Default::default()
            },
        )
        .await
        .expect("second co-located demo bootstrap must succeed");
        assert_eq!(
            fs::read(&discovery_path).expect("read controller discovery while 2nd demo runs"),
            initial_discovery_bytes
        );
        demo_state_async.shutdown_async().await;
        assert_eq!(
            fs::read(&discovery_path)
                .expect("read controller discovery after demo shutdown_async()"),
            initial_discovery_bytes,
            "co-located demo shutdown_async() must leave rust-clash.controller.json byte-for-byte identical"
        );
        assert_eq!(read_controller_discovery(&temp_dir), Some(existing_live));

        live_wakeup.stop();
        drop(live_guard);
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[tokio::test]
    async fn bootstrap_demo_with_instance_guard_publishes_and_cleans_up_controller_discovery() {
        use super::DesktopLaunchOptions;
        use proxy_core::platform::recovery::{
            CONTROLLER_DISCOVERY_FILENAME, normalize_loopback_controller_addr,
            read_controller_discovery,
        };

        let temp_dir = unique_temp_dir("demo-with-guard-discovery");
        let guard = SingleInstanceGuard::acquire(&temp_dir)
            .expect("acquire single-instance guard for sole demo desktop instance");

        let demo_state = DesktopAppState::bootstrap_demo_with_guard_options(
            temp_dir.clone(),
            Some(guard),
            DesktopLaunchOptions {
                use_demo: true,
                ..Default::default()
            },
        )
        .await
        .expect("sole demo bootstrap with instance guard must succeed");

        let status = demo_state.status();
        assert!(status.demo_mode);
        let expected_secret = status
            .api_secret
            .clone()
            .expect("demo bootstrap must populate ephemeral api_secret");
        let expected_addr = normalize_loopback_controller_addr(demo_state.api_addr)
            .expect("demo api_addr must normalize to loopback");

        let disc = read_controller_discovery(&temp_dir)
            .expect("demo bootstrap with Some(guard) must publish rust-clash.controller.json");
        assert_eq!(disc.pid, std::process::id());
        assert_eq!(disc.addr, expected_addr);
        assert_eq!(disc.secret.as_deref(), Some(expected_secret.as_str()));
        assert!(
            temp_dir.join(DESKTOP_IPC_FILENAME).exists(),
            "demo bootstrap with Some(guard) must bind rust-clash.desktop.ipc"
        );

        demo_state.shutdown_async().await;
        assert!(
            !temp_dir.join(CONTROLLER_DISCOVERY_FILENAME).exists(),
            "demo shutdown must remove its own rust-clash.controller.json"
        );
        assert!(
            read_controller_discovery(&temp_dir).is_none(),
            "read_controller_discovery must return None after demo shutdown"
        );
        assert!(
            !temp_dir.join(DESKTOP_IPC_FILENAME).exists(),
            "demo shutdown must remove its own rust-clash.desktop.ipc"
        );

        let _ = fs::remove_dir_all(&temp_dir);
    }
}

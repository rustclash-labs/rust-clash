use std::{
    fs::{self, File, OpenOptions},
    io::{self, Seek, SeekFrom, Write},
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};

const JOURNAL_FILENAME: &str = "network_recovery.json";
const LOCK_FILENAME: &str = "rust-clash.instance.lock";
pub const CONTROLLER_DISCOVERY_FILENAME: &str = "rust-clash.controller.json";
const MAX_CONTROLLER_DISCOVERY_BYTES: u64 = 16 * 1024;
static DISCOVERY_TMP_SEQ: AtomicU64 = AtomicU64::new(1);

/// Resolve the persistent application state directory used for `network_recovery.json`,
/// single-instance PID lockfiles, and managed profiles.
/// Can be overridden via `RUST_CLASH_STATE_DIR` for hermetic testing.
pub fn default_state_dir() -> PathBuf {
    if let Ok(custom) = std::env::var("RUST_CLASH_STATE_DIR") {
        let trimmed = custom.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed);
        }
    }

    #[cfg(windows)]
    {
        if let Ok(local_app_data) = std::env::var("LOCALAPPDATA")
            && !local_app_data.trim().is_empty()
        {
            return PathBuf::from(local_app_data).join("rust-clash");
        }
    }

    #[cfg(target_os = "macos")]
    {
        if let Ok(home) = std::env::var("HOME")
            && !home.trim().is_empty()
        {
            return PathBuf::from(home)
                .join("Library")
                .join("Application Support")
                .join("rust-clash");
        }
    }

    if let Ok(xdg_state) = std::env::var("XDG_STATE_HOME")
        && !xdg_state.trim().is_empty()
    {
        return PathBuf::from(xdg_state).join("rust-clash");
    }
    if let Ok(home) = std::env::var("HOME")
        && !home.trim().is_empty()
    {
        return PathBuf::from(home)
            .join(".local")
            .join("state")
            .join("rust-clash");
    }

    std::env::temp_dir().join("rust-clash-state")
}

/// Owned Linux policy-routing & interface mutations recorded for crash recovery.
/// Only exact rules/routes created by `rust-clash` are stored — never shared tables as a whole.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxRecoveryRecord {
    pub device_name: String,
    pub route_table_id: u32,
    pub fwmark: u32,
    /// Exact `ip -4 rule del <args...>` argument vectors owned by `rust-clash`.
    pub owned_v4_rule_del_args: Vec<Vec<String>>,
    /// Exact `ip -6 rule del <args...>` argument vectors owned by `rust-clash`.
    pub owned_v6_rule_del_args: Vec<Vec<String>>,
    /// Exact `ip route del <args...>` argument vectors owned by `rust-clash` in `main` or `table <id>`.
    pub owned_route_del_args: Vec<Vec<String>>,
}

impl LinuxRecoveryRecord {
    pub fn is_empty(&self) -> bool {
        self.owned_v4_rule_del_args.is_empty()
            && self.owned_v6_rule_del_args.is_empty()
            && self.owned_route_del_args.is_empty()
            && self.device_name.is_empty()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacOsDnsBackup {
    pub service_name: String,
    /// Empty vector means DHCP-provided `"Empty"` DNS servers in `networksetup`.
    pub previous_servers: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacOsRecoveryRecord {
    pub utun_name: String,
    /// Exact `route -n delete ...` argument vectors added by `rust-clash`.
    pub owned_route_del_args: Vec<Vec<String>>,
    pub dns_backups: Vec<MacOsDnsBackup>,
}

impl MacOsRecoveryRecord {
    pub fn is_empty(&self) -> bool {
        self.owned_route_del_args.is_empty() && self.dns_backups.is_empty()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsRouteRecord {
    pub destination_prefix: String,
    pub prefix_length: u8,
    pub next_hop: String,
    pub interface_luid: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsDnsFamilySnapshot {
    /// Comma-separated DNS servers returned by `GetInterfaceDnsSettings`, or empty `""` for DHCP/none.
    pub name_server: String,
    #[serde(default)]
    pub domain: Option<String>,
    #[serde(default)]
    pub search_list: Option<String>,
}

const fn default_restore_ipv4_true() -> bool {
    true
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsDnsInterfaceBackup {
    pub interface_guid: String,
    pub ipv4: WindowsDnsFamilySnapshot,
    #[serde(default)]
    pub ipv6: Option<WindowsDnsFamilySnapshot>,
    /// Whether `ipv4` still needs restoration (`true` initially; cleared if IPv4 succeeded while IPv6 failed).
    #[serde(default = "default_restore_ipv4_true")]
    pub restore_ipv4: bool,
}

impl Default for WindowsDnsInterfaceBackup {
    fn default() -> Self {
        Self {
            interface_guid: String::new(),
            ipv4: WindowsDnsFamilySnapshot::default(),
            ipv6: None,
            restore_ipv4: true,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsRecoveryRecord {
    pub adapter_name: String,
    pub adapter_luid: u64,
    pub owned_routes: Vec<WindowsRouteRecord>,
    pub dns_interface_guid: Option<String>,
    /// `None` means no DNS change was made; `Some(vec![])` means restore to DHCP.
    pub previous_dns_servers: Option<Vec<String>>,
    /// Full pre-mutation IPv4 & IPv6 `GetInterfaceDnsSettings` snapshot for exact restoration.
    #[serde(default)]
    pub dns_backup: Option<WindowsDnsInterfaceBackup>,
}

impl WindowsRecoveryRecord {
    pub fn is_empty(&self) -> bool {
        let has_dns = self
            .dns_backup
            .as_ref()
            .is_some_and(|b| b.restore_ipv4 || b.ipv6.is_some())
            || self.previous_dns_servers.is_some();
        self.owned_routes.is_empty() && !has_dns
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxGnomeProtoBackup {
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub port: Option<u16>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxKdeProxyBackup {
    /// `6` for `kwriteconfig6`, `5` for `kwriteconfig5`.
    #[serde(default)]
    pub tool_generation: u8,
    #[serde(default)]
    pub proxy_type: Option<String>,
    #[serde(default)]
    pub http_proxy: Option<String>,
    #[serde(default)]
    pub https_proxy: Option<String>,
    #[serde(default)]
    pub socks_proxy: Option<String>,
    #[serde(default)]
    pub no_proxy_for: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SysProxyRecoveryRecord {
    pub platform: String,
    pub windows_proxy_enable: Option<u32>,
    pub windows_proxy_server: Option<String>,
    pub windows_proxy_override: Option<String>,
    #[serde(default)]
    pub macos_services: Vec<MacOsProxyServiceBackup>,
    pub linux_gnome_mode: Option<String>,
    #[serde(default)]
    pub linux_gnome_ignore_hosts: Option<String>,
    #[serde(default)]
    pub linux_gnome_http: Option<LinuxGnomeProtoBackup>,
    #[serde(default)]
    pub linux_gnome_https: Option<LinuxGnomeProtoBackup>,
    #[serde(default)]
    pub linux_gnome_socks: Option<LinuxGnomeProtoBackup>,
    #[serde(default)]
    pub linux_kde: Option<LinuxKdeProxyBackup>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacOsProxyServiceBackup {
    pub service_name: String,
    pub web_enabled: bool,
    pub web_host: String,
    pub web_port: u16,
    pub secure_web_enabled: bool,
    pub secure_web_host: String,
    pub secure_web_port: u16,
    pub socks_enabled: bool,
    pub socks_host: String,
    pub socks_port: u16,
    #[serde(default)]
    pub bypass_domains: Option<Vec<String>>,
}

/// Persistent crash-recovery journal written atomically BEFORE applying host network mutations
/// and cleared on graceful teardown.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryJournal {
    pub pid: u32,
    pub started_at_unix_ms: u64,
    pub platform: String,
    pub linux_tun: Option<LinuxRecoveryRecord>,
    pub macos_tun: Option<MacOsRecoveryRecord>,
    pub windows_tun: Option<WindowsRecoveryRecord>,
    pub sysproxy: Option<SysProxyRecoveryRecord>,
    /// Optional explicit owner PID for the TUN section when `sysproxy` and `tun` are managed by
    /// different concurrent `rust-clash` processes. Defaults to `self.pid` when `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tun_owner_pid: Option<u32>,
    /// Optional explicit owner PID for the `sysproxy` section when `sysproxy` and `tun` are
    /// managed by different concurrent `rust-clash` processes. Defaults to `self.pid` when `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sysproxy_owner_pid: Option<u32>,
}

impl RecoveryJournal {
    pub fn new_for_current_process() -> Self {
        Self::new_for_pid(std::process::id())
    }

    pub fn new_for_pid(pid: u32) -> Self {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        Self {
            pid,
            started_at_unix_ms: now_ms,
            platform: std::env::consts::OS.to_string(),
            linux_tun: None,
            macos_tun: None,
            windows_tun: None,
            sysproxy: None,
            tun_owner_pid: None,
            sysproxy_owner_pid: None,
        }
    }

    pub fn has_tun(&self) -> bool {
        self.linux_tun.is_some() || self.macos_tun.is_some() || self.windows_tun.is_some()
    }

    pub fn effective_tun_pid(&self) -> u32 {
        self.tun_owner_pid.unwrap_or(self.pid)
    }

    pub fn effective_sysproxy_pid(&self) -> u32 {
        self.sysproxy_owner_pid.unwrap_or(self.pid)
    }

    pub fn normalize_owner_pids(
        &mut self,
        tun_pid: Option<u32>,
        sysproxy_pid: Option<u32>,
        fallback_pid: u32,
    ) {
        let effective_tun = tun_pid.filter(|_| self.has_tun());
        let effective_sp = sysproxy_pid.filter(|_| self.sysproxy.is_some());
        self.pid = effective_tun.or(effective_sp).unwrap_or(fallback_pid);
        self.tun_owner_pid = effective_tun.filter(|&p| p != self.pid);
        self.sysproxy_owner_pid = effective_sp.filter(|&p| p != self.pid);
    }

    pub fn is_empty(&self) -> bool {
        !self.has_tun() && self.sysproxy.is_none()
    }

    pub fn path_in(state_dir: &Path) -> PathBuf {
        state_dir.join(JOURNAL_FILENAME)
    }

    pub fn load_from(state_dir: &Path) -> io::Result<Option<Self>> {
        let path = Self::path_in(state_dir);
        if !path.exists() {
            return Ok(None);
        }
        let raw = fs::read_to_string(&path)?;
        if raw.trim().is_empty() {
            return Ok(None);
        }
        let parsed: Self = serde_json::from_str(&raw).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("corrupt recovery journal '{}': {e}", path.display()),
            )
        })?;
        Ok(Some(parsed))
    }

    /// Persist atomically via `<dir>/network_recovery.json.tmp.<pid>.<nonce>` + `rename`.
    /// If the journal has no owned resources left, removes the journal file instead.
    pub fn save_atomic(&self, state_dir: &Path) -> io::Result<()> {
        use rand::RngCore;
        if self.is_empty() {
            return Self::remove_from(state_dir);
        }
        fs::create_dir_all(state_dir)?;
        let final_path = Self::path_in(state_dir);
        let nonce = rand::rng().next_u64();
        let tmp_path = state_dir.join(format!(
            "{JOURNAL_FILENAME}.tmp.{}.{nonce:016x}",
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
        if let Err(err) = fs::rename(&tmp_path, &final_path) {
            let _ = fs::remove_file(&tmp_path);
            return Err(err);
        }
        Ok(())
    }

    pub fn remove_from(state_dir: &Path) -> io::Result<()> {
        let path = Self::path_in(state_dir);
        match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }
}

static JOURNAL_MUTEX: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
const JOURNAL_LOCK_FILENAME: &str = "network_recovery.journal.lock";

fn acquire_journal_file_lock(state_dir: &Path) -> Option<File> {
    let _ = fs::create_dir_all(state_dir);
    let lock_path = state_dir.join(JOURNAL_LOCK_FILENAME);
    let mut opts = OpenOptions::new();
    opts.create(true).read(true).write(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        opts.share_mode(0x7);
    }
    let file = opts.open(lock_path).ok()?;
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        // SAFETY: Blocking `flock(LOCK_EX)` on valid open `file` fd serializes cross-process journal updates.
        let _ = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::{
            Storage::FileSystem::{LOCKFILE_EXCLUSIVE_LOCK, LockFileEx},
            System::IO::OVERLAPPED,
        };
        // SAFETY: Blocking `LockFileEx` with zeroed `OVERLAPPED` serializes cross-process journal updates;
        // the lock is automatically released when `file` is dropped.
        unsafe {
            let mut overlapped: OVERLAPPED = std::mem::zeroed();
            let _ = LockFileEx(
                file.as_raw_handle() as _,
                LOCKFILE_EXCLUSIVE_LOCK,
                0,
                1,
                0,
                &mut overlapped,
            );
        }
    }
    Some(file)
}

/// Update (or clear if empty) a section of the current process's `RecoveryJournal` in `state_dir`,
/// preserving any `tun` or `sysproxy` recovery entries owned by other processes.
pub fn update_current_journal<F>(state_dir: &Path, mutate: F) -> io::Result<()>
where
    F: FnOnce(&mut RecoveryJournal),
{
    update_journal_for_pid_with_liveness(state_dir, std::process::id(), is_pid_alive, mutate)
}

pub fn update_journal_for_pid_with_liveness<F, L>(
    state_dir: &Path,
    caller_pid: u32,
    is_alive: L,
    mutate: F,
) -> io::Result<()>
where
    F: FnOnce(&mut RecoveryJournal),
    L: Fn(u32) -> bool,
{
    let _mem_guard = JOURNAL_MUTEX.lock();
    let _file_guard = acquire_journal_file_lock(state_dir);

    let existing = RecoveryJournal::load_from(state_dir).ok().flatten();
    let mut journal = RecoveryJournal::new_for_pid(caller_pid);

    if let Some(ref ex) = existing {
        if ex.pid == caller_pid {
            journal.started_at_unix_ms = ex.started_at_unix_ms;
        }
        if ex.has_tun() && ex.effective_tun_pid() == caller_pid {
            journal.linux_tun = ex.linux_tun.clone();
            journal.macos_tun = ex.macos_tun.clone();
            journal.windows_tun = ex.windows_tun.clone();
        }
        if ex.sysproxy.is_some() && ex.effective_sysproxy_pid() == caller_pid {
            journal.sysproxy = ex.sysproxy.clone();
        }
    }

    mutate(&mut journal);

    let final_tun_pid = if journal.has_tun() {
        Some(caller_pid)
    } else if let Some(ref ex) = existing
        && ex.has_tun()
    {
        let ex_tun_pid = ex.effective_tun_pid();
        if ex_tun_pid != caller_pid {
            // Preserve foreign process's TUN record (especially when `is_alive(ex_tun_pid)` is true,
            // and also if a foreign process crashed and awaits `recover_stale_network_state`).
            let _ = is_alive(ex_tun_pid);
            journal.linux_tun = ex.linux_tun.clone();
            journal.macos_tun = ex.macos_tun.clone();
            journal.windows_tun = ex.windows_tun.clone();
            Some(ex_tun_pid)
        } else {
            None
        }
    } else {
        None
    };

    let final_sp_pid = if journal.sysproxy.is_some() {
        Some(caller_pid)
    } else if let Some(ref ex) = existing
        && ex.sysproxy.is_some()
    {
        let ex_sp_pid = ex.effective_sysproxy_pid();
        if ex_sp_pid != caller_pid {
            // Preserve foreign process's sysproxy backup unconditionally (both when `ex_sp_pid` is
            // alive and when a crashed/unrecovered foreign process awaits `recover_stale_network_state`).
            let _ = is_alive(ex_sp_pid);
            journal.sysproxy = ex.sysproxy.clone();
            Some(ex_sp_pid)
        } else {
            None
        }
    } else {
        None
    };

    journal.normalize_owner_pids(final_tun_pid, final_sp_pid, caller_pid);
    journal.save_atomic(state_dir)
}

/// Clear a stale/unowned `sysproxy` entry after `disable_system_proxy` has restored OS settings,
/// without touching any live or unrecovered `tun` entry in `network_recovery.json`.
pub(crate) fn clear_sysproxy_journal_entry(state_dir: &Path) -> io::Result<()> {
    let _mem_guard = JOURNAL_MUTEX.lock();
    let _file_guard = acquire_journal_file_lock(state_dir);
    let Some(mut journal) = RecoveryJournal::load_from(state_dir)? else {
        return Ok(());
    };
    let tun_pid = journal.has_tun().then(|| journal.effective_tun_pid());
    journal.sysproxy = None;
    journal.normalize_owner_pids(tun_pid, None, std::process::id());
    journal.save_atomic(state_dir)
}

fn finalize_tun_teardown_journal_inner<F>(
    state_dir: &Path,
    caller_pid: u32,
    apply_remaining: F,
) -> io::Result<()>
where
    F: FnOnce(&mut RecoveryJournal) -> bool,
{
    let _mem_guard = JOURNAL_MUTEX.lock();
    let _file_guard = acquire_journal_file_lock(state_dir);

    let existing = RecoveryJournal::load_from(state_dir).ok().flatten();
    let mut journal = RecoveryJournal::new_for_pid(caller_pid);
    if let Some(ref ex) = existing
        && ex.pid == caller_pid
    {
        journal.started_at_unix_ms = ex.started_at_unix_ms;
    }

    let has_unrecovered_tun = apply_remaining(&mut journal);
    let final_tun_pid = if has_unrecovered_tun {
        // Mark unrecovered TUN state with `pid = 0` (`!is_pid_alive(0)`) so `recover_stale_network_state`
        // retries restoring DNS/routes even while the current daemon stays running!
        Some(0)
    } else if let Some(ref ex) = existing
        && ex.has_tun()
    {
        let ex_tun_pid = ex.effective_tun_pid();
        if ex_tun_pid != caller_pid && ex_tun_pid != 0 {
            journal.linux_tun = ex.linux_tun.clone();
            journal.macos_tun = ex.macos_tun.clone();
            journal.windows_tun = ex.windows_tun.clone();
            Some(ex_tun_pid)
        } else {
            None
        }
    } else {
        None
    };

    let final_sp_pid = if let Some(ref ex) = existing
        && ex.sysproxy.is_some()
    {
        // Always preserve existing `sysproxy` entries during TUN teardown — whether owned by
        // `caller_pid`, a live foreign process, or a dead/unrecovered (`pid = 0`) foreign entry
        // awaiting `recover_stale_network_state`.
        let ex_sp_pid = ex.effective_sysproxy_pid();
        journal.sysproxy = ex.sysproxy.clone();
        Some(ex_sp_pid)
    } else {
        None
    };

    journal.normalize_owner_pids(final_tun_pid, final_sp_pid, caller_pid);
    journal.save_atomic(state_dir)
}

/// Update `network_recovery.json` after Linux TUN teardown (`stop()` or failed `start()`):
/// retains ONLY genuinely unrecovered policy rules/routes/interface (with `tun_owner_pid = 0`)
/// and clears the TUN journal entry when teardown succeeded cleanly.
pub fn finalize_linux_tun_teardown_journal(
    state_dir: &Path,
    remaining: Option<LinuxRecoveryRecord>,
) -> io::Result<()> {
    finalize_tun_teardown_journal_inner(state_dir, std::process::id(), |j| {
        if let Some(rem) = remaining.filter(|r| !r.is_empty()) {
            j.linux_tun = Some(rem);
            true
        } else {
            false
        }
    })
}

/// Update `network_recovery.json` after macOS TUN teardown (`stop()` or failed `start()`):
/// retains ONLY genuinely unrecovered routes/DNS backups (with `tun_owner_pid = 0`) and clears
/// the TUN journal entry when teardown succeeded cleanly.
pub fn finalize_macos_tun_teardown_journal(
    state_dir: &Path,
    remaining: Option<MacOsRecoveryRecord>,
) -> io::Result<()> {
    finalize_tun_teardown_journal_inner(state_dir, std::process::id(), |j| {
        if let Some(rem) = remaining.filter(|r| !r.is_empty()) {
            j.macos_tun = Some(rem);
            true
        } else {
            false
        }
    })
}

/// Update `network_recovery.json` after Windows Wintun teardown (`stop()` or failed `start()`):
/// retains ONLY genuinely unrecovered routes/DNS backups (with `tun_owner_pid = 0`) and clears
/// the TUN journal entry when teardown succeeded cleanly.
pub fn finalize_windows_tun_teardown_journal(
    state_dir: &Path,
    remaining: Option<WindowsRecoveryRecord>,
) -> io::Result<()> {
    finalize_tun_teardown_journal_inner(state_dir, std::process::id(), |j| {
        if let Some(rem) = remaining.filter(|r| !r.is_empty()) {
            j.windows_tun = Some(rem);
            true
        } else {
            false
        }
    })
}

/// Check whether OS process `pid` is currently alive.
pub fn is_pid_alive(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    if pid == std::process::id() {
        return true;
    }

    #[cfg(unix)]
    {
        // SAFETY: `kill(pid, 0)` performs a kernel existence/permission check without delivering any signal.
        let rc = unsafe { libc::kill(pid as libc::pid_t, 0) };
        if rc == 0 {
            return true;
        }
        let err = io::Error::last_os_error();
        err.raw_os_error() == Some(libc::EPERM)
    }

    #[cfg(windows)]
    {
        use windows_sys::Win32::{
            Foundation::{CloseHandle, STILL_ACTIVE},
            System::Threading::{
                GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
            },
        };
        // SAFETY: `OpenProcess` with `PROCESS_QUERY_LIMITED_INFORMATION` is read-only; handle is closed immediately.
        unsafe {
            let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if handle.is_null() {
                return false;
            }
            let mut code: u32 = 0;
            let ok = GetExitCodeProcess(handle, &mut code);
            let _ = CloseHandle(handle);
            ok != 0 && code == (STILL_ACTIVE as u32)
        }
    }

    #[cfg(not(any(unix, windows)))]
    {
        false
    }
}

/// Single-instance PID lockfile preventing concurrent `rust-clash` daemons from conflicting on
/// TUN adapters, routing tables, or OS system proxy settings.
pub struct SingleInstanceGuard {
    lock_path: PathBuf,
    _file: File,
}

impl SingleInstanceGuard {
    pub fn lock_path(&self) -> &Path {
        &self.lock_path
    }

    pub fn acquire(state_dir: &Path) -> io::Result<Self> {
        fs::create_dir_all(state_dir)?;
        let lock_path = state_dir.join(LOCK_FILENAME);

        #[cfg(unix)]
        {
            use std::os::{fd::AsRawFd, unix::fs::MetadataExt};

            const MAX_INODE_RETRIES: usize = 8;
            let mut acquired_file: Option<File> = None;

            for _attempt in 0..MAX_INODE_RETRIES {
                let file = OpenOptions::new()
                    .create(true)
                    .read(true)
                    .write(true)
                    .truncate(false)
                    .open(&lock_path)?;

                // SAFETY: `flock` with `LOCK_EX | LOCK_NB` on a valid open `File` fd is safe and non-blocking.
                let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
                if rc != 0 {
                    let err = io::Error::last_os_error();
                    if err.kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    let pid_note = fs::read_to_string(&lock_path)
                        .ok()
                        .and_then(|s| s.trim().parse::<u32>().ok())
                        .map(|pid| format!(" (PID {pid})"))
                        .unwrap_or_default();
                    return Err(io::Error::new(
                        io::ErrorKind::AddrInUse,
                        format!(
                            "another rust-clash instance{pid_note} holds exclusive lock '{}'",
                            lock_path.display()
                        ),
                    ));
                }

                // Verify that the locked descriptor still refers to the exact `(st_dev, st_ino)`
                // currently linked at `lock_path` so external deletion/replacement cannot split
                // two concurrent processes across different inodes.
                let fd_meta = file.metadata()?;
                match fs::metadata(&lock_path) {
                    Ok(path_meta)
                        if fd_meta.dev() == path_meta.dev() && fd_meta.ino() == path_meta.ino() =>
                    {
                        acquired_file = Some(file);
                        break;
                    }
                    Ok(_) => continue,
                    Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                    Err(e) => return Err(e),
                }
            }

            let mut file = acquired_file.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::AddrInUse,
                    format!(
                        "unable to stabilize exclusive lock inode for '{}' after {MAX_INODE_RETRIES} attempts",
                        lock_path.display()
                    ),
                )
            })?;

            file.set_len(0)?;
            Seek::seek(&mut file, SeekFrom::Start(0))?;
            writeln!(file, "{}", std::process::id())?;
            file.sync_all()?;

            Ok(Self {
                lock_path,
                _file: file,
            })
        }

        #[cfg(not(unix))]
        {
            #[cfg(not(windows))]
            {
                if let Ok(existing_raw) = fs::read_to_string(&lock_path)
                    && let Ok(existing_pid) = existing_raw.trim().parse::<u32>()
                    && existing_pid != std::process::id()
                    && is_pid_alive(existing_pid)
                {
                    return Err(io::Error::new(
                        io::ErrorKind::AddrInUse,
                        format!(
                            "another rust-clash instance (PID {existing_pid}) is already running (lock: '{}')",
                            lock_path.display()
                        ),
                    ));
                }
            }

            let mut open_opts = OpenOptions::new();
            open_opts
                .create(true)
                .read(true)
                .write(true)
                .truncate(false);
            #[cfg(windows)]
            {
                use std::os::windows::fs::OpenOptionsExt;
                // FILE_SHARE_READ (0x1) | FILE_SHARE_WRITE (0x2) | FILE_SHARE_DELETE (0x4) = 0x7
                open_opts.share_mode(0x7);
            }
            let mut file = open_opts.open(&lock_path)?;

            #[cfg(windows)]
            {
                use std::os::windows::io::AsRawHandle;
                use windows_sys::Win32::{
                    Storage::FileSystem::{
                        LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY, LockFileEx,
                    },
                    System::IO::OVERLAPPED,
                };
                // SAFETY: `LockFileEx` with `LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY` and a
                // zeroed `OVERLAPPED` on a valid open `File` handle is non-blocking; the Windows NT kernel
                // automatically releases the lock when the handle closes or the process terminates.
                let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
                let ok = unsafe {
                    LockFileEx(
                        file.as_raw_handle() as _,
                        LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
                        0,
                        1,
                        0,
                        &mut overlapped,
                    )
                };
                if ok == 0 {
                    let pid_note = fs::read_to_string(&lock_path)
                        .ok()
                        .and_then(|s| s.trim().parse::<u32>().ok())
                        .map(|pid| format!(" (PID {pid})"))
                        .unwrap_or_default();
                    return Err(io::Error::new(
                        io::ErrorKind::AddrInUse,
                        format!(
                            "another rust-clash instance{pid_note} holds exclusive lock '{}'",
                            lock_path.display()
                        ),
                    ));
                }
            }

            file.set_len(0)?;
            Seek::seek(&mut file, SeekFrom::Start(0))?;
            writeln!(file, "{}", std::process::id())?;
            file.sync_all()?;

            Ok(Self {
                lock_path,
                _file: file,
            })
        }
    }
}

impl Drop for SingleInstanceGuard {
    fn drop(&mut self) {
        // On Unix, `flock(2)` locks the underlying inode rather than the directory path.
        // Unlinking `lock_path` on drop would allow a racing process on the old unlinked inode
        // and a new process creating a fresh inode to both succeed in `LOCK_EX` simultaneously.
        // Dropping `self._file` releases the kernel `flock` atomically while keeping the inode stable.
        #[cfg(not(unix))]
        {
            let _ = fs::remove_file(&self.lock_path);
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct RecoveryOutcome {
    pub found_stale_journal: bool,
    pub stale_pid: Option<u32>,
    pub actions_executed: Vec<String>,
    pub warnings: Vec<String>,
}

/// Inspect `state_dir/network_recovery.json` on startup.
/// If a previous `rust-clash` PID exited uncleanly (`!is_pid_alive(journal.pid)`), clean up ONLY
/// the exact routes/rules/DNS/sysproxy recorded in that journal and remove the stale journal.
pub fn recover_stale_network_state(state_dir: &Path) -> RecoveryOutcome {
    recover_stale_network_state_with_runner(state_dir, &mut default_command_runner)
}

pub fn recover_stale_network_state_with_runner<F>(
    state_dir: &Path,
    run_cmd: &mut F,
) -> RecoveryOutcome
where
    F: FnMut(&str, &[String]) -> io::Result<()>,
{
    let mut outcome = RecoveryOutcome::default();
    let _mem_guard = JOURNAL_MUTEX.lock();
    let _file_guard = acquire_journal_file_lock(state_dir);

    let journal = match RecoveryJournal::load_from(state_dir) {
        Ok(Some(j)) => j,
        Ok(None) => return outcome,
        Err(e) => {
            outcome.warnings.push(e.to_string());
            return outcome;
        }
    };

    let tun_pid = journal.effective_tun_pid();
    let sp_pid = journal.effective_sysproxy_pid();
    let tun_stale = journal.has_tun() && !is_pid_alive(tun_pid);
    let sp_stale = journal.sysproxy.is_some() && !is_pid_alive(sp_pid);
    let empty_stale = journal.is_empty() && !is_pid_alive(journal.pid);

    if !tun_stale && !sp_stale && !empty_stale {
        // Every active section in this journal belongs to a live OS process — never touch its state!
        return outcome;
    }

    outcome.found_stale_journal = true;
    outcome.stale_pid = if tun_stale {
        Some(tun_pid)
    } else if sp_stale {
        Some(sp_pid)
    } else {
        Some(journal.pid)
    };

    let mut remaining_linux: Option<LinuxRecoveryRecord> = None;
    let mut remaining_macos: Option<MacOsRecoveryRecord> = None;
    let mut remaining_windows: Option<WindowsRecoveryRecord> = None;

    if tun_stale {
        if let Some(linux) = &journal.linux_tun {
            remaining_linux = crate::platform::tun::linux::rollback_linux_record_with_runner(
                linux,
                &mut outcome,
                run_cmd,
            );
        }

        if let Some(macos) = &journal.macos_tun {
            remaining_macos = crate::platform::tun::macos::rollback_macos_record_with_runner(
                macos,
                &mut outcome,
                run_cmd,
            );
        }

        if let Some(win) = &journal.windows_tun {
            #[cfg(windows)]
            {
                remaining_windows =
                    crate::platform::tun::windows::recover_windows_tun_record_pruning(
                        win,
                        &mut outcome,
                    );
            }
            #[cfg(not(windows))]
            {
                let target_guid = win
                    .dns_backup
                    .as_ref()
                    .map(|b| b.interface_guid.as_str())
                    .or(win.dns_interface_guid.as_deref());
                if let Some(guid) = target_guid {
                    let v4_servers: Option<Vec<String>> = if let Some(b) = &win.dns_backup {
                        b.restore_ipv4.then(|| {
                            b.ipv4
                                .name_server
                                .split([',', ' '])
                                .filter(|s| !s.is_empty())
                                .map(str::to_string)
                                .collect()
                        })
                    } else {
                        win.previous_dns_servers.clone()
                    };
                    if let Some(servers) = v4_servers {
                        let mut args = vec![
                            "interface".to_string(),
                            "ipv4".to_string(),
                            "set".to_string(),
                            "dnsservers".to_string(),
                            format!("name={guid}"),
                        ];
                        if servers.is_empty() {
                            args.push("source=dhcp".to_string());
                        } else {
                            args.push("source=static".to_string());
                            args.push(format!("address={}", servers[0]));
                        }
                        let desc = format!("netsh {}", args.join(" "));
                        match run_cmd("netsh", &args) {
                            Ok(()) => outcome.actions_executed.push(desc),
                            Err(e) => {
                                if !crate::platform::tun::windows::is_windows_benign_absent_error(
                                    &e,
                                ) {
                                    outcome.warnings.push(format!("{desc}: {e}"));
                                    remaining_windows = Some(win.clone());
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    let mut sp_recovered = false;
    if sp_stale && let Some(sp) = &journal.sysproxy {
        struct AdapterRunner<'a, F>(&'a mut F);
        impl<F> crate::platform::sysproxy::SysProxyCommandBackend for AdapterRunner<'_, F>
        where
            F: FnMut(&str, &[String]) -> io::Result<()>,
        {
            fn run_capture(&mut self, program: &str, args: &[String]) -> io::Result<String> {
                (self.0)(program, args)?;
                Ok(String::new())
            }
        }
        let mut adapter = AdapterRunner(run_cmd);
        match crate::platform::sysproxy::restore_sysproxy_record_with_runner_desc(sp, &mut adapter)
        {
            Ok(desc) => {
                outcome.actions_executed.push(desc);
                sp_recovered = true;
                let _ = fs::remove_file(state_dir.join("sysproxy_active.json"));
            }
            Err(e) => outcome
                .warnings
                .push(format!("sysproxy recovery failed: {e}")),
        }
    }

    // Preserve any remaining section owned by a still-live process AND any genuinely unrecovered
    // Linux / macOS / Windows TUN or sysproxy rollback items (`pid = 0` so future recovery retries
    // them); if none remain, `save_atomic` removes `network_recovery.json` cleanly.
    let mut survivor = journal;
    let keep_tun_pid = if tun_stale {
        survivor.linux_tun = remaining_linux.filter(|r| !r.is_empty());
        survivor.macos_tun = remaining_macos.filter(|r| !r.is_empty());
        survivor.windows_tun = remaining_windows.filter(|r| !r.is_empty());
        survivor.has_tun().then_some(0)
    } else {
        survivor.has_tun().then_some(tun_pid)
    };
    let keep_sp_pid = if sp_stale {
        if sp_recovered {
            survivor.sysproxy = None;
            None
        } else {
            survivor.sysproxy.is_some().then_some(0)
        }
    } else {
        survivor.sysproxy.is_some().then_some(sp_pid)
    };
    survivor.normalize_owner_pids(keep_tun_pid, keep_sp_pid, std::process::id());

    if let Err(e) = survivor.save_atomic(state_dir) {
        outcome
            .warnings
            .push(format!("failed updating/removing recovery journal: {e}"));
    }

    outcome
}

fn format_cmd_output_error(out: &std::process::Output) -> io::Error {
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let se = stderr.trim();
    let so = stdout.trim();
    let combined = match (se.is_empty(), so.is_empty()) {
        (false, false) => format!("{se}; {so}"),
        (false, true) => se.to_string(),
        (true, false) => so.to_string(),
        (true, true) => format!("exit status {}", out.status),
    };
    io::Error::other(combined)
}

fn default_command_runner(program: &str, args: &[String]) -> io::Result<()> {
    let candidates: &[&str] = match program {
        "ip" => &["/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip", "/bin/ip"],
        "route" => &["/sbin/route", "/usr/sbin/route"],
        "networksetup" => &["/usr/sbin/networksetup"],
        _ => &[],
    };
    let mut resolved = program;
    for &cand in candidates {
        if Path::new(cand).exists() {
            resolved = cand;
            break;
        }
    }
    let out = std::process::Command::new(resolved).args(args).output()?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format_cmd_output_error(&out))
    }
}

/// Runtime control-plane discovery metadata written to `state_dir/rust-clash.controller.json`
/// so local tools such as `rust-clash mcp` can auto-discover the bound loopback port and active
/// (potentially ephemeral) Bearer secret of a running desktop or CLI daemon.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControllerRuntimeEndpoint {
    pub pid: u32,
    pub addr: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,
}

fn canonical_discovery_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(v6)),
        IpAddr::V4(v4) => IpAddr::V4(v4),
    }
}

/// Normalize a bound API listener [`SocketAddr`] to a dialable loopback `host:port` string
/// suitable for local discovery. Returns `None` for explicit non-loopback LAN bind addresses
/// so discovery metadata is strictly restricted to loopback control planes.
pub fn normalize_loopback_controller_addr(addr: SocketAddr) -> Option<String> {
    if addr.port() == 0 {
        return None;
    }
    let ip = canonical_discovery_ip(addr.ip());
    if ip.is_unspecified() {
        return match ip {
            IpAddr::V4(_) => Some(format!("127.0.0.1:{}", addr.port())),
            IpAddr::V6(_) => Some(format!("[::1]:{}", addr.port())),
        };
    }
    if ip.is_loopback() {
        return match ip {
            IpAddr::V4(v4) => Some(format!("{v4}:{}", addr.port())),
            IpAddr::V6(v6) => Some(format!("[{v6}]:{}", addr.port())),
        };
    }
    None
}

/// Validate that a raw `host:port` string parses cleanly as a loopback [`SocketAddr`] with a non-zero port.
pub fn is_loopback_controller_addr(raw: &str) -> bool {
    let trimmed = raw.trim();
    let Ok(sock) = trimmed.parse::<SocketAddr>() else {
        return false;
    };
    sock.port() != 0 && canonical_discovery_ip(sock.ip()).is_loopback()
}

pub fn controller_discovery_path(state_dir: &Path) -> PathBuf {
    state_dir.join(CONTROLLER_DISCOVERY_FILENAME)
}

/// Atomically persist [`ControllerRuntimeEndpoint`] to `state_dir/rust-clash.controller.json`
/// with strict symlink checks, loopback-only validation, and Unix `0o600` file permissions.
pub fn write_controller_discovery(
    state_dir: &Path,
    endpoint: &ControllerRuntimeEndpoint,
) -> io::Result<()> {
    if state_dir.as_os_str().is_empty() {
        return Ok(());
    }
    if endpoint.pid == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "controller discovery pid must be non-zero",
        ));
    }
    if !is_loopback_controller_addr(&endpoint.addr) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "controller discovery addr must be a loopback host:port",
        ));
    }

    fs::create_dir_all(state_dir)?;
    let final_path = controller_discovery_path(state_dir);
    if let Ok(meta) = fs::symlink_metadata(&final_path)
        && meta.file_type().is_symlink()
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "refusing to overwrite symlink controller discovery file '{}'",
                final_path.display()
            ),
        ));
    }

    let normalized = ControllerRuntimeEndpoint {
        pid: endpoint.pid,
        addr: endpoint.addr.trim().to_string(),
        secret: endpoint
            .secret
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToString::to_string),
    };
    let serialized = serde_json::to_vec_pretty(&normalized).map_err(io::Error::other)?;

    let seq = DISCOVERY_TMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let tmp_path = state_dir.join(format!(
        "{CONTROLLER_DISCOVERY_FILENAME}.tmp.{}.{seq}",
        std::process::id()
    ));

    let write_res: io::Result<()> = (|| {
        let mut opts = OpenOptions::new();
        opts.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp_path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            f.set_permissions(fs::Permissions::from_mode(0o600))?;
        }
        f.write_all(&serialized)?;
        f.sync_all()?;
        Ok(())
    })();

    if let Err(err) = write_res {
        let _ = fs::remove_file(&tmp_path);
        return Err(err);
    }

    // Re-check destination symlink immediately prior to rename.
    if let Ok(meta) = fs::symlink_metadata(&final_path)
        && meta.file_type().is_symlink()
    {
        let _ = fs::remove_file(&tmp_path);
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "refusing to replace symlink controller discovery file '{}'",
                final_path.display()
            ),
        ));
    }

    if let Err(err) = fs::rename(&tmp_path, &final_path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(err);
    }
    Ok(())
}

/// Read and validate `state_dir/rust-clash.controller.json`, rejecting symlinks, non-files,
/// oversized payloads, or non-loopback target addresses.
pub fn read_controller_discovery(state_dir: &Path) -> Option<ControllerRuntimeEndpoint> {
    if state_dir.as_os_str().is_empty() {
        return None;
    }
    let path = controller_discovery_path(state_dir);
    let meta = fs::symlink_metadata(&path).ok()?;
    if meta.file_type().is_symlink()
        || !meta.file_type().is_file()
        || meta.len() == 0
        || meta.len() > MAX_CONTROLLER_DISCOVERY_BYTES
    {
        return None;
    }
    let raw = fs::read_to_string(&path).ok()?;
    let mut parsed: ControllerRuntimeEndpoint = serde_json::from_str(&raw).ok()?;
    if parsed.pid == 0 || !is_loopback_controller_addr(&parsed.addr) {
        return None;
    }
    parsed.addr = parsed.addr.trim().to_string();
    parsed.secret = parsed
        .secret
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string);
    Some(parsed)
}

/// Remove `state_dir/rust-clash.controller.json` strictly when it is a regular file whose
/// recorded `pid` matches `expected_pid`, avoiding races with a newly launched replacement daemon.
pub fn cleanup_controller_discovery(state_dir: &Path, expected_pid: u32) {
    if state_dir.as_os_str().is_empty() || expected_pid == 0 {
        return;
    }
    let path = controller_discovery_path(state_dir);
    let Ok(meta) = fs::symlink_metadata(&path) else {
        return;
    };
    if meta.file_type().is_symlink() || !meta.file_type().is_file() {
        return;
    }
    if let Some(ep) = read_controller_discovery(state_dir)
        && ep.pid == expected_pid
    {
        let _ = fs::remove_file(&path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stale_journal_executes_only_owned_cleanup_and_live_pid_is_untouched() {
        let dir = std::env::temp_dir().join(format!("rc-recovery-test-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();

        // 1. Journal owned by CURRENT live PID must NEVER be touched!
        let mut live_j = RecoveryJournal::new_for_current_process();
        live_j.linux_tun = Some(LinuxRecoveryRecord {
            device_name: "ClashTest0".into(),
            route_table_id: 20255,
            fwmark: 0x1a5,
            owned_v4_rule_del_args: vec![vec![
                "-4".into(),
                "rule".into(),
                "del".into(),
                "pref".into(),
                "9020".into(),
            ]],
            owned_v6_rule_del_args: vec![],
            owned_route_del_args: vec![],
        });
        live_j.save_atomic(&dir).unwrap();

        let mut recorded_cmds = Vec::new();
        let out_live = recover_stale_network_state_with_runner(&dir, &mut |prog, args| {
            recorded_cmds.push(format!("{prog} {}", args.join(" ")));
            Ok(())
        });
        assert!(!out_live.found_stale_journal);
        assert!(recorded_cmds.is_empty());
        assert!(RecoveryJournal::path_in(&dir).exists());

        // 2. Journal owned by a dead PID (`999_999_991`) MUST replay exact owned rules in reverse & clear file!
        let mut dead_j = live_j.clone();
        dead_j.pid = 999_999_991;
        dead_j.save_atomic(&dir).unwrap();

        let out_dead = recover_stale_network_state_with_runner(&dir, &mut |prog, args| {
            recorded_cmds.push(format!("{prog} {}", args.join(" ")));
            Ok(())
        });
        assert!(out_dead.found_stale_journal);
        assert_eq!(out_dead.stale_pid, Some(999_999_991));
        assert!(
            recorded_cmds
                .iter()
                .any(|c| c == "ip -4 rule del pref 9020")
        );
        assert!(
            recorded_cmds
                .iter()
                .any(|c| c == "ip link delete dev ClashTest0")
        );
        assert!(!RecoveryJournal::path_in(&dir).exists());

        // 3. SingleInstanceGuard prevents duplicate acquisition in the same directory
        let g1 = SingleInstanceGuard::acquire(&dir).expect("first lock");
        let g2_same_pid = SingleInstanceGuard::acquire(&dir);
        #[cfg(any(unix, windows))]
        assert!(
            g2_same_pid.is_err(),
            "OS file lock must reject second open handle even from same PID"
        );
        let _ = g2_same_pid;
        drop(g1);
        let g3 = SingleInstanceGuard::acquire(&dir).expect("reacquire after drop");
        drop(g3);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn foreign_live_pid_tun_and_sysproxy_entries_are_preserved_across_processes() {
        let dir = std::env::temp_dir().join(format!(
            "rc-recovery-multiproc-test-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&dir).unwrap();

        let daemon_pid = std::process::id();
        let demo_cli_pid = daemon_pid.wrapping_add(50_000);

        // 1. Live TUN daemon (`daemon_pid` == current process, genuinely alive via OS `is_pid_alive`)
        //    records its active TUN recovery entry.
        let tun_rec = LinuxRecoveryRecord {
            device_name: "ClashLive0".into(),
            route_table_id: 20260,
            fwmark: 0x1a5,
            owned_v4_rule_del_args: vec![vec![
                "-4".into(),
                "rule".into(),
                "del".into(),
                "pref".into(),
                "9020".into(),
            ]],
            owned_v6_rule_del_args: vec![],
            owned_route_del_args: vec![],
        };
        update_current_journal(&dir, |j| {
            j.linux_tun = Some(tun_rec.clone());
        })
        .unwrap();

        // 2. A second concurrent process (`demo_cli_pid`) enables and then disables System Proxy.
        //    Using real `is_pid_alive`, `daemon_pid` is alive so its `linux_tun` MUST NOT be clobbered!
        let sp_rec = SysProxyRecoveryRecord {
            platform: "linux".into(),
            linux_gnome_mode: Some("none".into()),
            ..Default::default()
        };
        update_journal_for_pid_with_liveness(&dir, demo_cli_pid, is_pid_alive, |j| {
            assert!(
                j.linux_tun.is_none(),
                "foreign process view must not expose daemon's TUN for mutation"
            );
            j.sysproxy = Some(sp_rec.clone());
        })
        .unwrap();

        let merged = RecoveryJournal::load_from(&dir).unwrap().unwrap();
        assert_eq!(merged.linux_tun.as_ref(), Some(&tun_rec));
        assert_eq!(merged.sysproxy.as_ref(), Some(&sp_rec));
        assert_eq!(merged.effective_tun_pid(), daemon_pid);
        assert_eq!(merged.effective_sysproxy_pid(), demo_cli_pid);

        // Foreign process disables its own System Proxy (`j.sysproxy = None`): live daemon's TUN remains!
        update_journal_for_pid_with_liveness(&dir, demo_cli_pid, is_pid_alive, |j| {
            j.sysproxy = None;
        })
        .unwrap();

        let after_sp_off = RecoveryJournal::load_from(&dir).unwrap().unwrap();
        assert_eq!(after_sp_off.linux_tun.as_ref(), Some(&tun_rec));
        assert!(after_sp_off.sysproxy.is_none());
        assert_eq!(after_sp_off.effective_tun_pid(), daemon_pid);

        // 3. Symmetrically, if `demo_cli_pid` is alive holding `sysproxy` while `daemon_pid` stops TUN,
        //    `demo_cli_pid`'s live `sysproxy` entry is preserved!
        let both_alive = |pid: u32| pid == daemon_pid || pid == demo_cli_pid;
        update_journal_for_pid_with_liveness(&dir, demo_cli_pid, both_alive, |j| {
            j.sysproxy = Some(sp_rec.clone());
        })
        .unwrap();
        update_journal_for_pid_with_liveness(&dir, daemon_pid, both_alive, |j| {
            j.linux_tun = None;
        })
        .unwrap();

        let after_tun_off = RecoveryJournal::load_from(&dir).unwrap().unwrap();
        assert!(after_tun_off.linux_tun.is_none());
        assert_eq!(after_tun_off.sysproxy.as_ref(), Some(&sp_rec));
        assert_eq!(after_tun_off.effective_sysproxy_pid(), demo_cli_pid);

        // 4. Selective crash recovery: `daemon_pid` (alive) holds `linux_tun` while a dead PID
        //    (`999_999_993`) crashed holding `sysproxy`. Only `sysproxy` is recovered; live TUN stays!
        let dead_sp_pid = 999_999_993u32;
        update_current_journal(&dir, |j| {
            j.linux_tun = Some(tun_rec.clone());
        })
        .unwrap();
        update_journal_for_pid_with_liveness(&dir, dead_sp_pid, is_pid_alive, |j| {
            j.sysproxy = Some(sp_rec.clone());
        })
        .unwrap();

        let mut cmds = Vec::new();
        let partial = recover_stale_network_state_with_runner(&dir, &mut |prog, args| {
            cmds.push(format!("{prog} {}", args.join(" ")));
            Ok(())
        });
        assert!(partial.found_stale_journal);
        assert_eq!(partial.stale_pid, Some(dead_sp_pid));
        assert!(
            cmds.iter().all(|c| !c.starts_with("ip ")),
            "must NOT tear down live daemon's TUN routes: {cmds:?}"
        );
        assert!(
            cmds.iter()
                .any(|c| c == "gsettings set org.gnome.system.proxy mode none")
        );

        let surviving = RecoveryJournal::load_from(&dir).unwrap().unwrap();
        assert_eq!(surviving.linux_tun.as_ref(), Some(&tun_rec));
        assert!(surviving.sysproxy.is_none());
        assert_eq!(surviving.effective_tun_pid(), daemon_pid);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn partial_macos_teardown_retains_stale_journal_until_retry_succeeds_while_preserving_live_sysproxy()
     {
        let dir =
            std::env::temp_dir().join(format!("rc-macos-partial-journal-{}", uuid::Uuid::new_v4()));
        let my_pid = std::process::id();

        let sp_rec = SysProxyRecoveryRecord {
            platform: "linux-gnome".to_string(),
            linux_gnome_mode: Some("none".to_string()),
            ..Default::default()
        };
        let full_macos = MacOsRecoveryRecord {
            utun_name: "utun9".to_string(),
            owned_route_del_args: vec![vec![
                "-n".to_string(),
                "delete".to_string(),
                "-net".to_string(),
                "0.0.0.0/1".to_string(),
                "-interface".to_string(),
                "utun9".to_string(),
            ]],
            dns_backups: vec![MacOsDnsBackup {
                service_name: "Wi-Fi".to_string(),
                previous_servers: Vec::new(),
            }],
        };

        // Active daemon owns both macOS TUN and system proxy.
        update_current_journal(&dir, |j| {
            j.macos_tun = Some(full_macos.clone());
            j.sysproxy = Some(sp_rec.clone());
        })
        .unwrap();

        // Normal `stop()` encounters a `networksetup` failure for Wi-Fi DNS while utun route was cleaned up:
        // `finalize_macos_tun_teardown_journal` MUST keep Wi-Fi DNS in `network_recovery.json` marked
        // with `effective_tun_pid() == 0` so `recover_stale_network_state` retries it even while `my_pid` lives!
        let remaining_dns_only = MacOsRecoveryRecord {
            utun_name: "utun9".to_string(),
            owned_route_del_args: Vec::new(),
            dns_backups: full_macos.dns_backups.clone(),
        };
        finalize_macos_tun_teardown_journal(&dir, Some(remaining_dns_only.clone())).unwrap();

        let after_stop = RecoveryJournal::load_from(&dir).unwrap().unwrap();
        assert_eq!(after_stop.macos_tun.as_ref(), Some(&remaining_dns_only));
        assert_eq!(
            after_stop.effective_tun_pid(),
            0,
            "unrecovered teardown state must use sentinel PID 0 so recovery runs even while daemon is alive"
        );
        assert_eq!(after_stop.sysproxy.as_ref(), Some(&sp_rec));
        assert_eq!(after_stop.effective_sysproxy_pid(), my_pid);

        // Retry #1: `networksetup` still fails -> journal MUST remain on disk with Wi-Fi DNS intact,
        // and live `sysproxy` owned by `my_pid` MUST NOT be touched!
        let fail_outcome = recover_stale_network_state_with_runner(&dir, &mut |prog, _args| {
            if prog == "networksetup" {
                Err(io::Error::other(
                    "authorization denied while setting DNS servers",
                ))
            } else {
                panic!("unexpected command during macOS DNS retry: {prog}");
            }
        });
        assert!(fail_outcome.found_stale_journal);
        assert_eq!(fail_outcome.warnings.len(), 1);
        let still_pending = RecoveryJournal::load_from(&dir).unwrap().unwrap();
        assert_eq!(still_pending.macos_tun.as_ref(), Some(&remaining_dns_only));
        assert_eq!(still_pending.sysproxy.as_ref(), Some(&sp_rec));

        // Retry #2: `networksetup` succeeds -> `macos_tun` is cleared while live `sysproxy` stays!
        let mut executed = Vec::new();
        let ok_outcome = recover_stale_network_state_with_runner(&dir, &mut |prog, args| {
            executed.push(format!("{prog} {}", args.join(" ")));
            Ok(())
        });
        assert!(ok_outcome.found_stale_journal);
        assert!(ok_outcome.warnings.is_empty());
        assert_eq!(executed, vec!["networksetup -setdnsservers Wi-Fi Empty"]);

        let after_retry = RecoveryJournal::load_from(&dir).unwrap().unwrap();
        assert!(after_retry.macos_tun.is_none());
        assert_eq!(after_retry.sysproxy.as_ref(), Some(&sp_rec));
        assert_eq!(after_retry.effective_sysproxy_pid(), my_pid);

        // Clearing live `sysproxy` now deletes `network_recovery.json` completely.
        update_current_journal(&dir, |j| {
            j.sysproxy = None;
        })
        .unwrap();
        assert!(RecoveryJournal::load_from(&dir).unwrap().is_none());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn controller_discovery_roundtrip_permissions_and_pid_guarded_cleanup() {
        let dir = std::env::temp_dir().join(format!("rc-ctrl-disc-{}", uuid::Uuid::new_v4()));
        let my_pid = std::process::id();
        let ep = ControllerRuntimeEndpoint {
            pid: my_pid,
            addr: normalize_loopback_controller_addr("0.0.0.0:19090".parse().unwrap()).unwrap(),
            secret: Some("ephemeral-secret-abc123".to_string()),
        };
        assert_eq!(ep.addr, "127.0.0.1:19090");
        assert_eq!(
            normalize_loopback_controller_addr("[::]:19091".parse().unwrap()).as_deref(),
            Some("[::1]:19091")
        );
        assert_eq!(
            normalize_loopback_controller_addr("192.168.1.50:9090".parse().unwrap()),
            None
        );

        write_controller_discovery(&dir, &ep).expect("write discovery");
        let path = controller_discovery_path(&dir);
        assert!(path.is_file());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::symlink_metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(
                mode, 0o600,
                "controller discovery file must be 0o600 on Unix"
            );
        }

        assert_eq!(read_controller_discovery(&dir), Some(ep.clone()));

        // Cleanup with a non-matching PID must preserve the newer instance's file
        cleanup_controller_discovery(&dir, my_pid.wrapping_add(9999).max(1));
        assert_eq!(read_controller_discovery(&dir), Some(ep));

        // Cleanup with matching PID removes the file cleanly
        cleanup_controller_discovery(&dir, my_pid);
        assert!(!path.exists());
        assert_eq!(read_controller_discovery(&dir), None);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn controller_discovery_rejects_non_loopback_and_symlinks() {
        let dir = std::env::temp_dir().join(format!("rc-ctrl-disc-sec-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();

        let bad_ep = ControllerRuntimeEndpoint {
            pid: std::process::id(),
            addr: "203.0.113.10:9090".to_string(),
            secret: Some("should-never-write".to_string()),
        };
        assert!(write_controller_discovery(&dir, &bad_ep).is_err());

        // Manually write a tampered non-loopback JSON file -> reader must reject it
        let path = controller_discovery_path(&dir);
        fs::write(
            &path,
            r#"{"pid":1234,"addr":"203.0.113.10:9090","secret":"stolen"}"#,
        )
        .unwrap();
        assert_eq!(read_controller_discovery(&dir), None);
        let _ = fs::remove_file(&path);

        #[cfg(unix)]
        {
            let target = dir.join("decoy.json");
            fs::write(
                &target,
                r#"{"pid":1234,"addr":"127.0.0.1:9090","secret":"decoy"}"#,
            )
            .unwrap();
            std::os::unix::fs::symlink(&target, &path).unwrap();

            assert_eq!(
                read_controller_discovery(&dir),
                None,
                "symlink discovery file must never be read"
            );
            let good_ep = ControllerRuntimeEndpoint {
                pid: std::process::id(),
                addr: "127.0.0.1:9090".to_string(),
                secret: Some("real-secret".to_string()),
            };
            assert!(
                write_controller_discovery(&dir, &good_ep).is_err(),
                "symlink discovery file must never be overwritten"
            );
            assert!(target.exists());
        }

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn stale_sysproxy_recovery_failure_retains_backup_with_sentinel_pid_zero_until_retry_succeeds()
    {
        for (label, sp_rec, expected_prog) in [
            (
                "gnome",
                SysProxyRecoveryRecord {
                    platform: "linux".into(),
                    linux_gnome_mode: Some("none".into()),
                    ..Default::default()
                },
                "gsettings",
            ),
            (
                "kde",
                SysProxyRecoveryRecord {
                    platform: "linux".into(),
                    linux_kde: Some(LinuxKdeProxyBackup {
                        tool_generation: 6,
                        proxy_type: Some("0".into()),
                        http_proxy: Some(String::new()),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
                "kwriteconfig6",
            ),
            (
                "macos",
                SysProxyRecoveryRecord {
                    platform: "macos".into(),
                    macos_services: vec![MacOsProxyServiceBackup {
                        service_name: "Wi-Fi".into(),
                        web_enabled: false,
                        web_host: String::new(),
                        web_port: 0,
                        secure_web_enabled: false,
                        secure_web_host: String::new(),
                        secure_web_port: 0,
                        socks_enabled: false,
                        socks_host: String::new(),
                        socks_port: 0,
                        bypass_domains: Some(vec![]),
                    }],
                    ..Default::default()
                },
                "networksetup",
            ),
        ] {
            let dir = std::env::temp_dir().join(format!(
                "rc-sp-fail-retain-{label}-{}",
                uuid::Uuid::new_v4()
            ));
            fs::create_dir_all(&dir).unwrap();

            let mut dead_j = RecoveryJournal::new_for_pid(999_999_992);
            dead_j.sysproxy = Some(sp_rec.clone());
            dead_j.save_atomic(&dir).unwrap();

            let meta_path = dir.join("sysproxy_active.json");
            fs::write(&meta_path, b"[\"127.0.0.1\",7890,[\"localhost\"]]").unwrap();

            // Attempt #1 fails -> journal & `sysproxy_active.json` MUST be preserved with PID 0!
            let fail_out = recover_stale_network_state_with_runner(&dir, &mut |prog, _args| {
                if prog == expected_prog {
                    Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        format!("{prog} failed transiently"),
                    ))
                } else {
                    Ok(())
                }
            });
            assert!(fail_out.found_stale_journal, "{label}: stale expected");
            assert!(
                !fail_out.warnings.is_empty(),
                "{label}: warning expected on failed sysproxy recovery"
            );
            assert!(
                meta_path.exists(),
                "{label}: sysproxy_active.json must NOT be deleted when recovery fails"
            );
            let retained = RecoveryJournal::load_from(&dir)
                .unwrap()
                .expect("recovery journal must remain on disk after failed sysproxy restore");
            assert_eq!(retained.sysproxy.as_ref(), Some(&sp_rec));
            assert_eq!(
                retained.effective_sysproxy_pid(),
                0,
                "{label}: failed sysproxy recovery must use sentinel PID 0"
            );

            // Attempt #2 succeeds -> both journal and `sysproxy_active.json` are removed cleanly!
            let ok_out = recover_stale_network_state_with_runner(&dir, &mut |_prog, _args| Ok(()));
            assert!(ok_out.found_stale_journal);
            assert!(ok_out.warnings.is_empty(), "{label}: {:?}", ok_out.warnings);
            assert!(
                !meta_path.exists(),
                "{label}: sysproxy_active.json must be deleted after recovery succeeds"
            );
            assert!(
                RecoveryJournal::load_from(&dir).unwrap().is_none(),
                "{label}: journal must be removed once recovery succeeds"
            );

            let _ = fs::remove_dir_all(&dir);
        }
    }

    #[test]
    fn stale_linux_tun_eperm_retains_unrecovered_items_with_pid_zero_and_prunes_benign_absent() {
        let dir = std::env::temp_dir().join(format!(
            "rc-linux-tun-eperm-retain-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&dir).unwrap();

        let rule_absent = vec![
            "-4".into(),
            "rule".into(),
            "del".into(),
            "pref".into(),
            "8990".into(),
            "to".into(),
            "1.2.3.4/32".into(),
            "lookup".into(),
            "main".into(),
        ];
        let rule_eperm_v4 = vec![
            "-4".into(),
            "rule".into(),
            "del".into(),
            "pref".into(),
            "9020".into(),
            "not".into(),
            "fwmark".into(),
            "0x1a5".into(),
            "lookup".into(),
            "20220".into(),
        ];
        let rule_eperm_v6 = vec![
            "-6".into(),
            "rule".into(),
            "del".into(),
            "pref".into(),
            "9020".into(),
            "not".into(),
            "fwmark".into(),
            "0x1a5".into(),
            "lookup".into(),
            "20220".into(),
        ];
        let route_absent = vec![
            "-4".into(),
            "route".into(),
            "del".into(),
            "default".into(),
            "dev".into(),
            "Clash0".into(),
            "table".into(),
            "20220".into(),
        ];

        let mut dead_j = RecoveryJournal::new_for_pid(999_999_994);
        dead_j.linux_tun = Some(LinuxRecoveryRecord {
            device_name: "Clash0".into(),
            route_table_id: 20220,
            fwmark: 0x1a5,
            owned_v4_rule_del_args: vec![rule_absent.clone(), rule_eperm_v4.clone()],
            owned_v6_rule_del_args: vec![rule_eperm_v6.clone()],
            owned_route_del_args: vec![route_absent.clone()],
        });
        dead_j.save_atomic(&dir).unwrap();

        // Non-root recovery: benign-absent items are pruned while EPERM items are retained with PID 0.
        let non_root_out = recover_stale_network_state_with_runner(&dir, &mut |prog, args| {
            assert_eq!(prog, "ip");
            let joined = args.join(" ");
            if joined.contains("pref 8990") {
                Err(io::Error::other(
                    "RTNETLINK answers: No such file or directory",
                ))
            } else if joined.contains("Clash0") {
                Err(io::Error::other("Cannot find device \"Clash0\""))
            } else {
                Err(io::Error::other(
                    "RTNETLINK answers: Operation not permitted",
                ))
            }
        });
        assert!(non_root_out.found_stale_journal);
        assert_eq!(non_root_out.warnings.len(), 2);

        let surviving = RecoveryJournal::load_from(&dir)
            .unwrap()
            .expect("journal must retain unrecovered EPERM Linux TUN rules");
        assert_eq!(surviving.effective_tun_pid(), 0);
        let rem = surviving.linux_tun.expect("remaining linux_tun");
        assert!(!rem.is_empty());
        assert!(
            rem.device_name.is_empty(),
            "absent device_name must be pruned"
        );
        assert!(
            rem.owned_route_del_args.is_empty(),
            "absent route must be pruned"
        );
        assert_eq!(rem.owned_v4_rule_del_args, vec![rule_eperm_v4.clone()]);
        assert_eq!(rem.owned_v6_rule_del_args, vec![rule_eperm_v6.clone()]);

        // Elevated retry succeeds and clears the journal completely.
        let mut retry_cmds = Vec::new();
        let retry_out = recover_stale_network_state_with_runner(&dir, &mut |prog, args| {
            retry_cmds.push(format!("{prog} {}", args.join(" ")));
            Ok(())
        });
        assert!(retry_out.found_stale_journal);
        assert!(retry_out.warnings.is_empty());
        assert_eq!(retry_cmds.len(), 2);
        assert!(RecoveryJournal::load_from(&dir).unwrap().is_none());

        // `finalize_linux_tun_teardown_journal` retains unrecovered items with sentinel PID 0,
        // and removes the journal when passed `None` or an empty `LinuxRecoveryRecord`.
        let partial_rem = LinuxRecoveryRecord {
            device_name: String::new(),
            route_table_id: 20220,
            fwmark: 0x1a5,
            owned_v4_rule_del_args: vec![rule_eperm_v4],
            owned_v6_rule_del_args: Vec::new(),
            owned_route_del_args: Vec::new(),
        };
        finalize_linux_tun_teardown_journal(&dir, Some(partial_rem.clone())).unwrap();
        let after_partial = RecoveryJournal::load_from(&dir).unwrap().unwrap();
        assert_eq!(after_partial.linux_tun.as_ref(), Some(&partial_rem));
        assert_eq!(after_partial.effective_tun_pid(), 0);

        finalize_linux_tun_teardown_journal(&dir, Some(LinuxRecoveryRecord::default())).unwrap();
        assert!(RecoveryJournal::load_from(&dir).unwrap().is_none());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn foreign_dead_and_sentinel_sysproxy_preserved_across_journal_update_and_tun_teardown() {
        let dir = std::env::temp_dir().join(format!(
            "rc-foreign-dead-sp-preserve-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&dir).unwrap();

        let my_pid = std::process::id();
        let dead_foreign_pid = 999_999_995u32;
        let sp_rec = SysProxyRecoveryRecord {
            platform: "linux".into(),
            linux_gnome_mode: Some("none".into()),
            ..Default::default()
        };
        let tun_rec = LinuxRecoveryRecord {
            device_name: "Clash0".into(),
            route_table_id: 20221,
            fwmark: 0x1a5,
            owned_v4_rule_del_args: vec![vec![
                "-4".into(),
                "rule".into(),
                "del".into(),
                "pref".into(),
                "9020".into(),
            ]],
            owned_v6_rule_del_args: Vec::new(),
            owned_route_del_args: Vec::new(),
        };

        // 1. Dead foreign PID leaves behind an unrecovered `sysproxy` backup.
        let mut initial = RecoveryJournal::new_for_pid(dead_foreign_pid);
        initial.sysproxy = Some(sp_rec.clone());
        initial.save_atomic(&dir).unwrap();

        // 2. Current live process writes its own `linux_tun` via `update_journal_for_pid_with_liveness`
        //    (where `dead_foreign_pid` reports NOT alive). The dead foreign `sysproxy` MUST survive!
        update_journal_for_pid_with_liveness(
            &dir,
            my_pid,
            |p| p == my_pid,
            |j| {
                j.linux_tun = Some(tun_rec.clone());
            },
        )
        .unwrap();

        let after_update = RecoveryJournal::load_from(&dir).unwrap().unwrap();
        assert_eq!(after_update.linux_tun.as_ref(), Some(&tun_rec));
        assert_eq!(after_update.effective_tun_pid(), my_pid);
        assert_eq!(after_update.sysproxy.as_ref(), Some(&sp_rec));
        assert_eq!(after_update.effective_sysproxy_pid(), dead_foreign_pid);

        // 3. Current live process cleanly finalizes its Linux TUN teardown via
        //    `finalize_linux_tun_teardown_journal`: the dead foreign `sysproxy` MUST STILL survive!
        finalize_linux_tun_teardown_journal(&dir, None).unwrap();
        let after_teardown = RecoveryJournal::load_from(&dir).unwrap().unwrap();
        assert!(after_teardown.linux_tun.is_none());
        assert_eq!(after_teardown.sysproxy.as_ref(), Some(&sp_rec));
        assert_eq!(after_teardown.effective_sysproxy_pid(), dead_foreign_pid);

        // 4. Same invariant for sentinel PID `0` (previously failed sysproxy recovery):
        let mut sentinel_j = RecoveryJournal::new_for_pid(0);
        sentinel_j.sysproxy = Some(sp_rec.clone());
        sentinel_j.save_atomic(&dir).unwrap();

        update_journal_for_pid_with_liveness(
            &dir,
            my_pid,
            |p| p == my_pid,
            |j| {
                j.linux_tun = Some(tun_rec.clone());
            },
        )
        .unwrap();
        let with_sentinel = RecoveryJournal::load_from(&dir).unwrap().unwrap();
        assert_eq!(with_sentinel.sysproxy.as_ref(), Some(&sp_rec));
        assert_eq!(with_sentinel.effective_sysproxy_pid(), 0);

        finalize_linux_tun_teardown_journal(&dir, None).unwrap();
        let after_sentinel_teardown = RecoveryJournal::load_from(&dir).unwrap().unwrap();
        assert!(after_sentinel_teardown.linux_tun.is_none());
        assert_eq!(after_sentinel_teardown.sysproxy.as_ref(), Some(&sp_rec));
        assert_eq!(after_sentinel_teardown.effective_sysproxy_pid(), 0);

        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn unix_single_instance_guard_keeps_inode_on_drop_and_enforces_concurrent_exclusion() {
        use std::{
            os::unix::fs::MetadataExt,
            sync::{
                Arc,
                atomic::{AtomicUsize, Ordering as AtomicOrdering},
            },
        };

        let dir =
            std::env::temp_dir().join(format!("rc-single-instance-inode-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();

        // 1. Lockfile inode MUST NOT be unlinked on Drop; reacquisition reuses the exact same inode.
        let g1 = SingleInstanceGuard::acquire(&dir).expect("acquire #1");
        let lock_path = g1.lock_path().to_path_buf();
        let meta1 = fs::metadata(&lock_path).unwrap();
        let (dev1, ino1) = (meta1.dev(), meta1.ino());

        assert!(
            SingleInstanceGuard::acquire(&dir).is_err(),
            "second concurrent acquire must fail while guard #1 is held"
        );

        drop(g1);
        assert!(
            lock_path.exists(),
            "Unix Drop must NOT unlink lockfile inode"
        );
        let meta_after_drop = fs::metadata(&lock_path).unwrap();
        assert_eq!((meta_after_drop.dev(), meta_after_drop.ino()), (dev1, ino1));

        let g2 = SingleInstanceGuard::acquire(&dir).expect("acquire #2");
        let meta2 = fs::metadata(&lock_path).unwrap();
        assert_eq!((meta2.dev(), meta2.ino()), (dev1, ino1));
        drop(g2);

        // 2. External deletion while unlocked recovers cleanly to a valid inode on next acquire.
        fs::remove_file(&lock_path).unwrap();
        let g3 = SingleInstanceGuard::acquire(&dir).expect("acquire after external unlink");
        assert!(lock_path.exists());
        drop(g3);

        // 3. Multi-threaded contention: at most ONE thread may hold the guard at any instant.
        let active = Arc::new(AtomicUsize::new(0));
        let max_seen = Arc::new(AtomicUsize::new(0));
        let acquired_total = Arc::new(AtomicUsize::new(0));
        let mut threads = Vec::new();
        for _ in 0..6 {
            let d = dir.clone();
            let act = Arc::clone(&active);
            let max = Arc::clone(&max_seen);
            let tot = Arc::clone(&acquired_total);
            threads.push(std::thread::spawn(move || {
                for _ in 0..25 {
                    if let Ok(guard) = SingleInstanceGuard::acquire(&d) {
                        let cur = act.fetch_add(1, AtomicOrdering::SeqCst) + 1;
                        max.fetch_max(cur, AtomicOrdering::SeqCst);
                        tot.fetch_add(1, AtomicOrdering::SeqCst);
                        std::thread::sleep(std::time::Duration::from_millis(1));
                        act.fetch_sub(1, AtomicOrdering::SeqCst);
                        drop(guard);
                    } else {
                        std::thread::yield_now();
                    }
                }
            }));
        }
        for t in threads {
            t.join().unwrap();
        }
        assert!(acquired_total.load(AtomicOrdering::SeqCst) > 0);
        assert_eq!(
            max_seen.load(AtomicOrdering::SeqCst),
            1,
            "SingleInstanceGuard must enforce strict mutual exclusion across racing threads"
        );

        let _ = fs::remove_dir_all(&dir);
    }
}

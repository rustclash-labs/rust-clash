use std::{
    fs::{self, File, OpenOptions},
    io::{self, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};

const JOURNAL_FILENAME: &str = "network_recovery.json";
const LOCK_FILENAME: &str = "rust-clash.instance.lock";

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

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsDnsInterfaceBackup {
    pub interface_guid: String,
    pub ipv4: WindowsDnsFamilySnapshot,
    #[serde(default)]
    pub ipv6: Option<WindowsDnsFamilySnapshot>,
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

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SysProxyRecoveryRecord {
    pub platform: String,
    pub windows_proxy_enable: Option<u32>,
    pub windows_proxy_server: Option<String>,
    pub windows_proxy_override: Option<String>,
    pub macos_services: Vec<MacOsProxyServiceBackup>,
    pub linux_gnome_mode: Option<String>,
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
}

impl RecoveryJournal {
    pub fn new_for_current_process() -> Self {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        Self {
            pid: std::process::id(),
            started_at_unix_ms: now_ms,
            platform: std::env::consts::OS.to_string(),
            linux_tun: None,
            macos_tun: None,
            windows_tun: None,
            sysproxy: None,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.linux_tun.is_none()
            && self.macos_tun.is_none()
            && self.windows_tun.is_none()
            && self.sysproxy.is_none()
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

    /// Persist atomically via `<dir>/network_recovery.json.tmp.<pid>` + `rename`.
    /// If the journal has no owned resources left, removes the journal file instead.
    pub fn save_atomic(&self, state_dir: &Path) -> io::Result<()> {
        if self.is_empty() {
            return Self::remove_from(state_dir);
        }
        fs::create_dir_all(state_dir)?;
        let final_path = Self::path_in(state_dir);
        let tmp_path = state_dir.join(format!("{JOURNAL_FILENAME}.tmp.{}", std::process::id()));
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

    pub fn remove_from(state_dir: &Path) -> io::Result<()> {
        let path = Self::path_in(state_dir);
        match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }
}

/// Update (or clear if empty) a section of the current process's `RecoveryJournal` in `state_dir`.
pub fn update_current_journal<F>(state_dir: &Path, mutate: F) -> io::Result<()>
where
    F: FnOnce(&mut RecoveryJournal),
{
    let mut journal = match RecoveryJournal::load_from(state_dir) {
        Ok(Some(existing)) if existing.pid == std::process::id() => existing,
        _ => RecoveryJournal::new_for_current_process(),
    };
    mutate(&mut journal);
    journal.save_atomic(state_dir)
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
    pub fn acquire(state_dir: &Path) -> io::Result<Self> {
        fs::create_dir_all(state_dir)?;
        let lock_path = state_dir.join(LOCK_FILENAME);

        #[cfg(not(any(unix, windows)))]
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
        open_opts.create(true).read(true).write(true);
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            // FILE_SHARE_READ (0x1) | FILE_SHARE_WRITE (0x2) | FILE_SHARE_DELETE (0x4) = 0x7
            open_opts.share_mode(0x7);
        }
        let mut file = open_opts.open(&lock_path)?;

        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            // SAFETY: `flock` with `LOCK_EX | LOCK_NB` on a valid open `File` fd is safe and non-blocking.
            let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
            if rc != 0 {
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

impl Drop for SingleInstanceGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.lock_path);
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
    let journal = match RecoveryJournal::load_from(state_dir) {
        Ok(Some(j)) => j,
        Ok(None) => return outcome,
        Err(e) => {
            outcome.warnings.push(e.to_string());
            return outcome;
        }
    };

    if is_pid_alive(journal.pid) {
        // Another live process owns this journal — never touch its active routes!
        return outcome;
    }

    outcome.found_stale_journal = true;
    outcome.stale_pid = Some(journal.pid);

    if let Some(linux) = &journal.linux_tun {
        for args in linux.owned_v4_rule_del_args.iter().rev() {
            let desc = format!("ip {}", args.join(" "));
            match run_cmd("ip", args) {
                Ok(()) => outcome.actions_executed.push(desc),
                Err(e) => outcome.warnings.push(format!("{desc}: {e}")),
            }
        }
        for args in linux.owned_v6_rule_del_args.iter().rev() {
            let desc = format!("ip {}", args.join(" "));
            match run_cmd("ip", args) {
                Ok(()) => outcome.actions_executed.push(desc),
                Err(e) => outcome.warnings.push(format!("{desc}: {e}")),
            }
        }
        for args in linux.owned_route_del_args.iter().rev() {
            let desc = format!("ip {}", args.join(" "));
            match run_cmd("ip", args) {
                Ok(()) => outcome.actions_executed.push(desc),
                Err(e) => outcome.warnings.push(format!("{desc}: {e}")),
            }
        }
        if !linux.device_name.is_empty() {
            let del_link = vec![
                "link".to_string(),
                "delete".to_string(),
                "dev".to_string(),
                linux.device_name.clone(),
            ];
            if run_cmd("ip", &del_link).is_ok() {
                outcome
                    .actions_executed
                    .push(format!("ip link delete dev {}", linux.device_name));
            }
        }
    }

    if let Some(macos) = &journal.macos_tun {
        for args in macos.owned_route_del_args.iter().rev() {
            let desc = format!("route {}", args.join(" "));
            match run_cmd("route", args) {
                Ok(()) => outcome.actions_executed.push(desc),
                Err(e) => outcome.warnings.push(format!("{desc}: {e}")),
            }
        }
        for dns in &macos.dns_backups {
            let mut args = vec!["-setdnsservers".to_string(), dns.service_name.clone()];
            if dns.previous_servers.is_empty() {
                args.push("Empty".to_string());
            } else {
                args.extend(dns.previous_servers.iter().cloned());
            }
            let desc = format!("networksetup {}", args.join(" "));
            match run_cmd("networksetup", &args) {
                Ok(()) => outcome.actions_executed.push(desc),
                Err(e) => outcome.warnings.push(format!("{desc}: {e}")),
            }
        }
    }

    if let Some(win) = &journal.windows_tun {
        #[cfg(windows)]
        {
            crate::platform::tun::windows::recover_windows_tun_record(win, &mut outcome);
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
                    Some(
                        b.ipv4
                            .name_server
                            .split([',', ' '])
                            .filter(|s| !s.is_empty())
                            .map(str::to_string)
                            .collect(),
                    )
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
                        Err(e) => outcome.warnings.push(format!("{desc}: {e}")),
                    }
                }
            }
        }
    }

    if let Some(sp) = &journal.sysproxy {
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
            Ok(desc) => outcome.actions_executed.push(desc),
            Err(e) => outcome
                .warnings
                .push(format!("sysproxy recovery failed: {e}")),
        }
        let _ = fs::remove_file(state_dir.join("sysproxy_active.json"));
    }

    if let Err(e) = RecoveryJournal::remove_from(state_dir) {
        outcome
            .warnings
            .push(format!("failed removing recovery journal: {e}"));
    }

    outcome
}

fn default_command_runner(program: &str, args: &[String]) -> io::Result<()> {
    let resolved = if program == "ip" {
        for cand in ["/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip", "/bin/ip"] {
            if Path::new(cand).exists() {
                let out = std::process::Command::new(cand).args(args).output()?;
                return if out.status.success() {
                    Ok(())
                } else {
                    Err(io::Error::other(
                        String::from_utf8_lossy(&out.stderr).trim().to_string(),
                    ))
                };
            }
        }
        program
    } else {
        program
    };
    let out = std::process::Command::new(resolved).args(args).output()?;
    if out.status.success() {
        Ok(())
    } else {
        Err(io::Error::other(
            String::from_utf8_lossy(&out.stderr).trim().to_string(),
        ))
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
}

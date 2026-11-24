use std::{io, path::Path};

use serde::{Deserialize, Serialize};

use crate::platform::recovery::{
    LinuxGnomeProtoBackup, LinuxKdeProxyBackup, MacOsProxyServiceBackup, RecoveryJournal,
    SysProxyRecoveryRecord, clear_sysproxy_journal_entry, update_current_journal,
};

pub fn default_proxy_bypass_list() -> Vec<String> {
    vec![
        "localhost".to_string(),
        "127.0.0.1".to_string(),
        "::1".to_string(),
        "10.0.0.0/8".to_string(),
        "172.16.0.0/12".to_string(),
        "192.168.0.0/16".to_string(),
        "*.local".to_string(),
    ]
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SysProxyStatus {
    pub supported: bool,
    pub enabled: bool,
    pub host: Option<String>,
    pub port: Option<u16>,
    pub bypass: Vec<String>,
    pub backend: String,
    pub last_error: Option<String>,
}

/// Abstract OS command runner so unit tests can verify macOS/Linux command sequences and
/// crash-recovery journal updates hermetically without mutating the host VM's live proxy settings!
pub trait SysProxyCommandBackend {
    fn run_capture(&mut self, program: &str, args: &[String]) -> io::Result<String>;
}

pub struct RealOsCommandBackend;

fn find_desktop_helper_binary(program: &str) -> Option<std::path::PathBuf> {
    if program.contains('/') {
        let p = Path::new(program);
        return p.is_file().then(|| p.to_path_buf());
    }
    if let Some(paths) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&paths) {
            if dir.as_os_str().is_empty() {
                continue;
            }
            let p = dir.join(program);
            if p.is_file() {
                return Some(p);
            }
        }
    }
    for dir in [
        "/usr/bin",
        "/bin",
        "/usr/local/bin",
        "/run/current-system/sw/bin",
    ] {
        let p = Path::new(dir).join(program);
        if p.is_file() {
            return Some(p);
        }
    }
    None
}

pub fn is_kde_desktop_env(
    xdg_current_desktop: Option<&str>,
    desktop_session: Option<&str>,
    kde_full_session: Option<&str>,
) -> bool {
    if let Some(full) = kde_full_session {
        let t = full.trim();
        if !t.is_empty() && t != "0" && !t.eq_ignore_ascii_case("false") {
            return true;
        }
    }
    for val in [xdg_current_desktop, desktop_session].into_iter().flatten() {
        let lower = val.to_ascii_lowercase();
        if lower.contains("kde") || lower.contains("plasma") {
            return true;
        }
    }
    false
}

fn is_current_env_kde() -> bool {
    is_kde_desktop_env(
        std::env::var("XDG_CURRENT_DESKTOP").ok().as_deref(),
        std::env::var("DESKTOP_SESSION").ok().as_deref(),
        std::env::var("KDE_FULL_SESSION").ok().as_deref(),
    )
}

#[cfg(target_os = "linux")]
fn detect_linux_sysproxy_capability() -> (bool, &'static str) {
    let has_gsettings = find_desktop_helper_binary("gsettings").is_some();
    let has_kde6 = find_desktop_helper_binary("kwriteconfig6").is_some();
    let has_kde5 = find_desktop_helper_binary("kwriteconfig5").is_some();
    let has_kde = has_kde6 || has_kde5;
    let kde_env = is_current_env_kde();

    if kde_env && has_kde && has_gsettings {
        (true, "linux-kde-gsettings")
    } else if has_kde && (kde_env || !has_gsettings) {
        (
            true,
            if has_kde6 {
                "linux-kde-kwriteconfig6"
            } else {
                "linux-kde-kwriteconfig5"
            },
        )
    } else if has_gsettings && has_kde {
        (true, "linux-gsettings-kde")
    } else if has_gsettings {
        (true, "linux-gsettings")
    } else {
        (false, "linux-unsupported")
    }
}

impl SysProxyCommandBackend for RealOsCommandBackend {
    fn run_capture(&mut self, program: &str, args: &[String]) -> io::Result<String> {
        let resolved = find_desktop_helper_binary(program)
            .unwrap_or_else(|| std::path::PathBuf::from(program));
        let out = std::process::Command::new(&resolved).args(args).output()?;
        if out.status.success() {
            Ok(String::from_utf8_lossy(&out.stdout).to_string())
        } else {
            Err(io::Error::other(format!(
                "{program} {} failed: {}",
                args.join(" "),
                String::from_utf8_lossy(&out.stderr).trim()
            )))
        }
    }
}

/// Query current `rust-clash`-managed OS System Proxy state from the active `RecoveryJournal`.
pub fn query_sysproxy_status(state_dir: &Path) -> SysProxyStatus {
    let owned = RecoveryJournal::load_from(state_dir)
        .ok()
        .flatten()
        .and_then(|j| {
            let sp_pid = j.effective_sysproxy_pid();
            if sp_pid == std::process::id() || sp_pid == 0 {
                j.sysproxy
            } else {
                None
            }
        });

    #[cfg(windows)]
    let (supported, backend) = (true, "windows-wininet-registry");
    #[cfg(target_os = "macos")]
    let (supported, backend) = (true, "macos-networksetup");
    #[cfg(target_os = "linux")]
    let (supported, backend) = {
        let (cap_ok, label) = detect_linux_sysproxy_capability();
        (cap_ok || owned.is_some(), label)
    };
    #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
    let (supported, backend) = (false, "unsupported");

    let meta_path = state_dir.join("sysproxy_active.json");
    let active_meta: Option<(String, u16, Vec<String>)> = if owned.is_some() && meta_path.exists() {
        std::fs::read_to_string(&meta_path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
    } else {
        None
    };

    SysProxyStatus {
        supported,
        enabled: owned.is_some(),
        host: active_meta.as_ref().map(|m| m.0.clone()),
        port: active_meta.as_ref().map(|m| m.1),
        bypass: active_meta
            .map(|m| m.2)
            .unwrap_or_else(default_proxy_bypass_list),
        backend: backend.to_string(),
        last_error: None,
    }
}

/// Enable OS System Proxy pointing HTTP, HTTPS, and SOCKS to `host:port`, recording the
/// exact pre-mutation backup in `network_recovery.json` BEFORE applying changes.
pub fn enable_system_proxy(
    host: &str,
    port: u16,
    bypass: &[String],
    state_dir: &Path,
) -> io::Result<SysProxyStatus> {
    if port == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "system proxy port must be non-zero",
        ));
    }
    let bypass_vec = if bypass.is_empty() {
        default_proxy_bypass_list()
    } else {
        bypass.to_vec()
    };

    #[cfg(windows)]
    {
        enable_windows_sysproxy(host, port, &bypass_vec, state_dir)?;
    }

    #[cfg(target_os = "macos")]
    {
        let mut backend = RealOsCommandBackend;
        enable_macos_sysproxy_with_backend(host, port, &bypass_vec, state_dir, &mut backend)?;
    }

    #[cfg(target_os = "linux")]
    {
        let mut backend = RealOsCommandBackend;
        enable_linux_sysproxy_with_backend(host, port, &bypass_vec, state_dir, &mut backend)?;
    }

    let meta_path = state_dir.join("sysproxy_active.json");
    let _ = std::fs::create_dir_all(state_dir);
    let _ = std::fs::write(
        &meta_path,
        serde_json::to_vec(&(host.to_string(), port, bypass_vec.clone())).unwrap_or_default(),
    );

    Ok(query_sysproxy_status(state_dir))
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum SysProxyBackupDisposition {
    None,
    OwnedByCurrent(SysProxyRecoveryRecord),
    AdoptStale(SysProxyRecoveryRecord),
}

fn inspect_sysproxy_backup_with_liveness<L>(
    state_dir: &Path,
    expected_platform: &str,
    is_alive: L,
) -> io::Result<SysProxyBackupDisposition>
where
    L: Fn(u32) -> bool,
{
    let Some(journal) = RecoveryJournal::load_from(state_dir).ok().flatten() else {
        return Ok(SysProxyBackupDisposition::None);
    };
    let sp_pid = journal.effective_sysproxy_pid();
    let Some(existing) = journal.sysproxy else {
        return Ok(SysProxyBackupDisposition::None);
    };
    let current_pid = std::process::id();
    if sp_pid == current_pid {
        return Ok(SysProxyBackupDisposition::OwnedByCurrent(existing));
    }
    if sp_pid != 0 && is_alive(sp_pid) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "system proxy journal belongs to another live rust-clash process (PID {sp_pid})"
            ),
        ));
    }
    if existing.platform == expected_platform {
        Ok(SysProxyBackupDisposition::AdoptStale(existing))
    } else {
        Ok(SysProxyBackupDisposition::None)
    }
}

fn resolve_or_adopt_sysproxy_backup_with_liveness<L>(
    state_dir: &Path,
    expected_platform: &str,
    is_alive: L,
) -> io::Result<Option<SysProxyRecoveryRecord>>
where
    L: Fn(u32) -> bool,
{
    match inspect_sysproxy_backup_with_liveness(state_dir, expected_platform, is_alive)? {
        SysProxyBackupDisposition::None => Ok(None),
        SysProxyBackupDisposition::OwnedByCurrent(existing) => Ok(Some(existing)),
        SysProxyBackupDisposition::AdoptStale(existing) => {
            update_current_journal(state_dir, |cur| {
                cur.sysproxy = Some(existing.clone());
            })?;
            Ok(Some(existing))
        }
    }
}

#[cfg(any(windows, test))]
fn resolve_or_adopt_sysproxy_backup(
    state_dir: &Path,
    expected_platform: &str,
) -> io::Result<Option<SysProxyRecoveryRecord>> {
    resolve_or_adopt_sysproxy_backup_with_liveness(
        state_dir,
        expected_platform,
        crate::platform::recovery::is_pid_alive,
    )
}

fn parse_macos_bypass_domains_output(out: &str) -> Option<Vec<String>> {
    let trimmed = out.trim();
    if trimmed.is_empty() {
        return None;
    }
    if trimmed
        .to_ascii_lowercase()
        .contains("there aren't any bypass domains")
    {
        return Some(Vec::new());
    }
    let domains: Vec<String> = trimmed
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && (!l.starts_with('*') || l.starts_with("*.")))
        .map(ToString::to_string)
        .collect();
    Some(domains)
}

/// Restore the original OS System Proxy settings recorded in `network_recovery.json`.
pub fn disable_system_proxy(state_dir: &Path) -> io::Result<SysProxyStatus> {
    let mut backend = RealOsCommandBackend;
    disable_system_proxy_with_backend(state_dir, &mut backend)
}

/// Restore the original OS System Proxy settings recorded in `network_recovery.json` using an
/// injectable [`SysProxyCommandBackend`]. Preserves both `network_recovery.json` and
/// `sysproxy_active.json` whenever the OS restore fails so subsequent retries or crash recovery
/// can still restore the user's original proxy configuration.
pub fn disable_system_proxy_with_backend<B: SysProxyCommandBackend>(
    state_dir: &Path,
    backend: &mut B,
) -> io::Result<SysProxyStatus> {
    let loaded = RecoveryJournal::load_from(state_dir).ok().flatten();
    if let Some(ref j) = loaded
        && j.sysproxy.is_some()
    {
        let sp_pid = j.effective_sysproxy_pid();
        if sp_pid != std::process::id() && crate::platform::recovery::is_pid_alive(sp_pid) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "system proxy journal belongs to another live rust-clash process (PID {sp_pid})"
                ),
            ));
        }
    }

    if let Some(j) = loaded
        && let Some(rec) = j.sysproxy.clone()
    {
        let sp_pid = j.effective_sysproxy_pid();
        restore_sysproxy_record_with_backend(&rec, backend)?;
        if sp_pid == std::process::id() {
            update_current_journal(state_dir, |cur| {
                cur.sysproxy = None;
            })?;
        } else {
            clear_sysproxy_journal_entry(state_dir)?;
        }
    }
    let _ = std::fs::remove_file(state_dir.join("sysproxy_active.json"));
    Ok(query_sysproxy_status(state_dir))
}

fn is_macos_benign_missing_service_error(err: &io::Error) -> bool {
    let low = err.to_string().to_ascii_lowercase();
    low.contains("not a recognized network service")
}

pub fn restore_sysproxy_record_with_runner_desc<B: SysProxyCommandBackend>(
    rec: &SysProxyRecoveryRecord,
    backend: &mut B,
) -> io::Result<String> {
    restore_sysproxy_record_with_backend(rec, backend)?;
    Ok(format!("restore-sysproxy({})", rec.platform))
}

pub fn restore_sysproxy_record_with_backend<B: SysProxyCommandBackend>(
    rec: &SysProxyRecoveryRecord,
    backend: &mut B,
) -> io::Result<()> {
    let mut failures: Vec<String> = Vec::new();
    match rec.platform.as_str() {
        "windows" => {
            #[cfg(windows)]
            {
                restore_windows_sysproxy_record(rec)?;
            }
            let _ = backend;
        }
        "macos" => {
            let mut run_macos = |args: &[String]| {
                if let Err(err) = backend.run_capture("networksetup", args)
                    && !is_macos_benign_missing_service_error(&err)
                {
                    failures.push(format!("networksetup {}: {err}", args.join(" ")));
                }
            };
            for svc in &rec.macos_services {
                if svc.web_enabled && !svc.web_host.is_empty() && svc.web_port > 0 {
                    run_macos(&[
                        "-setwebproxy".into(),
                        svc.service_name.clone(),
                        svc.web_host.clone(),
                        svc.web_port.to_string(),
                    ]);
                }
                run_macos(&[
                    "-setwebproxystate".into(),
                    svc.service_name.clone(),
                    if svc.web_enabled { "on" } else { "off" }.into(),
                ]);

                if svc.secure_web_enabled
                    && !svc.secure_web_host.is_empty()
                    && svc.secure_web_port > 0
                {
                    run_macos(&[
                        "-setsecurewebproxy".into(),
                        svc.service_name.clone(),
                        svc.secure_web_host.clone(),
                        svc.secure_web_port.to_string(),
                    ]);
                }
                run_macos(&[
                    "-setsecurewebproxystate".into(),
                    svc.service_name.clone(),
                    if svc.secure_web_enabled { "on" } else { "off" }.into(),
                ]);

                if svc.socks_enabled && !svc.socks_host.is_empty() && svc.socks_port > 0 {
                    run_macos(&[
                        "-setsocksfirewallproxy".into(),
                        svc.service_name.clone(),
                        svc.socks_host.clone(),
                        svc.socks_port.to_string(),
                    ]);
                }
                run_macos(&[
                    "-setsocksfirewallproxystate".into(),
                    svc.service_name.clone(),
                    if svc.socks_enabled { "on" } else { "off" }.into(),
                ]);

                if let Some(ref domains) = svc.bypass_domains {
                    let mut b_args =
                        vec!["-setproxybypassdomains".into(), svc.service_name.clone()];
                    if domains.is_empty() {
                        b_args.push("Empty".into());
                    } else {
                        b_args.extend(domains.iter().cloned());
                    }
                    run_macos(&b_args);
                }
            }
        }
        "linux" => {
            let mut run_checked = |program: &str, args: &[String]| {
                if let Err(err) = backend.run_capture(program, args) {
                    failures.push(format!("{program} {}: {err}", args.join(" ")));
                }
            };
            for (proto, proto_bkp) in [
                ("http", &rec.linux_gnome_http),
                ("https", &rec.linux_gnome_https),
                ("socks", &rec.linux_gnome_socks),
            ] {
                if let Some(bkp) = proto_bkp {
                    let schema = format!("org.gnome.system.proxy.{proto}");
                    if let Some(ref host) = bkp.host {
                        run_checked(
                            "gsettings",
                            &["set".into(), schema.clone(), "host".into(), host.clone()],
                        );
                    }
                    if let Some(port) = bkp.port {
                        run_checked(
                            "gsettings",
                            &["set".into(), schema, "port".into(), port.to_string()],
                        );
                    }
                }
            }
            if let Some(ref ignore_hosts) = rec.linux_gnome_ignore_hosts
                && !ignore_hosts.trim().is_empty()
            {
                run_checked(
                    "gsettings",
                    &[
                        "set".into(),
                        "org.gnome.system.proxy".into(),
                        "ignore-hosts".into(),
                        ignore_hosts.trim().to_string(),
                    ],
                );
            }
            if rec.linux_gnome_mode.is_some() || rec.linux_kde.is_none() {
                let mode = rec.linux_gnome_mode.as_deref().unwrap_or("'none'");
                let cleaned = mode.trim().trim_matches('\'');
                run_checked(
                    "gsettings",
                    &[
                        "set".into(),
                        "org.gnome.system.proxy".into(),
                        "mode".into(),
                        cleaned.to_string(),
                    ],
                );
            }
            if let Some(ref kde) = rec.linux_kde {
                let write_bin = if kde.tool_generation == 5 {
                    "kwriteconfig5"
                } else {
                    "kwriteconfig6"
                };
                for (key, val_opt) in [
                    ("httpProxy", &kde.http_proxy),
                    ("httpsProxy", &kde.https_proxy),
                    ("socksProxy", &kde.socks_proxy),
                    ("NoProxyFor", &kde.no_proxy_for),
                ] {
                    if let Some(val) = val_opt {
                        run_checked(
                            write_bin,
                            &[
                                "--file".into(),
                                "kioslaverc".into(),
                                "--group".into(),
                                "Proxy Settings".into(),
                                "--key".into(),
                                key.into(),
                                val.clone(),
                            ],
                        );
                    }
                }
                let proxy_type = kde.proxy_type.as_deref().unwrap_or("0");
                run_checked(
                    write_bin,
                    &[
                        "--file".into(),
                        "kioslaverc".into(),
                        "--group".into(),
                        "Proxy Settings".into(),
                        "--key".into(),
                        "ProxyType".into(),
                        proxy_type.to_string(),
                    ],
                );
                // Keep D-Bus KIO notification best-effort because headless or non-KDE sessions
                // may not have a live session bus even after `kioslaverc` is restored on disk.
                let _ = backend.run_capture(
                    "dbus-send",
                    &[
                        "--type=signal".into(),
                        "/KIO/Scheduler".into(),
                        "org.kde.KIO.Scheduler.reparseSlaveConfiguration".into(),
                        "string:".into(),
                    ],
                );
            }
        }
        _ => {}
    }

    if !failures.is_empty() {
        return Err(io::Error::other(format!(
            "failed restoring {} system proxy setting(s): {}",
            failures.len(),
            failures.join("; ")
        )));
    }
    Ok(())
}

pub fn enable_macos_sysproxy_with_backend<B: SysProxyCommandBackend>(
    host: &str,
    port: u16,
    bypass: &[String],
    state_dir: &Path,
    backend: &mut B,
) -> io::Result<()> {
    enable_macos_sysproxy_with_backend_and_liveness(
        host,
        port,
        bypass,
        state_dir,
        backend,
        crate::platform::recovery::is_pid_alive,
    )
}

fn snapshot_macos_service<B: SysProxyCommandBackend>(
    backend: &mut B,
    svc: &str,
) -> MacOsProxyServiceBackup {
    let web = backend
        .run_capture("networksetup", &["-getwebproxy".into(), svc.to_string()])
        .unwrap_or_default();
    let sweb = backend
        .run_capture(
            "networksetup",
            &["-getsecurewebproxy".into(), svc.to_string()],
        )
        .unwrap_or_default();
    let socks = backend
        .run_capture(
            "networksetup",
            &["-getsocksfirewallproxy".into(), svc.to_string()],
        )
        .unwrap_or_default();
    let bypass_raw = backend
        .run_capture(
            "networksetup",
            &["-getproxybypassdomains".into(), svc.to_string()],
        )
        .unwrap_or_default();
    let (we, wh, wp) = parse_networksetup_proxy_output(&web);
    let (se, sh, sp) = parse_networksetup_proxy_output(&sweb);
    let (ke, kh, kp) = parse_networksetup_proxy_output(&socks);
    MacOsProxyServiceBackup {
        service_name: svc.to_string(),
        web_enabled: we,
        web_host: wh,
        web_port: wp,
        secure_web_enabled: se,
        secure_web_host: sh,
        secure_web_port: sp,
        socks_enabled: ke,
        socks_host: kh,
        socks_port: kp,
        bypass_domains: parse_macos_bypass_domains_output(&bypass_raw),
    }
}

fn enable_macos_sysproxy_with_backend_and_liveness<B, L>(
    host: &str,
    port: u16,
    bypass: &[String],
    state_dir: &Path,
    backend: &mut B,
    is_alive: L,
) -> io::Result<()>
where
    B: SysProxyCommandBackend,
    L: Fn(u32) -> bool,
{
    // Fail fast before running any OS command if another live process owns `sysproxy`.
    let _ = inspect_sysproxy_backup_with_liveness(state_dir, "macos", &is_alive)?;

    let raw_services = backend.run_capture("networksetup", &["-listallnetworkservices".into()])?;
    let services: Vec<String> = raw_services
        .lines()
        .map(str::trim)
        .filter(|l| {
            !l.is_empty()
                && !l.starts_with("An asterisk")
                && !l.starts_with('*')
                && !l.contains("Thunderbolt Bridge")
        })
        .map(ToString::to_string)
        .collect();

    if services.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "no active macOS network services found via networksetup",
        ));
    }

    let existing_backup =
        resolve_or_adopt_sysproxy_backup_with_liveness(state_dir, "macos", &is_alive)?;

    match existing_backup {
        None => {
            let backups = services
                .iter()
                .map(|svc| snapshot_macos_service(backend, svc))
                .collect();
            update_current_journal(state_dir, |j| {
                j.sysproxy = Some(SysProxyRecoveryRecord {
                    platform: "macos".to_string(),
                    macos_services: backups,
                    ..Default::default()
                });
            })?;
        }
        Some(mut rec) => {
            let mut augmented = false;
            for svc in &services {
                if !rec.macos_services.iter().any(|s| s.service_name == *svc) {
                    rec.macos_services
                        .push(snapshot_macos_service(backend, svc));
                    augmented = true;
                }
            }
            if augmented {
                update_current_journal(state_dir, |j| {
                    j.sysproxy = Some(rec);
                })?;
            }
        }
    }

    let port_str = port.to_string();
    for svc in &services {
        backend.run_capture(
            "networksetup",
            &[
                "-setwebproxy".into(),
                svc.clone(),
                host.to_string(),
                port_str.clone(),
            ],
        )?;
        backend.run_capture(
            "networksetup",
            &[
                "-setsecurewebproxy".into(),
                svc.clone(),
                host.to_string(),
                port_str.clone(),
            ],
        )?;
        backend.run_capture(
            "networksetup",
            &[
                "-setsocksfirewallproxy".into(),
                svc.clone(),
                host.to_string(),
                port_str.clone(),
            ],
        )?;
        if !bypass.is_empty() {
            let mut b_args = vec!["-setproxybypassdomains".into(), svc.clone()];
            b_args.extend(bypass.iter().cloned());
            let _ = backend.run_capture("networksetup", &b_args);
        }
    }

    Ok(())
}

fn parse_gsettings_string_value(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let unquoted = trimmed
        .strip_prefix('\'')
        .and_then(|s| s.strip_suffix('\''))
        .unwrap_or(trimmed);
    Some(unquoted.replace("\\'", "'").replace("\\\\", "\\"))
}

fn parse_gsettings_port_value(raw: &str) -> Option<u16> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    trimmed
        .split_whitespace()
        .last()
        .and_then(|tok| tok.parse::<u16>().ok())
}

fn capture_gnome_proto_backup<B: SysProxyCommandBackend>(
    backend: &mut B,
    proto: &str,
) -> Option<LinuxGnomeProtoBackup> {
    let schema = format!("org.gnome.system.proxy.{proto}");
    let host = backend
        .run_capture("gsettings", &["get".into(), schema.clone(), "host".into()])
        .ok()
        .and_then(|s| parse_gsettings_string_value(&s));
    let port = backend
        .run_capture("gsettings", &["get".into(), schema, "port".into()])
        .ok()
        .and_then(|s| parse_gsettings_port_value(&s));
    if host.is_some() || port.is_some() {
        Some(LinuxGnomeProtoBackup { host, port })
    } else {
        None
    }
}

fn capture_gnome_proxy_backup_into<B: SysProxyCommandBackend>(
    backend: &mut B,
    prev_mode: &str,
    rec: &mut SysProxyRecoveryRecord,
) {
    rec.linux_gnome_mode = Some(prev_mode.to_string());
    rec.linux_gnome_ignore_hosts = backend
        .run_capture(
            "gsettings",
            &[
                "get".into(),
                "org.gnome.system.proxy".into(),
                "ignore-hosts".into(),
            ],
        )
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    rec.linux_gnome_http = capture_gnome_proto_backup(backend, "http");
    rec.linux_gnome_https = capture_gnome_proto_backup(backend, "https");
    rec.linux_gnome_socks = capture_gnome_proto_backup(backend, "socks");
}

fn probe_kde_generation<B: SysProxyCommandBackend>(backend: &mut B) -> Option<(u8, String)> {
    for (kde_gen, read_bin) in [(6u8, "kreadconfig6"), (5u8, "kreadconfig5")] {
        if let Ok(out) = backend.run_capture(
            read_bin,
            &[
                "--file".into(),
                "kioslaverc".into(),
                "--group".into(),
                "Proxy Settings".into(),
                "--key".into(),
                "ProxyType".into(),
                "--default".into(),
                "0".into(),
            ],
        ) {
            let trimmed = out.trim();
            if !trimmed.is_empty() {
                return Some((kde_gen, trimmed.to_string()));
            }
        }
    }
    for (kde_gen, write_bin) in [(6u8, "kwriteconfig6"), (5u8, "kwriteconfig5")] {
        if let Ok(out) = backend.run_capture(write_bin, &["--help".into()])
            && !out.trim().is_empty()
        {
            return Some((kde_gen, "0".to_string()));
        }
    }
    None
}

fn capture_kde_proxy_backup<B: SysProxyCommandBackend>(
    backend: &mut B,
    kde_gen: u8,
    prev_proxy_type: String,
) -> LinuxKdeProxyBackup {
    let read_bin = if kde_gen == 5 {
        "kreadconfig5"
    } else {
        "kreadconfig6"
    };
    let mut read_key = |key: &str| -> Option<String> {
        backend
            .run_capture(
                read_bin,
                &[
                    "--file".into(),
                    "kioslaverc".into(),
                    "--group".into(),
                    "Proxy Settings".into(),
                    "--key".into(),
                    key.into(),
                ],
            )
            .ok()
            .map(|s| s.trim().to_string())
    };
    LinuxKdeProxyBackup {
        tool_generation: kde_gen,
        proxy_type: Some(prev_proxy_type),
        http_proxy: read_key("httpProxy"),
        https_proxy: read_key("httpsProxy"),
        socks_proxy: read_key("socksProxy"),
        no_proxy_for: read_key("NoProxyFor"),
    }
}

pub fn enable_linux_sysproxy_with_backend<B: SysProxyCommandBackend>(
    host: &str,
    port: u16,
    bypass: &[String],
    state_dir: &Path,
    backend: &mut B,
) -> io::Result<()> {
    enable_linux_sysproxy_with_env(host, port, bypass, state_dir, is_current_env_kde(), backend)
}

pub fn enable_linux_sysproxy_with_env<B: SysProxyCommandBackend>(
    host: &str,
    port: u16,
    bypass: &[String],
    state_dir: &Path,
    prefer_kde: bool,
    backend: &mut B,
) -> io::Result<()> {
    enable_linux_sysproxy_with_env_and_liveness(
        host,
        port,
        bypass,
        state_dir,
        prefer_kde,
        backend,
        crate::platform::recovery::is_pid_alive,
    )
}

fn enable_linux_sysproxy_with_env_and_liveness<B, L>(
    host: &str,
    port: u16,
    bypass: &[String],
    state_dir: &Path,
    prefer_kde: bool,
    backend: &mut B,
    is_alive: L,
) -> io::Result<()>
where
    B: SysProxyCommandBackend,
    L: Fn(u32) -> bool,
{
    // Fail fast before running any OS command if another live process owns `sysproxy`.
    let _ = inspect_sysproxy_backup_with_liveness(state_dir, "linux", &is_alive)?;

    let gnome_mode_res = backend
        .run_capture(
            "gsettings",
            &["get".into(), "org.gnome.system.proxy".into(), "mode".into()],
        )
        .map(|s| s.trim().trim_matches('\'').to_string());

    let kde_probe = if prefer_kde || gnome_mode_res.is_err() {
        probe_kde_generation(backend)
    } else {
        None
    };

    if let Err(ref g_err) = gnome_mode_res
        && kde_probe.is_none()
    {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!(
                "Linux desktop proxy helpers (gsettings / kwriteconfig6 / kwriteconfig5) unavailable: {g_err}"
            ),
        ));
    }

    let existing_backup =
        resolve_or_adopt_sysproxy_backup_with_liveness(state_dir, "linux", &is_alive)?;
    match existing_backup {
        None => {
            let mut rec = SysProxyRecoveryRecord {
                platform: "linux".to_string(),
                ..Default::default()
            };
            if let Ok(ref prev_mode) = gnome_mode_res {
                capture_gnome_proxy_backup_into(backend, prev_mode, &mut rec);
            }
            rec.linux_kde = kde_probe
                .as_ref()
                .map(|(kde_gen, ptype)| capture_kde_proxy_backup(backend, *kde_gen, ptype.clone()));
            update_current_journal(state_dir, |j| {
                j.sysproxy = Some(rec);
            })?;
        }
        Some(mut rec) => {
            let mut augmented = false;
            if let Ok(ref prev_mode) = gnome_mode_res
                && rec.linux_gnome_mode.is_none()
                && rec.linux_kde.is_some()
            {
                capture_gnome_proxy_backup_into(backend, prev_mode, &mut rec);
                augmented = true;
            }
            if let Some((kde_gen, ref ptype)) = kde_probe
                && rec.linux_kde.is_none()
            {
                if rec.linux_gnome_mode.is_none() {
                    // Preserve legacy minimal GNOME-only restore semantics (`unwrap_or("'none'")`)
                    // without re-snapshotting an already-mutated GNOME session.
                    rec.linux_gnome_mode = Some("none".to_string());
                }
                rec.linux_kde = Some(capture_kde_proxy_backup(backend, kde_gen, ptype.clone()));
                augmented = true;
            }
            if augmented {
                update_current_journal(state_dir, |j| {
                    j.sysproxy = Some(rec);
                })?;
            }
        }
    }

    if gnome_mode_res.is_ok() {
        let port_s = port.to_string();
        for proto in ["http", "https", "socks"] {
            let schema = format!("org.gnome.system.proxy.{proto}");
            backend.run_capture(
                "gsettings",
                &["set".into(), schema.clone(), "host".into(), host.into()],
            )?;
            backend.run_capture(
                "gsettings",
                &["set".into(), schema, "port".into(), port_s.clone()],
            )?;
        }
        if !bypass.is_empty() {
            let quoted: Vec<String> = bypass
                .iter()
                .map(|b| format!("'{}'", b.replace('\\', "\\\\").replace('\'', "\\'")))
                .collect();
            let list_arg = format!("[{}]", quoted.join(", "));
            let _ = backend.run_capture(
                "gsettings",
                &[
                    "set".into(),
                    "org.gnome.system.proxy".into(),
                    "ignore-hosts".into(),
                    list_arg,
                ],
            );
        }
        backend.run_capture(
            "gsettings",
            &[
                "set".into(),
                "org.gnome.system.proxy".into(),
                "mode".into(),
                "manual".into(),
            ],
        )?;
    }

    if let Some((kde_gen, _)) = kde_probe {
        let write_bin = if kde_gen == 5 {
            "kwriteconfig5"
        } else {
            "kwriteconfig6"
        };
        let host_port = if host.contains(':') && !host.starts_with('[') {
            format!("[{host}]:{port}")
        } else {
            format!("{host}:{port}")
        };
        let http_url = format!("http://{host_port}");
        let socks_url = format!("socks://{host_port}");
        for (key, val) in [
            ("httpProxy", http_url.as_str()),
            ("httpsProxy", http_url.as_str()),
            ("socksProxy", socks_url.as_str()),
        ] {
            backend.run_capture(
                write_bin,
                &[
                    "--file".into(),
                    "kioslaverc".into(),
                    "--group".into(),
                    "Proxy Settings".into(),
                    "--key".into(),
                    key.into(),
                    val.into(),
                ],
            )?;
        }
        if !bypass.is_empty() {
            let no_proxy = bypass
                .iter()
                .map(|b| {
                    b.strip_prefix("*.")
                        .map_or_else(|| b.clone(), |rest| format!(".{rest}"))
                })
                .collect::<Vec<_>>()
                .join(",");
            let _ = backend.run_capture(
                write_bin,
                &[
                    "--file".into(),
                    "kioslaverc".into(),
                    "--group".into(),
                    "Proxy Settings".into(),
                    "--key".into(),
                    "NoProxyFor".into(),
                    no_proxy,
                ],
            );
        }
        backend.run_capture(
            write_bin,
            &[
                "--file".into(),
                "kioslaverc".into(),
                "--group".into(),
                "Proxy Settings".into(),
                "--key".into(),
                "ProxyType".into(),
                "1".into(),
            ],
        )?;
        let _ = backend.run_capture(
            "dbus-send",
            &[
                "--type=signal".into(),
                "/KIO/Scheduler".into(),
                "org.kde.KIO.Scheduler.reparseSlaveConfiguration".into(),
                "string:".into(),
            ],
        );
    }

    Ok(())
}

fn parse_networksetup_proxy_output(out: &str) -> (bool, String, u16) {
    let mut enabled = false;
    let mut server = String::new();
    let mut port = 0u16;
    for line in out.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("Enabled:") {
            enabled = rest.trim().eq_ignore_ascii_case("Yes");
        } else if let Some(rest) = trimmed.strip_prefix("Server:") {
            server = rest.trim().to_string();
        } else if let Some(rest) = trimmed.strip_prefix("Port:") {
            port = rest.trim().parse::<u16>().unwrap_or(0);
        }
    }
    (enabled, server, port)
}

/// Formats `ProxyServer` and `ProxyOverride` strings for Windows WinINET / WinHTTP settings,
/// bracketing IPv6 hosts (`[::1]:7890`) and translating CIDR bypass entries (such as
/// `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) into WinINET `*` wildcards.
pub fn format_windows_proxy_server_and_override(
    host: &str,
    port: u16,
    bypass: &[String],
) -> (String, String) {
    let trimmed_host = host.trim();
    let proxy_server = if trimmed_host.contains(':') && !trimmed_host.starts_with('[') {
        format!("[{trimmed_host}]:{port}")
    } else {
        format!("{trimmed_host}:{port}")
    };

    let mut override_items: Vec<String> = Vec::with_capacity(bypass.len() + 20);
    let mut push_unique = |item: String| {
        if !item.is_empty() && !override_items.iter().any(|x| x.eq_ignore_ascii_case(&item)) {
            override_items.push(item);
        }
    };

    for raw in bypass {
        let entry = raw.trim();
        if entry.is_empty() {
            continue;
        }
        if entry == "::1" || entry.eq_ignore_ascii_case("::1/128") {
            push_unique("[::1]".to_string());
            continue;
        }
        if let Some((ip_part, prefix_part)) = entry.split_once('/') {
            if let (Ok(v4), Ok(prefix)) = (
                ip_part.trim().parse::<std::net::Ipv4Addr>(),
                prefix_part.trim().parse::<u8>(),
            ) && prefix <= 32
            {
                let oct = v4.octets();
                match prefix {
                    32 => push_unique(v4.to_string()),
                    24 => push_unique(format!("{}.{}.{}.*", oct[0], oct[1], oct[2])),
                    16 => push_unique(format!("{}.{}.*", oct[0], oct[1])),
                    8 => push_unique(format!("{}.*", oct[0])),
                    9..=15 => {
                        let span = 1u16 << (16 - prefix);
                        let base = (oct[1] as u16) & !(span - 1);
                        for second in base..(base + span).min(256) {
                            push_unique(format!("{}.{}.*", oct[0], second));
                        }
                    }
                    17..=23 => {
                        let span = 1u16 << (24 - prefix);
                        let base = (oct[2] as u16) & !(span - 1);
                        for third in base..(base + span).min(256) {
                            push_unique(format!("{}.{}.{}.*", oct[0], oct[1], third));
                        }
                    }
                    _ => {}
                }
                continue;
            }
            if let Ok(v6) = ip_part.trim().parse::<std::net::Ipv6Addr>() {
                if prefix_part.trim() == "128" {
                    push_unique(format!("[{v6}]"));
                } else {
                    let seg0 = v6.segments()[0];
                    if seg0 != 0 {
                        push_unique(format!("[{seg0:x}:*]"));
                    }
                }
                continue;
            }
        }
        if entry.contains(':')
            && !entry.starts_with('[')
            && entry.parse::<std::net::Ipv6Addr>().is_ok()
        {
            push_unique(format!("[{entry}]"));
        } else {
            push_unique(entry.to_string());
        }
    }

    push_unique("<local>".to_string());
    (proxy_server, override_items.join(";"))
}

#[cfg(windows)]
fn wide_nul(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(windows)]
fn enable_windows_sysproxy(
    host: &str,
    port: u16,
    bypass: &[String],
    state_dir: &Path,
) -> io::Result<()> {
    use windows_sys::Win32::{
        Foundation::ERROR_SUCCESS,
        Networking::WinInet::{
            INTERNET_OPTION_REFRESH, INTERNET_OPTION_SETTINGS_CHANGED, InternetSetOptionW,
        },
        System::Registry::{
            HKEY, HKEY_CURRENT_USER, KEY_READ, KEY_WRITE, REG_DWORD, REG_SZ, RegCloseKey,
            RegOpenKeyExW, RegSetValueExW,
        },
    };

    let existing_backup = resolve_or_adopt_sysproxy_backup(state_dir, "windows")?;

    let subkey = wide_nul("Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings");
    let mut hkey: HKEY = std::ptr::null_mut();
    // SAFETY: Standard Win32 HKCU registry open with valid UTF-16 NUL-terminated subkey.
    let rc = unsafe {
        RegOpenKeyExW(
            HKEY_CURRENT_USER,
            subkey.as_ptr(),
            0,
            KEY_READ | KEY_WRITE,
            &mut hkey,
        )
    };
    if rc != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(rc as i32));
    }

    if existing_backup.is_none() {
        let prev_enable = unsafe { query_reg_dword(hkey, "ProxyEnable") };
        let prev_server = unsafe { query_reg_sz(hkey, "ProxyServer") };
        let prev_override = unsafe { query_reg_sz(hkey, "ProxyOverride") };
        if let Err(e) = update_current_journal(state_dir, |j| {
            j.sysproxy = Some(SysProxyRecoveryRecord {
                platform: "windows".to_string(),
                windows_proxy_enable: prev_enable,
                windows_proxy_server: prev_server,
                windows_proxy_override: prev_override,
                ..Default::default()
            });
        }) {
            unsafe {
                let _ = RegCloseKey(hkey);
            }
            return Err(e);
        }
    }

    let (proxy_server, proxy_override) =
        format_windows_proxy_server_and_override(host, port, bypass);

    let enable_val: u32 = 1;
    let enable_name = wide_nul("ProxyEnable");
    let server_name = wide_nul("ProxyServer");
    let server_w = wide_nul(&proxy_server);
    let override_name = wide_nul("ProxyOverride");
    let override_w = wide_nul(&proxy_override);

    // SAFETY: `hkey` is open with `KEY_WRITE`, all names and values are valid NUL-terminated UTF-16 or `u32`.
    unsafe {
        let r1 = RegSetValueExW(
            hkey,
            enable_name.as_ptr(),
            0,
            REG_DWORD,
            (&raw const enable_val).cast::<u8>(),
            std::mem::size_of::<u32>() as u32,
        );
        let r2 = RegSetValueExW(
            hkey,
            server_name.as_ptr(),
            0,
            REG_SZ,
            server_w.as_ptr().cast::<u8>(),
            (server_w.len() * 2) as u32,
        );
        let r3 = RegSetValueExW(
            hkey,
            override_name.as_ptr(),
            0,
            REG_SZ,
            override_w.as_ptr().cast::<u8>(),
            (override_w.len() * 2) as u32,
        );
        let _ = RegCloseKey(hkey);
        if r1 != ERROR_SUCCESS || r2 != ERROR_SUCCESS || r3 != ERROR_SUCCESS {
            return Err(io::Error::other(
                "failed writing Windows Internet Settings proxy registry values",
            ));
        }
        let _ = InternetSetOptionW(
            std::ptr::null_mut(),
            INTERNET_OPTION_SETTINGS_CHANGED,
            std::ptr::null(),
            0,
        );
        let _ = InternetSetOptionW(
            std::ptr::null_mut(),
            INTERNET_OPTION_REFRESH,
            std::ptr::null(),
            0,
        );
    }

    Ok(())
}

#[cfg(windows)]
pub fn restore_windows_sysproxy_record(rec: &SysProxyRecoveryRecord) -> io::Result<()> {
    use windows_sys::Win32::{
        Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS},
        Networking::WinInet::{
            INTERNET_OPTION_REFRESH, INTERNET_OPTION_SETTINGS_CHANGED, InternetSetOptionW,
        },
        System::Registry::{
            HKEY, HKEY_CURRENT_USER, KEY_WRITE, REG_DWORD, REG_SZ, RegCloseKey, RegDeleteValueW,
            RegOpenKeyExW, RegSetValueExW,
        },
    };

    let subkey = wide_nul("Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings");
    let mut hkey: HKEY = std::ptr::null_mut();
    // SAFETY: Standard HKCU registry open.
    let rc = unsafe { RegOpenKeyExW(HKEY_CURRENT_USER, subkey.as_ptr(), 0, KEY_WRITE, &mut hkey) };
    if rc != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(rc as i32));
    }

    let enable_val: u32 = rec.windows_proxy_enable.unwrap_or(0);
    let enable_name = wide_nul("ProxyEnable");
    let server_name = wide_nul("ProxyServer");
    let override_name = wide_nul("ProxyOverride");
    let mut failures: Vec<String> = Vec::new();

    // SAFETY: `hkey` is open with `KEY_WRITE`, all names and values are valid NUL-terminated UTF-16 or `u32`.
    unsafe {
        let r_enable = RegSetValueExW(
            hkey,
            enable_name.as_ptr(),
            0,
            REG_DWORD,
            (&raw const enable_val).cast::<u8>(),
            std::mem::size_of::<u32>() as u32,
        );
        if r_enable != ERROR_SUCCESS {
            failures.push(format!(
                "RegSetValueExW(ProxyEnable) failed: {}",
                io::Error::from_raw_os_error(r_enable as i32)
            ));
        }
        match &rec.windows_proxy_server {
            Some(s) => {
                let sw = wide_nul(s);
                let r_server = RegSetValueExW(
                    hkey,
                    server_name.as_ptr(),
                    0,
                    REG_SZ,
                    sw.as_ptr().cast::<u8>(),
                    (sw.len() * 2) as u32,
                );
                if r_server != ERROR_SUCCESS {
                    failures.push(format!(
                        "RegSetValueExW(ProxyServer) failed: {}",
                        io::Error::from_raw_os_error(r_server as i32)
                    ));
                }
            }
            None => {
                let r_server = RegDeleteValueW(hkey, server_name.as_ptr());
                if r_server != ERROR_SUCCESS && r_server != ERROR_FILE_NOT_FOUND {
                    failures.push(format!(
                        "RegDeleteValueW(ProxyServer) failed: {}",
                        io::Error::from_raw_os_error(r_server as i32)
                    ));
                }
            }
        }
        match &rec.windows_proxy_override {
            Some(s) => {
                let sw = wide_nul(s);
                let r_override = RegSetValueExW(
                    hkey,
                    override_name.as_ptr(),
                    0,
                    REG_SZ,
                    sw.as_ptr().cast::<u8>(),
                    (sw.len() * 2) as u32,
                );
                if r_override != ERROR_SUCCESS {
                    failures.push(format!(
                        "RegSetValueExW(ProxyOverride) failed: {}",
                        io::Error::from_raw_os_error(r_override as i32)
                    ));
                }
            }
            None => {
                let r_override = RegDeleteValueW(hkey, override_name.as_ptr());
                if r_override != ERROR_SUCCESS && r_override != ERROR_FILE_NOT_FOUND {
                    failures.push(format!(
                        "RegDeleteValueW(ProxyOverride) failed: {}",
                        io::Error::from_raw_os_error(r_override as i32)
                    ));
                }
            }
        }
        let _ = RegCloseKey(hkey);
        let _ = InternetSetOptionW(
            std::ptr::null_mut(),
            INTERNET_OPTION_SETTINGS_CHANGED,
            std::ptr::null(),
            0,
        );
        let _ = InternetSetOptionW(
            std::ptr::null_mut(),
            INTERNET_OPTION_REFRESH,
            std::ptr::null(),
            0,
        );
    }

    if !failures.is_empty() {
        return Err(io::Error::other(format!(
            "failed restoring Windows Internet Settings proxy registry values: {}",
            failures.join("; ")
        )));
    }
    Ok(())
}

#[cfg(windows)]
unsafe fn query_reg_dword(
    hkey: windows_sys::Win32::System::Registry::HKEY,
    name: &str,
) -> Option<u32> {
    use windows_sys::Win32::{Foundation::ERROR_SUCCESS, System::Registry::RegQueryValueExW};
    let name_w = wide_nul(name);
    let mut val: u32 = 0;
    let mut len = std::mem::size_of::<u32>() as u32;
    let rc = unsafe {
        RegQueryValueExW(
            hkey,
            name_w.as_ptr(),
            std::ptr::null(),
            std::ptr::null_mut(),
            (&raw mut val).cast::<u8>(),
            &mut len,
        )
    };
    if rc == ERROR_SUCCESS { Some(val) } else { None }
}

#[cfg(windows)]
unsafe fn query_reg_sz(
    hkey: windows_sys::Win32::System::Registry::HKEY,
    name: &str,
) -> Option<String> {
    use windows_sys::Win32::{Foundation::ERROR_SUCCESS, System::Registry::RegQueryValueExW};
    let name_w = wide_nul(name);
    let mut byte_len: u32 = 0;
    let rc0 = unsafe {
        RegQueryValueExW(
            hkey,
            name_w.as_ptr(),
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut byte_len,
        )
    };
    if rc0 != ERROR_SUCCESS || byte_len == 0 {
        return None;
    }
    let mut wbuf = vec![0u16; (byte_len as usize).div_ceil(2) + 1];
    let rc1 = unsafe {
        RegQueryValueExW(
            hkey,
            name_w.as_ptr(),
            std::ptr::null(),
            std::ptr::null_mut(),
            wbuf.as_mut_ptr().cast::<u8>(),
            &mut byte_len,
        )
    };
    if rc1 != ERROR_SUCCESS {
        return None;
    }
    let u16_len = (byte_len as usize) / 2;
    let slice = &wbuf[..u16_len];
    let trimmed_end = slice.iter().position(|&c| c == 0).unwrap_or(slice.len());
    Some(String::from_utf16_lossy(&slice[..trimmed_end]))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockBackend {
        calls: Vec<String>,
    }

    impl SysProxyCommandBackend for MockBackend {
        fn run_capture(&mut self, program: &str, args: &[String]) -> io::Result<String> {
            let cmd = format!("{program} {}", args.join(" "));
            self.calls.push(cmd.clone());
            if cmd == "networksetup -listallnetworkservices" {
                return Ok("An asterisk (*) denotes disabled.\nWi-Fi\n*Unused VPN\n".into());
            }
            if cmd.starts_with("networksetup -getwebproxy") {
                return Ok("Enabled: No\nServer: \nPort: 0\n".into());
            }
            if cmd.starts_with("networksetup -getsecurewebproxy") {
                return Ok("Enabled: Yes\nServer: corp.local\nPort: 8080\n".into());
            }
            if cmd.starts_with("networksetup -getsocksfirewallproxy") {
                return Ok("Enabled: No\nServer: \nPort: 0\n".into());
            }
            if cmd == "gsettings get org.gnome.system.proxy mode" {
                return Ok("'none'\n".into());
            }
            Ok(String::new())
        }
    }

    #[test]
    fn macos_and_linux_sysproxy_journal_backup_and_restore_roundtrip() {
        let dir = std::env::temp_dir().join(format!("rc-sysproxy-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();

        let mut mock = MockBackend { calls: Vec::new() };
        enable_macos_sysproxy_with_backend(
            "127.0.0.1",
            7890,
            &["localhost".into()],
            &dir,
            &mut mock,
        )
        .unwrap();

        let journal = RecoveryJournal::load_from(&dir).unwrap().unwrap();
        let rec = journal.sysproxy.expect("macos sysproxy backup saved");
        assert_eq!(rec.platform, "macos");
        assert_eq!(rec.macos_services.len(), 1);
        assert_eq!(rec.macos_services[0].service_name, "Wi-Fi");
        assert!(rec.macos_services[0].secure_web_enabled);
        assert_eq!(rec.macos_services[0].secure_web_host, "corp.local");
        assert_eq!(rec.macos_services[0].secure_web_port, 8080);

        mock.calls.clear();
        restore_sysproxy_record_with_backend(&rec, &mut mock).unwrap();
        assert!(
            mock.calls
                .iter()
                .any(|c| c == "networksetup -setwebproxystate Wi-Fi off")
        );
        assert!(
            mock.calls
                .iter()
                .any(|c| c == "networksetup -setsecurewebproxy Wi-Fi corp.local 8080")
        );
        assert!(
            mock.calls
                .iter()
                .any(|c| c == "networksetup -setsecurewebproxystate Wi-Fi on")
        );

        // Clear and test Linux gsettings backup & restore
        update_current_journal(&dir, |j| j.sysproxy = None).unwrap();
        mock.calls.clear();
        enable_linux_sysproxy_with_backend(
            "127.0.0.1",
            7890,
            &["localhost".into(), "127.0.0.1".into()],
            &dir,
            &mut mock,
        )
        .unwrap();
        let j_linux = RecoveryJournal::load_from(&dir).unwrap().unwrap();
        let rec_linux = j_linux.sysproxy.unwrap();
        assert_eq!(rec_linux.linux_gnome_mode.as_deref(), Some("none"));

        mock.calls.clear();
        restore_sysproxy_record_with_backend(&rec_linux, &mut mock).unwrap();
        assert_eq!(
            mock.calls,
            vec!["gsettings set org.gnome.system.proxy mode none"]
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sysproxy_restores_macos_bypass_domains_and_linux_ignore_hosts() {
        struct BypassMock {
            calls: Vec<String>,
        }
        impl SysProxyCommandBackend for BypassMock {
            fn run_capture(&mut self, program: &str, args: &[String]) -> io::Result<String> {
                let cmd = format!("{program} {}", args.join(" "));
                self.calls.push(cmd.clone());
                if cmd == "networksetup -listallnetworkservices" {
                    return Ok("An asterisk (*) denotes disabled.\nWi-Fi\n".into());
                }
                if cmd.starts_with("networksetup -getproxybypassdomains") {
                    return Ok("*.corp.internal\n10.0.0.0/8\n".into());
                }
                if cmd.starts_with("networksetup -get") {
                    return Ok("Enabled: No\nServer: \nPort: 0\n".into());
                }
                if cmd == "gsettings get org.gnome.system.proxy mode" {
                    return Ok("'none'\n".into());
                }
                if cmd == "gsettings get org.gnome.system.proxy ignore-hosts" {
                    return Ok("['localhost', '127.0.0.0/8', '.intranet.local']\n".into());
                }
                Ok(String::new())
            }
        }

        let dir = std::env::temp_dir().join(format!("rc-sysproxy-bypass-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut mock = BypassMock { calls: Vec::new() };

        enable_macos_sysproxy_with_backend(
            "127.0.0.1",
            7890,
            &["localhost".into()],
            &dir,
            &mut mock,
        )
        .unwrap();
        let rec_mac = RecoveryJournal::load_from(&dir)
            .unwrap()
            .unwrap()
            .sysproxy
            .unwrap();
        assert_eq!(
            rec_mac.macos_services[0].bypass_domains.as_deref(),
            Some(&["*.corp.internal".to_string(), "10.0.0.0/8".to_string()][..])
        );
        mock.calls.clear();
        restore_sysproxy_record_with_backend(&rec_mac, &mut mock).unwrap();
        assert!(
            mock.calls.iter().any(
                |c| c == "networksetup -setproxybypassdomains Wi-Fi *.corp.internal 10.0.0.0/8"
            )
        );

        update_current_journal(&dir, |j| j.sysproxy = None).unwrap();
        enable_linux_sysproxy_with_backend(
            "127.0.0.1",
            7890,
            &["localhost".into()],
            &dir,
            &mut mock,
        )
        .unwrap();
        let rec_lin = RecoveryJournal::load_from(&dir)
            .unwrap()
            .unwrap()
            .sysproxy
            .unwrap();
        assert_eq!(
            rec_lin.linux_gnome_ignore_hosts.as_deref(),
            Some("['localhost', '127.0.0.0/8', '.intranet.local']")
        );
        mock.calls.clear();
        restore_sysproxy_record_with_backend(&rec_lin, &mut mock).unwrap();
        assert!(mock.calls.contains(
            &"gsettings set org.gnome.system.proxy ignore-hosts ['localhost', '127.0.0.0/8', '.intranet.local']"
                .to_string()
        ));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn gnome_host_port_and_kde_kioslaverc_backup_restore_and_serde_compat() {
        assert!(is_kde_desktop_env(Some("KDE"), None, None));
        assert!(is_kde_desktop_env(None, Some("plasma"), None));
        assert!(is_kde_desktop_env(None, None, Some("true")));
        assert!(!is_kde_desktop_env(
            Some("GNOME"),
            Some("gnome"),
            Some("false")
        ));

        // 1. Legacy JSON without `linux_gnome_{http,https,socks}` or `linux_kde` deserializes cleanly
        let legacy_json = r#"{
            "platform": "linux",
            "windows_proxy_enable": null,
            "windows_proxy_server": null,
            "windows_proxy_override": null,
            "macos_services": [],
            "linux_gnome_mode": "none"
        }"#;
        let legacy_rec: SysProxyRecoveryRecord = serde_json::from_str(legacy_json).unwrap();
        assert_eq!(legacy_rec.linux_gnome_mode.as_deref(), Some("none"));
        assert!(legacy_rec.linux_gnome_http.is_none());
        assert!(legacy_rec.linux_kde.is_none());

        // 2. Full GNOME `http/https/socks` `host` & `port` backup and restore roundtrip
        struct GnomeFullMock {
            calls: Vec<String>,
        }
        impl SysProxyCommandBackend for GnomeFullMock {
            fn run_capture(&mut self, program: &str, args: &[String]) -> io::Result<String> {
                let cmd = format!("{program} {}", args.join(" "));
                self.calls.push(cmd.clone());
                match cmd.as_str() {
                    "gsettings get org.gnome.system.proxy mode" => Ok("'manual'\n".into()),
                    "gsettings get org.gnome.system.proxy ignore-hosts" => {
                        Ok("['localhost', '10.0.0.0/8']\n".into())
                    }
                    "gsettings get org.gnome.system.proxy.http host" => {
                        Ok("'corp-http.internal'\n".into())
                    }
                    "gsettings get org.gnome.system.proxy.http port" => Ok("3128\n".into()),
                    "gsettings get org.gnome.system.proxy.https host" => {
                        Ok("'corp-https.internal'\n".into())
                    }
                    "gsettings get org.gnome.system.proxy.https port" => Ok("8443\n".into()),
                    "gsettings get org.gnome.system.proxy.socks host" => Ok("''\n".into()),
                    "gsettings get org.gnome.system.proxy.socks port" => Ok("0\n".into()),
                    _ => Ok(String::new()),
                }
            }
        }

        let dir =
            std::env::temp_dir().join(format!("rc-sysproxy-gnome-kde-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();

        let mut gnome_mock = GnomeFullMock { calls: Vec::new() };
        enable_linux_sysproxy_with_env(
            "127.0.0.1",
            7890,
            &["localhost".into()],
            &dir,
            false,
            &mut gnome_mock,
        )
        .unwrap();

        let rec_gnome = RecoveryJournal::load_from(&dir)
            .unwrap()
            .unwrap()
            .sysproxy
            .unwrap();
        assert_eq!(
            rec_gnome.linux_gnome_http,
            Some(LinuxGnomeProtoBackup {
                host: Some("corp-http.internal".into()),
                port: Some(3128),
            })
        );
        assert_eq!(
            rec_gnome.linux_gnome_https,
            Some(LinuxGnomeProtoBackup {
                host: Some("corp-https.internal".into()),
                port: Some(8443),
            })
        );
        assert_eq!(
            rec_gnome.linux_gnome_socks,
            Some(LinuxGnomeProtoBackup {
                host: Some(String::new()),
                port: Some(0),
            })
        );

        gnome_mock.calls.clear();
        restore_sysproxy_record_with_backend(&rec_gnome, &mut gnome_mock).unwrap();
        for expected in [
            "gsettings set org.gnome.system.proxy.http host corp-http.internal",
            "gsettings set org.gnome.system.proxy.http port 3128",
            "gsettings set org.gnome.system.proxy.https host corp-https.internal",
            "gsettings set org.gnome.system.proxy.https port 8443",
            "gsettings set org.gnome.system.proxy.socks host ",
            "gsettings set org.gnome.system.proxy.socks port 0",
            "gsettings set org.gnome.system.proxy ignore-hosts ['localhost', '10.0.0.0/8']",
            "gsettings set org.gnome.system.proxy mode manual",
        ] {
            assert!(
                gnome_mock.calls.iter().any(|c| c == expected),
                "missing expected GNOME restore call `{expected}` in {:?}",
                gnome_mock.calls
            );
        }

        // 3. Pure KDE Plasma (`kreadconfig6`/`kwriteconfig6` `kioslaverc` when `gsettings` is absent)
        struct PureKde6Mock {
            calls: Vec<String>,
        }
        impl SysProxyCommandBackend for PureKde6Mock {
            fn run_capture(&mut self, program: &str, args: &[String]) -> io::Result<String> {
                let cmd = format!("{program} {}", args.join(" "));
                self.calls.push(cmd.clone());
                if program == "gsettings" {
                    return Err(io::Error::new(io::ErrorKind::NotFound, "no gsettings"));
                }
                if program == "kreadconfig6" {
                    if args.iter().any(|a| a == "ProxyType") {
                        return Ok("2\n".into());
                    }
                    if args.iter().any(|a| a == "httpProxy") {
                        return Ok("http://old.kde.local:8000\n".into());
                    }
                    return Ok("\n".into());
                }
                Ok(String::new())
            }
        }

        update_current_journal(&dir, |j| j.sysproxy = None).unwrap();
        let mut kde_mock = PureKde6Mock { calls: Vec::new() };
        enable_linux_sysproxy_with_env(
            "127.0.0.1",
            7890,
            &["localhost".into(), "*.local".into()],
            &dir,
            true,
            &mut kde_mock,
        )
        .unwrap();

        assert!(kde_mock.calls.iter().any(
            |c| c == "kwriteconfig6 --file kioslaverc --group Proxy Settings --key httpProxy http://127.0.0.1:7890"
        ));
        assert!(kde_mock.calls.iter().any(
            |c| c == "kwriteconfig6 --file kioslaverc --group Proxy Settings --key socksProxy socks://127.0.0.1:7890"
        ));
        assert!(kde_mock.calls.iter().any(
            |c| c == "kwriteconfig6 --file kioslaverc --group Proxy Settings --key NoProxyFor localhost,.local"
        ));
        assert!(kde_mock.calls.iter().any(
            |c| c == "kwriteconfig6 --file kioslaverc --group Proxy Settings --key ProxyType 1"
        ));

        let rec_kde = RecoveryJournal::load_from(&dir)
            .unwrap()
            .unwrap()
            .sysproxy
            .unwrap();
        assert!(rec_kde.linux_gnome_mode.is_none());
        assert_eq!(
            rec_kde
                .linux_kde
                .as_ref()
                .and_then(|k| k.proxy_type.as_deref()),
            Some("2")
        );

        kde_mock.calls.clear();
        restore_sysproxy_record_with_backend(&rec_kde, &mut kde_mock).unwrap();
        assert!(
            kde_mock.calls.iter().all(|c| !c.starts_with("gsettings ")),
            "pure KDE restore must not invoke gsettings: {:?}",
            kde_mock.calls
        );
        assert!(kde_mock.calls.iter().any(
            |c| c == "kwriteconfig6 --file kioslaverc --group Proxy Settings --key httpProxy http://old.kde.local:8000"
        ));
        assert!(kde_mock.calls.iter().any(
            |c| c == "kwriteconfig6 --file kioslaverc --group Proxy Settings --key ProxyType 2"
        ));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn windows_proxy_formatter_brackets_ipv6_and_expands_cidr_bypass() {
        let mut bypass = default_proxy_bypass_list();
        bypass.push("127.0.0.0/8".to_string());
        let (srv_v6, ovr) = format_windows_proxy_server_and_override("::1", 7890, &bypass);
        assert_eq!(srv_v6, "[::1]:7890");
        let items: Vec<&str> = ovr.split(';').collect();
        assert!(items.contains(&"127.0.0.1"));
        assert!(items.contains(&"127.*"));
        assert!(items.contains(&"10.*"));
        assert!(items.contains(&"172.16.*"));
        assert!(items.contains(&"172.31.*"));
        assert!(items.contains(&"192.168.*"));
        assert!(items.contains(&"[::1]"));
        assert!(items.contains(&"<local>"));
        assert!(
            items.iter().all(|s| !s.contains('/')),
            "WinINET ProxyOverride must not contain raw CIDR slashes: {ovr}"
        );
    }

    #[test]
    fn restore_macos_collects_errors_best_effort_and_tolerates_unplugged_service() {
        struct MacRestoreMock {
            calls: Vec<String>,
            fail_wifi_web_state: bool,
        }
        impl SysProxyCommandBackend for MacRestoreMock {
            fn run_capture(&mut self, program: &str, args: &[String]) -> io::Result<String> {
                let cmd = format!("{program} {}", args.join(" "));
                self.calls.push(cmd.clone());
                if args.iter().any(|a| a == "USB 10/100/1000 LAN") {
                    return Err(io::Error::other(
                        "USB 10/100/1000 LAN is not a recognized network service.",
                    ));
                }
                if self.fail_wifi_web_state && cmd == "networksetup -setwebproxystate Wi-Fi off" {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "authorization denied for Wi-Fi",
                    ));
                }
                Ok(String::new())
            }
        }

        let rec = SysProxyRecoveryRecord {
            platform: "macos".into(),
            macos_services: vec![
                MacOsProxyServiceBackup {
                    service_name: "USB 10/100/1000 LAN".into(),
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
                },
                MacOsProxyServiceBackup {
                    service_name: "Wi-Fi".into(),
                    web_enabled: false,
                    web_host: String::new(),
                    web_port: 0,
                    secure_web_enabled: true,
                    secure_web_host: "corp.local".into(),
                    secure_web_port: 8443,
                    socks_enabled: false,
                    socks_host: String::new(),
                    socks_port: 0,
                    bypass_domains: Some(vec!["*.corp.local".into()]),
                },
            ],
            ..Default::default()
        };

        // Unplugged USB adapter is tolerated, while Wi-Fi authorization error MUST be returned
        // AND remaining Wi-Fi commands must still be attempted best-effort.
        let mut failing = MacRestoreMock {
            calls: Vec::new(),
            fail_wifi_web_state: true,
        };
        let err = restore_sysproxy_record_with_backend(&rec, &mut failing)
            .expect_err("non-benign macOS networksetup failure must not be swallowed");
        let msg = err.to_string();
        assert!(msg.contains("Wi-Fi"), "unexpected error: {msg}");
        assert!(
            !msg.contains("USB 10/100/1000 LAN"),
            "benign unplugged service must not pollute failures: {msg}"
        );
        assert!(
            failing
                .calls
                .iter()
                .any(|c| c == "networksetup -setsecurewebproxy Wi-Fi corp.local 8443"),
            "remaining Wi-Fi restore calls must still be attempted best-effort"
        );
        assert!(
            failing
                .calls
                .iter()
                .any(|c| c == "networksetup -setproxybypassdomains Wi-Fi *.corp.local"),
            "bypass domain restore must still be attempted best-effort"
        );

        // When only the unplugged USB service fails with missing-service error, restore succeeds.
        let mut benign_only = MacRestoreMock {
            calls: Vec::new(),
            fail_wifi_web_state: false,
        };
        restore_sysproxy_record_with_backend(&rec, &mut benign_only)
            .expect("unplugged macOS service error should be tolerated");
    }

    #[test]
    fn restore_linux_gnome_and_kde_propagate_errors_while_dbus_send_is_best_effort() {
        struct LinuxErrMock {
            calls: Vec<String>,
            fail_gsettings_mode: bool,
            fail_kwrite_proxy_type: bool,
            fail_dbus_send: bool,
        }
        impl SysProxyCommandBackend for LinuxErrMock {
            fn run_capture(&mut self, program: &str, args: &[String]) -> io::Result<String> {
                let cmd = format!("{program} {}", args.join(" "));
                self.calls.push(cmd.clone());
                if self.fail_gsettings_mode
                    && cmd == "gsettings set org.gnome.system.proxy mode none"
                {
                    return Err(io::Error::other("dconf unavailable: no D-Bus session"));
                }
                if self.fail_kwrite_proxy_type
                    && program == "kwriteconfig6"
                    && args.iter().any(|a| a == "ProxyType")
                {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "kioslaverc read-only",
                    ));
                }
                if self.fail_dbus_send && program == "dbus-send" {
                    return Err(io::Error::new(io::ErrorKind::NotFound, "dbus-send missing"));
                }
                Ok(String::new())
            }
        }

        let rec = SysProxyRecoveryRecord {
            platform: "linux".into(),
            linux_gnome_mode: Some("none".into()),
            linux_gnome_http: Some(LinuxGnomeProtoBackup {
                host: Some("127.0.0.1".into()),
                port: Some(3128),
            }),
            linux_kde: Some(LinuxKdeProxyBackup {
                tool_generation: 6,
                proxy_type: Some("0".into()),
                http_proxy: Some(String::new()),
                https_proxy: None,
                socks_proxy: None,
                no_proxy_for: None,
            }),
            ..Default::default()
        };

        // 1. GNOME `gsettings` error is propagated while KDE keys are still attempted best-effort.
        let mut m1 = LinuxErrMock {
            calls: Vec::new(),
            fail_gsettings_mode: true,
            fail_kwrite_proxy_type: false,
            fail_dbus_send: false,
        };
        let err1 = restore_sysproxy_record_with_backend(&rec, &mut m1)
            .expect_err("gsettings failure must return Err");
        assert!(err1.to_string().contains("gsettings"));
        assert!(
            m1.calls.iter().any(|c| c.starts_with("kwriteconfig6 ")),
            "KDE restore must still be attempted after gsettings error"
        );

        // 2. KDE `kwriteconfig6` error is propagated.
        let mut m2 = LinuxErrMock {
            calls: Vec::new(),
            fail_gsettings_mode: false,
            fail_kwrite_proxy_type: true,
            fail_dbus_send: false,
        };
        let err2 = restore_sysproxy_record_with_backend(&rec, &mut m2)
            .expect_err("kwriteconfig6 failure must return Err");
        assert!(err2.to_string().contains("kwriteconfig6"));

        // 3. `dbus-send` failure alone is best-effort and must NOT fail KDE restore.
        let mut m3 = LinuxErrMock {
            calls: Vec::new(),
            fail_gsettings_mode: false,
            fail_kwrite_proxy_type: false,
            fail_dbus_send: true,
        };
        restore_sysproxy_record_with_backend(&rec, &mut m3)
            .expect("dbus-send failure must remain best-effort");
    }

    #[test]
    fn disable_system_proxy_preserves_journal_and_active_meta_on_failure_and_clears_on_retry() {
        struct ToggleFailBackend {
            fail_restore: bool,
            calls: Vec<String>,
        }
        impl SysProxyCommandBackend for ToggleFailBackend {
            fn run_capture(&mut self, program: &str, args: &[String]) -> io::Result<String> {
                let cmd = format!("{program} {}", args.join(" "));
                self.calls.push(cmd.clone());
                if cmd == "gsettings get org.gnome.system.proxy mode" {
                    return Ok("'none'\n".into());
                }
                if self.fail_restore && cmd.starts_with("gsettings set ") {
                    return Err(io::Error::other("D-Bus session temporarily unreachable"));
                }
                Ok(String::new())
            }
        }

        let dir = std::env::temp_dir().join(format!(
            "rc-sysproxy-disable-preserve-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap();

        let mut backend = ToggleFailBackend {
            fail_restore: false,
            calls: Vec::new(),
        };
        enable_linux_sysproxy_with_env(
            "127.0.0.1",
            7890,
            &["localhost".into()],
            &dir,
            false,
            &mut backend,
        )
        .unwrap();
        let meta_path = dir.join("sysproxy_active.json");
        std::fs::write(
            &meta_path,
            serde_json::to_vec(&(
                "127.0.0.1".to_string(),
                7890u16,
                vec!["localhost".to_string()],
            ))
            .unwrap(),
        )
        .unwrap();

        // Failing restore MUST NOT clear `network_recovery.json` or delete `sysproxy_active.json`!
        backend.fail_restore = true;
        let err = disable_system_proxy_with_backend(&dir, &mut backend)
            .expect_err("disable_system_proxy must surface OS restore failure");
        assert!(
            err.to_string()
                .contains("D-Bus session temporarily unreachable")
        );
        assert!(
            meta_path.exists(),
            "sysproxy_active.json must be preserved when restore fails"
        );
        let retained = RecoveryJournal::load_from(&dir)
            .unwrap()
            .expect("network_recovery.json must remain on disk after failed disable");
        assert!(retained.sysproxy.is_some());

        // Subsequent retry succeeds and cleans up both `network_recovery.json` and `sysproxy_active.json`.
        backend.fail_restore = false;
        let status = disable_system_proxy_with_backend(&dir, &mut backend)
            .expect("retry disable_system_proxy should succeed");
        assert!(!status.enabled);
        assert!(!meta_path.exists());
        assert!(RecoveryJournal::load_from(&dir).unwrap().is_none());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn query_sysproxy_status_exposes_sentinel_zero_and_hides_foreign_nonzero_pids() {
        use crate::platform::recovery::{
            LinuxRecoveryRecord, recover_stale_network_state_with_runner,
        };

        let dir = std::env::temp_dir().join(format!(
            "rc-sysproxy-sentinel-status-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap();

        let original_backup = SysProxyRecoveryRecord {
            platform: "linux".into(),
            linux_gnome_mode: Some("none".into()),
            linux_gnome_http: Some(LinuxGnomeProtoBackup {
                host: Some("corp.internal".into()),
                port: Some(8080),
            }),
            ..Default::default()
        };

        let dead_foreign_pid = 999_999_991u32;
        let mut dead_j = RecoveryJournal::new_for_pid(dead_foreign_pid);
        dead_j.sysproxy = Some(original_backup.clone());
        dead_j.save_atomic(&dir).unwrap();

        let meta_path = dir.join("sysproxy_active.json");
        let active_bypass = vec!["localhost".to_string(), "10.0.0.0/8".to_string()];
        std::fs::write(
            &meta_path,
            serde_json::to_vec(&("127.0.0.1".to_string(), 7890u16, active_bypass.clone())).unwrap(),
        )
        .unwrap();

        // 1. Non-zero foreign PID (dead or live) must still report `enabled: false`.
        let before_recovery = query_sysproxy_status(&dir);
        assert!(!before_recovery.enabled);
        assert_eq!(before_recovery.host, None);
        assert_eq!(before_recovery.port, None);

        // 2. Failed startup crash recovery retains the original backup under sentinel PID `0`
        //    alongside `sysproxy_active.json`; `query_sysproxy_status` must expose it as enabled!
        let outcome = recover_stale_network_state_with_runner(&dir, &mut |_prog, _args| {
            Err(io::Error::other("dconf unavailable"))
        });
        assert!(outcome.found_stale_journal);
        assert!(!outcome.warnings.is_empty());
        let retained = RecoveryJournal::load_from(&dir)
            .unwrap()
            .expect("sentinel-0 journal must remain on disk");
        assert_eq!(retained.effective_sysproxy_pid(), 0);
        assert_eq!(retained.sysproxy.as_ref(), Some(&original_backup));

        let sentinel_status = query_sysproxy_status(&dir);
        assert!(sentinel_status.enabled);
        assert_eq!(sentinel_status.host.as_deref(), Some("127.0.0.1"));
        assert_eq!(sentinel_status.port, Some(7890));
        assert_eq!(sentinel_status.bypass, active_bypass);

        // 3. Subsequent `disable_system_proxy_with_backend` clears sentinel-0 backup cleanly.
        let mut ok_backend = MockBackend { calls: Vec::new() };
        let after_disable = disable_system_proxy_with_backend(&dir, &mut ok_backend).unwrap();
        assert!(!after_disable.enabled);
        assert_eq!(after_disable.host, None);
        assert_eq!(after_disable.port, None);
        assert!(!meta_path.exists());
        assert!(RecoveryJournal::load_from(&dir).unwrap().is_none());

        // 4. Sentinel-0 TUN-only journal (with `sysproxy: None`) must NOT report sysproxy enabled.
        let mut tun_only_sentinel = RecoveryJournal::new_for_pid(0);
        tun_only_sentinel.linux_tun = Some(LinuxRecoveryRecord {
            device_name: "utun-clash".into(),
            route_table_id: 2022,
            fwmark: 0x1a5,
            owned_v4_rule_del_args: vec![vec![
                "fwmark".into(),
                "421".into(),
                "table".into(),
                "main".into(),
            ]],
            owned_v6_rule_del_args: Vec::new(),
            owned_route_del_args: Vec::new(),
        });
        tun_only_sentinel.save_atomic(&dir).unwrap();
        let tun_only_status = query_sysproxy_status(&dir);
        assert!(!tun_only_status.enabled);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn enable_linux_and_macos_preserve_sentinel_zero_and_dead_foreign_backups_and_promote_owner() {
        use crate::platform::recovery::{
            LinuxRecoveryRecord, recover_stale_network_state_with_runner,
        };

        struct MutatedOsBackend {
            calls: Vec<String>,
        }
        impl SysProxyCommandBackend for MutatedOsBackend {
            fn run_capture(&mut self, program: &str, args: &[String]) -> io::Result<String> {
                let cmd = format!("{program} {}", args.join(" "));
                self.calls.push(cmd.clone());
                match cmd.as_str() {
                    // Simulated already-mutated Linux GNOME state pointing at rust-clash
                    "gsettings get org.gnome.system.proxy mode" => Ok("'manual'\n".into()),
                    "gsettings get org.gnome.system.proxy ignore-hosts" => {
                        Ok("['localhost']\n".into())
                    }
                    "gsettings get org.gnome.system.proxy.http host"
                    | "gsettings get org.gnome.system.proxy.https host"
                    | "gsettings get org.gnome.system.proxy.socks host" => {
                        Ok("'127.0.0.1'\n".into())
                    }
                    "gsettings get org.gnome.system.proxy.http port"
                    | "gsettings get org.gnome.system.proxy.https port"
                    | "gsettings get org.gnome.system.proxy.socks port" => Ok("7890\n".into()),
                    // Simulated already-mutated macOS Wi-Fi state pointing at rust-clash
                    "networksetup -listallnetworkservices" => {
                        Ok("An asterisk (*) denotes disabled.\nWi-Fi\n".into())
                    }
                    "networksetup -getwebproxy Wi-Fi"
                    | "networksetup -getsecurewebproxy Wi-Fi"
                    | "networksetup -getsocksfirewallproxy Wi-Fi" => {
                        Ok("Enabled: Yes\nServer: 127.0.0.1\nPort: 7890\n".into())
                    }
                    "networksetup -getproxybypassdomains Wi-Fi" => Ok("localhost\n".into()),
                    _ => Ok(String::new()),
                }
            }
        }

        let dir =
            std::env::temp_dir().join(format!("rc-sysproxy-adopt-backup-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();

        // --- 1. Linux sentinel-0 adoption ---
        let orig_linux = SysProxyRecoveryRecord {
            platform: "linux".into(),
            linux_gnome_mode: Some("none".into()),
            linux_gnome_ignore_hosts: Some("['localhost', '.corp.internal']".into()),
            linux_gnome_http: Some(LinuxGnomeProtoBackup {
                host: Some("corp-proxy.internal".into()),
                port: Some(8080),
            }),
            ..Default::default()
        };
        let mut dead_linux = RecoveryJournal::new_for_pid(999_999_991);
        dead_linux.sysproxy = Some(orig_linux.clone());
        dead_linux.save_atomic(&dir).unwrap();
        let _ = recover_stale_network_state_with_runner(&dir, &mut |_p, _a| {
            Err(io::Error::other("D-Bus unavailable"))
        });
        assert_eq!(
            RecoveryJournal::load_from(&dir)
                .unwrap()
                .unwrap()
                .effective_sysproxy_pid(),
            0
        );

        let mut mutated = MutatedOsBackend { calls: Vec::new() };
        enable_linux_sysproxy_with_env(
            "127.0.0.1",
            7891,
            &["localhost".into()],
            &dir,
            false,
            &mut mutated,
        )
        .unwrap();

        let adopted_linux = RecoveryJournal::load_from(&dir).unwrap().unwrap();
        assert_eq!(adopted_linux.effective_sysproxy_pid(), std::process::id());
        assert_eq!(adopted_linux.sysproxy.as_ref(), Some(&orig_linux));
        assert!(
            mutated
                .calls
                .iter()
                .all(|c| !c.starts_with("gsettings get org.gnome.system.proxy.http ")),
            "must not re-snapshot already-mutated GNOME proxy: {:?}",
            mutated.calls
        );
        assert!(
            mutated
                .calls
                .iter()
                .any(|c| c == "gsettings set org.gnome.system.proxy.http port 7891")
        );

        // --- 2. Linux dead-foreign PID direct adoption (preserving foreign dead TUN too) ---
        let dead_tun_pid = 999_999_992u32;
        let dead_tun = LinuxRecoveryRecord {
            device_name: "utun-dead".into(),
            route_table_id: 2022,
            fwmark: 0x1a5,
            owned_v4_rule_del_args: vec![vec![
                "fwmark".into(),
                "421".into(),
                "table".into(),
                "main".into(),
            ]],
            owned_v6_rule_del_args: Vec::new(),
            owned_route_del_args: Vec::new(),
        };
        let mut dead_mixed = RecoveryJournal::new_for_pid(dead_tun_pid);
        dead_mixed.linux_tun = Some(dead_tun.clone());
        dead_mixed.sysproxy = Some(orig_linux.clone());
        dead_mixed.save_atomic(&dir).unwrap();

        mutated.calls.clear();
        enable_linux_sysproxy_with_env(
            "127.0.0.1",
            7892,
            &["localhost".into()],
            &dir,
            false,
            &mut mutated,
        )
        .unwrap();
        let after_dead_linux = RecoveryJournal::load_from(&dir).unwrap().unwrap();
        assert_eq!(
            after_dead_linux.effective_sysproxy_pid(),
            std::process::id()
        );
        assert_eq!(after_dead_linux.sysproxy.as_ref(), Some(&orig_linux));
        assert_eq!(after_dead_linux.effective_tun_pid(), dead_tun_pid);
        assert_eq!(after_dead_linux.linux_tun.as_ref(), Some(&dead_tun));

        // --- 3. macOS sentinel-0 and dead-foreign adoption ---
        let orig_macos = SysProxyRecoveryRecord {
            platform: "macos".into(),
            macos_services: vec![MacOsProxyServiceBackup {
                service_name: "Wi-Fi".into(),
                web_enabled: false,
                web_host: String::new(),
                web_port: 0,
                secure_web_enabled: true,
                secure_web_host: "corp.local".into(),
                secure_web_port: 8443,
                socks_enabled: false,
                socks_host: String::new(),
                socks_port: 0,
                bypass_domains: Some(vec!["*.corp.local".into()]),
            }],
            ..Default::default()
        };
        for initial_pid in [0u32, 999_999_993u32] {
            let mut j = RecoveryJournal::new_for_pid(initial_pid);
            j.sysproxy = Some(orig_macos.clone());
            j.save_atomic(&dir).unwrap();

            mutated.calls.clear();
            enable_macos_sysproxy_with_backend(
                "127.0.0.1",
                7891,
                &["localhost".into()],
                &dir,
                &mut mutated,
            )
            .unwrap();

            let adopted_mac = RecoveryJournal::load_from(&dir).unwrap().unwrap();
            assert_eq!(adopted_mac.effective_sysproxy_pid(), std::process::id());
            assert_eq!(adopted_mac.sysproxy.as_ref(), Some(&orig_macos));
            assert!(
                mutated
                    .calls
                    .iter()
                    .all(|c| !c.starts_with("networksetup -get")),
                "must not re-snapshot already-mutated macOS proxy (pid={initial_pid}): {:?}",
                mutated.calls
            );
            assert!(
                mutated
                    .calls
                    .iter()
                    .any(|c| c == "networksetup -setwebproxy Wi-Fi 127.0.0.1 7891")
            );
        }

        // --- 4. Windows sentinel-0 adoption + cross-platform stale replacement + corrupt journal ---
        let orig_windows = SysProxyRecoveryRecord {
            platform: "windows".into(),
            windows_proxy_enable: Some(0),
            windows_proxy_server: Some("corp-win.internal:8080".into()),
            windows_proxy_override: Some("<local>".into()),
            ..Default::default()
        };
        let mut win_sentinel = RecoveryJournal::new_for_pid(0);
        win_sentinel.sysproxy = Some(orig_windows.clone());
        win_sentinel.save_atomic(&dir).unwrap();

        let adopted_win = resolve_or_adopt_sysproxy_backup(&dir, "windows")
            .unwrap()
            .expect("sentinel-0 windows backup should be adopted");
        assert_eq!(adopted_win, orig_windows);
        let after_win = RecoveryJournal::load_from(&dir).unwrap().unwrap();
        assert_eq!(after_win.effective_sysproxy_pid(), std::process::id());
        assert_eq!(after_win.sysproxy.as_ref(), Some(&orig_windows));

        // Cross-platform stale sentinel-0 entry returns Ok(None) so fresh snapshot replaces it.
        let mut cross_plat = RecoveryJournal::new_for_pid(0);
        cross_plat.sysproxy = Some(orig_macos.clone());
        cross_plat.save_atomic(&dir).unwrap();
        assert_eq!(
            resolve_or_adopt_sysproxy_backup(&dir, "linux").unwrap(),
            None
        );

        // Corrupt journal returns Ok(None) cleanly without panicking.
        std::fs::write(RecoveryJournal::path_in(&dir), "{corrupt-json").unwrap();
        assert_eq!(
            resolve_or_adopt_sysproxy_backup(&dir, "linux").unwrap(),
            None
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn enable_linux_and_macos_reject_live_foreign_pid_without_mutating_journal_or_os() {
        struct RecordingBackend {
            calls: Vec<String>,
        }
        impl SysProxyCommandBackend for RecordingBackend {
            fn run_capture(&mut self, program: &str, args: &[String]) -> io::Result<String> {
                self.calls.push(format!("{program} {}", args.join(" ")));
                Ok(String::new())
            }
        }

        let dir =
            std::env::temp_dir().join(format!("rc-sysproxy-live-foreign-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();

        let foreign_pid = if std::process::id() == 42_424 {
            42_425
        } else {
            42_424
        };
        let foreign_linux_backup = SysProxyRecoveryRecord {
            platform: "linux".into(),
            linux_gnome_mode: Some("none".into()),
            linux_gnome_http: Some(LinuxGnomeProtoBackup {
                host: Some("foreign-corp.internal".into()),
                port: Some(3128),
            }),
            ..Default::default()
        };
        let mut foreign_j = RecoveryJournal::new_for_pid(foreign_pid);
        foreign_j.sysproxy = Some(foreign_linux_backup.clone());
        foreign_j.save_atomic(&dir).unwrap();
        let raw_before = std::fs::read_to_string(RecoveryJournal::path_in(&dir)).unwrap();

        let mut backend = RecordingBackend { calls: Vec::new() };
        let err_linux = enable_linux_sysproxy_with_env_and_liveness(
            "127.0.0.1",
            7890,
            &["localhost".into()],
            &dir,
            false,
            &mut backend,
            |pid| pid == foreign_pid,
        )
        .expect_err("live foreign sysproxy owner must block Linux enable");
        assert_eq!(err_linux.kind(), io::ErrorKind::PermissionDenied);
        assert!(
            backend.calls.is_empty(),
            "no OS command may run when live foreign PID owns sysproxy: {:?}",
            backend.calls
        );
        assert_eq!(
            std::fs::read_to_string(RecoveryJournal::path_in(&dir)).unwrap(),
            raw_before,
            "network_recovery.json must remain byte-for-byte untouched"
        );

        let err_macos = enable_macos_sysproxy_with_backend_and_liveness(
            "127.0.0.1",
            7890,
            &["localhost".into()],
            &dir,
            &mut backend,
            |pid| pid == foreign_pid,
        )
        .expect_err("live foreign sysproxy owner must block macOS enable");
        assert_eq!(err_macos.kind(), io::ErrorKind::PermissionDenied);
        assert!(
            backend.calls.is_empty(),
            "no OS command may run when live foreign PID owns sysproxy: {:?}",
            backend.calls
        );
        assert_eq!(
            std::fs::read_to_string(RecoveryJournal::path_in(&dir)).unwrap(),
            raw_before
        );

        let err_win = resolve_or_adopt_sysproxy_backup_with_liveness(&dir, "windows", |pid| {
            pid == foreign_pid
        })
        .expect_err("live foreign sysproxy owner must block Windows backup adoption");
        assert_eq!(err_win.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(
            std::fs::read_to_string(RecoveryJournal::path_in(&dir)).unwrap(),
            raw_before
        );

        // Also exercise public entrypoints against a genuine live foreign OS PID on Unix.
        #[cfg(unix)]
        {
            let ppid = std::os::unix::process::parent_id();
            let real_live_foreign_pid = if ppid != 0
                && ppid != std::process::id()
                && crate::platform::recovery::is_pid_alive(ppid)
            {
                ppid
            } else {
                assert_ne!(std::process::id(), 1);
                assert!(crate::platform::recovery::is_pid_alive(1));
                1
            };

            let mut real_foreign_j = RecoveryJournal::new_for_pid(real_live_foreign_pid);
            real_foreign_j.sysproxy = Some(foreign_linux_backup.clone());
            real_foreign_j.save_atomic(&dir).unwrap();
            let real_raw_before = std::fs::read_to_string(RecoveryJournal::path_in(&dir)).unwrap();

            let err_pub_linux = enable_linux_sysproxy_with_env(
                "127.0.0.1",
                7890,
                &["localhost".into()],
                &dir,
                false,
                &mut backend,
            )
            .expect_err("public enable_linux_sysproxy_with_env must reject live foreign OS PID");
            assert_eq!(err_pub_linux.kind(), io::ErrorKind::PermissionDenied);
            assert!(backend.calls.is_empty());
            assert_eq!(
                std::fs::read_to_string(RecoveryJournal::path_in(&dir)).unwrap(),
                real_raw_before
            );

            let err_pub_macos = enable_macos_sysproxy_with_backend(
                "127.0.0.1",
                7890,
                &["localhost".into()],
                &dir,
                &mut backend,
            )
            .expect_err(
                "public enable_macos_sysproxy_with_backend must reject live foreign OS PID",
            );
            assert_eq!(err_pub_macos.kind(), io::ErrorKind::PermissionDenied);
            assert!(backend.calls.is_empty());
            assert_eq!(
                std::fs::read_to_string(RecoveryJournal::path_in(&dir)).unwrap(),
                real_raw_before
            );
        }

        // Verify that sentinel-0 stays unmutated if Linux desktop helpers are still unavailable.
        struct UnavailableBackend;
        impl SysProxyCommandBackend for UnavailableBackend {
            fn run_capture(&mut self, _program: &str, _args: &[String]) -> io::Result<String> {
                Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "helper unavailable",
                ))
            }
        }
        let mut sentinel_j = RecoveryJournal::new_for_pid(0);
        sentinel_j.sysproxy = Some(foreign_linux_backup.clone());
        sentinel_j.save_atomic(&dir).unwrap();
        let mut unavailable = UnavailableBackend;
        let err_unavail = enable_linux_sysproxy_with_env(
            "127.0.0.1",
            7890,
            &["localhost".into()],
            &dir,
            false,
            &mut unavailable,
        )
        .expect_err("unavailable Linux helpers should return Unsupported");
        assert_eq!(err_unavail.kind(), io::ErrorKind::Unsupported);
        let retained_sentinel = RecoveryJournal::load_from(&dir).unwrap().unwrap();
        assert_eq!(retained_sentinel.effective_sysproxy_pid(), 0);
        assert_eq!(
            retained_sentinel.sysproxy.as_ref(),
            Some(&foreign_linux_backup)
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn linux_gnome_sentinel_zero_to_kde_fallback_and_plasma_augments_kde_before_mutation() {
        use crate::platform::recovery::recover_stale_network_state_with_runner;

        struct LinuxKdeAugmentBackend {
            state_dir: std::path::PathBuf,
            gnome_available: bool,
            calls: Vec<String>,
            journal_at_first_mutation: Option<SysProxyRecoveryRecord>,
        }
        impl SysProxyCommandBackend for LinuxKdeAugmentBackend {
            fn run_capture(&mut self, program: &str, args: &[String]) -> io::Result<String> {
                let cmd = format!("{program} {}", args.join(" "));
                let is_mutation = (program == "gsettings"
                    && args.first().map(String::as_str) == Some("set"))
                    || program == "kwriteconfig6"
                    || program == "kwriteconfig5";
                if is_mutation && self.journal_at_first_mutation.is_none() {
                    self.journal_at_first_mutation = RecoveryJournal::load_from(&self.state_dir)
                        .ok()
                        .flatten()
                        .and_then(|j| j.sysproxy);
                }
                self.calls.push(cmd.clone());

                if program == "gsettings" {
                    if !self.gnome_available {
                        return Err(io::Error::other("dconf unavailable: no D-Bus session"));
                    }
                    return match cmd.as_str() {
                        // Already-mutated GNOME state pointing at rust-clash (must NOT overwrite original backup!)
                        "gsettings get org.gnome.system.proxy mode" => Ok("'manual'\n".into()),
                        "gsettings get org.gnome.system.proxy ignore-hosts" => {
                            Ok("['localhost']\n".into())
                        }
                        "gsettings get org.gnome.system.proxy.http host" => {
                            Ok("'127.0.0.1'\n".into())
                        }
                        "gsettings get org.gnome.system.proxy.http port" => Ok("7890\n".into()),
                        _ => Ok(String::new()),
                    };
                }
                if program == "kreadconfig6" {
                    if args.iter().any(|a| a == "ProxyType") {
                        return Ok("2\n".into());
                    }
                    if args.iter().any(|a| a == "httpProxy") {
                        return Ok("http://old-kde.corp:8000\n".into());
                    }
                    if args.iter().any(|a| a == "httpsProxy") {
                        return Ok("http://old-kde.corp:8443\n".into());
                    }
                    if args.iter().any(|a| a == "socksProxy") {
                        return Ok("socks://old-kde.corp:1080\n".into());
                    }
                    if args.iter().any(|a| a == "NoProxyFor") {
                        return Ok("localhost,.kde.corp\n".into());
                    }
                    return Ok(String::new());
                }
                Ok(String::new())
            }
        }

        let dir = std::env::temp_dir().join(format!(
            "rc-sysproxy-augment-gnome-kde-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap();

        let orig_gnome = SysProxyRecoveryRecord {
            platform: "linux".into(),
            linux_gnome_mode: Some("none".into()),
            linux_gnome_ignore_hosts: Some("['localhost', '.corp.internal']".into()),
            linux_gnome_http: Some(LinuxGnomeProtoBackup {
                host: Some("corp-gnome.internal".into()),
                port: Some(8080),
            }),
            ..Default::default()
        };

        // Test both A3a (gsettings fails -> KDE fallback, prefer_kde=false) and
        // A3b (KDE Plasma session, prefer_kde=true with already-mutated GNOME).
        for (prefer_kde, gnome_available) in [(false, false), (true, true)] {
            let mut dead_j = RecoveryJournal::new_for_pid(999_999_991);
            dead_j.sysproxy = Some(orig_gnome.clone());
            dead_j.save_atomic(&dir).unwrap();
            let _ = recover_stale_network_state_with_runner(&dir, &mut |_p, _a| {
                Err(io::Error::other("D-Bus unavailable during startup"))
            });
            assert_eq!(
                RecoveryJournal::load_from(&dir)
                    .unwrap()
                    .unwrap()
                    .effective_sysproxy_pid(),
                0
            );

            let mut backend = LinuxKdeAugmentBackend {
                state_dir: dir.clone(),
                gnome_available,
                calls: Vec::new(),
                journal_at_first_mutation: None,
            };
            enable_linux_sysproxy_with_env(
                "127.0.0.1",
                7891,
                &["localhost".into()],
                &dir,
                prefer_kde,
                &mut backend,
            )
            .unwrap();

            // Write-before-mutate invariant: journal on disk ALREADY has BOTH original GNOME
            // and pre-mutation KDE backup before the first mutating command ran.
            let pre_mut = backend
                .journal_at_first_mutation
                .take()
                .expect("at least one mutating OS command must have executed");
            assert_eq!(pre_mut.linux_gnome_mode, orig_gnome.linux_gnome_mode);
            assert_eq!(
                pre_mut.linux_gnome_ignore_hosts,
                orig_gnome.linux_gnome_ignore_hosts
            );
            assert_eq!(pre_mut.linux_gnome_http, orig_gnome.linux_gnome_http);
            let pre_kde = pre_mut
                .linux_kde
                .expect("linux_kde must be persisted before any OS mutation");
            assert_eq!(pre_kde.tool_generation, 6);
            assert_eq!(pre_kde.proxy_type.as_deref(), Some("2"));
            assert_eq!(
                pre_kde.http_proxy.as_deref(),
                Some("http://old-kde.corp:8000")
            );
            assert_eq!(
                pre_kde.https_proxy.as_deref(),
                Some("http://old-kde.corp:8443")
            );
            assert_eq!(
                pre_kde.socks_proxy.as_deref(),
                Some("socks://old-kde.corp:1080")
            );
            assert_eq!(pre_kde.no_proxy_for.as_deref(), Some("localhost,.kde.corp"));

            // Original GNOME backup must never be re-snapshotted when already present.
            assert!(
                backend
                    .calls
                    .iter()
                    .all(|c| !c.starts_with("gsettings get org.gnome.system.proxy.http ")),
                "must not re-snapshot already-backed-up GNOME (prefer_kde={prefer_kde}): {:?}",
                backend.calls
            );
            assert!(
                backend.calls.iter().any(|c| c
                    == "kwriteconfig6 --file kioslaverc --group Proxy Settings --key ProxyType 1")
            );

            // Disable restores BOTH KDE and GNOME cleanly and removes the journal.
            backend.gnome_available = true;
            backend.calls.clear();
            let status = disable_system_proxy_with_backend(&dir, &mut backend).unwrap();
            assert!(!status.enabled);
            assert!(RecoveryJournal::load_from(&dir).unwrap().is_none());
            for expected in [
                "gsettings set org.gnome.system.proxy.http host corp-gnome.internal",
                "gsettings set org.gnome.system.proxy.http port 8080",
                "gsettings set org.gnome.system.proxy ignore-hosts ['localhost', '.corp.internal']",
                "gsettings set org.gnome.system.proxy mode none",
                "kwriteconfig6 --file kioslaverc --group Proxy Settings --key httpProxy http://old-kde.corp:8000",
                "kwriteconfig6 --file kioslaverc --group Proxy Settings --key ProxyType 2",
            ] {
                assert!(
                    backend.calls.iter().any(|c| c == expected),
                    "missing expected restore call `{expected}` (prefer_kde={prefer_kde}) in {:?}",
                    backend.calls
                );
            }
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn linux_kde_sentinel_zero_to_gnome_augments_gnome_and_preserves_kde() {
        struct LinuxGnomeAugmentBackend {
            state_dir: std::path::PathBuf,
            calls: Vec<String>,
            journal_at_first_mutation: Option<SysProxyRecoveryRecord>,
        }
        impl SysProxyCommandBackend for LinuxGnomeAugmentBackend {
            fn run_capture(&mut self, program: &str, args: &[String]) -> io::Result<String> {
                let cmd = format!("{program} {}", args.join(" "));
                let is_mutation = (program == "gsettings"
                    && args.first().map(String::as_str) == Some("set"))
                    || program == "kwriteconfig6"
                    || program == "kwriteconfig5";
                if is_mutation && self.journal_at_first_mutation.is_none() {
                    self.journal_at_first_mutation = RecoveryJournal::load_from(&self.state_dir)
                        .ok()
                        .flatten()
                        .and_then(|j| j.sysproxy);
                }
                self.calls.push(cmd.clone());

                match cmd.as_str() {
                    "gsettings get org.gnome.system.proxy mode" => Ok("'none'\n".into()),
                    "gsettings get org.gnome.system.proxy ignore-hosts" => {
                        Ok("['localhost', '.gnome.corp']\n".into())
                    }
                    "gsettings get org.gnome.system.proxy.http host" => {
                        Ok("'orig-gnome.corp'\n".into())
                    }
                    "gsettings get org.gnome.system.proxy.http port" => Ok("3128\n".into()),
                    "gsettings get org.gnome.system.proxy.https host" => {
                        Ok("'orig-gnome-tls.corp'\n".into())
                    }
                    "gsettings get org.gnome.system.proxy.https port" => Ok("8443\n".into()),
                    "gsettings get org.gnome.system.proxy.socks host" => Ok("''\n".into()),
                    "gsettings get org.gnome.system.proxy.socks port" => Ok("0\n".into()),
                    _ if program == "kreadconfig6" && args.iter().any(|a| a == "ProxyType") => {
                        // Already-mutated KDE state (must NOT overwrite original KDE backup!)
                        Ok("1\n".into())
                    }
                    _ if program == "kreadconfig6" => Ok("http://127.0.0.1:7890\n".into()),
                    _ => Ok(String::new()),
                }
            }
        }

        let dir = std::env::temp_dir().join(format!(
            "rc-sysproxy-augment-kde-gnome-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap();

        let orig_kde = LinuxKdeProxyBackup {
            tool_generation: 6,
            proxy_type: Some("2".into()),
            http_proxy: Some("http://orig-kde.corp:8000".into()),
            https_proxy: Some("http://orig-kde.corp:8443".into()),
            socks_proxy: Some(String::new()),
            no_proxy_for: Some("localhost,.orig-kde.local".into()),
        };

        // Test A3c under both prefer_kde=false (GNOME-only enable) and prefer_kde=true (dual enable).
        for prefer_kde in [false, true] {
            let mut sentinel_j = RecoveryJournal::new_for_pid(0);
            sentinel_j.sysproxy = Some(SysProxyRecoveryRecord {
                platform: "linux".into(),
                linux_gnome_mode: None,
                linux_kde: Some(orig_kde.clone()),
                ..Default::default()
            });
            sentinel_j.save_atomic(&dir).unwrap();

            let mut backend = LinuxGnomeAugmentBackend {
                state_dir: dir.clone(),
                calls: Vec::new(),
                journal_at_first_mutation: None,
            };
            enable_linux_sysproxy_with_env(
                "127.0.0.1",
                7891,
                &["localhost".into()],
                &dir,
                prefer_kde,
                &mut backend,
            )
            .unwrap();

            let pre_mut = backend
                .journal_at_first_mutation
                .take()
                .expect("mutating command must have executed");
            assert_eq!(pre_mut.linux_gnome_mode.as_deref(), Some("none"));
            assert_eq!(
                pre_mut.linux_gnome_ignore_hosts.as_deref(),
                Some("['localhost', '.gnome.corp']")
            );
            assert_eq!(
                pre_mut.linux_gnome_http,
                Some(LinuxGnomeProtoBackup {
                    host: Some("orig-gnome.corp".into()),
                    port: Some(3128),
                })
            );
            assert_eq!(
                pre_mut.linux_kde.as_ref(),
                Some(&orig_kde),
                "original KDE backup must be preserved untouched (prefer_kde={prefer_kde})"
            );
            assert!(
                backend
                    .calls
                    .iter()
                    .all(|c| !(c.starts_with("kreadconfig6 ") && c.contains("httpProxy"))),
                "must not re-snapshot already-backed-up KDE keys: {:?}",
                backend.calls
            );

            backend.calls.clear();
            let status = disable_system_proxy_with_backend(&dir, &mut backend).unwrap();
            assert!(!status.enabled);
            assert!(RecoveryJournal::load_from(&dir).unwrap().is_none());
            for expected in [
                "gsettings set org.gnome.system.proxy.http host orig-gnome.corp",
                "gsettings set org.gnome.system.proxy.http port 3128",
                "gsettings set org.gnome.system.proxy ignore-hosts ['localhost', '.gnome.corp']",
                "gsettings set org.gnome.system.proxy mode none",
                "kwriteconfig6 --file kioslaverc --group Proxy Settings --key httpProxy http://orig-kde.corp:8000",
                "kwriteconfig6 --file kioslaverc --group Proxy Settings --key ProxyType 2",
            ] {
                assert!(
                    backend.calls.iter().any(|c| c == expected),
                    "missing expected restore call `{expected}` (prefer_kde={prefer_kde}) in {:?}",
                    backend.calls
                );
            }
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn linux_legacy_minimal_gnome_record_augmented_with_kde_preserves_gnome_restore() {
        struct LegacyMinimalBackend {
            gnome_available: bool,
            calls: Vec<String>,
        }
        impl SysProxyCommandBackend for LegacyMinimalBackend {
            fn run_capture(&mut self, program: &str, args: &[String]) -> io::Result<String> {
                let cmd = format!("{program} {}", args.join(" "));
                self.calls.push(cmd.clone());
                if program == "gsettings" {
                    if !self.gnome_available {
                        return Err(io::Error::other("no D-Bus session"));
                    }
                    if cmd == "gsettings get org.gnome.system.proxy mode" {
                        return Ok("'manual'\n".into());
                    }
                    if cmd.starts_with("gsettings get org.gnome.system.proxy.") {
                        return Ok("'127.0.0.1'\n".into());
                    }
                    return Ok(String::new());
                }
                if program == "kreadconfig6" {
                    if args.iter().any(|a| a == "ProxyType") {
                        return Ok("2\n".into());
                    }
                    if args.iter().any(|a| a == "httpProxy") {
                        return Ok("http://legacy-kde.corp:8000\n".into());
                    }
                    return Ok(String::new());
                }
                Ok(String::new())
            }
        }

        let dir = std::env::temp_dir().join(format!(
            "rc-sysproxy-legacy-minimal-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap();

        for (prefer_kde, gnome_available) in [(false, false), (true, true)] {
            let mut sentinel_j = RecoveryJournal::new_for_pid(0);
            sentinel_j.sysproxy = Some(SysProxyRecoveryRecord {
                platform: "linux".into(),
                linux_gnome_mode: None,
                linux_kde: None,
                ..Default::default()
            });
            sentinel_j.save_atomic(&dir).unwrap();

            let mut backend = LegacyMinimalBackend {
                gnome_available,
                calls: Vec::new(),
            };
            enable_linux_sysproxy_with_env(
                "127.0.0.1",
                7891,
                &["localhost".into()],
                &dir,
                prefer_kde,
                &mut backend,
            )
            .unwrap();

            let saved = RecoveryJournal::load_from(&dir)
                .unwrap()
                .unwrap()
                .sysproxy
                .unwrap();
            assert_eq!(
                saved.linux_gnome_mode.as_deref(),
                Some("none"),
                "legacy minimal GNOME record must default mode to \"none\" rather than suppressing GNOME restore or snapshotting \"manual\""
            );
            assert!(saved.linux_gnome_http.is_none());
            assert_eq!(
                saved
                    .linux_kde
                    .as_ref()
                    .and_then(|k| k.proxy_type.as_deref()),
                Some("2")
            );
            assert!(
                backend
                    .calls
                    .iter()
                    .all(|c| !c.starts_with("gsettings get org.gnome.system.proxy.http ")),
                "must not re-snapshot already-mutated GNOME for legacy minimal record: {:?}",
                backend.calls
            );

            backend.gnome_available = true;
            backend.calls.clear();
            disable_system_proxy_with_backend(&dir, &mut backend).unwrap();
            assert!(
                backend
                    .calls
                    .iter()
                    .any(|c| c == "gsettings set org.gnome.system.proxy mode none"),
                "GNOME mode restore must not be suppressed after augmenting linux_kde: {:?}",
                backend.calls
            );
            assert!(
                backend.calls.iter().any(|c| c
                    == "kwriteconfig6 --file kioslaverc --group Proxy Settings --key ProxyType 2")
            );
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn macos_sentinel_zero_augments_newly_active_service_without_resnapshotting_existing() {
        struct MacNewServiceBackend {
            state_dir: std::path::PathBuf,
            calls: Vec<String>,
            journal_at_first_mutation: Option<SysProxyRecoveryRecord>,
        }
        impl SysProxyCommandBackend for MacNewServiceBackend {
            fn run_capture(&mut self, program: &str, args: &[String]) -> io::Result<String> {
                let cmd = format!("{program} {}", args.join(" "));
                let is_mutation = program == "networksetup"
                    && args.first().is_some_and(|a| a.starts_with("-set"));
                if is_mutation && self.journal_at_first_mutation.is_none() {
                    self.journal_at_first_mutation = RecoveryJournal::load_from(&self.state_dir)
                        .ok()
                        .flatten()
                        .and_then(|j| j.sysproxy);
                }
                self.calls.push(cmd.clone());

                match cmd.as_str() {
                    "networksetup -listallnetworkservices" => Ok(
                        "An asterisk (*) denotes disabled.\nWi-Fi\nUSB 10/100/1000 LAN\n".into(),
                    ),
                    // Simulated already-mutated Wi-Fi (must NEVER be queried!)
                    "networksetup -getwebproxy Wi-Fi"
                    | "networksetup -getsecurewebproxy Wi-Fi"
                    | "networksetup -getsocksfirewallproxy Wi-Fi" => {
                        Ok("Enabled: Yes\nServer: 127.0.0.1\nPort: 7890\n".into())
                    }
                    "networksetup -getproxybypassdomains Wi-Fi" => Ok("localhost\n".into()),
                    // Newly active USB LAN with pre-existing corporate web proxy
                    "networksetup -getwebproxy USB 10/100/1000 LAN" => {
                        Ok("Enabled: Yes\nServer: usb-proxy.corp\nPort: 8080\n".into())
                    }
                    "networksetup -getsecurewebproxy USB 10/100/1000 LAN"
                    | "networksetup -getsocksfirewallproxy USB 10/100/1000 LAN" => {
                        Ok("Enabled: No\nServer: \nPort: 0\n".into())
                    }
                    "networksetup -getproxybypassdomains USB 10/100/1000 LAN" => {
                        Ok("*.usb.local\n10.0.0.0/8\n".into())
                    }
                    _ => Ok(String::new()),
                }
            }
        }

        let dir = std::env::temp_dir().join(format!(
            "rc-sysproxy-macos-new-svc-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap();

        let orig_wifi = MacOsProxyServiceBackup {
            service_name: "Wi-Fi".into(),
            web_enabled: false,
            web_host: String::new(),
            web_port: 0,
            secure_web_enabled: true,
            secure_web_host: "corp.local".into(),
            secure_web_port: 8443,
            socks_enabled: false,
            socks_host: String::new(),
            socks_port: 0,
            bypass_domains: Some(vec!["*.corp.local".into()]),
        };
        let mut sentinel_j = RecoveryJournal::new_for_pid(0);
        sentinel_j.sysproxy = Some(SysProxyRecoveryRecord {
            platform: "macos".into(),
            macos_services: vec![orig_wifi.clone()],
            ..Default::default()
        });
        sentinel_j.save_atomic(&dir).unwrap();

        let mut backend = MacNewServiceBackend {
            state_dir: dir.clone(),
            calls: Vec::new(),
            journal_at_first_mutation: None,
        };
        enable_macos_sysproxy_with_backend(
            "127.0.0.1",
            7891,
            &["localhost".into()],
            &dir,
            &mut backend,
        )
        .unwrap();

        // Zero `-get*` calls for already-backed-up Wi-Fi.
        assert!(
            backend
                .calls
                .iter()
                .all(|c| !(c.starts_with("networksetup -get") && c.ends_with(" Wi-Fi"))),
            "must never call networksetup -get* for already-backed-up Wi-Fi: {:?}",
            backend.calls
        );

        // Write-before-mutate invariant: BOTH Wi-Fi (original) and USB LAN (newly snapshotted)
        // must be persisted BEFORE the first `-set*` call runs.
        let pre_mut = backend
            .journal_at_first_mutation
            .take()
            .expect("networksetup -set* must have executed");
        assert_eq!(pre_mut.macos_services.len(), 2);
        assert_eq!(pre_mut.macos_services[0], orig_wifi);
        let usb = &pre_mut.macos_services[1];
        assert_eq!(usb.service_name, "USB 10/100/1000 LAN");
        assert!(usb.web_enabled);
        assert_eq!(usb.web_host, "usb-proxy.corp");
        assert_eq!(usb.web_port, 8080);
        assert_eq!(
            usb.bypass_domains.as_deref(),
            Some(&["*.usb.local".to_string(), "10.0.0.0/8".to_string()][..])
        );

        // Both services were mutated to 127.0.0.1:7891.
        assert!(
            backend
                .calls
                .iter()
                .any(|c| c == "networksetup -setwebproxy Wi-Fi 127.0.0.1 7891")
        );
        assert!(
            backend
                .calls
                .iter()
                .any(|c| c == "networksetup -setwebproxy USB 10/100/1000 LAN 127.0.0.1 7891")
        );

        // Disable restores BOTH Wi-Fi and USB 10/100/1000 LAN.
        backend.calls.clear();
        let status = disable_system_proxy_with_backend(&dir, &mut backend).unwrap();
        assert!(!status.enabled);
        assert!(RecoveryJournal::load_from(&dir).unwrap().is_none());
        for expected in [
            "networksetup -setsecurewebproxy Wi-Fi corp.local 8443",
            "networksetup -setsecurewebproxystate Wi-Fi on",
            "networksetup -setproxybypassdomains Wi-Fi *.corp.local",
            "networksetup -setwebproxy USB 10/100/1000 LAN usb-proxy.corp 8080",
            "networksetup -setwebproxystate USB 10/100/1000 LAN on",
            "networksetup -setproxybypassdomains USB 10/100/1000 LAN *.usb.local 10.0.0.0/8",
        ] {
            assert!(
                backend.calls.iter().any(|c| c == expected),
                "missing expected macOS restore call `{expected}` in {:?}",
                backend.calls
            );
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn same_pid_hot_reload_augments_new_linux_kde_and_macos_ethernet_targets() {
        // --- 1. Linux same-PID port hot-reload: GNOME-only (7890) -> GNOME + KDE (7891) ---
        struct LinuxHotReloadBackend {
            state_dir: std::path::PathBuf,
            phase: u8,
            calls: Vec<String>,
            journal_at_phase2_first_mutation: Option<SysProxyRecoveryRecord>,
        }
        impl SysProxyCommandBackend for LinuxHotReloadBackend {
            fn run_capture(&mut self, program: &str, args: &[String]) -> io::Result<String> {
                let cmd = format!("{program} {}", args.join(" "));
                let is_mutation = (program == "gsettings"
                    && args.first().map(String::as_str) == Some("set"))
                    || program == "kwriteconfig6";
                if self.phase == 2 && is_mutation && self.journal_at_phase2_first_mutation.is_none()
                {
                    self.journal_at_phase2_first_mutation =
                        RecoveryJournal::load_from(&self.state_dir)
                            .ok()
                            .flatten()
                            .and_then(|j| j.sysproxy);
                }
                self.calls.push(cmd.clone());

                if self.phase == 1 {
                    match cmd.as_str() {
                        "gsettings get org.gnome.system.proxy mode" => Ok("'none'\n".into()),
                        "gsettings get org.gnome.system.proxy ignore-hosts" => {
                            Ok("['localhost', '.orig.corp']\n".into())
                        }
                        "gsettings get org.gnome.system.proxy.http host" => {
                            Ok("'orig-gnome.corp'\n".into())
                        }
                        "gsettings get org.gnome.system.proxy.http port" => Ok("3128\n".into()),
                        _ => Ok(String::new()),
                    }
                } else {
                    match cmd.as_str() {
                        // Phase 2: GNOME is already mutated to 127.0.0.1:7890
                        "gsettings get org.gnome.system.proxy mode" => Ok("'manual'\n".into()),
                        "gsettings get org.gnome.system.proxy.http host" => {
                            Ok("'127.0.0.1'\n".into())
                        }
                        "gsettings get org.gnome.system.proxy.http port" => Ok("7890\n".into()),
                        _ if program == "kreadconfig6" && args.iter().any(|a| a == "ProxyType") => {
                            Ok("2\n".into())
                        }
                        _ if program == "kreadconfig6" && args.iter().any(|a| a == "httpProxy") => {
                            Ok("http://orig-kde.corp:8000\n".into())
                        }
                        _ => Ok(String::new()),
                    }
                }
            }
        }

        let dir = std::env::temp_dir().join(format!(
            "rc-sysproxy-hot-reload-augment-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap();

        let mut linux_backend = LinuxHotReloadBackend {
            state_dir: dir.clone(),
            phase: 1,
            calls: Vec::new(),
            journal_at_phase2_first_mutation: None,
        };
        enable_linux_sysproxy_with_env(
            "127.0.0.1",
            7890,
            &["localhost".into()],
            &dir,
            false,
            &mut linux_backend,
        )
        .unwrap();

        linux_backend.phase = 2;
        linux_backend.calls.clear();
        enable_linux_sysproxy_with_env(
            "127.0.0.1",
            7891,
            &["localhost".into()],
            &dir,
            true,
            &mut linux_backend,
        )
        .unwrap();

        let pre_mut_linux = linux_backend
            .journal_at_phase2_first_mutation
            .take()
            .expect("phase 2 must mutate OS");
        assert_eq!(pre_mut_linux.linux_gnome_mode.as_deref(), Some("none"));
        assert_eq!(
            pre_mut_linux.linux_gnome_http,
            Some(LinuxGnomeProtoBackup {
                host: Some("orig-gnome.corp".into()),
                port: Some(3128),
            })
        );
        assert_eq!(
            pre_mut_linux
                .linux_kde
                .as_ref()
                .and_then(|k| k.http_proxy.as_deref()),
            Some("http://orig-kde.corp:8000")
        );

        linux_backend.calls.clear();
        disable_system_proxy_with_backend(&dir, &mut linux_backend).unwrap();
        for expected in [
            "gsettings set org.gnome.system.proxy.http host orig-gnome.corp",
            "gsettings set org.gnome.system.proxy.http port 3128",
            "gsettings set org.gnome.system.proxy mode none",
            "kwriteconfig6 --file kioslaverc --group Proxy Settings --key httpProxy http://orig-kde.corp:8000",
            "kwriteconfig6 --file kioslaverc --group Proxy Settings --key ProxyType 2",
        ] {
            assert!(
                linux_backend.calls.iter().any(|c| c == expected),
                "missing expected Linux hot-reload restore call `{expected}` in {:?}",
                linux_backend.calls
            );
        }

        // --- 2. macOS same-PID port hot-reload: Wi-Fi (7890) -> Wi-Fi + Ethernet (7891) ---
        struct MacHotReloadBackend {
            state_dir: std::path::PathBuf,
            phase: u8,
            calls: Vec<String>,
            journal_at_phase2_first_mutation: Option<SysProxyRecoveryRecord>,
        }
        impl SysProxyCommandBackend for MacHotReloadBackend {
            fn run_capture(&mut self, program: &str, args: &[String]) -> io::Result<String> {
                let cmd = format!("{program} {}", args.join(" "));
                let is_mutation = program == "networksetup"
                    && args.first().is_some_and(|a| a.starts_with("-set"));
                if self.phase == 2 && is_mutation && self.journal_at_phase2_first_mutation.is_none()
                {
                    self.journal_at_phase2_first_mutation =
                        RecoveryJournal::load_from(&self.state_dir)
                            .ok()
                            .flatten()
                            .and_then(|j| j.sysproxy);
                }
                self.calls.push(cmd.clone());

                if self.phase == 1 {
                    match cmd.as_str() {
                        "networksetup -listallnetworkservices" => {
                            Ok("An asterisk (*) denotes disabled.\nWi-Fi\n".into())
                        }
                        "networksetup -getwebproxy Wi-Fi" => {
                            Ok("Enabled: Yes\nServer: orig-wifi.corp\nPort: 8080\n".into())
                        }
                        "networksetup -getproxybypassdomains Wi-Fi" => Ok("*.wifi.local\n".into()),
                        _ => Ok("Enabled: No\nServer: \nPort: 0\n".into()),
                    }
                } else {
                    match cmd.as_str() {
                        "networksetup -listallnetworkservices" => {
                            Ok("An asterisk (*) denotes disabled.\nWi-Fi\nEthernet\n".into())
                        }
                        // Wi-Fi already mutated to 127.0.0.1:7890 (must NEVER be re-snapshotted!)
                        "networksetup -getwebproxy Wi-Fi"
                        | "networksetup -getsecurewebproxy Wi-Fi"
                        | "networksetup -getsocksfirewallproxy Wi-Fi" => {
                            Ok("Enabled: Yes\nServer: 127.0.0.1\nPort: 7890\n".into())
                        }
                        "networksetup -getproxybypassdomains Wi-Fi" => Ok("localhost\n".into()),
                        // Newly plugged Ethernet
                        "networksetup -getsecurewebproxy Ethernet" => {
                            Ok("Enabled: Yes\nServer: orig-eth.corp\nPort: 9090\n".into())
                        }
                        "networksetup -getproxybypassdomains Ethernet" => {
                            Ok("*.eth.local\n".into())
                        }
                        _ => Ok("Enabled: No\nServer: \nPort: 0\n".into()),
                    }
                }
            }
        }

        let mut mac_backend = MacHotReloadBackend {
            state_dir: dir.clone(),
            phase: 1,
            calls: Vec::new(),
            journal_at_phase2_first_mutation: None,
        };
        enable_macos_sysproxy_with_backend(
            "127.0.0.1",
            7890,
            &["localhost".into()],
            &dir,
            &mut mac_backend,
        )
        .unwrap();

        mac_backend.phase = 2;
        mac_backend.calls.clear();
        enable_macos_sysproxy_with_backend(
            "127.0.0.1",
            7891,
            &["localhost".into()],
            &dir,
            &mut mac_backend,
        )
        .unwrap();

        assert!(
            mac_backend
                .calls
                .iter()
                .all(|c| !(c.starts_with("networksetup -get") && c.ends_with(" Wi-Fi"))),
            "phase 2 hot-reload must not re-snapshot Wi-Fi: {:?}",
            mac_backend.calls
        );
        let pre_mut_mac = mac_backend
            .journal_at_phase2_first_mutation
            .take()
            .expect("phase 2 must mutate macOS");
        assert_eq!(pre_mut_mac.macos_services.len(), 2);
        assert_eq!(pre_mut_mac.macos_services[0].service_name, "Wi-Fi");
        assert_eq!(pre_mut_mac.macos_services[0].web_host, "orig-wifi.corp");
        assert_eq!(pre_mut_mac.macos_services[0].web_port, 8080);
        assert_eq!(pre_mut_mac.macos_services[1].service_name, "Ethernet");
        assert_eq!(
            pre_mut_mac.macos_services[1].secure_web_host,
            "orig-eth.corp"
        );
        assert_eq!(pre_mut_mac.macos_services[1].secure_web_port, 9090);

        mac_backend.calls.clear();
        disable_system_proxy_with_backend(&dir, &mut mac_backend).unwrap();
        for expected in [
            "networksetup -setwebproxy Wi-Fi orig-wifi.corp 8080",
            "networksetup -setwebproxystate Wi-Fi on",
            "networksetup -setproxybypassdomains Wi-Fi *.wifi.local",
            "networksetup -setsecurewebproxy Ethernet orig-eth.corp 9090",
            "networksetup -setsecurewebproxystate Ethernet on",
            "networksetup -setproxybypassdomains Ethernet *.eth.local",
        ] {
            assert!(
                mac_backend.calls.iter().any(|c| c == expected),
                "missing expected macOS hot-reload restore call `{expected}` in {:?}",
                mac_backend.calls
            );
        }

        let _ = std::fs::remove_dir_all(&dir);
    }
}

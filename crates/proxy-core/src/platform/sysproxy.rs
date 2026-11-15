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
            if j.effective_sysproxy_pid() == std::process::id() {
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

fn load_current_pid_sysproxy_backup(state_dir: &Path) -> Option<SysProxyRecoveryRecord> {
    RecoveryJournal::load_from(state_dir)
        .ok()
        .flatten()
        .filter(|j| j.effective_sysproxy_pid() == std::process::id())
        .and_then(|j| j.sysproxy)
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
        let mut backend = RealOsCommandBackend;
        restore_sysproxy_record_with_backend(&rec, &mut backend)?;
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
    match rec.platform.as_str() {
        "windows" => {
            #[cfg(windows)]
            {
                restore_windows_sysproxy_record(rec)?;
            }
            let _ = backend;
        }
        "macos" => {
            for svc in &rec.macos_services {
                if svc.web_enabled && !svc.web_host.is_empty() && svc.web_port > 0 {
                    let _ = backend.run_capture(
                        "networksetup",
                        &[
                            "-setwebproxy".into(),
                            svc.service_name.clone(),
                            svc.web_host.clone(),
                            svc.web_port.to_string(),
                        ],
                    );
                }
                let _ = backend.run_capture(
                    "networksetup",
                    &[
                        "-setwebproxystate".into(),
                        svc.service_name.clone(),
                        if svc.web_enabled { "on" } else { "off" }.into(),
                    ],
                );

                if svc.secure_web_enabled
                    && !svc.secure_web_host.is_empty()
                    && svc.secure_web_port > 0
                {
                    let _ = backend.run_capture(
                        "networksetup",
                        &[
                            "-setsecurewebproxy".into(),
                            svc.service_name.clone(),
                            svc.secure_web_host.clone(),
                            svc.secure_web_port.to_string(),
                        ],
                    );
                }
                let _ = backend.run_capture(
                    "networksetup",
                    &[
                        "-setsecurewebproxystate".into(),
                        svc.service_name.clone(),
                        if svc.secure_web_enabled { "on" } else { "off" }.into(),
                    ],
                );

                if svc.socks_enabled && !svc.socks_host.is_empty() && svc.socks_port > 0 {
                    let _ = backend.run_capture(
                        "networksetup",
                        &[
                            "-setsocksfirewallproxy".into(),
                            svc.service_name.clone(),
                            svc.socks_host.clone(),
                            svc.socks_port.to_string(),
                        ],
                    );
                }
                let _ = backend.run_capture(
                    "networksetup",
                    &[
                        "-setsocksfirewallproxystate".into(),
                        svc.service_name.clone(),
                        if svc.socks_enabled { "on" } else { "off" }.into(),
                    ],
                );

                if let Some(ref domains) = svc.bypass_domains {
                    let mut b_args =
                        vec!["-setproxybypassdomains".into(), svc.service_name.clone()];
                    if domains.is_empty() {
                        b_args.push("Empty".into());
                    } else {
                        b_args.extend(domains.iter().cloned());
                    }
                    let _ = backend.run_capture("networksetup", &b_args);
                }
            }
        }
        "linux" => {
            for (proto, proto_bkp) in [
                ("http", &rec.linux_gnome_http),
                ("https", &rec.linux_gnome_https),
                ("socks", &rec.linux_gnome_socks),
            ] {
                if let Some(bkp) = proto_bkp {
                    let schema = format!("org.gnome.system.proxy.{proto}");
                    if let Some(ref host) = bkp.host {
                        let _ = backend.run_capture(
                            "gsettings",
                            &["set".into(), schema.clone(), "host".into(), host.clone()],
                        );
                    }
                    if let Some(port) = bkp.port {
                        let _ = backend.run_capture(
                            "gsettings",
                            &["set".into(), schema, "port".into(), port.to_string()],
                        );
                    }
                }
            }
            if let Some(ref ignore_hosts) = rec.linux_gnome_ignore_hosts
                && !ignore_hosts.trim().is_empty()
            {
                let _ = backend.run_capture(
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
                let _ = backend.run_capture(
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
                        let _ = backend.run_capture(
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
                let _ = backend.run_capture(
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
    Ok(())
}

pub fn enable_macos_sysproxy_with_backend<B: SysProxyCommandBackend>(
    host: &str,
    port: u16,
    bypass: &[String],
    state_dir: &Path,
    backend: &mut B,
) -> io::Result<()> {
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

    let existing_backup = load_current_pid_sysproxy_backup(state_dir);

    if existing_backup.is_none() {
        let mut backups = Vec::new();
        for svc in &services {
            let web = backend
                .run_capture("networksetup", &["-getwebproxy".into(), svc.clone()])
                .unwrap_or_default();
            let sweb = backend
                .run_capture("networksetup", &["-getsecurewebproxy".into(), svc.clone()])
                .unwrap_or_default();
            let socks = backend
                .run_capture(
                    "networksetup",
                    &["-getsocksfirewallproxy".into(), svc.clone()],
                )
                .unwrap_or_default();
            let bypass_raw = backend
                .run_capture(
                    "networksetup",
                    &["-getproxybypassdomains".into(), svc.clone()],
                )
                .unwrap_or_default();
            let (we, wh, wp) = parse_networksetup_proxy_output(&web);
            let (se, sh, sp) = parse_networksetup_proxy_output(&sweb);
            let (ke, kh, kp) = parse_networksetup_proxy_output(&socks);
            backups.push(MacOsProxyServiceBackup {
                service_name: svc.clone(),
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
            });
        }
        update_current_journal(state_dir, |j| {
            j.sysproxy = Some(SysProxyRecoveryRecord {
                platform: "macos".to_string(),
                macos_services: backups,
                ..Default::default()
            });
        })?;
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

    let existing_backup = load_current_pid_sysproxy_backup(state_dir);
    if existing_backup.is_none() {
        let (gnome_mode, gnome_ignore, gnome_http, gnome_https, gnome_socks) =
            if let Ok(ref prev_mode) = gnome_mode_res {
                let prev_ignore_hosts = backend
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
                let prev_http = capture_gnome_proto_backup(backend, "http");
                let prev_https = capture_gnome_proto_backup(backend, "https");
                let prev_socks = capture_gnome_proto_backup(backend, "socks");
                (
                    Some(prev_mode.clone()),
                    prev_ignore_hosts,
                    prev_http,
                    prev_https,
                    prev_socks,
                )
            } else {
                (None, None, None, None, None)
            };

        let kde_backup = kde_probe
            .as_ref()
            .map(|(kde_gen, ptype)| capture_kde_proxy_backup(backend, *kde_gen, ptype.clone()));

        update_current_journal(state_dir, |j| {
            j.sysproxy = Some(SysProxyRecoveryRecord {
                platform: "linux".to_string(),
                linux_gnome_mode: gnome_mode,
                linux_gnome_ignore_hosts: gnome_ignore,
                linux_gnome_http: gnome_http,
                linux_gnome_https: gnome_https,
                linux_gnome_socks: gnome_socks,
                linux_kde: kde_backup,
                ..Default::default()
            });
        })?;
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

    let existing_backup = load_current_pid_sysproxy_backup(state_dir);

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

    let proxy_server = format!("{host}:{port}");
    let mut override_items: Vec<String> = bypass.to_vec();
    if !override_items.iter().any(|x| x == "<local>") {
        override_items.push("<local>".to_string());
    }
    let proxy_override = override_items.join(";");

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
        Foundation::ERROR_SUCCESS,
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

    unsafe {
        let _ = RegSetValueExW(
            hkey,
            enable_name.as_ptr(),
            0,
            REG_DWORD,
            (&raw const enable_val).cast::<u8>(),
            std::mem::size_of::<u32>() as u32,
        );
        match &rec.windows_proxy_server {
            Some(s) => {
                let sw = wide_nul(s);
                let _ = RegSetValueExW(
                    hkey,
                    server_name.as_ptr(),
                    0,
                    REG_SZ,
                    sw.as_ptr().cast::<u8>(),
                    (sw.len() * 2) as u32,
                );
            }
            None => {
                let _ = RegDeleteValueW(hkey, server_name.as_ptr());
            }
        }
        match &rec.windows_proxy_override {
            Some(s) => {
                let sw = wide_nul(s);
                let _ = RegSetValueExW(
                    hkey,
                    override_name.as_ptr(),
                    0,
                    REG_SZ,
                    sw.as_ptr().cast::<u8>(),
                    (sw.len() * 2) as u32,
                );
            }
            None => {
                let _ = RegDeleteValueW(hkey, override_name.as_ptr());
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
}

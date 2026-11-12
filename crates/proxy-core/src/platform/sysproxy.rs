use std::{io, path::Path};

use serde::{Deserialize, Serialize};

use crate::platform::recovery::{
    MacOsProxyServiceBackup, RecoveryJournal, SysProxyRecoveryRecord, update_current_journal,
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

impl SysProxyCommandBackend for RealOsCommandBackend {
    fn run_capture(&mut self, program: &str, args: &[String]) -> io::Result<String> {
        let out = std::process::Command::new(program).args(args).output()?;
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
            if j.pid == std::process::id() {
                j.sysproxy
            } else {
                None
            }
        });

    let backend = if cfg!(windows) {
        "windows-wininet-registry"
    } else if cfg!(target_os = "macos") {
        "macos-networksetup"
    } else if cfg!(target_os = "linux") {
        "linux-gsettings-kde"
    } else {
        "unsupported"
    };

    let meta_path = state_dir.join("sysproxy_active.json");
    let active_meta: Option<(String, u16, Vec<String>)> = if owned.is_some() && meta_path.exists() {
        std::fs::read_to_string(&meta_path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
    } else {
        None
    };

    SysProxyStatus {
        supported: cfg!(any(windows, target_os = "macos", target_os = "linux")),
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

/// Restore the original OS System Proxy settings recorded in `network_recovery.json`.
pub fn disable_system_proxy(state_dir: &Path) -> io::Result<SysProxyStatus> {
    let record_opt = RecoveryJournal::load_from(state_dir)
        .ok()
        .flatten()
        .and_then(|j| j.sysproxy);

    if let Some(rec) = record_opt {
        let mut backend = RealOsCommandBackend;
        restore_sysproxy_record_with_backend(&rec, &mut backend)?;
        update_current_journal(state_dir, |j| {
            j.sysproxy = None;
        })?;
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
            }
        }
        "linux" => {
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

    let existing_backup = RecoveryJournal::load_from(state_dir)
        .ok()
        .flatten()
        .and_then(|j| j.sysproxy);

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

pub fn enable_linux_sysproxy_with_backend<B: SysProxyCommandBackend>(
    host: &str,
    port: u16,
    bypass: &[String],
    state_dir: &Path,
    backend: &mut B,
) -> io::Result<()> {
    let prev_mode = backend
        .run_capture(
            "gsettings",
            &["get".into(), "org.gnome.system.proxy".into(), "mode".into()],
        )
        .map(|s| s.trim().trim_matches('\'').to_string())
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::Unsupported,
                format!("Linux desktop proxy helper (gsettings) unavailable: {e}"),
            )
        })?;

    let existing_backup = RecoveryJournal::load_from(state_dir)
        .ok()
        .flatten()
        .and_then(|j| j.sysproxy);
    if existing_backup.is_none() {
        update_current_journal(state_dir, |j| {
            j.sysproxy = Some(SysProxyRecoveryRecord {
                platform: "linux".to_string(),
                linux_gnome_mode: Some(prev_mode),
                ..Default::default()
            });
        })?;
    }

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
        let quoted: Vec<String> = bypass.iter().map(|b| format!("'{b}'")).collect();
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

    let existing_backup = RecoveryJournal::load_from(state_dir)
        .ok()
        .flatten()
        .and_then(|j| j.sysproxy);

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
}

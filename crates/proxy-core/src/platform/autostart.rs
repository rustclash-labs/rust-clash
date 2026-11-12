use std::{
    fs, io,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AutostartStatus {
    pub supported: bool,
    pub enabled: bool,
    pub mechanism: String,
    pub entry_path: Option<String>,
}

/// Cross-platform Start-at-Login manager (never requires administrator/root privileges).
///
/// - **Windows**: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` value `"RustClash"`.
/// - **macOS**: `~/Library/LaunchAgents/io.github.rustclashlabs.rust-clash.plist`.
/// - **Linux**: `$XDG_CONFIG_HOME/autostart/rust-clash.desktop` (`~/.config/autostart/rust-clash.desktop`).
pub struct AutostartManager {
    /// Optional root override used in hermetic tests so host autostart directories are never touched.
    test_root: Option<PathBuf>,
}

impl Default for AutostartManager {
    fn default() -> Self {
        Self::new()
    }
}

impl AutostartManager {
    pub fn new() -> Self {
        let test_root = std::env::var("RUST_CLASH_AUTOSTART_ROOT")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .map(PathBuf::from);
        Self { test_root }
    }

    pub fn with_test_root(root: PathBuf) -> Self {
        Self {
            test_root: Some(root),
        }
    }

    pub fn status(&self) -> AutostartStatus {
        if let Some(ref root) = self.test_root {
            let p = root.join("rust-clash.desktop");
            return AutostartStatus {
                supported: true,
                enabled: p.exists(),
                mechanism: "xdg-autostart-test".to_string(),
                entry_path: Some(p.display().to_string()),
            };
        }

        #[cfg(windows)]
        {
            let enabled = windows_autostart_exists();
            AutostartStatus {
                supported: true,
                enabled,
                mechanism: "hkcu-run-registry".to_string(),
                entry_path: Some(
                    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\RustClash".into(),
                ),
            }
        }

        #[cfg(target_os = "macos")]
        {
            if let Some(plist) = self.macos_plist_path() {
                AutostartStatus {
                    supported: true,
                    enabled: plist.exists(),
                    mechanism: "macos-launch-agent".to_string(),
                    entry_path: Some(plist.display().to_string()),
                }
            } else {
                AutostartStatus {
                    supported: false,
                    enabled: false,
                    mechanism: "unsupported".to_string(),
                    entry_path: None,
                }
            }
        }

        #[cfg(not(any(windows, target_os = "macos")))]
        {
            if let Some(desktop) = self.linux_desktop_path() {
                AutostartStatus {
                    supported: true,
                    enabled: desktop.exists(),
                    mechanism: "xdg-autostart".to_string(),
                    entry_path: Some(desktop.display().to_string()),
                }
            } else {
                AutostartStatus {
                    supported: false,
                    enabled: false,
                    mechanism: "unsupported".to_string(),
                    entry_path: None,
                }
            }
        }
    }

    pub fn set_enabled(&self, enabled: bool, exe_path: &Path, args: &[&str]) -> io::Result<()> {
        if let Some(ref root) = self.test_root {
            fs::create_dir_all(root)?;
            let p = root.join("rust-clash.desktop");
            if enabled {
                fs::write(&p, render_xdg_desktop_entry(exe_path, args))?;
            } else if p.exists() {
                fs::remove_file(&p)?;
            }
            return Ok(());
        }

        #[cfg(windows)]
        {
            set_windows_autostart(enabled, exe_path, args)
        }

        #[cfg(target_os = "macos")]
        {
            let plist = self.macos_plist_path().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    "HOME not set for LaunchAgents plist",
                )
            })?;
            if enabled {
                if let Some(parent) = plist.parent() {
                    fs::create_dir_all(parent)?;
                }
                fs::write(&plist, render_macos_launch_agent(exe_path, args))?;
            } else if plist.exists() {
                fs::remove_file(&plist)?;
            }
            Ok(())
        }

        #[cfg(not(any(windows, target_os = "macos")))]
        {
            let desktop = self.linux_desktop_path().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    "HOME/XDG_CONFIG_HOME not set for autostart",
                )
            })?;
            if enabled {
                if let Some(parent) = desktop.parent() {
                    fs::create_dir_all(parent)?;
                }
                fs::write(&desktop, render_xdg_desktop_entry(exe_path, args))?;
            } else if desktop.exists() {
                fs::remove_file(&desktop)?;
            }
            Ok(())
        }
    }

    #[cfg(target_os = "macos")]
    fn macos_plist_path(&self) -> Option<PathBuf> {
        let home = std::env::var("HOME")
            .ok()
            .filter(|s| !s.trim().is_empty())?;
        Some(
            PathBuf::from(home)
                .join("Library")
                .join("LaunchAgents")
                .join("io.github.rustclashlabs.rust-clash.plist"),
        )
    }

    #[cfg(not(any(windows, target_os = "macos")))]
    fn linux_desktop_path(&self) -> Option<PathBuf> {
        if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME")
            && !xdg.trim().is_empty()
        {
            return Some(
                PathBuf::from(xdg)
                    .join("autostart")
                    .join("rust-clash.desktop"),
            );
        }
        let home = std::env::var("HOME")
            .ok()
            .filter(|s| !s.trim().is_empty())?;
        Some(
            PathBuf::from(home)
                .join(".config")
                .join("autostart")
                .join("rust-clash.desktop"),
        )
    }
}

pub fn render_xdg_desktop_entry(exe_path: &Path, args: &[&str]) -> String {
    let mut exec_parts = vec![format!("\"{}\"", exe_path.display())];
    exec_parts.extend(args.iter().map(|a| a.to_string()));
    format!(
        "[Desktop Entry]\nType=Application\nName=RustClash\nComment=Pure-Rust Multi-Protocol Proxy Client\nExec={}\nTerminal=false\nX-GNOME-Autostart-enabled=true\n",
        exec_parts.join(" ")
    )
}

pub fn render_macos_launch_agent(exe_path: &Path, args: &[&str]) -> String {
    let mut items = format!("        <string>{}</string>\n", exe_path.display());
    for a in args {
        items.push_str(&format!("        <string>{a}</string>\n"));
    }
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict>\n    <key>Label</key>\n    <string>io.github.rustclashlabs.rust-clash</string>\n    <key>ProgramArguments</key>\n    <array>\n{items}    </array>\n    <key>RunAtLoad</key>\n    <true/>\n</dict>\n</plist>\n"
    )
}

#[cfg(windows)]
fn windows_autostart_exists() -> bool {
    use windows_sys::Win32::{
        Foundation::ERROR_SUCCESS,
        System::Registry::{
            HKEY, HKEY_CURRENT_USER, KEY_READ, RegCloseKey, RegOpenKeyExW, RegQueryValueExW,
        },
    };
    let subkey: Vec<u16> = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let val_name: Vec<u16> = "RustClash"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let mut hkey: HKEY = std::ptr::null_mut();
    unsafe {
        if RegOpenKeyExW(HKEY_CURRENT_USER, subkey.as_ptr(), 0, KEY_READ, &mut hkey)
            != ERROR_SUCCESS
        {
            return false;
        }
        let mut len: u32 = 0;
        let ok = RegQueryValueExW(
            hkey,
            val_name.as_ptr(),
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut len,
        ) == ERROR_SUCCESS;
        let _ = RegCloseKey(hkey);
        ok && len > 0
    }
}

#[cfg(windows)]
fn set_windows_autostart(enabled: bool, exe_path: &Path, args: &[&str]) -> io::Result<()> {
    use windows_sys::Win32::{
        Foundation::ERROR_SUCCESS,
        System::Registry::{
            HKEY, HKEY_CURRENT_USER, KEY_WRITE, REG_SZ, RegCloseKey, RegDeleteValueW,
            RegOpenKeyExW, RegSetValueExW,
        },
    };
    let subkey: Vec<u16> = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let val_name: Vec<u16> = "RustClash"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let mut hkey: HKEY = std::ptr::null_mut();
    unsafe {
        let rc = RegOpenKeyExW(HKEY_CURRENT_USER, subkey.as_ptr(), 0, KEY_WRITE, &mut hkey);
        if rc != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(rc as i32));
        }
        if enabled {
            let mut cmd = format!("\"{}\"", exe_path.display());
            for a in args {
                cmd.push(' ');
                cmd.push_str(a);
            }
            let cmd_w: Vec<u16> = cmd.encode_utf16().chain(std::iter::once(0)).collect();
            let r = RegSetValueExW(
                hkey,
                val_name.as_ptr(),
                0,
                REG_SZ,
                cmd_w.as_ptr().cast::<u8>(),
                (cmd_w.len() * 2) as u32,
            );
            let _ = RegCloseKey(hkey);
            if r != ERROR_SUCCESS {
                return Err(io::Error::from_raw_os_error(r as i32));
            }
        } else {
            let _ = RegDeleteValueW(hkey, val_name.as_ptr());
            let _ = RegCloseKey(hkey);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn autostart_hermetic_toggle_and_template_rendering() {
        let root = std::env::temp_dir().join(format!("rc-autostart-{}", uuid::Uuid::new_v4()));
        let mgr = AutostartManager::with_test_root(root.clone());
        assert!(!mgr.status().enabled);

        let exe = Path::new("/usr/local/bin/rust-clash-desktop");
        mgr.set_enabled(true, exe, &["--minimized"]).unwrap();
        assert!(mgr.status().enabled);

        let plist = render_macos_launch_agent(exe, &["--minimized"]);
        assert!(plist.contains("io.github.rustclashlabs.rust-clash"));
        assert!(plist.contains("--minimized"));

        mgr.set_enabled(false, exe, &[]).unwrap();
        assert!(!mgr.status().enabled);
        let _ = fs::remove_dir_all(&root);
    }
}

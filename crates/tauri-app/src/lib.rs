use std::{net::SocketAddr, sync::Arc};

use proxy_core::{
    api::spawn_api_server,
    engine::ProxyEngine,
    platform::{
        autostart::{AutostartManager, AutostartStatus},
        recovery::{SingleInstanceGuard, default_state_dir, recover_stale_network_state},
        sysproxy::{SysProxyStatus, query_sysproxy_status},
    },
    profile::ProfileManager,
};
use serde::Serialize;
use tokio::sync::watch;

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[derive(Clone)]
pub struct DesktopAppState {
    pub engine: Arc<ProxyEngine>,
    pub api_addr: SocketAddr,
    _instance_guard: Option<Arc<SingleInstanceGuard>>,
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
    pub sysproxy: SysProxyStatus,
    pub autostart: AutostartStatus,
    pub active_connections: usize,
    pub fake_ip_entries: usize,
}

impl DesktopAppState {
    /// Default production launcher: starts in **Real User Mode** backed by persistent `ProfileManager`
    /// (`~/.local/share/rust-clash/profiles` / `%LOCALAPPDATA%\rust-clash\profiles` / `~/Library/Application Support/rust-clash/profiles`),
    /// enforces single-instance lockfile safety, and recovers any stale network state from unclean exits.
    pub async fn bootstrap_default() -> anyhow::Result<Self> {
        let state_dir = default_state_dir();
        let instance_guard = SingleInstanceGuard::acquire(&state_dir)
            .map(Arc::new)
            .map_err(|e| anyhow::anyhow!("RustClash Desktop is already running: {e}"))?;
        let _ = recover_stale_network_state(&state_dir);

        let profile_mgr = ProfileManager::open_or_init(&state_dir)?;
        let (mut cfg, active_path) = profile_mgr.load_active_config()?;

        let engine = match ProxyEngine::start_with_path(cfg.clone(), Some(active_path)).await {
            Ok(eng) => eng,
            Err(_) => {
                cfg.mixed_port = 0;
                cfg.dns.listen = "127.0.0.1:0".to_string();
                ProxyEngine::start_with_state_dir(cfg, state_dir).await?
            }
        };
        engine.attach_profile_manager(profile_mgr);

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
            _instance_guard: Some(instance_guard),
            _shutdown_tx: shutdown_tx,
        })
    }

    /// Optional self-contained Multi-Protocol Demo Sandbox launcher (`--demo` or `RUST_CLASH_DEMO=1`).
    pub async fn bootstrap_demo() -> anyhow::Result<Self> {
        let state_dir = default_state_dir();
        let instance_guard = SingleInstanceGuard::acquire(&state_dir).ok().map(Arc::new);
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
            _instance_guard: instance_guard,
            _shutdown_tx: shutdown_tx,
        })
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
            sysproxy: query_sysproxy_status(&state_dir),
            autostart: AutostartManager::new().status(),
            active_connections: self.engine.hub().list_connections().len(),
            fake_ip_entries: self.engine.router().dns().entry_count(),
        }
    }

    /// Idempotently shuts down the embedded control API server, `ProxyEngine`, OS TUN routes, and OS System Proxy.
    pub fn shutdown(&self) {
        let _ = self._shutdown_tx.send(true);
        self.engine.shutdown();
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
    let preflight = proxy_core::platform::tun::preflight_system_tun(
        cfg.tun.wintun_path.as_deref().map(std::path::Path::new),
    );
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
    use std::{
        sync::atomic::{AtomicBool, Ordering},
        time::Duration,
    };

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
            .map_err(|e| e.to_string())
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
            .map_err(|e| e.to_string())
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
            .map_err(|e| e.to_string())
    }

    #[tauri::command]
    pub fn set_system_proxy(
        state: State<'_, DesktopAppState>,
        enable: bool,
    ) -> Result<SysProxyStatus, String> {
        let state_dir = state.engine.state_dir();
        if enable {
            let port = state.engine.mixed_addr().port();
            enable_system_proxy("127.0.0.1", port, &[], &state_dir).map_err(|e| e.to_string())
        } else {
            disable_system_proxy(&state_dir).map_err(|e| e.to_string())
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

    fn show_and_focus_main_window<R: tauri::Runtime>(app: &tauri::AppHandle<R>) {
        if let Some(win) = app.get_webview_window("main") {
            let _ = win.show();
            let _ = win.unminimize();
            let _ = win.set_focus();
        }
    }

    fn report_tray_error<R: tauri::Runtime>(
        app: &tauri::AppHandle<R>,
        engine: &ProxyEngine,
        context: &str,
        err: impl std::fmt::Display,
    ) {
        let msg = format!("{context}: {err}");
        tracing::warn!("{msg}");
        engine.hub().push_log("error", msg.clone());
        let _ = app.emit("rust-clash://desktop-error", msg);
        show_and_focus_main_window(app);
    }

    fn setup_system_tray<R: tauri::Runtime>(
        app: &tauri::AppHandle<R>,
        state: DesktopAppState,
    ) -> tauri::Result<()> {
        let show_i = MenuItem::with_id(app, "show", "Open RustClash Console", true, None::<&str>)?;
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

        let mut builder = TrayIconBuilder::with_id("rust-clash-tray")
            .tooltip("RustClash — Pure-Rust Proxy & TUN")
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

        if let Some(icon) = app.default_window_icon().cloned() {
            builder = builder.icon(icon);
        }
        let _ = builder.build(app)?;
        Ok(())
    }

    pub fn run_tauri_window(app_state: DesktopAppState) -> anyhow::Result<()> {
        let tray_state = app_state.clone();
        let exit_state = app_state.clone();
        let tray_available = Arc::new(AtomicBool::new(false));
        let tray_flag_setup = Arc::clone(&tray_available);
        let tray_flag_close = Arc::clone(&tray_available);

        let app = tauri::Builder::default()
            .manage(app_state)
            .setup(move |app| {
                match setup_system_tray(app.handle(), tray_state) {
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
                // Only minimize-to-tray on close when a system tray icon was actually registered!
                // On headless / Wayland environments without StatusNotifierItem, allow normal window close & clean exit.
                if let WindowEvent::CloseRequested { api, .. } = event
                    && tray_flag_close.load(Ordering::Acquire)
                {
                    api.prevent_close();
                    let _ = window.hide();
                }
            })
            .invoke_handler(tauri::generate_handler![
                get_desktop_status,
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

        app.run(move |_app_handle, event| {
            if let RunEvent::Exit = event {
                exit_state.shutdown();
            }
        });
        Ok(())
    }
}

#[cfg(feature = "desktop")]
pub use desktop_ipc::run_tauri_window;

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::parse_elevated_tun_helper_args;

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
}

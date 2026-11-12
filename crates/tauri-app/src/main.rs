#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use rust_clash_tauri_lib::{
    DesktopAppState, parse_elevated_tun_helper_args, run_elevated_tun_helper,
};
use tracing_subscriber::EnvFilter;

fn main() -> anyhow::Result<()> {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,smoltcp=warn"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .compact()
        .try_init();

    let raw_args: Vec<String> = std::env::args().skip(1).collect();

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    // Handle privileged TUN helper invocations BEFORE single-instance lock / GUI initialization
    // so elevated helper child processes are never swallowed by a running desktop GUI instance.
    if let Some(helper_target) = parse_elevated_tun_helper_args(&raw_args) {
        let cfg_path = helper_target.map_err(|e| anyhow::anyhow!(e))?;
        return rt.block_on(run_elevated_tun_helper(&cfg_path));
    }

    let use_demo = raw_args.iter().any(|a| a == "--demo")
        || std::env::var("RUST_CLASH_DEMO").as_deref() == Ok("1");

    let state = if use_demo {
        rt.block_on(DesktopAppState::bootstrap_demo())?
    } else {
        rt.block_on(DesktopAppState::bootstrap_default())?
    };

    #[cfg(feature = "desktop")]
    {
        tauri::async_runtime::set(rt.handle().clone());
        rust_clash_tauri_lib::run_tauri_window(state)
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

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::time::Duration;

use proxy_core::{config::uri::redact_sensitive_text, platform::recovery::default_state_dir};
use rust_clash_tauri_lib::{
    parse_elevated_tun_helper_args, run_desktop_app, run_elevated_tun_helper,
    write_startup_crash_log,
};
use tracing_subscriber::EnvFilter;

fn run_entry(rt: &tokio::runtime::Runtime, raw_args: &[String]) -> anyhow::Result<()> {
    // Handle privileged TUN helper invocations BEFORE single-instance lock / GUI initialization
    // so elevated helper child processes are never swallowed by a running desktop GUI instance.
    if let Some(helper_target) = parse_elevated_tun_helper_args(raw_args) {
        let cfg_path = helper_target.map_err(|e| anyhow::anyhow!(e))?;
        return rt.block_on(run_elevated_tun_helper(&cfg_path));
    }

    let use_demo = raw_args.iter().any(|a| a == "--demo")
        || std::env::var("RUST_CLASH_DEMO").as_deref() == Ok("1");

    run_desktop_app(rt, use_demo)
}

fn report_fatal_error(err: &anyhow::Error) {
    let safe_err = redact_sensitive_text(&format!("{err:#}"));
    let state_dir = default_state_dir();
    let log_path = write_startup_crash_log(&state_dir, &safe_err);
    eprintln!(
        "RustClash fatal startup error: {safe_err} (logged to {})",
        log_path.display()
    );

    #[cfg(windows)]
    {
        use windows_sys::Win32::UI::WindowsAndMessaging::{MB_ICONERROR, MB_OK, MessageBoxW};

        let caption: Vec<u16> = "RustClash Startup Error"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let body = format!(
            "RustClash encountered a fatal startup error:\n\n{safe_err}\n\nDiagnostic log:\n{}",
            log_path.display()
        );
        let text: Vec<u16> = body.encode_utf16().chain(std::iter::once(0)).collect();
        // SAFETY: `text` and `caption` are valid NUL-terminated UTF-16 buffers that outlive `MessageBoxW`,
        // and a null `HWND` creates a top-level error dialog even under `windows_subsystem = "windows"`.
        unsafe {
            let _ = MessageBoxW(
                std::ptr::null_mut(),
                text.as_ptr(),
                caption.as_ptr(),
                MB_OK | MB_ICONERROR,
            );
        }
    }
}

fn main() {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,smoltcp=warn"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .compact()
        .try_init();

    let raw_args: Vec<String> = std::env::args().skip(1).collect();

    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(err) => {
            report_fatal_error(&anyhow::anyhow!(
                "Failed to initialize Tokio async runtime: {err}"
            ));
            std::process::exit(1);
        }
    };

    let result = run_entry(&rt, &raw_args);
    // Explicitly bound runtime teardown so lingering blocking/DNS worker threads never leave
    // a background ghost process holding resources after window exit.
    rt.shutdown_timeout(Duration::from_millis(500));

    if let Err(err) = result {
        report_fatal_error(&err);
        std::process::exit(1);
    }
}

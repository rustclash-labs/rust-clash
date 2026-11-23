use std::{
    any::Any,
    backtrace::Backtrace,
    cell::Cell,
    fs::{self, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    sync::{Mutex, Once},
    time::{SystemTime, UNIX_EPOCH},
};

use crate::config::uri::redact_sensitive_text;

pub const CRASH_LOG_DIR_NAME: &str = "logs";
pub const CRASH_LOG_FILENAME: &str = "crash.log";
pub const CRASH_LOG_BACKUP_FILENAME: &str = "crash.log.1";
/// Maximum size of the active `state_dir/logs/crash.log` before rotating to `crash.log.1`.
pub const MAX_CRASH_LOG_BYTES: u64 = 512 * 1024;
/// Maximum UTF-8 bytes of a single captured backtrace persisted per crash entry.
pub const MAX_BACKTRACE_BYTES: usize = 16 * 1024;

static PANIC_HOOK_ONCE: Once = Once::new();
static CRASH_LOG_LOCK: Mutex<()> = Mutex::new(());

thread_local! {
    static IN_PANIC_HOOK: Cell<bool> = const { Cell::new(false) };
}

/// Return the canonical path `state_dir/logs/crash.log`.
pub fn crash_log_path(state_dir: &Path) -> PathBuf {
    state_dir.join(CRASH_LOG_DIR_NAME).join(CRASH_LOG_FILENAME)
}

/// Extract a human-readable string from a Rust panic payload (`Box<dyn Any + Send>` or `&dyn Any`).
pub fn extract_panic_payload(payload: &(dyn Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "<non-string panic payload>".to_string()
    }
}

/// Scrub secrets, proxy share links, bearer tokens, and OS user profile directory names
/// from crash diagnostics (messages, locations, and backtraces) before persisting to disk.
pub fn sanitize_crash_text(raw: &str) -> String {
    let mut out = redact_sensitive_text(raw);
    out = scrub_bearer_tokens(&out);
    out = scrub_home_user_segments(&out);
    out
}

fn scrub_bearer_tokens(input: &str) -> String {
    let mut out = input.to_string();
    let needle = "bearer ";
    let mut cursor = 0usize;
    while let Some(rel) = out[cursor..].to_ascii_lowercase().find(needle) {
        let start = cursor + rel;
        let tok_start = start + needle.len();
        let tok_end = out[tok_start..]
            .find(|c: char| {
                c.is_whitespace() || matches!(c, '"' | '\'' | '`' | ',' | ';' | ')' | ']' | '}')
            })
            .map(|len| tok_start + len)
            .unwrap_or(out.len());
        if tok_end > tok_start {
            out.replace_range(tok_start..tok_end, "<redacted>");
            cursor = tok_start + "<redacted>".len();
        } else {
            cursor = tok_start;
        }
    }
    out
}

fn scrub_home_user_segments(input: &str) -> String {
    let mut out = input.to_string();
    for (prefix, sep) in [
        ("/Users/", '/'),
        ("/home/", '/'),
        ("C:\\Users\\", '\\'),
        ("c:\\Users\\", '\\'),
        ("C:\\users\\", '\\'),
        ("C:/Users/", '/'),
        ("c:/Users/", '/'),
    ] {
        let mut cursor = 0usize;
        while let Some(rel) = out[cursor..].find(prefix) {
            let user_start = cursor + rel + prefix.len();
            let user_end = out[user_start..]
                .find(|c: char| {
                    c == sep
                        || c == '/'
                        || c == '\\'
                        || c.is_whitespace()
                        || matches!(c, '"' | '\'' | ':' | ')')
                })
                .map(|len| user_start + len)
                .unwrap_or(out.len());
            if user_end > user_start && &out[user_start..user_end] != "<redacted>" {
                out.replace_range(user_start..user_end, "<redacted>");
                cursor = user_start + "<redacted>".len();
            } else {
                cursor = user_end;
            }
        }
    }
    out
}

fn truncate_utf8_bytes(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s.to_string();
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}\n...<truncated>...", &s[..end])
}

fn reject_if_symlink(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "refusing to write crash log through symlink '{}'",
                path.display()
            ),
        )),
        Ok(_) | Err(_) => Ok(()),
    }
}

/// Append a single redacted, size-bounded crash entry to `state_dir/logs/crash.log`,
/// rotating to `crash.log.1` when the active log exceeds `MAX_CRASH_LOG_BYTES`.
pub fn append_crash_log_entry(
    state_dir: &Path,
    component: &str,
    version: &str,
    location: &str,
    thread_name: &str,
    message: &str,
    backtrace: &str,
) -> io::Result<PathBuf> {
    append_crash_log_entry_with_limit(
        state_dir,
        component,
        version,
        location,
        thread_name,
        message,
        backtrace,
        MAX_CRASH_LOG_BYTES,
    )
}

#[allow(clippy::too_many_arguments)]
fn append_crash_log_entry_with_limit(
    state_dir: &Path,
    component: &str,
    version: &str,
    location: &str,
    thread_name: &str,
    message: &str,
    backtrace: &str,
    max_bytes: u64,
) -> io::Result<PathBuf> {
    let _guard = CRASH_LOG_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let logs_dir = state_dir.join(CRASH_LOG_DIR_NAME);
    reject_if_symlink(state_dir)?;
    reject_if_symlink(&logs_dir)?;
    fs::create_dir_all(&logs_dir)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&logs_dir, fs::Permissions::from_mode(0o700));
    }

    let log_path = logs_dir.join(CRASH_LOG_FILENAME);
    let backup_path = logs_dir.join(CRASH_LOG_BACKUP_FILENAME);
    reject_if_symlink(&log_path)?;
    reject_if_symlink(&backup_path)?;

    let unix_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let safe_location = sanitize_crash_text(location);
    let safe_thread = sanitize_crash_text(thread_name);
    let safe_message = sanitize_crash_text(message);
    let safe_bt = truncate_utf8_bytes(&sanitize_crash_text(backtrace), MAX_BACKTRACE_BYTES);

    let entry = format!(
        "=== PANIC [unix={unix_secs} component={component} v={version} pid={} thread={safe_thread}] ===\n\
         location: {safe_location}\n\
         message: {safe_message}\n\
         backtrace:\n{safe_bt}\n\n",
        std::process::id(),
    );

    if let Ok(meta) = fs::metadata(&log_path)
        && meta.len().saturating_add(entry.len() as u64) > max_bytes
        && meta.len() > 0
    {
        let _ = fs::remove_file(&backup_path);
        let _ = fs::rename(&log_path, &backup_path);
    }

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = file.set_permissions(fs::Permissions::from_mode(0o600));
    }
    file.write_all(entry.as_bytes())?;
    let _ = file.sync_all();

    Ok(log_path)
}

/// Install a process-wide panic hook once at startup that persists sanitized panic diagnostics
/// and forced stack backtraces into `state_dir/logs/crash.log` (bounded + rotated) before
/// delegating to the previously installed panic hook.
pub fn install_panic_hook(component: &'static str, version: &'static str, state_dir: PathBuf) {
    PANIC_HOOK_ONCE.call_once(move || {
        let prev_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let reentered = IN_PANIC_HOOK.with(|flag| {
                if flag.get() {
                    true
                } else {
                    flag.set(true);
                    false
                }
            });
            if !reentered {
                struct ResetFlag;
                impl Drop for ResetFlag {
                    fn drop(&mut self) {
                        IN_PANIC_HOOK.with(|flag| flag.set(false));
                    }
                }
                let _reset = ResetFlag;

                let location = info
                    .location()
                    .map(|loc| format!("{}:{}:{}", loc.file(), loc.line(), loc.column()))
                    .unwrap_or_else(|| "<unknown>".to_string());
                let thread_name = std::thread::current()
                    .name()
                    .unwrap_or("<unnamed>")
                    .to_string();
                let message = extract_panic_payload(info.payload());
                let backtrace = Backtrace::force_capture().to_string();

                let _ = append_crash_log_entry(
                    &state_dir,
                    component,
                    version,
                    &location,
                    &thread_name,
                    &message,
                    &backtrace,
                );
            }
            prev_hook(info);
        }));
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_test_dir(prefix: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "rust_clash_{prefix}_{}_{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn sanitize_crash_text_redacts_secrets_uris_bearer_and_user_paths() {
        let raw = "panic at C:\\Users\\alice\\src\\main.rs:10: failed with vless://11111111-2222-3333-4444-555555555555@example.com:443?pbk=SECRETKEY token=abc123 Authorization: Bearer eyJhbGciOiJIUzI1NiJ9 at /Users/bob/.cargo/registry and /home/charlie/repo and /Users/<redacted>中文 and C:\\Users\\测试用户\\桌面";
        let sanitized = sanitize_crash_text(raw);

        assert!(
            !sanitized.contains("alice"),
            "Windows username leaked: {sanitized}"
        );
        assert!(
            !sanitized.contains("bob"),
            "macOS username leaked: {sanitized}"
        );
        assert!(
            !sanitized.contains("charlie"),
            "Linux username leaked: {sanitized}"
        );
        assert!(
            !sanitized.contains("测试用户"),
            "UTF-8 Windows username leaked: {sanitized}"
        );
        assert!(
            !sanitized.contains("11111111-2222"),
            "VLESS UUID leaked: {sanitized}"
        );
        assert!(
            !sanitized.contains("SECRETKEY"),
            "PQ/Reality pbk leaked: {sanitized}"
        );
        assert!(
            !sanitized.contains("abc123"),
            "token param leaked: {sanitized}"
        );
        assert!(
            !sanitized.contains("eyJhbGciOiJIUzI1NiJ9"),
            "Bearer token leaked: {sanitized}"
        );
        assert!(sanitized.contains("C:\\Users\\<redacted>\\src\\main.rs:10"));
        assert!(sanitized.contains("C:\\Users\\<redacted>\\桌面"));
        assert!(sanitized.contains("/Users/<redacted>/.cargo/registry"));
        assert!(sanitized.contains("/home/<redacted>/repo"));
    }

    #[test]
    fn append_crash_log_rotates_and_bounds_size() {
        let state_dir = temp_test_dir("crash_rotate");
        let log_path = crash_log_path(&state_dir);
        let backup_path = state_dir
            .join(CRASH_LOG_DIR_NAME)
            .join(CRASH_LOG_BACKUP_FILENAME);

        let p1 = append_crash_log_entry_with_limit(
            &state_dir,
            "rust-clash-desktop",
            "0.5.15",
            "smoltcp/src/wire/tcp.rs:81:13",
            "tokio-runtime-worker",
            "first panic vless://secret-uuid@host:443",
            "frame0\nframe1",
            320,
        )
        .unwrap();
        assert_eq!(p1, log_path);
        assert!(log_path.exists());
        assert!(!backup_path.exists());

        // Second entry pushes total beyond 320B -> rotates first entry into crash.log.1
        append_crash_log_entry_with_limit(
            &state_dir,
            "rust-clash-desktop",
            "0.5.15",
            "crates/proxy-core/src/inbound/tun.rs:450:13",
            "tun-worker",
            "second panic message",
            "frameA\nframeB",
            320,
        )
        .unwrap();

        assert!(log_path.exists());
        assert!(backup_path.exists());
        let active = fs::read_to_string(&log_path).unwrap();
        let rotated = fs::read_to_string(&backup_path).unwrap();
        assert!(active.contains("second panic message"));
        assert!(!active.contains("first panic"));
        assert!(rotated.contains("first panic"));
        assert!(!rotated.contains("secret-uuid"));

        let _ = fs::remove_dir_all(&state_dir);
    }

    #[cfg(unix)]
    #[test]
    fn append_crash_log_rejects_symlink_target() {
        use std::os::unix::fs::symlink;

        let state_dir = temp_test_dir("crash_symlink");
        let logs_dir = state_dir.join(CRASH_LOG_DIR_NAME);
        fs::create_dir_all(&logs_dir).unwrap();
        let outside = state_dir.join("outside.txt");
        fs::write(&outside, b"keep-me").unwrap();
        symlink(&outside, logs_dir.join(CRASH_LOG_FILENAME)).unwrap();

        let err = append_crash_log_entry(
            &state_dir,
            "rust-clash-cli",
            "0.5.15",
            "test:1:1",
            "main",
            "boom",
            "bt",
        )
        .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(fs::read_to_string(&outside).unwrap(), "keep-me");

        let _ = fs::remove_dir_all(&state_dir);
    }
}

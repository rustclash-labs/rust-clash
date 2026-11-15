use std::{
    fs::{self, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
};

use aws_lc_rs::{
    aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey},
    digest::{SHA256, digest},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::RngCore;
use zeroize::Zeroize;

#[cfg(any(target_os = "macos", target_os = "linux", test))]
const KEYCHAIN_SERVICE: &str = "io.github.rustclashlabs.rust-clash";
const MASTER_KEY_FILE: &str = "vault.master.key";

/// Cross-platform OS-backed secret storage for subscription tokens, credentials, and sensitive URIs.
///
/// Backends:
/// - **Windows**: Win32 DPAPI (`CryptProtectData` / `CryptUnprotectData` with `CRYPTPROTECT_UI_FORBIDDEN`),
///   cryptographically bound to the current Windows user logon credential.
/// - **macOS**: macOS Security Keychain (`/usr/bin/security` generic-password) when available and unlocked,
///   with automatic fallback to an `0600` AES-256-GCM authenticated vault in `state_dir/vault/`.
/// - **Linux / Unix**: Freedesktop Secret Service (`secret-tool` / `libsecret`) when a session DBus is active,
///   with automatic fallback to an `0600` AES-256-GCM authenticated vault in `state_dir/vault/`.
#[derive(Clone, Debug)]
pub struct SecretVault {
    vault_dir: PathBuf,
    force_file_backend: bool,
}

impl SecretVault {
    pub fn new(state_dir: &Path) -> Self {
        let force_file = std::env::var("RUST_CLASH_FORCE_FILE_VAULT")
            .ok()
            .is_some_and(|v| v == "1" || v.eq_ignore_ascii_case("true"));
        Self {
            vault_dir: state_dir.join("vault"),
            force_file_backend: force_file,
        }
    }

    pub fn new_file_backed(state_dir: &Path) -> Self {
        Self {
            vault_dir: state_dir.join("vault"),
            force_file_backend: true,
        }
    }

    pub fn backend_name(&self) -> &'static str {
        if self.force_file_backend {
            return "aes-256-gcm-0600-file-vault";
        }
        #[cfg(windows)]
        {
            "windows-dpapi"
        }
        #[cfg(target_os = "macos")]
        {
            "macos-keychain+aes256gcm-fallback"
        }
        #[cfg(target_os = "linux")]
        {
            if Self::has_linux_secret_service() {
                "linux-libsecret+aes256gcm-fallback"
            } else {
                "aes-256-gcm-0600-file-vault"
            }
        }
        #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
        {
            "aes-256-gcm-0600-file-vault"
        }
    }

    pub fn put_secret(&self, key_id: &str, plaintext: &str) -> io::Result<()> {
        if key_id.trim().is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "secret key_id cannot be empty",
            ));
        }

        if !self.force_file_backend {
            #[cfg(windows)]
            {
                return self.put_windows_dpapi(key_id, plaintext.as_bytes());
            }

            #[cfg(target_os = "macos")]
            {
                if self.try_put_macos_keychain(key_id, plaintext).is_ok() {
                    // Remove any stale file fallback so only one copy exists
                    let _ = fs::remove_file(self.entry_path(key_id, "enc"));
                    return Ok(());
                }
            }

            #[cfg(target_os = "linux")]
            {
                if Self::has_linux_secret_service()
                    && self.try_put_linux_secret_tool(key_id, plaintext).is_ok()
                {
                    let _ = fs::remove_file(self.entry_path(key_id, "enc"));
                    return Ok(());
                }
            }
        }

        self.put_encrypted_file(key_id, plaintext.as_bytes())
    }

    pub fn get_secret(&self, key_id: &str) -> io::Result<Option<String>> {
        if key_id.trim().is_empty() {
            return Ok(None);
        }

        if !self.force_file_backend {
            #[cfg(windows)]
            {
                return match self.get_windows_dpapi(key_id)? {
                    Some(mut bytes) => {
                        let res = String::from_utf8(bytes.clone()).map_err(|e| {
                            io::Error::new(io::ErrorKind::InvalidData, format!("utf8 secret: {e}"))
                        });
                        bytes.zeroize();
                        res.map(Some)
                    }
                    None => Ok(None),
                };
            }

            #[cfg(target_os = "macos")]
            {
                if let Ok(Some(val)) = self.try_get_macos_keychain(key_id) {
                    return Ok(Some(val));
                }
            }

            #[cfg(target_os = "linux")]
            {
                if Self::has_linux_secret_service()
                    && let Ok(Some(val)) = self.try_get_linux_secret_tool(key_id)
                {
                    return Ok(Some(val));
                }
            }
        }

        match self.get_encrypted_file(key_id)? {
            Some(mut bytes) => {
                let res = String::from_utf8(bytes.clone()).map_err(|e| {
                    io::Error::new(io::ErrorKind::InvalidData, format!("utf8 secret: {e}"))
                });
                bytes.zeroize();
                res.map(Some)
            }
            None => Ok(None),
        }
    }

    pub fn delete_secret(&self, key_id: &str) -> io::Result<()> {
        if !self.force_file_backend {
            #[cfg(windows)]
            {
                let p = self.entry_path(key_id, "dpapi");
                if p.exists() {
                    let _ = fs::remove_file(p);
                }
            }
            #[cfg(target_os = "macos")]
            {
                let _ = self.try_delete_macos_keychain(key_id);
            }
            #[cfg(target_os = "linux")]
            {
                if Self::has_linux_secret_service() {
                    let _ = self.try_delete_linux_secret_tool(key_id);
                }
            }
        }

        let enc_path = self.entry_path(key_id, "enc");
        match fs::remove_file(enc_path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }

    fn ensure_vault_dir(&self) -> io::Result<()> {
        fs::create_dir_all(&self.vault_dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Err(err) =
                fs::set_permissions(&self.vault_dir, fs::Permissions::from_mode(0o700))
            {
                tracing::warn!(
                    "Failed setting 0700 permissions on vault directory '{}': {err}",
                    self.vault_dir.display()
                );
            }
        }
        Ok(())
    }

    fn entry_path(&self, key_id: &str, ext: &str) -> PathBuf {
        let d = digest(&SHA256, key_id.as_bytes());
        let slug = URL_SAFE_NO_PAD.encode(&d.as_ref()[..16]);
        self.vault_dir.join(format!("item_{slug}.{ext}"))
    }

    fn read_existing_master_key(key_path: &Path) -> io::Result<[u8; 32]> {
        for attempt in 0..10 {
            let mut raw = fs::read(key_path)?;
            if raw.len() == 32 {
                let mut key = [0u8; 32];
                key.copy_from_slice(&raw);
                raw.zeroize();
                return Ok(key);
            }
            let was_empty = raw.is_empty();
            raw.zeroize();
            if !was_empty || attempt == 9 {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "corrupt vault master key '{}' (expected 32 bytes)",
                key_path.display()
            ),
        ))
    }

    fn publish_master_key_atomic(
        vault_dir: &Path,
        key_path: &Path,
        mut candidate: [u8; 32],
    ) -> io::Result<[u8; 32]> {
        let nonce = rand::rng().next_u64();
        let tmp_path = vault_dir.join(format!(
            "{MASTER_KEY_FILE}.tmp.{}.{nonce:016x}",
            std::process::id()
        ));
        let write_tmp = (|| -> io::Result<()> {
            let mut opts = OpenOptions::new();
            opts.write(true).create_new(true);
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
            f.write_all(&candidate)?;
            f.sync_all()?;
            Ok(())
        })();
        if let Err(err) = write_tmp {
            let _ = fs::remove_file(&tmp_path);
            candidate.zeroize();
            return Err(err);
        }

        let link_res = fs::hard_link(&tmp_path, key_path);
        let _ = fs::remove_file(&tmp_path);

        match link_res {
            Ok(()) => Ok(candidate),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                candidate.zeroize();
                Self::read_existing_master_key(key_path)
            }
            Err(_) => {
                let mut opts = OpenOptions::new();
                opts.write(true).create_new(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    opts.mode(0o600);
                }
                match opts.open(key_path) {
                    Ok(mut f) => {
                        let direct_res = (|| -> io::Result<()> {
                            #[cfg(unix)]
                            {
                                use std::os::unix::fs::PermissionsExt;
                                f.set_permissions(fs::Permissions::from_mode(0o600))?;
                            }
                            f.write_all(&candidate)?;
                            f.sync_all()?;
                            Ok(())
                        })();
                        if let Err(err) = direct_res {
                            drop(f);
                            let _ = fs::remove_file(key_path);
                            candidate.zeroize();
                            return Err(err);
                        }
                        Ok(candidate)
                    }
                    Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                        candidate.zeroize();
                        Self::read_existing_master_key(key_path)
                    }
                    Err(e) => {
                        candidate.zeroize();
                        Err(e)
                    }
                }
            }
        }
    }

    fn load_or_create_master_key(&self) -> io::Result<[u8; 32]> {
        static MASTER_KEY_INIT_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
        let _guard = MASTER_KEY_INIT_LOCK.lock();

        self.ensure_vault_dir()?;
        let key_path = self.vault_dir.join(MASTER_KEY_FILE);
        if key_path.exists() {
            return Self::read_existing_master_key(&key_path);
        }

        let mut candidate = [0u8; 32];
        rand::rng().fill_bytes(&mut candidate);
        Self::publish_master_key_atomic(&self.vault_dir, &key_path, candidate)
    }

    fn put_encrypted_file(&self, key_id: &str, plaintext: &[u8]) -> io::Result<()> {
        let mut master_key = self.load_or_create_master_key()?;
        let unbound = UnboundKey::new(&AES_256_GCM, &master_key)
            .map_err(|_| io::Error::other("AES-256-GCM key init failed"))?;
        master_key.zeroize();
        let aead_key = LessSafeKey::new(unbound);

        let mut nonce_bytes = [0u8; 12];
        rand::rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);

        let mut buf = plaintext.to_vec();
        aead_key
            .seal_in_place_append_tag(nonce, Aad::from(key_id.as_bytes()), &mut buf)
            .map_err(|_| io::Error::other("AES-256-GCM seal failed"))?;

        let mut blob = Vec::with_capacity(12 + buf.len());
        blob.extend_from_slice(&nonce_bytes);
        blob.extend_from_slice(&buf);
        buf.zeroize();

        let target = self.entry_path(key_id, "enc");
        let tmp_nonce = rand::rng().next_u64();
        let tmp = target.with_extension(format!("enc.tmp.{}.{tmp_nonce:016x}", std::process::id()));
        {
            let mut opts = OpenOptions::new();
            opts.create(true).write(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            let mut f = opts.open(&tmp)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                f.set_permissions(fs::Permissions::from_mode(0o600))?;
            }
            f.write_all(&blob)?;
            f.sync_all()?;
        }
        if let Err(err) = fs::rename(&tmp, &target) {
            let _ = fs::remove_file(&tmp);
            return Err(err);
        }
        Ok(())
    }

    fn get_encrypted_file(&self, key_id: &str) -> io::Result<Option<Vec<u8>>> {
        let target = self.entry_path(key_id, "enc");
        if !target.exists() {
            return Ok(None);
        }
        let raw = fs::read(&target)?;
        if raw.len() < 12 + 16 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "corrupt encrypted secret entry (truncated)",
            ));
        }
        let mut master_key = self.load_or_create_master_key()?;
        let unbound = UnboundKey::new(&AES_256_GCM, &master_key)
            .map_err(|_| io::Error::other("AES-256-GCM key init failed"))?;
        master_key.zeroize();
        let aead_key = LessSafeKey::new(unbound);

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes.copy_from_slice(&raw[..12]);
        let mut ciphertext = raw[12..].to_vec();

        let opened = aead_key
            .open_in_place(
                Nonce::assume_unique_for_key(nonce_bytes),
                Aad::from(key_id.as_bytes()),
                &mut ciphertext,
            )
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "secret vault authentication failed (tampered ciphertext or mismatched key)",
                )
            })?;
        Ok(Some(opened.to_vec()))
    }

    #[cfg(windows)]
    fn put_windows_dpapi(&self, key_id: &str, plaintext: &[u8]) -> io::Result<()> {
        use windows_sys::Win32::{
            Foundation::LocalFree,
            Security::Cryptography::{
                CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData,
            },
        };

        self.ensure_vault_dir()?;
        let in_blob = CRYPT_INTEGER_BLOB {
            cbData: plaintext.len() as u32,
            pbData: plaintext.as_ptr() as *mut u8,
        };
        let entropy_bytes = key_id.as_bytes();
        let entropy_blob = CRYPT_INTEGER_BLOB {
            cbData: entropy_bytes.len() as u32,
            pbData: entropy_bytes.as_ptr() as *mut u8,
        };
        let mut out_blob = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: std::ptr::null_mut(),
        };

        // SAFETY: `in_blob` and `entropy_blob` reference valid slices for the duration of `CryptProtectData`;
        // `out_blob.pbData` is freed immediately via `LocalFree`.
        let protected = unsafe {
            let ok = CryptProtectData(
                &in_blob,
                std::ptr::null(),
                &entropy_blob,
                std::ptr::null_mut(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out_blob,
            );
            if ok == 0 || out_blob.pbData.is_null() {
                return Err(io::Error::last_os_error());
            }
            let slice =
                std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize).to_vec();
            let _ = LocalFree(out_blob.pbData as *mut _);
            slice
        };

        let target = self.entry_path(key_id, "dpapi");
        let tmp_nonce = rand::rng().next_u64();
        let tmp =
            target.with_extension(format!("dpapi.tmp.{}.{tmp_nonce:016x}", std::process::id()));
        fs::write(&tmp, &protected)?;
        if let Err(err) = fs::rename(&tmp, &target) {
            let _ = fs::remove_file(&tmp);
            return Err(err);
        }
        Ok(())
    }

    #[cfg(windows)]
    fn get_windows_dpapi(&self, key_id: &str) -> io::Result<Option<Vec<u8>>> {
        use windows_sys::Win32::{
            Foundation::LocalFree,
            Security::Cryptography::{
                CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptUnprotectData,
            },
        };

        let target = self.entry_path(key_id, "dpapi");
        if !target.exists() {
            return Ok(None);
        }
        let encrypted = fs::read(&target)?;
        let in_blob = CRYPT_INTEGER_BLOB {
            cbData: encrypted.len() as u32,
            pbData: encrypted.as_ptr() as *mut u8,
        };
        let entropy_bytes = key_id.as_bytes();
        let entropy_blob = CRYPT_INTEGER_BLOB {
            cbData: entropy_bytes.len() as u32,
            pbData: entropy_bytes.as_ptr() as *mut u8,
        };
        let mut out_blob = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: std::ptr::null_mut(),
        };

        // SAFETY: `in_blob` and `entropy_blob` outlive `CryptUnprotectData`; output buffer freed via `LocalFree`.
        unsafe {
            let ok = CryptUnprotectData(
                &in_blob,
                std::ptr::null_mut(),
                &entropy_blob,
                std::ptr::null_mut(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out_blob,
            );
            if ok == 0 || out_blob.pbData.is_null() {
                return Err(io::Error::last_os_error());
            }
            let plain =
                std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize).to_vec();
            std::ptr::write_bytes(out_blob.pbData, 0, out_blob.cbData as usize);
            let _ = LocalFree(out_blob.pbData as *mut _);
            Ok(Some(plain))
        }
    }

    #[cfg(target_os = "macos")]
    fn try_put_macos_keychain(&self, key_id: &str, plaintext: &str) -> io::Result<()> {
        use std::process::Stdio;
        let mut cmd_line = build_macos_security_stdin_command(key_id, plaintext)?;
        let mut child = std::process::Command::new("/usr/bin/security")
            .arg("-i")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .inspect_err(|_| cmd_line.zeroize())?;
        let write_res = if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(cmd_line.as_bytes())
                .and_then(|()| stdin.flush())
        } else {
            Err(io::Error::other("macOS security -i stdin unavailable"))
        };
        cmd_line.zeroize();
        write_res?;
        let status = child.wait()?;
        if status.success() {
            Ok(())
        } else {
            Err(io::Error::other(
                "macOS security keychain write unavailable",
            ))
        }
    }

    #[cfg(target_os = "macos")]
    fn try_get_macos_keychain(&self, key_id: &str) -> io::Result<Option<String>> {
        let out = std::process::Command::new("/usr/bin/security")
            .args([
                "find-generic-password",
                "-s",
                KEYCHAIN_SERVICE,
                "-a",
                key_id,
                "-w",
            ])
            .output()?;
        if !out.status.success() {
            return Ok(None);
        }
        let hex_str = String::from_utf8_lossy(&out.stdout).trim().to_string();
        let bytes = hex::decode(hex_str)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        let text = String::from_utf8(bytes)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        Ok(Some(text))
    }

    #[cfg(target_os = "macos")]
    fn try_delete_macos_keychain(&self, key_id: &str) -> io::Result<()> {
        let _ = std::process::Command::new("/usr/bin/security")
            .args([
                "delete-generic-password",
                "-s",
                KEYCHAIN_SERVICE,
                "-a",
                key_id,
            ])
            .output()?;
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn has_linux_secret_service() -> bool {
        let has_dbus = std::env::var("DBUS_SESSION_BUS_ADDRESS")
            .ok()
            .is_some_and(|s| !s.trim().is_empty());
        has_dbus && Path::new("/usr/bin/secret-tool").exists()
    }

    #[cfg(target_os = "linux")]
    fn try_put_linux_secret_tool(&self, key_id: &str, plaintext: &str) -> io::Result<()> {
        use std::process::Stdio;
        let mut child = std::process::Command::new("/usr/bin/secret-tool")
            .args([
                "store",
                "--label=RustClash Secret",
                "service",
                KEYCHAIN_SERVICE,
                "account",
                key_id,
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(plaintext.as_bytes())?;
        }
        let status = child.wait()?;
        if status.success() {
            Ok(())
        } else {
            Err(io::Error::other("secret-tool store failed"))
        }
    }

    #[cfg(target_os = "linux")]
    fn try_get_linux_secret_tool(&self, key_id: &str) -> io::Result<Option<String>> {
        let out = std::process::Command::new("/usr/bin/secret-tool")
            .args(["lookup", "service", KEYCHAIN_SERVICE, "account", key_id])
            .output()?;
        if !out.status.success() {
            return Ok(None);
        }
        Ok(Some(String::from_utf8_lossy(&out.stdout).to_string()))
    }

    #[cfg(target_os = "linux")]
    fn try_delete_linux_secret_tool(&self, key_id: &str) -> io::Result<()> {
        let _ = std::process::Command::new("/usr/bin/secret-tool")
            .args(["clear", "service", KEYCHAIN_SERVICE, "account", key_id])
            .output()?;
        Ok(())
    }
}

#[cfg(any(target_os = "macos", test))]
fn build_macos_security_stdin_command(key_id: &str, plaintext: &str) -> io::Result<String> {
    if key_id.is_empty()
        || key_id
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || matches!(c, '\'' | '"' | '\\'))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid macOS Keychain key_id (must not contain whitespace, quotes, backslashes, or control characters)",
        ));
    }
    let mut encoded = hex::encode(plaintext.as_bytes());
    let cmd = format!("add-generic-password -U -s {KEYCHAIN_SERVICE} -a {key_id} -w {encoded}\n");
    encoded.zeroize();
    Ok(cmd)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn macos_security_stdin_command_encodes_secret_and_rejects_shell_chars_in_key_id() {
        let cmd = build_macos_security_stdin_command("sub:alpha_1", "my-secret-token").unwrap();
        let expected_prefix =
            format!("add-generic-password -U -s {KEYCHAIN_SERVICE} -a sub:alpha_1 -w ");
        assert!(cmd.starts_with(&expected_prefix));
        assert!(cmd.ends_with('\n'));
        assert!(!cmd.contains("my-secret-token"));

        for bad_id in [
            "",
            "bad space",
            "quote\"id",
            "single'id",
            "back\\slash",
            "line\ninject",
        ] {
            assert!(
                build_macos_security_stdin_command(bad_id, "secret").is_err(),
                "expected bad key_id '{bad_id:?}' to be rejected"
            );
        }
    }

    #[test]
    fn secret_vault_roundtrip_tamper_detection_and_0600_permissions() {
        let dir = std::env::temp_dir().join(format!("rc-vault-test-{}", uuid::Uuid::new_v4()));
        let vault = SecretVault::new_file_backed(&dir);

        assert_eq!(vault.get_secret("sub:alpha").unwrap(), None);
        vault
            .put_secret(
                "sub:alpha",
                "https://provider.example/sub?token=super-secret-token-2026",
            )
            .unwrap();
        assert_eq!(
            vault.get_secret("sub:alpha").unwrap().as_deref(),
            Some("https://provider.example/sub?token=super-secret-token-2026")
        );

        // Verify AAD key binding: copying ciphertext to another key_id MUST fail authentication!
        let p_alpha = vault.entry_path("sub:alpha", "enc");
        let p_beta = vault.entry_path("sub:beta", "enc");
        fs::copy(&p_alpha, &p_beta).unwrap();
        assert!(
            vault.get_secret("sub:beta").is_err(),
            "swapped key_id AAD must reject ciphertext"
        );
        vault.delete_secret("sub:beta").unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let key_mode = fs::metadata(dir.join("vault").join(MASTER_KEY_FILE))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(key_mode, 0o600, "master key file must be 0600");
            let entry_mode = fs::metadata(&p_alpha).unwrap().permissions().mode() & 0o777;
            assert_eq!(entry_mode, 0o600, "encrypted entry file must be 0600");
        }

        // Tamper 1 byte in ciphertext and verify AEAD tag failure
        let mut raw = fs::read(&p_alpha).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 0x55;
        fs::write(&p_alpha, &raw).unwrap();
        assert!(vault.get_secret("sub:alpha").is_err());

        vault.delete_secret("sub:alpha").unwrap();
        assert_eq!(vault.get_secret("sub:alpha").unwrap(), None);

        // Also test default OS backend on current platform (DPAPI on Windows, file/keychain on Unix)
        let os_vault = SecretVault::new(&dir);
        os_vault
            .put_secret("os-test-key", "os-secret-payload-99")
            .unwrap();
        assert_eq!(
            os_vault.get_secret("os-test-key").unwrap().as_deref(),
            Some("os-secret-payload-99")
        );
        os_vault.delete_secret("os-test-key").unwrap();

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn concurrent_first_time_secret_vault_init_never_clobbers_master_key() {
        use std::sync::{Arc, Barrier};

        let dir =
            std::env::temp_dir().join(format!("rc-vault-concurrent-test-{}", uuid::Uuid::new_v4()));
        let worker_count = 16usize;
        let barrier = Arc::new(Barrier::new(worker_count));
        let mut handles = Vec::with_capacity(worker_count);

        for idx in 0..worker_count {
            let dir_c = dir.clone();
            let bar_c = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                let v = SecretVault::new_file_backed(&dir_c);
                bar_c.wait();
                v.put_secret(
                    &format!("concurrent-sub-{idx}"),
                    &format!("secret-token-value-{idx}"),
                )
                .expect("concurrent put_secret must succeed");
            }));
        }

        for h in handles {
            h.join().expect("worker thread panicked");
        }

        // Every thread's ciphertext MUST authenticate cleanly under the single winning master key!
        let reader = SecretVault::new_file_backed(&dir);
        for idx in 0..worker_count {
            let got = reader.get_secret(&format!("concurrent-sub-{idx}")).expect(
                "ciphertext written during concurrent init must decrypt without tag mismatch",
            );
            assert_eq!(
                got.as_deref(),
                Some(format!("secret-token-value-{idx}").as_str())
            );
        }

        // Simulate cross-process race (`AlreadyExists` on `hard_link` / `create_new(true)`):
        // losing process must return the winning on-disk key without overwriting `vault.master.key`.
        let mp_dir =
            std::env::temp_dir().join(format!("rc-vault-multiproc-test-{}", uuid::Uuid::new_v4()));
        let mp_vault = SecretVault::new_file_backed(&mp_dir);
        mp_vault.ensure_vault_dir().unwrap();
        let key_path = mp_vault.vault_dir.join(MASTER_KEY_FILE);
        let winning_key = [0x42u8; 32];
        let first =
            SecretVault::publish_master_key_atomic(&mp_vault.vault_dir, &key_path, winning_key)
                .unwrap();
        assert_eq!(first, winning_key);

        let losing_candidate = [0x99u8; 32];
        let second = SecretVault::publish_master_key_atomic(
            &mp_vault.vault_dir,
            &key_path,
            losing_candidate,
        )
        .unwrap();
        assert_eq!(
            second, winning_key,
            "losing concurrent process must adopt winning master key"
        );
        assert_eq!(fs::read(&key_path).unwrap(), winning_key);

        let _ = fs::remove_dir_all(&dir);
        let _ = fs::remove_dir_all(&mp_dir);
    }
}

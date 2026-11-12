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

#[cfg(any(target_os = "macos", target_os = "linux"))]
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
            let _ = fs::set_permissions(&self.vault_dir, fs::Permissions::from_mode(0o700));
        }
        Ok(())
    }

    fn entry_path(&self, key_id: &str, ext: &str) -> PathBuf {
        let d = digest(&SHA256, key_id.as_bytes());
        let slug = URL_SAFE_NO_PAD.encode(&d.as_ref()[..16]);
        self.vault_dir.join(format!("item_{slug}.{ext}"))
    }

    fn load_or_create_master_key(&self) -> io::Result<[u8; 32]> {
        self.ensure_vault_dir()?;
        let key_path = self.vault_dir.join(MASTER_KEY_FILE);
        if key_path.exists() {
            let raw = fs::read(&key_path)?;
            if raw.len() == 32 {
                let mut key = [0u8; 32];
                key.copy_from_slice(&raw);
                return Ok(key);
            }
        }

        let mut key = [0u8; 32];
        rand::rng().fill_bytes(&mut key);
        let tmp_path = self
            .vault_dir
            .join(format!("{MASTER_KEY_FILE}.tmp.{}", std::process::id()));
        {
            let mut f = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&tmp_path)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                f.set_permissions(fs::Permissions::from_mode(0o600))?;
            }
            f.write_all(&key)?;
            f.sync_all()?;
        }
        fs::rename(&tmp_path, &key_path)?;
        Ok(key)
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
        let tmp = target.with_extension(format!("enc.tmp.{}", std::process::id()));
        {
            let mut f = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&tmp)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                f.set_permissions(fs::Permissions::from_mode(0o600))?;
            }
            f.write_all(&blob)?;
            f.sync_all()?;
        }
        fs::rename(&tmp, &target)?;
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
        let tmp = target.with_extension(format!("dpapi.tmp.{}", std::process::id()));
        fs::write(&tmp, &protected)?;
        fs::rename(&tmp, &target)?;
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
        let encoded = hex::encode(plaintext.as_bytes());
        let out = std::process::Command::new("/usr/bin/security")
            .args([
                "add-generic-password",
                "-U",
                "-s",
                KEYCHAIN_SERVICE,
                "-a",
                key_id,
                "-w",
                &encoded,
            ])
            .output()?;
        if out.status.success() {
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

#[cfg(test)]
mod tests {
    use super::*;

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
}

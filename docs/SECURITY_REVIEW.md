# Security Architecture & Hardening Review

This document summarizes the threat model, security controls, supply-chain protections, and automated regression tests protecting `rust-clash` across Windows, macOS, Linux, and Android.

---

## 1. Threat Model

`rust-clash` operates at a high-trust boundary: it holds long-lived proxy credentials and subscription URLs, exposes a local HTTP/WebSocket management controller, accepts local/LAN proxy connections, and (when TUN/VPN is enabled) processes raw L3/L4 network packets.

We defend against six primary threat classes:
1. **Malicious Browser Tabs (Drive-by CSRF & DNS Rebinding)** attempting to read proxy credentials or hijack system proxy/TUN settings via `127.0.0.1:9090`.
2. **Unauthorized LAN Peers** probing Mixed Inbound (`:7890`) or Control API (`:9090`).
3. **Silent Cleartext / Direct Traffic Leaks** caused by malformed rules, cyclic proxy groups, unauthenticated SOCKS5 fallback, or routing loops.
4. **Credential Leakage at Rest, in UI/API Responses, or in Diagnostic Bundles**.
5. **Privileged Helper / Driver Hijacking** (Windows DLL search-order hijacking, unverified driver downloads, orphaned routes/DNS after crashes).
6. **Protocol Replay & Resource Exhaustion** (Shadowsocks-2022 salt replay, slowloris inbound connections, unbounded TUN packet queues).

---

## 2. Implemented Security Controls

### 2.1 Control API & WebView Defense-in-Depth (`crates/proxy-core/src/api/mod.rs`)
- **Anti-DNS-Rebinding (`Host` Validation)**: Every HTTP and WebSocket request (including static UI assets) validates the `Host` header against `127.0.0.1`, `localhost`, `[::1]`, or the exact bound IP when authenticated. Requests bearing attacker domains (`evil.rebind.attacker.com:9090`) fail immediately with `403 Forbidden`.
- **Anti-CSRF (`Origin` & `Sec-Fetch-Site`)**: Requests from untrusted browser `Origin`s (`https://evil.example`, `http://localhost:3000`, `Origin: null`) or `Sec-Fetch-Site: cross-site` are rejected with `403 Forbidden` unless accompanied by a valid configured Bearer `secret`.
- **Constant-Time Bearer & WebSocket Query Authentication**: Secrets are compared via bitwise constant-time comparison (`constant_time_eq`) across `Authorization: Bearer`, percent-decoded `?token=` (Clash/Mihomo compatible), and `?secret=`. Non-loopback peers are unconditionally blocked (`403` / `401`) unless a non-empty `secret` is configured and presented.
- **Query-Token Scrubbing in UI (`ui/src/api.ts`)**: When launched with `/?secret=<ephemeral-token>`, the frontend captures the token into memory/`sessionStorage` on boot and immediately strips `?secret=` via `window.history.replaceState`.
- **Restrictive Tauri 2 CSP & Native Android UI**: `crates/tauri-app/tauri.conf.json` enforces an explicit Content Security Policy restricting scripts and connections to `'self'`, Tauri IPC, and `127.0.0.1` / `localhost`, while the Android app uses a 100% native Jetpack Compose UI communicating directly over in-process JNI (zero external WebView surface) and restricts `FileProvider` diagnostic exports exclusively to `cache-path/diagnostics/`.

### 2.2 Zero-Leak Redaction (`GET /configs/raw` & `GET /diagnostics/export`)
- `ClashConfig::redacted()` (`crates/proxy-core/src/config/mod.rs`) scrubs:
  - `secret` -> `***REDACTED***`
  - `authentication` passwords -> `user:***REDACTED***`
  - Shadowsocks, Trojan, AnyTLS, SOCKS5 & HTTP `password` -> `***REDACTED***`
  - VLESS `uuid` -> `00000000-0000-0000-0000-000000000000` (`Uuid::nil()`) and `encryption` -> `***REDACTED***`
  - `rule-providers` Basic-Auth credentials -> `***REDACTED***`
- `ClashConfig::restore_redacted_from()` transparently rehydrates nil VLESS UUIDs and `***REDACTED***` secrets across all 6 outbound protocol types on hot-reload (`PUT /configs`), so editing rules in the Web Console never overwrites real credentials.
- `GET /diagnostics/export` additionally runs `scrub_sensitive_substrings()` across exported YAML and recent log buffers, redacting all known secrets, `ss://` / `vless://` / `trojan://` / `anytls://` / `socks5://` / `http-proxy://` URIs, `http(s)://user:pass@` userinfo, and HTTPS subscription query/path tokens (`redact_subscription_url`). Verified by [`milestone5_product_e2e.rs`](../crates/proxy-core/tests/milestone5_product_e2e.rs).

### 2.3 Encrypted Secret Storage at Rest (`crates/proxy-core/src/platform/keystore.rs`)
- Subscription URLs (containing provider tokens) are never written to `profiles_index.json`; only redacted display URLs (`https://host/***REDACTED***`) are stored in metadata while raw URLs are stored in `SecretVault`:
  - **Windows**: Win32 DPAPI (`CryptProtectData` / `CryptUnprotectData` with `CRYPTPROTECT_UI_FORBIDDEN`).
  - **macOS**: Security Keychain (`/usr/bin/security add-generic-password` / `find-generic-password`).
  - **Linux**: Freedesktop Secret Service (`secret-tool`) with automatic fallback to an `0600` (`0700` directory) `AES-256-GCM` authenticated file vault (`aws-lc-rs`) with `zeroize` memory scrubbing.
  - **Android**: Hardware-backed `AndroidKeyStore` `AES/GCM/NoPadding` (`AndroidKeystoreVault.kt`).

### 2.4 Fail-Closed Routing & Inbound Access Control
- **No Silent `DIRECT` Fallback**: `ClashConfig::validate()` rejects unknown proxy targets, empty groups, and cyclic group references via DFS cycle detection at load time. At runtime, `Router::resolve_chain()` fails closed to `REJECT` if a target cannot be resolved; `DIRECT` is used **only** when explicitly configured.
- **Mixed Inbound Hardening (`crates/proxy-core/src/inbound/mixed.rs`)**:
  - Enforces RFC 1929 (`0x02`) username/password negotiation for SOCKS5 and `407 Proxy-Authenticate` for HTTP when `authentication` is configured (never accepting `0x00` No-Auth).
  - Enforces `lan-allowed-ips` CIDR ACLs when `allow-lan: true`, handshake read timeouts, and a 2,048-permit concurrency `Semaphore`.
  - Locks SOCKS5 `UDP ASSOCIATE` sockets to the authenticated TCP control client's IP address, dropping spoofed third-party UDP datagrams.

### 2.5 Platform & Supply-Chain Hardening
- **Windows DLL Search-Order Protection**: `wintun.dll` is loaded exclusively with `LoadLibraryExW(..., LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32)`.
- **SHA-256 Supply-Chain Pinning**:
  - `scripts/fetch_wintun.py` verifies `wintun-0.14.1.zip` against `07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51` before extracting a single byte (with an offline tamper-rejection `--self-test` run in CI).
  - `.github/workflows/ci.yml` and `scripts/run_comparative_benchmarks.py` verify pinned SHA-256 digests for `shadowsocks-rust`, `Xray-core`, `anytls-go`, `mihomo`, and `sing-box`.
- **Protocol Replay Defense**: Shadowsocks-2022 (`2022-blake3-*`) enforces ±30s timestamp validation and a 60s salt replay filter on both TCP streams and UDP sessions; bounded channels (`mpsc::channel`) enforce backpressure across `smoltcp` TUN queues.

---

## 3. Automated Security Regression Coverage

| Security Test | File | Status |
| :--- | :--- | :--- |
| Anti-DNS-rebinding, Anti-CSRF `Origin`/`Sec-Fetch-Site`, Bearer & WS auth, `/configs/raw` redaction + hot-reload rehydration | [`security_and_hardening_e2e.rs`](../crates/proxy-core/tests/security_and_hardening_e2e.rs) | **PASS** |
| SOCKS5 RFC 1929 auth, HTTP 407 auth, UDP ASSOCIATE peer IP lock, LAN CIDR ACLs | [`security_and_hardening_e2e.rs`](../crates/proxy-core/tests/security_and_hardening_e2e.rs) | **PASS** |
| Cyclic proxy-group rejection & zero silent `DIRECT` fallback | [`security_and_hardening_e2e.rs`](../crates/proxy-core/tests/security_and_hardening_e2e.rs) | **PASS** |
| `SecretVault` AES-256-GCM encryption, ciphertext tamper rejection & `0600` file permissions | [`keystore.rs`](../crates/proxy-core/src/platform/keystore.rs) | **PASS** |
| TLS 1.3 subscription refresh, failed-update atomic rollback & zero-leak `/diagnostics/export` | [`milestone5_product_e2e.rs`](../crates/proxy-core/tests/milestone5_product_e2e.rs) | **PASS** |
| Wintun archive SHA-256 tamper rejection (`--self-test`) | [`fetch_wintun.py`](../scripts/fetch_wintun.py) | **PASS** |
| Android Per-App Lockdown conflict protection (preserving `protect(fd)`) | [`VpnConfigAndLifecycleTest.kt`](../android/app/src/test/java/io/github/rustclashlabs/rustclash/VpnConfigAndLifecycleTest.kt) | **PASS** |

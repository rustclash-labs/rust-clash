# Security Architecture & Hardening Review (`v0.4.0+`)

This document summarizes the threat model, security controls, supply-chain protections, and automated regression tests protecting `rust-clash` across Windows, macOS, Linux, and Android.

---

## 1. Threat Model

`rust-clash` operates at a high-trust boundary: it holds long-lived proxy credentials and subscription URLs, exposes a local management controller on desktop/CLI hosts (while using direct in-process JNI only on Android), accepts local/LAN proxy connections, and (when TUN/VPN is enabled) processes raw L3/L4 network packets.

We defend against seven primary threat classes:
1. **Unauthenticated Local Processes & Malicious Browser Tabs (Drive-by CSRF & DNS Rebinding)** attempting to read proxy credentials or hijack system proxy/TUN settings via `127.0.0.1:9090`.
2. **Unauthorized LAN Peers** probing Mixed Inbound (`:7890`) or Control API (`:9090`).
3. **Hostile / Compromised Remote Subscription Servers** attempting to inject dangerous daemon settings (`secret`, `allow-lan`, `bind-address`, `authentication`, `external-controller`) or traverse local filesystems via `file` `rule-providers` or `rule-providers.path`.
4. **Silent Cleartext / Direct Traffic Leaks** caused by malformed rules, cyclic proxy groups, unauthenticated SOCKS5 fallback, or routing loops.
5. **Credential Leakage at Rest, in Browser Storage/History, in UI/API Responses, or in Diagnostic Bundles**.
6. **Privileged Helper / Driver Hijacking** (Windows DLL search-order hijacking, unverified driver downloads, secrets leaked via CLI `argv`, orphaned routes/DNS after crashes).
7. **Protocol Replay & Resource Exhaustion** (Shadowsocks-2022 salt replay, slowloris inbound connections, unbounded TUN packet queues).

---

## 2. Implemented Security Controls

### 2.1 Control Plane, Ephemeral Auth & Native Android Isolation (`crates/proxy-core/src/api/mod.rs`)
- **Default CSPRNG Ephemeral `secret` (Desktop, CLI & Privileged Helper)**: Whenever a configuration omits an explicit controller `secret`, Desktop (`tauri-app`), CLI (`proxy-cli`), and `elevated-tun-helper` automatically generate a fresh CSPRNG ephemeral `secret` at startup. Loopback Control API endpoints (`127.0.0.1:9090`) are therefore authenticated by default rather than left open to unprivileged local processes or browser tabs.
- **Android Direct In-Process JNI Only (Zero Loopback HTTP Control API)**: On Android (`crates/proxy-ffi`), `RustClashVpnService` and the native Jetpack Compose UI invoke the Rust engine strictly via direct in-process JNI calls. **No loopback HTTP or WebSocket Control API server is spawned on Android at all**, completely eliminating local TCP port-probing, WebView, and cross-origin browser attack surfaces on mobile devices.
- **Anti-DNS-Rebinding (`Host` Validation)**: Every desktop/CLI HTTP and WebSocket request (including static UI assets) validates the `Host` header against `127.0.0.1`, `localhost`, `[::1]`, or the exact bound IP when authenticated. Requests bearing attacker domains (`evil.rebind.attacker.com:9090`) fail immediately with `403 Forbidden`.
- **Anti-CSRF (`Origin` & `Sec-Fetch-Site`)**: Requests from untrusted browser `Origin`s (`https://evil.example`, `http://localhost:3000`, `Origin: null`) or `Sec-Fetch-Site: cross-site` are rejected with `403 Forbidden` unless accompanied by a valid configured Bearer `secret`.
- **Constant-Time Bearer & WebSocket Query Authentication**: Secrets are compared via bitwise constant-time comparison (`constant_time_eq`) across `Authorization: Bearer`, percent-decoded `?token=` (Clash/Mihomo compatible), and `?secret=`. Non-loopback peers are unconditionally blocked (`403` / `401`) unless a non-empty `secret` is configured and presented.
- **Session-Scoped Secret & URL Query Scrubbing in Web UI ([`ui/src/api.ts`](../ui/src/api.ts))**: When launched with `/?secret=<ephemeral-token>` (or `?token=`), the frontend stores the token in tab-scoped `sessionStorage` (`rust_clash_session_secret_v1`), migrates and scrubs any legacy persistent `secret` from `localStorage` so tokens do not persist indefinitely on shared disks, and immediately strips `?secret=` and `?token=` from the browser address bar via `window.history.replaceState` so credentials are never left exposed in browser history or `Referer` headers.
- **Restrictive Tauri 2 CSP & Scoped Android `FileProvider`**: `crates/tauri-app/tauri.conf.json` enforces an explicit Content Security Policy restricting scripts and connections to `'self'`, Tauri IPC, and `127.0.0.1` / `localhost`, while Android restricts `FileProvider` diagnostic exports exclusively to `cache-path/diagnostics/`.

### 2.2 Untrusted Subscription Sanitization & `rule-providers.path` Confinement
- **Remote Subscription Sanitization**: Remote subscription payloads (Clash YAML and proxy URI bundles) are treated as untrusted network input. Before persisting or activating a remote subscription profile, `rust-clash` strips control-plane and listener exposure fields (`secret`, `external-controller`, `allow-lan`, `bind-address`, `authentication`) and rejects/strips `file`-type providers so a remote subscription server cannot disable controller authentication, expose LAN proxy ports, or read local host files.
- **`rule-providers.path` State-Directory Confinement**: Every `rule-providers.<name>.path` entry is validated and strictly confined within `state_dir`. Configurations specifying absolute paths outside `state_dir`, parent-directory traversal (`..`), or symlink escapes are rejected before any read or write occurs.

### 2.3 Zero-Leak Redaction (`GET /configs/raw` & `GET /diagnostics/export`)
- `ClashConfig::redacted()` (`crates/proxy-core/src/config/mod.rs`) scrubs:
  - `secret` -> `***REDACTED***`
  - `authentication` passwords -> `user:***REDACTED***`
  - Shadowsocks, Trojan, AnyTLS, SOCKS5 & HTTP `password` -> `***REDACTED***`
  - VLESS `uuid` -> `00000000-0000-0000-0000-000000000000` (`Uuid::nil()`) and `encryption` -> `***REDACTED***`
  - `rule-providers` Basic-Auth credentials -> `***REDACTED***`
- `ClashConfig::restore_redacted_from()` transparently rehydrates nil VLESS UUIDs and `***REDACTED***` secrets across all 6 outbound protocol types on hot-reload (`PUT /configs`), so editing rules in the Web Console never overwrites real credentials.
- `GET /diagnostics/export` additionally runs `scrub_sensitive_substrings()` across exported YAML and recent log buffers, redacting all known secrets, `ss://` / `vless://` / `trojan://` / `anytls://` / `socks5://` / `http-proxy://` URIs, `http(s)://user:pass@` userinfo, and HTTPS subscription query/path tokens (`redact_subscription_url`). Verified by [`milestone5_product_e2e.rs`](../crates/proxy-core/tests/milestone5_product_e2e.rs).

### 2.4 Secret Storage at Rest (`SecretVault` in `crates/proxy-core/src/platform/keystore.rs`)
Subscription URLs (containing provider tokens) are never written in cleartext to `profiles_index.json`; only redacted display URLs (`https://host/***REDACTED***`) are stored in profile metadata while raw URLs are persisted via `SecretVault` per platform:
- **Windows**: Win32 DPAPI (`CryptProtectData` / `CryptUnprotectData` with `CRYPTPROTECT_UI_FORBIDDEN`), binding ciphertext to the current Windows user logon credential.
- **macOS**: macOS Keychain via `/usr/bin/security -i` interactive stdin commands so secrets are piped over standard input rather than exposed on process `argv` (`ps`).
- **Linux**: `libsecret` (`secret-tool` via stdin pipe) when a D-Bus Secret Service session is available, with automatic fallback to a `0600` (`0700` parent directory) local `AES-256-GCM` authenticated file vault (`aws-lc-rs` + `zeroize` memory scrubbing) in headless or minimal environments where D-Bus/`secret-tool` is absent.
- **Android**: `0700` app-sandboxed internal file store (`Context.filesDir` isolated by Android kernel UID enforcement, with `android:allowBackup="false"` in `AndroidManifest.xml` preventing ADB/cloud backup extraction). *(Note: `SecretVault` on Android relies on app-private `0700`/`0600` UID sandbox isolation and `allowBackup="false"`, not hardware-backed `AndroidKeyStore` wrapping.)*

### 2.5 Fail-Closed Routing & Inbound Access Control
- **No Silent `DIRECT` Fallback**: `ClashConfig::validate()` rejects unknown proxy targets, empty groups, and cyclic group references via DFS cycle detection at load time. At runtime, `Router::resolve_chain()` fails closed to `REJECT` if a target cannot be resolved; `DIRECT` is used **only** when explicitly configured.
- **Mixed Inbound Hardening (`crates/proxy-core/src/inbound/mixed.rs`)**:
  - Enforces RFC 1929 (`0x02`) username/password negotiation for SOCKS5 and `407 Proxy-Authenticate` for HTTP when `authentication` is configured (never accepting `0x00` No-Auth).
  - Enforces `lan-allowed-ips` CIDR ACLs when `allow-lan: true`, handshake read timeouts, and a 2,048-permit concurrency `Semaphore`.
  - Locks SOCKS5 `UDP ASSOCIATE` sockets to the authenticated TCP control client's IP address, dropping spoofed third-party UDP datagrams.

### 2.6 Platform, CLI `argv` & Supply-Chain Hardening
- **Windows DLL Search-Order Protection**: `wintun.dll` is loaded exclusively with `LoadLibraryExW(..., LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32)`.
- **Process `argv` & Keystore Secret Hygiene**: macOS Keychain operations (`security -i`), Linux `secret-tool` calls, [`release.yml`](../.github/workflows/release.yml) (`keytool -storepass:env`), and [`scripts/generate_android_keystore.sh`](../scripts/generate_android_keystore.sh) (`-storepass:env` / `-keypass:env` + `0600` secrets output file) avoid placing passwords on CLI `argv` or dumping plaintext secrets to terminal stdout by default.
- **SHA-256 Supply-Chain Pinning**:
  - [`scripts/fetch_wintun.py`](../scripts/fetch_wintun.py) verifies `wintun-0.14.1.zip` against `07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51` before extracting a single byte (with an offline tamper-rejection `--self-test` run in CI).
  - [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) and [`scripts/run_comparative_benchmarks.py`](../scripts/run_comparative_benchmarks.py) verify pinned SHA-256 digests for `shadowsocks-rust`, `Xray-core`, `anytls-go`, `mihomo`, and `sing-box`.
- **Protocol Replay & Queue Backpressure Defense**: Shadowsocks-2022 (`2022-blake3-*`) enforces ±30s timestamp validation and a 60s salt replay filter on both TCP streams and UDP sessions; [`VirtualTunHandle`](../crates/proxy-core/src/inbound/tun.rs) enforces bounded packet queues (`TUN_PACKET_QUEUE_CAPACITY = 4096`) and `64 KiB × 2` per-flow `smoltcp` TCP buffers.

---

## 3. Automated Security Regression Coverage

| Security Control Under Test | Verification Suite / Script | Status |
| :--- | :--- | :--- |
| Anti-DNS-rebinding, Anti-CSRF `Origin`/`Sec-Fetch-Site`, Bearer & WS auth, `/configs/raw` redaction + hot-reload rehydration | [`security_and_hardening_e2e.rs`](../crates/proxy-core/tests/security_and_hardening_e2e.rs) | **PASS** |
| Untrusted subscription sanitization (`secret`/`allow-lan`/`bind-address`/`authentication`/`file` provider stripping) & `rule-providers.path` `state_dir` confinement | [`security_and_hardening_e2e.rs`](../crates/proxy-core/tests/security_and_hardening_e2e.rs), [`subscription_wild_matrix_and_fuzz.rs`](../crates/proxy-core/tests/subscription_wild_matrix_and_fuzz.rs) | **PASS** |
| SOCKS5 RFC 1929 auth, HTTP 407 auth, UDP ASSOCIATE peer IP lock, LAN CIDR ACLs | [`security_and_hardening_e2e.rs`](../crates/proxy-core/tests/security_and_hardening_e2e.rs) | **PASS** |
| Cyclic proxy-group rejection & zero silent `DIRECT` fallback | [`security_and_hardening_e2e.rs`](../crates/proxy-core/tests/security_and_hardening_e2e.rs) | **PASS** |
| `SecretVault` encryption/sandboxing, ciphertext tamper rejection & `0600`/`0700` POSIX permissions | [`keystore.rs`](../crates/proxy-core/src/platform/keystore.rs) | **PASS** |
| TLS 1.3 subscription refresh, failed-update atomic rollback & zero-leak `/diagnostics/export` | [`milestone5_product_e2e.rs`](../crates/proxy-core/tests/milestone5_product_e2e.rs) | **PASS** |
| Android direct-JNI isolation (no HTTP listener) & FFI lifecycle safety | [`ffi_bridge_e2e.rs`](../crates/proxy-ffi/tests/ffi_bridge_e2e.rs) | **PASS** |
| Wintun archive SHA-256 tamper rejection (`--self-test`) | [`fetch_wintun.py`](../scripts/fetch_wintun.py) | **PASS** |
| Android Per-App Lockdown conflict protection (preserving `protect(fd)`) | [`VpnConfigAndLifecycleTest.kt`](../android/app/src/test/java/io/github/rustclashlabs/rustclash/VpnConfigAndLifecycleTest.kt) | **PASS** |


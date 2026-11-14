# Comprehensive Test & Verification Report (`v0.4.0+`)

This document records the exact automated test inventory, external protocol interoperability verification, multi-round comparative + TUN-path benchmarks, cross-platform GitHub Actions **`ci.yml` (PR/Push CI)** vs **`release.yml` (Release Packaging)** matrices, and explicit **`PASS / BLOCKED / NOT TESTED`** status across **Linux (`x86_64`), macOS, Windows, and Android (`versionCode = 16`)**.

---

## 1. Summary Status Matrix

| Category | Suite / Verification Target | Pipeline & Platform(s) | Status | Evidence / Notes |
|---|---|---|---|---|
| **Web Console Unit & Typecheck** | `statusModel.test.mjs` (`node --test`: honest 3-layer status, zero fabricated memory/IP/country metrics, symmetric master takeover toggle) + `tsc --noEmit` + Vite 6 production bundle | `ci.yml` & `release.yml` (`ubuntu-latest`) | **PASS** | `npm --prefix ui test && npm --prefix ui run build` |
| **Rust Unit Tests** | `proxy-core --lib` (crypto, AEAD, VLESS PQ, Trojan, WS 0-RTT, SOCKS5, HTTP CONNECT, Happy Eyeballs RFC 8305, singleflight DoH/DoT DNS, `O(log N)` IP-CIDR interval router, MMDB, `SocketProtector`, `RecoveryJournal`, `SysProxy`, `SecretVault`, `Autostart`, `ProfileManager` subscription sanitizer & `state_dir` path confinement, Linux/macOS/Windows TUN helpers, **6 Windows DNS backup/rollback fault-injection tests**) | `ci.yml` & `release.yml` (Linux `x86_64`, macOS, Windows) | **PASS** | `cargo test -p proxy-core --lib` |
| **FFI, RAII & Tauri Shell** | `proxy-ffi` ([`ffi_bridge_e2e.rs`](../crates/proxy-ffi/tests/ffi_bridge_e2e.rs): Android `OwnedFd` `SOCK_SEQPACKET` `POLLHUP`/`fstat` zero-FD-leak across invalid YAML/port-conflict/duplicate-start/`onRevoke`, 10x8-thread macOS `NE` `stopTunnel` UAF stress + `0 Hz` `Condvar` wakeup) + `tauri-app` (headless `default = []` + `--features desktop` clippy & unit tests) | `ci.yml` & `release.yml` (Linux `x86_64`, macOS, Windows, Android NDK) | **PASS** | `cargo test -p proxy-ffi -p tauri-app` |
| **Network Handoff Recovery E2E** | [`network_handoff_recovery_e2e.rs`](../crates/proxy-core/tests/network_handoff_recovery_e2e.rs) (AnyTLS idle-pool eviction + live TLS abort + epoch anti-poisoning; `ProxyEngine::notify_network_change` resetting TUN `UdpNatManager` + active TCP + DNS cache) | `ci.yml` & `release.yml` (Linux `x86_64`, macOS, Windows) | **PASS** | `cargo test -p proxy-core --test network_handoff_recovery_e2e` |
| **Protocol, DNS, Split-Tunnel & Control API E2E** | [`protocols_e2e.rs`](../crates/proxy-core/tests/protocols_e2e.rs), [`tun_stack_e2e.rs`](../crates/proxy-core/tests/tun_stack_e2e.rs), [`routing_dns_e2e.rs`](../crates/proxy-core/tests/routing_dns_e2e.rs), [`dns_router_ultimate_e2e.rs`](../crates/proxy-core/tests/dns_router_ultimate_e2e.rs), [`custom_dns_policy_e2e.rs`](../crates/proxy-core/tests/custom_dns_policy_e2e.rs), [`split_tunnel_routing_e2e.rs`](../crates/proxy-core/tests/split_tunnel_routing_e2e.rs), [`latency_preconnect_e2e.rs`](../crates/proxy-core/tests/latency_preconnect_e2e.rs), [`node_import_persistence_e2e.rs`](../crates/proxy-core/tests/node_import_persistence_e2e.rs), [`subscription_wild_matrix_and_fuzz.rs`](../crates/proxy-core/tests/subscription_wild_matrix_and_fuzz.rs), [`network_quality_regressions.rs`](../crates/proxy-core/tests/network_quality_regressions.rs), [`api_control_e2e.rs`](../crates/proxy-core/tests/api_control_e2e.rs), [`milestone5_product_e2e.rs`](../crates/proxy-core/tests/milestone5_product_e2e.rs), [`security_and_hardening_e2e.rs`](../crates/proxy-core/tests/security_and_hardening_e2e.rs) | `ci.yml` & `release.yml` (Linux `x86_64`, macOS, Windows) | **PASS** | `cargo test -p proxy-core` |
| **External Interop (`Xray-core` / `shadowsocks-rust` / `anytls-go`)** | [`interop_external_e2e.rs`](../crates/proxy-core/tests/interop_external_e2e.rs): bidirectional VLESS `mlkem768x25519plus` (`XTLS/Xray-core v26.10.31`), SIP022 `2022-blake3-aes-256-gcm` TCP+UDP (`shadowsocks-rust v1.25.0`), and AnyTLS v2 + UoT v2 (`anytls-go v0.0.13`) | `ci.yml` (`ubuntu-latest` `x86_64`) + Local | **PASS** | Reference binaries SHA-256 pinned in `ci.yml` |
| **Linux Real Kernel `/dev/net/tun` E2E** | [`linux_netns_tun_e2e.rs`](../crates/proxy-core/tests/linux_netns_tun_e2e.rs) via [`ci_linux_netns_tun_test.sh`](../scripts/ci_linux_netns_tun_test.sh): real `/dev/net/tun` (`ClashNs0`), browser HTTP GET/POST via Fake-IP, armed IPv4+IPv6 canary `0` DNS leaks, 4 MiB TCP + half-close, 8-pkt UDP NAT, native IPv6 TCP/UDP, handoff recovery, **3x repeated stop/start cycles**, clean teardown | `ci.yml` (`ubuntu-latest` `x86_64` isolated `ip netns`) | **PASS** | Real Linux `/dev/net/tun` verified end-to-end *(Linux `aarch64` CI is not run; source is portable Rust)* |
| **macOS `utun` & NetworkExtension Check (`ci.yml`)** | Darwin 4-byte `AF_INET`/`AF_INET6` codec + `NE` FFI UAF/Condvar suite + `xcrun --sdk macosx swiftc -typecheck PacketTunnelProvider.swift` + `tauri-app` clippy/tests | `ci.yml` (`macos-latest` ARM64) | **PASS** | Typechecked against Apple `NetworkExtension.framework` SDK |
| **Windows Signed Wintun & DNS Rollback Check (`ci.yml`)** | Official WireGuard-signed `wintun.dll` v0.14.1 SHA-256 `--self-test` + 6 deterministic DNS backup/restore/partial-failure rollback unit tests + `tauri-app` clippy/tests | `ci.yml` (`windows-latest` x64) | **PASS** | Never falsely reports TUN active when `SetInterfaceDnsSettings` fails |
| **Android Native VPN Debug Check (`ci.yml`)** | NDK `arm64-v8a` + `x86_64` `libproxy_ffi.so`, `:app:testDebugUnitTest` (JUnit + Robolectric), `:app:lintDebug`, `:app:assembleDebug` (`ANDROID_SKIP_BUNDLE=1`) | `ci.yml` (`ubuntu-latest` + Android SDK 35 / NDK 27.2.12479018) | **PASS** | Fast PR/push verification of JNI `.so`, unit tests, lint, and debug APK |
| **Release Installers & Signed Packages (`release.yml`)** | Preflight `refs/heads/main` + tag/version alignment + `npm test` + `cargo fmt`/`clippy`/`test` gate -> Linux `.tar.gz`/`.deb`/`.rpm`, Windows `.zip`/NSIS `-setup.exe`/`.msi`, macOS `arm64`+`x86_64` `.tar.gz`/`.dmg`, Android `testDebugUnitTest` + `lintDebug` + signed release split/universal `.apk` (`v1+v2+v3` `apksigner`) + `.aab` (`versionCode = 16`, `versionName = "0.4.0"`) + `SHA256SUMS.txt` | `release.yml` (Linux `x86_64`, Windows `x64`, macOS `arm64`+`x86_64`, Android) | **PASS** | 14 release artifacts + `SHA256SUMS.txt` published atomically |
| **Multi-Round + TUN Benchmarks** | [`run_comparative_benchmarks.py`](../scripts/run_comparative_benchmarks.py): 6-round balanced Latin-square (`rust-clash v0.2.0` baseline vs `mihomo v1.19.33` vs `sing-box v1.14.4`) + 6-round L3 `smoltcp` TUN (`MTU 1500`) + exact two-sample Welch's $t$-tests | Linux `x86_64` | **PASS** | Exact Welch $t$/$\text{df}$/$p$-values & raw data in [`PERFORMANCE_BENCHMARK.md`](./PERFORMANCE_BENCHMARK.md) |
| **macOS `.systemextension` Signing** | Gatekeeper/NESessionManager loading of signed NetworkExtension bundle | macOS | **BLOCKED** | Requires paid Apple Developer ID + restricted `packet-tunnel-provider` entitlement |
| **Windows Authenticode App Signing** | SmartScreen reputation signing for `rust-clash.exe` / `-setup.exe` / `.msi` | Windows | **BLOCKED** | Requires external Authenticode certificate (`wintun.dll` itself is officially WireGuard-signed) |
| **Google Play Store Listing Upload** | Google Play Console developer enrollment & store listing publication | Android | **BLOCKED** | GitHub Release APKs/AAB are signed with persistent project release keystore (`versionCode = 16`); Play Store distribution requires an external Play Console account |
| **Windows Live OS Wintun Networking** | Real browser access, DNS leak check, TCP/UDP/IPv6, disconnect/recovery, and repeated start/stop on live Windows 10/11 | Windows 10/11 | **`NOT TESTED`** | Headless CI runner cannot elevate interactive UAC or reroute default gateway without severing runner WinRM session |
| **macOS Live OS `utun` / `NE` Networking** | Real browser access, DNS leak check, TCP/UDP/IPv6, sleep/wake recovery, and repeated start/stop on live macOS | macOS 13+ | **`NOT TESTED`** | Headless CI runner cannot alter host primary `en0`/DNS without severing runner management connection; `.systemextension` requires Apple entitlement |
| **Android Live Device `VpnService` Networking** | Real browser access, DNS leak check, TCP/UDP/IPv6, Wi-Fi ↔ 5G cellular handoff, `onRevoke`, and repeated start/stop on physical Android | Android 8.0–15 | **`NOT TESTED`** | No physical Android device or KVM cellular/Wi-Fi emulator available in headless container environment |

---

## 2. Reproducing All Automated Suites Locally

```bash
# 1. Test & Build Embedded Web Console
npm --prefix ui ci && npm --prefix ui test && npm --prefix ui run build

# 2. Strict Format & Clippy Lint Gate (0 warnings allowed)
cargo fmt --all -- --check
cargo clippy --workspace --exclude tauri-app --all-targets -- -D warnings

# 3. Full Rust Unit, FFI, Security & Session-Recovery E2E Suite
RUST_CLASH_INTEROP_BIN_DIR=$HOME/.cache/rust-clash-tools/interop-bins \
RUST_CLASH_REQUIRE_EXTERNAL_INTEROP=1 \
cargo test --workspace --exclude tauri-app

# 4. Isolated Linux Kernel /dev/net/tun 8-Dimension E2E (requires Linux root / sudo ip netns)
./scripts/ci_linux_netns_tun_test.sh

# 5. Recompute Exact Welch's t-Test p-Values or Run Full 6-Round Benchmark Suite
python3 scripts/run_comparative_benchmarks.py --recompute-stats docs/benchmarks_latest.json
python3 scripts/run_comparative_benchmarks.py --rounds 6 --idle-seconds 2.0
```

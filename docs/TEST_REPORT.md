# Comprehensive Test & Verification Report (`v0.3.0`)

This document records the exact automated test inventory, external protocol interoperability verification, multi-round comparative + TUN-path benchmarks, cross-platform GitHub Actions CI matrix, and explicit **`PASS / BLOCKED / NOT TESTED`** status across **Linux, macOS, Windows, and Android**.

---

## 1. Summary Status Matrix

| Category | Suite / Verification Target | Platform(s) | Status | Evidence / Notes |
|---|---|---|---|---|
| **Rust Unit Tests** | `proxy-core --lib` (crypto, AEAD, VLESS PQ, Trojan, WS 0-RTT, SOCKS5, HTTP CONNECT, Happy Eyeballs RFC 8305, singleflight DoH/DoT DNS, `O(log N)` IP-CIDR interval router, MMDB, `SocketProtector`, `RecoveryJournal`, `SysProxy`, `SecretVault`, `Autostart`, `ProfileManager` mixed-subscription sanitizer, Linux/macOS/Windows TUN helpers, **6 Windows DNS backup/rollback fault-injection tests**) | Linux, macOS, Windows | **PASS** | `cargo test -p proxy-core --lib` |
| **FFI, RAII & Tauri Shell** | `proxy-ffi` ([`ffi_bridge_e2e.rs`](../crates/proxy-ffi/tests/ffi_bridge_e2e.rs): Android `OwnedFd` `SOCK_SEQPACKET` `POLLHUP`/`fstat` zero-FD-leak across invalid YAML/port-conflict/duplicate-start/`onRevoke`, 10x8-thread macOS `NE` `stopTunnel` UAF stress + `0 Hz` `Condvar` wakeup) + `tauri-app` (`--features desktop` clippy + helper CLI unit tests) | Linux, macOS, Windows, Android NDK | **PASS** | `cargo test -p proxy-ffi -p tauri-app` |
| **Network Handoff Recovery E2E** | [`network_handoff_recovery_e2e.rs`](../crates/proxy-core/tests/network_handoff_recovery_e2e.rs) (`2` E2E tests: AnyTLS idle-pool eviction + live TLS abort + epoch anti-poisoning; `ProxyEngine::notify_network_change` resetting TUN `UdpNatManager` + active TCP + DNS cache) | Linux, macOS, Windows | **PASS** | `cargo test -p proxy-core --test network_handoff_recovery_e2e` |
| **Protocol & Control API E2E** | `protocols_e2e` (SS-2022, VLESS+PQ, VLESS+WS 0-RTT, Trojan TCP/UDP, Trojan+WS, AnyTLS v2, SOCKS5 TCP/UDP, HTTP CONNECT, mixed-sub sanitization), `tun_stack_e2e`, `routing_dns_e2e`, `dns_router_ultimate_e2e`, `api_control_e2e` (`/connections` WS, `?token=` auth, `/routing/custom-rules`, `/geodata`), `milestone5_product_e2e`, `security_and_hardening_e2e` | Linux, macOS, Windows | **PASS** | `cargo test -p proxy-core` |
| **External Interop (Xray-core)** | `interop_vless_mlkem768x25519plus_bidirectional_with_xray_core` (`XTLS/Xray-core v26.10.31`) | Linux `x86_64` CI + Local | **PASS** | Bidirectional client<->server 0-RTT & 1-RTT PQ hybrid verified |
| **External Interop (shadowsocks-rust)** | `interop_shadowsocks_2022_bidirectional_with_shadowsocks_rust` (`shadowsocks-rust v1.25.0`) | Linux `x86_64` CI + Local | **PASS** | Bidirectional SIP022 `2022-blake3-aes-256-gcm` TCP + UDP verified |
| **External Interop (anytls-go)** | `interop_anytls_bidirectional_with_anytls_go` (`anytls-go v0.0.13`) | Linux `x86_64` CI + Local | **PASS** | Bidirectional AnyTLS v2 TCP + `sp.v2.udp-over-tcp.arpa` UoT v2 UDP verified |
| **Linux Real Kernel `/dev/net/tun` E2E** | [`linux_netns_tun_e2e.rs`](../crates/proxy-core/tests/linux_netns_tun_e2e.rs) via [`ci_linux_netns_tun_test.sh`](../scripts/ci_linux_netns_tun_test.sh): real `/dev/net/tun` (`ClashNs0`), browser HTTP GET/POST via Fake-IP, armed IPv4+IPv6 canary `0` DNS leaks, 4 MiB TCP + half-close, 8-pkt UDP NAT, native IPv6 TCP/UDP, handoff recovery, **3x repeated stop/start cycles**, clean teardown | Linux (`ubuntu-latest` CI isolated `ip netns`) | **PASS** | Real OS `/dev/net/tun` verified end-to-end |
| **macOS `utun` & NetworkExtension** | Darwin 4-byte `AF_INET`/`AF_INET6` codec + `NE` FFI UAF/Condvar suite + `xcrun --sdk macosx swiftc -typecheck PacketTunnelProvider.swift` | macOS (`macos-latest` ARM64 CI) | **PASS** | Typechecked against Apple `NetworkExtension.framework` SDK |
| **Windows Signed Wintun & DNS Rollback** | Official WireGuard-signed `wintun.dll` v0.14.1 SHA-256 verification + 6 deterministic DNS backup/restore/partial-failure rollback unit tests | Windows (`windows-latest` x64 CI) | **PASS** | Never falsely reports TUN active when `SetInterfaceDnsSettings` fails |
| **Android Native VPN Build, Lint & JUnit** | NDK `arm64-v8a` + `x86_64` `libproxy_ffi.so`, `:app:testDebugUnitTest`, `:app:lintDebug`, `:app:assembleRelease`, `:app:bundleRelease` | Ubuntu CI + Android SDK 35 / NDK 27.2.12479018 | **PASS** | Produces signed `arm64-v8a`, `x86_64`, `universal` APKs & `.aab` |
| **Multi-Round + TUN Benchmarks** | [`run_comparative_benchmarks.py`](../scripts/run_comparative_benchmarks.py): 6-round balanced Latin-square interleaved (`rust-clash v0.2.0` vs `mihomo v1.19.33` vs `sing-box v1.14.4`) + 6-round L3 `smoltcp` TUN (`MTU 1500`) | Linux `x86_64` | **PASS** | Full mean/stddev/median/IQR/95% CI in [`PERFORMANCE_BENCHMARK.md`](./PERFORMANCE_BENCHMARK.md) |
| **macOS `.systemextension` Signing** | Gatekeeper/NESessionManager loading of signed NetworkExtension bundle | macOS | **BLOCKED** | Requires paid Apple Developer ID + restricted `packet-tunnel-provider` entitlement |
| **Windows Authenticode App Signing** | SmartScreen reputation signing for `rust-clash.exe` / `.msi` | Windows | **BLOCKED** | Requires external Authenticode certificate (`wintun.dll` itself is officially WireGuard-signed) |
| **Android Play Store Release Signing** | Production upload keystore signing for Google Play Console | Android | **BLOCKED** | Requires external `.jks` upload keystore (universal sideloadable debug-signed `.apk` provided) |
| **Windows Live OS Wintun Networking** | Real browser access, DNS leak check, TCP/UDP/IPv6, disconnect/recovery, and repeated start/stop on live Windows 10/11 | Windows 10/11 | **`NOT TESTED`** | Headless CI runner cannot elevate interactive UAC or reroute default gateway without severing runner WinRM session |
| **macOS Live OS `utun` / `NE` Networking** | Real browser access, DNS leak check, TCP/UDP/IPv6, sleep/wake recovery, and repeated start/stop on live macOS | macOS 13+ | **`NOT TESTED`** | Headless CI runner cannot alter host primary `en0`/DNS without severing runner management connection; `.systemextension` requires Apple entitlement |
| **Android Live Device `VpnService` Networking** | Real browser access, DNS leak check, TCP/UDP/IPv6, Wi-Fi ↔ 5G cellular handoff, `onRevoke`, and repeated start/stop on physical Android | Android 8.0–15 | **`NOT TESTED`** | No physical Android device or KVM cellular/Wi-Fi emulator available in headless container environment |

---

## 2. Reproducing All Automated Suites Locally

```bash
# 1. Build Embedded Web Console
npm --prefix ui ci && npm --prefix ui run build

# 2. Strict Format & Clippy Lint Gate (0 warnings allowed)
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings

# 3. Full Rust Unit, FFI, Security & Session-Recovery E2E Suite (61 workspace tests)
RUST_CLASH_INTEROP_BIN_DIR=$HOME/.cache/rust-clash-tools/interop-bins \
RUST_CLASH_REQUIRE_EXTERNAL_INTEROP=1 \
cargo test --workspace

# 4. Isolated Linux Kernel /dev/net/tun 8-Dimension E2E (requires Linux root / sudo ip netns)
./scripts/ci_linux_netns_tun_test.sh

# 5. 6-Round Balanced Latin-Square Comparative + L3 TUN Benchmark Suite
python3 scripts/run_comparative_benchmarks.py --rounds 6 --idle-seconds 2.0
```

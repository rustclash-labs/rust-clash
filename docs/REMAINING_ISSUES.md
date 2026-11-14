# Remaining Issues, Honest `NOT TESTED` Boundaries & External Blockers (`v0.4.0+`)

In accordance with our strict zero-fabrication policy, this document records every item blocked by external credentials or **`NOT TESTED`** on live physical/interactive OS environments, along with exact technical boundaries and user verification steps.

---

## 1. Real-OS Live TUN/VPN Acceptance Boundaries (`NOT TESTED`)

Simulated packet channels and unit/fault-injection mocks do **not** replace real operating-system network stack acceptance. While **Linux (`x86_64`)** real kernel `/dev/net/tun` + policy routing + `SO_MARK` anti-loop is **TESTED & PASSED** end-to-end inside isolated `ip netns` namespaces in PR/Push CI ([`ci_linux_netns_tun_test.sh`](../scripts/ci_linux_netns_tun_test.sh) / [`linux_netns_tun_e2e.rs`](../crates/proxy-core/tests/linux_netns_tun_e2e.rs)), the following live OS environments remain **`NOT TESTED`** end-to-end with real internet traffic:

1. **Windows 10/11 Live Wintun Networking — `NOT TESTED`**
   - **Why**: GitHub Actions `windows-latest` runners communicate over a single live WinRM management NIC without Linux-style `ip netns` isolation; mutating live default split routes (`0.0.0.0/1`, `128.0.0.0/1`) or interface DNS on the runner risks severing the CI orchestrator connection, and interactive UAC elevation prompts require a desktop session.
   - **What Was Verified**: In `ci.yml`, official signed `wintun.dll` v0.14.1 SHA-256 `--self-test` & dynamic symbol loading, `DNS_SETTING_IPV6` / `DNS_SETTING_NAMESERVER` Win32 constant alignment, transactional IPv4+IPv6 DNS backup/restore, and 6 deterministic DNS fault-injection rollback unit tests ([`windows.rs`](../crates/proxy-core/src/platform/tun/windows.rs)); in `release.yml`, standalone `.zip` and Tauri NSIS `-setup.exe` / `.msi` installer packaging.
2. **macOS 13+ Live `utun` / `NEPacketTunnelProvider` Networking — `NOT TESTED`**
   - **Why**: Headless `macos-latest` CI runners lack an isolated network namespace mechanism and lack Apple's restricted `packet-tunnel-provider` code-signing entitlement.
   - **What Was Verified**: In `ci.yml`, `xcrun --sdk macosx swiftc -typecheck` on [`PacketTunnelProvider.swift`](../platforms/macos-ne/PacketTunnelProvider.swift), Darwin 4-byte `AF_INET`/`AF_INET6` framing tests, and 10 rounds of 8-thread concurrent `stopTunnel` vs packet/status callback UAF torture + `0 Hz` `Condvar` wakeup E2E ([`ffi_bridge_e2e.rs`](../crates/proxy-ffi/tests/ffi_bridge_e2e.rs)); in `release.yml`, `arm64` + `x86_64` CLI `.tar.gz` and Tauri `.dmg` packaging.
3. **Android 8.0–15 Physical Device / Emulator Live `VpnService` Networking — `NOT TESTED`**
   - **Why**: The sandboxed build VM has no physical Android device attached and no `/dev/kvm` nested virtualization with live Wi-Fi + cellular radio interfaces.
   - **What Was Verified**: In `ci.yml`, NDK `arm64-v8a` + `x86_64` `libproxy_ffi.so` compilation, `SOCK_SEQPACKET` `fstat`/`POLLHUP` kernel proof of zero leaked/double-closed FDs across all `nativeStartVpn` error/duplicate/`onRevoke` paths, `testDebugUnitTest` (JUnit + Robolectric), `lintDebug` static checks, `ProxyEngine::notify_network_change()` full UDP NAT + TCP + AnyTLS session recovery E2E, and `assembleDebug`; in `release.yml`, unit tests + lint + signed per-ABI split + universal `.apk` (`v1+v2+v3` `apksigner`) and `.aab` packaging (`versionCode = 16`, `versionName = "0.4.0"`).
4. **Linux `aarch64` Native Runner CI & Physical Linux Desktop GUI — `NOT TESTED`**
   - **Why**: Automated CI and release workflows execute on `x86_64` `ubuntu-latest` runners (without native `aarch64-unknown-linux-gnu` runners or interactive Wayland/X11 desktop sessions), although the Rust codebase itself uses portable target abstractions.

Step-by-step manual acceptance checklists for Windows, macOS, Linux desktop, and Android physical devices are provided in [`USER_ACCEPTANCE_TESTS.md`](./USER_ACCEPTANCE_TESTS.md).

---

## 2. External Signing & Credential Blockers (`BLOCKED`)

### 2.1 macOS System Extension (`NEPacketTunnelProvider`) Distribution Signing
- **Status**: **BLOCKED (External Paid Apple Developer ID + Restricted Entitlement Required)**
- **Details**: macOS `sysextd` / `nesessionmanager` refuses to load any `.systemextension` unless signed with a paid Apple Developer ID certificate and an Apple-approved provisioning profile containing `com.apple.developer.networking.networkextension` (`packet-tunnel-provider`). Without Apple credentials, users on macOS can run the built-in Darwin `PF_SYSTEM` `utun` backend ([`macos.rs`](../crates/proxy-core/src/platform/tun/macos.rs)) via privileged helper (`sudo ./rust-clash elevated-tun-helper --config ...`).

### 2.2 Windows Authenticode Application Binary Signing
- **Status**: **BLOCKED (External Authenticode Certificate Required)**
- **Details**: Release archives bundle the **official WireGuard LLC EV-signed `wintun.dll` v0.14.1** (satisfying Windows kernel driver signing under Secure Boot), while `rust-clash.exe` and the `.msi` / `-setup.exe` installers themselves are unsigned unless an Authenticode certificate is configured, triggering a standard SmartScreen confirmation on first run.

### 2.3 Google Play Console Distribution Account
- **Status**: **BLOCKED (External Google Play Developer Account Required for Store Listing)**
- **Details**: GitHub Releases sign `arm64-v8a`, `x86_64`, and `universal` APKs (`v1+v2+v3` verified via `apksigner`) plus `.aab` bundles (`io.github.rustclashlabs.rustclash`, `versionCode = 16`, `versionName = "0.4.0"`) with the persistent project release keystore (`ANDROID_KEYSTORE_*`) for seamless in-place APK upgrades (`adb install -r`), whereas publishing on Google Play requires an external Google Play Console developer account and Play App Signing enrollment.

---

## 3. Architectural & Performance Trade-Offs (Non-Blocking)

1. **Userspace `smoltcp` L3 TUN vs Kernel Bypass / GSO**:
   - `rust-clash` processes TUN packets through its pure-Rust memory-safe `smoltcp` L3 stack ([`VirtualTunHandle`](../crates/proxy-core/src/inbound/tun.rs): `MTU 1500`, `64 KiB × 2` per-flow RX/TX TCP socket buffers, `TUN_PACKET_QUEUE_CAPACITY = 4096`) rather than C/C++ `lwIP` or unsafe raw kernel splices. As documented in [`PERFORMANCE_BENCHMARK.md`](./PERFORMANCE_BENCHMARK.md) and [`benchmarks_latest.json`](./benchmarks_latest.json), L3 `smoltcp` TUN throughput (`1,930.2 ± 337.4 Mbps` 1-stream, `2,621.6 ± 142.7 Mbps` 4-stream) is lower than `64 KiB` SOCKS5 loopback streams due to `1,500 B` IP packet segmentation, IPv4/TCP checksum verification, and TCP window ACK pacing, while saturating gigabit broadband/2.5GbE/5G links at `9.46 ± 0.13 MiB` idle and `24.34 ± 0.45 MiB` peak benchmark RSS (`13.80 ± 0.28 MiB` peak RSS on Mixed SOCKS5).
2. **Protocol Scope (`v0.4.0+`)**:
   - `v0.4.0+` supports **Shadowsocks AEAD**, **Shadowsocks-2022 (`SIP022` TCP+UDP)**, **VLESS v0 + Post-Quantum `mlkem768x25519plus` (`0-RTT`/`1-RTT`, TCP & WebSocket)**, **Trojan (`TCP+TLS` & `WS+TLS` + UDP)**, **AnyTLS v2 (TLS 1.3 mux + UoT v2 UDP)**, **SOCKS5 (`RFC 1928/1929` TCP + UDP + TLS)**, and **HTTP/HTTPS `CONNECT`**. Mixed third-party Clash subscriptions containing unimplemented protocols (such as `vmess`, `hysteria2`, `tuic`, or `wireguard`) are automatically sanitized on import with unsupported entries reported via structured `skipped-unsupported` summaries rather than failing the subscription.

# Remaining Issues, Honest `NOT TESTED` Boundaries & External Blockers (`v0.3.0`)

In accordance with our strict zero-fabrication policy, this document records every item blocked by external credentials or **`NOT TESTED`** on live physical/interactive OS environments, along with exact technical boundaries and user verification steps.

---

## 1. Real-OS Live TUN/VPN Acceptance Boundaries (`NOT TESTED`)

Simulated packet channels and unit/fault-injection mocks do **not** replace real operating-system network stack acceptance. While **Linux** real kernel `/dev/net/tun` + policy routing + `SO_MARK` anti-loop is **TESTED & PASSED** end-to-end inside isolated `ip netns` namespaces in CI ([`ci_linux_netns_tun_test.sh`](../scripts/ci_linux_netns_tun_test.sh) / [`linux_netns_tun_e2e.rs`](../crates/proxy-core/tests/linux_netns_tun_e2e.rs)), the following three live OS environments were **`NOT TESTED`** end-to-end with real internet traffic:

1. **Windows 10/11 Live Wintun Networking — `NOT TESTED`**
   - **Why**: GitHub Actions `windows-latest` runners communicate over a single live WinRM management NIC without Linux-style `ip netns` isolation; mutating live default split routes (`0.0.0.0/1`, `128.0.0.0/1`) or interface DNS on the runner risks severing the CI orchestrator connection, and interactive UAC elevation prompts require a desktop session.
   - **What Was Verified**: Official signed `wintun.dll` v0.14.1 SHA-256 verification & dynamic symbol loading, `DNS_SETTING_IPV6` / `DNS_SETTING_NAMESERVER` Win32 constant alignment, transactional IPv4+IPv6 DNS backup/restore, and 6 deterministic DNS fault-injection rollback unit tests ([`windows.rs`](../crates/proxy-core/src/platform/tun/windows.rs)).
2. **macOS 13+ Live `utun` / `NEPacketTunnelProvider` Networking — `NOT TESTED`**
   - **Why**: Headless `macos-latest` CI runners lack an isolated network namespace mechanism and lack Apple's restricted `packet-tunnel-provider` code-signing entitlement.
   - **What Was Verified**: `xcrun --sdk macosx swiftc -typecheck` on [`PacketTunnelProvider.swift`](../platforms/macos-ne/PacketTunnelProvider.swift), Darwin 4-byte `AF_INET`/`AF_INET6` framing tests, and 10 rounds of 8-thread concurrent `stopTunnel` vs packet/status callback UAF torture + `0 Hz` `Condvar` wakeup E2E ([`ffi_bridge_e2e.rs`](../crates/proxy-ffi/tests/ffi_bridge_e2e.rs)).
3. **Android 8.0–15 Physical Device / Emulator Live `VpnService` Networking — `NOT TESTED`**
   - **Why**: The sandboxed build VM has no physical Android device attached and no `/dev/kvm` nested virtualization with live Wi-Fi + cellular radio interfaces.
   - **What Was Verified**: NDK `arm64-v8a` + `x86_64` `libproxy_ffi.so` compilation, `SOCK_SEQPACKET` `fstat`/`POLLHUP` kernel proof of zero leaked/double-closed FDs across all `nativeStartVpn` error/duplicate/`onRevoke` paths, `UnderlyingNetworkTracker` + QR inversion + protocol deep-link JUnit tests, `lintDebug` static checks, `ProxyEngine::notify_network_change()` full UDP NAT + TCP + AnyTLS session recovery E2E, and signed per-ABI split + universal `.apk` / `.aab` packaging.

Step-by-step manual acceptance checklists for Windows, macOS, Linux desktop, and Android physical devices are provided in [`USER_ACCEPTANCE_TESTS.md`](./USER_ACCEPTANCE_TESTS.md).

---

## 2. External Signing & Credential Blockers (`BLOCKED`)

### 2.1 macOS System Extension (`NEPacketTunnelProvider`) Distribution Signing
- **Status**: **BLOCKED (External Paid Apple Developer ID + Restricted Entitlement Required)**
- **Details**: macOS `sysextd` / `nesessionmanager` refuses to load any `.systemextension` unless signed with a paid Apple Developer ID certificate and an Apple-approved provisioning profile containing `com.apple.developer.networking.networkextension` (`packet-tunnel-provider`). Without Apple credentials, users on macOS can run the built-in Darwin `PF_SYSTEM` `utun` backend ([`macos.rs`](../crates/proxy-core/src/platform/tun/macos.rs)) via privileged helper (`sudo ./rust-clash elevated-tun-helper --config ...`).

### 2.2 Windows Authenticode Application Binary Signing
- **Status**: **BLOCKED (External Authenticode Certificate Required)**
- **Details**: Release archives bundle the **official WireGuard LLC EV-signed `wintun.dll` v0.14.1** (satisfying Windows kernel driver signing under Secure Boot), while `rust-clash.exe` and the `.msi` / `-setup.exe` installers themselves are unsigned unless an Authenticode certificate is configured, triggering a standard SmartScreen confirmation on first run.

### 2.3 Android Play Store Production Keystore
- **Status**: **BLOCKED (External Upload Keystore Required for Google Play)**
- **Details**: Release pipelines verify `ANDROID_KEYSTORE_*` secrets via `apksigner` v2/v3 across `arm64-v8a`, `x86_64`, and `universal` APKs (`versionCode = 6`, `versionName = "0.3.0"`), while Google Play Console distribution requires a developer-owned upload keystore.

---

## 3. Architectural & Performance Trade-Offs (Non-Blocking)

1. **Userspace `smoltcp` L3 TUN vs Kernel Bypass / GSO**:
   - `rust-clash` processes TUN packets through its pure-Rust memory-safe `smoltcp` L3 stack (`MTU 1500`, `64 KiB` per-flow TCP buffers) rather than C/C++ `lwIP` or unsafe raw kernel splices. As documented in [`PERFORMANCE_BENCHMARK.md`](./PERFORMANCE_BENCHMARK.md), L3 `smoltcp` TUN throughput is naturally lower than `64 KiB` SOCKS5 loopback streams due to `1500 B` IP packet segmentation, IPv4/TCP checksum verification, and TCP window ACK pacing, while still comfortably saturating gigabit broadband/5G links at `~13–15 MiB` RSS.
2. **Protocol Scope (`v0.3.0`)**:
   - `v0.3.0` supports **Shadowsocks AEAD**, **Shadowsocks-2022 (`SIP022` TCP+UDP)**, **VLESS v0 + Post-Quantum `mlkem768x25519plus` (`0-RTT`/`1-RTT`, TCP & WebSocket)**, **Trojan (`TCP+TLS` & `WS+TLS` + UDP)**, **AnyTLS v2 (TLS 1.3 mux + UoT v2 UDP)**, **SOCKS5 (`RFC 1928/1929` TCP + UDP + TLS)**, and **HTTP/HTTPS `CONNECT`**. Mixed third-party Clash subscriptions containing unimplemented protocols (such as `vmess`, `hysteria2`, `tuic`, or `wireguard`) are automatically sanitized on import with unsupported entries reported via `skipped-unsupported` rather than failing the subscription.

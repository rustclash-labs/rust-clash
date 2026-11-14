# RUST-CLASH ULTIMATE — Engineering Architecture & Milestone Verification (`v0.4.0+`)

> **Current Status (`v0.4.0+`)**: All 6 engineering milestones are implemented across Linux, macOS, Windows, and Android. Core protocol interop, DNS/routing, userspace & Linux `ip netns` kernel TUN, FFI/JNI lifecycle, and Web/Android unit suites run automatically in CI (`PASS`), while live Windows kernel Wintun packet transit, macOS `utun` / signed `NEPacketTunnelProvider` activation, and physical Android `VpnService` runs remain documented under `BLOCKED` / `NOT TESTED` boundaries in [`docs/TEST_REPORT.md`](TEST_REPORT.md) and [`docs/REMAINING_ISSUES.md`](REMAINING_ISSUES.md).

## Companion Engineering Reports

- [`docs/PLATFORM_SUPPORT.md`](PLATFORM_SUPPORT.md) — Windows Wintun, macOS `utun` + `NEPacketTunnelProvider`, Linux `/dev/net/tun` policy routing, OS System Proxy, `SecretVault`, and Crash Recovery architecture.
- [`docs/ANDROID_IMPLEMENTATION.md`](ANDROID_IMPLEMENTATION.md) — `crates/proxy-ffi` direct JNI/C-ABI bridge, `RustClashVpnService`, `VpnService.protect(fd)` anti-loop design, per-app VPN routing, and APK/AAB build pipeline.
- [`docs/SECURITY_REVIEW.md`](SECURITY_REVIEW.md) — Threat model, default CSPRNG ephemeral controller `secret`, Android direct-JNI isolation, subscription sanitization & `rule-providers.path` confinement, per-OS `SecretVault` storage, and zero-leak credential redaction audit.
- [`docs/PERFORMANCE_BENCHMARK.md`](PERFORMANCE_BENCHMARK.md) — Reproducible comparative benchmarks (`rust-clash` vs `MetaCubeX/mihomo v1.19.33` vs `SagerNet/sing-box v1.14.4`) with exact two-sample Welch's $t$-tests over raw telemetry in [`docs/benchmarks_latest.json`](benchmarks_latest.json).
- [`docs/TEST_REPORT.md`](TEST_REPORT.md) — Complete `PASS / FAIL / BLOCKED / NOT TESTED` verification matrix across `ci.yml` (PR/Push CI) and `release.yml` (Release pipeline).
- [`docs/REMAINING_ISSUES.md`](REMAINING_ISSUES.md) — Transparent accounting of external code-signing/entitlement blockers and known architectural trade-offs.
- [`docs/USER_ACCEPTANCE_TESTS.md`](USER_ACCEPTANCE_TESTS.md) — Step-by-step manual acceptance checklist for physical Windows 11, macOS, Linux, and Android devices.

---

## 1. Architecture Summary

### 1.1 Core Proxy Kernel (`crates/proxy-core`)
- **Protocols & Interoperability**:
  - **Shadowsocks AEAD & SS-2022**: `aes-128-gcm`, `aes-256-gcm`, `chacha20-ietf-poly1305`, `2022-blake3-aes-128-gcm`, `2022-blake3-aes-256-gcm`, `2022-blake3-chacha20-poly1305` (with ±30s timestamp & 60s salt replay filter). Bidirectionally verified against `shadowsocks-rust v1.25.0`.
  - **VLESS v0 + Post-Quantum Hybrid Encryption (`mlkem768x25519plus`)**: `native` / `xorpub` / `random` header modes, 1-RTT X25519 + ML-KEM-768 handshake, 0-RTT Session Ticket resumption. Bidirectionally verified against `XTLS/Xray-core v26.10.31`.
  - **AnyTLS v2 & Trojan**: TLS 1.3 transport (`tokio-rustls`), AnyTLS SHA-256 + `padding0` auth, dynamic `PaddingScheme` MD5 negotiation, LIFO `SessionPool` multiplexing, and `sp.v2.udp-over-tcp.arpa` UoT v2. Bidirectionally verified against `anytls-go v0.0.13`.
  - **SOCKS5 & HTTP Outbound / Hardened Mixed Inbound**: RFC 1929 SOCKS5 `0x02` & HTTP `407` auth, `UDP ASSOCIATE` peer IP locking, LAN CIDR ACLs, and fail-closed DAG router validation.

### 1.2 Cross-Platform TUN, DNS, Routing & Product Hardening
1. **Cross-Platform System TUN & Mobile FFI**:
   - **Linux**: `/dev/net/tun` with dynamic collision-free routing table allocation, owned-rule ledger, IPv4 + IPv6 policy routing, `SO_MARK` (`fwmark`) loop prevention, and privileged `ip netns` kernel TUN E2E testing in CI.
   - **Windows**: Signed `wintun.dll` FFI adapter (`LoadLibraryExW` safe search flags + SHA-256 verification via [`scripts/fetch_wintun.py`](../scripts/fetch_wintun.py)), ring-buffer packet I/O, `iphlpapi` route/DNS configuration, `IP_UNICAST_IF` loop prevention, and `NotifyIpInterfaceChange` recovery.
   - **macOS**: Darwin `PF_SYSTEM` `utun` socket, 4-byte `AF_INET`/`AF_INET6` framing, `IP_BOUND_IF` loop protection, `scutil`/`networksetup` DNS & route snapshot/restore, plus Swift `NEPacketTunnelProvider` + C-ABI bridge (`platforms/macos-ne/`).
   - **Android**: Direct in-process JNI bridge (`crates/proxy-ffi` — zero loopback HTTP Control API spawned), `AsyncFd` TUN I/O, `VpnService.protect(fd)` callback on every outbound & DNS socket, Jetpack Compose UI (`android/`), per-app VPN + Lockdown detector, and `ConnectivityManager` network handoff.
2. **Event-Driven Data Plane, DNS & O(1) Router**:
   - Event-driven `smoltcp` (`iface.poll_delay()`, `0.0%` idle CPU, bounded `TUN_PACKET_QUEUE_CAPACITY = 4096`, `64 KiB × 2` per-flow TCP buffers) and stateful `OutboundUdpSession` + `UdpNatManager`.
   - Multi-transport DNS (`UDP`, `TCP`, `DoT` `tls://`, `DoH` `https://` RFC 8484), `default-nameserver` bootstrap, `fake-ip` & `redir-host`/`normal` modes, `dns.ipv6` policy, negative caching, and TTL clamping.
   - O(1) domain/suffix radix router, `GEOSITE`, `RULE-SET` / `rule-providers` (strictly confined within `state_dir`), pure-Rust `.mmdb` GeoIP reader, and cross-platform `PROCESS-NAME` matching.
3. **Security, Secret Storage & Crash Recovery**:
   - Default CSPRNG ephemeral controller `secret` across Desktop (`tauri-app`), CLI (`proxy-cli`), and `elevated-tun-helper`; session-scoped `sessionStorage` + URL `?secret=`/`?token=` scrubbing in [`ui/src/api.ts`](../ui/src/api.ts); untrusted remote subscription sanitization (`secret`/`allow-lan`/`bind-address`/`authentication`/`file`-provider stripping).
   - `RecoveryJournal` (`network_recovery.json`) + `SingleInstanceGuard` lockfile + 2-phase transactional config reload rollback.
   - Per-OS `SecretVault` (`keystore.rs`): Windows DPAPI, macOS Keychain (`security -i` stdin), Linux `libsecret` (`secret-tool` stdin) with `0600` local `AES-256-GCM` fallback, and Android `0700` app-sandboxed internal file store (`allowBackup="false"`).

---

## 2. Milestone Architecture & Verification Ledger

| Milestone | Engineering Scope | Automated Verification Suites & Workflows | Verification Status |
| :--- | :--- | :--- | :--- |
| **Milestone 1: Core Data Plane & UDP/TUN Engine** | `SocketProtector` anti-loop trait, event-driven `smoltcp` (`poll_delay()`), bounded [`VirtualTunHandle`](../crates/proxy-core/src/inbound/tun.rs), stateful `OutboundUdpSession` + `UdpNatManager`, AnyTLS UoT v2 | [`protocols_e2e.rs`](../crates/proxy-core/tests/protocols_e2e.rs), [`interop_external_e2e.rs`](../crates/proxy-core/tests/interop_external_e2e.rs), [`tun_stack_e2e.rs`](../crates/proxy-core/tests/tun_stack_e2e.rs), [`network_quality_regressions.rs`](../crates/proxy-core/tests/network_quality_regressions.rs) | **CI PASS** (Linux `x86_64`, macOS, Windows) |
| **Milestone 2: Multi-Transport DNS & O(1) Router** | `UDP`/`TCP`/`DoT`/`DoH` resolvers, bootstrap DNS, `fake-ip` & `redir-host`, negative cache, radix domain router, `GEOSITE`, confined `RULE-SET`, `.mmdb`, `PROCESS-NAME` | [`routing_dns_e2e.rs`](../crates/proxy-core/tests/routing_dns_e2e.rs), [`dns_router_ultimate_e2e.rs`](../crates/proxy-core/tests/dns_router_ultimate_e2e.rs), [`custom_dns_policy_e2e.rs`](../crates/proxy-core/tests/custom_dns_policy_e2e.rs), [`split_tunnel_routing_e2e.rs`](../crates/proxy-core/tests/split_tunnel_routing_e2e.rs) | **CI PASS** (Linux `x86_64`, macOS, Windows) |
| **Milestone 3: System TUN & Crash Recovery** | Linux `/dev/net/tun` policy routing (`fwmark`), Windows `wintun.dll` adapter, macOS `utun` + Swift `NEPacketTunnelProvider`, `RecoveryJournal`, `SingleInstanceGuard`, 2-phase reload rollback | [`linux_netns_tun_e2e.rs`](../crates/proxy-core/tests/linux_netns_tun_e2e.rs) ([`ci_linux_netns_tun_test.sh`](../scripts/ci_linux_netns_tun_test.sh)), [`network_handoff_recovery_e2e.rs`](../crates/proxy-core/tests/network_handoff_recovery_e2e.rs), [`fetch_wintun.py`](../scripts/fetch_wintun.py) (`--self-test`), `swiftc -typecheck` | **CI PASS** for Linux kernel `netns` TUN, Windows Wintun unit/tamper checks & macOS `swiftc`; live Windows/macOS kernel TUN **BLOCKED** in cloud CI (signing/privileges) |
| **Milestone 4: Native Android Client & JNI Bridge** | `crates/proxy-ffi` direct JNI/C-ABI (no HTTP listener), `RustClashVpnService`, `protect(fd)` callback, per-app VPN + Lockdown detector, Jetpack Compose UI, NDK APK/AAB build | [`ffi_bridge_e2e.rs`](../crates/proxy-ffi/tests/ffi_bridge_e2e.rs), [`VpnConfigAndLifecycleTest.kt`](../android/app/src/test/java/io/github/rustclashlabs/rustclash/VpnConfigAndLifecycleTest.kt), [`DebugLogManagerTest.kt`](../android/app/src/test/java/io/github/rustclashlabs/rustclash/DebugLogManagerTest.kt) | **CI PASS** (`testDebugUnitTest`, `lintDebug`, 4-ABI `assembleDebug`); live device `VpnService` **NOT TESTED** in headless CI |
| **Milestone 5: Desktop UX, Profiles & Security Hardening** | Real User Mode, `ProfileManager`, sanitized TLS 1.3 subscriptions, per-OS `SecretVault`, OS `SysProxy`, `AutostartManager`, Tauri 2 Tray, React Web Console (`npm test`), zero-leak diagnostics | [`milestone5_product_e2e.rs`](../crates/proxy-core/tests/milestone5_product_e2e.rs), [`security_and_hardening_e2e.rs`](../crates/proxy-core/tests/security_and_hardening_e2e.rs), [`node_import_persistence_e2e.rs`](../crates/proxy-core/tests/node_import_persistence_e2e.rs), [`subscription_wild_matrix_and_fuzz.rs`](../crates/proxy-core/tests/subscription_wild_matrix_and_fuzz.rs), [`api_control_e2e.rs`](../crates/proxy-core/tests/api_control_e2e.rs), [`latency_preconnect_e2e.rs`](../crates/proxy-core/tests/latency_preconnect_e2e.rs) | **CI PASS** (`cargo test`, `npm test`, `npm run build`) |
| **Milestone 6: Benchmarks, CI/Release Gates & Reports** | Comparative `rust-clash` vs `mihomo` vs `sing-box` harness with Welch's $t$-tests, **4-job** PR/Push CI ([`ci.yml`](../.github/workflows/ci.yml)), **6-job (7-matrix-run)** Release pipeline ([`release.yml`](../.github/workflows/release.yml)), and reconciled documentation | [`run_comparative_benchmarks.py`](../scripts/run_comparative_benchmarks.py) (`--recompute-stats`), [`.github/workflows/ci.yml`](../.github/workflows/ci.yml), [`.github/workflows/release.yml`](../.github/workflows/release.yml) | **CI PASS** |


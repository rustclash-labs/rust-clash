# Four-Platform Support Matrix & Systems Architecture (`v0.2.0`)

`rust-clash` is architected as a **four-platform** pure-Rust proxy client spanning **Windows**, **macOS**, **Linux**, and **Android**. All four platforms share the exact same Rust protocol, DNS, routing, and `smoltcp` userspace TCP/IP engine ([`crates/proxy-core`](../crates/proxy-core)), isolated behind narrow, auditable OS adapters in [`crates/proxy-core/src/platform/`](../crates/proxy-core/src/platform) and [`crates/proxy-ffi/`](../crates/proxy-ffi).

---

## 1. Honest Four-Platform Support & Real-World TUN Acceptance Matrix

Per our zero-fabrication engineering policy, simulated or in-memory packet channel tests are **never** counted as real OS TUN acceptance. Every platform's automated verification level and real-world live TUN test status are reported explicitly below:

| Platform | System Capture Backend | Loop Prevention (`SocketProtector`) | OS DNS & Crash Recovery | Automated CI Verification | Live Real-OS TUN Internet Acceptance (Browser, DNS Leak, TCP, UDP, IPv6, Handoff, Restart Cycles) | External / Hardware Blockers |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Linux (`x86_64` / `aarch64`)** | `/dev/net/tun` (`IFF_TUN \| IFF_NO_PI`) + collision-free policy-routing table (`20220..20320`) | `SO_MARK` (`0x1a5`) + `ip rule` / `ip -6 rule not fwmark 0x1a5` | `resolvectl` per-link DNS (`198.19.255.254`, `~.`) + `LinuxRecoveryRecord` rule/route rollback | **PASS** (`ubuntu-latest` CI: fmt, Clippy `-D warnings`, unit/E2E, external interop, isolated `ip netns` real `/dev/net/tun` 8-scenario E2E) | **TESTED & PASSED in Isolated Linux Kernel `ip netns`** (`ClashNs0` `/dev/net/tun`: HTTP GET/POST, IPv4+IPv6 canary `0` DNS leaks, 4 MiB TCP, UDP NAT, native IPv6 TCP/UDP, handoff recovery, 3x stop/start cycles). Physical desktop Wayland/X11 GUI session: **`NOT TESTED`** | Interactive physical desktop GUI smoke |
| **Windows (`x86_64`)** | Official WireGuard-signed **Wintun v0.14.1** (`wintun.dll`) ring-buffer session + `iphlpapi` | `IP_UNICAST_IF` / `IPV6_UNICAST_IF` pinned to physical NIC + `/32`/`/128` proxy bypass routes | Transactional `GetInterfaceDnsSettings` / `SetInterfaceDnsSettings` IPv4+IPv6 backup, strict result check & rollback (`WindowsDnsInterfaceBackup`) | **PASS** (`windows-latest` CI: Clippy `-D warnings`, signed `wintun.dll` SHA-256 verification, 6 DNS fault-injection & rollback tests, NSIS `.exe` + `.msi` build) | **`NOT TESTED`** *(No privileged interactive Windows VM/host with live internet & UAC elevation available without severing GitHub Actions runner WinRM/management NIC)* | Requires interactive Windows 10/11 Administrator session; Authenticode binary signing certificate (**BLOCKED**) |
| **macOS (`arm64` / `x86_64`)** | Native Darwin `PF_SYSTEM` `utun` socket **+** Swift `NEPacketTunnelProvider` System Extension ([`platforms/macos-ne/`](../platforms/macos-ne)) | `IP_BOUND_IF` / `IPV6_BOUND_IF` bound to primary `enX` interface + host bypass routes (`utun`) / Apple `NEPacketTunnelProvider` tunnel exclusion | Primary `networksetup` DNS snapshot & crash-recovery restore (`utun`) / `NEPacketTunnelNetworkSettings` (`NE`) | **PASS** (`macos-latest` CI: Clippy `-D warnings`, `utun` framing tests, 8-thread concurrent `NE` FFI UAF torture + `0 Hz` `Condvar` wakeup E2E, `xcrun swiftc -typecheck`, `.dmg` build) | **`NOT TESTED`** *(No root/entitled macOS host available for live `utun` / `.systemextension` capture without severing CI runner management network)* | Distributable `.systemextension` requires paid Apple Developer ID + `packet-tunnel-provider` entitlement (**BLOCKED**); live `sudo` `utun` requires physical/VM Mac |
| **Android (API 26–35, `arm64-v8a` / `x86_64`)** | `android.net.VpnService` foreground service (`specialUse`) + wakeup-pipe `0 Hz` idle `OwnedFd` packet bridge | JNI `VpnService.protect(fd)` invoked before every outbound TCP/UDP/DNS connect | `VpnService.Builder.addDnsServer("198.19.255.254")` + `UnderlyingNetworkTracker` Wi-Fi ↔ Cellular full session reset | **PASS** (`ubuntu-latest` CI: NDK `.so` cross-compile, `SOCK_SEQPACKET` `fstat`/`POLLHUP` zero-FD-leak & handoff E2E, Kotlin JUnit suite, universal `.apk` + `.aab` build) | **`NOT TESTED`** *(No physical Android phone or KVM-enabled Android emulator with cellular/Wi-Fi radios available in headless container environment)* | Physical Android 8–15 device / KVM emulator required for live `VpnService` consent & radio handoff; Play Store release keystore (**BLOCKED**) |

---

## 2. Shared Cross-Platform Core Invariants

### 2.1 In-Band TUN Peer DNS (`198.19.255.254`) vs Kernel `RTN_LOCAL`
- Assigning `198.18.0.1/15` as the OS kernel TUN interface's own IPv4 address causes the kernel to install `198.18.0.1` in its `local` routing table (`RTN_LOCAL` on Linux/Android). Packets addressed to `198.18.0.1:53` are delivered to loopback inside the host kernel and never enter the TUN file descriptor where `smoltcp` listens.
- [`TunLaunchSpec::dns_ipv4()`](../crates/proxy-core/src/platform/tun/mod.rs#L48-L52) reserves `broadcast - 1` (`198.19.255.254` in `198.18.0.0/15`) as the dedicated in-band TUN DNS peer, keeping `198.18.0.1` as the OS interface address and `198.18.0.2 .. 198.19.255.253` as the deterministic Fake-IP pool.

### 2.2 Event-Driven `0 Hz` Idle Packet Loops Across Core, Android, and macOS NE
- **Core `smoltcp` Stack** ([`inbound/tun.rs`](../crates/proxy-core/src/inbound/tun.rs)): Computes exact protocol timers via `iface.poll_delay(now, &sockets)` and sleeps on `tokio::select!` with `0 Hz` idle wakeups.
- **Android / Unix FD Bridge** ([`fd_bridge.rs`](../crates/proxy-ffi/src/fd_bridge.rs)): Uses a self-pipe (`poll([rx_fd, wake_rd], 2, -1)`) for pure event-driven blocking (`0 Hz` idle wakeups) and `< 1 ms` deterministic wake-on-stop.
- **macOS `NEPacketTunnelProvider` FFI Bridge** ([`ne_c_api.rs`](../crates/proxy-ffi/src/ne_c_api.rs) + [`PacketTunnelProvider.swift`](../platforms/macos-ne/PacketTunnelProvider.swift)): Uses a `Mutex + Condvar` outbound queue (`rc_ne_wait_outbound_packet(..., -1)`) with 64-packet batch coalescing — **0 timer wakeups when idle** (replacing the legacy `2ms` / `500 Hz` `DispatchSourceTimer`) — and an opaque handle registry (`Mutex<HashMap<usize, Arc<NeEngineContext>>>`) eliminating Use-After-Free races between `stopTunnel` and concurrent packet/status callbacks.

### 2.3 Full Session Recovery Across Network Handoffs (`ProxyEngine::notify_network_change`)
- Invoked automatically by Android `UnderlyingNetworkTracker` (`ConnectivityManager` Wi-Fi ↔ Cellular / AP roaming / `onLost`), macOS `NEPacketTunnelProvider.wake()`, and desktop route watchers (`LinuxSystemTunSession`, `MacOsUtunSession`, `WindowsWintunSession`).
- [`ProxyEngine::notify_network_change()`](../crates/proxy-core/src/engine.rs#L1313-L1315) atomically:
  1. Resets all active `UdpNatManager` sessions (closing outbound UDP sockets bound to the stale physical interface),
  2. Advances the `AnyTlsSessionPool` generation epoch, drains pooled `idle` TLS 1.3 sessions, and aborts live reader/writer tasks so pre-handoff streams fail fast and can never poison the post-handoff pool,
  3. Signals `ActiveConnection` cancellation across tracked TCP/UDP flows, and
  4. Flushes positive, negative, wire-packet, and bootstrap DNS caches.

### 2.4 Transactional OS Mutation & Crash-Consistent `RecoveryJournal`
- Before mutating OS routes, DNS settings, or System Proxy settings, `rust-clash` acquires `rust-clash.lock` ([`SingleInstanceGuard`](../crates/proxy-core/src/platform/recovery.rs)) and persists rollback state atomically to `network_recovery.json` ([`RecoveryJournal`](../crates/proxy-core/src/platform/recovery.rs)).
- On Windows ([`windows.rs`](../crates/proxy-core/src/platform/tun/windows.rs)), `apply_windows_adapter_dns_transactional` snapshots prior IPv4 & IPv6 `DNS_INTERFACE_SETTINGS` (`NameServer`, `Domain`, `SearchList`), verifies every Win32 return code (`NO_ERROR`), rolls back IPv4 DNS immediately if IPv6 DNS fails, and aborts `WindowsWintunSession::start` with full route/adapter cleanup rather than ever falsely reporting active TUN on DNS failure.

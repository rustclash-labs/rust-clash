# macOS System TUN & NetworkExtension (`NEPacketTunnelProvider`)

`rust-clash` provides **two** genuine macOS system-level packet capture backends sharing the same `smoltcp` userspace TCP/IP + Fake-IP + multi-protocol outbound core:

1. **Native Darwin `PF_SYSTEM` `utun` Backend (`crates/proxy-core/src/platform/tun/macos.rs`) — Active Default**
   - Works on both **Apple Silicon (`aarch64-apple-darwin`)** and **Intel (`x86_64-apple-darwin`)** without requiring a paid Apple Developer Program `NetworkExtension` entitlement.
   - Opens `PF_SYSTEM` / `SYSPROTO_CONTROL` (`com.apple.net.utun_control`), frames raw L3 IPv4/IPv6 packets with Darwin's 4-byte `AF_INET=2` / `AF_INET6=30` big-endian header, configures `ifconfig` IP/MTU, installs reversible split-tunnel routes (`0.0.0.0/1` + `128.0.0.0/1` and `::/1` + `8000::/1`), binds outbound proxy & bootstrap DNS sockets to the physical `enX` interface via `IP_BOUND_IF` / `IPV6_BOUND_IF`, snapshots/restores `networksetup` DNS, and logs all owned mutations to `network_recovery.json`.
   - Requires root privileges (`sudo rust-clash elevated-tun-helper --config <path>`).

2. **Native Apple `NEPacketTunnelProvider` System Extension (`platforms/macos-ne/` + `crates/proxy-ffi`)**
   - Implements Apple's first-party `NEPacketTunnelProvider` (`PacketTunnelProvider.swift`) linked against `libproxy_ffi.a` (`RustClashNEBridge.h`).
   - Uses `NEPacketTunnelNetworkSettings` (`includedRoutes`, `excludedRoutes` for loop prevention, `NEDNSSettings`, and `NEPacketTunnelFlow`) so non-root users can toggle system VPN directly from macOS System Settings / Tauri.

## Honest Signing & Distribution Status

Apple's macOS kernel (`nesessionmanager` / AMFI) refuses to load `com.apple.networkextension.packet-tunnel` System Extensions unless signed with:
- A paid **Apple Developer ID Application** (or Mac App Store) certificate,
- The restricted `com.apple.developer.networking.networkextension` (`packet-tunnel-provider`) entitlement, and
- Matching notarization & provisioning profile for `io.github.rustclashlabs.rustclash.packet-tunnel`.

Because those proprietary Apple credentials are not present in CI, `libproxy_ffi.a` and `PacketTunnelProvider.swift` are compiled/type-checked on `macos-latest` CI (`xcrun swiftc -typecheck`), while signed `.systemextension` notarization is explicitly marked **`BLOCKED (Requires Apple Developer Entitlement)`**.

### Building Locally with an Apple Developer Certificate

```bash
# 1. Build universal static FFI library (Apple Silicon + Intel)
cargo build --release -p proxy-ffi --target aarch64-apple-darwin
cargo build --release -p proxy-ffi --target x86_64-apple-darwin
lipo -create \
  target/aarch64-apple-darwin/release/libproxy_ffi.a \
  target/x86_64-apple-darwin/release/libproxy_ffi.a \
  -output platforms/macos-ne/libproxy_ffi_universal.a

# 2. Type-check / compile the Swift NEPacketTunnelProvider against RustClashNEBridge.h
xcrun swiftc -typecheck \
  -import-objc-header platforms/macos-ne/RustClashNEBridge.h \
  platforms/macos-ne/PacketTunnelProvider.swift
```

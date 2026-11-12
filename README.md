# rust-clash

> **Experimental Pure-Rust Multi-Platform Proxy Client, Userspace TUN Stack & Desktop/Mobile Apps (`v0.3.2`, Pre-1.0) — VLESS (`mlkem768x25519plus`), Trojan, AnyTLS v2, Shadowsocks-2022, WebSocket 0-RTT, Multi-Transport DNS, Tauri 2 & Jetpack Compose.**

`rust-clash` is an experimental pure-Rust proxy engine (`crates/proxy-core`), CLI daemon (`crates/proxy-cli`), Tauri 2 desktop client (`crates/tauri-app`), JNI/C-ABI bridge (`crates/proxy-ffi`), Jetpack Compose Android `VpnService` client (`android/`), and React 19 Web Console (`ui/`), written without Go (`mihomo`/`sing-box`/`xray-core`) or C/C++ proxy sidecars.

> **Experimental & AI-Authored Notice / 实验性项目与 AI 编写声明**
> - **AI-Authored Prototype**: This codebase is **experimental** in nature and was written end-to-end by **Gemini 4 Argon** and **Gemini 4 Carbon** under human direction and review. It has **not** undergone an independent third-party cryptographic or security audit. Do not rely on it for high-stakes anonymity or production workloads.
> - **Verification & Signing Scope**: Only Linux (`ip netns` `/dev/net/tun` + policy routing) and localhost (`127.0.0.1`) protocol interoperability are executed end-to-end in automated CI today. Live privileged TUN/VPN packet capture on **physical Windows, macOS, and Android devices** has not yet undergone hardware UAT sign-off, and Windows/macOS desktop installers are currently unsigned. Review the [Platform & Verification Matrix](#platform--verification-status) below before use.
> - **中文说明**：本项目为**实验性质**的纯 Rust 跨平台代理客户端原型，代码全程由 **Gemini 4 Argon** 与 **Gemini 4 Carbon** 编写，尚未经过独立第三方密码学或安全审计，且 Windows / macOS / Android 真机系统级 TUN 仍待实机验收，仅供技术研究、学习与受控环境测试使用。

---

## Platform & Verification Status

| Platform / Subsystem | Build & CI Automated Coverage | Live OS / Physical Hardware Status | Signing & Distribution Notes |
|---|---|---|---|
| **Linux (`x86_64`)** | Unit/E2E suite, Tauri 2 WebKitGTK build, and isolated `ip netns` `/dev/net/tun` + `SO_MARK` policy routing E2E (`scripts/ci_linux_netns_tun_test.sh`) | **Live-tested in Linux kernel network namespaces** | `.tar.gz`, `.deb`, `.rpm` (unsigned packages; `SHA256SUMS.txt` published) |
| **Windows 10/11 (`x86_64`)** | Rust unit/E2E suite, `wintun.dll` SHA-256 verification, CLI `.zip` & Tauri `.exe`/`.msi` packaging | **`NOT TESTED` on a live Administrator Windows host** (`wintun.dll` ring I/O, `iphlpapi` split routes & roaming recovery implemented, pending live host UAT) | Executable/installers are **not Authenticode-signed** (SmartScreen warning); bundled `wintun.dll` retains upstream Microsoft/WireGuard LLC driver signature |
| **macOS 13+ (`arm64` / `x86_64`)** | Rust unit/E2E suite, CLI `.tar.gz` & Tauri `.dmg` packaging, Swift `NEPacketTunnelProvider` (`platforms/macos-ne/`) `swiftc -typecheck` | **`NOT TESTED` on physical macOS hardware** (`PF_SYSTEM` `utun` & `scutil` DNS/route code pending root UAT; `.systemextension` blocked by macOS without paid entitlement) | `.dmg` is **not signed/notarized** with Apple Developer ID; `NEPacketTunnelProvider` requires a paid Apple Developer `networkextension` entitlement |
| **Android 8.0+ (`API 26+`)** | Cross-compiled `libproxy_ffi.so` (`arm64-v8a`, `x86_64`), Kotlin JUnit + Robolectric UI tests, Android Lint, R8 APK/AAB assembly | **`NOT TESTED` on a physical Android handset or emulator VPN tunnel** (`VpnService`, `protect(fd)`, Per-App VPN & network handoff implemented, pending device UAT per [`docs/USER_ACCEPTANCE_TESTS.md`](docs/USER_ACCEPTANCE_TESTS.md)) | Release APKs (`v1+v2+v3`) signed with project self-signed release keystore (`SHA256SUMS.txt` published) |
| **External Protocol Interop** | Bidirectional TCP + UDP tests against official `XTLS/Xray-core v26.10.31`, `shadowsocks-rust v1.25.0`, and `anytls-go v0.0.13` (`interop_external_e2e.rs`) | **Verified over local loopback (`127.0.0.1`) in CI** (not benchmarked or soaked across multi-hop WAN/CDN paths) | Reference binaries fetched & SHA-256 checked in CI `/tmp` only; never bundled |

---

## Differentiating Highlights: Glass-Box Diagnostics, Static Config Audit & Credential-Redacted `MCP`

Instead of competing purely on legacy protocol sprawl, `rust-clash` focuses on three pain points common across mainstream proxy clients (`Mihomo`, `Clash Verge Rev`, `sing-box`, `v2rayN`): opaque `generate_204` latency numbers, silent subscription security/DNS pitfalls, and manual black-box troubleshooting when AI/developer tools fail behind a proxy:

1. **`Clippy for Clash` Static Config Audit, Rule Shadowing Linter & Route Simulator (`rust-clash audit` + `/diagnostics/audit`)**
   - Audits Clash YAML and remote subscriptions (`0–100` score, Grade `A`–`F`), flagging MITM-vulnerable `skip-cert-verify: true` nodes, unencrypted remote transports, unauthenticated LAN controllers, shadowed domain/CIDR rules, dead rules after `MATCH`, and `IP-CIDR`/`GEOIP` rules missing `no-resolve` (distinguishing encrypted DoH/DoT pre-route resolver lookups from plaintext `:53` ISP DNS exposure).
   - Separates offline static first-member estimates (`static_first_member_estimate`) from live `Router` selector/URLTest state (`live_router_selection`) and optional live DNS verification (`?resolve_dns=true`), plus **credential-redacted Subscription Refresh Security Diffs**.
2. **Surge-Grade Per-Stage Timing Waterfall & AI / Developer Endpoint Matrix (`rust-clash probe` + `/proxies/{name}/probe` & `/matrix`)**
   - Decomposes TCP latency into `DNS Resolve -> Tunnel Connect -> TLS Handshake [TLSv1.3 / ALPN] -> HTTP TTFB` (isolated from parallel UDP checks so slow/blackholed UDP probes never inflate TCP latency history), distinguishing `Reachable` (`2xx`/`3xx`), `AuthRequired` (`401` unblocked API gateway), `RateLimited` (`429` shared-IP quota/throttle — never misreported as API-ready), and `BlockedOrChallenged` (`403`/`451` Geo/WAF blocks).
   - Verifies **real UDP datagram relay** (`verified` vs `blackholed` vs `unsupported`) via RFC 1035 DNS echo, and protects diagnostic probe APIs with a built-in **SSRF / private-network guard** (blocking loopback, RFC1918 LAN, link-local `169.254.0.0/16`, and cloud metadata endpoints by default) plus concurrency limiting.
3. **Built-in Credential-Redacted `MCP` Server (`rust-clash mcp`)**
   - Native JSON-RPC 2.0 `stdio` Model Context Protocol server (`audit_config_security`, `explain_route`, `probe_waterfall`, `probe_ai_matrix`, `get_proxy_status`, plus opt-in `switch_proxy_selector` behind `--allow-mutations`) so **Claude Code**, **Gemini CLI**, or **Cursor** can diagnose proxy routing, Split-DNS rules, and `403`/`429` responses.
   - Redacts passwords, UUIDs, private keys, and Bearer tokens unconditionally, rejects raw YAML secret payloads in tool arguments (auditing local files via `config_path` instead), and runs in **metadata privacy mode by default** (hiding proxy server IPs/domains and browsed destination hosts unless `--include-network-metadata` is explicitly enabled).

---

## Architecture & Implemented Capabilities

### 1. System TUN Backends & Userspace `smoltcp` Stack
- **Linux (`/dev/net/tun` + Policy Routing + `SO_MARK`)**: Dynamic policy routing table selection, owned-rule ledger (avoids flushing unrelated host tables), IPv4/IPv6 capture, and `SO_MARK` (`fwmark`) outbound loop prevention.
- **Windows (`wintun.dll` + `iphlpapi`)**: Dynamic loading of unmodified `wintun.dll` (`LoadLibraryExW` safe search flags), ring-buffer packet I/O, `CreateUnicastIpAddressEntry` IPv4/IPv6 + `0.0.0.0/1` & `128.0.0.0/1` split-tunnel routes, `IP_UNICAST_IF` physical NIC binding, and `NotifyIpInterfaceChange` callbacks *(pending live Windows UAT)*.
- **macOS (`PF_SYSTEM` `utun` + Swift `NEPacketTunnelProvider` source)**: Darwin `com.apple.net.utun_control` socket framing, `IP_BOUND_IF` primary interface binding, `scutil`/`networksetup` DNS & route snapshot/restore, plus Swift `NEPacketTunnelProvider` bridge source under `platforms/macos-ne/` *(pending physical macOS UAT & Apple Developer signing)*.
- **Android (`VpnService` + Jetpack Compose + Quick Settings `TileService` + `crates/proxy-ffi` JNI)**: Kotlin Material 3 client (`android/`) bridging `ParcelFileDescriptor` TUN FDs into `smoltcp`, invoking `VpnService.protect(fd)` on outbound TCP/UDP/DNS bootstrap sockets, with Per-App allowlist/denylist and `ConnectivityManager` callbacks *(pending physical handset UAT)*.
- **Event-Driven Userspace Stack (`smoltcp` `AnyIP`)**: `iface.poll_delay()` timer scheduling, IPv4/IPv6 TCP stream reassembly, stateful `UdpNatManager` UDP sessions, and `any:53` DNS interception.

### 2. Supported Outbound Protocols & Compatibility Boundaries
- **VLESS (`v0`) + Post-Quantum Encryption (`mlkem768x25519plus`) + WebSocket (`WS` / `WSS` + `0-RTT`)**:
  - Loopback-verified against **`XTLS/Xray-core v26.10.31`**; supports `native`, `xorpub`, and `random` header modes, **1-RTT** (`X25519` + `ML-KEM-768`) & **0-RTT** ticket resumption, VLESS UDP (`0x02`) & XUDP (`0x03`), WebSocket `max-early-data`, and `rust-clash keygen-vless`.
- **Trojan (`TCP+TLS` & `WS+TLS` + UDP Relay)**:
  - SHA-224 hex credential framing with initial payload coalescing, native Trojan UDP framing, TLS session resumption, WebSocket `0-RTT` early-data transport, and `trojan://` URI import/export *(verified via internal loopback E2E tests)*.
- **AnyTLS v2 + UoT v2**:
  - Loopback-verified against **`anytls-go v0.0.13`**; TLS 1.3 (`tokio-rustls` + `aws-lc-rs`), SHA-256 + `padding0` authentication, configurable `PaddingScheme`, LIFO `SessionPool` multiplexing, and UDP-over-TCP v2 (`sp.v2.udp-over-tcp.arpa`).
- **Shadowsocks Legacy AEAD & Shadowsocks-2022 (`SIP022`)**:
  - Loopback-verified against **`shadowsocks-rust v1.25.0`**; `aes-128-gcm`, `aes-256-gcm`, `chacha20-ietf-poly1305`, `2022-blake3-aes-128-gcm`, `2022-blake3-aes-256-gcm`, and `2022-blake3-chacha20-poly1305` (TCP + stateful SIP022 UDP + 60s replay window).
- **SOCKS5 (`RFC 1928/1929` TCP + `UDP ASSOCIATE` + Optional TLS) & HTTP/HTTPS `CONNECT`**:
  - Supports `socks5://`, `socks5h://`, `http-proxy://`, and `https-proxy://` URIs and Clash YAML entries.
- **Explicitly Unsupported Clash Meta Protocols**:
  - `VMess`, `Hysteria2`, `TUIC`, `WireGuard` outbound, VLESS `REALITY` / XTLS `flow` (`xtls-rprx-vision`), and `gRPC` / `HTTPUpgrade` transports are **not** implemented. Mixed V2Board/Mihomo subscriptions containing unsupported node types automatically skip those entries and prune group references (`SkippedProxyEntry`) when at least one supported node is present.

### 3. Multi-Transport DNS, Routing Engine & Profile Management
- **Multi-Transport DNS Engine**: `UDP`, `TCP`, **DNS-over-TLS (`tls://`)**, and **DNS-over-HTTPS (`https://` RFC 8484)** with pooled connections, `singleflight` query deduplication, literal-IP `default-nameserver` bootstrap separation, `fake-ip` (`198.18.0.0/15`) & `redir-host`/`normal` modes, negative caching, and TTL clamping.
- **RFC 8305 Happy Eyeballs & TLS Resumption**: Interleaved IPv6/IPv4 connection racing (`250 ms` stagger) integrated with engine DNS + `SocketProtector` and `rustls` `ClientSessionMemoryCache(256)`.
- **Routing Engine**: Hash/radix domain matching, binary-search interval tables for `IP-CIDR` / `IP-CIDR6` / `SRC-IP-CIDR` / `RULE-SET` (`rule-providers`), built-in fallback + optional `.mmdb` / remote rule-list `GEOIP` & `GEOSITE`, `PROCESS-NAME` matching, and `/rules/explain` diagnostics.
- **Profiles & Credential Hygiene**: Persistent HTTPS subscription manager (`Subscription-Userinfo`, V2Board/Mihomo YAML normalization, atomic `.bak` rollback), OS `SecretVault` integration (Windows DPAPI, macOS Keychain, Linux Secret Service, Android Keystore, with `0600` local AES-256-GCM fallback in headless environments), `RecoveryJournal` crash rollback, and automatic credential redaction in `GET /configs` and `GET /diagnostics/export`.

---

## Single-Host Loopback Benchmark Summary (`v0.2.0`, Linux `x86_64`, `n = 6` Rounds)

> **Benchmark Scope & Caveats**: Measurements below were recorded on **`rust-clash v0.2.0`** across 6 interleaved Latin-square rounds on a **single Linux `x86_64` cloud VM (`Intel Xeon Platinum 8481C`, 2 vCPUs)** over **kernel loopback (`127.0.0.1`)** against a local `shadowsocks-rust v1.25.0` server (`2022-blake3-aes-256-gcm`). Client, proxy, upstream server, and echo origin shared the same 2-vCPU host; results measure userspace CPU/memory overhead and loopback scheduling rather than physical NIC, WAN packet-loss, or mobile hardware performance. Notice that `sing-box` leads single-stream TCP bulk throughput on loopback, while 8-stream TCP multi-stream 95% confidence intervals overlap across all three engines. Full methodology, CIs, and raw data are in [`docs/PERFORMANCE_BENCHMARK.md`](docs/PERFORMANCE_BENCHMARK.md).

| Metric (`n = 6` interleaved rounds, `Mean ± SD` / `Median`) | `rust-clash v0.2.0` (Mixed) | `mihomo v1.19.33` (Mixed) | `sing-box v1.14.4` (Mixed) | `rust-clash v0.2.0` (`L3 TUN MTU 1500`) |
|---|---:|---:|---:|---:|
| **Binary Size** | `20.02 MiB` *(incl. Web UI)* | `59.20 MiB` | `77.64 MiB` | `20.02 MiB` |
| **Cold Startup Ready (ms)** | `22.87 ± 12.37` (`21.00`) | `25.64 ± 6.89` (`21.44`) | `43.51 ± 4.19` (`41.91`) | — |
| **Idle CPU (%)** | `0.00 ± 0.00 %` | `0.17 ± 0.26 %` (`0.00 %`) | `0.00 ± 0.00 %` | `0.00 %` *(event-driven)* |
| **Idle / Peak `VmRSS` (MiB)** | `9.63 ± 0.20` / `13.80 ± 0.28` | `39.49 ± 0.93` / `60.76 ± 1.11` | `54.35 ± 0.53` / `56.73 ± 0.52` | `9.46 ± 0.13` / `24.34 ± 0.45` |
| **TCP Single-Stream 64 MiB (Mbps)** | `2,690 ± 148` (`2,704`) | `2,630 ± 78` (`2,621`) | `4,536 ± 231` (`4,606`) | `2,175 ± 225` (`2,243`, 16 MiB) |
| **TCP Multi-Stream (Mbps)** | `5,347 ± 1,305` (`5,833`, 8-str) | `5,429 ± 511` (`5,381`, 8-str) | `6,078 ± 287` (`6,037`, 8-str) | `2,622 ± 143` (`2,600`, 4-str) |
| **Encrypted Echo RTT `P50` (ms)** | `0.194 ± 0.042` (`0.178`) | `0.339 ± 0.020` (`0.333`) | `0.274 ± 0.023` (`0.269`) | `0.344 ± 0.023` (`0.343`) |
| **UDP Relay (`loss` / `PPS`)** | `0.0%` / `11,630 ± 1,407` | `0.0%` / `10,200 ± 427` | `0.0%` / `12,642 ± 930` | `0.0%` / `8,036 ± 573` |
| **DNS / Hijack `P50` (ms)** | `0.026 ± 0.001` (`26 µs`) | `0.046 ± 0.002` (`45 µs`) | `0.049 ± 0.005` (`48 µs`) | `0.033 ± 0.009` (`36 µs`) |

---

## Workspace Layout

```text
rust-clash/
├── crates/
│   ├── proxy-core/        # Pure-Rust proxy kernel, protocols, DNS, router, TUN, profiles & REST/WS API
│   ├── proxy-ffi/         # JNI & C-ABI mobile/extension bridge (Android VpnService + macOS NE)
│   ├── proxy-cli/         # `rust-clash` CLI daemon, TUN helper, config validator & protocol servers
│   └── tauri-app/         # `rust-clash-desktop` Tauri 2 native shell, System Tray & IPC commands
├── android/               # Native Kotlin Android VpnService client, Per-App VPN UI & Gradle project
├── platforms/macos-ne/    # Swift NEPacketTunnelProvider & C FFI header source for macOS
├── ui/                    # Responsive Desktop & Mobile React 19 + TypeScript + Vite 6 Console
├── configs/               # Synthetic RFC 2606 example configuration (`clash-demo.yaml`)
├── scripts/               # Android NDK build, Wintun verifier, Linux netns E2E & benchmark scripts
└── docs/                  # Architecture, platform support, security, benchmark, test & UAT reports
```

---

## Quickstart

### 1. Desktop & CLI (Starter Profile or Local Demo Sandbox)

```bash
# Validate synthetic example YAML syntax, proxy ciphers, DAG groups, and compiled rules
cargo run --release -p proxy-cli -- check -c configs/clash-demo.yaml

# Launch with the persistent Starter Profile (creates an empty local profile with zero third-party nodes)
cargo run --release -p proxy-cli -- run

# Or launch the self-contained localhost Demo Cluster (spawns local loopback VLESS+PQ, AnyTLS v2 & SS-2022 servers)
cargo run --release -p proxy-cli -- run --demo \
  --mixed-port 7890 \
  --controller 127.0.0.1:9090 \
  --dns-listen 127.0.0.1:1053

# Check OS System TUN driver, privilege & crash-recovery preflight status
cargo run --release -p proxy-cli -- tun-check

# Run static config security audit, rule shadowing linter & Split-DNS route simulator
cargo run --release -p proxy-cli -- audit -c configs/clash-demo.yaml

# Run per-stage timing waterfall (`DNS -> Tunnel -> TLS -> HTTP TTFB`) + UDP relay probe or full AI matrix
# (private/loopback targets are blocked by default; pass `--allow-private-targets` for local lab debugging)
cargo run --release -p proxy-cli -- probe --url https://api.github.com/
cargo run --release -p proxy-cli -- probe --matrix

# Start the credential-redacted MCP JSON-RPC 2.0 `stdio` server
# (read-only & metadata-private by default; add `--include-network-metadata` or `--allow-mutations` if desired)
cargo run --release -p proxy-cli -- mcp

# Generate Xray-compatible Post-Quantum VLESS (`mlkem768x25519plus`) keypairs
cargo run --release -p proxy-cli -- keygen-vless --mode xorpub
```

### 2. Build Desktop App (`tauri-app`) & Native Android Client (`android/`)

```bash
# 1. Build embedded React 19 Web Console
cd ui && npm ci && npm run build && cd ..

# 2. Build Tauri 2 Desktop App (Windows WebView2 / macOS WKWebView / Linux WebKitGTK)
cargo build --release -p tauri-app --features desktop

# 3. Cross-compile Rust JNI (`arm64-v8a` + `x86_64`), run JUnit tests, and assemble Android APK & AAB
./scripts/build_android.sh
```

---

## Documentation, Security & Contributing

### Governance & Vulnerability Reporting
- **Maintainer**: **RustClash Labs** (`https://github.com/rustclash-labs/rust-clash` · [`rustclash.labs@proton.me`](mailto:rustclash.labs@proton.me))
- [**Security Policy & Private Vulnerability Reporting (`SECURITY.md`)**](SECURITY.md) — **Never** post real subscription URLs, server IPs, node passwords/UUIDs, or undisclosed vulnerabilities in public GitHub Issues.
- [**Contributing & Sanitization Guidelines (`CONTRIBUTING.md`)**](CONTRIBUTING.md)
- [**Third-Party Licenses & Attribution Notices (`THIRD_PARTY_NOTICES.md`)**](THIRD_PARTY_NOTICES.md)

### Engineering Reports (`docs/`)
1. [**Cross-Platform System TUN & OS Verification Matrix**](docs/PLATFORM_SUPPORT.md)
2. [**Native Android VpnService & JNI Architecture**](docs/ANDROID_IMPLEMENTATION.md)
3. [**Security Review & Threat Model**](docs/SECURITY_REVIEW.md)
4. [**Comparative Loopback Benchmarks (`rust-clash` vs `Mihomo` vs `sing-box`)**](docs/PERFORMANCE_BENCHMARK.md)
5. [**Test & Interoperability Verification Matrix**](docs/TEST_REPORT.md)
6. [**Remaining Issues, Signing & Physical-Hardware UAT Blockers**](docs/REMAINING_ISSUES.md)
7. [**Physical Device User Acceptance Test Guide**](docs/USER_ACCEPTANCE_TESTS.md)
8. [**Engineering Plan & Milestone Ledger**](docs/ULTIMATE_PLAN.md)

---

## License

Dual-licensed under either the [**MIT License**](LICENSE-MIT) or the [**Apache License, Version 2.0**](LICENSE-APACHE), at your option.

Windows release archives include unmodified `wintun.dll` (`v0.14.1`) alongside `wintun-LICENSE.txt` under the WireGuard LLC Prebuilt Binaries License; see [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md) for complete third-party license notices and trademark disclaimers.

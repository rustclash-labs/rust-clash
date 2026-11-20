<div align="center">

<img src="crates/tauri-app/icons/128x128@2x.png" alt="RustClash" width="88">

# RustClash

A pure-Rust multi-platform proxy client and userspace TUN engine. Transparent, lightweight, open-source and ad-free.

[简体中文](README.md) · **English**

[![Release](https://img.shields.io/github/v/release/rustclash-labs/rust-clash?style=flat-square&label=release&color=10b981)](https://github.com/rustclash-labs/rust-clash/releases/latest)
[![CI](https://img.shields.io/github/actions/workflow/status/rustclash-labs/rust-clash/ci.yml?style=flat-square&label=ci)](https://github.com/rustclash-labs/rust-clash/actions/workflows/ci.yml)
[![Pure Rust](https://img.shields.io/badge/core-Pure%20Rust-f59e0b?style=flat-square)](crates/proxy-core)
[![AI Authored](https://img.shields.io/badge/AI--Authored-Gemini%20Argon%20%C2%B7%20Carbon%20%C2%B7%20Neon%20%7C%20GPT%20Reviewed-8b5cf6?style=flat-square)](#status--docs)
[![License](https://img.shields.io/badge/license-MIT%20%2F%20Apache--2.0-38bdf8?style=flat-square)](LICENSE-MIT)

[Download](#download) · [Features](#features) · [Usage](#usage) · [Build from source](#build-from-source) · [Docs](#status--docs)

</div>

> [!IMPORTANT]
> **100% AI-Authored & AI-Reviewed Codebase**: Every line of code in this repository — the pure-Rust proxy kernel, `smoltcp` userspace TUN stack, Tauri 2 desktop client, React Web UI, and native Android app — was **written end-to-end by Gemini Argon, Gemini Carbon, and Gemini Neon, with GPT participating in code review** (humans provided product direction and real-device acceptance feedback only). Experimental Pre-1.0 prototype; not independently security-audited.

<p align="center">
  <img alt="RustClash Android Light UI Showcase — Exit City Landmark Skylines, Live Telemetry & One-Handed Controls" src="docs/images/android-light-showcase.png" width="94%">
</p>

<details>
<summary>More screenshots (Android 5-Screen Light Overview · Desktop Console · Security Audit · Timing Waterfall · AI Matrix · MCP)</summary>
<br>
<p align="center">
  <img src="docs/images/android-light-overview.png" alt="Android Light UI 5-Screen Overview (Home, Nodes, Rules, Profiles, Settings)" width="100%" />
  <br><strong>Native Android Jetpack Compose Light UI</strong> — Exit city landmark skylines, live throughput &amp; latency telemetry, smart routing rules, profiles, and appearance controls.
</p>
<table>
  <tr>
    <td width="50%" valign="top">
      <img src="docs/images/dashboard-overview.png" alt="Desktop and Web Console Overview" />
      <br><strong>Desktop &amp; Embedded Web Console</strong> — Real-time kernel telemetry and OS takeover controls across Windows, macOS, and Linux.
    </td>
    <td width="50%" valign="top">
      <img src="docs/images/config-security-audit.png" alt="Config Security Audit" />
      <br><strong>Config Security Audit</strong> — Static linter catching MITM risks, DNS leaks, and shadowed rules.
    </td>
  </tr>
  <tr>
    <td width="50%" valign="top">
      <img src="docs/images/timing-waterfall.png" alt="Timing Waterfall" />
      <br><strong>Timing Waterfall</strong> — Breaks latency into <code>DNS → Tunnel → TLS → HTTP TTFB</code> plus UDP check.
    </td>
    <td width="50%" valign="top">
      <img src="docs/images/ai-endpoint-matrix.png" alt="AI Endpoint Matrix" />
      <br><strong>AI &amp; Dev Readiness Matrix</strong> — 1-click stage-isolated probe across common AI and API endpoints.
    </td>
  </tr>
  <tr>
    <td colspan="2" valign="top">
      <img src="docs/images/mcp-integration.png" alt="MCP Integration" />
      <br><strong>Privacy-First MCP Studio</strong> — Ready-to-copy <code>MCP</code> config and credential-redacted YAML view.
    </td>
  </tr>
</table>
</details>

## Features

- **One client across Android, Windows, macOS, and Linux** — native Jetpack Compose Android app, Tauri 2 desktop app, headless CLI, and embedded Web UI.
- **100% pure-Rust core & userspace `smoltcp` TUN** — zero Go or C/C++ proxy sidecars (`~10–25 MiB` desktop RSS, `0%` idle CPU).
- **Mainstream outbound protocols** — 100% pure-Rust **VLESS** (`REALITY` + `xtls-rprx-vision` and Post-Quantum `mlkem768x25519plus` 0-RTT/1-RTT), **VMess AEAD**, **Hysteria2** (with Salamander obfuscation & port hopping), **TUIC v5**, **Trojan**, **AnyTLS v2**, **Shadowsocks (AEAD / 2022)**, and **SOCKS5 / HTTP(S)**.
- **Multi-transport Split-DNS** — `Fake-IP` and Real-IP modes over `UDP`, `TCP`, `DoT`, and multiplexed `HTTP/2 DoH` with hedged failover and `Smart CN` routing.
- **Glass-box diagnostics** — plain-language Site Connectivity Doctor, `DNS → Tunnel → TLS → HTTP TTFB` waterfall probes, and real UDP relay verification.
- **`Clippy for Clash` security audit** — built-in static config linter (`0–100` score), Split-DNS route simulator, and subscription refresh diffing.
- **Credential-redacted `MCP` server** — lets Claude Code, Gemini CLI, and Cursor inspect routing and connectivity without exposing node secrets.
- **Platform touches** — Android Quick Settings tile, per-app VPN, Android Keystore AES-256-GCM hardware-wrapped vault key, and fast Wi-Fi/5G handoff; desktop system tray and OS keychain storage.

## Download

Get the latest build from [`v0.5.8` Latest Release](https://github.com/rustclash-labs/rust-clash/releases/latest) (all artifacts ship with `SHA256SUMS.txt`).

| Platform | Packages | Notes |
| --- | --- | --- |
| **Android 8.0+** | `arm64-v8a` and `universal` `.apk` | Most phones use `arm64-v8a`. Signed with the project release key. |
| **Windows 10+** | `.exe` installer, `.msi`, or CLI `.zip` (`x64`) | Includes signed `wintun.dll`; installer is unsigned. See [Platform Matrix](docs/PLATFORM_SUPPORT.md) for live TUN verification status. |
| **macOS 13+** | `.dmg` and CLI `.tar.gz` (`Apple Silicon` & `Intel`) | Unsigned `.dmg` (right-click Open on first launch). See [Platform Matrix](docs/PLATFORM_SUPPORT.md) for live `utun` status. |
| **Linux** | `.deb`, `.rpm`, and CLI `.tar.gz` (`x64`) | Embedded Web UI included in both desktop and CLI builds. |

## Usage

**Run from CLI or try the local Demo Sandbox** (no external servers required):

```bash
rust-clash run                  # Normal mode (web console on 127.0.0.1:9090)
rust-clash run --demo           # Local loopback sandbox (VLESS+PQ, AnyTLS v2, SS-2022)
rust-clash audit -c config.yaml # Static security & Split-DNS leak check
rust-clash probe --matrix       # Stage-by-stage timing waterfall & UDP check
```

**Connect AI coding agents via `MCP`** (`Claude Code` / `Gemini CLI` / `Cursor`):

```json
{
  "mcpServers": {
    "rust-clash": {
      "command": "rust-clash",
      "args": ["mcp"]
    }
  }
}
```

## Build from source

Requires [Rust](https://rustup.rs/) (stable) and [Node.js](https://nodejs.org/) 22+.

```bash
cd ui && npm ci && npm run build && cd ..
cargo build --locked --release -p proxy-cli                     # Headless CLI + Web UI
cargo build --locked --release -p tauri-app --features desktop  # Desktop client
./scripts/build_android.sh                                      # Android APK & AAB
```

| Platform | Extra prerequisites |
| --- | --- |
| **Android** | JDK 17+, Android SDK (`API 35+`), and Android NDK. |
| **Windows** | MSVC Build Tools and WebView2 Runtime (preinstalled on Windows 11). |
| **macOS** | Xcode Command Line Tools. |
| **Linux** | WebKitGTK 4.1 & GTK 3 development headers (only required for `tauri-app`). |

## Status & Docs

- **Protocol scope**: Mainstream Clash / Mihomo protocols are implemented natively in pure Rust; legacy or non-proxy-stream protocols (such as `SSR`, `Snell`, `WireGuard`, and `gRPC` transport) are omitted and automatically skipped during mixed-subscription import.
- **Documentation**: [Platform & TUN Support](docs/PLATFORM_SUPPORT.md) · [Android Architecture](docs/ANDROID_IMPLEMENTATION.md) · [Benchmarks](docs/PERFORMANCE_BENCHMARK.md) · [Security Policy](SECURITY.md) · [Contributing](CONTRIBUTING.md)

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE). Third-party notices (including bundled `wintun.dll` on Windows) are listed in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

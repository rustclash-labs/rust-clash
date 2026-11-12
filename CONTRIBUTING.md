# Contributing to `rust-clash`

Thank you for your interest in contributing to `rust-clash` (maintained by **RustClash Labs** — [`rustclash.labs@proton.me`](mailto:rustclash.labs@proton.me))!

> **Experimental & AI-Authored Codebase**: `rust-clash` is an experimental pure-Rust prototype written end-to-end by **Gemini 4 Argon** and **Gemini 4 Carbon** under human direction and review. Please read the security, privacy, verification, and licensing guidelines below before opening an issue or pull request.

---

## 1. Mandatory Privacy & Credential Sanitization Rules

Proxy client bug reports frequently risk exposing sensitive user infrastructure. **Before submitting any Issue, Pull Request, test fixture, screenshot, or log snippet, verify that you have removed:**

- **Subscription URLs & query tokens** (e.g., `https://.../api/v1/client/subscribe?token=...`).
- **Server endpoints** (real IPv4/IPv6 addresses or private domain names — replace with `127.0.0.1`, `192.0.2.1`, or `*.example.com` per RFC 2606 / RFC 5737).
- **Node credentials & keys** (`password`, `uuid`, Shadowsocks base64 PSKs, VLESS `encryption`/`decryption` strings, `secret`, `authentication`).
- **Raw packet captures (`.pcap` / `.pcapng`)**, unredacted system routing tables containing public WAN IPs, or personal usernames/file paths.

> **Tip**: Whenever attaching diagnostic state, use the built-in redacted diagnostic export (`GET /diagnostics/export` or **Settings -> Export Redacted Diagnostics** in the UI), and double-check the output before posting publicly. For security vulnerabilities, **never** open a public issue — follow [`SECURITY.md`](SECURITY.md) instead.

---

## 2. Clean-Room & Licensing Policy (`MIT OR Apache-2.0`)

`rust-clash` is dual-licensed under [`LICENSE-MIT`](LICENSE-MIT) and [`LICENSE-APACHE`](LICENSE-APACHE).

1. **No Copyleft Code Copying**: Do **not** copy, translate line-for-line, or adapt source code or embedded rule datasets from `GPL` / `LGPL` / `AGPL` / `SSPL` repositories (such as `MetaCubeX/mihomo`, `SagerNet/sing-box`, or `Loyalsoldier/clash-rules`). Protocol implementations must be written cleanly from public specifications (RFCs, SIP022, public wire-format docs) and verified via black-box interoperability tests.
2. **Third-Party Dependencies**: New Cargo, npm, or Gradle dependencies must use permissive licenses compatible with `MIT OR Apache-2.0` (`MIT`, `Apache-2.0`, `BSD-2-Clause`, `BSD-3-Clause`, `ISC`, `0BSD`, `Zlib`, `Unicode-3.0`) and be documented in [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md) when applicable.
3. **Developer Certificate of Origin / License Grant**: Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in `rust-clash` is licensed under both `MIT` and `Apache-2.0` without additional terms or conditions.

---

## 3. Scope & Engineering Standards

- **Truthful Verification Claims**: Do not mark OS-specific TUN, routing, or mobile VPN behavior as "verified on real hardware" unless reproducible test evidence exists. Clearly distinguish unit/mock tests, local loopback interop tests, Linux `ip netns` tests, and physical-device UAT in docs and PR descriptions.
- **Safety & Secret Hygiene**:
  - Keep `unsafe` blocks isolated to OS/FFI boundaries (`crates/proxy-ffi`, `crates/proxy-core/src/platform/`) with explicit safety invariants.
  - Ensure any new proxy field, URL parameter, or auth token is covered by `ClashConfig::redacted()` and `redact_sensitive_text()`.
  - Never hardcode real domains, IPs, or credentials in unit/integration tests; generate ephemeral loopback certificates and keys dynamically at test runtime.

---

## 4. Local Development & Verification Checklist

### Prerequisites

- **Rust**: Stable toolchain (`rustfmt`, `clippy`).
- **Node.js**: Node 24 LTS + `npm` (for `ui/`).
- **Android (optional)**: JDK 17 + Android SDK Platform 35 + NDK `27.2.12479018` (for `crates/proxy-ffi` & `android/`).

### Pre-PR Checks

```bash
# 1. Build embedded React 19 Web Console (required before compiling proxy-cli / tauri-app)
cd ui && npm ci && npm run build && cd ..

# 2. Check Rust formatting
cargo fmt --all -- --check

# 3. Run strict Clippy lints across the workspace
cargo clippy --workspace --all-targets -- -D warnings

# 4. Run unit and end-to-end integration tests
cargo test --workspace

# 5. Validate the example configuration
cargo run -p proxy-cli -- check -c configs/clash-demo.yaml
```

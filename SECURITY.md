# Security Policy

## Experimental Posture & Supported Versions

`rust-clash` is an **experimental, pre-1.0** codebase (`0.3.x`) written end-to-end by **Gemini 4 Argon** and **Gemini 4 Carbon** under human direction. It has **not** undergone an external cryptographic or security audit and is provided strictly `AS IS` for research, testing, and evaluation. Security fixes are applied on a best-effort basis to the latest minor release series on `main`:

| Version | Supported |
|---|---|
| `0.3.x` (`main`) | Yes (experimental / best-effort) |
| `< 0.3.0` | No (please upgrade to the latest `0.3.x` release) |

---

## Reporting a Vulnerability Privately

**Please do NOT report security vulnerabilities through public GitHub Issues, Discussions, or Pull Requests.**

Use **GitHub Private Vulnerability Reporting** to submit a confidential advisory directly to the maintainers:

1. Navigate to the repository's **Security** tab -> **Advisories** -> **New draft security advisory** (`https://github.com/rustclash-labs/rust-clash/security/advisories/new`), or email **RustClash Labs** directly at [`rustclash.labs@proton.me`](mailto:rustclash.labs@proton.me).
2. Provide a concise description of the affected crate/component (`proxy-core`, `proxy-ffi`, `proxy-cli`, `tauri-app`, `android`, or `ui`), reproduction steps, and potential impact.
3. **Sanitize all examples**: never include real proxy server IPs/domains, subscription URLs, `UUID`s, Shadowsocks PSKs, VLESS `encryption`/`decryption` private keys, API `secret` tokens, or unredacted packet captures (`.pcap`). Use localhost (`127.0.0.1`) or RFC 2606 example domains (`example.com`) and synthetic keys generated via `rust-clash keygen-vless`.

### Response Targets

- **Initial acknowledgment**: within **72 hours** of submission.
- **Triage & remediation plan**: within **7 days** for confirmed high/critical issues.
- **Coordinated disclosure**: once a patched release is available (or as mutually agreed with the reporter). Credit will be given in the security advisory and release notes unless anonymity is requested.

---

## Scope & Security Model

### In Scope

- Cryptographic or protocol framing flaws in `proxy-core` (`Shadowsocks-2022` replay protection, `VLESS` `mlkem768x25519plus` 1-RTT/0-RTT key derivation, `Trojan`, `AnyTLS v2`).
- External Controller REST/WebSocket authentication bypass, CORS/Origin validation bypass, DNS rebinding against `127.0.0.1`, or Tauri IPC privilege escalation.
- Credential or subscription token leakage in logs, error responses, `GET /configs` redaction, or diagnostic bundle exports (`GET /diagnostics/export`).
- Memory safety bugs in `unsafe` FFI/OS boundaries (`crates/proxy-ffi`, Windows `wintun.dll` / `iphlpapi`, macOS `PF_SYSTEM`, Linux `netlink`/ioctl, Android `VpnService` JNI).
- Routing loop / firewall bypass or DNS leak bugs when `tun.enable: true` or `mode: rule` is active.
- Untrusted input DoS (e.g., malformed Clash YAML, malicious subscription payloads, crafted DNS packets, or `smoltcp` L3 packets causing panics or unbounded allocation).

### Out of Scope / Known Deployment Constraints

- **Cleartext `external-controller` exposed on `0.0.0.0` without `secret` by explicit user override** (note: `rust-clash` refuses non-loopback controller binds without `secret` by default).
- **Self-signed / `skip-cert-verify: true` TLS nodes** explicitly configured by the user.
- **Unsigned Desktop Installers (`Windows SmartScreen` / `macOS Gatekeeper` / `macOS NetworkExtension`)**: Official Windows `.exe`/`.msi` and macOS `.dmg` builds are not yet signed with paid EV Authenticode or Apple Developer ID certificates; see [`docs/REMAINING_ISSUES.md`](docs/REMAINING_ISSUES.md) and [`docs/SECURITY_REVIEW.md`](docs/SECURITY_REVIEW.md).
- **Platform TUN paths pending physical-device sign-off**: Windows live Wintun, macOS live `utun`, and Android physical handset `VpnService` paths are documented in [`docs/PLATFORM_SUPPORT.md`](docs/PLATFORM_SUPPORT.md) with their exact verification status.

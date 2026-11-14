# User Acceptance Test (UAT) Runbook — Windows, macOS, Linux & Android

This guide provides step-by-step, non-destructive verification procedures for testing `rust-clash` on real physical machines and mobile devices.

---

## 1. Linux Desktop / Server (`x86_64` / `aarch64`)

### 1.1 Unprivileged Real User Mode + System Proxy
1. Start `rust-clash` (or launch the `RustClash` `.deb`/`.rpm` desktop app):
   ```bash
   ./rust-clash
   ```
2. Open `http://127.0.0.1:9090` in your browser.
3. Verify the **Welcome to RustClash — Clean Starter Profile Active** onboarding card appears (`Real User Mode`).
4. Navigate to **Profiles & PQ Studio**, enter a profile name, paste an `https://...` Clash subscription URL (or `ss://` / `vless://` / `anytls://` share links), and click **Fetch & Activate**.
5. Verify proxy nodes populate under **Proxies & Groups** and click **Test Group Latency**.
6. Verify proxy forwarding via `curl`:
   ```bash
   curl -x http://127.0.0.1:7890 https://api.ipify.org
   curl --socks5-hostname 127.0.0.1:7890 https://cloudflare.com/cdn-cgi/trace
   ```
7. On **Overview**, toggle **OS System Proxy** -> `Enabled`, verify desktop browser traffic appears under **Active Connections**, then toggle **OS System Proxy** -> `Disabled` and confirm GNOME/KDE proxy settings return to their prior state.

### 1.2 Linux System TUN Mode (`CAP_NET_ADMIN`)
1. Grant minimal `CAP_NET_ADMIN` capability (avoids full root):
   ```bash
   sudo setcap cap_net_admin+ep ./rust-clash
   ./rust-clash
   ```
2. On **Overview**, click **Enable OS TUN**.
3. Verify policy routing without host `main` default-route destruction:
   ```bash
   ip addr show Clash
   ip rule show | grep 202
   ```
4. Confirm ordinary unproxied CLI tools (`curl https://cloudflare.com/cdn-cgi/trace`) traverse the `Clash` TUN interface and appear in **Active Connections** with restored Fake-IP hostnames (`198.18.x.x -> cloudflare.com`).
5. Press `Ctrl+C` (or click **Disable OS TUN**) and verify `ip addr show Clash` is gone and `ip rule show` has zero leftover rules.

---

## 2. Windows 10 / 11 (`x86_64`)

### 2.1 Installation & System Proxy Mode (Standard User — No Admin Required)
1. Install `RustClash_0.4.0_x64-setup.exe` (or extract `rust-clash-cli-windows-x86_64.zip`, which includes `rust-clash.exe`, signed `wintun.dll`, and `wintun-LICENSE.txt` in the same folder).
2. Launch **RustClash**. Verify the system tray icon appears in the Windows taskbar notification area.
3. Import your subscription or node URI in **Profiles**. Verify the structured **Import Result Report** displays imported count, skipped duplicates, and grouped unsupported protocols (if any).
4. Right-click the tray icon -> **Toggle OS System Proxy** (or click the **Master Toggle** in **Overview**). Confirm the 3-layer status strip shows `Core Engine: Running`, `System Proxy / TUN: SysProxy`, and `Internet Connectivity: Normal` (after probe), while preserving your selected routing mode (`Rule` / `Global` / `Direct`) without silent mode mutation.
5. Open `Settings -> Network & internet -> Proxy` and confirm `127.0.0.1:7890` is active. Browse to `https://ipleak.net` in Edge/Chrome and confirm proxy egress.
6. Quit **RustClash** from the tray menu and confirm Windows Proxy automatically reverts to **Off** (or your previous corporate proxy).

### 2.2 Windows Wintun System TUN Mode (Administrator)
1. Close any running instance, then right-click **RustClash** -> **Run as administrator** (accept the UAC prompt).
2. On **Overview -> Advanced Network & System**, verify `TUN Privilege / Driver Hint` disappears (`driver_loaded: true`, `privilege_ok: true`) and enable **TUN**.
3. Open PowerShell and inspect the Wintun adapter and split routes:
   ```powershell
   Get-NetAdapter -Name "Clash"
   Get-NetRoute -AddressFamily IPv4 | Where-Object { $_.DestinationPrefix -in @("0.0.0.0/1", "128.0.0.0/1") }
   ```
4. Verify non-proxy-aware apps (e.g., `curl.exe https://api.ipify.org`, `nslookup example.com`) resolve Fake-IPs via `198.19.255.254` and tunnel cleanly without routing loops.
5. Switch between Wi-Fi and Ethernet (or toggle Wi-Fi off/on) and verify connectivity resumes automatically.
6. Disable **TUN** (or exit the app) and verify the `Clash` adapter and `0.0.0.0/1` + `128.0.0.0/1` routes are cleanly removed.

---

## 3. macOS 13+ (Apple Silicon `arm64` & Intel `x86_64`)

### 3.1 Desktop App & `networksetup` System Proxy (Standard User)
1. Open `RustClash_0.4.0_aarch64.dmg` (or `x86_64.dmg`) and drag **RustClash.app** to `/Applications`.
2. If Gatekeeper prompts for an unsigned developer build, run `xattr -cr /Applications/RustClash.app` once and open **RustClash**.
3. Import a profile in **Profiles**, then enable **OS System Proxy** on **Overview**.
4. Verify macOS proxy state:
   ```bash
   scutil --proxy
   ```
5. Disable **OS System Proxy** (or Quit from the macOS menu-bar tray icon) and confirm `scutil --proxy` restores `HTTPEnable : 0` / `SOCKSEnable : 0`.

### 3.2 macOS Native `utun` System TUN Mode
1. Run the CLI (or app binary) with `sudo`:
   ```bash
   sudo /Applications/RustClash.app/Contents/MacOS/rust-clash-desktop
   ```
2. Enable **TUN** in **Overview -> Advanced Network & System**.
3. Verify the `utunX` interface, `0/1` + `128.0/1` split routes, and `198.19.255.254` DNS configuration:
   ```bash
   ifconfig | grep -A 4 utun
   netstat -rn -f inet | grep -E "0/1|128.0/1"
   scutil --dns | head -n 30
   ```
4. Verify Safari, `curl https://api.ipify.org`, and UDP DNS queries traverse `rust-clash`.
5. Close the lid briefly (sleep/wake) and verify DNS & tunnel traffic recover cleanly.
6. Disable TUN or press `Ctrl+C` and confirm `scutil --dns` and `netstat -rn` return to their exact pre-TUN baseline.

---

## 4. Android 8.0–15 (`arm64-v8a` Physical Device / `x86_64` Emulator)

> **Verification Status Note**: Automated CI verifies `libproxy_ffi.so` cross-compilation (`arm64-v8a`, `x86_64`), pure-JVM + Robolectric tests, Android Lint, and persistent keystore APK v1/v2/v3 signing. Items in **4.1** below require manual execution on a physical Android handset before claiming real-device sign-off.

1. Install or upgrade `rust-clash-android-arm64-v8a.apk` (package `io.github.rustclashlabs.rustclash`, `versionCode >= 16`):
   ```bash
   adb install -r rust-clash-android-arm64-v8a.apk
   ```
2. Launch **RustClash**.
3. **Import Encrypted Profile & Inspect Report**:
   - Tap **配置 (Profiles) -> 导入/订阅**, paste your Clash YAML, `ss://` / `vless://` / `trojan://` / `anytls://` URI, or `https://` subscription URL, and submit (stored via Android Keystore).
   - Verify the **导入结果报告** card clearly separates `成功导入`, `重复跳过`, and `暂不支持` (with protocol breakdown such as `VMess` / `Hysteria2` if present).
4. **Connect & Consent**:
   - Tap the hero connect button on **首页 (Home)** and approve the Android system *Connection request* dialog.
   - Verify the Android VPN key icon + foreground notification appear, and confirm switching to `全局直连 (Direct)` explicitly displays `已连接（全局直连） · 当前为 Direct 模式 · 流量不经过代理节点`.
5. **Site Connectivity Doctor (`诊断连接问题`)**:
   - Tap **诊断连接问题** on **首页** (or open **规则 -> 网站排障**), enter `chatgpt.com` or `bilibili.com`, and tap **一键实测诊断**.
   - Verify plain-language route flow (`Rule → ...`), per-stage checks (`DNS` / `代理节点建连` / `TLS` / `HTTP`), and actionable suggestions render accurately.
6. **Per-App Split Tunneling**:
   - Open **设置 (Settings) -> 分应用代理**, choose **Allowlist** or **Blocklist**, select a browser app, save, and reconnect VPN. Verify included vs bypassed apps show expected egress IPs and `RustClash` never blocks its own `VpnService.protect(fd)` sockets under Android Lockdown.
7. **Wi-Fi ↔ Cellular Handoff & Doze Recovery**:
   - Toggle Wi-Fi off so Android switches to 5G/LTE, then toggle Wi-Fi back on. Confirm `RustClashVpnService` transitions cleanly (`RECONNECTING -> RUNNING`) without socket loops.

### 4.1 Physical Handset Sign-Off Checklist (Pending Hardware Execution)
- [ ] **In-Place APK Upgrade**: Install `v0.4.0` (`versionCode 16`) over `v0.3.9` (`versionCode 15`) without uninstalling; confirm single launcher icon (`io.github.rustclashlabs.rustclash`) and preserved encrypted profiles + manual nodes.
- [ ] **Wi-Fi ↔ 5G Roaming**: 5 consecutive Wi-Fi ↔ 5G transitions during active HTTPS browsing without stuck sockets or DNS timeouts.
- [ ] **Screen-Off Doze Wake**: Lock screen on battery for >= 15 minutes, unlock, and immediately run **网站排障 -> 一键实测诊断** (`github.com`).
- [ ] **Redacted Diagnostics & YAML Export**: Export Debug Diagnostic Report and Redacted YAML via SAF; confirm zero raw passwords, UUIDs, or subscription tokens appear in exported text.

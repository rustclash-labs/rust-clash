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
1. Install `RustClash_0.1.0_x64-setup.exe` (or extract `rust-clash-cli-windows-x86_64.zip`, which includes `rust-clash.exe`, signed `wintun.dll`, and `wintun-LICENSE.txt` in the same folder).
2. Launch **RustClash**. Verify the system tray icon appears in the Windows taskbar notification area.
3. Import your subscription or node URI in **Profiles & PQ Studio**.
4. Right-click the tray icon -> **Toggle OS System Proxy** (or click **Enable** next to *OS System Proxy* in Overview).
5. Open `Settings -> Network & internet -> Proxy` and confirm `127.0.0.1:7890` is active. Browse to `https://ipleak.net` in Edge/Chrome and confirm proxy egress.
6. Quit **RustClash** from the tray menu and confirm Windows Proxy automatically reverts to **Off** (or your previous corporate proxy).

### 2.2 Windows Wintun System TUN Mode (Administrator)
1. Close any running instance, then right-click **RustClash** -> **Run as administrator** (accept the UAC prompt).
2. On **Overview**, verify `TUN Privilege / Driver Hint` disappears (`driver_loaded: true`, `privilege_ok: true`) and click **Enable OS TUN**.
3. Open PowerShell and inspect the Wintun adapter and split routes:
   ```powershell
   Get-NetAdapter -Name "Clash"
   Get-NetRoute -AddressFamily IPv4 | Where-Object { $_.DestinationPrefix -in @("0.0.0.0/1", "128.0.0.0/1") }
   ```
4. Verify non-proxy-aware apps (e.g., `curl.exe https://api.ipify.org`, `nslookup example.com`) resolve Fake-IPs via `198.19.255.254` and tunnel cleanly without routing loops.
5. Switch between Wi-Fi and Ethernet (or toggle Wi-Fi off/on) and verify connectivity resumes automatically.
6. Click **Disable OS TUN** (or exit the app) and verify the `Clash` adapter and `0.0.0.0/1` + `128.0.0.0/1` routes are cleanly removed.

---

## 3. macOS 13+ (Apple Silicon `arm64` & Intel `x86_64`)

### 3.1 Desktop App & `networksetup` System Proxy (Standard User)
1. Open `RustClash_0.1.0_aarch64.dmg` (or `x86_64.dmg`) and drag **RustClash.app** to `/Applications`.
2. If Gatekeeper prompts for an unsigned developer build, run `xattr -cr /Applications/RustClash.app` once and open **RustClash**.
3. Import a profile in **Profiles & PQ Studio**, then enable **OS System Proxy** on **Overview**.
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
2. Click **Enable OS TUN** in **Overview**.
3. Verify the `utunX` interface, `0/1` + `128.0/1` split routes, and `198.19.255.254` DNS configuration:
   ```bash
   ifconfig | grep -A 4 utun
   netstat -rn -f inet | grep -E "0/1|128.0/1"
   scutil --dns | head -n 30
   ```
4. Verify Safari, `curl https://api.ipify.org`, and UDP DNS queries traverse `rust-clash`.
5. Close the lid briefly (sleep/wake) and verify DNS & tunnel traffic recover cleanly.
6. Disable OS TUN or press `Ctrl+C` and confirm `scutil --dns` and `netstat -rn` return to their exact pre-TUN baseline.

---

## 4. Android 8.0–15 (`arm64-v8a` Physical Device / `x86_64` Emulator)

1. Install `rust-clash-android-universal.apk` (or `android/app/build/outputs/apk/debug/app-debug.apk`):
   ```bash
   adb install -r android/app/build/outputs/apk/debug/app-debug.apk
   ```
2. Launch **RustClash VPN**.
3. **Import Encrypted Profile**:
   - Tap **Profile / Sub**, paste your Clash YAML, `ss://` / `vless://` / `anytls://` URI, or `https://` subscription URL, and tap **Save & Apply** (encrypted in Android hardware Keystore).
   - *(Optional offline test)*: Check **Enable Local Loopback Sandbox Demo Cluster** before connecting.
4. **Connect & Consent**:
   - Tap **Connect VPN** and approve the Android system *Connection request* dialog (and notification permission on Android 13+).
   - Verify the status badge turns green (`RUNNING`), the Android status bar displays the key icon + live `↓ / ↑` notification, and the mobile Web Console opens seamlessly with the bottom navigation bar (`Home`, `Proxies`, `Streams`, `Rules`, `Profiles`, `Logs`).
5. **Per-App Split Tunneling**:
   - Tap **Per-App** (or **Per-App Split Tunnel** inside the console), choose **Bypass Selected Apps (Blocklist)** or **Only Selected Apps (Allowlist)**, select a browser app, save, and reconnect VPN. Verify included vs bypassed apps show expected egress IPs.
6. **Wi-Fi ↔ Cellular Handoff**:
   - While streaming or loading pages, toggle Wi-Fi off so Android switches to mobile data (5G/LTE), then toggle Wi-Fi back on. Confirm `RustClashVpnService` stays `RUNNING` without socket loops.
7. **Disconnect / Revoke**:
   - Tap **Disconnect** (either in the app header or directly from the Android notification shade) and verify the VPN key icon disappears immediately.

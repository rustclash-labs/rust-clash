# Third-Party Licenses & Redistribution Notices

`rust-clash` source code is dual-licensed under either the [MIT License](LICENSE-MIT) or the [Apache License, Version 2.0](LICENSE-APACHE), at your option.

Binary distributions (CLI archives, Tauri desktop installers, and Android APK/AAB packages) incorporate or dynamically link third-party open-source components under the licenses summarized below.

---

## 1. Wintun Tunnel Driver (Windows Distributions Only)

Official Windows release packages (`rust-clash-cli-windows-x86_64.zip`, NSIS `.exe` installer, and `.msi` installer) fetch and bundle the unmodified, Microsoft- and WireGuard-signed `wintun.dll` (`v0.14.1`) from `https://www.wintun.net/` alongside `wintun-LICENSE.txt` at build time (`scripts/fetch_wintun.py`). `wintun.dll` is **not** checked into this Git repository.

### Wintun Prebuilt Binaries License Notice

```text
Copyright (c) 2018-2021 WireGuard LLC. All Rights Reserved.

Redistribution and use in binary form, without modification, are permitted
provided that the following conditions are met:

1. Redistributions must reproduce the above copyright notice, this list of
   conditions and the following disclaimer in the documentation and/or other
   materials provided with the distribution.
2. Neither the name of the copyright holder nor the names of its contributors may
   be used to endorse or promote products derived from this software without
   specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

"WireGuard" and "Wintun" are registered trademarks or trademarks of Jason A. Donenfeld / WireGuard LLC. Their names are referenced strictly to describe technical compatibility and driver provenance; WireGuard LLC does not endorse or sponsor `rust-clash`.

---

## 2. Rust Workspace Dependencies (`Cargo.lock`)

Direct and transitive Rust crates compiled into `proxy-core`, `proxy-ffi`, `proxy-cli`, and `tauri-app` are distributed under permissive or weak file-level copyleft licenses compatible with `MIT OR Apache-2.0` distribution:

| Component Group | Representative Crates | License(s) |
|---|---|---|
| Async Runtime & HTTP/WS | `tokio`, `tokio-util`, `hyper`, `axum`, `tower`, `tokio-tungstenite` | `MIT` |
| TLS, AEAD & Post-Quantum Crypto | `rustls`, `tokio-rustls`, `aws-lc-rs`, `aws-lc-sys`, `chacha20poly1305`, `aes-gcm`, `x25519-dalek`, `ml-kem`, `blake3`, `sha2`, `md-5` | `MIT`, `Apache-2.0`, `ISC`, `BSD-3-Clause`, `CC0-1.0` |
| Mozilla Root CA Store | `webpki-roots` | `CDLA-Permissive-2.0` |
| Userspace TCP/IP Stack | `smoltcp` | `0BSD` |
| Desktop Shell & Tray | `tauri`, `tauri-build`, `wry`, `tao`, `tray-icon`, `muda` | `Apache-2.0 OR MIT` |
| Serialization, CLI & FFI | `serde`, `serde_json`, `serde-saphyr`, `clap`, `jni`, `uuid`, `ipnet`, `parking_lot` | `MIT OR Apache-2.0` |
| File-Level Weak Copyleft / Multi-Licensed | `option-ext` (unmodified crate dependency), `r-efi` (elected under `MIT OR Apache-2.0`) | `MPL-2.0`, `MIT OR Apache-2.0` |
| Linux Desktop System Libraries (Dynamic Only) | `webkit2gtk-4.1`, `gtk+-3.0`, `libsoup-3.0`, `libayatana-appindicator3` | `LGPL-2.1-or-later` (dynamically linked from host OS packages on Linux; never statically linked) |

### CDLA-Permissive-2.0 Attribution (`webpki-roots`)

`rust-clash` embeds root CA trust anchors via `webpki-roots` (derived from the Mozilla Included CA Certificate List) under the Community Data License Agreement – Permissive, Version 2.0 (`CDLA-Permissive-2.0`, <https://cdla.dev/permissive-2-0/>).

---

## 3. Embedded Web Console Dependencies (`ui/package-lock.json`)

Only the production browser bundle (`ui/dist`) is embedded into `proxy-cli` and `tauri-app`:

| Package | Version Range | License |
|---|---|---|
| `react` | `^19.0.0` | `MIT` |
| `react-dom` | `^19.0.0` | `MIT` |
| `scheduler` | transitive (`react-dom`) | `MIT` |

Build-only developer toolchains (`vite`, `typescript`, `@vitejs/plugin-react`, `esbuild`, `rollup`) are not shipped inside release binaries.

---

## 4. Android Client Dependencies (`android/app/build.gradle.kts`)

The Android application (`io.github.rustclashlabs.rustclash`) bundles Kotlin/JVM libraries licensed under **Apache License, Version 2.0** (`http://www.apache.org/licenses/LICENSE-2.0`):

- **AndroidX & Jetpack Compose** (`androidx.core:core-ktx`, `androidx.activity:activity-compose`, `androidx.lifecycle:*`, `androidx.compose.ui:*`, `androidx.compose.material3:material3`, `androidx.compose.material:material-icons-extended`) — Copyright The Android Open Source Project (`Apache-2.0`).
- **Kotlin Standard Library & Coroutines** (`org.jetbrains.kotlin:*`, `org.jetbrains.kotlinx:kotlinx-coroutines-android`) — Copyright JetBrains s.r.o. and Kotlin Programming Language contributors (`Apache-2.0`).
- **ZXing Core** (`com.google.zxing:core:3.5.3`, QR code generation/parsing) — Copyright ZXing authors (`Apache-2.0`).
- **Gradle Wrapper** (`android/gradle/wrapper/gradle-wrapper.jar`) — Copyright Gradle Inc. (`Apache-2.0`).

*(Note: Unit/screenshot test dependencies under `testImplementation` such as JUnit 4 `EPL-1.0`, Robolectric `MIT`, and `org.json:json` are used strictly during local/CI JVM test execution and are never packaged into release or debug APKs/AABs.)*

---

## 5. External Protocol & GeoData Ecosystem References

- **Clean-Room Implementation**: `rust-clash` contains zero source code copied from GPL/AGPL projects (`mihomo`, `sing-box`, `Loyalsoldier/clash-rules`, etc.).
- **CI Interop & Benchmark Binaries**: External binaries (`XTLS/Xray-core` `MPL-2.0`, `shadowsocks/shadowsocks-rust` `MIT`, `anytls/anytls-go` `MIT`, `MetaCubeX/mihomo` `GPL-3.0`, `SagerNet/sing-box` `GPL-3.0`) are downloaded into ephemeral `/tmp` directories during CI/benchmark runs solely as black-box peers over localhost sockets and are **never** linked or distributed with `rust-clash`.
- **Optional Runtime GeoData Downloads**: Built-in routing fallback tables (`geoip_data.rs`, `geosite_data.rs`) consist of factual RIR/APNIC CIDR allocations and well-known public domain suffixes. When a user explicitly triggers runtime GeoData updates (`POST /geodata/update` or UI "Update GeoData"), the client fetches rule lists configured by URL (defaulting to `Loyalsoldier/clash-rules`, licensed under `GPL-3.0`) directly onto the user's device; those external datasets are not redistributed in this repository or its release artifacts.

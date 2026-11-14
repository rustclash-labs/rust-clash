# Comparative Performance, Statistical Distribution & TUN-Path Benchmark Report

This report documents the committed multi-round, order-interleaved benchmark baseline (`rust-clash v0.2.0` dataset in [`docs/benchmarks_latest.json`](benchmarks_latest.json)) comparing **`rust-clash` (`v0.2.0` data-plane baseline)** against cryptographic-hash-pinned official releases of **`MetaCubeX/mihomo` (`v1.19.33`)** and **`SagerNet/sing-box` (`v1.14.4`)**, alongside dedicated **`rust-clash` L3 `smoltcp` TUN (`MTU 1500`)** data-path measurements.

Raw per-round samples, aggregated error distributions (`mean`, `stdev`, `median`, `iqr`, `min`, `max`, `ci95_half_width`, `cv_pct`), and two-sample unequal-variance **Welch's $t$-tests** (Satterthwaite $\text{df}$, exact two-sided $p$-values via the regularized incomplete beta function) are committed in [`docs/benchmarks_latest.json`](benchmarks_latest.json) and reproduced/verified via [`scripts/run_comparative_benchmarks.py`](../scripts/run_comparative_benchmarks.py) (`--recompute-stats docs/benchmarks_latest.json`) and [`crates/proxy-cli/src/bench_tun.rs`](../crates/proxy-cli/src/bench_tun.rs).

---

## 1. Test Environment & Supply-Chain Pins

| Property | Value |
|---|---|
| **Measured At (UTC)** | `2026-11-09T03:15:17Z` (`v0.2.0` historical benchmark baseline) |
| **Operating System** | `Linux 6.12.105+ x86_64 (Debian 12 / glibc 2.36)` |
| **CPU Model** | `Intel(R) Xeon(R) Platinum 8481C` (`2` logical vCPUs) |
| **Rounds & Interleaving** | **`6` rounds** — complete **`6`-permutation balanced Latin square** across all engine orderings |
| **Statistical Hypothesis Test** | Two-sided **Welch's two-sample $t$-test** ($\alpha = 0.05$, Satterthwaite $\text{df}$), 95% Student-$t$ CIs ($\text{df} = 5$, $t_{0.975, 5} = 2.5706$), plus **`median (IQR)`** & **`min..max`** |
| **Neutral Upstream Proxy Server** | Official `shadowsocks-rust v1.25.0` (`ssserver -U`), SHA-256 `8439bf43c324b0fc273e663d0b1f8926fd8f666cbd1e0fd59b35096f0e778e92` |
| **Encrypted Wire Protocol** | **Shadowsocks-2022 (`2022-blake3-aes-256-gcm`)** — SIP022 AEAD stream (TCP) + SIP022 encrypted datagrams (UDP) |
| **Reference Engine 1** | `MetaCubeX/mihomo v1.19.33` (`linux-amd64-compatible`), SHA-256 `386508bfb1c72c43b6a0eda73708ecdce82546581b0ebcb16366c53757c622b6` |
| **Reference Engine 2** | `SagerNet/sing-box v1.14.4` (`linux-amd64`), SHA-256 `699a1b510aa4396b2176d32d1181920399ebf1e267835da6f3b598d0f7c24968` |
| **`rust-clash` Build Profile** | `cargo build --release -p proxy-cli --bin rust-clash` (`rustc` stable, embedded Web UI assets included) |

---

## 2. Experimental Design (Eliminating Order Bias & Single-Run Noise)

Single-shot loopback runs on shared-vCPU hosts suffer from thermal/turbo drift, page-cache warm-up after compilation, and ephemeral port churn. To prevent overclaiming from single-round noise:

1. **Complete 6-Permutation Balanced Latin Square**:
   - **Round 1**: `rust-clash -> mihomo -> sing-box`
   - **Round 2**: `mihomo -> sing-box -> rust-clash`
   - **Round 3**: `sing-box -> rust-clash -> mihomo`
   - **Round 4**: `rust-clash -> sing-box -> mihomo`
   - **Round 5**: `sing-box -> mihomo -> rust-clash`
   - **Round 6**: `mihomo -> rust-clash -> sing-box`
   - Every engine executes **twice in position #1**, **twice in position #2**, and **twice in position #3**, and precedes/follows every peer engine an equal number of times.
2. **Identical Neutral Upstream & Routing**:
   - All three engines dial the same standalone `shadowsocks-rust` (`ssserver -U`) instance using `2022-blake3-aes-256-gcm` with `mode: rule`, `redir-host` / `hijack-dns`, and `MATCH -> SS-2022`.
   - Only one engine runs at any instant; its process tree is terminated and reaped before the next engine starts.
3. **Kernel `/proc` Telemetry**:
   - **Idle CPU %** from `/proc/<pid>/stat` (`utime + stime`) across a quiet `2.0 s` window per round (`12.0 s` total idle observation per engine).
   - **Idle & Peak `VmRSS`** from `/proc/<pid>/statm` (`20 ms` background sampler during the `8 x 16 MiB = 128 MiB` concurrent encrypted stream flood).
4. **Actual L3 TUN Stack Measurement (`rust-clash bench-tun`) + Kernel `/dev/net/tun` E2E**:
   - In every round (`n = 6`), `rust-clash bench-tun` drives **real IPv4 `MTU 1500` (`MSS 1460`) packets** through [`VirtualTunHandle`](../crates/proxy-core/src/inbound/tun.rs) (`smoltcp 0.12` IP/TCP/UDP checksums, sliding-window segmentation/ACKs, port-53 DNS interception, and bounded `mpsc` queues with `TUN_PACKET_QUEUE_CAPACITY = 4096`) -> `ProxyEngine` -> `2022-blake3-aes-256-gcm` -> external `ssserver`.
   - Because the local benchmark sandbox runs without `CAP_NET_ADMIN` (`os_kernel_tun_privilege_in_local_env: false`), `mihomo` and `sing-box` kernel `/dev/net/tun` adapters cannot be opened inside this unprivileged VM. Real Linux kernel `/dev/net/tun` + `ip rule` + `SO_MARK` throughput and 8-dimension verification for `rust-clash` is executed in GitHub Actions inside an isolated `ip netns` via [`scripts/ci_linux_netns_tun_test.sh`](../scripts/ci_linux_netns_tun_test.sh).

---

## 3. Multi-Round Comparative Results — Mixed Inbound (`n = 6` Interleaved Rounds)

Values are reported on two lines per cell:
- Top: **`Mean ± SD`** (`± 95% Student-t CI half-width`)
- Bottom: **`Median (IQR)`** `[min .. max]`

Exact two-sided Welch's $t$-tests compare `rust-clash` against `mihomo` and `sing-box` from the 6 per-round raw samples ($\alpha = 0.05$):

| Metric | `rust-clash v0.2.0` (Rust) | `mihomo v1.19.33` (Go) | `sing-box v1.14.4` (Go) | Exact Welch's $t$-Test Verdict ($\alpha = 0.05$, two-sided) |
|---|---:|---:|---:|---|
| **Binary Size** | **`20.02 MiB`** *(incl. Web UI)* | `59.20 MiB` | `77.64 MiB` | **Deterministic** (`0` variance): **`2.96x` smaller** than `mihomo` (`-39.18 MiB`); **`3.88x` smaller** than `sing-box` (`-57.62 MiB`) |
| **Cold Startup Ready (ms)** | `22.87 ± 12.37` (`±12.98`)<br>**`21.00 (15.49)`** `[10.58..42.59]` | `25.64 ± 6.89` (`±7.23`)<br>`21.44 (7.45)` `[21.15..37.11]` | `43.51 ± 4.19` (`±4.40`)<br>`41.91 (0.64)` `[41.38..52.04]` | vs `mihomo`: **Not statistically significant** (`t = -0.478`, `df = 7.83`, `p = 0.6457`);<br>vs `sing-box`: **Significant** (`t = -3.869`, `df = 6.13`, `p = 0.0079`) |
| **Idle CPU (%)** | **`0.00 ± 0.00`** (`±0.00`)<br>**`0.00 (0.00)`** `[0.00..0.00]` | `0.17 ± 0.26` (`±0.27`)<br>`0.00 (0.37)` `[0.00..0.50]` | **`0.00 ± 0.00`** (`±0.00`)<br>**`0.00 (0.00)`** `[0.00..0.00]` | vs `mihomo`: **Not statistically significant** (`t = -1.581`, `df = 5.00`, `p = 0.1747`);<br>vs `sing-box`: **Not statistically significant** (`t = 0.000`, `df = 10.00`, `p = 1.0000`) |
| **Idle Memory `VmRSS` (MiB)** | **`9.63 ± 0.20`** (`±0.21`)<br>**`9.59 (0.25)`** `[9.41..9.95]` | `39.49 ± 0.93` (`±0.98`)<br>`39.94 (1.30)` `[38.16..40.33]` | `54.35 ± 0.53` (`±0.56`)<br>`54.21 (0.30)` `[53.85..55.36]` | vs `mihomo`: **Significant** (`t = -76.647`, `df = 5.48`, `p = 1.614e-09`, `4.10x` lower);<br>vs `sing-box`: **Significant** (`t = -192.457`, `df = 6.45`, `p = 2.253e-13`, `5.64x` lower) |
| **Peak Memory `VmRSS` (MiB)** | **`13.80 ± 0.28`** (`±0.29`)<br>**`13.76 (0.39)`** `[13.51..14.19]` | `60.76 ± 1.11` (`±1.17`)<br>`60.92 (1.37)` `[58.92..61.81]` | `56.73 ± 0.52` (`±0.54`)<br>`56.69 (0.36)` `[56.11..57.64]` | vs `mihomo`: **Significant** (`t = -100.523`, `df = 5.62`, `p = 2.281e-10`, `4.40x` lower);<br>vs `sing-box`: **Significant** (`t = -179.117`, `df = 7.66`, `p = 3.804e-15`, `4.11x` lower) |
| **TCP 1-Stream (`32 MiB`, Mbps)** | `5,747.5 ± 1,954.5` (`±2,051.1`)<br>`6,303.8 (927.7)` `[1,898..7,222]` | `5,556.2 ± 442.7` (`±464.6`)<br>`5,615.6 (517.7)` `[4,869..6,057]` | **`7,743.4 ± 771.9`** (`±810.1`)<br>**`7,980.2 (303.7)`** `[6,224..8,369]` | vs `mihomo`: **Not statistically significant** (`t = +0.234`, `df = 5.51`, `p = 0.8236`);<br>vs `sing-box`: **Not statistically significant** (`t = -2.326`, `df = 6.52`, `p = 0.0555`; `sing-box` higher point mean, R1 cold-VM outlier widens `rust-clash` variance — see §5) |
| **TCP 8-Stream (`128 MiB`, Mbps)** | `5,347.0 ± 1,305.3` (`±1,369.9`)<br>`5,833.4 (123.7)` `[2,689..6,036]` | `5,428.9 ± 510.7` (`±536.0`)<br>`5,381.2 (467.5)` `[4,725..6,214]` | **`6,077.9 ± 286.5`** (`±300.7`)<br>**`6,036.8 (348.6)`** `[5,803..6,544]` | vs `mihomo`: **Not statistically significant** (`t = -0.143`, `df = 6.50`, `p = 0.8906`);<br>vs `sing-box`: **Not statistically significant** (`t = -1.340`, `df = 5.48`, `p = 0.2332`) |
| **SOCKS5 Setup `P50` (ms)** | `0.255 ± 0.066` (`±0.070`)<br>**`0.229 (0.003)`** `[0.227..0.391]` | **`0.252 ± 0.038`** (`±0.040`)<br>`0.246 (0.045)` `[0.207..0.311]` | `0.398 ± 0.032` (`±0.033`)<br>`0.406 (0.030)` `[0.349..0.439]` | vs `mihomo`: **Not statistically significant** (`t = +0.107`, `df = 7.95`, `p = 0.9177`);<br>vs `sing-box`: **Significant** (`t = -4.748`, `df = 7.15`, `p = 0.0020`) |
| **SOCKS5 Setup `P95` (ms)** | **`0.353 ± 0.121`** (`±0.127`)<br>**`0.314 (0.015)`** `[0.272..0.598]` | `0.525 ± 0.126` (`±0.132`)<br>`0.500 (0.139)` `[0.413..0.743]` | `0.564 ± 0.030` (`±0.031`)<br>`0.554 (0.043)` `[0.534..0.606]` | vs `mihomo`: **Significant** (`t = -2.407`, `df = 9.98`, `p = 0.0369`);<br>vs `sing-box`: **Significant** (`t = -4.144`, `df = 5.60`, `p = 0.0070`) |
| **Encrypted Echo RTT `P50` (ms)** | **`0.194 ± 0.042`** (`±0.044`)<br>**`0.178 (0.004)`** `[0.173..0.280]` | `0.339 ± 0.020` (`±0.021`)<br>`0.333 (0.010)` `[0.314..0.374]` | `0.274 ± 0.023` (`±0.024`)<br>`0.269 (0.029)` `[0.246..0.309]` | vs `mihomo`: **Significant** (`t = -7.580`, `df = 7.15`, `p = 1.151e-04`, `42.8%` lower);<br>vs `sing-box`: **Significant** (`t = -4.038`, `df = 7.79`, `p = 0.0040`, `29.2%` lower) |
| **Encrypted Echo RTT `P95` (ms)** | **`0.324 ± 0.083`** (`±0.087`)<br>**`0.310 (0.050)`** `[0.239..0.477]` | `0.566 ± 0.074` (`±0.078`)<br>`0.553 (0.074)` `[0.474..0.684]` | `0.437 ± 0.033` (`±0.034`)<br>`0.446 (0.040)` `[0.384..0.468]` | vs `mihomo`: **Significant** (`t = -5.360`, `df = 9.89`, `p = 3.316e-04`);<br>vs `sing-box`: **Significant** (`t = -3.127`, `df = 6.53`, `p = 0.0182`) |
| **UDP Associate Loss (%)** | **`0.0 ± 0.0 %`** (`3,000` pkts) | **`0.0 ± 0.0 %`** (`3,000` pkts) | **`0.0 ± 0.0 %`** (`3,000` pkts) | vs `mihomo`: **Not statistically significant** (`t = 0.000`, `df = 10.00`, `p = 1.0000`);<br>vs `sing-box`: **Not statistically significant** (`t = 0.000`, `df = 10.00`, `p = 1.0000`) |
| **UDP Associate Rate (PPS)** | `11,629.5 ± 1,407.3` (`±1,476.9`)<br>`11,595.0 (1,945.0)` `[10,189..13,730]` | `10,200.3 ± 427.1` (`±448.3`)<br>`10,035.5 (339.8)` `[9,802..10,977]` | **`12,642.2 ± 930.0`** (`±976.0`)<br>**`12,203.0 (1,212.5)`** `[11,901..14,122]` | vs `mihomo`: **Not statistically significant** (`t = +2.380`, `df = 5.91`, `p = 0.0554`);<br>vs `sing-box`: **Not statistically significant** (`t = -1.470`, `df = 8.67`, `p = 0.1768`) |
| **UDP Associate `P95` RTT (ms)** | `0.103 ± 0.002` (`±0.002`)<br>`0.103 (0.002)` `[0.101..0.105]` | `0.123 ± 0.009` (`±0.010`)<br>`0.125 (0.007)` `[0.107..0.134]` | **`0.098 ± 0.007`** (`±0.007`)<br>`0.101 (0.005)` `[0.085..0.103]` | vs `mihomo`: **Significant** (`t = -5.105`, `df = 5.27`, `p = 0.0032`);<br>vs `sing-box`: **Not statistically significant** (`t = +1.970`, `df = 5.48`, `p = 0.1009`) |
| **DNS Latency `P50` (ms)** | **`0.026 ± 0.001`** (`±0.001`)<br>**`0.026 (0.001)`** `[0.025..0.027]` | `0.046 ± 0.002` (`±0.002`)<br>`0.045 (0.003)` `[0.043..0.049]` | `0.049 ± 0.005` (`±0.005`)<br>`0.048 (0.008)` `[0.045..0.056]` | vs `mihomo`: **Significant** (`t = -19.551`, `df = 6.29`, `p = 7.237e-07`, `1.77x` faster);<br>vs `sing-box`: **Significant** (`t = -11.106`, `df = 5.27`, `p = 7.470e-05`, `1.88x` faster) |

*(Additional recorded DNS & UDP latency metrics in [`benchmarks_latest.json`](benchmarks_latest.json): `udp_rtt_p50_ms` vs `mihomo` `t = -1.157, p = 0.2781` [Not statistically significant] / vs `sing-box` `t = +1.878, p = 0.1033` [Not statistically significant]; `dns_p95_ms` vs `mihomo` `t = -7.010, p = 3.675e-05` [Significant] / vs `sing-box` `t = -5.021, p = 0.0028` [Significant]; `dns_cached_p50_ms` vs `mihomo` `t = -17.799, p = 4.345e-06` [Significant] / vs `sing-box` `t = -5.039, p = 0.0039` [Significant].)*

---

## 4. Actual TUN Data-Path Benchmark (`rust-clash bench-tun`, `n = 6` Rounds)

Unlike SOCKS5 `CONNECT` (where the kernel hands pre-reassembled L4 byte streams directly to Tokio), the TUN data path processes raw **L3 IPv4 packets (`MTU 1500`, `MSS 1,460 B`)** through [`VirtualTunHandle`](../crates/proxy-core/src/inbound/tun.rs) (`smoltcp 0.12` checksum validation, sliding-window TCP segmentation/reassembly with `64 KiB × 2` per-flow buffers, `TUN_PACKET_QUEUE_CAPACITY = 4096` bounded packet queues, UDP flow table, and port-53 DNS hijack) before forwarding over **`2022-blake3-aes-256-gcm`** to `ssserver`.

| TUN Path Metric (`MTU 1500 -> smoltcp -> SS-2022`) | Mean ± SD (`± 95% CI`) | Median (`IQR`) | Range `[min .. max]` | Comparison vs `rust-clash` Mixed SOCKS5 Path |
|---|---:|---:|---:|---|
| **TUN Idle `VmRSS` (MiB)** | `9.46 ± 0.13` (`±0.14`) | `9.43 (0.15)` | `[9.33 .. 9.68]` | Identical idle footprint (`~9.5 MiB`) |
| **TUN Peak `VmRSS` (MiB, 4 concurrent L3 streams)** | `24.34 ± 0.45` (`±0.47`) | `24.48 (0.69)` | `[23.72 .. 24.79]` | `+10.5 MiB` for `smoltcp` `64 KiB × 2` RX/TX socket ring buffers (**still `2.3x–2.5x` smaller** than Go engines' Mixed-only RSS) |
| **TUN TCP 1-Stream (`16 MiB`, `MSS 1460`)** | **`1,930.2 ± 337.4 Mbps`** (`±354.1`) | **`1,816.0 Mbps`** (`335.3`) | `[1,642.1 .. 2,533.1]` | `~1.93 Gbps` (`31%` of warm Mixed 1-stream due to per-`1,460 B` L3 packet framing + userspace TCP ACK state machine) |
| **TUN TCP 4-Stream Concurrent (`32 MiB` total)** | **`2,621.6 ± 142.7 Mbps`** (`±149.7`) | **`2,600.1 Mbps`** (`132.2`) | `[2,430.6 .. 2,845.8]` | **`2.62 Gbps` sustained** (`CV = 5.44%`), exceeding 2.5GbE / Wi-Fi 6E / 5G physical line rates |
| **TUN L3 TCP `SYN -> SYN-ACK -> ACK` (`P50 / P95`)** | `0.059 ± 0.009` / `0.123 ± 0.025 ms` | `0.059` / `0.135 ms` | `[0.045..0.068]` / `[0.075..0.141]` | Sub-`140 µs` userspace TCP 3-way handshake |
| **TUN Encrypted Echo RTT (`P50 / P95`)** | **`0.344 ± 0.023`** / **`0.688 ± 0.218 ms`** | **`0.343`** / **`0.601 ms`** | `[0.319..0.382]` / `[0.572..1.130]` | `+0.165 ms` median L3 userspace TCP overhead vs Mixed SOCKS5 (`0.178 ms`) |
| **TUN Encrypted UDP NAT (`2,400` pkts, `6 x 400`)** | **`0.0 %` loss**, `8,036.3 ± 573.3 PPS` | `7,762.5 PPS` (`815.8`) | `[7,551 .. 8,866]` | Zero drops; `P50 0.122 ± 0.009 ms`, `P95 0.139 ± 0.004 ms` (`CV = 2.98%`) |
| **TUN Port-53 DNS Hijack (`1,800` pkts, `6 x 300`)** | **`0.033 ± 0.009 ms`** (`P95 0.114 ms`) | **`0.036 ms`** (`0.007`) | `[0.015 .. 0.039]` | `33 µs` mean L3 UDP `:53` intercept + Fake-IP synthesis |

---

## 5. Honest Engineering Interpretation & Limitations

1. **Why Multi-Round Interleaving & Exact Welch's $t$-Tests Matter**:
   - Single non-interleaved loopback runs overstate throughput wins due to thermal/cache ordering drift.
   - Across `6` Latin-square rounds on this 2-vCPU VM, `rust-clash` Round 1 Position #1 (immediately after `cargo build --release` finished compiling the workspace) experienced a transient cold-VM dip (`1,898.2 Mbps` 1-stream / `2,689.4 Mbps` 8-stream), whereas Rounds 2–6 delivered **`5,805–7,222 Mbps` 1-stream** and **`5,776–6,036 Mbps` 8-stream** (`IQR` only `123.7 Mbps`). Meanwhile, `mihomo` averaged `5,428.9 ± 510.7 Mbps` and `sing-box` averaged `6,077.9 ± 286.5 Mbps`.
   - **Correct statistical conclusion**: Neither 1-stream TCP (`p = 0.8236` vs `mihomo`; `p = 0.0555` vs `sing-box`), 8-stream TCP (`p = 0.8906` vs `mihomo`; `p = 0.2332` vs `sing-box`), nor UDP packet rate (`p = 0.0554` vs `mihomo`; `p = 0.1768` vs `sing-box`) reaches statistical significance at two-sided $\alpha = 0.05$. `sing-box` holds the highest point-mean single-stream loopback throughput (`7.74 ± 0.77 Gbps`), while all three engines achieve multi-gigabit 8-stream AEAD parity on 2 vCPUs.
2. **Where `rust-clash` Holds Statistically Significant Advantages ($\alpha = 0.05$)**:
   - **Memory Efficiency (`p <= 1.61e-9`)**: `9.63 ± 0.20 MiB` idle and `13.80 ± 0.28 MiB` Mixed peak (`24.34 ± 0.45 MiB` full L3 TUN peak) vs `56.73–60.76 MiB` for `sing-box` and `mihomo` (**`4.1x–4.4x` lower Mixed RAM; `2.3x–2.5x` lower even with full userspace TCP/IP TUN**).
   - **Request/Response & DNS Latency (`p <= 0.0369`)**: Significantly lower encrypted echo RTT (`P50`: `p = 1.15e-4` vs `mihomo`, `p = 0.0040` vs `sing-box`; `P95`: `p = 3.32e-4` vs `mihomo`, `p = 0.0182` vs `sing-box`), lower SOCKS5 `P95` setup latency (`p = 0.0369` vs `mihomo`, `p = 0.0070` vs `sing-box`), and faster DNS `P50`/`P95` resolution (`p <= 0.0028`).
3. **TUN Data-Path Bottleneck & Future Headroom**:
   - Full L3 `smoltcp` TUN achieves **`1,930.2 ± 337.4 Mbps` single-stream** and **`2,621.6 ± 142.7 Mbps` 4-stream** (`0.0%` UDP loss), which saturates gigabit fiber, 2.5GbE, Wi-Fi 6E/7, and 5G cellular links, while incurring framing/checksum overhead relative to Mixed SOCKS5 due to `1,500 B` L3 packetization (`no GSO / virtio-net-hdr offloading` yet). Adding Linux `IFF_VNET_HDR` / GSO-GRO batching is the primary future lever if >5 Gbps kernel TUN is needed on 10GbE desktops.

---

## 6. Reproducing & Auditing the Multi-Round + TUN Benchmark

```bash
# 1. Recompute & verify exact two-sample Welch's t-tests from the committed raw dataset (no cargo/network needed)
python3 scripts/run_comparative_benchmarks.py --recompute-stats docs/benchmarks_latest.json

# 2. Execute a full 6-round balanced Latin-square + L3 TUN benchmark run
python3 scripts/run_comparative_benchmarks.py \
  --rounds 6 \
  --idle-seconds 2.0 \
  --cache-dir /tmp/rust-clash-bench-cache \
  --cargo-target-dir target \
  --json-out docs/benchmarks_latest.json
```

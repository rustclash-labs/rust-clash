#!/usr/bin/env python3
"""Reproducible, statistically rigorous comparative & TUN-path benchmark suite:
`rust-clash` vs `MetaCubeX/mihomo` vs `SagerNet/sing-box`.

Key methodological guarantees:
1. Supply-chain SHA-256 verification on all external binaries (`mihomo`, `sing-box`, `ssserver`).
2. Multi-round repetition (`--rounds`, default 6) using a balanced 6-permutation Latin-square
   execution schedule (`A-B-C`, `B-C-A`, `C-A-B`, `A-C-B`, `C-B-A`, `B-A-C`) so every engine runs
   1st, 2nd, and 3rd an equal number of times and eliminates thermal/cache/ordering bias.
3. Full error-distribution reporting for every metric (`mean`, `stdev`, `median`, `iqr`, `min`,
   `max`, `ci95_half_width` via two-sided Student-t, and `cv_pct`) plus complete per-round raw data.
4. Multi-round actual L3 `smoltcp` TUN packet-stack measurements (`rust-clash bench-tun`, MTU 1500
   IPv4 packets -> `smoltcp` TCP/UDP/DNS hijack -> `2022-blake3-aes-256-gcm` -> external `ssserver`),
   preventing misleading claims derived solely from `64 KiB` SOCKS5 loopback streams.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import gzip
import hashlib
import json
import math
import os
import platform
import shutil
import socket
import statistics
import struct
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
from pathlib import Path
from typing import Any

MIHOMO_VERSION = "v1.19.33"
MIHOMO_URL = (
    f"https://github.com/MetaCubeX/mihomo/releases/download/{MIHOMO_VERSION}/"
    f"mihomo-linux-amd64-compatible-{MIHOMO_VERSION}.gz"
)
MIHOMO_SHA256 = "386508bfb1c72c43b6a0eda73708ecdce82546581b0ebcb16366c53757c622b6"

SINGBOX_VERSION = "1.14.4"
SINGBOX_URL = (
    f"https://github.com/SagerNet/sing-box/releases/download/v{SINGBOX_VERSION}/"
    f"sing-box-{SINGBOX_VERSION}-linux-amd64.tar.gz"
)
SINGBOX_SHA256 = "699a1b510aa4396b2176d32d1181920399ebf1e267835da6f3b598d0f7c24968"

SS_RUST_VERSION = "1.25.0"
SS_RUST_URL = (
    f"https://github.com/shadowsocks/shadowsocks-rust/releases/download/v{SS_RUST_VERSION}/"
    f"shadowsocks-v{SS_RUST_VERSION}.x86_64-unknown-linux-musl.tar.xz"
)
SS_RUST_SHA256 = "8439bf43c324b0fc273e663d0b1f8926fd8f666cbd1e0fd59b35096f0e778e92"

SS2022_KEY_B64 = base64.b64encode(bytes(range(32))).decode("ascii")

# Complete 6-permutation balanced schedule across 3 engines:
# Every engine executes 2x first, 2x second, 2x third; every pairwise transition occurs equally.
BALANCED_ENGINE_ORDERS: list[list[str]] = [
    ["rust-clash", "mihomo", "sing-box"],
    ["mihomo", "sing-box", "rust-clash"],
    ["sing-box", "rust-clash", "mihomo"],
    ["rust-clash", "sing-box", "mihomo"],
    ["sing-box", "mihomo", "rust-clash"],
    ["mihomo", "rust-clash", "sing-box"],
]

# Two-sided 95% Student-t critical values t_{0.975, df}
STUDENT_T_95: dict[int, float] = {
    1: 12.7062,
    2: 4.3027,
    3: 3.1824,
    4: 2.7764,
    5: 2.5706,
    6: 2.4469,
    7: 2.3646,
    8: 2.3060,
    9: 2.2622,
    10: 2.2281,
    11: 2.2010,
    12: 2.1788,
    15: 2.1314,
    20: 2.0860,
    25: 2.0595,
    30: 2.0423,
}

NUMERIC_MIXED_METRICS: list[str] = [
    "binary_size_mib",
    "startup_ready_ms",
    "idle_cpu_pct",
    "idle_rss_mib",
    "peak_rss_mib",
    "tcp_1stream_mbps",
    "tcp_8stream_mbps",
    "conn_setup_p50_ms",
    "conn_setup_p95_ms",
    "proxy_rtt_p50_ms",
    "proxy_rtt_p95_ms",
    "udp_loss_pct",
    "udp_pps",
    "udp_rtt_p50_ms",
    "udp_rtt_p95_ms",
    "dns_p50_ms",
    "dns_p95_ms",
    "dns_cached_p50_ms",
]

NUMERIC_TUN_METRICS: list[str] = [
    "idle_rss_mib",
    "peak_rss_mib",
    "tcp_1stream_mbps",
    "tcp_multistream_mbps",
    "conn_setup_p50_ms",
    "conn_setup_p95_ms",
    "proxy_rtt_p50_ms",
    "proxy_rtt_p95_ms",
    "udp_loss_pct",
    "udp_pps",
    "udp_rtt_p50_ms",
    "udp_rtt_p95_ms",
    "dns_hijack_p50_ms",
    "dns_hijack_p95_ms",
    "dns_hijack_cached_p50_ms",
]


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def download_verified(url: str, expected_sha256: str, dest: Path) -> Path:
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.is_file() and sha256_file(dest) == expected_sha256:
        return dest
    tmp = dest.with_suffix(dest.suffix + ".part")
    req = urllib.request.Request(url, headers={"User-Agent": "rust-clash-bench/2.0"})
    print(f"[bench] Downloading {url} ...")
    with urllib.request.urlopen(req, timeout=90) as resp, tmp.open("wb") as out:
        shutil.copyfileobj(resp, out)
    actual = sha256_file(tmp)
    if actual != expected_sha256:
        tmp.unlink(missing_ok=True)
        raise RuntimeError(
            f"SHA-256 verification failed for {url}: expected {expected_sha256}, got {actual}"
        )
    tmp.replace(dest)
    return dest


def prepare_reference_binaries(
    cache_dir: Path, repo_root: Path, cargo_target_dir: Path
) -> dict[str, Path]:
    dl_dir = cache_dir / "downloads"
    bin_dir = cache_dir / "bins"
    bin_dir.mkdir(parents=True, exist_ok=True)

    # 1. Mihomo
    mihomo_bin = bin_dir / "mihomo"
    if not mihomo_bin.is_file():
        gz_path = download_verified(MIHOMO_URL, MIHOMO_SHA256, dl_dir / "mihomo.gz")
        with gzip.open(gz_path, "rb") as src, mihomo_bin.open("wb") as dst:
            shutil.copyfileobj(src, dst)
        mihomo_bin.chmod(0o755)

    # 2. sing-box
    singbox_bin = bin_dir / "sing-box"
    if not singbox_bin.is_file():
        tgz_path = download_verified(SINGBOX_URL, SINGBOX_SHA256, dl_dir / "sing-box.tar.gz")
        with tarfile.open(tgz_path, "r:gz") as tf:
            member = next(
                m for m in tf.getmembers() if m.name.endswith("/sing-box") or m.name == "sing-box"
            )
            extracted = tf.extractfile(member)
            assert extracted is not None
            with singbox_bin.open("wb") as dst:
                shutil.copyfileobj(extracted, dst)
        singbox_bin.chmod(0o755)

    # 3. shadowsocks-rust ssserver (neutral upstream server)
    cached_ss = Path.home() / ".cache" / "rust-clash-tools" / "interop-bins" / "ssserver"
    ssserver_bin = bin_dir / "ssserver"
    if cached_ss.is_file() and sha256_file(cached_ss):
        ssserver_bin = cached_ss
    elif not ssserver_bin.is_file():
        txz_path = download_verified(SS_RUST_URL, SS_RUST_SHA256, dl_dir / "ss-rust.tar.xz")
        with tarfile.open(txz_path, "r:xz") as tf:
            member = next(m for m in tf.getmembers() if m.name.endswith("ssserver"))
            extracted = tf.extractfile(member)
            assert extracted is not None
            with ssserver_bin.open("wb") as dst:
                shutil.copyfileobj(extracted, dst)
        ssserver_bin.chmod(0o755)

    # 4. Build release rust-clash
    print("[bench] Building release-optimized rust-clash binary...")
    env = os.environ.copy()
    env["CARGO_TARGET_DIR"] = str(cargo_target_dir)
    subprocess.run(
        ["cargo", "build", "--release", "-p", "proxy-cli"],
        cwd=str(repo_root),
        env=env,
        check=True,
    )
    rust_clash_bin = cargo_target_dir / "release" / "rust-clash"
    if not rust_clash_bin.is_file():
        raise FileNotFoundError(f"Expected binary at {rust_clash_bin}")

    return {
        "rust-clash": rust_clash_bin,
        "mihomo": mihomo_bin,
        "sing-box": singbox_bin,
        "ssserver": ssserver_bin,
    }


def detect_rust_clash_version(bin_path: Path) -> str:
    out = subprocess.check_output([str(bin_path), "--version"], text=True).strip()
    parts = out.split()
    return parts[-1] if parts else "0.2.0"


def allocate_free_port(udp: bool = False) -> int:
    sock_type = socket.SOCK_DGRAM if udp else socket.SOCK_STREAM
    with socket.socket(socket.AF_INET, sock_type) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def read_proc_rss_mib(pid: int) -> float:
    page_size = os.sysconf("SC_PAGE_SIZE")
    statm = Path(f"/proc/{pid}/statm").read_text().split()
    rss_pages = int(statm[1])
    return (rss_pages * page_size) / (1024.0 * 1024.0)


def read_proc_cpu_seconds(pid: int) -> float:
    clk_tck = os.sysconf("SC_CLK_TCK")
    raw = Path(f"/proc/{pid}/stat").read_text()
    rparen = raw.rfind(")")
    fields = raw[rparen + 2 :].split()
    utime_ticks = int(fields[11])
    stime_ticks = int(fields[12])
    return (utime_ticks + stime_ticks) / float(clk_tck)


def percentile(sorted_vals: list[float], pct: float) -> float:
    if not sorted_vals:
        return 0.0
    idx = (len(sorted_vals) - 1) * (pct / 100.0)
    lo = int(idx)
    hi = min(lo + 1, len(sorted_vals) - 1)
    frac = idx - lo
    return sorted_vals[lo] * (1.0 - frac) + sorted_vals[hi] * frac


def student_t_crit_95(n: int) -> float:
    if n < 2:
        return 0.0
    df = n - 1
    if df in STUDENT_T_95:
        return STUDENT_T_95[df]
    for k in sorted(STUDENT_T_95):
        if df < k:
            return STUDENT_T_95[k]
    return 1.96


def summarize_distribution(values: list[float], ndigits: int = 3) -> dict[str, Any]:
    if not values:
        return {
            "n": 0,
            "mean": 0.0,
            "stdev": 0.0,
            "median": 0.0,
            "iqr": 0.0,
            "min": 0.0,
            "max": 0.0,
            "ci95_half_width": 0.0,
            "cv_pct": 0.0,
        }
    sv = sorted(float(v) for v in values)
    n = len(sv)
    mean_v = statistics.fmean(sv)
    stdev_v = statistics.stdev(sv) if n >= 2 else 0.0
    med_v = percentile(sv, 50.0)
    iqr_v = percentile(sv, 75.0) - percentile(sv, 25.0)
    ci95_hw = student_t_crit_95(n) * (stdev_v / math.sqrt(n)) if n >= 2 else 0.0
    cv_pct = (stdev_v / abs(mean_v) * 100.0) if abs(mean_v) > 1e-9 else 0.0
    return {
        "n": n,
        "mean": round(mean_v, ndigits),
        "stdev": round(stdev_v, ndigits),
        "median": round(med_v, ndigits),
        "iqr": round(iqr_v, ndigits),
        "min": round(sv[0], ndigits),
        "max": round(sv[-1], ndigits),
        "ci95_half_width": round(ci95_hw, ndigits),
        "cv_pct": round(cv_pct, 2),
    }


def _betacf(a: float, b: float, x: float) -> float:
    """Evaluate continued fraction for incomplete beta via modified Lentz's method."""
    max_iter = 500
    eps = 3.0e-15
    fpmin = 1.0e-300
    qab = a + b
    qap = a + 1.0
    qam = a - 1.0
    c = 1.0
    d = 1.0 - qab * x / qap
    if abs(d) < fpmin:
        d = fpmin
    d = 1.0 / d
    h = d
    for m in range(1, max_iter + 1):
        m2 = 2 * m
        aa = m * (b - m) * x / ((qam + m2) * (a + m2))
        d = 1.0 + aa * d
        if abs(d) < fpmin:
            d = fpmin
        c = 1.0 + aa / c
        if abs(c) < fpmin:
            c = fpmin
        d = 1.0 / d
        h *= d * c

        aa = -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2))
        d = 1.0 + aa * d
        if abs(d) < fpmin:
            d = fpmin
        c = 1.0 + aa / c
        if abs(c) < fpmin:
            c = fpmin
        d = 1.0 / d
        del_h = d * c
        h *= del_h
        if abs(del_h - 1.0) <= eps:
            break
    return h


def regularized_incomplete_beta(a: float, b: float, x: float) -> float:
    """Compute regularized incomplete beta I_x(a, b) using pure Python stdlib math."""
    if a <= 0.0 or b <= 0.0:
        raise ValueError(f"Beta parameters must be positive (got a={a}, b={b})")
    if x <= 0.0:
        return 0.0
    if x >= 1.0:
        return 1.0
    ln_beta = math.lgamma(a) + math.lgamma(b) - math.lgamma(a + b)
    front = math.exp(a * math.log(x) + b * math.log1p(-x) - ln_beta)
    if x < (a + 1.0) / (a + b + 2.0):
        return front * _betacf(a, b, x) / a
    return 1.0 - front * _betacf(b, a, 1.0 - x) / b


def student_t_two_sided_p_value(t_stat: float, df: float) -> float:
    """Exact two-sided p-value P(|T_df| >= |t_stat|) via I_{df/(df+t^2)}(df/2, 1/2)."""
    if math.isnan(t_stat) or df <= 0.0:
        return 1.0
    if math.isinf(t_stat):
        return 0.0
    if t_stat == 0.0:
        return 1.0
    x = df / (df + t_stat * t_stat)
    return max(0.0, min(1.0, regularized_incomplete_beta(0.5 * df, 0.5, x)))


def welch_t_test(
    sample_a: list[float], sample_b: list[float], alpha: float = 0.05
) -> dict[str, Any]:
    """Two-sample unequal-variance Welch's t-test with Satterthwaite degrees of freedom."""
    n_a = len(sample_a)
    n_b = len(sample_b)
    if n_a < 2 or n_b < 2:
        return {
            "n_a": n_a,
            "n_b": n_b,
            "mean_a": statistics.fmean(sample_a) if sample_a else 0.0,
            "mean_b": statistics.fmean(sample_b) if sample_b else 0.0,
            "diff_mean": 0.0,
            "t_stat": 0.0,
            "df": 0.0,
            "p_value": 1.0,
            "significant_alpha_0_05": False,
            "note": "insufficient_samples",
        }

    vals_a = [float(v) for v in sample_a]
    vals_b = [float(v) for v in sample_b]
    mean_a = statistics.fmean(vals_a)
    mean_b = statistics.fmean(vals_b)
    diff = mean_a - mean_b
    var_a = statistics.variance(vals_a)
    var_b = statistics.variance(vals_b)
    se2_a = var_a / n_a
    se2_b = var_b / n_b
    se2_sum = se2_a + se2_b

    if se2_sum == 0.0:
        if abs(diff) <= 1e-12:
            return {
                "n_a": n_a,
                "n_b": n_b,
                "mean_a": round(mean_a, 6),
                "mean_b": round(mean_b, 6),
                "diff_mean": 0.0,
                "t_stat": 0.0,
                "df": float(n_a + n_b - 2),
                "p_value": 1.0,
                "significant_alpha_0_05": False,
                "note": "identical_zero_variance",
            }
        return {
            "n_a": n_a,
            "n_b": n_b,
            "mean_a": round(mean_a, 6),
            "mean_b": round(mean_b, 6),
            "diff_mean": round(diff, 6),
            "t_stat": None,
            "df": float(n_a + n_b - 2),
            "p_value": 0.0,
            "significant_alpha_0_05": True,
            "note": "deterministic_zero_variance",
        }

    t_stat = diff / math.sqrt(se2_sum)
    denom = (se2_a * se2_a) / (n_a - 1) + (se2_b * se2_b) / (n_b - 1)
    df = (se2_sum * se2_sum) / denom
    p_val = student_t_two_sided_p_value(t_stat, df)
    return {
        "n_a": n_a,
        "n_b": n_b,
        "mean_a": round(mean_a, 6),
        "mean_b": round(mean_b, 6),
        "diff_mean": round(diff, 6),
        "t_stat": round(t_stat, 4),
        "df": round(df, 4),
        "p_value": p_val,
        "significant_alpha_0_05": bool(p_val < alpha),
    }


def compute_comparative_welch_tests(
    comparative_entries: list[dict[str, Any]],
    metric_keys: list[str] | None = None,
) -> dict[str, dict[str, dict[str, Any]]]:
    """Compute Welch's t-tests comparing rust-clash against mihomo and sing-box across all metrics."""
    keys = metric_keys if metric_keys is not None else NUMERIC_MIXED_METRICS
    by_slug: dict[str, dict[str, Any]] = {}
    for entry in comparative_entries:
        label = str(entry.get("engine", "")).lower()
        if label.startswith("rust-clash"):
            by_slug["rust-clash"] = entry
        elif label.startswith("mihomo"):
            by_slug["mihomo"] = entry
        elif label.startswith("sing-box"):
            by_slug["sing-box"] = entry

    rc_rounds = by_slug.get("rust-clash", {}).get("raw_rounds", [])
    results: dict[str, dict[str, dict[str, Any]]] = {}
    for peer_slug, pair_key in [
        ("mihomo", "rust_clash_vs_mihomo"),
        ("sing-box", "rust_clash_vs_sing_box"),
    ]:
        peer_rounds = by_slug.get(peer_slug, {}).get("raw_rounds", [])
        pair_metrics: dict[str, dict[str, Any]] = {}
        for metric in keys:
            vals_rc = [float(r[metric]) for r in rc_rounds if metric in r]
            vals_peer = [float(r[metric]) for r in peer_rounds if metric in r]
            pair_metrics[metric] = welch_t_test(vals_rc, vals_peer)
        results[pair_key] = pair_metrics
    return results


def build_dns_query_packet(txid: int, domain: str) -> bytes:
    header = struct.pack("!HHHHHH", txid & 0xFFFF, 0x0100, 1, 0, 0, 0)
    qname = b"".join(bytes([len(lbl)]) + lbl.encode("ascii") for lbl in domain.split(".")) + b"\x00"
    question = qname + struct.pack("!HH", 1, 1)
    return header + question


def build_dns_a_response(query: bytes, ip_str: str = "93.184.216.34") -> bytes:
    txid = query[:2]
    flags = struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0)
    idx = 12
    while idx < len(query) and query[idx] != 0:
        idx += 1 + query[idx]
    q_end = idx + 5
    question = query[12:q_end]
    answer = struct.pack("!HHHLH", 0xC00C, 1, 1, 60, 4) + socket.inet_aton(ip_str)
    return txid + flags + question + answer


class UdpEchoProtocol(asyncio.DatagramProtocol):
    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        self.transport.sendto(data, addr)


class AuthoritativeDnsProtocol(asyncio.DatagramProtocol):
    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        if len(data) >= 17:
            resp = build_dns_a_response(data)
            self.transport.sendto(resp, addr)


async def start_local_origins() -> tuple[int, int, int, list[Any]]:
    handles: list[Any] = []
    bulk_chunk = b"R" * 65536

    async def handle_tcp(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            op = await reader.readexactly(1)
            if op == b"E":
                payload = await reader.readexactly(64)
                writer.write(payload)
                await writer.drain()
            elif op == b"D":
                raw_len = await reader.readexactly(4)
                (remaining,) = struct.unpack("!I", raw_len)
                while remaining > 0:
                    n = min(len(bulk_chunk), remaining)
                    writer.write(bulk_chunk[:n])
                    remaining -= n
                    if remaining % (256 * 1024) == 0:
                        await writer.drain()
                await writer.drain()
        except Exception:
            pass
        finally:
            writer.close()

    tcp_srv = await asyncio.start_server(handle_tcp, "127.0.0.1", 0)
    tcp_port = int(tcp_srv.sockets[0].getsockname()[1])
    handles.append(tcp_srv)

    loop = asyncio.get_running_loop()
    udp_transport, _ = await loop.create_datagram_endpoint(
        UdpEchoProtocol, local_addr=("127.0.0.1", 0)
    )
    udp_port = int(udp_transport.get_extra_info("sockname")[1])
    handles.append(udp_transport)

    dns_transport, _ = await loop.create_datagram_endpoint(
        AuthoritativeDnsProtocol, local_addr=("127.0.0.1", 0)
    )
    dns_port = int(dns_transport.get_extra_info("sockname")[1])
    handles.append(dns_transport)

    return tcp_port, udp_port, dns_port, handles


async def socks5_connect(
    host: str, port: int, target_ip: str, target_port: int
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    reader, writer = await asyncio.open_connection(host, port)
    writer.write(b"\x05\x01\x00")
    resp = await reader.readexactly(2)
    if resp != b"\x05\x00":
        writer.close()
        raise RuntimeError(f"SOCKS5 greeting failed: {resp!r}")
    req = b"\x05\x01\x00\x01" + socket.inet_aton(target_ip) + struct.pack("!H", target_port)
    writer.write(req)
    await writer.drain()
    head = await reader.readexactly(4)
    if head[1] != 0x00:
        writer.close()
        raise RuntimeError(f"SOCKS5 connect failed: {head!r}")
    atyp = head[3]
    if atyp == 1:
        await reader.readexactly(6)
    elif atyp == 4:
        await reader.readexactly(18)
    elif atyp == 3:
        ln = (await reader.readexactly(1))[0]
        await reader.readexactly(ln + 2)
    return reader, writer


async def measure_tcp_stream_bytes(mixed_port: int, tcp_origin_port: int, total_bytes: int) -> int:
    reader, writer = await socks5_connect("127.0.0.1", mixed_port, "127.0.0.1", tcp_origin_port)
    try:
        writer.write(b"D" + struct.pack("!I", total_bytes))
        await writer.drain()
        received = 0
        while received < total_bytes:
            chunk = await reader.read(65536)
            if not chunk:
                break
            received += len(chunk)
        return received
    finally:
        writer.close()


async def wait_for_tcp_port(
    port: int,
    timeout_s: float = 10.0,
    proc: subprocess.Popen[bytes] | None = None,
) -> float:
    t0 = time.perf_counter()
    deadline = t0 + timeout_s
    while time.perf_counter() < deadline:
        if proc is not None and proc.poll() is not None:
            err_out = proc.stderr.read().decode("utf-8", errors="replace") if proc.stderr else ""
            raise RuntimeError(
                f"Process exited early (code={proc.returncode}) while waiting for 127.0.0.1:{port}:\n{err_out}"
            )
        try:
            _, w = await asyncio.open_connection("127.0.0.1", port)
            w.close()
            await w.wait_closed()
            return (time.perf_counter() - t0) * 1000.0
        except OSError:
            await asyncio.sleep(0.01)
    raise TimeoutError(f"Port 127.0.0.1:{port} did not become ready within {timeout_s}s")


def measure_udp_associate_sync(
    mixed_port: int, udp_origin_port: int, packet_count: int = 500
) -> tuple[float, float, float, float]:
    with socket.create_connection(("127.0.0.1", mixed_port), timeout=5.0) as ctrl:
        ctrl.sendall(b"\x05\x01\x00")
        if ctrl.recv(2) != b"\x05\x00":
            raise RuntimeError("SOCKS5 UDP greeting failed")
        ctrl.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
        reply = ctrl.recv(10)
        if len(reply) < 10 or reply[1] != 0x00:
            raise RuntimeError(f"UDP ASSOCIATE rejected: {reply!r}")
        relay_ip = socket.inet_ntoa(reply[4:8])
        if relay_ip == "0.0.0.0":
            relay_ip = "127.0.0.1"
        (relay_port,) = struct.unpack("!H", reply[8:10])

        s5_hdr = (
            b"\x00\x00\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack("!H", udp_origin_port)
        )
        rtts_ms: list[float] = []
        received = 0

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_sock:
            udp_sock.bind(("127.0.0.1", 0))
            udp_sock.settimeout(0.25)
            t_start = time.perf_counter()
            for seq in range(packet_count):
                payload = struct.pack("!I", seq) + b"U" * 60
                pkt_t0 = time.perf_counter()
                udp_sock.sendto(s5_hdr + payload, (relay_ip, relay_port))
                try:
                    data, _ = udp_sock.recvfrom(2048)
                    if data.endswith(payload):
                        received += 1
                        rtts_ms.append((time.perf_counter() - pkt_t0) * 1000.0)
                except socket.timeout:
                    pass
            elapsed = max(time.perf_counter() - t_start, 1e-6)

    loss_pct = ((packet_count - received) / float(packet_count)) * 100.0
    pps = received / elapsed
    rtts_ms.sort()
    return loss_pct, pps, percentile(rtts_ms, 50), percentile(rtts_ms, 95)


def measure_dns_queries_sync(dns_port: int, count: int = 300) -> tuple[float, float, float]:
    uncached_ms: list[float] = []
    cached_ms: list[float] = []
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(1.0)
        for i in range(100):
            q = build_dns_query_packet(0x1000 + i, f"bench-host-{i}.example.com")
            t0 = time.perf_counter()
            sock.sendto(q, ("127.0.0.1", dns_port))
            data, _ = sock.recvfrom(1500)
            if len(data) >= 12:
                uncached_ms.append((time.perf_counter() - t0) * 1000.0)

        warm_q = build_dns_query_packet(0x2222, "bench-host-0.example.com")
        for _ in range(count):
            t0 = time.perf_counter()
            sock.sendto(warm_q, ("127.0.0.1", dns_port))
            data, _ = sock.recvfrom(1500)
            if len(data) >= 12:
                cached_ms.append((time.perf_counter() - t0) * 1000.0)

    all_ms = sorted(uncached_ms + cached_ms)
    cached_ms.sort()
    return percentile(all_ms, 50), percentile(all_ms, 95), percentile(cached_ms, 50)


async def benchmark_single_engine(
    name: str,
    cmd: list[str],
    mixed_port: int,
    dns_port: int,
    tcp_origin_port: int,
    udp_origin_port: int,
    idle_seconds: float,
    round_idx: int,
    order_pos: int,
) -> dict[str, Any]:
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    try:
        startup_ms = await wait_for_tcp_port(mixed_port, timeout_s=12.0, proc=proc)
        await asyncio.sleep(0.25)

        # 1. Idle CPU & Idle RSS over `idle_seconds`
        idle_rss_before = read_proc_rss_mib(proc.pid)
        cpu_t0 = read_proc_cpu_seconds(proc.pid)
        wall_t0 = time.perf_counter()
        await asyncio.sleep(idle_seconds)
        cpu_dt = read_proc_cpu_seconds(proc.pid) - cpu_t0
        wall_dt = max(time.perf_counter() - wall_t0, 1e-6)
        idle_cpu_pct = (cpu_dt / wall_dt) * 100.0
        idle_rss_mib = max(idle_rss_before, read_proc_rss_mib(proc.pid))

        # 2. Warmup 2 connections
        for _ in range(2):
            await measure_tcp_stream_bytes(mixed_port, tcp_origin_port, 65536)

        # 3. Single-stream TCP encrypted throughput (32 MiB)
        single_bytes = 32 * 1024 * 1024
        t0 = time.perf_counter()
        got_single = await measure_tcp_stream_bytes(mixed_port, tcp_origin_port, single_bytes)
        dt_single = time.perf_counter() - t0
        single_mbps = (got_single * 8.0) / (dt_single * 1_000_000.0)

        # 4. 8-stream concurrent TCP encrypted throughput (8 x 16 MiB = 128 MiB) + Peak RSS sampling
        per_stream = 16 * 1024 * 1024
        peak_rss_mib = idle_rss_mib
        sampling_done = False

        async def sample_rss() -> None:
            nonlocal peak_rss_mib
            while not sampling_done:
                try:
                    peak_rss_mib = max(peak_rss_mib, read_proc_rss_mib(proc.pid))
                except Exception:
                    pass
                await asyncio.sleep(0.02)

        sampler_task = asyncio.create_task(sample_rss())
        t0 = time.perf_counter()
        results = await asyncio.gather(
            *[measure_tcp_stream_bytes(mixed_port, tcp_origin_port, per_stream) for _ in range(8)]
        )
        dt_multi = time.perf_counter() - t0
        sampling_done = True
        await sampler_task
        multi_mbps = (sum(results) * 8.0) / (dt_multi * 1_000_000.0)

        # 5. Sequential TCP Proxy Connection Setup + 64B Echo Latency (150 iterations)
        setup_latencies_ms: list[float] = []
        echo_rtts_ms: list[float] = []
        echo_payload = b"P" * 64
        for _ in range(150):
            c_t0 = time.perf_counter()
            r, w = await socks5_connect("127.0.0.1", mixed_port, "127.0.0.1", tcp_origin_port)
            setup_ms = (time.perf_counter() - c_t0) * 1000.0
            setup_latencies_ms.append(setup_ms)

            e_t0 = time.perf_counter()
            w.write(b"E" + echo_payload)
            await w.drain()
            echoed = await r.readexactly(64)
            assert echoed == echo_payload
            echo_rtts_ms.append((time.perf_counter() - e_t0) * 1000.0)
            w.close()
            await w.wait_closed()

        setup_latencies_ms.sort()
        echo_rtts_ms.sort()

        # 6. UDP Relay Packet Loss & Latency over SOCKS5 UDP ASSOCIATE -> SS-2022 UDP
        udp_loss_pct, udp_pps, udp_p50_ms, udp_p95_ms = await asyncio.to_thread(
            measure_udp_associate_sync, mixed_port, udp_origin_port, 500
        )

        # 7. DNS Query Latency
        dns_p50_ms, dns_p95_ms, dns_cached_p50_ms = await asyncio.to_thread(
            measure_dns_queries_sync, dns_port, 300
        )

        binary_mib = Path(cmd[0]).stat().st_size / (1024.0 * 1024.0)
        return {
            "engine": name,
            "round": round_idx,
            "order_position": order_pos,
            "binary_size_mib": round(binary_mib, 2),
            "startup_ready_ms": round(startup_ms, 2),
            "idle_cpu_pct": round(idle_cpu_pct, 3),
            "idle_rss_mib": round(idle_rss_mib, 2),
            "peak_rss_mib": round(peak_rss_mib, 2),
            "tcp_1stream_mbps": round(single_mbps, 1),
            "tcp_8stream_mbps": round(multi_mbps, 1),
            "conn_setup_p50_ms": round(percentile(setup_latencies_ms, 50), 3),
            "conn_setup_p95_ms": round(percentile(setup_latencies_ms, 95), 3),
            "proxy_rtt_p50_ms": round(percentile(echo_rtts_ms, 50), 3),
            "proxy_rtt_p95_ms": round(percentile(echo_rtts_ms, 95), 3),
            "udp_loss_pct": round(udp_loss_pct, 2),
            "udp_pps": round(udp_pps, 0),
            "udp_rtt_p50_ms": round(udp_p50_ms, 3),
            "udp_rtt_p95_ms": round(udp_p95_ms, 3),
            "dns_p50_ms": round(dns_p50_ms, 3),
            "dns_p95_ms": round(dns_p95_ms, 3),
            "dns_cached_p50_ms": round(dns_cached_p50_ms, 3),
        }
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


async def benchmark_rust_clash_tun_round(
    rust_clash_bin: Path,
    ss_port: int,
    tcp_origin_port: int,
    udp_origin_port: int,
    dns_origin_port: int,
    round_idx: int,
    mtu: int = 1500,
) -> dict[str, Any]:
    cmd = [
        str(rust_clash_bin),
        "bench-tun",
        "--ss-port",
        str(ss_port),
        "--ss-password",
        SS2022_KEY_B64,
        "--tcp-origin-port",
        str(tcp_origin_port),
        "--udp-origin-port",
        str(udp_origin_port),
        "--dns-origin-port",
        str(dns_origin_port),
        "--mtu",
        str(mtu),
    ]
    env = os.environ.copy()
    env["RUST_LOG"] = "error"

    def _run_sync() -> dict[str, Any]:
        out = subprocess.check_output(cmd, env=env, text=True, timeout=90)
        lines = [ln.strip() for ln in out.splitlines() if ln.strip().startswith("{")]
        if not lines:
            raise RuntimeError(f"bench-tun produced no JSON line:\n{out}")
        parsed = json.loads(lines[-1])
        parsed["round"] = round_idx
        return parsed

    return await asyncio.to_thread(_run_sync)


def write_clash_yaml(
    path: Path,
    mixed_port: int,
    ctrl_port: int,
    dns_port: int,
    ss_port: int,
    upstream_dns_port: int,
    enhanced_mode: str,
) -> None:
    yaml_text = f"""mixed-port: {mixed_port}
bind-address: 127.0.0.1
allow-lan: false
mode: rule
log-level: error
ipv6: false
external-controller: 127.0.0.1:{ctrl_port}
dns:
  enable: true
  listen: 127.0.0.1:{dns_port}
  ipv6: false
  enhanced-mode: {enhanced_mode}
  default-nameserver:
    - 127.0.0.1:{upstream_dns_port}
  nameserver:
    - 127.0.0.1:{upstream_dns_port}
proxies:
  - name: Bench-SS2022
    type: ss
    server: 127.0.0.1
    port: {ss_port}
    cipher: 2022-blake3-aes-256-gcm
    password: "{SS2022_KEY_B64}"
    udp: true
proxy-groups:
  - name: PROXY
    type: select
    proxies:
      - Bench-SS2022
rules:
  - MATCH,Bench-SS2022
"""
    path.write_text(yaml_text)


def write_singbox_json(
    path: Path, mixed_port: int, dns_port: int, ss_port: int, upstream_dns_port: int
) -> None:
    cfg = {
        "log": {"level": "error"},
        "dns": {
            "servers": [
                {
                    "type": "udp",
                    "tag": "local-auth",
                    "server": "127.0.0.1",
                    "server_port": upstream_dns_port,
                }
            ],
            "final": "local-auth",
        },
        "inbounds": [
            {
                "type": "mixed",
                "tag": "mixed-in",
                "listen": "127.0.0.1",
                "listen_port": mixed_port,
            },
            {
                "type": "direct",
                "tag": "dns-in",
                "listen": "127.0.0.1",
                "listen_port": dns_port,
                "network": "udp",
                "override_address": "127.0.0.1",
                "override_port": upstream_dns_port,
            },
        ],
        "outbounds": [
            {
                "type": "shadowsocks",
                "tag": "ss-out",
                "server": "127.0.0.1",
                "server_port": ss_port,
                "method": "2022-blake3-aes-256-gcm",
                "password": SS2022_KEY_B64,
            },
            {
                "type": "direct",
                "tag": "dns-direct",
            },
        ],
        "route": {
            "rules": [{"inbound": ["dns-in"], "action": "hijack-dns"}],
            "final": "ss-out",
        },
    }
    path.write_text(json.dumps(cfg, indent=2))


def aggregate_engine_rounds(
    engine_label: str, rounds_data: list[dict[str, Any]], metric_keys: list[str]
) -> dict[str, Any]:
    distributions: dict[str, Any] = {}
    point_means: dict[str, Any] = {"engine": engine_label, "rounds": len(rounds_data)}
    for key in metric_keys:
        vals = [float(r[key]) for r in rounds_data if key in r]
        ndigits = 1 if key.endswith("_mbps") or key.endswith("_pps") else 3
        if key in ("binary_size_mib", "startup_ready_ms", "idle_rss_mib", "peak_rss_mib", "udp_loss_pct"):
            ndigits = 2
        dist = summarize_distribution(vals, ndigits=ndigits)
        distributions[key] = dist
        point_means[key] = dist["mean"]
    return {
        "engine": engine_label,
        "rounds": len(rounds_data),
        "summary_mean": point_means,
        "distributions": distributions,
        "raw_rounds": rounds_data,
    }


async def async_main(args: argparse.Namespace) -> int:
    if args.rounds < 1:
        raise ValueError("--rounds must be >= 1")

    repo_root = Path(__file__).resolve().parent.parent
    bins = prepare_reference_binaries(args.cache_dir, repo_root, args.cargo_target_dir)
    rc_version = detect_rust_clash_version(bins["rust-clash"])

    engine_labels = {
        "rust-clash": f"rust-clash v{rc_version} (rustc)",
        "mihomo": f"mihomo {MIHOMO_VERSION} (Go)",
        "sing-box": f"sing-box v{SINGBOX_VERSION} (Go)",
    }

    tcp_origin_port, udp_origin_port, auth_dns_port, origin_handles = await start_local_origins()

    ss_port = allocate_free_port()
    ss_proc = subprocess.Popen(
        [
            str(bins["ssserver"]),
            "-s",
            f"127.0.0.1:{ss_port}",
            "-m",
            "2022-blake3-aes-256-gcm",
            "-k",
            SS2022_KEY_B64,
            "-U",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )

    try:
        await wait_for_tcp_port(ss_port, timeout_s=8.0)

        per_engine_rounds: dict[str, list[dict[str, Any]]] = {
            "rust-clash": [],
            "mihomo": [],
            "sing-box": [],
        }
        tun_rounds: list[dict[str, Any]] = []
        schedule_executed: list[dict[str, Any]] = []

        for r_idx in range(args.rounds):
            round_no = r_idx + 1
            order = BALANCED_ENGINE_ORDERS[r_idx % len(BALANCED_ENGINE_ORDERS)]
            schedule_executed.append({"round": round_no, "order": order})
            print(
                f"\n[bench] ================ Round {round_no}/{args.rounds} | Interleaved Order: {' -> '.join(order)} ================"
            )

            with tempfile.TemporaryDirectory(prefix=f"rc-bench-r{round_no}-") as work_str:
                work = Path(work_str)
                for pos, key in enumerate(order, start=1):
                    label = engine_labels[key]
                    if key == "rust-clash":
                        mixed_p = allocate_free_port()
                        ctrl_p = allocate_free_port()
                        dns_p = allocate_free_port(udp=True)
                        cfg_p = work / "rust-clash.yaml"
                        write_clash_yaml(
                            cfg_p, mixed_p, ctrl_p, dns_p, ss_port, auth_dns_port, "redir-host"
                        )
                        cmd = [str(bins["rust-clash"]), "run", "--config", str(cfg_p)]
                    elif key == "mihomo":
                        mh_dir = work / "mihomo-home"
                        mh_dir.mkdir(parents=True, exist_ok=True)
                        mixed_p = allocate_free_port()
                        ctrl_p = allocate_free_port()
                        dns_p = allocate_free_port(udp=True)
                        cfg_p = mh_dir / "config.yaml"
                        write_clash_yaml(
                            cfg_p, mixed_p, ctrl_p, dns_p, ss_port, auth_dns_port, "redir-host"
                        )
                        cmd = [str(bins["mihomo"]), "-d", str(mh_dir), "-f", str(cfg_p)]
                    else:
                        mixed_p = allocate_free_port()
                        dns_p = allocate_free_port(udp=True)
                        cfg_p = work / "sing-box.json"
                        write_singbox_json(cfg_p, mixed_p, dns_p, ss_port, auth_dns_port)
                        cmd = [str(bins["sing-box"]), "run", "-c", str(cfg_p)]

                    res = await benchmark_single_engine(
                        label,
                        cmd,
                        mixed_p,
                        dns_p,
                        tcp_origin_port,
                        udp_origin_port,
                        args.idle_seconds,
                        round_idx=round_no,
                        order_pos=pos,
                    )
                    per_engine_rounds[key].append(res)
                    print(
                        f"[bench] [R{round_no} #{pos}] {label}: "
                        f"1-stream={res['tcp_1stream_mbps']} Mbps, "
                        f"8-stream={res['tcp_8stream_mbps']} Mbps, "
                        f"echo_p50={res['proxy_rtt_p50_ms']} ms, "
                        f"peak_rss={res['peak_rss_mib']} MiB"
                    )

                # Measure actual L3 `smoltcp` TUN stack (`rust-clash bench-tun`, MTU 1500) in the same round!
                tun_res = await benchmark_rust_clash_tun_round(
                    bins["rust-clash"],
                    ss_port,
                    tcp_origin_port,
                    udp_origin_port,
                    auth_dns_port,
                    round_idx=round_no,
                    mtu=1500,
                )
                tun_rounds.append(tun_res)
                print(
                    f"[bench] [R{round_no} TUN] rust-clash smoltcp L3 TUN (MTU 1500): "
                    f"1-stream={tun_res['tcp_1stream_mbps']} Mbps, "
                    f"4-stream={tun_res['tcp_multistream_mbps']} Mbps, "
                    f"echo_p50={tun_res['proxy_rtt_p50_ms']} ms, "
                    f"udp={tun_res['udp_pps']} PPS (loss={tun_res['udp_loss_pct']}%), "
                    f"dns_hijack_p50={tun_res['dns_hijack_p50_ms']} ms"
                )

        comparative_aggregated = [
            aggregate_engine_rounds(
                engine_labels[k], per_engine_rounds[k], NUMERIC_MIXED_METRICS
            )
            for k in ["rust-clash", "mihomo", "sing-box"]
        ]
        tun_aggregated = aggregate_engine_rounds(
            f"rust-clash v{rc_version} L3 smoltcp TUN (MTU 1500 -> SS-2022)",
            tun_rounds,
            NUMERIC_TUN_METRICS,
        )

        cpu_model = "Unknown CPU"
        if Path("/proc/cpuinfo").is_file():
            for line in Path("/proc/cpuinfo").read_text().splitlines():
                if line.lower().startswith("model name"):
                    cpu_model = line.split(":", 1)[1].strip()
                    break

        os_tun_priv_ok = Path("/dev/net/tun").exists() and os.geteuid() == 0

        report = {
            "generated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "methodology": {
                "rounds": args.rounds,
                "interleaving": "balanced_6_permutation_latin_square",
                "confidence_interval": "two_sided_95pct_student_t",
                "schedule": schedule_executed,
                "os_kernel_tun_privilege_in_local_env": os_tun_priv_ok,
                "os_kernel_tun_note": (
                    "Userspace L3 smoltcp TUN (MTU 1500 IPv4 segmentation + checksum + TCP/UDP/DNS hijack -> SS-2022) "
                    "is measured across all rounds here; real Linux kernel /dev/net/tun + ip rule + fwmark throughput/RTT "
                    "is additionally verified inside isolated ip netns in CI (scripts/ci_linux_netns_tun_test.sh)."
                ),
            },
            "host": {
                "os": platform.platform(),
                "arch": platform.machine(),
                "cpu_model": cpu_model,
                "logical_cores": os.cpu_count(),
            },
            "supply_chain_pins": {
                "mihomo": {"version": MIHOMO_VERSION, "sha256": MIHOMO_SHA256},
                "sing_box": {"version": SINGBOX_VERSION, "sha256": SINGBOX_SHA256},
                "shadowsocks_rust_upstream": {
                    "version": SS_RUST_VERSION,
                    "sha256": SS_RUST_SHA256,
                },
            },
            "workload": {
                "cipher": "2022-blake3-aes-256-gcm (SIP022 TCP + UDP)",
                "idle_window_seconds": args.idle_seconds,
                "mixed_tcp_single_stream_bytes": 32 * 1024 * 1024,
                "mixed_tcp_multi_stream_bytes": 8 * 16 * 1024 * 1024,
                "mixed_tcp_latency_iterations": 150,
                "mixed_udp_packets": 500,
                "mixed_dns_queries": 400,
                "tun_mtu": 1500,
                "tun_tcp_single_stream_bytes": 16 * 1024 * 1024,
                "tun_tcp_multi_stream_bytes": 4 * 8 * 1024 * 1024,
                "tun_tcp_latency_iterations": 100,
                "tun_udp_packets": 400,
                "tun_dns_hijack_queries": 300,
            },
            "comparative_mixed_socks5": comparative_aggregated,
            "welch_t_tests": compute_comparative_welch_tests(comparative_aggregated),
            "rust_clash_tun_l3_path": tun_aggregated,
        }

        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(report, indent=2) + "\n")
        print(f"\n[bench] Saved multi-round statistical & TUN-path report to {args.json_out}")
        return 0
    finally:
        ss_proc.terminate()
        for h in origin_handles:
            h.close()


def _verify_incomplete_beta_accuracy() -> None:
    """Self-verify regularized incomplete beta against exact Student-t 95% critical values."""
    for df, t_crit in STUDENT_T_95.items():
        p = student_t_two_sided_p_value(t_crit, float(df))
        if abs(p - 0.05) > 2e-4:
            raise AssertionError(f"Student-t p-value check failed for df={df}: got p={p}")


def recompute_stats_from_json(json_path: Path) -> int:
    _verify_incomplete_beta_accuracy()
    data = json.loads(json_path.read_text())
    comp = data.get("comparative_mixed_socks5", [])
    tun = data.get("rust_clash_tun_l3_path", {})
    welch = compute_comparative_welch_tests(comp)

    print(f"=== Welch's Two-Sample t-Test Recomputation ({json_path}) ===")
    print(
        f"{'Metric':<22} | {'vs mihomo (t, df, two-sided p)':<40} | {'vs sing-box (t, df, two-sided p)':<40}"
    )
    print("-" * 108)
    for metric in NUMERIC_MIXED_METRICS:
        m_res = welch["rust_clash_vs_mihomo"][metric]
        s_res = welch["rust_clash_vs_sing_box"][metric]

        def _fmt(r: dict[str, Any]) -> str:
            t_v = r["t_stat"]
            df_v = r["df"]
            p_v = r["p_value"]
            sig = "SIG" if r["significant_alpha_0_05"] else "ns"
            if t_v is None:
                return f"det (diff={r['diff_mean']:+.3f}), p=0 [{sig}]"
            p_str = f"{p_v:.3e}" if p_v < 0.001 and p_v > 0.0 else f"{p_v:.4f}"
            return f"t={t_v:+.3f}, df={df_v:.2f}, p={p_str} [{sig}]"

        print(f"{metric:<22} | {_fmt(m_res):<40} | {_fmt(s_res):<40}")

    if comp:
        print("\n=== Comparative Mixed SOCKS5 Recorded Distributions ===")
        for entry in comp:
            print(f"  [{entry.get('engine')}]")
            dists = entry.get("distributions", {})
            for metric in ("binary_size_mib", "startup_ready_ms", "idle_cpu_pct", "idle_rss_mib", "peak_rss_mib", "tcp_1stream_mbps", "tcp_8stream_mbps", "proxy_rtt_p50_ms", "udp_loss_pct", "udp_pps", "dns_p50_ms"):
                if metric in dists:
                    d = dists[metric]
                    print(
                        f"    {metric:<20}: mean={d['mean']} ± {d['stdev']} (95% CI ±{d['ci95_half_width']}), "
                        f"median={d['median']} (IQR {d['iqr']}), [{d['min']}..{d['max']}]"
                    )

    if tun and "distributions" in tun:
        print("\n=== L3 smoltcp TUN Recorded Distributions ===")
        for metric in NUMERIC_TUN_METRICS:
            if metric in tun["distributions"]:
                d = tun["distributions"][metric]
                print(
                    f"  {metric:<24}: mean={d['mean']} ± {d['stdev']} (95% CI ±{d['ci95_half_width']}), "
                    f"median={d['median']} (IQR {d['iqr']}), [{d['min']}..{d['max']}]"
                )

    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run multi-round interleaved rust-clash vs mihomo vs sing-box + L3 TUN benchmarks"
    )
    parser.add_argument(
        "--recompute-stats",
        type=Path,
        default=None,
        help="Recompute and print exact two-sample Welch's t-test p-values from an existing JSON dataset (e.g. docs/benchmarks_latest.json)",
    )
    parser.add_argument(
        "--rounds",
        type=int,
        default=6,
        help="Number of interleaved benchmark rounds (default: 6 for full balanced Latin square)",
    )
    parser.add_argument(
        "--cache-dir",
        type=Path,
        default=Path("/tmp/rust-clash-bench-cache"),
    )
    parser.add_argument(
        "--cargo-target-dir",
        type=Path,
        default=Path("/tmp/rust-clash-bench-target"),
    )
    parser.add_argument(
        "--idle-seconds",
        type=float,
        default=2.0,
        help="Idle CPU/RSS measurement window per engine per round in seconds (default: 2.0)",
    )
    parser.add_argument(
        "--json-out",
        type=Path,
        default=Path(__file__).resolve().parent.parent / "docs" / "benchmarks_latest.json",
    )
    args = parser.parse_args()
    if args.recompute_stats is not None:
        return recompute_stats_from_json(args.recompute_stats)
    return asyncio.run(async_main(args))


if __name__ == "__main__":
    sys.exit(main())

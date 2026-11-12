#!/usr/bin/env python3
"""Download and verify the official signed Wintun v0.14.1 driver distribution.

Supply-chain security:
- Pins official URL `https://www.wintun.net/builds/wintun-0.14.1.zip`
- Verifies full archive SHA-256 (`07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51`)
  before extracting a single byte.
- Preserves Wintun's official `LICENSE.txt` (`wintun-LICENSE.txt`) alongside `wintun.dll`
  in compliance with WireGuard LLC's Prebuilt Binary Redistribution terms.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import platform
import shutil
import sys
import tempfile
import urllib.request
import zipfile
from pathlib import Path

WINTUN_VERSION = "0.14.1"
WINTUN_URL = f"https://www.wintun.net/builds/wintun-{WINTUN_VERSION}.zip"
WINTUN_ZIP_SHA256 = "07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51"

VALID_ARCHS = ("amd64", "arm64", "x86", "arm")


def detect_default_arch() -> str:
    machine = platform.machine().lower()
    if machine in ("amd64", "x86_64", "x64"):
        return "amd64"
    if machine in ("arm64", "aarch64"):
        return "arm64"
    if machine in ("i386", "i686", "x86"):
        return "x86"
    return "amd64"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def download_verified_zip(dest_zip: Path) -> None:
    dest_zip.parent.mkdir(parents=True, exist_ok=True)
    if dest_zip.is_file() and sha256_file(dest_zip) == WINTUN_ZIP_SHA256:
        print(f"[fetch_wintun] Using cached verified archive: {dest_zip}")
        return

    fd, tmp_name = tempfile.mkstemp(prefix="wintun-", suffix=".zip", dir=str(dest_zip.parent))
    os.close(fd)
    tmp_path = Path(tmp_name)
    last_err: Exception | None = None
    try:
        for attempt in range(1, 4):
            try:
                print(f"[fetch_wintun] Downloading {WINTUN_URL} (attempt {attempt}/3) ...")
                req = urllib.request.Request(
                    WINTUN_URL,
                    headers={
                        "User-Agent": "curl/8.5.0",
                        "Accept": "*/*",
                    },
                )
                with urllib.request.urlopen(req, timeout=60) as resp, tmp_path.open("wb") as out:
                    shutil.copyfileobj(resp, out)

                actual = sha256_file(tmp_path)
                if actual != WINTUN_ZIP_SHA256:
                    raise RuntimeError(
                        f"SHA-256 mismatch for {WINTUN_URL}: expected {WINTUN_ZIP_SHA256}, got {actual}"
                    )
                tmp_path.replace(dest_zip)
                print(f"[fetch_wintun] Verified SHA-256: {actual}")
                return
            except Exception as err:
                last_err = err
                if attempt < 3:
                    import time

                    time.sleep(2 * attempt)
        assert last_err is not None
        raise last_err
    finally:
        tmp_path.unlink(missing_ok=True)


def extract_wintun(zip_path: Path, arch: str, out_dir: Path) -> tuple[Path, Path]:
    if arch not in VALID_ARCHS:
        raise ValueError(f"Unsupported Wintun architecture '{arch}'; expected one of {VALID_ARCHS}")

    actual = sha256_file(zip_path)
    if actual != WINTUN_ZIP_SHA256:
        raise RuntimeError(
            f"Refusing to extract unverified archive {zip_path}: SHA-256 {actual} != {WINTUN_ZIP_SHA256}"
        )

    dll_member = f"wintun/bin/{arch}/wintun.dll"
    license_member = "wintun/LICENSE.txt"

    out_dir.mkdir(parents=True, exist_ok=True)
    out_dll = out_dir / "wintun.dll"
    out_license = out_dir / "wintun-LICENSE.txt"

    with zipfile.ZipFile(zip_path, "r") as zf:
        with zf.open(dll_member, "r") as src, out_dll.open("wb") as dst:
            shutil.copyfileobj(src, dst)
        with zf.open(license_member, "r") as src, out_license.open("wb") as dst:
            shutil.copyfileobj(src, dst)

    dll_digest = sha256_file(out_dll)
    print(f"[fetch_wintun] Extracted {out_dll} ({arch}, sha256={dll_digest})")
    print(f"[fetch_wintun] Extracted {out_license}")
    return out_dll, out_license


def run_self_test() -> int:
    with tempfile.TemporaryDirectory() as td:
        fake_zip = Path(td) / "tampered.zip"
        with zipfile.ZipFile(fake_zip, "w") as zf:
            zf.writestr("wintun/bin/amd64/wintun.dll", b"tampered-payload")
            zf.writestr("wintun/LICENSE.txt", b"license")
        try:
            extract_wintun(fake_zip, "amd64", Path(td) / "out")
        except RuntimeError as err:
            if "Refusing to extract unverified archive" in str(err):
                print("[fetch_wintun] self-test PASS: tampered archive rejected fail-closed")
                return 0
            raise
        raise AssertionError("tampered archive should have been rejected")


def main() -> int:
    parser = argparse.ArgumentParser(description="Fetch and verify official signed Wintun DLL")
    parser.add_argument(
        "--arch",
        default=detect_default_arch(),
        choices=VALID_ARCHS,
        help="Target Windows architecture (default: auto-detected)",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=Path("target/wintun"),
        help="Output directory for wintun.dll and wintun-LICENSE.txt",
    )
    parser.add_argument(
        "--cache-zip",
        type=Path,
        default=Path.home() / ".cache" / "rust-clash-tools" / f"wintun-{WINTUN_VERSION}.zip",
        help="Cached zip archive location",
    )
    parser.add_argument(
        "--from-zip",
        type=Path,
        default=None,
        help="Use an existing local zip archive instead of downloading",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Verify fail-closed SHA-256 tamper rejection offline",
    )
    args = parser.parse_args()

    if args.self_test:
        return run_self_test()

    zip_path = args.from_zip if args.from_zip is not None else args.cache_zip
    if args.from_zip is None:
        download_verified_zip(zip_path)

    extract_wintun(zip_path, args.arch, args.out_dir)
    return 0


if __name__ == "__main__":
    sys.exit(main())

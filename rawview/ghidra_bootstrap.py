"""Locate or download a Ghidra install for RawView (no bundling of full Ghidra in git)."""

from __future__ import annotations

import io
import json
import os
import ssl
import stat
import sys
import urllib.error
import urllib.request
import zipfile
from collections.abc import Callable
from pathlib import Path

ProgressCb = Callable[[int, int, str], None]  # bytes_done, bytes_total, message


def _ssl_context() -> ssl.SSLContext:
    """Use Mozilla CA bundle from certifi (fixes VERIFY_FAILED on some Python installs)."""
    ctx = ssl.create_default_context()
    try:
        import certifi

        ctx.load_verify_locations(cafile=certifi.where())
    except Exception:
        pass
    return ctx


# Official NSA Ghidra release zip (must match a real GitHub release asset name).
# Security: 12.0.4 and earlier are vulnerable to multiple Ghidra CVEs fixed in 12.1+
# (decompiler heap-UAF CVE-2026-52757, SleighBuilder UAF CVE-2026-52752, Swift demangler
# arbitrary code execution CVE-2026-52750, Mach-O export-trie OOM CVE-2026-52753).
# RawView requires >= 12.1 for parsed-malware analysis. Auto-resolution via
# resolve_latest_ghidra_public_zip_url() picks the newest GitHub PUBLIC release.
DEFAULT_GHIDRA_ZIP_URL = (
    "https://github.com/NationalSecurityAgency/ghidra/releases/download/"
    "Ghidra_12.1.3_build/ghidra_12.1.3_PUBLIC_20260817.zip"
)


def is_valid_ghidra_root(path: Path) -> bool:
    """True if directory looks like a Ghidra install root (contains support + Ghidra jars)."""
    if not path.is_dir():
        return False
    support = path / "support"
    ghidra_dir = path / "Ghidra"
    return support.is_dir() and ghidra_dir.is_dir()


def resolve_latest_ghidra_public_zip_url(*, timeout_s: float = 30.0) -> str | None:
    """Ask GitHub for the latest Ghidra release and return the main PUBLIC .zip download URL."""
    api = "https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/latest"
    req = urllib.request.Request(
        api,
        headers={"User-Agent": "RawView/1.0", "Accept": "application/vnd.github+json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout_s, context=_ssl_context()) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except Exception:
        return None
    for asset in data.get("assets", []):
        name = str(asset.get("name", ""))
        if name.endswith(".zip") and "PUBLIC" in name and name.startswith("ghidra_"):
            url = asset.get("browser_download_url")
            if isinstance(url, str):
                return url
    return None


def find_ghidra_root_inside_extract(base: Path) -> Path | None:
    """After extracting the release zip, locate the inner `ghidra_*_PUBLIC` folder."""
    if is_valid_ghidra_root(base):
        return base
    for child in base.iterdir():
        if child.is_dir() and child.name.lower().startswith("ghidra") and is_valid_ghidra_root(child):
            return child
    return None


def download_and_extract_ghidra(
    *,
    zip_url: str,
    dest_parent: Path,
    progress: ProgressCb | None = None,
) -> Path:
    """
    Download the Ghidra public zip into dest_parent and extract it.
    Returns the Ghidra install root path to set as GHIDRA_INSTALL_DIR.
    """
    dest_parent.mkdir(parents=True, exist_ok=True)
    zip_path = dest_parent / "ghidra_download.zip"
    progress = progress or (lambda a, b, c: None)

    progress(0, 1, "Downloading Ghidra (this is large, several hundred MB)…")
    req = urllib.request.Request(zip_url, headers={"User-Agent": "RawView/1.0"})
    ctx = _ssl_context()
    try:
        resp = urllib.request.urlopen(req, timeout=120, context=ctx)  # noqa: S310
    except urllib.error.HTTPError as e:
        if e.code == 404:
            progress(0, 1, "Download URL returned 404; resolving latest Ghidra from GitHub…")
            latest = resolve_latest_ghidra_public_zip_url()
            if not latest or latest == zip_url:
                raise RuntimeError(
                    "Could not download Ghidra (404) and could not resolve a different release URL."
                ) from e
            zip_url = latest
            req = urllib.request.Request(zip_url, headers={"User-Agent": "RawView/1.0"})
            resp = urllib.request.urlopen(req, timeout=120, context=ctx)  # noqa: S310
        else:
            raise
    with resp:
        total = int(resp.headers.get("Content-Length") or 0)
        buf = io.BytesIO()
        done = 0
        chunk = 1024 * 256
        while True:
            part = resp.read(chunk)
            if not part:
                break
            buf.write(part)
            done += len(part)
            if total:
                progress(done, total, f"Downloading… {done // (1024 * 1024)} MB")
            else:
                progress(done, done + 1, f"Downloading… {done // (1024 * 1024)} MB")

    progress(done, max(done, 1), "Saving archive…")
    zip_path.write_bytes(buf.getvalue())

    progress(0, 1, "Extracting (may take a minute)…")
    extract_root = dest_parent / "ghidra_extract"
    if extract_root.is_dir():
        import shutil

        shutil.rmtree(extract_root, ignore_errors=True)
    extract_root.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_path, "r") as zf:
        for zi in zf.infolist():
            zf.extract(zi, extract_root)
            # Restore Unix execute bits (stored in upper 16 bits of external_attr).
            # zipfile.extractall() silently drops them, so Linux native binaries
            # (Ghidra decompiler, SLEIGH, demanglers) would be non-executable.
            if sys.platform != "win32":
                unix_mode = (zi.external_attr >> 16) & 0xFFFF
                if unix_mode:
                    dest = extract_root / zi.filename
                    try:
                        dest.chmod(unix_mode)
                    except OSError:
                        pass
    zip_path.unlink(missing_ok=True)

    inner = find_ghidra_root_inside_extract(extract_root)
    if inner is None:
        raise RuntimeError("Extracted zip did not contain a recognizable Ghidra root folder.")
    progress(1, 1, f"Ghidra ready at {inner}")
    return inner.resolve()

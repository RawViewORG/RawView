"""Ship Ghidra's macOS native binaries, which an official Ghidra release does not.

Ghidra's own ``GettingStarted.md`` is explicit about this: a public release contains
native binaries for Windows x86-64, Windows ARM64 and Linux x86-64 only. macOS (both
architectures), Linux ARM64 and FreeBSD are "supported ... with user-built native
binaries", built by the user with::

    cd <GhidraInstallDir>/support/gradle/ && gradle buildNatives

Without them there is no ``decompile`` or ``sleigh`` for the platform, so Ghidra can
open its UI but cannot analyze anything - which is precisely how a macOS RawView build
failed before this module existed. Requiring Gradle and Xcode Command Line Tools from
someone who downloaded a .dmg is not a reasonable ask, so RawView builds the natives on
CI (each macOS runner builds its own architecture), bundles them, and drops them into
whichever Ghidra install is in use on first launch.

Ghidra is Apache-2.0, so redistributing binaries built from it is fine.
"""

from __future__ import annotations

import logging
import platform
import shutil
import stat
import sys
from pathlib import Path

logger = logging.getLogger(__name__)

# Ghidra's own platform directory names (see ghidra.framework.Platform).
_MAC_ARM = "mac_arm_64"
_MAC_X86 = "mac_x86_64"

# Where bundled natives live inside the package / PyInstaller tree.
_BUNDLE_SUBDIR = "ghidra_natives"

# A Ghidra install without this cannot analyze; used to decide whether to install.
_SENTINEL = Path("Ghidra") / "Features" / "Decompiler" / "os"


def current_platform_key() -> str | None:
    """Ghidra's platform directory name for this host, or None where Ghidra ships its own."""
    if sys.platform != "darwin":
        # Windows and Linux x86-64 natives come with the official release.
        return None
    machine = platform.machine().lower()
    if machine in ("arm64", "aarch64"):
        return _MAC_ARM
    if machine in ("x86_64", "amd64"):
        return _MAC_X86
    return None


def bundled_natives_dir(platform_key: str | None = None) -> Path | None:
    """The bundled natives tree for this platform, or None when nothing was shipped."""
    key = platform_key or current_platform_key()
    if key is None:
        return None
    roots: list[Path] = [Path(__file__).resolve().parent]
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        roots.append(Path(meipass) / "rawview")
    for root in roots:
        candidate = root / _BUNDLE_SUBDIR / key
        if candidate.is_dir():
            return candidate
    return None


def natives_installed(ghidra_root: Path, platform_key: str | None = None) -> bool:
    """Whether ``ghidra_root`` already has native binaries for this platform."""
    key = platform_key or current_platform_key()
    if key is None:
        return True
    decompiler_os = ghidra_root / _SENTINEL / key
    return (decompiler_os / "decompile").is_file()


def install_natives(ghidra_root: Path, platform_key: str | None = None) -> int:
    """Copy bundled natives into ``ghidra_root``; return how many files were written.

    Files are copied rather than symlinked so the Ghidra install stays self-contained
    if RawView is later removed, and the execute bit is set explicitly: Ghidra runs
    these as subprocesses, and a copy that is not executable fails exactly like a
    missing one.
    """
    key = platform_key or current_platform_key()
    if key is None:
        return 0
    source = bundled_natives_dir(key)
    if source is None:
        logger.warning(
            "No bundled Ghidra natives for %s; analysis will fail until they are built "
            "(cd %s/support/gradle && ./gradlew buildNatives)",
            key,
            ghidra_root,
        )
        return 0

    written = 0
    for src in sorted(source.rglob("*")):
        if src.is_dir():
            continue
        dest = ghidra_root / src.relative_to(source)
        if dest.is_file():
            continue
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dest)
        mode = dest.stat().st_mode
        dest.chmod(mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        written += 1
    if written:
        logger.info("Installed %d Ghidra native file(s) for %s into %s", written, key, ghidra_root)
    return written


def ensure_natives(ghidra_root: Path) -> int:
    """Install bundled natives when the install has none. Safe to call on every launch."""
    key = current_platform_key()
    if key is None:
        return 0
    try:
        if natives_installed(ghidra_root, key):
            return 0
        return install_natives(ghidra_root, key)
    except OSError:
        # A read-only or otherwise unwritable Ghidra install is the user's to fix; the
        # JVM will report the missing decompiler itself rather than dying here.
        logger.exception("Could not install Ghidra natives into %s", ghidra_root)
        return 0


def collect_from_install(ghidra_root: Path, dest_root: Path, platform_key: str | None = None) -> int:
    """Build-time: harvest freshly built ``os/<platform>`` trees out of a Ghidra install.

    Used by CI after ``gradlew buildNatives`` to populate the tree this module ships.
    Returns the number of files collected.
    """
    key = platform_key or current_platform_key()
    if key is None:
        raise RuntimeError("collect_from_install needs a macOS platform key")
    dest = dest_root / key
    collected = 0
    for os_dir in sorted(ghidra_root.rglob(f"os/{key}")):
        if not os_dir.is_dir():
            continue
        for src in sorted(os_dir.rglob("*")):
            if src.is_dir():
                continue
            target = dest / src.relative_to(ghidra_root)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, target)
            collected += 1
    return collected

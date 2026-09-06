"""Harvest Ghidra's freshly built macOS natives into the RawView package for bundling.

Build-time only. Run on a macOS builder after::

    cd "$GHIDRA_INSTALL_DIR/support/gradle" && ./gradlew buildNatives

then ``rawview/ghidra_natives/<platform>/`` holds the binaries that
:mod:`rawview.ghidra_natives` installs into a user's Ghidra at first launch.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from rawview.ghidra_natives import collect_from_install, current_platform_key


def main() -> int:
    ghidra = os.environ.get("GHIDRA_INSTALL_DIR", "").strip()
    if not ghidra:
        print("GHIDRA_INSTALL_DIR is not set.", file=sys.stderr)
        return 2
    root = Path(ghidra)
    if not (root / "Ghidra").is_dir():
        print(f"{root} does not look like a Ghidra install root.", file=sys.stderr)
        return 2

    key = current_platform_key()
    if key is None:
        print(f"Nothing to collect on {sys.platform}: Ghidra ships its own natives.")
        return 0

    dest_root = Path(__file__).resolve().parent.parent / "ghidra_natives"
    count = collect_from_install(root, dest_root, key)
    if count == 0:
        print(
            f"No os/{key} binaries found under {root}. Did `gradlew buildNatives` run?",
            file=sys.stderr,
        )
        return 1

    decompile = dest_root / key / "Ghidra" / "Features" / "Decompiler" / "os" / key / "decompile"
    if not decompile.is_file():
        print(f"Collected {count} file(s) but {decompile.name} is missing.", file=sys.stderr)
        return 1

    print(f"Collected {count} native file(s) for {key} into {dest_root / key}")
    for f in sorted((dest_root / key).rglob("*")):
        if f.is_file():
            print(f"  {f.relative_to(dest_root / key)}  ({f.stat().st_size // 1024} KB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

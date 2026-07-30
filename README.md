<div align="center">

<img src="https://raw.githubusercontent.com/codeminute-the-dev/RawView/master/assets/banner.png" width="920" alt="RawView banner">

<br><br>

<a href="https://github.com/codeminute-the-dev" title="CODEMINUTE on GitHub"><img src="https://github.com/codeminute-the-dev.png" width="72" height="72" alt="CODEMINUTE"></a>

</div>

# RawView

AI-assisted reverse engineering for **Ghidra**: a **Qt (PySide6)** desktop app that drives Ghidra headlessly over **Py4J**, with decompiler, disassembly, strings, imports/exports, xrefs, and related tools in one docked window.

**Optional:** an **agent** dock uses the **Anthropic** API when you add a key under **File -> Settings**. Ghidra is not bundled; you point RawView at your install (or ZIP URL) in settings.

<p align="center">
  <img src="assets/demo.gif" width="920" alt="RawView demo">
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-GPL%20v3-blue" alt="GPL v3"></a>
  <img src="https://img.shields.io/badge/platform-Windows-blue" alt="Windows">
  <img src="https://img.shields.io/badge/python-3.11%2B-blue" alt="Python 3.11+">
</p>

**Author:** [@codeminute-the-dev](https://github.com/codeminute-the-dev)

**Discord:** [Codeminute's Discord Server](https://discord.gg/aHRjNzhNgk)

**RawOS:** [RawView's Operating System](https://github.com/codeminute-the-dev/RawOS)

---

## Features

- Open binaries and run analysis through Ghidra without using the Ghidra Swing UI for day-to-day navigation.
- Docked panes, themes, shortcuts, work notes, and optional RE session archives (`.rvre.zip` style workflow).
- Windows-focused packaging: **PyInstaller** onedir + **WiX** per-user MSI. Use the repo **Releases** tab for prebuilt installers when the maintainer uploads them.

## Requirements

| | |
|--|--|
| OS | **Windows** (primary; scripts and MSI are Windows-oriented) |
| Python | **3.11+** |
| Ghidra | Your own install or official ZIP; configured inside the app |
| JDK | **21+** for compiling the Java bridge; the app can fetch Temurin into `%LOCALAPPDATA%\RawView\` on first run |

## Build from source

```powershell
git clone https://github.com/codeminute-the-dev/RawView.git
cd RawView
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
python -m rawview.scripts.compile_java
python -m rawview
```

Editable install (`-e`) picks up Python changes without reinstalling.

## Windows MSI (from this repo)

1. Install [WiX Toolset 3.11+](https://github.com/wixtoolset/wix3/releases) and ensure `bin` is on `PATH`, or set env var `WIX` to the toolkit root.
2. From the repo root:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\build-msi.ps1
```

Output:

- `dist\RawView\`: portable PyInstaller layout (`RawView.exe`). All Python dependencies from `pyproject.toml` are **frozen into** `_internal` at build time (there is no Python or `pip` on the user's PC for the MSI build).
- `dist\RawView\BUNDLED_PYTHON_PACKAGES.txt`: `pip freeze` from the build machine after `pip install ".[dev]"`, shipped next to `RawView.exe` for transparency.
- `dist_installer\RawView-<version>.msi`: per-user WiX installer (Start menu + desktop shortcuts, full GPL license text in the wizard).

Rebuild WiX only (reuse `dist\RawView`): `.\scripts\build-msi.ps1 -SkipPyInstaller` (the script still runs `pip install ".[dev]"` and refreshes `BUNDLED_PYTHON_PACKAGES.txt` before harvesting).

## Repository layout

| Path | Purpose |
|------|---------|
| `rawview/` | Application code; Java bridge **sources** under `rawview/java/` |
| `packaging/` | `rawview.spec`, WiX `Product.wxs`, icons |
| `scripts/` | `build-windows.ps1`, `build-msi.ps1`, `export-source-zip.ps1` |
| `installer/` | Windows installer build notes (`BUILD.txt`) |
| `pip/` | Helper scripts for editable installs in a dedicated folder |
| `LICENSE` | GPLv3 full text |

This repo is the **project root** (the folder with `pyproject.toml`). The inner `rawview/` directory is only the Python package name, not a separate publishable tree.

## Source-only archive

To zip exactly what Git tracks (no `dist/`, `build/`, etc.):

```powershell
powershell -ExecutionPolicy Bypass -File scripts\export-source-zip.ps1
```

Writes `RawView-source-<version>.zip` on the parent of this repo folder.

## Security

Do **not** commit API keys, tokens, or `rawview.env` from your machine. Settings normally live under `%LOCALAPPDATA%\RawView\`. `.gitignore` excludes common secret filenames and large local Ghidra/JDK trees if they are ever copied next to the clone.

## License

[GNU General Public License v3.0](LICENSE).

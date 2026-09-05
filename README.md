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
  <img src="https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-blue" alt="Windows | Linux | macOS">
  <img src="https://img.shields.io/badge/python-3.11%2B-blue" alt="Python 3.11+">
</p>

**Author:** [@codeminute-the-dev](https://github.com/codeminute-the-dev)

**Discord:** [Codeminute's Discord Server](https://discord.gg/aHRjNzhNgk)

**RawOS:** [RawView's Operating System](https://github.com/codeminute-the-dev/RawOS)

---

## Features

- Open binaries and run analysis through Ghidra without using the Ghidra Swing UI for day-to-day navigation.
- Docked panes, themes, shortcuts, work notes, and optional RE session archives (`.rvre.zip` style workflow).
- Packaged for all three desktops: **PyInstaller** onedir plus a per-user **WiX MSI** (Windows), `.deb`/`.rpm`/`.AppImage` (Linux), and a signed-ad-hoc `.app` inside a `.dmg` (macOS, Apple Silicon and Intel). Prebuilt installers are on the **Releases** tab.

## Requirements

| | |
|--|--|
| OS | **Windows 10/11**, **Linux**, or **macOS 12+** (Apple Silicon or Intel) |
| Python | **3.11+** |
| Ghidra | Your own install or official ZIP; configured inside the app |
| JDK | **21+** for compiling the Java bridge; the app can fetch Temurin on first run (`%LOCALAPPDATA%\RawView\`, `~/.local/share/RawView/`, or `~/Library/Application Support/RawView/`) |

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

## macOS .app and .dmg (from this repo)

From the repo root, with the venv active:

```bash
bash build-macos.sh              # dist/RawView.app + dist_installer/RawView-<version>-<arch>.dmg
bash build-macos.sh --skip-dmg   # bundle only
```

The script renders `app_icon.icns` from the PNG, runs PyInstaller against `packaging/rawview.spec`
(which adds the `BUNDLE` step on macOS), then **ad-hoc signs** the bundle - Apple Silicon refuses to
run unsigned native code, so this is required, not cosmetic.

The `.dmg` is **not notarized**. On first launch macOS will say the app "cannot be opened because the
developer cannot be verified". Right-click the app → **Open** → **Open**, or clear the quarantine flag:

```bash
xattr -dr com.apple.quarantine /Applications/RawView.app
```

The Ghidra JVM sandbox is Linux-only (bubblewrap builds on Linux namespaces), so macOS runs the JVM
unsandboxed, the same as Windows.

## Repository layout

| Path | Purpose |
|------|---------|
| `rawview/` | Application code; Java bridge **sources** under `rawview/java/` |
| `packaging/` | `rawview.spec`, WiX `Product.wxs`, icons |
| `scripts/` | `build-windows.ps1`, `build-msi.ps1`, `export-source-zip.ps1` |
| `build-*.sh` | Linux (`build-linux.sh`, `build-deb.sh`, `build-rpm.sh`, `build-appimage.sh`) and macOS (`build-macos.sh`) package builds |
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

### Ghidra version (CVE fixes)

RawView analyzes untrusted binaries **through Ghidra's importers and native decompiler**. Ghidra releases before **12.1** have known high-severity vulnerabilities that a crafted binary can trigger during import or decompilation:

- **CVE-2026-52757** (CVSS 7.8) — heap use-after-free in the decompiler's `HighVariable::merge()`, triggerable by a crafted binary.
- **CVE-2026-52752** (CVSS 7.8) — SleighBuilder use-after-free, triggerable by decompiling a malicious binary.
- **CVE-2026-52750** (CVSS 7.8) — Swift demangler arbitrary code execution via a malicious Ghidra project.
- **CVE-2026-52753** (CVSS 5.5) — Mach-O export-trie out-of-memory (JVM crash).

RawView requires **Ghidra ≥ 12.1** to analyze hostile samples. The bundled default and `GHIDRA_BUNDLE_URL` point at the latest public release (auto-resolved at download time).

### Sandboxed Ghidra engine (optional, Linux)

On Linux with [bubblewrap](https://github.com/containers/bubblewrap), RawView can run the **entire Ghidra JVM (parsers + native decompiler) inside a mount-namespace sandbox** while the Python/Qt app stays user-mode on the host. `RAWVIEW_SANDBOX=bwrap` (default on Linux when `bwrap` is installed) wraps the JVM launch:

- Read-only root, sensitive trees stripped to tmpfs (`/home`, `/root`, `/media`, `/mnt`, `/srv`, `/var`).
- The toolchain (Ghidra, JDK, bridge classes, py4j jar) is re-bound read-only at its real path.
- The **project dir** is the only writable host tree.
- Py4J stays loopback-only; network namespace is shared.

This means a compromise of the Ghidra process — e.g. an unknown importer/decompiler bug in the parser — **cannot read your `~/.ssh`, wallets, browsers, or other host files**. Set `RAWVIEW_SANDBOX=none` to disable, or `bwrap` to enable. The sandbox is used only on Linux **when the `bwrap` binary is actually present**; Windows and macOS always run the JVM unsandboxed, and so does a Linux box without bubblewrap installed (`sudo apt install bubblewrap`).

> Best practice: for highly hostile samples, still consider a dedicated analysis **VM**; the sandbox removes file access, but shared-kernel+network residual risk remains.

## License

[GNU General Public License v3.0](LICENSE).

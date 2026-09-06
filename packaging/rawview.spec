# PyInstaller spec - run from repo root:  pyinstaller packaging\rawview.spec
# -*- mode: python ; coding: utf-8 -*-

import os
import sys
from pathlib import Path

from PyInstaller.utils.hooks import collect_all

# SPECPATH is the spec’s directory (PyInstaller); if it ever points at the file, normalize.
_p = Path(SPECPATH).resolve()
_spec_dir = _p.parent if _p.is_file() else _p
REPO_ROOT = _spec_dir.parent

# Prefer live sources; fall back to setuptools' build/lib copy (e.g. sparse checkout / partial tree).
_entry = REPO_ROOT / "rawview" / "__main__.py"
if not _entry.is_file():
    _entry = REPO_ROOT / "build" / "lib" / "rawview" / "__main__.py"
if not _entry.is_file():
    raise SystemExit(
        "Cannot find rawview/__main__.py. From the repo root run:  python -m pip install -e ."
    )

_is_macos = sys.platform == "darwin"

_version = "0.0.0"
for _init in (REPO_ROOT / "rawview" / "__init__.py", REPO_ROOT / "build" / "lib" / "rawview" / "__init__.py"):
    if _init.is_file():
        for _line in _init.read_text(encoding="utf-8").splitlines():
            if _line.startswith("__version__"):
                _version = _line.split("=", 1)[1].strip().strip('"\'')
                break
        break

_res = REPO_ROOT / "rawview" / "qt_ui" / "resources"
if not _res.is_dir():
    _res = REPO_ROOT / "build" / "lib" / "rawview" / "qt_ui" / "resources"
datas = []
if _res.is_dir():
    datas.append((str(_res), "rawview/qt_ui/resources"))
binaries: list = []
# py4j ships the JVM client JAR under <prefix>/share/py4j (not inside site-packages/py4j).
# PyInstaller does not pick that up automatically, so Ghidra JVM boot fails without this.
_share_py4j = Path(sys.prefix) / "share" / "py4j"
if _share_py4j.is_dir():
    datas.append((str(_share_py4j), "share/py4j"))
else:
    _base_share = Path(getattr(sys, "base_prefix", sys.prefix)) / "share" / "py4j"
    if _base_share.is_dir():
        datas.append((str(_base_share), "share/py4j"))

# Ghidra's macOS natives, harvested by rawview.scripts.collect_ghidra_natives after
# `gradlew buildNatives` on the builder. An official Ghidra release has none for macOS,
# so without these the app opens but cannot analyze anything.
_natives = REPO_ROOT / "rawview" / "ghidra_natives"
if _is_macos:
    if _natives.is_dir() and any(_natives.iterdir()):
        datas.append((str(_natives), "rawview/ghidra_natives"))
    elif os.environ.get("RAWVIEW_REQUIRE_GHIDRA_NATIVES") == "1":
        raise SystemExit(
            "rawview/ghidra_natives is empty. On a macOS builder run:\n"
            "  cd \"$GHIDRA_INSTALL_DIR/support/gradle\" && ./gradlew buildNatives\n"
            "  python -m rawview.scripts.collect_ghidra_natives"
        )

# Ghidra JVM bridge: .class files from `python -m rawview.scripts.compile_java` (needs GHIDRA_INSTALL_DIR + JDK).
_java_out = REPO_ROOT / "rawview" / "java" / "out"
_java_marker = _java_out / "io" / "rawview" / "ghidra" / "GhidraServer.class"
if _java_marker.is_file():
    datas.append((str(_java_out), "rawview/java/out"))
elif os.environ.get("RAWVIEW_REQUIRE_JAVA_CLASSES") == "1":
    raise SystemExit(
        "rawview/java/out is missing the Ghidra bridge (expected GhidraServer.class). "
        "Set GHIDRA_INSTALL_DIR to your Ghidra root, ensure javac is available, then run:\n"
        "  python -m rawview.scripts.compile_java\n"
        "Or unset RAWVIEW_REQUIRE_JAVA_CLASSES to build without Ghidra support."
    )

hiddenimports = [
    "rawview",
    "rawview.qt_ui",
    "rawview.qt_ui.app",
    "rawview.qt_ui.main_window",
    "rawview.agent.brain",
    "rawview.agent.tools",
    "rawview.agent.memory",
    "rawview.agent.long_term_memory",
    "rawview.agent.conversation_summarize",
    "pydantic_settings",
    "dotenv",
    "certifi",
    "anthropic",
    "py4j",
    # java_gateway loads this with __import__ at runtime when auto_convert=True (PyInstaller misses it).
    "py4j.java_collections",
    "psutil",
    # Discord Rich Presence (optional, gracefully missing).
    "pypresence",
]

def _drops_nested_app_bundle(entry) -> bool:
    """Whether a collected PySide6 entry belongs to a nested .app inside the wheel.

    PySide6 ships Qt's developer tools (Assistant, Designer, Linguist) and the
    WebEngine helper as complete .app bundles. PyInstaller rewrites those paths to
    ``Assistant__dot__app``, which is no longer a valid bundle, and `codesign` then
    refuses the whole RawView.app with "the main executable or Info.plist must be a
    regular file". RawView launches none of them, so they are dropped rather than
    repaired. Non-macOS builds keep collecting everything as before.
    """
    dest = str(entry[1] if len(entry) > 1 else entry[0]).replace("\\", "/")
    return ".app/" in dest or "__dot__app/" in dest


for pkg in ("PySide6", "shiboken6"):
    try:
        d, b, h = collect_all(pkg)
        if _is_macos:
            d = [e for e in d if not _drops_nested_app_bundle(e)]
            b = [e for e in b if not _drops_nested_app_bundle(e)]
        datas += d
        binaries += b
        hiddenimports += h
    except Exception:
        pass

block_cipher = None

a = Analysis(
    [str(_entry)],
    pathex=[str(REPO_ROOT), str(REPO_ROOT / "build" / "lib")],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

_res_dir = REPO_ROOT / "rawview" / "qt_ui" / "resources"
# macOS wants .icns; build-macos.sh generates it from app_icon.png next to the .ico.
_app_ico = _res_dir / ("app_icon.icns" if _is_macos else "app_icon.ico")
if _is_macos and not _app_ico.is_file():
    _app_ico = _res_dir / "app_icon.png"
_exe_icon = str(_app_ico) if _app_ico.is_file() else None

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="RawView",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=_exe_icon,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="RawView",
)

# macOS ships an .app bundle: Finder will not launch a bare COLLECT directory, and
# only a bundle carries the Info.plist that makes the window a real windowed app
# (Dock icon, menu bar) instead of a background process.
if _is_macos:
    app = BUNDLE(
        coll,
        name="RawView.app",
        icon=_exe_icon,
        bundle_identifier="org.rawview.RawView",
        info_plist={
            "CFBundleName": "RawView",
            "CFBundleDisplayName": "RawView",
            "CFBundleShortVersionString": _version,
            "CFBundleVersion": _version,
            "NSHighResolutionCapable": True,
            # RawView is a normal windowed app, not an agent/daemon.
            "LSUIElement": False,
            # Bounded by the bundled Qt, not by our own code: PySide6 6.11 ships a
            # single macosx_13_0_universal2 wheel, so the frozen app cannot load on
            # macOS 12. Claiming 12.0 here would turn a clean "requires macOS 13"
            # refusal into a dyld crash after launch.
            "LSMinimumSystemVersion": "13.0",
            "NSRequiresAquaSystemAppearance": False,
            # The user picks binaries to analyze through the File dock, and drops are
            # accepted onto the window - declare the type so Finder can hand files over.
            "CFBundleDocumentTypes": [
                {
                    "CFBundleTypeName": "Binary",
                    "CFBundleTypeRole": "Viewer",
                    "LSHandlerRank": "Alternate",
                    "LSItemContentTypes": [
                        "public.executable",
                        "public.unix-executable",
                        "com.microsoft.windows-executable",
                        "public.data",
                    ],
                }
            ],
        },
    )

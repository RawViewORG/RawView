#!/usr/bin/env bash
# Build RawView as a macOS .app bundle and a .dmg.
# Run from the repo root with the venv active:
#   source .venv/bin/activate
#   bash build-macos.sh              # .app + .dmg
#   bash build-macos.sh --skip-dmg   # .app only
#
# The bundle is ad-hoc signed. It is NOT notarized, so Gatekeeper still asks the
# user to confirm the first launch (see the README).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

SKIP_DMG=0
for arg in "$@"; do
    case "$arg" in
        --skip-dmg) SKIP_DMG=1 ;;
        *) echo "Unknown option: $arg" >&2; exit 2 ;;
    esac
done

if [ "$(uname -s)" != "Darwin" ]; then
    echo "build-macos.sh must run on macOS (got $(uname -s))." >&2
    exit 1
fi

echo "=== RawView macOS build ($(uname -m)) ==="

VERSION=$(grep -m1 '^\s*version\s*=' pyproject.toml | sed 's/.*"\(.*\)".*/\1/')
ARCH=$(uname -m)
APP="dist/RawView.app"
DMG="dist_installer/RawView-${VERSION}-${ARCH}.dmg"

if ! python -c "import PyInstaller" 2>/dev/null; then
    echo "Installing PyInstaller..."
    pip install "pyinstaller>=6.0"
fi

if ! python -c "import pypresence" 2>/dev/null; then
    echo "Installing pypresence for Discord Rich Presence..."
    pip install pypresence
fi

# Compile the Java bridge if GHIDRA_INSTALL_DIR is set and classes are missing.
MARKER="rawview/java/out/io/rawview/ghidra/GhidraServer.class"
if [ -n "${GHIDRA_INSTALL_DIR:-}" ] && [ ! -f "$MARKER" ]; then
    echo "Compiling Java bridge classes..."
    python -m rawview.scripts.compile_java
fi

# Ghidra ships no macOS natives (its GettingStarted.md: official releases cover Windows
# and Linux x86-64 only). Build them here so the bundle can carry them; without this the
# app installs fine and then cannot analyze a single binary.
NATIVES_KEY="mac_arm_64"
[ "$ARCH" = "x86_64" ] && NATIVES_KEY="mac_x86_64"
if [ -n "${GHIDRA_INSTALL_DIR:-}" ] && [ ! -d "rawview/ghidra_natives/$NATIVES_KEY" ]; then
    if [ ! -f "$GHIDRA_INSTALL_DIR/Ghidra/Features/Decompiler/os/$NATIVES_KEY/decompile" ]; then
        echo "Building Ghidra native binaries for $NATIVES_KEY (needs Xcode Command Line Tools)..."
        (cd "$GHIDRA_INSTALL_DIR/support/gradle" && ./gradlew buildNatives)
    fi
    echo "Collecting Ghidra natives into the package..."
    python -m rawview.scripts.collect_ghidra_natives
fi

# PyInstaller wants .icns on macOS; the repo only carries .png/.ico, so render one.
ICNS="rawview/qt_ui/resources/app_icon.icns"
PNG="rawview/qt_ui/resources/app_icon.png"
if [ ! -f "$ICNS" ] && [ -f "$PNG" ]; then
    echo "Generating app_icon.icns from app_icon.png..."
    ICONSET="$(mktemp -d)/RawView.iconset"
    mkdir -p "$ICONSET"
    for size in 16 32 64 128 256 512; do
        sips -z "$size" "$size" "$PNG" --out "$ICONSET/icon_${size}x${size}.png" >/dev/null
        sips -z "$((size * 2))" "$((size * 2))" "$PNG" \
            --out "$ICONSET/icon_${size}x${size}@2x.png" >/dev/null
    done
    iconutil -c icns "$ICONSET" -o "$ICNS"
fi

echo "Running PyInstaller..."
rm -rf "$APP" dist/RawView
pyinstaller packaging/rawview.spec --noconfirm

if [ ! -d "$APP" ]; then
    echo "PyInstaller did not produce $APP." >&2
    exit 1
fi

# Ad-hoc signature. Apple Silicon refuses to run unsigned native code outright, so
# without this the .app dies at launch on every arm64 Mac.
echo "Ad-hoc signing the bundle..."
codesign --force --deep --sign - "$APP"
# Separate statements on purpose: under `set -e` a failing command on the left of
# `&&` does not abort the script, which is how a bundle that fails verification
# silently made it into a .dmg once already.
codesign --verify --deep --strict "$APP"
echo "Signature OK"

if [ "$SKIP_DMG" -eq 1 ]; then
    echo ""
    echo "Done. Bundle: $APP"
    exit 0
fi

echo "Building $DMG..."
mkdir -p dist_installer
rm -f "$DMG"
STAGE="$(mktemp -d)/RawView"
mkdir -p "$STAGE"
cp -R "$APP" "$STAGE/"
# The /Applications alias is what makes the window a drag-to-install target.
ln -s /Applications "$STAGE/Applications"
hdiutil create -volname "RawView $VERSION" -srcfolder "$STAGE" -ov -format UDZO "$DMG"

echo ""
echo "Done."
echo "  Bundle: $APP"
echo "  Disk image: $DMG"

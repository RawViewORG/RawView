#!/usr/bin/env bash
# Build RawView as an AppImage (runs on any Linux distro, no install needed).
# Downloads appimagetool automatically on first run.
#
# Usage (repo root, venv active):
#   source .venv/bin/activate
#   bash build-appimage.sh                      # full build
#   bash build-appimage.sh --skip-pyinstaller   # repackage existing dist/RawView/
#
# Run the result:
#   chmod +x dist_installer/RawView-*.AppImage
#   ./dist_installer/RawView-*.AppImage
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# ── args ──────────────────────────────────────────────────────────────────────
SKIP_PYINSTALLER=0
for arg in "$@"; do
    case "$arg" in
        --skip-pyinstaller) SKIP_PYINSTALLER=1 ;;
        -h|--help) echo "Usage: bash build-appimage.sh [--skip-pyinstaller]"; exit 0 ;;
    esac
done

# ── version ───────────────────────────────────────────────────────────────────
VERSION=$(grep -m1 'version\s*=' pyproject.toml | sed 's/.*"\(.*\)".*/\1/')
ARCH="x86_64"
APPIMAGE_FILENAME="RawView-${VERSION}-${ARCH}.AppImage"
DIST_BUNDLE="$SCRIPT_DIR/dist/RawView"
OUT_DIR="$SCRIPT_DIR/dist_installer"
TOOLS_DIR="$SCRIPT_DIR/build_tools"
APPIMAGETOOL="$TOOLS_DIR/appimagetool-x86_64.AppImage"
APPDIR="$SCRIPT_DIR/dist_installer/RawView.AppDir"

echo "=== RawView AppImage build ==="
echo "Version : $VERSION"
echo "Output  : $OUT_DIR/$APPIMAGE_FILENAME"
echo ""

# ── step 1: appimagetool ──────────────────────────────────────────────────────
if [ ! -x "$APPIMAGETOOL" ]; then
    mkdir -p "$TOOLS_DIR"
    echo "[tool] Downloading appimagetool..."
    curl -L --progress-bar \
        -o "$APPIMAGETOOL" \
        "https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-x86_64.AppImage"
    chmod +x "$APPIMAGETOOL"
    echo "[tool] appimagetool saved to $APPIMAGETOOL"
fi

# ── step 2: PyInstaller ───────────────────────────────────────────────────────
if [ "$SKIP_PYINSTALLER" -eq 0 ]; then
    echo "[1/3] Running PyInstaller..."
    bash "$SCRIPT_DIR/build-linux.sh"
else
    echo "[1/3] Skipping PyInstaller (--skip-pyinstaller)."
fi

if [ ! -f "$DIST_BUNDLE/RawView" ]; then
    echo "ERROR: $DIST_BUNDLE/RawView not found."
    echo "       Run without --skip-pyinstaller, or run build-linux.sh first."
    exit 1
fi

# ── step 3: AppDir ────────────────────────────────────────────────────────────
echo "[2/3] Building AppDir..."
rm -rf "$APPDIR"
mkdir -p "$APPDIR"

# Copy PyInstaller bundle into AppDir root
cp -r "$DIST_BUNDLE/." "$APPDIR/"

# AppRun - required entry point
cat > "$APPDIR/AppRun" << 'APPRUN'
#!/bin/sh
HERE="$(cd "$(dirname "$0")" && pwd)"
exec "$HERE/RawView" "$@"
APPRUN
chmod 755 "$APPDIR/AppRun"

# Desktop file - must be at AppDir root; Exec= must be just the binary name
cat > "$APPDIR/rawview.desktop" << DESKTOP
[Desktop Entry]
Version=1.0
Type=Application
Name=RawView
Comment=Qt + Ghidra reverse engineering desktop UI
Exec=RawView
Icon=rawview
Terminal=false
Categories=Development;Debugger;
Keywords=reverse;engineering;ghidra;disassembler;decompiler;binary;
StartupWMClass=RawView
DESKTOP
chmod 644 "$APPDIR/rawview.desktop"

# Icon - filename (without extension) must match Icon= field above
if [ -f "$SCRIPT_DIR/rawview/qt_ui/resources/app_icon.png" ]; then
    cp "$SCRIPT_DIR/rawview/qt_ui/resources/app_icon.png" "$APPDIR/rawview.png"
fi

# Fix permissions
find "$APPDIR" -type d -exec chmod 755 {} \;
find "$APPDIR" -type f -exec chmod 644 {} \;
chmod 755 "$APPDIR/AppRun" "$APPDIR/RawView"
find "$APPDIR" -type f -name "*.so*" -exec chmod 755 {} \;
# ELF executables without extension
find "$APPDIR" -type f ! -name "*.*" ! -name "AppRun" ! -name "RawView" | while read -r f; do
    if file "$f" 2>/dev/null | grep -qE 'ELF.*(executable|shared object)'; then
        chmod 755 "$f"
    fi
done

# ── step 4: package ───────────────────────────────────────────────────────────
echo "[3/3] Running appimagetool..."
mkdir -p "$OUT_DIR"
# APPIMAGE_EXTRACT_AND_RUN avoids needing FUSE to run the tool itself
ARCH="$ARCH" APPIMAGE_EXTRACT_AND_RUN=1 \
    "$APPIMAGETOOL" "$APPDIR" "$OUT_DIR/$APPIMAGE_FILENAME" 2>&1

echo ""
echo "Done: $OUT_DIR/$APPIMAGE_FILENAME"
echo ""
echo "Run:"
echo "  chmod +x $OUT_DIR/$APPIMAGE_FILENAME"
echo "  $OUT_DIR/$APPIMAGE_FILENAME"

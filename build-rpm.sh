#!/usr/bin/env bash
# Build RawView as an RPM package (Fedora, RHEL, openSUSE, etc.).
# Uses 'alien' to convert the .deb to .rpm (builds .deb first if needed).
# alien is available on all Debian/Ubuntu systems: sudo apt-get install alien
#
# Usage (repo root, venv active):
#   source .venv/bin/activate
#   bash build-rpm.sh                      # full build
#   bash build-rpm.sh --skip-pyinstaller   # repackage existing dist/RawView/
#
# Install the result:
#   sudo dnf install dist_installer/rawview-*.rpm
#   sudo rpm -i dist_installer/rawview-*.rpm
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# ── args ──────────────────────────────────────────────────────────────────────
SKIP_PYINSTALLER=0
for arg in "$@"; do
    case "$arg" in
        --skip-pyinstaller) SKIP_PYINSTALLER=1 ;;
        -h|--help) echo "Usage: bash build-rpm.sh [--skip-pyinstaller]"; exit 0 ;;
    esac
done

# ── version ───────────────────────────────────────────────────────────────────
VERSION=$(grep -m1 'version\s*=' pyproject.toml | sed 's/.*"\(.*\)".*/\1/')
ARCH="x86_64"
OUT_DIR="$SCRIPT_DIR/dist_installer"
DEB_FILE="$OUT_DIR/rawview_${VERSION}_amd64.deb"

echo "=== RawView RPM build ==="
echo "Version : $VERSION"
echo "Output  : $OUT_DIR/"
echo ""

# ── step 1: check alien ───────────────────────────────────────────────────────
if ! command -v alien &>/dev/null; then
    echo "[prereq] alien not found - installing..."
    sudo apt-get install -y alien
fi

# ── step 2: ensure .deb exists ───────────────────────────────────────────────
if [ ! -f "$DEB_FILE" ]; then
    echo "[1/2] .deb not found - building it first..."
    bash "$SCRIPT_DIR/build-deb.sh" $([ "$SKIP_PYINSTALLER" -eq 1 ] && echo "--skip-pyinstaller" || true)
else
    echo "[1/2] Using existing $DEB_FILE"
fi

# ── step 3: convert .deb → .rpm ──────────────────────────────────────────────
echo "[2/2] Converting .deb to .rpm with alien..."
mkdir -p "$OUT_DIR"
# alien outputs the .rpm in the current directory, so cd there
cd "$OUT_DIR"
sudo alien --to-rpm --scripts "$DEB_FILE"

RPM_FILE=$(ls rawview-*.rpm 2>/dev/null | head -1)
if [ -z "$RPM_FILE" ]; then
    echo "ERROR: alien did not produce an .rpm file."
    exit 1
fi

echo ""
echo "Done: $OUT_DIR/$RPM_FILE"
echo ""
echo "Install:"
echo "  sudo dnf install $OUT_DIR/$RPM_FILE"
echo "  sudo rpm -i $OUT_DIR/$RPM_FILE"

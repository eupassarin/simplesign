#!/usr/bin/env bash
# SimpleSign - Install HostSigner from GitHub Releases (macOS/Linux)
# Downloads the latest (or specified) release and installs to ~/.local/share/SimpleSign/HostSigner
# No .NET SDK required — the download is self-contained.
#
# Usage:
#   curl -sL https://raw.githubusercontent.com/eupassarin/SimpleSign/main/scripts/install/install-hostsigner.sh | bash
#   ./install-hostsigner.sh                   # latest release
#   ./install-hostsigner.sh 0.7.0            # specific version

set -euo pipefail

VERSION="${1:-}"

REPO="eupassarin/SimpleSign"
INSTALL_DIR="$HOME/.local/share/SimpleSign/HostSigner"
EXE_NAME="simplesign-hostsigner"

step() { tput setaf 6; echo; echo "-> $*"; tput sgr0; }
ok()   { tput setaf 2; echo "  [OK] $*"; tput sgr0; }
err()  { tput setaf 1; echo "  [X] $*"; tput sgr0; }
dim()  { tput setaf 8; echo "$*"; tput sgr0; }

# Detect platform
ARCH=$(uname -m)
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$OS" in
    linux)  RID="linux";;
    darwin) RID="osx";;
    *)      err "Unsupported OS: $OS"; exit 1;;
esac
case "$ARCH" in
    x86_64|amd64) RID="$RID-x64";;
    aarch64|arm64) RID="$RID-arm64";;
    *)      err "Unsupported arch: $ARCH"; exit 1;;
esac

ASSET_NAME="simplesign-hostsigner-$RID.zip"

echo
step "SimpleSign - Install HostSigner"
echo "==============================="
echo

# 1. Resolve release
step "Finding release..."
RELEASE_URL="https://api.github.com/repos/$REPO/releases/latest"
if [ -n "$VERSION" ]; then
    RELEASE_URL="https://api.github.com/repos/$REPO/releases/tags/v$VERSION"
fi

JSON=$(curl -sL "$RELEASE_URL" 2>/dev/null || true)
TAG=$(echo "$JSON" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('tag_name',''))" 2>/dev/null || echo "")
if [ -z "$TAG" ]; then
    err "Could not find release. Check the version or your internet connection."
    dim "URL: $RELEASE_URL"
    exit 1
fi
ok "Found release $TAG"

# 2. Find the HostSigner asset
DOWNLOAD_URL=$(echo "$JSON" | python3 -c "
import sys,json
data = json.load(sys.stdin)
for a in data.get('assets', []):
    if a['name'] == '$ASSET_NAME':
        print(a['browser_download_url'])
" 2>/dev/null)

if [ -z "$DOWNLOAD_URL" ]; then
    err "Asset '$ASSET_NAME' not found in release $TAG"
    dim "Available assets:"
    echo "$JSON" | python3 -c "
import sys,json
data = json.load(sys.stdin)
for a in data.get('assets', []):
    print(f'    - {a[\"name\"]}')
" 2>/dev/null || true
    exit 1
fi
SIZE_KB=$(echo "$JSON" | python3 -c "
import sys,json
data = json.load(sys.stdin)
for a in data.get('assets', []):
    if a['name'] == '$ASSET_NAME':
        print(round(a['size'] / 1024))
" 2>/dev/null || echo "?")
ok "Asset: $ASSET_NAME (${SIZE_KB} KB)"

# 3. Download
TEMP_ZIP="/tmp/simplesign-hostsigner-$TAG.zip"
step "Downloading $TAG..."
curl -sL "$DOWNLOAD_URL" -o "$TEMP_ZIP"
ok "Downloaded to $TEMP_ZIP"

# 4. Stop running instance
RUNNING_PID=$(pgrep -x "$EXE_NAME" 2>/dev/null || echo "")
if [ -n "$RUNNING_PID" ]; then
    step "Stopping running HostSigner..."
    pkill -x "$EXE_NAME" 2>/dev/null || true
    sleep 2
    ok "Stopped"
fi

# 5. Extract to install dir
step "Installing to $INSTALL_DIR..."
rm -rf "$INSTALL_DIR"
mkdir -p "$INSTALL_DIR"
unzip -oq "$TEMP_ZIP" -d "$INSTALL_DIR"
ok "Extracted"

# 6. Clean up download
rm -f "$TEMP_ZIP"

# 7. Verify
step "Verifying installation..."
EXE_PATH="$INSTALL_DIR/$EXE_NAME"
if [ -f "$EXE_PATH" ]; then
    SIZE_MB=$(du -h "$EXE_PATH" | cut -f1)
    ok "Executable found ($SIZE_MB MB)"
else
    err "Executable not found at $EXE_PATH"
    exit 1
fi

# 8. Done
echo
tput setaf 2; echo "  HostSigner $TAG installed successfully!"; tput sgr0
echo
dim "  Location: $EXE_PATH"
dim "  API      : http://localhost:21590"
echo
dim "  Start    : $EXE_PATH &"
dim "  Test     : curl -s http://localhost:21590/api/health"
echo

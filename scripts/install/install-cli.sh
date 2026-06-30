#!/usr/bin/env bash
# SimpleSign CLI - Install from GitHub Releases (macOS/Linux)
# Downloads the latest (or specified) release and installs to ~/.local/share/SimpleSign/Cli
#
# Usage:
#   curl -sL https://raw.githubusercontent.com/eupassarin/SimpleSign/main/scripts/install/install-cli.sh | bash
#   ./install-cli.sh                   # latest release
#   ./install-cli.sh 0.7.0            # specific version

set -euo pipefail

VERSION="${1:-}"

REPO="eupassarin/SimpleSign"
INSTALL_DIR="$HOME/.local/share/SimpleSign/Cli"
LAUNCHER_NAME="simplesign"

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

ASSET_NAME="simplesign-$RID.zip"

echo
step "SimpleSign CLI - Install"
echo "========================"
echo

# 1. Resolve release
step "Finding release..."
RELEASE_URL="https://api.github.com/repos/$REPO/releases/latest"
TAG="latest"
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

# 2. Find the CLI asset
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
TEMP_ZIP="/tmp/simplesign-$TAG.zip"
step "Downloading $TAG..."
curl -sL "$DOWNLOAD_URL" -o "$TEMP_ZIP"
ok "Downloaded to $TEMP_ZIP"

# 4. Extract to install dir
step "Installing to $INSTALL_DIR..."
rm -rf "$INSTALL_DIR"
mkdir -p "$INSTALL_DIR"
unzip -oq "$TEMP_ZIP" -d "$INSTALL_DIR"
ok "Extracted"

# 5. Clean up download
rm -f "$TEMP_ZIP"

# 6. Create launcher
step "Setting up launcher..."
LAUNCHER_DIR="$HOME/.local/bin"
mkdir -p "$LAUNCHER_DIR"
LAUNCHER_PATH="$LAUNCHER_DIR/$LAUNCHER_NAME"

EXE_PATH="$INSTALL_DIR/$LAUNCHER_NAME"
DLL_PATH="$INSTALL_DIR/$LAUNCHER_NAME.dll"

if [ -f "$EXE_PATH" ]; then
    # Self-contained publish
    cat > "$LAUNCHER_PATH" << LAUNCHER
#!/usr/bin/env bash
exec "$EXE_PATH" "\$@"
LAUNCHER
    chmod +x "$LAUNCHER_PATH"
    ok "Self-contained executable found"
elif [ -f "$DLL_PATH" ]; then
    # Framework-dependent — create wrapper
    cat > "$LAUNCHER_PATH" << LAUNCHER
#!/usr/bin/env bash
exec dotnet "$DLL_PATH" "\$@"
LAUNCHER
    chmod +x "$LAUNCHER_PATH"
    ok "Created launcher: $LAUNCHER_PATH (requires .NET runtime)"
else
    err "Neither $LAUNCHER_NAME nor $LAUNCHER_NAME.dll found in package"
    exit 1
fi

# 7. Add to PATH
step "Checking PATH..."
case ":${PATH}:" in
    *:"$LAUNCHER_DIR":*)
        ok "Already in PATH."
        ;;
    *)
        # Add to shell profile
        PROFILE_FILE=""
        case "${SHELL:-}" in
            */zsh) PROFILE_FILE="$HOME/.zshrc";;
            */bash) PROFILE_FILE="$HOME/.bashrc";;
        esac
        if [ -n "$PROFILE_FILE" ]; then
            echo "export PATH=\"\$PATH:$LAUNCHER_DIR\"" >> "$PROFILE_FILE"
            ok "Added to PATH in $PROFILE_FILE"
            dim "  Run 'source $PROFILE_FILE' or open a new terminal."
        else
            err "Add $LAUNCHER_DIR to your PATH manually."
        fi
        ;;
esac

# 8. Verify
step "Verifying installation..."
if [ -f "$LAUNCHER_PATH" ]; then
    ok "Installed: $LAUNCHER_PATH"
else
    err "Installation verification failed."
    exit 1
fi

# 9. Done
echo
tput setaf 2; echo "  SimpleSign CLI $TAG installed successfully!"; tput sgr0
echo
dim "  Location : $INSTALL_DIR"
dim "  Run      : $LAUNCHER_NAME --help"
echo

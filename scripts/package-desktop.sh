#!/usr/bin/env bash
# Packages SimpleSign Desktop (self-contained) for one runtime:
#   osx-arm64 / osx-x64  → SimpleSign-<version>-<rid>.zip with SimpleSign.app
#   linux-x64 / linux-arm64 → SimpleSign-<version>-<rid>.tar.gz
# Usage: scripts/package-desktop.sh <rid> [version] [output-dir]
# The app is not code-signed or notarized: on macOS, the first launch needs right-click → Open.
set -euo pipefail

rid="${1:?usage: package-desktop.sh <rid> [version] [output-dir]}"
version="${2:-0.0.0-dev}"
repo="$(cd "$(dirname "$0")/.." && pwd)"
out="${3:-$repo/artifacts/desktop}"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$out"

dotnet publish "$repo/src/SimpleSign.Desktop/SimpleSign.Desktop.csproj" -c Release -r "$rid" --self-contained true \
  -p:Version="$version" -p:PublishSingleFile=false -o "$tmp/publish"

case "$rid" in
  osx-*)
    app="$tmp/SimpleSign.app"
    mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
    cp -R "$tmp/publish/." "$app/Contents/MacOS/"
    if command -v sips >/dev/null && command -v iconutil >/dev/null; then
      iconset="$tmp/SimpleSign.iconset"
      mkdir -p "$iconset"
      for size in 16 32 128 256 512; do
        sips -z $size $size "$repo/assets/icon.png" --out "$iconset/icon_${size}x${size}.png" >/dev/null
        sips -z $((size * 2)) $((size * 2)) "$repo/assets/icon.png" --out "$iconset/icon_${size}x${size}@2x.png" >/dev/null
      done
      iconutil -c icns "$iconset" -o "$app/Contents/Resources/SimpleSign.icns"
    fi
    cat > "$app/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key><string>SimpleSign</string>
  <key>CFBundleDisplayName</key><string>SimpleSign</string>
  <key>CFBundleIdentifier</key><string>io.github.eupassarin.simplesign</string>
  <key>CFBundleExecutable</key><string>SimpleSign</string>
  <key>CFBundleIconFile</key><string>SimpleSign</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>${version}</string>
  <key>CFBundleVersion</key><string>${version}</string>
  <key>LSMinimumSystemVersion</key><string>12.0</string>
  <key>NSHighResolutionCapable</key><true/>
  <key>LSUIElement</key><false/>
</dict>
</plist>
PLIST
    target="$out/SimpleSign-$version-$rid.zip"
    rm -f "$target"
    if command -v ditto >/dev/null; then
      ditto -c -k --keepParent "$app" "$target"
    else
      (cd "$tmp" && zip -qr "$target" SimpleSign.app)
    fi
    ;;
  linux-*)
    target="$out/SimpleSign-$version-$rid.tar.gz"
    tar -C "$tmp/publish" -czf "$target" .
    ;;
  *)
    echo "Use the release workflow (Compress-Archive) for $rid." >&2
    exit 1
    ;;
esac

echo "Wrote $target"

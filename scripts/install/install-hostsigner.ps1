# SimpleSign - Install HostSigner from GitHub Releases (Windows)
# Downloads the latest (or specified) release and installs to %LOCALAPPDATA%\SimpleSign\HostSigner
# Registers the simplesign:// protocol handler for the current user.
# No .NET SDK required — the download is self-contained.
#
# Usage:
#   irm https://raw.githubusercontent.com/eupassarin/SimpleSign/main/scripts/install/install-hostsigner.ps1 | iex
#   .\install-hostsigner.ps1                     # latest release
#   .\install-hostsigner.ps1 -Version 0.1.0      # specific version

#Requires -Version 5.1
param(
    [string]$Version = ""
)

$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$repo = "eupassarin/SimpleSign"
$assetName = "simplesign-hostsigner-win-x64.zip"
$installDir = Join-Path $env:LOCALAPPDATA "SimpleSign\HostSigner"
$exeName = "simplesign-hostsigner.exe"

function Write-Step($m) { Write-Host "`n-> $m" -ForegroundColor Cyan }
function Write-Ok($m) { Write-Host "  [OK] $m" -ForegroundColor Green }
function Write-Err($m) { Write-Host "  [X] $m" -ForegroundColor Red }

Write-Host ""
Write-Host "SimpleSign - Install HostSigner" -ForegroundColor Cyan
Write-Host "===============================" -ForegroundColor Cyan
Write-Host ""

# 1. Resolve release
Write-Step "Finding release..."
if ($Version) {
    $releaseUrl = "https://api.github.com/repos/$repo/releases/tags/v$Version"
} else {
    $releaseUrl = "https://api.github.com/repos/$repo/releases/latest"
}

try {
    $release = Invoke-RestMethod -Uri $releaseUrl -Headers @{ Accept = "application/vnd.github.v3+json" }
} catch {
    Write-Err "Could not find release. Check the version or your internet connection."
    Write-Host "  URL: $releaseUrl" -ForegroundColor DarkGray
    exit 1
}

$tag = $release.tag_name
Write-Ok "Found release $tag"

# 2. Find the HostSigner asset
$asset = $release.assets | Where-Object { $_.name -eq $assetName }
if (-not $asset) {
    Write-Err "Asset '$assetName' not found in release $tag"
    Write-Host "  Available assets:" -ForegroundColor DarkGray
    $release.assets | ForEach-Object { Write-Host "    - $($_.name)" -ForegroundColor DarkGray }
    exit 1
}

$downloadUrl = $asset.browser_download_url
$sizeKB = [math]::Round($asset.size / 1KB)
Write-Ok "Asset: $assetName ($sizeKB KB)"

# 3. Download
$tempZip = Join-Path $env:TEMP "simplesign-hostsigner-$tag.zip"
Write-Step "Downloading $tag..."
try {
    Invoke-WebRequest -Uri $downloadUrl -OutFile $tempZip -UseBasicParsing
} catch {
    Write-Err "Download failed: $_"
    exit 1
}
Write-Ok "Downloaded to $tempZip"

# 4. Stop running instance
$running = Get-Process -Name "simplesign-hostsigner" -ErrorAction SilentlyContinue
if ($running) {
    Write-Step "Stopping running HostSigner..."
    $running | ForEach-Object { Stop-Process -Id $_.Id -Force }
    Start-Sleep -Seconds 2
    Write-Ok "Stopped"
}

# 5. Extract to install dir
Write-Step "Installing to $installDir..."
if (Test-Path $installDir) { Remove-Item $installDir -Recurse -Force }
New-Item -ItemType Directory -Path $installDir -Force | Out-Null
Expand-Archive -Path $tempZip -DestinationPath $installDir -Force
Write-Ok "Extracted"

# 6. Clean up download
Remove-Item $tempZip -Force -ErrorAction SilentlyContinue

# 7. Unblock files
Write-Step "Unblocking files..."
Get-ChildItem $installDir -Recurse | Unblock-File -ErrorAction SilentlyContinue
Write-Ok "Files unblocked"

# 8. Register simplesign:// protocol handler (HKCU — no admin needed)
$exePath = Join-Path $installDir $exeName
Write-Step "Registering simplesign:// protocol..."
$protocolKey = "HKCU:\Software\Classes\simplesign"
New-Item -Path $protocolKey -Force | Out-Null
Set-ItemProperty -Path $protocolKey -Name "(Default)" -Value "SimpleSign HostSigner"
Set-ItemProperty -Path $protocolKey -Name "URL Protocol" -Value ""
New-Item -Path "$protocolKey\DefaultIcon" -Force | Out-Null
Set-ItemProperty -Path "$protocolKey\DefaultIcon" -Name "(Default)" -Value "$exePath,0"
New-Item -Path "$protocolKey\shell\open\command" -Force | Out-Null
Set-ItemProperty -Path "$protocolKey\shell\open\command" -Name "(Default)" -Value "`"$exePath`" `"%1`""
Write-Ok "Protocol registered"

# 9. Verify
Write-Step "Verifying installation..."
if (Test-Path $exePath) {
    $sizeMB = [math]::Round((Get-Item $exePath).Length / 1MB, 1)
    Write-Ok "Executable found ($sizeMB MB)"
} else {
    Write-Err "Executable not found at $exePath"
    exit 1
}

# 10. Done
Write-Host ""
Write-Host "  HostSigner $tag installed successfully!" -ForegroundColor Green
Write-Host ""
Write-Host "  Location : $exePath" -ForegroundColor DarkGray
Write-Host "  Protocol : simplesign://" -ForegroundColor DarkGray
Write-Host "  API      : http://localhost:21590" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  Start    : & `"$exePath`"" -ForegroundColor DarkGray
Write-Host "  Test     : Invoke-RestMethod http://localhost:21590/api/health" -ForegroundColor DarkGray
Write-Host ""

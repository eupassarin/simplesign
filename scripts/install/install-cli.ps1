# SimpleSign CLI - Install from GitHub Releases (Windows)
# Downloads the latest (or specified) release and installs to %LOCALAPPDATA%\SimpleSign\Cli
#
# Usage:
#   irm https://raw.githubusercontent.com/eupassarin/SimpleSign/main/scripts/install/install-cli.ps1 | iex
#   .\install-cli.ps1                     # latest release
#   .\install-cli.ps1 -Version 0.1.0      # specific version

#Requires -Version 5.1
param(
    [string]$Version = ""
)

$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$repo = "eupassarin/SimpleSign"
$assetName = "simplesign-win-x64.zip"
$installDir = Join-Path $env:LOCALAPPDATA "SimpleSign\Cli"
$launcherName = "simplesign"

function Write-Step($m) { Write-Host "`n-> $m" -ForegroundColor Cyan }
function Write-Ok($m) { Write-Host "  [OK] $m" -ForegroundColor Green }
function Write-Err($m) { Write-Host "  [X] $m" -ForegroundColor Red }

Write-Host ""
Write-Host "SimpleSign CLI - Install" -ForegroundColor Cyan
Write-Host "========================" -ForegroundColor Cyan
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

# 2. Find the CLI asset
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
$tempZip = Join-Path $env:TEMP "simplesign-$tag.zip"
Write-Step "Downloading $tag..."
try {
    Invoke-WebRequest -Uri $downloadUrl -OutFile $tempZip -UseBasicParsing
} catch {
    Write-Err "Download failed: $_"
    exit 1
}
Write-Ok "Downloaded to $tempZip"

# 4. Extract to install dir
Write-Step "Installing to $installDir..."
if (Test-Path $installDir) { Remove-Item $installDir -Recurse -Force }
New-Item -ItemType Directory -Path $installDir -Force | Out-Null
Expand-Archive -Path $tempZip -DestinationPath $installDir -Force
Write-Ok "Extracted"

# 5. Clean up download
Remove-Item $tempZip -Force -ErrorAction SilentlyContinue

# 6. Unblock files
Write-Step "Unblocking files..."
Get-ChildItem $installDir -Recurse | Unblock-File -ErrorAction SilentlyContinue
Write-Ok "Files unblocked"

# 7. Create launcher (.cmd wrapper) if needed
Write-Step "Setting up launcher..."
$exePath = Join-Path $installDir "$launcherName.exe"
$dllPath = Join-Path $installDir "$launcherName.dll"

if (Test-Path $exePath) {
    # Self-contained publish — exe already present
    Write-Ok "Self-contained executable found"
} elseif (Test-Path $dllPath) {
    # Framework-dependent — create .cmd wrapper
    $cmdPath = Join-Path $installDir "$launcherName.cmd"
    $cmdContent = "@echo off`r`ndotnet exec `"$dllPath`" %*"
    Set-Content -Path $cmdPath -Value $cmdContent -Encoding ASCII
    Write-Ok "Created launcher: $launcherName.cmd (requires .NET runtime)"
} else {
    Write-Err "Neither $launcherName.exe nor $launcherName.dll found in package"
    exit 1
}

# 8. Add to PATH
Write-Step "Checking PATH..."
$userPath = [Environment]::GetEnvironmentVariable("PATH", "User")
if ($userPath -split ";" | Where-Object { $_ -eq $installDir }) {
    Write-Ok "Already in PATH."
} else {
    [Environment]::SetEnvironmentVariable("PATH", "$userPath;$installDir", "User")
    Write-Ok "Added to user PATH."
    Write-Host "  Note: Open a new terminal for PATH to take effect." -ForegroundColor Gray
}

# 9. Verify
Write-Step "Verifying installation..."
$installed = if (Test-Path $exePath) { $exePath } else { Join-Path $installDir "$launcherName.cmd" }
if (Test-Path $installed) {
    Write-Ok "Installed: $installed"
} else {
    Write-Err "Installation verification failed."
    exit 1
}

# 10. Done
Write-Host ""
Write-Host "  SimpleSign CLI $tag installed successfully!" -ForegroundColor Green
Write-Host ""
Write-Host "  Location : $installDir" -ForegroundColor DarkGray
Write-Host "  Run      : simplesign --help" -ForegroundColor DarkGray
Write-Host ""

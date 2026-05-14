# SimpleSign - Install HostSigner Locally (Windows)
# Builds from source and installs the HostSigner tray app to %LOCALAPPDATA%\SimpleSign\HostSigner
# Registers the simplesign:// protocol handler for the current user.
# Requires: .NET 8 SDK
# Usage: .\install-hostsigner-local.ps1

#Requires -Version 5.1
$ErrorActionPreference = "Stop"

$repoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$projectDir = Join-Path $repoRoot "src\SimpleSign.HostSigner"
$publishDir = Join-Path $projectDir "bin\publish-local"
$installDir = Join-Path $env:LOCALAPPDATA "SimpleSign\HostSigner"
$exeName = "simplesign-hostsigner.exe"

function Write-Step($m) { Write-Host "`n-> $m" -ForegroundColor Cyan }
function Write-Ok($m) { Write-Host "  [OK] $m" -ForegroundColor Green }
function Write-Err($m) { Write-Host "  [X] $m" -ForegroundColor Red }

Write-Host ""
Write-Host "SimpleSign - Install HostSigner (local build)" -ForegroundColor Cyan
Write-Host "==============================================" -ForegroundColor Cyan
Write-Host ""

if (-not (Test-Path $projectDir)) {
    Write-Err "Project directory not found: $projectDir"
    exit 1
}

# 1. Publish self-contained single-file
Write-Step "Publishing HostSigner (self-contained, single-file)..."
dotnet publish $projectDir `
    -c Release `
    -f net8.0-windows `
    -r win-x64 `
    --self-contained true `
    -p:PublishSingleFile=true `
    -p:IncludeNativeLibrariesForSelfExtract=true `
    -o $publishDir `
    -v quiet
if ($LASTEXITCODE -ne 0) { Write-Err "Publish failed."; exit 1 }
Write-Ok "Published to $publishDir"

# 2. Stop running instance
$running = Get-Process -Name "simplesign-hostsigner" -ErrorAction SilentlyContinue
if ($running) {
    Write-Step "Stopping running HostSigner instance..."
    $running | ForEach-Object { Stop-Process -Id $_.Id -Force }
    Start-Sleep -Seconds 2
    Write-Ok "Stopped"
}

# 3. Copy to install dir
Write-Step "Installing to $installDir..."
if (Test-Path $installDir) { Remove-Item $installDir -Recurse -Force }
New-Item -ItemType Directory -Path $installDir -Force | Out-Null
Copy-Item -Path "$publishDir\*" -Destination $installDir -Recurse -Force
Write-Ok "Installed"

# 4. Clean up publish output
Remove-Item $publishDir -Recurse -Force -ErrorAction SilentlyContinue
Write-Ok "Cleaned up publish artifacts"

# 5. Unblock files (Windows may block copied executables)
Write-Step "Unblocking files..."
Get-ChildItem $installDir -Recurse | Unblock-File -ErrorAction SilentlyContinue
Write-Ok "Files unblocked"

# 6. Register simplesign:// protocol handler (HKCU — no admin needed)
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

# 7. Verify
Write-Step "Verifying installation..."
if (Test-Path $exePath) {
    $size = [math]::Round((Get-Item $exePath).Length / 1MB, 1)
    Write-Ok "Executable found ($size MB)"
} else {
    Write-Err "Executable not found at $exePath"
    exit 1
}

# 8. Done
Write-Host ""
Write-Host "  HostSigner installed successfully!" -ForegroundColor Green
Write-Host ""
Write-Host "  Location : $exePath" -ForegroundColor DarkGray
Write-Host "  Protocol : simplesign://" -ForegroundColor DarkGray
Write-Host "  API      : http://localhost:21590" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  Start    : & `"$exePath`"" -ForegroundColor DarkGray
Write-Host "  Test     : Invoke-RestMethod http://localhost:21590/api/health" -ForegroundColor DarkGray
Write-Host ""

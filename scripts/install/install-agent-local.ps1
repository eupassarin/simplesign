# SimpleSign - Install Tauri Agent Locally (Windows)
# Builds the Tauri project and installs the agent to %LOCALAPPDATA%\SimpleSign\Agent
# Requires: Node.js, Rust toolchain, and tauri prerequisites. Run as normal user.
#Usage: .\install-agent-local.ps1

#Requires -Version 5.1
$ErrorActionPreference = "Stop"

$repoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$agentDir = Join-Path $repoRoot "src\SimpleSign.Agent"
$releaseExe = Join-Path $agentDir "src-tauri\target\release\simplesign-agent.exe"
$installDir = Join-Path $env:LOCALAPPDATA "SimpleSign\Agent"
$exeName = "simplesign-agent.exe"
$exePath = Join-Path $installDir $exeName

function Write-Step($m){ Write-Host "`n-> $m" -ForegroundColor Cyan }
function Write-Ok($m){ Write-Host "  [OK] $m" -ForegroundColor Green }
function Write-Err($m){ Write-Host "  [X] $m" -ForegroundColor Red }

Write-Host ""
Write-Host "SimpleSign - Install Tauri Agent (local)" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

if (-not (Test-Path $agentDir)) {
    Write-Err "Agent directory not found: $agentDir"
    exit 1
}

# 1. Frontend install
Write-Step "Installing frontend dependencies (npm)..."
Push-Location $agentDir
try {
    $node = Get-Command npm -ErrorAction SilentlyContinue
    if (-not $node) { Write-Err "npm not found. Install Node.js (LTS) first."; exit 1 }

    npm ci --silent
    if ($LASTEXITCODE -ne 0) { Write-Err "npm ci failed."; exit 1 }
    Write-Ok "npm dependencies installed"

    # 2. Build Tauri (frontend + Rust release binary, no installer bundle)
    Write-Step "Building Tauri release binary..."
    npm run tauri build -- --no-bundle
    if ($LASTEXITCODE -ne 0) { Write-Err "Tauri build failed."; exit 1 }
    Write-Ok "Tauri build complete"
} finally {
    Pop-Location
}

# 3. Verify release executable exists
Write-Step "Locating release executable..."
if (-not (Test-Path $releaseExe)) {
    Write-Err "Release executable not found: $releaseExe"
    exit 1
}
Write-Ok "Found: $releaseExe"

# 4. Stop running instance if any
$running = Get-Process -Name "simplesign-agent" -ErrorAction SilentlyContinue
if ($running) {
    Write-Step "Stopping running Agent instance..."
    Stop-Process -Id $running.Id -Force
    Start-Sleep -Seconds 1
    Write-Ok "Stopped"
}

# 5. Install (copy)
Write-Step "Installing to $installDir..."
if (-not (Test-Path $installDir)) { New-Item -ItemType Directory -Path $installDir -Force | Out-Null }
Copy-Item -Path $releaseExe -Destination $exePath -Force
Unblock-File -Path $exePath -ErrorAction SilentlyContinue
Write-Ok "Installed: $exePath"

# 6. Register protocol handler simplesign://
Write-Step "Registering simplesign:// protocol..."
$protocolKey = "HKCU:\Software\Classes\simplesign"
New-Item -Path $protocolKey -Force | Out-Null
Set-ItemProperty -Path $protocolKey -Name "(Default)" -Value "SimpleSign Agent"
Set-ItemProperty -Path $protocolKey -Name "URL Protocol" -Value ""
New-Item -Path "$protocolKey\DefaultIcon" -Force | Out-Null
Set-ItemProperty -Path "$protocolKey\DefaultIcon" -Name "(Default)" -Value "$exePath,0"
New-Item -Path "$protocolKey\shell\open\command" -Force | Out-Null
Set-ItemProperty -Path "$protocolKey\shell\open\command" -Name "(Default)" -Value "`"$exePath`" `"%1`""
Write-Ok "Protocol registered"

Write-Host ""
Write-Ok "Agent installed and simplesign:// protocol registered."
Write-Host "  Test: simplesign-cli sign test.pdf --agent" -ForegroundColor DarkGray

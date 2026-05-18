# SimpleSign CLI - Local Build & Install
# Usage: .\install-cli-local.ps1
# Builds the CLI from source and installs to %LOCALAPPDATA%\SimpleSign\Cli

#Requires -Version 5.1
$ErrorActionPreference = "Stop"

$repoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$publishDir = Join-Path $repoRoot "publish-cli-local"
$installDir = Join-Path $env:LOCALAPPDATA "SimpleSign\Cli"
$launcherPath = Join-Path $installDir "simplesign.cmd"

Write-Host ""
Write-Host "SimpleSign CLI - Local Install" -ForegroundColor Cyan
Write-Host "==============================" -ForegroundColor Cyan
Write-Host "  Source : $repoRoot"
Write-Host "  Install: $installDir"
Write-Host ""

# 1. Clean and publish
Write-Host "1. Building CLI (net8.0)..." -ForegroundColor Yellow
if (Test-Path $publishDir) { Remove-Item $publishDir -Recurse -Force }

dotnet publish "$repoRoot\src\SimpleSign.Cli" -c Release -f net8.0 -o $publishDir -p:UseAppHost=false
if ($LASTEXITCODE -ne 0) {
    Write-Host "  [X] Build failed." -ForegroundColor Red
    exit 1
}

$dll = Join-Path $publishDir "simplesign.dll"
if (-not (Test-Path $dll)) {
    Write-Host "  [X] simplesign.dll not found in output." -ForegroundColor Red
    exit 1
}
Write-Host "  [OK] Built: simplesign.dll" -ForegroundColor Green

# 2. Copy to install folder
Write-Host ""
Write-Host "2. Installing to $installDir..." -ForegroundColor Yellow
if (-not (Test-Path $installDir)) { New-Item -ItemType Directory -Path $installDir -Force | Out-Null }
Copy-Item "$publishDir\*" $installDir -Recurse -Force
Write-Host "  [OK] Files copied." -ForegroundColor Green

# Clean up publish output
Remove-Item $publishDir -Recurse -Force
Write-Host "  [OK] Cleaned publish output." -ForegroundColor Green

# Remove unsigned apphost exe if present (left from old installs or accidental publish)
$staleExe = Join-Path $installDir "simplesign.exe"
if (Test-Path $staleExe) {
    Remove-Item $staleExe -Force
    Write-Host "  [OK] Removed stale simplesign.exe (cmd wrapper takes precedence)." -ForegroundColor Green
}

# 3. Create launcher (.cmd wrapper using dotnet exec)
Write-Host ""
Write-Host "3. Creating launcher..." -ForegroundColor Yellow
$dllInInstall = Join-Path $installDir "simplesign.dll"
$cmdContent = "@echo off`r`ndotnet exec `"$dllInInstall`" %*"
Set-Content -Path $launcherPath -Value $cmdContent -Encoding ASCII
Write-Host "  [OK] Created: simplesign.cmd" -ForegroundColor Green

# 4. Add to PATH
Write-Host ""
Write-Host "4. Checking PATH..." -ForegroundColor Yellow
$userPath = [Environment]::GetEnvironmentVariable("PATH", "User")
if ($userPath -split ";" | Where-Object { $_ -eq $installDir }) {
    Write-Host "  [OK] Already in PATH." -ForegroundColor Green
} else {
    [Environment]::SetEnvironmentVariable("PATH", "$userPath;$installDir", "User")
    Write-Host "  [OK] Added to user PATH." -ForegroundColor Green
    Write-Host "  Note: Open a new terminal for PATH to take effect." -ForegroundColor Gray
}

# 5. Done
Write-Host ""
Write-Host "[OK] Install complete!" -ForegroundColor Green
Write-Host "  Run: simplesign --help" -ForegroundColor Gray
Write-Host ""

# SimpleSign - Run Interop Tests (Docker required)
# Builds Docker images for external validators and runs interop test suite.

#Requires -Version 5.1
$ErrorActionPreference = "Stop"

$repoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$interopDir = Join-Path $repoRoot "interop"

Write-Host ""
Write-Host "SimpleSign - Interop Tests" -ForegroundColor Cyan
Write-Host "==========================" -ForegroundColor Cyan
Write-Host ""

# Check Docker
$dockerVersion = $null
try { $dockerVersion = (docker --version 2>$null) } catch { }
if (-not $dockerVersion) {
    Write-Host "[X] Docker not found. Install Docker Desktop first." -ForegroundColor Red
    exit 1
}
Write-Host "[OK] $dockerVersion" -ForegroundColor Green

# Build images
Write-Host ""
Write-Host "Building Docker images..." -ForegroundColor Yellow

$images = @(
    @{ Name = "simplesign-dss"; Path = "$interopDir\dss-validator" }
    @{ Name = "simplesign-pdfbox"; Path = "$interopDir\pdfbox" }
    @{ Name = "simplesign-eu-dss"; Path = "$interopDir\eu-dss" }
    @{ Name = "simplesign-itext"; Path = "$interopDir\itext" }
)

foreach ($img in $images) {
    Write-Host "  Building $($img.Name)..." -NoNewline
    docker build -t $img.Name $img.Path --quiet 2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Host " OK" -ForegroundColor Green
    } else {
        Write-Host " FAILED" -ForegroundColor Red
        Write-Host "  Run manually: docker build -t $($img.Name) $($img.Path)" -ForegroundColor Gray
    }
}

# Run tests
Write-Host ""
Write-Host "Running interop tests..." -ForegroundColor Yellow
Write-Host ""

Push-Location $repoRoot
try {
    dotnet test tests/interop/SimpleSign.Interop.Tests --filter Category=Interop --logger "console;verbosity=normal"
} finally {
    Pop-Location
}

Write-Host ""
if ($LASTEXITCODE -eq 0) {
    Write-Host "[OK] All interop tests passed!" -ForegroundColor Green
} else {
    Write-Host "[!] Some tests failed (exit code: $LASTEXITCODE)" -ForegroundColor Yellow
}
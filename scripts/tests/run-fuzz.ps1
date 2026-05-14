# SimpleSign - Run Fuzz Tests Locally
# Runs SharpFuzz against all fuzzing targets.
# Usage: .\run-fuzz.ps1 [target] [seconds]
#   target: cms, pdf, dss, timestamp, ocsp (default: all)
#   seconds: duration per target (default: 60)

#Requires -Version 5.1
param(
    [string]$Target = "",
    [int]$Seconds = 60
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$fuzzDir = Join-Path $repoRoot "tests\fuzz\SimpleSign.Fuzz"

Write-Host ""
Write-Host "SimpleSign - Fuzz Testing" -ForegroundColor Cyan
Write-Host "=========================" -ForegroundColor Cyan
Write-Host ""

# Install SharpFuzz CLI if not present
$sharpfuzz = Get-Command SharpFuzz -ErrorAction SilentlyContinue
if (-not $sharpfuzz) {
    Write-Host "Installing SharpFuzz CLI..." -ForegroundColor Yellow
    dotnet tool install -g SharpFuzz.CommandLine
}

$targets = @("cms", "pdf", "dss", "timestamp", "ocsp")
if ($Target) { $targets = @($Target) }

Write-Host "Targets: $($targets -join ', ')" -ForegroundColor Gray
Write-Host "Duration: ${Seconds}s per target" -ForegroundColor Gray
Write-Host ""

Push-Location $fuzzDir
try {
    foreach ($t in $targets) {
        Write-Host "[$t] Fuzzing for ${Seconds}s..." -ForegroundColor Yellow -NoNewline
        dotnet run -c Release -- $t $Seconds 2>$null
        if ($LASTEXITCODE -eq 0) {
            Write-Host " OK" -ForegroundColor Green
        } else {
            Write-Host " CRASH FOUND" -ForegroundColor Red
        }
    }
} finally {
    Pop-Location
}

$findings = Join-Path $fuzzDir "Findings"
if (Test-Path $findings) {
    $crashes = Get-ChildItem $findings -Recurse -File
    if ($crashes.Count -gt 0) {
        Write-Host ""
        Write-Host "[!] $($crashes.Count) crash(es) found in: $findings" -ForegroundColor Red
    }
} else {
    Write-Host ""
    Write-Host "[OK] No crashes found." -ForegroundColor Green
}
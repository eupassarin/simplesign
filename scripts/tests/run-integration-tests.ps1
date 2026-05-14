# SimpleSign - Run Integration Tests
# Runs integration tests that require network access (TSA servers, etc.)

#Requires -Version 5.1
$ErrorActionPreference = "Stop"

$repoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent

Write-Host ""
Write-Host "SimpleSign - Integration Tests" -ForegroundColor Cyan
Write-Host "===============================" -ForegroundColor Cyan
Write-Host ""

Push-Location $repoRoot
try {
    dotnet test tests/integration/SimpleSign.Integration.Tests --logger "console;verbosity=normal"
    dotnet test tests/unit/SimpleSign.Brasil.Tests --filter Category=Integration --logger "console;verbosity=normal"
} finally {
    Pop-Location
}

Write-Host ""
if ($LASTEXITCODE -eq 0) {
    Write-Host "[OK] All integration tests passed!" -ForegroundColor Green
} else {
    Write-Host "[!] Some tests failed (exit code: $LASTEXITCODE)" -ForegroundColor Yellow
}

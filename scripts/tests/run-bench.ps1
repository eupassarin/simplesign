# SimpleSign - Run Benchmarks Locally
# Usage: .\run-bench.ps1 [filter]
#   filter: BenchmarkDotNet filter (default: '*' = all)
#   Example: .\run-bench.ps1 "SigningBenchmarks"

#Requires -Version 5.1
param(
    [string]$Filter = "*"
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$benchDir = Join-Path $repoRoot "bench\SimpleSign.Benchmarks"

Write-Host ""
Write-Host "SimpleSign - Benchmarks" -ForegroundColor Cyan
Write-Host "=======================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Filter: $Filter" -ForegroundColor Gray
Write-Host ""

Push-Location $benchDir
try {
    dotnet run -c Release -- --filter $Filter --exporters json markdown
} finally {
    Pop-Location
}

$artifacts = Join-Path $benchDir "BenchmarkDotNet.Artifacts"
if (Test-Path $artifacts) {
    Write-Host ""
    Write-Host "[OK] Results: $artifacts" -ForegroundColor Green
}

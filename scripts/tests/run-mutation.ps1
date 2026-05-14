# SimpleSign - Run Mutation Tests (Stryker.NET)
# Usage: .\run-mutation.ps1 [project]
#   project: Core, CAdES, PAdES, Brasil (default: all)

#Requires -Version 5.1
param(
    [string]$Project = ""
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent

Write-Host ""
Write-Host "SimpleSign - Mutation Testing (Stryker)" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

Push-Location $repoRoot
try {
    # Restore dotnet tools (includes Stryker)
    Write-Host "Restoring tools..." -ForegroundColor Gray
    dotnet tool restore 2>$null

    $projects = @("SimpleSign.Core", "SimpleSign.CAdES", "SimpleSign.PAdES", "SimpleSign.Brasil")
    if ($Project) {
        if (-not $Project.StartsWith("SimpleSign.")) { $Project = "SimpleSign.$Project" }
        $projects = @($Project)
    }

    Write-Host "Projects: $($projects -join ', ')" -ForegroundColor Gray
    Write-Host ""

    foreach ($p in $projects) {
        Write-Host "[$p] Running Stryker..." -ForegroundColor Yellow
        $csproj = "src\$p\$p.csproj"
        if (-not (Test-Path $csproj)) {
            Write-Host "  [SKIP] Project not found: $csproj" -ForegroundColor Gray
            continue
        }

        dotnet stryker --project $csproj --reporter cleartext --reporter html --output "stryker-out\$p"

        if ($LASTEXITCODE -eq 0) {
            Write-Host "  [OK] Report: stryker-out\$p" -ForegroundColor Green
        } else {
            Write-Host "  [!] Stryker finished with issues" -ForegroundColor Yellow
        }
        Write-Host ""
    }
} finally {
    Pop-Location
}

Write-Host "Reports saved to: $repoRoot\stryker-out\" -ForegroundColor Gray

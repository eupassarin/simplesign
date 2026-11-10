#Requires -Version 7.2
# Starts the TestBench connected to the stack's Sandbox, with the SoftHSM token that softhsm-provision.ps1 (or .sh)
# filled. The PowerShell version of tools/stack/testbench.sh, for Windows (it runs on macOS and Linux too).
# SoftHSM reads SOFTHSM2_CONF with getenv(), so it is set here, before the process starts. Without a token
# (no SoftHSM on this machine) the TestBench starts anyway, without the PKCS#11 credential.
#
#   pwsh -File tools/stack/testbench.ps1                          (SANDBOX_URL, default http://localhost:5300)
#   pwsh -File tools/stack/testbench.ps1 --port 5200 --no-browser (extra arguments go to the TestBench)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($args -contains '-Help' -or $args -contains '--help' -or $args -contains '-h') {
    foreach ($line in Get-Content -LiteralPath $PSCommandPath | Select-Object -Skip 1) {
        if ($line -notmatch '^#') { break }
        $line -replace '^# ?', ''
    }
    exit 0
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$conf = Join-Path $repoRoot '.softhsm/softhsm2.conf'
if (Test-Path -LiteralPath $conf) {
    $env:SOFTHSM2_CONF = $conf
}
else {
    Write-Warning 'No SoftHSM token yet (run tools/stack/up.ps1 or softhsm-provision.ps1): the TestBench starts without the PKCS#11 credential.'
}

$sandbox = if ($env:SANDBOX_URL) { $env:SANDBOX_URL } else { 'http://localhost:5300' }
& dotnet run --project (Join-Path $repoRoot 'src/Apps/SimpleSign.TestBench') -- --sandbox $sandbox @args
exit $LASTEXITCODE

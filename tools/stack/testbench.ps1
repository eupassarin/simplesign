#Requires -Version 7.2
# Starts the TestBench connected to the stack's Sandbox, with the SoftHSM token that softhsm-provision.ps1 (or .sh)
# filled. The PowerShell version of tools/stack/testbench.sh, for Windows (it runs on macOS and Linux too).
# SoftHSM reads SOFTHSM2_CONF with getenv(), so it is set here, before the process starts. Without a token
# (no SoftHSM on this machine) the TestBench starts anyway, without the PKCS#11 credential.
#
#   pwsh -File tools/stack/testbench.ps1                          (SANDBOX_URL, default http://localhost:5300)
#   pwsh -File tools/stack/testbench.ps1 --port 5200 --no-browser (extra arguments go to the TestBench)
#   pwsh -File tools/stack/testbench.ps1 -Pfx my.pfx[,other.p12] [-PfxPasswordFile FILE] [TestBench args]
#
# -Pfx imports your own PFX into the token first (softhsm-provision.ps1 -Pfx), labelled with its file name; it is
# imported again on every run, so it comes back after the token is rebuilt. Its password, never on the command line:
#   -PfxPasswordFile FILE       the file's first line
#   $env:PFX_PASSWORD = '...'   the environment (for every PFX)
#   (neither)                   asked in the terminal, without echo
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', 'PfxPasswordFile', Justification = 'The path of a file, not the password.')]
param(
    [string[]]$Pfx = @(),
    [string]$PfxPasswordFile,
    [switch]$Help,
    [Parameter(ValueFromRemainingArguments = $true)][string[]]$Rest = @()
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($Help -or $Rest -contains '--help') {
    foreach ($line in Get-Content -LiteralPath $PSCommandPath | Select-Object -Skip 1) {
        if ($line -notmatch '^#') { break }
        $line -replace '^# ?', ''
    }
    exit 0
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$conf = Join-Path $repoRoot '.softhsm/softhsm2.conf'
$sandbox = if ($env:SANDBOX_URL) { $env:SANDBOX_URL } else { 'http://localhost:5300' }
# pwsh -File passes "a.pfx,b.p12" as one string.
$Pfx = @($Pfx | ForEach-Object { $_ -split ',' } | Where-Object { $_ })

if ($Pfx) {
    $env:SANDBOX_URL = $sandbox
    $provision = @{ Pfx = $Pfx }
    if ($PfxPasswordFile) { $provision.PfxPasswordFile = $PfxPasswordFile }
    & (Join-Path $PSScriptRoot 'softhsm-provision.ps1') @provision
    if ($LASTEXITCODE) { exit $LASTEXITCODE }
}
elseif (-not (Test-Path -LiteralPath $conf)) {
    Write-Warning 'No SoftHSM token yet (run tools/stack/up.ps1 or softhsm-provision.ps1): the TestBench starts without the PKCS#11 credential.'
}
if (Test-Path -LiteralPath $conf) {
    $env:SOFTHSM2_CONF = $conf
}

& dotnet run --project (Join-Path $repoRoot 'src/Apps/Development/SimpleSign.TestBench') -- --sandbox $sandbox @Rest
exit $LASTEXITCODE

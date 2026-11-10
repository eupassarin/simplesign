#Requires -Version 7.2
# Stops the TestBench's test stack that tools/stack/up.ps1 (or up.sh) started: the Sandbox and DSS containers.
# The PowerShell version of tools/stack/down.sh, for Windows (it runs on macOS and Linux too).
#
#   pwsh -File tools/stack/down.ps1             stop; the Sandbox's PKI and the DSS download cache are kept
#   pwsh -File tools/stack/down.ps1 -DropPki    stop and drop the Sandbox's PKI (the next up makes a new one); keep the DSS cache
#   pwsh -File tools/stack/down.ps1 -Volumes    stop and drop every volume: the PKI and the DSS download cache
# The SoftHSM token (.softhsm/) is left as is: up.ps1 fills it again from the Sandbox.
# The project name (COMPOSE_PROJECT_NAME, default simplesign-stack) must be the one up was given.
param(
    [switch]$DropPki,
    [switch]$Volumes,
    [switch]$Help,
    [Parameter(ValueFromRemainingArguments = $true)][string[]]$Rest
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Show-Help {
    foreach ($line in Get-Content -LiteralPath $PSCommandPath | Select-Object -Skip 1) {
        if ($line -notmatch '^#') { break }
        $line -replace '^# ?', ''
    }
}

function Invoke-Native {
    param([string]$Command, [string[]]$Arguments)
    & $Command @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Command $($Arguments -join ' ') failed (exit code $LASTEXITCODE)." }
}

if ($Help) { Show-Help; exit 0 }
if ($Rest) { [Console]::Error.WriteLine("Unknown option: $($Rest -join ' ')"); exit 2 }

$project = if ($env:COMPOSE_PROJECT_NAME) { $env:COMPOSE_PROJECT_NAME } else { 'simplesign-stack' }
$compose = @('compose', '-p', $project, '-f', (Join-Path $PSScriptRoot 'docker-compose.yml'))

if ($Volumes) {
    Invoke-Native docker ($compose + @('down', '-v', '--remove-orphans'))
    Write-Host "Stopped $project; its volumes (the Sandbox's PKI, the DSS download cache) are gone."
}
elseif ($DropPki) {
    Invoke-Native docker ($compose + @('down', '--remove-orphans'))
    Invoke-Native docker @('volume', 'rm', '-f', "${project}_sandbox-data") | Out-Null
    Write-Host "Stopped $project; the Sandbox's PKI is gone (the next up makes a new one), the DSS download cache is kept."
}
else {
    Invoke-Native docker ($compose + @('down', '--remove-orphans'))
    Write-Host "Stopped $project; the Sandbox's PKI and the DSS download cache are kept. Start again: pwsh -File tools/stack/up.ps1"
}

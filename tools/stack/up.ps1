#Requires -Version 7.2
# Starts the TestBench's test stack, in order. The PowerShell version of tools/stack/up.sh, for Windows (it runs on
# macOS and Linux too):
#   1. the SimpleSign Sandbox (Docker), and waits until it answers;
#   2. a local SoftHSM token with the Sandbox's signing certificates (softhsm-provision.ps1, on the host).
#      On Windows the token is optional: without SoftHSM2 and OpenSC this step is skipped with a warning;
#   3. the EU DSS validation service (Docker), trusting the Sandbox's PKI.
# Then start the TestBench with: pwsh -File tools/stack/testbench.ps1
#
#   pwsh -File tools/stack/up.ps1            keep the Sandbox's PKI from the last run (a volume)
#   pwsh -File tools/stack/up.ps1 -Fresh     a new PKI: new root, new certificates, token and DSS rebuilt
#   pwsh -File tools/stack/up.ps1 -NoDss     the Sandbox and the token only
#   pwsh -File tools/stack/up.ps1 -ContainerEngine Podman
#   -ContainerEngine Docker|Podman (default: SIMPLESIGN_CONTAINER_ENGINE or Docker)
# Stop: pwsh -File tools/stack/down.ps1 (-DropPki, -Volumes; see its -Help)
# Ports: SANDBOX_PORT (5300; HTTPS and LDAP on the next two unless SANDBOX_HTTPS_PORT / SANDBOX_LDAP_PORT),
# DSS_PORT (8080). The project name (COMPOSE_PROJECT_NAME, default simplesign-stack) separates two stacks.
param(
    [switch]$Fresh,
    [switch]$NoDss,
    [ValidateSet('Docker', 'Podman')]
    [string]$ContainerEngine = $(if ($env:SIMPLESIGN_CONTAINER_ENGINE) { $env:SIMPLESIGN_CONTAINER_ENGINE } else { 'Docker' }),
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

Import-Module (Join-Path $PSScriptRoot 'PodmanForwarding.psm1') -Force

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
# Exported: the selected Compose engine reads them from the environment.
if (-not $env:SANDBOX_PORT) { $env:SANDBOX_PORT = '5300' }
if (-not $env:SANDBOX_HTTPS_PORT) { $env:SANDBOX_HTTPS_PORT = [string]([int]$env:SANDBOX_PORT + 1) }
if (-not $env:SANDBOX_LDAP_PORT) { $env:SANDBOX_LDAP_PORT = [string]([int]$env:SANDBOX_PORT + 2) }
if (-not $env:DSS_PORT) { $env:DSS_PORT = '8080' }
$project = if ($env:COMPOSE_PROJECT_NAME) { $env:COMPOSE_PROJECT_NAME } else { 'simplesign-stack' }
$sandbox = "http://localhost:$($env:SANDBOX_PORT)"
$containerCli = if ($ContainerEngine -eq 'Podman') { 'podman' } else { 'docker' }
if (-not (Get-Command $containerCli -ErrorAction SilentlyContinue)) {
    throw "$containerCli was not found. Install it or select another engine with -ContainerEngine."
}
$usePodmanOnWindows = $ContainerEngine -eq 'Podman' -and $IsWindows
if ($usePodmanOnWindows) {
    Stop-SimpleSignPodmanForwarding -Project $project
}
$compose = @('compose', '-p', $project, '-f', (Join-Path $PSScriptRoot 'docker-compose.yml'))
$dssMarker = Join-Path $repoRoot '.softhsm/dss-root'

if ($Fresh) {
    Write-Host '== A new Sandbox PKI'
    Invoke-Native $containerCli ($compose + @('down'))
    # Only the Sandbox's volume: DSS keeps its download cache.
    Invoke-Native $containerCli @('volume', 'rm', '-f', "${project}_sandbox-data") | Out-Null
}

Write-Host "== 1/3 Sandbox ($ContainerEngine)"
Invoke-Native $containerCli ($compose + @('up', '-d', '--build', '--wait', 'sandbox'))
$root = $null
$lastError = $null
$podmanSshForwarding = $false
if ($usePodmanOnWindows) {
    try {
        $root = (Invoke-RestMethod -Uri "http://127.0.0.1:$($env:SANDBOX_PORT)/api/info" -TimeoutSec 2).rootThumbprint
    }
    catch {
        $lastError = $_.Exception
    }

    if (-not $root) {
        $tunnel = Start-SimpleSignPodmanForwarding -Project $project -Podman $containerCli -ComposeArguments $compose -Service 'sandbox' -Ports @(
            @{ LocalPort = $env:SANDBOX_PORT; RemotePort = $env:SANDBOX_PORT }
            @{ LocalPort = $env:SANDBOX_HTTPS_PORT; RemotePort = $env:SANDBOX_HTTPS_PORT }
            @{ LocalPort = $env:SANDBOX_LDAP_PORT; RemotePort = $env:SANDBOX_LDAP_PORT }
        )
        $podmanSshForwarding = $true
        Write-Host "   Podman SSH tunnel: $($tunnel.Forwards -join ', ')"
    }
}

for ($attempt = 1; $attempt -le 10; $attempt++) {
    if ($root) { break }
    try {
        $info = Invoke-RestMethod -Uri "http://127.0.0.1:$($env:SANDBOX_PORT)/api/info" -TimeoutSec 3
        $root = $info.rootThumbprint
        if (-not $root) { throw 'The Sandbox response did not contain a root thumbprint.' }
        break
    }
    catch {
        $lastError = $_.Exception
        if ($attempt -lt 10) { Start-Sleep -Seconds 1 }
    }
}
if (-not $root) {
    if ($usePodmanOnWindows) {
        Stop-SimpleSignPodmanForwarding -Project $project
    }
    $hint = if ($ContainerEngine -eq 'Podman' -and $IsWindows) {
        ' Verify that the Podman machine SSH connection is available and that ssh.exe is on PATH.'
    }
    else {
        ''
    }
    throw "The Sandbox container is running, but its API did not respond at $sandbox/api/info. Check the container logs with '$containerCli compose -p $project -f tools/stack/docker-compose.yml logs sandbox'.$hint Last error: $lastError"
}
Write-Host "   $sandbox (root $root)"

Write-Host '== 2/3 SoftHSM token'
$env:SANDBOX_URL = $sandbox
& ([Environment]::ProcessPath) -NoProfile -File (Join-Path $PSScriptRoot 'softhsm-provision.ps1')
$token = $true
if ($LASTEXITCODE -eq 3 -and $IsWindows) {
    Write-Warning 'No SoftHSM token: SoftHSM2 or OpenSC is not installed (see above). The TestBench will start without the PKCS#11 credential.'
    $token = $false
}
elseif ($LASTEXITCODE -ne 0) {
    throw "softhsm-provision.ps1 failed (exit code $LASTEXITCODE)."
}

if (-not $NoDss) {
    Write-Host '== 3/3 DSS (the first build downloads the DSS bundle: about 15 minutes)'
    # DSS reads the Sandbox's root and trusted-list operator when it starts: a new PKI needs a new container.
    $recreate = @()
    if (-not (Test-Path -LiteralPath $dssMarker) -or (Get-Content -LiteralPath $dssMarker -Raw).Trim() -ne $root) {
        $recreate = @('--force-recreate')
    }
    Invoke-Native $containerCli ($compose + @('up', '-d', '--wait', '--wait-timeout', '900') + $recreate + @('dss'))
    if ($podmanSshForwarding) {
        $tunnel = Start-SimpleSignPodmanForwarding -Project $project -Podman $containerCli -ComposeArguments $compose -Service 'dss' -Ports @(
            @{ LocalPort = $env:DSS_PORT; RemotePort = 8080 }
        )
        Write-Host "   Podman SSH tunnel: $($tunnel.Forwards -join ', ')"
    }
    New-Item -ItemType Directory -Force -Path (Split-Path $dssMarker) | Out-Null
    Set-Content -LiteralPath $dssMarker -Encoding ascii -Value $root -NoNewline
    Write-Host "   http://localhost:$($env:DSS_PORT) (turn `"DSS`" on in the TestBench's top bar)"
}
else {
    Write-Host '== 3/3 DSS skipped (-NoDss)'
}

$pinLine = if ($token) { "PKCS#11 credential: token `"$(if ($env:SOFTHSM_TOKEN_LABEL) { $env:SOFTHSM_TOKEN_LABEL } else { 'SimpleSign Sandbox' })`", PIN $(if ($env:SOFTHSM_PIN) { $env:SOFTHSM_PIN } else { '1234' })." } else { 'PKCS#11 credential: none (no SoftHSM token).' }
Write-Host @"

Ready. Start the TestBench (connected to the Sandbox$(if ($token) { ', with the SoftHSM token' })):
  `$env:SANDBOX_URL = '$sandbox'; pwsh -File tools/stack/testbench.ps1
DSS address in the TestBench: http://localhost:$($env:DSS_PORT)
$pinLine
"@

#Requires -Version 7.2
# Fills a local SoftHSM token with the signing certificates of a running SimpleSign Sandbox, so the TestBench (and
# the CLI) can sign with them through PKCS#11. The PowerShell version of tools/stack/softhsm-provision.sh: it runs on
# Windows, macOS and Linux, and needs neither OpenSSL nor jq (the PFX files are read with .NET).
#
#   pwsh -File tools/stack/softhsm-provision.ps1           (tools/stack/up.ps1 calls it)
#   pwsh -File tools/stack/softhsm-provision.ps1 -Force    (rebuild the token even if the Sandbox root did not change)
#
# Needs SoftHSM2 (softhsm2-util and its PKCS#11 module) and OpenSC (pkcs11-tool):
#   Windows: SoftHSM2 for Windows (https://github.com/disig/SoftHSM2-for-Windows/releases, into C:\SoftHSM2)
#            and OpenSC (winget install OpenSC.OpenSC)
#   macOS:   brew install softhsm opensc        Debian/Ubuntu: apt-get install softhsm2 opensc
# Exit code 3 when one of them is missing (up.ps1 then goes on without the token on Windows).
#
# The token is kept in <repo>/.softhsm (its own softhsm2.conf), the same folder softhsm-provision.sh uses.
# Environment: SANDBOX_URL (http://localhost:5300), SOFTHSM_TOKEN_LABEL ("SimpleSign Sandbox"), SOFTHSM_PIN (1234),
# SOFTHSM_SO_PIN (0000), SOFTHSM2_MODULE (found automatically).
param(
    [switch]$Force,
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
    $output = & $Command @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "$(Split-Path -Leaf $Command) failed (exit code $LASTEXITCODE): $($output -join [Environment]::NewLine)"
    }
    $output
}

# A tool on the PATH, or in one of the folders its Windows installer uses.
function Find-Tool {
    param([string]$Name, [string[]]$WindowsCandidates)
    $command = Get-Command $Name -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($command) { return $command.Source }
    if ($IsWindows) {
        foreach ($candidate in $WindowsCandidates) {
            if ($candidate -and (Test-Path -LiteralPath $candidate)) { return $candidate }
        }
    }
    return $null
}

if ($Help) { Show-Help; exit 0 }
if ($Rest) { [Console]::Error.WriteLine("Unknown option: $($Rest -join ' ')"); exit 2 }

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$sandboxUrl = (($env:SANDBOX_URL, 'http://localhost:5300') | Where-Object { $_ } | Select-Object -First 1).TrimEnd('/')
$tokenLabel = if ($env:SOFTHSM_TOKEN_LABEL) { $env:SOFTHSM_TOKEN_LABEL } else { 'SimpleSign Sandbox' }
$pin = if ($env:SOFTHSM_PIN) { $env:SOFTHSM_PIN } else { '1234' }
$soPin = if ($env:SOFTHSM_SO_PIN) { $env:SOFTHSM_SO_PIN } else { '0000' }
$hsmDir = Join-Path $repoRoot '.softhsm'
$tokens = Join-Path $hsmDir 'tokens'
$conf = Join-Path $hsmDir 'softhsm2.conf'
$marker = Join-Path $hsmDir 'sandbox-root'
# Certificates of the Sandbox's own services, not signers.
$skipIds = @('tsa', 'tsa-revoked', 'ocsp-responder', 'tls-server')

# Windows install folders ([IO.Path]::Combine: Join-Path would look for a C: drive on macOS and Linux).
$programFiles = @($env:ProgramFiles, ${env:ProgramFiles(x86)}) | Where-Object { $_ }
$softhsmHomes = @('C:\SoftHSM2') + @($programFiles | ForEach-Object { [IO.Path]::Combine($_, 'SoftHSM2') })
$softhsmUtil = Find-Tool 'softhsm2-util' @($softhsmHomes | ForEach-Object { [IO.Path]::Combine($_, 'bin', 'softhsm2-util.exe') })
$pkcs11Tool = Find-Tool 'pkcs11-tool' @($programFiles | ForEach-Object { [IO.Path]::Combine($_, 'OpenSC Project', 'OpenSC', 'tools', 'pkcs11-tool.exe') })

$module = $env:SOFTHSM2_MODULE
if (-not $module) {
    $candidates = if ($IsWindows) {
        @($softhsmHomes | ForEach-Object { [IO.Path]::Combine($_, 'lib', 'softhsm2-x64.dll') })
        if ($softhsmUtil) { [IO.Path]::Combine((Split-Path (Split-Path $softhsmUtil)), 'lib', 'softhsm2-x64.dll') }
    }
    else {
        '/opt/homebrew/lib/softhsm/libsofthsm2.so', '/usr/local/lib/softhsm/libsofthsm2.so',
        '/usr/lib/softhsm/libsofthsm2.so', '/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so',
        '/usr/lib/aarch64-linux-gnu/softhsm/libsofthsm2.so'
    }
    $module = $candidates | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -First 1
}

$missing = @()
if (-not $softhsmUtil) { $missing += 'softhsm2-util (SoftHSM2)' }
if (-not $pkcs11Tool) { $missing += 'pkcs11-tool (OpenSC)' }
if (-not $module -or -not (Test-Path -LiteralPath $module)) { $missing += 'the SoftHSM2 PKCS#11 module (set SOFTHSM2_MODULE)' }
if ($missing) {
    [Console]::Error.WriteLine("Missing: $($missing -join ', ').")
    [Console]::Error.WriteLine('  Windows: SoftHSM2 for Windows (https://github.com/disig/SoftHSM2-for-Windows/releases, into C:\SoftHSM2) and winget install OpenSC.OpenSC')
    [Console]::Error.WriteLine('  macOS: brew install softhsm opensc        Debian/Ubuntu: apt-get install softhsm2 opensc')
    exit 3
}

try {
    $info = Invoke-RestMethod -Uri "$sandboxUrl/api/info" -TimeoutSec 10
}
catch {
    [Console]::Error.WriteLine("No SimpleSign Sandbox at $sandboxUrl ($($_.Exception.Message)); start it first: pwsh -File tools/stack/up.ps1.")
    exit 1
}
$root = $info.rootThumbprint
$pfxPassword = $info.pfxPassword

New-Item -ItemType Directory -Force -Path $tokens | Out-Null
Set-Content -LiteralPath $conf -Encoding ascii -Value @(
    "directories.tokendir = $tokens"
    'objectstore.backend = file'
    'log.level = ERROR'
    'slots.removable = false'
)
$env:SOFTHSM2_CONF = $conf

if (-not $Force -and (Test-Path -LiteralPath $marker) -and (Get-Content -LiteralPath $marker -Raw).Trim() -eq $root) {
    $slots = & $softhsmUtil --show-slots 2>$null
    if ($LASTEXITCODE -eq 0 -and ($slots | Select-String -SimpleMatch "Label:" | Where-Object { $_ -match [regex]::Escape($tokenLabel) })) {
        Write-Host "SoftHSM token `"$tokenLabel`" already holds the certificates of the Sandbox root $root; nothing to do (-Force rebuilds it)."
        Write-Host "`$env:SOFTHSM2_CONF = `"$conf`""
        exit 0
    }
}

Write-Host "-> SoftHSM token `"$tokenLabel`" for the Sandbox at $sandboxUrl (root $root)"
Remove-Item -LiteralPath $tokens -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $marker -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $tokens | Out-Null
Invoke-Native $softhsmUtil @('--init-token', '--free', '--label', $tokenLabel, '--so-pin', $soPin, '--pin', $pin) | Out-Null

$work = Join-Path ([IO.Path]::GetTempPath()) "simplesign-softhsm-$([guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Path $work | Out-Null
# Keys are exported once, in memory; on Windows an ephemeral key set keeps them out of the user's key store.
$flags = [Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable
if ($IsWindows) { $flags = $flags -bor [Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet }
$imported = @()
try {
    $pki = Invoke-RestMethod -Uri "$sandboxUrl/api/pki" -TimeoutSec 30
    $index = 0
    foreach ($entry in $pki.certificates) {
        if ($skipIds -contains $entry.id) { continue }
        $index++
        $keyId = '{0:x2}' -f $index
        $pfx = (Invoke-WebRequest -Uri "$sandboxUrl/api/certificates/$($entry.id)/pfx" -TimeoutSec 30).Content
        $collection = [Security.Cryptography.X509Certificates.X509Certificate2Collection]::new()
        $collection.Import([byte[]]$pfx, $pfxPassword, $flags)
        # The leaf certificate: the one with the private key.
        $certificate = $collection | Where-Object HasPrivateKey | Select-Object -First 1
        if (-not $certificate) { throw "The PFX of $($entry.id) has no private key." }
        $key = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($certificate)
        if (-not $key) { $key = [Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($certificate) }
        if (-not $key) { throw "The key of $($entry.id) is neither RSA nor ECDSA." }
        $keyFile = Join-Path $work "$($entry.id).key.der"
        $certFile = Join-Path $work "$($entry.id).cert.der"
        try {
            [IO.File]::WriteAllBytes($keyFile, $key.ExportPkcs8PrivateKey())
            [IO.File]::WriteAllBytes($certFile, $certificate.RawData)
            foreach ($object in @(@('privkey', $keyFile), @('cert', $certFile))) {
                Invoke-Native $pkcs11Tool @('--module', $module, '--token-label', $tokenLabel, '--login', '--pin', $pin,
                    '--write-object', $object[1], '--type', $object[0], '--id', $keyId, '--label', $entry.id) | Out-Null
            }
        }
        finally {
            Remove-Item -LiteralPath $keyFile -Force -ErrorAction SilentlyContinue
            $key.Dispose()
            $collection | ForEach-Object { $_.Dispose() }
        }
        $imported += '  {0,-22} {1}' -f $entry.id, $entry.subject
    }
}
finally {
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}

Set-Content -LiteralPath $marker -Encoding ascii -Value $root -NoNewline
Write-Host "-> $($imported.Count) key pair(s) on `"$tokenLabel`" (PIN $pin, SO PIN $soPin), module ${module}:"
$imported | ForEach-Object { Write-Host $_ }
Write-Host "`$env:SOFTHSM2_CONF = `"$conf`""

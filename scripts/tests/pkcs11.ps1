#Requires -Version 7.2
# SimpleSign - PKCS#11 tests in Docker (SoftHSM2), for machines without SoftHSM. The PowerShell version of
# scripts/tests/pkcs11.sh, for Windows (Docker Desktop with Linux containers; it runs on macOS and Linux too).
#
#   pwsh -File scripts/tests/pkcs11.ps1
#
# Builds tests/docker/pkcs11, copies the repository into the container (without bin/obj) and runs
# scripts/tests/pkcs11-run.sh there. The NuGet cache is kept in a Docker volume.
param(
    [switch]$Help,
    [Parameter(ValueFromRemainingArguments = $true)][string[]]$Rest
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($Help) {
    foreach ($line in Get-Content -LiteralPath $PSCommandPath | Select-Object -Skip 1) {
        if ($line -notmatch '^#') { break }
        $line -replace '^# ?', ''
    }
    exit 0
}
if ($Rest) { [Console]::Error.WriteLine("Unknown option: $($Rest -join ' ')"); exit 2 }

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$image = 'simplesign-pkcs11-test'

& docker build -t $image (Join-Path $repoRoot 'tests/docker/pkcs11')
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

# The copy has no .git, so SourceLink is turned off (MSBuild reads environment variables as properties).
# The copy also drops Windows line endings from the scripts it runs, in case the checkout converted them.
$inside = @'
set -euo pipefail
tar -C /src --exclude=./.git --exclude=./node_modules \
  --exclude="*/bin" --exclude="*/obj" --exclude="*/TestResults" -cf - . | tar -C /work -xf -
cd /work
find scripts -name "*.sh" -exec sed -i "s/\r$//" {} +
scripts/tests/pkcs11-run.sh
'@
& docker run --rm `
    -e EnableSourceLink=false -e EnableSourceControlManagerQueries=false `
    -v "${repoRoot}:/src:ro" `
    -v simplesign-pkcs11-nuget:/root/.nuget/packages `
    $image bash -c ($inside -replace "`r", '')
exit $LASTEXITCODE

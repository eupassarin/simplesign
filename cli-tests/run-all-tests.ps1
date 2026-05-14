#!/usr/bin/env pwsh
# =============================================================================
# SimpleSign CLI - comprehensive test script
# Signs all combinations, generates a static HTML report with results.
# =============================================================================

param(
    [string]$CliProject = "D:\simplesign\SimpleSign\src\SimpleSign.Cli",
    [string]$Framework  = "net8.0"
)

Add-Type -AssemblyName System.Web
$ErrorActionPreference = "Continue"

$BaseDir   = "D:\simplesign-tests"
$Cert      = "$BaseDir\cert.pfx"
$InputPdf  = "$BaseDir\test.pdf"
$OutDir    = "$BaseDir\results"
$TsaUrl    = "http://timestamp.digicert.com"

# --- Ask password once (masked) ---
$SecurePwd = Read-Host -Prompt "Certificate password (leave blank if none)" -AsSecureString
$BSTR      = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePwd)
$PlainPwd  = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
[System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)

# --- Build CLI once ---
Write-Host "Building CLI..." -ForegroundColor DarkGray
& dotnet build $CliProject --framework $Framework -v q 2>&1 | Out-Null
$CliExe = Join-Path $CliProject "bin\Debug\$Framework\simplesign-cli.exe"
if (-not (Test-Path $CliExe)) {
    Write-Host "ERROR: CLI exe not found at $CliExe" -ForegroundColor Red
    exit 1
}

# --- Prepare output directory ---
if (Test-Path $OutDir) { Remove-Item $OutDir -Recurse -Force }
New-Item -ItemType Directory -Path $OutDir | Out-Null

# --- Results tracker ---
$testCases = [System.Collections.Generic.List[PSObject]]::new()

function Run-TestCase {
    param(
        [string]$Name,
        [string[]]$SignArgs
    )

    $folder = Join-Path $OutDir $Name
    New-Item -ItemType Directory -Path $folder | Out-Null
    $outPdf = Join-Path $folder "signed.pdf"

    Write-Host "  $Name ... " -NoNewline -ForegroundColor Cyan

    # Build sign command (for display, mask password)
    $displayArgs = @("sign", "test.pdf", "-c", "cert.pfx", "-o", "signed.pdf")
    if ($PlainPwd) { $displayArgs += @("--password", "********") }
    $displayArgs += $SignArgs
    $signCmd = "simplesign-cli " + ($displayArgs -join " ")

    # Actual sign
    $baseArgs = @("sign", $InputPdf, "-c", $Cert, "-o", $outPdf)
    if ($PlainPwd) { $baseArgs += @("--password", $PlainPwd) }
    $allArgs = $baseArgs + $SignArgs
    $signOutput = & $CliExe @allArgs 2>&1 | Out-String
    $signOk = ($LASTEXITCODE -eq 0) -and (Test-Path $outPdf)

    $inspectOutput = ""
    $validateOutput = ""
    $inspectCmd = ""
    $validateCmd = ""

    if ($signOk) {
        # Inspect
        $inspectCmd = "simplesign-cli inspect signed.pdf"
        $inspectOutput = & $CliExe inspect $outPdf 2>&1 | Out-String

        # Validate
        $validateCmd = "simplesign-cli validate signed.pdf"
        $validateOutput = & $CliExe validate $outPdf 2>&1 | Out-String

        Write-Host "OK" -ForegroundColor Green
    } else {
        Write-Host "FAIL" -ForegroundColor Red
    }

    $testCases.Add([PSCustomObject]@{
        Name           = $Name
        Folder         = $folder
        SignOk         = $signOk
        SignCmd         = $signCmd
        SignOutput     = $signOutput
        InspectCmd     = $inspectCmd
        InspectOutput  = $inspectOutput
        ValidateCmd    = $validateCmd
        ValidateOutput = $validateOutput
        HasPdf         = $signOk
    })
}

# =============================================================================
# Run all test cases
# =============================================================================
Write-Host ""
Write-Host "Running tests..." -ForegroundColor Green
Write-Host ""

# --- Basic ---
Run-TestCase "01-basic-default"              @()
Run-TestCase "02-basic-legacy-cms"           @("--legacy-cms")
Run-TestCase "03-basic-pdfa"                 @("--pdfa", "--legacy-cms")

# --- Hash algorithms ---
Run-TestCase "04-hash-sha256"                @("--hash", "SHA256")
Run-TestCase "05-hash-sha384"                @("--hash", "SHA384")
Run-TestCase "06-hash-sha512"                @("--hash", "SHA512")

# --- Metadata ---
Run-TestCase "07-meta-reason"                @("--reason", "Test signing")
Run-TestCase "08-meta-location"              @("--location", "Sao Paulo, BR")
Run-TestCase "09-meta-contact"               @("--contact", "test@example.com")
Run-TestCase "10-meta-signer-name"           @("--signer-name", "Test User")
Run-TestCase "11-meta-all"                   @("--reason", "Full metadata", "--location", "Brasilia", "--contact", "admin@gov.br", "--signer-name", "Fulano de Tal")

# --- Field name ---
Run-TestCase "12-field-custom-name"          @("--field-name", "MyCustomSig")

# --- Certification / DocMDP ---
Run-TestCase "13-certify-no-changes"         @("--certify", "no-changes")
Run-TestCase "14-certify-form-filling"       @("--certify", "form-filling")
Run-TestCase "15-certify-annotations"        @("--certify", "annotations")

# --- Timestamp ---
Run-TestCase "16-tsa-digicert"               @("-t", $TsaUrl)

# --- LTV (requires TSA) ---
Run-TestCase "17-ltv"                        @("-t", $TsaUrl, "--ltv")

# --- Archival / B-LTA ---
Run-TestCase "18-archival"                   @("-t", $TsaUrl, "--archival")

# --- LTV + Archival ---
Run-TestCase "19-ltv-archival"               @("-t", $TsaUrl, "--ltv", "--archival")

# --- Legacy CMS + TSA ---
Run-TestCase "20-legacy-cms-tsa"             @("--legacy-cms", "-t", $TsaUrl)
Run-TestCase "21-legacy-cms-ltv"             @("--legacy-cms", "-t", $TsaUrl, "--ltv")

# --- Visible signature ---
Run-TestCase "22-visible-auto"               @("--visible")
Run-TestCase "23-visible-page1"              @("--visible", "--page", "1")
Run-TestCase "24-visible-coords"             @("--visible", "--pos-x", "100", "--pos-y", "200")
Run-TestCase "25-visible-page-coords"        @("--visible", "--page", "1", "--pos-x", "50", "--pos-y", "700")

# --- Visible + QR ---
Run-TestCase "26-visible-qr"                 @("--visible", "--qr-url", "https://verify.example.com/doc123")

# --- Visible + metadata ---
Run-TestCase "27-visible-meta"               @("--visible", "--reason", "Visual test", "--location", "Office")

# --- Full combos ---
Run-TestCase "28-full-sha384-ltv-visible"    @("--hash", "SHA384", "-t", $TsaUrl, "--ltv", "--visible", "--reason", "Complete test", "--signer-name", "Admin")
Run-TestCase "29-full-sha512-archival-certify" @("--hash", "SHA512", "-t", $TsaUrl, "--archival", "--certify", "form-filling")
Run-TestCase "30-pdfa-legacy-meta"           @("--pdfa", "--legacy-cms", "--reason", "PDF/A test", "--location", "Lab")

# --- Verbose mode ---
Run-TestCase "31-verbose-basic"              @("--verbose")

# =============================================================================
# Generate static HTML site
# =============================================================================
Write-Host ""
Write-Host "Generating HTML report..." -ForegroundColor Yellow

$ok   = ($testCases | Where-Object { $_.SignOk }).Count
$fail = ($testCases | Where-Object { -not $_.SignOk }).Count
$total = $testCases.Count
$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

# --- Generate card HTML for each test case ---
$cardsHtml = ""
foreach ($tc in $testCases) {
    $statusClass = if ($tc.SignOk) { "success" } else { "failure" }
    $statusIcon  = if ($tc.SignOk) { "&#10003;" } else { "&#10007;" }
    $statusText  = if ($tc.SignOk) { "OK" } else { "FAILED" }

    $pdfEmbed = ""
    if ($tc.HasPdf) {
        $pdfRelPath = "$($tc.Name)/signed.pdf"
        $pdfEmbed = @"
      <div class="pdf-viewer">
        <object data="$pdfRelPath" type="application/pdf" width="100%" height="400px">
          <p>PDF preview not available. <a href="$pdfRelPath" target="_blank">Download PDF</a></p>
        </object>
      </div>
"@
    }

    $signOutputEsc = [System.Web.HttpUtility]::HtmlEncode($tc.SignOutput)
    $inspectOutputEsc = [System.Web.HttpUtility]::HtmlEncode($tc.InspectOutput)
    $validateOutputEsc = [System.Web.HttpUtility]::HtmlEncode($tc.ValidateOutput)
    $signCmdEsc = [System.Web.HttpUtility]::HtmlEncode($tc.SignCmd)
    $inspectCmdEsc = [System.Web.HttpUtility]::HtmlEncode($tc.InspectCmd)
    $validateCmdEsc = [System.Web.HttpUtility]::HtmlEncode($tc.ValidateCmd)

    $cardsHtml += @"
    <div class="card $statusClass" id="$($tc.Name)">
      <div class="card-header">
        <span class="status-badge $statusClass">$statusIcon $statusText</span>
        <h3>$($tc.Name)</h3>
      </div>
      <div class="card-body">
        <div class="section">
          <h4>&#128396; Sign Command</h4>
          <code class="command">$signCmdEsc</code>
          <pre class="output">$signOutputEsc</pre>
        </div>

"@

    if ($tc.SignOk) {
        $cardsHtml += @"
        <div class="section">
          <h4>&#128269; Inspect</h4>
          <code class="command">$inspectCmdEsc</code>
          <pre class="output">$inspectOutputEsc</pre>
        </div>
        <div class="section">
          <h4>&#9989; Validate</h4>
          <code class="command">$validateCmdEsc</code>
          <pre class="output">$validateOutputEsc</pre>
        </div>
$pdfEmbed

"@
    }

    $cardsHtml += @"
      </div>
    </div>

"@
}

# --- Navigation links ---
$navHtml = ""
foreach ($tc in $testCases) {
    $statusClass = if ($tc.SignOk) { "success" } else { "failure" }
    $icon = if ($tc.SignOk) { "&#10003;" } else { "&#10007;" }
    $navHtml += "        <a href=`"#$($tc.Name)`" class=`"nav-item $statusClass`">$icon $($tc.Name)</a>`n"
}

# --- Write index.html ---
$html = @"
<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SimpleSign CLI - Test Results</title>
  <style>
    :root {
      --bg: #0d1117; --surface: #161b22; --border: #30363d;
      --text: #e6edf3; --muted: #8b949e; --green: #3fb950;
      --red: #f85149; --blue: #58a6ff; --yellow: #d29922;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: var(--bg); color: var(--text); line-height: 1.5; }
    .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
    header { text-align: center; padding: 30px 0; border-bottom: 1px solid var(--border); margin-bottom: 30px; }
    header h1 { font-size: 2em; margin-bottom: 10px; }
    .summary { display: flex; gap: 20px; justify-content: center; margin-top: 15px; flex-wrap: wrap; }
    .summary-item { padding: 8px 20px; border-radius: 8px; background: var(--surface); border: 1px solid var(--border); font-weight: 600; }
    .summary-item.ok { color: var(--green); border-color: var(--green); }
    .summary-item.fail { color: var(--red); border-color: var(--red); }
    .summary-item.total { color: var(--blue); border-color: var(--blue); }
    .layout { display: grid; grid-template-columns: 260px 1fr; gap: 20px; }
    @media (max-width: 900px) { .layout { grid-template-columns: 1fr; } }
    .sidebar { position: sticky; top: 20px; height: fit-content; max-height: 90vh; overflow-y: auto; }
    .sidebar nav { display: flex; flex-direction: column; gap: 2px; }
    .nav-item { padding: 6px 12px; border-radius: 6px; text-decoration: none; color: var(--muted); font-size: 0.82em; transition: background 0.2s; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
    .nav-item:hover { background: var(--surface); color: var(--text); }
    .nav-item.success { color: var(--green); }
    .nav-item.failure { color: var(--red); }
    .cards { display: flex; flex-direction: column; gap: 20px; }
    .card { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; overflow: hidden; }
    .card.success { border-left: 4px solid var(--green); }
    .card.failure { border-left: 4px solid var(--red); }
    .card-header { display: flex; align-items: center; gap: 12px; padding: 14px 20px; border-bottom: 1px solid var(--border); background: rgba(0,0,0,0.2); cursor: pointer; }
    .card-header h3 { font-size: 1em; font-weight: 600; }
    .status-badge { padding: 3px 10px; border-radius: 12px; font-size: 0.8em; font-weight: 700; }
    .status-badge.success { background: rgba(63,185,80,0.15); color: var(--green); }
    .status-badge.failure { background: rgba(248,81,73,0.15); color: var(--red); }
    .card-body { padding: 16px 20px; }
    .section { margin-bottom: 16px; }
    .section h4 { color: var(--blue); margin-bottom: 6px; font-size: 0.9em; text-transform: uppercase; letter-spacing: 0.5px; }
    .command { display: block; background: #1c2128; padding: 8px 12px; border-radius: 6px; font-family: 'JetBrains Mono', 'Fira Code', 'Cascadia Code', monospace; font-size: 0.82em; color: var(--yellow); margin-bottom: 8px; word-break: break-all; }
    .output { background: #010409; padding: 12px; border-radius: 6px; font-family: 'JetBrains Mono', 'Fira Code', 'Cascadia Code', monospace; font-size: 0.78em; color: var(--muted); overflow-x: auto; white-space: pre-wrap; max-height: 350px; overflow-y: auto; }
    .pdf-viewer { margin-top: 12px; border: 1px solid var(--border); border-radius: 6px; overflow: hidden; }
    .pdf-viewer object { display: block; }
    .timestamp { color: var(--muted); font-size: 0.85em; }
    .filter-bar { display: flex; gap: 10px; margin-bottom: 20px; }
    .filter-btn { padding: 6px 14px; border-radius: 6px; border: 1px solid var(--border); background: var(--surface); color: var(--text); cursor: pointer; font-size: 0.85em; transition: all 0.2s; }
    .filter-btn:hover, .filter-btn.active { border-color: var(--blue); color: var(--blue); }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <h1>SimpleSign CLI &mdash; Test Results</h1>
      <p class="timestamp">Generated: $timestamp</p>
      <div class="summary">
        <span class="summary-item total">Total: $total</span>
        <span class="summary-item ok">&#10003; Passed: $ok</span>
        <span class="summary-item fail">&#10007; Failed: $fail</span>
      </div>
    </header>

    <div class="filter-bar">
      <button class="filter-btn active" onclick="filter('all', this)">All</button>
      <button class="filter-btn" onclick="filter('success', this)">&#10003; Passed</button>
      <button class="filter-btn" onclick="filter('failure', this)">&#10007; Failed</button>
    </div>

    <div class="layout">
      <aside class="sidebar">
        <nav>
$navHtml
        </nav>
      </aside>
      <main class="cards">
$cardsHtml
      </main>
    </div>
  </div>

  <script>
    function filter(type, btn) {
      document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      document.querySelectorAll('.card').forEach(card => {
        card.style.display = (type === 'all' || card.classList.contains(type)) ? '' : 'none';
      });
      document.querySelectorAll('.nav-item').forEach(link => {
        link.style.display = (type === 'all' || link.classList.contains(type)) ? '' : 'none';
      });
    }

    // Collapse/expand cards on header click
    document.querySelectorAll('.card-header').forEach(header => {
      header.addEventListener('click', () => {
        const body = header.nextElementSibling;
        body.style.display = body.style.display === 'none' ? '' : 'none';
      });
    });
  </script>
</body>
</html>
"@

$html | Out-File -FilePath (Join-Path $OutDir "index.html") -Encoding utf8

# =============================================================================
# Done
# =============================================================================
Write-Host ""
Write-Host "  Total: $total  |  OK: $ok  |  FAIL: $fail" -ForegroundColor White
Write-Host "  Report: $OutDir\index.html" -ForegroundColor Green
Write-Host ""

# Open in default browser
Start-Process (Join-Path $OutDir "index.html")

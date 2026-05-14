# convert-all.ps1
# Script para converter todos os arquivos HTML para PDF usando o SimpleSign CLI.
# Uso: .\convert-all.ps1
# Os PDFs são salvos na pasta ./results/

param(
    [string]$CliProject = (Join-Path $PSScriptRoot ".." "src" "SimpleSign.Cli")
)

$ErrorActionPreference = "Stop"
$scriptDir = $PSScriptRoot
$resultsDir = Join-Path $scriptDir "results"

# Criar pasta de resultados
if (-not (Test-Path $resultsDir)) {
    New-Item -ItemType Directory -Path $resultsDir -Force | Out-Null
}

Write-Host "============================================" -ForegroundColor Cyan
Write-Host " SimpleSign HtmlToPdf - Conversao em Lote" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Projeto CLI: $CliProject"
Write-Host "Resultados:  $resultsDir"
Write-Host ""

$cssFile = Join-Path $scriptDir "custom.css"

# Definir conversoes: [arquivo, opcoes_extras]
$conversions = @(
    @{ File = "01-basico.html";           Options = @() },
    @{ File = "02-tabela.html";           Options = @("--page-size", "Letter") },
    @{ File = "03-listas.html";           Options = @("--margin", "60") },
    @{ File = "04-formatacao.html";       Options = @("--title", "Guia de Formatacao", "--author", "SimpleSign") },
    @{ File = "05-layout-sections.html";  Options = @("--page-size", "A3") },
    @{ File = "06-blockquote-pre.html";   Options = @("--margin-top", "80") },
    @{ File = "07-css-externo.html";      Options = @("--css", $cssFile) },
    @{ File = "08-documento-longo.html";  Options = @("--page-size", "Legal") },
    @{ File = "09-mixed-content.html";    Options = @() },
    @{ File = "10-minimal.html";          Options = @() }
)

$success = 0
$failed = 0
$totalTime = [System.Diagnostics.Stopwatch]::StartNew()

foreach ($conv in $conversions) {
    $inputFile = Join-Path $scriptDir $conv.File
    $outputFile = Join-Path $resultsDir ([System.IO.Path]::ChangeExtension($conv.File, ".pdf"))

    if (-not (Test-Path $inputFile)) {
        Write-Host "  [SKIP] $($conv.File) - arquivo nao encontrado" -ForegroundColor Yellow
        $failed++
        continue
    }

    $args = @("run", "--project", $CliProject, "--framework", "net8.0", "--", "html-to-pdf", $inputFile, "-o", $outputFile) + $conv.Options

    Write-Host "  Convertendo $($conv.File)..." -NoNewline

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $output = & dotnet @args 2>&1
        $exitCode = $LASTEXITCODE
        $sw.Stop()

        if ($exitCode -eq 0) {
            $size = (Get-Item $outputFile).Length
            Write-Host " OK ($($sw.ElapsedMilliseconds)ms, $([math]::Round($size/1024, 1))KB)" -ForegroundColor Green
            $success++
        } else {
            Write-Host " ERRO (exit code: $exitCode)" -ForegroundColor Red
            Write-Host "    $output" -ForegroundColor Red
            $failed++
        }
    } catch {
        $sw.Stop()
        Write-Host " ERRO: $($_.Exception.Message)" -ForegroundColor Red
        $failed++
    }
}

$totalTime.Stop()
Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host " Resumo:" -ForegroundColor Cyan
Write-Host "   Sucesso: $success" -ForegroundColor Green
Write-Host "   Falha:   $failed" -ForegroundColor $(if ($failed -gt 0) { "Red" } else { "Green" })
Write-Host "   Tempo:   $($totalTime.Elapsed.TotalSeconds.ToString('F1'))s" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan

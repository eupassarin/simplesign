using System.ComponentModel;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using SimpleSign.CAdES;
using SimpleSign.Cli.Json;
using SimpleSign.Core.Validation;
using Spectre.Console;
using Spectre.Console.Cli;

namespace SimpleSign.Cli.Commands;

/// <summary>Validate a CAdES detached signature (CMS/PKCS#7).</summary>
[Description("Validate a CAdES detached signature (CMS/PKCS#7)")]
internal sealed class CadesValidateCommand : AsyncCommand<CadesValidateCommand.Settings>
{
    private readonly ICertificateChainService _certChainService;

    public CadesValidateCommand(ICertificateChainService certChainService)
    {
        _certChainService = certChainService;
    }

    /// <summary>CAdES validate command settings.</summary>
    internal sealed class Settings : CommonSettings
    {
        /// <summary>CAdES signature file (.p7s).</summary>
        [CommandArgument(0, "<signature>")]
        [Description("CAdES signature file (.p7s)")]
        public string SignaturePath { get; init; } = null!;

        /// <summary>Original data file (required for detached signatures).</summary>
        [CommandOption("--data|-d <PATH>")]
        [Description("Original data file (required for detached signatures)")]
        public string? DataPath { get; init; }

        /// <summary>Trust anchor certificate(s) — PEM or DER.</summary>
        [CommandOption("--trust <PATH>")]
        [Description("Trust anchor certificate(s) — PEM or DER")]
        public string? TrustPath { get; init; }

        /// <summary>Output validation result as JSON instead of a table.</summary>
        [CommandOption("--json")]
        [Description("Output result as JSON")]
        public bool Json { get; init; }

        public override ValidationResult Validate()
        {
            if (!File.Exists(SignaturePath))
            {
                return ValidationResult.Error($"Signature file not found: {SignaturePath}");
            }

            if (DataPath is not null && !File.Exists(DataPath))
            {
                return ValidationResult.Error($"Data file not found: {DataPath}");
            }

            return ValidationResult.Success();
        }
    }

    protected override async Task<int> ExecuteAsync(
        CommandContext context, Settings settings, CancellationToken cancellationToken)
    {
        byte[] cmsBytes = await CommonSettings.ReadInputBytesAsync(settings.SignaturePath, cancellationToken);

        byte[]? originalData = null;
        if (settings.DataPath is not null)
        {
            originalData = await CommonSettings.ReadInputBytesAsync(settings.DataPath, cancellationToken);
        }

        var trustAnchors = LoadTrustAnchors(settings.TrustPath);

        var validator = new CadesSignatureValidator(
            new ValidationOptions { CheckRevocation = false, TrustSystemRoots = trustAnchors is null });

        var result = validator.Validate(
            cmsBytes,
            originalData ?? throw new InvalidOperationException("Original data file is required. Use --data <path>."),
            trustAnchors);

        if (settings.Json)
        {
            var output = new CadesValidateOutput
            {
                File = settings.SignaturePath,
                IsValid = result.IsValid,
                IsSignatureValid = result.IsSignatureValid,
                IsIntegrityValid = result.IsIntegrityValid,
                IsCertificateChainValid = result.IsCertificateChainValid,
                HasValidTimestamp = result.HasValidTimestamp,
                IsLtvDataValid = result.IsLtvDataValid,
                HasValidArchiveTimestamp = result.HasValidArchiveTimestamp,
                Signer = result.SignerCertificate?.Subject,
                Issuer = result.SignerCertificate?.Issuer,
                Serial = result.SignerCertificate?.SerialNumber,
                Thumbprint = result.SignerCertificate?.Thumbprint,
                SigningTime = result.SigningTime,
                Errors = [.. result.Errors],
                Warnings = [.. result.Warnings],
            };
            Console.WriteLine(JsonSerializer.Serialize(output, CliJsonContext.Default.CadesValidateOutput));
            return result.IsValid ? 0 : 1;
        }

        var table = new Table();
        table.AddColumn("Check");
        table.AddColumn("Result");

        table.AddRow("CMS parsed", result.SignerCertificate is not null ? "[green]OK[/]" : "[red]FAIL[/]");
        table.AddRow("Content integrity", result.IsIntegrityValid ? "[green]OK[/]" : "[red]FAIL[/]");
        table.AddRow("Cryptographic signature", result.IsSignatureValid ? "[green]OK[/]" : "[red]FAIL[/]");
        table.AddRow("Certificate chain", result.IsCertificateChainValid ? "[green]OK[/]" : "[red]FAIL[/]");

        if (result.HasValidTimestamp.HasValue)
        {
            table.AddRow("Timestamp", result.HasValidTimestamp.Value ? "[green]OK[/]" : "[red]FAIL[/]");
        }

        if (result.IsLtvDataValid.HasValue)
        {
            table.AddRow("LTV data", result.IsLtvDataValid.Value ? "[green]OK[/]" : "[yellow]WARN[/]");
        }

        if (result.SignerCertificate is not null)
        {
            AnsiConsole.MarkupLine($"\nSigner: [bold]{result.SignerCertificate.Subject}[/]");
            AnsiConsole.MarkupLine($"Issuer: {result.SignerCertificate.Issuer}");
            AnsiConsole.MarkupLine($"Serial: {result.SignerCertificate.SerialNumber}");
            AnsiConsole.MarkupLine($"Thumbprint: {result.SignerCertificate.Thumbprint}");
        }

        if (result.SigningTime.HasValue)
        {
            AnsiConsole.MarkupLine($"Signing time: {result.SigningTime:yyyy-MM-dd HH:mm:ss}");
        }

        AnsiConsole.Write(table);

        if (result.Errors.Count > 0)
        {
            AnsiConsole.MarkupLine("\n[red]Errors:[/]");
            foreach (var err in result.Errors)
            {
                AnsiConsole.MarkupLine($"  [red]✗[/] {err}");
            }
        }

        if (result.Warnings.Count > 0)
        {
            AnsiConsole.MarkupLine("\n[yellow]Warnings:[/]");
            foreach (var warn in result.Warnings)
            {
                AnsiConsole.MarkupLine($"  [yellow]![/] {warn}");
            }
        }

        var isValid = result.IsValid;
        AnsiConsole.MarkupLine(isValid ? "\n[green]✓ Signature is VALID[/]" : "\n[red]✗ Signature is INVALID[/]");

        return isValid ? 0 : 1;
    }

    private List<X509Certificate2>? LoadTrustAnchors(string? trustPath)
    {
        if (trustPath is null)
        {
            return null;
        }

        byte[] raw = File.ReadAllBytes(trustPath);
        return [.. _certChainService.LoadCertsFromBytes(raw)];
    }
}

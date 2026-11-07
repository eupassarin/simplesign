using SimpleSign.Cli.Rendering;
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
    private readonly SimpleSign.Core.Http.IHttpClientProvider _httpClientProvider;

    public CadesValidateCommand(ICertificateChainService certChainService, SimpleSign.Core.Http.IHttpClientProvider httpClientProvider)
    {
        _certChainService = certChainService;
        _httpClientProvider = httpClientProvider;
    }

    /// <summary>CAdES validate command settings.</summary>
    internal sealed class Settings : TrustedValidationSettings
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

        [CommandOption("--check-revocation")]
        [Description("Check the revocation of the signer and TSA chains (CRL/OCSP, needs network)")]
        public bool CheckRevocation { get; init; }

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

            return ValidateTrustOptions();
        }
    }

    public override async Task<int> ExecuteAsync(
        CommandContext context, Settings settings, CancellationToken cancellationToken)
    {
        byte[] cmsBytes = await CommonSettings.ReadInputBytesAsync(settings.SignaturePath, cancellationToken);

        byte[]? originalData = null;
        if (settings.DataPath is not null)
        {
            originalData = await CommonSettings.ReadInputBytesAsync(settings.DataPath, cancellationToken);
        }

        var (policy, extraAnchors) = await settings.LoadTrustAsync(cancellationToken);
        List<X509Certificate2>? trustAnchors = [.. LoadTrustAnchors(settings.TrustPath) ?? [], .. extraAnchors];
        if (trustAnchors.Count == 0)
        {
            trustAnchors = null;
        }

        var validator = new CadesSignatureValidator(
            new ValidationOptions { CheckRevocation = settings.CheckRevocation, TrustSystemRoots = trustAnchors is null, Policy = policy },
            chainRevocationChecker: TrustedValidationSettings.RevocationCheckerFor(_httpClientProvider));

        var result = await validator.ValidateAsync(
            cmsBytes,
            originalData ?? throw new InvalidOperationException("Original data file is required. Use --data <path>."),
            trustAnchors,
            cancellationToken);

        if (settings.Json)
        {
            var report = ValidationReportRenderer.ToDto(result.SubIndication, result.Constraints, result.SignerCertificate);
            var output = new CadesValidateOutput
            {
                File = settings.SignaturePath,
                IsValid = result.IsValid,
                Indication = result.Indication.ToString(),
                SubIndication = report.SubIndication,
                NotRevoked = result.IsNotRevoked,
                PublicKey = report.PublicKey,
                Constraints = report.Constraints,
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

        ValidationReportRenderer.Write(result.Indication, result.SubIndication, result.Constraints, result.SignerCertificate, settings.Spanish);
        var isValid = result.IsValid;
        AnsiConsole.MarkupLine(result.Indication switch
        {
            SignatureIndication.Valid => "\n[green]✓ Signature is VALID[/]",
            SignatureIndication.Invalid => "\n[red]✗ Signature is INVALID[/]",
            _ => "\n[yellow]? Signature is INDETERMINATE[/]"
                + (result.SubIndication is { } sub ? $" ({sub.ToEtsiName()})" : string.Empty),
        });

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

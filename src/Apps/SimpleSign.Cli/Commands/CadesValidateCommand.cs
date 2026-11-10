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

        var (policy, extraAnchors) = await settings.LoadTrustAsync(_httpClientProvider, cancellationToken);
        List<X509Certificate2>? trustAnchors = [.. LoadTrustAnchors(settings.TrustPath) ?? [], .. extraAnchors];
        if (trustAnchors.Count == 0)
        {
            trustAnchors = null;
        }

        var validator = new CadesSignatureValidator(
            new ValidationOptions
            {
                CheckRevocation = settings.CheckRevocation,
                TrustSystemRoots = !settings.NoSystemRoots,
                Policy = policy,
                Level = settings.ValidationLevel,
                Verifier = settings.Verifier,
                TrustedLists = settings.LoadedTrustedLists.Count > 0 ? settings.LoadedTrustedLists : null,
            },
            chainRevocationChecker: settings.RevocationCheckerFor(_httpClientProvider));

        // Every signer and countersignature; an attached signature carries its content (no --data).
        var report = await validator.ValidateAllAsync(cmsBytes, originalData, trustAnchors, cancellationToken);
        var signers = Flatten(report.Signers, "signer").ToList();
        settings.WriteReports([.. signers.Select(s => s.Signer.Result.ToReportEntry(s.Id))]);

        if (settings.Json)
        {
            var dtos = report.Signers.Select((s, i) => JsonMapper.MapCadesSigner(s, $"signer-{i + 1}")).ToList();
            var first = report.Signers.FirstOrDefault()?.Result;
            var firstReport = first is null ? default : ValidationReportRenderer.ToDto(first.SubIndication, first.Constraints, first.SignerCertificate);
            var output = new CadesValidateOutput
            {
                File = settings.SignaturePath,
                IsValid = report.IsValid,
                Indication = first?.Indication.ToString() ?? SignatureIndication.Invalid.ToString(),
                SubIndication = firstReport.SubIndication,
                NotRevoked = first?.IsNotRevoked,
                PublicKey = firstReport.PublicKey,
                Constraints = firstReport.Constraints ?? [],
                IsSignatureValid = first?.IsSignatureValid ?? false,
                IsIntegrityValid = first?.IsIntegrityValid ?? false,
                IsCertificateChainValid = first?.IsCertificateChainValid ?? false,
                HasValidTimestamp = first?.HasValidTimestamp,
                IsLtvDataValid = first?.IsLtvDataValid,
                HasValidArchiveTimestamp = first?.HasValidArchiveTimestamp,
                Signer = first?.SignerCertificate?.Subject,
                Issuer = first?.SignerCertificate?.Issuer,
                Serial = first?.SignerCertificate?.SerialNumber,
                Thumbprint = first?.SignerCertificate?.Thumbprint,
                SigningTime = first?.SigningTime,
                Errors = first is null ? [.. report.Errors] : [.. first.Errors],
                Warnings = first is null ? [] : [.. first.Warnings],
                ReportErrors = [.. report.Errors],
                Signatures = dtos,
            };
            Console.WriteLine(JsonSerializer.Serialize(output, CliJsonContext.Default.CadesValidateOutput));
            return report.IsValid ? 0 : 1;
        }

        foreach (string error in report.Errors)
        {
            AnsiConsole.MarkupLine($"[red]✗[/] {error.EscapeMarkup()}");
        }

        foreach (var (id, signer) in signers)
        {
            if (signers.Count > 1)
            {
                AnsiConsole.MarkupLine($"\n[bold]{id.EscapeMarkup()}[/]");
            }

            WriteText(signer.Result, settings.Spanish);
        }

        return report.IsValid ? 0 : 1;
    }

    /// <summary>The signers in order, each followed by its countersignatures: <c>signer-1</c>, <c>signer-1.1</c>…</summary>
    private static IEnumerable<(string Id, CadesSignerValidationResult Signer)> Flatten(IReadOnlyList<CadesSignerValidationResult> signers, string prefix)
    {
        for (int i = 0; i < signers.Count; i++)
        {
            string id = prefix == "signer" ? $"signer-{i + 1}" : $"{prefix}.{i + 1}";
            yield return (id, signers[i]);
            foreach (var counter in Flatten(signers[i].CounterSignatures, id))
            {
                yield return counter;
            }
        }
    }

    private static void WriteText(CadesValidationResult result, bool spanish)
    {
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

        ValidationReportRenderer.Write(result.Indication, result.SubIndication, result.Constraints, result.SignerCertificate, spanish);
        AnsiConsole.MarkupLine(result.Indication switch
        {
            SignatureIndication.Valid => "\n[green]✓ Signature is VALID[/]",
            SignatureIndication.Invalid => "\n[red]✗ Signature is INVALID[/]",
            _ => "\n[yellow]? Signature is INDETERMINATE[/]"
                + (result.SubIndication is { } sub ? $" ({sub.ToEtsiName()})" : string.Empty),
        });
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

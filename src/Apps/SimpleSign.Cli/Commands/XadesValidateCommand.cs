using SimpleSign.Cli.Rendering;
using System.ComponentModel;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using SimpleSign.Cli.Json;
using SimpleSign.Core.Signing;
using SimpleSign.Core.Validation;
using SimpleSign.XAdES;
using Spectre.Console;
using Spectre.Console.Cli;

namespace SimpleSign.Cli.Commands;

/// <summary>Validate a signed XAdES XML document.</summary>
[Description("Validate a signed XAdES XML document")]
internal sealed class XadesValidateCommand : AsyncCommand<XadesValidateCommand.Settings>
{
    private readonly ICertificateChainService _certChainService;
    private readonly SimpleSign.Core.Http.IHttpClientProvider _httpClientProvider;

    public XadesValidateCommand(ICertificateChainService certChainService, SimpleSign.Core.Http.IHttpClientProvider httpClientProvider)
    {
        _certChainService = certChainService;
        _httpClientProvider = httpClientProvider;
    }

    /// <summary>XAdES validate command settings.</summary>
    internal sealed class Settings : TrustedValidationSettings
    {
        /// <summary>Signed XML file.</summary>
        [CommandArgument(0, "<signature>")]
        [Description("Signed XML file")]
        public string SignaturePath { get; init; } = null!;

        /// <summary>Original data file (required for detached signatures).</summary>
        [CommandOption("--data|-d <PATH>")]
        [Description("Original data file (required for detached signatures)")]
        public string? DataPath { get; init; }

        /// <summary>Content of a data object the signature references by URI.</summary>
        [CommandOption("--external-object <URI=PATH>")]
        [Description("Content of a data object the signature references by URI (may be specified multiple times; use it for the detached document too)")]
        public string[]? ExternalObjects { get; init; }

        /// <summary>Trust anchor certificate(s) — PEM or DER.</summary>
        [CommandOption("--trust <PATH>")]
        [Description("Trust anchor certificate(s) — PEM or DER")]
        public string? TrustPath { get; init; }

        /// <summary>Enable online revocation checking (OCSP/CRL).</summary>
        [CommandOption("--check-revocation")]
        [Description("Enable online revocation checking (OCSP/CRL)")]
        public bool CheckRevocation { get; init; }

        /// <summary>Output validation result as JSON instead of a table.</summary>
        [CommandOption("--json")]
        [Description("Output result as JSON")]
        public bool Json { get; init; }

        public override ValidationResult Validate()
        {
            if (!File.Exists(SignaturePath))
            {
                return ValidationResult.Error($"File not found: {SignaturePath}");
            }

            if (DataPath is not null && !File.Exists(DataPath))
            {
                return ValidationResult.Error($"Data file not found: {DataPath}");
            }

            if (ExternalObjects is { Length: > 0 })
            {
                if (DataPath is not null)
                {
                    return ValidationResult.Error("Use either --data or --external-object: with --external-object, give the detached document as URI=PATH too.");
                }

                if (ExternalObjects.FirstOrDefault(o => AdesOptionSupport.SplitUriAndPath(o) is null) is { } malformed)
                {
                    return ValidationResult.Error($"Invalid --external-object: {malformed}. Expected URI=PATH");
                }

                if (AdesOptionSupport.ValidateFiles("--external-object", ExternalObjects.Select(o => AdesOptionSupport.SplitUriAndPath(o)!.Value.Path)) is { } missing)
                {
                    return ValidationResult.Error(missing);
                }
            }

            return ValidateTrustOptions();
        }
    }

    public override async Task<int> ExecuteAsync(
        CommandContext context, Settings settings, CancellationToken cancellationToken)
    {
        byte[] signedXml = await CommonSettings.ReadInputBytesAsync(settings.SignaturePath, cancellationToken);

        var (policy, extraAnchors) = await settings.LoadTrustAsync(_httpClientProvider, cancellationToken);
        List<X509Certificate2>? trustAnchors = [.. LoadTrustAnchors(settings.TrustPath) ?? [], .. extraAnchors];
        if (trustAnchors.Count == 0)
        {
            trustAnchors = null;
        }

        var validator = new XadesSignatureValidator(
            new ValidationOptions
            {
                CheckRevocation = settings.CheckRevocation,
                TrustSystemRoots = !settings.NoSystemRoots,
                Policy = policy,
                Level = settings.ValidationLevel,
                Verifier = settings.Verifier,
                TrustedLists = settings.LoadedTrustedLists.Count > 0 ? settings.LoadedTrustedLists : null,
                TimedTrustAnchors = settings.LoadedTimedAnchors.Count > 0 ? settings.LoadedTimedAnchors : null,
                SignatureQualifiers = settings.LoadedQualifiers.Count > 0 ? settings.LoadedQualifiers : null,
            },
            logger: null,
            chainRevocationChecker: settings.RevocationCheckerFor(_httpClientProvider));
        byte[]? originalData = settings.DataPath is null
            ? null
            : await CommonSettings.ReadInputBytesAsync(settings.DataPath, cancellationToken);
        IReadOnlyList<XadesValidationResult> results;
        if (settings.ExternalObjects is { Length: > 0 })
        {
            var externalData = new Dictionary<string, byte[]>(StringComparer.Ordinal);
            foreach (string value in settings.ExternalObjects)
            {
                var (uri, path, _) = AdesOptionSupport.SplitUriAndPath(value)!.Value;
                externalData[uri] = await File.ReadAllBytesAsync(path, cancellationToken);
            }

            results = await validator.ValidateAllAsync(signedXml, trustAnchors, externalData, cancellationToken);
            if (results.Count == 0)
            {
                results = [await validator.ValidateAsync(signedXml, trustAnchors, externalData, cancellationToken)];
            }
        }
        else
        {
            // Every ds:Signature; a document without one gets the single result that says so.
            results = await validator.ValidateAllAsync(signedXml, trustAnchors, originalData, cancellationToken);
            if (results.Count == 0)
            {
                results = [await validator.ValidateAsync(signedXml, trustAnchors, originalData, cancellationToken)];
            }
        }

        var all = Flatten(results).ToList();
        bool allValid = all.All(r => r.IsValid);
        var result = results[0];
        settings.WriteReports([.. all.Select(r => r.ToReportEntry())]);

        if (settings.Json)
        {
            var report = ValidationReportRenderer.ToDto(result.SubIndication, result.Constraints, result.SignerCertificate);
            var output = new XadesValidateOutput
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
                HasValidSignatureTimeStamp = result.HasValidSignatureTimeStamp,
                IsLtvDataValid = result.IsLtvDataValid,
                HasValidArchiveTimeStamp = result.HasValidArchiveTimeStamp,
                Signer = result.SignerCertificate?.Subject,
                Issuer = result.SignerCertificate?.Issuer,
                Serial = result.SignerCertificate?.SerialNumber,
                Thumbprint = result.SignerCertificate?.Thumbprint,
                SigningTime = result.SigningTime,
                DetectedLevel = result.DetectedLevel.ToString(),
                Errors = [.. result.Errors],
                Warnings = [.. result.Warnings],
                Signatures = [.. results.Select(JsonMapper.MapXadesSignature)],
            };
            Console.WriteLine(JsonSerializer.Serialize(output, CliJsonContext.Default.XadesValidateOutput));
            return allValid ? 0 : 1;
        }

        foreach (var signature in all)
        {
            if (all.Count > 1)
            {
                AnsiConsole.MarkupLine($"\n[bold]{(signature.SignatureId ?? "Signature").EscapeMarkup()}[/]");
            }

            WriteText(signature, settings.Spanish);
        }

        return allValid ? 0 : 1;
    }

    /// <summary>The signatures in order, each followed by its countersignatures.</summary>
    private static IEnumerable<XadesValidationResult> Flatten(IEnumerable<XadesValidationResult> results) =>
        results.SelectMany(r => new[] { r }.Concat(Flatten(r.CounterSignatures)));

    private static void WriteText(XadesValidationResult result, bool spanish)
    {

        var table = new Table();
        table.AddColumn("Check");
        table.AddColumn("Result");

        table.AddRow("XMLDSig parsed", result.SignerCertificate is not null ? "[green]OK[/]" : "[red]FAIL[/]");
        table.AddRow("Cryptographic signature", result.IsSignatureValid ? "[green]OK[/]" : "[red]FAIL[/]");
        table.AddRow("Document integrity", result.IsIntegrityValid ? "[green]OK[/]" : "[red]FAIL[/]");
        table.AddRow("Certificate chain", result.IsCertificateChainValid ? "[green]OK[/]" : "[red]FAIL[/]");

        table.AddRow("XAdES level", result.DetectedLevel switch
        {
            AdesBaselineLevel.Archive => "B-LTA (Archive)",
            AdesBaselineLevel.LongTerm => "B-LT (Long-Term)",
            AdesBaselineLevel.Timestamped => "B-T (Timestamped)",
            _ => "B-B (Basic)"
        });

        if (result.HasValidSignatureTimeStamp.HasValue)
        {
            table.AddRow("Signature timestamp", result.HasValidSignatureTimeStamp.Value ? "[green]OK[/]" : "[red]FAIL[/]");
        }

        if (result.IsLtvDataValid.HasValue)
        {
            table.AddRow("LTV data", result.IsLtvDataValid.Value ? "[green]OK[/]" : "[yellow]WARN[/]");
        }

        if (result.HasValidArchiveTimeStamp.HasValue)
        {
            table.AddRow("Archive timestamp", result.HasValidArchiveTimeStamp.Value ? "[green]OK[/]" : "[red]FAIL[/]");
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

        ValidationReportRenderer.Write(result.Indication, result.SubIndication, result.Constraints, result.SignerCertificate, spanish, result.Qualification);
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

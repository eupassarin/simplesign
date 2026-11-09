using System.ComponentModel;
using SimpleSign.Brazil;
using SimpleSign.Brazil.IcpBrasil;
using SimpleSign.Brazil.Signing;
using SimpleSign.Cli.Json;
using SimpleSign.Cli.Rendering;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Extensions;
using SimpleSign.Core.Http;
using SimpleSign.Core.Revocation;
using SimpleSign.Core.Validation;
using SimpleSign.PAdES.Inspection;
using SimpleSign.PAdES.Validation;
using Spectre.Console;
using Spectre.Console.Cli;
using SimpleSign.Brazil.GovBr;

namespace SimpleSign.Cli.Commands;

/// <summary>Validate PDF signatures.</summary>
[Description("Validate PDF signatures")]
internal sealed class ValidateCommand : AsyncCommand<ValidateCommand.Settings>
{
    private readonly IHttpClientProvider _httpClientProvider;
    private readonly IRevocationChecker _revocationChecker;
    private readonly ICertificateChainService _certChainService;
    private readonly ICryptoVerifier _cryptoVerifier;
    private readonly IIntegrityVerifier _integrityVerifier;
    private readonly ICmsParser _cmsParser;
    private readonly ITimestampValidator _timestampValidator;
    private readonly IPdfSignatureInspector _inspector;
    private readonly IConformanceDetector _conformanceDetector;
    private readonly IEnumerable<ITrustAnchorProvider> _trustAnchorProviders;

    public ValidateCommand(
        IHttpClientProvider httpClientProvider,
        IRevocationChecker revocationChecker,
        ICertificateChainService certChainService,
        ICryptoVerifier cryptoVerifier,
        IIntegrityVerifier integrityVerifier,
        ICmsParser cmsParser,
        ITimestampValidator timestampValidator,
        IPdfSignatureInspector inspector,
        IConformanceDetector conformanceDetector,
        IEnumerable<ITrustAnchorProvider> trustAnchorProviders)
    {
        _httpClientProvider = httpClientProvider;
        _revocationChecker = revocationChecker;
        _certChainService = certChainService;
        _cryptoVerifier = cryptoVerifier;
        _integrityVerifier = integrityVerifier;
        _cmsParser = cmsParser;
        _timestampValidator = timestampValidator;
        _inspector = inspector;
        _conformanceDetector = conformanceDetector;
        _trustAnchorProviders = trustAnchorProviders;
    }

    /// <summary>Validate command settings.</summary>
    internal sealed class Settings : TrustedValidationSettings
    {
        /// <summary>Input PDF file to validate.</summary>
        [CommandArgument(0, "<input>")]
        [Description("Input PDF file to validate")]
        public string InputPath { get; init; } = null!;

        /// <summary>Extra trust anchor certificate(s), PEM or DER, added to the default roots.</summary>
        [CommandOption("--trust <PATH>")]
        [Description("Extra trust anchor certificate(s), PEM or DER, added to the default roots")]
        public string? TrustPath { get; init; }

        /// <summary>Skip CRL/OCSP revocation checks.</summary>
        [CommandOption("--no-revocation")]
        [Description("Skip CRL/OCSP revocation checks")]
        public bool NoRevocation { get; init; }

        /// <summary>Output as JSON (machine-readable).</summary>
        [CommandOption("--json")]
        [Description("Output as JSON (machine-readable)")]
        public bool Json { get; init; }

        /// <summary>One-line summary per signature instead of full tree.</summary>
        [CommandOption("--simple")]
        [Description("One-line summary per signature instead of full tree")]
        public bool Simple { get; init; }

        public override ValidationResult Validate()
        {
            if (!File.Exists(InputPath))
            {
                return ValidationResult.Error($"File not found: {InputPath}");
            }

            if (TrustPath is not null && !File.Exists(TrustPath))
            {
                return ValidationResult.Error($"Trust anchor file not found: {TrustPath}");
            }

            return ValidateTrustOptions();
        }
    }

    public override async Task<int> ExecuteAsync(CommandContext context, Settings settings, CancellationToken cancellationToken)
    {
        using var loggerFactory = settings.CreateLoggerFactory();
        var (policy, extraAnchors) = await settings.LoadTrustAsync(cancellationToken);
        List<System.Security.Cryptography.X509Certificates.X509Certificate2> roots =
        [
            .. settings.TrustPath is null
                ? []
                : _certChainService.LoadCertsFromBytes(await File.ReadAllBytesAsync(settings.TrustPath, cancellationToken)),
            .. extraAnchors,
        ];
        var options = new ValidationOptions
        {
            CheckRevocation = !settings.NoRevocation,
            TrustSystemRoots = !settings.NoSystemRoots,
            TrustedRoots = roots.Count == 0 ? null : roots,
            Policy = policy,
            Level = settings.ValidationLevel,
            Verifier = settings.Verifier,
        };
        var logger = settings.CreateLogger<PdfSignatureValidator>();
        var validator = new PdfSignatureValidator(
            _httpClientProvider, _revocationChecker, options, logger,
            trustAnchorProviders: _trustAnchorProviders,
            certChainService: _certChainService,
            cryptoVerifier: _cryptoVerifier,
            integrityVerifier: _integrityVerifier,
            cmsParser: _cmsParser,
            timestampValidator: _timestampValidator,
            chainValidationProviders:
            [
                .. new IcpBrasilExtension(_httpClientProvider.GetClient(), logger).ChainValidationProviders,
                .. new GovBrExtension(_httpClientProvider.GetClient(), logger).ChainValidationProviders,
            ]);

        await using var stream = File.OpenRead(settings.InputPath);
        var results = await validator.ValidateAsync(stream, cancellationToken: cancellationToken);
        settings.WriteReports([.. results.Select(r => r.ToReportEntry())]);

        // Run inspection to get PAdES conformance levels and AEA info
        stream.Position = 0;
        var inspection = await _inspector.InspectAsync(stream, cancellationToken: cancellationToken);
        var conformanceLevels = _conformanceDetector.DetectAll(inspection)
            .GroupBy(x => x.Signature.FieldName)
            .ToDictionary(g => g.Key, g => g.First().Level);
        var aeaInfo = inspection.Signatures
            .Where(s => s.CommitmentTypeOid is not null)
            .GroupBy(s => s.FieldName)
            .ToDictionary(g => g.Key, g => (g.First().CommitmentTypeOid!, g.First().SignaturePolicyOid, g.First().ManifestJson));

        // Build lookup from field name to inspection signature
        var inspectionLookup = inspection.Signatures
            .GroupBy(s => s.FieldName)
            .ToDictionary(g => g.Key, g => g.First());

        if (settings.Json)
        {
            OutputJson(settings.InputPath, results, conformanceLevels,
                inspectionLookup.ToDictionary(kv => kv.Key, kv => kv.Value.ManifestJson));
        }
        else if (settings.Simple)
        {
            OutputSimple(settings.InputPath, results, conformanceLevels);
        }
        else
        {
            OutputText(settings.InputPath, results, conformanceLevels, aeaInfo, inspection, inspectionLookup, settings.Spanish);
        }

        bool hasUnvalidated = results.Any(r => r.Indication != SignatureIndication.Valid);
        return hasUnvalidated ? 1 : 0;
    }

    private static void OutputSimple(string inputPath, IReadOnlyList<SignatureValidationResult> results,
        Dictionary<string, PAdESConformanceLevel> conformanceLevels)
    {
        var fileName = Path.GetFileName(inputPath);
        var userSigs = results.Where(r => !r.IsDocumentTimestamp).ToList();
        var validCount = userSigs.Count(r => r.Indication == SignatureIndication.Valid);
        var indeterminateCount = userSigs.Count(r => r.Indication == SignatureIndication.Indeterminate);
        var invalidCount = userSigs.Count(r => r.Indication == SignatureIndication.Invalid);
        var statusIcon = userSigs.Count == 0
            ? "[yellow]?[/]"
            : invalidCount > 0
                ? "[red]✗[/]"
                : indeterminateCount > 0
                    ? "[yellow]?[/]"
                    : "[green]✓[/]";

        var summary = $"{validCount}/{userSigs.Count} valid";
        if (indeterminateCount > 0)
        {
            summary += $", {indeterminateCount} indeterminate";
        }
        if (invalidCount > 0)
        {
            summary += $", {invalidCount} invalid";
        }
        AnsiConsole.MarkupLine($"{statusIcon} [bold]{fileName.EscapeMarkup()}[/]  {summary}");

        foreach (var r in results)
        {
            string icon;
            if (r.IsDocumentTimestamp)
            {
                icon = r.Indication switch
                {
                    SignatureIndication.Valid => "[green]T[/]",
                    SignatureIndication.Indeterminate => "[yellow]?[/]",
                    _ => "[red]T[/]"
                };
            }
            else
            {
                icon = r.Indication switch
                {
                    SignatureIndication.Valid => "[green]✓[/]",
                    SignatureIndication.Indeterminate => "[yellow]?[/]",
                    _ => "[red]✗[/]"
                };
            }

            var signer = (r.SignerName ?? "unknown").EscapeMarkup();
            var level = conformanceLevels.TryGetValue(r.FieldName, out var l) ? $"  [dim]{Formatting.FormatLevel(l)}[/]" : string.Empty;
            var time = r.SigningTime.HasValue ? $"  [dim]{r.SigningTime.Value:yyyy-MM-dd}[/]" : string.Empty;
            var errSuffix = r.Indication switch
            {
                SignatureIndication.Valid => string.Empty,
                SignatureIndication.Indeterminate => $"  [yellow]{(r.Errors.Count > 0 ? r.Errors[0].EscapeMarkup() : "indeterminate")}[/]",
                _ => $"  [red]{(r.Errors.Count > 0 ? r.Errors[0].EscapeMarkup() : "invalid")}[/]"
            };

            AnsiConsole.MarkupLine($"  {icon} {r.FieldName.EscapeMarkup()}  {signer}{level}{time}{errSuffix}");
        }
    }

    private static void AddBrasilNode(TreeNode sigNode, SignatureValidationResult result, byte[]? manifestJson)
    {
        var level = Lei14063.Classify(result, manifestJson);
        if (result.ChainValidationRegion != "BR" && level is null)
        {
            return;
        }

        var node = sigNode.AddNode($"Brasil:       [blue]{(level is null ? "—" : $"Lei 14.063: {level}")}[/]");
        var metadata = result.ChainValidationMetadata ?? new Dictionary<string, string>();
        if (metadata.TryGetValue("BR.Hierarchy", out var hierarchy))
        {
            node.AddNode($"Hierarchy:      {hierarchy.EscapeMarkup()} {(result.PolicyLevel ?? string.Empty).EscapeMarkup()}");
        }

        if (result.SignerId is not null)
        {
            node.AddNode($"{(result.SignerIdType ?? "ID").EscapeMarkup()}:{new string(' ', Math.Max(1, 16 - (result.SignerIdType ?? "ID").Length - 1))}{result.SignerId.EscapeMarkup()}");
        }

        if (metadata.TryGetValue("BR.ResponsibleCpf", out var responsible))
        {
            node.AddNode($"Responsible:    CPF {responsible.EscapeMarkup()}");
        }

        foreach (var (key, value) in metadata.Where(m => m.Key.StartsWith("BR.Registration.", StringComparison.Ordinal)))
        {
            node.AddNode($"Registration:   {key["BR.Registration.".Length..].ToUpperInvariant().EscapeMarkup()} {value.EscapeMarkup()}");
        }

        if (metadata.TryGetValue("BR.SignaturePolicy", out var policy))
        {
            string status = metadata.GetValueOrDefault("BR.SignaturePolicyStatus") ?? string.Empty;
            string color = status == "Valid" ? "green" : status == "Invalid" ? "red" : "yellow";
            node.AddNode($"Policy:         {policy.EscapeMarkup()} [{color}]{status.EscapeMarkup()}[/]");
        }

        if (metadata.TryGetValue("BR.RevocationStatus", out var revocation))
        {
            node.AddNode($"Revocation:     {revocation.EscapeMarkup()} [dim]at {metadata.GetValueOrDefault("BR.ValidationTime", string.Empty).EscapeMarkup()}[/]");
        }
    }

    private static void OutputJson(string inputPath, IReadOnlyList<SignatureValidationResult> results,
        Dictionary<string, PAdESConformanceLevel> conformanceLevels, IReadOnlyDictionary<string, byte[]?> manifests)
    {
        var fileName = Path.GetFileName(inputPath);
        var output = JsonMapper.MapValidation(fileName, results, conformanceLevels, manifests);
        var json = System.Text.Json.JsonSerializer.Serialize(output, CliJsonContext.Default.ValidateOutput);
        Console.WriteLine(json);
    }

    private static void OutputText(string inputPath, IReadOnlyList<SignatureValidationResult> results,
        Dictionary<string, PAdESConformanceLevel> conformanceLevels,
        Dictionary<string, (string CommitmentOid, string? PolicyOid, byte[]? ManifestJson)> aeaInfo,
        PdfInspectionResult inspection,
        Dictionary<string, SignatureFieldInfo> inspectionLookup,
        bool spanish)
    {
        var fileName = Path.GetFileName(inputPath);

        // Only count user signatures (not infrastructure document timestamps) in the valid/total header
        var userSigs = results.Where(r => !r.IsDocumentTimestamp).ToList();
        var docTimestamps = results.Where(r => r.IsDocumentTimestamp).ToList();

        var validCount = userSigs.Count(r => r.Indication == SignatureIndication.Valid);
        var indeterminateCount = userSigs.Count(r => r.Indication == SignatureIndication.Indeterminate);
        var invalidCount = userSigs.Count(r => r.Indication == SignatureIndication.Invalid);
        var summaryColor = invalidCount > 0 ? "red" : indeterminateCount > 0 ? "yellow" : "green";
        var summary = $"{validCount}/{userSigs.Count} valid";
        if (indeterminateCount > 0)
        {
            summary += $", {indeterminateCount} indeterminate";
        }
        if (invalidCount > 0)
        {
            summary += $", {invalidCount} invalid";
        }

        var tree = new Tree($"[bold]{fileName.EscapeMarkup()}[/]  [{summaryColor}]{summary}[/]");
        tree.Style = Style.Parse("dim");

        // Document-level info
        var doc = inspection.Document;
        var docNode = tree.AddNode("[blue]Document[/]");
        docNode.AddNode($"Signatures: [bold]{userSigs.Count}[/] user + [bold]{docTimestamps.Count}[/] timestamps");
        docNode.AddNode($"Encrypted:  {(doc.IsEncrypted ? "[green]✓[/] Yes" : "No")}");
        docNode.AddNode($"DocMDP:     {FormatDocMdp(doc)}");
        docNode.AddNode($"PDF/A:      {Formatting.FormatPdfA(doc.PdfALevel).EscapeMarkup()}");
        if (doc.SecurityStore is { IsPresent: true })
        {
            docNode.AddNode("[green]✓[/] DSS [dim](embedded)[/]");
        }
        else
        {
            docNode.AddNode("[red]✗[/] DSS [dim]— not embedded[/]");
        }

        // Render user signatures first
        foreach (var result in results)
        {
            if (result.IsDocumentTimestamp)
            {
                continue;
            }

            var status = FormatIndication(result.Indication);

            var sigNode = tree.AddNode($"{result.FieldName}  {status}");
            sigNode.AddNode($"Signer:       [bold]{(result.SignerName ?? "(unknown)").EscapeMarkup()}[/]");

            // SubFilter
            if (result.SubFilter is not null)
            {
                sigNode.AddNode($"SubFilter:    {result.SubFilter.EscapeMarkup()}");
            }

            // PAdES level
            if (conformanceLevels.TryGetValue(result.FieldName, out var level))
            {
                sigNode.AddNode($"PAdES:        [bold]{Formatting.FormatLevel(level).EscapeMarkup()}[/]");
            }

            // Metadata
            inspectionLookup.TryGetValue(result.FieldName, out var sig);
            if (sig?.Reason is not null)
            {
                sigNode.AddNode($"Reason:       {sig.Reason.EscapeMarkup()}");
            }

            if (sig?.Location is not null)
            {
                sigNode.AddNode($"Location:     {sig.Location.EscapeMarkup()}");
            }

            if (sig?.ContactInfo is not null)
            {
                sigNode.AddNode($"Contact:      {sig.ContactInfo.EscapeMarkup()}");
            }

            // Certificate details
            if (result.SignerCertificate is { } cert || sig?.Signer is not null)
            {
                var certNode = sigNode.AddNode("[blue]Certificate[/]");

                if (sig?.Signer is { } signerInfo)
                {
                    certNode.AddNode($"Subject:        [bold]{signerInfo.Subject.EscapeMarkup()}[/]");
                    var issuer = result.SignerCertificate is not null
                        ? GetCn(result.SignerCertificate.IssuerName.Name)
                        : signerInfo.Issuer;
                    certNode.AddNode($"Issuer:         [dim]{issuer.EscapeMarkup()}[/]");
                    certNode.AddNode($"Serial:         {signerInfo.SerialNumber}");
                    certNode.AddNode($"Thumbprint:     {Formatting.FormatThumbprint(signerInfo.Thumbprint)}");
                    certNode.AddNode($"Key:            {signerInfo.KeyAlgorithm} {(signerInfo.KeySizeBits.HasValue ? $"{signerInfo.KeySizeBits}-bit" : "[dim](unknown)[/]")}");
                    if (result.SignerCertificate is not null)
                    {
                        certNode.AddNode($"Valid:          [dim]{result.SignerCertificate.NotBefore:yyyy-MM-dd} \u2013 {result.SignerCertificate.NotAfter:yyyy-MM-dd}[/]");
                    }
                    else
                    {
                        certNode.AddNode($"Valid:          [dim]{signerInfo.NotBefore:yyyy-MM-dd} \u2013 {signerInfo.NotAfter:yyyy-MM-dd}[/]");
                    }
                    certNode.AddNode(signerInfo.HasNonRepudiation
                        ? "NonRepudiation: [green]✓[/]"
                        : "NonRepudiation: [red]✗[/]");
                    certNode.AddNode(signerInfo.KeyUsages.Count > 0
                        ? $"Key Usage:      {string.Join(", ", signerInfo.KeyUsages)}"
                        : "Key Usage:      [dim]— not present[/]");
                    if (signerInfo.ExtendedKeyUsages.Count > 0)
                    {
                        certNode.AddNode($"Extended KU:    {string.Join(", ", signerInfo.ExtendedKeyUsages.Select(Formatting.FormatEku))}");
                    }
                }
                else if (result.SignerCertificate is not null)
                {
                    var issuerCn = GetCn(result.SignerCertificate.IssuerName.Name);
                    certNode.AddNode($"Issuer:         [dim]{issuerCn.EscapeMarkup()}[/]");
                    certNode.AddNode($"Valid:          [dim]{result.SignerCertificate.NotBefore:yyyy-MM-dd} \u2013 {result.SignerCertificate.NotAfter:yyyy-MM-dd}[/]");
                }
            }

            // ESS CertV2
            if (sig is not null)
            {
                sigNode.AddNode(sig.HasSigningCertificateV2
                    ? "ESS CertV2:   [green]✓[/]"
                    : "ESS CertV2:   [red]✗[/]");
            }

            // Validation status
            ValidationReportRenderer.AddNodes(sigNode, result.Indication, result.SubIndication, result.Constraints, result.SignerCertificate, spanish);
            var valNode = sigNode.AddNode("[blue]Validation[/]");
            valNode.AddNode($"Integrity:  {Check(result.IsIntegrityValid)}");
            valNode.AddNode($"Signature:  {Check(result.IsSignatureValid)}");
            valNode.AddNode($"Chain:      {Check(result.IsCertificateChainValid)}");
            valNode.AddNode($"Revoked:    {FormatRevocationStatus(result)}");

            if (result.HasValidTimestamp.HasValue)
            {
                var tsTime = result.SigningTime.HasValue
                    ? $" {result.SigningTime.Value:yyyy-MM-dd HH:mm:ss} UTC"
                    : string.Empty;
                valNode.AddNode($"Timestamp:  {Check(result.HasValidTimestamp.Value)}{tsTime}");
            }

            // AEA info
            if (aeaInfo.TryGetValue(result.FieldName, out var aea))
            {
                string commitmentName = aea.CommitmentOid switch
                {
                    "1.2.840.113549.1.9.16.6.1" => "Proof of Origin",
                    "1.2.840.113549.1.9.16.6.5" => "Proof of Approval",
                    _ => aea.CommitmentOid
                };
                var aeaNode = sigNode.AddNode($"AEA:          [blue]Lei 14.063 ({commitmentName})[/]");

                if (aea.ManifestJson is { Length: > 0 })
                {
                    var manifest = SignatureManifest.FromJsonUtf8(aea.ManifestJson);
                    if (manifest is not null)
                    {
                        aeaNode.AddNode($"CPF:            {manifest.Signer.Cpf.EscapeMarkup()}");
                        if (manifest.Signer.Email is not null)
                        {
                            aeaNode.AddNode($"Email:          {manifest.Signer.Email.EscapeMarkup()}");
                        }
                        if (manifest.Evidence.Ip is not null)
                        {
                            aeaNode.AddNode($"IP:             {manifest.Evidence.Ip.EscapeMarkup()}");
                        }
                        aeaNode.AddNode($"Authentication: {manifest.Evidence.AuthMethod.EscapeMarkup()}");
                        if (manifest.Institution?.Name is not null)
                        {
                            aeaNode.AddNode($"Institution:    {manifest.Institution.Name.EscapeMarkup()}");
                        }
                    }
                }
            }

            AddBrasilNode(sigNode, result, sig?.ManifestJson);

            sigNode.AddNode($"Algorithm:    {(result.DigestAlgorithmName ?? result.DigestAlgorithmOid ?? "\u2014").EscapeMarkup()}");

            // Byte range, CMS data, embedded certs from inspection
            if (sig is not null)
            {
                var br = sig.ByteRange;
                sigNode.AddNode($"Byte Range:   [[{br.Offset1}, {br.Length1}, {br.Offset2}, {br.Length2}]]  {(br.IsValid ? "[green]✓[/]" : "[red]✗ inconsistent[/]")}");
                sigNode.AddNode($"CMS Data:     {Formatting.FormatBytes(sig.CmsRawData.Length)}");
                sigNode.AddNode($"Embedded Certs: {sig.EmbeddedCertificates.Count}");

                // Timestamp details from inspection
                if (sig.Timestamp is { } ts)
                {
                    var tsNode = sigNode.AddNode("[blue]Timestamp[/]");
                    tsNode.AddNode($"Time:       [bold]{ts.GenerationTime:yyyy-MM-dd HH:mm:ss} UTC[/]");
                    if (ts.TsaCertificate is not null)
                    {
                        tsNode.AddNode($"TSA:        {ts.TsaCertificate.Subject.EscapeMarkup()}");
                        tsNode.AddNode($"TSA Valid:  {ts.TsaCertificate.NotBefore:yyyy-MM-dd} \u2192 {ts.TsaCertificate.NotAfter:yyyy-MM-dd}");
                    }
                    tsNode.AddNode($"Token Size: {Formatting.FormatBytes(ts.RawToken.Length)}");
                }
            }

            if (result.SigningTime.HasValue)
            {
                sigNode.AddNode($"Signed at:    {result.SigningTime.Value:yyyy-MM-dd HH:mm:ss} UTC");
            }

            foreach (var error in result.Errors)
            {
                sigNode.AddNode($"[yellow]\u26a0 {error.EscapeMarkup()}[/]");
            }
        }

        // Render document timestamps (archival infrastructure) separately, after user signatures
        foreach (var result in docTimestamps)
        {
            var tsStatus = FormatIndication(result.Indication);

            var tsNode = tree.AddNode($"{result.FieldName}  [dim]Archive Timestamp[/]  {tsStatus}");

            tsNode.AddNode($"TSA:          [bold]{(result.SignerName ?? "(unknown)").EscapeMarkup()}[/]");

            // SubFilter
            if (result.SubFilter is not null)
            {
                tsNode.AddNode($"SubFilter:    {result.SubFilter.EscapeMarkup()}");
            }

            if (result.SignerCertificate is { } tsaCert)
            {
                var tsaIssuerCn = GetCn(tsaCert.IssuerName.Name);
                if (!string.IsNullOrEmpty(tsaIssuerCn))
                {
                    tsNode.AddNode($"Issued by:    [dim]{tsaIssuerCn.EscapeMarkup()}[/]");
                }
                tsNode.AddNode($"TSA Cert:     [dim]{tsaCert.NotBefore:yyyy-MM-dd} \u2013 {tsaCert.NotAfter:yyyy-MM-dd}[/]");
            }

            tsNode.AddNode($"Algorithm:    {(result.DigestAlgorithmName ?? result.DigestAlgorithmOid ?? "\u2014").EscapeMarkup()}");
            tsNode.AddNode($"Integrity:    {Check(result.IsIntegrityValid)}");
            tsNode.AddNode($"Signature:    {Check(result.IsSignatureValid)}");

            if (result.IsChainTrustWarning)
            {
                tsNode.AddNode($"Chain:        [yellow]?[/] [dim]TSA not in local trust store (integrity OK)[/]");
            }
            else
            {
                tsNode.AddNode($"Chain:        {Check(result.IsCertificateChainValid)}");
            }

            tsNode.AddNode($"Revoked:      {FormatRevocationStatus(result)}");

            if (result.SigningTime.HasValue)
            {
                tsNode.AddNode($"Stamped:      {result.SigningTime.Value:yyyy-MM-dd HH:mm:ss} UTC");
            }

            // Inspection-sourced details for document timestamps
            if (inspectionLookup.TryGetValue(result.FieldName, out var tsSig))
            {
                var br = tsSig.ByteRange;
                var coverageText = br.IsValid
                    ? $"[[0 \u2192 {br.Offset2 + br.Length2:N0} bytes]]  [green]✓[/]"
                    : "[red]✗ inconsistent[/]";
                tsNode.AddNode($"Covers:       {coverageText}");
                tsNode.AddNode($"Token Size:   {Formatting.FormatBytes(tsSig.CmsRawData.Length)}");
                tsNode.AddNode($"Embedded Certs: {tsSig.EmbeddedCertificates.Count}");

                if (tsSig.Signer is { } tsaInfo)
                {
                    var tsaCertNode = tsNode.AddNode("[blue]TSA Certificate[/]");
                    tsaCertNode.AddNode($"Serial:     {tsaInfo.SerialNumber}");
                    tsaCertNode.AddNode($"Thumbprint: {Formatting.FormatThumbprint(tsaInfo.Thumbprint)}");
                    tsaCertNode.AddNode($"Key:        {tsaInfo.KeyAlgorithm} {(tsaInfo.KeySizeBits.HasValue ? $"{tsaInfo.KeySizeBits}-bit" : "[dim](unknown)[/]")}");
                    tsaCertNode.AddNode($"Valid:      {tsaInfo.NotBefore:yyyy-MM-dd} \u2192 {tsaInfo.NotAfter:yyyy-MM-dd}");
                }
            }

            foreach (var error in result.Errors)
            {
                tsNode.AddNode($"[yellow]\u26a0 {error.EscapeMarkup()}[/]");
            }
        }

        AnsiConsole.WriteLine();
        AnsiConsole.Write(tree);
        AnsiConsole.WriteLine();
    }

    private static string Check(bool value, bool invert = false)
    {
        var display = invert ? !value : value;
        return display ? "[green]✓[/]" : "[red]✗[/]";
    }

    private static string FormatIndication(SignatureIndication indication) => indication switch
    {
        SignatureIndication.Valid => "[green]✓ VALID[/]",
        SignatureIndication.Indeterminate => "[yellow]? INDETERMINATE[/]",
        _ => "[red]✗ INVALID[/]"
    };

    private static string GetCn(string distinguishedName)
    {
        var prefix = "CN=";
        var start = distinguishedName.IndexOf(prefix, StringComparison.OrdinalIgnoreCase);
        if (start < 0)
        {
            return distinguishedName;
        }

        start += prefix.Length;
        var end = distinguishedName.IndexOf(',', start);
        return end < 0 ? distinguishedName[start..] : distinguishedName[start..end];
    }

    private static string FormatDocMdp(PdfDocumentInfo doc) => doc.DocMdpPermissionLevel switch
    {
        1 => "[red]✗[/] Locked — [bold]no changes[/] allowed",
        2 => "[yellow]![/] Locked — [bold]form filling[/] only",
        3 => "[green]✓[/] Certified — [bold]form filling and annotations[/] allowed",
        _ => "Not locked"
    };

    internal static string FormatRevocationStatus(SignatureValidationResult result) => result.RevocationSource switch
    {
        RevocationSource.None => "[dim]not checked[/]",
        RevocationSource.Indeterminate => "[yellow]? (indeterminate)[/]",
        _ => $"{Check(!result.IsNotRevoked, invert: true)}{FormatRevocationSource(result.RevocationSource)}"
    };

    private static string FormatRevocationSource(RevocationSource source) => source switch
    {
        RevocationSource.EmbeddedCrl => " [dim](embedded DSS CRL — offline)[/]",
        RevocationSource.EmbeddedOcsp => " [dim](embedded DSS OCSP — offline)[/]",
        RevocationSource.OnlineCrl => " [dim](online CRL)[/]",
        RevocationSource.OnlineOcsp => " [dim](online OCSP)[/]",
        RevocationSource.CertificateChain => " [dim](certificate chain — CRL/OCSP)[/]",
        RevocationSource.Indeterminate => " [yellow](indeterminate)[/]",
        _ => string.Empty
    };
}

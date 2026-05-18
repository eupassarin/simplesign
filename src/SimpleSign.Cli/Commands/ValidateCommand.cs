using System.ComponentModel;
using System.Text.Json;
using SimpleSign.Brasil;
using SimpleSign.Brasil.Signing;
using SimpleSign.Cli.Json;
using SimpleSign.Core.Validation;
using SimpleSign.PAdES.Inspection;
using SimpleSign.PAdES.Validation;
using SimpleSign.Pdf.Enums;
using Spectre.Console;
using Spectre.Console.Cli;

namespace SimpleSign.Cli.Commands;

[Description("Validate PDF signatures")]
internal sealed class ValidateCommand : AsyncCommand<ValidateCommand.Settings>
{
    internal sealed class Settings : CommonSettings
    {
        [CommandArgument(0, "<input>")]
        [Description("Input PDF file to validate")]
        public string InputPath { get; init; } = null!;

        [CommandOption("--no-revocation")]
        [Description("Skip CRL/OCSP revocation checks")]
        public bool NoRevocation { get; init; }

        [CommandOption("--json")]
        [Description("Output as JSON (machine-readable)")]
        public bool Json { get; init; }

        public override ValidationResult Validate()
        {
            if (!File.Exists(InputPath))
            {
                return ValidationResult.Error($"File not found: {InputPath}");
            }

            return ValidationResult.Success();
        }
    }

    protected override async Task<int> ExecuteAsync(CommandContext context, Settings settings, CancellationToken cancellationToken)
    {
        using var loggerFactory = settings.CreateLoggerFactory();
        var options = new ValidationOptions { CheckRevocation = !settings.NoRevocation };
        var logger = settings.CreateLogger<PdfSignatureValidator>();
        var brasil = new BrasilExtension();
        var validator = new PdfSignatureValidator(options, httpClient: null, logger: logger,
            trustAnchorProviders: brasil.TrustAnchorProviders);

        await using var stream = File.OpenRead(settings.InputPath);
        var results = await validator.ValidateAsync(stream, cancellationToken: cancellationToken);

        // Run inspection to get PAdES conformance levels and AEA info
        stream.Position = 0;
        var inspection = await PdfSignatureInspector.InspectAsync(stream, cancellationToken);
        var conformanceLevels = ConformanceDetector.DetectAll(inspection)
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
            OutputJson(settings.InputPath, results, conformanceLevels);
        }
        else
        {
            OutputText(settings.InputPath, results, conformanceLevels, aeaInfo, inspection, inspectionLookup);
        }

        bool hasInvalid = results.Any(r => !r.IsValid);
        return hasInvalid ? 1 : 0;
    }

    private static void OutputText(string inputPath, IReadOnlyList<SignatureValidationResult> results,
        Dictionary<string, PAdESConformanceLevel> conformanceLevels,
        Dictionary<string, (string CommitmentOid, string? PolicyOid, byte[]? ManifestJson)> aeaInfo,
        PdfInspectionResult inspection,
        Dictionary<string, SignatureFieldInfo> inspectionLookup)
    {
        var fileName = Path.GetFileName(inputPath);

        // Only count user signatures (not infrastructure document timestamps) in the valid/total header
        var userSigs = results.Where(r => !r.IsDocumentTimestamp).ToList();
        var docTimestamps = results.Where(r => r.IsDocumentTimestamp).ToList();

        var validCount = userSigs.Count(r => r.IsValid);
        var summaryColor = validCount == userSigs.Count ? "green" : "red";

        var tree = new Tree($"[bold]{fileName.EscapeMarkup()}[/]  [{summaryColor}]{validCount}/{userSigs.Count} valid[/]");
        tree.Style = Style.Parse("dim");

        // Document-level info
        var doc = inspection.Document;
        var docNode = tree.AddNode("[blue]Document[/]");
        docNode.AddNode($"Signatures: [bold]{userSigs.Count}[/] user + [bold]{docTimestamps.Count}[/] timestamps");
        docNode.AddNode($"Encrypted:  {(doc.IsEncrypted ? "[green]✓[/] Yes" : "No")}");
        docNode.AddNode($"DocMDP:     {FormatDocMdp(doc)}");
        docNode.AddNode($"PDF/A:      {FormatPdfA(doc.PdfALevel).EscapeMarkup()}");
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

            var status = result.IsValid
                ? "[green]✓ VALID[/]"
                : "[red]✗ INVALID[/]";

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
                sigNode.AddNode($"PAdES:        [bold]{FormatLevel(level).EscapeMarkup()}[/]");
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
                    certNode.AddNode($"Thumbprint:     {FormatThumbprint(signerInfo.Thumbprint)}");
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
                        certNode.AddNode($"Extended KU:    {string.Join(", ", signerInfo.ExtendedKeyUsages.Select(FormatEku))}");
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
            var valNode = sigNode.AddNode("[blue]Validation[/]");
            valNode.AddNode($"Integrity:  {Check(result.IsIntegrityValid)}");
            valNode.AddNode($"Signature:  {Check(result.IsSignatureValid)}");
            valNode.AddNode($"Chain:      {Check(result.IsCertificateChainValid)}");
            valNode.AddNode($"Revoked:    {Check(!result.IsNotRevoked, invert: true)}{FormatRevocationSource(result.RevocationSource)}");

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

            sigNode.AddNode($"Algorithm:    {(result.DigestAlgorithmName ?? result.DigestAlgorithmOid ?? "—").EscapeMarkup()}");

            // Byte range, CMS data, embedded certs from inspection
            if (sig is not null)
            {
                var br = sig.ByteRange;
                sigNode.AddNode($"Byte Range:   [[{br.Offset1}, {br.Length1}, {br.Offset2}, {br.Length2}]]  {(br.IsValid ? "[green]✓[/]" : "[red]✗ inconsistent[/]")}");
                sigNode.AddNode($"CMS Data:     {FormatBytes(sig.CmsRawData.Length)}");
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
                    tsNode.AddNode($"Token Size: {FormatBytes(ts.RawToken.Length)}");
                }
            }

            if (result.SigningTime.HasValue)
            {
                sigNode.AddNode($"Signed at:    {result.SigningTime.Value:yyyy-MM-dd HH:mm:ss} UTC");
            }

            foreach (var error in result.Errors)
            {
                sigNode.AddNode($"[yellow]⚠ {error.EscapeMarkup()}[/]");
            }
        }

        // Render document timestamps (archival infrastructure) separately, after user signatures
        foreach (var result in docTimestamps)
        {
            var tsStatus = result.IsChainTrustWarning
                ? "[yellow]? CHAIN UNVERIFIED[/]"
                : result.IsValid
                    ? "[green]✓ VALID[/]"
                    : "[red]✗ INVALID[/]";

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

            tsNode.AddNode($"Algorithm:    {(result.DigestAlgorithmName ?? result.DigestAlgorithmOid ?? "—").EscapeMarkup()}");
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

            tsNode.AddNode($"Revoked:      {Check(!result.IsNotRevoked, invert: true)}{FormatRevocationSource(result.RevocationSource)}");

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
                tsNode.AddNode($"Token Size:   {FormatBytes(tsSig.CmsRawData.Length)}");
                tsNode.AddNode($"Embedded Certs: {tsSig.EmbeddedCertificates.Count}");

                if (tsSig.Signer is { } tsaInfo)
                {
                    var tsaCertNode = tsNode.AddNode("[blue]TSA Certificate[/]");
                    tsaCertNode.AddNode($"Serial:     {tsaInfo.SerialNumber}");
                    tsaCertNode.AddNode($"Thumbprint: {FormatThumbprint(tsaInfo.Thumbprint)}");
                    tsaCertNode.AddNode($"Key:        {tsaInfo.KeyAlgorithm} {(tsaInfo.KeySizeBits.HasValue ? $"{tsaInfo.KeySizeBits}-bit" : "[dim](unknown)[/]")}");
                    tsaCertNode.AddNode($"Valid:      {tsaInfo.NotBefore:yyyy-MM-dd} \u2192 {tsaInfo.NotAfter:yyyy-MM-dd}");
                }
            }

            foreach (var error in result.Errors)
            {
                tsNode.AddNode($"[yellow]⚠ {error.EscapeMarkup()}[/]");
            }
        }

        AnsiConsole.WriteLine();
        AnsiConsole.Write(tree);
        AnsiConsole.WriteLine();
    }

    private static void OutputJson(string inputPath, IReadOnlyList<SignatureValidationResult> results,
        Dictionary<string, PAdESConformanceLevel> conformanceLevels)
    {
        var output = JsonMapper.MapValidation(Path.GetFileName(inputPath), results, conformanceLevels);
        Console.WriteLine(JsonSerializer.Serialize(output, CliJsonContext.Default.ValidateOutput));
    }

    private static string Check(bool value, bool invert = false)
    {
        var display = invert ? !value : value;
        return display ? "[green]✓[/]" : "[red]✗[/]";
    }

    /// <summary>Extracts the CN value from an X.500 distinguished name string.</summary>
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

    private static string FormatRevocationSource(RevocationSource source) => source switch
    {
        RevocationSource.EmbeddedCrl => " [dim](embedded DSS CRL — offline)[/]",
        RevocationSource.EmbeddedOcsp => " [dim](embedded DSS OCSP — offline)[/]",
        RevocationSource.OnlineCrl => " [dim](online CRL)[/]",
        RevocationSource.OnlineOcsp => " [dim](online OCSP)[/]",
        RevocationSource.Indeterminate => " [yellow](indeterminate)[/]",
        _ => string.Empty
    };

    private static string FormatLevel(PAdESConformanceLevel level) => level switch
    {
        PAdESConformanceLevel.Unknown => "Unknown",
        PAdESConformanceLevel.CmsOnly => "CMS (no PAdES attributes)",
        PAdESConformanceLevel.BaselineB => "PAdES B-B",
        PAdESConformanceLevel.BaselineT => "PAdES B-T",
        PAdESConformanceLevel.BaselineLT => "PAdES B-LT",
        PAdESConformanceLevel.BaselineLTA => "PAdES B-LTA",
        _ => level.ToString()
    };

    private static string FormatPdfA(PdfALevel level) => level switch
    {
        PdfALevel.None => "Not detected",
        PdfALevel.A1a => "PDF/A-1a",
        PdfALevel.A1b => "PDF/A-1b",
        PdfALevel.A2a => "PDF/A-2a",
        PdfALevel.A2b => "PDF/A-2b",
        PdfALevel.A2u => "PDF/A-2u",
        PdfALevel.A3a => "PDF/A-3a",
        PdfALevel.A3b => "PDF/A-3b",
        PdfALevel.A3u => "PDF/A-3u",
        PdfALevel.Unknown => "PDF/A (level unknown)",
        _ => level.ToString()
    };

    private static string FormatBytes(int bytes) => bytes switch
    {
        0 => "0 bytes",
        < 1024 => $"{bytes:N0} bytes",
        < 1048576 => $"{bytes / 1024.0:N1} KB ({bytes:N0} bytes)",
        _ => $"{bytes / 1048576.0:N1} MB ({bytes:N0} bytes)"
    };

    private static string FormatThumbprint(string hex)
    {
        if (string.IsNullOrEmpty(hex) || hex.Length < 4)
        {
            return hex;
        }

        var chars = new char[hex.Length + (hex.Length / 2) - 1];
        var pos = 0;
        for (var i = 0; i < hex.Length; i++)
        {
            if (i > 0 && i % 2 == 0)
            {
                chars[pos++] = ':';
            }

            chars[pos++] = char.ToUpperInvariant(hex[i]);
        }

        return new string(chars, 0, pos);
    }

    private static string FormatEku(string oid) => oid switch
    {
        "1.3.6.1.5.5.7.3.1" => "serverAuth",
        "1.3.6.1.5.5.7.3.2" => "clientAuth",
        "1.3.6.1.5.5.7.3.3" => "codeSigning",
        "1.3.6.1.5.5.7.3.4" => "emailProtection",
        "1.3.6.1.5.5.7.3.8" => "timeStamping",
        "1.3.6.1.5.5.7.3.9" => "OCSPSigning",
        "1.3.6.1.4.1.311.10.3.12" => "documentSigning",
        _ => oid
    };
}

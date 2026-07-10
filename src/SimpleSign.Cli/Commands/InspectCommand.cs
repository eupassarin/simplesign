using System.ComponentModel;
using System.Text.Json;
using SimpleSign.Brasil.Signing;
using SimpleSign.Cli.Json;
using SimpleSign.Cli.Rendering;
using SimpleSign.Core.Inspection;
using SimpleSign.PAdES.Inspection;
using Spectre.Console;
using Spectre.Console.Cli;

namespace SimpleSign.Cli.Commands;

/// <summary>Inspect signature metadata (no validation).</summary>
[Description("Inspect signature metadata (no validation)")]
internal sealed class InspectCommand : AsyncCommand<InspectCommand.Settings>
{
    private readonly IConformanceDetector _conformanceDetector;

    public InspectCommand(IConformanceDetector conformanceDetector)
    {
        _conformanceDetector = conformanceDetector;
    }

    /// <summary>Inspect command settings.</summary>
    internal sealed class Settings : CommonSettings
    {
        /// <summary>Input PDF file to inspect.</summary>
        [CommandArgument(0, "<input>")]
        [Description("Input PDF file to inspect")]
        public string InputPath { get; init; } = null!;

        /// <summary>Output as JSON (machine-readable).</summary>
        [CommandOption("--json")]
        [Description("Output as JSON (machine-readable)")]
        public bool Json { get; init; }

        /// <summary>Show raw PDF object structure of signatures.</summary>
        [CommandOption("--structure|-s")]
        [Description("Show raw PDF object structure of signatures")]
        public bool Structure { get; init; }

        /// <summary>Add inline explanations to the structure dump (use with --structure).</summary>
        [CommandOption("--explain")]
        [Description("Add inline explanations to the structure dump (use with --structure)")]
        public bool Explain { get; init; }

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
        await using var stream = File.OpenRead(settings.InputPath);
        var result = await PdfSignatureInspector.InspectAsync(stream, cancellationToken: cancellationToken);
        var fileName = Path.GetFileName(settings.InputPath);

        if (settings.Json)
        {
            var output = JsonMapper.MapInspection(fileName, result);
            Console.WriteLine(JsonSerializer.Serialize(output, CliJsonContext.Default.InspectOutput));
        }
        else
        {
            OutputTree(result, fileName);

            if (settings.Structure)
            {
                // Read PDF bytes and dump structure
                stream.Seek(0, SeekOrigin.Begin);
                var pdfBytes = new byte[stream.Length];
                await stream.ReadExactlyAsync(pdfBytes, cancellationToken);

                var objects = PdfStructureDumper.ExtractSignatureObjects(pdfBytes, settings.Explain);
                StructureRenderer.Render(objects, settings.Explain);
            }
        }

        return 0;
    }

    private void OutputTree(PdfInspectionResult result, string fileName)
    {
        var doc = result.Document;
        var userSigs = result.Signatures.Where(s => !s.IsDocumentTimestamp).ToList();
        var archiveTss = result.Signatures.Where(s => s.IsDocumentTimestamp).ToList();

        // Root tree
        var tree = new Tree($"[bold]{fileName.EscapeMarkup()}[/]");
        tree.Style = Style.Parse("dim");

        // Document properties
        var docNode = tree.AddNode("[blue]Document[/]");
        docNode.AddNode($"PDF Version:      [bold]{Formatting.FormatVersion(doc.PdfVersion)}[/]");
        docNode.AddNode($"Signatures:       [bold]{userSigs.Count}[/]");
        if (archiveTss.Count > 0)
        {
            docNode.AddNode($"Archive Stamps:   [bold magenta]{archiveTss.Count}[/]");
        }
        docNode.AddNode($"Encrypted:        {(doc.IsEncrypted ? "[green]✓[/] Yes" : "No")}");
        docNode.AddNode($"DocMDP:           {FormatDocMdp(doc)}");
        docNode.AddNode($"PDF/A:            {Formatting.FormatPdfAFull(doc.PdfALevel).EscapeMarkup()}");

        // DSS
        if (doc.SecurityStore is { IsPresent: true } dss)
        {
            var dssNode = docNode.AddNode("[green]✓[/] DSS (Document Security Store)");
            dssNode.AddNode($"Certificates: {dss.CertificateCount}");
            dssNode.AddNode($"CRLs:         {dss.CrlCount}");
            dssNode.AddNode($"OCSPs:        {dss.OcspResponseCount}");
            dssNode.AddNode($"VRI:          {(dss.HasVri ? "[green]✓[/]" : "[red]✗[/]")}");
            if (dss.HasVri && dss.VriEntryCount > 0)
            {
                dssNode.AddNode($"VRI entries:  {dss.VriEntryCount}");
                dssNode.AddNode($"VRI /TU:      {(dss.VriHasTimestamps ? "[green]✓[/] all entries" : "[yellow]⚠[/] missing")}");
            }
            foreach (var warning in dss.VriWarnings)
            {
                dssNode.AddNode($"[yellow]⚠ {warning.EscapeMarkup()}[/]");
            }
        }
        else
        {
            docNode.AddNode("[red]✗[/] DSS [dim]— not embedded (required for PAdES B-LT/B-LTA)[/]");
        }

        // Per-signature (user signatures and archive timestamps shown separately)
        var sigIdx = 0;
        var tsIdx = 0;

        foreach (var sig in result.Signatures)
        {
            if (sig.IsDocumentTimestamp)
            {
                tsIdx++;
                var tsNode = tree.AddNode($"[bold magenta]Archive Timestamp {tsIdx}/{archiveTss.Count}:[/] {sig.FieldName}");
                BuildDocumentTimestampNode(tsNode, sig);
            }
            else
            {
                sigIdx++;
                var level = _conformanceDetector.Detect(sig, doc, result.Signatures);
                var sigNode = tree.AddNode($"[bold blue]Signature {sigIdx}/{userSigs.Count}:[/] {sig.FieldName}");
                BuildSignatureNode(sigNode, sig, level);
            }
        }

        AnsiConsole.WriteLine();
        AnsiConsole.Write(tree);
        AnsiConsole.WriteLine();
    }

    private static void BuildSignatureNode(TreeNode sigNode, SignatureFieldInfo sig, PAdESConformanceLevel level)
    {
        // Properties
        var propsNode = sigNode.AddNode("[blue]Properties[/]");
        propsNode.AddNode($"SubFilter:  {sig.SubFilter?.EscapeMarkup() ?? "[dim]— not present[/]"}");
        propsNode.AddNode($"Level:      [bold]{Formatting.FormatLevel(level).EscapeMarkup()}[/]");
        propsNode.AddNode(sig.IsDigestAlgorithmDeprecated
            ? $"[yellow]\u26a0[/] Digest:     {FormatAlgo(sig.DigestAlgorithm)} [yellow](DEPRECATED per ISO 32000-2)[/]"
            : $"Digest:     {FormatAlgo(sig.DigestAlgorithm)}");
        propsNode.AddNode(sig.IsSignatureAlgorithmDeprecated
            ? $"[yellow]\u26a0[/] Algorithm:  {FormatAlgo(sig.SignatureAlgorithm)} [yellow](DEPRECATED per ISO 32000-2)[/]"
            : $"Algorithm:  {FormatAlgo(sig.SignatureAlgorithm)}");

        if (sig.SigningTime.HasValue)
        {
            propsNode.AddNode($"Signed:     {sig.SigningTime.Value:yyyy-MM-dd HH:mm:ss} UTC [dim](CMS signed attribute)[/]");
        }
        else
        {
            propsNode.AddNode("Signed:     [dim]— not present[/]");
        }

        if (sig.PdfDeclaredSigningTime.HasValue)
        {
            propsNode.AddNode($"PDF Time:   {sig.PdfDeclaredSigningTime.Value:yyyy-MM-dd HH:mm:ss} UTC [dim](not cryptographically bound)[/]");
        }

        // Metadata
        if (sig.Reason is not null)
        {
            propsNode.AddNode($"Reason:     {sig.Reason.EscapeMarkup()}");
        }

        if (sig.Location is not null)
        {
            propsNode.AddNode($"Location:   {sig.Location.EscapeMarkup()}");
        }

        if (sig.ContactInfo is not null)
        {
            propsNode.AddNode($"Contact:    {sig.ContactInfo.EscapeMarkup()}");
        }

        if (sig.DeclaredSignerName is not null)
        {
            propsNode.AddNode($"Name:       {sig.DeclaredSignerName.EscapeMarkup()} [dim](PDF /Name)[/]");
        }

        propsNode.AddNode(sig.HasSigningCertificateV2
            ? "ESS CertV2: [green]✓[/] Present [dim]— required by PAdES[/]"
            : "ESS CertV2: [red]✗[/] Not present");

        // AEA attributes (Lei 14.063)
        if (sig.CommitmentTypeOid is not null)
        {
            string commitmentName = sig.CommitmentTypeOid switch
            {
                "1.2.840.113549.1.9.16.6.1" => "Proof of Origin",
                "1.2.840.113549.1.9.16.6.5" => "Proof of Approval",
                _ => sig.CommitmentTypeOid
            };
            propsNode.AddNode($"Commitment: [blue]{commitmentName}[/] [dim]— AEA (Lei 14.063)[/]");
        }
        if (sig.SignaturePolicyOid is not null)
        {
            propsNode.AddNode($"Policy:     [blue]{sig.SignaturePolicyOid}[/]");
        }

        // Signature Manifest
        if (sig.ManifestJson is { Length: > 0 })
        {
            var manifest = SignatureManifest.FromJsonUtf8(sig.ManifestJson);
            if (manifest is not null)
            {
                var manifestNode = propsNode.AddNode("[blue]Signature Manifest[/] [dim]— Lei 14.063[/]");
                manifestNode.AddNode($"Name:           [bold]{manifest.Signer.Name.EscapeMarkup()}[/]");
                manifestNode.AddNode($"CPF:            {manifest.Signer.Cpf.EscapeMarkup()}");
                if (manifest.Signer.Email is not null)
                {
                    manifestNode.AddNode($"Email:          {manifest.Signer.Email.EscapeMarkup()}");
                }
                if (manifest.Evidence.Ip is not null)
                {
                    manifestNode.AddNode($"IP:             {manifest.Evidence.Ip.EscapeMarkup()}");
                }
                manifestNode.AddNode($"Authentication: {manifest.Evidence.AuthMethod.EscapeMarkup()}");
                manifestNode.AddNode($"Timestamp:      {manifest.Evidence.Timestamp:yyyy-MM-dd HH:mm:ss} UTC");
                if (manifest.Institution is not null)
                {
                    if (manifest.Institution.Name is not null)
                    {
                        manifestNode.AddNode($"Institution:    {manifest.Institution.Name.EscapeMarkup()}");
                    }
                    if (manifest.Institution.Cnpj is not null)
                    {
                        manifestNode.AddNode($"CNPJ:           {manifest.Institution.Cnpj.EscapeMarkup()}");
                    }
                }
                manifestNode.AddNode($"Commitment:     {TranslateCommitment(manifest.Commitment)}");
            }
        }

        propsNode.AddNode($"CMS Data:   {Formatting.FormatBytes(sig.CmsRawData.Length)}");

        // Byte range
        var br = sig.ByteRange;
        propsNode.AddNode($"Byte Range: [[{br.Offset1}, {br.Length1}, {br.Offset2}, {br.Length2}]]  {(br.IsValid ? "[green]✓[/]" : "[red]✗ inconsistent[/]")}");
        propsNode.AddNode($"Contents:   {Formatting.FormatBytes(br.ContentsLength)}");

        // Signer Certificate
        BuildSignerNode(sigNode, sig);

        // Timestamp
        BuildTimestampNode(sigNode, sig);

        // Embedded Certificates
        BuildEmbeddedCertsNode(sigNode, sig);
    }

    private static void BuildDocumentTimestampNode(TreeNode tsNode, SignatureFieldInfo sig)
    {
        tsNode.AddNode("Purpose:    [bold]Archive protection layer[/] [dim]— protects all preceding signatures (LTA)[/]");
        tsNode.AddNode($"SubFilter:  {sig.SubFilter?.EscapeMarkup() ?? "[dim]— not present[/]"}");
        tsNode.AddNode(sig.IsDigestAlgorithmDeprecated
            ? $"[yellow]⚠[/] Hash:       {FormatAlgo(sig.DigestAlgorithm)} [yellow](DEPRECATED per ISO 32000-2)[/]"
            : $"Hash:       {FormatAlgo(sig.DigestAlgorithm)}");

        if (sig.SigningTime.HasValue)
        {
            tsNode.AddNode($"Time:       [bold]{sig.SigningTime.Value:yyyy-MM-dd HH:mm:ss} UTC[/]");
        }

        var br = sig.ByteRange;
        var coverageText = br.IsValid
            ? $"[[0 \u2192 {br.Offset2 + br.Length2:N0} bytes]]  [green]✓[/]"
            : "[red]✗ inconsistent[/]";
        tsNode.AddNode($"Covers:     {coverageText}");
        tsNode.AddNode($"Token Size: {Formatting.FormatBytes(sig.CmsRawData.Length)}");

        // TSA certificate
        if (sig.Signer is not null)
        {
            var cert = sig.Signer;
            var tsaCertNode = tsNode.AddNode("[blue]TSA Certificate[/]");
            tsaCertNode.AddNode($"Subject:    [bold]{cert.Subject.EscapeMarkup()}[/]");
            tsaCertNode.AddNode($"Issuer:     {cert.Issuer.EscapeMarkup()}");
            tsaCertNode.AddNode($"Valid:      {cert.NotBefore:yyyy-MM-dd} → {cert.NotAfter:yyyy-MM-dd}");
            tsaCertNode.AddNode(cert.IsExpired
                ? $"Expired:    [red]✗ Yes — expired on {cert.NotAfter:yyyy-MM-dd}[/]"
                : "Expired:    [green]✓[/] No");
            if (cert.ExtendedKeyUsages.Count > 0)
            {
                tsaCertNode.AddNode($"Extended KU: {string.Join(", ", cert.ExtendedKeyUsages.Select(Formatting.FormatEku))}");
            }
        }
        else
        {
            tsNode.AddNode("[red]✗[/] TSA Certificate [dim]— not found in token[/]");
        }

        // Embedded certs (chain of the TSA)
        BuildEmbeddedCertsNode(tsNode, sig);
    }

    private static void BuildSignerNode(TreeNode parent, SignatureFieldInfo sig)
    {
        if (sig.Signer is null)
        {
            parent.AddNode("[red]✗[/] Signer Certificate [dim]— not found in CMS[/]");
            return;
        }

        var cert = sig.Signer;
        var certNode = parent.AddNode("[blue]Signer Certificate[/]");
        certNode.AddNode($"Subject:        [bold]{cert.Subject.EscapeMarkup()}[/]");
        certNode.AddNode($"Issuer:         {cert.Issuer.EscapeMarkup()}");
        certNode.AddNode($"Serial:         {cert.SerialNumber}");
        certNode.AddNode($"Thumbprint:     {Formatting.FormatThumbprint(cert.Thumbprint)}");
        certNode.AddNode($"Key:            {cert.KeyAlgorithm} {(cert.KeySizeBits.HasValue ? $"{cert.KeySizeBits}-bit" : "[dim](unknown)[/]")}");
        certNode.AddNode($"Valid:          {cert.NotBefore:yyyy-MM-dd HH:mm:ss} → {cert.NotAfter:yyyy-MM-dd HH:mm:ss}");
        certNode.AddNode(cert.IsExpired
            ? $"Expired:        [red]✗ Yes — expired on {cert.NotAfter:yyyy-MM-dd}[/]"
            : "Expired:        [green]✓[/] No");
        certNode.AddNode(cert.KeyUsages.Count > 0
            ? $"Key Usage:      {string.Join(", ", cert.KeyUsages)}"
            : "Key Usage:      [dim]— not present[/]");
        certNode.AddNode(cert.HasNonRepudiation
            ? "NonRepudiation: [green]✓[/] [dim]— suitable for legal signatures[/]"
            : "NonRepudiation: [red]✗[/] Not set");
        certNode.AddNode(cert.ExtendedKeyUsages.Count > 0
            ? $"Extended KU:    {string.Join(", ", cert.ExtendedKeyUsages.Select(Formatting.FormatEku))}"
            : "Extended KU:    [dim]— not present[/]");
        certNode.AddNode(cert.OcspUrl is not null
            ? $"OCSP:           {cert.OcspUrl.EscapeMarkup()}"
            : "OCSP:           [dim]— not present[/]");
        certNode.AddNode(cert.CrlUrl is not null
            ? $"CRL:            {cert.CrlUrl.EscapeMarkup()}"
            : "CRL:            [dim]— not present[/]");

        if (cert.AiaUrls.Count > 0)
        {
            var aiaText = string.Join("\n                ", cert.AiaUrls.Select(u => u.EscapeMarkup()));
            certNode.AddNode($"AIA:            {aiaText}");
        }
        else
        {
            certNode.AddNode("AIA:            [dim]— not present[/]");
        }
    }

    private static void BuildTimestampNode(TreeNode parent, SignatureFieldInfo sig)
    {
        if (sig.Timestamp is null)
        {
            parent.AddNode("[red]✗[/] Timestamp [dim]— not present (required for PAdES B-T and above)[/]");
            return;
        }

        var ts = sig.Timestamp;
        var tsNode = parent.AddNode("[green]✓[/] [blue]RFC 3161 Timestamp[/]");
        tsNode.AddNode($"Time:       [bold]{ts.GenerationTime:yyyy-MM-dd HH:mm:ss} UTC[/]");

        if (ts.TsaCertificate is not null)
        {
            tsNode.AddNode($"TSA:        {ts.TsaCertificate.Subject.EscapeMarkup()}");
            tsNode.AddNode($"TSA Issuer: {ts.TsaCertificate.Issuer.EscapeMarkup()}");
            tsNode.AddNode($"TSA Valid:  {ts.TsaCertificate.NotBefore:yyyy-MM-dd} → {ts.TsaCertificate.NotAfter:yyyy-MM-dd}");
        }
        else
        {
            tsNode.AddNode("TSA:        [dim]— certificate not found in token[/]");
        }

        tsNode.AddNode($"Hash:       {FormatAlgo(ts.HashAlgorithm)}");
        tsNode.AddNode(ts.PolicyOid is not null
            ? $"Policy:     {ts.PolicyOid}"
            : "Policy:     [dim]— not present[/]");
        tsNode.AddNode(ts.SerialNumber is not null
            ? $"Serial:     {ts.SerialNumber}"
            : "Serial:     [dim]— not present[/]");
        tsNode.AddNode($"Token Size: {Formatting.FormatBytes(ts.RawToken.Length)}");
    }

    private static void BuildEmbeddedCertsNode(TreeNode parent, SignatureFieldInfo sig)
    {
        var certsNode = parent.AddNode($"[blue]Embedded Certificates ({sig.EmbeddedCertificates.Count})[/]");

        if (sig.EmbeddedCertificates.Count == 0)
        {
            certsNode.AddNode("[red]✗[/] None [dim]— CMS should embed at least the signer certificate[/]");
            return;
        }

        foreach (var cert in sig.EmbeddedCertificates)
        {
            var role = DetermineRole(cert, sig);
            var expired = cert.IsExpired ? " [red]EXPIRED[/]" : "";
            var keyInfo = $"{cert.KeyAlgorithm}{(cert.KeySizeBits.HasValue ? $" {cert.KeySizeBits}-bit" : "")}";
            certsNode.AddNode($"{cert.Subject.EscapeMarkup()} [dim]· {role} · {keyInfo} · {cert.NotBefore:yyyy-MM-dd} → {cert.NotAfter:yyyy-MM-dd}[/]{expired}");
        }
    }

    #region Formatting Helpers

    private static string FormatAlgo(AlgorithmInfo? algo)
    {
        if (algo is null || string.IsNullOrEmpty(algo.Oid))
        {
            return "[dim]— not present[/]";
        }

        return $"{algo.Name} [dim]({algo.Oid})[/]";
    }

    private static string FormatDocMdp(PdfDocumentInfo doc) => doc.DocMdpPermissionLevel switch
    {
        1 => "[red]✗[/] Locked — [bold]no changes[/] allowed",
        2 => "[yellow]![/] Locked — [bold]form filling[/] only",
        3 => "[green]✓[/] Certified — [bold]form filling and annotations[/] allowed",
        _ => "Not locked"
    };

    private static string TranslateCommitment(string commitment) => commitment switch
    {
        "proofOfApproval" => "Approval",
        "proofOfOrigin" => "Authorship",
        _ => commitment
    };

    private static string DetermineRole(CertificateInfo cert, SignatureFieldInfo sig)
    {
        if (sig.Signer is not null && cert.Thumbprint == sig.Signer.Thumbprint)
        {
            return "Signer";
        }

        if (cert.Subject == cert.Issuer)
        {
            return "Root CA";
        }

        return cert.KeyUsages.Contains("KeyCertSign") ? "Intermediate CA" : "Certificate";
    }

    #endregion
}

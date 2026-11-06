using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using SimpleSign.Brasil;
using SimpleSign.Brasil.IcpBrasil;
using SimpleSign.Core.Inspection;
using SimpleSign.Core.Validation;
using SimpleSign.PAdES.Inspection;
using SimpleSign.PAdES.Validation;
using SimpleSign.TestBench.Documents;
using SimpleSign.TestBench.Localization;
using SimpleSign.TestBench.Sandbox;
using SimpleSign.TestBench.Signing;

namespace SimpleSign.TestBench.Validation;

/// <summary>Which roots the validator trusts.</summary>
public enum TrustChoice
{
    /// <summary>The sandbox root (AC Raiz Sandbox SimpleSign).</summary>
    Sandbox,

    /// <summary>The operating system's trusted roots.</summary>
    System,

    /// <summary>The ICP-Brasil roots bundled with SimpleSign.Brasil.</summary>
    IcpBrasil,

    /// <summary>The ICP-Brasil homologation (test) hierarchy.</summary>
    IcpHomologation,
}

/// <summary>How to validate.</summary>
public sealed record ValidationSettings
{
    public EnvironmentMode Environment { get; init; } = EnvironmentMode.Sandbox;

    public IReadOnlyList<TrustChoice> Trust { get; init; } = [TrustChoice.Sandbox];

    /// <summary>Uploaded root certificates (DER or PEM) to trust as well.</summary>
    public IReadOnlyList<string> CustomRootUploadIds { get; init; } = [];

    public bool CheckRevocation { get; init; } = true;

    public int TimeoutSeconds { get; init; } = 10;

    /// <summary>Apply the ICP-Brasil / Gov.br / Lei 14.063 rules (BrasilExtension).</summary>
    public bool UseBrasil { get; init; } = true;

    /// <summary>The defaults for a mode: the sandbox root, or the OS and ICP-Brasil roots.</summary>
    public static ValidationSettings For(EnvironmentMode mode) => mode == EnvironmentMode.Sandbox
        ? new ValidationSettings()
        : new ValidationSettings { Environment = mode, Trust = [TrustChoice.System, TrustChoice.IcpBrasil] };
}

public sealed record CertificateView(string Subject, string Issuer, string SerialNumber, string NotBefore, string NotAfter, string KeyAlgorithm, int? KeySize, bool HasNonRepudiation, string Thumbprint);

public sealed record TimestampView(string Time, string? Tsa, string? PolicyOid, string? HashAlgorithm, string? SerialNumber);

/// <summary>What part of the file a signature covers.</summary>
public sealed record CoverageView(long SignedUntil, long FileSize, bool CoversWholeFile, int Revision, int Revisions);

/// <summary>Everything known about one signature: the validator's verdict plus what the inspector read.</summary>
public sealed record DetailedSignature(
    SignatureReport Report,
    string? PadesLevel,
    string? Lei14063Level,
    CertificateView? Signer,
    IReadOnlyList<CertificateView> EmbeddedCertificates,
    TimestampView? Timestamp,
    CoverageView? Coverage,
    string? SignatureAlgorithm,
    bool DeprecatedAlgorithm,
    string? CommitmentTypeOid,
    string? PolicyOid,
    string? PolicyName,
    string? Reason,
    string? Location,
    string? ContactInfo);

/// <summary>Trust settings turned into library objects.</summary>
internal sealed record ValidationTrust(ValidationOptions Options, BrasilExtension Brasil, bool UsesIcp, IReadOnlyList<X509Certificate2> IcpAnchors);

public sealed record DssView(int Certificates, int Crls, int Ocsps, bool HasVri, int VriEntries, IReadOnlyList<string> Warnings);

public sealed record ValidationReport(
    string FileId,
    DocumentFacts Document,
    string Overall,
    IReadOnlyList<DetailedSignature> Signatures,
    DssView? Dss,
    long Ms,
    CodeSnippets Code,
    string? Error);

/// <summary>Validates PDFs with PdfSignatureValidator (+ BrasilExtension) and enriches the result with the inspector's facts.</summary>
internal sealed class ValidationService(SandboxEnvironment sandbox, DocumentStore documents)
{
    /// <summary>The per-signature verdicts (used by the signing result).</summary>
    public async Task<IReadOnlyList<SignatureReport>> ValidateAsync(byte[] pdf, ValidationSettings settings, CancellationToken cancellationToken)
    {
        var results = await RunValidatorAsync(pdf, settings, cancellationToken);
        return [.. results.Select(ToReport)];
    }

    /// <summary>The full report for the Validation page.</summary>
    public async Task<ValidationReport> ReportAsync(string fileId, ValidationSettings settings, CancellationToken cancellationToken)
    {
        var file = documents.Get(fileId);
        var facts = await documents.FactsAsync(fileId, cancellationToken);
        var code = ValidationCode(settings);
        var watch = Stopwatch.StartNew();
        IReadOnlyList<SignatureValidationResult> results;
        try
        {
            results = await RunValidatorAsync(file.Content, settings, cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return new ValidationReport(fileId, facts, "Error", [], null, watch.ElapsedMilliseconds, code, ex.Message);
        }

        long ms = watch.ElapsedMilliseconds;
        PdfInspectionResult? inspection = null;
        try
        {
            using var stream = new MemoryStream(file.Content, writable: false);
            inspection = await PdfSignatureInspector.InspectAsync(stream, cancellationToken: cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Reported through the validator's own errors; the inspector only enriches.
        }

        var levels = inspection is null ? [] : new ConformanceDetectorService().DetectAll(inspection);
        int revisions = CountRevisions(file.Content);
        var signatures = new List<DetailedSignature>();
        foreach (var result in results)
        {
            var info = inspection?.Signatures.FirstOrDefault(s => s.FieldName == result.FieldName);
            var level = levels.FirstOrDefault(l => l.Signature.FieldName == result.FieldName).Level;
            signatures.Add(Detail(result, info, info is null ? null : level.ToString(), file.Content.Length, revisions));
        }

        var dss = inspection?.Document.SecurityStore is { IsPresent: true } store
            ? new DssView(store.CertificateCount, store.CrlCount, store.OcspResponseCount, store.HasVri, store.VriEntryCount, store.VriWarnings)
            : null;
        string overall = results.Count == 0 ? "NoSignatures"
            : results.All(r => r.Indication == SignatureIndication.Valid) ? "Valid"
            : results.Any(r => r.Indication == SignatureIndication.Invalid) ? "Invalid"
            : "Indeterminate";
        return new ValidationReport(fileId, facts, overall, signatures, dss, ms, code, null);
    }

    internal async Task<IReadOnlyList<SignatureValidationResult>> RunValidatorAsync(byte[] pdf, ValidationSettings settings, CancellationToken cancellationToken)
    {
        var validator = CreateValidator(settings);
        using var stream = new MemoryStream(pdf, writable: false);
        return await validator.ValidateAsync(stream, cancellationToken: cancellationToken);
    }

    internal PdfSignatureValidator CreateValidator(ValidationSettings settings)
    {
        var trust = Trust(settings);
        return new PdfSignatureValidator(sandbox.HttpFor(settings.Environment), trust.Options, null,
            trust.UsesIcp ? trust.Brasil.TrustAnchorProviders : [],
            settings.UseBrasil ? trust.Brasil.ChainValidationProviders : []);
    }

    /// <summary>The trust settings as library objects, shared by the PAdES, CAdES and XAdES validators.</summary>
    internal ValidationTrust Trust(ValidationSettings settings)
    {
        var http = sandbox.HttpFor(settings.Environment);
        var roots = new List<X509Certificate2>();
        if (settings.Trust.Contains(TrustChoice.Sandbox))
        {
            roots.Add(sandbox.Pki.Root);
        }

        foreach (string id in settings.CustomRootUploadIds)
        {
            roots.Add(LoadCertificate(documents.Get(id).Content));
        }

        bool icp = settings.Trust.Contains(TrustChoice.IcpBrasil) || settings.Trust.Contains(TrustChoice.IcpHomologation);
        var brasil = new BrasilExtension(new BrasilExtensionOptions
        {
            HttpClient = http.GetClient(),
            IcpEnvironment = settings.Trust.Contains(TrustChoice.IcpHomologation) ? IcpBrasilEnvironment.Homologation : IcpBrasilEnvironment.Production,
        });
        var options = new ValidationOptions
        {
            TrustSystemRoots = settings.Trust.Contains(TrustChoice.System),
            TrustedRoots = roots.Count > 0 ? roots : null,
            CheckRevocation = settings.CheckRevocation,
            NetworkTimeout = TimeSpan.FromSeconds(Math.Clamp(settings.TimeoutSeconds, 1, 120)),
        };
        IReadOnlyList<X509Certificate2> icpAnchors = icp ? [.. brasil.TrustAnchorProviders.SelectMany(p => p.GetTrustAnchors())] : [];
        return new ValidationTrust(options, brasil, icp, icpAnchors);
    }

    internal static SignatureReport ToReport(SignatureValidationResult r)
    {
        static string Status(bool? ok) => ok switch { true => "pass", false => "fail", null => "n/a" };
        var checks = new List<CheckRow>
        {
            new("integrity", L.T("Integrity (ByteRange digest)"), Status(r.IsIntegrityValid), r.IsIntegrityValid
                ? L.T("The signed bytes were not changed after signing.")
                : L.T("The signed bytes were changed after signing: the digest no longer matches.")),
            new("signature", L.T("Signature value"), Status(r.IsSignatureValid), r.DigestAlgorithmName is { } digest ? L.T("Digest {0}.", digest) : null),
            new("chain", L.T("Certificate chain"), r.IsChainTrustWarning ? "warn" : Status(r.IsCertificateChainValid), r.ChainValidationRegion),
            new("revocation", L.T("Revocation"), Status(r.IsNotRevoked), r.RevocationSource.ToString()),
            new("timestamp", L.T("Signature timestamp"), Status(r.HasValidTimestamp), r.IsTsaTrusted is { } trusted ? (trusted ? L.T("TSA trusted.") : L.T("TSA not trusted.")) : null),
        };
        return new SignatureReport(
            r.FieldName, r.Indication.ToString(), r.IsDocumentTimestamp,
            r.SignerName ?? r.SignerCertificate?.GetNameInfo(X509NameType.SimpleName, false),
            r.SubFilter, r.DigestAlgorithmName,
            r.SigningTime?.ToString("yyyy-MM-dd HH:mm:ss zzz", System.Globalization.CultureInfo.InvariantCulture),
            r.PolicyLevel, r.SignerId, checks, r.Errors, r.Warnings, r.ChainValidationMetadata);
    }

    private static DetailedSignature Detail(SignatureValidationResult result, SignatureFieldInfo? info, string? level, long fileSize, int revisions)
    {
        CoverageView? coverage = null;
        if (info is not null)
        {
            long end = info.ByteRange.Offset2 + info.ByteRange.Length2;
            coverage = new CoverageView(end, fileSize, end >= fileSize - 2, RevisionOf(end, fileSize, revisions), revisions);
        }

        string? lei = Lei14063.Classify(result, info?.ManifestJson ?? default) is { } classified
            ? classified.ToString()
            : null;
        string? policyName = info?.SignaturePolicyOid is { } oid && IcpBrasilPolicyInfo.TryParse(oid, out var policy)
            ? $"{policy.Policy} {policy.Format} v{policy.Version}"
            : null;
        return new DetailedSignature(
            ToReport(result),
            level,
            lei,
            info?.Signer is { } signer ? View(signer) : null,
            info is null ? [] : [.. info.EmbeddedCertificates.Select(View)],
            info?.Timestamp is { } ts
                ? new TimestampView(ts.GenerationTime.ToString("yyyy-MM-dd HH:mm:ss zzz", System.Globalization.CultureInfo.InvariantCulture),
                    ts.TsaCertificate?.Subject, ts.PolicyOid, ts.HashAlgorithm.Name, ts.SerialNumber)
                : null,
            coverage,
            info?.SignatureAlgorithm.ToString(),
            info is { IsDigestAlgorithmDeprecated: true } or { IsSignatureAlgorithmDeprecated: true },
            info?.CommitmentTypeOid,
            info?.SignaturePolicyOid,
            policyName,
            info?.Reason,
            info?.Location,
            info?.ContactInfo);
    }

    private static CertificateView View(CertificateInfo c) => new(
        c.Subject, c.Issuer, c.SerialNumber,
        c.NotBefore.ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture),
        c.NotAfter.ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture),
        c.KeyAlgorithm, c.KeySizeBits, c.HasNonRepudiation, c.Thumbprint);

    /// <summary>Revisions = the %%EOF markers (each incremental update ends with one).</summary>
    internal static int CountRevisions(byte[] pdf)
    {
        int count = 0;
        var span = pdf.AsSpan();
        ReadOnlySpan<byte> marker = "%%EOF"u8;
        for (int i = span.IndexOf(marker); i >= 0; i = span.IndexOf(marker))
        {
            count++;
            span = span[(i + marker.Length)..];
        }

        return Math.Max(count, 1);
    }

    private static int RevisionOf(long signedUntil, long fileSize, int revisions) =>
        signedUntil >= fileSize - 2 ? revisions : Math.Max(1, revisions - 1);

    private static X509Certificate2 LoadCertificate(byte[] content)
    {
        string text = Encoding.ASCII.GetString(content);
        return text.Contains("-----BEGIN CERTIFICATE-----", StringComparison.Ordinal)
            ? X509Certificate2.CreateFromPem(text)
            : X509CertificateLoader.LoadCertificate(content);
    }

    private static CodeSnippets ValidationCode(ValidationSettings s)
    {
        var sb = new StringBuilder();
        sb.Append("using SimpleSign.PAdES.Validation;\nusing SimpleSign.Core.Validation;\n");
        if (s.UseBrasil)
        {
            sb.Append("using SimpleSign.Brasil;\n");
        }

        sb.Append('\n');
        bool icp = s.Trust.Contains(TrustChoice.IcpBrasil) || s.Trust.Contains(TrustChoice.IcpHomologation);
        var options = new List<string>();
        if (!s.Trust.Contains(TrustChoice.System))
        {
            options.Add("TrustSystemRoots = false");
        }

        if (s.Trust.Contains(TrustChoice.Sandbox) || s.CustomRootUploadIds.Count > 0)
        {
            options.Add("TrustedRoots = [root] // X509CertificateLoader.LoadCertificateFromFile(\"root.cer\")");
        }

        if (!s.CheckRevocation)
        {
            options.Add("CheckRevocation = false");
        }

        if (s.TimeoutSeconds != 10)
        {
            options.Add($"NetworkTimeout = TimeSpan.FromSeconds({s.TimeoutSeconds})");
        }

        string optionsCode = options.Count == 0 ? "ValidationOptions.Default" : "new ValidationOptions\n{\n    " + string.Join(",\n    ", options) + ",\n}";
        if (s.UseBrasil && icp && options.Count == 0)
        {
            sb.Append("// ICP-Brasil + Gov.br roots and rules (policy, Lei 14.063 level, CPF/CNPJ):\n");
            sb.Append("var validator = BrasilExtension.CreateValidator();\n");
        }
        else
        {
            sb.Append("var options = ").Append(optionsCode).Append(";\n");
            if (s.UseBrasil)
            {
                sb.Append(s.Trust.Contains(TrustChoice.IcpHomologation)
                    ? "var brasil = new BrasilExtension(new BrasilExtensionOptions { IcpEnvironment = IcpBrasilEnvironment.Homologation });\n"
                    : "var brasil = new BrasilExtension();\n");
                sb.Append(icp
                    ? "var validator = new PdfSignatureValidator(options, httpClient: null, logger: null, brasil.TrustAnchorProviders, brasil.ChainValidationProviders);\n"
                    : "var validator = new PdfSignatureValidator(options, httpClient: null, logger: null, trustAnchorProviders: [], brasil.ChainValidationProviders);\n");
            }
            else
            {
                sb.Append("var validator = new PdfSignatureValidator(options);\n");
            }
        }

        sb.Append("\nIReadOnlyList<SignatureValidationResult> results = await validator.ValidateAsync(File.OpenRead(\"signed.pdf\"));\n");
        sb.Append("foreach (var r in results)\n{\n    Console.WriteLine($\"{r.FieldName}: {r.Indication} — {r.SignerName}\");\n");
        sb.Append("    foreach (var error in r.Errors) Console.WriteLine($\"  ✕ {error}\");\n}\n");
        if (s.UseBrasil)
        {
            sb.Append("\n// Lei 14.063 level of each valid signature:\n// Lei14063.Classify(result, signatureInfo.ManifestJson)\n");
        }

        string cli = "simplesign validate signed.pdf"
            + (s.Trust.Contains(TrustChoice.Sandbox) || s.CustomRootUploadIds.Count > 0 ? " --trust root.cer" : "")
            + (s.Trust.Contains(TrustChoice.IcpHomologation) ? " --icp-homologation" : "")
            + (s.CheckRevocation ? "" : " --no-revocation");
        var notes = new List<string>
        {
            L.T("The CLI always applies the ICP-Brasil rules and trusts the OS and ICP-Brasil roots; --trust adds roots."),
            L.T("simplesign inspect signed.pdf shows the structure; simplesign validate-dir validates a folder in bulk."),
        };
        return new CodeSnippets(sb.ToString(), cli, notes);
    }
}

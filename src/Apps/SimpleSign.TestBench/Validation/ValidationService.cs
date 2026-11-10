using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using SimpleSign.Core.Extensions;
using SimpleSign.Core.Inspection;
using SimpleSign.Core.Validation;
using SimpleSign.PAdES.Inspection;
using SimpleSign.PAdES.Validation;
using SimpleSign.TestBench.Documents;
using SimpleSign.TestBench.Localization;
using SimpleSign.TestBench.Runs;
using SimpleSign.TestBench.Sandbox;
using SimpleSign.TestBench.Signing;

namespace SimpleSign.TestBench.Validation;

/// <summary>Which roots the validator trusts.</summary>
public enum TrustChoice
{
    /// <summary>The root of the connected SimpleSign Sandbox, as a bare trust anchor.</summary>
    Sandbox,

    /// <summary>The operating system's trusted roots.</summary>
    System,

    /// <summary>
    /// The connected Sandbox's trusted list, read through its list of trusted lists (/tl/lotl.xml): its CAs with their
    /// service types and statuses, so the TrustedLists constraints are evaluated. A Sandbox without one: its root.
    /// </summary>
    SandboxTrustedList,
}

/// <summary>How to validate.</summary>
public sealed record ValidationSettings
{
    /// <summary>The roots to trust. Default: the connected Sandbox's trusted list and the operating system's roots.</summary>
    public IReadOnlyList<TrustChoice> Trust { get; init; } = [TrustChoice.SandboxTrustedList, TrustChoice.System];

    /// <summary>Uploaded root certificates (DER or PEM) to trust as well.</summary>
    public IReadOnlyList<string> CustomRootUploadIds { get; init; } = [];

    public int TimeoutSeconds { get; init; } = 10;

    /// <summary>The uploaded validation policy (JSON, root ValidationConstraints); null: <c>ValidationPolicy.Default</c>.</summary>
    public string? PolicyId { get; init; }

    /// <summary>How much of each signature is validated (default: everything).</summary>
    public ValidationLevel Level { get; init; } = ValidationLevel.ArchivalData;

    /// <summary>Which revocation source is asked first.</summary>
    public RevocationStrategy RevocationStrategy { get; init; } = RevocationStrategy.OcspFirst;
}

public sealed record CertificateView(string Subject, string Issuer, string SerialNumber, string NotBefore, string NotAfter, string KeyAlgorithm, int? KeySize, bool HasNonRepudiation, string Thumbprint);

public sealed record TimestampView(string Time, string? Tsa, string? PolicyOid, string? HashAlgorithm, string? SerialNumber);

/// <summary>What part of the file a signature covers.</summary>
public sealed record CoverageView(long SignedUntil, long FileSize, bool CoversWholeFile, int Revision, int Revisions);

/// <summary>Everything known about one signature: the validator's verdict plus what the inspector read.</summary>
public sealed record DetailedSignature(
    SignatureReport Report,
    string? PadesLevel,
    CertificateView? Signer,
    IReadOnlyList<CertificateView> EmbeddedCertificates,
    TimestampView? Timestamp,
    CoverageView? Coverage,
    string? SignatureAlgorithm,
    bool DeprecatedAlgorithm,
    string? CommitmentTypeOid,
    string? PolicyOid,
    string? Reason,
    string? Location,
    string? ContactInfo);

/// <summary>Trust settings turned into library objects.</summary>
internal sealed record ValidationTrust(ValidationOptions Options)
{
    /// <summary>The trust anchor providers (the Sandbox's trusted lists), for the PAdES validator.</summary>
    public IReadOnlyList<ITrustAnchorProvider> Providers { get; init; } = [];
}

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

/// <summary>Validates PDFs with PdfSignatureValidator and enriches the result with the inspector's facts.</summary>
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
            inspection = await PdfSignatureInspector.InspectAsync(stream, RunLog.Logger, cancellationToken);
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
        var validator = await CreateValidatorAsync(settings, cancellationToken);
        using var stream = new MemoryStream(pdf, writable: false);
        return await validator.ValidateAsync(stream, cancellationToken: cancellationToken);
    }

    internal async Task<PdfSignatureValidator> CreateValidatorAsync(ValidationSettings settings, CancellationToken cancellationToken = default)
    {
        var trust = await TrustAsync(settings, cancellationToken);
        return new PdfSignatureValidator(sandbox, trust.Options, new RunLogger<PdfSignatureValidator>(RunLog.Logger), trust.Providers, []);
    }

    /// <summary>The chain revocation checker of the CAdES and XAdES validators, on the TestBench's network.</summary>
    internal Core.Revocation.IChainRevocationChecker RevocationChecker() =>
        new Core.Revocation.ChainRevocationChecker(sandbox.GetClient(), RunLog.Logger, sandbox.OutboundPolicy);

    /// <summary>The ETSI name of a sub-indication, or null.</summary>
    internal static string? SubIndicationName(SignatureSubIndication? subIndication) => subIndication?.ToEtsiName();

    /// <summary>
    /// The checks of the validation policy (algorithms, key size, key usage) as report rows; the integrity,
    /// signature, chain and revocation checks have their own rows.
    /// </summary>
    internal static IEnumerable<CheckRow> PolicyRows(IReadOnlyList<ValidationConstraintResult> constraints) =>
        constraints
            .Where(c => c.Id.StartsWith("crypto.", StringComparison.Ordinal) || c.Id.StartsWith("signingCertificate.", StringComparison.Ordinal))
            .Select(c => new CheckRow("policy." + c.Id, L.T("Validation policy: {0}", c.Id), c.Status switch
            {
                ConstraintStatus.Passed => "pass",
                ConstraintStatus.Warning => "warn",
                ConstraintStatus.Failed => "fail",
                _ => "n/a",
            }, c.Message));

    /// <summary>The revocation row of a CAdES or XAdES result.</summary>
    internal static CheckRow RevocationRow(bool? notRevoked, RevocationSource source) =>
        new("revocation", L.T("Revocation"), notRevoked switch { true => "pass", false => "fail", null => "n/a" },
            notRevoked is null ? null : source.ToString());

    /// <summary>The trust settings as library objects, shared by the PAdES, CAdES and XAdES validators.</summary>
    internal async Task<ValidationTrust> TrustAsync(ValidationSettings settings, CancellationToken cancellationToken = default)
    {
        var roots = new List<X509Certificate2>();
        var providers = new List<ITrustAnchorProvider>();
        IReadOnlyList<Core.Extensions.TrustedListInfo>? trustedLists = null;
        if (sandbox.Current is { } connection)
        {
            bool viaList = settings.Trust.Contains(TrustChoice.SandboxTrustedList) && connection.LotlUri is not null && connection.LotlSigner is not null;
            if (viaList && await SandboxTrustedListsAsync(connection, cancellationToken) is { } set)
            {
                providers.Add(set);
                roots.AddRange(set.GetTrustAnchors());
                trustedLists = set.TrustedLists;
            }

            // The root as a bare anchor: asked for, or the trusted list asked of a Sandbox that has none.
            if (settings.Trust.Contains(TrustChoice.Sandbox)
                || (settings.Trust.Contains(TrustChoice.SandboxTrustedList) && connection.LotlUri is null))
            {
                roots.Add(connection.Root);
            }
        }

        foreach (string id in settings.CustomRootUploadIds)
        {
            roots.Add(LoadCertificate(documents.Get(id).Content));
        }

        var options = new ValidationOptions
        {
            TrustSystemRoots = settings.Trust.Contains(TrustChoice.System),
            TrustedRoots = roots.Count > 0 ? roots : null,
            TrustedLists = trustedLists,
            NetworkTimeout = TimeSpan.FromSeconds(Math.Clamp(settings.TimeoutSeconds, 1, 120)),
            Policy = PolicyUploads.Validation(settings.PolicyId, documents),
            Level = settings.Level,
            Verifier = VerifierOptions.Default with { RevocationStrategy = settings.RevocationStrategy },
        };
        return new ValidationTrust(options) { Providers = providers };
    }

    /// <summary>
    /// The Sandbox's trusted lists, read again for each validation so its trusted-list failures show at once. An expired
    /// list is kept: the TLNotExpired constraint of the policy judges it. A list that cannot be read gives no anchors.
    /// </summary>
    private async Task<XAdES.TrustedLists.TrustedListSet?> SandboxTrustedListsAsync(SandboxConnection connection, CancellationToken cancellationToken)
    {
        try
        {
            var set = await XAdES.TrustedLists.TrustedListSet.LoadAsync(new XAdES.TrustedLists.TrustedListSetOptions
            {
                LotlLocation = connection.LotlUri!,
                LotlSignerCertificates = [connection.LotlSigner!],
                Services = new XAdES.TrustedLists.TrustedListOptions { RejectExpired = false },
            }, sandbox, cancellationToken);
            foreach (var problem in set.Problems)
            {
                RunLog.Logger.LogWarning("The Sandbox's trusted list {Location} was not loaded: {Reason}", problem.Location, problem.Reason);
            }

            return set;
        }
        catch (Exception ex) when (ex is HttpRequestException or System.Security.Cryptography.CryptographicException or InvalidDataException or System.Xml.XmlException)
        {
            RunLog.Logger.LogWarning("The Sandbox's list of trusted lists could not be read: {Reason}", ex.Message);
            return null;
        }
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
        checks.AddRange(PolicyRows(r.Constraints));
        return new SignatureReport(
            r.FieldName, r.Indication.ToString(), r.IsDocumentTimestamp,
            r.SignerName ?? r.SignerCertificate?.GetNameInfo(X509NameType.SimpleName, false),
            r.SubFilter, r.DigestAlgorithmName,
            r.SigningTime?.ToString("yyyy-MM-dd HH:mm:ss zzz", System.Globalization.CultureInfo.InvariantCulture),
            checks, r.Errors, r.Warnings, r.ChainValidationMetadata, SubIndicationName(r.SubIndication));
    }

    private static DetailedSignature Detail(SignatureValidationResult result, SignatureFieldInfo? info, string? level, long fileSize, int revisions)
    {
        CoverageView? coverage = null;
        if (info is not null)
        {
            long end = info.ByteRange.Offset2 + info.ByteRange.Length2;
            coverage = new CoverageView(end, fileSize, end >= fileSize - 2, RevisionOf(end, fileSize, revisions), revisions);
        }

        return new DetailedSignature(
            ToReport(result),
            level,
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

    /// <summary>The <c>ValidationOptions</c> initializers for the policy, level and revocation strategy that differ from the defaults.</summary>
    internal static IEnumerable<string> PolicyOptionsCode(ValidationSettings s)
    {
        if (s.PolicyId is not null)
        {
            yield return $"Policy = ValidationPolicy.Load(\"{PolicyUploads.ValidationFileName}\")";
        }

        if (s.Level != ValidationLevel.ArchivalData)
        {
            yield return $"Level = ValidationLevel.{s.Level}";
        }

        if (s.RevocationStrategy != RevocationStrategy.OcspFirst)
        {
            yield return $"Verifier = new VerifierOptions {{ RevocationStrategy = RevocationStrategy.{s.RevocationStrategy} }}";
        }
    }

    /// <summary>The CLI options for the policy, level and revocation strategy that differ from the defaults.</summary>
    internal static IEnumerable<string> PolicyCliArgs(ValidationSettings s)
    {
        if (s.PolicyId is not null)
        {
            yield return "--policy " + PolicyUploads.ValidationFileName;
        }

        if (s.Level != ValidationLevel.ArchivalData)
        {
            yield return "--level " + s.Level switch
            {
                ValidationLevel.BasicSignatures => "basic",
                ValidationLevel.Timestamps => "timestamps",
                _ => "lt",
            };
        }

        if (s.RevocationStrategy != RevocationStrategy.OcspFirst)
        {
            yield return "--revocation-strategy crl-first";
        }
    }

    /// <summary>Whether the settings read the Sandbox's trusted list (the snippets then load it).</summary>
    internal static bool UsesSandboxTrustedList(ValidationSettings s) => s.Trust.Contains(TrustChoice.SandboxTrustedList);

    /// <summary>The ValidationOptions lines that trust the Sandbox through its trusted list, for the code snippets.</summary>
    internal static IEnumerable<string> TrustedListOptionsCode(ValidationSettings s) => UsesSandboxTrustedList(s)
        ?
        [
            "// var lists = await TrustedListSet.LoadAsync(new() { LotlLocation = new Uri(\"http://localhost:5300/tl/lotl.xml\"), LotlSignerCertificates = [lotlSigner] });",
            "TrustedRoots = [.. lists.GetTrustAnchors()]",
            "TrustedLists = lists.TrustedLists",
        ]
        : [];

    /// <summary>The CLI arguments that trust the Sandbox through its trusted list.</summary>
    internal static IEnumerable<string> TrustedListCliArgs(ValidationSettings s) => UsesSandboxTrustedList(s)
        ? ["--lotl http://localhost:5300/tl/lotl.xml", "--lotl-signer lotl-signer.pem"]
        : [];

    private static CodeSnippets ValidationCode(ValidationSettings s)
    {
        var sb = new StringBuilder();
        sb.Append("using SimpleSign.PAdES.Validation;\nusing SimpleSign.Core.Validation;\n");
        sb.Append(s.PolicyId is null ? "\n" : "using SimpleSign.Core.Policies;\n\n");
        var options = new List<string>();
        if (!s.Trust.Contains(TrustChoice.System))
        {
            options.Add("TrustSystemRoots = false");
        }

        if (s.Trust.Contains(TrustChoice.Sandbox) || s.CustomRootUploadIds.Count > 0)
        {
            options.Add("TrustedRoots = [root] // X509CertificateLoader.LoadCertificateFromFile(\"root.cer\")");
        }

        options.AddRange(TrustedListOptionsCode(s));

        if (s.TimeoutSeconds != 10)
        {
            options.Add($"NetworkTimeout = TimeSpan.FromSeconds({s.TimeoutSeconds})");
        }

        options.AddRange(PolicyOptionsCode(s));
        string optionsCode = options.Count == 0 ? "ValidationOptions.Default" : "new ValidationOptions\n{\n    " + string.Join(",\n    ", options) + ",\n}";
        sb.Append("var options = ").Append(optionsCode).Append(";\n");
        sb.Append("var validator = new PdfSignatureValidator(options);\n");
        sb.Append("\nIReadOnlyList<SignatureValidationResult> results = await validator.ValidateAsync(File.OpenRead(\"signed.pdf\"));\n");
        sb.Append("foreach (var r in results)\n{\n    Console.WriteLine($\"{r.FieldName}: {r.Indication} — {r.SignerName}\");\n");
        sb.Append("    foreach (var error in r.Errors) Console.WriteLine($\"  ✕ {error}\");\n}\n");
        string cli = "simplesign validate signed.pdf"
            + (s.Trust.Contains(TrustChoice.Sandbox) || s.CustomRootUploadIds.Count > 0 ? " --trust root.cer" : "")
            + string.Concat(TrustedListCliArgs(s).Select(a => " " + a))
            + string.Concat(PolicyCliArgs(s).Select(a => " " + a));
        var notes = new List<string>
        {
            L.T("The CLI trusts the operating system's roots too; --trust adds roots."),
            L.T("simplesign inspect signed.pdf shows the structure; simplesign validate-dir validates a folder in bulk."),
        };
        return new CodeSnippets(sb.ToString(), cli, notes);
    }
}

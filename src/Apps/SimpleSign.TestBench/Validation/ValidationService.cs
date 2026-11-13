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

    /// <summary>
    /// The connected Sandbox's trusted list (/tl/tl.xml), read directly with <c>IofeExtension.DefaultListOptions</c>, as
    /// <c>IofeExtension</c> reads INDECOPI's: its CA and <c>unspecified</c> services with their statuses, so the
    /// TrustedLists constraints are evaluated.
    /// </summary>
    SandboxIofeList,

    /// <summary>
    /// The roots of the public TSAs the TestBench offers (DigiCert, Sectigo, FreeTSA), so their timestamps reach a
    /// trust anchor. DSS (tools/dss) trusts the same roots.
    /// </summary>
    PublicTsas,
}

/// <summary>How to validate.</summary>
public sealed record ValidationSettings
{
    /// <summary>The roots to trust. Default: the connected Sandbox's trusted list, the operating system's roots and the public TSAs' roots.</summary>
    public IReadOnlyList<TrustChoice> Trust { get; init; } = [TrustChoice.SandboxTrustedList, TrustChoice.System, TrustChoice.PublicTsas];

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

/// <summary>The verdict on one PDF signature, from the library's result or from the JSON of <c>simplesign validate</c>.</summary>
internal sealed record PadesVerdict(
    string FieldName,
    string Indication,
    string? SubIndication,
    bool IsDocumentTimestamp,
    string? Signer,
    string? SubFilter,
    string? Digest,
    DateTimeOffset? SigningTime,
    bool IntegrityValid,
    bool SignatureValid,
    bool ChainValid,
    bool ChainTrustWarning,
    string? ChainRegion,
    bool NotRevoked,
    string RevocationSource,
    bool? HasValidTimestamp,
    bool? TsaTrusted,
    IReadOnlyList<ValidationConstraintResult> Constraints,
    IReadOnlyList<string> Errors,
    IReadOnlyList<string> Warnings,
    IReadOnlyDictionary<string, string>? ChainMetadata);

/// <summary>Validates PDFs with PdfSignatureValidator and enriches the result with the inspector's facts.</summary>
internal sealed class ValidationService(SandboxEnvironment sandbox, DocumentStore documents)
{
    /// <summary>The per-signature verdicts (used by the signing result).</summary>
    public async Task<IReadOnlyList<SignatureReport>> ValidateAsync(byte[] pdf, ValidationSettings settings, CancellationToken cancellationToken)
    {
        var results = await RunValidatorAsync(pdf, settings, cancellationToken);
        return [.. results.Select(ToReport)];
    }

    /// <summary>
    /// The per-signature verdicts through <c>simplesign validate</c> (used by a signing run through the CLI). A CLI that
    /// prints no verdict gives none; the outcome says why.
    /// </summary>
    public async Task<(IReadOnlyList<SignatureReport> Reports, CliOutcome Outcome)> CliValidateAsync(byte[] pdf, ValidationSettings settings, CancellationToken cancellationToken)
    {
        var command = ValidationCode(settings).CliCommands[0];
        var outcome = await CliValidation.RunAsync(command, new Dictionary<string, byte[]> { [CliLine.Placeholders.Output] = pdf }, CliFiles(settings), cancellationToken);
        var output = outcome.Success ? CliValidation.Parse<CliPadesOutput>(outcome.ValidationJson) : null;
        return ([.. (output?.Signatures ?? []).Select(s => ToReport(CliValidation.Verdict(s)))], outcome);
    }

    /// <summary>The full report for the Validation page.</summary>
    public async Task<ValidationReport> ReportAsync(string fileId, ValidationSettings settings, CancellationToken cancellationToken)
    {
        var file = documents.Get(fileId);
        var code = ValidationCode(settings);
        var watch = Stopwatch.StartNew();
        IReadOnlyList<SignatureValidationResult> results;
        try
        {
            results = await RunValidatorAsync(file.Content, settings, cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return new ValidationReport(fileId, await documents.FactsAsync(fileId, cancellationToken), "Error", [], null, watch.ElapsedMilliseconds, code, ex.Message);
        }

        return await DescribeAsync(fileId, [.. results.Select(ToReport)], watch.ElapsedMilliseconds, code, cancellationToken);
    }

    /// <summary>
    /// The full report for the Validation page through <c>simplesign validate</c>: the verdicts are the CLI's, the
    /// description of the file (structure, levels, coverage, DSS) the inspector's.
    /// </summary>
    public async Task<(ValidationReport Report, CliOutcome? Outcome)> CliReportAsync(string fileId, ValidationSettings settings, CancellationToken cancellationToken)
    {
        var file = documents.Get(fileId);
        var code = ValidationCode(settings);
        var watch = Stopwatch.StartNew();
        var outcome = await CliValidation.RunAsync(code.CliCommands[0], new Dictionary<string, byte[]> { [CliLine.Placeholders.Output] = file.Content }, CliFiles(settings), cancellationToken);
        if (!outcome.Success || CliValidation.Parse<CliPadesOutput>(outcome.ValidationJson) is not { } output)
        {
            return (new ValidationReport(fileId, await documents.FactsAsync(fileId, cancellationToken), "Error", [], null, watch.ElapsedMilliseconds, code,
                outcome.Error ?? L.T("The CLI printed no validation result.")), outcome);
        }

        var reports = output.Signatures.Select(s => ToReport(CliValidation.Verdict(s))).ToList();
        return (await DescribeAsync(fileId, reports, watch.ElapsedMilliseconds, code, cancellationToken), outcome);
    }

    /// <summary>The report of the verdicts on a PDF's signatures, with what the inspector reads of each one and of the file.</summary>
    internal async Task<ValidationReport> DescribeAsync(string fileId, IReadOnlyList<SignatureReport> results, long ms, CodeSnippets code, CancellationToken cancellationToken)
    {
        var file = documents.Get(fileId);
        var facts = await documents.FactsAsync(fileId, cancellationToken);
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
            : results.All(r => r.Indication == nameof(SignatureIndication.Valid)) ? "Valid"
            : results.Any(r => r.Indication == nameof(SignatureIndication.Invalid)) ? "Invalid"
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

    /// <summary>The root of the connected Sandbox, to complete the chains of the SimpleSign report; null without a Sandbox.</summary>
    internal X509Certificate2? SandboxRoot => sandbox.Current?.Root;

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

    /// <summary>
    /// The constraints that failed, warned or informed, one finding per constraint and outcome with all its messages
    /// (a check repeated for each certificate of each token shows once), failures first.
    /// </summary>
    internal static IReadOnlyList<FindingView> Findings(IReadOnlyList<ValidationConstraintResult> constraints) =>
        [.. constraints
            .Where(c => c.Status is ConstraintStatus.Failed or ConstraintStatus.Warning or ConstraintStatus.Information)
            .GroupBy(c => (Name: c.Id.Split('/')[^1], c.Status))
            .OrderBy(g => g.Key.Status switch { ConstraintStatus.Failed => 0, ConstraintStatus.Warning => 1, _ => 2 })
            .Select(g =>
            {
                var guide = Policies.PolicyGuide.Of(g.Key.Name);
                string status = g.Key.Status switch { ConstraintStatus.Failed => "fail", ConstraintStatus.Warning => "warn", _ => "info" };
                return new FindingView(g.Key.Name, guide?.Text ?? g.Key.Name, guide?.Standard, status, [.. g.Select(c => c.Message).Distinct()]);
            })];

    /// <summary>The revocation row of a CAdES or XAdES result.</summary>
    internal static CheckRow RevocationRow(bool? notRevoked, string source) =>
        new("revocation", L.T("Revocation"), notRevoked switch { true => "pass", false => "fail", null => "n/a" },
            notRevoked is null ? null : source);

    /// <summary>The trust settings as library objects, shared by the PAdES, CAdES and XAdES validators.</summary>
    internal async Task<ValidationTrust> TrustAsync(ValidationSettings settings, CancellationToken cancellationToken = default)
    {
        var roots = new List<X509Certificate2>();
        var providers = new List<ITrustAnchorProvider>();
        IReadOnlyList<Core.Extensions.TrustedListInfo>? trustedLists = null;
        IReadOnlyList<Core.Extensions.ITimedTrustAnchorProvider>? timed = null;
        if (sandbox.Current is { } connection)
        {
            bool viaList = settings.Trust.Contains(TrustChoice.SandboxTrustedList) && connection.LotlUri is not null && connection.LotlSigner is not null;
            if (viaList && await SandboxTrustedListsAsync(connection, cancellationToken) is { } set)
            {
                providers.Add(set);
                roots.AddRange(set.GetTrustAnchors());
                trustedLists = set.TrustedLists;
                timed = [set];
            }

            if (settings.Trust.Contains(TrustChoice.SandboxIofeList) && await SandboxIofeListAsync(connection, cancellationToken) is { } iofe)
            {
                providers.Add(iofe);
                roots.AddRange(iofe.GetTrustAnchors());
                trustedLists = [.. trustedLists ?? [], .. iofe.TrustedLists];
                timed = [.. timed ?? [], iofe];
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

        if (settings.Trust.Contains(TrustChoice.PublicTsas))
        {
            roots.AddRange(PublicTsaRoots.Certificates);
        }

        var options = new ValidationOptions
        {
            TrustSystemRoots = settings.Trust.Contains(TrustChoice.System),
            TrustedRoots = roots.Count > 0 ? roots : null,
            TrustedLists = trustedLists,
            TimedTrustAnchors = timed,
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

    /// <summary>
    /// The Sandbox's trusted list, read again for each validation, with the options of <c>IofeExtension</c>. An
    /// expired list is kept (the policy's TLNotExpired judges it); a list that cannot be read or verified gives no anchors.
    /// </summary>
    private async Task<XAdES.TrustedLists.TrustedList?> SandboxIofeListAsync(SandboxConnection connection, CancellationToken cancellationToken)
    {
        if (connection.TlUri is not { } url || connection.TlSigner is not { } signer)
        {
            RunLog.Logger.LogWarning("The Sandbox publishes no trusted list: update it.");
            return null;
        }

        try
        {
            return await XAdES.TrustedLists.TrustedList.DownloadAsync(
                url, Peru.Iofe.IofeExtension.DefaultListOptions with { SignerCertificates = [signer], RejectExpired = false }, sandbox, cancellationToken: cancellationToken);
        }
        catch (Exception ex) when (ex is HttpRequestException or System.Security.Cryptography.CryptographicException or InvalidDataException or System.Xml.XmlException)
        {
            RunLog.Logger.LogWarning("The Sandbox's trusted list could not be read with the IOFE profile: {Reason}", ex.Message);
            return null;
        }
    }

    internal static SignatureReport ToReport(SignatureValidationResult r) =>
        ToReport(new PadesVerdict(
            r.FieldName, r.Indication.ToString(), SubIndicationName(r.SubIndication), r.IsDocumentTimestamp,
            r.SignerName ?? r.SignerCertificate?.GetNameInfo(X509NameType.SimpleName, false), r.SubFilter, r.DigestAlgorithmName, r.SigningTime,
            r.IsIntegrityValid, r.IsSignatureValid, r.IsCertificateChainValid, r.IsChainTrustWarning, r.ChainValidationRegion,
            r.IsNotRevoked, r.RevocationSource.ToString(), r.HasValidTimestamp, r.IsTsaTrusted,
            r.Constraints, r.Errors, r.Warnings, r.ChainValidationMetadata))
        with
        {
            Source = new Reports.ReportSource(r.ToReportEntry(), r.EmbeddedCertificates),
        };

    /// <summary>The report of one PDF signature from its verdict, whichever validated it (the library or the CLI).</summary>
    internal static SignatureReport ToReport(PadesVerdict v)
    {
        static string Status(bool? ok) => ok switch { true => "pass", false => "fail", null => "n/a" };
        var checks = new List<CheckRow>
        {
            new("integrity", L.T("Integrity (ByteRange digest)"), Status(v.IntegrityValid), v.IntegrityValid
                ? L.T("The signed bytes were not changed after signing.")
                : L.T("The signed bytes were changed after signing: the digest no longer matches.")),
            new("signature", L.T("Signature value"), Status(v.SignatureValid), v.Digest is { } digest ? L.T("Digest {0}.", digest) : null),
            new("chain", L.T("Certificate chain"), v.ChainTrustWarning ? "warn" : Status(v.ChainValid), v.ChainRegion),
            new("revocation", L.T("Revocation"), Status(v.NotRevoked), v.RevocationSource),
            new("timestamp", L.T("Signature timestamp"), Status(v.HasValidTimestamp), v.TsaTrusted is { } trusted ? (trusted ? L.T("TSA trusted.") : L.T("TSA not trusted.")) : null),
        };
        checks.AddRange(PolicyRows(v.Constraints));
        return new SignatureReport(
            v.FieldName, v.Indication, v.IsDocumentTimestamp, v.Signer, v.SubFilter, v.Digest,
            v.SigningTime?.ToString("yyyy-MM-dd HH:mm:ss zzz", System.Globalization.CultureInfo.InvariantCulture),
            checks, v.Errors, v.Warnings, v.ChainMetadata, v.SubIndication, Findings(v.Constraints));
    }

    private static DetailedSignature Detail(SignatureReport report, SignatureFieldInfo? info, string? level, long fileSize, int revisions)
    {
        CoverageView? coverage = null;
        if (info is not null)
        {
            long end = info.ByteRange.Offset2 + info.ByteRange.Length2;
            coverage = new CoverageView(end, fileSize, end >= fileSize - 2, RevisionOf(end, fileSize, revisions), revisions);
        }

        return new DetailedSignature(
            report,
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

    /// <summary>
    /// The validation flags of a <c>validate</c> command: the roots (<c>--trust</c>, <c>--no-system-roots</c>), the policy,
    /// level and revocation strategy that differ from the defaults, and the Sandbox's origins.
    /// </summary>
    internal static void ValidationCli(CliLine line, ValidationSettings s, SandboxEnvironment sandbox)
    {
        if (SandboxRootTrusted(s, sandbox) || s.CustomRootUploadIds.Count > 0 || s.Trust.Contains(TrustChoice.PublicTsas))
        {
            line.Add("--trust", RootFile);
        }

        // The Sandbox's trusted list: read through its LOTL, when the Sandbox publishes one (the example address without a Sandbox).
        if (UsesSandboxTrustedList(s) && sandbox.Current is not { LotlUri: null })
        {
            string lotl = sandbox.Current?.LotlUri?.AbsoluteUri ?? "http://localhost:5300/tl/lotl.xml";
            line.Add("--lotl", lotl, "--lotl-signer", LotlSignerFile);
        }

        // The trusted list with the IOFE profile: read directly, as IofeExtension reads INDECOPI's.
        if (s.Trust.Contains(TrustChoice.SandboxIofeList))
        {
            string iofe = sandbox.Current?.TlUri?.AbsoluteUri ?? "http://localhost:5300/tl/tl.xml";
            line.Add("--tsl", iofe, "--tsl-signer", TlSignerFile, "--tsl-profile", "iofe");
        }

        if (!s.Trust.Contains(TrustChoice.System))
        {
            line.Add("--no-system-roots");
        }

        if (s.PolicyId is not null)
        {
            line.Add("--policy", PolicyUploads.ValidationFileName);
        }

        if (s.Level != ValidationLevel.ArchivalData)
        {
            line.Add("--level", s.Level switch
            {
                ValidationLevel.BasicSignatures => "basic",
                ValidationLevel.Timestamps => "timestamps",
                _ => "lt",
            });
        }

        if (s.RevocationStrategy != RevocationStrategy.OcspFirst)
        {
            line.Add("--revocation-strategy", "crl-first");
        }

        PlanContext.SandboxNetwork(line, sandbox);
    }

    /// <summary>The trusted roots a generated <c>validate</c> command reads (PEM, one or more).</summary>
    internal const string RootFile = "root.cer";

    /// <summary>
    /// Whether the Sandbox's root is a bare trust anchor: asked for, or the trusted list asked of a connected Sandbox that
    /// publishes none (as <see cref="TrustAsync"/> does).
    /// </summary>
    private static bool SandboxRootTrusted(ValidationSettings s, SandboxEnvironment sandbox) =>
        s.Trust.Contains(TrustChoice.Sandbox) || (UsesSandboxTrustedList(s) && sandbox.Current is { LotlUri: null });

    /// <summary>
    /// The files a generated validate command reads, with the same trust as <see cref="TrustAsync"/>: <see cref="RootFile"/>
    /// (the Sandbox's root when trusted as an anchor, the uploaded roots, the public TSAs' roots), the LOTL signer and the
    /// validation policy.
    /// </summary>
    internal Dictionary<string, byte[]> CliFiles(ValidationSettings settings)
    {
        var files = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        var roots = new List<X509Certificate2>();
        if (SandboxRootTrusted(settings, sandbox) && sandbox.Current is { } connection)
        {
            roots.Add(connection.Root);
        }

        roots.AddRange(settings.CustomRootUploadIds.Select(id => LoadCertificate(documents.Get(id).Content)));
        if (settings.Trust.Contains(TrustChoice.PublicTsas))
        {
            roots.AddRange(PublicTsaRoots.Certificates);
        }

        if (roots.Count > 0)
        {
            files[RootFile] = Encoding.ASCII.GetBytes(string.Concat(roots.Select(r => r.ExportCertificatePem() + "\n")));
        }

        if (UsesSandboxTrustedList(settings) && sandbox.Current?.LotlSigner is { } signer)
        {
            files[LotlSignerFile] = Encoding.ASCII.GetBytes(signer.ExportCertificatePem() + "\n");
        }

        if (settings.Trust.Contains(TrustChoice.SandboxIofeList) && sandbox.Current?.TlSigner is { } tlSigner)
        {
            files[TlSignerFile] = Encoding.ASCII.GetBytes(tlSigner.ExportCertificatePem() + "\n");
        }

        if (settings.PolicyId is { } policyId && documents.TryGet(policyId, out var policy))
        {
            files[PolicyUploads.ValidationFileName] = policy!.Content;
        }

        return files;
    }

    /// <summary>The LOTL signer certificate a generated <c>validate</c> command reads.</summary>
    internal const string LotlSignerFile = "lotl-signer.pem";

    /// <summary>The certificate the trusted list is signed with, as a generated <c>validate</c> command reads it.</summary>
    internal const string TlSignerFile = "tl-signer.pem";

    /// <summary>Whether the settings read the Sandbox's trusted list (the snippets then load it).</summary>
    internal static bool UsesSandboxTrustedList(ValidationSettings s) => s.Trust.Contains(TrustChoice.SandboxTrustedList);

    /// <summary>The ValidationOptions lines that trust the Sandbox through its trusted list, for the code snippets.</summary>
    internal static IEnumerable<string> TrustedListOptionsCode(ValidationSettings s) => (UsesSandboxTrustedList(s), s.Trust.Contains(TrustChoice.SandboxIofeList)) switch
    {
        (true, _) =>
        [
            "// var lists = await TrustedListSet.LoadAsync(new() { LotlLocation = new Uri(\"http://localhost:5300/tl/lotl.xml\"), LotlSignerCertificates = [lotlSigner] });",
            "TrustedRoots = [.. lists.GetTrustAnchors()]",
            "TrustedLists = lists.TrustedLists",
            "TimedTrustAnchors = [lists]",
        ],
        (false, true) =>
        [
            "// var iofe = await TrustedList.DownloadAsync(new Uri(\"http://localhost:5300/tl/tl.xml\"), IofeExtension.DefaultListOptions with { SignerCertificates = [tlSigner] });",
            "TrustedRoots = [.. iofe.GetTrustAnchors()]",
            "TrustedLists = iofe.TrustedLists",
            "TimedTrustAnchors = [iofe]",
        ],
        _ => [],
    };

    internal CodeSnippets ValidationCode(ValidationSettings s)
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
        var line = new CliLine("validate", CliLine.Placeholders.Output);
        ValidationCli(line, s, sandbox);
        var notes = new List<string>
        {
            L.T("simplesign inspect signed.pdf shows the structure; simplesign validate-dir validates a folder in bulk."),
        };
        if (s.Trust.Contains(TrustChoice.PublicTsas))
        {
            notes.Add(L.T("root.cer holds the roots to trust, the public TSAs' among them: copy them from src/Apps/SimpleSign.TestBench/TsaRoots (the operating system usually trusts DigiCert's and Sectigo's, never FreeTSA's)."));
        }
        return new CodeSnippets(sb.ToString(), line.ToString(), notes) { CliCommands = [line] };
    }
}

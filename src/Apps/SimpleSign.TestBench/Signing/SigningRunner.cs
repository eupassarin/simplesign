using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SimpleSign.Core.Signing;
using SimpleSign.PAdES;
using SimpleSign.PAdES.Inspection;
using SimpleSign.PAdES.Signing;
using SimpleSign.TestBench.Credentials;
using SimpleSign.TestBench.Documents;
using SimpleSign.TestBench.Localization;
using SimpleSign.TestBench.Runs;
using SimpleSign.TestBench.Sandbox;
using SimpleSign.TestBench.Validation;

namespace SimpleSign.TestBench.Signing;

public sealed record CheckRow(string Id, string Name, string Status, string? Detail);

/// <summary>One signature of the validation report.</summary>
public sealed record SignatureReport(
    string FieldName,
    string Indication,
    bool IsDocumentTimestamp,
    string? Signer,
    string? SubFilter,
    string? Digest,
    string? SigningTime,
    IReadOnlyList<CheckRow> Checks,
    IReadOnlyList<string> Errors,
    IReadOnlyList<string> Warnings,
    IReadOnlyDictionary<string, string>? Metadata,
    string? SubIndication = null,
    IReadOnlyList<FindingView>? Findings = null);

/// <summary>
/// A constraint of the validation policy that failed, warned or informed on a signature, with every message it gave
/// (one per certificate or token it applied to): <paramref name="Title"/> says in plain words what it checks.
/// </summary>
public sealed record FindingView(string Constraint, string Title, string? Standard, string Status, IReadOnlyList<string> Messages);

/// <summary>What the signed PDF contains, read back with the inspector.</summary>
public sealed record OutputFacts(
    int SignatureCount,
    string? DetectedLevel,
    bool HasDss,
    int DssCertificates,
    int DssCrls,
    int DssOcsps,
    string? PdfALevel,
    int DocMdpLevel);

public sealed record DeferredInfo(string HashToSignHex, string DigestAlgorithm, string SignatureAlgorithmOid, int SessionBytes, string RawSignatureHex);

public sealed record BatchItem(string Id, bool Ok, string? Error, string? OutputId, long Bytes);

public sealed record CodeSnippets(string CSharp, string Cli, IReadOnlyList<string> CliNotes)
{
    /// <summary>The CLI commands of <see cref="Cli"/>, token by token, for the equivalence test.</summary>
    [System.Text.Json.Serialization.JsonIgnore]
    public IReadOnlyList<CliLine> CliCommands { get; init; } = [];
}

public sealed record SigningResult(
    bool Success,
    string? Error,
    string? ErrorType,
    string? OutputId,
    string? FileName,
    long Bytes,
    string RequestedLevel,
    string? AchievedLevel,
    bool HasSignatureTimestamp,
    bool HasLongTermValidation,
    bool HasArchiveTimestamp,
    IReadOnlyList<string> Warnings,
    long SignMs,
    long ValidateMs,
    IReadOnlyList<SignatureReport> Validation,
    OutputFacts? Output,
    DeferredInfo? Deferred,
    IReadOnlyList<BatchItem> Batch,
    CodeSnippets Code,
    IReadOnlyList<OptionIssue> Issues);

/// <summary>Signs with the effective options, validates the output and produces the matching code.</summary>
internal sealed class SigningRunner(SandboxEnvironment sandbox, DocumentStore documents, CredentialStore credentials)
{
    private readonly ValidationService _validation = new(sandbox, documents);

    public async Task<SigningResult> RunAsync(SigningOptions options, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(options);
        DocumentFacts? document = options.DocumentId is { } id ? await documents.FactsAsync(id, cancellationToken) : null;
        credentials.TryGet(options.CredentialId, out var credential);
        var report = Compatibility.Evaluate(options, document, credential?.Facts, sandbox.IsConnected, PolicyUploads.Signing(options.SigningPolicyId, documents));
        var empty = new CodeSnippets("", "", []);
        if (!report.CanSign)
        {
            return Failure(report, L.T("The options are not compatible; fix the errors listed for each step."), "Compatibility", empty);
        }

        var effective = report.Effective;
        byte[] pdf = documents.Get(effective.DocumentId!).Content;
        SigningPlan plan;
        CodeSnippets code = empty;
        try
        {
            plan = new SigningPlan(effective, credential!, sandbox, documents);
            var steps = plan.SignSteps();
            code = CodeGenerator.Generate(effective, plan, steps, credential!.Facts);
            var watch = Stopwatch.StartNew();
            return effective.Mode switch
            {
                RunMode.Deferred => await DeferredAsync(effective, plan, credential, pdf, report, code, watch, cancellationToken),
                RunMode.Batch => await BatchAsync(effective, plan, credential, pdf, report, code, watch, cancellationToken),
                _ => await SignAsync(effective, plan, steps, pdf, report, code, watch, cancellationToken),
            };
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !cancellationToken.IsCancellationRequested)
        {
            return Failure(report, Describe(ex), ErrorTypeOf(ex), code);
        }
    }

    private async Task<SigningResult> SignAsync(SigningOptions o, SigningPlan plan, IReadOnlyList<PlanStep> steps, byte[] pdf,
        OptionsReport report, CodeSnippets code, Stopwatch watch, CancellationToken cancellationToken)
    {
        var builder = PadesSigner.Document(pdf).WithLogger(RunLog.Logger);
        foreach (var step in steps)
        {
            builder = step.Apply(builder);
        }

        var result = await builder.SignWithDetailsAsync(cancellationToken);
        long signMs = watch.ElapsedMilliseconds;
        return await FinishAsync(o, report, code, result.SignedArtifact, LevelName(result.AchievedLevel),
            result.HasSignatureTimestamp, result.HasLongTermValidationMaterial, result.HasArchiveTimestamp,
            [.. result.Warnings.Select(w => $"{w.Code}: {w.Message}")], signMs, null, [], cancellationToken);
    }

    private async Task<SigningResult> DeferredAsync(SigningOptions o, SigningPlan plan, CredentialHandle credential, byte[] pdf,
        OptionsReport report, CodeSnippets code, Stopwatch watch, CancellationToken cancellationToken)
    {
        byte[] integrityKey = RandomNumberGenerator.GetBytes(32);
        var builder = DeferredSigner.Document(pdf)
            .WithCertificate(credential.Certificate, credential.Chain)
            .WithHttpClientProvider(plan.Http)
            .WithHashAlgorithm(plan.HashAlgorithm)
            .WithFieldOptions(plan.Field)
            .WithLevel(plan.Profile!)
            .WithLogger(RunLog.Logger)
            .WithSessionIntegrityKey(integrityKey);
        if (plan.SignatureAlgorithmOid is { } oid)
        {
            builder = builder.WithSignatureAlgorithm(oid);
        }

        // Phase 1 (server): prepare the PDF and get the hash to sign. The session can be stored anywhere.
        var prepared = await builder.PrepareAsync(cancellationToken);

        // Phase 2 (signer, e.g. a browser + local agent, a token or a cloud service): sign the DER
        // signed attributes in HashToSign (the signer hashes them) and return the raw signature.
        byte[] raw = await SignPreparedAsync(credential, prepared, plan, cancellationToken);

        // Phase 3 (server): resume the session and embed the signature (plus timestamps / LTV).
        var resume = DeferredSigner.Resume(prepared.SessionData, integrityKey).WithHttpClientProvider(plan.Http).WithLogger(RunLog.Logger);
        if (plan.Timestamp is { } tsa && (tsa.Authorization is not null || tsa.ClientCertificate is not null || plan.ArchiveTimestamp?.Authorization is not null))
        {
            // Secrets are never stored in the session: supply them again on resume.
            resume = resume.WithTimestampOptions(tsa, plan.ArchiveTimestamp);
        }

        byte[] signed = await resume.CompleteAsync(raw, cancellationToken);
        long signMs = watch.ElapsedMilliseconds;
        var info = new DeferredInfo(Convert.ToHexString(prepared.HashToSign.AsSpan(0, Math.Min(prepared.HashToSign.Length, 96))) + "…", prepared.DigestAlgorithm, prepared.SignatureAlgorithmOid,
            prepared.SessionData.Length, Convert.ToHexString(raw.AsSpan(0, Math.Min(raw.Length, 64))) + (raw.Length > 64 ? "…" : ""));
        var level = plan.Profile!.Level;
        return await FinishAsync(o, report, code, signed, LevelName(level), level >= AdesBaselineLevel.Timestamped,
            level >= AdesBaselineLevel.LongTerm, level >= AdesBaselineLevel.Archive, [], signMs, info, [], cancellationToken);
    }

    private async Task<SigningResult> BatchAsync(SigningOptions o, SigningPlan plan, CredentialHandle credential, byte[] pdf,
        OptionsReport report, CodeSnippets code, Stopwatch watch, CancellationToken cancellationToken)
    {
        var builder = BatchSigner.Create(credential.Certificate)
            .WithChain(credential.Chain)
            .WithHttpClientProvider(plan.Http)
            .WithHashAlgorithm(plan.HashAlgorithm)
            .WithFieldOptions(plan.Field)
            .WithLevel(plan.Profile!)
            .WithLogger(RunLog.Logger)
            .WithMaxConcurrency(o.MaxConcurrency);
        if (credential.External is { } external)
        {
            builder = builder.WithExternalSigner(external);
        }

        if (plan.SignatureAlgorithmOid is { } oid)
        {
            builder = builder.WithSignatureAlgorithm(oid);
        }

        if (!string.IsNullOrWhiteSpace(o.OperationId))
        {
            builder = builder.WithOperationId(o.OperationId);
        }

        await using var batch = builder.Build();
        var items = new List<BatchItem>();
        byte[]? first = null;
        await foreach (var r in batch.SignAllAsync(Inputs(pdf, o.BatchCopies), cancellationToken))
        {
            string? outputId = r.SignedPdf is { } bytes ? documents.Add($"batch-{r.Id}.pdf", bytes).Id : null;
            first ??= r.SignedPdf;
            items.Add(new BatchItem(r.Id, r.IsSuccess, r.Error is null ? null : Describe(r.Error), outputId, r.SignedPdf?.Length ?? 0));
        }

        long signMs = watch.ElapsedMilliseconds;
        items.Sort((a, b) => string.CompareOrdinal(a.Id, b.Id));
        if (first is null)
        {
            return Failure(report, L.T("Every document of the batch failed: {0}", items.FirstOrDefault()?.Error), "BatchFailure", code) with { Batch = items };
        }

        var level = plan.Profile!.Level;
        var result = await FinishAsync(o, report, code, first, LevelName(level), level >= AdesBaselineLevel.Timestamped,
            level >= AdesBaselineLevel.LongTerm, level >= AdesBaselineLevel.Archive,
            [L.T("Batch: {0} signed, {1} failed, {2:0} ms average per document. The report below validates the first one.", batch.SuccessCount, batch.FailureCount, batch.AverageElapsedMs)],
            signMs, null, items, cancellationToken);
        return result;

        static async IAsyncEnumerable<(string Id, byte[] PdfBytes)> Inputs(byte[] pdf, int copies)
        {
            for (int i = 1; i <= copies; i++)
            {
                await Task.Yield();
                yield return ($"doc-{i:D2}", pdf);
            }
        }
    }

    private async Task<SigningResult> FinishAsync(SigningOptions o, OptionsReport report, CodeSnippets code, byte[] signed, string achieved,
        bool hasTimestamp, bool hasLtv, bool hasArchive, IReadOnlyList<string> warnings, long signMs, DeferredInfo? deferred,
        IReadOnlyList<BatchItem> batch, CancellationToken cancellationToken)
    {
        var source = documents.Get(o.DocumentId!);
        string fileName = Path.GetFileNameWithoutExtension(source.FileName) + "-signed.pdf";
        var stored = documents.Add(fileName, signed);
        var watch = Stopwatch.StartNew();
        IReadOnlyList<SignatureReport> validation = o.Validate ? await _validation.ValidateAsync(signed, o.Validation ?? new ValidationSettings(), cancellationToken) : [];
        long validateMs = watch.ElapsedMilliseconds;
        var output = await InspectAsync(signed, cancellationToken);
        return new SigningResult(true, null, null, stored.Id, fileName, signed.Length, Compatibility.LevelName(o), achieved,
            hasTimestamp, hasLtv, hasArchive, warnings, signMs, validateMs, validation, output, deferred, batch, code, report.Issues);
    }

    private static async Task<OutputFacts?> InspectAsync(byte[] pdf, CancellationToken cancellationToken)
    {
        try
        {
            using var stream = new MemoryStream(pdf, writable: false);
            var inspection = await PdfSignatureInspector.InspectAsync(stream, RunLog.Logger, cancellationToken);
            var dss = inspection.Document.SecurityStore;
            var level = new ConformanceDetectorService().DetectHighest(inspection);
            return new OutputFacts(inspection.Signatures.Count, level.ToString(), dss?.IsPresent == true,
                dss?.CertificateCount ?? 0, dss?.CrlCount ?? 0, dss?.OcspResponseCount ?? 0,
                inspection.Document.PdfALevel.ToString(), inspection.Document.DocMdpPermissionLevel);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return null;
        }
    }

    /// <summary>
    /// Phase 2 of a deferred signature: what the browser + local agent, the token or the cloud
    /// service does with <see cref="DeferredSigningPrepareResult.HashToSign"/> (DER signed attributes).
    /// </summary>
    internal static async Task<byte[]> SignPreparedAsync(CredentialHandle credential, DeferredSigningPrepareResult prepared, SigningPlan plan, CancellationToken cancellationToken)
    {
        bool pss = plan.SignatureAlgorithmOid is not null;
        if (credential.External is { } external)
        {
            var request = new ExternalSigningRequest(prepared.HashToSign, plan.HashAlgorithm, prepared.SignatureAlgorithmOid,
                ExternalSigningPayloadKind.CmsSignedAttributes, null,
                pss ? new RsaPssParameters(plan.HashAlgorithm, plan.HashAlgorithm, HashLength(plan.HashAlgorithm)) : null);
            return (await external.SignAsync(request, cancellationToken)).ToArray();
        }

        var certificate = credential.Certificate;
        if (certificate.GetRSAPrivateKey() is { } rsa)
        {
            using (rsa)
            {
                return rsa.SignData(prepared.HashToSign, plan.HashAlgorithm, pss ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1);
            }
        }

        using var ec = certificate.GetECDsaPrivateKey() ?? throw new CryptographicException("The certificate has no usable private key.");
        return ec.SignData(prepared.HashToSign, plan.HashAlgorithm, DSASignatureFormat.Rfc3279DerSequence);
    }

    private static int HashLength(HashAlgorithmName hash) =>
        hash == HashAlgorithmName.SHA384 || hash == HashAlgorithmName.SHA3_384 ? 48
        : hash == HashAlgorithmName.SHA512 || hash == HashAlgorithmName.SHA3_512 ? 64
        : 32;

    private static string LevelName(AdesBaselineLevel level) => level switch
    {
        AdesBaselineLevel.Basic => "B-B",
        AdesBaselineLevel.Timestamped => "B-T",
        AdesBaselineLevel.LongTerm => "B-LT",
        _ => "B-LTA",
    };

    private static SigningResult Failure(OptionsReport report, string error, string type, CodeSnippets code) =>
        new(false, error, type, null, null, 0, report.EffectiveLevel, null, false, false, false, [], 0, 0, [], null, null, [], code, report.Issues);

    private static string Describe(Exception ex)
    {
        var messages = new List<string>();
        for (var e = ex; e is not null && messages.Count < 4; e = e.InnerException)
        {
            if (!messages.Contains(e.Message))
            {
                messages.Add(e.Message);
            }
        }

        return string.Join(" → ", messages);
    }

    /// <summary>The exception type shown in the result; a SigningException adds its reason, such as KeyTooWeak.</summary>
    internal static string ErrorTypeOf(Exception ex) =>
        ex is SigningException signing && signing.Reason != SigningErrorReason.Unspecified
            ? $"{ex.GetType().Name} ({signing.Reason})"
            : ex.GetType().Name;
}

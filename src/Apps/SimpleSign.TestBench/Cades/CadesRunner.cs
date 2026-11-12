using System.Diagnostics;
using System.Globalization;
using System.Text;
using SimpleSign.CAdES;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Signing;
using SimpleSign.TestBench.Credentials;
using SimpleSign.TestBench.Documents;
using SimpleSign.TestBench.Localization;
using SimpleSign.TestBench.Runs;
using SimpleSign.TestBench.Sandbox;
using SimpleSign.TestBench.Signing;
using SimpleSign.TestBench.Validation;

namespace SimpleSign.TestBench.Cades;

/// <summary>The verdict for one CAdES signer, with its countersignatures nested.</summary>
public sealed record CadesSignerReport(
    int Index,
    string? Signer,
    string Indication,
    string? SigningTime,
    IReadOnlyList<CheckRow> Checks,
    IReadOnlyList<string> Errors,
    IReadOnlyList<string> Warnings,
    IReadOnlyList<CadesSignerReport> CounterSignatures,
    string? SubIndication = null,
    IReadOnlyList<FindingView>? Findings = null)
{
    /// <summary>The library's report entry of this signature and the certificates next to it, for the SimpleSign report (not sent to the UI).</summary>
    [System.Text.Json.Serialization.JsonIgnore]
    public Reports.ReportSource? Source { get; init; }
}

/// <summary>The verdict on one CAdES signer, from the library's result or from the JSON of <c>simplesign cades validate</c>.</summary>
internal sealed record CadesVerdict(
    int Index,
    string? Signer,
    string Indication,
    string? SubIndication,
    DateTimeOffset? SigningTime,
    bool IntegrityValid,
    bool SignatureValid,
    bool ChainValid,
    bool? HasValidTimestamp,
    bool? TsaTrusted,
    bool? HasValidContentTimestamp,
    DateTimeOffset? ContentTimestampTime,
    bool? LtvDataValid,
    bool? HasValidEscTimestamp,
    bool? HasValidArchiveTimestamp,
    bool? NotRevoked,
    string RevocationSource,
    IReadOnlyList<SimpleSign.Core.Validation.ValidationConstraintResult> Constraints,
    IReadOnlyList<string> Errors,
    IReadOnlyList<string> Warnings,
    IReadOnlyList<CadesVerdict> CounterSignatures)
{
    /// <summary>The library's report entry, for the SimpleSign report; null from the CLI.</summary>
    public Reports.ReportSource? Source { get; init; }
}

/// <summary>The result of <c>CadesSignatureValidator.ValidateAll</c>, for the UI.</summary>
public sealed record CadesValidationView(
    string Overall,
    IReadOnlyList<CadesSignerReport> Signers,
    IReadOnlyList<string> Errors,
    CmsFacts Structure,
    long Ms,
    CodeSnippets Code);

public sealed record CadesSignResult(
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
    CadesValidationView? Validation,
    CodeSnippets Code,
    IReadOnlyList<OptionIssue> Issues)
{
    /// <summary>The commands a run through the CLI executed, with their exit codes and output; null for a library run.</summary>
    public IReadOnlyList<CliStep>? Cli { get; init; }

    /// <summary>The reports the CLI's validation wrote; null for a library run.</summary>
    public CliReports? Reports { get; init; }
}

/// <summary>Signs with <c>CadesSigner</c> and validates with <c>CadesSignatureValidator.ValidateAll</c>.</summary>
internal sealed class CadesRunner(SandboxEnvironment sandbox, DocumentStore documents, CredentialStore credentials, ValidationService validation)
{
    /// <summary>Whether a Sandbox is connected (its TSAs and signers can be chosen).</summary>
    public bool SandboxConnected => sandbox.IsConnected;

    public CadesInputs Inputs(CadesOptions o)
    {
        string? dataName = o.DataId is { } dataId && documents.TryGet(dataId, out var data) ? data!.FileName : null;
        CmsFacts? existing = null;
        bool? matches = null;
        if (o.ExistingSignatureId is { } existingId && documents.TryGet(existingId, out var signature))
        {
            existing = CadesInspector.Inspect(existingId, signature!.FileName, signature.Content);
            if (o.Operation != CadesOperation.Sign && dataName is not null && existing.IsDetached)
            {
                matches = CadesInspector.DataMatches(signature.Content, documents.Get(o.DataId!).Content);
            }
        }

        return new CadesInputs(dataName, existing, matches);
    }

    /// <summary>What a CAdES signature with <paramref name="options"/> would do, without making it.</summary>
    internal async Task<RunDescription> DescribeAsync(CadesOptions options, CancellationToken cancellationToken)
    {
        var report = Evaluate(options);
        credentials.TryGet(report.Effective.CredentialId, out var credential);
        CodeSnippets? code = null;
        string? error = null;
        if (credential is not null)
        {
            try
            {
                var controls = await SigningControls.ResolveAsync(report.Effective.SigningControls, sandbox, cancellationToken);
                code = new CadesPlan(report.Effective, new PlanContext(credential, sandbox, documents) { Controls = controls }).Code(credential.Facts);
            }
            catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or SigningException or HttpRequestException or KeyNotFoundException)
            {
                error = ex.Message;
            }
        }

        return new RunDescription(report.Effective, report.Options, report.Issues, code, error, credential?.Facts);
    }

    public CadesOptionsReport Evaluate(CadesOptions o)
    {
        credentials.TryGet(o.CredentialId, out var credential);
        return CadesCompatibility.Evaluate(o, Inputs(o), credential?.Facts, sandbox.IsConnected, PolicyUploads.Signing(o.SigningPolicyId, documents));
    }

    private readonly CliExecutor _cli = new();

    public Task<CadesSignResult> RunAsync(CadesOptions options, CancellationToken cancellationToken) =>
        RunAsync(options, RunEngines.Library, cancellationToken);

    /// <summary>Signs through the library or, with <see cref="RunEngines.Cli"/>, by running the generated command through the CLI.</summary>
    public async Task<CadesSignResult> RunAsync(CadesOptions options, string engine, CancellationToken cancellationToken)
    {
        var report = Evaluate(options);
        var o = report.Effective;
        var empty = new CodeSnippets("", "", []);
        if (!report.CanRun)
        {
            return Failure(o, report, L.T("Fix the issues before signing."), "Validation", empty);
        }

        var credential = credentials.Get(o.CredentialId!);
        credential.LastUsed = DateTimeOffset.UtcNow;
        SigningControls controls;
        try
        {
            controls = await SigningControls.ResolveAsync(o.SigningControls, sandbox, cancellationToken);
        }
        catch (Exception ex) when (ex is SigningException or ArgumentException or HttpRequestException)
        {
            return Failure(o, report, ex.Message, SigningRunner.ErrorTypeOf(ex), empty);
        }

        var plan = new CadesPlan(o, new PlanContext(credential, sandbox, documents) { Controls = controls });
        byte[]? data = o.DataId is { } id && o.Operation != CadesOperation.CounterSign && report.Options["data"].Visible ? documents.Get(id).Content : null;
        byte[]? existing = o.ExistingSignatureId is { } existingId && report.Options["existing"].Visible ? documents.Get(existingId).Content : null;
        var code = plan.Code(credential.Facts);
        var watch = Stopwatch.StartNew();
        if (engine == RunEngines.Cli)
        {
            if (CliJobs.Unsupported(credential) is { } unsupported)
            {
                return Failure(o, report, unsupported, "CliUnsupported", code);
            }

            var jobs = new CliJobs().Credential(credential).Timestamp(o.Timestamp, documents).Uploads(o, o.SigningPolicyId, documents);
            foreach (var (name, content) in controls.CliFiles())
            {
                jobs.File(name, content);
            }

            if (data is not null)
            {
                jobs.File(DataFile, data);
            }

            if (existing is not null)
            {
                jobs.File(SignatureFile, existing);
            }

            var outcome = await _cli.RunAsync(jobs.Build(code.CliCommands), cancellationToken);
            controls.Report(outcome.AuditTrail);
            if (!outcome.Success)
            {
                return Failure(o, report, outcome.Error!, outcome.Json?.ErrorType ?? "Cli", code) with { Cli = outcome.Steps };
            }

            string achieved = outcome.Json?.AchievedLevel ?? report.EffectiveLevel;
            var result = await FinishAsync(o, report, code, outcome.Output!, achieved, achieved is not "B-B", achieved is "B-LT" or "B-LTA", achieved is "B-LTA",
                outcome.Json?.Warnings ?? [], watch.ElapsedMilliseconds, cancellationToken, cli: true);
            return result with { Cli = [.. outcome.Steps, .. result.Cli ?? []] };
        }

        CAdES.CadesSigningResult signed;
        try
        {
            var builder = o.Operation switch
            {
                CadesOperation.CoSign => CadesSigner.CoSign(existing!, data),
                CadesOperation.CounterSign => CadesSigner.CounterSign(existing!, o.SignerIndex),
                _ => CadesSigner.Document(data!),
            };
            builder = builder.WithLogger(RunLog.Logger);
            foreach (var step in plan.Steps)
            {
                builder = step.Apply(builder);
            }

            signed = await builder.SignWithDetailsAsync(cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return Failure(o, report, ex.Message, SigningRunner.ErrorTypeOf(ex), code);
        }
        finally
        {
            controls.Report(cliTrail: null);
        }

        return await FinishAsync(o, report, code, signed.SignedArtifact, LevelName(signed.AchievedLevel),
            signed.HasSignatureTimestamp, signed.HasLongTermValidationMaterial, signed.HasArchiveTimestamp,
            [.. signed.Warnings.Select(w => w.Message)], watch.ElapsedMilliseconds, cancellationToken);
    }

    /// <summary>Stores the signature and validates it.</summary>
    private async Task<CadesSignResult> FinishAsync(CadesOptions o, CadesOptionsReport report, CodeSnippets code, byte[] signed, string achieved,
        bool hasTimestamp, bool hasLtv, bool hasArchive, IReadOnlyList<string> warnings, long signMs, CancellationToken cancellationToken, bool cli = false)
    {
        string fileName = OutputName(o);
        var output = documents.Add(fileName, signed);

        // Detached signatures validate against the data; enveloped ones carry it. Signed through the CLI, validated through it.
        string? contentId = o.ContentType == CadesContentChoice.Detached && report.Options["data"].Visible ? o.DataId : null;
        var settings = o.Validation ?? new ValidationSettings();
        CadesValidationView? view = null;
        CliOutcome? outcome = null;
        if (o.Validate && cli)
        {
            (view, outcome) = await ValidateWithCliAsync(output.Id, contentId, settings, cancellationToken);
        }
        else if (o.Validate)
        {
            view = await ValidateAsync(output.Id, contentId, settings, cancellationToken);
        }

        return new CadesSignResult(true, null, null, output.Id, fileName, signed.LongLength, report.EffectiveLevel, achieved,
            hasTimestamp, hasLtv, hasArchive, warnings, signMs, view, code, report.Issues)
        {
            Cli = outcome?.Steps,
            Reports = outcome is null ? null : CliValidation.Store(outcome, documents, fileName),
        };
    }

    /// <summary>Validates every signer (and countersigner) of a stored signature.</summary>
    public async Task<CadesValidationView> ValidateAsync(string signatureId, string? dataId, ValidationSettings settings, CancellationToken cancellationToken = default)
    {
        var signature = documents.Get(signatureId);
        byte[]? data = dataId is null ? null : documents.Get(dataId).Content;
        var structure = CadesInspector.Inspect(signatureId, signature.FileName, signature.Content);
        var code = ValidationCode(settings, structure.IsDetached);
        var watch = Stopwatch.StartNew();
        if (structure.IsDetached && data is null && structure.Error is null)
        {
            return new CadesValidationView("Indeterminate", [], [L.T("The signature is detached: choose the data it signed to check its integrity.")], structure, 0, code);
        }

        var trust = await validation.TrustAsync(settings, cancellationToken);
        var validator = new CadesSignatureValidator(trust.Options, RunLog.Logger, chainRevocationChecker: validation.RevocationChecker());
        var result = await validator.ValidateAllAsync(signature.Content, structure.IsDetached ? data : null, null, cancellationToken);
        var signers = result.Signers.Select(s => Signer(Verdict(s, $"signer-{s.Index + 1}"))).ToList();
        return new CadesValidationView(Overall(signers, result.Errors), signers, result.Errors, structure, watch.ElapsedMilliseconds, code);
    }

    /// <summary>
    /// Validates every signer through <c>simplesign cades validate</c>: the verdicts are the CLI's, the structure the
    /// inspector's. The outcome holds the command, its output and its reports.
    /// </summary>
    public async Task<(CadesValidationView View, CliOutcome? Outcome)> ValidateWithCliAsync(string signatureId, string? dataId, ValidationSettings settings,
        CancellationToken cancellationToken = default)
    {
        var signature = documents.Get(signatureId);
        byte[]? data = dataId is null ? null : documents.Get(dataId).Content;
        var structure = CadesInspector.Inspect(signatureId, signature.FileName, signature.Content);
        var code = ValidationCode(settings, structure.IsDetached);
        var watch = Stopwatch.StartNew();
        if (structure.IsDetached && data is null && structure.Error is null)
        {
            return (new CadesValidationView("Indeterminate", [], [L.T("The signature is detached: choose the data it signed to check its integrity.")], structure, 0, code), null);
        }

        var inputs = new Dictionary<string, byte[]> { [SignatureFile] = signature.Content };
        if (structure.IsDetached && data is not null)
        {
            inputs[DataFile] = data;
        }

        var outcome = await CliValidation.RunAsync(code.CliCommands[0], inputs, validation.CliFiles(settings), cancellationToken);
        if (!outcome.Success || CliValidation.Parse<CliCadesOutput>(outcome.ValidationJson) is not { } output)
        {
            return (new CadesValidationView("Invalid", [], [outcome.Error ?? L.T("The CLI printed no validation result.")], structure, watch.ElapsedMilliseconds, code), outcome);
        }

        var signers = output.Signatures.Select(s => Signer(Verdict(s))).ToList();
        IReadOnlyList<string> errors = output.ReportErrors ?? [];
        return (new CadesValidationView(Overall(signers, errors), signers, errors, structure, watch.ElapsedMilliseconds, code), outcome);
    }

    private static string Overall(IReadOnlyList<CadesSignerReport> signers, IReadOnlyList<string> errors) =>
        errors.Count > 0 || signers.Count == 0 ? "Invalid"
            : Flatten(signers).All(s => s.Indication == "Valid") ? "Valid"
            : Flatten(signers).Any(s => s.Indication == "Invalid") ? "Invalid"
            : "Indeterminate";

    /// <summary>The verdict on a signer the library validated, with its countersignatures (<c>signer-1.1</c>…).</summary>
    private static CadesVerdict Verdict(CadesSignerValidationResult s, string id)
    {
        var r = s.Result;
        return new CadesVerdict(s.Index, CadesInspector.SimpleName(r.SignerCertificate), r.Indication.ToString(), ValidationService.SubIndicationName(r.SubIndication),
            r.SigningTime, r.IsIntegrityValid, r.IsSignatureValid, r.IsCertificateChainValid, r.HasValidTimestamp, r.IsTsaTrusted,
            r.HasValidContentTimestamp, r.ContentTimestampTime, r.IsLtvDataValid, r.HasValidEscTimestamp, r.HasValidArchiveTimestamp,
            r.IsNotRevoked, r.RevocationSource.ToString(), r.Constraints, r.Errors, r.Warnings,
            [.. s.CounterSignatures.Select((c, i) => Verdict(c, $"{id}.{i + 1}"))])
        {
            Source = new Reports.ReportSource(r.ToReportEntry(id), []),
        };
    }

    /// <summary>The verdict on a signer the CLI validated, with its countersignatures.</summary>
    private static CadesVerdict Verdict(CliCadesSigner s) => new(
        s.Index, s.Signer, s.Indication, s.SubIndication, s.SigningTime, s.IsIntegrityValid, s.IsSignatureValid, s.IsCertificateChainValid,
        s.HasValidTimestamp, s.IsTsaTrusted, s.HasValidContentTimestamp, s.ContentTimestampTime, s.IsLtvDataValid, s.HasValidEscTimestamp,
        s.HasValidArchiveTimestamp, s.NotRevoked, s.RevocationSource ?? "", CliValidation.Constraints(s.Constraints), s.Errors ?? [], s.Warnings ?? [],
        [.. (s.CounterSignatures ?? []).Select(Verdict)]);

    private static IEnumerable<CadesSignerReport> Flatten(IEnumerable<CadesSignerReport> signers) =>
        signers.SelectMany(s => new[] { s }.Concat(Flatten(s.CounterSignatures)));

    /// <summary>One signer's report, with its countersignatures nested, whichever validated it (the library or the CLI).</summary>
    private static CadesSignerReport Signer(CadesVerdict v)
    {
        static string Status(bool? ok) => ok switch { true => "pass", false => "fail", null => "n/a" };
        var checks = new List<CheckRow>
        {
            new("integrity", L.T("Integrity (message digest)"), Status(v.IntegrityValid), v.IntegrityValid
                ? L.T("The signed content matches the message-digest attribute.")
                : L.T("The content does not match the message-digest attribute.")),
            new("signature", L.T("Signature value"), Status(v.SignatureValid), null),
            new("chain", L.T("Certificate chain"), Status(v.ChainValid), null),
            new("timestamp", L.T("Signature timestamp"), Status(v.HasValidTimestamp), v.TsaTrusted is { } trusted ? (trusted ? L.T("TSA trusted.") : L.T("TSA not trusted.")) : null),
            new("contentTimestamp", L.T("Content timestamp"), Status(v.HasValidContentTimestamp),
                v.ContentTimestampTime?.ToString("yyyy-MM-dd HH:mm:ss zzz", CultureInfo.InvariantCulture)),
            new("ltv", L.T("Validation data (certificate and revocation values)"), Status(v.LtvDataValid), null),
            new("escTimestamp", L.T("CAdES-C timestamp (escTimeStamp)"), Status(v.HasValidEscTimestamp), null),
            new("archive", L.T("Archive timestamp"), Status(v.HasValidArchiveTimestamp), null),
            ValidationService.RevocationRow(v.NotRevoked, v.RevocationSource),
        };
        checks.AddRange(ValidationService.PolicyRows(v.Constraints));
        // The validator's indication, made INVALID by a timestamp that does not verify (not part of the indication).
        bool brokenTimestamp = v.HasValidTimestamp == false || v.HasValidArchiveTimestamp == false || v.HasValidEscTimestamp == false || v.HasValidContentTimestamp == false;
        string indication = brokenTimestamp ? "Invalid" : v.Indication;
        return new CadesSignerReport(v.Index, v.Signer, indication,
            v.SigningTime?.ToString("yyyy-MM-dd HH:mm:ss zzz", CultureInfo.InvariantCulture),
            [.. checks.Where(c => c.Status != "n/a" || c.Id is "integrity" or "signature" or "chain")], v.Errors, v.Warnings,
            [.. v.CounterSignatures.Select(Signer)], v.SubIndication, ValidationService.Findings(v.Constraints))
        {
            Source = v.Source,
        };
    }

    /// <summary>The data file a generated command signs, and the existing signature it co-signs or countersigns.</summary>
    internal const string DataFile = "document";

    internal const string SignatureFile = "signature.p7s";

    private CodeSnippets ValidationCode(ValidationSettings settings, bool detached)
    {
        bool sandboxRoot = settings.Trust.Contains(TrustChoice.Sandbox);
        var sb = new StringBuilder("using SimpleSign.CAdES;\nusing SimpleSign.Core.Validation;\n" + (settings.PolicyId is null ? "" : "using SimpleSign.Core.Policies;\n"));
        sb.Append("\nvar validator = new CadesSignatureValidator(new ValidationOptions\n{\n");
        sb.Append(CultureInfo.InvariantCulture, $"    TrustSystemRoots = {(settings.Trust.Contains(TrustChoice.System) ? "true" : "false")},\n");
        if (sandboxRoot || settings.CustomRootUploadIds.Count > 0)
        {
            sb.Append("    TrustedRoots = [root], // X509CertificateLoader.LoadCertificateFromFile(\"root.cer\")\n");
        }

        foreach (string option in ValidationService.TrustedListOptionsCode(settings))
        {
            sb.Append("    ").Append(option).Append(option.StartsWith("//", StringComparison.Ordinal) ? "\n" : ",\n");
        }

        foreach (string option in ValidationService.PolicyOptionsCode(settings))
        {
            sb.Append("    ").Append(option).Append(",\n");
        }

        sb.Append("});\n");

        sb.Append("\nCadesValidationReport report = validator.ValidateAll(\n    File.ReadAllBytes(\"signature.p7s\"),\n");
        sb.Append(detached ? "    File.ReadAllBytes(\"document\") /* the signed data: the signature is detached */" : "    null /* enveloped: the content is inside */");
        sb.Append(");\n");
        sb.Append("\nforeach (var signer in report.Signers)\n{\n    Console.WriteLine($\"#{signer.Index}: {(signer.IsValid ? \"valid\" : \"not valid\")}\");\n");
        sb.Append("    foreach (var error in signer.Result.Errors) Console.WriteLine($\"  ✕ {error}\");\n");
        sb.Append("    foreach (var counter in signer.CounterSignatures) Console.WriteLine($\"  countersignature #{counter.Index}: {counter.IsValid}\");\n}\n");

        var line = new CliLine("cades", "validate", SignatureFile);
        if (detached)
        {
            line.Add("--data", DataFile);
        }

        if (settings.Level >= SimpleSign.Core.Validation.ValidationLevel.LongTermData)
        {
            line.Add("--check-revocation");
        }

        ValidationService.ValidationCli(line, settings, sandbox);
        return new CodeSnippets(sb.ToString(), line.ToString(), []) { CliCommands = [line] };
    }

    internal static string OutputName(CadesOptions o) =>
        (o.Operation switch { CadesOperation.CoSign => "cosigned", CadesOperation.CounterSign => "countersigned", _ => "signed" })
        + (o.ContentType == CadesContentChoice.Enveloped ? ".p7m" : ".p7s");

    private static string LevelName(AdesBaselineLevel level) => level switch
    {
        AdesBaselineLevel.Basic => "B-B",
        AdesBaselineLevel.Timestamped => "B-T",
        AdesBaselineLevel.LongTerm => "B-LT",
        _ => "B-LTA",
    };

    private static CadesSignResult Failure(CadesOptions o, CadesOptionsReport report, string error, string type, CodeSnippets code) =>
        new(false, error, type, null, null, 0, report.EffectiveLevel, null, false, false, false, [], 0, null, code, report.Issues);
}

/// <summary>The <c>CadesSigner</c> builder calls for the options, each with its C#.</summary>
internal sealed class CadesPlan
{
    private readonly CadesOptions _o;
    private readonly PlanContext _context;
    private readonly List<(string Code, Func<CadesSignerBuilder, CadesSignerBuilder> Apply)> _steps = [];

    public CadesPlan(CadesOptions o, PlanContext context)
    {
        _o = o;
        _context = context;
        var credential = context.Credential;
        string credentialCode = context.CredentialCode();
        _steps.Add(credential.External is { } external
            ? (credentialCode, b => b.WithExternalSigner(credential.Certificate, external, credential.Chain))
            : (credentialCode, b => b.WithCertificate(credential.Certificate, credential.Chain)));
        if (context.IsSandbox)
        {
            _steps.Add((context.HttpCode, b => b.WithHttpClientProvider(context.Http)));
        }

        if (o.Operation == CadesOperation.Sign && o.ContentType == CadesContentChoice.Enveloped)
        {
            _steps.Add((".WithContentType(CadesContentType.Enveloped) // .p7m: the data goes inside", b => b.WithContentType(CadesContentType.Enveloped)));
        }

        var hash = SigningPlan.ToHash(o.Hash);
        if (hash != System.Security.Cryptography.HashAlgorithmName.SHA256)
        {
            _steps.Add(($".WithHashAlgorithm(HashAlgorithmName.{hash.Name})", b => b.WithHashAlgorithm(hash)));
        }

        var signingPolicy = PolicyUploads.Signing(o.SigningPolicyId, context.Documents);
        if (signingPolicy.Error is { } policyError)
        {
            throw new ArgumentException(L.T("The signing policy cannot be read: {0}", policyError));
        }

        if (signingPolicy.Uploaded)
        {
            _steps.Add((PolicyUploads.SigningCode(signingPolicy), b => b.WithSigningPolicy(signingPolicy.Policy)));
        }

        var controls = context.Controls;
        if (controls.TrustCode() is { } trustCode)
        {
            _steps.Add((trustCode, b => b.WithTrustAnchors([.. controls.Anchors])));
        }

        if (controls.Audit is { } audit)
        {
            _steps.Add((controls.AuditCode()!, b => b.WithAuditSink(audit)));
        }

        if (credential.Facts.KeyAlgorithm == "RSA" && o.Padding == RsaPadding.Pss)
        {
            _steps.Add((".WithSignatureAlgorithm(Oids.RsaPss) // RSASSA-PSS, salt = hash length", b => b.WithSignatureAlgorithm(Oids.RsaPss)));
        }

        if (o.SigningTime is { } time)
        {
            _steps.Add(($".WithSigningTime(DateTimeOffset.Parse(\"{time:O}\"))", b => b.WithSigningTime(time)));
        }

        if (o.Commitment is { } commitmentName)
        {
            var commitment = Enum.Parse<CommitmentType>(commitmentName);
            _steps.Add(($".WithCommitmentType(CommitmentType.{commitment})", b => b.WithCommitmentType(commitment)));
        }

        if (o.ContentTimestamp)
        {
            var contentTsa = context.BuildTimestamp(o.Timestamp, "tsa");
            _steps.Add((".WithContentTimestamp(tsa) // asked before signing: the content existed at that time", b => b.WithContentTimestamp(contentTsa)));
        }

        AddSignerAndContentAttributes();
        AddType();
        if (!string.IsNullOrWhiteSpace(o.OperationId))
        {
            _steps.Add(($".WithOperationId({SigningPlan.Str(o.OperationId)})", b => b.WithOperationId(o.OperationId!)));
        }
    }

    public IEnumerable<(string Code, Func<CadesSignerBuilder, CadesSignerBuilder> Apply)> Steps => _steps;

    private void AddSignerAndContentAttributes()
    {
        if (_o.SignerCountry is not null || _o.SignerLocality is not null || _o.SignerPostalAddress.Count > 0)
        {
            var location = new CadesSignerLocation
            {
                CountryName = _o.SignerCountry,
                LocalityName = _o.SignerLocality,
                PostalAddress = _o.SignerPostalAddress,
            };
            var fields = new List<string>();
            SigningPlan.AddField(fields, "CountryName", location.CountryName);
            SigningPlan.AddField(fields, "LocalityName", location.LocalityName);
            if (location.PostalAddress.Count > 0)
            {
                fields.Add($"PostalAddress = [{string.Join(", ", location.PostalAddress.Select(SigningPlan.Str))}]");
            }

            _steps.Add(($".WithSignerLocation(new CadesSignerLocation {{ {string.Join(", ", fields)} }})", b => b.WithSignerLocation(location)));
        }

        if (_o.SignerRoles.Count > 0)
        {
            var roles = _o.SignerRoles;
            _steps.Add(($".WithSignerRoles([{string.Join(", ", roles.Select(SigningPlan.Str))}])", b => b.WithSignerRoles(roles)));
        }

        if (!string.IsNullOrEmpty(_o.AttributeCertificateId))
        {
            byte[] attributeCertificate = _context.Upload(_o.AttributeCertificateId, "attributeCertificate").Content;
            _steps.Add((".WithAttributeCertificates([attributeCertificate]) // embedded as given, not verified", b => b.WithAttributeCertificates([attributeCertificate])));
        }

        if (!string.IsNullOrEmpty(_o.SignedAssertionId))
        {
            var assertion = CadesSignedAssertion.Saml(_context.Upload(_o.SignedAssertionId, "samlAssertion").Content);
            _steps.Add((".WithSignedAssertions([CadesSignedAssertion.Saml(samlAssertion)]) // embedded as given, not verified", b => b.WithSignedAssertions([assertion])));
        }

        if (_o.MimeType is { } mimeType)
        {
            _steps.Add(($".WithMimeType({SigningPlan.Str(mimeType)})", b => b.WithMimeType(mimeType)));
        }

        if (_o.ContentDescription is { } description)
        {
            var hints = new CadesContentHints { Description = description };
            _steps.Add(($".WithContentHints(new CadesContentHints {{ Description = {SigningPlan.Str(description)} }}) // content type: id-data", b => b.WithContentHints(hints)));
        }
    }

    private void AddType()
    {
        if (_o.Kind == CadesKind.CustomPolicy)
        {
            string? uri = SigningPlan.Blank(_o.PolicyUri);
            if (string.IsNullOrEmpty(_o.PolicyDocumentId))
            {
                _steps.Add(($".WithSignaturePolicy({SigningPlan.Str(_o.PolicyOid)}{(uri is null ? "" : ", " + SigningPlan.Str(uri))})", b => b.WithSignaturePolicy(_o.PolicyOid, uri)));
            }
            else
            {
                // With the document at hand the policy carries its hash, which is what lets the store be added.
                var uploaded = _context.BuildUploadedPolicy(_o.PolicyOid, uri, _o.PolicyDocumentId, _o.PolicySpecification);
                _steps.Add((uploaded.PolicyCode, b => b.WithSignaturePolicy(uploaded.Policy)));
                _steps.Add((uploaded.StoreCode, b => b.WithSignaturePolicyStore(uploaded.Store)));
            }
        }

        string ltv = _context.LongTermCode(_o.RevocationPreference);
        var longTerm = _context.BuildLongTerm(_o.RevocationPreference);
        switch (_o.Level)
        {
            case BaselineLevel.BT:
                var tsa = _context.BuildTimestamp(_o.Timestamp, "tsa");
                _steps.Add((".WithLevel(AdesBaselineProfile.Timestamped(tsa))", b => b.WithLevel(AdesBaselineProfile.Timestamped(tsa))));
                break;
            case BaselineLevel.BLT:
                var ltTsa = _context.BuildTimestamp(_o.Timestamp, "tsa");
                _steps.Add(($".WithLevel(AdesBaselineProfile.LongTerm(tsa, {ltv}))", b => b.WithLevel(AdesBaselineProfile.LongTerm(ltTsa, longTerm))));
                break;
            case BaselineLevel.BLTA:
                var ltaTsa = _context.BuildTimestamp(_o.Timestamp, "tsa");
                _steps.Add(($".WithLevel(AdesBaselineProfile.Archive(tsa, {ltv}))", b => b.WithLevel(AdesBaselineProfile.Archive(ltaTsa, longTerm))));
                break;
        }

        if (_o.ExtendedForm != CadesExtendedChoice.None)
        {
            var form = Enum.Parse<CadesExtendedForm>(_o.ExtendedForm.ToString());
            _steps.Add(($".WithExtendedValidationData(CadesExtendedForm.{form})", b => b.WithExtendedValidationData(form)));
        }
    }

    /// <summary>The C# and the <c>simplesign cades sign</c> command.</summary>
    public CodeSnippets Code(CredentialFacts credential)
    {
        var sb = new StringBuilder("using SimpleSign.CAdES;\nusing SimpleSign.Core.Signing;\n\n");
        if (_context.IsSandbox)
        {
            sb.Append("// The SimpleSign Sandbox runs on this machine: sandboxHttp (below) lets the library reach it.\n");
        }

        sb.Append(_o.Operation switch
        {
            CadesOperation.CoSign => "byte[] existing = File.ReadAllBytes(\"signature.p7s\");\n"
                + (_o.ContentType == CadesContentChoice.Detached ? "byte[] data = File.ReadAllBytes(\"document\"); // the content the existing signature signed\n" : ""),
            CadesOperation.CounterSign => "byte[] existing = File.ReadAllBytes(\"signature.p7s\");\n",
            _ => "byte[] data = File.ReadAllBytes(\"document\");\n",
        });
        foreach (string line in _context.Setup.Distinct())
        {
            sb.Append(line).Append('\n');
        }

        sb.Append("\nCadesSigningResult result = await ").Append(_o.Operation switch
        {
            CadesOperation.CoSign => _o.ContentType == CadesContentChoice.Detached ? "CadesSigner.CoSign(existing, data)" : "CadesSigner.CoSign(existing) // the content comes from the .p7m",
            CadesOperation.CounterSign => $"CadesSigner.CounterSign(existing, signerIndex: {_o.SignerIndex})",
            _ => "CadesSigner.Document(data)",
        }).Append('\n');
        foreach (var (code, _) in _steps)
        {
            sb.Append("    ").Append(code).Append('\n');
        }

        sb.Append("    .SignWithDetailsAsync();\n\n");
        sb.Append(CultureInfo.InvariantCulture, $"File.WriteAllBytes(\"{OutputName()}\", result.SignedArtifact);\n");
        sb.Append("Console.WriteLine($\"Requested {result.RequestedLevel}, achieved {result.AchievedLevel}\");\n");

        var cli = new CliLine("cades", "sign", _o.Operation == CadesOperation.Sign ? CadesRunner.DataFile : CadesRunner.SignatureFile).Add("--output", OutputName());
        var notes = new List<string>();
        CodeGenerator.CliCredential(credential, cli, notes);
        switch (_o.Operation)
        {
            case CadesOperation.CoSign:
                cli.Add("--cosign");
                if (_o.ContentType == CadesContentChoice.Detached)
                {
                    cli.Add("--data", CadesRunner.DataFile);
                }

                break;
            case CadesOperation.CounterSign:
                cli.Add("--countersign");
                if (_o.SignerIndex != 0)
                {
                    cli.Add("--signer-index", _o.SignerIndex.ToString(CultureInfo.InvariantCulture));
                }

                break;
            default:
                if (_o.ContentType == CadesContentChoice.Enveloped)
                {
                    cli.Add("--content-type", "enveloped");
                }

                break;
        }

        if (_o.Level != BaselineLevel.BB)
        {
            _context.CliTimestamp(cli, _o.Timestamp);
            cli.Add("--level", _o.Level switch { BaselineLevel.BT => "timestamped", BaselineLevel.BLT => "longterm", _ => "archive" });
            if (_o.RevocationPreference == RevocationPreference.CrlFirst && _o.Level >= BaselineLevel.BLT)
            {
                cli.Add("--revocation-preference", "crl");
            }
        }
        else if (_o.ContentTimestamp)
        {
            _context.CliTimestamp(cli, _o.Timestamp);
        }

        if (_o.Kind == CadesKind.CustomPolicy)
        {
            cli.Add("--policy-oid", _o.PolicyOid ?? "").AddIf("--policy-uri", SigningPlan.Blank(_o.PolicyUri));
            if (!string.IsNullOrEmpty(_o.PolicyDocumentId))
            {
                cli.AddIf("--policy-document", _context.FileName(_o.PolicyDocumentId)).AddIf("--policy-specification", _o.PolicySpecification);
            }
        }

        if (_o.ExtendedForm != CadesExtendedChoice.None)
        {
            cli.Add("--extended-form", CodeGenerator.ExtendedForm(_o.ExtendedForm.ToString()));
        }

        if (_o.Hash != HashChoice.Sha256)
        {
            cli.Add("--hash", SigningPlan.HashName(_o.Hash));
        }

        if (_o.Padding == RsaPadding.Pss && credential.KeyAlgorithm == "RSA")
        {
            cli.Add("--signature-algorithm", "rsassa-pss");
        }

        if (_o.SigningTime is { } time)
        {
            cli.Add("--signing-time", time.ToString("O", CultureInfo.InvariantCulture));
        }

        if (_o.SigningPolicyId is not null)
        {
            cli.Add("--signing-policy", PolicyUploads.SigningFileName);
        }

        _context.Controls.Cli(cli);

        cli.AddIf("--commitment", _o.Commitment);
        AddSignedAttributeArgs(cli);
        cli.AddIf("--operation-id", _o.OperationId);
        _context.CliNetwork(cli);
        return new CodeSnippets(sb.ToString(), cli.ToString(), notes) { CliCommands = [cli] };
    }

    /// <summary>The flags of the signed attributes beyond the baseline: location, roles, content description and timestamp.</summary>
    private void AddSignedAttributeArgs(CliLine cli)
    {
        cli.AddIf("--signer-country", _o.SignerCountry).AddIf("--signer-locality", _o.SignerLocality);
        foreach (string address in _o.SignerPostalAddress)
        {
            cli.AddIf("--signer-postal-address", address);
        }

        foreach (string role in _o.SignerRoles)
        {
            cli.AddIf("--signer-role", role);
        }

        if (!string.IsNullOrEmpty(_o.AttributeCertificateId))
        {
            cli.AddIf("--attribute-certificate", _context.FileName(_o.AttributeCertificateId));
        }

        if (!string.IsNullOrEmpty(_o.SignedAssertionId))
        {
            cli.AddIf("--signed-assertion", _context.FileName(_o.SignedAssertionId));
        }

        cli.AddIf("--mime-type", _o.MimeType).AddIf("--content-description", _o.ContentDescription);
        if (_o.ContentTimestamp)
        {
            cli.Add("--content-timestamp");
        }
    }

    private string OutputName() => CadesRunner.OutputName(_o);
}

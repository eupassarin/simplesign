using System.Diagnostics;
using System.Globalization;
using System.Text;
using System.Xml;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Signing;
using SimpleSign.TestBench.Cades;
using SimpleSign.TestBench.Credentials;
using SimpleSign.TestBench.Documents;
using SimpleSign.TestBench.Localization;
using SimpleSign.TestBench.Runs;
using SimpleSign.TestBench.Sandbox;
using SimpleSign.TestBench.Signing;
using SimpleSign.TestBench.Validation;
using SimpleSign.XAdES;

namespace SimpleSign.TestBench.Xml;

/// <summary>The verdict for one XML signature.</summary>
public sealed record XmlSignatureReport(
    int Index,
    string? Reference,
    string? Signer,
    string Indication,
    string? Level,
    string? SigningTime,
    IReadOnlyList<CheckRow> Checks,
    IReadOnlyList<string> Errors,
    IReadOnlyList<string> Warnings,
    string? SubIndication = null,
    IReadOnlyList<FindingView>? Findings = null)
{
    /// <summary>The library's report entry of this signature and the certificates next to it, for the SimpleSign report (not sent to the UI).</summary>
    [System.Text.Json.Serialization.JsonIgnore]
    public Reports.ReportSource? Source { get; init; }
}

/// <summary>The verdict on one XML signature, from the library's result or from the JSON of <c>simplesign xades validate</c>.</summary>
internal sealed record XmlVerdict(
    string? SignatureId,
    string? Signer,
    string Indication,
    string? SubIndication,
    string? DetectedLevel,
    DateTimeOffset? SigningTime,
    bool SignatureValid,
    bool IntegrityValid,
    bool ChainValid,
    bool? HasValidSignatureTimeStamp,
    bool? TsaTrusted,
    bool? HasValidDataObjectsTimeStamp,
    DateTimeOffset? DataObjectsTimeStampTime,
    bool? HasValidCompleteReferences,
    bool? HasValidSigAndRefsTimeStamp,
    bool? LtvDataValid,
    bool? HasValidArchiveTimeStamp,
    bool? NotRevoked,
    string RevocationSource,
    IReadOnlyList<SimpleSign.Core.Validation.ValidationConstraintResult> Constraints,
    IReadOnlyList<string> Errors,
    IReadOnlyList<string> Warnings,
    IReadOnlyList<XmlVerdict> CounterSignatures)
{
    /// <summary>The library's report entry, for the SimpleSign report; null from the CLI.</summary>
    public Reports.ReportSource? Source { get; init; }
}

public sealed record XmlValidationView(
    string Overall,
    IReadOnlyList<XmlSignatureReport> Signatures,
    IReadOnlyList<string> Errors,
    string? SignatureXml,
    string DocumentPreview,
    long Ms,
    CodeSnippets Code);

public sealed record XmlSignResult(
    bool Success,
    string? Error,
    string? ErrorType,
    string? OutputId,
    string? FileName,
    long Bytes,
    string RequestedLevel,
    string? AchievedLevel,
    IReadOnlyList<string> Warnings,
    long SignMs,
    XmlValidationView? Validation,
    CodeSnippets Code,
    IReadOnlyList<OptionIssue> Issues)
{
    /// <summary>The commands a run through the CLI executed, with their exit codes and output; null for a library run.</summary>
    public IReadOnlyList<CliStep>? Cli { get; init; }

    /// <summary>The reports the CLI's validation wrote; null for a library run.</summary>
    public CliReports? Reports { get; init; }
}

/// <summary>Signs with <c>XadesSigner</c> and validates the result.</summary>
internal sealed class XmlRunner(SandboxEnvironment sandbox, DocumentStore documents, CredentialStore credentials, ValidationService validation)
{
    /// <summary>Whether a Sandbox is connected (its TSAs and signers can be chosen).</summary>
    public bool SandboxConnected => sandbox.IsConnected;

    public XmlFacts? Facts(string? dataId) =>
        dataId is not null && documents.TryGet(dataId, out var file) ? XmlInspector.Inspect(dataId, file!.FileName, file.Content) : null;

    /// <summary>What a XAdES signature with <paramref name="options"/> would do, without making it.</summary>
    internal async Task<RunDescription> DescribeAsync(XmlOptions options, CancellationToken cancellationToken)
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
                code = new XadesPlan(report.Effective, new PlanContext(credential, sandbox, documents) { Controls = controls }).Code(credential.Facts);
            }
            catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or SigningException or HttpRequestException or KeyNotFoundException)
            {
                error = ex.Message;
            }
        }

        return new RunDescription(report.Effective, report.Options, report.Issues, code, error, credential?.Facts);
    }

    public XmlOptionsReport Evaluate(XmlOptions o)
    {
        credentials.TryGet(o.CredentialId, out var credential);
        return XmlCompatibility.Evaluate(o, Facts(o.DataId), credential?.Facts, sandbox.IsConnected, PolicyUploads.Signing(o.SigningPolicyId, documents));
    }

    private readonly CliExecutor _cli = new();

    public Task<XmlSignResult> RunAsync(XmlOptions options, CancellationToken cancellationToken) =>
        RunAsync(options, RunEngines.Library, cancellationToken);

    /// <summary>Signs through the library or, with <see cref="RunEngines.Cli"/>, by running the generated command through the CLI.</summary>
    public async Task<XmlSignResult> RunAsync(XmlOptions options, string engine, CancellationToken cancellationToken)
    {
        var report = Evaluate(options);
        var o = report.Effective;
        if (!report.CanRun)
        {
            return Failure(report, L.T("Fix the issues before signing."), "Validation", new CodeSnippets("", "", []));
        }

        var credential = credentials.Get(o.CredentialId!);
        credential.LastUsed = DateTimeOffset.UtcNow;
        var data = documents.Get(o.DataId!);
        SigningControls controls;
        try
        {
            controls = await SigningControls.ResolveAsync(o.SigningControls, sandbox, cancellationToken);
        }
        catch (Exception ex) when (ex is SigningException or ArgumentException or HttpRequestException)
        {
            return Failure(report, ex.Message, SigningRunner.ErrorTypeOf(ex), new CodeSnippets("", "", []));
        }

        var context = new PlanContext(credential, sandbox, documents) { Controls = controls };
        var watch = Stopwatch.StartNew();
        byte[] signed;
        string? achieved;
        var warnings = new List<string>();
        CodeSnippets code;
        IReadOnlyList<CliStep>? cliSteps = null;
        try
        {
            var plan = new XadesPlan(o, context);
            code = plan.Code(credential.Facts);
            if (engine == RunEngines.Cli)
            {
                if (CliJobs.Unsupported(credential) is { } unsupported)
                {
                    return Failure(report, unsupported, "CliUnsupported", code);
                }

                var jobs = new CliJobs().Credential(credential).Timestamp(o.Timestamp, documents).Uploads(o, o.SigningPolicyId, documents)
                    .File(o.CounterSign ? SignedFile : DataFile, data.Content);
                foreach (var (name, content) in controls.CliFiles())
                {
                    jobs.File(name, content);
                }

                var outcome = await _cli.RunAsync(jobs.Build(code.CliCommands), cancellationToken);
                controls.Report(outcome.AuditTrail);
                if (!outcome.Success)
                {
                    return Failure(report, outcome.Error!, outcome.Json?.ErrorType ?? "Cli", code) with { Cli = outcome.Steps };
                }

                signed = outcome.Output!;
                achieved = outcome.Json?.AchievedLevel ?? report.EffectiveLevel;
                warnings.AddRange(outcome.Json?.Warnings ?? []);
                cliSteps = outcome.Steps;
            }
            else
            {
                var builder = (o.CounterSign ? XadesSigner.CounterSign(data.Content, o.CounterSignatureId) : XadesSigner.Document(data.Content))
                    .WithLogger(RunLog.Logger);
                foreach (var (_, apply) in plan.Steps)
                {
                    builder = apply(builder);
                }

                var result = await builder.SignWithDetailsAsync(cancellationToken);
                signed = result.SignedArtifact;
                achieved = result.AchievedLevel switch
                {
                    AdesBaselineLevel.Basic => "B-B",
                    AdesBaselineLevel.Timestamped => "B-T",
                    AdesBaselineLevel.LongTerm => "B-LT",
                    _ => "B-LTA",
                };
                warnings.AddRange(result.Warnings.Select(w => w.Message));
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return Failure(report, ex.Message, SigningRunner.ErrorTypeOf(ex), FallbackCode(o, context, credential.Facts));
        }
        finally
        {
            if (cliSteps is null && engine != RunEngines.Cli)
            {
                controls.Report(cliTrail: null);
            }
        }

        long signMs = watch.ElapsedMilliseconds;
        string fileName = OutputName(o, data.FileName);
        var output = documents.Add(fileName, signed);
        // Signed through the CLI, validated through it too.
        string? detachedId = o.Form == XadesFormChoice.Detached ? o.DataId : null;
        var settings = o.Validation ?? new ValidationSettings();
        XmlValidationView? view = null;
        CliOutcome? checkedByCli = null;
        if (o.Validate && cliSteps is not null)
        {
            (view, checkedByCli) = await ValidateWithCliAsync(output.Id, detachedId, settings, report.Effective.ExternalObjectId, cancellationToken);
        }
        else if (o.Validate)
        {
            view = await ValidateAsync(output.Id, detachedId, settings, report.Effective.ExternalObjectId, cancellationToken);
        }

        return new XmlSignResult(true, null, null, output.Id, fileName, signed.LongLength, report.EffectiveLevel, achieved, warnings, signMs, view, code, report.Issues)
        {
            Cli = cliSteps is null ? null : [.. cliSteps, .. checkedByCli?.Steps ?? []],
            Reports = checkedByCli is null ? null : CliValidation.Store(checkedByCli, documents, fileName),
        };
    }

    /// <summary>
    /// Validates a signed XML. <paramref name="externalObjectId"/> is a file the signature references
    /// by its file name (an additional external data object), when the caller has it.
    /// </summary>
    public async Task<XmlValidationView> ValidateAsync(string signatureId, string? dataId, ValidationSettings settings, string? externalObjectId = null,
        CancellationToken cancellationToken = default)
    {
        var file = documents.Get(signatureId);
        byte[]? data = dataId is null ? null : documents.Get(dataId).Content;
        var externalObject = externalObjectId is null ? null : documents.Get(externalObjectId);
        var watch = Stopwatch.StartNew();
        string preview = XmlInspector.Preview(file.Content);
        string? signatureXml = XmlInspector.SignatureXml(file.Content);
        try
        {
            XmlInspector.Load(file.Content);
        }
        catch (XmlException ex)
        {
            return new XmlValidationView("Invalid", [], [L.T("The file is not well-formed XML: {0}", ex.Message)], null, preview, 0, new CodeSnippets("", "", []));
        }

        var trust = await validation.TrustAsync(settings, cancellationToken);
        var signatures = await ValidateXadesAsync(file.Content, data, externalObject, trust, cancellationToken);
        return View(signatures, signatureXml, preview, watch.ElapsedMilliseconds, ValidationCode(settings, data is not null));
    }

    /// <summary>
    /// Validates a signed XML through <c>simplesign xades validate</c>: the verdicts are the CLI's. The detached document
    /// and the external data object are given to it as <c>--data</c> or <c>--external-object URI=file</c>.
    /// </summary>
    public async Task<(XmlValidationView View, CliOutcome? Outcome)> ValidateWithCliAsync(string signatureId, string? dataId, ValidationSettings settings,
        string? externalObjectId = null, CancellationToken cancellationToken = default)
    {
        var file = documents.Get(signatureId);
        byte[]? data = dataId is null ? null : documents.Get(dataId).Content;
        var externalObject = externalObjectId is null ? null : documents.Get(externalObjectId);
        var watch = Stopwatch.StartNew();
        string preview = XmlInspector.Preview(file.Content);
        string? signatureXml = XmlInspector.SignatureXml(file.Content);
        try
        {
            XmlInspector.Load(file.Content);
        }
        catch (XmlException ex)
        {
            return (new XmlValidationView("Invalid", [], [L.T("The file is not well-formed XML: {0}", ex.Message)], null, preview, 0, new CodeSnippets("", "", [])), null);
        }

        var code = ValidationCode(settings, data is not null);
        var command = code.CliCommands[0];
        var inputs = new Dictionary<string, byte[]> { [SignedFile] = file.Content };
        if (externalObject is not null)
        {
            // Every external reference by URI, as files next to the signature: --external-object replaces --data.
            command = new CliLine([.. command.Args.Where((a, i) => !(a == "--data" || (i > 0 && command.Args[i - 1] == "--data")))]);
            int n = 0;
            foreach (var (uri, content) in ExternalData(file.Content, data, externalObject))
            {
                string name = $"external-{++n}";
                inputs[name] = content;
                command.Add("--external-object", $"{uri}={name}");
            }
        }
        else if (data is not null)
        {
            inputs[DataFile] = data;
        }

        var outcome = await CliValidation.RunAsync(command, inputs, validation.CliFiles(settings), cancellationToken);
        if (!outcome.Success || CliValidation.Parse<CliXadesOutput>(outcome.ValidationJson) is not { } output)
        {
            return (new XmlValidationView("Invalid", [], [outcome.Error ?? L.T("The CLI printed no validation result.")], signatureXml, preview, watch.ElapsedMilliseconds, code), outcome);
        }

        return (View(Reports(output.Signatures.Select(Verdict)), signatureXml, preview, watch.ElapsedMilliseconds, code), outcome);
    }

    private static XmlValidationView View(List<XmlSignatureReport> signatures, string? signatureXml, string preview, long ms, CodeSnippets code)
    {
        string overall = signatures.Count == 0 ? "Invalid"
            : signatures.All(s => s.Indication == "Valid") ? "Valid"
            : signatures.Any(s => s.Indication == "Invalid") ? "Invalid"
            : "Indeterminate";
        var errors = signatures.Count == 0 ? new List<string> { L.T("No ds:Signature in this XML.") } : [];
        return new XmlValidationView(overall, signatures, errors, signatureXml, preview, ms, code);
    }

    private async Task<List<XmlSignatureReport>> ValidateXadesAsync(byte[] xml, byte[]? data, StoredFile? externalObject, ValidationTrust trust,
        CancellationToken cancellationToken)
    {
        var validator = new XadesSignatureValidator(trust.Options, logger: RunLog.Logger, chainRevocationChecker: validation.RevocationChecker());
        // An external additional data object is found by the URI of its reference, which is its file name.
        var results = externalObject is null
            ? await validator.ValidateAllAsync(xml, null, data, cancellationToken)
            : await validator.ValidateAllAsync(xml, null, ExternalData(xml, data, externalObject), cancellationToken);
        return Reports(results.Select(Verdict));
    }

    /// <summary>The verdict on a signature the library validated, with its countersignatures.</summary>
    private static XmlVerdict Verdict(XadesValidationResult r) => new(
        r.SignatureId, CadesInspector.SimpleName(r.SignerCertificate), r.Indication.ToString(), ValidationService.SubIndicationName(r.SubIndication),
        r.DetectedLevel.ToString(), r.SigningTime, r.IsSignatureValid, r.IsIntegrityValid, r.IsCertificateChainValid, r.HasValidSignatureTimeStamp, r.IsTsaTrusted,
        r.HasValidDataObjectsTimeStamp, r.DataObjectsTimeStampTime, r.HasValidCompleteReferences, r.HasValidSigAndRefsTimeStamp, r.IsLtvDataValid,
        r.HasValidArchiveTimeStamp, r.IsNotRevoked, r.RevocationSource.ToString(), r.Constraints, r.Errors, r.Warnings,
        [.. r.CounterSignatures.Select(Verdict)])
    {
        Source = new Reports.ReportSource(r.ToReportEntry(), []),
    };

    /// <summary>The verdict on a signature the CLI validated, with its countersignatures.</summary>
    private static XmlVerdict Verdict(CliXadesSignature s) => new(
        s.Id, s.Signer, s.Indication, s.SubIndication, s.DetectedLevel, s.SigningTime, s.IsSignatureValid, s.IsIntegrityValid, s.IsCertificateChainValid,
        s.HasValidSignatureTimeStamp, s.IsTsaTrusted, s.HasValidDataObjectsTimeStamp, s.DataObjectsTimeStampTime, s.HasValidCompleteReferences,
        s.HasValidSigAndRefsTimeStamp, s.IsLtvDataValid, s.HasValidArchiveTimeStamp, s.NotRevoked, s.RevocationSource ?? "",
        CliValidation.Constraints(s.Constraints), s.Errors ?? [], s.Warnings ?? [], [.. (s.CounterSignatures ?? []).Select(Verdict)]);

    /// <summary>The reports of the signatures, whichever validated them: a countersignature right after the signature it signs, saying so.</summary>
    private static List<XmlSignatureReport> Reports(IEnumerable<XmlVerdict> verdicts)
    {
        static string Status(bool? ok) => ok switch { true => "pass", false => "fail", null => "n/a" };
        var reports = new List<XmlSignatureReport>();
        foreach (var verdict in verdicts)
        {
            Report(verdict, countersigned: null);
        }

        void Report(XmlVerdict v, string? countersigned)
        {
            int i = reports.Count;
            var checks = new List<CheckRow>
            {
                new("signature", L.T("Signature value and references"), Status(v.SignatureValid && v.IntegrityValid), null),
                new("chain", L.T("Certificate chain"), Status(v.ChainValid), null),
                new("timestamp", L.T("Signature timestamp"), Status(v.HasValidSignatureTimeStamp), v.TsaTrusted is { } trusted ? (trusted ? L.T("TSA trusted.") : L.T("TSA not trusted.")) : null),
                new("dataObjectsTimestamp", L.T("Data objects timestamp"), Status(v.HasValidDataObjectsTimeStamp),
                    v.DataObjectsTimeStampTime?.ToString("yyyy-MM-dd HH:mm:ss zzz", CultureInfo.InvariantCulture)),
                new("references", L.T("Complete references (XAdES-C)"), Status(v.HasValidCompleteReferences), null),
                new("sigAndRefs", L.T("SigAndRefsTimeStamp (XAdES-X)"), Status(v.HasValidSigAndRefsTimeStamp), null),
                new("ltv", L.T("Validation data (certificate and revocation values)"), Status(v.LtvDataValid), null),
                new("archive", L.T("Archive timestamp"), Status(v.HasValidArchiveTimeStamp), null),
                ValidationService.RevocationRow(v.NotRevoked, v.RevocationSource),
            };
            checks.AddRange(ValidationService.PolicyRows(v.Constraints));
            bool invalid = !v.SignatureValid || !v.IntegrityValid || v.HasValidSignatureTimeStamp == false || v.HasValidArchiveTimeStamp == false
                || v.HasValidSigAndRefsTimeStamp == false || v.HasValidCompleteReferences == false || v.HasValidDataObjectsTimeStamp == false;
            string indication = invalid ? "Invalid" : v.Indication;
            string? reference = countersigned is null ? v.SignatureId : L.T("{0} (countersignature of {1})", v.SignatureId ?? "-", countersigned);
            reports.Add(new XmlSignatureReport(i, reference, v.Signer, indication,
                v.DetectedLevel switch
                {
                    nameof(AdesBaselineLevel.Basic) => "B-B",
                    nameof(AdesBaselineLevel.Timestamped) => "B-T",
                    nameof(AdesBaselineLevel.LongTerm) => "B-LT",
                    _ => "B-LTA",
                },
                v.SigningTime?.ToString("yyyy-MM-dd HH:mm:ss zzz", CultureInfo.InvariantCulture),
                [.. checks.Where(c => c.Status != "n/a" || c.Id is "signature" or "chain")], v.Errors, v.Warnings,
                v.SubIndication, ValidationService.Findings(v.Constraints))
            {
                Source = v.Source,
            });
            foreach (var counter in v.CounterSignatures)
            {
                Report(counter, v.SignatureId ?? "-");
            }
        }

        return reports;
    }

    /// <summary>
    /// The content of every external reference by URI: the additional data object under its file
    /// name, and the detached document under every other external URI.
    /// </summary>
    private static Dictionary<string, byte[]> ExternalData(byte[] xml, byte[]? data, StoredFile externalObject)
    {
        var byUri = new Dictionary<string, byte[]>(StringComparer.Ordinal) { [externalObject.FileName] = externalObject.Content };
        if (data is null)
        {
            return byUri;
        }

        var doc = XmlInspector.Load(xml);
        foreach (XmlElement reference in doc.GetElementsByTagName("Reference", "http://www.w3.org/2000/09/xmldsig#"))
        {
            string uri = reference.GetAttribute("URI");
            if (uri.Length > 0 && uri[0] != '#')
            {
                byUri.TryAdd(uri, data);
            }
        }

        return byUri;
    }

    private static string OutputName(XmlOptions o, string input)
    {
        string name = Path.GetFileNameWithoutExtension(input);
        return o.Form == XadesFormChoice.Detached ? name + "-signature.xml"
            : o.Form == XadesFormChoice.Enveloping ? name + "-enveloping.xml"
            : name + "-signed.xml";
    }

    private static CodeSnippets FallbackCode(XmlOptions o, PlanContext context, CredentialFacts credential)
    {
        try
        {
            return new XadesPlan(o, context).Code(credential);
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException)
        {
            return new CodeSnippets("", "", []);
        }
    }

    /// <summary>The XML a generated command signs, and the signed XML it writes, countersigns or validates.</summary>
    internal const string DataFile = "document.xml";

    internal const string SignedFile = "signed.xml";

    private CodeSnippets ValidationCode(ValidationSettings settings, bool detached)
    {
        bool customRoot = settings.Trust.Contains(TrustChoice.Sandbox) || settings.CustomRootUploadIds.Count > 0;
        var sb = new StringBuilder("using SimpleSign.XAdES;\nusing SimpleSign.Core.Validation;\n" + (settings.PolicyId is null ? "" : "using SimpleSign.Core.Policies;\n") + "\nvar validator = new XadesSignatureValidator(new ValidationOptions\n{\n");
        sb.Append(CultureInfo.InvariantCulture, $"    TrustSystemRoots = {(settings.Trust.Contains(TrustChoice.System) ? "true" : "false")},\n");
        if (customRoot)
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

        sb.Append("});\n\nIReadOnlyList<XadesValidationResult> results = validator.ValidateAll(\n    File.ReadAllBytes(\"signed.xml\")");
        sb.Append(detached ? ",\n    trustAnchors: null,\n    originalData: File.ReadAllBytes(\"document.xml\")); // detached\n" : ");\n");
        sb.Append("foreach (var r in results) Console.WriteLine($\"{r.SignatureId}: {(r.IsValid ? \"valid\" : string.Join(\"; \", r.Errors))} ({r.DetectedLevel})\");\n");
        var line = new CliLine("xades", "validate", SignedFile);
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

    private static XmlSignResult Failure(XmlOptionsReport report, string error, string type, CodeSnippets code) =>
        new(false, error, type, null, null, 0, report.EffectiveLevel, null, [], 0, null, code, report.Issues);
}

/// <summary>The <c>XadesSigner</c> builder calls for the options, each with its C#.</summary>
internal sealed class XadesPlan
{
    private readonly XmlOptions _o;
    private readonly PlanContext _context;
    private readonly List<(string Code, Func<XadesSignerBuilder, XadesSignerBuilder> Apply)> _steps = [];

    public XadesPlan(XmlOptions o, PlanContext context)
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

        if (o.Form != XadesFormChoice.Enveloped)
        {
            var form = Enum.Parse<XadesForm>(o.Form.ToString());
            _steps.Add(($".WithForm(XadesForm.{form})", b => b.WithForm(form)));
        }

        if (o.Form == XadesFormChoice.Detached)
        {
            _steps.Add(($".WithDataUri({SigningPlan.Str(o.DataUri)}) // where the validator will find the data", b => b.WithDataUri(o.DataUri)));
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

        if (o.DataObjectsTimestamp)
        {
            var dataTsa = context.BuildTimestamp(o.Timestamp, "tsa");
            _steps.Add((".WithDataObjectsTimestamp(tsa) // asked before signing: the data existed at that time", b => b.WithDataObjectsTimestamp(dataTsa)));
        }

        if (o.EmbeddedObjectId is not null)
        {
            var file = context.Upload(o.EmbeddedObjectId, "attachment");
            var embedded = XadesDataObject.Embedded(file.Content);
            _steps.Add((".WithAdditionalDataObject(XadesDataObject.Embedded(attachment)) // carried inside the signature, as base64", b => b.WithAdditionalDataObject(embedded)));
        }

        if (o.ExternalObjectId is not null)
        {
            var file = context.Upload(o.ExternalObjectId, "externalFile");
            var externalObject = XadesDataObject.External(file.FileName, file.Content);
            _steps.Add(($".WithAdditionalDataObject(XadesDataObject.External({SigningPlan.Str(file.FileName)}, externalFile)) // stays outside; the validator needs it again",
                b => b.WithAdditionalDataObject(externalObject)));
        }

        if (o.AttributeCertificateId is not null)
        {
            byte[] attributeCertificate = context.Upload(o.AttributeCertificateId, "attributeCertificate").Content;
            _steps.Add((".WithAttributeCertificates([attributeCertificate]) // embedded as given, not verified", b => b.WithAttributeCertificates([attributeCertificate])));
        }

        if (o.SignedAssertionId is not null)
        {
            string assertion = Encoding.UTF8.GetString(context.Upload(o.SignedAssertionId, "assertionXml").Content);
            _steps.Add((".WithSignedAssertions([Encoding.UTF8.GetString(assertionXml)]) // embedded as given, not verified", b => b.WithSignedAssertions([assertion])));
        }

        if (o.SignerRoles.Count > 0)
        {
            var roles = o.SignerRoles;
            _steps.Add(($".WithSignerRoles([{string.Join(", ", roles.Select(SigningPlan.Str))}])", b => b.WithSignerRoles(roles)));
        }

        if (!string.IsNullOrWhiteSpace(o.MimeType))
        {
            var format = new DataObjectFormat { MimeType = o.MimeType.Trim() };
            _steps.Add(($".WithDataObjectFormat(new DataObjectFormat {{ MimeType = {SigningPlan.Str(format.MimeType)} }})", b => b.WithDataObjectFormat(format)));
        }

        if (o.PlaceCity is not null || o.PlaceStreet is not null || o.PlaceState is not null || o.PlacePostalCode is not null || o.PlaceCountry is not null)
        {
            var place = new SignatureProductionPlace
            {
                City = o.PlaceCity,
                StreetAddress = o.PlaceStreet,
                StateOrProvince = o.PlaceState,
                PostalCode = o.PlacePostalCode,
                CountryName = o.PlaceCountry,
            };
            var fields = new List<string>();
            SigningPlan.AddField(fields, "City", place.City);
            SigningPlan.AddField(fields, "StreetAddress", place.StreetAddress);
            SigningPlan.AddField(fields, "StateOrProvince", place.StateOrProvince);
            SigningPlan.AddField(fields, "PostalCode", place.PostalCode);
            SigningPlan.AddField(fields, "CountryName", place.CountryName);
            _steps.Add(($".WithSignatureProductionPlace(new SignatureProductionPlace {{ {string.Join(", ", fields)} }})", b => b.WithSignatureProductionPlace(place)));
        }

        if (o.Canonicalization != XadesCanonicalization.Exclusive)
        {
            var canonicalization = o.Canonicalization;
            _steps.Add(($".WithCanonicalization(XadesCanonicalization.{canonicalization}) // SignedInfo and the references", b => b.WithCanonicalization(canonicalization)));
        }

        if (o.SigningCertificateV1)
        {
            _steps.Add((".WithSigningCertificateForm(XadesSigningCertificateForm.V1) // XAdES 1.3.2 SigningCertificate", b => b.WithSigningCertificateForm(XadesSigningCertificateForm.V1)));
        }

        AddType();
        if (!string.IsNullOrWhiteSpace(o.OperationId))
        {
            _steps.Add(($".WithOperationId({SigningPlan.Str(o.OperationId)})", b => b.WithOperationId(o.OperationId!)));
        }
    }

    public IEnumerable<(string Code, Func<XadesSignerBuilder, XadesSignerBuilder> Apply)> Steps => _steps;

    private void AddType()
    {
        if (_o.Kind == XadesKind.CustomPolicy)
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

        if (_o.ExtendedForm != XadesExtendedChoice.None)
        {
            var form = Enum.Parse<XadesExtendedForm>(_o.ExtendedForm.ToString());
            _steps.Add(($".WithExtendedValidationData(XadesExtendedForm.{form})", b => b.WithExtendedValidationData(form)));
        }
    }

    public CodeSnippets Code(CredentialFacts credential)
    {
        var sb = new StringBuilder("using SimpleSign.XAdES;\nusing SimpleSign.Core.Signing;\n\n");
        if (_context.IsSandbox)
        {
            sb.Append("// The SimpleSign Sandbox runs on this machine: sandboxHttp (below) lets the library reach it.\n");
        }

        sb.Append("byte[] xml = File.ReadAllBytes(\"document.xml\");\n");
        foreach (string line in _context.Setup.Distinct())
        {
            sb.Append(line).Append('\n');
        }

        sb.Append(_o.CounterSign
            ? $"\n// xml is the signed document: the countersignature is embedded in the signature it signs.\nXadesSigningResult result = await XadesSigner.CounterSign(xml{(_o.CounterSignatureId is null ? "" : ", " + SigningPlan.Str(_o.CounterSignatureId))})\n"
            : "\nXadesSigningResult result = await XadesSigner.Document(xml)\n");
        foreach (var (code, _) in _steps)
        {
            sb.Append("    ").Append(code).Append('\n');
        }

        sb.Append("    .SignWithDetailsAsync();\n\n");
        sb.Append("File.WriteAllBytes(\"signed.xml\", result.SignedArtifact);\n");
        sb.Append("Console.WriteLine($\"Requested {result.RequestedLevel}, achieved {result.AchievedLevel}\");\n");

        var cli = _o.CounterSign
            ? new CliLine("xades", "sign", XmlRunner.SignedFile).Add("--countersign").Add("--output", "countersigned.xml")
            : new CliLine("xades", "sign", XmlRunner.DataFile).Add("--output", XmlRunner.SignedFile);
        var notes = new List<string>();
        CodeGenerator.CliCredential(credential, cli, notes);
        if (_o.CounterSign)
        {
            cli.AddIf("--countersign-id", _o.CounterSignatureId);
        }
        else if (_o.Form != XadesFormChoice.Enveloped)
        {
            cli.Add("--form", _o.Form.ToString().ToLowerInvariant());
        }

        if (_o.Form == XadesFormChoice.Detached && !_o.CounterSign)
        {
            cli.Add("--data-uri", _o.DataUri ?? "");
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
        else if (_o.DataObjectsTimestamp)
        {
            _context.CliTimestamp(cli, _o.Timestamp);
        }

        if (_o.Kind == XadesKind.CustomPolicy)
        {
            cli.Add("--policy-oid", _o.PolicyOid ?? "").AddIf("--policy-uri", SigningPlan.Blank(_o.PolicyUri));
            if (!string.IsNullOrEmpty(_o.PolicyDocumentId))
            {
                cli.AddIf("--policy-document", _context.FileName(_o.PolicyDocumentId)).AddIf("--policy-specification", _o.PolicySpecification);
            }
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

        if (_o.ExtendedForm != XadesExtendedChoice.None)
        {
            cli.Add("--extended-form", CodeGenerator.ExtendedForm(_o.ExtendedForm.ToString()));
        }

        if (_o.SigningCertificateV1)
        {
            cli.Add("--signing-certificate-v1");
        }

        cli.AddIf("--data-mime-type", _o.MimeType?.Trim());
        if (_o.SigningPolicyId is not null)
        {
            cli.Add("--signing-policy", PolicyUploads.SigningFileName);
        }

        _context.Controls.Cli(cli);

        cli.AddIf("--commitment", _o.Commitment);
        foreach (string role in _o.SignerRoles)
        {
            cli.AddIf("--signer-role", role);
        }

        AddPropertyAndDataObjectArgs(cli);
        cli.AddIf("--operation-id", _o.OperationId);
        _context.CliNetwork(cli);
        return new CodeSnippets(sb.ToString(), cli.ToString(), notes) { CliCommands = [cli] };
    }

    /// <summary>The flags of the properties beyond the baseline: place, canonicalization, data timestamp, certified roles, more data objects.</summary>
    private void AddPropertyAndDataObjectArgs(CliLine line)
    {
        line.AddIf("--place-city", _o.PlaceCity).AddIf("--place-street", _o.PlaceStreet).AddIf("--place-state", _o.PlaceState)
            .AddIf("--place-postal-code", _o.PlacePostalCode).AddIf("--place-country", _o.PlaceCountry);
        if (_o.Canonicalization == XadesCanonicalization.Inclusive)
        {
            line.Add("--canonicalization", "inclusive");
        }

        if (_o.DataObjectsTimestamp)
        {
            line.Add("--data-objects-timestamp");
        }

        if (_o.AttributeCertificateId is not null)
        {
            line.AddIf("--attribute-certificate", _context.FileName(_o.AttributeCertificateId));
        }

        if (_o.SignedAssertionId is not null)
        {
            line.AddIf("--signed-assertion", _context.FileName(_o.SignedAssertionId));
        }

        if (_o.EmbeddedObjectId is not null)
        {
            line.AddIf("--embed-object", _context.FileName(_o.EmbeddedObjectId));
        }

        if (_o.ExternalObjectId is not null)
        {
            string name = _context.FileName(_o.ExternalObjectId);
            line.AddIf("--external-object", name + "=" + name);
        }
    }
}

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
    IReadOnlyList<FindingView>? Findings = null);

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
    IReadOnlyList<OptionIssue> Issues);

/// <summary>Signs with <c>XadesSigner</c> and validates the result.</summary>
internal sealed class XmlRunner(SandboxEnvironment sandbox, DocumentStore documents, CredentialStore credentials, ValidationService validation)
{
    /// <summary>Whether a Sandbox is connected (its TSAs and signers can be chosen).</summary>
    public bool SandboxConnected => sandbox.IsConnected;

    public XmlFacts? Facts(string? dataId) =>
        dataId is not null && documents.TryGet(dataId, out var file) ? XmlInspector.Inspect(dataId, file!.FileName, file.Content) : null;

    public XmlOptionsReport Evaluate(XmlOptions o)
    {
        credentials.TryGet(o.CredentialId, out var credential);
        return XmlCompatibility.Evaluate(o, Facts(o.DataId), credential?.Facts, sandbox.IsConnected, PolicyUploads.Signing(o.SigningPolicyId, documents));
    }

    public async Task<XmlSignResult> RunAsync(XmlOptions options, CancellationToken cancellationToken)
    {
        var report = Evaluate(options);
        var o = report.Effective;
        if (!report.CanSign)
        {
            return Failure(report, L.T("Fix the issues before signing."), "Validation", new CodeSnippets("", "", []));
        }

        var credential = credentials.Get(o.CredentialId!);
        credential.LastUsed = DateTimeOffset.UtcNow;
        var data = documents.Get(o.DataId!);
        var context = new PlanContext(credential, sandbox, documents);
        var watch = Stopwatch.StartNew();
        byte[] signed;
        string? achieved;
        var warnings = new List<string>();
        CodeSnippets code;
        try
        {
            var plan = new XadesPlan(o, context);
            code = plan.Code(credential.Facts);
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
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return Failure(report, ex.Message, SigningRunner.ErrorTypeOf(ex), FallbackCode(o, context, credential.Facts));
        }

        long signMs = watch.ElapsedMilliseconds;
        string fileName = OutputName(o, data.FileName);
        var output = documents.Add(fileName, signed);
        var view = o.Validate
            ? await ValidateAsync(output.Id, o.Form == XadesFormChoice.Detached ? o.DataId : null, o.Validation ?? new ValidationSettings(),
                report.Effective.ExternalObjectId, cancellationToken)
            : null;
        return new XmlSignResult(true, null, null, output.Id, fileName, signed.LongLength, report.EffectiveLevel, achieved, warnings, signMs, view, code, report.Issues);
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

        var trust = validation.Trust(settings);
        var signatures = await ValidateXadesAsync(file.Content, data, externalObject, trust, settings, cancellationToken);
        string overall = signatures.Count == 0 ? "Invalid"
            : signatures.All(s => s.Indication == "Valid") ? "Valid"
            : signatures.Any(s => s.Indication == "Invalid") ? "Invalid"
            : "Indeterminate";
        var errors = signatures.Count == 0 ? new List<string> { L.T("No ds:Signature in this XML.") } : [];
        return new XmlValidationView(overall, signatures, errors, signatureXml, preview, watch.ElapsedMilliseconds, ValidationCode(settings, data is not null));
    }

    private async Task<List<XmlSignatureReport>> ValidateXadesAsync(byte[] xml, byte[]? data, StoredFile? externalObject, ValidationTrust trust,
        ValidationSettings settings, CancellationToken cancellationToken)
    {
        var validator = new XadesSignatureValidator(trust.Options, logger: RunLog.Logger, chainRevocationChecker: validation.RevocationChecker());
        // An external additional data object is found by the URI of its reference, which is its file name.
        var results = externalObject is null
            ? await validator.ValidateAllAsync(xml, null, data, cancellationToken)
            : await validator.ValidateAllAsync(xml, null, ExternalData(xml, data, externalObject), cancellationToken);
        static string Status(bool? ok) => ok switch { true => "pass", false => "fail", null => "n/a" };
        var reports = new List<XmlSignatureReport>();
        foreach (var result in results)
        {
            Report(result, countersigned: null);
        }

        // A countersignature is listed right after the signature it signs, and says so.
        void Report(XadesValidationResult r, string? countersigned)
        {
            int i = reports.Count;
            var checks = new List<CheckRow>
            {
                new("signature", L.T("Signature value and references"), Status(r.IsSignatureValid && r.IsIntegrityValid), null),
                new("chain", L.T("Certificate chain"), Status(r.IsCertificateChainValid), null),
                new("timestamp", L.T("Signature timestamp"), Status(r.HasValidSignatureTimeStamp), r.IsTsaTrusted is { } trusted ? (trusted ? L.T("TSA trusted.") : L.T("TSA not trusted.")) : null),
                new("dataObjectsTimestamp", L.T("Data objects timestamp"), Status(r.HasValidDataObjectsTimeStamp),
                    r.DataObjectsTimeStampTime?.ToString("yyyy-MM-dd HH:mm:ss zzz", CultureInfo.InvariantCulture)),
                new("references", L.T("Complete references (XAdES-C)"), Status(r.HasValidCompleteReferences), null),
                new("sigAndRefs", L.T("SigAndRefsTimeStamp (XAdES-X)"), Status(r.HasValidSigAndRefsTimeStamp), null),
                new("ltv", L.T("Validation data (certificate and revocation values)"), Status(r.IsLtvDataValid), null),
                new("archive", L.T("Archive timestamp"), Status(r.HasValidArchiveTimeStamp), null),
                ValidationService.RevocationRow(r.IsNotRevoked, r.RevocationSource),
            };
            checks.AddRange(ValidationService.PolicyRows(r.Constraints));
            bool invalid = !r.IsSignatureValid || !r.IsIntegrityValid || r.HasValidSignatureTimeStamp == false || r.HasValidArchiveTimeStamp == false
                || r.HasValidSigAndRefsTimeStamp == false || r.HasValidCompleteReferences == false || r.HasValidDataObjectsTimeStamp == false;
            string indication = invalid ? "Invalid" : r.Indication.ToString();
            string? reference = countersigned is null ? r.SignatureId : L.T("{0} (countersignature of {1})", r.SignatureId ?? "-", countersigned);
            reports.Add(new XmlSignatureReport(i, reference, CadesInspector.SimpleName(r.SignerCertificate), indication,
                r.DetectedLevel switch
                {
                    AdesBaselineLevel.Basic => "B-B",
                    AdesBaselineLevel.Timestamped => "B-T",
                    AdesBaselineLevel.LongTerm => "B-LT",
                    _ => "B-LTA",
                },
                r.SigningTime?.ToString("yyyy-MM-dd HH:mm:ss zzz", CultureInfo.InvariantCulture),
                [.. checks.Where(c => c.Status != "n/a" || c.Id is "signature" or "chain")], r.Errors, r.Warnings,
                ValidationService.SubIndicationName(r.SubIndication), ValidationService.Findings(r.Constraints)));
            foreach (var counter in r.CounterSignatures)
            {
                Report(counter, r.SignatureId ?? "-");
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

    private static CodeSnippets ValidationCode(ValidationSettings settings, bool detached)
    {
        bool customRoot = settings.Trust.Contains(TrustChoice.Sandbox) || settings.CustomRootUploadIds.Count > 0;
        var sb = new StringBuilder("using SimpleSign.XAdES;\nusing SimpleSign.Core.Validation;\n" + (settings.PolicyId is null ? "" : "using SimpleSign.Core.Policies;\n") + "\nvar validator = new XadesSignatureValidator(new ValidationOptions\n{\n");
        sb.Append(CultureInfo.InvariantCulture, $"    TrustSystemRoots = {(settings.Trust.Contains(TrustChoice.System) ? "true" : "false")},\n");
        if (customRoot)
        {
            sb.Append("    TrustedRoots = [root], // X509CertificateLoader.LoadCertificateFromFile(\"root.cer\")\n");
        }

        foreach (string option in ValidationService.PolicyOptionsCode(settings))
        {
            sb.Append("    ").Append(option).Append(",\n");
        }

        sb.Append("});\n\nIReadOnlyList<XadesValidationResult> results = validator.ValidateAll(\n    File.ReadAllBytes(\"signed.xml\")");
        sb.Append(detached ? ",\n    trustAnchors: null,\n    originalData: File.ReadAllBytes(\"document.xml\")); // detached\n" : ");\n");
        sb.Append("foreach (var r in results) Console.WriteLine($\"{r.SignatureId}: {(r.IsValid ? \"valid\" : string.Join(\"; \", r.Errors))} ({r.DetectedLevel})\");\n");
        var args = new List<string> { "simplesign xades validate signed.xml" };
        if (detached)
        {
            args.Add("--data document.xml");
        }

        if (customRoot)
        {
            args.Add("--trust root.cer");
        }

        if (settings.Level >= SimpleSign.Core.Validation.ValidationLevel.LongTermData)
        {
            args.Add("--check-revocation");
        }

        args.AddRange(ValidationService.PolicyCliArgs(settings));

        return new CodeSnippets(sb.ToString(), string.Join(" \\\n  ", args), []);
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

        var args = _o.CounterSign
            ? new List<string> { "simplesign xades sign signed.xml", "--countersign", "--output countersigned.xml" }
            : new List<string> { "simplesign xades sign document.xml", "--output signed.xml" };
        var notes = new List<string>();
        CodeGenerator.CliCredential(credential, args, notes);
        if (_o.CounterSign)
        {
            CodeGenerator.AddIf(args, "--countersign-id", _o.CounterSignatureId);
        }
        else if (_o.Form != XadesFormChoice.Enveloped)
        {
            args.Add("--form " + _o.Form.ToString().ToLowerInvariant());
        }

        if (_o.Form == XadesFormChoice.Detached && !_o.CounterSign)
        {
            args.Add($"--data-uri {_o.DataUri}");
        }

        if (_o.Level != BaselineLevel.BB)
        {
            args.Add("--tsa " + _context.CliUrl(_o.Timestamp));
            args.Add("--level " + _o.Level switch { BaselineLevel.BT => "timestamped", BaselineLevel.BLT => "longterm", _ => "archive" });
        }

        if (_o.Kind == XadesKind.CustomPolicy)
        {
            args.Add($"--policy-oid {_o.PolicyOid}");
            CodeGenerator.AddIf(args, "--policy-uri", SigningPlan.Blank(_o.PolicyUri));
            if (!string.IsNullOrEmpty(_o.PolicyDocumentId))
            {
                CodeGenerator.AddIf(args, "--policy-document", _context.FileName(_o.PolicyDocumentId));
                CodeGenerator.AddIf(args, "--policy-specification", _o.PolicySpecification);
            }
        }

        if (_o.RevocationPreference == RevocationPreference.CrlFirst && _o.Level >= BaselineLevel.BLT)
        {
            args.Add("--revocation-preference crl");
        }

        if (_o.Hash != HashChoice.Sha256)
        {
            args.Add("--hash " + SigningPlan.HashName(_o.Hash));
        }

        if (_o.SigningPolicyId is not null)
        {
            args.Add("--signing-policy " + PolicyUploads.SigningFileName);
        }

        CodeGenerator.AddIf(args, "--commitment", _o.Commitment);
        foreach (string role in _o.SignerRoles)
        {
            CodeGenerator.AddIf(args, "--signer-role", role);
        }

        if (_o.ExtendedForm != XadesExtendedChoice.None || _o.SigningCertificateV1 || !string.IsNullOrWhiteSpace(_o.MimeType)
            || _o.Padding == RsaPadding.Pss && credential.KeyAlgorithm == "RSA" || _o.SigningTime is not null || _o.Timestamp.Auth != TsaAuth.None)
        {
            notes.Add("Extended forms, SigningCertificate V1, DataObjectFormat, RSASSA-PSS, a claimed signing time and TSA authentication have no xades flag: use the library.");
        }

        AddPropertyAndDataObjectArgs(args);
        return new CodeSnippets(sb.ToString(), string.Join(" \\\n  ", args), notes);
    }

    /// <summary>The flags of the properties beyond the baseline: place, canonicalization, data timestamp, certified roles, more data objects.</summary>
    private void AddPropertyAndDataObjectArgs(List<string> args)
    {
        CodeGenerator.AddIf(args, "--place-city", _o.PlaceCity);
        CodeGenerator.AddIf(args, "--place-street", _o.PlaceStreet);
        CodeGenerator.AddIf(args, "--place-state", _o.PlaceState);
        CodeGenerator.AddIf(args, "--place-postal-code", _o.PlacePostalCode);
        CodeGenerator.AddIf(args, "--place-country", _o.PlaceCountry);
        if (_o.Canonicalization == XadesCanonicalization.Inclusive)
        {
            args.Add("--canonicalization inclusive");
        }

        if (_o.DataObjectsTimestamp)
        {
            if (_o.Level == BaselineLevel.BB)
            {
                args.Add("--tsa " + _context.CliUrl(_o.Timestamp));
            }

            args.Add("--data-objects-timestamp");
        }

        if (_o.AttributeCertificateId is not null)
        {
            CodeGenerator.AddIf(args, "--attribute-certificate", _context.FileName(_o.AttributeCertificateId));
        }

        if (_o.SignedAssertionId is not null)
        {
            CodeGenerator.AddIf(args, "--signed-assertion", _context.FileName(_o.SignedAssertionId));
        }

        if (_o.EmbeddedObjectId is not null)
        {
            CodeGenerator.AddIf(args, "--embed-object", _context.FileName(_o.EmbeddedObjectId));
        }

        if (_o.ExternalObjectId is not null)
        {
            string name = _context.FileName(_o.ExternalObjectId);
            CodeGenerator.AddIf(args, "--external-object", name + "=" + name);
        }
    }
}

using System.Diagnostics;
using System.Globalization;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml;
using SimpleSign.Brazil.Fiscal;
using SimpleSign.Brazil.IcpBrasil;
using SimpleSign.Brazil.IcpBrasil.Xades;
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
    string? Cnpj,
    string? Cpf,
    string Indication,
    string? Level,
    string? SigningTime,
    IReadOnlyList<CheckRow> Checks,
    IReadOnlyList<string> Errors,
    IReadOnlyList<string> Warnings);

public sealed record XmlValidationView(
    string Overall,
    XmlMode Mode,
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

/// <summary>Signs with <c>XadesSigner</c> or <c>FiscalXmlSigner</c> and validates the result.</summary>
internal sealed class XmlRunner(SandboxEnvironment sandbox, DocumentStore documents, CredentialStore credentials, ValidationService validation)
{
    private const string XadesNamespace = "http://uri.etsi.org/01903/v1.3.2#";

    public XmlFacts? Facts(string? dataId) =>
        dataId is not null && documents.TryGet(dataId, out var file) ? XmlInspector.Inspect(dataId, file!.FileName, file.Content) : null;

    public XmlOptionsReport Evaluate(XmlOptions o)
    {
        credentials.TryGet(o.CredentialId, out var credential);
        return XmlCompatibility.Evaluate(o, Facts(o.DataId), credential?.Facts);
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
        var context = new PlanContext(o.Environment, credential, sandbox, documents);
        var watch = Stopwatch.StartNew();
        byte[] signed;
        string? achieved;
        var warnings = new List<string>();
        CodeSnippets code;
        try
        {
            if (o.Mode == XmlMode.Fiscal)
            {
                var profile = FiscalDocumentProfile.ByName[o.Profile];
                code = FiscalCode(o, context, credential.Facts);
                signed = credential.External is { } external
                    ? await FiscalXmlSigner.SignAsync(data.Content, profile, credential.Certificate, external, o.ElementId, cancellationToken)
                    : o.SignAll
                        ? FiscalXmlSigner.SignAll(data.Content, profile, credential.Certificate)
                        : FiscalXmlSigner.Sign(data.Content, profile, credential.Certificate, o.ElementId);
                achieved = "XML-DSig";
            }
            else
            {
                var plan = new XadesPlan(o, context);
                code = plan.Code(credential.Facts);
                var builder = XadesSigner.Document(data.Content).WithLogger(RunLog.Logger);
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
            return Failure(report, ex.Message, ex.GetType().Name, FallbackCode(o, context, credential.Facts));
        }

        long signMs = watch.ElapsedMilliseconds;
        string fileName = OutputName(o, data.FileName);
        var output = documents.Add(fileName, signed);
        var view = o.Validate
            ? Validate(output.Id, o.Mode == XmlMode.Xades && o.Form == XadesFormChoice.Detached ? o.DataId : null, o.Validation ?? ValidationSettings.For(o.Environment))
            : null;
        return new XmlSignResult(true, null, null, output.Id, fileName, signed.LongLength, report.EffectiveLevel, achieved, warnings, signMs, view, code, report.Issues);
    }

    /// <summary>Validates every signature of a stored XML: XAdES if any has QualifyingProperties, else fiscal XML-DSig.</summary>
    public XmlValidationView Validate(string signatureId, string? dataId, ValidationSettings settings)
    {
        var file = documents.Get(signatureId);
        byte[]? data = dataId is null ? null : documents.Get(dataId).Content;
        var watch = Stopwatch.StartNew();
        string preview = XmlInspector.Preview(file.Content);
        string? signatureXml = XmlInspector.SignatureXml(file.Content);
        XmlMode mode;
        try
        {
            var doc = XmlInspector.Load(file.Content);
            mode = doc.GetElementsByTagName("QualifyingProperties", XadesNamespace).Count > 0 ? XmlMode.Xades : XmlMode.Fiscal;
        }
        catch (XmlException ex)
        {
            return new XmlValidationView("Invalid", XmlMode.Xades, [], [L.T("The file is not well-formed XML: {0}", ex.Message)], null, preview, 0, new CodeSnippets("", "", []));
        }

        var trust = validation.Trust(settings);
        var signatures = mode == XmlMode.Xades
            ? ValidateXades(file.Content, data, trust, settings)
            : ValidateFiscal(file.Content, trust, settings);
        string overall = signatures.Count == 0 ? "Invalid"
            : signatures.All(s => s.Indication == "Valid") ? "Valid"
            : signatures.Any(s => s.Indication == "Invalid") ? "Invalid"
            : "Indeterminate";
        var errors = signatures.Count == 0 ? new List<string> { L.T("No ds:Signature in this XML.") } : [];
        return new XmlValidationView(overall, mode, signatures, errors, signatureXml, preview, watch.ElapsedMilliseconds, ValidationCode(mode, settings, data is not null));
    }

    private static List<XmlSignatureReport> ValidateXades(byte[] xml, byte[]? data, ValidationTrust trust, ValidationSettings settings)
    {
        var validator = new XadesSignatureValidator(trust.Options, logger: RunLog.Logger);
        var results = validator.ValidateAll(xml, trust.IcpAnchors.Count > 0 ? trust.IcpAnchors : null, data);
        static string Status(bool? ok) => ok switch { true => "pass", false => "fail", null => "n/a" };
        var reports = new List<XmlSignatureReport>();
        foreach (var (r, i) in results.Select((r, i) => (r, i)))
        {
            var checks = new List<CheckRow>
            {
                new("signature", L.T("Signature value and references"), Status(r.IsSignatureValid && r.IsIntegrityValid), null),
                new("chain", L.T("Certificate chain"), Status(r.IsCertificateChainValid), null),
                new("timestamp", L.T("Signature timestamp"), Status(r.HasValidSignatureTimeStamp), r.IsTsaTrusted is { } trusted ? (trusted ? L.T("TSA trusted.") : L.T("TSA not trusted.")) : null),
                new("references", L.T("Complete references (XAdES-C)"), Status(r.HasValidCompleteReferences), null),
                new("sigAndRefs", L.T("SigAndRefsTimeStamp (XAdES-X)"), Status(r.HasValidSigAndRefsTimeStamp), null),
                new("ltv", L.T("Validation data (certificate and revocation values)"), Status(r.IsLtvDataValid), null),
                new("archive", L.T("Archive timestamp"), Status(r.HasValidArchiveTimeStamp), null),
            };
            if (r.SignaturePolicy is not null && settings.UseBrasil)
            {
                var policy = IcpBrasilXadesPolicyValidator.Validate(xml, r);
                checks.Add(new("policy", L.T("ICP-Brasil policy"), policy.Status switch
                {
                    IcpBrasilPolicyStatus.Valid => "pass",
                    IcpBrasilPolicyStatus.Invalid => "warn",
                    _ => "n/a",
                }, policy.Status == IcpBrasilPolicyStatus.Valid
                    ? policy.Policy?.Oid
                    : string.Join(" ", policy.Errors.DefaultIfEmpty(policy.Status.ToString()))));
            }

            bool invalid = !r.IsSignatureValid || !r.IsIntegrityValid || r.HasValidSignatureTimeStamp == false || r.HasValidArchiveTimeStamp == false
                || r.HasValidSigAndRefsTimeStamp == false || r.HasValidCompleteReferences == false;
            string indication = invalid ? "Invalid" : r.IsValid ? "Valid" : "Indeterminate";
            reports.Add(new XmlSignatureReport(i, r.SignatureId, CadesInspector.SimpleName(r.SignerCertificate), null, null, indication,
                r.DetectedLevel switch
                {
                    AdesBaselineLevel.Basic => "B-B",
                    AdesBaselineLevel.Timestamped => "B-T",
                    AdesBaselineLevel.LongTerm => "B-LT",
                    _ => "B-LTA",
                },
                r.SigningTime?.ToString("yyyy-MM-dd HH:mm:ss zzz", CultureInfo.InvariantCulture),
                [.. checks.Where(c => c.Status != "n/a" || c.Id is "signature" or "chain")], r.Errors, r.Warnings));
        }

        return reports;
    }

    private List<XmlSignatureReport> ValidateFiscal(byte[] xml, ValidationTrust trust, ValidationSettings settings)
    {
        var result = FiscalXmlValidator.VerifySignatures(xml);
        var reports = new List<XmlSignatureReport>();
        foreach (var (s, i) in result.Signatures.Select((s, i) => (s, i)))
        {
            var errors = new List<string>(s.Errors);
            bool chain = s.Certificate is not null && ChainIsValid(s.Certificate, trust, settings, errors);
            var checks = new List<CheckRow>
            {
                new("digest", L.T("Reference digest ({0})", s.HashAlgorithm ?? "?"), s.IsDigestValid ? "pass" : "fail",
                    s.IsDigestValid ? L.T("The signed element was not changed.") : L.T("The signed element changed after signing.")),
                new("signature", L.T("Signature value"), s.IsSignatureValid ? "pass" : "fail", null),
                new("chain", L.T("Certificate chain"), chain ? "pass" : "fail", null),
            };
            string indication = !s.IsDigestValid || !s.IsSignatureValid ? "Invalid" : chain ? "Valid" : "Indeterminate";
            reports.Add(new XmlSignatureReport(i, s.ReferenceUri, CadesInspector.SimpleName(s.Certificate), s.Cnpj, s.Cpf, indication,
                s.SignedElement is null ? null : "<" + s.SignedElement + ">", null, checks, errors, []));
        }

        return reports;
    }

    /// <summary>The fiscal layouts carry only the signer certificate; the sandbox intermediate is supplied (real validators fetch it by AIA).</summary>
    private bool ChainIsValid(X509Certificate2 certificate, ValidationTrust trust, ValidationSettings settings, List<string> errors)
    {
        using var chain = new X509Chain();
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.ExtraStore.Add(sandbox.Pki.Intermediate);
        var roots = (trust.Options.TrustedRoots ?? []).Concat(trust.IcpAnchors).ToList();
        if (roots.Count > 0 || !settings.Trust.Contains(TrustChoice.System))
        {
            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            chain.ChainPolicy.CustomTrustStore.AddRange(roots.ToArray());
        }

        if (chain.Build(certificate))
        {
            return true;
        }

        errors.AddRange(chain.ChainStatus.Select(s => $"{s.Status}: {s.StatusInformation}".TrimEnd()));
        return false;
    }

    private static string OutputName(XmlOptions o, string input)
    {
        string name = Path.GetFileNameWithoutExtension(input);
        return o.Mode == XmlMode.Xades && o.Form == XadesFormChoice.Detached ? name + "-signature.xml"
            : o.Mode == XmlMode.Xades && o.Form == XadesFormChoice.Enveloping ? name + "-enveloping.xml"
            : name + "-signed.xml";
    }

    private static CodeSnippets FallbackCode(XmlOptions o, PlanContext context, CredentialFacts credential)
    {
        try
        {
            return o.Mode == XmlMode.Fiscal ? FiscalCode(o, context, credential) : new XadesPlan(o, context).Code(credential);
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException)
        {
            return new CodeSnippets("", "", []);
        }
    }

    internal static string ProfileProperty(string key) => key switch
    {
        "nfe" => "NFe",
        "evento" => "Evento",
        "inutilizacao" => "Inutilizacao",
        "cte" => "CTe",
        "mdfe" => "MDFe",
        "nfse" => "NFSeDps",
        "esocial" => "ESocial",
        _ => "Reinf",
    };

    private static CodeSnippets FiscalCode(XmlOptions o, PlanContext context, CredentialFacts credential)
    {
        string credentialCode = context.CredentialCode();
        string profile = $"FiscalDocumentProfile.{ProfileProperty(o.Profile)}";
        string id = o.ElementId is { } elementId ? $", elementId: {SigningPlan.Str(elementId)}" : "";
        var sb = new StringBuilder("using SimpleSign.Brazil.Fiscal;\n\nbyte[] xml = File.ReadAllBytes(\"document.xml\");\n");
        foreach (string line in context.Setup.Distinct())
        {
            sb.Append(line).Append('\n');
        }

        sb.Append('\n');
        if (context.Credential.External is not null)
        {
            string variable = credentialCode[(credentialCode.IndexOf('(', StringComparison.Ordinal) + 1)..credentialCode.IndexOf('.', StringComparison.Ordinal)];
            sb.Append(CultureInfo.InvariantCulture, $"byte[] signed = await FiscalXmlSigner.SignAsync(xml, {profile}, {variable}.Certificate, {variable}{id});\n");
        }
        else
        {
            sb.Append(o.SignAll
                ? $"byte[] signed = FiscalXmlSigner.SignAll(xml, {profile}, certificate); // every unsigned element of the layout\n"
                : $"byte[] signed = FiscalXmlSigner.Sign(xml, {profile}, certificate{id});\n");
        }

        sb.Append("File.WriteAllBytes(\"document-signed.xml\", signed);\n\n");
        sb.Append("// Digests and signature values only (no network); FiscalXmlValidator.ValidateAsync also checks the ICP-Brasil chain.\n");
        sb.Append("var check = FiscalXmlValidator.VerifySignatures(signed);\n");
        sb.Append("foreach (var s in check.Signatures) Console.WriteLine($\"{s.ReferenceUri}: {(s.IsValid ? \"ok\" : string.Join(\"; \", s.Errors))} CNPJ {s.Cnpj}\");\n");

        var args = new List<string> { "simplesign fiscal sign document.xml", $"--profile {o.Profile}" };
        var notes = new List<string>();
        CodeGenerator.CliCredential(credential, args, notes);
        if (o.SignAll)
        {
            args.Add("--all");
        }
        else if (o.ElementId is not null)
        {
            args.Add($"--id {o.ElementId}");
        }

        args.Add("--output document-signed.xml");
        return new CodeSnippets(sb.ToString(), string.Join(" \\\n  ", args), notes);
    }

    private static CodeSnippets ValidationCode(XmlMode mode, ValidationSettings settings, bool detached)
    {
        bool customRoot = settings.Trust.Contains(TrustChoice.Sandbox) || settings.CustomRootUploadIds.Count > 0;
        if (mode == XmlMode.Fiscal)
        {
            string fiscal = "using SimpleSign.Brazil.Fiscal;\n\nbyte[] xml = File.ReadAllBytes(\"document-signed.xml\");\n"
                + "// Digests and signature values only:\nFiscalValidationResult quick = FiscalXmlValidator.VerifySignatures(xml);\n"
                + "// Plus the ICP-Brasil chain (AIA, LCR/OCSP):\nFiscalValidationResult full = await new FiscalXmlValidator().ValidateAsync(xml"
                + (settings.CheckRevocation ? "" : ", checkRevocation: false") + ");\n";
            var notes = new List<string>();
            if (customRoot)
            {
                notes.Add("FiscalXmlValidator trusts the ICP-Brasil roots only; the TestBench checks sandbox chains itself.");
            }

            return new CodeSnippets(fiscal, "simplesign fiscal validate document-signed.xml" + (settings.CheckRevocation ? "" : " --no-revocation"), notes);
        }

        var sb = new StringBuilder("using SimpleSign.XAdES;\nusing SimpleSign.Core.Validation;\n\nvar validator = new XadesSignatureValidator(new ValidationOptions\n{\n");
        sb.Append(CultureInfo.InvariantCulture, $"    TrustSystemRoots = {(settings.Trust.Contains(TrustChoice.System) ? "true" : "false")},\n");
        if (customRoot)
        {
            sb.Append("    TrustedRoots = [root], // X509CertificateLoader.LoadCertificateFromFile(\"root.cer\")\n");
        }

        if (!settings.CheckRevocation)
        {
            sb.Append("    CheckRevocation = false,\n");
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

        if (settings.CheckRevocation)
        {
            args.Add("--check-revocation");
        }

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

        if (o.SigningCertificateV1 && o.Kind != XadesKind.IcpBrasil)
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
        if (_o.Kind == XadesKind.IcpBrasil)
        {
            var policy = Enum.Parse<IcpBrasilPolicy>(_o.IcpPolicy.ToString());
            if (policy == IcpBrasilPolicy.AdRb)
            {
                _steps.Add((".WithIcpBrasilPolicy(IcpBrasilPolicy.AdRb) // SigningCertificate V1 + the policy version for the signer's root", b => b.WithIcpBrasilPolicy(policy)));
            }
            else
            {
                var tsa = _context.BuildTimestamp(_o.Timestamp, "tsa");
                _steps.Add(($".WithIcpBrasilPolicy(IcpBrasilPolicy.{policy}, tsa) // V1, policy, B-T{(policy == IcpBrasilPolicy.AdRt ? "" : " + extended form")}",
                    b => b.WithIcpBrasilPolicy(policy, tsa)));
            }

            return;
        }

        if (_o.Kind == XadesKind.CustomPolicy)
        {
            string? uri = SigningPlan.Blank(_o.PolicyUri);
            _steps.Add(($".WithSignaturePolicy({SigningPlan.Str(_o.PolicyOid)}{(uri is null ? "" : ", " + SigningPlan.Str(uri))})", b => b.WithSignaturePolicy(_o.PolicyOid, uri)));
        }

        string ltv = $"new LongTermValidationOptions({(_context.IsSandbox ? "sandboxHttp" : "")})";
        switch (_o.Level)
        {
            case BaselineLevel.BT:
                var tsa = _context.BuildTimestamp(_o.Timestamp, "tsa");
                _steps.Add((".WithLevel(AdesBaselineProfile.Timestamped(tsa))", b => b.WithLevel(AdesBaselineProfile.Timestamped(tsa))));
                break;
            case BaselineLevel.BLT:
                var ltTsa = _context.BuildTimestamp(_o.Timestamp, "tsa");
                _steps.Add(($".WithLevel(AdesBaselineProfile.LongTerm(tsa, {ltv}))", b => b.WithLevel(AdesBaselineProfile.LongTerm(ltTsa, new LongTermValidationOptions(_context.Http)))));
                break;
            case BaselineLevel.BLTA:
                var ltaTsa = _context.BuildTimestamp(_o.Timestamp, "tsa");
                _steps.Add(($".WithLevel(AdesBaselineProfile.Archive(tsa, {ltv}))", b => b.WithLevel(AdesBaselineProfile.Archive(ltaTsa, new LongTermValidationOptions(_context.Http)))));
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
        var sb = new StringBuilder("using SimpleSign.XAdES;\nusing SimpleSign.Core.Signing;\n");
        if (_o.Kind == XadesKind.IcpBrasil)
        {
            sb.Append("using SimpleSign.Brazil.IcpBrasil;\nusing SimpleSign.Brazil.IcpBrasil.Xades;\n");
        }

        sb.Append('\n');
        if (_context.IsSandbox)
        {
            sb.Append("// Sandbox: sandboxHttp is an IHttpClientProvider that answers *.sandbox.simplesign.test (TSA and CRLs).\n");
        }

        sb.Append("byte[] xml = File.ReadAllBytes(\"document.xml\");\n");
        foreach (string line in _context.Setup.Distinct())
        {
            sb.Append(line).Append('\n');
        }

        sb.Append("\nXadesSigningResult result = await XadesSigner.Document(xml)\n");
        foreach (var (code, _) in _steps)
        {
            sb.Append("    ").Append(code).Append('\n');
        }

        sb.Append("    .SignWithDetailsAsync();\n\n");
        sb.Append("File.WriteAllBytes(\"signed.xml\", result.SignedArtifact);\n");
        sb.Append("Console.WriteLine($\"Requested {result.RequestedLevel}, achieved {result.AchievedLevel}\");\n");

        var args = new List<string> { "simplesign xades sign document.xml", "--output signed.xml" };
        var notes = new List<string>();
        CodeGenerator.CliCredential(credential, args, notes);
        if (_o.Form != XadesFormChoice.Enveloped)
        {
            args.Add("--form " + _o.Form.ToString().ToLowerInvariant());
        }

        if (_o.Form == XadesFormChoice.Detached)
        {
            args.Add($"--data-uri {_o.DataUri}");
        }

        if (_o.Kind == XadesKind.IcpBrasil)
        {
            notes.Add("The CLI has no ICP-Brasil XAdES policy flag: use WithIcpBrasilPolicy (SimpleSign.Brazil.IcpBrasil.Xades).");
        }
        else
        {
            if (_o.Level != BaselineLevel.BB)
            {
                args.Add("--tsa " + PlanContext.CliUrl(_o.Timestamp));
                args.Add("--level " + _o.Level switch { BaselineLevel.BT => "timestamped", BaselineLevel.BLT => "longterm", _ => "archive" });
            }

            if (_o.Kind == XadesKind.CustomPolicy)
            {
                args.Add($"--policy-oid {_o.PolicyOid}");
                CodeGenerator.AddIf(args, "--policy-uri", SigningPlan.Blank(_o.PolicyUri));
            }
        }

        if (_o.Hash != HashChoice.Sha256)
        {
            args.Add("--hash " + SigningPlan.HashName(_o.Hash));
        }

        CodeGenerator.AddIf(args, "--commitment", _o.Commitment);
        foreach (string role in _o.SignerRoles)
        {
            CodeGenerator.AddIf(args, "--signer-role", role);
        }

        if (_o.ExtendedForm != XadesExtendedChoice.None || _o.SigningCertificateV1 && _o.Kind != XadesKind.IcpBrasil || !string.IsNullOrWhiteSpace(_o.MimeType)
            || _o.Padding == RsaPadding.Pss && credential.KeyAlgorithm == "RSA" || _o.SigningTime is not null || _o.Timestamp.Auth != TsaAuth.None)
        {
            notes.Add("Extended forms, SigningCertificate V1, DataObjectFormat, RSASSA-PSS, a claimed signing time and TSA authentication have no xades flag: use the library.");
        }

        return new CodeSnippets(sb.ToString(), string.Join(" \\\n  ", args), notes);
    }
}

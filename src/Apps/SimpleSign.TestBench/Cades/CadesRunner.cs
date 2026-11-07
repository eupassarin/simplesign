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
    string? SubIndication = null);

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
    IReadOnlyList<OptionIssue> Issues);

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

    public CadesOptionsReport Evaluate(CadesOptions o)
    {
        credentials.TryGet(o.CredentialId, out var credential);
        return CadesCompatibility.Evaluate(o, Inputs(o), credential?.Facts, sandbox.IsConnected);
    }

    public async Task<CadesSignResult> RunAsync(CadesOptions options, CancellationToken cancellationToken)
    {
        var report = Evaluate(options);
        var o = report.Effective;
        var empty = new CodeSnippets("", "", []);
        if (!report.CanSign)
        {
            return Failure(o, report, L.T("Fix the issues before signing."), "Validation", empty);
        }

        var credential = credentials.Get(o.CredentialId!);
        credential.LastUsed = DateTimeOffset.UtcNow;
        var plan = new CadesPlan(o, new PlanContext(credential, sandbox, documents));
        byte[]? data = o.DataId is { } id && o.Operation != CadesOperation.CounterSign && report.Options["data"].Visible ? documents.Get(id).Content : null;
        byte[]? existing = o.ExistingSignatureId is { } existingId && report.Options["existing"].Visible ? documents.Get(existingId).Content : null;
        var code = plan.Code(credential.Facts);
        var watch = Stopwatch.StartNew();
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

        long signMs = watch.ElapsedMilliseconds;
        string fileName = OutputName(o);
        var output = documents.Add(fileName, signed.SignedArtifact);

        // Detached signatures validate against the data; enveloped ones carry it.
        string? contentId = o.ContentType == CadesContentChoice.Detached && report.Options["data"].Visible ? o.DataId : null;
        var view = o.Validate
            ? await ValidateAsync(output.Id, contentId, o.Validation ?? new ValidationSettings(), cancellationToken)
            : null;
        return new CadesSignResult(true, null, null, output.Id, fileName, signed.SignedArtifact.LongLength, report.EffectiveLevel, LevelName(signed.AchievedLevel),
            signed.HasSignatureTimestamp, signed.HasLongTermValidationMaterial, signed.HasArchiveTimestamp,
            [.. signed.Warnings.Select(w => w.Message)], signMs, view, code, report.Issues);
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

        var trust = validation.Trust(settings);
        var validator = new CadesSignatureValidator(trust.Options, RunLog.Logger, chainRevocationChecker: validation.RevocationChecker());
        var result = await validator.ValidateAllAsync(signature.Content, structure.IsDetached ? data : null, null, cancellationToken);
        var signers = result.Signers.Select(Signer).ToList();
        string overall = result.Errors.Count > 0 || signers.Count == 0 ? "Invalid"
            : Flatten(signers).All(s => s.Indication == "Valid") ? "Valid"
            : Flatten(signers).Any(s => s.Indication == "Invalid") ? "Invalid"
            : "Indeterminate";
        return new CadesValidationView(overall, signers, result.Errors, structure, watch.ElapsedMilliseconds, code);
    }

    private static IEnumerable<CadesSignerReport> Flatten(IEnumerable<CadesSignerReport> signers) =>
        signers.SelectMany(s => new[] { s }.Concat(Flatten(s.CounterSignatures)));

    private static CadesSignerReport Signer(CadesSignerValidationResult s)
    {
        var r = s.Result;
        static string Status(bool? ok) => ok switch { true => "pass", false => "fail", null => "n/a" };
        var checks = new List<CheckRow>
        {
            new("integrity", L.T("Integrity (message digest)"), Status(r.IsIntegrityValid), r.IsIntegrityValid
                ? L.T("The signed content matches the message-digest attribute.")
                : L.T("The content does not match the message-digest attribute.")),
            new("signature", L.T("Signature value"), Status(r.IsSignatureValid), null),
            new("chain", L.T("Certificate chain"), Status(r.IsCertificateChainValid), null),
            new("timestamp", L.T("Signature timestamp"), Status(r.HasValidTimestamp), r.IsTsaTrusted is { } trusted ? (trusted ? L.T("TSA trusted.") : L.T("TSA not trusted.")) : null),
            new("contentTimestamp", L.T("Content timestamp"), Status(r.HasValidContentTimestamp),
                r.ContentTimestampTime?.ToString("yyyy-MM-dd HH:mm:ss zzz", CultureInfo.InvariantCulture)),
            new("ltv", L.T("Validation data (certificate and revocation values)"), Status(r.IsLtvDataValid), null),
            new("escTimestamp", L.T("CAdES-C timestamp (escTimeStamp)"), Status(r.HasValidEscTimestamp), null),
            new("archive", L.T("Archive timestamp"), Status(r.HasValidArchiveTimestamp), null),
            ValidationService.RevocationRow(r.IsNotRevoked, r.RevocationSource),
        };
        checks.AddRange(ValidationService.PolicyRows(r.Constraints));
        // The library's indication, made INVALID by a timestamp that does not verify (not part of the indication).
        bool brokenTimestamp = r.HasValidTimestamp == false || r.HasValidArchiveTimestamp == false || r.HasValidEscTimestamp == false || r.HasValidContentTimestamp == false;
        string indication = brokenTimestamp ? "Invalid" : r.Indication.ToString();
        return new CadesSignerReport(s.Index, CadesInspector.SimpleName(r.SignerCertificate), indication,
            r.SigningTime?.ToString("yyyy-MM-dd HH:mm:ss zzz", CultureInfo.InvariantCulture),
            [.. checks.Where(c => c.Status != "n/a" || c.Id is "integrity" or "signature" or "chain")], r.Errors, r.Warnings,
            [.. s.CounterSignatures.Select(Signer)], ValidationService.SubIndicationName(r.SubIndication));
    }

    private static CodeSnippets ValidationCode(ValidationSettings settings, bool detached)
    {
        bool sandboxRoot = settings.Trust.Contains(TrustChoice.Sandbox);
        var sb = new StringBuilder("using SimpleSign.CAdES;\nusing SimpleSign.Core.Validation;\n");
        sb.Append("\nvar validator = new CadesSignatureValidator(new ValidationOptions\n{\n");
        sb.Append(CultureInfo.InvariantCulture, $"    TrustSystemRoots = {(settings.Trust.Contains(TrustChoice.System) ? "true" : "false")},\n");
        if (sandboxRoot || settings.CustomRootUploadIds.Count > 0)
        {
            sb.Append("    TrustedRoots = [root], // X509CertificateLoader.LoadCertificateFromFile(\"root.cer\")\n");
        }

        if (!settings.CheckRevocation)
        {
            sb.Append("    CheckRevocation = false,\n");
        }

        sb.Append("});\n");

        sb.Append("\nCadesValidationReport report = validator.ValidateAll(\n    File.ReadAllBytes(\"signature.p7s\"),\n");
        sb.Append(detached ? "    File.ReadAllBytes(\"document\") /* the signed data: the signature is detached */" : "    null /* enveloped: the content is inside */");
        sb.Append(");\n");
        sb.Append("\nforeach (var signer in report.Signers)\n{\n    Console.WriteLine($\"#{signer.Index}: {(signer.IsValid ? \"valid\" : \"not valid\")}\");\n");
        sb.Append("    foreach (var error in signer.Result.Errors) Console.WriteLine($\"  ✕ {error}\");\n");
        sb.Append("    foreach (var counter in signer.CounterSignatures) Console.WriteLine($\"  countersignature #{counter.Index}: {counter.IsValid}\");\n}\n");

        var args = new List<string> { "simplesign cades validate signature.p7s" };
        var notes = new List<string>();
        if (detached)
        {
            args.Add("--data document");
        }

        if (sandboxRoot || settings.CustomRootUploadIds.Count > 0)
        {
            args.Add("--trust root.cer");
        }

        if (!settings.CheckRevocation || !settings.Trust.Contains(TrustChoice.System))
        {
            notes.Add("The CLI validates against the OS roots plus --trust; turning revocation or the OS roots off needs the library.");
        }

        return new CodeSnippets(sb.ToString(), string.Join(" \\\n  ", args), notes);
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

        if (o.SigningPolicy != SigningPolicyChoice.Default)
        {
            var signingPolicy = SigningPlan.ToSigningPolicy(o.SigningPolicy);
            _steps.Add((SigningPlan.SigningPolicyCode(o.SigningPolicy), b => b.WithSigningPolicy(signingPolicy)));
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

        var args = new List<string> { $"simplesign cades sign {(_o.Operation == CadesOperation.Sign ? "document" : "signature.p7s")}", $"--output {OutputName()}" };
        var notes = new List<string>();
        CodeGenerator.CliCredential(credential, args, notes);
        if (_o.Operation != CadesOperation.Sign)
        {
            notes.Add("Co-signing and countersigning are library APIs (CadesSigner.CoSign / CounterSign); the CLI creates new signatures only.");
        }

        if (_o.ContentType == CadesContentChoice.Enveloped && _o.Operation == CadesOperation.Sign)
        {
            args.Add("--content-type enveloped");
        }

        if (_o.Level != BaselineLevel.BB)
        {
            args.Add("--tsa " + _context.CliUrl(_o.Timestamp));
            args.Add("--level " + _o.Level switch { BaselineLevel.BT => "timestamped", BaselineLevel.BLT => "longterm", _ => "archive" });
        }

        if (_o.Kind == CadesKind.CustomPolicy)
        {
            args.Add($"--policy-oid {_o.PolicyOid}");
            CodeGenerator.AddIf(args, "--policy-uri", SigningPlan.Blank(_o.PolicyUri));
            if (!string.IsNullOrEmpty(_o.PolicyDocumentId))
            {
                CodeGenerator.AddIf(args, "--policy-document", _context.FileName(_o.PolicyDocumentId));
                CodeGenerator.AddIf(args, "--policy-specification", _o.PolicySpecification);
            }
        }

        if (_o.ExtendedForm != CadesExtendedChoice.None)
        {
            notes.Add("Extended forms (CAdES-X / X Long / A) need the library: WithExtendedValidationData.");
        }

        if (_o.Hash != HashChoice.Sha256)
        {
            args.Add("--hash " + SigningPlan.HashName(_o.Hash));
        }

        if (_o.SigningPolicy != SigningPolicyChoice.Default)
        {
            args.Add("--signing-policy " + _o.SigningPolicy.ToString().ToLowerInvariant());
        }

        CodeGenerator.AddIf(args, "--commitment", _o.Commitment);
        if (_o.Padding == RsaPadding.Pss && credential.KeyAlgorithm == "RSA" || _o.SigningTime is not null || _o.Timestamp.Auth != TsaAuth.None)
        {
            notes.Add("RSASSA-PSS, a claimed signing time and TSA authentication have no cades flag: use the library.");
        }

        AddSignedAttributeArgs(args);
        if (_o.RevocationPreference == RevocationPreference.CrlFirst && _o.Level >= BaselineLevel.BLT)
        {
            args.Add("--revocation-preference crl");
        }

        return new CodeSnippets(sb.ToString(), string.Join(" \\\n  ", args), notes);
    }

    /// <summary>The flags of the signed attributes beyond the baseline: location, roles, content description and timestamp.</summary>
    private void AddSignedAttributeArgs(List<string> args)
    {
        CodeGenerator.AddIf(args, "--signer-country", _o.SignerCountry);
        CodeGenerator.AddIf(args, "--signer-locality", _o.SignerLocality);
        foreach (string line in _o.SignerPostalAddress)
        {
            CodeGenerator.AddIf(args, "--signer-postal-address", line);
        }

        foreach (string role in _o.SignerRoles)
        {
            CodeGenerator.AddIf(args, "--signer-role", role);
        }

        if (!string.IsNullOrEmpty(_o.AttributeCertificateId))
        {
            CodeGenerator.AddIf(args, "--attribute-certificate", _context.FileName(_o.AttributeCertificateId));
        }

        if (!string.IsNullOrEmpty(_o.SignedAssertionId))
        {
            CodeGenerator.AddIf(args, "--signed-assertion", _context.FileName(_o.SignedAssertionId));
        }

        CodeGenerator.AddIf(args, "--mime-type", _o.MimeType);
        CodeGenerator.AddIf(args, "--content-description", _o.ContentDescription);
        if (_o.ContentTimestamp)
        {
            if (_o.Level == BaselineLevel.BB)
            {
                args.Add("--tsa " + _context.CliUrl(_o.Timestamp));
            }

            args.Add("--content-timestamp");
        }
    }

    private string OutputName() => CadesRunner.OutputName(_o);
}

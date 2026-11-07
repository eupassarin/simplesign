using System.Diagnostics;
using System.Security.Cryptography;
using SimpleSign.TestBench.Cades;
using SimpleSign.TestBench.Credentials;
using SimpleSign.TestBench.Signing;

namespace SimpleSign.TestBench.Matrix;

/// <summary>
/// The CAdES run matrix: cases generated from <see cref="CadesCompatibility"/> (every value, then
/// pairwise), signed with <c>CadesSigner</c> in the sandbox, validated, and checked against what
/// was asked (content type, signers, countersignature, timestamp, policy, extended attributes).
/// </summary>
internal sealed class CadesMatrix(CadesRunner runner, CadesSampleStore samples, CredentialStore credentials, CredentialFactory factory) : IDisposable
{
    private static readonly string[] Signers = ["rsa-2048", "rsa-3072", "ecdsa-p256", "ecdsa-p384"];
    private readonly SemaphoreSlim _gate = new(1, 1);
    private Dictionary<string, (string Id, CredentialFacts Facts)>? _credentials;
    private IReadOnlyList<MatrixCase>? _cases;
    private int _uncoverable;

    private sealed record Dimension(string Name, IReadOnlyList<(string Value, Func<CadesOptions, Func<string, string>, CadesOptions> Apply)> Values);

    private static IReadOnlyList<Dimension> Dimensions()
    {
        static (string, Func<CadesOptions, Func<string, string>, CadesOptions>) V(string value, Func<CadesOptions, Func<string, string>, CadesOptions> apply) => (value, apply);
        return
        [
            new("signer", [.. Signers.Select(s => V(s, (o, _) => o))]),
            new("data", [V("text", (o, f) => o with { DataId = f("text") }), V("json", (o, f) => o with { DataId = f("json") }), V("pdf", (o, f) => o with { DataId = f("pdf") })]),
            new("operation",
            [
                V("sign", (o, _) => o),
                V("cosign-detached", (o, f) => o with { Operation = CadesOperation.CoSign, ExistingSignatureId = f("detached") }),
                V("cosign-enveloped", (o, f) => o with { Operation = CadesOperation.CoSign, ExistingSignatureId = f("enveloped") }),
                V("countersign-detached", (o, f) => o with { Operation = CadesOperation.CounterSign, ExistingSignatureId = f("detached") }),
                V("countersign-enveloped", (o, f) => o with { Operation = CadesOperation.CounterSign, ExistingSignatureId = f("enveloped") }),
            ]),
            new("contentType", [V("Detached", (o, _) => o), V("Enveloped", (o, _) => o with { ContentType = CadesContentChoice.Enveloped })]),
            new("type",
            [
                V("B-B", (o, _) => o),
                V("B-T", (o, _) => o with { Level = BaselineLevel.BT }),
                V("B-LT", (o, _) => o with { Level = BaselineLevel.BLT }),
                V("B-LTA", (o, _) => o with { Level = BaselineLevel.BLTA }),
                V("custom-policy", (o, _) => o with { Kind = CadesKind.CustomPolicy, PolicyOid = "1.2.3.4.5", PolicyUri = "https://example.com/policy.der" }),
            ]),
            new("extended", [.. Enum.GetValues<CadesExtendedChoice>().Select(e => V(e.ToString(), (o, _) => o with { ExtendedForm = e }))]),
            new("hash", [.. HashValues().Select(h => V(h.ToString(), (o, _) => o with { Hash = h }))]),
            new("padding", [V("Pkcs1", (o, _) => o), V("Pss", (o, _) => o with { Padding = RsaPadding.Pss })]),
            new("details",
            [
                V("none", (o, _) => o),
                V("commitment+time+operation", (o, _) => o with { Commitment = "ProofOfOrigin", SigningTime = DateTimeOffset.UtcNow.AddMinutes(-5), OperationId = "matrix" }),
                V("location+roles+content+crl-first", (o, _) => o with
                {
                    SignerCountry = "BR",
                    SignerLocality = "Recife",
                    SignerPostalAddress = ["Rua da Aurora, 1", "50050-000"],
                    SignerRoles = ["Diretor"],
                    MimeType = "text/plain",
                    ContentDescription = "Matrix content",
                    RevocationPreference = Core.Signing.RevocationPreference.CrlFirst,
                }),

                // Any stored file serves as the policy document: its hash goes in the policy identifier.
                V("content-timestamp+policy-store", (o, f) => o with { ContentTimestamp = true, PolicyDocumentId = f("json") }),
            ]),
        ];
    }

    public void Dispose() => _gate.Dispose();

    public IReadOnlyList<MatrixCase> Cases()
    {
        EnsureCases();
        return _cases!;
    }

    public async Task<MatrixRunResult> RunAsync(MatrixRunRequest request, CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            EnsureCases();
            var cases = _cases!.Where(c => request.CaseId is null ? request.Group == "all" || c.Group == request.Group : c.Id == request.CaseId)
                .Take(request.Limit ?? int.MaxValue).ToList();
            var results = new List<MatrixCaseResult>();
            var total = Stopwatch.StartNew();
            foreach (var matrixCase in cases)
            {
                results.Add(await RunCaseAsync(matrixCase, cancellationToken));
            }

            return new MatrixRunResult(results.Count, results.Count(r => r.Status == "pass"), results.Count(r => r.Status == "fail"),
                results.Count(r => r.Status == "skip"), total.ElapsedMilliseconds, _uncoverable, results);
        }
        finally
        {
            _gate.Release();
        }
    }

    internal CadesOptions Build(IReadOnlyDictionary<string, string> values)
    {
        var options = new CadesOptions { CredentialId = _credentials![values["signer"]].Id };
        string File(string id) => samples.Samples.Single(s => s.Id == id).FileId;
        foreach (var dimension in Dimensions())
        {
            options = dimension.Values.First(v => v.Value == values[dimension.Name]).Apply(options, File);
        }

        return options;
    }

    private void EnsureCases()
    {
        if (_cases is not null)
        {
            return;
        }

        _credentials = Signers.ToDictionary(s => s, s =>
        {
            var handle = credentials.Add(factory.OpenSandbox(new SandboxCredentialRequest(s)));
            return (handle.Id, handle.Facts);
        }, StringComparer.Ordinal);
        var dims = Dimensions();
        Dictionary<string, string> Map(string[] values) => dims.Select((d, i) => (d.Name, values[i])).ToDictionary(p => p.Name, p => p.Item2, StringComparer.Ordinal);
        bool Valid(string[] values)
        {
            var options = Build(Map(values));
            return CadesCompatibility.Evaluate(options, runner.Inputs(options), _credentials[values[0]].Facts).CanSign;
        }

        var generated = Pairwise.Generate([.. dims.Select(d => (IReadOnlyList<string>)[.. d.Values.Select(v => v.Value)])], Valid, 250, out _uncoverable);
        _cases = [.. generated.Select((c, i) => new MatrixCase($"C{c.Group[0]}{i + 1:D3}", c.Group, Map(c.Values)))];
    }

    private async Task<MatrixCaseResult> RunCaseAsync(MatrixCase matrixCase, CancellationToken cancellationToken)
    {
        var options = Build(matrixCase.Values);
        var watch = Stopwatch.StartNew();
        var result = await runner.RunAsync(options, cancellationToken);
        var checks = new List<string>();
        string? failure = result.Success ? Expect(result, runner.Evaluate(options), matrixCase.Values, checks) : result.Error;
        return new MatrixCaseResult(matrixCase.Id, matrixCase.Group, matrixCase.Values, failure is null ? "pass" : "fail", watch.ElapsedMilliseconds,
            failure, result.AchievedLevel, checks);
    }

    /// <summary>The requested facts must hold in the output.</summary>
    internal static string? Expect(CadesSignResult result, CadesOptionsReport report, IReadOnlyDictionary<string, string> values, List<string> checks)
    {
        var o = report.Effective;
        var view = result.Validation;
        if (view is null)
        {
            return "no validation";
        }

        if (view.Overall != "Valid")
        {
            var errors = view.Errors.Concat(view.Signers.SelectMany(s => s.Errors.Concat(s.CounterSignatures.SelectMany(c => c.Errors))));
            return $"validation {view.Overall}: {string.Join("; ", errors)}";
        }

        checks.Add("valid");
        var structure = view.Structure;
        if (structure.IsDetached != (o.ContentType == CadesContentChoice.Detached))
        {
            return $"content type: expected {o.ContentType}, file is {(structure.IsDetached ? "detached" : "enveloped")}";
        }

        checks.Add(o.ContentType.ToString());
        int expectedSigners = o.Operation == CadesOperation.CoSign ? 2 : 1;
        if (structure.Signers.Count != expectedSigners)
        {
            return $"signers: expected {expectedSigners}, got {structure.Signers.Count}";
        }

        var mine = o.Operation switch
        {
            CadesOperation.CoSign => structure.Signers[1],
            CadesOperation.CounterSign => structure.Signers[0].CounterSignatures.LastOrDefault(),
            _ => structure.Signers[0],
        };
        if (mine is null)
        {
            return "no countersignature on the signer";
        }

        checks.Add(o.Operation.ToString());
        bool needsTsa = o.Level != BaselineLevel.BB;
        if (mine.HasSignatureTimestamp != needsTsa)
        {
            return $"signature timestamp: expected {needsTsa}";
        }

        if (needsTsa)
        {
            checks.Add("timestamp");
        }

        if (o.Kind != CadesKind.Baseline && mine.PolicyOid is null)
        {
            return "policy OID missing";
        }

        string? attribute = o.ExtendedForm switch
        {
            CadesExtendedChoice.CompleteReferences => "esc-time-stamp (CAdES-C timestamp)",
            CadesExtendedChoice.ExtendedLong => "certificate-values",
            CadesExtendedChoice.Archive => "archive-time-stamp-v2",
            _ => null,
        };
        if (attribute is not null && mine.UnsignedAttributes.All(a => a.Name != attribute))
        {
            return $"{o.ExtendedForm}: {attribute} missing";
        }

        if (attribute is not null)
        {
            checks.Add(o.ExtendedForm.ToString());
        }

        if (o.Padding == RsaPadding.Pss && values["signer"].StartsWith("rsa", StringComparison.Ordinal) && mine.SignatureAlgorithm != "RSASSA-PSS")
        {
            return $"padding: expected RSASSA-PSS, got {mine.SignatureAlgorithm}";
        }

        string digest = o.Hash switch
        {
            HashChoice.Sha384 => "SHA-384",
            HashChoice.Sha512 => "SHA-512",
            HashChoice.Sha3_256 => "SHA3-256",
            HashChoice.Sha3_384 => "SHA3-384",
            HashChoice.Sha3_512 => "SHA3-512",
            _ => "SHA-256",
        };
        if (mine.DigestAlgorithm != digest)
        {
            return $"digest: expected {digest}, got {mine.DigestAlgorithm}";
        }

        checks.Add(digest);
        var expectations = new (bool Asked, bool Present, string Name)[]
        {
            (o.SignerCountry is not null || o.SignerLocality is not null || o.SignerPostalAddress.Count > 0, Signed("signer-location"), "signer-location"),
            (o.SignerRoles.Count > 0, Signed("signer-attributes-v2"), "signer-attributes-v2"),
            (o.MimeType is not null, Signed("mime-type"), "mime-type"),
            (o.ContentDescription is not null, Signed("content-hints"), "content-hints"),
            (o.ContentTimestamp, Signed("content-time-stamp"), "content-time-stamp"),
            (o.Kind == CadesKind.CustomPolicy && !string.IsNullOrEmpty(o.PolicyDocumentId), mine.UnsignedAttributes.Any(a => a.Name == "signature-policy-store"), "signature-policy-store"),
        };
        foreach (var (asked, present, name) in expectations)
        {
            if (asked && !present)
            {
                return $"{name} missing";
            }

            if (asked)
            {
                checks.Add(name);
            }
        }

        return null;

        bool Signed(string name) => mine.SignedAttributes.Any(a => a.Name == name);
    }

    private static IEnumerable<HashChoice> HashValues() =>
        SHA3_256.IsSupported ? Enum.GetValues<HashChoice>() : [HashChoice.Sha256, HashChoice.Sha384, HashChoice.Sha512];
}

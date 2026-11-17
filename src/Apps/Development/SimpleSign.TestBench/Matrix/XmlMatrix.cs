using System.Diagnostics;
using SimpleSign.TestBench.Credentials;
using SimpleSign.TestBench.Signing;
using SimpleSign.TestBench.Xml;

namespace SimpleSign.TestBench.Matrix;

/// <summary>
/// The XML run matrix: XAdES cases generated from <see cref="XmlCompatibility"/> (every value, then
/// pairwise), signed in the sandbox, validated, and checked against what was asked.
/// </summary>
internal sealed class XmlMatrix(XmlRunner runner, XmlSampleStore samples, CredentialStore credentials, CredentialFactory factory) : IDisposable
{
    private static readonly string[] Signers = ["rsa-2048", "rsa-3072", "ecdsa-p256", "ecdsa-p384"];
    private readonly SemaphoreSlim _gate = new(1, 1);
    private Dictionary<string, (string Id, CredentialFacts Facts)>? _credentials;
    private IReadOnlyList<MatrixCase>? _cases;
    private int _uncoverable;

    private sealed record Dimension(string Name, IReadOnlyList<(string Value, Func<XmlOptions, XmlOptions> Apply)> Values);

    private IReadOnlyList<Dimension> Dimensions()
    {
        static (string, Func<XmlOptions, XmlOptions>) V(string value, Func<XmlOptions, XmlOptions> apply) => (value, apply);

        // Any stored file serves as a policy document or as one more signed data object.
        string File(string id) => samples.Samples.Single(s => s.Id == id).FileId;
        return
        [
            new("signer", [.. Signers.Select(s => V(s, o => o))]),
            new("form", [.. Enum.GetValues<XadesFormChoice>().Select(f => V(f.ToString(), o => o with { Form = f }))]),
            new("type",
            [
                V("B-B", o => o),
                V("B-T", o => o with { Level = BaselineLevel.BT }),
                V("B-LT", o => o with { Level = BaselineLevel.BLT }),
                V("B-LTA", o => o with { Level = BaselineLevel.BLTA }),
                V("custom-policy", o => o with { Kind = XadesKind.CustomPolicy, PolicyOid = "1.2.3.4.5", PolicyUri = "https://example.com/policy.xml" }),
            ]),
            new("extended", [.. Enum.GetValues<XadesExtendedChoice>().Select(e => V(e.ToString(), o => o with { ExtendedForm = e }))]),
            new("hash", [.. HashValues().Select(h => V(h.ToString(), o => o with { Hash = h }))]),
            new("padding", [V("Pkcs1", o => o), V("Pss", o => o with { Padding = RsaPadding.Pss })]),
            new("details",
            [
                V("none", o => o),
                V("roles+mime+commitment+time+V1", o => o with
                {
                    SignerRoles = ["Gerente", "Aprovador"],
                    MimeType = "text/xml",
                    Commitment = "ProofOfApproval",
                    SigningTime = DateTimeOffset.UtcNow.AddMinutes(-5),
                    SigningCertificateV1 = true,
                    OperationId = "matrix",
                }),
                V("place+inclusive+crl-first", o => o with
                {
                    PlaceCity = "Recife",
                    PlaceStreet = "Rua da Aurora, 1",
                    PlaceState = "PE",
                    PlacePostalCode = "50050-000",
                    PlaceCountry = "BR",
                    Canonicalization = SimpleSign.XAdES.XadesCanonicalization.Inclusive,
                    RevocationPreference = Core.Signing.RevocationPreference.CrlFirst,
                }),
                V("data-timestamp+objects+policy-store", o => o with
                {
                    DataObjectsTimestamp = true,
                    EmbeddedObjectId = File("v-xades"),
                    ExternalObjectId = File("v-untrusted"),
                    PolicyDocumentId = File("v-changed"),
                    PlaceCity = "Recife",
                }),
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

    internal XmlOptions Build(IReadOnlyDictionary<string, string> values)
    {
        var options = new XmlOptions
        {
            CredentialId = _credentials![values["signer"]].Id,
            DataId = samples.Samples.Single(s => s.Id == "order").FileId,
        };
        foreach (var dimension in Dimensions())
        {
            options = dimension.Values.First(v => v.Value == values[dimension.Name]).Apply(options);
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
            return XmlCompatibility.Evaluate(options, runner.Facts(options.DataId), _credentials[values[0]].Facts).CanSign;
        }

        var generated = Pairwise.Generate([.. dims.Select(d => (IReadOnlyList<string>)[.. d.Values.Select(v => v.Value)])], Valid, 200, out _uncoverable);
        var cases = generated.Select((c, i) => new MatrixCase($"X{c.Group[0]}{i + 1:D3}", c.Group, Map(c.Values))).ToList();

        _cases = cases;
    }

    private async Task<MatrixCaseResult> RunCaseAsync(MatrixCase matrixCase, CancellationToken cancellationToken)
    {
        var options = Build(matrixCase.Values);
        var watch = Stopwatch.StartNew();
        var result = await runner.RunAsync(options, cancellationToken);
        var checks = new List<string>();
        string? failure = result.Success ? Expect(result, runner.Evaluate(options).Effective, checks) : result.Error;
        return new MatrixCaseResult(matrixCase.Id, matrixCase.Group, matrixCase.Values, failure is null ? "pass" : "fail", watch.ElapsedMilliseconds,
            failure, result.AchievedLevel, checks);
    }

    internal static string? Expect(XmlSignResult result, XmlOptions o, List<string> checks)
    {
        var view = result.Validation;
        if (view is null)
        {
            return "no validation";
        }

        if (view.Overall != "Valid")
        {
            return $"validation {view.Overall}: {string.Join("; ", view.Errors.Concat(view.Signatures.SelectMany(s => s.Errors)))}";
        }

        checks.Add("valid");
        if (view.Signatures.Count != 1)
        {
            return $"expected one XAdES signature, got {view.Signatures.Count}";
        }

        string expectedLevel = o.ExtendedForm switch
        {
            XadesExtendedChoice.CompleteReferences => "B-T",
            XadesExtendedChoice.ExtendedLong => "B-LT",
            XadesExtendedChoice.Archive => "B-LTA",
            _ => o.Level switch { BaselineLevel.BB => "B-B", BaselineLevel.BT => "B-T", BaselineLevel.BLT => "B-LT", _ => "B-LTA" },
        };
        if (result.AchievedLevel != expectedLevel)
        {
            return $"level: expected {expectedLevel}, achieved {result.AchievedLevel}";
        }

        checks.Add(expectedLevel);
        if (view.SignatureXml is not { } signature)
        {
            return "no ds:Signature";
        }

        if (o.SignerRoles.Count > 0 && !signature.Contains("ClaimedRole", StringComparison.Ordinal))
        {
            return "signer roles missing";
        }

        if (o.SigningCertificateV1 && signature.Contains("SigningCertificateV2", StringComparison.Ordinal))
        {
            return "expected SigningCertificate (V1)";
        }

        checks.Add(o.Form.ToString());
        return ExpectProperties(signature, o, checks);
    }

    /// <summary>The properties and data objects beyond the baseline that were asked for must be in the signature.</summary>
    private static string? ExpectProperties(string signature, XmlOptions o, List<string> checks)
    {
        bool legacyForm = o.SigningCertificateV1;
        bool hasPlace = o.PlaceCity is not null || o.PlaceStreet is not null || o.PlaceState is not null || o.PlacePostalCode is not null || o.PlaceCountry is not null;
        var expectations = new (bool Asked, string Marker, string Name)[]
        {
            (!legacyForm, "DataObjectFormat", "data object format"),
            (hasPlace, legacyForm ? "SignatureProductionPlace>" : "SignatureProductionPlaceV2", "production place"),
            (o.Canonicalization == SimpleSign.XAdES.XadesCanonicalization.Inclusive, "CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\"", "inclusive canonicalization"),
            (o.DataObjectsTimestamp, "AllDataObjectsTimeStamp", "data objects timestamp"),
            (o.EmbeddedObjectId is not null, "http://www.w3.org/2000/09/xmldsig#base64", "embedded data object"),
            (o.ExternalObjectId is not null, "URI=\"raiz-desconhecida.xml\"", "external data object"),
            (o.Kind == XadesKind.CustomPolicy && !string.IsNullOrEmpty(o.PolicyDocumentId), "SignaturePolicyStore", "policy store"),
        };
        foreach (var (asked, marker, name) in expectations)
        {
            if (asked && !signature.Contains(marker, StringComparison.Ordinal))
            {
                return $"{name} missing";
            }

            if (asked && name != "data object format")
            {
                checks.Add(name);
            }
        }

        return null;
    }

    // XML-DSig as implemented by SimpleSign.XAdES has signature-method URIs for SHA-2 only (XmlDSigUrls):
    // SHA-3 cases cannot be signed, whether or not the platform supports SHA-3 hashing.
    private static IEnumerable<HashChoice> HashValues() => [HashChoice.Sha256, HashChoice.Sha384, HashChoice.Sha512];
}

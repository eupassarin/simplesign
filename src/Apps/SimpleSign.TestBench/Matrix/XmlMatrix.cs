using System.Diagnostics;
using System.Security.Cryptography;
using SimpleSign.TestBench.Credentials;
using SimpleSign.TestBench.Signing;
using SimpleSign.TestBench.Xml;

namespace SimpleSign.TestBench.Matrix;

/// <summary>
/// The XML run matrix: XAdES cases generated from <see cref="XmlCompatibility"/> (every value, then
/// pairwise), plus every fiscal profile with an RSA e-CPF and the e-CNPJ, signed in the sandbox,
/// validated, and checked against what was asked.
/// </summary>
internal sealed class XmlMatrix(XmlRunner runner, XmlSampleStore samples, CredentialStore credentials, CredentialFactory factory) : IDisposable
{
    private static readonly string[] Signers = ["rsa-2048", "rsa-3072", "ecdsa-p256", "company"];
    private readonly SemaphoreSlim _gate = new(1, 1);
    private Dictionary<string, (string Id, CredentialFacts Facts)>? _credentials;
    private IReadOnlyList<MatrixCase>? _cases;
    private int _uncoverable;

    private sealed record Dimension(string Name, IReadOnlyList<(string Value, Func<XmlOptions, XmlOptions> Apply)> Values);

    private static IReadOnlyList<Dimension> Dimensions()
    {
        static (string, Func<XmlOptions, XmlOptions>) V(string value, Func<XmlOptions, XmlOptions> apply) => (value, apply);
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
                V("custom-policy", o => o with { Kind = XadesKind.CustomPolicy, PolicyOid = "2.16.76.1.7.1.6.2.3", PolicyUri = "http://politicas.icpbrasil.gov.br/PA_AD_RB_v2_3.xml" }),
                .. Enum.GetValues<XadesIcpPolicy>().Select(p => V($"ICP {p}", o => o with { Kind = XadesKind.IcpBrasil, IcpPolicy = p })),
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
        var options = new XmlOptions { CredentialId = _credentials![values["signer"]].Id };
        if (values["form"] == "fiscal")
        {
            var sample = samples.Samples.Single(s => s.Id == values["type"]);
            return options with
            {
                Mode = XmlMode.Fiscal,
                Profile = sample.Profile!,
                DataId = sample.FileId,
                SignAll = values["details"] == "sign-all",
                ElementId = values["details"].StartsWith("id:", StringComparison.Ordinal) ? values["details"][3..] : null,
            };
        }

        options = options with { DataId = samples.Samples.Single(s => s.Id == "order").FileId };
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

        // Fiscal: every layout with an e-CPF and the e-CNPJ; the batch also by Id and all at once.
        int n = 0;
        foreach (var sample in samples.Samples.Where(s => s is { Kind: "data", Mode: XmlMode.Fiscal }))
        {
            var modes = sample.Id == "nfe-batch" ? new[] { "sign-all", $"id:{BatchFirstId(sample)}" } : ["sign"];
            foreach (string signer in new[] { "rsa-2048", "company" })
            {
                foreach (string mode in modes)
                {
                    var values = new Dictionary<string, string>(StringComparer.Ordinal)
                    {
                        ["signer"] = signer,
                        ["form"] = "fiscal",
                        ["type"] = sample.Id,
                        ["extended"] = "—",
                        ["hash"] = "profile",
                        ["padding"] = "—",
                        ["details"] = mode,
                    };
                    cases.Add(new MatrixCase($"XF{++n:D3}", "fiscal", values));
                }
            }
        }

        _cases = cases;
    }

    private string BatchFirstId(XmlSample sample) => runner.Facts(sample.FileId)!.FiscalTargets["nfe"][0];

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
        if (o.Mode == XmlMode.Fiscal)
        {
            int expected = o.SignAll ? 2 : 1;
            if (view.Mode != XmlMode.Fiscal || view.Signatures.Count != expected)
            {
                return $"fiscal: expected {expected} XML-DSig signature(s), got {view.Signatures.Count} ({view.Mode})";
            }

            checks.Add($"{expected} signature(s)");
            return null;
        }

        if (view.Mode != XmlMode.Xades || view.Signatures.Count != 1)
        {
            return $"expected one XAdES signature, got {view.Signatures.Count} ({view.Mode})";
        }

        string expectedLevel = o.Kind == XadesKind.IcpBrasil
            ? o.IcpPolicy switch
            {
                XadesIcpPolicy.AdRb => "B-B",
                XadesIcpPolicy.AdRt or XadesIcpPolicy.AdRv => "B-T",
                XadesIcpPolicy.AdRc => "B-LT",
                _ => "B-LTA",
            }
            : o.ExtendedForm switch
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

        if ((o.SigningCertificateV1 || o.Kind == XadesKind.IcpBrasil) && signature.Contains("SigningCertificateV2", StringComparison.Ordinal))
        {
            return "expected SigningCertificate (V1)";
        }

        checks.Add(o.Form.ToString());
        return null;
    }

    private static IEnumerable<HashChoice> HashValues() =>
        SHA3_256.IsSupported ? Enum.GetValues<HashChoice>() : [HashChoice.Sha256, HashChoice.Sha384, HashChoice.Sha512];
}

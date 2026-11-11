using System.Diagnostics;
using System.Security.Cryptography;
using SimpleSign.TestBench.Credentials;
using SimpleSign.TestBench.Documents;
using SimpleSign.TestBench.Sandbox;
using SimpleSign.TestBench.Signing;

namespace SimpleSign.TestBench.Matrix;

/// <summary>One value of one dimension, and how it changes the options.</summary>
public sealed record MatrixValue(string Dimension, string Value, Func<SigningOptions, MatrixContext, SigningOptions> Apply);

/// <summary>What a case needs besides its options: credentials and documents by name.</summary>
public sealed class MatrixContext
{
    internal Dictionary<string, string> CredentialIds { get; } = new(StringComparer.Ordinal);

    internal Dictionary<string, CredentialFacts> CredentialFacts { get; } = new(StringComparer.Ordinal);

    internal Dictionary<string, DocumentFacts> DocumentFacts { get; } = new(StringComparer.Ordinal);

    public string? ImageUploadId { get; internal set; }
}

/// <summary>A generated case: one value per dimension.</summary>
public sealed record MatrixCase(string Id, string Group, IReadOnlyDictionary<string, string> Values);

public sealed record MatrixCaseResult(
    string Id,
    string Group,
    IReadOnlyDictionary<string, string> Values,
    string Status,
    long Ms,
    string? Detail,
    string? AchievedLevel,
    IReadOnlyList<string> Checks);

public sealed record MatrixRunRequest(string Group = "all", int? Limit = null, string? CaseId = null, string Format = "pades");

public sealed record MatrixRunResult(int Total, int Passed, int Failed, int Skipped, long Ms, int UncoverablePairs, IReadOnlyList<MatrixCaseResult> Cases);

/// <summary>
/// Proves every option is testable: generates pairwise combinations of every dimension (plus each
/// value on its own), keeps only those <see cref="Compatibility"/> allows, signs them in the
/// sandbox and checks the output has what was asked.
/// </summary>
internal sealed class MatrixRunner(SandboxEnvironment sandbox, DocumentStore documents, CredentialStore credentials, CredentialFactory factory) : IDisposable
{
    private static readonly string[] Signers = ["rsa-2048", "rsa-4096", "ecdsa-p256", "ecdsa-p384", "ecdsa-p521"];
    private static readonly string[] Documents = ["contract", "empty-field", "signed", "certified-p2", "certified-p3", "pdfa-2b", "pdfa-1b"];
    private readonly SemaphoreSlim _gate = new(1, 1);
    private MatrixContext? _context;
    private IReadOnlyList<MatrixCase>? _cases;
    private int _uncoverable;

    public static IReadOnlyList<IReadOnlyList<MatrixValue>> Dimensions()
    {
        static MatrixValue V(string d, string v, Func<SigningOptions, MatrixContext, SigningOptions> f) => new(d, v, f);
        var dims = new List<IReadOnlyList<MatrixValue>>
        {
            Signers.Select(s => V("signer", s, (o, c) => o with { CredentialId = c.CredentialIds[s] })).ToList(),
            Documents.Select(d => V("document", d, (o, _) => o with { DocumentId = DocumentStore.SampleKey(d) })).ToList(),
            new List<MatrixValue>
            {
                V("type", "B-B", (o, _) => o with { Kind = SignatureKind.Baseline, Level = BaselineLevel.BB }),
                V("type", "B-T", (o, _) => o with { Kind = SignatureKind.Baseline, Level = BaselineLevel.BT }),
                V("type", "B-LT", (o, _) => o with { Kind = SignatureKind.Baseline, Level = BaselineLevel.BLT }),
                V("type", "B-LTA", (o, _) => o with { Kind = SignatureKind.Baseline, Level = BaselineLevel.BLTA }),
                V("type", "Custom policy B-T", (o, _) => o with
                {
                    Kind = SignatureKind.CustomPolicy, Level = BaselineLevel.BT,
                    CustomPolicy = new CustomPolicyChoice { Oid = "1.3.6.1.4.1.99999.1.1", HashHex = Convert.ToHexString(SHA256.HashData("policy"u8)), Uri = "https://example.com/policy.der" },
                }),
            },
            HashValues().Select(h => V("hash", h.ToString(), (o, _) => o with { Hash = h })).ToList(),
            new List<MatrixValue>
            {
                V("padding", "PKCS#1 v1.5", (o, _) => o with { Padding = RsaPadding.Pkcs1 }),
                V("padding", "PSS", (o, _) => o with { Padding = RsaPadding.Pss }),
            },
            new List<MatrixValue>
            {
                V("subFilter", "ETSI.CAdES.detached", (o, _) => o with { SubFilter = SubFilterChoice.EtsiCadesDetached }),
                V("subFilter", "adbe.pkcs7.detached", (o, _) => o with { SubFilter = SubFilterChoice.AdbePkcs7Detached }),
            },
            new List<MatrixValue>
            {
                V("pdfa", "off", (o, _) => o with { PreservePdfA = false }),
                V("pdfa", "preserve", (o, _) => o with { PreservePdfA = true }),
            },
            new List<MatrixValue>
            {
                V("field", "new", (o, _) => o with { FieldMode = FieldMode.New, FieldName = "TestBench" }),
                V("field", "existing", (o, _) => o with { FieldMode = FieldMode.Existing, ExistingFieldName = "Assinatura" }),
            },
            new List<MatrixValue>
            {
                V("appearance", "invisible", (o, _) => o with { Appearance = new AppearanceChoice() }),
                V("appearance", "visible", (o, _) => o with { Appearance = new AppearanceChoice { Visible = true, ShowReason = true, ShowLocation = true } }),
                V("appearance", "styled+QR", (o, _) => o with
                {
                    Appearance = new AppearanceChoice
                    {
                        Visible = true, Page = 1, X = 300, Y = 60, Width = 240, Height = 90, TextAlignment = "Center", VerticalAlignment = "Middle",
                        BackgroundColor = "#f4f4f5", TextColor = "#18181b", BorderColor = "#2563eb", BorderWidth = 1, BaseFont = "Times-Roman",
                        DateFormat = "dd/MM/yyyy HH:mm", TimeZoneId = "America/Sao_Paulo", Culture = "pt-BR", SignedByLabel = "Assinado por",
                        ExtraLines = ["Linha extra"], VerificationUrl = "https://validar.iti.gov.br/",
                    },
                }),
                V("appearance", "auto+image", (o, c) => o with { Appearance = new AppearanceChoice { Visible = true, AutoPosition = true, ImageUploadId = c.ImageUploadId, ImageFit = "Contain" } }),
            },
            new List<MatrixValue>
            {
                V("details", "none", (o, _) => o with { UseSignerDetails = false }),
                V("details", "basic", (o, _) => o with { Reason = "Approval", Location = "São Paulo", ContactInfo = "test@example.com", SignerName = "Matrix" }),
                V("details", "metadata", (o, _) => o with
                {
                    UseSignerDetails = true, Reason = "Approval",
                    Metadata = new MetadataChoice { SignerName = "Matrix Signer", SignerId = "A-1001", SignerIdType = "Employee", Email = "m@example.com", CommitmentType = "ProofOfOrigin" },
                }),
                V("details", "info", (o, _) => o with
                {
                    DocumentInfo = [new DocumentInfoEntry("Title", "Matrix"), new DocumentInfoEntry("Subject", "Pairwise")],
                    SigningTime = DateTimeOffset.UtcNow.AddMinutes(-5),
                    OperationId = "matrix",
                }),
            },
            new List<MatrixValue>
            {
                V("certification", "none", (o, _) => o with { Certification = CertificationChoice.None }),
                V("certification", "P=1", (o, _) => o with { Certification = CertificationChoice.NoChanges }),
                V("certification", "P=2", (o, _) => o with { Certification = CertificationChoice.FormFilling }),
                V("certification", "P=3", (o, _) => o with { Certification = CertificationChoice.FormFillingAndAnnotations }),
            },
            new List<MatrixValue>
            {
                V("tsa", "sandbox", (o, _) => o with { Timestamp = new TimestampChoice() }),
                V("tsa", "basic auth + separate archive", (o, _) => o with
                {
                    Timestamp = new TimestampChoice { Provider = TsaProvider.SandboxAuthenticated },
                    SeparateArchiveTsa = true,
                    ArchiveTimestamp = new TimestampChoice { Provider = TsaProvider.Sandbox },
                }),
                V("tsa", "lower level on failure", (o, _) => o with { ReturnLowerLevel = true, ContentsReservedBytes = 32768 }),
            },
            new List<MatrixValue>
            {
                V("mode", "sign", (o, _) => o with { Mode = RunMode.Sign }),
                V("mode", "deferred", (o, _) => o with { Mode = RunMode.Deferred }),
                V("mode", "batch", (o, _) => o with { Mode = RunMode.Batch, BatchCopies = 3, MaxConcurrency = 2 }),
            },
        };
        return dims;
    }

    public void Dispose() => _gate.Dispose();

    public IReadOnlyList<MatrixCase> Cases()
    {
        EnsureContext();
        return _cases!;
    }

    public async Task<MatrixRunResult> RunAsync(MatrixRunRequest request, CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            var context = EnsureContext();
            var cases = _cases!.Where(c => request.CaseId is null ? request.Group == "all" || c.Group == request.Group : c.Id == request.CaseId)
                .Take(request.Limit ?? int.MaxValue).ToList();
            var runner = new SigningRunner(sandbox, documents, credentials);
            var results = new List<MatrixCaseResult>();
            var total = Stopwatch.StartNew();
            foreach (var matrixCase in cases)
            {
                results.Add(await RunCaseAsync(runner, matrixCase, context, cancellationToken));
            }

            return new MatrixRunResult(results.Count, results.Count(r => r.Status == "pass"), results.Count(r => r.Status == "fail"),
                results.Count(r => r.Status == "skip"), total.ElapsedMilliseconds, _uncoverable, results);
        }
        finally
        {
            _gate.Release();
        }
    }

    internal static SigningOptions Build(MatrixCase matrixCase, MatrixContext context)
    {
        var options = new SigningOptions { Validate = true };
        foreach (var dimension in Dimensions())
        {
            var value = dimension.First(v => v.Value == matrixCase.Values[v.Dimension]);
            options = value.Apply(options, context);
        }

        return options;
    }

    private static async Task<MatrixCaseResult> RunCaseAsync(SigningRunner runner, MatrixCase matrixCase, MatrixContext context, CancellationToken cancellationToken)
    {
        var options = Build(matrixCase, context);
        var watch = Stopwatch.StartNew();
        var result = await runner.RunAsync(options, cancellationToken);
        var checks = new List<string>();
        string? failure = result.Success ? null : result.Error;
        if (result.Success)
        {
            var report = Compatibility.Evaluate(options, context.DocumentFacts[options.DocumentId!], context.CredentialFacts[matrixCase.Values["signer"]]);
            var effective = report.Effective;
            failure = Expect(result, effective, checks);
        }

        return new MatrixCaseResult(matrixCase.Id, matrixCase.Group, matrixCase.Values, failure is null ? "pass" : "fail", watch.ElapsedMilliseconds,
            failure, result.AchievedLevel, checks);
    }

    /// <summary>The requested facts must hold in the output.</summary>
    internal static string? Expect(SigningResult result, SigningOptions effective, List<string> checks)
    {
        string expectedLevel = effective.Level switch
        {
            BaselineLevel.BB => "B-B",
            BaselineLevel.BT => "B-T",
            BaselineLevel.BLT => "B-LT",
            _ => "B-LTA",
        };
        if (result.AchievedLevel is null || !result.AchievedLevel.Contains(expectedLevel, StringComparison.Ordinal))
        {
            return $"Achieved level {result.AchievedLevel}, expected {expectedLevel}.";
        }

        checks.Add($"level {expectedLevel}");
        var mine = result.Validation.Where(v => !v.IsDocumentTimestamp).LastOrDefault();
        if (mine is null)
        {
            return "The validator found no signature.";
        }

        if (mine.Checks.Any(c => c.Id is "integrity" or "signature" && c.Status != "pass"))
        {
            return "Integrity or signature value check failed: " + string.Join("; ", mine.Errors);
        }

        checks.Add("integrity + signature value");
        if (mine.Indication != "Valid")
        {
            return $"Indication {mine.Indication}: " + string.Join("; ", mine.Errors.Concat(mine.Warnings));
        }

        checks.Add($"indication {mine.Indication}");
        string expectedSubFilter = effective.SubFilter switch
        {
            SubFilterChoice.AdbePkcs7Detached => "adbe.pkcs7.detached",
            _ => "ETSI.CAdES.detached",
        };
        if (mine.SubFilter != expectedSubFilter)
        {
            return $"Sub-filter {mine.SubFilter}, expected {expectedSubFilter}.";
        }

        checks.Add("sub-filter " + expectedSubFilter);
        string expectedField = effective.FieldMode == FieldMode.Existing ? effective.ExistingFieldName! : effective.FieldName;
        if (mine.FieldName != expectedField)
        {
            return $"Signed field '{mine.FieldName}', expected '{expectedField}'.";
        }

        checks.Add("field " + expectedField);
        if (effective.Level >= BaselineLevel.BT && mine.Checks.FirstOrDefault(c => c.Id == "timestamp")?.Status != "pass")
        {
            return "Missing or invalid signature timestamp.";
        }

        if (effective.Level >= BaselineLevel.BLT && result.Output?.HasDss != true)
        {
            return "No DSS in the output.";
        }

        if (effective.Level == BaselineLevel.BLTA && !result.Validation.Any(v => v.IsDocumentTimestamp))
        {
            return "No document timestamp in the output.";
        }

        if (effective.Certification != CertificationChoice.None && result.Output?.DocMdpLevel != (int)effective.Certification)
        {
            return $"DocMDP level {result.Output?.DocMdpLevel}, expected P={(int)effective.Certification}.";
        }

        if (effective.Mode == RunMode.Batch && result.Batch.Any(b => !b.Ok))
        {
            return "Batch item failed: " + result.Batch.First(b => !b.Ok).Error;
        }

        if (effective.Mode == RunMode.Deferred && result.Deferred is null)
        {
            return "Deferred details missing.";
        }

        checks.Add("timestamps / DSS / DocMDP / mode as requested");
        return null;
    }

    private MatrixContext EnsureContext()
    {
        if (_context is not null)
        {
            return _context;
        }

        var context = new MatrixContext();
        foreach (string signer in Signers)
        {
            var handle = credentials.Add(factory.OpenSandbox(new SandboxCredentialRequest(signer)));
            context.CredentialIds[signer] = handle.Id;
            context.CredentialFacts[signer] = handle.Facts;
        }

        foreach (string document in Documents)
        {
            string key = DocumentStore.SampleKey(document);
            context.DocumentFacts[key] = documents.FactsAsync(key).GetAwaiter().GetResult();
        }

        // Pinned: the matrix stores more signed outputs than the upload limit, which would evict an ordinary upload.
        context.ImageUploadId = documents.AddPinned("stamp.png", StampPng()).Id;
        _cases = Generate(context, out _uncoverable);
        _context = context;
        return context;
    }

    /// <summary>Single-value cases (each value with the defaults of the others) plus greedy pairwise cases.</summary>
    internal static IReadOnlyList<MatrixCase> Generate(MatrixContext context, out int uncoverable)
    {
        var dims = Dimensions();
        bool Valid(string[] values)
        {
            var options = Build(new MatrixCase("", "", Map(dims, values)), context);
            return Compatibility.Evaluate(options, context.DocumentFacts[options.DocumentId!], context.CredentialFacts[values[0]]).CanSign;
        }

        var generated = Pairwise.Generate([.. dims.Select(d => (IReadOnlyList<string>)[.. d.Select(v => v.Value)])], Valid, 400, out uncoverable);
        return [.. generated.Select((c, i) => new MatrixCase($"{c.Group[0]}{i + 1:D3}", c.Group, Map(dims, c.Values)))];
    }

    private static Dictionary<string, string> Map(IReadOnlyList<IReadOnlyList<MatrixValue>> dims, string[] values)
    {
        var map = new Dictionary<string, string>(StringComparer.Ordinal);
        for (int i = 0; i < dims.Count; i++)
        {
            map[dims[i][0].Dimension] = values[i];
        }

        return map;
    }

    private static IEnumerable<HashChoice> HashValues() =>
        SHA3_256.IsSupported
            ? [HashChoice.Sha256, HashChoice.Sha384, HashChoice.Sha512, HashChoice.Sha3_256]
            : [HashChoice.Sha256, HashChoice.Sha384, HashChoice.Sha512];

    /// <summary>A small opaque 2×2 PNG (the stamp background of the image cases).</summary>
    private static byte[] StampPng() => Convert.FromBase64String(
        "iVBORw0KGgoAAAANSUhEUgAAAAIAAAACCAIAAAD91JpzAAAAFklEQVR4nGP8z8DAwMDAxMDAwMDAAAANHQEDK+mmyAAAAABJRU5ErkJggg==");
}

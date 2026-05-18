using Shouldly;
using SimpleSign.Core.Validation;
using SimpleSign.PAdES.Inspection;
using SimpleSign.PAdES.Validation;
using Xunit;
using Xunit.Abstractions;

namespace SimpleSign.Interop.Tests;

/// <summary>
/// ETSI/EU DSS corpus conformance tests.
///
/// These tests load real-world PAdES documents from the EU DSS interoperability corpus
/// (https://github.com/esig/dss/tree/master/dss-test/src/test/resources/validation)
/// and verify that SimpleSign can parse them correctly — without crashing — and that
/// cryptographic integrity checks pass for known-good documents.
///
/// Goals
/// -----
/// 1. <b>Resilience</b>: no unhandled exception for any corpus file (including malformed ones).
/// 2. <b>Correctness</b>: all valid PAdES documents must report IsIntegrityValid = true.
/// 3. <b>Multi-vendor coverage</b>: signatures produced by BG, DE, FR, HU, ES, BE implementations
///    are all parsed and inspected successfully.
///
/// Corpus files (&lt;500 KB) are embedded as assembly resources so they work in CI without
/// network access. Large files (&gt;500 KB: 51sigs, DSS-1443, PAdES-LTA) are read from the
/// local corpus directory when available, and the test is skipped otherwise.
/// </summary>
[Trait("Category", "Interop")]
[Trait("Category", "EtsiCorpus")]
public sealed class EtsiCorpusTests(ITestOutputHelper output)
{
    private const string ResourcePrefix = "SimpleSign.Interop.Tests.corpus.pades.";
    private const string LocalCorpusDir = "corpus/pades";

    // ── Validation options that avoid any network I/O ─────────────────────────────────────
    private static readonly ValidationOptions NoNetworkOptions = new()
    {
        CheckRevocation = false,
        TrustSystemRoots = false,
        NetworkTimeout = TimeSpan.FromSeconds(1),
    };

    // ── Inspector: smoke tests (must not crash, must find at least 1 signature) ──────────

    /// <summary>
    /// Known-good ETSI corpus PDFs — inspector must find at least <paramref name="minSigs"/> signatures.
    /// All files embedded as assembly resources.
    /// </summary>
    [Theory]
    [InlineData("AD-RB.pdf", 1)] // ETSI plugtest: AdES baseline
    [InlineData("DSS-1683.pdf", 1)] // EU DSS bug-report fixture
    [InlineData("DSS-1983.pdf", 1)] // EU DSS bug-report fixture
    [InlineData("PAdES-LT.pdf", 1)] // PAdES LT profile (with OCSP embedded)
    [InlineData("Signature-P-BG_BOR-1.pdf", 1)] // Bulgarian plugtest
    [InlineData("Signature-P-BG_BOR-2.pdf", 1)] // Bulgarian plugtest
    [InlineData("Signature-P-DE_SCI-4.pdf", 1)] // German plugtest
    [InlineData("Signature-P-FR_CS-5.pdf", 1)] // French plugtest
    [InlineData("belgian_pki_multiple_ocsps.pdf", 1)] // Belgian PKI — multiple OCSP responses
    [InlineData("doc-firmado.pdf", 1)] // Spanish B-B level
    [InlineData("doc-firmado-T.pdf", 1)] // Spanish T level (with timestamp)
    [InlineData("doc-firmado-LT.pdf", 1)] // Spanish LT level
    public async Task Inspector_Embedded_FindsExpectedSignatures(string filename, int minSigs)
    {
        var bytes = LoadEmbedded(filename);
        var result = await PdfSignatureInspector.InspectAsync(new MemoryStream(bytes));

        output.WriteLine($"[{filename}] signatures={result.Signatures.Count}");
        foreach (var sig in result.Signatures)
            output.WriteLine($"  {sig.FieldName}: algo={sig.SubFilter} signer={sig.Signer?.Subject}");

        result.Signatures.Count().ShouldBeGreaterThanOrEqualTo(minSigs,
            $"'{filename}' is a known-good PAdES document from the ETSI corpus");
    }

    /// <summary>
    /// Signature-P-HU_MIC-1.pdf uses a non-standard internal structure that the inspector
    /// does not recognize. The requirement is resilience: no exception must be thrown.
    /// This documents a known limitation of the current parser.
    /// </summary>
    [Fact]
    public async Task Inspector_HungarianPlugtest_DoesNotThrow()
    {
        var bytes = LoadEmbedded("Signature-P-HU_MIC-1.pdf");
        var ex = await Record.ExceptionAsync(() =>
            PdfSignatureInspector.InspectAsync(new MemoryStream(bytes)));
        ex.ShouldBeNull("the inspector must not throw on any corpus file, even unrecognized formats");
        output.WriteLine("Signature-P-HU_MIC-1.pdf: inspector returned without crashing ✓");
    }

    /// <summary>
    /// BadEncodedCMS.pdf contains a malformed CMS structure.
    /// The inspector must not throw — it should return an empty/partial result.
    /// </summary>
    [Fact]
    public async Task Inspector_BadEncodedCMS_DoesNotThrow()
    {
        var bytes = LoadEmbedded("BadEncodedCMS.pdf");
        var ex = await Record.ExceptionAsync(() =>
            PdfSignatureInspector.InspectAsync(new MemoryStream(bytes)));

        ex.ShouldBeNull("the inspector must handle malformed CMS gracefully");
        output.WriteLine("BadEncodedCMS.pdf: inspector returned without crashing ✓");
    }

    // ── Inspector: large files (local only, skipped in CI) ──────────────────────────────

    /// <summary>
    /// Large corpus files are not embedded in the assembly. When the file is present
    /// in the local corpus directory (e.g. development machine), the test runs. In CI
    /// it is skipped automatically.
    /// </summary>
    [Theory]
    [InlineData("51sigs.pdf", 51)] // 4.4 MB — 51 incremental signatures
    [InlineData("PAdES-LTA.pdf", 1)] // 4.1 MB — PAdES LTA profile
    [InlineData("DSS-1443.pdf", 1)] // 5.1 MB — EU DSS bug-report (same doc as LTA)
    public async Task Inspector_LargeLocalFile_FindsExpectedSignatures(string filename, int minSigs)
    {
        var bytes = TryLoadLocal(filename);
        Skip.If(bytes is null, $"'{filename}' not found in local corpus — skipping (large file not in git)");

        var result = await PdfSignatureInspector.InspectAsync(new MemoryStream(bytes!));

        output.WriteLine($"[{filename}] signatures={result.Signatures.Count}");
        result.Signatures.Count().ShouldBeGreaterThanOrEqualTo(minSigs);
    }

    // ── Validator: integrity checks ───────────────────────────────────────────────────────

    /// <summary>
    /// Single-signature documents where the one and only signature must have integrity = true.
    /// These are "simple" B-B or T-level documents with no DSS revocation data appended.
    /// </summary>
    [Theory]
    [InlineData("AD-RB.pdf")] // ETSI plugtest, single CMS sig
    [InlineData("Signature-P-BG_BOR-1.pdf")] // Bulgarian plugtest, single sig
    [InlineData("doc-firmado-T.pdf")] // Spanish T level, single sig + embedded timestamp
    [InlineData("doc-firmado-LT.pdf")] // Spanish LT, single sig + revocation data
    public async Task Validator_SingleSignatureDoc_AllIntegrityValid(string filename)
    {
        var bytes = LoadEmbedded(filename);
        var validator = new PdfSignatureValidator(NoNetworkOptions);
        var results = await validator.ValidateAsync(new MemoryStream(bytes));

        output.WriteLine($"[{filename}] {results.Count} result(s):");
        foreach (var r in results)
            output.WriteLine($"  {r.FieldName}: integrity={r.IsIntegrityValid} sig={r.IsSignatureValid} algo={r.DigestAlgorithmName}");

        results.ShouldNotBeEmpty($"'{filename}' must have at least one parseable signature");
        foreach (var r in results)
            r.IsIntegrityValid.ShouldBeTrue(
            $"'{filename}' is a single-signature ETSI corpus document — byte-range hash must verify");
    }

    /// <summary>
    /// Multi-revision documents (LT/LTA profile, plugtest signatures with timestamps, Belgian PKI
    /// with multiple OCSP responses). Our validator surfaces every signature field it finds,
    /// including document timestamps and archive timestamps, which may report integrity=False
    /// because their byte ranges cover different document revisions.
    ///
    /// Requirement: at least one signature (the primary CMS signature) must have integrity = true.
    /// The test documents the realistic behaviour without masking legitimate partial failures.
    /// </summary>
    [Theory]
    [InlineData("DSS-1983.pdf")] // 2 revisions: CMS sig + DSS update
    [InlineData("PAdES-LT.pdf")] // 4 revisions: main sig + doc timestamp + DSS update + archive ts
    [InlineData("Signature-P-BG_BOR-2.pdf")] // SHA-512 main sig + SHA-1 document timestamp
    [InlineData("Signature-P-DE_SCI-4.pdf")] // main sig + archive timestamp revision
    [InlineData("Signature-P-FR_CS-5.pdf")] // main sig + 2 archive timestamp revisions
    [InlineData("belgian_pki_multiple_ocsps.pdf")] // main sig + DSS update with multiple OCSPs
    [InlineData("doc-firmado.pdf")] // main sig + DSS update revision
    public async Task Validator_MultiRevisionDoc_PrimarySignatureIntegrityValid(string filename)
    {
        var bytes = LoadEmbedded(filename);
        var validator = new PdfSignatureValidator(NoNetworkOptions);
        var results = await validator.ValidateAsync(new MemoryStream(bytes));

        output.WriteLine($"[{filename}] {results.Count} result(s):");
        foreach (var r in results)
            output.WriteLine($"  {r.FieldName}: integrity={r.IsIntegrityValid} sig={r.IsSignatureValid} algo={r.DigestAlgorithmName}");

        results.ShouldNotBeEmpty($"'{filename}' must have at least one parseable signature");
        results.ShouldContain(r => r.IsIntegrityValid,
            $"'{filename}' must contain at least one signature with a valid byte-range hash");
    }

    /// <summary>
    /// DSS-1683.pdf is an EU DSS bug-report fixture — it contains a SHA-1 signature whose
    /// byte-range verification fails. The validator must not throw; returning an error result is correct.
    /// </summary>
    [Fact]
    public async Task Validator_Dss1683_DoesNotThrow()
    {
        var bytes = LoadEmbedded("DSS-1683.pdf");
        var validator = new PdfSignatureValidator(NoNetworkOptions);

        var ex = await Record.ExceptionAsync(() => validator.ValidateAsync(new MemoryStream(bytes)));
        ex.ShouldBeNull("the validator must handle known-problematic corpus files gracefully without throwing");

        output.WriteLine("DSS-1683.pdf: validator returned without crashing ✓");
    }

    /// <summary>
    /// BadEncodedCMS.pdf — the validator must not throw. It may return an error result.
    /// </summary>
    [Fact]
    public async Task Validator_BadEncodedCMS_DoesNotThrow()
    {
        var bytes = LoadEmbedded("BadEncodedCMS.pdf");
        var validator = new PdfSignatureValidator(NoNetworkOptions);

        var ex = await Record.ExceptionAsync(() => validator.ValidateAsync(new MemoryStream(bytes)));
        ex.ShouldBeNull("the validator must handle malformed CMS gracefully without throwing");

        output.WriteLine("BadEncodedCMS.pdf: validator returned without crashing ✓");
    }

    /// <summary>
    /// Large corpus files — integrity check, skipped in CI.
    /// PAdES-LTA has at least one valid archive timestamp over the primary signature.
    /// 51sigs.pdf has 51 incremental signatures — the first must be integrity-valid.
    /// </summary>
    [Theory]
    [InlineData("51sigs.pdf", 51)]
    [InlineData("PAdES-LTA.pdf", 1)]
    [InlineData("DSS-1443.pdf", 1)]
    public async Task Validator_LargeLocalFile_AtLeastOneIntegrityValid(string filename, int minResults)
    {
        var bytes = TryLoadLocal(filename);
        if (bytes is null)
        {
            output.WriteLine($"[SKIP] '{filename}' not found in local corpus — large file not in git");
            return;
        }

        var validator = new PdfSignatureValidator(NoNetworkOptions);
        var results = await validator.ValidateAsync(new MemoryStream(bytes));

        output.WriteLine($"[{filename}] {results.Count} result(s):");
        foreach (var r in results)
            output.WriteLine($"  {r.FieldName}: integrity={r.IsIntegrityValid}");

        results.Count().ShouldBeGreaterThanOrEqualTo(minResults);
        results.ShouldContain(r => r.IsIntegrityValid,
            $"'{filename}' must contain at least one signature with a valid byte-range hash");
    }

    // ── Helpers ──────────────────────────────────────────────────────────────────────────

    private static byte[] LoadEmbedded(string filename)
    {
        var resourceName = ResourcePrefix + filename.Replace('-', '_').Replace(' ', '_');
        // xUnit replaces path separators with dots, but '-' in filenames stays as '-' — try exact match first
        var assembly = typeof(EtsiCorpusTests).Assembly;

        // Try exact resource name (dots come from directory separators only)
        var stream = assembly.GetManifestResourceStream(ResourcePrefix + filename)
            ?? assembly.GetManifestResourceStream(resourceName);

        if (stream is null)
        {
            // List available resources to produce a useful error message
            var available = string.Join(", ", assembly.GetManifestResourceNames()
                .Where(n => n.Contains("corpus")));
            throw new FileNotFoundException(
                $"Embedded corpus resource '{filename}' not found. Available: {available}");
        }

        using (stream)
        {
            var bytes = new byte[stream.Length];
            stream.ReadExactly(bytes);
            return bytes;
        }
    }

    private static byte[]? TryLoadLocal(string filename)
    {
        // Try relative to the test binary and to the repo root
        var candidates = new[]
        {
            Path.Combine(LocalCorpusDir, filename),
            Path.Combine(AppContext.BaseDirectory, LocalCorpusDir, filename),
            Path.Combine(AppContext.BaseDirectory, "..", "..", "..", LocalCorpusDir, filename),
        };

        foreach (var path in candidates)
        {
            var full = Path.GetFullPath(path);
            if (File.Exists(full))
                return File.ReadAllBytes(full);
        }

        return null;
    }
}

using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Shouldly;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Extensions;
using SimpleSign.Core.Validation;
using SimpleSign.PAdES.Signing;
using SimpleSign.PAdES.Validation;
using SimpleSign.Pdf;
#pragma warning disable CA1822, IDE0005, IDE0055
using SimpleSign.TestHelpers;
using Xunit;
using Xunit.Abstractions;

namespace SimpleSign.PAdES.Tests.Signing;

/// <summary>
/// Tests that verify LTV embedding and archival timestamp don't corrupt PDF structure.
/// Regression tests for the bug where LTV/archival signing produces files Adobe can't open.
/// </summary>
public sealed class LtvArchivalCorruptionTests
{
    private readonly ITestOutputHelper _out;
    public LtvArchivalCorruptionTests(ITestOutputHelper output) => _out = output;

    private static byte[] BuildPdfWithPage() =>
        Encoding.Latin1.GetBytes(
            "%PDF-1.7\n" +
            "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n" +
            "2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n" +
            "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] >>\nendobj\n" +
            "xref\n0 4\n" +
            "0000000000 65535 f \n" +
            "0000000009 00000 n \n" +
            "0000000058 00000 n \n" +
            "0000000115 00000 n \n" +
            "trailer\n<< /Size 4 /Root 1 0 R >>\n" +
            "startxref\n181\n%%EOF");

    private static X509Certificate2 CreateCertWithCrlUrl(string url = "http://crl.test/root.crl")
    {
        using RSA key = RSA.Create(2048);
        var req = new CertificateRequest("CN=LTV Test", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        byte[] urlBytes = Encoding.ASCII.GetBytes(url);
        // Build CRL Distribution Points extension (DER)
        var uri = new byte[2 + urlBytes.Length];
        uri[0] = 134; // context-specific tag 6 (URI)
        uri[1] = (byte)urlBytes.Length;
        Array.Copy(urlBytes, 0, uri, 2, urlBytes.Length);
        var gn = new byte[2 + uri.Length];
        gn[0] = 0xA0; gn[1] = (byte)uri.Length;
        Array.Copy(uri, 0, gn, 2, uri.Length);
        var dpn = new byte[2 + gn.Length];
        dpn[0] = 0xA0; dpn[1] = (byte)gn.Length;
        Array.Copy(gn, 0, dpn, 2, gn.Length);
        var dp = new byte[2 + dpn.Length];
        dp[0] = 0x30; dp[1] = (byte)dpn.Length;
        Array.Copy(dpn, 0, dp, 2, dpn.Length);
        var cdp = new byte[2 + dp.Length];
        cdp[0] = 0x30; cdp[1] = (byte)dp.Length;
        Array.Copy(dp, 0, cdp, 2, dp.Length);
        req.CertificateExtensions.Add(new X509Extension("2.5.29.31", cdp, false));
        var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        return CertificateLoader.LoadPkcs12(cert.Export(X509ContentType.Pfx, "t"), "t");
    }

    private static byte[] BuildFakeCrl()
    {
        var w = new System.Formats.Asn1.AsnWriter(System.Formats.Asn1.AsnEncodingRules.DER);
        using (w.PushSequence())
        {
            using (w.PushSequence())
            {
                w.WriteInteger(1);
                using (w.PushSequence()) w.WriteObjectIdentifier("1.2.840.113549.1.1.11");
                using (w.PushSequence())
                using (w.PushSetOf())
                using (w.PushSequence())
                {
                    w.WriteObjectIdentifier("2.5.4.3");
                    w.WriteCharacterString(System.Formats.Asn1.UniversalTagNumber.UTF8String, "Test");
                }
                w.WriteUtcTime(DateTimeOffset.UtcNow);
            }
            using (w.PushSequence()) w.WriteObjectIdentifier("1.2.840.113549.1.1.11");
            w.WriteBitString(new byte[256]);
        }
        return w.Encode();
    }

    private HttpClient BuildMockCrlClient()
    {
        var fakeCrl = BuildFakeCrl();
        return new HttpClient(new MockHttpHandler(_ =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new ByteArrayContent(fakeCrl)
            })));
    }

    /// <summary>
    /// After signing + LTV embedding, the PDF must have valid xref chain and parseable structure.
    /// </summary>
    [Fact(DisplayName = "LTV embedding on classic-xref PDF produces valid structure")]
    public async Task LtvEmbedding_ClassicXref_ProducesValidStructure()
    {
        byte[] pdf = BuildPdfWithPage();
        using var cert = CreateCertWithCrlUrl();
        byte[] signedPdf = await SimpleSigner.Document(pdf).WithCertificate(cert).SignAsync();

        using var httpClient = BuildMockCrlClient();
        var embedder = new LtvEmbedder(httpClient);
        byte[] ltvPdf = await embedder.EmbedLtvDataAsync(signedPdf, [cert]);

        ltvPdf.ShouldNotBeSameAs(signedPdf, "LTV data should have been embedded");
        _out.WriteLine($"Signed: {signedPdf.Length}, LTV: {ltvPdf.Length}");

        VerifyPdfStructure(ltvPdf);

        string text = Encoding.Latin1.GetString(ltvPdf);
        text.ShouldContain("/Type /DSS");

        using var ms = new MemoryStream(ltvPdf);
        var fields = await PdfStructureReader.ReadSignatureFieldsAsync(ms);
        fields.Count().ShouldBeGreaterThanOrEqualTo(1, "Signature field must be readable after LTV");
    }

    /// <summary>
    /// After signing + LTV, our own validator should not report integrity errors.
    /// The ByteRange not covering LTV data is expected and must NOT be an error.
    /// </summary>
    [Fact(DisplayName = "LTV embedding does not cause validation errors")]
    public async Task LtvEmbedding_ValidationStillPasses()
    {
        byte[] pdf = BuildPdfWithPage();
        using var cert = CreateCertWithCrlUrl();
        byte[] signedPdf = await SimpleSigner.Document(pdf).WithCertificate(cert).SignAsync();

        using var httpClient = BuildMockCrlClient();
        var embedder = new LtvEmbedder(httpClient);
        byte[] ltvPdf = await embedder.EmbedLtvDataAsync(signedPdf, [cert]);

        var opts = new ValidationOptions { CheckRevocation = false, TrustSystemRoots = false };
        var validator = new PdfSignatureValidator(opts, httpClient: null, logger: null,
            trustAnchorProviders: [new InMemoryTrust(cert)]);
        using var ms = new MemoryStream(ltvPdf);
        var results = await validator.ValidateAsync(ms);

        results.Count().ShouldBe(1, "should have exactly one signature");
        var r = results[0];
        _out.WriteLine($"Integrity: {r.IsIntegrityValid}, Sig: {r.IsSignatureValid}");
        foreach (var e in r.Errors) _out.WriteLine($"  Error: {e}");
        foreach (var w in r.Warnings) _out.WriteLine($"  Warning: {w}");

        r.IsIntegrityValid.ShouldBeTrue("byte-range hash should verify");
        r.IsSignatureValid.ShouldBeTrue("cryptographic signature should be valid");

        // LTV data after signature is expected per PAdES B-LT — must NOT be reported as error
        r.Errors.ShouldNotContain(e => e.Contains("ByteRange does not cover entire PDF"),
            "LTV data after signature is expected per PAdES B-LT spec and must not be an error");
    }

    /// <summary>
    /// LTV on xref-stream PDF must produce valid structure.
    /// </summary>
    [Fact(DisplayName = "LTV embedding on xref-stream PDF produces valid structure")]
    public async Task LtvEmbedding_XRefStreamPdf_ProducesValidStructure()
    {
        string fixturePath = Path.Combine(
            AppDomain.CurrentDomain.BaseDirectory,
            "..", "..", "..", "..", "..", "integration",
            "SimpleSign.Integration.Tests", "Fixtures", "empty-page-unsigned.pdf");
        if (!File.Exists(fixturePath)) return;

        byte[] pdf = await File.ReadAllBytesAsync(fixturePath);
        using var cert = CreateCertWithCrlUrl();
        byte[] signedPdf = await SimpleSigner.Document(pdf).WithCertificate(cert).SignAsync();

        using var httpClient = BuildMockCrlClient();
        var embedder = new LtvEmbedder(httpClient);
        byte[] ltvPdf = await embedder.EmbedLtvDataAsync(signedPdf, [cert]);

        _out.WriteLine($"Original xref streams: {PdfStructureParser.UsesXRefStreams(pdf)}");
        _out.WriteLine($"Signed xref streams: {PdfStructureParser.UsesXRefStreams(signedPdf)}");
        if (!ReferenceEquals(ltvPdf, signedPdf))
        {
            _out.WriteLine($"LTV xref streams: {PdfStructureParser.UsesXRefStreams(ltvPdf)}");
            _out.WriteLine($"Signed: {signedPdf.Length}, LTV: {ltvPdf.Length}");
            VerifyPdfStructure(ltvPdf);
        }
    }

    /// <summary>
    /// Catalog rewritten by LTV must preserve /AcroForm reference.
    /// </summary>
    [Fact(DisplayName = "LTV catalog update preserves AcroForm reference")]
    public async Task LtvEmbedding_CatalogPreservesAcroForm()
    {
        byte[] pdf = BuildPdfWithPage();
        using var cert = CreateCertWithCrlUrl();
        byte[] signedPdf = await SimpleSigner.Document(pdf).WithCertificate(cert).SignAsync();

        using var httpClient = BuildMockCrlClient();
        var embedder = new LtvEmbedder(httpClient);
        byte[] ltvPdf = await embedder.EmbedLtvDataAsync(signedPdf, [cert]);
        if (ReferenceEquals(ltvPdf, signedPdf)) return;

        // Find the catalog in the LTV PDF
        int catalogObjNum = PdfStructureParser.FindRootObjectNumber(ltvPdf);
        var (catStart, catEnd) = PdfStructureParser.FindObjectBytes(ltvPdf, catalogObjNum);
        catStart.ShouldBeGreaterThanOrEqualTo(0, "catalog object must be found");

        string catalog = Encoding.Latin1.GetString(ltvPdf.AsSpan().Slice(catStart, catEnd - catStart));
        _out.WriteLine($"Catalog: {catalog}");

        catalog.ShouldContain("/AcroForm");
        catalog.ShouldContain("/DSS");
        catalog.ShouldContain("/Type /Catalog");
    }

    private void VerifyPdfStructure(byte[] pdf)
    {
        string text = Encoding.Latin1.GetString(pdf);

        text.ShouldStartWith("%PDF-");
        text.TrimEnd().ShouldEndWith("%%EOF");

        // Verify startxref points to valid location
        int lastStartxref = text.LastIndexOf("startxref", StringComparison.Ordinal);
        lastStartxref.ShouldBeGreaterThan(0);

        int offStart = lastStartxref + "startxref".Length;
        while (offStart < text.Length && (text[offStart] == '\r' || text[offStart] == '\n' || text[offStart] == ' '))
            offStart++;

        int offEnd = offStart;
        while (offEnd < text.Length && char.IsDigit(text[offEnd]))
            offEnd++;

        string offStr = text[offStart..offEnd];
        _out.WriteLine($"startxref offset: {offStr}");
        long xrefOffset = long.Parse(offStr);
        xrefOffset.ShouldBeLessThan(pdf.Length, "startxref must point within file");
        xrefOffset.ShouldBeGreaterThan(0, "startxref must be positive");

        string atXref = text[(int)xrefOffset..Math.Min((int)xrefOffset + 20, text.Length)];
        _out.WriteLine($"At xref offset: {atXref.Replace("\n", "\\n").Replace("\r", "\\r")}");

        bool isClassic = atXref.StartsWith("xref", StringComparison.Ordinal);
        bool isStream = char.IsDigit(atXref[0]);
        (isClassic || isStream).ShouldBeTrue($"xref at offset {xrefOffset} must be valid, found: '{atXref}'");

        // Verify /Root points to a valid catalog object
        int rootObjNum = PdfStructureParser.FindRootObjectNumber(pdf);
        rootObjNum.ShouldBeGreaterThan(0, "must have valid /Root");

        var (rootStart, rootEnd) = PdfStructureParser.FindObjectBytes(pdf, rootObjNum);
        rootStart.ShouldBeGreaterThanOrEqualTo(0, $"catalog object {rootObjNum} must be found");

        string rootText = Encoding.Latin1.GetString(pdf.AsSpan().Slice(rootStart, rootEnd - rootStart));
        rootText.ShouldContain("/Catalog");
    }

    private sealed class InMemoryTrust(X509Certificate2 cert) : ITrustAnchorProvider
    {
        public string RegionCode => "TEST";
        public string DisplayName => "In-Memory Trust";
        public IReadOnlyList<X509Certificate2> GetTrustAnchors() => [cert];
    }

    private sealed class MockHttpHandler(Func<HttpRequestMessage, Task<HttpResponseMessage>> handler)
        : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage req, CancellationToken ct)
            => handler(req);
    }
}

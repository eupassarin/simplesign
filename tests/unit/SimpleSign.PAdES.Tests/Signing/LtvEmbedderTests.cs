using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Shouldly;
using SimpleSign.Core.Crypto;
using SimpleSign.PAdES.Signing;
using SimpleSign.Pdf;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.PAdES.Tests.Signing;

[Trait("Category", "Unit")]
public sealed class LtvEmbedderTests
{




    /// <summary>
    /// Creates a self-signed cert whose CRL Distribution Points extension
    /// contains an HTTP URL so that <see cref="LtvEmbedder" /> will attempt
    /// to download a CRL.
    /// </summary>
    private static X509Certificate2 CreateCertWithCrlUrl(string url = "http://crl.test/root.crl")
    {
        using RSA key = RSA.Create(2048);
        CertificateRequest certificateRequest = new CertificateRequest("CN=CRL Test", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        byte[] bytes = Encoding.ASCII.GetBytes(url);
        byte b = 134;
        byte b2 = (byte)bytes.Length;
        byte[] array = bytes;
        int num = 0;
        byte[] array2 = new byte[2 + array.Length];
        array2[num] = b;
        num++;
        array2[num] = b2;
        num++;
        ReadOnlySpan<byte> readOnlySpan = new ReadOnlySpan<byte>(array);
        readOnlySpan.CopyTo(new Span<byte>(array2).Slice(num, readOnlySpan.Length));
        num += readOnlySpan.Length;
        byte[] array3 = array2;
        b2 = 160;
        b = (byte)array3.Length;
        array2 = array3;
        num = 0;
        array = new byte[2 + array2.Length];
        array[num] = b2;
        num++;
        array[num] = b;
        num++;
        readOnlySpan = new ReadOnlySpan<byte>(array2);
        readOnlySpan.CopyTo(new Span<byte>(array).Slice(num, readOnlySpan.Length));
        num += readOnlySpan.Length;
        byte[] array4 = array;
        b = 160;
        b2 = (byte)array4.Length;
        array = array4;
        num = 0;
        array2 = new byte[2 + array.Length];
        array2[num] = b;
        num++;
        array2[num] = b2;
        num++;
        readOnlySpan = new ReadOnlySpan<byte>(array);
        readOnlySpan.CopyTo(new Span<byte>(array2).Slice(num, readOnlySpan.Length));
        num += readOnlySpan.Length;
        byte[] array5 = array2;
        b2 = 48;
        b = (byte)array5.Length;
        array2 = array5;
        num = 0;
        array = new byte[2 + array2.Length];
        array[num] = b2;
        num++;
        array[num] = b;
        num++;
        readOnlySpan = new ReadOnlySpan<byte>(array2);
        readOnlySpan.CopyTo(new Span<byte>(array).Slice(num, readOnlySpan.Length));
        num += readOnlySpan.Length;
        byte[] array6 = array;
        b = 48;
        b2 = (byte)array6.Length;
        array = array6;
        num = 0;
        array2 = new byte[2 + array.Length];
        array2[num] = b;
        num++;
        array2[num] = b2;
        num++;
        readOnlySpan = new ReadOnlySpan<byte>(array);
        readOnlySpan.CopyTo(new Span<byte>(array2).Slice(num, readOnlySpan.Length));
        num += readOnlySpan.Length;
        byte[] rawData = array2;
        certificateRequest.CertificateExtensions.Add(new X509Extension("2.5.29.31", rawData, critical: false));
        X509Certificate2 x509Certificate = certificateRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1.0), DateTimeOffset.UtcNow.AddYears(1));
        return CertificateLoader.LoadPkcs12(x509Certificate.Export(X509ContentType.Pfx, "test-export"), "test-export");
    }

    [Fact(DisplayName = "Constructor accepts HttpClient")]
    public void Constructor_AcceptsHttpClient()
    {
        using HttpClient httpClient = new HttpClient();
        LtvEmbedder actualValue = new LtvEmbedder(httpClient);
        actualValue.ShouldNotBeNull("");
    }

    [Fact(DisplayName = "Constructor accepts null and uses shared client")]
    public void Constructor_AcceptsNull_UsesSharedClient()
    {
        LtvEmbedder actualValue = new LtvEmbedder();
        actualValue.ShouldNotBeNull("");
    }

    [Fact(DisplayName = "Null PDF throws ArgumentNullException")]
    public async Task EmbedLtvDataAsync_NullPdf_ThrowsArgumentNullException()
    {
        LtvEmbedder embedder = new LtvEmbedder();
        X509Certificate2 cert = TestCertificateFactory.CreateSelfSignedCert();
        try
        {
            await Assert.ThrowsAsync<ArgumentNullException>(() => embedder.EmbedLtvDataAsync(null!, [cert]));
        }
        finally
        {
            if (cert != null)
            {
                ((IDisposable)cert).Dispose();
            }
        }
    }

    [Fact(DisplayName = "Null chain throws ArgumentNullException")]
    public async Task EmbedLtvDataAsync_NullChain_ThrowsArgumentNullException()
    {
        LtvEmbedder embedder = new LtvEmbedder();
        await Assert.ThrowsAsync<ArgumentNullException>(() => embedder.EmbedLtvDataAsync(TestPdfFactory.CreateMinimalPdf(), null!));
    }

    [Fact(DisplayName = "Empty PDF does not throw exception")]
    public async Task EmbedLtvDataAsync_EmptyPdf_DoesNotThrow()
    {
        LtvEmbedder ltvEmbedder = new LtvEmbedder();
        using X509Certificate2 cert = TestCertificateFactory.CreateSelfSignedCert();
        (await ltvEmbedder.EmbedLtvDataAsync([], [cert])).ShouldBeEmpty("");
    }

    [Fact(DisplayName = "Invalid bytes do not throw exception")]
    public async Task EmbedLtvDataAsync_GarbageBytes_DoesNotThrow()
    {
        LtvEmbedder ltvEmbedder = new LtvEmbedder();
        using X509Certificate2 cert = TestCertificateFactory.CreateSelfSignedCert();
        byte[] garbage = [0, 255, 222, 173];
        // v0.4.0: garbage input still passes through EnsureTrailingEol — it adds a
        // trailing \n if the input is not already EOL-terminated. Garbage [173] is
        // not EOL, so the output gains 1 byte.
        byte[] result = await ltvEmbedder.EmbedLtvDataAsync(garbage, [cert]);
        result.AsSpan(0, garbage.Length).SequenceEqual(garbage).ShouldBeTrue();
        result.Length.ShouldBe(garbage.Length + 1);
        result[^1].ShouldBe((byte)'\n');
    }

    [Fact(DisplayName = "Cert without CRL URL returns unchanged PDF")]
    public async Task EmbedLtvDataAsync_CertWithoutCrlUrl_ReturnsSamePdf()
    {
        LtvEmbedder ltvEmbedder = new LtvEmbedder();
        using X509Certificate2 cert = TestCertificateFactory.CreateSelfSignedCert();
        byte[] pdf = TestPdfFactory.CreateMinimalPdf();
        // v0.4.0: even when no LTV data is embedded, EnsureTrailingEol adds a trailing
        // \n if the source PDF is bare-%%EOF (no EOL after %%EOF).
        byte[] result = await ltvEmbedder.EmbedLtvDataAsync(pdf, [cert]);
        result.AsSpan(0, pdf.Length).SequenceEqual(pdf).ShouldBeTrue();
        result.Length.ShouldBe(pdf.Length + 1);
        result[^1].ShouldBe((byte)'\n');
    }

    [Fact(DisplayName = "With CRL data, output is larger than input")]
    public async Task EmbedLtvDataAsync_WithCrlData_OutputIsLargerThanInput()
    {
        byte[] array = new byte[256];
        Random.Shared.NextBytes(array);
        using HttpClient httpClient = MockHttpHandler.ForGetBytes(array, HttpStatusCode.OK);
        LtvEmbedder ltvEmbedder = new LtvEmbedder(httpClient);
        using X509Certificate2 cert = CreateCertWithCrlUrl();
        byte[] pdf = TestPdfFactory.CreateMinimalPdf();
        (await ltvEmbedder.EmbedLtvDataAsync(pdf, [cert])).Length.ShouldBeGreaterThan(pdf.Length, "DSS dictionary with CRL data should be appended");
    }

    [Fact(DisplayName = "With CRL data, output contains DSS dictionary")]
    public async Task EmbedLtvDataAsync_WithCrlData_OutputContainsDssMarker()
    {
        byte[] content = [48, 130, 1, 0];
        using HttpClient httpClient = MockHttpHandler.ForGetBytes(content, HttpStatusCode.OK);
        LtvEmbedder ltvEmbedder = new LtvEmbedder(httpClient);
        using X509Certificate2 cert = CreateCertWithCrlUrl();
        byte[] signedPdf = TestPdfFactory.CreateMinimalPdf();
        byte[] bytes = await ltvEmbedder.EmbedLtvDataAsync(signedPdf, [cert]);
        string actualValue = Encoding.Latin1.GetString(bytes);
        actualValue.ShouldContain("/Type /DSS");
        actualValue.ShouldContain("/CRLs [");
    }

    [Fact(DisplayName = "LTV catalog write (BuildUpdatedCatalogDss) ends with LF after endobj")]
    public async Task EmbedLtvDataAsync_WithCrlData_CatalogWriteEndsWithLfAfterEndobj()
    {
        // Regression for the v0.4.0 fix to BuildUpdatedCatalogDss — the catalog write
        // returned by the embedder must end with an EOL marker after "endobj" so the
        // XRef stream written immediately after is LF-preceded.
        byte[] content = [48, 130, 1, 0];
        using HttpClient httpClient = MockHttpHandler.ForGetBytes(content, HttpStatusCode.OK);
        LtvEmbedder ltvEmbedder = new LtvEmbedder(httpClient);
        using X509Certificate2 cert = CreateCertWithCrlUrl();
        byte[] signedPdf = TestPdfFactory.CreateMinimalPdf();
        byte[] bytes = await ltvEmbedder.EmbedLtvDataAsync(signedPdf, [cert]);
        string text = Encoding.Latin1.GetString(bytes);

        // The LTV update rewrites the Catalog with /DSS added. Find the LAST occurrence
        // of "/Type /Catalog" — that's the LTV catalog write.
        int catalogIdx = text.LastIndexOf("/Type /Catalog", StringComparison.Ordinal);
        catalogIdx.ShouldBeGreaterThan(-1, "Catalog object must exist in the output");

        // Walk back to find the start of "N 0 obj" preceding the catalog dict.
        string surrounding = text[..catalogIdx];
        int objMarker = surrounding.LastIndexOf("obj\n", StringComparison.Ordinal);
        objMarker.ShouldBeGreaterThan(-1);
        // Find the byte after "endobj" that closes this catalog write.
        int endobjIdx = text.IndexOf("endobj", objMarker, StringComparison.Ordinal);
        endobjIdx.ShouldBeGreaterThan(-1);
        int afterEndobj = endobjIdx + 6;
        afterEndobj.ShouldBeLessThan(text.Length);
        char byteAfter = text[afterEndobj];
        bool isEol = byteAfter == '\n' || byteAfter == '\r';
        string context = text[Math.Max(0, afterEndobj - 20)..Math.Min(text.Length, afterEndobj + 20)];
        isEol.ShouldBeTrue(
            $"byte after 'endobj' (offset {afterEndobj}) is 0x{(int)byteAfter:X2}; expected LF or CR. Context: ...{context}...");
    }

    [Fact(DisplayName = "With CRL data, output starts with original PDF")]
    public async Task EmbedLtvDataAsync_WithCrlData_OutputStartsWithOriginalPdf()
    {
        byte[] content = [48, 130, 1, 0];
        using HttpClient httpClient = MockHttpHandler.ForGetBytes(content, HttpStatusCode.OK);
        LtvEmbedder ltvEmbedder = new LtvEmbedder(httpClient);
        using X509Certificate2 cert = CreateCertWithCrlUrl();
        byte[] pdf = TestPdfFactory.CreateMinimalPdf();
        (await ltvEmbedder.EmbedLtvDataAsync(pdf, [cert])).AsSpan(0, pdf.Length).ToArray().ShouldBe(pdf);
    }

    [Fact(DisplayName = "CRL download failure returns unchanged PDF")]
    public async Task EmbedLtvDataAsync_CrlDownloadFails_ReturnsSamePdf()
    {
        using HttpClient httpClient = new HttpClient(new MockHttpHandler(_ => Task.FromResult(new HttpResponseMessage(HttpStatusCode.InternalServerError))));
        LtvEmbedder ltvEmbedder = new LtvEmbedder(httpClient);
        using X509Certificate2 cert = CreateCertWithCrlUrl();
        byte[] pdf = TestPdfFactory.CreateMinimalPdf();
        // v0.4.0: failed CRL/OCSP download → no DSS to embed → EnsureTrailingEol
        // adds a trailing \n if the source is bare-%%EOF.
        byte[] result = await ltvEmbedder.EmbedLtvDataAsync(pdf, [cert]);
        result.AsSpan(0, pdf.Length).SequenceEqual(pdf).ShouldBeTrue();
        result.Length.ShouldBe(pdf.Length + 1);
        result[^1].ShouldBe((byte)'\n');
    }

    [Fact(DisplayName = "Empty chain returns unchanged PDF")]
    public async Task EmbedLtvDataAsync_EmptyChain_ReturnsSamePdf()
    {
        LtvEmbedder ltvEmbedder = new LtvEmbedder();
        byte[] pdf = TestPdfFactory.CreateMinimalPdf();
        // v0.4.0: empty chain → no DSS to embed → EnsureTrailingEol adds a trailing
        // \n if the source is bare-%%EOF.
        byte[] result = await ltvEmbedder.EmbedLtvDataAsync(pdf, []);
        result.AsSpan(0, pdf.Length).SequenceEqual(pdf).ShouldBeTrue();
        result.Length.ShouldBe(pdf.Length + 1);
        result[^1].ShouldBe((byte)'\n');
    }

    [Fact(DisplayName = "LTV embedding preserves xref stream format for xref-stream PDFs")]
    public async Task EmbedLtvDataAsync_XRefStreamPdf_PreservesXRefStreamFormat()
    {
        // Sign a xref-stream PDF to create a realistic signed PDF with CRL-bearing cert
        string fixturePath = Path.Combine(
            AppDomain.CurrentDomain.BaseDirectory,
            "..", "..", "..", "..", "..", "integration",
            "SimpleSign.Integration.Tests", "Fixtures", "empty-page-unsigned.pdf");

        byte[] pdf;
        if (File.Exists(fixturePath))
        {
            pdf = await File.ReadAllBytesAsync(fixturePath);
        }
        else
        {
            // Skip if fixture not available
            return;
        }

        // Sign the PDF so LtvEmbedder has a signed PDF to work with
        using var cert = CreateCertWithCrlUrl();
        byte[] signedPdf = await PadesSigner.Document(pdf)
            .WithCertificate(cert)
            .SignAsync();

        // Verify the signed PDF uses xref streams (since original does)
        bool usesXRefStreams = PdfStructureParser.UsesXRefStreams(signedPdf);
        usesXRefStreams.ShouldBeTrue("signed PDF should preserve xref stream format");

        // Embed LTV with a CRL server that returns valid-looking data
        byte[] fakeCrl = BuildFakeCrl();
        using var httpClient = MockHttpHandler.ForGetBytes(fakeCrl, HttpStatusCode.OK);
        var embedder = new LtvEmbedder(httpClient);
        byte[] ltvPdf = await embedder.EmbedLtvDataAsync(signedPdf, [cert]);

        // If LTV data was embedded, check xref format is preserved
        if (!ReferenceEquals(ltvPdf, signedPdf))
        {
            bool ltvUsesXRefStreams = PdfStructureParser.UsesXRefStreams(ltvPdf);
            ltvUsesXRefStreams.ShouldBeTrue(
                "LtvEmbedder must preserve xref stream format when the signed PDF uses xref streams");
        }
    }

    // ── Parallelism ───────────────────────────────────────────────────────────

    [Fact(DisplayName = "Multiple certs with CRL URLs: all CRLs are embedded")]
    public async Task EmbedLtvDataAsync_MultipleCertsWithCrls_AllCrlsEmbedded()
    {
        byte[] crl1 = [48, 12, 2, 1, 1];
        byte[] crl2 = [48, 12, 2, 1, 2];
        int requestCount = 0;

        using HttpClient httpClient = new HttpClient(new MockHttpHandler(async _ =>
        {
            int current = Interlocked.Increment(ref requestCount);
            byte[] response = current % 2 == 1 ? crl1 : crl2;
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new ByteArrayContent(response)
            };
        }));

        LtvEmbedder embedder = new LtvEmbedder(httpClient);
        using X509Certificate2 cert1 = CreateCertWithCrlUrl("http://crl.test/cert1.crl");
        using X509Certificate2 cert2 = CreateCertWithCrlUrl("http://crl.test/cert2.crl");
        byte[] pdf = TestPdfFactory.CreateMinimalPdf();

        byte[] result = await embedder.EmbedLtvDataAsync(pdf, [cert1, cert2]);

        requestCount.ShouldBeGreaterThanOrEqualTo(2, "both certs should have triggered a CRL request");
        string text = Encoding.Latin1.GetString(result);
        text.ShouldContain("/Type /DSS");
    }

    [Fact(DisplayName = "Parallel processing: one cert failure does not block others")]
    public async Task EmbedLtvDataAsync_OneCertFails_StillProcessesOthers()
    {
        byte[] crlData = [48, 12, 2, 1, 0];

        int requestCount = 0;
        using HttpClient httpClient = new HttpClient(new MockHttpHandler(async _ =>
        {
            int seq = Interlocked.Increment(ref requestCount);
            if (seq == 1)
            {
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new ByteArrayContent(crlData)
                };
            }

            return new HttpResponseMessage(HttpStatusCode.InternalServerError);
        }));

        LtvEmbedder embedder = new LtvEmbedder(httpClient);
        using X509Certificate2 cert1 = CreateCertWithCrlUrl("http://crl.test/ok.crl");
        using X509Certificate2 cert2 = CreateCertWithCrlUrl("http://crl.test/fail.crl");
        byte[] pdf = TestPdfFactory.CreateMinimalPdf();

        byte[] result = await embedder.EmbedLtvDataAsync(pdf, [cert1, cert2]);
        string text = Encoding.Latin1.GetString(result);
        text.ShouldContain("/Type /DSS");
    }

    [Fact(DisplayName = "Multiple certs: result is structurally identical across runs")]
    public async Task EmbedLtvDataAsync_MultipleCerts_StructureStableAcrossRuns()
    {
        byte[] crl1 = [48, 6, 2, 1, 0];
        byte[] crl2 = [48, 6, 2, 1, 1];

        async Task<byte[]> RunEmbedAsync()
        {
            using HttpClient httpClient = new HttpClient(new MockHttpHandler(async req =>
            {
                string url = req.RequestUri?.AbsoluteUri ?? "";
                byte[] data = url.Contains("cert1", StringComparison.OrdinalIgnoreCase) ? crl1 : crl2;
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new ByteArrayContent(data)
                };
            }));

            LtvEmbedder embedder = new LtvEmbedder(httpClient);
            using X509Certificate2 cert1 = CreateCertWithCrlUrl("http://crl.test/cert1.crl");
            using X509Certificate2 cert2 = CreateCertWithCrlUrl("http://crl.test/cert2.crl");
            return await embedder.EmbedLtvDataAsync(TestPdfFactory.CreateMinimalPdf(), [cert1, cert2]);
        }

        byte[] result1 = await RunEmbedAsync();
        byte[] result2 = await RunEmbedAsync();

        Encoding.Latin1.GetString(result1).ShouldContain("/Type /DSS");
        Encoding.Latin1.GetString(result2).ShouldContain("/Type /DSS");

        int count1 = CountSubstring(Encoding.Latin1.GetString(result1), "/FlateDecode");
        int count2 = CountSubstring(Encoding.Latin1.GetString(result2), "/FlateDecode");
        count1.ShouldBe(count2);
    }

    private static int CountSubstring(string text, string substring)
    {
        int count = 0;
        int pos = 0;
        while ((pos = text.IndexOf(substring, pos, StringComparison.Ordinal)) >= 0)
        {
            count++;
            pos += substring.Length;
        }

        return count;
    }

    private static byte[] BuildFakeCrl()
    {
        // Build a minimal DER-encoded CRL structure
        // This is a fake CRL that won't validate but is enough for LtvEmbedder to embed
        var writer = new System.Formats.Asn1.AsnWriter(System.Formats.Asn1.AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            // TBSCertList
            using (writer.PushSequence())
            {
                writer.WriteInteger(1); // version
                // signature algorithm
                using (writer.PushSequence())
                {
                    writer.WriteObjectIdentifier("1.2.840.113549.1.1.11"); // sha256WithRSAEncryption
                }
                // issuer
                using (writer.PushSequence())
                {
                    using (writer.PushSetOf())
                    {
                        using (writer.PushSequence())
                        {
                            writer.WriteObjectIdentifier("2.5.4.3"); // CN
                            writer.WriteCharacterString(System.Formats.Asn1.UniversalTagNumber.UTF8String, "CRL Test");
                        }
                    }
                }
                // thisUpdate
                writer.WriteUtcTime(DateTimeOffset.UtcNow);
            }
            // signatureAlgorithm
            using (writer.PushSequence())
            {
                writer.WriteObjectIdentifier("1.2.840.113549.1.1.11");
            }
            // signature
            writer.WriteBitString(new byte[256]);
        }
        return writer.Encode();
    }

    [Fact(DisplayName = "VRI dictionary contains no /SHA256 key")]
    public async Task EmbedLtvDataAsync_VriDictionary_ContainsNoSha256Key()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        byte[] pdf = TestPdfFactory.CreateMinimalPdf();
        byte[] signed = await PadesSigner.Document(pdf).WithCertificate(cert).SignAsync();

        using HttpClient httpClient = MockHttpHandler.ForGetBytes([48, 6, 2, 1, 0], HttpStatusCode.OK);
        var embedder = new LtvEmbedder(httpClient);
        using X509Certificate2 crlCert = CreateCertWithCrlUrl();
        byte[] ltvPdf = await embedder.EmbedLtvDataAsync(signed, [cert, crlCert]);

        string pdfText = Encoding.Latin1.GetString(ltvPdf);
        Assert.DoesNotContain("/SHA256", pdfText, StringComparison.Ordinal);
    }

    [Fact(DisplayName = "VRI dictionary contains only ISO 32000-2 spec keys")]
    public async Task EmbedLtvDataAsync_VriDictionary_ContainsOnlySpecKeys()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        byte[] pdf = TestPdfFactory.CreateMinimalPdf();
        byte[] signed = await PadesSigner.Document(pdf).WithCertificate(cert).SignAsync();

        using HttpClient httpClient = MockHttpHandler.ForGetBytes([48, 6, 2, 1, 0], HttpStatusCode.OK);
        var embedder = new LtvEmbedder(httpClient);
        using X509Certificate2 crlCert = CreateCertWithCrlUrl();
        byte[] ltvPdf = await embedder.EmbedLtvDataAsync(signed, [cert, crlCert]);

        string pdfText = Encoding.Latin1.GetString(ltvPdf);
        int vriStart = pdfText.IndexOf("/Type /VRI", StringComparison.Ordinal);
        Assert.True(vriStart >= 0, "Expected VRI dictionary in LTV PDF");

        int vriEnd = pdfText.IndexOf("endobj", vriStart, StringComparison.Ordinal);
        Assert.True(vriEnd > vriStart, "Expected endobj after VRI dictionary");
        string vriBody = pdfText[vriStart..vriEnd];

        string[] allowed = ["/Type", "/Cert", "/CRL", "/OCSP", "/TU", "/TS"];

        int pos = 0;
        while (pos < vriBody.Length)
        {
            int slash = vriBody.IndexOf('/', pos);
            if (slash < 0)
            {
                break;
            }

            int end = slash + 1;
            while (end < vriBody.Length && (char.IsLetterOrDigit(vriBody[end]) || vriBody[end] == '_'))
            {
                end++;
            }

            string key = vriBody[slash..end];
            if (key != "/VRI")
            {
                Assert.Contains(key, allowed);
            }

            pos = end;
        }
    }
}

using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using FluentAssertions;
using SimpleSign.Core.Crypto;
using SimpleSign.PAdES.Signing;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.PAdES.Tests.Signing;

public sealed class LtvEmbedderTests
{
    private sealed class MockHandler(HttpStatusCode status, byte[]? content = null) : HttpMessageHandler()
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            HttpResponseMessage httpResponseMessage = new HttpResponseMessage(status);
            if (content != null)
            {
                httpResponseMessage.Content = new ByteArrayContent(content);
            }
            return Task.FromResult(httpResponseMessage);
        }
    }

    private static byte[] BuildMinimalPdf()
    {
        return Encoding.Latin1.GetBytes("%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\nxref\n0 3\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \ntrailer\n<< /Size 3 /Root 1 0 R >>\nstartxref\n110\n%%EOF");
    }

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
        actualValue.Should().NotBeNull("");
    }

    [Fact(DisplayName = "Constructor accepts null and uses shared client")]
    public void Constructor_AcceptsNull_UsesSharedClient()
    {
        LtvEmbedder actualValue = new LtvEmbedder();
        actualValue.Should().NotBeNull("");
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
        await Assert.ThrowsAsync<ArgumentNullException>(() => embedder.EmbedLtvDataAsync(BuildMinimalPdf(), null!));
    }

    [Fact(DisplayName = "Empty PDF does not throw exception")]
    public async Task EmbedLtvDataAsync_EmptyPdf_DoesNotThrow()
    {
        LtvEmbedder ltvEmbedder = new LtvEmbedder();
        using X509Certificate2 cert = TestCertificateFactory.CreateSelfSignedCert();
        (await ltvEmbedder.EmbedLtvDataAsync(Array.Empty<byte>(), [cert])).Should().BeEmpty("");
    }

    [Fact(DisplayName = "Invalid bytes do not throw exception")]
    public async Task EmbedLtvDataAsync_GarbageBytes_DoesNotThrow()
    {
        LtvEmbedder ltvEmbedder = new LtvEmbedder();
        using X509Certificate2 cert = TestCertificateFactory.CreateSelfSignedCert();
        byte[] garbage = new byte[4] { 0, 255, 222, 173 };
        (await ltvEmbedder.EmbedLtvDataAsync(garbage, [cert])).Should().Equal(garbage);
    }

    [Fact(DisplayName = "Cert without CRL URL returns unchanged PDF")]
    public async Task EmbedLtvDataAsync_CertWithoutCrlUrl_ReturnsSamePdf()
    {
        LtvEmbedder ltvEmbedder = new LtvEmbedder();
        using X509Certificate2 cert = TestCertificateFactory.CreateSelfSignedCert();
        byte[] pdf = BuildMinimalPdf();
        (await ltvEmbedder.EmbedLtvDataAsync(pdf, [cert])).Should().Equal(pdf, "no CRL/OCSP data means no DSS to append");
    }

    [Fact(DisplayName = "With CRL data, output is larger than input")]
    public async Task EmbedLtvDataAsync_WithCrlData_OutputIsLargerThanInput()
    {
        byte[] array = new byte[256];
        Random.Shared.NextBytes(array);
        using HttpClient httpClient = new HttpClient(new MockHandler(HttpStatusCode.OK, array));
        LtvEmbedder ltvEmbedder = new LtvEmbedder(httpClient);
        using X509Certificate2 cert = CreateCertWithCrlUrl();
        byte[] pdf = BuildMinimalPdf();
        (await ltvEmbedder.EmbedLtvDataAsync(pdf, [cert])).Length.Should().BeGreaterThan(pdf.Length, "DSS dictionary with CRL data should be appended");
    }

    [Fact(DisplayName = "With CRL data, output contains DSS dictionary")]
    public async Task EmbedLtvDataAsync_WithCrlData_OutputContainsDssMarker()
    {
        byte[] content = new byte[4] { 48, 130, 1, 0 };
        using HttpClient httpClient = new HttpClient(new MockHandler(HttpStatusCode.OK, content));
        LtvEmbedder ltvEmbedder = new LtvEmbedder(httpClient);
        using X509Certificate2 cert = CreateCertWithCrlUrl();
        byte[] signedPdf = BuildMinimalPdf();
        byte[] bytes = await ltvEmbedder.EmbedLtvDataAsync(signedPdf, [cert]);
        string actualValue = Encoding.Latin1.GetString(bytes);
        actualValue.Should().Contain("/Type /DSS", "output must contain a DSS dictionary");
        actualValue.Should().Contain("/CRLs [", "DSS must reference the CRL objects");
    }

    [Fact(DisplayName = "With CRL data, output starts with original PDF")]
    public async Task EmbedLtvDataAsync_WithCrlData_OutputStartsWithOriginalPdf()
    {
        byte[] content = new byte[4] { 48, 130, 1, 0 };
        using HttpClient httpClient = new HttpClient(new MockHandler(HttpStatusCode.OK, content));
        LtvEmbedder ltvEmbedder = new LtvEmbedder(httpClient);
        using X509Certificate2 cert = CreateCertWithCrlUrl();
        byte[] pdf = BuildMinimalPdf();
        (await ltvEmbedder.EmbedLtvDataAsync(pdf, [cert])).AsSpan(0, pdf.Length).ToArray().Should().Equal(pdf);
    }

    [Fact(DisplayName = "CRL download failure returns unchanged PDF")]
    public async Task EmbedLtvDataAsync_CrlDownloadFails_ReturnsSamePdf()
    {
        using HttpClient httpClient = new HttpClient(new MockHandler(HttpStatusCode.InternalServerError));
        LtvEmbedder ltvEmbedder = new LtvEmbedder(httpClient);
        using X509Certificate2 cert = CreateCertWithCrlUrl();
        byte[] pdf = BuildMinimalPdf();
        (await ltvEmbedder.EmbedLtvDataAsync(pdf, [cert])).Should().Equal(pdf, "failed CRL download means no DSS to append");
    }

    [Fact(DisplayName = "Empty chain returns unchanged PDF")]
    public async Task EmbedLtvDataAsync_EmptyChain_ReturnsSamePdf()
    {
        LtvEmbedder ltvEmbedder = new LtvEmbedder();
        byte[] pdf = BuildMinimalPdf();
        (await ltvEmbedder.EmbedLtvDataAsync(pdf, Array.Empty<X509Certificate2>())).Should().Equal(pdf);
    }
}

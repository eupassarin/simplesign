using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Shouldly;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Http;
using SimpleSign.Core.Revocation;
using SimpleSign.Core.Validation;
using SimpleSign.PAdES.Validation;
using Xunit;

namespace SimpleSign.PAdES.Tests.Validation;

/// <summary>
/// Tests for DssExtractor, RevocationChecker, and HttpClient injection (DefaultHttpClientProvider, PdfSignatureValidator).
/// </summary>
[Trait("Category", "Unit")]
public sealed class DssExtractorAndHttpProviderTests
{
    private static X509Certificate2 CreateCert(string subject = "CN=Dss Test")
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, false));
        var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        return CertificateLoader.LoadPkcs12(cert.Export(X509ContentType.Pkcs12, "test-export"), "test-export");
    }

    private static byte[] CreateMinimalPdf()
    {
        var sb = new StringBuilder();
        sb.AppendLine("%PDF-1.4");
        sb.AppendLine("1 0 obj <</Type /Catalog /Pages 2 0 R>> endobj");
        sb.AppendLine("2 0 obj <</Type /Pages /Kids [3 0 R] /Count 1>> endobj");
        sb.AppendLine("3 0 obj <</Type /Page /Parent 2 0 R /MediaBox [0 0 612 792]>> endobj");
        sb.AppendLine("xref");
        sb.AppendLine("0 4");
        sb.AppendLine("0000000000 65535 f ");
        sb.AppendLine("0000000009 00000 n ");
        sb.AppendLine("0000000058 00000 n ");
        sb.AppendLine("0000000115 00000 n ");
        sb.AppendLine("trailer <</Size 4 /Root 1 0 R>>");
        sb.AppendLine("startxref");
        sb.AppendLine("183");
        sb.AppendLine("%%EOF");
        return Encoding.ASCII.GetBytes(sb.ToString());
    }

    // ── DssExtractor ──────────────────────────────────────────────────────

    [Fact(DisplayName = "PDF without DSS returns null dictionary")]
    public void FindDssDictionary_NoDss_ReturnsNull()
    {
        var data = Encoding.ASCII.GetBytes("%PDF-1.4\ntrailer <</Size 1>>\n%%EOF");

        DssExtractor.FindDssDictionary(data).ShouldBeNull();
    }

    [Fact(DisplayName = "IndexOfBytes finds pattern in haystack")]
    public void IndexOfBytes_FindsPattern()
    {
        ReadOnlySpan<byte> haystack = "Hello World"u8;
        ReadOnlySpan<byte> needle = "World"u8;

        DssExtractor.IndexOfBytes(haystack, needle).ShouldBe(6);
    }

    [Fact(DisplayName = "IndexOfBytes returns -1 when pattern not found")]
    public void IndexOfBytes_NotFound_ReturnsNegative()
    {
        ReadOnlySpan<byte> haystack = "Hello"u8;
        ReadOnlySpan<byte> needle = "World"u8;

        DssExtractor.IndexOfBytes(haystack, needle).ShouldBe(-1);
    }

    [Fact(DisplayName = "ParseObjRefs extracts object references correctly")]
    public void ParseObjRefs_ExtractsReferences()
    {
        ReadOnlySpan<byte> content = "10 0 R 20 0 R 30 0 R"u8;

        var refs = DssExtractor.ParseObjRefs(content).ToList();

        refs.ShouldBe([10, 20, 30]);
    }

    // ── RevocationChecker ─────────────────────────────────────────────────

    [Fact(DisplayName = "Certificate without OCSP/CRL throws ValidationException")]
    public async Task RevocationChecker_NoUrlAvailable_ThrowsInvalidOperation()
    {
        // Self-signed cert has no OCSP/CRL URLs
        using var cert = CreateCert();
        var checker = new RevocationChecker(
            new OcspClient(new HttpClient()),
            new CrlClient(new HttpClient()));

        var act = () => checker.CheckRevocationAsync(cert, [cert], [], CancellationToken.None);

        var ex2 = await Should.ThrowAsync<ValidationException>(act);
        ex2.Message.ShouldContain("no OCSP or CRL URL");
    }

    // ── HttpClient injection ──────────────────────────────────────────────

    [Fact(DisplayName = "HttpClientProvider returns same client instance")]
    public void DefaultHttpClientProvider_GetClient_ReturnsSameInstance()
    {
        var provider = DefaultHttpClientProvider.Instance;

        var client1 = provider.GetClient();
        var client2 = provider.GetClient();

        client1.ShouldBeSameAs(client2);
    }

    [Fact(DisplayName = "Default HttpClient has 30 second timeout")]
    public void DefaultHttpClientProvider_GetClient_Has30sTimeout()
    {
        var client = DefaultHttpClientProvider.Instance.GetClient();

        client.Timeout.ShouldBe(TimeSpan.FromSeconds(30));
    }

    [Fact(DisplayName = "Validator accepts IHttpClientProvider in constructor")]
    public void PdfSignatureValidator_AcceptsIHttpClientProvider()
    {
        var provider = DefaultHttpClientProvider.Instance;

        var validator = new PdfSignatureValidator(provider);

        validator.ShouldNotBeNull();
    }

    [Fact(DisplayName = "Null provider throws ArgumentNullException")]
    public void PdfSignatureValidator_ProviderNull_Throws()
    {
        var act = () => new PdfSignatureValidator(httpClientProvider: null!);

        Should.Throw<ArgumentNullException>(act);
    }

    [Fact(DisplayName = "WithHttpClientProvider returns new builder instance")]
    public void SignerBuilder_WithHttpClientProvider_ReturnsNewInstance()
    {
        using var cert = CreateCert();
        var pdf = CreateMinimalPdf();
        var builder = PadesSigner.Document(pdf).WithCertificate(cert);
        var provider = DefaultHttpClientProvider.Instance;

        var newBuilder = builder.WithHttpClientProvider(provider);

        newBuilder.ShouldNotBeSameAs(builder);
    }
}

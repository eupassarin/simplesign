using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Shouldly;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Signing;
using Xunit;

namespace SimpleSign.Core.Tests.Crypto;

/// <summary>
/// Unit tests for TimestampClient.
/// HttpClient is mocked — no real network calls.
/// </summary>
public sealed class TimestampClientTests
{
    // ── Helpers ────────────────────────────────────────────────────────────────

    private static byte[] BuildFakeTimestampResponse()
    {
        // Builds a minimal TSR: SEQUENCE { PKIStatusInfo { status = 0 }, TimeStampToken (CMS) }
        // We use a fake CMS for the token
        var fakeCmsToken = BuildFakeCmsToken();

        var writer = new System.Formats.Asn1.AsnWriter(System.Formats.Asn1.AsnEncodingRules.DER);
        using (writer.PushSequence()) // TimeStampResp
        {
            // PKIStatusInfo
            using (writer.PushSequence())
                writer.WriteInteger(0); // status = granted

            // TimeStampToken (ContentInfo)
            writer.WriteEncodedValue(fakeCmsToken);
        }
        return writer.Encode();
    }

    private static byte[] BuildFakeCmsToken()
    {
        // Minimal ContentInfo to simulate a TimeStampToken
        var writer = new System.Formats.Asn1.AsnWriter(System.Formats.Asn1.AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            writer.WriteObjectIdentifier("1.2.840.113549.1.7.2"); // id-signedData
            using (writer.PushSequence(new System.Formats.Asn1.Asn1Tag(
                System.Formats.Asn1.TagClass.ContextSpecific, 0, true)))
            {
                writer.WriteOctetString(new byte[] { 0x01, 0x02, 0x03 });
            }
        }
        return writer.Encode();
    }

    private static HttpClient BuildMockHttpClient(byte[] responseBytes, HttpStatusCode statusCode = HttpStatusCode.OK)
    {
        var handler = new MockHttpMessageHandler(responseBytes, statusCode,
            "application/timestamp-reply");
        return new HttpClient(handler);
    }

    // ── Tests ─────────────────────────────────────────────────────────────────

    [Fact(DisplayName = "Null HttpClient throws ArgumentNullException")]
    public void Constructor_NullHttpClient_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(
            () => new TimestampClient(null!, "http://tsa.example.com"));
    }

    [Fact(DisplayName = "Null URL throws ArgumentNullException")]
    public void Constructor_NullUrl_ThrowsArgumentException()
    {
        Assert.Throws<ArgumentNullException>(
            () => new TimestampClient(new HttpClient(), null!));
    }

    [Fact(DisplayName = "Empty URL throws ArgumentException")]
    public void Constructor_EmptyUrl_ThrowsArgumentException()
    {
        Assert.Throws<ArgumentException>(
            () => new TimestampClient(new HttpClient(), ""));
    }

    [Theory(DisplayName = "SSRF: localhost/private TSA URLs are blocked")]
    [InlineData("http://localhost/tsa")]
    [InlineData("http://127.0.0.1/tsa")]
    [InlineData("http://10.0.0.1/tsa")]
    [InlineData("http://192.168.1.1/tsa")]
    [InlineData("http://169.254.169.254/tsa")]
    public void Constructor_SsrfUrl_ThrowsArgumentException(string tsaUrl)
    {
        Assert.Throws<ArgumentException>(
            () => new TimestampClient(new HttpClient(), tsaUrl));
    }

    [Fact(DisplayName = "Valid response returns timestamp token")]
    public async Task GetTimestampAsync_ValidResponse_ReturnsToken()
    {
        var tsr = BuildFakeTimestampResponse();
        var httpClient = BuildMockHttpClient(tsr);
        var client = new TimestampClient(httpClient, "http://tsa.example.com");

        var token = await client.GetTimestampAsync(
            new byte[] { 0x01, 0x02, 0x03 }, HashAlgorithmName.SHA256);

        token.ShouldNotBeNull();
        token.Length.ShouldBeGreaterThan(0);
    }

    [Fact(DisplayName = "Server error throws TimestampException")]
    public async Task GetTimestampAsync_ServerError_ThrowsHttpRequestException()
    {
        var httpClient = BuildMockHttpClient([], HttpStatusCode.InternalServerError);
        var client = new TimestampClient(httpClient, "http://tsa.example.com");

        await Assert.ThrowsAsync<TimestampException>(
            () => client.GetTimestampAsync(new byte[] { 0x01 }, HashAlgorithmName.SHA256));
    }

    [Fact(DisplayName = "Rejected status throws TimestampException")]
    public async Task GetTimestampAsync_RejectedStatus_ThrowsInvalidOperationException()
    {
        // TSR com status = 2 (rejection)
        var writer = new System.Formats.Asn1.AsnWriter(System.Formats.Asn1.AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            using (writer.PushSequence())
                writer.WriteInteger(2); // rejection
        }
        var tsr = writer.Encode();

        var httpClient = BuildMockHttpClient(tsr);
        var client = new TimestampClient(httpClient, "http://tsa.example.com");

        await Assert.ThrowsAsync<TimestampException>(
            () => client.GetTimestampAsync(new byte[] { 0x01 }, HashAlgorithmName.SHA256));
    }

    [Fact(DisplayName = "Unsupported hash throws NotSupportedException")]
    public async Task GetTimestampAsync_UnsupportedHash_ThrowsNotSupportedException()
    {
        var client = new TimestampClient(new HttpClient(), "http://tsa.example.com");
        await Assert.ThrowsAsync<NotSupportedException>(
            () => client.GetTimestampAsync(new byte[] { 0x01 }, HashAlgorithmName.MD5));
    }

    [Fact(DisplayName = "Wrong Content-Type throws TimestampException")]
    public async Task GetTimestampAsync_WrongContentType_ThrowsInvalidDataException()
    {
        var handler = new MockHttpMessageHandler(
            new byte[] { 0x01 }, HttpStatusCode.OK, "text/html");
        var httpClient = new HttpClient(handler);
        var client = new TimestampClient(httpClient, "http://tsa.example.com");

        await Assert.ThrowsAsync<TimestampException>(
            () => client.GetTimestampAsync(new byte[] { 0x01 }, HashAlgorithmName.SHA256));
    }

    [Fact(DisplayName = "EmbedTimestamp with null CMS throws ArgumentNullException")]
    public void EmbedTimestampInCms_NullCms_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(
            () => TimestampClient.EmbedTimestampInCms(null!, new byte[] { 0x01 }));
    }

    [Fact(DisplayName = "EmbedTimestamp with null token throws ArgumentNullException")]
    public void EmbedTimestampInCms_NullToken_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(
            () => TimestampClient.EmbedTimestampInCms(new byte[] { 0x30 }, null!));
    }

    [Fact(DisplayName = "Valid CMS with timestamp returns larger CMS")]
    public void EmbedTimestampInCms_ValidCms_ReturnsCmsWithTimestamp()
    {
        // Generates a real CMS with CmsSignatureBuilder
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=TSA Test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        using var certWithKey = CertificateLoader
            .LoadPkcs12(cert.Export(X509ContentType.Pkcs12, "test-export"), "test-export");

        var cms = CmsSignatureBuilder.Build("test data"u8.ToArray(), certWithKey, HashAlgorithmName.SHA256);
        var fakeToken = new byte[] { 0x30, 0x03, 0x02, 0x01, 0x01 };

        var result = TimestampClient.EmbedTimestampInCms(cms, fakeToken);

        result.ShouldNotBeNull();
        result.Length.ShouldBeGreaterThan(cms.Length);
        // Token must appear in the result
        result.AsSpan().IndexOf(fakeToken).ShouldBeGreaterThan(0);
    }
}

/// <summary>Fake HttpMessageHandler for tests without network.</summary>
internal sealed class MockHttpMessageHandler(
    byte[] responseBytes,
    HttpStatusCode statusCode,
    string contentType) : HttpMessageHandler
{
    protected override Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var response = new HttpResponseMessage(statusCode)
        {
            Content = new ByteArrayContent(responseBytes)
        };
        response.Content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue(contentType);
        return Task.FromResult(response);
    }
}

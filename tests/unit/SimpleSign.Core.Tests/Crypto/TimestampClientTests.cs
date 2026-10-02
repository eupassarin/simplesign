using System.Formats.Asn1;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Shouldly;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Signing;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.Core.Tests.Crypto;

/// <summary>
/// Unit tests for TimestampClient.
/// HttpClient is mocked — no real network calls.
/// </summary>
[Trait("Category", "Unit")]
public sealed class TimestampClientTests
{
    // ── Helpers ────────────────────────────────────────────────────────────────

    private static byte[] BuildTimestampResponseForRequest(
        byte[] requestBytes,
        bool alterImprint = false,
        bool alterNonce = false)
        => TimestampTestResponseBuilder.CreateForRequest(requestBytes, alterImprint, alterNonce);

    private static HttpClient BuildMockHttpClient(byte[] responseBytes, HttpStatusCode statusCode = HttpStatusCode.OK)
    {
        return new HttpClient(new MockHttpHandler(async _ =>
        {
            var response = new HttpResponseMessage(statusCode)
            {
                Content = new ByteArrayContent(responseBytes)
            };
            response.Content.Headers.ContentType = new MediaTypeHeaderValue("application/timestamp-reply");
            return response;
        }));
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
        var httpClient = new HttpClient(new MockHttpHandler(async request =>
        {
            byte[] requestBytes = await request.Content!.ReadAsByteArrayAsync();
            var timestampRequest = new AsnReader(requestBytes, AsnEncodingRules.DER).ReadSequence();
            _ = timestampRequest.ReadInteger();
            var algorithm = timestampRequest.ReadSequence().ReadSequence();
            algorithm.ReadObjectIdentifier().ShouldBe(Oids.Sha256);
            algorithm.ReadNull();
            algorithm.ThrowIfNotEmpty();
            var response = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new ByteArrayContent(BuildTimestampResponseForRequest(requestBytes))
            };
            response.Content.Headers.ContentType = new MediaTypeHeaderValue("application/timestamp-reply");
            return response;
        }));
        var client = new TimestampClient(httpClient, "http://tsa.example.com");

        var token = await client.GetTimestampAsync(
            new byte[] { 0x01, 0x02, 0x03 }, HashAlgorithmName.SHA256);

        token.ShouldNotBeNull();
        token.Length.ShouldBeGreaterThan(0);
    }

    [SkippableFact(DisplayName = "RFC 9688 timestamp requests omit SHA-3 message-imprint parameters")]
    public async Task GetTimestampAsync_Sha3MessageImprint_OmitsParameters()
    {
        try
        {
            _ = SHA3_256.HashData("test"u8);
        }
        catch (PlatformNotSupportedException)
        {
            Skip.If(true, "SHA-3 not supported on this platform/runtime");
        }

        foreach ((HashAlgorithmName hash, string expectedOid) in new[]
        {
            (HashAlgorithmName.SHA3_256, Oids.Sha3_256),
            (HashAlgorithmName.SHA3_384, Oids.Sha3_384),
            (HashAlgorithmName.SHA3_512, Oids.Sha3_512)
        })
        {
            using var httpClient = new HttpClient(new MockHttpHandler(async request =>
            {
                byte[] requestBytes = await request.Content!.ReadAsByteArrayAsync();
                var reader = new AsnReader(requestBytes, AsnEncodingRules.DER);
                var timestampRequest = reader.ReadSequence();
                _ = timestampRequest.ReadInteger();
                var imprint = timestampRequest.ReadSequence();
                var algorithm = imprint.ReadSequence();
                algorithm.ReadObjectIdentifier().ShouldBe(expectedOid);
                algorithm.ThrowIfNotEmpty();

                var response = new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new ByteArrayContent(BuildTimestampResponseForRequest(requestBytes))
                };
                response.Content.Headers.ContentType = new MediaTypeHeaderValue("application/timestamp-reply");
                return response;
            }));
            var client = new TimestampClient(httpClient, "http://tsa.example.com");

            byte[] token = await client.GetTimestampAsync("imprint"u8.ToArray(), hash);
            token.ShouldNotBeEmpty();
        }
    }

    [Fact(DisplayName = "Timestamp response with a different message imprint is rejected")]
    public async Task GetTimestampAsync_DifferentMessageImprint_ThrowsTimestampException()
    {
        var httpClient = new HttpClient(new MockHttpHandler(async request =>
        {
            byte[] requestBytes = await request.Content!.ReadAsByteArrayAsync();
            var response = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new ByteArrayContent(BuildTimestampResponseForRequest(requestBytes, alterImprint: true))
            };
            response.Content.Headers.ContentType = new MediaTypeHeaderValue("application/timestamp-reply");
            return response;
        }));
        var client = new TimestampClient(httpClient, "http://tsa.example.com");

        await Assert.ThrowsAsync<TimestampException>(
            () => client.GetTimestampAsync(new byte[] { 0x01, 0x02, 0x03 }, HashAlgorithmName.SHA256));
    }

    [Fact(DisplayName = "Timestamp response with a different nonce is rejected")]
    public async Task GetTimestampAsync_DifferentNonce_ThrowsTimestampException()
    {
        var httpClient = new HttpClient(new MockHttpHandler(async request =>
        {
            byte[] requestBytes = await request.Content!.ReadAsByteArrayAsync();
            var response = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new ByteArrayContent(BuildTimestampResponseForRequest(requestBytes, alterNonce: true))
            };
            response.Content.Headers.ContentType = new MediaTypeHeaderValue("application/timestamp-reply");
            return response;
        }));
        var client = new TimestampClient(httpClient, "http://tsa.example.com");

        await Assert.ThrowsAsync<TimestampException>(
            () => client.GetTimestampAsync(new byte[] { 0x01, 0x02, 0x03 }, HashAlgorithmName.SHA256));
    }

    [Fact(DisplayName = "Factory timestamp token is validated against the supplied datum")]
    public void ValidateTimestampToken_TokenBoundToData_DoesNotThrow()
    {
        byte[] data = [0x01, 0x02, 0x03];
        byte[] token = TimestampTestResponseBuilder.CreateTokenForData(data, HashAlgorithmName.SHA256);

        var contentInfo = new AsnReader(token, AsnEncodingRules.DER).ReadSequence();
        contentInfo.ReadObjectIdentifier().ShouldBe("1.2.840.113549.1.7.2");
        var signedData = contentInfo.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true)).ReadSequence();
        signedData.ReadInteger().ShouldBe(new System.Numerics.BigInteger(3), "TSTInfo content requires CMS SignedData version 3");

        TimestampClient.ValidateTimestampToken(token, data, HashAlgorithmName.SHA256);
    }

    [Fact(DisplayName = "Factory timestamp token with a wrong imprint is rejected")]
    public void ValidateTimestampToken_TokenBoundToDifferentData_ThrowsTimestampException()
    {
        byte[] token = TimestampTestResponseBuilder.CreateTokenForData([0x01, 0x02, 0x03], HashAlgorithmName.SHA256);

        Assert.Throws<TimestampException>(
            () => TimestampClient.ValidateTimestampToken(token, [0x03, 0x02, 0x01], HashAlgorithmName.SHA256));
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
        var httpClient = new HttpClient(new MockHttpHandler(async _ =>
        {
            var response = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new ByteArrayContent([0x01])
            };
            response.Content.Headers.ContentType = new MediaTypeHeaderValue("text/html");
            return response;
        }));
        var client = new TimestampClient(httpClient, "http://tsa.example.com");

        await Assert.ThrowsAsync<TimestampException>(
            () => client.GetTimestampAsync(new byte[] { 0x01 }, HashAlgorithmName.SHA256));
    }

    [Fact(DisplayName = "EmbedTimestamp with null CMS throws ArgumentNullException")]
    public void EmbedTimestampInCms_NullCms_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(
            () => TimestampClient.EmbedTimestampInCms(null!, [0x01]));
    }

    [Fact(DisplayName = "EmbedTimestamp with null token throws ArgumentNullException")]
    public void EmbedTimestampInCms_NullToken_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(
            () => TimestampClient.EmbedTimestampInCms([0x30], null!));
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

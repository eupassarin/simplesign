using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using Shouldly;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Http;
using SimpleSign.Core.Signing;
using SimpleSign.Core.Validation;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.Core.Tests.Crypto;

[Trait("Category", "Unit")]
public sealed class TimestampTokenTests
{
    private static readonly byte[] s_data = "contrato de locação"u8.ToArray();

    [Fact]
    public async Task CreateAsync_Data_SendsOnlyTheHashAndReturnsTokenCoveringIt()
    {
        byte[]? sentHash = null;
        var options = Tsa(request => sentHash = ReadRequestHash(request));

        byte[] token = await TimestampToken.CreateAsync(s_data, options);

        sentHash.ShouldBe(SHA256.HashData(s_data));
        var result = TimestampToken.Verify(token, s_data);
        result.IsValid.ShouldBeTrue(string.Join("; ", result.Errors));
        result.IsTsaTrusted.ShouldBeNull();
        result.Info.ShouldNotBeNull().GenerationTime.ShouldBe(new DateTimeOffset(2024, 1, 1, 0, 0, 0, TimeSpan.Zero));
    }

    [Fact]
    public async Task CreateForHashAsync_Sha512Hash_VerifiesWithVerifyHash()
    {
        byte[] hash = SHA512.HashData(s_data);

        byte[] token = await TimestampToken.CreateForHashAsync(hash, HashAlgorithmName.SHA512, Tsa());

        TimestampToken.VerifyHash(token, hash, HashAlgorithmName.SHA512).IsValid.ShouldBeTrue();
        TimestampToken.Verify(token, s_data).IsValid.ShouldBeTrue();
    }

    [Fact]
    public async Task CreateForHashAsync_WrongHashLength_Throws()
    {
        await Should.ThrowAsync<ArgumentException>(() =>
            TimestampToken.CreateForHashAsync(new byte[20], HashAlgorithmName.SHA256, Tsa()));
    }

    [Fact]
    public async Task Verify_OtherData_ImprintInvalid()
    {
        byte[] token = await TimestampToken.CreateAsync(s_data, Tsa());

        var result = TimestampToken.Verify(token, "outro contrato"u8);

        result.IsValid.ShouldBeFalse();
        result.IsImprintValid.ShouldBeFalse();
        result.IsIntegrityValid.ShouldBeTrue();
        result.Errors.ShouldContain(e => e.Contains("messageImprint", StringComparison.Ordinal));
    }

    [Fact]
    public async Task VerifyHash_DifferentAlgorithm_ImprintInvalid()
    {
        byte[] token = await TimestampToken.CreateAsync(s_data, Tsa());

        TimestampToken.VerifyHash(token, SHA512.HashData(s_data), HashAlgorithmName.SHA512).IsImprintValid.ShouldBeFalse();
    }

    [Fact]
    public async Task Verify_TamperedToken_IntegrityInvalid()
    {
        byte[] token = await TimestampToken.CreateAsync(s_data, Tsa());
        token[^10] ^= 0xFF;

        var result = TimestampToken.Verify(token, s_data);

        result.IsIntegrityValid.ShouldBeFalse();
        result.IsValid.ShouldBeFalse();
    }

    [Fact]
    public void Verify_NotAToken_ReportsIt()
    {
        var result = TimestampToken.Verify([1, 2, 3], s_data);

        result.IsValid.ShouldBeFalse();
        result.Errors.ShouldHaveSingleItem();
    }

    [Fact]
    public async Task Verify_TrustAnchors_TrustedOnlyWhenTsaChains()
    {
        byte[] token = await TimestampToken.CreateAsync(s_data, Tsa());
        var tsa = TimestampValidator.ReadTokenCertificates(token)[0];
        using var other = TestCertificateFactory.CreateSelfSignedCert("CN=Other Root");

        TimestampToken.Verify(token, s_data, [tsa]).IsTsaTrusted.ShouldBe(true);
        var untrusted = TimestampToken.Verify(token, s_data, [other]);
        untrusted.IsTsaTrusted.ShouldBe(false);
        untrusted.IsValid.ShouldBeFalse();
    }

    private static TimestampOptions Tsa(Action<byte[]>? onRequest = null) =>
        new(new Uri("https://tsa.example.com/"), new SingleClientProvider(new HttpClient(new MockHttpHandler(async request =>
        {
            byte[] tsq = await request.Content!.ReadAsByteArrayAsync();
            onRequest?.Invoke(tsq);
            var response = new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(TimestampTestResponseBuilder.CreateForRequest(tsq)) };
            response.Content.Headers.ContentType = new MediaTypeHeaderValue("application/timestamp-reply");
            return response;
        }))));

    private static byte[] ReadRequestHash(byte[] request)
    {
        var reader = new System.Formats.Asn1.AsnReader(request, System.Formats.Asn1.AsnEncodingRules.DER).ReadSequence();
        _ = reader.ReadInteger();
        var imprint = reader.ReadSequence();
        _ = imprint.ReadSequence();
        return imprint.ReadOctetString();
    }
}

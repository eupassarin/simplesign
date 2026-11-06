using System.Formats.Asn1;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Shouldly;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Http;
using SimpleSign.Core.Signing;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.CAdES.Tests;

/// <summary>The content-time-stamp signed attribute (ETSI EN 319 122-1 §5.2.8): written by the builder, checked by the validator.</summary>
[Trait("Category", "Unit")]
public sealed class CadesContentTimestampTests : IDisposable
{
    private readonly X509Certificate2 _cert = TestCertificateFactory.CreateSelfSignedCert();
    private readonly byte[] _data = "content that existed before the signature"u8.ToArray();
    private readonly HttpClient _tsaHttp = new(new MockHttpHandler(async request =>
    {
        byte[] requestBytes = await request.Content!.ReadAsByteArrayAsync();
        var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(TimestampTestResponseBuilder.CreateForRequest(requestBytes)),
        };
        response.Content.Headers.ContentType = new MediaTypeHeaderValue("application/timestamp-reply");
        return response;
    }));

    public void Dispose()
    {
        _cert.Dispose();
        _tsaHttp.Dispose();
    }

    private TimestampOptions Tsa => new(new Uri("http://mock-tsa.example.com"), new SingleClientProvider(_tsaHttp));

    [SkippableFact]
    public async Task Validate_ContentTimestampWithSha3_IsValid()
    {
        // The token's imprint uses the signature's hash algorithm, so the validator has to recompute a SHA-3 imprint.
        Skip.IfNot(SHA3_256.IsSupported, "SHA-3 is unavailable on this platform.");
        byte[] cms = await CadesSigner.Document(_data)
            .WithCertificate(_cert)
            .WithHashAlgorithm(HashAlgorithmName.SHA3_256)
            .WithContentTimestamp(Tsa)
            .SignAsync();

        var result = new CadesSignatureValidator().Validate(cms, _data, [_cert]);

        result.Errors.ShouldBeEmpty();
        result.HasValidContentTimestamp.ShouldBe(true);
    }

    [Theory]
    [InlineData(CadesContentType.Detached)]
    [InlineData(CadesContentType.Enveloped)]
    public async Task SignAsync_WithContentTimestamp_SignsATokenOverTheContent(CadesContentType contentType)
    {
        byte[] cms = await CadesSigner.Document(_data)
            .WithCertificate(_cert)
            .WithContentType(contentType)
            .WithContentTimestamp(Tsa)
            .SignAsync();

        var signer = CmsParser.Parse(cms);
        byte[] token = SignedAttribute(signer, Oids.ContentTimestamp).ShouldNotBeNull();
        var verification = TimestampToken.Verify(token, _data);
        verification.IsImprintValid.ShouldBeTrue();
        verification.IsIntegrityValid.ShouldBeTrue();
        // A B-B signature: the content timestamp is not the signature timestamp.
        signer.SignatureTimestampToken.ShouldBeNull();
    }

    [Fact]
    public async Task Validate_SignatureWithContentTimestamp_ReportsItValidWithItsTime()
    {
        byte[] cms = await CadesSigner.Document(_data).WithCertificate(_cert).WithContentTimestamp(Tsa).SignAsync();

        var report = new CadesSignatureValidator().ValidateAll(cms, _data, [_cert]);

        report.IsValid.ShouldBeTrue(string.Join("; ", report.Errors.Concat(report.Signers.SelectMany(s => s.Result.Errors))));
        var result = report.Signers[0].Result;
        result.HasValidContentTimestamp.ShouldBe(true);
        // The mock TSA stamps every token with this fixed time.
        result.ContentTimestampTime.ShouldBe(new DateTimeOffset(2024, 1, 1, 0, 0, 0, TimeSpan.Zero));
        result.HasValidTimestamp.ShouldBeNull();
    }

    [Fact]
    public async Task Validate_OtherContent_ContentTimestampDoesNotCoverIt()
    {
        byte[] cms = await CadesSigner.Document(_data).WithCertificate(_cert).WithContentTimestamp(Tsa).SignAsync();

        var result = new CadesSignatureValidator().ValidateAll(cms, "another content"u8.ToArray(), [_cert]).Signers[0].Result;

        result.IsIntegrityValid.ShouldBeFalse();
        result.HasValidContentTimestamp.ShouldBe(false);
        result.ContentTimestampTime.ShouldBeNull();
        result.Errors.ShouldContain(e => e.Contains("content-time-stamp", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Validate_SignatureWithoutContentTimestamp_ReportsNull()
    {
        byte[] cms = await CadesSigner.Document(_data).WithCertificate(_cert).SignAsync();

        new CadesSignatureValidator().ValidateAll(cms, _data, [_cert]).Signers[0].Result.HasValidContentTimestamp.ShouldBeNull();
    }

    [Fact]
    public async Task SignAsync_ContentTimestampWithTimestampedLevel_CarriesBothTimestamps()
    {
        byte[] cms = await CadesSigner.Document(_data)
            .WithCertificate(_cert)
            .WithContentTimestamp(Tsa)
            .WithLevel(AdesBaselineProfile.Timestamped(Tsa))
            .SignAsync();

        var result = new CadesSignatureValidator().ValidateAll(cms, _data, [_cert]).Signers[0].Result;

        result.HasValidContentTimestamp.ShouldBe(true);
        result.HasValidTimestamp.ShouldBe(true);
    }

    [Fact]
    public async Task SignAsync_ExternalSignerWithContentTimestamp_Validates()
    {
        byte[] cms = await CadesSigner.Document(_data)
            .WithExternalSigner(_cert, new DelegatingExternalSigner(data =>
            {
                using var rsa = _cert.GetRSAPrivateKey()!;
                return Task.FromResult(rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
            }))
            .WithContentTimestamp(Tsa)
            .SignAsync();

        var report = new CadesSignatureValidator().ValidateAll(cms, _data, [_cert]);

        report.IsValid.ShouldBeTrue(string.Join("; ", report.Signers.SelectMany(s => s.Result.Errors)));
        report.Signers[0].Result.HasValidContentTimestamp.ShouldBe(true);
    }

    [Fact]
    public async Task SignAsync_TsaDoesNotAnswer_Throws()
    {
        using var failing = MockHttpHandler.Failing();
        var builder = CadesSigner.Document(_data).WithCertificate(_cert)
            .WithContentTimestamp(new TimestampOptions(new Uri("http://mock-tsa.example.com"), new SingleClientProvider(failing)));

        var exception = await Should.ThrowAsync<SigningException>(() => builder.SignAsync());

        exception.Reason.ShouldBe(SigningErrorReason.NetworkFailure);
        exception.Message.ShouldContain("Content timestamp");
    }

    [Fact]
    public async Task SignAsync_CounterSignatureWithContentTimestamp_Throws()
    {
        byte[] signed = await CadesSigner.Document(_data).WithCertificate(_cert).SignAsync();
        var builder = CadesSigner.CounterSign(signed).WithCertificate(_cert).WithContentTimestamp(Tsa);

        var exception = await Should.ThrowAsync<SigningException>(() => builder.SignAsync());

        exception.Message.ShouldContain("countersignature");
    }

    [Fact]
    public void WithContentTimestamp_Null_Throws() =>
        Should.Throw<ArgumentNullException>(() => CadesSigner.Document(_data).WithContentTimestamp(null!));

    private static byte[]? SignedAttribute(CmsSignedData signer, string oid)
    {
        var set = new AsnReader(signer.SignedAttrs!, AsnEncodingRules.BER).ReadSetOf();
        while (set.HasData)
        {
            var attribute = set.ReadSequence();
            if (attribute.ReadObjectIdentifier() == oid)
            {
                return attribute.ReadSetOf().ReadEncodedValue().ToArray();
            }
        }

        return null;
    }
}

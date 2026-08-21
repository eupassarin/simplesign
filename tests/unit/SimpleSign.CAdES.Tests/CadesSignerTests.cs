using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Http;
using SimpleSign.Core.Signing;
using SimpleSign.Core.Validation;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.CAdES.Tests;

public sealed class CadesSignerTests : IDisposable
{
    private readonly X509Certificate2 _cert;
    private readonly byte[] _data;
    private readonly SyntheticPki _pki;

    public CadesSignerTests()
    {
        _cert = TestCertificateFactory.CreateSelfSignedCert();
        _data = "Hello, CAdES!"u8.ToArray();
        _pki = new SyntheticPki("http://mock-tsa.example.com/crl");
    }

    public void Dispose()
    {
        _cert.Dispose();
        _pki.Dispose();
    }

    [Fact]
    public async Task SignAsync_Basic_CreatesValidCms()
    {
        var cms = await CadesSigner.Document(_data)
            .WithCertificate(_cert)
            .SignAsync();

        Assert.NotNull(cms);
        Assert.True(cms.Length > 100, "CMS should be substantial in size");

        var parsed = CmsParser.Parse(cms);
        Assert.NotNull(parsed.SignerCertificate);
        Assert.Equal(_cert.Subject, parsed.SignerCertificate.Subject);
        Assert.NotNull(parsed.MessageDigest);
        Assert.NotNull(parsed.Signature);
        Assert.NotNull(parsed.SignedAttrs);
        Assert.Null(parsed.SignatureTimestampToken);
        Assert.NotNull(parsed.SigningTime);
    }

    [Fact]
    public async Task SignAsync_Basic_HashMatchesOriginalData()
    {
        var cms = await CadesSigner.Document(_data)
            .WithCertificate(_cert)
            .SignAsync();

        var parsed = CmsParser.Parse(cms);
        var expectedHash = SHA256.HashData(_data);

        Assert.Equal(expectedHash, parsed.MessageDigest);
    }

    [Fact]
    public async Task SignAsync_WithCommitmentType_IncludesAttribute()
    {
        var cms = await CadesSigner.Document(_data)
            .WithCertificate(_cert)
            .WithCommitmentType(CommitmentType.ProofOfOrigin)
            .SignAsync();
        var parsed = CmsParser.Parse(cms);

        Assert.Equal(Core.Constants.Oids.ProofOfOrigin, parsed.CommitmentTypeOid);
    }

    [Fact]
    public async Task SignAsync_WithSignaturePolicy_IncludesAttribute()
    {
        var cms = await CadesSigner.Document(_data)
            .WithCertificate(_cert)
            .WithSignaturePolicy("2.16.76.1.7.1.1.1.1", "https://example.com/policy")
            .SignAsync();

        var parsed = CmsParser.Parse(cms);

        Assert.Equal("2.16.76.1.7.1.1.1.1", parsed.SignaturePolicyOid);
    }

    [Fact]
    public async Task SignAsync_WithExtraCertificates_IncludesChain()
    {
        var cms = await CadesSigner.Document(_data)
            .WithCertificate(_cert, [_pki.IntermediateCa])
            .SignAsync();
        var parsed = CmsParser.Parse(cms);

        Assert.Contains(parsed.Certificates, c => c.Subject == _pki.IntermediateCa.Subject);
    }

    [Fact]
    public async Task SignAsync_WithSha512_UsesSha512Digest()
    {
        var cms = await CadesSigner.Document(_data)
            .WithCertificate(_cert)
            .WithHashAlgorithm(HashAlgorithmName.SHA512)
            .SignAsync();
        var parsed = CmsParser.Parse(cms);

        Assert.Equal(Core.Constants.Oids.Sha512, parsed.DigestAlgorithmOid);
    }

    [Fact]
    public async Task SignAsync_ExternalSigner_CreatesValidCms()
    {
        var cms = await CadesSigner.Document(_data)
            .WithExternalSigner(_cert, new FuncExternalSigner(async signedAttrs =>
            {
                using var key = _cert.GetRSAPrivateKey()!;
                return await Task.FromResult(key.SignData(signedAttrs, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
            }))
            .WithSignatureAlgorithm(Core.Constants.Oids.RsaSha256)
            .SignAsync();

        Assert.NotNull(cms);
        Assert.True(cms.Length > 100);

        var parsed = CmsParser.Parse(cms);
        Assert.NotNull(parsed.SignerCertificate);
    }

    [Fact]
    public async Task SignAndValidate_Roundtrip_Succeeds()
    {
        var cms = await CadesSigner.Document(_data)
            .WithCertificate(_cert)
            .SignAsync();

        var validator = new CadesSignatureValidator(
            new ValidationOptions { CheckRevocation = false, TrustSystemRoots = false });
        var result = validator.Validate(cms, _data, [_cert]);

        Assert.True(result.IsIntegrityValid);
        Assert.True(result.IsSignatureValid);
        Assert.True(result.IsCertificateChainValid);
        Assert.True(result.IsValid);
        Assert.Empty(result.Errors);
    }

    [Fact]
    public async Task Validate_TamperedData_DetectsIntegrityFailure()
    {
        var cms = await CadesSigner.Document(_data)
            .WithCertificate(_cert)
            .SignAsync();
        var tamperedData = "Tampered!"u8.ToArray();

        var validator = new CadesSignatureValidator(
            new ValidationOptions { CheckRevocation = false, TrustSystemRoots = false });
        var result = validator.Validate(cms, tamperedData, [_cert]);

        Assert.False(result.IsIntegrityValid);
        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Contains("hash mismatch", StringComparison.OrdinalIgnoreCase)
                                          || e.Contains("altered", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Validate_InvalidCertificateChain_ReportsChainFailure()
    {
        var cms = await CadesSigner.Document(_data)
            .WithCertificate(_cert)
            .SignAsync();

        var validator = new CadesSignatureValidator(
            new ValidationOptions { CheckRevocation = false, TrustSystemRoots = false });
        var result = validator.Validate(cms, _data);

        Assert.False(result.IsCertificateChainValid);
        Assert.False(result.IsValid);
    }

    [Fact]
    public async Task SignAsync_WithEcdsa_CreatesValidCms()
    {
        using var ecdsaCert = TestCertificateFactory.CreateEcdsaCert();

        var cms = await CadesSigner.Document(_data)
            .WithCertificate(ecdsaCert)
            .SignAsync();
        var parsed = CmsParser.Parse(cms);

        Assert.NotNull(parsed.SignerCertificate);
        Assert.Equal(ecdsaCert.Subject, parsed.SignerCertificate.Subject);

        var validator = new CadesSignatureValidator(
            new ValidationOptions { CheckRevocation = false, TrustSystemRoots = false });
        var result = validator.Validate(cms, _data, [ecdsaCert]);

        Assert.True(result.IsIntegrityValid);
        Assert.True(result.IsSignatureValid);
    }

    [Fact]
    public async Task SignAsync_LongTerm_IncludesCertValues()
    {
        var mockTsa = BuildMockTsaHandler();
        using var tsaHttpClient = new HttpClient(mockTsa);

        var cms = await CadesSigner.Document(_data)
            .WithCertificate(_cert, [_pki.IntermediateCa])
            .WithLevel(AdesBaselineProfile.LongTerm(
                new TimestampOptions(new Uri("http://mock-tsa.example.com"), new SingleClientProvider(tsaHttpClient)),
                new LongTermValidationOptions(new SingleClientProvider(tsaHttpClient))))
            .SignAsync();
        var parsed = CmsParser.Parse(cms);

        Assert.NotNull(parsed.SignatureTimestampToken);
        Assert.NotNull(parsed.UnsignedAttributes);
        Assert.True(parsed.UnsignedAttributes.ContainsKey(Oids.CertValues));
    }

    [Fact]
    public async Task SignAsync_LongTerm_WithoutRevocationData_ThrowsSigningException()
    {
        var mockTsa = BuildMockTsaHandler();
        using var tsaHttpClient = new HttpClient(mockTsa);

        await Assert.ThrowsAsync<SigningException>(() => CadesSigner.Document(_data)
            .WithCertificate(_cert)
            .WithLevel(AdesBaselineProfile.LongTerm(
                new TimestampOptions(new Uri("http://mock-tsa.example.com"), new SingleClientProvider(tsaHttpClient)),
                new LongTermValidationOptions(new SingleClientProvider(tsaHttpClient))))
            .SignAsync());
    }

    [Fact]
    public async Task SignAsync_Archive_IncludesArchiveTimestamp()
    {
        var mockTsa = BuildMockTsaHandler();
        using var tsaHttpClient = new HttpClient(mockTsa);

        var cms = await CadesSigner.Document(_data)
            .WithCertificate(_cert, [_pki.IntermediateCa])
            .WithLevel(AdesBaselineProfile.Archive(
                new TimestampOptions(new Uri("http://mock-tsa.example.com"), new SingleClientProvider(tsaHttpClient)),
                new LongTermValidationOptions(new SingleClientProvider(tsaHttpClient))))
            .SignAsync();
        var parsed = CmsParser.Parse(cms);

        Assert.NotNull(parsed.SignatureTimestampToken);
        Assert.NotNull(parsed.ArchiveTimestampToken);
        Assert.NotNull(parsed.UnsignedAttributes);
        Assert.True(parsed.UnsignedAttributes.ContainsKey(Oids.CertValues));
        Assert.True(parsed.UnsignedAttributes.ContainsKey(Oids.ArchiveTimeStamp));
    }

    [Fact]
    public async Task SignAndValidate_LongTerm_Roundtrip_Succeeds()
    {
        var mockTsa = BuildMockTsaHandler();
        using var tsaHttpClient = new HttpClient(mockTsa);

        var cms = await CadesSigner.Document(_data)
            .WithCertificate(_cert, [_pki.IntermediateCa])
            .WithLevel(AdesBaselineProfile.LongTerm(
                new TimestampOptions(new Uri("http://mock-tsa.example.com"), new SingleClientProvider(tsaHttpClient)),
                new LongTermValidationOptions(new SingleClientProvider(tsaHttpClient))))
            .SignAsync();

        var directParsed = CmsParser.Parse(cms);
        Assert.NotNull(directParsed.UnsignedAttributes);
        Assert.True(directParsed.UnsignedAttributes.ContainsKey(Oids.CertValues));

        var validator = new CadesSignatureValidator(
            new ValidationOptions { CheckRevocation = false, TrustSystemRoots = false });
        var result = validator.Validate(cms, _data, [_cert]);

        Assert.True(result.IsIntegrityValid);
        Assert.True(result.IsSignatureValid);
        Assert.True(result.IsCertificateChainValid);
        Assert.True(result.IsValid);
        Assert.True(result.IsLtvDataValid);
    }

    [Fact]
    public async Task CmsParser_ParsesUnsignedAttributes()
    {
        // Create a minimal CMS with unsigned attributes to verify parsing
        var cmsNoUnsigned = await CadesSigner.Document(_data)
            .WithCertificate(_cert)
            .SignAsync();
        var parsedNoUnsigned = CmsParser.Parse(cmsNoUnsigned);
        Assert.Null(parsedNoUnsigned.UnsignedAttributes);

        // With B-T, should have SignatureTimestampToken unsigned attribute
        var mockTsa = BuildMockTsaHandler();
        using var tsaHttpClient = new HttpClient(mockTsa);
        var cmsWithUnsigned = await CadesSigner.Document(_data)
            .WithCertificate(_cert)
            .WithLevel(AdesBaselineProfile.Timestamped(
                new TimestampOptions(new Uri("http://mock-tsa.example.com"), new SingleClientProvider(tsaHttpClient))))
            .SignAsync();
        var parsedWithUnsigned = CmsParser.Parse(cmsWithUnsigned);

        Assert.NotNull(parsedWithUnsigned.UnsignedAttributes);
        Assert.True(parsedWithUnsigned.UnsignedAttributes.ContainsKey(Oids.SignatureTimestampToken));
    }

    private static MockHttpHandler BuildMockTsaHandler()
    {
        var fakeTsr = BuildFakeTimestampResponse();
        return new MockHttpHandler(async _ =>
        {
            var response = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new ByteArrayContent(fakeTsr)
            };
            response.Content.Headers.ContentType =
                new MediaTypeHeaderValue("application/timestamp-reply");
            await Task.CompletedTask;
            return response;
        });
    }

    private static byte[] BuildFakeTimestampResponse()
    {
        var fakeCmsToken = BuildFakeCmsToken();
        var writer = new System.Formats.Asn1.AsnWriter(System.Formats.Asn1.AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            using (writer.PushSequence())
                writer.WriteInteger(0);
            writer.WriteEncodedValue(fakeCmsToken);
        }
        return writer.Encode();
    }

    private static byte[] BuildFakeCmsToken()
    {
        var writer = new System.Formats.Asn1.AsnWriter(System.Formats.Asn1.AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            writer.WriteObjectIdentifier("1.2.840.113549.1.7.2");
            using (writer.PushSequence(new System.Formats.Asn1.Asn1Tag(
                System.Formats.Asn1.TagClass.ContextSpecific, 0, true)))
            {
                writer.WriteOctetString([0x01, 0x02, 0x03]);
            }
        }
        return writer.Encode();
    }
}

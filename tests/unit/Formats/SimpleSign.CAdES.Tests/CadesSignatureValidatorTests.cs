using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography.X509Certificates;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Http;
using SimpleSign.Core.Signing;
using SimpleSign.Core.Validation;
using SimpleSign.TestHelpers;
using Shouldly;
using Xunit;

namespace SimpleSign.CAdES.Tests;

[Trait("Category", "Unit")]
public sealed class CadesSignatureValidatorTests : IDisposable
{
    private readonly X509Certificate2 _cert;
    private readonly byte[] _data;

    public CadesSignatureValidatorTests()
    {
        _cert = TestCertificateFactory.CreateSelfSignedCert();
        _data = "Hello, CAdES!"u8.ToArray();
    }

    public void Dispose() => _cert.Dispose();

    [Fact]
    public async Task Validate_ValidDetachedSignature_ReturnsValid()
    {
        var cms = await CadesSigner.Document(_data)
            .WithCertificate(_cert)
            .SignAsync();

        var validator = new CadesSignatureValidator(
            new ValidationOptions { CheckRevocation = false });
        var result = validator.Validate(cms, _data, [_cert]);

        result.IsValid.ShouldBeTrue();
    }

    [Fact]
    public async Task Validate_EnvelopedSignature_ReturnsValid()
    {
        var cms = await CadesSigner.Document(_data)
            .WithCertificate(_cert)
            .WithContentType(CadesContentType.Enveloped)
            .SignAsync();

        var validator = new CadesSignatureValidator(
            new ValidationOptions { CheckRevocation = false });
        var result = validator.Validate(cms, _data, [_cert]);

        result.IsValid.ShouldBeTrue();
    }

    [Fact]
    public async Task Validate_DetachedSignatureWithoutData_IndeterminateSignedDataNotFound()
    {
        var cms = await CadesSigner.Document(_data)
            .WithCertificate(_cert)
            .SignAsync();

        var validator = new CadesSignatureValidator(
            new ValidationOptions { CheckRevocation = false });
        var result = validator.Validate(cms, originalData: null, [_cert]);

        result.Indication.ShouldBe(SignatureIndication.Indeterminate);
        result.SubIndication.ShouldBe(SignatureSubIndication.SignedDataNotFound);
        result.Errors.ShouldContain(e => e.Contains("signed data was not given", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Validate_WrongData_DetachedSignature_ReturnsInvalid()
    {
        var cms = await CadesSigner.Document(_data)
            .WithCertificate(_cert)
            .SignAsync();
        var wrongData = "Wrong data!"u8.ToArray();

        var validator = new CadesSignatureValidator(
            new ValidationOptions { CheckRevocation = false });
        var result = validator.Validate(cms, wrongData, [_cert]);

        result.IsIntegrityValid.ShouldBeFalse();
    }

    [Fact]
    public async Task Validate_TamperedCms_ReturnsInvalid()
    {
        var cms = await CadesSigner.Document(_data)
            .WithCertificate(_cert)
            .SignAsync();
        var tampered = (byte[])cms.Clone();
        tampered[^1] ^= 0xFF;

        var validator = new CadesSignatureValidator(
            new ValidationOptions { CheckRevocation = false });
        var result = validator.Validate(tampered, _data, [_cert]);

        result.IsSignatureValid.ShouldBeFalse();
    }

    [Fact]
    public async Task Validate_TrustedChain_ReturnsValid()
    {
        using var pki = new SyntheticPki();
        var cms = await CadesSigner.Document(_data)
            .WithCertificate(pki.Leaf, pki.IntermediatesAndRoot())
            .SignAsync();

        var validator = new CadesSignatureValidator(
            new ValidationOptions { CheckRevocation = false, TrustSystemRoots = false });
        var result = validator.Validate(cms, _data, [pki.IntermediateCa, pki.RootCa]);

        result.IsCertificateChainValid.ShouldBeTrue();
    }

    [Fact]
    public async Task Validate_OnlyRootTrusted_UsesIntermediateEmbeddedInCms()
    {
        using var pki = new SyntheticPki();
        var cms = await CadesSigner.Document(_data)
            .WithCertificate(pki.Leaf, pki.IntermediatesAndRoot())
            .SignAsync();

        var validator = new CadesSignatureValidator(
            new ValidationOptions { CheckRevocation = false, TrustSystemRoots = false, TrustedRoots = [pki.RootCa] });
        var result = validator.Validate(cms, _data);

        result.Errors.ShouldBeEmpty();
        result.IsCertificateChainValid.ShouldBeTrue();
    }

    [Fact]
    public async Task Validate_UntrustedChain_ReturnsInvalid()
    {
        var cms = await CadesSigner.Document(_data)
            .WithCertificate(_cert)
            .SignAsync();
        using var wrongAnchor = TestCertificateFactory.CreateSelfSignedCert("CN=Wrong Anchor");

        var validator = new CadesSignatureValidator(
            new ValidationOptions { CheckRevocation = false, TrustSystemRoots = false });
        var result = validator.Validate(cms, _data, [wrongAnchor]);

        result.IsCertificateChainValid.ShouldBeFalse();
    }

    // Null data now means "use the encapsulated content" (attached .p7m); with unparseable
    // CMS it is a validation error, not an exception.
    [Fact]
    public void Validate_NullOriginalDataAndInvalidCms_ReturnsError()
    {
        var cms = new byte[] { 1, 2, 3 };
        var validator = new CadesSignatureValidator(
            new ValidationOptions { CheckRevocation = false });

        var result = validator.Validate(cms, null);

        result.Errors.ShouldNotBeEmpty();
        result.IsIntegrityValid.ShouldBeFalse();
    }

    [Fact]
    public void Validate_EmptyCms_ReturnsError()
    {
        var validator = new CadesSignatureValidator(
            new ValidationOptions { CheckRevocation = false });
        var result = validator.Validate([], _data);

        result.Errors.ShouldNotBeEmpty();
    }

    [Fact]
    public async Task Validate_DetectedLevel_Basic()
    {
        var cms = await CadesSigner.Document(_data)
            .WithCertificate(_cert)
            .SignAsync();

        var validator = new CadesSignatureValidator(
            new ValidationOptions { CheckRevocation = false });
        var result = validator.Validate(cms, _data, [_cert]);

        result.HasValidTimestamp.ShouldBeNull();
        result.IsLtvDataValid.ShouldBeNull();
    }

    [Fact]
    public async Task Validate_IncompleteLegacyUnsignedValidationAttributes_DoesNotClaimLtv()
    {
        byte[] cms = await CadesSigner.Document(_data)
            .WithCertificate(_cert)
            .SignAsync();
        byte[] legacy = CmsSignatureBuilder.AddUnsignedAttributes(cms,
        [
            CmsAttribute.Raw(Oids.CertValues, [0x30, 0x00]),
        ]);

        var result = new CadesSignatureValidator(
            new ValidationOptions { CheckRevocation = false }).Validate(legacy, _data, [_cert]);

        result.IsLtvDataValid.ShouldBe(false);
    }

    [Fact]
    public async Task ReadValidationMaterial_RootOcspChoice_ExtractsResponse()
    {
        byte[] cms = await CadesSigner.Document(_data)
            .WithCertificate(_cert)
            .SignAsync();
        byte[] ocspResponse = [0x30, 0x03, 0x02, 0x01, 0x01];
        byte[] withOcsp = CmsSignatureBuilder.AddValidationMaterial(
            cms, [_cert.RawData], [], [ocspResponse]);

        CadesValidationMaterial material = CadesValidationMaterial.Read(withOcsp);

        material.HasRevocationSet.ShouldBeTrue();
        material.Certificates.ShouldContain(cert => cert.SequenceEqual(_cert.RawData));
        material.OcspResponses.ShouldContain(response => response.SequenceEqual(ocspResponse));
        material.Crls.ShouldBeEmpty();
    }

    [Fact]
    public async Task Validate_DetectedLevel_Timestamped()
    {
        var mockTsa = BuildMockTsaHandler();
        using var tsaHttpClient = new HttpClient(mockTsa);

        var cms = await CadesSigner.Document(_data)
            .WithCertificate(_cert)
            .WithLevel(AdesBaselineProfile.Timestamped(
                new TimestampOptions(new Uri("http://mock-tsa.example.com"), new SingleClientProvider(tsaHttpClient))))
            .SignAsync();

        var validator = new CadesSignatureValidator(
            new ValidationOptions { CheckRevocation = false },
            timestampValidator: new AlwaysValidTimestampValidator());
        var result = validator.Validate(cms, _data, [_cert]);

        result.HasValidTimestamp.ShouldBe(true);
    }

    private sealed class AlwaysValidTimestampValidator : Core.Validation.ITimestampValidator
    {
        public bool? Validate(
            byte[] timestampToken,
            byte[] signatureValueBytes,
            DateTimeOffset? signingTime,
            List<string> warnings,
            Core.Validation.TimestampValidator.CertificateChainValidatorDelegate? validateChain = null,
            Microsoft.Extensions.Logging.ILogger? logger = null) => true;

        public bool? Validate(
            Core.Crypto.CmsSignedData cmsData,
            List<string> warnings,
            Core.Validation.TimestampValidator.CertificateChainValidatorDelegate? validateChain = null,
            Microsoft.Extensions.Logging.ILogger? logger = null) => true;
    }

    private static MockHttpHandler BuildMockTsaHandler()
    {
        return new MockHttpHandler(async request =>
        {
            byte[] requestBytes = await request.Content!.ReadAsByteArrayAsync();
            var response = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new ByteArrayContent(TimestampTestResponseBuilder.CreateForRequest(requestBytes))
            };
            response.Content.Headers.ContentType =
                new MediaTypeHeaderValue("application/timestamp-reply");
            return response;
        });
    }

    [Fact]
    public async Task Validate_RootWithdrawnAfterTheTimestamp_TimedAnchorsTrustTheSignature()
    {
        using var pki = new SyntheticPki();
        using var tsaCert = pki.IssueTimestampingCertificate();
        using var tsa = new HttpClient(new MockHttpHandler(async request =>
        {
            byte[] body = await request.Content!.ReadAsByteArrayAsync().ConfigureAwait(false);
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new ByteArrayContent(TimestampTestResponseBuilder.CreateForRequest(body,
                    new TimestampTokenOptions { TsaCertificate = tsaCert, ExtraCertificates = [pki.IntermediateCa], GenTime = DateTimeOffset.UtcNow }))
                {
                    Headers = { ContentType = new MediaTypeHeaderValue("application/timestamp-reply") },
                },
            };
        }));
        byte[] cms = await CadesSigner.Document(_data)
            .WithCertificate(pki.Leaf, [pki.IntermediateCa])
            .WithLevel(AdesBaselineProfile.Timestamped(new TimestampOptions(new Uri("http://tsa.example.com"), new SingleClientProvider(tsa))))
            .SignAsync();
        var withdrawal = DateTimeOffset.UtcNow.AddSeconds(1);
        var history = new WithdrawnAt(pki.RootCa, withdrawal);
        await Task.Delay(TimeSpan.FromSeconds(1.5));

        var withoutHistory = new CadesSignatureValidator(new ValidationOptions { CheckRevocation = false, TrustSystemRoots = false }).Validate(cms, _data);
        var withHistory = new CadesSignatureValidator(
            new ValidationOptions { CheckRevocation = false, TrustSystemRoots = false, TimedTrustAnchors = [history] }).Validate(cms, _data);

        withoutHistory.Indication.ShouldNotBe(SignatureIndication.Valid);
        withHistory.IsCertificateChainValid.ShouldBeTrue(string.Join("; ", withHistory.Errors) + " W: " + string.Join("; ", withHistory.Warnings));
        withHistory.Indication.ShouldBe(SignatureIndication.Valid, string.Join("; ", withHistory.Errors));
        withHistory.Warnings.ShouldContain(w => w.Contains("proof of existence", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Validate_SignatureTsaExpiredWithArchiveTimestamp_TsaTrustedThroughPastSignatureValidation()
    {
        var now = DateTimeOffset.UtcNow;
        using var expiredTsa = SelfSignedTsa("CN=Expired TSA", now.AddDays(-3), now.AddDays(-1));
        using var archiveTsa = SelfSignedTsa("CN=Archive TSA", now.AddDays(-3), now.AddYears(1));
        byte[] signed = await CadesSigner.Document(_data).WithCertificate(_cert).SignAsync();
        byte[] signatureToken = TimestampTestResponseBuilder.CreateTokenForData(
            TimestampClient.ExtractSignatureValue(signed), new TimestampTokenOptions { TsaCertificate = expiredTsa, GenTime = now.AddDays(-2) });
        byte[] timestamped = TimestampClient.EmbedTimestampInCms(signed, signatureToken);
        byte[] hashIndex = CadesArchiveTimestampV3.CreateHashIndex(timestamped, System.Security.Cryptography.HashAlgorithmName.SHA256);
        byte[] input = CadesArchiveTimestampV3.CreateMessageImprintInput(timestamped, _data, System.Security.Cryptography.HashAlgorithmName.SHA256, hashIndex);
        byte[] archiveToken = CadesArchiveTimestampV3.AddHashIndexToTimestampToken(
            TimestampTestResponseBuilder.CreateTokenForData(input, new TimestampTokenOptions { TsaCertificate = archiveTsa, GenTime = now.AddDays(-1.5) }), hashIndex);
        byte[] archived = CmsSignatureBuilder.AddUnsignedAttributes(timestamped, [CmsAttribute.Raw(Oids.ArchiveTimeStampV3, archiveToken)]);
        var options = new ValidationOptions { CheckRevocation = false, TrustSystemRoots = false, TrustedRoots = [_cert, expiredTsa, archiveTsa] };

        var withoutArchive = new CadesSignatureValidator(options).Validate(timestamped, _data);
        var withArchive = new CadesSignatureValidator(options).Validate(archived, _data);

        withoutArchive.IsTsaTrusted.ShouldNotBe(true);
        withArchive.IsTsaTrusted.ShouldBe(true, string.Join("; ", withArchive.Warnings));
        withArchive.Warnings.ShouldContain(w => w.Contains("past signature validation", StringComparison.Ordinal));
    }

    private static X509Certificate2 SelfSignedTsa(string subject, DateTimeOffset notBefore, DateTimeOffset notAfter)
    {
        using var key = System.Security.Cryptography.RSA.Create(2048);
        var request = new System.Security.Cryptography.X509Certificates.CertificateRequest(
            subject, key, System.Security.Cryptography.HashAlgorithmName.SHA256, System.Security.Cryptography.RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation, true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new System.Security.Cryptography.Oid("1.3.6.1.5.5.7.3.8")], true));
        return request.CreateSelfSigned(notBefore, notAfter);
    }

    /// <summary>A trusted list whose root CA service is granted until <paramref name="withdrawal"/>, withdrawn after.</summary>
    private sealed class WithdrawnAt(X509Certificate2 root, DateTimeOffset withdrawal) : SimpleSign.Core.Extensions.ITimedTrustAnchorProvider
    {
        public string RegionCode => "XX";

        public string DisplayName => "Withdrawn root";

        public IReadOnlyList<X509Certificate2> GetTrustAnchors() => GetTrustAnchors(DateTimeOffset.UtcNow);

        public IReadOnlyList<X509Certificate2> GetTrustAnchors(DateTimeOffset at) => at < withdrawal ? [root] : [];
    }
}

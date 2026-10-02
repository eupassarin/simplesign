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

    [Fact]
    public void Validate_NullOriginalData_Throws()
    {
        var cms = new byte[] { 1, 2, 3 };
        var validator = new CadesSignatureValidator(
            new ValidationOptions { CheckRevocation = false });

        Should.Throw<ArgumentNullException>(() => validator.Validate(cms, null!));
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

}

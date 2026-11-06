using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;
using Shouldly;
using SimpleSign.Core.Validation;
using SimpleSign.Core.Validation.Policy;
using SimpleSign.PAdES;
using SimpleSign.PAdES.Validation;
using SimpleSign.TestHelpers;

namespace SimpleSign.Peru.Iofe.Tests;

[Trait("Category", "Unit")]
public sealed class IofeExtensionTests : IDisposable
{
    private readonly RSA _operatorKey = RSA.Create(2048);
    private readonly X509Certificate2 _operator;
    private readonly SyntheticPki _pki = new();

    public IofeExtensionTests()
    {
        _operator = new CertificateRequest("CN=INDECOPI TSL, C=PE", _operatorKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            .CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(2));
    }

    [Fact]
    public void Load_SignedList_AnchorsAreTheActiveCas()
    {
        var iofe = IofeExtension.Load(TrustedListXml(), [_operator]);

        iofe.RegionCode.ShouldBe("PE");
        iofe.TrustAnchorProviders.ShouldHaveSingleItem().GetTrustAnchors().ShouldHaveSingleItem().Thumbprint.ShouldBe(_pki.RootCa.Thumbprint);
    }

    [Fact]
    public async Task LoadAsync_WithoutSigner_Throws() =>
        await Should.ThrowAsync<ArgumentException>(() => IofeExtension.LoadAsync(new IofeExtensionOptions()));

    [Fact]
    public async Task Validator_WithIofe_TrustsAChainOfTheList()
    {
        var iofe = IofeExtension.Load(TrustedListXml(), [_operator]);
        byte[] signed = await PadesSigner.Document(TestPdfFactory.CreateMinimalPdf())
            .WithCertificate(_pki.Leaf, [_pki.IntermediateCa])
            .WithSigningPolicy(IofePolicies.Signing with { CheckRevocation = false })
            .SignAsync();

        var validator = new PdfSignatureValidator(
            new ValidationOptions { CheckRevocation = false, TrustSystemRoots = false, Policy = IofePolicies.Validation },
            httpClient: null, logger: null, countryExtensions: [iofe]);
        var result = (await validator.ValidateAsync(new MemoryStream(signed))).ShouldHaveSingleItem();

        result.Indication.ShouldBe(SignatureIndication.Valid);
        result.Constraints.ShouldContain(c => c.Id == "signingCertificate.keyUsage" && c.Status == ConstraintStatus.Passed);
    }

    [Fact]
    public void Policies_Validation_FailsOnKeyUsage() =>
        IofePolicies.Validation.SigningCertificate.KeyUsage.ShouldBe(ConstraintLevel.Fail);

    [Fact]
    public void Policies_Signing_ChecksRevocation() =>
        IofePolicies.Signing.CheckRevocation.ShouldBeTrue();

    public void Dispose()
    {
        _operator.Dispose();
        _operatorKey.Dispose();
        _pki.Dispose();
    }

    private byte[] TrustedListXml()
    {
        string xml = $"""
            <TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#" Id="tsl">
              <SchemeInformation>
                <TSLSequenceNumber>7</TSLSequenceNumber>
                <SchemeTerritory>PE</SchemeTerritory>
                <NextUpdate><dateTime>{DateTimeOffset.UtcNow.AddMonths(6):yyyy-MM-ddTHH:mm:ssZ}</dateTime></NextUpdate>
              </SchemeInformation>
              <TrustServiceProviderList><TrustServiceProvider><TSPServices><TSPService><ServiceInformation>
                <ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/QC</ServiceTypeIdentifier>
                <ServiceDigitalIdentity><DigitalId><X509Certificate>{Convert.ToBase64String(_pki.RootCa.RawData)}</X509Certificate></DigitalId></ServiceDigitalIdentity>
                <ServiceStatus>http://uri.etsi.org/TrstSvc/eSigDir-1999-93-EC-TrustedList/Svcstatus/undersupervision</ServiceStatus>
              </ServiceInformation></TSPService></TSPServices></TrustServiceProvider></TrustServiceProviderList>
            </TrustServiceStatusList>
            """;
        var doc = new XmlDocument { PreserveWhitespace = true };
        doc.LoadXml(xml);
        var signedXml = new SignedXml(doc) { SigningKey = _operatorKey };
        var reference = new Reference("#tsl") { DigestMethod = SignedXml.XmlDsigSHA256Url };
        reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
        signedXml.SignedInfo!.SignatureMethod = SignedXml.XmlDsigRSASHA256Url;
        signedXml.AddReference(reference);
        signedXml.ComputeSignature();
        doc.DocumentElement!.AppendChild(doc.ImportNode(signedXml.GetXml(), true));
        return System.Text.Encoding.UTF8.GetBytes(doc.OuterXml);
    }
}

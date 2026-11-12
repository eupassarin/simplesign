using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;
using Shouldly;
using SimpleSign.Core.Http;
using SimpleSign.Core.Policies;
using SimpleSign.Core.Signing;
using SimpleSign.Core.Validation;
using SimpleSign.PAdES;
using SimpleSign.PAdES.Validation;
using SimpleSign.TestHelpers;
using SimpleSign.XAdES.TrustedLists;

namespace SimpleSign.Peru.Iofe.Tests;

[Trait("Category", "Unit")]
public sealed class IofeExtensionTests : IDisposable
{
    private const string CaQc = "http://uri.etsi.org/TrstSvc/Svctype/CA/QC";
    private const string Unspecified = "http://uri.etsi.org/TrstSvc/Svctype/unspecified";
    private const string TsaUrl = "http://tsa.example.pe/tsr";
    private readonly RSA _operatorKey = RSA.Create(2048);
    private readonly X509Certificate2 _operator;
    private readonly SyntheticPki _pki = new();

    // A TSA provider laid out as Llama.pe is in INDECOPI's list: its root as CA/QC, the CA that issues its TSUs
    // (not self-signed) as Svctype/unspecified.
    private readonly SyntheticPki _tsaPki = new();
    private readonly X509Certificate2 _tsu;
    private readonly RSA _codeSigningKey = RSA.Create(2048);
    private readonly X509Certificate2 _codeSigning;

    public IofeExtensionTests()
    {
        _operator = new CertificateRequest("CN=INDECOPI TSL, C=PE", _operatorKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            .CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(2));
        _tsu = _tsaPki.IssueTimestampingCertificate("CN=Peruvian TSU, O=Synthetic TSA, C=PE");

        // The list also publishes signature software as Svctype/unspecified, identified by a code-signing certificate.
        var request = new CertificateRequest("CN=Signature Software, C=PE", _codeSigningKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.5.5.7.3.3") }, critical: false));
        _codeSigning = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
    }

    [Fact]
    public void Load_SignedList_AnchorsAreTheActiveCas()
    {
        var iofe = IofeExtension.Load(TrustedListXml((CaQc, _pki.RootCa)), [_operator]);

        iofe.RegionCode.ShouldBe("PE");
        iofe.TrustAnchorProviders.ShouldHaveSingleItem().GetTrustAnchors().ShouldHaveSingleItem().Thumbprint.ShouldBe(_pki.RootCa.Thumbprint);
    }

    [Fact]
    public void Load_UnspecifiedServices_TsasAreAnchorsAndSignatureSoftwareIsNot()
    {
        var iofe = IofeExtension.Load(
            TrustedListXml(
                (CaQc, _pki.RootCa), (CaQc, _tsaPki.RootCa), (Unspecified, _tsaPki.IntermediateCa), (Unspecified, _tsu), (Unspecified, _codeSigning)),
            [_operator]);

        var provider = iofe.TrustAnchorProviders.ShouldHaveSingleItem();
        provider.GetTrustAnchors().Select(a => a.Thumbprint).ShouldBe(
            [_pki.RootCa.Thumbprint, _tsaPki.RootCa.Thumbprint, _tsaPki.IntermediateCa.Thumbprint, _tsu.Thumbprint], ignoreOrder: true);
        provider.GetIntermediateCertificates().ShouldContain(c => c.Thumbprint == _tsaPki.IntermediateCa.Thumbprint);
    }

    [Fact]
    public void DefaultListOptions_KeepUnspecifiedServicesWithoutCodeSigning()
    {
        IofeExtension.DefaultListOptions.ServiceTypes.ShouldContain("/unspecified");
        IofeExtension.DefaultListOptions.ServiceTypes.ShouldContain("/CA/QC");
        IofeExtension.DefaultListOptions.ExcludedExtendedKeyUsages.ShouldBe(["1.3.6.1.5.5.7.3.3"]);
    }

    [Fact]
    public async Task Sign_TimestampFromTsaListedAsUnspecified_IsAccepted()
    {
        var iofe = IofeExtension.Load(TrustedListXml((CaQc, _pki.RootCa), (CaQc, _tsaPki.RootCa), (Unspecified, _tsaPki.IntermediateCa)), [_operator]);

        byte[] signed = await SignTimestamped(iofe);

        signed.Length.ShouldBeGreaterThan(0);
    }

    [Fact]
    public async Task Sign_TimestampFromUnspecifiedTsaWithGenericListOptions_IsRefused()
    {
        byte[] xml = TrustedListXml((CaQc, _pki.RootCa), (CaQc, _tsaPki.RootCa), (Unspecified, _tsaPki.IntermediateCa));
        var iofe = new IofeExtension(TrustedList.Load(xml, new TrustedListOptions { SignerCertificates = [_operator] }));

        var ex = await Should.ThrowAsync<SigningException>(() => SignTimestamped(iofe));

        ex.Reason.ShouldBe(SigningErrorReason.TimestampUntrusted);
    }

    [Fact]
    public async Task LoadAsync_WithoutSigner_Throws() =>
        await Should.ThrowAsync<ArgumentException>(() => IofeExtension.LoadAsync(new IofeExtensionOptions()));

    [Fact]
    public async Task Validator_WithIofe_TrustsAChainOfTheList()
    {
        var iofe = IofeExtension.Load(TrustedListXml((CaQc, _pki.RootCa)), [_operator]);
        byte[] signed = await PadesSigner.Document(TestPdfFactory.CreateMinimalPdf())
            .WithCertificate(_pki.Leaf, [_pki.IntermediateCa])
            .WithCountryExtension(iofe)
            .WithSigningPolicy(SigningWithoutRevocation())
            .SignAsync();

        var validator = new PdfSignatureValidator(
            new ValidationOptions { CheckRevocation = false, TrustSystemRoots = false, Policy = IofePolicies.Validation },
            httpClient: null, logger: null, countryExtensions: [iofe]);
        var result = (await validator.ValidateAsync(new MemoryStream(signed))).ShouldHaveSingleItem();

        result.Indication.ShouldBe(SignatureIndication.Valid);
        result.Constraints.ShouldContain(c => c.Id == TestPolicies.SigningCertificate("KeyUsage") && c.Status == ConstraintStatus.Passed);
    }

    [Fact]
    public void Policies_Validation_FailsOnKeyUsage() =>
        IofePolicies.Validation.Find(TestPolicies.SigningCertificate("KeyUsage"))!.Level.ShouldBe(ConstraintLevel.Fail);

    [Fact]
    public void Policies_Signing_ChecksRevocation() =>
        IofePolicies.Signing.Find("SigningCertificate/NotRevoked")!.Level.ShouldBe(ConstraintLevel.Fail);

    public void Dispose()
    {
        _operator.Dispose();
        _operatorKey.Dispose();
        _tsu.Dispose();
        _codeSigning.Dispose();
        _codeSigningKey.Dispose();
        _pki.Dispose();
        _tsaPki.Dispose();
    }

    // The INDECOPI policy without the revocation checks, which need CRL servers; the TSA must still chain to an anchor.
    private static SigningPolicy SigningWithoutRevocation() => IofePolicies.Signing
        .With("SigningCertificate/NotRevoked", null).With("SigningCertificate/RevocationDataAvailable", null)
        .With("CACertificate/NotRevoked", null).With("CACertificate/RevocationDataAvailable", null)
        .With("Timestamp/NotRevoked", null).With("Timestamp/RevocationDataAvailable", null);

    // The token carries the TSU certificate only: the CA that issued it has to come from the list.
    private Task<byte[]> SignTimestamped(IofeExtension iofe)
    {
        var tsa = TsaClient(new TimestampTokenOptions { TsaCertificate = _tsu, GenTime = DateTimeOffset.UtcNow });
        return PadesSigner.Document(TestPdfFactory.CreateMinimalPdf())
            .WithCertificate(_pki.Leaf, [_pki.IntermediateCa])
            .WithCountryExtension(iofe)
            .WithSigningPolicy(SigningWithoutRevocation())
            .WithLevel(AdesBaselineProfile.Timestamped(new TimestampOptions(new Uri(TsaUrl), new SingleClientProvider(tsa))))
            .SignAsync();
    }

    private static HttpClient TsaClient(TimestampTokenOptions options) =>
        new(new MockHttpHandler(async request =>
        {
            byte[] requestBytes = await request.Content!.ReadAsByteArrayAsync();
            var response = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new ByteArrayContent(TimestampTestResponseBuilder.CreateForRequest(requestBytes, options)),
            };
            response.Content.Headers.ContentType = new MediaTypeHeaderValue("application/timestamp-reply");
            return response;
        }));

    private byte[] TrustedListXml(params (string Type, X509Certificate2 Certificate)[] services)
    {
        string serviceXml = string.Concat(services.Select(s => $"""
            <TSPService><ServiceInformation>
              <ServiceTypeIdentifier>{s.Type}</ServiceTypeIdentifier>
              <ServiceDigitalIdentity><DigitalId><X509Certificate>{Convert.ToBase64String(s.Certificate.RawData)}</X509Certificate></DigitalId></ServiceDigitalIdentity>
              <ServiceStatus>http://uri.etsi.org/TrstSvc/eSigDir-1999-93-EC-TrustedList/Svcstatus/undersupervision</ServiceStatus>
            </ServiceInformation></TSPService>
            """));
        string xml = $"""
            <TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#" Id="tsl">
              <SchemeInformation>
                <TSLSequenceNumber>7</TSLSequenceNumber>
                <SchemeTerritory>PE</SchemeTerritory>
                <NextUpdate><dateTime>{DateTimeOffset.UtcNow.AddMonths(6):yyyy-MM-ddTHH:mm:ssZ}</dateTime></NextUpdate>
              </SchemeInformation>
              <TrustServiceProviderList><TrustServiceProvider><TSPServices>{serviceXml}</TSPServices></TrustServiceProvider></TrustServiceProviderList>
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

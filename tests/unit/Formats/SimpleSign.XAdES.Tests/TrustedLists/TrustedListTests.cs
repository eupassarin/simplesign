using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;
using Shouldly;
using SimpleSign.TestHelpers;
using SimpleSign.XAdES.TrustedLists;
using Xunit;

namespace SimpleSign.XAdES.Tests.TrustedLists;

[Trait("Category", "Unit")]
public sealed class TrustedListTests : IDisposable
{
    private const string Granted = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted";
    private const string Withdrawn = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn";
    private const string UnderSupervision = "http://uri.etsi.org/TrstSvc/eSigDir-1999-93-EC-TrustedList/Svcstatus/undersupervision";
    private const string CaQc = "http://uri.etsi.org/TrstSvc/Svctype/CA/QC";
    private readonly RSA _operatorKey = RSA.Create(2048);
    private readonly X509Certificate2 _operator;
    private readonly SyntheticPki _pki = new();
    private readonly SyntheticPki _other = new();

    public TrustedListTests()
    {
        var request = new CertificateRequest("CN=Scheme Operator, C=PE", _operatorKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        _operator = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(2));
    }

    [Fact]
    public void Load_SignedList_KeepsActiveCaServicesOnly()
    {
        byte[] xml = Build([(CaQc, Granted, _pki.RootCa), (CaQc, Withdrawn, _other.RootCa)]);

        var list = TrustedList.Load(xml, Options());

        list.Territory.ShouldBe("PE");
        list.SequenceNumber.ShouldBe("42");
        list.Services.Count.ShouldBe(2);
        list.GetTrustAnchors().ShouldHaveSingleItem().Thumbprint.ShouldBe(_pki.RootCa.Thumbprint);
    }

    [Fact]
    public void Load_SignedList_ReportsItsStructureToThePolicy()
    {
        var list = TrustedList.Load(Build([(CaQc, Granted, _pki.RootCa)]), Options());

        list.TrustedLists.ShouldHaveSingleItem().IsStructureValid.ShouldBe(list.StructureErrors.Count == 0);
    }

    [Fact]
    public void Load_Version3UnderSupervision_IsActive()
    {
        byte[] xml = Build([(CaQc, UnderSupervision, _pki.RootCa)]);

        TrustedList.Load(xml, Options()).GetTrustAnchors().ShouldHaveSingleItem();
    }

    [Fact]
    public void Load_ExcludedExtendedKeyUsage_CertificateIsNotAnAnchor()
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=Signature Software", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.5.5.7.3.3") }, critical: false));
        using var codeSigning = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        byte[] xml = Build([(CaQc, Granted, _pki.RootCa), (CaQc, Granted, codeSigning)]);

        var list = TrustedList.Load(xml, Options() with { ExcludedExtendedKeyUsages = ["1.3.6.1.5.5.7.3.3"] });

        list.GetTrustAnchors().ShouldHaveSingleItem().Thumbprint.ShouldBe(_pki.RootCa.Thumbprint);
        list.Services.Count.ShouldBe(2);
    }

    [Fact]
    public void Load_ChangedAfterSigning_ThrowsCryptographicException()
    {
        string text = System.Text.Encoding.UTF8.GetString(Build([(CaQc, Withdrawn, _pki.RootCa)]));
        byte[] tampered = System.Text.Encoding.UTF8.GetBytes(text.Replace(Withdrawn, Granted, StringComparison.Ordinal));

        Should.Throw<CryptographicException>(() => TrustedList.Load(tampered, Options()));
    }

    [Fact]
    public void Load_OtherSigner_ThrowsCryptographicException()
    {
        byte[] xml = Build([(CaQc, Granted, _pki.RootCa)]);
        using var key = RSA.Create(2048);
        using var stranger = new CertificateRequest("CN=Stranger", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            .CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

        Should.Throw<CryptographicException>(() => TrustedList.Load(xml, new TrustedListOptions { SignerCertificates = [stranger] }));
    }

    [Fact]
    public void Load_NextUpdatePassed_ThrowsInvalidDataException()
    {
        byte[] xml = Build([(CaQc, Granted, _pki.RootCa)], nextUpdate: DateTimeOffset.UtcNow.AddDays(-1));

        Should.Throw<InvalidDataException>(() => TrustedList.Load(xml, Options()));
        TrustedList.Load(xml, Options() with { RejectExpired = false }).GetTrustAnchors().ShouldHaveSingleItem();
    }

    [Fact]
    public void Load_Unsigned_ThrowsCryptographicException()
    {
        byte[] xml = Build([(CaQc, Granted, _pki.RootCa)], sign: false);

        Should.Throw<CryptographicException>(() => TrustedList.Load(xml, Options()));
    }

    public void Dispose()
    {
        _operator.Dispose();
        _operatorKey.Dispose();
        _pki.Dispose();
        _other.Dispose();
    }

    private TrustedListOptions Options() => new() { SignerCertificates = [_operator] };

    private byte[] Build((string Type, string Status, X509Certificate2 Cert)[] services, DateTimeOffset? nextUpdate = null, bool sign = true)
    {
        string serviceXml = string.Concat(services.Select(s => $"""
            <TSPService><ServiceInformation>
              <ServiceTypeIdentifier>{s.Type}</ServiceTypeIdentifier>
              <ServiceName><Name xml:lang="es">Servicio</Name></ServiceName>
              <ServiceDigitalIdentity><DigitalId><X509Certificate>{Convert.ToBase64String(s.Cert.RawData)}</X509Certificate></DigitalId></ServiceDigitalIdentity>
              <ServiceStatus>{s.Status}</ServiceStatus>
            </ServiceInformation></TSPService>
            """));
        string xml = $"""
            <TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#" Id="tsl" TSLTag="http://uri.etsi.org/02231/TSLTag">
              <SchemeInformation>
                <TSLVersionIdentifier>5</TSLVersionIdentifier>
                <TSLSequenceNumber>42</TSLSequenceNumber>
                <SchemeOperatorName><Name xml:lang="es">INDECOPI</Name></SchemeOperatorName>
                <SchemeTerritory>PE</SchemeTerritory>
                <ListIssueDateTime>{DateTimeOffset.UtcNow.AddDays(-2):yyyy-MM-ddTHH:mm:ssZ}</ListIssueDateTime>
                <NextUpdate><dateTime>{(nextUpdate ?? DateTimeOffset.UtcNow.AddMonths(6)):yyyy-MM-ddTHH:mm:ssZ}</dateTime></NextUpdate>
              </SchemeInformation>
              <TrustServiceProviderList><TrustServiceProvider>
                <TSPInformation><TSPName><Name xml:lang="es">Proveedor</Name></TSPName></TSPInformation>
                <TSPServices>{serviceXml}</TSPServices>
              </TrustServiceProvider></TrustServiceProviderList>
            </TrustServiceStatusList>
            """;
        var doc = new XmlDocument { PreserveWhitespace = true };
        doc.LoadXml(xml);
        if (sign)
        {
            var signedXml = new SignedXml(doc) { SigningKey = _operatorKey };
            var reference = new Reference("#tsl");
            reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
            reference.AddTransform(new XmlDsigExcC14NTransform());
            reference.DigestMethod = SignedXml.XmlDsigSHA256Url;
            signedXml.SignedInfo!.SignatureMethod = SignedXml.XmlDsigRSASHA256Url;
            signedXml.AddReference(reference);
            var keyInfo = new KeyInfo();
            keyInfo.AddClause(new KeyInfoX509Data(_operator));
            signedXml.KeyInfo = keyInfo;
            signedXml.ComputeSignature();
            doc.DocumentElement!.AppendChild(doc.ImportNode(signedXml.GetXml(), true));
        }

        return System.Text.Encoding.UTF8.GetBytes(doc.OuterXml);
    }
}

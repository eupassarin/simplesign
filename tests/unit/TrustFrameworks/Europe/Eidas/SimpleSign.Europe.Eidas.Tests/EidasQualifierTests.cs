using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;
using Shouldly;
using SimpleSign.Core.Extensions;
using SimpleSign.Core.Validation;
using SimpleSign.XAdES.TrustedLists;

namespace SimpleSign.Europe.Eidas.Tests;

[Trait("Category", "Unit")]
public sealed class EidasQualifierTests : IDisposable
{
    private const string Granted = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted";
    private const string Withdrawn = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn";
    private const string CaQc = "http://uri.etsi.org/TrstSvc/Svctype/CA/QC";
    private const string CaPkc = "http://uri.etsi.org/TrstSvc/Svctype/CA/PKC";
    private const string Ext = "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/";

    private readonly RSA _operatorKey = RSA.Create(2048);
    private readonly RSA _rootKey = RSA.Create(2048);
    private readonly RSA _caKey = RSA.Create(2048);
    private readonly RSA _leafKey = RSA.Create(2048);
    private readonly X509Certificate2 _operator;
    private readonly X509Certificate2 _root;
    private readonly X509Certificate2 _ca;

    public EidasQualifierTests()
    {
        _operator = new CertificateRequest("CN=Operator", _operatorKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            .CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(2));
        var rootRequest = new CertificateRequest("CN=Root CA, C=ZZ", _rootKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        rootRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        rootRequest.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(rootRequest.PublicKey, false));
        _root = rootRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddYears(-3), DateTimeOffset.UtcNow.AddYears(10));
        var caRequest = new CertificateRequest("CN=Issuing CA, C=ZZ", _caKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        caRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        caRequest.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(caRequest.PublicKey, false));
        caRequest.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(_root, true, false));
        using var ca = caRequest.Create(_root, DateTimeOffset.UtcNow.AddYears(-2), DateTimeOffset.UtcNow.AddYears(5), [9, 9]);
        _ca = ca.CopyWithPrivateKey(_caKey);
    }

    [Theory]
    [InlineData(true, true, QcStatements.ESignOid, "QESig")]
    [InlineData(true, false, QcStatements.ESignOid, "AdESig-QC")]
    [InlineData(true, true, QcStatements.ESealOid, "QESeal")]
    [InlineData(true, false, QcStatements.ESealOid, "AdESeal-QC")]
    [InlineData(false, false, QcStatements.ESignOid, "AdESig")]
    public void Qualify_GrantedCaQc_TheLevelFollowsTheQcStatements(bool compliance, bool sscd, string type, string expected)
    {
        using var leaf = Leaf(QcStatements.Encode(compliance, sscd, type));

        Qualify(leaf, Service(CaQc, Granted)).Level.ShouldBe(expected);
    }

    [Fact]
    public void Qualify_UnderCaPkc_IsAdESigWhateverTheStatements()
    {
        using var leaf = Leaf(QcStatements.Encode(true, true, QcStatements.ESignOid));

        Qualify(leaf, Service(CaPkc, Granted)).Level.ShouldBe("AdESig");
    }

    [Fact]
    public void Qualify_QualifierQcWithQscd_GivesTheQscdTheCertificateDoesNotDeclare()
    {
        using var leaf = Leaf(QcStatements.Encode(true, false, QcStatements.ESignOid));

        Qualify(leaf, Service(CaQc, Granted, Qualification("QCWithQSCD"))).Level.ShouldBe("QESig");
    }

    [Fact]
    public void Qualify_QualifierNotQualified_TakesTheQualificationAway()
    {
        using var leaf = Leaf(QcStatements.Encode(true, true, QcStatements.ESignOid));

        Qualify(leaf, Service(CaQc, Granted, Qualification("NotQualified"))).Level.ShouldBe("AdESig");
    }

    [Fact]
    public void Qualify_WithdrawnAfterTheSignature_StaysQualifiedByTheHistory()
    {
        using var leaf = Leaf(QcStatements.Encode(true, true, QcStatements.ESignOid));
        var withdrawn = DateTimeOffset.UtcNow.AddHours(-1);
        var service = Service(CaQc, Withdrawn, since: withdrawn, history: (Granted, withdrawn.AddYears(-3)));

        Qualify(leaf, service, signedAt: withdrawn.AddHours(-2)).Level.ShouldBe("QESig");
        Qualify(leaf, service, signedAt: DateTimeOffset.UtcNow).Level.ShouldBe("AdESig");
    }

    [Theory]
    [InlineData(SignatureIndication.Indeterminate, "Indeterminate QESig")]
    [InlineData(SignatureIndication.Invalid, "Not AdES")]
    public void Qualify_NotValid_FollowsTs119172_4(SignatureIndication indication, string expected)
    {
        using var leaf = Leaf(QcStatements.Encode(true, true, QcStatements.ESignOid));

        Qualify(leaf, Service(CaQc, Granted), indication: indication).Level.ShouldBe(expected);
    }

    [Fact]
    public void Qualify_CaNotInTheLists_IsNotApplicable()
    {
        using var otherKey = RSA.Create(2048);
        using var other = new CertificateRequest("CN=Other", otherKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            .CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

        var qualification = new EidasQualifier(() => [List(Service(CaQc, Granted))])
            .Qualify(new SignatureQualificationContext(other, SignatureIndication.Valid)).ShouldNotBeNull();

        qualification.Level.ShouldBe("N/A");
        qualification.EtsiUri.ShouldBe("urn:cef:dss:signatureQualification:N/A");
    }

    public void Dispose()
    {
        _operator.Dispose();
        _root.Dispose();
        _ca.Dispose();
        _operatorKey.Dispose();
        _rootKey.Dispose();
        _caKey.Dispose();
        _leafKey.Dispose();
    }

    private SignatureQualification Qualify(X509Certificate2 leaf, string service, DateTimeOffset? signedAt = null,
        SignatureIndication indication = SignatureIndication.Valid) =>
        new EidasQualifier(() => [List(service)]).Qualify(new SignatureQualificationContext(leaf, indication)
        {
            Certificates = [leaf, _ca, _root],
            BestSignatureTime = signedAt ?? DateTimeOffset.UtcNow,
            Format = "PAdES",
        }).ShouldNotBeNull();

    private X509Certificate2 Leaf(byte[] qcStatements)
    {
        var request = new CertificateRequest("CN=Holder, C=ZZ", _leafKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.NonRepudiation, true));
        request.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(_ca, true, false));
        request.CertificateExtensions.Add(new X509Extension(QcStatements.ExtensionOid, qcStatements, false));
        return request.Create(_ca, DateTimeOffset.UtcNow.AddDays(-30), DateTimeOffset.UtcNow.AddYears(1), [1, 2, 3]);
    }

    private static string Qualification(string qualifier) => $"""
        <ServiceInformationExtensions><Extension Critical="true">
          <ecc:Qualifications xmlns:ecc="http://uri.etsi.org/TrstSvc/SvcInfoExt/eSigDir-1999-93-EC-TrustedList/#">
            <ecc:QualificationElement>
              <ecc:Qualifiers><ecc:Qualifier uri="{Ext}{qualifier}"/></ecc:Qualifiers>
              <ecc:CriteriaList assert="all"><ecc:KeyUsage><ecc:KeyUsageBit name="nonRepudiation">true</ecc:KeyUsageBit></ecc:KeyUsage></ecc:CriteriaList>
            </ecc:QualificationElement>
          </ecc:Qualifications>
        </Extension></ServiceInformationExtensions>
        """;

    private string Service(string type, string status, string extensions = "", DateTimeOffset? since = null, (string Status, DateTimeOffset Since)? history = null) => $"""
        <TSPService><ServiceInformation>
          <ServiceTypeIdentifier>{type}</ServiceTypeIdentifier>
          <ServiceName><Name xml:lang="en">Root CA</Name></ServiceName>
          <ServiceDigitalIdentity><DigitalId><X509Certificate>{Convert.ToBase64String(_root.RawData)}</X509Certificate></DigitalId></ServiceDigitalIdentity>
          <ServiceStatus>{status}</ServiceStatus>
          <StatusStartingTime>{since ?? DateTimeOffset.UtcNow.AddYears(-3):yyyy-MM-ddTHH:mm:ssZ}</StatusStartingTime>
          {extensions}
        </ServiceInformation>
        {(history is { } h ? $"""
          <ServiceHistory><ServiceHistoryInstance>
            <ServiceTypeIdentifier>{type}</ServiceTypeIdentifier>
            <ServiceName><Name xml:lang="en">Root CA</Name></ServiceName>
            <ServiceDigitalIdentity><DigitalId><X509Certificate>{Convert.ToBase64String(_root.RawData)}</X509Certificate></DigitalId></ServiceDigitalIdentity>
            <ServiceStatus>{h.Status}</ServiceStatus>
            <StatusStartingTime>{h.Since:yyyy-MM-ddTHH:mm:ssZ}</StatusStartingTime>
          </ServiceHistoryInstance></ServiceHistory>
          """ : "")}
        </TSPService>
        """;

    private TrustedList List(string services)
    {
        string xml = $"""
            <TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#" Id="tsl" TSLTag="http://uri.etsi.org/02231/TSLTag">
              <SchemeInformation>
                <TSLVersionIdentifier>5</TSLVersionIdentifier>
                <TSLSequenceNumber>1</TSLSequenceNumber>
                <SchemeOperatorName><Name xml:lang="en">Operator</Name></SchemeOperatorName>
                <SchemeTerritory>ZZ</SchemeTerritory>
                <ListIssueDateTime>{DateTimeOffset.UtcNow.AddDays(-1):yyyy-MM-ddTHH:mm:ssZ}</ListIssueDateTime>
                <NextUpdate><dateTime>{DateTimeOffset.UtcNow.AddMonths(3):yyyy-MM-ddTHH:mm:ssZ}</dateTime></NextUpdate>
              </SchemeInformation>
              <TrustServiceProviderList><TrustServiceProvider>
                <TSPInformation><TSPName><Name xml:lang="en">Provider</Name></TSPName></TSPInformation>
                <TSPServices>{services}</TSPServices>
              </TrustServiceProvider></TrustServiceProviderList>
            </TrustServiceStatusList>
            """;
        var doc = new XmlDocument { PreserveWhitespace = true };
        doc.LoadXml(xml);
        var signedXml = new SignedXml(doc) { SigningKey = _operatorKey };
        var reference = new Reference("#tsl");
        reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
        reference.AddTransform(new XmlDsigExcC14NTransform());
        reference.DigestMethod = SignedXml.XmlDsigSHA256Url;
        signedXml.SignedInfo!.SignatureMethod = SignedXml.XmlDsigRSASHA256Url;
        signedXml.AddReference(reference);
        signedXml.ComputeSignature();
        doc.DocumentElement!.AppendChild(doc.ImportNode(signedXml.GetXml(), true));
        return TrustedList.Load(System.Text.Encoding.UTF8.GetBytes(doc.OuterXml), new TrustedListOptions { SignerCertificates = [_operator] });
    }
}

using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;
using Shouldly;
using SimpleSign.XAdES.TrustedLists;
using Xunit;

namespace SimpleSign.XAdES.Tests.TrustedLists;

[Trait("Category", "Unit")]
public sealed class TrustedListQualificationsTests : IDisposable
{
    private const string Granted = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted";
    private const string Withdrawn = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn";
    private const string CaQc = "http://uri.etsi.org/TrstSvc/Svctype/CA/QC";
    private const string Ext = "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/";
    private const string QscdPolicy = "0.4.0.194112.1.2";

    private readonly RSA _operatorKey = RSA.Create(2048);
    private readonly RSA _caKey = RSA.Create(2048);
    private readonly X509Certificate2 _operator;
    private readonly X509Certificate2 _ca;

    public TrustedListQualificationsTests()
    {
        _operator = new CertificateRequest("CN=Operator", _operatorKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            .CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(2));
        var request = new CertificateRequest("CN=Qualified CA", _caKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        _ca = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddYears(-2), DateTimeOffset.UtcNow.AddYears(5));
    }

    [Fact]
    public void Load_ServiceExtensions_ReadsAdditionalInformationQualificationsAndExpiredCertsRevocationInfo()
    {
        var service = Load(Extensions).Services.Single();

        service.Extensions.HasAdditionalInformation("/ForeSignatures").ShouldBeTrue();
        service.Extensions.Qualifications.ShouldHaveSingleItem().Qualifiers.ShouldBe([Ext + "QCWithQSCD"]);
        service.Extensions.ExpiredCertsRevocationInfo.ShouldBe(new DateTimeOffset(2016, 6, 30, 22, 0, 0, TimeSpan.Zero));
    }

    [Fact]
    public void QualifiersFor_CertificateWithThePolicySet_GetsTheQualifier()
    {
        var service = Load(Extensions).Services.Single();
        using var key = RSA.Create(2048);

        using var qscd = Leaf(key, QscdPolicy);
        using var other = Leaf(key, "1.2.3.4");

        service.Extensions.QualifiersFor(qscd).ShouldBe([Ext + "QCWithQSCD"]);
        service.Extensions.QualifiersFor(other).ShouldBeEmpty();
    }

    [Theory]
    [InlineData("all", true, false)]
    [InlineData("atLeastOne", true, true)]
    [InlineData("none", false, false)]
    public void Matches_Assert_CombinesTheCriteria(string assert, bool both, bool policyOnly)
    {
        var criteria = new TrustedListCriteria
        {
            Assert = assert,
            KeyUsages = [new Dictionary<string, bool> { ["nonRepudiation"] = true }],
            PolicySets = [[QscdPolicy]],
        };
        using var key = RSA.Create(2048);
        using var withBoth = Leaf(key, QscdPolicy, X509KeyUsageFlags.NonRepudiation);
        using var withPolicy = Leaf(key, QscdPolicy, X509KeyUsageFlags.DigitalSignature);

        criteria.Matches(withBoth).ShouldBe(both);
        criteria.Matches(withPolicy).ShouldBe(policyOnly);
    }

    [Fact]
    public void InformationAt_BeforeTheCurrentStatus_GivesTheHistoryEntryAndItsExtensions()
    {
        var withdrawnAt = DateTimeOffset.UtcNow.AddDays(-10);
        var service = Load($"""
            <ServiceStatus>{Withdrawn}</ServiceStatus>
            <StatusStartingTime>{withdrawnAt:yyyy-MM-ddTHH:mm:ssZ}</StatusStartingTime>
            </ServiceInformation>
            <ServiceHistory><ServiceHistoryInstance>
              <ServiceTypeIdentifier>{CaQc}</ServiceTypeIdentifier>
              <ServiceName><Name xml:lang="en">CA</Name></ServiceName>
              <ServiceDigitalIdentity><DigitalId><X509Certificate>{Convert.ToBase64String(_ca.RawData)}</X509Certificate></DigitalId></ServiceDigitalIdentity>
              <ServiceStatus>{Granted}</ServiceStatus>
              <StatusStartingTime>{withdrawnAt.AddYears(-1):yyyy-MM-ddTHH:mm:ssZ}</StatusStartingTime>
              <ServiceInformationExtensions><Extension Critical="true"><AdditionalServiceInformation>
                <URI xml:lang="en">{Ext}ForeSignatures</URI>
              </AdditionalServiceInformation></Extension></ServiceInformationExtensions>
            </ServiceHistoryInstance></ServiceHistory>
            <ServiceInformation>
            """, closeServiceInformation: false).Services.Single();

        var before = service.InformationAt(withdrawnAt.AddDays(-1)).ShouldNotBeNull();
        before.Status.ShouldBe(Granted);
        before.ServiceType.ShouldBe(CaQc);
        before.Extensions.HasAdditionalInformation("/ForeSignatures").ShouldBeTrue();
        service.InformationAt(DateTimeOffset.UtcNow).ShouldNotBeNull().Status.ShouldBe(Withdrawn);
    }

    public void Dispose()
    {
        _operator.Dispose();
        _operatorKey.Dispose();
        _ca.Dispose();
        _caKey.Dispose();
    }

    private static string Extensions => $"""
        <ServiceStatus>{Granted}</ServiceStatus>
        <ServiceInformationExtensions>
          <Extension Critical="true"><AdditionalServiceInformation><URI xml:lang="en">{Ext}ForeSignatures</URI></AdditionalServiceInformation></Extension>
          <Extension Critical="true">
            <ecc:Qualifications xmlns:ecc="http://uri.etsi.org/TrstSvc/SvcInfoExt/eSigDir-1999-93-EC-TrustedList/#" xmlns:xades="http://uri.etsi.org/01903/v1.3.2#">
              <ecc:QualificationElement>
                <ecc:Qualifiers><ecc:Qualifier uri="{Ext}QCWithQSCD"/></ecc:Qualifiers>
                <ecc:CriteriaList assert="atLeastOne">
                  <ecc:PolicySet><ecc:PolicyIdentifier><xades:Identifier>{QscdPolicy}</xades:Identifier></ecc:PolicyIdentifier></ecc:PolicySet>
                </ecc:CriteriaList>
              </ecc:QualificationElement>
            </ecc:Qualifications>
          </Extension>
          <Extension Critical="false"><ExpiredCertsRevocationInfo>2016-06-30T22:00:00Z</ExpiredCertsRevocationInfo></Extension>
        </ServiceInformationExtensions>
        """;

    private X509Certificate2 Leaf(RSA key, string policy, X509KeyUsageFlags usage = X509KeyUsageFlags.NonRepudiation)
    {
        var request = new CertificateRequest("CN=Holder", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509KeyUsageExtension(usage, true));
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            using (writer.PushSequence())
            {
                writer.WriteObjectIdentifier(policy);
            }
        }

        request.CertificateExtensions.Add(new X509Extension("2.5.29.32", writer.Encode(), false));
        return request.Create(_ca, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1), [1, 2, 3, 4]);
    }

    private TrustedList Load(string statusAndExtensions, bool closeServiceInformation = true)
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
                <TSPServices><TSPService><ServiceInformation>
                  <ServiceTypeIdentifier>{CaQc}</ServiceTypeIdentifier>
                  <ServiceName><Name xml:lang="en">CA</Name></ServiceName>
                  <ServiceDigitalIdentity><DigitalId><X509Certificate>{Convert.ToBase64String(_ca.RawData)}</X509Certificate></DigitalId></ServiceDigitalIdentity>
                  {statusAndExtensions}
                {(closeServiceInformation ? "</ServiceInformation>" : "")}</TSPService></TSPServices>
              </TrustServiceProvider></TrustServiceProviderList>
            </TrustServiceStatusList>
            """;
        // A history sits after ServiceInformation: the caller closes it and reopens one, dropped here.
        var doc = new XmlDocument { PreserveWhitespace = true };
        doc.LoadXml(System.Text.RegularExpressions.Regex.Replace(xml, @"<ServiceInformation>\s*</TSPService>", "</TSPService>"));
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

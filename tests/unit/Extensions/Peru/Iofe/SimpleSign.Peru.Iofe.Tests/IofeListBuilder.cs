using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace SimpleSign.Peru.Iofe.Tests;

/// <summary>Builds trusted lists laid out as INDECOPI's (TS 102 231 v3, one provider per service), signed by an operator.</summary>
internal sealed class IofeListBuilder : IDisposable
{
    public const string CaQc = "http://uri.etsi.org/TrstSvc/Svctype/CA/QC";
    public const string Unspecified = "http://uri.etsi.org/TrstSvc/Svctype/unspecified";
    public const string UnderSupervision = "http://uri.etsi.org/TrstSvc/eSigDir-1999-93-EC-TrustedList/Svcstatus/undersupervision";
    public const string SupervisionRevoked = "http://uri.etsi.org/TrstSvc/eSigDir-1999-93-EC-TrustedList/Svcstatus/supervisionrevoked";

    private readonly RSA _key = RSA.Create(2048);

    public IofeListBuilder(string subject = "CN=TSL Suscriptor, O=INDECOPI, C=PE")
    {
        Operator = new CertificateRequest(subject, _key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            .CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(2));
    }

    /// <summary>The certificate the lists are signed with.</summary>
    public X509Certificate2 Operator { get; }

    /// <summary>A signed list.</summary>
    /// <param name="sequence">TSLSequenceNumber.</param>
    /// <param name="services">Name, type, status and certificate of each service.</param>
    /// <param name="nextUpdate">NextUpdate; six months from now by default.</param>
    public byte[] List(int sequence, IEnumerable<(string Name, string Type, string Status, X509Certificate2 Certificate)> services, DateTimeOffset? nextUpdate = null)
    {
        string providers = string.Concat(services.Select(s => $"""
            <tsl:TrustServiceProvider>
              <tsl:TSPInformation><tsl:TSPName><tsl:Name xml:lang="es">{s.Name}</tsl:Name></tsl:TSPName></tsl:TSPInformation>
              <tsl:TSPServices><tsl:TSPService><tsl:ServiceInformation>
                <tsl:ServiceTypeIdentifier>{s.Type}</tsl:ServiceTypeIdentifier>
                <tsl:ServiceName><tsl:Name xml:lang="es">{s.Name}</tsl:Name></tsl:ServiceName>
                <tsl:ServiceDigitalIdentity><tsl:DigitalId><tsl:X509Certificate>{Convert.ToBase64String(s.Certificate.RawData)}</tsl:X509Certificate></tsl:DigitalId></tsl:ServiceDigitalIdentity>
                <tsl:ServiceStatus>{s.Status}</tsl:ServiceStatus>
                <tsl:StatusStartingTime>{s.Certificate.NotBefore.ToUniversalTime():yyyy-MM-ddTHH:mm:ssZ}</tsl:StatusStartingTime>
              </tsl:ServiceInformation></tsl:TSPService></tsl:TSPServices>
            </tsl:TrustServiceProvider>
            """));
        var now = DateTimeOffset.UtcNow;
        string xml = $"""
            <tsl:TrustServiceStatusList xmlns:tsl="http://uri.etsi.org/02231/v2#" Id="tsl" TSLTag="http://uri.etsi.org/02231/TSLTag">
              <tsl:SchemeInformation>
                <tsl:TSLVersionIdentifier>3</tsl:TSLVersionIdentifier>
                <tsl:TSLSequenceNumber>{sequence}</tsl:TSLSequenceNumber>
                <tsl:TSLType>http://uri.etsi.org/TrstSvc/eSigDir-1999-93-EC-TrustedList/TSLType/generic</tsl:TSLType>
                <tsl:SchemeOperatorName><tsl:Name xml:lang="es">INDECOPI</tsl:Name></tsl:SchemeOperatorName>
                <tsl:SchemeTerritory>PE</tsl:SchemeTerritory>
                <tsl:ListIssueDateTime>{now:yyyy-MM-ddTHH:mm:ssZ}</tsl:ListIssueDateTime>
                <tsl:NextUpdate><tsl:dateTime>{nextUpdate ?? now.AddMonths(6):yyyy-MM-ddTHH:mm:ssZ}</tsl:dateTime></tsl:NextUpdate>
              </tsl:SchemeInformation>
              <tsl:TrustServiceProviderList>{providers}</tsl:TrustServiceProviderList>
            </tsl:TrustServiceStatusList>
            """;
        var doc = new XmlDocument { PreserveWhitespace = true };
        doc.LoadXml(xml);
        var signedXml = new SignedXml(doc) { SigningKey = _key };
        var reference = new Reference("") { DigestMethod = SignedXml.XmlDsigSHA256Url };
        reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
        reference.AddTransform(new XmlDsigExcC14NTransform());
        signedXml.SignedInfo!.SignatureMethod = SignedXml.XmlDsigRSASHA256Url;
        signedXml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;
        signedXml.AddReference(reference);
        signedXml.ComputeSignature();
        doc.DocumentElement!.AppendChild(doc.ImportNode(signedXml.GetXml(), true));
        return System.Text.Encoding.UTF8.GetBytes(doc.OuterXml);
    }

    public void Dispose()
    {
        Operator.Dispose();
        _key.Dispose();
    }
}

/// <summary>A clock the test moves.</summary>
internal sealed class ManualClock(DateTimeOffset now) : TimeProvider
{
    public DateTimeOffset Now { get; set; } = now;

    public override DateTimeOffset GetUtcNow() => Now;
}

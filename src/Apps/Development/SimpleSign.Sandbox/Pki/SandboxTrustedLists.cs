using System.Numerics;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;
using SimpleSign.Sandbox.Services;

namespace SimpleSign.Sandbox.Pki;

/// <summary>
/// The Sandbox as a trust scheme: a trusted list (ETSI TS 119 612 v5) whose services are the root CA and the
/// time-stamping units, and a list of trusted lists (LOTL) that points to it, each signed (XAdES enveloped) by its
/// own scheme operator. A validator given the LOTL and its operator's certificate trusts the Sandbox's chains as a
/// trusted list, with service types and statuses, instead of a bare root. Both are built on each request, so they
/// follow the environment (and the <see cref="TlFault"/> switched on). The signature follows TS 119 612 §5.7.1: an
/// enveloped XAdES baseline B signature whose only transforms are the enveloped one and exclusive canonicalization.
/// </summary>
internal sealed class SandboxTrustedLists(SandboxPki pki)
{
    /// <summary>The media type of an XML trusted list.</summary>
    public const string MediaType = "application/vnd.etsi.tsl+xml";

    /// <summary>The territory of the Sandbox's lists: ZZ, a code ISO 3166 leaves to users.</summary>
    public const string Territory = "ZZ";

    private const string Ns = "http://uri.etsi.org/02231/v2#";
    private const string AdditionalTypes = "http://uri.etsi.org/02231/v2/additionaltypes#";
    private const string TslTypes = "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/";
    private const string ServiceTypes = "http://uri.etsi.org/TrstSvc/Svctype/";
    private const string Statuses = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/";

    /// <summary>The TSLType of the LOTL: what DSS expects of a list of lists (and of its own pointer to itself).</summary>
    public const string LotlType = TslTypes + "EUlistofthelists";

    /// <summary>The TSLType of the trusted list.</summary>
    public const string TlType = TslTypes + "EUgeneric";

    public Uri LotlUrl => new(pki.BaseUrl, "tl/lotl.xml");

    public Uri TlUrl => new(pki.BaseUrl, "tl/tl.xml");

    /// <summary>The signed list of trusted lists: a pointer to itself and one to the trusted list, with each operator's certificate.</summary>
    public Task<byte[]> LotlAsync(CancellationToken cancellationToken)
    {
        var fault = pki.Faults.Lotl;
        var now = DateTimeOffset.UtcNow;
        string pointers =
            Pointer(LotlUrl, pki.LotlSigner, LotlType) +
            Pointer(TlUrl, pki.TlSigner, TlType);
        var nextUpdate = fault == LotlFault.Expired ? now.AddDays(-1) : now.AddMonths(6);
        var issued = fault == LotlFault.Expired ? now.AddMonths(-7) : now;
        string xml = Document(LotlType, "Sandbox list of trusted lists", pointers, services: "", issued, nextUpdate);
        cancellationToken.ThrowIfCancellationRequested();
        byte[] signed = Sign(xml, fault == LotlFault.WrongSigner ? pki.UntrustedSigner : pki.LotlSigner);
        return Task.FromResult(fault == LotlFault.Tampered ? Tamper(signed) : signed);
    }

    /// <summary>
    /// The signed trusted list: the root CA (CA/QC, granted), the TSA (TSA/QTST, granted), the revoked TSA (withdrawn),
    /// and two services typed <c>Svctype/unspecified</c> as INDECOPI's list types them: the self-signed Timestamping CA of
    /// the <c>/tsa/iofe</c> TSA (the CA, not the TSA, as INDECOPI lists the Llama.pe Timestamping CA) and a signature
    /// software listed with its code-signing certificate. A reader with the default options leaves both out; one with
    /// <c>IofeExtension.DefaultListOptions</c> keeps the Timestamping CA, never the code-signing certificate.
    /// </summary>
    public Task<byte[]> TlAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var fault = pki.Faults.TrustedList;
        var now = DateTimeOffset.UtcNow;
        var revokedTsa = pki.Certificates.FirstOrDefault(c => c.Id == "tsa-revoked")?.Certificate;
        var software = pki.Certificates.FirstOrDefault(c => c.Id == "code-signing")?.Certificate;
        var nonQualifiedTsa = pki.Certificates.FirstOrDefault(c => c.Id == "tsa-non-qualified")?.Certificate;
        var pkcCa = pki.AuthorityCertificate(SandboxPki.PkcIntermediateId);
        string services = $"""
            <TrustServiceProviderList><TrustServiceProvider>
              <TSPInformation>
                <TSPName><Name xml:lang="en">SimpleSign Sandbox ({Escape(pki.Name)})</Name></TSPName>
                <TSPAddress>{Address()}</TSPAddress>
                <TSPInformationURI><URI xml:lang="en">{pki.BaseUrl}</URI></TSPInformationURI>
              </TSPInformation>
              <TSPServices>
                {(fault == TlFault.WithdrawnAfterUse
                    ? Service("CA/QC", "Sandbox root CA", pki.Root, "withdrawn", now.AddSeconds(-1), history: "granted", extensions: QualifiedCaExtensions)
                    : Service("CA/QC", "Sandbox root CA", pki.Root, "granted", extensions: QualifiedCaExtensions))}
                {(pkcCa is null ? "" : Service("CA/PKC", "Sandbox non-qualified CA", pkcCa, "granted"))}
                {Service("TSA/QTST", "Sandbox time-stamping unit", pki.Tsa, "granted")}
                {(nonQualifiedTsa is null ? "" : Service("TSA", "Sandbox non-qualified time-stamping unit", nonQualifiedTsa, "granted"))}
                {(revokedTsa is null ? "" : Service("TSA/QTST", "Sandbox revoked time-stamping unit", revokedTsa, "withdrawn"))}
                {Service("unspecified", "Sandbox Timestamping CA", pki.TsaCa, "granted")}
                {(software is null ? "" : Service("unspecified", "Sandbox signature software", software, "granted"))}
              </TSPServices>
            </TrustServiceProvider></TrustServiceProviderList>
            """;
        var nextUpdate = fault == TlFault.Expired ? now.AddDays(-1) : now.AddMonths(6);
        var issued = fault == TlFault.Expired ? now.AddMonths(-7) : now;
        string xml = Document(TlType, "Sandbox trusted list", pointers: "", services, issued, nextUpdate);
        byte[] signed = Sign(xml, fault == TlFault.WrongSigner ? pki.UntrustedSigner : pki.TlSigner);
        return Task.FromResult(fault == TlFault.Tampered ? Tamper(signed) : signed);
    }

    /// <summary>
    /// A service of the trusted list, for one certificate: its status since <paramref name="since"/> (the certificate's
    /// NotBefore by default), and, with <paramref name="history"/>, the earlier status from NotBefore until then.
    /// </summary>
    private static string Service(string type, string name, X509Certificate2 certificate, string status, DateTimeOffset? since = null, string? history = null,
        string extensions = "") => $"""
        <TSPService><ServiceInformation>
          <ServiceTypeIdentifier>{ServiceTypes}{type}</ServiceTypeIdentifier>
          <ServiceName><Name xml:lang="en">{Escape(name)}</Name></ServiceName>
          <ServiceDigitalIdentity><DigitalId><X509Certificate>{Convert.ToBase64String(certificate.RawData)}</X509Certificate></DigitalId></ServiceDigitalIdentity>
          <ServiceStatus>{Statuses}{status}</ServiceStatus>
          <StatusStartingTime>{Time((since ?? certificate.NotBefore).ToUniversalTime())}</StatusStartingTime>
          {extensions}
        </ServiceInformation>{(history is null ? "" : $"""
        <ServiceHistory><ServiceHistoryInstance>
          <ServiceTypeIdentifier>{ServiceTypes}{type}</ServiceTypeIdentifier>
          <ServiceName><Name xml:lang="en">{Escape(name)}</Name></ServiceName>
          <ServiceDigitalIdentity><DigitalId><X509Certificate>{Convert.ToBase64String(certificate.RawData)}</X509Certificate></DigitalId></ServiceDigitalIdentity>
          <ServiceStatus>{Statuses}{history}</ServiceStatus>
          <StatusStartingTime>{Time(certificate.NotBefore.ToUniversalTime())}</StatusStartingTime>
          {extensions}
        </ServiceHistoryInstance></ServiceHistory>
        """)}</TSPService>
        """;

    /// <summary>
    /// The service information extensions of the root's CA/QC service (ETSI TS 119 612 §5.5.9): it issues qualified
    /// certificates for signatures and seals, and the certificates under the QCP-n-qscd policy (0.4.0.194112.1.2) have
    /// their key on a QSCD even when they do not say so (QCWithQSCD), as the <c>qc-esign-policy</c> signer shows.
    /// </summary>
    private const string QualifiedCaExtensions = """
        <ServiceInformationExtensions>
          <Extension Critical="true"><AdditionalServiceInformation><URI xml:lang="en">http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForeSignatures</URI></AdditionalServiceInformation></Extension>
          <Extension Critical="true"><AdditionalServiceInformation><URI xml:lang="en">http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForeSeals</URI></AdditionalServiceInformation></Extension>
          <Extension Critical="true">
            <ecc:Qualifications xmlns:ecc="http://uri.etsi.org/TrstSvc/SvcInfoExt/eSigDir-1999-93-EC-TrustedList/#" xmlns:xades="http://uri.etsi.org/01903/v1.3.2#">
              <ecc:QualificationElement>
                <ecc:Qualifiers><ecc:Qualifier uri="http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCWithQSCD"/></ecc:Qualifiers>
                <ecc:CriteriaList assert="atLeastOne">
                  <ecc:PolicySet><ecc:PolicyIdentifier><xades:Identifier Qualifier="OIDAsURN">urn:oid:0.4.0.194112.1.2</xades:Identifier></ecc:PolicyIdentifier></ecc:PolicySet>
                </ecc:CriteriaList>
              </ecc:QualificationElement>
            </ecc:Qualifications>
          </Extension>
        </ServiceInformationExtensions>
        """;

    /// <summary>A pointer of the LOTL: where the list is, who signs it, its type, territory and media type.</summary>
    private static string Pointer(Uri location, X509Certificate2 signer, string tslType) => $"""
        <OtherTSLPointer>
          <ServiceDigitalIdentities><ServiceDigitalIdentity><DigitalId><X509Certificate>{Convert.ToBase64String(signer.RawData)}</X509Certificate></DigitalId></ServiceDigitalIdentity></ServiceDigitalIdentities>
          <TSLLocation>{location}</TSLLocation>
          <AdditionalInformation>
            <OtherInformation><TSLType>{tslType}</TSLType></OtherInformation>
            <OtherInformation><SchemeOperatorName><Name xml:lang="en">SimpleSign Sandbox</Name></SchemeOperatorName></OtherInformation>
            <OtherInformation><SchemeTerritory>{Territory}</SchemeTerritory></OtherInformation>
            <OtherInformation><ns3:MimeType xmlns:ns3="{AdditionalTypes}">{MediaType}</ns3:MimeType></OtherInformation>
          </AdditionalInformation>
        </OtherTSLPointer>
        """;

    /// <summary>A TS 119 612 v5 list with every element its schema requires.</summary>
    private string Document(string tslType, string schemeName, string pointers, string services, DateTimeOffset issued, DateTimeOffset nextUpdate) => $"""
        <TrustServiceStatusList xmlns="{Ns}" Id="tsl" TSLTag="http://uri.etsi.org/19612/TSLTag">
          <SchemeInformation>
            <TSLVersionIdentifier>5</TSLVersionIdentifier>
            <TSLSequenceNumber>1</TSLSequenceNumber>
            <TSLType>{tslType}</TSLType>
            <SchemeOperatorName><Name xml:lang="en">SimpleSign Sandbox ({Escape(pki.Name)})</Name></SchemeOperatorName>
            <SchemeOperatorAddress>{Address()}</SchemeOperatorAddress>
            <SchemeName><Name xml:lang="en">ZZ: {Escape(schemeName)} ({Escape(pki.Name)}), for tests only</Name></SchemeName>
            <SchemeInformationURI><URI xml:lang="en">{pki.BaseUrl}</URI></SchemeInformationURI>
            <StatusDeterminationApproach>http://uri.etsi.org/TrstSvc/TrustedList/StatusDetn/EUappropriate</StatusDeterminationApproach>
            <SchemeTypeCommunityRules><URI xml:lang="en">http://uri.etsi.org/TrstSvc/TrustedList/schemerules/EUcommon</URI></SchemeTypeCommunityRules>
            <SchemeTerritory>{Territory}</SchemeTerritory>
            <PolicyOrLegalNotice><TSLLegalNotice xml:lang="en">Test trust scheme of the SimpleSign Sandbox. Never trust it for real signatures.</TSLLegalNotice></PolicyOrLegalNotice>
            <HistoricalInformationPeriod>65535</HistoricalInformationPeriod>
            {(pointers.Length > 0 ? $"<PointersToOtherTSL>{pointers}</PointersToOtherTSL>" : "")}
            <ListIssueDateTime>{Time(issued)}</ListIssueDateTime>
            <NextUpdate><dateTime>{Time(nextUpdate)}</dateTime></NextUpdate>
            <DistributionPoints><URI>{(tslType == LotlType ? LotlUrl : TlUrl)}</URI></DistributionPoints>
          </SchemeInformation>
          {services}
        </TrustServiceStatusList>
        """;

    private string Address() => $"""
        <PostalAddresses><PostalAddress xml:lang="en">
          <StreetAddress>Sandbox</StreetAddress><Locality>Localhost</Locality><CountryName>{Territory}</CountryName>
        </PostalAddress></PostalAddresses>
        <ElectronicAddress><URI xml:lang="en">{pki.BaseUrl}</URI></ElectronicAddress>
        """;

    /// <summary>
    /// Signs the list: an enveloped signature, a child of the root, whose references are the whole document (enveloped
    /// and exclusive canonicalization transforms, nothing else, as TS 119 612 §5.7.1 asks) and the XAdES
    /// SignedProperties (signing time and signing certificate).
    /// </summary>
    private static byte[] Sign(string xml, X509Certificate2 signer)
    {
        const string Xades = "http://uri.etsi.org/01903/v1.3.2#";
        var doc = new XmlDocument { PreserveWhitespace = true };
        doc.LoadXml(xml);
        using var key = signer.GetRSAPrivateKey() ?? throw new InvalidOperationException("The scheme operator has no RSA key.");
        string id = Convert.ToHexString(RandomNumberGenerator.GetBytes(8)).ToLowerInvariant();
        string signatureId = "sig-" + id;
        string propertiesId = "xades-" + id;

        var signedXml = new XadesSignedXml(doc) { SigningKey = key };
        signedXml.Signature.Id = signatureId;
        signedXml.SignedInfo!.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;
        signedXml.SignedInfo.SignatureMethod = SignedXml.XmlDsigRSASHA256Url;

        var whole = new Reference("") { DigestMethod = SignedXml.XmlDsigSHA256Url };
        whole.AddTransform(new XmlDsigEnvelopedSignatureTransform());
        whole.AddTransform(new XmlDsigExcC14NTransform());
        signedXml.AddReference(whole);

        // QualifyingProperties/SignedProperties, in a ds:Object of the signature.
        var holder = doc.CreateElement("holder");
        var qualifying = (XmlElement)holder.AppendChild(doc.CreateElement("xades", "QualifyingProperties", Xades))!;
        qualifying.SetAttribute("Target", "#" + signatureId);
        var properties = (XmlElement)qualifying.AppendChild(doc.CreateElement("xades", "SignedProperties", Xades))!;
        properties.SetAttribute("Id", propertiesId);
        var signatureProperties = properties.AppendChild(doc.CreateElement("xades", "SignedSignatureProperties", Xades))!;
        signatureProperties.AppendChild(doc.CreateElement("xades", "SigningTime", Xades))!.InnerText = Time(DateTimeOffset.UtcNow);
        // SigningCertificate (XAdES 1.3.2), not V2: the TL schema DSS checks lists against does not know V2.
        var certificate = signatureProperties.AppendChild(doc.CreateElement("xades", "SigningCertificate", Xades))!
            .AppendChild(doc.CreateElement("xades", "Cert", Xades))!;
        var digest = certificate.AppendChild(doc.CreateElement("xades", "CertDigest", Xades))!;
        ((XmlElement)digest.AppendChild(doc.CreateElement("ds", "DigestMethod", SignedXml.XmlDsigNamespaceUrl))!).SetAttribute("Algorithm", SignedXml.XmlDsigSHA256Url);
        digest.AppendChild(doc.CreateElement("ds", "DigestValue", SignedXml.XmlDsigNamespaceUrl))!.InnerText = Convert.ToBase64String(SHA256.HashData(signer.RawData));
        var issuerSerial = certificate.AppendChild(doc.CreateElement("xades", "IssuerSerial", Xades))!;
        issuerSerial.AppendChild(doc.CreateElement("ds", "X509IssuerName", SignedXml.XmlDsigNamespaceUrl))!.InnerText = signer.IssuerName.Name;
        issuerSerial.AppendChild(doc.CreateElement("ds", "X509SerialNumber", SignedXml.XmlDsigNamespaceUrl))!.InnerText =
            new BigInteger(signer.SerialNumberBytes.Span, isUnsigned: true, isBigEndian: true).ToString(System.Globalization.CultureInfo.InvariantCulture);
        signedXml.Properties = properties;
        signedXml.AddObject(new DataObject { Data = holder.ChildNodes });

        var signedProperties = new Reference("#" + propertiesId) { Type = "http://uri.etsi.org/01903#SignedProperties", DigestMethod = SignedXml.XmlDsigSHA256Url };
        signedProperties.AddTransform(new XmlDsigExcC14NTransform());
        signedXml.AddReference(signedProperties);

        var keyInfo = new KeyInfo();
        keyInfo.AddClause(new KeyInfoX509Data(signer));
        signedXml.KeyInfo = keyInfo;
        signedXml.ComputeSignature();
        doc.DocumentElement!.AppendChild(doc.ImportNode(signedXml.GetXml(), true));
        return Encoding.UTF8.GetBytes(doc.OuterXml);
    }

    /// <summary>
    /// A <see cref="SignedXml"/> that finds the XAdES SignedProperties by its Id: the stock one only looks in the
    /// document and at the ds:Object elements themselves, not inside them.
    /// </summary>
    private sealed class XadesSignedXml(XmlDocument document) : SignedXml(document)
    {
        public XmlElement? Properties { get; set; }

        public override XmlElement? GetIdElement(XmlDocument? document, string idValue) =>
            Properties is not null && Properties.GetAttribute("Id") == idValue ? Properties : base.GetIdElement(document, idValue);
    }

    /// <summary>Changes a character of the scheme name after signing: the signature no longer verifies.</summary>
    private static byte[] Tamper(byte[] signed)
    {
        string text = Encoding.UTF8.GetString(signed);
        int at = text.IndexOf("for tests only", StringComparison.Ordinal);
        return Encoding.UTF8.GetBytes(at < 0 ? text : string.Concat(text.AsSpan(0, at), "FOR", text.AsSpan(at + 3)));
    }

    private static string Time(DateTimeOffset time) => time.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ssZ", System.Globalization.CultureInfo.InvariantCulture);

    private static string Escape(string text) => SecurityElement.Escape(text);
}

using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;
using Shouldly;
using SimpleSign.Core.Http;
using SimpleSign.TestHelpers;
using SimpleSign.XAdES.TrustedLists;
using Xunit;

namespace SimpleSign.XAdES.Tests.TrustedLists;

[Trait("Category", "Unit")]
public sealed class TrustedListSetTests : IDisposable
{
    private const string LotlUrl = "https://198.51.100.7/eu-lotl.xml";
    private const string PtUrl = "https://198.51.100.7/pt.xml";
    private const string DeUrl = "https://198.51.100.7/de.xml";
    private const string Granted = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted";
    private const string CaQc = "http://uri.etsi.org/TrstSvc/Svctype/CA/QC";

    private readonly RSA _lotlKey = RSA.Create(2048);
    private readonly RSA _ptKey = RSA.Create(2048);
    private readonly RSA _deKey = RSA.Create(2048);
    private readonly X509Certificate2 _lotlSigner;
    private readonly X509Certificate2 _ptSigner;
    private readonly X509Certificate2 _deSigner;
    private readonly SyntheticPki _pt = new();
    private readonly SyntheticPki _de = new();
    private readonly string _cache = Directory.CreateTempSubdirectory("simplesign-lotl-").FullName;

    public TrustedListSetTests()
    {
        _lotlSigner = Operator("CN=EU LOTL", _lotlKey);
        _ptSigner = Operator("CN=PT operator", _ptKey);
        _deSigner = Operator("CN=DE operator", _deKey);
    }

    [Fact]
    public async Task LoadAsync_FollowsThePointersAndChecksEachListWithItsCertificate()
    {
        using var http = Server(Lists());

        var set = await TrustedListSet.LoadAsync(Options(), new SingleClientProvider(http));

        set.Lists.Select(l => l.Territory).ShouldBe(["PT", "DE"], ignoreOrder: true);
        set.GetTrustAnchors().Select(c => c.Thumbprint).ShouldBe([_pt.RootCa.Thumbprint, _de.RootCa.Thumbprint], ignoreOrder: true);
        set.TrustedLists.ShouldAllBe(l => l.IsWellSigned && l.Version == "5" && l.Location != null);
        set.Problems.ShouldBeEmpty();
    }

    [Fact]
    public async Task LoadAsync_Territories_LoadsOnlyThose()
    {
        using var http = Server(Lists());

        var set = await TrustedListSet.LoadAsync(Options() with { Territories = ["PT"] }, new SingleClientProvider(http));

        set.Lists.ShouldHaveSingleItem().Territory.ShouldBe("PT");
    }

    [Fact]
    public async Task LoadAsync_ListSignedByAnotherKey_IsAProblemNotAFailure()
    {
        var lists = Lists();
        lists[DeUrl] = Tl("DE", _de.RootCa, _ptKey, _ptSigner); // signed with the PT key: the LOTL says DE's
        using var http = Server(lists);

        var set = await TrustedListSet.LoadAsync(Options(), new SingleClientProvider(http));

        set.Lists.ShouldHaveSingleItem().Territory.ShouldBe("PT");
        set.Problems.ShouldHaveSingleItem().Territory.ShouldBe("DE");
    }

    [Fact]
    public async Task LoadAsync_FreshCache_IsUsedWithoutTheNetwork()
    {
        using (var http = Server(Lists()))
        {
            await TrustedListSet.LoadAsync(Options() with { CacheDirectory = _cache }, new SingleClientProvider(http));
        }

        using var offline = new HttpClient(new MockHttpHandler(_ => throw new HttpRequestException("offline")));
        var set = await TrustedListSet.LoadAsync(Options() with { CacheDirectory = _cache }, new SingleClientProvider(offline));

        set.Lists.Count.ShouldBe(2);
    }

    [Fact]
    public async Task LoadAsync_LotlSignedByAnotherKey_Throws()
    {
        using var http = Server(Lists());

        await Should.ThrowAsync<CryptographicException>(() =>
            TrustedListSet.LoadAsync(Options() with { LotlSignerCertificates = [_ptSigner] }, new SingleClientProvider(http)));
    }

    [Fact]
    public async Task LoadAsync_LotlSignedByANewKey_CarriesTheGivenKeyForwardThroughThePivots()
    {
        // The given (Official Journal) key signs the pivot; the pivot says the LOTL is signed by the new key from then on.
        using var newKey = RSA.Create(2048);
        using var newSigner = Operator("CN=EU LOTL 2", newKey);
        var lists = Lists();
        lists[LotlUrl] = Lotl(newKey, newSigner, PivotUrl);
        lists[PivotUrl] = Sign(Document("EU", LotlPointer(newSigner), ""), _lotlKey, _lotlSigner);
        using var http = Server(lists);

        var set = await TrustedListSet.LoadAsync(Options(), new SingleClientProvider(http));

        set.Lists.Count.ShouldBe(2);
        set.PivotsFollowed.ShouldBe([new Uri(PivotUrl)]);
        set.LotlSigners.ShouldHaveSingleItem().Thumbprint.ShouldBe(newSigner.Thumbprint);
    }

    [Fact]
    public async Task LoadAsync_PivotSignedByAnUnknownKey_Throws()
    {
        using var newKey = RSA.Create(2048);
        using var newSigner = Operator("CN=EU LOTL 2", newKey);
        var lists = Lists();
        lists[LotlUrl] = Lotl(newKey, newSigner, PivotUrl);
        lists[PivotUrl] = Sign(Document("EU", LotlPointer(newSigner), ""), newKey, newSigner);
        using var http = Server(lists);

        var ex = await Should.ThrowAsync<CryptographicException>(() => TrustedListSet.LoadAsync(Options(), new SingleClientProvider(http)));

        ex.Message.ShouldContain("pivot");
    }

    [Fact]
    public async Task LoadAsync_FollowPivotsOff_DoesNotWalkThem()
    {
        using var newKey = RSA.Create(2048);
        using var newSigner = Operator("CN=EU LOTL 2", newKey);
        var lists = Lists();
        lists[LotlUrl] = Lotl(newKey, newSigner, PivotUrl);
        lists[PivotUrl] = Sign(Document("EU", LotlPointer(newSigner), ""), _lotlKey, _lotlSigner);
        using var http = Server(lists);

        await Should.ThrowAsync<CryptographicException>(() =>
            TrustedListSet.LoadAsync(Options() with { FollowPivots = false }, new SingleClientProvider(http)));
    }

    private const string PivotUrl = "https://198.51.100.7/eu-lotl-pivot-300.xml";

    private static string LotlPointer(X509Certificate2 signer) => $"""
        <OtherTSLPointer>
          <ServiceDigitalIdentities><ServiceDigitalIdentity><DigitalId><X509Certificate>{Convert.ToBase64String(signer.RawData)}</X509Certificate></DigitalId></ServiceDigitalIdentity></ServiceDigitalIdentities>
          <TSLLocation>{LotlUrl}</TSLLocation>
          <AdditionalInformation>
            <OtherInformation><TSLType>http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUlistofthelists</TSLType></OtherInformation>
            <OtherInformation><SchemeTerritory>EU</SchemeTerritory></OtherInformation>
          </AdditionalInformation>
        </OtherTSLPointer>
        """;

    public void Dispose()
    {
        Directory.Delete(_cache, recursive: true);
        _pt.Dispose();
        _de.Dispose();
        _lotlSigner.Dispose();
        _ptSigner.Dispose();
        _deSigner.Dispose();
        _lotlKey.Dispose();
        _ptKey.Dispose();
        _deKey.Dispose();
    }

    private TrustedListSetOptions Options() => new() { LotlLocation = new Uri(LotlUrl), LotlSignerCertificates = [_lotlSigner] };

    private Dictionary<string, byte[]> Lists() => new()
    {
        [LotlUrl] = Lotl(),
        [PtUrl] = Tl("PT", _pt.RootCa, _ptKey, _ptSigner),
        [DeUrl] = Tl("DE", _de.RootCa, _deKey, _deSigner),
    };

    private static HttpClient Server(Dictionary<string, byte[]> lists) =>
        new(new MockHttpHandler(request => Task.FromResult(
            lists.TryGetValue(request.RequestUri!.AbsoluteUri, out byte[]? body)
                ? new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(body) }
                : new HttpResponseMessage(HttpStatusCode.NotFound))));

    private byte[] Lotl() => Lotl(_lotlKey, _lotlSigner, null);

    private byte[] Lotl(RSA key, X509Certificate2 signer, string? pivot)
    {
        string Pointer(string territory, string url, X509Certificate2 signer) => $"""
            <OtherTSLPointer>
              <ServiceDigitalIdentities><ServiceDigitalIdentity><DigitalId><X509Certificate>{Convert.ToBase64String(signer.RawData)}</X509Certificate></DigitalId></ServiceDigitalIdentity></ServiceDigitalIdentities>
              <TSLLocation>{url}</TSLLocation>
              <AdditionalInformation>
                <OtherInformation><SchemeTerritory>{territory}</SchemeTerritory></OtherInformation>
                <OtherInformation><ns3:MimeType xmlns:ns3="http://uri.etsi.org/02231/v2/additionaltypes#">application/vnd.etsi.tsl+xml</ns3:MimeType></OtherInformation>
              </AdditionalInformation>
            </OtherTSLPointer>
            """;
        string pointers = Pointer("PT", PtUrl, _ptSigner) + Pointer("DE", DeUrl, _deSigner)
            + Pointer("PT", "https://198.51.100.7/pt.pdf", _ptSigner).Replace("application/vnd.etsi.tsl+xml", "application/pdf", StringComparison.Ordinal);
        string document = Document("EU", pointers, "");
        if (pivot is not null)
        {
            document = document.Replace("<SchemeTerritory>EU</SchemeTerritory>",
                $"<SchemeTerritory>EU</SchemeTerritory><SchemeInformationURI><URI xml:lang=\"en\">{pivot}</URI><URI xml:lang=\"en\">https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=OJ</URI></SchemeInformationURI>", StringComparison.Ordinal);
        }

        return Sign(document, key, signer);
    }

    private static byte[] Tl(string territory, X509Certificate2 anchor, RSA key, X509Certificate2 signer)
    {
        string services = $"""
            <TrustServiceProviderList><TrustServiceProvider>
              <TSPInformation><TSPName><Name xml:lang="en">Provider</Name></TSPName></TSPInformation>
              <TSPServices><TSPService><ServiceInformation>
                <ServiceTypeIdentifier>{CaQc}</ServiceTypeIdentifier>
                <ServiceName><Name xml:lang="en">CA</Name></ServiceName>
                <ServiceDigitalIdentity><DigitalId><X509Certificate>{Convert.ToBase64String(anchor.RawData)}</X509Certificate></DigitalId></ServiceDigitalIdentity>
                <ServiceStatus>{Granted}</ServiceStatus>
              </ServiceInformation></TSPService></TSPServices>
            </TrustServiceProvider></TrustServiceProviderList>
            """;
        return Sign(Document(territory, "", services), key, signer);
    }

    private static string Document(string territory, string pointers, string services) => $"""
        <TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#" Id="tsl" TSLTag="http://uri.etsi.org/02231/TSLTag">
          <SchemeInformation>
            <TSLVersionIdentifier>5</TSLVersionIdentifier>
            <TSLSequenceNumber>7</TSLSequenceNumber>
            <SchemeOperatorName><Name xml:lang="en">Operator</Name></SchemeOperatorName>
            <SchemeTerritory>{territory}</SchemeTerritory>
            {(pointers.Length > 0 ? "<PointersToOtherTSL>" + pointers + "</PointersToOtherTSL>" : "")}
            <ListIssueDateTime>{DateTimeOffset.UtcNow.AddDays(-1):yyyy-MM-ddTHH:mm:ssZ}</ListIssueDateTime>
            <NextUpdate><dateTime>{DateTimeOffset.UtcNow.AddMonths(3):yyyy-MM-ddTHH:mm:ssZ}</dateTime></NextUpdate>
          </SchemeInformation>
          {services}
        </TrustServiceStatusList>
        """;

    private static byte[] Sign(string xml, RSA key, X509Certificate2 signer)
    {
        var doc = new XmlDocument { PreserveWhitespace = true };
        doc.LoadXml(xml);
        var signedXml = new SignedXml(doc) { SigningKey = key };
        var reference = new Reference("#tsl");
        reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
        reference.AddTransform(new XmlDsigExcC14NTransform());
        reference.DigestMethod = SignedXml.XmlDsigSHA256Url;
        signedXml.SignedInfo!.SignatureMethod = SignedXml.XmlDsigRSASHA256Url;
        signedXml.AddReference(reference);
        var keyInfo = new KeyInfo();
        keyInfo.AddClause(new KeyInfoX509Data(signer));
        signedXml.KeyInfo = keyInfo;
        signedXml.ComputeSignature();
        doc.DocumentElement!.AppendChild(doc.ImportNode(signedXml.GetXml(), true));
        return System.Text.Encoding.UTF8.GetBytes(doc.OuterXml);
    }

    private static X509Certificate2 Operator(string subject, RSA key) =>
        new CertificateRequest(subject, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            .CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(2));
}

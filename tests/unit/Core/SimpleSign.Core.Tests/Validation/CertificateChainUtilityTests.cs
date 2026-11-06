using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Shouldly;

using SimpleSign.Core.Crypto;
using SimpleSign.Core.Validation;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.Core.Tests.Validation;

[Trait("Category", "Unit")]
public sealed class CertificateChainUtilityTests
{
    private static byte[] BuildAiaExtensionBytes(
        string url,
        string accessMethodOid = "1.3.6.1.5.5.7.48.2")
    {
        AsnWriter asnWriter = new AsnWriter(AsnEncodingRules.DER);
        using (asnWriter.PushSequence())
        {
            using (asnWriter.PushSequence())
            {
                asnWriter.WriteObjectIdentifier(accessMethodOid);
                asnWriter.WriteCharacterString(UniversalTagNumber.IA5String, url, new Asn1Tag(TagClass.ContextSpecific, 6));
            }
        }
        return asnWriter.Encode();
    }

    private static X509Certificate2 CreateCertWithAia(string aiaUrl)
    {
        using RSA key = RSA.Create(2048);
        CertificateRequest certificateRequest = new CertificateRequest("CN=AIA Test", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        certificateRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: false));
        byte[] rawData = BuildAiaExtensionBytes(aiaUrl);
        certificateRequest.CertificateExtensions.Add(new X509Extension("1.3.6.1.5.5.7.1.1", rawData, critical: false));
        X509Certificate2 x509Certificate = certificateRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1.0), DateTimeOffset.UtcNow.AddYears(1));
        return CertificateLoader.LoadPkcs12(x509Certificate.Export(X509ContentType.Pfx, "test-export"), "test-export");
    }

    [Fact(DisplayName = "Valid ASN.1 returns AIA URLs correctly")]
    public void ExtractAiaUrls_ValidAsn1_ReturnsUrls()
    {
        byte[] data = BuildAiaExtensionBytes("http://example.com/ca.crt");
        List<string> list = [.. CertificateChainUtility.ExtractAiaUrls(data)];
        list.Count().ShouldBe(1);
        list[0].ShouldBe("http://example.com/ca.crt");
    }

    [Fact(DisplayName = "OCSP access locations are not treated as CA Issuers URLs")]
    public void ExtractAiaUrls_OcspLocation_IsIgnored()
    {
        byte[] data = BuildAiaExtensionBytes(
            "http://ocsp.example.com",
            "1.3.6.1.5.5.7.48.1");

        CertificateChainUtility.ExtractAiaUrls(data).ShouldBeEmpty();
    }

    [Fact(DisplayName = "Invalid ASN.1 falls back to text search")]
    public void ExtractAiaUrls_InvalidAsn1_FallsBackToTextSearch()
    {
        byte[] bytes = Encoding.ASCII.GetBytes("garbage http://example.com/ca.crt more garbage");
        List<string> list = [.. CertificateChainUtility.ExtractAiaUrls(bytes)];
        list.Count().ShouldBe(1);
        list[0].ShouldBe("http://example.com/ca.crt");
    }

    [Fact(DisplayName = "Empty data returns empty AIA URL list")]
    public void ExtractAiaUrls_EmptyData_ReturnsEmpty()
    {
        List<string> list = [.. CertificateChainUtility.ExtractAiaUrls([])];
        list.ShouldBeEmpty("");
    }

    [Fact(DisplayName = "Valid DER loads certificate successfully")]
    public void LoadCertsFromBytes_ValidDer_ReturnsCert()
    {
        using X509Certificate2 x509Certificate = TestCertificateFactory.CreateSelfSignedCert();
        List<X509Certificate2> actualValue = [.. CertificateChainUtility.LoadCertsFromBytes(x509Certificate.RawData)];
        actualValue.Count().ShouldBe(1, "");
    }

    [Fact(DisplayName = "Invalid bytes return empty or throw platform exception")]
    public void LoadCertsFromBytes_GarbageBytes_ReturnsEmptyOrThrowsPlatformException()
    {
        Func<List<X509Certificate2>> func = () => [.. CertificateChainUtility.LoadCertsFromBytes([255, 254])];
        // Behavior varies by platform and .NET version — either empty or PlatformNotSupportedException
        try
        {
            func().ShouldBeEmpty();
        }
        catch (PlatformNotSupportedException)
        {
            // Acceptable on some macOS/.NET version combinations
        }
    }

    [Fact(DisplayName = "Subject with CN extracts short name correctly")]
    public void ShortName_WithCn_ExtractsCn() => CertificateChainUtility.ShortName("CN=Fulano, O=Org").ShouldBe("Fulano", "");

    [Fact(DisplayName = "Subject without CN returns full subject")]
    public void ShortName_WithoutCn_ReturnsFullSubject() => CertificateChainUtility.ShortName("O=Org").ShouldBe("O=Org", "");

    [Fact(DisplayName = "PKCS#7 (.p7b) bytes load a collection of certificates")]
    public void LoadCertsFromBytes_P7bBytes_ReturnsAllCertificates()
    {
        using var ca = TestCertificateFactory.CreateCaCert("CN=P7B CA Test, O=Tests, C=BR");
        using var leaf = TestCertificateFactory.CreateLeafCert(ca, "CN=P7B Leaf Test, O=Tests, C=BR");

        var collection = new X509Certificate2Collection { ca, leaf };
#pragma warning disable SYSLIB0057
        byte[] p7bBytes = collection.Export(X509ContentType.Pkcs7)!;
#pragma warning restore SYSLIB0057

        List<X509Certificate2> loaded = [.. CertificateChainUtility.LoadCertsFromBytes(p7bBytes)];

        loaded.Count.ShouldBe(2, "P7B bundle should yield both the CA and leaf certificates");
        loaded.ShouldContain(c => c.Thumbprint == ca.Thumbprint, "CA cert should be present");
        loaded.ShouldContain(c => c.Thumbprint == leaf.Thumbprint, "leaf cert should be present");
    }

    [Fact(DisplayName = "BFS AIA chasing downloads certs beyond first level")]
    public async Task DownloadAiaCertsAsync_MultiLevelAia_ChasesBeyondFirstLevel()
    {
        // Arrange: build a 3-level chain — leaf → intermediate → root
        // leaf.AIA → "http://aia.test/intermediate.crt" (serves intermediate DER)
        // intermediate.AIA → "http://aia.test/root.crt"    (serves root DER)
        using var pki = new SyntheticPki(
            intermediateCaIssuersUrl: "http://aia.test/root.crt",
            leafCaIssuersUrl: "http://aia.test/intermediate.crt");

        var urlMap = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase)
        {
            ["http://aia.test/intermediate.crt"] = pki.IntermediateCa.RawData,
            ["http://aia.test/root.crt"] = pki.RootCa.RawData,
        };

        using var httpClient = new HttpClient(new MockHttpHandler(async req =>
        {
            var url = req.RequestUri!.ToString();
            return urlMap.TryGetValue(url, out var bytes)
                ? new System.Net.Http.HttpResponseMessage(System.Net.HttpStatusCode.OK)
                { Content = new ByteArrayContent(bytes) }
                : new System.Net.Http.HttpResponseMessage(System.Net.HttpStatusCode.NotFound);
        }));

        var warnings = new List<string>();

        // Act
        var result = await CertificateChainUtility.DownloadAiaCertsAsync(
            httpClient, pki.Leaf, null, warnings, CancellationToken.None);

        // Assert: BFS should have followed leaf→intermediate→root (both levels)
        result.ShouldContain(c => c.Thumbprint == pki.IntermediateCa.Thumbprint,
            "first-level AIA cert (intermediate) must be downloaded");
        result.ShouldContain(c => c.Thumbprint == pki.RootCa.Thumbprint,
            "second-level AIA cert (root) must be chased recursively");
        warnings.ShouldBeEmpty();
    }

    [Fact(DisplayName = "Certificate without AIA extension returns empty list")]
    public async Task DownloadAiaCertsAsync_NoAiaExtension_ReturnsEmpty()
    {
        using X509Certificate2 cert = TestCertificateFactory.CreateSelfSignedCert();
        using HttpClient httpClient = MockHttpHandler.ForGetBytes([]);
        List<string> warnings = new List<string>();
        (await CertificateChainUtility.DownloadAiaCertsAsync(httpClient, cert, null, warnings, CancellationToken.None)).ShouldBeEmpty("");
    }

    [Fact(DisplayName = "Cancellation while downloading AIA propagates")]
    public async Task DownloadAiaCertsAsync_Cancellation_Propagates()
    {
        using X509Certificate2 cert = CreateCertWithAia("http://example.com/ca.crt");
        using HttpClient httpClient = MockHttpHandler.Failing();
        using CancellationTokenSource cts = new CancellationTokenSource();
        cts.Cancel();
        List<string> warnings = new List<string>();
        await Should.ThrowAsync<OperationCanceledException>(() =>
            CertificateChainUtility.DownloadAiaCertsAsync(httpClient, cert, null, warnings, cts.Token));
        warnings.ShouldBeEmpty();
    }
}

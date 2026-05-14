using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using FluentAssertions;

using SimpleSign.Core.Crypto;
using SimpleSign.Core.Validation;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.Core.Tests.Validation;

public sealed class CertificateChainUtilityTests
{
    private static byte[] BuildAiaExtensionBytes(string url)
    {
        AsnWriter asnWriter = new AsnWriter(AsnEncodingRules.DER);
        using (asnWriter.PushSequence())
        {
            using (asnWriter.PushSequence())
            {
                asnWriter.WriteObjectIdentifier("1.3.6.1.5.5.7.48.2");
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
        List<string> list = CertificateChainUtility.ExtractAiaUrls(data).ToList();
        list.Should().ContainSingle("").Which.Should().Be("http://example.com/ca.crt", "");
    }

    [Fact(DisplayName = "Invalid ASN.1 falls back to text search")]
    public void ExtractAiaUrls_InvalidAsn1_FallsBackToTextSearch()
    {
        byte[] bytes = Encoding.ASCII.GetBytes("garbage http://example.com/ca.crt more garbage");
        List<string> list = CertificateChainUtility.ExtractAiaUrls(bytes).ToList();
        list.Should().ContainSingle("").Which.Should().Be("http://example.com/ca.crt", "");
    }

    [Fact(DisplayName = "Empty data returns empty AIA URL list")]
    public void ExtractAiaUrls_EmptyData_ReturnsEmpty()
    {
        List<string> list = CertificateChainUtility.ExtractAiaUrls(Array.Empty<byte>()).ToList();
        list.Should().BeEmpty("");
    }

    [Fact(DisplayName = "Valid DER loads certificate successfully")]
    public void LoadCertsFromBytes_ValidDer_ReturnsCert()
    {
        using X509Certificate2 x509Certificate = TestCertificateFactory.CreateSelfSignedCert();
        List<X509Certificate2> actualValue = CertificateChainUtility.LoadCertsFromBytes(x509Certificate.RawData).ToList();
        actualValue.Should().HaveCount(1, "");
    }

    [Fact(DisplayName = "Invalid bytes return empty or throw platform exception")]
    public void LoadCertsFromBytes_GarbageBytes_ReturnsEmptyOrThrowsPlatformException()
    {
        Func<List<X509Certificate2>> func = () => CertificateChainUtility.LoadCertsFromBytes(new byte[2] { 255, 254 }).ToList();
#if NET9_0_OR_GREATER
        if (OperatingSystem.IsMacOS())
        {
            func.Should().Throw<PlatformNotSupportedException>();
        }
        else
        {
            func().Should().BeEmpty();
        }
#else
        // On .NET 8 + macOS, garbage bytes return empty instead of throwing.
        func().Should().BeEmpty();
#endif
    }

    [Fact(DisplayName = "Subject with CN extracts short name correctly")]
    public void ShortName_WithCn_ExtractsCn()
    {
        CertificateChainUtility.ShortName("CN=Fulano, O=Org").Should().Be("Fulano", "");
    }

    [Fact(DisplayName = "Subject without CN returns full subject")]
    public void ShortName_WithoutCn_ReturnsFullSubject()
    {
        CertificateChainUtility.ShortName("O=Org").Should().Be("O=Org", "");
    }

    [Fact(DisplayName = "Certificate without AIA extension returns empty list")]
    public async Task DownloadAiaCertsAsync_NoAiaExtension_ReturnsEmpty()
    {
        using X509Certificate2 cert = TestCertificateFactory.CreateSelfSignedCert();
        using HttpClient httpClient = MockHttpHandler.ForGetBytes(Array.Empty<byte>());
        List<string> warnings = new List<string>();
        (await CertificateChainUtility.DownloadAiaCertsAsync(httpClient, cert, null, warnings, CancellationToken.None)).Should().BeEmpty("");
    }

    [Fact(DisplayName = "Network failure downloading AIA adds warning")]
    public async Task DownloadAiaCertsAsync_NetworkFailure_AddsWarning()
    {
        using X509Certificate2 cert = CreateCertWithAia("http://example.com/ca.crt");
        using HttpClient httpClient = MockHttpHandler.Failing();
        using CancellationTokenSource cts = new CancellationTokenSource();
        cts.Cancel();
        List<string> warnings = new List<string>();
        await CertificateChainUtility.DownloadAiaCertsAsync(httpClient, cert, null, warnings, cts.Token);
        warnings.Should().NotBeEmpty("");
        warnings[0].Should().Contain("example.com/ca.crt", "");
    }
}

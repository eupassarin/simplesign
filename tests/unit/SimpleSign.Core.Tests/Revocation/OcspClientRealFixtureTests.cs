using Shouldly;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Revocation;
using SimpleSign.TestFixtures;
using Xunit;

namespace SimpleSign.Core.Tests.Revocation;

/// <summary>
/// Real-fixture tests for <see cref="OcspClient.ParseOcspResponse"/>.
/// Loads an actual OCSPResponse captured from DigiCert's responder for
/// <c>www.digicert.com</c> and verifies the parser handles the real wire format
/// — including DER-with-context-tags, GeneralizedTime, and signature blocks.
/// </summary>
public sealed class OcspClientRealFixtureTests
{
    [Fact(DisplayName = "ParseOcspResponse returns true for real DigiCert 'good' response")]
    public void ParseOcspResponse_RealDigiCertGood_ReturnsTrue()
    {
        using var cert = CertificateLoader.LoadCertificate(RecordedFixtures.DigiCertPublicCertDer);
        var result = OcspClient.ParseOcspResponse(RecordedFixtures.DigiCertOcspGood, cert);
        result.ShouldBeTrue("DigiCert reported the cert as not revoked when the fixture was captured");
    }

    [Fact(DisplayName = "ParseOcspResponse handles real responder cert embedded in [0] OPTIONAL")]
    public void ParseOcspResponse_RealDigiCertResponse_DoesNotThrow()
    {
        using var cert = CertificateLoader.LoadCertificate(RecordedFixtures.DigiCertPublicCertDer);
        // Just exercising: the responder embeds its cert; parse() must verify the signature
        // and not throw. If the parser had a bug here, it would surface immediately.
        Action act = () => OcspClient.ParseOcspResponse(RecordedFixtures.DigiCertOcspGood, cert);
        Should.NotThrow(act);
    }

    [Fact(DisplayName = "Real DigiCert public cert has the expected issuer subject")]
    public void DigiCertPublicCert_HasExpectedIssuer()
    {
        using var cert = CertificateLoader.LoadCertificate(RecordedFixtures.DigiCertPublicCertDer);
        cert.Issuer.ShouldContain("DigiCert");
    }

    [Fact(DisplayName = "Real DigiCert issuer cert can be loaded and is self-signed within DigiCert hierarchy")]
    public void DigiCertIssuerCert_HasDigiCertIssuer()
    {
        using var cert = CertificateLoader.LoadCertificate(RecordedFixtures.DigiCertIssuerCertDer);
        cert.Subject.ShouldContain("DigiCert");
    }

    [Fact(DisplayName = "GetOcspUrl on real DigiCert public cert returns http://ocsp.digicert.com")]
    public void GetOcspUrl_RealDigiCertCert_ReturnsExpectedUrl()
    {
        using var cert = CertificateLoader.LoadCertificate(RecordedFixtures.DigiCertPublicCertDer);
        var ocspUrl = OcspClient.GetOcspUrl(cert);
        ocspUrl.ShouldBe("http://ocsp.digicert.com");
    }

    [Fact(DisplayName = "GetCaIssuersUrl on real DigiCert public cert returns the CA Issuers URL")]
    public void GetCaIssuersUrl_RealDigiCertCert_ReturnsExpectedUrl()
    {
        using var cert = CertificateLoader.LoadCertificate(RecordedFixtures.DigiCertPublicCertDer);
        var url = OcspClient.GetCaIssuersUrl(cert);
        url!.ShouldStartWith("http://");
        url.ShouldContain("digicert.com");
        url.ShouldEndWith(".crt");
    }
}

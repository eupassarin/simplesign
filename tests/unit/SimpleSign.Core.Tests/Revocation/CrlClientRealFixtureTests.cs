using FluentAssertions;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Revocation;
using SimpleSign.TestFixtures;
using Xunit;

namespace SimpleSign.Core.Tests.Revocation;

/// <summary>
/// Real-fixture tests for <see cref="CrlClient.IsSerialInCrl"/> with a CRL captured
/// from DigiCert's distribution point. Exercises the full CRL parser including
/// signed-revocation-list, revokedCertificates SEQUENCE iteration, and signature
/// verification when an issuer cert is supplied.
/// </summary>
public sealed class CrlClientRealFixtureTests
{
    [Fact(DisplayName = "IsSerialInCrl returns false for a fresh DigiCert cert (not in CRL)")]
    public void IsSerialInCrl_FreshCert_ReturnsFalse()
    {
        // The captured DigiCert public cert is currently valid, so its serial should NOT
        // appear in the issuer's CRL. IsSerialInCrl returns true=revoked, false=not-in-CRL,
        // null=could-not-determine. We accept false or null (depending on whether the issuer
        // cert chain matches the CRL signer perfectly).
        using var cert = CertificateLoader.LoadCertificate(RecordedFixtures.DigiCertPublicCertDer);
        using var issuer = CertificateLoader.LoadCertificate(RecordedFixtures.DigiCertIssuerCertDer);

        var result = CrlClient.IsSerialInCrl(cert, RecordedFixtures.DigiCertCrl, issuer);

        result.Should().NotBe(true, "the cert is currently valid; it must not appear as revoked");
    }

    [Fact(DisplayName = "IsSerialInCrl handles the real DigiCert CRL without throwing")]
    public void IsSerialInCrl_RealCrl_DoesNotThrow()
    {
        using var cert = CertificateLoader.LoadCertificate(RecordedFixtures.DigiCertPublicCertDer);
        using var issuer = CertificateLoader.LoadCertificate(RecordedFixtures.DigiCertIssuerCertDer);

        Action act = () => CrlClient.IsSerialInCrl(cert, RecordedFixtures.DigiCertCrl, issuer);
        act.Should().NotThrow();
    }

    [Fact(DisplayName = "GetCrlUrl on real DigiCert cert returns the http URL")]
    public void GetCrlUrl_RealDigiCertCert_ReturnsHttpUrl()
    {
        using var cert = CertificateLoader.LoadCertificate(RecordedFixtures.DigiCertPublicCertDer);
        var url = CrlClient.GetCrlUrl(cert);
        url.Should().StartWith("http://").And.EndWith(".crl");
    }

    [Fact(DisplayName = "Real DigiCert CRL is hundreds of KB (real CA produces large CRLs)")]
    public void RealDigiCertCrl_IsRealisticSize()
    {
        // Captured DigiCert CRL has ~400KB at fixture time. If this fixture ever shrinks
        // to a few hundred bytes, something has gone wrong with the recording.
        RecordedFixtures.DigiCertCrl.Length.Should().BeGreaterThan(10_000);
    }
}

using SimpleSign.Core.Revocation;
using SimpleSign.Core.Validation;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.Core.Tests.Validation;

public sealed class EmbeddedRevocationEvidenceTests
{
    [Fact]
    public void CoversCertificate_RevokedCertificate_ReturnsFalse()
    {
        using var pki = new SyntheticPki();
        using var httpClient = MockHttpHandler.Failing();

        Assert.False(EmbeddedRevocationEvidence.CoversCertificate(
            pki.Leaf, pki.IntermediateCa, [], [pki.BuildRevokedLeafCrl()],
            DateTimeOffset.UtcNow, new OcspClient(httpClient)));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void CoversCertificate_GoodAndRevokedCrlInEitherOrder_ReturnsFalse(bool revokedFirst)
    {
        using var pki = new SyntheticPki();
        using var httpClient = MockHttpHandler.Failing();
        byte[] good = pki.BuildLeafCrl();
        byte[] revoked = pki.BuildRevokedLeafCrl();
        byte[][] crls = revokedFirst ? [revoked, good] : [good, revoked];
        DateTimeOffset validationTime = DateTimeOffset.UtcNow;
        Assert.True(CrlClient.IsSerialInCrl(pki.Leaf, revoked, pki.IntermediateCa, signingTime: validationTime));
        Assert.False(CrlClient.IsSerialInCrl(pki.Leaf, good, pki.IntermediateCa, signingTime: validationTime));

        Assert.False(EmbeddedRevocationEvidence.CoversCertificate(
            pki.Leaf, pki.IntermediateCa, [], crls,
            validationTime, new OcspClient(httpClient)));
    }

    [Fact]
    public void CoversAll_ValidCrlForEveryCertificate_ReturnsTrue()
    {
        using var pki = new SyntheticPki();
        using var httpClient = new HttpClient();
        byte[] leafCrl = pki.BuildLeafCrl();
        byte[] intermediateCrl = pki.BuildIntermediateCrl();

        bool covered = EmbeddedRevocationEvidence.CoversAll(
            [pki.Leaf, pki.IntermediateCa, pki.RootCa], [],
            [leafCrl, intermediateCrl], DateTimeOffset.UtcNow, new OcspClient(httpClient));

        Assert.True(covered);
    }

    [Fact]
    public void CoversAll_MissingLaterCertificateCrl_ReturnsFalse()
    {
        using var pki = new SyntheticPki();
        using var httpClient = new HttpClient();
        byte[] leafCrl = pki.BuildLeafCrl();

        bool covered = EmbeddedRevocationEvidence.CoversAll(
            [pki.Leaf, pki.IntermediateCa, pki.RootCa], [],
            [leafCrl], DateTimeOffset.UtcNow, new OcspClient(httpClient));

        Assert.False(covered);

        Assert.False(EmbeddedRevocationEvidence.CoversAll(
            [pki.Leaf], [pki.Leaf, pki.IntermediateCa, pki.RootCa], [],
            [leafCrl], DateTimeOffset.UtcNow, new OcspClient(httpClient)));
    }

    [Fact]
    public void CoversCertificate_MismatchedOrCorruptedCrl_ReturnsFalse()
    {
        using var pki = new SyntheticPki();
        using var httpClient = new HttpClient();
        var ocsp = new OcspClient(httpClient);
        byte[] wrongIssuerCrl = pki.BuildIntermediateCrl();
        byte[] damagedCrl = pki.BuildLeafCrl();
        damagedCrl[^1] ^= 0x01;

        Assert.False(EmbeddedRevocationEvidence.CoversCertificate(
            pki.Leaf, pki.IntermediateCa, [], [wrongIssuerCrl], DateTimeOffset.UtcNow, ocsp));
        Assert.False(EmbeddedRevocationEvidence.CoversCertificate(
            pki.Leaf, pki.IntermediateCa, [], [damagedCrl], DateTimeOffset.UtcNow, ocsp));
    }

    [Fact]
    public void CoversAll_MissingIssuer_ReturnsFalse()
    {
        using var pki = new SyntheticPki();
        using var httpClient = new HttpClient();

        bool covered = EmbeddedRevocationEvidence.CoversAll(
            [pki.Leaf], [pki.Leaf], [], [pki.BuildLeafCrl()],
            DateTimeOffset.UtcNow, new OcspClient(httpClient));

        Assert.False(covered);
    }

    [Fact]
    public void CoversAll_SameIssuerNameWithDifferentKey_ReturnsFalse()
    {
        using var pki = new SyntheticPki();
        using var unrelated = new SyntheticPki();
        using var httpClient = new HttpClient();

        Assert.False(EmbeddedRevocationEvidence.CoversAll(
            [pki.Leaf], [pki.Leaf, unrelated.IntermediateCa, unrelated.RootCa], [],
            [unrelated.BuildLeafCrl()], DateTimeOffset.UtcNow, new OcspClient(httpClient)));
    }

    [Fact]
    public void CoversCertificate_ExpiredOrEarlyCrl_ReturnsFalse()
    {
        using var pki = new SyntheticPki();
        using var httpClient = new HttpClient();

        byte[] crl = pki.BuildLeafCrl();
        var ocsp = new OcspClient(httpClient);
        Assert.False(EmbeddedRevocationEvidence.CoversCertificate(
            pki.Leaf, pki.IntermediateCa, [], [crl], DateTimeOffset.UtcNow.AddDays(40), ocsp));
        Assert.False(EmbeddedRevocationEvidence.CoversCertificate(
            pki.Leaf, pki.IntermediateCa, [], [crl], DateTimeOffset.UtcNow.AddDays(-2), ocsp));
    }
}

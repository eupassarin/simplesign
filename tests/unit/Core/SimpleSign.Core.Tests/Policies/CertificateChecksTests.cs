using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Shouldly;
using SimpleSign.Core.Policies;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.Core.Tests.Policies;

[Trait("Category", "Unit")]
public sealed class CertificateChecksTests : IDisposable
{
    private readonly SyntheticPki _pki = new();

    [Fact]
    public void SyntheticChain_FollowsRfc5280()
    {
        var chain = _pki.Chain();

        CertificateChecks.IssuerNameMatches(_pki.Leaf, _pki.IntermediateCa).ShouldBeTrue();
        CertificateChecks.PathLengthsRespected(chain).ShouldBeTrue();
        CertificateChecks.HasExtension(_pki.IntermediateCa, CertificateChecks.SubjectKeyIdentifier).ShouldBeTrue();
        CertificateChecks.NoRevAvailCompliant(_pki.Leaf).ShouldBeTrue();
        CertificateChecks.NameConstraintsRespected(CertificateChecks.ChainFlags(chain)).ShouldBeTrue();
    }

    [Fact]
    public void IssuerNameMatches_WrongIssuer_IsFalse() =>
        CertificateChecks.IssuerNameMatches(_pki.Leaf, _pki.RootCa).ShouldBeFalse();

    [Fact]
    public void PathLengthsRespected_CaBelowARootWithPathLengthZero_IsFalse()
    {
        var now = DateTimeOffset.UtcNow;
        using var rootKey = RSA.Create(2048);
        var rootRequest = new CertificateRequest("CN=Root pathLen 0", rootKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        rootRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 0, true));
        using var root = rootRequest.CreateSelfSigned(now.AddDays(-1), now.AddYears(1));
        using var caKey = RSA.Create(2048);
        var caRequest = new CertificateRequest("CN=CA below", caKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        caRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        using var ca = caRequest.Create(root, now.AddDays(-1), now.AddMonths(6), [1]);
        using var caWithKey = ca.CopyWithPrivateKey(caKey);
        using var leafKey = RSA.Create(2048);
        var leafRequest = new CertificateRequest("CN=Leaf", leafKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var leaf = leafRequest.Create(caWithKey, now.AddDays(-1), now.AddMonths(3), [2]);

        CertificateChecks.PathLengthsRespected([leaf, ca, root]).ShouldBeFalse();
    }

    [Fact]
    public void NoRevAvailCompliant_OnACa_IsFalse()
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=CA with noRevAvail", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(new X509Extension(CertificateChecks.NoRevocationAvailable, [0x05, 0x00], false));
        using var ca = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

        CertificateChecks.NoRevAvailCompliant(ca).ShouldBeFalse();
    }

    [Fact]
    public void SubjectValues_ReadsTheAttribute()
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=Ana, O=Org, C=BR", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

        CertificateChecks.SubjectValues(certificate, CertificateChecks.SubjectAttributes["Country"]).ShouldBe(["BR"]);
        CertificateChecks.SubjectValues(certificate, CertificateChecks.SubjectAttributes["OrganizationName"]).ShouldBe(["Org"]);
    }

    public void Dispose() => _pki.Dispose();
}

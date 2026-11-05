using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Shouldly;
using Xunit;
using SimpleSign.Core.Revocation;

namespace SimpleSign.Core.Tests.Revocation;

/// <summary>CRL evaluation at a point in time (revocation date and CRL validity window).</summary>
[Trait("Category", "Unit")]
public sealed class CrlEvaluatorTests : IDisposable
{
    private static readonly DateTimeOffset At = new(2025, 6, 1, 12, 0, 0, TimeSpan.Zero);
    private readonly X509Certificate2 _ca;
    private readonly X509Certificate2 _leaf;

    public CrlEvaluatorTests()
    {
        _ca = CreateCa("CN=Test CA");
        using var key = RSA.Create(2048);
        var req = new CertificateRequest("CN=Leaf", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        _leaf = req.Create(_ca, At.AddYears(-1), At.AddYears(1), [0x42]);
    }

    public void Dispose()
    {
        _ca.Dispose();
        _leaf.Dispose();
    }

    [Fact]
    public void Evaluate_NotListed_IsGood() =>
        CrlEvaluator.Evaluate(_leaf, Crl(_ca, At.AddDays(-1), At.AddDays(6)), _ca, At).ShouldBe(CrlStatus.Good);

    [Fact]
    public void Evaluate_RevokedBeforeTime_IsRevoked() =>
        CrlEvaluator.Evaluate(_leaf, Crl(_ca, At.AddDays(-1), At.AddDays(6), At.AddDays(-2)), _ca, At).ShouldBe(CrlStatus.Revoked);

    [Fact]
    public void Evaluate_RevokedAfterTime_IsGood() =>
        CrlEvaluator.Evaluate(_leaf, Crl(_ca, At.AddDays(30), At.AddDays(37), At.AddDays(10)), _ca, At).ShouldBe(CrlStatus.Good);

    [Fact]
    public void Evaluate_IssuedAfterTime_Covers() =>
        CrlEvaluator.Evaluate(_leaf, Crl(_ca, At.AddYears(1), At.AddYears(1).AddDays(7)), _ca, At).ShouldBe(CrlStatus.Good);

    [Fact]
    public void Evaluate_ExpiredBeforeTime_IsNotApplicable() =>
        CrlEvaluator.Evaluate(_leaf, Crl(_ca, At.AddDays(-10), At.AddDays(-3)), _ca, At).ShouldBe(CrlStatus.NotApplicable);

    [Fact]
    public void Evaluate_SignedByAnotherKey_IsNotApplicable()
    {
        using var impostor = CreateCa("CN=Test CA");

        CrlEvaluator.Evaluate(_leaf, Crl(impostor, At.AddDays(-1), At.AddDays(6), At.AddDays(-2)), _ca, At)
            .ShouldBe(CrlStatus.NotApplicable);
    }

    [Fact]
    public void Evaluate_Garbage_IsNotApplicable() =>
        CrlEvaluator.Evaluate(_leaf, [0x30, 0x03, 0x02, 0x01, 0x00], _ca, At).ShouldBe(CrlStatus.NotApplicable);

    private byte[] Crl(X509Certificate2 issuer, DateTimeOffset thisUpdate, DateTimeOffset nextUpdate, DateTimeOffset? revokedAt = null)
    {
        var builder = new CertificateRevocationListBuilder();
        if (revokedAt is { } at)
        {
            builder.AddEntry(_leaf, at);
        }

        return builder.Build(issuer, BigInteger.One, nextUpdate, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1, thisUpdate);
    }

    private static X509Certificate2 CreateCa(string name)
    {
        using var key = RSA.Create(2048);
        var req = new CertificateRequest(name, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        req.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(req.PublicKey, false));
        return req.CreateSelfSigned(At.AddYears(-5), At.AddYears(5));
    }
}

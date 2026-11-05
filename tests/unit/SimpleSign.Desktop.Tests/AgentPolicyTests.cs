using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Shouldly;
using SimpleSign.Desktop.Agent;

namespace SimpleSign.Desktop.Tests;

public sealed class AgentPolicyTests
{
    [Theory]
    [InlineData("https://Portal.Example.com", "https://portal.example.com")]
    [InlineData("https://portal.example.com:443", "https://portal.example.com")]
    [InlineData("http://localhost:5173", "http://localhost:5173")]
    [InlineData("null", null)]
    [InlineData("file://", null)]
    [InlineData("https://portal.example.com/path", null)]
    [InlineData("https://user@portal.example.com", null)]
    [InlineData("ftp://portal.example.com", null)]
    public void Normalize_OnlyExactHttpOrigins(string origin, string? expected) =>
        OriginPolicy.Normalize(origin).ShouldBe(expected);

    [Fact]
    public void RateLimiter_BlocksAfterLimitUntilTheWindowEnds()
    {
        var time = new ManualTime();
        var limiter = new RateLimiter(2, TimeSpan.FromMinutes(1), time);

        limiter.TryAcquire("a").ShouldBeTrue();
        limiter.TryAcquire("a").ShouldBeTrue();
        limiter.TryAcquire("a").ShouldBeFalse();
        limiter.TryAcquire("b").ShouldBeTrue();
        time.Advance(TimeSpan.FromMinutes(1));
        limiter.TryAcquire("a").ShouldBeTrue();
    }

    [Fact]
    public void DerToP1363_RoundTripsAnEcdsaSignature()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var certificate = new CertificateRequest("CN=EC", key, HashAlgorithmName.SHA256).CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddDays(1));
        byte[] data = [1, 2, 3];
        byte[] der = key.SignData(data, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);

        byte[] p1363 = AgentSigner.DerToP1363(der, certificate);

        p1363.Length.ShouldBe(64);
        key.VerifyData(data, p1363, HashAlgorithmName.SHA256).ShouldBeTrue();
    }

    private sealed class ManualTime : TimeProvider
    {
        private DateTimeOffset _now = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

        public override DateTimeOffset GetUtcNow() => _now;

        public void Advance(TimeSpan by) => _now += by;
    }
}

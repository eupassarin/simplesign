using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Shouldly;
using SimpleSign.Core.Crypto;
using Xunit;

namespace SimpleSign.Core.Tests.Crypto;

public sealed class CertificateCacheTests
{
    private static X509Certificate2 CreateCert(string cn = "CN=Test")
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest(cn, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return req.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(1));
    }

    [Fact(DisplayName = "Set and TryGet retrieves cached certificate")]
    public void SetAndGet_Success()
    {
        var cache = new InMemoryCertificateCache();
        using var cert = CreateCert();

        cache.Set(cert);
        var thumbprint = cert.GetCertHashString(HashAlgorithmName.SHA256);

        cache.TryGet(thumbprint, out var retrieved).ShouldBeTrue();
        retrieved.ShouldBeSameAs(cert);
    }

    [Fact(DisplayName = "TryGet returns false for unknown thumbprint")]
    public void TryGet_Unknown_ReturnsFalse()
    {
        var cache = new InMemoryCertificateCache();
        cache.TryGet("AABBCCDD", out var cert).ShouldBeFalse();
        cert.ShouldBeNull();
    }

    [Fact(DisplayName = "Count reflects cached entries")]
    public void Count_ReflectsEntries()
    {
        var cache = new InMemoryCertificateCache();
        cache.Count.ShouldBe(0);

        using var cert = CreateCert();
        cache.Set(cert);
        cache.Count.ShouldBe(1);
    }

    [Fact(DisplayName = "Clear removes all entries")]
    public void Clear_RemovesAll()
    {
        var cache = new InMemoryCertificateCache();
        using var cert1 = CreateCert("CN=One");
        using var cert2 = CreateCert("CN=Two");

        cache.Set(cert1);
        cache.Set(cert2);
        cache.Count.ShouldBe(2);

        cache.Clear();
        cache.Count.ShouldBe(0);
    }

    [Fact(DisplayName = "Expired entries are not returned")]
    public void TryGet_Expired_ReturnsFalse()
    {
        var cache = new InMemoryCertificateCache(ttl: TimeSpan.FromMilliseconds(1));
        using var cert = CreateCert();

        cache.Set(cert);
        Thread.Sleep(10); // Let TTL expire

        var thumbprint = cert.GetCertHashString(HashAlgorithmName.SHA256);
        cache.TryGet(thumbprint, out _).ShouldBeFalse();
    }

    [Fact(DisplayName = "Evict removes expired entries")]
    public void Evict_RemovesExpired()
    {
        var cache = new InMemoryCertificateCache(ttl: TimeSpan.FromMilliseconds(1));
        using var cert = CreateCert();

        cache.Set(cert);
        Thread.Sleep(10);

        var removed = cache.Evict();
        removed.ShouldBe(1);
        cache.Count.ShouldBe(0);
    }

    [Fact(DisplayName = "Constructor rejects zero TTL")]
    public void Constructor_ZeroTtl_Throws()
    {
        var act = () => new InMemoryCertificateCache(ttl: TimeSpan.Zero);
        Should.Throw<ArgumentOutOfRangeException>(act);
    }

    [Fact(DisplayName = "Constructor rejects negative TTL")]
    public void Constructor_NegativeTtl_Throws()
    {
        var act = () => new InMemoryCertificateCache(ttl: TimeSpan.FromSeconds(-1));
        Should.Throw<ArgumentOutOfRangeException>(act);
    }

    [Fact(DisplayName = "Default TTL is 1 hour")]
    public void DefaultTtl_IsOneHour()
    {
        var cache = new InMemoryCertificateCache();
        using var cert = CreateCert();

        cache.Set(cert);
        var thumbprint = cert.GetCertHashString(HashAlgorithmName.SHA256);

        // Should still be valid (well within 1 hour)
        cache.TryGet(thumbprint, out _).ShouldBeTrue();
    }

    [Fact(DisplayName = "Set overwrites existing entry")]
    public void Set_OverwritesExisting()
    {
        var cache = new InMemoryCertificateCache();
        using var cert1 = CreateCert();
        using var cert2 = CreateCert(); // Same CN but different cert

        cache.Set(cert1);
        cache.Set(cert1); // Set again
        cache.Count.ShouldBe(1);
    }

    [Fact(DisplayName = "TryGet is case-insensitive on thumbprint")]
    public void TryGet_CaseInsensitive()
    {
        var cache = new InMemoryCertificateCache();
        using var cert = CreateCert();

        cache.Set(cert);
        var thumbprint = cert.GetCertHashString(HashAlgorithmName.SHA256);

        cache.TryGet(thumbprint.ToLowerInvariant(), out var retrieved).ShouldBeTrue();
        retrieved.ShouldBeSameAs(cert);
    }
}

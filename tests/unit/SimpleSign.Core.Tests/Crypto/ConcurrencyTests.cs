using Shouldly;
using SimpleSign.Core.Crypto;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.Core.Tests.Crypto;

[Trait("Category", "Concurrency")]
public sealed class ConcurrencyTests
{
    [Fact(DisplayName = "InMemoryCertificateCache concurrent Set and Get — no exceptions")]
    public void InMemoryCertificateCache_ConcurrentSetAndGet_NoExceptions()
    {
        var cache = new InMemoryCertificateCache();
        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=CacheTest");
        var thumbprint = cert.GetCertHashString(System.Security.Cryptography.HashAlgorithmName.SHA256);

        var exception = Record.Exception(() =>
        {
            Parallel.For(0, 10, i =>
            {
                if (i % 2 == 0)
                {
                    cache.Set(cert);
                }
                else
                {
                    cache.TryGet(thumbprint, out _);
                }
            });
        });

        exception.ShouldBeNull();
        cache.Count.ShouldBeGreaterThanOrEqualTo(0);
    }

    [Fact(DisplayName = "InMemoryCertificateCache concurrent Set and Clear — no exceptions")]
    public void InMemoryCertificateCache_ConcurrentSetAndClear_NoExceptions()
    {
        var cache = new InMemoryCertificateCache();
        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=ClearTest");
        var certBytes = cert.Export(System.Security.Cryptography.X509Certificates.X509ContentType.Pfx);

        var exception = Record.Exception(() =>
        {
            Parallel.For(0, 10, i =>
            {
                if (i % 3 == 0)
                {
                    cache.Clear();
                }
                else
                {
                    // Use a fresh cert instance per Set to avoid disposing a shared object
                    using var freshCert = System.Security.Cryptography.X509Certificates.X509CertificateLoader.LoadPkcs12(certBytes, null);
                    cache.Set(freshCert);
                }
            });
        });

        exception.ShouldBeNull();
    }
}

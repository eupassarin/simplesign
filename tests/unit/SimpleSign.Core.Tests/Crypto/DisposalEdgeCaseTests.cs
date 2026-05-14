using System.Security.Cryptography.X509Certificates;
using FluentAssertions;
using SimpleSign.Core.Crypto;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.Core.Tests.Crypto;

public sealed class DisposalEdgeCaseTests
{
    private static X509Certificate2 CreateExportableCert(string cn = "CN=DisposalTest")
        => TestCertificateFactory.CreateSelfSignedCert(cn);

    [Fact(DisplayName = "SystemCertificateStore: Double Dispose does not throw")]
    public void SystemCertificateStore_DoubleDispose_DoesNotThrow()
    {
        using var store = new SystemCertificateStore(StoreName.Root, StoreLocation.CurrentUser);

        var act = () =>
        {
            store.Dispose();
            store.Dispose();
        };

        act.Should().NotThrow();
    }

    [Fact(DisplayName = "FileCertificateStore: Double Dispose does not throw")]
    public void FileCertificateStore_DoubleDispose_DoesNotThrow()
    {
        var tempFile = Path.Combine(Path.GetTempPath(), $"test-store-{Guid.NewGuid()}.pfx");
        try
        {
            // Create PFX bytes directly from a fresh self-signed cert (avoid macOS re-export issues)
            using var rsa = System.Security.Cryptography.RSA.Create(2048);
            var req = new System.Security.Cryptography.X509Certificates.CertificateRequest(
                "CN=DisposalTest", rsa,
                System.Security.Cryptography.HashAlgorithmName.SHA256,
                System.Security.Cryptography.RSASignaturePadding.Pkcs1);
            using var tmpCert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(1));
            File.WriteAllBytes(tempFile, tmpCert.Export(X509ContentType.Pfx, "test"));

            using var store = new FileCertificateStore(tempFile, "test");

            var act = () =>
            {
                store.Dispose();
                store.Dispose();
            };

            act.Should().NotThrow();
        }
        finally
        {
            File.Delete(tempFile);
        }
    }

    [Fact(DisplayName = "InMemoryCertificateCache: Clear after heavy usage results in Count == 0")]
    public void InMemoryCertificateCache_ClearAfterHeavyUsage_CountIsZero()
    {
        var cache = new InMemoryCertificateCache();

        // Add many entries
        for (int i = 0; i < 100; i++)
        {
            using var cert = CreateExportableCert($"CN=Test{i}");
            cache.Set(cert);
        }

        cache.Count.Should().BeGreaterThan(0);

        cache.Clear();

        cache.Count.Should().Be(0);
    }
}

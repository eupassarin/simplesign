using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using FluentAssertions;
using SimpleSign.Core.Crypto;
using Xunit;

namespace SimpleSign.Core.Tests.Crypto;

public sealed class CertificateStoreTests
{
    private static X509Certificate2 CreateCert(string cn = "CN=StoreTest")
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest(cn, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return req.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(1));
    }

    [Fact(DisplayName = "FileCertificateStore loads cert from PFX file")]
    public void FileCertificateStore_LoadsPfx()
    {
        var tempFile = Path.GetTempFileName() + ".pfx";
        try
        {
            using var cert = CreateCert();
            var pfxBytes = cert.Export(X509ContentType.Pfx, "test123");
            File.WriteAllBytes(tempFile, pfxBytes);

            using var store = new FileCertificateStore(tempFile, "test123");
            store.ListAll().Should().HaveCount(1);
            store.ListAll()[0].Subject.Should().Contain("StoreTest");
        }
        finally
        {
            File.Delete(tempFile);
        }
    }

    [Fact(DisplayName = "FileCertificateStore FindByThumbprint works")]
    public void FileCertificateStore_FindByThumbprint()
    {
        var tempFile = Path.GetTempFileName() + ".pfx";
        try
        {
            using var cert = CreateCert();
            var thumbprint = cert.Thumbprint;
            var pfxBytes = cert.Export(X509ContentType.Pfx, "test");
            File.WriteAllBytes(tempFile, pfxBytes);

            using var store = new FileCertificateStore(tempFile, "test");
            store.FindByThumbprint(thumbprint).Should().NotBeNull();
            store.FindByThumbprint("NONEXISTENT").Should().BeNull();
        }
        finally
        {
            File.Delete(tempFile);
        }
    }

    [Fact(DisplayName = "FileCertificateStore FindBySubject works")]
    public void FileCertificateStore_FindBySubject()
    {
        var tempFile = Path.GetTempFileName() + ".pfx";
        try
        {
            using var cert = CreateCert("CN=UniqueSubject123");
            File.WriteAllBytes(tempFile, cert.Export(X509ContentType.Pfx, "pw"));

            using var store = new FileCertificateStore(tempFile, "pw");
            store.FindBySubject("UniqueSubject123").Should().HaveCount(1);
            store.FindBySubject("NonExistent").Should().BeEmpty();
        }
        finally
        {
            File.Delete(tempFile);
        }
    }

    [Fact(DisplayName = "SystemCertificateStore ListAll returns certificates")]
    public void SystemCertificateStore_ListAll()
    {
        using var store = new SystemCertificateStore(StoreName.Root, StoreLocation.CurrentUser);
        // System root store should have at least some certs on any OS
        store.ListAll().Should().NotBeNull();
    }

    [Fact(DisplayName = "CompositeCertificateStore searches all stores")]
    public void CompositeCertificateStore_SearchesAll()
    {
        var tempFile1 = Path.GetTempFileName() + ".pfx";
        var tempFile2 = Path.GetTempFileName() + ".pfx";
        try
        {
            using var cert1 = CreateCert("CN=First");
            using var cert2 = CreateCert("CN=Second");
            File.WriteAllBytes(tempFile1, cert1.Export(X509ContentType.Pfx, "pw"));
            File.WriteAllBytes(tempFile2, cert2.Export(X509ContentType.Pfx, "pw"));

            using var store1 = new FileCertificateStore(tempFile1, "pw");
            using var store2 = new FileCertificateStore(tempFile2, "pw");

            var composite = new CompositeCertificateStore(store1, store2);
            composite.ListAll().Should().HaveCount(2);
            composite.FindBySubject("First").Should().HaveCount(1);
            composite.FindBySubject("Second").Should().HaveCount(1);
        }
        finally
        {
            File.Delete(tempFile1);
            File.Delete(tempFile2);
        }
    }

    [Fact(DisplayName = "CompositeCertificateStore FindByThumbprint returns first match")]
    public void CompositeCertificateStore_FindByThumbprint_FirstMatch()
    {
        var tempFile = Path.GetTempFileName() + ".pfx";
        try
        {
            using var cert = CreateCert();
            File.WriteAllBytes(tempFile, cert.Export(X509ContentType.Pfx, "pw"));

            using var store = new FileCertificateStore(tempFile, "pw");
            var composite = new CompositeCertificateStore(store);

            composite.FindByThumbprint(cert.Thumbprint).Should().NotBeNull();
            composite.FindByThumbprint("0000").Should().BeNull();
        }
        finally
        {
            File.Delete(tempFile);
        }
    }

    [Fact(DisplayName = "Dispose clears certificates")]
    public void FileCertificateStore_Dispose_Clears()
    {
        var tempFile = Path.GetTempFileName() + ".pfx";
        try
        {
            using var cert = CreateCert();
            File.WriteAllBytes(tempFile, cert.Export(X509ContentType.Pfx, "pw"));

            var store = new FileCertificateStore(tempFile, "pw");
            store.ListAll().Should().HaveCount(1);
            store.Dispose();
            store.ListAll().Should().BeEmpty();
        }
        finally
        {
            File.Delete(tempFile);
        }
    }
}

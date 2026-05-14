using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using FluentAssertions;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Inspection;

using Xunit;

namespace SimpleSign.Core.Tests.Inspection;

public sealed class CertificateInfoTests
{
    [Fact(DisplayName = "From extracts Subject and Issuer")]
    public void From_SelfSignedCert_ExtractsSubjectAndIssuer()
    {
        using X509Certificate2 cert = CreateCert("CN=Test User, O=Org, C=BR");
        CertificateInfo certificateInfo = CertificateInfo.From(cert);
        certificateInfo.Subject.Should().Contain("CN=Test User", "");
        certificateInfo.Subject.Should().Contain("O=Org", "");
        certificateInfo.Issuer.Should().Contain("CN=Test User", "");
    }

    [Fact(DisplayName = "From extracts serial number")]
    public void From_SelfSignedCert_ExtractsSerialNumber()
    {
        using X509Certificate2 cert = CreateCert();
        CertificateInfo certificateInfo = CertificateInfo.From(cert);
        certificateInfo.SerialNumber.Should().NotBeNullOrEmpty("");
    }

    [Fact(DisplayName = "From extracts RSA key info")]
    public void From_RsaCert_ExtractsKeyInfo()
    {
        using X509Certificate2 cert = CreateCert();
        CertificateInfo certificateInfo = CertificateInfo.From(cert);
        certificateInfo.KeyAlgorithm.Should().Be("RSA", "");
        certificateInfo.KeySizeBits.Should().Be(2048, "");
    }

    [Fact(DisplayName = "From extracts ECDSA key info")]
    public void From_EcdsaCert_ExtractsKeyInfo()
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        CertificateRequest certificateRequest = new CertificateRequest("CN=ECDSA Test", key, HashAlgorithmName.SHA256);
        X509Certificate2 x509Certificate = certificateRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1.0), DateTimeOffset.UtcNow.AddYears(1));
        using X509Certificate2 cert = CertificateLoader.LoadPkcs12(x509Certificate.Export(X509ContentType.Pfx, "test-export"), "test-export");
        CertificateInfo certificateInfo = CertificateInfo.From(cert);
        certificateInfo.KeyAlgorithm.Should().Be("ECDSA", "");
        certificateInfo.KeySizeBits.Should().Be(256, "");
    }

    [Fact(DisplayName = "From extracts key usages")]
    public void From_CertWithKeyUsage_ExtractsUsages()
    {
        using RSA key = RSA.Create(2048);
        CertificateRequest certificateRequest = new CertificateRequest("CN=KeyUsage Test", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        certificateRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.NonRepudiation | X509KeyUsageFlags.DigitalSignature, critical: false));
        X509Certificate2 x509Certificate = certificateRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1.0), DateTimeOffset.UtcNow.AddYears(1));
        using X509Certificate2 cert = CertificateLoader.LoadPkcs12(x509Certificate.Export(X509ContentType.Pfx, "test-export"), "test-export");
        CertificateInfo certificateInfo = CertificateInfo.From(cert);
        certificateInfo.KeyUsages.Should().Contain("DigitalSignature", "");
        certificateInfo.KeyUsages.Should().Contain("NonRepudiation", "");
        certificateInfo.HasNonRepudiation.Should().BeTrue("");
    }

    [Fact(DisplayName = "From extracts validity dates")]
    public void From_Cert_ExtractsValidityDates()
    {
        using X509Certificate2 cert = CreateCert();
        CertificateInfo certificateInfo = CertificateInfo.From(cert);
        certificateInfo.NotBefore.Should().BeBefore(DateTime.UtcNow, "");
        certificateInfo.NotAfter.Should().BeAfter(DateTime.UtcNow, "");
        certificateInfo.IsExpired.Should().BeFalse("");
    }

    [Fact(DisplayName = "From extracts thumbprint")]
    public void From_Cert_ExtractsThumbprint()
    {
        using X509Certificate2 cert = CreateCert();
        CertificateInfo certificateInfo = CertificateInfo.From(cert);
        certificateInfo.Thumbprint.Should().NotBeNullOrEmpty("");
        certificateInfo.Thumbprint.Should().HaveLength(40, "");
    }

    [Fact(DisplayName = "From keeps reference to original certificate")]
    public void From_Cert_KeepsReference()
    {
        using X509Certificate2 x509Certificate = CreateCert();
        CertificateInfo certificateInfo = CertificateInfo.From(x509Certificate);
        certificateInfo.Certificate.Should().BeSameAs(x509Certificate, "");
    }

    [Fact(DisplayName = "ToString shows subject and expiry")]
    public void ToString_ShowsSubjectAndExpiry()
    {
        using X509Certificate2 cert = CreateCert("CN=Display Test");
        CertificateInfo certificateInfo = CertificateInfo.From(cert);
        certificateInfo.ToString().Should().Contain("Display Test", "");
        certificateInfo.ToString().Should().Contain("expires", "");
    }

    private static X509Certificate2 CreateCert(string subject = "CN=Test, O=Tests")
    {
        using RSA key = RSA.Create(2048);
        CertificateRequest certificateRequest = new CertificateRequest(subject, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        certificateRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: false));
        X509Certificate2 x509Certificate = certificateRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1.0), DateTimeOffset.UtcNow.AddYears(1));
        return CertificateLoader.LoadPkcs12(x509Certificate.Export(X509ContentType.Pfx, "test-export"), "test-export");
    }
}

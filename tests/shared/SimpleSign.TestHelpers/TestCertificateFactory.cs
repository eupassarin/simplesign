using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SimpleSign.Core.Crypto;

namespace SimpleSign.TestHelpers;

/// <summary>
/// Reusable certificate factory for unit tests.
/// Creates self-signed CA + leaf certificates in memory.
/// </summary>
public static class TestCertificateFactory
{
    public static X509Certificate2 CreateCaCert(string subject = "CN=Test CA, O=SimpleSign Tests")
    {
        using RSA key = RSA.Create(2048);
        CertificateRequest certificateRequest = new CertificateRequest(subject, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        certificateRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(certificateAuthority: true, hasPathLengthConstraint: false, 0, critical: true));
        certificateRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.CrlSign | X509KeyUsageFlags.KeyCertSign, critical: true));
        X509Certificate2 x509Certificate = certificateRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1.0), DateTimeOffset.UtcNow.AddYears(10));
        return ExportAndReload(x509Certificate);
    }

    public static X509Certificate2 CreateLeafCert(X509Certificate2 issuer, string subject = "CN=Test Leaf, O=SimpleSign Tests", byte[]? serialNumber = null)
    {
        using RSA key = RSA.Create(2048);
        CertificateRequest certificateRequest = new CertificateRequest(subject, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        certificateRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: false));
        X509Certificate2 x509Certificate = certificateRequest.Create(issuer, DateTimeOffset.UtcNow.AddDays(-1.0), DateTimeOffset.UtcNow.AddYears(1), serialNumber ?? new byte[3] { 1, 2, 3 });
        return CertificateLoader.LoadCertificate(x509Certificate.RawData);
    }

    public static X509Certificate2 CreateSelfSignedCert(string subject = "CN=Self Signed, O=Tests")
    {
        using RSA key = RSA.Create(2048);
        CertificateRequest certificateRequest = new CertificateRequest(subject, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        certificateRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: false));
        X509Certificate2 x509Certificate = certificateRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1.0), DateTimeOffset.UtcNow.AddYears(1));
        return ExportAndReload(x509Certificate);
    }

    /// <summary>
    /// Creates a self-signed certificate using ECDSA with the specified curve.
    /// </summary>
    public static X509Certificate2 CreateEcdsaCert(ECCurve? curve = null, string subject = "CN=ECDSA Signer, O=Tests")
    {
        using ECDsa key = ECDsa.Create(curve ?? ECCurve.NamedCurves.nistP256);
        CertificateRequest certificateRequest = new CertificateRequest(subject, key, HashAlgorithmName.SHA256);
        certificateRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: false));
        X509Certificate2 x509Certificate = certificateRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1.0), DateTimeOffset.UtcNow.AddYears(1));
        return ExportAndReload(x509Certificate);
    }

    /// <summary>
    /// Creates a self-signed certificate with a specific RSA key size and hash algorithm.
    /// </summary>
    public static X509Certificate2 CreateSelfSignedCert(string subject, int keySize, HashAlgorithmName hashAlgorithm)
    {
        using RSA key = RSA.Create(keySize);
        CertificateRequest certificateRequest = new CertificateRequest(subject, key, hashAlgorithm, RSASignaturePadding.Pkcs1);
        certificateRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: false));
        X509Certificate2 x509Certificate = certificateRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1.0), DateTimeOffset.UtcNow.AddYears(1));
        return ExportAndReload(x509Certificate);
    }

    private static X509Certificate2 ExportAndReload(X509Certificate2 cert)
    {
        const string password = "test-export";
        var pfx = cert.Export(X509ContentType.Pfx, password);
#pragma warning disable SYSLIB0057
        return new X509Certificate2(pfx, password, X509KeyStorageFlags.Exportable);
#pragma warning restore SYSLIB0057
    }
}

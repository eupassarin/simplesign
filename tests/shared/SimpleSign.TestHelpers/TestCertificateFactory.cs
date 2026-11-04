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
        X509Certificate2 x509Certificate = certificateRequest.Create(issuer, DateTimeOffset.UtcNow.AddDays(-1.0), DateTimeOffset.UtcNow.AddYears(1), serialNumber ?? [1, 2, 3]);
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

    /// <summary>
    /// Creates a self-signed certificate using RSASSA-PSS padding. The resulting
    /// certificate's <c>SignatureAlgorithm.Value</c> is <c>id-RSASSA-PSS</c>
    /// (<c>1.2.840.113549.1.1.10</c>) and its <c>RawData</c> carries the
    /// <c>RSASSA-PSS-params</c> structure declaring the specified hash.
    /// </summary>
    /// <param name="hashAlgorithm">Hash to embed in the PSS params. Default: SHA-256.</param>
    /// <param name="keySize">RSA key size in bits. Default: 2048.</param>
    /// <param name="subject">X.500 subject name.</param>
    public static X509Certificate2 CreatePssSelfSignedCert(
        HashAlgorithmName? hashAlgorithm = null,
        int keySize = 2048,
        string subject = "CN=PSS Signer, O=Tests")
    {
        HashAlgorithmName hash = hashAlgorithm ?? HashAlgorithmName.SHA256;
        using RSA key = RSA.Create(keySize);
        RSASignaturePadding padding = RSASignaturePadding.Pss;
        CertificateRequest certificateRequest = new CertificateRequest(subject, key, hash, padding);
        certificateRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: false));
        X509Certificate2 x509Certificate = certificateRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1.0), DateTimeOffset.UtcNow.AddYears(1));
        return ExportAndReload(x509Certificate);
    }

    /// <summary>
    /// Attempts to create a self-signed EdDSA (Ed25519) certificate.
    /// Returns <see langword="null"/> if the platform or runtime does not support EdDSA.
    /// </summary>
    /// <param name="subject">X.500 subject name.</param>
    public static X509Certificate2? TryCreateEdDsaCert(string subject = "CN=EdDSA Signer, O=Tests")
    {
        X509Certificate2? result = null;
#if NET9_0_OR_GREATER
        try
        {
            using ECDsa key = ECDsa.Create(ECCurve.CreateFromFriendlyName("Ed25519"));
            var req = new CertificateRequest(subject, key, HashAlgorithmName.SHA256);
            req.CertificateExtensions.Add(
                new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: false));
            var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
            result = ExportAndReload(cert);
        }
        catch (PlatformNotSupportedException)
        {
        }
        catch (CryptographicException)
        {
        }
#endif
        return result;
    }

    /// <summary>
    /// Writes a PKCS#12 file holding a leaf certificate with its private key and the
    /// (public) CA certificate that issued it. Returns public copies of both.
    /// </summary>
    public static (X509Certificate2 Ca, X509Certificate2 Leaf) WritePfxWithChain(string path, string password)
    {
        using RSA caKey = RSA.Create(2048);
        var caRequest = new CertificateRequest("CN=Pfx Test CA, O=SimpleSign Tests", caKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        caRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(certificateAuthority: true, hasPathLengthConstraint: false, 0, critical: true));
        caRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.CrlSign | X509KeyUsageFlags.KeyCertSign, critical: true));
        using X509Certificate2 ca = caRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(10));

        using RSA leafKey = RSA.Create(2048);
        var leafRequest = new CertificateRequest("CN=Pfx Test Signer, O=SimpleSign Tests", leafKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        leafRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: false));
        using X509Certificate2 leafPublic = leafRequest.Create(ca, DateTimeOffset.UtcNow.AddHours(-1), DateTimeOffset.UtcNow.AddYears(1), [4, 5, 6]);
        using X509Certificate2 leaf = leafPublic.CopyWithPrivateKey(leafKey);

        X509Certificate2 caPublic = CertificateLoader.LoadCertificate(ca.RawData);
        var collection = new X509Certificate2Collection { leaf, caPublic };
        File.WriteAllBytes(path, collection.Export(X509ContentType.Pkcs12, password)!);
        return (caPublic, CertificateLoader.LoadCertificate(leaf.RawData));
    }

    private static X509Certificate2 ExportAndReload(X509Certificate2 cert)
    {
        const string password = "test-export";
        var pfx = cert.Export(X509ContentType.Pfx, password);
#pragma warning disable SYSLIB0057
        // EphemeralKeySet keeps keys in memory (not persisted to Windows/Linux key store).
        // macOS does not support EphemeralKeySet — fall back to Exportable only.
        var flags = X509KeyStorageFlags.Exportable;
        if (!OperatingSystem.IsMacOS())
            flags |= X509KeyStorageFlags.EphemeralKeySet;
        return new X509Certificate2(pfx, password, flags);
#pragma warning restore SYSLIB0057
    }
}

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace SimpleSign.TestHelpers;

/// <summary>
/// Signing certificates that break one rule each, for the tests of the checks made before signing:
/// no signing key usage, a weak RSA key, an expired intermediate under a valid leaf.
/// </summary>
public static class ConstraintTestCertificates
{
    /// <summary>A self-signed certificate with a private key and the given key usage (none when null).</summary>
    public static X509Certificate2 SelfSigned(X509KeyUsageFlags? keyUsage, int rsaKeySize = 2048, string subject = "CN=Constraint Signer")
    {
        using var key = RSA.Create(rsaKeySize);
        var request = new CertificateRequest(subject, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        if (keyUsage is { } usage)
        {
            request.CertificateExtensions.Add(new X509KeyUsageExtension(usage, critical: true));
        }

        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        return Reload(certificate);
    }

    /// <summary>
    /// A valid leaf (with its private key) under an intermediate CA that expired yesterday, under a valid root.
    /// The caller disposes the three certificates.
    /// </summary>
    public static (X509Certificate2 Leaf, X509Certificate2 Intermediate, X509Certificate2 Root) ExpiredIntermediateChain()
    {
        var now = DateTimeOffset.UtcNow;
        using var rootKey = RSA.Create(2048);
        var rootRequest = new CertificateRequest("CN=Constraint Root", rootKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        rootRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        rootRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        var root = rootRequest.CreateSelfSigned(now.AddYears(-5), now.AddYears(5));

        using var intermediateKey = RSA.Create(2048);
        var intermediateRequest = new CertificateRequest("CN=Constraint Expired Intermediate", intermediateKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        intermediateRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        intermediateRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        var intermediate = intermediateRequest.Create(root.SubjectName, X509SignatureGenerator.CreateForRSA(rootKey, RSASignaturePadding.Pkcs1),
            now.AddYears(-3), now.AddDays(-1), [0x11, 0x22]);

        using var leafKey = RSA.Create(2048);
        var leafRequest = new CertificateRequest("CN=Constraint Leaf", leafKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        leafRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation, true));
        using var leaf = leafRequest.Create(intermediate.SubjectName, X509SignatureGenerator.CreateForRSA(intermediateKey, RSASignaturePadding.Pkcs1),
            now.AddDays(-10), now.AddYears(1), [0x33, 0x44]);
        using var leafWithKey = leaf.CopyWithPrivateKey(leafKey);
        return (Reload(leafWithKey), intermediate, root);
    }

    // Exportable, unlike the library's own loading: tests write these certificates out as PFX files.
    private static X509Certificate2 Reload(X509Certificate2 certificate) =>
#if NET9_0_OR_GREATER
        X509CertificateLoader.LoadPkcs12(certificate.Export(X509ContentType.Pfx, "constraint"), "constraint", X509KeyStorageFlags.Exportable);
#else
        new(certificate.Export(X509ContentType.Pfx, "constraint"), "constraint", X509KeyStorageFlags.Exportable);
#endif
}

using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SimpleSign.Core.Crypto;

namespace SimpleSign.TestHelpers;

/// <summary>
/// Three-tier in-memory PKI: Root CA → Intermediate CA → Leaf signer.
/// Built specifically to exercise <c>ChainValidator</c>, <c>RevocationChecker</c>,
/// and PAdES-LTV paths that single self-signed certs short-circuit.
/// </summary>
/// <remarks>
/// Each cert is exported to PFX and re-imported so the private key is fully
/// usable on macOS, Windows, and Linux. Use <see cref="Dispose"/> to release
/// the underlying X509Certificate2 instances.
/// </remarks>
public sealed class SyntheticPki : IDisposable
{
    private readonly RSA _rootKey;
    private readonly RSA _intermediateKey;
    private readonly RSA _leafKey;

    /// <summary>Self-signed Root CA certificate (10y validity).</summary>
    public X509Certificate2 RootCa { get; }

    /// <summary>Intermediate CA signed by the Root (5y validity).</summary>
    public X509Certificate2 IntermediateCa { get; }

    /// <summary>End-entity leaf signed by the Intermediate (1y validity, has private key).</summary>
    public X509Certificate2 Leaf { get; }

    /// <summary>Optional CRL Distribution Point URL embedded in Intermediate and Leaf.</summary>
    public string? CrlDistributionPoint { get; }

    /// <summary>Optional OCSP responder URL embedded in Intermediate and Leaf.</summary>
    public string? OcspResponder { get; }

    public SyntheticPki(string? crlDistributionPoint = null, string? ocspResponder = null)
    {
        CrlDistributionPoint = crlDistributionPoint;
        OcspResponder = ocspResponder;

        _rootKey = RSA.Create(2048);
        _intermediateKey = RSA.Create(2048);
        _leafKey = RSA.Create(2048);

        var notBefore = DateTimeOffset.UtcNow.AddDays(-1);

        RootCa = BuildRoot(_rootKey, notBefore, notBefore.AddYears(10));
        IntermediateCa = BuildIntermediate(_intermediateKey, RootCa, _rootKey, notBefore, notBefore.AddYears(5));
        Leaf = BuildLeaf(_leafKey, IntermediateCa, _intermediateKey, notBefore, notBefore.AddYears(1));
    }

    private static X509Certificate2 BuildRoot(RSA key, DateTimeOffset notBefore, DateTimeOffset notAfter)
    {
        var req = new CertificateRequest(
            "CN=SimpleSign Synthetic Root CA, O=SimpleSign Tests",
            key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(certificateAuthority: true, hasPathLengthConstraint: true, pathLengthConstraint: 1, critical: true));
        req.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, critical: true));
        req.CertificateExtensions.Add(
            new X509SubjectKeyIdentifierExtension(req.PublicKey, critical: false));
        var cert = req.CreateSelfSigned(notBefore, notAfter);
        return ExportAndReload(cert);
    }

    private X509Certificate2 BuildIntermediate(RSA key, X509Certificate2 issuer, RSA issuerKey, DateTimeOffset notBefore, DateTimeOffset notAfter)
    {
        var req = new CertificateRequest(
            "CN=SimpleSign Synthetic Intermediate CA, O=SimpleSign Tests",
            key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(certificateAuthority: true, hasPathLengthConstraint: true, pathLengthConstraint: 0, critical: true));
        req.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, critical: true));
        req.CertificateExtensions.Add(
            new X509SubjectKeyIdentifierExtension(req.PublicKey, critical: false));
        AddAuthorityKeyIdentifier(req, issuer);
        AddCrlAndOcspExtensions(req);

        // Use a unique serial — required so revocation tests can distinguish certs.
        byte[] serial = RandomNumberGenerator.GetBytes(16);
        serial[0] &= 0x7F; // ensure positive integer
        var cert = req.Create(issuer, notBefore, notAfter, serial);
        // Attach the private key to the resulting cert before exporting.
        var withKey = cert.CopyWithPrivateKey(key);
        return ExportAndReload(withKey);
    }

    private X509Certificate2 BuildLeaf(RSA key, X509Certificate2 issuer, RSA issuerKey, DateTimeOffset notBefore, DateTimeOffset notAfter)
    {
        var req = new CertificateRequest(
            "CN=SimpleSign Synthetic Signer, O=SimpleSign Tests",
            key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(certificateAuthority: false, hasPathLengthConstraint: false, pathLengthConstraint: 0, critical: true));
        req.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation, critical: true));
        req.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension(
                new OidCollection { new Oid("1.3.6.1.5.5.7.3.4") /* email protection — accepted by most validators */ },
                critical: false));
        req.CertificateExtensions.Add(
            new X509SubjectKeyIdentifierExtension(req.PublicKey, critical: false));
        AddAuthorityKeyIdentifier(req, issuer);
        AddCrlAndOcspExtensions(req);

        byte[] serial = RandomNumberGenerator.GetBytes(16);
        serial[0] &= 0x7F;
        var cert = req.Create(issuer, notBefore, notAfter, serial);
        var withKey = cert.CopyWithPrivateKey(key);
        return ExportAndReload(withKey);
    }

    private static void AddAuthorityKeyIdentifier(CertificateRequest req, X509Certificate2 issuer)
    {
        // Mirror the issuer's SubjectKeyIdentifier as our AuthorityKeyIdentifier.
        var ski = issuer.Extensions.OfType<X509SubjectKeyIdentifierExtension>().FirstOrDefault();
        if (ski is null)
        {
            return;
        }
        // AuthorityKeyIdentifier ::= SEQUENCE { keyIdentifier [0] OCTET STRING OPTIONAL, ... }
        byte[] keyIdBytes = Convert.FromHexString(ski.SubjectKeyIdentifier!);
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            writer.WriteOctetString(keyIdBytes, new Asn1Tag(TagClass.ContextSpecific, 0));
        }
        req.CertificateExtensions.Add(new X509Extension("2.5.29.35", writer.Encode(), critical: false));
    }

    private void AddCrlAndOcspExtensions(CertificateRequest req)
    {
        if (CrlDistributionPoint is not null)
        {
            req.CertificateExtensions.Add(BuildCrlDistributionPointExtension(CrlDistributionPoint));
        }
        if (OcspResponder is not null)
        {
            req.CertificateExtensions.Add(BuildAuthorityInfoAccessExtension(OcspResponder));
        }
    }

    private static X509Extension BuildCrlDistributionPointExtension(string url)
    {
        // CRLDistributionPoints ::= SEQUENCE OF DistributionPoint
        // DistributionPoint ::= SEQUENCE { distributionPoint [0] EXPLICIT DistributionPointName OPTIONAL, ... }
        // DistributionPointName ::= CHOICE { fullName [0] GeneralNames }
        // GeneralName ::= [6] IA5String (URI)
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            using (writer.PushSequence())
            {
                using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0)))
                {
                    using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0)))
                    {
                        writer.WriteCharacterString(UniversalTagNumber.IA5String, url, new Asn1Tag(TagClass.ContextSpecific, 6));
                    }
                }
            }
        }
        return new X509Extension("2.5.29.31", writer.Encode(), critical: false);
    }

    private static X509Extension BuildAuthorityInfoAccessExtension(string ocspUrl)
    {
        // AuthorityInfoAccessSyntax ::= SEQUENCE OF AccessDescription
        // AccessDescription ::= SEQUENCE { accessMethod OID, accessLocation GeneralName }
        // id-ad-ocsp = 1.3.6.1.5.5.7.48.1
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            using (writer.PushSequence())
            {
                writer.WriteObjectIdentifier("1.3.6.1.5.5.7.48.1");
                writer.WriteCharacterString(UniversalTagNumber.IA5String, ocspUrl, new Asn1Tag(TagClass.ContextSpecific, 6));
            }
        }
        return new X509Extension("1.3.6.1.5.5.7.1.1", writer.Encode(), critical: false);
    }

    private static X509Certificate2 ExportAndReload(X509Certificate2 cert)
    {
        const string password = "synthetic-pki";
        return CertificateLoader.LoadPkcs12(cert.Export(X509ContentType.Pfx, password), password);
    }

    /// <summary>Returns the chain as <c>[Leaf, Intermediate, Root]</c>.</summary>
    public X509Certificate2[] Chain() => [Leaf, IntermediateCa, RootCa];

    /// <summary>Returns intermediates only (for embedding in CMS extra-certs).</summary>
    public X509Certificate2[] IntermediatesAndRoot() => [IntermediateCa, RootCa];

    public void Dispose()
    {
        Leaf.Dispose();
        IntermediateCa.Dispose();
        RootCa.Dispose();
        _leafKey.Dispose();
        _intermediateKey.Dispose();
        _rootKey.Dispose();
    }
}

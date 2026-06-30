#pragma warning disable CA1707 // Identifiers should not contain underscores — XML names follow OID notation

namespace SimpleSign.Core.Constants;

/// <summary>
/// Standard URIs for XML Digital Signatures (W3C XMLDSig).
/// </summary>
public static class XmlDSigUrls
{
    #region Namespaces

    /// <summary>W3C XML Digital Signature namespace.</summary>
    public const string DsNamespace = "http://www.w3.org/2000/09/xmldsig#";

    #endregion

    #region Canonicalization Methods

    /// <summary>Exclusive Canonical XML 1.0 (omit comments).</summary>
    public const string ExcC14N = "http://www.w3.org/2001/10/xml-exc-c14n#";

    #endregion

    #region Transform Algorithms

    /// <summary>Enveloped Signature Transform — removes the Signature element before hashing.</summary>
    public const string EnvelopedSignatureTransform = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";

    #endregion

    #region Digest Methods

    // The namespace mix (xmlenc vs xmldsig-more) follows RFC 6931:
    // SHA-256/512 were defined in XML Encryption (xmlenc);
    // SHA-384 and SHA-3 variants were added later in xmldsig-more.

    /// <summary>SHA-256 digest (XML Encryption §8).</summary>
    public const string Sha256Digest = "http://www.w3.org/2001/04/xmlenc#sha256";

    /// <summary>SHA-384 digest (RFC 6931).</summary>
    public const string Sha384Digest = "http://www.w3.org/2001/04/xmldsig-more#sha384";

    /// <summary>SHA-512 digest (XML Encryption §8).</summary>
    public const string Sha512Digest = "http://www.w3.org/2001/04/xmlenc#sha512";

    /// <summary>SHA3-256 digest (RFC 6931).</summary>
    public const string Sha3_256Digest = "http://www.w3.org/2001/04/xmldsig-more#sha3-256";

    /// <summary>SHA3-384 digest (RFC 6931).</summary>
    public const string Sha3_384Digest = "http://www.w3.org/2001/04/xmldsig-more#sha3-384";

    /// <summary>SHA3-512 digest (RFC 6931).</summary>
    public const string Sha3_512Digest = "http://www.w3.org/2001/04/xmldsig-more#sha3-512";

    /// <summary>SHA-1 digest (legacy).</summary>
    public const string Sha1Digest = "http://www.w3.org/2000/09/xmldsig#sha1";

    #endregion

    #region Signature Methods

    /// <summary>RSA with SHA-256.</summary>
    public const string RsaSha256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

    /// <summary>RSA with SHA-384.</summary>
    public const string RsaSha384 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384";

    /// <summary>RSA with SHA-512.</summary>
    public const string RsaSha512 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";

    /// <summary>ECDSA with SHA-256.</summary>
    public const string EcdsaSha256 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";

    /// <summary>ECDSA with SHA-384.</summary>
    public const string EcdsaSha384 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384";

    /// <summary>ECDSA with SHA-512.</summary>
    public const string EcdsaSha512 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512";

    /// <summary>RSA with SHA-1 (legacy).</summary>
    public const string RsaSha1 = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";

    /// <summary>RSA-PSS with SHA-256.</summary>
    public const string RsaPssSha256 = "http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1";

    /// <summary>RSA-PSS with SHA-384.</summary>
    public const string RsaPssSha384 = "http://www.w3.org/2007/05/xmldsig-more#sha384-rsa-MGF1";

    /// <summary>RSA-PSS with SHA-512.</summary>
    public const string RsaPssSha512 = "http://www.w3.org/2007/05/xmldsig-more#sha512-rsa-MGF1";

    #endregion

    /// <summary>Maps a <see cref="System.Security.Cryptography.HashAlgorithmName"/> to an XMLDSig digest URI.</summary>
    public static string GetDigestUri(System.Security.Cryptography.HashAlgorithmName algorithm) =>
        algorithm.Name switch
        {
            "SHA256" => Sha256Digest,
            "SHA384" => Sha384Digest,
            "SHA512" => Sha512Digest,
            "SHA3-256" => Sha3_256Digest,
            "SHA3-384" => Sha3_384Digest,
            "SHA3-512" => Sha3_512Digest,
            "SHA1" => Sha1Digest,
            _ => throw new NotSupportedException($"Hash algorithm '{algorithm.Name}' is not supported for XMLDSig."),
        };

    /// <summary>Maps a certificate key algorithm and hash to an XMLDSig signature method URI.</summary>
    public static string GetSignatureMethodUri(
        System.Security.Cryptography.X509Certificates.X509Certificate2 certificate,
        System.Security.Cryptography.HashAlgorithmName hashAlgorithm)
    {
        var keyAlg = certificate.GetKeyAlgorithm();
        var isEcdsa = keyAlg == "1.2.840.10045.2.1";

        return (isEcdsa, hashAlgorithm.Name) switch
        {
            (true, "SHA256") => EcdsaSha256,
            (true, "SHA384") => EcdsaSha384,
            (true, "SHA512") => EcdsaSha512,
            (false, "SHA256") => RsaSha256,
            (false, "SHA384") => RsaSha384,
            (false, "SHA512") => RsaSha512,
            (false, "SHA1") => RsaSha1,
            _ => throw new NotSupportedException($"Unsupported key/hash combination: ECDSA={isEcdsa}, Hash={hashAlgorithm.Name}"),
        };
    }

    /// <summary>Maps a signature algorithm OID to an XMLDSig signature method URI.</summary>
    public static string GetSignatureMethodUri(string signatureAlgorithmOid) =>
        signatureAlgorithmOid switch
        {
            "1.2.840.113549.1.1.11" => RsaSha256,
            "1.2.840.113549.1.1.12" => RsaSha384,
            "1.2.840.113549.1.1.13" => RsaSha512,
            "1.2.840.10045.4.3.2" => EcdsaSha256,
            "1.2.840.10045.4.3.3" => EcdsaSha384,
            "1.2.840.10045.4.3.4" => EcdsaSha512,
            Oids.RsaPss => throw new NotSupportedException(
                "RSA-PSS requires a hash algorithm parameter. Use GetSignatureMethodUri(string, HashAlgorithmName) instead."),
            _ => throw new NotSupportedException($"Unsupported signature algorithm OID: {signatureAlgorithmOid}"),
        };

    /// <summary>
    /// Maps a signature algorithm OID and hash algorithm to an XMLDSig signature method URI.
    /// Supports RSA-PSS where the hash algorithm determines the specific PSS URI.
    /// </summary>
    public static string GetSignatureMethodUri(string signatureAlgorithmOid, System.Security.Cryptography.HashAlgorithmName hashAlgorithm) =>
        signatureAlgorithmOid switch
        {
            "1.2.840.113549.1.1.11" => RsaSha256,
            "1.2.840.113549.1.1.12" => RsaSha384,
            "1.2.840.113549.1.1.13" => RsaSha512,
            "1.2.840.10045.4.3.2" => EcdsaSha256,
            "1.2.840.10045.4.3.3" => EcdsaSha384,
            "1.2.840.10045.4.3.4" => EcdsaSha512,
            Oids.RsaPss => hashAlgorithm.Name switch
            {
                "SHA256" => RsaPssSha256,
                "SHA384" => RsaPssSha384,
                "SHA512" => RsaPssSha512,
                _ => throw new NotSupportedException(
                    $"RSA-PSS with hash '{hashAlgorithm.Name}' is not supported for XMLDSig."),
            },
            _ => throw new NotSupportedException(
                $"Unsupported signature algorithm OID: {signatureAlgorithmOid}"),
        };

    /// <summary>Maps an XMLDSig digest URI back to a <see cref="System.Security.Cryptography.HashAlgorithmName"/>.</summary>
    public static System.Security.Cryptography.HashAlgorithmName GetHashAlgorithmFromUri(string digestUri) =>
        digestUri switch
        {
            Sha256Digest => System.Security.Cryptography.HashAlgorithmName.SHA256,
            Sha384Digest => System.Security.Cryptography.HashAlgorithmName.SHA384,
            Sha512Digest => System.Security.Cryptography.HashAlgorithmName.SHA512,
            Sha3_256Digest => System.Security.Cryptography.HashAlgorithmName.SHA3_256,
            Sha3_384Digest => System.Security.Cryptography.HashAlgorithmName.SHA3_384,
            Sha3_512Digest => System.Security.Cryptography.HashAlgorithmName.SHA3_512,
            Sha1Digest => System.Security.Cryptography.HashAlgorithmName.SHA1,
            _ => throw new NotSupportedException($"Unknown digest URI: {digestUri}"),
        };
}

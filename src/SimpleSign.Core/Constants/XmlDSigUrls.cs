namespace SimpleSign.Core.Constants;

/// <summary>
/// Standard URIs for XML Digital Signatures (W3C XMLDSig).
/// </summary>
internal static class XmlDSigUrls
{
    #region Namespaces

    /// <summary>W3C XML Digital Signature namespace.</summary>
    internal const string DsNamespace = "http://www.w3.org/2000/09/xmldsig#";

    #endregion

    #region Canonicalization Methods

    /// <summary>Canonical XML 1.0 (omit comments).</summary>
    internal const string C14N = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";

    /// <summary>Canonical XML 1.0 (with comments).</summary>
    internal const string C14NWithComments = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments";

    /// <summary>Exclusive Canonical XML 1.0 (omit comments).</summary>
    internal const string ExcC14N = "http://www.w3.org/2001/10/xml-exc-c14n#";

    /// <summary>Exclusive Canonical XML 1.0 (with comments).</summary>
    internal const string ExcC14NWithComments = "http://www.w3.org/2001/10/xml-exc-c14n#WithComments";

    #endregion

    #region Transform Algorithms

    /// <summary>Enveloped Signature Transform — removes the Signature element before hashing.</summary>
    internal const string EnvelopedSignatureTransform = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";

    /// <summary>Base64 decoding transform.</summary>
    internal const string Base64Transform = "http://www.w3.org/2000/09/xmldsig#base64";

    #endregion

    #region Digest Methods

    /// <summary>SHA-256 digest.</summary>
    internal const string Sha256Digest = "http://www.w3.org/2001/04/xmlenc#sha256";

    /// <summary>SHA-384 digest.</summary>
    internal const string Sha384Digest = "http://www.w3.org/2001/04/xmldsig-more#sha384";

    /// <summary>SHA-512 digest.</summary>
    internal const string Sha512Digest = "http://www.w3.org/2001/04/xmlenc#sha512";

    /// <summary>SHA-1 digest (legacy).</summary>
    internal const string Sha1Digest = "http://www.w3.org/2000/09/xmldsig#sha1";

    #endregion

    #region Signature Methods

    /// <summary>RSA with SHA-256.</summary>
    internal const string RsaSha256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

    /// <summary>RSA with SHA-384.</summary>
    internal const string RsaSha384 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384";

    /// <summary>RSA with SHA-512.</summary>
    internal const string RsaSha512 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";

    /// <summary>ECDSA with SHA-256.</summary>
    internal const string EcdsaSha256 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";

    /// <summary>ECDSA with SHA-384.</summary>
    internal const string EcdsaSha384 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384";

    /// <summary>ECDSA with SHA-512.</summary>
    internal const string EcdsaSha512 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512";

    /// <summary>RSA with SHA-1 (legacy).</summary>
    internal const string RsaSha1 = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";

    #endregion

    /// <summary>Maps a <see cref="System.Security.Cryptography.HashAlgorithmName"/> to an XMLDSig digest URI.</summary>
    internal static string GetDigestUri(System.Security.Cryptography.HashAlgorithmName algorithm) =>
        algorithm.Name switch
        {
            "SHA256" => Sha256Digest,
            "SHA384" => Sha384Digest,
            "SHA512" => Sha512Digest,
            "SHA1" => Sha1Digest,
            _ => throw new NotSupportedException($"Hash algorithm '{algorithm.Name}' is not supported for XMLDSig."),
        };

    /// <summary>Maps a certificate key algorithm and hash to an XMLDSig signature method URI.</summary>
    internal static string GetSignatureMethodUri(
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

    /// <summary>Maps an XMLDSig digest URI back to a <see cref="System.Security.Cryptography.HashAlgorithmName"/>.</summary>
    internal static System.Security.Cryptography.HashAlgorithmName GetHashAlgorithmFromUri(string digestUri) =>
        digestUri switch
        {
            Sha256Digest => System.Security.Cryptography.HashAlgorithmName.SHA256,
            Sha384Digest => System.Security.Cryptography.HashAlgorithmName.SHA384,
            Sha512Digest => System.Security.Cryptography.HashAlgorithmName.SHA512,
            Sha1Digest => System.Security.Cryptography.HashAlgorithmName.SHA1,
            _ => throw new NotSupportedException($"Unknown digest URI: {digestUri}"),
        };
}

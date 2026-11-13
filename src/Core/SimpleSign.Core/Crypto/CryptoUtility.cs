using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SimpleSign.Core.Constants;

namespace SimpleSign.Core.Crypto;

/// <summary>
/// Shared cryptographic utility methods used across signature formats.
/// </summary>
internal static class CryptoUtility
{
    /// <summary>
    /// Configures the common <see cref="X509Chain.ChainPolicy"/> settings used by the signature validators.
    /// The platform chain never checks revocation: the validators check it themselves (<c>IChainRevocationChecker</c>,
    /// CRL and OCSP through <c>IHttpClientProvider</c> and its outbound HTTP policy), so the operating system must not
    /// fetch CRLs on its own, outside that policy and with its own timeouts.
    /// <paramref name="urlRetrievalTimeout"/> bounds what the platform still downloads (AIA issuer certificates).
    /// </summary>
    internal static void ConfigureChainPolicy(X509Chain chain, TimeSpan urlRetrievalTimeout)
    {
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.UrlRetrievalTimeout = urlRetrievalTimeout;
    }

    /// <summary>
    /// Detects the appropriate RSA signature padding from the certificate, checking
    /// the SubjectPublicKeyInfo OID (RFC 4055 §4) first, then the signature algorithm.
    /// </summary>
    internal static RSASignaturePadding DetectRsaPadding(X509Certificate2 cert)
    {
        return cert.PublicKey.Oid.Value == Oids.RsaPss || cert.SignatureAlgorithm.Value == Oids.RsaPss
            ? RSASignaturePadding.Pss
            : RSASignaturePadding.Pkcs1;
    }

    /// <summary>
    /// Detects the CMS signature algorithm OID for a given certificate and hash algorithm.
    /// Maps RSA+hash → PKCS#1 OIDs (RSA-SHA*), EC+hash → ECDSA OIDs, and handles PSS.
    /// </summary>
    internal static string DetectSignatureAlgorithmOid(X509Certificate2 cert, HashAlgorithmName hashAlg)
    {
        string keyAlg = cert.PublicKey.Oid.Value ?? string.Empty;

        if (cert.PublicKey.Oid.Value == Oids.RsaPss || cert.SignatureAlgorithm.Value == Oids.RsaPss)
        {
            return Oids.RsaPss;
        }

        return (keyAlg, hashAlg) switch
        {
            (Oids.RsaEncryption, _) when hashAlg == HashAlgorithmName.SHA256 => Oids.RsaSha256,
            (Oids.RsaEncryption, _) when hashAlg == HashAlgorithmName.SHA384 => Oids.RsaSha384,
            (Oids.RsaEncryption, _) when hashAlg == HashAlgorithmName.SHA512 => Oids.RsaSha512,
            (Oids.RsaEncryption, _) when hashAlg == HashAlgorithmName.SHA3_256 => Oids.RsaSha3_256,
            (Oids.RsaEncryption, _) when hashAlg == HashAlgorithmName.SHA3_384 => Oids.RsaSha3_384,
            (Oids.RsaEncryption, _) when hashAlg == HashAlgorithmName.SHA3_512 => Oids.RsaSha3_512,
            (Oids.EcPublicKey, _) when hashAlg == HashAlgorithmName.SHA256 => Oids.EcdsaSha256,
            (Oids.EcPublicKey, _) when hashAlg == HashAlgorithmName.SHA384 => Oids.EcdsaSha384,
            (Oids.EcPublicKey, _) when hashAlg == HashAlgorithmName.SHA512 => Oids.EcdsaSha512,
            (Oids.EcPublicKey, _) when hashAlg == HashAlgorithmName.SHA3_256 => Oids.EcdsaSha3_256,
            (Oids.EcPublicKey, _) when hashAlg == HashAlgorithmName.SHA3_384 => Oids.EcdsaSha3_384,
            (Oids.EcPublicKey, _) when hashAlg == HashAlgorithmName.SHA3_512 => Oids.EcdsaSha3_512,
            (Oids.Ed25519, _) => Oids.Ed25519,
            (Oids.Ed448, _) => Oids.Ed448,
            _ => throw new NotSupportedException(
                $"Cannot auto-detect signature OID for key '{cert.PublicKey.Oid.FriendlyName}' + hash '{hashAlg.Name}'.")
        };
    }

    /// <summary>
    /// Computes a hash of the given data using the specified algorithm.
    /// </summary>
    internal static byte[] ComputeHash(ReadOnlySpan<byte> data, HashAlgorithmName algorithm) => algorithm switch
    {
        _ when algorithm == HashAlgorithmName.SHA256 => SHA256.HashData(data),
        _ when algorithm == HashAlgorithmName.SHA384 => SHA384.HashData(data),
        _ when algorithm == HashAlgorithmName.SHA512 => SHA512.HashData(data),
        _ when algorithm == HashAlgorithmName.SHA3_256 => SHA3_256.HashData(data),
        _ when algorithm == HashAlgorithmName.SHA3_384 => SHA3_384.HashData(data),
        _ when algorithm == HashAlgorithmName.SHA3_512 => SHA3_512.HashData(data),
        _ => throw new NotSupportedException($"Hash algorithm '{algorithm.Name}' is not supported.")
    };

    /// <summary>
    /// Parses the hash algorithm from a DER-encoded <c>RSASSA-PSS-params</c> structure
    /// (RFC 4055 §3.1). The ASN.1 default inside an encoded parameter sequence is SHA-1;
    /// callers that see an absent parameter field must handle that separately because it
    /// means no key-level restriction rather than an encoded default.
    /// </summary>
    internal static HashAlgorithmName ParsePssHashAlgorithm(ReadOnlySpan<byte> algIdentifierParams)
    {
        if (algIdentifierParams.IsEmpty)
        {
            return HashAlgorithmName.SHA1; // DEFAULT per RFC 4055 §3.1
        }

        try
        {
            byte[] paramsCopy = algIdentifierParams.ToArray();
            var reader = new AsnReader(paramsCopy, AsnEncodingRules.BER);
            // reader.ReadSequence() returns AsnReader; drill into the [0]-tagged element
            // and then into the inner AlgorithmIdentifier SEQUENCE to read the OID.
            var seq = reader.ReadSequence();

            // hashAlgorithm [0] EXPLICIT AlgorithmIdentifier — present means non-default
            if (seq.HasData &&
                seq.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 0, true))
            {
                // [0] EXPLICIT wraps a SEQUENCE; AsnReader.ReadSequence(tag) returns AsnReader
                var hashAlgReader = seq.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true));
                // Inner AlgorithmIdentifier ::= SEQUENCE { OID, ... }
                var hashAlgSeq = hashAlgReader.ReadSequence();
                string hashOid = hashAlgSeq.ReadObjectIdentifier();
                return hashOid switch
                {
                    Oids.Sha256 => HashAlgorithmName.SHA256,
                    Oids.Sha384 => HashAlgorithmName.SHA384,
                    Oids.Sha512 => HashAlgorithmName.SHA512,
                    _ => HashAlgorithmName.SHA1 // unrecognised → RFC default
                };
            }
        }
        catch (AsnContentException)
        {
            // Malformed params — fall through to default
        }

        return HashAlgorithmName.SHA1; // DEFAULT per RFC 4055 §3.1
    }

    /// <summary>
    /// Whether a chain reaches a trust anchor with sound certificates, even when a certificate is revoked or outside its
    /// validity: built, or failing only for revocation or time. Those failures are the policy's NotRevoked and NotExpired
    /// constraints; an untrusted root, a partial chain or a bad signature are not.
    /// </summary>
    internal static bool ReachesTrustAnchor(X509Chain chain, bool built)
    {
        const X509ChainStatusFlags RevocationOrTime =
            X509ChainStatusFlags.Revoked | X509ChainStatusFlags.RevocationStatusUnknown | X509ChainStatusFlags.OfflineRevocation
            | X509ChainStatusFlags.NotTimeValid | X509ChainStatusFlags.NotTimeNested;
        return built
            || (chain.ChainElements.Count > 0 && chain.ChainStatus.All(s => (s.Status & ~RevocationOrTime) == 0));
    }
}

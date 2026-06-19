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
    /// Configures the common <see cref="X509Chain.ChainPolicy"/> settings used by all validators:
    /// revocation mode based on <paramref name="checkRevocation"/> and <c>ExcludeRoot</c> flag.
    /// </summary>
    internal static void ConfigureChainPolicy(X509Chain chain, bool checkRevocation)
    {
        chain.ChainPolicy.RevocationMode = checkRevocation
            ? X509RevocationMode.Online
            : X509RevocationMode.NoCheck;
        chain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
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
    /// (RFC 4055 §3.1). Returns SHA-256 if the params are absent or the hash OID is
    /// unrecognised (RFC 4055 default).
    /// </summary>
    internal static HashAlgorithmName ParsePssHashAlgorithm(ReadOnlySpan<byte> algIdentifierParams)
    {
        if (algIdentifierParams.IsEmpty)
        {
            return HashAlgorithmName.SHA256; // DEFAULT per RFC 4055 §3.1
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
                    _ => HashAlgorithmName.SHA256 // unrecognised → RFC default
                };
            }
        }
        catch (AsnContentException)
        {
            // Malformed params — fall through to default
        }

        return HashAlgorithmName.SHA256; // DEFAULT per RFC 4055 §3.1
    }
}

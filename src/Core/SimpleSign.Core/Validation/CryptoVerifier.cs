using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Internal;

namespace SimpleSign.Core.Validation;

/// <summary>
/// Verifies cryptographic signature validity and PAdES attribute binding.
/// All methods are static — no state needed. Uses Span&lt;byte&gt; to minimize allocations.
/// </summary>
public static class CryptoVerifier
{
    /// <summary>
    /// Verifies the RSA/ECDSA signature over the signed attributes.
    /// SignedAttrs must already have SET OF tag (0x31) — normalized by CmsParser.
    /// </summary>
    public static bool VerifySignature(CmsSignedData cmsData, ILogger? logger = null)
    {
        if (cmsData.SignerCertificate is null || cmsData.SignedAttrs is null || cmsData.Signature is null)
        {
            return false;
        }

#pragma warning disable CA5350 // SHA-1 is required for validating legacy ICP-Brasil signatures (pre-2016)
        var hashAlg = cmsData.DigestAlgorithmOid switch
        {
            Oids.Sha256 => HashAlgorithmName.SHA256,
            Oids.Sha384 => HashAlgorithmName.SHA384,
            Oids.Sha512 => HashAlgorithmName.SHA512,
            Oids.Sha3_256 => HashAlgorithmName.SHA3_256,
            Oids.Sha3_384 => HashAlgorithmName.SHA3_384,
            Oids.Sha3_512 => HashAlgorithmName.SHA3_512,
            Oids.Sha1 => HashAlgorithmName.SHA1,
            _ => throw new NotSupportedException($"Digest OID '{cmsData.DigestAlgorithmOid}' not supported.")
        };
#pragma warning restore CA5350

        (logger ?? NullLogger.Instance).VerifyingCryptoSignature(
            cmsData.SignatureAlgorithmOid,
            cmsData.SignerCertificate.Subject);

        // SignedAttrs already normalized to SET OF tag (0x31) by CmsParser — no clone needed
        using var rsaKey = cmsData.SignerCertificate.GetRSAPublicKey();
        if (rsaKey is not null)
        {
            var padding = cmsData.SignatureAlgorithmOid == Oids.RsaPss
                ? RSASignaturePadding.Pss
                : RSASignaturePadding.Pkcs1;
            bool rsaValid = rsaKey.VerifyData(cmsData.SignedAttrs, cmsData.Signature, hashAlg, padding);
            if (rsaValid)
            {
                (logger ?? NullLogger.Instance).CryptoSignatureVerified();
            }
            return rsaValid;
        }

        using var ecKey = cmsData.SignerCertificate.GetECDsaPublicKey();
        if (ecKey is not null)
        {
            bool ecValid = ecKey.VerifyData(cmsData.SignedAttrs, cmsData.Signature, hashAlg,
                DSASignatureFormat.Rfc3279DerSequence);
            if (ecValid)
            {
                (logger ?? NullLogger.Instance).CryptoSignatureVerified();
            }
            return ecValid;
        }

        string algo = cmsData.SignatureAlgorithmOid switch
        {
            Oids.Ed25519 => "Ed25519",
            Oids.Ed448 => "Ed448",
            _ => cmsData.SignatureAlgorithmOid
        };
        throw new NotSupportedException(
            $"Signature algorithm '{algo}' is not supported by this runtime. " +
            "Use an environment/runtime that supports the required key algorithm.");

    }

    /// <summary>
    /// Validates signingCertificate (V1/V2) binding (certificate ↔ signature anti-substitution).
    /// Respects the hash algorithm declared in the attribute (SHA-1 for V1, SHA-256 default for V2).
    /// </summary>
    public static void ValidateSigningCertV2(CmsSignedData cmsData, List<string> errors, ILogger? logger = null)
    {
        if (cmsData.SigningCertificateHash is not null && cmsData.SignerCertificate is not null)
        {
            (logger ?? NullLogger.Instance).ValidatingSigningCertV2(
                cmsData.SignerCertificate.Issuer,
                cmsData.SignerCertificate.SerialNumber);

            var certData = cmsData.SignerCertificate.RawData;

#pragma warning disable CA5350 // SHA-1 is required for validating legacy V1 signingCertificate attributes
            byte[] actualCertHash = cmsData.SigningCertificateHashAlgorithmOid switch
            {
                null or "" => SHA256.HashData(certData), // SHA-256 is default for V2 when no OID specified
                Oids.Sha256 => SHA256.HashData(certData),
                Oids.Sha384 => SHA384.HashData(certData),
                Oids.Sha512 => SHA512.HashData(certData),
                Oids.Sha3_256 => SHA3_256.HashData(certData),
                Oids.Sha3_384 => SHA3_384.HashData(certData),
                Oids.Sha3_512 => SHA3_512.HashData(certData),
                Oids.Sha1 => SHA1.HashData(certData),
                _ => throw new NotSupportedException(
                    $"Unsupported hash algorithm OID '{cmsData.SigningCertificateHashAlgorithmOid}' in signingCertificateV2 attribute.")
            };
#pragma warning restore CA5350

            if (!actualCertHash.AsSpan().SequenceEqual(cmsData.SigningCertificateHash))
            {
                errors.Add("signingCertificateV2 mismatch: signer certificate does not match the hash in the signed attribute.");
            }
        }
    }
}

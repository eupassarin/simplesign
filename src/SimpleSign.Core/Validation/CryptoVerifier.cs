using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Crypto;

namespace SimpleSign.Core.Validation;

/// <summary>
/// Verifies cryptographic signature validity and PAdES attribute binding.
/// All methods are static — no state needed. Uses Span&lt;byte&gt; to minimize allocations.
/// </summary>
internal static class CryptoVerifier
{
    /// <summary>
    /// Verifies the RSA/ECDSA signature over the signed attributes.
    /// SignedAttrs must already have SET OF tag (0x31) — normalized by CmsParser.
    /// </summary>
    internal static bool VerifySignature(CmsSignedData cmsData, ILogger? logger = null)
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
            Oids.Sha1 => HashAlgorithmName.SHA1,
            _ => throw new NotSupportedException($"Digest OID '{cmsData.DigestAlgorithmOid}' not supported.")
        };
#pragma warning restore CA5350

        if (cmsData.SignatureAlgorithmOid is Oids.Ed25519 or Oids.Ed448)
        {
            throw new NotSupportedException(
                $"EdDSA signature algorithm '{cmsData.SignatureAlgorithmOid}' is not currently supported by this runtime. " +
                "Use an environment/runtime that supports EdDSA key algorithms in System.Security.Cryptography.");
        }

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

        throw new NotSupportedException("Unsupported key algorithm in signer certificate.");
    }

    /// <summary>
    /// Validates signingCertificateV2 binding (certificate ↔ signature anti-substitution).
    /// Uses stackalloc for the SHA-256 hash (32 bytes).
    /// </summary>
    internal static void ValidateSigningCertV2(CmsSignedData cmsData, List<string> errors, ILogger? logger = null)
    {
        if (cmsData.SigningCertificateV2Hash is not null && cmsData.SignerCertificate is not null)
        {
            (logger ?? NullLogger.Instance).ValidatingSigningCertV2(
                cmsData.SignerCertificate.Issuer,
                cmsData.SignerCertificate.SerialNumber);

            Span<byte> actualCertHash = stackalloc byte[32]; // SHA-256 = 32 bytes
            SHA256.TryHashData(cmsData.SignerCertificate.RawData, actualCertHash, out _);
            if (!actualCertHash.SequenceEqual(cmsData.SigningCertificateV2Hash))
            {
                errors.Add("signingCertificateV2 mismatch: signer certificate does not match the hash in the signed attribute.");
            }
        }
    }
}

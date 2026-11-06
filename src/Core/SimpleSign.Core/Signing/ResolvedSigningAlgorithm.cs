using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Crypto;

namespace SimpleSign.Core.Signing;

/// <summary>
/// The complete, effective signature selection used for one signing operation.
/// </summary>
/// <remarks>
/// A resolved value is deliberately shared by the local signer, external-signer request,
/// and container writer so that an algorithm identifier cannot contradict the actual
/// cryptographic operation.
/// </remarks>
public sealed record ResolvedSigningAlgorithm
{
    /// <summary>The digest used by the signing operation.</summary>
    public HashAlgorithmName HashAlgorithm { get; }

    /// <summary>The signature algorithm OID written to the signed container.</summary>
    public string SignatureAlgorithmOid { get; }

    /// <summary>
    /// RSASSA-PSS parameters, or <see langword="null"/> when the signature scheme is not PSS.
    /// </summary>
    public RsaPssParameters? RsaPssParameters { get; }

    internal ResolvedSigningAlgorithm(
        HashAlgorithmName hashAlgorithm,
        string signatureAlgorithmOid,
        RsaPssParameters? rsaPssParameters)
    {
        HashAlgorithm = hashAlgorithm;
        SignatureAlgorithmOid = signatureAlgorithmOid;
        RsaPssParameters = rsaPssParameters;
    }
}

/// <summary>
/// The RSASSA-PSS parameters required to reproduce a signature operation.
/// </summary>
public sealed record RsaPssParameters
{
    /// <summary>The digest used for the message hash.</summary>
    public HashAlgorithmName HashAlgorithm { get; }

    /// <summary>The digest used by MGF1.</summary>
    public HashAlgorithmName MaskGenerationHashAlgorithm { get; }

    /// <summary>The PSS salt length, in octets.</summary>
    public int SaltLength { get; }

    /// <summary>The PSS trailer field. Only value 1 is supported by CMS and .NET.</summary>
    public int TrailerField { get; }

    /// <summary>Creates a PSS parameter value.</summary>
    /// <exception cref="ArgumentOutOfRangeException">A parameter is not supported.</exception>
    public RsaPssParameters(
        HashAlgorithmName hashAlgorithm,
        HashAlgorithmName maskGenerationHashAlgorithm,
        int saltLength,
        int trailerField = 1)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(saltLength);

        if (trailerField != 1)
        {
            throw new ArgumentOutOfRangeException(nameof(trailerField), "Only PSS trailer field 1 is supported.");
        }

        HashAlgorithm = hashAlgorithm;
        MaskGenerationHashAlgorithm = maskGenerationHashAlgorithm;
        SaltLength = saltLength;
        TrailerField = trailerField;
    }
}

/// <summary>
/// Resolves one coherent digest, signature OID, and PSS convention for a signing operation.
/// </summary>
public static class SigningAlgorithmResolver
{
    /// <summary>
    /// Resolves and validates the algorithm selection for a certificate.
    /// </summary>
    /// <param name="certificate">The signing certificate.</param>
    /// <param name="configuredHashAlgorithm">The configured hash algorithm.</param>
    /// <param name="hashAlgorithmExplicitlySet">Whether the caller explicitly selected the hash.</param>
    /// <param name="configuredSignatureAlgorithmOid">An optional signature algorithm OID.</param>
    /// <returns>The coherent algorithm selection to use throughout the operation.</returns>
    /// <exception cref="SigningException">The configured selection is incompatible.</exception>
    public static ResolvedSigningAlgorithm Resolve(
        X509Certificate2 certificate,
        HashAlgorithmName configuredHashAlgorithm,
        bool hashAlgorithmExplicitlySet,
        string? configuredSignatureAlgorithmOid = null)
    {
        ArgumentNullException.ThrowIfNull(certificate);

        HashAlgorithmName hashAlgorithm = configuredHashAlgorithm;
        if (!hashAlgorithmExplicitlySet && configuredSignatureAlgorithmOid is not null)
        {
            HashAlgorithmName? hashFromOid = TryInferHashFromSignatureOid(configuredSignatureAlgorithmOid);
            if (hashFromOid is not null)
            {
                hashAlgorithm = hashFromOid.Value;
            }
        }

        string signatureAlgorithmOid = configuredSignatureAlgorithmOid
            ?? CryptoUtility.DetectSignatureAlgorithmOid(certificate, hashAlgorithm);

        if (signatureAlgorithmOid is Oids.Ed25519 or Oids.Ed448)
        {
            throw new SigningException(
                "EdDSA signing is not supported because the net8.0 target cannot verify raw external EdDSA output.",
                SigningErrorReason.AlgorithmIncompatible);
        }

        CmsSignatureBuilder.ValidateSignatureAlgorithmDigestCompatibility(hashAlgorithm, signatureAlgorithmOid);
        try
        {
            CmsSignatureBuilder.ValidateSignatureAlgorithmCompatibility(certificate, signatureAlgorithmOid);
        }
        catch (ArgumentException ex)
        {
            throw new SigningException(ex.Message, SigningErrorReason.AlgorithmIncompatible, ex);
        }

        RsaPssParameters? pss = signatureAlgorithmOid == Oids.RsaPss
            ? CreateDefaultPssParameters(hashAlgorithm)
            : null;
        if (pss is not null)
        {
            ValidatePssKeyConstraints(certificate, pss);
        }

        return new ResolvedSigningAlgorithm(hashAlgorithm, signatureAlgorithmOid, pss);
    }

    /// <summary>
    /// Returns the digest encoded by a combined signature OID, if that OID defines one.
    /// </summary>
    public static HashAlgorithmName? TryInferHashFromSignatureOid(string signatureAlgorithmOid) => signatureAlgorithmOid switch
    {
        Oids.RsaSha256 or Oids.EcdsaSha256 => HashAlgorithmName.SHA256,
        Oids.RsaSha384 or Oids.EcdsaSha384 => HashAlgorithmName.SHA384,
        Oids.RsaSha512 or Oids.EcdsaSha512 => HashAlgorithmName.SHA512,
        Oids.RsaSha3_256 or Oids.EcdsaSha3_256 => HashAlgorithmName.SHA3_256,
        Oids.RsaSha3_384 or Oids.EcdsaSha3_384 => HashAlgorithmName.SHA3_384,
        Oids.RsaSha3_512 or Oids.EcdsaSha3_512 => HashAlgorithmName.SHA3_512,
        _ => null,
    };

    private static RsaPssParameters CreateDefaultPssParameters(HashAlgorithmName hashAlgorithm)
    {
        int saltLength = hashAlgorithm switch
        {
            _ when hashAlgorithm == HashAlgorithmName.SHA256 => 32,
            _ when hashAlgorithm == HashAlgorithmName.SHA384 => 48,
            _ when hashAlgorithm == HashAlgorithmName.SHA512 => 64,
            _ => throw new SigningException(
                $"RSASSA-PSS is not supported with hash '{hashAlgorithm.Name}'.",
                SigningErrorReason.AlgorithmIncompatible)
        };

        // This is the library's explicit convention for unrestricted RSA keys, not an RFC default.
        return new RsaPssParameters(hashAlgorithm, hashAlgorithm, saltLength);
    }

    private static void ValidatePssKeyConstraints(X509Certificate2 certificate, RsaPssParameters resolved)
    {
        if (certificate.PublicKey.Oid.Value != Oids.RsaPss)
        {
            return;
        }

        RsaPssParameters? restrictions = ReadPssKeyRestrictions(certificate);
        if (restrictions is null)
        {
            // RFC 4055: an absent parameter field in SubjectPublicKeyInfo imposes no PSS restriction.
            return;
        }

        if (restrictions.HashAlgorithm != resolved.HashAlgorithm ||
            restrictions.MaskGenerationHashAlgorithm != resolved.MaskGenerationHashAlgorithm ||
            restrictions.TrailerField != resolved.TrailerField ||
            resolved.SaltLength < restrictions.SaltLength)
        {
            throw new SigningException(
                "The requested RSASSA-PSS parameters are incompatible with the certificate public-key restrictions.",
                SigningErrorReason.AlgorithmIncompatible);
        }
    }

    private static RsaPssParameters? ReadPssKeyRestrictions(X509Certificate2 certificate)
    {
        try
        {
            var certificateReader = new AsnReader(certificate.RawData, AsnEncodingRules.DER);
            var certificateSequence = certificateReader.ReadSequence();
            var tbsCertificate = certificateSequence.ReadSequence();
            if (tbsCertificate.HasData && tbsCertificate.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 0, true))
            {
                _ = tbsCertificate.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true));
            }

            _ = tbsCertificate.ReadInteger();
            _ = tbsCertificate.ReadSequence();
            _ = tbsCertificate.ReadSequence();
            _ = tbsCertificate.ReadSequence();
            _ = tbsCertificate.ReadSequence();

            var subjectPublicKeyInfo = tbsCertificate.ReadSequence();
            var algorithmIdentifier = subjectPublicKeyInfo.ReadSequence();
            if (algorithmIdentifier.ReadObjectIdentifier() != Oids.RsaPss)
            {
                throw new SigningException(
                    "The certificate public-key algorithm changed while resolving RSASSA-PSS restrictions.",
                    SigningErrorReason.AlgorithmIncompatible);
            }

            if (!algorithmIdentifier.HasData)
            {
                return null;
            }

            return ParsePssParameters(algorithmIdentifier.ReadEncodedValue().ToArray());
        }
        catch (SigningException)
        {
            throw;
        }
        catch (AsnContentException ex)
        {
            throw new SigningException(
                "The RSASSA-PSS parameters in the signing certificate are malformed.",
                SigningErrorReason.AlgorithmIncompatible,
                ex);
        }
    }

    private static RsaPssParameters ParsePssParameters(byte[] encodedParameters)
    {
        try
        {
            var reader = new AsnReader(encodedParameters, AsnEncodingRules.DER);
            var parameters = reader.ReadSequence();
            HashAlgorithmName hashAlgorithm = HashAlgorithmName.SHA1;
            HashAlgorithmName mgfHashAlgorithm = HashAlgorithmName.SHA1;
            int saltLength = 20;
            int trailerField = 1;

            while (parameters.HasData)
            {
                Asn1Tag tag = parameters.PeekTag();
                if (tag == new Asn1Tag(TagClass.ContextSpecific, 0, true))
                {
                    hashAlgorithm = ReadHashAlgorithm(parameters.ReadSequence(tag));
                }
                else if (tag == new Asn1Tag(TagClass.ContextSpecific, 1, true))
                {
                    var mgfAlgorithm = parameters.ReadSequence(tag).ReadSequence();
                    if (mgfAlgorithm.ReadObjectIdentifier() != Oids.Mgf1 || !mgfAlgorithm.HasData)
                    {
                        throw new AsnContentException("Only MGF1 is supported for RSASSA-PSS.");
                    }

                    mgfHashAlgorithm = ReadHashAlgorithm(new AsnReader(
                        mgfAlgorithm.ReadEncodedValue().ToArray(), AsnEncodingRules.DER));
                }
                else if (tag == new Asn1Tag(TagClass.ContextSpecific, 2, true))
                {
                    saltLength = (int)parameters.ReadSequence(tag).ReadInteger();
                }
                else if (tag == new Asn1Tag(TagClass.ContextSpecific, 3, true))
                {
                    trailerField = (int)parameters.ReadSequence(tag).ReadInteger();
                }
                else
                {
                    throw new AsnContentException("Unexpected RSASSA-PSS parameter.");
                }
            }

            reader.ThrowIfNotEmpty();
            return new RsaPssParameters(hashAlgorithm, mgfHashAlgorithm, saltLength, trailerField);
        }
        catch (AsnContentException ex)
        {
            throw new SigningException(
                "The RSASSA-PSS parameters in the signing certificate are malformed or unsupported.",
                SigningErrorReason.AlgorithmIncompatible,
                ex);
        }
    }

    private static HashAlgorithmName ReadHashAlgorithm(AsnReader reader)
    {
        var algorithmIdentifier = reader.ReadSequence();
        string oid = algorithmIdentifier.ReadObjectIdentifier();
        return oid switch
        {
            Oids.Sha1 => HashAlgorithmName.SHA1,
            Oids.Sha256 => HashAlgorithmName.SHA256,
            Oids.Sha384 => HashAlgorithmName.SHA384,
            Oids.Sha512 => HashAlgorithmName.SHA512,
            _ => throw new AsnContentException($"Unsupported RSASSA-PSS hash algorithm '{oid}'.")
        };
    }
}

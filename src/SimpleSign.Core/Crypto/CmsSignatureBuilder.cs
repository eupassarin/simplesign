using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Signing;

namespace SimpleSign.Core.Crypto;

/// <summary>
/// Builds a CMS/PKCS#7 SignedData compatible with PAdES (adbe.pkcs7.detached).
/// Uses exclusively System.Security.Cryptography from .NET — zero external dependencies.
/// </summary>
public sealed class CmsSignatureBuilder
{


    /// <summary>
    /// Signs the provided bytes and returns a DER-encoded CMS/SignedData.
    /// The certificate must contain a private key (A1/PFX or Windows Store with minidriver).
    /// </summary>
    /// <param name="dataToSign">The document bytes to be signed (ByteRange 1 + ByteRange 2).</param>
    /// <param name="certificate">Certificate with private key.</param>
    /// <param name="hashAlgorithm">Hash algorithm (SHA256 or SHA512).</param>
    /// <param name="signingTime">Signing date/time (UTC).</param>
    /// <param name="extraCertificates">Intermediate certificates to compose the chain.</param>
    /// <param name="extraAttributes">Optional CAdES signed attributes (e.g., commitment-type, signature-policy).</param>
    /// <param name="padesAttributes">
    /// When <see langword="true"/> (default), adds the <c>id-aa-signingCertificateV2</c> (ESS CertV2) attribute
    /// required by PAdES B-B.
    /// </param>
    /// <param name="signatureAlgorithmOid">
    /// Optional override for the signature algorithm OID. When not <see langword="null"/>,
    /// this OID is used instead of the one auto-detected from the certificate. Must be
    /// compatible with the certificate's public key type (validated at call time).
    /// Primary use case: forcing RSASSA-PSS on an <c>rsaEncryption</c> certificate.
    /// </param>
    /// <param name="logger">Optional logger for debug diagnostics.</param>
    /// <param name="eContent">Optional embedded content for enveloped mode (null = detached).</param>
    public static byte[] Build(
        ReadOnlySpan<byte> dataToSign,
        X509Certificate2 certificate,
        HashAlgorithmName hashAlgorithm,
        DateTimeOffset? signingTime = null,
        IReadOnlyList<X509Certificate2>? extraCertificates = null,
        IReadOnlyList<CmsAttribute>? extraAttributes = null,
        bool padesAttributes = true,
        string? signatureAlgorithmOid = null,
        ILogger? logger = null,
        byte[]? eContent = null)
    {
        ArgumentNullException.ThrowIfNull(certificate);

        if (!certificate.HasPrivateKey)
        {
            throw new ArgumentException("Certificate must have a private key.", nameof(certificate));
        }

        if (signatureAlgorithmOid is not null)
        {
            ValidateSignatureAlgorithmCompatibility(certificate, signatureAlgorithmOid);
        }

        var time = signingTime ?? DateTimeOffset.UtcNow;
        string digestOid = GetDigestOid(hashAlgorithm);
        string signatureOid = signatureAlgorithmOid
            ?? CryptoUtility.DetectSignatureAlgorithmOid(certificate, hashAlgorithm);

        byte[] contentHash = ComputeHash(dataToSign, hashAlgorithm);
        (logger ?? NullLogger.Instance).CmsContentHashComputed(contentHash.Length, hashAlgorithm.Name!);

        byte[] signedAttrs = BuildSignedAttributes(contentHash, digestOid, time, certificate, extraAttributes, padesAttributes);
        byte[] signature = SignData(signedAttrs, certificate, hashAlgorithm, signatureOid);

        List<X509Certificate2> allCerts = [certificate, .. (extraCertificates ?? [])];

        (logger ?? NullLogger.Instance).CmsBuildStarted(digestOid, signatureOid, certificate.Subject);
        return BuildSignedData(digestOid, signatureOid, hashAlgorithm, signedAttrs, signature, certificate, allCerts,
            extraAttributes?.Count ?? 0, logger, eContent);
    }

    /// <summary>
    /// Signs the provided bytes using an external signing delegate and returns a DER-encoded CMS/SignedData.
    /// Use this overload for A3 tokens, HSMs, cloud KMS, or any scenario where the private key
    /// is not directly accessible via <see cref="X509Certificate2"/>.
    /// </summary>
    /// <param name="dataToSign">The document bytes to be signed (ByteRange 1 + ByteRange 2).</param>
    /// <param name="certificate">The signer's public certificate (private key NOT required).</param>
    /// <param name="externalSigner">
    /// A delegate that receives the DER-encoded signed attributes and returns the raw signature bytes.
    /// For RSA: PKCS#1 v1.5 or PSS signature. For ECDSA: DER SEQUENCE { r, s } (RFC 3279).
    /// </param>
    /// <param name="signatureAlgorithmOid">
    /// The OID of the signature algorithm (e.g., "1.2.840.113549.1.1.11" for RSA-SHA256).
    /// Must match the algorithm used by the external signer.
    /// </param>
    /// <param name="hashAlgorithm">Hash algorithm (SHA256 or SHA512).</param>
    /// <param name="signingTime">Signing date/time (UTC).</param>
    /// <param name="extraCertificates">Intermediate certificates to compose the chain.</param>
    /// <param name="extraAttributes">Optional CAdES signed attributes (e.g., commitment-type, signature-policy).</param>
    /// <param name="padesAttributes">
    /// When <see langword="true"/> (default), adds the <c>id-aa-signingCertificateV2</c> (ESS CertV2) attribute
    /// required by PAdES B-B. Set to <see langword="false"/> to produce a plain PKCS#7/CMS signature
    /// without PAdES-specific attributes.
    /// </param>
    /// <param name="logger">Optional logger for debug diagnostics.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public static async Task<byte[]> BuildAsync(
        ReadOnlyMemory<byte> dataToSign,
        X509Certificate2 certificate,
        Func<byte[], Task<byte[]>> externalSigner,
        string signatureAlgorithmOid,
        HashAlgorithmName hashAlgorithm,
        DateTimeOffset? signingTime = null,
        IReadOnlyList<X509Certificate2>? extraCertificates = null,
        IReadOnlyList<CmsAttribute>? extraAttributes = null,
        bool padesAttributes = true,
        ILogger? logger = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        ArgumentNullException.ThrowIfNull(externalSigner);
        ArgumentException.ThrowIfNullOrWhiteSpace(signatureAlgorithmOid);
        cancellationToken.ThrowIfCancellationRequested();

        ValidateSignatureAlgorithmCompatibility(certificate, signatureAlgorithmOid);
        ValidateSignatureAlgorithmDigestCompatibility(hashAlgorithm, signatureAlgorithmOid);
        if (signatureAlgorithmOid is Oids.Ed25519 or Oids.Ed448)
        {
            throw new SigningException(
                "EdDSA signing is not supported because the net8.0 target cannot verify raw external EdDSA output.",
                SigningErrorReason.AlgorithmIncompatible);
        }

        var time = signingTime ?? DateTimeOffset.UtcNow;
        string digestOid = GetDigestOid(hashAlgorithm);

        byte[] contentHash = ComputeHash(dataToSign.Span, hashAlgorithm);
        (logger ?? NullLogger.Instance).CmsContentHashComputed(contentHash.Length, hashAlgorithm.Name!);

        byte[] signedAttrs = BuildSignedAttributes(contentHash, digestOid, time, certificate, extraAttributes, padesAttributes);

        (logger ?? NullLogger.Instance).CmsExternalSignerInvoked(signedAttrs.Length);
        byte[] signature;
        try
        {
            signature = await externalSigner(signedAttrs).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            throw new SigningException(
                "External signer failed to produce a signature.",
                SigningErrorReason.ExternalSignerFailure,
                ex);
        }

        if (signature is null || signature.Length == 0)
        {
            throw new SigningException(
                "External signer returned null or empty signature.",
                SigningErrorReason.ExternalSignerReturnedEmpty);
        }

        if (!VerifyExternalSignature(signedAttrs, signature, certificate, hashAlgorithm, signatureAlgorithmOid))
        {
            throw new SigningException(
                "External signer returned a signature that does not verify with the configured certificate.",
                SigningErrorReason.AlgorithmIncompatible);
        }

        (logger ?? NullLogger.Instance).CmsExternalSignatureReceived(signature.Length);

        List<X509Certificate2> allCerts = [certificate, .. (extraCertificates ?? [])];

        (logger ?? NullLogger.Instance).CmsBuildStarted(digestOid, signatureAlgorithmOid, certificate.Subject);
        return BuildSignedData(digestOid, signatureAlgorithmOid, hashAlgorithm, signedAttrs, signature, certificate, allCerts,
            extraAttributes?.Count ?? 0, logger);
    }

    #region ASN.1 construction

    /// <summary>
    /// Assembles a complete CMS/PKCS#7 SignedData DER structure from pre-built components.
    /// Used by the deferred signing pipeline and the CAdES external signer flow.
    /// </summary>
    /// <param name="digestOid">The digest algorithm OID used for the content hash.</param>
    /// <param name="signatureOid">The signature algorithm OID.</param>
    /// <param name="hashAlgorithm">The hash algorithm (used for RSASSA-PSS-params).</param>
    /// <param name="signedAttrs">Pre-built DER-encoded signed attributes SET.</param>
    /// <param name="signature">The raw signature bytes over the signed attributes.</param>
    /// <param name="signerCert">The signer's certificate.</param>
    /// <param name="allCerts">All certificates to embed (signer + intermediates).</param>
    /// <param name="extraAttributeCount">Count of extra signed attributes (for logging).</param>
    /// <param name="logger">Optional logger.</param>
    /// <param name="eContent">Optional embedded content for enveloped CAdES (null = detached).</param>
    public static byte[] BuildSignedData(
        string digestOid,
        string signatureOid,
        HashAlgorithmName hashAlgorithm,
        byte[] signedAttrs,
        byte[] signature,
        X509Certificate2 signerCert,
        List<X509Certificate2> allCerts,
        int extraAttributeCount = 0,
        ILogger? logger = null,
        byte[]? eContent = null)
    {
        var log = logger ?? NullLogger.Instance;
        log.CmsSignedAttributesBuilt(signedAttrs.Length, extraAttributeCount);

        string paddingName = signerCert.PublicKey.Oid.Value == Oids.EcPublicKey
            ? "ECDSA"
            : signatureOid == Oids.RsaPss ? "Pss" : "Pkcs1";
        log.CmsSignatureGenerated(signature.Length, paddingName);

        var writer = new AsnWriter(AsnEncodingRules.DER);

        // ContentInfo { signedData }
        using (writer.PushSequence())
        {
            writer.WriteObjectIdentifier(Oids.SignedData);

            // [0] EXPLICIT SignedData
            using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true)))
            {
                // SignedData SEQUENCE
                using (writer.PushSequence())
                {
                    // version CMSVersion = 1
                    // RFC 5652 §5.1: version = 1 when all SignerInfos use issuerAndSerialNumber (v1).
                    // ETSI EN 319 142-1 does not mandate v3; v1 is interoperable with all major validators.
                    writer.WriteInteger(1);

                    // digestAlgorithms SET
                    using (writer.PushSetOf())
                    {
                        using (writer.PushSequence())
                        {
                            writer.WriteObjectIdentifier(digestOid);
                            if (DigestAlgorithmUsesNullParameter(digestOid))
                            {
                                writer.WriteNull();
                            }
                        }
                    }

                    // encapContentInfo: { id-data, OPTIONAL OCTET STRING }
                    using (writer.PushSequence())
                    {
                        writer.WriteObjectIdentifier(Oids.Data);
                        if (eContent is not null)
                        {
                            using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true)))
                            {
                                writer.WriteOctetString(eContent);
                            }
                        }
                    }

                    // certificates [0] IMPLICIT SET
                    using (writer.PushSetOf(new Asn1Tag(TagClass.ContextSpecific, 0, true)))
                    {
                        foreach (var cert in allCerts)
                        {
                            writer.WriteEncodedValue(cert.RawData);
                        }
                    }

                    // signerInfos SET
                    using (writer.PushSetOf())
                    {
                        BuildSignerInfo(writer, digestOid, signatureOid, hashAlgorithm,
                                        signedAttrs, signature, signerCert);
                    }
                }
            }
        }

        byte[] result = writer.Encode();
        log.CmsSignedDataAssembled(result.Length, allCerts.Count);
        return result;
    }

    private static void BuildSignerInfo(
        AsnWriter writer,
        string digestOid,
        string signatureOid,
        HashAlgorithmName hashAlg,
        byte[] signedAttrs,
        byte[] signature,
        X509Certificate2 cert)
    {
        using (writer.PushSequence())
        {
            // version = 1
            writer.WriteInteger(1);

            // issuerAndSerialNumber
            using (writer.PushSequence())
            {
                // IssuerName is a complete DER SEQUENCE
                writer.WriteEncodedValue(cert.IssuerName.RawData);
                // serialNumber
                writer.WriteInteger(BigIntegerFromSerial(cert.SerialNumberBytes.Span));
            }

            // digestAlgorithm
            using (writer.PushSequence())
            {
                writer.WriteObjectIdentifier(digestOid);
                if (DigestAlgorithmUsesNullParameter(digestOid))
                {
                    writer.WriteNull();
                }
            }

            // signedAttrs [0] IMPLICIT SET OF Attribute
            // signedAttrs is a DER SET (tag 0x31). For [0] IMPLICIT, we replace the tag with 0xA0
            byte[] implicitAttrs = (byte[])signedAttrs.Clone();
            implicitAttrs[0] = Asn1Tags.ContextSpecific0Constructed;
            writer.WriteEncodedValue(implicitAttrs);

            // signatureAlgorithm
            using (writer.PushSequence())
            {
                writer.WriteObjectIdentifier(signatureOid);
                if (signatureOid == Oids.RsaPss)
                {
                    WriteRsaPssParams(writer, hashAlg);
                }
                else if (SignatureAlgorithmUsesNullParameter(signatureOid))
                {
                    writer.WriteNull();
                }
            }

            // signature OCTET STRING
            writer.WriteOctetString(signature);
        }
    }

    /// <summary>
    /// Writes the <c>RSASSA-PSS-params</c> structure (RFC 4055 §3.1) that must accompany the
    /// <c>id-RSASSA-PSS</c> OID in <c>signatureAlgorithm</c>. The params declare the hash
    /// algorithm, the mask-generation function (always id-mgf1 with the same hash), and the
    /// salt length (always equal to the hash output size per RFC defaults).
    /// </summary>
    private static void WriteRsaPssParams(AsnWriter writer, HashAlgorithmName hashAlg)
    {
        (string hashOid, int saltLength) = hashAlg switch
        {
            _ when hashAlg == HashAlgorithmName.SHA256 => (Oids.Sha256, 32),
            _ when hashAlg == HashAlgorithmName.SHA384 => (Oids.Sha384, 48),
            _ when hashAlg == HashAlgorithmName.SHA512 => (Oids.Sha512, 64),
            _ => throw new NotSupportedException(
                $"No RSASSA-PSS-params defined for hash '{hashAlg.Name}'.")
        };

        // RSASSA-PSS-params ::= SEQUENCE { ... }
        using (writer.PushSequence())
        {
            // hashAlgorithm [0] EXPLICIT AlgorithmIdentifier
            using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true)))
            using (writer.PushSequence())
            {
                writer.WriteObjectIdentifier(hashOid);
                writer.WriteNull();
            }

            // maskGenAlgorithm [1] EXPLICIT MaskGenAlgorithm = id-mgf1 with the same hash
            using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 1, true)))
            using (writer.PushSequence())
            {
                writer.WriteObjectIdentifier(Oids.Mgf1);
                using (writer.PushSequence())
                {
                    writer.WriteObjectIdentifier(hashOid);
                    writer.WriteNull();
                }
            }

            // saltLength [2] EXPLICIT INTEGER
            using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 2, true)))
            {
                writer.WriteInteger(saltLength);
            }
        }
    }

    /// <summary>Builds the DER-encoded signed attributes SET for a CMS signature.</summary>
    /// <param name="contentHash">The hash of the content being signed.</param>
    /// <param name="digestOid">The digest algorithm OID.</param>
    /// <param name="time">Signing timestamp.</param>
    /// <param name="signerCertificate">The signer's certificate (for signingCertificateV2).</param>
    /// <param name="extraAttributes">Optional extra CAdES signed attributes.</param>
    /// <param name="padesAttributes">When true, includes PAdES-specific attributes (signingCertificateV2).</param>
    public static byte[] BuildSignedAttributes(byte[] contentHash, string digestOid, DateTimeOffset time,
        X509Certificate2 signerCertificate, IReadOnlyList<CmsAttribute>? extraAttributes = null,
        bool padesAttributes = true)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);

        using (writer.PushSetOf())
        {
            // contentType = id-data
            using (writer.PushSequence())
            {
                writer.WriteObjectIdentifier(Oids.ContentType);
                using (writer.PushSetOf())
                {
                    writer.WriteObjectIdentifier(Oids.Data);
                }
            }

            // signingTime — PKCS#7/CMS legacy only.
            // CAdES (ETSI EN 319 122-1 §5.2) does not permit signingTime in signed attributes.
            if (!padesAttributes)
            {
                using (writer.PushSequence())
                {
                    writer.WriteObjectIdentifier(Oids.SigningTime);
                    using (writer.PushSetOf())
                    {
                        writer.WriteUtcTime(time);
                    }
                }
            }

            // messageDigest
            using (writer.PushSequence())
            {
                writer.WriteObjectIdentifier(Oids.MessageDigest);
                using (writer.PushSetOf())
                {
                    writer.WriteOctetString(contentHash);
                }
            }

            // id-aa-signingCertificateV2 (RFC 5035 / PAdES-B-B required)
            // Binds the signer certificate to the signature via SHA-256 hash.
            // Without this attribute, Adobe Acrobat displays "Not PAdES compliant".
            // Omitted for plain CMS/PKCS#7 (legacy) signatures.
            if (padesAttributes)
            {
                BuildSigningCertificateV2Attribute(writer, signerCertificate);
            }

            // Extra CAdES attributes (e.g., commitment-type-indication, signature-policy-identifier)
            if (extraAttributes is { Count: > 0 })
            {
                foreach (var attr in extraAttributes)
                {
                    using (writer.PushSequence()) // Attribute
                    {
                        writer.WriteObjectIdentifier(attr.Oid);
                        using (writer.PushSetOf()) // attrValues SET OF
                        {
                            writer.WriteEncodedValue(attr.DerValue);
                        }
                    }
                }
            }
        }

        return writer.Encode();
    }

    /// <summary>
    /// Builds the id-aa-signingCertificateV2 attribute (OID 1.2.840.113549.1.9.16.2.47).
    ///
    /// ASN.1 structure:
    ///   SigningCertificateV2 ::= SEQUENCE {
    ///     certs  SEQUENCE OF ESSCertIDv2 }
    ///   ESSCertIDv2 ::= SEQUENCE {
    ///     hashAlgorithm  AlgorithmIdentifier DEFAULT id-sha256,  -- omitted when SHA-256
    ///     certHash       OCTET STRING,                           -- SHA-256 of the DER cert
    ///     issuerSerial   IssuerSerial OPTIONAL }
    ///   IssuerSerial ::= SEQUENCE {
    ///     issuer         GeneralNames,                           -- [4] directoryName
    ///     serialNumber   INTEGER }
    /// </summary>
    private static void BuildSigningCertificateV2Attribute(AsnWriter writer, X509Certificate2 cert)
    {
        byte[] certHash = SHA256.HashData(cert.RawData);

        using (writer.PushSequence()) // Attribute
        {
            writer.WriteObjectIdentifier(Oids.SigningCertificateV2);
            using (writer.PushSetOf()) // attrValues SET
            {
                using (writer.PushSequence()) // SigningCertificateV2
                {
                    using (writer.PushSequence()) // certs SEQUENCE OF
                    {
                        using (writer.PushSequence()) // ESSCertIDv2
                        {
                            // hashAlgorithm omitted — DEFAULT id-sha256
                            // certHash
                            writer.WriteOctetString(certHash);
                            // issuerSerial
                            using (writer.PushSequence()) // IssuerSerial
                            {
                                // issuer GeneralNames SEQUENCE OF GeneralName
                                using (writer.PushSequence())
                                {
                                    // directoryName [4] EXPLICIT Name (issuer RDN)
                                    using (writer.PushSequence(
                                        new Asn1Tag(TagClass.ContextSpecific, 4, isConstructed: true)))
                                    {
                                        writer.WriteEncodedValue(cert.IssuerName.RawData);
                                    }
                                }
                                // serialNumber
                                writer.WriteInteger(BigIntegerFromSerial(cert.SerialNumberBytes.Span));
                            }
                        }
                    }
                }
            }
        }
    }
    #endregion

    #region Cryptography

    private static byte[] SignData(byte[] signedAttrs, X509Certificate2 cert, HashAlgorithmName hashAlg, string signatureOid)
    {
        // Signs the signedAttrs (not the document — this is the CMS/PAdES standard)
        using var key = cert.GetRSAPrivateKey();
        if (key is not null)
        {
            // OID-based override takes precedence over cert-derived padding.
            // This enables forcing PSS on an rsaEncryption certificate.
            var padding = signatureOid == Oids.RsaPss
                ? RSASignaturePadding.Pss
                : DetectRsaPadding(cert);
            return key.SignData(signedAttrs, hashAlg, padding);
        }

        using var ecKey = cert.GetECDsaPrivateKey();
        if (ecKey is not null)
        {
            // DSASignatureFormat.Rfc3279DerSequence = DER SEQUENCE { r, s } format required by CMS
            return ecKey.SignData(signedAttrs, hashAlg, DSASignatureFormat.Rfc3279DerSequence);
        }

        string keyOid = cert.PublicKey.Oid.Value ?? "";
        if (keyOid is Oids.Ed25519 or Oids.Ed448)
        {
            throw new NotSupportedException(
                $"EdDSA key algorithm '{cert.PublicKey.Oid.FriendlyName}' is not supported for signing.");
        }

        throw new NotSupportedException(
            $"Certificate key algorithm '{cert.PublicKey.Oid.FriendlyName}' is not supported. Use RSA or ECDSA.");

    }

    /// <summary>
    /// Detects the RSA padding mode from the certificate's signature algorithm.
    /// Returns PSS if the cert was issued with RSA-PSS, PKCS1 otherwise.
    /// </summary>
    public static RSASignaturePadding DetectRsaPadding(X509Certificate2 cert)
        => CryptoUtility.DetectRsaPadding(cert);

    /// <summary>
    /// Verifies raw bytes returned by an external signer before they are embedded in a CMS or XML container.
    /// </summary>
    /// <param name="data">The exact bytes handed to the external signer.</param>
    /// <param name="signature">The raw signature returned by the external signer.</param>
    /// <param name="certificate">The public certificate for the signing key.</param>
    /// <param name="hashAlgorithm">The resolved digest algorithm.</param>
    /// <param name="signatureAlgorithmOid">The resolved signature algorithm OID.</param>
    /// <returns><see langword="true"/> when the signature verifies with the certificate public key.</returns>
    public static bool VerifyExternalSignature(
        ReadOnlySpan<byte> data,
        ReadOnlySpan<byte> signature,
        X509Certificate2 certificate,
        HashAlgorithmName hashAlgorithm,
        string signatureAlgorithmOid)
    {
        using var rsa = certificate.GetRSAPublicKey();
        if (rsa is not null)
        {
            var padding = signatureAlgorithmOid == Oids.RsaPss
                ? RSASignaturePadding.Pss
                : RSASignaturePadding.Pkcs1;
            return rsa.VerifyData(data, signature, hashAlgorithm, padding);
        }

        using var ecdsa = certificate.GetECDsaPublicKey();
        if (ecdsa is not null)
        {
            return ecdsa.VerifyData(data, signature, hashAlgorithm, DSASignatureFormat.Rfc3279DerSequence);
        }

        throw new NotSupportedException(
            $"External signature verification is not supported for certificate key algorithm " +
            $"'{certificate.PublicKey.Oid.FriendlyName}'.");
    }

    /// <summary>Computes a cryptographic hash of the provided data using the specified algorithm.</summary>
    public static byte[] ComputeHash(ReadOnlySpan<byte> data, HashAlgorithmName algorithm)
        => CryptoUtility.ComputeHash(data, algorithm);
    #endregion

    #region ASN.1 utilities

    private static System.Numerics.BigInteger BigIntegerFromSerial(ReadOnlySpan<byte> serial)
    {
        // Serial is big-endian, BigInteger is little-endian — reverse and ensure positive
        Span<byte> buf = stackalloc byte[serial.Length + 1];
        for (int i = 0; i < serial.Length; i++)
        {
            buf[i] = serial[serial.Length - 1 - i];
        }
        buf[serial.Length] = 0; // ensures positive
        return new System.Numerics.BigInteger(buf);
    }

    /// <summary>Maps a HashAlgorithmName to its corresponding OID string.</summary>
    public static string GetDigestOid(HashAlgorithmName alg) => alg switch
    {
        _ when alg == HashAlgorithmName.SHA256 => Oids.Sha256,
        _ when alg == HashAlgorithmName.SHA384 => Oids.Sha384,
        _ when alg == HashAlgorithmName.SHA512 => Oids.Sha512,
        _ when alg == HashAlgorithmName.SHA3_256 => Oids.Sha3_256,
        _ when alg == HashAlgorithmName.SHA3_384 => Oids.Sha3_384,
        _ when alg == HashAlgorithmName.SHA3_512 => Oids.Sha3_512,
        _ when alg == HashAlgorithmName.SHA1 => throw new NotSupportedException("SHA-1 is deprecated and not supported for new signatures. Use SHA-256 or stronger."),
        _ when alg == HashAlgorithmName.MD5 => throw new NotSupportedException("MD5 is insecure and not supported for signatures."),
        _ => throw new NotSupportedException($"Hash algorithm '{alg.Name}' is not supported.")
    };

    private static string GetSignatureAlgorithmOid(X509Certificate2 cert, HashAlgorithmName hashAlg)
        => CryptoUtility.DetectSignatureAlgorithmOid(cert, hashAlg);

    /// <summary>
    /// Validates that the requested signature algorithm OID is compatible with the
    /// certificate's public key type. Throws <see cref="ArgumentException"/> if not.
    /// </summary>
    /// <param name="cert">The signer's certificate.</param>
    /// <param name="signatureAlgorithmOid">OID of the signature algorithm to validate.</param>
    /// <exception cref="ArgumentException">The OID is incompatible with the certificate's key type.</exception>
    public static void ValidateSignatureAlgorithmCompatibility(
        X509Certificate2 cert, string signatureAlgorithmOid)
    {
        string keyOid = cert.PublicKey.Oid.Value ?? string.Empty;
        bool compatible = (keyOid, signatureAlgorithmOid) switch
        {
            (Oids.RsaEncryption, Oids.RsaSha256)
                or (Oids.RsaEncryption, Oids.RsaSha384)
                or (Oids.RsaEncryption, Oids.RsaSha512)
                or (Oids.RsaEncryption, Oids.RsaPss)
                or (Oids.RsaEncryption, Oids.RsaSha3_256)
                or (Oids.RsaEncryption, Oids.RsaSha3_384)
                or (Oids.RsaEncryption, Oids.RsaSha3_512) => true,
            (Oids.RsaPss, Oids.RsaPss) => true,
            (Oids.EcPublicKey, Oids.EcdsaSha256)
                or (Oids.EcPublicKey, Oids.EcdsaSha384)
                or (Oids.EcPublicKey, Oids.EcdsaSha512)
                or (Oids.EcPublicKey, Oids.EcdsaSha3_256)
                or (Oids.EcPublicKey, Oids.EcdsaSha3_384)
                or (Oids.EcPublicKey, Oids.EcdsaSha3_512) => true,
            (Oids.Ed25519, Oids.Ed25519) => true,
            (Oids.Ed448, Oids.Ed448) => true,
            _ => false
        };

        if (!compatible)
        {
            throw new ArgumentException(
                $"Signature algorithm OID '{signatureAlgorithmOid}' is not compatible with " +
                $"certificate key type '{cert.PublicKey.Oid.FriendlyName}' ({keyOid}). " +
                "Use an OID from the same algorithm family as the certificate's public key.");
        }
    }

    /// <summary>
    /// Validates that an algorithm OID which encodes a digest is not combined with a different digest.
    /// </summary>
    /// <param name="hashAlgorithm">The digest used by the signing operation.</param>
    /// <param name="signatureAlgorithmOid">The signature algorithm OID written to the container.</param>
    /// <exception cref="SigningException">The OID and digest contradict each other.</exception>
    public static void ValidateSignatureAlgorithmDigestCompatibility(
        HashAlgorithmName hashAlgorithm,
        string signatureAlgorithmOid)
    {
        HashAlgorithmName? requiredHash = signatureAlgorithmOid switch
        {
            Oids.RsaSha256 or Oids.EcdsaSha256 => HashAlgorithmName.SHA256,
            Oids.RsaSha384 or Oids.EcdsaSha384 => HashAlgorithmName.SHA384,
            Oids.RsaSha512 or Oids.EcdsaSha512 => HashAlgorithmName.SHA512,
            Oids.RsaSha3_256 or Oids.EcdsaSha3_256 => HashAlgorithmName.SHA3_256,
            Oids.RsaSha3_384 or Oids.EcdsaSha3_384 => HashAlgorithmName.SHA3_384,
            Oids.RsaSha3_512 or Oids.EcdsaSha3_512 => HashAlgorithmName.SHA3_512,
            _ => null
        };

        if (requiredHash is not null && requiredHash != hashAlgorithm)
        {
            throw new SigningException(
                $"Signature algorithm OID '{signatureAlgorithmOid}' requires {requiredHash.Value.Name}, " +
                $"but the signing operation uses {hashAlgorithm.Name}.",
                SigningErrorReason.AlgorithmIncompatible);
        }
    }

    /// <summary>Returns true when the digest algorithm OID expects an explicit NULL parameter in the AlgorithmIdentifier.</summary>
    internal static bool DigestAlgorithmUsesNullParameter(string digestOid) => digestOid is not
        (Oids.Sha3_256 or Oids.Sha3_384 or Oids.Sha3_512);

    /// <summary>Returns true when the signature algorithm OID expects an explicit NULL parameter in the AlgorithmIdentifier.</summary>
    public static bool SignatureAlgorithmUsesNullParameter(string signatureOid) => signatureOid switch
    {
        Oids.EcdsaSha256 or Oids.EcdsaSha384 or Oids.EcdsaSha512
            or Oids.EcdsaSha3_256 or Oids.EcdsaSha3_384 or Oids.EcdsaSha3_512 => false,
        Oids.Ed25519 or Oids.Ed448 => false,
        Oids.RsaPss => false,
        _ => true
    };

    /// <summary>
    /// Adds unsigned attributes to an existing CMS/PKCS#7 SignedData structure.
    /// Parses the original CMS, injects the attributes into SignerInfo unsignedAttrs [1],
    /// and returns the rewritten DER. Follows the same pattern used for timestamp embedding.
    /// </summary>
    /// <param name="cmsBytes">DER-encoded CMS/PKCS#7 SignedData.</param>
    /// <param name="unsignedAttributes">Unsigned attributes to inject (e.g., CertValues, RevocationValues, ArchiveTimeStamp).</param>
    /// <returns>Rewritten CMS bytes with unsigned attributes appended.</returns>
    public static byte[] AddUnsignedAttributes(byte[] cmsBytes, IReadOnlyList<CmsAttribute> unsignedAttributes)
    {
        ArgumentNullException.ThrowIfNull(cmsBytes);
        ArgumentNullException.ThrowIfNull(unsignedAttributes);

        if (unsignedAttributes.Count == 0)
        {
            return cmsBytes;
        }

        var reader = new AsnReader(cmsBytes, AsnEncodingRules.DER);
        var contentInfoSeq = reader.ReadSequence();
        string contentOid = contentInfoSeq.ReadObjectIdentifier();

        var explicitWrapper = contentInfoSeq.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true));
        var signedDataSeq = explicitWrapper.ReadSequence();

        int version = (int)signedDataSeq.ReadInteger();
        byte[] digestAlgorithms = signedDataSeq.ReadEncodedValue().ToArray();
        byte[] encapContentInfo = signedDataSeq.ReadEncodedValue().ToArray();

        byte[]? certificates = null;
        if (signedDataSeq.HasData && signedDataSeq.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 0, true))
        {
            certificates = signedDataSeq.ReadEncodedValue().ToArray();
        }

        byte[]? crls = null;
        if (signedDataSeq.HasData && signedDataSeq.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 1, true))
        {
            crls = signedDataSeq.ReadEncodedValue().ToArray();
        }

        var signerInfosTag = signedDataSeq.ReadSetOf();
        byte[] signerInfoBytes = signerInfosTag.ReadEncodedValue().ToArray();
        byte[] newSignerInfo = AddUnsignedAttrsToSignerInfo(signerInfoBytes, unsignedAttributes);

        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            writer.WriteObjectIdentifier(contentOid);
            using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true)))
            {
                using (writer.PushSequence())
                {
                    writer.WriteInteger(version);
                    writer.WriteEncodedValue(digestAlgorithms);
                    writer.WriteEncodedValue(encapContentInfo);

                    if (certificates is not null)
                    {
                        writer.WriteEncodedValue(certificates);
                    }
                    if (crls is not null)
                    {
                        writer.WriteEncodedValue(crls);
                    }

                    using (writer.PushSetOf())
                    {
                        writer.WriteEncodedValue(newSignerInfo);
                    }
                }
            }
        }

        return writer.Encode();
    }

    /// <summary>
    /// Adds certificates and revocation information to the root SignedData sets used by CAdES-B-LT.
    /// Existing certificate, revocation, and signer information is preserved.
    /// </summary>
    internal static byte[] AddValidationMaterial(
        byte[] cmsBytes,
        IReadOnlyList<byte[]> certificates,
        IReadOnlyList<byte[]> crls,
        IReadOnlyList<byte[]> ocspResponses)
    {
        ArgumentNullException.ThrowIfNull(cmsBytes);
        ArgumentNullException.ThrowIfNull(certificates);
        ArgumentNullException.ThrowIfNull(crls);
        ArgumentNullException.ThrowIfNull(ocspResponses);

        var reader = new AsnReader(cmsBytes, AsnEncodingRules.BER);
        var contentInfo = reader.ReadSequence();
        string contentOid = contentInfo.ReadObjectIdentifier();
        var wrapper = contentInfo.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true));
        var signedData = wrapper.ReadSequence();
        byte[] version = signedData.ReadEncodedValue().ToArray();
        byte[] digestAlgorithms = signedData.ReadEncodedValue().ToArray();
        byte[] encapContentInfo = signedData.ReadEncodedValue().ToArray();

        var allCertificates = new List<byte[]>();
        if (signedData.HasData && signedData.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 0, true))
        {
            var existing = signedData.ReadSetOf(skipSortOrderValidation: true,
                new Asn1Tag(TagClass.ContextSpecific, 0, true));
            while (existing.HasData)
            {
                allCertificates.Add(existing.ReadEncodedValue().ToArray());
            }
        }
        foreach (byte[] certificate in certificates)
        {
            if (!allCertificates.Any(existing => existing.AsSpan().SequenceEqual(certificate)))
            {
                allCertificates.Add(certificate);
            }
        }

        var allRevocations = new List<byte[]>();
        if (signedData.HasData && signedData.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 1, true))
        {
            var existing = signedData.ReadSetOf(skipSortOrderValidation: true,
                new Asn1Tag(TagClass.ContextSpecific, 1, true));
            while (existing.HasData)
            {
                allRevocations.Add(existing.ReadEncodedValue().ToArray());
            }
        }
        foreach (byte[] crl in crls)
        {
            if (!allRevocations.Any(existing => existing.AsSpan().SequenceEqual(crl)))
            {
                allRevocations.Add(crl);
            }
        }
        foreach (byte[] ocspResponse in ocspResponses)
        {
            var otherWriter = new AsnWriter(AsnEncodingRules.DER);
            using (otherWriter.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 1, true)))
            {
                otherWriter.WriteObjectIdentifier("1.3.6.1.5.5.7.16.2"); // id-ri-ocsp-response (RFC 5940)
                otherWriter.WriteEncodedValue(ocspResponse);
            }
            byte[] encoded = otherWriter.Encode();
            if (!allRevocations.Any(existing => existing.AsSpan().SequenceEqual(encoded)))
            {
                allRevocations.Add(encoded);
            }
        }

        byte[] signerInfos = signedData.ReadEncodedValue().ToArray();
        bool hasOtherRevocationInfo = allRevocations.Any(revocation =>
            revocation.Length > 0 && revocation[0] == 0xA1);
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            writer.WriteObjectIdentifier(contentOid);
            using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true)))
            using (writer.PushSequence())
            {
                if (hasOtherRevocationInfo)
                {
                    writer.WriteInteger(5);
                }
                else
                {
                    writer.WriteEncodedValue(version);
                }
                writer.WriteEncodedValue(digestAlgorithms);
                writer.WriteEncodedValue(encapContentInfo);
                using (writer.PushSetOf(new Asn1Tag(TagClass.ContextSpecific, 0, true)))
                {
                    foreach (byte[] certificate in allCertificates)
                    {
                        writer.WriteEncodedValue(certificate);
                    }
                }
                if (allRevocations.Count > 0)
                {
                    using (writer.PushSetOf(new Asn1Tag(TagClass.ContextSpecific, 1, true)))
                    {
                        foreach (byte[] revocation in allRevocations)
                        {
                            writer.WriteEncodedValue(revocation);
                        }
                    }
                }
                writer.WriteEncodedValue(signerInfos);
            }
        }
        return writer.Encode();
    }

    private static byte[] AddUnsignedAttrsToSignerInfo(byte[] signerInfoBytes, IReadOnlyList<CmsAttribute> unsignedAttributes)
    {
        var reader = new AsnReader(signerInfoBytes, AsnEncodingRules.DER);
        var siSeq = reader.ReadSequence();

        int version = (int)siSeq.ReadInteger();
        byte[] issuerAndSerial = siSeq.ReadEncodedValue().ToArray();
        byte[] digestAlg = siSeq.ReadEncodedValue().ToArray();

        byte[]? signedAttrs = null;
        if (siSeq.HasData && siSeq.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 0, true))
        {
            signedAttrs = siSeq.ReadEncodedValue().ToArray();
        }

        byte[] signatureAlg = siSeq.ReadEncodedValue().ToArray();
        byte[] signature = siSeq.ReadEncodedValue().ToArray();

        var existing = new List<byte[]>();
        if (siSeq.HasData && siSeq.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 1, true))
        {
            var existingSet = siSeq.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 1, true));
            while (existingSet.HasData)
            {
                existing.Add(existingSet.ReadEncodedValue().ToArray());
            }
        }

        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            writer.WriteInteger(version);
            writer.WriteEncodedValue(issuerAndSerial);
            writer.WriteEncodedValue(digestAlg);

            if (signedAttrs is not null)
            {
                writer.WriteEncodedValue(signedAttrs);
            }

            writer.WriteEncodedValue(signatureAlg);
            writer.WriteEncodedValue(signature);

            using (writer.PushSetOf(new Asn1Tag(TagClass.ContextSpecific, 1, true)))
            {
                foreach (byte[] attribute in existing)
                {
                    writer.WriteEncodedValue(attribute);
                }
                foreach (var attr in unsignedAttributes)
                {
                    using (writer.PushSequence())
                    {
                        writer.WriteObjectIdentifier(attr.Oid);
                        using (writer.PushSetOf())
                        {
                            writer.WriteEncodedValue(attr.DerValue);
                        }
                    }
                }
            }
        }

        return writer.Encode();
    }

    #endregion

}

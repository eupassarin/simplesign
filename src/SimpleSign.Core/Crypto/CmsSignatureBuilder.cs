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
    /// required by PAdES B-B. Set to <see langword="false"/> to produce a plain PKCS#7/CMS signature
    /// without PAdES-specific attributes (compatible with legacy validators and <c>adbe.pkcs7.detached</c>
    /// documents that predate PAdES).
    /// </param>
    /// <param name="logger">Optional logger for debug diagnostics.</param>
    public static byte[] Build(
        ReadOnlySpan<byte> dataToSign,
        X509Certificate2 certificate,
        HashAlgorithmName hashAlgorithm,
        DateTimeOffset? signingTime = null,
        IReadOnlyList<X509Certificate2>? extraCertificates = null,
        IReadOnlyList<CmsAttribute>? extraAttributes = null,
        bool padesAttributes = true,
        ILogger? logger = null)
    {
        ArgumentNullException.ThrowIfNull(certificate);

        if (!certificate.HasPrivateKey)
        {
            throw new ArgumentException("Certificate must have a private key.", nameof(certificate));
        }

        var time = signingTime ?? DateTimeOffset.UtcNow;
        string digestOid = GetDigestOid(hashAlgorithm);
        string signatureOid = GetSignatureAlgorithmOid(certificate, hashAlgorithm);

        byte[] contentHash = ComputeHash(dataToSign, hashAlgorithm);
        (logger ?? NullLogger.Instance).CmsContentHashComputed(contentHash.Length, hashAlgorithm.Name!);

        byte[] signedAttrs = BuildSignedAttributes(contentHash, digestOid, time, certificate, extraAttributes, padesAttributes);
        byte[] signature = SignData(signedAttrs, certificate, hashAlgorithm);

        List<X509Certificate2> allCerts = [certificate, .. (extraCertificates ?? [])];

        (logger ?? NullLogger.Instance).CmsBuildStarted(digestOid, signatureOid, certificate.Subject);
        return BuildSignedData(digestOid, signatureOid, signedAttrs, signature, certificate, allCerts,
            extraAttributes?.Count ?? 0, logger);
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
    /// For RSA: PKCS#1 v1.5 signature. For ECDSA: DER SEQUENCE { r, s } (RFC 3279). For EdDSA: raw signature bytes.
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
        ILogger? logger = null)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        ArgumentNullException.ThrowIfNull(externalSigner);
        ArgumentException.ThrowIfNullOrWhiteSpace(signatureAlgorithmOid);

        var time = signingTime ?? DateTimeOffset.UtcNow;
        string digestOid = GetDigestOid(hashAlgorithm);

        byte[] contentHash = ComputeHash(dataToSign.Span, hashAlgorithm);
        (logger ?? NullLogger.Instance).CmsContentHashComputed(contentHash.Length, hashAlgorithm.Name!);

        byte[] signedAttrs = BuildSignedAttributes(contentHash, digestOid, time, certificate, extraAttributes, padesAttributes);

        (logger ?? NullLogger.Instance).CmsExternalSignerInvoked(signedAttrs.Length);
        byte[] signature = await externalSigner(signedAttrs).ConfigureAwait(false);
        if (signature is null || signature.Length == 0)
        {
            throw new SigningException("External signer returned null or empty signature.");
        }

        (logger ?? NullLogger.Instance).CmsExternalSignatureReceived(signature.Length);

        List<X509Certificate2> allCerts = [certificate, .. (extraCertificates ?? [])];

        (logger ?? NullLogger.Instance).CmsBuildStarted(digestOid, signatureAlgorithmOid, certificate.Subject);
        return BuildSignedData(digestOid, signatureAlgorithmOid, signedAttrs, signature, certificate, allCerts,
            extraAttributes?.Count ?? 0, logger);
    }

    #region ASN.1 construction

    internal static byte[] BuildSignedData(
        string digestOid,
        string signatureOid,
        byte[] signedAttrs,
        byte[] signature,
        X509Certificate2 signerCert,
        List<X509Certificate2> allCerts,
        int extraAttributeCount = 0,
        ILogger? logger = null)
    {
        var log = logger ?? NullLogger.Instance;
        log.CmsSignedAttributesBuilt(signedAttrs.Length, extraAttributeCount);

        string paddingName = signerCert.PublicKey.Oid.Value == Oids.EcPublicKey
            ? "ECDSA"
            : DetectRsaPadding(signerCert).ToString();
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
                    writer.WriteInteger(1);

                    // digestAlgorithms SET
                    using (writer.PushSetOf())
                    {
                        using (writer.PushSequence())
                        {
                            writer.WriteObjectIdentifier(digestOid);
                            writer.WriteNull();
                        }
                    }

                    // encapContentInfo: { id-data, OPTIONAL OCTET STRING }
                    using (writer.PushSequence())
                    {
                        writer.WriteObjectIdentifier(Oids.Data);
                        // Detached: no embedded content
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
                        BuildSignerInfo(writer, digestOid, signatureOid,
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
                writer.WriteNull();
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
                if (SignatureAlgorithmUsesNullParameter(signatureOid))
                {
                    writer.WriteNull();
                }
            }

            // signature OCTET STRING
            writer.WriteOctetString(signature);
        }
    }

    internal static byte[] BuildSignedAttributes(byte[] contentHash, string digestOid, DateTimeOffset time,
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

            // signingTime
            using (writer.PushSequence())
            {
                writer.WriteObjectIdentifier(Oids.SigningTime);
                using (writer.PushSetOf())
                {
                    writer.WriteUtcTime(time);
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

    private static byte[] SignData(byte[] signedAttrs, X509Certificate2 cert, HashAlgorithmName hashAlg)
    {
        // Signs the signedAttrs (not the document — this is the CMS/PAdES standard)
        using var key = cert.GetRSAPrivateKey();
        if (key is not null)
        {
            var padding = DetectRsaPadding(cert);
            return key.SignData(signedAttrs, hashAlg, padding);
        }

        using var ecKey = cert.GetECDsaPrivateKey();
        if (ecKey is not null)
        {
            // DSASignatureFormat.Rfc3279DerSequence = DER SEQUENCE { r, s } format required by CMS
            return ecKey.SignData(signedAttrs, hashAlg, DSASignatureFormat.Rfc3279DerSequence);
        }

        throw new NotSupportedException(
            $"Certificate key algorithm '{cert.PublicKey.Oid.FriendlyName}' is not supported. Use RSA or ECDSA.");
    }

    /// <summary>
    /// Detects the RSA padding mode from the certificate's signature algorithm.
    /// Returns PSS if the cert was issued with RSA-PSS, PKCS1 otherwise.
    /// </summary>
    internal static RSASignaturePadding DetectRsaPadding(X509Certificate2 cert)
        => CryptoUtility.DetectRsaPadding(cert);

    internal static byte[] ComputeHash(ReadOnlySpan<byte> data, HashAlgorithmName algorithm)
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

    internal static string GetDigestOid(HashAlgorithmName alg) => alg switch
    {
        _ when alg == HashAlgorithmName.SHA256 => Oids.Sha256,
        _ when alg == HashAlgorithmName.SHA384 => Oids.Sha384,
        _ when alg == HashAlgorithmName.SHA512 => Oids.Sha512,
        _ => throw new NotSupportedException($"Hash algorithm '{alg.Name}' is not supported.")
    };

    private static string GetSignatureAlgorithmOid(X509Certificate2 cert, HashAlgorithmName hashAlg)
    {
        string keyAlg = cert.PublicKey.Oid.Value ?? string.Empty;

        // RSA-PSS uses a single OID regardless of hash (parameters carry the hash)
        if (cert.SignatureAlgorithm.Value == Oids.RsaPss)
        {
            return Oids.RsaPss;
        }

        return (keyAlg, hashAlg) switch
        {
            (Oids.RsaEncryption, _) when hashAlg == HashAlgorithmName.SHA256 => Oids.RsaSha256,
            (Oids.RsaEncryption, _) when hashAlg == HashAlgorithmName.SHA384 => Oids.RsaSha384,
            (Oids.RsaEncryption, _) when hashAlg == HashAlgorithmName.SHA512 => Oids.RsaSha512,
            (Oids.EcPublicKey, _) when hashAlg == HashAlgorithmName.SHA256 => Oids.EcdsaSha256,
            (Oids.EcPublicKey, _) when hashAlg == HashAlgorithmName.SHA384 => Oids.EcdsaSha384,
            (Oids.EcPublicKey, _) when hashAlg == HashAlgorithmName.SHA512 => Oids.EcdsaSha512,
            (Oids.Ed25519, _) => Oids.Ed25519,
            (Oids.Ed448, _) => Oids.Ed448,
            _ => throw new NotSupportedException(
                $"No signature OID for key '{cert.PublicKey.Oid.FriendlyName}' + hash '{hashAlg.Name}'.")
        };
    }

    internal static bool SignatureAlgorithmUsesNullParameter(string signatureOid) => signatureOid switch
    {
        Oids.EcdsaSha256 or Oids.EcdsaSha384 or Oids.EcdsaSha512 => false,
        Oids.Ed25519 or Oids.Ed448 => false,
        _ => true
    };
    #endregion

}

using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using SimpleSign.Core.Constants;

namespace SimpleSign.Core.Crypto;

/// <summary>
/// Parses CMS/PKCS#7 SignedData structures from raw DER bytes.
/// Extracts signer info, certificates, signed attributes, and timestamp tokens.
/// </summary>
internal static class CmsParser
{

    private record ParsedSignedAttributes(
        byte[]? MessageDigest,
        DateTimeOffset? SigningTime,
        byte[]? SigningCertV2Hash,
        string? CommitmentTypeOid,
        string? SignaturePolicyOid,
        byte[]? ManifestJson,
        string? ContentTypeOid);

    private record ParsedSignerInfo(
        X509Certificate2? SignerCert,
        byte[]? MessageDigest,
        byte[]? SignedAttrs,
        byte[]? Signature,
        DateTimeOffset? SigningTime,
        byte[]? TimestampToken,
        byte[]? SigningCertV2Hash,
        string SignatureAlgorithmOid,
        string? CommitmentTypeOid,
        string? SignaturePolicyOid,
        byte[]? ManifestJson,
        string? ContentTypeOid);

    /// <summary>Parses a CMS/PKCS#7 SignedData structure.</summary>
    public static CmsSignedData Parse(byte[] cmsBytes, ILogger? logger = null)
    {
        // Gov.br and some CAs emit CMS in BER (not strict DER) — accepts both
        var reader = new AsnReader(cmsBytes, AsnEncodingRules.BER);
        var contentInfo = reader.ReadSequence();

        // OID signedData
        _ = contentInfo.ReadObjectIdentifier();

        // [0] EXPLICIT SignedData
        var wrapper = contentInfo.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true));
        var signedData = wrapper.ReadSequence();

        _ = signedData.ReadInteger(); // version

        string digestOid = ParseDigestAlgorithm(signedData);

        // encapContentInfo — extract eContentType and, for document timestamps, TSTInfo messageImprint
        (string? eContentTypeOid, string? tstHashAlgOid, byte[]? tstHashBytes) = ParseEncapContentInfo(signedData);

        var embeddedCerts = ParseEmbeddedCertificates(signedData, logger);

        // crls [1] OPTIONAL
        if (signedData.HasData && signedData.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 1, true))
        {
            _ = signedData.ReadEncodedValue();
        }

        var signerInfo = ParseSignerInfo(signedData, embeddedCerts, logger);

        return new CmsSignedData
        {
            DigestAlgorithmOid = digestOid,
            SignatureAlgorithmOid = signerInfo.SignatureAlgorithmOid,
            Certificates = embeddedCerts.AsReadOnly(),
            SignerCertificate = signerInfo.SignerCert,
            MessageDigest = signerInfo.MessageDigest,
            SignedAttrs = signerInfo.SignedAttrs,
            Signature = signerInfo.Signature,
            SigningTime = signerInfo.SigningTime,
            SignatureTimestampToken = signerInfo.TimestampToken,
            SigningCertificateV2Hash = signerInfo.SigningCertV2Hash,
            CommitmentTypeOid = signerInfo.CommitmentTypeOid,
            SignaturePolicyOid = signerInfo.SignaturePolicyOid,
            ManifestJson = signerInfo.ManifestJson,
            ContentTypeOid = signerInfo.ContentTypeOid,
            EContentTypeOid = eContentTypeOid,
            TstMessageImprintHashAlgOid = tstHashAlgOid,
            TstMessageImprintHash = tstHashBytes
        };
    }

    private static string ParseDigestAlgorithm(AsnReader signedData)
    {
        var digestAlgs = signedData.ReadSetOf();
        string digestOid = Oids.Sha256;
        if (digestAlgs.HasData)
        {
            var algSeq = digestAlgs.ReadSequence();
            digestOid = algSeq.ReadObjectIdentifier();
        }
        return digestOid;
    }

    /// <summary>
    /// Parses encapContentInfo from the CMS SignedData.
    /// For regular signatures, eContentType is id-data (1.2.840.113549.1.7.1).
    /// For document timestamps (ETSI.RFC3161), eContentType is id-ct-TSTInfo and
    /// eContent contains the TSTInfo from which we extract messageImprint.
    /// </summary>
    private static (string? EContentTypeOid, string? TstHashAlgOid, byte[]? TstHashBytes)
        ParseEncapContentInfo(AsnReader signedData)
    {
        const string IdCtTstInfo = "1.2.840.113549.1.9.16.1.4";

        try
        {
            var encapContent = signedData.ReadSequence();
            string eContentTypeOid = encapContent.ReadObjectIdentifier();

            if (eContentTypeOid != IdCtTstInfo || !encapContent.HasData)
            {
                return (eContentTypeOid, null, null);
            }

            // eContent is [0] EXPLICIT OCTET STRING containing the TSTInfo DER
            var eContentWrapper = encapContent.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true));
            byte[] tstInfoDer = eContentWrapper.ReadOctetString();

            // Parse TSTInfo to extract messageImprint
            var tstInfo = new AsnReader(tstInfoDer, AsnEncodingRules.BER).ReadSequence();
            _ = tstInfo.ReadInteger();                       // version
            _ = tstInfo.ReadObjectIdentifier();              // policy
            var msgImprint = tstInfo.ReadSequence();         // messageImprint
            var hashAlgSeq = msgImprint.ReadSequence();      // AlgorithmIdentifier
            string hashAlgOid = hashAlgSeq.ReadObjectIdentifier();
            byte[] hashedMessage = msgImprint.ReadOctetString();

            return (eContentTypeOid, hashAlgOid, hashedMessage);
        }
        catch
        {
            // If parsing fails, don't block the rest of the validation pipeline
            return (null, null, null);
        }
    }

    private static List<X509Certificate2> ParseEmbeddedCertificates(AsnReader signedData, ILogger? logger = null)
    {
        var embeddedCerts = new List<X509Certificate2>();
        if (signedData.HasData && signedData.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 0, true))
        {
            var certsWrapper = signedData.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true));
            while (certsWrapper.HasData)
            {
                ReadOnlyMemory<byte> certMemory = certsWrapper.ReadEncodedValue();
                try
                { embeddedCerts.Add(CertificateLoader.LoadCertificate(certMemory.Span)); }
                catch (CryptographicException ex) { logger?.EmbeddedCertLoadingFailed(ex.Message); }
            }
        }
        return embeddedCerts;
    }

    private static ParsedSignerInfo ParseSignerInfo(AsnReader signedData, List<X509Certificate2> embeddedCerts, ILogger? logger = null)
    {
        X509Certificate2? signerCert = null;
        byte[]? messageDigest = null;
        byte[]? signedAttrs = null;
        byte[]? signature = null;
        DateTimeOffset? signingTime = null;
        byte[]? timestampToken = null;
        byte[]? signingCertV2Hash = null;
        string signatureAlgorithmOid = string.Empty;
        string? commitmentTypeOid = null;
        string? signaturePolicyOid = null;
        byte[]? manifestJson = null;
        string? contentTypeOid = null;

        var signerInfosSet = signedData.ReadSetOf();
        if (signerInfosSet.HasData)
        {
            var si = signerInfosSet.ReadSequence();
            _ = si.ReadInteger(); // version

            // issuerAndSerialNumber → identifies the certificate
            var ias = si.ReadSequence();
            ReadOnlyMemory<byte> issuerRaw = ias.ReadEncodedValue();
            var serial = ias.ReadInteger();
            string serialHex = serial.ToString("X");

            // Finds the signer certificate
            signerCert = embeddedCerts.FirstOrDefault(c =>
                c.IssuerName.RawData.AsSpan().SequenceEqual(issuerRaw.Span) &&
                c.SerialNumber.Equals(serialHex, StringComparison.OrdinalIgnoreCase));

            // P0: fallback removed — if not found by serial, try partial match (issuer DN only)
            signerCert ??= embeddedCerts.FirstOrDefault(c =>
                c.IssuerName.RawData.AsSpan().SequenceEqual(issuerRaw.Span));
            // If still not found, signerCert will be null — ValidateFieldAsync will report error

            // digestAlgorithm
            _ = si.ReadEncodedValue();

            // signedAttrs [0] IMPLICIT OPTIONAL
            if (si.HasData && si.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 0, true))
            {
                signedAttrs = si.ReadEncodedValue().ToArray();
                // Normalize: replace [0] IMPLICIT tag (0xA0) with SET OF (0x31)
                // so both ParseSignedAttributes and CryptoVerifier can use it directly — no clones needed
                signedAttrs[0] = Asn1Tags.SetOf;
                var parsedAttrs = ParseSignedAttributes(signedAttrs, logger);
                messageDigest = parsedAttrs.MessageDigest;
                signingTime = parsedAttrs.SigningTime;
                signingCertV2Hash = parsedAttrs.SigningCertV2Hash;
                commitmentTypeOid = parsedAttrs.CommitmentTypeOid;
                signaturePolicyOid = parsedAttrs.SignaturePolicyOid;
                manifestJson = parsedAttrs.ManifestJson;
                contentTypeOid = parsedAttrs.ContentTypeOid;
            }

            // signatureAlgorithm — extract the OID
            var sigAlgSeq = si.ReadSequence();
            signatureAlgorithmOid = sigAlgSeq.ReadObjectIdentifier();

            // signature
            signature = si.ReadOctetString();

            // unsignedAttrs [1] IMPLICIT OPTIONAL — loads timestamp token if present
            if (si.HasData && si.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 1, true))
            {
                var unsignedAttrs = si.ReadSetOf(new Asn1Tag(TagClass.ContextSpecific, 1, true));
                while (unsignedAttrs.HasData)
                {
                    try
                    {
                        var uAttr = unsignedAttrs.ReadSequence();
                        string uOid = uAttr.ReadObjectIdentifier();
                        if (uOid == Oids.SignatureTimestampToken && uAttr.HasData)
                        {
                            var valSet = uAttr.ReadSetOf();
                            if (valSet.HasData)
                            {
                                timestampToken = valSet.ReadEncodedValue().ToArray();
                            }
                        }
                    }
                    catch (AsnContentException ex) { logger?.UnsignedAttributeParsingFailed(ex.Message); }
                }
            }
        }

        return new ParsedSignerInfo(signerCert, messageDigest, signedAttrs, signature, signingTime, timestampToken,
            signingCertV2Hash, signatureAlgorithmOid, commitmentTypeOid, signaturePolicyOid, manifestJson, contentTypeOid);
    }

    private static ParsedSignedAttributes ParseSignedAttributes(byte[] signedAttrs, ILogger? logger = null)
    {
        byte[]? messageDigest = null;
        DateTimeOffset? signingTime = null;
        byte[]? signingCertV2Hash = null;
        byte[]? signingCertV1Hash = null;
        string? commitmentTypeOid = null;
        string? signaturePolicyOid = null;
        byte[]? manifestJson = null;
        string? contentTypeOid = null;

        // signedAttrs already has SET OF tag (0x31) — parse directly, no clone needed
        var attrsReader = new AsnReader(signedAttrs, AsnEncodingRules.BER);
        var attrsSet = attrsReader.ReadSetOf();
        while (attrsSet.HasData)
        {
            var attr = attrsSet.ReadSequence();
            string oid = attr.ReadObjectIdentifier();
            var valSet = attr.ReadSetOf();

            switch (oid)
            {
                case Oids.ContentType:
                    try
                    {
                        contentTypeOid = valSet.ReadObjectIdentifier();
                    }
                    catch (AsnContentException) { /* ignore malformed */ }
                    break;
                case Oids.MessageDigest:
                    messageDigest = valSet.ReadOctetString();
                    break;
                case Oids.SigningTime:
                    try
                    { signingTime = valSet.ReadUtcTime(); }
                    catch
                    {
                        // Some CMS use GeneralizedTime instead of UTCTime
                        try
                        { signingTime = valSet.ReadGeneralizedTime(); }
                        catch (AsnContentException ex) { logger?.GeneralizedTimeParsingFailed(ex.Message); }
                    }
                    break;
                case Oids.SigningCertificate:
                    // id-aa-signingCertificate (V1, RFC 2634): uses SHA-1 hash
                    try
                    {
                        // SigningCertificate → SEQUENCE → ESSCertID → certHash OCTET STRING
                        var signingCertV1Sequence = valSet.ReadSequence();
                        if (signingCertV1Sequence.HasData)
                        {
                            var certIdSeq = signingCertV1Sequence.ReadSequence(); // SEQUENCE OF ESSCertID
                            if (certIdSeq.HasData)
                            {
                                var essCertIdSequence = certIdSeq.ReadSequence(); // ESSCertID
                                if (essCertIdSequence.HasData)
                                {
                                    signingCertV1Hash = essCertIdSequence.ReadOctetString();
                                }
                            }
                        }
                    }
                    catch (AsnContentException ex) { logger?.SigningCertificateV2ParsingFailed(ex.Message); }
                    break;
                case Oids.SigningCertificateV2:
                    // id-aa-signingCertificateV2: extracts certHash for later validation
                    try
                    {
                        // SigningCertificateV2 → SEQUENCE → ESSCertIDv2 → certHash OCTET STRING
                        var signingCertV2Sequence = valSet.ReadSequence(); // SigningCertificateV2
                        if (signingCertV2Sequence.HasData)
                        {
                            var certIdSeq = signingCertV2Sequence.ReadSequence(); // SEQUENCE OF ESSCertIDv2
                            if (certIdSeq.HasData)
                            {
                                var essCertIdSequence = certIdSeq.ReadSequence(); // ESSCertIDv2
                                // hashAlgorithm DEFAULT id-sha256 — if present, it is a SEQUENCE
                                if (essCertIdSequence.HasData && essCertIdSequence.PeekTag() is { TagValue: (int)UniversalTagNumber.Sequence })
                                {
                                    essCertIdSequence.ReadEncodedValue(); // skips AlgorithmIdentifier
                                }
                                if (essCertIdSequence.HasData)
                                {
                                    signingCertV2Hash = essCertIdSequence.ReadOctetString();
                                }
                            }
                        }
                    }
                    catch (AsnContentException ex) { logger?.SigningCertificateV2ParsingFailed(ex.Message); }
                    break;
                case Oids.CommitmentTypeIndication:
                    // CommitmentTypeIndication ::= SEQUENCE { commitmentTypeId OID, ... }
                    try
                    {
                        var commitmentSeq = valSet.ReadSequence();
                        if (commitmentSeq.HasData)
                        {
                            commitmentTypeOid = commitmentSeq.ReadObjectIdentifier();
                        }
                    }
                    catch (AsnContentException) { /* ignore malformed */ }
                    break;
                case Oids.SignaturePolicyIdentifier:
                    // SignaturePolicyIdentifier ::= SEQUENCE { signaturePolicyId OID, ... }
                    try
                    {
                        var policySeq = valSet.ReadSequence();
                        if (policySeq.HasData)
                        {
                            signaturePolicyOid = policySeq.ReadObjectIdentifier();
                        }
                    }
                    catch (AsnContentException) { /* ignore malformed */ }
                    break;
                case Oids.SignatureManifest:
                    // Signature manifest: OCTET STRING containing UTF-8 JSON
                    try
                    {
                        manifestJson = valSet.ReadOctetString();
                    }
                    catch (AsnContentException) { /* ignore malformed */ }
                    break;
                default:
                    // Ignores other attributes
                    while (valSet.HasData)
                    {
                        valSet.ReadEncodedValue();
                    }
                    break;
            }
        }

        return new ParsedSignedAttributes(messageDigest, signingTime, signingCertV2Hash ?? signingCertV1Hash,
            commitmentTypeOid, signaturePolicyOid, manifestJson, contentTypeOid);
    }
}

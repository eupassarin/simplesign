using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Internal;

namespace SimpleSign.Core.Crypto;

/// <summary>
/// Parses CMS/PKCS#7 SignedData structures from raw DER bytes.
/// Extracts signer info, certificates, signed attributes, and timestamp tokens.
/// </summary>
public static class CmsParser
{

    private record ParsedSignedAttributes(
        byte[]? MessageDigest,
        DateTimeOffset? SigningTime,
        byte[]? SigningCertHash,
        string? SigningCertHashAlgOid,
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
        byte[]? SigningCertHash,
        string? SigningCertHashAlgOid,
        string SignatureAlgorithmOid,
        string? CommitmentTypeOid,
        string? SignaturePolicyOid,
        byte[]? ManifestJson,
        string? ContentTypeOid,
        IReadOnlyDictionary<string, byte[][]>? UnsignedAttributes,
        byte[]? ArchiveTimestampToken,
        string? DigestAlgorithmOid = null,
        IReadOnlyList<ParsedSignerInfo>? CounterSigners = null);

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
        (string? eContentTypeOid, string? tstHashAlgOid, byte[]? tstHashBytes) = ParseEncapContentInfo(signedData, out byte[]? eContent, logger);

        var embeddedCerts = ParseEmbeddedCertificates(signedData, logger);

        // crls [1] OPTIONAL
        if (signedData.HasData && signedData.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 1, true))
        {
            _ = signedData.ReadEncodedValue();
        }

        var signerInfo = ParseSignerInfo(signedData, embeddedCerts, logger);
        return ToSignedData(signerInfo, digestOid, embeddedCerts, eContentTypeOid, tstHashAlgOid, tstHashBytes, eContent);
    }

    /// <summary>
    /// Parses a CMS SignedData with every signer: co-signatures (several SignerInfos) and, inside
    /// each, its countersignatures. <see cref="Parse(byte[], ILogger?)"/> returns the first signer only.
    /// </summary>
    /// <param name="cmsBytes">DER or BER encoded CMS ContentInfo.</param>
    /// <param name="logger">Optional logger.</param>
    public static CmsSignedDataSet ParseAll(byte[] cmsBytes, ILogger? logger = null)
    {
        ArgumentNullException.ThrowIfNull(cmsBytes);
        var contentInfo = new AsnReader(cmsBytes, AsnEncodingRules.BER).ReadSequence();
        _ = contentInfo.ReadObjectIdentifier();
        var signedData = contentInfo.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true)).ReadSequence();
        _ = signedData.ReadInteger(); // version

        var digestAlgorithms = new List<string>();
        var digestSet = signedData.ReadSetOf(skipSortOrderValidation: true);
        while (digestSet.HasData)
        {
            digestAlgorithms.Add(digestSet.ReadSequence().ReadObjectIdentifier());
        }

        (string? eContentTypeOid, string? tstHashAlgOid, byte[]? tstHashBytes) = ParseEncapContentInfo(signedData, out byte[]? eContent, logger);
        var embeddedCerts = ParseEmbeddedCertificates(signedData, logger);
        if (signedData.HasData && signedData.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 1, true))
        {
            _ = signedData.ReadEncodedValue(); // crls
        }

        string fallbackDigest = digestAlgorithms.FirstOrDefault() ?? Oids.Sha256;
        var signers = ParseAllSignerInfos(signedData, embeddedCerts, logger)
            .Select(si => ToSignedData(si, fallbackDigest, embeddedCerts, eContentTypeOid, tstHashAlgOid, tstHashBytes, eContent))
            .ToList();

        return new CmsSignedDataSet
        {
            DigestAlgorithmOids = digestAlgorithms.AsReadOnly(),
            Certificates = embeddedCerts.AsReadOnly(),
            EContentTypeOid = eContentTypeOid,
            EncapsulatedContent = eContent,
            Signers = signers.AsReadOnly(),
        };
    }

    private static CmsSignedData ToSignedData(
        ParsedSignerInfo signerInfo,
        string fallbackDigestOid,
        List<X509Certificate2> embeddedCerts,
        string? eContentTypeOid,
        string? tstHashAlgOid,
        byte[]? tstHashBytes,
        byte[]? eContent)
    {
        return new CmsSignedData
        {
            DigestAlgorithmOid = signerInfo.DigestAlgorithmOid ?? fallbackDigestOid,
            SignatureAlgorithmOid = signerInfo.SignatureAlgorithmOid,
            Certificates = embeddedCerts.AsReadOnly(),
            SignerCertificate = signerInfo.SignerCert,
            MessageDigest = signerInfo.MessageDigest,
            SignedAttrs = signerInfo.SignedAttrs,
            Signature = signerInfo.Signature,
            SigningTime = signerInfo.SigningTime,
            SignatureTimestampToken = signerInfo.TimestampToken,
            SigningCertificateHash = signerInfo.SigningCertHash,
            SigningCertificateHashAlgorithmOid = signerInfo.SigningCertHashAlgOid,
            CommitmentTypeOid = signerInfo.CommitmentTypeOid,
            SignaturePolicyOid = signerInfo.SignaturePolicyOid,
            ManifestJson = signerInfo.ManifestJson,
            ContentTypeOid = signerInfo.ContentTypeOid,
            EContentTypeOid = eContentTypeOid,
            TstMessageImprintHashAlgOid = tstHashAlgOid,
            TstMessageImprintHash = tstHashBytes,
            UnsignedAttributes = signerInfo.UnsignedAttributes,
            ArchiveTimestampToken = signerInfo.ArchiveTimestampToken,
            EncapsulatedContent = eContent,
            CounterSignatures = signerInfo.CounterSigners is { Count: > 0 } counter
                ? [.. counter.Select(c => ToSignedData(c, fallbackDigestOid, embeddedCerts, null, null, null, null))]
                : [],
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
        ParseEncapContentInfo(AsnReader signedData, out byte[]? eContent, ILogger? logger = null)
    {
        const string IdCtTstInfo = "1.2.840.113549.1.9.16.1.4";
        eContent = null;

        try
        {
            var encapContent = signedData.ReadSequence();
            string eContentTypeOid = encapContent.ReadObjectIdentifier();

            if (eContentTypeOid != IdCtTstInfo || !encapContent.HasData)
            {
                if (encapContent.HasData)
                {
                    // Attached (.p7m): eContent [0] EXPLICIT OCTET STRING (possibly BER-constructed)
                    eContent = encapContent.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true)).ReadOctetString();
                }

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
        catch (Exception ex)
        {
            // If parsing fails, don't block the rest of the validation pipeline
            logger?.EncapContentInfoParsingFailed(ex.Message);
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
        var signerInfosSet = signedData.ReadSetOf(skipSortOrderValidation: true);
        if (!signerInfosSet.HasData)
        {
            return new ParsedSignerInfo(null, null, null, null, null, null, null, null, string.Empty, null, null, null, null, null, null);
        }

        return ParseOneSignerInfo(signerInfosSet.ReadSequence(), embeddedCerts, logger, depth: 0);
    }

    /// <summary>Parses every SignerInfo of the set, in order.</summary>
    private static List<ParsedSignerInfo> ParseAllSignerInfos(AsnReader signedData, List<X509Certificate2> embeddedCerts, ILogger? logger)
    {
        var result = new List<ParsedSignerInfo>();
        var signerInfosSet = signedData.ReadSetOf(skipSortOrderValidation: true);
        while (signerInfosSet.HasData)
        {
            result.Add(ParseOneSignerInfo(signerInfosSet.ReadSequence(), embeddedCerts, logger, depth: 0));
        }

        return result;
    }

    // Countersignatures nest (a countersignature can be countersigned); bound the recursion.
    private const int MaxCounterSignatureDepth = 8;

    private static ParsedSignerInfo ParseOneSignerInfo(AsnReader si, List<X509Certificate2> embeddedCerts, ILogger? logger, int depth)
    {
        X509Certificate2? signerCert = null;
        byte[]? messageDigest = null;
        byte[]? signedAttrs = null;
        byte[]? signature = null;
        DateTimeOffset? signingTime = null;
        byte[]? timestampToken = null;
        byte[]? signingCertHash = null;
        string? signingCertHashAlgOid = null;
        string signatureAlgorithmOid = string.Empty;
        string? commitmentTypeOid = null;
        string? signaturePolicyOid = null;
        byte[]? manifestJson = null;
        string? contentTypeOid = null;
        Dictionary<string, List<byte[]>>? unsignedAttrsDict = null;
        byte[]? archiveTimestampToken = null;
        string? digestAlgorithmOid = null;
        var counterSigners = new List<ParsedSignerInfo>();
        {
            _ = si.ReadInteger(); // version

            // issuerAndSerialNumber → identifies the certificate
            var ias = si.ReadSequence();
            ReadOnlyMemory<byte> issuerRaw = ias.ReadEncodedValue();
            // ReadIntegerBytes preserves leading-zero bytes (e.g. "00BB3F..." serials) unlike
            // BigInteger.ToString("X") which would strip them, causing a mismatch with SerialNumberBytes.
            ReadOnlyMemory<byte> serialBytes = ias.ReadIntegerBytes();

            // 1. Exact match: issuer raw bytes + serial bytes
            signerCert = embeddedCerts.FirstOrDefault(c =>
                c.IssuerName.RawData.AsSpan().SequenceEqual(issuerRaw.Span) &&
                c.SerialNumberBytes.Span.SequenceEqual(serialBytes.Span));

            // 2. Normalized issuer (tolerates UTF8String vs PrintableString encoding differences) + serial
            signerCert ??= embeddedCerts.FirstOrDefault(c =>
                NormalizedIssuerMatches(c.IssuerName, issuerRaw.Span) &&
                c.SerialNumberBytes.Span.SequenceEqual(serialBytes.Span));
            if (signerCert is not null && !signerCert.IssuerName.RawData.AsSpan().SequenceEqual(issuerRaw.Span))
            {
                logger?.SignerCertNormalizedIssuerFallback();
            }

            // 3. Last resort: issuer raw bytes only (no serial check) — avoids null signerCert
            //    when all else fails, accepting the risk of picking wrong cert from same issuer
            signerCert ??= embeddedCerts.FirstOrDefault(c =>
                c.IssuerName.RawData.AsSpan().SequenceEqual(issuerRaw.Span));
            // If still not found, signerCert will be null — ValidateFieldAsync will report error
            if (signerCert is null)
            {
                logger?.SignerCertNotFound();
            }

            // digestAlgorithm
            digestAlgorithmOid = si.ReadSequence().ReadObjectIdentifier();

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
                signingCertHash = parsedAttrs.SigningCertHash;
                signingCertHashAlgOid = parsedAttrs.SigningCertHashAlgOid;
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

            // unsignedAttrs [1] IMPLICIT OPTIONAL — loads timestamp token and all attributes
            if (si.HasData && si.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 1, true))
            {
                unsignedAttrsDict = new Dictionary<string, List<byte[]>>();
                var unsignedAttrs = si.ReadSetOf(new Asn1Tag(TagClass.ContextSpecific, 1, true));
                while (unsignedAttrs.HasData)
                {
                    try
                    {
                        var uAttr = unsignedAttrs.ReadSequence();
                        string uOid = uAttr.ReadObjectIdentifier();
                        if (!uAttr.HasData)
                        {
                            continue;
                        }

                        var valSet = uAttr.ReadSetOf();
                        var values = new List<byte[]>();
                        while (valSet.HasData)
                        {
                            values.Add(valSet.ReadEncodedValue().ToArray());
                        }

                        unsignedAttrsDict[uOid] = values;

                        if (uOid == Oids.SignatureTimestampToken && values.Count > 0)
                        {
                            timestampToken = values[0];
                        }
                        else if ((uOid == Oids.ArchiveTimeStamp || uOid == Oids.ArchiveTimeStampV3) && values.Count > 0)
                        {
                            archiveTimestampToken = values[0];
                        }
                        else if (uOid == Oids.CounterSignature && depth < MaxCounterSignatureDepth)
                        {
                            foreach (byte[] value in values)
                            {
                                counterSigners.Add(ParseOneSignerInfo(
                                    new AsnReader(value, AsnEncodingRules.BER).ReadSequence(), embeddedCerts, logger, depth + 1));
                            }
                        }
                    }
                    catch (AsnContentException ex) { logger?.UnsignedAttributeParsingFailed(ex.Message); }
                }
            }
        }

        IReadOnlyDictionary<string, byte[][]>? unsignedFinal = unsignedAttrsDict?.ToDictionary(
            kvp => kvp.Key, kvp => kvp.Value.ToArray());

        return new ParsedSignerInfo(signerCert, messageDigest, signedAttrs, signature, signingTime, timestampToken,
            signingCertHash, signingCertHashAlgOid, signatureAlgorithmOid, commitmentTypeOid, signaturePolicyOid, manifestJson, contentTypeOid,
            unsignedFinal, archiveTimestampToken, digestAlgorithmOid, counterSigners);
    }

    private static ParsedSignedAttributes ParseSignedAttributes(byte[] signedAttrs, ILogger? logger = null)
    {
        byte[]? messageDigest = null;
        DateTimeOffset? signingTime = null;
        byte[]? signingCertHash = null;
        string? signingCertHashAlgOid = null;
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
                    // id-aa-signingCertificate (V1, RFC 2634): implicitly uses SHA-1
                    // Only stored when no V2 attribute is present (priority is given to V2 below)
                    if (signingCertHash is null)
                    {
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
                                        signingCertHash = essCertIdSequence.ReadOctetString();
                                        signingCertHashAlgOid = Oids.Sha1; // V1 always uses SHA-1
                                    }
                                }
                            }
                        }
                        catch (AsnContentException ex) { logger?.SigningCertificateV2ParsingFailed(ex.Message); }
                    }
                    break;
                case Oids.SigningCertificateV2:
                    // id-aa-signingCertificateV2 (RFC 5035): explicit hash algorithm, DEFAULT id-sha256
                    // V2 takes priority — overwrite any V1 hash already stored
                    try
                    {
                        // ESSCertIDv2 ::= SEQUENCE { hashAlgorithm AlgorithmIdentifier DEFAULT sha256, certHash Hash }
                        var signingCertV2Sequence = valSet.ReadSequence(); // SigningCertificateV2
                        if (signingCertV2Sequence.HasData)
                        {
                            var certIdSeq = signingCertV2Sequence.ReadSequence(); // SEQUENCE OF ESSCertIDv2
                            if (certIdSeq.HasData)
                            {
                                var essCertIdSequence = certIdSeq.ReadSequence(); // ESSCertIDv2
                                // hashAlgorithm: DEFAULT id-sha256; if present it is a SEQUENCE (AlgorithmIdentifier)
                                string? explicitAlgOid = null;
                                if (essCertIdSequence.HasData && essCertIdSequence.PeekTag() is { TagValue: (int)UniversalTagNumber.Sequence })
                                {
                                    var algIdSeq = essCertIdSequence.ReadSequence(); // AlgorithmIdentifier
                                    if (algIdSeq.HasData)
                                    {
                                        explicitAlgOid = algIdSeq.ReadObjectIdentifier();
                                    }
                                }
                                if (essCertIdSequence.HasData)
                                {
                                    signingCertHash = essCertIdSequence.ReadOctetString();
                                    signingCertHashAlgOid = explicitAlgOid ?? Oids.Sha256; // DEFAULT sha256
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
                case Oids.SignatureManifestLegacy:
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

        return new ParsedSignedAttributes(messageDigest, signingTime, signingCertHash, signingCertHashAlgOid,
            commitmentTypeOid, signaturePolicyOid, manifestJson, contentTypeOid);
    }

    /// <summary>
    /// Compares a raw DER-encoded issuer Name against a certificate's IssuerName.
    /// First tries exact byte equality (fast path), then falls back to normalized string comparison
    /// to tolerate re-encoding differences (e.g. UTF8String vs PrintableString) in the CMS issuer field.
    /// </summary>
    private static bool NormalizedIssuerMatches(X500DistinguishedName certIssuer, ReadOnlySpan<byte> issuerRaw)
    {
        if (certIssuer.RawData.AsSpan().SequenceEqual(issuerRaw))
        {
            return true;
        }

        try
        {
            var dn = new X500DistinguishedName(issuerRaw.ToArray());
            return string.Equals(dn.Name, certIssuer.Name, StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }
}

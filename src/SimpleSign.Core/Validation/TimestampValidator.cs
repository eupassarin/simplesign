using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Crypto;

namespace SimpleSign.Core.Validation;

/// <summary>
/// Validates RFC 3161 timestamp tokens embedded in CMS signatures.
/// Verifies TSA signature, nonce, and extracts timestamp date.
/// </summary>
public static class TimestampValidator
{

    /// <summary>
    /// Delegate for certificate chain validation, allowing the caller to supply its own implementation.
    /// </summary>
    public delegate bool CertificateChainValidatorDelegate(
        X509Certificate2? signerCert,
        IReadOnlyList<X509Certificate2> embeddedCerts,
        List<string> errors,
        List<string> warnings);

    private sealed record ParsedTsaSignerInfo(
        List<X509Certificate2> Certificates,
        byte[]? SignedAttrs,
        byte[]? Signature,
        string? DigestOid,
        string? SignatureAlgOid,
        byte[]? SignatureAlgParams);

    /// <summary>Validates an RFC 3161 timestamp token against a signature value.</summary>
    /// <param name="timestampToken">DER-encoded RFC 3161 timestamp token.</param>
    /// <param name="signatureValueBytes">The signature bytes that were timestamped.</param>
    /// <param name="signingTime">Optional signing time for temporal validation.</param>
    /// <param name="warnings">Accumulated warnings.</param>
    /// <param name="validateChain">Optional TSA certificate chain validator delegate.</param>
    /// <param name="logger">Optional logger.</param>
    /// <returns>true = valid, false = invalid, null = no data to validate.</returns>
    public static bool? Validate(
        byte[] timestampToken,
        byte[] signatureValueBytes,
        DateTimeOffset? signingTime,
        List<string> warnings,
        CertificateChainValidatorDelegate? validateChain = null,
        ILogger? logger = null)
    {
        if (timestampToken is null || timestampToken.Length == 0)
        {
            return null;
        }
        if (signatureValueBytes is null || signatureValueBytes.Length == 0)
        {
            return null;
        }

        try
        {
            byte[]? tstInfoBytes = ExtractTstInfo(timestampToken);
            if (tstInfoBytes is null)
            {
                return null;
            }

            var tsaData = ExtractTsaCertificatesAndSigner(timestampToken, logger);

            if (!VerifyTsaSignature(tsaData, warnings))
            {
                return false;
            }

            if (!ValidateHashMatch(tstInfoBytes, signatureValueBytes, warnings, out var tstInfo))
            {
                return false;
            }

            // P1: Temporal validation — extrair genTime do TSTInfo
            try
            {
                // serialNumber
                _ = tstInfo.ReadInteger();
                // genTime (GeneralizedTime)
                DateTimeOffset genTime = tstInfo.ReadGeneralizedTime();
                if (genTime > DateTimeOffset.UtcNow.AddMinutes(5))
                {
                    warnings.Add($"Timestamp genTime ({genTime:o}) is in the future.");
                }
                if (signingTime.HasValue && genTime < signingTime.Value.AddMinutes(-5))
                {
                    warnings.Add($"Timestamp genTime ({genTime:o}) is before signingTime ({signingTime.Value:o}).");
                }
            }
            catch (AsnContentException ex) { logger?.TimestampGenTimeExtractionFailed(ex.Message); }

            // M3: validates the TSA certificate chain
            if (tsaData.Certificates is not [] && validateChain is not null)
            {
                var tsaErrors = new List<string>();
                var tsaWarnings = new List<string>();
                validateChain(tsaData.Certificates[0], tsaData.Certificates, tsaErrors, tsaWarnings);
                foreach (var w in tsaWarnings)
                {
                    warnings.Add($"TSA: {w}");
                }
                foreach (var e in tsaErrors)
                {
                    warnings.Add($"TSA chain: {e}"); // reports as warning (not a fatal error)
                }
            }

            return true;
        }
        // S2221: intentional — timestamp validation reports parsing failures as warnings
        catch (Exception ex)
        {
            warnings.Add($"Could not validate timestamp token: {ex.Message}");
            return null;
        }
    }

    /// <summary>Validates the timestamp token in a CMS signature.</summary>
    /// <returns>true = valid, false = invalid, null = absent.</returns>
    public static bool? Validate(
        CmsSignedData cmsData,
        List<string> warnings,
        CertificateChainValidatorDelegate? validateChain = null,
        ILogger? logger = null)
    {
        if (cmsData.SignatureTimestampToken is null || cmsData.Signature is null)
        {
            return null;
        }

        return Validate(
            cmsData.SignatureTimestampToken,
            cmsData.Signature,
            cmsData.SigningTime,
            warnings,
            validateChain,
            logger);
    }

    private static byte[]? ExtractTstInfo(byte[] timestampToken)
    {
        // The token is a CMS SignedData containing a TSTInfo as encapContentInfo
        var tokenReader = new AsnReader(timestampToken, AsnEncodingRules.BER);
        var contentInfo = tokenReader.ReadSequence();
        _ = contentInfo.ReadObjectIdentifier(); // OID signedData

        var wrapper = contentInfo.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true));
        var signedData = wrapper.ReadSequence();
        _ = signedData.ReadInteger(); // version
        _ = signedData.ReadSetOf();   // digestAlgorithms

        // encapContentInfo: { OID id-ct-TSTInfo, [0] EXPLICIT OCTET STRING }
        var encap = signedData.ReadSequence();
        _ = encap.ReadObjectIdentifier(); // id-ct-TSTInfo = 1.2.840.113549.1.9.16.1.4

        if (!encap.HasData)
        {
            return null;
        }
        var tstInfoWrapper = encap.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true));
        return tstInfoWrapper.ReadOctetString();
    }

    private static ParsedTsaSignerInfo ExtractTsaCertificatesAndSigner(byte[] timestampToken, ILogger? logger = null)
    {
        var tsaCerts = new List<X509Certificate2>();
        byte[]? tsaSignerInfoSignedAttrs = null;
        byte[]? tsaSignerInfoSignature = null;
        string? tsaSignerDigestOid = null;
        string? tsaSignerSigAlgOid = null;
        byte[]? tsaSignerSigAlgParams = null;
        ReadOnlyMemory<byte> signerIssuerRaw = default;
        ReadOnlyMemory<byte> signerSerialBytes = default;
        try
        {
            var tsaTokenReader2 = new AsnReader(timestampToken, AsnEncodingRules.BER);
            var tsaCi = tsaTokenReader2.ReadSequence();
            _ = tsaCi.ReadObjectIdentifier();
            var tsaWrapper = tsaCi.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true));
            var tsaSd = tsaWrapper.ReadSequence();
            _ = tsaSd.ReadInteger();  // version
            _ = tsaSd.ReadSetOf();    // digestAlgorithms
            _ = tsaSd.ReadEncodedValue(); // encapContentInfo
            if (tsaSd.HasData && tsaSd.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 0, true))
            {
                var certsWrapper = tsaSd.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true));
                while (certsWrapper.HasData)
                {
                    var certBytes = certsWrapper.ReadEncodedValue().ToArray();
                    try
                    { tsaCerts.Add(CertificateLoader.LoadCertificate(certBytes)); }
                    catch (CryptographicException ex) { logger?.TsaCertLoadingFailed(ex.Message); }
                }
            }
            // Skip CRLs [1] OPTIONAL
            if (tsaSd.HasData && tsaSd.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 1, true))
            {
                tsaSd.ReadEncodedValue();
            }
            // signerInfos SET
            if (tsaSd.HasData)
            {
                var siSet = tsaSd.ReadSetOf();
                if (siSet.HasData)
                {
                    var si = siSet.ReadSequence();
                    _ = si.ReadInteger(); // version
                    // issuerAndSerialNumber — parse to identify signer cert
                    var ias = si.ReadSequence();
                    signerIssuerRaw = ias.ReadEncodedValue();
                    signerSerialBytes = ias.ReadIntegerBytes();
                    var digestAlgSeq = si.ReadSequence();
                    tsaSignerDigestOid = digestAlgSeq.ReadObjectIdentifier();
                    // signedAttrs [0] IMPLICIT OPTIONAL
                    if (si.HasData && si.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 0, true))
                    {
                        tsaSignerInfoSignedAttrs = si.ReadEncodedValue().ToArray();
                    }
                    var sigAlgSeq2 = si.ReadSequence();
                    tsaSignerSigAlgOid = sigAlgSeq2.ReadObjectIdentifier();
                    if (sigAlgSeq2.HasData)
                    {
                        tsaSignerSigAlgParams = sigAlgSeq2.ReadEncodedValue().ToArray();
                    }
                    tsaSignerInfoSignature = si.ReadOctetString();
                }
            }
        }
        catch (AsnContentException ex) { logger?.TsaDataExtractionFailed(ex.Message); }

        // Identify signer cert from embedded certificates via issuerAndSerialNumber
        if (tsaCerts.Count > 1 && !signerIssuerRaw.IsEmpty)
        {
            var signerCert = tsaCerts.FirstOrDefault(c =>
                c.IssuerName.RawData.AsSpan().SequenceEqual(signerIssuerRaw.Span) &&
                c.SerialNumberBytes.Span.SequenceEqual(signerSerialBytes.Span));
            if (signerCert is not null && tsaCerts[0] != signerCert)
            {
                // Move signer cert to position [0] so VerifyTsaSignature uses the correct one
                tsaCerts.Remove(signerCert);
                tsaCerts.Insert(0, signerCert);
                logger?.TsaSignerCertIdentified(signerCert.Subject);
            }
        }

        return new ParsedTsaSignerInfo(tsaCerts, tsaSignerInfoSignedAttrs, tsaSignerInfoSignature, tsaSignerDigestOid, tsaSignerSigAlgOid, tsaSignerSigAlgParams);
    }

    private static bool VerifyTsaSignature(ParsedTsaSignerInfo tsaData, List<string> warnings)
    {
        if (tsaData.Certificates is [] || tsaData.SignedAttrs is null || tsaData.Signature is null)
        {
            return false; // nothing to verify
        }

        // Convert implicit [0] back to SET OF for verification (RFC 5652 §5.4)
        byte[] attrsForVerify = (byte[])tsaData.SignedAttrs.Clone();
        if (attrsForVerify is [Asn1Tags.ContextSpecific0Constructed, ..])
        {
            attrsForVerify[0] = Asn1Tags.SetOf; // IMPLICIT [0] → SET OF
        }

        var tsaHashAlg = (tsaData.DigestOid ?? Oids.Sha256) switch
        {
            Oids.Sha256 => HashAlgorithmName.SHA256,
            Oids.Sha384 => HashAlgorithmName.SHA384,
            Oids.Sha512 => HashAlgorithmName.SHA512,
            Oids.Sha1 => HashAlgorithmName.SHA1,
            _ => HashAlgorithmName.SHA256
        };

        // For RSA-PSS, the RSASSA-PSS-params are authoritative (RFC 4055 §3.1) — override
        // the digest-algorithm-derived hash with the one carried in the signatureAlgorithm
        // parameters when present.
        if (tsaData.SignatureAlgOid == Oids.RsaPss && tsaData.SignatureAlgParams is not null)
        {
            tsaHashAlg = CryptoUtility.ParsePssHashAlgorithm(tsaData.SignatureAlgParams);
        }

        bool tsaSigValid = false;
        using (var rsa = tsaData.Certificates[0].GetRSAPublicKey())
        {
            if (rsa is not null)
            {
                var padding = tsaData.SignatureAlgOid == Oids.RsaPss
                    ? RSASignaturePadding.Pss
                    : RSASignaturePadding.Pkcs1;
                tsaSigValid = rsa.VerifyData(attrsForVerify, tsaData.Signature, tsaHashAlg, padding);
            }
        }
        if (!tsaSigValid)
        {
            using var ecdsa = tsaData.Certificates[0].GetECDsaPublicKey();
            if (ecdsa is not null)
            {
                // CMS encodes ECDSA signatures as DER (RFC 3279 §2.2.3), not the default IEEE P1363
                // raw r||s. Without an explicit format the default is P1363 and verification fails
                // for every real-world ECDSA-signed RFC 3161 token (e.g. freetsa.org).
                tsaSigValid = ecdsa.VerifyData(
                    attrsForVerify, tsaData.Signature, tsaHashAlg,
                    DSASignatureFormat.Rfc3279DerSequence);
            }
        }

        if (!tsaSigValid)
        {
            warnings.Add("Timestamp token CMS signature verification failed.");
            return false;
        }

        return true;
    }

    private static bool ValidateHashMatch(byte[] tstInfoBytes, byte[] signatureValueBytes, List<string> warnings, out AsnReader tstInfo)
    {
        // TSTInfo
        tstInfo = new AsnReader(tstInfoBytes, AsnEncodingRules.BER).ReadSequence();
        _ = tstInfo.ReadInteger();           // version
        _ = tstInfo.ReadObjectIdentifier();  // policy

        // messageImprint: { hashAlgorithm, hashedMessage }
        var msgImprint = tstInfo.ReadSequence();
        var algSeq = msgImprint.ReadSequence();
        string hashOid = algSeq.ReadObjectIdentifier();
        byte[] hashedMessage = msgImprint.ReadOctetString();

        // Computes hash of the signature with the algorithm indicated by the timestamp
        byte[] actualHash = hashOid switch
        {
            Oids.Sha256 => SHA256.HashData(signatureValueBytes),
            Oids.Sha384 => SHA384.HashData(signatureValueBytes),
            Oids.Sha512 => SHA512.HashData(signatureValueBytes),
            Oids.Sha1 => SHA1.HashData(signatureValueBytes),
            _ => throw new NotSupportedException($"Timestamp hash OID {hashOid} not supported.")
        };

        bool hashValid = actualHash.AsSpan().SequenceEqual(hashedMessage);
        if (!hashValid)
        {
            warnings.Add("Signature timestamp token hash mismatch — timestamp may be invalid.");
            return false;
        }

        return true;
    }
}

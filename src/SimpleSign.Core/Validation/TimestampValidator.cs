using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Crypto;

namespace SimpleSign.Core.Validation;

/// <summary>
/// Validates RFC 3161 timestamp tokens embedded in CMS signatures.
/// Verifies TSA signature and signed-content binding, and extracts timestamp date.
/// Request nonce binding is checked by <see cref="TimestampClient"/> when receiving a response.
/// </summary>
public static class TimestampValidator
{
    /// <summary>Verifies a token's CMS signature and its binding to the signed TSTInfo, without evaluating TSA trust.</summary>
    public static bool VerifyTokenSignature(byte[] timestampToken)
        => VerifyTokenSignature(timestampToken, []);

    /// <summary>Verifies token integrity and reports why verification failed.</summary>
    public static bool VerifyTokenSignature(byte[] timestampToken, List<string> warnings)
    {
        ArgumentNullException.ThrowIfNull(timestampToken);
        ArgumentNullException.ThrowIfNull(warnings);
        try
        {
            byte[]? tstInfo = ExtractTstInfo(timestampToken);
            if (tstInfo is null)
            {
                warnings.Add("Timestamp token does not contain TSTInfo.");
                return false;
            }

            return VerifyTsaSignature(ExtractTsaCertificatesAndSigner(timestampToken), tstInfo, warnings);
        }
        catch (Exception ex) when (ex is AsnContentException or CryptographicException or InvalidOperationException or NotSupportedException)
        {
            warnings.Add($"Timestamp token integrity check failed: {ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// Delegate for certificate chain validation, allowing the caller to supply its own implementation.
    /// </summary>
    public delegate bool CertificateChainValidatorDelegate(
        X509Certificate2? signerCert,
        IReadOnlyList<X509Certificate2> embeddedCerts,
        List<string> errors,
        List<string> warnings);

    /// <summary>Validates token integrity and reports the optional TSA trust decision separately.</summary>
    public static TimestampTokenValidationResult ValidateWithTrust(
        byte[] timestampToken,
        byte[] signatureValueBytes,
        DateTimeOffset? signingTime,
        List<string> warnings,
        CertificateChainValidatorDelegate? validateChain = null,
        ILogger? logger = null)
    {
        bool? trusted = null;
        CertificateChainValidatorDelegate? capturedPolicy = validateChain is null ? null :
            (certificate, certificates, errors, chainWarnings) =>
            {
                try
                {
                    trusted = HasTimestampingEku(certificate, errors)
                        && validateChain(certificate, certificates, errors, chainWarnings);
                }
                catch (Exception ex)
                {
                    errors.Add($"TSA trust evaluation failed: {ex.Message}");
                    trusted = false;
                }
                return trusted.Value;
            };
        bool? integrity = Validate(timestampToken, signatureValueBytes, signingTime,
            warnings, capturedPolicy, logger);
        return new TimestampTokenValidationResult
        {
            IsIntegrityValid = integrity,
            IsTsaTrusted = integrity == true ? trusted : null
        };
    }

    private sealed record ParsedTsaSignerInfo(
        List<X509Certificate2> Certificates,
        bool SignerCertificateMatched,
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

            if (!VerifyTsaSignature(tsaData, tstInfoBytes, warnings))
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
                bool chainValid;
                try
                {
                    chainValid = validateChain(
                        tsaData.Certificates[0], tsaData.Certificates, tsaErrors, tsaWarnings);
                }
                catch (Exception ex)
                {
                    tsaErrors.Add($"Trust evaluation failed: {ex.Message}");
                    chainValid = false;
                }
                foreach (var w in tsaWarnings)
                {
                    warnings.Add($"TSA: {w}");
                }
                foreach (var e in tsaErrors)
                {
                    warnings.Add($"TSA chain: {e}");
                }
                if (!chainValid)
                {
                    warnings.Add("TSA certificate chain is not trusted; token integrity was verified independently.");
                }
            }

            return true;
        }
        catch (NotSupportedException ex)
        {
            warnings.Add($"Unsupported timestamp token algorithm: {ex.Message}");
            return false;
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
        if (contentInfo.ReadObjectIdentifier() != Oids.SignedData)
        {
            return null;
        }

        var wrapper = contentInfo.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true));
        var signedData = wrapper.ReadSequence();
        _ = signedData.ReadInteger(); // version
        _ = signedData.ReadSetOf();   // digestAlgorithms

        // encapContentInfo: { OID id-ct-TSTInfo, [0] EXPLICIT OCTET STRING }
        var encap = signedData.ReadSequence();
        if (encap.ReadObjectIdentifier() != Oids.TimestampInfoContentType)
        {
            return null;
        }

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
        bool signerCertificateMatched = false;
        if (tsaCerts.Count > 0 && !signerIssuerRaw.IsEmpty)
        {
            var signerCert = tsaCerts.FirstOrDefault(c =>
                c.IssuerName.RawData.AsSpan().SequenceEqual(signerIssuerRaw.Span) &&
                c.SerialNumberBytes.Span.SequenceEqual(signerSerialBytes.Span));
            signerCertificateMatched = signerCert is not null;
            if (signerCert is not null && tsaCerts[0] != signerCert)
            {
                // Move signer cert to position [0] so VerifyTsaSignature uses the correct one
                tsaCerts.Remove(signerCert);
                tsaCerts.Insert(0, signerCert);
                logger?.TsaSignerCertIdentified(signerCert.Subject);
            }
        }

        return new ParsedTsaSignerInfo(tsaCerts, signerCertificateMatched,
            tsaSignerInfoSignedAttrs, tsaSignerInfoSignature, tsaSignerDigestOid,
            tsaSignerSigAlgOid, tsaSignerSigAlgParams);
    }

    private static bool VerifyTsaSignature(ParsedTsaSignerInfo tsaData, byte[] tstInfoBytes, List<string> warnings)
    {
        if (tsaData.Certificates is [] || !tsaData.SignerCertificateMatched
            || tsaData.SignedAttrs is null || tsaData.Signature is null)
        {
            warnings.Add("TSA signer certificate or signed attributes are missing.");
            return false;
        }

        // Convert implicit [0] back to SET OF for verification (RFC 5652 §5.4)
        byte[] attrsForVerify = (byte[])tsaData.SignedAttrs.Clone();
        if (attrsForVerify is [Asn1Tags.ContextSpecific0Constructed, ..])
        {
            attrsForVerify[0] = Asn1Tags.SetOf; // IMPLICIT [0] → SET OF
        }

        if (!VerifyTsaSignedAttributes(attrsForVerify, tstInfoBytes, tsaData.DigestOid,
            tsaData.Certificates[0], warnings))
        {
            return false;
        }

        var tsaHashAlg = tsaData.DigestOid switch
        {
            Oids.Sha256 => HashAlgorithmName.SHA256,
            Oids.Sha384 => HashAlgorithmName.SHA384,
            Oids.Sha512 => HashAlgorithmName.SHA512,
            Oids.Sha1 => HashAlgorithmName.SHA1,
            Oids.Sha3_256 => HashAlgorithmName.SHA3_256,
            Oids.Sha3_384 => HashAlgorithmName.SHA3_384,
            Oids.Sha3_512 => HashAlgorithmName.SHA3_512,
            _ => throw new NotSupportedException("Unsupported TSA signer digest algorithm.")
        };

        // For RSA-PSS, the RSASSA-PSS-params are authoritative (RFC 4055 §3.1) — override
        // the digest-algorithm-derived hash with the one carried in the signatureAlgorithm
        // parameters when present.
        if (tsaData.SignatureAlgOid == Oids.RsaPss && tsaData.SignatureAlgParams is not null)
        {
            if (CryptoUtility.ParsePssHashAlgorithm(tsaData.SignatureAlgParams) != tsaHashAlg)
            {
                warnings.Add("TSA signature and signer digest algorithms disagree.");
                return false;
            }
        }

        bool rsaAlgorithm = tsaData.SignatureAlgOid is Oids.RsaEncryption or Oids.RsaPss
            or Oids.RsaSha1 or Oids.RsaSha256 or Oids.RsaSha384 or Oids.RsaSha512
            or Oids.RsaSha3_256 or Oids.RsaSha3_384 or Oids.RsaSha3_512;
        bool ecdsaAlgorithm = tsaData.SignatureAlgOid is Oids.EcdsaSha256 or Oids.EcdsaSha384
            or Oids.EcdsaSha512 or Oids.EcdsaSha3_256 or Oids.EcdsaSha3_384 or Oids.EcdsaSha3_512;
        bool algorithmMatchesDigest = tsaData.SignatureAlgOid switch
        {
            Oids.RsaEncryption or Oids.RsaPss => true,
            Oids.RsaSha1 => tsaHashAlg == HashAlgorithmName.SHA1,
            Oids.RsaSha256 or Oids.EcdsaSha256 => tsaHashAlg == HashAlgorithmName.SHA256,
            Oids.RsaSha384 or Oids.EcdsaSha384 => tsaHashAlg == HashAlgorithmName.SHA384,
            Oids.RsaSha512 or Oids.EcdsaSha512 => tsaHashAlg == HashAlgorithmName.SHA512,
            Oids.RsaSha3_256 or Oids.EcdsaSha3_256 => tsaHashAlg == HashAlgorithmName.SHA3_256,
            Oids.RsaSha3_384 or Oids.EcdsaSha3_384 => tsaHashAlg == HashAlgorithmName.SHA3_384,
            Oids.RsaSha3_512 or Oids.EcdsaSha3_512 => tsaHashAlg == HashAlgorithmName.SHA3_512,
            _ => false
        };
        if (!algorithmMatchesDigest)
        {
            warnings.Add("TSA signature algorithm does not match the signer digest.");
            return false;
        }

        bool tsaSigValid = false;
        using (var rsa = rsaAlgorithm ? tsaData.Certificates[0].GetRSAPublicKey() : null)
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
            using var ecdsa = ecdsaAlgorithm ? tsaData.Certificates[0].GetECDsaPublicKey() : null;
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

    private static bool VerifyTsaSignedAttributes(
        byte[] signedAttributes,
        byte[] tstInfoBytes,
        string? digestOid,
        X509Certificate2 signerCertificate,
        List<string> warnings)
    {
        bool contentTypeValid = false;
        bool messageDigestValid = false;
        bool signingCertificatePresent = false;
        bool signingCertificateValid = true;
        var seenRequiredAttributes = new HashSet<string>(StringComparer.Ordinal);
        var attributes = new AsnReader(signedAttributes, AsnEncodingRules.DER).ReadSetOf();
        while (attributes.HasData)
        {
            var attribute = attributes.ReadSequence();
            string oid = attribute.ReadObjectIdentifier();
            var values = attribute.ReadSetOf();
            if (!values.HasData)
            {
                return false;
            }
            if (oid == Oids.ContentType)
            {
                contentTypeValid = seenRequiredAttributes.Add(oid)
                    && values.ReadObjectIdentifier() == Oids.TimestampInfoContentType
                    && !values.HasData;
            }
            else if (oid == Oids.MessageDigest)
            {
                byte[] expected = digestOid switch
                {
                    Oids.Sha1 => SHA1.HashData(tstInfoBytes),
                    Oids.Sha256 => SHA256.HashData(tstInfoBytes),
                    Oids.Sha384 => SHA384.HashData(tstInfoBytes),
                    Oids.Sha512 => SHA512.HashData(tstInfoBytes),
                    Oids.Sha3_256 => SHA3_256.HashData(tstInfoBytes),
                    Oids.Sha3_384 => SHA3_384.HashData(tstInfoBytes),
                    Oids.Sha3_512 => SHA3_512.HashData(tstInfoBytes),
                    _ => []
                };
                byte[] actual = values.ReadOctetString();
                messageDigestValid = seenRequiredAttributes.Add(oid)
                    && expected.Length == actual.Length
                    && CryptographicOperations.FixedTimeEquals(expected, actual)
                    && !values.HasData;
            }
            else if (oid is Oids.SigningCertificate or Oids.SigningCertificateV2)
            {
                var signingCertificate = values.ReadSequence();
                var certs = signingCertificate.ReadSequence();
                var certIdentifier = certs.ReadSequence();
                string hashOid = Oids.Sha1;
                if (oid == Oids.SigningCertificateV2)
                {
                    hashOid = Oids.Sha256;
                    if (certIdentifier.PeekTag().HasSameClassAndValue(Asn1Tag.Sequence))
                    {
                        var algorithm = certIdentifier.ReadSequence();
                        hashOid = algorithm.ReadObjectIdentifier();
                    }
                }
                byte[] actual = certIdentifier.ReadOctetString();
                byte[] expected = hashOid switch
                {
                    Oids.Sha1 => SHA1.HashData(signerCertificate.RawData),
                    Oids.Sha256 => SHA256.HashData(signerCertificate.RawData),
                    Oids.Sha384 => SHA384.HashData(signerCertificate.RawData),
                    Oids.Sha512 => SHA512.HashData(signerCertificate.RawData),
                    Oids.Sha3_256 => SHA3_256.HashData(signerCertificate.RawData),
                    Oids.Sha3_384 => SHA3_384.HashData(signerCertificate.RawData),
                    Oids.Sha3_512 => SHA3_512.HashData(signerCertificate.RawData),
                    _ => []
                };
                signingCertificatePresent = true;
                signingCertificateValid &= seenRequiredAttributes.Add(oid)
                    && expected.Length == actual.Length
                    && CryptographicOperations.FixedTimeEquals(expected, actual)
                    && !values.HasData;
            }
        }

        if (!contentTypeValid || !messageDigestValid || !signingCertificatePresent || !signingCertificateValid)
        {
            warnings.Add("TSA signed attributes do not bind TSTInfo and the TSA certificate.");
            return false;
        }
        return true;
    }

    private static bool HasTimestampingEku(X509Certificate2? certificate, List<string> errors)
    {
        var eku = certificate?.Extensions.OfType<X509EnhancedKeyUsageExtension>().FirstOrDefault();
        if (eku is not null && eku.Critical && eku.EnhancedKeyUsages.Count == 1
            && eku.EnhancedKeyUsages[0]?.Value == "1.3.6.1.5.5.7.3.8")
        {
            return true;
        }

        errors.Add("TSA certificate lacks the critical, exclusive timeStamping EKU.");
        return false;
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
            Oids.Sha3_256 => SHA3_256.HashData(signatureValueBytes),
            Oids.Sha3_384 => SHA3_384.HashData(signatureValueBytes),
            Oids.Sha3_512 => SHA3_512.HashData(signatureValueBytes),
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

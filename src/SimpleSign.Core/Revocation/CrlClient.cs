using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Http;
using SimpleSign.Core.Validation;

namespace SimpleSign.Core.Revocation;

/// <summary>
/// CRL (Certificate Revocation List) client for certificate revocation checking.
/// Downloads CRLs, checks serial numbers, and verifies CRL signatures.
/// </summary>
public sealed class CrlClient : ICrlClient
{
    private readonly HttpClient _httpClient;
    private readonly ILogger _logger;

    /// <summary>Creates a CRL client with the specified HTTP client and optional logger.</summary>
    public CrlClient(HttpClient httpClient, ILogger? logger = null)
    {
        _httpClient = httpClient;
        _logger = logger ?? NullLogger.Instance;
    }

    /// <inheritdoc />
    public async Task<bool> CheckCrlAsync(X509Certificate2 cert, string crlUrl, CancellationToken ct)
    {
        _logger.CrlDownloading(crlUrl);
        var crlBytes = await ResilientHttp.GetBytesAsync(_httpClient, crlUrl, logger: _logger, ct: ct).ConfigureAwait(false)
            ?? throw new HttpRequestException($"CRL download failed after retries: {crlUrl}");
        _logger.CrlDownloaded(crlBytes.Length);
        bool? result = IsSerialInCrl(cert, crlBytes);
        // null means CRL could not be parsed or doesn't belong to this issuer — indeterminate
        return result switch
        {
            true => false,  // cert IS in CRL → revoked → not ok
            false => true,  // cert NOT in CRL → ok
            null => throw new RevocationCheckException(
                $"Online CRL from '{crlUrl}' could not be parsed or is not relevant for this certificate.",
                cert.Thumbprint, null, crlUrl is not null ? new Uri(crlUrl) : null)
        };
    }

    /// <summary>
    /// Verifies whether the certificate is in the CRL via ASN.1 parsing.
    /// Validates the CRL signature when possible.
    /// Returns: true = revoked, false = not revoked (CRL belongs to correct issuer), null = CRL does not belong to this issuer.
    /// </summary>
    internal static bool? IsSerialInCrl(X509Certificate2 cert, byte[] crlBytes, X509Certificate2? issuerCert = null, ILogger? logger = null, DateTimeOffset? signingTime = null)
    {
        // Parse ASN.1 correto da CRL (RFC 5280):
        // CertificateList ::= SEQUENCE {
        //   tbsCertList  TBSCertList,
        //   signatureAlgorithm  AlgorithmIdentifier,
        //   signatureValue  BIT STRING }
        // TBSCertList ::= SEQUENCE {
        //   version     [0] Version OPTIONAL,
        //   signature   AlgorithmIdentifier,
        //   issuer      Name,
        //   thisUpdate  Time,
        //   nextUpdate  Time OPTIONAL,
        //   revokedCertificates SEQUENCE OF SEQUENCE {
        //     userCertificate  CertificateSerialNumber,  ← INTEGER comparado aqui
        //     revocationDate   Time,
        //     crlEntryExtensions Extensions OPTIONAL } OPTIONAL,
        //   crlExtensions [0] EXPLICIT Extensions OPTIONAL }
        try
        {
            var certSerial = new System.Numerics.BigInteger(
                cert.SerialNumberBytes.Span, isUnsigned: false, isBigEndian: true);

            // Accepts BER since some Brazilian CAs do not emit strict DER
            var reader = new AsnReader(crlBytes, AsnEncodingRules.BER);
            var crlSeq = reader.ReadSequence();

            // Keep raw tbsCertList for signature verification
            byte[] tbsCrlRaw = crlSeq.PeekEncodedValue().ToArray();
            var tbsCrl = crlSeq.ReadSequence();

            // signatureAlgorithm (outer)
            var crlSigAlgSeq = crlSeq.ReadSequence();
            string crlSigAlgOid = crlSigAlgSeq.ReadObjectIdentifier();
            byte[]? crlSigAlgParams = null;
            if (crlSigAlgSeq.HasData)
            {
                crlSigAlgParams = crlSigAlgSeq.ReadEncodedValue().ToArray();
            }

            // signatureValue BIT STRING (outer)
            byte[] crlSignature = crlSeq.ReadBitString(out _);

            // version Version OPTIONAL — bare INTEGER (tag Universal 2), present in v2 CRLs.
            // RFC 5280 TBSCertList defines version as a plain INTEGER with no context wrapper.
            if (tbsCrl.HasData && tbsCrl.PeekTag() == new Asn1Tag(TagClass.Universal, (int)UniversalTagNumber.Integer, false))
            {
                tbsCrl.ReadEncodedValue();
            }

            // signature AlgorithmIdentifier
            tbsCrl.ReadSequence();
            // issuer Name — verify if it matches the certificate issuer
            byte[] crlIssuer = tbsCrl.ReadEncodedValue().ToArray();

            // If the CRL issuer does not match the certificate issuer, this CRL is not relevant.
            // Check BEFORE signature verification to avoid calling VerifyCrlSignature with the wrong
            // issuer key (which would throw CryptographicException when iterating a chain's CRL set).
            if (!IssuerMatchesCertificate(crlIssuer, cert.IssuerName))
            {
                logger?.CrlIssuerMismatch();
                return null;
            }

            // Verify CRL signature with issuer cert (only after confirming the issuer matches).
            // Return null (indeterminate) instead of throwing if verification fails — some Brazilian CAs
            // emit CRLs with non-standard BER encodings that cause false failures on .NET.
            // The caller falls through to an online CRL download as a safe fallback.
            if (issuerCert is not null)
            {
                bool sigValid = VerifyCrlSignature(issuerCert, tbsCrlRaw, crlSignature, crlSigAlgOid, crlSigAlgParams, logger);
                if (!sigValid)
                {
                    logger?.CrlSignatureVerificationFailed("CRL signature check failed — falling back to online CRL");
                    return null;
                }
            }

            // thisUpdate Time
            DateTimeOffset? thisUpdate = null;
            if (tbsCrl.HasData)
            {
                var tag = tbsCrl.PeekTag();
                if (tag.TagValue is 0x17 or 0x18 && tag.TagClass == TagClass.Universal)
                {
                    try
                    {
                        thisUpdate = tag.TagValue == 0x17
                            ? tbsCrl.ReadUtcTime()
                            : tbsCrl.ReadGeneralizedTime();
                    }
                    catch (AsnContentException)
                    {
                        tbsCrl.ReadEncodedValue();
                    }
                }
            }

            // nextUpdate Time OPTIONAL — P0: verify expiration
            DateTimeOffset? nextUpdate = null;
            if (tbsCrl.HasData)
            {
                var tag = tbsCrl.PeekTag();
                // UTCTime = 0x17, GeneralizedTime = 0x18
                if (tag.TagValue is 0x17 or 0x18 && tag.TagClass == TagClass.Universal)
                {
                    try
                    {
                        nextUpdate = tag.TagValue == 0x17
                            ? tbsCrl.ReadUtcTime()
                            : tbsCrl.ReadGeneralizedTime();
                    }
                    catch (AsnContentException ex)
                    {
                        logger?.CrlNextUpdateParsingFailed(ex.Message);
                        tbsCrl.ReadEncodedValue();
                    }
                }
            }

            // When a signing time is provided (B-LT validation), verify the CRL was valid at that moment.
            // Without it (online freshness check), verify against current time.
            var referenceTime = signingTime ?? DateTimeOffset.UtcNow;

            // CRL was already expired at signing time → not valid for this signing event
            if (nextUpdate.HasValue && nextUpdate.Value < referenceTime)
            {
                logger?.CrlExpired(nextUpdate.Value, referenceTime);
                return null;
            }

            // CRL was issued after the signing time → cannot cover this signing event
            if (signingTime.HasValue && thisUpdate.HasValue && thisUpdate.Value > signingTime.Value)
            {
                logger?.CrlIssuedAfterSigningTime(thisUpdate.Value, signingTime.Value);
                return null;
            }

            // revokedCertificates SEQUENCE OF OPTIONAL
            if (!tbsCrl.HasData)
            {
                return false;
            }
            var nextTag = tbsCrl.PeekTag();
            if (nextTag is not { TagClass: TagClass.Universal, TagValue: (int)UniversalTagNumber.Sequence })
            {
                return false; // no revoked entries
            }

            var revokedList = tbsCrl.ReadSequence();
            while (revokedList.HasData)
            {
                var entry = revokedList.ReadSequence();
                // userCertificate INTEGER
                var revokedSerial = entry.ReadInteger();
                if (revokedSerial == certSerial)
                {
                    return true; // certificate is revoked
                }
            }

            return false; // not found in CRL
        }
        catch (AsnContentException ex)
        {
            logger?.CrlSerialCheckParsingFailed(ex.Message);
            return null;
        }
    }

    /// <summary>
    /// Compares a CRL issuer (raw DER bytes) against a certificate's issuer DN.
    /// First attempts an exact raw-byte match (fast path). If that fails, falls back to a
    /// normalized string comparison to tolerate encoding differences between CAs that use
    /// different ASN.1 string types (UTF8String vs PrintableString) for the same DN value.
    /// This is common in Brazilian ICP-Brasil / Gov.br CAs.
    /// </summary>
    private static bool IssuerMatchesCertificate(byte[] crlIssuerBytes, X500DistinguishedName certIssuer)
    {
        if (crlIssuerBytes.AsSpan().SequenceEqual(certIssuer.RawData))
        {
            return true; // exact DER match
        }

        // Fallback: normalize both DNs to string and compare case-insensitively.
        // X500DistinguishedName.Name decodes the string values regardless of their ASN.1 string type.
        try
        {
            var crlIssuerDn = new X500DistinguishedName(crlIssuerBytes);
            if (string.Equals(crlIssuerDn.Name, certIssuer.Name, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            const X500DistinguishedNameFlags flags =
                X500DistinguishedNameFlags.Reversed |
                X500DistinguishedNameFlags.UseCommas |
                X500DistinguishedNameFlags.DoNotUsePlusSign |
                X500DistinguishedNameFlags.DoNotUseQuotes;

            return string.Equals(
                crlIssuerDn.Decode(flags),
                certIssuer.Decode(flags),
                StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    internal static bool VerifyCrlSignature(
        X509Certificate2 issuerCert,
        byte[] tbsData,
        byte[] signature,
        string sigAlgOid,
        byte[]? sigAlgParams = null,
        ILogger? logger = null)
    {
        try
        {
            using var rsa = issuerCert.GetRSAPublicKey();
            if (rsa is not null)
            {
                var hashAlg = sigAlgOid == Oids.RsaPss
                    ? CryptoUtility.ParsePssHashAlgorithm(sigAlgParams ?? [])
                    : sigAlgOid switch
                    {
                        Oids.RsaSha256 => HashAlgorithmName.SHA256,
                        Oids.RsaSha384 => HashAlgorithmName.SHA384,
                        Oids.RsaSha512 => HashAlgorithmName.SHA512,
                        Oids.RsaSha1 => HashAlgorithmName.SHA1,
                        _ => HashAlgorithmName.SHA256
                    };
                var padding = sigAlgOid == Oids.RsaPss ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1;
                return rsa.VerifyData(tbsData, signature, hashAlg, padding);
            }

            using var ecdsa = issuerCert.GetECDsaPublicKey();
            if (ecdsa is not null)
            {
                var hashAlg = sigAlgOid switch
                {
                    Oids.EcdsaSha256 => HashAlgorithmName.SHA256,
                    Oids.EcdsaSha384 => HashAlgorithmName.SHA384,
                    Oids.EcdsaSha512 => HashAlgorithmName.SHA512,
                    _ => HashAlgorithmName.SHA256
                };
                return ecdsa.VerifyData(tbsData, signature, hashAlg);
            }

            return false; // unsupported key type
        }
        catch (CryptographicException ex) { logger?.CrlSignatureVerificationFailed(ex.Message); return false; }
    }

    internal static string? GetCrlUrl(X509Certificate2 cert, ILogger? logger = null)
    {
        var cdp = cert.Extensions[Oids.CrlDistributionPoints];
        if (cdp is null)
        {
            return null;
        }

        try
        {
            // Use BER: X.509 allows CAs to encode extension values in BER (not strict DER)
            var reader = new AsnReader(cdp.RawData, AsnEncodingRules.BER);
            var cdpSeq = reader.ReadSequence();
            while (cdpSeq.HasData)
            {
                var dp = cdpSeq.ReadSequence();
                if (!dp.HasData)
                {
                    continue;
                }

                // distributionPoint [0] EXPLICIT DistributionPointName
                if (dp.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 0, true))
                {
                    var dpNameWrapper = dp.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true));
                    // fullName [0] IMPLICIT GeneralNames (SEQUENCE OF GeneralName)
                    if (dpNameWrapper.HasData &&
                        dpNameWrapper.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 0, true))
                    {
                        var generalNames = dpNameWrapper.ReadSequence(
                            new Asn1Tag(TagClass.ContextSpecific, 0, true));
                        while (generalNames.HasData)
                        {
                            var gn = generalNames.PeekTag();
                            // [6] uniformResourceIdentifier
                            if (gn.TagClass == TagClass.ContextSpecific && gn.TagValue == 6)
                            {
                                string uri = generalNames.ReadCharacterString(
                                    UniversalTagNumber.IA5String,
                                    new Asn1Tag(TagClass.ContextSpecific, 6));
                                if (uri.StartsWith("http", StringComparison.OrdinalIgnoreCase))
                                {
                                    return uri;
                                }
                            }
                            else
                            {
                                generalNames.ReadEncodedValue();
                            }
                        }
                    }
                }
            }
        }
        catch (AsnContentException ex) { logger?.CrlUrlExtensionParsingFailed(ex.Message); }
        return null;
    }

    /// <summary>
    /// Extracts the issuer DN (Distinguished Name) raw bytes from a DER-encoded CRL.
    /// Used by the LTV stabilisation loop to identify CRL issuers that differ from
    /// the certificate issuer (indirect CRL issuers).
    /// Returns null if the CRL cannot be parsed.
    /// </summary>
    internal static byte[]? ExtractCrlIssuerDn(byte[] crlBytes, ILogger? logger = null)
    {
        try
        {
            var crlReader = new AsnReader(crlBytes, AsnEncodingRules.BER);
            var certList = crlReader.ReadSequence();
            var tbsCrl = certList.ReadSequence();

            // version Version OPTIONAL — bare INTEGER
            if (tbsCrl.HasData && tbsCrl.PeekTag() == new Asn1Tag(TagClass.Universal, (int)UniversalTagNumber.Integer, false))
            {
                tbsCrl.ReadEncodedValue();
            }

            // signature AlgorithmIdentifier
            tbsCrl.ReadSequence();

            // issuer Name
            return tbsCrl.ReadEncodedValue().ToArray();
        }
        catch (Exception ex) when (ex is AsnContentException or CryptographicException or InvalidOperationException)
        {
            logger?.CrlUrlExtensionParsingFailed($"Failed to extract CRL issuer: {ex.Message}");
            return null;
        }
    }

}

using System.Formats.Asn1;
using System.Numerics;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using SimpleSign.Core.Internal;

namespace SimpleSign.Core.Revocation;

/// <summary>The status of a certificate according to one CRL, at a given time.</summary>
public enum CrlStatus
{
    /// <summary>The CRL does not apply: other issuer, bad signature, malformed, or not current at the time.</summary>
    NotApplicable,

    /// <summary>The CRL covers the time and the certificate was not revoked at that time.</summary>
    Good,

    /// <summary>The certificate was revoked at or before the time.</summary>
    Revoked,
}

/// <summary>
/// Evaluates a CRL for a certificate at a point in time (RFC 5280 §6.3, ETSI EN 319 102-1 §5.2.5):
/// the CRL must be signed by the issuer and either be current at that time or have been issued
/// after it; an entry counts only when its revocationDate is not after that time.
/// </summary>
public static class CrlEvaluator
{
    /// <summary>Evaluates <paramref name="crlBytes"/> for <paramref name="certificate"/> at <paramref name="time"/>.</summary>
    /// <param name="certificate">The certificate whose status is wanted.</param>
    /// <param name="crlBytes">The DER (or BER) encoded CRL.</param>
    /// <param name="issuer">The certificate's issuer; the CRL signature must verify with its key.</param>
    /// <param name="time">The time of interest (signature timestamp time, or now).</param>
    /// <param name="logger">Optional logger.</param>
    /// <returns>The status of the certificate according to this CRL.</returns>
    public static CrlStatus Evaluate(
        X509Certificate2 certificate, byte[] crlBytes, X509Certificate2 issuer, DateTimeOffset time, ILogger? logger = null)
    {
        try
        {
            var crl = new AsnReader(crlBytes, AsnEncodingRules.BER).ReadSequence();
            byte[] tbsRaw = crl.PeekEncodedValue().ToArray();
            var tbs = crl.ReadSequence();
            var sigAlg = crl.ReadSequence();
            string sigAlgOid = sigAlg.ReadObjectIdentifier();
            byte[]? sigAlgParams = sigAlg.HasData ? sigAlg.ReadEncodedValue().ToArray() : null;
            byte[] signature = crl.ReadBitString(out _);

            if (tbs.PeekTag() == Asn1Tag.Integer)
            {
                tbs.ReadEncodedValue(); // version
            }

            tbs.ReadSequence(); // signature AlgorithmIdentifier
            byte[] crlIssuer = tbs.ReadEncodedValue().ToArray();
            if (!CrlClient.IssuerMatchesCertificate(crlIssuer, certificate.IssuerName)
                || !CrlClient.VerifyCrlSignature(issuer, tbsRaw, signature, sigAlgOid, sigAlgParams, logger))
            {
                return CrlStatus.NotApplicable;
            }

            DateTimeOffset thisUpdate = ReadTime(tbs);
            DateTimeOffset? nextUpdate = tbs.HasData && IsTime(tbs.PeekTag()) ? ReadTime(tbs) : null;

            // Current at the time, or issued after it (a later CRL still lists earlier revocations).
            if (thisUpdate < time && nextUpdate < time)
            {
                return CrlStatus.NotApplicable;
            }

            if (tbs.HasData && tbs.PeekTag() == Asn1Tag.Sequence)
            {
                var serial = new BigInteger(certificate.SerialNumberBytes.Span, isUnsigned: false, isBigEndian: true);
                var entries = tbs.ReadSequence();
                while (entries.HasData)
                {
                    var entry = entries.ReadSequence();
                    if (entry.ReadInteger() == serial)
                    {
                        return ReadTime(entry) <= time ? CrlStatus.Revoked : CrlStatus.Good;
                    }
                }
            }

            return CrlStatus.Good;
        }
        catch (AsnContentException ex)
        {
            logger?.CrlSerialCheckParsingFailed(ex.Message);
            return CrlStatus.NotApplicable;
        }
    }

    /// <summary>The nextUpdate of a CRL, or null when it has none or cannot be parsed.</summary>
    /// <param name="crlBytes">The DER (or BER) encoded CRL.</param>
    /// <returns>The nextUpdate time, or <see langword="null"/>.</returns>
    public static DateTimeOffset? ReadNextUpdate(byte[] crlBytes)
    {
        try
        {
            var tbs = new AsnReader(crlBytes, AsnEncodingRules.BER).ReadSequence().ReadSequence();
            if (tbs.PeekTag() == Asn1Tag.Integer)
            {
                tbs.ReadEncodedValue(); // version
            }

            tbs.ReadSequence();       // signature
            tbs.ReadEncodedValue();   // issuer
            ReadTime(tbs);            // thisUpdate
            return tbs.HasData && IsTime(tbs.PeekTag()) ? ReadTime(tbs) : null;
        }
        catch (AsnContentException)
        {
            return null;
        }
    }

    /// <summary>The thisUpdate of a CRL (when it was issued), or null when it cannot be parsed.</summary>
    /// <param name="crlBytes">The DER (or BER) encoded CRL.</param>
    /// <returns>The thisUpdate time, or <see langword="null"/>.</returns>
    public static DateTimeOffset? ReadThisUpdate(byte[] crlBytes)
    {
        try
        {
            var tbs = new AsnReader(crlBytes, AsnEncodingRules.BER).ReadSequence().ReadSequence();
            if (tbs.PeekTag() == Asn1Tag.Integer)
            {
                tbs.ReadEncodedValue(); // version
            }

            tbs.ReadSequence();       // signature
            tbs.ReadEncodedValue();   // issuer
            return ReadTime(tbs);
        }
        catch (AsnContentException)
        {
            return null;
        }
    }

    private static bool IsTime(Asn1Tag tag) =>
        tag.TagClass == TagClass.Universal && tag.TagValue is (int)UniversalTagNumber.UtcTime or (int)UniversalTagNumber.GeneralizedTime;

    private static DateTimeOffset ReadTime(AsnReader reader) =>
        reader.PeekTag().TagValue == (int)UniversalTagNumber.UtcTime
            ? reader.ReadUtcTime()
            : reader.ReadGeneralizedTime();
}

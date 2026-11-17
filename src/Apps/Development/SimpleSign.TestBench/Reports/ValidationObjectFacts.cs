using System.Formats.Asn1;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace SimpleSign.TestBench.Reports;

/// <summary>What a CRL or an OCSP response says, as far as the report viewer needs it.</summary>
/// <param name="Issuer">Who issued it: the CRL issuer, or the OCSP responder (by name).</param>
/// <param name="ProducedAt">When the OCSP response was produced (null for a CRL).</param>
/// <param name="ThisUpdate">Its thisUpdate.</param>
/// <param name="NextUpdate">Its nextUpdate, or null.</param>
/// <param name="Serial">For an OCSP response, the serial number of the certificate it is about (its first answer).</param>
/// <param name="Status">For an OCSP response, that certificate's status: GOOD, REVOKED or UNKNOWN.</param>
internal sealed record RevocationFacts(string? Issuer, DateTimeOffset? ProducedAt, DateTimeOffset? ThisUpdate, DateTimeOffset? NextUpdate, BigInteger? Serial, string? Status);

/// <summary>
/// Reads the timestamps, CRLs and OCSP responses a validation used (the DER in <c>ValidationObjectEntry.Data</c>), tolerantly:
/// what cannot be read is left out of the report, never an error.
/// </summary>
internal static class ValidationObjectFacts
{
    private const string BasicOcspOid = "1.3.6.1.5.5.7.48.1.1";

    /// <summary>The certificate of the TSA that signed a timestamp token, or null.</summary>
    public static X509Certificate2? TimestampSigner(ReadOnlyMemory<byte> token)
    {
        try
        {
            return Core.Crypto.CmsParser.ParseAll(token.ToArray()).Signers.FirstOrDefault()?.SignerCertificate;
        }
        catch (Exception ex) when (ex is CryptographicException or AsnContentException or ArgumentException or InvalidOperationException or IndexOutOfRangeException)
        {
            return null;
        }
    }

    /// <summary>The issuer and dates of a CRL (RFC 5280 §5.1), or null when it is not one.</summary>
    public static RevocationFacts? Crl(ReadOnlyMemory<byte> der)
    {
        try
        {
            var tbs = new AsnReader(der, AsnEncodingRules.DER).ReadSequence().ReadSequence();
            if (tbs.PeekTag().HasSameClassAndValue(Asn1Tag.Integer))
            {
                tbs.ReadInteger();
            }

            tbs.ReadSequence(); // signature algorithm
            string issuer = new X500DistinguishedName(tbs.ReadEncodedValue().Span).Name;
            var thisUpdate = ReadTime(tbs);
            DateTimeOffset? nextUpdate = tbs.HasData && IsTime(tbs.PeekTag()) ? ReadTime(tbs) : null;
            return new RevocationFacts(issuer, null, thisUpdate, nextUpdate, null, null);
        }
        catch (Exception ex) when (ex is AsnContentException or CryptographicException or ArgumentException)
        {
            return null;
        }
    }

    /// <summary>
    /// The responder, dates and first answer of an OCSP response (RFC 6960 §4.2.1): a whole OCSPResponse or only its
    /// BasicOCSPResponse. Null when it is neither.
    /// </summary>
    public static RevocationFacts? Ocsp(ReadOnlyMemory<byte> der)
    {
        try
        {
            var basic = BasicResponse(der);
            var tbs = new AsnReader(basic, AsnEncodingRules.DER).ReadSequence().ReadSequence();
            if (tbs.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0, true)))
            {
                tbs.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true)); // version
            }

            string? responder = null;
            var responderTag = tbs.PeekTag();
            if (responderTag.HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 1, true)))
            {
                var byName = tbs.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 1, true));
                responder = new X500DistinguishedName(byName.ReadEncodedValue().Span).Name;
            }
            else
            {
                tbs.ReadEncodedValue(); // by key hash
            }

            var producedAt = tbs.ReadGeneralizedTime();
            var responses = tbs.ReadSequence();
            BigInteger? serial = null;
            string? status = null;
            DateTimeOffset? thisUpdate = null;
            DateTimeOffset? nextUpdate = null;
            if (responses.HasData)
            {
                var single = responses.ReadSequence();
                var certId = single.ReadSequence();
                certId.ReadSequence(); // hash algorithm
                certId.ReadOctetString();
                certId.ReadOctetString();
                serial = certId.ReadInteger();
                var statusTag = single.PeekTag();
                status = statusTag.TagClass == TagClass.ContextSpecific
                    ? statusTag.TagValue switch { 0 => "GOOD", 1 => "REVOKED", _ => "UNKNOWN" }
                    : null;
                single.ReadEncodedValue();
                thisUpdate = single.ReadGeneralizedTime();
                if (single.HasData && single.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0, true)))
                {
                    nextUpdate = single.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true)).ReadGeneralizedTime();
                }
            }

            return new RevocationFacts(responder, producedAt, thisUpdate, nextUpdate, serial, status);
        }
        catch (Exception ex) when (ex is AsnContentException or CryptographicException or ArgumentException or InvalidOperationException)
        {
            return null;
        }
    }

    /// <summary>The BasicOCSPResponse: unwrapped from an OCSPResponse, or the input when it already is one.</summary>
    private static ReadOnlyMemory<byte> BasicResponse(ReadOnlyMemory<byte> der)
    {
        var outer = new AsnReader(der, AsnEncodingRules.DER).ReadSequence();
        if (!outer.PeekTag().HasSameClassAndValue(Asn1Tag.Enumerated))
        {
            return der;
        }

        outer.ReadEnumeratedBytes();
        var bytes = outer.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true)).ReadSequence();
        string type = bytes.ReadObjectIdentifier();
        return type == BasicOcspOid ? bytes.ReadOctetString() : throw new AsnContentException("Not a basic OCSP response.");
    }

    private static bool IsTime(Asn1Tag tag) => tag.HasSameClassAndValue(Asn1Tag.UtcTime) || tag.HasSameClassAndValue(Asn1Tag.GeneralizedTime);

    private static DateTimeOffset ReadTime(AsnReader reader) =>
        reader.PeekTag().HasSameClassAndValue(Asn1Tag.UtcTime) ? reader.ReadUtcTime() : reader.ReadGeneralizedTime();
}

using System.Formats.Asn1;

namespace SimpleSign.Core.Validation;

/// <summary>
/// Reads the revocation data a signature carries (CAdES <c>revocation-values</c>, ETSI EN 319 122-1 §5.5.2), in the
/// form the revocation checkers take: CRLs and full OCSPResponses.
/// </summary>
internal static class EmbeddedRevocationValues
{
    private const string BasicOcspResponse = "1.3.6.1.5.5.7.48.1.1";

    /// <summary>The CRLs and OCSP responses of the attribute values; empty lists when none can be read.</summary>
    /// <param name="attributeValues">The values of the revocation-values attributes (each a DER <c>RevocationValues</c>).</param>
    internal static (List<byte[]> Crls, List<byte[]> Ocsps) Read(IEnumerable<byte[]>? attributeValues)
    {
        var crls = new List<byte[]>();
        var ocsps = new List<byte[]>();
        foreach (byte[] value in attributeValues ?? [])
        {
            try
            {
                // RevocationValues ::= SEQUENCE { crlVals [0] SEQUENCE OF CertificateList OPTIONAL,
                //   ocspVals [1] SEQUENCE OF BasicOCSPResponse OPTIONAL, otherRevVals [2] OtherRevVals OPTIONAL }
                var values = new AsnReader(value, AsnEncodingRules.BER).ReadSequence();
                while (values.HasData)
                {
                    var tag = values.PeekTag();
                    if (tag.HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0)))
                    {
                        var list = values.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
                        while (list.HasData)
                        {
                            crls.Add(list.ReadEncodedValue().ToArray());
                        }
                    }
                    else if (tag.HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 1)))
                    {
                        var list = values.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 1));
                        while (list.HasData)
                        {
                            ocsps.Add(WrapBasicResponse(list.ReadEncodedValue().Span));
                        }
                    }
                    else
                    {
                        values.ReadEncodedValue();
                    }
                }
            }
            catch (AsnContentException)
            {
                // Not readable: the online sources decide.
            }
        }

        return (crls, ocsps);
    }

    /// <summary>A BasicOCSPResponse inside an OCSPResponse { successful, responseBytes { id-pkix-ocsp-basic, … } }.</summary>
    internal static byte[] WrapBasicResponse(ReadOnlySpan<byte> basicResponse)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            writer.WriteEncodedValue([0x0A, 0x01, 0x00]); // responseStatus ENUMERATED successful (0)
            using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true)))
            using (writer.PushSequence())
            {
                writer.WriteObjectIdentifier(BasicOcspResponse);
                writer.WriteOctetString(basicResponse);
            }
        }

        return writer.Encode();
    }
}

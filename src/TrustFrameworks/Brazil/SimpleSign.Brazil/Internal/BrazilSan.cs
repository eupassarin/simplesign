using System.Formats.Asn1;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using SimpleSign.Core.Constants;

namespace SimpleSign.Brazil.Internal;

/// <summary>
/// The SubjectAltName otherNames that ICP-Brasil and Gov.br certificates share
/// (DOC-ICP-04: holder data, CPF, CNPJ, professional registrations).
/// </summary>
internal static class BrazilSan
{
    /// <summary>Reads every otherName (OID and decoded text) of the certificate's SubjectAltName.</summary>
    internal static List<(string Oid, string Value)> ReadOtherNames(X509Certificate2 certificate, ILogger? logger)
    {
        var result = new List<(string, string)>();
        var sanExt = certificate.Extensions[Oids.SubjectAltName];
        if (sanExt is null)
        {
            return result;
        }

        try
        {
            var seq = new AsnReader(sanExt.RawData, AsnEncodingRules.BER).ReadSequence();
            while (seq.HasData)
            {
                var tag = seq.PeekTag();
                // otherName [0] IMPLICIT SEQUENCE { typeId OID, value [0] EXPLICIT ANY }
                if (tag.TagClass == TagClass.ContextSpecific && tag.TagValue == 0)
                {
                    var otherName = seq.ReadSequence(tag);
                    string oid = otherName.ReadObjectIdentifier();
                    if (otherName.HasData)
                    {
                        var valueWrapper = otherName.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true));
                        result.Add((oid, ExtractStringFromAsn1Value(valueWrapper.ReadEncodedValue().ToArray())));
                    }
                }
                else
                {
                    seq.ReadEncodedValue(); // skip non-otherName entries
                }
            }
        }
        catch (AsnContentException ex) { logger?.SanParsingFailed(ex.Message); }
        catch (InvalidOperationException ex) { logger?.SanParsingFailed(ex.Message); }

        return result;
    }

    private static string ExtractStringFromAsn1Value(byte[] encoded)
    {
        try
        {
            var r = new AsnReader(encoded, AsnEncodingRules.BER);
            var tag = r.PeekTag();
            // UTF8String(12), PrintableString(19), IA5String(22), OctetString(4)
            if (tag.TagValue is 12 or 19 or 22)
            {
                return r.ReadCharacterString((UniversalTagNumber)tag.TagValue);
            }
            if (tag.TagValue == 4)
            {
                return System.Text.Encoding.UTF8.GetString(r.ReadOctetString());
            }
            var encodedValue = r.ReadEncodedValue().Span;
            int headerSize = encodedValue[1] switch
            {
                <= 127 => 2,
                0x81 => 3,
                0x82 => 4,
                _ => 2,
            };
            return System.Text.Encoding.UTF8.GetString(encodedValue[headerSize..]);
        }
        catch (AsnContentException)
        {
            return System.Text.Encoding.UTF8.GetString(encoded);
        }
    }

    /// <summary>
    /// The CPF in an ICP-Brasil holder-data field (birth date ddMMyyyy followed by the CPF),
    /// or null when the field is too short or the CPF is not valid.
    /// </summary>
    internal static string? CpfFromHolderData(string? value)
    {
        if (value is null || value.Length < 19)
        {
            return null;
        }

        string candidate = value.Substring(8, 11);
        return BrazilDocuments.IsValidCpf(candidate) ? candidate : null;
    }
}

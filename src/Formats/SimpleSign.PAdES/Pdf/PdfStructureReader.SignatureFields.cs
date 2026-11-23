using Microsoft.Extensions.Logging;
using SimpleSign.PAdES.Internal;
using SimpleSign.PAdES.Pdf.Model;

namespace SimpleSign.PAdES.Pdf;

public sealed partial class PdfStructureReader
{
    #region Signature Field Extraction

    /// <summary>
    /// The signature fields of a document's latest revision, read through the object model (ADR 0032): every signature
    /// dictionary with a <c>/ByteRange</c> of four integers, in file order, but usage-rights ones. The field name is the
    /// holding field's partial name (<c>/T</c>), or <c>Signature_N</c> for an orphan; the CMS is read from the byte
    /// range's gap, the bytes the signature leaves out.
    /// </summary>
    /// <exception cref="Exceptions.EncryptedPdfException">The document is encrypted.</exception>
    /// <exception cref="Exceptions.PdfStructureException">The document has no catalog that can be read.</exception>
    internal static IReadOnlyList<PdfSignatureField> ReadSignatureFields(PdfDocument document)
    {
        ThrowIfEncrypted(document);

        // A file with no catalog to read is refused, as it always was (it had no startxref, or nothing at it).
        if (document.Catalog is null)
        {
            throw new Exceptions.PdfStructureException(document.StartXref < 0
                ? "PDF is missing 'startxref' marker, and no catalog was found in it."
                : "The PDF's catalog cannot be read.");
        }

        var data = document.Data.Span;
        var fields = new List<PdfSignatureField>();
        foreach (var signature in document.View().Signatures)
        {
            if (signature.IsUsageRights || signature.ByteRange is not [long offset1, long length1, long offset2, long length2])
            {
                continue;
            }

            var byteRange = new PdfByteRange { Offset1 = offset1, Length1 = length1, Offset2 = offset2, Length2 = length2 };
            int number = signature.Id?.Number ?? signature.Field?.Id?.Number ?? 0;
            fields.Add(new PdfSignatureField
            {
                FieldName = string.IsNullOrEmpty(signature.Field?.PartialName) ? $"Signature_{number}" : signature.Field.PartialName,
                ByteRange = byteRange,
                ContentsBytes = ExtractContents(byteRange, data),
                SigDictObjectNumber = number,
                PdfSigningTime = signature.Text("M") is { } time ? ParsePdfDate(time) : null,
                Filter = signature.Name("Filter"),
                SubFilter = signature.Name("SubFilter"),
                Reason = NullIfEmpty(signature.Text("Reason")),
                Location = NullIfEmpty(signature.Text("Location")),
                ContactInfo = NullIfEmpty(signature.Text("ContactInfo")),
                SignerName = NullIfEmpty(signature.Text("Name")),
            });
        }

        return fields.AsReadOnly();
    }

    /// <summary>An empty text string is no value, as the reader has always reported it.</summary>
    private static string? NullIfEmpty(string? text) => string.IsNullOrEmpty(text) ? null : text;

    /// <summary>
    /// Parses a PDF date string (D:YYYYMMDDHHmmss±HH'mm') into a DateTimeOffset.
    /// </summary>
    private static DateTimeOffset? ParsePdfDate(string dateStr, ILogger? logger = null)
    {
        // Strip "D:" prefix
        if (dateStr.StartsWith("D:", StringComparison.OrdinalIgnoreCase))
        {
            dateStr = dateStr[2..];
        }

        if (dateStr.Length < 14)
        {
            return null;
        }

        if (!int.TryParse(dateStr[0..4], out int year))
        {
            return null;
        }
        if (!int.TryParse(dateStr[4..6], out int month))
        {
            return null;
        }
        if (!int.TryParse(dateStr[6..8], out int day))
        {
            return null;
        }
        if (!int.TryParse(dateStr[8..10], out int hour))
        {
            return null;
        }
        if (!int.TryParse(dateStr[10..12], out int minute))
        {
            return null;
        }
        if (!int.TryParse(dateStr[12..14], out int second))
        {
            return null;
        }

        // Parse timezone offset (e.g., +03'00', -05'30', Z)
        var tzOffset = TimeSpan.Zero;
        if (dateStr.Length > 14)
        {
            char sign = dateStr[14];
            if ((sign == '+' || sign == '-')
                && dateStr.Length >= 20
                && int.TryParse(dateStr[15..17], out int tzHours)
                && int.TryParse(dateStr[18..20], out int tzMinutes))
            {
                tzOffset = new TimeSpan(tzHours, tzMinutes, 0);
                if (sign == '-')
                {
                    tzOffset = -tzOffset;
                }
            }
        }

        try
        {
            return new DateTimeOffset(year, month, day, hour, minute, second, tzOffset);
        }
        catch (Exception ex) when (ex is ArgumentOutOfRangeException or ArgumentException)
        {
            logger?.PdfDateParsingFailed(ex.Message);
            return null;
        }
    }

    /// <summary>
    /// Extracts the /Contents hex string between the two ByteRange segments.
    /// The Contents field contains the CMS/PKCS#7 signature in hex encoding.
    /// </summary>
    private static byte[] ExtractContents(PdfByteRange byteRange, ReadOnlySpan<byte> fullData)
    {
        long gapStart = byteRange.Offset1 + byteRange.Length1;
        long gapEnd = byteRange.Offset2;

        if (gapStart >= fullData.Length || gapEnd > fullData.Length || gapStart >= gapEnd
            || gapStart > int.MaxValue || gapEnd > int.MaxValue)
        {
            return [];
        }

        ReadOnlySpan<byte> gapRegion = fullData[(int)gapStart..(int)gapEnd];

        // Find hex string delimiters: <hexdata>, skipping comments (% to end of line)
        // that may appear between the ByteRange segments.
        int hexStart = -1;
        int hexEnd = -1;
        for (int i = 0; i < gapRegion.Length; i++)
        {
            if (gapRegion[i] == (byte)'%')
            {
                while (i < gapRegion.Length && gapRegion[i] != (byte)'\n' && gapRegion[i] != (byte)'\r')
                {
                    i++;
                }
                continue;
            }

            if (gapRegion[i] == '<' && hexStart < 0)
            {
                hexStart = i;
            }
            if (gapRegion[i] == '>')
            {
                hexEnd = i;
                break;
            }
        }

        if (hexStart < 0 || hexEnd <= hexStart)
        {
            return [];
        }

        return HexDecode(gapRegion[(hexStart + 1)..hexEnd]);
    }

    /// <summary>The bytes of a hexadecimal string's digits, white-space skipped; empty when their number is odd.</summary>
    private static byte[] HexDecode(ReadOnlySpan<byte> hex)
    {
        var digits = new List<byte>(hex.Length);
        foreach (byte b in hex)
        {
            if (b is not ((byte)' ' or (byte)'\n' or (byte)'\r' or (byte)'\t'))
            {
                digits.Add(b);
            }
        }

        if (digits.Count % 2 != 0)
        {
            return [];
        }

        byte[] result = new byte[digits.Count / 2];
        for (int i = 0; i < result.Length; i++)
        {
            result[i] = (byte)((Nibble(digits[i * 2]) << 4) | Nibble(digits[(i * 2) + 1]));
        }

        return result;
    }

    private static int Nibble(byte b) => b switch
    {
        >= (byte)'0' and <= (byte)'9' => b - '0',
        >= (byte)'a' and <= (byte)'f' => b - 'a' + 10,
        >= (byte)'A' and <= (byte)'F' => b - 'A' + 10,
        _ => 0,
    };
    #endregion
}

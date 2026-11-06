using System.Text;
using Microsoft.Extensions.Logging;
using SimpleSign.PAdES.Internal;

namespace SimpleSign.PAdES.Pdf;

public sealed partial class PdfStructureReader
{
    #region Signature Field Extraction

    /// <summary>
    /// Scans the PDF data for /ByteRange markers and extracts signature field metadata.
    /// </summary>
    private static IReadOnlyList<PdfSignatureField> ExtractSignatureFields(
        ReadOnlySpan<byte> data, List<PdfCrossRef> crossRefs)
    {
        var fields = new List<PdfSignatureField>();
        int skipUntil = 0;

        foreach (var (byteRangePos, dictStart, dictEnd) in FindByteRangeDictionaries(data))
        {
            // A later /ByteRange inside a dictionary that was already parsed adds nothing.
            if (byteRangePos < skipUntil || dictStart < 0 || dictEnd < 0)
            {
                continue;
            }

            int objNumber = FindOwningObject(data, dictStart, crossRefs);
            var field = ParseSignatureDict(data[dictStart..(dictEnd + 2)], objNumber, data);
            if (field is not null)
            {
                fields.Add(field);
            }

            skipUntil = dictEnd + 2;
        }

        return fields.AsReadOnly();
    }

    /// <summary>
    /// Finds every <c>/ByteRange</c> name together with its innermost enclosing dictionary, in
    /// one forward pass. The pass tracks open dictionaries on a stack and skips comments,
    /// literal and hexadecimal strings, and stream data, so the cost is linear in the file size
    /// whatever the input (a backward search per marker was quadratic on hostile files).
    /// </summary>
    /// <returns>For each marker, in file order: its position, the start of the enclosing
    /// <c>&lt;&lt;</c> (or -1), and the first <c>&gt;</c> of its closing <c>&gt;&gt;</c> (or -1 when it never closes).</returns>
    internal static List<(int Position, int DictStart, int DictEnd)> FindByteRangeDictionaries(ReadOnlySpan<byte> data)
    {
        var markers = new List<(int Position, int DictStart, int DictEnd)>();
        var open = new List<int>();           // starts of currently open dictionaries
        var pending = new Dictionary<int, List<int>>(); // dict start -> marker indexes waiting for its end

        void Unwind()
        {
            // Dictionaries left open at an object or stream boundary never close.
            open.Clear();
            pending.Clear();
        }

        int i = 0;
        while (i < data.Length)
        {
            byte b = data[i];
            switch (b)
            {
                case (byte)'%':
                    while (i < data.Length && data[i] != (byte)'\n' && data[i] != (byte)'\r')
                    {
                        i++;
                    }

                    continue;

                case (byte)'(':
                    i = SkipLiteralString(data, i) + 1;
                    continue;

                case (byte)'<' when i + 1 < data.Length && data[i + 1] == (byte)'<':
                    open.Add(i);
                    i += 2;
                    continue;

                case (byte)'<':
                    i = SkipHexString(data, i) + 1;
                    continue;

                case (byte)'>' when i + 1 < data.Length && data[i + 1] == (byte)'>':
                    if (open.Count > 0)
                    {
                        int dictStart = open[^1];
                        open.RemoveAt(open.Count - 1);
                        if (pending.Remove(dictStart, out var waiting))
                        {
                            foreach (int index in waiting)
                            {
                                markers[index] = (markers[index].Position, dictStart, i);
                            }
                        }
                    }

                    i += 2;
                    continue;

                case (byte)'/' when data[i..].StartsWith(ByteRangeKey)
                    && (i + ByteRangeKey.Length >= data.Length || IsTokenBoundary(data[i + ByteRangeKey.Length])):
                    {
                        int enclosing = open.Count > 0 ? open[^1] : -1;
                        markers.Add((i, enclosing, -1));
                        if (enclosing >= 0)
                        {
                            if (!pending.TryGetValue(enclosing, out var list))
                            {
                                pending[enclosing] = list = [];
                            }

                            list.Add(markers.Count - 1);
                        }

                        i += ByteRangeKey.Length;
                        continue;
                    }

                case (byte)'m' when KeywordEndsAt(data, i, "stream"u8)
                    && !(i >= 8 && data.Slice(i - 8, 3).SequenceEqual("end"u8)):
                    {
                        Unwind();
                        int streamEnd = IndexOf(data, "endstream"u8, i + 1);
                        i = streamEnd < 0 ? data.Length : streamEnd + "endstream".Length;
                        continue;
                    }

                case (byte)'j' when KeywordEndsAt(data, i, "endobj"u8):
                    Unwind();
                    i++;
                    continue;

                default:
                    i++;
                    continue;
            }
        }

        return markers;
    }

    /// <summary>
    /// Parses a signature dictionary to extract ByteRange, Contents, signing time, and SubFilter.
    /// </summary>
    private static PdfSignatureField? ParseSignatureDict(
        ReadOnlySpan<byte> dictSpan, int objNumber, ReadOnlySpan<byte> fullData)
    {
        var byteRange = ExtractByteRange(dictSpan);
        if (byteRange is null)
        {
            return null;
        }

        // Usage-rights signatures (Adobe Reader Extensions, /TransformMethod /UR3 in
        // the /Reference array) are not document signatures: Acrobat does not show them
        // in the signature panel, and they must not be reported by inspection or
        // validation. Skip them here so every consumer of this reader behaves
        // consistently.
        if (ContainsNameToken(dictSpan, "/UR3"u8))
        {
            return null;
        }

        byte[] contentsBytes = ExtractContents(byteRange, fullData);
        DateTimeOffset? signingTime = ExtractPdfDate(dictSpan);
        string? subFilter = ExtractPdfName(dictSpan, "/SubFilter"u8);
        string? filter = ExtractPdfName(dictSpan, "/Filter"u8);
        string? reason = ExtractPdfString(dictSpan, "/Reason"u8);
        string? location = ExtractPdfString(dictSpan, "/Location"u8);
        string? contactInfo = ExtractPdfString(dictSpan, "/ContactInfo"u8);
        string? signerName = ExtractPdfString(dictSpan, "/Name"u8);

        string fieldName = ResolveSignatureFieldName(fullData, objNumber)
            ?? $"Signature_{objNumber}";

        return new PdfSignatureField
        {
            FieldName = fieldName,
            ByteRange = byteRange,
            ContentsBytes = contentsBytes,
            SigDictObjectNumber = objNumber,
            PdfSigningTime = signingTime,
            Filter = filter,
            SubFilter = subFilter,
            Reason = reason,
            Location = location,
            ContactInfo = contactInfo,
            SignerName = signerName,
        };
    }

    /// <summary>
    /// Resolves the AcroForm field dictionary whose /V entry points at the
    /// signature dictionary and returns its /T value.
    /// </summary>
    private static string? ResolveSignatureFieldName(
        ReadOnlySpan<byte> data, int signatureObjectNumber)
    {
        int valuePos = 0;
        while ((valuePos = IndexOf(data, "/V"u8, valuePos)) >= 0)
        {
            int pos = valuePos + 2;
            while (pos < data.Length && IsWhitespace(data[pos]))
            {
                pos++;
            }

            if (TryParseDecimalLong(data, pos, out long referencedObject, out int afterObject)
                && referencedObject == signatureObjectNumber)
            {
                pos = afterObject;
                while (pos < data.Length && IsWhitespace(data[pos]))
                {
                    pos++;
                }

                if (TryParseDecimalLong(data, pos, out _, out int afterGeneration))
                {
                    pos = afterGeneration;
                    while (pos < data.Length && IsWhitespace(data[pos]))
                    {
                        pos++;
                    }

                    if (pos < data.Length && data[pos] == 'R')
                    {
                        int dictStart = FindDictStart(data, valuePos);
                        int dictEnd = dictStart >= 0 ? FindMatchingDictEnd(data, dictStart) : -1;
                        if (dictEnd >= 0)
                        {
                            string? fieldName = ExtractPdfString(
                                data[dictStart..(dictEnd + 2)], "/T"u8);
                            if (!string.IsNullOrEmpty(fieldName))
                            {
                                return fieldName;
                            }
                        }
                    }
                }
            }

            valuePos += 2;
        }

        return null;
    }

    /// <summary>
    /// Determines whether a PDF name token (e.g. "/UR3") appears in the span with a
    /// valid token boundary after it (whitespace, '/', '>', ']', or end of span),
    /// so that longer names such as "/UR3Something" do not match.
    /// </summary>
    private static bool ContainsNameToken(ReadOnlySpan<byte> span, ReadOnlySpan<byte> name)
    {
        int pos = 0;
        while ((pos = IndexOf(span, name, pos)) >= 0)
        {
            int after = pos + name.Length;
            if (after >= span.Length
                || IsWhitespace(span[after])
                || span[after] == (byte)'/'
                || span[after] == (byte)'>'
                || span[after] == (byte)']')
            {
                return true;
            }

            pos = after;
        }

        return false;
    }

    /// <summary>
    /// Extracts a PDF name value (e.g., /SubFilter /adbe.pkcs7.detached) from a dictionary span.
    /// </summary>
    private static string? ExtractPdfName(ReadOnlySpan<byte> dictSpan, ReadOnlySpan<byte> key)
    {
        int keyPos = IndexOf(dictSpan, key, 0);
        if (keyPos < 0)
        {
            return null;
        }

        // Skip whitespace after key
        int pos = keyPos + key.Length;
        while (pos < dictSpan.Length && IsWhitespace(dictSpan[pos]))
        {
            pos++;
        }

        if (pos >= dictSpan.Length)
        {
            return null;
        }

        // Expect '/' (0x2F) starting the name value
        if (dictSpan[pos] != '/')
        {
            return null;
        }
        pos++;

        // Read until delimiter (/, >, newline, space)
        int nameStart = pos;
        while (pos < dictSpan.Length
               && dictSpan[pos] != '/' && dictSpan[pos] != '>'
               && dictSpan[pos] != '\n' && dictSpan[pos] != '\r' && dictSpan[pos] != ' ')
        {
            pos++;
        }

        if (pos <= nameStart)
        {
            return null;
        }

        return Encoding.ASCII.GetString(dictSpan[nameStart..pos]).Trim();
    }

    /// <summary>
    /// Extracts a PDF text string value for a given key (e.g., /Reason (text) or
    /// /Reason &lt;FEFF...&gt;). Supports literal strings (with escape sequences,
    /// nested parentheses and octal escapes) and hexadecimal strings per
    /// ISO 32000-1 §7.3.4.
    /// </summary>
    internal static string? ExtractPdfString(ReadOnlySpan<byte> dictSpan, ReadOnlySpan<byte> key)
    {
        int searchPos = 0;
        int keyPos;
        while ((keyPos = IndexOf(dictSpan, key, searchPos)) >= 0)
        {
            int afterKey = keyPos + key.Length;
            if (afterKey >= dictSpan.Length
                || IsWhitespace(dictSpan[afterKey])
                || dictSpan[afterKey] == '('
                || dictSpan[afterKey] == '<')
            {
                break;
            }

            // A short key such as /T must not match /Type.
            searchPos = afterKey;
        }

        if (keyPos < 0)
        {
            return null;
        }

        // Skip whitespace after key
        int pos = keyPos + key.Length;
        while (pos < dictSpan.Length && IsWhitespace(dictSpan[pos]))
        {
            pos++;
        }

        if (pos >= dictSpan.Length)
        {
            return null;
        }

        if (dictSpan[pos] == '(')
        {
            return ExtractLiteralString(dictSpan, pos);
        }

        if (dictSpan[pos] == '<')
        {
            return ExtractHexString(dictSpan, pos);
        }

        return null;
    }

    /// <summary>
    /// Extracts a literal string starting at the '(' at <paramref name="openParenPos"/>,
    /// honouring escape sequences, nested parentheses and octal escapes
    /// (ISO 32000-1 §7.3.4.2).
    /// </summary>
    private static string? ExtractLiteralString(ReadOnlySpan<byte> dictSpan, int openParenPos)
    {
        int pos = openParenPos + 1;

        // Read until the closing parenthesis, handling escaped chars and nesting.
        int depth = 1;
        int valueStart = pos;
        while (pos < dictSpan.Length && depth > 0)
        {
            if (dictSpan[pos] == '\\')
            {
                pos++; // skip escaped char
            }
            else if (dictSpan[pos] == '(')
            {
                depth++;
            }
            else if (dictSpan[pos] == ')')
            {
                depth--;
            }
            pos++;
        }

        if (depth != 0)
        {
            return null;
        }

        int valueEnd = pos - 1; // exclude closing paren
        if (valueEnd <= valueStart)
        {
            return null;
        }

        byte[] unescaped = UnescapePdfLiteralString(dictSpan[valueStart..valueEnd]);
        return DecodePdfTextString(unescaped);
    }

    /// <summary>
    /// Extracts a hexadecimal string starting at the '&lt;' at <paramref name="openAnglePos"/>
    /// (ISO 32000-1 §7.3.4.3).
    /// </summary>
    private static string? ExtractHexString(ReadOnlySpan<byte> dictSpan, int openAnglePos)
    {
        int pos = openAnglePos + 1;
        int hexStart = pos;
        while (pos < dictSpan.Length && dictSpan[pos] != '>')
        {
            pos++;
        }

        if (pos >= dictSpan.Length)
        {
            return null;
        }

        return DecodePdfTextString(DecodePdfHexString(dictSpan[hexStart..pos]));
    }

    /// <summary>
    /// Unescapes a PDF literal string body per ISO 32000-1 §7.3.4.2 Table 3,
    /// including \n \r \t \b \f \( \) \\, octal escapes (\ddd) and line
    /// continuations (\&lt;EOL&gt;). Unknown escapes drop the backslash.
    /// </summary>
    private static byte[] UnescapePdfLiteralString(ReadOnlySpan<byte> raw)
    {
        var output = new List<byte>(raw.Length);
        for (int i = 0; i < raw.Length; i++)
        {
            byte b = raw[i];
            if (b != (byte)'\\')
            {
                output.Add(b);
                continue;
            }

            if (i + 1 >= raw.Length)
            {
                break; // trailing backslash — ignore
            }

            byte next = raw[i + 1];
            switch (next)
            {
                case (byte)'n':
                    output.Add((byte)'\n');
                    i++;
                    break;
                case (byte)'r':
                    output.Add((byte)'\r');
                    i++;
                    break;
                case (byte)'t':
                    output.Add((byte)'\t');
                    i++;
                    break;
                case (byte)'b':
                    output.Add((byte)'\b');
                    i++;
                    break;
                case (byte)'f':
                    output.Add((byte)'\f');
                    i++;
                    break;
                case (byte)'(':
                case (byte)')':
                case (byte)'\\':
                    output.Add(next);
                    i++;
                    break;
                case (byte)'\r':
                    // Line continuation: \r or \r\n.
                    i++;
                    if (i + 1 < raw.Length && raw[i + 1] == (byte)'\n')
                    {
                        i++;
                    }
                    break;
                case (byte)'\n':
                    // Line continuation: \<LF>.
                    i++;
                    break;
                default:
                    if (next is >= (byte)'0' and <= (byte)'7')
                    {
                        // Octal escape: one to three octal digits.
                        int value = 0;
                        int count = 0;
                        while (count < 3 && i + 1 < raw.Length && raw[i + 1] is >= (byte)'0' and <= (byte)'7')
                        {
                            value = (value * 8) + (raw[i + 1] - (byte)'0');
                            i++;
                            count++;
                        }
                        output.Add((byte)value);
                    }
                    else
                    {
                        // Unknown escape: the backslash is ignored (ISO 32000-1 §7.3.4.2).
                        output.Add(next);
                        i++;
                    }
                    break;
            }
        }

        return [.. output];
    }

    /// <summary>
    /// Decodes the body of a hexadecimal PDF string (between '&lt;' and '&gt;').
    /// Whitespace characters are ignored and an odd final nibble is padded
    /// with a trailing zero nibble (ISO 32000-1 §7.3.4.3).
    /// </summary>
    internal static byte[] DecodePdfHexString(ReadOnlySpan<byte> hex)
    {
        var output = new List<byte>((hex.Length / 2) + 1);
        int highNibble = -1;
        foreach (byte b in hex)
        {
            if (IsHexWhitespace(b))
            {
                continue;
            }

            int nibble = HexNibble(b);
            if (nibble < 0)
            {
                continue;
            }

            if (highNibble < 0)
            {
                highNibble = nibble;
            }
            else
            {
                output.Add((byte)((highNibble << 4) | nibble));
                highNibble = -1;
            }
        }

        if (highNibble >= 0)
        {
            output.Add((byte)(highNibble << 4));
        }

        return [.. output];
    }

    /// <summary>
    /// Determines whether a byte is PDF whitespace inside a hexadecimal string
    /// (NUL, TAB, LF, FF, CR, SP — ISO 32000-1 §7.2.2).
    /// </summary>
    private static bool IsHexWhitespace(byte b) => b is 0 or (byte)' ' or (byte)'\t' or (byte)'\n' or (byte)'\f' or (byte)'\r';

    /// <summary>
    /// Converts one hex digit to its numeric value, or -1 when not a hex digit.
    /// </summary>
    private static int HexNibble(byte b)
    {
        if (b is >= (byte)'0' and <= (byte)'9')
        {
            return b - (byte)'0';
        }
        if (b is >= (byte)'A' and <= (byte)'F')
        {
            return (b - (byte)'A') + 10;
        }
        if (b is >= (byte)'a' and <= (byte)'f')
        {
            return (b - (byte)'a') + 10;
        }

        return -1;
    }

    /// <summary>
    /// Decodes a PDF text string per ISO 32000-1 §7.9.2.2.
    /// UTF-16BE (FE FF) and UTF-16LE (FF FE) byte-order marks are honoured;
    /// strings without a BOM are decoded as PDFDocEncoding (Annex D).
    /// </summary>
    internal static string DecodePdfTextString(ReadOnlySpan<byte> raw)
    {
        if (raw.Length >= 2 && raw[0] == 0xFE && raw[1] == 0xFF)
        {
            return DecodeUtf16(raw[2..], Encoding.BigEndianUnicode);
        }

        if (raw.Length >= 2 && raw[0] == 0xFF && raw[1] == 0xFE)
        {
            return DecodeUtf16(raw[2..], Encoding.Unicode);
        }

        return DecodePdfDocEncoding(raw);
    }

    /// <summary>
    /// Decodes UTF-16 bytes, dropping a trailing odd byte when present.
    /// </summary>
    private static string DecodeUtf16(ReadOnlySpan<byte> payload, Encoding encoding)
    {
        if ((payload.Length & 1) == 1)
        {
            payload = payload[..^1];
        }

        return encoding.GetString(payload);
    }

    /// <summary>
    /// Decodes bytes as PDFDocEncoding per ISO 32000-1 Annex D (Table D.2).
    /// </summary>
    private static string DecodePdfDocEncoding(ReadOnlySpan<byte> raw)
    {
        var sb = new StringBuilder(raw.Length);
        foreach (byte b in raw)
        {
            sb.Append(MapPdfDocByte(b));
        }

        return sb.ToString();
    }

    /// <summary>
    /// Maps one PDFDocEncoding byte to its Unicode code point (ISO 32000-1 Annex D).
    /// </summary>
    private static char MapPdfDocByte(byte b) => b switch
    {
        0x18 => '\u02D8', // breve
        0x19 => '\u02C7', // caron
        0x1A => '\u02C6', // modifier letter circumflex
        0x1B => '\u02D9', // dot above
        0x1C => '\u02DD', // double acute accent
        0x1D => '\u02DB', // ogonek
        0x1E => '\u02DA', // ring above
        0x1F => '\u02DC', // small tilde
        0x7F => '\uFFFD', // undefined in PDFDocEncoding
        0x80 => '\u2022', // bullet
        0x81 => '\u2020', // dagger
        0x82 => '\u2021', // double dagger
        0x83 => '\u2026', // ellipsis
        0x84 => '\u2014', // em dash
        0x85 => '\u2013', // en dash
        0x86 => '\u0192', // florin
        0x87 => '\u2044', // fraction slash
        0x88 => '\u2039', // single left-pointing angle quote
        0x89 => '\u203A', // single right-pointing angle quote
        0x8A => '\u2212', // minus sign
        0x8B => '\u2030', // per mille sign
        0x8C => '\u201E', // double low-9 quotation mark
        0x8D => '\u201C', // left double quotation mark
        0x8E => '\u201D', // right double quotation mark
        0x8F => '\u2018', // left single quotation mark
        0x90 => '\u2019', // right single quotation mark
        0x91 => '\u201A', // single low-9 quotation mark
        0x92 => '\u2122', // trademark
        0x93 => '\uFB01', // fi ligature
        0x94 => '\uFB02', // fl ligature
        0x95 => '\u0141', // L with stroke
        0x96 => '\u0152', // OE ligature
        0x97 => '\u0160', // S with caron
        0x98 => '\u0178', // Y with diaeresis
        0x99 => '\u017D', // Z with caron
        0x9A => '\u0131', // dotless i
        0x9B => '\u0142', // l with stroke
        0x9C => '\u0153', // oe ligature
        0x9D => '\u0161', // s with caron
        0x9E => '\u017E', // z with caron
        0x9F => '\uFFFD', // undefined in PDFDocEncoding
        0xA0 => '\u20AC', // euro sign
        _ => (char)b,
    };

    /// <summary>
    /// Extracts the /M (modification date) from a signature dictionary.
    /// Format: /M (D:YYYYMMDDHHmmss+HH'mm'). Literal, hexadecimal, and UTF-16
    /// text strings are decoded with the shared PDF text-string decoder.
    /// </summary>
    private static DateTimeOffset? ExtractPdfDate(ReadOnlySpan<byte> dictSpan)
    {
        string? dateString = ExtractPdfString(dictSpan, "/M"u8);
        if (string.IsNullOrEmpty(dateString))
        {
            return null;
        }

        return ParsePdfDate(dateString);
    }

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
    /// Extracts the /ByteRange [offset1 length1 offset2 length2] array from a dictionary.
    /// </summary>
    private static PdfByteRange? ExtractByteRange(ReadOnlySpan<byte> dictSpan)
    {
        int keyPos = IndexOf(dictSpan, ByteRangeKey, 0);
        if (keyPos < 0)
        {
            return null;
        }

        // Skip whitespace and find opening bracket '['
        int pos = keyPos + ByteRangeKey.Length;
        while (pos < dictSpan.Length && IsWhitespace(dictSpan[pos]))
        {
            pos++;
        }

        if (pos >= dictSpan.Length || dictSpan[pos] != '[')
        {
            return null;
        }
        pos++; // skip '['

        if (!TryReadFourLongs(dictSpan, pos, out long offset1, out long length1, out long offset2, out long length2))
        {
            return null;
        }

        return new PdfByteRange
        {
            Offset1 = offset1,
            Length1 = length1,
            Offset2 = offset2,
            Length2 = length2
        };
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
    #endregion
}

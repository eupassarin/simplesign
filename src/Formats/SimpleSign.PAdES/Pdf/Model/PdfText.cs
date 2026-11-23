using System.Text;

namespace SimpleSign.PAdES.Pdf.Model;

/// <summary>Decodes PDF text strings (ISO 32000-1 §7.9.2.2; ISO 32000-2 §7.9.2.2 for UTF-8).</summary>
internal static class PdfText
{
    /// <summary>
    /// Decodes a text string: UTF-16BE (<c>FE FF</c>), UTF-16LE (<c>FF FE</c>, written by some producers) and UTF-8
    /// (<c>EF BB BF</c>, PDF 2.0) by their byte order mark; without one, PDFDocEncoding (Annex D).
    /// </summary>
    /// <param name="raw">The string's bytes, escapes resolved.</param>
    /// <returns>The text.</returns>
    public static string Decode(ReadOnlySpan<byte> raw)
    {
        if (raw.Length >= 2 && raw[0] == 0xFE && raw[1] == 0xFF)
        {
            return DecodeUtf16(raw[2..], Encoding.BigEndianUnicode);
        }

        if (raw.Length >= 2 && raw[0] == 0xFF && raw[1] == 0xFE)
        {
            return DecodeUtf16(raw[2..], Encoding.Unicode);
        }

        if (raw.Length >= 3 && raw[0] == 0xEF && raw[1] == 0xBB && raw[2] == 0xBF)
        {
            return Encoding.UTF8.GetString(raw[3..]);
        }

        return DecodePdfDocEncoding(raw);
    }

    /// <summary>
    /// Reads a PDF date (ISO 32000-1 §7.9.4), <c>D:YYYYMMDDHHmmSS</c> followed by an optional offset (<c>+HH'mm'</c>,
    /// <c>-HH'mm'</c>, <c>Z</c>): the seconds must be there; an offset that cannot be read is taken as UTC.
    /// </summary>
    /// <param name="text">The date, its <c>D:</c> prefix optional.</param>
    /// <returns>The date; null when it cannot be read.</returns>
    public static DateTimeOffset? ParseDate(string text)
    {
        if (text.StartsWith("D:", StringComparison.OrdinalIgnoreCase))
        {
            text = text[2..];
        }

        if (text.Length < 14
            || !int.TryParse(text[0..4], out int year)
            || !int.TryParse(text[4..6], out int month)
            || !int.TryParse(text[6..8], out int day)
            || !int.TryParse(text[8..10], out int hour)
            || !int.TryParse(text[10..12], out int minute)
            || !int.TryParse(text[12..14], out int second))
        {
            return null;
        }

        var offset = TimeSpan.Zero;
        if (text.Length >= 20
            && text[14] is '+' or '-'
            && int.TryParse(text[15..17], out int offsetHours)
            && int.TryParse(text[18..20], out int offsetMinutes))
        {
            offset = new TimeSpan(offsetHours, offsetMinutes, 0);
            if (text[14] == '-')
            {
                offset = -offset;
            }
        }

        try
        {
            return new DateTimeOffset(year, month, day, hour, minute, second, offset);
        }
        catch (ArgumentException)
        {
            return null;
        }
    }

    /// <summary>Decodes UTF-16 bytes, dropping a trailing odd byte.</summary>
    private static string DecodeUtf16(ReadOnlySpan<byte> payload, Encoding encoding)
    {
        if ((payload.Length & 1) == 1)
        {
            payload = payload[..^1];
        }

        return encoding.GetString(payload);
    }

    /// <summary>Decodes bytes as PDFDocEncoding (ISO 32000-1 Annex D, Table D.2).</summary>
    private static string DecodePdfDocEncoding(ReadOnlySpan<byte> raw)
    {
        var text = new StringBuilder(raw.Length);
        foreach (byte b in raw)
        {
            text.Append(MapPdfDocByte(b));
        }

        return text.ToString();
    }

    /// <summary>Maps one PDFDocEncoding byte to its Unicode character (ISO 32000-1 Annex D).</summary>
    private static char MapPdfDocByte(byte b) => b switch
    {
        0x18 => '˘', // breve
        0x19 => 'ˇ', // caron
        0x1A => 'ˆ', // modifier letter circumflex
        0x1B => '˙', // dot above
        0x1C => '˝', // double acute accent
        0x1D => '˛', // ogonek
        0x1E => '˚', // ring above
        0x1F => '˜', // small tilde
        0x7F => '�', // undefined in PDFDocEncoding
        0x80 => '•', // bullet
        0x81 => '†', // dagger
        0x82 => '‡', // double dagger
        0x83 => '…', // ellipsis
        0x84 => '—', // em dash
        0x85 => '–', // en dash
        0x86 => 'ƒ', // florin
        0x87 => '⁄', // fraction slash
        0x88 => '‹', // single left-pointing angle quote
        0x89 => '›', // single right-pointing angle quote
        0x8A => '−', // minus sign
        0x8B => '‰', // per mille sign
        0x8C => '„', // double low-9 quotation mark
        0x8D => '“', // left double quotation mark
        0x8E => '”', // right double quotation mark
        0x8F => '‘', // left single quotation mark
        0x90 => '’', // right single quotation mark
        0x91 => '‚', // single low-9 quotation mark
        0x92 => '™', // trademark
        0x93 => 'ﬁ', // fi ligature
        0x94 => 'ﬂ', // fl ligature
        0x95 => 'Ł', // L with stroke
        0x96 => 'Œ', // OE ligature
        0x97 => 'Š', // S with caron
        0x98 => 'Ÿ', // Y with diaeresis
        0x99 => 'Ž', // Z with caron
        0x9A => 'ı', // dotless i
        0x9B => 'ł', // l with stroke
        0x9C => 'œ', // oe ligature
        0x9D => 'š', // s with caron
        0x9E => 'ž', // z with caron
        0x9F => '�', // undefined in PDFDocEncoding
        0xA0 => '€', // euro sign
        _ => (char)b,
    };
}

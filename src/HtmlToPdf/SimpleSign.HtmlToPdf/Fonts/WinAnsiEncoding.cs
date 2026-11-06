namespace SimpleSign.HtmlToPdf.Fonts;

/// <summary>
/// Maps Unicode code points to WinAnsiEncoding byte values used by standard PDF fonts.
/// WinAnsi codes 128-159 differ from Unicode; codes 0-127 and 160-255 map directly.
/// </summary>
internal static class WinAnsiEncoding
{
    private static readonly Dictionary<char, byte> UnicodeToWinAnsiMap = new()
    {
        ['\u20AC'] = 128, // € Euro sign
        ['\u201A'] = 130, // ‚ Single low-9 quotation mark
        ['\u0192'] = 131, // ƒ Latin small f with hook
        ['\u201E'] = 132, // „ Double low-9 quotation mark
        ['\u2026'] = 133, // … Horizontal ellipsis
        ['\u2020'] = 134, // † Dagger
        ['\u2021'] = 135, // ‡ Double dagger
        ['\u02C6'] = 136, // ˆ Modifier letter circumflex accent
        ['\u2030'] = 137, // ‰ Per mille sign
        ['\u0160'] = 138, // Š Latin capital S with caron
        ['\u2039'] = 139, // ‹ Single left-pointing angle quotation mark
        ['\u0152'] = 140, // Œ Latin capital ligature OE
        ['\u017D'] = 142, // Ž Latin capital Z with caron
        ['\u2018'] = 145, // ' Left single quotation mark
        ['\u2019'] = 146, // ' Right single quotation mark
        ['\u201C'] = 147, // " Left double quotation mark
        ['\u201D'] = 148, // " Right double quotation mark
        ['\u2022'] = 149, // • Bullet
        ['\u2013'] = 150, // – En dash
        ['\u2014'] = 151, // — Em dash
        ['\u02DC'] = 152, // ˜ Small tilde
        ['\u2122'] = 153, // ™ Trade mark sign
        ['\u0161'] = 154, // š Latin small s with caron
        ['\u203A'] = 155, // › Single right-pointing angle quotation mark
        ['\u0153'] = 156, // œ Latin small ligature oe
        ['\u017E'] = 158, // ž Latin small z with caron
        ['\u0178'] = 159, // Ÿ Latin capital Y with dieresis
    };

    /// <summary>
    /// Converts a Unicode character to its WinAnsi byte value.
    /// Returns -1 if the character cannot be encoded in WinAnsi.
    /// </summary>
    public static int MapToWinAnsi(char c)
    {
        if (c <= 127)
        {
            return c;
        }

        if (c >= 160 && c <= 255)
        {
            return c;
        }

        if (UnicodeToWinAnsiMap.TryGetValue(c, out byte code))
        {
            return code;
        }

        return -1;
    }
}

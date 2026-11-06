using System.Text;

namespace SimpleSign.PAdES.Signing;

/// <summary>
/// Writes PDF text strings (ISO 32000-1 §7.9.2.2) such as /Name, /Reason and /T.
/// Text that PDFDocEncoding can hold byte-for-byte is written as a literal string; anything
/// else (characters outside Latin-1, the euro sign, typographic quotes, ...) is written as a
/// UTF-16BE hexadecimal string with a byte-order mark, so no character is lost.
/// </summary>
internal static class PdfTextString
{
    /// <summary>Returns the PDF string token for <paramref name="text"/>, including its delimiters.</summary>
    internal static string Encode(string text)
    {
        foreach (char c in text)
        {
            if (!IsLiteralSafe(c))
            {
                return EncodeUtf16(text);
            }
        }

        return $"({SignatureAppearanceRenderer.EscapePdfString(text)})";
    }

    /// <summary>
    /// True when the character has the same code in PDFDocEncoding and Latin-1:
    /// printable ASCII, tab/line breaks, and U+00A1–U+00FF except the soft hyphen.
    /// </summary>
    private static bool IsLiteralSafe(char c) =>
        c is (>= ' ' and <= '~') or '\t' or '\n' or '\r' or (>= '¡' and <= 'ÿ' and not '­');

    private static string EncodeUtf16(string text)
    {
        byte[] bytes = Encoding.BigEndianUnicode.GetBytes(text);
        return $"<FEFF{Convert.ToHexString(bytes)}>";
    }
}

namespace SimpleSign.PAdES.Pdf.Writing;

/// <summary>Changes the PDF/A part an XMP packet declares (ISO 19005-3 §6.6.4), and nothing else of it.</summary>
internal static class PdfXmpPatch
{
    /// <summary>
    /// The XMP with its first <c>pdfaid:part</c> (an element, <c>&lt;pdfaid:part&gt;2&lt;/…&gt;</c>, or an attribute,
    /// <c>pdfaid:part="2"</c>) set to <paramref name="part"/>; null when there is no such property or its value is not
    /// one digit. The packet keeps its length.
    /// </summary>
    /// <param name="xmp">The XMP packet.</param>
    /// <param name="part">The part, 1 to 9.</param>
    public static byte[]? SetPdfAPart(ReadOnlySpan<byte> xmp, int part)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(part, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(part, 9);
        int pos = 0;
        while (pos < xmp.Length)
        {
            int found = xmp[pos..].IndexOf("pdfaid:part"u8);
            if (found < 0)
            {
                return null;
            }

            int i = SkipWhitespace(xmp, pos + found + "pdfaid:part".Length);
            int value = -1;
            if (i < xmp.Length && xmp[i] == (byte)'>')
            {
                value = SkipWhitespace(xmp, i + 1);
            }
            else if (i < xmp.Length && xmp[i] == (byte)'=')
            {
                i = SkipWhitespace(xmp, i + 1);
                if (i < xmp.Length && xmp[i] is (byte)'"' or (byte)'\'')
                {
                    value = SkipWhitespace(xmp, i + 1);
                }
            }

            if (value >= 0)
            {
                if (value + 1 >= xmp.Length || xmp[value] is < (byte)'0' or > (byte)'9' || xmp[value + 1] is >= (byte)'0' and <= (byte)'9')
                {
                    return null;
                }

                byte[] patched = xmp.ToArray();
                patched[value] = (byte)('0' + part);
                return patched;
            }

            pos += found + 1;
        }

        return null;
    }

    private static int SkipWhitespace(ReadOnlySpan<byte> span, int i)
    {
        while (i < span.Length && span[i] is (byte)' ' or (byte)'\t' or (byte)'\r' or (byte)'\n')
        {
            i++;
        }

        return i;
    }
}

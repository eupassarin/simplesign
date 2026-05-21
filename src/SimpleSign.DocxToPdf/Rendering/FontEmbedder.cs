using System.Globalization;
using System.Text;
using SimpleSign.DocxToPdf.Fonts;

namespace SimpleSign.DocxToPdf.Rendering;

/// <summary>Handles embedding font subsets into PDF documents.</summary>
internal static class FontEmbedder
{
    /// <summary>Creates a ToUnicode CMap for text extraction from PDF.</summary>
    /// <param name="glyphToUnicode">Mapping of glyph IDs to Unicode code points.</param>
    /// <returns>The CMap data as a string.</returns>
    public static string CreateToUnicodeCMap(Dictionary<ushort, char> glyphToUnicode)
    {
        ArgumentNullException.ThrowIfNull(glyphToUnicode);

        var sb = new StringBuilder();
        sb.AppendLine("/CIDInit /ProcSet findresource begin");
        sb.AppendLine("12 dict begin");
        sb.AppendLine("begincmap");
        sb.AppendLine("/CIDSystemInfo");
        sb.AppendLine("<< /Registry (Adobe) /Ordering (UCS) /Supplement 0 >> def");
        sb.AppendLine("/CMapName /Adobe-Identity-UCS def");
        sb.AppendLine("/CMapType 2 def");
        sb.AppendLine("1 begincodespacerange");
        sb.AppendLine("<0000> <FFFF>");
        sb.AppendLine("endcodespacerange");

        var entries = glyphToUnicode.OrderBy(kv => kv.Key).ToList();
        int batchSize = 100;

        for (int i = 0; i < entries.Count; i += batchSize)
        {
            int count = Math.Min(batchSize, entries.Count - i);
            sb.AppendLine(CultureInfo.InvariantCulture, $"{count} beginbfchar");

            for (int j = i; j < i + count; j++)
            {
                KeyValuePair<ushort, char> entry = entries[j];
                sb.AppendLine(CultureInfo.InvariantCulture, $"<{entry.Key:X4}> <{(int)entry.Value:X4}>");
            }

            sb.AppendLine("endbfchar");
        }

        sb.AppendLine("endcmap");
        sb.AppendLine("CMapName currentdict /CMap defineresource pop");
        sb.AppendLine("end");
        sb.AppendLine("end");

        return sb.ToString();
    }

    /// <summary>Builds a font descriptor dictionary content for embedding.</summary>
    /// <param name="font">The parsed font.</param>
    /// <param name="fontStreamObjectId">The object ID of the font stream.</param>
    /// <returns>The font descriptor dictionary string.</returns>
    public static string BuildFontDescriptor(TrueTypeParser font, int fontStreamObjectId) =>
        string.Create(CultureInfo.InvariantCulture,
            $"<< /Type /FontDescriptor /FontName /{SanitizeFontName(font.FamilyName)} /Flags 32 /ItalicAngle 0 /Ascent {font.Ascender} /Descent {font.Descender} /CapHeight {font.Ascender} /StemV 80 /FontFile2 {fontStreamObjectId} 0 R >>");

    private static string SanitizeFontName(string name) =>
        name.Replace(" ", "", StringComparison.Ordinal)
            .Replace("-", "", StringComparison.Ordinal);
}

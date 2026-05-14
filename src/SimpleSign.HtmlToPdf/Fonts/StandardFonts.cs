namespace SimpleSign.HtmlToPdf.Fonts;

/// <summary>
/// Registry of the 14 standard PDF fonts.
/// Maps CSS font-family names to PDF base font names.
/// </summary>
public static class StandardFonts
{
    /// <summary>Resolves a CSS font-family to a PDF base font name.</summary>
    /// <param name="family">CSS font-family (e.g., "Helvetica", "Arial", "sans-serif").</param>
    /// <param name="bold">Whether bold variant is needed.</param>
    /// <param name="italic">Whether italic variant is needed.</param>
    /// <returns>The PDF base font name.</returns>
    public static string Resolve(string family, bool bold, bool italic)
    {
        string baseName = NormalizeFamily(family);
        return (baseName, bold, italic) switch
        {
            ("Helvetica", false, false) => "Helvetica",
            ("Helvetica", true, false) => "Helvetica-Bold",
            ("Helvetica", false, true) => "Helvetica-Oblique",
            ("Helvetica", true, true) => "Helvetica-BoldOblique",
            ("Courier", false, false) => "Courier",
            ("Courier", true, false) => "Courier-Bold",
            ("Courier", false, true) => "Courier-Oblique",
            ("Courier", true, true) => "Courier-BoldOblique",
            ("Times", false, false) => "Times-Roman",
            ("Times", true, false) => "Times-Bold",
            ("Times", false, true) => "Times-Italic",
            ("Times", true, true) => "Times-BoldItalic",
            _ => bold ? "Helvetica-Bold" : "Helvetica"
        };
    }

    private static string NormalizeFamily(string family)
    {
        return family.Trim().ToLowerInvariant() switch
        {
            "arial" or "helvetica" or "sans-serif" or "verdana" or "tahoma" or "trebuchet ms" => "Helvetica",
            "courier new" or "courier" or "monospace" or "consolas" or "lucida console" => "Courier",
            "times new roman" or "times" or "georgia" or "serif" or "palatino" or "book antiqua" => "Times",
            _ => "Helvetica"
        };
    }
}

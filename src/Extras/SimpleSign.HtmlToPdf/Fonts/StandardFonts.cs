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

    /// <summary>Returns true when the CSS family name maps to one of the standard PDF fonts.</summary>
    /// <param name="family">CSS family name.</param>
    /// <returns>True for generic families and the Helvetica/Arial, Times, and Courier names.</returns>
    public static bool IsKnownFamily(string family) => family.Trim().Trim('\'', '"').ToLowerInvariant() is
        "arial" or "helvetica" or "helvetica neue" or "sans-serif" or "system-ui" or "-apple-system" or "ui-sans-serif"
        or "courier" or "courier new" or "monospace" or "ui-monospace"
        or "times" or "times new roman" or "serif" or "ui-serif";

    private static string NormalizeFamily(string family)
    {
        return family.Trim().Trim('\'', '"').ToLowerInvariant() switch
        {
            "courier new" or "courier" or "monospace" or "consolas" or "lucida console" or "ui-monospace" or "menlo"
                or "monaco" or "liberation mono" or "dejavu sans mono" => "Courier",
            "times new roman" or "times" or "georgia" or "serif" or "palatino" or "book antiqua" or "cambria"
                or "garamond" or "liberation serif" or "dejavu serif" or "ui-serif" or "palatino linotype" => "Times",
            _ => "Helvetica",
        };
    }
}

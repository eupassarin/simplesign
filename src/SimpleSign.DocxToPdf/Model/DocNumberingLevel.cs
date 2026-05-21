namespace SimpleSign.DocxToPdf.Model;

/// <summary>Defines a numbering level format and appearance.</summary>
public sealed class DocNumberingLevel
{
    /// <summary>Gets or sets the level number (0-based).</summary>
    public int Level { get; set; }

    /// <summary>Gets or sets the number format (decimal, bullet, lowerLetter, upperLetter, lowerRoman, upperRoman).</summary>
    public string Format { get; set; } = "decimal";

    /// <summary>Gets or sets the text template (e.g., "%1." or "%1.%2").</summary>
    public string TextTemplate { get; set; } = "%1.";

    /// <summary>Gets or sets the font name for this level.</summary>
    public string? FontName { get; set; }

    /// <summary>Gets or sets the start value.</summary>
    public int StartValue { get; set; } = 1;

    /// <summary>Gets or sets the indent in points.</summary>
    public float IndentPt { get; set; }
}

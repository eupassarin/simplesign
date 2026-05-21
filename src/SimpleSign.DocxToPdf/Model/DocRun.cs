namespace SimpleSign.DocxToPdf.Model;

/// <summary>A run of text with uniform character formatting.</summary>
public sealed class DocRun
{
    /// <summary>Gets or sets the text content of this run.</summary>
    public string Text { get; set; } = string.Empty;

    /// <summary>Gets or sets the font family name.</summary>
    public string? FontName { get; set; }

    /// <summary>Gets or sets the font size in half-points (24 = 12pt).</summary>
    public int SizeHalfPoints { get; set; }

    /// <summary>Gets or sets a value indicating whether the text is bold.</summary>
    public bool Bold { get; set; }

    /// <summary>Gets or sets a value indicating whether the text is italic.</summary>
    public bool Italic { get; set; }

    /// <summary>Gets or sets the underline type.</summary>
    public UnderlineType Underline { get; set; }

    /// <summary>Gets or sets a value indicating whether the text has strikethrough.</summary>
    public bool Strikethrough { get; set; }

    /// <summary>Gets or sets the text color as a hex RGB string.</summary>
    public string? Color { get; set; }

    /// <summary>Gets or sets the highlight color name.</summary>
    public string? Highlight { get; set; }

    /// <summary>Gets or sets a value indicating whether the text is superscript.</summary>
    public bool Superscript { get; set; }

    /// <summary>Gets or sets a value indicating whether the text is subscript.</summary>
    public bool Subscript { get; set; }

    /// <summary>Gets or sets a value indicating whether all caps is applied.</summary>
    public bool AllCaps { get; set; }

    /// <summary>Gets the font size in points.</summary>
    public float SizePt => SizeHalfPoints / 2f;
}

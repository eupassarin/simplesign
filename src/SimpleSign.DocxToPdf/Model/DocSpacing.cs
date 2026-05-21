namespace SimpleSign.DocxToPdf.Model;

/// <summary>Paragraph spacing configuration.</summary>
public sealed class DocSpacing
{
    /// <summary>Gets or sets the space before the paragraph in points.</summary>
    public float BeforePt { get; set; }

    /// <summary>Gets or sets the space after the paragraph in points.</summary>
    public float AfterPt { get; set; }

    /// <summary>Gets or sets the line spacing value in points.</summary>
    public float LinePt { get; set; }

    /// <summary>Gets or sets the line spacing rule (exact, atLeast, or multiple).</summary>
    public string LineRule { get; set; } = "auto";
}

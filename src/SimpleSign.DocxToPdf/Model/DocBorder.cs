namespace SimpleSign.DocxToPdf.Model;

/// <summary>Represents a border with style, color, and width.</summary>
public sealed class DocBorder
{
    /// <summary>Gets or sets the border line style.</summary>
    public BorderStyle Style { get; set; }

    /// <summary>Gets or sets the border color as a hex RGB string (e.g., "FF0000").</summary>
    public string Color { get; set; } = "000000";

    /// <summary>Gets or sets the border width in points.</summary>
    public float WidthPt { get; set; }
}

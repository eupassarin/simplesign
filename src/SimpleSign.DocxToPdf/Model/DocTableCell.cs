namespace SimpleSign.DocxToPdf.Model;

/// <summary>A cell within a table row.</summary>
public sealed class DocTableCell
{
    /// <summary>Gets the paragraphs within this cell.</summary>
    public List<DocParagraph> Paragraphs { get; init; } = [];

    /// <summary>Gets or sets the cell width in points.</summary>
    public float WidthPt { get; set; }

    /// <summary>Gets or sets the number of grid columns this cell spans.</summary>
    public int GridSpan { get; set; } = 1;

    /// <summary>Gets or sets the vertical merge type (null, "restart", or "continue").</summary>
    public string? VerticalMerge { get; set; }

    /// <summary>Gets or sets the top border.</summary>
    public DocBorder? BorderTop { get; set; }

    /// <summary>Gets or sets the bottom border.</summary>
    public DocBorder? BorderBottom { get; set; }

    /// <summary>Gets or sets the left border.</summary>
    public DocBorder? BorderLeft { get; set; }

    /// <summary>Gets or sets the right border.</summary>
    public DocBorder? BorderRight { get; set; }

    /// <summary>Gets or sets the shading color as hex RGB.</summary>
    public string? ShadingColor { get; set; }

    /// <summary>Gets or sets the vertical alignment of cell content.</summary>
    public VerticalAlignment VerticalAlignment { get; set; }
}

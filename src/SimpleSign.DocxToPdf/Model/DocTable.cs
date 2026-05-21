namespace SimpleSign.DocxToPdf.Model;

/// <summary>A table element containing rows and cells.</summary>
public sealed class DocTable
{
    /// <summary>Gets the rows in this table.</summary>
    public List<DocTableRow> Rows { get; init; } = [];

    /// <summary>Gets or sets the table width in points.</summary>
    public float WidthPt { get; set; }

    /// <summary>Gets or sets the table alignment.</summary>
    public ParagraphAlignment Alignment { get; set; }

    /// <summary>Gets or sets the default cell margin in points.</summary>
    public float CellMarginPt { get; set; } = 5.4f;

    /// <summary>Gets or sets the table border.</summary>
    public DocBorder? Border { get; set; }
}

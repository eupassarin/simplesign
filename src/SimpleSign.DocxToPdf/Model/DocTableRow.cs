namespace SimpleSign.DocxToPdf.Model;

/// <summary>A row within a table.</summary>
public sealed class DocTableRow
{
    /// <summary>Gets the cells in this row.</summary>
    public List<DocTableCell> Cells { get; init; } = [];

    /// <summary>Gets or sets the row height in points (0 for auto).</summary>
    public float HeightPt { get; set; }
}

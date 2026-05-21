namespace SimpleSign.DocxToPdf.Model;

/// <summary>A document section defining page layout and content.</summary>
public sealed class DocSection
{
    /// <summary>Gets or sets the page width in points.</summary>
    public float PageWidthPt { get; set; } = 612f;

    /// <summary>Gets or sets the page height in points.</summary>
    public float PageHeightPt { get; set; } = 792f;

    /// <summary>Gets or sets the top margin in points.</summary>
    public float MarginTopPt { get; set; } = 72f;

    /// <summary>Gets or sets the bottom margin in points.</summary>
    public float MarginBottomPt { get; set; } = 72f;

    /// <summary>Gets or sets the left margin in points.</summary>
    public float MarginLeftPt { get; set; } = 72f;

    /// <summary>Gets or sets the right margin in points.</summary>
    public float MarginRightPt { get; set; } = 72f;

    /// <summary>Gets or sets the page orientation.</summary>
    public PageOrientation Orientation { get; set; }

    /// <summary>Gets the paragraphs in this section.</summary>
    public List<DocParagraph> Paragraphs { get; init; } = [];

    /// <summary>Gets the tables in this section.</summary>
    public List<DocTable> Tables { get; init; } = [];

    /// <summary>Gets the content elements in document order (paragraphs and tables).</summary>
    public List<object> Content { get; init; } = [];
}

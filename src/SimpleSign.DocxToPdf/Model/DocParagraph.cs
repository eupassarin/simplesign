namespace SimpleSign.DocxToPdf.Model;

/// <summary>A paragraph element containing runs of text.</summary>
public sealed class DocParagraph
{
    /// <summary>Gets the list of text runs in this paragraph.</summary>
    public List<DocRun> Runs { get; init; } = [];

    /// <summary>Gets the list of images in this paragraph.</summary>
    public List<DocImage> Images { get; init; } = [];

    /// <summary>Gets or sets the paragraph alignment.</summary>
    public ParagraphAlignment Alignment { get; set; }

    /// <summary>Gets or sets the paragraph spacing.</summary>
    public DocSpacing Spacing { get; set; } = new();

    /// <summary>Gets or sets the left indent in points.</summary>
    public float IndentLeftPt { get; set; }

    /// <summary>Gets or sets the right indent in points.</summary>
    public float IndentRightPt { get; set; }

    /// <summary>Gets or sets the first line indent in points.</summary>
    public float IndentFirstLinePt { get; set; }

    /// <summary>Gets or sets the numbering level reference (null if not numbered).</summary>
    public int? NumberingLevel { get; set; }

    /// <summary>Gets or sets the numbering definition ID.</summary>
    public int? NumberingId { get; set; }

    /// <summary>Gets or sets a value indicating whether to keep all lines together on one page.</summary>
    public bool KeepTogether { get; set; }

    /// <summary>Gets or sets a value indicating whether to keep this paragraph with the next.</summary>
    public bool KeepWithNext { get; set; }

    /// <summary>Gets or sets a value indicating whether to insert a page break before this paragraph.</summary>
    public bool PageBreakBefore { get; set; }

    /// <summary>Gets or sets the style ID for this paragraph.</summary>
    public string? StyleId { get; set; }
}

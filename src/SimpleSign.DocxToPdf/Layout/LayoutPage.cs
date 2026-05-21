namespace SimpleSign.DocxToPdf.Layout;

/// <summary>A single page with positioned layout elements.</summary>
internal sealed class LayoutPage
{
    /// <summary>Gets or sets the page width in points.</summary>
    public float Width { get; init; }

    /// <summary>Gets or sets the page height in points.</summary>
    public float Height { get; init; }

    /// <summary>Gets the layout elements on this page.</summary>
    public List<LayoutElement> Elements { get; init; } = [];
}

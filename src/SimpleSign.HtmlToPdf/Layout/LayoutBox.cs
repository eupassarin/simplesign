// Licensed to SimpleSign under the MIT License.

using System.Diagnostics.CodeAnalysis;
using SimpleSign.HtmlToPdf.Parsing;

namespace SimpleSign.HtmlToPdf.Layout;

/// <summary>Type of layout box content.</summary>
public enum LayoutBoxType
{
    /// <summary>Block container (div, p, h1, etc.).</summary>
    Block,

    /// <summary>Inline text run.</summary>
    InlineText,

    /// <summary>Line break (br).</summary>
    LineBreak,

    /// <summary>Horizontal rule (hr).</summary>
    HorizontalRule,

    /// <summary>Image placeholder.</summary>
    Image,

    /// <summary>List item marker (bullet or number).</summary>
    ListMarker,

    /// <summary>Forced page break.</summary>
    PageBreak,
}

/// <summary>Graphical list marker shape.</summary>
internal enum MarkerShape
{
    /// <summary>Text marker (numbers, letters).</summary>
    Text,

    /// <summary>Filled circle (disc).</summary>
    Disc,

    /// <summary>Hollow circle.</summary>
    Circle,

    /// <summary>Filled square.</summary>
    Square,
}

/// <summary>
/// Represents a positioned box in the layout tree.
/// Uses top-down Y coordinates during layout (0 = top of content area).
/// The renderer flips Y to PDF coordinates (bottom-up).
/// </summary>
[ExcludeFromCodeCoverage]
public sealed class LayoutBox
{
    /// <summary>Gets the box type.</summary>
    public LayoutBoxType Type { get; init; }

    /// <summary>Gets the source DOM node (for style access).</summary>
    public HtmlNode? Node { get; init; }

    /// <summary>Gets the computed style snapshot.</summary>
    public ComputedStyle Style { get; set; } = new();

    /// <summary>Gets or sets the X position relative to page content area.</summary>
    public float X { get; set; }

    /// <summary>Gets or sets the Y position relative to page content area.</summary>
    public float Y { get; set; }

    /// <summary>Gets or sets the content width in points.</summary>
    public float Width { get; set; }

    /// <summary>Gets or sets the content height in points.</summary>
    public float Height { get; set; }

    /// <summary>Gets the child boxes.</summary>
    public List<LayoutBox> Children { get; } = [];

    /// <summary>Gets or sets the text content for inline text boxes.</summary>
    public string? Text { get; set; }

    /// <summary>Gets or sets the list marker string (e.g., "•", "1.").</summary>
    public string? Marker { get; set; }

    /// <summary>Gets or sets the image source path or data URI.</summary>
    public string? ImageSource { get; set; }

    /// <summary>Gets or sets the link URL for clickable text.</summary>
    public string? LinkUrl { get; set; }

    /// <summary>Gets or sets the background painted behind an inline text run (from an inline ancestor).</summary>
    internal PdfColor? InlineBackground { get; set; }

    /// <summary>Gets or sets a value indicating whether a collapsed space precedes this inline box on its line.</summary>
    internal bool SpaceBefore { get; set; }

    /// <summary>Gets or sets the graphical marker shape for list markers.</summary>
    internal MarkerShape MarkerShape { get; set; }

    /// <summary>Gets or sets a value indicating whether the top border is omitted (box continues from a previous page).</summary>
    internal bool SuppressTopBorder { get; set; }

    /// <summary>Gets or sets a value indicating whether the bottom border is omitted (box continues on the next page).</summary>
    internal bool SuppressBottomBorder { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether borders are centered on the box edges (collapsed table borders)
    /// instead of drawn inside the border box.
    /// </summary>
    internal bool BorderCentered { get; set; }

    /// <summary>Creates a shallow copy positioned at a different location.</summary>
    internal LayoutBox CloneAt(float x, float y) => new()
    {
        Type = Type,
        Node = Node,
        Style = Style,
        X = x,
        Y = y,
        Width = Width,
        Height = Height,
        Text = Text,
        Marker = Marker,
        ImageSource = ImageSource,
        LinkUrl = LinkUrl,
        InlineBackground = InlineBackground,
        SpaceBefore = SpaceBefore,
        MarkerShape = MarkerShape,
        SuppressTopBorder = SuppressTopBorder,
        SuppressBottomBorder = SuppressBottomBorder,
        BorderCentered = BorderCentered,
        Svg = Svg,
        Rtl = Rtl,
    };

    /// <summary>Gets or sets a value indicating whether the text is drawn right to left (glyph order reversed, brackets mirrored).</summary>
    internal bool Rtl { get; set; }

    /// <summary>Gets or sets the SVG document drawn in this image box (inline &lt;svg&gt; or an SVG image source).</summary>
    internal HtmlNode? Svg { get; set; }

    /// <summary>Gets the total box width including margin, border, and padding.</summary>
    public float TotalWidth =>
        Style.Margin.Left + Style.Border.LeftWidth + Style.Padding.Left
        + Width
        + Style.Padding.Right + Style.Border.RightWidth + Style.Margin.Right;

    /// <summary>Gets the total box height including margin, border, and padding.</summary>
    public float TotalHeight =>
        Style.Margin.Top + Style.Border.TopWidth + Style.Padding.Top
        + Height
        + Style.Padding.Bottom + Style.Border.BottomWidth + Style.Margin.Bottom;

    /// <summary>Gets the content left edge (after margin+border+padding).</summary>
    public float ContentLeft =>
        X + Style.Margin.Left + Style.Border.LeftWidth + Style.Padding.Left;

    /// <summary>Gets the content top edge (after margin+border+padding).</summary>
    public float ContentTop =>
        Y + Style.Margin.Top + Style.Border.TopWidth + Style.Padding.Top;
}

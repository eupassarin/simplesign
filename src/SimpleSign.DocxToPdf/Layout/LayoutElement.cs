namespace SimpleSign.DocxToPdf.Layout;

/// <summary>Base class for positioned layout elements on a page.</summary>
internal abstract class LayoutElement
{
    /// <summary>Gets or sets the X position in points from left edge.</summary>
    public float X { get; set; }

    /// <summary>Gets or sets the Y position in points from top edge.</summary>
    public float Y { get; set; }

    /// <summary>Gets or sets the width in points.</summary>
    public float Width { get; set; }

    /// <summary>Gets or sets the height in points.</summary>
    public float Height { get; set; }
}

/// <summary>A text element positioned on the page.</summary>
internal sealed class LayoutText : LayoutElement
{
    /// <summary>Gets or sets the text content.</summary>
    public string Text { get; set; } = string.Empty;

    /// <summary>Gets or sets the font name.</summary>
    public string FontName { get; set; } = "Calibri";

    /// <summary>Gets or sets the font size in points.</summary>
    public float FontSizePt { get; set; } = 12f;

    /// <summary>Gets or sets a value indicating whether the text is bold.</summary>
    public bool Bold { get; set; }

    /// <summary>Gets or sets a value indicating whether the text is italic.</summary>
    public bool Italic { get; set; }

    /// <summary>Gets or sets the text color as hex RGB.</summary>
    public string Color { get; set; } = "000000";

    /// <summary>Gets or sets the underline type.</summary>
    public Model.UnderlineType Underline { get; set; }

    /// <summary>Gets or sets a value indicating whether strikethrough is applied.</summary>
    public bool Strikethrough { get; set; }
}

/// <summary>A horizontal or vertical line element.</summary>
internal sealed class LayoutLine : LayoutElement
{
    /// <summary>Gets or sets the end X position.</summary>
    public float EndX { get; set; }

    /// <summary>Gets or sets the end Y position.</summary>
    public float EndY { get; set; }

    /// <summary>Gets or sets the line width in points.</summary>
    public float LineWidth { get; set; } = 0.5f;

    /// <summary>Gets or sets the line color as hex RGB.</summary>
    public string Color { get; set; } = "000000";
}

/// <summary>An image element positioned on the page.</summary>
internal sealed class LayoutImage : LayoutElement
{
    /// <summary>Gets or sets the image data.</summary>
    public byte[] Data { get; set; } = [];

    /// <summary>Gets or sets the image format (jpeg or png).</summary>
    public string Format { get; set; } = "jpeg";
}

/// <summary>A filled rectangle for table cell shading.</summary>
internal sealed class LayoutRect : LayoutElement
{
    /// <summary>Gets or sets the fill color as hex RGB.</summary>
    public string FillColor { get; set; } = "FFFFFF";
}

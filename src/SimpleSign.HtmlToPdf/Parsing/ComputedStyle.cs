using System.Globalization;

namespace SimpleSign.HtmlToPdf.Parsing;

/// <summary>
/// Computed style properties for an HTML node after CSS cascade resolution.
/// All values are resolved to concrete types (no "inherit" or "auto" strings).
/// Lengths are in points (1pt = 1/72 inch).
/// </summary>
public sealed class ComputedStyle
{
    // ── Font ──────────────────────────────────────────────────────────────────

    /// <summary>Gets or sets the font family name.</summary>
    public string FontFamily { get; set; } = "Helvetica";

    /// <summary>Gets or sets the font size in points.</summary>
    public float FontSize { get; set; } = 12f;

    /// <summary>Gets or sets a value indicating whether text is bold.</summary>
    public bool IsBold { get; set; }

    /// <summary>Gets or sets a value indicating whether text is italic.</summary>
    public bool IsItalic { get; set; }

    /// <summary>Gets or sets a value indicating whether text is underlined.</summary>
    public bool IsUnderline { get; set; }

    /// <summary>Gets or sets a value indicating whether text has a strikethrough.</summary>
    public bool IsStrikethrough { get; set; }

    /// <summary>Gets or sets the vertical font position (normal, subscript, superscript).</summary>
    public FontPosition FontPosition { get; set; } = FontPosition.Normal;

    // ── Text ──────────────────────────────────────────────────────────────────

    /// <summary>Gets or sets the text color.</summary>
    public PdfColor Color { get; set; } = PdfColor.Black;

    /// <summary>Gets or sets the text alignment.</summary>
    public TextAlign TextAlign { get; set; } = TextAlign.Left;

    /// <summary>Gets or sets the line height as a multiplier of font size.</summary>
    public float LineHeight { get; set; } = 1.4f;

    /// <summary>Gets or sets the text indent in points.</summary>
    public float TextIndent { get; set; }

    // ── Box model (all in points) ─────────────────────────────────────────────

    /// <summary>Gets or sets the margin thickness.</summary>
    public Thickness Margin { get; set; } = Thickness.Zero;

    /// <summary>Gets or sets the padding thickness.</summary>
    public Thickness Padding { get; set; } = Thickness.Zero;

    /// <summary>Gets or sets the border style.</summary>
    public BorderStyle Border { get; set; } = BorderStyle.None;

    // ── Layout ────────────────────────────────────────────────────────────────

    /// <summary>Gets or sets the explicit width in points. Null means auto.</summary>
    public float? Width { get; set; }

    /// <summary>Gets or sets the maximum width in points.</summary>
    public float? MaxWidth { get; set; }

    /// <summary>Gets or sets the explicit height in points. Null means auto.</summary>
    public float? Height { get; set; }

    /// <summary>Gets or sets the display type.</summary>
    public DisplayType Display { get; set; } = DisplayType.Block;

    /// <summary>Gets or sets the page-break-before behavior.</summary>
    public PageBreak PageBreakBefore { get; set; } = PageBreak.Auto;

    /// <summary>Gets or sets the page-break-after behavior.</summary>
    public PageBreak PageBreakAfter { get; set; } = PageBreak.Auto;

    // ── Visual ────────────────────────────────────────────────────────────────

    /// <summary>Gets or sets the background color. Null means transparent.</summary>
    public PdfColor? BackgroundColor { get; set; }

    // ── Table ─────────────────────────────────────────────────────────────────

    /// <summary>Gets or sets the vertical alignment for table cells.</summary>
    public VerticalAlign VerticalAlign { get; set; } = VerticalAlign.Top;

    /// <summary>Gets or sets a value indicating whether table borders should collapse.</summary>
    public bool BorderCollapse { get; set; }

    /// <summary>Creates a deep copy for inheritance.</summary>
    /// <returns>A cloned instance of this style.</returns>
    public ComputedStyle Clone() => (ComputedStyle)MemberwiseClone();
}

/// <summary>RGB color in 0-1 range for direct use in PDF operators.</summary>
/// <param name="R">Red component (0-1).</param>
/// <param name="G">Green component (0-1).</param>
/// <param name="B">Blue component (0-1).</param>
public readonly record struct PdfColor(float R, float G, float B)
{
    /// <summary>Black color (0, 0, 0).</summary>
    public static readonly PdfColor Black = new(0, 0, 0);

    /// <summary>White color (1, 1, 1).</summary>
    public static readonly PdfColor White = new(1, 1, 1);

    /// <summary>Gray color (#808080).</summary>
    public static readonly PdfColor Gray = new(0.502f, 0.502f, 0.502f);

    /// <summary>Light gray color (#ddd).</summary>
    public static readonly PdfColor LightGray = new(0.867f, 0.867f, 0.867f);

    /// <summary>Very light gray color (#f5f5f5).</summary>
    public static readonly PdfColor VeryLightGray = new(0.96f, 0.96f, 0.96f);

    /// <summary>Sentinel value representing a transparent/no color.</summary>
    public static readonly PdfColor Transparent = new(-1, -1, -1);

    /// <summary>Gets a value indicating whether this color is transparent.</summary>
    public bool IsTransparent => R < 0;

    private static readonly Dictionary<string, PdfColor> NamedColors = new(StringComparer.OrdinalIgnoreCase)
    {
        ["black"] = Black,
        ["white"] = White,
        ["red"] = new(1, 0, 0),
        ["green"] = new(0, 0.502f, 0),
        ["blue"] = new(0, 0, 1),
        ["gray"] = new(0.502f, 0.502f, 0.502f),
        ["grey"] = new(0.502f, 0.502f, 0.502f),
        ["navy"] = new(0, 0, 0.502f),
        ["maroon"] = new(0.502f, 0, 0),
        ["olive"] = new(0.502f, 0.502f, 0),
        ["teal"] = new(0, 0.502f, 0.502f),
        ["purple"] = new(0.502f, 0, 0.502f),
        ["silver"] = new(0.753f, 0.753f, 0.753f),
        ["aqua"] = new(0, 1, 1),
        ["fuchsia"] = new(1, 0, 1),
        ["lime"] = new(0, 1, 0),
        ["yellow"] = new(1, 1, 0),
        ["orange"] = new(1, 0.647f, 0),
        ["transparent"] = Transparent,
        // CSS3 extended colors
        ["lightblue"] = new(0.678f, 0.847f, 0.902f),
        ["lightgreen"] = new(0.565f, 0.933f, 0.565f),
        ["lightgray"] = new(0.827f, 0.827f, 0.827f),
        ["lightgrey"] = new(0.827f, 0.827f, 0.827f),
        ["darkgray"] = new(0.663f, 0.663f, 0.663f),
        ["darkgrey"] = new(0.663f, 0.663f, 0.663f),
        ["darkblue"] = new(0, 0, 0.545f),
        ["darkgreen"] = new(0, 0.392f, 0),
        ["darkred"] = new(0.545f, 0, 0),
        ["coral"] = new(1, 0.498f, 0.314f),
        ["crimson"] = new(0.863f, 0.078f, 0.235f),
        ["gold"] = new(1, 0.843f, 0),
        ["indigo"] = new(0.294f, 0, 0.510f),
        ["ivory"] = new(1, 1, 0.941f),
        ["khaki"] = new(0.941f, 0.902f, 0.549f),
        ["lavender"] = new(0.902f, 0.902f, 0.980f),
        ["linen"] = new(0.980f, 0.941f, 0.902f),
        ["magenta"] = new(1, 0, 1),
        ["cyan"] = new(0, 1, 1),
        ["pink"] = new(1, 0.753f, 0.796f),
        ["plum"] = new(0.867f, 0.627f, 0.867f),
        ["salmon"] = new(0.980f, 0.502f, 0.447f),
        ["tan"] = new(0.824f, 0.706f, 0.549f),
        ["tomato"] = new(1, 0.388f, 0.278f),
        ["turquoise"] = new(0.251f, 0.878f, 0.816f),
        ["violet"] = new(0.933f, 0.510f, 0.933f),
        ["wheat"] = new(0.961f, 0.871f, 0.702f),
    };

    /// <summary>
    /// Parses a CSS color value into a <see cref="PdfColor"/>.
    /// Supports #RGB, #RRGGBB, rgb(r,g,b), and named CSS colors.
    /// </summary>
    /// <param name="css">The CSS color string.</param>
    /// <returns>The parsed color.</returns>
    public static PdfColor Parse(string css)
    {
        string trimmed = css.Trim();

        if (NamedColors.TryGetValue(trimmed, out PdfColor named))
        {
            return named;
        }

        if (trimmed.StartsWith('#'))
        {
            return ParseHex(trimmed.AsSpan(1));
        }

        if (trimmed.StartsWith("rgb(", StringComparison.OrdinalIgnoreCase) && trimmed.EndsWith(')'))
        {
            return ParseRgb(trimmed.AsSpan(4, trimmed.Length - 5));
        }

        if (trimmed.StartsWith("rgba(", StringComparison.OrdinalIgnoreCase) && trimmed.EndsWith(')'))
        {
            return ParseRgb(trimmed.AsSpan(5, trimmed.Length - 6));
        }

        if (trimmed.StartsWith("hsl(", StringComparison.OrdinalIgnoreCase) && trimmed.EndsWith(')'))
        {
            return ParseHsl(trimmed.AsSpan(4, trimmed.Length - 5));
        }

        if (trimmed.StartsWith("hsla(", StringComparison.OrdinalIgnoreCase) && trimmed.EndsWith(')'))
        {
            return ParseHsl(trimmed.AsSpan(5, trimmed.Length - 6));
        }

        return Black;
    }

    private static PdfColor ParseHex(ReadOnlySpan<char> hex)
    {
        if (hex.Length == 3)
        {
            // #RGB -> #RRGGBB
            int r = ParseHexDigit(hex[0]);
            int g = ParseHexDigit(hex[1]);
            int b = ParseHexDigit(hex[2]);
            return new PdfColor(
                (r * 17) / 255f,
                (g * 17) / 255f,
                (b * 17) / 255f);
        }

        if (hex.Length == 6)
        {
            int r = (ParseHexDigit(hex[0]) << 4) | ParseHexDigit(hex[1]);
            int g = (ParseHexDigit(hex[2]) << 4) | ParseHexDigit(hex[3]);
            int b = (ParseHexDigit(hex[4]) << 4) | ParseHexDigit(hex[5]);
            return new PdfColor(r / 255f, g / 255f, b / 255f);
        }

        return Black;
    }

    private static int ParseHexDigit(char c) => c switch
    {
        >= '0' and <= '9' => c - '0',
        >= 'a' and <= 'f' => c - 'a' + 10,
        >= 'A' and <= 'F' => c - 'A' + 10,
        _ => 0,
    };

    private static PdfColor ParseRgb(ReadOnlySpan<char> inner)
    {
        Span<Range> parts = stackalloc Range[4];
        int count = inner.Split(parts, ',', StringSplitOptions.TrimEntries);
        if (count < 3)
        {
            return Black;
        }

        float r = ParseComponent(inner[parts[0]]);
        float g = ParseComponent(inner[parts[1]]);
        float b = ParseComponent(inner[parts[2]]);
        return new PdfColor(r, g, b);
    }

    private static float ParseComponent(ReadOnlySpan<char> value)
    {
        if (float.TryParse(value, NumberStyles.Float, CultureInfo.InvariantCulture, out float f))
        {
            return Math.Clamp(f / 255f, 0f, 1f);
        }

        return 0f;
    }

    private static PdfColor ParseHsl(ReadOnlySpan<char> inner)
    {
        Span<Range> parts = stackalloc Range[4];
        int count = inner.Split(parts, ',', StringSplitOptions.TrimEntries);
        if (count < 3)
        {
            return Black;
        }

        if (!float.TryParse(inner[parts[0]], NumberStyles.Float, CultureInfo.InvariantCulture, out float h))
        {
            return Black;
        }

        ReadOnlySpan<char> sPart = inner[parts[1]];
        if (sPart.EndsWith("%"))
        {
            sPart = sPart[..^1];
        }

        ReadOnlySpan<char> lPart = inner[parts[2]];
        if (lPart.EndsWith("%"))
        {
            lPart = lPart[..^1];
        }

        if (!float.TryParse(sPart, NumberStyles.Float, CultureInfo.InvariantCulture, out float s) ||
            !float.TryParse(lPart, NumberStyles.Float, CultureInfo.InvariantCulture, out float l))
        {
            return Black;
        }

        // Normalize: h to 0-360, s and l to 0-1
        h = ((h % 360) + 360) % 360;
        s = Math.Clamp(s / 100f, 0f, 1f);
        l = Math.Clamp(l / 100f, 0f, 1f);

        // HSL to RGB conversion
        float c = (1f - Math.Abs(2f * l - 1f)) * s;
        float x = c * (1f - Math.Abs((h / 60f) % 2f - 1f));
        float m = l - c / 2f;

        float r1, g1, b1;
        if (h < 60)
        {
            (r1, g1, b1) = (c, x, 0);
        }
        else if (h < 120)
        {
            (r1, g1, b1) = (x, c, 0);
        }
        else if (h < 180)
        {
            (r1, g1, b1) = (0, c, x);
        }
        else if (h < 240)
        {
            (r1, g1, b1) = (0, x, c);
        }
        else if (h < 300)
        {
            (r1, g1, b1) = (x, 0, c);
        }
        else
        {
            (r1, g1, b1) = (c, 0, x);
        }

        return new PdfColor(
            Math.Clamp(r1 + m, 0f, 1f),
            Math.Clamp(g1 + m, 0f, 1f),
            Math.Clamp(b1 + m, 0f, 1f));
    }
}

/// <summary>Box model thickness (top, right, bottom, left) in points.</summary>
/// <param name="Top">Top thickness.</param>
/// <param name="Right">Right thickness.</param>
/// <param name="Bottom">Bottom thickness.</param>
/// <param name="Left">Left thickness.</param>
public readonly record struct Thickness(float Top, float Right, float Bottom, float Left)
{
    /// <summary>Zero thickness on all sides.</summary>
    public static readonly Thickness Zero = new(0, 0, 0, 0);

    /// <summary>Creates a uniform thickness on all sides.</summary>
    /// <param name="all">The thickness for all four sides.</param>
    /// <returns>Uniform thickness.</returns>
    public static Thickness Uniform(float all) => new(all, all, all, all);

    /// <summary>Creates a thickness with a single value for all sides.</summary>
    /// <param name="all">The thickness for all four sides.</param>
    public Thickness(float all) : this(all, all, all, all) { }

    /// <summary>Creates a thickness with vertical and horizontal values.</summary>
    /// <param name="vertical">The thickness for top and bottom.</param>
    /// <param name="horizontal">The thickness for left and right.</param>
    public Thickness(float vertical, float horizontal) : this(vertical, horizontal, vertical, horizontal) { }
}

/// <summary>Border style for one or all sides of a box.</summary>
public sealed class BorderStyle
{
    /// <summary>A border style with no borders.</summary>
    public static readonly BorderStyle None = new();

    /// <summary>Gets or sets the top border width in points.</summary>
    public float TopWidth { get; set; }

    /// <summary>Gets or sets the right border width in points.</summary>
    public float RightWidth { get; set; }

    /// <summary>Gets or sets the bottom border width in points.</summary>
    public float BottomWidth { get; set; }

    /// <summary>Gets or sets the left border width in points.</summary>
    public float LeftWidth { get; set; }

    /// <summary>Gets or sets the top border color.</summary>
    public PdfColor TopColor { get; set; } = PdfColor.Black;

    /// <summary>Gets or sets the right border color.</summary>
    public PdfColor RightColor { get; set; } = PdfColor.Black;

    /// <summary>Gets or sets the bottom border color.</summary>
    public PdfColor BottomColor { get; set; } = PdfColor.Black;

    /// <summary>Gets or sets the left border color.</summary>
    public PdfColor LeftColor { get; set; } = PdfColor.Black;

    /// <summary>Gets a value indicating whether any border side has a non-zero width.</summary>
    public bool HasBorder => TopWidth > 0 || RightWidth > 0 || BottomWidth > 0 || LeftWidth > 0;

    /// <summary>Creates a deep copy of this border style.</summary>
    /// <returns>A cloned instance.</returns>
    public BorderStyle Clone() => (BorderStyle)MemberwiseClone();
}

/// <summary>Text alignment options.</summary>
public enum TextAlign
{
    /// <summary>Left-aligned text.</summary>
    Left,

    /// <summary>Center-aligned text.</summary>
    Center,

    /// <summary>Right-aligned text.</summary>
    Right,

    /// <summary>Justified text.</summary>
    Justify,
}

/// <summary>CSS display type.</summary>
public enum DisplayType
{
    /// <summary>Block-level element.</summary>
    Block,

    /// <summary>Inline element.</summary>
    Inline,

    /// <summary>Hidden element (display: none).</summary>
    None,

    /// <summary>Table display.</summary>
    Table,

    /// <summary>Table cell display.</summary>
    TableCell,

    /// <summary>Table row display.</summary>
    TableRow,

    /// <summary>List item display.</summary>
    ListItem,
}

/// <summary>Page break behavior.</summary>
public enum PageBreak
{
    /// <summary>Automatic page break.</summary>
    Auto,

    /// <summary>Force a page break.</summary>
    Always,

    /// <summary>Avoid a page break if possible.</summary>
    Avoid,
}

/// <summary>Vertical alignment for table cells.</summary>
public enum VerticalAlign
{
    /// <summary>Align content to top.</summary>
    Top,

    /// <summary>Align content to middle.</summary>
    Middle,

    /// <summary>Align content to bottom.</summary>
    Bottom,
}

/// <summary>Vertical font position for subscript/superscript rendering.</summary>
public enum FontPosition
{
    /// <summary>Normal baseline position.</summary>
    Normal,

    /// <summary>Subscript: smaller font, below baseline.</summary>
    Subscript,

    /// <summary>Superscript: smaller font, above baseline.</summary>
    Superscript,
}

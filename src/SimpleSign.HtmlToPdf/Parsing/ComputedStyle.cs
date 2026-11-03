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

    /// <summary>Gets or sets the font family name (the first family of the CSS list).</summary>
    public string FontFamily { get; set; } = "Helvetica";

    /// <summary>Gets or sets the complete CSS <c>font-family</c> fallback list, in priority order.</summary>
    public IReadOnlyList<string> FontFamilies { get; set; } = ["Helvetica"];

    /// <summary>Gets or sets the numeric font weight (100–900). Values of 600 and above render bold.</summary>
    public int FontWeight { get; set; } = 400;

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
    public TextAlign TextAlign
    {
        get => _textAlign;
        set
        {
            _textAlign = value;
            LogicalAlign = null;
        }
    }

    private TextAlign _textAlign = TextAlign.Left;

    /// <summary>Gets the logical alignment (<c>start</c>/<c>end</c>, the initial value is start); null when a physical value was set.</summary>
    internal LogicalTextAlign? LogicalAlign { get; set; } = LogicalTextAlign.Start;

    /// <summary>Gets a value indicating whether the inline base direction is right-to-left (<c>direction: rtl</c>).</summary>
    internal bool Rtl { get; set; }

    /// <summary>Gets the physical alignment after resolving start/end against the direction.</summary>
    internal TextAlign EffectiveTextAlign => LogicalAlign switch
    {
        LogicalTextAlign.Start => Rtl ? TextAlign.Right : TextAlign.Left,
        LogicalTextAlign.End => Rtl ? TextAlign.Left : TextAlign.Right,
        _ => TextAlign,
    };

    /// <summary>Gets or sets the line height as a multiplier of font size.</summary>
    public float LineHeight { get; set; } = 1.4f;

    /// <summary>Gets or sets the text indent in points.</summary>
    public float TextIndent { get; set; }

    /// <summary>Gets or sets how whitespace is preserved and wrapped.</summary>
    public WhiteSpaceMode WhiteSpace { get; set; } = WhiteSpaceMode.Normal;

    /// <summary>Gets or sets how unbreakable words may wrap.</summary>
    public WordBreakMode WordBreak { get; set; } = WordBreakMode.Normal;

    /// <summary>Gets or sets whether long words may break anywhere to avoid overflow.</summary>
    public bool OverflowWrapAnywhere { get; set; }

    /// <summary>Gets or sets CSS text-transform for text runs.</summary>
    public TextTransformMode TextTransform { get; set; }

    /// <summary>Gets or sets additional spacing between glyphs in points.</summary>
    public float LetterSpacing { get; set; }

    /// <summary>Gets or sets additional spacing after spaces in points.</summary>
    public float WordSpacing { get; set; }

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

    /// <summary>Gets or sets the minimum width in points (negative values are percentages).</summary>
    public float? MinWidth { get; set; }

    /// <summary>Gets or sets the minimum height in points.</summary>
    public float? MinHeight { get; set; }

    /// <summary>Gets or sets the maximum height in points.</summary>
    public float? MaxHeight { get; set; }

    /// <summary>Gets or sets a value indicating whether the left margin is <c>auto</c>.</summary>
    public bool MarginLeftAuto { get; set; }

    /// <summary>Gets or sets a value indicating whether the right margin is <c>auto</c>.</summary>
    public bool MarginRightAuto { get; set; }

    /// <summary>Gets or sets the box-sizing model.</summary>
    public BoxSizing BoxSizing { get; set; } = BoxSizing.ContentBox;

    /// <summary>Gets or sets the float placement.</summary>
    public FloatMode Float { get; set; } = FloatMode.None;

    /// <summary>Gets or sets which floats this box clears.</summary>
    public ClearMode Clear { get; set; } = ClearMode.None;

    /// <summary>Gets or sets the positioning scheme.</summary>
    public PositionMode Position { get; set; } = PositionMode.Static;

    /// <summary>Gets or sets the <c>top</c> offset in points (null = auto).</summary>
    public float? Top { get; set; }

    /// <summary>Gets or sets the <c>right</c> offset in points (null = auto).</summary>
    public float? Right { get; set; }

    /// <summary>Gets or sets the <c>bottom</c> offset in points (null = auto).</summary>
    public float? Bottom { get; set; }

    /// <summary>Gets or sets the <c>left</c> offset in points (null = auto).</summary>
    public float? Left { get; set; }

    /// <summary>Gets or sets a value indicating whether overflow is clipped (establishes a block formatting context).</summary>
    public bool OverflowHidden { get; set; }

    /// <summary>Gets or sets a value indicating whether the box is invisible but still occupies space.</summary>
    public bool IsHidden { get; set; }

    /// <summary>Gets or sets the grid column template (raw CSS value) for <c>display: grid</c>.</summary>
    public string? GridTemplateColumns { get; set; }

    /// <summary>Gets or sets the raw <c>grid-column</c> placement of a grid item (e.g. <c>span 2</c>, <c>1 / -1</c>).</summary>
    public string? GridColumn { get; set; }

    /// <summary>Gets or sets the gap between rows for flex wrapping and grids in points.</summary>
    public float RowGap { get; set; }

    /// <summary>Gets or sets the flex container direction.</summary>
    public FlexDirection FlexDirection { get; set; } = FlexDirection.Row;

    /// <summary>Gets or sets the main-axis item alignment.</summary>
    public JustifyContent JustifyContent { get; set; } = JustifyContent.Start;

    /// <summary>Gets or sets the cross-axis item alignment.</summary>
    public AlignItems AlignItems { get; set; } = AlignItems.Stretch;

    /// <summary>Gets or sets the gap between flex items in points.</summary>
    public float Gap { get; set; }

    /// <summary>Gets or sets whether a flex row wraps onto additional rows.</summary>
    public bool FlexWrap { get; set; }

    /// <summary>Gets or sets the flex grow factor.</summary>
    public float FlexGrow { get; set; }

    /// <summary>Gets or sets the flex shrink factor.</summary>
    public float FlexShrink { get; set; } = 1;

    /// <summary>Gets or sets the flex basis in points (negative values are percentages).</summary>
    public float? FlexBasis { get; set; }

    /// <summary>Gets or sets the display type.</summary>
    public DisplayType Display { get; set; } = DisplayType.Block;

    /// <summary>Gets or sets the page-break-before behavior.</summary>
    public PageBreak PageBreakBefore { get; set; } = PageBreak.Auto;

    /// <summary>Gets or sets the page-break-after behavior.</summary>
    public PageBreak PageBreakAfter { get; set; } = PageBreak.Auto;

    /// <summary>Gets or sets the page-break-inside behavior (<c>avoid</c> keeps the box on one page when it fits).</summary>
    public PageBreak PageBreakInside { get; set; } = PageBreak.Auto;

    /// <summary>Gets or sets the minimum number of lines left at the bottom of a page.</summary>
    public int Orphans { get; set; } = 2;

    /// <summary>Gets or sets the minimum number of lines carried to the top of a page.</summary>
    public int Widows { get; set; } = 2;

    // ── Lists ─────────────────────────────────────────────────────────────────

    /// <summary>Gets or sets the list marker type (<c>disc</c>, <c>decimal</c>, <c>lower-roman</c>, <c>none</c>, ...).</summary>
    public string ListStyleType { get; set; } = "disc";

    /// <summary>Gets or sets a value indicating whether the list marker is placed inside the content box.</summary>
    public bool ListStyleInside { get; set; }

    // ── Visual ────────────────────────────────────────────────────────────────

    /// <summary>Gets or sets the background color. Null means transparent.</summary>
    public PdfColor? BackgroundColor { get; set; }

    // ── Table ─────────────────────────────────────────────────────────────────

    /// <summary>Gets or sets the vertical alignment for table cells.</summary>
    public VerticalAlign VerticalAlign { get; set; } = VerticalAlign.Top;

    /// <summary>Gets or sets a value indicating whether table borders should collapse.</summary>
    public bool BorderCollapse { get; set; }

    /// <summary>Gets or sets the spacing between cells for the separated border model, in points.</summary>
    public float BorderSpacing { get; set; } = 1.5f;

    /// <summary>Gets or sets the corner radius in points.</summary>
    public float BorderRadius { get; set; }

    /// <summary>Gets the CSS custom properties visible to this element.</summary>
    internal IReadOnlyDictionary<string, string>? CustomProperties { get; set; }

    /// <summary>Gets or sets the opacity applied to the element and its descendants (0–1).</summary>
    public float Opacity { get; set; } = 1f;

    /// <summary>Gets the background image layers (first is painted on top); null entries are <c>none</c>.</summary>
    internal IReadOnlyList<CssImage?>? BackgroundImages { get; set; }

    /// <summary>Gets the per-layer background positions.</summary>
    internal IReadOnlyList<CssPosition>? BackgroundPositions { get; set; }

    /// <summary>Gets the per-layer background sizes.</summary>
    internal IReadOnlyList<BackgroundSize>? BackgroundSizes { get; set; }

    /// <summary>Gets the per-layer repeat modes.</summary>
    internal IReadOnlyList<BackgroundRepeat>? BackgroundRepeats { get; set; }

    /// <summary>Gets the per-layer positioning areas.</summary>
    internal IReadOnlyList<BackgroundBox>? BackgroundOrigins { get; set; }

    /// <summary>Gets the per-layer painting areas.</summary>
    internal IReadOnlyList<BackgroundBox>? BackgroundClips { get; set; }

    /// <summary>Gets the box shadows.</summary>
    internal IReadOnlyList<CssShadow>? BoxShadows { get; set; }

    /// <summary>Gets the text shadows (inherited).</summary>
    internal IReadOnlyList<CssShadow>? TextShadows { get; set; }

    /// <summary>Gets the transform functions.</summary>
    internal IReadOnlyList<TransformFunction>? Transform { get; set; }

    /// <summary>Gets the transform origin.</summary>
    internal CssPosition TransformOrigin { get; set; } = CssPosition.CenterCenter;

    /// <summary>Gets SVG paint properties declared through CSS (fill, stroke, ...), applied over presentation attributes.</summary>
    internal IReadOnlyDictionary<string, string>? SvgProperties { get; set; }

    /// <summary>Gets the content language (from the nearest <c>lang</c> attribute), used for hyphenation.</summary>
    internal string? Language { get; set; }

    /// <summary>Gets the <c>hyphens</c> mode.</summary>
    internal HyphensMode Hyphens { get; set; } = HyphensMode.Manual;

    /// <summary>Gets the <c>column-count</c> (0 = auto).</summary>
    internal int ColumnCount { get; set; }

    /// <summary>Gets the <c>column-width</c> in points (null = auto).</summary>
    internal float? ColumnWidth { get; set; }

    /// <summary>Gets a value indicating whether a column/row gap was declared (multi-column defaults to 1em otherwise).</summary>
    internal bool GapDeclared { get; set; }

    /// <summary>Gets the column rule width.</summary>
    internal float ColumnRuleWidth { get; set; }

    /// <summary>Gets the column rule line style.</summary>
    internal BorderLineStyle ColumnRuleStyle { get; set; } = BorderLineStyle.None;

    /// <summary>Gets the column rule color (null = currentColor).</summary>
    internal PdfColor? ColumnRuleColor { get; set; }

    /// <summary>Gets a value indicating whether the element spans all columns (<c>column-span: all</c>).</summary>
    internal bool ColumnSpanAll { get; set; }

    /// <summary>Gets the raw <c>counter-reset</c> value.</summary>
    internal string? CounterReset { get; set; }

    /// <summary>Gets the raw <c>counter-increment</c> value.</summary>
    internal string? CounterIncrement { get; set; }

    /// <summary>Gets the raw <c>counter-set</c> value.</summary>
    internal string? CounterSet { get; set; }

    /// <summary>Gets a value indicating whether descendants are clipped to the padding box (<c>overflow</c> other than visible).</summary>
    internal bool ClipsContent { get; set; }

    /// <summary>Gets the PDF blend mode name for <c>mix-blend-mode</c>, or null for normal.</summary>
    internal string? BlendMode { get; set; }

    /// <summary>Gets a value indicating whether any background image layer is set.</summary>
    internal bool HasBackgroundImage => BackgroundImages is { } images && images.Any(i => i is not null);

    /// <summary>Gets the length properties whose <c>calc()</c>/<c>min()</c>/<c>max()</c> value depends on the containing block.</summary>
    internal IReadOnlyList<KeyValuePair<string, CssCalc>>? Calcs { get; set; }

    /// <summary>Creates a deep copy for inheritance.</summary>
    /// <returns>A cloned instance of this style.</returns>
    public ComputedStyle Clone()
    {
        var clone = (ComputedStyle)MemberwiseClone();
        if (clone.Border is not null && clone.Border != BorderStyle.None)
        {
            clone.Border = clone.Border.Clone();
        }

        return clone;
    }
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

    // Stored as transparency so default(PdfColor) stays opaque.
    private readonly float _transparency;

    /// <summary>Gets the opacity from 0 (invisible) to 1 (opaque). Translucent colors are drawn with PDF transparency.</summary>
    public float Alpha
    {
        get => 1f - _transparency;
        init => _transparency = 1f - Math.Clamp(value, 0f, 1f);
    }

    /// <summary>Returns the same color with a different opacity.</summary>
    /// <param name="alpha">The opacity from 0 to 1.</param>
    /// <returns>The color with the given opacity.</returns>
    public PdfColor WithAlpha(float alpha) => this with { Alpha = alpha };

    private static readonly Dictionary<string, PdfColor> NamedColors = new(StringComparer.OrdinalIgnoreCase)
    {
        ["aliceblue"] = new(0.941f, 0.973f, 1.000f),
        ["antiquewhite"] = new(0.980f, 0.922f, 0.843f),
        ["aqua"] = new(0, 1, 1),
        ["aquamarine"] = new(0.498f, 1.000f, 0.831f),
        ["azure"] = new(0.941f, 1.000f, 1.000f),
        ["beige"] = new(0.961f, 0.961f, 0.863f),
        ["bisque"] = new(1.000f, 0.894f, 0.769f),
        ["black"] = Black,
        ["blanchedalmond"] = new(1.000f, 0.922f, 0.804f),
        ["blue"] = new(0, 0, 1),
        ["blueviolet"] = new(0.541f, 0.169f, 0.886f),
        ["brown"] = new(0.647f, 0.165f, 0.165f),
        ["burlywood"] = new(0.871f, 0.722f, 0.529f),
        ["cadetblue"] = new(0.373f, 0.620f, 0.627f),
        ["chartreuse"] = new(0.498f, 1.000f, 0.000f),
        ["chocolate"] = new(0.824f, 0.412f, 0.118f),
        ["coral"] = new(1, 0.498f, 0.314f),
        ["cornflowerblue"] = new(0.392f, 0.584f, 0.929f),
        ["cornsilk"] = new(1.000f, 0.973f, 0.863f),
        ["crimson"] = new(0.863f, 0.078f, 0.235f),
        ["cyan"] = new(0, 1, 1),
        ["darkblue"] = new(0, 0, 0.545f),
        ["darkcyan"] = new(0.000f, 0.545f, 0.545f),
        ["darkgoldenrod"] = new(0.722f, 0.525f, 0.043f),
        ["darkgray"] = new(0.663f, 0.663f, 0.663f),
        ["darkgreen"] = new(0, 0.392f, 0),
        ["darkgrey"] = new(0.663f, 0.663f, 0.663f),
        ["darkkhaki"] = new(0.741f, 0.718f, 0.420f),
        ["darkmagenta"] = new(0.545f, 0.000f, 0.545f),
        ["darkolivegreen"] = new(0.333f, 0.420f, 0.184f),
        ["darkorange"] = new(1.000f, 0.549f, 0.000f),
        ["darkorchid"] = new(0.600f, 0.196f, 0.800f),
        ["darkred"] = new(0.545f, 0, 0),
        ["darksalmon"] = new(0.914f, 0.588f, 0.478f),
        ["darkseagreen"] = new(0.561f, 0.737f, 0.561f),
        ["darkslateblue"] = new(0.282f, 0.239f, 0.545f),
        ["darkslategray"] = new(0.184f, 0.310f, 0.310f),
        ["darkslategrey"] = new(0.184f, 0.310f, 0.310f),
        ["darkturquoise"] = new(0.000f, 0.808f, 0.820f),
        ["darkviolet"] = new(0.580f, 0.000f, 0.827f),
        ["deeppink"] = new(1.000f, 0.078f, 0.576f),
        ["deepskyblue"] = new(0.000f, 0.749f, 1.000f),
        ["dimgray"] = new(0.412f, 0.412f, 0.412f),
        ["dimgrey"] = new(0.412f, 0.412f, 0.412f),
        ["dodgerblue"] = new(0.118f, 0.565f, 1.000f),
        ["firebrick"] = new(0.698f, 0.133f, 0.133f),
        ["floralwhite"] = new(1.000f, 0.980f, 0.941f),
        ["forestgreen"] = new(0.133f, 0.545f, 0.133f),
        ["fuchsia"] = new(1, 0, 1),
        ["gainsboro"] = new(0.863f, 0.863f, 0.863f),
        ["ghostwhite"] = new(0.973f, 0.973f, 1.000f),
        ["gold"] = new(1, 0.843f, 0),
        ["goldenrod"] = new(0.855f, 0.647f, 0.125f),
        ["gray"] = new(0.502f, 0.502f, 0.502f),
        ["green"] = new(0, 0.502f, 0),
        ["greenyellow"] = new(0.678f, 1.000f, 0.184f),
        ["grey"] = new(0.502f, 0.502f, 0.502f),
        ["honeydew"] = new(0.941f, 1.000f, 0.941f),
        ["hotpink"] = new(1.000f, 0.412f, 0.706f),
        ["indianred"] = new(0.804f, 0.361f, 0.361f),
        ["indigo"] = new(0.294f, 0, 0.510f),
        ["ivory"] = new(1, 1, 0.941f),
        ["khaki"] = new(0.941f, 0.902f, 0.549f),
        ["lavender"] = new(0.902f, 0.902f, 0.980f),
        ["lavenderblush"] = new(1.000f, 0.941f, 0.961f),
        ["lawngreen"] = new(0.486f, 0.988f, 0.000f),
        ["lemonchiffon"] = new(1.000f, 0.980f, 0.804f),
        ["lightblue"] = new(0.678f, 0.847f, 0.902f),
        ["lightcoral"] = new(0.941f, 0.502f, 0.502f),
        ["lightcyan"] = new(0.878f, 1.000f, 1.000f),
        ["lightgoldenrodyellow"] = new(0.980f, 0.980f, 0.824f),
        ["lightgray"] = new(0.827f, 0.827f, 0.827f),
        ["lightgreen"] = new(0.565f, 0.933f, 0.565f),
        ["lightgrey"] = new(0.827f, 0.827f, 0.827f),
        ["lightpink"] = new(1.000f, 0.714f, 0.757f),
        ["lightsalmon"] = new(1.000f, 0.627f, 0.478f),
        ["lightseagreen"] = new(0.125f, 0.698f, 0.667f),
        ["lightskyblue"] = new(0.529f, 0.808f, 0.980f),
        ["lightslategray"] = new(0.467f, 0.533f, 0.600f),
        ["lightslategrey"] = new(0.467f, 0.533f, 0.600f),
        ["lightsteelblue"] = new(0.690f, 0.769f, 0.871f),
        ["lightyellow"] = new(1.000f, 1.000f, 0.878f),
        ["lime"] = new(0, 1, 0),
        ["limegreen"] = new(0.196f, 0.804f, 0.196f),
        ["linen"] = new(0.980f, 0.941f, 0.902f),
        ["magenta"] = new(1, 0, 1),
        ["maroon"] = new(0.502f, 0, 0),
        ["mediumaquamarine"] = new(0.400f, 0.804f, 0.667f),
        ["mediumblue"] = new(0.000f, 0.000f, 0.804f),
        ["mediumorchid"] = new(0.729f, 0.333f, 0.827f),
        ["mediumpurple"] = new(0.576f, 0.439f, 0.859f),
        ["mediumseagreen"] = new(0.235f, 0.702f, 0.443f),
        ["mediumslateblue"] = new(0.482f, 0.408f, 0.933f),
        ["mediumspringgreen"] = new(0.000f, 0.980f, 0.604f),
        ["mediumturquoise"] = new(0.282f, 0.820f, 0.800f),
        ["mediumvioletred"] = new(0.780f, 0.082f, 0.522f),
        ["midnightblue"] = new(0.098f, 0.098f, 0.439f),
        ["mintcream"] = new(0.961f, 1.000f, 0.980f),
        ["mistyrose"] = new(1.000f, 0.894f, 0.882f),
        ["moccasin"] = new(1.000f, 0.894f, 0.710f),
        ["navajowhite"] = new(1.000f, 0.871f, 0.678f),
        ["navy"] = new(0, 0, 0.502f),
        ["oldlace"] = new(0.992f, 0.961f, 0.902f),
        ["olive"] = new(0.502f, 0.502f, 0),
        ["olivedrab"] = new(0.420f, 0.557f, 0.137f),
        ["orange"] = new(1, 0.647f, 0),
        ["orangered"] = new(1.000f, 0.271f, 0.000f),
        ["orchid"] = new(0.855f, 0.439f, 0.839f),
        ["palegoldenrod"] = new(0.933f, 0.910f, 0.667f),
        ["palegreen"] = new(0.596f, 0.984f, 0.596f),
        ["paleturquoise"] = new(0.686f, 0.933f, 0.933f),
        ["palevioletred"] = new(0.859f, 0.439f, 0.576f),
        ["papayawhip"] = new(1.000f, 0.937f, 0.835f),
        ["peachpuff"] = new(1.000f, 0.855f, 0.725f),
        ["peru"] = new(0.804f, 0.522f, 0.247f),
        ["pink"] = new(1, 0.753f, 0.796f),
        ["plum"] = new(0.867f, 0.627f, 0.867f),
        ["powderblue"] = new(0.690f, 0.878f, 0.902f),
        ["purple"] = new(0.502f, 0, 0.502f),
        ["rebeccapurple"] = new(0.400f, 0.200f, 0.600f),
        ["red"] = new(1, 0, 0),
        ["rosybrown"] = new(0.737f, 0.561f, 0.561f),
        ["royalblue"] = new(0.255f, 0.412f, 0.882f),
        ["saddlebrown"] = new(0.545f, 0.271f, 0.075f),
        ["salmon"] = new(0.980f, 0.502f, 0.447f),
        ["sandybrown"] = new(0.957f, 0.643f, 0.376f),
        ["seagreen"] = new(0.180f, 0.545f, 0.341f),
        ["seashell"] = new(1.000f, 0.961f, 0.933f),
        ["sienna"] = new(0.627f, 0.322f, 0.176f),
        ["silver"] = new(0.753f, 0.753f, 0.753f),
        ["skyblue"] = new(0.529f, 0.808f, 0.922f),
        ["slateblue"] = new(0.416f, 0.353f, 0.804f),
        ["slategray"] = new(0.439f, 0.502f, 0.565f),
        ["slategrey"] = new(0.439f, 0.502f, 0.565f),
        ["snow"] = new(1.000f, 0.980f, 0.980f),
        ["springgreen"] = new(0.000f, 1.000f, 0.498f),
        ["steelblue"] = new(0.275f, 0.510f, 0.706f),
        ["tan"] = new(0.824f, 0.706f, 0.549f),
        ["teal"] = new(0, 0.502f, 0.502f),
        ["thistle"] = new(0.847f, 0.749f, 0.847f),
        ["tomato"] = new(1, 0.388f, 0.278f),
        ["turquoise"] = new(0.251f, 0.878f, 0.816f),
        ["violet"] = new(0.933f, 0.510f, 0.933f),
        ["wheat"] = new(0.961f, 0.871f, 0.702f),
        ["white"] = White,
        ["whitesmoke"] = new(0.961f, 0.961f, 0.961f),
        ["yellow"] = new(1, 1, 0),
        ["yellowgreen"] = new(0.604f, 0.804f, 0.196f),
        ["transparent"] = Transparent,
    };

    /// <summary>Returns true when the value is a CSS named color known to the parser.</summary>
    /// <param name="name">The candidate color name.</param>
    /// <returns>True for a known named color.</returns>
    public static bool IsNamedColor(string name) => NamedColors.ContainsKey(name.Trim());

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
        if (hex.Length is 3 or 4)
        {
            // #RGB(A) -> #RRGGBB(AA)
            int r = ParseHexDigit(hex[0]);
            int g = ParseHexDigit(hex[1]);
            int b = ParseHexDigit(hex[2]);
            float alpha = hex.Length == 4 ? ParseHexDigit(hex[3]) * 17 / 255f : 1f;
            return WithOpacity(r * 17 / 255f, g * 17 / 255f, b * 17 / 255f, alpha);
        }

        if (hex.Length is 6 or 8)
        {
            int r = (ParseHexDigit(hex[0]) << 4) | ParseHexDigit(hex[1]);
            int g = (ParseHexDigit(hex[2]) << 4) | ParseHexDigit(hex[3]);
            int b = (ParseHexDigit(hex[4]) << 4) | ParseHexDigit(hex[5]);
            float alpha = hex.Length == 8 ? ((ParseHexDigit(hex[6]) << 4) | ParseHexDigit(hex[7])) / 255f : 1f;
            return WithOpacity(r / 255f, g / 255f, b / 255f, alpha);
        }

        return Black;
    }

    /// <summary>
    /// Builds a color with the given opacity. Fully transparent colors map to <see cref="Transparent"/>.
    /// </summary>
    private static PdfColor WithOpacity(float r, float g, float b, float alpha)
    {
        if (alpha <= 0f)
        {
            return Transparent;
        }

        return alpha >= 1f ? new PdfColor(r, g, b) : new PdfColor(r, g, b) { Alpha = alpha };
    }

    private static int ParseHexDigit(char c) => c switch
    {
        >= '0' and <= '9' => c - '0',
        >= 'a' and <= 'f' => c - 'a' + 10,
        >= 'A' and <= 'F' => c - 'A' + 10,
        _ => 0,
    };

    private static List<string> SplitColorArguments(ReadOnlySpan<char> inner) =>
        [.. inner.ToString().Replace("/", " ", StringComparison.Ordinal)
            .Split([',', ' ', '\t'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)];

    private static PdfColor ParseRgb(ReadOnlySpan<char> inner)
    {
        List<string> parts = SplitColorArguments(inner);
        if (parts.Count < 3)
        {
            return Black;
        }

        float r = ParseComponent(parts[0]);
        float g = ParseComponent(parts[1]);
        float b = ParseComponent(parts[2]);
        float alpha = parts.Count > 3 ? ParseAlpha(parts[3]) : 1f;
        return WithOpacity(r, g, b, alpha);
    }

    private static float ParseComponent(string value)
    {
        if (value.EndsWith('%') && float.TryParse(value[..^1], NumberStyles.Float, CultureInfo.InvariantCulture, out float pct))
        {
            return Math.Clamp(pct / 100f, 0f, 1f);
        }

        if (float.TryParse(value, NumberStyles.Float, CultureInfo.InvariantCulture, out float f))
        {
            return Math.Clamp(f / 255f, 0f, 1f);
        }

        return 0f;
    }

    private static float ParseAlpha(string value)
    {
        if (value.EndsWith('%') && float.TryParse(value[..^1], NumberStyles.Float, CultureInfo.InvariantCulture, out float pct))
        {
            return Math.Clamp(pct / 100f, 0f, 1f);
        }

        return float.TryParse(value, NumberStyles.Float, CultureInfo.InvariantCulture, out float f)
            ? Math.Clamp(f, 0f, 1f)
            : 1f;
    }

    private static PdfColor ParseHsl(ReadOnlySpan<char> inner)
    {
        List<string> parts = SplitColorArguments(inner);
        if (parts.Count < 3)
        {
            return Black;
        }

        if (!float.TryParse(parts[0].Replace("deg", string.Empty, StringComparison.OrdinalIgnoreCase), NumberStyles.Float, CultureInfo.InvariantCulture, out float h))
        {
            return Black;
        }

        string sPart = parts[1].TrimEnd('%');
        string lPart = parts[2].TrimEnd('%');
        float alpha = parts.Count > 3 ? ParseAlpha(parts[3]) : 1f;

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

        return WithOpacity(
            Math.Clamp(r1 + m, 0f, 1f),
            Math.Clamp(g1 + m, 0f, 1f),
            Math.Clamp(b1 + m, 0f, 1f),
            alpha);
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

    /// <summary>Gets or sets the top border line style.</summary>
    public BorderLineStyle TopStyle { get; set; } = BorderLineStyle.Solid;

    /// <summary>Gets or sets the right border line style.</summary>
    public BorderLineStyle RightStyle { get; set; } = BorderLineStyle.Solid;

    /// <summary>Gets or sets the bottom border line style.</summary>
    public BorderLineStyle BottomStyle { get; set; } = BorderLineStyle.Solid;

    /// <summary>Gets or sets the left border line style.</summary>
    public BorderLineStyle LeftStyle { get; set; } = BorderLineStyle.Solid;

    /// <summary>Gets a value indicating whether all four sides share the same width, color, and style.</summary>
    public bool IsUniform =>
        TopWidth == RightWidth && TopWidth == BottomWidth && TopWidth == LeftWidth
        && TopColor == RightColor && TopColor == BottomColor && TopColor == LeftColor
        && TopStyle == RightStyle && TopStyle == BottomStyle && TopStyle == LeftStyle;

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

/// <summary>CSS white-space behavior supported by the HTML-to-PDF layout engine.</summary>
public enum WhiteSpaceMode
{
    /// <summary>Collapse whitespace and wrap at word boundaries.</summary>
    Normal,
    /// <summary>Collapse whitespace but do not wrap.</summary>
    NoWrap,
    /// <summary>Preserve whitespace and line breaks; do not wrap.</summary>
    Pre,
    /// <summary>Preserve whitespace and line breaks; wrap when needed.</summary>
    PreWrap,
    /// <summary>Collapse spaces while preserving explicit line breaks.</summary>
    PreLine,
}

/// <summary>CSS word-break behavior supported by the HTML-to-PDF layout engine.</summary>
public enum WordBreakMode
{
    /// <summary>Break at spaces only.</summary>
    Normal,
    /// <summary>Allow breaks between any Unicode scalar values.</summary>
    BreakAll,
    /// <summary>Prefer whole words (currently handled like normal).</summary>
    KeepAll,
}

/// <summary>CSS text-transform behavior.</summary>
public enum TextTransformMode
{
    /// <summary>Preserve source casing.</summary>
    None,
    /// <summary>Convert text to uppercase.</summary>
    Uppercase,
    /// <summary>Convert text to lowercase.</summary>
    Lowercase,
    /// <summary>Capitalize the first letter after each word boundary.</summary>
    Capitalize,
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

    /// <summary>Flex container.</summary>
    Flex,

    /// <summary>Atomic inline box laid out as a block and placed on the line.</summary>
    InlineBlock,

    /// <summary>Grid container (column templates with automatic row placement).</summary>
    Grid,

    /// <summary>Block container that establishes a new block formatting context.</summary>
    FlowRoot,
}

/// <summary>Border line style.</summary>
public enum BorderLineStyle
{
    /// <summary>Solid line.</summary>
    Solid,

    /// <summary>Dashed line.</summary>
    Dashed,

    /// <summary>Dotted line.</summary>
    Dotted,

    /// <summary>Two parallel solid lines.</summary>
    Double,

    /// <summary>No border.</summary>
    None,
}

/// <summary>CSS box-sizing.</summary>
public enum BoxSizing
{
    /// <summary>Width and height size the content box.</summary>
    ContentBox,

    /// <summary>Width and height include padding and border.</summary>
    BorderBox,
}

/// <summary>CSS float.</summary>
public enum FloatMode
{
    /// <summary>Not floated.</summary>
    None,

    /// <summary>Floated to the left edge.</summary>
    Left,

    /// <summary>Floated to the right edge.</summary>
    Right,
}

/// <summary>CSS clear.</summary>
public enum ClearMode
{
    /// <summary>Does not clear floats.</summary>
    None,

    /// <summary>Moves below left floats.</summary>
    Left,

    /// <summary>Moves below right floats.</summary>
    Right,

    /// <summary>Moves below all floats.</summary>
    Both,
}

/// <summary>CSS position.</summary>
public enum PositionMode
{
    /// <summary>Normal flow.</summary>
    Static,

    /// <summary>Normal flow, then shifted by top/left/right/bottom.</summary>
    Relative,

    /// <summary>Removed from flow and placed relative to the nearest positioned ancestor.</summary>
    Absolute,

    /// <summary>Removed from flow and repeated on every page relative to the page content area.</summary>
    Fixed,
}

/// <summary>Flex main axis direction.</summary>
public enum FlexDirection
{
    /// <summary>Lay flex items horizontally.</summary>
    Row,
    /// <summary>Lay flex items vertically.</summary>
    Column,
}

/// <summary>Flex main-axis alignment.</summary>
public enum JustifyContent
{
    /// <summary>Pack items at the start.</summary>
    Start,
    /// <summary>Center items.</summary>
    Center,
    /// <summary>Pack items at the end.</summary>
    End,
    /// <summary>Distribute free space between items.</summary>
    SpaceBetween,
    /// <summary>Distribute free space around items.</summary>
    SpaceAround,
    /// <summary>Distribute free space evenly.</summary>
    SpaceEvenly,
}

/// <summary>Flex cross-axis alignment.</summary>
public enum AlignItems
{
    /// <summary>Align items at the start.</summary>
    Start,
    /// <summary>Center items.</summary>
    Center,
    /// <summary>Align items at the end.</summary>
    End,
    /// <summary>Stretch items to the line's cross size.</summary>
    Stretch,
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

/// <summary>CSS <c>hyphens</c>.</summary>
internal enum HyphensMode
{
    /// <summary>Break only at soft hyphens.</summary>
    Manual,

    /// <summary>Never hyphenate.</summary>
    None,

    /// <summary>Hyphenate automatically for supported languages.</summary>
    Auto,
}

/// <summary>Logical text alignment keywords.</summary>
internal enum LogicalTextAlign
{
    /// <summary>Align to the start edge (left in LTR, right in RTL).</summary>
    Start,

    /// <summary>Align to the end edge.</summary>
    End,
}

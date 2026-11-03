using System.Globalization;

namespace SimpleSign.HtmlToPdf.Parsing;

/// <summary>Which box a background is clipped to or positioned against.</summary>
internal enum BackgroundBox
{
    /// <summary>The border box.</summary>
    BorderBox,

    /// <summary>The padding box.</summary>
    PaddingBox,

    /// <summary>The content box.</summary>
    ContentBox,
}

/// <summary>Background sizing mode.</summary>
internal enum BackgroundSizeKind
{
    /// <summary>Explicit or auto width/height.</summary>
    Explicit,

    /// <summary>Scale to cover the area.</summary>
    Cover,

    /// <summary>Scale to fit inside the area.</summary>
    Contain,
}

/// <summary>A <c>background-size</c> value; null dimensions mean <c>auto</c>.</summary>
internal readonly record struct BackgroundSize(BackgroundSizeKind Kind, float? Width, float? Height)
{
    public static readonly BackgroundSize Auto = new(BackgroundSizeKind.Explicit, null, null);
}

/// <summary>Repeat flags per axis.</summary>
internal readonly record struct BackgroundRepeat(bool X, bool Y)
{
    public static readonly BackgroundRepeat Both = new(true, true);
}

/// <summary>
/// One axis of a position: <c>(area - object) * Percent / 100 + Offset</c>.
/// Keywords and edge offsets (<c>right 10px</c>) reduce to this form.
/// </summary>
internal readonly record struct PositionComponent(float Percent, float Offset)
{
    public static readonly PositionComponent Center = new(50, 0);

    public static readonly PositionComponent Start = new(0, 0);

    public float Resolve(float freeSpace) => (freeSpace * Percent / 100f) + Offset;
}

/// <summary>A two-axis position.</summary>
internal readonly record struct CssPosition(PositionComponent X, PositionComponent Y)
{
    public static readonly CssPosition TopLeft = new(PositionComponent.Start, PositionComponent.Start);

    public static readonly CssPosition CenterCenter = new(PositionComponent.Center, PositionComponent.Center);
}

/// <summary>A background image layer: an URL or a gradient.</summary>
internal abstract record CssImage;

/// <summary>An image referenced by URL.</summary>
internal sealed record CssUrlImage(string Url) : CssImage;

/// <summary>A color stop. Position uses the <see cref="CssLength"/> encoding, null when implicit.</summary>
internal readonly record struct GradientStop(PdfColor Color, float? Position);

/// <summary>Radial gradient extent keywords.</summary>
internal enum RadialExtent
{
    /// <summary>Distance to the farthest corner (the default).</summary>
    FarthestCorner,

    /// <summary>Distance to the closest corner.</summary>
    ClosestCorner,

    /// <summary>Distance to the farthest side.</summary>
    FarthestSide,

    /// <summary>Distance to the closest side.</summary>
    ClosestSide,

    /// <summary>Explicit radii.</summary>
    Explicit,
}

/// <summary>A linear or radial gradient.</summary>
internal sealed record CssGradient : CssImage
{
    public bool IsRadial { get; init; }

    public bool Repeating { get; init; }

    /// <summary>Gets the linear gradient direction in degrees (0 = to top, 90 = to right).</summary>
    public float AngleDegrees { get; init; } = 180f;

    /// <summary>Gets the corner keywords of <c>to top right</c> style directions (resolved against the box aspect ratio).</summary>
    public (int X, int Y)? Corner { get; init; }

    public bool Circle { get; init; }

    public RadialExtent Extent { get; init; } = RadialExtent.FarthestCorner;

    /// <summary>Gets explicit radii (CssLength encoding).</summary>
    public float RadiusX { get; init; }

    public float RadiusY { get; init; }

    public CssPosition Center { get; init; } = CssPosition.CenterCenter;

    public IReadOnlyList<GradientStop> Stops { get; init; } = [];
}

/// <summary>A <c>box-shadow</c> or <c>text-shadow</c> entry.</summary>
internal readonly record struct CssShadow(float OffsetX, float OffsetY, float Blur, float Spread, PdfColor Color, bool Inset);

/// <summary>One transform function. Translations use the <see cref="CssLength"/> encoding; angles are radians.</summary>
internal readonly record struct TransformFunction(string Name, float[] Args);

/// <summary>Parsers for paint-related values: backgrounds, gradients, shadows and transforms.</summary>
internal static class CssPaint
{
    /// <summary>Parses a comma separated list of <c>&lt;image&gt;</c>/<c>none</c> values.</summary>
    public static List<CssImage?> ParseImages(string value, float fontSize, PdfColor currentColor) =>
        [.. CssParser.SplitTopLevel(value, ',').Select(layer => ParseImage(layer.Trim(), fontSize, currentColor))];

    public static CssImage? ParseImage(string token, float fontSize, PdfColor currentColor)
    {
        string lower = token.ToLowerInvariant();
        if (lower.StartsWith("url(", StringComparison.Ordinal) && token.EndsWith(')'))
        {
            string url = token[4..^1].Trim().Trim('"', '\'');
            return url.Length > 0 ? new CssUrlImage(url) : null;
        }

        bool repeating = lower.StartsWith("repeating-", StringComparison.Ordinal);
        string fn = repeating ? lower["repeating-".Length..] : lower;
        fn = fn.StartsWith("-webkit-", StringComparison.Ordinal) ? fn[8..] : fn;
        int paren = token.IndexOf('(', StringComparison.Ordinal);
        if (paren < 0 || !token.EndsWith(')'))
        {
            return null;
        }

        List<string> args = [.. CssParser.SplitTopLevel(token[(paren + 1)..^1], ',').Select(a => a.Trim())];
        if (fn.StartsWith("linear-gradient(", StringComparison.Ordinal))
        {
            return ParseLinear(args, repeating, fontSize, currentColor);
        }

        if (fn.StartsWith("radial-gradient(", StringComparison.Ordinal))
        {
            return ParseRadial(args, repeating, fontSize, currentColor);
        }

        return null;
    }

    private static CssGradient? ParseLinear(List<string> args, bool repeating, float fontSize, PdfColor currentColor)
    {
        float angle = 180f;
        (int, int)? corner = null;
        int first = 0;
        if (args.Count > 0)
        {
            string head = args[0].ToLowerInvariant();
            if (head.StartsWith("to ", StringComparison.Ordinal))
            {
                int x = 0, y = 0;
                foreach (string word in head[3..].Split(' ', StringSplitOptions.RemoveEmptyEntries))
                {
                    switch (word)
                    {
                        case "left":
                            x = -1;
                            break;
                        case "right":
                            x = 1;
                            break;
                        case "top":
                            y = -1;
                            break;
                        case "bottom":
                            y = 1;
                            break;
                    }
                }

                if (x != 0 && y != 0)
                {
                    corner = (x, y);
                }
                else
                {
                    angle = x switch { 1 => 90, -1 => 270, _ => y == -1 ? 0 : 180 };
                }

                first = 1;
            }
            else if (ParseAngle(head) is float a)
            {
                angle = a;
                first = 1;
            }
        }

        List<GradientStop>? stops = ParseStops(args.Skip(first), fontSize, currentColor);
        return stops is null ? null : new CssGradient { Repeating = repeating, AngleDegrees = angle, Corner = corner, Stops = stops };
    }

    private static CssGradient? ParseRadial(List<string> args, bool repeating, float fontSize, PdfColor currentColor)
    {
        bool circle = false;
        RadialExtent extent = RadialExtent.FarthestCorner;
        float rx = 0, ry = 0;
        CssPosition center = CssPosition.CenterCenter;
        int first = 0;
        if (args.Count > 0 && !LooksLikeStop(args[0]))
        {
            first = 1;
            string head = args[0];
            int at = head.IndexOf(" at ", StringComparison.OrdinalIgnoreCase);
            string shapePart = head;
            if (head.StartsWith("at ", StringComparison.OrdinalIgnoreCase))
            {
                shapePart = string.Empty;
                center = ParsePosition(head[3..], fontSize) ?? center;
            }
            else if (at >= 0)
            {
                shapePart = head[..at];
                center = ParsePosition(head[(at + 4)..], fontSize) ?? center;
            }

            List<float> radii = [];
            foreach (string word in CssParser.SplitValueTokens(shapePart))
            {
                switch (word.ToLowerInvariant())
                {
                    case "circle":
                        circle = true;
                        break;
                    case "ellipse":
                        break;
                    case "closest-side":
                        extent = RadialExtent.ClosestSide;
                        break;
                    case "closest-corner":
                        extent = RadialExtent.ClosestCorner;
                        break;
                    case "farthest-side":
                        extent = RadialExtent.FarthestSide;
                        break;
                    case "farthest-corner":
                        extent = RadialExtent.FarthestCorner;
                        break;
                    default:
                        if (CssParser.ParseLength(word, fontSize) is float r)
                        {
                            radii.Add(r);
                        }

                        break;
                }
            }

            if (radii.Count > 0)
            {
                extent = RadialExtent.Explicit;
                rx = radii[0];
                ry = radii.Count > 1 ? radii[1] : radii[0];
                circle |= radii.Count == 1;
            }
        }

        List<GradientStop>? stops = ParseStops(args.Skip(first), fontSize, currentColor);
        return stops is null
            ? null
            : new CssGradient
            {
                IsRadial = true,
                Repeating = repeating,
                Circle = circle,
                Extent = extent,
                RadiusX = rx,
                RadiusY = ry,
                Center = center,
                Stops = stops,
            };
    }

    private static bool LooksLikeStop(string arg)
    {
        List<string> tokens = CssParser.SplitValueTokens(arg);
        return tokens.Count > 0 && (CssParser.IsColorValue(tokens[0]) || tokens[0].Equals("transparent", StringComparison.OrdinalIgnoreCase)
            || tokens[0].Equals("currentcolor", StringComparison.OrdinalIgnoreCase));
    }

    private static List<GradientStop>? ParseStops(IEnumerable<string> args, float fontSize, PdfColor currentColor)
    {
        var stops = new List<GradientStop>();
        foreach (string arg in args)
        {
            List<string> tokens = CssParser.SplitValueTokens(arg);
            if (tokens.Count == 0)
            {
                continue;
            }

            PdfColor? color = null;
            var positions = new List<float>();
            foreach (string t in tokens)
            {
                if (t.Equals("currentcolor", StringComparison.OrdinalIgnoreCase))
                {
                    color = currentColor;
                }
                else if (t.Equals("transparent", StringComparison.OrdinalIgnoreCase))
                {
                    color = PdfColor.Transparent;
                }
                else if (CssParser.IsColorValue(t))
                {
                    color = PdfColor.Parse(t);
                }
                else if (CssParser.ParseLength(t, fontSize) is float p)
                {
                    positions.Add(p);
                }
            }

            if (color is not PdfColor c)
            {
                // A bare position is a color hint; approximate it by ignoring it.
                continue;
            }

            if (positions.Count == 0)
            {
                stops.Add(new GradientStop(c, null));
            }

            foreach (float p in positions)
            {
                stops.Add(new GradientStop(c, p));
            }
        }

        return stops.Count >= 2 ? stops : null;
    }

    /// <summary>Parses an angle into degrees.</summary>
    public static float? ParseAngle(string value)
    {
        string v = value.Trim().ToLowerInvariant();
        (string Suffix, float Factor)[] units = [("deg", 1f), ("grad", 0.9f), ("rad", 180f / MathF.PI), ("turn", 360f)];
        foreach (var (suffix, factor) in units)
        {
            if (v.EndsWith(suffix, StringComparison.Ordinal)
                && float.TryParse(v[..^suffix.Length], NumberStyles.Float, CultureInfo.InvariantCulture, out float n))
            {
                return n * factor;
            }
        }

        return v == "0" ? 0 : null;
    }

    /// <summary>Parses a <c>background-position</c>/<c>transform-origin</c>-style position.</summary>
    public static CssPosition? ParsePosition(string value, float fontSize)
    {
        List<string> tokens = CssParser.SplitValueTokens(value.Trim());
        if (tokens.Count == 0)
        {
            return null;
        }

        PositionComponent? x = null, y = null;
        int i = 0;
        var pending = new List<PositionComponent>();
        while (i < tokens.Count)
        {
            string t = tokens[i].ToLowerInvariant();
            float? next = i + 1 < tokens.Count && !IsPositionKeyword(tokens[i + 1]) ? CssParser.ParseLength(tokens[i + 1], fontSize) : null;
            switch (t)
            {
                case "left" or "right":
                    x = Edge(t == "right", next);
                    i += next is null ? 1 : 2;
                    continue;
                case "top" or "bottom":
                    y = Edge(t == "bottom", next);
                    i += next is null ? 1 : 2;
                    continue;
                case "center":
                    pending.Add(PositionComponent.Center);
                    i++;
                    continue;
            }

            if (CssParser.ParseLength(tokens[i], fontSize) is float length)
            {
                pending.Add(CssLength.IsPercent(length) ? new PositionComponent(CssLength.PercentOf(length), 0) : new PositionComponent(0, length));
            }

            i++;
        }

        foreach (PositionComponent p in pending)
        {
            if (x is null)
            {
                x = p;
            }
            else
            {
                y ??= p;
            }
        }

        return new CssPosition(x ?? PositionComponent.Center, y ?? PositionComponent.Center);

        static PositionComponent Edge(bool far, float? offset)
        {
            float o = offset is float v ? (CssLength.IsPercent(v) ? 0 : v) : 0;
            float pctOffset = offset is float pv && CssLength.IsPercent(pv) ? CssLength.PercentOf(pv) : 0;
            return far ? new PositionComponent(100 - pctOffset, -o) : new PositionComponent(pctOffset, o);
        }
    }

    private static bool IsPositionKeyword(string token) => token.ToLowerInvariant() is "left" or "right" or "top" or "bottom" or "center";

    public static List<CssPosition> ParsePositions(string value, float fontSize) =>
        [.. CssParser.SplitTopLevel(value, ',').Select(p => ParsePosition(p, fontSize) ?? CssPosition.TopLeft)];

    public static List<BackgroundSize> ParseSizes(string value, float fontSize) =>
        [.. CssParser.SplitTopLevel(value, ',').Select(p => ParseSize(p, fontSize))];

    private static BackgroundSize ParseSize(string value, float fontSize)
    {
        List<string> tokens = CssParser.SplitValueTokens(value.Trim().ToLowerInvariant());
        if (tokens.Count == 1 && tokens[0] is "cover")
        {
            return new BackgroundSize(BackgroundSizeKind.Cover, null, null);
        }

        if (tokens.Count == 1 && tokens[0] is "contain")
        {
            return new BackgroundSize(BackgroundSizeKind.Contain, null, null);
        }

        float? w = tokens.Count > 0 ? CssParser.ParseLength(tokens[0], fontSize) : null;
        float? h = tokens.Count > 1 ? CssParser.ParseLength(tokens[1], fontSize) : null;
        return new BackgroundSize(BackgroundSizeKind.Explicit, w, h);
    }

    public static List<BackgroundRepeat> ParseRepeats(string value) =>
        [.. CssParser.SplitTopLevel(value, ',').Select(p => ParseRepeat(CssParser.SplitValueTokens(p.Trim().ToLowerInvariant())) ?? BackgroundRepeat.Both)];

    private static BackgroundRepeat? ParseRepeat(List<string> tokens)
    {
        if (tokens.Count == 1)
        {
            return tokens[0] switch
            {
                "repeat-x" => new BackgroundRepeat(true, false),
                "repeat-y" => new BackgroundRepeat(false, true),
                "no-repeat" => new BackgroundRepeat(false, false),
                "repeat" or "space" or "round" => BackgroundRepeat.Both,
                _ => null,
            };
        }

        if (tokens.Count == 2)
        {
            return new BackgroundRepeat(tokens[0] != "no-repeat", tokens[1] != "no-repeat");
        }

        return null;
    }

    public static List<BackgroundBox> ParseBoxes(string value) =>
        [.. CssParser.SplitTopLevel(value, ',').Select(p => ParseBox(p.Trim()) ?? BackgroundBox.BorderBox)];

    private static BackgroundBox? ParseBox(string token) => token.ToLowerInvariant() switch
    {
        "border-box" => BackgroundBox.BorderBox,
        "padding-box" => BackgroundBox.PaddingBox,
        "content-box" => BackgroundBox.ContentBox,
        _ => null,
    };

    /// <summary>The result of expanding the <c>background</c> shorthand.</summary>
    public sealed record BackgroundShorthand(
        PdfColor Color,
        List<CssImage?> Images,
        List<CssPosition> Positions,
        List<BackgroundSize> Sizes,
        List<BackgroundRepeat> Repeats,
        List<BackgroundBox> Origins,
        List<BackgroundBox> Clips);

    public static BackgroundShorthand ParseBackground(string value, float fontSize, PdfColor currentColor)
    {
        var result = new BackgroundShorthand(PdfColor.Transparent, [], [], [], [], [], []);
        PdfColor color = PdfColor.Transparent;
        foreach (string layer in CssParser.SplitTopLevel(value, ','))
        {
            CssImage? image = null;
            var positionTokens = new List<string>();
            var sizeTokens = new List<string>();
            var repeatTokens = new List<string>();
            var boxes = new List<BackgroundBox>();
            bool inSize = false;
            foreach (string raw in CssParser.SplitValueTokens(layer.Trim()))
            {
                string token = raw;
                string lower = token.ToLowerInvariant();
                if (token.Contains('/', StringComparison.Ordinal) && !lower.StartsWith("url(", StringComparison.Ordinal) && !token.Contains('(', StringComparison.Ordinal))
                {
                    int slash = token.IndexOf('/', StringComparison.Ordinal);
                    if (slash > 0)
                    {
                        positionTokens.Add(token[..slash]);
                    }

                    inSize = true;
                    if (slash + 1 < token.Length)
                    {
                        sizeTokens.Add(token[(slash + 1)..]);
                    }

                    continue;
                }

                if (lower.StartsWith("url(", StringComparison.Ordinal) || lower.Contains("gradient(", StringComparison.Ordinal))
                {
                    image = ParseImage(token, fontSize, currentColor);
                    inSize = false;
                }
                else if (lower is "repeat" or "repeat-x" or "repeat-y" or "no-repeat" or "space" or "round")
                {
                    repeatTokens.Add(lower);
                    inSize = false;
                }
                else if (ParseBox(lower) is BackgroundBox box)
                {
                    boxes.Add(box);
                    inSize = false;
                }
                else if (lower is "scroll" or "fixed" or "local" or "none")
                {
                    inSize = false;
                }
                else if (lower is "currentcolor")
                {
                    color = currentColor;
                }
                else if (lower is "transparent")
                {
                    color = PdfColor.Transparent;
                }
                else if (CssParser.IsColorValue(token))
                {
                    color = PdfColor.Parse(token);
                    inSize = false;
                }
                else if (inSize)
                {
                    sizeTokens.Add(token);
                }
                else
                {
                    positionTokens.Add(token);
                }
            }

            result.Images.Add(image);
            result.Positions.Add(positionTokens.Count > 0 ? ParsePosition(string.Join(' ', positionTokens), fontSize) ?? CssPosition.TopLeft : CssPosition.TopLeft);
            result.Sizes.Add(sizeTokens.Count > 0 ? ParseSize(string.Join(' ', sizeTokens), fontSize) : BackgroundSize.Auto);
            result.Repeats.Add(ParseRepeat(repeatTokens) ?? BackgroundRepeat.Both);
            result.Origins.Add(boxes.Count > 0 ? boxes[0] : BackgroundBox.PaddingBox);
            result.Clips.Add(boxes.Count > 1 ? boxes[1] : boxes.Count == 1 ? boxes[0] : BackgroundBox.BorderBox);
        }

        return result with { Color = color };
    }

    /// <summary>Parses <c>box-shadow</c> (allowSpread) or <c>text-shadow</c>.</summary>
    public static List<CssShadow> ParseShadows(string value, float fontSize, PdfColor currentColor, bool boxShadow)
    {
        var shadows = new List<CssShadow>();
        if (value.Trim().Equals("none", StringComparison.OrdinalIgnoreCase))
        {
            return shadows;
        }

        foreach (string part in CssParser.SplitTopLevel(value, ','))
        {
            var lengths = new List<float>();
            PdfColor color = currentColor;
            bool inset = false;
            foreach (string token in CssParser.SplitValueTokens(part.Trim()))
            {
                string lower = token.ToLowerInvariant();
                if (lower == "inset")
                {
                    inset = true;
                }
                else if (lower == "currentcolor")
                {
                    color = currentColor;
                }
                else if (lower == "transparent")
                {
                    color = PdfColor.Transparent;
                }
                else if (CssParser.IsColorValue(token))
                {
                    color = PdfColor.Parse(token);
                }
                else if (CssParser.ParseLength(token, fontSize) is float l && !CssLength.IsPercent(l))
                {
                    lengths.Add(l);
                }
            }

            if (lengths.Count < 2 || (inset && !boxShadow))
            {
                continue;
            }

            shadows.Add(new CssShadow(
                lengths[0],
                lengths[1],
                lengths.Count > 2 ? Math.Max(0, lengths[2]) : 0,
                boxShadow && lengths.Count > 3 ? lengths[3] : 0,
                color,
                inset));
        }

        return shadows;
    }

    /// <summary>Parses the <c>transform</c> property.</summary>
    public static List<TransformFunction>? ParseTransform(string value, float fontSize)
    {
        string v = value.Trim();
        if (v.Equals("none", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        var functions = new List<TransformFunction>();
        foreach (string token in CssParser.SplitValueTokens(v))
        {
            int paren = token.IndexOf('(', StringComparison.Ordinal);
            if (paren <= 0 || !token.EndsWith(')'))
            {
                return null;
            }

            string name = token[..paren].Trim().ToLowerInvariant();
            List<string> args = [.. CssParser.SplitTopLevel(token[(paren + 1)..^1], ',').SelectMany(CssParser.SplitValueTokens)];
            float[]? parsed = name switch
            {
                "translate" or "translatex" or "translatey" or "translate3d" => ParseArgs(args, a => CssParser.ParseLength(a, fontSize)),
                "scale" or "scalex" or "scaley" or "scale3d" => ParseArgs(args, ParseNumberOrPercent),
                "rotate" or "rotatez" or "skew" or "skewx" or "skewy" => ParseArgs(args, a => ParseAngle(a) is float d ? d * MathF.PI / 180f : null),
                "matrix" => ParseArgs(args, ParseNumber),
                _ => null,
            };

            if (parsed is null || parsed.Length == 0)
            {
                return null;
            }

            functions.Add(new TransformFunction(name, parsed));
        }

        return functions.Count > 0 ? functions : null;
    }

    private static float? ParseNumber(string token) =>
        float.TryParse(token, NumberStyles.Float, CultureInfo.InvariantCulture, out float n) ? n : null;

    private static float? ParseNumberOrPercent(string token) =>
        token.EndsWith('%') ? ParseNumber(token[..^1]) / 100f : ParseNumber(token);

    private static float[]? ParseArgs(List<string> args, Func<string, float?> parse)
    {
        var result = new float[args.Count];
        for (int i = 0; i < args.Count; i++)
        {
            if (parse(args[i]) is not float f)
            {
                return null;
            }

            result[i] = f;
        }

        return result;
    }

    /// <summary>
    /// Builds the transform as a PDF-style matrix [a b c d e f] in CSS coordinates (y down),
    /// relative to the transform origin.
    /// </summary>
    public static Matrix2D ToMatrix(IReadOnlyList<TransformFunction> functions, float boxWidth, float boxHeight)
    {
        Matrix2D m = Matrix2D.Identity;
        foreach (TransformFunction f in functions)
        {
            float[] a = f.Args;
            Matrix2D step = f.Name switch
            {
                "translate" or "translate3d" => Matrix2D.Translation(CssLength.Resolve(a[0], boxWidth), a.Length > 1 ? CssLength.Resolve(a[1], boxHeight) : 0),
                "translatex" => Matrix2D.Translation(CssLength.Resolve(a[0], boxWidth), 0),
                "translatey" => Matrix2D.Translation(0, CssLength.Resolve(a[0], boxHeight)),
                "scale" or "scale3d" => Matrix2D.Scale(a[0], a.Length > 1 ? a[1] : a[0]),
                "scalex" => Matrix2D.Scale(a[0], 1),
                "scaley" => Matrix2D.Scale(1, a[0]),
                "rotate" or "rotatez" => Matrix2D.Rotation(a[0]),
                "skew" => new Matrix2D(1, MathF.Tan(a.Length > 1 ? a[1] : 0), MathF.Tan(a[0]), 1, 0, 0),
                "skewx" => new Matrix2D(1, 0, MathF.Tan(a[0]), 1, 0, 0),
                "skewy" => new Matrix2D(1, MathF.Tan(a[0]), 0, 1, 0, 0),
                "matrix" when a.Length == 6 => new Matrix2D(a[0], a[1], a[2], a[3], a[4], a[5]),
                _ => Matrix2D.Identity,
            };
            m = step.Then(m);
        }

        return m;
    }
}

/// <summary>An affine matrix [a b c d e f] mapping (x, y) to (a·x + c·y + e, b·x + d·y + f).</summary>
internal readonly record struct Matrix2D(float A, float B, float C, float D, float E, float F)
{
    public static readonly Matrix2D Identity = new(1, 0, 0, 1, 0, 0);

    public bool IsIdentity => this == Identity;

    public static Matrix2D Translation(float x, float y) => new(1, 0, 0, 1, x, y);

    public static Matrix2D Scale(float x, float y) => new(x, 0, 0, y, 0, 0);

    public static Matrix2D Rotation(float radians)
    {
        float cos = MathF.Cos(radians), sin = MathF.Sin(radians);
        return new Matrix2D(cos, sin, -sin, cos, 0, 0);
    }

    /// <summary>Returns the matrix that applies <c>this</c> first, then <paramref name="next"/>.</summary>
    public Matrix2D Then(Matrix2D next) => new(
        (A * next.A) + (B * next.C),
        (A * next.B) + (B * next.D),
        (C * next.A) + (D * next.C),
        (C * next.B) + (D * next.D),
        (E * next.A) + (F * next.C) + next.E,
        (E * next.B) + (F * next.D) + next.F);

    public (float X, float Y) Apply(float x, float y) => ((A * x) + (C * y) + E, (B * x) + (D * y) + F);

    /// <summary>Returns the inverse matrix, or identity when the matrix is singular.</summary>
    public Matrix2D Invert()
    {
        float det = (A * D) - (B * C);
        if (MathF.Abs(det) < 1e-12f)
        {
            return Identity;
        }

        return new Matrix2D(D / det, -B / det, -C / det, A / det, ((C * F) - (D * E)) / det, ((B * E) - (A * F)) / det);
    }
}

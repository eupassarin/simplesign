using System.Globalization;
using System.Text;
using SimpleSign.HtmlToPdf.Fonts;
using SimpleSign.HtmlToPdf.Parsing;

namespace SimpleSign.HtmlToPdf.Rendering.Svg;

/// <summary>
/// Draws SVG content as native PDF vector graphics: shapes, paths, text, gradients,
/// clipping paths, <c>use</c>/<c>symbol</c>, nested viewports and embedded images.
/// Masks, patterns, filters and markers are not supported and are skipped.
/// </summary>
internal sealed class SvgRenderer
{
    private const int MaxDepth = 64;
    private const int MaxUseExpansions = 10_000;

    private static readonly HashSet<string> NonRendering = new(StringComparer.Ordinal)
    {
        "defs", "lineargradient", "radialgradient", "clippath", "mask", "symbol", "marker", "pattern",
        "title", "desc", "metadata", "style", "script", "filter", "font", "font-face", "foreignobject",
    };

    private readonly Dictionary<HtmlNode, Dictionary<string, HtmlNode>> _idMaps = [];
    private readonly ImageObjectCache _images;
    private readonly HashSet<string> _pageImages;
    private int _useExpansions;
    private int _drawDepth;

    public SvgRenderer(ImageObjectCache images, HashSet<string> pageImages)
    {
        _images = images;
        _pageImages = pageImages;
    }

    /// <summary>Inherited presentation state.</summary>
    private sealed record State
    {
        public string Fill { get; init; } = "black";

        public string Stroke { get; init; } = "none";

        public float FillOpacity { get; init; } = 1;

        public float StrokeOpacity { get; init; } = 1;

        public string StrokeWidth { get; init; } = "1";

        public string LineCap { get; init; } = "butt";

        public string LineJoin { get; init; } = "miter";

        public float MiterLimit { get; init; } = 4;

        public string DashArray { get; init; } = "none";

        public float DashOffset { get; init; }

        public bool EvenOdd { get; init; }

        public bool ClipEvenOdd { get; init; }

        public float FontSize { get; init; } = 16;

        public string FontFamily { get; init; } = "sans-serif";

        public bool Bold { get; init; }

        public bool Italic { get; init; }

        public string TextAnchor { get; init; } = "start";

        public string Baseline { get; init; } = "auto";

        public PdfColor Color { get; init; } = PdfColor.Black;

        public bool Hidden { get; init; }

        /// <summary>Gets the current viewport size (for percentages).</summary>
        public float ViewportWidth { get; init; } = 300;

        public float ViewportHeight { get; init; } = 150;
    }

    /// <summary>Draws an SVG root into a rectangle given in PDF coordinates.</summary>
    public void Draw(PdfContentStream cs, HtmlNode svg, PdfRect target)
    {
        // An SVG may embed itself (or another SVG that embeds it) through <image>.
        if (target.Width <= 0 || target.Height <= 0 || _drawDepth >= 4)
        {
            return;
        }

        _drawDepth++;
        try
        {
            DrawRoot(cs, svg, target);
        }
        finally
        {
            _drawDepth--;
        }
    }

    private void DrawRoot(PdfContentStream cs, HtmlNode svg, PdfRect target)
    {
        (float iw, float ih) = SvgDocument.IntrinsicSize(svg);
        float[] viewBox = SvgDocument.ParseViewBox(svg.GetAttribute("viewbox")) ?? [0, 0, iw, ih];
        Matrix2D toPage = ViewportMatrix(viewBox, target.Width, target.Height, svg.GetAttribute("preserveaspectratio"));

        // SVG user space is y-down; flip into the target rectangle.
        Matrix2D flip = new(1, 0, 0, -1, target.X, target.Top);
        Matrix2D m = toPage.Then(flip);

        cs.SaveState();
        cs.ClipRect(target.X, target.Bottom, target.Width, target.Height);
        Concat(cs, m);
        State state = Inherit(new State { ViewportWidth = viewBox[2], ViewportHeight = viewBox[3] }, svg);
        float savedAlpha = cs.GroupAlpha;
        cs.GroupAlpha *= ElementOpacity(svg);
        RenderChildren(cs, svg, state, 0);
        cs.GroupAlpha = savedAlpha;
        cs.RestoreState();
    }

    /// <summary>Maps a viewBox onto a viewport of the given size (y-down on both sides).</summary>
    internal static Matrix2D ViewportMatrix(float[] viewBox, float width, float height, string? preserveAspectRatio)
    {
        float sx = width / viewBox[2], sy = height / viewBox[3];
        string par = (preserveAspectRatio ?? "xMidYMid meet").Trim();
        if (par.StartsWith("defer", StringComparison.Ordinal))
        {
            par = par[5..].Trim();
        }

        string[] parts = par.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        string align = parts.Length > 0 ? parts[0] : "xMidYMid";
        bool slice = parts.Length > 1 && parts[1] == "slice";
        float tx = 0, ty = 0;
        if (align != "none")
        {
            float s = slice ? Math.Max(sx, sy) : Math.Min(sx, sy);
            sx = sy = s;
            float freeX = width - (viewBox[2] * s), freeY = height - (viewBox[3] * s);
            tx = align.Contains("xMid", StringComparison.Ordinal) ? freeX / 2 : align.Contains("xMax", StringComparison.Ordinal) ? freeX : 0;
            ty = align.Contains("YMid", StringComparison.Ordinal) ? freeY / 2 : align.Contains("YMax", StringComparison.Ordinal) ? freeY : 0;
        }

        return new Matrix2D(sx, 0, 0, sy, tx - (viewBox[0] * sx), ty - (viewBox[1] * sy));
    }

    private void RenderChildren(PdfContentStream cs, HtmlNode parent, State state, int depth)
    {
        foreach (HtmlNode child in parent.Children)
        {
            if (child.NodeType == HtmlNodeType.Element)
            {
                RenderElement(cs, child, state, depth + 1);
            }
        }
    }

    private void RenderElement(PdfContentStream cs, HtmlNode node, State parentState, int depth)
    {
        string tag = node.Tag ?? string.Empty;
        if (depth > MaxDepth || NonRendering.Contains(tag) || node.GetAttribute("display") == "none"
            || node.ComputedStyle?.Display == DisplayType.None)
        {
            return;
        }

        State state = Inherit(parentState, node);
        float opacity = ElementOpacity(node);
        if (opacity <= 0.001f)
        {
            return;
        }

        float savedAlpha = cs.GroupAlpha;
        cs.SaveState();
        cs.GroupAlpha = savedAlpha * opacity;
        if (ParseTransform(node.GetAttribute("transform")) is { } transform)
        {
            Concat(cs, transform);
        }

        ApplyClipPath(cs, node, state);
        switch (tag)
        {
            case "g" or "a":
                RenderChildren(cs, node, state, depth);
                break;
            case "switch":
                if (node.Children.FirstOrDefault(c => c.NodeType == HtmlNodeType.Element && !NonRendering.Contains(c.Tag ?? string.Empty)) is { } first)
                {
                    RenderElement(cs, first, state, depth + 1);
                }

                break;
            case "svg":
                RenderNestedSvg(cs, node, node, state, depth, Length(node.GetAttribute("width"), state, 'x'), Length(node.GetAttribute("height"), state, 'y'));
                break;
            case "use":
                RenderUse(cs, node, state, depth);
                break;
            case "image":
                RenderImage(cs, node, state);
                break;
            case "text":
                if (!state.Hidden)
                {
                    RenderText(cs, node, state);
                }

                break;
            default:
                if (!state.Hidden && ShapePath(node, state, Matrix2D.Identity) is { } shape)
                {
                    PaintShape(cs, node, state, shape.Path, shape.Bounds, canFill: tag != "line");
                }

                break;
        }

        cs.RestoreState();
        cs.GroupAlpha = savedAlpha;
    }

    private static float ElementOpacity(HtmlNode node)
    {
        float opacity = ParseOpacity(node.GetAttribute("opacity")) ?? 1;
        if (node.ComputedStyle is { Opacity: < 1 } style)
        {
            opacity = style.Opacity;
        }

        return opacity;
    }

    // ── Presentation state ───────────────────────────────────────────────

    private static State Inherit(State parent, HtmlNode node)
    {
        State s = parent;
        foreach (var (name, value) in node.Attributes)
        {
            s = ApplyProperty(s, name, value);
        }

        if (node.ComputedStyle is { } computed)
        {
            if (computed.SvgProperties is { } css)
            {
                foreach (var (name, value) in css)
                {
                    s = ApplyProperty(s, name, value);
                }
            }

            s = s with { Color = computed.Color };
            if (node.GetAttribute("color") is { } colorAttr && CssParser.IsColorValue(colorAttr))
            {
                s = s with { Color = PdfColor.Parse(colorAttr) };
            }

            if (computed.IsHidden)
            {
                s = s with { Hidden = true };
            }
        }

        if (node.GetAttribute("visibility") is { } visibility)
        {
            s = s with { Hidden = visibility is "hidden" or "collapse" };
        }

        return s;
    }

    private static State ApplyProperty(State s, string name, string raw)
    {
        string value = raw.Trim();
        if (value is "inherit" || value.Length == 0)
        {
            return s;
        }

        switch (name)
        {
            case "fill":
                return s with { Fill = value };
            case "stroke":
                return s with { Stroke = value };
            case "fill-opacity":
                return s with { FillOpacity = ParseOpacity(value) ?? s.FillOpacity };
            case "stroke-opacity":
                return s with { StrokeOpacity = ParseOpacity(value) ?? s.StrokeOpacity };
            case "stroke-width":
                return s with { StrokeWidth = value };
            case "stroke-linecap":
                return s with { LineCap = value };
            case "stroke-linejoin":
                return s with { LineJoin = value };
            case "stroke-miterlimit":
                return s with { MiterLimit = Number(value) ?? s.MiterLimit };
            case "stroke-dasharray":
                return s with { DashArray = value };
            case "stroke-dashoffset":
                return s with { DashOffset = Number(value) ?? 0 };
            case "fill-rule":
                return s with { EvenOdd = value == "evenodd" };
            case "clip-rule":
                return s with { ClipEvenOdd = value == "evenodd" };
            case "font-size":
                {
                    float? size = value.EndsWith('%') ? Number(value[..^1]) * s.FontSize / 100
                        : value.EndsWith("em", StringComparison.Ordinal) && !value.EndsWith("rem", StringComparison.Ordinal) ? Number(value[..^2]) * s.FontSize
                        : SvgDocument.ParseAbsolute(value);
                    return size is float f && f > 0 ? s with { FontSize = f } : s;
                }

            case "font-family":
                return s with { FontFamily = value };
            case "font-weight":
                return s with { Bold = value is "bold" or "bolder" || (int.TryParse(value, out int w) && w >= 600) };
            case "font-style":
                return s with { Italic = value is "italic" or "oblique" };
            case "text-anchor":
                return s with { TextAnchor = value };
            case "dominant-baseline" or "alignment-baseline":
                return s with { Baseline = value };
            case "style":
                // Inline style attributes are already part of the CSS cascade (SvgProperties).
                return s;
            default:
                return s;
        }
    }

    // ── Shapes ───────────────────────────────────────────────────────────

    private readonly record struct Shape(string Path, PdfRect Bounds);

    /// <summary>Builds the path of a basic shape, with points mapped through <paramref name="m"/>.</summary>
    private static Shape? ShapePath(HtmlNode node, State s, Matrix2D m)
    {
        var path = new PathWriter(m);
        switch (node.Tag)
        {
            case "rect":
                {
                    float x = Length(node.GetAttribute("x"), s, 'x'), y = Length(node.GetAttribute("y"), s, 'y');
                    float w = Length(node.GetAttribute("width"), s, 'x'), h = Length(node.GetAttribute("height"), s, 'y');
                    if (w <= 0 || h <= 0)
                    {
                        return null;
                    }

                    string? rxAttr = node.GetAttribute("rx"), ryAttr = node.GetAttribute("ry");
                    float rx = rxAttr is null ? -1 : Length(rxAttr, s, 'x');
                    float ry = ryAttr is null ? -1 : Length(ryAttr, s, 'y');
                    rx = rx < 0 ? Math.Max(0, ry) : rx;
                    ry = ry < 0 ? rx : ry;
                    path.Rect(x, y, w, h, Math.Min(rx, w / 2), Math.Min(ry, h / 2));
                    break;
                }

            case "circle":
                {
                    float r = Length(node.GetAttribute("r"), s, 'd');
                    if (r <= 0)
                    {
                        return null;
                    }

                    path.Ellipse(Length(node.GetAttribute("cx"), s, 'x'), Length(node.GetAttribute("cy"), s, 'y'), r, r);
                    break;
                }

            case "ellipse":
                {
                    float rx = Length(node.GetAttribute("rx"), s, 'x'), ry = Length(node.GetAttribute("ry"), s, 'y');
                    if (rx <= 0 || ry <= 0)
                    {
                        return null;
                    }

                    path.Ellipse(Length(node.GetAttribute("cx"), s, 'x'), Length(node.GetAttribute("cy"), s, 'y'), rx, ry);
                    break;
                }

            case "line":
                path.MoveTo(Length(node.GetAttribute("x1"), s, 'x'), Length(node.GetAttribute("y1"), s, 'y'));
                path.LineTo(Length(node.GetAttribute("x2"), s, 'x'), Length(node.GetAttribute("y2"), s, 'y'));
                break;

            case "polyline" or "polygon":
                {
                    float[] pts = SvgPathParser.ParseNumbers(node.GetAttribute("points") ?? string.Empty);
                    if (pts.Length < 4)
                    {
                        return null;
                    }

                    path.MoveTo(pts[0], pts[1]);
                    for (int i = 2; i + 1 < pts.Length; i += 2)
                    {
                        path.LineTo(pts[i], pts[i + 1]);
                    }

                    if (node.Tag == "polygon")
                    {
                        path.Close();
                    }

                    break;
                }

            case "path":
                foreach (PathSegment seg in SvgPathParser.Parse(node.GetAttribute("d")))
                {
                    switch (seg.Kind)
                    {
                        case 'M':
                            path.MoveTo(seg.X, seg.Y);
                            break;
                        case 'L':
                            path.LineTo(seg.X, seg.Y);
                            break;
                        case 'C':
                            path.CurveTo(seg.X1, seg.Y1, seg.X2, seg.Y2, seg.X, seg.Y);
                            break;
                        default:
                            path.Close();
                            break;
                    }
                }

                break;

            default:
                return null;
        }

        return path.IsEmpty ? null : new Shape(path.ToString(), path.Bounds);
    }

    private void PaintShape(PdfContentStream cs, HtmlNode node, State s, string path, PdfRect bounds, bool canFill)
    {
        PdfColor? fillColor = canFill ? ResolvePaint(node, s.Fill, s) : null;
        HtmlNode? fillGradient = canFill ? GradientFor(node, s.Fill) : null;
        PdfColor? strokeColor = ResolvePaint(node, s.Stroke, s);
        HtmlNode? strokeGradient = GradientFor(node, s.Stroke);
        float strokeWidth = Length(s.StrokeWidth, s, 'd');

        if (fillGradient is not null)
        {
            cs.SaveState();
            cs.AppendRaw(path);
            cs.ClipPath(s.EvenOdd);
            PaintGradient(cs, fillGradient, bounds, s.FillOpacity);
            cs.RestoreState();
            fillColor = null;
        }

        // Gradient strokes fall back to the first stop color.
        if (strokeGradient is not null)
        {
            strokeColor = FirstStopColor(strokeGradient);
        }

        bool fill = fillColor is not null;
        bool stroke = strokeColor is not null && strokeWidth > 0;
        if (!fill && !stroke)
        {
            return;
        }

        if (fill)
        {
            PdfColor c = fillColor!.Value;
            cs.SetFillColor(c with { Alpha = c.Alpha * s.FillOpacity });
        }

        if (stroke)
        {
            PdfColor c = strokeColor!.Value;
            cs.SetStrokeColor(c with { Alpha = c.Alpha * s.StrokeOpacity });
            var sb = new StringBuilder();
            sb.Append(N(strokeWidth)).Append(" w ");
            sb.Append(s.LineCap switch { "round" => 1, "square" => 2, _ => 0 }).Append(" J ");
            sb.Append(s.LineJoin switch { "round" => 1, "bevel" => 2, _ => 0 }).Append(" j ");
            sb.Append(N(Math.Max(1, s.MiterLimit))).Append(" M\n");
            float[] dashes = s.DashArray == "none" ? [] : SvgPathParser.ParseNumbers(s.DashArray);
            if (dashes.Length > 0 && dashes.All(d => d >= 0) && dashes.Any(d => d > 0))
            {
                if (dashes.Length % 2 == 1)
                {
                    dashes = [.. dashes, .. dashes];
                }

                sb.Append('[').Append(string.Join(' ', dashes.Select(N))).Append("] ").Append(N(s.DashOffset)).Append(" d\n");
            }

            cs.AppendRaw(sb.ToString());
        }

        cs.AppendRaw(path);
        string op = (fill, stroke) switch
        {
            (true, true) => s.EvenOdd ? "B*" : "B",
            (true, false) => s.EvenOdd ? "f*" : "f",
            _ => "S",
        };
        cs.AppendRaw(op + "\n");
    }

    /// <summary>Resolves a paint to a solid color; null for none or unresolvable URLs without fallback.</summary>
    private PdfColor? ResolvePaint(HtmlNode node, string paint, State s)
    {
        string p = paint.Trim();
        if (p.StartsWith("url(", StringComparison.OrdinalIgnoreCase))
        {
            int close = p.IndexOf(')', StringComparison.Ordinal);
            string fallback = close >= 0 ? p[(close + 1)..].Trim() : string.Empty;
            if (Lookup(node, p) is { } target)
            {
                return target.Tag is "lineargradient" or "radialgradient" ? null : ResolvePaintColor(fallback.Length > 0 ? fallback : "none", s);
            }

            return ResolvePaintColor(fallback.Length > 0 ? fallback : "none", s);
        }

        return ResolvePaintColor(p, s);
    }

    private static PdfColor? ResolvePaintColor(string paint, State s)
    {
        string p = paint.Trim();
        if (p is "none" or "transparent" || p.Length == 0)
        {
            return null;
        }

        if (p.Equals("currentcolor", StringComparison.OrdinalIgnoreCase))
        {
            return s.Color;
        }

        if (!CssParser.IsColorValue(p))
        {
            return null;
        }

        PdfColor color = PdfColor.Parse(p);
        return color.IsTransparent ? null : color;
    }

    // ── Gradients ────────────────────────────────────────────────────────

    private HtmlNode? GradientFor(HtmlNode node, string paint) =>
        paint.TrimStart().StartsWith("url(", StringComparison.OrdinalIgnoreCase) && Lookup(node, paint) is { Tag: "lineargradient" or "radialgradient" } g ? g : null;

    /// <summary>Reads a gradient attribute, following href inheritance.</summary>
    private string? GradientAttribute(HtmlNode gradient, string name)
    {
        HtmlNode? current = gradient;
        for (int i = 0; i < 16 && current is not null; i++)
        {
            if (current.GetAttribute(name) is { } value)
            {
                return value;
            }

            current = Href(current) is { } href ? Lookup(current, href) : null;
        }

        return null;
    }

    private List<(float T, PdfColor Color)> GradientStops(HtmlNode gradient)
    {
        HtmlNode? current = gradient;
        for (int i = 0; i < 16 && current is not null; i++)
        {
            List<HtmlNode> stopNodes = [.. current.Children.Where(c => c.Tag == "stop")];
            if (stopNodes.Count > 0)
            {
                var stops = new List<(float, PdfColor)>();
                foreach (HtmlNode stop in stopNodes)
                {
                    string offsetText = stop.GetAttribute("offset")?.Trim() ?? "0";
                    float offset = offsetText.EndsWith('%') ? (Number(offsetText[..^1]) ?? 0) / 100 : Number(offsetText) ?? 0;
                    string colorText = stop.ComputedStyle?.SvgProperties?.GetValueOrDefault("stop-color") ?? stop.GetAttribute("stop-color") ?? "black";
                    string opacityText = stop.ComputedStyle?.SvgProperties?.GetValueOrDefault("stop-opacity") ?? stop.GetAttribute("stop-opacity") ?? "1";
                    PdfColor color = colorText.Trim().Equals("currentcolor", StringComparison.OrdinalIgnoreCase)
                        ? stop.ComputedStyle?.Color ?? PdfColor.Black
                        : PdfColor.Parse(colorText);
                    float alpha = (color.IsTransparent ? 0 : color.Alpha) * (ParseOpacity(opacityText) ?? 1);
                    PdfColor opaque = color.IsTransparent ? PdfColor.Black : color;
                    stops.Add((Math.Clamp(offset, 0, 1), alpha <= 0 ? PdfColor.Transparent with { Alpha = 1 } : opaque with { Alpha = alpha }));
                }

                // Transparent stops keep their neighbour's color so they fade instead of darkening.
                for (int k = 0; k < stops.Count; k++)
                {
                    if (stops[k].Item2.IsTransparent)
                    {
                        PdfColor near = stops.Skip(k + 1).Concat(stops.Take(k).Reverse()).Select(x => x.Item2).FirstOrDefault(c => !c.IsTransparent, PdfColor.Black);
                        stops[k] = (stops[k].Item1, near with { Alpha = 0.0001f });
                    }
                }

                return stops;
            }

            current = Href(current) is { } href ? Lookup(current, href) : null;
        }

        return [];
    }

    private PdfColor? FirstStopColor(HtmlNode gradient) =>
        GradientStops(gradient) is { Count: > 0 } stops ? stops[0].Color with { Alpha = 1 } : null;

    private void PaintGradient(PdfContentStream cs, HtmlNode gradient, PdfRect bounds, float opacity)
    {
        List<(float T, PdfColor Color)> stops = GradientStops(gradient);
        if (stops.Count == 0)
        {
            return;
        }

        if (opacity < 1)
        {
            stops = [.. stops.Select(st => (st.T, st.Color with { Alpha = st.Color.Alpha * opacity }))];
        }

        if (stops.Count == 1)
        {
            cs.SetFillColor(stops[0].Color);
            cs.FillRect(bounds.X, bounds.Bottom, bounds.Width, bounds.Height);
            return;
        }

        bool userSpace = GradientAttribute(gradient, "gradientunits") == "userSpaceOnUse";
        Matrix2D units = userSpace ? Matrix2D.Identity : new Matrix2D(bounds.Width, 0, 0, bounds.Height, bounds.X, bounds.Bottom);
        Matrix2D gradientTransform = ParseTransform(GradientAttribute(gradient, "gradienttransform")) ?? Matrix2D.Identity;
        Matrix2D total = gradientTransform.Then(units);
        if (MathF.Abs((total.A * total.D) - (total.B * total.C)) < 1e-12f)
        {
            return;
        }

        // Coordinates: fractions in bounding-box units, user-space lengths otherwise.
        var state = new State { ViewportWidth = bounds.Width, ViewportHeight = bounds.Height };
        float Coord(string name, string fallback, char axis)
        {
            string raw = GradientAttribute(gradient, name) ?? fallback;
            if (!userSpace)
            {
                string t = raw.Trim();
                return t.EndsWith('%') ? (Number(t[..^1]) ?? 0) / 100 : Number(t) ?? 0;
            }

            return Length(raw, state, axis);
        }

        Concat(cs, total);

        // The soft-mask box must cover the clip, expressed in the gradient's own space.
        Matrix2D inverse = total.Invert();
        var corners = new[]
        {
            inverse.Apply(bounds.X, bounds.Bottom), inverse.Apply(bounds.Right, bounds.Bottom),
            inverse.Apply(bounds.X, bounds.Top), inverse.Apply(bounds.Right, bounds.Top),
        };
        float minX = corners.Min(c => c.X), minY = corners.Min(c => c.Y);
        var maskBox = new PdfRect(minX, minY, corners.Max(c => c.X) - minX, corners.Max(c => c.Y) - minY);

        if (gradient.Tag == "lineargradient")
        {
            float[] coords = [Coord("x1", "0%", 'x'), Coord("y1", "0%", 'y'), Coord("x2", "100%", 'x'), Coord("y2", "0%", 'y')];
            GradientShading.PaintGeometry(cs, radial: false, coords, stops, maskBox);
        }
        else
        {
            float cx = Coord("cx", "50%", 'x'), cy = Coord("cy", "50%", 'y'), r = Coord("r", "50%", 'd');
            float fx = GradientAttribute(gradient, "fx") is null ? cx : Coord("fx", "50%", 'x');
            float fy = GradientAttribute(gradient, "fy") is null ? cy : Coord("fy", "50%", 'y');
            if (r <= 0)
            {
                return;
            }

            GradientShading.PaintGeometry(cs, radial: true, [fx, fy, 0, cx, cy, r], stops, maskBox);
        }
    }

    // ── Clipping, use, nested viewports, images ──────────────────────────

    private void ApplyClipPath(PdfContentStream cs, HtmlNode node, State s)
    {
        string? clip = node.ComputedStyle?.SvgProperties?.GetValueOrDefault("clip-path") ?? node.GetAttribute("clip-path");
        if (clip is null || !clip.TrimStart().StartsWith("url(", StringComparison.OrdinalIgnoreCase) || Lookup(node, clip) is not { Tag: "clippath" } clipPath)
        {
            return;
        }

        Matrix2D m = ParseTransform(clipPath.GetAttribute("transform")) ?? Matrix2D.Identity;
        if (clipPath.GetAttribute("clippathunits") == "objectBoundingBox" && ShapePath(node, s, Matrix2D.Identity) is { } own)
        {
            // Bounds are y-up in PdfRect terms but computed from SVG coordinates: Bottom holds the minimum y.
            m = m.Then(new Matrix2D(own.Bounds.Width, 0, 0, own.Bounds.Height, own.Bounds.X, own.Bounds.Bottom));
        }

        var sb = new StringBuilder();
        bool evenOdd = false;
        foreach (HtmlNode child in clipPath.Children)
        {
            if (child.NodeType != HtmlNodeType.Element)
            {
                continue;
            }

            HtmlNode shapeNode = child.Tag == "use" && Href(child) is { } href && Lookup(child, href) is { } target ? target : child;
            Matrix2D childMatrix = (ParseTransform(child.GetAttribute("transform")) ?? Matrix2D.Identity).Then(m);
            State childState = Inherit(s, shapeNode);
            evenOdd |= childState.ClipEvenOdd;
            if (ShapePath(shapeNode, childState, childMatrix) is { } shape)
            {
                sb.Append(shape.Path);
            }
        }

        if (sb.Length == 0)
        {
            // An empty clip path hides the element.
            cs.ClipRect(0, 0, 0, 0);
            return;
        }

        cs.AppendRaw(sb.ToString());
        cs.ClipPath(evenOdd);
    }

    private void RenderUse(PdfContentStream cs, HtmlNode use, State state, int depth)
    {
        if (++_useExpansions > MaxUseExpansions || Href(use) is not { } href || Lookup(use, href) is not { } target || IsAncestor(target, use))
        {
            return;
        }

        float x = Length(use.GetAttribute("x"), state, 'x'), y = Length(use.GetAttribute("y"), state, 'y');
        if (x != 0 || y != 0)
        {
            Concat(cs, Matrix2D.Translation(x, y));
        }

        if (target.Tag is "symbol" or "svg")
        {
            string? w = use.GetAttribute("width") ?? target.GetAttribute("width");
            string? h = use.GetAttribute("height") ?? target.GetAttribute("height");
            RenderNestedSvg(cs, target, use, Inherit(state, target), depth, w is null ? state.ViewportWidth : Length(w, state, 'x'), h is null ? state.ViewportHeight : Length(h, state, 'y'), ignorePosition: true);
            return;
        }

        RenderElement(cs, target, state, depth + 1);
    }

    private void RenderNestedSvg(PdfContentStream cs, HtmlNode viewportNode, HtmlNode positionNode, State state, int depth, float width, float height, bool ignorePosition = false)
    {
        if (width <= 0 || height <= 0)
        {
            return;
        }

        float x = ignorePosition ? 0 : Length(positionNode.GetAttribute("x"), state, 'x');
        float y = ignorePosition ? 0 : Length(positionNode.GetAttribute("y"), state, 'y');
        float[]? viewBox = SvgDocument.ParseViewBox(viewportNode.GetAttribute("viewbox"));
        cs.AppendRaw($"{N(x)} {N(y)} {N(width)} {N(height)} re W n\n");
        Concat(cs, Matrix2D.Translation(x, y));
        State inner = state with { ViewportWidth = width, ViewportHeight = height };
        if (viewBox is not null)
        {
            Concat(cs, ViewportMatrix(viewBox, width, height, viewportNode.GetAttribute("preserveaspectratio")));
            inner = inner with { ViewportWidth = viewBox[2], ViewportHeight = viewBox[3] };
        }

        RenderChildren(cs, viewportNode, inner, depth);
    }

    private void RenderImage(PdfContentStream cs, HtmlNode node, State state)
    {
        if (Href(node) is not { Length: > 0 } href || state.Hidden)
        {
            return;
        }

        float x = Length(node.GetAttribute("x"), state, 'x'), y = Length(node.GetAttribute("y"), state, 'y');
        float w = Length(node.GetAttribute("width"), state, 'x'), h = Length(node.GetAttribute("height"), state, 'y');
        if (_images.GetSvg(href) is { } nested)
        {
            (float iw, float ih) = SvgDocument.IntrinsicSize(nested);
            w = w > 0 ? w : iw;
            h = h > 0 ? h : ih;
            Concat(cs, new Matrix2D(1, 0, 0, -1, x, y + h));
            Draw(cs, nested, new PdfRect(0, 0, w, h));
            return;
        }

        if (_images.GetOrAdd(href) is not { } name || !_images.TryGetSize(name, out int pw, out int ph) || pw <= 0 || ph <= 0)
        {
            return;
        }

        w = w > 0 ? w : pw;
        h = h > 0 ? h : ph;
        _pageImages.Add(name);
        Matrix2D fit = ViewportMatrix([0, 0, pw, ph], w, h, node.GetAttribute("preserveaspectratio"));

        // Image space is y-up unit square; map it to the fitted rectangle in y-down user space.
        cs.AppendRaw($"{N(x)} {N(y)} {N(w)} {N(h)} re W n\n");
        Concat(cs, new Matrix2D(pw * fit.A, 0, 0, -ph * fit.D, x + fit.E, y + fit.F + (ph * fit.D)));
        cs.DrawImage(name, 0, 0, 1, 1);
    }

    private static bool IsAncestor(HtmlNode candidate, HtmlNode node)
    {
        for (HtmlNode? p = node; p is not null; p = p.Parent)
        {
            if (ReferenceEquals(p, candidate))
            {
                return true;
            }
        }

        return false;
    }

    // ── Text ─────────────────────────────────────────────────────────────

    private readonly record struct TextRun(string Text, State State, HtmlNode Node, float? X, float? Y, float Dx, float Dy);

    private void RenderText(PdfContentStream cs, HtmlNode text, State state)
    {
        var runs = new List<TextRun>();
        CollectRuns(text, state, runs, first: true);
        if (runs.Count == 0)
        {
            return;
        }

        // Collapse whitespace across the element (xml:space default).
        var cleaned = new List<TextRun>();
        bool lastSpace = true;
        foreach (TextRun run in runs)
        {
            var sb = new StringBuilder();
            foreach (char c in run.Text)
            {
                bool space = char.IsWhiteSpace(c);
                if (space && lastSpace)
                {
                    continue;
                }

                sb.Append(space ? ' ' : c);
                lastSpace = space;
            }

            cleaned.Add(run with { Text = sb.ToString() });
        }

        if (cleaned.Count > 0)
        {
            TextRun lastRun = cleaned[^1];
            cleaned[^1] = lastRun with { Text = lastRun.Text.TrimEnd() };
        }

        float penX = 0, penY = 0;
        int i = 0;
        while (i < cleaned.Count)
        {
            // A chunk starts at an absolutely positioned run and is anchored as a whole.
            int end = i + 1;
            while (end < cleaned.Count && cleaned[end].X is null && cleaned[end].Y is null)
            {
                end++;
            }

            TextRun head = cleaned[i];
            penX = head.X ?? penX;
            penY = head.Y ?? penY;
            float chunkWidth = 0;
            for (int k = i; k < end; k++)
            {
                chunkWidth += cleaned[k].Dx + Measure(cleaned[k]);
            }

            float shift = head.State.TextAnchor switch
            {
                "middle" => -chunkWidth / 2,
                "end" => -chunkWidth,
                _ => 0,
            };
            penX += shift;
            for (int k = i; k < end; k++)
            {
                TextRun run = cleaned[k];
                penX += run.Dx;
                penY += run.Dy;
                if (run.Text.Length > 0 && ResolvePaint(run.Node, run.State.Fill, run.State) is PdfColor fill && !run.State.Hidden)
                {
                    float baselineShift = run.State.Baseline switch
                    {
                        "middle" or "central" => run.State.FontSize * 0.35f,
                        "hanging" or "text-before-edge" or "text-top" => run.State.FontSize * 0.8f,
                        _ => 0,
                    };
                    cs.SaveState();
                    Concat(cs, new Matrix2D(1, 0, 0, -1, penX, penY + baselineShift));
                    cs.DrawText(run.Text, 0, 0, FontFor(run, cs.Fonts), run.State.FontSize, fill with { Alpha = fill.Alpha * run.State.FillOpacity });
                    cs.RestoreState();
                }
                else if (GradientFor(run.Node, run.State.Fill) is { } gradient && FirstStopColor(gradient) is PdfColor first && run.Text.Length > 0)
                {
                    cs.SaveState();
                    Concat(cs, new Matrix2D(1, 0, 0, -1, penX, penY));
                    cs.DrawText(run.Text, 0, 0, FontFor(run, cs.Fonts), run.State.FontSize, first);
                    cs.RestoreState();
                }

                penX += Measure(run);
            }

            i = end;
        }

        float Measure(TextRun run) =>
            run.Text.Length == 0 ? 0 : TextMeasurer.MeasureResolved(run.Text, FontFor(run, cs.Fonts), cs.Fonts, run.State.FontSize, 0, 0);
    }

    private static ResolvedFont FontFor(TextRun run, FontCollection? fonts)
    {
        List<string> families = [.. run.State.FontFamily.Split(',').Select(f => f.Trim().Trim('"', '\'')).Where(f => f.Length > 0)];
        var style = new ComputedStyle
        {
            FontFamily = families.FirstOrDefault() ?? "sans-serif",
            FontFamilies = families,
            IsBold = run.State.Bold,
            IsItalic = run.State.Italic,
        };
        return TextMeasurer.ResolveFont(style, fonts);
    }

    private static void CollectRuns(HtmlNode element, State state, List<TextRun> runs, bool first)
    {
        float? x = First(element.GetAttribute("x"));
        float? y = First(element.GetAttribute("y"));
        float dx = First(element.GetAttribute("dx")) ?? 0;
        float dy = First(element.GetAttribute("dy")) ?? 0;
        bool positioned = true;
        foreach (HtmlNode child in element.Children)
        {
            if (child.NodeType == HtmlNodeType.Text)
            {
                runs.Add(new TextRun(child.Text ?? string.Empty, state, element, positioned ? x : null, positioned ? y : null, positioned ? dx : 0, positioned ? dy : 0));
                positioned = false;
            }
            else if (child.Tag is "tspan" or "a" or "textpath")
            {
                if (positioned && (x is not null || y is not null || dx != 0 || dy != 0))
                {
                    runs.Add(new TextRun(string.Empty, state, element, x, y, dx, dy));
                }

                positioned = false;
                State childState = Inherit(state, child);
                if (child.GetAttribute("display") != "none")
                {
                    CollectRuns(child, childState, runs, first: false);
                }
            }
        }

        if (first && runs.Count == 0)
        {
            runs.Add(new TextRun(string.Empty, state, element, x, y, dx, dy));
        }

        static float? First(string? list) =>
            list is null ? null : SvgPathParser.ParseNumbers(list) is { Length: > 0 } n ? n[0] : null;
    }

    // ── Helpers ──────────────────────────────────────────────────────────

    private static string? Href(HtmlNode node) => node.GetAttribute("href") ?? node.GetAttribute("xlink:href");

    /// <summary>Finds the element referenced by <c>#id</c> or <c>url(#id)</c> in the node's document.</summary>
    private HtmlNode? Lookup(HtmlNode from, string reference)
    {
        string r = reference.Trim();
        if (r.StartsWith("url(", StringComparison.OrdinalIgnoreCase))
        {
            int close = r.IndexOf(')', StringComparison.Ordinal);
            r = close > 4 ? r[4..close].Trim().Trim('"', '\'') : string.Empty;
        }

        if (!r.StartsWith('#'))
        {
            return null;
        }

        HtmlNode root = from;
        while (root.Parent is not null)
        {
            root = root.Parent;
        }

        if (!_idMaps.TryGetValue(root, out Dictionary<string, HtmlNode>? map))
        {
            map = new Dictionary<string, HtmlNode>(StringComparer.Ordinal);
            var stack = new Stack<HtmlNode>();
            stack.Push(root);
            while (stack.Count > 0)
            {
                HtmlNode n = stack.Pop();
                if (n.GetAttribute("id") is { } id)
                {
                    map.TryAdd(id, n);
                }

                for (int c = n.Children.Count - 1; c >= 0; c--)
                {
                    stack.Push(n.Children[c]);
                }
            }

            _idMaps[root] = map;
        }

        return map.GetValueOrDefault(r[1..]);
    }

    /// <summary>Resolves an SVG length. Axis 'x'/'y' use the viewport width/height for percentages, 'd' the normalized diagonal.</summary>
    private static float Length(string? value, State s, char axis)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return 0;
        }

        string v = value.Trim();
        if (v.EndsWith('%'))
        {
            float pct = Number(v[..^1]) ?? 0;
            float reference = axis switch
            {
                'x' => s.ViewportWidth,
                'y' => s.ViewportHeight,
                _ => MathF.Sqrt(((s.ViewportWidth * s.ViewportWidth) + (s.ViewportHeight * s.ViewportHeight)) / 2),
            };
            return reference * pct / 100;
        }

        if (v.EndsWith("em", StringComparison.Ordinal) && !v.EndsWith("rem", StringComparison.Ordinal))
        {
            return (Number(v[..^2]) ?? 0) * s.FontSize;
        }

        return Number(v) ?? SvgDocument.ParseAbsolute(v) ?? 0;
    }

    private static float? Number(string text) =>
        float.TryParse(text.Trim(), NumberStyles.Float, CultureInfo.InvariantCulture, out float n) && float.IsFinite(n) ? n : null;

    private static float? ParseOpacity(string? value)
    {
        if (value is null)
        {
            return null;
        }

        string v = value.Trim();
        float? n = v.EndsWith('%') ? Number(v[..^1]) / 100 : Number(v);
        return n is float f ? Math.Clamp(f, 0, 1) : null;
    }

    /// <summary>Parses the SVG <c>transform</c> attribute (unitless numbers, angles in degrees).</summary>
    internal static Matrix2D? ParseTransform(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        Matrix2D m = Matrix2D.Identity;
        int i = 0;
        string s = value;
        while (i < s.Length)
        {
            while (i < s.Length && (char.IsWhiteSpace(s[i]) || s[i] == ','))
            {
                i++;
            }

            int nameStart = i;
            while (i < s.Length && char.IsLetter(s[i]))
            {
                i++;
            }

            string name = s[nameStart..i].ToLowerInvariant();
            int open = s.IndexOf('(', i);
            int close = open < 0 ? -1 : s.IndexOf(')', open);
            if (name.Length == 0 || open < 0 || close < 0)
            {
                break;
            }

            float[] a = SvgPathParser.ParseNumbers(s[(open + 1)..close]);
            i = close + 1;
            Matrix2D step = name switch
            {
                "matrix" when a.Length == 6 => new Matrix2D(a[0], a[1], a[2], a[3], a[4], a[5]),
                "translate" when a.Length >= 1 => Matrix2D.Translation(a[0], a.Length > 1 ? a[1] : 0),
                "scale" when a.Length >= 1 => Matrix2D.Scale(a[0], a.Length > 1 ? a[1] : a[0]),
                "rotate" when a.Length == 1 => Matrix2D.Rotation(a[0] * MathF.PI / 180),
                "rotate" when a.Length >= 3 => Matrix2D.Translation(-a[1], -a[2]).Then(Matrix2D.Rotation(a[0] * MathF.PI / 180)).Then(Matrix2D.Translation(a[1], a[2])),
                "skewx" when a.Length == 1 => new Matrix2D(1, 0, MathF.Tan(a[0] * MathF.PI / 180), 1, 0, 0),
                "skewy" when a.Length == 1 => new Matrix2D(1, MathF.Tan(a[0] * MathF.PI / 180), 0, 1, 0, 0),
                _ => Matrix2D.Identity,
            };

            // "a b" means apply b first, then a.
            m = step.Then(m);
        }

        return m.IsIdentity ? null : m;
    }

    private static void Concat(PdfContentStream cs, Matrix2D m)
    {
        if (!m.IsIdentity)
        {
            cs.ConcatMatrix(m.A, m.B, m.C, m.D, m.E, m.F);
        }
    }

    private static string N(float value) => (MathF.Abs(value) < 1e-6f ? 0f : value).ToString("0.####", CultureInfo.InvariantCulture);

    /// <summary>Writes path operators with precise numbers, tracking the bounding box (in unmapped coordinates).</summary>
    private sealed class PathWriter(Matrix2D m)
    {
        private const float Kappa = 0.5522848f;
        private readonly StringBuilder _sb = new();
        private float _minX = float.MaxValue, _minY = float.MaxValue, _maxX = float.MinValue, _maxY = float.MinValue;

        public bool IsEmpty => _sb.Length == 0;

        public PdfRect Bounds => IsEmpty ? default : new PdfRect(_minX, _minY, _maxX - _minX, _maxY - _minY);

        public void MoveTo(float x, float y) => Op("m", (x, y));

        public void LineTo(float x, float y) => Op("l", (x, y));

        public void CurveTo(float x1, float y1, float x2, float y2, float x, float y) => Op("c", (x1, y1), (x2, y2), (x, y));

        public void Close() => _sb.Append("h\n");

        public void Rect(float x, float y, float w, float h, float rx, float ry)
        {
            if (rx <= 0 || ry <= 0)
            {
                MoveTo(x, y);
                LineTo(x + w, y);
                LineTo(x + w, y + h);
                LineTo(x, y + h);
                Close();
                return;
            }

            float kx = rx * Kappa, ky = ry * Kappa;
            MoveTo(x + rx, y);
            LineTo(x + w - rx, y);
            CurveTo(x + w - rx + kx, y, x + w, y + ry - ky, x + w, y + ry);
            LineTo(x + w, y + h - ry);
            CurveTo(x + w, y + h - ry + ky, x + w - rx + kx, y + h, x + w - rx, y + h);
            LineTo(x + rx, y + h);
            CurveTo(x + rx - kx, y + h, x, y + h - ry + ky, x, y + h - ry);
            LineTo(x, y + ry);
            CurveTo(x, y + ry - ky, x + rx - kx, y, x + rx, y);
            Close();
        }

        public void Ellipse(float cx, float cy, float rx, float ry)
        {
            float kx = rx * Kappa, ky = ry * Kappa;
            MoveTo(cx + rx, cy);
            CurveTo(cx + rx, cy + ky, cx + kx, cy + ry, cx, cy + ry);
            CurveTo(cx - kx, cy + ry, cx - rx, cy + ky, cx - rx, cy);
            CurveTo(cx - rx, cy - ky, cx - kx, cy - ry, cx, cy - ry);
            CurveTo(cx + kx, cy - ry, cx + rx, cy - ky, cx + rx, cy);
            Close();
        }

        public override string ToString() => _sb.ToString();

        private void Op(string op, params (float X, float Y)[] points)
        {
            foreach (var (x, y) in points)
            {
                _minX = Math.Min(_minX, x);
                _minY = Math.Min(_minY, y);
                _maxX = Math.Max(_maxX, x);
                _maxY = Math.Max(_maxY, y);
                (float px, float py) = m.Apply(x, y);
                _sb.Append(N(px)).Append(' ').Append(N(py)).Append(' ');
            }

            _sb.Append(op).Append('\n');
        }
    }
}

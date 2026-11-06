using SimpleSign.HtmlToPdf.Layout;
using SimpleSign.HtmlToPdf.Parsing;

namespace SimpleSign.HtmlToPdf.Rendering;

/// <summary>
/// Inherited visual effects for the boxes of one page: opacity, transforms, blend modes and
/// overflow clipping. Layout flattens the tree into boxes, so each box re-applies the effects
/// of its element and its ancestors (outermost first) inside its own q/Q pair.
/// </summary>
internal sealed class BoxEffects
{
    private readonly Dictionary<HtmlNode, PdfRect> _borderBoxes = [];
    private readonly Dictionary<HtmlNode, Effect> _own = [];
    private readonly Dictionary<HtmlNode, Effect> _inner = [];
    private readonly Matrix2D _flip;

    public BoxEffects(PageBox page, PageSettings settings)
    {
        float originY = settings.PageHeight - settings.Margins.Top;
        _flip = new Matrix2D(1, 0, 0, -1, 0, originY);
        foreach (LayoutBox box in page.Boxes)
        {
            if (box.Node is { } node && box.Type is LayoutBoxType.Block or LayoutBoxType.Image && !_borderBoxes.ContainsKey(node))
            {
                _borderBoxes[node] = PdfDocumentRenderer.BorderBoxOf(box, settings);
            }
        }
    }

    /// <summary>One drawing step: a matrix to concatenate or a rectangle to clip to.</summary>
    internal readonly record struct Step(Matrix2D? Matrix, PdfRect? Clip);

    /// <summary>The effect stack for a box.</summary>
    internal sealed record Effect(IReadOnlyList<Step> Steps, float Alpha, string? BlendMode)
    {
        public static readonly Effect None = new([], 1f, null);

        public bool IsTrivial => Steps.Count == 0 && Alpha >= 0.999f && BlendMode is null;
    }

    /// <summary>Gets the effects that apply to a box drawn for <paramref name="node"/>.</summary>
    public Effect For(HtmlNode? node) => node is null ? Effect.None : Own(node);

    /// <summary>Gets the border box of an element on this page, when it has one.</summary>
    public bool TryGetBorderBox(HtmlNode node, out PdfRect rect) => _borderBoxes.TryGetValue(node, out rect);

    // Effects of the element itself: its ancestors' inner effects plus its own transform/opacity.
    private Effect Own(HtmlNode node)
    {
        if (_own.TryGetValue(node, out Effect? cached))
        {
            return cached;
        }

        Effect parent = node.Parent is { } p ? Inner(p) : Effect.None;
        ComputedStyle? style = node.NodeType == HtmlNodeType.Element ? node.ComputedStyle : null;
        Effect result = parent;
        if (style is not null)
        {
            List<Step>? steps = null;
            if (style.Transform is { Count: > 0 } transform && _borderBoxes.TryGetValue(node, out PdfRect rect))
            {
                Matrix2D m = ToPdfMatrix(transform, style.TransformOrigin, rect);
                if (!m.IsIdentity)
                {
                    steps = [.. parent.Steps, new Step(m, null)];
                }
            }

            float alpha = parent.Alpha * Math.Clamp(style.Opacity, 0, 1);
            string? blend = style.BlendMode ?? parent.BlendMode;
            if (steps is not null || alpha != parent.Alpha || blend != parent.BlendMode)
            {
                result = new Effect(steps ?? parent.Steps, alpha, blend);
            }
        }

        _own[node] = result;
        return result;
    }

    // Effects for descendants: the element's own effects plus its overflow clip.
    private Effect Inner(HtmlNode node)
    {
        if (_inner.TryGetValue(node, out Effect? cached))
        {
            return cached;
        }

        Effect own = Own(node);
        Effect result = own;
        if (node.ComputedStyle is { ClipsContent: true } style && _borderBoxes.TryGetValue(node, out PdfRect rect))
        {
            BorderStyle b = style.Border;
            PdfRect padding = rect.Inset(b.TopWidth, b.RightWidth, b.BottomWidth, b.LeftWidth);
            result = own with { Steps = [.. own.Steps, new Step(null, padding)] };
        }

        _inner[node] = result;
        return result;
    }

    /// <summary>Converts a CSS transform (y-down, about the transform origin) to a PDF-space matrix.</summary>
    private Matrix2D ToPdfMatrix(IReadOnlyList<TransformFunction> transform, CssPosition origin, PdfRect rect)
    {
        Matrix2D css = CssPaint.ToMatrix(transform, rect.Width, rect.Height);

        // Origin in layout coordinates: the border box's top-left plus the origin offset.
        (float left, float top) = _flip.Apply(rect.X, rect.Top);
        float ox = left + origin.X.Resolve(rect.Width);
        float oy = top + origin.Y.Resolve(rect.Height);
        Matrix2D aboutOrigin = Matrix2D.Translation(-ox, -oy).Then(css).Then(Matrix2D.Translation(ox, oy));

        // PDF → layout → transform → PDF (the flip is its own inverse).
        return _flip.Then(aboutOrigin).Then(_flip);
    }

    /// <summary>Emits the effect's matrices and clips; the caller wraps this in q/Q.</summary>
    public static void Apply(PdfContentStream cs, Effect effect)
    {
        foreach (Step step in effect.Steps)
        {
            if (step.Matrix is Matrix2D m)
            {
                cs.ConcatMatrix(m.A, m.B, m.C, m.D, m.E, m.F);
            }
            else if (step.Clip is PdfRect clip)
            {
                BackgroundPainter.ClipShape(cs, clip);
            }
        }

        cs.GroupAlpha = effect.Alpha;
        cs.SetBlendMode(effect.BlendMode);
    }

    /// <summary>Maps a PDF-space rectangle through the effect's matrices (for link annotations).</summary>
    public static (float X1, float Y1, float X2, float Y2) TransformBounds(Effect effect, float x1, float y1, float x2, float y2)
    {
        Matrix2D total = Matrix2D.Identity;
        foreach (Step step in effect.Steps)
        {
            if (step.Matrix is Matrix2D m)
            {
                // Later cm operators apply first to the drawn coordinates.
                total = m.Then(total);
            }
        }

        if (total.IsIdentity)
        {
            return (x1, y1, x2, y2);
        }

        var corners = new[] { total.Apply(x1, y1), total.Apply(x2, y1), total.Apply(x1, y2), total.Apply(x2, y2) };
        return (corners.Min(c => c.X), corners.Min(c => c.Y), corners.Max(c => c.X), corners.Max(c => c.Y));
    }
}

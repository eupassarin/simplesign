using SimpleSign.HtmlToPdf.Parsing;

namespace SimpleSign.HtmlToPdf.Rendering;

/// <summary>A rectangle in PDF coordinates (bottom-left origin) with an optional corner radius.</summary>
internal readonly record struct PdfRect(float X, float Bottom, float Width, float Height, float Radius = 0)
{
    public float Top => Bottom + Height;

    public float Right => X + Width;

    public PdfRect Inset(float top, float right, float bottom, float left) => new(
        X + left,
        Bottom + bottom,
        Math.Max(0, Width - left - right),
        Math.Max(0, Height - top - bottom),
        Math.Max(0, Radius - Math.Max(Math.Max(top, bottom), Math.Max(left, right))));

    public PdfRect Expand(float amount) => new(
        X - amount, Bottom - amount, Math.Max(0, Width + (2 * amount)), Math.Max(0, Height + (2 * amount)), Math.Max(0, Radius + amount));
}

/// <summary>Paints CSS backgrounds (colors, images, gradients) and box shadows.</summary>
internal static class BackgroundPainter
{
    private const int MaxTiles = 4096;

    /// <summary>Paints the background color and image layers of a box.</summary>
    public static void Paint(PdfContentStream cs, ComputedStyle style, PdfRect borderBox, ImageObjectCache images, HashSet<string> pageImages)
    {
        BorderStyle b = style.Border;
        PdfRect paddingBox = borderBox.Inset(b.TopWidth, b.RightWidth, b.BottomWidth, b.LeftWidth);
        Thickness p = style.Padding;
        PdfRect contentBox = paddingBox.Inset(Math.Max(0, p.Top), Math.Max(0, p.Right), Math.Max(0, p.Bottom), Math.Max(0, p.Left));
        PdfRect AreaOf(BackgroundBox box) => box switch
        {
            BackgroundBox.PaddingBox => paddingBox,
            BackgroundBox.ContentBox => contentBox,
            _ => borderBox,
        };

        IReadOnlyList<CssImage?> layers = style.BackgroundImages ?? [];
        BackgroundBox colorClip = Pick(style.BackgroundClips, Math.Max(0, layers.Count - 1), BackgroundBox.BorderBox);
        if (style.BackgroundColor is PdfColor color && !color.IsTransparent)
        {
            cs.SetFillColor(color);
            FillShape(cs, AreaOf(colorClip));
        }

        // The first layer is on top, so paint from the last.
        for (int i = layers.Count - 1; i >= 0; i--)
        {
            if (layers[i] is not CssImage image)
            {
                continue;
            }

            PdfRect clip = AreaOf(Pick(style.BackgroundClips, i, BackgroundBox.BorderBox));
            PdfRect origin = AreaOf(Pick(style.BackgroundOrigins, i, BackgroundBox.PaddingBox));
            PaintLayer(cs, image, clip, origin,
                Pick(style.BackgroundSizes, i, BackgroundSize.Auto),
                Pick(style.BackgroundPositions, i, CssPosition.TopLeft),
                Pick(style.BackgroundRepeats, i, BackgroundRepeat.Both),
                images, pageImages);
        }
    }

    /// <summary>Paints one image or gradient layer, tiled as requested, inside <paramref name="clip"/>.</summary>
    public static void PaintLayer(PdfContentStream cs, CssImage image, PdfRect clip, PdfRect origin, BackgroundSize size,
        CssPosition position, BackgroundRepeat repeat, ImageObjectCache images, HashSet<string> pageImages)
    {
        if (clip.Width <= 0 || clip.Height <= 0)
        {
            return;
        }

        string? imageName = null;
        HtmlNode? svg = image is CssUrlImage svgUrl ? images.GetSvg(svgUrl.Url) : null;
        float? intrinsicW = null, intrinsicH = null;
        if (svg is not null)
        {
            (float sw, float sh) = Svg.SvgDocument.IntrinsicSize(svg);
            intrinsicW = sw * 0.75f;
            intrinsicH = sh * 0.75f;
        }
        else if (image is CssUrlImage url)
        {
            imageName = images.GetOrAdd(url.Url);
            if (imageName is null || !images.TryGetSize(imageName, out int pw, out int ph) || pw <= 0 || ph <= 0)
            {
                return;
            }

            // CSS pixels → points.
            intrinsicW = pw * 0.75f;
            intrinsicH = ph * 0.75f;
            pageImages.Add(imageName);
        }

        (float tileW, float tileH) = TileSize(size, origin, intrinsicW, intrinsicH);
        if (tileW <= 0.01f || tileH <= 0.01f)
        {
            return;
        }

        // Position is measured from the origin box's top-left corner (CSS y-down).
        float left = origin.X + position.X.Resolve(origin.Width - tileW);
        float top = origin.Top - position.Y.Resolve(origin.Height - tileH);

        float startX = left, endX = left + tileW;
        if (repeat.X)
        {
            startX = left - (MathF.Ceiling((left - clip.X) / tileW) * tileW);
            endX = clip.Right;
        }

        float startTop = top, endBottom = top - tileH;
        if (repeat.Y)
        {
            startTop = top + (MathF.Ceiling((clip.Top - top) / tileH) * tileH);
            endBottom = clip.Bottom;
        }

        int columns = Math.Max(1, (int)MathF.Ceiling((endX - startX) / tileW - 0.001f));
        int rows = Math.Max(1, (int)MathF.Ceiling((startTop - endBottom) / tileH - 0.001f));
        if ((long)columns * rows > MaxTiles)
        {
            return;
        }

        cs.SaveState();
        ClipShape(cs, clip);
        for (int r = 0; r < rows; r++)
        {
            float tileTop = startTop - (r * tileH);
            for (int c = 0; c < columns; c++)
            {
                float tileX = startX + (c * tileW);
                const float Epsilon = 0.01f;
                if (tileX >= clip.Right - Epsilon || tileX + tileW <= clip.X + Epsilon || tileTop <= clip.Bottom + Epsilon || tileTop - tileH >= clip.Top - Epsilon)
                {
                    continue;
                }

                if (svg is not null)
                {
                    new Svg.SvgRenderer(images, pageImages).Draw(cs, svg, new PdfRect(tileX, tileTop - tileH, tileW, tileH));
                }
                else if (imageName is not null)
                {
                    cs.DrawImage(imageName, tileX, tileTop - tileH, tileW, tileH);
                }
                else if (image is CssGradient gradient)
                {
                    cs.SaveState();
                    cs.ClipRect(tileX, tileTop - tileH, tileW, tileH);
                    GradientShading.Paint(cs, gradient, tileX, tileTop - tileH, tileW, tileH);
                    cs.RestoreState();
                }
            }
        }

        cs.RestoreState();
    }

    private static (float W, float H) TileSize(BackgroundSize size, PdfRect area, float? intrinsicW, float? intrinsicH)
    {
        float? ratio = intrinsicW is float iw && intrinsicH is float ih && ih > 0 ? iw / ih : null;
        switch (size.Kind)
        {
            case BackgroundSizeKind.Cover or BackgroundSizeKind.Contain:
                if (ratio is not float rr)
                {
                    return (area.Width, area.Height);
                }

                float scaleW = area.Width, scaleH = area.Width / rr;
                bool tooTall = scaleH > area.Height;
                if (size.Kind == BackgroundSizeKind.Cover ? !tooTall && scaleH < area.Height : tooTall)
                {
                    scaleH = area.Height;
                    scaleW = area.Height * rr;
                }

                return (scaleW, scaleH);

            default:
                float? w = size.Width is float sw ? CssLength.Resolve(sw, area.Width) : null;
                float? h = size.Height is float sh ? CssLength.Resolve(sh, area.Height) : null;
                if (w is float fw && h is float fh)
                {
                    return (fw, fh);
                }

                if (w is float onlyW)
                {
                    return (onlyW, ratio is float r1 ? onlyW / r1 : intrinsicH ?? area.Height);
                }

                if (h is float onlyH)
                {
                    return (ratio is float r2 ? onlyH * r2 : intrinsicW ?? area.Width, onlyH);
                }

                return (intrinsicW ?? area.Width, intrinsicH ?? area.Height);
        }
    }

    /// <summary>Paints the outer box shadows (under the box) of a box.</summary>
    public static void PaintOuterShadows(PdfContentStream cs, IReadOnlyList<CssShadow> shadows, PdfRect borderBox, PdfRect page)
    {
        for (int i = shadows.Count - 1; i >= 0; i--)
        {
            CssShadow s = shadows[i];
            if (s.Inset || s.Color.IsTransparent)
            {
                continue;
            }

            // The shadow never shows through the box itself.
            cs.SaveState();
            PdfRect outer = page.Expand(Math.Abs(s.OffsetX) + Math.Abs(s.OffsetY) + s.Blur + Math.Abs(s.Spread) + 10);
            cs.RectPath(outer.X, outer.Bottom, outer.Width, outer.Height);
            ShapePath(cs, borderBox);
            cs.ClipPath(evenOdd: true);

            PdfRect shape = new PdfRect(borderBox.X + s.OffsetX, borderBox.Bottom - s.OffsetY, borderBox.Width, borderBox.Height, borderBox.Radius).Expand(s.Spread);
            if (s.Spread < 0 && borderBox.Radius <= 0)
            {
                shape = shape with { Radius = 0 };
            }

            PaintBlurred(cs, s.Color, s.Blur, e =>
            {
                PdfRect layer = shape.Expand(e);
                if (shape.Radius <= 0)
                {
                    layer = layer with { Radius = Math.Max(0, e) };
                }

                ShapePath(cs, layer);
                cs.Fill();
            }, inward: false);
            cs.RestoreState();
        }
    }

    /// <summary>Paints inset box shadows (above the background, inside the padding box).</summary>
    public static void PaintInsetShadows(PdfContentStream cs, IReadOnlyList<CssShadow> shadows, PdfRect paddingBox)
    {
        for (int i = shadows.Count - 1; i >= 0; i--)
        {
            CssShadow s = shadows[i];
            if (!s.Inset || s.Color.IsTransparent || paddingBox.Width <= 0 || paddingBox.Height <= 0)
            {
                continue;
            }

            cs.SaveState();
            ClipShape(cs, paddingBox);
            PdfRect hole = new PdfRect(paddingBox.X + s.OffsetX, paddingBox.Bottom - s.OffsetY, paddingBox.Width, paddingBox.Height, paddingBox.Radius).Expand(-s.Spread);
            PdfRect outer = paddingBox.Expand(Math.Abs(s.OffsetX) + Math.Abs(s.OffsetY) + s.Blur + Math.Abs(s.Spread) + 10);
            PaintBlurred(cs, s.Color, s.Blur, e =>
            {
                cs.RectPath(outer.X, outer.Bottom, outer.Width, outer.Height);
                ShapePath(cs, hole.Expand(e));
                cs.FillEvenOdd();
            }, inward: true);
            cs.RestoreState();
        }
    }

    /// <summary>
    /// Approximates a Gaussian blur with nested layers whose accumulated opacity ramps linearly
    /// across the blur band. <paramref name="drawLayer"/> receives the expansion of each layer.
    /// </summary>
    private static void PaintBlurred(PdfContentStream cs, PdfColor color, float blur, Action<float> drawLayer, bool inward)
    {
        if (blur <= 0.01f)
        {
            cs.SetFillColor(color);
            drawLayer(0);
            return;
        }

        int layers = Math.Clamp((int)MathF.Round(blur * 1.5f), 6, 24);
        float target = color.Alpha;
        float accumulated = 0;
        for (int k = 1; k <= layers; k++)
        {
            // Smoothstep ramp: closer to a Gaussian edge than a linear one.
            float u = (float)k / layers;
            float next = target * u * u * (3 - (2 * u));
            float layerAlpha = (next - accumulated) / Math.Max(1e-4f, 1 - accumulated);
            accumulated = next;

            // Outer shadows shrink from +blur to -blur; inset holes grow from -blur to +blur.
            float fraction = (k - 0.5f) / layers;
            float e = inward ? -blur + (2 * blur * fraction) : blur - (2 * blur * fraction);
            cs.SetFillColor(color with { Alpha = Math.Clamp(layerAlpha, 0, 1) });
            drawLayer(e);
        }
    }

    private static T Pick<T>(IReadOnlyList<T>? values, int index, T fallback) =>
        values is { Count: > 0 } ? values[index % values.Count] : fallback;

    /// <summary>Appends a (rounded) rectangle to the current path.</summary>
    public static void ShapePath(PdfContentStream cs, PdfRect rect)
    {
        if (rect.Radius > 0)
        {
            cs.RoundedRectPath(rect.X, rect.Bottom, rect.Width, rect.Height, rect.Radius);
        }
        else
        {
            cs.RectPath(rect.X, rect.Bottom, rect.Width, rect.Height);
        }
    }

    private static void FillShape(PdfContentStream cs, PdfRect rect)
    {
        ShapePath(cs, rect);
        cs.Fill();
    }

    public static void ClipShape(PdfContentStream cs, PdfRect rect)
    {
        ShapePath(cs, rect);
        cs.ClipPath();
    }
}

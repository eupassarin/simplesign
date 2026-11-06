using System.Globalization;
using System.Text;
using SimpleSign.HtmlToPdf.Parsing;

namespace SimpleSign.HtmlToPdf.Rendering;

/// <summary>
/// Paints CSS linear and radial gradients with PDF axial/radial shadings. Translucent
/// stops are drawn through a luminosity soft mask holding the alpha ramp.
/// </summary>
internal static class GradientShading
{
    private const int MaxRepeats = 256;

    private readonly record struct Stop(float T, PdfColor Color, float Alpha);

    /// <summary>
    /// Paints <paramref name="gradient"/> filling the rectangle (PDF coordinates, bottom-left origin).
    /// The caller has already set the clip.
    /// </summary>
    public static void Paint(PdfContentStream cs, CssGradient gradient, float x, float bottom, float width, float height)
    {
        if (cs.Resources is not { } resources || width <= 0 || height <= 0)
        {
            return;
        }

        if (gradient.IsRadial)
        {
            PaintRadial(cs, resources, gradient, x, bottom, width, height);
        }
        else
        {
            PaintLinear(cs, resources, gradient, x, bottom, width, height);
        }
    }

    /// <summary>
    /// Paints a gradient from explicit geometry (used by SVG). <paramref name="coords"/> holds the
    /// shading coordinates in the current user space: 4 numbers for axial, 6 for radial.
    /// <paramref name="bounds"/> must cover the painted area (it bounds the soft mask for translucent stops).
    /// </summary>
    internal static void PaintGeometry(PdfContentStream cs, bool radial, float[] coords, IReadOnlyList<(float T, PdfColor Color)> stops, PdfRect bounds)
    {
        if (cs.Resources is not { } resources || stops.Count == 0)
        {
            return;
        }

        var list = new List<Stop>(stops.Count);
        float max = 0;
        foreach (var (t, color) in stops)
        {
            max = Math.Max(max, Math.Clamp(t, 0, 1));
            PdfColor c = color.IsTransparent ? PdfColor.Black : color;
            list.Add(new Stop(max, c with { Alpha = 1 }, color.IsTransparent ? 0 : color.Alpha));
        }

        if (list.Count == 1)
        {
            list.Add(list[0]);
        }

        List<Stop> mapped = Remap(list, 0, 1);
        string coordText = "[" + string.Join(' ', coords.Select(N)) + "]";
        int type = radial ? 3 : 2;
        if (NeedsAlpha(mapped))
        {
            ApplySoftMask(cs, resources, $"<< /ShadingType {type} /ColorSpace /DeviceGray /Coords {coordText} /Function {BuildFunction(mapped, alpha: true)} /Extend [true true] >>",
                bounds.X, bounds.Bottom, bounds.Width, bounds.Height);
        }

        cs.PaintShading(resources.AddShading($"<< /ShadingType {type} /ColorSpace /DeviceRGB /Coords {coordText} /Function {BuildFunction(mapped, alpha: false)} /Extend [true true] >>"));
    }

    private static void PaintLinear(PdfContentStream cs, PageResources resources, CssGradient g, float x, float bottom, float w, float h)
    {
        // Direction in CSS space (y down).
        float dx, dy;
        if (g.Corner is (int cx, int cy))
        {
            dx = cx * h;
            dy = cy * w;
            float len = MathF.Sqrt((dx * dx) + (dy * dy));
            dx /= len;
            dy /= len;
        }
        else
        {
            float rad = g.AngleDegrees * MathF.PI / 180f;
            dx = MathF.Sin(rad);
            dy = -MathF.Cos(rad);
        }

        float length = MathF.Abs(w * dx) + MathF.Abs(h * dy);
        if (length <= 0.001f)
        {
            return;
        }

        List<Stop> stops = NormalizeStops(g.Stops, length, g.Repeating, 0f, 1f);
        if (stops.Count == 0)
        {
            return;
        }

        (float tMin, float tMax) = (Math.Min(0, stops[0].T), Math.Max(1, stops[^1].T));

        // Center in PDF space; CSS y-down direction flips to y-up.
        float centerX = x + (w / 2), centerY = bottom + (h / 2);
        float sx = centerX - (dx * length / 2), sy = centerY + (dy * length / 2);
        float ex = centerX + (dx * length / 2), ey = centerY - (dy * length / 2);
        float x0 = sx + ((ex - sx) * tMin), y0 = sy + ((ey - sy) * tMin);
        float x1 = sx + ((ex - sx) * tMax), y1 = sy + ((ey - sy) * tMax);
        List<Stop> mapped = Remap(stops, tMin, tMax);

        string coords = string.Create(CultureInfo.InvariantCulture, $"[{N(x0)} {N(y0)} {N(x1)} {N(y1)}]");
        if (NeedsAlpha(mapped))
        {
            string maskShading = $"<< /ShadingType 2 /ColorSpace /DeviceGray /Coords {coords} /Function {BuildFunction(mapped, alpha: true)} /Extend [true true] >>";
            ApplySoftMask(cs, resources, maskShading, x, bottom, w, h);
        }

        string shading = $"<< /ShadingType 2 /ColorSpace /DeviceRGB /Coords {coords} /Function {BuildFunction(mapped, alpha: false)} /Extend [true true] >>";
        cs.PaintShading(resources.AddShading(shading));
    }

    private static void PaintRadial(PdfContentStream cs, PageResources resources, CssGradient g, float x, float bottom, float w, float h)
    {
        // Center in CSS space relative to the box's top-left.
        float cx = g.Center.X.Resolve(w);
        float cy = g.Center.Y.Resolve(h);
        float left = Math.Abs(cx), right = Math.Abs(w - cx), top = Math.Abs(cy), down = Math.Abs(h - cy);
        float rx, ry;
        switch (g.Extent)
        {
            case RadialExtent.Explicit:
                rx = CssLength.Resolve(g.RadiusX, w);
                ry = g.Circle ? rx : CssLength.Resolve(g.RadiusY, h);
                break;
            case RadialExtent.ClosestSide:
                (rx, ry) = g.Circle ? Same(Math.Min(Math.Min(left, right), Math.Min(top, down))) : (Math.Min(left, right), Math.Min(top, down));
                break;
            case RadialExtent.FarthestSide:
                (rx, ry) = g.Circle ? Same(Math.Max(Math.Max(left, right), Math.Max(top, down))) : (Math.Max(left, right), Math.Max(top, down));
                break;
            case RadialExtent.ClosestCorner:
                (rx, ry) = g.Circle
                    ? Same(MathF.Sqrt((Math.Min(left, right) * Math.Min(left, right)) + (Math.Min(top, down) * Math.Min(top, down))))
                    : (Math.Min(left, right) * MathF.Sqrt(2), Math.Min(top, down) * MathF.Sqrt(2));
                break;
            default:
                (rx, ry) = g.Circle
                    ? Same(MathF.Sqrt((Math.Max(left, right) * Math.Max(left, right)) + (Math.Max(top, down) * Math.Max(top, down))))
                    : (Math.Max(left, right) * MathF.Sqrt(2), Math.Max(top, down) * MathF.Sqrt(2));
                break;
        }

        if (rx <= 0.001f || ry <= 0.001f)
        {
            return;
        }

        // Unit space: the ellipse is the unit circle. The tile's far corner bounds the repeats.
        float pdfCx = x + cx, pdfCy = bottom + h - cy;
        float reach = 0;
        foreach (var (px, py) in new[] { (x, bottom), (x + w, bottom), (x, bottom + h), (x + w, bottom + h) })
        {
            float ux = (px - pdfCx) / rx, uy = (py - pdfCy) / ry;
            reach = Math.Max(reach, MathF.Sqrt((ux * ux) + (uy * uy)));
        }

        List<Stop> stops = NormalizeStops(g.Stops, rx, g.Repeating, 0f, Math.Max(1f, reach));
        if (stops.Count == 0)
        {
            return;
        }

        stops = [.. stops.Select(s => s with { T = Math.Max(0, s.T) })];
        float tMax = Math.Max(1, stops[^1].T);
        List<Stop> mapped = Remap(stops, 0, tMax);

        cs.ConcatMatrix(rx, 0, 0, ry, pdfCx, pdfCy);
        string coords = string.Create(CultureInfo.InvariantCulture, $"[0 0 0 0 0 {N(tMax)}]");
        if (NeedsAlpha(mapped))
        {
            string maskShading = $"<< /ShadingType 3 /ColorSpace /DeviceGray /Coords {coords} /Function {BuildFunction(mapped, alpha: true)} /Extend [true true] >>";
            float ux0 = (x - pdfCx) / rx, ux1 = (x + w - pdfCx) / rx;
            float uy0 = (bottom - pdfCy) / ry, uy1 = (bottom + h - pdfCy) / ry;
            ApplySoftMask(cs, resources, maskShading, ux0, uy0, ux1 - ux0, uy1 - uy0);
        }

        string shading = $"<< /ShadingType 3 /ColorSpace /DeviceRGB /Coords {coords} /Function {BuildFunction(mapped, alpha: false)} /Extend [true true] >>";
        cs.PaintShading(resources.AddShading(shading));

        static (float, float) Same(float r) => (r, r);
    }

    /// <summary>Installs a luminosity soft mask whose gray levels are the gradient's alpha ramp.</summary>
    private static void ApplySoftMask(PdfContentStream cs, PageResources resources, string grayShading, float x, float y, float w, float h)
    {
        PdfObjectWriter writer = resources.Writer;
        int formObj = writer.AllocateObject();
        string bbox = string.Create(CultureInfo.InvariantCulture, $"[{N(x)} {N(y)} {N(x + w)} {N(y + h)}]");
        writer.WriteStreamObject(
            formObj,
            $"/Type /XObject /Subtype /Form /BBox {bbox} /Group << /S /Transparency /CS /DeviceGray >> /Resources << /Shading << /A {grayShading} >> >>",
            Encoding.ASCII.GetBytes("/A sh\n"));
        string gs = resources.AddExtGState($"<< /Type /ExtGState /SMask << /Type /Mask /S /Luminosity /G {formObj} 0 R >> >>");
        cs.ApplyExtGState(gs);
    }

    /// <summary>
    /// Resolves stop positions to fractions of the gradient length, fills in implicit positions,
    /// enforces monotonic order, expands transparent stops and unrolls repeating gradients over
    /// [<paramref name="coverFrom"/>, <paramref name="coverTo"/>].
    /// </summary>
    private static List<Stop> NormalizeStops(IReadOnlyList<GradientStop> source, float length, bool repeating, float coverFrom, float coverTo)
    {
        int n = source.Count;
        var t = new float?[n];
        for (int i = 0; i < n; i++)
        {
            t[i] = source[i].Position is float p ? (CssLength.IsPercent(p) ? CssLength.PercentOf(p) / 100f : p / length) : null;
        }

        if (n < 2 || Array.Exists(t, v => v is float f && !float.IsFinite(f)))
        {
            return [];
        }

        t[0] ??= 0;
        t[n - 1] ??= 1;
        float max = float.MinValue;
        for (int i = 0; i < n; i++)
        {
            if (t[i] is float v)
            {
                max = Math.Max(max, v);
                t[i] = max;
            }
        }

        for (int i = 1; i < n; i++)
        {
            if (t[i] is null)
            {
                int j = i;
                while (t[j] is null)
                {
                    j++;
                }

                float from = t[i - 1]!.Value, to = t[j]!.Value;
                for (int k = i; k < j; k++)
                {
                    t[k] = from + ((to - from) * (k - i + 1) / (j - i + 1));
                }
            }
        }

        // Transparent stops take the neighbouring colors at zero alpha (premultiplied interpolation).
        var stops = new List<Stop>(n + 4);
        for (int i = 0; i < n; i++)
        {
            PdfColor c = source[i].Color;
            if (!c.IsTransparent)
            {
                stops.Add(new Stop(t[i]!.Value, c with { Alpha = 1 }, c.Alpha));
                continue;
            }

            PdfColor? before = i > 0 ? NearestOpaque(source, i, -1) : null;
            PdfColor? after = i < n - 1 ? NearestOpaque(source, i, 1) : null;
            PdfColor fallback = before ?? after ?? PdfColor.Black;
            stops.Add(new Stop(t[i]!.Value, (before ?? fallback) with { Alpha = 1 }, 0));
            if (after is PdfColor a && before is not null)
            {
                stops.Add(new Stop(t[i]!.Value, a with { Alpha = 1 }, 0));
            }
        }

        if (!repeating)
        {
            return stops;
        }

        float first = stops[0].T, period = stops[^1].T - first;
        if (period <= 1e-4f)
        {
            return [stops[^1] with { T = coverFrom }, stops[^1] with { T = coverTo }];
        }

        double startRepeat = Math.Floor((coverFrom - first) / period);
        double endRepeat = Math.Ceiling((coverTo - first) / period);
        if (!double.IsFinite(startRepeat) || !double.IsFinite(endRepeat) || endRepeat <= startRepeat)
        {
            return [stops[^1] with { T = coverFrom }, stops[^1] with { T = coverTo }];
        }

        int startK = (int)Math.Clamp(startRepeat, int.MinValue / 2, int.MaxValue / 2);
        int endK = (int)Math.Clamp(endRepeat, int.MinValue / 2, int.MaxValue / 2);
        if (endK - startK > MaxRepeats)
        {
            endK = startK + MaxRepeats;
        }

        var repeated = new List<Stop>();
        for (int k = startK; k < endK; k++)
        {
            foreach (Stop s in stops)
            {
                repeated.Add(s with { T = s.T + (k * period) });
            }
        }

        return repeated;
    }

    private static PdfColor? NearestOpaque(IReadOnlyList<GradientStop> stops, int from, int step)
    {
        for (int i = from + step; i >= 0 && i < stops.Count; i += step)
        {
            if (!stops[i].Color.IsTransparent)
            {
                return stops[i].Color;
            }
        }

        return null;
    }

    private static List<Stop> Remap(List<Stop> stops, float tMin, float tMax)
    {
        float span = tMax - tMin;
        List<Stop> mapped = [.. stops.Select(s => s with { T = span > 0 ? Math.Clamp((s.T - tMin) / span, 0, 1) : 0 })];

        // Pad so the stitched function's intervals line up with the stops (solid color outside them).
        if (mapped[0].T > 0)
        {
            mapped.Insert(0, mapped[0] with { T = 0 });
        }

        if (mapped[^1].T < 1)
        {
            mapped.Add(mapped[^1] with { T = 1 });
        }

        return mapped;
    }

    private static bool NeedsAlpha(List<Stop> stops) => stops.Exists(s => s.Alpha < 0.999f);

    private static string BuildFunction(List<Stop> stops, bool alpha)
    {
        string C(Stop s) => alpha
            ? N(s.Alpha)
            : string.Create(CultureInfo.InvariantCulture, $"{N(s.Color.R)} {N(s.Color.G)} {N(s.Color.B)}");

        string Interp(Stop a, Stop b) => $"<< /FunctionType 2 /Domain [0 1] /C0 [{C(a)}] /C1 [{C(b)}] /N 1 >>";

        if (stops.Count <= 2)
        {
            return Interp(stops[0], stops[^1]);
        }

        // Stitch consecutive pairs; bounds must increase strictly, so nudge hard stops apart.
        var functions = new StringBuilder();
        var bounds = new StringBuilder();
        var encode = new StringBuilder();
        float previous = 0;
        for (int i = 0; i < stops.Count - 1; i++)
        {
            functions.Append(Interp(stops[i], stops[i + 1])).Append(' ');
            encode.Append("0 1 ");
            if (i < stops.Count - 2)
            {
                float bound = Math.Clamp(stops[i + 1].T, 0, 1);
                bound = Math.Min(Math.Max(bound, previous + 1e-5f), 1);
                bounds.Append(N(bound)).Append(' ');
                previous = bound;
            }
        }

        return $"<< /FunctionType 3 /Domain [0 1] /Functions [{functions.ToString().TrimEnd()}] /Bounds [{bounds.ToString().TrimEnd()}] /Encode [{encode.ToString().TrimEnd()}] >>";
    }

    private static string N(float value) => value.ToString("0.#####", CultureInfo.InvariantCulture);
}

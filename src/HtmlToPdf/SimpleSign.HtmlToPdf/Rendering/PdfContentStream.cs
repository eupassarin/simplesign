// Licensed to SimpleSign under the MIT License.

using System.Globalization;
using System.Text;
using SimpleSign.HtmlToPdf.Fonts;
using SimpleSign.HtmlToPdf.Parsing;

namespace SimpleSign.HtmlToPdf.Rendering;

/// <summary>
/// Builds PDF content stream operators for text, graphics, and colors.
/// All coordinates use PDF convention: origin at bottom-left, Y increases upward.
/// </summary>
internal sealed class PdfContentStream
{
    private readonly StringBuilder _sb = new(4096);
    private readonly HashSet<string> _usedFonts = new(StringComparer.Ordinal);
    private readonly HashSet<EmbeddedFont> _usedEmbeddedFonts = [];

    private readonly Stack<(float Fill, float Stroke, string? Blend)> _stateStack = new();
    private float _fillAlpha = 1f;
    private float _strokeAlpha = 1f;
    private string? _blendMode;

    internal PdfContentStream(FontCollection? embeddedFonts = null, PageResources? resources = null)
    {
        Fonts = embeddedFonts;
        Resources = resources;
    }

    /// <summary>Gets the page resources that graphics states and shadings are registered in.</summary>
    internal PageResources? Resources { get; }

    /// <summary>Gets or sets the opacity multiplied into every color (CSS <c>opacity</c> of the current element and its ancestors).</summary>
    internal float GroupAlpha { get; set; } = 1f;

    /// <summary>Gets the set of PDF font names used in this content stream.</summary>
    public IReadOnlySet<string> UsedFonts => _usedFonts;

    internal IReadOnlySet<EmbeddedFont> UsedEmbeddedFonts => _usedEmbeddedFonts;

    /// <summary>Gets the registered fonts available to this content stream.</summary>
    internal FontCollection? Fonts { get; }

    internal string ResolveFontName(string family, bool bold, bool italic) =>
        Fonts is not null && Fonts.TryGet(family, out _) ? family : StandardFonts.Resolve(family, bold, italic);

    /// <summary>Saves graphics state (q operator).</summary>
    public void SaveState()
    {
        _stateStack.Push((_fillAlpha, _strokeAlpha, _blendMode));
        _sb.Append("q\n");
    }

    /// <summary>Restores graphics state (Q operator).</summary>
    public void RestoreState()
    {
        if (_stateStack.Count > 0)
        {
            (_fillAlpha, _strokeAlpha, _blendMode) = _stateStack.Pop();
        }

        _sb.Append("Q\n");
    }

    /// <summary>Sets the fill color (rg operator).</summary>
    /// <param name="color">The fill color.</param>
    public void SetFillColor(PdfColor color)
    {
        _sb.Append(CultureInfo.InvariantCulture, $"{F(color.R)} {F(color.G)} {F(color.B)} rg\n");
        SetFillAlpha(color.Alpha * GroupAlpha);
    }

    /// <summary>Sets the stroke color (RG operator).</summary>
    /// <param name="color">The stroke color.</param>
    public void SetStrokeColor(PdfColor color)
    {
        _sb.Append(CultureInfo.InvariantCulture, $"{F(color.R)} {F(color.G)} {F(color.B)} RG\n");
        SetStrokeAlpha(color.Alpha * GroupAlpha);
    }

    /// <summary>Sets the non-stroking alpha (also used for images and shadings).</summary>
    internal void SetFillAlpha(float alpha)
    {
        alpha = MathF.Round(Math.Clamp(alpha, 0f, 1f), 3);
        if (alpha == _fillAlpha || Resources is null)
        {
            return;
        }

        _fillAlpha = alpha;
        string name = Resources.AddExtGState(string.Create(CultureInfo.InvariantCulture, $"<< /Type /ExtGState /ca {alpha:0.###} >>"));
        _sb.Append(CultureInfo.InvariantCulture, $"/{name} gs\n");
    }

    /// <summary>Sets the stroking alpha.</summary>
    internal void SetStrokeAlpha(float alpha)
    {
        alpha = MathF.Round(Math.Clamp(alpha, 0f, 1f), 3);
        if (alpha == _strokeAlpha || Resources is null)
        {
            return;
        }

        _strokeAlpha = alpha;
        string name = Resources.AddExtGState(string.Create(CultureInfo.InvariantCulture, $"<< /Type /ExtGState /CA {alpha:0.###} >>"));
        _sb.Append(CultureInfo.InvariantCulture, $"/{name} gs\n");
    }

    /// <summary>Sets the PDF blend mode (null = Normal).</summary>
    internal void SetBlendMode(string? blendMode)
    {
        if (blendMode == _blendMode || Resources is null)
        {
            return;
        }

        _blendMode = blendMode;
        string name = Resources.AddExtGState($"<< /Type /ExtGState /BM /{blendMode ?? "Normal"} >>");
        _sb.Append(CultureInfo.InvariantCulture, $"/{name} gs\n");
    }

    /// <summary>Applies a registered graphics state by name (e.g. a soft mask).</summary>
    internal void ApplyExtGState(string name) => _sb.Append(CultureInfo.InvariantCulture, $"/{name} gs\n");

    /// <summary>Concatenates a matrix to the CTM (cm operator).</summary>
    internal void ConcatMatrix(float a, float b, float c, float d, float e, float f) =>
        _sb.Append(CultureInfo.InvariantCulture, $"{M(a)} {M(b)} {M(c)} {M(d)} {M(e)} {M(f)} cm\n");

    /// <summary>Intersects the clip with a rectangle.</summary>
    internal void ClipRect(float x, float y, float width, float height) =>
        _sb.Append(CultureInfo.InvariantCulture, $"{F(x)} {F(y)} {F(width)} {F(height)} re W n\n");

    /// <summary>Intersects the clip with the current path (after a path construction call).</summary>
    internal void ClipPath(bool evenOdd = false) => _sb.Append(evenOdd ? "W* n\n" : "W n\n");

    /// <summary>Appends a rectangle to the current path without painting it.</summary>
    internal void RectPath(float x, float y, float width, float height) =>
        _sb.Append(CultureInfo.InvariantCulture, $"{F(x)} {F(y)} {F(width)} {F(height)} re\n");

    /// <summary>Fills the current path with the even-odd rule.</summary>
    internal void FillEvenOdd() => _sb.Append("f*\n");

    /// <summary>Paints a registered shading over the current clip (sh operator).</summary>
    internal void PaintShading(string name)
    {
        SetFillAlpha(GroupAlpha);
        _sb.Append(CultureInfo.InvariantCulture, $"/{name} sh\n");
    }

    /// <summary>Paints an image XObject into the given rectangle.</summary>
    internal void DrawImage(string name, float x, float y, float width, float height)
    {
        SetFillAlpha(GroupAlpha);
        _sb.Append(CultureInfo.InvariantCulture, $"q {F(width)} 0 0 {F(height)} {F(x)} {F(y)} cm /{name} Do Q\n");
    }

    /// <summary>Sets the line width (w operator).</summary>
    /// <param name="width">Line width in points.</param>
    public void SetLineWidth(float width) => _sb.Append(CultureInfo.InvariantCulture, $"{F(width)} w\n");

    /// <summary>Draws a filled rectangle.</summary>
    /// <param name="x">X position.</param>
    /// <param name="y">Y position (bottom-left).</param>
    /// <param name="width">Width.</param>
    /// <param name="height">Height.</param>
    public void FillRect(float x, float y, float width, float height) => _sb.Append(CultureInfo.InvariantCulture, $"{F(x)} {F(y)} {F(width)} {F(height)} re f\n");

    /// <summary>Draws a stroked rectangle.</summary>
    /// <param name="x">X position.</param>
    /// <param name="y">Y position (bottom-left).</param>
    /// <param name="width">Width.</param>
    /// <param name="height">Height.</param>
    public void StrokeRect(float x, float y, float width, float height) => _sb.Append(CultureInfo.InvariantCulture, $"{F(x)} {F(y)} {F(width)} {F(height)} re S\n");

    /// <summary>Sets the dash pattern (empty array = solid line).</summary>
    /// <param name="dash">Dash and gap lengths.</param>
    internal void SetDash(params float[] dash) =>
        _sb.Append(CultureInfo.InvariantCulture, $"[{string.Join(' ', dash.Select(F))}] 0 d\n");

    /// <summary>Sets the line cap style (0 butt, 1 round, 2 square).</summary>
    /// <param name="cap">Line cap.</param>
    internal void SetLineCap(int cap) => _sb.Append(CultureInfo.InvariantCulture, $"{cap} J\n");

    /// <summary>Draws a straight line segment.</summary>
    internal void Line(float x1, float y1, float x2, float y2) =>
        _sb.Append(CultureInfo.InvariantCulture, $"{F(x1)} {F(y1)} m {F(x2)} {F(y2)} l S\n");

    /// <summary>Appends a rounded-rectangle path (bottom-left origin) without painting it.</summary>
    internal void RoundedRectPath(float x, float y, float width, float height, float radius)
    {
        float r = Math.Max(0, Math.Min(radius, Math.Min(width, height) / 2));
        const float k = 0.5523f;
        float c = r * k;
        _sb.Append(CultureInfo.InvariantCulture, $"{F(x + r)} {F(y)} m\n");
        _sb.Append(CultureInfo.InvariantCulture, $"{F(x + width - r)} {F(y)} l\n");
        _sb.Append(CultureInfo.InvariantCulture, $"{F(x + width - r + c)} {F(y)} {F(x + width)} {F(y + r - c)} {F(x + width)} {F(y + r)} c\n");
        _sb.Append(CultureInfo.InvariantCulture, $"{F(x + width)} {F(y + height - r)} l\n");
        _sb.Append(CultureInfo.InvariantCulture, $"{F(x + width)} {F(y + height - r + c)} {F(x + width - r + c)} {F(y + height)} {F(x + width - r)} {F(y + height)} c\n");
        _sb.Append(CultureInfo.InvariantCulture, $"{F(x + r)} {F(y + height)} l\n");
        _sb.Append(CultureInfo.InvariantCulture, $"{F(x + r - c)} {F(y + height)} {F(x)} {F(y + height - r + c)} {F(x)} {F(y + height - r)} c\n");
        _sb.Append(CultureInfo.InvariantCulture, $"{F(x)} {F(y + r)} l\n");
        _sb.Append(CultureInfo.InvariantCulture, $"{F(x)} {F(y + r - c)} {F(x + r - c)} {F(y)} {F(x + r)} {F(y)} c\nh\n");
    }

    /// <summary>Fills the current path.</summary>
    internal void Fill() => _sb.Append("f\n");

    /// <summary>Strokes the current path.</summary>
    internal void Stroke() => _sb.Append("S\n");

    /// <summary>Draws a filled or stroked circle.</summary>
    internal void Circle(float cx, float cy, float radius, bool fill)
    {
        RoundedRectPath(cx - radius, cy - radius, radius * 2, radius * 2, radius);
        _sb.Append(fill ? "f\n" : "S\n");
    }

    /// <summary>Draws a horizontal line.</summary>
    /// <param name="x1">Start X.</param>
    /// <param name="y">Y position.</param>
    /// <param name="x2">End X.</param>
    public void HorizontalLine(float x1, float y, float x2) => _sb.Append(CultureInfo.InvariantCulture, $"{F(x1)} {F(y)} m {F(x2)} {F(y)} l S\n");

    /// <summary>Draws a vertical line.</summary>
    /// <param name="x">X position.</param>
    /// <param name="y1">Start Y.</param>
    /// <param name="y2">End Y.</param>
    public void VerticalLine(float x, float y1, float y2) => _sb.Append(CultureInfo.InvariantCulture, $"{F(x)} {F(y1)} m {F(x)} {F(y2)} l S\n");

    /// <summary>Draws text at the specified position.</summary>
    /// <param name="text">Text to render.</param>
    /// <param name="x">X position.</param>
    /// <param name="y">Y position (baseline).</param>
    /// <param name="pdfFontName">PDF base font name, or the family of a registered font.</param>
    /// <param name="fontSize">Font size in points.</param>
    /// <param name="color">Text color.</param>
    /// <param name="letterSpacing">Additional spacing between glyphs in points.</param>
    /// <param name="wordSpacing">Additional spacing after spaces in points.</param>
    public void DrawText(string text, float x, float y, string pdfFontName, float fontSize, PdfColor color, float letterSpacing = 0, float wordSpacing = 0)
    {
        ResolvedFont font = Fonts is not null && Fonts.TryGet(pdfFontName, out EmbeddedFont embedded)
            ? new ResolvedFont(embedded, string.Empty, false, false)
            : ResolvedFont.Standard(pdfFontName);
        DrawText(text, x, y, font, fontSize, color, letterSpacing, wordSpacing);
    }

    /// <summary>Draws text with a resolved face, falling back per glyph to faces that contain missing characters.</summary>
    internal void DrawText(string text, float x, float y, ResolvedFont font, float fontSize, PdfColor color, float letterSpacing = 0, float wordSpacing = 0, bool rightToLeft = false)
    {
        float cursorX = x;
        List<(string Text, ResolvedFont Font)> runs = FontCollection.SplitRuns(text, font, Fonts);
        if (rightToLeft)
        {
            // Font-fallback runs of a right-to-left word are laid out right to left too.
            runs.Reverse();
        }

        foreach (var (segment, segmentFont) in runs)
        {
            DrawSegment(segment, cursorX, y, segmentFont, fontSize, color, letterSpacing, wordSpacing, rightToLeft);
            cursorX += TextMeasurer.MeasureResolved(segment, segmentFont, Fonts, fontSize, letterSpacing, wordSpacing) + letterSpacing;
        }
    }

    private void DrawSegment(string text, float x, float y, ResolvedFont font, float fontSize, PdfColor color, float letterSpacing, float wordSpacing, bool rightToLeft)
    {
        bool synthetic = font.SyntheticBold || font.SyntheticItalic;
        if (synthetic)
        {
            SaveState();
        }

        SetFillColor(color);
        if (font.SyntheticBold)
        {
            SetStrokeColor(color);
            SetLineWidth(fontSize * 0.03f);
        }

        _sb.Append("BT\n");
        if (font.Embedded is { } embedded)
        {
            _usedEmbeddedFonts.Add(embedded);
            _sb.Append(CultureInfo.InvariantCulture, $"/{embedded.ResourceKey} {F(fontSize)} Tf\n");
        }
        else
        {
            _usedFonts.Add(font.StandardName);
            _sb.Append(CultureInfo.InvariantCulture, $"/{ToFontKey(font.StandardName)} {F(fontSize)} Tf\n");
        }

        if (font.SyntheticBold)
        {
            _sb.Append("2 Tr\n");
        }

        if (letterSpacing != 0)
        {
            _sb.Append(CultureInfo.InvariantCulture, $"{F(letterSpacing)} Tc\n");
        }

        if (font.SyntheticItalic)
        {
            _sb.Append(CultureInfo.InvariantCulture, $"1 0 0.21 1 {F(x)} {F(y)} Tm\n");
        }
        else
        {
            _sb.Append(CultureInfo.InvariantCulture, $"{F(x)} {F(y)} Td\n");
        }

        if (font.Embedded is { } face && TextMeasurer.UsesShaping(font, text, letterSpacing))
        {
            AppendShapedText(text, face, fontSize, wordSpacing, rightToLeft);
        }
        else if (font.Embedded is { } plain)
        {
            AppendEmbeddedText(rightToLeft ? Reverse(text) : text, plain, fontSize, wordSpacing);
        }
        else
        {
            if (wordSpacing != 0)
            {
                _sb.Append(CultureInfo.InvariantCulture, $"{F(wordSpacing)} Tw\n");
            }

            _sb.Append(CultureInfo.InvariantCulture, $"({EscapePdfString(text)}) Tj\n");
        }

        _sb.Append("ET\n");
        if (synthetic)
        {
            RestoreState();
        }
    }

    /// <summary>Reverses a string by text element (keeps surrogate pairs and combining sequences intact).</summary>
    private static string Reverse(string text)
    {
        var elements = new List<string>();
        TextElementEnumerator e = StringInfo.GetTextElementEnumerator(text);
        while (e.MoveNext())
        {
            elements.Add(e.GetTextElement());
        }

        elements.Reverse();
        return string.Concat(elements);
    }

    /// <summary>
    /// Emits shaped glyphs with a TJ array: kerning, ligature and mark offsets become TJ adjustments,
    /// vertical mark offsets become text rise.
    /// </summary>
    private void AppendShapedText(string text, EmbeddedFont font, float fontSize, float wordSpacing, bool rightToLeft)
    {
        _usedEmbeddedFonts.Add(font);
        Fonts.OpenType.ShapedRun run = font.Shape(text, rightToLeft);
        float toTextSpace = 1000f / font.UnitsPerEm;
        float extraPerSpace = wordSpacing == 0 ? 0 : wordSpacing * font.UnitsPerEm / fontSize;
        float extra = 0;
        float pen = 0;
        float rise = 0;
        _sb.Append('[');
        foreach (Fonts.OpenType.PositionedGlyph g in run.Glyphs)
        {
            if (g.Glyph == 0 && Fonts?.EmbeddedOnly == true)
            {
                continue; // PDF/A forbids referencing .notdef
            }

            float glyphRise = g.Y * fontSize / font.UnitsPerEm;
            if (MathF.Abs(glyphRise - rise) > 0.001f)
            {
                rise = glyphRise;
                _sb.Append(CultureInfo.InvariantCulture, $"] TJ\n{rise:0.###} Ts\n[");
            }

            float target = g.X + extra;
            float delta = pen - target;
            if (MathF.Abs(delta) > 0.01f)
            {
                _sb.Append(CultureInfo.InvariantCulture, $"{delta * toTextSpace:0.##} ");
            }

            font.UseGlyph(g.Glyph, g.Text);
            _sb.Append('<').Append(g.Glyph.ToString("X4", CultureInfo.InvariantCulture)).Append('>');
            pen = target + font.AdvanceOf(g.Glyph);
            if (g.Text == " ")
            {
                extra += extraPerSpace;
            }
        }

        _sb.Append("] TJ\n");
        if (rise != 0)
        {
            _sb.Append("0 Ts\n");
        }
    }

    private void AppendEmbeddedText(string text, EmbeddedFont font, float fontSize, float wordSpacing)
    {
        bool hasWordSpacing = wordSpacing != 0 && text.Contains(' ', StringComparison.Ordinal);
        if (hasWordSpacing)
        {
            _sb.Append('[');
            foreach (Rune rune in text.EnumerateRunes())
            {
                if (Fonts?.EmbeddedOnly == true && !font.HasGlyph(rune))
                {
                    continue;
                }

                _sb.Append('<');
                _sb.Append(font.GetCid(rune).ToString("X4", CultureInfo.InvariantCulture));
                _sb.Append('>');
                if (rune.Value == ' ')
                {
                    float adjustment = -wordSpacing * 1000f / fontSize;
                    _sb.Append(CultureInfo.InvariantCulture, $" {F(adjustment)} ");
                }
            }

            _sb.Append("] TJ\n");
        }
        else
        {
            _sb.Append('<');
            foreach (Rune rune in text.EnumerateRunes())
            {
                if (Fonts?.EmbeddedOnly == true && !font.HasGlyph(rune))
                {
                    continue; // PDF/A forbids referencing .notdef
                }

                _sb.Append(font.GetCid(rune).ToString("X4", CultureInfo.InvariantCulture));
            }

            _sb.Append("> Tj\n");
        }
    }

    /// <summary>Draws an underline below text.</summary>
    /// <param name="x">Start X of text.</param>
    /// <param name="y">Baseline Y of text.</param>
    /// <param name="width">Width of text.</param>
    /// <param name="fontSize">Font size.</param>
    /// <param name="color">Underline color.</param>
    public void DrawUnderline(float x, float y, float width, float fontSize, PdfColor color)
    {
        float underlineY = y - fontSize * 0.15f;
        float thickness = Math.Max(0.5f, fontSize * 0.05f);

        SetStrokeColor(color);
        SetLineWidth(thickness);
        HorizontalLine(x, underlineY, x + width);
    }

    /// <summary>Draws a strikethrough line through text at approximately mid-height.</summary>
    /// <param name="x">Start X position.</param>
    /// <param name="y">Baseline Y position.</param>
    /// <param name="width">Width of text.</param>
    /// <param name="fontSize">Font size.</param>
    /// <param name="color">Strikethrough color.</param>
    public void DrawStrikethrough(float x, float y, float width, float fontSize, PdfColor color)
    {
        float strikeY = y + fontSize * 0.3f;
        float thickness = Math.Max(0.5f, fontSize * 0.05f);

        SetStrokeColor(color);
        SetLineWidth(thickness);
        HorizontalLine(x, strikeY, x + width);
    }

    /// <summary>Appends raw content stream operators.</summary>
    /// <param name="content">Raw PDF operator string.</param>
    public void AppendRaw(string content) => _sb.Append(content);

    /// <summary>Gets the content stream bytes.</summary>
    /// <returns>ASCII-encoded content stream.</returns>
    public byte[] ToBytes() => Encoding.ASCII.GetBytes(_sb.ToString());

    /// <summary>Converts a PDF font name to a resource key (e.g., "Helvetica-Bold" → "F2").</summary>
    /// <param name="pdfFontName">PDF base font name.</param>
    /// <returns>Font resource key.</returns>
    internal static string ToFontKey(string pdfFontName)
    {
        return pdfFontName switch
        {
            "Helvetica" => "F1",
            "Helvetica-Bold" => "F2",
            "Helvetica-Oblique" => "F3",
            "Helvetica-BoldOblique" => "F4",
            "Courier" => "F5",
            "Courier-Bold" => "F6",
            "Courier-Oblique" => "F7",
            "Courier-BoldOblique" => "F8",
            "Times-Roman" => "F9",
            "Times-Bold" => "F10",
            "Times-Italic" => "F11",
            "Times-BoldItalic" => "F12",
            _ => "F1",
        };
    }

    /// <summary>Builds the /Font resource dictionary for all used fonts.</summary>
    /// <returns>PDF font dictionary string.</returns>
    internal string BuildFontResources(string customFontEntries = "")
    {
        if (_usedFonts.Count == 0 && customFontEntries.Length == 0)
        {
            return string.Empty;
        }

        var sb = new StringBuilder();
        sb.Append("/Font <<");
        foreach (string fontName in _usedFonts)
        {
            string key = ToFontKey(fontName);
            sb.Append(CultureInfo.InvariantCulture, $" /{key} << /Type /Font /Subtype /Type1 /BaseFont /{fontName} /Encoding /WinAnsiEncoding >>");
        }

        if (customFontEntries.Length > 0)
        {
            if (_usedFonts.Count > 0)
            {
                sb.Append(' ');
            }
            sb.Append(customFontEntries);
        }

        sb.Append(" >>");
        return sb.ToString();
    }

    private static string F(float value) => value.ToString("F2", CultureInfo.InvariantCulture);

    private static string M(float value) => (Math.Abs(value) < 1e-5f ? 0f : value).ToString("0.#####", CultureInfo.InvariantCulture);

    private static string EscapePdfString(string s)
    {
        var sb = new StringBuilder(s.Length + 8);
        foreach (char c in s)
        {
            if (char.IsLowSurrogate(c))
            {
                continue;
            }

            switch (c)
            {
                case '(':
                    sb.Append("\\(");
                    break;
                case ')':
                    sb.Append("\\)");
                    break;
                case '\\':
                    sb.Append("\\\\");
                    break;
                default:
                    if (c >= 32 && c <= 126)
                    {
                        sb.Append(c);
                    }
                    else
                    {
                        int winAnsiCode = WinAnsiEncoding.MapToWinAnsi(c);
                        if (winAnsiCode >= 0)
                        {
                            sb.Append('\\');
                            sb.Append(Convert.ToString(winAnsiCode, 8).PadLeft(3, '0'));
                        }
                        else
                        {
                            sb.Append('?');
                        }
                    }
                    break;
            }
        }
        return sb.ToString();
    }
}

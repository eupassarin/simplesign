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

    /// <summary>Gets the set of PDF font names used in this content stream.</summary>
    public IReadOnlySet<string> UsedFonts => _usedFonts;

    /// <summary>Saves graphics state (q operator).</summary>
    public void SaveState()
    {
        _sb.Append("q\n");
    }

    /// <summary>Restores graphics state (Q operator).</summary>
    public void RestoreState()
    {
        _sb.Append("Q\n");
    }

    /// <summary>Sets the fill color (rg operator).</summary>
    /// <param name="color">The fill color.</param>
    public void SetFillColor(PdfColor color)
    {
        _sb.Append(CultureInfo.InvariantCulture, $"{F(color.R)} {F(color.G)} {F(color.B)} rg\n");
    }

    /// <summary>Sets the stroke color (RG operator).</summary>
    /// <param name="color">The stroke color.</param>
    public void SetStrokeColor(PdfColor color)
    {
        _sb.Append(CultureInfo.InvariantCulture, $"{F(color.R)} {F(color.G)} {F(color.B)} RG\n");
    }

    /// <summary>Sets the line width (w operator).</summary>
    /// <param name="width">Line width in points.</param>
    public void SetLineWidth(float width)
    {
        _sb.Append(CultureInfo.InvariantCulture, $"{F(width)} w\n");
    }

    /// <summary>Draws a filled rectangle.</summary>
    /// <param name="x">X position.</param>
    /// <param name="y">Y position (bottom-left).</param>
    /// <param name="width">Width.</param>
    /// <param name="height">Height.</param>
    public void FillRect(float x, float y, float width, float height)
    {
        _sb.Append(CultureInfo.InvariantCulture, $"{F(x)} {F(y)} {F(width)} {F(height)} re f\n");
    }

    /// <summary>Draws a stroked rectangle.</summary>
    /// <param name="x">X position.</param>
    /// <param name="y">Y position (bottom-left).</param>
    /// <param name="width">Width.</param>
    /// <param name="height">Height.</param>
    public void StrokeRect(float x, float y, float width, float height)
    {
        _sb.Append(CultureInfo.InvariantCulture, $"{F(x)} {F(y)} {F(width)} {F(height)} re S\n");
    }

    /// <summary>Draws a horizontal line.</summary>
    /// <param name="x1">Start X.</param>
    /// <param name="y">Y position.</param>
    /// <param name="x2">End X.</param>
    public void HorizontalLine(float x1, float y, float x2)
    {
        _sb.Append(CultureInfo.InvariantCulture, $"{F(x1)} {F(y)} m {F(x2)} {F(y)} l S\n");
    }

    /// <summary>Draws a vertical line.</summary>
    /// <param name="x">X position.</param>
    /// <param name="y1">Start Y.</param>
    /// <param name="y2">End Y.</param>
    public void VerticalLine(float x, float y1, float y2)
    {
        _sb.Append(CultureInfo.InvariantCulture, $"{F(x)} {F(y1)} m {F(x)} {F(y2)} l S\n");
    }

    /// <summary>Draws text at the specified position.</summary>
    /// <param name="text">Text to render.</param>
    /// <param name="x">X position.</param>
    /// <param name="y">Y position (baseline).</param>
    /// <param name="pdfFontName">PDF base font name.</param>
    /// <param name="fontSize">Font size in points.</param>
    /// <param name="color">Text color.</param>
    public void DrawText(string text, float x, float y, string pdfFontName, float fontSize, PdfColor color)
    {
        string fontKey = ToFontKey(pdfFontName);
        _usedFonts.Add(pdfFontName);

        SetFillColor(color);
        _sb.Append("BT\n");
        _sb.Append(CultureInfo.InvariantCulture, $"/{fontKey} {F(fontSize)} Tf\n");
        _sb.Append(CultureInfo.InvariantCulture, $"{F(x)} {F(y)} Td\n");
        _sb.Append(CultureInfo.InvariantCulture, $"({EscapePdfString(text)}) Tj\n");
        _sb.Append("ET\n");
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
    public void AppendRaw(string content)
    {
        _sb.Append(content);
    }

    /// <summary>Gets the content stream bytes.</summary>
    /// <returns>ASCII-encoded content stream.</returns>
    public byte[] ToBytes()
    {
        return Encoding.ASCII.GetBytes(_sb.ToString());
    }

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
    internal string BuildFontResources()
    {
        if (_usedFonts.Count == 0)
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

        sb.Append(" >>");
        return sb.ToString();
    }

    private static string F(float value)
    {
        return value.ToString("F2", CultureInfo.InvariantCulture);
    }

    private static string EscapePdfString(string s)
    {
        var sb = new StringBuilder(s.Length + 8);
        foreach (char c in s)
        {
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

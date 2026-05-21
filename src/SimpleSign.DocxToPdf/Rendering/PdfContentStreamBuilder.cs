using System.Globalization;
using System.Text;

namespace SimpleSign.DocxToPdf.Rendering;

/// <summary>Builds PDF content stream operators for page rendering.</summary>
internal sealed class PdfContentStreamBuilder
{
    private readonly StringBuilder _sb = new();

    /// <summary>Begins a text block (BT operator).</summary>
    public void BeginText() => _sb.AppendLine("BT");

    /// <summary>Ends a text block (ET operator).</summary>
    public void EndText() => _sb.AppendLine("ET");

    /// <summary>Sets the font and size (Tf operator).</summary>
    /// <param name="fontName">The PDF font resource name.</param>
    /// <param name="size">The font size in points.</param>
    public void SetFont(string fontName, float size) =>
        _sb.AppendLine(CultureInfo.InvariantCulture, $"/{fontName} {size:F2} Tf");

    /// <summary>Sets the text position (Td operator).</summary>
    /// <param name="x">The X offset.</param>
    /// <param name="y">The Y offset.</param>
    public void SetTextPosition(float x, float y) =>
        _sb.AppendLine(CultureInfo.InvariantCulture, $"{x:F2} {y:F2} Td");

    /// <summary>Sets the text matrix (Tm operator).</summary>
    /// <param name="a">Scale X.</param>
    /// <param name="b">Skew X.</param>
    /// <param name="c">Skew Y.</param>
    /// <param name="d">Scale Y.</param>
    /// <param name="e">Translate X.</param>
    /// <param name="f">Translate Y.</param>
    public void SetTextMatrix(float a, float b, float c, float d, float e, float f) =>
        _sb.AppendLine(CultureInfo.InvariantCulture, $"{a:F4} {b:F4} {c:F4} {d:F4} {e:F2} {f:F2} Tm");

    /// <summary>Shows a text string (Tj operator).</summary>
    /// <param name="text">The text to show.</param>
    public void ShowText(string text) =>
        _sb.AppendLine(CultureInfo.InvariantCulture, $"({EscapePdfString(text)}) Tj");

    /// <summary>Sets the fill color in RGB (rg operator).</summary>
    /// <param name="r">Red component (0-1).</param>
    /// <param name="g">Green component (0-1).</param>
    /// <param name="b">Blue component (0-1).</param>
    public void SetFillColor(float r, float g, float b) =>
        _sb.AppendLine(CultureInfo.InvariantCulture, $"{r:F3} {g:F3} {b:F3} rg");

    /// <summary>Sets the stroke color in RGB (RG operator).</summary>
    /// <param name="r">Red component (0-1).</param>
    /// <param name="g">Green component (0-1).</param>
    /// <param name="b">Blue component (0-1).</param>
    public void SetStrokeColor(float r, float g, float b) =>
        _sb.AppendLine(CultureInfo.InvariantCulture, $"{r:F3} {g:F3} {b:F3} RG");

    /// <summary>Sets the line width (w operator).</summary>
    /// <param name="width">The line width in points.</param>
    public void SetLineWidth(float width) =>
        _sb.AppendLine(CultureInfo.InvariantCulture, $"{width:F2} w");

    /// <summary>Moves to a point (m operator).</summary>
    /// <param name="x">The X coordinate.</param>
    /// <param name="y">The Y coordinate.</param>
    public void MoveTo(float x, float y) =>
        _sb.AppendLine(CultureInfo.InvariantCulture, $"{x:F2} {y:F2} m");

    /// <summary>Draws a line to a point (l operator).</summary>
    /// <param name="x">The X coordinate.</param>
    /// <param name="y">The Y coordinate.</param>
    public void LineTo(float x, float y) =>
        _sb.AppendLine(CultureInfo.InvariantCulture, $"{x:F2} {y:F2} l");

    /// <summary>Strokes the current path (S operator).</summary>
    public void Stroke() => _sb.AppendLine("S");

    /// <summary>Draws a rectangle (re operator).</summary>
    /// <param name="x">The X coordinate.</param>
    /// <param name="y">The Y coordinate.</param>
    /// <param name="width">The width.</param>
    /// <param name="height">The height.</param>
    public void Rectangle(float x, float y, float width, float height) =>
        _sb.AppendLine(CultureInfo.InvariantCulture, $"{x:F2} {y:F2} {width:F2} {height:F2} re");

    /// <summary>Fills the current path (f operator).</summary>
    public void Fill() => _sb.AppendLine("f");

    /// <summary>Saves the graphics state (q operator).</summary>
    public void SaveState() => _sb.AppendLine("q");

    /// <summary>Restores the graphics state (Q operator).</summary>
    public void RestoreState() => _sb.AppendLine("Q");

    /// <summary>Applies a transformation matrix (cm operator).</summary>
    /// <param name="a">Scale X.</param>
    /// <param name="b">Skew X.</param>
    /// <param name="c">Skew Y.</param>
    /// <param name="d">Scale Y.</param>
    /// <param name="e">Translate X.</param>
    /// <param name="f">Translate Y.</param>
    public void ConcatMatrix(float a, float b, float c, float d, float e, float f) =>
        _sb.AppendLine(CultureInfo.InvariantCulture, $"{a:F4} {b:F4} {c:F4} {d:F4} {e:F2} {f:F2} cm");

    /// <summary>Paints an XObject (Do operator).</summary>
    /// <param name="name">The XObject resource name.</param>
    public void PaintXObject(string name) =>
        _sb.AppendLine($"/{name} Do");

    /// <summary>Returns the content stream as a string.</summary>
    /// <returns>The content stream string.</returns>
    public override string ToString() => _sb.ToString();

    /// <summary>Returns the content stream as UTF-8 bytes.</summary>
    /// <returns>The content stream bytes.</returns>
    public byte[] ToBytes() => Encoding.ASCII.GetBytes(_sb.ToString());

    private static string EscapePdfString(string text)
    {
        var sb = new StringBuilder(text.Length);
        foreach (char c in text)
        {
            switch (c)
            {
                case '(':
                    sb.Append(@"\(");
                    break;
                case ')':
                    sb.Append(@"\)");
                    break;
                case '\\':
                    sb.Append(@"\\");
                    break;
                default:
                    if (c < 32 || c > 126)
                    {
                        sb.Append($"\\{(int)c:o3}");
                    }
                    else
                    {
                        sb.Append(c);
                    }

                    break;
            }
        }

        return sb.ToString();
    }
}

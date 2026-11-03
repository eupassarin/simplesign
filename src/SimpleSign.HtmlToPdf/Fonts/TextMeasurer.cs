using System.Text;
using SimpleSign.HtmlToPdf.Parsing;

namespace SimpleSign.HtmlToPdf.Fonts;

/// <summary>
/// Measures text dimensions using standard PDF font metrics or registered TrueType metrics.
/// Used by the layout engine for word wrapping and text positioning.
/// </summary>
public static class TextMeasurer
{
    /// <summary>Measures the width of a text string in points.</summary>
    /// <param name="text">The text to measure.</param>
    /// <param name="fontFamily">CSS font family name.</param>
    /// <param name="fontSize">Font size in points.</param>
    /// <param name="bold">Whether text is bold.</param>
    /// <param name="italic">Whether text is italic.</param>
    /// <returns>Width of the text in points.</returns>
    public static float MeasureWidth(string text, string fontFamily, float fontSize, bool bold = false, bool italic = false) =>
        MeasureWidth(text, fontFamily, fontSize, bold, italic, null);

    internal static float MeasureWidth(string text, string fontFamily, float fontSize, bool bold, bool italic, FontCollection? fonts, float letterSpacing = 0, float wordSpacing = 0) =>
        MeasureResolved(text, FontCollection.Resolve(fonts, fontFamily, bold, italic), fonts, fontSize, letterSpacing, wordSpacing);

    /// <summary>Measures text using every typographic property of a computed style (family fallback list included).</summary>
    internal static float MeasureWidth(string text, ComputedStyle style, FontCollection? fonts) =>
        MeasureResolved(text, ResolveFont(style, fonts), fonts, style.FontSize, style.LetterSpacing, style.WordSpacing);

    /// <summary>Resolves the primary face for a computed style.</summary>
    internal static ResolvedFont ResolveFont(ComputedStyle style, FontCollection? fonts) =>
        FontCollection.Resolve(fonts, style.FontFamilies.Count > 0 ? style.FontFamilies : [style.FontFamily], style.IsBold, style.IsItalic);

    internal static float MeasureResolved(string text, ResolvedFont primary, FontCollection? fonts, float fontSize, float letterSpacing, float wordSpacing)
    {
        if (text.Length == 0)
        {
            return 0;
        }

        float width = 0;
        int runeCount = 0;
        int spaces = 0;
        foreach (var (segment, font) in FontCollection.SplitRuns(text, primary, fonts))
        {
            bool shaped = UsesShaping(font, segment, letterSpacing);
            if (shaped)
            {
                width += font.Embedded!.Shape(segment, rightToLeft: false).Advance * fontSize / font.Embedded.UnitsPerEm;
            }

            foreach (Rune rune in segment.EnumerateRunes())
            {
                if (!shaped)
                {
                    width += font.MeasureRune(rune, fontSize);
                }

                runeCount++;
                if (rune.Value == ' ')
                {
                    spaces++;
                }
            }
        }

        return width + (Math.Max(0, runeCount - 1) * letterSpacing) + (spaces * wordSpacing);
    }

    /// <summary>
    /// Returns true when a run is drawn through the OpenType shaper: always for complex scripts,
    /// and for other text when the font has layout tables and no letter-spacing is applied
    /// (letter-spacing disables ligatures, as in browsers).
    /// </summary>
    internal static bool UsesShaping(ResolvedFont font, string text, float letterSpacing)
    {
        if (font.Embedded is not { } embedded)
        {
            return false;
        }

        if (OpenType.TextShaper.DetectScript(text) != OpenType.ShapingScript.Default)
        {
            return true;
        }

        return letterSpacing == 0 && embedded.Shaper.HasLayout;
    }

    /// <summary>Measures the width of a single character in points.</summary>
    /// <param name="c">The character to measure.</param>
    /// <param name="fontFamily">CSS font family name.</param>
    /// <param name="fontSize">Font size in points.</param>
    /// <param name="bold">Whether text is bold.</param>
    /// <param name="italic">Whether text is italic.</param>
    /// <returns>Width of the character in points.</returns>
    public static float MeasureChar(char c, string fontFamily, float fontSize, bool bold = false, bool italic = false) =>
        MeasureChar(c, fontFamily, fontSize, bold, italic, null);

    internal static float MeasureChar(char c, string fontFamily, float fontSize, bool bold, bool italic, FontCollection? fonts, float letterSpacing = 0, float wordSpacing = 0) =>
        MeasureResolved(c.ToString(), FontCollection.Resolve(fonts, fontFamily, bold, italic), fonts, fontSize, 0, 0)
            + letterSpacing + (c == ' ' ? wordSpacing : 0);

    /// <summary>
    /// Finds how many characters fit within a given width.
    /// Returns the index of the last character that fits (exclusive).
    /// </summary>
    /// <param name="text">The text to measure.</param>
    /// <param name="startIndex">Index to start measuring from.</param>
    /// <param name="availableWidth">Maximum width in points.</param>
    /// <param name="fontFamily">CSS font family name.</param>
    /// <param name="fontSize">Font size in points.</param>
    /// <param name="bold">Whether text is bold.</param>
    /// <param name="italic">Whether text is italic.</param>
    /// <returns>The exclusive index of the last character that fits within the available width.</returns>
    public static int FitChars(string text, int startIndex, float availableWidth, string fontFamily, float fontSize, bool bold = false, bool italic = false) =>
        FitChars(text, startIndex, availableWidth, fontFamily, fontSize, bold, italic, null);

    internal static int FitChars(string text, int startIndex, float availableWidth, string fontFamily, float fontSize, bool bold, bool italic, FontCollection? fonts)
    {
        ArgumentNullException.ThrowIfNull(text);
        ResolvedFont primary = FontCollection.Resolve(fonts, fontFamily, bold, italic);
        float width = 0;
        int index = startIndex;
        foreach (var (segment, font) in FontCollection.SplitRuns(text[startIndex..], primary, fonts))
        {
            foreach (Rune rune in segment.EnumerateRunes())
            {
                float runeWidth = font.MeasureRune(rune, fontSize);
                if (width + runeWidth > availableWidth)
                {
                    return index;
                }

                width += runeWidth;
                index += rune.Utf16SequenceLength;
            }
        }

        return index;
    }

    /// <summary>
    /// Splits text into lines that fit within maxWidth.
    /// Breaks at word boundaries (spaces) when possible, character-level otherwise.
    /// </summary>
    /// <param name="text">The text to wrap.</param>
    /// <param name="maxWidth">Maximum line width in points.</param>
    /// <param name="fontFamily">CSS font family name.</param>
    /// <param name="fontSize">Font size in points.</param>
    /// <param name="bold">Whether text is bold.</param>
    /// <param name="italic">Whether text is italic.</param>
    /// <returns>A list of text lines that each fit within the specified width.</returns>
    public static List<string> WrapText(string text, float maxWidth, string fontFamily, float fontSize, bool bold = false, bool italic = false) =>
        WrapText(text, maxWidth, fontFamily, fontSize, bold, italic, null);

    internal static List<string> WrapText(string text, float maxWidth, string fontFamily, float fontSize, bool bold, bool italic, FontCollection? fonts, float letterSpacing = 0, float wordSpacing = 0)
    {
        ResolvedFont primary = FontCollection.Resolve(fonts, fontFamily, bold, italic);
        return WrapText(text, maxWidth, s => MeasureResolved(s, primary, fonts, fontSize, letterSpacing, wordSpacing));
    }

    private static List<string> WrapText(string text, float maxWidth, Func<string, float> measure)
    {
        var lines = new List<string>();
        if (string.IsNullOrEmpty(text))
        {
            return lines;
        }

        float spaceWidth = measure("a a") - measure("aa");
        foreach (string paragraph in text.Split('\n'))
        {
            string[] words = paragraph.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (words.Length == 0)
            {
                lines.Add(string.Empty);
                continue;
            }

            var line = new StringBuilder();
            float width = 0;
            foreach (string word in words)
            {
                float wordWidth = measure(word);
                float gap = line.Length == 0 ? 0 : spaceWidth;
                if (line.Length > 0 && width + gap + wordWidth > maxWidth)
                {
                    lines.Add(line.ToString());
                    line.Clear();
                    width = 0;
                    gap = 0;
                }

                if (wordWidth <= maxWidth || maxWidth <= 0)
                {
                    if (line.Length > 0)
                    {
                        line.Append(' ');
                    }

                    line.Append(word);
                    width += gap + wordWidth;
                    continue;
                }

                // Word wider than the line: break between characters.
                if (line.Length > 0)
                {
                    lines.Add(line.ToString());
                    line.Clear();
                    width = 0;
                }

                foreach (Rune rune in word.EnumerateRunes())
                {
                    string piece = rune.ToString();
                    float runeWidth = measure(piece);
                    if (line.Length > 0 && width + runeWidth > maxWidth)
                    {
                        lines.Add(line.ToString());
                        line.Clear();
                        width = 0;
                    }

                    line.Append(piece);
                    width += runeWidth;
                }
            }

            if (line.Length > 0)
            {
                lines.Add(line.ToString());
            }
        }

        return lines;
    }
}

namespace SimpleSign.HtmlToPdf.Fonts;

/// <summary>
/// Measures text dimensions using standard PDF font metrics.
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
    public static float MeasureWidth(string text, string fontFamily, float fontSize, bool bold = false, bool italic = false)
    {
        string pdfFont = StandardFonts.Resolve(fontFamily, bold, italic);
        float totalWidth = 0;
        foreach (char c in text)
        {
            totalWidth += FontMetrics.GetCharWidth(pdfFont, c) * fontSize / 1000f;
        }
        return totalWidth;
    }

    /// <summary>Measures the width of a single character in points.</summary>
    /// <param name="c">The character to measure.</param>
    /// <param name="fontFamily">CSS font family name.</param>
    /// <param name="fontSize">Font size in points.</param>
    /// <param name="bold">Whether text is bold.</param>
    /// <param name="italic">Whether text is italic.</param>
    /// <returns>Width of the character in points.</returns>
    public static float MeasureChar(char c, string fontFamily, float fontSize, bool bold = false, bool italic = false)
    {
        string pdfFont = StandardFonts.Resolve(fontFamily, bold, italic);
        return FontMetrics.GetCharWidth(pdfFont, c) * fontSize / 1000f;
    }

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
    public static int FitChars(string text, int startIndex, float availableWidth, string fontFamily, float fontSize, bool bold = false, bool italic = false)
    {
        string pdfFont = StandardFonts.Resolve(fontFamily, bold, italic);
        float width = 0;
        for (int i = startIndex; i < text.Length; i++)
        {
            float charWidth = FontMetrics.GetCharWidth(pdfFont, text[i]) * fontSize / 1000f;
            if (width + charWidth > availableWidth)
            {
                return i;
            }
            width += charWidth;
        }
        return text.Length;
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
    public static List<string> WrapText(string text, float maxWidth, string fontFamily, float fontSize, bool bold = false, bool italic = false)
    {
        var lines = new List<string>();
        if (string.IsNullOrEmpty(text))
        {
            return lines;
        }

        string pdfFont = StandardFonts.Resolve(fontFamily, bold, italic);
        float scale = fontSize / 1000f;

        foreach (string paragraph in text.Split('\n'))
        {
            if (paragraph.Length == 0)
            {
                lines.Add(string.Empty);
                continue;
            }

            WrapParagraph(paragraph, pdfFont, scale, maxWidth, lines);
        }

        return lines;
    }

    private static void WrapParagraph(string paragraph, string pdfFont, float scale, float maxWidth, List<string> lines)
    {
        string[] words = paragraph.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (words.Length == 0)
        {
            lines.Add(string.Empty);
            return;
        }

        float spaceWidth = FontMetrics.GetCharWidth(pdfFont, ' ') * scale;
        var currentLine = new System.Text.StringBuilder();
        float currentWidth = 0;

        foreach (string word in words)
        {
            float wordWidth = MeasureWordWidth(word, pdfFont, scale);

            if (currentLine.Length == 0)
            {
                if (wordWidth <= maxWidth)
                {
                    currentLine.Append(word);
                    currentWidth = wordWidth;
                }
                else
                {
                    BreakLongWord(word, pdfFont, scale, maxWidth, lines, ref currentLine, ref currentWidth);
                }
            }
            else if (currentWidth + spaceWidth + wordWidth <= maxWidth)
            {
                currentLine.Append(' ');
                currentLine.Append(word);
                currentWidth += spaceWidth + wordWidth;
            }
            else
            {
                lines.Add(currentLine.ToString());
                currentLine.Clear();
                currentWidth = 0;

                if (wordWidth <= maxWidth)
                {
                    currentLine.Append(word);
                    currentWidth = wordWidth;
                }
                else
                {
                    BreakLongWord(word, pdfFont, scale, maxWidth, lines, ref currentLine, ref currentWidth);
                }
            }
        }

        if (currentLine.Length > 0)
        {
            lines.Add(currentLine.ToString());
        }
    }

    private static void BreakLongWord(
        string word,
        string pdfFont,
        float scale,
        float maxWidth,
        List<string> lines,
        ref System.Text.StringBuilder currentLine,
        ref float currentWidth)
    {
        int pos = 0;
        while (pos < word.Length)
        {
            float lineWidth = 0;
            int start = pos;

            while (pos < word.Length)
            {
                float charWidth = FontMetrics.GetCharWidth(pdfFont, word[pos]) * scale;
                if (lineWidth + charWidth > maxWidth && pos > start)
                {
                    break;
                }
                lineWidth += charWidth;
                pos++;
            }

            if (pos < word.Length)
            {
                lines.Add(word[start..pos]);
            }
            else
            {
                // Last fragment — keep it as the current line for potential continuation
                currentLine.Append(word[start..pos]);
                currentWidth = lineWidth;
            }
        }
    }

    private static float MeasureWordWidth(string word, string pdfFont, float scale)
    {
        float width = 0;
        foreach (char c in word)
        {
            width += FontMetrics.GetCharWidth(pdfFont, c) * scale;
        }
        return width;
    }
}

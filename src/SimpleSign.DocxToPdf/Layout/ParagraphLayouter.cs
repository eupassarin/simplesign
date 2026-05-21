using SimpleSign.DocxToPdf.Fonts;
using SimpleSign.DocxToPdf.Model;

namespace SimpleSign.DocxToPdf.Layout;

/// <summary>Lays out a single paragraph into positioned text elements.</summary>
internal sealed class ParagraphLayouter
{
    private readonly FontResolver _fontResolver;
    private readonly StyleMap _styles;

    /// <summary>Initializes a new instance of the <see cref="ParagraphLayouter"/> class.</summary>
    /// <param name="fontResolver">The font resolver.</param>
    /// <param name="styles">The document style map.</param>
    public ParagraphLayouter(FontResolver fontResolver, StyleMap styles)
    {
        _fontResolver = fontResolver;
        _styles = styles;
    }

    /// <summary>Lays out a paragraph and returns positioned text elements with total height consumed.</summary>
    /// <param name="paragraph">The paragraph to layout.</param>
    /// <param name="x">The left X position.</param>
    /// <param name="y">The top Y position.</param>
    /// <param name="availableWidth">The available width for text.</param>
    /// <returns>A tuple of layout elements and total height used.</returns>
    public (List<LayoutElement> Elements, float Height) Layout(DocParagraph paragraph, float x, float y, float availableWidth)
    {
        var elements = new List<LayoutElement>();
        float currentY = y + paragraph.Spacing.BeforePt;
        float lineHeight = GetDefaultLineHeight(paragraph);

        if (paragraph.Runs.Count == 0 && paragraph.Images.Count == 0)
        {
            // Empty paragraph still takes up spacing
            float totalHeight = paragraph.Spacing.BeforePt + lineHeight + paragraph.Spacing.AfterPt;
            return (elements, totalHeight);
        }

        // Build word list from all runs
        List<WordSegment> words = BuildWordList(paragraph);

        // Line-breaking
        float leftIndent = paragraph.IndentLeftPt;
        float rightIndent = paragraph.IndentRightPt;
        float firstLineIndent = paragraph.IndentFirstLinePt;
        float lineWidth = availableWidth - leftIndent - rightIndent;
        bool isFirstLine = true;

        var currentLine = new List<WordSegment>();
        float currentLineWidth = 0f;

        foreach (WordSegment word in words)
        {
            float effectiveWidth = lineWidth - (isFirstLine ? firstLineIndent : 0f);
            if (effectiveWidth <= 0)
            {
                effectiveWidth = lineWidth;
            }

            if (currentLine.Count > 0 && currentLineWidth + word.Width > effectiveWidth)
            {
                // Emit current line
                float lineX = x + leftIndent + (isFirstLine ? firstLineIndent : 0f);
                EmitLine(elements, currentLine, lineX, currentY, effectiveWidth, paragraph.Alignment);
                currentY += lineHeight;
                currentLine.Clear();
                currentLineWidth = 0f;
                isFirstLine = false;
            }

            currentLine.Add(word);
            currentLineWidth += word.Width;
        }

        // Emit last line
        if (currentLine.Count > 0)
        {
            float effectiveWidth = lineWidth - (isFirstLine ? firstLineIndent : 0f);
            if (effectiveWidth <= 0)
            {
                effectiveWidth = lineWidth;
            }

            float lineX = x + leftIndent + (isFirstLine ? firstLineIndent : 0f);
            // Last line is never justified
            ParagraphAlignment align = paragraph.Alignment == ParagraphAlignment.Justify
                ? ParagraphAlignment.Left
                : paragraph.Alignment;
            EmitLine(elements, currentLine, lineX, currentY, effectiveWidth, align);
            currentY += lineHeight;
        }

        // Add images
        foreach (DocImage image in paragraph.Images)
        {
            elements.Add(new LayoutImage
            {
                X = x + leftIndent,
                Y = currentY,
                Width = image.WidthPt,
                Height = image.HeightPt,
                Data = [],
                Format = "jpeg"
            });
            currentY += image.HeightPt;
        }

        float totalHeightUsed = currentY - y + paragraph.Spacing.AfterPt;
        return (elements, totalHeightUsed);
    }

    private List<WordSegment> BuildWordList(DocParagraph paragraph)
    {
        var words = new List<WordSegment>();

        foreach (DocRun run in paragraph.Runs)
        {
            float fontSize = run.SizeHalfPoints > 0
                ? run.SizePt
                : _styles.DefaultFontSizeHalfPoints / 2f;
            string fontName = run.FontName ?? _styles.DefaultFontName;
            string text = run.AllCaps ? run.Text.ToUpperInvariant() : run.Text;

            // Split on spaces but keep space with preceding word
            string[] parts = text.Split(' ');
            for (int i = 0; i < parts.Length; i++)
            {
                string wordText = i < parts.Length - 1 ? parts[i] + " " : parts[i];
                if (string.IsNullOrEmpty(wordText))
                {
                    wordText = " ";
                }

                float width = MeasureText(wordText, fontName, fontSize);
                words.Add(new WordSegment
                {
                    Text = wordText,
                    Width = width,
                    FontName = fontName,
                    FontSizePt = fontSize,
                    Bold = run.Bold,
                    Italic = run.Italic,
                    Color = run.Color ?? "000000",
                    Underline = run.Underline,
                    Strikethrough = run.Strikethrough
                });
            }
        }

        return words;
    }

    private float MeasureText(string text, string fontName, float fontSize)
    {
        TrueTypeParser? font = _fontResolver.Resolve(fontName);
        if (font is null)
        {
            // Fallback: approximate width
            return text.Length * fontSize * 0.5f;
        }

        int designUnits = font.MeasureString(text);
        return designUnits * fontSize / font.UnitsPerEm;
    }

    private static void EmitLine(
        List<LayoutElement> elements,
        List<WordSegment> words,
        float x,
        float y,
        float availableWidth,
        ParagraphAlignment alignment)
    {
        float totalWidth = words.Sum(w => w.Width);
        float startX = alignment switch
        {
            ParagraphAlignment.Center => x + (availableWidth - totalWidth) / 2f,
            ParagraphAlignment.Right => x + availableWidth - totalWidth,
            _ => x
        };

        float extraSpace = 0f;
        if (alignment == ParagraphAlignment.Justify && words.Count > 1)
        {
            extraSpace = (availableWidth - totalWidth) / (words.Count - 1);
        }

        float currentX = startX;
        foreach (WordSegment word in words)
        {
            elements.Add(new LayoutText
            {
                X = currentX,
                Y = y,
                Width = word.Width,
                Height = word.FontSizePt,
                Text = word.Text,
                FontName = word.FontName,
                FontSizePt = word.FontSizePt,
                Bold = word.Bold,
                Italic = word.Italic,
                Color = word.Color,
                Underline = word.Underline,
                Strikethrough = word.Strikethrough
            });
            currentX += word.Width + extraSpace;
        }
    }

    private float GetDefaultLineHeight(DocParagraph paragraph)
    {
        if (paragraph.Spacing.LinePt > 0)
        {
            return paragraph.Spacing.LinePt;
        }

        float maxFontSize = _styles.DefaultFontSizeHalfPoints / 2f;
        foreach (DocRun run in paragraph.Runs)
        {
            float sz = run.SizeHalfPoints > 0 ? run.SizePt : maxFontSize;
            if (sz > maxFontSize)
            {
                maxFontSize = sz;
            }
        }

        return maxFontSize * 1.15f; // Default ~115% line spacing
    }

    private sealed class WordSegment
    {
        public string Text { get; init; } = string.Empty;
        public float Width { get; init; }
        public string FontName { get; init; } = "Calibri";
        public float FontSizePt { get; init; } = 12f;
        public bool Bold { get; init; }
        public bool Italic { get; init; }
        public string Color { get; init; } = "000000";
        public UnderlineType Underline { get; init; }
        public bool Strikethrough { get; init; }
    }
}

// Licensed to SimpleSign under the MIT License.

using SimpleSign.HtmlToPdf.Fonts;
using SimpleSign.HtmlToPdf.Parsing;
using SimpleSign.HtmlToPdf.Rendering;

namespace SimpleSign.HtmlToPdf.Layout;

/// <summary>
/// Lays out a styled DOM tree into positioned boxes across pages.
/// Handles block flow, inline text wrapping, page breaking, and list markers.
/// </summary>
public sealed class LayoutEngine
{
    private readonly PageSettings _settings;
    private readonly List<PageBox> _pages = [];
    private readonly List<BookmarkEntry> _bookmarks = [];
    private PageBox _currentPage;
    private float _cursorY;
    private float _lastMarginBottom;

    /// <summary>
    /// Initializes a new instance of the <see cref="LayoutEngine"/> class.
    /// </summary>
    /// <param name="settings">Page settings for layout.</param>
    public LayoutEngine(PageSettings settings)
    {
        _settings = settings;
        _currentPage = CreateNewPage();
    }

    /// <summary>
    /// Lays out the DOM tree into pages.
    /// </summary>
    /// <param name="root">Root node of the styled DOM tree.</param>
    /// <returns>Layout result with positioned pages and boxes.</returns>
    public LayoutResult Layout(HtmlNode root)
    {
        LayoutBlockChildren(root, _settings.ContentWidth, _settings.Margins.Left);
        FlushCurrentPage();

        var result = new LayoutResult { Settings = _settings };
        result.Pages.AddRange(_pages);
        result.Bookmarks.AddRange(_bookmarks);
        return result;
    }

    private void LayoutBlockChildren(HtmlNode parent, float availableWidth, float offsetX)
    {
        int listCounter = 0;
        bool inOrderedList = parent.Tag is "ol";

        for (int i = 0; i < parent.Children.Count; i++)
        {
            HtmlNode child = parent.Children[i];
            ComputedStyle style = child.ComputedStyle ?? new ComputedStyle();

            if (style.Display == DisplayType.None)
            {
                continue;
            }

            if (child.NodeType == HtmlNodeType.Text)
            {
                // Collect consecutive inline content starting from this text node
                int end = CollectInlineSpan(parent, i);
                LayoutInlineContent(parent, i, end, availableWidth, offsetX);
                i = end - 1;
                continue;
            }

            if (style.Display == DisplayType.Inline)
            {
                // Handle <img> as block-level even though it's inline
                if (child.Tag is "img")
                {
                    LayoutImage(child, availableWidth, offsetX);
                    continue;
                }

                int end = CollectInlineSpan(parent, i);
                LayoutInlineContent(parent, i, end, availableWidth, offsetX);
                i = end - 1;
                continue;
            }

            if (style.Display == DisplayType.ListItem)
            {
                listCounter++;
                string marker = inOrderedList
                    ? $"{listCounter}."
                    : "\u2022";
                LayoutListItem(child, availableWidth, offsetX, marker);
                continue;
            }

            if (child.Tag is "br")
            {
                float lineHeight = style.FontSize * style.LineHeight;
                EnsureSpace(lineHeight);
                _cursorY += lineHeight;
                continue;
            }

            if (child.Tag is "hr")
            {
                LayoutHorizontalRule(child, availableWidth, offsetX);
                continue;
            }

            if (child.Tag is "img")
            {
                LayoutImage(child, availableWidth, offsetX);
                continue;
            }

            if (child.Tag is "table" || style.Display == DisplayType.Table)
            {
                if (style.PageBreakBefore == PageBreak.Always)
                {
                    StartNewPage();
                }

                float tableHeight = TableLayoutHelper.LayoutTable(
                    child,
                    availableWidth,
                    offsetX,
                    _cursorY,
                    box => _currentPage.Boxes.Add(box));
                _cursorY += tableHeight;

                if (style.PageBreakAfter == PageBreak.Always)
                {
                    StartNewPage();
                }

                continue;
            }

            if (style.PageBreakBefore == PageBreak.Always)
            {
                StartNewPage();
            }

            LayoutBlock(child, availableWidth, offsetX);

            if (style.PageBreakAfter == PageBreak.Always)
            {
                StartNewPage();
            }
        }
    }

    private void LayoutBlock(HtmlNode node, float availableWidth, float offsetX)
    {
        ComputedStyle style = node.ComputedStyle ?? new ComputedStyle();

        // Margin collapsing: collapse top margin with previous bottom margin
        float marginTop = style.Margin.Top;
        float collapsedSpacing = Math.Max(marginTop, _lastMarginBottom) - _lastMarginBottom;
        _cursorY += collapsedSpacing;
        _lastMarginBottom = 0;

        float borderLeft = style.Border.LeftWidth;
        float borderRight = style.Border.RightWidth;
        float borderTop = style.Border.TopWidth;
        float borderBottom = style.Border.BottomWidth;

        float paddingLeft = style.Padding.Left;
        float paddingRight = style.Padding.Right;
        float paddingTop = style.Padding.Top;
        float paddingBottom = style.Padding.Bottom;

        float marginLeft = style.Margin.Left;
        float marginRight = style.Margin.Right;

        float contentWidth = availableWidth - marginLeft - marginRight - borderLeft - borderRight - paddingLeft - paddingRight;
        if (style.Width is float explicitWidth)
        {
            if (explicitWidth < 0)
            {
                // Negative values represent percentages (e.g., -50 = 50%)
                float resolvedWidth = availableWidth * (-explicitWidth / 100f);
                contentWidth = Math.Min(contentWidth, resolvedWidth - marginLeft - marginRight - borderLeft - borderRight - paddingLeft - paddingRight);
            }
            else
            {
                contentWidth = Math.Min(contentWidth, explicitWidth);
            }
        }

        if (style.MaxWidth is float maxWidth)
        {
            if (maxWidth < 0)
            {
                float resolvedMax = availableWidth * (-maxWidth / 100f);
                contentWidth = Math.Min(contentWidth, resolvedMax);
            }
            else
            {
                contentWidth = Math.Min(contentWidth, maxWidth);
            }
        }

        contentWidth = Math.Max(contentWidth, 0);

        float boxX = offsetX + marginLeft;
        float boxStartY = _cursorY;

        // Advance past border+padding top
        _cursorY += borderTop + paddingTop;

        float contentOffsetX = boxX + borderLeft + paddingLeft;

        // Add block box BEFORE children so background renders behind text content
        var box = new LayoutBox
        {
            Type = LayoutBoxType.Block,
            Node = node,
            Style = style,
            X = boxX,
            Y = boxStartY,
            Width = contentWidth,
            Height = 0, // Updated after children layout
        };

        // Track the page before children layout to detect page breaks
        PageBox startPage = _currentPage;
        startPage.Boxes.Add(box);

        // Layout children inside this block
        float childStartY = _cursorY;
        LayoutBlockChildren(node, contentWidth, contentOffsetX);

        float contentHeight = _cursorY - childStartY;
        if (style.Height is float explicitHeight)
        {
            contentHeight = Math.Max(contentHeight, explicitHeight);
            _cursorY = childStartY + contentHeight;
        }

        _cursorY += paddingBottom + borderBottom;

        if (_currentPage == startPage)
        {
            // No page break — update the block box height
            box.Height = contentHeight;
        }
        else
        {
            // Page break occurred during children layout.
            // Cap the start page box to remaining space
            float startPageRemaining = _settings.ContentHeight - boxStartY;
            box.Height = Math.Max(startPageRemaining, 0);

            // Add a continuation block box on the current page (before any subsequent content)
            var continuationBox = new LayoutBox
            {
                Type = LayoutBoxType.Block,
                Node = node,
                Style = style,
                X = boxX,
                Y = 0,
                Width = contentWidth,
                Height = _cursorY,
            };

            // Insert at position 0 so background renders behind text on this page too
            _currentPage.Boxes.Insert(0, continuationBox);
        }

        // Collect bookmark for headings (use page index from before children layout)
        if (node.Tag is "h1" or "h2" or "h3" or "h4" or "h5" or "h6")
        {
            int bookmarkPage = _pages.IndexOf(startPage);
            if (bookmarkPage < 0)
            {
                // startPage is still the current (unflushed) page; its index will be _pages.Count
                bookmarkPage = _pages.Count;
            }
            int level = node.Tag[1] - '0';
            string title = GetTextContent(node);
            if (title.Length > 0)
            {
                _bookmarks.Add(new BookmarkEntry(title, level, bookmarkPage, boxStartY));
            }
        }

        // Set margin-bottom for collapsing with next sibling
        _lastMarginBottom = style.Margin.Bottom;
        _cursorY += style.Margin.Bottom;
    }

    private void LayoutInlineContent(HtmlNode parent, int startIdx, int endIdx, float availableWidth, float offsetX)
    {
        // Collect text runs from consecutive inline nodes
        var runs = new List<TextRun>();
        for (int i = startIdx; i < endIdx; i++)
        {
            CollectTextRuns(parent.Children[i], runs);
        }

        if (runs.Count == 0)
        {
            return;
        }

        // Build lines by word-wrapping runs
        var lines = WrapRunsIntoLines(runs, availableWidth);

        ComputedStyle parentStyle = parent.ComputedStyle ?? new ComputedStyle();

        foreach (LayoutLine line in lines)
        {
            float lineHeight = line.Height;
            EnsureSpace(lineHeight);

            // Apply text-align
            float lineX = offsetX;
            float extraSpace = availableWidth - line.Width;
            if (parentStyle.TextAlign == TextAlign.Center)
            {
                lineX += extraSpace / 2;
            }
            else if (parentStyle.TextAlign == TextAlign.Right)
            {
                lineX += extraSpace;
            }

            foreach (LayoutBox box in line.Boxes)
            {
                box.X += lineX;
                box.Y = _cursorY;
                _currentPage.Boxes.Add(box);
            }

            _cursorY += lineHeight;
        }
    }

    private void LayoutListItem(HtmlNode node, float availableWidth, float offsetX, string marker)
    {
        ComputedStyle style = node.ComputedStyle ?? new ComputedStyle();

        float marginTop = style.Margin.Top;
        float collapsedSpacing = Math.Max(marginTop, _lastMarginBottom) - _lastMarginBottom;
        _cursorY += collapsedSpacing;
        _lastMarginBottom = 0;

        float paddingLeft = style.Padding.Left;
        float contentWidth = availableWidth - style.Margin.Left - style.Margin.Right - paddingLeft;
        contentWidth = Math.Max(contentWidth, 0);

        // Position marker
        float markerWidth = TextMeasurer.MeasureWidth(marker + " ", style.FontFamily, style.FontSize, style.IsBold, style.IsItalic);
        float markerX = offsetX + style.Margin.Left + paddingLeft - markerWidth;

        var markerBox = new LayoutBox
        {
            Type = LayoutBoxType.ListMarker,
            Node = node,
            Style = style,
            X = markerX,
            Y = _cursorY,
            Width = markerWidth,
            Height = style.FontSize * style.LineHeight,
            Marker = marker,
        };
        _currentPage.Boxes.Add(markerBox);

        // Layout children in the content area
        float contentX = offsetX + style.Margin.Left + paddingLeft;
        LayoutBlockChildren(node, contentWidth, contentX);

        _lastMarginBottom = style.Margin.Bottom;
        _cursorY += style.Margin.Bottom;
    }

    private void LayoutHorizontalRule(HtmlNode node, float availableWidth, float offsetX)
    {
        ComputedStyle style = node.ComputedStyle ?? new ComputedStyle();
        float hrHeight = style.Border.TopWidth > 0 ? style.Border.TopWidth : 1;
        float totalHeight = style.Margin.Top + hrHeight + style.Margin.Bottom;

        EnsureSpace(totalHeight);
        _cursorY += style.Margin.Top;

        var box = new LayoutBox
        {
            Type = LayoutBoxType.HorizontalRule,
            Node = node,
            Style = style,
            X = offsetX,
            Y = _cursorY,
            Width = availableWidth,
            Height = hrHeight,
        };
        _currentPage.Boxes.Add(box);

        _cursorY += hrHeight + style.Margin.Bottom;
        _lastMarginBottom = 0;
    }

    private void LayoutImage(HtmlNode node, float availableWidth, float offsetX)
    {
        ComputedStyle style = node.ComputedStyle ?? new ComputedStyle();
        node.Attributes.TryGetValue("src", out string? src);

        ImageData? img = ImageData.Parse(src);
        if (img is null || img.Width == 0 || img.Height == 0)
        {
            // Fallback: render alt text if image can't be parsed
            if (node.Attributes.TryGetValue("alt", out string? alt) && alt.Length > 0)
            {
                float fontSize = style.FontSize;
                float lineHeight = fontSize * style.LineHeight;
                EnsureSpace(lineHeight);
                var altBox = new LayoutBox
                {
                    Type = LayoutBoxType.InlineText,
                    Node = node,
                    Style = new ComputedStyle
                    {
                        FontSize = fontSize,
                        IsItalic = true,
                        Color = new PdfColor(0.5f, 0.5f, 0.5f),
                    },
                    X = offsetX,
                    Y = _cursorY,
                    Width = availableWidth,
                    Height = lineHeight,
                    Text = $"[{alt}]",
                };
                _currentPage.Boxes.Add(altBox);
                _cursorY += lineHeight;
            }

            return;
        }

        // Determine display size in points (default: 1 px = 0.75 pt)
        const float PxToPt = 0.75f;
        float intrinsicW = img.Width * PxToPt;
        float intrinsicH = img.Height * PxToPt;
        float aspectRatio = intrinsicW / intrinsicH;

        // Apply CSS width/height if specified
        float displayW = intrinsicW;
        float displayH = intrinsicH;

        if (style.Width is float cssW && cssW > 0)
        {
            displayW = cssW;
            displayH = displayW / aspectRatio;
        }
        else if (style.Width is float cssWPct && cssWPct < 0)
        {
            displayW = availableWidth * (-cssWPct / 100f);
            displayH = displayW / aspectRatio;
        }

        if (style.Height is float cssH && cssH > 0)
        {
            displayH = cssH;
            if (style.Width is null)
            {
                displayW = displayH * aspectRatio;
            }
        }

        // Also check HTML width/height attributes
        if (style.Width is null && node.Attributes.TryGetValue("width", out string? widthAttr) &&
            float.TryParse(widthAttr, System.Globalization.CultureInfo.InvariantCulture, out float attrW))
        {
            displayW = attrW * PxToPt;
            displayH = displayW / aspectRatio;
        }

        if (style.Height is null && node.Attributes.TryGetValue("height", out string? heightAttr) &&
            float.TryParse(heightAttr, System.Globalization.CultureInfo.InvariantCulture, out float attrH))
        {
            displayH = attrH * PxToPt;
            if (style.Width is null && !node.Attributes.ContainsKey("width"))
            {
                displayW = displayH * aspectRatio;
            }
        }

        // Constrain to available width
        if (displayW > availableWidth)
        {
            displayW = availableWidth;
            displayH = displayW / aspectRatio;
        }

        // Apply max-width
        if (style.MaxWidth is float mw && mw > 0 && displayW > mw)
        {
            displayW = mw;
            displayH = displayW / aspectRatio;
        }

        float marginTop = style.Margin.Top;
        float marginBottom = style.Margin.Bottom;
        float totalHeight = marginTop + displayH + marginBottom;

        EnsureSpace(totalHeight);
        _cursorY += marginTop;

        // Center block images by default, or use text-align from parent
        float imgX = offsetX;
        ComputedStyle? parentStyle = node.Parent?.ComputedStyle;
        if (parentStyle?.TextAlign == TextAlign.Center)
        {
            imgX = offsetX + (availableWidth - displayW) / 2;
        }
        else if (parentStyle?.TextAlign == TextAlign.Right)
        {
            imgX = offsetX + availableWidth - displayW;
        }

        var box = new LayoutBox
        {
            Type = LayoutBoxType.Image,
            Node = node,
            Style = style,
            X = imgX,
            Y = _cursorY,
            Width = displayW,
            Height = displayH,
            ImageSource = src,
        };
        _currentPage.Boxes.Add(box);

        _cursorY += displayH + marginBottom;
        _lastMarginBottom = 0;
    }

    private static bool IsInsidePre(HtmlNode node)
    {
        HtmlNode? current = node.Parent;
        while (current is not null)
        {
            if (current.Tag is "pre")
            {
                return true;
            }

            current = current.Parent;
        }

        return false;
    }

    private static void CollectTextRuns(HtmlNode node, List<TextRun> runs)
    {
        if (node.NodeType == HtmlNodeType.Text)
        {
            bool inPre = IsInsidePre(node);
            string rawText = node.Text ?? string.Empty;
            string text = inPre ? rawText : NormalizeWhitespace(rawText);
            if (text.Length > 0)
            {
                ComputedStyle style = node.ComputedStyle ?? node.Parent?.ComputedStyle ?? new ComputedStyle();
                string? linkUrl = FindAncestorLink(node);

                if (inPre)
                {
                    // Split pre-formatted text on newlines so WrapRunsIntoLines handles line breaks
                    string[] lines = text.Split('\n');
                    for (int li = 0; li < lines.Length; li++)
                    {
                        if (li > 0)
                        {
                            runs.Add(new TextRun("\n", style));
                        }

                        string line = lines[li];
                        if (line.Length > 0)
                        {
                            runs.Add(new TextRun(line, style, linkUrl));
                        }
                    }
                }
                else
                {
                    runs.Add(new TextRun(text, style, linkUrl));
                }
            }

            return;
        }

        if (node.NodeType == HtmlNodeType.Element)
        {
            if (node.Tag is "br")
            {
                runs.Add(new TextRun("\n", node.ComputedStyle ?? new ComputedStyle()));
                return;
            }

            foreach (HtmlNode child in node.Children)
            {
                CollectTextRuns(child, runs);
            }
        }
    }

    private static string? FindAncestorLink(HtmlNode node)
    {
        HtmlNode? current = node.Parent;
        while (current is not null)
        {
            if (current.Tag is "a" && current.Attributes.TryGetValue("href", out string? href))
            {
                return href;
            }

            current = current.Parent;
        }

        return null;
    }

    private static string GetTextContent(HtmlNode node)
    {
        if (node.NodeType == HtmlNodeType.Text)
        {
            return node.Text ?? string.Empty;
        }

        var sb = new System.Text.StringBuilder();
        foreach (HtmlNode child in node.Children)
        {
            string childText = GetTextContent(child);
            if (childText.Length > 0)
            {
                if (sb.Length > 0 && sb[sb.Length - 1] != ' ')
                {
                    sb.Append(' ');
                }

                sb.Append(childText);
            }
        }

        return sb.ToString().Trim();
    }

    private static List<LayoutLine> WrapRunsIntoLines(List<TextRun> runs, float maxWidth)
    {
        var lines = new List<LayoutLine>();
        var currentLine = new LayoutLine();
        float cursorX = 0;
        bool pendingSpace = false;

        foreach (TextRun run in runs)
        {
            if (run.Text == "\n")
            {
                FinalizeLine(currentLine, lines);
                currentLine = new LayoutLine();
                cursorX = 0;
                pendingSpace = false;
                continue;
            }

            string[] words = run.Text.Split(' ');
            bool needsSpaceBefore = false;

            for (int wi = 0; wi < words.Length; wi++)
            {
                string word = words[wi];
                if (word.Length == 0)
                {
                    if (wi < words.Length - 1)
                    {
                        // Empty word from split = space delimiter (leading or mid-run space)
                        needsSpaceBefore = true;
                    }
                    else
                    {
                        // Trailing empty string from "text " split → carry space to next run
                        if (cursorX > 0 || needsSpaceBefore)
                        {
                            pendingSpace = true;
                        }
                    }

                    continue;
                }

                // Calculate space before this word
                float spaceWidth = 0;
                if (cursorX > 0 && (needsSpaceBefore || pendingSpace))
                {
                    spaceWidth = TextMeasurer.MeasureChar(' ', run.Style.FontFamily, run.Style.FontSize, run.Style.IsBold, run.Style.IsItalic);
                }

                needsSpaceBefore = true;
                pendingSpace = false;

                float wordWidth = TextMeasurer.MeasureWidth(word, run.Style.FontFamily, run.Style.FontSize, run.Style.IsBold, run.Style.IsItalic);

                // Word fits on current line?
                if (cursorX + spaceWidth + wordWidth <= maxWidth || cursorX == 0)
                {
                    cursorX += spaceWidth;

                    var box = new LayoutBox
                    {
                        Type = LayoutBoxType.InlineText,
                        Style = run.Style,
                        X = cursorX,
                        Y = 0,
                        Width = wordWidth,
                        Height = run.Style.FontSize * run.Style.LineHeight,
                        Text = word,
                        LinkUrl = run.LinkUrl,
                    };
                    currentLine.Boxes.Add(box);
                    cursorX += wordWidth;
                    currentLine.Width = cursorX;
                    currentLine.Height = Math.Max(currentLine.Height, box.Height);
                }
                else
                {
                    // Start new line
                    FinalizeLine(currentLine, lines);
                    currentLine = new LayoutLine();
                    cursorX = 0;
                    pendingSpace = false;

                    var box = new LayoutBox
                    {
                        Type = LayoutBoxType.InlineText,
                        Style = run.Style,
                        X = 0,
                        Y = 0,
                        Width = wordWidth,
                        Height = run.Style.FontSize * run.Style.LineHeight,
                        Text = word,
                        LinkUrl = run.LinkUrl,
                    };
                    currentLine.Boxes.Add(box);
                    cursorX = wordWidth;
                    currentLine.Width = cursorX;
                    currentLine.Height = Math.Max(currentLine.Height, box.Height);
                }
            }
        }

        if (currentLine.Boxes.Count > 0)
        {
            FinalizeLine(currentLine, lines);
        }

        return lines;
    }

    private static void FinalizeLine(LayoutLine line, List<LayoutLine> lines)
    {
        if (line.Boxes.Count == 0)
        {
            // Empty line (just a line break) — use default line height
            line.Height = 12f * 1.4f;
        }

        lines.Add(line);
    }

    private static int CollectInlineSpan(HtmlNode parent, int startIdx)
    {
        int i = startIdx;
        while (i < parent.Children.Count)
        {
            HtmlNode child = parent.Children[i];
            if (child.NodeType == HtmlNodeType.Text)
            {
                i++;
                continue;
            }

            ComputedStyle style = child.ComputedStyle ?? new ComputedStyle();
            if (style.Display == DisplayType.Inline)
            {
                i++;
                continue;
            }

            break;
        }

        return Math.Max(i, startIdx + 1);
    }

    private static string NormalizeWhitespace(string text)
    {
        // Collapse runs of whitespace into single spaces
        var sb = new System.Text.StringBuilder(text.Length);
        bool lastWasSpace = false;

        foreach (char c in text)
        {
            if (char.IsWhiteSpace(c))
            {
                if (!lastWasSpace)
                {
                    sb.Append(' ');
                    lastWasSpace = true;
                }
            }
            else
            {
                sb.Append(c);
                lastWasSpace = false;
            }
        }

        return sb.ToString();
    }

    private void EnsureSpace(float height)
    {
        if (_cursorY + height > _settings.ContentHeight)
        {
            StartNewPage();
        }
    }

    private void StartNewPage()
    {
        FlushCurrentPage();
        _currentPage = CreateNewPage();
    }

    private void FlushCurrentPage()
    {
        if (_currentPage.Boxes.Count > 0)
        {
            _pages.Add(_currentPage);
        }
    }

    private PageBox CreateNewPage()
    {
        _cursorY = 0;
        _lastMarginBottom = 0;
        return new PageBox
        {
            PageNumber = _pages.Count + 1,
            Settings = _settings,
        };
    }
}

/// <summary>A segment of text with uniform styling for inline layout.</summary>
/// <param name="Text">The text content.</param>
/// <param name="Style">The computed style.</param>
/// <param name="LinkUrl">Optional hyperlink URL from ancestor &lt;a&gt; element.</param>
internal readonly record struct TextRun(string Text, ComputedStyle Style, string? LinkUrl = null);

/// <summary>A single line of laid-out inline content.</summary>
internal sealed class LayoutLine
{
    /// <summary>Gets or sets the line Y position.</summary>
    public float Y { get; set; }

    /// <summary>Gets or sets the total line width.</summary>
    public float Width { get; set; }

    /// <summary>Gets or sets the line height.</summary>
    public float Height { get; set; }

    /// <summary>Gets the inline boxes on this line.</summary>
    public List<LayoutBox> Boxes { get; } = [];
}

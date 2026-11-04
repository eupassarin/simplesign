// Licensed to SimpleSign under the MIT License.

using System.Globalization;
using System.Text;
using SimpleSign.HtmlToPdf.Fonts;
using SimpleSign.HtmlToPdf.Parsing;
using SimpleSign.HtmlToPdf.Rendering;

namespace SimpleSign.HtmlToPdf.Layout;

/// <summary>Inline formatting: line building, alignment, justification, atomic inlines and list markers.</summary>
public sealed partial class LayoutEngine
{
    private const float AscentRatio = 0.8f;
    private const float WrapTolerance = 0.05f;

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
            if (style.Display == DisplayType.None || IsInlineLevel(child, style))
            {
                i++;
                continue;
            }

            break;
        }

        return Math.Max(i, startIdx + 1);
    }

    private void LayoutInlineContent(HtmlNode parent, int startIdx, int endIdx, float availableWidth, float offsetX, bool firstContent)
    {
        ComputedStyle parentStyle = parent.ComputedStyle ?? new ComputedStyle();
        var items = new List<InlineItem>();
        var context = new InlineContext(null, null, availableWidth, offsetX);
        for (int i = startIdx; i < endIdx; i++)
        {
            CollectInlineItems(parent.Children[i], items, context);
        }

        if (items.Count == 0 || items.All(item => item.Kind == InlineKind.Text && item.Text.Trim().Length == 0 && item.Style.WhiteSpace is not (WhiteSpaceMode.Pre or WhiteSpaceMode.PreWrap)))
        {
            return;
        }

        float indent = _pendingIndent + (firstContent ? ResolvePercent(parentStyle.TextIndent, availableWidth) : 0);
        _pendingIndent = 0;

        List<LayoutLine> lines = WrapItems(items, parentStyle, availableWidth, offsetX, indent);
        HashSet<int> breaks = ComputeLineBreaks(lines, parentStyle);

        for (int index = 0; index < lines.Count; index++)
        {
            LayoutLine line = lines[index];
            if (breaks.Contains(index) && (CursorY > 0 || _currentPage.Boxes.Count > 0))
            {
                StartNewPage();
            }
            else
            {
                EnsureSpace(line.Height);
            }

            PlaceLine(line, parentStyle, isLastLine: index == lines.Count - 1);
            CursorY += line.Height;
        }

        _lastMarginBottom = 0;
    }

    /// <summary>Chooses the lines before which a page break happens, honoring orphans and widows.</summary>
    private HashSet<int> ComputeLineBreaks(List<LayoutLine> lines, ComputedStyle style)
    {
        var breaks = new HashSet<int>();
        if (IsIsolated || lines.Count == 0)
        {
            return breaks;
        }

        float pageHeight = _settings.ContentHeight;
        float y = CursorY;
        int start = 0;
        bool atTop = CursorY <= 0;
        int n = lines.Count;
        int orphans = Math.Max(1, style.Orphans);
        int widows = Math.Max(1, style.Widows);

        for (int i = 0; i < n; i++)
        {
            float h = lines[i].Height;
            if (y + h > pageHeight && !(i == start && atTop))
            {
                int b = i;
                if (n - b < widows)
                {
                    b = Math.Max(start + 1, n - widows);
                }

                if (b - start < orphans && start == 0 && !atTop)
                {
                    b = 0;
                }

                if (b <= start && !(start == 0 && b == 0 && !atTop))
                {
                    b = i;
                }

                breaks.Add(b);
                start = b;
                atTop = true;
                y = 0;
                for (int k = b; k < i; k++)
                {
                    y += lines[k].Height;
                }
            }

            y += h;
        }

        return breaks;
    }

    private void PlaceLine(LayoutLine line, ComputedStyle parentStyle, bool isLastLine)
    {
        float lineX = line.BandX;
        float extra = line.BandWidth - line.Width;
        float justifyGap = 0;
        if (!IsMeasuring && extra > 0)
        {
            TextAlign align = parentStyle.EffectiveTextAlign;
            if (align == TextAlign.Justify && (isLastLine || line.HardBreak))
            {
                align = parentStyle.Rtl ? TextAlign.Right : TextAlign.Left;
            }

            switch (align)
            {
                case TextAlign.Center:
                    lineX += extra / 2;
                    break;
                case TextAlign.Right:
                    lineX += extra;
                    break;
                case TextAlign.Justify when !isLastLine && !line.HardBreak:
                    int gaps = line.Entries.Count(e => e.SpaceBefore);
                    if (gaps > 0)
                    {
                        justifyGap = extra / gaps;
                    }

                    break;
            }
        }

        // Logical positions first (justification spreads the extra space over the word gaps).
        var xs = new float[line.Entries.Count];
        float shift = 0;
        for (int i = 0; i < line.Entries.Count; i++)
        {
            if (line.Entries[i].SpaceBefore)
            {
                shift += justifyGap;
            }

            xs[i] = lineX + line.Entries[i].X + shift;
        }

        bool bidi = !IsMeasuring && NeedsBidi(line, parentStyle);
        if (bidi)
        {
            xs = SplitNeutralAffixes(line, xs);
        }

        bool[] rtl = new bool[line.Entries.Count];
        if (bidi)
        {
            ReorderLine(line, parentStyle.Rtl, xs, rtl);
        }

        var mergeTarget = new LayoutBox?[1];
        for (int i = 0; i < line.Entries.Count; i++)
        {
            LineEntry entry = line.Entries[i];
            float x = xs[i];
            float y = CursorY + entry.RelY;
            if (entry.TextBox is { } textBox)
            {
                // Merge consecutive words of the same run into one text box (smaller PDFs, better text extraction).
                if (!bidi && justifyGap == 0 && mergeTarget[0] is { } previous && CanMerge(previous, textBox, y))
                {
                    previous.Text += (textBox.SpaceBefore ? " " : string.Empty) + textBox.Text;
                    previous.Width = x + textBox.Width - previous.X;
                    continue;
                }

                textBox.X = x;
                textBox.Y = y;
                textBox.Rtl = rtl[i];
                _currentPage.Boxes.Add(textBox);
                mergeTarget[0] = textBox;
                continue;
            }

            mergeTarget[0] = null;
            if (entry.Atomic is { } atomic)
            {
                foreach (LayoutBox child in atomic.Boxes)
                {
                    LayoutBox placed = child.CloneAt(x + child.X, y + child.Y);
                    if (entry.LinkUrl is not null && placed.Type == LayoutBoxType.Image)
                    {
                        placed.LinkUrl = entry.LinkUrl;
                    }

                    _currentPage.Boxes.Add(placed);
                }
            }
        }
    }

    /// <summary>
    /// Splits leading/trailing punctuation off words so it is resolved as a bidi neutral on its own
    /// (e.g. the period after a number at the end of a right-to-left sentence goes to the left).
    /// </summary>
    private float[] SplitNeutralAffixes(LayoutLine line, float[] xs)
    {
        var entries = new List<LineEntry>(line.Entries.Count);
        var positions = new List<float>(xs.Length);
        for (int i = 0; i < line.Entries.Count; i++)
        {
            LineEntry entry = line.Entries[i];
            if (entry.TextBox is not { Text: { Length: > 1 } text } box)
            {
                entries.Add(entry);
                positions.Add(xs[i]);
                continue;
            }

            int start = 0, end = text.Length;
            while (start < end && IsBidiNeutral(text[start]))
            {
                start++;
            }

            while (end > start && IsBidiNeutral(text[end - 1]))
            {
                end--;
            }

            if ((start == 0 && end == text.Length) || start == end)
            {
                entries.Add(entry);
                positions.Add(xs[i]);
                continue;
            }

            float x = xs[i];
            bool first = true;
            foreach (string part in new[] { text[..start], text[start..end], text[end..] })
            {
                if (part.Length == 0)
                {
                    continue;
                }

                float width = TextMeasurer.MeasureWidth(part, box.Style, _shared.Fonts);
                LayoutBox piece = box.CloneAt(box.X, box.Y);
                piece.Text = part;
                piece.Width = width;
                piece.SpaceBefore = first && box.SpaceBefore;
                entries.Add(new LineEntry { X = entry.X, RelY = entry.RelY, TextBox = piece, SpaceBefore = piece.SpaceBefore, LinkUrl = entry.LinkUrl });
                positions.Add(x);
                x += width;
                first = false;
            }
        }

        line.Entries.Clear();
        line.Entries.AddRange(entries);
        return [.. positions];
    }

    private static bool IsBidiNeutral(char c) =>
        !char.IsLetterOrDigit(c) && !char.IsWhiteSpace(c) && !char.IsSurrogate(c)
        && char.GetUnicodeCategory(c) is not (UnicodeCategory.NonSpacingMark or UnicodeCategory.SpacingCombiningMark or UnicodeCategory.EnclosingMark);

    private static bool NeedsBidi(LayoutLine line, ComputedStyle parentStyle) =>
        parentStyle.Rtl || line.Entries.Exists(e => e.TextBox?.Text is { } text && Bidi.ContainsRtl(text));

    /// <summary>
    /// Reorders a line's entries for display (UAX #9 at word level): <paramref name="xs"/> receives
    /// visual positions and <paramref name="rtl"/> marks words drawn right to left.
    /// </summary>
    private static void ReorderLine(LayoutLine line, bool rtlBase, float[] xs, bool[] rtl)
    {
        int n = line.Entries.Count;
        var types = new BidiType[n];
        var widths = new float[n];
        for (int i = 0; i < n; i++)
        {
            LineEntry e = line.Entries[i];
            types[i] = e.TextBox?.Text is { } text ? Bidi.WordType(text) : BidiType.Neutral;
            widths[i] = e.TextBox?.Width ?? e.Atomic?.Width ?? 0;
        }

        int[] levels = Bidi.ResolveLevels(types, rtlBase);
        int[] order = Bidi.VisualOrder(levels);

        // Gap before each entry in logical order (word spacing plus any justification).
        var gaps = new float[n];
        float start = n > 0 ? xs[0] : 0;
        float end = start;
        for (int i = 0; i < n; i++)
        {
            gaps[i] = i == 0 ? 0 : Math.Max(0, xs[i] - (xs[i - 1] + widths[i - 1]));
            end = Math.Max(end, xs[i] + widths[i]);
        }

        float x = start;
        for (int v = 0; v < n; v++)
        {
            int i = order[v];
            if (v > 0)
            {
                int prev = order[v - 1];
                x += gaps[Math.Max(prev, i)];
            }

            xs[i] = x;
            x += widths[i];
            rtl[i] = levels[i] % 2 == 1;
        }

        // Keep the line's extent: in a right-to-left paragraph the visual line ends where the logical one did.
        float shift = end - x;
        if (rtlBase && shift != 0)
        {
            for (int i = 0; i < n; i++)
            {
                xs[i] += shift;
            }
        }
    }

    private static bool CanMerge(LayoutBox previous, LayoutBox next, float nextY) =>
        ReferenceEquals(previous.Style, next.Style)
        && ReferenceEquals(previous.Node, next.Node)
        && Math.Abs(previous.Y - nextY) < 0.01f
        && previous.LinkUrl == next.LinkUrl
        && previous.InlineBackground == next.InlineBackground
        && previous.Style.WhiteSpace is not (WhiteSpaceMode.Pre or WhiteSpaceMode.PreWrap)
        && previous.Style.LetterSpacing == 0
        && previous.Style.WordSpacing == 0;

    // ── Inline item collection ───────────────────────────────────────────

    private void CollectInlineItems(HtmlNode node, List<InlineItem> items, InlineContext context)
    {
        if (node.NodeType == HtmlNodeType.Text)
        {
            CollectTextItems(node, items, context);
            return;
        }

        ComputedStyle style = StyleFor(node, context.AvailableWidth);
        if (style.Display == DisplayType.None)
        {
            return;
        }

        if (TryHandleOutOfFlow(node, style, context.AvailableWidth, context.OffsetX))
        {
            return;
        }

        if (node.Tag is "br")
        {
            items.Add(InlineItem.LineBreak(style));
            return;
        }

        if (IsReplaced(node))
        {
            AtomicInline? image = CreateImageAtomic(node, style, context.AvailableWidth, context.LinkUrl, includeVerticalMargins: true);
            if (image is not null)
            {
                items.Add(InlineItem.ForAtomic(image, style, context.LinkUrl));
            }
            else if (node.GetAttribute("alt") is { Length: > 0 } alt)
            {
                ComputedStyle altStyle = style.Clone();
                altStyle.IsItalic = true;
                altStyle.Color = new PdfColor(0.5f, 0.5f, 0.5f);
                items.Add(InlineItem.ForText($"[{alt}]", altStyle, context.LinkUrl, context.Background, node));
            }

            return;
        }

        if (style.Display == DisplayType.InlineBlock)
        {
            AtomicInline atomic = CreateInlineBlockAtomic(node, style, context.AvailableWidth);
            items.Add(InlineItem.ForAtomic(atomic, style, context.LinkUrl));
            return;
        }

        InlineContext childContext = context;
        if (style.BackgroundColor is PdfColor bg && !bg.IsTransparent && node.Tag is not ("html" or "body"))
        {
            childContext = childContext with { Background = bg };
        }

        if (node.Tag is "a" && node.GetAttribute("href") is { Length: > 0 } href)
        {
            childContext = childContext with { LinkUrl = href };
        }

        foreach (HtmlNode child in node.Children)
        {
            CollectInlineItems(child, items, childContext);
        }
    }

    private static void CollectTextItems(HtmlNode node, List<InlineItem> items, InlineContext context)
    {
        ComputedStyle style = node.ComputedStyle ?? node.Parent?.ComputedStyle ?? new ComputedStyle();
        string rawText = ApplyTextTransform(node.Text ?? string.Empty, style.TextTransform);
        string text = style.WhiteSpace switch
        {
            WhiteSpaceMode.Pre or WhiteSpaceMode.PreWrap => NormalizePreservedWhitespace(rawText),
            WhiteSpaceMode.PreLine => CollapseWhitespacePreservingLineBreaks(rawText),
            _ => NormalizeWhitespace(rawText),
        };
        if (text.Length == 0)
        {
            return;
        }

        if (style.WhiteSpace is WhiteSpaceMode.Pre or WhiteSpaceMode.PreWrap or WhiteSpaceMode.PreLine)
        {
            string[] lines = text.Split('\n');
            for (int li = 0; li < lines.Length; li++)
            {
                if (li > 0)
                {
                    items.Add(InlineItem.LineBreak(style));
                }

                if (lines[li].Length > 0)
                {
                    items.Add(InlineItem.ForText(lines[li], style, context.LinkUrl, context.Background, node));
                }
            }

            return;
        }

        items.Add(InlineItem.ForText(text, style, context.LinkUrl, context.Background, node));
    }

    private AtomicInline CreateInlineBlockAtomic(HtmlNode node, ComputedStyle style, float available)
    {
        float outer = style.Width is float w && w > 0
            ? MeasureIntrinsic(node, asBox: true).Max
            : ShrinkToFit(node, available);
        if (style.Width is float pct && CssLength.IsPercent(pct))
        {
            outer = CssLength.Resolve(pct, available);
        }

        IsolatedResult result = LayoutBoxIsolated(node, outer, ignoreExplicitWidth: true);

        // Baseline: last line of text inside, or the bottom margin edge when there is none.
        float ascent = result.Height;
        LayoutBox? lastText = result.Boxes.LastOrDefault(b => b.Type == LayoutBoxType.InlineText);
        if (lastText is not null)
        {
            ascent = lastText.Y + (lastText.Style.FontSize * AscentRatio);
        }

        if (style.VerticalAlign == VerticalAlign.Middle)
        {
            ascent = -1; // resolved against the line's font in FinalizeLine
        }

        return new AtomicInline(result.Boxes, outer, result.Height, ascent);
    }

    private HtmlNode? LoadSvgImage(string? src)
    {
        if (string.IsNullOrWhiteSpace(src))
        {
            return null;
        }

        if (!_shared.SvgImages.TryGetValue(src, out HtmlNode? svg))
        {
            svg = Rendering.Svg.SvgDocument.Load(src, _shared.Loader);
            _shared.SvgImages[src] = svg;
        }

        return svg;
    }

    private AtomicInline? CreateImageAtomic(HtmlNode node, ComputedStyle style, float availableWidth, string? linkUrl, bool includeVerticalMargins)
    {
        node.Attributes.TryGetValue("src", out string? src);
        HtmlNode? svg = node.Tag == "svg" ? node : LoadSvgImage(src);
        float pixelW, pixelH;
        if (svg is not null)
        {
            (pixelW, pixelH) = Rendering.Svg.SvgDocument.IntrinsicSize(svg);
        }
        else
        {
            ImageData? img = ImageData.Parse(src, _shared.Loader);
            if (img is null || img.Width == 0 || img.Height == 0)
            {
                return null;
            }

            (pixelW, pixelH) = (img.Width, img.Height);
        }

        // Determine display size in points (default: 1 px = 0.75 pt)
        const float PxToPt = 0.75f;
        float intrinsicW = pixelW * PxToPt;
        float intrinsicH = pixelH * PxToPt;
        float aspectRatio = intrinsicW / intrinsicH;

        float displayW = intrinsicW;
        float displayH = intrinsicH;
        bool widthSet = false;

        if (style.Width is float cssW && cssW > 0)
        {
            displayW = cssW;
            displayH = displayW / aspectRatio;
            widthSet = true;
        }
        else if (style.Width is float cssWPct && CssLength.IsPercent(cssWPct))
        {
            displayW = CssLength.Resolve(cssWPct, availableWidth);
            displayH = displayW / aspectRatio;
            widthSet = true;
        }
        else if (node.Tag != "svg" && node.Attributes.TryGetValue("width", out string? widthAttr) &&
            float.TryParse(widthAttr.Replace("px", string.Empty, StringComparison.OrdinalIgnoreCase), NumberStyles.Float, CultureInfo.InvariantCulture, out float attrW))
        {
            displayW = attrW * PxToPt;
            displayH = displayW / aspectRatio;
            widthSet = true;
        }

        if (style.Height is float cssH && cssH > 0)
        {
            displayH = cssH;
            if (!widthSet)
            {
                displayW = displayH * aspectRatio;
            }
        }
        else if (node.Tag != "svg" && node.Attributes.TryGetValue("height", out string? heightAttr) &&
            float.TryParse(heightAttr.Replace("px", string.Empty, StringComparison.OrdinalIgnoreCase), NumberStyles.Float, CultureInfo.InvariantCulture, out float attrH))
        {
            displayH = attrH * PxToPt;
            if (!widthSet)
            {
                displayW = displayH * aspectRatio;
            }
        }

        // Apply max-width (default behaves like max-width: 100% of the container to avoid overflowing the page).
        float maxW = style.MaxWidth is float mw ? CssLength.Resolve(mw, availableWidth) : float.MaxValue;
        if (!IsMeasuring)
        {
            maxW = Math.Min(maxW, availableWidth);
        }

        if (displayW > maxW && maxW > 0)
        {
            displayW = maxW;
            displayH = displayW / aspectRatio;
        }

        float ml = Math.Max(0, style.Margin.Left);
        float mr = Math.Max(0, style.Margin.Right);
        float mt = includeVerticalMargins ? Math.Max(0, style.Margin.Top) : 0;
        float mb = includeVerticalMargins ? Math.Max(0, style.Margin.Bottom) : 0;
        float bl = style.Border.LeftWidth, br = style.Border.RightWidth, bt = style.Border.TopWidth, bb = style.Border.BottomWidth;
        float pl = Math.Max(0, style.Padding.Left), pr = Math.Max(0, style.Padding.Right);
        float pt = Math.Max(0, style.Padding.Top), pb = Math.Max(0, style.Padding.Bottom);

        var boxes = new List<LayoutBox>();
        if (style.Border.HasBorder || (style.BackgroundColor is PdfColor bg && !bg.IsTransparent))
        {
            boxes.Add(new LayoutBox
            {
                Type = LayoutBoxType.Block,
                Node = node,
                Style = style,
                X = ml,
                Y = mt,
                Width = displayW,
                Height = displayH,
            });
        }

        boxes.Add(new LayoutBox
        {
            Type = LayoutBoxType.Image,
            Node = node,
            Style = style,
            X = ml + bl + pl,
            Y = mt + bt + pt,
            Width = displayW,
            Height = displayH,
            ImageSource = src,
            LinkUrl = linkUrl,
            Svg = svg,
        });

        float outerW = ml + bl + pl + displayW + pr + br + mr;
        float outerH = mt + bt + pt + displayH + pb + bb + mb;
        float ascent = style.VerticalAlign == VerticalAlign.Middle ? -1 : outerH;
        return new AtomicInline(boxes, outerW, outerH, ascent);
    }

    // ── Line building ────────────────────────────────────────────────────

    private List<LayoutLine> WrapItems(List<InlineItem> items, ComputedStyle strut, float availableWidth, float offsetX, float firstIndent)
    {
        var lines = new List<LayoutLine>();
        float estimatedLineHeight = strut.FontSize * strut.LineHeight;
        float lineTop = 0;
        var current = NewLine(lineTop, firstIndent);
        float cursorX = 0;
        bool pendingSpace = false;
        ComputedStyle lastStyle = strut;

        LayoutLine NewLine(float top, float indent)
        {
            (float x, float width) = LineBand(top, estimatedLineHeight, offsetX, availableWidth);
            return new LayoutLine { BandX = x + indent, BandWidth = Math.Max(0, width - indent) };
        }

        void Break(bool hard, ComputedStyle breakStyle)
        {
            current.HardBreak = hard;
            FinalizeLine(current, current.Entries.Count == 0 ? breakStyle : strut);
            lines.Add(current);
            lineTop += current.Height;
            current = NewLine(lineTop, 0);
            cursorX = 0;
        }

        foreach (InlineItem item in items)
        {
            if (item.Kind == InlineKind.LineBreak)
            {
                Break(hard: true, item.Style);
                pendingSpace = false;
                continue;
            }

            float maxWidth = current.BandWidth;
            if (item.Kind == InlineKind.Atomic)
            {
                AtomicInline atomic = item.Atomic!;
                float space = pendingSpace && cursorX > 0 ? MeasureSpace(lastStyle) : 0;
                if (cursorX > 0 && cursorX + space + atomic.Width > maxWidth + WrapTolerance && lastStyle.WhiteSpace != WhiteSpaceMode.NoWrap)
                {
                    Break(hard: false, strut);
                    space = 0;
                }

                cursorX += space;
                current.Entries.Add(new LineEntry { X = cursorX, Atomic = atomic, SpaceBefore = space > 0, LinkUrl = item.LinkUrl });
                cursorX += atomic.Width;
                current.Width = cursorX;
                pendingSpace = false;
                continue;
            }

            ComputedStyle style = item.Style;
            bool preservesSpaces = style.WhiteSpace is WhiteSpaceMode.Pre or WhiteSpaceMode.PreWrap;
            bool wraps = style.WhiteSpace is WhiteSpaceMode.Normal or WhiteSpaceMode.PreLine or WhiteSpaceMode.PreWrap;
            foreach ((string segment, bool isWhitespace) in SplitTextSegments(item.Text, preservesSpaces))
            {
                if (segment.Length == 0)
                {
                    continue;
                }

                maxWidth = current.BandWidth;
                if (isWhitespace)
                {
                    if (!preservesSpaces)
                    {
                        pendingSpace = cursorX > 0 || current.Entries.Count > 0;
                        lastStyle = style;
                        continue;
                    }

                    if (style.WhiteSpace == WhiteSpaceMode.PreWrap)
                    {
                        // Preserved spaces may wrap between any two of them.
                        foreach (Rune whitespaceRune in segment.EnumerateRunes())
                        {
                            string whitespaceText = whitespaceRune.ToString();
                            float oneSpaceWidth = TextMeasurer.MeasureWidth(whitespaceText, style, _shared.Fonts);
                            if (cursorX > 0 && cursorX + oneSpaceWidth > current.BandWidth + WrapTolerance)
                            {
                                Break(hard: false, strut);
                            }

                            AddTextEntry(current, whitespaceText, cursorX, oneSpaceWidth, item, spaceBefore: false);
                            cursorX += oneSpaceWidth;
                            current.Width = cursorX;
                        }

                        continue;
                    }

                    float whitespaceWidth = TextMeasurer.MeasureWidth(segment, style, _shared.Fonts);
                    AddTextEntry(current, segment, cursorX, whitespaceWidth, item, spaceBefore: false);
                    cursorX += whitespaceWidth;
                    current.Width = cursorX;
                    continue;
                }

                float spaceWidth = cursorX > 0 && pendingSpace ? MeasureSpace(lastStyle) : 0;
                pendingSpace = false;
                string word = segment.Contains(SoftHyphen, StringComparison.Ordinal) ? segment.Replace(SoftHyphen, string.Empty, StringComparison.Ordinal) : segment;
                float segmentWidth = TextMeasurer.MeasureWidth(word, style, _shared.Fonts);

                // Hyphenate a word that overflows the line at soft hyphens, hard hyphens or (hyphens: auto) syllables.
                if (wraps && !IsMeasuring && cursorX + spaceWidth + segmentWidth > maxWidth + WrapTolerance)
                {
                    List<(int Index, bool AddHyphen)> breaks = HyphenationBreaks(segment, style);
                    string fullWord = word;
                    int consumed = 0; // characters of fullWord already placed on earlier lines
                    int first = 0;    // first break point after `consumed`
                    int guard = 0;

                    // Prefix text and width from `consumed` up to break point `index`.
                    bool Fits(int index, out string text, out float width)
                    {
                        text = fullWord[consumed..breaks[index].Index] + (breaks[index].AddHyphen ? "-" : string.Empty);
                        width = TextMeasurer.MeasureWidth(text, style, _shared.Fonts);
                        return cursorX + spaceWidth + width <= current.BandWidth + WrapTolerance;
                    }

                    while (first < breaks.Count && cursorX + spaceWidth + segmentWidth > current.BandWidth + WrapTolerance && guard++ < 1000)
                    {
                        int chosen = -1;
                        string prefix = string.Empty;
                        float prefixWidth = 0;

                        // Prefix widths grow with the break index. Gallop from the first break
                        // (+0, +1, +2, +4, ...) to bracket the longest prefix that fits, then
                        // binary-search inside the bracket. Only prefixes about a line long are
                        // measured, and nothing is copied or re-measured per line, so a long
                        // word stays linear.
                        int low = first;
                        int high = breaks.Count - 1;
                        int step = 0;
                        while (first + step <= high)
                        {
                            int probe = first + step;
                            if (!Fits(probe, out string text, out float width))
                            {
                                high = probe - 1;
                                break;
                            }

                            (chosen, prefix, prefixWidth) = (probe, text, width);
                            low = probe + 1;
                            step = step == 0 ? 1 : step * 2;
                        }

                        while (low <= high)
                        {
                            int mid = (low + high) >>> 1;
                            if (Fits(mid, out string text, out float width))
                            {
                                (chosen, prefix, prefixWidth) = (mid, text, width);
                                low = mid + 1;
                            }
                            else
                            {
                                high = mid - 1;
                            }
                        }

                        if (chosen < 0)
                        {
                            if (cursorX > 0)
                            {
                                Break(hard: false, strut);
                                spaceWidth = 0;
                                continue;
                            }

                            break;
                        }

                        AddTextEntry(current, prefix, cursorX + spaceWidth, prefixWidth, item, spaceBefore: spaceWidth > 0);
                        current.Width = cursorX + spaceWidth + prefixWidth;
                        Break(hard: false, strut);
                        spaceWidth = 0;

                        // Estimate the rest's width from the placed part; it is measured exactly once below.
                        segmentWidth -= TextMeasurer.MeasureWidth(fullWord[consumed..breaks[chosen].Index], style, _shared.Fonts);
                        consumed = breaks[chosen].Index;
                        first = chosen + 1;
                    }

                    if (consumed > 0)
                    {
                        word = fullWord[consumed..];
                        segmentWidth = TextMeasurer.MeasureWidth(word, style, _shared.Fonts);
                    }

                    maxWidth = current.BandWidth;
                }

                if (wraps && cursorX > 0 && cursorX + spaceWidth + segmentWidth > maxWidth + WrapTolerance)
                {
                    Break(hard: false, strut);
                    maxWidth = current.BandWidth;
                    spaceWidth = 0;
                }

                cursorX += spaceWidth;
                bool breakLongWord = style.WordBreak == WordBreakMode.BreakAll || style.OverflowWrapAnywhere;
                if (wraps && breakLongWord && segmentWidth > maxWidth - cursorX && maxWidth > 0 && !IsMeasuring)
                {
                    var piece = new StringBuilder();
                    float pieceWidth = 0;
                    float pieceStart = cursorX;
                    bool first = true;
                    foreach (Rune rune in word.EnumerateRunes())
                    {
                        string runeText = rune.ToString();
                        float runeWidth = TextMeasurer.MeasureWidth(runeText, style, _shared.Fonts);
                        if (piece.Length > 0 && pieceStart + pieceWidth + runeWidth > maxWidth)
                        {
                            AddTextEntry(current, piece.ToString(), pieceStart, pieceWidth, item, spaceBefore: first && spaceWidth > 0);
                            first = false;
                            current.Width = pieceStart + pieceWidth;
                            Break(hard: false, strut);
                            maxWidth = current.BandWidth;
                            piece.Clear();
                            pieceStart = 0;
                            pieceWidth = 0;
                        }

                        piece.Append(runeText);
                        pieceWidth += runeWidth;
                    }

                    if (piece.Length > 0)
                    {
                        AddTextEntry(current, piece.ToString(), pieceStart, pieceWidth, item, spaceBefore: first && spaceWidth > 0);
                        cursorX = pieceStart + pieceWidth;
                        current.Width = cursorX;
                    }

                    lastStyle = style;
                    continue;
                }

                AddTextEntry(current, word, cursorX, segmentWidth, item, spaceBefore: spaceWidth > 0);
                cursorX += segmentWidth;
                current.Width = cursorX;
                lastStyle = style;
            }
        }

        if (current.Entries.Count > 0)
        {
            FinalizeLine(current, strut);
            lines.Add(current);
        }

        return lines;
    }

    private const string SoftHyphen = "\u00AD";

    /// <summary>
    /// Break opportunities inside a word, as indices into the word without soft hyphens.
    /// Soft hyphens and automatic points show a hyphen; a hard hyphen already ends the piece.
    /// </summary>
    private static List<(int Index, bool AddHyphen)> HyphenationBreaks(string segment, ComputedStyle style)
    {
        var breaks = new List<(int, bool)>();
        var plain = new StringBuilder(segment.Length);
        foreach (char c in segment)
        {
            if (c == '\u00AD')
            {
                if (style.Hyphens != HyphensMode.None && plain.Length > 0)
                {
                    breaks.Add((plain.Length, true));
                }

                continue;
            }

            plain.Append(c);
            if (c is '-' or '\u2010' or '\u2013' && plain.Length > 1 && char.IsLetterOrDigit(plain[^2]))
            {
                breaks.Add((plain.Length, false));
            }
        }

        string word = plain.ToString();
        if (breaks.Count > 0 && breaks[^1].Item1 >= word.Length)
        {
            breaks.RemoveAt(breaks.Count - 1);
        }

        if (style.Hyphens == HyphensMode.Auto && !segment.Contains('\u00AD', StringComparison.Ordinal))
        {
            // Hyphenate each hyphen-separated part independently.
            int partStart = 0;
            foreach (string part in word.Split('-'))
            {
                foreach (int p in Hyphenator.Points(part, style.Language))
                {
                    breaks.Add((partStart + p, true));
                }

                partStart += part.Length + 1;
            }
        }

        breaks.Sort((a, b) => a.Item1.CompareTo(b.Item1));
        return breaks;
    }

    private float MeasureSpace(ComputedStyle style) => TextMeasurer.MeasureWidth(" ", style, _shared.Fonts);

    private static void AddTextEntry(LayoutLine line, string text, float x, float width, InlineItem item, bool spaceBefore)
    {
        var box = new LayoutBox
        {
            Type = LayoutBoxType.InlineText,
            Node = item.Node,
            Style = item.Style,
            X = x,
            Y = 0,
            Width = width,
            Height = item.Style.FontSize * item.Style.LineHeight,
            Text = text,
            LinkUrl = item.LinkUrl,
            InlineBackground = item.Background,
            SpaceBefore = spaceBefore,
        };
        line.Entries.Add(new LineEntry { X = x, TextBox = box, SpaceBefore = spaceBefore });
    }

    /// <summary>Computes the line height and baseline, aligning every entry on a common baseline.</summary>
    private static void FinalizeLine(LayoutLine line, ComputedStyle strut)
    {
        (float strutAscent, float strutDescent) = TextMetrics(strut);
        float ascent = strutAscent;
        float descent = strutDescent;

        foreach (LineEntry entry in line.Entries)
        {
            if (entry.TextBox is { } box)
            {
                (float a, float d) = TextMetrics(box.Style);
                ascent = Math.Max(ascent, a);
                descent = Math.Max(descent, d);
            }
            else if (entry.Atomic is { } atomic)
            {
                float a = atomic.Ascent >= 0 ? atomic.Ascent : (atomic.Height / 2) + (strut.FontSize * 0.3f);
                ascent = Math.Max(ascent, a);
                descent = Math.Max(descent, atomic.Height - a);
            }
        }

        line.Height = ascent + descent;
        line.Baseline = ascent;
        foreach (LineEntry entry in line.Entries)
        {
            if (entry.TextBox is { } box)
            {
                entry.RelY = ascent - (box.Style.FontSize * AscentRatio);
            }
            else if (entry.Atomic is { } atomic)
            {
                float a = atomic.Ascent >= 0 ? atomic.Ascent : (atomic.Height / 2) + (strut.FontSize * 0.3f);
                entry.RelY = ascent - a;
            }
        }
    }

    private static (float Ascent, float Descent) TextMetrics(ComputedStyle style)
    {
        float fs = style.FontSize;
        float halfLeading = ((fs * style.LineHeight) - fs) / 2;
        return (halfLeading + (fs * AscentRatio), halfLeading + (fs * (1 - AscentRatio)));
    }

    private static IEnumerable<(string Segment, bool IsWhitespace)> SplitTextSegments(string text, bool preserveWhitespace)
    {
        int start = 0;
        while (start < text.Length)
        {
            bool whitespace = IsCollapsibleWhitespace(text[start]);
            int end = start + 1;
            while (end < text.Length && IsCollapsibleWhitespace(text[end]) == whitespace)
            {
                end++;
            }

            yield return whitespace && !preserveWhitespace ? (" ", true) : (text[start..end], whitespace);
            start = end;
        }
    }

    // A no-break space is not a break opportunity.
    private static bool IsCollapsibleWhitespace(char c) => c != ' ' && c != ' ' && char.IsWhiteSpace(c);

    // ── List markers ─────────────────────────────────────────────────────

    private float MeasureMarker(MarkerInfo marker, ComputedStyle style) =>
        marker.Shape == MarkerShape.Text && marker.Text is not null
            ? TextMeasurer.MeasureWidth(marker.Text, style, _shared.Fonts)
            : style.FontSize * 0.45f;

    private void PlaceMarker(MarkerInfo marker, ComputedStyle style, PageBox page, int fromIndex, float contentX, float childStartY)
    {
        float fs = style.FontSize;
        float baseline = childStartY + TextMetrics(style).Ascent;
        for (int i = fromIndex; i < page.Boxes.Count; i++)
        {
            LayoutBox candidate = page.Boxes[i];
            if (candidate.Type == LayoutBoxType.InlineText)
            {
                baseline = candidate.Y + (candidate.Style.FontSize * AscentRatio);
                break;
            }

            if (candidate.Type == LayoutBoxType.Image)
            {
                baseline = candidate.Y + candidate.Height;
                break;
            }
        }

        bool inside = style.ListStyleInside;
        if (marker.Shape == MarkerShape.Text && marker.Text is not null)
        {
            float width = TextMeasurer.MeasureWidth(marker.Text, style, _shared.Fonts);
            float x = inside ? contentX : contentX - width - (fs * 0.5f);
            page.Boxes.Add(new LayoutBox
            {
                Type = LayoutBoxType.ListMarker,
                Style = style,
                X = x,
                Y = baseline - (fs * AscentRatio),
                Width = width,
                Height = fs * style.LineHeight,
                Marker = marker.Text,
                MarkerShape = MarkerShape.Text,
            });
            return;
        }

        float size = fs * 0.36f;
        float centerY = baseline - (fs * 0.3f);
        float markerX = inside ? contentX + (fs * 0.05f) : contentX - (fs * 0.9f);
        page.Boxes.Add(new LayoutBox
        {
            Type = LayoutBoxType.ListMarker,
            Style = style,
            X = markerX,
            Y = centerY - (size / 2),
            Width = size,
            Height = size,
            MarkerShape = marker.Shape,
        });
    }

    // ── Whitespace helpers ───────────────────────────────────────────────

    private static string NormalizeWhitespace(string text)
    {
        var sb = new StringBuilder(text.Length);
        bool lastWasSpace = false;

        foreach (char c in text)
        {
            if (IsCollapsibleWhitespace(c))
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

    private static string NormalizePreservedWhitespace(string text) =>
        text.Replace("\r\n", "\n", StringComparison.Ordinal)
            .Replace('\r', '\n')
            .Replace("\t", "    ", StringComparison.Ordinal);

    private static string CollapseWhitespacePreservingLineBreaks(string text)
    {
        string normalized = text.Replace("\r\n", "\n", StringComparison.Ordinal).Replace('\r', '\n');
        string[] paragraphs = normalized.Split('\n');
        for (int i = 0; i < paragraphs.Length; i++)
        {
            paragraphs[i] = NormalizeWhitespace(paragraphs[i]);
        }

        return string.Join('\n', paragraphs);
    }

    private static string ApplyTextTransform(string text, TextTransformMode transform) => transform switch
    {
        TextTransformMode.Uppercase => text.ToUpperInvariant(),
        TextTransformMode.Lowercase => text.ToLowerInvariant(),
        TextTransformMode.Capitalize => CapitalizeWords(text),
        _ => text,
    };

    private static string CapitalizeWords(string text)
    {
        var builder = new StringBuilder(text.Length);
        bool wordStart = true;
        foreach (Rune rune in text.EnumerateRunes())
        {
            if (Rune.IsWhiteSpace(rune))
            {
                wordStart = true;
                builder.Append(rune.ToString());
            }
            else
            {
                builder.Append((wordStart ? Rune.ToUpperInvariant(rune) : rune).ToString());
                wordStart = false;
            }
        }

        return builder.ToString();
    }

    /// <summary>Inheritable inline context while collecting items.</summary>
    private sealed record InlineContext(string? LinkUrl, PdfColor? Background, float AvailableWidth, float OffsetX);
}

/// <summary>Kind of inline item.</summary>
internal enum InlineKind
{
    Text,
    LineBreak,
    Atomic,
}

/// <summary>A piece of inline content: a text run, a forced line break, or an atomic inline box.</summary>
internal sealed class InlineItem
{
    private InlineItem(InlineKind kind, string text, ComputedStyle style)
    {
        Kind = kind;
        Text = text;
        Style = style;
    }

    internal InlineKind Kind { get; }

    internal string Text { get; }

    internal ComputedStyle Style { get; }

    internal string? LinkUrl { get; private init; }

    internal PdfColor? Background { get; private init; }

    internal AtomicInline? Atomic { get; private init; }

    internal HtmlNode? Node { get; private init; }

    internal static InlineItem ForText(string text, ComputedStyle style, string? linkUrl, PdfColor? background, HtmlNode? node = null) =>
        new(InlineKind.Text, text, style) { LinkUrl = linkUrl, Background = background, Node = node };

    internal static InlineItem LineBreak(ComputedStyle style) => new(InlineKind.LineBreak, "\n", style);

    internal static InlineItem ForAtomic(AtomicInline atomic, ComputedStyle style, string? linkUrl) =>
        new(InlineKind.Atomic, string.Empty, style) { Atomic = atomic, LinkUrl = linkUrl };
}

/// <summary>An atomic inline box (image or inline-block) with its laid-out boxes relative to its margin box.</summary>
/// <param name="Boxes">Boxes relative to the margin-box origin.</param>
/// <param name="Width">Outer (margin-box) width.</param>
/// <param name="Height">Outer (margin-box) height.</param>
/// <param name="Ascent">Distance from the top to the baseline, or negative for vertical-align: middle.</param>
internal sealed record AtomicInline(List<LayoutBox> Boxes, float Width, float Height, float Ascent);

/// <summary>An entry positioned on a line.</summary>
internal sealed class LineEntry
{
    internal float X { get; set; }

    internal float RelY { get; set; }

    internal LayoutBox? TextBox { get; init; }

    internal AtomicInline? Atomic { get; init; }

    internal bool SpaceBefore { get; init; }

    internal string? LinkUrl { get; init; }
}

/// <summary>A single line of laid-out inline content.</summary>
internal sealed class LayoutLine
{
    /// <summary>Gets or sets the line Y position.</summary>
    public float Y { get; set; }

    /// <summary>Gets or sets the total line width.</summary>
    public float Width { get; set; }

    /// <summary>Gets or sets the line height.</summary>
    public float Height { get; set; }

    /// <summary>Gets or sets the distance from the line top to the baseline.</summary>
    public float Baseline { get; set; }

    /// <summary>Gets or sets the left edge available to this line (after floats and indentation).</summary>
    public float BandX { get; set; }

    /// <summary>Gets or sets the width available to this line.</summary>
    public float BandWidth { get; set; }

    /// <summary>Gets or sets a value indicating whether the line ended with a forced break.</summary>
    public bool HardBreak { get; set; }

    /// <summary>Gets the entries on this line.</summary>
    public List<LineEntry> Entries { get; } = [];

    /// <summary>Gets the text boxes on this line.</summary>
    public IEnumerable<LayoutBox> Boxes => Entries.Where(e => e.TextBox is not null).Select(e => e.TextBox!);
}

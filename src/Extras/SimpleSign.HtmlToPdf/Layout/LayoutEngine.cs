// Licensed to SimpleSign under the MIT License.

using SimpleSign.HtmlToPdf.Fonts;
using SimpleSign.HtmlToPdf.Internal;
using SimpleSign.HtmlToPdf.Parsing;
using SimpleSign.HtmlToPdf.Rendering;

namespace SimpleSign.HtmlToPdf.Layout;

/// <summary>
/// Lays out a styled DOM tree into positioned boxes across pages.
/// Handles block flow, inline formatting (wrapping, alignment, justification), floats, positioning,
/// flexbox, grid, tables, list markers, and page fragmentation.
/// </summary>
/// <remarks>
/// Content that must be measured before it is placed (table cells, inline-blocks, floats, flex and grid items,
/// absolutely positioned boxes) is laid out by an <em>isolated</em> engine on a single, unbounded page. The
/// resulting boxes are then translated into the main flow, splitting them across pages when necessary.
/// </remarks>
public sealed partial class LayoutEngine
{
    private const float UnboundedHeight = 10_000_000f;
    private const float MaxContentProbeWidth = 100_000f;
    private const float MinContentProbeWidth = 0.01f;

    private readonly PageSettings _settings;
    private readonly SharedState _shared;
    private readonly List<PageBox> _pages = [];
    private readonly List<BookmarkEntry> _bookmarks = [];
    private PageBox _currentPage;
    private float _lastMarginBottom;
    private float _pendingIndent;

    /// <summary>
    /// Initializes a new instance of the <see cref="LayoutEngine"/> class.
    /// </summary>
    /// <param name="settings">Page settings for layout.</param>
    public LayoutEngine(PageSettings settings) : this(settings, null)
    {
    }

    internal LayoutEngine(PageSettings settings, FontCollection? fonts) : this(settings, fonts, null)
    {
    }

    internal LayoutEngine(PageSettings settings, FontCollection? fonts, ResourceLoader? loader)
        : this(settings, new SharedState(fonts, loader ?? ResourceLoader.DataUriOnly), isolated: false, measuring: false)
    {
    }

    private LayoutEngine(PageSettings settings, SharedState shared, bool isolated, bool measuring)
    {
        _settings = settings;
        _shared = shared;
        IsIsolated = isolated;
        IsMeasuring = measuring;
        _currentPage = CreateNewPage();
    }

    internal FontCollection? Fonts => _shared.Fonts;

    internal ResourceLoader Resources => _shared.Loader;

    internal bool IsIsolated { get; }

    internal bool IsMeasuring { get; }

    internal float CursorY { get; set; }

    internal float PageContentHeight => _settings.ContentHeight;

    /// <summary>
    /// Lays out the DOM tree into pages.
    /// </summary>
    /// <param name="root">Root node of the styled DOM tree.</param>
    /// <returns>Layout result with positioned pages and boxes.</returns>
    public LayoutResult Layout(HtmlNode root)
    {
        ArgumentNullException.ThrowIfNull(root);
        LayoutBlockChildren(root, _settings.ContentWidth, _settings.Margins.Left);
        LayoutPendingAbsolutes(null, new ContainingBlock(_settings.Margins.Left, 0, _settings.ContentWidth, _settings.ContentHeight, _currentPage));
        FlushCurrentPage();

        // A forced break after the last element leaves only empty continuation fragments behind.
        while (_pages.Count > 1 && _pages[^1].Boxes.TrueForAll(b => b.Type == LayoutBoxType.Block && b.Height <= 0.5f && b.SuppressTopBorder))
        {
            _pages.RemoveAt(_pages.Count - 1);
        }

        StampFixedBoxes();

        (HtmlNode? canvasNode, ComputedStyle? canvasStyle) = FindCanvas(root);
        var result = new LayoutResult
        {
            Settings = _settings,
            Fonts = _shared.Fonts,
            Resources = _shared.Loader,
            CanvasNode = canvasNode,
            CanvasStyle = canvasStyle,
        };
        result.Pages.AddRange(_pages);
        result.Bookmarks.AddRange(_bookmarks);
        return result;
    }

    /// <summary>
    /// CSS propagates the root element's background (or the body's, when the root has none)
    /// to the canvas, which covers every page.
    /// </summary>
    private static (HtmlNode? Node, ComputedStyle? Style) FindCanvas(HtmlNode root)
    {
        HtmlNode? html = root.Tag == "html" ? root : root.Descendants("html").FirstOrDefault();
        HtmlNode? body = (html ?? root).Descendants("body").FirstOrDefault();
        foreach (HtmlNode? candidate in new[] { html, body })
        {
            if (candidate?.ComputedStyle is { } style
                && ((style.BackgroundColor is PdfColor color && !color.IsTransparent) || style.HasBackgroundImage))
            {
                return (candidate, style);
            }
        }

        return (null, null);
    }

    // ── Block flow ───────────────────────────────────────────────────────

    private void LayoutBlockChildren(HtmlNode parent, float availableWidth, float offsetX)
    {
        if (!StackGuard.HasSufficientStack)
        {
            LayoutBlockChildrenOnEmptyStack(parent, availableWidth, offsetX);
            return;
        }

        ListCounter? counter = null;

        for (int i = 0; i < parent.Children.Count; i++)
        {
            HtmlNode child = parent.Children[i];
            ComputedStyle style = StyleFor(child, availableWidth);

            if (style.Display == DisplayType.None)
            {
                continue;
            }

            if (child.NodeType == HtmlNodeType.Element && TryHandleOutOfFlow(child, style, availableWidth, offsetX))
            {
                continue;
            }

            if (child.NodeType == HtmlNodeType.Text || IsInlineLevel(child, style))
            {
                int end = CollectInlineSpan(parent, i);
                bool firstContent = IsFirstContent(parent, i);
                LayoutInlineContent(parent, i, end, availableWidth, offsetX, firstContent);
                i = end - 1;
                continue;
            }

            ApplyClear(style.Clear);

            if (style.PageBreakBefore == PageBreak.Always)
            {
                ForcePageBreak();
            }

            if (style.Display == DisplayType.ListItem)
            {
                counter ??= new ListCounter(parent);
                (string? text, MarkerShape shape) = ListMarkers.Create(style.ListStyleType, counter.Next(child));
                MarkerInfo? marker = text is null && shape == MarkerShape.Text ? null : new MarkerInfo(text, shape);
                LayoutBlock(child, availableWidth, offsetX, marker: marker);
            }
            else if (child.Tag is "hr")
            {
                LayoutHorizontalRule(child, availableWidth, offsetX);
            }
            else if (IsReplaced(child))
            {
                LayoutBlockImage(child, availableWidth, offsetX);
            }
            else if (style.Display == DisplayType.Table || (child.Tag is "table" && style.Display != DisplayType.Inline))
            {
                TableLayoutHelper.Layout(this, child, availableWidth, offsetX);
            }
            else
            {
                LayoutBlock(child, availableWidth, offsetX);
            }

            if (style.PageBreakAfter == PageBreak.Always)
            {
                ForcePageBreak();
            }
        }
    }

    // Deeply nested documents recurse here once per level; these continue on a fresh stack instead
    // of overflowing (kept out of line so the hot methods capture nothing).
    private void LayoutBlockChildrenOnEmptyStack(HtmlNode parent, float availableWidth, float offsetX) =>
        StackGuard.RunOnEmptyStack(static s => s.Engine.LayoutBlockChildren(s.Parent, s.AvailableWidth, s.OffsetX), (Engine: this, Parent: parent, AvailableWidth: availableWidth, OffsetX: offsetX));

    private void LayoutBlockOnEmptyStack(HtmlNode node, float availableWidth, float offsetX, bool ignoreExplicitWidth, MarkerInfo? marker) =>
        StackGuard.RunOnEmptyStack(
            static s => s.Engine.LayoutBlock(s.Node, s.AvailableWidth, s.OffsetX, s.IgnoreExplicitWidth, s.Marker),
            (Engine: this, Node: node, AvailableWidth: availableWidth, OffsetX: offsetX, IgnoreExplicitWidth: ignoreExplicitWidth, Marker: marker));

    private static bool IsInlineLevel(HtmlNode node, ComputedStyle style) =>
        style.Float == FloatMode.None
        && style.Display is DisplayType.Inline or DisplayType.InlineBlock
        && !(IsReplaced(node) && style.Display == DisplayType.Block);

    /// <summary>Replaced elements are laid out as images: raster images and inline SVG.</summary>
    private static bool IsReplaced(HtmlNode node) => node.Tag is "img" or "svg";

    private static bool IsFirstContent(HtmlNode parent, int index)
    {
        for (int i = 0; i < index; i++)
        {
            HtmlNode sibling = parent.Children[i];
            if (sibling.NodeType == HtmlNodeType.Text)
            {
                if (!string.IsNullOrWhiteSpace(sibling.Text))
                {
                    return false;
                }

                continue;
            }

            if (sibling.ComputedStyle?.Display != DisplayType.None)
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>Lays out a block box (and its subtree), advancing the cursor.</summary>
    /// <param name="node">The block element.</param>
    /// <param name="availableWidth">Width of the containing block.</param>
    /// <param name="offsetX">Left edge of the containing block.</param>
    /// <param name="ignoreExplicitWidth">True when the caller already decided the outer width (flex/grid items, floats).</param>
    /// <param name="marker">List marker to draw next to the first line, if any.</param>
    private void LayoutBlock(HtmlNode node, float availableWidth, float offsetX, bool ignoreExplicitWidth = false, MarkerInfo? marker = null)
    {
        if (!StackGuard.HasSufficientStack)
        {
            LayoutBlockOnEmptyStack(node, availableWidth, offsetX, ignoreExplicitWidth, marker);
            return;
        }

        ComputedStyle style = StyleFor(node, availableWidth);

        // Block formatting context roots are placed beside floats instead of under them.
        bool bfcRoot = IsBlockFormattingContextRoot(style);
        if (bfcRoot && _floats.Count > 0)
        {
            (float bandLeft, float bandRight) = FloatBand(CursorY, CursorY + 1, offsetX, offsetX + availableWidth);
            offsetX = bandLeft;
            availableWidth = Math.Max(0, bandRight - bandLeft);
        }

        // Margin collapsing: collapse top margin with previous bottom margin
        float marginTop = style.Margin.Top;
        float collapsedSpacing = Math.Max(marginTop, _lastMarginBottom) - _lastMarginBottom;
        CursorY += collapsedSpacing;
        _lastMarginBottom = 0;

        float borderLeft = style.Border.LeftWidth;
        float borderRight = style.Border.RightWidth;
        float borderTop = style.Border.TopWidth;
        float borderBottom = style.Border.BottomWidth;
        float paddingLeft = ResolvePercent(style.Padding.Left, availableWidth);
        float paddingRight = ResolvePercent(style.Padding.Right, availableWidth);
        float paddingTop = ResolvePercent(style.Padding.Top, availableWidth);
        float paddingBottom = ResolvePercent(style.Padding.Bottom, availableWidth);
        float marginLeft = ResolvePercent(style.Margin.Left, availableWidth);
        float marginRight = ResolvePercent(style.Margin.Right, availableWidth);
        float horizontalExtras = borderLeft + borderRight + paddingLeft + paddingRight;

        float contentWidth = availableWidth - marginLeft - marginRight - horizontalExtras;
        bool widthConstrained = false;
        if (!ignoreExplicitWidth && ResolveWidth(style.Width, style, availableWidth, horizontalExtras) is float explicitWidth)
        {
            contentWidth = Math.Min(contentWidth, explicitWidth);
            widthConstrained = true;
        }

        if (ResolveWidth(style.MaxWidth, style, availableWidth, horizontalExtras) is float maxWidth && contentWidth > maxWidth)
        {
            contentWidth = maxWidth;
            widthConstrained = true;
        }

        if (ResolveWidth(style.MinWidth, style, availableWidth, horizontalExtras) is float minWidth && contentWidth < minWidth)
        {
            contentWidth = minWidth;
        }

        contentWidth = Math.Max(contentWidth, 0);

        // Auto horizontal margins center (or right-align) a box narrower than its container.
        float autoShift = 0;
        if (widthConstrained && !IsMeasuring)
        {
            float free = availableWidth - marginLeft - marginRight - horizontalExtras - contentWidth;
            if (free > 0)
            {
                if (style.MarginLeftAuto && style.MarginRightAuto)
                {
                    autoShift = free / 2;
                }
                else if (style.MarginLeftAuto)
                {
                    autoShift = free;
                }
            }
        }

        // Keep small boxes (break-inside: avoid) and headings (keep with next) together.
        bool isHeading = node.Tag is "h1" or "h2" or "h3" or "h4" or "h5" or "h6";
        if (!IsIsolated && CursorY > 0 && (style.PageBreakInside == PageBreak.Avoid || isHeading))
        {
            float needed = MeasureBlockHeight(node, availableWidth) + (isHeading ? 2 * 12f * 1.4f : 0);
            if (CursorY + needed > _settings.ContentHeight && needed <= _settings.ContentHeight)
            {
                StartNewPage();
            }
        }

        if (!IsIsolated && CursorY > 0 && CursorY + borderTop + paddingTop + (style.FontSize * style.LineHeight) > _settings.ContentHeight)
        {
            StartNewPage();
        }

        float boxX = offsetX + marginLeft + autoShift;
        float boxStartY = CursorY;
        float contentOffsetX = boxX + borderLeft + paddingLeft;

        // Percentage paddings are resolved now so the renderer sees absolute values.
        ComputedStyle boxStyle = style;
        if (CssLength.IsPercent(style.Padding.Left) || CssLength.IsPercent(style.Padding.Right) || CssLength.IsPercent(style.Padding.Top) || CssLength.IsPercent(style.Padding.Bottom))
        {
            boxStyle = style.Clone();
            boxStyle.Padding = new Thickness(paddingTop, paddingRight, paddingBottom, paddingLeft);
        }

        var box = new LayoutBox
        {
            Type = LayoutBoxType.Block,
            Node = node,
            Style = boxStyle,
            X = boxX,
            Y = boxStartY,
            Width = contentWidth,
            Height = 0,
        };

        // Add the block box BEFORE children so its background renders behind them.
        PageBox startPage = _currentPage;
        int startIndex = startPage.Boxes.Count;
        startPage.Boxes.Add(box);
        int floatsBefore = _floats.Count;

        CursorY += borderTop + paddingTop;
        float childStartY = CursorY;

        if (marker is not null && style.ListStyleInside)
        {
            _pendingIndent = MeasureMarker(marker, style) + (style.FontSize * 0.3f);
        }

        switch (style.Display)
        {
            case DisplayType.Flex:
                LayoutFlexChildren(node, contentWidth, contentOffsetX);
                break;
            case DisplayType.Grid:
                LayoutGridChildren(node, contentWidth, contentOffsetX);
                break;
            default:
                if (ColumnLayout(style, contentWidth) is { } columns)
                {
                    LayoutMultiColumn(node, style, columns, contentOffsetX);
                }
                else
                {
                    LayoutBlockChildren(node, contentWidth, contentOffsetX);
                }

                break;
        }

        _pendingIndent = 0;

        bool samePage = _currentPage == startPage;
        float contentHeight = CursorY - childStartY;
        if (samePage && bfcRoot)
        {
            for (int f = floatsBefore; f < _floats.Count; f++)
            {
                contentHeight = Math.Max(contentHeight, _floats[f].Bottom - childStartY);
            }
        }

        if (samePage)
        {
            float verticalExtras = borderTop + borderBottom + paddingTop + paddingBottom;
            if (ResolveHeight(style.Height, style, verticalExtras) is float explicitHeight)
            {
                // Clipped boxes keep their declared height; visible overflow grows the box instead of overlapping.
                contentHeight = style.ClipsContent ? explicitHeight : Math.Max(contentHeight, explicitHeight);
            }

            if (ResolveHeight(style.MinHeight, style, verticalExtras) is float minHeight)
            {
                contentHeight = Math.Max(contentHeight, minHeight);
            }

            if (ResolveHeight(style.MaxHeight, style, verticalExtras) is float maxHeight && contentHeight > maxHeight && style.ClipsContent)
            {
                contentHeight = maxHeight;
            }

            CursorY = childStartY + contentHeight;
            box.Height = contentHeight;
        }
        else
        {
            SplitBlockAcrossPages(box, startPage, boxStartY, borderTop + paddingTop, CursorY);
        }

        CursorY += paddingBottom + borderBottom;

        if (marker is not null)
        {
            PlaceMarker(marker, style, startPage, startIndex + 1, contentOffsetX, childStartY);
        }

        if (samePage && style.Position == PositionMode.Relative)
        {
            ShiftBoxes(startPage, startIndex, RelativeOffset(style));
        }

        if (style.Position is PositionMode.Relative or PositionMode.Absolute or PositionMode.Fixed)
        {
            float paddingBoxHeight = samePage ? contentHeight + paddingTop + paddingBottom : _settings.ContentHeight;
            (float dx, float dy) = samePage && style.Position == PositionMode.Relative ? RelativeOffset(style) : (0, 0);
            LayoutPendingAbsolutes(node, new ContainingBlock(
                boxX + borderLeft + dx,
                boxStartY + borderTop + dy,
                contentWidth + paddingLeft + paddingRight,
                paddingBoxHeight,
                startPage));
        }

        if (isHeading && !IsIsolated)
        {
            int bookmarkPage = _pages.IndexOf(startPage);
            if (bookmarkPage < 0)
            {
                bookmarkPage = _pages.Count;
            }

            int level = node.Tag![1] - '0';
            string title = GetTextContent(node);
            if (title.Length > 0)
            {
                _bookmarks.Add(new BookmarkEntry(title, level, bookmarkPage, boxStartY));
            }
        }

        _lastMarginBottom = style.Margin.Bottom;
        CursorY += style.Margin.Bottom;
    }

    /// <summary>Distributes a block's background/border over every page it spans.</summary>
    private void SplitBlockAcrossPages(LayoutBox box, PageBox startPage, float boxStartY, float topExtras, float contentEndOnLastPage)
    {
        float pageHeight = _settings.ContentHeight;
        box.Height = Math.Max(pageHeight - boxStartY - topExtras, 0);
        box.SuppressBottomBorder = true;

        int startIndex = _pages.IndexOf(startPage);
        if (startIndex >= 0)
        {
            for (int p = startIndex + 1; p < _pages.Count; p++)
            {
                LayoutBox middle = box.CloneAt(box.X, 0);
                middle.Height = pageHeight;
                middle.SuppressTopBorder = true;
                middle.SuppressBottomBorder = true;
                _pages[p].Boxes.Insert(0, middle);
            }
        }

        LayoutBox last = box.CloneAt(box.X, 0);
        last.Height = Math.Max(contentEndOnLastPage, 0);
        last.SuppressTopBorder = true;
        last.SuppressBottomBorder = false;
        _currentPage.Boxes.Insert(0, last);
    }

    private static bool IsBlockFormattingContextRoot(ComputedStyle style) =>
        style.OverflowHidden || style.Display is DisplayType.FlowRoot or DisplayType.Flex or DisplayType.Grid or DisplayType.InlineBlock or DisplayType.Table
        || style.Float != FloatMode.None || style.Position is PositionMode.Absolute or PositionMode.Fixed;

    /// <summary>
    /// Returns the node's style with percentage margins/paddings and math functions resolved
    /// against <paramref name="containerWidth"/>. The cascaded style is kept as a template so
    /// the node can be laid out again at another width (intrinsic sizing probes).
    /// </summary>
    private ComputedStyle StyleFor(HtmlNode node, float containerWidth, float? containerHeight = null)
    {
        ComputedStyle? template = node.CalcTemplate ?? node.ComputedStyle;
        if (template is null)
        {
            return new ComputedStyle();
        }

        if (!StyleResolver.DependsOnContainer(template))
        {
            return template;
        }

        node.CalcTemplate = template;
        node.ComputedStyle = StyleResolver.ResolveCalcs(template, containerWidth, containerHeight ?? _settings.ContentHeight);
        return node.ComputedStyle;
    }

    private static float ResolvePercent(float value, float reference) => CssLength.Resolve(value, reference);

    /// <summary>Resolves a width property to a content-box width (null for auto).</summary>
    private static float? ResolveWidth(float? value, ComputedStyle style, float reference, float horizontalExtras)
    {
        if (value is not float width)
        {
            return null;
        }

        float resolved = CssLength.Resolve(width, reference);
        if (style.BoxSizing == BoxSizing.BorderBox)
        {
            resolved -= horizontalExtras;
        }

        return Math.Max(0, resolved);
    }

    private static float? ResolveHeight(float? value, ComputedStyle style, float verticalExtras)
    {
        if (value is not float height || height < 0 || CssLength.IsPercent(height))
        {
            return null;
        }

        return style.BoxSizing == BoxSizing.BorderBox ? Math.Max(0, height - verticalExtras) : height;
    }

    private float MeasureBlockHeight(HtmlNode node, float availableWidth) =>
        LayoutBoxIsolated(node, availableWidth, ignoreExplicitWidth: false).Height;

    private void LayoutHorizontalRule(HtmlNode node, float availableWidth, float offsetX)
    {
        ComputedStyle style = StyleFor(node, availableWidth);
        float hrHeight = style.Border.TopWidth > 0 ? style.Border.TopWidth : 1;
        float collapsed = Math.Max(style.Margin.Top, _lastMarginBottom) - _lastMarginBottom;
        CursorY += collapsed;
        _lastMarginBottom = 0;
        EnsureSpace(hrHeight);

        float width = ResolveWidth(style.Width, style, availableWidth, 0) is float w ? Math.Min(w, availableWidth) : availableWidth;
        float x = offsetX;
        if (width < availableWidth && style.MarginLeftAuto)
        {
            x += style.MarginRightAuto ? (availableWidth - width) / 2 : availableWidth - width;
        }

        var box = new LayoutBox
        {
            Type = LayoutBoxType.HorizontalRule,
            Node = node,
            Style = style,
            X = x,
            Y = CursorY,
            Width = width,
            Height = hrHeight,
        };
        _currentPage.Boxes.Add(box);

        CursorY += hrHeight + style.Margin.Bottom;
        _lastMarginBottom = style.Margin.Bottom;
    }

    private void LayoutBlockImage(HtmlNode node, float availableWidth, float offsetX)
    {
        ComputedStyle style = StyleFor(node, availableWidth);
        float collapsed = Math.Max(style.Margin.Top, _lastMarginBottom) - _lastMarginBottom;
        CursorY += collapsed;
        _lastMarginBottom = 0;

        AtomicInline? image = CreateImageAtomic(node, style, availableWidth, null, includeVerticalMargins: false);
        if (image is null)
        {
            return;
        }

        EnsureSpace(image.Height);
        float x = offsetX;
        float free = availableWidth - image.Width;
        if (free > 0 && style.MarginLeftAuto)
        {
            x += style.MarginRightAuto ? free / 2 : free;
        }
        else if (free > 0 && node.Parent?.ComputedStyle?.EffectiveTextAlign is TextAlign.Center && !IsMeasuring)
        {
            x += free / 2;
        }
        else if (free > 0 && node.Parent?.ComputedStyle?.EffectiveTextAlign is TextAlign.Right && !IsMeasuring)
        {
            x += free;
        }

        foreach (LayoutBox b in image.Boxes)
        {
            _currentPage.Boxes.Add(b.CloneAt(b.X + x, b.Y + CursorY));
        }

        CursorY += image.Height + style.Margin.Bottom;
        _lastMarginBottom = style.Margin.Bottom;
    }

    // ── Isolated layout & measurement ────────────────────────────────────

    /// <summary>Lays out the children of a container on an unbounded page; boxes are relative to (0,0).</summary>
    internal IsolatedResult LayoutChildrenIsolated(HtmlNode container, float contentWidth)
    {
        LayoutEngine engine = CreateIsolated(IsMeasuring);
        engine.LayoutBlockChildren(container, contentWidth, 0);
        return engine.FinishIsolated();
    }

    /// <summary>Lays out a node as a block box of the given outer width on an unbounded page.</summary>
    internal IsolatedResult LayoutBoxIsolated(HtmlNode node, float outerWidth, bool ignoreExplicitWidth = true)
    {
        LayoutEngine engine = CreateIsolated(IsMeasuring);
        engine.LayoutAsBox(node, outerWidth, ignoreExplicitWidth);
        return engine.FinishIsolated();
    }

    private void LayoutAsBox(HtmlNode node, float outerWidth, bool ignoreExplicitWidth)
    {
        ComputedStyle style = StyleFor(node, outerWidth);
        if (style.Display == DisplayType.Table || node.Tag == "table")
        {
            TableLayoutHelper.Layout(this, node, outerWidth, 0);
        }
        else if (IsReplaced(node))
        {
            LayoutBlockImage(node, outerWidth, 0);
        }
        else if (node.NodeType == HtmlNodeType.Text)
        {
            LayoutInlineContent(node.Parent!, node.Parent!.Children.IndexOf(node), node.Parent.Children.IndexOf(node) + 1, outerWidth, 0, false);
        }
        else
        {
            LayoutBlock(node, outerWidth, 0, ignoreExplicitWidth);
        }
    }

    private LayoutEngine CreateIsolated(bool measuring)
    {
        var settings = new PageSettings
        {
            PageWidth = MaxContentProbeWidth * 10,
            PageHeight = UnboundedHeight,
            Margins = Thickness.Zero,
        };
        return new LayoutEngine(settings, _shared, isolated: true, measuring);
    }

    private IsolatedResult FinishIsolated()
    {
        LayoutPendingAbsolutes(null, new ContainingBlock(0, 0, _settings.ContentWidth, CursorY, _currentPage), flushAll: true);
        float height = CursorY;
        foreach (FloatBox f in _floats)
        {
            height = Math.Max(height, f.Bottom);
        }

        return new IsolatedResult(_currentPage.Boxes, Math.Max(height, 0));
    }

    /// <summary>Computes min-content and max-content widths of a node (as a box when <paramref name="asBox"/> is true).</summary>
    internal (float Min, float Max) MeasureIntrinsic(HtmlNode node, bool asBox)
    {
        var key = (node, asBox);
        if (_shared.IntrinsicCache.TryGetValue(key, out var cached))
        {
            return cached;
        }

        ComputedStyle style = node.ComputedStyle ?? new ComputedStyle();
        (float Min, float Max) result;
        if (asBox && style.Width is float fixedWidth && fixedWidth > 0)
        {
            float extras = style.Border.LeftWidth + style.Border.RightWidth + Math.Max(0, style.Padding.Left) + Math.Max(0, style.Padding.Right);
            float outer = (style.BoxSizing == BoxSizing.BorderBox ? fixedWidth : fixedWidth + extras)
                + Math.Max(0, style.Margin.Left) + Math.Max(0, style.Margin.Right);
            result = (outer, outer);
        }
        else
        {
            float min = MeasureExtent(node, asBox, MinContentProbeWidth);
            float max = MeasureExtent(node, asBox, MaxContentProbeWidth);
            if (asBox)
            {
                // Leaf extents already include the left-side offsets; add the right side.
                float rightExtras = Math.Max(0, style.Margin.Right) + style.Border.RightWidth + Math.Max(0, style.Padding.Right);
                min += rightExtras;
                max += rightExtras;
            }

            // A hair of slack so the content laid out at exactly max-content does not wrap from rounding.
            result = (min + 0.01f, Math.Max(min, max) + 0.02f);
        }

        _shared.IntrinsicCache[key] = result;
        return result;
    }

    private float MeasureExtent(HtmlNode node, bool asBox, float probeWidth)
    {
        LayoutEngine engine = CreateIsolated(measuring: true);
        if (asBox)
        {
            engine.LayoutAsBox(node, probeWidth, ignoreExplicitWidth: true);
        }
        else
        {
            engine.LayoutBlockChildren(node, probeWidth, 0);
        }

        float extent = 0;
        foreach (LayoutBox box in engine._currentPage.Boxes)
        {
            float right = box.Type switch
            {
                LayoutBoxType.Block when box.Style.Width is > 0 => box.X + BorderBoxWidth(box),
                LayoutBoxType.Block or LayoutBoxType.HorizontalRule or LayoutBoxType.ListMarker => 0,
                _ => box.X + box.Width,
            };
            extent = Math.Max(extent, right);
        }

        foreach (FloatBox f in engine._floats)
        {
            extent = Math.Max(extent, f.X + f.Width);
        }

        return extent;
    }

    private static float BorderBoxWidth(LayoutBox box) =>
        box.Style.Border.LeftWidth + Math.Max(0, box.Style.Padding.Left) + box.Width + Math.Max(0, box.Style.Padding.Right) + box.Style.Border.RightWidth;

    /// <summary>Shrink-to-fit width: min(max(min-content, available), max-content).</summary>
    internal float ShrinkToFit(HtmlNode node, float available)
    {
        (float min, float max) = MeasureIntrinsic(node, asBox: true);
        return Math.Max(min, Math.Min(max, available));
    }

    // ── Placement helpers ────────────────────────────────────────────────

    internal void AddBox(LayoutBox box) => _currentPage.Boxes.Add(box);

    internal void NewPage() => StartNewPage();


    /// <summary>Collapses a top margin against the previous sibling's bottom margin and advances the cursor.</summary>
    internal void ApplyTopMargin(float marginTop)
    {
        CursorY += Math.Max(marginTop, _lastMarginBottom) - _lastMarginBottom;
        _lastMarginBottom = 0;
    }

    /// <summary>Records a bottom margin for collapsing with the next sibling and advances the cursor.</summary>
    internal void ApplyBottomMargin(float marginBottom)
    {
        CursorY += marginBottom;
        _lastMarginBottom = marginBottom;
    }

    /// <summary>Translates isolated boxes into the current page.</summary>
    internal void PlaceBoxes(IEnumerable<LayoutBox> boxes, float dx, float dy)
    {
        foreach (LayoutBox box in boxes)
        {
            box.X += dx;
            box.Y += dy;
            _currentPage.Boxes.Add(box);
        }
    }

    /// <summary>
    /// Places isolated content of the given height at the cursor, splitting it across pages between leaf boxes.
    /// Containers crossing a break are cut into per-page segments. Advances the cursor.
    /// </summary>
    internal void PlaceFragmented(List<LayoutBox> boxes, float height, float dx)
    {
        float sliceTop = 0;
        int guard = 0;
        while (true)
        {
            float available = _settings.ContentHeight - CursorY;
            if (IsIsolated || height - sliceTop <= available + 0.01f || guard++ > 10_000)
            {
                PlaceSlice(boxes, sliceTop, float.MaxValue, dx);
                CursorY += height - sliceTop;
                return;
            }

            float sliceBottom = sliceTop + available;
            bool moved = true;
            while (moved)
            {
                moved = false;
                foreach (LayoutBox box in boxes)
                {
                    if (box.Type == LayoutBoxType.Block)
                    {
                        continue;
                    }

                    float bottom = box.Y + box.Height;
                    if (box.Y < sliceBottom && bottom > sliceBottom + 0.01f && box.Y > sliceTop)
                    {
                        sliceBottom = box.Y;
                        moved = true;
                    }
                }
            }

            if (sliceBottom <= sliceTop + 0.5f)
            {
                if (CursorY > 0)
                {
                    StartNewPage();
                    continue;
                }

                sliceBottom = sliceTop + available;
            }

            PlaceSlice(boxes, sliceTop, sliceBottom, dx);
            StartNewPage();
            sliceTop = sliceBottom;
        }
    }

    private void PlaceSlice(List<LayoutBox> boxes, float sliceTop, float sliceBottom, float dx)
    {
        float baseY = CursorY;
        foreach (LayoutBox box in boxes)
        {
            if (box.Type == LayoutBoxType.Block)
            {
                ComputedStyle s = box.Style;
                float topExtras = box.SuppressTopBorder ? 0 : s.Border.TopWidth + Math.Max(0, s.Padding.Top);
                float bottomExtras = box.SuppressBottomBorder ? 0 : s.Border.BottomWidth + Math.Max(0, s.Padding.Bottom);
                float top = box.Y;
                float bottom = box.Y + topExtras + box.Height + bottomExtras;
                if (bottom <= sliceTop || top >= sliceBottom)
                {
                    continue;
                }

                float segTop = Math.Max(top, sliceTop);
                float segBottom = Math.Min(bottom, sliceBottom);
                LayoutBox segment = box.CloneAt(box.X + dx, baseY + segTop - sliceTop);
                segment.SuppressTopBorder = box.SuppressTopBorder || top < sliceTop;
                segment.SuppressBottomBorder = box.SuppressBottomBorder || bottom > sliceBottom;
                float segTopExtras = segment.SuppressTopBorder ? 0 : topExtras;
                float segBottomExtras = segment.SuppressBottomBorder ? 0 : bottomExtras;
                segment.Height = Math.Max(0, segBottom - segTop - segTopExtras - segBottomExtras);
                _currentPage.Boxes.Add(segment);
                continue;
            }

            if (box.Y >= sliceTop - 0.01f && box.Y < sliceBottom)
            {
                _currentPage.Boxes.Add(box.CloneAt(box.X + dx, baseY + box.Y - sliceTop));
            }
        }
    }

    private static void ShiftBoxes(PageBox page, int startIndex, (float Dx, float Dy) offset)
    {
        if (offset.Dx == 0 && offset.Dy == 0)
        {
            return;
        }

        for (int i = startIndex; i < page.Boxes.Count; i++)
        {
            page.Boxes[i].X += offset.Dx;
            page.Boxes[i].Y += offset.Dy;
        }
    }

    private static (float Dx, float Dy) RelativeOffset(ComputedStyle style)
    {
        float dx = style.Left is float left && !CssLength.IsPercent(left) ? left : style.Right is float right && !CssLength.IsPercent(right) ? -right : 0;
        float dy = style.Top is float top && !CssLength.IsPercent(top) ? top : style.Bottom is float bottom && !CssLength.IsPercent(bottom) ? -bottom : 0;
        return (dx, dy);
    }

    // ── Text helpers ─────────────────────────────────────────────────────

    private static string GetTextContent(HtmlNode node)
    {
        if (node.NodeType == HtmlNodeType.Text)
        {
            return node.Text ?? string.Empty;
        }

        var sb = new System.Text.StringBuilder();
        foreach (HtmlNode child in node.Children)
        {
            if (child.IsPseudo)
            {
                continue;
            }

            string childText = GetTextContent(child);
            if (childText.Length > 0)
            {
                if (sb.Length > 0 && sb[^1] != ' ')
                {
                    sb.Append(' ');
                }

                sb.Append(childText);
            }
        }

        return string.Join(' ', sb.ToString().Split([' ', '\t', '\r', '\n'], StringSplitOptions.RemoveEmptyEntries));
    }

    // ── Pages ────────────────────────────────────────────────────────────

    private void EnsureSpace(float height)
    {
        if (!IsIsolated && CursorY > 0 && CursorY + height > _settings.ContentHeight)
        {
            StartNewPage();
        }
    }

    /// <summary>Starts a new page when the content does not fit in the remaining space (and would fit on a page).</summary>
    internal void EnsureSpaceFor(float height)
    {
        if (height <= _settings.ContentHeight)
        {
            EnsureSpace(height);
        }
    }

    private void ForcePageBreak()
    {
        if (IsIsolated)
        {
            return;
        }

        if (CursorY > 0 || _currentPage.Boxes.Count > 0)
        {
            StartNewPage();
        }
    }

    private void StartNewPage()
    {
        if (IsIsolated)
        {
            return;
        }

        FlushCurrentPage(force: true);
        _currentPage = CreateNewPage();
        _floats.Clear();
    }

    private void FlushCurrentPage(bool force = false)
    {
        if ((force || _currentPage.Boxes.Count > 0) && !_pages.Contains(_currentPage))
        {
            _pages.Add(_currentPage);
        }
    }

    private PageBox CreateNewPage()
    {
        CursorY = 0;
        _lastMarginBottom = 0;
        return new PageBox
        {
            PageNumber = _pages.Count + 1,
            Settings = _settings,
        };
    }

    /// <summary>State shared by the main engine and the isolated engines it creates.</summary>
    private sealed class SharedState(FontCollection? fonts, ResourceLoader loader)
    {
        internal FontCollection? Fonts { get; } = fonts;

        internal ResourceLoader Loader { get; } = loader;

        internal Dictionary<(HtmlNode Node, bool AsBox), (float Min, float Max)> IntrinsicCache { get; } = [];

        internal Dictionary<string, HtmlNode?> SvgImages { get; } = new(StringComparer.Ordinal);
    }
}

/// <summary>Boxes produced by an isolated layout, relative to its origin, and the total height.</summary>
/// <param name="Boxes">Laid-out boxes.</param>
/// <param name="Height">Total height including floats.</param>
internal sealed record IsolatedResult(List<LayoutBox> Boxes, float Height);

/// <summary>List marker to render next to a list item.</summary>
/// <param name="Text">Marker text for textual markers.</param>
/// <param name="Shape">Graphical shape.</param>
internal sealed record MarkerInfo(string? Text, MarkerShape Shape);

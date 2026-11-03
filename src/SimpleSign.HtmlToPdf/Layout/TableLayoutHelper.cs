// Licensed to SimpleSign under the MIT License.

using System.Globalization;
using SimpleSign.HtmlToPdf.Parsing;

namespace SimpleSign.HtmlToPdf.Layout;

/// <summary>
/// Lays out HTML tables: automatic and fixed column sizing (min/max-content), colspan/rowspan,
/// separated and collapsed borders, any block content inside cells, and pagination that keeps rows
/// (and rowspan groups) together and repeats the table header on every page.
/// </summary>
internal static class TableLayoutHelper
{
    /// <summary>Lays out a table element at the engine's cursor and advances it.</summary>
    internal static void Layout(LayoutEngine engine, HtmlNode tableNode, float availableWidth, float offsetX)
    {
        ComputedStyle tableStyle = tableNode.ComputedStyle ?? new ComputedStyle();
        engine.ApplyTopMargin(Math.Max(0, tableStyle.Margin.Top));

        var model = TableModel.Build(tableNode);
        bool collapse = tableStyle.BorderCollapse;
        float spacing = collapse ? 0 : tableStyle.BorderSpacing;

        float marginLeft = Math.Max(0, Resolve(tableStyle.Margin.Left, availableWidth));
        float marginRight = Math.Max(0, Resolve(tableStyle.Margin.Right, availableWidth));
        float borderL = collapse ? 0 : tableStyle.Border.LeftWidth;
        float borderR = collapse ? 0 : tableStyle.Border.RightWidth;
        float borderT = collapse ? 0 : tableStyle.Border.TopWidth;
        float borderB = collapse ? 0 : tableStyle.Border.BottomWidth;
        float padL = collapse ? 0 : Math.Max(0, tableStyle.Padding.Left);
        float padR = collapse ? 0 : Math.Max(0, tableStyle.Padding.Right);
        float padT = collapse ? 0 : Math.Max(0, tableStyle.Padding.Top);
        float padB = collapse ? 0 : Math.Max(0, tableStyle.Padding.Bottom);
        int columns = model.ColumnCount;

        float frameWidth = borderL + borderR + padL + padR + (columns > 0 ? spacing * (columns + 1) : 0);
        float outerAvailable = Math.Max(0, availableWidth - marginLeft - marginRight);

        float[] colWidths = columns > 0
            ? ComputeColumnWidths(engine, model, tableStyle, outerAvailable, frameWidth, collapse)
            : [];
        float tableWidth = colWidths.Sum() + frameWidth;

        // A caption widens an auto-sized table up to the caption's preferred width.
        if (model.Caption is { } widthCaption && columns > 0 && tableStyle.Width is null && widthCaption.ComputedStyle?.Display != DisplayType.None)
        {
            float captionWidth = Math.Min(engine.MeasureIntrinsic(widthCaption, asBox: true).Max, outerAvailable);
            if (captionWidth > tableWidth)
            {
                float columnsWidth = colWidths.Sum();
                float extra = captionWidth - tableWidth;
                for (int c = 0; c < columns; c++)
                {
                    colWidths[c] += columnsWidth > 0 ? extra * colWidths[c] / columnsWidth : extra / columns;
                }

                tableWidth = captionWidth;
            }
        }

        if (columns == 0 && tableStyle.Width is float emptyWidth)
        {
            tableWidth = Resolve(emptyWidth, outerAvailable);
        }

        float tableX = offsetX + marginLeft;
        float free = outerAvailable - tableWidth;
        if (free > 0 && !engine.IsMeasuring)
        {
            if (tableStyle.MarginLeftAuto && tableStyle.MarginRightAuto)
            {
                tableX += free / 2;
            }
            else if (tableStyle.MarginLeftAuto)
            {
                tableX += free;
            }
        }

        // Caption above the table.
        if (model.Caption is { } caption && caption.ComputedStyle?.Display != DisplayType.None)
        {
            IsolatedResult captionLayout = engine.LayoutBoxIsolated(caption, tableWidth);
            engine.EnsureSpaceFor(captionLayout.Height);
            engine.PlaceBoxes(captionLayout.Boxes, tableX, engine.CursorY);
            engine.CursorY += captionLayout.Height;
        }

        if (columns == 0)
        {
            engine.ApplyBottomMargin(Math.Max(0, tableStyle.Margin.Bottom));
            return;
        }

        float[] colOffsets = new float[columns + 1];
        float contentLeft = tableX + borderL + padL;
        float x = spacing;
        for (int c = 0; c < columns; c++)
        {
            colOffsets[c] = x;
            x += colWidths[c] + spacing;
        }

        colOffsets[columns] = x;

        // Lay out every cell's content once.
        var cellLayouts = new Dictionary<CellInfo, CellLayout>();
        foreach (CellInfo cell in model.Cells)
        {
            ComputedStyle cs = cell.Node.ComputedStyle ?? new ComputedStyle();
            float cellWidth = colOffsets[cell.Col + cell.ColSpan] - colOffsets[cell.Col] - spacing;
            (float bl, float br, float bt, float bb) = CellBorders(cs, collapse);
            float pl = Math.Max(0, Resolve(cs.Padding.Left, cellWidth));
            float pr = Math.Max(0, Resolve(cs.Padding.Right, cellWidth));
            float pt = Math.Max(0, Resolve(cs.Padding.Top, cellWidth));
            float pb = Math.Max(0, Resolve(cs.Padding.Bottom, cellWidth));
            float contentWidth = Math.Max(0, cellWidth - bl - br - pl - pr);
            IsolatedResult content = engine.LayoutChildrenIsolated(cell.Node, contentWidth);
            float height = content.Height + bt + bb + pt + pb;
            if (cs.Height is float explicitHeight && explicitHeight > 0)
            {
                height = Math.Max(height, cs.BoxSizing == BoxSizing.BorderBox ? explicitHeight : explicitHeight + bt + bb + pt + pb);
            }

            cellLayouts[cell] = new CellLayout(cell, cs, cellWidth, content, height, bl, bt, pl, pt, pb, bb);
        }

        // Row heights (rowspan cells grow the last row they span).
        int rowCount = model.Rows.Count;
        float[] rowHeights = new float[rowCount];
        for (int r = 0; r < rowCount; r++)
        {
            ComputedStyle rowStyle = model.Rows[r].Node.ComputedStyle ?? new ComputedStyle();
            if (rowStyle.Height is float rowHeight && rowHeight > 0)
            {
                rowHeights[r] = rowHeight;
            }
        }

        foreach (CellLayout layout in cellLayouts.Values.Where(l => l.Cell.RowSpan == 1))
        {
            rowHeights[layout.Cell.Row] = Math.Max(rowHeights[layout.Cell.Row], layout.Height);
        }

        foreach (CellLayout layout in cellLayouts.Values.Where(l => l.Cell.RowSpan > 1).OrderBy(l => l.Cell.RowSpan))
        {
            int last = layout.Cell.Row + layout.Cell.RowSpan - 1;
            float have = 0;
            for (int r = layout.Cell.Row; r <= last; r++)
            {
                have += rowHeights[r];
            }

            have += spacing * (layout.Cell.RowSpan - 1);
            if (layout.Height > have)
            {
                rowHeights[last] += layout.Height - have;
            }
        }

        var emitter = new TableEmitter(engine, model, tableStyle, cellLayouts, rowHeights, colOffsets, spacing, collapse,
            tableX, tableWidth, contentLeft, borderT + padT, borderB + padB);
        emitter.Emit();
        engine.ApplyBottomMargin(Math.Max(0, tableStyle.Margin.Bottom));
    }

    private static (float Left, float Right, float Top, float Bottom) CellBorders(ComputedStyle style, bool collapse)
    {
        BorderStyle b = style.Border;
        return collapse
            ? (b.LeftWidth / 2, b.RightWidth / 2, b.TopWidth / 2, b.BottomWidth / 2)
            : (b.LeftWidth, b.RightWidth, b.TopWidth, b.BottomWidth);
    }

    private static float Resolve(float value, float reference) => CssLength.Resolve(value, reference);

    // ── Column sizing ────────────────────────────────────────────────────

    private static float[] ComputeColumnWidths(LayoutEngine engine, TableModel model, ComputedStyle tableStyle, float outerAvailable, float frameWidth, bool collapse)
    {
        int n = model.ColumnCount;
        float[] min = new float[n];
        float[] max = new float[n];
        float[] fixedWidth = new float[n];
        float[] percent = new float[n];

        // <col>/<colgroup> widths.
        for (int c = 0; c < n && c < model.ColumnStyles.Count; c++)
        {
            if (model.ColumnStyles[c]?.Width is float colWidth)
            {
                if (CssLength.IsPercent(colWidth))
                {
                    percent[c] = Math.Max(0, CssLength.PercentOf(colWidth));
                }
                else
                {
                    fixedWidth[c] = colWidth;
                }
            }
        }

        float? tableSpec = tableStyle.Width is float tw ? Resolve(tw, outerAvailable) : null;
        float specContent = tableSpec is float spec ? Math.Max(0, spec - frameWidth) : 0;

        // Single-column cells first.
        foreach (CellInfo cell in model.Cells.OrderBy(c => c.ColSpan))
        {
            ComputedStyle cs = cell.Node.ComputedStyle ?? new ComputedStyle();
            (float bl, float br, _, _) = CellBorders(cs, collapse);
            float extras = bl + br + Math.Max(0, cs.Padding.Left) + Math.Max(0, cs.Padding.Right);
            (float cellMin, float cellMax) = engine.MeasureIntrinsic(cell.Node, asBox: false);
            cellMin += extras;
            cellMax += extras;
            if (cs.WhiteSpace == WhiteSpaceMode.NoWrap)
            {
                cellMin = cellMax;
            }

            if (cell.ColSpan == 1)
            {
                int c = cell.Col;
                if (cs.Width is float w)
                {
                    if (CssLength.IsPercent(w))
                    {
                        percent[c] = Math.Max(percent[c], CssLength.PercentOf(w));
                    }
                    else
                    {
                        float outer = cs.BoxSizing == BoxSizing.BorderBox ? w : w + extras;
                        fixedWidth[c] = Math.Max(fixedWidth[c], outer);
                        cellMax = Math.Max(cellMax, outer);
                    }
                }

                min[c] = Math.Max(min[c], cellMin);
                max[c] = Math.Max(max[c], cellMax);
                continue;
            }

            // Spanning cells: spread any excess evenly over the spanned columns.
            float spanSpacing = (cell.ColSpan - 1) * (collapse ? 0 : tableStyle.BorderSpacing);
            float spanMin = 0;
            float spanMax = 0;
            for (int c = cell.Col; c < cell.Col + cell.ColSpan; c++)
            {
                spanMin += min[c];
                spanMax += max[c];
            }

            float minExcess = cellMin - spanSpacing - spanMin;
            float maxExcess = cellMax - spanSpacing - spanMax;
            for (int c = cell.Col; c < cell.Col + cell.ColSpan; c++)
            {
                if (minExcess > 0)
                {
                    min[c] += minExcess / cell.ColSpan;
                }

                if (maxExcess > 0)
                {
                    max[c] += maxExcess / cell.ColSpan;
                }
            }
        }

        for (int c = 0; c < n; c++)
        {
            max[c] = Math.Max(max[c], min[c]);
        }

        float sumMin = min.Sum();
        float sumMax = max.Sum();
        float available = Math.Max(0, outerAvailable - frameWidth);

        // Target width of the columns area.
        float target;
        if (tableSpec is not null)
        {
            target = Math.Max(specContent, sumMin);
        }
        else
        {
            float percentTotal = percent.Sum();
            float wanted = sumMax;
            if (percentTotal > 0 && percentTotal < 100)
            {
                // A percentage column implies a minimum table width.
                for (int c = 0; c < n; c++)
                {
                    if (percent[c] > 0)
                    {
                        wanted = Math.Max(wanted, max[c] * 100f / percent[c]);
                    }
                }
            }
            else if (percentTotal >= 100)
            {
                wanted = available;
            }

            target = Math.Max(sumMin, Math.Min(available, wanted));
        }

        if (engine.IsMeasuring)
        {
            target = tableSpec is not null ? Math.Max(specContent, sumMin) : (available < 1 ? sumMin : Math.Min(sumMax, Math.Max(sumMin, available)));
        }

        if (target <= sumMin || sumMin <= 0 && sumMax <= 0)
        {
            if (sumMin <= 0)
            {
                return [.. Enumerable.Repeat(target / n, n)];
            }

            // Not even min-content fits: shrink proportionally (content may wrap harder / overflow cells).
            float scale = sumMin > 0 && target < sumMin && !engine.IsMeasuring && target >= available - 0.01f ? target / sumMin : 1;
            return [.. min.Select(m => m * scale)];
        }

        // Start at min-content; satisfy fixed and percentage columns; then grow auto columns toward max-content.
        float[] widths = [.. min];
        float remaining = target - sumMin;
        for (int c = 0; c < n && remaining > 0; c++)
        {
            float want = percent[c] > 0 ? target * percent[c] / 100f : fixedWidth[c];
            float grow = Math.Max(0, want - widths[c]);
            float take = Math.Min(grow, remaining);
            widths[c] += take;
            remaining -= take;
        }

        bool[] isAuto = new bool[n];
        for (int c = 0; c < n; c++)
        {
            isAuto[c] = percent[c] <= 0 && fixedWidth[c] <= 0;
        }

        float autoRange = 0;
        for (int c = 0; c < n; c++)
        {
            if (isAuto[c])
            {
                autoRange += Math.Max(0, max[c] - widths[c]);
            }
        }

        if (remaining > 0 && autoRange > 0)
        {
            float share = Math.Min(1, remaining / autoRange);
            for (int c = 0; c < n; c++)
            {
                if (isAuto[c])
                {
                    float grow = Math.Max(0, max[c] - widths[c]) * share;
                    widths[c] += grow;
                    remaining -= grow;
                }
            }
        }

        if (remaining > 0.01f)
        {
            // Extra space (explicit table width wider than content): distribute to auto columns by max-content,
            // or to all columns when every column is constrained.
            int[] receivers = [.. Enumerable.Range(0, n).Where(c => isAuto[c])];
            if (receivers.Length == 0)
            {
                receivers = [.. Enumerable.Range(0, n)];
            }

            float weightTotal = receivers.Sum(c => Math.Max(widths[c], 1));
            foreach (int c in receivers)
            {
                widths[c] += remaining * Math.Max(widths[c], 1) / weightTotal;
            }
        }

        return widths;
    }

    // ── Model ────────────────────────────────────────────────────────────

    /// <summary>A cell placed in the table grid.</summary>
    internal sealed record CellInfo(HtmlNode Node, int Row, int Col, int ColSpan, int RowSpan);

    /// <summary>A table row with its section (thead/tbody/tfoot).</summary>
    internal sealed record RowInfo(HtmlNode Node, HtmlNode? Group, RowSection Section, List<HtmlNode> Cells);

    internal enum RowSection
    {
        Header,
        Body,
        Footer,
    }

    private sealed record CellLayout(CellInfo Cell, ComputedStyle Style, float Width, IsolatedResult Content, float Height,
        float BorderLeft, float BorderTop, float PaddingLeft, float PaddingTop, float PaddingBottom, float BorderBottom);

    /// <summary>Structural model of a table: rows in render order (header, body, footer) and the cell grid.</summary>
    private sealed class TableModel
    {
        internal List<RowInfo> Rows { get; } = [];

        internal List<CellInfo> Cells { get; } = [];

        internal List<ComputedStyle?> ColumnStyles { get; } = [];

        internal HtmlNode? Caption { get; private set; }

        internal int ColumnCount { get; private set; }

        internal int HeaderRowCount => Rows.Count(r => r.Section == RowSection.Header);

        internal int FooterRowCount => Rows.Count(r => r.Section == RowSection.Footer);

        internal static TableModel Build(HtmlNode table)
        {
            var model = new TableModel();
            var header = new List<RowInfo>();
            var body = new List<RowInfo>();
            var footer = new List<RowInfo>();

            foreach (HtmlNode child in table.Children)
            {
                if (child.NodeType != HtmlNodeType.Element || child.ComputedStyle?.Display == DisplayType.None)
                {
                    continue;
                }

                switch (child.Tag)
                {
                    case "caption":
                        model.Caption ??= child;
                        break;
                    case "colgroup":
                        foreach (HtmlNode col in child.Children.Where(c => c.Tag == "col"))
                        {
                            AddColumnStyles(model, col);
                        }

                        if (!child.Children.Any(c => c.Tag == "col"))
                        {
                            AddColumnStyles(model, child);
                        }

                        break;
                    case "col":
                        AddColumnStyles(model, child);
                        break;
                    case "thead":
                        AddRows(child, header.Count == 0 ? header : body, header.Count == 0 ? RowSection.Header : RowSection.Body);
                        break;
                    case "tfoot":
                        AddRows(child, footer, RowSection.Footer);
                        break;
                    case "tbody":
                        AddRows(child, body, RowSection.Body);
                        break;
                    case "tr":
                        AddRow(child, null, body, RowSection.Body);
                        break;
                }
            }

            model.Rows.AddRange(header);
            model.Rows.AddRange(body);
            model.Rows.AddRange(footer.Select(r => r with { Section = RowSection.Footer }));
            model.BuildGrid();
            return model;
        }

        private static void AddColumnStyles(TableModel model, HtmlNode col)
        {
            int span = int.TryParse(col.GetAttribute("span"), NumberStyles.Integer, CultureInfo.InvariantCulture, out int s) && s > 0 ? Math.Min(s, 1000) : 1;
            ComputedStyle? style = col.ComputedStyle;
            if (style is not null && style.Width is null && col.GetAttribute("width") is { } widthAttr)
            {
                string w = widthAttr.Trim();
                style = style.Clone();
                style.Width = w.EndsWith('%') && float.TryParse(w[..^1], NumberStyles.Float, CultureInfo.InvariantCulture, out float pct)
                    ? CssLength.Percent(pct)
                    : CssParser.ParseLength(w);
            }

            for (int i = 0; i < span; i++)
            {
                model.ColumnStyles.Add(style);
            }
        }

        private static void AddRows(HtmlNode group, List<RowInfo> target, RowSection section)
        {
            foreach (HtmlNode row in group.Children)
            {
                if (row.Tag == "tr" && row.ComputedStyle?.Display != DisplayType.None)
                {
                    AddRow(row, group, target, section);
                }
            }
        }

        private static void AddRow(HtmlNode row, HtmlNode? group, List<RowInfo> target, RowSection section)
        {
            if (row.ComputedStyle?.Display == DisplayType.None)
            {
                return;
            }

            var cells = row.Children
                .Where(c => c.Tag is "td" or "th" && c.ComputedStyle?.Display != DisplayType.None)
                .ToList();
            target.Add(new RowInfo(row, group, section, cells));
        }

        private void BuildGrid()
        {
            var occupied = new List<bool[]>();
            int maxCols = 0;
            foreach (RowInfo row in Rows)
            {
                maxCols = Math.Max(maxCols, row.Cells.Sum(c => Span(c, "colspan")));
            }

            maxCols = Math.Max(maxCols, 0);
            for (int r = 0; r < Rows.Count; r++)
            {
                occupied.Add(new bool[maxCols]);
            }

            for (int r = 0; r < Rows.Count; r++)
            {
                int col = 0;
                foreach (HtmlNode cellNode in Rows[r].Cells)
                {
                    while (col < maxCols && occupied[r][col])
                    {
                        col++;
                    }

                    if (col >= maxCols)
                    {
                        break;
                    }

                    int colSpan = Math.Min(Span(cellNode, "colspan"), maxCols - col);
                    int rowSpanAttr = Span(cellNode, "rowspan", allowZero: true);
                    int rowSpan = rowSpanAttr == 0 ? Rows.Count - r : Math.Min(rowSpanAttr, Rows.Count - r);

                    // Rowspans do not cross from the header into the body (or into the footer).
                    int sectionEnd = r;
                    while (sectionEnd + 1 < Rows.Count && Rows[sectionEnd + 1].Section == Rows[r].Section && sectionEnd + 1 < r + rowSpan)
                    {
                        sectionEnd++;
                    }

                    rowSpan = sectionEnd - r + 1;
                    for (int dr = 0; dr < rowSpan; dr++)
                    {
                        for (int dc = 0; dc < colSpan; dc++)
                        {
                            occupied[r + dr][col + dc] = true;
                        }
                    }

                    Cells.Add(new CellInfo(cellNode, r, col, colSpan, rowSpan));
                    col += colSpan;
                }
            }

            ColumnCount = maxCols;
        }

        private static int Span(HtmlNode cell, string attribute, bool allowZero = false)
        {
            if (int.TryParse(cell.GetAttribute(attribute), NumberStyles.Integer, CultureInfo.InvariantCulture, out int span))
            {
                if (span == 0 && allowZero)
                {
                    return 0;
                }

                return Math.Clamp(span, 1, 1000);
            }

            return 1;
        }
    }

    // ── Emission with pagination ─────────────────────────────────────────

    private sealed class TableEmitter(
        LayoutEngine engine,
        TableModel model,
        ComputedStyle tableStyle,
        Dictionary<CellInfo, CellLayout> cells,
        float[] rowHeights,
        float[] colOffsets,
        float spacing,
        bool collapse,
        float tableX,
        float tableWidth,
        float contentLeft,
        float topFrame,
        float bottomFrame)
    {
        private LayoutBox? _segmentBox;
        private float _segmentTop;
        private int _rowsOnSegment;

        internal void Emit()
        {
            int headerCount = model.HeaderRowCount;
            int footerStart = model.Rows.Count - model.FooterRowCount;
            List<(int Start, int End)> groups = BuildGroups(headerCount, model.Rows.Count);
            float headerHeight = GroupHeight(0, headerCount);
            float bodyAndFooterHeight = GroupHeight(headerCount, model.Rows.Count);
            float totalHeight = topFrame + headerHeight + bodyAndFooterHeight + bottomFrame;

            bool canBreak = !engine.IsIsolated;
            if (canBreak && tableStyle.PageBreakInside == PageBreak.Avoid)
            {
                engine.EnsureSpaceFor(totalHeight);
            }

            // Do not leave the header (or the first rows) alone at the bottom of a page.
            float firstChunk = topFrame + headerHeight + (groups.Count > 0 ? GroupHeight(groups[0].Start, groups[0].End) : 0) + spacing;
            if (canBreak && engine.CursorY > 0 && engine.CursorY + firstChunk > engine.PageContentHeight && firstChunk <= engine.PageContentHeight)
            {
                engine.NewPage();
            }

            OpenSegment();
            PlaceRows(0, headerCount);

            foreach ((int start, int end) in groups)
            {
                float groupHeight = GroupHeight(start, end) + spacing;
                bool repeatsHeader = start < footerStart;
                float needed = groupHeight + bottomFrame;
                if (canBreak && _rowsOnSegment > 0 && engine.CursorY + needed > engine.PageContentHeight)
                {
                    CloseSegment();
                    engine.NewPage();
                    OpenSegment();
                    if (repeatsHeader)
                    {
                        PlaceRows(0, headerCount, repeated: true);
                    }
                }

                if (canBreak && engine.CursorY + groupHeight > engine.PageContentHeight)
                {
                    // Taller than a page: split the row group between its contents.
                    List<LayoutBox> boxes = BuildRows(start, end, 0, out float height);
                    CloseSegment(includeBottomFrame: false);
                    engine.PlaceFragmented(boxes, height + spacing, 0);
                    OpenSegment();
                    _rowsOnSegment = 1;
                    continue;
                }

                PlaceRows(start, end);
            }

            CloseSegment();
        }

        private List<(int Start, int End)> BuildGroups(int start, int end)
        {
            var groups = new List<(int, int)>();
            int r = start;
            while (r < end)
            {
                int groupEnd = r + 1;
                for (int k = r; k < groupEnd; k++)
                {
                    foreach (CellLayout cell in cells.Values)
                    {
                        if (cell.Cell.Row == k)
                        {
                            groupEnd = Math.Max(groupEnd, Math.Min(end, cell.Cell.Row + cell.Cell.RowSpan));
                        }
                    }
                }

                groups.Add((r, groupEnd));
                r = groupEnd;
            }

            return groups;
        }

        private float GroupHeight(int start, int end)
        {
            float height = 0;
            for (int r = start; r < end; r++)
            {
                height += rowHeights[r] + spacing;
            }

            return Math.Max(0, height - (end > start ? spacing : 0));
        }

        private void OpenSegment()
        {
            _segmentTop = engine.CursorY;
            _rowsOnSegment = 0;
            _segmentBox = new LayoutBox
            {
                Type = LayoutBoxType.Block,
                Node = null,
                Style = SegmentStyle(),
                X = tableX,
                Y = _segmentTop,
                Width = tableWidth,
                Height = 0,
                BorderCentered = collapse,
            };
            engine.AddBox(_segmentBox);
            engine.CursorY += topFrame + spacing;
        }

        private ComputedStyle SegmentStyle()
        {
            var style = new ComputedStyle
            {
                BackgroundColor = tableStyle.BackgroundColor,
                Border = tableStyle.Border,
                BorderRadius = tableStyle.BorderRadius,
                IsHidden = tableStyle.IsHidden,
            };
            return style;
        }

        private void CloseSegment(bool includeBottomFrame = true)
        {
            if (_segmentBox is null)
            {
                return;
            }

            engine.CursorY += includeBottomFrame ? bottomFrame : 0;
            _segmentBox.Height = Math.Max(0, engine.CursorY - _segmentTop);
            if (_rowsOnSegment == 0 && _segmentBox.Height <= topFrame + spacing + bottomFrame + 0.01f)
            {
                _segmentBox.Style = new ComputedStyle();
            }

            _segmentBox = null;
        }

        private void PlaceRows(int start, int end, bool repeated = false)
        {
            if (end <= start)
            {
                return;
            }

            List<LayoutBox> boxes = BuildRows(start, end, engine.CursorY, out float height);
            foreach (LayoutBox box in boxes)
            {
                engine.AddBox(box);
            }

            engine.CursorY += height + spacing;
            if (!repeated)
            {
                _rowsOnSegment += end - start;
            }
        }

        /// <summary>Builds boxes for rows [start, end) with the first row's top at <paramref name="top"/>.</summary>
        private List<LayoutBox> BuildRows(int start, int end, float top, out float height)
        {
            var background = new List<LayoutBox>();
            var borders = new List<LayoutBox>();
            var content = new List<LayoutBox>();
            float[] rowTops = new float[end - start + 1];
            float y = top;
            for (int r = start; r < end; r++)
            {
                rowTops[r - start] = y;
                y += rowHeights[r] + spacing;
            }

            rowTops[end - start] = y;
            height = y - top - spacing;

            for (int r = start; r < end; r++)
            {
                RowInfo row = model.Rows[r];
                ComputedStyle rowStyle = row.Node.ComputedStyle ?? new ComputedStyle();
                float rowTop = rowTops[r - start];
                if (collapse && rowStyle.Border.HasBorder)
                {
                    borders.Add(new LayoutBox
                    {
                        Type = LayoutBoxType.Block,
                        Node = row.Node,
                        Style = new ComputedStyle { Border = rowStyle.Border },
                        X = contentLeft + colOffsets[0],
                        Y = rowTop,
                        Width = colOffsets[^1] - colOffsets[0] - spacing,
                        Height = rowHeights[r],
                        BorderCentered = true,
                    });
                }
            }

            foreach (CellLayout layout in cells.Values)
            {
                CellInfo cell = layout.Cell;
                if (cell.Row < start || cell.Row >= end)
                {
                    continue;
                }

                int lastRow = Math.Min(cell.Row + cell.RowSpan, end);
                float cellTop = rowTops[cell.Row - start];
                float cellHeight = rowTops[lastRow - start] - cellTop - spacing;
                float cellX = contentLeft + colOffsets[cell.Col];
                float cellWidth = layout.Width;
                RowInfo row = model.Rows[cell.Row];
                ComputedStyle cs = layout.Style;

                PdfColor? bg = Opaque(cs.BackgroundColor) ?? Opaque(row.Node.ComputedStyle?.BackgroundColor) ?? Opaque(row.Group?.ComputedStyle?.BackgroundColor);
                if (bg is PdfColor color && !cs.IsHidden)
                {
                    background.Add(new LayoutBox
                    {
                        Type = LayoutBoxType.Block,
                        Node = cell.Node,
                        Style = new ComputedStyle { BackgroundColor = color, BorderRadius = cs.BorderRadius },
                        X = cellX,
                        Y = cellTop,
                        Width = cellWidth,
                        Height = cellHeight,
                    });
                }

                if (cs.Border.HasBorder && !cs.IsHidden)
                {
                    borders.Add(new LayoutBox
                    {
                        Type = LayoutBoxType.Block,
                        Node = cell.Node,
                        Style = new ComputedStyle { Border = cs.Border, BorderRadius = collapse ? 0 : cs.BorderRadius },
                        X = cellX,
                        Y = cellTop,
                        Width = collapse ? cellWidth : cellWidth - cs.Border.LeftWidth - cs.Border.RightWidth,
                        Height = collapse ? cellHeight : cellHeight - cs.Border.TopWidth - cs.Border.BottomWidth,
                        BorderCentered = collapse,
                    });
                }

                float innerHeight = cellHeight - layout.BorderTop - layout.PaddingTop - layout.PaddingBottom - layout.BorderBottom;
                float extra = Math.Max(0, innerHeight - layout.Content.Height);
                float shift = cs.VerticalAlign switch
                {
                    VerticalAlign.Middle => extra / 2,
                    VerticalAlign.Bottom => extra,
                    _ => 0,
                };
                float originX = cellX + layout.BorderLeft + layout.PaddingLeft;
                float originY = cellTop + layout.BorderTop + layout.PaddingTop + shift;
                foreach (LayoutBox box in layout.Content.Boxes)
                {
                    content.Add(box.CloneAt(box.X + originX, box.Y + originY));
                }
            }

            return [.. background, .. content, .. borders];
        }

        private static PdfColor? Opaque(PdfColor? color) => color is PdfColor c && !c.IsTransparent ? c : null;
    }
}

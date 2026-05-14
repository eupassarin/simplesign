// Licensed to SimpleSign under the MIT License.

using SimpleSign.HtmlToPdf.Fonts;
using SimpleSign.HtmlToPdf.Parsing;

namespace SimpleSign.HtmlToPdf.Layout;

/// <summary>
/// Lays out HTML tables into positioned boxes.
/// Supports auto column sizing, colspan, cell padding, and borders.
/// </summary>
internal static class TableLayoutHelper
{
    /// <summary>
    /// Lays out a table element and returns the total height consumed.
    /// Adds cell boxes directly to the provided page action.
    /// </summary>
    /// <param name="tableNode">The table DOM node.</param>
    /// <param name="availableWidth">Available width for the table.</param>
    /// <param name="offsetX">X offset for the table.</param>
    /// <param name="startY">Starting Y cursor position.</param>
    /// <param name="addBox">Callback to add a layout box to the current page.</param>
    /// <returns>Total height of the table.</returns>
    internal static float LayoutTable(
        HtmlNode tableNode,
        float availableWidth,
        float offsetX,
        float startY,
        Action<LayoutBox> addBox)
    {
        ComputedStyle tableStyle = tableNode.ComputedStyle ?? new ComputedStyle();

        // Collect rows and cells from table structure
        List<TableRow> rows = CollectRows(tableNode);
        if (rows.Count == 0)
        {
            return 0;
        }

        int colCount = GetColumnCount(rows);
        if (colCount == 0)
        {
            return 0;
        }

        // Build cell grid for colspan/rowspan
        var (grid, gridCols) = BuildCellGrid(rows);
        int actualColCount = gridCols > 0 ? gridCols : colCount;

        // Calculate column widths (resolve percentage widths)
        float tableWidth = tableStyle.Width ?? availableWidth;
        if (tableWidth < 0)
        {
            tableWidth = availableWidth * (-tableWidth / 100f);
        }

        tableWidth = Math.Min(tableWidth, availableWidth);
        float[] colWidths = CalculateColumnWidths(rows, actualColCount, tableWidth, tableStyle);

        // Layout caption if present
        float cursorY = startY;
        HtmlNode? caption = tableNode.Children.FirstOrDefault(c => c.Tag is "caption");
        if (caption is not null)
        {
            ComputedStyle captionStyle = caption.ComputedStyle ?? new ComputedStyle
            {
                IsBold = true,
                TextAlign = TextAlign.Center,
            };
            string captionText = CollectAllText(caption).Trim();
            if (captionText.Length > 0)
            {
                float captionHeight = captionStyle.FontSize * captionStyle.LineHeight;
                addBox(new LayoutBox
                {
                    Type = LayoutBoxType.InlineText,
                    Node = caption,
                    Style = captionStyle,
                    X = offsetX,
                    Y = cursorY,
                    Width = tableWidth,
                    Height = captionHeight,
                    Text = captionText,
                });
                cursorY += captionHeight + 4f;
            }
        }

        // Layout each row
        bool borderCollapse = tableStyle.BorderCollapse;
        float tableStartY = cursorY;

        for (int rowIdx = 0; rowIdx < rows.Count; rowIdx++)
        {
            float rowHeight = LayoutRow(rows[rowIdx], colWidths, actualColCount, offsetX, cursorY, borderCollapse, addBox, grid, rowIdx);
            cursorY += rowHeight;
        }

        float totalHeight = cursorY - tableStartY;

        // Table background box
        if (tableStyle.BackgroundColor is PdfColor bg && !bg.IsTransparent)
        {
            addBox(new LayoutBox
            {
                Type = LayoutBoxType.Block,
                Node = tableNode,
                Style = tableStyle,
                X = offsetX,
                Y = tableStartY,
                Width = tableWidth,
                Height = totalHeight,
            });
        }

        // Table border
        if (tableStyle.Border.HasBorder && !borderCollapse)
        {
            addBox(new LayoutBox
            {
                Type = LayoutBoxType.Block,
                Node = tableNode,
                Style = new ComputedStyle
                {
                    Border = tableStyle.Border.Clone(),
                },
                X = offsetX,
                Y = tableStartY,
                Width = tableWidth,
                Height = totalHeight,
            });
        }

        return totalHeight;
    }

    private static float LayoutRow(
        TableRow row,
        float[] colWidths,
        int colCount,
        float offsetX,
        float rowY,
        bool borderCollapse,
        Action<LayoutBox> addBox,
        CellInfo?[][] grid,
        int rowIndex)
    {
        // First pass: measure cell heights
        float maxCellHeight = 0;
        var cellLayouts = new List<CellLayout>();
        var processedCells = new HashSet<HtmlNode>();

        for (int gridCol = 0; gridCol < colCount; gridCol++)
        {
            CellInfo? info = grid.Length > rowIndex && grid[rowIndex].Length > gridCol
                ? grid[rowIndex][gridCol]
                : null;

            // Skip if this cell starts in a different row (rowspan continuation)
            if (info is null || info.Row != rowIndex || info.Col != gridCol)
            {
                continue;
            }

            // Skip already processed cells (colspan continuation)
            if (!processedCells.Add(info.Node))
            {
                continue;
            }

            HtmlNode cell = info.Node;
            ComputedStyle cellStyle = cell.ComputedStyle ?? new ComputedStyle();

            // Cell width spans multiple columns
            float cellWidth = 0;
            for (int c = gridCol; c < gridCol + info.ColSpan && c < colCount; c++)
            {
                cellWidth += colWidths[c];
            }

            float contentWidth = cellWidth - cellStyle.Padding.Left - cellStyle.Padding.Right
                - cellStyle.Border.LeftWidth - cellStyle.Border.RightWidth;
            contentWidth = Math.Max(contentWidth, 0);

            float contentHeight = MeasureCellContent(cell, contentWidth);
            float totalCellHeight = contentHeight + cellStyle.Padding.Top + cellStyle.Padding.Bottom
                + cellStyle.Border.TopWidth + cellStyle.Border.BottomWidth;

            maxCellHeight = Math.Max(maxCellHeight, totalCellHeight);

            float cellX = offsetX + GetColumnOffset(colWidths, gridCol);

            cellLayouts.Add(new CellLayout(cell, cellStyle, cellX, cellWidth, contentWidth, contentHeight));
        }

        if (maxCellHeight == 0)
        {
            maxCellHeight = 12f * 1.4f; // minimum row height
        }

        // Second pass: emit cell boxes
        foreach (CellLayout cl in cellLayouts)
        {
            // Cell background
            if (cl.Style.BackgroundColor is PdfColor bg && !bg.IsTransparent)
            {
                addBox(new LayoutBox
                {
                    Type = LayoutBoxType.Block,
                    Node = cl.Node,
                    Style = new ComputedStyle { BackgroundColor = bg },
                    X = cl.X,
                    Y = rowY,
                    Width = cl.CellWidth,
                    Height = maxCellHeight,
                });
            }

            // Cell border
            if (cl.Style.Border.HasBorder)
            {
                addBox(new LayoutBox
                {
                    Type = LayoutBoxType.Block,
                    Node = cl.Node,
                    Style = new ComputedStyle { Border = cl.Style.Border.Clone() },
                    X = cl.X,
                    Y = rowY,
                    Width = cl.CellWidth,
                    Height = maxCellHeight,
                });
            }

            // Cell text content
            float textX = cl.X + cl.Style.Padding.Left + cl.Style.Border.LeftWidth;
            float textY = rowY + cl.Style.Padding.Top + cl.Style.Border.TopWidth;

            // Vertical alignment
            float extraSpace = maxCellHeight - cl.ContentHeight
                - cl.Style.Padding.Top - cl.Style.Padding.Bottom
                - cl.Style.Border.TopWidth - cl.Style.Border.BottomWidth;
            if (extraSpace > 0)
            {
                if (cl.Style.VerticalAlign == VerticalAlign.Middle)
                {
                    textY += extraSpace / 2;
                }
                else if (cl.Style.VerticalAlign == VerticalAlign.Bottom)
                {
                    textY += extraSpace;
                }
            }

            EmitCellContent(cl.Node, cl.Style, textX, textY, cl.ContentWidth, addBox);
        }

        return maxCellHeight;
    }

    private static float MeasureCellContent(HtmlNode cell, float contentWidth)
    {
        ComputedStyle style = cell.ComputedStyle ?? new ComputedStyle();
        float totalHeight = 0;

        foreach (HtmlNode child in cell.Children)
        {
            if (child.NodeType == HtmlNodeType.Text)
            {
                string text = child.Text ?? string.Empty;
                if (text.Trim().Length == 0)
                {
                    continue;
                }

                List<string> lines = TextMeasurer.WrapText(
                    text.Trim(),
                    contentWidth,
                    style.FontFamily,
                    style.FontSize,
                    style.IsBold,
                    style.IsItalic);

                totalHeight += lines.Count * style.FontSize * style.LineHeight;
            }
            else if (child.NodeType == HtmlNodeType.Element)
            {
                ComputedStyle childStyle = child.ComputedStyle ?? style;
                string childText = CollectAllText(child);
                if (childText.Trim().Length > 0)
                {
                    List<string> lines = TextMeasurer.WrapText(
                        childText.Trim(),
                        contentWidth,
                        childStyle.FontFamily,
                        childStyle.FontSize,
                        childStyle.IsBold,
                        childStyle.IsItalic);

                    totalHeight += lines.Count * childStyle.FontSize * childStyle.LineHeight;
                }
            }
        }

        // Minimum: one line
        if (totalHeight == 0)
        {
            totalHeight = style.FontSize * style.LineHeight;
        }

        return totalHeight;
    }

    private static void EmitCellContent(
        HtmlNode cell,
        ComputedStyle cellStyle,
        float x,
        float y,
        float contentWidth,
        Action<LayoutBox> addBox)
    {
        float curY = y;

        foreach (HtmlNode child in cell.Children)
        {
            ComputedStyle style;
            string text;

            if (child.NodeType == HtmlNodeType.Text)
            {
                text = child.Text ?? string.Empty;
                style = cellStyle;
            }
            else
            {
                text = CollectAllText(child);
                style = child.ComputedStyle ?? cellStyle;
            }

            text = text.Trim();
            if (text.Length == 0)
            {
                continue;
            }

            List<string> lines = TextMeasurer.WrapText(
                text,
                contentWidth,
                style.FontFamily,
                style.FontSize,
                style.IsBold,
                style.IsItalic);

            foreach (string line in lines)
            {
                float lineWidth = TextMeasurer.MeasureWidth(
                    line,
                    style.FontFamily,
                    style.FontSize,
                    style.IsBold,
                    style.IsItalic);

                float lineX = x;
                if (cellStyle.TextAlign == TextAlign.Center)
                {
                    lineX += (contentWidth - lineWidth) / 2;
                }
                else if (cellStyle.TextAlign == TextAlign.Right)
                {
                    lineX += contentWidth - lineWidth;
                }

                addBox(new LayoutBox
                {
                    Type = LayoutBoxType.InlineText,
                    Node = child,
                    Style = style,
                    X = lineX,
                    Y = curY,
                    Width = lineWidth,
                    Height = style.FontSize * style.LineHeight,
                    Text = line,
                });

                curY += style.FontSize * style.LineHeight;
            }
        }
    }

    private static string CollectAllText(HtmlNode node)
    {
        if (node.NodeType == HtmlNodeType.Text)
        {
            return node.Text ?? string.Empty;
        }

        var sb = new System.Text.StringBuilder();
        foreach (HtmlNode child in node.Children)
        {
            sb.Append(CollectAllText(child));
        }

        return sb.ToString();
    }

    private static List<TableRow> CollectRows(HtmlNode table)
    {
        var rows = new List<TableRow>();

        foreach (HtmlNode child in table.Children)
        {
            if (child.Tag is "tr")
            {
                rows.Add(new TableRow(CollectCells(child)));
            }
            else if (child.Tag is "thead" or "tbody" or "tfoot")
            {
                foreach (HtmlNode grandchild in child.Children)
                {
                    if (grandchild.Tag is "tr")
                    {
                        rows.Add(new TableRow(CollectCells(grandchild)));
                    }
                }
            }
        }

        return rows;
    }

    private static List<HtmlNode> CollectCells(HtmlNode tr)
    {
        var cells = new List<HtmlNode>();
        foreach (HtmlNode child in tr.Children)
        {
            if (child.Tag is "td" or "th")
            {
                cells.Add(child);
            }
        }

        return cells;
    }

    private static int GetColumnCount(List<TableRow> rows)
    {
        int max = 0;
        foreach (TableRow row in rows)
        {
            int cols = 0;
            foreach (HtmlNode cell in row.Cells)
            {
                cols += GetSpanAttribute(cell, "colspan");
            }

            max = Math.Max(max, cols);
        }

        return max;
    }

    private static float[] CalculateColumnWidths(
        List<TableRow> rows,
        int colCount,
        float tableWidth,
        ComputedStyle tableStyle)
    {
        // Track explicit CSS widths from cells
        float[] explicitWidths = new float[colCount];
        bool[] hasExplicit = new bool[colCount];

        // Measure natural widths
        float[] minWidths = new float[colCount];
        float[] maxWidths = new float[colCount];

        foreach (TableRow row in rows)
        {
            int gridCol = 0;
            for (int cellIdx = 0; cellIdx < row.Cells.Count && gridCol < colCount; cellIdx++)
            {
                HtmlNode cell = row.Cells[cellIdx];
                int colSpan = GetSpanAttribute(cell, "colspan");
                ComputedStyle style = cell.ComputedStyle ?? tableStyle;

                // Only measure single-span cells for min/max (multi-span handled separately)
                if (colSpan == 1)
                {
                    // Check for explicit CSS width on cell
                    if (!hasExplicit[gridCol] && style.Width is float cellWidth)
                    {
                        if (cellWidth < 0)
                        {
                            explicitWidths[gridCol] = tableWidth * (-cellWidth / 100f);
                        }
                        else
                        {
                            explicitWidths[gridCol] = cellWidth;
                        }

                        hasExplicit[gridCol] = true;
                    }

                    string text = CollectAllText(cell).Trim();

                    if (text.Length > 0)
                    {
                        float padding = style.Padding.Left + style.Padding.Right
                            + style.Border.LeftWidth + style.Border.RightWidth;

                        float minW = padding;
                        foreach (string word in text.Split(' ', StringSplitOptions.RemoveEmptyEntries))
                        {
                            float ww = TextMeasurer.MeasureWidth(
                                word,
                                style.FontFamily,
                                style.FontSize,
                                style.IsBold,
                                style.IsItalic) + padding;
                            minW = Math.Max(minW, ww);
                        }

                        float maxW = TextMeasurer.MeasureWidth(
                            text,
                            style.FontFamily,
                            style.FontSize,
                            style.IsBold,
                            style.IsItalic) + padding;

                        minWidths[gridCol] = Math.Max(minWidths[gridCol], minW);
                        maxWidths[gridCol] = Math.Max(maxWidths[gridCol], maxW);
                    }
                }

                gridCol += colSpan;
            }
        }

        // Apply explicit widths first
        float[] widths = new float[colCount];
        float explicitTotal = 0;
        int autoCount = 0;

        for (int c = 0; c < colCount; c++)
        {
            if (hasExplicit[c])
            {
                widths[c] = Math.Max(explicitWidths[c], minWidths[c]);
                explicitTotal += widths[c];
            }
            else
            {
                autoCount++;
            }
        }

        // Distribute remaining space among auto columns
        float remainingWidth = tableWidth - explicitTotal;

        if (autoCount == 0)
        {
            // All columns explicit — scale proportionally if needed
            if (explicitTotal > 0 && Math.Abs(explicitTotal - tableWidth) > 1f)
            {
                float scale = tableWidth / explicitTotal;
                for (int c = 0; c < colCount; c++)
                {
                    widths[c] *= scale;
                }
            }

            return widths;
        }

        // Auto-size remaining columns using min/max algorithm
        float totalMin = 0;
        float totalMax = 0;
        for (int c = 0; c < colCount; c++)
        {
            if (!hasExplicit[c])
            {
                totalMin += minWidths[c];
                totalMax += maxWidths[c];
            }
        }

        if (totalMax <= remainingWidth)
        {
            float extra = remainingWidth - totalMax;
            for (int c = 0; c < colCount; c++)
            {
                if (!hasExplicit[c])
                {
                    widths[c] = maxWidths[c] + (extra / autoCount);
                }
            }
        }
        else if (totalMin >= remainingWidth)
        {
            for (int c = 0; c < colCount; c++)
            {
                if (!hasExplicit[c])
                {
                    widths[c] = remainingWidth / autoCount;
                }
            }
        }
        else
        {
            float range = totalMax - totalMin;
            float available = remainingWidth - totalMin;
            float ratio = range > 0 ? available / range : 0;

            for (int c = 0; c < colCount; c++)
            {
                if (!hasExplicit[c])
                {
                    widths[c] = minWidths[c] + (maxWidths[c] - minWidths[c]) * ratio;
                }
            }
        }

        return widths;
    }

    private static float GetColumnOffset(float[] colWidths, int colIndex)
    {
        float offset = 0;
        for (int i = 0; i < colIndex; i++)
        {
            offset += colWidths[i];
        }

        return offset;
    }

    private sealed record TableRow(List<HtmlNode> Cells);

    private sealed record CellLayout(
        HtmlNode Node,
        ComputedStyle Style,
        float X,
        float CellWidth,
        float ContentWidth,
        float ContentHeight);

    /// <summary>Tracks a cell's position and span in the grid.</summary>
    private sealed record CellInfo(HtmlNode Node, int Row, int Col, int ColSpan, int RowSpan);

    /// <summary>Builds a 2D grid mapping (row, col) to CellInfo, handling colspan and rowspan.</summary>
    private static (CellInfo?[][] Grid, int ColCount) BuildCellGrid(List<TableRow> rows)
    {
        // First pass: determine actual column count considering colspan
        int maxCols = 0;
        foreach (TableRow row in rows)
        {
            int cols = 0;
            foreach (HtmlNode cell in row.Cells)
            {
                int cs = GetSpanAttribute(cell, "colspan");
                cols += cs;
            }

            maxCols = Math.Max(maxCols, cols);
        }

        if (maxCols == 0)
        {
            return ([], 0);
        }

        // Second pass: place cells in grid
        var grid = new CellInfo?[rows.Count][];
        for (int i = 0; i < rows.Count; i++)
        {
            grid[i] = new CellInfo?[maxCols];
        }

        for (int r = 0; r < rows.Count; r++)
        {
            int gridCol = 0;
            foreach (HtmlNode cell in rows[r].Cells)
            {
                // Skip columns occupied by rowspan from previous rows
                while (gridCol < maxCols && grid[r][gridCol] is not null)
                {
                    gridCol++;
                }

                if (gridCol >= maxCols)
                {
                    break;
                }

                int colSpan = GetSpanAttribute(cell, "colspan");
                int rowSpan = GetSpanAttribute(cell, "rowspan");

                // Clamp spans to grid bounds
                colSpan = Math.Min(colSpan, maxCols - gridCol);
                rowSpan = Math.Min(rowSpan, rows.Count - r);

                var info = new CellInfo(cell, r, gridCol, colSpan, rowSpan);

                // Mark all spanned positions
                for (int dr = 0; dr < rowSpan; dr++)
                {
                    for (int dc = 0; dc < colSpan; dc++)
                    {
                        grid[r + dr][gridCol + dc] = info;
                    }
                }

                gridCol += colSpan;
            }
        }

        return (grid, maxCols);
    }

    private static int GetSpanAttribute(HtmlNode cell, string attrName)
    {
        if (cell.Attributes.TryGetValue(attrName, out string? val) &&
            int.TryParse(val, out int span) && span > 1)
        {
            return span;
        }

        return 1;
    }
}

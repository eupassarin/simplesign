using SimpleSign.DocxToPdf.Model;

namespace SimpleSign.DocxToPdf.Layout;

/// <summary>Lays out tables into positioned elements.</summary>
internal sealed class TableLayouter
{
    private readonly ParagraphLayouter _paragraphLayouter;

    /// <summary>Initializes a new instance of the <see cref="TableLayouter"/> class.</summary>
    /// <param name="paragraphLayouter">The paragraph layouter for cell content.</param>
    public TableLayouter(ParagraphLayouter paragraphLayouter)
    {
        _paragraphLayouter = paragraphLayouter;
    }

    /// <summary>Lays out a table and returns positioned elements with total height.</summary>
    /// <param name="table">The table to layout.</param>
    /// <param name="x">The left X position.</param>
    /// <param name="y">The top Y position.</param>
    /// <param name="availableWidth">The available width.</param>
    /// <returns>A tuple of elements and total height.</returns>
    public (List<LayoutElement> Elements, float Height) Layout(DocTable table, float x, float y, float availableWidth)
    {
        var elements = new List<LayoutElement>();

        if (table.Rows.Count == 0)
        {
            return (elements, 0f);
        }

        // Calculate column widths
        float[] columnWidths = CalculateColumnWidths(table, availableWidth);
        float tableWidth = columnWidths.Sum();

        // Adjust starting X for table alignment
        float tableX = table.Alignment switch
        {
            ParagraphAlignment.Center => x + (availableWidth - tableWidth) / 2f,
            ParagraphAlignment.Right => x + availableWidth - tableWidth,
            _ => x
        };

        float currentY = y;
        float cellMargin = table.CellMarginPt;

        foreach (DocTableRow row in table.Rows)
        {
            float rowHeight = Math.Max(row.HeightPt, CalculateRowHeight(row, columnWidths, cellMargin));
            float cellX = tableX;

            for (int cellIdx = 0; cellIdx < row.Cells.Count && cellIdx < columnWidths.Length; cellIdx++)
            {
                DocTableCell cell = row.Cells[cellIdx];
                float cellWidth = 0f;
                for (int span = 0; span < cell.GridSpan && cellIdx + span < columnWidths.Length; span++)
                {
                    cellWidth += columnWidths[cellIdx + span];
                }

                // Draw cell shading
                if (cell.ShadingColor is not null && cell.ShadingColor != "auto")
                {
                    elements.Add(new LayoutRect
                    {
                        X = cellX,
                        Y = currentY,
                        Width = cellWidth,
                        Height = rowHeight,
                        FillColor = cell.ShadingColor
                    });
                }

                // Draw cell borders
                AddCellBorders(elements, cellX, currentY, cellWidth, rowHeight);

                // Layout cell content
                float contentX = cellX + cellMargin;
                float contentY = currentY + cellMargin;
                float contentWidth = cellWidth - (cellMargin * 2);

                foreach (DocParagraph para in cell.Paragraphs)
                {
                    (List<LayoutElement> paraElements, float paraHeight) = _paragraphLayouter.Layout(para, contentX, contentY, contentWidth);
                    elements.AddRange(paraElements);
                    contentY += paraHeight;
                }

                cellX += cellWidth;
            }

            currentY += rowHeight;
        }

        return (elements, currentY - y);
    }

    /// <summary>Calculates column widths for the table.</summary>
    /// <param name="table">The table.</param>
    /// <param name="availableWidth">The available width.</param>
    /// <returns>An array of column widths in points.</returns>
    internal static float[] CalculateColumnWidths(DocTable table, float availableWidth)
    {
        if (table.Rows.Count == 0)
        {
            return [];
        }

        // Determine number of columns from the first row
        int numCols = table.Rows[0].Cells.Sum(c => c.GridSpan);
        if (numCols == 0)
        {
            return [];
        }

        var widths = new float[numCols];

        // Try to use explicit cell widths from first row
        int colIdx = 0;
        foreach (DocTableCell cell in table.Rows[0].Cells)
        {
            if (cell.WidthPt > 0)
            {
                float perCol = cell.WidthPt / cell.GridSpan;
                for (int i = 0; i < cell.GridSpan && colIdx + i < numCols; i++)
                {
                    widths[colIdx + i] = perCol;
                }
            }

            colIdx += cell.GridSpan;
        }

        // If no widths specified, distribute evenly
        float totalSpecified = widths.Sum();
        if (totalSpecified <= 0)
        {
            float evenWidth = availableWidth / numCols;
            for (int i = 0; i < numCols; i++)
            {
                widths[i] = evenWidth;
            }
        }
        else
        {
            // Fill any zero-width columns
            int zeroCount = widths.Count(w => w <= 0);
            if (zeroCount > 0)
            {
                float remaining = availableWidth - totalSpecified;
                float perZero = Math.Max(remaining / zeroCount, 20f);
                for (int i = 0; i < numCols; i++)
                {
                    if (widths[i] <= 0)
                    {
                        widths[i] = perZero;
                    }
                }
            }
        }

        return widths;
    }

    private float CalculateRowHeight(DocTableRow row, float[] columnWidths, float cellMargin)
    {
        float maxHeight = 14f; // Minimum row height

        int colIdx = 0;
        foreach (DocTableCell cell in row.Cells)
        {
            float cellWidth = 0f;
            for (int span = 0; span < cell.GridSpan && colIdx + span < columnWidths.Length; span++)
            {
                cellWidth += columnWidths[colIdx + span];
            }

            float contentWidth = cellWidth - (cellMargin * 2);
            float cellHeight = cellMargin * 2;

            foreach (DocParagraph para in cell.Paragraphs)
            {
                (_, float paraHeight) = _paragraphLayouter.Layout(para, 0, 0, contentWidth);
                cellHeight += paraHeight;
            }

            if (cellHeight > maxHeight)
            {
                maxHeight = cellHeight;
            }

            colIdx += cell.GridSpan;
        }

        return maxHeight;
    }

    private static void AddCellBorders(List<LayoutElement> elements, float x, float y, float width, float height)
    {
        // Top border
        elements.Add(new LayoutLine { X = x, Y = y, EndX = x + width, EndY = y, LineWidth = 0.5f, Color = "000000" });
        // Bottom border
        elements.Add(new LayoutLine { X = x, Y = y + height, EndX = x + width, EndY = y + height, LineWidth = 0.5f, Color = "000000" });
        // Left border
        elements.Add(new LayoutLine { X = x, Y = y, EndX = x, EndY = y + height, LineWidth = 0.5f, Color = "000000" });
        // Right border
        elements.Add(new LayoutLine { X = x + width, Y = y, EndX = x + width, EndY = y + height, LineWidth = 0.5f, Color = "000000" });
    }
}

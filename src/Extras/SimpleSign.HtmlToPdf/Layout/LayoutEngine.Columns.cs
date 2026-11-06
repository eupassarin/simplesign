using SimpleSign.HtmlToPdf.Parsing;

namespace SimpleSign.HtmlToPdf.Layout;

/// <summary>Multi-column layout (<c>column-count</c>, <c>column-width</c>, <c>column-gap</c>, <c>column-rule</c>).</summary>
public sealed partial class LayoutEngine
{
    /// <summary>The resolved column geometry of a multi-column container.</summary>
    private readonly record struct Columns(int Count, float Width, float Gap);

    /// <summary>Returns the column geometry, or null when the element is not a multi-column container.</summary>
    private static Columns? ColumnLayout(ComputedStyle style, float contentWidth)
    {
        if (style.ColumnCount <= 0 && style.ColumnWidth is null)
        {
            return null;
        }

        float gap = style.GapDeclared ? Math.Max(0, style.Gap) : style.FontSize;
        int count = style.ColumnCount > 0 ? style.ColumnCount : int.MaxValue;
        if (style.ColumnWidth is float wanted && wanted > 0)
        {
            int fit = Math.Max(1, (int)MathF.Floor((contentWidth + gap) / (wanted + gap)));
            count = Math.Min(count, fit);
        }

        // Columns narrower than a few points are useless; fall back to fewer.
        count = Math.Max(1, Math.Min(count, (int)Math.Max(1, (contentWidth + gap) / (gap + 10))));
        if (count == 1)
        {
            return null;
        }

        float width = (contentWidth - (gap * (count - 1))) / count;
        return new Columns(count, width, gap);
    }

    private void LayoutMultiColumn(HtmlNode node, ComputedStyle style, Columns columns, float offsetX)
    {
        float fullWidth = (columns.Width * columns.Count) + (columns.Gap * (columns.Count - 1));

        // column-span: all children interrupt the columns and take the full width.
        var segment = new List<HtmlNode>();
        foreach (HtmlNode child in node.Children)
        {
            if (child.ComputedStyle is { ColumnSpanAll: true, Display: not DisplayType.None })
            {
                FlushColumnSegment(node, style, segment, columns, offsetX);
                LayoutBlockChildren(Wrapper(node, [child]), fullWidth, offsetX);
                continue;
            }

            segment.Add(child);
        }

        FlushColumnSegment(node, style, segment, columns, offsetX);
    }

    /// <summary>A stand-in parent holding a subset of the container's children (their Parent is unchanged).</summary>
    private static HtmlNode Wrapper(HtmlNode container, List<HtmlNode> children)
    {
        var wrapper = new HtmlNode { NodeType = HtmlNodeType.Element, Tag = container.Tag, ComputedStyle = container.ComputedStyle };
        wrapper.Children.AddRange(children);
        return wrapper;
    }

    private void FlushColumnSegment(HtmlNode container, ComputedStyle style, List<HtmlNode> children, Columns columns, float offsetX)
    {
        if (children.Count == 0)
        {
            return;
        }

        IsolatedResult content = LayoutChildrenIsolated(Wrapper(container, [.. children]), columns.Width);
        children.Clear();
        _lastMarginBottom = 0;
        List<LayoutBox> boxes = content.Boxes;
        float total = content.Height;
        float sliceTop = 0;
        int guard = 0;
        while (total - sliceTop > 0.01f && guard++ < 10_000)
        {
            float available = IsIsolated ? float.MaxValue : _settings.ContentHeight - CursorY;
            float columnHeight = FitsInColumns(boxes, sliceTop, total, columns.Count, available)
                ? BalancedColumnHeight(boxes, sliceTop, total, columns.Count, available)
                : available;

            // Not even one line fits below the cursor: continue on a fresh page.
            if (!IsIsolated && CursorY > 0 && ColumnBreak(boxes, sliceTop, sliceTop + columnHeight, total) <= sliceTop + 0.5f)
            {
                StartNewPage();
                continue;
            }

            float rowTop = CursorY;
            float used = 0;
            int placed = 0;
            for (int k = 0; k < columns.Count && total - sliceTop > 0.01f; k++)
            {
                float bottom = total - sliceTop <= columnHeight + 0.5f
                    ? total
                    : ColumnBreak(boxes, sliceTop, sliceTop + columnHeight, total);
                if (bottom <= sliceTop + 0.5f)
                {
                    bottom = Math.Min(total, sliceTop + columnHeight);
                }

                CursorY = rowTop;
                PlaceSlice(boxes, sliceTop, bottom >= total ? float.MaxValue : bottom, offsetX + (k * (columns.Width + columns.Gap)));
                used = Math.Max(used, bottom - sliceTop);
                sliceTop = bottom;
                placed++;
            }

            AddColumnRules(style, columns, offsetX, rowTop, used, placed);
            CursorY = rowTop + used;
            if (total - sliceTop > 0.01f)
            {
                StartNewPage();
            }
        }
    }

    private void AddColumnRules(ComputedStyle style, Columns columns, float offsetX, float top, float height, int count)
    {
        if (style.ColumnRuleStyle == BorderLineStyle.None || style.ColumnRuleWidth <= 0 || height <= 0 || IsMeasuring)
        {
            return;
        }

        var border = new BorderStyle
        {
            LeftWidth = style.ColumnRuleWidth,
            LeftColor = style.ColumnRuleColor ?? style.Color,
            LeftStyle = style.ColumnRuleStyle,
        };
        for (int k = 1; k < count; k++)
        {
            float x = offsetX + (k * (columns.Width + columns.Gap)) - (columns.Gap / 2) - (style.ColumnRuleWidth / 2);
            _currentPage.Boxes.Add(new LayoutBox
            {
                Type = LayoutBoxType.Block,
                Style = new ComputedStyle { Border = border },
                X = x,
                Y = top,
                Width = 0,
                Height = height,
            });
        }
    }

    /// <summary>Moves a column bottom up so no line or atomic box is cut in half.</summary>
    private static float ColumnBreak(List<LayoutBox> boxes, float top, float bottom, float total)
    {
        if (bottom >= total)
        {
            return total;
        }

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

                if (box.Y < bottom && box.Y + box.Height > bottom + 0.01f && box.Y > top)
                {
                    bottom = box.Y;
                    moved = true;
                }
            }
        }

        return bottom;
    }

    /// <summary>Simulates filling <paramref name="count"/> columns of the given height.</summary>
    private static bool FitsInColumns(List<LayoutBox> boxes, float top, float total, int count, float height)
    {
        float s = top;
        for (int k = 0; k < count; k++)
        {
            if (total - s <= height + 0.5f)
            {
                return true;
            }

            float b = ColumnBreak(boxes, s, s + height, total);
            s = b <= s + 0.5f ? s + height : b;
        }

        return total - s <= 0.01f;
    }

    /// <summary>Finds the smallest column height (up to <paramref name="max"/>) that holds the rest of the content.</summary>
    private static float BalancedColumnHeight(List<LayoutBox> boxes, float top, float total, int count, float max)
    {
        float lo = (total - top) / count;
        float hi = Math.Min(max, total - top);
        if (FitsInColumns(boxes, top, total, count, lo))
        {
            return lo;
        }

        for (int i = 0; i < 24 && hi - lo > 0.25f; i++)
        {
            float mid = (lo + hi) / 2;
            if (FitsInColumns(boxes, top, total, count, mid))
            {
                hi = mid;
            }
            else
            {
                lo = mid;
            }
        }

        return hi;
    }
}

// Licensed to SimpleSign under the MIT License.

using System.Globalization;
using SimpleSign.HtmlToPdf.Parsing;

namespace SimpleSign.HtmlToPdf.Layout;

/// <summary>Flexbox and grid containers.</summary>
public sealed partial class LayoutEngine
{
    private List<HtmlNode> CollectContainerItems(HtmlNode container, float availableWidth, float offsetX)
    {
        List<HtmlNode> items = [];
        foreach (HtmlNode child in container.Children)
        {
            if (child.NodeType == HtmlNodeType.Text)
            {
                if (string.IsNullOrWhiteSpace(child.Text))
                {
                    continue;
                }

                // Anonymous item wrapping loose text.
                HtmlNode wrapper = HtmlNode.CreateElement("div", container);
                ComputedStyle wrapperStyle = child.ComputedStyle?.Clone() ?? container.ComputedStyle?.Clone() ?? new ComputedStyle();
                wrapperStyle.Display = DisplayType.Block;
                wrapperStyle.Margin = Thickness.Zero;
                wrapperStyle.Padding = Thickness.Zero;
                wrapperStyle.Border = BorderStyle.None;
                wrapperStyle.BackgroundColor = null;
                wrapperStyle.Width = null;
                wrapperStyle.FlexGrow = 0;
                wrapperStyle.FlexBasis = null;
                wrapper.ComputedStyle = wrapperStyle;
                HtmlNode textCopy = HtmlNode.CreateText(child.Text!, wrapper);
                textCopy.ComputedStyle = child.ComputedStyle;
                wrapper.Children.Add(textCopy);
                items.Add(wrapper);
                continue;
            }

            ComputedStyle style = StyleFor(child, availableWidth);
            if (style.Display == DisplayType.None)
            {
                continue;
            }

            if (style.Position is PositionMode.Absolute or PositionMode.Fixed)
            {
                TryHandleOutOfFlow(child, style, availableWidth, offsetX);
                continue;
            }

            items.Add(child);
        }

        return items;
    }

    private void LayoutFlexChildren(HtmlNode container, float availableWidth, float offsetX)
    {
        List<HtmlNode> items = CollectContainerItems(container, availableWidth, offsetX);
        if (items.Count == 0)
        {
            return;
        }

        ComputedStyle containerStyle = container.ComputedStyle ?? new ComputedStyle();
        if (containerStyle.FlexDirection == FlexDirection.Column)
        {
            for (int i = 0; i < items.Count; i++)
            {
                HtmlNode item = items[i];
                ComputedStyle itemStyle = item.ComputedStyle ?? new ComputedStyle();
                float width = availableWidth;
                float x = offsetX;
                if (containerStyle.AlignItems != AlignItems.Stretch || itemStyle.Width is not null)
                {
                    width = itemStyle.Width is not null ? MeasureIntrinsic(item, asBox: true).Max : ShrinkToFit(item, availableWidth);
                    width = Math.Min(width, availableWidth);
                    x += containerStyle.AlignItems switch
                    {
                        AlignItems.Center => (availableWidth - width) / 2,
                        AlignItems.End => availableWidth - width,
                        _ => 0,
                    };
                }

                LayoutBlock(item, width, x, ignoreExplicitWidth: true);
                _lastMarginBottom = 0;
                if (i < items.Count - 1)
                {
                    CursorY += containerStyle.RowGap > 0 ? containerStyle.RowGap : containerStyle.Gap;
                }
            }

            _lastMarginBottom = 0;
            return;
        }

        float columnGap = containerStyle.Gap;
        float rowGap = containerStyle.RowGap > 0 ? containerStyle.RowGap : containerStyle.Gap;
        var hypothetical = items.Select(item => GetFlexBasis(item, availableWidth)).ToList();
        List<List<int>> lines = BuildFlexLines(hypothetical, availableWidth, columnGap, containerStyle.FlexWrap);

        for (int lineIndex = 0; lineIndex < lines.Count; lineIndex++)
        {
            List<int> line = lines[lineIndex];
            float gapTotal = columnGap * Math.Max(0, line.Count - 1);
            float[] sizes = [.. line.Select(i => hypothetical[i])];
            float[] minSizes = [.. line.Select(i => MeasureIntrinsic(items[i], asBox: true).Min)];
            ResolveFlexibleLengths([.. line.Select(i => items[i])], sizes, minSizes, availableWidth - gapTotal);

            float used = sizes.Sum() + gapTotal;
            float free = Math.Max(0, availableWidth - used);
            int count = line.Count;
            (float startX, float gap) = containerStyle.JustifyContent switch
            {
                JustifyContent.Center => (free / 2, columnGap),
                JustifyContent.End => (free, columnGap),
                JustifyContent.SpaceBetween when count > 1 => (0, columnGap + (free / (count - 1))),
                JustifyContent.SpaceAround => (free / count / 2, columnGap + (free / count)),
                JustifyContent.SpaceEvenly => (free / (count + 1), columnGap + (free / (count + 1))),
                _ => (0, columnGap),
            };

            var results = new List<IsolatedResult>(count);
            for (int k = 0; k < count; k++)
            {
                results.Add(LayoutBoxIsolated(items[line[k]], sizes[k], ignoreExplicitWidth: true));
            }

            float rowHeight = results.Max(r => r.Height);
            List<LayoutBox> rowBoxes = [];
            float x = startX;
            for (int k = 0; k < count; k++)
            {
                HtmlNode item = items[line[k]];
                ComputedStyle itemStyle = item.ComputedStyle ?? new ComputedStyle();
                IsolatedResult result = results[k];
                float shift = containerStyle.AlignItems switch
                {
                    AlignItems.Center => (rowHeight - result.Height) / 2,
                    AlignItems.End => rowHeight - result.Height,
                    _ => 0,
                };

                if (containerStyle.AlignItems == AlignItems.Stretch && itemStyle.Height is null)
                {
                    StretchItem(item, itemStyle, result, rowHeight);
                }

                foreach (LayoutBox box in result.Boxes)
                {
                    box.X += x;
                    box.Y += shift;
                    rowBoxes.Add(box);
                }

                x += sizes[k] + gap;
            }

            PlaceRow(rowBoxes, rowHeight, offsetX);
            if (lineIndex < lines.Count - 1)
            {
                CursorY += rowGap;
            }
        }

        _lastMarginBottom = 0;
    }

    /// <summary>Places a row of isolated boxes, moving it to a new page or fragmenting it as needed.</summary>
    private void PlaceRow(List<LayoutBox> rowBoxes, float rowHeight, float offsetX)
    {
        if (!IsIsolated && CursorY > 0 && CursorY + rowHeight > _settings.ContentHeight && rowHeight <= _settings.ContentHeight)
        {
            StartNewPage();
        }

        if (!IsIsolated && CursorY + rowHeight > _settings.ContentHeight)
        {
            PlaceFragmented(rowBoxes, rowHeight, offsetX);
            return;
        }

        PlaceBoxes(rowBoxes, offsetX, CursorY);
        CursorY += rowHeight;
    }

    private static void StretchItem(HtmlNode item, ComputedStyle itemStyle, IsolatedResult result, float rowHeight)
    {
        LayoutBox? itemBox = result.Boxes.FirstOrDefault(box => box.Node == item && box.Type == LayoutBoxType.Block);
        if (itemBox is null)
        {
            return;
        }

        float decorations = Math.Max(0, itemStyle.Margin.Top) + Math.Max(0, itemStyle.Margin.Bottom)
            + itemStyle.Padding.Top + itemStyle.Padding.Bottom
            + itemStyle.Border.TopWidth + itemStyle.Border.BottomWidth;
        itemBox.Height = Math.Max(itemBox.Height, rowHeight - decorations);
    }

    private static List<List<int>> BuildFlexLines(List<float> sizes, float availableWidth, float gap, bool wrap)
    {
        List<List<int>> lines = [[]];
        float lineWidth = 0;
        for (int i = 0; i < sizes.Count; i++)
        {
            float nextWidth = lineWidth + (lines[^1].Count > 0 ? gap : 0) + sizes[i];
            if (wrap && lines[^1].Count > 0 && nextWidth > availableWidth + 0.01f)
            {
                lines.Add([]);
                lineWidth = 0;
            }

            if (lines[^1].Count > 0)
            {
                lineWidth += gap;
            }

            lines[^1].Add(i);
            lineWidth += sizes[i];
        }

        return lines;
    }

    /// <summary>Flex base size: flex-basis, then width, then max-content (outer, including margins).</summary>
    private float GetFlexBasis(HtmlNode item, float availableWidth)
    {
        ComputedStyle style = item.ComputedStyle ?? new ComputedStyle();
        float boxExtras = Math.Max(0, style.Margin.Left) + Math.Max(0, style.Margin.Right);
        float contentExtras = style.Border.LeftWidth + style.Border.RightWidth + Math.Max(0, style.Padding.Left) + Math.Max(0, style.Padding.Right);
        float? specified = style.FlexBasis ?? style.Width;
        if (specified is float basis)
        {
            float resolved = CssLength.Resolve(basis, availableWidth);
            if (style.BoxSizing == BoxSizing.ContentBox && !(style.FlexBasis == 0 && style.FlexGrow > 0))
            {
                resolved += contentExtras;
            }

            return resolved + boxExtras;
        }

        return Math.Min(MeasureIntrinsic(item, asBox: true).Max, Math.Max(availableWidth, 0));
    }

    private static void ResolveFlexibleLengths(List<HtmlNode> items, float[] sizes, float[] minSizes, float space)
    {
        float free = space - sizes.Sum();
        if (free > 0)
        {
            float growTotal = items.Sum(item => Math.Max(0, item.ComputedStyle?.FlexGrow ?? 0));
            if (growTotal > 0)
            {
                for (int i = 0; i < items.Count; i++)
                {
                    sizes[i] += free * Math.Max(0, items[i].ComputedStyle?.FlexGrow ?? 0) / growTotal;
                }
            }

            return;
        }

        if (free < 0)
        {
            // Shrink, weighted by flex-shrink × base size, never below min-content; iterate when items freeze.
            bool[] frozen = new bool[items.Count];
            for (int pass = 0; pass < items.Count && free < -0.01f; pass++)
            {
                float weightTotal = 0;
                for (int i = 0; i < items.Count; i++)
                {
                    if (!frozen[i])
                    {
                        weightTotal += Math.Max(0, items[i].ComputedStyle?.FlexShrink ?? 1) * sizes[i];
                    }
                }

                if (weightTotal <= 0)
                {
                    break;
                }

                float overflow = -free;
                for (int i = 0; i < items.Count; i++)
                {
                    if (frozen[i])
                    {
                        continue;
                    }

                    float weight = Math.Max(0, items[i].ComputedStyle?.FlexShrink ?? 1) * sizes[i];
                    float target = sizes[i] - (overflow * weight / weightTotal);
                    if (target < minSizes[i])
                    {
                        target = minSizes[i];
                        frozen[i] = true;
                    }

                    sizes[i] = target;
                }

                free = space - sizes.Sum();
            }
        }
    }

    // ── Grid ─────────────────────────────────────────────────────────────

    private void LayoutGridChildren(HtmlNode container, float availableWidth, float offsetX)
    {
        List<HtmlNode> items = CollectContainerItems(container, availableWidth, offsetX);
        if (items.Count == 0)
        {
            return;
        }

        ComputedStyle containerStyle = container.ComputedStyle ?? new ComputedStyle();
        float columnGap = containerStyle.Gap;
        float rowGap = containerStyle.RowGap;
        float[] tracks = ResolveGridTracks(containerStyle.GridTemplateColumns, availableWidth, columnGap, items);
        int columns = tracks.Length;

        // Auto-placement, row by row, honoring "grid-column: span N".
        int col = 0;
        var row = new List<(HtmlNode Item, int Col, int Span)>();
        var rows = new List<List<(HtmlNode Item, int Col, int Span)>>();
        foreach (HtmlNode item in items)
        {
            int span = Math.Clamp(GridSpan(item, columns), 1, columns);
            if (col + span > columns)
            {
                rows.Add(row);
                row = [];
                col = 0;
            }

            row.Add((item, col, span));
            col += span;
            if (col >= columns)
            {
                rows.Add(row);
                row = [];
                col = 0;
            }
        }

        if (row.Count > 0)
        {
            rows.Add(row);
        }

        for (int r = 0; r < rows.Count; r++)
        {
            var results = new List<(IsolatedResult Result, float X, HtmlNode Item)>();
            foreach (var (item, startCol, span) in rows[r])
            {
                float x = tracks.Take(startCol).Sum() + (columnGap * startCol);
                float width = tracks.Skip(startCol).Take(span).Sum() + (columnGap * (span - 1));
                results.Add((LayoutBoxIsolated(item, width, ignoreExplicitWidth: true), x, item));
            }

            float rowHeight = results.Max(entry => entry.Result.Height);
            List<LayoutBox> rowBoxes = [];
            foreach (var (result, x, item) in results)
            {
                ComputedStyle itemStyle = item.ComputedStyle ?? new ComputedStyle();
                float shift = containerStyle.AlignItems switch
                {
                    AlignItems.Center => (rowHeight - result.Height) / 2,
                    AlignItems.End => rowHeight - result.Height,
                    _ => 0,
                };
                if (containerStyle.AlignItems == AlignItems.Stretch && itemStyle.Height is null)
                {
                    StretchItem(item, itemStyle, result, rowHeight);
                }

                foreach (LayoutBox box in result.Boxes)
                {
                    box.X += x;
                    box.Y += shift;
                    rowBoxes.Add(box);
                }
            }

            PlaceRow(rowBoxes, rowHeight, offsetX);
            if (r < rows.Count - 1)
            {
                CursorY += rowGap;
            }
        }

        _lastMarginBottom = 0;
    }

    private static int GridSpan(HtmlNode item, int columns)
    {
        string? value = item.ComputedStyle?.GridColumn;
        if (value is null)
        {
            return 1;
        }

        string v = value.Trim().ToLowerInvariant();
        if (v.StartsWith("span", StringComparison.Ordinal)
            && int.TryParse(v[4..].Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out int span))
        {
            return span;
        }

        string[] parts = v.Split('/', StringSplitOptions.TrimEntries);
        if (parts.Length == 2
            && int.TryParse(parts[0], NumberStyles.Integer, CultureInfo.InvariantCulture, out int start))
        {
            if (parts[1].StartsWith("span", StringComparison.Ordinal)
                && int.TryParse(parts[1][4..].Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out int spanEnd))
            {
                return spanEnd;
            }

            if (int.TryParse(parts[1], NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out int end))
            {
                if (end < 0)
                {
                    end = columns + 2 + end;
                }

                return Math.Max(1, end - start);
            }
        }

        return 1;
    }

    /// <summary>Resolves grid-template-columns into track widths (px/%/fr/auto, repeat(), minmax()).</summary>
    private float[] ResolveGridTracks(string? template, float availableWidth, float gap, List<HtmlNode> items)
    {
        List<string> tokens = ExpandGridTemplate(template, availableWidth, gap);
        if (tokens.Count == 0)
        {
            return [availableWidth];
        }

        int count = tokens.Count;
        float[] widths = new float[count];
        float[] fractions = new float[count];
        bool[] auto = new bool[count];
        float fixedTotal = gap * (count - 1);
        for (int i = 0; i < count; i++)
        {
            string token = tokens[i].Trim().ToLowerInvariant();
            if (token.StartsWith("minmax(", StringComparison.Ordinal) && token.EndsWith(')'))
            {
                string[] args = token[7..^1].Split(',', StringSplitOptions.TrimEntries);
                token = args.Length == 2 && args[1].EndsWith("fr", StringComparison.Ordinal) ? args[1] : args[0];
            }

            if (token.EndsWith("fr", StringComparison.Ordinal)
                && float.TryParse(token[..^2], NumberStyles.Float, CultureInfo.InvariantCulture, out float fr))
            {
                fractions[i] = Math.Max(0, fr);
            }
            else if (token is "auto" or "min-content" or "max-content" or "fit-content")
            {
                auto[i] = true;
            }
            else if (CssParser.ParseLength(token) is float length)
            {
                widths[i] = CssLength.Resolve(length, availableWidth);
                fixedTotal += widths[i];
            }
            else
            {
                fractions[i] = 1;
            }
        }

        // auto tracks: size to the max-content of the items that will land in them (first row approximation).
        for (int i = 0; i < count; i++)
        {
            if (!auto[i])
            {
                continue;
            }

            float best = 0;
            for (int k = i; k < items.Count; k += count)
            {
                best = Math.Max(best, MeasureIntrinsic(items[k], asBox: true).Max);
            }

            widths[i] = best;
            fixedTotal += best;
        }

        float remaining = Math.Max(0, availableWidth - fixedTotal);
        float fractionTotal = fractions.Sum();
        if (fractionTotal > 0)
        {
            for (int i = 0; i < count; i++)
            {
                if (fractions[i] > 0)
                {
                    widths[i] = remaining * fractions[i] / Math.Max(1, fractionTotal);
                }
            }
        }
        else if (fixedTotal > availableWidth && fixedTotal > 0)
        {
            float scale = (availableWidth - (gap * (count - 1))) / (fixedTotal - (gap * (count - 1)));
            for (int i = 0; i < count; i++)
            {
                widths[i] *= scale;
            }
        }

        return widths;
    }

    private static List<string> ExpandGridTemplate(string? template, float availableWidth, float gap)
    {
        var tokens = new List<string>();
        if (string.IsNullOrWhiteSpace(template) || template.Trim() == "none")
        {
            return tokens;
        }

        foreach (string token in CssParser.SplitValueTokens(template))
        {
            if (token.StartsWith("repeat(", StringComparison.OrdinalIgnoreCase) && token.EndsWith(')'))
            {
                string inner = token[7..^1];
                int comma = inner.IndexOf(',', StringComparison.Ordinal);
                if (comma < 0)
                {
                    continue;
                }

                string countText = inner[..comma].Trim().ToLowerInvariant();
                List<string> pattern = CssParser.SplitValueTokens(inner[(comma + 1)..]);
                int repeat;
                if (countText is "auto-fill" or "auto-fit")
                {
                    // repeat(auto-fill, minmax(200px, 1fr)): as many columns of the minimum size as fit.
                    float min = 0;
                    string first = pattern.FirstOrDefault() ?? "1fr";
                    if (first.StartsWith("minmax(", StringComparison.OrdinalIgnoreCase))
                    {
                        string minText = first[7..^1].Split(',')[0];
                        min = CssParser.ParseLength(minText) ?? 0;
                    }
                    else
                    {
                        min = CssParser.ParseLength(first) ?? 0;
                    }

                    repeat = min > 0 ? Math.Max(1, (int)((availableWidth + gap) / (min + gap))) : 1;
                    pattern = [.. pattern.Select(p => p.StartsWith("minmax(", StringComparison.OrdinalIgnoreCase) ? "1fr" : p)];
                }
                else if (!int.TryParse(countText, NumberStyles.Integer, CultureInfo.InvariantCulture, out repeat))
                {
                    repeat = 1;
                }

                for (int r = 0; r < Math.Clamp(repeat, 1, 100); r++)
                {
                    tokens.AddRange(pattern);
                }
            }
            else
            {
                tokens.Add(token);
            }
        }

        return tokens;
    }
}

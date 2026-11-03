// Licensed to SimpleSign under the MIT License.

using SimpleSign.HtmlToPdf.Parsing;

namespace SimpleSign.HtmlToPdf.Layout;

/// <summary>Floats, clearance, and absolute/fixed positioning.</summary>
public sealed partial class LayoutEngine
{
    private readonly List<FloatBox> _floats = [];
    private readonly List<PendingAbsolute> _pendingAbsolutes = [];
    private readonly List<LayoutBox> _fixedBoxes = [];

    /// <summary>Handles floats and absolutely/fixed positioned elements. Returns true when the node left the normal flow.</summary>
    private bool TryHandleOutOfFlow(HtmlNode node, ComputedStyle style, float availableWidth, float offsetX)
    {
        if (node.NodeType != HtmlNodeType.Element)
        {
            return false;
        }

        if (style.Position is PositionMode.Absolute or PositionMode.Fixed)
        {
            HtmlNode? container = null;
            if (style.Position == PositionMode.Absolute)
            {
                for (HtmlNode? p = node.Parent; p is not null; p = p.Parent)
                {
                    if (p.ComputedStyle?.Position is PositionMode.Relative or PositionMode.Absolute or PositionMode.Fixed)
                    {
                        container = p;
                        break;
                    }
                }
            }

            _pendingAbsolutes.Add(new PendingAbsolute(node, container, offsetX, CursorY, availableWidth, _currentPage, style.Position == PositionMode.Fixed));
            return true;
        }

        if (style.Float != FloatMode.None)
        {
            LayoutFloat(node, style, availableWidth, offsetX);
            return true;
        }

        return false;
    }

    private void LayoutFloat(HtmlNode node, ComputedStyle style, float availableWidth, float offsetX)
    {
        ApplyClear(style.Clear);

        float outerWidth;
        if (style.Width is float pct && CssLength.IsPercent(pct))
        {
            outerWidth = CssLength.Resolve(pct, availableWidth)
                + Math.Max(0, style.Margin.Left) + Math.Max(0, style.Margin.Right);
            if (style.BoxSizing == BoxSizing.ContentBox)
            {
                outerWidth += style.Border.LeftWidth + style.Border.RightWidth + Math.Max(0, style.Padding.Left) + Math.Max(0, style.Padding.Right);
            }
        }
        else
        {
            outerWidth = ShrinkToFit(node, availableWidth);
        }

        outerWidth = Math.Min(outerWidth, Math.Max(availableWidth, 0));
        IsolatedResult result = LayoutBoxIsolated(node, outerWidth, ignoreExplicitWidth: true);
        float height = result.Height;

        float y = CursorY;
        (float left, float right) = FloatBand(y, y + height, offsetX, offsetX + availableWidth);
        for (int attempt = 0; attempt < 64 && right - left < outerWidth - 0.01f; attempt++)
        {
            float next = float.MaxValue;
            foreach (FloatBox f in _floats)
            {
                if (f.Top < y + height && f.Bottom > y)
                {
                    next = Math.Min(next, f.Bottom);
                }
            }

            if (next == float.MaxValue)
            {
                break;
            }

            y = next;
            (left, right) = FloatBand(y, y + height, offsetX, offsetX + availableWidth);
        }

        if (!IsIsolated && y + height > _settings.ContentHeight && height <= _settings.ContentHeight && y > 0)
        {
            StartNewPage();
            y = 0;
            (left, right) = FloatBand(y, y + height, offsetX, offsetX + availableWidth);
        }

        float x = style.Float == FloatMode.Left ? left : right - outerWidth;
        if (!IsIsolated && y + height > _settings.ContentHeight)
        {
            float savedCursor = CursorY;
            CursorY = y;
            PlaceFragmented(result.Boxes, height, x);
            CursorY = savedCursor;
            return;
        }

        PlaceBoxes(result.Boxes, x, y);
        _floats.Add(new FloatBox(style.Float, x, outerWidth, y, y + height));
    }

    /// <summary>Returns the horizontal band [left, right) left free by floats between top and bottom.</summary>
    private (float Left, float Right) FloatBand(float top, float bottom, float minX, float maxX)
    {
        float left = minX;
        float right = maxX;
        foreach (FloatBox f in _floats)
        {
            if (f.Top >= bottom || f.Bottom <= top)
            {
                continue;
            }

            if (f.Side == FloatMode.Left)
            {
                left = Math.Max(left, Math.Min(f.X + f.Width, maxX));
            }
            else
            {
                right = Math.Min(right, Math.Max(f.X, minX));
            }
        }

        return (left, Math.Max(left, right));
    }

    /// <summary>Gets the band available to a line starting at a given offset from the cursor.</summary>
    private (float X, float Width) LineBand(float relativeTop, float estimatedHeight, float offsetX, float availableWidth)
    {
        if (_floats.Count == 0)
        {
            return (offsetX, availableWidth);
        }

        float top = CursorY + relativeTop;
        (float left, float right) = FloatBand(top, top + estimatedHeight, offsetX, offsetX + availableWidth);
        return (left, right - left);
    }

    private void ApplyClear(ClearMode clear)
    {
        if (clear == ClearMode.None || _floats.Count == 0)
        {
            return;
        }

        float bottom = CursorY;
        foreach (FloatBox f in _floats)
        {
            bool matches = clear == ClearMode.Both
                || (clear == ClearMode.Left && f.Side == FloatMode.Left)
                || (clear == ClearMode.Right && f.Side == FloatMode.Right);
            if (matches)
            {
                bottom = Math.Max(bottom, f.Bottom);
            }
        }

        if (bottom > CursorY)
        {
            CursorY = bottom;
            _lastMarginBottom = 0;
        }
    }

    /// <summary>Lays out absolutely positioned descendants whose containing block is <paramref name="container"/>.</summary>
    private void LayoutPendingAbsolutes(HtmlNode? container, ContainingBlock block, bool flushAll = false)
    {
        if (_pendingAbsolutes.Count == 0)
        {
            return;
        }

        List<PendingAbsolute> ready = flushAll || container is null
            ? [.. _pendingAbsolutes]
            : [.. _pendingAbsolutes.Where(p => p.Container == container)];

        foreach (PendingAbsolute pending in ready)
        {
            _pendingAbsolutes.Remove(pending);
            if (pending.Fixed && !IsIsolated)
            {
                LayoutFixed(pending);
                continue;
            }

            LayoutAbsolute(pending, container is null ? block with { Page = pending.Page } : block);
        }
    }

    private void LayoutAbsolute(PendingAbsolute pending, ContainingBlock block)
    {
        HtmlNode node = pending.Node;
        ComputedStyle style = StyleFor(node, block.Width, block.Height);
        float outerWidth = ResolveAbsoluteWidth(node, style, block.Width);
        IsolatedResult result = LayoutBoxIsolated(node, outerWidth, ignoreExplicitWidth: true);

        float x = style.Left is float left
            ? block.X + ResolvePercent(left, block.Width)
            : style.Right is float right
                ? block.X + block.Width - ResolvePercent(right, block.Width) - outerWidth
                : pending.StaticX;
        float y = style.Top is float top
            ? block.Y + ResolvePercent(top, block.Height)
            : style.Bottom is float bottom
                ? block.Y + block.Height - ResolvePercent(bottom, block.Height) - result.Height
                : pending.StaticY;

        foreach (LayoutBox box in result.Boxes)
        {
            box.X += x;
            box.Y += y;
            block.Page.Boxes.Add(box);
        }
    }

    private void LayoutFixed(PendingAbsolute pending)
    {
        HtmlNode node = pending.Node;
        float areaWidth = _settings.ContentWidth;
        float areaHeight = _settings.ContentHeight;
        ComputedStyle style = StyleFor(node, areaWidth, areaHeight);
        float outerWidth = ResolveAbsoluteWidth(node, style, areaWidth);
        IsolatedResult result = LayoutBoxIsolated(node, outerWidth, ignoreExplicitWidth: true);

        float x = _settings.Margins.Left + (style.Left is float left
            ? ResolvePercent(left, areaWidth)
            : style.Right is float right ? areaWidth - ResolvePercent(right, areaWidth) - outerWidth : 0);
        float y = style.Top is float top
            ? ResolvePercent(top, areaHeight)
            : style.Bottom is float bottom ? areaHeight - ResolvePercent(bottom, areaHeight) - result.Height : 0;

        foreach (LayoutBox box in result.Boxes)
        {
            box.X += x;
            box.Y += y;
            _fixedBoxes.Add(box);
        }
    }

    private float ResolveAbsoluteWidth(HtmlNode node, ComputedStyle style, float containerWidth)
    {
        float extras = Math.Max(0, style.Margin.Left) + Math.Max(0, style.Margin.Right);
        float boxExtras = style.Border.LeftWidth + style.Border.RightWidth + Math.Max(0, style.Padding.Left) + Math.Max(0, style.Padding.Right);
        if (style.Width is float width)
        {
            float resolved = CssLength.Resolve(width, containerWidth);
            return resolved + extras + (style.BoxSizing == BoxSizing.ContentBox ? boxExtras : 0);
        }

        if (style.Left is float l && style.Right is float r)
        {
            return Math.Max(0, containerWidth - ResolvePercent(l, containerWidth) - ResolvePercent(r, containerWidth));
        }

        return ShrinkToFit(node, containerWidth);
    }

    /// <summary>Repeats position: fixed boxes on every page (behind the page's own content is not required; drawn last).</summary>
    private void StampFixedBoxes()
    {
        if (_fixedBoxes.Count == 0)
        {
            return;
        }

        if (_pages.Count == 0)
        {
            _pages.Add(_currentPage);
        }

        foreach (PageBox page in _pages)
        {
            foreach (LayoutBox box in _fixedBoxes)
            {
                page.Boxes.Add(box.CloneAt(box.X, box.Y));
            }
        }
    }

    /// <summary>A placed float.</summary>
    private readonly record struct FloatBox(FloatMode Side, float X, float Width, float Top, float Bottom);

    /// <summary>Containing block (padding box) for absolutely positioned descendants.</summary>
    private sealed record ContainingBlock(float X, float Y, float Width, float Height, PageBox Page);

    /// <summary>An absolutely/fixed positioned element waiting for its containing block to be laid out.</summary>
    private sealed record PendingAbsolute(HtmlNode Node, HtmlNode? Container, float StaticX, float StaticY, float StaticWidth, PageBox Page, bool Fixed);
}

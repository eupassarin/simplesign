namespace SimpleSign.HtmlToPdf.Parsing;

/// <summary>
/// Resolves CSS cascade: applies browser defaults, stylesheet rules, and inline styles
/// to produce a <see cref="ComputedStyle"/> for each DOM node.
/// </summary>
public static class StyleResolver
{
    /// <summary>
    /// Resolves computed styles for the entire DOM tree.
    /// Call after parsing HTML and CSS. Sets <see cref="HtmlNode.ComputedStyle"/> on each node.
    /// </summary>
    public static void Resolve(HtmlNode root, List<CssRule> stylesheetRules)
    {
        var sortedRules = stylesheetRules
            .OrderBy(r => r.Specificity)
            .ToList();

        ResolveNode(root, parentStyle: null, sortedRules);
    }

    private static void ResolveNode(HtmlNode node, ComputedStyle? parentStyle, List<CssRule> rules)
    {
        var style = CreateInheritedStyle(parentStyle);

        if (node.NodeType == HtmlNodeType.Element && node.Tag is not null)
        {
            ApplyBrowserDefaults(style, node.Tag);

            foreach (var rule in rules)
            {
                if (MatchesSelector(node, rule.Selector))
                {
                    ApplyProperties(style, rule.Properties, parentStyle?.FontSize ?? 12f);
                }
            }

            if (node.InlineStyle is { Count: > 0 })
            {
                ApplyProperties(style, node.InlineStyle, parentStyle?.FontSize ?? 12f);
            }
            else if (node.Attributes.TryGetValue("style", out string? inlineCss) &&
                     !string.IsNullOrWhiteSpace(inlineCss))
            {
                var inlineProps = CssParser.ParseInlineStyle(inlineCss);
                ApplyProperties(style, inlineProps, parentStyle?.FontSize ?? 12f);
            }
        }

        node.ComputedStyle = style;

        foreach (var child in node.Children)
        {
            ResolveNode(child, style, rules);
        }
    }

    private static ComputedStyle CreateInheritedStyle(ComputedStyle? parent)
    {
        if (parent is null)
        {
            return new ComputedStyle();
        }

        return new ComputedStyle
        {
            FontFamily = parent.FontFamily,
            FontSize = parent.FontSize,
            IsBold = parent.IsBold,
            IsItalic = parent.IsItalic,
            Color = parent.Color,
            TextAlign = parent.TextAlign,
            LineHeight = parent.LineHeight,
        };
    }

    private static void ApplyBrowserDefaults(ComputedStyle style, string tag)
    {
        switch (tag)
        {
            case "h1":
                style.FontSize = 24f;
                style.IsBold = true;
                style.Margin = new Thickness(16f, 0f, 16f, 0f);
                style.Display = DisplayType.Block;
                break;
            case "h2":
                style.FontSize = 20f;
                style.IsBold = true;
                style.Margin = new Thickness(14f, 0f, 14f, 0f);
                style.Display = DisplayType.Block;
                break;
            case "h3":
                style.FontSize = 16f;
                style.IsBold = true;
                style.Margin = new Thickness(12f, 0f, 12f, 0f);
                style.Display = DisplayType.Block;
                break;
            case "h4":
                style.FontSize = 14f;
                style.IsBold = true;
                style.Margin = new Thickness(10f, 0f, 10f, 0f);
                style.Display = DisplayType.Block;
                break;
            case "h5":
                style.FontSize = 12f;
                style.IsBold = true;
                style.Margin = new Thickness(8f, 0f, 8f, 0f);
                style.Display = DisplayType.Block;
                break;
            case "h6":
                style.FontSize = 10f;
                style.IsBold = true;
                style.Margin = new Thickness(6f, 0f, 6f, 0f);
                style.Display = DisplayType.Block;
                break;
            case "p":
                style.Margin = new Thickness(10f, 0f, 10f, 0f);
                style.Display = DisplayType.Block;
                break;
            case "blockquote":
                style.Margin = new Thickness(10f, 20f, 10f, 20f);
                style.Padding = new Thickness(0f, 0f, 0f, 10f);
                style.Border = new BorderStyle
                {
                    LeftWidth = 2f,
                    LeftColor = PdfColor.Parse("gray"),
                };
                style.Display = DisplayType.Block;
                break;
            case "pre":
                style.FontFamily = "Courier";
                style.FontSize = 10f;
                style.Margin = new Thickness(8f, 0f, 8f, 0f);
                style.Padding = new Thickness(8f, 8f, 8f, 8f);
                style.BackgroundColor = PdfColor.Parse("#f5f5f5");
                style.Border = CreateUniformBorder(1f, PdfColor.Parse("#ddd"));
                style.Display = DisplayType.Block;
                break;
            case "code":
                style.FontFamily = "Courier";
                style.FontSize = 10f;
                break;
            case "strong" or "b":
                style.IsBold = true;
                style.Display = DisplayType.Inline;
                break;
            case "em" or "i":
                style.IsItalic = true;
                style.Display = DisplayType.Inline;
                break;
            case "u":
                style.IsUnderline = true;
                style.Display = DisplayType.Inline;
                break;
            case "s" or "del" or "strike":
                style.IsStrikethrough = true;
                style.Display = DisplayType.Inline;
                break;
            case "sub":
                style.FontPosition = FontPosition.Subscript;
                style.FontSize *= 0.7f;
                style.Display = DisplayType.Inline;
                break;
            case "sup":
                style.FontPosition = FontPosition.Superscript;
                style.FontSize *= 0.7f;
                style.Display = DisplayType.Inline;
                break;
            case "mark":
                style.BackgroundColor = new PdfColor(1f, 1f, 0f);
                style.Display = DisplayType.Inline;
                break;
            case "kbd":
                style.FontFamily = "Courier";
                style.FontSize = 10f;
                style.Display = DisplayType.Inline;
                break;
            case "a":
                style.Color = new PdfColor(0f, 0f, 1f);
                style.IsUnderline = true;
                style.Display = DisplayType.Inline;
                break;
            case "figure":
                style.Margin = new Thickness(10f, 20f, 10f, 20f);
                style.Display = DisplayType.Block;
                break;
            case "figcaption":
                style.IsItalic = true;
                style.FontSize = 10f;
                style.TextAlign = TextAlign.Center;
                style.Margin = new Thickness(4f, 0f, 0f, 0f);
                style.Display = DisplayType.Block;
                break;
            case "caption":
                style.IsBold = true;
                style.TextAlign = TextAlign.Center;
                style.Margin = new Thickness(0f, 0f, 4f, 0f);
                style.Display = DisplayType.Block;
                break;
            case "ul" or "ol":
                style.Margin = new Thickness(8f, 0f, 8f, 0f);
                style.Padding = new Thickness(0f, 0f, 0f, 30f);
                style.Display = DisplayType.Block;
                break;
            case "li":
                style.Display = DisplayType.ListItem;
                break;
            case "table":
                style.Margin = new Thickness(8f, 0f, 8f, 0f);
                style.Display = DisplayType.Block;
                break;
            case "thead" or "tbody" or "tfoot":
                style.Display = DisplayType.Block;
                break;
            case "tr":
                style.Display = DisplayType.TableRow;
                break;
            case "th":
                style.IsBold = true;
                style.Padding = new Thickness(4f, 4f, 4f, 4f);
                style.TextAlign = TextAlign.Center;
                style.Display = DisplayType.TableCell;
                break;
            case "td":
                style.Padding = new Thickness(4f, 4f, 4f, 4f);
                style.Display = DisplayType.TableCell;
                break;
            case "hr":
                style.Margin = new Thickness(8f, 0f, 8f, 0f);
                style.Border = new BorderStyle
                {
                    TopWidth = 1f,
                    TopColor = PdfColor.Parse("#999"),
                };
                style.Display = DisplayType.Block;
                break;
            case "div" or "header" or "footer" or "main" or "section" or "article" or "nav" or "aside":
                style.Display = DisplayType.Block;
                break;
            case "span" or "abbr" or "small" or "br" or "img":
                style.Display = DisplayType.Inline;
                break;
        }
    }

    private static void ApplyProperties(
        ComputedStyle style,
        Dictionary<string, string> properties,
        float parentFontSize)
    {
        foreach (var (name, value) in properties)
        {
            ApplyProperty(style, name, value, parentFontSize);
        }
    }

    private static void ApplyProperty(ComputedStyle style, string name, string value, float parentFontSize)
    {
        switch (name)
        {
            case "font-family":
                style.FontFamily = value.Split(',')[0].Trim().Trim('\'', '"');
                break;

            case "font-size":
                var fs = CssParser.ParseLength(value, parentFontSize);
                if (fs is > 0)
                {
                    style.FontSize = fs.Value;
                }

                break;

            case "font-weight":
                style.IsBold = value is "bold" or "bolder" or "700" or "800" or "900";
                break;

            case "font-style":
                style.IsItalic = value is "italic" or "oblique";
                break;

            case "text-decoration" or "text-decoration-line":
                style.IsUnderline = value.Contains("underline", StringComparison.OrdinalIgnoreCase);
                style.IsStrikethrough = value.Contains("line-through", StringComparison.OrdinalIgnoreCase);
                break;

            case "color":
                style.Color = PdfColor.Parse(value);
                break;

            case "text-align":
                style.TextAlign = ParseTextAlign(value);
                break;

            case "line-height":
                if (float.TryParse(value, System.Globalization.NumberStyles.Float,
                        System.Globalization.CultureInfo.InvariantCulture, out var lh))
                {
                    style.LineHeight = lh;
                }
                else if (CssParser.ParseLength(value, style.FontSize) is { } lhPt and > 0)
                {
                    style.LineHeight = lhPt / style.FontSize;
                }

                break;

            case "text-indent":
                if (CssParser.ParseLength(value, parentFontSize) is { } indent)
                {
                    style.TextIndent = indent;
                }

                break;

            case "margin-top":
                style.Margin = style.Margin with { Top = CssParser.ParseLength(value, parentFontSize) ?? 0f };
                break;
            case "margin-right":
                style.Margin = style.Margin with { Right = CssParser.ParseLength(value, parentFontSize) ?? 0f };
                break;
            case "margin-bottom":
                style.Margin = style.Margin with { Bottom = CssParser.ParseLength(value, parentFontSize) ?? 0f };
                break;
            case "margin-left":
                style.Margin = style.Margin with { Left = CssParser.ParseLength(value, parentFontSize) ?? 0f };
                break;

            case "padding-top":
                style.Padding = style.Padding with { Top = CssParser.ParseLength(value, parentFontSize) ?? 0f };
                break;
            case "padding-right":
                style.Padding = style.Padding with { Right = CssParser.ParseLength(value, parentFontSize) ?? 0f };
                break;
            case "padding-bottom":
                style.Padding = style.Padding with { Bottom = CssParser.ParseLength(value, parentFontSize) ?? 0f };
                break;
            case "padding-left":
                style.Padding = style.Padding with { Left = CssParser.ParseLength(value, parentFontSize) ?? 0f };
                break;

            case "border-top-width":
                EnsureMutableBorder(style).TopWidth = CssParser.ParseLength(value, parentFontSize) ?? 0f;
                break;
            case "border-right-width":
                EnsureMutableBorder(style).RightWidth = CssParser.ParseLength(value, parentFontSize) ?? 0f;
                break;
            case "border-bottom-width":
                EnsureMutableBorder(style).BottomWidth = CssParser.ParseLength(value, parentFontSize) ?? 0f;
                break;
            case "border-left-width":
                EnsureMutableBorder(style).LeftWidth = CssParser.ParseLength(value, parentFontSize) ?? 0f;
                break;

            case "border-top-color":
                EnsureMutableBorder(style).TopColor = PdfColor.Parse(value);
                break;
            case "border-right-color":
                EnsureMutableBorder(style).RightColor = PdfColor.Parse(value);
                break;
            case "border-bottom-color":
                EnsureMutableBorder(style).BottomColor = PdfColor.Parse(value);
                break;
            case "border-left-color":
                EnsureMutableBorder(style).LeftColor = PdfColor.Parse(value);
                break;
            case "border-color":
                var bc = PdfColor.Parse(value);
                var b = EnsureMutableBorder(style);
                b.TopColor = bc;
                b.RightColor = bc;
                b.BottomColor = bc;
                b.LeftColor = bc;
                break;

            case "border-collapse":
                style.BorderCollapse = value is "collapse";
                break;

            case "width":
                style.Width = CssParser.ParseLength(value, parentFontSize);
                break;
            case "max-width":
                style.MaxWidth = CssParser.ParseLength(value, parentFontSize);
                break;
            case "height":
                style.Height = CssParser.ParseLength(value, parentFontSize);
                break;

            case "display":
                style.Display = ParseDisplayType(value);
                break;

            case "page-break-before":
                style.PageBreakBefore = ParsePageBreak(value);
                break;
            case "page-break-after":
                style.PageBreakAfter = ParsePageBreak(value);
                break;

            case "background-color" or "background":
                style.BackgroundColor = PdfColor.Parse(value);
                break;

            case "vertical-align":
                style.VerticalAlign = ParseVerticalAlign(value);
                break;
        }
    }

    /// <summary>
    /// Ensures the style has a mutable (non-shared) BorderStyle instance.
    /// The default <see cref="BorderStyle.None"/> is a shared static instance that must not be mutated.
    /// </summary>
    private static BorderStyle EnsureMutableBorder(ComputedStyle style)
    {
        if (ReferenceEquals(style.Border, BorderStyle.None))
        {
            style.Border = new BorderStyle();
        }

        return style.Border;
    }

    private static BorderStyle CreateUniformBorder(float width, PdfColor color) => new()
    {
        TopWidth = width,
        RightWidth = width,
        BottomWidth = width,
        LeftWidth = width,
        TopColor = color,
        RightColor = color,
        BottomColor = color,
        LeftColor = color,
    };

    private static TextAlign ParseTextAlign(string value) => value.ToLowerInvariant() switch
    {
        "left" => TextAlign.Left,
        "center" => TextAlign.Center,
        "right" => TextAlign.Right,
        "justify" => TextAlign.Justify,
        _ => TextAlign.Left,
    };

    private static DisplayType ParseDisplayType(string value) => value.ToLowerInvariant() switch
    {
        "block" => DisplayType.Block,
        "inline" or "inline-block" => DisplayType.Inline,
        "none" => DisplayType.None,
        "table" or "table-row-group" => DisplayType.Block,
        "table-row" => DisplayType.TableRow,
        "table-cell" => DisplayType.TableCell,
        "list-item" => DisplayType.ListItem,
        _ => DisplayType.Block,
    };

    private static PageBreak ParsePageBreak(string value) => value.ToLowerInvariant() switch
    {
        "always" => PageBreak.Always,
        "avoid" => PageBreak.Avoid,
        _ => PageBreak.Auto,
    };

    private static VerticalAlign ParseVerticalAlign(string value) => value.ToLowerInvariant() switch
    {
        "top" => VerticalAlign.Top,
        "middle" => VerticalAlign.Middle,
        "bottom" => VerticalAlign.Bottom,
        _ => VerticalAlign.Top,
    };

    /// <summary>
    /// Tests whether an HTML node matches a CSS selector.
    /// Supports: tag, .class, #id, tag.class, and descendant combinators (space-separated).
    /// </summary>
    internal static bool MatchesSelector(HtmlNode node, string selector)
    {
        if (node.NodeType != HtmlNodeType.Element)
        {
            return false;
        }

        var parts = selector.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length == 0)
        {
            return false;
        }

        if (!MatchesCompoundSelector(node, parts[^1]))
        {
            return false;
        }

        if (parts.Length == 1)
        {
            return true;
        }

        // Walk up ancestors for remaining parts (right to left)
        var ancestor = node.Parent;
        for (var i = parts.Length - 2; i >= 0; i--)
        {
            var found = false;
            while (ancestor is not null)
            {
                if (MatchesCompoundSelector(ancestor, parts[i]))
                {
                    ancestor = ancestor.Parent;
                    found = true;
                    break;
                }

                ancestor = ancestor.Parent;
            }

            if (!found)
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// Matches a compound selector like "table.data" or "#main" against a single node.
    /// </summary>
    private static bool MatchesCompoundSelector(HtmlNode node, string compound)
    {
        if (node.NodeType != HtmlNodeType.Element || node.Tag is null)
        {
            return false;
        }

        string? requiredTag = null;
        string? requiredId = null;
        List<string>? requiredClasses = null;

        var i = 0;

        if (i < compound.Length && compound[i] != '.' && compound[i] != '#')
        {
            var start = i;
            while (i < compound.Length && compound[i] != '.' && compound[i] != '#')
            {
                i++;
            }

            requiredTag = compound[start..i];
        }

        while (i < compound.Length)
        {
            if (compound[i] == '.')
            {
                i++;
                var start = i;
                while (i < compound.Length && compound[i] != '.' && compound[i] != '#')
                {
                    i++;
                }

                requiredClasses ??= [];
                requiredClasses.Add(compound[start..i]);
            }
            else if (compound[i] == '#')
            {
                i++;
                var start = i;
                while (i < compound.Length && compound[i] != '.' && compound[i] != '#')
                {
                    i++;
                }

                requiredId = compound[start..i];
            }
            else
            {
                i++;
            }
        }

        if (requiredTag is not null &&
            !string.Equals(node.Tag, requiredTag, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (requiredId is not null &&
            !string.Equals(node.GetAttribute("id"), requiredId, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (requiredClasses is { Count: > 0 })
        {
            var nodeClasses = node.GetAttribute("class")?
                .Split(' ', StringSplitOptions.RemoveEmptyEntries) ?? [];

            foreach (var cls in requiredClasses)
            {
                if (!nodeClasses.Contains(cls, StringComparer.OrdinalIgnoreCase))
                {
                    return false;
                }
            }
        }

        return true;
    }
}

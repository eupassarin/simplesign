using System.Globalization;
using System.Text;

namespace SimpleSign.HtmlToPdf.Parsing;

/// <summary>
/// Parses CSS from &lt;style&gt; blocks and inline style attributes.
/// Supports tag, .class, #id selectors, shorthand properties, and common length units.
/// </summary>
public static class CssParser
{
    private const float PxToPoint = 0.75f;
    private const float MmToPoint = 2.8346f;
    private const float CmToPoint = 28.346f;
    private const float InToPoint = 72f;

    /// <summary>Parses a CSS stylesheet string into a list of rules.</summary>
    public static List<CssRule> ParseStylesheet(string css)
    {
        var rules = new List<CssRule>();
        if (string.IsNullOrWhiteSpace(css))
        {
            return rules;
        }

        css = RemoveComments(css);

        var i = 0;
        while (i < css.Length)
        {
            // Skip @-rules (e.g., @media, @import) — find matching block or semicolon
            if (i < css.Length && css[i] == '@')
            {
                var braceIdx = css.IndexOf('{', i);
                var semiIdx = css.IndexOf(';', i);

                if (semiIdx >= 0 && (braceIdx < 0 || semiIdx < braceIdx))
                {
                    i = semiIdx + 1;
                }
                else if (braceIdx >= 0)
                {
                    i = FindMatchingBrace(css, braceIdx) + 1;
                }
                else
                {
                    break;
                }

                continue;
            }

            var openBrace = css.IndexOf('{', i);
            if (openBrace < 0)
            {
                break;
            }

            var selectorPart = css[i..openBrace].Trim();

            var closeBrace = css.IndexOf('}', openBrace + 1);
            if (closeBrace < 0)
            {
                break;
            }

            var body = css[(openBrace + 1)..closeBrace].Trim();
            i = closeBrace + 1;

            if (string.IsNullOrWhiteSpace(selectorPart))
            {
                continue;
            }

            var properties = ParseDeclarations(body);
            var expanded = ExpandShorthands(properties);

            // Handle comma-separated selectors
            var selectors = selectorPart.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            foreach (var rawSelector in selectors)
            {
                var selector = NormalizeWhitespace(rawSelector);
                if (selector.Length == 0)
                {
                    continue;
                }

                rules.Add(new CssRule
                {
                    Selector = selector,
                    Properties = new Dictionary<string, string>(expanded, StringComparer.Ordinal),
                    Specificity = CalculateSpecificity(selector),
                });
            }
        }

        return rules;
    }

    /// <summary>Parses an inline style attribute value into properties.</summary>
    public static Dictionary<string, string> ParseInlineStyle(string style)
    {
        if (string.IsNullOrWhiteSpace(style))
        {
            return new Dictionary<string, string>(StringComparer.Ordinal);
        }

        var properties = ParseDeclarations(style);
        return ExpandShorthands(properties);
    }

    /// <summary>
    /// Parses a CSS length value to points. Returns null if unparseable.
    /// Percentages are returned as negative values for later resolution.
    /// </summary>
    public static float? ParseLength(string value, float parentFontSize = 12f)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var v = value.Trim().ToLowerInvariant();

        if (v is "0")
        {
            return 0f;
        }

        if (v is "auto" or "none" or "inherit" or "initial")
        {
            return null;
        }

        // Percentage → stored as negative for deferred resolution
        if (v.EndsWith('%') && TryParseFloat(v[..^1], out var pct))
        {
            return -pct;
        }

        if (v.EndsWith("px") && TryParseFloat(v[..^2], out var px))
        {
            return px * PxToPoint;
        }

        if (v.EndsWith("pt") && TryParseFloat(v[..^2], out var pt))
        {
            return pt;
        }

        if (v.EndsWith("em") && TryParseFloat(v[..^2], out var em))
        {
            return em * parentFontSize;
        }

        if (v.EndsWith("rem") && TryParseFloat(v[..^3], out var rem))
        {
            return rem * 12f; // rem relative to root (default 12pt)
        }

        if (v.EndsWith("mm") && TryParseFloat(v[..^2], out var mm))
        {
            return mm * MmToPoint;
        }

        if (v.EndsWith("cm") && TryParseFloat(v[..^2], out var cm))
        {
            return cm * CmToPoint;
        }

        if (v.EndsWith("in") && TryParseFloat(v[..^2], out var inches))
        {
            return inches * InToPoint;
        }

        // Bare number → treat as pixels
        if (TryParseFloat(v, out var bare))
        {
            return bare * PxToPoint;
        }

        return null;
    }

    /// <summary>Calculates specificity of a CSS selector.</summary>
    public static int CalculateSpecificity(string selector)
    {
        if (string.IsNullOrWhiteSpace(selector))
        {
            return 0;
        }

        var specificity = 0;
        var parts = selector.Split(' ', StringSplitOptions.RemoveEmptyEntries);

        foreach (var part in parts)
        {
            var j = 0;
            while (j < part.Length)
            {
                if (part[j] == '#')
                {
                    specificity += 100;
                    j++;
                    while (j < part.Length && part[j] != '.' && part[j] != '#')
                    {
                        j++;
                    }
                }
                else if (part[j] == '.')
                {
                    specificity += 10;
                    j++;
                    while (j < part.Length && part[j] != '.' && part[j] != '#')
                    {
                        j++;
                    }
                }
                else
                {
                    // Tag name
                    specificity += 1;
                    while (j < part.Length && part[j] != '.' && part[j] != '#')
                    {
                        j++;
                    }
                }
            }
        }

        return specificity;
    }

    private static string RemoveComments(string css)
    {
        var sb = new StringBuilder(css.Length);
        var i = 0;
        while (i < css.Length)
        {
            if (i + 1 < css.Length && css[i] == '/' && css[i + 1] == '*')
            {
                var end = css.IndexOf("*/", i + 2, StringComparison.Ordinal);
                if (end < 0)
                {
                    break;
                }
                i = end + 2;
            }
            else
            {
                sb.Append(css[i]);
                i++;
            }
        }

        return sb.ToString();
    }

    private static Dictionary<string, string> ParseDeclarations(string body)
    {
        var props = new Dictionary<string, string>(StringComparer.Ordinal);
        if (string.IsNullOrWhiteSpace(body))
        {
            return props;
        }

        var declarations = body.Split(';', StringSplitOptions.RemoveEmptyEntries);
        foreach (var decl in declarations)
        {
            var colon = decl.IndexOf(':');
            if (colon < 0)
            {
                continue;
            }

            var name = decl[..colon].Trim().ToLowerInvariant();
            var val = decl[(colon + 1)..].Trim();

            // Strip !important (treat as regular value)
            if (val.EndsWith("!important", StringComparison.OrdinalIgnoreCase))
            {
                val = val[..^10].Trim();
            }

            if (name.Length > 0 && val.Length > 0)
            {
                props[name] = val;
            }
        }

        return props;
    }

    private static Dictionary<string, string> ExpandShorthands(Dictionary<string, string> properties)
    {
        var result = new Dictionary<string, string>(properties, StringComparer.Ordinal);

        ExpandBoxShorthand(result, "margin");
        ExpandBoxShorthand(result, "padding");
        ExpandBorderShorthand(result);

        return result;
    }

    private static void ExpandBoxShorthand(Dictionary<string, string> props, string property)
    {
        if (!props.TryGetValue(property, out var value))
        {
            return;
        }

        props.Remove(property);
        var parts = value.Split(' ', StringSplitOptions.RemoveEmptyEntries);

        string top, right, bottom, left;
        switch (parts.Length)
        {
            case 1:
                top = right = bottom = left = parts[0];
                break;
            case 2:
                top = bottom = parts[0];
                right = left = parts[1];
                break;
            case 3:
                top = parts[0];
                right = left = parts[1];
                bottom = parts[2];
                break;
            default:
                top = parts[0];
                right = parts[1];
                bottom = parts[2];
                left = parts.Length > 3 ? parts[3] : parts[1];
                break;
        }

        props.TryAdd($"{property}-top", top);
        props.TryAdd($"{property}-right", right);
        props.TryAdd($"{property}-bottom", bottom);
        props.TryAdd($"{property}-left", left);
    }

    private static void ExpandBorderShorthand(Dictionary<string, string> props)
    {
        // Expand shorthand "border" into per-side width + color
        if (props.TryGetValue("border", out var borderValue))
        {
            props.Remove("border");
            ParseBorderValue(borderValue, out var width, out var color);

            if (width is not null)
            {
                props.TryAdd("border-top-width", width);
                props.TryAdd("border-right-width", width);
                props.TryAdd("border-bottom-width", width);
                props.TryAdd("border-left-width", width);
            }

            if (color is not null)
            {
                props.TryAdd("border-top-color", color);
                props.TryAdd("border-right-color", color);
                props.TryAdd("border-bottom-color", color);
                props.TryAdd("border-left-color", color);
            }
        }

        // Expand individual side shorthands: border-top, border-right, etc.
        ExpandSingleBorderSide(props, "border-top");
        ExpandSingleBorderSide(props, "border-right");
        ExpandSingleBorderSide(props, "border-bottom");
        ExpandSingleBorderSide(props, "border-left");
    }

    private static void ExpandSingleBorderSide(Dictionary<string, string> props, string property)
    {
        if (!props.TryGetValue(property, out var value))
        {
            return;
        }

        props.Remove(property);
        ParseBorderValue(value, out var width, out var color);

        if (width is not null)
        {
            props.TryAdd($"{property}-width", width);
        }

        if (color is not null)
        {
            props.TryAdd($"{property}-color", color);
        }
    }

    private static void ParseBorderValue(string value, out string? width, out string? color)
    {
        width = null;
        color = null;

        var parts = value.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        foreach (var part in parts)
        {
            if (part is "solid" or "dashed" or "dotted" or "double" or "groove" or "ridge" or "inset" or "outset" or "none")
            {
                continue;
            }

            if (IsColorValue(part))
            {
                color = part;
            }
            else
            {
                width ??= part;
            }
        }
    }

    private static bool IsColorValue(string value)
    {
        if (value.StartsWith('#'))
        {
            return true;
        }

        if (value.StartsWith("rgb", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return value.ToLowerInvariant() is "black" or "white" or "red" or "green" or "blue"
            or "gray" or "grey" or "silver" or "yellow" or "orange" or "purple" or "cyan"
            or "magenta" or "transparent" or "currentcolor";
    }

    private static int FindMatchingBrace(string css, int openBrace)
    {
        var depth = 1;
        for (var i = openBrace + 1; i < css.Length; i++)
        {
            if (css[i] == '{')
            {
                depth++;
            }
            else if (css[i] == '}' && --depth == 0)
            {
                return i;
            }
        }

        return css.Length - 1;
    }

    private static string NormalizeWhitespace(string s)
    {
        var sb = new StringBuilder(s.Length);
        var lastWasSpace = false;
        foreach (var c in s)
        {
            if (char.IsWhiteSpace(c))
            {
                if (!lastWasSpace && sb.Length > 0)
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

        // Trim trailing space
        if (sb.Length > 0 && sb[^1] == ' ')
        {
            sb.Length--;
        }

        return sb.ToString();
    }

    private static bool TryParseFloat(string s, out float result) =>
        float.TryParse(s, NumberStyles.Float, CultureInfo.InvariantCulture, out result);
}

using System.Globalization;
using System.Text;

namespace SimpleSign.HtmlToPdf.Parsing;

/// <summary>
/// Parses CSS from &lt;style&gt; blocks and inline style attributes.
/// Supports complex selectors, <c>!important</c>, <c>@media print</c>, <c>@page</c>,
/// <c>@font-face</c>, shorthand properties, and common length units.
/// </summary>
public static class CssParser
{
    private const float PxToPoint = 0.75f;
    private const float MmToPoint = 2.8346f;
    private const float CmToPoint = 28.346f;
    private const float InToPoint = 72f;
    private const float PcToPoint = 12f;

    /// <summary>Selector used for rules that come from <c>@page</c> blocks.</summary>
    public const string PageRuleSelector = "@page";

    /// <summary>Selector used for rules that come from <c>@font-face</c> blocks.</summary>
    public const string FontFaceRuleSelector = "@font-face";

    /// <summary>Parses a CSS stylesheet string into a list of rules.</summary>
    /// <param name="css">The stylesheet text.</param>
    /// <returns>The parsed rules in source order.</returns>
    public static List<CssRule> ParseStylesheet(string css)
    {
        var rules = new List<CssRule>();
        if (string.IsNullOrWhiteSpace(css))
        {
            return rules;
        }

        ParseBlock(RemoveComments(css), rules);
        for (int i = 0; i < rules.Count; i++)
        {
            rules[i].Order = i;
        }

        return rules;
    }

    private static void ParseBlock(string css, List<CssRule> rules)
    {
        var i = 0;
        while (i < css.Length)
        {
            while (i < css.Length && char.IsWhiteSpace(css[i]))
            {
                i++;
            }

            if (i >= css.Length)
            {
                break;
            }

            if (css[i] == '@')
            {
                i = ParseAtRule(css, i, rules);
                continue;
            }

            var openBrace = IndexOutsideStrings(css, '{', i);
            if (openBrace < 0)
            {
                break;
            }

            var selectorPart = css[i..openBrace].Trim();
            var closeBrace = FindMatchingBrace(css, openBrace);
            var body = css[(openBrace + 1)..Math.Min(closeBrace, css.Length)].Trim();
            i = closeBrace + 1;

            if (string.IsNullOrWhiteSpace(selectorPart))
            {
                continue;
            }

            var (normal, important) = ParseDeclarationsWithImportance(body);
            var expanded = ExpandShorthands(normal);
            var expandedImportant = ExpandShorthands(important);

            foreach (var rawSelector in SplitTopLevel(selectorPart, ','))
            {
                var selector = NormalizeWhitespace(rawSelector);
                if (selector.Length == 0)
                {
                    continue;
                }

                CssSelector? parsed = CssSelector.TryParse(selector);
                if (parsed is null)
                {
                    continue;
                }

                rules.Add(new CssRule
                {
                    Selector = selector,
                    Properties = new Dictionary<string, string>(expanded, StringComparer.Ordinal),
                    ImportantProperties = new Dictionary<string, string>(expandedImportant, StringComparer.Ordinal),
                    Specificity = CalculateSpecificity(selector),
                    ParsedSelector = parsed,
                });
            }
        }
    }

    private static int ParseAtRule(string css, int start, List<CssRule> rules)
    {
        var braceIdx = IndexOutsideStrings(css, '{', start);
        var semiIdx = IndexOutsideStrings(css, ';', start);

        if (semiIdx >= 0 && (braceIdx < 0 || semiIdx < braceIdx))
        {
            // @import, @charset, @namespace: ignored (no network access during conversion).
            return semiIdx + 1;
        }

        if (braceIdx < 0)
        {
            return css.Length;
        }

        int close = FindMatchingBrace(css, braceIdx);
        string prelude = css[(start + 1)..braceIdx].Trim();
        string body = css[(braceIdx + 1)..Math.Min(close, css.Length)];
        string keyword = prelude.Split([' ', '\t', '\n', '\r', '('], 2)[0].ToLowerInvariant();

        switch (keyword)
        {
            case "media":
                if (MediaQueryAppliesToPrint(prelude[5..]))
                {
                    ParseBlock(body, rules);
                }

                break;

            case "supports":
                ParseBlock(body, rules);
                break;

            case "page":
                {
                    var (normal, important) = ParseDeclarationsWithImportance(StripNestedBlocks(body));
                    foreach (var (key, value) in important)
                    {
                        normal[key] = value;
                    }

                    string pageSelector = prelude[4..].Trim();
                    string selector = pageSelector.Length > 0 ? $"{PageRuleSelector} {pageSelector}" : PageRuleSelector;
                    rules.Add(new CssRule
                    {
                        Selector = selector,
                        Properties = ExpandShorthands(normal),
                    });

                    // Margin boxes (@top-center { ... }) become "@page[ :first] @top-center" rules.
                    foreach (var (boxName, boxBody) in ExtractNestedBlocks(body))
                    {
                        var (boxNormal, boxImportant) = ParseDeclarationsWithImportance(boxBody);
                        foreach (var (key, value) in boxImportant)
                        {
                            boxNormal[key] = value;
                        }

                        rules.Add(new CssRule { Selector = $"{selector} @{boxName}", Properties = ExpandShorthands(boxNormal) });
                    }

                    break;
                }

            case "font-face":
                {
                    var (normal, _) = ParseDeclarationsWithImportance(body);
                    rules.Add(new CssRule
                    {
                        Selector = FontFaceRuleSelector,
                        Properties = normal,
                    });
                    break;
                }
        }

        return close + 1;
    }

    /// <summary>Evaluates a media query list for a paged print medium.</summary>
    internal static bool MediaQueryAppliesToPrint(string query)
    {
        string q = query.Trim().ToLowerInvariant();
        if (q.Length == 0)
        {
            return true;
        }

        foreach (string part in q.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            bool negated = part.StartsWith("not ", StringComparison.Ordinal);
            string body = negated ? part[4..] : part;
            if (body.StartsWith("only ", StringComparison.Ordinal))
            {
                body = body[5..];
            }

            string type = body.Split([' ', '('], 2)[0];
            bool typeMatches = type is "print" or "all" or "" || body.StartsWith('(');
            if (type is "screen" or "speech")
            {
                typeMatches = false;
            }

            if (typeMatches != negated)
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>Parses an inline style attribute value into properties.</summary>
    /// <param name="style">The inline style text.</param>
    /// <returns>The expanded properties (important declarations are merged in).</returns>
    public static Dictionary<string, string> ParseInlineStyle(string style)
    {
        if (string.IsNullOrWhiteSpace(style))
        {
            return new Dictionary<string, string>(StringComparer.Ordinal);
        }

        var (normal, important) = ParseDeclarationsWithImportance(style);
        foreach (var (key, value) in important)
        {
            normal[key] = value;
        }

        return ExpandShorthands(normal);
    }

    /// <summary>
    /// Parses a CSS length value to points. Returns null if unparseable.
    /// Percentages are returned as negative values for later resolution.
    /// </summary>
    /// <param name="value">The CSS length.</param>
    /// <param name="parentFontSize">The font size that <c>em</c> is relative to.</param>
    /// <returns>The length in points, a negative percentage, or null.</returns>
    public static float? ParseLength(string value, float parentFontSize = 12f) => ParseLengthCore(value, parentFontSize);

    private static float? EvaluateStaticCalc(string value, float fontSize)
    {
        if (CssCalc.TryParse(value, fontSize) is not { } calc)
        {
            return null;
        }

        if (!calc.HasPercent)
        {
            return calc.Evaluate(0);
        }

        // A pure percentage (e.g. calc(50% / 2)) keeps the negative-percentage encoding.
        float atHundred = calc.Evaluate(100f);
        bool purePercent = calc.IsLinear && Math.Abs(calc.Evaluate(0)) < 1e-4f;
        return purePercent ? CssLength.Percent(atHundred) : null;
    }

    private static float? ParseLengthCore(string value, float parentFontSize)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var v = value.Trim().ToLowerInvariant();

        if (CssCalc.IsMathFunction(v))
        {
            return EvaluateStaticCalc(v, parentFontSize);
        }

        if (v is "0" or "0.0")
        {
            return 0f;
        }

        if (v is "auto" or "none" or "inherit" or "initial" or "unset" or "normal")
        {
            return null;
        }

        if (v is "thin")
        {
            return 0.75f;
        }

        if (v is "medium")
        {
            return 2.25f;
        }

        if (v is "thick")
        {
            return 3.75f;
        }

        // Percentage → stored as negative for deferred resolution
        if (v.EndsWith('%') && TryParseFloat(v[..^1], out var pct))
        {
            return CssLength.Percent(pct);
        }

        if (v.EndsWith("px") && TryParseFloat(v[..^2], out var px))
        {
            return px * PxToPoint;
        }

        if (v.EndsWith("pt") && TryParseFloat(v[..^2], out var pt))
        {
            return pt;
        }

        if (v.EndsWith("rem") && TryParseFloat(v[..^3], out var rem))
        {
            return rem * 12f; // rem relative to root (default 12pt)
        }

        if (v.EndsWith("em") && TryParseFloat(v[..^2], out var em))
        {
            return em * parentFontSize;
        }

        if (v.EndsWith("ex") && TryParseFloat(v[..^2], out var ex))
        {
            return ex * parentFontSize * 0.5f;
        }

        if (v.EndsWith("ch") && TryParseFloat(v[..^2], out var ch))
        {
            return ch * parentFontSize * 0.5f;
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

        if (v.EndsWith("pc") && TryParseFloat(v[..^2], out var pc))
        {
            return pc * PcToPoint;
        }

        if (v.EndsWith('q') && TryParseFloat(v[..^1], out var q))
        {
            return q * MmToPoint / 4f;
        }

        // Bare number → treat as pixels
        if (TryParseFloat(v, out var bare))
        {
            return bare * PxToPoint;
        }

        return null;
    }

    /// <summary>Calculates specificity of a CSS selector (ids × 100 + classes/attributes/pseudo-classes × 10 + types).</summary>
    /// <param name="selector">The selector text.</param>
    /// <returns>The specificity weight.</returns>
    public static int CalculateSpecificity(string selector)
    {
        if (string.IsNullOrWhiteSpace(selector))
        {
            return 0;
        }

        CssSelector? parsed = CssSelector.TryParse(selector);
        if (parsed is null)
        {
            return 0;
        }

        int key = parsed.SpecificityKey;
        return ((key / 10000) * 100) + (((key / 100) % 100) * 10) + (key % 100);
    }

    /// <summary>Splits text on a separator that is not inside quotes or parentheses.</summary>
    internal static List<string> SplitTopLevel(string text, char separator)
    {
        var parts = new List<string>();
        int depth = 0;
        char quote = '\0';
        int start = 0;
        for (int i = 0; i < text.Length; i++)
        {
            char c = text[i];
            if (quote != '\0')
            {
                if (c == '\\')
                {
                    i++;
                }
                else if (c == quote)
                {
                    quote = '\0';
                }

                continue;
            }

            if (c is '"' or '\'')
            {
                quote = c;
            }
            else if (c is '(' or '[')
            {
                depth++;
            }
            else if (c is ')' or ']')
            {
                depth = Math.Max(0, depth - 1);
            }
            else if (c == separator && depth == 0)
            {
                parts.Add(text[start..i].Trim());
                start = i + 1;
            }
        }

        string last = text[start..].Trim();
        if (last.Length > 0)
        {
            parts.Add(last);
        }

        return parts;
    }

    /// <summary>Splits a value on whitespace that is not inside quotes or parentheses.</summary>
    internal static List<string> SplitValueTokens(string value)
    {
        var parts = new List<string>();
        int depth = 0;
        char quote = '\0';
        var current = new StringBuilder();
        foreach (char c in value)
        {
            if (quote != '\0')
            {
                current.Append(c);
                if (c == quote)
                {
                    quote = '\0';
                }

                continue;
            }

            if (c is '"' or '\'')
            {
                quote = c;
                current.Append(c);
            }
            else if (c == '(')
            {
                depth++;
                current.Append(c);
            }
            else if (c == ')')
            {
                depth = Math.Max(0, depth - 1);
                current.Append(c);
            }
            else if (char.IsWhiteSpace(c) && depth == 0)
            {
                if (current.Length > 0)
                {
                    parts.Add(current.ToString());
                    current.Clear();
                }
            }
            else
            {
                current.Append(c);
            }
        }

        if (current.Length > 0)
        {
            parts.Add(current.ToString());
        }

        return parts;
    }

    private static string RemoveComments(string css)
    {
        var sb = new StringBuilder(css.Length);
        var i = 0;
        char quote = '\0';
        while (i < css.Length)
        {
            char c = css[i];
            if (quote != '\0')
            {
                sb.Append(c);
                if (c == '\\' && i + 1 < css.Length)
                {
                    sb.Append(css[i + 1]);
                    i += 2;
                    continue;
                }

                if (c == quote)
                {
                    quote = '\0';
                }

                i++;
                continue;
            }

            if (c is '"' or '\'')
            {
                quote = c;
                sb.Append(c);
                i++;
            }
            else if (i + 1 < css.Length && c == '/' && css[i + 1] == '*')
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
                sb.Append(c);
                i++;
            }
        }

        return sb.ToString();
    }

    private static (Dictionary<string, string> Normal, Dictionary<string, string> Important) ParseDeclarationsWithImportance(string body)
    {
        var props = new Dictionary<string, string>(StringComparer.Ordinal);
        var important = new Dictionary<string, string>(StringComparer.Ordinal);
        if (string.IsNullOrWhiteSpace(body))
        {
            return (props, important);
        }

        foreach (var decl in SplitTopLevel(body, ';'))
        {
            var colon = decl.IndexOf(':', StringComparison.Ordinal);
            if (colon < 0)
            {
                continue;
            }

            var rawName = decl[..colon].Trim();
            var name = rawName.StartsWith("--", StringComparison.Ordinal) ? rawName : rawName.ToLowerInvariant();
            var val = decl[(colon + 1)..].Trim();

            bool isImportant = false;
            int bang = val.LastIndexOf('!');
            if (bang >= 0 && val[(bang + 1)..].Trim().Equals("important", StringComparison.OrdinalIgnoreCase))
            {
                val = val[..bang].Trim();
                isImportant = true;
            }

            if (name.Length == 0 || val.Length == 0)
            {
                continue;
            }

            if (isImportant)
            {
                important[name] = val;
                props.Remove(name);
            }
            else if (!important.ContainsKey(name))
            {
                props[name] = val;
            }
        }

        return (props, important);
    }

    private static Dictionary<string, string> ExpandShorthands(Dictionary<string, string> properties)
    {
        var result = new Dictionary<string, string>(StringComparer.Ordinal);

        // Shorthands expand in place so later longhands in the same block keep winning
        // (dictionary preserves insertion order for this small, add-only use).
        foreach (var (name, value) in properties)
        {
            switch (name)
            {
                case "margin" or "padding" or "border-width" or "border-color" or "border-style":
                    ExpandBoxShorthand(result, name, value);
                    break;
                case "border":
                    ExpandBorder(result, value, "border-top", "border-right", "border-bottom", "border-left");
                    break;
                case "border-top" or "border-right" or "border-bottom" or "border-left":
                    ExpandBorder(result, value, name);
                    break;
                case "list-style":
                    ExpandListStyle(result, value);
                    break;
                case "font":
                    ExpandFont(result, value);
                    break;
                case "flex-flow":
                    foreach (string token in SplitValueTokens(value))
                    {
                        result[token.Contains("wrap", StringComparison.OrdinalIgnoreCase) ? "flex-wrap" : "flex-direction"] = token;
                    }

                    break;
                case "break-before":
                    result["page-break-before"] = MapBreakValue(value);
                    break;
                case "break-after":
                    result["page-break-after"] = MapBreakValue(value);
                    break;
                case "break-inside":
                    result["page-break-inside"] = MapBreakValue(value);
                    break;
                case "inset":
                    ExpandBoxShorthand(result, "inset", value);
                    break;
                default:
                    result[name] = value;
                    break;
            }
        }

        return result;
    }

    private static string MapBreakValue(string value) => value.Trim().ToLowerInvariant() switch
    {
        "page" or "left" or "right" or "recto" or "verso" or "always" => "always",
        "avoid" or "avoid-page" => "avoid",
        _ => "auto",
    };

    private static void ExpandBoxShorthand(Dictionary<string, string> props, string property, string value)
    {
        var parts = SplitValueTokens(value);
        if (parts.Count == 0)
        {
            return;
        }

        string top, right, bottom, left;
        switch (parts.Count)
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
                left = parts[3];
                break;
        }

        if (property.StartsWith("border-", StringComparison.Ordinal))
        {
            string suffix = property[7..];
            props[$"border-top-{suffix}"] = top;
            props[$"border-right-{suffix}"] = right;
            props[$"border-bottom-{suffix}"] = bottom;
            props[$"border-left-{suffix}"] = left;
            return;
        }

        if (property == "inset")
        {
            props["top"] = top;
            props["right"] = right;
            props["bottom"] = bottom;
            props["left"] = left;
            return;
        }

        props[$"{property}-top"] = top;
        props[$"{property}-right"] = right;
        props[$"{property}-bottom"] = bottom;
        props[$"{property}-left"] = left;
    }

    private static void ExpandBorder(Dictionary<string, string> props, string value, params string[] sides)
    {
        ParseBorderValue(value, out var width, out var color, out var style);

        // The border shorthand resets all three longhands.
        bool isNone = style is "none" or "hidden";
        width ??= isNone ? "0" : "medium";
        color ??= "currentcolor";
        style ??= "solid";
        if (isNone)
        {
            width = "0";
        }

        foreach (string side in sides)
        {
            props[$"{side}-width"] = width;
            props[$"{side}-color"] = color;
            props[$"{side}-style"] = style;
        }
    }

    private static void ParseBorderValue(string value, out string? width, out string? color, out string? style)
    {
        width = null;
        color = null;
        style = null;

        foreach (var part in SplitValueTokens(value))
        {
            string lower = part.ToLowerInvariant();
            if (lower is "solid" or "dashed" or "dotted" or "double" or "groove" or "ridge" or "inset" or "outset" or "none" or "hidden")
            {
                style = lower;
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

    private static void ExpandListStyle(Dictionary<string, string> props, string value)
    {
        foreach (string token in SplitValueTokens(value))
        {
            string lower = token.ToLowerInvariant();
            if (lower is "inside" or "outside")
            {
                props["list-style-position"] = lower;
            }
            else if (lower.StartsWith("url(", StringComparison.Ordinal))
            {
                props["list-style-image"] = token;
            }
            else
            {
                props["list-style-type"] = token;
            }
        }
    }

    private static void ExpandFont(Dictionary<string, string> props, string value)
    {
        List<string> tokens = SplitValueTokens(value);
        int sizeIndex = -1;
        for (int i = 0; i < tokens.Count; i++)
        {
            string token = tokens[i].Split('/')[0];
            if (ParseLength(token) is not null || token.ToLowerInvariant() is "small" or "medium" or "large" or "x-large" or "xx-large" or "x-small" or "xx-small" or "smaller" or "larger")
            {
                if (i > 0 && int.TryParse(token, NumberStyles.Integer, CultureInfo.InvariantCulture, out int numeric) && numeric % 100 == 0 && !tokens[i].Contains('/', StringComparison.Ordinal) && i < tokens.Count - 2)
                {
                    // Numeric weight such as 700 before the size.
                    props["font-weight"] = token;
                    continue;
                }

                sizeIndex = i;
                break;
            }
        }

        if (sizeIndex < 0)
        {
            return;
        }

        props["font-style"] = "normal";
        props["font-weight"] = props.TryGetValue("font-weight", out string? existingWeight) ? existingWeight : "normal";
        for (int i = 0; i < sizeIndex; i++)
        {
            string lower = tokens[i].ToLowerInvariant();
            if (lower is "italic" or "oblique")
            {
                props["font-style"] = lower;
            }
            else if (lower is "bold" or "bolder" or "lighter" || (int.TryParse(lower, NumberStyles.Integer, CultureInfo.InvariantCulture, out int w) && w % 100 == 0))
            {
                props["font-weight"] = lower;
            }
        }

        string[] sizeAndLine = tokens[sizeIndex].Split('/', 2);
        props["font-size"] = sizeAndLine[0];
        if (sizeAndLine.Length > 1)
        {
            props["line-height"] = sizeAndLine[1];
        }
        else if (sizeIndex + 2 < tokens.Count && tokens[sizeIndex + 1] == "/")
        {
            props["line-height"] = tokens[sizeIndex + 2];
            sizeIndex += 2;
        }

        string family = string.Join(' ', tokens.Skip(sizeIndex + 1));
        if (family.Length > 0)
        {
            props["font-family"] = family;
        }
    }

    internal static bool IsColorValue(string value)
    {
        if (value.StartsWith('#'))
        {
            return true;
        }

        if (value.StartsWith("rgb", StringComparison.OrdinalIgnoreCase)
            || value.StartsWith("hsl", StringComparison.OrdinalIgnoreCase)
            || value.StartsWith("var(", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return value.Equals("currentcolor", StringComparison.OrdinalIgnoreCase) || PdfColor.IsNamedColor(value);
    }

    private static int FindMatchingBrace(string css, int openBrace)
    {
        var depth = 0;
        char quote = '\0';
        for (var i = openBrace; i < css.Length; i++)
        {
            char c = css[i];
            if (quote != '\0')
            {
                if (c == '\\')
                {
                    i++;
                }
                else if (c == quote)
                {
                    quote = '\0';
                }

                continue;
            }

            if (c is '"' or '\'')
            {
                quote = c;
            }
            else if (c == '{')
            {
                depth++;
            }
            else if (c == '}' && --depth == 0)
            {
                return i;
            }
        }

        return css.Length;
    }

    private static int IndexOutsideStrings(string css, char target, int start)
    {
        char quote = '\0';
        for (int i = start; i < css.Length; i++)
        {
            char c = css[i];
            if (quote != '\0')
            {
                if (c == '\\')
                {
                    i++;
                }
                else if (c == quote)
                {
                    quote = '\0';
                }

                continue;
            }

            if (c is '"' or '\'')
            {
                quote = c;
            }
            else if (c == target)
            {
                return i;
            }
        }

        return -1;
    }

    /// <summary>Returns the <c>@name { body }</c> blocks nested in an at-rule body.</summary>
    private static List<(string Name, string Body)> ExtractNestedBlocks(string body)
    {
        var blocks = new List<(string, string)>();
        int i = 0;
        while (i < body.Length)
        {
            int at = body.IndexOf('@', i);
            if (at < 0)
            {
                break;
            }

            int open = body.IndexOf('{', at);
            if (open < 0)
            {
                break;
            }

            int depth = 0;
            int close = -1;
            for (int j = open; j < body.Length; j++)
            {
                if (body[j] == '{')
                {
                    depth++;
                }
                else if (body[j] == '}' && --depth == 0)
                {
                    close = j;
                    break;
                }
            }

            if (close < 0)
            {
                break;
            }

            string name = body[(at + 1)..open].Trim().ToLowerInvariant();
            if (name.Length > 0 && name.All(c => char.IsAsciiLetterLower(c) || c == '-'))
            {
                blocks.Add((name, body[(open + 1)..close]));
            }

            i = close + 1;
        }

        return blocks;
    }

    private static string StripNestedBlocks(string body)
    {
        // Removes margin boxes such as @top-center { ... } inside @page.
        var sb = new StringBuilder(body.Length);
        int depth = 0;
        foreach (char c in body)
        {
            if (c == '{')
            {
                depth++;
                // Drop the at-keyword that introduced the nested block.
                int at = sb.ToString().LastIndexOf('@');
                if (at >= 0)
                {
                    sb.Length = at;
                }

                continue;
            }

            if (c == '}')
            {
                depth = Math.Max(0, depth - 1);
                continue;
            }

            if (depth == 0)
            {
                sb.Append(c);
            }
        }

        return sb.ToString();
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

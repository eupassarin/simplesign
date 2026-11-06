using System.Globalization;
using System.Text;

namespace SimpleSign.HtmlToPdf.Parsing;

/// <summary>
/// Tolerant HTML parser that produces a lightweight DOM tree.
/// Handles well-formed document HTML (headings, paragraphs, tables, lists, images).
/// Not a full HTML5 parser -- designed for structured documents, not arbitrary web pages.
/// </summary>
/// <remarks>
/// Architecture: single-pass character-by-character parser. No regex.
/// Supports self-closing tags, quoted/unquoted attributes, entities, comments,
/// DOCTYPE, implicit closing for p/li, and whitespace normalization (except pre).
/// </remarks>
public static class HtmlTokenizer
{
    /// <summary>Maximum nesting depth to prevent stack overflow on malicious input.</summary>
    private const int MaxNestingDepth = 256;

    // Tags that auto-close an open <p> when encountered
    private static readonly HashSet<string> BlockTags =
    [
        "div", "p", "h1", "h2", "h3", "h4", "h5", "h6",
        "blockquote", "pre", "ul", "ol", "li", "table",
        "thead", "tbody", "tfoot", "tr", "hr",
        "header", "footer", "section", "article", "main",
    ];

    /// <summary>Parses an HTML string into a DOM tree.</summary>
    /// <param name="html">The HTML content to parse.</param>
    /// <returns>The root node of the parsed DOM tree.</returns>
    public static HtmlNode Parse(string html)
    {
        HtmlNode root = HtmlNode.CreateElement("html");
        var stack = new Stack<HtmlNode>();
        stack.Push(root);

        int pos = 0;
        int length = html.Length;

        while (pos < length)
        {
            if (html[pos] == '<')
            {
                // Flush any accumulated text before processing the tag
                // (text is handled in the else branch below)

                if (pos + 1 < length && html[pos + 1] == '!')
                {
                    // Comment <!-- ... --> or DOCTYPE <!DOCTYPE ...>
                    pos = SkipCommentOrDoctype(html, pos);
                    continue;
                }

                if (pos + 1 < length && html[pos + 1] == '/')
                {
                    // Closing tag </tag>
                    pos = HandleClosingTag(html, pos, stack);
                    continue;
                }

                // Opening tag <tag ...> or self-closing <tag ... />
                pos = HandleOpeningTag(html, pos, stack);
            }
            else
            {
                // Text content
                pos = HandleText(html, pos, stack);
            }
        }

        return root;
    }

    /// <summary>Skips HTML comments and DOCTYPE declarations.</summary>
    private static int SkipCommentOrDoctype(string html, int pos)
    {
        // Comment: <!-- ... -->
        if (pos + 3 < html.Length && html[pos + 2] == '-' && html[pos + 3] == '-')
        {
            int end = html.IndexOf("-->", pos + 4, StringComparison.Ordinal);
            return end < 0 ? html.Length : end + 3;
        }

        // DOCTYPE or other <! ... >
        int close = html.IndexOf('>', pos + 2);
        return close < 0 ? html.Length : close + 1;
    }

    /// <summary>Handles a closing tag and pops the element stack.</summary>
    private static int HandleClosingTag(string html, int pos, Stack<HtmlNode> stack)
    {
        int tagStart = pos + 2; // skip </
        int tagEnd = html.IndexOf('>', tagStart);
        if (tagEnd < 0)
        {
            return html.Length;
        }

        string tag = html[tagStart..tagEnd].Trim().ToLowerInvariant();

        // Pop stack until we find the matching tag (tolerant of mismatched tags)
        PopStackTo(stack, tag);

        return tagEnd + 1;
    }

    /// <summary>Pops the element stack up to and including the element with the given tag.</summary>
    private static void PopStackTo(Stack<HtmlNode> stack, string tag)
    {
        // Search the stack for the matching tag
        bool found = false;
        foreach (HtmlNode node in stack)
        {
            if (node.Tag == tag)
            {
                found = true;
                break;
            }
        }

        if (!found)
        {
            return; // Tag not on stack -- ignore the close tag
        }

        // Pop until we reach the matching element
        while (stack.Count > 1)
        {
            if (stack.Peek().Tag == tag)
            {
                stack.Pop();
                return;
            }

            stack.Pop();
        }
    }

    /// <summary>Handles an opening tag, creating an element and pushing it onto the stack.</summary>
    private static int HandleOpeningTag(string html, int pos, Stack<HtmlNode> stack)
    {
        pos++; // skip <
        int length = html.Length;

        // Read tag name
        int nameStart = pos;
        while (pos < length && html[pos] != '>' && html[pos] != '/' && !char.IsWhiteSpace(html[pos]))
        {
            pos++;
        }

        string tag = html[nameStart..pos].ToLowerInvariant();
        if (tag.Length == 0)
        {
            // Malformed tag -- skip to next >
            int close = html.IndexOf('>', pos);
            return close < 0 ? length : close + 1;
        }

        // Auto-close logic for <p> and <li>
        AutoCloseImplicit(stack, tag);

        HtmlNode element = HtmlNode.CreateElement(tag);

        // Parse attributes
        pos = ParseAttributes(html, pos, element);

        // Check for self-closing /> or void element
        bool selfClosing = false;
        if (pos < length && html[pos] == '/')
        {
            selfClosing = true;
            pos++;
        }

        if (pos < length && html[pos] == '>')
        {
            pos++;
        }

        // Append to current parent
        stack.Peek().AppendChild(element);

        // Handle <style> specially: read raw content until </style>
        if (tag == "style")
        {
            pos = HandleRawTextElement(html, pos, element, "style");
            return pos;
        }

        // Handle <script> specially: skip content until </script>
        if (tag == "script")
        {
            pos = HandleRawTextElement(html, pos, element, "script");
            return pos;
        }

        // Don't push void or self-closing elements onto the stack
        // Enforce max nesting depth to prevent stack overflow on malicious input
        if (!selfClosing && !element.IsVoid && stack.Count < MaxNestingDepth)
        {
            stack.Push(element);
        }

        return pos;
    }

    /// <summary>Auto-closes implicitly closeable elements (p, li) when appropriate.</summary>
    private static void AutoCloseImplicit(Stack<HtmlNode> stack, string incomingTag)
    {
        if (stack.Count <= 1)
        {
            return;
        }

        string? currentTag = stack.Peek().Tag;

        // Auto-close <p> when a block element is encountered
        if (currentTag == "p" && BlockTags.Contains(incomingTag))
        {
            stack.Pop();
        }

        // Auto-close <li> when another <li> is encountered
        if (currentTag == "li" && incomingTag == "li")
        {
            stack.Pop();
        }

        // Auto-close <tr> when another <tr> is encountered
        if (currentTag == "tr" && incomingTag == "tr")
        {
            stack.Pop();
        }

        // Auto-close <td>/<th> when another <td>/<th> or <tr> is encountered
        if (currentTag is "td" or "th" && incomingTag is "td" or "th" or "tr")
        {
            stack.Pop();
        }
    }

    /// <summary>Parses element attributes from the current position.</summary>
    private static int ParseAttributes(string html, int pos, HtmlNode element)
    {
        int length = html.Length;

        while (pos < length)
        {
            // Skip whitespace
            while (pos < length && char.IsWhiteSpace(html[pos]))
            {
                pos++;
            }

            // Check for end of tag
            if (pos >= length || html[pos] == '>' || html[pos] == '/')
            {
                break;
            }

            // Read attribute name
            int attrNameStart = pos;
            while (pos < length && html[pos] != '=' && html[pos] != '>' && html[pos] != '/' && !char.IsWhiteSpace(html[pos]))
            {
                pos++;
            }

            string attrName = html[attrNameStart..pos].ToLowerInvariant();
            if (attrName.Length == 0)
            {
                break;
            }

            // Skip whitespace around =
            while (pos < length && char.IsWhiteSpace(html[pos]))
            {
                pos++;
            }

            if (pos >= length || html[pos] != '=')
            {
                // Boolean attribute (e.g., disabled, readonly)
                element.Attributes[attrName] = string.Empty;
                continue;
            }

            pos++; // skip =

            // Skip whitespace after =
            while (pos < length && char.IsWhiteSpace(html[pos]))
            {
                pos++;
            }

            // Read attribute value
            string attrValue;
            if (pos < length && html[pos] is '"' or '\'')
            {
                // Quoted value
                char quote = html[pos];
                pos++;
                int valueStart = pos;
                while (pos < length && html[pos] != quote)
                {
                    pos++;
                }

                attrValue = html[valueStart..pos];
                if (pos < length)
                {
                    pos++; // skip closing quote
                }
            }
            else
            {
                // Unquoted value
                int valueStart = pos;
                while (pos < length && html[pos] != '>' && html[pos] != '/' && !char.IsWhiteSpace(html[pos]))
                {
                    pos++;
                }

                attrValue = html[valueStart..pos];
            }

            element.Attributes[attrName] = DecodeEntities(attrValue);
        }

        return pos;
    }

    /// <summary>
    /// Handles raw text elements (style, script) by reading content verbatim until the closing tag.
    /// </summary>
    private static int HandleRawTextElement(string html, int pos, HtmlNode element, string tag)
    {
        string closeTag = $"</{tag}>";
        int end = html.IndexOf(closeTag, pos, StringComparison.OrdinalIgnoreCase);
        if (end < 0)
        {
            end = html.Length;
        }

        string content = html[pos..end];
        if (content.Length > 0)
        {
            element.AppendChild(HtmlNode.CreateText(content));
        }

        return end < html.Length ? end + closeTag.Length : end;
    }

    /// <summary>Handles text content between tags.</summary>
    private static int HandleText(string html, int pos, Stack<HtmlNode> stack)
    {
        int start = pos;
        while (pos < html.Length && html[pos] != '<')
        {
            pos++;
        }

        string raw = html[start..pos];

        // Check if we're inside a <pre> element (preserve whitespace)
        // Preserve source whitespace in the lightweight DOM. The computed CSS
        // white-space property is not known during tokenization, so collapsing here
        // would irreversibly discard spaces for CSS white-space: pre/pre-wrap.
        string text = DecodeEntities(raw);

        if (text.Length > 0)
        {
            stack.Peek().AppendChild(HtmlNode.CreateText(text));
        }

        return pos;
    }

    /// <summary>
    /// Decodes HTML entities in a string.
    /// Supports named entities (&amp;amp;, &amp;lt;, &amp;gt;, &amp;quot;, &amp;apos;, &amp;nbsp;),
    /// decimal numeric (&amp;#NNN;), and hex numeric (&amp;#xHH;) references.
    /// </summary>
    private static string DecodeEntities(string text)
    {
        int ampIdx = text.IndexOf('&');
        if (ampIdx < 0)
        {
            return text; // Fast path: no entities
        }

        var sb = new StringBuilder(text.Length);
        int pos = 0;

        while (pos < text.Length)
        {
            if (text[pos] != '&')
            {
                sb.Append(text[pos]);
                pos++;
                continue;
            }

            int semiIdx = text.IndexOf(';', pos + 1);
            if (semiIdx < 0 || semiIdx - pos > 10)
            {
                // No semicolon nearby -- treat & as literal
                sb.Append('&');
                pos++;
                continue;
            }

            string entity = text[(pos + 1)..semiIdx];
            string? decoded = DecodeEntity(entity);

            if (decoded is not null)
            {
                sb.Append(decoded);
                pos = semiIdx + 1;
            }
            else
            {
                // Unrecognized entity -- keep as literal
                sb.Append('&');
                pos++;
            }
        }

        return sb.ToString();
    }

    /// <summary>HTML 4 named character references (case-sensitive, as in HTML).</summary>
    private static readonly Dictionary<string, string> NamedEntities = new(StringComparer.Ordinal)
    {
        ["AElig"] = "\u00C6",
        ["Aacute"] = "\u00C1",
        ["Acirc"] = "\u00C2",
        ["Agrave"] = "\u00C0",
        ["Alpha"] = "\u0391",
        ["Aring"] = "\u00C5",
        ["Atilde"] = "\u00C3",
        ["Auml"] = "\u00C4",
        ["Beta"] = "\u0392",
        ["Ccedil"] = "\u00C7",
        ["Chi"] = "\u03A7",
        ["Dagger"] = "\u2021",
        ["Delta"] = "\u0394",
        ["ETH"] = "\u00D0",
        ["Eacute"] = "\u00C9",
        ["Ecirc"] = "\u00CA",
        ["Egrave"] = "\u00C8",
        ["Epsilon"] = "\u0395",
        ["Eta"] = "\u0397",
        ["Euml"] = "\u00CB",
        ["Gamma"] = "\u0393",
        ["Iacute"] = "\u00CD",
        ["Icirc"] = "\u00CE",
        ["Igrave"] = "\u00CC",
        ["Iota"] = "\u0399",
        ["Iuml"] = "\u00CF",
        ["Kappa"] = "\u039A",
        ["Lambda"] = "\u039B",
        ["Mu"] = "\u039C",
        ["Ntilde"] = "\u00D1",
        ["Nu"] = "\u039D",
        ["OElig"] = "\u0152",
        ["Oacute"] = "\u00D3",
        ["Ocirc"] = "\u00D4",
        ["Ograve"] = "\u00D2",
        ["Omega"] = "\u03A9",
        ["Omicron"] = "\u039F",
        ["Oslash"] = "\u00D8",
        ["Otilde"] = "\u00D5",
        ["Ouml"] = "\u00D6",
        ["Phi"] = "\u03A6",
        ["Pi"] = "\u03A0",
        ["Prime"] = "\u2033",
        ["Psi"] = "\u03A8",
        ["Rho"] = "\u03A1",
        ["Scaron"] = "\u0160",
        ["Sigma"] = "\u03A3",
        ["THORN"] = "\u00DE",
        ["Tau"] = "\u03A4",
        ["Theta"] = "\u0398",
        ["Uacute"] = "\u00DA",
        ["Ucirc"] = "\u00DB",
        ["Ugrave"] = "\u00D9",
        ["Upsilon"] = "\u03A5",
        ["Uuml"] = "\u00DC",
        ["Xi"] = "\u039E",
        ["Yacute"] = "\u00DD",
        ["Yuml"] = "\u0178",
        ["Zeta"] = "\u0396",
        ["aacute"] = "\u00E1",
        ["acirc"] = "\u00E2",
        ["acute"] = "\u00B4",
        ["aelig"] = "\u00E6",
        ["agrave"] = "\u00E0",
        ["alefsym"] = "\u2135",
        ["alpha"] = "\u03B1",
        ["amp"] = "\u0026",
        ["and"] = "\u2227",
        ["ang"] = "\u2220",
        ["aring"] = "\u00E5",
        ["asymp"] = "\u2248",
        ["atilde"] = "\u00E3",
        ["auml"] = "\u00E4",
        ["bdquo"] = "\u201E",
        ["beta"] = "\u03B2",
        ["brvbar"] = "\u00A6",
        ["bull"] = "\u2022",
        ["cap"] = "\u2229",
        ["ccedil"] = "\u00E7",
        ["cedil"] = "\u00B8",
        ["cent"] = "\u00A2",
        ["chi"] = "\u03C7",
        ["circ"] = "\u02C6",
        ["clubs"] = "\u2663",
        ["cong"] = "\u2245",
        ["copy"] = "\u00A9",
        ["crarr"] = "\u21B5",
        ["cup"] = "\u222A",
        ["curren"] = "\u00A4",
        ["dArr"] = "\u21D3",
        ["dagger"] = "\u2020",
        ["darr"] = "\u2193",
        ["deg"] = "\u00B0",
        ["delta"] = "\u03B4",
        ["diams"] = "\u2666",
        ["divide"] = "\u00F7",
        ["eacute"] = "\u00E9",
        ["ecirc"] = "\u00EA",
        ["egrave"] = "\u00E8",
        ["empty"] = "\u2205",
        ["emsp"] = "\u2003",
        ["ensp"] = "\u2002",
        ["epsilon"] = "\u03B5",
        ["equiv"] = "\u2261",
        ["eta"] = "\u03B7",
        ["eth"] = "\u00F0",
        ["euml"] = "\u00EB",
        ["euro"] = "\u20AC",
        ["exist"] = "\u2203",
        ["fnof"] = "\u0192",
        ["forall"] = "\u2200",
        ["frac12"] = "\u00BD",
        ["frac14"] = "\u00BC",
        ["frac34"] = "\u00BE",
        ["frasl"] = "\u2044",
        ["gamma"] = "\u03B3",
        ["ge"] = "\u2265",
        ["gt"] = "\u003E",
        ["hArr"] = "\u21D4",
        ["harr"] = "\u2194",
        ["hearts"] = "\u2665",
        ["hellip"] = "\u2026",
        ["iacute"] = "\u00ED",
        ["icirc"] = "\u00EE",
        ["iexcl"] = "\u00A1",
        ["igrave"] = "\u00EC",
        ["image"] = "\u2111",
        ["infin"] = "\u221E",
        ["int"] = "\u222B",
        ["iota"] = "\u03B9",
        ["iquest"] = "\u00BF",
        ["isin"] = "\u2208",
        ["iuml"] = "\u00EF",
        ["kappa"] = "\u03BA",
        ["lArr"] = "\u21D0",
        ["lambda"] = "\u03BB",
        ["lang"] = "\u2329",
        ["laquo"] = "\u00AB",
        ["larr"] = "\u2190",
        ["lceil"] = "\u2308",
        ["ldquo"] = "\u201C",
        ["le"] = "\u2264",
        ["lfloor"] = "\u230A",
        ["lowast"] = "\u2217",
        ["loz"] = "\u25CA",
        ["lrm"] = "\u200E",
        ["lsaquo"] = "\u2039",
        ["lsquo"] = "\u2018",
        ["lt"] = "\u003C",
        ["macr"] = "\u00AF",
        ["mdash"] = "\u2014",
        ["micro"] = "\u00B5",
        ["middot"] = "\u00B7",
        ["minus"] = "\u2212",
        ["mu"] = "\u03BC",
        ["nabla"] = "\u2207",
        ["nbsp"] = "\u00A0",
        ["ndash"] = "\u2013",
        ["ne"] = "\u2260",
        ["ni"] = "\u220B",
        ["not"] = "\u00AC",
        ["notin"] = "\u2209",
        ["nsub"] = "\u2284",
        ["ntilde"] = "\u00F1",
        ["nu"] = "\u03BD",
        ["oacute"] = "\u00F3",
        ["ocirc"] = "\u00F4",
        ["oelig"] = "\u0153",
        ["ograve"] = "\u00F2",
        ["oline"] = "\u203E",
        ["omega"] = "\u03C9",
        ["omicron"] = "\u03BF",
        ["oplus"] = "\u2295",
        ["or"] = "\u2228",
        ["ordf"] = "\u00AA",
        ["ordm"] = "\u00BA",
        ["oslash"] = "\u00F8",
        ["otilde"] = "\u00F5",
        ["otimes"] = "\u2297",
        ["ouml"] = "\u00F6",
        ["para"] = "\u00B6",
        ["part"] = "\u2202",
        ["permil"] = "\u2030",
        ["perp"] = "\u22A5",
        ["phi"] = "\u03C6",
        ["pi"] = "\u03C0",
        ["piv"] = "\u03D6",
        ["plusmn"] = "\u00B1",
        ["pound"] = "\u00A3",
        ["prime"] = "\u2032",
        ["prod"] = "\u220F",
        ["prop"] = "\u221D",
        ["psi"] = "\u03C8",
        ["quot"] = "\u0022",
        ["rArr"] = "\u21D2",
        ["radic"] = "\u221A",
        ["rang"] = "\u232A",
        ["raquo"] = "\u00BB",
        ["rarr"] = "\u2192",
        ["rceil"] = "\u2309",
        ["rdquo"] = "\u201D",
        ["real"] = "\u211C",
        ["reg"] = "\u00AE",
        ["rfloor"] = "\u230B",
        ["rho"] = "\u03C1",
        ["rlm"] = "\u200F",
        ["rsaquo"] = "\u203A",
        ["rsquo"] = "\u2019",
        ["sbquo"] = "\u201A",
        ["scaron"] = "\u0161",
        ["sdot"] = "\u22C5",
        ["sect"] = "\u00A7",
        ["shy"] = "\u00AD",
        ["sigma"] = "\u03C3",
        ["sigmaf"] = "\u03C2",
        ["sim"] = "\u223C",
        ["spades"] = "\u2660",
        ["sub"] = "\u2282",
        ["sube"] = "\u2286",
        ["sum"] = "\u2211",
        ["sup"] = "\u2283",
        ["sup1"] = "\u00B9",
        ["sup2"] = "\u00B2",
        ["sup3"] = "\u00B3",
        ["supe"] = "\u2287",
        ["szlig"] = "\u00DF",
        ["tau"] = "\u03C4",
        ["there4"] = "\u2234",
        ["theta"] = "\u03B8",
        ["thetasym"] = "\u03D1",
        ["thinsp"] = "\u2009",
        ["thorn"] = "\u00FE",
        ["tilde"] = "\u02DC",
        ["times"] = "\u00D7",
        ["trade"] = "\u2122",
        ["uArr"] = "\u21D1",
        ["uacute"] = "\u00FA",
        ["uarr"] = "\u2191",
        ["ucirc"] = "\u00FB",
        ["ugrave"] = "\u00F9",
        ["uml"] = "\u00A8",
        ["upsih"] = "\u03D2",
        ["upsilon"] = "\u03C5",
        ["uuml"] = "\u00FC",
        ["weierp"] = "\u2118",
        ["xi"] = "\u03BE",
        ["yacute"] = "\u00FD",
        ["yen"] = "\u00A5",
        ["yuml"] = "\u00FF",
        ["zeta"] = "\u03B6",
        ["zwj"] = "\u200D",
        ["zwnj"] = "\u200C",
        ["apos"] = "'",
    };

    /// <summary>Decodes a single HTML entity (without the leading &amp; and trailing ;).</summary>
    private static string? DecodeEntity(string entity)
    {
        if (NamedEntities.TryGetValue(entity, out string? named))
        {
            return named;
        }

        // Tolerate upper-case variants of the most common ones (&AMP;, &NBSP;).
        if (NamedEntities.TryGetValue(entity.ToLowerInvariant(), out string? lower) && entity.ToLowerInvariant() is "amp" or "lt" or "gt" or "quot" or "nbsp")
        {
            return lower;
        }

        // Numeric entities: &#NNN; or &#xHH;
        if (entity.Length > 1 && entity[0] == '#')
        {
            bool hex = entity[1] is 'x' or 'X';
            bool parsed = hex
                ? int.TryParse(entity.AsSpan(2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out int value)
                : int.TryParse(entity.AsSpan(1), NumberStyles.Integer, CultureInfo.InvariantCulture, out value);
            if (parsed && value is > 0 and <= 0x10FFFF and not (>= 0xD800 and <= 0xDFFF))
            {
                return char.ConvertFromUtf32(value);
            }

            // Invalid code points become U+FFFD like browsers.
            return parsed ? "\uFFFD" : null;
        }

        return null;
    }
}

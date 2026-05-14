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
        bool inPre = IsInsidePre(stack);
        string text = inPre ? DecodeEntities(raw) : NormalizeWhitespace(DecodeEntities(raw));

        if (text.Length > 0)
        {
            stack.Peek().AppendChild(HtmlNode.CreateText(text));
        }

        return pos;
    }

    /// <summary>Checks whether the current stack position is inside a pre element.</summary>
    private static bool IsInsidePre(Stack<HtmlNode> stack)
    {
        foreach (HtmlNode node in stack)
        {
            if (node.Tag == "pre")
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Normalizes whitespace in text content: collapses runs of whitespace to a single space.
    /// Does NOT trim leading/trailing spaces — inline spacing between elements depends on
    /// preserving boundary whitespace (e.g., "before " + "bold" + " after" must keep spaces).
    /// The layout engine handles ignoring leading space at line starts.
    /// </summary>
    private static string NormalizeWhitespace(string text)
    {
        var sb = new StringBuilder(text.Length);
        bool lastWasSpace = false;

        for (int i = 0; i < text.Length; i++)
        {
            if (char.IsWhiteSpace(text[i]))
            {
                if (!lastWasSpace)
                {
                    sb.Append(' ');
                    lastWasSpace = true;
                }
            }
            else
            {
                sb.Append(text[i]);
                lastWasSpace = false;
            }
        }

        return sb.ToString();
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
            char? decoded = DecodeEntity(entity);

            if (decoded.HasValue)
            {
                sb.Append(decoded.Value);
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

    /// <summary>Decodes a single HTML entity (without the leading &amp; and trailing ;).</summary>
    private static char? DecodeEntity(string entity)
    {
        // Named entities
        char? named = entity.ToLowerInvariant() switch
        {
            "amp" => '&',
            "lt" => '<',
            "gt" => '>',
            "quot" => '"',
            "apos" => '\'',
            "nbsp" => '\u00A0',
            _ => null,
        };

        if (named.HasValue)
        {
            return named;
        }

        // Numeric entities: &#NNN; or &#xHH;
        if (entity.Length > 1 && entity[0] == '#')
        {
            if (entity[1] is 'x' or 'X')
            {
                // Hex: &#xHH;
                if (int.TryParse(entity.AsSpan(2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out int hexVal) && hexVal is > 0 and <= 0xFFFF)
                {
                    return (char)hexVal;
                }
            }
            else
            {
                // Decimal: &#NNN;
                if (int.TryParse(entity.AsSpan(1), NumberStyles.Integer, CultureInfo.InvariantCulture, out int decVal) && decVal is > 0 and <= 0xFFFF)
                {
                    return (char)decVal;
                }
            }
        }

        return null;
    }
}

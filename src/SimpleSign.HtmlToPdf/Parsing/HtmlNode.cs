namespace SimpleSign.HtmlToPdf.Parsing;

/// <summary>Type of HTML node.</summary>
public enum HtmlNodeType
{
    /// <summary>An HTML element node (div, p, table, etc.).</summary>
    Element,

    /// <summary>A text content node.</summary>
    Text,
}

/// <summary>
/// Lightweight HTML DOM node. Represents either an element (div, p, table...) or a text node.
/// This is not a full DOM -- just enough structure for layout and rendering.
/// </summary>
public sealed class HtmlNode
{
    /// <summary>Gets the type of this node.</summary>
    public HtmlNodeType NodeType { get; init; }

    /// <summary>Tag name in lowercase (e.g., "div", "p", "table"). Null for text nodes.</summary>
    public string? Tag { get; init; }

    /// <summary>Text content. Only set for text nodes.</summary>
    public string? Text { get; init; }

    /// <summary>HTML attributes (lowercase keys). Empty for text nodes.</summary>
    public Dictionary<string, string> Attributes { get; init; } = [];

    /// <summary>Child nodes.</summary>
    public List<HtmlNode> Children { get; } = [];

    /// <summary>Parent node. Null for the root node.</summary>
    public HtmlNode? Parent { get; internal set; }

    /// <summary>Inline style attribute parsed into individual properties. Populated by StyleResolver.</summary>
    public Dictionary<string, string> InlineStyle { get; set; } = [];

    /// <summary>Computed style after cascade resolution. Populated by StyleResolver.</summary>
    public ComputedStyle? ComputedStyle { get; set; }

    /// <summary>Gets a value indicating whether this is a block-level element.</summary>
    public bool IsBlock => Tag is "div" or "p" or "h1" or "h2" or "h3" or "h4" or "h5" or "h6"
        or "blockquote" or "pre" or "ul" or "ol" or "li" or "table" or "thead" or "tbody"
        or "tr" or "hr" or "header" or "footer" or "section" or "article" or "main" or "body" or "html";

    /// <summary>Gets a value indicating whether this is a void/self-closing element.</summary>
    public bool IsVoid => Tag is "br" or "hr" or "img" or "input" or "meta" or "link";

    /// <summary>Gets a value indicating whether this is a table-related element.</summary>
    public bool IsTableElement => Tag is "table" or "thead" or "tbody" or "tfoot" or "tr" or "th" or "td";

    /// <summary>Creates a new element node with the given tag.</summary>
    /// <param name="tag">The HTML tag name (will be lowercased).</param>
    /// <param name="parent">Optional parent node.</param>
    /// <returns>A new element node.</returns>
    public static HtmlNode CreateElement(string tag, HtmlNode? parent = null) => new()
    {
        NodeType = HtmlNodeType.Element,
        Tag = tag.ToLowerInvariant(),
        Parent = parent,
    };

    /// <summary>Creates a new text node with the given content.</summary>
    /// <param name="text">The text content.</param>
    /// <param name="parent">Optional parent node.</param>
    /// <returns>A new text node.</returns>
    public static HtmlNode CreateText(string text, HtmlNode? parent = null) => new()
    {
        NodeType = HtmlNodeType.Text,
        Text = text,
        Parent = parent,
    };

    /// <summary>Gets attribute value or null.</summary>
    /// <param name="name">The attribute name (case-insensitive).</param>
    /// <returns>The attribute value, or null if not found.</returns>
    public string? GetAttribute(string name) =>
        Attributes.TryGetValue(name.ToLowerInvariant(), out string? val) ? val : null;

    /// <summary>Adds a child node and sets its parent.</summary>
    /// <param name="child">The child node to add.</param>
    public void AppendChild(HtmlNode child)
    {
        child.Parent = this;
        Children.Add(child);
    }

    /// <summary>Gets all descendant elements matching a tag name.</summary>
    /// <param name="tag">The tag name to search for (lowercase).</param>
    /// <returns>An enumerable of matching descendant nodes.</returns>
    public IEnumerable<HtmlNode> Descendants(string tag)
    {
        foreach (HtmlNode child in Children)
        {
            if (child.Tag == tag)
            {
                yield return child;
            }

            if (child.NodeType == HtmlNodeType.Element)
            {
                foreach (HtmlNode desc in child.Descendants(tag))
                {
                    yield return desc;
                }
            }
        }
    }

    /// <inheritdoc/>
    public override string ToString() => NodeType == HtmlNodeType.Text
        ? $"Text: \"{Text?[..Math.Min(Text.Length, 30)]}\""
        : $"<{Tag}> ({Children.Count} children)";
}

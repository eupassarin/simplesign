namespace SimpleSign.HtmlToPdf.Parsing;

/// <summary>
/// A CSS rule: selector + dictionary of property/value pairs.
/// </summary>
public sealed class CssRule
{
    /// <summary>Raw selector string (e.g., "h1", ".title", "#main", "table td").</summary>
    public required string Selector { get; init; }

    /// <summary>CSS property/value pairs (lowercase keys).</summary>
    public required Dictionary<string, string> Properties { get; init; }

    /// <summary>Specificity of this selector (higher = more specific).</summary>
    public int Specificity { get; init; }

    /// <summary>Gets the declarations marked <c>!important</c> (lowercase keys).</summary>
    public Dictionary<string, string> ImportantProperties { get; init; } = new(StringComparer.Ordinal);

    /// <summary>Gets the source order of the rule within the parsed stylesheet(s).</summary>
    internal int Order { get; set; }

    /// <summary>Gets the parsed selector, or null when it is an at-rule or unsupported.</summary>
    internal CssSelector? ParsedSelector { get; init; }
}

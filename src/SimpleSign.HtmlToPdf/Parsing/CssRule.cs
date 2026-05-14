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
}

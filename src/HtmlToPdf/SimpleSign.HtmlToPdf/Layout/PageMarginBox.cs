using System.Text;
using SimpleSign.HtmlToPdf.Parsing;

namespace SimpleSign.HtmlToPdf.Layout;

/// <summary>
/// A CSS page-margin box (<c>@page { @bottom-center { content: counter(page) } }</c>).
/// Content is kept unevaluated because page counters are only known while rendering.
/// </summary>
/// <param name="Position">The margin box name, e.g. <c>top-center</c>.</param>
/// <param name="PageSelector">The page pseudo-class (<c>:first</c>, <c>:left</c>, <c>:right</c>) or empty.</param>
/// <param name="Content">The raw <c>content</c> value.</param>
/// <param name="Style">Text style for the box.</param>
/// <param name="Order">Source order (later wins).</param>
internal sealed record PageMarginBox(string Position, string PageSelector, string Content, ComputedStyle Style, int Order)
{
    /// <summary>Gets the supported margin box positions.</summary>
    public static readonly string[] Positions =
    [
        "top-left-corner", "top-left", "top-center", "top-right", "top-right-corner",
        "bottom-left-corner", "bottom-left", "bottom-center", "bottom-right", "bottom-right-corner",
    ];

    /// <summary>Returns true when the box applies to the given 1-based page.</summary>
    public bool Matches(int pageNumber) => PageSelector switch
    {
        "" => true,
        ":first" => pageNumber == 1,
        ":left" => pageNumber % 2 == 0,
        ":right" => pageNumber % 2 == 1,
        _ => false,
    };

    /// <summary>Gets the selector specificity: :first beats :left/:right, which beat a bare @page.</summary>
    public int Specificity => PageSelector switch
    {
        ":first" => 2,
        "" => 0,
        _ => 1,
    };

    /// <summary>Picks, per position, the winning box for a page.</summary>
    public static List<PageMarginBox> ForPage(IReadOnlyList<PageMarginBox> boxes, int pageNumber) =>
        [.. boxes.Where(b => b.Matches(pageNumber))
            .GroupBy(b => b.Position, StringComparer.Ordinal)
            .Select(g => g.OrderBy(b => b.Specificity).ThenBy(b => b.Order).Last())];

    /// <summary>Evaluates the content for a page; returns null for <c>none</c>.</summary>
    public string? Evaluate(int pageNumber, int totalPages)
    {
        string value = Content.Trim();
        if (value is "none" or "normal" || value.Length == 0)
        {
            return null;
        }

        var sb = new StringBuilder();
        foreach (string token in CssParser.SplitValueTokens(value))
        {
            string lower = token.ToLowerInvariant();
            if (token.Length >= 2 && token[0] is '"' or '\'' && token[^1] == token[0])
            {
                sb.Append(StyleResolver.EvaluateContent(token, new HtmlNode()) ?? string.Empty);
            }
            else if (lower.StartsWith("counter(", StringComparison.Ordinal) && token.EndsWith(')'))
            {
                List<string> args = CssParser.SplitTopLevel(token[8..^1], ',');
                if (args.Count == 0)
                {
                    continue;
                }

                string name = args[0].Trim().ToLowerInvariant();
                string style = args.Count > 1 ? args[1].Trim() : "decimal";
                int number = name switch
                {
                    "page" => pageNumber,
                    "pages" => totalPages,
                    _ => 0,
                };
                sb.Append(ListMarkers.FormatCounter(number, style));
            }
        }

        return sb.ToString();
    }
}

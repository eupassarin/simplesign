using System.Globalization;
using SimpleSign.HtmlToPdf.Layout;

namespace SimpleSign.HtmlToPdf.Parsing;

/// <summary>
/// CSS counters (<c>counter-reset</c>, <c>counter-set</c>, <c>counter-increment</c>) evaluated in
/// document order while styles are resolved. A counter instance created by an element is visible to
/// the element, its descendants and its following siblings.
/// </summary>
internal sealed class CssCounters
{
    private const int MaxNesting = 256;

    private readonly Dictionary<string, List<Instance>> _counters = new(StringComparer.Ordinal);

    private sealed class Instance(HtmlNode? scope, int value)
    {
        /// <summary>Gets the parent whose children are in scope (the creating element's parent).</summary>
        public HtmlNode? Scope { get; } = scope;

        public int Value { get; set; } = value;
    }

    /// <summary>Applies an element's counter properties, in the order reset, set, increment.</summary>
    public void Apply(HtmlNode element, ComputedStyle style)
    {
        // Implicit list-item counter (CSS Lists 3): lists reset it and items increment it.
        if (element.Tag is "ol" or "ul" or "menu")
        {
            int start = int.TryParse(element.GetAttribute("start"), NumberStyles.Integer, CultureInfo.InvariantCulture, out int s) ? s - 1 : 0;
            Reset("list-item", start, element);
        }

        foreach (var (name, value) in ParsePairs(style.CounterReset, 0))
        {
            Reset(name, value, element);
        }

        foreach (var (name, value) in ParsePairs(style.CounterSet, 0))
        {
            if (Top(name) is { } top)
            {
                top.Value = value;
            }
            else
            {
                Instantiate(name, value);
            }
        }

        if (style.Display == DisplayType.ListItem && !(style.CounterIncrement?.Contains("list-item", StringComparison.Ordinal) ?? false))
        {
            Increment("list-item", 1);
        }

        foreach (var (name, value) in ParsePairs(style.CounterIncrement, 1))
        {
            Increment(name, value);
        }
    }

    /// <summary>Ends the scope of counters created by the children of <paramref name="parent"/>.</summary>
    public void LeaveChildrenOf(HtmlNode parent)
    {
        foreach (List<Instance> stack in _counters.Values)
        {
            while (stack.Count > 0 && ReferenceEquals(stack[^1].Scope, parent))
            {
                stack.RemoveAt(stack.Count - 1);
            }
        }
    }

    /// <summary>Formats <c>counter(name, style)</c>.</summary>
    public string Counter(string name, string style) => ListMarkers.FormatCounter(Top(name)?.Value ?? 0, style);

    /// <summary>Formats <c>counters(name, separator, style)</c>.</summary>
    public string Counters(string name, string separator, string style) =>
        _counters.TryGetValue(name, out List<Instance>? stack) && stack.Count > 0
            ? string.Join(separator, stack.Select(i => ListMarkers.FormatCounter(i.Value, style)))
            : ListMarkers.FormatCounter(0, style);

    private Instance? Top(string name) =>
        _counters.TryGetValue(name, out List<Instance>? stack) && stack.Count > 0 ? stack[^1] : null;

    private void Reset(string name, int value, HtmlNode element)
    {
        if (!_counters.TryGetValue(name, out List<Instance>? stack))
        {
            stack = [];
            _counters[name] = stack;
        }

        // A sibling's reset replaces the instance instead of nesting a new one.
        if (stack.Count > 0 && ReferenceEquals(stack[^1].Scope, element.Parent))
        {
            stack[^1].Value = value;
            return;
        }

        if (stack.Count < MaxNesting)
        {
            stack.Add(new Instance(element.Parent, value));
        }
    }

    private void Instantiate(string name, int value) => _counters[name] = [new Instance(null, value)];

    private void Increment(string name, int by)
    {
        if (Top(name) is null)
        {
            // Like browsers, a counter used without a reset lives at the document level.
            Instantiate(name, 0);
        }

        if (Top(name) is { } top)
        {
            top.Value = unchecked(top.Value + by);
        }
    }

    /// <summary>Parses <c>name [integer]</c> pairs; <c>none</c> yields nothing.</summary>
    internal static List<(string Name, int Value)> ParsePairs(string? value, int defaultValue)
    {
        var pairs = new List<(string, int)>();
        if (string.IsNullOrWhiteSpace(value))
        {
            return pairs;
        }

        string[] tokens = value.Split([' ', '\t', '\n', '\r'], StringSplitOptions.RemoveEmptyEntries);
        for (int i = 0; i < tokens.Length; i++)
        {
            string name = tokens[i];
            if (name is "none" or "inherit" or "initial" or "unset" || int.TryParse(name, out _))
            {
                continue;
            }

            int amount = defaultValue;
            if (i + 1 < tokens.Length && int.TryParse(tokens[i + 1], NumberStyles.Integer, CultureInfo.InvariantCulture, out int parsed))
            {
                amount = parsed;
                i++;
            }

            pairs.Add((name, amount));
        }

        return pairs;
    }
}

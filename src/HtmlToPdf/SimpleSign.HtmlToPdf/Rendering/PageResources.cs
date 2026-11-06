using System.Text;

namespace SimpleSign.HtmlToPdf.Rendering;

/// <summary>
/// Collects the named resources a page's content stream refers to besides fonts:
/// graphics states (transparency, blend modes, soft masks), shadings and XObjects.
/// Identical definitions share one name.
/// </summary>
internal sealed class PageResources
{
    private readonly Dictionary<string, string> _extGStates = new(StringComparer.Ordinal);
    private readonly Dictionary<string, string> _shadings = new(StringComparer.Ordinal);
    private readonly Dictionary<string, int> _xObjects = new(StringComparer.Ordinal);

    // Reverse lookups for de-duplication.
    private readonly Dictionary<string, string> _extGStateNames = new(StringComparer.Ordinal);
    private readonly Dictionary<string, string> _shadingNames = new(StringComparer.Ordinal);

    public PageResources(PdfObjectWriter writer)
    {
        Writer = writer;
    }

    /// <summary>Gets the document writer, for resources that must be indirect objects (soft-mask groups).</summary>
    public PdfObjectWriter Writer { get; }

    /// <summary>Gets a value indicating whether the page uses transparency.</summary>
    public bool UsesTransparency { get; private set; }

    /// <summary>Registers a graphics state dictionary and returns its resource name.</summary>
    public string AddExtGState(string dictionary)
    {
        if (_extGStateNames.TryGetValue(dictionary, out string? existing))
        {
            return existing;
        }

        string name = $"GS{_extGStates.Count + 1}";
        _extGStates[name] = dictionary;
        _extGStateNames[dictionary] = name;
        UsesTransparency = true;
        return name;
    }

    /// <summary>Registers a shading dictionary and returns its resource name.</summary>
    public string AddShading(string dictionary)
    {
        if (_shadingNames.TryGetValue(dictionary, out string? existing))
        {
            return existing;
        }

        string name = $"Sh{_shadings.Count + 1}";
        _shadings[name] = dictionary;
        _shadingNames[dictionary] = name;
        return name;
    }

    /// <summary>Registers an XObject reference.</summary>
    public void AddXObject(string name, int objectNumber) => _xObjects[name] = objectNumber;

    /// <summary>Builds the entries for the page resource dictionary.</summary>
    public string BuildEntries()
    {
        var sb = new StringBuilder();
        Append(sb, "XObject", _xObjects.Select(x => (x.Key, $"{x.Value} 0 R")));
        Append(sb, "ExtGState", _extGStates.Select(x => (x.Key, x.Value)));
        Append(sb, "Shading", _shadings.Select(x => (x.Key, x.Value)));
        return sb.ToString();
    }

    private static void Append(StringBuilder sb, string category, IEnumerable<(string Name, string Value)> entries)
    {
        bool any = false;
        foreach (var (name, value) in entries)
        {
            if (!any)
            {
                sb.Append(" /").Append(category).Append(" <<");
                any = true;
            }

            sb.Append(" /").Append(name).Append(' ').Append(value);
        }

        if (any)
        {
            sb.Append(" >>");
        }
    }
}

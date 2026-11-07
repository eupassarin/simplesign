using System.Text;

namespace SimpleSign.Playbook.Runs;

/// <summary>An unknown variable, or one that refers to itself.</summary>
public sealed class VariableException(string message) : Exception(message);

/// <summary>
/// The values a step can use as <c>${name}</c>: <c>asset.ID</c>, <c>asset.ID.password</c>,
/// <c>var.NAME</c>, <c>env.NAME</c>, <c>out</c> (the step's folder), <c>run</c> (the run's folder),
/// <c>workspace</c>, <c>sandbox.*</c>, and what Sandbox actions set (<c>cert.path</c>, <c>cert.password</c>).
/// <c>$${</c> writes a literal <c>${</c>.
/// </summary>
public sealed class Variables
{
    private readonly Dictionary<string, string> _values = new(StringComparer.Ordinal);
    private readonly Dictionary<string, string> _playbook;
    private readonly Func<string, string?> _environment;

    /// <param name="playbook">The playbook's own variables (<c>var.NAME</c>), which may use other variables.</param>
    /// <param name="environment">Reads <c>env.NAME</c>; the process environment when null.</param>
    public Variables(IReadOnlyDictionary<string, string>? playbook = null, Func<string, string?>? environment = null)
    {
        _playbook = playbook is null ? [] : new Dictionary<string, string>(playbook, StringComparer.Ordinal);
        _environment = environment ?? Environment.GetEnvironmentVariable;
    }

    /// <summary>Sets <c>${name}</c>.</summary>
    public void Set(string name, string value) => _values[name] = value;

    /// <summary>A copy, for one step (what the step sets does not leak into the next).</summary>
    public Variables Fork()
    {
        var copy = new Variables(_playbook, _environment);
        foreach (var (key, value) in _values)
        {
            copy._values[key] = value;
        }

        return copy;
    }

    /// <summary>The names set so far, for error messages and the UI.</summary>
    public IReadOnlyCollection<string> Names => _values.Keys;

    /// <summary>Replaces every <c>${name}</c> in <paramref name="text"/>.</summary>
    /// <exception cref="VariableException">A name is unknown, unterminated, or refers to itself.</exception>
    public string Resolve(string text) => Resolve(text, depth: 0);

    private string Resolve(string text, int depth)
    {
        ArgumentNullException.ThrowIfNull(text);
        if (depth > 8)
        {
            throw new VariableException($"Variables nest too deep (a variable refers to itself?) in '{text}'.");
        }

        if (!text.Contains("${", StringComparison.Ordinal))
        {
            return text;
        }

        var result = new StringBuilder(text.Length);
        int i = 0;
        while (i < text.Length)
        {
            if (text[i] == '$' && i + 2 < text.Length && text[i + 1] == '$' && text[i + 2] == '{')
            {
                result.Append("${");
                i += 3;
                continue;
            }

            if (text[i] == '$' && i + 1 < text.Length && text[i + 1] == '{')
            {
                int end = text.IndexOf('}', i + 2);
                if (end < 0)
                {
                    throw new VariableException($"Unterminated variable in '{text}'.");
                }

                string name = text[(i + 2)..end].Trim();
                result.Append(Lookup(name, depth));
                i = end + 1;
                continue;
            }

            result.Append(text[i]);
            i++;
        }

        return result.ToString();
    }

    private string Lookup(string name, int depth)
    {
        if (_values.TryGetValue(name, out string? value))
        {
            return value;
        }

        if (name.StartsWith("var.", StringComparison.Ordinal) && _playbook.TryGetValue(name[4..], out string? own))
        {
            return Resolve(own, depth + 1);
        }

        if (name.StartsWith("env.", StringComparison.Ordinal))
        {
            return _environment(name[4..]) ?? throw new VariableException($"The environment variable '{name[4..]}' is not set.");
        }

        throw new VariableException($"Unknown variable '${{{name}}}'.");
    }
}

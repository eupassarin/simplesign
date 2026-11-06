using System.Globalization;
using System.Reflection;
using SimpleSign.Agent.Localization;

namespace SimpleSign.Agent.Docs;

/// <summary>The documentation shipped inside the agent: one Markdown file per topic and language.</summary>
internal static class DocLibrary
{
    /// <summary>The topics, in reading order. Their titles are the "docs.topic.&lt;id&gt;" texts.</summary>
    public static IReadOnlyList<string> Topics { get; } = ["overview", "start", "integration", "security", "troubleshooting"];

    /// <summary>The Markdown of a topic in a language, with {port} replaced.</summary>
    public static string Load(string topic, string language, int port)
    {
        string name = $"Docs/{(language == L.Portuguese ? L.Portuguese : L.English)}/{topic}.md";
        using var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(name)
            ?? throw new FileNotFoundException(name);
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd().Replace("{port}", port.ToString(CultureInfo.InvariantCulture), StringComparison.Ordinal);
    }
}

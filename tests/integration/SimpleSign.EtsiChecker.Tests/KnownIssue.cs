using System.Text.Json;

namespace SimpleSign.EtsiChecker.Tests;

/// <summary>
/// A failure of the checker that is expected, with why: a sample made not to be baseline (<see cref="EtsiSample.IsBaseline"/>),
/// a fault of the checker (an issue on its tracker) or one of SimpleSign still to fix (an issue here). Listed in
/// <c>known-issues.json</c>.
/// </summary>
/// <param name="Sample">The sample it is about, or <c>*</c> for every sample.</param>
/// <param name="Check">The checker's test (<c>check</c> attribute).</param>
/// <param name="MessageContains">Text the checker's message has, to tell apart failures of the same test; empty for any.</param>
/// <param name="Reason">Why it is accepted.</param>
/// <param name="Link">The issue that tracks it, or the documentation that explains it.</param>
public sealed record KnownIssue(string Sample, string Check, string MessageContains, string Reason, string Link)
{
    /// <summary>Whether <paramref name="finding"/> of <paramref name="sample"/> is this issue.</summary>
    public bool Matches(string sample, EtsiFinding finding) =>
        (Sample == "*" || Sample == sample)
        && Check == finding.Check
        && finding.Message.Contains(MessageContains, StringComparison.Ordinal);

    /// <summary>Every known issue, from <c>known-issues.json</c> next to the test assembly.</summary>
    public static IReadOnlyList<KnownIssue> All { get; } = Load(Path.Combine(AppContext.BaseDirectory, "known-issues.json"));

    /// <summary>Reads a list of known issues: an array of objects with <c>sample</c>, <c>check</c>, <c>messageContains</c>, <c>reason</c>, <c>link</c>.</summary>
    public static IReadOnlyList<KnownIssue> Load(string path)
    {
        using var json = JsonDocument.Parse(File.ReadAllText(path));
        return [.. json.RootElement.EnumerateArray().Select(e => new KnownIssue(
            Text(e, "sample", required: true),
            Text(e, "check", required: true),
            Text(e, "messageContains", required: false),
            Text(e, "reason", required: true),
            Text(e, "link", required: true)))];
    }

    private static string Text(JsonElement element, string name, bool required) =>
        element.TryGetProperty(name, out var value) && value.GetString() is { } text
            ? text
            : required ? throw new InvalidDataException($"A known issue has no \"{name}\".") : "";
}

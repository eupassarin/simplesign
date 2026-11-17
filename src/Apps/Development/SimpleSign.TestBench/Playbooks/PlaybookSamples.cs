namespace SimpleSign.TestBench.Playbooks;

/// <summary>The playbooks bundled with the TestBench (<c>docs/playbooks/*.json</c>).</summary>
internal static class PlaybookSamples
{
    private const string Prefix = "SimpleSign.TestBench.Playbooks.Samples.";

    private static readonly Lazy<IReadOnlyList<Playbook>> s_all = new(Read);

    /// <summary>The samples, read once.</summary>
    public static IReadOnlyList<Playbook> All => s_all.Value;

    /// <summary>The JSON of a sample, or null.</summary>
    public static string? Json(string id)
    {
        using var stream = typeof(PlaybookSamples).Assembly.GetManifestResourceStream(Prefix + id + ".json");
        if (stream is null)
        {
            return null;
        }

        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }

    private static IReadOnlyList<Playbook> Read() =>
    [
        .. typeof(PlaybookSamples).Assembly.GetManifestResourceNames()
            .Where(n => n.StartsWith(Prefix, StringComparison.Ordinal) && n.EndsWith(".json", StringComparison.Ordinal))
            .Order(StringComparer.Ordinal)
            .Select(n => PlaybookValidator.Check(Json(n[Prefix.Length..^".json".Length])!, sandbox: null).Playbook)
            .OfType<Playbook>(),
    ];
}

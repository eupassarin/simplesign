namespace SimpleSign.TestBench.Scripts;

/// <summary>The certification scripts bundled with the TestBench (<c>docs/certification-scripts/*.json</c>).</summary>
internal static class ScriptSamples
{
    private const string Prefix = "SimpleSign.TestBench.Scripts.Samples.";

    private static readonly Lazy<IReadOnlyList<CertificationScript>> s_all = new(Read);

    /// <summary>The samples, read once.</summary>
    public static IReadOnlyList<CertificationScript> All => s_all.Value;

    /// <summary>The JSON of a sample, or null.</summary>
    public static string? Json(string id)
    {
        using var stream = typeof(ScriptSamples).Assembly.GetManifestResourceStream(Prefix + id + ".json");
        if (stream is null)
        {
            return null;
        }

        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }

    private static IReadOnlyList<CertificationScript> Read() =>
    [
        .. typeof(ScriptSamples).Assembly.GetManifestResourceNames()
            .Where(n => n.StartsWith(Prefix, StringComparison.Ordinal) && n.EndsWith(".json", StringComparison.Ordinal))
            .Order(StringComparer.Ordinal)
            .Select(n => ScriptValidator.Check(Json(n[Prefix.Length..^".json".Length])!, sandbox: null).Script)
            .OfType<CertificationScript>(),
    ];
}

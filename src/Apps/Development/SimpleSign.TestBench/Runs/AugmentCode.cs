using SimpleSign.TestBench.Signing;

namespace SimpleSign.TestBench.Runs;

/// <summary>
/// The library call and the CLI command of an augmentation, shown by the Augment tab's result and by a playbook step's
/// preview: the format's augmenter (<c>PadesAugmenter</c>, <c>CadesAugmenter</c>, <c>XadesAugmenter</c>) and
/// <c>simplesign augment</c>.
/// </summary>
internal static class AugmentCode
{
    /// <summary>The snippets for a file of the format, the level to reach (<c>BT</c>, <c>BLT</c>, <c>BLTA</c>) and whether a B-LTA is renewed.</summary>
    public static CodeSnippets For(string format, string fileName, string level, bool renew, bool detachedData)
    {
        string augmenter = format switch
        {
            RunFormats.Cades => "CadesAugmenter.Signature(File.ReadAllBytes(\"" + fileName + "\"), " + (detachedData ? "detachedData" : "null") + ")",
            RunFormats.Xades => "XadesAugmenter.Document(File.ReadAllBytes(\"" + fileName + "\"), " + (detachedData ? "detachedData" : "null") + ")",
            _ => "PadesAugmenter.Document(File.ReadAllBytes(\"" + fileName + "\"))",
        };
        string code = $"var result = await {augmenter}\n    .WithTimestamp(new TimestampOptions(new Uri(tsaUrl)))\n    .ToLevel(AdesBaselineLevel.{LevelName(level)})"
            + (renew ? "\n    .RenewArchive()" : "") + "\n    .AugmentAsync();\n// result.InitialLevel → result.Level: the level the signature had and the one reached";
        string cli = $"simplesign augment {fileName} --level {Normalize(level)} --tsa $TSA_URL" + (detachedData ? " --data data" : "") + (renew ? " --renew" : "");
        return new CodeSnippets(code, cli, ["The library's augmenter for the format, then a validation of the result."]);
    }

    /// <summary><c>BT</c>, <c>BLT</c> or <c>BLTA</c> (the default) from any spelling (<c>B-LT</c>, <c>blt</c>).</summary>
    public static string Normalize(string? level) => (level ?? "BLTA").ToUpperInvariant().Replace("-", "", StringComparison.Ordinal) switch
    {
        "BT" => "BT",
        "BLT" => "BLT",
        _ => "BLTA",
    };

    private static string LevelName(string level) => Normalize(level) switch
    {
        "BT" => "Timestamped",
        "BLT" => "LongTerm",
        _ => "Archive",
    };
}

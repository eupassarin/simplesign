using System.Security.Cryptography;
using System.Text.Json;
using Shouldly;
using SimpleSign.Integration.Tests.Helpers;
using Xunit;

namespace SimpleSign.Integration.Tests;

/// <summary>
/// The CAdES/XAdES corpus under <c>Fixtures/ades/</c> is the EU DSS files of the commit pinned in its
/// <c>manifest.json</c>, unchanged: every file there is listed with its SHA-256, and matches it.
/// </summary>
[Trait("Category", "Integration")]
public sealed class EtsiCorpusManifestTests
{
    private const string ManifestFile = "manifest.json";

    [Fact(DisplayName = "Every file of the CAdES/XAdES corpus matches the SHA-256 of its manifest")]
    public void Manifest_EveryCorpusFile_MatchesRecordedSha256()
    {
        var expected = ReadManifest();
        var root = Path.GetFullPath(EtsiCorpus.AdesPath(string.Empty));
        var files = Directory.GetFiles(root, "*", SearchOption.AllDirectories)
            .Select(f => Path.GetRelativePath(root, f).Replace(Path.DirectorySeparatorChar, '/'))
            .Where(f => f is not ManifestFile)
            .Order(StringComparer.Ordinal)
            .ToList();

        files.ShouldBe(expected.Keys.Order(StringComparer.Ordinal), ignoreOrder: false, "every corpus file must be in the manifest, and only those");
        foreach (var file in files)
        {
            var actual = Convert.ToHexString(SHA256.HashData(EtsiCorpus.ReadAdes(file)));
            actual.ShouldBe(expected[file].ToUpperInvariant(), $"'{file}' differs from the EU DSS file pinned in {ManifestFile}");
        }
    }

    private static Dictionary<string, string> ReadManifest()
    {
        using var manifest = JsonDocument.Parse(EtsiCorpus.ReadAdes(ManifestFile));
        var hashes = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var vector in manifest.RootElement.GetProperty("vectors").EnumerateArray())
        {
            hashes.Add(vector.GetProperty("resource").GetString()!, vector.GetProperty("sha256").GetString()!);
            if (vector.TryGetProperty("contentResource", out var content))
            {
                hashes.Add(content.GetString()!, vector.GetProperty("contentSha256").GetString()!);
            }
        }

        return hashes;
    }
}

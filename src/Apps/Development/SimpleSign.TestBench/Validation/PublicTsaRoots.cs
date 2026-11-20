using System.Security.Cryptography.X509Certificates;

namespace SimpleSign.TestBench.Validation;

/// <summary>
/// The roots of the public TSAs the TestBench offers (DigiCert, Sectigo, FreeTSA), from <c>TsaRoots/</c>: trusted so
/// their timestamps reach an anchor. DigiCert's and Sectigo's are usually among the operating system's roots too;
/// FreeTSA's never is. The DSS container (tools/dss) mounts the same folder, so both validators trust the same roots.
/// </summary>
internal static class PublicTsaRoots
{
    /// <summary>The folder, relative to the TestBench project, that holds the roots (PEM, one per file).</summary>
    public const string Folder = "src/Apps/Development/SimpleSign.TestBench/TsaRoots";

    private const string ResourcePrefix = "TsaRoots/";

    private static readonly Lazy<IReadOnlyList<(string Name, X509Certificate2 Certificate)>> s_files = new(Load);

    /// <summary>The roots, read once from the assembly's embedded copies.</summary>
    public static IReadOnlyList<X509Certificate2> Certificates => [.. s_files.Value.Select(f => f.Certificate)];

    /// <summary>The roots with the name of their file in <see cref="Folder"/> (e.g. <c>FreeTSA-RootCA.crt</c>).</summary>
    public static IReadOnlyList<(string Name, X509Certificate2 Certificate)> Files => s_files.Value;

    private static List<(string Name, X509Certificate2 Certificate)> Load()
    {
        var assembly = typeof(PublicTsaRoots).Assembly;
        var roots = new List<(string Name, X509Certificate2 Certificate)>();
        foreach (string name in assembly.GetManifestResourceNames().Where(n => n.StartsWith(ResourcePrefix, StringComparison.Ordinal)).Order(StringComparer.Ordinal))
        {
            using var stream = assembly.GetManifestResourceStream(name)!;
            using var reader = new StreamReader(stream);
            roots.Add((name[ResourcePrefix.Length..], X509Certificate2.CreateFromPem(reader.ReadToEnd())));
        }

        return roots;
    }
}

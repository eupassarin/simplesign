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
    public const string Folder = "src/Apps/SimpleSign.TestBench/TsaRoots";

    private const string ResourcePrefix = "TsaRoots/";

    private static readonly Lazy<IReadOnlyList<X509Certificate2>> s_certificates = new(Load);

    /// <summary>The roots, read once from the assembly's embedded copies.</summary>
    public static IReadOnlyList<X509Certificate2> Certificates => s_certificates.Value;

    private static List<X509Certificate2> Load()
    {
        var assembly = typeof(PublicTsaRoots).Assembly;
        var roots = new List<X509Certificate2>();
        foreach (string name in assembly.GetManifestResourceNames().Where(n => n.StartsWith(ResourcePrefix, StringComparison.Ordinal)).Order(StringComparer.Ordinal))
        {
            using var stream = assembly.GetManifestResourceStream(name)!;
            using var reader = new StreamReader(stream);
            roots.Add(X509Certificate2.CreateFromPem(reader.ReadToEnd()));
        }

        return roots;
    }
}

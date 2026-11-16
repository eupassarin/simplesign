using SimpleSign.Core.Validation;
using SimpleSign.TestHelpers;

namespace SimpleSign.Integration.Tests.Helpers;

/// <summary>
/// The EU DSS / ETSI plugtest corpus under <c>Fixtures/</c> (see <c>Fixtures/README.md</c>): signatures made by
/// other producers, validated offline — no revocation, no system roots, every HTTP request fails.
/// </summary>
internal static class EtsiCorpus
{
    /// <summary>The folder of the CAdES/XAdES vectors and their <c>manifest.json</c>, under <c>Fixtures/</c>.</summary>
    public const string AdesDir = "ades";

    /// <summary>Validation options that never reach the network.</summary>
    public static ValidationOptions OfflineOptions => new()
    {
        CheckRevocation = false,
        TrustSystemRoots = false,
        NetworkTimeout = TimeSpan.FromSeconds(1),
    };

    /// <summary>An HTTP client whose every request fails.</summary>
    public static HttpClient FailingHttpClient { get; } = MockHttpHandler.Failing();

    /// <summary>Reads a CAdES/XAdES vector by its path relative to <see cref="AdesDir"/> (e.g. <c>cades/cades-bt.p7m</c>).</summary>
    public static byte[] ReadAdes(string relativePath) =>
        File.ReadAllBytes(AdesPath(relativePath));

    /// <summary>The path of a CAdES/XAdES vector relative to <see cref="AdesDir"/>.</summary>
    public static string AdesPath(string relativePath) =>
        FixturePath.Get(Path.Combine(AdesDir, relativePath.Replace('/', Path.DirectorySeparatorChar)));
}

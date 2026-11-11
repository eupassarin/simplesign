using System.Security.Cryptography.X509Certificates;
using SimpleSign.Core.Extensions;

namespace SimpleSign.TestHelpers;

/// <summary>A trust anchor provider over certificates held in memory.</summary>
/// <param name="anchors">The trusted roots.</param>
public sealed class InMemoryTrustAnchors(params X509Certificate2[] anchors) : ITrustAnchorProvider
{
    /// <inheritdoc />
    public string RegionCode => "TEST";

    /// <inheritdoc />
    public string DisplayName => "Test anchors";

    /// <inheritdoc />
    public IReadOnlyList<X509Certificate2> GetTrustAnchors() => anchors;
}

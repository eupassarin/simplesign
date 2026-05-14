using System.Security.Cryptography.X509Certificates;

namespace SimpleSign.Core.Extensions;

/// <summary>
/// Provides trust anchor (root CA) certificates for a specific region or organization.
/// Implementations bundle root certificates that are automatically loaded during validation.
/// </summary>
public interface ITrustAnchorProvider
{
    /// <summary>Region or organization code (e.g., "BR", "EU", "US").</summary>
    string RegionCode { get; }

    /// <summary>Human-readable name (e.g., "ICP-Brasil", "EU Trusted List").</summary>
    string DisplayName { get; }

    /// <summary>Returns the bundled trust anchor certificates.</summary>
    IReadOnlyList<X509Certificate2> GetTrustAnchors();
}

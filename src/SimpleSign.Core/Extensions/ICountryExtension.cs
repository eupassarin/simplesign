namespace SimpleSign.Core.Extensions;

/// <summary>
/// Aggregates all country/regulation-specific extension points into a single registration unit.
/// Implement this interface to provide a complete country package (e.g., SimpleSign.Brasil, SimpleSign.EU).
/// Register via <c>SignerBuilder.WithCountryExtension&lt;T&gt;()</c> or DI.
/// </summary>
public interface ICountryExtension
{
    /// <summary>Region or organization code (e.g., "BR", "EU", "US").</summary>
    string RegionCode { get; }

    /// <summary>Human-readable name (e.g., "Brasil (ICP-Brasil + Lei 14.063)").</summary>
    string DisplayName { get; }

    /// <summary>Trust anchor providers for this region (root CA bundles).</summary>
    IReadOnlyList<ITrustAnchorProvider> TrustAnchorProviders { get; }

    /// <summary>Signature manifest provider, or null if no manifest is used.</summary>
    ISignatureManifestProvider? ManifestProvider { get; }

    /// <summary>Chain validation providers for this region.</summary>
    IReadOnlyList<IChainValidationProvider> ChainValidationProviders { get; }
}

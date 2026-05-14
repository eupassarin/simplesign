using System.Security.Cryptography.X509Certificates;

namespace SimpleSign.Core.Extensions;

/// <summary>
/// Performs country/regulation-specific certificate chain validation
/// beyond standard X.509 path building (e.g., ICP-Brasil policy OID mapping,
/// Gov.br assurance level detection, EU Trusted List verification).
/// </summary>
public interface IChainValidationProvider
{
    /// <summary>Region or organization code (e.g., "BR", "EU", "US").</summary>
    string RegionCode { get; }

    /// <summary>
    /// Determines whether this provider can validate the given certificate
    /// (e.g., by checking issuer OIDs, organization name, or policy arcs).
    /// </summary>
    bool CanValidate(X509Certificate2 certificate);

    /// <summary>
    /// Validates the certificate chain and returns region-specific results.
    /// </summary>
    ChainValidationResult Validate(X509Certificate2 certificate, IReadOnlyList<X509Certificate2>? chain = null);
}

/// <summary>
/// Result of a country/regulation-specific chain validation.
/// </summary>
public sealed class ChainValidationResult
{
    /// <summary>Whether the chain is trusted by this provider.</summary>
    public required bool IsTrusted { get; init; }

    /// <summary>Region code of the provider that produced this result.</summary>
    public required string RegionCode { get; init; }

    /// <summary>Human-readable policy or assurance level (e.g., "A3", "Gold", "QCP-w").</summary>
    public string? PolicyLevel { get; init; }

    /// <summary>Extracted signer national ID, if present in the certificate (e.g., CPF from SAN).</summary>
    public string? SignerId { get; init; }

    /// <summary>Type of the extracted ID (e.g., "CPF", "CNPJ").</summary>
    public string? SignerIdType { get; init; }

    /// <summary>Additional metadata extracted during validation.</summary>
    public IReadOnlyDictionary<string, string>? Metadata { get; init; }

    /// <summary>Validation errors, if any.</summary>
    public IReadOnlyList<string>? Errors { get; init; }
}

using System.Security.Cryptography.X509Certificates;
using SimpleSign.Core.Crypto;

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
    Task<ChainValidationResult> ValidateAsync(X509Certificate2 certificate, IReadOnlyList<X509Certificate2>? chain = null);

    /// <summary>
    /// Validates the certificate chain with cancellation support.
    /// The default implementation delegates to the parameterless CancellationToken overload.
    /// </summary>
    Task<ChainValidationResult> ValidateAsync(X509Certificate2 certificate, IReadOnlyList<X509Certificate2>? chain, CancellationToken cancellationToken)
        => ValidateAsync(certificate, chain);

    /// <summary>
    /// Validates the certificate chain at the time and with the revocation evidence the signature
    /// provides (<see cref="ChainValidationContext"/>). Signature validators call this overload.
    /// The default implementation delegates to
    /// <see cref="ValidateAsync(X509Certificate2, IReadOnlyList{X509Certificate2}, CancellationToken)"/>,
    /// which validates at the current time; implement it to honour the context.
    /// </summary>
    /// <param name="context">The certificate, the time of validation and the embedded evidence.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task<ChainValidationResult> ValidateAsync(ChainValidationContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        return ValidateAsync(context.Certificate, context.Certificates, cancellationToken);
    }
}

/// <summary>
/// What a signature validator knows when it asks an <see cref="IChainValidationProvider"/> to
/// validate a chain: the time to validate at and the revocation data embedded in the document.
/// </summary>
public sealed class ChainValidationContext
{
    /// <summary>The certificate to validate (usually the signer's).</summary>
    public required X509Certificate2 Certificate { get; init; }

    /// <summary>Certificates available to build the chain (from the signature and the DSS).</summary>
    public IReadOnlyList<X509Certificate2> Certificates { get; init; } = [];

    /// <summary>
    /// The time to validate at: the time of a trusted signature timestamp when there is one, so a
    /// long-term (B-LT/B-LTA) signature stays valid after the certificate expires. Null = now.
    /// </summary>
    public DateTimeOffset? ValidationTime { get; init; }

    /// <summary>Whether <see cref="ValidationTime"/> is proven by a signature timestamp (not just claimed by the signer).</summary>
    public bool IsValidationTimeFromTimestamp { get; init; }

    /// <summary>DER-encoded CRLs embedded in the document (DSS/VRI or the signature).</summary>
    public IReadOnlyList<byte[]> EmbeddedCrls { get; init; } = [];

    /// <summary>DER-encoded OCSP responses embedded in the document (DSS/VRI or the signature).</summary>
    public IReadOnlyList<byte[]> EmbeddedOcsps { get; init; } = [];

    /// <summary>Whether the provider should check revocation (embedded evidence first, then online).</summary>
    public bool CheckRevocation { get; init; } = true;

    /// <summary>The parsed signature, when the chain belongs to a CMS signature (policy, manifest, attributes).</summary>
    public CmsSignedData? Signature { get; init; }
}

/// <summary>The revocation status a chain validation provider established for the chain.</summary>
public enum ChainRevocationStatus
{
    /// <summary>Revocation was not checked.</summary>
    NotChecked,

    /// <summary>No certificate of the chain was revoked at the validation time.</summary>
    Good,

    /// <summary>A certificate of the chain was revoked at or before the validation time.</summary>
    Revoked,

    /// <summary>The status of at least one certificate could not be established (no evidence, network failure).</summary>
    Unknown,
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

    /// <summary>The revocation status of the chain, when the provider checked it.</summary>
    public ChainRevocationStatus RevocationStatus { get; init; }
}

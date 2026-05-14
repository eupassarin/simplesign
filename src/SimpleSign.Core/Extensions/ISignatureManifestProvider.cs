namespace SimpleSign.Core.Extensions;

/// <summary>
/// Builds and parses signature manifests — structured metadata embedded as CMS signed attributes.
/// Each country/regulation can define its own manifest format and OID.
/// </summary>
public interface ISignatureManifestProvider
{
    /// <summary>OID used to identify this manifest type in CMS signed attributes.</summary>
    string ManifestOid { get; }

    /// <summary>
    /// Builds a manifest from the signing context and returns the DER-encoded attribute value.
    /// </summary>
    byte[] BuildManifest(SignerContext context);

    /// <summary>
    /// Parses a manifest from raw bytes extracted from a CMS signed attribute.
    /// Returns null if the data is not a valid manifest for this provider.
    /// </summary>
    object? ParseManifest(ReadOnlySpan<byte> data);
}

/// <summary>
/// Context passed to <see cref="ISignatureManifestProvider.BuildManifest"/> during signing.
/// Contains signer metadata needed to build the manifest.
/// </summary>
public sealed class SignerContext
{
    /// <summary>Signer's display name.</summary>
    public required string SignerName { get; init; }

    /// <summary>National ID or equivalent (CPF, SSN, NIF, etc.).</summary>
    public string? SignerId { get; init; }

    /// <summary>Type of the signer ID (e.g., "CPF", "SSN", "NIF").</summary>
    public string? SignerIdType { get; init; }

    /// <summary>Signer's email address.</summary>
    public string? Email { get; init; }

    /// <summary>IP address at time of signing.</summary>
    public string? IpAddress { get; init; }

    /// <summary>Authentication method description.</summary>
    public string? AuthenticationMethod { get; init; }

    /// <summary>Institution or organization name.</summary>
    public string? InstitutionName { get; init; }

    /// <summary>Institution ID (CNPJ, VAT, EIN, etc.).</summary>
    public string? InstitutionId { get; init; }

    /// <summary>Type of the institution ID (e.g., "CNPJ", "VAT", "EIN").</summary>
    public string? InstitutionIdType { get; init; }

    /// <summary>Legal basis for the signature (e.g., "Lei 14.063/2020", "eIDAS").</summary>
    public string? LegalBasis { get; init; }

    /// <summary>Commitment type name (e.g., "proofOfApproval").</summary>
    public string? CommitmentType { get; init; }
}

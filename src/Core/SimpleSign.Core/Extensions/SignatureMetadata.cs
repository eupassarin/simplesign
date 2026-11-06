using SimpleSign.Core.Crypto;
using SimpleSign.Core.Signing;

namespace SimpleSign.Core.Extensions;

/// <summary>
/// Generic signer metadata for any country/regulation.
/// Country-specific types can map to this via extension methods.
/// </summary>
public sealed class SignatureMetadata
{
    /// <summary>Full name of the signer.</summary>
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

    /// <summary>CAdES commitment type.</summary>
    public CommitmentType CommitmentType { get; init; } = CommitmentType.ProofOfApproval;

    /// <summary>Legal basis for the signature (e.g., "Lei 14.063/2020", "eIDAS").</summary>
    public string? LegalBasis { get; init; }

    /// <summary>OID of the signature policy.</summary>
    public string? PolicyOid { get; init; }

    /// <summary>URI of the signature policy document.</summary>
    public string? PolicyUri { get; init; }

    /// <summary>Signing reason shown in PDF (e.g., "Approval", "Review").</summary>
    public string? Reason { get; init; }

    /// <summary>
    /// Structured contact info shown in Adobe "Signature Properties".
    /// If null, built automatically from available fields.
    /// </summary>
    public string? ContactInfo { get; init; }

    /// <summary>Signing location (e.g., institution name, city).</summary>
    public string? Location { get; init; }

    /// <summary>Extra CMS signed attributes to embed.</summary>
    public IReadOnlyList<CmsAttribute>? ExtraAttributes { get; init; }
}

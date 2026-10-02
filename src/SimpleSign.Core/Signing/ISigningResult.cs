namespace SimpleSign.Core.Signing;

/// <summary>
/// Common result contract for AdES signing operations across PAdES, CAdES, and XAdES.
/// </summary>
/// <remarks>
/// The <c>Has*</c> properties describe properties established in the produced artifact,
/// never pipeline operations that were merely attempted. <see cref="AchievedLevel"/>
/// is classified from the strongest complete set of established properties, never from
/// the requested enum or attempted steps. Completed signatures undergo cryptographic
/// signature and content-integrity read-back. Embedded-evidence applicability and
/// authenticity are distinct from certificate-chain and TSA trust; trust-anchor and
/// policy conclusions belong to the validation APIs.
/// </remarks>
public interface ISigningResult
{
    /// <summary>The baseline level requested by the caller.</summary>
    AdesBaselineLevel RequestedLevel { get; }

    /// <summary>The strongest baseline level established by checked evidence in the completed artifact.</summary>
    AdesBaselineLevel AchievedLevel { get; }

    /// <summary>
    /// Whether an embedded RFC 3161 token has checked cryptographic integrity and
    /// covers the format-required signature timestamp input, independently of TSA trust.
    /// </summary>
    bool HasSignatureTimestamp { get; }

    /// <summary>
    /// Whether the embedded certificate and revocation material required for B-LT
    /// has checked applicability, authenticity, and path coverage, independently of
    /// certificate-chain trust.
    /// </summary>
    bool HasLongTermValidationMaterial { get; }

    /// <summary>
    /// Whether an embedded archive timestamp has checked cryptographic integrity and
    /// format-required archive coverage, independently of TSA trust.
    /// </summary>
    bool HasArchiveTimestamp { get; }

    /// <summary>Non-fatal warnings raised during the signing operation.</summary>
    IReadOnlyList<SigningWarning> Warnings { get; }
}

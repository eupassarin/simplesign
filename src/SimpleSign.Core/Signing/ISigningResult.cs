namespace SimpleSign.Core.Signing;

/// <summary>
/// Common result contract for AdES signing operations across PAdES, CAdES, and XAdES.
/// </summary>
/// <remarks>
/// The <c>Has*</c> properties describe properties established in the produced artifact,
/// never pipeline operations that were merely attempted. <see cref="AchievedLevel"/>
/// is classified from the strongest complete set of established properties, never from
/// the requested enum or attempted steps. These facts are not a full signature-validity
/// or TSA-trust verdict; trust conclusions belong to the validation APIs.
/// </remarks>
public interface ISigningResult
{
    /// <summary>The baseline level requested by the caller.</summary>
    AdesBaselineLevel RequestedLevel { get; }

    /// <summary>The strongest baseline structure actually created in the produced artifact.</summary>
    AdesBaselineLevel AchievedLevel { get; }

    /// <summary>
    /// Whether an RFC 3161 response accepted by the creation pipeline and covering the
    /// signature value was embedded in the produced artifact.
    /// </summary>
    bool HasSignatureTimestamp { get; }

    /// <summary>
    /// Whether the certificate and revocation material required for the B-LT structure
    /// was actually included, not merely that at least one certificate or response was added.
    /// </summary>
    bool HasLongTermValidationMaterial { get; }

    /// <summary>
    /// Whether an archive timestamp accepted by the creation pipeline and calculated over
    /// the format-required coverage was embedded.
    /// </summary>
    bool HasArchiveTimestamp { get; }

    /// <summary>Non-fatal warnings raised during the signing operation.</summary>
    IReadOnlyList<SigningWarning> Warnings { get; }
}

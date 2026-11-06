using SimpleSign.Core.Signing;

namespace SimpleSign.CAdES;

/// <summary>
/// Detailed result of a CAdES signing operation, returned by
/// <see cref="CadesSignerBuilder.SignWithDetailsAsync"/>.
/// </summary>
/// <remarks>
/// The <c>Has*</c> properties and <see cref="ISigningResult.AchievedLevel"/> describe
/// properties established in the produced artifact, never configuration flags or
/// pipeline steps that were merely attempted.
/// </remarks>
public sealed record CadesSigningResult : ISigningResult
{
    /// <summary>DER-encoded CMS/PKCS#7 SignedData.</summary>
    public required byte[] SignedArtifact { get; init; }

    /// <inheritdoc/>
    public AdesBaselineLevel RequestedLevel { get; init; }

    /// <inheritdoc/>
    public AdesBaselineLevel AchievedLevel { get; init; }

    /// <inheritdoc/>
    public bool HasSignatureTimestamp { get; init; }

    /// <inheritdoc/>
    public bool HasLongTermValidationMaterial { get; init; }

    /// <inheritdoc/>
    public bool HasArchiveTimestamp { get; init; }

    /// <inheritdoc/>
    public IReadOnlyList<SigningWarning> Warnings { get; init; } = [];
}

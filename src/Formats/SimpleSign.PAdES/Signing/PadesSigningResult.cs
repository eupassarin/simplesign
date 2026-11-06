using SimpleSign.Core.Signing;

namespace SimpleSign.PAdES.Signing;

/// <summary>
/// Detailed result of a PAdES signing operation, returned by
/// <see cref="PadesSignerBuilder.SignWithDetailsAsync"/>.
/// </summary>
/// <remarks>
/// The <c>Has*</c> properties and <see cref="ISigningResult.AchievedLevel"/> describe
/// properties established in the produced artifact, never configuration flags or
/// pipeline steps that were merely attempted.
/// </remarks>
public sealed record PadesSigningResult : ISigningResult
{
    /// <summary>The signed PDF bytes.</summary>
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

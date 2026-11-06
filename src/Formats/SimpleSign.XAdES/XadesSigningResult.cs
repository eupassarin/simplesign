using SimpleSign.Core.Signing;

namespace SimpleSign.XAdES;

/// <summary>
/// Detailed result of a XAdES signing operation, returned by
/// <see cref="XadesSignerBuilder.SignWithDetailsAsync"/>.
/// </summary>
/// <remarks>
/// The <c>Has*</c> properties and <see cref="ISigningResult.AchievedLevel"/> describe
/// properties established in the produced artifact, never configuration flags or
/// pipeline steps that were merely attempted.
/// </remarks>
public sealed record XadesSigningResult : ISigningResult
{
    /// <summary>The signed XML bytes.</summary>
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

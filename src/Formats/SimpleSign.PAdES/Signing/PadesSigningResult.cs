using SimpleSign.Core.Signing;

namespace SimpleSign.PAdES.Signing;

/// <summary>
/// Detailed result of a PAdES signing operation, returned by
/// <see cref="PadesSignerBuilder.SignWithDetailsAsync"/>.
/// </summary>
/// <remarks>
/// The <c>Has*</c> properties and <see cref="ISigningResult.AchievedLevel"/> describe
/// properties established in the produced artifact, never configuration flags or
/// pipeline steps that were merely attempted. With a SubFilter other than <c>ETSI.CAdES.detached</c>
/// (<see cref="PdfSignatureSubFilter.AdbePkcs7Detached"/>, <see cref="PdfSignatureSubFilter.PbadPades"/>) the
/// signature is not a PAdES baseline signature under ETSI EN 319 142-1: the achieved level then tells what it
/// holds, and <see cref="Warnings"/> has <see cref="SigningWarningCode.SubFilterNotBaseline"/>.
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

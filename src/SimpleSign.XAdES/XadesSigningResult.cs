namespace SimpleSign.XAdES;

/// <summary>Result of a XAdES signing operation, returned by <see cref="XadesSignerBuilder.SignWithDetailsAsync"/>.</summary>
public sealed class XadesSigningResult
{
    /// <summary>The signed XML bytes.</summary>
    public byte[] SignedXml { get; init; } = [];

    /// <summary>Whether a timestamp token was applied (XAdES-B-T or higher).</summary>
    public bool TimestampApplied { get; init; }

    /// <summary>Whether long-term validation data was embedded (XAdES-B-LT or higher).</summary>
    public bool LtvDataEmbedded { get; init; }

    /// <summary>Whether an archive timestamp was applied (XAdES-B-LTA).</summary>
    public bool ArchiveTimestampApplied { get; init; }

    /// <summary>Non-critical warnings.</summary>
    public IReadOnlyList<string> Warnings { get; init; } = [];
}

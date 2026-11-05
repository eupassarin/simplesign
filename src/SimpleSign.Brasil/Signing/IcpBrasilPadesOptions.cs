using SimpleSign.Brasil.IcpBrasil;
using SimpleSign.Core.Signing;

namespace SimpleSign.Brasil.Signing;

/// <summary>
/// Settings for an ICP-Brasil PAdES signature policy (DOC-ICP-15.03): the TSA the policy needs,
/// the policy version and, for AD-RA, the policy artifacts.
/// </summary>
/// <remarks>
/// What each policy requires (Table A.22): AD-RB nothing more; AD-RT a signature timestamp;
/// AD-RC a signature timestamp, the DSS with VRI and a document timestamp; AD-RA all of AD-RC plus
/// the PA, LPA and LPA signature in the DSS (<see cref="Artifacts"/>).
/// </remarks>
public sealed record IcpBrasilPadesOptions
{
    /// <summary>The signature TSA (ideally an ICP-Brasil accredited ACT). Required for every policy but AD-RB.</summary>
    public TimestampOptions? Timestamp { get; init; }

    /// <summary>The document timestamp TSA for AD-RC/AD-RA; null uses <see cref="Timestamp"/>.</summary>
    public ArchiveTimestampOptions? ArchiveTimestamp { get; init; }

    /// <summary>How the DSS revocation data is collected for AD-RC/AD-RA; null uses the defaults.</summary>
    public LongTermValidationOptions? LongTermValidation { get; init; }

    /// <summary>
    /// A specific version of the policy; null picks the newest in-force version that accepts the
    /// signer's root.
    /// </summary>
    public IcpBrasilSignaturePolicy? Version { get; init; }

    /// <summary>The PA, LPA and LPA signature; required for AD-RA (<see cref="IcpBrasilPolicyArtifacts.DownloadAsync(HttpClient, IcpBrasilSignaturePolicy, CancellationToken)"/>).</summary>
    public IcpBrasilPolicyArtifacts? Artifacts { get; init; }
}

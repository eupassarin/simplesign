using System.Security.Cryptography.X509Certificates;

namespace SimpleSign.Core.Extensions;

/// <summary>What a validation needs to know about a trusted list (ETSI TS 119 612) for the eIDAS constraints of a policy.</summary>
/// <param name="Territory">The scheme territory.</param>
/// <param name="Location">Where the list was read from, or null.</param>
/// <param name="Version">The TSLVersionIdentifier, or null.</param>
/// <param name="IssueDate">The ListIssueDateTime, or null.</param>
/// <param name="NextUpdate">The NextUpdate, or null for a closed list.</param>
/// <param name="LoadedAt">When the list was downloaded (or read from its cache).</param>
/// <param name="IsWellSigned">Whether its signature verified with the expected certificates.</param>
/// <param name="Anchors">The trust anchors it gives.</param>
public sealed record TrustedListInfo(
    string Territory,
    Uri? Location,
    string? Version,
    DateTimeOffset? IssueDate,
    DateTimeOffset? NextUpdate,
    DateTimeOffset LoadedAt,
    bool IsWellSigned,
    IReadOnlyList<X509Certificate2> Anchors)
{
    /// <summary>The trust services of the list, for the <c>TrustServiceTypeIdentifier</c> and <c>TrustServiceStatus</c> constraints.</summary>
    public IReadOnlyList<TrustedServiceInfo> Services { get; init; } = [];

    /// <summary>Whether the list is valid against the ETSI TS 119 612 XML schema, for the <c>TLStructure</c> constraint; null when not checked.</summary>
    public bool? IsStructureValid { get; init; }
}

/// <summary>A trust service of a trusted list: its type, its status and its digital identity.</summary>
/// <param name="ServiceType">The ServiceTypeIdentifier URI.</param>
/// <param name="Status">The ServiceStatus URI.</param>
/// <param name="Certificates">The service's certificates.</param>
public sealed record TrustedServiceInfo(string ServiceType, string Status, IReadOnlyList<X509Certificate2> Certificates);

/// <summary>
/// A trust anchor provider backed by trusted lists: validators read the lists' state for the eIDAS constraints
/// (<c>TLFreshness</c>, <c>TLNotExpired</c>, <c>TLWellSigned</c>, <c>TLVersion</c>).
/// </summary>
public interface ITrustedListInfoProvider
{
    /// <summary>The trusted lists the anchors come from.</summary>
    IReadOnlyList<TrustedListInfo> TrustedLists { get; }
}

namespace SimpleSign.PAdES.Signing;

/// <summary>
/// Parsed data from an existing DSS dictionary in the PDF.
/// Used during LTV embedding to merge prior revocation data with new data.
/// </summary>
internal sealed record ExistingDssData(
    IReadOnlyList<int> CrlObjRefs,
    IReadOnlyList<int> OcspObjRefs,
    IReadOnlyList<int> CertObjRefs,
    IReadOnlyDictionary<string, int> VriEntries)
{
    /// <summary>Other top-level DSS arrays of references (e.g. PBAD_PolicyArtifacts), kept when the DSS is rewritten.</summary>
    internal IReadOnlyDictionary<string, IReadOnlyList<int>> ExtraArrays { get; init; } = new Dictionary<string, IReadOnlyList<int>>();

    /// <summary>Empty instance representing no prior DSS.</summary>
    internal static ExistingDssData Empty { get; } = new(
        [],
        [],
        [],
        new Dictionary<string, int>());
}

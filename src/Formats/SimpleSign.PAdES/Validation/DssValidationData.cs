namespace SimpleSign.PAdES.Validation;

/// <summary>
/// Full DSS validation data including global arrays and per-signature VRI entries.
/// Used for VRI-aware validation in multi-signature PDFs.
/// </summary>
internal sealed record DssValidationData(
    IReadOnlyList<byte[]> GlobalCrls,
    IReadOnlyList<byte[]> GlobalOcsps,
    IReadOnlyList<byte[]> GlobalCerts,
    IReadOnlyDictionary<string, VriData> VriEntries)
{
    /// <summary>The document has a DSS dictionary.</summary>
    internal bool Present { get; init; }

    /// <summary>The keys of the DSS dictionary.</summary>
    internal IReadOnlyCollection<string> Keys { get; init; } = [];

    /// <summary>Empty instance representing no DSS in the PDF.</summary>
    internal static DssValidationData Empty { get; } = new(
        [],
        [],
        [],
        new Dictionary<string, VriData>());
}

/// <summary>
/// Validation-related information for a specific signature (per VRI entry).
/// Keyed by uppercase hex SHA-1 hash of the signature's CMS /Contents value.
/// </summary>
internal sealed record VriData(
    IReadOnlyList<byte[]> Crls,
    IReadOnlyList<byte[]> Ocsps,
    IReadOnlyList<byte[]> Certs)
{
    /// <summary>The keys of the VRI dictionary.</summary>
    internal IReadOnlyCollection<string> Keys { get; init; } = [];
}

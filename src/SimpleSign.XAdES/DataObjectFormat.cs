namespace SimpleSign.XAdES;

/// <summary>
/// Describes the format of a signed data object (ETSI EN 319 132-1 §7.2.2).
/// Provides the MIME type and object reference URI for inclusion in XAdES SignedDataObjectProperties.
/// </summary>
public sealed class DataObjectFormat
{
    /// <summary>Reference URI of the signed data object (matches a ds:Reference URI). Null means no reference is set.</summary>
    public string? ObjectReference { get; init; }

    /// <summary>MIME type of the data object (e.g., "text/xml", "application/pdf").</summary>
    public string? MimeType { get; init; }
}

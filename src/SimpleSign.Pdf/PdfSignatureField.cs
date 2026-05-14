namespace SimpleSign.Pdf;

/// <summary>Represents a PDF signature field and its raw CMS contents.</summary>
public sealed class PdfSignatureField
{
    /// <summary>PDF field name (e.g., "Signature1").</summary>
    public string FieldName { get; init; } = string.Empty;

    /// <summary>Byte range covering the signed content.</summary>
    public PdfByteRange ByteRange { get; init; } = new PdfByteRange();

    /// <summary>Raw DER-encoded CMS/PKCS#7 bytes from /Contents.</summary>
    public byte[] ContentsBytes { get; init; } = Array.Empty<byte>();

    /// <summary>Indicates whether the field contains a signature.</summary>
    public bool IsSigned => ContentsBytes.Length != 0;

    /// <summary>PDF object number of the signature dictionary.</summary>
    public int SigDictObjectNumber { get; init; }

    /// <summary>Signing time from the /M entry in the signature dictionary, if present.</summary>
    public DateTimeOffset? PdfSigningTime { get; init; }

    /// <summary>SubFilter value (e.g., "adbe.pkcs7.detached" or "ETSI.CAdES.detached").</summary>
    public string? SubFilter { get; init; }

    /// <summary>Signing reason from the /Reason entry, if present.</summary>
    public string? Reason { get; init; }

    /// <summary>Signing location from the /Location entry, if present.</summary>
    public string? Location { get; init; }

    /// <summary>Contact information from the /ContactInfo entry, if present.</summary>
    public string? ContactInfo { get; init; }

    /// <summary>Signer name from the /Name entry, if present.</summary>
    public string? SignerName { get; init; }

    /// <summary>Whether this is a document timestamp (SubFilter = ETSI.RFC3161) rather than a regular signature.</summary>
    public bool IsDocumentTimestamp =>
        string.Equals(SubFilter, "ETSI.RFC3161", StringComparison.OrdinalIgnoreCase);
}

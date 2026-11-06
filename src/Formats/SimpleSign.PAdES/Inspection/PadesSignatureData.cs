using SimpleSign.Pdf;

namespace SimpleSign.PAdES.Inspection;

/// <summary>
/// Contains the extracted signature data from a PAdES-signed PDF.
/// The CMS signature can be validated independently using the CMS validator.
/// </summary>
public sealed class PadesSignatureData
{
    /// <summary>Signature field name in the PDF.</summary>
    public string FieldName { get; init; } = "";

    /// <summary>
    /// The bytes covered by ByteRange (the data that was signed).
    /// This is the concatenation of the two PDF segments excluding the /Contents hex.
    /// </summary>
    public byte[] SignedData { get; init; } = [];

    /// <summary>
    /// The CMS/PKCS#7 signature bytes (decoded from /Contents hex).
    /// This is a standard CAdES signature that can be saved as .p7s.
    /// </summary>
    public byte[] CmsSignature { get; init; } = [];

    /// <summary>The ByteRange from the PDF.</summary>
    public PdfByteRange ByteRange { get; init; } = null!;

    /// <summary>SubFilter (e.g., "adbe.pkcs7.detached", "ETSI.CAdES.detached").</summary>
    public string? SubFilter { get; init; }

    /// <summary>
    /// The PDF revision covered by this signature.
    /// This is the complete PDF as it existed when this signature was applied
    /// (bytes from 0 to ByteRange.Offset2 + ByteRange.Length2).
    /// For the last signature, this equals the full PDF.
    /// </summary>
    public byte[] PdfRevision { get; init; } = [];

    /// <summary>Saves the PDF revision to a file.</summary>
    public async Task SavePdfRevisionAsync(string filePath, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(filePath);
        await File.WriteAllBytesAsync(filePath, PdfRevision, ct).ConfigureAwait(false);
    }

    /// <summary>Saves the CMS signature as a .p7s file.</summary>
    public async Task SaveSignatureAsync(string filePath, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(filePath);
        await File.WriteAllBytesAsync(filePath, CmsSignature, ct).ConfigureAwait(false);
    }

    /// <summary>Saves the signed data bytes to a file.</summary>
    public async Task SaveSignedDataAsync(string filePath, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(filePath);
        await File.WriteAllBytesAsync(filePath, SignedData, ct).ConfigureAwait(false);
    }
}

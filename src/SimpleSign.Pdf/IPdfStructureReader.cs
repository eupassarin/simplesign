using Microsoft.Extensions.Logging;
using SimpleSign.Pdf.Enums;

namespace SimpleSign.Pdf;

/// <summary>Reads and inspects PDF structure (signature fields, DocMDP, PDF/A, encryption).</summary>
public interface IPdfStructureReader
{
    /// <summary>Reads all signature fields from a PDF stream.</summary>
    Task<IReadOnlyList<PdfSignatureField>> ReadSignatureFieldsAsync(Stream pdfStream, ILogger? logger = null, CancellationToken cancellationToken = default);

    /// <summary>Checks if a PDF has a DocMDP (document modification) lock.</summary>
    Task<bool> IsDocMdpLockedAsync(Stream pdfStream, ILogger? logger = null, CancellationToken cancellationToken = default);

    /// <summary>Reads the signed byte range from a PDF stream using ByteRange offsets.</summary>
    Task<byte[]> ReadSignedBytesAsync(Stream pdfStream, PdfByteRange byteRange, ILogger? logger = null, CancellationToken cancellationToken = default);

    /// <summary>Detects the PDF/A conformance level of a document.</summary>
    Task<PdfALevel> DetectPdfALevelAsync(Stream pdfStream, ILogger? logger = null, CancellationToken cancellationToken = default);

    /// <summary>Checks if the PDF is encrypted.</summary>
    Task<bool> IsEncryptedAsync(Stream pdfStream, ILogger? logger = null, CancellationToken cancellationToken = default);

    /// <summary>Gets the DocMDP permission level (0-3).</summary>
    Task<int> GetDocMdpPermissionLevelAsync(Stream pdfStream, ILogger? logger = null, CancellationToken cancellationToken = default);

    /// <summary>Detects the PDF version number.</summary>
    Task<PdfVersion> DetectPdfVersionAsync(Stream pdfStream, CancellationToken cancellationToken = default);
}

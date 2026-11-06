using Microsoft.Extensions.Logging;
using SimpleSign.Pdf.Enums;

namespace SimpleSign.Pdf;

/// <summary>Default implementation of <see cref="IPdfStructureReader"/>.</summary>
public sealed class PdfStructureReaderService : IPdfStructureReader
{
    /// <inheritdoc />
    public Task<IReadOnlyList<PdfSignatureField>> ReadSignatureFieldsAsync(Stream pdfStream, ILogger? logger = null, CancellationToken cancellationToken = default)
        => PdfStructureReader.ReadSignatureFieldsAsync(pdfStream, logger, cancellationToken);

    /// <inheritdoc />
    public Task<bool> IsDocMdpLockedAsync(Stream pdfStream, ILogger? logger = null, CancellationToken cancellationToken = default)
        => PdfStructureReader.IsDocMdpLockedAsync(pdfStream, logger, cancellationToken);

    /// <inheritdoc />
    public Task<byte[]> ReadSignedBytesAsync(Stream pdfStream, PdfByteRange byteRange, ILogger? logger = null, CancellationToken cancellationToken = default)
        => PdfStructureReader.ReadSignedBytesAsync(pdfStream, byteRange, logger, cancellationToken);

    /// <inheritdoc />
    public Task<PdfALevel> DetectPdfALevelAsync(Stream pdfStream, ILogger? logger = null, CancellationToken cancellationToken = default)
        => PdfStructureReader.DetectPdfALevelAsync(pdfStream, logger, cancellationToken);

    /// <inheritdoc />
    public Task<bool> IsEncryptedAsync(Stream pdfStream, ILogger? logger = null, CancellationToken cancellationToken = default)
        => PdfStructureReader.IsEncryptedAsync(pdfStream, logger, cancellationToken);

    /// <inheritdoc />
    public Task<int> GetDocMdpPermissionLevelAsync(Stream pdfStream, ILogger? logger = null, CancellationToken cancellationToken = default)
        => PdfStructureReader.GetDocMdpPermissionLevelAsync(pdfStream, logger, cancellationToken);

    /// <inheritdoc />
    public Task<PdfVersion> DetectPdfVersionAsync(Stream pdfStream, CancellationToken cancellationToken = default)
        => PdfStructureReader.DetectPdfVersionAsync(pdfStream, cancellationToken);
}

using Microsoft.Extensions.Logging;
using SimpleSign.Pdf;

namespace SimpleSign.PAdES.Inspection;

/// <summary>
/// Extracts CMS signatures and signed data from PAdES-signed PDFs.
/// Enables cross-validation: extract PAdES signature → validate with CAdES validator.
/// </summary>
public static class PadesExtractor
{
    /// <summary>Extracts all signatures from a PDF byte array.</summary>
    /// <param name="pdfBytes">The PDF content.</param>
    /// <param name="logger">Optional logger.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>List of extracted signature data, one per signature field.</returns>
    public static async Task<IReadOnlyList<PadesSignatureData>> ExtractAsync(
        byte[] pdfBytes, ILogger? logger = null, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(pdfBytes);

        using var stream = new MemoryStream(pdfBytes, writable: false);
        return await ExtractAsync(stream, logger, ct).ConfigureAwait(false);
    }

    /// <summary>Extracts all signatures from a PDF stream.</summary>
    /// <param name="pdfStream">A seekable PDF stream.</param>
    /// <param name="logger">Optional logger.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>List of extracted signature data, one per signature field.</returns>
    public static async Task<IReadOnlyList<PadesSignatureData>> ExtractAsync(
        Stream pdfStream, ILogger? logger = null, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(pdfStream);

        var fields = await PdfStructureReader.ReadSignatureFieldsAsync(pdfStream, logger, ct)
            .ConfigureAwait(false);

        var results = new List<PadesSignatureData>(fields.Count);

        foreach (var field in fields)
        {
            if (!field.IsSigned)
            {
                continue;
            }

            byte[] signedData = await PdfStructureReader.ReadSignedBytesAsync(
                pdfStream, field.ByteRange, logger, ct).ConfigureAwait(false);

            // The PDF revision is everything from byte 0 to the end of the second ByteRange segment
            long revisionEnd = field.ByteRange.Offset2 + field.ByteRange.Length2;
            byte[] pdfRevision = new byte[revisionEnd];
            pdfStream.Seek(0, SeekOrigin.Begin);
            await pdfStream.ReadExactlyAsync(pdfRevision.AsMemory(0, (int)revisionEnd), ct)
                .ConfigureAwait(false);

            results.Add(new PadesSignatureData
            {
                FieldName = field.FieldName,
                SignedData = signedData,
                CmsSignature = field.ContentsBytes,
                ByteRange = field.ByteRange,
                SubFilter = field.SubFilter,
                PdfRevision = pdfRevision,
            });
        }

        return results;
    }

    /// <summary>Extracts all signatures from a PDF file.</summary>
    /// <param name="filePath">Path to the PDF file.</param>
    /// <param name="logger">Optional logger.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>List of extracted signature data, one per signature field.</returns>
    public static async Task<IReadOnlyList<PadesSignatureData>> ExtractFromFileAsync(
        string filePath, ILogger? logger = null, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(filePath);

        byte[] pdfBytes = await File.ReadAllBytesAsync(filePath, ct).ConfigureAwait(false);
        return await ExtractAsync(pdfBytes, logger, ct).ConfigureAwait(false);
    }
}

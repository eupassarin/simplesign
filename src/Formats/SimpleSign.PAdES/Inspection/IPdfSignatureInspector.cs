using Microsoft.Extensions.Logging;

namespace SimpleSign.PAdES.Inspection;

/// <summary>Inspects PDF signatures and extracts signature metadata without validation.</summary>
public interface IPdfSignatureInspector
{
    /// <summary>Inspects signatures in a PDF stream and returns metadata.</summary>
    Task<PdfInspectionResult> InspectAsync(Stream pdfStream, ILogger? logger = null, CancellationToken cancellationToken = default);
}

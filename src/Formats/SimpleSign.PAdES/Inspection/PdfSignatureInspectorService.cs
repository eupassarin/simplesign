using Microsoft.Extensions.Logging;

namespace SimpleSign.PAdES.Inspection;

/// <summary>Default implementation of <see cref="IPdfSignatureInspector"/> that delegates to <see cref="PdfSignatureInspector"/>.</summary>
public sealed class PdfSignatureInspectorService : IPdfSignatureInspector
{
    /// <inheritdoc />
    public async Task<PdfInspectionResult> InspectAsync(Stream pdfStream, ILogger? logger = null, CancellationToken cancellationToken = default)
        => await PdfSignatureInspector.InspectAsync(pdfStream, logger, cancellationToken).ConfigureAwait(false);
}

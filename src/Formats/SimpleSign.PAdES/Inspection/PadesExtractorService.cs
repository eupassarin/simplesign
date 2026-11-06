using Microsoft.Extensions.Logging;

namespace SimpleSign.PAdES.Inspection;

/// <summary>Default implementation of <see cref="IPadesExtractor"/> that delegates to <see cref="PadesExtractor"/>.</summary>
public sealed class PadesExtractorService : IPadesExtractor
{
    /// <inheritdoc />
    public async Task<IReadOnlyList<PadesSignatureData>> ExtractFromFileAsync(string pdfPath, ILogger? logger = null, CancellationToken cancellationToken = default)
        => await PadesExtractor.ExtractFromFileAsync(pdfPath, logger, cancellationToken).ConfigureAwait(false);

    /// <inheritdoc />
    public Task<IReadOnlyList<PadesSignatureData>> ExtractAsync(byte[] pdfBytes, ILogger? logger = null, CancellationToken ct = default)
        => PadesExtractor.ExtractAsync(pdfBytes, logger, ct);

    /// <inheritdoc />
    public Task<IReadOnlyList<PadesSignatureData>> ExtractAsync(Stream pdfStream, ILogger? logger = null, CancellationToken ct = default)
        => PadesExtractor.ExtractAsync(pdfStream, logger, ct);
}

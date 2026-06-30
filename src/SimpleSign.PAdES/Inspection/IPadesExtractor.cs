using Microsoft.Extensions.Logging;

namespace SimpleSign.PAdES.Inspection;

/// <summary>Extracts CMS/PKCS#7 signature data from signed PDF files.</summary>
public interface IPadesExtractor
{
    /// <summary>Extracts all signature data from a PDF file.</summary>
    Task<IReadOnlyList<PadesSignatureData>> ExtractFromFileAsync(string pdfPath, ILogger? logger = null, CancellationToken cancellationToken = default);

    /// <summary>Extracts all signature data from PDF bytes.</summary>
    Task<IReadOnlyList<PadesSignatureData>> ExtractAsync(byte[] pdfBytes, ILogger? logger = null, CancellationToken ct = default);

    /// <summary>Extracts all signature data from a PDF stream.</summary>
    Task<IReadOnlyList<PadesSignatureData>> ExtractAsync(Stream pdfStream, ILogger? logger = null, CancellationToken ct = default);
}

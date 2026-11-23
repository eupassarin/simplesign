using Microsoft.Extensions.Logging;
using SimpleSign.PAdES.Internal;
using SimpleSign.PAdES.Pdf;
using SimpleSign.PAdES.Pdf.Model;

namespace SimpleSign.PAdES.Validation;

/// <summary>
/// Extracts embedded revocation data (CRLs, OCSPs) from the PDF DSS dictionary.
/// Used for offline/archival validation (PAdES-B-LT/LTA).
/// </summary>
internal static partial class DssExtractor
{
    /// <summary>
    /// Attempts to extract embedded CRLs from the PDF DSS (Document Security Store) dictionary.
    /// Returns a list of DER-encoded CRLs; empty list if no DSS is found or on error.
    /// </summary>
    internal static async Task<IReadOnlyList<byte[]>> TryReadDssDataAsync(
        Stream pdfStream,
        CancellationToken ct,
        ILogger? logger = null)
    {
        var fullData = await TryReadFullDssDataAsync(pdfStream, ct, logger).ConfigureAwait(false);
        return fullData.GlobalCrls;
    }

    /// <summary>
    /// Extracts full DSS validation data including global CRLs/OCSPs/Certs and per-signature VRI entries.
    /// Used for VRI-aware validation in multi-signature PDFs.
    /// </summary>
    internal static async Task<DssValidationData> TryReadFullDssDataAsync(
        Stream pdfStream,
        CancellationToken ct,
        ILogger? logger = null)
    {
        try
        {
            pdfStream.Seek(0, SeekOrigin.Begin);
            int length = (int)Math.Min(pdfStream.Length, PdfStructureReader.MaxPdfSize);
            var pdfBytes = new byte[length];
            int read = 0;
            while (read < length)
            {
                int n = await pdfStream.ReadAsync(pdfBytes.AsMemory(read, length - read), ct).ConfigureAwait(false);
                if (n == 0)
                {
                    break;
                }
                read += n;
            }
            return DssReader.Read(PdfDocument.Open(pdfBytes.AsMemory(0, read)).View());
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        // S2221: intentional broad catch — data extraction from untrusted PDF
        catch (Exception ex)
        {
            logger?.CrlExtractionFromPdfFailed(ex.Message);
            return DssValidationData.Empty;
        }
    }

    // Returns the index after the nested dictionary, array, hex string or literal string at i.
    /// <summary>
    /// Parses the existing DSS dictionary from PDF bytes and returns the object references
    /// for CRLs, OCSPs, Certs, and VRI entries. Used for DSS merge during multi-signature LTV embedding.
    /// </summary>
    internal static Signing.ExistingDssData ParseExistingDss(byte[] pdf) => DssReader.ReadExisting(PdfDocument.Open(pdf).View());

}

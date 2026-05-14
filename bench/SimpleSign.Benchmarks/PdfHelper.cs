using iText.Kernel.Geom;
using iText.Kernel.Pdf;

namespace SimpleSign.Benchmarks;

/// <summary>
/// Shared helper for building minimal valid PDFs across benchmark classes.
/// Uses iText7 to guarantee a well-formed PDF that all libraries can consume.
/// </summary>
internal static class PdfHelper
{
    public static byte[] BuildMinimalPdf()
    {
        using var ms = new MemoryStream();
        using (var writer = new PdfWriter(ms))
        using (var doc = new PdfDocument(writer))
        {
            doc.AddNewPage(PageSize.A4);
        }

        return ms.ToArray();
    }
}

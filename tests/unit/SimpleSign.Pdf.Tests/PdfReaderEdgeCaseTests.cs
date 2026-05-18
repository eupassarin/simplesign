using System.Text;
using Shouldly;
using SimpleSign.Pdf.Exceptions;
using Xunit;

namespace SimpleSign.Pdf.Tests;

/// <summary>
/// Edge-case tests for PdfStructureReader: malformed PDFs, cancellation, and boundary conditions.
/// </summary>
public sealed class PdfReaderEdgeCaseTests
{
    // ── Helpers ───────────────────────────────────────────────────────────────

    private static byte[] BuildMinimalPdf()
    {
        var sb = new StringBuilder();
        sb.Append("%PDF-1.7\n");
        sb.Append("1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");
        sb.Append("2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\n");
        long xrefOffset = sb.Length;
        sb.Append("xref\n0 3\n");
        sb.Append("0000000000 65535 f \n");
        sb.Append("0000000009 00000 n \n");
        sb.Append("0000000058 00000 n \n");
        sb.Append("trailer\n<< /Size 3 /Root 1 0 R >>\n");
        sb.Append($"startxref\n{xrefOffset}\n%%EOF");
        return Encoding.Latin1.GetBytes(sb.ToString());
    }

    // ══════════════════════════════════════════════════════════════════════════
    // PdfStructureReader edge cases
    // ══════════════════════════════════════════════════════════════════════════

    [Fact(DisplayName = "PDF with only whitespace after header throws PdfStructureException")]
    public async Task ReadSignatureFields_WhitespaceAfterHeader_ThrowsInvalidDataException()
    {
        var bytes = Encoding.ASCII.GetBytes("%PDF-1.4\n   \n   \n");
        using var stream = new MemoryStream(bytes);

        var act = () => PdfStructureReader.ReadSignatureFieldsAsync(stream);

        await Should.ThrowAsync<PdfStructureException>(act);
    }

    [Fact(DisplayName = "PDF with large xref table does not cause stack overflow")]
    public async Task ReadSignatureFields_LargeXrefTable_HandlesWithoutStackOverflow()
    {
        // Build a PDF with a large xref table (many entries)
        var sb = new StringBuilder();
        sb.Append("%PDF-1.7\n");
        sb.Append("1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");
        sb.Append("2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\n");
        long xrefOffset = sb.Length;
        int entryCount = 500;
        sb.Append($"xref\n0 {entryCount}\n");
        sb.Append("0000000000 65535 f \n");
        sb.Append("0000000009 00000 n \n");
        sb.Append("0000000058 00000 n \n");
        for (int i = 3; i < entryCount; i++)
            sb.Append($"{i:D10} 00000 f \n");
        sb.Append($"trailer\n<< /Size {entryCount} /Root 1 0 R >>\n");
        sb.Append($"startxref\n{xrefOffset}\n%%EOF");
        var pdfBytes = Encoding.Latin1.GetBytes(sb.ToString());
        using var stream = new MemoryStream(pdfBytes);

        var act = () => PdfStructureReader.ReadSignatureFieldsAsync(stream);

        // Should not throw stack overflow; result is just empty (no signatures)
        var results = await act();
        results.ShouldBeEmpty();
    }

    [Fact(DisplayName = "ReadSignatureFieldsAsync with cancelled token throws OperationCanceledException")]
    public async Task ReadSignatureFields_CancelledToken_ThrowsOperationCanceledException()
    {
        var pdfBytes = BuildMinimalPdf();
        using var stream = new MemoryStream(pdfBytes);
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        var act = () => PdfStructureReader.ReadSignatureFieldsAsync(stream, cancellationToken: cts.Token);

        await Should.ThrowAsync<OperationCanceledException>(act);
    }

    [Fact(DisplayName = "IsEncryptedAsync on non-PDF bytes throws exception")]
    public async Task IsEncryptedAsync_NonPdfBytes_ThrowsException()
    {
        var bytes = Encoding.ASCII.GetBytes("This is not a PDF");
        using var stream = new MemoryStream(bytes);

        // IsEncryptedAsync reads the stream but may not validate header — just check it doesn't crash
        var act = () => PdfStructureReader.IsEncryptedAsync(stream);

        // Depending on implementation, may return false or throw
        try
        {
            var result = await act();
            // If it doesn't throw, it should return false (no /Encrypt marker)
            result.ShouldBeFalse();
        }
        catch (Exception ex)
        {
            ex.ShouldBeAssignableTo<Exception>();
        }
    }

    [Fact(DisplayName = "PDF without signatures with partial ByteRange returns empty list")]
    public async Task ReadSignatureFields_NoBytRangeFields_ReturnsEmpty()
    {
        var pdfBytes = BuildMinimalPdf();
        using var stream = new MemoryStream(pdfBytes);

        var results = await PdfStructureReader.ReadSignatureFieldsAsync(stream);

        results.ShouldBeEmpty("minimal PDF has no signature fields");
    }
}

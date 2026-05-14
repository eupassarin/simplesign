using System.Text;
using FluentAssertions;
using SimpleSign.PAdES.Signing;
using SimpleSign.Pdf;
using Xunit;

namespace SimpleSign.PAdES.Tests.Signing;

public sealed class PdfSignatureWriterTests
{
    // ── Minimal PDF builder ────────────────────────────────────────────────────

    /// <summary>
    /// Builds a minimal valid PDF with a catalog, pages dict, and one page object.
    /// The xref offsets are approximate but structurally valid enough for the writer.
    /// </summary>
    private static byte[] BuildMinimalPdf()
    {
        var sb = new StringBuilder();
        sb.Append("%PDF-1.7\n");

        int obj1Offset = sb.Length;
        sb.Append("1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");

        int obj2Offset = sb.Length;
        sb.Append("2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n");

        int obj3Offset = sb.Length;
        sb.Append("3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n");

        long xrefOffset = sb.Length;
        sb.Append("xref\n");
        sb.Append("0 4\n");
        sb.Append("0000000000 65535 f \n");
        sb.Append($"{obj1Offset:D10} 00000 n \n");
        sb.Append($"{obj2Offset:D10} 00000 n \n");
        sb.Append($"{obj3Offset:D10} 00000 n \n");
        sb.Append("trailer\n<< /Size 4 /Root 1 0 R >>\n");
        sb.Append($"startxref\n{xrefOffset}\n%%EOF\n");

        return Encoding.Latin1.GetBytes(sb.ToString());
    }

    private static SignatureFieldOptions DefaultOptions() => new()
    {
        FieldName = "Sig1",
        SignerName = "Test Signer",
        ContentsReservedBytes = 1024,
    };

    // ── PrepareAsync tests ─────────────────────────────────────────────────────

    [Fact(DisplayName = "PrepareAsync with minimal PDF returns valid ByteRange")]
    public async Task PrepareAsync_WithMinimalPdf_ReturnsValidByteRange()
    {
        byte[] pdfBytes = BuildMinimalPdf();
        using var input = new MemoryStream(pdfBytes);
        using var output = new MemoryStream();
        var writer = new PdfSignatureWriter();

        var result = await PdfSignatureWriter.PrepareAsync(input, output, DefaultOptions());

        result.ByteRange.Should().NotBeNull();
        result.ByteRange.IsValid.Should().BeTrue();
        result.ByteRange.Offset1.Should().Be(0);
        result.ByteRange.Length1.Should().BeGreaterThan(0);
        result.ByteRange.Offset2.Should().BeGreaterThan(result.ByteRange.Length1);
        result.ByteRange.Length2.Should().BeGreaterThan(0);
        result.ContentsHexOffset.Should().Be(result.ByteRange.Length1 + 1);
        result.ContentsReservedBytes.Should().Be(1024);
    }

    [Fact(DisplayName = "Output contains original PDF and incremental update")]
    public async Task PrepareAsync_OutputContainsOriginalPdfAndIncrementalUpdate()
    {
        byte[] pdfBytes = BuildMinimalPdf();
        using var input = new MemoryStream(pdfBytes);
        using var output = new MemoryStream();
        var writer = new PdfSignatureWriter();

        await PdfSignatureWriter.PrepareAsync(input, output, DefaultOptions());

        byte[] outputBytes = output.ToArray();

        // Output must start with the original PDF content
        outputBytes.AsSpan(0, pdfBytes.Length).ToArray().Should().BeEquivalentTo(pdfBytes);

        // Output must be larger than input (incremental update was appended)
        outputBytes.Length.Should().BeGreaterThan(pdfBytes.Length);

        string outputText = Encoding.Latin1.GetString(outputBytes);

        // Must contain signature dictionary structures
        outputText.Should().Contain("/Type /Sig");
        outputText.Should().Contain("/Filter /Adobe.PPKLite");
        outputText.Should().Contain("/SubFilter /ETSI.CAdES.detached");
        outputText.Should().Contain("/ByteRange");
        outputText.Should().Contain("/FT /Sig");
        outputText.Should().Contain("/SigFlags 3");
        outputText.Should().Contain("xref");
        outputText.Should().Contain("%%EOF");
    }

    [Fact(DisplayName = "SubFilter ETSI.CAdES.detached is used correctly")]
    public async Task PrepareAsync_WithEtsiSubFilter_UsesCorrectSubFilterName()
    {
        byte[] pdfBytes = BuildMinimalPdf();
        using var input = new MemoryStream(pdfBytes);
        using var output = new MemoryStream();
        var writer = new PdfSignatureWriter();
        var options = new SignatureFieldOptions
        {
            FieldName = "Sig1",
            ContentsReservedBytes = 1024,
            SubFilter = PdfSignatureSubFilter.EtsiCadesDetached,
        };

        await PdfSignatureWriter.PrepareAsync(input, output, options);

        string outputText = Encoding.Latin1.GetString(output.ToArray());
        outputText.Should().Contain("/SubFilter /ETSI.CAdES.detached");
    }

    [Fact(DisplayName = "Throws exception for non-seekable stream")]
    public async Task PrepareAsync_ThrowsOnNonSeekableInput()
    {
        using var input = new NonSeekableStream();
        using var output = new MemoryStream();
        var writer = new PdfSignatureWriter();

        var act = () => PdfSignatureWriter.PrepareAsync(input, output, DefaultOptions());

        await act.Should().ThrowAsync<ArgumentException>().WithMessage("*seekable*");
    }

    [Fact(DisplayName = "Throws exception for null arguments in PrepareAsync")]
    public async Task PrepareAsync_ThrowsOnNullArguments()
    {
        var writer = new PdfSignatureWriter();
        using var stream = new MemoryStream();

        await Assert.ThrowsAsync<ArgumentNullException>(() => PdfSignatureWriter.PrepareAsync(null!, stream, DefaultOptions()));
        await Assert.ThrowsAsync<ArgumentNullException>(() => PdfSignatureWriter.PrepareAsync(stream, null!, DefaultOptions()));
        await Assert.ThrowsAsync<ArgumentNullException>(() => PdfSignatureWriter.PrepareAsync(stream, stream, null!));
    }

    // ── FinalizeAsync tests ────────────────────────────────────────────────────

    [Fact(DisplayName = "FinalizeAsync writes CMS hex at correct offset")]
    public async Task FinalizeAsync_WritesCmsHexAtCorrectOffset()
    {
        byte[] pdfBytes = BuildMinimalPdf();
        using var input = new MemoryStream(pdfBytes);
        using var output = new MemoryStream();
        var writer = new PdfSignatureWriter();

        var result = await PdfSignatureWriter.PrepareAsync(input, output, DefaultOptions());

        byte[] cmsBytes = new byte[] { 0xCA, 0xFE, 0xBA, 0xBE };
        await PdfSignatureWriter.FinalizeAsync(output, result, cmsBytes);

        output.Seek(result.ContentsHexOffset, SeekOrigin.Begin);
        byte[] hexBuf = new byte[result.ContentsReservedBytes * 2];
        int read = await output.ReadAsync(hexBuf);
        string hexStr = Encoding.Latin1.GetString(hexBuf, 0, read);

        // The hex should start with the CMS bytes in uppercase hex
        hexStr.Should().StartWith("CAFEBABE");

        // The rest should be zero-padded
        hexStr.Substring(8).Should().MatchRegex("^0+$");
    }

    [Fact(DisplayName = "Throws exception when CMS exceeds reserved space")]
    public async Task FinalizeAsync_ThrowsWhenCmsExceedsReservedSpace()
    {
        byte[] pdfBytes = BuildMinimalPdf();
        using var input = new MemoryStream(pdfBytes);
        using var output = new MemoryStream();
        var writer = new PdfSignatureWriter();
        var options = new SignatureFieldOptions
        {
            FieldName = "Sig1",
            ContentsReservedBytes = 8, // Very small
        };

        var result = await PdfSignatureWriter.PrepareAsync(input, output, options);
        byte[] oversizedCms = new byte[16]; // Larger than reserved

        var act = () => PdfSignatureWriter.FinalizeAsync(output, result, oversizedCms);

        await act.Should().ThrowAsync<ArgumentException>().WithMessage("*exceed*");
    }

    [Fact(DisplayName = "Throws exception for null arguments in FinalizeAsync")]
    public async Task FinalizeAsync_ThrowsOnNullArguments()
    {
        using var stream = new MemoryStream();
        var prepareResult = new PdfSignaturePrepareResult();

        await Assert.ThrowsAsync<ArgumentNullException>(() =>
            PdfSignatureWriter.FinalizeAsync(null!, prepareResult, new byte[1]));
        await Assert.ThrowsAsync<ArgumentNullException>(() =>
            PdfSignatureWriter.FinalizeAsync(stream, null!, new byte[1]));
        await Assert.ThrowsAsync<ArgumentNullException>(() =>
            PdfSignatureWriter.FinalizeAsync(stream, prepareResult, null!));
    }

    // ── Round-trip test ────────────────────────────────────────────────────────

    [Fact(DisplayName = "Prepare and Finalize produce readable signature")]
    public async Task RoundTrip_PrepareAndFinalize_ProducesReadableSignature()
    {
        byte[] pdfBytes = BuildMinimalPdf();
        using var input = new MemoryStream(pdfBytes);
        using var output = new MemoryStream();
        var writer = new PdfSignatureWriter();

        var prepareResult = await PdfSignatureWriter.PrepareAsync(input, output, DefaultOptions());

        // Write dummy CMS bytes
        byte[] dummyCms = new byte[64];
        for (int i = 0; i < dummyCms.Length; i++)
            dummyCms[i] = (byte)(i & 0xFF);
        await PdfSignatureWriter.FinalizeAsync(output, prepareResult, dummyCms);

        // Verify PdfStructureReader can find the signature
        output.Seek(0, SeekOrigin.Begin);
        var fields = await PdfStructureReader.ReadSignatureFieldsAsync(output);

        fields.Should().NotBeNullOrEmpty();
        fields.Should().Contain(f => f.ByteRange != null && f.ByteRange.IsValid);
    }

    [Fact(DisplayName = "ByteRange covers the entire file")]
    public async Task RoundTrip_ByteRangeCoverageIsComplete()
    {
        byte[] pdfBytes = BuildMinimalPdf();
        using var input = new MemoryStream(pdfBytes);
        using var output = new MemoryStream();
        var writer = new PdfSignatureWriter();

        var result = await PdfSignatureWriter.PrepareAsync(input, output, DefaultOptions());

        byte[] dummyCms = new byte[] { 0x01, 0x02, 0x03 };
        await PdfSignatureWriter.FinalizeAsync(output, result, dummyCms);

        long totalLength = output.Length;
        var br = result.ByteRange;

        // ByteRange should cover the entire file except the /Contents hex value
        (br.Length1 + br.Length2 + (br.Offset2 - br.Length1)).Should().Be(totalLength);

        // Offset2 + Length2 should equal total file length
        (br.Offset2 + br.Length2).Should().Be(totalLength);
    }

    [Fact(DisplayName = "Includes Reason, Location and Name in output")]
    public async Task PrepareAsync_WithReasonAndLocation_IncludesThemInOutput()
    {
        byte[] pdfBytes = BuildMinimalPdf();
        using var input = new MemoryStream(pdfBytes);
        using var output = new MemoryStream();
        var writer = new PdfSignatureWriter();
        var options = new SignatureFieldOptions
        {
            FieldName = "Sig1",
            SignerName = "Alice",
            Reason = "Approval",
            Location = "São Paulo",
            ContentsReservedBytes = 1024,
        };

        await PdfSignatureWriter.PrepareAsync(input, output, options);

        string text = Encoding.Latin1.GetString(output.ToArray());
        text.Should().Contain("/Reason (Approval)");
        text.Should().Contain("/Location (");
        text.Should().Contain("/Name (Alice)");
    }

    [Fact(DisplayName = "PrepareAsync preserves existing fields from AcroForm in ObjStm")]
    public async Task PrepareAsync_AcroFormInObjStm_PreservesExistingFields()
    {
        // Build a PDF where the AcroForm (object 5) is stored in a compressed ObjStm.
        // This simulates PDFs from iText, Adobe, and other generators that use object streams.
        byte[] pdfBytes = BuildPdfWithAcroFormInObjStm();
        using var input = new MemoryStream(pdfBytes);
        using var output = new MemoryStream();

        await PdfSignatureWriter.PrepareAsync(input, output, DefaultOptions());

        string outputText = Encoding.Latin1.GetString(output.ToArray());

        // The new AcroForm should contain the existing field references plus the new one
        outputText.Should().Contain("10 0 R", "existing field should be preserved");
        outputText.Should().Contain("20 0 R", "existing field should be preserved");
        outputText.Should().Contain("/SigFlags 3");
    }

    /// <summary>
    /// Builds a PDF where the AcroForm (object 5) is stored in a compressed Object Stream,
    /// reproducing the structure used by iText and other modern PDF generators.
    /// </summary>
    private static byte[] BuildPdfWithAcroFormInObjStm()
    {
        var sb = new StringBuilder();
        sb.Append("%PDF-1.7\n");

        // Object 1: Catalog referencing AcroForm as object 5
        int obj1Offset = sb.Length;
        sb.Append("1 0 obj\n<< /Type /Catalog /Pages 2 0 R /AcroForm 5 0 R >>\nendobj\n");

        // Object 2: Pages
        int obj2Offset = sb.Length;
        sb.Append("2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n");

        // Object 3: Page
        int obj3Offset = sb.Length;
        sb.Append("3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n");

        // Object 4: ObjStm containing objects 5 (AcroForm) and 6 (dummy)
        string acroFormData = "<< /Type /AcroForm /Fields [10 0 R 20 0 R] /SigFlags 3 >>";
        string dummyData = "<< /Type /Font /BaseFont /Helvetica >>";
        string objStmHeader = $"5 0 6 {acroFormData.Length}\n";
        string uncompressed = objStmHeader + acroFormData + dummyData;
        byte[] uncompressedBytes = Encoding.Latin1.GetBytes(uncompressed);

        // Compress with zlib
        byte[] compressed;
        using (var ms = new MemoryStream())
        {
            ms.WriteByte(0x78);
            ms.WriteByte(0x01);
            using (var deflate = new System.IO.Compression.DeflateStream(ms, System.IO.Compression.CompressionLevel.Fastest, leaveOpen: true))
            {
                deflate.Write(uncompressedBytes);
            }

            compressed = ms.ToArray();
        }

        int obj4Offset = sb.Length;
        sb.Append($"4 0 obj\n<< /Type /ObjStm /N 2 /First {objStmHeader.Length} /Filter /FlateDecode /Length {compressed.Length} >>\nstream\n");
        int streamInsertPos = Encoding.Latin1.GetByteCount(sb.ToString());

        string afterStream = "\nendstream\nendobj\n";

        // Build xref
        int xrefOffset = streamInsertPos + compressed.Length + Encoding.Latin1.GetByteCount(afterStream);
        var xrefSb = new StringBuilder();
        xrefSb.Append("xref\n0 5\n");
        xrefSb.Append("0000000000 65535 f \n");
        xrefSb.Append($"{obj1Offset:D10} 00000 n \n");
        xrefSb.Append($"{obj2Offset:D10} 00000 n \n");
        xrefSb.Append($"{obj3Offset:D10} 00000 n \n");
        xrefSb.Append($"{obj4Offset:D10} 00000 n \n");
        xrefSb.Append("trailer\n<< /Size 7 /Root 1 0 R >>\n");
        xrefSb.Append($"startxref\n{xrefOffset}\n%%EOF\n");

        // Assemble final PDF
        byte[] beforeStream = Encoding.Latin1.GetBytes(sb.ToString());
        byte[] afterStreamBytes = Encoding.Latin1.GetBytes(afterStream);
        byte[] xrefBytes = Encoding.Latin1.GetBytes(xrefSb.ToString());

        var result = new byte[beforeStream.Length + compressed.Length + afterStreamBytes.Length + xrefBytes.Length];
        beforeStream.CopyTo(result, 0);
        compressed.CopyTo(result, beforeStream.Length);
        afterStreamBytes.CopyTo(result, beforeStream.Length + compressed.Length);
        xrefBytes.CopyTo(result, beforeStream.Length + compressed.Length + afterStreamBytes.Length);

        return result;
    }

    // ── Helper: non-seekable stream ────────────────────────────────────────────

    private sealed class NonSeekableStream : MemoryStream
    {
        public override bool CanSeek => false;
    }
}

using System.Text;
using Shouldly;
using SimpleSign.PAdES.Signing;
using SimpleSign.PAdES.Pdf;
using SimpleSign.TestHelpers;
using SimpleSign.PAdES.Tests.Pdf.Parity;
using Xunit;

namespace SimpleSign.PAdES.Tests.Signing;

[Trait("Category", "Unit")]
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

        result.ByteRange.ShouldNotBeNull();
        result.ByteRange.IsValid.ShouldBeTrue();
        result.ByteRange.Offset1.ShouldBe(0);
        result.ByteRange.Length1.ShouldBeGreaterThan(0);
        result.ByteRange.Offset2.ShouldBeGreaterThan(result.ByteRange.Length1);
        result.ByteRange.Length2.ShouldBeGreaterThan(0);
        result.ContentsHexOffset.ShouldBe(result.ByteRange.Length1 + 1);
        result.ContentsReservedBytes.ShouldBe(1024);
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
        outputBytes.AsSpan(0, pdfBytes.Length).ToArray().ShouldBe(pdfBytes);

        // Output must be larger than input (incremental update was appended)
        outputBytes.Length.ShouldBeGreaterThan(pdfBytes.Length);

        string outputText = Encoding.Latin1.GetString(outputBytes);

        // Must contain signature dictionary structures
        outputText.ShouldContain("/Type /Sig");
        outputText.ShouldContain("/Filter /Adobe.PPKLite");
        outputText.ShouldContain("/SubFilter /ETSI.CAdES.detached");
        outputText.ShouldContain("/ByteRange");
        outputText.ShouldContain("/FT /Sig");
        outputText.ShouldContain("/SigFlags 3");
        outputText.ShouldContain("xref");
        outputText.ShouldContain("%%EOF");
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
        outputText.ShouldContain("/SubFilter /ETSI.CAdES.detached");
    }

    [Fact(DisplayName = "Throws exception for non-seekable stream")]
    public async Task PrepareAsync_ThrowsOnNonSeekableInput()
    {
        using var input = new NonSeekableStream();
        using var output = new MemoryStream();
        var writer = new PdfSignatureWriter();

        var act = () => PdfSignatureWriter.PrepareAsync(input, output, DefaultOptions());

        (await Should.ThrowAsync<ArgumentException>(act)).Message.ShouldContain("seekable");
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

        byte[] cmsBytes = [0xCA, 0xFE, 0xBA, 0xBE];
        await PdfSignatureWriter.FinalizeAsync(output, result, cmsBytes);

        output.Seek(result.ContentsHexOffset, SeekOrigin.Begin);
        byte[] hexBuf = new byte[result.ContentsReservedBytes * 2];
        int read = await output.ReadAsync(hexBuf);
        string hexStr = Encoding.Latin1.GetString(hexBuf, 0, read);

        // The hex should start with the CMS bytes in uppercase hex
        hexStr.ShouldStartWith("CAFEBABE");

        // The rest should be zero-padded
        hexStr.Substring(8).ShouldMatch("^0+$");
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

        (await Should.ThrowAsync<ArgumentException>(act)).Message.ShouldContain("exceed");
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

        fields.ShouldNotBeNull();
        fields.ShouldNotBeEmpty();
        fields.ShouldContain(f => f.ByteRange != null && f.ByteRange.IsValid);
    }

    [Fact(DisplayName = "ByteRange covers the entire file")]
    public async Task RoundTrip_ByteRangeCoverageIsComplete()
    {
        byte[] pdfBytes = BuildMinimalPdf();
        using var input = new MemoryStream(pdfBytes);
        using var output = new MemoryStream();
        var writer = new PdfSignatureWriter();

        var result = await PdfSignatureWriter.PrepareAsync(input, output, DefaultOptions());

        byte[] dummyCms = [0x01, 0x02, 0x03];
        await PdfSignatureWriter.FinalizeAsync(output, result, dummyCms);

        long totalLength = output.Length;
        var br = result.ByteRange;

        // ByteRange should cover the entire file except the /Contents hex value
        (br.Length1 + br.Length2 + (br.Offset2 - br.Length1)).ShouldBe(totalLength);

        // Offset2 + Length2 should equal total file length
        (br.Offset2 + br.Length2).ShouldBe(totalLength);
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
        text.ShouldContain("/Reason (Approval)");
        text.ShouldContain("/Location (");
        text.ShouldContain("/Name (Alice)");
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
        outputText.ShouldContain("10 0 R");
        outputText.ShouldContain("20 0 R");
        outputText.ShouldContain("/SigFlags 3");
    }

    [Fact(DisplayName = "PrepareAsync auto-positions a visible signature on a page stored in an object stream")]
    public async Task PrepareAsync_AutoAppearanceOnPageInObjStm_AddsWidgetToPage()
    {
        // Found by qpdf interop (tests/integration/SimpleSign.Interop.Tests): the page dictionary has no bytes of its
        // own to slice, and auto-positioning threw ArgumentOutOfRangeException.
        byte[] pdfBytes = BuildPdfWithPageInObjStm();
        using var certificate = TestCertificateFactory.CreateSelfSignedCert("CN=ObjStm Page");

        byte[] signed = await PadesSigner.Document(pdfBytes).WithCertificate(certificate)
            .WithAppearance(SignatureAppearance.Auto()).SignAsync();

        string appended = Encoding.Latin1.GetString(signed, pdfBytes.Length, signed.Length - pdfBytes.Length);
        appended.ShouldContain("3 0 obj");
        appended.ShouldContain("/Annots");
        appended.ShouldContain("/AP");
    }

    /// <summary>
    /// A PDF whose /Pages (object 2) and only /Page (object 3, 612 × 792) are stored in a compressed Object Stream, as
    /// qpdf's --object-streams=generate writes them.
    /// </summary>
    private static byte[] BuildPdfWithPageInObjStm()
    {
        // A cross-reference stream lists the compressed objects (a table cannot).
        return new PdfFileBuilder()
            .Object(1, "<< /Type /Catalog /Pages 2 0 R >>")
            .Compressed(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
            .Compressed(3, "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << >> >>")
            .EndRevision(XrefStyle.Stream, new RevisionOptions { ObjectStreamNumber = 4, XrefStreamNumber = 5 })
            .ToArray();
    }

    /// <summary>
    /// Builds a PDF where the AcroForm (object 5) is stored in a compressed Object Stream,
    /// reproducing the structure used by iText and other modern PDF generators.
    /// </summary>
    private static byte[] BuildPdfWithAcroFormInObjStm()
    {
        // A cross-reference stream lists the compressed objects (a table cannot).
        return new PdfFileBuilder()
            .Object(1, "<< /Type /Catalog /Pages 2 0 R /AcroForm 5 0 R >>")
            .Object(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
            .Object(3, "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>")
            .Object(10, "<< /FT /Tx /T (Name) >>")
            .Object(20, "<< /FT /Tx /T (Email) >>")
            .Compressed(5, "<< /Type /AcroForm /Fields [10 0 R 20 0 R] /SigFlags 3 >>")
            .Compressed(6, "<< /Type /Font /BaseFont /Helvetica >>")
            .EndRevision(XrefStyle.Stream, new RevisionOptions { ObjectStreamNumber = 4, XrefStreamNumber = 7 })
            .ToArray();
    }

    [Fact(DisplayName = "PrepareAsync preserves AcroForm keys whose values contain >>")]
    public async Task PrepareAsync_AcroFormDaWithAngleBrackets_PreservesExtraKeys()
    {
        byte[] pdfBytes = BuildPdfWithAcroFormDaWithAngles();
        using var input = new MemoryStream(pdfBytes);
        using var output = new MemoryStream();

        await PdfSignatureWriter.PrepareAsync(input, output, DefaultOptions());

        string outputText = Encoding.Latin1.GetString(output.ToArray());
        outputText.ShouldContain("/DA (x >> y)");
        outputText.ShouldContain("6 0 R");
    }

    /// <summary>
    /// Builds a PDF whose AcroForm (object 5) has a /DA literal string containing
    /// dictionary-like delimiters (>>) that must not break key extraction.
    /// </summary>
    private static byte[] BuildPdfWithAcroFormDaWithAngles()
    {
        var sb = new StringBuilder();
        sb.Append("%PDF-1.7\n");
        sb.Append("1 0 obj\n<< /Type /Catalog /Pages 2 0 R /AcroForm 5 0 R >>\nendobj\n");
        sb.Append("2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n");
        sb.Append("3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n");
        sb.Append("4 0 obj\n<< /Type /Font >>\nendobj\n");
        sb.Append("5 0 obj\n<< /Fields [6 0 R] /SigFlags 3 /DA (x >> y) >>\nendobj\n");
        sb.Append("6 0 obj\n<< /Type /Annot /Subtype /Widget /FT /Sig /T (Existing) /Rect [0 0 0 0] >>\nendobj\n");
        sb.Append("xref\n0 7\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \n0000000115 00000 n \n0000000173 00000 n \n0000000205 00000 n \n0000000270 00000 n \ntrailer\n<< /Size 7 /Root 1 0 R >>\nstartxref\n350\n%%EOF\n");
        return Encoding.Latin1.GetBytes(sb.ToString());
    }

    [Fact(DisplayName = "Page with compressed indirect /Annots keeps existing annotations")]
    public async Task PrepareAsync_CompressedIndirectAnnots_PreservesExistingAnnotations()
    {
        byte[] pdfBytes = BuildPdfWithCompressedIndirectAnnots();
        using var input = new MemoryStream(pdfBytes);
        using var output = new MemoryStream();

        await PdfSignatureWriter.PrepareAsync(input, output, DefaultOptions());

        string outputText = Encoding.Latin1.GetString(output.ToArray());
        outputText.ShouldMatch(@"/Annots \[11 0 R \d+ 0 R\]");
    }

    /// <summary>
    /// Builds a PDF whose page /Annots is an indirect reference to an array object
    /// (object 10) stored inside a compressed Object Stream (object 4), reproducing
    /// the structure used by iText/Adobe for compact PDFs.
    /// </summary>
    private static byte[] BuildPdfWithCompressedIndirectAnnots()
    {
        // A cross-reference stream lists the compressed objects (a table cannot).
        return new PdfFileBuilder()
            .Object(1, "<< /Type /Catalog /Pages 2 0 R >>")
            .Object(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
            .Object(3, "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Annots 10 0 R >>")
            .Compressed(10, "[11 0 R]")
            .Compressed(11, "<< /Type /Annot >>")
            .EndRevision(XrefStyle.Stream, new RevisionOptions { ObjectStreamNumber = 4, XrefStreamNumber = 5 })
            .ToArray();
    }

    // ── Helper: non-seekable stream ────────────────────────────────────────────

    [Theory(DisplayName = "Certifying into an existing field of an inline AcroForm keeps the form")]
    [InlineData(CertificationLevel.NoChanges)]
    [InlineData(CertificationLevel.FormFilling)]
    [InlineData(CertificationLevel.FormFillingAndAnnotations)]
    public async Task SignAsync_ExistingFieldInlineAcroFormCertified_KeepsTheFormAndTheFieldName(CertificationLevel level)
    {
        var objects = new[]
        {
            "<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [4 0 R] /SigFlags 3 >> >>",
            "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Annots [4 0 R] >>",
            "<< /Type /Annot /Subtype /Widget /FT /Sig /T (Assinatura) /P 3 0 R /Rect [72 300 292 370] /F 4 >>",
        };
        var sb = new StringBuilder("%PDF-1.7\n");
        var offsets = new List<int>();
        for (int i = 0; i < objects.Length; i++)
        {
            offsets.Add(sb.Length);
            sb.Append(System.Globalization.CultureInfo.InvariantCulture, $"{i + 1} 0 obj\n{objects[i]}\nendobj\n");
        }

        int xref = sb.Length;
        sb.Append("xref\n0 5\n0000000000 65535 f \n");
        foreach (int offset in offsets)
        {
            sb.Append(System.Globalization.CultureInfo.InvariantCulture, $"{offset:D10} 00000 n \n");
        }

        sb.Append(System.Globalization.CultureInfo.InvariantCulture, $"trailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n");
        using var cert = TestCertificateFactory.CreateSelfSignedCert();

        byte[] signed = await PadesSigner.Document(Encoding.Latin1.GetBytes(sb.ToString())).WithCertificate(cert)
            .WithExistingField("Assinatura").AsCertification(level).SignAsync();

        var document = SimpleSign.PAdES.Pdf.Model.PdfDocument.Open(signed);
        document.View().AcroForm.ShouldNotBeNull();
        document.View().Fields.ShouldHaveSingleItem().FullName.ShouldBe("Assinatura");
        using var stream = new MemoryStream(signed);
        var field = (await PdfStructureReader.ReadSignatureFieldsAsync(stream)).ShouldHaveSingleItem();
        field.FieldName.ShouldBe("Assinatura");
        (await PdfStructureReader.GetDocMdpPermissionLevelAsync(stream)).ShouldBe((int)level);
    }

    private sealed class NonSeekableStream : MemoryStream
    {
        public override bool CanSeek => false;
    }
}

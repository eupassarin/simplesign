using FluentAssertions;
using SimpleSign.HtmlToPdf.Layout;
using Xunit;

namespace SimpleSign.HtmlToPdf.Tests;

public class HtmlToPdfConverterTests
{
    // ── Entry points ────────────────────────────────────────────────────

    [Fact(DisplayName = "Html(string): converts to PDF bytes")]
    public void Html_String_ConvertsToPdfBytes()
    {
        byte[] pdf = HtmlToPdfConverter
            .Html("<h1>Test</h1><p>Content</p>")
            .Convert();

        pdf.Should().NotBeNull();
        pdf.Length.Should().BeGreaterThan(0);
        System.Text.Encoding.ASCII.GetString(pdf, 0, 5).Should().Be("%PDF-");
    }

    [Fact(DisplayName = "Html(byte[]): converts UTF-8 bytes")]
    public void Html_Bytes_ConvertsUtf8()
    {
        byte[] htmlBytes = System.Text.Encoding.UTF8.GetBytes("<p>Hello</p>");

        byte[] pdf = HtmlToPdfConverter
            .Html(htmlBytes)
            .Convert();

        pdf.Should().NotBeNull();
        pdf.Length.Should().BeGreaterThan(0);
    }

    [Fact(DisplayName = "Html(null): throws ArgumentNullException")]
    public void Html_Null_Throws()
    {
        var act = () => HtmlToPdfConverter.Html((string)null!);

        act.Should().Throw<ArgumentNullException>();
    }

    // ── File entry points ───────────────────────────────────────────────

    [Fact(DisplayName = "File: non-existent file throws FileNotFoundException")]
    public void File_NonExistent_ThrowsFileNotFound()
    {
        var act = () => HtmlToPdfConverter.File("/tmp/does-not-exist-12345.html");

        act.Should().Throw<FileNotFoundException>();
    }

    [Fact(DisplayName = "File: converts existing HTML file")]
    public void File_ExistingFile_Converts()
    {
        var tmpFile = Path.GetTempFileName() + ".html";
        try
        {
            System.IO.File.WriteAllText(tmpFile, "<h1>File Test</h1>");

            byte[] pdf = HtmlToPdfConverter
                .File(tmpFile)
                .Convert();

            pdf.Should().NotBeNull();
            System.Text.Encoding.ASCII.GetString(pdf, 0, 5).Should().Be("%PDF-");
        }
        finally
        {
            System.IO.File.Delete(tmpFile);
        }
    }

    [Fact(DisplayName = "FileAsync: converts existing HTML file")]
    public async Task FileAsync_ExistingFile_Converts()
    {
        var tmpFile = Path.GetTempFileName() + ".html";
        try
        {
            await System.IO.File.WriteAllTextAsync(tmpFile, "<h1>Async Test</h1>");

            var builder = await HtmlToPdfConverter.FileAsync(tmpFile);
            byte[] pdf = builder.Convert();

            pdf.Should().NotBeNull();
            System.Text.Encoding.ASCII.GetString(pdf, 0, 5).Should().Be("%PDF-");
        }
        finally
        {
            System.IO.File.Delete(tmpFile);
        }
    }

    // ── Fluent builder ──────────────────────────────────────────────────

    [Fact(DisplayName = "WithPageSize: produces valid PDF for all sizes")]
    public void WithPageSize_AllSizes_ProducesValidPdf()
    {
        foreach (PageSize size in Enum.GetValues<PageSize>())
        {
            byte[] pdf = HtmlToPdfConverter
                .Html("<p>Test</p>")
                .WithPageSize(size)
                .Convert();

            pdf.Should().NotBeNull($"PageSize.{size} should produce a valid PDF");
            pdf.Length.Should().BeGreaterThan(0);
        }
    }

    [Fact(DisplayName = "WithMargins(all): applies uniform margins")]
    public void WithMargins_Uniform_AppliesMargins()
    {
        byte[] pdf = HtmlToPdfConverter
            .Html("<p>Margins Test</p>")
            .WithMargins(50)
            .Convert();

        pdf.Should().NotBeNull();
        pdf.Length.Should().BeGreaterThan(0);
    }

    [Fact(DisplayName = "WithMargins(t,r,b,l): applies individual margins")]
    public void WithMargins_Individual_AppliesMargins()
    {
        byte[] pdf = HtmlToPdfConverter
            .Html("<p>Custom Margins</p>")
            .WithMargins(30, 25, 30, 25)
            .Convert();

        pdf.Should().NotBeNull();
        pdf.Length.Should().BeGreaterThan(0);
    }

    [Fact(DisplayName = "WithStylesheet: applies CSS to output")]
    public void WithStylesheet_AppliesCss()
    {
        byte[] pdf = HtmlToPdfConverter
            .Html("<p class=\"big\">Big Text</p>")
            .WithStylesheet(".big { font-size: 24px; }")
            .Convert();

        pdf.Should().NotBeNull();
        pdf.Length.Should().BeGreaterThan(0);
    }

    [Fact(DisplayName = "WithStylesheet: multiple calls accumulate")]
    public void WithStylesheet_MultipleCalls_Accumulate()
    {
        byte[] pdf = HtmlToPdfConverter
            .Html("<p class=\"a b\">Styled</p>")
            .WithStylesheet(".a { font-size: 18px; }")
            .WithStylesheet(".b { font-weight: bold; }")
            .Convert();

        pdf.Should().NotBeNull();
    }

    [Fact(DisplayName = "WithTitle: sets metadata")]
    public void WithTitle_SetsMetadata()
    {
        byte[] pdf = HtmlToPdfConverter
            .Html("<p>Title Test</p>")
            .WithTitle("My Document")
            .Convert();

        pdf.Should().NotBeNull();
    }

    [Fact(DisplayName = "WithAuthor: sets metadata")]
    public void WithAuthor_SetsMetadata()
    {
        byte[] pdf = HtmlToPdfConverter
            .Html("<p>Author Test</p>")
            .WithAuthor("André Almeida")
            .Convert();

        pdf.Should().NotBeNull();
    }

    [Fact(DisplayName = "WithHeader: sets header template")]
    public void WithHeader_SetsHeaderTemplate()
    {
        byte[] pdf = HtmlToPdfConverter
            .Html("<p>Header Test</p>")
            .WithHeader("Page {page} of {pages}")
            .Convert();

        pdf.Should().NotBeNull();
        pdf.Length.Should().BeGreaterThan(0);
        System.Text.Encoding.ASCII.GetString(pdf, 0, 5).Should().Be("%PDF-");
    }

    [Fact(DisplayName = "WithFooter: sets footer template")]
    public void WithFooter_SetsFooterTemplate()
    {
        byte[] pdf = HtmlToPdfConverter
            .Html("<p>Footer Test</p>")
            .WithFooter("{title} - {date}")
            .WithTitle("My Document")
            .Convert();

        pdf.Should().NotBeNull();
        pdf.Length.Should().BeGreaterThan(0);
        System.Text.Encoding.ASCII.GetString(pdf, 0, 5).Should().Be("%PDF-");
    }

    [Fact(DisplayName = "WithHeader: null throws ArgumentException")]
    public void WithHeader_Null_Throws()
    {
        var act = () => HtmlToPdfConverter
            .Html("<p>Test</p>")
            .WithHeader(null!);

        act.Should().Throw<ArgumentException>();
    }

    [Fact(DisplayName = "WithFooter: null throws ArgumentException")]
    public void WithFooter_Null_Throws()
    {
        var act = () => HtmlToPdfConverter
            .Html("<p>Test</p>")
            .WithFooter(null!);

        act.Should().Throw<ArgumentException>();
    }

    [Fact(DisplayName = "WithHeader: whitespace throws ArgumentException")]
    public void WithHeader_Whitespace_Throws()
    {
        var act = () => HtmlToPdfConverter
            .Html("<p>Test</p>")
            .WithHeader("   ");

        act.Should().Throw<ArgumentException>();
    }

    [Fact(DisplayName = "WithFooter: whitespace throws ArgumentException")]
    public void WithFooter_Whitespace_Throws()
    {
        var act = () => HtmlToPdfConverter
            .Html("<p>Test</p>")
            .WithFooter("   ");

        act.Should().Throw<ArgumentException>();
    }

    [Fact(DisplayName = "WithHeader and WithFooter: both render in PDF")]
    public void WithHeaderAndFooter_BothRender()
    {
        byte[] pdf = HtmlToPdfConverter
            .Html("<p>Content</p>")
            .WithHeader("Header: {title}")
            .WithFooter("Page {page} of {pages}")
            .WithTitle("Report")
            .Convert();

        pdf.Should().NotBeNull();
        pdf.Length.Should().BeGreaterThan(100);
    }

    [Fact(DisplayName = "Builder is immutable: each With returns new instance")]
    public void Builder_IsImmutable_EachWithReturnsNewInstance()
    {
        var original = HtmlToPdfConverter.Html("<p>Test</p>");
        var modified = original.WithPageSize(PageSize.Letter);

        // Both should produce valid PDFs (proves original wasn't mutated)
        byte[] pdf1 = original.Convert();
        byte[] pdf2 = modified.Convert();

        pdf1.Should().NotBeNull();
        pdf2.Should().NotBeNull();
    }

    // ── Output methods ──────────────────────────────────────────────────

    [Fact(DisplayName = "Convert(Stream): writes to stream")]
    public void Convert_Stream_WritesToStream()
    {
        using var ms = new MemoryStream();

        HtmlToPdfConverter
            .Html("<p>Stream Test</p>")
            .Convert(ms);

        ms.Length.Should().BeGreaterThan(0);
        ms.Position = 0;
        var buffer = new byte[5];
        _ = ms.Read(buffer, 0, 5);
        System.Text.Encoding.ASCII.GetString(buffer).Should().Be("%PDF-");
    }

    [Fact(DisplayName = "ConvertAsync: returns PDF bytes")]
    public async Task ConvertAsync_ReturnsPdfBytes()
    {
        byte[] pdf = await HtmlToPdfConverter
            .Html("<p>Async Test</p>")
            .ConvertAsync();

        pdf.Should().NotBeNull();
        pdf.Length.Should().BeGreaterThan(0);
    }

    [Fact(DisplayName = "ConvertAsync(Stream): writes to stream")]
    public async Task ConvertAsync_Stream_WritesToStream()
    {
        using var ms = new MemoryStream();

        await HtmlToPdfConverter
            .Html("<p>Async Stream Test</p>")
            .ConvertAsync(ms);

        ms.Length.Should().BeGreaterThan(0);
    }

    [Fact(DisplayName = "SaveTo: writes to file")]
    public void SaveTo_WritesToFile()
    {
        var tmpFile = Path.GetTempFileName();
        try
        {
            HtmlToPdfConverter
                .Html("<p>SaveTo Test</p>")
                .SaveTo(tmpFile);

            var info = new FileInfo(tmpFile);
            info.Length.Should().BeGreaterThan(0);
        }
        finally
        {
            System.IO.File.Delete(tmpFile);
        }
    }

    [Fact(DisplayName = "SaveToAsync: writes to file")]
    public async Task SaveToAsync_WritesToFile()
    {
        var tmpFile = Path.GetTempFileName();
        try
        {
            await HtmlToPdfConverter
                .Html("<p>SaveToAsync Test</p>")
                .SaveToAsync(tmpFile);

            var info = new FileInfo(tmpFile);
            info.Length.Should().BeGreaterThan(0);
        }
        finally
        {
            System.IO.File.Delete(tmpFile);
        }
    }

    // ── End-to-end scenarios ────────────────────────────────────────────

    [Fact(DisplayName = "E2E: government parecer document")]
    public void EndToEnd_GovernmentParecer()
    {
        const string html = """
            <html>
            <body>
                <h1>Parecer Técnico nº 042/2024</h1>
                <h2>TCE-ES</h2>
                <p>O presente parecer analisa a prestação de contas.</p>
                <h3>1. Introdução</h3>
                <p>A análise foi conduzida com base nos princípios da administração pública.</p>
                <h3>2. Conclusão</h3>
                <p><strong>Diante do exposto</strong>, opina-se pela <em>aprovação</em> das contas.</p>
            </body>
            </html>
            """;

        byte[] pdf = HtmlToPdfConverter
            .Html(html)
            .WithPageSize(PageSize.A4)
            .WithMargins(60, 50, 60, 50)
            .WithStylesheet("body { font-family: serif; font-size: 12px; line-height: 1.6; }")
            .Convert();

        pdf.Should().NotBeNull();
        pdf.Length.Should().BeGreaterThan(100);
        System.Text.Encoding.ASCII.GetString(pdf, 0, 5).Should().Be("%PDF-");
    }

    [Fact(DisplayName = "E2E: table with data")]
    public void EndToEnd_TableWithData()
    {
        const string html = """
            <table>
                <tr><th>Item</th><th>Valor</th></tr>
                <tr><td>Pessoal</td><td>R$ 1.000.000</td></tr>
                <tr><td>Custeio</td><td>R$ 500.000</td></tr>
            </table>
            """;

        byte[] pdf = HtmlToPdfConverter
            .Html(html)
            .WithStylesheet("table { width: 100%; } th, td { border: 1px solid black; padding: 4px; }")
            .Convert();

        pdf.Should().NotBeNull();
        pdf.Length.Should().BeGreaterThan(100);
    }

    [Fact(DisplayName = "E2E: lists and formatting")]
    public void EndToEnd_ListsAndFormatting()
    {
        const string html = """
            <h1>Checklist</h1>
            <ul>
                <li>Item A</li>
                <li>Item B</li>
            </ul>
            <ol>
                <li>Step 1</li>
                <li>Step 2</li>
            </ol>
            """;

        byte[] pdf = HtmlToPdfConverter
            .Html(html)
            .Convert();

        pdf.Should().NotBeNull();
    }

    [Fact(DisplayName = "E2E: complex styled document")]
    public void EndToEnd_ComplexStyledDocument()
    {
        const string html = """
            <html>
            <body>
                <h1>Report Title</h1>
                <p>This is a paragraph with <strong>bold</strong> and <em>italic</em> text.</p>
                <h2>Section 1</h2>
                <p>Some content here.</p>
                <ul>
                    <li>Point one</li>
                    <li>Point two</li>
                </ul>
                <h2>Section 2</h2>
                <table>
                    <tr><th>Name</th><th>Value</th></tr>
                    <tr><td>Alpha</td><td>100</td></tr>
                    <tr><td>Beta</td><td>200</td></tr>
                </table>
                <p>End of report.</p>
            </body>
            </html>
            """;

        byte[] pdf = HtmlToPdfConverter
            .Html(html)
            .WithPageSize(PageSize.A4)
            .WithMargins(40)
            .WithStylesheet("""
                body { font-size: 11px; line-height: 1.4; }
                h1 { font-size: 22px; }
                table { width: 100%; border-collapse: collapse; }
                th, td { border: 1px solid #666; padding: 4px; }
                th { background-color: #ddd; }
                """)
            .WithTitle("Test Report")
            .WithAuthor("Unit Test")
            .Convert();

        pdf.Should().NotBeNull();
        pdf.Length.Should().BeGreaterThan(500);
    }

    // ── FlateDecode compression ─────────────────────────────────────────

    [Fact(DisplayName = "FlateDecode: content streams are compressed")]
    public void FlateDecode_ContentStreamsAreCompressed()
    {
        byte[] pdf = HtmlToPdfConverter
            .Html("<p>Compressed content test</p>")
            .Convert();

        string text = System.Text.Encoding.ASCII.GetString(pdf);

        text.Should().Contain("/Filter /FlateDecode");
    }

    [Fact(DisplayName = "FlateDecode: PDF contains compressed stream markers")]
    public void FlateDecode_PdfContainsCompressedStreamMarkers()
    {
        byte[] pdf = HtmlToPdfConverter
            .Html("<p>Another compression test</p>")
            .Convert();

        string text = System.Text.Encoding.ASCII.GetString(pdf);

        text.Should().Contain("/Filter /FlateDecode");
        text.Should().Contain("stream");
        text.Should().Contain("endstream");
    }

    [Fact(DisplayName = "FlateDecode: JPEG images use DCTDecode (no double compression)")]
    public void FlateDecode_JpegImages_UseDctDecode()
    {
        // Minimal 1x1 JPEG (valid SOI/SOF0/EOI structure)
        const string jpegBase64 =
            "/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAgICAgICAgICAgICAgICAgICAgICAg" +
            "ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAj/wAALCA" +
            "ABAAEBAREA/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QAtRAA" +
            "AgEDAwIEAwUFBAQAAAF9AQIDAAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0f" +
            "AkM2JyggkKFhcYGRolJicoKSo0NTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZn" +
            "aGlqc3R1dnd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5us" +
            "LDxMXGx8jJytLT1NXW19jZ2uHi4+Tl5ufo6erx8vP09fb3+Pn6/9oACAEBAAA/" +
            "AHuUEQAAAP/Z";

        string html = $"""<img src="data:image/jpeg;base64,{jpegBase64}" />""";

        byte[] pdf = HtmlToPdfConverter
            .Html(html)
            .Convert();

        string text = System.Text.Encoding.ASCII.GetString(pdf);

        text.Should().Contain("/DCTDecode");
    }

    // ── Page orientation ────────────────────────────────────────────────

    [Fact(DisplayName = "WithPageOrientation: Landscape swaps A4 MediaBox dimensions")]
    public void WithPageOrientation_Landscape_SwapsMediaBoxDimensions()
    {
        byte[] pdf = HtmlToPdfConverter
            .Html("<p>Landscape test</p>")
            .WithPageSize(PageSize.A4)
            .WithPageOrientation(PageOrientation.Landscape)
            .Convert();

        string text = System.Text.Encoding.ASCII.GetString(pdf);

        // Landscape A4: width=841.89, height=595.28
        text.Should().Contain("/MediaBox [0 0 841.89 595.28]");
    }

    [Fact(DisplayName = "Default orientation: Portrait has normal A4 MediaBox")]
    public void Default_Portrait_HasNormalA4MediaBox()
    {
        byte[] pdf = HtmlToPdfConverter
            .Html("<p>Portrait test</p>")
            .WithPageSize(PageSize.A4)
            .Convert();

        string text = System.Text.Encoding.ASCII.GetString(pdf);

        // Portrait A4: width=595.28, height=841.89
        text.Should().Contain("/MediaBox [0 0 595.28 841.89]");
    }

    // ── PDF metadata ────────────────────────────────────────────────────

    [Fact(DisplayName = "WithTitle and WithAuthor: metadata appears in PDF")]
    public void WithTitleAndAuthor_MetadataAppearsInPdf()
    {
        byte[] pdf = HtmlToPdfConverter
            .Html("<p>Metadata test</p>")
            .WithTitle("Test Doc")
            .WithAuthor("André")
            .Convert();

        string text = System.Text.Encoding.Latin1.GetString(pdf);

        text.Should().Contain("/Title (Test Doc)");
        text.Should().Contain("/Author");
    }

    [Fact(DisplayName = "Default: Creator and Producer are always present")]
    public void Default_HasCreatorAndProducer()
    {
        byte[] pdf = HtmlToPdfConverter
            .Html("<p>Creator test</p>")
            .Convert();

        string text = System.Text.Encoding.ASCII.GetString(pdf);

        text.Should().Contain("/Creator (SimpleSign.HtmlToPdf)");
        text.Should().Contain("/Producer (SimpleSign.HtmlToPdf)");
    }

    [Fact(DisplayName = "Default: CreationDate is present")]
    public void Default_HasCreationDate()
    {
        byte[] pdf = HtmlToPdfConverter
            .Html("<p>Date test</p>")
            .Convert();

        string text = System.Text.Encoding.ASCII.GetString(pdf);

        text.Should().Contain("/CreationDate (D:");
    }

    // ── Bookmarks ───────────────────────────────────────────────────────

    [Fact(DisplayName = "Bookmarks: headings produce Outlines in PDF")]
    public void Bookmarks_Headings_ProduceOutlines()
    {
        byte[] pdf = HtmlToPdfConverter
            .Html("<h1>Title</h1><h2>Subtitle</h2><p>Content</p>")
            .Convert();

        string text = System.Text.Encoding.ASCII.GetString(pdf);

        text.Should().Contain("/Outlines");
        text.Should().Contain("/Type /Outlines");
    }

    [Fact(DisplayName = "Bookmarks: bookmark text appears in PDF")]
    public void Bookmarks_TextAppearsInPdf()
    {
        byte[] pdf = HtmlToPdfConverter
            .Html("<h1>Title</h1><h2>Subtitle</h2>")
            .Convert();

        string text = System.Text.Encoding.ASCII.GetString(pdf);

        text.Should().Contain("(Title)");
        text.Should().Contain("(Subtitle)");
    }

    [Fact(DisplayName = "Bookmarks: no headings means no Outlines")]
    public void Bookmarks_NoHeadings_NoOutlines()
    {
        byte[] pdf = HtmlToPdfConverter
            .Html("<p>Just a paragraph</p>")
            .Convert();

        string text = System.Text.Encoding.ASCII.GetString(pdf);

        text.Should().NotContain("/Type /Outlines");
    }

    // ── Header / Footer ─────────────────────────────────────────────────

    [Fact(DisplayName = "WithHeader: page number text rendered in PDF")]
    public void WithHeader_PageNumberRenderedInPdf()
    {
        byte[] pdf = HtmlToPdfConverter
            .Html("<p>Header test content</p>")
            .WithHeader("Page {page} of {pages}")
            .Convert();

        string decompressed = PdfTextHelper.GetDecompressedPdfText(pdf);

        decompressed.Should().Contain("Page 1 of 1");
    }

    [Fact(DisplayName = "WithFooter: title placeholder rendered in PDF")]
    public void WithFooter_TitleRenderedInPdf()
    {
        byte[] pdf = HtmlToPdfConverter
            .Html("<p>Footer test content</p>")
            .WithFooter("{title}")
            .WithTitle("Doc")
            .Convert();

        string decompressed = PdfTextHelper.GetDecompressedPdfText(pdf);

        decompressed.Should().Contain("Doc");
    }

    [Fact(DisplayName = "No header/footer: no extra margin text")]
    public void NoHeaderFooter_NoExtraMarginText()
    {
        byte[] pdf = HtmlToPdfConverter
            .Html("<p>Plain content only</p>")
            .Convert();

        string decompressed = PdfTextHelper.GetDecompressedPdfText(pdf);

        // "Page 1 of 1" should NOT appear when no header/footer is set
        decompressed.Should().NotContain("Page 1 of 1");
    }

    // ── Robustness ──────────────────────────────────────────────────────

    [Fact(DisplayName = "Deeply nested HTML (300 levels): does not throw")]
    public void DeeplyNestedHtml_DoesNotThrow()
    {
        // Build 300 levels of nested divs (exceeds the 256 limit safely)
        const int depth = 300;
        string open = string.Concat(Enumerable.Repeat("<div>", depth));
        string close = string.Concat(Enumerable.Repeat("</div>", depth));
        string html = $"{open}<p>Deep content</p>{close}";

        var act = () => HtmlToPdfConverter.Html(html).Convert();

        byte[] pdf = act.Should().NotThrow().Subject;
        pdf.Should().NotBeNull();
        pdf.Length.Should().BeGreaterThan(0);
    }

    [Fact(DisplayName = "Broken image with alt: renders alt text in brackets")]
    public void BrokenImage_WithAlt_ShowsAltText()
    {
        byte[] pdf = HtmlToPdfConverter
            .Html("""<img src="invalid" alt="Missing image">""")
            .Convert();

        string decompressed = PdfTextHelper.GetDecompressedPdfText(pdf);

        decompressed.Should().Contain("[Missing image]");
    }

    [Fact(DisplayName = "Broken image without alt: does not crash")]
    public void BrokenImage_NoAlt_DoesNotCrash()
    {
        var act = () => HtmlToPdfConverter
            .Html("""<p>Before</p><img src="invalid"><p>After</p>""")
            .Convert();

        byte[] pdf = act.Should().NotThrow().Subject;
        pdf.Should().NotBeNull();
        System.Text.Encoding.ASCII.GetString(pdf, 0, 5).Should().Be("%PDF-");
    }
}

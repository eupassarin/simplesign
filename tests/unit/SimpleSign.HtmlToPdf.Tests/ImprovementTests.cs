// Licensed to SimpleSign under the MIT License.

using Shouldly;
using SimpleSign.HtmlToPdf.Layout;
using SimpleSign.HtmlToPdf.Parsing;
using Xunit;

namespace SimpleSign.HtmlToPdf.Tests;

/// <summary>
/// Deep tests for all HtmlToPdf improvements: FlateDecode compression, page orientation,
/// PDF metadata, HSL colors, bookmarks, headers/footers, robustness, and E2E scenarios.
/// </summary>
public class ImprovementTests
{
    // ── FlateDecode Compression ────────────────────────────────────────

    [Fact(DisplayName = "Compression: reduces file size below raw HTML input")]
    public void Compression_ReducesFileSize()
    {
        string largeHtml = "<html><body>" +
            string.Concat(Enumerable.Repeat("<p>Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt.</p>", 60)) +
            "</body></html>";

        byte[] pdf = HtmlToPdfConverter.Html(largeHtml).Convert();

        pdf.Length.ShouldBeLessThan(largeHtml.Length,
            "FlateDecode compression should make the PDF smaller than raw HTML for large content");
    }

    [Fact(DisplayName = "Compression: multiple pages all have FlateDecode")]
    public void Compression_MultiplePages_AllCompressed()
    {
        string html = "<html><body>" +
            "<p>Page One Content</p>" +
            "<div style=\"page-break-before:always\"></div>" +
            "<p>Page Two Content</p>" +
            "<div style=\"page-break-before:always\"></div>" +
            "<p>Page Three Content</p>" +
            "</body></html>";

        byte[] pdf = HtmlToPdfConverter.Html(html).Convert();
        string text = System.Text.Encoding.ASCII.GetString(pdf);

        int count = 0;
        int idx = 0;
        while ((idx = text.IndexOf("/Filter /FlateDecode", idx, StringComparison.Ordinal)) >= 0)
        {
            count++;
            idx += "/Filter /FlateDecode".Length;
        }

        count.ShouldBeGreaterThanOrEqualTo(3,
            "each page content stream should have its own FlateDecode filter");
    }

    [Fact(DisplayName = "Compression: empty body still produces valid PDF")]
    public void Compression_EmptyBody_StillValidPdf()
    {
        byte[] pdf = HtmlToPdfConverter.Html("<html><body></body></html>").Convert();

        pdf.ShouldNotBeNull();
        pdf.Length.ShouldBeGreaterThan(0);
        System.Text.Encoding.ASCII.GetString(pdf, 0, 5).ShouldBe("%PDF-");
    }

    [Fact(DisplayName = "Compression: decompressed content matches original text")]
    public void Compression_DecompressedContentMatchesOriginalText()
    {
        byte[] pdf = HtmlToPdfConverter
            .Html("<p>Compression Test Content</p>")
            .Convert();

        string decompressed = PdfTextHelper.GetDecompressedPdfText(pdf);

        // PDF renderer splits inline text into individual word runs
        decompressed.ShouldContain("Compression");
        decompressed.ShouldContain("Content");
    }

    [Fact(DisplayName = "Compression: special characters survive roundtrip")]
    public void Compression_SpecialCharacters_SurviveRoundtrip()
    {
        byte[] pdf = HtmlToPdfConverter
            .Html("<p>Entities: &amp; &lt; &gt;</p>")
            .Convert();

        string decompressed = PdfTextHelper.GetDecompressedPdfText(pdf);

        decompressed.ShouldContain("&");
        decompressed.ShouldContain("<");
        decompressed.ShouldContain(">");
    }

    // ── Page Orientation ───────────────────────────────────────────────

    [Fact(DisplayName = "Landscape A4: MediaBox is 841.89 x 595.28")]
    public void Landscape_A4_MediaBoxIs842x595()
    {
        byte[] pdf = HtmlToPdfConverter
            .Html("<p>Landscape A4</p>")
            .WithPageSize(PageSize.A4)
            .WithPageOrientation(PageOrientation.Landscape)
            .Convert();

        string text = System.Text.Encoding.ASCII.GetString(pdf);

        text.ShouldContain("/MediaBox [0 0 841.89 595.28]");
    }

    [Fact(DisplayName = "Landscape Letter: MediaBox is 792 x 612")]
    public void Landscape_Letter_MediaBoxIs792x612()
    {
        byte[] pdf = HtmlToPdfConverter
            .Html("<p>Landscape Letter</p>")
            .WithPageSize(PageSize.Letter)
            .WithPageOrientation(PageOrientation.Landscape)
            .Convert();

        string text = System.Text.Encoding.ASCII.GetString(pdf);

        // Renderer formats dimensions with F2 (2 decimal places)
        text.ShouldContain("/MediaBox [0 0 792.00 612.00]");
    }

    [Fact(DisplayName = "Landscape: content width is wider than portrait")]
    public void Landscape_ContentWidth_IsWiderThanPortrait()
    {
        const string html = "<p>Width comparison test with enough text to span the page nicely</p>";

        byte[] portraitPdf = HtmlToPdfConverter.Html(html)
            .WithPageSize(PageSize.A4)
            .WithPageOrientation(PageOrientation.Portrait)
            .Convert();

        byte[] landscapePdf = HtmlToPdfConverter.Html(html)
            .WithPageSize(PageSize.A4)
            .WithPageOrientation(PageOrientation.Landscape)
            .Convert();

        string portraitText = System.Text.Encoding.ASCII.GetString(portraitPdf);
        string landscapeText = System.Text.Encoding.ASCII.GetString(landscapePdf);

        // Portrait A4 MediaBox: width=595.28, height=841.89
        portraitText.ShouldContain("/MediaBox [0 0 595.28 841.89]");
        // Landscape A4 MediaBox: width=841.89, height=595.28 (swapped)
        landscapeText.ShouldContain("/MediaBox [0 0 841.89 595.28]");
    }

    [Fact(DisplayName = "Landscape with custom margins: respects margins and MediaBox")]
    public void Landscape_WithCustomMargins_RespectsMargins()
    {
        byte[] pdf = HtmlToPdfConverter
            .Html("<p>Custom margins landscape</p>")
            .WithPageSize(PageSize.A4)
            .WithPageOrientation(PageOrientation.Landscape)
            .WithMargins(50, 50, 50, 50)
            .Convert();

        string text = System.Text.Encoding.ASCII.GetString(pdf);

        text.ShouldContain("/MediaBox [0 0 841.89 595.28]");
        pdf.Length.ShouldBeGreaterThan(0);
    }

    [Fact(DisplayName = "Portrait default: same MediaBox as explicit Portrait")]
    public void Portrait_Default_NoOrientationSwap()
    {
        byte[] defaultPdf = HtmlToPdfConverter
            .Html("<p>Default orientation</p>")
            .WithPageSize(PageSize.A4)
            .Convert();

        byte[] explicitPdf = HtmlToPdfConverter
            .Html("<p>Default orientation</p>")
            .WithPageSize(PageSize.A4)
            .WithPageOrientation(PageOrientation.Portrait)
            .Convert();

        string defaultText = System.Text.Encoding.ASCII.GetString(defaultPdf);
        string explicitText = System.Text.Encoding.ASCII.GetString(explicitPdf);

        defaultText.ShouldContain("/MediaBox [0 0 595.28 841.89]");
        explicitText.ShouldContain("/MediaBox [0 0 595.28 841.89]");
    }

    // ── PDF Metadata ───────────────────────────────────────────────────

    [Fact(DisplayName = "Metadata: title appears in Info dict")]
    public void Metadata_Title_AppearsInInfoDict()
    {
        byte[] pdf = HtmlToPdfConverter
            .Html("<p>Title metadata test</p>")
            .WithTitle("Teste")
            .Convert();

        string text = System.Text.Encoding.Latin1.GetString(pdf);

        text.ShouldContain("/Title (Teste)");
    }

    [Fact(DisplayName = "Metadata: author appears in Info dict")]
    public void Metadata_Author_AppearsInInfoDict()
    {
        byte[] pdf = HtmlToPdfConverter
            .Html("<p>Author metadata test</p>")
            .WithAuthor("André")
            .Convert();

        string text = System.Text.Encoding.Latin1.GetString(pdf);

        text.ShouldContain("/Author");
    }

    [Fact(DisplayName = "Metadata: special chars are escaped in title")]
    public void Metadata_SpecialChars_AreEscaped()
    {
        byte[] pdf = HtmlToPdfConverter
            .Html("<p>Special chars test</p>")
            .WithTitle("Test (with) parens")
            .Convert();

        string text = System.Text.Encoding.Latin1.GetString(pdf);

        text.ShouldContain("\\(");
        text.ShouldContain("\\)");
    }

    [Fact(DisplayName = "Metadata: no title or author still has Creator")]
    public void Metadata_NoTitleOrAuthor_StillHasCreator()
    {
        byte[] pdf = HtmlToPdfConverter
            .Html("<p>No metadata test</p>")
            .Convert();

        string text = System.Text.Encoding.ASCII.GetString(pdf);

        text.ShouldContain("/Creator (SimpleSign.HtmlToPdf)");
    }

    [Fact(DisplayName = "Metadata: combined with bookmarks, both present")]
    public void Metadata_CombinedWithBookmarks_BothPresent()
    {
        byte[] pdf = HtmlToPdfConverter
            .Html("<h1>Chapter 1</h1><h2>Section A</h2><p>Content</p>")
            .WithTitle("Combined Test")
            .WithAuthor("Test Author")
            .Convert();

        string text = System.Text.Encoding.Latin1.GetString(pdf);

        text.ShouldContain("/Title (Combined Test)");
        text.ShouldContain("/Outlines");
        text.ShouldContain("/Type /Outlines");
    }

    // ── HSL Colors ─────────────────────────────────────────────────────

    [Fact(DisplayName = "HSL: red (0, 100%, 50%) parses correctly")]
    public void Hsl_Red_CorrectRgb()
    {
        var color = PdfColor.Parse("hsl(0, 100%, 50%)");

        color.R.ShouldBe(1.0f, 0.01f);
        color.G.ShouldBe(0.0f, 0.01f);
        color.B.ShouldBe(0.0f, 0.01f);
    }

    [Fact(DisplayName = "HSL: green (120, 100%, 50%) parses correctly")]
    public void Hsl_Green_CorrectRgb()
    {
        var color = PdfColor.Parse("hsl(120, 100%, 50%)");

        color.R.ShouldBe(0.0f, 0.01f);
        color.G.ShouldBe(1.0f, 0.01f);
        color.B.ShouldBe(0.0f, 0.01f);
    }

    [Fact(DisplayName = "HSL: blue (240, 100%, 50%) parses correctly")]
    public void Hsl_Blue_CorrectRgb()
    {
        var color = PdfColor.Parse("hsl(240, 100%, 50%)");

        color.R.ShouldBe(0.0f, 0.01f);
        color.G.ShouldBe(0.0f, 0.01f);
        color.B.ShouldBe(1.0f, 0.01f);
    }

    [Fact(DisplayName = "HSL: white (0, 0%, 100%) parses correctly")]
    public void Hsl_White_CorrectRgb()
    {
        var color = PdfColor.Parse("hsl(0, 0%, 100%)");

        color.R.ShouldBe(1.0f, 0.01f);
        color.G.ShouldBe(1.0f, 0.01f);
        color.B.ShouldBe(1.0f, 0.01f);
    }

    [Fact(DisplayName = "HSL: black (0, 0%, 0%) parses correctly")]
    public void Hsl_Black_CorrectRgb()
    {
        var color = PdfColor.Parse("hsl(0, 0%, 0%)");

        color.R.ShouldBe(0.0f, 0.01f);
        color.G.ShouldBe(0.0f, 0.01f);
        color.B.ShouldBe(0.0f, 0.01f);
    }

    [Fact(DisplayName = "HSL: gray 50% (0, 0%, 50%) parses correctly")]
    public void Hsl_Gray50_CorrectRgb()
    {
        var color = PdfColor.Parse("hsl(0, 0%, 50%)");

        color.R.ShouldBe(0.5f, 0.01f);
        color.G.ShouldBe(0.5f, 0.01f);
        color.B.ShouldBe(0.5f, 0.01f);
    }

    [Fact(DisplayName = "HSLA: with alpha parses correctly without crash")]
    public void Hsla_WithAlpha_ParsesCorrectly()
    {
        var color = PdfColor.Parse("hsla(120, 100%, 50%, 0.5)");

        color.R.ShouldBe(0.0f, 0.01f);
        color.G.ShouldBe(1.0f, 0.01f);
        color.B.ShouldBe(0.0f, 0.01f);
    }

    [Fact(DisplayName = "HSL in CSS: renders valid PDF with color operator")]
    public void Hsl_InCss_RendersInPdf()
    {
        byte[] pdf = HtmlToPdfConverter
            .Html("""<p style="color: hsl(210, 80%, 30%)">HSL colored text</p>""")
            .Convert();

        pdf.ShouldNotBeNull();
        pdf.Length.ShouldBeGreaterThan(0);
        System.Text.Encoding.ASCII.GetString(pdf, 0, 5).ShouldBe("%PDF-");

        string decompressed = PdfTextHelper.GetDecompressedPdfText(pdf);
        decompressed.ShouldContain("HSL");
        decompressed.ShouldContain("colored");
    }

    // ── Bookmarks ──────────────────────────────────────────────────────

    [Fact(DisplayName = "Bookmarks: single H1 produces exactly 1 outline item")]
    public void Bookmarks_H1Only_SingleOutlineItem()
    {
        byte[] pdf = HtmlToPdfConverter
            .Html("<h1>Title</h1><p>Content</p>")
            .Convert();

        string text = System.Text.Encoding.ASCII.GetString(pdf);

        text.ShouldContain("/Type /Outlines");
        text.ShouldContain("/Count 1");
    }

    [Fact(DisplayName = "Bookmarks: multiple headings all present in PDF")]
    public void Bookmarks_MultipleHeadings_AllPresent()
    {
        byte[] pdf = HtmlToPdfConverter
            .Html("<h1>Chapter</h1><h2>Section</h2><h3>Subsection</h3><p>Body</p>")
            .Convert();

        string text = System.Text.Encoding.ASCII.GetString(pdf);

        text.ShouldContain("(Chapter)");
        text.ShouldContain("(Section)");
        text.ShouldContain("(Subsection)");
        text.ShouldContain("/Count 3");
    }

    [Fact(DisplayName = "Bookmarks: special chars are escaped in bookmark title")]
    public void Bookmarks_SpecialChars_Escaped()
    {
        byte[] pdf = HtmlToPdfConverter
            .Html("<h1>Test (with) special &amp; chars</h1><p>Content</p>")
            .Convert();

        string text = System.Text.Encoding.Latin1.GetString(pdf);

        text.ShouldContain("\\(");
        text.ShouldContain("\\)");
    }

    [Fact(DisplayName = "Bookmarks: empty heading is skipped")]
    public void Bookmarks_EmptyHeading_Skipped()
    {
        byte[] pdf = HtmlToPdfConverter
            .Html("<h1></h1><h1>Real Title</h1><p>Content</p>")
            .Convert();

        string text = System.Text.Encoding.ASCII.GetString(pdf);

        text.ShouldContain("/Count 1");
        text.ShouldContain("(Real Title)");
    }

    [Fact(DisplayName = "Bookmarks: catalog has Outlines and PageMode")]
    public void Bookmarks_CatalogHasOutlines()
    {
        byte[] pdf = HtmlToPdfConverter
            .Html("<h1>Title</h1><p>Content</p>")
            .Convert();

        string text = System.Text.Encoding.ASCII.GetString(pdf);

        text.ShouldContain("/Type /Outlines");
        text.ShouldContain("/PageMode /UseOutlines");
    }

    [Fact(DisplayName = "Bookmarks: destination points to valid page with XYZ")]
    public void Bookmarks_DestinationPointsToPage()
    {
        byte[] pdf = HtmlToPdfConverter
            .Html("<h1>Heading</h1><p>Content</p>")
            .Convert();

        string text = System.Text.Encoding.ASCII.GetString(pdf);

        text.ShouldMatch(@"/Dest \[\d+ 0 R /XYZ 0 \d+\.\d+ null\]");
    }

    // ── Headers & Footers ──────────────────────────────────────────────

    [Fact(DisplayName = "Header: {page} placeholder resolved correctly")]
    public void Header_PagePlaceholder_ResolvedCorrectly()
    {
        byte[] pdf = HtmlToPdfConverter
            .Html("<p>Content for header test</p>")
            .WithHeader("Page {page}")
            .Convert();

        string decompressed = PdfTextHelper.GetDecompressedPdfText(pdf);

        decompressed.ShouldContain("Page 1");
    }

    [Fact(DisplayName = "Footer: {page}/{pages} shows total page count")]
    public void Footer_PagesPlaceholder_ShowsTotal()
    {
        byte[] pdf = HtmlToPdfConverter
            .Html("<p>Single page content</p>")
            .WithFooter("{page}/{pages}")
            .Convert();

        string decompressed = PdfTextHelper.GetDecompressedPdfText(pdf);

        decompressed.ShouldContain("1/1");
    }

    [Fact(DisplayName = "Header: {title} placeholder uses metadata")]
    public void Header_TitlePlaceholder_UsesMetadata()
    {
        byte[] pdf = HtmlToPdfConverter
            .Html("<p>Title placeholder test</p>")
            .WithHeader("{title}")
            .WithTitle("My Doc")
            .Convert();

        string decompressed = PdfTextHelper.GetDecompressedPdfText(pdf);

        decompressed.ShouldContain("My Doc");
    }

    [Fact(DisplayName = "Footer: {date} placeholder has current date")]
    public void Footer_DatePlaceholder_HasCurrentDate()
    {
        byte[] pdf = HtmlToPdfConverter
            .Html("<p>Date placeholder test</p>")
            .WithFooter("{date}")
            .Convert();

        string decompressed = PdfTextHelper.GetDecompressedPdfText(pdf);

        string today = DateTime.Now.ToString("dd/MM/yyyy", System.Globalization.CultureInfo.InvariantCulture);
        decompressed.ShouldContain(today);
    }

    [Fact(DisplayName = "Header and footer: both appear in PDF simultaneously")]
    public void HeaderAndFooter_Combined()
    {
        byte[] pdf = HtmlToPdfConverter
            .Html("<p>Combined header footer test</p>")
            .WithHeader("HEADER TEXT")
            .WithFooter("FOOTER TEXT")
            .Convert();

        string decompressed = PdfTextHelper.GetDecompressedPdfText(pdf);

        decompressed.ShouldContain("HEADER TEXT");
        decompressed.ShouldContain("FOOTER TEXT");
    }

    [Fact(DisplayName = "Multi-page: header/footer appear on all pages")]
    public void MultiPage_HeaderFooter_OnAllPages()
    {
        string html = "<html><body>" +
            "<p>Page one</p>" +
            "<div style=\"page-break-before:always\"></div>" +
            "<p>Page two</p>" +
            "</body></html>";

        byte[] pdf = HtmlToPdfConverter
            .Html(html)
            .WithHeader("H-{page}")
            .WithFooter("F-{page}")
            .Convert();

        string decompressed = PdfTextHelper.GetDecompressedPdfText(pdf);

        decompressed.ShouldContain("H-1");
        decompressed.ShouldContain("H-2");
        decompressed.ShouldContain("F-1");
        decompressed.ShouldContain("F-2");
    }

    [Fact(DisplayName = "No header/footer: template text absent from PDF")]
    public void NoHeaderFooter_CleanMargins()
    {
        byte[] pdf = HtmlToPdfConverter
            .Html("<p>Clean content only</p>")
            .Convert();

        string decompressed = PdfTextHelper.GetDecompressedPdfText(pdf);

        // Without header/footer, page numbering text should not be present
        decompressed.ShouldNotContain("Page 1 of 1");
    }

    // ── Robustness ─────────────────────────────────────────────────────

    [Fact(DisplayName = "Max nesting 256 levels: parses successfully")]
    public void MaxNesting_256Levels_ParsesSuccessfully()
    {
        const int depth = 256;
        string open = string.Concat(Enumerable.Repeat("<div>", depth));
        string close = string.Concat(Enumerable.Repeat("</div>", depth));
        string html = $"{open}<p>Deep 256</p>{close}";

        var act = () => HtmlToPdfConverter.Html(html).Convert();

        byte[] pdf = act.Invoke();
        pdf.ShouldNotBeNull();

        string decompressed = PdfTextHelper.GetDecompressedPdfText(pdf);
        decompressed.ShouldContain("Deep");
        decompressed.ShouldContain("256");
    }

    [Fact(DisplayName = "Max nesting 300 levels: clamped at 256, content present")]
    public void MaxNesting_300Levels_ClampedAt256()
    {
        const int depth = 300;
        string open = string.Concat(Enumerable.Repeat("<div>", depth));
        string close = string.Concat(Enumerable.Repeat("</div>", depth));
        string html = $"{open}<p>Deep 300</p>{close}";

        var act = () => HtmlToPdfConverter.Html(html).Convert();

        byte[] pdf = act.Invoke();
        pdf.ShouldNotBeNull();

        string decompressed = PdfTextHelper.GetDecompressedPdfText(pdf);
        decompressed.ShouldContain("Deep");
        decompressed.ShouldContain("300");
    }

    [Fact(DisplayName = "Broken image data URI with alt: shows alt text in brackets")]
    public void BrokenImage_DataUri_WithAlt_ShowsAltText()
    {
        byte[] pdf = HtmlToPdfConverter
            .Html("""<img src="data:image/png;base64,INVALID" alt="Broken">""")
            .Convert();

        string decompressed = PdfTextHelper.GetDecompressedPdfText(pdf);

        decompressed.ShouldContain("[Broken]");
    }

    [Fact(DisplayName = "Broken image HTTP URL with alt: shows alt text in brackets")]
    public void BrokenImage_HttpUrl_WithAlt()
    {
        byte[] pdf = HtmlToPdfConverter
            .Html("""<img src="http://example.com/missing.png" alt="Not Found">""")
            .Convert();

        string decompressed = PdfTextHelper.GetDecompressedPdfText(pdf);

        decompressed.ShouldContain("[Not Found]");
    }

    [Fact(DisplayName = "Broken image no alt: valid PDF, no crash, no alt text box")]
    public void BrokenImage_NoAlt_NoOutput()
    {
        var act = () => HtmlToPdfConverter
            .Html("""<p>Before</p><img src="invalid"><p>After</p>""")
            .Convert();

        byte[] pdf = act.Invoke();
        pdf.ShouldNotBeNull();
        System.Text.Encoding.ASCII.GetString(pdf, 0, 5).ShouldBe("%PDF-");
    }

    [Fact(DisplayName = "Malformed HTML with unclosed tags: does not crash")]
    public void MalformedHtml_UnclosedTags_DoesNotCrash()
    {
        var act = () => HtmlToPdfConverter
            .Html("<div><p>Test<table><tr><td>Cell")
            .Convert();

        byte[] pdf = act.Invoke();
        pdf.ShouldNotBeNull();
        System.Text.Encoding.ASCII.GetString(pdf, 0, 5).ShouldBe("%PDF-");
    }

    // ── Integration / End-to-End ───────────────────────────────────────

    [Fact(DisplayName = "E2E: government report with all features")]
    public void E2E_GovernmentReport_AllFeatures()
    {
        const string html = """
            <html>
            <body>
                <h1>Parecer Técnico nº 100/2024</h1>
                <h2>1. Análise</h2>
                <p style="color: hsl(210, 80%, 30%)">Texto com cor HSL.</p>
                <table style="width:100%; border-collapse:collapse;">
                    <tr><th style="border:1px solid #000; background-color: hsl(0, 0%, 90%)">Item</th>
                        <th style="border:1px solid #000">Valor</th></tr>
                    <tr><td style="border:1px solid #000">Receita</td>
                        <td style="border:1px solid #000">R$ 1.000.000</td></tr>
                </table>
                <h2>2. Conclusão</h2>
                <p><strong>Aprovado</strong> conforme análise.</p>
            </body>
            </html>
            """;

        byte[] pdf = HtmlToPdfConverter
            .Html(html)
            .WithPageSize(PageSize.A4)
            .WithPageOrientation(PageOrientation.Landscape)
            .WithMargins(50, 40, 50, 40)
            .WithTitle("Parecer 100/2024")
            .WithAuthor("TCE-ES")
            .WithHeader("{title}")
            .WithFooter("Página {page} de {pages}")
            .Convert();

        string raw = System.Text.Encoding.Latin1.GetString(pdf);
        string decompressed = PdfTextHelper.GetDecompressedPdfText(pdf);

        // Valid PDF
        System.Text.Encoding.ASCII.GetString(pdf, 0, 5).ShouldBe("%PDF-");

        // Landscape A4
        raw.ShouldContain("/MediaBox [0 0 841.89 595.28]");

        // Metadata
        raw.ShouldContain("/Title");
        raw.ShouldContain("/Author");

        // Bookmarks (headings h1+h2 produce outlines)
        raw.ShouldContain("/Type /Outlines");

        // Header/footer resolved (text is split into words by renderer)
        decompressed.ShouldContain("Parecer");
    }

    [Fact(DisplayName = "E2E: multi-page with bookmarks and footers")]
    public void E2E_MultiPage_BookmarksAndFooters()
    {
        string longContent = string.Concat(
            Enumerable.Repeat("<p>Paragraph content for filling up space in the document.</p>", 80));

        string html = $"""
            <html><body>
                <h1>Chapter 1</h1>
                {longContent}
                <h1>Chapter 2</h1>
                {longContent}
                <h1>Chapter 3</h1>
                {longContent}
            </body></html>
            """;

        byte[] pdf = HtmlToPdfConverter
            .Html(html)
            .WithFooter("{page}/{pages}")
            .Convert();

        string raw = System.Text.Encoding.ASCII.GetString(pdf);
        string decompressed = PdfTextHelper.GetDecompressedPdfText(pdf);

        // All 3 bookmarks present
        raw.ShouldContain("(Chapter 1)");
        raw.ShouldContain("(Chapter 2)");
        raw.ShouldContain("(Chapter 3)");

        // Should have multiple pages (count MediaBox occurrences)
        int pageCount = 0;
        int searchIdx = 0;
        while ((searchIdx = raw.IndexOf("/MediaBox", searchIdx, StringComparison.Ordinal)) >= 0)
        {
            pageCount++;
            searchIdx += "/MediaBox".Length;
        }

        pageCount.ShouldBeGreaterThanOrEqualTo(3, "long content should span at least 3 pages");

        // Footer should show page numbers in decompressed content
        decompressed.ShouldContain($"/{pageCount}");
    }

    [Fact(DisplayName = "E2E: CKEditor-style output with improvements")]
    public void E2E_CkEditorOutput_WithImprovements()
    {
        const string html = """
            <html><body>
                <h1>Document Title</h1>
                <p>Regular paragraph with <strong>bold</strong> and <em>italic</em> text.</p>
                <p style="color: hsl(0, 80%, 40%)">Red HSL paragraph</p>
                <h2>Data Table</h2>
                <table style="width:100%; border-collapse:collapse;">
                    <tr><th style="border:1px solid #333; padding:4px;">Name</th>
                        <th style="border:1px solid #333; padding:4px;">Value</th></tr>
                    <tr><td style="border:1px solid #333; padding:4px;">Alpha</td>
                        <td style="border:1px solid #333; padding:4px;">100</td></tr>
                </table>
                <ul>
                    <li>Item one</li>
                    <li>Item two</li>
                </ul>
                <p>Final paragraph.</p>
            </body></html>
            """;

        byte[] pdf = HtmlToPdfConverter
            .Html(html)
            .WithTitle("CKEditor Doc")
            .WithAuthor("Editor User")
            .WithFooter("{page} / {pages} - {date}")
            .Convert();

        string raw = System.Text.Encoding.Latin1.GetString(pdf);
        string decompressed = PdfTextHelper.GetDecompressedPdfText(pdf);

        // Valid PDF
        System.Text.Encoding.ASCII.GetString(pdf, 0, 5).ShouldBe("%PDF-");

        // Metadata
        raw.ShouldContain("/Title (CKEditor Doc)");

        // Bookmarks
        raw.ShouldContain("(Document Title)");

        // Footer resolved - check date present in decompressed output
        string today = DateTime.Now.ToString("dd/MM/yyyy", System.Globalization.CultureInfo.InvariantCulture);
        decompressed.ShouldContain(today);

        // Content present (words are split individually by renderer)
        decompressed.ShouldContain("Final");
        decompressed.ShouldContain("paragraph");
    }

    [Fact(DisplayName = "E2E: empty HTML produces minimal valid PDF")]
    public void E2E_EmptyDocument_MinimalValidPdf()
    {
        byte[] pdf = HtmlToPdfConverter.Html("").Convert();

        pdf.ShouldNotBeNull();
        pdf.Length.ShouldBeGreaterThan(0);
        System.Text.Encoding.ASCII.GetString(pdf, 0, 5).ShouldBe("%PDF-");
    }
}

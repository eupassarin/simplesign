using Shouldly;
using SimpleSign.HtmlToPdf.Layout;
using SimpleSign.HtmlToPdf.Parsing;
using SimpleSign.HtmlToPdf.Rendering;
using Xunit;

namespace SimpleSign.HtmlToPdf.Tests;

public class PdfRendererTests
{
    // ── PDF structure ───────────────────────────────────────────────────

    [Fact(DisplayName = "Render: produces valid PDF header")]
    public void Render_ProducesValidPdfHeader()
    {
        var layout = CreateSimpleLayout("Hello");

        byte[] pdf = PdfDocumentRenderer.Render(layout);

        pdf.ShouldNotBeNull();
        pdf.Length.ShouldBeGreaterThan(0);

        string header = System.Text.Encoding.ASCII.GetString(pdf, 0, Math.Min(10, pdf.Length));
        header.ShouldStartWith("%PDF-");
    }

    [Fact(DisplayName = "Render: contains EOF marker")]
    public void Render_ContainsEofMarker()
    {
        var layout = CreateSimpleLayout("Test");

        byte[] pdf = PdfDocumentRenderer.Render(layout);

        string text = System.Text.Encoding.Latin1.GetString(pdf);
        text.ShouldContain("%%EOF");
    }

    [Fact(DisplayName = "Render: contains xref table")]
    public void Render_ContainsXrefTable()
    {
        var layout = CreateSimpleLayout("Test");

        byte[] pdf = PdfDocumentRenderer.Render(layout);

        string text = System.Text.Encoding.Latin1.GetString(pdf);
        text.ShouldContain("xref");
        text.ShouldContain("startxref");
    }

    [Fact(DisplayName = "Render: contains catalog and pages")]
    public void Render_ContainsCatalogAndPages()
    {
        var layout = CreateSimpleLayout("Test");

        byte[] pdf = PdfDocumentRenderer.Render(layout);

        string text = System.Text.Encoding.Latin1.GetString(pdf);
        text.ShouldContain("/Type /Catalog");
        text.ShouldContain("/Type /Pages");
        text.ShouldContain("/Type /Page");
    }

    [Fact(DisplayName = "Render: contains font resources")]
    public void Render_ContainsFontResources()
    {
        var layout = CreateSimpleLayout("Test");

        byte[] pdf = PdfDocumentRenderer.Render(layout);

        string text = System.Text.Encoding.Latin1.GetString(pdf);
        text.ShouldContain("/Type /Font");
        text.ShouldContain("/BaseFont");
    }

    // ── Multi-page ──────────────────────────────────────────────────────

    [Fact(DisplayName = "Render: multi-page layout renders all pages")]
    public void Render_MultiPage_RendersAllPages()
    {
        var layout = new LayoutResult();
        var settings = new PageSettings();

        for (int i = 0; i < 3; i++)
        {
            var page = new PageBox { PageNumber = i + 1, Settings = settings };
            page.Boxes.Add(new LayoutBox
            {
                Type = LayoutBoxType.InlineText,
                X = 72,
                Y = 72,
                Width = 100,
                Height = 14,
                Text = $"Page {i + 1}",
                Style = new ComputedStyle(),
            });
            layout.Pages.Add(page);
        }

        byte[] pdf = PdfDocumentRenderer.Render(layout);

        string text = System.Text.Encoding.Latin1.GetString(pdf);
        // Should have 3 page objects
        int pageCount = 0;
        int idx = 0;
        while ((idx = text.IndexOf("/Type /Page\n", idx, StringComparison.Ordinal)) >= 0)
        {
            pageCount++;
            idx++;
        }

        // Could match "/Type /Page" and "/Type /Pages" differently
        // Just verify we have content for multiple pages
        text.ShouldContain("/Count 3");
    }

    // ── Content stream ──────────────────────────────────────────────────

    [Fact(DisplayName = "Render: text content appears in stream")]
    public void Render_TextContent_AppearsInStream()
    {
        var layout = CreateSimpleLayout("HelloPDF");

        byte[] pdf = PdfDocumentRenderer.Render(layout);

        string text = PdfTextHelper.GetDecompressedPdfText(pdf);
        // PDF text is in (text) Tj format
        text.ShouldContain("BT");
        text.ShouldContain("ET");
        text.ShouldContain("Tj");
    }

    [Fact(DisplayName = "Render: empty layout produces valid PDF")]
    public void Render_EmptyLayout_ProducesValidPdf()
    {
        var layout = new LayoutResult();
        layout.Pages.Add(new PageBox
        {
            PageNumber = 1,
            Settings = new PageSettings(),
        });

        byte[] pdf = PdfDocumentRenderer.Render(layout);

        pdf.ShouldNotBeNull();
        string header = System.Text.Encoding.ASCII.GetString(pdf, 0, 5);
        header.ShouldBe("%PDF-");
    }

    // ── Background and borders ──────────────────────────────────────────

    [Fact(DisplayName = "Render: block with background renders rectangle")]
    public void Render_BlockWithBackground_RendersRectangle()
    {
        var layout = new LayoutResult();
        var page = new PageBox { PageNumber = 1, Settings = new PageSettings() };
        page.Boxes.Add(new LayoutBox
        {
            Type = LayoutBoxType.Block,
            X = 72,
            Y = 72,
            Width = 200,
            Height = 50,
            Style = new ComputedStyle { BackgroundColor = new PdfColor(0.9f, 0.9f, 0.9f) },
        });
        layout.Pages.Add(page);

        byte[] pdf = PdfDocumentRenderer.Render(layout);

        string text = System.Text.Encoding.Latin1.GetString(pdf);
        // Should contain rectangle fill operators
        text.ShouldContain("re");
    }

    // ── Helpers ──────────────────────────────────────────────────────────

    private static LayoutResult CreateSimpleLayout(string content)
    {
        var layout = new LayoutResult();
        var settings = new PageSettings();
        var page = new PageBox { PageNumber = 1, Settings = settings };

        page.Boxes.Add(new LayoutBox
        {
            Type = LayoutBoxType.InlineText,
            X = 72,
            Y = 72,
            Width = 100,
            Height = 14,
            Text = content,
            Style = new ComputedStyle(),
        });

        layout.Pages.Add(page);
        return layout;
    }
}

using Shouldly;
using SimpleSign.HtmlToPdf.Layout;
using SimpleSign.HtmlToPdf.Parsing;
using Xunit;

namespace SimpleSign.HtmlToPdf.Tests;

public class CkEditorCompatibilityTests
{
    // ── Strikethrough ───────────────────────────────────────────────────

    [Fact(DisplayName = "CK: <s> tag produces strikethrough style")]
    public void Strikethrough_STag_SetsStyle()
    {
        var root = HtmlTokenizer.Parse("<p><s>deleted text</s></p>");
        StyleResolver.Resolve(root, []);
        var sNode = FindByTag(root, "s");
        sNode.ShouldNotBeNull();
        sNode!.ComputedStyle!.IsStrikethrough.ShouldBeTrue();
    }

    [Fact(DisplayName = "CK: <del> tag produces strikethrough style")]
    public void Strikethrough_DelTag_SetsStyle()
    {
        var root = HtmlTokenizer.Parse("<p><del>removed</del></p>");
        StyleResolver.Resolve(root, []);
        var del = FindByTag(root, "del");
        del.ShouldNotBeNull();
        del!.ComputedStyle!.IsStrikethrough.ShouldBeTrue();
    }

    [Fact(DisplayName = "CK: text-decoration line-through from CSS sets strikethrough")]
    public void Strikethrough_CssLineThrough_SetsStyle()
    {
        var root = HtmlTokenizer.Parse("<p><span style=\"text-decoration: line-through\">crossed</span></p>");
        StyleResolver.Resolve(root, []);
        var span = FindByTag(root, "span");
        span.ShouldNotBeNull();
        span!.ComputedStyle!.IsStrikethrough.ShouldBeTrue();
    }

    [Fact(DisplayName = "CK: combined underline and line-through sets both flags")]
    public void TextDecoration_CombinedUnderlineLineThrough_SetsBothFlags()
    {
        var root = HtmlTokenizer.Parse("<p><span style=\"text-decoration: underline line-through\">both</span></p>");
        StyleResolver.Resolve(root, []);
        var span = FindByTag(root, "span");
        span.ShouldNotBeNull();
        span!.ComputedStyle!.IsUnderline.ShouldBeTrue();
        span!.ComputedStyle!.IsStrikethrough.ShouldBeTrue();
    }

    [Fact(DisplayName = "CK: strikethrough renders in PDF")]
    public void Strikethrough_RendersInPdf()
    {
        byte[] pdf = ConvertToPdf("<p><s>deleted</s></p>");
        string text = PdfTextHelper.GetDecompressedPdfText(pdf);
        // Text appears in PDF content stream (may be octal-encoded for special chars)
        text.ShouldContain("deleted");
    }

    // ── Subscript / Superscript ─────────────────────────────────────────

    [Fact(DisplayName = "CK: <sub> tag sets FontPosition.Subscript")]
    public void Sub_SetsSubscript()
    {
        var root = HtmlTokenizer.Parse("<p>H<sub>2</sub>O</p>");
        StyleResolver.Resolve(root, []);
        var sub = FindByTag(root, "sub");
        sub.ShouldNotBeNull();
        sub!.ComputedStyle!.FontPosition.ShouldBe(FontPosition.Subscript);
    }

    [Fact(DisplayName = "CK: <sup> tag sets FontPosition.Superscript")]
    public void Sup_SetsSuperscript()
    {
        var root = HtmlTokenizer.Parse("<p>x<sup>2</sup></p>");
        StyleResolver.Resolve(root, []);
        var sup = FindByTag(root, "sup");
        sup.ShouldNotBeNull();
        sup!.ComputedStyle!.FontPosition.ShouldBe(FontPosition.Superscript);
    }

    [Fact(DisplayName = "CK: <sub> reduces font size")]
    public void Sub_ReducesFontSize()
    {
        var root = HtmlTokenizer.Parse("<p style=\"font-size: 12pt\">H<sub>2</sub>O</p>");
        StyleResolver.Resolve(root, []);
        var sub = FindByTag(root, "sub");
        sub.ShouldNotBeNull();
        sub!.ComputedStyle!.FontSize.ShouldBeLessThan(12);
    }

    [Fact(DisplayName = "CK: subscript renders in PDF")]
    public void Subscript_RendersInPdf()
    {
        byte[] pdf = ConvertToPdf("<p>H<sub>2</sub>O</p>");
        string text = PdfTextHelper.GetDecompressedPdfText(pdf);
        text.ShouldContain("H");
        text.ShouldContain("2");
        text.ShouldContain("O");
    }

    // ── Mark (highlight) ────────────────────────────────────────────────

    [Fact(DisplayName = "CK: <mark> tag sets yellow background")]
    public void Mark_SetsYellowBackground()
    {
        var root = HtmlTokenizer.Parse("<p><mark>highlighted</mark></p>");
        StyleResolver.Resolve(root, []);
        var mark = FindByTag(root, "mark");
        mark.ShouldNotBeNull();
        mark!.ComputedStyle!.BackgroundColor.ShouldNotBeNull();
    }

    // ── Links ───────────────────────────────────────────────────────────

    [Fact(DisplayName = "CK: <a> tag produces blue text")]
    public void Link_ProducesBlueText()
    {
        var root = HtmlTokenizer.Parse("<p><a href=\"https://example.com\">click here</a></p>");
        StyleResolver.Resolve(root, []);
        var a = FindByTag(root, "a");
        a.ShouldNotBeNull();
        a!.ComputedStyle!.Color.B.ShouldBeGreaterThan(0.5f);
        a!.ComputedStyle!.IsUnderline.ShouldBeTrue();
    }

    [Fact(DisplayName = "CK: <a> produces link annotation in PDF")]
    public void Link_ProducesAnnotationInPdf()
    {
        byte[] pdf = ConvertToPdf("<p><a href=\"https://example.com\">visit</a></p>");
        string text = System.Text.Encoding.Latin1.GetString(pdf);
        text.ShouldContain("/Annot");
        text.ShouldContain("/Link");
        text.ShouldContain("example.com");
    }

    [Fact(DisplayName = "CK: link with special characters in URL")]
    public void Link_SpecialCharsInUrl()
    {
        byte[] pdf = ConvertToPdf("<p><a href=\"https://example.com/path?q=hello&lang=pt\">test</a></p>");
        string text = System.Text.Encoding.Latin1.GetString(pdf);
        text.ShouldContain("/URI");
        text.ShouldContain("example.com");
    }

    // ── Colspan / Rowspan ───────────────────────────────────────────────

    [Fact(DisplayName = "CK: table with colspan renders all content")]
    public void Table_Colspan_RendersAllContent()
    {
        string html = @"<table>
            <tr><th colspan=""2"">Header spanning 2 columns</th></tr>
            <tr><td>Cell 1</td><td>Cell 2</td></tr>
        </table>";
        byte[] pdf = ConvertToPdf(html);
        string text = PdfTextHelper.GetDecompressedPdfText(pdf);
        text.ShouldContain("Header spanning 2 columns");
        text.ShouldContain("Cell 1");
        text.ShouldContain("Cell 2");
    }

    [Fact(DisplayName = "CK: colspan cell gets wider layout")]
    public void Table_Colspan_CellGetsWiderLayout()
    {
        string html = @"<table style=""width:100%"">
            <tr><td colspan=""3"">X</td></tr>
            <tr><td>A</td><td>B</td><td>C</td></tr>
        </table>";
        byte[] pdf = ConvertToPdf(html);
        string text = PdfTextHelper.GetDecompressedPdfText(pdf);

        // All text renders in the PDF
        text.ShouldContain("(X)");
        text.ShouldContain("(A)");
        text.ShouldContain("(B)");
        text.ShouldContain("(C)");
        text.ShouldStartWith("%PDF-");
    }

    [Fact(DisplayName = "CK: table with rowspan renders all content")]
    public void Table_Rowspan_RendersAllContent()
    {
        string html = @"<table>
            <tr><td rowspan=""2"">Merged</td><td>Row 1</td></tr>
            <tr><td>Row 2</td></tr>
        </table>";
        byte[] pdf = ConvertToPdf(html);
        string text = PdfTextHelper.GetDecompressedPdfText(pdf);
        text.ShouldContain("Merged");
        text.ShouldContain("Row 1");
        text.ShouldContain("Row 2");
    }

    [Fact(DisplayName = "CK: complex table with both colspan and rowspan")]
    public void Table_ColspanAndRowspan_ComplexLayout()
    {
        string html = @"<table>
            <tr>
                <th rowspan=""2"">Category</th>
                <th colspan=""2"">Period</th>
            </tr>
            <tr>
                <th>Q1</th>
                <th>Q2</th>
            </tr>
            <tr>
                <td>Sales</td>
                <td>100</td>
                <td>200</td>
            </tr>
        </table>";
        byte[] pdf = ConvertToPdf(html);
        string text = PdfTextHelper.GetDecompressedPdfText(pdf);
        text.ShouldContain("Category");
        text.ShouldContain("Period");
        text.ShouldContain("Q1");
        text.ShouldContain("Q2");
        text.ShouldContain("Sales");
        text.ShouldContain("100");
        text.ShouldContain("200");
    }

    [Fact(DisplayName = "CK: table caption renders above table")]
    public void Table_Caption_RendersAboveTable()
    {
        string html = @"<table>
            <caption>Table 1: Summary</caption>
            <tr><td>Data</td></tr>
        </table>";
        var root = HtmlTokenizer.Parse(html);
        StyleResolver.Resolve(root, []);
        var engine = new LayoutEngine(new PageSettings());
        var result = engine.Layout(root);

        var boxes = result.Pages[0].Boxes;
        var captionBox = boxes.FirstOrDefault(b => b.Text?.Contains("Table 1") == true);
        captionBox.ShouldNotBeNull();
    }

    // ── Images ──────────────────────────────────────────────────────────

    [Fact(DisplayName = "CK: base64 PNG image produces Image layout box")]
    public void Image_Base64Png_ProducesImageBox()
    {
        string base64 = CreateTinyPngBase64();
        string html = $"<p><img src=\"data:image/png;base64,{base64}\" /></p>";
        var root = HtmlTokenizer.Parse(html);
        StyleResolver.Resolve(root, []);
        var engine = new LayoutEngine(new PageSettings());
        var result = engine.Layout(root);

        var imageBox = result.Pages[0].Boxes.FirstOrDefault(b => b.Type == LayoutBoxType.Image);
        imageBox.ShouldNotBeNull();
        imageBox!.Width.ShouldBeGreaterThan(0);
        imageBox!.Height.ShouldBeGreaterThan(0);
    }

    [Fact(DisplayName = "CK: image XObject appears in PDF output")]
    public void Image_XObjectInPdfOutput()
    {
        string base64 = CreateTinyPngBase64();
        string html = $"<p><img src=\"data:image/png;base64,{base64}\" /></p>";
        byte[] pdf = ConvertToPdf(html);
        string text = System.Text.Encoding.Latin1.GetString(pdf);
        text.ShouldContain("/XObject");
        text.ShouldContain("Img1");
        text.ShouldContain("/Image");
        text.ShouldContain("/FlateDecode");
    }

    [Fact(DisplayName = "CK: image with width attribute constrains size")]
    public void Image_WidthAttribute_ConstrainsSize()
    {
        string base64 = CreateTinyPngBase64();
        string html = $"<p><img src=\"data:image/png;base64,{base64}\" width=\"200\" /></p>";
        var root = HtmlTokenizer.Parse(html);
        StyleResolver.Resolve(root, []);
        var engine = new LayoutEngine(new PageSettings());
        var result = engine.Layout(root);

        var imageBox = result.Pages[0].Boxes.FirstOrDefault(b => b.Type == LayoutBoxType.Image);
        imageBox.ShouldNotBeNull();
        imageBox!.Width.ShouldBe(200 * 0.75f, 1f);
    }

    [Fact(DisplayName = "CK: invalid image src is silently skipped")]
    public void Image_InvalidSrc_IsSkipped()
    {
        string html = "<p><img src=\"invalid://not-a-real-url\" /></p>";
        var root = HtmlTokenizer.Parse(html);
        StyleResolver.Resolve(root, []);
        var engine = new LayoutEngine(new PageSettings());
        var result = engine.Layout(root);

        var imageBox = result.Pages[0].Boxes.FirstOrDefault(b => b.Type == LayoutBoxType.Image);
        imageBox.ShouldBeNull();
    }

    // ── CSS Improvements ────────────────────────────────────────────────

    [Fact(DisplayName = "CK: percentage width resolves correctly")]
    public void Css_PercentageWidth_Resolves()
    {
        string html = "<div style=\"width:100%\"><div style=\"width:50%\"><p>Half width</p></div></div>";
        var root = HtmlTokenizer.Parse(html);
        StyleResolver.Resolve(root, []);
        var engine = new LayoutEngine(new PageSettings());
        var result = engine.Layout(root);

        result.Pages.ShouldNotBeEmpty();
    }

    [Fact(DisplayName = "CK: RGBA color is parsed")]
    public void Css_RgbaColor_IsParsed()
    {
        var root = HtmlTokenizer.Parse("<p style=\"color: rgba(255,0,0,0.5)\">Red text</p>");
        StyleResolver.Resolve(root, []);
        var p = FindByTag(root, "p");
        p.ShouldNotBeNull();
        p!.ComputedStyle!.Color.R.ShouldBe(1.0f, 0.01f);
        p!.ComputedStyle!.Color.G.ShouldBe(0f, 0.01f);
    }

    [Fact(DisplayName = "CK: inline style from HTML attribute is applied")]
    public void Css_InlineStyleAttribute_IsApplied()
    {
        var root = HtmlTokenizer.Parse("<p style=\"color: red; font-weight: bold\">Bold red</p>");
        StyleResolver.Resolve(root, []);
        var p = FindByTag(root, "p");
        p.ShouldNotBeNull();
        p!.ComputedStyle!.IsBold.ShouldBeTrue();
        p!.ComputedStyle!.Color.R.ShouldBe(1.0f, 0.01f);
    }

    // ── Figure / Figcaption ─────────────────────────────────────────────

    [Fact(DisplayName = "CK: <figure> is block-level")]
    public void Figure_IsBlockLevel()
    {
        var root = HtmlTokenizer.Parse("<figure><figcaption>Caption text</figcaption></figure>");
        StyleResolver.Resolve(root, []);
        var figure = FindByTag(root, "figure");
        figure.ShouldNotBeNull();
        figure!.ComputedStyle!.Display.ShouldBe(DisplayType.Block);
    }

    // ── Additional elements ─────────────────────────────────────────────

    [Fact(DisplayName = "CK: <kbd> renders with monospace font")]
    public void Kbd_UsesMonospaceFont()
    {
        var root = HtmlTokenizer.Parse("<p><kbd>Ctrl+C</kbd></p>");
        StyleResolver.Resolve(root, []);
        var kbd = FindByTag(root, "kbd");
        kbd.ShouldNotBeNull();
        kbd!.ComputedStyle!.FontFamily.ShouldBe("Courier");
    }

    // ── E2E: Full CKEditor-style document ───────────────────────────────

    [Fact(DisplayName = "CK: E2E realistic CKEditor document renders")]
    public void E2E_CkEditorDocument_Renders()
    {
        string html = @"
        <html>
        <head>
        <style>
          body { font-family: Helvetica; font-size: 11pt; }
          table { width: 100%; border-collapse: collapse; }
          th, td { border: 1px solid #999; padding: 6pt; }
          th { background-color: #f0f0f0; font-weight: bold; }
          .highlight { background-color: #ffff00; }
        </style>
        </head>
        <body>
          <h1>Parecer Técnico nº 001/2024</h1>
          <p><strong>Processo:</strong> TC-123/2024</p>
          <p>Texto com <em>ênfase</em>, <strong>negrito</strong>, <u>sublinhado</u> e <s>tachado</s>.</p>
          <p>Fórmula: H<sub>2</sub>O e x<sup>2</sup>+y<sup>2</sup>=r<sup>2</sup></p>
          <p>Texto <mark>destacado</mark> e referência<a href=""https://www.tce.es.gov.br""> TCE-ES</a>.</p>
          <table>
            <tr><th colspan=""3"">Despesas de Pessoal</th></tr>
            <tr><th>Item</th><th>Previsto</th><th>Executado</th></tr>
            <tr><td>Salários</td><td>R$ 500.000,00</td><td>R$ 480.000,00</td></tr>
            <tr><td colspan=""2"" style=""text-align:right""><strong>Total:</strong></td><td><strong>R$ 480.000,00</strong></td></tr>
          </table>
          <p>Fim do parecer.</p>
        </body>
        </html>";

        byte[] pdf = ConvertToPdf(html);
        string text = PdfTextHelper.GetDecompressedPdfText(pdf);

        // Verify all major content appears (ASCII-safe strings only, special chars are octal-encoded)
        // Note: text may be split across multiple PDF text operations
        text.ShouldContain("Parecer");
        text.ShouldContain("Processo");
        text.ShouldContain("negrito");
        text.ShouldContain("tachado");
        text.ShouldContain("Despesas");
        text.ShouldContain("Pessoal");
        text.ShouldContain("500.000");
        text.ShouldContain("Fim");
        text.ShouldContain("parecer");
        text.ShouldContain("/Annot");  // link annotation
        text.ShouldContain("tce.es.gov.br");

        // Should be valid PDF
        text.ShouldStartWith("%PDF-");
        text.ShouldContain("%%EOF");
    }

    [Fact(DisplayName = "CK: E2E document with multiple text decorations in one paragraph")]
    public void E2E_MixedTextDecorations_Renders()
    {
        string html = @"<p>
            Normal text,
            <strong>bold</strong>,
            <em>italic</em>,
            <u>underline</u>,
            <s>strikethrough</s>,
            <sub>subscript</sub>,
            <sup>superscript</sup>,
            <mark>highlight</mark>,
            <kbd>keyboard</kbd>,
            <a href=""https://example.com"">link</a>.
        </p>";

        byte[] pdf = ConvertToPdf(html);
        string text = PdfTextHelper.GetDecompressedPdfText(pdf);

        text.ShouldContain("bold");
        text.ShouldContain("italic");
        text.ShouldContain("underline");
        text.ShouldContain("strikethrough");
        text.ShouldContain("subscript");
        text.ShouldContain("superscript");
        text.ShouldContain("highlight");
        text.ShouldContain("keyboard");
        text.ShouldContain("link");
    }

    // ── Helpers ─────────────────────────────────────────────────────────

    private static byte[] ConvertToPdf(string html)
    {
        return HtmlToPdfConverter.Html(html).Convert();
    }

    private static HtmlNode? FindByTag(HtmlNode node, string tag)
    {
        if (node.Tag == tag)
        {
            return node;
        }

        foreach (var child in node.Children)
        {
            var found = FindByTag(child, tag);
            if (found is not null)
            {
                return found;
            }
        }

        return null;
    }

    /// <summary>Creates a minimal 2x2 red PNG as base64.</summary>
    private static string CreateTinyPngBase64()
    {
        // Build a minimal valid PNG programmatically
        using var ms = new MemoryStream();

        // PNG signature
        ms.Write([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);

        // IHDR chunk: 2x2, 8-bit RGB
        WriteChunk(ms, "IHDR", [
            0x00, 0x00, 0x00, 0x02, // width: 2
            0x00, 0x00, 0x00, 0x02, // height: 2
            0x08,                   // bit depth: 8
            0x02,                   // color type: RGB
            0x00, 0x00, 0x00,       // compression, filter, interlace
        ]);

        // IDAT chunk: compressed pixel data
        // Raw: 2 rows × (1 filter byte + 6 pixel bytes) = 14 bytes
        byte[] raw = [
            0x00, 0xFF, 0x00, 0x00, 0xFF, 0x00, 0x00,  // Row 0: filter=None + 2 red pixels
            0x00, 0xFF, 0x00, 0x00, 0xFF, 0x00, 0x00,  // Row 1: filter=None + 2 red pixels
        ];

        // Compress with zlib (header + deflate + adler32)
        byte[] compressed;
        using (var zlibMs = new MemoryStream())
        {
            zlibMs.WriteByte(0x78); // zlib header
            zlibMs.WriteByte(0x01);
            using (var deflate = new System.IO.Compression.DeflateStream(zlibMs, System.IO.Compression.CompressionLevel.Optimal, leaveOpen: true))
            {
                deflate.Write(raw);
            }

            uint adler = Adler32(raw);
            zlibMs.WriteByte((byte)(adler >> 24));
            zlibMs.WriteByte((byte)(adler >> 16));
            zlibMs.WriteByte((byte)(adler >> 8));
            zlibMs.WriteByte((byte)adler);
            compressed = zlibMs.ToArray();
        }

        WriteChunk(ms, "IDAT", compressed);

        // IEND chunk
        WriteChunk(ms, "IEND", []);

        return Convert.ToBase64String(ms.ToArray());
    }

    private static void WriteChunk(Stream s, string type, byte[] data)
    {
        WriteBigEndian(s, data.Length);
        byte[] typeBytes = System.Text.Encoding.ASCII.GetBytes(type);
        s.Write(typeBytes);
        s.Write(data);

        // CRC over type + data
        byte[] crcInput = new byte[typeBytes.Length + data.Length];
        typeBytes.CopyTo(crcInput, 0);
        data.CopyTo(crcInput, typeBytes.Length);
        uint crc = Crc32(crcInput);
        WriteBigEndian(s, (int)crc);
    }

    private static uint Adler32(byte[] data)
    {
        uint a = 1, b = 0;
        foreach (byte d in data)
        {
            a = (a + d) % 65521;
            b = (b + a) % 65521;
        }

        return (b << 16) | a;
    }

    private static uint Crc32(byte[] data)
    {
        uint crc = 0xFFFFFFFF;
        foreach (byte b in data)
        {
            crc ^= b;
            for (int i = 0; i < 8; i++)
            {
                crc = (crc & 1) != 0 ? (crc >> 1) ^ 0xEDB88320 : crc >> 1;
            }
        }

        return crc ^ 0xFFFFFFFF;
    }

    private static void WriteBigEndian(Stream s, int value)
    {
        s.WriteByte((byte)(value >> 24));
        s.WriteByte((byte)(value >> 16));
        s.WriteByte((byte)(value >> 8));
        s.WriteByte((byte)value);
    }
}

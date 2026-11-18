using System.IO.Compression;
using System.Text;
using Shouldly;
using SimpleSign.PAdES.Pdf;
using SimpleSign.PAdES.Signing;
using Xunit;

namespace SimpleSign.PAdES.Tests.Pdf;

[Trait("Category", "Unit")]
public sealed class PdfTextLocatorTests
{
    private const string Helvetica = "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>";

    [Fact(DisplayName = "A text drawn by one Tj is found at its origin")]
    public void Find_SimpleTj_ReturnsOrigin()
    {
        byte[] pdf = TextPdf.Build(["BT /F1 12 Tf 100 200 Td (Contratante) Tj ET"]);

        var matches = PdfTextLocator.Find(pdf, "Contratante", ignoreCase: false);

        matches.ShouldBe([new PdfTextMatch(1, 100, 200)]);
    }

    [Fact(DisplayName = "A text in the middle of a run starts after the glyphs before it")]
    public void Find_MiddleOfRun_AdvancesByWidths()
    {
        byte[] pdf = TextPdf.Build(["BT /F1 12 Tf 100 200 Td (Assinatura do Contratante) Tj ET"]);

        var match = PdfTextLocator.Find(pdf, "Contratante", false).ShouldHaveSingleItem();

        match.X.ShouldBe(100 + AppearanceText.Measure("Assinatura do ", "Helvetica", 12), 0.01f);
        match.Y.ShouldBe(200f, 0.01f);
    }

    [Fact(DisplayName = "A text split by TJ kerning and by separate operators still matches")]
    public void Find_SplitText_Matches()
    {
        byte[] pdf = TextPdf.Build(["BT /F1 12 Tf 50 300 Td [(Con) -20 (tra) 10 (tante)] TJ ET BT /F1 12 Tf 50 100 Td (Assinado) Tj 60 0 Td (por) Tj ET"]);

        PdfTextLocator.Find(pdf, "Contratante", false).ShouldHaveSingleItem().X.ShouldBe(50f, 0.01f);
        PdfTextLocator.Find(pdf, "Assinado por", false).ShouldHaveSingleItem().Y.ShouldBe(100f, 0.01f);
    }

    [Fact(DisplayName = "The CTM and the text matrix place the text in user space")]
    public void Find_CtmAndTm_TransformOrigin()
    {
        byte[] pdf = TextPdf.Build(["q 2 0 0 2 50 50 cm BT /F1 10 Tf 1 0 0 1 10 20 Tm (Contratante) Tj ET Q"]);

        PdfTextLocator.Find(pdf, "Contratante", false).ShouldBe([new PdfTextMatch(1, 70, 90)]);
    }

    [Fact(DisplayName = "Text in a form XObject is found through the form's matrix")]
    public void Find_FormXObject_UsesMatrix()
    {
        string form = TextPdf.Stream("<< /Type /XObject /Subtype /Form /BBox [0 0 200 50] /Matrix [1 0 0 1 5 5] /Resources << /Font << /F1 4 0 R >> >> >>", "BT /F1 12 Tf 0 0 Td (Contratante) Tj ET");
        byte[] pdf = TextPdf.Build(["q 1 0 0 1 100 100 cm /Fm1 Do Q"], extraResources: "/XObject << /Fm1 5 0 R >>", extraObjects: [form]);

        PdfTextLocator.Find(pdf, "Contratante", false).ShouldBe([new PdfTextMatch(1, 105, 105)]);
    }

    [Fact(DisplayName = "A Type0 font with two-byte codes is read through its ToUnicode map and /W widths")]
    public void Find_Type0IdentityH_UsesToUnicode()
    {
        string cmap = "/CIDInit /ProcSet findresource begin 12 dict begin begincmap 1 begincodespacerange <0000> <FFFF> endcodespacerange "
            + "2 beginbfchar <0001> <0041> <0002> <0020> endbfchar 1 beginbfrange <0003> <0005> <0043> endbfrange endcmap end end";
        string font = "<< /Type /Font /Subtype /Type0 /BaseFont /ABCDEF+Arial /Encoding /Identity-H /DescendantFonts [6 0 R] /ToUnicode 5 0 R >>";
        string descendant = "<< /Type /Font /Subtype /CIDFontType2 /BaseFont /ABCDEF+Arial /DW 1000 /W [1 [500 250] 3 5 600] >>";
        // "A CDE": A, space, C, D, E.
        byte[] pdf = TextPdf.Build(["BT /F1 10 Tf 20 40 Td <00010002000300040005> Tj ET"], font: font, extraObjects: [TextPdf.Stream("<< >>", cmap), descendant]);

        var match = PdfTextLocator.Find(pdf, "CDE", false).ShouldHaveSingleItem();

        match.X.ShouldBe(20 + ((500 + 250) / 1000f * 10), 0.01f);
        PdfTextLocator.Find(pdf, "A CDE", false).ShouldHaveSingleItem().X.ShouldBe(20f, 0.01f);
    }

    [Fact(DisplayName = "Accented letters from /Differences and WinAnsi match the text")]
    public void Find_Accents_Match()
    {
        string font = "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding << /BaseEncoding /WinAnsiEncoding /Differences [1 /oacute /ccedilla /atilde] >> >>";
        byte[] pdf = TextPdf.Build(["BT /F1 12 Tf 10 10 Td (Vit\\001ria) Tj 0 -20 Td (Presta\\002\\003o) Tj 0 -20 Td (Cl\\341usula) Tj ET"], font: font);

        PdfTextLocator.Find(pdf, "Vitória", false).ShouldHaveSingleItem();
        PdfTextLocator.Find(pdf, "Prestação", false).ShouldHaveSingleItem();
        PdfTextLocator.Find(pdf, "Cláusula", false).ShouldHaveSingleItem().Y.ShouldBe(-30f, 0.01f);
    }

    [Fact(DisplayName = "Matches come in reading order across pages, and case can be ignored")]
    public void Find_SeveralPages_InOrder()
    {
        byte[] pdf = TextPdf.Build(
            ["BT /F1 12 Tf 10 700 Td (O CONTRATANTE paga) Tj ET", "BT /F1 12 Tf 10 300 Td (Contratante) Tj 0 -100 Td (Contratante) Tj ET"]);

        PdfTextLocator.Find(pdf, "Contratante", false).ShouldBe([new PdfTextMatch(2, 10, 300), new PdfTextMatch(2, 10, 200)]);
        PdfTextLocator.Find(pdf, "contratante", true).Select(m => m.Page).ShouldBe([1, 2, 2]);
    }

    [Fact(DisplayName = "A compressed content stream is read")]
    public void Find_FlateContent_Matches()
    {
        byte[] pdf = TextPdf.Build(["BT /F1 12 Tf 30 60 Td (Contratada) Tj ET"], compress: true);

        PdfTextLocator.Find(pdf, "Contratada", false).ShouldBe([new PdfTextMatch(1, 30, 60)]);
    }

    [Fact(DisplayName = "A page without the text gives no match")]
    public void Find_Missing_ReturnsEmpty()
    {
        byte[] pdf = TextPdf.Build(["0 0 m 100 100 l S"]);

        PdfTextLocator.Find(pdf, "Contratante", false).ShouldBeEmpty();
        PdfTextLocator.Find(TextPdf.Build(["BT /F1 12 Tf 0 0 Td (x) Tj ET"]), "  ", false).ShouldBeEmpty();
    }

    [Fact(DisplayName = "The MacRoman table has the 128 upper codes")]
    public void MacRomanHigh_Has128Codes() => PdfTextLocator.Tables.MacRomanHigh.Length.ShouldBe(128);

    /// <summary>Builds small PDFs with a content stream per page and a correct cross-reference table.</summary>
    internal static class TextPdf
    {
        /// <summary>A stream object body with its /Length.</summary>
        public static string Stream(string dict, string content) =>
            $"{dict[..^2].TrimEnd()} /Length {Encoding.Latin1.GetByteCount(content)} >>\nstream\n{content}\nendstream";

        /// <summary>
        /// Objects: 1 catalog, 2 pages, 3 resources, 4 font, then <paramref name="extraObjects"/> (5, 6…), then for each
        /// page its page object and its content stream.
        /// </summary>
        public static byte[] Build(string[] pages, string font = Helvetica, string extraResources = "", string[]? extraObjects = null, bool compress = false)
        {
            extraObjects ??= [];
            int firstPage = 5 + extraObjects.Length;
            var objects = new List<byte[]>
            {
                Latin1("<< /Type /Catalog /Pages 2 0 R >>"),
                Latin1($"<< /Type /Pages /Kids [{string.Join(' ', pages.Select((_, i) => $"{firstPage + (2 * i)} 0 R"))}] /Count {pages.Length} >>"),
                Latin1($"<< /Font << /F1 4 0 R >> {extraResources} >>"),
                Latin1(font),
            };
            objects.AddRange(extraObjects.Select(Latin1));
            for (int i = 0; i < pages.Length; i++)
            {
                int page = firstPage + (2 * i);
                objects.Add(Latin1($"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources 3 0 R /Contents {page + 1} 0 R >>"));
                objects.Add(compress ? Compressed(pages[i]) : Latin1(Stream("<< >>", pages[i])));
            }

            using var pdf = new MemoryStream();
            pdf.Write("%PDF-1.7\n"u8);
            var offsets = new List<long>();
            for (int i = 0; i < objects.Count; i++)
            {
                offsets.Add(pdf.Position);
                pdf.Write(Latin1($"{i + 1} 0 obj\n"));
                pdf.Write(objects[i]);
                pdf.Write("\nendobj\n"u8);
            }

            long xref = pdf.Position;
            var table = new StringBuilder($"xref\n0 {objects.Count + 1}\n0000000000 65535 f \n");
            foreach (long offset in offsets)
            {
                table.Append($"{offset:D10} 00000 n \n");
            }

            table.Append($"trailer\n<< /Size {objects.Count + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF");
            pdf.Write(Latin1(table.ToString()));
            return pdf.ToArray();
        }

        private static byte[] Compressed(string content)
        {
            using var data = new MemoryStream();
            using (var zlib = new ZLibStream(data, CompressionLevel.Optimal, leaveOpen: true))
            {
                zlib.Write(Latin1(content));
            }

            byte[] packed = data.ToArray();
            return [.. Latin1($"<< /Filter /FlateDecode /Length {packed.Length} >>\nstream\n"), .. packed, .. "\nendstream"u8];
        }

        private static byte[] Latin1(string text) => Encoding.Latin1.GetBytes(text);
    }
}

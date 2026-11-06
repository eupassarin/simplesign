// Licensed to SimpleSign under the MIT License.

using System.Text;
using Shouldly;
using Xunit;
using static SimpleSign.HtmlToPdf.Tests.TestSupport;

namespace SimpleSign.HtmlToPdf.Tests;

[Trait("Category", "Unit")]
public sealed class DocumentConversionTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("h2p-").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    [Fact]
    public void Convert_StyleElementInHead_IsAppliedAndNotRenderedAsText()
    {
        byte[] pdf = HtmlToPdfConverter.Html(
            "<html><head><style>p { color: #ff0000; } .secret-selector { color: blue; }</style></head><body><p>Visible</p></body></html>")
            .Convert();

        string text = Decompressed(pdf);
        text.ShouldContain("(Visible) Tj");
        text.ShouldNotContain("secret-selector");
        text.ShouldContain("1.00 0.00 0.00 rg");
    }

    [Fact]
    public void Convert_StyleElementWithScreenMedia_IsIgnored()
    {
        byte[] pdf = HtmlToPdfConverter.Html("<style media='screen'>p { color: #ff0000; }</style><p>x</p>").Convert();

        Decompressed(pdf).ShouldNotContain("1.00 0.00 0.00 rg");
    }

    [Fact]
    public void Convert_BuilderStylesheet_OverridesDocumentStyles()
    {
        byte[] pdf = HtmlToPdfConverter.Html("<style>p { color: #0000ff; }</style><p>x</p>")
            .WithStylesheet("p { color: #ff0000; }")
            .Convert();

        Decompressed(pdf).ShouldContain("1.00 0.00 0.00 rg");
    }

    [Fact]
    public void Convert_TitleElement_BecomesMetadataTitle()
    {
        byte[] pdf = HtmlToPdfConverter.Html("<html><head><title>  Relatório   Anual </title></head><body>x</body></html>").Convert();

        string raw = Encoding.Latin1.GetString(pdf);
        raw.ShouldContain("/Title <FEFF");
        raw.ShouldNotContain("(Relat"); // non-ASCII titles are UTF-16 encoded
    }

    [Fact]
    public void Convert_HtmlLang_WritesCatalogLang()
    {
        byte[] pdf = HtmlToPdfConverter.Html("<html lang='pt-BR'><body>x</body></html>").Convert();

        Encoding.Latin1.GetString(pdf).ShouldContain("/Lang (pt-BR)");
    }

    [Fact]
    public void Convert_PageRule_SetsSizeAndMargins()
    {
        byte[] pdf = HtmlToPdfConverter.Html("<style>@page { size: A5 landscape; margin: 0; }</style><p>x</p>").Convert();

        Encoding.Latin1.GetString(pdf).ShouldContain("/MediaBox [0 0 595.28 419.53]");
    }

    [Fact]
    public void Convert_PageRuleExplicitSize_IsUsed()
    {
        byte[] pdf = HtmlToPdfConverter.Html("<style>@page { size: 100mm 50mm; }</style><p>x</p>").Convert();

        Encoding.Latin1.GetString(pdf).ShouldContain("/MediaBox [0 0 283.46 141.73]");
    }

    [Fact]
    public void Convert_BuilderPageSize_OverridesPageRule()
    {
        byte[] pdf = HtmlToPdfConverter.Html("<style>@page { size: A5; }</style><p>x</p>")
            .WithPageSize(PageSize.Letter)
            .Convert();

        Encoding.Latin1.GetString(pdf).ShouldContain("/MediaBox [0 0 612.00 792.00]");
    }

    [Theory]
    [InlineData("A4", 595.28f, 841.89f)]
    [InlineData("letter landscape", 792f, 612f)]
    [InlineData("portrait", 595.28f, 841.89f)]
    [InlineData("8.5in 11in", 612f, 792f)]
    public void ParsePageSize_Values_ResolveToPoints(string value, float width, float height)
    {
        (float w, float h) = ConversionPipeline.ParsePageSize(value)!.Value;

        w.ShouldBe(width, 0.01f);
        h.ShouldBe(height, 0.01f);
    }

    [Fact]
    public void Convert_LinkedStylesheet_LoadedFromBaseDirectory()
    {
        File.WriteAllText(Path.Combine(_dir, "site.css"), "p { color: #ff0000; }");

        byte[] pdf = HtmlToPdfConverter.Html("<link rel='stylesheet' href='site.css'><p>x</p>")
            .WithBaseDirectory(_dir)
            .Convert();

        Decompressed(pdf).ShouldContain("1.00 0.00 0.00 rg");
    }

    [Fact]
    public void Convert_RelativeImage_LoadedFromBaseDirectory()
    {
        File.WriteAllBytes(Path.Combine(_dir, "logo.png"), RgbPng());

        byte[] pdf = HtmlToPdfConverter.Html("<img src='logo.png' alt='missing'>").WithBaseDirectory(_dir).Convert();

        string text = Decompressed(pdf);
        text.ShouldContain("/Subtype /Image");
        text.ShouldNotContain("[missing]");
    }

    [Fact]
    public void Convert_PathTraversal_IsNotLoaded()
    {
        string inner = Directory.CreateDirectory(Path.Combine(_dir, "inner")).FullName;
        File.WriteAllBytes(Path.Combine(_dir, "outside.png"), RgbPng());

        byte[] pdf = HtmlToPdfConverter.Html("<img src='../outside.png' alt='blocked'>").WithBaseDirectory(inner).Convert();

        string text = Decompressed(pdf);
        text.ShouldNotContain("/Subtype /Image");
        text.ShouldContain("[blocked]");
    }

    [Fact]
    public void Convert_WithoutBaseDirectory_DoesNotReadLocalFiles()
    {
        string file = Path.Combine(_dir, "a.png");
        File.WriteAllBytes(file, RgbPng());

        byte[] pdf = HtmlToPdfConverter.Html($"<img src='{file}'>").Convert();

        Decompressed(pdf).ShouldNotContain("/Subtype /Image");
    }

    [Fact]
    public void Convert_ResourceLoader_ResolvesCustomReferences()
    {
        var requested = new List<string>();
        byte[] pdf = HtmlToPdfConverter.Html("<img src='https://cdn.example/logo.png'>")
            .WithResourceLoader(reference =>
            {
                requested.Add(reference);
                return RgbPng();
            })
            .Convert();

        requested.ShouldContain("https://cdn.example/logo.png");
        Decompressed(pdf).ShouldContain("/Subtype /Image");
    }

    [Fact]
    public void Convert_FontFaceDataUri_RegistersEmbeddedFont()
    {
        string font = Convert.ToBase64String(LoadTestFont());
        string html = $"<style>@font-face {{ font-family: 'Doc Sans'; src: url(data:font/ttf;base64,{font}) format('truetype'); }} p {{ font-family: 'Doc Sans'; }}</style><p>Olá</p>";

        byte[] pdf = HtmlToPdfConverter.Html(html).Convert();

        string raw = Encoding.Latin1.GetString(pdf);
        raw.ShouldContain("/Subtype /Type0");
        raw.ShouldContain("+DocSans");
    }

    [Fact]
    public void Convert_LongTable_SpansSeveralPagesAndRepeatsHeader()
    {
        string rows = string.Concat(Enumerable.Range(1, 120).Select(i => $"<tr><td>Row {i}</td><td>Value {i}</td></tr>"));
        byte[] pdf = HtmlToPdfConverter.Html($"<table><thead><tr><th>HeaderCell</th><th>B</th></tr></thead><tbody>{rows}</tbody></table>").Convert();

        int pages = PageCount(pdf);
        pages.ShouldBeGreaterThan(2);
        string text = Decompressed(pdf);
        CountOccurrences(text, "(HeaderCell) Tj").ShouldBe(pages);
        text.ShouldContain("(Row 120) Tj");
    }

    [Fact]
    public void Convert_PdfA_WritesOutputIntentXmpAndId()
    {
        byte[] pdf = HtmlToPdfConverter.Html("<h1>Arquivo</h1><p>Texto <a href='https://x.y'>link</a></p>")
            .WithFont("Doc Sans", LoadTestFont())
            .WithTitle("Título & <arquivo>")
            .WithAuthor("Andre")
            .WithFooter("{page}/{pages}")
            .WithPdfA()
            .Convert();

        string raw = Encoding.Latin1.GetString(pdf);
        raw.ShouldContain("/OutputIntents [<< /Type /OutputIntent /S /GTS_PDFA1");
        raw.ShouldContain("/DestOutputProfile");
        raw.ShouldContain("<pdfaid:part>2</pdfaid:part>");
        raw.ShouldContain("<pdfaid:conformance>B</pdfaid:conformance>");
        raw.ShouldContain("T&#237;tulo &amp; &lt;arquivo&gt;".Replace("&#237;", "í", StringComparison.Ordinal).Replace("í", "Ã­", StringComparison.Ordinal));
        raw.ShouldContain("/ID [<");
        raw.ShouldContain("/F 4");
        raw.ShouldNotContain("/Subtype /Type1"); // no standard (non-embedded) fonts, not even in the footer
    }

    [Fact]
    public void Convert_PdfAWithoutFonts_Throws()
    {
        Should.Throw<InvalidOperationException>(() => HtmlToPdfConverter.Html("<p>x</p>").WithPdfA().Convert())
            .Message.ShouldContain("embedded");
    }

    [Fact]
    public void Convert_TrailerAlwaysHasFileIdentifier()
    {
        byte[] pdf = HtmlToPdfConverter.Html("<p>x</p>").Convert();

        Encoding.Latin1.GetString(pdf).ShouldContain("/ID [<");
    }

    [Fact]
    public void WithBaseDirectory_MissingDirectory_Throws() =>
        Should.Throw<DirectoryNotFoundException>(() => HtmlToPdfConverter.Html("x").WithBaseDirectory(Path.Combine(_dir, "nope")));

    [Fact]
    public void WithFont_InvalidData_ThrowsAtRegistration() =>
        Should.Throw<ArgumentException>(() => HtmlToPdfConverter.Html("x").WithFont("Bad", [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]));

    private static int CountOccurrences(string text, string value)
    {
        int count = 0;
        int index = 0;
        while ((index = text.IndexOf(value, index, StringComparison.Ordinal)) >= 0)
        {
            count++;
            index += value.Length;
        }

        return count;
    }
}

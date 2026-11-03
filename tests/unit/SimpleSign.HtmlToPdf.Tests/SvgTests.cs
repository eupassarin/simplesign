// Licensed to SimpleSign under the MIT License.

using System.Text;
using Shouldly;
using SimpleSign.HtmlToPdf.Layout;
using SimpleSign.HtmlToPdf.Parsing;
using SimpleSign.HtmlToPdf.Rendering.Svg;
using Xunit;
using static SimpleSign.HtmlToPdf.Tests.TestSupport;

namespace SimpleSign.HtmlToPdf.Tests;

[Trait("Category", "Unit")]
public sealed class SvgTests
{
    private const string Logo = """
        <svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 100 50" width="200" height="100">
          <style>.c { fill: #00ff00; }</style>
          <rect class="c" width="100" height="50"/>
        </svg>
        """;

    private static string SvgDataUri(string svg) => "data:image/svg+xml;base64," + Convert.ToBase64String(Encoding.UTF8.GetBytes(svg));

    private static string Pdf(string html) => Decompressed(HtmlToPdfConverter.Html(html).Convert());

    // ── Path parsing ─────────────────────────────────────────────────────

    [Fact]
    public void PathParser_AbsoluteAndRelativeCommands()
    {
        List<PathSegment> segments = SvgPathParser.Parse("M10 10 l5 0 L20 20 h-5 v5 z");

        segments.Select(s => s.Kind).ShouldBe(['M', 'L', 'L', 'L', 'L', 'Z']);
        segments[1].X.ShouldBe(15f);
        segments[3].X.ShouldBe(15f);
        segments[4].Y.ShouldBe(25f);
    }

    [Fact]
    public void PathParser_ImplicitLineToAfterMove() =>
        SvgPathParser.Parse("m0 0 10 0 0 10").Select(s => (s.Kind, s.X, s.Y)).ShouldBe([('M', 0f, 0f), ('L', 10f, 0f), ('L', 10f, 10f)]);

    [Fact]
    public void PathParser_CompactNumbers()
    {
        List<PathSegment> segments = SvgPathParser.Parse("M.5.5L-1-2e1");

        segments[0].X.ShouldBe(0.5f);
        segments[0].Y.ShouldBe(0.5f);
        segments[1].X.ShouldBe(-1f);
        segments[1].Y.ShouldBe(-20f);
    }

    [Fact]
    public void PathParser_QuadraticBecomesCubic()
    {
        PathSegment q = SvgPathParser.Parse("M0 0 Q 30 30 60 0")[1];

        q.Kind.ShouldBe('C');
        q.X1.ShouldBe(20f, 0.001f);
        q.Y1.ShouldBe(20f, 0.001f);
        q.X.ShouldBe(60f);
    }

    [Fact]
    public void PathParser_SmoothCubicReflectsControlPoint()
    {
        List<PathSegment> s = SvgPathParser.Parse("M0 0 C 10 10 20 10 30 0 S 50 -10 60 0");

        s[2].X1.ShouldBe(40f, 0.001f);
        s[2].Y1.ShouldBe(-10f, 0.001f);
    }

    [Fact]
    public void PathParser_ArcEndsAtTarget()
    {
        List<PathSegment> s = SvgPathParser.Parse("M0 0 A 10 10 0 0 1 20 0");

        s.Count(x => x.Kind == 'C').ShouldBe(2);
        s[^1].X.ShouldBe(20f);
        s[^1].Y.ShouldBe(0f);

        // A semicircle sweeping clockwise (y-down) bulges to negative y.
        s.Skip(1).Min(x => Math.Min(x.Y1, x.Y2)).ShouldBeLessThan(-5f);
    }

    [Fact]
    public void PathParser_CompactArcFlags() =>
        SvgPathParser.Parse("M0 0a5 5 0 1010 0")[^1].X.ShouldBe(10f, 0.001f);

    [Fact]
    public void PathParser_InvalidData_StopsAtError() =>
        SvgPathParser.Parse("M0 0 L10 10 X 5 5").Count.ShouldBe(2);

    [Fact]
    public void ParseTransform_RotateAboutPoint()
    {
        Matrix2D m = SvgRenderer.ParseTransform("rotate(90 10 10)")!.Value;
        (float x, float y) = m.Apply(20, 10);

        x.ShouldBe(10f, 0.001f);
        y.ShouldBe(20f, 0.001f);
    }

    [Fact]
    public void ParseTransform_ListAppliesRightmostFirst() =>
        SvgRenderer.ParseTransform("translate(10,0) scale(2)")!.Value.Apply(1, 1).ShouldBe((12f, 2f));

    [Theory]
    [InlineData("xMidYMid meet", 50, 0, 100)]
    [InlineData("xMinYMin meet", 0, 0, 100)]
    [InlineData("xMaxYMax meet", 100, 0, 100)]
    [InlineData("none", 0, 0, 200)]
    public void ViewportMatrix_PreserveAspectRatio(string par, float tx, float ty, float width)
    {
        // A square 10×10 viewBox into a 200×100 viewport.
        Matrix2D m = SvgRenderer.ViewportMatrix([0, 0, 10, 10], 200, 100, par);

        m.E.ShouldBe(tx, 0.01f);
        m.F.ShouldBe(ty, 0.01f);
        (m.A * 10).ShouldBe(width, 0.01f);
    }

    // ── Documents ────────────────────────────────────────────────────────

    [Fact]
    public void Document_ParsesAndAppliesInternalStylesheet()
    {
        HtmlNode svg = SvgDocument.Parse(Encoding.UTF8.GetBytes(Logo))!;

        svg.Tag.ShouldBe("svg");
        First(svg, "rect").ComputedStyle!.SvgProperties!["fill"].ShouldBe("#00ff00");
        SvgDocument.IntrinsicSize(svg).ShouldBe((200f, 100f));
    }

    [Theory]
    [InlineData("<svg viewBox='0 0 40 20'/>", 40f, 20f)]
    [InlineData("<svg width='10mm' height='1in'/>", 37.795f, 96f)]
    [InlineData("<svg width='100' viewBox='0 0 50 25'/>", 100f, 50f)]
    [InlineData("<svg/>", 300f, 150f)]
    public void Document_IntrinsicSize(string markup, float width, float height)
    {
        (float w, float h) = SvgDocument.IntrinsicSize(SvgDocument.Parse(Encoding.UTF8.GetBytes(markup))!);

        w.ShouldBe(width, 0.01f);
        h.ShouldBe(height, 0.01f);
    }

    [Theory]
    [InlineData("not xml at all")]
    [InlineData("<html><body/></html>")]
    [InlineData("<svg><rect></svg>")]
    public void Document_Invalid_ReturnsNull(string markup) =>
        SvgDocument.Parse(Encoding.UTF8.GetBytes(markup)).ShouldBeNull();

    [Fact]
    public void Document_IgnoresExternalEntities()
    {
        const string xxe = """<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY x SYSTEM "file:///etc/passwd">]><svg><text>&x;</text></svg>""";

        Should.NotThrow(() => SvgDocument.Parse(Encoding.UTF8.GetBytes(xxe)));
    }

    [Theory]
    [InlineData("a.svg", true)]
    [InlineData("a.svg?v=2", true)]
    [InlineData("data:image/svg+xml;base64,AA==", true)]
    [InlineData("a.png", false)]
    public void LooksLikeSvg_ByReference(string reference, bool expected) =>
        SvgDocument.LooksLikeSvg(reference, null).ShouldBe(expected);

    // ── Layout & rendering ───────────────────────────────────────────────

    [Fact]
    public void InlineSvg_IsReplacedElementWithIntrinsicSize()
    {
        LayoutResult result = LayoutHtml("<p>a <svg width='40' height='20'><text>hidden text</text></svg> b</p>");

        LayoutBox image = AllBoxes(result).Single(b => b.Type == LayoutBoxType.Image);
        image.Svg.ShouldNotBeNull();
        image.Width.ShouldBe(30f);
        image.Height.ShouldBe(15f);
        Texts(result).ShouldNotContain(t => t.Text!.Contains("hidden", StringComparison.Ordinal));
    }

    [Fact]
    public void InlineSvg_CssSizeOverridesAttributes()
    {
        LayoutResult result = LayoutHtml("<svg width='40' height='20' style='width:100pt;height:10pt'></svg>");

        LayoutBox image = AllBoxes(result).Single(b => b.Type == LayoutBoxType.Image);
        image.Width.ShouldBe(100f);
        image.Height.ShouldBe(10f);
    }

    [Fact]
    public void ImgWithSvgSource_IsVectorNotRaster()
    {
        string pdf = Pdf($"<img src='{SvgDataUri(Logo)}'>");

        pdf.ShouldNotContain("/Subtype /Image");
        pdf.ShouldContain("0.00 1.00 0.00 rg");
        pdf.ShouldContain(" re W n");
    }

    [Fact]
    public void Render_BasicShapes_EmitPaths()
    {
        string pdf = Pdf("""
            <svg width="100" height="100">
              <rect x="10" y="10" width="20" height="20" fill="red"/>
              <circle cx="50" cy="50" r="10" fill="none" stroke="blue" stroke-width="2"/>
              <line x1="0" y1="0" x2="100" y2="100" stroke="black"/>
              <polygon points="0,0 10,0 5,10" fill="lime" fill-rule="evenodd"/>
            </svg>
            """);

        pdf.ShouldContain("1.00 0.00 0.00 rg");
        pdf.ShouldContain("0.00 0.00 1.00 RG");
        pdf.ShouldContain("2 w");
        pdf.ShouldContain("f*\n");
        pdf.ShouldContain(" c\n");
    }

    [Fact]
    public void Render_ViewBoxMapsToBox()
    {
        string pdf = Pdf("<svg width='200' height='100' viewBox='0 0 20 10'><rect width='20' height='10'/></svg>");

        // 200 px = 150 pt over 20 user units → scale 7.5, flipped vertically.
        pdf.ShouldContain("7.5 0 0 -7.5 ");
    }

    [Fact]
    public void Render_LinearGradientFill_UsesShading()
    {
        string pdf = Pdf("""
            <svg width="100" height="50">
              <defs><linearGradient id="g"><stop offset="0" stop-color="red"/><stop offset="1" stop-color="blue"/></linearGradient></defs>
              <rect width="100" height="50" fill="url(#g)"/>
            </svg>
            """);

        pdf.ShouldContain("/ShadingType 2");
        pdf.ShouldContain("/C0 [1 0 0] /C1 [0 0 1]");
    }

    [Fact]
    public void Render_GradientHrefInheritsStops()
    {
        string pdf = Pdf("""
            <svg width="100" height="50">
              <linearGradient id="base"><stop offset="0" stop-color="red"/><stop offset="1" stop-color="blue"/></linearGradient>
              <radialGradient id="r" href="#base"/>
              <circle cx="50" cy="25" r="20" fill="url(#r)"/>
            </svg>
            """);

        pdf.ShouldContain("/ShadingType 3");
    }

    [Fact]
    public void Render_StopOpacity_UsesSoftMask() =>
        Pdf("""
            <svg width="100" height="50">
              <linearGradient id="g"><stop offset="0" stop-color="red"/><stop offset="1" stop-color="red" stop-opacity="0"/></linearGradient>
              <rect width="100" height="50" fill="url(#g)"/>
            </svg>
            """).ShouldContain("/S /Luminosity");

    [Fact]
    public void Render_UnknownPaintUrl_UsesFallback() =>
        Pdf("<svg width='10' height='10'><rect width='10' height='10' fill='url(#missing) #ff0000'/></svg>").ShouldContain("1.00 0.00 0.00 rg");

    [Fact]
    public void Render_CurrentColor_FollowsCssColor() =>
        Pdf("<span style='color:#0000ff'><svg width='10' height='10'><rect width='10' height='10' fill='currentColor'/></svg></span>").ShouldContain("0.00 0.00 1.00 rg");

    [Fact]
    public void Render_CssClassFill_OverridesAttribute() =>
        Pdf("<style>.x { fill: #00ff00 }</style><svg width='10' height='10'><rect class='x' fill='red' width='10' height='10'/></svg>")
            .ShouldContain("0.00 1.00 0.00 rg");

    [Fact]
    public void Render_DisplayNoneElement_IsSkipped() =>
        Pdf("<svg width='10' height='10'><rect width='10' height='10' fill='red' display='none'/></svg>").ShouldNotContain("1.00 0.00 0.00 rg");

    [Fact]
    public void Render_UseReferencesSymbol()
    {
        string pdf = Pdf("""
            <svg width="100" height="100">
              <symbol id="s" viewBox="0 0 10 10"><rect width="10" height="10" fill="red"/></symbol>
              <use href="#s" x="10" y="10" width="50" height="50"/>
            </svg>
            """);

        pdf.ShouldContain("1.00 0.00 0.00 rg");
        pdf.ShouldContain("5 0 0 5 0 0 cm");
    }

    [Fact]
    public void Render_SelfReferencingUse_DoesNotRecurse() =>
        Should.NotThrow(() => Pdf("<svg width='10' height='10'><g id='a'><use href='#a'/></g></svg>"));

    [Fact]
    public void Render_ClipPath_EmitsClip()
    {
        string pdf = Pdf("""
            <svg width="100" height="100">
              <clipPath id="c"><circle cx="50" cy="50" r="20"/></clipPath>
              <rect width="100" height="100" fill="red" clip-path="url(#c)"/>
            </svg>
            """);

        pdf.ShouldContain("h\nW n");
    }

    [Fact]
    public void Render_Text_UsesAnchorAndFlip()
    {
        string pdf = Pdf("<svg width='200' height='50'><text x='100' y='30' text-anchor='middle' font-size='20'>Mid</text></svg>");

        pdf.ShouldContain("(Mid) Tj");
        pdf.ShouldContain("20.00 Tf");
        pdf.ShouldMatch(@"1 0 0 -1 [\d.]+ 30 cm");
    }

    [Fact]
    public void Render_StrokeDashArray()
    {
        string pdf = Pdf("<svg width='100' height='10'><line x1='0' y1='5' x2='100' y2='5' stroke='black' stroke-dasharray='4 2'/></svg>");

        pdf.ShouldContain("[4 2] 0 d");
    }

    [Fact]
    public void Render_OpacityAttribute_UsesTransparency() =>
        Pdf("<svg width='10' height='10'><g opacity='0.5'><rect width='10' height='10'/></g></svg>").ShouldContain("/ca 0.5");

    [Fact]
    public void Render_BackgroundSvg_DrawsVector()
    {
        string pdf = Pdf($"<div style=\"height:20pt;background:url('{SvgDataUri(Logo)}') no-repeat\">x</div>");

        pdf.ShouldContain("0.00 1.00 0.00 rg");
        pdf.ShouldNotContain("/Subtype /Image");
    }

    [Fact]
    public void SvgTitle_IsNotDocumentTitle() =>
        Pdf("<p>x</p><svg width='10' height='10'><title>tooltip</title></svg>").ShouldNotContain("(tooltip)");

    [Fact]
    public void Render_HugeOrHostileSvg_DoesNotThrow()
    {
        string nested = string.Concat(Enumerable.Repeat("<g>", 500)) + "<rect width='1' height='1'/>" + string.Concat(Enumerable.Repeat("</g>", 500));

        Should.NotThrow(() => Pdf($"<svg width='10' height='10'>{nested}<path d='M0 0 A 0 0 0 0 0 0 0 L NaN 1'/><circle r='-5'/></svg>"));
    }
}

// Licensed to SimpleSign under the MIT License.

using System.Text.RegularExpressions;
using Shouldly;
using SimpleSign.HtmlToPdf.Layout;
using SimpleSign.HtmlToPdf.Parsing;
using Xunit;
using static SimpleSign.HtmlToPdf.Tests.TestSupport;

namespace SimpleSign.HtmlToPdf.Tests;

[Trait("Category", "Unit")]
public sealed partial class PaintTests
{
    private static string Pdf(string html, string css = "") =>
        Decompressed((css.Length > 0 ? HtmlToPdfConverter.Html(html).WithStylesheet(css) : HtmlToPdfConverter.Html(html)).Convert());

    // ── Parsing ──────────────────────────────────────────────────────────

    [Fact]
    public void ParseImage_LinearGradient_AngleAndStops()
    {
        var g = (CssGradient)CssPaint.ParseImage("linear-gradient(45deg, red, blue 80%)", 12, PdfColor.Black)!;

        g.IsRadial.ShouldBeFalse();
        g.AngleDegrees.ShouldBe(45f);
        g.Stops.Count.ShouldBe(2);
        g.Stops[0].Position.ShouldBeNull();
        CssLength.PercentOf(g.Stops[1].Position!.Value).ShouldBe(80f);
    }

    [Theory]
    [InlineData("to right", 90f)]
    [InlineData("to left", 270f)]
    [InlineData("to top", 0f)]
    [InlineData("0.25turn", 90f)]
    [InlineData("100grad", 90f)]
    public void ParseImage_LinearDirections(string direction, float expected) =>
        ((CssGradient)CssPaint.ParseImage($"linear-gradient({direction}, red, blue)", 12, PdfColor.Black)!).AngleDegrees.ShouldBe(expected, 0.01f);

    [Fact]
    public void ParseImage_CornerDirection_KeepsCorner() =>
        ((CssGradient)CssPaint.ParseImage("linear-gradient(to bottom right, red, blue)", 12, PdfColor.Black)!).Corner.ShouldBe((1, 1));

    [Fact]
    public void ParseImage_MultiPositionStop_ExpandsToTwoStops()
    {
        var g = (CssGradient)CssPaint.ParseImage("repeating-linear-gradient(45deg, #000 0 5px, #fff 5px 10px)", 12, PdfColor.Black)!;

        g.Repeating.ShouldBeTrue();
        g.Stops.Count.ShouldBe(4);
    }

    [Fact]
    public void ParseImage_Radial_ShapeExtentAndCenter()
    {
        var g = (CssGradient)CssPaint.ParseImage("radial-gradient(circle closest-side at 25% 75%, red, blue)", 12, PdfColor.Black)!;

        g.IsRadial.ShouldBeTrue();
        g.Circle.ShouldBeTrue();
        g.Extent.ShouldBe(RadialExtent.ClosestSide);
        g.Center.X.Percent.ShouldBe(25f);
        g.Center.Y.Percent.ShouldBe(75f);
    }

    [Theory]
    [InlineData("linear-gradient(red)")]
    [InlineData("conic-gradient(red, blue)")]
    [InlineData("linear-gradient(")]
    [InlineData("url()")]
    public void ParseImage_Unsupported_ReturnsNull(string value) =>
        CssPaint.ParseImage(value, 12, PdfColor.Black).ShouldBeNull();

    [Fact]
    public void ParseBackground_Shorthand_SplitsComponents()
    {
        CssPaint.BackgroundShorthand bg = CssPaint.ParseBackground("#fff url(a.png) no-repeat right 10pt bottom / 50% auto content-box", 12, PdfColor.Black);

        bg.Color.ShouldBe(PdfColor.White);
        bg.Images.Single().ShouldBe(new CssUrlImage("a.png"));
        bg.Repeats.Single().ShouldBe(new BackgroundRepeat(false, false));
        bg.Positions.Single().X.ShouldBe(new PositionComponent(100, -10));
        bg.Positions.Single().Y.ShouldBe(new PositionComponent(100, 0));
        CssLength.PercentOf(bg.Sizes.Single().Width!.Value).ShouldBe(50f);
        bg.Sizes.Single().Height.ShouldBeNull();
        bg.Origins.Single().ShouldBe(BackgroundBox.ContentBox);
    }

    [Fact]
    public void ParseBackground_MultipleLayers_ColorFromLastLayer()
    {
        CssPaint.BackgroundShorthand bg = CssPaint.ParseBackground("linear-gradient(red, blue), url(x.png) repeat-x, green", 12, PdfColor.Black);

        bg.Images.Count.ShouldBe(3);
        bg.Images[0].ShouldBeOfType<CssGradient>();
        bg.Images[2].ShouldBeNull();
        bg.Repeats[1].ShouldBe(new BackgroundRepeat(true, false));
        bg.Color.ShouldBe(PdfColor.Parse("green"));
    }

    [Fact]
    public void ParseShadows_BoxShadowList()
    {
        List<CssShadow> shadows = CssPaint.ParseShadows("0 2pt 4pt rgba(0,0,0,.5), inset 1pt 1pt 0 2pt red", 12, PdfColor.Black, boxShadow: true);

        shadows.Count.ShouldBe(2);
        shadows[0].Blur.ShouldBe(4f);
        shadows[0].Color.Alpha.ShouldBe(0.5f, 0.01f);
        shadows[1].Inset.ShouldBeTrue();
        shadows[1].Spread.ShouldBe(2f);
    }

    [Fact]
    public void ParseShadows_TextShadowIgnoresInset() =>
        CssPaint.ParseShadows("inset 1pt 1pt red", 12, PdfColor.Black, boxShadow: false).ShouldBeEmpty();

    [Fact]
    public void ParseTransform_ComposesRightToLeft()
    {
        List<TransformFunction> t = CssPaint.ParseTransform("translate(10pt, 0) scale(2)", 12)!;
        Matrix2D m = CssPaint.ToMatrix(t, 100, 100);

        // scale is applied first, then the translation.
        m.Apply(1, 1).ShouldBe((12f, 2f));
    }

    [Fact]
    public void ParseTransform_RotateDegrees()
    {
        Matrix2D m = CssPaint.ToMatrix(CssPaint.ParseTransform("rotate(90deg)", 12)!, 10, 10);
        (float x, float y) = m.Apply(1, 0);

        x.ShouldBe(0f, 1e-4f);
        y.ShouldBe(1f, 1e-4f);
    }

    [Fact]
    public void ParseTransform_PercentTranslateUsesBoxSize() =>
        CssPaint.ToMatrix(CssPaint.ParseTransform("translateX(50%)", 12)!, 200, 10).E.ShouldBe(100f);

    [Theory]
    [InlineData("none")]
    [InlineData("perspective(10px)")]
    [InlineData("rotate(abc)")]
    public void ParseTransform_InvalidOrNone_ReturnsNull(string value) =>
        CssPaint.ParseTransform(value, 12).ShouldBeNull();

    [Fact]
    public void Cascade_BackgroundShorthand_ResetsColor()
    {
        HtmlNode root = Resolve("<div>x</div>", "div { background-color: red; background: url(a.png); }");
        ComputedStyle style = First(root, "div").ComputedStyle!;

        style.BackgroundColor!.Value.IsTransparent.ShouldBeTrue();
        style.HasBackgroundImage.ShouldBeTrue();
    }

    [Fact]
    public void Cascade_TextShadow_IsInherited()
    {
        HtmlNode root = Resolve("<div><span>x</span></div>", "div { text-shadow: 1pt 1pt red; }");

        First(root, "span").ComputedStyle!.TextShadows.ShouldNotBeNull();
    }

    [Fact]
    public void Cascade_BackgroundAttribute_SetsImage() =>
        First(Resolve("<table background='bg.png'><tr><td>x</td></tr></table>"), "table").ComputedStyle!.HasBackgroundImage.ShouldBeTrue();

    [Theory]
    [InlineData("0.5", 0.5f)]
    [InlineData("40%", 0.4f)]
    [InlineData("2", 1f)]
    [InlineData("-1", 0f)]
    public void Cascade_Opacity_Clamped(string value, float expected) =>
        First(Resolve("<div>x</div>", $"div {{ opacity: {value}; }}"), "div").ComputedStyle!.Opacity.ShouldBe(expected, 0.001f);

    // ── Rendering ────────────────────────────────────────────────────────

    [Fact]
    public void Render_LinearGradient_UsesAxialShading()
    {
        string pdf = Pdf("<div style='height:50pt'>x</div>", "div { background: linear-gradient(to right, red, blue); }");

        pdf.ShouldContain("/ShadingType 2");
        pdf.ShouldContain("/C0 [1 0 0] /C1 [0 0 1]");
        pdf.ShouldContain(" sh\n");
    }

    [Fact]
    public void Render_ThreeStops_StitchingFunction()
    {
        string pdf = Pdf("<div style='height:50pt'>x</div>", "div { background: linear-gradient(red, lime 30%, blue); }");

        pdf.ShouldContain("/FunctionType 3");
        pdf.ShouldContain("/Bounds [0.3]");
    }

    [Fact]
    public void Render_RadialGradient_UsesRadialShading()
    {
        string pdf = Pdf("<div style='height:50pt'>x</div>", "div { background: radial-gradient(circle, white, black); }");

        pdf.ShouldContain("/ShadingType 3");
    }

    [Fact]
    public void Render_TransparentStop_UsesLuminositySoftMask()
    {
        string pdf = Pdf("<div style='height:50pt'>x</div>", "div { background: linear-gradient(transparent, black); }");

        pdf.ShouldContain("/S /Luminosity");
        pdf.ShouldContain("/ColorSpace /DeviceGray");
    }

    [Fact]
    public void Render_RgbaBackground_UsesFillAlphaAndPageGroup()
    {
        string pdf = Pdf("<div style='height:50pt'>x</div>", "div { background: rgba(255, 0, 0, 0.5); }");

        pdf.ShouldContain("/ca 0.5");
        pdf.ShouldContain("/Group << /Type /Group /S /Transparency /CS /DeviceRGB >>");
    }

    [Fact]
    public void Render_OpaqueDocument_HasNoTransparencyGroup() =>
        Pdf("<p>plain</p>").ShouldNotContain("/S /Transparency");

    [Fact]
    public void Render_Opacity_AppliesToTextOfDescendants()
    {
        string pdf = Pdf("<div class='o'><p>faded</p></div>", ".o { opacity: 0.25; }");

        pdf.ShouldContain("/ca 0.25");
    }

    [Fact]
    public void Render_NestedOpacity_Multiplies() =>
        Pdf("<div class='o'><div class='o'>x</div></div>", ".o { opacity: 0.5; }").ShouldContain("/ca 0.25");

    [Fact]
    public void Render_OpacityZero_SkipsContent() =>
        Pdf("<p style='opacity:0'>invisible</p><p>shown</p>").ShouldNotContain("invisible");

    [Fact]
    public void Render_Transform_EmitsMatrix()
    {
        string pdf = Pdf("<div class='r'>rotated</div>", ".r { transform: rotate(90deg); width: 100pt; height: 20pt; }");

        // A 90° turn in y-down CSS space is a -90° turn in PDF space: [0 -1 1 0 e f].
        pdf.ShouldMatch(@"0 -1 1 0 -?[\d.]+ -?[\d.]+ cm");
    }

    [Fact]
    public void Render_TransformOrigin_RotatesAboutCenter()
    {
        LayoutResult layout = LayoutHtml("<div class='r'>x</div>", ".r { transform: rotate(180deg); width: 100pt; height: 20pt; }");
        LayoutBox box = AllBoxes(layout).First(b => b.Type == LayoutBoxType.Block && b.Node?.Tag == "div");
        string pdf = Pdf("<div class='r'>x</div>", ".r { transform: rotate(180deg); width: 100pt; height: 20pt; }");

        // Rotating 180° about the center maps x → 2·cx − x.
        float cx = box.X + 50;
        Match m = MatrixRegex().Match(pdf);
        m.Success.ShouldBeTrue();
        float.Parse(m.Groups["e"].Value, System.Globalization.CultureInfo.InvariantCulture).ShouldBe(2 * cx, 0.05f);
    }

    [Fact]
    public void Render_MixBlendMode_SetsBlendGraphicsState() =>
        Pdf("<div style='mix-blend-mode:multiply;background:red'>x</div>").ShouldContain("/BM /Multiply");

    [Fact]
    public void Render_BoxShadow_PaintsBeforeBackground()
    {
        string pdf = Pdf("<div class='s'>x</div>", ".s { background: #ffffff; box-shadow: 3pt 3pt 0 #ff0000; }");

        int shadow = pdf.IndexOf("1.00 0.00 0.00 rg", StringComparison.Ordinal);
        int background = pdf.IndexOf("1.00 1.00 1.00 rg", StringComparison.Ordinal);
        shadow.ShouldBeGreaterThan(0);
        shadow.ShouldBeLessThan(background);
        pdf.ShouldContain("W* n");
    }

    [Fact]
    public void Render_BlurredShadow_UsesSeveralTranslucentLayers()
    {
        string pdf = Pdf("<div class='s'>x</div>", ".s { box-shadow: 0 0 8pt #000; }");

        Regex.Count(pdf, @"/ca 0\.\d+").ShouldBeGreaterThan(4);
    }

    [Fact]
    public void Render_InsetShadow_ClipsToPaddingBox() =>
        Pdf("<div class='s'>x</div>", ".s { height: 40pt; box-shadow: inset 0 0 0 4pt #00ff00; }").ShouldContain("f*");

    [Fact]
    public void Render_TextShadow_DrawsTextTwice()
    {
        string pdf = Pdf("<p class='t'>Shadowed</p>", ".t { text-shadow: 1pt 1pt 0 red; }");

        Regex.Count(pdf, @"\(Shadowed\) Tj").ShouldBe(2);
    }

    [Fact]
    public void Render_BackgroundImage_TilesAcrossBox()
    {
        string png = DataUri(RgbPng());
        string pdf = Pdf("<div class='b'>x</div>", $".b {{ height: 15pt; width: 30pt; overflow: hidden; background: url({png}); }}");

        // 2×2 px image = 1.5pt tiles: 20 columns × 10 rows.
        Regex.Count(pdf, @"/Img1 Do").ShouldBe(200);
    }

    [Fact]
    public void Render_BackgroundImageNoRepeat_DrawsOnce()
    {
        string png = DataUri(RgbPng());
        string pdf = Pdf("<div class='b'>x</div>", $".b {{ height: 40pt; background: url({png}) no-repeat center / 20pt 10pt; }}");

        Regex.Count(pdf, @"/Img1 Do").ShouldBe(1);
        pdf.ShouldContain("q 20.00 0 0 10.00 ");
    }

    [Fact]
    public void Render_BackgroundCover_ScalesToFill()
    {
        string png = DataUri(RgbPng());
        string pdf = Pdf("<div class='b'>x</div>", $".b {{ width: 100pt; height: 40pt; background: url({png}) no-repeat; background-size: cover; }}");

        pdf.ShouldContain("q 100.00 0 0 100.00 ");
    }

    [Fact]
    public void Render_BackgroundContain_FitsInside()
    {
        string png = DataUri(RgbPng());
        string pdf = Pdf("<div class='b'>x</div>", $".b {{ width: 100pt; height: 40pt; background: url({png}) no-repeat; background-size: contain; }}");

        pdf.ShouldContain("q 40.00 0 0 40.00 ");
    }

    [Fact]
    public void Render_MissingBackgroundImage_IsIgnored() =>
        Should.NotThrow(() => Pdf("<div style='background:url(missing.png) red'>x</div>"));

    [Fact]
    public void Render_BodyBackground_FillsWholePage()
    {
        string pdf = Pdf("<body><p>x</p></body>", "body { background: #eeeeee; }");

        pdf.ShouldContain("0.00 0.00 595.28 841.89 re");
    }

    [Fact]
    public void Render_OverflowHidden_ClipsDescendantsAndKeepsHeight()
    {
        LayoutResult layout = LayoutHtml("<div class='o'><p>one</p><p>two</p><p>three</p></div>", ".o { height: 20pt; overflow: hidden; }");
        LayoutBox box = AllBoxes(layout).First(b => b.Node?.Tag == "div");

        box.Height.ShouldBe(20f, 0.01f);
        Pdf("<div class='o'><p>one</p></div>", ".o { height: 20pt; overflow: hidden; }").ShouldContain("W n");
    }

    [Fact]
    public void Render_LinkInsideTransform_AnnotationFollowsTransform()
    {
        string pdf = Pdf("<div class='r'><a href='https://example.com'>link</a></div>", ".r { transform: translateX(100pt); }");
        Match rect = Regex.Match(pdf, @"/Rect \[(?<x1>[\d.]+) ");

        rect.Success.ShouldBeTrue();
        float.Parse(rect.Groups["x1"].Value, System.Globalization.CultureInfo.InvariantCulture).ShouldBeGreaterThan(150f);
    }

    [Fact]
    public void Render_PdfAWithTransparency_StillDeclaresGroup()
    {
        byte[] bytes = HtmlToPdfConverter.Html("<p style='color:rgba(0,0,0,.5)'>x</p>")
            .WithFont("Test", LoadTestFont())
            .WithStylesheet("p { font-family: Test; }")
            .WithPdfA()
            .Convert();

        Decompressed(bytes).ShouldContain("/S /Transparency /CS /DeviceRGB");
    }

    [Theory]
    [InlineData("repeating-radial-gradient(circle, red 0 0, blue 0 0)")]
    [InlineData("repeating-linear-gradient(red -9e9px, blue 1e39px)")]
    [InlineData("radial-gradient(red 1e39%, blue)")]
    [InlineData("repeating-radial-gradient(circle at 20% 30%, red 0 5px, blue 5px 1e-30px)")]
    public void Render_DegenerateGradients_DoNotThrow(string gradient) =>
        Should.NotThrow(() => Pdf("<div style='height:20pt'>x</div>", $"div {{ background: {gradient}; }}"));

    [GeneratedRegex(@"-1 0 0 -1 (?<e>-?[\d.]+) (?<f>-?[\d.]+) cm")]
    private static partial Regex MatrixRegex();
}

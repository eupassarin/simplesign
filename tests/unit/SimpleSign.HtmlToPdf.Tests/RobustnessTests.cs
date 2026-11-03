// Licensed to SimpleSign under the MIT License.

using System.Text;
using Shouldly;
using Xunit;

namespace SimpleSign.HtmlToPdf.Tests;

[Trait("Category", "Unit")]
public sealed class RobustnessTests
{
    private static readonly string[] Tags =
    [
        "div", "p", "span", "b", "i", "a", "table", "tr", "td", "th", "thead", "tbody", "ul", "ol", "li",
        "h1", "h3", "pre", "img", "br", "hr", "section", "blockquote", "sup", "code", "label",
    ];

    private static readonly string[] Declarations =
    [
        "display:flex", "display:grid", "display:inline-block", "display:none", "display:table", "display:list-item",
        "float:left", "float:right", "clear:both", "position:absolute", "position:relative", "position:fixed",
        "width:50%", "width:-20px", "width:9999px", "height:0", "min-height:40pt", "max-width:10px",
        "margin:0 auto", "margin:-30px", "padding:10%", "border:3px dashed red", "border-radius:50%",
        "white-space:pre", "white-space:nowrap", "word-break:break-all", "text-align:justify", "text-indent:-50pt",
        "font-size:0", "font-size:300pt", "line-height:0", "letter-spacing:5px", "column-gap:5px",
        "grid-template-columns:repeat(auto-fill,minmax(50px,1fr))", "flex-wrap:wrap", "flex:1 1 0",
        "page-break-before:always", "page-break-inside:avoid", "list-style:upper-roman inside", "visibility:hidden",
        "top:-10px", "left:200%", "content:'x'", "color:var(--nope)", "background:url(x.png) #f00",
    ];

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    [InlineData(5)]
    [InlineData(6)]
    [InlineData(7)]
    [InlineData(8)]
    public void Convert_RandomDocuments_NeverThrow(int seed)
    {
        var random = new Random(seed);
        var html = new StringBuilder("<style>div::before{content:'>'} li::after{content:attr(class)}</style>");
        for (int i = 0; i < 60; i++)
        {
            AppendRandomElement(html, random, depth: 0);
        }

        byte[] pdf = HtmlToPdfConverter.Html(html.ToString()).WithFooter("{page}/{pages}").Convert();

        Encoding.ASCII.GetString(pdf, 0, 5).ShouldBe("%PDF-");
    }

    [Fact]
    public void Convert_DeepNesting_DoesNotOverflowStack()
    {
        string html = string.Concat(Enumerable.Repeat("<div style='padding-left:1px'>", 400)) + "deep" + string.Concat(Enumerable.Repeat("</div>", 400));

        Should.NotThrow(() => HtmlToPdfConverter.Html(html).Convert());
    }

    [Fact]
    public void Convert_DeepTableNesting_DoesNotThrow()
    {
        string html = string.Concat(Enumerable.Repeat("<table><tr><td>", 40)) + "x" + string.Concat(Enumerable.Repeat("</td></tr></table>", 40));

        Should.NotThrow(() => HtmlToPdfConverter.Html(html).Convert());
    }

    [Theory]
    [InlineData("<table><tr><td colspan='100000'>x</td></tr></table>")]
    [InlineData("<table><tr><td rowspan='0'>x</td><td>y</td></tr><tr><td>z</td></tr></table>")]
    [InlineData("<table><tr><td rowspan='-3' colspan='abc'>x</td></tr></table>")]
    [InlineData("<ol start='-5' reversed><li value='x'>a</li></ol>")]
    [InlineData("<p>unclosed <b>bold <i>italic</p> <div>")]
    [InlineData("<style>@media print { p { color: red } </style><p>broken css</p>")]
    [InlineData("<style>p::before { content: '\\'; }</style><p>escape</p>")]
    [InlineData("<style>{{{{}}}} ;;; @page { size: } @font-face { src: url( }</style><p>x</p>")]
    [InlineData("<div style='display:grid;grid-template-columns:repeat(1000000, 1fr)'><div>a</div></div>")]
    [InlineData("<img src='data:image/png;base64,iVBORw0KGgo=' alt='bad png'>")]
    [InlineData("<pre>\t\ttabs\r\nand\rreturns</pre>")]
    [InlineData("<p style='width:0'>W</p>")]
    public void Convert_PathologicalInput_DoesNotThrow(string html) =>
        Should.NotThrow(() => HtmlToPdfConverter.Html(html).Convert());

    [Fact]
    public void Convert_HugeSingleWord_IsBrokenAcrossLines()
    {
        string word = new('W', 2000);

        byte[] pdf = HtmlToPdfConverter.Html($"<p style='overflow-wrap:anywhere'>{word}</p>").Convert();

        TestSupport.PageCount(pdf).ShouldBeGreaterThan(1);
    }

    private static void AppendRandomElement(StringBuilder html, Random random, int depth)
    {
        string tag = Tags[random.Next(Tags.Length)];
        string style = string.Join(';', Enumerable.Range(0, random.Next(0, 4)).Select(_ => Declarations[random.Next(Declarations.Length)]));
        string attributes = random.Next(4) switch
        {
            0 => " colspan='2'",
            1 => " rowspan='3'",
            2 => " class='a b'",
            _ => string.Empty,
        };

        if (tag is "img" or "br" or "hr")
        {
            html.Append($"<{tag} style=\"{style}\" src=\"data:image/png;base64,xx\" alt=\"alt\">");
            return;
        }

        html.Append($"<{tag} style=\"{style}\"{attributes}>");
        int children = depth > 4 ? 0 : random.Next(0, 4);
        for (int i = 0; i < children; i++)
        {
            if (random.Next(3) == 0)
            {
                html.Append("Texto com acentuação e palavras ");
            }
            else
            {
                AppendRandomElement(html, random, depth + 1);
            }
        }

        html.Append(random.Next(5) == 0 ? string.Empty : $"</{tag}>");
    }
}

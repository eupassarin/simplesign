using System.Text;
using Shouldly;
using SimpleSign.PAdES.Pdf.Model;
using SimpleSign.PAdES.Pdf.Writing;
using Xunit;

namespace SimpleSign.PAdES.Tests.Pdf.Writing;

[Trait("Category", "Unit")]
public sealed class PdfNameTreeWriterTests
{
    private static readonly PdfString s_key = new(Encoding.ASCII.GetBytes("m"), PdfStringForm.Literal);

    [Fact]
    public void Insert_NoTree_ReturnsAnInlineLeaf()
    {
        var view = PdfDocument.Open(Pdf("1 0 obj\n<< /Type /Catalog >>\nendobj\n")).View();

        var insertion = PdfNameTreeWriter.Insert(view, null, s_key, new PdfReference(9));

        insertion.Objects.ShouldBeEmpty();
        Keys(insertion.InlineRoot!).ShouldBe(["m"]);
    }

    [Fact]
    public void Insert_InlineLeaf_InsertsInKeyOrder()
    {
        var view = PdfDocument.Open(Pdf("1 0 obj\n<< /Type /Catalog /Names << /EmbeddedFiles << /Names [(a) 5 0 R (z) 6 0 R] >> >> >>\nendobj\n")).View();
        var root = ((PdfDictionary)view.Catalog!.Get("Names")!).Get("EmbeddedFiles");

        var insertion = PdfNameTreeWriter.Insert(view, root, s_key, new PdfReference(9));

        Keys(insertion.InlineRoot!).ShouldBe(["a", "m", "z"]);
    }

    [Fact]
    public void Insert_TreeWithKids_RewritesTheLeafAndWidensTheLimits()
    {
        var view = PdfDocument.Open(Pdf(
            "1 0 obj\n<< /Type /Catalog /Names << /EmbeddedFiles 2 0 R >> >>\nendobj\n" +
            "2 0 obj\n<< /Kids [3 0 R 4 0 R] >>\nendobj\n" +
            "3 0 obj\n<< /Limits [(a) (c)] /Names [(a) 5 0 R (c) 5 0 R] >>\nendobj\n" +
            "4 0 obj\n<< /Limits [(x) (z)] /Names [(x) 5 0 R (z) 5 0 R] >>\nendobj\n")).View();
        var root = ((PdfDictionary)view.Catalog!.Get("Names")!).Get("EmbeddedFiles");

        var insertion = PdfNameTreeWriter.Insert(view, root, s_key, new PdfReference(9));

        insertion.InlineRoot.ShouldBeNull();
        var (number, leaf) = insertion.Objects.ShouldHaveSingleItem();
        number.ShouldBe(4);
        Keys(leaf).ShouldBe(["m", "x", "z"]);
        ((PdfArray)leaf.Get("Limits")!).OfType<PdfString>().Select(s => s.Text).ShouldBe(["m", "z"]);
    }

    [Fact]
    public void Insert_KeyAfterEveryLeaf_GoesInTheLastOne()
    {
        var view = PdfDocument.Open(Pdf(
            "1 0 obj\n<< /Type /Catalog >>\nendobj\n" +
            "2 0 obj\n<< /Kids [3 0 R] >>\nendobj\n" +
            "3 0 obj\n<< /Limits [(a) (c)] /Names [(a) 5 0 R (c) 5 0 R] >>\nendobj\n")).View();

        var insertion = PdfNameTreeWriter.Insert(view, new PdfReference(2), s_key, new PdfReference(9));

        Keys(insertion.Objects.Single().Value).ShouldBe(["a", "c", "m"]);
    }

    private static List<string> Keys(PdfDictionary leaf) =>
        [.. ((PdfArray)leaf.Get("Names")!).Where((_, i) => i % 2 == 0).OfType<PdfString>().Select(s => s.Text)];

    private static byte[] Pdf(string objects) =>
        Encoding.Latin1.GetBytes("%PDF-1.7\n" + objects + "trailer\n<< /Root 1 0 R >>\n%%EOF");
}

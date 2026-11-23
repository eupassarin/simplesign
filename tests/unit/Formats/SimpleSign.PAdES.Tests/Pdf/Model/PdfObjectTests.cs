using Shouldly;
using SimpleSign.PAdES.Pdf.Model;
using Xunit;

namespace SimpleSign.PAdES.Tests.Pdf.Model;

[Trait("Category", "Unit")]
public sealed class PdfObjectTests
{
    [Theory]
    [InlineData("1", "1.0")]
    [InlineData("(A)", "<41>")]
    [InlineData("<< /A 1 /B 2 >>", "<< /B 2 /A 1 >>")]
    [InlineData("[1 (x) /N 2 0 R]", "[1.0 <78> /N 2 0 R]")]
    [InlineData("null", "null")]
    [InlineData("<< /A null >>", "<< /A null >>")]
    public void SemanticEquals_SameMeaning_IsTrue(string left, string right) =>
        PdfObject.SemanticEquals(Parse(left), Parse(right)).ShouldBeTrue();

    [Theory]
    [InlineData("1", "2")]
    [InlineData("1", "(1)")]
    [InlineData("/A", "/B")]
    [InlineData("(a)", "(b)")]
    [InlineData("1 0 R", "1 1 R")]
    [InlineData("[1 2]", "[1]")]
    [InlineData("[1 2]", "[2 1]")]
    [InlineData("<< /A 1 >>", "<< /A 1 /B 2 >>")]
    [InlineData("<< /A 1 >>", "<< /B 1 >>")]
    [InlineData("true", "false")]
    public void SemanticEquals_DifferentMeaning_IsFalse(string left, string right) =>
        PdfObject.SemanticEquals(Parse(left), Parse(right)).ShouldBeFalse();

    [Fact]
    public void SemanticEquals_Streams_CompareDictionaryAndData()
    {
        var a = new PdfStream(new PdfDictionary(("Length", new PdfInteger(3))), "abc"u8.ToArray());
        var b = new PdfStream(new PdfDictionary(("Length", new PdfInteger(3))), "abc"u8.ToArray());
        var c = new PdfStream(new PdfDictionary(("Length", new PdfInteger(3))), "abd"u8.ToArray());

        PdfObject.SemanticEquals(a, b).ShouldBeTrue();
        PdfObject.SemanticEquals(a, c).ShouldBeFalse();
    }

    [Fact]
    public void SemanticEquals_DeeplyNested_DoesNotRecurse()
    {
        PdfObject left = PdfNull.Instance;
        PdfObject right = PdfNull.Instance;
        for (int i = 0; i < 100_000; i++)
        {
            left = new PdfArray([left]);
            right = new PdfArray([right]);
        }

        PdfObject.SemanticEquals(left, right).ShouldBeTrue();
    }

    [Fact]
    public void Name_Of_SharesCommonNames()
    {
        PdfName.Of("Type").ShouldBeSameAs(PdfName.Type);
        PdfName.Of("Custom").ShouldBe(PdfName.Of("Custom"));
        PdfName.Of("Custom").ShouldNotBeSameAs(PdfName.Of("Custom"));
    }

    [Fact]
    public void Dictionary_CreatedInCode_HasNoSource()
    {
        var dictionary = new PdfDictionary(("Type", PdfName.Of("Catalog")), ("Pages", new PdfReference(2)));

        dictionary.Source.ShouldBeNull();
        dictionary.Get(PdfName.Pages).ShouldBeOfType<PdfReference>().Id.Number.ShouldBe(2);
        dictionary.Get("Missing").ShouldBeNull();
    }

    [Fact]
    public void String_Text_DecodesTextString()
    {
        new PdfString(new byte[] { 0xFE, 0xFF, 0x00, 0xE9 }).Text.ShouldBe("é");
        new PdfString("plain"u8.ToArray()).Text.ShouldBe("plain");
    }

    [Theory]
    [InlineData("1 0 R", "1 0 R")]
    [InlineData("-.5", "-.5")]
    [InlineData("/N", "/N")]
    [InlineData("true", "true")]
    public void ToString_Scalars_LookLikePdf(string text, string expected) =>
        Parse(text).ToString().ShouldBe(expected);

    private static PdfObject Parse(string text) => PdfParser.ParseObject(System.Text.Encoding.Latin1.GetBytes(text));
}

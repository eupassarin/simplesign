using System.Text;
using Shouldly;
using SimpleSign.PAdES.Pdf.Model;
using Xunit;

namespace SimpleSign.PAdES.Tests.Pdf.Model;

[Trait("Category", "Unit")]
public sealed class PdfLexerTests
{
    [Fact]
    public void Next_MixedSyntax_ReturnsTokensInOrder()
    {
        var kinds = Kinds("<< /Type /Catalog /Kids [1 0 R] /N -1.5 /S (a) /H <41> >> true % comment\nnull");

        kinds.ShouldBe([
            PdfTokenKind.DictionaryStart, PdfTokenKind.Name, PdfTokenKind.Name, PdfTokenKind.Name, PdfTokenKind.ArrayStart,
            PdfTokenKind.Integer, PdfTokenKind.Integer, PdfTokenKind.Keyword, PdfTokenKind.ArrayEnd, PdfTokenKind.Name,
            PdfTokenKind.Real, PdfTokenKind.Name, PdfTokenKind.LiteralString, PdfTokenKind.Name, PdfTokenKind.HexString,
            PdfTokenKind.DictionaryEnd, PdfTokenKind.Keyword, PdfTokenKind.Keyword, PdfTokenKind.EndOfInput,
        ]);
    }

    [Theory]
    [InlineData("123", "Integer")]
    [InlineData("-7", "Integer")]
    [InlineData("+7", "Integer")]
    [InlineData("1.5", "Real")]
    [InlineData(".5", "Real")]
    [InlineData("-.002", "Real")]
    [InlineData("--5", "Real")]
    [InlineData("5-", "Real")]
    [InlineData("-", "Real")]
    [InlineData("1e5", "Keyword")]
    [InlineData("obj", "Keyword")]
    public void Next_Run_IsClassified(string text, string expected) =>
        Kinds(text)[0].ToString().ShouldBe(expected);

    [Theory]
    [InlineData(")")]
    [InlineData(">")]
    [InlineData("{")]
    [InlineData("}")]
    public void Next_DelimiterThatCannotStartAToken_IsInvalid(string text) =>
        Kinds(text)[0].ShouldBe(PdfTokenKind.Invalid);

    [Theory]
    [InlineData("/Name", "Name")]
    [InlineData("/A#20B", "A B")]
    [InlineData("/application#2Fjson", "application/json")]
    [InlineData("/Bad#Z1", "Bad#Z1")]
    [InlineData("/End#4", "End#4")]
    [InlineData("/", "")]
    public void Name_Escapes_AreResolved(string text, string expected)
    {
        byte[] data = Encoding.Latin1.GetBytes(text);
        var lexer = new PdfLexer(data);
        lexer.Name(lexer.Next()).ShouldBe(expected);
    }

    [Theory]
    [InlineData(@"(plain)", "plain")]
    [InlineData(@"(a (nested) b)", "a (nested) b")]
    [InlineData(@"(esc \( \) \\ \n \t)", "esc ( ) \\ \n \t")]
    [InlineData(@"(\101\60\0063)", "A0\u00063")]
    [InlineData("(line\\\ncontinued)", "linecontinued")]
    [InlineData("(cr\rlf\r\nend)", "cr\nlf\nend")]
    [InlineData(@"(\q)", "q")]
    public void LiteralString_Escapes_AreResolved(string text, string expected)
    {
        byte[] data = Encoding.Latin1.GetBytes(text);
        var lexer = new PdfLexer(data);
        Encoding.Latin1.GetString(lexer.LiteralString(lexer.Next())).ShouldBe(expected);
    }

    [Fact]
    public void Next_UnterminatedLiteralString_RunsToEndAndIsMarked()
    {
        byte[] data = "(abc"u8.ToArray();
        var lexer = new PdfLexer(data);

        var token = lexer.Next();

        token.Terminated.ShouldBeFalse();
        Encoding.Latin1.GetString(lexer.LiteralString(token)).ShouldBe("abc");
    }

    [Theory]
    [InlineData("<4142>", new byte[] { 0x41, 0x42 }, false)]
    [InlineData("<41 4 2>", new byte[] { 0x41, 0x42 }, false)]
    [InlineData("<414>", new byte[] { 0x41, 0x40 }, false)]
    [InlineData("<>", new byte[0], false)]
    [InlineData("<41zz42>", new byte[] { 0x41, 0x42 }, true)]
    public void HexString_Digits_AreDecoded(string text, byte[] expected, bool invalid)
    {
        byte[] data = Encoding.Latin1.GetBytes(text);
        var lexer = new PdfLexer(data);

        lexer.HexString(lexer.Next(), out bool invalidDigit).ShouldBe(expected);
        invalidDigit.ShouldBe(invalid);
    }

    [Theory]
    [InlineData("0", 0L)]
    [InlineData("-42", -42L)]
    [InlineData("+9", 9L)]
    [InlineData("9223372036854775800", 9223372036854775800L)]
    public void Integer_Digits_AreRead(string text, long expected)
    {
        byte[] data = Encoding.Latin1.GetBytes(text);
        var lexer = new PdfLexer(data);

        lexer.Integer(lexer.Next(), out long value).ShouldBeTrue();
        value.ShouldBe(expected);
    }

    [Fact]
    public void Integer_TooLarge_ReturnsFalse()
    {
        byte[] data = "99999999999999999999"u8.ToArray();
        var lexer = new PdfLexer(data);

        lexer.Integer(lexer.Next(), out _).ShouldBeFalse();
    }

    [Theory]
    [InlineData("1.5", 1.5, true)]
    [InlineData("-.25", -0.25, true)]
    [InlineData("--5", -5.0, false)]
    [InlineData("1.2.3", 1.2, false)]
    [InlineData("4.", 4.0, true)]
    public void Real_Text_IsReadLeniently(string text, double expected, bool clean)
    {
        byte[] data = Encoding.Latin1.GetBytes(text);
        var lexer = new PdfLexer(data);

        lexer.Real(lexer.Next(), out double value, out bool wasClean).ShouldBeTrue();
        value.ShouldBe(expected, 1e-12);
        wasClean.ShouldBe(clean);
    }

    [Fact]
    public void Peek_DoesNotMove()
    {
        byte[] data = "/A /B"u8.ToArray();
        var lexer = new PdfLexer(data);

        var peeked = lexer.Peek();
        var next = lexer.Next();

        peeked.ShouldBe(next);
    }

    [Fact]
    public void Is_Keyword_ComparesBytes()
    {
        byte[] data = "endobj endstream"u8.ToArray();
        var lexer = new PdfLexer(data);

        var first = lexer.Next();

        lexer.Is(first, "endobj"u8).ShouldBeTrue();
        lexer.Is(first, "endstream"u8).ShouldBeFalse();
    }

    private static List<PdfTokenKind> Kinds(string text)
    {
        byte[] data = Encoding.Latin1.GetBytes(text);
        var lexer = new PdfLexer(data);
        var kinds = new List<PdfTokenKind>();
        while (true)
        {
            var token = lexer.Next();
            kinds.Add(token.Kind);
            if (token.Kind == PdfTokenKind.EndOfInput)
            {
                return kinds;
            }
        }
    }
}

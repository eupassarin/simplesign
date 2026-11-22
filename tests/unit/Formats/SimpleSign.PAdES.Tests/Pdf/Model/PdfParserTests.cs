using System.Diagnostics;
using System.Text;
using Shouldly;
using SimpleSign.PAdES.Pdf.Model;
using Xunit;

namespace SimpleSign.PAdES.Tests.Pdf.Model;

[Trait("Category", "Unit")]
public sealed class PdfParserTests
{
    [Fact]
    public void ParseObject_Dictionary_ReadsEveryKind()
    {
        var dictionary = Parse("<< /B true /N null /I -3 /R 2.50 /S (x) /H <41> /Na /V /A [1 /x] /D << /K 1 >> /Ref 12 3 R >>")
            .ShouldBeOfType<PdfDictionary>();

        dictionary.Get("B").ShouldBe(PdfBoolean.True);
        dictionary.Get("N").ShouldBe(PdfNull.Instance);
        dictionary.Get("I").ShouldBeOfType<PdfInteger>().Value.ShouldBe(-3);
        var real = dictionary.Get("R").ShouldBeOfType<PdfReal>();
        real.Value.ShouldBe(2.5);
        real.Text.ShouldBe("2.50");
        dictionary.Get("S").ShouldBeOfType<PdfString>().Form.ShouldBe(PdfStringForm.Literal);
        dictionary.Get("H").ShouldBeOfType<PdfString>().Bytes.ToArray().ShouldBe("A"u8.ToArray());
        dictionary.Get("Na").ShouldBe(PdfName.Of("V"));
        dictionary.Get("A").ShouldBeOfType<PdfArray>().Count.ShouldBe(2);
        dictionary.Get("D").ShouldBeOfType<PdfDictionary>().Get("K").ShouldBeOfType<PdfInteger>().Value.ShouldBe(1);
        dictionary.Get("Ref").ShouldBeOfType<PdfReference>().Id.ShouldBe(new PdfObjectId(12, 3));
    }

    [Fact]
    public void ParseObject_Dictionary_KeepsSourceRangesOfEntries()
    {
        const string text = "  << /A 1 /B [2 3] >> rest";
        int position = 0;
        var context = new PdfParseContext();

        var dictionary = PdfParser.ParseObject(Encoding.Latin1.GetBytes(text), ref position, context).ShouldBeOfType<PdfDictionary>();

        Slice(text, dictionary.Source!.Value).ShouldBe("<< /A 1 /B [2 3] >>");
        Slice(text, dictionary.Entry(PdfName.Of("B"))!.Source!.Value).ShouldBe("/B [2 3]");
        Slice(text, dictionary.Get("B").ShouldBeOfType<PdfArray>().Source!.Value).ShouldBe("[2 3]");
        text[position..].ShouldBe(" rest");
    }

    [Fact]
    public void ParseObject_BaseOffset_IsAddedToRanges()
    {
        int position = 0;
        var context = new PdfParseContext(baseOffset: 1000);

        var array = PdfParser.ParseObject("[1]"u8, ref position, context).ShouldBeOfType<PdfArray>();

        array.Source.ShouldBe(new PdfSourceRange(1000, 3));
    }

    [Fact]
    public void ParseObject_IntegerNotFollowedByReference_StopsAfterTheInteger()
    {
        int position = 0;
        var context = new PdfParseContext();

        PdfParser.ParseObject("12 0 obj"u8, ref position, context).ShouldBeOfType<PdfInteger>().Value.ShouldBe(12);
        position.ShouldBe(2);
    }

    [Fact]
    public void ParseObject_ArrayOfIntegersAndReferences_TellsThemApart()
    {
        var array = Parse("[1 2 3 0 R 4]").ShouldBeOfType<PdfArray>();

        array.Select(item => item.ToString()).ShouldBe(["1", "2", "3 0 R", "4"]);
    }

    [Theory]
    [InlineData("[0 0 R]")]
    [InlineData("[9999999999 0 R]")]
    [InlineData("[1 99999 R]")]
    public void ParseObject_ReferenceOutOfRange_IsNullAndRepaired(string text)
    {
        var context = new PdfParseContext();

        var array = Parse(text, context).ShouldBeOfType<PdfArray>();

        array[0].ShouldBe(PdfNull.Instance);
        context.Diagnostics.Has(PdfRepairKind.InvalidReference).ShouldBeTrue();
    }

    [Fact]
    public void ParseObject_SignedIntegers_AreNotAReference() =>
        Parse("[-1 0 R]").ShouldBeOfType<PdfArray>()[0].ShouldBeOfType<PdfInteger>().Value.ShouldBe(-1);

    [Fact]
    public void ParseObject_DuplicateKey_LastValueWinsAndIsRepaired()
    {
        var context = new PdfParseContext();

        var dictionary = Parse("<< /A 1 /B 2 /A 3 >>", context).ShouldBeOfType<PdfDictionary>();

        dictionary.Get("A").ShouldBeOfType<PdfInteger>().Value.ShouldBe(3);
        dictionary.Count.ShouldBe(2);
        dictionary.RawEntries.Count.ShouldBe(3);
        dictionary.Keys.Select(k => k.Value).ShouldBe(["A", "B"]);
        context.Diagnostics.Has(PdfRepairKind.DuplicateKey).ShouldBeTrue();
    }

    [Fact]
    public void ParseObject_KeyWithoutValue_IsNull()
    {
        var context = new PdfParseContext();

        var dictionary = Parse("<< /A 1 /B >>", context).ShouldBeOfType<PdfDictionary>();

        dictionary.ContainsKey(PdfName.Of("B")).ShouldBeTrue();
        dictionary.Get("B").ShouldBe(PdfNull.Instance);
        context.Diagnostics.Has(PdfRepairKind.MissingValue).ShouldBeTrue();
    }

    [Fact]
    public void ParseObject_ValueWhereKeyExpected_IsSkipped()
    {
        var context = new PdfParseContext();

        var dictionary = Parse("<< /A 1 (stray) [1 2] /B 2 >>", context).ShouldBeOfType<PdfDictionary>();

        dictionary.Keys.Select(k => k.Value).ShouldBe(["A", "B"]);
        context.Diagnostics.Has(PdfRepairKind.UnexpectedToken).ShouldBeTrue();
    }

    [Fact]
    public void ParseObject_UnclosedDictionaryBeforeEndobj_IsClosedThere()
    {
        int position = 0;
        var context = new PdfParseContext();
        const string text = "<< /A [1 2 /B (x) endobj";

        var dictionary = PdfParser.ParseObject(Encoding.Latin1.GetBytes(text), ref position, context).ShouldBeOfType<PdfDictionary>();

        dictionary.Get("A").ShouldBeOfType<PdfArray>().Count.ShouldBe(4);
        text[position..].ShouldBe("endobj");
        context.Diagnostics.Has(PdfRepairKind.UnclosedContainer).ShouldBeTrue();
    }

    [Fact]
    public void ParseObject_ArrayClosedByDictionaryEnd_ClosesBoth()
    {
        var context = new PdfParseContext();

        var dictionary = Parse("<< /A [1 2 >> /Next", context).ShouldBeOfType<PdfDictionary>();

        dictionary.Get("A").ShouldBeOfType<PdfArray>().Count.ShouldBe(2);
        context.Diagnostics.Has(PdfRepairKind.UnclosedContainer).ShouldBeTrue();
    }

    [Fact]
    public void ParseObject_UnmatchedClose_IsSkipped()
    {
        var context = new PdfParseContext();

        var array = Parse("[1 >> 2]", context).ShouldBeOfType<PdfArray>();

        array.Count.ShouldBe(2);
        context.Diagnostics.Has(PdfRepairKind.UnmatchedClose).ShouldBeTrue();
    }

    [Fact]
    public void ParseObject_EndOfInputInsideContainers_ClosesThem()
    {
        var context = new PdfParseContext();

        var array = Parse("[1 [2 << /K", context).ShouldBeOfType<PdfArray>();

        array.Count.ShouldBe(2);
        var inner = array[1].ShouldBeOfType<PdfArray>();
        inner[1].ShouldBeOfType<PdfDictionary>().Get("K").ShouldBe(PdfNull.Instance);
    }

    [Fact]
    public void ParseObject_NestingDeeperThanTheLimit_IsReadAsNull()
    {
        var context = new PdfParseContext(new PdfReadLimits { MaxNestingDepth = 3 });

        var array = Parse("[[[[[1]]]] 2]", context).ShouldBeOfType<PdfArray>();

        array.Count.ShouldBe(2);
        array[0].ShouldBeOfType<PdfArray>()[0].ShouldBeOfType<PdfArray>()[0].ShouldBe(PdfNull.Instance);
        array[1].ShouldBeOfType<PdfInteger>().Value.ShouldBe(2);
        context.Diagnostics.Has(PdfRepairKind.NestingTooDeep).ShouldBeTrue();
    }

    [Fact]
    public void ParseObject_HundredThousandOpenBrackets_DoesNotOverflowTheStack()
    {
        string text = new string('[', 100_000) + new string(']', 100_000);
        var stopwatch = Stopwatch.StartNew();

        var array = Parse(text).ShouldBeOfType<PdfArray>();

        array.Count.ShouldBe(1);
        stopwatch.Elapsed.ShouldBeLessThan(TimeSpan.FromSeconds(2));
    }

    [Theory]
    [InlineData("1.2.3")]
    [InlineData("--4")]
    public void ParseObject_MalformedNumber_IsReadLenientlyAndRepaired(string text)
    {
        var context = new PdfParseContext();

        Parse(text, context).ShouldBeOfType<PdfReal>();
        context.Diagnostics.Has(PdfRepairKind.InvalidNumber).ShouldBeTrue();
    }

    [Fact]
    public void ParseObject_IntegerTooLarge_IsAReal()
    {
        var context = new PdfParseContext();

        Parse("99999999999999999999", context).ShouldBeOfType<PdfReal>().Value.ShouldBe(1e20);
        context.Diagnostics.Has(PdfRepairKind.InvalidNumber).ShouldBeTrue();
    }

    [Fact]
    public void ParseObject_StrayKeywordInArray_IsSkipped()
    {
        var context = new PdfParseContext();

        Parse("[1 foo 2]", context).ShouldBeOfType<PdfArray>().Count.ShouldBe(2);
        context.Diagnostics.Has(PdfRepairKind.UnexpectedToken).ShouldBeTrue();
    }

    [Fact]
    public void ParseObject_Nothing_IsNull() =>
        Parse("   ").ShouldBe(PdfNull.Instance);

    [Fact]
    public void ParseIndirectObject_Dictionary_ReadsHeaderValueAndRange()
    {
        const string text = "garbage 7 2 obj\n<< /Type /Page >>\nendobj\ntrailer";
        int offset = text.IndexOf('7', StringComparison.Ordinal);

        var obj = PdfParser.ParseIndirectObject(Encoding.Latin1.GetBytes(text), offset, new PdfParseContext()).ShouldNotBeNull();

        obj.Id.ShouldBe(new PdfObjectId(7, 2));
        obj.Value.ShouldBeOfType<PdfDictionary>().Get(PdfName.Type).ShouldBe(PdfName.Of("Page"));
        Slice(text, obj.Source).ShouldBe("7 2 obj\n<< /Type /Page >>\nendobj");
    }

    [Fact]
    public void ParseIndirectObject_NoHeader_ReturnsNull() =>
        PdfParser.ParseIndirectObject("<< /A 1 >>"u8.ToArray(), 0, new PdfParseContext()).ShouldBeNull();

    [Fact]
    public void ParseIndirectObject_MissingEndobj_IsRepaired()
    {
        var context = new PdfParseContext();

        var obj = PdfParser.ParseIndirectObject("1 0 obj\n(x)\n2 0 obj"u8.ToArray(), 0, context).ShouldNotBeNull();

        obj.Value.ShouldBeOfType<PdfString>();
        context.Diagnostics.Has(PdfRepairKind.MissingEndObj).ShouldBeTrue();
    }

    [Fact]
    public void ParseIndirectObject_StreamWithDirectLength_SlicesTheData()
    {
        byte[] data = Encoding.Latin1.GetBytes("1 0 obj\n<< /Length 5 >>\nstream\r\nhello\nendstream\nendobj\n");

        var obj = PdfParser.ParseIndirectObject(data, 0, new PdfParseContext()).ShouldNotBeNull();

        var stream = obj.Value.ShouldBeOfType<PdfStream>();
        Encoding.Latin1.GetString(stream.Encoded.Span).ShouldBe("hello");
        stream.DataOffset.ShouldBe(Encoding.Latin1.GetString(data).IndexOf("hello", StringComparison.Ordinal));
        MemoryMarshalSameArray(stream.Encoded, data).ShouldBeTrue();
    }

    [Fact]
    public void ParseIndirectObject_StreamWithIndirectLength_UsesTheResolver()
    {
        byte[] data = Encoding.Latin1.GetBytes("1 0 obj\n<< /Length 2 0 R >>\nstream\nabc\nendstream\nendobj\n");

        var obj = PdfParser.ParseIndirectObject(data, 0, new PdfParseContext(), id => id.Number == 2 ? 3 : null).ShouldNotBeNull();

        Encoding.Latin1.GetString(obj.Value.ShouldBeOfType<PdfStream>().Encoded.Span).ShouldBe("abc");
    }

    [Theory]
    [InlineData("<< /Length 99 >>")]
    [InlineData("<< /Length 1 >>")]
    [InlineData("<< >>")]
    [InlineData("<< /Length 2 0 R >>")]
    public void ParseIndirectObject_StreamWithWrongLength_FindsEndstream(string dictionary)
    {
        var context = new PdfParseContext();
        byte[] data = Encoding.Latin1.GetBytes($"1 0 obj\n{dictionary}\nstream\r\nabc\r\nendstream\nendobj\n");

        var obj = PdfParser.ParseIndirectObject(data, 0, context).ShouldNotBeNull();

        Encoding.Latin1.GetString(obj.Value.ShouldBeOfType<PdfStream>().Encoded.Span).ShouldBe("abc");
        context.Diagnostics.Has(PdfRepairKind.StreamLength).ShouldBeTrue();
        context.Diagnostics.Has(PdfRepairKind.MissingEndObj).ShouldBeFalse();
    }

    [Fact]
    public void ParseIndirectObject_StreamWithoutEndstream_RunsToTheEnd()
    {
        var context = new PdfParseContext();

        var obj = PdfParser.ParseIndirectObject("1 0 obj\n<< >>\nstream\nabc"u8.ToArray(), 0, context).ShouldNotBeNull();

        Encoding.Latin1.GetString(obj.Value.ShouldBeOfType<PdfStream>().Encoded.Span).ShouldBe("abc");
        context.Diagnostics.Has(PdfRepairKind.MissingEndStream).ShouldBeTrue();
    }

    [Fact]
    public void ParseIndirectObject_StreamKeywordWithoutLineEnd_IsRepaired()
    {
        var context = new PdfParseContext();

        var obj = PdfParser.ParseIndirectObject("1 0 obj<< /Length 3 >>stream\rabc\nendstream endobj"u8.ToArray(), 0, context).ShouldNotBeNull();

        Encoding.Latin1.GetString(obj.Value.ShouldBeOfType<PdfStream>().Encoded.Span).ShouldBe("abc");
        context.Diagnostics.Has(PdfRepairKind.StreamLineEnd).ShouldBeTrue();
    }

    [Fact]
    public void ParseObject_RandomBytes_NeverThrowsAndEnds()
    {
        var random = new Random(20261122);
        byte[] alphabet = "<<>>[]()/% \n\r0123456789.-+RobjendstreamtruefalsenullABC#\\"u8.ToArray();
        for (int round = 0; round < 2000; round++)
        {
            byte[] data = new byte[random.Next(0, 300)];
            for (int i = 0; i < data.Length; i++)
            {
                data[i] = random.Next(4) == 0 ? (byte)random.Next(256) : alphabet[random.Next(alphabet.Length)];
            }

            int position = 0;
            var context = new PdfParseContext();
            while (position < data.Length)
            {
                int before = position;
                _ = PdfParser.ParseObject(data, ref position, context);
                if (position == before)
                {
                    // A structural keyword is left for the caller: step over it as a caller would.
                    position++;
                }
            }

            _ = PdfParser.ParseIndirectObject(data, 0, context);
        }
    }

    private static PdfObject Parse(string text, PdfParseContext? context = null) =>
        PdfParser.ParseObject(Encoding.Latin1.GetBytes(text), context);

    private static string Slice(string text, PdfSourceRange range) => text.Substring((int)range.Offset, range.Length);

    private static bool MemoryMarshalSameArray(ReadOnlyMemory<byte> slice, byte[] array) =>
        System.Runtime.InteropServices.MemoryMarshal.TryGetArray(slice, out var segment) && ReferenceEquals(segment.Array, array);
}

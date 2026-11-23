using System.Reflection;
using System.Text;
using Shouldly;
using SimpleSign.PAdES.Pdf.Enums;
using SimpleSign.PAdES.Pdf.Model;
using SimpleSign.PAdES.Pdf.Writing;
using SimpleSign.PAdES.Signing;
using Xunit;

namespace SimpleSign.PAdES.Tests.Pdf.Writing;

/// <summary>
/// The serializer writes objects byte for byte as the writers' templates do (ADR 0032): each golden test builds the
/// object with the model and compares it with the template's output for the same inputs.
/// </summary>
[Trait("Category", "Unit")]
public sealed class PdfObjectSerializerTests
{
    private const string ByteRangePlaceholder = "[0000000000 0000000000 0000000000 0000000000]";

    private static readonly DateTime s_time = new(2026, 11, 22, 10, 20, 30, DateTimeKind.Utc);

    private static string Text(PdfSerializedObject serialized) => Encoding.Latin1.GetString(serialized.Bytes);

    private static string LegacySignatureDictionary(int number, SignatureFieldOptions options, int hexLength) =>
        (string)typeof(PdfSignatureWriter).GetMethod("BuildSignatureDictionary", BindingFlags.NonPublic | BindingFlags.Static)!
            .Invoke(null, [number, options, hexLength, s_time])!;

    private static string LegacyFieldAnnotation(SignatureFieldOptions options, string name, int field, int sig, int app, float x, float y, float w, float h, int page, PdfALevel? level)
    {
        var parameters = typeof(PdfSignatureWriter).GetNestedType("FieldAnnotationParams", BindingFlags.NonPublic)!;
        object p = Activator.CreateInstance(parameters, [name, field, sig, app, x, y, w, h, page])!;
        return (string)typeof(PdfSignatureWriter).GetMethod("BuildFieldAnnotation", BindingFlags.NonPublic | BindingFlags.Static)!
            .Invoke(null, [options, p, level])!;
    }

    public static TheoryData<SignatureFieldOptions> SignatureOptions()
    {
        var data = new TheoryData<SignatureFieldOptions>();
        data.Add(new SignatureFieldOptions());
        data.Add(new SignatureFieldOptions { SubFilter = PdfSignatureSubFilter.AdbePkcs7Detached, SignerName = "Fulano de Tal", Reason = "Aprovação (final)" });
        data.Add(new SignatureFieldOptions { SubFilter = PdfSignatureSubFilter.PbadPades, Location = "São Paulo\\SP", ContactInfo = "fulano@example.test" });
        data.Add(new SignatureFieldOptions { Reason = "€ 100 — “ok”", CertificationLevel = CertificationLevel.NoChanges });
        data.Add(new SignatureFieldOptions { CertificationLevel = CertificationLevel.FormFillingAndAnnotations, SignerName = "Tab\tand\nlines" });
        return data;
    }

    [Theory]
    [MemberData(nameof(SignatureOptions))]
    public void Write_SignatureDictionary_IsTheSignerTemplateByteForByte(SignatureFieldOptions options)
    {
        const int hexLength = 64;
        string legacy = LegacySignatureDictionary(12, options, hexLength);

        var serialized = PdfObjectSerializer.Write(12, PdfSignatureWriter.SignatureDictionary(options, hexLength / 2, s_time), raw: new Dictionary<string, string> { ["ByteRange"] = ByteRangePlaceholder });

        Text(serialized).ShouldBe(legacy);
        var (start, length) = serialized.ValueRanges["ByteRange"];
        Text(serialized).Substring(start, length).ShouldBe(ByteRangePlaceholder);
        var contents = serialized.ValueRanges["Contents"];
        Text(serialized).Substring(contents.Start, contents.Length).ShouldBe("<" + new string('0', hexLength) + ">");
    }

    [Theory]
    [InlineData(true, 7, null)]
    [InlineData(false, 0, null)]
    [InlineData(true, 3, PdfALevel.A1b)]
    [InlineData(false, 3, PdfALevel.A2b)]
    public void Write_FieldAnnotation_IsTheSignerTemplateByteForByte(bool appearance, int page, PdfALevel? level)
    {
        var options = new SignatureFieldOptions { Appearance = appearance ? new SignatureAppearance() : null };
        string legacy = LegacyFieldAnnotation(options, "Assinatura do Contratante", 14, 12, 15, 72.5f, 300f, 220.25f, 70f, page, level);

        var entries = new List<PdfDictionaryEntry>
        {
            new(PdfName.Type, PdfName.Of("Annot")),
            new(PdfName.Subtype, PdfName.Of("Widget")),
            new(PdfName.FT, PdfName.Sig),
            new(PdfName.T, PdfObjectSerializer.TextString("Assinatura do Contratante")),
            new(PdfName.V, new PdfReference(12)),
        };
        if (page > 0)
        {
            entries.Add(new(PdfName.Of("P"), new PdfReference(page)));
        }

        entries.Add(new(PdfName.Of("F"), new PdfInteger(level is PdfALevel.A1a or PdfALevel.A1b ? 4 : 132)));
        entries.Add(new(PdfName.Of("Border"), new PdfArray([new PdfInteger(0), new PdfInteger(0), new PdfInteger(0)])));
        if (appearance)
        {
            entries.Add(new(PdfName.Of("Rect"), new PdfArray([
                PdfObjectSerializer.Coordinate(72.5f), PdfObjectSerializer.Coordinate(300f),
                PdfObjectSerializer.Coordinate(72.5f + 220.25f), PdfObjectSerializer.Coordinate(300f + 70f)])));
            entries.Add(new(PdfName.Of("AP"), new PdfDictionary(("N", new PdfReference(15)))));
        }
        else
        {
            entries.Add(new(PdfName.Of("Rect"), new PdfArray([new PdfInteger(0), new PdfInteger(0), new PdfInteger(0), new PdfInteger(0)])));
        }

        Text(PdfObjectSerializer.Write(14, new PdfDictionary(entries))).ShouldBe(legacy);
    }

    [Theory]
    [InlineData("Signature1")]
    [InlineData("Assinatura (1)")]
    [InlineData("back\\slash")]
    [InlineData("€uro")]
    [InlineData("soft­hyphen")]
    [InlineData("çãõ é ü")]
    public void TextString_AnyText_IsWhatPdfTextStringEncodeWrites(string text) =>
        PdfObjectSerializer.ToText(PdfObjectSerializer.TextString(text)).ShouldBe(PdfTextString.Encode(text));

    [Fact]
    public void Write_Stream_DataBetweenStreamAndEndstream()
    {
        var stream = new PdfStream(new PdfDictionary(("Length", new PdfInteger(3))), "abc"u8.ToArray());

        Text(PdfObjectSerializer.Write(9, stream)).ShouldBe("9 0 obj\n<< /Length 3\n>>\nstream\nabc\nendstream\nendobj\n");
    }

    [Fact]
    public void Write_NonDictionary_OnOneLine() =>
        Text(PdfObjectSerializer.Write(4, new PdfArray([new PdfReference(5), new PdfReference(6, 2)]))).ShouldBe("4 0 obj\n[5 0 R 6 2 R]\nendobj\n");

    [Theory]
    [InlineData("A B", "/A#20B")]
    [InlineData("a#b", "/a#23b")]
    [InlineData("x/y(z)", "/x#2Fy#28z#29")]
    [InlineData("Adobe.PPKLite", "/Adobe.PPKLite")]
    public void ToText_Name_EscapesWhatANameCannotHold(string name, string expected) =>
        PdfObjectSerializer.ToText(PdfName.Of(name)).ShouldBe(expected);

    [Fact]
    public void ToText_EmptyContainers_AreWrittenAsTheWritersDo()
    {
        PdfObjectSerializer.ToText(new PdfArray([])).ShouldBe("[]");
        PdfObjectSerializer.ToText(PdfDictionary.Empty).ShouldBe("<< >>");
    }

    [Fact]
    public void Write_ParsedBack_IsTheSameObject()
    {
        var value = new PdfDictionary(
            ("Type", PdfName.Of("Test")),
            ("Numbers", new PdfArray([new PdfInteger(-5), new PdfReal(1.5, "1.5"), PdfObjectSerializer.Coordinate(72f)])),
            ("Text", PdfObjectSerializer.TextString("paren ( and \\ back")),
            ("Unicode", PdfObjectSerializer.TextString("日本")),
            ("Nested", new PdfDictionary(("Flag", PdfBoolean.True), ("Nothing", PdfNull.Instance), ("Ref", new PdfReference(3, 1)))),
            ("Name", PdfName.Of("with space")));
        var bytes = PdfObjectSerializer.Write(21, value).Bytes;

        var parsed = PdfParser.ParseIndirectObject(bytes, 0, new PdfParseContext()).ShouldNotBeNull();

        parsed.Id.ShouldBe(new PdfObjectId(21, 0));
        PdfObject.SemanticEquals(parsed.Value, value).ShouldBeTrue();
    }

    [Fact]
    public void ToText_DeeplyNestedArray_DoesNotOverflow()
    {
        PdfObject value = new PdfInteger(1);
        for (int i = 0; i < 100_000; i++)
        {
            value = new PdfArray([value]);
        }

        PdfObjectSerializer.ToText(value).Length.ShouldBe((2 * 100_000) + 1);
    }
}

using Shouldly;
using SimpleSign.PAdES.Pdf;
using SimpleSign.PAdES.Pdf.Exceptions;
using SimpleSign.PAdES.Tests.Pdf.Parity;
using Xunit;

namespace SimpleSign.PAdES.Tests.Pdf;

/// <summary>The signature fields read through the object model (ADR 0032): PdfStructureReader.SignatureFields.</summary>
[Trait("Category", "Unit")]
public sealed class PdfStructureReaderSignatureFieldsTests
{
    private const string Prefix = "<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /ETSI.CAdES.detached /Contents ";

    /// <summary>A signature dictionary whose /ByteRange gap is its /Contents (or another place, given).</summary>
    private static PdfFileBuilder Signature(PdfFileBuilder builder, int number, string contents = "3082AABB", string extra = "", long? gapStart = null)
    {
        long start = gapStart ?? builder.Position + $"{number} 0 obj\n".Length + Prefix.Length;
        long end = start + contents.Length + 2;
        return builder.Object(number, $"{Prefix}<{contents}> /ByteRange [0 {start:D10} {end:D10} 0000000001] /M (D:20260101120000Z) {extra}>>");
    }

    private static PdfFileBuilder Catalog(string fields) => new PdfFileBuilder()
        .Object(1, $"<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [{fields}] /SigFlags 3 >> >>")
        .Object(2, "<< /Type /Pages /Kids [] /Count 0 >>");

    private static async Task<IReadOnlyList<PdfSignatureField>> Read(PdfFileBuilder builder)
    {
        using var stream = new MemoryStream(builder.ToArray());
        return await PdfStructureReader.ReadSignatureFieldsAsync(stream);
    }

    [Fact]
    public async Task ReadSignatureFieldsAsync_HeldAndOrphan_InFileOrderWithTheirNames()
    {
        var builder = Catalog("10 0 R");
        Signature(builder, 12, "3082CCDD");
        builder.Object(10, "<< /FT /Sig /T (Approval) /V 11 0 R /Subtype /Widget /Rect [0 0 0 0] >>");
        Signature(builder, 11, extra: "/Reason (ok) /Name () ").EndRevision();

        var fields = await Read(builder);

        fields.Select(f => f.SigDictObjectNumber).ShouldBe([12, 11]);
        fields[0].FieldName.ShouldBe("Signature_12");
        fields[0].ContentsBytes.ShouldBe([0x30, 0x82, 0xCC, 0xDD]);
        fields[1].FieldName.ShouldBe("Approval");
        fields[1].ContentsBytes.ShouldBe([0x30, 0x82, 0xAA, 0xBB]);
        fields[1].SubFilter.ShouldBe("ETSI.CAdES.detached");
        fields[1].Reason.ShouldBe("ok");
        fields[1].SignerName.ShouldBeNull();
        fields[1].PdfSigningTime.ShouldBe(new DateTimeOffset(2026, 1, 1, 12, 0, 0, TimeSpan.Zero));
    }

    [Fact]
    public async Task ReadSignatureFieldsAsync_FieldInObjectStream_HasItsName()
    {
        var builder = Catalog("10 0 R").Compressed(10, "<< /FT /Sig /T (Compressed) /V 11 0 R /Subtype /Widget /Rect [0 0 0 0] >>");
        Signature(builder, 11).EndRevision(XrefStyle.Stream, new RevisionOptions { XrefStreamNumber = 14, ObjectStreamNumber = 13 });

        (await Read(builder)).ShouldHaveSingleItem().FieldName.ShouldBe("Compressed");
    }

    [Fact]
    public async Task ReadSignatureFieldsAsync_DictionaryWrittenAgain_IsOneSignatureWithTheSignedContents()
    {
        var builder = Catalog("10 0 R").Object(10, "<< /FT /Sig /T (Sig1) /V 11 0 R >>");
        long gap = builder.Position + "11 0 obj\n".Length + Prefix.Length;
        Signature(builder, 11).EndRevision();
        Signature(builder, 11, "3082CCDD", gapStart: gap).EndRevision();

        // The CMS is the one the byte range leaves out: the signed one, not the copy written later.
        (await Read(builder)).ShouldHaveSingleItem().ContentsBytes.ShouldBe([0x30, 0x82, 0xAA, 0xBB]);
    }

    [Fact]
    public async Task ReadSignatureFieldsAsync_UsageRightsSignature_IsLeftOut()
    {
        var builder = Catalog("");
        Signature(builder, 11, extra: "/Reference [<< /TransformMethod /UR3 >>] ").EndRevision();

        (await Read(builder)).ShouldBeEmpty();
    }

    [Fact]
    public async Task ReadSignatureFieldsAsync_EncryptedTrailer_Throws()
    {
        var builder = Catalog("").Object(9, "<< /Filter /Standard >>").EndRevision(options: new RevisionOptions { TrailerExtra = "/Encrypt 9 0 R " });

        await Should.ThrowAsync<EncryptedPdfException>(() => Read(builder));
    }
}

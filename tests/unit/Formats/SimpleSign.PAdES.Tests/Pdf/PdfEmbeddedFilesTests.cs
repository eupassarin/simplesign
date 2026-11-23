using System.IO.Compression;
using System.Text;
using Shouldly;
using SimpleSign.PAdES.Pdf;
using SimpleSign.PAdES.Pdf.Exceptions;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.PAdES.Tests.Pdf;

[Trait("Category", "Unit")]
public sealed class PdfEmbeddedFilesTests
{
    [Fact]
    public void Read_NoEmbeddedFiles_ReturnsEmpty() =>
        PdfEmbeddedFiles.Read(TestPdfFactory.CreateMinimalPdfWithPage()).ShouldBeEmpty();

    [Fact]
    public void Read_CompressedFiles_ReturnsNameAndContent()
    {
        byte[] xml = Encoding.UTF8.GetBytes("<SecuritySettings><a>é</a></SecuritySettings>");
        byte[] pdf = TestPdfFactory.CreatePdfWithAttachments(("SecuritySettings.xml", xml), ("notes.txt", "hello"u8.ToArray()));

        var files = PdfEmbeddedFiles.Read(pdf);

        files.Select(f => f.Name).ShouldBe(["SecuritySettings.xml", "notes.txt"]);
        files[0].Data.ToArray().ShouldBe(xml);
        files[1].Data.ToArray().ShouldBe("hello"u8.ToArray());
    }

    [Fact]
    public void Read_StreamWithoutFilter_ReturnsRawBytes()
    {
        byte[] pdf = Pdf(
            "1 0 obj\n<< /Type /Catalog /Names << /EmbeddedFiles << /Names [ (a.txt) 2 0 R ] >> >> >>\nendobj\n" +
            "2 0 obj\n<< /Type /Filespec /F (a.txt) /EF << /F 3 0 R >> >>\nendobj\n" +
            "3 0 obj\n<< /Length 5 >>\nstream\nplain\nendstream\nendobj\n");

        var file = PdfEmbeddedFiles.Read(pdf).ShouldHaveSingleItem();

        file.Name.ShouldBe("a.txt");
        Encoding.ASCII.GetString(file.Data.Span).ShouldBe("plain");
    }

    [Fact]
    public void Read_IndirectNamesTreeLengthAndKids_FollowsReferences()
    {
        byte[] pdf = Pdf(
            "1 0 obj\n<< /Type /Catalog /Names 2 0 R >>\nendobj\n" +
            "2 0 obj\n<< /EmbeddedFiles 3 0 R >>\nendobj\n" +
            "3 0 obj\n<< /Kids [ 4 0 R 5 0 R ] >>\nendobj\n" +
            "4 0 obj\n<< /Limits [ (a) (a) ] /Names [ (a) 6 0 R ] >>\nendobj\n" +
            "5 0 obj\n<< /Limits [ (b) (b) ] /Names [ (b) 8 0 R ] >>\nendobj\n" +
            "6 0 obj\n<< /Type /Filespec /EF << /F 7 0 R >> >>\nendobj\n" +
            "7 0 obj\n<< /Length 10 0 R >>\nstream\nfirst\nendstream\nendobj\n" +
            "8 0 obj\n<< /Type /Filespec /UF <FEFF00E9002E007400780074> /F (ignored) /EF << /UF 9 0 R >> >>\nendobj\n" +
            "9 0 obj\n<< /Length 6 >>\nstream\nsecond\nendstream\nendobj\n" +
            "10 0 obj\n5\nendobj\n");

        var files = PdfEmbeddedFiles.Read(pdf);

        files.Select(f => f.Name).ShouldBe(["a", "é.txt"]);
        Encoding.ASCII.GetString(files[0].Data.Span).ShouldBe("first");
        Encoding.ASCII.GetString(files[1].Data.Span).ShouldBe("second");
    }

    [Fact]
    public void Read_NameWithEscapesAndNestedParentheses_DecodesTheString()
    {
        byte[] pdf = Pdf(
            "1 0 obj\n<< /Type /Catalog /Names << /EmbeddedFiles << /Names [ (k) 2 0 R ] >> >> >>\nendobj\n" +
            "2 0 obj\n<< /F (a \\(1\\) (b) \\101.txt) /EF << /F 3 0 R >> >>\nendobj\n" +
            "3 0 obj\n<< /Length 1 >>\nstream\nx\nendstream\nendobj\n");

        PdfEmbeddedFiles.Read(pdf).ShouldHaveSingleItem().Name.ShouldBe("a (1) (b) A.txt");
    }

    [Fact]
    public void Read_SubtypeNameContainingStream_FindsTheStreamKeywordAfterTheDictionary()
    {
        byte[] pdf = Pdf(
            "1 0 obj\n<< /Type /Catalog /Names << /EmbeddedFiles << /Names [ (k) 2 0 R ] >> >> >>\nendobj\n" +
            "2 0 obj\n<< /F (k) /EF << /F 3 0 R >> >>\nendobj\n" +
            "3 0 obj\n<< /Subtype /application#2Foctet-stream /Length 4 >>\nstream\ndata\nendstream\nendobj\n");

        Encoding.ASCII.GetString(PdfEmbeddedFiles.Read(pdf).ShouldHaveSingleItem().Data.Span).ShouldBe("data");
    }

    [Fact]
    public void Read_LaterRevisionOfTheStream_ReturnsTheLastOne()
    {
        byte[] pdf = Pdf(
            "1 0 obj\n<< /Type /Catalog /Names << /EmbeddedFiles << /Names [ (k) 2 0 R ] >> >> >>\nendobj\n" +
            "2 0 obj\n<< /F (k) /EF << /F 3 0 R >> >>\nendobj\n" +
            "3 0 obj\n<< /Length 3 >>\nstream\nold\nendstream\nendobj\n" +
            "3 0 obj\n<< /Length 3 >>\nstream\nnew\nendstream\nendobj\n");

        Encoding.ASCII.GetString(PdfEmbeddedFiles.Read(pdf).ShouldHaveSingleItem().Data.Span).ShouldBe("new");
    }

    [Fact]
    public void Read_KidsThatLoop_ReadsEachNodeOnce()
    {
        byte[] pdf = Pdf(
            "1 0 obj\n<< /Type /Catalog /Names << /EmbeddedFiles 2 0 R >> >>\nendobj\n" +
            "2 0 obj\n<< /Names [ (k) 3 0 R ] /Kids [ 2 0 R 2 0 R ] >>\nendobj\n" +
            "3 0 obj\n<< /F (k) /EF << /F 4 0 R >> >>\nendobj\n" +
            "4 0 obj\n<< /Length 1 >>\nstream\nx\nendstream\nendobj\n");

        // The root is node 2: its kids that point back to it are not read again (the scanning reader read it twice).
        PdfEmbeddedFiles.Read(pdf).Count.ShouldBe(1);
    }

    [Fact]
    public void Read_EntryWithoutEmbeddedStream_IsSkipped()
    {
        byte[] pdf = Pdf(
            "1 0 obj\n<< /Type /Catalog /Names << /EmbeddedFiles << /Names [ (k) 2 0 R (m) 9 0 R ] >> >> >>\nendobj\n" +
            "2 0 obj\n<< /Type /Filespec /F (http://example.test/file) >>\nendobj\n");

        PdfEmbeddedFiles.Read(pdf).ShouldBeEmpty();
    }

    [Fact]
    public void Read_UnsupportedFilter_Throws()
    {
        byte[] pdf = Pdf(
            "1 0 obj\n<< /Type /Catalog /Names << /EmbeddedFiles << /Names [ (k) 2 0 R ] >> >> >>\nendobj\n" +
            "2 0 obj\n<< /F (k.bin) /EF << /F 3 0 R >> >>\nendobj\n" +
            "3 0 obj\n<< /Filter [ /LZWDecode ] /Length 1 >>\nstream\nx\nendstream\nendobj\n");

        Should.Throw<PdfStructureException>(() => PdfEmbeddedFiles.Read(pdf)).Message.ShouldContain("/LZWDecode");
    }

    [Fact]
    public void Read_FlateWithPngPredictor_IsDecoded()
    {
        // Two PNG "Up" rows of two bytes: 1 2, then 1+1 1+2.
        string rows = Encoding.Latin1.GetString(Zlib([2, 1, 2, 2, 1, 1]));
        byte[] pdf = Pdf(
            "1 0 obj\n<< /Type /Catalog /Names << /EmbeddedFiles << /Names [ (k) 2 0 R ] >> >> >>\nendobj\n" +
            "2 0 obj\n<< /F (rows.bin) /EF << /F 3 0 R >> >>\nendobj\n" +
            $"3 0 obj\n<< /Filter /FlateDecode /DecodeParms << /Predictor 12 /Columns 2 >> /Length {rows.Length} >>\nstream\n{rows}\nendstream\nendobj\n");

        PdfEmbeddedFiles.Read(pdf).ShouldHaveSingleItem().Data.ToArray().ShouldBe([1, 2, 2, 3]);
    }

    [Fact]
    public void Read_NameWithoutByteOrderMark_IsPdfDocEncoding()
    {
        // 0x80 is a bullet in PDFDocEncoding (ISO 32000-1 Annex D), a control character in Latin-1.
        byte[] pdf = Pdf(
            "1 0 obj\n<< /Type /Catalog /Names << /EmbeddedFiles << /Names [ (k) 2 0 R ] >> >> >>\nendobj\n" +
            "2 0 obj\n<< /F (\\200 notes.txt) /EF << /F 3 0 R >> >>\nendobj\n" +
            "3 0 obj\n<< /Length 1 >>\nstream\nx\nendstream\nendobj\n");

        PdfEmbeddedFiles.Read(pdf).ShouldHaveSingleItem().Name.ShouldBe("\u2022 notes.txt");
    }

    [Fact]
    public void Read_CorruptCompressedStream_Throws()
    {
        byte[] pdf = Pdf(
            "1 0 obj\n<< /Type /Catalog /Names << /EmbeddedFiles << /Names [ (k) 2 0 R ] >> >> >>\nendobj\n" +
            "2 0 obj\n<< /F (k.bin) /EF << /F 3 0 R >> >>\nendobj\n" +
            "3 0 obj\n<< /Filter /FlateDecode /Length 9 >>\nstream\nnot zlib!\nendstream\nendobj\n");

        Should.Throw<PdfStructureException>(() => PdfEmbeddedFiles.Read(pdf)).Message.ShouldContain("k.bin");
    }

    [Fact]
    public void Read_FileLargerThanTheLimit_Throws()
    {
        // 65 MB of zeros compress to a few kilobytes: a decompression bomb.
        using var compressed = new MemoryStream();
        using (var zlib = new ZLibStream(compressed, CompressionLevel.Optimal, leaveOpen: true))
        {
            byte[] zeros = new byte[1024 * 1024];
            for (int i = 0; i < 65; i++)
            {
                zlib.Write(zeros);
            }
        }

        byte[] pdf =
        [
            .. Encoding.Latin1.GetBytes(
                "%PDF-1.7\n" +
                "1 0 obj\n<< /Type /Catalog /Names << /EmbeddedFiles << /Names [ (k) 2 0 R ] >> >> >>\nendobj\n" +
                "2 0 obj\n<< /F (bomb.bin) /EF << /F 3 0 R >> >>\nendobj\n" +
                $"3 0 obj\n<< /Filter /FlateDecode /Length {compressed.Length} >>\nstream\n"),
            .. compressed.ToArray(),
            .. Encoding.Latin1.GetBytes("\nendstream\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF"),
        ];

        Should.Throw<PdfStructureException>(() => PdfEmbeddedFiles.Read(pdf)).Message.ShouldContain("bomb.bin");
    }

    [Fact]
    public void Read_NameTreeInAnObjectStream_ReadsIt()
    {
        // Objects 2 (the name tree) and 3 (the file specification) are compressed in the object stream 5.
        string first = "<< /Names [ (k) 3 0 R ] >>";
        string second = "<< /F (packed.txt) /EF << /F 4 0 R >> >>";
        string header = $"2 0 3 {first.Length + 1} ";
        using var compressed = new MemoryStream();
        using (var zlib = new ZLibStream(compressed, CompressionLevel.Optimal, leaveOpen: true))
        {
            zlib.Write(Encoding.Latin1.GetBytes(header + first + "\n" + second));
        }

        byte[] pdf =
        [
            .. Encoding.Latin1.GetBytes(
                "%PDF-1.7\n" +
                "1 0 obj\n<< /Type /Catalog /Names << /EmbeddedFiles 2 0 R >> >>\nendobj\n" +
                "4 0 obj\n<< /Length 6 >>\nstream\npacked\nendstream\nendobj\n" +
                $"5 0 obj\n<< /Type /ObjStm /N 2 /First {header.Length} /Filter /FlateDecode /Length {compressed.Length} >>\nstream\n"),
            .. compressed.ToArray(),
            .. Encoding.Latin1.GetBytes("\nendstream\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF"),
        ];

        var file = PdfEmbeddedFiles.Read(pdf).ShouldHaveSingleItem();

        file.Name.ShouldBe("packed.txt");
        Encoding.ASCII.GetString(file.Data.Span).ShouldBe("packed");
    }

    [Fact]
    public async Task Read_SignedPdf_KeepsTheFilesAndTheSignatureCoversThem()
    {
        using var pki = new SyntheticPki();
        byte[] content = "<list/>"u8.ToArray();
        byte[] signed = await PadesSigner.Document(TestPdfFactory.CreatePdfWithAttachments(("list.xml", content)))
            .WithCertificate(pki.Leaf, pki.IntermediatesAndRoot())
            .SignAsync();

        var file = PdfEmbeddedFiles.Read(signed).ShouldHaveSingleItem();
        file.Name.ShouldBe("list.xml");
        file.Data.ToArray().ShouldBe(content);

        using var stream = new MemoryStream(signed, writable: false);
        var field = (await PdfStructureReader.ReadSignatureFieldsAsync(stream)).ShouldHaveSingleItem();
        field.ByteRange.CoversEntireFile(signed.Length).ShouldBeTrue();
    }

    [Fact]
    public void Read_EncryptedPdf_Throws()
    {
        byte[] pdf = Encoding.Latin1.GetBytes(
            "%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\ntrailer\n<< /Root 1 0 R /Encrypt 5 0 R >>\n%%EOF");

        Should.Throw<EncryptedPdfException>(() => PdfEmbeddedFiles.Read(pdf));
    }

    [Fact]
    public void Read_AssociatedFile_ReadsRelationshipAndIsAssociated()
    {
        byte[] pdf = Pdf(
            "1 0 obj\n<< /Type /Catalog /AF [ 2 0 R ] /Names << /EmbeddedFiles << /Names [ (envelope.json) 2 0 R ] >> >> >>\nendobj\n" +
            "2 0 obj\n<< /Type /Filespec /F (envelope.json) /UF (envelope.json) /AFRelationship /Data /Desc (The envelope) /EF << /F 3 0 R >> >>\nendobj\n" +
            "3 0 obj\n<< /Type /EmbeddedFile /Subtype /application#2Fjson /Length 2 >>\nstream\n{}\nendstream\nendobj\n");

        var file = PdfEmbeddedFiles.Read(pdf).ShouldHaveSingleItem();

        file.IsAssociated.ShouldBeTrue();
        file.Relationship.ShouldBe("Data");
        file.Description.ShouldBe("The envelope");
        file.MediaType.ShouldBe("application/json");
    }

    [Fact]
    public void Read_FileNotInAf_IsNotAssociated()
    {
        byte[] pdf = Pdf(
            "1 0 obj\n<< /Type /Catalog /AF [ 4 0 R ] /Names << /EmbeddedFiles << /Names [ (a.txt) 2 0 R ] >> >> >>\nendobj\n" +
            "2 0 obj\n<< /Type /Filespec /F (a.txt) /AFRelationship /Source /EF << /F 3 0 R >> >>\nendobj\n" +
            "3 0 obj\n<< /Length 1 >>\nstream\na\nendstream\nendobj\n" +
            "4 0 obj\n<< /Type /Filespec /F (other.txt) >>\nendobj\n");

        var file = PdfEmbeddedFiles.Read(pdf).ShouldHaveSingleItem();

        file.IsAssociated.ShouldBeFalse();
        file.Relationship.ShouldBe("Source");
    }

    [Fact]
    public void Read_InlineFileSpecInAf_IsAssociated()
    {
        const string specification = "<< /Type /Filespec /F (a.txt) /AFRelationship /Supplement /EF << /F 3 0 R >> >>";
        byte[] pdf = Pdf(
            $"1 0 obj\n<< /Type /Catalog /AF [ {specification} ] /Names << /EmbeddedFiles << /Names [ (a.txt) {specification} ] >> >> >>\nendobj\n" +
            "3 0 obj\n<< /Length 1 >>\nstream\na\nendstream\nendobj\n");

        PdfEmbeddedFiles.Read(pdf).ShouldHaveSingleItem().IsAssociated.ShouldBeTrue();
    }

    [Fact]
    public void Read_Params_ReadsSizeAndDates()
    {
        byte[] pdf = Pdf(
            "1 0 obj\n<< /Type /Catalog /Names << /EmbeddedFiles << /Names [ (a.txt) 2 0 R ] >> >> >>\nendobj\n" +
            "2 0 obj\n<< /Type /Filespec /F (a.txt) /EF << /F 3 0 R >> >>\nendobj\n" +
            "3 0 obj\n<< /Type /EmbeddedFile /Params << /Size 1 /CreationDate (D:20261123120000-03'00') /ModDate 4 0 R >> /Length 1 >>\nstream\na\nendstream\nendobj\n" +
            "4 0 obj\n(D:20261124083015Z)\nendobj\n");

        var file = PdfEmbeddedFiles.Read(pdf).ShouldHaveSingleItem();

        file.Size.ShouldBe(1);
        file.CreationDate.ShouldBe(new DateTimeOffset(2026, 11, 23, 12, 0, 0, TimeSpan.FromHours(-3)));
        file.ModDate.ShouldBe(new DateTimeOffset(2026, 11, 24, 8, 30, 15, TimeSpan.Zero));
    }

    [Fact]
    public void Read_InvalidParams_LeavesThemNull()
    {
        byte[] pdf = Pdf(
            "1 0 obj\n<< /Type /Catalog /Names << /EmbeddedFiles << /Names [ (a.txt) 2 0 R ] >> >> >>\nendobj\n" +
            "2 0 obj\n<< /Type /Filespec /F (a.txt) /AFRelationship (Data) /EF << /F 3 0 R >> >>\nendobj\n" +
            "3 0 obj\n<< /Subtype (text/plain) /Params << /Size (one) /CreationDate (yesterday) /ModDate (D:20261399000000) >> /Length 1 >>\nstream\na\nendstream\nendobj\n");

        var file = PdfEmbeddedFiles.Read(pdf).ShouldHaveSingleItem();

        file.Relationship.ShouldBeNull();
        file.MediaType.ShouldBeNull();
        file.Size.ShouldBeNull();
        file.CreationDate.ShouldBeNull();
        file.ModDate.ShouldBeNull();
    }

    [Fact]
    public void Read_NoMetadata_PropertiesAreNull()
    {
        var file = PdfEmbeddedFiles.Read(TestPdfFactory.CreatePdfWithAttachments(("a.txt", "a"u8.ToArray()))).ShouldHaveSingleItem();

        file.IsAssociated.ShouldBeFalse();
        file.Relationship.ShouldBeNull();
        file.Description.ShouldBeNull();
        file.Size.ShouldBeNull();
        file.CreationDate.ShouldBeNull();
        file.ModDate.ShouldBeNull();
    }

    [Fact]
    public void Read_NoCatalog_Throws() =>
        Should.Throw<PdfStructureException>(() => PdfEmbeddedFiles.Read("%PDF-1.7\n%%EOF"u8.ToArray()));

    /// <summary>The objects between a header and a trailer that names object 1 as the catalog.</summary>
    private static byte[] Zlib(byte[] data)
    {
        using var output = new MemoryStream();
        using (var zlib = new ZLibStream(output, CompressionLevel.Optimal, leaveOpen: true))
        {
            zlib.Write(data);
        }

        return output.ToArray();
    }

    private static byte[] Pdf(string objects) =>
        Encoding.Latin1.GetBytes("%PDF-1.7\n" + objects + "trailer\n<< /Root 1 0 R >>\n%%EOF");
}

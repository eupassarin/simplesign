using SimpleSign.DocxToPdf.Fonts;
using Shouldly;

namespace SimpleSign.DocxToPdf.Tests;

public sealed class FontTests
{
    [Fact]
    public void TrueTypeParser_WithValidFont_ParsesUnitsPerEm()
    {
        // Arrange
        byte[] fontData = CreateMinimalTtfFont();

        // Act
        var parser = new TrueTypeParser(fontData);

        // Assert
        parser.UnitsPerEm.ShouldBeGreaterThan((ushort)0);
    }

    [Fact]
    public void TrueTypeParser_WithValidFont_ParsesFamilyName()
    {
        // Arrange
        byte[] fontData = CreateMinimalTtfFont();

        // Act
        var parser = new TrueTypeParser(fontData);

        // Assert
        parser.FamilyName.ShouldNotBeNullOrEmpty();
    }

    [Fact]
    public void TrueTypeParser_GetGlyphId_ReturnsZeroForMissingGlyph()
    {
        // Arrange
        byte[] fontData = CreateMinimalTtfFont();
        var parser = new TrueTypeParser(fontData);

        // Act
        ushort glyphId = parser.GetGlyphId('\uFFFF');

        // Assert
        glyphId.ShouldBe((ushort)0);
    }

    [Fact]
    public void TrueTypeParser_GetGlyphId_FindsMappedCharacter()
    {
        // Arrange
        byte[] fontData = CreateMinimalTtfFont();
        var parser = new TrueTypeParser(fontData);

        // Act
        ushort glyphId = parser.GetGlyphId('A');

        // Assert - 'A' is mapped in our test font
        glyphId.ShouldBeGreaterThan((ushort)0);
    }

    [Fact]
    public void TrueTypeParser_GetAdvanceWidth_ReturnsValueForGlyph0()
    {
        // Arrange
        byte[] fontData = CreateMinimalTtfFont();
        var parser = new TrueTypeParser(fontData);

        // Act
        ushort width = parser.GetAdvanceWidth(0);

        // Assert
        width.ShouldBeGreaterThan((ushort)0);
    }

    [Fact]
    public void TrueTypeParser_GetGlyphMetrics_ReturnsMetrics()
    {
        // Arrange
        byte[] fontData = CreateMinimalTtfFont();
        var parser = new TrueTypeParser(fontData);

        // Act
        GlyphMetrics metrics = parser.GetGlyphMetrics(0);

        // Assert
        metrics.GlyphId.ShouldBe((ushort)0);
        metrics.AdvanceWidth.ShouldBeGreaterThan((ushort)0);
    }

    [Fact]
    public void TrueTypeParser_MeasureString_ReturnsPositiveForMappedText()
    {
        // Arrange
        byte[] fontData = CreateMinimalTtfFont();
        var parser = new TrueTypeParser(fontData);

        // Act
        int width = parser.MeasureString("AB");

        // Assert
        width.ShouldBeGreaterThan(0);
    }

    [Fact]
    public void TrueTypeParser_ThrowsOnNullData() =>
        Should.Throw<ArgumentNullException>(() => new TrueTypeParser(null!));

    [Fact]
    public void FontSubsetter_CreateSubset_ReturnsValidFont()
    {
        // Arrange
        byte[] fontData = CreateMinimalTtfFont();
        var glyphIds = new HashSet<ushort> { 0, 1, 2 };

        // Act
        byte[] subset = FontSubsetter.CreateSubset(fontData, glyphIds);

        // Assert
        subset.ShouldNotBeEmpty();
        subset.Length.ShouldBeGreaterThan(12);
    }

    [Fact]
    public void FontSubsetter_CreateSubset_IncludesNotdefGlyph()
    {
        // Arrange
        byte[] fontData = CreateMinimalTtfFont();
        var glyphIds = new HashSet<ushort> { 5, 10 };

        // Act
        byte[] subset = FontSubsetter.CreateSubset(fontData, glyphIds);

        // Assert
        glyphIds.ShouldContain((ushort)0);
        subset.ShouldNotBeEmpty();
    }

    [Fact]
    public void FontSubsetter_ThrowsOnNullFont()
    {
        // Act & Assert
        Should.Throw<ArgumentNullException>(
            () => FontSubsetter.CreateSubset(null!, new HashSet<ushort> { 0 }));
    }

    [Fact]
    public void FontSubsetter_ThrowsOnNullGlyphIds()
    {
        // Act & Assert
        Should.Throw<ArgumentNullException>(
            () => FontSubsetter.CreateSubset(CreateMinimalTtfFont(), null!));
    }

    [Fact]
    public void FontResolver_Resolve_DoesNotThrowForNonexistentFont()
    {
        // Arrange
        var resolver = new FontResolver(["NonExistentFont12345"]);

        // Act
        string? path = resolver.ResolvePath("CompletelyFakeFont999");

        // Assert - just verify it doesn't throw; path may be null on CI
        _ = path;
    }

    /// <summary>Creates a minimal valid TrueType font for testing.</summary>
    private static byte[] CreateMinimalTtfFont()
    {
        var tables = new Dictionary<string, byte[]>();

        // head table (54 bytes)
        var head = new byte[54];
        WriteUInt16(head, 0, 0x0001); // version 1.0
        WriteUInt16(head, 18, 1000); // unitsPerEm = 1000
        WriteUInt32(head, 12, 0x5F0F3CF5); // magic
        WriteUInt16(head, 16, 0x000B); // flags
        tables["head"] = head;

        // hhea table (36 bytes)
        var hhea = new byte[36];
        WriteUInt16(hhea, 0, 0x0001); // version
        WriteInt16(hhea, 4, 800); // ascender
        WriteInt16(hhea, 6, -400); // descender
        WriteInt16(hhea, 8, 0); // lineGap
        WriteUInt16(hhea, 34, 3); // numHMetrics
        tables["hhea"] = hhea;

        // maxp table (6 bytes - version 0.5)
        var maxp = new byte[6];
        WriteUInt16(maxp, 2, 0x5000); // version 0.5
        WriteUInt16(maxp, 4, 3); // numGlyphs
        tables["maxp"] = maxp;

        // hmtx table (12 bytes - 3 glyphs x 4 bytes)
        var hmtx = new byte[12];
        WriteUInt16(hmtx, 0, 512); // glyph 0 advanceWidth
        WriteUInt16(hmtx, 4, 600); // glyph 1 advanceWidth
        WriteUInt16(hmtx, 8, 700); // glyph 2 advanceWidth
        tables["hmtx"] = hmtx;

        // cmap table with format 4
        tables["cmap"] = BuildTestCmapTable();

        // name table
        tables["name"] = BuildTestNameTable("TestFont");

        // post table
        var post = new byte[32];
        WriteUInt16(post, 0, 0x0003); // version 3.0
        tables["post"] = post;

        return AssembleTestFont(tables);
    }

    private static byte[] BuildTestCmapTable()
    {
        // Format 4 cmap with one segment: 'A'(65)-'B'(66) -> glyphs 1-2
        var cmap = new byte[60];

        // cmap header
        WriteUInt16(cmap, 0, 0); // version
        WriteUInt16(cmap, 2, 1); // numTables
        WriteUInt16(cmap, 4, 3); // platformID (Windows)
        WriteUInt16(cmap, 6, 1); // encodingID (Unicode BMP)
        WriteUInt32(cmap, 8, 12); // offset to subtable

        // Format 4 subtable at offset 12
        WriteUInt16(cmap, 12, 4); // format
        WriteUInt16(cmap, 14, 32); // length
        WriteUInt16(cmap, 16, 0); // language
        WriteUInt16(cmap, 18, 4); // segCountX2 (2 segments)
        WriteUInt16(cmap, 20, 4); // searchRange
        WriteUInt16(cmap, 22, 1); // entrySelector
        WriteUInt16(cmap, 24, 0); // rangeShift
        // endCode array
        WriteUInt16(cmap, 26, 66); // segment 1 end = 'B'
        WriteUInt16(cmap, 28, 0xFFFF); // sentinel
        // reservedPad
        WriteUInt16(cmap, 30, 0);
        // startCode array
        WriteUInt16(cmap, 32, 65); // segment 1 start = 'A'
        WriteUInt16(cmap, 34, 0xFFFF); // sentinel
        // idDelta array: glyph = char + delta, so delta = 1 - 65 = -64
        WriteUInt16(cmap, 36, unchecked((ushort)-64));
        WriteUInt16(cmap, 38, 1); // sentinel delta
        // idRangeOffset array
        WriteUInt16(cmap, 40, 0);
        WriteUInt16(cmap, 42, 0);

        return cmap;
    }

    private static byte[] BuildTestNameTable(string familyName)
    {
        byte[] nameBytes = System.Text.Encoding.BigEndianUnicode.GetBytes(familyName);
        int headerSize = 6 + 12; // header + 1 name record
        var name = new byte[headerSize + nameBytes.Length];

        WriteUInt16(name, 0, 0); // format
        WriteUInt16(name, 2, 1); // count
        WriteUInt16(name, 4, (ushort)headerSize); // stringOffset

        // name record
        WriteUInt16(name, 6, 3); // platformID (Windows)
        WriteUInt16(name, 8, 1); // encodingID (Unicode BMP)
        WriteUInt16(name, 10, 0x0409); // languageID
        WriteUInt16(name, 12, 1); // nameID (family)
        WriteUInt16(name, 14, (ushort)nameBytes.Length);
        WriteUInt16(name, 16, 0); // offset

        Array.Copy(nameBytes, 0, name, headerSize, nameBytes.Length);
        return name;
    }

    private static byte[] AssembleTestFont(Dictionary<string, byte[]> tables)
    {
        int numTables = tables.Count;
        int headerSize = 12 + (numTables * 16);

        int totalSize = headerSize;
        foreach (byte[] tableData in tables.Values)
        {
            totalSize += (tableData.Length + 3) & ~3;
        }

        var font = new byte[totalSize];
        WriteUInt32(font, 0, 0x00010000); // sfVersion
        WriteUInt16(font, 4, (ushort)numTables);
        WriteUInt16(font, 6, 16); // searchRange
        WriteUInt16(font, 8, 1); // entrySelector
        WriteUInt16(font, 10, (ushort)(numTables * 16 - 16)); // rangeShift

        int directoryOffset = 12;
        int dataOffset = headerSize;

        foreach (string tag in tables.Keys.OrderBy(t => t, StringComparer.Ordinal))
        {
            byte[] tableData = tables[tag];
            byte[] tagBytes = System.Text.Encoding.ASCII.GetBytes(tag.PadRight(4)[..4]);

            Array.Copy(tagBytes, 0, font, directoryOffset, 4);
            WriteUInt32(font, directoryOffset + 4, 0);
            WriteUInt32(font, directoryOffset + 8, (uint)dataOffset);
            WriteUInt32(font, directoryOffset + 12, (uint)tableData.Length);
            directoryOffset += 16;

            Array.Copy(tableData, 0, font, dataOffset, tableData.Length);
            dataOffset += (tableData.Length + 3) & ~3;
        }

        return font;
    }

    private static void WriteUInt16(byte[] buf, int off, ushort val)
    {
        buf[off] = (byte)(val >> 8);
        buf[off + 1] = (byte)val;
    }

    private static void WriteInt16(byte[] buf, int off, short val)
    {
        buf[off] = (byte)(val >> 8);
        buf[off + 1] = (byte)val;
    }

    private static void WriteUInt32(byte[] buf, int off, uint val)
    {
        buf[off] = (byte)(val >> 24);
        buf[off + 1] = (byte)(val >> 16);
        buf[off + 2] = (byte)(val >> 8);
        buf[off + 3] = (byte)val;
    }
}

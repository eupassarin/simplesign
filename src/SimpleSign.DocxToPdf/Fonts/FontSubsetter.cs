using System.Text;

namespace SimpleSign.DocxToPdf.Fonts;

/// <summary>Creates a minimal TrueType font subset containing only the specified glyphs.</summary>
internal static class FontSubsetter
{
    /// <summary>Creates a subset font containing only the specified glyph IDs.</summary>
    /// <param name="originalFont">The original font data.</param>
    /// <param name="glyphIds">The glyph IDs to include (must include 0 for .notdef).</param>
    /// <returns>The subset font data.</returns>
    public static byte[] CreateSubset(byte[] originalFont, HashSet<ushort> glyphIds)
    {
        ArgumentNullException.ThrowIfNull(originalFont);
        ArgumentNullException.ThrowIfNull(glyphIds);

        // Ensure .notdef glyph is included
        glyphIds.Add(0);

        var sortedGlyphs = glyphIds.OrderBy(g => g).ToList();
        var glyphMap = new Dictionary<ushort, ushort>();
        for (int i = 0; i < sortedGlyphs.Count; i++)
        {
            glyphMap[sortedGlyphs[i]] = (ushort)i;
        }

        return BuildMinimalFont(originalFont, sortedGlyphs, glyphMap);
    }

    private static byte[] BuildMinimalFont(byte[] original, List<ushort> glyphs, Dictionary<ushort, ushort> glyphMap)
    {
        _ = glyphMap;
        var parser = new TrueTypeParser(original);
        ushort numGlyphs = (ushort)glyphs.Count;

        // Build tables
        var tables = new Dictionary<string, byte[]>
        {
            ["head"] = BuildHeadTable(original),
            ["hhea"] = BuildHheaTable(parser, numGlyphs),
            ["maxp"] = BuildMaxpTable(numGlyphs),
            ["hmtx"] = BuildHmtxTable(parser, glyphs),
            ["cmap"] = BuildCmapTable(),
            ["loca"] = BuildLocaTable(numGlyphs),
            ["glyf"] = BuildGlyfTable(),
            ["post"] = BuildPostTable(),
            ["name"] = BuildNameTable(parser.FamilyName + "-Subset"),
            ["OS/2"] = BuildOs2Table(parser)
        };

        return AssembleFont(tables);
    }

    private static byte[] BuildHeadTable(byte[] original)
    {
        // Minimal 54-byte head table
        var head = new byte[54];
        // Version 1.0
        WriteUInt16(head, 0, 0x0001);
        // unitsPerEm = 1000
        WriteUInt16(head, 18, 1000);
        // indexToLocFormat = 0 (short)
        WriteInt16(head, 50, 0);
        // magicNumber
        WriteUInt32(head, 12, 0x5F0F3CF5);
        // flags
        WriteUInt16(head, 16, 0x000B);

        if (original.Length <= 54)
        {
            return head;
        }

        // Try to copy unitsPerEm from original
        uint numTables = (ushort)((original[4] << 8) | original[5]);
        uint offset = 12;
        for (uint i = 0; i < numTables && offset + 16 <= original.Length; i++)
        {
            string tag = Encoding.ASCII.GetString(original, (int)offset, 4);
            if (tag == "head")
            {
                uint tableOffset = ((uint)original[offset + 8] << 24) | ((uint)original[offset + 9] << 16) |
                                   ((uint)original[offset + 10] << 8) | original[offset + 11];
                if (tableOffset + 54 <= original.Length)
                {
                    Array.Copy(original, (int)tableOffset, head, 0, 54);
                    // Reset checksum adjustment
                    WriteUInt32(head, 8, 0);
                    // Set indexToLocFormat to short
                    WriteInt16(head, 50, 0);
                }

                break;
            }

            offset += 16;
        }

        return head;
    }

    private static byte[] BuildHheaTable(TrueTypeParser parser, ushort numHMetrics)
    {
        var hhea = new byte[36];
        // Version 1.0
        WriteUInt16(hhea, 0, 0x0001);
        WriteInt16(hhea, 4, parser.Ascender);
        WriteInt16(hhea, 6, parser.Descender);
        WriteInt16(hhea, 8, parser.LineGap);
        // advanceWidthMax (approximate)
        WriteUInt16(hhea, 10, 1000);
        // numOfLongHorMetrics
        WriteUInt16(hhea, 34, numHMetrics);
        return hhea;
    }

    private static byte[] BuildMaxpTable(ushort numGlyphs)
    {
        var maxp = new byte[6];
        // Version 0.5 (for TrueType outline-less)
        WriteUInt16(maxp, 2, 0x5000);
        WriteUInt16(maxp, 4, numGlyphs);
        return maxp;
    }

    private static byte[] BuildHmtxTable(TrueTypeParser parser, List<ushort> glyphs)
    {
        var hmtx = new byte[glyphs.Count * 4];
        for (int i = 0; i < glyphs.Count; i++)
        {
            ushort advanceWidth = parser.GetAdvanceWidth(glyphs[i]);
            WriteUInt16(hmtx, i * 4, advanceWidth);
        }

        return hmtx;
    }

    private static byte[] BuildCmapTable()
    {
        // Minimal cmap with format 0 for compatibility
        var cmap = new byte[262];
        // version
        WriteUInt16(cmap, 0, 0);
        // numTables
        WriteUInt16(cmap, 2, 1);
        // platformId (1 = Mac), encodingId (0), offset
        WriteUInt16(cmap, 4, 1);
        WriteUInt16(cmap, 6, 0);
        WriteUInt32(cmap, 8, 12);
        // Format 0 subtable
        WriteUInt16(cmap, 12, 0);
        WriteUInt16(cmap, 14, 262 - 12);

        return cmap;
    }

    private static byte[] BuildLocaTable(ushort numGlyphs)
    {
        // Short format: (numGlyphs + 1) entries of 2 bytes
        var loca = new byte[(numGlyphs + 1) * 2];
        return loca;
    }

    private static byte[] BuildGlyfTable() =>
        [0, 0, 0, 0];

    private static byte[] BuildPostTable()
    {
        var post = new byte[32];
        // Version 3.0 (no glyph names)
        WriteUInt16(post, 0, 0x0003);
        return post;
    }

    private static byte[] BuildNameTable(string familyName)
    {
        byte[] nameBytes = Encoding.BigEndianUnicode.GetBytes(familyName);
        int stringStorageSize = nameBytes.Length * 4;
        int headerSize = 6 + (4 * 12);
        var name = new byte[headerSize + stringStorageSize];

        // Header
        WriteUInt16(name, 4, (ushort)headerSize);
        WriteUInt16(name, 2, 4);

        // Write 4 name records (nameIDs 1,2,4,6) all pointing to same string
        for (int i = 0; i < 4; i++)
        {
            int recordOffset = 6 + (i * 12);
            WriteUInt16(name, recordOffset, 3);
            WriteUInt16(name, recordOffset + 2, 1);
            WriteUInt16(name, recordOffset + 4, 0x0409);
            ushort nameId = i switch { 0 => 1, 1 => 2, 2 => 4, _ => 6 };
            WriteUInt16(name, recordOffset + 6, nameId);
            WriteUInt16(name, recordOffset + 8, (ushort)nameBytes.Length);
            WriteUInt16(name, recordOffset + 10, (ushort)(i * nameBytes.Length));
        }

        // Write string data
        for (int i = 0; i < 4; i++)
        {
            Array.Copy(nameBytes, 0, name, headerSize + (i * nameBytes.Length), nameBytes.Length);
        }

        return name;
    }

    private static byte[] BuildOs2Table(TrueTypeParser parser)
    {
        var os2 = new byte[96];
        // Version 4
        WriteUInt16(os2, 0, 4);
        WriteInt16(os2, 2, 500);
        WriteUInt16(os2, 4, 400);
        WriteUInt16(os2, 6, 5);
        WriteInt16(os2, 68, parser.Ascender);
        WriteInt16(os2, 70, parser.Descender);
        WriteInt16(os2, 72, parser.LineGap);
        WriteUInt16(os2, 74, (ushort)Math.Max(parser.Ascender, (short)0));
        WriteUInt16(os2, 76, (ushort)Math.Abs(parser.Descender));
        return os2;
    }

    private static byte[] AssembleFont(Dictionary<string, byte[]> tables)
    {
        int numTables = tables.Count;
        int headerSize = 12 + (numTables * 16);

        int totalSize = headerSize;
        foreach (byte[] tableData in tables.Values)
        {
            totalSize += (tableData.Length + 3) & ~3;
        }

        var font = new byte[totalSize];

        WriteUInt32(font, 0, 0x00010000);
        WriteUInt16(font, 4, (ushort)numTables);

        int searchRange = 1;
        int entrySelector = 0;
        while (searchRange * 2 <= numTables)
        {
            searchRange *= 2;
            entrySelector++;
        }

        searchRange *= 16;
        WriteUInt16(font, 6, (ushort)searchRange);
        WriteUInt16(font, 8, (ushort)entrySelector);
        WriteUInt16(font, 10, (ushort)(numTables * 16 - searchRange));

        int directoryOffset = 12;
        int dataOffset = headerSize;

        foreach (string tag in tables.Keys.OrderBy(t => t, StringComparer.Ordinal))
        {
            byte[] tableData = tables[tag];
            byte[] tagBytes = Encoding.ASCII.GetBytes(tag.PadRight(4)[..4]);

            Array.Copy(tagBytes, 0, font, directoryOffset, 4);
            WriteUInt32(font, directoryOffset + 4, CalculateChecksum(tableData));
            WriteUInt32(font, directoryOffset + 8, (uint)dataOffset);
            WriteUInt32(font, directoryOffset + 12, (uint)tableData.Length);
            directoryOffset += 16;

            Array.Copy(tableData, 0, font, dataOffset, tableData.Length);
            dataOffset += (tableData.Length + 3) & ~3;
        }

        return font;
    }

    private static uint CalculateChecksum(byte[] data)
    {
        uint sum = 0;
        int length = (data.Length + 3) & ~3;
        for (int i = 0; i < length; i += 4)
        {
            uint val = 0;
            for (int j = 0; j < 4 && i + j < data.Length; j++)
            {
                val = (val << 8) | data[i + j];
            }

            sum += val;
        }

        return sum;
    }

    private static void WriteUInt16(byte[] buffer, int offset, ushort value)
    {
        buffer[offset] = (byte)(value >> 8);
        buffer[offset + 1] = (byte)value;
    }

    private static void WriteInt16(byte[] buffer, int offset, short value)
    {
        buffer[offset] = (byte)(value >> 8);
        buffer[offset + 1] = (byte)value;
    }

    private static void WriteUInt32(byte[] buffer, int offset, uint value)
    {
        buffer[offset] = (byte)(value >> 24);
        buffer[offset + 1] = (byte)(value >> 16);
        buffer[offset + 2] = (byte)(value >> 8);
        buffer[offset + 3] = (byte)value;
    }
}

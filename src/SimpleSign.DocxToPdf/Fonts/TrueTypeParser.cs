using System.Text;

namespace SimpleSign.DocxToPdf.Fonts;

/// <summary>Parses TrueType/OpenType font files for metrics and subsetting.</summary>
internal sealed class TrueTypeParser
{
    private readonly Dictionary<string, (uint Offset, uint Length)> _tables = new();

    /// <summary>Gets the units per em from the head table.</summary>
    public ushort UnitsPerEm { get; private set; } = 1000;

    /// <summary>Gets the typographic ascender.</summary>
    public short Ascender { get; private set; }

    /// <summary>Gets the typographic descender (negative).</summary>
    public short Descender { get; private set; }

    /// <summary>Gets the line gap.</summary>
    public short LineGap { get; private set; }

    /// <summary>Gets the font family name.</summary>
    public string FamilyName { get; private set; } = "Unknown";

    /// <summary>Gets the number of glyphs in the font.</summary>
    public ushort NumGlyphs { get; private set; }

    /// <summary>Gets the raw font data.</summary>
    public byte[] RawData { get; }

    /// <summary>Initializes a new instance of the <see cref="TrueTypeParser"/> class.</summary>
    /// <param name="fontData">The raw TrueType font data.</param>
    public TrueTypeParser(byte[] fontData)
    {
        ArgumentNullException.ThrowIfNull(fontData);
        RawData = fontData;
        ReadTableDirectory();
        ReadHeadTable();
        ReadHheaTable();
        ReadMaxpTable();
        ReadNameTable();
    }

    /// <summary>Gets the glyph ID for a given Unicode code point.</summary>
    /// <param name="codePoint">The Unicode code point.</param>
    /// <returns>The glyph ID, or 0 if not found.</returns>
    public ushort GetGlyphId(char codePoint)
    {
        if (!_tables.TryGetValue("cmap", out (uint Offset, uint Length) cmap))
        {
            return 0;
        }

        uint offset = cmap.Offset;
        ushort numSubtables = ReadUInt16(offset + 2);

        for (int i = 0; i < numSubtables; i++)
        {
            uint subtableOffset = offset + 4 + (uint)(i * 8);
            ushort platformId = ReadUInt16(subtableOffset);
            ushort encodingId = ReadUInt16(subtableOffset + 2);
            uint subOffset = ReadUInt32(subtableOffset + 4);

            // Windows Unicode BMP (platform 3, encoding 1)
            if (platformId == 3 && encodingId == 1)
            {
                return ReadCmapFormat4(offset + subOffset, codePoint);
            }
        }

        return 0;
    }

    /// <summary>Gets the advance width for a glyph.</summary>
    /// <param name="glyphId">The glyph ID.</param>
    /// <returns>The advance width in font design units.</returns>
    public ushort GetAdvanceWidth(ushort glyphId)
    {
        if (!_tables.TryGetValue("hmtx", out (uint Offset, uint Length) hmtx) ||
            !_tables.TryGetValue("hhea", out (uint Offset, uint Length) hhea))
        {
            return 0;
        }

        ushort numHMetrics = ReadUInt16(hhea.Offset + 34);

        if (glyphId < numHMetrics)
        {
            return ReadUInt16(hmtx.Offset + (uint)(glyphId * 4));
        }

        // All glyphs beyond numHMetrics use the last advance width
        if (numHMetrics > 0)
        {
            return ReadUInt16(hmtx.Offset + (uint)((numHMetrics - 1) * 4));
        }

        return 0;
    }

    /// <summary>Gets metrics for a specific glyph.</summary>
    /// <param name="glyphId">The glyph ID.</param>
    /// <returns>The glyph metrics.</returns>
    public GlyphMetrics GetGlyphMetrics(ushort glyphId)
    {
        ushort advanceWidth = GetAdvanceWidth(glyphId);
        short lsb = GetLeftSideBearing(glyphId);
        return new GlyphMetrics(glyphId, advanceWidth, lsb);
    }

    /// <summary>Measures the width of a string in font design units.</summary>
    /// <param name="text">The text to measure.</param>
    /// <returns>The total advance width in font design units.</returns>
    public int MeasureString(string text)
    {
        int totalWidth = 0;
        foreach (char c in text)
        {
            ushort glyphId = GetGlyphId(c);
            totalWidth += GetAdvanceWidth(glyphId);
        }

        return totalWidth;
    }

    private short GetLeftSideBearing(ushort glyphId)
    {
        if (!_tables.TryGetValue("hmtx", out (uint Offset, uint Length) hmtx) ||
            !_tables.TryGetValue("hhea", out (uint Offset, uint Length) hhea))
        {
            return 0;
        }

        ushort numHMetrics = ReadUInt16(hhea.Offset + 34);

        if (glyphId < numHMetrics)
        {
            return ReadInt16(hmtx.Offset + (uint)(glyphId * 4) + 2);
        }

        uint lsbArrayOffset = hmtx.Offset + (uint)(numHMetrics * 4);
        uint index = (uint)(glyphId - numHMetrics);
        return ReadInt16(lsbArrayOffset + index * 2);
    }

    private void ReadTableDirectory()
    {
        if (RawData.Length < 12)
        {
            return;
        }

        ushort numTables = ReadUInt16(4);
        uint offset = 12;

        for (int i = 0; i < numTables && offset + 16 <= RawData.Length; i++)
        {
            string tag = Encoding.ASCII.GetString(RawData, (int)offset, 4);
            uint tableOffset = ReadUInt32(offset + 8);
            uint tableLength = ReadUInt32(offset + 12);
            _tables[tag] = (tableOffset, tableLength);
            offset += 16;
        }
    }

    private void ReadHeadTable()
    {
        if (!_tables.TryGetValue("head", out (uint Offset, uint Length) head))
        {
            return;
        }

        UnitsPerEm = ReadUInt16(head.Offset + 18);
    }

    private void ReadHheaTable()
    {
        if (!_tables.TryGetValue("hhea", out (uint Offset, uint Length) hhea))
        {
            return;
        }

        Ascender = ReadInt16(hhea.Offset + 4);
        Descender = ReadInt16(hhea.Offset + 6);
        LineGap = ReadInt16(hhea.Offset + 8);
    }

    private void ReadMaxpTable()
    {
        if (!_tables.TryGetValue("maxp", out (uint Offset, uint Length) maxp))
        {
            return;
        }

        NumGlyphs = ReadUInt16(maxp.Offset + 4);
    }

    private void ReadNameTable()
    {
        if (!_tables.TryGetValue("name", out (uint Offset, uint Length) name))
        {
            return;
        }

        ushort count = ReadUInt16(name.Offset + 2);
        ushort stringOffset = ReadUInt16(name.Offset + 4);
        uint storageOffset = name.Offset + stringOffset;

        // Try platform 3 (Windows) first
        for (int i = 0; i < count; i++)
        {
            uint recordOffset = name.Offset + 6 + (uint)(i * 12);
            if (recordOffset + 12 > RawData.Length)
            {
                break;
            }

            ushort platformId = ReadUInt16(recordOffset);
            ushort nameId = ReadUInt16(recordOffset + 6);
            ushort length = ReadUInt16(recordOffset + 8);
            ushort strOffset = ReadUInt16(recordOffset + 10);

            if (nameId == 1 && platformId == 3)
            {
                uint start = storageOffset + strOffset;
                if (start + length <= RawData.Length)
                {
                    FamilyName = Encoding.BigEndianUnicode.GetString(RawData, (int)start, length);
                    return;
                }
            }
        }

        // Fallback: try platform 1 (Mac)
        for (int i = 0; i < count; i++)
        {
            uint recordOffset = name.Offset + 6 + (uint)(i * 12);
            if (recordOffset + 12 > RawData.Length)
            {
                break;
            }

            ushort platformId = ReadUInt16(recordOffset);
            ushort nameId = ReadUInt16(recordOffset + 6);
            ushort length = ReadUInt16(recordOffset + 8);
            ushort strOffset = ReadUInt16(recordOffset + 10);

            if (nameId == 1 && platformId == 1)
            {
                uint start = storageOffset + strOffset;
                if (start + length <= RawData.Length)
                {
                    FamilyName = Encoding.ASCII.GetString(RawData, (int)start, length);
                    return;
                }
            }
        }
    }

    private ushort ReadCmapFormat4(uint offset, char codePoint)
    {
        ushort format = ReadUInt16(offset);
        if (format != 4)
        {
            return 0;
        }

        ushort segCount = (ushort)(ReadUInt16(offset + 6) / 2);
        uint endCodeOffset = offset + 14;
        uint startCodeOffset = endCodeOffset + (uint)(segCount * 2) + 2;
        uint idDeltaOffset = startCodeOffset + (uint)(segCount * 2);
        uint idRangeOffset = idDeltaOffset + (uint)(segCount * 2);

        ushort code = codePoint;

        for (int i = 0; i < segCount; i++)
        {
            ushort endCode = ReadUInt16(endCodeOffset + (uint)(i * 2));
            if (endCode < code)
            {
                continue;
            }

            ushort startCode = ReadUInt16(startCodeOffset + (uint)(i * 2));
            if (startCode > code)
            {
                return 0;
            }

            short idDelta = ReadInt16(idDeltaOffset + (uint)(i * 2));
            ushort idRangeOffsetVal = ReadUInt16(idRangeOffset + (uint)(i * 2));

            if (idRangeOffsetVal == 0)
            {
                return (ushort)(code + idDelta);
            }

            uint glyphOffset = idRangeOffset + (uint)(i * 2) + idRangeOffsetVal + (uint)((code - startCode) * 2);
            ushort glyphId = ReadUInt16(glyphOffset);
            if (glyphId != 0)
            {
                return (ushort)(glyphId + idDelta);
            }

            return 0;
        }

        return 0;
    }

    private ushort ReadUInt16(uint offset) =>
        (ushort)((RawData[offset] << 8) | RawData[offset + 1]);

    private short ReadInt16(uint offset) =>
        (short)((RawData[offset] << 8) | RawData[offset + 1]);

    private uint ReadUInt32(uint offset) =>
        ((uint)RawData[offset] << 24) | ((uint)RawData[offset + 1] << 16) |
        ((uint)RawData[offset + 2] << 8) | RawData[offset + 3];
}

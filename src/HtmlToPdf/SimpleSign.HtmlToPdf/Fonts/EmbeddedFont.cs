using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using SimpleSign.HtmlToPdf.Rendering;

namespace SimpleSign.HtmlToPdf.Fonts;

/// <summary>
/// Represents a caller-supplied TrueType/OpenType font embedded in generated PDFs as a Type0 font
/// with Identity-H encoding (CID = glyph id), a ToUnicode map, and — for TrueType outlines — a
/// subset that only carries the glyphs used by the document.
/// </summary>
internal sealed class EmbeddedFont
{
    private readonly byte[] _data;
    private readonly Dictionary<string, (int Offset, int Length)> _tables = new(StringComparer.Ordinal);
    private readonly SortedDictionary<ushort, string> _usedGlyphs = [];
    private readonly Dictionary<(string Text, bool Rtl), OpenType.ShapedRun> _shapeCache = [];
    private OpenType.TextShaper? _shaper;
    private readonly Dictionary<int, ushort> _glyphCache = [];
    private readonly int _numHMetrics;
    private readonly ushort _numGlyphs;
    private readonly int _hmtxOffset;
    private readonly int _cmapOffset;
    private readonly int _cmapLength;
    private readonly (int Offset, int Length)? _cmap12;
    private readonly (int Offset, int Length)? _cmap4;

    internal EmbeddedFont(string family, byte[] data)
        : this(family, data, FontVariant.Regular)
    {
    }

    internal EmbeddedFont(string family, byte[] data, FontVariant variant)
    {
        Family = family;
        Variant = variant;
        _data = data;
        if (data.Length < 12)
        {
            throw new ArgumentException("The font data is not a valid TrueType font.", nameof(data));
        }

        uint sfntVersion = ReadUInt32(data, 0);
        if (sfntVersion == 0x74746366)
        {
            throw new ArgumentException("TrueType collections (.ttc) are not supported; extract a single .ttf face first.", nameof(data));
        }

        if (sfntVersion is 0x774F4646 or 0x774F4632)
        {
            throw new ArgumentException("WOFF/WOFF2 fonts are not supported; supply the uncompressed .ttf or .otf file.", nameof(data));
        }

        ushort tableCount = ReadUInt16(data, 4);
        for (int i = 0; i < tableCount; i++)
        {
            int entry = 12 + (i * 16);
            if (entry + 16 > data.Length)
            {
                throw new ArgumentException("The TrueType table directory is truncated.", nameof(data));
            }

            string tag = Encoding.ASCII.GetString(data, entry, 4);
            uint offset = ReadUInt32(data, entry + 8);
            uint length = ReadUInt32(data, entry + 12);
            if (offset > data.Length || length > data.Length - offset)
            {
                throw new ArgumentException($"The TrueType '{tag}' table is outside the font data.", nameof(data));
            }

            _tables[tag] = ((int)offset, (int)length);
        }

        if (!_tables.TryGetValue("head", out var head)
            || !_tables.TryGetValue("hhea", out var hhea)
            || !_tables.TryGetValue("maxp", out var maxp)
            || !_tables.TryGetValue("hmtx", out var hmtx)
            || !_tables.TryGetValue("cmap", out var cmap))
        {
            throw new ArgumentException("The TrueType font is missing a required table (head, hhea, maxp, hmtx, or cmap).", nameof(data));
        }

        if (head.Length < 54 || hhea.Length < 36 || maxp.Length < 6)
        {
            throw new ArgumentException("The TrueType font has truncated head, hhea, or maxp tables.", nameof(data));
        }

        IsCff = _tables.ContainsKey("CFF ");
        if (IsCff && CffIsCidKeyed(data, _tables["CFF "]))
        {
            throw new ArgumentException("CID-keyed CFF (OpenType/CFF CJK) fonts are not supported; use the TrueType (.ttf) version of the font.", nameof(data));
        }

        if (!IsCff && !_tables.ContainsKey("glyf"))
        {
            throw new ArgumentException("The font has neither TrueType (glyf) nor CFF outlines.", nameof(data));
        }

        UnitsPerEm = ReadUInt16(data, head.Offset + 18);
        _numHMetrics = ReadUInt16(data, hhea.Offset + 34);
        _numGlyphs = ReadUInt16(data, maxp.Offset + 4);
        _hmtxOffset = hmtx.Offset;
        _cmapOffset = cmap.Offset;
        _cmapLength = cmap.Length;
        if (UnitsPerEm == 0 || _numHMetrics == 0 || _numGlyphs == 0 || hmtx.Length < _numHMetrics * 4)
        {
            throw new ArgumentException("The TrueType font contains invalid metrics.", nameof(data));
        }

        ushort encodingCount = ReadUInt16(data, _cmapOffset + 2);
        if (_cmapOffset + 4 + (encodingCount * 8) > _cmapOffset + _cmapLength)
        {
            throw new ArgumentException("The TrueType cmap encoding records are truncated.", nameof(data));
        }

        for (int i = 0; i < encodingCount; i++)
        {
            int record = _cmapOffset + 4 + (i * 8);
            ushort platformId = ReadUInt16(data, record);
            ushort encodingId = ReadUInt16(data, record + 2);
            uint subtableOffset = ReadUInt32(data, record + 4);
            if (subtableOffset >= _cmapLength)
            {
                continue;
            }

            int subtable = _cmapOffset + (int)subtableOffset;
            ushort format = ReadUInt16(data, subtable);
            if (format == 12 && subtable + 16 <= _cmapOffset + _cmapLength && (platformId == 0 || platformId == 3))
            {
                uint length = ReadUInt32(data, subtable + 4);
                if (length >= 16 && length <= _cmapOffset + _cmapLength - subtable)
                {
                    _cmap12 = (subtable, (int)length);
                }
            }
            else if (format == 4 && subtable + 4 <= _cmapOffset + _cmapLength && (platformId == 0 || (platformId == 3 && encodingId is 0 or 1 or 10)))
            {
                ushort length = ReadUInt16(data, subtable + 2);
                if (length >= 16 && length <= _cmapOffset + _cmapLength - subtable)
                {
                    _cmap4 ??= (subtable, length);
                }
            }
        }

        if (_cmap12 is null && _cmap4 is null)
        {
            throw new ArgumentException("The TrueType font has no supported Unicode cmap (format 4 or 12).", nameof(data));
        }

        short ascent = ReadInt16(data, hhea.Offset + 4);
        short descent = ReadInt16(data, hhea.Offset + 6);
        Ascent = ascent * 1000f / UnitsPerEm;
        Descent = descent * 1000f / UnitsPerEm;
        CapHeight = Ascent * 0.7f;
        if (_tables.TryGetValue("OS/2", out var os2) && os2.Length >= 90 && ReadUInt16(data, os2.Offset) >= 2)
        {
            short capHeight = ReadInt16(data, os2.Offset + 88);
            if (capHeight > 0)
            {
                CapHeight = capHeight * 1000f / UnitsPerEm;
            }
        }

        if (_tables.TryGetValue("post", out var post) && post.Length >= 8)
        {
            // Fixed 16.16
            ItalicAngle = ReadInt32(data, post.Offset + 4) / 65536f;
        }

        string safe = new([.. family.Where(char.IsAsciiLetterOrDigit)]);
        string baseName = safe.Length == 0 ? "EmbeddedFont" : safe;
        PdfName = variant switch
        {
            FontVariant.Bold => baseName + "-Bold",
            FontVariant.Italic => baseName + "-Italic",
            FontVariant.BoldItalic => baseName + "-BoldItalic",
            _ => baseName,
        };
    }

    internal string Family { get; }

    internal FontVariant Variant { get; }

    internal string PdfName { get; }

    internal string ResourceKey { get; set; } = string.Empty;

    /// <summary>Gets a value indicating whether the font uses CFF (PostScript) outlines.</summary>
    internal bool IsCff { get; }

    /// <summary>Gets the ascent in 1/1000 em.</summary>
    internal float Ascent { get; }

    /// <summary>Gets the descent in 1/1000 em (negative).</summary>
    internal float Descent { get; }

    /// <summary>Gets the cap height in 1/1000 em.</summary>
    internal float CapHeight { get; }

    /// <summary>Gets the italic angle in degrees.</summary>
    internal float ItalicAngle { get; }

    /// <summary>Gets the object number of the Type0 font dictionary once reserved, or 0.</summary>
    internal int ObjectNumber { get; private set; }

    /// <summary>Gets the number of distinct glyphs referenced so far.</summary>
    internal int UsedGlyphCount => _usedGlyphs.Count;

    internal bool HasGlyph(Rune rune) => GetGlyphId(rune) != 0;

    internal ushort GetGlyphId(Rune rune)
    {
        if (_glyphCache.TryGetValue(rune.Value, out ushort cached))
        {
            return cached;
        }

        ushort glyph = LookupGlyph(rune.Value);
        _glyphCache[rune.Value] = glyph;
        return glyph;
    }

    private ushort LookupGlyph(int codepoint)
    {
        if (_cmap12 is { } cmap12)
        {
            ushort glyph = MapFormat12(cmap12.Offset, cmap12.Offset + cmap12.Length, (uint)codepoint);
            if (glyph != 0 || _cmap4 is null || codepoint > 0xFFFF)
            {
                return glyph;
            }
        }

        return codepoint <= 0xFFFF && _cmap4 is { } cmap4
            ? MapFormat4(cmap4.Offset, cmap4.Offset + cmap4.Length, (ushort)codepoint)
            : (ushort)0;
    }

    internal float Measure(Rune rune, float fontSize) => GetAdvance(GetGlyphId(rune)) * fontSize / UnitsPerEm;

    private ushort GetAdvance(ushort glyph)
    {
        int metricIndex = Math.Min(glyph, _numHMetrics - 1);
        return ReadUInt16(_data, _hmtxOffset + (metricIndex * 4));
    }

    /// <summary>Returns the 2-byte code used in content streams for the rune (the glyph id) and records its use.</summary>
    internal ushort GetCid(Rune rune)
    {
        ushort glyph = GetGlyphId(rune);
        _usedGlyphs.TryAdd(glyph, rune.ToString());
        return glyph;
    }

    /// <summary>Gets the font's design units per em.</summary>
    internal int UnitsPerEm { get; }

    /// <summary>Gets the advance width of a glyph in font units.</summary>
    internal int AdvanceOf(ushort glyph) => GetAdvance(glyph);

    /// <summary>Records a glyph produced by shaping and the text it stands for (empty when it is part of a larger cluster).</summary>
    internal void UseGlyph(ushort glyph, string text)
    {
        if (!_usedGlyphs.TryGetValue(glyph, out string? existing) || (existing.Length == 0 && text.Length > 0))
        {
            _usedGlyphs[glyph] = text;
        }
    }

    /// <summary>Gets the OpenType shaper for this font.</summary>
    internal OpenType.TextShaper Shaper => _shaper ??= new OpenType.TextShaper(
        codepoint => codepoint is >= 0 and <= 0x10FFFF and not (>= 0xD800 and <= 0xDFFF) ? GetGlyphId(new Rune(codepoint)) : (ushort)0,
        glyph => GetAdvance(glyph),
        Table("GSUB"),
        Table("GPOS"),
        Table("GDEF"),
        Table("kern"));

    /// <summary>Shapes text with this font, caching recent results (layout measures the same words it later draws).</summary>
    internal OpenType.ShapedRun Shape(string text, bool rightToLeft)
    {
        if (_shapeCache.TryGetValue((text, rightToLeft), out OpenType.ShapedRun? cached))
        {
            return cached;
        }

        if (_shapeCache.Count > 16_384)
        {
            _shapeCache.Clear();
        }

        OpenType.ShapedRun run = Shaper.Shape(text, rightToLeft);
        _shapeCache[(text, rightToLeft)] = run;
        return run;
    }

    private OpenType.TableReader Table(string tag) =>
        _tables.TryGetValue(tag, out var table) ? new OpenType.TableReader(_data, table.Offset, table.Length) : default;

    /// <summary>Reserves the Type0 font object number (called when the font is first referenced by a page).</summary>
    internal int ReserveObject(PdfObjectWriter writer)
    {
        if (ObjectNumber == 0)
        {
            ObjectNumber = writer.AllocateObject();
        }

        return ObjectNumber;
    }

    /// <summary>Gets the subset tag (six uppercase letters derived from the glyph set), e.g. <c>ABCDEF</c>.</summary>
    internal string SubsetTag
    {
        get
        {
            var bytes = new byte[_usedGlyphs.Count * 2];
            int i = 0;
            foreach (ushort gid in _usedGlyphs.Keys)
            {
                BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(i), gid);
                i += 2;
            }

            byte[] hash = SHA256.HashData([.. Encoding.UTF8.GetBytes(PdfName), .. bytes]);
            var tag = new char[6];
            for (int c = 0; c < 6; c++)
            {
                tag[c] = (char)('A' + (hash[c] % 26));
            }

            return new string(tag);
        }
    }

    /// <summary>Writes the font program, descriptor, CIDFont, ToUnicode CMap, and Type0 dictionary.</summary>
    internal void WriteObjects(PdfObjectWriter writer)
    {
        int type0Obj = ReserveObject(writer);
        _usedGlyphs.TryAdd((ushort)0, "\uFFFD");

        bool subset = !IsCff;
        string baseFont = subset ? $"{SubsetTag}+{PdfName}" : PdfName;

        int fontFileObj = writer.AllocateObject();
        if (IsCff)
        {
            writer.WriteStreamObject(fontFileObj, "/Subtype /OpenType", _data);
        }
        else
        {
            byte[] program = TrueTypeSubsetter.Subset(_data, _tables, _usedGlyphs.Keys);
            writer.WriteStreamObject(fontFileObj, $"/Length1 {program.Length}", program);
        }

        int descriptorObj = writer.AllocateObject();
        var head = _tables["head"];
        short xMin = ReadInt16(_data, head.Offset + 36);
        short yMin = ReadInt16(_data, head.Offset + 38);
        short xMax = ReadInt16(_data, head.Offset + 40);
        short yMax = ReadInt16(_data, head.Offset + 42);
        float scale = 1000f / UnitsPerEm;
        int flags = 4; // Symbolic: glyphs are addressed by CID, not by a standard encoding.
        if (ItalicAngle != 0 || Variant is FontVariant.Italic or FontVariant.BoldItalic)
        {
            flags |= 64;
        }

        int stemV = Variant is FontVariant.Bold or FontVariant.BoldItalic ? 140 : 80;
        string fontFileKey = IsCff ? "/FontFile3" : "/FontFile2";
        writer.WriteObject(descriptorObj,
            $"<< /Type /FontDescriptor /FontName /{baseFont} /Flags {flags} " +
            $"/FontBBox [{Scale(xMin, scale)} {Scale(yMin, scale)} {Scale(xMax, scale)} {Scale(yMax, scale)}] " +
            $"/ItalicAngle {F(ItalicAngle)} /Ascent {F(Ascent)} /Descent {F(Descent)} " +
            $"/CapHeight {F(CapHeight)} /StemV {stemV} {fontFileKey} {fontFileObj} 0 R >>");

        var cidFont = writer.AllocateObject();
        string subtype = IsCff ? "/CIDFontType0" : "/CIDFontType2";
        string cidToGid = IsCff ? string.Empty : " /CIDToGIDMap /Identity";
        writer.WriteObject(cidFont,
            $"<< /Type /Font /Subtype {subtype} /BaseFont /{baseFont} " +
            "/CIDSystemInfo << /Registry (Adobe) /Ordering (Identity) /Supplement 0 >> " +
            $"/FontDescriptor {descriptorObj} 0 R /DW {GetAdvance(0) * 1000 / UnitsPerEm} /W {BuildWidths()}{cidToGid} >>");

        int toUnicodeObj = writer.AllocateObject();
        writer.WriteStreamObject(toUnicodeObj, string.Empty, BuildToUnicodeCMap());

        writer.WriteObject(type0Obj,
            $"<< /Type /Font /Subtype /Type0 /BaseFont /{baseFont} /Encoding /Identity-H " +
            $"/DescendantFonts [{cidFont} 0 R] /ToUnicode {toUnicodeObj} 0 R >>");
    }

    /// <summary>Kept for compatibility: writes the font and returns its resource entry.</summary>
    internal string BuildFontResource(PdfObjectWriter writer)
    {
        WriteObjects(writer);
        return $"/{ResourceKey} {ObjectNumber} 0 R";
    }

    private string BuildWidths()
    {
        var widths = new StringBuilder("[");
        ushort? runStart = null;
        ushort previous = 0;
        var run = new List<string>();
        foreach (ushort gid in _usedGlyphs.Keys)
        {
            string width = Math.Round(GetAdvance(gid) * 1000d / UnitsPerEm).ToString(CultureInfo.InvariantCulture);
            if (runStart is not null && gid == previous + 1)
            {
                run.Add(width);
            }
            else
            {
                FlushRun(widths, runStart, run);
                runStart = gid;
                run.Clear();
                run.Add(width);
            }

            previous = gid;
        }

        FlushRun(widths, runStart, run);
        widths.Append(']');
        return widths.ToString();
    }

    private static void FlushRun(StringBuilder widths, ushort? start, List<string> run)
    {
        if (start is null || run.Count == 0)
        {
            return;
        }

        if (widths.Length > 1)
        {
            widths.Append(' ');
        }

        widths.Append(start.Value.ToString(CultureInfo.InvariantCulture));
        widths.Append(" [");
        widths.Append(string.Join(' ', run));
        widths.Append(']');
    }

    internal byte[] BuildToUnicodeCMap()
    {
        var sb = new StringBuilder();
        sb.Append("/CIDInit /ProcSet findresource begin\n12 dict begin\nbegincmap\n");
        sb.Append("/CIDSystemInfo << /Registry (Adobe) /Ordering (UCS) /Supplement 0 >> def\n");
        sb.Append("/CMapName /Adobe-Identity-UCS def\n/CMapType 2 def\n");
        sb.Append("1 begincodespacerange\n<0000> <FFFF>\nendcodespacerange\n");
        foreach (var chunk in _usedGlyphs.Where(g => g.Key != 0 && g.Value.Length > 0).Chunk(100))
        {
            sb.Append(chunk.Length.ToString(CultureInfo.InvariantCulture));
            sb.Append(" beginbfchar\n");
            foreach (var (gid, text) in chunk)
            {
                sb.Append('<');
                sb.Append(gid.ToString("X4", CultureInfo.InvariantCulture));
                sb.Append("> <");
                foreach (char codeUnit in text)
                {
                    sb.Append(((int)codeUnit).ToString("X4", CultureInfo.InvariantCulture));
                }

                sb.Append(">\n");
            }

            sb.Append("endbfchar\n");
        }

        sb.Append("endcmap\nCMapName currentdict /CMap defineresource pop\nend\nend\n");
        return Encoding.ASCII.GetBytes(sb.ToString());
    }

    /// <summary>Detects a CID-keyed CFF font (Top DICT contains the ROS operator 12 30).</summary>
    private static bool CffIsCidKeyed(byte[] data, (int Offset, int Length) cff)
    {
        try
        {
            int pos = cff.Offset;
            int end = cff.Offset + cff.Length;
            int headerSize = data[pos + 2];
            pos += headerSize;
            pos = SkipIndex(data, pos); // Name INDEX
            // Top DICT INDEX: read first entry.
            int count = ReadUInt16(data, pos);
            if (count == 0)
            {
                return false;
            }

            int offSize = data[pos + 2];
            int offsetsStart = pos + 3;
            int first = ReadOffset(data, offsetsStart, offSize);
            int second = ReadOffset(data, offsetsStart + offSize, offSize);
            int dataStart = offsetsStart + ((count + 1) * offSize) - 1;
            int dictStart = dataStart + first;
            int dictEnd = Math.Min(dataStart + second, end);
            for (int i = dictStart; i < dictEnd; i++)
            {
                byte b = data[i];
                if (b == 12 && i + 1 < dictEnd)
                {
                    if (data[i + 1] == 30)
                    {
                        return true;
                    }

                    i++;
                }
                else if (b == 28)
                {
                    i += 2;
                }
                else if (b == 29)
                {
                    i += 4;
                }
                else if (b == 30)
                {
                    // Real number: nibbles until 0xf terminator.
                    while (++i < dictEnd && (data[i] & 0x0F) != 0x0F && (data[i] & 0xF0) != 0xF0)
                    {
                    }
                }
                else if (b is >= 247 and <= 254)
                {
                    i++;
                }
            }

            return false;
        }
        catch (IndexOutOfRangeException)
        {
            return false;
        }
        catch (ArgumentOutOfRangeException)
        {
            return false;
        }
    }

    private static int SkipIndex(byte[] data, int pos)
    {
        int count = ReadUInt16(data, pos);
        if (count == 0)
        {
            return pos + 2;
        }

        int offSize = data[pos + 2];
        int lastOffset = ReadOffset(data, pos + 3 + (count * offSize), offSize);
        return pos + 3 + ((count + 1) * offSize) + lastOffset - 1;
    }

    private static int ReadOffset(byte[] data, int pos, int size)
    {
        int value = 0;
        for (int i = 0; i < size; i++)
        {
            value = (value << 8) | data[pos + i];
        }

        return value;
    }

    private static int ReadInt32(byte[] data, int offset) => BinaryPrimitives.ReadInt32BigEndian(data.AsSpan(offset, 4));

    private static string F(float value) => value.ToString("0.##", CultureInfo.InvariantCulture);

    private ushort MapFormat4(int offset, int limit, ushort codepoint)
    {
        if (offset + 16 > limit)
        {
            return 0;
        }

        int segCount = ReadUInt16(_data, offset + 6) / 2;
        int endCodeBase = offset + 14;
        int startCodeBase = endCodeBase + (segCount * 2) + 2;
        int idDeltaBase = startCodeBase + (segCount * 2);
        int idRangeOffsetBase = idDeltaBase + (segCount * 2);
        if (idRangeOffsetBase + (segCount * 2) > limit)
        {
            return 0;
        }

        for (int i = 0; i < segCount; i++)
        {
            ushort endCode = ReadUInt16(_data, endCodeBase + (i * 2));
            if (codepoint > endCode)
            {
                continue;
            }

            ushort startCode = ReadUInt16(_data, startCodeBase + (i * 2));
            if (codepoint < startCode)
            {
                return 0;
            }

            short delta = ReadInt16(_data, idDeltaBase + (i * 2));
            int rangeOffsetPos = idRangeOffsetBase + (i * 2);
            ushort rangeOffset = ReadUInt16(_data, rangeOffsetPos);
            if (rangeOffset == 0)
            {
                return unchecked((ushort)(codepoint + delta));
            }

            int glyphPos = rangeOffsetPos + rangeOffset + ((codepoint - startCode) * 2);
            if (glyphPos + 2 > limit)
            {
                return 0;
            }

            ushort glyph = ReadUInt16(_data, glyphPos);
            return glyph == 0 ? (ushort)0 : unchecked((ushort)(glyph + delta));
        }

        return 0;
    }

    private ushort MapFormat12(int offset, int limit, uint codepoint)
    {
        if (offset + 16 > limit)
        {
            return 0;
        }

        uint groupCount = ReadUInt32(_data, offset + 12);
        int low = 0;
        int high = (int)Math.Min(groupCount, (uint)((limit - offset - 16) / 12)) - 1;
        while (low <= high)
        {
            int mid = low + ((high - low) / 2);
            int group = offset + 16 + (mid * 12);
            uint start = ReadUInt32(_data, group);
            uint end = ReadUInt32(_data, group + 4);
            if (codepoint < start)
            {
                high = mid - 1;
            }
            else if (codepoint > end)
            {
                low = mid + 1;
            }
            else
            {
                uint glyph = ReadUInt32(_data, group + 8) + (codepoint - start);
                return glyph < _numGlyphs ? (ushort)glyph : (ushort)0;
            }
        }

        return 0;
    }

    private static ushort ReadUInt16(byte[] data, int offset) => BinaryPrimitives.ReadUInt16BigEndian(data.AsSpan(offset, 2));

    private static short ReadInt16(byte[] data, int offset) => BinaryPrimitives.ReadInt16BigEndian(data.AsSpan(offset, 2));

    private static uint ReadUInt32(byte[] data, int offset) => BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(offset, 4));

    private static string Scale(short value, float scale) =>
        (value * scale).ToString("F0", CultureInfo.InvariantCulture);
}

using System.Buffers.Binary;

namespace SimpleSign.HtmlToPdf.Fonts;

/// <summary>
/// Produces a TrueType subset that keeps only the outlines of the glyphs used in a document.
/// Glyph ids are preserved (unused glyphs become empty), so the PDF can keep using an identity
/// CID-to-GID mapping. Composite glyph components are included automatically.
/// </summary>
internal static class TrueTypeSubsetter
{
    // Tables required to render a CIDFontType2 font program; cmap/name/post are not needed by PDF viewers.
    private static readonly string[] KeptTables = ["head", "hhea", "maxp", "hmtx", "cvt ", "fpgm", "prep", "OS/2"];

    private const ushort ArgsAreWords = 0x0001;
    private const ushort WeHaveAScale = 0x0008;
    private const ushort MoreComponents = 0x0020;
    private const ushort WeHaveAnXAndYScale = 0x0040;
    private const ushort WeHaveATwoByTwo = 0x0080;

    /// <summary>Builds the subset font program.</summary>
    /// <param name="font">The original font file.</param>
    /// <param name="tables">Table directory of the original font.</param>
    /// <param name="usedGlyphs">Glyph ids referenced by the document.</param>
    /// <returns>The subset font bytes, or the original font when it cannot be subset.</returns>
    internal static byte[] Subset(byte[] font, IReadOnlyDictionary<string, (int Offset, int Length)> tables, IEnumerable<ushort> usedGlyphs)
    {
        if (!tables.TryGetValue("glyf", out var glyf) || !tables.TryGetValue("loca", out var loca)
            || !tables.TryGetValue("head", out var head) || !tables.TryGetValue("maxp", out var maxp))
        {
            return font;
        }

        int numGlyphs = ReadUInt16(font, maxp.Offset + 4);
        bool longLoca = ReadInt16(font, head.Offset + 50) == 1;
        int[] offsets = ReadLoca(font, loca, numGlyphs, longLoca);
        if (offsets.Length == 0)
        {
            return font;
        }

        var keep = new SortedSet<int> { 0 };
        var pending = new Stack<int>();
        foreach (ushort gid in usedGlyphs)
        {
            if (gid < numGlyphs && keep.Add(gid))
            {
                pending.Push(gid);
            }
        }

        pending.Push(0);
        while (pending.Count > 0)
        {
            int gid = pending.Pop();
            foreach (int component in GetComponents(font, glyf, offsets, gid))
            {
                if (component < numGlyphs && keep.Add(component))
                {
                    pending.Push(component);
                }
            }
        }

        // New glyf + long loca: unused glyphs get zero length.
        using var glyfStream = new MemoryStream();
        var newLoca = new byte[(numGlyphs + 1) * 4];
        for (int gid = 0; gid < numGlyphs; gid++)
        {
            BinaryPrimitives.WriteUInt32BigEndian(newLoca.AsSpan(gid * 4), (uint)glyfStream.Position);
            if (!keep.Contains(gid))
            {
                continue;
            }

            int start = offsets[gid];
            int end = offsets[gid + 1];
            if (end > start && glyf.Offset + end <= font.Length && end <= glyf.Length)
            {
                glyfStream.Write(font, glyf.Offset + start, end - start);
                while (glyfStream.Position % 4 != 0)
                {
                    glyfStream.WriteByte(0);
                }
            }
        }

        BinaryPrimitives.WriteUInt32BigEndian(newLoca.AsSpan(numGlyphs * 4), (uint)glyfStream.Position);

        var newTables = new SortedDictionary<string, byte[]>(StringComparer.Ordinal)
        {
            ["glyf"] = glyfStream.ToArray(),
            ["loca"] = newLoca,
        };

        foreach (string tag in KeptTables)
        {
            if (tables.TryGetValue(tag, out var table))
            {
                newTables[tag] = font.AsSpan(table.Offset, table.Length).ToArray();
            }
        }

        // head: long loca format, checksum adjustment recomputed below.
        byte[] newHead = newTables["head"];
        if (newHead.Length >= 54)
        {
            BinaryPrimitives.WriteInt16BigEndian(newHead.AsSpan(50), 1);
            BinaryPrimitives.WriteUInt32BigEndian(newHead.AsSpan(8), 0);
        }

        return Assemble(newTables);
    }

    private static byte[] Assemble(SortedDictionary<string, byte[]> tables)
    {
        int numTables = tables.Count;
        int entrySelector = (int)Math.Floor(Math.Log2(numTables));
        int searchRange = (1 << entrySelector) * 16;
        int rangeShift = (numTables * 16) - searchRange;

        int headerLength = 12 + (numTables * 16);
        int offset = headerLength;
        var directory = new List<(string Tag, int Offset, byte[] Data)>();
        foreach (var (tag, data) in tables)
        {
            directory.Add((tag, offset, data));
            offset += (data.Length + 3) & ~3;
        }

        byte[] output = new byte[offset];
        BinaryPrimitives.WriteUInt32BigEndian(output.AsSpan(0), 0x00010000);
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(4), (ushort)numTables);
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(6), (ushort)searchRange);
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(8), (ushort)entrySelector);
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(10), (ushort)rangeShift);

        int headOffset = -1;
        for (int i = 0; i < directory.Count; i++)
        {
            var (tag, tableOffset, data) = directory[i];
            int record = 12 + (i * 16);
            for (int c = 0; c < 4; c++)
            {
                output[record + c] = (byte)tag[c];
            }

            BinaryPrimitives.WriteUInt32BigEndian(output.AsSpan(record + 4), Checksum(data));
            BinaryPrimitives.WriteUInt32BigEndian(output.AsSpan(record + 8), (uint)tableOffset);
            BinaryPrimitives.WriteUInt32BigEndian(output.AsSpan(record + 12), (uint)data.Length);
            data.CopyTo(output, tableOffset);
            if (tag == "head")
            {
                headOffset = tableOffset;
            }
        }

        if (headOffset >= 0)
        {
            uint adjustment = unchecked(0xB1B0AFBA - Checksum(output));
            BinaryPrimitives.WriteUInt32BigEndian(output.AsSpan(headOffset + 8), adjustment);
        }

        return output;
    }

    private static uint Checksum(byte[] data)
    {
        uint sum = 0;
        int full = data.Length & ~3;
        for (int i = 0; i < full; i += 4)
        {
            sum = unchecked(sum + BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(i)));
        }

        if (full < data.Length)
        {
            Span<byte> tail = stackalloc byte[4];
            data.AsSpan(full).CopyTo(tail);
            sum = unchecked(sum + BinaryPrimitives.ReadUInt32BigEndian(tail));
        }

        return sum;
    }

    private static int[] ReadLoca(byte[] font, (int Offset, int Length) loca, int numGlyphs, bool longFormat)
    {
        int entrySize = longFormat ? 4 : 2;
        if (loca.Length < (numGlyphs + 1) * entrySize)
        {
            return [];
        }

        var offsets = new int[numGlyphs + 1];
        for (int i = 0; i <= numGlyphs; i++)
        {
            offsets[i] = longFormat
                ? (int)BinaryPrimitives.ReadUInt32BigEndian(font.AsSpan(loca.Offset + (i * 4)))
                : ReadUInt16(font, loca.Offset + (i * 2)) * 2;
        }

        return offsets;
    }

    private static IEnumerable<int> GetComponents(byte[] font, (int Offset, int Length) glyf, int[] offsets, int gid)
    {
        if (gid + 1 >= offsets.Length)
        {
            yield break;
        }

        int start = offsets[gid];
        int end = offsets[gid + 1];
        if (end - start < 10 || glyf.Offset + end > font.Length)
        {
            yield break;
        }

        int pos = glyf.Offset + start;
        short contours = ReadInt16(font, pos);
        if (contours >= 0)
        {
            yield break;
        }

        pos += 10;
        int limit = glyf.Offset + end;
        while (pos + 4 <= limit)
        {
            ushort flags = ReadUInt16(font, pos);
            ushort component = ReadUInt16(font, pos + 2);
            yield return component;
            pos += 4;
            pos += (flags & ArgsAreWords) != 0 ? 4 : 2;
            if ((flags & WeHaveAScale) != 0)
            {
                pos += 2;
            }
            else if ((flags & WeHaveAnXAndYScale) != 0)
            {
                pos += 4;
            }
            else if ((flags & WeHaveATwoByTwo) != 0)
            {
                pos += 8;
            }

            if ((flags & MoreComponents) == 0)
            {
                break;
            }
        }
    }

    private static ushort ReadUInt16(byte[] data, int offset) => BinaryPrimitives.ReadUInt16BigEndian(data.AsSpan(offset, 2));

    private static short ReadInt16(byte[] data, int offset) => BinaryPrimitives.ReadInt16BigEndian(data.AsSpan(offset, 2));
}

using System.Buffers.Binary;

namespace SimpleSign.HtmlToPdf.Fonts.OpenType;

/// <summary>Bounds-checked big-endian reads over a font table. Out-of-range reads return 0.</summary>
internal readonly struct TableReader(byte[] data, int start, int length)
{
    public int Start => start;

    public int Length => length;

    public ushort U16(int offset) =>
        offset >= 0 && offset + 2 <= length ? BinaryPrimitives.ReadUInt16BigEndian(data.AsSpan(start + offset)) : (ushort)0;

    public short S16(int offset) => unchecked((short)U16(offset));

    public uint U32(int offset) =>
        offset >= 0 && offset + 4 <= length ? BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(start + offset)) : 0;

    public string Tag(int offset) =>
        offset >= 0 && offset + 4 <= length ? System.Text.Encoding.ASCII.GetString(data, start + offset, 4) : string.Empty;

    /// <summary>Returns a reader positioned at a sub-table (offset relative to this reader).</summary>
    public TableReader At(int offset) =>
        offset > 0 && offset < length ? new TableReader(data, start + offset, length - offset) : default;

    public bool IsValid => length > 0;
}

/// <summary>Coverage and class definition helpers.</summary>
internal static class LayoutCommon
{
    /// <summary>Returns the coverage index of a glyph, or -1.</summary>
    public static int Coverage(TableReader t, ushort glyph)
    {
        if (!t.IsValid)
        {
            return -1;
        }

        ushort format = t.U16(0);
        if (format == 1)
        {
            int count = t.U16(2);
            int lo = 0, hi = count - 1;
            while (lo <= hi)
            {
                int mid = (lo + hi) >> 1;
                ushort g = t.U16(4 + (mid * 2));
                if (g == glyph)
                {
                    return mid;
                }

                if (g < glyph)
                {
                    lo = mid + 1;
                }
                else
                {
                    hi = mid - 1;
                }
            }

            return -1;
        }

        if (format == 2)
        {
            int count = t.U16(2);
            int lo = 0, hi = count - 1;
            while (lo <= hi)
            {
                int mid = (lo + hi) >> 1;
                int record = 4 + (mid * 6);
                ushort startGlyph = t.U16(record), endGlyph = t.U16(record + 2);
                if (glyph < startGlyph)
                {
                    hi = mid - 1;
                }
                else if (glyph > endGlyph)
                {
                    lo = mid + 1;
                }
                else
                {
                    return t.U16(record + 4) + glyph - startGlyph;
                }
            }
        }

        return -1;
    }

    /// <summary>Returns the class of a glyph in a ClassDef table (0 when absent).</summary>
    public static int ClassOf(TableReader t, ushort glyph)
    {
        if (!t.IsValid)
        {
            return 0;
        }

        ushort format = t.U16(0);
        if (format == 1)
        {
            ushort startGlyph = t.U16(2);
            int count = t.U16(4);
            return glyph >= startGlyph && glyph < startGlyph + count ? t.U16(6 + ((glyph - startGlyph) * 2)) : 0;
        }

        if (format == 2)
        {
            int count = t.U16(2);
            int lo = 0, hi = count - 1;
            while (lo <= hi)
            {
                int mid = (lo + hi) >> 1;
                int record = 4 + (mid * 6);
                ushort startGlyph = t.U16(record), endGlyph = t.U16(record + 2);
                if (glyph < startGlyph)
                {
                    hi = mid - 1;
                }
                else if (glyph > endGlyph)
                {
                    lo = mid + 1;
                }
                else
                {
                    return t.U16(record + 4);
                }
            }
        }

        return 0;
    }
}

/// <summary>GDEF glyph classes and mark sets.</summary>
internal sealed class GdefTable
{
    public const int BaseClass = 1;
    public const int LigatureClass = 2;
    public const int MarkClass = 3;

    private readonly TableReader _glyphClasses;
    private readonly TableReader _markAttachClasses;
    private readonly TableReader _markGlyphSets;

    public GdefTable(TableReader table)
    {
        if (!table.IsValid)
        {
            return;
        }

        _glyphClasses = table.At(table.U16(4));
        _markAttachClasses = table.At(table.U16(10));
        if (table.U16(2) >= 2)
        {
            _markGlyphSets = table.At(table.U16(12));
        }
    }

    public bool HasGlyphClasses => _glyphClasses.IsValid;

    public int GlyphClass(ushort glyph) => LayoutCommon.ClassOf(_glyphClasses, glyph);

    public int MarkAttachClass(ushort glyph) => LayoutCommon.ClassOf(_markAttachClasses, glyph);

    public bool InMarkSet(int set, ushort glyph)
    {
        if (!_markGlyphSets.IsValid || set >= _markGlyphSets.U16(2))
        {
            return false;
        }

        int offset = (int)_markGlyphSets.U32(4 + (set * 4));
        return LayoutCommon.Coverage(_markGlyphSets.At(offset), glyph) >= 0;
    }
}

/// <summary>A GSUB or GPOS table: script/feature/lookup lists.</summary>
internal sealed class LayoutTable
{
    private readonly TableReader _scripts;
    private readonly TableReader _features;
    private readonly TableReader _lookups;

    public LayoutTable(TableReader table)
    {
        Table = table;
        if (!table.IsValid || table.U16(0) != 1)
        {
            return;
        }

        _scripts = table.At(table.U16(4));
        _features = table.At(table.U16(6));
        _lookups = table.At(table.U16(8));
    }

    public TableReader Table { get; }

    public bool IsValid => _lookups.IsValid;

    public int LookupCount => _lookups.U16(0);

    /// <summary>Gets a lookup: type, flag, mark filtering set and subtables (extension subtables unwrapped).</summary>
    public (int Type, ushort Flag, int MarkSet, List<TableReader> Subtables) Lookup(int index, int extensionType)
    {
        TableReader lookup = _lookups.At(_lookups.U16(2 + (index * 2)));
        int type = lookup.U16(0);
        ushort flag = lookup.U16(2);
        int count = lookup.U16(4);
        var subtables = new List<TableReader>(count);
        for (int i = 0; i < count; i++)
        {
            TableReader sub = lookup.At(lookup.U16(6 + (i * 2)));
            if (type == extensionType && sub.U16(0) == 1)
            {
                type = sub.U16(2);
                sub = sub.At((int)sub.U32(4));
            }

            subtables.Add(sub);
        }

        int markSet = (flag & 0x10) != 0 ? lookup.U16(6 + (count * 2)) : -1;
        return (type, flag, markSet, subtables);
    }

    /// <summary>Gets the lookup indices of each requested feature for the best matching script/language.</summary>
    public Dictionary<string, List<int>> FeatureLookups(IReadOnlyList<string> scriptTags, string? languageTag)
    {
        var result = new Dictionary<string, List<int>>(StringComparer.Ordinal);
        if (!_scripts.IsValid || !_features.IsValid)
        {
            return result;
        }

        TableReader script = default;
        foreach (string wanted in scriptTags)
        {
            int count = _scripts.U16(0);
            for (int i = 0; i < count && !script.IsValid; i++)
            {
                if (_scripts.Tag(2 + (i * 6)) == wanted)
                {
                    script = _scripts.At(_scripts.U16(6 + (i * 6)));
                }
            }

            if (script.IsValid)
            {
                break;
            }
        }

        if (!script.IsValid)
        {
            return result;
        }

        TableReader langSys = script.At(script.U16(0));
        if (languageTag is not null)
        {
            int langCount = script.U16(2);
            for (int i = 0; i < langCount; i++)
            {
                if (script.Tag(4 + (i * 6)) == languageTag)
                {
                    langSys = script.At(script.U16(8 + (i * 6)));
                    break;
                }
            }
        }

        if (!langSys.IsValid)
        {
            return result;
        }

        var featureIndices = new List<int>();
        ushort required = langSys.U16(2);
        if (required != 0xFFFF)
        {
            featureIndices.Add(required);
        }

        int featureCount = langSys.U16(4);
        for (int i = 0; i < featureCount; i++)
        {
            featureIndices.Add(langSys.U16(6 + (i * 2)));
        }

        int totalFeatures = _features.U16(0);
        foreach (int fi in featureIndices)
        {
            if (fi >= totalFeatures)
            {
                continue;
            }

            string tag = _features.Tag(2 + (fi * 6));
            TableReader feature = _features.At(_features.U16(6 + (fi * 6)));
            if (!result.TryGetValue(tag, out List<int>? lookups))
            {
                lookups = [];
                result[tag] = lookups;
            }

            int lookupCount = feature.U16(2);
            for (int k = 0; k < lookupCount; k++)
            {
                int li = feature.U16(4 + (k * 2));
                if (li < LookupCount && !lookups.Contains(li))
                {
                    lookups.Add(li);
                }
            }
        }

        return result;
    }
}

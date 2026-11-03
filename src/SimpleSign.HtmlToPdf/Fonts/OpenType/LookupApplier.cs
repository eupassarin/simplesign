namespace SimpleSign.HtmlToPdf.Fonts.OpenType;

/// <summary>
/// Applies GSUB and GPOS lookups to a glyph buffer: single, multiple, ligature and contextual
/// substitutions; single, pair, mark-to-base, mark-to-ligature, mark-to-mark and contextual positioning.
/// </summary>
internal sealed class LookupApplier
{
    private const int MaxNesting = 8;
    private const int MaxBufferGrowth = 4096;

    private readonly LayoutTable? _gsub;
    private readonly LayoutTable? _gpos;
    private readonly GdefTable _gdef;
    private int _operations;

    public LookupApplier(LayoutTable? gsub, LayoutTable? gpos, GdefTable gdef)
    {
        _gsub = gsub;
        _gpos = gpos;
        _gdef = gdef;
    }

    /// <summary>Sets the GDEF class of each glyph (falling back to Unicode marks when GDEF has no classes).</summary>
    public void Classify(List<GlyphInfo> buffer)
    {
        foreach (GlyphInfo g in buffer)
        {
            if (_gdef.HasGlyphClasses)
            {
                g.Class = _gdef.GlyphClass(g.Glyph);
            }
            else
            {
                g.Class = g.Text.Length > 0 && char.GetUnicodeCategory(g.Text, 0) is System.Globalization.UnicodeCategory.NonSpacingMark or System.Globalization.UnicodeCategory.EnclosingMark
                    ? GdefTable.MarkClass
                    : GdefTable.BaseClass;
            }

            g.MarkAttachClass = _gdef.MarkAttachClass(g.Glyph);
        }
    }

    /// <summary>Applies the given GSUB lookups (in lookup-list order) to glyphs whose mask matches.</summary>
    public void Substitute(List<GlyphInfo> buffer, IEnumerable<(int Lookup, ShapeMask Mask)> lookups)
    {
        if (_gsub is not { IsValid: true })
        {
            return;
        }

        foreach (var (lookup, mask) in lookups.OrderBy(l => l.Lookup))
        {
            var (type, flag, markSet, subtables) = _gsub.Lookup(lookup, 7);
            int i = 0;
            int limit = buffer.Count + MaxBufferGrowth;
            while (i < buffer.Count && buffer.Count < limit && _operations++ < 2_000_000)
            {
                GlyphInfo g = buffer[i];
                if ((g.Mask & mask) == 0 || Ignored(g, flag, markSet))
                {
                    i++;
                    continue;
                }

                int next = ApplySubstitution(buffer, i, type, flag, markSet, subtables, 0);
                i = next > i ? next : i + 1;
            }
        }
    }

    /// <summary>Applies the given GPOS lookups.</summary>
    public void Position(List<GlyphInfo> buffer, IEnumerable<int> lookups)
    {
        if (_gpos is not { IsValid: true })
        {
            return;
        }

        foreach (int lookup in lookups.Order())
        {
            var (type, flag, markSet, subtables) = _gpos.Lookup(lookup, 9);
            for (int i = 0; i < buffer.Count; i++)
            {
                if (!Ignored(buffer[i], flag, markSet))
                {
                    ApplyPositioning(buffer, i, type, flag, markSet, subtables, 0);
                }
            }
        }
    }

    // ── Matching helpers ─────────────────────────────────────────────────

    private bool Ignored(GlyphInfo g, ushort flag, int markSet)
    {
        int cls = g.Class;
        if (((flag & 0x2) != 0 && cls == GdefTable.BaseClass)
            || ((flag & 0x4) != 0 && cls == GdefTable.LigatureClass)
            || ((flag & 0x8) != 0 && cls == GdefTable.MarkClass))
        {
            return true;
        }

        if (cls == GdefTable.MarkClass)
        {
            int attachType = flag >> 8;
            if (attachType != 0 && g.MarkAttachClass != attachType)
            {
                return true;
            }

            if ((flag & 0x10) != 0 && markSet >= 0 && !_gdef.InMarkSet(markSet, g.Glyph))
            {
                return true;
            }
        }

        return false;
    }

    private int Next(List<GlyphInfo> buffer, int i, ushort flag, int markSet)
    {
        for (int j = i + 1; j < buffer.Count; j++)
        {
            if (!Ignored(buffer[j], flag, markSet))
            {
                return j;
            }
        }

        return -1;
    }

    private int Previous(List<GlyphInfo> buffer, int i, ushort flag, int markSet)
    {
        for (int j = i - 1; j >= 0; j--)
        {
            if (!Ignored(buffer[j], flag, markSet))
            {
                return j;
            }
        }

        return -1;
    }

    // ── GSUB ─────────────────────────────────────────────────────────────

    /// <summary>Tries each subtable at position i. Returns the index after the substitution, or i when nothing applied.</summary>
    private int ApplySubstitution(List<GlyphInfo> buffer, int i, int type, ushort flag, int markSet, List<TableReader> subtables, int depth)
    {
        foreach (TableReader t in subtables)
        {
            int result = type switch
            {
                1 => SingleSubst(buffer, i, t),
                2 => MultipleSubst(buffer, i, t),
                4 => LigatureSubst(buffer, i, t, flag, markSet),
                5 => ContextSubst(buffer, i, t, flag, markSet, depth, gsub: true),
                6 => ChainContext(buffer, i, t, flag, markSet, depth, gsub: true),
                _ => -1,
            };
            if (result >= 0)
            {
                return result;
            }
        }

        return i;
    }

    private int SingleSubst(List<GlyphInfo> buffer, int i, TableReader t)
    {
        GlyphInfo g = buffer[i];
        int index = LayoutCommon.Coverage(t.At(t.U16(2)), g.Glyph);
        if (index < 0)
        {
            return -1;
        }

        ushort replacement = t.U16(0) == 1
            ? unchecked((ushort)(g.Glyph + t.S16(4)))
            : index < t.U16(4) ? t.U16(6 + (index * 2)) : g.Glyph;
        SetGlyph(g, replacement);
        return i + 1;
    }

    private int MultipleSubst(List<GlyphInfo> buffer, int i, TableReader t)
    {
        GlyphInfo g = buffer[i];
        int index = LayoutCommon.Coverage(t.At(t.U16(2)), g.Glyph);
        if (index < 0 || index >= t.U16(4))
        {
            return -1;
        }

        TableReader sequence = t.At(t.U16(6 + (index * 2)));
        int count = sequence.U16(0);
        if (count == 0)
        {
            // Deleting a glyph keeps its text with the neighbour for ToUnicode.
            if (i > 0)
            {
                buffer[i - 1].Text += g.Text;
            }

            buffer.RemoveAt(i);
            return i;
        }

        var replacement = new List<GlyphInfo>(count);
        for (int k = 0; k < count; k++)
        {
            GlyphInfo copy = g.Clone();
            if (k > 0)
            {
                copy.Text = string.Empty;
            }

            SetGlyph(copy, sequence.U16(2 + (k * 2)));
            replacement.Add(copy);
        }

        buffer.RemoveAt(i);
        buffer.InsertRange(i, replacement);
        return i + count;
    }

    private int LigatureSubst(List<GlyphInfo> buffer, int i, TableReader t, ushort flag, int markSet)
    {
        GlyphInfo first = buffer[i];
        int index = LayoutCommon.Coverage(t.At(t.U16(2)), first.Glyph);
        if (index < 0 || index >= t.U16(4))
        {
            return -1;
        }

        TableReader set = t.At(t.U16(6 + (index * 2)));
        int ligatureCount = set.U16(0);
        for (int l = 0; l < ligatureCount; l++)
        {
            TableReader lig = set.At(set.U16(2 + (l * 2)));
            int components = lig.U16(2);
            if (components < 1)
            {
                continue;
            }

            var positions = new List<int>(components) { i };
            int pos = i;
            bool match = true;
            for (int c = 1; c < components && match; c++)
            {
                pos = Next(buffer, pos, flag, markSet);
                match = pos >= 0 && buffer[pos].Glyph == lig.U16(4 + ((c - 1) * 2));
                positions.Add(pos);
            }

            if (!match)
            {
                continue;
            }

            // Merge the components' text into the ligature; skipped marks stay in place.
            var text = new System.Text.StringBuilder(first.Text);
            for (int c = 1; c < positions.Count; c++)
            {
                text.Append(buffer[positions[c]].Text);
                first.Flags |= buffer[positions[c]].Flags;
            }

            first.Text = text.ToString();
            SetGlyph(first, lig.U16(0));
            if (_gdef.HasGlyphClasses)
            {
                first.Class = _gdef.GlyphClass(first.Glyph);
            }
            else if (components > 1)
            {
                first.Class = GdefTable.LigatureClass;
            }

            for (int c = positions.Count - 1; c >= 1; c--)
            {
                buffer.RemoveAt(positions[c]);
            }

            return i + 1;
        }

        return -1;
    }

    private void SetGlyph(GlyphInfo g, ushort glyph)
    {
        g.Glyph = glyph;
        if (_gdef.HasGlyphClasses)
        {
            g.Class = _gdef.GlyphClass(glyph);
            g.MarkAttachClass = _gdef.MarkAttachClass(glyph);
        }
    }

    // ── Context (shared by GSUB 5/6 and GPOS 7/8) ────────────────────────

    private int ContextSubst(List<GlyphInfo> buffer, int i, TableReader t, ushort flag, int markSet, int depth, bool gsub)
    {
        ushort format = t.U16(0);
        ushort first = buffer[i].Glyph;
        if (format == 1)
        {
            int index = LayoutCommon.Coverage(t.At(t.U16(2)), first);
            if (index < 0 || index >= t.U16(4))
            {
                return -1;
            }

            TableReader ruleSet = t.At(t.U16(6 + (index * 2)));
            for (int r = 0; r < ruleSet.U16(0); r++)
            {
                TableReader rule = ruleSet.At(ruleSet.U16(2 + (r * 2)));
                int glyphCount = rule.U16(0);
                int recordCount = rule.U16(2);
                if (MatchInput(buffer, i, glyphCount, flag, markSet, (k, g) => g == rule.U16(4 + ((k - 1) * 2))) is { } positions)
                {
                    return ApplyRecords(buffer, positions, rule, 4 + ((glyphCount - 1) * 2), recordCount, depth, gsub);
                }
            }

            return -1;
        }

        if (format == 2)
        {
            if (LayoutCommon.Coverage(t.At(t.U16(2)), first) < 0)
            {
                return -1;
            }

            TableReader classDef = t.At(t.U16(4));
            int cls = LayoutCommon.ClassOf(classDef, first);
            if (cls >= t.U16(6) || t.U16(8 + (cls * 2)) == 0)
            {
                return -1;
            }

            TableReader classSet = t.At(t.U16(8 + (cls * 2)));
            for (int r = 0; r < classSet.U16(0); r++)
            {
                TableReader rule = classSet.At(classSet.U16(2 + (r * 2)));
                int glyphCount = rule.U16(0);
                int recordCount = rule.U16(2);
                if (MatchInput(buffer, i, glyphCount, flag, markSet, (k, g) => LayoutCommon.ClassOf(classDef, g) == rule.U16(4 + ((k - 1) * 2))) is { } positions)
                {
                    return ApplyRecords(buffer, positions, rule, 4 + ((glyphCount - 1) * 2), recordCount, depth, gsub);
                }
            }

            return -1;
        }

        if (format == 3)
        {
            int glyphCount = t.U16(2);
            int recordCount = t.U16(4);
            if (glyphCount == 0 || LayoutCommon.Coverage(t.At(t.U16(6)), first) < 0)
            {
                return -1;
            }

            if (MatchInput(buffer, i, glyphCount, flag, markSet, (k, g) => LayoutCommon.Coverage(t.At(t.U16(6 + (k * 2))), g) >= 0) is { } positions)
            {
                return ApplyRecords(buffer, positions, t, 6 + (glyphCount * 2), recordCount, depth, gsub);
            }
        }

        return -1;
    }

    private int ChainContext(List<GlyphInfo> buffer, int i, TableReader t, ushort flag, int markSet, int depth, bool gsub)
    {
        ushort format = t.U16(0);
        ushort first = buffer[i].Glyph;
        if (format == 1 || format == 2)
        {
            if (LayoutCommon.Coverage(t.At(t.U16(2)), first) is int index && index < 0)
            {
                return -1;
            }

            TableReader backtrackClasses = default, inputClasses = default, lookaheadClasses = default;
            int setIndex;
            int setsOffset;
            if (format == 1)
            {
                setIndex = LayoutCommon.Coverage(t.At(t.U16(2)), first);
                setsOffset = 4;
            }
            else
            {
                backtrackClasses = t.At(t.U16(4));
                inputClasses = t.At(t.U16(6));
                lookaheadClasses = t.At(t.U16(8));
                setIndex = LayoutCommon.ClassOf(inputClasses, first);
                setsOffset = 10;
            }

            if (setIndex >= t.U16(setsOffset) || t.U16(setsOffset + 2 + (setIndex * 2)) == 0)
            {
                return -1;
            }

            TableReader set = t.At(t.U16(setsOffset + 2 + (setIndex * 2)));
            Func<TableReader, ushort, int> classOf = format == 1 ? (_, g) => g : LayoutCommon.ClassOf;
            for (int r = 0; r < set.U16(0); r++)
            {
                TableReader rule = set.At(set.U16(2 + (r * 2)));
                int pos = 0;
                int backtrackCount = rule.U16(pos);
                int backtrackStart = pos + 2;
                pos = backtrackStart + (backtrackCount * 2);
                int inputCount = rule.U16(pos);
                int inputStart = pos + 2;
                pos = inputStart + (Math.Max(0, inputCount - 1) * 2);
                int lookaheadCount = rule.U16(pos);
                int lookaheadStart = pos + 2;
                pos = lookaheadStart + (lookaheadCount * 2);
                int recordCount = rule.U16(pos);
                if (inputCount == 0)
                {
                    continue;
                }

                List<int>? positions = MatchInput(buffer, i, inputCount, flag, markSet, (k, g) => classOf(inputClasses, g) == rule.U16(inputStart + ((k - 1) * 2)));
                if (positions is null
                    || !MatchBacktrack(buffer, i, backtrackCount, flag, markSet, (k, g) => classOf(backtrackClasses, g) == rule.U16(backtrackStart + (k * 2)))
                    || !MatchLookahead(buffer, positions[^1], lookaheadCount, flag, markSet, (k, g) => classOf(lookaheadClasses, g) == rule.U16(lookaheadStart + (k * 2))))
                {
                    continue;
                }

                return ApplyRecords(buffer, positions, rule, pos + 2, recordCount, depth, gsub);
            }

            return -1;
        }

        if (format == 3)
        {
            int pos = 2;
            int backtrackCount = t.U16(pos);
            int backtrackStart = pos + 2;
            pos = backtrackStart + (backtrackCount * 2);
            int inputCount = t.U16(pos);
            int inputStart = pos + 2;
            pos = inputStart + (inputCount * 2);
            int lookaheadCount = t.U16(pos);
            int lookaheadStart = pos + 2;
            pos = lookaheadStart + (lookaheadCount * 2);
            int recordCount = t.U16(pos);
            if (inputCount == 0 || LayoutCommon.Coverage(t.At(t.U16(inputStart)), first) < 0)
            {
                return -1;
            }

            List<int>? positions = MatchInput(buffer, i, inputCount, flag, markSet, (k, g) => LayoutCommon.Coverage(t.At(t.U16(inputStart + (k * 2))), g) >= 0);
            if (positions is null
                || !MatchBacktrack(buffer, i, backtrackCount, flag, markSet, (k, g) => LayoutCommon.Coverage(t.At(t.U16(backtrackStart + (k * 2))), g) >= 0)
                || !MatchLookahead(buffer, positions[^1], lookaheadCount, flag, markSet, (k, g) => LayoutCommon.Coverage(t.At(t.U16(lookaheadStart + (k * 2))), g) >= 0))
            {
                return -1;
            }

            return ApplyRecords(buffer, positions, t, pos + 2, recordCount, depth, gsub);
        }

        return -1;
    }

    /// <summary>Matches the input sequence; <paramref name="test"/> receives (k ≥ 1, glyph) for the glyphs after the first.</summary>
    private List<int>? MatchInput(List<GlyphInfo> buffer, int i, int count, ushort flag, int markSet, Func<int, ushort, bool> test)
    {
        var positions = new List<int>(count) { i };
        int pos = i;
        for (int k = 1; k < count; k++)
        {
            pos = Next(buffer, pos, flag, markSet);
            if (pos < 0 || !test(k, buffer[pos].Glyph))
            {
                return null;
            }

            positions.Add(pos);
        }

        return positions;
    }

    private bool MatchBacktrack(List<GlyphInfo> buffer, int i, int count, ushort flag, int markSet, Func<int, ushort, bool> test)
    {
        int pos = i;
        for (int k = 0; k < count; k++)
        {
            pos = Previous(buffer, pos, flag, markSet);
            if (pos < 0 || !test(k, buffer[pos].Glyph))
            {
                return false;
            }
        }

        return true;
    }

    private bool MatchLookahead(List<GlyphInfo> buffer, int last, int count, ushort flag, int markSet, Func<int, ushort, bool> test)
    {
        int pos = last;
        for (int k = 0; k < count; k++)
        {
            pos = Next(buffer, pos, flag, markSet);
            if (pos < 0 || !test(k, buffer[pos].Glyph))
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>Applies nested lookups at matched positions. Returns the index after the matched input.</summary>
    private int ApplyRecords(List<GlyphInfo> buffer, List<int> positions, TableReader table, int recordsOffset, int recordCount, int depth, bool gsub)
    {
        int end = positions[^1] + 1;
        if (depth >= MaxNesting)
        {
            return end;
        }

        LayoutTable layout = (gsub ? _gsub : _gpos)!;
        for (int r = 0; r < recordCount; r++)
        {
            int sequenceIndex = table.U16(recordsOffset + (r * 4));
            int lookupIndex = table.U16(recordsOffset + (r * 4) + 2);
            if (sequenceIndex >= positions.Count || lookupIndex >= layout.LookupCount)
            {
                continue;
            }

            int at = positions[sequenceIndex];
            if (at >= buffer.Count)
            {
                continue;
            }

            var (type, flag, markSet, subtables) = layout.Lookup(lookupIndex, gsub ? 7 : 9);
            if (gsub)
            {
                int before = buffer.Count;
                ApplySubstitution(buffer, at, type, flag, markSet, subtables, depth + 1);
                int delta = buffer.Count - before;
                if (delta != 0)
                {
                    for (int p = 0; p < positions.Count; p++)
                    {
                        if (positions[p] > at)
                        {
                            positions[p] = Math.Max(at, positions[p] + delta);
                        }
                    }

                    end = Math.Max(at + 1, end + delta);
                }
            }
            else
            {
                ApplyPositioning(buffer, at, type, flag, markSet, subtables, depth + 1);
            }
        }

        return Math.Min(end, buffer.Count);
    }

    // ── GPOS ─────────────────────────────────────────────────────────────

    private void ApplyPositioning(List<GlyphInfo> buffer, int i, int type, ushort flag, int markSet, List<TableReader> subtables, int depth)
    {
        foreach (TableReader t in subtables)
        {
            bool applied = type switch
            {
                1 => SinglePos(buffer[i], t),
                2 => PairPos(buffer, i, t, flag, markSet),
                4 => MarkToBase(buffer, i, t),
                5 => MarkToLigature(buffer, i, t),
                6 => MarkToMark(buffer, i, t, flag, markSet),
                7 => ContextSubst(buffer, i, t, flag, markSet, depth, gsub: false) >= 0,
                8 => ChainContext(buffer, i, t, flag, markSet, depth, gsub: false) >= 0,
                _ => false,
            };
            if (applied)
            {
                return;
            }
        }
    }

    private static int ValueSize(ushort format) => System.Numerics.BitOperations.PopCount((uint)(format & 0xFF)) * 2;

    private static void ApplyValue(GlyphInfo g, TableReader t, int offset, ushort format)
    {
        int pos = offset;
        if ((format & 0x1) != 0)
        {
            g.XOffset += t.S16(pos);
            pos += 2;
        }

        if ((format & 0x2) != 0)
        {
            g.YOffset += t.S16(pos);
            pos += 2;
        }

        if ((format & 0x4) != 0)
        {
            g.XAdvance += t.S16(pos);
        }
    }

    private static bool SinglePos(GlyphInfo g, TableReader t)
    {
        int index = LayoutCommon.Coverage(t.At(t.U16(2)), g.Glyph);
        if (index < 0)
        {
            return false;
        }

        ushort format = t.U16(4);
        int offset = t.U16(0) == 1 ? 6 : 8 + (index * ValueSize(format));
        ApplyValue(g, t, offset, format);
        return true;
    }

    private bool PairPos(List<GlyphInfo> buffer, int i, TableReader t, ushort flag, int markSet)
    {
        int index = LayoutCommon.Coverage(t.At(t.U16(2)), buffer[i].Glyph);
        int j = Next(buffer, i, flag, markSet);
        if (index < 0 || j < 0)
        {
            return false;
        }

        ushort format1 = t.U16(4), format2 = t.U16(6);
        int size1 = ValueSize(format1), size2 = ValueSize(format2);
        ushort second = buffer[j].Glyph;
        if (t.U16(0) == 1)
        {
            if (index >= t.U16(8))
            {
                return false;
            }

            TableReader set = t.At(t.U16(10 + (index * 2)));
            int count = set.U16(0);
            int recordSize = 2 + size1 + size2;
            int lo = 0, hi = count - 1;
            while (lo <= hi)
            {
                int mid = (lo + hi) >> 1;
                int record = 2 + (mid * recordSize);
                ushort g = set.U16(record);
                if (g == second)
                {
                    ApplyValue(buffer[i], set, record + 2, format1);
                    ApplyValue(buffer[j], set, record + 2 + size1, format2);
                    return true;
                }

                if (g < second)
                {
                    lo = mid + 1;
                }
                else
                {
                    hi = mid - 1;
                }
            }

            return false;
        }

        if (t.U16(0) == 2)
        {
            int class1 = LayoutCommon.ClassOf(t.At(t.U16(8)), buffer[i].Glyph);
            int class2 = LayoutCommon.ClassOf(t.At(t.U16(10)), second);
            int class1Count = t.U16(12), class2Count = t.U16(14);
            if (class1 >= class1Count || class2 >= class2Count)
            {
                return false;
            }

            int record = 16 + (((class1 * class2Count) + class2) * (size1 + size2));
            ApplyValue(buffer[i], t, record, format1);
            ApplyValue(buffer[j], t, record + size1, format2);
            return true;
        }

        return false;
    }

    private static (int X, int Y)? Anchor(TableReader t) => t.IsValid ? (t.S16(2), t.S16(4)) : null;

    private static void Attach(List<GlyphInfo> buffer, int mark, int baseIndex, (int X, int Y) baseAnchor, (int X, int Y) markAnchor)
    {
        GlyphInfo m = buffer[mark];
        m.XOffset = baseAnchor.X - markAnchor.X;
        m.YOffset = baseAnchor.Y - markAnchor.Y;
        m.XAdvance = 0;
        m.AttachTo = baseIndex;
    }

    private static (int MarkClass, (int X, int Y) Anchor)? MarkRecord(TableReader t, int markArrayOffset, int markIndex)
    {
        TableReader markArray = t.At(t.U16(markArrayOffset));
        if (markIndex >= markArray.U16(0))
        {
            return null;
        }

        int record = 2 + (markIndex * 4);
        return Anchor(markArray.At(markArray.U16(record + 2))) is { } anchor ? (markArray.U16(record), anchor) : null;
    }

    private static bool MarkToBase(List<GlyphInfo> buffer, int i, TableReader t)
    {
        int markIndex = LayoutCommon.Coverage(t.At(t.U16(2)), buffer[i].Glyph);
        if (markIndex < 0)
        {
            return false;
        }

        // The base is the closest preceding glyph that is not a mark.
        int b = i - 1;
        while (b >= 0 && buffer[b].Class == GdefTable.MarkClass)
        {
            b--;
        }

        if (b < 0)
        {
            return false;
        }

        int baseIndex = LayoutCommon.Coverage(t.At(t.U16(4)), buffer[b].Glyph);
        int classCount = t.U16(6);
        if (baseIndex < 0 || MarkRecord(t, 8, markIndex) is not { } mark || mark.MarkClass >= classCount)
        {
            return false;
        }

        TableReader baseArray = t.At(t.U16(10));
        if (baseIndex >= baseArray.U16(0))
        {
            return false;
        }

        int anchorOffset = baseArray.U16(2 + (((baseIndex * classCount) + mark.MarkClass) * 2));
        if (Anchor(baseArray.At(anchorOffset)) is not { } baseAnchor)
        {
            return false;
        }

        Attach(buffer, i, b, baseAnchor, mark.Anchor);
        return true;
    }

    private static bool MarkToLigature(List<GlyphInfo> buffer, int i, TableReader t)
    {
        int markIndex = LayoutCommon.Coverage(t.At(t.U16(2)), buffer[i].Glyph);
        if (markIndex < 0)
        {
            return false;
        }

        int b = i - 1;
        while (b >= 0 && buffer[b].Class == GdefTable.MarkClass)
        {
            b--;
        }

        if (b < 0)
        {
            return false;
        }

        int ligIndex = LayoutCommon.Coverage(t.At(t.U16(4)), buffer[b].Glyph);
        int classCount = t.U16(6);
        if (ligIndex < 0 || MarkRecord(t, 8, markIndex) is not { } mark || mark.MarkClass >= classCount)
        {
            return false;
        }

        TableReader ligArray = t.At(t.U16(10));
        if (ligIndex >= ligArray.U16(0))
        {
            return false;
        }

        TableReader attach = ligArray.At(ligArray.U16(2 + (ligIndex * 2)));
        int components = attach.U16(0);
        if (components == 0)
        {
            return false;
        }

        // Approximation: attach to the last component.
        int component = components - 1;
        int anchorOffset = attach.U16(2 + (((component * classCount) + mark.MarkClass) * 2));
        if (Anchor(attach.At(anchorOffset)) is not { } ligAnchor)
        {
            return false;
        }

        Attach(buffer, i, b, ligAnchor, mark.Anchor);
        return true;
    }

    private bool MarkToMark(List<GlyphInfo> buffer, int i, TableReader t, ushort flag, int markSet)
    {
        int markIndex = LayoutCommon.Coverage(t.At(t.U16(2)), buffer[i].Glyph);
        int j = Previous(buffer, i, flag, markSet);
        if (markIndex < 0 || j < 0 || buffer[j].Class != GdefTable.MarkClass)
        {
            return false;
        }

        int mark2Index = LayoutCommon.Coverage(t.At(t.U16(4)), buffer[j].Glyph);
        int classCount = t.U16(6);
        if (mark2Index < 0 || MarkRecord(t, 8, markIndex) is not { } mark || mark.MarkClass >= classCount)
        {
            return false;
        }

        TableReader mark2Array = t.At(t.U16(10));
        if (mark2Index >= mark2Array.U16(0))
        {
            return false;
        }

        int anchorOffset = mark2Array.U16(2 + (((mark2Index * classCount) + mark.MarkClass) * 2));
        if (Anchor(mark2Array.At(anchorOffset)) is not { } mark2Anchor)
        {
            return false;
        }

        // Offsets chain: relative to the first mark, which is itself relative to its base.
        GlyphInfo first = buffer[j];
        Attach(buffer, i, first.AttachTo >= 0 ? first.AttachTo : j, mark2Anchor, mark.Anchor);
        if (first.AttachTo >= 0)
        {
            buffer[i].XOffset += first.XOffset;
            buffer[i].YOffset += first.YOffset;
        }

        return true;
    }
}

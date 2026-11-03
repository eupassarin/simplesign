using System.Globalization;
using System.Text;

namespace SimpleSign.HtmlToPdf.Fonts.OpenType;

/// <summary>Script families with their own shaping rules.</summary>
internal enum ShapingScript
{
    /// <summary>Latin, Greek, Cyrillic, Hebrew and other simple scripts.</summary>
    Default,

    /// <summary>Arabic and Syriac-style cursive joining.</summary>
    Arabic,

    /// <summary>Devanagari (basic Indic syllable shaping).</summary>
    Devanagari,
}

/// <summary>
/// Shapes text with a font's OpenType tables: Arabic joining forms and ligatures, basic Devanagari
/// conjuncts (reph, half forms, pre-base matra), Latin ligatures, kerning (GPOS or legacy kern) and
/// mark positioning. Output glyphs are in logical order.
/// </summary>
internal sealed class TextShaper
{
    private static readonly string[] DefaultGsub = ["ccmp", "locl", "rlig", "liga", "clig", "calt"];
    private static readonly string[] ArabicGsub = ["ccmp", "locl", "isol", "fina", "fin2", "fin3", "medi", "med2", "init", "rlig", "calt", "liga", "mset"];
    private static readonly string[] IndicBasic = ["nukt", "akhn", "rphf", "rkrf", "pref", "blwf", "abvf", "half", "pstf", "vatu", "cjct"];
    private static readonly string[] IndicPresentation = ["init", "pres", "abvs", "blws", "psts", "haln", "calt", "clig", "liga", "rlig"];
    private static readonly string[] DefaultGpos = ["kern", "mark", "mkmk"];
    private static readonly string[] IndicGpos = ["kern", "dist", "abvm", "blwm", "mark", "mkmk"];

    private readonly Func<int, ushort> _cmap;
    private readonly Func<ushort, int> _advance;
    private readonly LookupApplier _applier;
    private readonly LayoutTable? _gsub;
    private readonly LayoutTable? _gpos;
    private readonly Dictionary<(int, int), short>? _legacyKern;
    private readonly Dictionary<ShapingScript, (Dictionary<string, List<int>> Gsub, Dictionary<string, List<int>> Gpos)> _features = [];

    public TextShaper(Func<int, ushort> cmap, Func<ushort, int> advance, TableReader gsub, TableReader gpos, TableReader gdef, TableReader kern)
    {
        _cmap = cmap;
        _advance = advance;
        _gsub = gsub.IsValid ? new LayoutTable(gsub) : null;
        _gpos = gpos.IsValid ? new LayoutTable(gpos) : null;
        _applier = new LookupApplier(_gsub, _gpos, new GdefTable(gdef));
        _legacyKern = ReadLegacyKern(kern);
    }

    /// <summary>Gets a value indicating whether the font has any layout tables worth shaping with.</summary>
    public bool HasLayout => _gsub is { IsValid: true } || _gpos is { IsValid: true } || _legacyKern is not null;

    /// <summary>Detects which shaping rules a text needs.</summary>
    public static ShapingScript DetectScript(string text)
    {
        foreach (char c in text)
        {
            if (c is >= '؀' and <= 'ࣿ' or >= 'ﭐ' and <= '﷿' or >= 'ﹰ' and <= '﻿' or >= '܀' and <= 'ݏ')
            {
                return ShapingScript.Arabic;
            }

            if (c is >= 'ऀ' and <= 'ॿ' or >= '꣠' and <= 'ꣿ')
            {
                return ShapingScript.Devanagari;
            }
        }

        return ShapingScript.Default;
    }

    /// <summary>Shapes a run of text. Glyphs come back in visual order (reversed for right-to-left runs).</summary>
    public ShapedRun Shape(string text, bool rightToLeft)
    {
        // Canonical ordering/composition first (e.g. fatha before shadda), as shaping engines do.
        if (!text.IsNormalized(NormalizationForm.FormC))
        {
            text = text.Normalize(NormalizationForm.FormC);
        }

        ShapingScript script = DetectScript(text);
        if (script == ShapingScript.Arabic)
        {
            text = ReorderArabicMarks(text);
        }

        var buffer = new List<GlyphInfo>(text.Length);
        int index = 0;
        foreach (Rune rune in text.EnumerateRunes())
        {
            buffer.Add(new GlyphInfo { Glyph = _cmap(rune.Value), Cluster = index, Text = rune.ToString() });
            index += rune.Utf16SequenceLength;
        }

        _applier.Classify(buffer);
        (Dictionary<string, List<int>> gsub, Dictionary<string, List<int>> gpos) = Features(script);
        switch (script)
        {
            case ShapingScript.Arabic:
                ArabicJoining.SetMasks(buffer);
                _applier.Substitute(buffer, Lookups(gsub, ArabicGsub, ArabicMask));
                break;
            case ShapingScript.Devanagari:
                IndicShaping.Prepare(buffer, gsub.ContainsKey("rphf"));
                foreach (string feature in IndicBasic)
                {
                    _applier.Substitute(buffer, Lookups(gsub, [feature], IndicMask));
                }

                IndicShaping.FinalReorder(buffer);
                _applier.Substitute(buffer, Lookups(gsub, IndicPresentation, IndicMask));
                break;
            default:
                _applier.Substitute(buffer, Lookups(gsub, DefaultGsub, _ => ShapeMask.Global));
                break;
        }

        // Default-ignorable characters (joiners, variation selectors) that the font cannot draw are dropped.
        buffer.RemoveAll(g => g.Glyph == 0 && g.Text.Length > 0 && IsDefaultIgnorable(g.Text));

        foreach (GlyphInfo g in buffer)
        {
            g.XAdvance = _advance(g.Glyph);
            g.XOffset = 0;
            g.YOffset = 0;
            g.AttachTo = -1;
        }

        _applier.Classify(buffer);
        string[] gposFeatures = script == ShapingScript.Devanagari ? IndicGpos : DefaultGpos;
        _applier.Position(buffer, gposFeatures.Where(gpos.ContainsKey).SelectMany(f => gpos[f]).Distinct());
        if (!gpos.ContainsKey("kern") && _legacyKern is not null)
        {
            ApplyLegacyKern(buffer);
        }

        // Marks never advance the pen.
        foreach (GlyphInfo g in buffer)
        {
            if (g.Class == GdefTable.MarkClass)
            {
                g.XAdvance = 0;
            }
        }

        return Resolve(buffer, rightToLeft);
    }

    /// <summary>
    /// Orders harakat like HarfBuzz's modified combining classes: shadda comes first, then the
    /// other marks by canonical class.
    /// </summary>
    private static string ReorderArabicMarks(string text)
    {
        static bool IsHaraka(char c) => c is >= '\u064B' and <= '\u0652';
        static int Key(char c) => c == '\u0651' ? 0 : c;
        char[]? chars = null;
        int i = 0;
        while (i < text.Length)
        {
            if (!IsHaraka(text[i]))
            {
                i++;
                continue;
            }

            int start = i;
            while (i < text.Length && IsHaraka(text[i]))
            {
                i++;
            }

            if (i - start > 1)
            {
                chars ??= text.ToCharArray();
                char[] run = [.. chars.AsSpan(start, i - start).ToArray().OrderBy(Key)];
                run.CopyTo(chars, start);
            }
        }

        return chars is null ? text : new string(chars);
    }

    private static ShapeMask ArabicMask(string feature) => feature switch
    {
        "isol" => ShapeMask.Isol,
        "init" => ShapeMask.Init,
        "medi" or "med2" => ShapeMask.Medi,
        "fina" or "fin2" or "fin3" => ShapeMask.Fina,
        _ => ShapeMask.Global,
    };

    private static ShapeMask IndicMask(string feature) => feature switch
    {
        "rphf" => ShapeMask.Rphf,
        "half" => ShapeMask.Half,
        "blwf" => ShapeMask.Blwf,
        "pstf" => ShapeMask.Pstf,
        "rkrf" => ShapeMask.Rkrf,
        _ => ShapeMask.Global,
    };

    private static IEnumerable<(int, ShapeMask)> Lookups(Dictionary<string, List<int>> features, string[] tags, Func<string, ShapeMask> mask)
    {
        // A lookup shared by several features is eligible for the union of their masks.
        var result = new Dictionary<int, ShapeMask>();
        foreach (string tag in tags)
        {
            if (!features.TryGetValue(tag, out List<int>? lookups))
            {
                continue;
            }

            foreach (int lookup in lookups)
            {
                result[lookup] = result.GetValueOrDefault(lookup) | mask(tag);
            }
        }

        return result.Select(kv => (kv.Key, kv.Value));
    }

    private (Dictionary<string, List<int>> Gsub, Dictionary<string, List<int>> Gpos) Features(ShapingScript script)
    {
        if (!_features.TryGetValue(script, out var features))
        {
            string[] scriptTags = script switch
            {
                ShapingScript.Arabic => ["arab", "DFLT", "dflt", "latn"],
                ShapingScript.Devanagari => ["dev2", "deva", "DFLT", "dflt"],
                _ => ["latn", "DFLT", "dflt", "cyrl", "grek", "hebr"],
            };
            features = (
                _gsub?.FeatureLookups(scriptTags, null) ?? [],
                _gpos?.FeatureLookups(scriptTags, null) ?? []);
            _features[script] = features;
        }

        return features;
    }

    /// <summary>Converts advances and mark attachments into absolute glyph positions (font units).</summary>
    private static ShapedRun Resolve(List<GlyphInfo> buffer, bool rightToLeft)
    {
        var penX = new int[buffer.Count];
        int pen = 0;
        for (int i = 0; i < buffer.Count; i++)
        {
            penX[i] = pen;
            pen += buffer[i].XAdvance;
        }

        int width = pen;

        // Left edge of glyph i's own pen box in visual space.
        int Origin(int i) => rightToLeft ? width - penX[i] - buffer[i].XAdvance : penX[i];

        var glyphs = new List<PositionedGlyph>(buffer.Count);
        for (int i = 0; i < buffer.Count; i++)
        {
            GlyphInfo g = buffer[i];
            int x;
            int y = g.YOffset;
            if (g.AttachTo >= 0 && g.AttachTo < buffer.Count)
            {
                // Anchors are in glyph space, so the offset applies from the base's origin in either direction.
                GlyphInfo b = buffer[g.AttachTo];
                x = Origin(g.AttachTo) + g.XOffset + (b.AttachTo < 0 ? b.XOffset : 0);
                y += b.AttachTo < 0 ? b.YOffset : 0;
            }
            else
            {
                x = Origin(i) + g.XOffset;
            }

            glyphs.Add(new PositionedGlyph(g.Glyph, g.Text, x, y));
        }

        if (rightToLeft)
        {
            glyphs.Reverse();
        }

        return new ShapedRun(glyphs, width);
    }

    private static bool IsDefaultIgnorable(string text) =>
        text[0] is '​' or '‌' or '‍' or '‎' or '‏' or '⁠' or '﻿' or '­'
        || (text[0] >= '︀' && text[0] <= '️');

    private void ApplyLegacyKern(List<GlyphInfo> buffer)
    {
        for (int i = 0; i + 1 < buffer.Count; i++)
        {
            if (_legacyKern!.TryGetValue((buffer[i].Glyph, buffer[i + 1].Glyph), out short value))
            {
                buffer[i].XAdvance += value;
            }
        }
    }

    private static Dictionary<(int, int), short>? ReadLegacyKern(TableReader kern)
    {
        if (!kern.IsValid || kern.U16(0) != 0)
        {
            return null;
        }

        var pairs = new Dictionary<(int, int), short>();
        int tables = kern.U16(2);
        int pos = 4;
        for (int t = 0; t < tables && pos + 6 <= kern.Length; t++)
        {
            int length = kern.U16(pos + 2);
            ushort coverage = kern.U16(pos + 4);
            bool horizontal = (coverage & 0x1) != 0 && (coverage & 0x4) == 0 && (coverage >> 8) == 0;
            if (horizontal)
            {
                int count = kern.U16(pos + 6);
                for (int p = 0; p < count; p++)
                {
                    int record = pos + 14 + (p * 6);
                    pairs.TryAdd((kern.U16(record), kern.U16(record + 2)), kern.S16(record + 4));
                }
            }

            if (length <= 0)
            {
                break;
            }

            pos += length;
        }

        return pairs.Count > 0 ? pairs : null;
    }
}

/// <summary>Arabic cursive joining: chooses isolated/initial/medial/final forms.</summary>
internal static class ArabicJoining
{
    private enum Joining
    {
        NonJoining,
        Right,
        Dual,
        Causing,
        Transparent,
    }

    public static void SetMasks(List<GlyphInfo> buffer)
    {
        var types = buffer.Select(g => TypeOf(g.Text)).ToArray();
        var connectsBefore = new bool[buffer.Count];
        int previous = -1;
        for (int i = 0; i < buffer.Count; i++)
        {
            if (types[i] == Joining.Transparent)
            {
                continue;
            }

            if (previous >= 0 && types[previous] is Joining.Dual or Joining.Causing && types[i] is Joining.Right or Joining.Dual or Joining.Causing)
            {
                connectsBefore[i] = true;
            }

            previous = i;
        }

        for (int i = 0; i < buffer.Count; i++)
        {
            if (types[i] is not (Joining.Right or Joining.Dual))
            {
                continue;
            }

            int next = i + 1;
            while (next < buffer.Count && types[next] == Joining.Transparent)
            {
                next++;
            }

            bool before = connectsBefore[i];
            bool after = types[i] == Joining.Dual && next < buffer.Count && connectsBefore[next];
            buffer[i].Mask = ShapeMask.Global | (before, after) switch
            {
                (true, true) => ShapeMask.Medi,
                (true, false) => ShapeMask.Fina,
                (false, true) => ShapeMask.Init,
                _ => ShapeMask.Isol,
            };
        }
    }

    private static Joining TypeOf(string text)
    {
        if (text.Length == 0)
        {
            return Joining.NonJoining;
        }

        int c = char.ConvertToUtf32(text, 0);
        if (c is 0x200D or 0x0640 or 0x07FA)
        {
            return Joining.Causing;
        }

        UnicodeCategory category = CharUnicodeInfo.GetUnicodeCategory(c);
        if (category is UnicodeCategory.NonSpacingMark or UnicodeCategory.EnclosingMark || (category == UnicodeCategory.Format && c != 0x200C))
        {
            return Joining.Transparent;
        }

        return c switch
        {
            0x0622 or 0x0623 or 0x0624 or 0x0625 or 0x0627 or 0x0629 or 0x062F or 0x0630 or 0x0631 or 0x0632 or 0x0648
                or (>= 0x0671 and <= 0x0673) or (>= 0x0675 and <= 0x0677) or (>= 0x0688 and <= 0x0699) or 0x06C0
                or (>= 0x06C3 and <= 0x06CB) or 0x06CD or 0x06CF or 0x06D2 or 0x06D3 or 0x06D5 or 0x06EE or 0x06EF
                or (>= 0x0759 and <= 0x075B) or 0x076B or 0x076C or 0x0771 or 0x0773 or 0x0774 or 0x0778 or 0x0779
                or (>= 0x08AA and <= 0x08AC) or 0x08AE or 0x08B1 or 0x08B2 or 0x08B9 => Joining.Right,
            0x0626 or 0x0628 or (>= 0x062A and <= 0x062E) or (>= 0x0633 and <= 0x063F) or (>= 0x0641 and <= 0x0647)
                or 0x0649 or 0x064A or 0x066E or 0x066F or (>= 0x0678 and <= 0x0687) or (>= 0x069A and <= 0x06BF)
                or 0x06C1 or 0x06C2 or 0x06CC or 0x06CE or 0x06D0 or 0x06D1 or (>= 0x06FA and <= 0x06FC) or 0x06FF
                or (>= 0x0750 and <= 0x0758) or (>= 0x075C and <= 0x076A) or (>= 0x076D and <= 0x0770) or 0x0772
                or (>= 0x0775 and <= 0x0777) or (>= 0x077A and <= 0x077F) or (>= 0x08A0 and <= 0x08A9) or 0x08AF or 0x08B0
                or (>= 0x08B3 and <= 0x08B8) or (>= 0x08BA and <= 0x08C8) => Joining.Dual,
            _ => Joining.NonJoining,
        };
    }
}

/// <summary>
/// Basic Devanagari shaping: syllable detection, reph and half-form masks, pre-base matra and
/// reph reordering. Covers common conjuncts; rare Indic behaviours are not modelled.
/// </summary>
internal static class IndicShaping
{
    private const char Halant = '्';
    private const char Nukta = '़';
    private const char Ra = 'र';

    private enum Category
    {
        Other,
        Consonant,
        Vowel,
        Matra,
        PreBaseMatra,
        Halant,
        Nukta,
        Modifier,
        Joiner,
    }

    private static Category CategoryOf(string text)
    {
        if (text.Length != 1)
        {
            return Category.Other;
        }

        char c = text[0];
        return c switch
        {
            (>= 'क' and <= 'ह') or (>= 'क़' and <= 'य़') or (>= 'ॸ' and <= 'ॿ') => Category.Consonant,
            (>= 'ऄ' and <= 'औ') or 'ॠ' or 'ॡ' or (>= 'ॲ' and <= 'ॷ') => Category.Vowel,
            'ि' or 'ॎ' => Category.PreBaseMatra,
            (>= 'ऺ' and <= 'ौ') and not '़' and not 'ऽ' => Category.Matra,
            'ॏ' or (>= 'ॕ' and <= 'ॗ') or 'ॢ' or 'ॣ' => Category.Matra,
            Halant => Category.Halant,
            Nukta => Category.Nukta,
            (>= 'ऀ' and <= 'ः') => Category.Modifier,
            '‌' or '‍' => Category.Joiner,
            _ => Category.Other,
        };
    }

    /// <summary>Finds syllables, sets feature masks and moves pre-base matras to the syllable start.</summary>
    public static void Prepare(List<GlyphInfo> buffer, bool fontHasReph)
    {
        Category[] cats = [.. buffer.Select(g => CategoryOf(g.Text))];
        int syllable = 0;
        int i = 0;
        while (i < buffer.Count)
        {
            int start = i;
            if (cats[i] == Category.Consonant)
            {
                // C (N)? (H ZWJ/ZWNJ? C (N)?)*
                var consonants = new List<int>();
                while (i < buffer.Count && cats[i] == Category.Consonant)
                {
                    consonants.Add(i);
                    i++;
                    if (i < buffer.Count && cats[i] == Category.Nukta)
                    {
                        i++;
                    }

                    int afterHalant = i + 1;
                    bool nonJoiner = false;
                    while (afterHalant < buffer.Count && cats[afterHalant] == Category.Joiner)
                    {
                        nonJoiner |= buffer[afterHalant].Text == "\u200C";
                        afterHalant++;
                    }

                    // ZWNJ after a halant keeps the virama visible and ends the cluster.
                    if (nonJoiner)
                    {
                        break;
                    }

                    if (i < buffer.Count && cats[i] == Category.Halant && afterHalant < buffer.Count && cats[afterHalant] == Category.Consonant)
                    {
                        i = afterHalant;
                        continue;
                    }

                    break;
                }

                // Final halant, then matras and modifiers.
                if (i < buffer.Count && cats[i] == Category.Halant)
                {
                    i++;
                }

                while (i < buffer.Count && cats[i] is Category.Matra or Category.PreBaseMatra or Category.Nukta or Category.Halant)
                {
                    i++;
                }

                while (i < buffer.Count && cats[i] == Category.Modifier)
                {
                    i++;
                }

                MarkConsonantSyllable(buffer, cats, start, i, consonants, fontHasReph);
            }
            else if (cats[i] == Category.Vowel)
            {
                i++;
                while (i < buffer.Count && cats[i] is Category.Nukta or Category.Matra or Category.Modifier or Category.Halant)
                {
                    i++;
                }
            }
            else
            {
                i++;
            }

            for (int k = start; k < i; k++)
            {
                buffer[k].Syllable = syllable;
                if (cats[k] == Category.Modifier)
                {
                    buffer[k].Flags |= GlyphFlags.Modifier;
                }
            }

            syllable++;
        }

        // Pre-base matras go to the start of their syllable (after a reph, which moves later anyway).
        for (int k = 0; k < buffer.Count; k++)
        {
            if ((buffer[k].Flags & GlyphFlags.PreBaseMatra) == 0)
            {
                continue;
            }

            int s = buffer[k].Syllable;
            int target = k;
            while (target > 0 && buffer[target - 1].Syllable == s && (buffer[target - 1].Flags & GlyphFlags.Reph) == 0
                && !(buffer[target - 1].Mask.HasFlag(ShapeMask.Rphf)))
            {
                target--;
            }

            if (target < k)
            {
                GlyphInfo matra = buffer[k];
                buffer.RemoveAt(k);
                buffer.Insert(target, matra);
            }
        }
    }

    private static void MarkConsonantSyllable(List<GlyphInfo> buffer, Category[] cats, int start, int end, List<int> consonants, bool fontHasReph)
    {
        for (int k = start; k < end; k++)
        {
            if (cats[k] == Category.PreBaseMatra)
            {
                buffer[k].Flags |= GlyphFlags.PreBaseMatra;
            }

            if (cats[k] == Category.Halant)
            {
                buffer[k].Flags |= GlyphFlags.Halant;
            }
        }

        int firstConsonant = 0;
        bool reph = fontHasReph && consonants.Count > 1 && buffer[consonants[0]].Text[0] == Ra
            && consonants[0] + 1 < end && cats[consonants[0] + 1] == Category.Halant;
        if (reph)
        {
            buffer[consonants[0]].Mask = ShapeMask.Global | ShapeMask.Rphf;
            buffer[consonants[0] + 1].Mask = ShapeMask.Global | ShapeMask.Rphf;
            buffer[consonants[0]].Flags |= GlyphFlags.Reph;
            firstConsonant = 1;
        }

        // The base is the last consonant, except that a final Ra after a halant becomes a below-base form.
        int baseIndex = consonants.Count - 1;
        if (baseIndex > firstConsonant && buffer[consonants[baseIndex]].Text[0] == Ra && cats[consonants[baseIndex] - 1] == Category.Halant)
        {
            int ra = consonants[baseIndex];
            buffer[ra - 1].Mask |= ShapeMask.Blwf | ShapeMask.Rkrf | ShapeMask.Pstf;
            buffer[ra].Mask |= ShapeMask.Blwf | ShapeMask.Rkrf | ShapeMask.Pstf;

            // rkrf/blwf also see the preceding consonant (Ka + Halant + Ra → kra).
            buffer[ra - 2 >= 0 ? ra - 2 : ra].Mask |= ShapeMask.Rkrf;
            baseIndex--;
        }

        buffer[consonants[baseIndex]].Flags |= GlyphFlags.Base;
        for (int c = firstConsonant; c < baseIndex; c++)
        {
            int k = consonants[c];
            buffer[k].Mask |= ShapeMask.Half;
            if (k + 1 < end && cats[k + 1] == Category.Halant)
            {
                buffer[k + 1].Mask |= ShapeMask.Half;
            }
            else if (k + 2 < end && cats[k + 1] == Category.Nukta && cats[k + 2] == Category.Halant)
            {
                buffer[k + 1].Mask |= ShapeMask.Half;
                buffer[k + 2].Mask |= ShapeMask.Half;
            }
        }
    }

    /// <summary>After the basic features: move the reph after the base cluster and the pre-base matra past standalone halants.</summary>
    public static void FinalReorder(List<GlyphInfo> buffer)
    {
        int i = 0;
        while (i < buffer.Count)
        {
            int s = buffer[i].Syllable;
            int end = i;
            while (end < buffer.Count && buffer[end].Syllable == s)
            {
                end++;
            }

            if (s >= 0)
            {
                ReorderSyllable(buffer, i, end);
            }

            i = end;
        }
    }

    private static void ReorderSyllable(List<GlyphInfo> buffer, int start, int end)
    {
        // Reph: the glyph formed from Ra+Halant (flagged on its first component) moves to the end,
        // before syllable modifiers (anusvara, visarga, candrabindu).
        int reph = -1;
        for (int k = start; k < end; k++)
        {
            if ((buffer[k].Flags & GlyphFlags.Reph) != 0 && buffer[k].Text.Length >= 2 && buffer[k].Text[0] == Ra)
            {
                reph = k;
                break;
            }
        }

        if (reph >= 0)
        {
            int target = end;
            while (target - 1 > reph && (buffer[target - 1].Flags & GlyphFlags.Modifier) != 0)
            {
                target--;
            }

            GlyphInfo glyph = buffer[reph];
            buffer.RemoveAt(reph);
            buffer.Insert(target - 1, glyph);
        }

        // A pre-base matra sits after the last standalone (unconsumed) halant before the base.
        int matra = -1;
        int baseIndex = -1;
        for (int k = start; k < end; k++)
        {
            if ((buffer[k].Flags & GlyphFlags.PreBaseMatra) != 0 && buffer[k].Text.Length == 1)
            {
                matra = k;
            }

            if ((buffer[k].Flags & GlyphFlags.Base) != 0 && baseIndex < 0)
            {
                baseIndex = k;
            }
        }

        if (matra < 0 || baseIndex < 0 || matra > baseIndex)
        {
            return;
        }

        int lastHalant = -1;
        for (int k = matra + 1; k < baseIndex; k++)
        {
            if (buffer[k].Text == Halant.ToString())
            {
                lastHalant = k;
            }
        }

        if (lastHalant > matra)
        {
            GlyphInfo glyph = buffer[matra];
            buffer.RemoveAt(matra);
            buffer.Insert(lastHalant, glyph);
        }
    }
}

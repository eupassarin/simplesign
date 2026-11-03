using System.Text;
using SimpleSign.HtmlToPdf.Rendering;

namespace SimpleSign.HtmlToPdf.Fonts;

/// <summary>A caller-supplied font file registered under a CSS family name.</summary>
/// <param name="Family">CSS family name.</param>
/// <param name="Variant">Face variant.</param>
/// <param name="Data">Font file bytes.</param>
internal sealed record FontRegistration(string Family, FontVariant Variant, byte[] Data);

/// <summary>
/// The concrete face chosen for a piece of text: either an embedded font or one of the standard 14 fonts,
/// plus whether bold/italic must be synthesized because the family lacks that face.
/// </summary>
/// <param name="Embedded">The embedded face, or null for a standard font.</param>
/// <param name="StandardName">The standard PDF base font name used when <paramref name="Embedded"/> is null.</param>
/// <param name="SyntheticBold">Whether to emulate bold (fill + stroke).</param>
/// <param name="SyntheticItalic">Whether to emulate italic (skewed text matrix).</param>
internal readonly record struct ResolvedFont(EmbeddedFont? Embedded, string StandardName, bool SyntheticBold, bool SyntheticItalic)
{
    internal static ResolvedFont Standard(string name) => new(null, name, false, false);

    internal bool IsEmbedded => Embedded is not null;

    /// <summary>Returns true when this face can render the rune.</summary>
    internal bool CanRender(Rune rune)
    {
        if (Embedded is not null)
        {
            return Embedded.HasGlyph(rune);
        }

        return rune.Value < 0x10000 && (rune.Value is >= 32 and < 127 || WinAnsiEncoding.MapToWinAnsi((char)rune.Value) >= 0);
    }

    /// <summary>Measures a single rune in this face (no letter/word spacing).</summary>
    internal float MeasureRune(Rune rune, float fontSize)
    {
        if (Embedded is not null)
        {
            return Embedded.Measure(rune, fontSize);
        }

        char c = rune.Value < 0x10000 ? (char)rune.Value : '?';
        return FontMetrics.GetCharWidth(StandardName, c) * fontSize / 1000f;
    }
}

/// <summary>Registered fonts for one HTML-to-PDF conversion, with family/variant resolution and glyph fallback.</summary>
internal sealed class FontCollection
{
    private readonly Dictionary<string, Dictionary<FontVariant, EmbeddedFont>> _families = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<EmbeddedFont> _ordered = [];

    internal FontCollection(IReadOnlyDictionary<string, byte[]> fonts)
        : this(fonts.Select(f => new FontRegistration(f.Key, FontVariant.Regular, f.Value)))
    {
    }

    internal FontCollection(IEnumerable<FontRegistration> registrations)
    {
        foreach (FontRegistration registration in registrations)
        {
            string family = NormalizeFamily(registration.Family);
            var font = new EmbeddedFont(family, registration.Data, registration.Variant);
            if (!_families.TryGetValue(family, out var faces))
            {
                faces = [];
                _families[family] = faces;
            }

            if (faces.TryGetValue(registration.Variant, out EmbeddedFont? existing))
            {
                _ordered.Remove(existing);
            }

            faces[registration.Variant] = font;
            _ordered.Add(font);
        }

        for (int i = 0; i < _ordered.Count; i++)
        {
            _ordered[i].ResourceKey = $"CF{i + 1}";
        }
    }

    internal bool IsEmpty => _ordered.Count == 0;

    /// <summary>
    /// Gets or sets a value indicating whether only embedded fonts may be used (PDF/A). Families that are not
    /// registered resolve to the first registered family, and missing glyphs are dropped instead of drawn as .notdef.
    /// </summary>
    internal bool EmbeddedOnly { get; set; }

    internal IEnumerable<EmbeddedFont> Fonts => _ordered;

    /// <summary>Gets the regular (or closest) face of a registered family.</summary>
    internal bool TryGet(string family, out EmbeddedFont font)
    {
        if (_families.TryGetValue(NormalizeFamily(family), out var faces))
        {
            font = faces.TryGetValue(FontVariant.Regular, out EmbeddedFont? regular) ? regular : faces.Values.First();
            return true;
        }

        font = null!;
        return false;
    }

    internal bool HasFamily(string family) => _families.ContainsKey(NormalizeFamily(family));

    /// <summary>Resolves the face for a CSS family list and requested style.</summary>
    internal static ResolvedFont Resolve(FontCollection? fonts, IReadOnlyList<string> families, bool bold, bool italic)
    {
        foreach (string family in families)
        {
            if (fonts is not null && fonts._families.TryGetValue(NormalizeFamily(family), out var faces))
            {
                return PickFace(faces, bold, italic);
            }

            if (StandardFonts.IsKnownFamily(family) && fonts?.EmbeddedOnly != true)
            {
                return ResolvedFont.Standard(StandardFonts.Resolve(family, bold, italic));
            }
        }

        if (fonts is { EmbeddedOnly: true, IsEmpty: false })
        {
            return PickFace(fonts._families.Values.First(), bold, italic);
        }

        return ResolvedFont.Standard(StandardFonts.Resolve(families.Count > 0 ? families[0] : "Helvetica", bold, italic));
    }

    /// <summary>Resolves a single family name (compatibility path for callers without a family list).</summary>
    internal static ResolvedFont Resolve(FontCollection? fonts, string family, bool bold, bool italic) =>
        Resolve(fonts, [family], bold, italic);

    private static ResolvedFont PickFace(Dictionary<FontVariant, EmbeddedFont> faces, bool bold, bool italic)
    {
        FontVariant wanted = (bold, italic) switch
        {
            (true, true) => FontVariant.BoldItalic,
            (true, false) => FontVariant.Bold,
            (false, true) => FontVariant.Italic,
            _ => FontVariant.Regular,
        };

        if (faces.TryGetValue(wanted, out EmbeddedFont? exact))
        {
            return new ResolvedFont(exact, string.Empty, false, false);
        }

        // Closest face, then synthesize what is missing.
        FontVariant[] preference = wanted switch
        {
            FontVariant.BoldItalic => [FontVariant.Bold, FontVariant.Italic, FontVariant.Regular],
            FontVariant.Bold => [FontVariant.Regular, FontVariant.BoldItalic, FontVariant.Italic],
            FontVariant.Italic => [FontVariant.Regular, FontVariant.BoldItalic, FontVariant.Bold],
            _ => [FontVariant.Bold, FontVariant.Italic, FontVariant.BoldItalic],
        };

        foreach (FontVariant candidate in preference)
        {
            if (faces.TryGetValue(candidate, out EmbeddedFont? face))
            {
                bool faceBold = candidate is FontVariant.Bold or FontVariant.BoldItalic;
                bool faceItalic = candidate is FontVariant.Italic or FontVariant.BoldItalic;
                return new ResolvedFont(face, string.Empty, bold && !faceBold, italic && !faceItalic);
            }
        }

        EmbeddedFont any = faces.Values.First();
        return new ResolvedFont(any, string.Empty, bold, italic);
    }

    /// <summary>
    /// Splits text into runs that can each be rendered by a single face. Characters missing from the
    /// primary face fall back to other registered fonts that contain them, then to the standard fonts.
    /// </summary>
    internal static List<(string Text, ResolvedFont Font)> SplitRuns(string text, ResolvedFont primary, FontCollection? fonts)
    {
        var runs = new List<(string Text, ResolvedFont Font)>(1);
        if (text.Length == 0)
        {
            return runs;
        }

        // Fast path: everything renders with the primary face.
        bool allPrimary = true;
        foreach (Rune rune in text.EnumerateRunes())
        {
            if (!IsRenderable(primary, rune))
            {
                allPrimary = false;
                break;
            }
        }

        if (allPrimary)
        {
            runs.Add((text, primary));
            return runs;
        }

        var current = new StringBuilder();
        ResolvedFont currentFont = primary;
        foreach (Rune rune in text.EnumerateRunes())
        {
            ResolvedFont font = IsRenderable(primary, rune) ? primary : FindFallback(rune, primary, fonts);
            if (current.Length > 0 && font != currentFont)
            {
                runs.Add((current.ToString(), currentFont));
                current.Clear();
            }

            currentFont = font;
            current.Append(rune.ToString());
        }

        if (current.Length > 0)
        {
            runs.Add((current.ToString(), currentFont));
        }

        return runs;
    }

    private static bool IsRenderable(ResolvedFont font, Rune rune) =>
        font.CanRender(rune) || Rune.IsControl(rune) || rune.Value is 0x200B or 0xFEFF or 0x00AD;

    private static ResolvedFont FindFallback(Rune rune, ResolvedFont primary, FontCollection? fonts)
    {
        bool bold = primary.SyntheticBold || primary.Embedded?.Variant is FontVariant.Bold or FontVariant.BoldItalic
            || primary.StandardName.Contains("Bold", StringComparison.Ordinal);
        bool italic = primary.SyntheticItalic || primary.Embedded?.Variant is FontVariant.Italic or FontVariant.BoldItalic
            || primary.StandardName.Contains("Oblique", StringComparison.Ordinal) || primary.StandardName.Contains("Italic", StringComparison.Ordinal);

        if (fonts is not null)
        {
            foreach (var faces in fonts._families.Values)
            {
                ResolvedFont candidate = PickFace(faces, bold, italic);
                if (candidate.Embedded!.HasGlyph(rune))
                {
                    return candidate;
                }
            }
        }

        if (primary.IsEmbedded && fonts?.EmbeddedOnly != true)
        {
            ResolvedFont standard = ResolvedFont.Standard(StandardFonts.Resolve("Helvetica", bold, italic));
            if (standard.CanRender(rune))
            {
                return standard;
            }
        }

        // Nothing can render it: keep the primary face (.notdef / '?').
        return primary;
    }

    /// <summary>Writes every embedded font that was referenced by at least one page.</summary>
    internal void WriteUsedFonts(PdfObjectWriter writer)
    {
        foreach (EmbeddedFont font in _ordered)
        {
            if (font.ObjectNumber != 0)
            {
                font.WriteObjects(writer);
            }
        }
    }

    internal static string BuildFontResources(PdfObjectWriter writer, IEnumerable<EmbeddedFont> usedFonts)
    {
        var entries = new List<string>();
        foreach (EmbeddedFont font in usedFonts.Distinct())
        {
            entries.Add($"/{font.ResourceKey} {font.ReserveObject(writer)} 0 R");
        }

        return string.Join(" ", entries);
    }

    private static string NormalizeFamily(string family) => family.Trim().Trim('\'', '"').Trim();
}

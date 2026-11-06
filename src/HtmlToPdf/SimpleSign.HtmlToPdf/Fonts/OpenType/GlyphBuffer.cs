namespace SimpleSign.HtmlToPdf.Fonts.OpenType;

/// <summary>Feature masks: a glyph takes part in a masked feature only when its mask has the feature's bit.</summary>
[Flags]
internal enum ShapeMask : uint
{
    None = 0,
    Isol = 1,
    Init = 2,
    Medi = 4,
    Fina = 8,
    Rphf = 16,
    Half = 32,
    Blwf = 64,
    Pstf = 128,
    Rkrf = 256,
    Global = 0x80000000,
}

/// <summary>Indic bookkeeping flags carried through substitutions.</summary>
[Flags]
internal enum GlyphFlags
{
    None = 0,
    Base = 1,
    Reph = 2,
    PreBaseMatra = 4,
    Halant = 8,
    Modifier = 16,
}

/// <summary>A glyph being shaped, with its source text and positioning (font units).</summary>
internal sealed class GlyphInfo
{
    public ushort Glyph { get; set; }

    /// <summary>Gets or sets the index of the first source character.</summary>
    public int Cluster { get; set; }

    /// <summary>Gets or sets the source characters this glyph represents (empty for the extra glyphs of a decomposition).</summary>
    public string Text { get; set; } = string.Empty;

    public ShapeMask Mask { get; set; } = ShapeMask.Global;

    public GlyphFlags Flags { get; set; }

    public int Syllable { get; set; } = -1;

    /// <summary>Gets or sets the GDEF class (1 base, 2 ligature, 3 mark, 4 component).</summary>
    public int Class { get; set; }

    public int MarkAttachClass { get; set; }

    public int XAdvance { get; set; }

    public int XOffset { get; set; }

    public int YOffset { get; set; }

    /// <summary>Gets or sets the index of the glyph a mark is attached to (offsets are then relative to its origin).</summary>
    public int AttachTo { get; set; } = -1;

    public GlyphInfo Clone() => (GlyphInfo)MemberwiseClone();
}

/// <summary>A glyph placed relative to the start of its run (font units, y up).</summary>
/// <param name="Glyph">The glyph id.</param>
/// <param name="Text">Source characters (for ToUnicode); empty for extra glyphs.</param>
/// <param name="X">Horizontal position of the glyph origin.</param>
/// <param name="Y">Vertical offset of the glyph origin.</param>
internal readonly record struct PositionedGlyph(ushort Glyph, string Text, int X, int Y);

/// <summary>The result of shaping a run.</summary>
/// <param name="Glyphs">Glyphs in visual order.</param>
/// <param name="Advance">Total advance width in font units.</param>
internal sealed record ShapedRun(List<PositionedGlyph> Glyphs, int Advance);

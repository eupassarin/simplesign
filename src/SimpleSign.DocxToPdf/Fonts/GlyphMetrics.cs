namespace SimpleSign.DocxToPdf.Fonts;

/// <summary>Metrics for a single glyph.</summary>
/// <param name="GlyphId">The glyph ID in the font.</param>
/// <param name="AdvanceWidth">The advance width in font design units.</param>
/// <param name="LeftSideBearing">The left side bearing in font design units.</param>
internal readonly record struct GlyphMetrics(ushort GlyphId, ushort AdvanceWidth, short LeftSideBearing);

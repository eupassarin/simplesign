namespace SimpleSign.DocxToPdf.Model;

/// <summary>An embedded image reference within a run.</summary>
public sealed class DocImage
{
    /// <summary>Gets or sets the relationship ID referencing the image data.</summary>
    public string RelationshipId { get; set; } = string.Empty;

    /// <summary>Gets or sets the image width in EMU.</summary>
    public long WidthEmu { get; set; }

    /// <summary>Gets or sets the image height in EMU.</summary>
    public long HeightEmu { get; set; }

    /// <summary>Gets or sets a value indicating whether this is an inline image.</summary>
    public bool IsInline { get; set; } = true;

    /// <summary>Gets the image width in points.</summary>
    public float WidthPt => WidthEmu / 914400f * 72f;

    /// <summary>Gets the image height in points.</summary>
    public float HeightPt => HeightEmu / 914400f * 72f;
}

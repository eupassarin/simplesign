namespace SimpleSign.DocxToPdf.Model;

/// <summary>Root document model parsed from OOXML.</summary>
public sealed class DocumentModel
{
    /// <summary>Gets the sections of the document.</summary>
    public List<DocSection> Sections { get; init; } = [];

    /// <summary>Gets the style map.</summary>
    public StyleMap Styles { get; init; } = new();

    /// <summary>Gets the numbering definitions.</summary>
    public NumberingDefinitions Numbering { get; init; } = new();

    /// <summary>Gets the theme data.</summary>
    public ThemeData Theme { get; init; } = new();

    /// <summary>Gets the images keyed by relationship ID.</summary>
    public Dictionary<string, byte[]> Images { get; init; } = new();
}

namespace SimpleSign.DocxToPdf.Model;

/// <summary>Maps style IDs to their property definitions.</summary>
public sealed class StyleMap
{
    /// <summary>Gets the paragraph styles keyed by style ID.</summary>
    public Dictionary<string, DocParagraphStyle> ParagraphStyles { get; init; } = new();

    /// <summary>Gets the character styles keyed by style ID.</summary>
    public Dictionary<string, DocCharacterStyle> CharacterStyles { get; init; } = new();

    /// <summary>Gets or sets the default font name.</summary>
    public string DefaultFontName { get; set; } = "Calibri";

    /// <summary>Gets or sets the default font size in half-points.</summary>
    public int DefaultFontSizeHalfPoints { get; set; } = 22;
}

/// <summary>Style properties for a paragraph.</summary>
public sealed class DocParagraphStyle
{
    /// <summary>Gets or sets the style ID.</summary>
    public string Id { get; set; } = string.Empty;

    /// <summary>Gets or sets the style name.</summary>
    public string Name { get; set; } = string.Empty;

    /// <summary>Gets or sets the base style ID for inheritance.</summary>
    public string? BasedOn { get; set; }

    /// <summary>Gets or sets the paragraph alignment.</summary>
    public ParagraphAlignment? Alignment { get; set; }

    /// <summary>Gets or sets the font name.</summary>
    public string? FontName { get; set; }

    /// <summary>Gets or sets the font size in half-points.</summary>
    public int? SizeHalfPoints { get; set; }

    /// <summary>Gets or sets a value indicating whether bold is set.</summary>
    public bool? Bold { get; set; }

    /// <summary>Gets or sets a value indicating whether italic is set.</summary>
    public bool? Italic { get; set; }

    /// <summary>Gets or sets the spacing.</summary>
    public DocSpacing? Spacing { get; set; }
}

/// <summary>Style properties for character formatting.</summary>
public sealed class DocCharacterStyle
{
    /// <summary>Gets or sets the style ID.</summary>
    public string Id { get; set; } = string.Empty;

    /// <summary>Gets or sets the style name.</summary>
    public string Name { get; set; } = string.Empty;

    /// <summary>Gets or sets the base style ID for inheritance.</summary>
    public string? BasedOn { get; set; }

    /// <summary>Gets or sets the font name.</summary>
    public string? FontName { get; set; }

    /// <summary>Gets or sets the font size in half-points.</summary>
    public int? SizeHalfPoints { get; set; }

    /// <summary>Gets or sets a value indicating whether bold is set.</summary>
    public bool? Bold { get; set; }

    /// <summary>Gets or sets a value indicating whether italic is set.</summary>
    public bool? Italic { get; set; }

    /// <summary>Gets or sets the text color.</summary>
    public string? Color { get; set; }
}

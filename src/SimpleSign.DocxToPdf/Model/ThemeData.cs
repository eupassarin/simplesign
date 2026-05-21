namespace SimpleSign.DocxToPdf.Model;

/// <summary>Theme data extracted from the document.</summary>
public sealed class ThemeData
{
    /// <summary>Gets or sets the major (heading) font family.</summary>
    public string MajorFont { get; set; } = "Calibri Light";

    /// <summary>Gets or sets the minor (body) font family.</summary>
    public string MinorFont { get; set; } = "Calibri";

    /// <summary>Gets the color scheme mapping theme color names to hex RGB values.</summary>
    public Dictionary<string, string> ColorScheme { get; init; } = new();
}

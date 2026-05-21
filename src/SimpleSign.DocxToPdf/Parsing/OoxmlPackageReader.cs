using DocumentFormat.OpenXml.Packaging;
using SimpleSign.DocxToPdf.Model;

namespace SimpleSign.DocxToPdf.Parsing;

/// <summary>Reads a DOCX package and extracts all parts needed for conversion.</summary>
internal sealed class OoxmlPackageReader : IDisposable
{
    private readonly WordprocessingDocument _document;

    /// <summary>Initializes a new instance of the <see cref="OoxmlPackageReader"/> class from a stream.</summary>
    /// <param name="stream">The DOCX stream to read.</param>
    public OoxmlPackageReader(Stream stream)
    {
        ArgumentNullException.ThrowIfNull(stream);
        _document = WordprocessingDocument.Open(stream, false);
    }

    /// <summary>Parses the complete document into a <see cref="DocumentModel"/>.</summary>
    /// <returns>The parsed document model.</returns>
    public DocumentModel Parse()
    {
        var mainPart = _document.MainDocumentPart;
        if (mainPart is null)
        {
            return new DocumentModel();
        }

        ThemeData theme = ThemeParser.Parse(mainPart.ThemePart);
        StyleMap styles = StylesParser.Parse(mainPart.StyleDefinitionsPart);
        NumberingDefinitions numbering = NumberingParser.Parse(mainPart.NumberingDefinitionsPart);
        Dictionary<string, byte[]> images = ExtractImages(mainPart);
        List<DocSection> sections = DocumentParser.Parse(mainPart);

        return new DocumentModel
        {
            Sections = sections,
            Styles = styles,
            Numbering = numbering,
            Theme = theme,
            Images = images
        };
    }

    /// <inheritdoc/>
    public void Dispose() => _document.Dispose();

    private static Dictionary<string, byte[]> ExtractImages(MainDocumentPart mainPart)
    {
        var images = new Dictionary<string, byte[]>();

        foreach (ImagePart imagePart in mainPart.ImageParts)
        {
            string? relationshipId = mainPart.GetIdOfPart(imagePart);
            if (relationshipId is null)
            {
                continue;
            }

            using Stream stream = imagePart.GetStream();
            using var ms = new MemoryStream();
            stream.CopyTo(ms);
            images[relationshipId] = ms.ToArray();
        }

        return images;
    }
}

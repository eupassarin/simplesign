using SimpleSign.DocxToPdf.Fonts;
using SimpleSign.DocxToPdf.Layout;
using SimpleSign.DocxToPdf.Model;
using SimpleSign.DocxToPdf.Parsing;
using SimpleSign.DocxToPdf.Rendering;

namespace SimpleSign.DocxToPdf;

/// <summary>Fluent builder for configuring and executing DOCX-to-PDF conversion.</summary>
public sealed class DocxToPdfBuilder
{
    private readonly byte[] _docxData;
    private string[] _fontFallback = ["Arial", "Liberation Sans", "DejaVu Sans", "Helvetica"];
    private bool _embedFonts;
    private float _overrideWidthMm;
    private float _overrideHeightMm;

    /// <summary>Initializes a new instance of the <see cref="DocxToPdfBuilder"/> class.</summary>
    /// <param name="docxData">The DOCX file data.</param>
    internal DocxToPdfBuilder(byte[] docxData)
    {
        _docxData = docxData;
    }

    /// <summary>Sets the font fallback chain.</summary>
    /// <param name="fontNames">The font names to try in order.</param>
    /// <returns>This builder for chaining.</returns>
    public DocxToPdfBuilder WithFontFallback(params string[] fontNames)
    {
        ArgumentNullException.ThrowIfNull(fontNames);
        _fontFallback = fontNames;
        return this;
    }

    /// <summary>Sets whether to embed fonts in the PDF.</summary>
    /// <param name="embed">True to embed fonts.</param>
    /// <returns>This builder for chaining.</returns>
    public DocxToPdfBuilder WithEmbedFonts(bool embed = true)
    {
        _embedFonts = embed;
        return this;
    }

    /// <summary>Overrides the page size for the output PDF.</summary>
    /// <param name="widthMm">The page width in millimeters.</param>
    /// <param name="heightMm">The page height in millimeters.</param>
    /// <returns>This builder for chaining.</returns>
    public DocxToPdfBuilder WithPageSize(float widthMm, float heightMm)
    {
        _overrideWidthMm = widthMm;
        _overrideHeightMm = heightMm;
        return this;
    }

    /// <summary>Converts the DOCX to PDF and returns the result as a byte array.</summary>
    /// <returns>The PDF file bytes.</returns>
    public byte[] Convert()
    {
        using var ms = new MemoryStream();
        ConvertTo(ms);
        return ms.ToArray();
    }

    /// <summary>Converts the DOCX to PDF asynchronously.</summary>
    /// <param name="ct">A cancellation token.</param>
    /// <returns>The PDF file bytes.</returns>
    public Task<byte[]> ConvertAsync(CancellationToken ct = default) =>
        Task.Run(Convert, ct);

    /// <summary>Converts the DOCX to PDF and writes to the specified stream.</summary>
    /// <param name="output">The output stream to write the PDF to.</param>
    public void ConvertTo(Stream output)
    {
        ArgumentNullException.ThrowIfNull(output);

        // Parse
        DocumentModel model;
        using (var docxStream = new MemoryStream(_docxData))
        using (var reader = new OoxmlPackageReader(docxStream))
        {
            model = reader.Parse();
        }

        // Apply page size override
        if (_overrideWidthMm > 0 && _overrideHeightMm > 0)
        {
            float widthPt = _overrideWidthMm * 72f / 25.4f;
            float heightPt = _overrideHeightMm * 72f / 25.4f;
            foreach (DocSection section in model.Sections)
            {
                section.PageWidthPt = widthPt;
                section.PageHeightPt = heightPt;
            }
        }

        // Layout
        var fontResolver = new FontResolver(_embedFonts ? _fontFallback : _fontFallback);
        var layoutEngine = new DocumentLayoutEngine(fontResolver);
        List<LayoutPage> pages = layoutEngine.Layout(model);

        // Render
        var writer = new PdfDocumentWriter(pages, model.Images);
        writer.WriteTo(output);
    }

    /// <summary>Converts the DOCX to PDF asynchronously and writes to the specified stream.</summary>
    /// <param name="output">The output stream.</param>
    /// <param name="ct">A cancellation token.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    public Task ConvertToAsync(Stream output, CancellationToken ct = default) =>
        Task.Run(() => ConvertTo(output), ct);
}

// Licensed to SimpleSign under the MIT License.

using SimpleSign.HtmlToPdf.Fonts;
using SimpleSign.HtmlToPdf.Layout;
using SimpleSign.HtmlToPdf.Parsing;

namespace SimpleSign.HtmlToPdf;

/// <summary>
/// Main entry point for HTML-to-PDF conversion.
/// Provides a fluent API for converting HTML strings or files into PDF documents.
/// </summary>
/// <example>
/// <code>
/// // Simple conversion
/// byte[] pdf = HtmlToPdfConverter
///     .Html("&lt;h1&gt;Hello&lt;/h1&gt;&lt;p&gt;World&lt;/p&gt;")
///     .Convert();
///
/// // With options
/// byte[] pdf = HtmlToPdfConverter
///     .Html(htmlContent)
///     .WithPageSize(PageSize.A4)
///     .WithMargins(top: 30, right: 25, bottom: 30, left: 25)
///     .WithStylesheet("body { font-size: 14px; }")
///     .Convert();
///
/// // From file (relative images/stylesheets resolve against the file's folder)
/// byte[] pdf = await (await HtmlToPdfConverter.FileAsync("report.html"))
///     .WithBaseDirectory("templates")
///     .WithPageSize(PageSize.Legal)
///     .ConvertAsync();
/// </code>
/// </example>
public static class HtmlToPdfConverter
{
    /// <summary>Creates a conversion builder from an HTML string.</summary>
    /// <param name="html">The HTML content to convert.</param>
    /// <returns>A builder for configuring the conversion.</returns>
    public static HtmlToPdfBuilder Html(string html)
    {
        ArgumentNullException.ThrowIfNull(html);
        return new HtmlToPdfBuilder(html);
    }

    /// <summary>Creates a conversion builder from HTML bytes (UTF-8).</summary>
    /// <param name="htmlBytes">UTF-8 encoded HTML content.</param>
    /// <returns>A builder for configuring the conversion.</returns>
    public static HtmlToPdfBuilder Html(byte[] htmlBytes)
    {
        ArgumentNullException.ThrowIfNull(htmlBytes);
        return new HtmlToPdfBuilder(System.Text.Encoding.UTF8.GetString(htmlBytes));
    }

    /// <summary>Creates a conversion builder from an HTML file.</summary>
    /// <param name="filePath">Path to the HTML file.</param>
    /// <returns>A builder for configuring the conversion.</returns>
    public static HtmlToPdfBuilder File(string filePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(filePath);
        if (!System.IO.File.Exists(filePath))
        {
            throw new FileNotFoundException("HTML file not found.", filePath);
        }

        string html = System.IO.File.ReadAllText(filePath);
        return new HtmlToPdfBuilder(html);
    }

    /// <summary>Creates a conversion builder from an HTML file asynchronously.</summary>
    /// <param name="filePath">Path to the HTML file.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A builder for configuring the conversion.</returns>
    public static async Task<HtmlToPdfBuilder> FileAsync(
        string filePath,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(filePath);
        if (!System.IO.File.Exists(filePath))
        {
            throw new FileNotFoundException("HTML file not found.", filePath);
        }

        string html = await System.IO.File.ReadAllTextAsync(filePath, cancellationToken).ConfigureAwait(false);
        return new HtmlToPdfBuilder(html);
    }
}

/// <summary>
/// Builder for configuring HTML-to-PDF conversion options.
/// All methods return a new instance (immutable builder pattern).
/// </summary>
public sealed class HtmlToPdfBuilder
{
    private readonly ConversionOptions _options;

    internal HtmlToPdfBuilder(string html)
    {
        _options = new ConversionOptions { Html = html };
    }

    private HtmlToPdfBuilder(ConversionOptions options)
    {
        _options = options;
    }

    private static HtmlToPdfBuilder With(ConversionOptions options) => new(options);

    /// <summary>Sets the page size for the output PDF (overrides any CSS <c>@page size</c>).</summary>
    /// <param name="pageSize">The paper size.</param>
    /// <returns>A new builder.</returns>
    public HtmlToPdfBuilder WithPageSize(PageSize pageSize) => With(_options with { PageSize = pageSize });

    /// <summary>Sets the page orientation for the output PDF (overrides any CSS <c>@page size</c>).</summary>
    /// <param name="orientation">The page orientation.</param>
    /// <returns>A new builder.</returns>
    public HtmlToPdfBuilder WithPageOrientation(PageOrientation orientation) => With(_options with { Orientation = orientation });

    /// <summary>Sets uniform margins (in points, 1pt = 1/72 inch). Overrides CSS <c>@page margin</c>.</summary>
    /// <param name="all">The margin for all sides.</param>
    /// <returns>A new builder.</returns>
    public HtmlToPdfBuilder WithMargins(float all) => WithMargins(all, all, all, all);

    /// <summary>Sets margins individually (in points, 1pt = 1/72 inch). Overrides CSS <c>@page margin</c>.</summary>
    /// <param name="top">Top margin.</param>
    /// <param name="right">Right margin.</param>
    /// <param name="bottom">Bottom margin.</param>
    /// <param name="left">Left margin.</param>
    /// <returns>A new builder.</returns>
    public HtmlToPdfBuilder WithMargins(float top, float right, float bottom, float left) =>
        With(_options with { Margins = new Thickness(top, right, bottom, left) });

    /// <summary>Adds a CSS stylesheet to apply during conversion (after the document's own styles).</summary>
    /// <param name="css">The stylesheet text.</param>
    /// <returns>A new builder.</returns>
    public HtmlToPdfBuilder WithStylesheet(string css)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(css);
        string combined = _options.Stylesheet is not null ? _options.Stylesheet + "\n" + css : css;
        return With(_options with { Stylesheet = combined });
    }

    /// <summary>Sets the PDF document title metadata (defaults to the HTML <c>&lt;title&gt;</c>).</summary>
    /// <param name="title">The title.</param>
    /// <returns>A new builder.</returns>
    public HtmlToPdfBuilder WithTitle(string title)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(title);
        return With(_options with { Title = title });
    }

    /// <summary>Sets the PDF document author metadata.</summary>
    /// <param name="author">The author.</param>
    /// <returns>A new builder.</returns>
    public HtmlToPdfBuilder WithAuthor(string author)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(author);
        return With(_options with { Author = author });
    }

    /// <summary>Sets a header template. Supports {page}, {pages}, {title}, {date} placeholders.</summary>
    /// <param name="template">The header text template.</param>
    /// <returns>A new builder.</returns>
    public HtmlToPdfBuilder WithHeader(string template)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(template);
        return With(_options with { HeaderTemplate = template });
    }

    /// <summary>Sets a footer template. Supports {page}, {pages}, {title}, {date} placeholders.</summary>
    /// <param name="template">The footer text template.</param>
    /// <returns>A new builder.</returns>
    public HtmlToPdfBuilder WithFooter(string template)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(template);
        return With(_options with { FooterTemplate = template });
    }

    /// <summary>Registers a TrueType font for CSS <c>font-family</c> use and embeds it in the output PDF.</summary>
    /// <param name="family">The family alias used by CSS, e.g. <c>Brand Sans</c>.</param>
    /// <param name="fontData">The complete TrueType font file bytes (TTF, cmap format 4 or 12).</param>
    /// <returns>A new builder with the font registered.</returns>
    public HtmlToPdfBuilder WithFont(string family, byte[] fontData) => WithFont(family, fontData, FontVariant.Regular);

    /// <summary>
    /// Registers one face (regular, bold, italic, or bold italic) of a font family. When a family lacks the
    /// face a style asks for, the closest registered face is used and bold/italic are synthesized.
    /// </summary>
    /// <param name="family">The family alias used by CSS.</param>
    /// <param name="fontData">The complete TrueType or OpenType (CFF) font file bytes.</param>
    /// <param name="variant">Which face of the family this file provides.</param>
    /// <returns>A new builder with the font registered.</returns>
    public HtmlToPdfBuilder WithFont(string family, byte[] fontData, FontVariant variant)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(family);
        ArgumentNullException.ThrowIfNull(fontData);
        if (fontData.Length == 0)
        {
            throw new ArgumentException("Font data must not be empty.", nameof(fontData));
        }

        // Validate eagerly so callers get the error at registration time.
        _ = new EmbeddedFont(family.Trim(), fontData, variant);

        List<FontRegistration> fonts = [.. _options.Fonts.Where(f =>
            !(string.Equals(f.Family, family.Trim(), StringComparison.OrdinalIgnoreCase) && f.Variant == variant))];
        fonts.Add(new FontRegistration(family.Trim(), variant, [.. fontData]));
        return With(_options with { Fonts = fonts });
    }

    /// <summary>Registers a TrueType font from a file path for CSS <c>font-family</c> use.</summary>
    /// <param name="family">The family alias used by CSS.</param>
    /// <param name="filePath">Path to a complete TrueType font file.</param>
    /// <returns>A new builder with the font registered.</returns>
    public HtmlToPdfBuilder WithFontFile(string family, string filePath) => WithFontFile(family, filePath, FontVariant.Regular);

    /// <summary>Registers one face of a font family from a file path.</summary>
    /// <param name="family">The family alias used by CSS.</param>
    /// <param name="filePath">Path to a TrueType or OpenType font file.</param>
    /// <param name="variant">Which face of the family this file provides.</param>
    /// <returns>A new builder with the font registered.</returns>
    public HtmlToPdfBuilder WithFontFile(string family, string filePath, FontVariant variant)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(filePath);
        return WithFont(family, File.ReadAllBytes(filePath), variant);
    }

    /// <summary>
    /// Allows relative image, stylesheet (<c>&lt;link rel="stylesheet"&gt;</c>) and font references to be loaded
    /// from this directory. Files outside the directory are never read.
    /// </summary>
    /// <param name="directory">The base directory.</param>
    /// <returns>A new builder.</returns>
    public HtmlToPdfBuilder WithBaseDirectory(string directory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(directory);
        if (!Directory.Exists(directory))
        {
            throw new DirectoryNotFoundException($"Base directory not found: {directory}");
        }

        return With(_options with { BaseDirectory = Path.GetFullPath(directory) });
    }

    /// <summary>
    /// Supplies a callback that resolves resource references (for example <c>https://</c> images or custom
    /// schemes). Return null to fall back to the base directory. The library never accesses the network itself.
    /// </summary>
    /// <param name="loader">Callback that maps a reference (as written in HTML/CSS) to its bytes.</param>
    /// <returns>A new builder.</returns>
    public HtmlToPdfBuilder WithResourceLoader(Func<string, byte[]?> loader)
    {
        ArgumentNullException.ThrowIfNull(loader);
        return With(_options with { ResourceLoader = loader });
    }

    /// <summary>
    /// Produces a PDF/A-2b archival document: embeds an sRGB output intent and XMP metadata.
    /// All text must use registered (embedded) fonts; conversion fails if a standard PDF font would be needed.
    /// </summary>
    /// <returns>A new builder.</returns>
    public HtmlToPdfBuilder WithPdfA() => With(_options with { PdfA = true });

    /// <summary>Sets the document language (e.g. <c>pt-BR</c>); defaults to the HTML <c>lang</c> attribute.</summary>
    /// <param name="language">A BCP 47 language tag.</param>
    /// <returns>A new builder.</returns>
    public HtmlToPdfBuilder WithLanguage(string language)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(language);
        return With(_options with { Language = language });
    }

    /// <summary>Converts the HTML to PDF and returns the PDF bytes.</summary>
    /// <returns>The PDF bytes.</returns>
    public byte[] Convert() => ConversionPipeline.Run(_options);

    /// <summary>Converts the HTML to PDF and writes to the output stream.</summary>
    /// <param name="outputStream">The destination stream.</param>
    public void Convert(Stream outputStream)
    {
        ArgumentNullException.ThrowIfNull(outputStream);
        byte[] pdf = Convert();
        outputStream.Write(pdf, 0, pdf.Length);
    }

    /// <summary>Converts the HTML to PDF asynchronously and returns the PDF bytes.</summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The PDF bytes.</returns>
    public Task<byte[]> ConvertAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.Run(Convert, cancellationToken);
    }

    /// <summary>Converts the HTML to PDF and writes to the output stream asynchronously.</summary>
    /// <param name="outputStream">The destination stream.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A task that completes when the PDF has been written.</returns>
    public async Task ConvertAsync(Stream outputStream, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(outputStream);
        byte[] pdf = await ConvertAsync(cancellationToken).ConfigureAwait(false);
        await outputStream.WriteAsync(pdf, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Converts the HTML to PDF and saves to a file.</summary>
    /// <param name="filePath">The destination file.</param>
    public void SaveTo(string filePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(filePath);
        byte[] pdf = Convert();
        File.WriteAllBytes(filePath, pdf);
    }

    /// <summary>Converts the HTML to PDF and saves to a file asynchronously.</summary>
    /// <param name="filePath">The destination file.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A task that completes when the file has been written.</returns>
    public async Task SaveToAsync(string filePath, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(filePath);
        byte[] pdf = await ConvertAsync(cancellationToken).ConfigureAwait(false);
        await File.WriteAllBytesAsync(filePath, pdf, cancellationToken).ConfigureAwait(false);
    }
}

/// <summary>Standard page sizes for PDF output.</summary>
public enum PageSize
{
    /// <summary>A4 (210 × 297 mm)</summary>
    A4,

    /// <summary>US Letter (8.5 × 11 in)</summary>
    Letter,

    /// <summary>US Legal (8.5 × 14 in)</summary>
    Legal,

    /// <summary>A3 (297 × 420 mm)</summary>
    A3,
}

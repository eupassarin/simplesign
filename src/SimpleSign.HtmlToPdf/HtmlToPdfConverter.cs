// Licensed to SimpleSign under the MIT License.

using SimpleSign.HtmlToPdf.Layout;
using SimpleSign.HtmlToPdf.Parsing;
using SimpleSign.HtmlToPdf.Rendering;

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
/// // From file
/// byte[] pdf = await HtmlToPdfConverter
///     .FileAsync("report.html")
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
    private readonly string _html;
    private readonly PageSize _pageSize;
    private readonly PageOrientation _orientation;
    private readonly float? _marginTop;
    private readonly float? _marginRight;
    private readonly float? _marginBottom;
    private readonly float? _marginLeft;
    private readonly string? _stylesheet;
    private readonly string? _title;
    private readonly string? _author;
    private readonly string? _headerTemplate;
    private readonly string? _footerTemplate;

    internal HtmlToPdfBuilder(string html)
    {
        _html = html;
        _pageSize = PageSize.A4;
        _orientation = PageOrientation.Portrait;
    }

    private HtmlToPdfBuilder(
        string html,
        PageSize pageSize,
        PageOrientation orientation,
        float? marginTop,
        float? marginRight,
        float? marginBottom,
        float? marginLeft,
        string? stylesheet,
        string? title,
        string? author,
        string? headerTemplate,
        string? footerTemplate)
    {
        _html = html;
        _pageSize = pageSize;
        _orientation = orientation;
        _marginTop = marginTop;
        _marginRight = marginRight;
        _marginBottom = marginBottom;
        _marginLeft = marginLeft;
        _stylesheet = stylesheet;
        _title = title;
        _author = author;
        _headerTemplate = headerTemplate;
        _footerTemplate = footerTemplate;
    }

    private HtmlToPdfBuilder With(
        PageSize? pageSize = null,
        PageOrientation? orientation = null,
        float? marginTop = null,
        float? marginRight = null,
        float? marginBottom = null,
        float? marginLeft = null,
        string? stylesheet = null,
        string? title = null,
        string? author = null,
        string? headerTemplate = null,
        string? footerTemplate = null)
        => new(
            _html,
            pageSize ?? _pageSize,
            orientation ?? _orientation,
            marginTop ?? _marginTop,
            marginRight ?? _marginRight,
            marginBottom ?? _marginBottom,
            marginLeft ?? _marginLeft,
            stylesheet ?? _stylesheet,
            title ?? _title,
            author ?? _author,
            headerTemplate ?? _headerTemplate,
            footerTemplate ?? _footerTemplate);

    /// <summary>Sets the page size for the output PDF.</summary>
    public HtmlToPdfBuilder WithPageSize(PageSize pageSize) => With(pageSize: pageSize);

    /// <summary>Sets the page orientation for the output PDF.</summary>
    public HtmlToPdfBuilder WithPageOrientation(PageOrientation orientation) => With(orientation: orientation);

    /// <summary>Sets uniform margins (in points, 1pt = 1/72 inch).</summary>
    public HtmlToPdfBuilder WithMargins(float all) =>
        With(marginTop: all, marginRight: all, marginBottom: all, marginLeft: all);

    /// <summary>Sets margins individually (in points, 1pt = 1/72 inch).</summary>
    public HtmlToPdfBuilder WithMargins(float top, float right, float bottom, float left) =>
        With(marginTop: top, marginRight: right, marginBottom: bottom, marginLeft: left);

    /// <summary>Adds a CSS stylesheet to apply during conversion.</summary>
    public HtmlToPdfBuilder WithStylesheet(string css)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(css);
        string combined = _stylesheet is not null ? _stylesheet + "\n" + css : css;
        return With(stylesheet: combined);
    }

    /// <summary>Sets the PDF document title metadata.</summary>
    public HtmlToPdfBuilder WithTitle(string title)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(title);
        return With(title: title);
    }

    /// <summary>Sets the PDF document author metadata.</summary>
    public HtmlToPdfBuilder WithAuthor(string author)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(author);
        return With(author: author);
    }

    /// <summary>Sets a header template. Supports {page}, {pages}, {title}, {date} placeholders.</summary>
    public HtmlToPdfBuilder WithHeader(string template)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(template);
        return With(headerTemplate: template);
    }

    /// <summary>Sets a footer template. Supports {page}, {pages}, {title}, {date} placeholders.</summary>
    public HtmlToPdfBuilder WithFooter(string template)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(template);
        return With(footerTemplate: template);
    }

    /// <summary>Converts the HTML to PDF and returns the PDF bytes.</summary>
    public byte[] Convert()
    {
        // 1. Parse HTML → DOM
        HtmlNode dom = HtmlTokenizer.Parse(_html);

        // 2. Apply CSS + stylesheet
        List<CssRule> rules = [];
        if (_stylesheet is not null)
        {
            rules.AddRange(CssParser.ParseStylesheet(_stylesheet));
        }

        StyleResolver.Resolve(dom, rules);

        // 3. Layout → pages
        PageSettings pageSettings = BuildPageSettings();
        var engine = new LayoutEngine(pageSettings);
        LayoutResult layout = engine.Layout(dom);

        // Attach metadata if title, author, header, or footer was set
        if (_title is not null || _author is not null || _headerTemplate is not null || _footerTemplate is not null)
        {
            var layoutWithMeta = new LayoutResult
            {
                Settings = layout.Settings,
                Metadata = new PdfMetadata(_title, _author, _headerTemplate, _footerTemplate),
            };
            foreach (PageBox p in layout.Pages)
            {
                layoutWithMeta.Pages.Add(p);
            }

            foreach (BookmarkEntry bm in layout.Bookmarks)
            {
                layoutWithMeta.Bookmarks.Add(bm);
            }

            layout = layoutWithMeta;
        }

        // 4. Render → PDF bytes
        return PdfDocumentRenderer.Render(layout);
    }

    /// <summary>Converts the HTML to PDF and writes to the output stream.</summary>
    public void Convert(Stream outputStream)
    {
        ArgumentNullException.ThrowIfNull(outputStream);
        byte[] pdf = Convert();
        outputStream.Write(pdf, 0, pdf.Length);
    }

    /// <summary>Converts the HTML to PDF asynchronously and returns the PDF bytes.</summary>
    public Task<byte[]> ConvertAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.Run(Convert, cancellationToken);
    }

    /// <summary>Converts the HTML to PDF and writes to the output stream asynchronously.</summary>
    public async Task ConvertAsync(Stream outputStream, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(outputStream);
        byte[] pdf = await ConvertAsync(cancellationToken).ConfigureAwait(false);
        await outputStream.WriteAsync(pdf, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Converts the HTML to PDF and saves to a file.</summary>
    public void SaveTo(string filePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(filePath);
        byte[] pdf = Convert();
        System.IO.File.WriteAllBytes(filePath, pdf);
    }

    /// <summary>Converts the HTML to PDF and saves to a file asynchronously.</summary>
    public async Task SaveToAsync(string filePath, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(filePath);
        byte[] pdf = await ConvertAsync(cancellationToken).ConfigureAwait(false);
        await System.IO.File.WriteAllBytesAsync(filePath, pdf, cancellationToken).ConfigureAwait(false);
    }

    private PageSettings BuildPageSettings()
    {
        PaperSize paperSize = _pageSize switch
        {
            PageSize.Letter => PaperSize.Letter,
            PageSize.Legal => PaperSize.Legal,
            PageSize.A3 => PaperSize.A3,
            _ => PaperSize.A4,
        };

        PageSettings settings = PageSettings.FromPaperSize(paperSize, _orientation);

        if (_marginTop.HasValue || _marginRight.HasValue || _marginBottom.HasValue || _marginLeft.HasValue)
        {
            settings = new PageSettings
            {
                PageWidth = settings.PageWidth,
                PageHeight = settings.PageHeight,
                Margins = new Thickness(
                    _marginTop ?? settings.Margins.Top,
                    _marginRight ?? settings.Margins.Right,
                    _marginBottom ?? settings.Margins.Bottom,
                    _marginLeft ?? settings.Margins.Left),
            };
        }

        return settings;
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

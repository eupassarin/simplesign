// Licensed to SimpleSign under the MIT License.

using SimpleSign.HtmlToPdf.Parsing;

namespace SimpleSign.HtmlToPdf.Layout;

/// <summary>Standard paper sizes.</summary>
public enum PaperSize
{
    /// <summary>A4 (210 x 297 mm).</summary>
    A4,

    /// <summary>US Letter (8.5 x 11 in).</summary>
    Letter,

    /// <summary>US Legal (8.5 x 14 in).</summary>
    Legal,

    /// <summary>A3 (297 x 420 mm).</summary>
    A3,
}

/// <summary>Page orientation.</summary>
public enum PageOrientation
{
    /// <summary>Portrait (taller than wide).</summary>
    Portrait,

    /// <summary>Landscape (wider than tall).</summary>
    Landscape,
}

/// <summary>PDF document metadata.</summary>
/// <param name="Title">The document title.</param>
/// <param name="Author">The document author.</param>
/// <param name="HeaderTemplate">Header template with placeholders like {page}, {pages}, {title}, {date}.</param>
/// <param name="FooterTemplate">Footer template with placeholders like {page}, {pages}, {title}, {date}.</param>
public sealed record PdfMetadata(string? Title, string? Author, string? HeaderTemplate = null, string? FooterTemplate = null);

/// <summary>Page dimensions and margins for PDF layout.</summary>
public sealed class PageSettings
{
    /// <summary>Gets the page width in points.</summary>
    public float PageWidth { get; init; } = 595.28f;

    /// <summary>Gets the page height in points.</summary>
    public float PageHeight { get; init; } = 841.89f;

    /// <summary>Gets the page margins in points.</summary>
    public Thickness Margins { get; init; } = new(72, 72, 72, 72);

    /// <summary>Gets the available content width.</summary>
    public float ContentWidth => PageWidth - Margins.Left - Margins.Right;

    /// <summary>Gets the available content height.</summary>
    public float ContentHeight => PageHeight - Margins.Top - Margins.Bottom;

    /// <summary>Creates page settings for a standard paper size with 1-inch margins.</summary>
    /// <param name="size">The paper size.</param>
    /// <param name="orientation">The page orientation.</param>
    /// <returns>Page settings for the specified size.</returns>
    public static PageSettings FromPaperSize(PaperSize size, PageOrientation orientation = PageOrientation.Portrait)
    {
        PageSettings settings = size switch
        {
            PaperSize.Letter => new PageSettings { PageWidth = 612, PageHeight = 792 },
            PaperSize.Legal => new PageSettings { PageWidth = 612, PageHeight = 1008 },
            PaperSize.A3 => new PageSettings { PageWidth = 841.89f, PageHeight = 1190.55f },
            _ => new PageSettings(),
        };

        if (orientation == PageOrientation.Landscape)
        {
            settings = new PageSettings
            {
                PageWidth = settings.PageHeight,
                PageHeight = settings.PageWidth,
                Margins = settings.Margins,
            };
        }

        return settings;
    }
}

/// <summary>A single laid-out page containing positioned boxes.</summary>
public sealed class PageBox
{
    /// <summary>Gets the page number (1-based).</summary>
    public int PageNumber { get; init; }

    /// <summary>Gets the layout boxes on this page.</summary>
    public List<LayoutBox> Boxes { get; } = [];

    /// <summary>Gets the page settings.</summary>
    public PageSettings Settings { get; init; } = new();
}

/// <summary>Represents a heading bookmark for PDF outlines.</summary>
/// <param name="Title">The heading text.</param>
/// <param name="Level">The heading level (1-6).</param>
/// <param name="PageIndex">0-based page index.</param>
/// <param name="Y">Y position on the page in layout coordinates (from top of content area).</param>
public sealed record BookmarkEntry(string Title, int Level, int PageIndex, float Y);

/// <summary>Complete layout result: pages ready for PDF rendering.</summary>
public sealed class LayoutResult
{
    /// <summary>Gets the pages in order.</summary>
    public List<PageBox> Pages { get; } = [];

    /// <summary>Gets the page settings used.</summary>
    public PageSettings Settings { get; init; } = new();

    /// <summary>Gets or sets the PDF metadata.</summary>
    public PdfMetadata? Metadata { get; init; }

    /// <summary>Gets the bookmarks collected from headings.</summary>
    public List<BookmarkEntry> Bookmarks { get; } = [];
}

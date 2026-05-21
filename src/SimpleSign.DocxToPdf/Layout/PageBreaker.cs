namespace SimpleSign.DocxToPdf.Layout;

/// <summary>Handles page break decisions during layout.</summary>
internal sealed class PageBreaker
{
    /// <summary>Gets the total page height in points.</summary>
    public float PageHeight { get; }

    /// <summary>Gets the top margin in points.</summary>
    public float MarginTop { get; }

    /// <summary>Gets the bottom margin in points.</summary>
    public float MarginBottom { get; }

    /// <summary>Initializes a new instance of the <see cref="PageBreaker"/> class.</summary>
    /// <param name="pageHeight">The total page height in points.</param>
    /// <param name="marginTop">The top margin in points.</param>
    /// <param name="marginBottom">The bottom margin in points.</param>
    public PageBreaker(float pageHeight, float marginTop, float marginBottom)
    {
        PageHeight = pageHeight;
        MarginTop = marginTop;
        MarginBottom = marginBottom;
    }

    /// <summary>Gets the usable height for content on a page.</summary>
    public float ContentHeight => PageHeight - MarginTop - MarginBottom;

    /// <summary>Gets the Y position where content starts on a page.</summary>
    public float ContentStartY => MarginTop;

    /// <summary>Determines if a block of the given height fits on the current page.</summary>
    /// <param name="currentY">The current Y position.</param>
    /// <param name="blockHeight">The height of the block to fit.</param>
    /// <returns>True if the block fits; otherwise, false.</returns>
    public bool FitsOnPage(float currentY, float blockHeight) =>
        currentY + blockHeight <= PageHeight - MarginBottom;

    /// <summary>Determines if a page break is needed before a paragraph.</summary>
    /// <param name="currentY">The current Y position.</param>
    /// <param name="paragraphHeight">The paragraph height.</param>
    /// <param name="keepWithNext">Whether this paragraph must stay with the next.</param>
    /// <param name="nextParagraphHeight">The next paragraph height (for keep-with-next).</param>
    /// <returns>True if a page break is needed.</returns>
    public bool NeedsPageBreak(float currentY, float paragraphHeight, bool keepWithNext, float nextParagraphHeight)
    {
        if (!FitsOnPage(currentY, paragraphHeight))
        {
            return true;
        }

        if (keepWithNext && !FitsOnPage(currentY, paragraphHeight + nextParagraphHeight))
        {
            return true;
        }

        return false;
    }
}

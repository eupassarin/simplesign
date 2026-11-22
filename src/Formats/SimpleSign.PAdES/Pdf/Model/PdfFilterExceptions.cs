namespace SimpleSign.PAdES.Pdf.Model;

/// <summary>
/// The encoded data of a stream cannot be decoded by one of its filters: a character the filter does not
/// allow, a corrupt deflate stream, a PNG row with an unknown tag, decode parameters out of range.
/// </summary>
/// <remarks>
/// A <see cref="FormatException"/>: the data is not in the format the filter defines.
/// </remarks>
internal class PdfFilterException : FormatException
{
    /// <summary>Creates the exception.</summary>
    /// <param name="filterName">The filter that refused the data (<c>FlateDecode</c>, <c>ASCII85Decode</c>…).</param>
    /// <param name="message">What was wrong.</param>
    /// <param name="innerException">The error from the decoder underneath, if any.</param>
    public PdfFilterException(string filterName, string message, Exception? innerException = null)
        : base($"{filterName}: {message}", innerException)
    {
        FilterName = filterName;
    }

    /// <summary>The filter that refused the data.</summary>
    public string FilterName { get; }
}

/// <summary>
/// A filter's output went over the most decoded bytes the caller allows: a decompression bomb, or a
/// stream larger than the reader is willing to hold in memory.
/// </summary>
internal sealed class PdfDecodedSizeLimitException : PdfFilterException
{
    /// <summary>Creates the exception.</summary>
    /// <param name="filterName">The filter whose output went over the limit.</param>
    /// <param name="maxDecodedBytes">The limit.</param>
    public PdfDecodedSizeLimitException(string filterName, int maxDecodedBytes)
        : base(filterName, $"decoded data exceeds the limit of {maxDecodedBytes} bytes (possible decompression bomb).")
    {
        MaxDecodedBytes = maxDecodedBytes;
    }

    /// <summary>The limit that was exceeded, in bytes.</summary>
    public int MaxDecodedBytes { get; }
}

/// <summary>
/// A stream uses a filter this reader does not decode: <c>LZWDecode</c>, <c>RunLengthDecode</c>, the image
/// codecs (<c>DCTDecode</c>, <c>JPXDecode</c>, <c>CCITTFaxDecode</c>, <c>JBIG2Decode</c>), <c>Crypt</c>, or a
/// name the specification does not define.
/// </summary>
/// <remarks>
/// Not a <see cref="PdfFilterException"/>: the data may well be valid; it is the reader that cannot read it.
/// </remarks>
internal sealed class PdfUnsupportedFilterException : NotSupportedException
{
    /// <summary>Creates the exception.</summary>
    /// <param name="filterName">The filter that is not supported.</param>
    public PdfUnsupportedFilterException(string filterName)
        : base($"The PDF stream filter '{filterName}' is not supported.")
    {
        FilterName = filterName;
    }

    /// <summary>The filter that is not supported, as named in the stream (abbreviations kept).</summary>
    public string FilterName { get; }
}

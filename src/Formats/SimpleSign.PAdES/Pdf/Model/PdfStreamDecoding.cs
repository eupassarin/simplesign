namespace SimpleSign.PAdES.Pdf.Model;

/// <summary>
/// Turns a stream dictionary's <c>/Filter</c> and <c>/DecodeParms</c> (ISO 32000-1 §7.3.8.2) into the plain values
/// <see cref="PdfFilters"/> takes, and decodes the stream.
/// </summary>
internal static class PdfStreamDecoding
{
    private static readonly PdfName s_predictor = PdfName.Of("Predictor");
    private static readonly PdfName s_colors = PdfName.Of("Colors");
    private static readonly PdfName s_bitsPerComponent = PdfName.Of("BitsPerComponent");
    private static readonly PdfName s_columns = PdfName.Of("Columns");
    private static readonly PdfName s_earlyChange = PdfName.Of("EarlyChange");

    /// <summary>Decodes a stream's data through its filters.</summary>
    /// <param name="stream">The stream.</param>
    /// <param name="maxDecodedBytes">The most bytes any filter may produce.</param>
    /// <param name="resolve">
    /// Resolves an indirect value of <c>/Filter</c> or <c>/DecodeParms</c>; null when they must be direct (a
    /// cross-reference stream), an indirect value then being ignored.
    /// </param>
    /// <returns>The decoded bytes.</returns>
    /// <exception cref="PdfUnsupportedFilterException">A filter is not supported.</exception>
    /// <exception cref="PdfFilterException">The data is corrupt, or decodes to more than the limit.</exception>
    public static byte[] Decode(PdfStream stream, int maxDecodedBytes, Func<PdfObject?, PdfObject?>? resolve = null)
    {
        ArgumentNullException.ThrowIfNull(stream);
        var (filters, parameters) = Filters(stream.Dictionary, resolve);
        return PdfFilters.Decode(stream.Encoded.Span, filters, parameters, maxDecodedBytes);
    }

    /// <summary>The filter names and their decode parameters, by position.</summary>
    /// <param name="dictionary">The stream dictionary.</param>
    /// <param name="resolve">Resolves indirect values; null when they must be direct.</param>
    public static (IReadOnlyList<string> Filters, IReadOnlyList<PdfDecodeParams?> Parameters) Filters(
        PdfDictionary dictionary, Func<PdfObject?, PdfObject?>? resolve = null)
    {
        ArgumentNullException.ThrowIfNull(dictionary);
        PdfObject? Direct(PdfObject? value)
        {
            return value is PdfReference ? resolve?.Invoke(value) : value;
        }

        var filters = new List<string>();
        switch (Direct(dictionary.Get(PdfName.Filter)))
        {
            case PdfName name:
                filters.Add(name.Value);
                break;
            case PdfArray array:
                foreach (var item in array)
                {
                    if (Direct(item) is PdfName filter)
                    {
                        filters.Add(filter.Value);
                    }
                }

                break;
        }

        var parameters = new List<PdfDecodeParams?>();
        switch (Direct(dictionary.Get(PdfName.DecodeParms)))
        {
            case PdfDictionary parms:
                parameters.Add(Parameters(parms, Direct));
                break;
            case PdfArray array:
                foreach (var item in array)
                {
                    parameters.Add(Direct(item) is PdfDictionary parms ? Parameters(parms, Direct) : null);
                }

                break;
        }

        return (filters, parameters);
    }

    private static PdfDecodeParams Parameters(PdfDictionary parms, Func<PdfObject?, PdfObject?> direct)
    {
        int Int(PdfName key, int fallback)
        {
            return direct(parms.Get(key)) is PdfInteger integer && integer.Value is >= int.MinValue and <= int.MaxValue
                ? (int)integer.Value
                : fallback;
        }

        return new PdfDecodeParams
        {
            Predictor = Int(s_predictor, 1),
            Colors = Int(s_colors, 1),
            BitsPerComponent = Int(s_bitsPerComponent, 8),
            Columns = Int(s_columns, 1),
            EarlyChange = Int(s_earlyChange, 1),
        };
    }
}

using System.Globalization;
using System.Text;
using SimpleSign.PAdES.Pdf.Model;

namespace SimpleSign.PAdES.Pdf.Writing;

/// <summary>An object's bytes to rewrite, and the data its source ranges are offsets in.</summary>
/// <param name="Buffer">The file, or the decoded data of the object stream the object is in.</param>
/// <param name="ObjectBytes">The object as an object of its own: <c>N 0 obj</c>, its value as written, <c>endobj</c>.</param>
/// <param name="Compressed">Whether the object is in an object stream.</param>
internal sealed record PdfObjectSource(ReadOnlyMemory<byte> Buffer, byte[] ObjectBytes, bool Compressed)
{
    /// <summary>
    /// Where an object was read from, for a writer that rewrites it in an update (ADR 0032). Its bytes are the file's
    /// from its value to <c>endobj</c>, after a <c>N 0 obj</c> line (the header the writers have always written for a
    /// page) or after its own header (as they have always kept a catalog's); for
    /// an object of an object stream, its value as the stream writes it (trimmed), between that line and
    /// <c>endobj</c>.
    /// </summary>
    /// <param name="document">The document.</param>
    /// <param name="number">The object number.</param>
    /// <param name="obj">The object, as the document gives it for that number.</param>
    /// <param name="keepHeader">For an object in the file, whether its own <c>N G obj</c> and line end are kept as the file writes them.</param>
    public static PdfObjectSource Of(PdfDocument document, int number, PdfIndirectObject obj, bool keepHeader = false)
    {
        ArgumentNullException.ThrowIfNull(document);
        ArgumentNullException.ThrowIfNull(obj);
        var header = Encoding.Latin1.GetBytes(string.Create(CultureInfo.InvariantCulture, $"{number} 0 obj\n"));
        if (document.Lookup(number) is { Type: PdfXrefEntryType.Compressed } entry
            && document.GetObject(entry.StreamNumber)?.Value is PdfStream stream)
        {
            byte[] decoded = document.DecodeStream(stream);
            string value = SourceOf(obj.Value) is { } range && range.End <= decoded.Length
                ? Encoding.Latin1.GetString(decoded, (int)range.Offset, range.Length).Trim()
                : PdfObjectSerializer.ToText(obj.Value);
            return new PdfObjectSource(decoded, [.. header, .. Encoding.Latin1.GetBytes($"{value}\nendobj\n")], Compressed: true);
        }

        if (keepHeader)
        {
            return new PdfObjectSource(document.Data, document.Data.Span[(int)obj.Source.Offset..(int)obj.Source.End].ToArray(), Compressed: false);
        }

        int valueStart = SourceOf(obj.Value) is { } valueRange ? (int)valueRange.Offset : (int)obj.Source.Offset;
        return new PdfObjectSource(document.Data, [.. header, .. document.Data.Span[valueStart..(int)obj.Source.End]], Compressed: false);
    }

    /// <summary>Where a value was read from, for the values that keep it (dictionaries, arrays, streams).</summary>
    /// <param name="value">The value.</param>
    public static PdfSourceRange? SourceOf(PdfObject value) => value switch
    {
        PdfDictionary dictionary => dictionary.Source,
        PdfArray array => array.Source,
        PdfStream stream => stream.Dictionary.Source,
        _ => null,
    };
}

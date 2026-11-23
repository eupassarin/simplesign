using System.Buffers;
using System.Globalization;
using System.IO.Compression;
using System.Text;
using SimpleSign.PAdES.Pdf.Model;

namespace SimpleSign.PAdES.Pdf.Writing;

/// <summary>How an incremental update writes its cross-reference section.</summary>
internal enum PdfXrefStyle
{
    /// <summary>As the document does: a stream when its latest section is one, else a table.</summary>
    AsTheDocument,

    /// <summary>A table (ISO 32000-1 §7.5.4).</summary>
    Table,

    /// <summary>A cross-reference stream (§7.5.8).</summary>
    Stream,
}

/// <summary>
/// An incremental update (ISO 32000-1 §7.5.6) of a document, written the way the library's three writers write theirs
/// (ADR 0032): the original bytes, a line feed when they do not end with a line end, the new and changed objects, and
/// a cross-reference section with its trailer:
/// <list type="bullet">
/// <item>a table: one subsection per run of object numbers, entries ending in CR LF, and a trailer with
/// <c>/Size</c>, <c>/Root</c>, <c>/Prev</c>, then the document's <c>/ID</c> as it is written and its <c>/Info</c>;</item>
/// <item>a stream (<c>/W [1 4 1]</c>, FlateDecode) that lists itself, with the same entries in its dictionary.</item>
/// </list>
/// The caller chooses the object numbers, as each writer numbers its objects; where each object was written is kept,
/// for the cross-reference and to fill placeholders (a signature's <c>/ByteRange</c>) afterwards.
/// </summary>
internal sealed class PdfIncrementalUpdate
{
    private readonly ArrayBufferWriter<byte> _output = new();
    private readonly SortedDictionary<int, long> _offsets = [];

    /// <summary>Starts an update of a document: its bytes are copied, and a line feed added when they need one.</summary>
    /// <param name="document">The document as it is now.</param>
    public PdfIncrementalUpdate(PdfDocument document)
    {
        ArgumentNullException.ThrowIfNull(document);
        Document = document;
        var data = document.Data.Span;
        _output.Write(data);
        OriginalLength = data.Length;

        // ISO 32000-1 §7.3.10: an object number is preceded by a line end (and PDF/A checks it, ISO 19005-3 §6.1.9).
        if (data.Length > 0 && data[^1] is not ((byte)'\n' or (byte)'\r'))
        {
            _output.Write("\n"u8);
        }
    }

    /// <summary>The document updated.</summary>
    public PdfDocument Document { get; }

    /// <summary>The length of the original bytes.</summary>
    public int OriginalLength { get; }

    /// <summary>Where the next byte is written.</summary>
    public long Position => _output.WrittenCount;

    /// <summary>The objects written so far, by number, and where each starts.</summary>
    public IReadOnlyDictionary<int, long> Offsets => _offsets;

    /// <summary>The bytes written so far.</summary>
    public ReadOnlySpan<byte> Written => _output.WrittenSpan;

    /// <summary>Whether the update writes a cross-reference stream when it follows the document.</summary>
    public bool DocumentUsesXrefStream => !Document.IsReconstructed && Document.Latest.Sections[0].Kind == PdfXrefSectionKind.Stream;

    /// <summary>Writes an object, serialized in the writers' layout.</summary>
    /// <param name="number">Its number.</param>
    /// <param name="value">Its value.</param>
    /// <param name="raw">Top-level values written as given (placeholders), by key.</param>
    /// <returns>Where it was written and, for each top-level value, where it is in the file.</returns>
    public (long Offset, IReadOnlyDictionary<string, (long Start, int Length)> Values) Add(
        int number, PdfObject value, IReadOnlyDictionary<string, string>? raw = null)
    {
        var serialized = PdfObjectSerializer.Write(number, value, raw: raw);
        long offset = Add(number, serialized.Bytes);
        return (offset, serialized.ValueRanges.ToDictionary(e => e.Key, e => (offset + e.Value.Start, e.Value.Length), StringComparer.Ordinal));
    }

    /// <summary>Writes an object already serialized (<c>N G obj</c> … <c>endobj</c> and its line end).</summary>
    /// <param name="number">Its number.</param>
    /// <param name="objectBytes">Its bytes.</param>
    /// <returns>Where it was written.</returns>
    public long Add(int number, ReadOnlySpan<byte> objectBytes)
    {
        long offset = Position;
        _offsets[number] = offset;
        _output.Write(objectBytes);
        return offset;
    }

    /// <summary>Records an object written inside bytes already added (an appearance's image after its form, say).</summary>
    /// <param name="number">Its number.</param>
    /// <param name="offset">Where it starts.</param>
    public void Locate(int number, long offset)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(offset, OriginalLength);
        ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(offset, Position);
        _offsets[number] = offset;
    }

    /// <summary>
    /// Writes the cross-reference section and the trailer, and returns the updated document's bytes.
    /// </summary>
    /// <param name="size">The trailer's <c>/Size</c> (raised for a cross-reference stream's own number).</param>
    /// <param name="root">The catalog's object number.</param>
    /// <param name="style">Table or stream.</param>
    /// <param name="xrefStreamNumber">For a stream, its object number; one more than the largest written when 0.</param>
    public byte[] Finish(int size, int root, PdfXrefStyle style = PdfXrefStyle.AsTheDocument, int xrefStreamNumber = 0)
    {
        if (_offsets.Count == 0)
        {
            throw new InvalidOperationException("An incremental update must write at least one object.");
        }

        long prev = Document.StartXref < 0 ? 0 : Document.StartXref;
        string? id = TrailerId();
        string? info = Trailers().Select(t => t.Get(PdfName.Info)).OfType<PdfReference>().FirstOrDefault() is { } reference
            ? string.Create(CultureInfo.InvariantCulture, $"/Info {reference.Id.Number} {reference.Id.Generation} R")
            : null;
        bool stream = style == PdfXrefStyle.Stream || (style == PdfXrefStyle.AsTheDocument && DocumentUsesXrefStream);
        long xrefOffset = Position;
        if (stream)
        {
            int number = xrefStreamNumber > 0 ? xrefStreamNumber : _offsets.Keys.Max() + 1;
            _output.Write(XrefStream(number, Math.Max(size, number + 1), root, prev, xrefOffset, id, info));
        }
        else
        {
            _output.Write(XrefTable(size, root, prev, xrefOffset, id, info));
        }

        return _output.WrittenSpan.ToArray();
    }

    /// <summary>
    /// The trailers, latest first: a value an update left out is taken from the trailer before it, as the writers have
    /// always carried <c>/ID</c> and <c>/Info</c> forward.
    /// </summary>
    private IEnumerable<PdfDictionary> Trailers() =>
        Document.Revisions.Reverse().SelectMany(r => r.Sections.Select(s => s.Trailer));

    /// <summary>The <c>/ID</c> as the file writes it (<c>/ID [&lt;…&gt; &lt;…&gt;]</c>), so it is copied byte for byte.</summary>
    private string? TrailerId()
    {
        foreach (var trailer in Trailers())
        {
            switch (trailer.Get(PdfName.ID))
            {
                case PdfArray { Source: { } source } when source.End <= Document.Data.Length:
                    return "/ID " + Encoding.Latin1.GetString(Document.Data.Span.Slice((int)source.Offset, source.Length));
                case PdfArray array:
                    return "/ID " + PdfObjectSerializer.ToText(array);
            }
        }

        return null;
    }

    private byte[] XrefTable(int size, int root, long prev, long xrefOffset, string? id, string? info)
    {
        var text = new StringBuilder("xref\n");
        foreach (var run in Runs(_offsets.Keys))
        {
            text.Append(CultureInfo.InvariantCulture, $"{run[0]} {run.Count}\n");
            foreach (int number in run)
            {
                text.Append(CultureInfo.InvariantCulture, $"{_offsets[number]:D10} 00000 n\r\n");
            }
        }

        text.Append("trailer\n");
        text.Append(CultureInfo.InvariantCulture, $"<< /Size {size}\n");
        text.Append(CultureInfo.InvariantCulture, $"   /Root {root} 0 R\n");
        text.Append(CultureInfo.InvariantCulture, $"   /Prev {prev}\n");
        AppendTrailerExtras(text, id, info);
        text.Append(">>\n");
        text.Append(CultureInfo.InvariantCulture, $"startxref\n{xrefOffset}\n%%EOF\n");
        return Encoding.Latin1.GetBytes(text.ToString());
    }

    private byte[] XrefStream(int number, int size, int root, long prev, long offset, string? id, string? info)
    {
        // The stream lists itself (§7.5.8.1).
        var all = new SortedDictionary<int, long>(_offsets) { [number] = offset };
        var index = new List<string>();
        var rows = new List<byte>();
        foreach (var run in Runs(all.Keys))
        {
            index.Add(string.Create(CultureInfo.InvariantCulture, $"{run[0]} {run.Count}"));
            foreach (int n in run)
            {
                long at = all[n];
                rows.AddRange([1, (byte)(at >> 24), (byte)(at >> 16), (byte)(at >> 8), (byte)at, 0]);
            }
        }

        byte[] compressed;
        using (var ms = new MemoryStream())
        {
            using (var zlib = new ZLibStream(ms, CompressionLevel.Optimal, leaveOpen: true))
            {
                zlib.Write([.. rows]);
            }

            compressed = ms.ToArray();
        }

        var text = new StringBuilder();
        text.Append(CultureInfo.InvariantCulture, $"{number} 0 obj\n");
        text.Append("<< /Type /XRef\n");
        text.Append(CultureInfo.InvariantCulture, $"   /Size {size}\n");
        text.Append(CultureInfo.InvariantCulture, $"   /Root {root} 0 R\n");
        text.Append(CultureInfo.InvariantCulture, $"   /Prev {prev}\n");
        text.Append("   /W [1 4 1]\n");
        text.Append(CultureInfo.InvariantCulture, $"   /Index [{string.Join(" ", index)}]\n");
        text.Append("   /Filter /FlateDecode\n");
        text.Append(CultureInfo.InvariantCulture, $"   /Length {compressed.Length}\n");
        AppendTrailerExtras(text, id, info);
        text.Append(">>\nstream\n");
        return
        [
            .. Encoding.Latin1.GetBytes(text.ToString()),
            .. compressed,
            .. Encoding.Latin1.GetBytes(string.Create(CultureInfo.InvariantCulture, $"\nendstream\nendobj\nstartxref\n{offset}\n%%EOF\n")),
        ];
    }

    private static void AppendTrailerExtras(StringBuilder text, string? id, string? info)
    {
        if (id is not null)
        {
            text.Append(CultureInfo.InvariantCulture, $"   {id}\n");
        }

        if (info is not null)
        {
            text.Append(CultureInfo.InvariantCulture, $"   {info}\n");
        }
    }

    private static List<List<int>> Runs(IEnumerable<int> numbers)
    {
        var runs = new List<List<int>>();
        foreach (int n in numbers)
        {
            if (runs.Count == 0 || runs[^1][^1] != n - 1)
            {
                runs.Add([]);
            }

            runs[^1].Add(n);
        }

        return runs;
    }
}

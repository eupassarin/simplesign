using System.Globalization;
using System.IO.Compression;
using System.Text;

namespace SimpleSign.PAdES.Tests.Pdf.Parity;

/// <summary>How a revision's cross-reference section is written.</summary>
internal enum XrefStyle
{
    /// <summary>A table (ISO 32000-1 §7.5.4).</summary>
    Table,

    /// <summary>A cross-reference stream (§7.5.8).</summary>
    Stream,

    /// <summary>A table whose trailer's <c>/XRefStm</c> points to a stream listing the compressed objects (§7.5.8.4).</summary>
    Hybrid,
}

/// <summary>What else a revision's cross-reference does, to build broken files.</summary>
internal sealed record RevisionOptions
{
    /// <summary>The number of the cross-reference stream object (Stream and Hybrid).</summary>
    public int XrefStreamNumber { get; init; }

    /// <summary>The number of the object stream holding the compressed objects.</summary>
    public int ObjectStreamNumber { get; init; }

    /// <summary>Added to every offset a table lists: entries that miss their objects.</summary>
    public int OffsetShift { get; init; }

    /// <summary>Writes the first subsection as <c>1 n</c> with object 0's entry first (a common writer bug).</summary>
    public bool ShiftedSubsection { get; init; }

    /// <summary>The <c>/Prev</c> to write instead of the previous section's offset.</summary>
    public long? Prev { get; init; }

    /// <summary>Writes no <c>/Prev</c>, even after an earlier section.</summary>
    public bool NoPrev { get; init; }

    /// <summary>The offset <c>startxref</c> gives instead of this section's.</summary>
    public long? StartXref { get; init; }

    /// <summary>Compresses the cross-reference stream with FlateDecode and PNG predictor 12.</summary>
    public bool Predictor { get; init; }

    /// <summary>Leaves out <c>startxref</c> and its offset.</summary>
    public bool OmitStartXref { get; init; }

    /// <summary>The end of line of the table's 20-byte entries: <c>" \n"</c> or <c>"\r\n"</c>.</summary>
    public string EntryEnd { get; init; } = " \n";

    /// <summary>Written between a table's last entry and <c>trailer</c>.</summary>
    public string BeforeTrailer { get; init; } = "";

    /// <summary>Extra trailer entries.</summary>
    public string TrailerExtra { get; init; } = "";
}

/// <summary>
/// Writes small PDFs revision by revision, with each kind of cross-reference (table, stream, hybrid), object streams,
/// generations above 0, free entries and the usual breakages, to test the reader against known offsets.
/// </summary>
internal sealed class PdfFileBuilder
{
    private readonly List<byte> _out = [];
    private readonly string _eol;
    private readonly List<(int Number, int Generation, long Offset)> _written = [];
    private readonly List<(int Number, string Body)> _compressed = [];
    private readonly List<(int Number, int Generation)> _freed = [];
    private readonly HashSet<int> _allNumbers = [];
    private int _root = 1;

    public PdfFileBuilder(string header = "%PDF-1.7", string eol = "\n")
    {
        _eol = eol;
        Write(header + eol + "%âãÏÓ" + eol);
    }

    /// <summary>The offsets of the sections written, oldest first.</summary>
    public List<long> XrefOffsets { get; } = [];

    /// <summary>The offset of each object header written, by number and generation (the last one wins).</summary>
    public Dictionary<(int Number, int Generation), long> ObjectOffsets { get; } = [];

    /// <summary>The offsets just after each <c>%%EOF</c> line.</summary>
    public List<long> RevisionEnds { get; } = [];

    public long Position => _out.Count;

    public PdfFileBuilder Root(int number)
    {
        _root = number;
        return this;
    }

    public PdfFileBuilder Object(int number, string body, int generation = 0)
    {
        long offset = _out.Count;
        Write($"{number} {generation} obj{_eol}{body}{_eol}endobj{_eol}");
        _written.Add((number, generation, offset));
        ObjectOffsets[(number, generation)] = offset;
        _allNumbers.Add(number);
        return this;
    }

    public PdfFileBuilder Stream(int number, string dictionaryEntries, byte[] data, int generation = 0)
    {
        long offset = _out.Count;
        Write($"{number} {generation} obj{_eol}<< {dictionaryEntries} /Length {data.Length} >>{_eol}stream{_eol}");
        _out.AddRange(data);
        Write($"{_eol}endstream{_eol}endobj{_eol}");
        _written.Add((number, generation, offset));
        ObjectOffsets[(number, generation)] = offset;
        _allNumbers.Add(number);
        return this;
    }

    /// <summary>An object put in this revision's object stream.</summary>
    public PdfFileBuilder Compressed(int number, string body)
    {
        _compressed.Add((number, body));
        _allNumbers.Add(number);
        return this;
    }

    /// <summary>A free entry in this revision's section.</summary>
    public PdfFileBuilder Free(int number, int nextGeneration = 1)
    {
        _freed.Add((number, nextGeneration));
        return this;
    }

    /// <summary>Bytes written as they are, between objects.</summary>
    public PdfFileBuilder Raw(string text)
    {
        Write(text);
        return this;
    }

    public PdfFileBuilder EndRevision(XrefStyle style = XrefStyle.Table, RevisionOptions? options = null)
    {
        options ??= new RevisionOptions();
        var streamEntries = new SortedDictionary<int, (int Type, long Second, int Third)>();

        if (_compressed.Count > 0)
        {
            int objStm = options.ObjectStreamNumber;
            var header = new StringBuilder();
            var body = new StringBuilder();
            for (int i = 0; i < _compressed.Count; i++)
            {
                header.Append(CultureInfo.InvariantCulture, $"{_compressed[i].Number} {body.Length} ");
                body.Append(_compressed[i].Body).Append('\n');
                streamEntries[_compressed[i].Number] = (2, objStm, i);
            }

            string content = header.ToString() + body;
            byte[] packed = Zlib(Encoding.Latin1.GetBytes(content));
            Stream(objStm, $"/Type /ObjStm /N {_compressed.Count} /First {header.Length} /Filter /FlateDecode", packed);
        }

        long? prev = options.NoPrev ? null : options.Prev ?? (XrefOffsets.Count > 0 ? XrefOffsets[^1] : null);
        int size = _allNumbers.Concat([options.XrefStreamNumber]).Max() + 1;
        string prevEntry = prev is long p ? $" /Prev {p}" : "";

        if (style == XrefStyle.Stream)
        {
            foreach (var (number, generation, at) in _written)
            {
                streamEntries[number] = (1, at, generation);
            }

            foreach (var (number, generation) in _freed)
            {
                streamEntries[number] = (0, 0, generation);
            }

            if (XrefOffsets.Count == 0)
            {
                streamEntries[0] = (0, 0, 65535);
            }

            long offset = _out.Count;
            streamEntries[options.XrefStreamNumber] = (1, offset, 0);
            WriteXrefStream(options.XrefStreamNumber, streamEntries, $"/Size {size} /Root {_root} 0 R{prevEntry} {options.TrailerExtra}", options.Predictor);
            XrefOffsets.Add(offset);
        }
        else
        {
            long? hybridOffset = null;
            if (style == XrefStyle.Hybrid)
            {
                hybridOffset = _out.Count;
                streamEntries[options.XrefStreamNumber] = (1, hybridOffset.Value, 0);
                WriteXrefStream(options.XrefStreamNumber, streamEntries, $"/Size {size}", options.Predictor);
            }

            long offset = _out.Count;
            var table = new SortedDictionary<int, string>();
            if (XrefOffsets.Count == 0)
            {
                table[0] = "0000000000 65535 f";
            }

            foreach (var (number, generation, at) in _written)
            {
                table[number] = $"{at + options.OffsetShift:D10} {generation:D5} n";
            }

            foreach (var (number, generation) in _freed)
            {
                table[number] = $"0000000000 {generation:D5} f";
            }

            var text = new StringBuilder("xref" + _eol);
            foreach (var run in Runs(table.Keys))
            {
                int first = options.ShiftedSubsection && run[0] == 0 ? 1 : run[0];
                text.Append(CultureInfo.InvariantCulture, $"{first} {run.Count}{_eol}");
                foreach (int number in run)
                {
                    text.Append(table[number]).Append(options.EntryEnd);
                }
            }

            string hybrid = hybridOffset is long h ? $" /XRefStm {h}" : "";
            text.Append(options.BeforeTrailer);
            text.Append(CultureInfo.InvariantCulture, $"trailer{_eol}<< /Size {size} /Root {_root} 0 R{prevEntry}{hybrid} {options.TrailerExtra}>>{_eol}");
            Write(text.ToString());
            XrefOffsets.Add(offset);
        }

        if (!options.OmitStartXref)
        {
            Write($"startxref{_eol}{options.StartXref ?? XrefOffsets[^1]}{_eol}%%EOF{_eol}");
        }

        RevisionEnds.Add(_out.Count);
        _written.Clear();
        _compressed.Clear();
        _freed.Clear();
        return this;
    }

    public byte[] ToArray() => [.. _out];

    private void WriteXrefStream(int number, SortedDictionary<int, (int Type, long Second, int Third)> entries, string trailer, bool predictor)
    {
        const int width = 1 + 4 + 2;
        var index = new StringBuilder();
        var rows = new MemoryStream();
        foreach (var run in Runs(entries.Keys))
        {
            index.Append(CultureInfo.InvariantCulture, $"{run[0]} {run.Count} ");
            foreach (int n in run)
            {
                var (type, second, third) = entries[n];
                if (predictor)
                {
                    rows.WriteByte(0); // PNG None; the Up rows are checked in the predictor tests
                }

                rows.Write([(byte)type, (byte)(second >> 24), (byte)(second >> 16), (byte)(second >> 8), (byte)second, (byte)(third >> 8), (byte)third]);
            }
        }

        string parms = predictor ? $" /DecodeParms << /Predictor 12 /Columns {width} >>" : "";
        Stream(number, $"/Type /XRef /W [1 4 2] /Index [{index.ToString().TrimEnd()}] /Filter /FlateDecode{parms} {trailer}", Zlib(rows.ToArray()));
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

    private void Write(string text) => _out.AddRange(Encoding.Latin1.GetBytes(text));

    internal static byte[] Zlib(byte[] data)
    {
        using var ms = new MemoryStream();
        using (var zlib = new ZLibStream(ms, CompressionLevel.Optimal, leaveOpen: true))
        {
            zlib.Write(data);
        }

        return ms.ToArray();
    }
}

// Licensed to SimpleSign under the MIT License.

using System.Globalization;
using System.IO.Compression;
using System.Text;

namespace SimpleSign.HtmlToPdf.Rendering;

/// <summary>
/// Low-level PDF object writer. Manages object numbering, streams, xref table,
/// and the final PDF byte assembly.
/// </summary>
internal sealed class PdfObjectWriter
{
    private readonly List<byte[]> _objects = [];
    private int _nextObjNum = 1;

    /// <summary>Gets or sets the object number for the /Info dictionary, included in the trailer when set.</summary>
    public int? InfoObjectNum { get; set; }

    /// <summary>Allocates the next object number.</summary>
    /// <returns>The allocated object number.</returns>
    public int AllocateObject()
    {
        return _nextObjNum++;
    }

    /// <summary>Writes a PDF object with the given content.</summary>
    /// <param name="objNum">Object number.</param>
    /// <param name="content">Object content (between obj and endobj).</param>
    public void WriteObject(int objNum, string content)
    {
        string obj = $"{objNum} 0 obj\n{content}\nendobj\n";
        StoreObject(objNum, Encoding.ASCII.GetBytes(obj));
    }

    /// <summary>Writes a PDF stream object with dictionary and binary data.</summary>
    /// <param name="objNum">Object number.</param>
    /// <param name="dict">Dictionary content (without &lt;&lt; &gt;&gt;).</param>
    /// <param name="streamData">Raw stream bytes.</param>
    public void WriteStreamObject(int objNum, string dict, byte[] streamData)
    {
        bool alreadyFiltered = dict.Contains("/Filter", StringComparison.Ordinal);
        byte[] outputData = streamData;
        string outputDict = dict;

        if (!alreadyFiltered)
        {
            outputData = Compress(streamData);
            outputDict = $"{dict} /Filter /FlateDecode";
        }

        var sb = new StringBuilder();
        sb.Append(CultureInfo.InvariantCulture, $"{objNum} 0 obj\n");
        sb.Append(CultureInfo.InvariantCulture, $"<< {outputDict} /Length {outputData.Length} >>\n");
        sb.Append("stream\n");

        byte[] header = Encoding.ASCII.GetBytes(sb.ToString());
        byte[] footer = Encoding.ASCII.GetBytes("\nendstream\nendobj\n");

        byte[] full = new byte[header.Length + outputData.Length + footer.Length];
        header.CopyTo(full, 0);
        outputData.CopyTo(full, header.Length);
        footer.CopyTo(full, header.Length + outputData.Length);

        StoreObject(objNum, full);
    }

    private static byte[] Compress(byte[] data)
    {
        using var output = new MemoryStream();
        using (var zlib = new ZLibStream(output, CompressionLevel.Optimal, leaveOpen: true))
        {
            zlib.Write(data, 0, data.Length);
        }

        return output.ToArray();
    }

    /// <summary>Assembles the complete PDF document.</summary>
    /// <returns>Complete PDF bytes.</returns>
    public byte[] Assemble()
    {
        using var ms = new MemoryStream();

        // Header
        byte[] header = "%PDF-1.7\n%\xe2\xe3\xcf\xd3\n"u8.ToArray();
        ms.Write(header);

        // Objects
        var objectOffsets = new long[_nextObjNum];
        foreach (int objNum in Enumerable.Range(1, _nextObjNum - 1))
        {
            int idx = objNum - 1;
            if (idx < _objects.Count && _objects[idx].Length > 0)
            {
                objectOffsets[objNum] = ms.Position;
                ms.Write(_objects[idx]);
            }
        }

        // Xref table
        long xrefOffset = ms.Position;
        var xrefSb = new StringBuilder();
        xrefSb.Append(CultureInfo.InvariantCulture, $"xref\n0 {_nextObjNum}\n");
        xrefSb.Append("0000000000 65535 f\r\n");

        for (int i = 1; i < _nextObjNum; i++)
        {
            xrefSb.Append(CultureInfo.InvariantCulture, $"{objectOffsets[i]:D10} 00000 n\r\n");
        }

        ms.Write(Encoding.ASCII.GetBytes(xrefSb.ToString()));

        // Trailer
        string infoRef = InfoObjectNum.HasValue ? $" /Info {InfoObjectNum.Value} 0 R" : string.Empty;
        string trailer = $"trailer\n<< /Size {_nextObjNum} /Root 1 0 R{infoRef} >>\nstartxref\n{xrefOffset}\n%%EOF\n";
        ms.Write(Encoding.ASCII.GetBytes(trailer));

        return ms.ToArray();
    }

    private void StoreObject(int objNum, byte[] data)
    {
        int idx = objNum - 1;
        while (_objects.Count <= idx)
        {
            _objects.Add([]);
        }

        _objects[idx] = data;
    }
}

using System.Globalization;
using System.IO.Compression;
using System.Text;

namespace SimpleSign.TestHelpers;

public static class TestPdfFactory
{
    /// <summary>Creates a minimal PDF with a Catalog and Pages tree (no page objects).</summary>
    public static byte[] CreateMinimalPdf()
    {
        return Encoding.Latin1.GetBytes(
            "%PDF-1.7\n" +
            "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n" +
            "2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\n" +
            "xref\n0 3\n" +
            "0000000000 65535 f \n" +
            "0000000009 00000 n \n" +
            "0000000058 00000 n \n" +
            "trailer\n<< /Size 3 /Root 1 0 R >>\n" +
            "startxref\n110\n%%EOF");
    }

    /// <summary>Creates a minimal PDF with a single A4 page.</summary>
    public static byte[] CreateMinimalPdfWithPage()
    {
        return Encoding.Latin1.GetBytes(
            "%PDF-1.7\n" +
            "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n" +
            "2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n" +
            "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n" +
            "xref\n0 4\n" +
            "0000000000 65535 f \n" +
            "0000000009 00000 n \n" +
            "0000000058 00000 n \n" +
            "0000000115 00000 n \n" +
            "trailer\n<< /Size 4 /Root 1 0 R >>\n" +
            "startxref\n190\n%%EOF");
    }

    /// <summary>Creates a minimal 3-page PDF.</summary>
    public static byte[] CreateThreePagePdf()
    {
        return Encoding.Latin1.GetBytes(
            "%PDF-1.7\n" +
            "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n" +
            "2 0 obj\n<< /Type /Pages /Kids [3 0 R 4 0 R 5 0 R] /Count 3 >>\nendobj\n" +
            "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n" +
            "4 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n" +
            "5 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n" +
            "xref\n0 6\n" +
            "0000000000 65535 f \n" +
            "0000000009 00000 n \n" +
            "0000000058 00000 n \n" +
            "0000000123 00000 n \n" +
            "0000000198 00000 n \n" +
            "0000000273 00000 n \n" +
            "trailer\n<< /Size 6 /Root 1 0 R >>\n" +
            "startxref\n348\n%%EOF");
    }

    /// <summary>
    /// Creates a one-page PDF with embedded files: a <c>/Names /EmbeddedFiles</c> name tree whose entries are file
    /// specifications with a <c>/FlateDecode</c> stream each, named in UTF-16BE (as Acrobat writes them).
    /// </summary>
    /// <param name="files">The files: name and content.</param>
    public static byte[] CreatePdfWithAttachments(params (string Name, byte[] Content)[] files)
    {
        ArgumentNullException.ThrowIfNull(files);
        var sorted = files.OrderBy(f => f.Name, StringComparer.Ordinal).ToArray();
        var objects = new List<byte[]>
        {
            Encoding.Latin1.GetBytes("<< /Type /Catalog /Pages 2 0 R /Names << /EmbeddedFiles 4 0 R >> >>"),
            Encoding.Latin1.GetBytes("<< /Type /Pages /Kids [3 0 R] /Count 1 >>"),
            Encoding.Latin1.GetBytes("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>"),
        };

        var tree = new StringBuilder("<< /Names [");
        for (int i = 0; i < sorted.Length; i++)
        {
            tree.Append(CultureInfo.InvariantCulture, $" {Utf16Hex(sorted[i].Name)} {5 + (2 * i)} 0 R");
        }

        objects.Add(Encoding.Latin1.GetBytes(tree.Append(" ] >>").ToString()));
        foreach (var (name, content) in sorted)
        {
            int stream = objects.Count + 2;
            objects.Add(Encoding.Latin1.GetBytes(
                $"<< /Type /Filespec /F {Utf16Hex(name)} /UF {Utf16Hex(name)} /EF << /F {stream} 0 R >> >>"));
            byte[] compressed = Deflate(content);
            objects.Add([
                .. Encoding.Latin1.GetBytes($"<< /Type /EmbeddedFile /Subtype /application#2Foctet-stream /Filter /FlateDecode /Length {compressed.Length} >>\nstream\n"),
                .. compressed,
                .. "\nendstream"u8,
            ]);
        }

        using var pdf = new MemoryStream();
        pdf.Write("%PDF-1.7\n"u8);
        var offsets = new List<long>();
        for (int i = 0; i < objects.Count; i++)
        {
            offsets.Add(pdf.Position);
            pdf.Write(Encoding.Latin1.GetBytes($"{i + 1} 0 obj\n"));
            pdf.Write(objects[i]);
            pdf.Write("\nendobj\n"u8);
        }

        long xref = pdf.Position;
        var table = new StringBuilder();
        table.Append(CultureInfo.InvariantCulture, $"xref\n0 {objects.Count + 1}\n0000000000 65535 f \n");
        foreach (long offset in offsets)
        {
            table.Append(CultureInfo.InvariantCulture, $"{offset:D10} 00000 n \n");
        }

        table.Append(CultureInfo.InvariantCulture, $"trailer\n<< /Size {objects.Count + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF");
        pdf.Write(Encoding.Latin1.GetBytes(table.ToString()));
        return pdf.ToArray();
    }

    /// <summary>A PDF text string in UTF-16BE with its byte order mark, as a hexadecimal string.</summary>
    private static string Utf16Hex(string text) => $"<FEFF{Convert.ToHexString(Encoding.BigEndianUnicode.GetBytes(text))}>";

    private static byte[] Deflate(byte[] content)
    {
        using var output = new MemoryStream();
        using (var zlib = new ZLibStream(output, CompressionLevel.Optimal, leaveOpen: true))
        {
            zlib.Write(content);
        }

        return output.ToArray();
    }
}

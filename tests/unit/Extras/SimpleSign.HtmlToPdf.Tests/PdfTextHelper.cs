// Licensed to SimpleSign under the MIT License.

using System.IO.Compression;
using System.Text;

namespace SimpleSign.HtmlToPdf.Tests;

/// <summary>
/// Extracts readable text from PDF bytes by decompressing FlateDecode streams.
/// Used by tests that need to assert on content inside compressed streams.
/// </summary>
internal static class PdfTextHelper
{
    /// <summary>
    /// Returns the full PDF as Latin1 text with FlateDecode streams decompressed inline.
    /// </summary>
    public static string GetDecompressedPdfText(byte[] pdf)
    {
        // Get the raw text and also append decompressed stream content
        string rawText = Encoding.Latin1.GetString(pdf);
        var sb = new StringBuilder(rawText);

        // Find and decompress all FlateDecode streams
        byte[] streamMarker = Encoding.ASCII.GetBytes("stream\n");
        byte[] endMarker = Encoding.ASCII.GetBytes("\nendstream");

        int pos = 0;
        while (pos < pdf.Length)
        {
            int streamStart = IndexOf(pdf, streamMarker, pos);
            if (streamStart < 0)
            {
                break;
            }

            int dataStart = streamStart + streamMarker.Length;
            int endPos = IndexOf(pdf, endMarker, dataStart);
            if (endPos < 0)
            {
                break;
            }

            int dataLen = endPos - dataStart;
            if (dataLen > 0)
            {
                try
                {
                    using var input = new MemoryStream(pdf, dataStart, dataLen);
                    using var zlib = new ZLibStream(input, CompressionMode.Decompress);
                    using var output = new MemoryStream();
                    zlib.CopyTo(output);
                    string decompressed = Encoding.Latin1.GetString(output.ToArray());
                    sb.Append('\n');
                    sb.Append(decompressed);
                }
                catch (InvalidDataException)
                {
                    // Not a valid zlib stream; skip
                }
            }

            pos = endPos + endMarker.Length;
        }

        return sb.ToString();
    }

    private static int IndexOf(byte[] haystack, byte[] needle, int startIndex)
    {
        int end = haystack.Length - needle.Length;
        for (int i = startIndex; i <= end; i++)
        {
            bool match = true;
            for (int j = 0; j < needle.Length; j++)
            {
                if (haystack[i + j] != needle[j])
                {
                    match = false;
                    break;
                }
            }

            if (match)
            {
                return i;
            }
        }

        return -1;
    }
}

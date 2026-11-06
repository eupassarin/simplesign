using System.IO.Compression;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Shouldly;
using SimpleSign.PAdES.Signing;
using SimpleSign.PAdES.Pdf;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.PAdES.Tests.Signing;

/// <summary>
/// Tests for the embedded LiberationSans /FontFile2 stream metadata.
/// Adobe Acrobat rejects the embedded font when /Length1 (decoded font
/// program length, ISO 32000-1 §9.9 Table 126) is missing from the stream
/// dictionary.
/// </summary>
[Trait("Category", "Unit")]
public sealed class FontEmbeddingTests
{
    /// <summary>
    /// Parses a /FontFile2 object ("N 0 obj ... endobj") and returns the
    /// /Length1 dictionary value plus the decoded (FlateDecode) stream bytes.
    /// </summary>
    private static (int Length1, byte[] Decoded) ParseFontFile2Object(byte[] objBytes)
    {
        string text = Encoding.Latin1.GetString(objBytes);

        int length1Key = text.IndexOf("/Length1 ", StringComparison.Ordinal);
        length1Key.ShouldBeGreaterThanOrEqualTo(0, "FontFile2 stream dictionary must contain /Length1");

        int valueStart = length1Key + "/Length1 ".Length;
        int valueEnd = valueStart;
        while (valueEnd < text.Length && char.IsAsciiDigit(text[valueEnd]))
        {
            valueEnd++;
        }

        int length1 = int.Parse(text.AsSpan(valueStart, valueEnd - valueStart));

        int streamMarker = text.IndexOf(">>\nstream\n", StringComparison.Ordinal);
        streamMarker.ShouldBeGreaterThanOrEqualTo(0, "FontFile2 object must contain a stream");

        int streamStart = streamMarker + ">>\nstream\n".Length;
        // LastIndexOf avoids any accidental "endstream" match inside the binary stream data.
        int endMarker = text.LastIndexOf("\nendstream", StringComparison.Ordinal);
        endMarker.ShouldBeGreaterThanOrEqualTo(streamStart, "FontFile2 stream must be terminated by endstream");

        byte[] compressed = objBytes.AsSpan(streamStart, endMarker - streamStart).ToArray();

        using var input = new MemoryStream(compressed);
        using var zlib = new ZLibStream(input, CompressionMode.Decompress);
        using var output = new MemoryStream();
        zlib.CopyTo(output);
        return (length1, output.ToArray());
    }

    /// <summary>
    /// Extracts the /FontFile2 object referenced by the font descriptor of a signed
    /// PDF and returns its parsed /Length1 value and decoded stream bytes.
    /// </summary>
    private static (int Length1, byte[] Decoded) ExtractFontFile2FromPdf(byte[] pdf)
    {
        string pdfText = Encoding.Latin1.GetString(pdf);

        int refPos = pdfText.IndexOf("/FontFile2 ", StringComparison.Ordinal);
        refPos.ShouldBeGreaterThanOrEqualTo(0, "signed PDF must embed a /FontFile2 stream");

        int numStart = refPos + "/FontFile2 ".Length;
        int numEnd = numStart;
        while (numEnd < pdfText.Length && char.IsAsciiDigit(pdfText[numEnd]))
        {
            numEnd++;
        }

        int fontFileObjNum = int.Parse(pdfText.AsSpan(numStart, numEnd - numStart));

        var (objStart, objEnd) = PdfStructureParser.FindObjectBytes(pdf, fontFileObjNum);
        objStart.ShouldBeGreaterThanOrEqualTo(0, "FontFile2 object must be locatable via object number");

        return ParseFontFile2Object(pdf.AsSpan(objStart, objEnd - objStart).ToArray());
    }

    [Fact(DisplayName = "FontFile2 object includes /Length1 equal to decoded TTF length")]
    public void BuildFontFileObject_IncludesLength1MatchingDecodedTtfLength()
    {
        byte[] objBytes = PdfFontWriter.BuildFontFileObject(59);

        var (length1, decoded) = ParseFontFile2Object(objBytes);

        length1.ShouldBe(FontResources.TtfData.Length);
        decoded.Length.ShouldBe(FontResources.TtfData.Length);
        decoded.ShouldBe(FontResources.TtfData);
    }

    [Fact(DisplayName = "Signed PDF FontFile2 has /Length1 and decodes to the embedded TTF")]
    public async Task SignAsync_WithDefaultAppearance_FontFile2DecodesWithLength1()
    {
        using X509Certificate2 cert = TestCertificateFactory.CreateSelfSignedCert("CN=Font Embedder, O=Tests");
        byte[] pdf = TestPdfFactory.CreateMinimalPdfWithPage();
        byte[] signed = await PadesSigner.Document(pdf)
            .WithCertificate(cert)
            .WithAppearance(new SignatureAppearance { X = 20, Y = 20, AutoPosition = false })
            .SignAsync();

        var (length1, decoded) = ExtractFontFile2FromPdf(signed);

        length1.ShouldBe(FontResources.TtfData.Length);
        decoded.Length.ShouldBe(FontResources.TtfData.Length);
        decoded.ShouldBe(FontResources.TtfData);
    }
}

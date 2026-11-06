using Shouldly;
using SimpleSign.Cli.Rendering;
using SimpleSign.Core.Inspection;
using SimpleSign.Core.Validation;
using SimpleSign.PAdES.Inspection;
using SimpleSign.PAdES.Pdf.Enums;

namespace SimpleSign.Cli.Tests;

public sealed class FormattingTests
{
    [Theory]
    [InlineData(1, "Locked — no changes allowed")]
    [InlineData(2, "Locked — form filling only")]
    [InlineData(3, "Certified — form filling and annotations allowed")]
    [InlineData(0, "Not locked")]
    [InlineData(99, "Not locked")]
    public void FormatDocMdp_ReturnsExpected(int level, string expected) =>
        Formatting.FormatDocMdp(level).ShouldBe(expected);

    [Theory]
    [InlineData(PAdESConformanceLevel.Unknown, "Unknown")]
    [InlineData(PAdESConformanceLevel.CmsOnly, "CMS (no PAdES attributes)")]
    [InlineData(PAdESConformanceLevel.BaselineB, "PAdES B-B")]
    [InlineData(PAdESConformanceLevel.BaselineT, "PAdES B-T")]
    [InlineData(PAdESConformanceLevel.BaselineLT, "PAdES B-LT")]
    [InlineData(PAdESConformanceLevel.BaselineLTA, "PAdES B-LTA")]
    public void FormatLevel_ReturnsExpected(PAdESConformanceLevel level, string expected) =>
        Formatting.FormatLevel(level).ShouldBe(expected);

    [Theory]
    [InlineData(PdfALevel.None, "Not detected")]
    [InlineData(PdfALevel.A1b, "PDF/A-1b")]
    [InlineData(PdfALevel.A3u, "PDF/A-3u")]
    [InlineData(PdfALevel.A4b, "PDF/A-4b")]
    [InlineData(PdfALevel.A4e, "PDF/A-4e")]
    public void FormatPdfA_ReturnsExpected(PdfALevel level, string expected) =>
        Formatting.FormatPdfA(level).ShouldBe(expected);

    [Theory]
    [InlineData(PdfALevel.None, "Not detected")]
    [InlineData(PdfALevel.A1b, "PDF/A-1b (ISO 19005-1)")]
    [InlineData(PdfALevel.A3u, "PDF/A-3u (ISO 19005-3)")]
    [InlineData(PdfALevel.A4b, "PDF/A-4b (ISO 19005-4)")]
    [InlineData(PdfALevel.A4e, "PDF/A-4e (ISO 19005-4)")]
    public void FormatPdfAFull_ReturnsExpected(PdfALevel level, string expected) =>
        Formatting.FormatPdfAFull(level).ShouldBe(expected);

    [Theory]
    [InlineData(SimpleSign.PAdES.Pdf.PdfVersion.Pdf17, "1.7")]
    [InlineData(SimpleSign.PAdES.Pdf.PdfVersion.Pdf20, "2.0")]
    public void FormatVersion_ReturnsExpected(SimpleSign.PAdES.Pdf.PdfVersion version, string expected) =>
        Formatting.FormatVersion(version).ShouldBe(expected);

    [Theory]
    [InlineData(0, "0 bytes")]
    [InlineData(500, "500 bytes")]
    [InlineData(1024, "1.0 KB (1,024 bytes)")]
    [InlineData(1048576, "1.0 MB (1,048,576 bytes)")]
    public void FormatBytes_ReturnsExpected(int bytes, string expected) =>
        Formatting.FormatBytes(bytes).ShouldBe(expected);

    [Theory]
    [InlineData("", "")]
    [InlineData("abc", "abc")]
    [InlineData("deadbeef", "DE:AD:BE:EF")]
    [InlineData("deadbeef00", "DE:AD:BE:EF:00")]
    public void FormatThumbprint_ReturnsExpected(string hex, string expected) =>
        Formatting.FormatThumbprint(hex).ShouldBe(expected);

    [Theory]
    [InlineData("1.3.6.1.5.5.7.3.1", "serverAuth")]
    [InlineData("1.3.6.1.5.5.7.3.2", "clientAuth")]
    [InlineData("1.3.6.1.5.5.7.3.8", "timeStamping")]
    [InlineData("1.3.6.1.4.1.311.10.3.12", "documentSigning")]
    [InlineData("1.2.3.4", "1.2.3.4")]
    public void FormatEku_ReturnsExpected(string oid, string expected) =>
        Formatting.FormatEku(oid).ShouldBe(expected);

    [Theory]
    [InlineData(RevocationSource.EmbeddedCrl, " (embedded DSS CRL — offline)")]
    [InlineData(RevocationSource.OnlineOcsp, " (online OCSP)")]
    [InlineData(RevocationSource.None, "")]
    public void FormatRevocationSource_ReturnsExpected(RevocationSource source, string expected) =>
        Formatting.FormatRevocationSource(source).ShouldBe(expected);

    [Fact]
    public void FormatAlgo_NullReturnsDash() =>
        Formatting.FormatAlgo(null).ShouldBe("—");

    [Fact]
    public void FormatAlgo_WithValues()
    {
        var algo = new AlgorithmInfo { Name = "SHA-256", Oid = "2.16.840.1.101.3.4.2.1" };
        Formatting.FormatAlgo(algo).ShouldBe("SHA-256 (2.16.840.1.101.3.4.2.1)");
    }
}

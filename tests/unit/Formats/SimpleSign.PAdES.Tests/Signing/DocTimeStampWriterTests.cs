using System.Text;
using Shouldly;
using SimpleSign.PAdES.Pdf.Exceptions;
using SimpleSign.PAdES.Signing;
using Xunit;

namespace SimpleSign.PAdES.Tests.Signing;

[Trait("Category", "Unit")]
public sealed class DocTimeStampWriterTests
{
    [Fact(DisplayName = "Null PDF throws ArgumentNullException")]
    public async Task AppendDocTimeStampAsync_NullPdf_ThrowsArgumentNull()
    {
        var act = () => DocTimeStampWriter.AppendDocTimeStampAsync(
            null!, "http://tsa.example.com", new HttpClient());

        var ex = await Should.ThrowAsync<ArgumentNullException>(act);
        ex.ParamName.ShouldBe("signedPdf");
    }

    [Fact(DisplayName = "Null TSA URL throws ArgumentException")]
    public async Task AppendDocTimeStampAsync_NullTsaUrl_ThrowsArgument()
    {
        var act = () => DocTimeStampWriter.AppendDocTimeStampAsync(
            [0x25], null!, new HttpClient());

        var ex2 = await Should.ThrowAsync<ArgumentException>(act);
        ex2.ParamName.ShouldBe("tsaUrl");
    }

    [Fact(DisplayName = "Null HttpClient throws ArgumentNullException")]
    public async Task AppendDocTimeStampAsync_NullHttpClient_ThrowsArgumentNull()
    {
        var act = () => DocTimeStampWriter.AppendDocTimeStampAsync(
            [0x25], "http://tsa.example.com", null!);

        var ex3 = await Should.ThrowAsync<ArgumentNullException>(act);
        ex3.ParamName.ShouldBe("httpClient");
    }

    [Fact(DisplayName = "A document without a catalog is refused before the TSA is asked")]
    public async Task AppendDocTimeStampAsync_NoCatalog_ThrowsPdfStructureException()
    {
        byte[] pdf = Encoding.Latin1.GetBytes("%PDF-1.7\n1 0 obj\n<< /Producer (x) >>\nendobj\ntrailer\n<< /Size 2 >>\n%%EOF\n");

        await Should.ThrowAsync<PdfStructureException>(() => DocTimeStampWriter.AppendDocTimeStampAsync(pdf, "http://tsa.invalid", new HttpClient()));
    }

    [Fact(DisplayName = "Default reserved bytes for timestamp is 12KB")]
    public void DefaultTimestampReservedBytes_Is12KB() => DocTimeStampWriter.DefaultTimestampReservedBytes.ShouldBe(12288);
}

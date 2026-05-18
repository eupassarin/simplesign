using Shouldly;
using SimpleSign.PAdES.Signing;
using Xunit;

namespace SimpleSign.PAdES.Tests.Signing;

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

    [Fact(DisplayName = "Default reserved bytes for timestamp is 12KB")]
    public void DefaultTimestampReservedBytes_Is12KB()
    {
        DocTimeStampWriter.DefaultTimestampReservedBytes.ShouldBe(12288);
    }
}

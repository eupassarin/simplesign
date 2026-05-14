using FluentAssertions;
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

        await act.Should().ThrowAsync<ArgumentNullException>()
            .WithParameterName("signedPdf");
    }

    [Fact(DisplayName = "Null TSA URL throws ArgumentException")]
    public async Task AppendDocTimeStampAsync_NullTsaUrl_ThrowsArgument()
    {
        var act = () => DocTimeStampWriter.AppendDocTimeStampAsync(
            [0x25], null!, new HttpClient());

        await act.Should().ThrowAsync<ArgumentException>()
            .WithParameterName("tsaUrl");
    }

    [Fact(DisplayName = "Null HttpClient throws ArgumentNullException")]
    public async Task AppendDocTimeStampAsync_NullHttpClient_ThrowsArgumentNull()
    {
        var act = () => DocTimeStampWriter.AppendDocTimeStampAsync(
            [0x25], "http://tsa.example.com", null!);

        await act.Should().ThrowAsync<ArgumentNullException>()
            .WithParameterName("httpClient");
    }

    [Fact(DisplayName = "Default reserved bytes for timestamp is 32KB")]
    public void DefaultTimestampReservedBytes_Is32KB()
    {
        DocTimeStampWriter.DefaultTimestampReservedBytes.Should().Be(32768);
    }
}

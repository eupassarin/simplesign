using FluentAssertions;
using SimpleSign.Core.Inspection;
using Xunit;

namespace SimpleSign.Core.Tests.Inspection;

/// <summary>
/// Unit tests for the negative paths of <see cref="TimestampDataExtractor"/>.
/// Building a valid RFC 3161 token in unit tests is impractical; these tests
/// cover the error/empty paths so the catch-all returns <c>null</c> as designed.
/// </summary>
public sealed class TimestampDataExtractorTests
{
    [Fact(DisplayName = "Extract returns null for empty bytes")]
    public void Extract_EmptyBytes_ReturnsNull()
    {
        TimestampDataExtractor.Extract([]).Should().BeNull();
    }

    [Fact(DisplayName = "Extract returns null for garbage bytes")]
    public void Extract_GarbageBytes_ReturnsNull()
    {
        TimestampDataExtractor.Extract([0xFF, 0xFE, 0xFD, 0xFC, 0xFB]).Should().BeNull();
    }

    [Fact(DisplayName = "Extract returns null for ASCII text")]
    public void Extract_AsciiText_ReturnsNull()
    {
        var bytes = "this is definitely not a timestamp token"u8.ToArray();
        TimestampDataExtractor.Extract(bytes).Should().BeNull();
    }

    [Fact(DisplayName = "Extract returns null for malformed ASN.1 sequence")]
    public void Extract_MalformedAsn1_ReturnsNull()
    {
        // 0x30 = SEQUENCE tag, but length byte claims much more than is available
        var bytes = new byte[] { 0x30, 0x82, 0xFF, 0xFF, 0x01 };
        TimestampDataExtractor.Extract(bytes).Should().BeNull();
    }
}

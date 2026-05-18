using System.Text;
using Shouldly;
using SimpleSign.PAdES.Validation;
using Xunit;

namespace SimpleSign.PAdES.Tests.Validation;

/// <summary>
/// Unit tests for <see cref="DssExtractor"/> — pure byte-level parsing of the
/// PDF Document Security Store dictionary. No real PDF needed; we feed crafted
/// byte sequences that mimic the parts of a PDF the extractor cares about.
/// </summary>
public sealed class DssExtractorTests
{
    // ── IndexOfBytes / IndexOfBytesFrom ─────────────────────────────────────

    [Fact(DisplayName = "IndexOfBytes finds first occurrence")]
    public void IndexOfBytes_FoundFirst_ReturnsIndex()
    {
        ReadOnlySpan<byte> haystack = "abcdef"u8;
        ReadOnlySpan<byte> needle = "cd"u8;
        DssExtractor.IndexOfBytes(haystack, needle).ShouldBe(2);
    }

    [Fact(DisplayName = "IndexOfBytes returns -1 when not found")]
    public void IndexOfBytes_NotFound_ReturnsMinusOne()
    {
        ReadOnlySpan<byte> haystack = "abcdef"u8;
        ReadOnlySpan<byte> needle = "xyz"u8;
        DssExtractor.IndexOfBytes(haystack, needle).ShouldBe(-1);
    }

    [Fact(DisplayName = "IndexOfBytes returns -1 when needle longer than haystack")]
    public void IndexOfBytes_NeedleLonger_ReturnsMinusOne()
    {
        ReadOnlySpan<byte> haystack = "ab"u8;
        ReadOnlySpan<byte> needle = "abc"u8;
        DssExtractor.IndexOfBytes(haystack, needle).ShouldBe(-1);
    }

    [Fact(DisplayName = "IndexOfBytesFrom skips earlier occurrences")]
    public void IndexOfBytesFrom_SkipsBefore_ReturnsLater()
    {
        ReadOnlySpan<byte> haystack = "ab cd ab cd"u8;
        ReadOnlySpan<byte> needle = "ab"u8;
        DssExtractor.IndexOfBytesFrom(haystack, needle, 3).ShouldBe(6);
    }

    [Fact(DisplayName = "IndexOfBytesFrom returns -1 with negative offset")]
    public void IndexOfBytesFrom_NegativeOffset_ReturnsMinusOne()
    {
        ReadOnlySpan<byte> haystack = "abc"u8;
        ReadOnlySpan<byte> needle = "a"u8;
        DssExtractor.IndexOfBytesFrom(haystack, needle, -1).ShouldBe(-1);
    }

    [Fact(DisplayName = "IndexOfBytesFrom returns -1 when offset past end")]
    public void IndexOfBytesFrom_OffsetPastEnd_ReturnsMinusOne()
    {
        ReadOnlySpan<byte> haystack = "abc"u8;
        ReadOnlySpan<byte> needle = "a"u8;
        DssExtractor.IndexOfBytesFrom(haystack, needle, 100).ShouldBe(-1);
    }

    // ── ParseObjRefs ────────────────────────────────────────────────────────

    [Fact(DisplayName = "ParseObjRefs returns object numbers from PDF array content")]
    public void ParseObjRefs_ValidArray_ReturnsNumbers()
    {
        var content = Encoding.ASCII.GetBytes("10 0 R 20 0 R 30 0 R");
        var result = DssExtractor.ParseObjRefs(content).ToList();
        result.ShouldBe(new[] { 10, 20, 30 });
    }

    [Fact(DisplayName = "ParseObjRefs ignores garbage tokens")]
    public void ParseObjRefs_WithGarbage_IgnoresGarbage()
    {
        var content = Encoding.ASCII.GetBytes("garbage 5 0 R nonsense 7 0 R end");
        var result = DssExtractor.ParseObjRefs(content).ToList();
        result.ShouldBe(new[] { 5, 7 });
    }

    [Fact(DisplayName = "ParseObjRefs on empty input returns empty")]
    public void ParseObjRefs_Empty_ReturnsEmpty()
    {
        var result = DssExtractor.ParseObjRefs(Array.Empty<byte>()).ToList();
        result.ShouldBeEmpty();
    }

    // ── FindDssDictionary ───────────────────────────────────────────────────

    [Fact(DisplayName = "FindDssDictionary returns null when /DSS marker is missing")]
    public void FindDssDictionary_NoDssKey_ReturnsNull()
    {
        var data = Encoding.ASCII.GetBytes("plain pdf content with no dss");
        DssExtractor.FindDssDictionary(data).ShouldBeNull();
    }

    [Fact(DisplayName = "FindDssDictionary returns null when number is missing after /DSS")]
    public void FindDssDictionary_NoNumberAfterDss_ReturnsNull()
    {
        var data = Encoding.ASCII.GetBytes("/DSS notanumber");
        DssExtractor.FindDssDictionary(data).ShouldBeNull();
    }

    [Fact(DisplayName = "FindDssDictionary returns null when DSS object body cannot be located")]
    public void FindDssDictionary_NumberWithoutObjMarker_ReturnsNull()
    {
        // Reference to /DSS 99 0 R but no `99 0 obj` body in the data
        var data = Encoding.ASCII.GetBytes("/Catalog << /DSS 99 0 R >>");
        DssExtractor.FindDssDictionary(data).ShouldBeNull();
    }

    [Fact(DisplayName = "FindDssDictionary returns dict bytes when DSS object is present")]
    public void FindDssDictionary_WithDssObject_ReturnsDictBytes()
    {
        // A minimal mock: /DSS 5 0 R reference + object body containing a dictionary
        const string body =
            "%PDF-1.7\n" +
            "1 0 obj << /Type /Catalog /DSS 5 0 R >> endobj\n" +
            "5 0 obj << /CRLs [10 0 R] /Certs [20 0 R] >> endobj\n" +
            "%%EOF";
        var data = Encoding.ASCII.GetBytes(body);

        var slice = DssExtractor.FindDssDictionary(data);

        slice.ShouldNotBeNull();
        var sliceText = Encoding.ASCII.GetString(slice!.Value.Span);
        sliceText.ShouldStartWith("<<");
        sliceText.ShouldEndWith(">>");
        sliceText.ShouldContain("/CRLs [10 0 R]");
    }

    // ── TryReadDssDataAsync (entry point) ───────────────────────────────────

    [Fact(DisplayName = "TryReadDssDataAsync returns empty when stream is not a PDF")]
    public async Task TryReadDssDataAsync_NoDss_ReturnsEmpty()
    {
        using var stream = new MemoryStream(Encoding.ASCII.GetBytes("not a pdf"));
        var crls = await DssExtractor.TryReadDssDataAsync(stream, CancellationToken.None);
        crls.ShouldBeEmpty();
    }

    [Fact(DisplayName = "TryReadDssDataAsync extracts CRL bytes from minimal DSS-shaped payload")]
    public async Task TryReadDssDataAsync_WithEmbeddedCrl_ExtractsBytes()
    {
        // Build a minimal byte layout that the extractor can parse:
        //   - reference /DSS 5 0 R
        //   - DSS object 5 with /CRLs [10 0 R]
        //   - CRL stream object 10 with three bytes between "stream\n" and "\nendstream"
        var crlContent = new byte[] { 0xDE, 0xAD, 0xBE };
        var sb = new StringBuilder();
        sb.Append("%PDF-1.7\n");
        sb.Append("1 0 obj << /Type /Catalog /DSS 5 0 R >> endobj\n");
        sb.Append("5 0 obj << /CRLs [10 0 R] >> endobj\n");
        sb.Append("10 0 obj << /Length 3 >>\nstream\n");
        var prefix = Encoding.ASCII.GetBytes(sb.ToString());
        var suffix = Encoding.ASCII.GetBytes("\nendstream\nendobj\n%%EOF");

        var data = new byte[prefix.Length + crlContent.Length + suffix.Length];
        prefix.CopyTo(data, 0);
        crlContent.CopyTo(data, prefix.Length);
        suffix.CopyTo(data, prefix.Length + crlContent.Length);

        using var stream = new MemoryStream(data);
        var crls = await DssExtractor.TryReadDssDataAsync(stream, CancellationToken.None);

        crls.Count().ShouldBe(1);
        crls[0].ShouldBe(crlContent);
    }
}

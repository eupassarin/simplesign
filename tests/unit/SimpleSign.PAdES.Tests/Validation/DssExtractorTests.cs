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
[Trait("Category", "Unit")]
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
        var result = DssExtractor.ParseObjRefs([]).ToList();
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

    [Fact(DisplayName = "FindDssDictionary resolves DSS from the latest catalog revision")]
    public void FindDssDictionary_IncrementalCatalog_UsesActiveDssReference()
    {
        const string body =
            "%PDF-1.7\n" +
            "1 0 obj << /Type /Catalog /DSS 5 0 R >> endobj\n" +
            "5 0 obj << /VRI << /OLD 6 0 R >> >> endobj\n" +
            "1 0 obj << /Type /Catalog /DSS 9 0 R >> endobj\n" +
            "9 0 obj << /VRI << /CURRENT 10 0 R >> >> endobj\n" +
            "trailer << /Root 1 0 R >>\n" +
            "%%EOF";
        var data = Encoding.ASCII.GetBytes(body);

        var slice = DssExtractor.FindDssDictionary(data);

        slice.ShouldNotBeNull();
        string sliceText = Encoding.ASCII.GetString(slice!.Value.Span);
        sliceText.ShouldContain("/CURRENT 10 0 R");
        sliceText.ShouldNotContain("/OLD 6 0 R");
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

        crls.Count().ShouldBe(1, "should extract exactly one CRL");
        crls[0].ShouldBe(crlContent, "extracted bytes must match the original CRL content");
    }

    [Fact(DisplayName = "TryReadDssDataAsync handles CRLF before endstream (PDF EOL variant)")]
    public async Task TryReadDssDataAsync_WithCrLfBeforeEndstream_ExtractsBytes()
    {
        // PDF spec §7.3.8.1 allows both \r\n and \n as the EOL before "endstream".
        // This test verifies the DssExtractor handles the \r\n variant produced by
        // some PDF generators (e.g., Microsoft Print to PDF, Adobe Acrobat).
        var crlContent = new byte[] { 0xCA, 0xFE, 0xBA };
        var sb = new StringBuilder();
        sb.Append("%PDF-1.7\n");
        sb.Append("1 0 obj << /Type /Catalog /DSS 5 0 R >> endobj\n");
        sb.Append("5 0 obj << /CRLs [10 0 R] >> endobj\n");
        sb.Append("10 0 obj << /Length 3 >>\nstream\n");
        var prefix = Encoding.ASCII.GetBytes(sb.ToString());
        // Use \r\n before endstream — this is the variant fixed in upstream commit eedf8a3
        var suffix = Encoding.ASCII.GetBytes("\r\nendstream\nendobj\n%%EOF");

        var data = new byte[prefix.Length + crlContent.Length + suffix.Length];
        prefix.CopyTo(data, 0);
        crlContent.CopyTo(data, prefix.Length);
        suffix.CopyTo(data, prefix.Length + crlContent.Length);

        using var stream = new MemoryStream(data);
        var crls = await DssExtractor.TryReadDssDataAsync(stream, CancellationToken.None);

        crls.Count().ShouldBe(1, "should extract exactly one CRL");
        crls[0].ShouldBe(crlContent, "extracted bytes must match the original CRL content");
    }

    // ── ParseExistingDss (DSS merge support) ────────────────────────────────

    [Fact(DisplayName = "ParseExistingDss returns empty when no DSS present")]
    public void ParseExistingDss_NoDss_ReturnsEmpty()
    {
        var data = Encoding.ASCII.GetBytes("plain pdf without dss");
        var result = DssExtractor.ParseExistingDss(data);
        result.CrlObjRefs.ShouldBeEmpty();
        result.OcspObjRefs.ShouldBeEmpty();
        result.CertObjRefs.ShouldBeEmpty();
        result.VriEntries.ShouldBeEmpty();
    }

    [Fact(DisplayName = "ParseExistingDss extracts CRL, OCSP, and Cert object refs")]
    public void ParseExistingDss_WithArrays_ParsesRefs()
    {
        const string body =
            "%PDF-1.7\n" +
            "1 0 obj << /Type /Catalog /DSS 5 0 R >> endobj\n" +
            "5 0 obj << /CRLs [10 0 R 11 0 R] /OCSPs [20 0 R] /Certs [30 0 R 31 0 R 32 0 R] >> endobj\n" +
            "%%EOF";
        var data = Encoding.ASCII.GetBytes(body);

        var result = DssExtractor.ParseExistingDss(data);

        result.CrlObjRefs.ShouldBe([10, 11]);
        result.OcspObjRefs.ShouldBe([20]);
        result.CertObjRefs.ShouldBe([30, 31, 32]);
    }

    [Fact(DisplayName = "ParseExistingDss extracts VRI entries")]
    public void ParseExistingDss_WithVri_ParsesHashKeys()
    {
        const string body =
            "%PDF-1.7\n" +
            "1 0 obj << /Type /Catalog /DSS 5 0 R >> endobj\n" +
            "5 0 obj << /CRLs [10 0 R] /VRI << /ABCDEF0123456789ABCDEF0123456789ABCDEF01 50 0 R /1234567890ABCDEF1234567890ABCDEF12345678 51 0 R >> >> endobj\n" +
            "%%EOF";
        var data = Encoding.ASCII.GetBytes(body);

        var result = DssExtractor.ParseExistingDss(data);

        result.VriEntries.Count.ShouldBe(2);
        result.VriEntries["ABCDEF0123456789ABCDEF0123456789ABCDEF01"].ShouldBe(50);
        result.VriEntries["1234567890ABCDEF1234567890ABCDEF12345678"].ShouldBe(51);
    }

    // ── TryReadFullDssDataAsync (VRI-aware validation) ──────────────────────

    [Fact(DisplayName = "TryReadFullDssDataAsync returns empty for non-PDF stream")]
    public async Task TryReadFullDssDataAsync_NoDss_ReturnsEmpty()
    {
        using var stream = new MemoryStream(Encoding.ASCII.GetBytes("not a pdf"));
        var result = await DssExtractor.TryReadFullDssDataAsync(stream, CancellationToken.None);
        result.GlobalCrls.ShouldBeEmpty();
        result.GlobalOcsps.ShouldBeEmpty();
        result.GlobalCerts.ShouldBeEmpty();
        result.VriEntries.ShouldBeEmpty();
    }

    [Fact(DisplayName = "TryReadFullDssDataAsync extracts global OCSPs and Certs")]
    public async Task TryReadFullDssDataAsync_WithOcspsAndCerts_ExtractsAll()
    {
        var ocspContent = new byte[] { 0x30, 0x03, 0x0A, 0x01, 0x00 };
        var certContent = new byte[] { 0x30, 0x82, 0x01, 0x00 };

        var sb = new StringBuilder();
        sb.Append("%PDF-1.7\n");
        sb.Append("1 0 obj << /Type /Catalog /DSS 5 0 R >> endobj\n");
        sb.Append("5 0 obj << /OCSPs [10 0 R] /Certs [11 0 R] >> endobj\n");
        sb.Append($"10 0 obj << /Length {ocspContent.Length} >>\nstream\n");
        var prefix1 = Encoding.ASCII.GetBytes(sb.ToString());
        var mid1 = Encoding.ASCII.GetBytes($"\nendstream\nendobj\n11 0 obj << /Length {certContent.Length} >>\nstream\n");
        var suffix = Encoding.ASCII.GetBytes("\nendstream\nendobj\n%%EOF");

        var data = new byte[prefix1.Length + ocspContent.Length + mid1.Length + certContent.Length + suffix.Length];
        int pos = 0;
        prefix1.CopyTo(data, pos);
        pos += prefix1.Length;
        ocspContent.CopyTo(data, pos);
        pos += ocspContent.Length;
        mid1.CopyTo(data, pos);
        pos += mid1.Length;
        certContent.CopyTo(data, pos);
        pos += certContent.Length;
        suffix.CopyTo(data, pos);

        using var stream = new MemoryStream(data);
        var result = await DssExtractor.TryReadFullDssDataAsync(stream, CancellationToken.None);

        result.GlobalOcsps.Count.ShouldBe(1);
        result.GlobalOcsps[0].ShouldBe(ocspContent);
        result.GlobalCerts.Count.ShouldBe(1);
        result.GlobalCerts[0].ShouldBe(certContent);
    }
}

using FluentAssertions;
using SimpleSign.Integration.Tests.Helpers;
using SimpleSign.Pdf;
using SimpleSign.Pdf.Exceptions;
using Xunit;
using Xunit.Abstractions;

namespace SimpleSign.Integration.Tests;

public sealed class PdfParsingTests(ITestOutputHelper output)
{
    [SkippableFact(DisplayName = "Unsigned PDF should return no fields")]
    public async Task UnsignedPdf_ReturnsNoFields()
    {
        const string fixture = "empty-page-unsigned.pdf";
        Skip.IfNot(FixturePath.Exists(fixture), $"Fixture {fixture} not found");

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        using var stream = FixturePath.Open(fixture);
        var fields = await PdfStructureReader.ReadSignatureFieldsAsync(stream, cancellationToken: cts.Token);

        fields.Should().BeEmpty();
    }

    [SkippableFact(DisplayName = "Malformed PDF should throw InvalidDataException")]
    public async Task MalformedPdf_ThrowsInvalidDataException()
    {
        const string fixture = "malformed-pades.pdf";
        Skip.IfNot(FixturePath.Exists(fixture), $"Fixture {fixture} not found");

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        using var stream = FixturePath.Open(fixture);

        var act = () => PdfStructureReader.ReadSignatureFieldsAsync(stream, cancellationToken: cts.Token);
        await act.Should().ThrowAsync<PdfStructureException>();
    }

    [SkippableFact(DisplayName = "PAdES-BES PDF should return a single signed field")]
    public async Task PadesBesPdf_ReturnsSingleSignedField()
    {
        const string fixture = "pades-bes.pdf";
        Skip.IfNot(FixturePath.Exists(fixture), $"Fixture {fixture} not found");

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        using var stream = FixturePath.Open(fixture);
        var fields = await PdfStructureReader.ReadSignatureFieldsAsync(stream, cancellationToken: cts.Token);

        fields.Should().HaveCount(1);
        var field = fields[0];
        field.IsSigned.Should().BeTrue();
        field.SubFilter.Should().Be("ETSI.CAdES.detached");
        field.ByteRange.Should().NotBeNull();
        field.ByteRange!.IsValid.Should().BeTrue();
        output.WriteLine($"Field: {field.FieldName}, SubFilter: {field.SubFilter}");
    }

    [SkippableFact(DisplayName = "PKCS7 detached PDF should return signature field")]
    public async Task Pkcs7DetachedPdf_ReturnsField()
    {
        const string fixture = "dss-2025.pdf";
        Skip.IfNot(FixturePath.Exists(fixture), $"Fixture {fixture} not found");

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        using var stream = FixturePath.Open(fixture);
        var fields = await PdfStructureReader.ReadSignatureFieldsAsync(stream, cancellationToken: cts.Token);

        fields.Should().HaveCountGreaterThanOrEqualTo(1);
        fields.Should().Contain(f => f.SubFilter == "adbe.pkcs7.detached");
    }

    [SkippableFact(DisplayName = "Multi-signature PDF should return all fields")]
    public async Task MultiSignaturePdf_ReturnsAllFields()
    {
        const string fixture = "pades-5sigs-1ts.pdf";
        Skip.IfNot(FixturePath.Exists(fixture), $"Fixture {fixture} not found");

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        using var stream = FixturePath.Open(fixture);
        var fields = await PdfStructureReader.ReadSignatureFieldsAsync(stream, cancellationToken: cts.Token);

        fields.Should().HaveCount(6);
        fields.Should().OnlyContain(f => f.IsSigned);
        output.WriteLine($"Fields: {string.Join(", ", fields.Select(f => f.FieldName ?? "(none)"))}");
    }

    [SkippableFact(DisplayName = "Legacy SHA-1 PDF should return fields correctly")]
    public async Task LegacySha1Pdf_ReturnsFields()
    {
        const string fixture = "wrong-digest-algo.pdf";
        Skip.IfNot(FixturePath.Exists(fixture), $"Fixture {fixture} not found");

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        using var stream = FixturePath.Open(fixture);
        var fields = await PdfStructureReader.ReadSignatureFieldsAsync(stream, cancellationToken: cts.Token);

        fields.Should().HaveCount(4);
        fields[0].SubFilter.Should().Be("adbe.pkcs7.sha1");
    }

    [SkippableTheory(DisplayName = "All fixtures should parse without hanging")]
    [InlineData("AD-RB.pdf")]
    [InlineData("bad-encoded-cms.pdf")]
    [InlineData("dss-1683.pdf")]
    [InlineData("dss-2025.pdf")]
    [InlineData("dss-2821.pdf")]
    [InlineData("dss-3226.pdf")]
    [InlineData("empty-page-unsigned.pdf")]
    [InlineData("pades-5sigs-1ts.pdf")]
    [InlineData("pades-bes.pdf")]
    [InlineData("pades-bes-no-certs.pdf")]
    [InlineData("pades-cross-cert-ocsp.pdf")]
    [InlineData("pades-lt.pdf")]
    [InlineData("test-with-vri.pdf")]
    [InlineData("timestamped-and-signed.pdf")]
    [InlineData("wrong-digest-algo.pdf")]
    [InlineData("pades-lta.pdf")]
    [InlineData("doc-firmado-T.pdf")]
    [InlineData("doc-firmado-B.pdf")]
    [InlineData("pades-epes.pdf")]
    [InlineData("sha512-lta.pdf")]
    [InlineData("modified-after-sig.pdf")]
    [InlineData("incremental-multi-sign.pdf")]
    [InlineData("incremental-edited.pdf")]
    [InlineData("double-signed.pdf")]
    [InlineData("pades-ltv-reason.pdf")]
    [InlineData("pades-ltv-full.pdf")]
    [InlineData("51sigs.pdf")]
    [InlineData("dss-1443.pdf")]
    [InlineData("dss-3567.pdf")]
    [InlineData("belgian-multi-ocsp.pdf")]
    [InlineData("pades-enveloping-cms.pdf")]
    [InlineData("adbe-crl-signed.pdf")]
    [InlineData("adbe-ocsp-signed.pdf")]
    [InlineData("pades-ecdsa.pdf")]
    public async Task AllFixtures_ParseWithoutHanging(string fixture)
    {
        Skip.IfNot(FixturePath.Exists(fixture), $"Fixture {fixture} not found");

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        using var stream = FixturePath.Open(fixture);
        var fields = await PdfStructureReader.ReadSignatureFieldsAsync(stream, cancellationToken: cts.Token);

        fields.Should().NotBeNull();
        output.WriteLine($"{fixture}: {fields.Count} field(s)");
    }
}

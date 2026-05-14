using FluentAssertions;
using SimpleSign.Integration.Tests.Helpers;
using SimpleSign.Pdf;
using Xunit;
using Xunit.Abstractions;

namespace SimpleSign.Integration.Tests;

public sealed class IncrementalUpdateTests(ITestOutputHelper output)
{
    [SkippableFact(DisplayName = "PDF with incremental multi-sign should have at least 2 signatures")]
    public async Task IncrementalMultiSign_HasAtLeastTwoSignatures()
    {
        const string fixture = "incremental-multi-sign.pdf";
        Skip.IfNot(FixturePath.Exists(fixture), $"Fixture {fixture} not found");

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        using var stream = FixturePath.Open(fixture);
        var fields = await PdfStructureReader.ReadSignatureFieldsAsync(stream, cancellationToken: cts.Token);

        fields.Should().HaveCountGreaterThanOrEqualTo(2, "Incremental PDF should have at least 2 signatures");
        fields.Should().OnlyContain(f => f.IsSigned);
        output.WriteLine($"Fields: {string.Join(", ", fields.Select(f => f.FieldName ?? "(none)"))}");
    }

    [SkippableFact(DisplayName = "PDF edited after second incremental signature should parse")]
    public async Task IncrementalEdited_ParsesSuccessfully()
    {
        const string fixture = "incremental-edited.pdf";
        Skip.IfNot(FixturePath.Exists(fixture), $"Fixture {fixture} not found");

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        using var stream = FixturePath.Open(fixture);
        var fields = await PdfStructureReader.ReadSignatureFieldsAsync(stream, cancellationToken: cts.Token);

        fields.Should().NotBeNull();
        output.WriteLine($"Fields: {fields.Count}");
        foreach (var f in fields)
            output.WriteLine($"  {f.FieldName}: Signed={f.IsSigned}, SubFilter={f.SubFilter ?? "(none)"}");
    }

    [SkippableFact(DisplayName = "Double-signed PDF should parse both signatures")]
    public async Task DoubleSigned_BothSignaturesParsed()
    {
        const string fixture = "double-signed.pdf";
        Skip.IfNot(FixturePath.Exists(fixture), $"Fixture {fixture} not found");

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        using var stream = FixturePath.Open(fixture);
        var fields = await PdfStructureReader.ReadSignatureFieldsAsync(stream, cancellationToken: cts.Token);

        fields.Should().HaveCountGreaterThanOrEqualTo(2, "Double-signed PDF should have at least 2 fields");
        fields.Should().OnlyContain(f => f.IsSigned);
        output.WriteLine($"Fields: {string.Join(", ", fields.Select(f => f.FieldName ?? "(none)"))}");
    }

    [SkippableFact(DisplayName = "PDF with 51 signatures should parse all without hanging")]
    public async Task FiftyOneSignatures_AllParsedWithoutHanging()
    {
        const string fixture = "51sigs.pdf";
        Skip.IfNot(FixturePath.Exists(fixture), $"Fixture {fixture} not found");

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        using var stream = FixturePath.Open(fixture);
        var fields = await PdfStructureReader.ReadSignatureFieldsAsync(stream, cancellationToken: cts.Token);

        fields.Should().HaveCountGreaterThanOrEqualTo(51, "PDF with 51 signatures should return at least 51 fields");
        output.WriteLine($"Total fields: {fields.Count}");
    }
}

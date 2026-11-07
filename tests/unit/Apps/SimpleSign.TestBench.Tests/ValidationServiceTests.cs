using Shouldly;
using SimpleSign.TestBench.Sandbox;
using SimpleSign.TestBench.Validation;

namespace SimpleSign.TestBench.Tests;

/// <summary>Each validation sample gets the verdict and the failing check it was built for.</summary>
[Collection(TestBenchCollection.Name)]
[Trait("Category", "Unit")]
public sealed class ValidationServiceTests(TestBenchFixture fixture)
{
    [Theory]
    [InlineData("valid")]
    [InlineData("tampered-content")]
    [InlineData("tampered-cms")]
    [InlineData("appended")]
    [InlineData("revoked")]
    [InlineData("expired")]
    [InlineData("untrusted-root")]
    [InlineData("untrusted-tsa")]
    public async Task ReportAsync_Sample_MatchesItsExpectedResult(string id)
    {
        var sample = fixture.ValidationSamples.Single(s => s.Id == id);

        var report = await fixture.Validation.ReportAsync(sample.FileId, new ValidationSettings(), default);

        report.Error.ShouldBeNull();
        var signature = report.Signatures.ShouldHaveSingleItem();
        signature.Report.Indication.ShouldBe(sample.ExpectedIndication);
        switch (sample.ExpectedCheck)
        {
            case "coverage":
                signature.Coverage!.CoversWholeFile.ShouldBeFalse();
                signature.Report.Errors.ShouldContain(e => e.Contains("ByteRange", StringComparison.Ordinal));
                break;
            case "timestamp":
                signature.Report.Checks.Single(c => c.Id == "timestamp").Detail.ShouldNotBeNull();
                signature.Report.Warnings.ShouldContain(w => w.Contains("TSA", StringComparison.Ordinal));
                break;
            case "—":
                signature.Report.Checks.ShouldAllBe(c => c.Status == "pass");
                break;
            default:
                signature.Report.Checks.Single(c => c.Id == sample.ExpectedCheck).Status.ShouldBe("fail");
                break;
        }
    }

    [Fact]
    public async Task ReportAsync_ValidControl_HasLevelsCertificatesAndDss()
    {
        var sample = fixture.ValidationSamples.Single(s => s.Id == "valid");

        var report = await fixture.Validation.ReportAsync(sample.FileId, new ValidationSettings(), default);

        report.Overall.ShouldBe("Valid");
        var signature = report.Signatures.Single();
        signature.PadesLevel.ShouldBe("BaselineLT");
        signature.Signer!.Subject.ShouldContain("Maria da Silva");
        signature.Timestamp.ShouldNotBeNull();
        signature.Coverage!.Revisions.ShouldBeGreaterThan(1);
        report.Dss!.Crls.ShouldBeGreaterThan(0);
        report.Code.CSharp.ShouldContain("PdfSignatureValidator");
    }

    [Fact]
    public async Task ReportAsync_SandboxRootNotTrusted_IsIndeterminate()
    {
        var sample = fixture.ValidationSamples.Single(s => s.Id == "valid");

        var report = await fixture.Validation.ReportAsync(sample.FileId, new ValidationSettings { Trust = [], CheckRevocation = false }, default);

        report.Signatures.Single().Report.Indication.ShouldNotBe("Valid");
    }

    [Fact]
    public async Task ReportAsync_CustomRootUpload_TrustsIt()
    {
        var sample = fixture.ValidationSamples.Single(s => s.Id == "valid");
        string rootId = fixture.Documents.Add("root.cer", fixture.Sandbox.Pki.Root.RawData).Id;

        var report = await fixture.Validation.ReportAsync(sample.FileId, new ValidationSettings { Trust = [], CustomRootUploadIds = [rootId] }, default);

        report.Overall.ShouldBe("Valid");
        report.Code.Cli.ShouldContain("--trust root.cer");
    }

    [Fact]
    public async Task BulkAsync_AllSamples_ReportsEachFile()
    {
        var inspection = new InspectionService(fixture.Validation, fixture.Documents);

        var report = await inspection.BulkAsync(new BulkRequest([.. fixture.ValidationSamples.Select(s => s.FileId)], new ValidationSettings(), 3), default);

        report.Items.Count.ShouldBe(fixture.ValidationSamples.Count);
        report.Items.Count(i => i.Overall == "Valid").ShouldBe(fixture.ValidationSamples.Count(s => s.ExpectedIndication == "Valid"));
        report.Items.ShouldAllBe(i => i.Error == null);
    }

    [Fact]
    public async Task InspectAsync_BltSample_ListsSignatureDictionaryAndDss()
    {
        var inspection = new InspectionService(fixture.Validation, fixture.Documents);
        var sample = fixture.ValidationSamples.Single(s => s.Id == "valid");

        var report = await inspection.InspectAsync(sample.FileId, default);

        report.Error.ShouldBeNull();
        report.SignatureFields.ShouldBe(["Assinatura"]);
        report.Objects.ShouldContain(o => o.Entries.Any(e => e.Key == "/ByteRange"));
        report.Objects.ShouldContain(o => o.Label.Contains("DSS", StringComparison.OrdinalIgnoreCase));
        (await inspection.CmsAsync(sample.FileId, "Assinatura", default)).ShouldNotBeNull();
    }

    [Fact]
    public void For_RealMode_TrustsSystemRoots() =>
        ValidationSettings.For(EnvironmentMode.Real).Trust.ShouldBe([TrustChoice.System]);
}

using System.Text.Json;
using Shouldly;
using SimpleSign.TestBench.Cades;
using SimpleSign.TestBench.CrossValidation;
using SimpleSign.TestBench.Runs;
using SimpleSign.TestBench.Signing;
using SimpleSign.TestBench.Xml;

namespace SimpleSign.TestBench.Tests;

/// <summary>A run signs in any of the three formats and returns the verdicts and the library log, grouped by stage.</summary>
[Collection(TestBenchCollection.Name)]
[Trait("Category", "Unit")]
public sealed class RunServiceTests(TestBenchFixture fixture)
{
    private static RunRequest Request<T>(string format, T options, bool crossValidate = false) =>
        new(format, JsonSerializer.SerializeToElement(options, WorkbenchJson.Options), crossValidate);

    private RunRequest Pades(BaselineLevel level) => Request(RunFormats.Pades, fixture.Options() with { Level = level });

    private RunRequest Cades(BaselineLevel level) => Request(RunFormats.Cades, new CadesOptions
    {
        DataId = fixture.CadesSamples.Single(s => s.Id == "text").FileId,
        CredentialId = fixture.Sandboxed(),
        Level = level,
    });

    private RunRequest Xades(BaselineLevel level) => Request(RunFormats.Xades, new XmlOptions
    {
        DataId = fixture.XmlSamples.Single(s => s.Id == "order").FileId,
        CredentialId = fixture.Sandboxed(),
        Level = level,
    });

    private static string Problems(RunView run) =>
        string.Join("; ", run.Issues.Select(i => i.Message).Concat(run.Validation.SelectMany(v => v.Errors)).Append(run.Error ?? ""));

    [Theory]
    [InlineData(RunFormats.Pades)]
    [InlineData(RunFormats.Cades)]
    [InlineData(RunFormats.Xades)]
    public async Task RunAsync_Archive_IsValidAndLogsEveryStage(string format)
    {
        var request = format switch
        {
            RunFormats.Cades => Cades(BaselineLevel.BLTA),
            RunFormats.Xades => Xades(BaselineLevel.BLTA),
            _ => Pades(BaselineLevel.BLTA),
        };

        var run = await fixture.Runs().RunAsync(request, default);

        run.Success.ShouldBeTrue(Problems(run));
        run.Status.ShouldBe("done");
        run.Format.ShouldBe(format);
        run.Overall.ShouldBe("Valid", Problems(run));
        run.Validation.ShouldNotBeEmpty();
        run.OutputId.ShouldNotBeNull();
        run.Code!.CSharp.ShouldNotBeNullOrWhiteSpace();
        var stages = run.Logs.Select(l => l.Stage).Distinct().ToList();
        string[] expected =
        [
            RunStages.Prepare, RunStages.Digest, RunStages.SignedAttributes, RunStages.Signature, RunStages.Timestamp,
            RunStages.ValidationData, RunStages.Archive, RunStages.Finish, RunStages.Validation, RunStages.Network,
        ];
        foreach (string stage in expected)
        {
            stages.ShouldContain(stage, $"{format}: {string.Join(", ", stages)}");
        }

        run.Logs.Select(l => l.Seq).ShouldBe(Enumerable.Range(0, run.Logs.Count));
        run.Logs.ShouldContain(l => l.Source == "network" && l.Message.StartsWith("TSA:", StringComparison.Ordinal));
    }

    [Fact]
    public async Task RunAsync_Basic_LogsNoTimestampStage()
    {
        var run = await fixture.Runs().RunAsync(Cades(BaselineLevel.BB), default);

        run.Success.ShouldBeTrue(Problems(run));
        run.Logs.ShouldNotContain(l => l.Stage == RunStages.Timestamp);
        run.Logs.ShouldNotContain(l => l.Stage == RunStages.Archive);
    }

    [Fact]
    public async Task RunAsync_TwoRunsAtOnce_KeepTheirLogsApart()
    {
        var service = fixture.Runs();
        var first = service.RunAsync(Request(RunFormats.Cades, new CadesOptions
        {
            DataId = fixture.CadesSamples.Single(s => s.Id == "text").FileId,
            CredentialId = fixture.Sandboxed(),
            OperationId = "first-run",
        }), default);
        var second = service.RunAsync(Request(RunFormats.Xades, new XmlOptions
        {
            DataId = fixture.XmlSamples.Single(s => s.Id == "order").FileId,
            CredentialId = fixture.Sandboxed(),
            OperationId = "second-run",
        }), default);

        var runs = await Task.WhenAll(first, second);

        runs[0].Logs.ShouldContain(l => l.Message.Contains("[first-run]", StringComparison.Ordinal));
        runs[0].Logs.ShouldNotContain(l => l.Message.Contains("[second-run]", StringComparison.Ordinal));
        runs[1].Logs.ShouldContain(l => l.Message.Contains("[second-run]", StringComparison.Ordinal));
        runs[1].Logs.ShouldNotContain(l => l.Message.Contains("[first-run]", StringComparison.Ordinal));
    }

    [Fact]
    public async Task RunAsync_IncompatibleOptions_FailsWithTheIssues()
    {
        var run = await fixture.Runs().RunAsync(Request(RunFormats.Pades, new SigningOptions()), default);

        run.Success.ShouldBeFalse();
        run.Status.ShouldBe("failed");
        run.Issues.ShouldContain(i => i.Severity == IssueSeverity.Error);
    }

    [Fact]
    public void Start_UnknownFormat_Throws() =>
        Should.Throw<ArgumentException>(() => fixture.Runs().Start(new RunRequest("jades", JsonSerializer.SerializeToElement(new { }))));

    [Fact]
    public async Task RunAsync_Finished_IsInTheHistoryAndCanBeReplayed()
    {
        var service = fixture.Runs();

        var view = await service.RunAsync(Cades(BaselineLevel.BT), default);

        service.History().ShouldContain(h => h.Id == view.Id && h.Status == "done" && h.Format == RunFormats.Cades);
        var (events, _) = service.Find(view.Id)!.Read(0);
        events.Count(e => e.Type == "log").ShouldBe(view.Logs.Count);
        events[^1].Run!.Id.ShouldBe(view.Id);
    }

    [Fact]
    public async Task RunAsync_CrossValidateWithDssDown_StillSucceedsAndSaysWhy()
    {
        var service = fixture.Runs(new DssSettings(true, "http://127.0.0.1:9"));

        var run = await service.RunAsync(Cades(BaselineLevel.BB) with { CrossValidate = true }, default);

        run.Success.ShouldBeTrue(Problems(run));
        var dss = run.CrossValidation.ShouldBeOfType<DssComparison>();
        dss.Available.ShouldBeFalse();
        dss.Error.ShouldNotBeNullOrWhiteSpace();
        run.Logs.ShouldContain(l => l.Stage == RunStages.CrossValidation && l.Level == "Warning");
    }
}

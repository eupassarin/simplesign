using System.Text.Json;
using Shouldly;
using SimpleSign.Signers.Cloud.Psc;
using SimpleSign.TestBench.Cades;
using SimpleSign.TestBench.Credentials;
using SimpleSign.TestBench.CrossValidation;
using SimpleSign.TestBench.Runs;
using SimpleSign.TestBench.Sandbox;
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

    private static RunRequest Validate(string fileId, string? dataId = null) =>
        new("", JsonSerializer.SerializeToElement(new ValidateOptions(fileId, dataId), WorkbenchJson.Options), Kind: RunKinds.Validate);

    [Fact]
    public async Task RunAsync_ValidatePdfSamples_DetectsPadesAndGivesTheExpectedVerdict()
    {
        fixture.ValidationSamples.ShouldNotBeEmpty();
        foreach (var sample in fixture.ValidationSamples)
        {
            var run = await fixture.Runs().RunAsync(Validate(sample.FileId), default);

            run.Kind.ShouldBe(RunKinds.Validate);
            run.Format.ShouldBe(RunFormats.Pades, sample.Id);
            run.Overall.ShouldBe(sample.ExpectedIndication, sample.Id);
            run.OutputId.ShouldBe(sample.FileId);
            run.Logs.ShouldContain(l => l.Stage == RunStages.Validation, sample.Id);
            run.Code!.CSharp.ShouldNotBeNullOrWhiteSpace();
        }
    }

    [Fact]
    public async Task RunAsync_ValidateCadesSamples_DetectsCadesAndGivesTheExpectedVerdict()
    {
        var samples = fixture.CadesSamples.Where(s => s.Kind != "data" && s.ExpectedIndication is not null).ToList();
        samples.ShouldNotBeEmpty();
        foreach (var sample in samples)
        {
            var run = await fixture.Runs().RunAsync(Validate(sample.FileId, sample.DataId), default);

            run.Format.ShouldBe(RunFormats.Cades, sample.Id);
            run.Overall.ShouldBe(sample.ExpectedIndication, sample.Id);
            run.Detail.ShouldBeOfType<CadesValidationView>();
        }
    }

    [Fact]
    public async Task RunAsync_ValidateXmlSamples_DetectsXmlAndGivesTheExpectedVerdict()
    {
        var samples = fixture.XmlSamples.Where(s => s.Kind == "validation" && s.ExpectedIndication is not null).ToList();
        samples.ShouldNotBeEmpty();
        foreach (var sample in samples)
        {
            var run = await fixture.Runs().RunAsync(Validate(sample.FileId, sample.DataId), default);

            run.Format.ShouldBe(RunFormats.Xades, sample.Id);
            run.Overall.ShouldBe(sample.ExpectedIndication, sample.Id);
            run.Detail.ShouldBeOfType<XmlValidationView>();
        }
    }

    [Fact]
    public async Task RunAsync_ValidateAFileJustSigned_IsValidAndIsInTheHistoryAsAValidation()
    {
        var service = fixture.Runs();
        var signed = await service.RunAsync(Xades(BaselineLevel.BT), default);

        var run = await service.RunAsync(Validate(signed.OutputId!), default);

        run.Overall.ShouldBe("Valid", Problems(run));
        run.AchievedLevel.ShouldNotBeNull();
        service.History().ShouldContain(h => h.Id == run.Id && h.Kind == RunKinds.Validate);
        service.History().ShouldContain(h => h.Id == signed.Id && h.Kind == RunKinds.Sign);
    }

    [Fact]
    public async Task RunAsync_SimulatedPsc_SignsThroughTheProviderAndShowsItInTheLog()
    {
        var handle = fixture.Credentials.Add(await fixture.Factory.OpenPscPasswordAsync(
            new PscCredentialRequest(null, null, null, null, SandboxPsc.Otp, PscScope.SignatureSession, "maria-rsa2048"), EnvironmentMode.Sandbox, default));

        var run = await fixture.Runs().RunAsync(Request(RunFormats.Pades, fixture.Options() with { CredentialId = handle.Id, Level = BaselineLevel.BT }), default);

        run.Success.ShouldBeTrue(Problems(run));
        run.Overall.ShouldBe("Valid", Problems(run));
        // The hash goes to the provider (network), and the cloud signer reports it (events 731x).
        run.Logs.ShouldContain(l => l.Source == "network" && l.Message.StartsWith("PSC:", StringComparison.Ordinal));
        run.Logs.ShouldContain(l => l.EventId == 7311 && l.Stage == RunStages.Signature);
        run.Logs.ShouldContain(l => l.EventId == 7312);
    }

    [Fact]
    public async Task RunAsync_SimulatedCsc_AuthorizesTheCredentialAndShowsItInTheLog()
    {
        var handle = fixture.Credentials.Add(await fixture.Factory.OpenCscAsync(
            new CscCredentialRequest(null, CscServiceAuth.ClientCredentials, null, null, null, "rsa-scal2", CscAuthorizerKind.Explicit, SandboxCsc.Pin, SandboxCsc.Otp),
            EnvironmentMode.Sandbox, default));

        var run = await fixture.Runs().RunAsync(Request(RunFormats.Cades, new CadesOptions
        {
            DataId = fixture.CadesSamples.Single(s => s.Id == "text").FileId,
            CredentialId = handle.Id,
            Level = BaselineLevel.BT,
        }), default);

        run.Success.ShouldBeTrue(Problems(run));
        run.Overall.ShouldBe("Valid", Problems(run));
        run.Logs.ShouldContain(l => l.Source == "network" && l.Message.StartsWith("CSC:", StringComparison.Ordinal) && l.Message.Contains("signatures/signHash", StringComparison.Ordinal));
        run.Logs.ShouldContain(l => l.EventId == 7301);
        run.Logs.ShouldContain(l => l.EventId == 7303 && l.Stage == RunStages.Signature);
        run.Logs.ShouldAllBe(l => !l.Message.Contains(SandboxCsc.Otp, StringComparison.Ordinal));
    }

    [Fact]
    public void Real_ListsBundledRootsAndPublicTsas()
    {
        var real = SimpleSign.TestBench.Endpoints.EnvironmentApi.Real();

        real.BundledRoots.ShouldContain(r => r.Source == "ICP-Brasil");
        real.PublicTsas.Select(t => t.Name).ShouldBe(["DigiCert", "Sectigo", "FreeTSA"]);
        real.PublicTsas.ShouldAllBe(t => t.Url.StartsWith("http", StringComparison.Ordinal));
    }

    [Fact]
    public void Start_ValidateWithoutAFile_Throws() =>
        Should.Throw<ArgumentException>(() => fixture.Runs().Start(Validate("no-such-file")));

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

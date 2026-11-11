using System.Text.Json;
using Shouldly;
using SimpleSign.TestBench.Cades;
using SimpleSign.TestBench.Credentials;
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

    [SkippableTheory]
    [InlineData(RunFormats.Pades, "sign")]
    [InlineData(RunFormats.Pades, "deferred")]
    [InlineData(RunFormats.Pades, "batch")]
    [InlineData(RunFormats.Cades, "sign")]
    [InlineData(RunFormats.Xades, "sign")]
    public async Task RunAsync_CliEngine_SignsThroughTheCliLikeTheLibrary(string format, string mode)
    {
        var library = format switch
        {
            RunFormats.Cades => Cades(BaselineLevel.BLT),
            RunFormats.Xades => Xades(BaselineLevel.BLT),
            _ => Request(RunFormats.Pades, fixture.Options() with
            {
                Level = BaselineLevel.BLT,
                Mode = mode switch { "deferred" => RunMode.Deferred, "batch" => RunMode.Batch, _ => RunMode.Sign },
                BatchCopies = 2,
            }),
        };

        var expected = await fixture.Runs().RunAsync(library, default);
        var run = await fixture.Runs().RunAsync(library with { Engine = RunEngines.Cli }, default);

        expected.Success.ShouldBeTrue(Problems(expected));
        run.Success.ShouldBeTrue(Problems(run) + "\n" + string.Join("\n", (run.Cli ?? []).Select(c => $"{c.Command}\n{c.Output}")));
        run.Engine.ShouldBe(RunEngines.Cli);
        run.Cli.ShouldNotBeNull().ShouldNotBeEmpty();
        run.Cli!.ShouldAllBe(c => c.ExitCode == 0);
        run.Cli!.ShouldContain(c => c.Command.Contains(" validate ", StringComparison.Ordinal), "signed through the CLI, validated through it too");
        run.Cli!.ShouldAllBe(c => !c.Command.Contains(fixture.Sandbox.Connection.Info.PfxPassword, StringComparison.Ordinal));
        run.Overall.ShouldBe(expected.Overall, Problems(run));
        run.Validation.Select(v => v.Indication).ShouldBe(expected.Validation.Select(v => v.Indication));
        run.AchievedLevel.ShouldBe(expected.AchievedLevel);
    }

    [SkippableFact]
    public async Task RunAsync_CliEngine_DrawsTheSameStampAsTheLibrary()
    {
        var library = Request(RunFormats.Pades, fixture.Options() with
        {
            Reason = "Contrato",
            Appearance = new AppearanceChoice
            {
                Visible = true,
                Page = 1,
                X = 90,
                Y = 110,
                Width = 230,
                Height = 80,
                VerticalAlignment = "Middle",
                ShowReason = false,
                ExtraLines = ["CRM 12345"],
                TextColor = "#202060",
                BorderColor = "#000000",
                Culture = "pt-BR",
            },
        });

        var expected = await fixture.Runs().RunAsync(library, default);
        var run = await fixture.Runs().RunAsync(library with { Engine = RunEngines.Cli }, default);

        expected.Success.ShouldBeTrue(Problems(expected));
        run.Success.ShouldBeTrue(Problems(run) + "\n" + string.Join("\n", (run.Cli ?? []).Select(c => $"{c.Command}\n{c.Output}")));
        run.Cli!.First().Command.ShouldContain("--hide-reason");
        fixture.Documents.TryGet(run.OutputId!, out var cliOutput).ShouldBeTrue();
        fixture.Documents.TryGet(expected.OutputId!, out var libraryOutput).ShouldBeTrue();
        StampPreviewService.Rect(cliOutput!.Content, "Signature1").ShouldBe(StampPreviewService.Rect(libraryOutput!.Content, "Signature1"));
        StampPreviewService.Rect(cliOutput.Content, "Signature1").ShouldBe([90, 110, 230, 80]);
    }

    [Fact]
    public void Start_UnknownEngine_Throws()
    {
        var request = new RunRequest(RunFormats.Pades, JsonSerializer.SerializeToElement(new SigningOptions(), WorkbenchJson.Options), Engine: "python");

        Should.Throw<ArgumentException>(() => fixture.Runs().Start(request));
    }

    [SkippableTheory]
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

    [SkippableFact]
    public async Task RunAsync_Basic_LogsNoTimestampStage()
    {
        var run = await fixture.Runs().RunAsync(Cades(BaselineLevel.BB), default);

        run.Success.ShouldBeTrue(Problems(run));
        run.Logs.ShouldNotContain(l => l.Stage == RunStages.Timestamp);
        run.Logs.ShouldNotContain(l => l.Stage == RunStages.Archive);
    }

    [SkippableFact]
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

    [SkippableFact]
    public async Task RunAsync_IncompatibleOptions_FailsWithTheIssues()
    {
        var run = await fixture.Runs().RunAsync(Request(RunFormats.Pades, new SigningOptions()), default);

        run.Success.ShouldBeFalse();
        run.Status.ShouldBe("failed");
        run.Issues.ShouldContain(i => i.Severity == IssueSeverity.Error);
    }

    private static RunRequest Validate(string fileId, string? dataId = null) =>
        new("", JsonSerializer.SerializeToElement(new ValidateOptions(fileId, dataId), WorkbenchJson.Options), Kind: RunKinds.Validate);

    [SkippableFact]
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

    [SkippableFact]
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

    [SkippableFact]
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

    [SkippableTheory]
    [InlineData(RunFormats.Pades)]
    [InlineData(RunFormats.Cades)]
    [InlineData(RunFormats.Xades)]
    public async Task RunAsync_ValidateThroughTheCli_GivesTheLibrarysVerdicts(string format)
    {
        List<(string Id, string FileId, string? DataId)> samples = format switch
        {
            RunFormats.Cades => [.. fixture.CadesSamples.Where(s => s.Kind != "data" && s.ExpectedIndication is not null).Select(s => (s.Id, s.FileId, s.DataId))],
            RunFormats.Xades => [.. fixture.XmlSamples.Where(s => s.Kind == "validation" && s.ExpectedIndication is not null).Select(s => (s.Id, s.FileId, s.DataId))],
            _ => [.. fixture.ValidationSamples.Select(s => (s.Id, s.FileId, (string?)null))],
        };
        samples.ShouldNotBeEmpty();
        foreach (var (id, fileId, dataId) in samples)
        {
            var expected = await fixture.Runs().RunAsync(Validate(fileId, dataId), default);
            var run = await fixture.Runs().RunAsync(Validate(fileId, dataId) with { Engine = RunEngines.Cli }, default);

            string commands = string.Join("\n", (run.Cli ?? []).Select(c => $"{c.Command} → {c.ExitCode}\n{c.Output}"));
            run.Engine.ShouldBe(RunEngines.Cli, id);
            run.Success.ShouldBe(expected.Success, $"{id}: {Problems(run)}\n{commands}");
            run.Overall.ShouldBe(expected.Overall, $"{id}: {Problems(run)}\n{commands}");
            run.Validation.Select(v => (v.Indication, v.SubIndication)).ShouldBe(expected.Validation.Select(v => (v.Indication, v.SubIndication)), $"{id}\n{commands}");
            if (expected.Validation.Count > 0)
            {
                run.Cli.ShouldNotBeNull(id).ShouldHaveSingleItem(id).Command.ShouldContain("validate", Case.Sensitive, id);
                run.ReportId.ShouldNotBeNull(id);
                run.EtsiReportId.ShouldNotBeNull(id);
            }
        }
    }

    [SkippableFact]
    public async Task RunAsync_ValidateCadesWithACountersignature_StoresSimpleSignsReportWithEverySignature()
    {
        var sample = fixture.CadesSamples.Single(s => s.Id == "v-tree");

        var run = await fixture.Runs().RunAsync(Validate(sample.FileId, sample.DataId), default);

        run.ReportId.ShouldNotBeNull();
        var report = SimpleSign.TestBench.Reports.ReportReader.Read(System.Text.Encoding.UTF8.GetString(fixture.Documents.Get(run.ReportId).Content)).ShouldNotBeNull();
        report.Source.ShouldBe("simplesign");
        report.Signatures.Select(s => s.Id).ShouldBe(["signer-1", "signer-1.1", "signer-2"]);
        report.Signatures.Select(s => s.Kind).ShouldBe(["signature", "counterSignature", "signature"]);
        report.Signatures.ShouldAllBe(s => s.Indication == "Valid" && s.Chain.Count == 3 && s.Constraints.Count > 0);
        run.Validation.Select(v => v.EtsiIndication).ShouldAllBe(e => e == "TOTAL_PASSED");
    }

    [SkippableFact]
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

    [SkippableFact]
    public async Task RunAsync_SimulatedCsc_AuthorizesTheCredentialAndShowsItInTheLog()
    {
        fixture.RequireSandbox();
        var csc = fixture.Sandbox.Connection.Info.Csc;
        var handle = fixture.Credentials.Add(await fixture.Factory.OpenCscAsync(
            new CscCredentialRequest(null, CscServiceAuth.ClientCredentials, null, null, null, "rsa-scal2", CscAuthorizerKind.Explicit, csc.Pin, csc.Otp), default));

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
        run.Logs.ShouldAllBe(l => !l.Message.Contains(csc.Otp, StringComparison.Ordinal));
    }

    [SkippableFact]
    public void Real_ListsPublicTsas()
    {
        var real = SimpleSign.TestBench.Endpoints.EnvironmentApi.Real();

        real.PublicTsas.Select(t => t.Name).ShouldBe(["DigiCert", "Sectigo", "FreeTSA"]);
        real.PublicTsas.ShouldAllBe(t => t.Url.StartsWith("http", StringComparison.Ordinal));
    }

    [SkippableFact]
    public void Start_ValidateWithoutAFile_Throws() =>
        Should.Throw<ArgumentException>(() => fixture.Runs().Start(Validate("no-such-file")));

    [SkippableFact]
    public void Start_UnknownFormat_Throws() =>
        Should.Throw<ArgumentException>(() => fixture.Runs().Start(new RunRequest("jades", JsonSerializer.SerializeToElement(new { }))));

    [SkippableFact]
    public async Task RunAsync_Finished_IsInTheHistoryAndCanBeReplayed()
    {
        var service = fixture.Runs();

        var view = await service.RunAsync(Cades(BaselineLevel.BT), default);

        service.History().ShouldContain(h => h.Id == view.Id && h.Status == "done" && h.Format == RunFormats.Cades);
        var (events, _) = service.Find(view.Id)!.Read(0);
        events.Count(e => e.Type == "log").ShouldBe(view.Logs.Count);
        events[^1].Run!.Id.ShouldBe(view.Id);
    }

    [SkippableFact]
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

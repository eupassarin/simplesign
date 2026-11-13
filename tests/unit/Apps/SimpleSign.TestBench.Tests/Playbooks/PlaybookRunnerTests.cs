using System.IO.Compression;
using Shouldly;
using SimpleSign.TestBench.Playbooks;

namespace SimpleSign.TestBench.Tests.Playbooks;

/// <summary>Playbooks run against the Sandbox: results kept per step, the preview of a step, the evidence.</summary>
[Collection(TestBenchCollection.Name)]
[Trait("Category", "Unit")]
public sealed class PlaybookRunnerTests(TestBenchFixture fixture)
{
    private const string Small = """
        {
          "schema": 2, "id": "demo", "title": "Demo",
          "defaults": { "engine": "both", "options": { "common": { "level": "BB" } } },
          "sections": [
            { "id": "s1", "title": "Revocation", "steps": [
              { "id": "good", "title": "Good", "tags": ["R2", "signing"],
                "options": { "documentId": "sample:contract", "credentialId": "sandbox:rsa-2048" }, "expect": { "outcome": "signed", "level": "B-B" } },
              { "id": "revoked", "title": "Revoked now", "tags": ["R1"], "sandbox": { "revoke": ["rsa-2048"] },
                "options": { "documentId": "sample:contract", "credentialId": "sandbox:rsa-2048", "signingPolicyId": "preset:signing:iofe",
                             "signingControls": { "trust": ["SandboxRoot"] } },
                "expect": { "outcome": "refused", "reason": "CertificateRevoked" } },
              { "id": "check", "title": "Validate", "kind": "validate", "engine": "library", "tags": ["R2"],
                "options": { "fileId": "step:good" }, "expect": { "outcome": "valid" } }
            ] }
          ]
        }
        """;

    private PlaybookRunner Runner(bool samples = false, Runs.RunService? runs = null) => samples
        ? new PlaybookRunner(runs ?? fixture.Runs(), fixture.Sandbox, fixture.Documents, fixture.Credentials, fixture.Factory,
            fixture.Runner, fixture.Cades, fixture.Xml, fixture.Validation,
            new Cades.CadesSampleStore { Samples = fixture.CadesSamples }, new Xml.XmlSampleStore { Samples = fixture.XmlSamples },
            new Validation.ValidationSampleStore { Samples = fixture.ValidationSamples })
        : new PlaybookRunner(runs ?? fixture.Runs(), fixture.Sandbox, fixture.Documents, fixture.Credentials, fixture.Factory,
            fixture.Runner, fixture.Cades, fixture.Xml, fixture.Validation);

    private static string Failures(PlaybookStateView view) => string.Join("; ", view.Steps.Where(s => s.Status != PlaybookStatuses.Passed).Select(s =>
        $"{s.StepId}: {s.Status} {s.Result?.Message} " + string.Join(", ", (s.Result?.Runs ?? []).SelectMany(r => r.Checks).Where(c => !c.Passed)
            .Select(c => $"{c.What} {c.Expected}≠{c.Found}")) + " " + string.Join(" | ", (s.Result?.Runs ?? []).Where(r => r.Error is not null)
            .Select(r => $"{r.Engine}: {r.ErrorType} {r.Error}"))));

    [SkippableTheory]
    [InlineData("sandbox-basics")]
    [InlineData("indecopi-guia-v4")]
    [InlineData("etsi-baseline")]
    [InlineData("icp-brasil-pades")]
    [InlineData("govbr-pades")]
    public async Task RunToEnd_Sample_PassesEveryStep(string sample)
    {
        fixture.RequireSandbox();
        using var runner = Runner(samples: true);
        runner.Load(PlaybookSamples.Json(sample)!).CanRun.ShouldBeTrue();

        var view = await runner.RunToEndAsync(new PlaybookRunRequest()).WaitAsync(TimeSpan.FromMinutes(15));

        view.Steps.ShouldAllBe(s => s.Status == PlaybookStatuses.Passed, Failures(view));
    }

    [SkippableFact]
    public async Task RunToEnd_OneStep_KeepsTheOtherResults()
    {
        fixture.RequireSandbox();
        var runs = fixture.Runs();
        using var runner = Runner(runs: runs);
        runner.Load(Small).CanRun.ShouldBeTrue();

        var all = await runner.RunToEndAsync(new PlaybookRunRequest()).WaitAsync(TimeSpan.FromMinutes(3));
        all.Steps.ShouldAllBe(s => s.Status == PlaybookStatuses.Passed, Failures(all));
        var firstGood = all.Steps.Single(s => s.StepId == "good").Result!;
        firstGood.Runs.Select(r => r.Engine).ShouldBe(["library", "cli"]);

        var again = await runner.RunToEndAsync(new PlaybookRunRequest(StepId: "revoked", Engine: "library")).WaitAsync(TimeSpan.FromMinutes(3));

        again.Steps.Single(s => s.StepId == "good").Result.ShouldBe(firstGood);
        again.Steps.Single(s => s.StepId == "revoked").Result!.Runs.Select(r => r.Engine).ShouldBe(["library"]);
        again.Steps.ShouldAllBe(s => s.Status == PlaybookStatuses.Passed, Failures(again));

        // Loading the same file keeps the results; the validation step alone uses the file "good" signed.
        runner.Load(Small);
        var check = await runner.RunToEndAsync(new PlaybookRunRequest(StepId: "check")).WaitAsync(TimeSpan.FromMinutes(3));
        check.Steps.Single(s => s.StepId == "check").Status.ShouldBe(PlaybookStatuses.Passed, Failures(check));
        check.Steps.Single(s => s.StepId == "good").Result.ShouldBe(firstGood);

        string html = PlaybookEvidence.Html(runner.Session!, fixture.Documents);
        html.ShouldContain("By tag");
        html.ShouldContain(">R1<");
        using var zip = new ZipArchive(new MemoryStream(PlaybookEvidence.Zip(runner.Session!, fixture.Documents, runs)));
        zip.GetEntry("evidence.html").ShouldNotBeNull();
        zip.GetEntry("playbook.json").ShouldNotBeNull();
        zip.Entries.ShouldContain(e => e.FullName.StartsWith("steps/good/cli/", StringComparison.Ordinal) && e.FullName.EndsWith(".pdf", StringComparison.Ordinal));

        // Another file starts with no result.
        runner.Load(Small.Replace("\"Demo\"", "\"Demo 2\"", StringComparison.Ordinal));
        runner.State().Steps.ShouldAllBe(s => s.Result == null);
    }

    [SkippableFact]
    public async Task Clear_OneStep_KeepsTheOthersAndItsDependentsNeedItAgain()
    {
        fixture.RequireSandbox();
        using var runner = Runner();
        runner.Load(Small);
        await runner.RunToEndAsync(new PlaybookRunRequest(StepId: "good", Engine: "library")).WaitAsync(TimeSpan.FromMinutes(2));
        var check = await runner.RunToEndAsync(new PlaybookRunRequest(StepId: "check")).WaitAsync(TimeSpan.FromMinutes(2));
        var checkResult = check.Steps.Single(s => s.StepId == "check").Result.ShouldNotBeNull();

        var view = runner.Clear("good");

        view.Steps.Single(s => s.StepId == "good").Status.ShouldBe(PlaybookStatuses.Pending);
        view.Steps.Single(s => s.StepId == "good").Result.ShouldBeNull();
        view.Steps.Single(s => s.StepId == "check").Result.ShouldBe(checkResult);
        var again = await runner.RunToEndAsync(new PlaybookRunRequest(StepId: "check")).WaitAsync(TimeSpan.FromMinutes(1));
        again.Steps.Single(s => s.StepId == "check").Result!.Message.ShouldNotBeNull().ShouldContain("good");
    }

    [SkippableFact]
    public async Task Clear_All_LeavesEveryStepPending()
    {
        fixture.RequireSandbox();
        using var runner = Runner();
        runner.Load(Small);
        await runner.RunToEndAsync(new PlaybookRunRequest(StepId: "good", Engine: "library")).WaitAsync(TimeSpan.FromMinutes(2));

        var view = runner.Clear(null);

        view.Steps.ShouldAllBe(s => s.Status == PlaybookStatuses.Pending && s.Result == null);
    }

    [SkippableFact]
    public async Task Clear_WhileRunning_Throws()
    {
        fixture.RequireSandbox();
        using var runner = Runner();
        runner.Load(Small);

        var run = runner.Start(new PlaybookRunRequest(StepId: "good", Engine: "library"));

        Should.Throw<InvalidOperationException>(() => runner.Clear(null));
        await run.WaitAsync(TimeSpan.FromMinutes(2));
        runner.Clear(null).Steps.ShouldAllBe(s => s.Result == null);
    }

    [Fact]
    public void Clear_UnknownStepOrNoPlaybook_Throws()
    {
        using var runner = Runner();
        Should.Throw<KeyNotFoundException>(() => runner.Clear(null));
        runner.Load(Small);
        Should.Throw<KeyNotFoundException>(() => runner.Clear("nope"));
    }

    [SkippableFact]
    public async Task RunToEnd_ValidationBeforeItsStep_SaysToRunItFirst()
    {
        fixture.RequireSandbox();
        using var runner = Runner();
        runner.Load(Small);

        var view = await runner.RunToEndAsync(new PlaybookRunRequest(StepId: "check")).WaitAsync(TimeSpan.FromMinutes(1));

        var step = view.Steps.Single(s => s.StepId == "check");
        step.Status.ShouldBe(PlaybookStatuses.Failed);
        step.Result!.Message.ShouldNotBeNull().ShouldContain("good");
    }

    [SkippableFact]
    public async Task PreviewAsync_SignStep_ShowsSignerSettingsSandboxAndBothCommands()
    {
        fixture.RequireSandbox();
        var runs = fixture.Runs();
        using var runner = Runner(runs: runs);
        runner.Load(Small);

        var preview = await runner.PreviewAsync("revoked", engine: null, CancellationToken.None);

        preview.Kind.ShouldBe("sign");
        preview.Engine.ShouldBe("both");
        preview.CrossValidate.ShouldBeFalse();
        preview.CrossValidateFrom.ShouldBe("defaults");
        preview.Target.ShouldContain(t => t.Key == "document");
        preview.Signer.ShouldContain(s => s.Key == "playbook" && s.Value == "sandbox:rsa-2048");
        preview.Signer.ShouldContain(s => s.Key == "subject");
        preview.Groups.ShouldNotBeEmpty();
        preview.Groups.SelectMany(g => g.Settings).ShouldContain(s => s.FromPlaybook && s.Changed);
        preview.Sandbox.ShouldBe([new PreviewItem("revoke", "Revoke", "rsa-2048")]);
        preview.Expect.ShouldContain(e => e.Key == "reason" && e.Value == "CertificateRevoked");
        preview.Code.ShouldNotBeNull();
        preview.Code!.CSharp.ShouldContain("PadesSigner");
        preview.Code.Cli.ShouldContain("simplesign");
        runs.History().ShouldBeEmpty("a preview signs nothing");
    }

    [SkippableFact]
    public async Task PreviewAsync_ValidationOfAStepNotRun_SaysWhichStep()
    {
        fixture.RequireSandbox();
        using var runner = Runner();
        runner.Load(Small);

        var preview = await runner.PreviewAsync("check", engine: null, CancellationToken.None);

        preview.Kind.ShouldBe("validate");
        preview.NeedsSteps.ShouldBe(["good"]);
        preview.Code.ShouldNotBeNull();
    }
}

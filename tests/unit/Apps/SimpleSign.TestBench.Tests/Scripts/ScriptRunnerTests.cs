using System.IO.Compression;
using Shouldly;
using SimpleSign.TestBench.Scripts;

namespace SimpleSign.TestBench.Tests.Scripts;

/// <summary>A small script run end to end against the Sandbox, through both engines.</summary>
[Collection(TestBenchCollection.Name)]
[Trait("Category", "Unit")]
public sealed class ScriptRunnerTests(TestBenchFixture fixture)
{
    private const string Script = """
        {
          "schema": 1, "id": "demo", "title": "Demo", "language": "es",
          "defaults": { "engine": "both", "options": { "common": { "level": "BB" } } },
          "requirements": [
            { "id": "R1", "text": "Refuse a revoked certificate." },
            { "id": "R2", "text": "Show the signature." },
            { "id": "R3", "text": "Manuals.", "applies": true },
            { "id": "R4", "text": "Keys in a module.", "applies": false, "justification": "The library holds no key." }
          ],
          "sections": [
            { "id": "s1", "title": "Revocation", "steps": [
              { "id": "good", "title": "Good", "requirements": ["R2"],
                "options": { "documentId": "sample:contract", "credentialId": "sandbox:rsa-2048" }, "expect": { "outcome": "signed", "level": "B-B" } },
              { "id": "revoked", "title": "Revoked now", "requirements": ["R1"], "sandbox": { "revoke": ["rsa-2048"] },
                "options": { "documentId": "sample:contract", "credentialId": "sandbox:rsa-2048", "signingPolicyId": "preset:signing:iofe",
                             "signingControls": { "trust": ["SandboxRoot"] } },
                "expect": { "outcome": "refused", "reason": "CertificateRevoked" } },
              { "id": "check", "title": "Validate", "kind": "validate", "engine": "library", "requirements": ["R2"],
                "options": { "fileId": "step:good" }, "expect": { "outcome": "valid" } },
              { "id": "hand", "title": "Manuals", "kind": "manual", "requirements": ["R3"], "manual": { "instructions": "Show the manuals." } }
            ] }
          ]
        }
        """;

    [SkippableTheory]
    [InlineData("sandbox-basics")]
    [InlineData("indecopi-guia-v4")]
    public async Task Run_Sample_PassesEveryAutomatedStep(string sample)
    {
        fixture.RequireSandbox();
        var runner = new ScriptRunner(fixture.Runs(), fixture.Sandbox, fixture.Documents, fixture.Credentials, fixture.Factory,
            new Cades.CadesSampleStore { Samples = fixture.CadesSamples }, new Xml.XmlSampleStore { Samples = fixture.XmlSamples },
            new Validation.ValidationSampleStore { Samples = fixture.ValidationSamples });
        runner.Load(ScriptSamples.Json(sample)!).CanRun.ShouldBeTrue();

        var run = runner.Start(new ScriptRunRequest());
        var deadline = DateTime.UtcNow.AddMinutes(15);
        while (!run.IsFinished && DateTime.UtcNow < deadline)
        {
            if (run.View().WaitingFor is { } manual)
            {
                runner.Decide(run.Id, manual, new ScriptDecision(true, "Checked by the test."));
            }

            await Task.Delay(100);
        }

        var failed = run.View().Steps.Where(s => s.Status != ScriptStatuses.Passed).ToList();
        failed.ShouldBeEmpty(string.Join("; ", failed.Select(s => $"{s.StepId}: {s.Status} {s.Message} "
            + string.Join(", ", s.Runs.SelectMany(r => r.Checks).Where(c => !c.Passed).Select(c => $"{c.What} {c.Expected}≠{c.Found}")))));
    }

    [SkippableFact]
    public async Task Run_SmallScript_PassesEveryStepAndWritesTheEvidence()
    {
        fixture.RequireSandbox();
        var runner = new ScriptRunner(fixture.Runs(), fixture.Sandbox, fixture.Documents, fixture.Credentials, fixture.Factory);
        runner.Load(Script).CanRun.ShouldBeTrue();

        var run = runner.Start(new ScriptRunRequest());
        for (int i = 0; i < 600 && run.View().WaitingFor is null && !run.IsFinished; i++)
        {
            await Task.Delay(100);
        }

        run.View().WaitingFor.ShouldBe("hand");
        var attachment = fixture.Documents.Add("manual.txt", "the manuals"u8.ToArray());
        runner.Decide(run.Id, "hand", new ScriptDecision(true, "Shown to the auditor.", [attachment.Id]));
        await run.Completion.WaitAsync(TimeSpan.FromMinutes(3));
        var view = run.View();

        view.Steps.ShouldAllBe(s => s.Status == ScriptStatuses.Passed,
            string.Join("; ", view.Steps.Select(s => $"{s.StepId}: {s.Status} {s.Message} " + string.Join(", ", s.Runs.SelectMany(r => r.Checks).Where(c => !c.Passed).Select(c => $"{c.What} {c.Expected}≠{c.Found}")))));
        view.Steps.Single(s => s.StepId == "good").Runs.Select(r => r.Engine).ShouldBe(["library", "cli"]);
        view.Requirements.Single(r => r.Id == "R4").Status.ShouldBe(ScriptStatuses.NotApplicable);
        view.Requirements.Where(r => r.Applies).ShouldAllBe(r => r.Status == ScriptStatuses.Passed);

        string html = ScriptEvidence.Html(run, fixture.Documents);
        html.ShouldContain("lang=\"es\"");
        html.ShouldContain("Matriz de requisitos y evidencias");
        using var zip = new ZipArchive(new MemoryStream(ScriptEvidence.Zip(run, fixture.Documents, fixture.Runs())));
        zip.GetEntry("evidence.html").ShouldNotBeNull();
        zip.GetEntry("steps/hand/manual/manual.txt").ShouldNotBeNull();
        zip.Entries.ShouldContain(e => e.FullName.StartsWith("steps/good/cli/", StringComparison.Ordinal) && e.FullName.EndsWith(".pdf", StringComparison.Ordinal));
    }
}

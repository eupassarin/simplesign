using System.ComponentModel;
using System.Text.Json;
using Shouldly;
using SimpleSign.Playbook.Model;
using SimpleSign.Playbook.Runs;
using SimpleSign.Playbook.Workspaces;

namespace SimpleSign.Playbook.Tests;

[Trait("Category", "Unit")]
public sealed class PlaybookRunnerTests : IDisposable
{
    private readonly string _folder = Path.Combine(Path.GetTempPath(), "simplesign-playbook-" + Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        if (Directory.Exists(_folder))
        {
            Directory.Delete(_folder, recursive: true);
        }
    }

    private Workspace NewWorkspace(PlaybookDefinition playbook)
    {
        var workspace = Workspace.Create(_folder, playbook.Name);
        workspace.SavePlaybookText(JsonSerializer.Serialize(playbook, PlaybookJson.Default.PlaybookDefinition));
        return workspace;
    }

    private static PlaybookDefinition OneStep(StepDefinition step, bool sandbox = true) => new()
    {
        Name = "test",
        Sandbox = sandbox ? new SandboxSettings() : null,
        Sections = [new SectionDefinition { Id = "a", Title = "A", Steps = [step] }],
    };

    private static async Task<(RunRecord Run, FakeProcessRunner Cli, List<string> Calls, FakeSandbox Sandbox)> RunAsync(
        Workspace workspace, PlaybookDefinition playbook, Func<ProcessCommand, ProcessResult>? answer = null,
        IReadOnlyCollection<string>? selection = null, IRunObserver? observer = null, CancellationToken cancellationToken = default)
    {
        var calls = new List<string>();
        var cli = new FakeProcessRunner(answer);
        var sandbox = new FakeSandbox(calls);
        var runner = new PlaybookRunner(new CallRecorder(cli, calls), _ => sandbox);
        var run = await runner.RunAsync(workspace, playbook, ("simplesign", []), selection, observer ?? new RecordingObserver(), cancellationToken);
        return (run, cli, calls, sandbox);
    }

    /// <summary>Puts the CLI's calls in the same list as the Sandbox's, to check the order.</summary>
    private sealed class CallRecorder(FakeProcessRunner inner, List<string> calls) : IProcessRunner
    {
        public Task<ProcessResult> RunAsync(ProcessCommand command, Action<bool, string>? onLine, CancellationToken cancellationToken)
        {
            calls.Add("cli " + command.Arguments.FirstOrDefault());
            return inner.RunAsync(command, onLine, cancellationToken);
        }
    }

    [Fact]
    public async Task RunAsync_Step_SetupRunCheckTeardownInOrder()
    {
        var playbook = OneStep(new StepDefinition
        {
            Id = "s",
            Title = "sign",
            Setup = [new SandboxAction { Sandbox = "faults", Crl = "Stale" }, new SandboxAction { Sandbox = "certificate", Id = "revoked-ocsp" }],
            Run = new RunDefinition { Args = ["sign", "--cert", "${cert.path}", "--password", "${cert.password}"] },
            Expect = new Expectation { Json = new() { ["success"] = JsonDocument.Parse("true").RootElement.Clone() } },
            Teardown = [new SandboxAction { Sandbox = "reset" }],
        });
        var workspace = NewWorkspace(playbook);

        var (run, cli, calls, _) = await RunAsync(workspace, playbook);

        calls.ShouldBe(["sandbox reset", "cli version", "sandbox faults", "sandbox certificate", "cli sign", "sandbox reset"]);
        run.Status.ShouldBe(RunStatus.Passed, run.Error);
        var step = run.Steps.Single();
        step.Status.ShouldBe(RunStatus.Passed);
        step.Actions.ShouldContain(a => a.Contains("faults crl=Stale", StringComparison.Ordinal));
        var command = cli.Commands.Last();
        command.Arguments[2].ShouldEndWith(Path.Combine("steps", "s", "cert.pfx"));
        command.Arguments[4].ShouldBe("sandbox");
        File.ReadAllBytes(command.Arguments[2]).ShouldBe([1, 2, 3]);
    }

    [Fact]
    public async Task RunAsync_WithSandbox_AddsTheNetworkOptions()
    {
        var playbook = OneStep(new StepDefinition { Id = "s", Title = "t", Run = new RunDefinition { Args = ["sign", "a.pdf"] } });
        var (_, cli, _, _) = await RunAsync(NewWorkspace(playbook), playbook);

        var args = cli.Commands.Last().Arguments;
        args.ShouldContain("--allow-ldap");
        args.Where((a, i) => i > 0 && args[i - 1] == "--allow-origin").ShouldBe(["http://localhost:5300", "ldap://localhost:5302"]);
        args[args.ToList().IndexOf("--tls-trust") + 1].ShouldEndWith("sandbox-chain.pem");
    }

    [Fact]
    public async Task RunAsync_NetworkNone_KeepsTheArgumentsAsWritten()
    {
        var playbook = OneStep(new StepDefinition { Id = "s", Title = "t", Run = new RunDefinition { Args = ["version"], Network = "none" } });
        var (_, cli, _, _) = await RunAsync(NewWorkspace(playbook), playbook);

        cli.Commands.Last().Arguments.ShouldBe(["version"]);
    }

    [Fact]
    public async Task RunAsync_FailedCheck_FailsTheStepAndTheRun()
    {
        var playbook = OneStep(new StepDefinition
        {
            Id = "s",
            Title = "t",
            Run = new RunDefinition { Args = ["sign"] },
            Expect = new Expectation { Json = new() { ["error.reason"] = JsonDocument.Parse("\"CertificateRevoked\"").RootElement.Clone() } },
        });
        var (run, _, _, _) = await RunAsync(NewWorkspace(playbook), playbook,
            _ => new ProcessResult(255, """{ "success": false, "error": { "reason": "KeyTooWeak" } }""", "", false, 1));

        run.Status.ShouldBe(RunStatus.Failed);
        var check = run.Steps.Single().Checks.Single();
        check.Passed.ShouldBeFalse();
        check.Actual.ShouldBe("\"KeyTooWeak\"");
    }

    [Fact]
    public async Task RunAsync_NoExpectation_ExpectsExitZero()
    {
        var playbook = OneStep(new StepDefinition { Id = "s", Title = "t", Run = new RunDefinition { Args = ["sign"] } }, sandbox: false);
        var (run, _, _, _) = await RunAsync(NewWorkspace(playbook), playbook, _ => new ProcessResult(1, "", "boom", false, 1));

        run.Steps.Single().Status.ShouldBe(RunStatus.Failed);
    }

    [Fact]
    public async Task RunAsync_SandboxRequestsOfTheStep_AreChecked()
    {
        var playbook = OneStep(new StepDefinition
        {
            Id = "s",
            Title = "t",
            Run = new RunDefinition { Args = ["sign"] },
            Expect = new Expectation { SandboxRequests = [new SandboxRequestExpectation { Service = "OCSP" }] },
        });
        var workspace = NewWorkspace(playbook);
        var calls = new List<string>();
        var sandbox = new FakeSandbox(calls);
        sandbox.Log.Add(new SandboxRequestRecord(1, DateTimeOffset.UtcNow, "POST", "/ocsp/old", 200, "OCSP", null, 1));
        var cli = new FakeProcessRunner(_ =>
        {
            sandbox.Log.Add(new SandboxRequestRecord(2, DateTimeOffset.UtcNow, "GET", "/crl/x.crl", 200, "CRL", null, 1));
            return new ProcessResult(0, "", "", false, 1);
        });

        var run = await new PlaybookRunner(cli, _ => sandbox).RunAsync(workspace, playbook, ("simplesign", []), null, new RecordingObserver(), default);

        // Only the CRL request was made during the step: the OCSP one came before.
        var step = run.Steps.Single();
        step.SandboxRequests.ShouldHaveSingleItem().Service.ShouldBe("CRL");
        step.Status.ShouldBe(RunStatus.Failed);
    }

    [Fact]
    public async Task RunAsync_ManualStep_TakesTheOperatorsDecision()
    {
        var playbook = OneStep(new StepDefinition { Id = "m", Title = "look", Manual = true }, sandbox: false);
        var observer = new RecordingObserver { Decision = new ManualDecision(RunStatus.Failed, "the panel says unknown signer") };

        var (run, _, _, _) = await RunAsync(NewWorkspace(playbook), playbook, observer: observer);

        observer.Waiting.ShouldBe(["m"]);
        var step = run.Steps.Single();
        step.Status.ShouldBe(RunStatus.Failed);
        step.Note.ShouldBe("the panel says unknown signer");
    }

    [Fact]
    public async Task RunAsync_FileAttachedWhileWaiting_IsAnAttachment()
    {
        var playbook = OneStep(new StepDefinition { Id = "m", Title = "look", Manual = true }, sandbox: false);
        var workspace = NewWorkspace(playbook);
        var observer = new AttachingObserver(workspace);

        var (run, _, _, _) = await RunAsync(workspace, playbook, observer: observer);

        var step = run.Steps.Single();
        step.Attachments.ShouldBe(["steps/m/attachments/panel.png"]);
        step.Files.ShouldBeEmpty();
        RunStore.Load(Path.Combine(workspace.RunsPath, run.Id))!.Steps.Single().Attachments.ShouldHaveSingleItem();
        File.ReadAllText(Path.Combine(workspace.RunsPath, run.Id, "report.html")).ShouldContain("steps/m/attachments/panel.png");
    }

    /// <summary>Attaches a file the way the API does, while the step waits, then passes it.</summary>
    private sealed class AttachingObserver(Workspace workspace) : IRunObserver
    {
        private string? _runId;

        public void RunChanged(RunRecord run) => _runId = run.Id;

        public void StepChanged(RunRecord run, StepRecord step)
        {
        }

        public void OutputLine(StepRecord step, bool isError, string text)
        {
        }

        public Task<ManualDecision> WaitForDecisionAsync(StepRecord step, CancellationToken cancellationToken)
        {
            RunService.Attach(workspace, _runId!, step.StepId, "panel.png", [1, 2, 3]);
            return Task.FromResult(new ManualDecision(RunStatus.Passed, null));
        }
    }

    [Fact]
    public async Task RunAsync_Selection_SkipsTheOthers()
    {
        var playbook = new PlaybookDefinition
        {
            Name = "two",
            Sections = [new SectionDefinition { Id = "a", Title = "A", Steps =
            [
                new StepDefinition { Id = "one", Title = "1", Run = new RunDefinition { Args = ["sign"] } },
                new StepDefinition { Id = "two", Title = "2", Run = new RunDefinition { Args = ["validate"] } },
            ] }],
        };
        var (run, cli, _, _) = await RunAsync(NewWorkspace(playbook), playbook, selection: ["two"]);

        run.Steps.Select(s => s.Status).ShouldBe([RunStatus.Skipped, RunStatus.Passed]);
        cli.Commands.Select(c => c.Arguments[0]).ShouldBe(["version", "validate"]);
    }

    [Fact]
    public async Task RunAsync_UnknownVariable_IsAnErrorOfTheStep()
    {
        var playbook = OneStep(new StepDefinition { Id = "s", Title = "t", Run = new RunDefinition { Args = ["sign", "${nope}"] } }, sandbox: false);
        var (run, _, _, _) = await RunAsync(NewWorkspace(playbook), playbook);

        var step = run.Steps.Single();
        step.Status.ShouldBe(RunStatus.Error);
        step.Error!.ShouldContain("nope");
    }

    [Fact]
    public async Task RunAsync_CliMissing_StopsTheRunWithTheReason()
    {
        var playbook = OneStep(new StepDefinition { Id = "s", Title = "t", Run = new RunDefinition { Args = ["sign"] } }, sandbox: false);
        var workspace = NewWorkspace(playbook);
        var cli = new FakeProcessRunner { Before = (_, _) => throw new Win32Exception("No such file") };

        var run = await new PlaybookRunner(cli, _ => throw new InvalidOperationException()).RunAsync(
            workspace, playbook, ("missing-cli", []), null, new RecordingObserver(), default);

        run.Status.ShouldBe(RunStatus.Error);
        run.Error!.ShouldContain("missing-cli");
        run.Steps.Single().Status.ShouldBe(RunStatus.Skipped);
    }

    [Fact]
    public async Task RunAsync_Cancelled_MarksTheRest()
    {
        var playbook = OneStep(new StepDefinition { Id = "s", Title = "t", Run = new RunDefinition { Args = ["sign"] } }, sandbox: false);
        var workspace = NewWorkspace(playbook);
        using var cancellation = new CancellationTokenSource();
        var cli = new FakeProcessRunner
        {
            Before = (command, ct) =>
            {
                if (command.Arguments[0] == "sign")
                {
                    cancellation.Cancel();
                    ct.ThrowIfCancellationRequested();
                }

                return Task.CompletedTask;
            },
        };

        var run = await new PlaybookRunner(cli, _ => throw new InvalidOperationException()).RunAsync(
            workspace, playbook, ("simplesign", []), null, new RecordingObserver(), cancellation.Token);

        run.Status.ShouldBe(RunStatus.Cancelled);
        run.Steps.Single().Status.ShouldBe(RunStatus.Cancelled);
    }

    [Fact]
    public async Task RunAsync_Finished_WritesTheRunFolder()
    {
        var playbook = OneStep(new StepDefinition { Id = "s", Title = "Sign it", Run = new RunDefinition { Args = ["sign"] } });
        var workspace = NewWorkspace(playbook);

        var (run, _, _, _) = await RunAsync(workspace, playbook, _ => new ProcessResult(0, "signed\n", "", false, 1));

        string folder = Path.Combine(workspace.RunsPath, run.Id);
        RunStore.Load(folder).ShouldNotBeNull().Steps.Single().Status.ShouldBe(RunStatus.Passed);
        File.ReadAllText(Path.Combine(folder, "steps", "s", "stdout.txt")).ShouldBe("signed\n");
        File.ReadAllText(Path.Combine(folder, "steps", "s", "command.txt")).ShouldStartWith("simplesign sign");
        File.ReadAllText(Path.Combine(folder, "report.md")).ShouldContain("Sign it");
        File.ReadAllText(Path.Combine(folder, "report.html")).ShouldContain("<h1>test</h1>");
        RunStore.List(workspace.RunsPath).ShouldHaveSingleItem().Summary.Passed.ShouldBe(1);
        run.CliVersion.ShouldBe("simplesign 9.9.9");
        run.Sandbox!.Name.ShouldBe("fake");
    }

    [Theory]
    [InlineData("simple", "simple")]
    [InlineData("two words", "'two words'")]
    [InlineData("it's", "'it'\\''s'")]
    [InlineData("--allow-origin=http://localhost:5300", "--allow-origin=http://localhost:5300")]
    public void CommandLine_QuotesWhatAShellWouldSplit(string argument, string quoted) =>
        PlaybookRunner.CommandLine("simplesign", [argument]).ShouldBe("simplesign " + quoted);
}

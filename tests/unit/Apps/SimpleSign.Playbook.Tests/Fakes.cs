using SimpleSign.Playbook.Model;
using SimpleSign.Playbook.Runs;

namespace SimpleSign.Playbook.Tests;

/// <summary>A CLI that answers from a function and records what it was asked.</summary>
internal sealed class FakeProcessRunner(Func<ProcessCommand, ProcessResult>? answer = null) : IProcessRunner
{
    public List<ProcessCommand> Commands { get; } = [];

    public List<string> Calls { get; } = [];

    public Func<ProcessCommand, CancellationToken, Task>? Before { get; set; }

    public async Task<ProcessResult> RunAsync(ProcessCommand command, Action<bool, string>? onLine, CancellationToken cancellationToken)
    {
        Commands.Add(command);
        Calls.Add("run " + string.Join(' ', command.Arguments.Take(1)));
        if (Before is not null)
        {
            await Before(command, cancellationToken);
        }

        var result = command.Arguments.Contains("version")
            ? new ProcessResult(0, "simplesign 9.9.9\n", "", false, 1)
            : answer?.Invoke(command) ?? new ProcessResult(0, """{ "success": true }""", "", false, 1);
        foreach (string line in result.Stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            onLine?.Invoke(false, line);
        }

        return result;
    }
}

/// <summary>A Sandbox that records the actions and answers a fixed info and log.</summary>
internal sealed class FakeSandbox(List<string> calls) : ISandboxClient
{
    public Uri Url { get; } = new("http://localhost:5300/");

    public List<SandboxRequestRecord> Log { get; } = [];

    public Task<SandboxSummary> InfoAsync(CancellationToken cancellationToken) => Task.FromResult(new SandboxSummary(
        "fake", "1.0", Url.AbsoluteUri, "AB", "CN=Root", "sandbox",
        ["http://localhost:5300", "ldap://localhost:5302"],
        new SandboxTsaSummary("http://localhost:5300/tsa/tsr", "a", "u", "r", "w", "user", "pw")));

    public Task<SandboxPkiSummary> PkiAsync(CancellationToken cancellationToken) => Task.FromResult(new SandboxPkiSummary([], []));

    public Task<string> ChainPemAsync(CancellationToken cancellationToken) => Task.FromResult("-----BEGIN CERTIFICATE-----\n");

    public Task<string> RootPemAsync(CancellationToken cancellationToken) => Task.FromResult("-----BEGIN CERTIFICATE-----\n");

    public Task<byte[]?> ApplyAsync(SandboxAction action, CancellationToken cancellationToken)
    {
        calls.Add("sandbox " + action.Sandbox);
        return Task.FromResult<byte[]?>(action.Sandbox is "certificate" or "shortLived" ? [1, 2, 3] : null);
    }

    public Task ResetAsync(CancellationToken cancellationToken)
    {
        calls.Add("sandbox reset");
        return Task.CompletedTask;
    }

    public Task<IReadOnlyList<SandboxRequestRecord>> LogAsync(long after, CancellationToken cancellationToken) =>
        Task.FromResult<IReadOnlyList<SandboxRequestRecord>>([.. Log.Where(r => r.Id > after)]);
}

/// <summary>Records events; decides manual steps with <see cref="Decision"/>.</summary>
internal sealed class RecordingObserver : IRunObserver
{
    public ManualDecision Decision { get; set; } = new(RunStatus.Passed, "looked fine");

    public List<string> Lines { get; } = [];

    public List<string> Waiting { get; } = [];

    public void RunChanged(RunRecord run)
    {
    }

    public void StepChanged(RunRecord run, StepRecord step)
    {
    }

    public void OutputLine(StepRecord step, bool isError, string text) => Lines.Add($"{step.StepId}: {text}");

    public Task<ManualDecision> WaitForDecisionAsync(StepRecord step, CancellationToken cancellationToken)
    {
        Waiting.Add(step.StepId);
        return Task.FromResult(Decision);
    }
}

using System.Text.Json;
using System.Text.Json.Serialization;
using SimpleSign.Playbook.Model;
using SimpleSign.Playbook.Workspaces;

namespace SimpleSign.Playbook.Runs;

/// <summary>A run in progress: its events (already serialized, so readers never see a half-updated record) and its decisions.</summary>
public sealed class ActiveRun : IRunObserver
{
    private readonly Lock _gate = new();
    private readonly List<string> _events = [];
    private readonly Dictionary<string, TaskCompletionSource<ManualDecision>> _decisions = new(StringComparer.Ordinal);
    private TaskCompletionSource _changed = new(TaskCreationOptions.RunContinuationsAsynchronously);

    internal ActiveRun(string workspace, CancellationTokenSource cancellation)
    {
        Workspace = workspace;
        Cancellation = cancellation;
    }

    public string Workspace { get; }

    public string? Id { get; private set; }

    public bool IsFinished { get; private set; }

    internal CancellationTokenSource Cancellation { get; }

    internal Task<RunRecord>? Task { get; set; }

    /// <summary>The events from <paramref name="from"/> on, and a task that completes when there are more.</summary>
    public (IReadOnlyList<string> Events, Task Changed, bool Finished) Read(int from)
    {
        lock (_gate)
        {
            return ([.. _events.Skip(from)], _changed.Task, IsFinished);
        }
    }

    /// <summary>Records the operator's decision on a waiting manual step.</summary>
    public bool Decide(string stepId, ManualDecision decision)
    {
        lock (_gate)
        {
            return _decisions.Remove(stepId, out var waiting) && waiting.TrySetResult(decision);
        }
    }

    public void RunChanged(RunRecord run)
    {
        lock (_gate)
        {
            Id = run.Id;
            IsFinished = run.FinishedAt is not null;
            Publish(new RunEvent(RunEvent.RunChanged, Run: run));
        }
    }

    public void StepChanged(RunRecord run, StepRecord step)
    {
        lock (_gate)
        {
            Publish(new RunEvent(RunEvent.StepChanged, Step: step, StepId: step.StepId));
        }
    }

    public void OutputLine(StepRecord step, bool isError, string text)
    {
        lock (_gate)
        {
            Publish(new RunEvent(RunEvent.OutputLine, StepId: step.StepId, Stream: isError ? "stderr" : "stdout", Text: text));
        }
    }

    public Task<ManualDecision> WaitForDecisionAsync(StepRecord step, CancellationToken cancellationToken)
    {
        var waiting = new TaskCompletionSource<ManualDecision>(TaskCreationOptions.RunContinuationsAsynchronously);
        lock (_gate)
        {
            _decisions[step.StepId] = waiting;
        }

        cancellationToken.Register(() => waiting.TrySetCanceled(cancellationToken));
        return waiting.Task;
    }

    private void Publish(RunEvent runEvent)
    {
        _events.Add(JsonSerializer.Serialize(runEvent, ServiceJson.Default.RunEvent));
        var changed = _changed;
        _changed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        changed.TrySetResult();
    }
}

/// <summary>Starts runs (one at a time), follows them, and records manual decisions and attachments.</summary>
public sealed class RunService(PlaybookRunner runner, AppSettingsStore settings)
{
    private readonly Lock _gate = new();
    private ActiveRun? _active;

    /// <summary>The run in progress, or the last one this app started.</summary>
    public ActiveRun? Active
    {
        get
        {
            lock (_gate)
            {
                return _active;
            }
        }
    }

    /// <summary>Starts a run of <paramref name="workspace"/>'s playbook.</summary>
    /// <exception cref="InvalidOperationException">A run is in progress, or the playbook has errors.</exception>
    public ActiveRun Start(Workspace workspace, IReadOnlyCollection<string>? selection)
    {
        ArgumentNullException.ThrowIfNull(workspace);
        var (playbook, issues) = workspace.LoadPlaybook();
        if (playbook is null || issues.Any(i => i.IsError))
        {
            throw new InvalidOperationException("The playbook has errors: " + string.Join("; ", issues.Where(i => i.IsError).Select(i => $"{i.Path}: {i.Message}")));
        }

        lock (_gate)
        {
            if (_active is { IsFinished: false, Task: not null })
            {
                throw new InvalidOperationException("A run is in progress; stop it or wait for it to end.");
            }

            var active = new ActiveRun(workspace.Directory, new CancellationTokenSource());
            active.Task = Task.Run(async () =>
            {
                try
                {
                    return await runner.RunAsync(workspace, playbook, settings.ResolveCli(), selection, active, active.Cancellation.Token);
                }
                finally
                {
                    active.Cancellation.Dispose();
                }
            });
            _active = active;
            return active;
        }
    }

    /// <summary>Stops the run in progress.</summary>
    public bool Cancel()
    {
        var active = Active;
        if (active is null || active.IsFinished)
        {
            return false;
        }

        try
        {
            active.Cancellation.Cancel();
        }
        catch (ObjectDisposedException)
        {
            return false;
        }

        return true;
    }

    /// <summary>Adds the operator's file to a step of a run (in progress or finished) and writes the reports again.</summary>
    public static string Attach(Workspace workspace, string runId, string stepId, string fileName, byte[] content)
    {
        ArgumentNullException.ThrowIfNull(workspace);
        string runFolder = RunStore.Folder(workspace.RunsPath, runId);
        if (!PlaybookValidator.IsId(stepId))
        {
            throw new ArgumentException($"'{stepId}' is not a step id.", nameof(stepId));
        }

        string name = Path.GetFileName(fileName);
        string folder = Path.Combine(runFolder, "steps", stepId, "attachments");
        Directory.CreateDirectory(folder);
        File.WriteAllBytes(Path.Combine(folder, name), content);
        string relative = $"steps/{stepId}/attachments/{name}";
        if (RunStore.Load(runFolder) is { } run && run.Steps.FirstOrDefault(s => s.StepId == stepId) is { } step)
        {
            if (!step.Attachments.Contains(relative))
            {
                step.Attachments.Add(relative);
            }

            RunStore.Save(runFolder, run);
            RunReport.Write(runFolder, run);
        }

        return relative;
    }
}

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase, DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(RunEvent))]
internal sealed partial class ServiceJson : JsonSerializerContext;

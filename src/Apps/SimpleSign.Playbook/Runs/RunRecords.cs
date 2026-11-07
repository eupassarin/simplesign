using System.Text.Json.Serialization;

namespace SimpleSign.Playbook.Runs;

/// <summary>The state of a run or a step.</summary>
public static class RunStatus
{
    public const string Pending = "pending";
    public const string Running = "running";
    public const string Waiting = "waiting";
    public const string Passed = "passed";
    public const string Failed = "failed";
    public const string Error = "error";
    public const string Skipped = "skipped";
    public const string Cancelled = "cancelled";
}

/// <summary>The Sandbox a run used.</summary>
public sealed record SandboxRecord(string Url, string Name, string Version, string RootSubject, string RootThumbprint);

/// <summary>Counts of step results.</summary>
public sealed record RunSummary(int Total, int Passed, int Failed, int Errors, int Skipped, int Pending);

/// <summary>
/// A run as it is kept in <c>runs/ID/run.json</c>: when, on what (machine, CLI, Sandbox, playbook
/// hash), and each step's command, checks, Sandbox requests, files and result.
/// </summary>
public sealed class RunRecord
{
    public string Id { get; set; } = "";

    public string PlaybookName { get; set; } = "";

    public string PlaybookHash { get; set; } = "";

    public DateTimeOffset StartedAt { get; set; }

    public DateTimeOffset? FinishedAt { get; set; }

    public string Status { get; set; } = RunStatus.Running;

    /// <summary>Why the run stopped before its steps (the CLI or the Sandbox could not be reached…).</summary>
    public string? Error { get; set; }

    public string Machine { get; set; } = Environment.MachineName;

    public string User { get; set; } = Environment.UserName;

    /// <summary>The CLI command line prefix (program and fixed arguments).</summary>
    public string Cli { get; set; } = "";

    /// <summary>What <c>simplesign version</c> printed.</summary>
    public string? CliVersion { get; set; }

    public SandboxRecord? Sandbox { get; set; }

    /// <summary>The steps asked for (null: all).</summary>
    public List<string>? Selection { get; set; }

    public List<StepRecord> Steps { get; set; } = [];

    public RunSummary Summary => new(
        Steps.Count,
        Steps.Count(s => s.Status == RunStatus.Passed),
        Steps.Count(s => s.Status == RunStatus.Failed),
        Steps.Count(s => s.Status == RunStatus.Error),
        Steps.Count(s => s.Status is RunStatus.Skipped or RunStatus.Cancelled),
        Steps.Count(s => s.Status is RunStatus.Pending or RunStatus.Running or RunStatus.Waiting));
}

/// <summary>One step of a run.</summary>
public sealed class StepRecord
{
    public string SectionId { get; set; } = "";

    public string SectionTitle { get; set; } = "";

    public string StepId { get; set; } = "";

    public string Title { get; set; } = "";

    public string? Description { get; set; }

    public bool Manual { get; set; }

    public string Status { get; set; } = RunStatus.Pending;

    public DateTimeOffset? StartedAt { get; set; }

    public long? DurationMs { get; set; }

    /// <summary>What the setup and teardown did, one line each.</summary>
    public List<string> Actions { get; set; } = [];

    /// <summary>The command line, as it can be pasted in a shell.</summary>
    public string? Command { get; set; }

    public int? ExitCode { get; set; }

    public bool TimedOut { get; set; }

    public List<CheckResult> Checks { get; set; } = [];

    public List<SandboxRequestRecord> SandboxRequests { get; set; } = [];

    /// <summary>The files the step left in its folder (paths relative to the run folder).</summary>
    public List<string> Files { get; set; } = [];

    public string? Error { get; set; }

    /// <summary>The operator's note (manual steps, or any step).</summary>
    public string? Note { get; set; }

    /// <summary>The operator's files (relative to the run folder).</summary>
    public List<string> Attachments { get; set; } = [];
}

/// <summary>What the operator decided for a manual step.</summary>
public sealed record ManualDecision(string Status, string? Note);

/// <summary>One event of a running run, for the live view.</summary>
public sealed record RunEvent(string Type, RunRecord? Run = null, StepRecord? Step = null, string? StepId = null, string? Stream = null, string? Text = null)
{
    public const string RunChanged = "run";
    public const string StepChanged = "step";
    public const string OutputLine = "line";
}

/// <summary>A run in the history list.</summary>
public sealed record RunListItem(string Id, string PlaybookName, DateTimeOffset StartedAt, DateTimeOffset? FinishedAt, string Status, RunSummary Summary);

[JsonSourceGenerationOptions(WriteIndented = true, PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(RunRecord))]
[JsonSerializable(typeof(List<SandboxRequestRecord>))]
internal sealed partial class RunJson : JsonSerializerContext;

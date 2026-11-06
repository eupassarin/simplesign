using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text.Json;
using SimpleSign.TestBench.Cades;
using SimpleSign.TestBench.Localization;
using SimpleSign.TestBench.Signing;
using SimpleSign.TestBench.Xml;

namespace SimpleSign.TestBench.Runs;

/// <summary>The signature formats of the workbench.</summary>
public static class RunFormats
{
    public const string Pades = "pades";
    public const string Cades = "cades";
    public const string Xades = "xades";

    public static IReadOnlyList<string> All { get; } = [Pades, Cades, Xades];
}

/// <summary>A request to sign: the format and that format's options (SigningOptions, CadesOptions or XmlOptions).</summary>
public sealed record RunRequest(string Format, JsonElement Options, bool CrossValidate = false);

/// <summary>One signature's verdict, in the same shape for the three formats.</summary>
public sealed record RunVerdict(
    string Label,
    string? Signer,
    string Indication,
    string? Level,
    string? SigningTime,
    IReadOnlyList<CheckRow> Checks,
    IReadOnlyList<string> Errors,
    IReadOnlyList<string> Warnings,
    IReadOnlyList<RunVerdict> Children,
    bool IsTimestamp = false);

/// <summary>Everything about one run: what was asked, what came out, the verdicts, the code and the log.</summary>
public sealed record RunView(
    string Id,
    string Format,
    string Status,
    DateTimeOffset StartedAt,
    long TotalMs,
    JsonElement Options,
    bool Success,
    string? Error,
    string? ErrorType,
    string? OutputId,
    string? FileName,
    long Bytes,
    string? RequestedLevel,
    string? AchievedLevel,
    IReadOnlyList<string> Warnings,
    long SignMs,
    long ValidateMs,
    CodeSnippets? Code,
    IReadOnlyList<OptionIssue> Issues,
    string? Overall,
    IReadOnlyList<RunVerdict> Validation,
    object? Detail,
    object? CrossValidation,
    IReadOnlyList<RunLogEntry> Logs);

/// <summary>A row of the run history.</summary>
public sealed record RunSummary(string Id, string Format, string Status, DateTimeOffset StartedAt, long TotalMs, bool Success, string? RequestedLevel, string? AchievedLevel, string? Overall, string? FileName, string? Error);

/// <summary>What the events stream sends: a log line while the run is going, then the finished run.</summary>
public sealed record RunEvent(string Type, RunLogEntry? Log, RunView? Run);

/// <summary>One run: its log and, when finished, its result. Readers follow it with <see cref="Read"/>.</summary>
internal sealed class Run(string id, string format, JsonElement options)
{
    private readonly Lock _gate = new();
    private readonly List<RunEvent> _events = [];
    private TaskCompletionSource _changed = new(TaskCreationOptions.RunContinuationsAsynchronously);

    public string Id { get; } = id;

    public string Format { get; } = format;

    public JsonElement Options { get; } = options;

    public DateTimeOffset StartedAt { get; } = DateTimeOffset.Now;

    public RunView? Result { get; private set; }

    public bool IsFinished => Result is not null;

    public void Add(RunEvent runEvent)
    {
        TaskCompletionSource changed;
        lock (_gate)
        {
            _events.Add(runEvent);
            if (runEvent.Run is not null)
            {
                Result = runEvent.Run;
            }

            changed = _changed;
            _changed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        }

        changed.TrySetResult();
    }

    /// <summary>The events from <paramref name="from"/> on, and the task that completes when another one arrives.</summary>
    public (IReadOnlyList<RunEvent> Events, Task Changed) Read(int from)
    {
        lock (_gate)
        {
            return ([.. _events.Skip(from)], _changed.Task);
        }
    }
}

/// <summary>
/// Runs signatures for the workbench: dispatches to the format's runner, collects the library log
/// and the network requests on one timeline, and keeps the last runs in memory for the history.
/// </summary>
internal sealed class RunService(
    SigningRunner pades,
    CadesRunner cades,
    XmlRunner xml,
    CrossValidation.DssClient dss)
{
    private const int MaxRuns = 100;

    private readonly ConcurrentDictionary<string, Run> _runs = new(StringComparer.Ordinal);
    private readonly ConcurrentQueue<string> _order = new();

    public IReadOnlyList<RunSummary> History() =>
        [.. _order.Reverse().Select(id => _runs.TryGetValue(id, out var run) ? run : null).OfType<Run>().Select(Summary)];

    public Run? Find(string id) => _runs.TryGetValue(id, out var run) ? run : null;

    /// <summary>Starts a run in the background and returns it at once; follow it with <see cref="Run.Read"/>.</summary>
    public Run Start(RunRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (!RunFormats.All.Contains(request.Format))
        {
            throw new ArgumentException(L.T("Unknown format: {0}. Use pades, cades or xades.", request.Format), nameof(request));
        }

        var run = new Run(Guid.NewGuid().ToString("N")[..12], request.Format, request.Options.Clone());
        _runs[run.Id] = run;
        _order.Enqueue(run.Id);
        while (_order.Count > MaxRuns && _order.TryDequeue(out string? old))
        {
            _runs.TryRemove(old, out _);
        }

        var culture = System.Globalization.CultureInfo.CurrentUICulture;
        _ = Task.Run(async () =>
        {
            System.Globalization.CultureInfo.CurrentUICulture = culture;
            await ExecuteAsync(run, request.CrossValidate);
        });
        return run;
    }

    /// <summary>Runs to completion (used by the tests and the variants runner).</summary>
    public async Task<RunView> RunAsync(RunRequest request, CancellationToken cancellationToken)
    {
        var run = Start(request);
        int seen = 0;
        while (true)
        {
            var (events, changed) = run.Read(seen);
            seen += events.Count;
            if (run.Result is { } result)
            {
                return result;
            }

            await changed.WaitAsync(cancellationToken);
        }
    }

    private async Task ExecuteAsync(Run run, bool crossValidate)
    {
        var logger = new RunLogger(entry => run.Add(new RunEvent("log", entry, null)));
        var watch = Stopwatch.StartNew();
        RunView view;
        using (RunLog.Begin(logger))
        {
            try
            {
                view = run.Format switch
                {
                    RunFormats.Cades => FromCades(run, await cades.RunAsync(Options<CadesOptions>(run), CancellationToken.None)),
                    RunFormats.Xades => FromXml(run, await xml.RunAsync(Options<XmlOptions>(run), CancellationToken.None)),
                    _ => FromPades(run, await pades.RunAsync(Options<SigningOptions>(run), CancellationToken.None)),
                };
                if (crossValidate && view.Success && view.OutputId is not null)
                {
                    view = view with { CrossValidation = await dss.CompareAsync(run.Format, view, DetachedDataId(run), logger, CancellationToken.None) };
                }
            }
            catch (Exception ex) when (ex is JsonException or InvalidOperationException or ArgumentException or KeyNotFoundException)
            {
                view = Empty(run) with { Error = ex.Message, ErrorType = ex.GetType().Name };
            }
        }

        view = view with
        {
            Status = view.Success ? "done" : "failed",
            TotalMs = watch.ElapsedMilliseconds,
            Logs = logger.Entries,
        };
        run.Add(new RunEvent("result", null, view));
    }

    private static T Options<T>(Run run) =>
        run.Options.Deserialize<T>(WorkbenchJson.Options) ?? throw new JsonException(L.T("The run has no options."));

    /// <summary>The data a detached signature covers, which an external validator needs next to the signature.</summary>
    private static string? DetachedDataId(Run run) =>
        run.Format != RunFormats.Pades && run.Options.TryGetProperty("dataId", out var data) && data.ValueKind == JsonValueKind.String
            ? data.GetString()
            : null;

    private static RunView Empty(Run run) => new(
        run.Id, run.Format, "running", run.StartedAt, 0, run.Options, false, null, null, null, null, 0, null, null,
        [], 0, 0, null, [], null, [], null, null, []);

    private static RunSummary Summary(Run run) => run.Result is { } r
        ? new RunSummary(run.Id, run.Format, r.Status, run.StartedAt, r.TotalMs, r.Success, r.RequestedLevel, r.AchievedLevel, r.Overall, r.FileName, r.Error)
        : new RunSummary(run.Id, run.Format, "running", run.StartedAt, 0, false, null, null, null, null, null);

    private static RunView FromPades(Run run, SigningResult r) => Empty(run) with
    {
        Success = r.Success,
        Error = r.Error,
        ErrorType = r.ErrorType,
        OutputId = r.OutputId,
        FileName = r.FileName,
        Bytes = r.Bytes,
        RequestedLevel = r.RequestedLevel,
        AchievedLevel = r.AchievedLevel,
        Warnings = r.Warnings,
        SignMs = r.SignMs,
        ValidateMs = r.ValidateMs,
        Code = r.Code,
        Issues = r.Issues,
        Overall = Overall(r.Validation.Select(v => v.Indication)),
        Validation = [.. r.Validation.Select(v => new RunVerdict(
            v.FieldName, v.Signer, v.Indication, v.PolicyLevel, v.SigningTime, v.Checks, v.Errors, v.Warnings, [], v.IsDocumentTimestamp))],
        Detail = r,
    };

    private static RunView FromCades(Run run, CadesSignResult r) => Empty(run) with
    {
        Success = r.Success,
        Error = r.Error,
        ErrorType = r.ErrorType,
        OutputId = r.OutputId,
        FileName = r.FileName,
        Bytes = r.Bytes,
        RequestedLevel = r.RequestedLevel,
        AchievedLevel = r.AchievedLevel,
        Warnings = r.Warnings,
        SignMs = r.SignMs,
        ValidateMs = r.Validation?.Ms ?? 0,
        Code = r.Code,
        Issues = r.Issues,
        Overall = r.Validation?.Overall,
        Validation = [.. (r.Validation?.Signers ?? []).Select(Verdict)],
        Detail = r,
    };

    private static RunVerdict Verdict(CadesSignerReport s) => new(
        L.T("Signer {0}", s.Index + 1), s.Signer, s.Indication, null, s.SigningTime, s.Checks, s.Errors, s.Warnings,
        [.. s.CounterSignatures.Select(Verdict)]);

    private static RunView FromXml(Run run, XmlSignResult r) => Empty(run) with
    {
        Success = r.Success,
        Error = r.Error,
        ErrorType = r.ErrorType,
        OutputId = r.OutputId,
        FileName = r.FileName,
        Bytes = r.Bytes,
        RequestedLevel = r.RequestedLevel,
        AchievedLevel = r.AchievedLevel,
        Warnings = r.Warnings,
        SignMs = r.SignMs,
        ValidateMs = r.Validation?.Ms ?? 0,
        Code = r.Code,
        Issues = r.Issues,
        Overall = r.Validation?.Overall,
        Validation = [.. (r.Validation?.Signatures ?? []).Select(s => new RunVerdict(
            s.Reference ?? L.T("Signature {0}", s.Index + 1), s.Signer, s.Indication, s.Level, s.SigningTime, s.Checks, s.Errors, s.Warnings, []))],
        Detail = r,
    };

    private static string? Overall(IEnumerable<string> indications)
    {
        var all = indications.ToList();
        return all.Count == 0 ? null
            : all.Contains("Invalid") ? "Invalid"
            : all.Contains("Indeterminate") ? "Indeterminate"
            : "Valid";
    }
}

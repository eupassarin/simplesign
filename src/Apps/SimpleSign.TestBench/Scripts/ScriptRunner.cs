using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Nodes;
using SimpleSign.TestBench.Credentials;
using SimpleSign.TestBench.Documents;
using SimpleSign.TestBench.Runs;
using SimpleSign.TestBench.Sandbox;

namespace SimpleSign.TestBench.Scripts;

/// <summary>The statuses of a step and of a requirement.</summary>
public static class ScriptStatuses
{
    public const string Pending = "pending";
    public const string Running = "running";
    public const string Waiting = "waiting";
    public const string Passed = "passed";
    public const string Failed = "failed";
    public const string Skipped = "skipped";
    public const string NotApplicable = "notApplicable";
    public const string Done = "done";
    public const string Cancelled = "cancelled";
}

/// <summary>One check of an expectation: what was expected and what the run showed.</summary>
public sealed record ScriptCheckRow(string What, string Expected, string Found, bool Passed);

/// <summary>A run of a step through one engine, with the TestBench run that holds its logs, reports and file.</summary>
public sealed record ScriptEngineRun(
    string Engine,
    string RunId,
    bool Success,
    string? Error,
    string? ErrorType,
    string? OutputId,
    string? FileName,
    string? AchievedLevel,
    string? Indication,
    string? SubIndication,
    bool? DssAgrees,
    string? ReportId,
    string? EtsiReportId,
    long Ms,
    IReadOnlyList<ScriptCheckRow> Checks)
{
    /// <summary>Whether every check passed.</summary>
    public bool Passed => Checks.All(c => c.Passed);
}

/// <summary>A file attached to a manual step.</summary>
public sealed record ScriptAttachment(string Id, string FileName);

/// <summary>A step of a run, as the page shows it.</summary>
public sealed record ScriptStepView(
    string SectionId,
    string StepId,
    string Title,
    string Kind,
    IReadOnlyList<string> Requirements,
    string Status,
    string? Message,
    IReadOnlyList<ScriptEngineRun> Runs,
    string? Note,
    IReadOnlyList<ScriptAttachment> Attachments,
    long Ms);

/// <summary>A requirement of a run, with the steps that show it and their outcome.</summary>
public sealed record ScriptRequirementView(string Id, string? Group, string Text, bool Applies, string? Justification, string Status, IReadOnlyList<string> Steps);

/// <summary>A run of a script.</summary>
public sealed record ScriptRunView(
    string Id,
    string ScriptId,
    string Title,
    string Language,
    string Status,
    DateTimeOffset StartedAt,
    DateTimeOffset? EndedAt,
    int Version,
    string? WaitingFor,
    IReadOnlyList<ScriptStepView> Steps,
    IReadOnlyList<ScriptRequirementView> Requirements);

/// <summary>What to run: the whole script, a section or a step, through the script's engines or another.</summary>
public sealed record ScriptRunRequest(string? Engine = null, string? SectionId = null, string? StepId = null);

/// <summary>The decision on a manual step.</summary>
public sealed record ScriptDecision(bool Passed, string? Note = null, IReadOnlyList<string>? AttachmentIds = null);

/// <summary>
/// Runs certification scripts: each step through <see cref="RunService"/> (so it has the log, reports, file and DSS
/// verdict of any TestBench run), with the Sandbox put in the state the step asks and back after it. One run at a time.
/// </summary>
internal sealed class ScriptRunner(
    RunService runs, SandboxEnvironment sandbox, DocumentStore documents, CredentialStore credentials, CredentialFactory factory,
    Cades.CadesSampleStore? cadesSamples = null, Xml.XmlSampleStore? xmlSamples = null, Validation.ValidationSampleStore? validationSamples = null)
{
    private readonly Lock _gate = new();
    private readonly List<ScriptRun> _history = [];
    private ScriptRun? _active;

    /// <summary>The script loaded on the page, and its check.</summary>
    public ScriptCheck? Loaded { get; private set; }

    /// <summary>The source of <see cref="Loaded"/>, to keep with the evidence.</summary>
    public string? LoadedJson { get; private set; }

    /// <summary>Reads and checks a script and keeps it as the loaded one.</summary>
    public ScriptCheck Load(string json)
    {
        var check = ScriptValidator.Check(json, sandbox.Current);
        lock (_gate)
        {
            Loaded = check;
            LoadedJson = json;
        }

        return check;
    }

    /// <summary>The runs of this session, newest first.</summary>
    public IReadOnlyList<ScriptRunView> History()
    {
        lock (_gate)
        {
            return [.. _history.Select(r => r.View()).Reverse()];
        }
    }

    /// <summary>A run, or null.</summary>
    public ScriptRun? Get(string id)
    {
        lock (_gate)
        {
            return _history.FirstOrDefault(r => r.Id == id);
        }
    }

    /// <summary>Starts running the loaded script.</summary>
    /// <exception cref="InvalidOperationException">No script can run, or a run is going.</exception>
    public ScriptRun Start(ScriptRunRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        lock (_gate)
        {
            if (Loaded is not { CanRun: true, Script: { } script })
            {
                throw new InvalidOperationException("Load a script without errors first.");
            }

            if (_active is { IsFinished: false })
            {
                throw new InvalidOperationException("A script is running: wait for it or cancel it.");
            }

            if (request.Engine is { } engine && !ScriptEngines.All.Contains(engine))
            {
                throw new ArgumentException($"Unknown engine '{engine}'.", nameof(request));
            }

            var run = new ScriptRun(Guid.NewGuid().ToString("N")[..12], script, LoadedJson ?? "", request);
            _history.Add(run);
            _active = run;
            _ = Task.Run(() => ExecuteAsync(run));
            return run;
        }
    }

    /// <summary>Records the decision on the manual step a run waits for.</summary>
    public void Decide(string runId, string stepId, ScriptDecision decision)
    {
        var run = Get(runId) ?? throw new KeyNotFoundException($"No script run '{runId}'.");
        var attachments = (decision.AttachmentIds ?? [])
            .Select(id => documents.Get(id))
            .Select(f => new ScriptAttachment(f.Id, f.FileName))
            .ToList();
        run.Decide(stepId, decision.Passed, decision.Note, attachments);
    }

    /// <summary>Stops a run after its current step.</summary>
    public void Cancel(string runId) => (Get(runId) ?? throw new KeyNotFoundException($"No script run '{runId}'.")).Cancel();

    /// <summary>Runs a script to the end (tests).</summary>
    internal async Task<ScriptRunView> RunToEndAsync(ScriptRunRequest request)
    {
        var run = Start(request);
        await run.Completion.ConfigureAwait(false);
        return run.View();
    }

    private async Task ExecuteAsync(ScriptRun run)
    {
        var outputs = new Dictionary<string, string>(StringComparer.Ordinal);
        var signers = new Dictionary<string, string>(StringComparer.Ordinal);
        try
        {
            if (sandbox.IsConnected)
            {
                await sandbox.ResetAsync(run.Token).ConfigureAwait(false);
            }

            foreach (var (section, step) in run.Script.AllSteps())
            {
                if (run.Token.IsCancellationRequested)
                {
                    break;
                }

                if (!run.Includes(section, step))
                {
                    run.Update(step.Id, ScriptStatuses.Skipped, null, [], 0);
                    continue;
                }

                await ExecuteStepAsync(run, step, outputs, signers).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (run.Token.IsCancellationRequested)
        {
        }
        finally
        {
            if (sandbox.IsConnected)
            {
                try
                {
                    await sandbox.ResetAsync(CancellationToken.None).ConfigureAwait(false);
                }
                catch (HttpRequestException)
                {
                }
            }

            run.Finish();
        }
    }

    private async Task ExecuteStepAsync(ScriptRun run, ScriptStep step, Dictionary<string, string> outputs, Dictionary<string, string> signers)
    {
        var watch = Stopwatch.StartNew();
        if (step.Kind == ScriptStepKinds.Manual)
        {
            run.Update(step.Id, ScriptStatuses.Waiting, null, [], 0);
            await run.WaitForDecisionAsync(step.Id).ConfigureAwait(false);
            return;
        }

        run.Update(step.Id, ScriptStatuses.Running, null, [], 0);
        var results = new List<ScriptEngineRun>();
        string? message = null;
        bool changedSandbox = false;
        try
        {
            changedSandbox = await ApplySandboxAsync(step.Sandbox, run.Token).ConfigureAwait(false);
            string format = step.Format ?? run.Script.Defaults.Format;
            JsonElement options = Resolve(Merge(run.Script.Defaults.Options, format, step.Options), outputs, signers);
            foreach (string engine in Engines(run.Engine(step)))
            {
                var request = new RunRequest(format, options, step.CrossValidate ?? run.Script.Defaults.CrossValidate,
                    step.Kind == ScriptStepKinds.Validate ? RunKinds.Validate : RunKinds.Sign, engine);
                var view = await runs.RunAsync(request, run.Token).ConfigureAwait(false);
                results.Add(ScriptExpectations.Evaluate(engine, view, step.Expect ?? new ScriptExpectation()));
                run.Update(step.Id, ScriptStatuses.Running, null, results, watch.ElapsedMilliseconds);
            }

            if (results.FirstOrDefault(r => r.OutputId is not null)?.OutputId is { } output)
            {
                outputs[step.Id] = output;
            }
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or HttpRequestException or KeyNotFoundException or JsonException)
        {
            message = ex.Message;
        }
        finally
        {
            if (changedSandbox)
            {
                await sandbox.ResetAsync(CancellationToken.None).ConfigureAwait(false);
            }
        }

        bool passed = message is null && results.Count > 0 && results.All(r => r.Passed);
        run.Update(step.Id, passed ? ScriptStatuses.Passed : ScriptStatuses.Failed, message, results, watch.ElapsedMilliseconds);
    }

    private async Task<bool> ApplySandboxAsync(ScriptSandbox? box, CancellationToken cancellationToken)
    {
        if (box is not { Any: true })
        {
            return false;
        }

        if (!sandbox.IsConnected)
        {
            throw new InvalidOperationException("The step changes the Sandbox: connect one.");
        }

        var faults = new SandboxFaults(
            Tsa: Parse(box.Tsa, TsaFault.None),
            Crl: Parse(box.Crl, CrlFault.None),
            Ocsp: Parse(box.Ocsp, OcspFault.None),
            TrustedList: Parse(box.TrustedList, TlFault.None));
        if (faults.Any)
        {
            await sandbox.SetFaultsAsync(faults, cancellationToken).ConfigureAwait(false);
        }

        foreach (string id in box.Revoke)
        {
            await sandbox.RevokeAsync(id, cancellationToken).ConfigureAwait(false);
        }

        return true;
    }

    private static (string Id, bool Data) SampleId(string value) =>
        value.EndsWith("#data", StringComparison.Ordinal) ? (value[..^"#data".Length], true) : (value, false);

    private static T Parse<T>(string? value, T fallback)
        where T : struct, Enum => value is not null && Enum.TryParse<T>(value, ignoreCase: true, out var parsed) ? parsed : fallback;

    private static IEnumerable<string> Engines(string engine) =>
        engine == ScriptEngines.Both ? [RunEngines.Library, RunEngines.Cli] : [engine];

    /// <summary>The defaults' <c>common</c> and format options, then the step's, merged (the step wins).</summary>
    internal static JsonObject Merge(JsonElement? defaults, string format, JsonElement? step)
    {
        var merged = new JsonObject();
        if (defaults is { ValueKind: JsonValueKind.Object } d)
        {
            foreach (string part in new[] { "common", format })
            {
                if (d.TryGetProperty(part, out var options) && options.ValueKind == JsonValueKind.Object)
                {
                    MergeInto(merged, (JsonObject)JsonNode.Parse(options.GetRawText())!);
                }
            }
        }

        if (step is { ValueKind: JsonValueKind.Object } s)
        {
            MergeInto(merged, (JsonObject)JsonNode.Parse(s.GetRawText())!);
        }

        return merged;
    }

    private static void MergeInto(JsonObject target, JsonObject source)
    {
        foreach (var (name, value) in source.ToList())
        {
            if (value is JsonObject inner && target[name] is JsonObject existing)
            {
                MergeInto(existing, inner);
            }
            else
            {
                source.Remove(name);
                target[name] = value;
            }
        }
    }

    /// <summary>The options with their symbolic values replaced: <c>sandbox:SIGNER</c> by a credential, <c>step:ID</c> by its file.</summary>
    private JsonElement Resolve(JsonObject options, Dictionary<string, string> outputs, Dictionary<string, string> signers)
    {
        Replace(options);
        return JsonSerializer.SerializeToElement(options);

        void Replace(JsonNode? node)
        {
            switch (node)
            {
                case JsonObject obj:
                    foreach (var (name, value) in obj.ToList())
                    {
                        if (value is JsonValue v && v.TryGetValue<string>(out var text) && Symbol(text) is { } replaced)
                        {
                            obj[name] = replaced;
                        }
                        else
                        {
                            Replace(value);
                        }
                    }

                    break;
                case JsonArray array:
                    for (int i = 0; i < array.Count; i++)
                    {
                        if (array[i] is JsonValue v && v.TryGetValue<string>(out var text) && Symbol(text) is { } replaced)
                        {
                            array[i] = replaced;
                        }
                        else
                        {
                            Replace(array[i]);
                        }
                    }

                    break;
            }
        }

        string? Symbol(string text)
        {
            if (text.StartsWith("sandbox:", StringComparison.Ordinal))
            {
                string signer = text["sandbox:".Length..];
                if (!signers.TryGetValue(signer, out string? id))
                {
                    id = credentials.Add(factory.OpenSandbox(new SandboxCredentialRequest(signer))).Id;
                    signers[signer] = id;
                }

                return id;
            }

            // sample:ID that is not a PDF sample is a PAdES validation sample; cades-sample:ID and xades-sample:ID the others.
            if (text.StartsWith("sample:", StringComparison.Ordinal) && !documents.TryGet(text, out _))
            {
                string id = text["sample:".Length..];
                return validationSamples?.Samples.FirstOrDefault(s => s.Id == id)?.FileId ?? throw new KeyNotFoundException($"No sample '{id}'.");
            }

            // ID#data: the data a detached sample signature is checked against.
            if (text.StartsWith("cades-sample:", StringComparison.Ordinal))
            {
                var (id, data) = SampleId(text["cades-sample:".Length..]);
                var sample = cadesSamples?.Samples.FirstOrDefault(s => s.Id == id) ?? throw new KeyNotFoundException($"No CAdES sample '{id}'.");
                return data ? sample.DataId ?? throw new KeyNotFoundException($"CAdES sample '{id}' has no data.") : sample.FileId;
            }

            if (text.StartsWith("xades-sample:", StringComparison.Ordinal))
            {
                var (id, data) = SampleId(text["xades-sample:".Length..]);
                var sample = xmlSamples?.Samples.FirstOrDefault(s => s.Id == id) ?? throw new KeyNotFoundException($"No XAdES sample '{id}'.");
                return data ? sample.DataId ?? throw new KeyNotFoundException($"XAdES sample '{id}' has no data.") : sample.FileId;
            }

            if (text.StartsWith("step:", StringComparison.Ordinal))
            {
                string stepId = text["step:".Length..];
                return outputs.TryGetValue(stepId, out string? output)
                    ? output
                    : throw new InvalidOperationException($"Step '{stepId}' produced no file to use here.");
            }

            return null;
        }
    }
}

/// <summary>A run of a script in progress or done.</summary>
internal sealed class ScriptRun : IDisposable
{
    private readonly Lock _gate = new();
    private readonly CancellationTokenSource _cancel = new();
    private readonly TaskCompletionSource _done = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly Dictionary<string, TaskCompletionSource> _decisions = new(StringComparer.Ordinal);
    private readonly Dictionary<string, ScriptStepView> _steps = new(StringComparer.Ordinal);
    private readonly ScriptRunRequest _request;
    private string _status = ScriptStatuses.Running;
    private DateTimeOffset? _ended;
    private int _version;

    public ScriptRun(string id, CertificationScript script, string json, ScriptRunRequest request)
    {
        Id = id;
        Script = script;
        Json = json;
        _request = request;
        foreach (var (section, step) in script.AllSteps())
        {
            _steps[step.Id] = new(section.Id, step.Id, step.Title, step.Kind, step.Requirements, ScriptStatuses.Pending, null, [], null, [], 0);
        }
    }

    public string Id { get; }

    public CertificationScript Script { get; }

    /// <summary>The script file as it was run.</summary>
    public string Json { get; }

    public DateTimeOffset StartedAt { get; } = DateTimeOffset.Now;

    public CancellationToken Token => _cancel.Token;

    public bool IsFinished => _done.Task.IsCompleted;

    public Task Completion => _done.Task;

    /// <summary>The engine a step runs through: the request's, the step's or the script's.</summary>
    public string Engine(ScriptStep step) => _request.Engine ?? step.Engine ?? Script.Defaults.Engine;

    /// <summary>Whether the request covers the step.</summary>
    public bool Includes(ScriptSection section, ScriptStep step) =>
        (_request.SectionId is null || _request.SectionId == section.Id) && (_request.StepId is null || _request.StepId == step.Id);

    public void Update(string stepId, string status, string? message, IReadOnlyList<ScriptEngineRun> runs, long ms)
    {
        lock (_gate)
        {
            _steps[stepId] = _steps[stepId] with { Status = status, Message = message, Runs = [.. runs], Ms = ms };
            _version++;
        }
    }

    public Task WaitForDecisionAsync(string stepId)
    {
        TaskCompletionSource decision;
        lock (_gate)
        {
            decision = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            _decisions[stepId] = decision;
        }

        return decision.Task.WaitAsync(Token);
    }

    public void Decide(string stepId, bool passed, string? note, IReadOnlyList<ScriptAttachment> attachments)
    {
        TaskCompletionSource? waiting;
        lock (_gate)
        {
            if (!_steps.TryGetValue(stepId, out var step) || step.Kind != ScriptStepKinds.Manual)
            {
                throw new KeyNotFoundException($"No manual step '{stepId}'.");
            }

            _steps[stepId] = step with
            {
                Status = passed ? ScriptStatuses.Passed : ScriptStatuses.Failed,
                Note = note,
                Attachments = [.. step.Attachments, .. attachments],
            };
            _version++;
            _decisions.Remove(stepId, out waiting);
        }

        waiting?.TrySetResult();
    }

    public void Cancel() => _cancel.Cancel();

    public void Dispose() => _cancel.Dispose();

    public void Finish()
    {
        lock (_gate)
        {
            _status = _cancel.IsCancellationRequested ? ScriptStatuses.Cancelled : ScriptStatuses.Done;
            _ended = DateTimeOffset.Now;
            _version++;
        }

        _done.TrySetResult();
    }

    public ScriptRunView View()
    {
        lock (_gate)
        {
            var steps = Script.AllSteps().Select(s => _steps[s.Step.Id]).ToList();
            string? waiting = steps.FirstOrDefault(s => s.Status == ScriptStatuses.Waiting)?.StepId;
            var requirements = Script.Requirements.Select(r =>
            {
                var covering = steps.Where(s => s.Requirements.Contains(r.Id)).ToList();
                string status = !r.Applies ? ScriptStatuses.NotApplicable
                    : covering.Count == 0 ? ScriptStatuses.Pending
                    : covering.Any(s => s.Status == ScriptStatuses.Failed) ? ScriptStatuses.Failed
                    : covering.All(s => s.Status == ScriptStatuses.Passed) ? ScriptStatuses.Passed
                    : covering.Any(s => s.Status == ScriptStatuses.Waiting) ? ScriptStatuses.Waiting
                    : ScriptStatuses.Pending;
                return new ScriptRequirementView(r.Id, r.Group, r.Text, r.Applies, r.Justification, status, [.. covering.Select(s => s.StepId)]);
            }).ToList();
            return new ScriptRunView(Id, Script.Id, Script.Title, Script.Language, waiting is null ? _status : ScriptStatuses.Waiting,
                StartedAt, _ended, _version, waiting, steps, requirements);
        }
    }
}

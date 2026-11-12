using System.Diagnostics;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SimpleSign.TestBench.Cades;
using SimpleSign.TestBench.Credentials;
using SimpleSign.TestBench.Documents;
using SimpleSign.TestBench.Runs;
using SimpleSign.TestBench.Sandbox;
using SimpleSign.TestBench.Schema;
using SimpleSign.TestBench.Signing;
using SimpleSign.TestBench.Validation;
using SimpleSign.TestBench.Xml;

namespace SimpleSign.TestBench.Playbooks;

/// <summary>The statuses of a step.</summary>
public static class PlaybookStatuses
{
    public const string Pending = "pending";
    public const string Queued = "queued";
    public const string Running = "running";
    public const string Passed = "passed";
    public const string Failed = "failed";
}

/// <summary>One check of an expectation: what was expected and what the run showed.</summary>
public sealed record PlaybookCheckRow(string What, string Expected, string Found, bool Passed);

/// <summary>A run of a step through one engine, with the TestBench run that holds its log, reports and file.</summary>
public sealed record PlaybookEngineRun(
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
    IReadOnlyList<PlaybookCheckRow> Checks)
{
    /// <summary>Whether EU DSS was asked to validate the run (crossValidate on, and the run produced a file).</summary>
    public bool CrossValidated { get; init; }

    /// <summary>Why DSS gave no verdict (unreachable, an error); null when it answered or was not asked.</summary>
    public string? DssError { get; init; }

    /// <summary>Whether every check passed.</summary>
    public bool Passed => Checks.All(c => c.Passed);
}

/// <summary>The latest result of a step: kept until the step runs again or another playbook is loaded.</summary>
public sealed record PlaybookStepResult(string Status, string? Message, IReadOnlyList<PlaybookEngineRun> Runs, long Ms, DateTimeOffset At);

/// <summary>A step as the page shows it: its definition's summary, its status and its latest result.</summary>
public sealed record PlaybookStepView(string SectionId, string StepId, string Title, string Kind, IReadOnlyList<string> Tags, string Status, PlaybookStepResult? Result);

/// <summary>The loaded playbook with the latest result of each step, and whether a run is going.</summary>
public sealed record PlaybookStateView(
    string? Key,
    string? PlaybookId,
    string? Title,
    bool Running,
    string? RunningStep,
    int Version,
    IReadOnlyList<PlaybookStepView> Steps);

/// <summary>What to run: the whole playbook, a section or a step, through the playbook's engines or another.</summary>
public sealed record PlaybookRunRequest(string? Engine = null, string? SectionId = null, string? StepId = null);

/// <summary>A labelled value of a preview; <paramref name="Key"/> is stable (the page translates it), <paramref name="Label"/> is in English.</summary>
public sealed record PreviewItem(string Key, string Label, string Value);

/// <summary>One setting of a step: its value, and whether the playbook sets it and whether it differs from the default.</summary>
public sealed record PreviewSetting(string Id, string Title, string Value, bool FromPlaybook, bool Changed);

/// <summary>The settings of one group of the Sign page.</summary>
public sealed record PreviewGroup(string Id, string Title, IReadOnlyList<PreviewSetting> Settings);

/// <summary>Everything a step will do, before it runs.</summary>
public sealed record PlaybookStepPreview(
    string StepId,
    string Kind,
    string Format,
    string Engine,
    bool CrossValidate,
    string CrossValidateFrom,
    IReadOnlyList<PreviewItem> Target,
    IReadOnlyList<PreviewItem> Signer,
    IReadOnlyList<PreviewGroup> Groups,
    IReadOnlyList<PreviewItem> Sandbox,
    IReadOnlyList<PreviewItem> Expect,
    CodeSnippets? Code,
    IReadOnlyList<OptionIssue> Issues,
    IReadOnlyList<string> NeedsSteps,
    string? CodeError);

/// <summary>
/// Runs playbooks: each step through <see cref="RunService"/> (so it has the log, reports, file and DSS verdict of
/// any TestBench run), with the Sandbox put in the state the step asks and back after it. One loaded playbook, one
/// run at a time; the latest result of each step is kept while the playbook stays loaded.
/// </summary>
internal sealed class PlaybookRunner(
    RunService runs, SandboxEnvironment sandbox, DocumentStore documents, CredentialStore credentials, CredentialFactory factory,
    SigningRunner signing, CadesRunner cades, XmlRunner xml, ValidationService validation,
    CadesSampleStore? cadesSamples = null, XmlSampleStore? xmlSamples = null, ValidationSampleStore? validationSamples = null) : IDisposable
{
    private readonly Lock _gate = new();
    private PlaybookSession? _session;

    /// <summary>The loaded playbook's check, or null.</summary>
    public PlaybookCheck? Loaded { get; private set; }

    /// <summary>The loaded playbook's file, or null.</summary>
    public string? LoadedJson { get; private set; }

    /// <summary>The loaded playbook with its results, for the evidence; null when none can run.</summary>
    internal PlaybookSession? Session
    {
        get
        {
            lock (_gate)
            {
                return _session;
            }
        }
    }

    /// <summary>
    /// Reads and checks a playbook and keeps it as the loaded one. Loading the same file again keeps its results;
    /// another file starts with none.
    /// </summary>
    /// <exception cref="InvalidOperationException">A run is going.</exception>
    public PlaybookCheck Load(string json)
    {
        var check = PlaybookValidator.Check(json, sandbox.Current);
        lock (_gate)
        {
            if (_session is { IsRunning: true })
            {
                throw new InvalidOperationException("A playbook is running: wait for it or stop it.");
            }

            Loaded = check;
            LoadedJson = json;
            string key = Key(check.Playbook, json);
            if (check.Playbook is { } playbook && _session?.Key != key)
            {
                _session?.Dispose();
                _session = new PlaybookSession(key, playbook, json);
            }
            else if (check.Playbook is null)
            {
                _session?.Dispose();
                _session = null;
            }
        }

        return check;
    }

    public void Dispose()
    {
        lock (_gate)
        {
            _session?.Dispose();
            _session = null;
        }
    }

    /// <summary>The loaded playbook with the latest result of each step.</summary>
    public PlaybookStateView State() => Session?.View() ?? new(null, null, null, false, null, 0, []);

    /// <summary>Starts running the loaded playbook (all of it, a section or a step).</summary>
    /// <exception cref="InvalidOperationException">No playbook can run, or a run is going.</exception>
    public Task Start(PlaybookRunRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        lock (_gate)
        {
            if (Loaded is not { CanRun: true } || _session is null)
            {
                throw new InvalidOperationException("Load a playbook without errors first.");
            }

            if (request.Engine is { } engine && !PlaybookEngines.All.Contains(engine))
            {
                throw new ArgumentException($"Unknown engine '{engine}'.", nameof(request));
            }

            if (request.StepId is { } stepId && _session.Playbook.Step(stepId) is null)
            {
                throw new KeyNotFoundException($"No step '{stepId}'.");
            }

            var session = _session;
            var steps = session.Playbook.AllSteps()
                .Where(s => (request.SectionId is null || request.SectionId == s.Section.Id) && (request.StepId is null || request.StepId == s.Step.Id))
                .Select(s => s.Step)
                .ToList();
            session.Begin(steps.Select(s => s.Id));
            return Task.Run(() => ExecuteAsync(session, steps, request.Engine));
        }
    }

    /// <summary>Stops the run after its current step.</summary>
    public void Cancel() => Session?.Cancel();

    /// <summary>Drops the latest result of a step, or of every step when <paramref name="stepId"/> is null (restart).</summary>
    /// <exception cref="KeyNotFoundException">No playbook is loaded, or it has no such step.</exception>
    /// <exception cref="InvalidOperationException">A run is going.</exception>
    public PlaybookStateView Clear(string? stepId)
    {
        var session = Session ?? throw new KeyNotFoundException("No playbook is loaded.");
        if (stepId is not null && session.Playbook.Step(stepId) is null)
        {
            throw new KeyNotFoundException($"No step '{stepId}'.");
        }

        session.Clear(stepId);
        return session.View();
    }

    /// <summary>Runs (part of) the loaded playbook to its end (tests).</summary>
    internal async Task<PlaybookStateView> RunToEndAsync(PlaybookRunRequest request)
    {
        await Start(request).ConfigureAwait(false);
        return State();
    }

    /// <summary>Everything a step will do: what is signed and by whom, every group of settings, the Sandbox changes, the expectation and the commands.</summary>
    /// <exception cref="KeyNotFoundException">No playbook is loaded, or it has no such step.</exception>
    public async Task<PlaybookStepPreview> PreviewAsync(string stepId, string? engine, CancellationToken cancellationToken)
    {
        var session = Session ?? throw new KeyNotFoundException("No playbook is loaded.");
        var step = session.Playbook.Step(stepId) ?? throw new KeyNotFoundException($"No step '{stepId}'.");
        string format = step.Format ?? session.Playbook.Defaults.Format;
        string runEngine = engine ?? step.Engine ?? session.Playbook.Defaults.Engine;
        bool crossValidate = step.CrossValidate ?? session.Playbook.Defaults.CrossValidate;
        string crossValidateFrom = step.CrossValidate is null ? "defaults" : "step";
        var merged = Merge(session.Playbook.Defaults.Options, format, step.Options);
        var asked = (JsonObject)merged.DeepClone();
        var sandboxLines = SandboxRows(step.Sandbox);
        var expect = (step.Expect?.Fields() ?? []).Select(f => new PreviewItem(f.Name, f.Name, f.Value)).ToList();
        var missing = new List<string>();
        var options = Resolve(merged, session, missing);

        if (step.Kind == PlaybookStepKinds.Validate)
        {
            var validate = options.Deserialize<ValidateOptions>(WorkbenchJson.Options);
            var target = new List<PreviewItem>();
            if (validate?.FileId is { } fileId && documents.TryGet(fileId, out var file))
            {
                target.Add(new("file", "File", $"{file!.FileName} ({file.Content.Length.ToString("N0", CultureInfo.InvariantCulture)} bytes)"));
            }
            else
            {
                target.Add(new("file", "File", missing.Count > 0 ? $"step:{missing[0]}" : "—"));
            }

            if (validate?.DataId is { } dataId && documents.TryGet(dataId, out var data))
            {
                target.Add(new("data", "Data", data!.FileName));
            }

            var settings = validate?.Settings ?? new ValidationSettings();
            var group = new PreviewGroup("validation", "Validation", ValidationSettingsRows(settings, asked));
            return new PlaybookStepPreview(step.Id, step.Kind, format, PlaybookEngines.Library, crossValidate, crossValidateFrom, target, [], [group], sandboxLines, expect,
                validation.ValidationCode(settings), [], missing, null);
        }

        RunDescription description = format switch
        {
            RunFormats.Cades => await cades.DescribeAsync(Options<CadesOptions>(options), cancellationToken).ConfigureAwait(false),
            RunFormats.Xades => await xml.DescribeAsync(Options<XmlOptions>(options), cancellationToken).ConfigureAwait(false),
            _ => await signing.DescribeAsync(Options<SigningOptions>(options), cancellationToken).ConfigureAwait(false),
        };
        var effective = JsonSerializer.SerializeToElement(description.Effective, description.Effective.GetType(), WorkbenchJson.Options);
        return new PlaybookStepPreview(step.Id, step.Kind, format, runEngine, crossValidate, crossValidateFrom,
            await TargetAsync(format, effective, cancellationToken).ConfigureAwait(false),
            SignerRows(description.Signer, asked),
            Groups(format, effective, asked, description.States),
            sandboxLines, expect, description.Code, description.Issues, missing, description.Error);
    }

    private static T Options<T>(JsonElement options) =>
        options.Deserialize<T>(WorkbenchJson.Options) ?? throw new ArgumentException("The step's options cannot be read.");

    private async Task ExecuteAsync(PlaybookSession session, IReadOnlyList<PlaybookStep> steps, string? engine)
    {
        try
        {
            // A run of several steps starts from a clean Sandbox (failures switched on by hand are off). A step that changes
            // the Sandbox puts it back itself, so one step alone needs no reset (a reset takes seconds).
            if (sandbox.IsConnected && steps.Count > 1)
            {
                await sandbox.ResetAsync(session.Token).ConfigureAwait(false);
            }

            foreach (var step in steps)
            {
                if (session.Token.IsCancellationRequested)
                {
                    break;
                }

                await ExecuteStepAsync(session, step, engine).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (session.Token.IsCancellationRequested)
        {
        }
        finally
        {
            session.End();
        }
    }

    private async Task ExecuteStepAsync(PlaybookSession session, PlaybookStep step, string? engineOverride)
    {
        var watch = Stopwatch.StartNew();
        session.Running(step.Id);
        var results = new List<PlaybookEngineRun>();
        string? message = null;
        bool changedSandbox = false;
        try
        {
            // Put back even when applying fails half-way.
            changedSandbox = step.Sandbox is { Any: true } && sandbox.IsConnected;
            await ApplySandboxAsync(step.Sandbox, session.Token).ConfigureAwait(false);
            string format = step.Format ?? session.Playbook.Defaults.Format;
            var missing = new List<string>();
            var options = Resolve(Merge(session.Playbook.Defaults.Options, format, step.Options), session, missing);
            if (missing.Count > 0)
            {
                throw new InvalidOperationException($"Step {missing[0]} produced no file yet: run it first.");
            }

            string engine = engineOverride ?? step.Engine ?? session.Playbook.Defaults.Engine;
            foreach (string runEngine in engine == PlaybookEngines.Both ? [RunEngines.Library, RunEngines.Cli] : new[] { engine })
            {
                var request = new RunRequest(format, options, step.CrossValidate ?? session.Playbook.Defaults.CrossValidate,
                    step.Kind == PlaybookStepKinds.Validate ? RunKinds.Validate : RunKinds.Sign, runEngine);
                var view = await runs.RunAsync(request, session.Token).ConfigureAwait(false);
                results.Add(PlaybookExpectations.Evaluate(runEngine, view, step.Expect ?? new PlaybookExpectation()));
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Anything a step throws is its result: the run goes on with the next step.
            message = ex.Message;
        }
        finally
        {
            if (changedSandbox)
            {
                try
                {
                    await sandbox.ResetAsync(CancellationToken.None).ConfigureAwait(false);
                }
                catch (HttpRequestException ex)
                {
                    message ??= $"The Sandbox could not be put back: {ex.Message}";
                }
            }
        }

        bool passed = message is null && results.Count > 0 && results.All(r => r.Passed);
        session.Done(step.Id, new PlaybookStepResult(passed ? PlaybookStatuses.Passed : PlaybookStatuses.Failed, message, results, watch.ElapsedMilliseconds, DateTimeOffset.Now));
    }

    private async Task ApplySandboxAsync(PlaybookSandbox? box, CancellationToken cancellationToken)
    {
        if (box is not { Any: true })
        {
            return;
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
    }

    private static T Parse<T>(string? value, T fallback)
        where T : struct, Enum => value is not null && Enum.TryParse<T>(value, ignoreCase: true, out var parsed) ? parsed : fallback;

    private static string Key(Playbook? playbook, string json) =>
        playbook is null ? "" : playbook.Id + ":" + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(json)))[..12];

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

    /// <summary>
    /// The options with their symbolic values replaced: <c>sandbox:SIGNER</c> by a credential, <c>step:ID</c> by the file
    /// that step signed (the steps without one go to <paramref name="missing"/>), and the samples by their files.
    /// </summary>
    private JsonElement Resolve(JsonObject options, PlaybookSession session, List<string> missing)
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
                return session.Signer(signer, () => credentials.Add(factory.OpenSandbox(new SandboxCredentialRequest(signer))).Id);
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
                if (session.Output(stepId) is { } output)
                {
                    return output;
                }

                missing.Add(stepId);
                return null;
            }

            return null;
        }
    }

    private static (string Id, bool Data) SampleId(string value) =>
        value.EndsWith("#data", StringComparison.Ordinal) ? (value[..^"#data".Length], true) : (value, false);

    private async Task<IReadOnlyList<PreviewItem>> TargetAsync(string format, JsonElement effective, CancellationToken cancellationToken)
    {
        var rows = new List<PreviewItem> { new("format", "Format", format.ToUpperInvariant()) };
        if (format == RunFormats.Pades)
        {
            if (Text(effective, "documentId") is { } id && documents.TryGet(id, out _))
            {
                var facts = await documents.FactsAsync(id, cancellationToken).ConfigureAwait(false);
                rows.Add(new("document", "Document", $"{facts.FileName} ({facts.Size.ToString("N0", CultureInfo.InvariantCulture)} bytes, PDF {facts.PdfVersion})"));
                rows.Add(new("existingSignatures", "Signatures already in it", facts.Signatures.Count.ToString(CultureInfo.InvariantCulture)));
            }
        }
        else if (Text(effective, "dataId") is { } dataId && documents.TryGet(dataId, out var data))
        {
            rows.Add(new("data", "Data", $"{data!.FileName} ({data.Content.Length.ToString("N0", CultureInfo.InvariantCulture)} bytes)"));
        }

        return rows;
    }

    private static List<PreviewItem> SandboxRows(PlaybookSandbox? box)
    {
        var rows = new List<PreviewItem>();
        if (box is null)
        {
            return rows;
        }

        void Add(string key, string label, string? value)
        {
            if (value is not null)
            {
                rows.Add(new(key, label, value));
            }
        }

        Add("crl", "CRL", box.Crl);
        Add("ocsp", "OCSP", box.Ocsp);
        Add("tsa", "TSA", box.Tsa);
        Add("trustedList", "Trusted list", box.TrustedList);
        foreach (string id in box.Revoke)
        {
            rows.Add(new("revoke", "Revoke", id));
        }

        return rows;
    }

    private static IReadOnlyList<PreviewItem> SignerRows(CredentialFacts? signer, JsonObject asked)
    {
        if (signer is null)
        {
            return [new("signer", "Signer", "—")];
        }

        string? symbol = asked["credentialId"]?.GetValue<string>();
        var rows = new List<PreviewItem>();
        if (symbol is not null)
        {
            rows.Add(new("playbook", "Playbook", symbol));
        }

        rows.Add(new("subject", "Subject", signer.Subject));
        rows.Add(new("issuer", "Issuer", signer.Issuer));
        rows.Add(new("key", "Key", $"{signer.KeyAlgorithm} {signer.KeySize}"));
        rows.Add(new("valid", "Valid", $"{signer.NotBefore} → {signer.NotAfter}" + (signer.IsExpired ? " (expired)" : signer.IsNotYetValid ? " (not yet valid)" : "")));
        rows.Add(new("nonRepudiation", "nonRepudiation", signer.HasNonRepudiation ? "yes" : "no"));
        rows.Add(new("source", "Source", signer.Source));
        return rows;
    }

    /// <summary>The options of the Sign page for <paramref name="format"/>, grouped by its sections, as the run will use them.</summary>
    private IReadOnlyList<PreviewGroup> Groups(string format, JsonElement effective, JsonObject asked, IReadOnlyDictionary<string, OptionState> states)
    {
        var schema = OptionSchema.Localized();
        var defaults = schema.Defaults.TryGetValue(format, out var d) ? JsonSerializer.SerializeToElement(d, d.GetType(), WorkbenchJson.Options) : default;
        var askedElement = JsonSerializer.SerializeToElement(asked);
        var groups = new List<PreviewGroup>();
        foreach (var section in schema.Sections)
        {
            var settings = new List<PreviewSetting>();
            foreach (var option in schema.Options.Where(o => o.Section == section.Id && o.Path is not null && o.Formats.Contains(format)))
            {
                if (option.StateKey is { } key && states.TryGetValue(key, out var state) && !state.Visible)
                {
                    continue;
                }

                var value = Get(effective, option.Path!);
                if (value is null && option.Kind is "document" or "data" or "credential")
                {
                    continue;
                }

                bool fromPlaybook = Get(askedElement, option.Path!) is not null;
                var byDefault = Get(defaults, option.Path!);
                bool changed = !Same(value, byDefault);
                settings.Add(new(option.Id, option.Title, Display(option, value), fromPlaybook, changed));
            }

            if (settings.Count > 0)
            {
                groups.Add(new(section.Id, section.Title, settings));
            }
        }

        return groups;
    }

    private IReadOnlyList<PreviewSetting> ValidationSettingsRows(ValidationSettings settings, JsonObject asked)
    {
        var askedSettings = asked["settings"] as JsonObject;
        bool Asked(string name) => askedSettings?[name] is not null;
        string policy = settings.PolicyId is { } id && documents.TryGet(id, out var file) ? file!.FileName : "";
        return
        [
            new("trust", "Trusted roots", string.Join(", ", settings.Trust), Asked("trust"), true),
            new("policy", "Validation policy", policy, Asked("policyId"), settings.PolicyId is not null),
            new("level", "Validation level", settings.Level.ToString(), Asked("level"), settings.Level != SimpleSign.Core.Validation.ValidationLevel.ArchivalData),
            new("revocation", "Revocation first", settings.RevocationStrategy.ToString(), Asked("revocationStrategy"), false),
        ];
    }

    /// <summary>A value as the page shows it: a choice's title, a file's name, a signer's subject.</summary>
    private string Display(SchemaOption option, JsonElement? value)
    {
        if (value is not { } v || v.ValueKind is JsonValueKind.Null or JsonValueKind.Undefined)
        {
            return "—";
        }

        string Title(string raw) => option.Values.FirstOrDefault(x => string.Equals(x.Value, raw, StringComparison.OrdinalIgnoreCase))?.Title is { Length: > 0 } t ? t : raw;
        return v.ValueKind switch
        {
            JsonValueKind.True => "on",
            JsonValueKind.False => "off",
            JsonValueKind.Number => v.GetRawText(),
            JsonValueKind.Array => v.GetArrayLength() == 0 ? "—" : string.Join(", ", v.EnumerateArray().Select(e => e.ValueKind == JsonValueKind.String ? Title(e.GetString()!) : e.GetRawText())),
            JsonValueKind.String when option.Kind is "upload" or "document" or "data" && documents.TryGet(v.GetString()!, out var file) => file!.FileName,
            JsonValueKind.String when option.Kind == "credential" && credentials.TryGet(v.GetString(), out var credential) => credential!.Facts.Subject,
            JsonValueKind.String => v.GetString() is { Length: > 0 } s ? Title(s) : "—",
            _ => v.GetRawText(),
        };
    }

    private static JsonElement? Get(JsonElement root, string path)
    {
        if (root.ValueKind != JsonValueKind.Object)
        {
            return null;
        }

        var current = root;
        foreach (string part in path.Split('.'))
        {
            if (current.ValueKind != JsonValueKind.Object || !current.TryGetProperty(part, out current))
            {
                return null;
            }
        }

        return current;
    }

    private static string? Text(JsonElement root, string path) =>
        Get(root, path) is { ValueKind: JsonValueKind.String } v ? v.GetString() : null;

    private static bool Same(JsonElement? a, JsonElement? b) =>
        (a is null || a.Value.ValueKind == JsonValueKind.Null) && (b is null || b.Value.ValueKind == JsonValueKind.Null)
        || (a is { } x && b is { } y && JsonNode.DeepEquals(JsonNode.Parse(x.GetRawText()), JsonNode.Parse(y.GetRawText())));
}

/// <summary>A loaded playbook: its latest result per step, the Sandbox credentials it opened, and the run in progress.</summary>
internal sealed class PlaybookSession(string key, Playbook playbook, string json) : IDisposable
{
    private readonly Lock _gate = new();
    private readonly Dictionary<string, PlaybookStepResult> _results = new(StringComparer.Ordinal);
    private readonly Dictionary<string, string> _signers = new(StringComparer.Ordinal);
    private readonly HashSet<string> _queued = new(StringComparer.Ordinal);
    private CancellationTokenSource _cancel = new();
    private string? _running;
    private bool _active;
    private int _version;

    public string Key { get; } = key;

    public Playbook Playbook { get; } = playbook;

    /// <summary>The playbook file, kept with the evidence.</summary>
    public string Json { get; } = json;

    public CancellationToken Token
    {
        get
        {
            lock (_gate)
            {
                return _cancel.Token;
            }
        }
    }

    public bool IsRunning
    {
        get
        {
            lock (_gate)
            {
                return _active;
            }
        }
    }

    /// <summary>The latest results, by step id.</summary>
    public IReadOnlyDictionary<string, PlaybookStepResult> Results
    {
        get
        {
            lock (_gate)
            {
                return new Dictionary<string, PlaybookStepResult>(_results, StringComparer.Ordinal);
            }
        }
    }

    /// <summary>The credential of a Sandbox signer, opened once.</summary>
    public string Signer(string signer, Func<string> open)
    {
        lock (_gate)
        {
            if (!_signers.TryGetValue(signer, out string? id))
            {
                id = open();
                _signers[signer] = id;
            }

            return id;
        }
    }

    /// <summary>The file a step signed in its latest result, or null.</summary>
    public string? Output(string stepId)
    {
        lock (_gate)
        {
            return _results.TryGetValue(stepId, out var result) ? result.Runs.FirstOrDefault(r => r.OutputId is not null)?.OutputId : null;
        }
    }

    public void Begin(IEnumerable<string> steps)
    {
        lock (_gate)
        {
            if (_active)
            {
                throw new InvalidOperationException("A playbook is running: wait for it or stop it.");
            }

            _cancel.Dispose();
            _cancel = new CancellationTokenSource();
            _active = true;
            _queued.Clear();
            _queued.UnionWith(steps);
            _version++;
        }
    }

    public void Running(string stepId)
    {
        lock (_gate)
        {
            _running = stepId;
            _version++;
        }
    }

    public void Done(string stepId, PlaybookStepResult result)
    {
        lock (_gate)
        {
            _results[stepId] = result;
            _queued.Remove(stepId);
            _running = null;
            _version++;
        }
    }

    public void Cancel()
    {
        lock (_gate)
        {
            _cancel.Cancel();
        }
    }

    /// <summary>Drops a step's result, or all of them; the Sandbox credentials opened stay cached.</summary>
    /// <exception cref="InvalidOperationException">A run is going.</exception>
    public void Clear(string? stepId)
    {
        lock (_gate)
        {
            if (_active)
            {
                throw new InvalidOperationException("Wait for the run to end (or stop it) before clearing results.");
            }

            if (stepId is null)
            {
                _results.Clear();
            }
            else
            {
                _results.Remove(stepId);
            }

            _version++;
        }
    }

    public void End()
    {
        lock (_gate)
        {
            _active = false;
            _running = null;
            _queued.Clear();
            _version++;
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            _cancel.Dispose();
        }
    }

    public PlaybookStateView View()
    {
        lock (_gate)
        {
            var steps = Playbook.AllSteps().Select(s =>
            {
                _results.TryGetValue(s.Step.Id, out var result);
                string status = _running == s.Step.Id ? PlaybookStatuses.Running
                    : _queued.Contains(s.Step.Id) ? PlaybookStatuses.Queued
                    : result?.Status ?? PlaybookStatuses.Pending;
                return new PlaybookStepView(s.Section.Id, s.Step.Id, s.Step.Title, s.Step.Kind, s.Step.Tags, status, result);
            }).ToList();
            return new PlaybookStateView(Key, Playbook.Id, Playbook.Title, _active, _running, _version, steps);
        }
    }
}

using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Serialization;
using SimpleSign.Core.Http;
using SimpleSign.Core.Signing;
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
/// <param name="Format">pades, cades or xades (ignored for a validation run).</param>
/// <param name="Options">The format's options.</param>
/// <param name="CrossValidate">Whether DSS validates the output too.</param>
/// <param name="Kind">Sign or validate.</param>
/// <param name="Engine">How the signature is made: <see cref="RunEngines.Library"/> (default) or <see cref="RunEngines.Cli"/>.</param>
public sealed record RunRequest(string Format, JsonElement Options, bool CrossValidate = false, string Kind = RunKinds.Sign, string Engine = RunEngines.Library);

/// <summary>What a run does: make a signature, validate a file that already exists, or raise its level.</summary>
public static class RunKinds
{
    public const string Sign = "sign";
    public const string Validate = "validate";
    public const string Augment = "augment";
}

/// <summary>
/// The options of an augmentation run: the signed file (and the data of a detached signature), the level to reach
/// (<c>BT</c>, <c>BLT</c>, <c>BLTA</c>), the TSA, whether to renew a B-LTA's archive time-stamp, and how the result
/// is validated.
/// </summary>
public sealed record AugmentOptions(
    string FileId,
    string? DataId = null,
    string Level = "BLTA",
    TimestampChoice? Timestamp = null,
    bool Renew = false,
    Validation.ValidationSettings? Validation = null);

/// <summary>The options of a validation run: the file, the data of a detached signature, and the trust.</summary>
public sealed record ValidateOptions(string FileId, string? DataId = null, Validation.ValidationSettings? Settings = null);

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
    bool IsTimestamp = false,
    string? SubIndication = null,
    IReadOnlyList<FindingView>? Findings = null)
{
    /// <summary>The ETSI indication (EN 319 102-1 §5.1.3): TOTAL_PASSED, TOTAL_FAILED or INDETERMINATE.</summary>
    public string EtsiIndication => Indication switch
    {
        "Valid" => "TOTAL_PASSED",
        "Invalid" => "TOTAL_FAILED",
        _ => "INDETERMINATE",
    };

    /// <summary>The library's report entry of this signature, for the SimpleSign report (not sent to the UI).</summary>
    [JsonIgnore]
    public Reports.ReportSource? Source { get; init; }
}

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
    IReadOnlyList<RunLogEntry> Logs,
    string Kind = RunKinds.Sign,
    string? ReportId = null,
    string Engine = RunEngines.Library,
    IReadOnlyList<CliStep>? Cli = null,
    string? EtsiReportId = null);

/// <summary>A row of the run history.</summary>
public sealed record RunSummary(string Id, string Format, string Status, DateTimeOffset StartedAt, long TotalMs, bool Success, string? RequestedLevel, string? AchievedLevel, string? Overall, string? FileName, string? Error, string Kind = RunKinds.Sign, string Engine = RunEngines.Library);

/// <summary>What the events stream sends: a log line while the run is going, then the finished run.</summary>
public sealed record RunEvent(string Type, RunLogEntry? Log, RunView? Run);

/// <summary>One run: its log and, when finished, its result. Readers follow it with <see cref="Read"/>.</summary>
internal sealed class Run(string id, string format, JsonElement options, string kind = RunKinds.Sign, string engine = RunEngines.Library)
{
    public string Kind { get; } = kind;

    /// <summary>How the signature is made and validated: through the library or the CLI.</summary>
    public string Engine { get; } = engine;

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
    CrossValidation.DssClient dss,
    Validation.ValidationService validation,
    Documents.DocumentStore documents,
    Sandbox.SandboxEnvironment? sandbox = null)
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
        string format = request.Format;
        if (request.Kind == RunKinds.Augment)
        {
            var options = request.Options.Deserialize<AugmentOptions>(WorkbenchJson.Options);
            if (options?.FileId is null || !documents.TryGet(options.FileId, out var signed))
            {
                throw new ArgumentException(L.T("Choose a file to augment."), nameof(request));
            }

            format = Validation.FormatDetector.Detect(signed!.Content);
            if (request.Engine == RunEngines.Cli)
            {
                throw new ArgumentException(L.T("Augmentation runs through the library."), nameof(request));
            }
        }
        else if (request.Kind == RunKinds.Validate)
        {
            // The file says what it is: validation needs no format choice.
            var options = request.Options.Deserialize<ValidateOptions>(WorkbenchJson.Options);
            if (options?.FileId is null || !documents.TryGet(options.FileId, out var file))
            {
                throw new ArgumentException(L.T("Choose a file to validate."), nameof(request));
            }

            format = Validation.FormatDetector.Detect(file!.Content);
        }
        else if (!RunFormats.All.Contains(format))
        {
            throw new ArgumentException(L.T("Unknown format: {0}. Use pades, cades or xades.", request.Format), nameof(request));
        }

        string engine = request.Engine ?? RunEngines.Library;
        if (!RunEngines.All.Contains(engine))
        {
            throw new ArgumentException(L.T("Unknown engine: {0}. Use library or cli.", engine), nameof(request));
        }

        // The engine makes and validates the signature: the library in this process, or the simplesign CLI.
        var run = new Run(Guid.NewGuid().ToString("N")[..12], format, request.Options.Clone(), request.Kind, engine);
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
                view = run.Kind == RunKinds.Augment ? await AugmentAsync(run) : run.Kind == RunKinds.Validate ? await ValidateAsync(run) : run.Format switch
                {
                    RunFormats.Cades => FromCades(run, await cades.RunAsync(Options<CadesOptions>(run), run.Engine, CancellationToken.None)),
                    RunFormats.Xades => FromXml(run, await xml.RunAsync(Options<XmlOptions>(run), run.Engine, CancellationToken.None)),
                    _ => FromPades(run, await pades.RunAsync(Options<SigningOptions>(run), run.Engine, CancellationToken.None)),
                };
                view = view with { ReportId = view.ReportId ?? StoreReport(view), EtsiReportId = view.EtsiReportId ?? StoreEtsiReport(view, run) };
                if (crossValidate && view.Success && view.OutputId is not null && view.Validation.Count > 0)
                {
                    view = view with
                    {
                        CrossValidation = await dss.CompareAsync(run.Format, view, DetachedDataId(run), DetachedDataName(run, view), logger, CancellationToken.None,
                            PolicyUploads.Validation(ValidationSettingsOf(run).PolicyId, documents)),
                    };
                }
            }
            catch (Exception ex) when (ex is JsonException or InvalidOperationException or ArgumentException or KeyNotFoundException)
            {
                view = Empty(run) with { Error = ex.Message, ErrorType = SigningRunner.ErrorTypeOf(ex) };
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

    /// <summary>
    /// Writes SimpleSign's JSON report of the run's verdicts (the library's simple report, with each signature's chain and
    /// constraints) next to the output, and returns its id; null when nothing was validated.
    /// </summary>
    private string? StoreReport(RunView view)
    {
        var sources = Flatten(view.Validation).Select(v => v.Source).OfType<Reports.ReportSource>().ToList();
        if (sources.Count == 0)
        {
            return null;
        }

        var pool = new List<System.Security.Cryptography.X509Certificates.X509Certificate2>();
        if (view.OutputId is { } id && documents.TryGet(id, out var output))
        {
            pool.AddRange(Reports.SimpleSignReport.CertificatesIn(output!.Content));
        }

        if (validation.SandboxRoot is { } root)
        {
            pool.Add(root);
        }

        string json = Reports.SimpleSignReport.Build(sources, view.FileName, pool);
        return documents.Add(Reports.SimpleSignReport.FileName(view.FileName), System.Text.Encoding.UTF8.GetBytes(json)).Id;
    }

    /// <summary>
    /// The ETSI TS 119 102-2 report of a library run (a CLI run writes its own with <c>--etsi-report</c>), from the same
    /// report entries as the JSON report; null when nothing was validated.
    /// </summary>
    private string? StoreEtsiReport(RunView view, Run run)
    {
        var entries = Flatten(view.Validation).Select(v => v.Source).OfType<Reports.ReportSource>().Select(s => s.Entry).ToList();
        if (entries.Count == 0)
        {
            return null;
        }

        string xml = SimpleSign.Core.Validation.ValidationReports.ToEtsiXml(entries, ValidationSettingsOf(run).Level);
        string stem = Path.GetFileNameWithoutExtension(view.FileName ?? "signature");
        return documents.Add(stem + "-etsi-report.xml", System.Text.Encoding.UTF8.GetBytes(xml)).Id;
    }

    private static IEnumerable<RunVerdict> Flatten(IEnumerable<RunVerdict> verdicts) =>
        verdicts.SelectMany(v => new[] { v }.Concat(Flatten(v.Children)));

    /// <summary>The validation settings of a run: the settings of a validation run, or the validation step of a signing run.</summary>
    private static Validation.ValidationSettings ValidationSettingsOf(Run run) =>
        run.Kind == RunKinds.Validate
            ? Options<ValidateOptions>(run).Settings ?? new Validation.ValidationSettings()
            : run.Options.TryGetProperty("validation", out var settings) && settings.ValueKind == JsonValueKind.Object
                ? settings.Deserialize<Validation.ValidationSettings>(WorkbenchJson.Options) ?? new Validation.ValidationSettings()
                : new Validation.ValidationSettings();

    private static T Options<T>(Run run) =>
        run.Options.Deserialize<T>(WorkbenchJson.Options) ?? throw new JsonException(L.T("The run has no options."));

    /// <summary>The data a detached signature covers, which an external validator needs next to the signature.</summary>
    private static string? DetachedDataId(Run run) =>
        run.Format != RunFormats.Pades && run.Options.TryGetProperty("dataId", out var data) && data.ValueKind == JsonValueKind.String
            ? data.GetString()
            : null;

    /// <summary>
    /// The name a detached XAdES signature refers to its data by (the Reference URI): an external
    /// validator matches the original document to the reference by this name.
    /// </summary>
    private string? DetachedDataName(Run run, RunView view) =>
        run.Format != RunFormats.Xades ? null
            : run.Kind == RunKinds.Sign && run.Options.TryGetProperty("dataUri", out var uri) && uri.ValueKind == JsonValueKind.String ? uri.GetString()
            : view.OutputId is { } id && documents.TryGet(id, out var file) ? Validation.FormatDetector.DetachedReferenceUri(file!.Content)
            : null;

    /// <summary>
    /// Raises the level of an existing signature with the format's augmenter (<c>PadesAugmenter</c>,
    /// <c>CadesAugmenter</c>, <c>XadesAugmenter</c>), then validates the result as a validation run would.
    /// </summary>
    private async Task<RunView> AugmentAsync(Run run)
    {
        var options = Options<AugmentOptions>(run);
        var file = documents.Get(options.FileId);
        byte[]? data = options.DataId is { } dataId ? documents.Get(dataId).Content : null;
        var target = options.Level.ToUpperInvariant().Replace("-", "", StringComparison.Ordinal) switch
        {
            "BT" => AdesBaselineLevel.Timestamped,
            "BLT" => AdesBaselineLevel.LongTerm,
            _ => AdesBaselineLevel.Archive,
        };
        IHttpClientProvider http = sandbox is { IsConnected: true } ? sandbox : DefaultHttpClientProvider.Instance;
        var timestamp = TimestampOf(options.Timestamp ?? new TimestampChoice(), http);
        var watch = Stopwatch.StartNew();
        byte[] output;
        AdesBaselineLevel initial, reached;
        try
        {
            switch (run.Format)
            {
                case RunFormats.Cades:
                    var cadesAugmenter = CAdES.CadesAugmenter.Signature(file.Content, data).WithHttpClientProvider(http).WithTimestamp(timestamp)
                        .ToLevel(target).WithLogger(RunLog.Logger);
                    var cadesResult = await (options.Renew ? cadesAugmenter.RenewArchive() : cadesAugmenter).AugmentAsync();
                    (output, initial, reached) = (cadesResult.Signature, cadesResult.InitialLevel, cadesResult.Level);
                    break;
                case RunFormats.Xades:
                    var xadesAugmenter = XAdES.XadesAugmenter.Document(file.Content, data).WithHttpClientProvider(http).WithTimestamp(timestamp)
                        .ToLevel(target).WithLogger(RunLog.Logger);
                    var xadesResult = await (options.Renew ? xadesAugmenter.RenewArchive() : xadesAugmenter).AugmentAsync();
                    (output, initial, reached) = (xadesResult.Document, xadesResult.InitialLevel, xadesResult.Level);
                    break;
                default:
                    var padesAugmenter = PAdES.PadesAugmenter.Document(file.Content).WithHttpClientProvider(http).WithTimestamp(timestamp)
                        .ToLevel(target).WithLogger(RunLog.Logger);
                    var padesResult = await (options.Renew ? padesAugmenter.RenewArchive() : padesAugmenter).AugmentAsync();
                    (output, initial, reached) = (padesResult.Document, padesResult.InitialLevel, padesResult.Level);
                    break;
            }
        }
        catch (Exception ex) when (ex is SigningException or ArgumentException or System.Security.Cryptography.CryptographicException)
        {
            RunLog.Logger.LogWarning("Augmentation stopped: {Message}", ex.Message);
            return Empty(run) with { Error = ex.Message, ErrorType = SigningRunner.ErrorTypeOf(ex), SignMs = watch.ElapsedMilliseconds };
        }

        RunLog.Logger.LogInformation("Augmented {Format} {From} to {To}", run.Format, LevelName(initial), LevelName(reached));
        string name = Path.GetFileNameWithoutExtension(file.FileName) + "-augmented" + Path.GetExtension(file.FileName);
        var stored = documents.Add(name, output);
        var validation = new Run(run.Id, run.Format,
            JsonSerializer.SerializeToElement(new ValidateOptions(stored.Id, options.DataId, options.Validation), WorkbenchJson.Options),
            RunKinds.Validate, RunEngines.Library);
        var view = await ValidateAsync(validation);
        return view with
        {
            Kind = RunKinds.Augment,
            Options = run.Options,
            OutputId = stored.Id,
            FileName = stored.FileName,
            Bytes = output.Length,
            RequestedLevel = LevelName(target),
            AchievedLevel = LevelName(reached),
            SignMs = watch.ElapsedMilliseconds,
        };
    }

    private static string LevelName(AdesBaselineLevel level) => level switch
    {
        AdesBaselineLevel.Archive => "B-LTA",
        AdesBaselineLevel.LongTerm => "B-LT",
        AdesBaselineLevel.Timestamped => "B-T",
        _ => "B-B",
    };

    /// <summary>The TSA of an augmentation: the connected Sandbox's TSAs by name, or a URL.</summary>
    private TimestampOptions TimestampOf(TimestampChoice choice, IHttpClientProvider http)
    {
        var connection = sandbox?.Current;
        Uri endpoint = choice.Provider switch
        {
            TsaProvider.Sandbox when connection is not null => connection.TsaUri,
            TsaProvider.SandboxRevoked when connection is not null => connection.RevokedTsaUri,
            TsaProvider.SandboxUntrusted when connection is not null => connection.UntrustedTsaUri,
            TsaProvider.SandboxExpired when connection is not null => connection.ExpiredTsaUri,
            TsaProvider.SandboxWrongName when connection is not null => connection.WrongNameTsaUri,
            TsaProvider.SandboxShortLived when connection is not null => connection.ShortLivedTsaUri,
            TsaProvider.SandboxIofe when connection is not null => connection.IofeTsaUri,
            TsaProvider.DigiCert => TimestampOptions.DigiCert.Endpoint,
            TsaProvider.Sectigo => TimestampOptions.Sectigo.Endpoint,
            TsaProvider.FreeTsa => TimestampOptions.FreeTsa.Endpoint,
            _ when choice.Url is { Length: > 0 } url => new Uri(url),
            _ => throw new ArgumentException(L.T("Choose a TSA for the augmentation.")),
        };
        return new TimestampOptions(endpoint, http);
    }

    /// <summary>Validates an existing file with the validator of its format, in the same shape as a signing run.</summary>
    private async Task<RunView> ValidateAsync(Run run)
    {
        var options = Options<ValidateOptions>(run);
        var file = documents.Get(options.FileId);
        var settings = options.Settings ?? new Validation.ValidationSettings();
        var view = Empty(run) with { OutputId = options.FileId, FileName = file.FileName, Bytes = file.Content.Length };
        bool cli = run.Engine == RunEngines.Cli;
        switch (run.Format)
        {
            case RunFormats.Cades:
                {
                    CliOutcome? outcome = null;
                    var report = cli
                        ? await Through(cades.ValidateWithCliAsync(options.FileId, options.DataId, settings), o => outcome = o)
                        : await cades.ValidateAsync(options.FileId, options.DataId, settings);
                    var reports = Validation.CliValidation.Store(outcome, documents, file.FileName);
                    return view with
                    {
                        Success = true,
                        ValidateMs = report.Ms,
                        Code = report.Code,
                        Overall = report.Overall,
                        Warnings = report.Errors,
                        Validation = [.. report.Signers.Select(Verdict)],
                        Detail = report,
                        Cli = outcome?.Steps,
                        ReportId = reports.SimpleId,
                        EtsiReportId = reports.EtsiId,
                    };
                }

            case RunFormats.Xades:
                {
                    CliOutcome? outcome = null;
                    var report = cli
                        ? await Through(xml.ValidateWithCliAsync(options.FileId, options.DataId, settings), o => outcome = o)
                        : await xml.ValidateAsync(options.FileId, options.DataId, settings);
                    var reports = Validation.CliValidation.Store(outcome, documents, file.FileName);
                    return view with
                    {
                        Success = true,
                        ValidateMs = report.Ms,
                        Code = report.Code,
                        Overall = report.Overall,
                        Warnings = report.Errors,
                        AchievedLevel = report.Signatures.LastOrDefault()?.Level,
                        Validation = [.. report.Signatures.Select(Verdict)],
                        Detail = report,
                        Cli = outcome?.Steps,
                        ReportId = reports.SimpleId,
                        EtsiReportId = reports.EtsiId,
                    };
                }

            default:
                {
                    CliOutcome? outcome = null;
                    var report = cli
                        ? await Through(validation.CliReportAsync(options.FileId, settings, CancellationToken.None), o => outcome = o)
                        : await validation.ReportAsync(options.FileId, settings, CancellationToken.None);
                    var reports = Validation.CliValidation.Store(outcome, documents, file.FileName);
                    return view with
                    {
                        Success = report.Error is null,
                        Error = report.Error,
                        ErrorType = report.Error is null ? null : "Validation",
                        ValidateMs = report.Ms,
                        Code = report.Code,
                        Overall = report.Overall is "NoSignatures" or "Error" ? null : report.Overall,
                        Warnings = report.Overall == "NoSignatures" ? [L.T("This PDF has no signature.")] : [],
                        AchievedLevel = report.Signatures.LastOrDefault(s => !s.Report.IsDocumentTimestamp)?.PadesLevel,
                        Validation = [.. report.Signatures.Select(s => Verdict(s.Report))],
                        Detail = report,
                        Cli = outcome?.Steps,
                        ReportId = reports.SimpleId,
                        EtsiReportId = reports.EtsiId,
                    };
                }
        }
    }

    /// <summary>The view of a validation through the CLI, handing its outcome (the commands, the reports) to <paramref name="keep"/>.</summary>
    private static async Task<T> Through<T>(Task<(T View, CliOutcome? Outcome)> validation, Action<CliOutcome?> keep)
    {
        var (view, outcome) = await validation;
        keep(outcome);
        return view;
    }

    private static RunVerdict Verdict(SignatureReport v) =>
        new(v.FieldName, v.Signer, v.Indication, null, v.SigningTime, v.Checks, v.Errors, v.Warnings, [], v.IsDocumentTimestamp, v.SubIndication, v.Findings)
        {
            Source = v.Source,
        };

    private static RunVerdict Verdict(XmlSignatureReport s) => new(
        s.Reference ?? L.T("Signature {0}", s.Index + 1), s.Signer, s.Indication, s.Level, s.SigningTime, s.Checks, s.Errors, s.Warnings, [],
        SubIndication: s.SubIndication, Findings: s.Findings)
    {
        Source = s.Source,
    };

    private static RunView Empty(Run run) => new(
        run.Id, run.Format, "running", run.StartedAt, 0, run.Options, false, null, null, null, null, 0, null, null,
        [], 0, 0, null, [], null, [], null, null, [], run.Kind, Engine: run.Engine);

    private static RunSummary Summary(Run run) => run.Result is { } r
        ? new RunSummary(run.Id, run.Format, r.Status, run.StartedAt, r.TotalMs, r.Success, r.RequestedLevel, r.AchievedLevel, r.Overall, r.FileName, r.Error, run.Kind, run.Engine)
        : new RunSummary(run.Id, run.Format, "running", run.StartedAt, 0, false, null, null, null, null, null, run.Kind, run.Engine);

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
        Validation = [.. r.Validation.Select(Verdict)],
        Detail = r,
        Cli = r.Cli,
        ReportId = r.Reports?.SimpleId,
        EtsiReportId = r.Reports?.EtsiId,
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
        Cli = r.Cli,
        ReportId = r.Reports?.SimpleId,
        EtsiReportId = r.Reports?.EtsiId,
    };

    private static RunVerdict Verdict(CadesSignerReport s) => new(
        L.T("Signer {0}", s.Index + 1), s.Signer, s.Indication, null, s.SigningTime, s.Checks, s.Errors, s.Warnings,
        [.. s.CounterSignatures.Select(Verdict)], SubIndication: s.SubIndication, Findings: s.Findings)
    {
        Source = s.Source,
    };

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
        Validation = [.. (r.Validation?.Signatures ?? []).Select(Verdict)],
        Detail = r,
        Cli = r.Cli,
        ReportId = r.Reports?.SimpleId,
        EtsiReportId = r.Reports?.EtsiId,
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

using Microsoft.Extensions.Logging.Abstractions;

namespace SimpleSign.TestBench.Runs;

/// <summary>One line of a run's log: a library log event or a network request, placed on the run's timeline.</summary>
/// <param name="Seq">Position in the run (0-based).</param>
/// <param name="Ms">Milliseconds since the run started.</param>
/// <param name="Level">Trace, Debug, Information, Warning, Error or Critical.</param>
/// <param name="EventId">The library's log EventId (0 for network requests).</param>
/// <param name="Source">"library" or "network".</param>
/// <param name="Stage">The signing stage the event belongs to (a <see cref="RunStages"/> id).</param>
/// <param name="Message">The formatted message.</param>
public sealed record RunLogEntry(int Seq, long Ms, string Level, int EventId, string Source, string Stage, string Message);

/// <summary>
/// The ambient logger of the run in progress. The runners pass <see cref="Logger"/> to every
/// builder and validator, so each run collects exactly its own log without threading a logger
/// through every method.
/// </summary>
internal static class RunLog
{
    private static readonly AsyncLocal<RunLogger?> s_current = new();

    /// <summary>The logger of the run in progress, or a no-op logger outside a run.</summary>
    public static ILogger Logger => s_current.Value ?? (ILogger)NullLogger.Instance;

    /// <summary>The run's recorder, or null outside a run.</summary>
    public static RunLogger? Current => s_current.Value;

    /// <summary>Makes <paramref name="logger"/> the ambient logger until the returned scope is disposed.</summary>
    public static IDisposable Begin(RunLogger logger)
    {
        var previous = s_current.Value;
        s_current.Value = logger;
        return new Scope(previous);
    }

    private sealed class Scope(RunLogger? previous) : IDisposable
    {
        public void Dispose() => s_current.Value = previous;
    }
}

/// <summary>Gives the run's logger to APIs that ask for an <see cref="ILogger{T}"/>.</summary>
internal sealed class RunLogger<T>(ILogger inner) : ILogger<T>
{
    public IDisposable? BeginScope<TState>(TState state)
        where TState : notnull => inner.BeginScope(state);

    public bool IsEnabled(LogLevel logLevel) => inner.IsEnabled(logLevel);

    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) =>
        inner.Log(logLevel, eventId, state, exception, formatter);
}

/// <summary>Records every log event of one run and tells the run when a new one arrives.</summary>
internal sealed class RunLogger(Action<RunLogEntry> onEntry) : ILogger
{
    private readonly System.Diagnostics.Stopwatch _watch = System.Diagnostics.Stopwatch.StartNew();
    private readonly Lock _gate = new();
    private readonly List<RunLogEntry> _entries = [];

    public IReadOnlyList<RunLogEntry> Entries
    {
        get
        {
            lock (_gate)
            {
                return [.. _entries];
            }
        }
    }

    public IDisposable? BeginScope<TState>(TState state)
        where TState : notnull => null;

    public bool IsEnabled(LogLevel logLevel) => logLevel != LogLevel.None;

    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
    {
        string message = formatter(state, exception);
        if (exception is not null)
        {
            message += $" ({exception.GetType().Name}: {exception.Message})";
        }

        Add(logLevel.ToString(), eventId.Id, "library", RunStages.Of(eventId.Id), message);
    }

    /// <summary>Adds a network request (TSA, CRL, OCSP, AIA, PSC, CSC) to the timeline.</summary>
    public void Network(string method, string url, int status, string service) =>
        Add(status >= 400 ? "Warning" : "Information", 0, "network", RunStages.Network, $"{service}: {method} {url} → {status}");

    /// <summary>Adds a line written by the TestBench itself (for example the DSS call).</summary>
    public void Note(string stage, string message, bool warning = false) =>
        Add(warning ? "Warning" : "Information", 0, "testbench", stage, message);

    private void Add(string level, int eventId, string source, string stage, string message)
    {
        RunLogEntry entry;
        lock (_gate)
        {
            entry = new RunLogEntry(_entries.Count, _watch.ElapsedMilliseconds, level, eventId, source, stage, message);
            _entries.Add(entry);
        }

        onEntry(entry);
    }
}

/// <summary>The stages of a signature, in order, and which library EventIds belong to each.</summary>
public static class RunStages
{
    public const string Prepare = "prepare";
    public const string Digest = "digest";
    public const string SignedAttributes = "signed-attributes";
    public const string Signature = "signature";
    public const string Timestamp = "timestamp";
    public const string ValidationData = "validation-data";
    public const string Archive = "archive";
    public const string Finish = "finish";
    public const string Validation = "validation";
    public const string CrossValidation = "cross-validation";
    public const string Network = "network";
    public const string Other = "other";

    /// <summary>Every stage, in the order a signature goes through them.</summary>
    public static IReadOnlyList<string> All { get; } =
        [Prepare, Digest, SignedAttributes, Signature, Timestamp, ValidationData, Archive, Finish, Validation, CrossValidation, Network, Other];

    /// <summary>The stage of a library EventId (see the Log classes of each library project).</summary>
    public static string Of(int eventId) => eventId switch
    {
        // PAdES pipeline, PDF reader and writer; XAdES and CAdES start and algorithm.
        1000 or (>= 1002 and <= 1004) or 1030 or (>= 3010 and <= 3027) or 5000 or 5001 or 5002
            or 6000 or 6001 or 7000 or 7002 or 7100 or 7102 => Prepare,
        4000 or 4001 or 5003 or 7004 => Digest,
        4002 or 7003 or 7103 => SignedAttributes,
        (>= 4003 and <= 4006) or 5004 or 5005 or 6002 or (>= 6010 and <= 6012) or (>= 7005 and <= 7008)
            or 7104 or 7105 or 7130 or 7131 or (>= 7200 and <= 7399) => Signature,
        1010 or 1011 or (>= 2710 and <= 2719) or (>= 7010 and <= 7012) or (>= 7110 and <= 7112) => Timestamp,
        1020 or 1023 or 1024 or (>= 2400 and <= 2699) or (>= 2910 and <= 2913) or 3410 or 3510 or 3600
            or (>= 7020 and <= 7024) or (>= 7120 and <= 7124) => ValidationData,
        1021 or 1022 or 5010 or 5011 or (>= 7025 and <= 7027) or (>= 7125 and <= 7127) => Archive,
        1001 or 1005 or 7001 or 7028 or 7101 or 7128 => Finish,
        (>= 2000 and <= 2399) or (>= 2810 and <= 2817) or (>= 3100 and <= 3399) or 3500 or (>= 3610 and <= 3613)
            or 7050 or 7051 => Validation,
        _ => Other,
    };
}

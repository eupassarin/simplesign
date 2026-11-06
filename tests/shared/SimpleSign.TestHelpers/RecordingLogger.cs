using Microsoft.Extensions.Logging;

namespace SimpleSign.TestHelpers;

/// <summary>An <see cref="ILogger"/> that keeps every entry, for tests that assert on what was logged.</summary>
public sealed class RecordingLogger : ILogger
{
    private readonly List<(LogLevel Level, int EventId, string Message)> _entries = [];

    /// <summary>Every entry logged so far, in order.</summary>
    public IReadOnlyList<(LogLevel Level, int EventId, string Message)> Entries
    {
        get
        {
            lock (_entries)
            {
                return [.. _entries];
            }
        }
    }

    /// <summary>The event IDs logged so far, in order.</summary>
    public IReadOnlyList<int> EventIds => [.. Entries.Select(e => e.EventId)];

    /// <inheritdoc />
    public IDisposable? BeginScope<TState>(TState state)
        where TState : notnull => null;

    /// <inheritdoc />
    public bool IsEnabled(LogLevel logLevel) => true;

    /// <inheritdoc />
    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
        Func<TState, Exception?, string> formatter)
    {
        ArgumentNullException.ThrowIfNull(formatter);
        lock (_entries)
        {
            _entries.Add((logLevel, eventId.Id, formatter(state, exception)));
        }
    }
}

using Microsoft.Extensions.Logging;

namespace SimpleSign.Cli;

/// <summary>
/// Minimal ILogger implementation that writes to stderr with colored level prefixes.
/// AOT-safe — no reflection, no NuGet dependencies.
/// </summary>
internal class CliConsoleLogger(string categoryName, LogLevel minLevel) : ILogger
{
    public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

    public bool IsEnabled(LogLevel logLevel) => logLevel >= minLevel;

    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
    {
        if (!IsEnabled(logLevel))
        {
            return;
        }

        var (prefix, color) = logLevel switch
        {
            LogLevel.Trace => ("TRC", ConsoleColor.DarkGray),
            LogLevel.Debug => ("DBG", ConsoleColor.Gray),
            LogLevel.Information => ("INF", ConsoleColor.Cyan),
            LogLevel.Warning => ("WRN", ConsoleColor.Yellow),
            LogLevel.Error => ("ERR", ConsoleColor.Red),
            LogLevel.Critical => ("CRT", ConsoleColor.DarkRed),
            _ => ("???", ConsoleColor.White)
        };

        var shortCategory = ExtractShortName(categoryName);
        var message = formatter(state, exception);

        var prev = Console.ForegroundColor;
        Console.ForegroundColor = color;
        Console.Error.Write($"[{prefix}]");
        Console.ForegroundColor = prev;
        Console.Error.WriteLine($" {shortCategory}: {message}");

        if (exception is not null)
        {
            Console.Error.WriteLine($"       {exception.GetType().Name}: {exception.Message}");
        }
    }

    private static string ExtractShortName(string fullName)
    {
        var lastDot = fullName.LastIndexOf('.');
        return lastDot >= 0 ? fullName[(lastDot + 1)..] : fullName;
    }
}

/// <summary>
/// Minimal ILoggerFactory that creates <see cref="CliConsoleLogger"/> instances.
/// </summary>
internal sealed class CliConsoleLoggerFactory(LogLevel minLevel) : ILoggerFactory
{
    public ILogger CreateLogger(string categoryName) => new CliConsoleLogger(categoryName, minLevel);

    public void AddProvider(ILoggerProvider provider) { }

    public void Dispose() { }
}

/// <summary>
/// Typed logger wrapper for APIs that require <see cref="ILogger{T}"/>.
/// Delegates to <see cref="CliConsoleLogger"/>.
/// </summary>
internal sealed class CliConsoleLogger<T>(LogLevel minLevel) : CliConsoleLogger(typeof(T).FullName ?? typeof(T).Name, minLevel), ILogger<T>;

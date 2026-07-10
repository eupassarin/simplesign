using System.ComponentModel;
using Microsoft.Extensions.Logging;
using Spectre.Console.Cli;

namespace SimpleSign.Cli.Commands;

/// <summary>Common settings shared across CLI commands.</summary>
internal class CommonSettings : CommandSettings
{
    /// <summary>Enable detailed logging (writes to stderr).</summary>
    [CommandOption("--verbose|-v")]
    [Description("Enable detailed logging (writes to stderr)")]
    public bool Verbose { get; init; }

    public ILoggerFactory? CreateLoggerFactory() => Verbose ? new CliConsoleLoggerFactory(LogLevel.Debug) : null;

    public ILogger<T>? CreateLogger<T>() => Verbose ? new CliConsoleLogger<T>(LogLevel.Debug) : null;

    /// <summary>Reads input bytes from a file path, or from stdin if path is "-".</summary>
    internal static async Task<byte[]> ReadInputBytesAsync(string path, CancellationToken ct = default)
    {
        if (path == "-")
        {
            using var ms = new MemoryStream();
            using var stdin = Console.OpenStandardInput();
            await stdin.CopyToAsync(ms, ct);
            return ms.ToArray();
        }
        return await File.ReadAllBytesAsync(path, ct);
    }
}

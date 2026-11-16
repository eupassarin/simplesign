using System.ComponentModel;
using System.Diagnostics;

namespace SimpleSign.TestHelpers;

/// <summary>What an external program printed and how it ended.</summary>
/// <param name="ExitCode">The process exit code.</param>
/// <param name="Stdout">Everything written to standard output.</param>
/// <param name="Stderr">Everything written to standard error.</param>
public sealed record ExternalProcessResult(int ExitCode, string Stdout, string Stderr)
{
    /// <summary>Both streams, for an assertion message.</summary>
    public string Output => $"exit code {ExitCode}\nstdout:\n{Stdout}\nstderr:\n{Stderr}";
}

/// <summary>
/// Runs a program the tests compare SimpleSign with (veraPDF, qpdf, OpenSSL, xmlsec1, pyHanko): arguments passed as a
/// list (no shell quoting), both output streams drained at once, killed after a timeout.
/// </summary>
public static class ExternalProcess
{
    /// <summary>The default time a program is given before it is killed.</summary>
    public static readonly TimeSpan DefaultTimeout = TimeSpan.FromMinutes(3);

    /// <summary>Runs <paramref name="command"/> with <paramref name="args"/> and waits for it to end.</summary>
    /// <exception cref="TimeoutException">The program did not end within <paramref name="timeout"/>.</exception>
    public static async Task<ExternalProcessResult> RunAsync(
        string command, IEnumerable<string> args, TimeSpan? timeout = null, CancellationToken cancellationToken = default)
    {
        var startInfo = new ProcessStartInfo(command)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        foreach (string arg in args)
        {
            startInfo.ArgumentList.Add(arg);
        }

        using var process = Process.Start(startInfo) ?? throw new InvalidOperationException($"Could not start {command}.");
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(timeout ?? DefaultTimeout);

        // Both streams are drained at once: a full stderr pipe would otherwise block the process.
        var stdout = process.StandardOutput.ReadToEndAsync(deadline.Token);
        var stderr = process.StandardError.ReadToEndAsync(deadline.Token);
        try
        {
            await process.WaitForExitAsync(deadline.Token);
            return new ExternalProcessResult(process.ExitCode, await stdout, await stderr);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            process.Kill(entireProcessTree: true);
            throw new TimeoutException($"{command} did not finish within {timeout ?? DefaultTimeout}.");
        }
    }

    /// <summary>Whether <paramref name="command"/> runs and exits with 0 within 30 seconds.</summary>
    public static bool Succeeds(string command, params string[] args)
    {
        try
        {
            return RunAsync(command, args, TimeSpan.FromSeconds(30)).GetAwaiter().GetResult().ExitCode == 0;
        }
        catch (Exception ex) when (ex is Win32Exception or TimeoutException or InvalidOperationException)
        {
            return false;
        }
    }
}

using System.Diagnostics;
using System.Text;

namespace SimpleSign.Playbook.Runs;

/// <summary>A command to run: the program, its arguments (one per entry, no shell), its folder and extra environment.</summary>
public sealed record ProcessCommand(
    string FileName,
    IReadOnlyList<string> Arguments,
    string WorkingDirectory,
    TimeSpan Timeout,
    IReadOnlyDictionary<string, string>? Environment = null);

/// <summary>What a command gave.</summary>
public sealed record ProcessResult(int? ExitCode, string Stdout, string Stderr, bool TimedOut, long DurationMs);

/// <summary>Runs a command. A fake one in the tests.</summary>
public interface IProcessRunner
{
    /// <summary>Runs <paramref name="command"/>; each line of stdout (false) or stderr (true) goes to <paramref name="onLine"/> as it comes.</summary>
    /// <exception cref="System.ComponentModel.Win32Exception">The program cannot be started.</exception>
    Task<ProcessResult> RunAsync(ProcessCommand command, Action<bool, string>? onLine, CancellationToken cancellationToken);
}

/// <summary>Runs a real process, kills it (and its children) on timeout or cancellation.</summary>
public sealed class ProcessRunner : IProcessRunner
{
    public async Task<ProcessResult> RunAsync(ProcessCommand command, Action<bool, string>? onLine, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        var start = new ProcessStartInfo(command.FileName)
        {
            WorkingDirectory = command.WorkingDirectory,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = true,
            UseShellExecute = false,
            CreateNoWindow = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
        };
        foreach (string argument in command.Arguments)
        {
            start.ArgumentList.Add(argument);
        }

        // Plain output: no colors, no width-dependent wrapping, no interactive prompts.
        start.Environment["NO_COLOR"] = "1";
        start.Environment["TERM"] = "dumb";
        start.Environment["COLUMNS"] = "200";
        start.Environment["DOTNET_NOLOGO"] = "1";
        if (command.Environment is not null)
        {
            foreach (var (key, value) in command.Environment)
            {
                start.Environment[key] = value;
            }
        }

        var stdout = new StringBuilder();
        var stderr = new StringBuilder();
        using var process = new Process { StartInfo = start, EnableRaisingEvents = true };
        process.OutputDataReceived += (_, e) => Append(stdout, e.Data, isError: false);
        process.ErrorDataReceived += (_, e) => Append(stderr, e.Data, isError: true);

        void Append(StringBuilder buffer, string? line, bool isError)
        {
            if (line is null)
            {
                return;
            }

            lock (buffer)
            {
                buffer.Append(line).Append('\n');
            }

            onLine?.Invoke(isError, line);
        }

        var watch = Stopwatch.StartNew();
        process.Start();
        process.StandardInput.Close();
        process.BeginOutputReadLine();
        process.BeginErrorReadLine();

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(command.Timeout);
        bool timedOut = false;
        try
        {
            await process.WaitForExitAsync(timeout.Token);
        }
        catch (OperationCanceledException)
        {
            timedOut = !cancellationToken.IsCancellationRequested;
            try
            {
                process.Kill(entireProcessTree: true);
            }
            catch (InvalidOperationException)
            {
                // It ended meanwhile.
            }

            await process.WaitForExitAsync(CancellationToken.None);
            cancellationToken.ThrowIfCancellationRequested();
        }

        // The last lines of the asynchronous readers.
        process.WaitForExit();
        watch.Stop();
        string Text(StringBuilder buffer)
        {
            lock (buffer)
            {
                return buffer.ToString();
            }
        }

        return new ProcessResult(timedOut ? null : process.ExitCode, Text(stdout), Text(stderr), timedOut, watch.ElapsedMilliseconds);
    }
}

using System.Diagnostics;
using System.Text;
using System.Text.Json;
using SimpleSign.TestBench.Localization;
using SimpleSign.TestBench.Signing;

namespace SimpleSign.TestBench.Runs;

/// <summary>How a run makes the signature: through the library (in this process) or through the <c>simplesign</c> CLI.</summary>
public static class RunEngines
{
    public const string Library = "library";
    public const string Cli = "cli";

    public static IReadOnlyList<string> All { get; } = [Library, Cli];
}

/// <summary>
/// What a CLI run needs: the generated commands, the files their placeholders name (by file name, relative to the work
/// folder) and the values of the secret placeholders (<c>$PFX_PASSWORD</c>…), never shown.
/// </summary>
/// <param name="Commands">The commands, run in order; each must succeed.</param>
/// <param name="Files">The files to write in the work folder before the first command, by relative path.</param>
/// <param name="Secrets">The value of each secret placeholder.</param>
/// <param name="BeforeCommand">Runs before a command, in the work folder (the signer of a deferred signature).</param>
internal sealed record CliJob(
    IReadOnlyList<CliLine> Commands,
    IReadOnlyDictionary<string, byte[]> Files,
    IReadOnlyDictionary<string, string> Secrets,
    Func<CliLine, string, CancellationToken, Task>? BeforeCommand = null);

/// <summary>One command the CLI ran: the line (secrets masked), its exit code and what it wrote.</summary>
public sealed record CliStep(string Command, int ExitCode, string Output, long Ms);

/// <summary>
/// What the CLI did: each command, the file the last <c>--output</c> (or <c>--output-dir</c>) names, the JSON of a sign
/// command, and what a validate command printed and wrote.
/// </summary>
internal sealed record CliOutcome(IReadOnlyList<CliStep> Steps, byte[]? Output, CliSignJson? Json)
{
    /// <summary>The command that failed (a sign that did not end with 0, a validate that printed no verdict), or null.</summary>
    public CliStep? Failed { get; init; }

    /// <summary>The <c>--json</c> object a validate command printed, or null.</summary>
    public string? ValidationJson { get; init; }

    /// <summary>The ETSI TS 119 102-2 report (XML) a validate command wrote, or null.</summary>
    public byte[]? EtsiReport { get; init; }

    /// <summary>The simple report (JSON) a validate command wrote, or null.</summary>
    public byte[]? SimpleReport { get; init; }

    public bool Success => Steps.Count > 0 && Failed is null && (Output is not null || ValidationJson is not null);

    /// <summary>The error of the first command that failed, or why the output is missing.</summary>
    public string? Error => Failed is { } failed
        ? Json?.Error ?? L.T("The CLI ended with exit code {0}: {1}", failed.ExitCode, Last(failed.Output))
        : Output is null && ValidationJson is null ? L.T("The CLI wrote no output file.") : null;

    private static string Last(string output)
    {
        string[] lines = output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        return lines.Length == 0 ? "" : string.Join(" ", lines.TakeLast(3));
    }
}

/// <summary>The <c>--json</c> object of <c>sign</c>, <c>cades sign</c> and <c>xades sign</c>.</summary>
internal sealed record CliSignJson(bool Success, string? RequestedLevel, string? AchievedLevel, IReadOnlyList<string> Warnings, string? Error, string? ErrorType);

/// <summary>
/// Runs the commands the Code tab shows through the real <c>simplesign</c> CLI, as a child process, in a work folder
/// holding the files and secrets their placeholders name. The TestBench build copies the CLI next to itself (<c>cli/</c>);
/// <c>SIMPLESIGN_CLI</c> points to another build (a <c>simplesign</c> executable or <c>simplesign.dll</c>).
/// </summary>
internal sealed class CliExecutor
{
    /// <summary>The longest a command may take.</summary>
    private static readonly TimeSpan s_timeout = TimeSpan.FromMinutes(3);

    /// <summary>The commands that print one JSON object with <c>--json</c>.</summary>
    private static readonly string[][] s_json = [["sign"], ["cades", "sign"], ["xades", "sign"]];

    /// <summary>The validate commands: <c>--json</c> and the two reports are added, and exit code 1 means "not valid", not a failure.</summary>
    private static readonly string[][] s_validate = [["validate"], ["cades", "validate"], ["xades", "validate"]];

    /// <summary>The reports a validate command writes in the work folder.</summary>
    internal const string EtsiReportFile = "etsi-report.xml";

    internal const string SimpleReportFile = "simple-report.json";

    private readonly Func<string?> _locate;

    public CliExecutor()
        : this(() => Locate(Environment.GetEnvironmentVariable("SIMPLESIGN_CLI"), AppContext.BaseDirectory))
    {
    }

    internal CliExecutor(Func<string?> locate)
    {
        _locate = locate;
    }

    /// <summary>The CLI this TestBench runs (the executable or the .dll), or null when it is not there.</summary>
    public string? Path => _locate();

    /// <summary>The CLI: <paramref name="configured"/> when set, else <c>cli/</c> next to the TestBench.</summary>
    internal static string? Locate(string? configured, string baseDirectory)
    {
        if (!string.IsNullOrWhiteSpace(configured))
        {
            return File.Exists(configured) ? System.IO.Path.GetFullPath(configured) : null;
        }

        string folder = System.IO.Path.Combine(baseDirectory, "cli");
        string dll = System.IO.Path.Combine(folder, "simplesign.dll");
        return File.Exists(dll) ? dll : null;
    }

    /// <summary>Runs every command of <paramref name="job"/> until one fails; logs each line (secrets masked) and its output to the run.</summary>
    public async Task<CliOutcome> RunAsync(CliJob job, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(job);
        string cli = Path ?? throw new InvalidOperationException(L.T("The simplesign CLI was not found next to the TestBench (cli/simplesign.dll). Build the TestBench again, or set SIMPLESIGN_CLI."));
        string dir = Directory.CreateTempSubdirectory("simplesign-testbench-cli-").FullName;
        try
        {
            foreach (var (name, content) in job.Files)
            {
                string path = System.IO.Path.Combine(dir, name);
                Directory.CreateDirectory(System.IO.Path.GetDirectoryName(path)!);
                await File.WriteAllBytesAsync(path, content, cancellationToken);
            }

            var steps = new List<CliStep>();
            string? written = null;
            CliSignJson? json = null;
            string? validation = null;
            foreach (var command in job.Commands)
            {
                if (job.BeforeCommand is { } before)
                {
                    await before(command, dir, cancellationToken);
                }

                var args = Resolve(command.Args, dir, job.Secrets);
                bool wantsJson = Is(s_json, command);
                bool validates = Is(s_validate, command);
                string extra = validates ? $" --json --etsi-report {EtsiReportFile} --simple-report {SimpleReportFile}" : wantsJson ? " --json" : "";
                if (validates)
                {
                    args.AddRange(["--json", "--etsi-report", System.IO.Path.Combine(dir, EtsiReportFile), "--simple-report", System.IO.Path.Combine(dir, SimpleReportFile)]);
                }
                else if (wantsJson)
                {
                    args.Add("--json");
                }

                string shown = Mask(command) + extra;
                RunLog.Current?.Note(RunStages.Prepare, "$ " + shown);
                var (exit, output, ms) = await StartAsync(cli, args, dir, cancellationToken);
                RunLog.Current?.Note(RunStages.Finish, L.T("simplesign ended with exit code {0} in {1} ms.", exit, ms) + (output.Length > 0 ? "\n" + Trim(output) : ""), warning: exit != 0);
                steps.Add(new CliStep(shown, exit, output, ms));
                if (wantsJson)
                {
                    json = ParseJson(output) ?? json;
                }

                if (validates && exit is 0 or 1 && JsonText(output) is { } verdict)
                {
                    validation = verdict;
                    continue;
                }

                if (exit != 0 || validates)
                {
                    return new CliOutcome(steps, null, json) { Failed = steps[^1] };
                }

                written = OutputOf(command.Args, dir) ?? written;
            }

            return new CliOutcome(steps, written is null ? null : await ReadOutputAsync(written, cancellationToken), json)
            {
                ValidationJson = validation,
                EtsiReport = await ReadOutputAsync(System.IO.Path.Combine(dir, EtsiReportFile), cancellationToken),
                SimpleReport = await ReadOutputAsync(System.IO.Path.Combine(dir, SimpleReportFile), cancellationToken),
            };
        }
        finally
        {
            try
            {
                Directory.Delete(dir, recursive: true);
            }
            catch (IOException)
            {
            }
            catch (UnauthorizedAccessException)
            {
            }
        }
    }

    /// <summary>
    /// The tokens with the placeholders filled in: the secrets, and the file names (those in the work folder, and the
    /// outputs the commands write) as paths in it.
    /// </summary>
    internal static List<string> Resolve(IReadOnlyList<string> args, string dir, IReadOnlyDictionary<string, string> secrets)
    {
        var resolved = new List<string>(args.Count);
        for (int i = 0; i < args.Count; i++)
        {
            string token = args[i];
            if (secrets.TryGetValue(token, out string? secret))
            {
                resolved.Add(secret);
                continue;
            }

            bool isOutput = i > 0 && args[i - 1] is "--output" or "--output-dir";
            string path = System.IO.Path.Combine(dir, token);
            bool isFile = !token.StartsWith('-') && !token.Contains("://", StringComparison.Ordinal) && !System.IO.Path.IsPathRooted(token)
                && (isOutput || File.Exists(path) || Directory.Exists(path) || token == CliLine.Placeholders.Signature);
            resolved.Add(isFile ? path : token);
        }

        return resolved;
    }

    /// <summary>The command as the Code tab shows it, on one line, with every secret placeholder kept as its name.</summary>
    internal static string Mask(CliLine command) =>
        "simplesign " + string.Join(' ', command.Args.Select(CliLine.Quote));

    /// <summary>The file (or the first file of the folder) the command's <c>--output</c> or <c>--output-dir</c> names.</summary>
    private static string? OutputOf(IReadOnlyList<string> args, string dir)
    {
        for (int i = args.Count - 2; i >= 0; i--)
        {
            if (args[i] is "--output" or "--output-dir")
            {
                return System.IO.Path.Combine(dir, args[i + 1]);
            }
        }

        return null;
    }

    private static async Task<byte[]?> ReadOutputAsync(string path, CancellationToken cancellationToken)
    {
        if (File.Exists(path))
        {
            return await File.ReadAllBytesAsync(path, cancellationToken);
        }

        if (Directory.Exists(path) && Directory.GetFiles(path).Order(StringComparer.Ordinal).FirstOrDefault() is { } first)
        {
            return await File.ReadAllBytesAsync(first, cancellationToken);
        }

        return null;
    }

    private static bool Is(string[][] commands, CliLine command) =>
        commands.Any(c => command.Args.Take(c.Length).SequenceEqual(c, StringComparer.Ordinal));

    /// <summary>The last JSON object the command printed (indented: it starts a line), or null.</summary>
    internal static string? JsonText(string output)
    {
        int start = output.LastIndexOf("\n{", StringComparison.Ordinal) + 1;
        if (start == 0 && !output.StartsWith('{'))
        {
            start = output.IndexOf('{', StringComparison.Ordinal);
        }

        if (start < 0)
        {
            return null;
        }

        string text = output[start..].Trim();
        try
        {
            using var document = JsonDocument.Parse(text);
            return document.RootElement.ValueKind == JsonValueKind.Object ? text : null;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    /// <summary>The last JSON object the command printed.</summary>
    internal static CliSignJson? ParseJson(string output)
    {
        if (JsonText(output) is not { } text)
        {
            return null;
        }

        try
        {
            using var document = JsonDocument.Parse(text);
            var root = document.RootElement;
            static string? Text(JsonElement element, string name) =>
                element.ValueKind == JsonValueKind.Object && element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;
            IReadOnlyList<string> warnings = root.TryGetProperty("warnings", out var list) && list.ValueKind == JsonValueKind.Array
                ? [.. list.EnumerateArray().Select(w => w.ValueKind == JsonValueKind.String ? w.GetString()! : w.GetRawText())]
                : [];
            bool success = root.TryGetProperty("success", out var ok) && ok.ValueKind == JsonValueKind.True;
            var error = root.TryGetProperty("error", out var e) ? e : default;
            string? type = Text(error, "type");
            string? reason = Text(error, "reason");
            return new CliSignJson(success, Text(root, "requestedLevel"), Text(root, "achievedLevel"), warnings, Text(error, "message"),
                type is null ? null : reason is null ? type : $"{type} ({reason})");
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static string Trim(string output) => output.Length <= 4000 ? output.TrimEnd() : output[..4000] + "…";

    /// <summary>Starts the CLI (its executable, or <c>dotnet simplesign.dll</c>) and waits for it.</summary>
    private static async Task<(int Exit, string Output, long Ms)> StartAsync(string cli, IReadOnlyList<string> args, string dir, CancellationToken cancellationToken)
    {
        bool isDll = cli.EndsWith(".dll", StringComparison.OrdinalIgnoreCase);
        var info = new ProcessStartInfo(isDll ? DotnetHost() : cli)
        {
            WorkingDirectory = dir,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
        };
        if (isDll)
        {
            info.ArgumentList.Add(cli);
        }

        foreach (string arg in args)
        {
            info.ArgumentList.Add(arg);
        }

        // Plain text: no colors or links in the output the run shows.
        info.Environment["NO_COLOR"] = "1";
        info.Environment["DOTNET_CLI_TELEMETRY_OPTOUT"] = "1";

        // The CLI targets net8.0: run it on a newer runtime when net8.0 is not installed.
        info.Environment["DOTNET_ROLL_FORWARD"] = "Major";
        var watch = Stopwatch.StartNew();
        using var process = Process.Start(info) ?? throw new InvalidOperationException(L.T("The simplesign CLI could not be started."));
        var stdout = process.StandardOutput.ReadToEndAsync(cancellationToken);
        var stderr = process.StandardError.ReadToEndAsync(cancellationToken);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(s_timeout);
        try
        {
            await process.WaitForExitAsync(timeout.Token);
        }
        catch (OperationCanceledException)
        {
            process.Kill(entireProcessTree: true);
            if (cancellationToken.IsCancellationRequested)
            {
                throw;
            }

            return (-1, L.T("The CLI took longer than {0} minutes and was stopped.", s_timeout.TotalMinutes), watch.ElapsedMilliseconds);
        }

        string output = await stdout;
        string errors = await stderr;
        return (process.ExitCode, errors.Length == 0 ? output : output + errors, watch.ElapsedMilliseconds);
    }

    /// <summary>The <c>dotnet</c> host: the one running the TestBench when it is <c>dotnet</c>, else the one on the PATH.</summary>
    private static string DotnetHost()
    {
        if (Environment.GetEnvironmentVariable("DOTNET_HOST_PATH") is { Length: > 0 } host && File.Exists(host))
        {
            return host;
        }

        string? current = Environment.ProcessPath;
        return current is not null && System.IO.Path.GetFileNameWithoutExtension(current).Equals("dotnet", StringComparison.OrdinalIgnoreCase)
            ? current
            : "dotnet";
    }
}

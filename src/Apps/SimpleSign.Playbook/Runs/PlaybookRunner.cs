using System.ComponentModel;
using System.Globalization;
using System.Text;
using System.Text.Json;
using SimpleSign.Playbook.Model;
using SimpleSign.Playbook.Workspaces;

namespace SimpleSign.Playbook.Runs;

/// <summary>Hears what a run does, as it does it.</summary>
public interface IRunObserver
{
    void RunChanged(RunRecord run);

    void StepChanged(RunRecord run, StepRecord step);

    void OutputLine(StepRecord step, bool isError, string text);

    /// <summary>Waits for the operator's decision on a manual step.</summary>
    Task<ManualDecision> WaitForDecisionAsync(StepRecord step, CancellationToken cancellationToken);
}

/// <summary>
/// Runs a playbook: for each step, the Sandbox actions of its setup, the CLI command, the checks, the
/// teardown; then writes the run folder (run.json, each step's output and files, the reports).
/// </summary>
public sealed class PlaybookRunner(IProcessRunner processes, Func<Uri, ISandboxClient> sandboxFactory)
{
    /// <summary>Runs <paramref name="playbook"/> of <paramref name="workspace"/>. Never throws for a failing step.</summary>
    /// <param name="workspace">The workspace (assets, secrets, runs folder).</param>
    /// <param name="playbook">The checked playbook.</param>
    /// <param name="cli">The program and fixed arguments that start the CLI.</param>
    /// <param name="selection">The step ids to run (null: all).</param>
    /// <param name="observer">Hears the progress and answers manual steps.</param>
    /// <param name="cancellationToken">Stops the run (the step running is killed).</param>
    public async Task<RunRecord> RunAsync(
        Workspace workspace,
        PlaybookDefinition playbook,
        (string Program, IReadOnlyList<string> Prefix) cli,
        IReadOnlyCollection<string>? selection,
        IRunObserver observer,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(workspace);
        ArgumentNullException.ThrowIfNull(playbook);
        ArgumentNullException.ThrowIfNull(observer);
        var started = DateTimeOffset.Now;
        var run = new RunRecord
        {
            Id = started.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture) + "-" + Guid.NewGuid().ToString("N")[..4],
            PlaybookName = playbook.Name,
            PlaybookHash = workspace.PlaybookHash(),
            StartedAt = started,
            Cli = CommandLine(cli.Program, cli.Prefix),
            Selection = selection?.ToList(),
        };
        foreach (var section in playbook.Sections)
        {
            foreach (var step in section.Steps)
            {
                run.Steps.Add(new StepRecord
                {
                    SectionId = section.Id,
                    SectionTitle = section.Title,
                    StepId = step.Id,
                    Title = step.Title,
                    Description = step.Description,
                    Manual = step.Manual,
                    Status = selection is null || selection.Contains(step.Id) ? RunStatus.Pending : RunStatus.Skipped,
                });
            }
        }

        string runFolder = Path.Combine(workspace.RunsPath, run.Id);
        Directory.CreateDirectory(runFolder);
        observer.RunChanged(run);

        var variables = new Variables(playbook.Variables);
        variables.Set("workspace", workspace.Directory);
        variables.Set("run", runFolder);
        var secrets = workspace.ReadSecrets();
        foreach (var asset in playbook.Assets)
        {
            variables.Set($"asset.{asset.Id}", workspace.Resolve(asset.File));
            if (asset.Secret is { } key && secrets.TryGetValue(key, out string? password))
            {
                variables.Set($"asset.{asset.Id}.password", password);
            }
        }

        ISandboxClient? sandbox = null;
        SandboxSummary? sandboxInfo = null;
        try
        {
            if (playbook.Sandbox is { } settings)
            {
                sandbox = sandboxFactory(new Uri(settings.Url));
                sandboxInfo = await sandbox.InfoAsync(cancellationToken);
                run.Sandbox = new SandboxRecord(sandbox.Url.AbsoluteUri, sandboxInfo.Name, sandboxInfo.Version, sandboxInfo.RootSubject, sandboxInfo.RootThumbprint);
                string rootPath = Path.Combine(runFolder, "sandbox-root.pem");
                string chainPath = Path.Combine(runFolder, "sandbox-chain.pem");
                await File.WriteAllTextAsync(rootPath, await sandbox.RootPemAsync(cancellationToken), cancellationToken);
                await File.WriteAllTextAsync(chainPath, await sandbox.ChainPemAsync(cancellationToken), cancellationToken);
                variables.Set("sandbox.url", sandbox.Url.AbsoluteUri);
                variables.Set("sandbox.name", sandboxInfo.Name);
                variables.Set("sandbox.root", rootPath);
                variables.Set("sandbox.chain", chainPath);
                variables.Set("sandbox.pfxPassword", sandboxInfo.PfxPassword);
                variables.Set("sandbox.tsa", sandboxInfo.Tsa.Url);
                variables.Set("sandbox.tsaAuthenticated", sandboxInfo.Tsa.AuthenticatedUrl);
                variables.Set("sandbox.tsaUntrusted", sandboxInfo.Tsa.UntrustedUrl);
                variables.Set("sandbox.tsaRevoked", sandboxInfo.Tsa.RevokedUrl);
                variables.Set("sandbox.tsaWrongName", sandboxInfo.Tsa.WrongNameUrl);
                variables.Set("sandbox.tsaUser", sandboxInfo.Tsa.User);
                variables.Set("sandbox.tsaPassword", sandboxInfo.Tsa.Password);
                if (settings.ResetBeforeRun)
                {
                    await sandbox.ResetAsync(cancellationToken);
                }
            }

            var version = await processes.RunAsync(
                new ProcessCommand(cli.Program, [.. cli.Prefix, "version"], workspace.Directory, TimeSpan.FromSeconds(60)), null, cancellationToken);
            run.CliVersion = version.ExitCode == 0
                ? version.Stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).FirstOrDefault()
                : throw new InvalidOperationException($"'{run.Cli} version' failed: {version.Stderr}{version.Stdout}".Trim());
            observer.RunChanged(run);

            foreach (var section in playbook.Sections)
            {
                foreach (var step in section.Steps)
                {
                    var record = run.Steps.First(s => s.StepId == step.Id);
                    if (record.Status == RunStatus.Skipped)
                    {
                        continue;
                    }

                    cancellationToken.ThrowIfCancellationRequested();
                    await RunStepAsync(run, step, record, variables.Fork(), runFolder, cli, sandbox, sandboxInfo, observer, cancellationToken);
                }
            }

            run.Status = run.Steps.Any(s => s.Status is RunStatus.Failed or RunStatus.Error) ? RunStatus.Failed : RunStatus.Passed;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            run.Status = RunStatus.Cancelled;
            foreach (var step in run.Steps.Where(s => s.Status is RunStatus.Pending or RunStatus.Running or RunStatus.Waiting))
            {
                step.Status = RunStatus.Cancelled;
            }
        }
        catch (Exception ex) when (ex is HttpRequestException or InvalidOperationException or Win32Exception or IOException or VariableException or JsonException or TaskCanceledException)
        {
            run.Status = RunStatus.Error;
            run.Error = ex is Win32Exception
                ? $"The CLI could not be started ({run.Cli}): {ex.Message}. Set it in Settings."
                : ex is HttpRequestException or TaskCanceledException && run.Sandbox is null && playbook.Sandbox is not null
                    ? $"The Sandbox at {playbook.Sandbox.Url} did not answer: {ex.Message}"
                    : ex.Message;
            foreach (var step in run.Steps.Where(s => s.Status == RunStatus.Pending))
            {
                step.Status = RunStatus.Skipped;
            }
        }
        finally
        {
            (sandbox as IDisposable)?.Dispose();
        }

        run.FinishedAt = DateTimeOffset.Now;
        RunStore.Save(runFolder, run);
        RunReport.Write(runFolder, run);
        observer.RunChanged(run);
        return run;
    }

    private async Task RunStepAsync(
        RunRecord runRecord,
        StepDefinition step,
        StepRecord record,
        Variables variables,
        string runFolder,
        (string Program, IReadOnlyList<string> Prefix) cli,
        ISandboxClient? sandbox,
        SandboxSummary? sandboxInfo,
        IRunObserver observer,
        CancellationToken cancellationToken)
    {
        string stepFolder = Path.Combine(runFolder, "steps", record.StepId);
        Directory.CreateDirectory(stepFolder);
        variables.Set("out", stepFolder);
        record.Status = RunStatus.Running;
        record.StartedAt = DateTimeOffset.Now;
        observer.StepChanged(runRecord, record);
        var watch = System.Diagnostics.Stopwatch.StartNew();
        try
        {
            if (step.Manual)
            {
                record.Status = RunStatus.Waiting;
                observer.StepChanged(runRecord, record);
                var decision = await observer.WaitForDecisionAsync(record, cancellationToken);
                record.Status = decision.Status is RunStatus.Passed or RunStatus.Failed or RunStatus.Skipped ? decision.Status : RunStatus.Failed;
                record.Note = decision.Note;
                return;
            }

            foreach (var action in step.Setup)
            {
                await ApplyAsync(action, sandbox!, sandboxInfo!, variables, stepFolder, record, "setup", cancellationToken);
            }

            long cursor = sandbox is null ? 0 : (await sandbox.LogAsync(0, cancellationToken)).Select(r => r.Id).DefaultIfEmpty(0).Max();

            var definition = step.Run!;
            var args = definition.Args.Select(variables.Resolve).ToList();
            if (sandboxInfo is not null && definition.Network != "none")
            {
                args.AddRange(NetworkArguments(sandboxInfo, variables.Resolve("${sandbox.chain}")));
            }

            List<string> full = [.. cli.Prefix, .. args];
            record.Command = CommandLine(cli.Program, full);
            await File.WriteAllTextAsync(Path.Combine(stepFolder, "command.txt"), record.Command + "\n", cancellationToken);
            observer.StepChanged(runRecord, record);

            var result = await processes.RunAsync(
                new ProcessCommand(cli.Program, full, variables.Resolve("${workspace}"), TimeSpan.FromSeconds(definition.TimeoutSeconds)),
                (isError, line) => observer.OutputLine(record, isError, line),
                cancellationToken);
            record.ExitCode = result.ExitCode;
            record.TimedOut = result.TimedOut;
            await File.WriteAllTextAsync(Path.Combine(stepFolder, "stdout.txt"), result.Stdout, cancellationToken);
            await File.WriteAllTextAsync(Path.Combine(stepFolder, "stderr.txt"), result.Stderr, cancellationToken);

            if (sandbox is not null)
            {
                record.SandboxRequests = [.. await sandbox.LogAsync(cursor, cancellationToken)];
                await File.WriteAllTextAsync(Path.Combine(stepFolder, "sandbox-requests.json"),
                    JsonSerializer.Serialize(record.SandboxRequests, RunJson.Default.ListSandboxRequestRecord), cancellationToken);
            }

            var expect = step.Expect ?? new Expectation { ExitCode = 0 };
            record.Checks = [.. Expectations.Evaluate(expect, new CommandOutcome(result.ExitCode, result.Stdout, result.Stderr, result.TimedOut),
                record.SandboxRequests, variables.Resolve)];
            record.Status = record.Checks.All(c => c.Passed) ? RunStatus.Passed : RunStatus.Failed;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            record.Status = RunStatus.Cancelled;
            throw;
        }
        catch (Exception ex) when (ex is HttpRequestException or VariableException or InvalidOperationException or IOException or Win32Exception or TaskCanceledException)
        {
            record.Status = RunStatus.Error;
            record.Error = ex is Win32Exception ? $"The CLI could not be started ({cli.Program}): {ex.Message}" : ex.Message;
        }
        finally
        {
            if (!cancellationToken.IsCancellationRequested)
            {
                foreach (var action in step.Teardown)
                {
                    try
                    {
                        await ApplyAsync(action, sandbox!, sandboxInfo!, variables, stepFolder, record, "teardown", CancellationToken.None);
                    }
                    catch (Exception ex) when (ex is HttpRequestException or InvalidOperationException or IOException or TaskCanceledException)
                    {
                        record.Actions.Add($"teardown {action.Sandbox} failed: {ex.Message}");
                        if (record.Status == RunStatus.Passed)
                        {
                            record.Status = RunStatus.Error;
                            record.Error = $"Teardown failed: {ex.Message}";
                        }
                    }
                }
            }

            watch.Stop();
            record.DurationMs = watch.ElapsedMilliseconds;
            List<string> files = Directory.Exists(stepFolder)
                ? [.. Directory.EnumerateFiles(stepFolder, "*", SearchOption.AllDirectories).Select(f => Path.GetRelativePath(runFolder, f).Replace('\\', '/')).Order(StringComparer.Ordinal)]
                : [];
            // What the operator attached during the step (steps/ID/attachments/) is kept apart from what the command left.
            string attachments = $"steps/{record.StepId}/attachments/";
            record.Attachments = [.. files.Where(f => f.StartsWith(attachments, StringComparison.Ordinal))];
            record.Files = [.. files.Where(f => !f.StartsWith(attachments, StringComparison.Ordinal))];
            observer.StepChanged(runRecord, record);
        }
    }

    /// <summary>The arguments that let the CLI reach the Sandbox: its origins, LDAP, and its chain for TLS.</summary>
    internal static IEnumerable<string> NetworkArguments(SandboxSummary info, string chainPath)
    {
        foreach (string origin in info.LoopbackOrigins)
        {
            yield return "--allow-origin";
            yield return origin;
        }

        yield return "--allow-ldap";
        yield return "--tls-trust";
        yield return chainPath;
    }

    private static async Task ApplyAsync(
        SandboxAction action, ISandboxClient sandbox, SandboxSummary info, Variables variables, string stepFolder,
        StepRecord record, string phase, CancellationToken cancellationToken)
    {
        byte[]? pfx = await sandbox.ApplyAsync(action, cancellationToken);
        string description = action.Sandbox switch
        {
            "faults" => "faults " + string.Join(", ", new[] { ("crl", action.Crl), ("ocsp", action.Ocsp), ("tsa", action.Tsa), ("ocspSigner", action.OcspSigner) }
                .Where(f => f.Item2 is not null).Select(f => $"{f.Item1}={f.Item2}")),
            "revoke" => $"revoke {action.Certificate} ({action.Reason ?? "KeyCompromise"}, {action.Publication ?? "Both"})",
            "unrevoke" => $"unrevoke {action.Certificate}",
            "certificate" => $"certificate {action.Id}",
            "shortLived" => $"short-lived certificate ({action.Seconds ?? 10} s)",
            _ => action.Sandbox,
        };
        if (pfx is not null)
        {
            string name = action.As ?? "cert";
            string path = Path.Combine(stepFolder, $"{name}.pfx");
            await File.WriteAllBytesAsync(path, pfx, cancellationToken);
            variables.Set($"{name}.path", path);
            variables.Set($"{name}.password", info.PfxPassword);
            description += $" → ${{{name}.path}}";
        }

        record.Actions.Add($"{phase}: {description}");
    }

    /// <summary>A command line that can be pasted in a POSIX shell (arguments quoted when needed).</summary>
    internal static string CommandLine(string program, IEnumerable<string> arguments)
    {
        var line = new StringBuilder(Quote(program));
        foreach (string argument in arguments)
        {
            line.Append(' ').Append(Quote(argument));
        }

        return line.ToString();

        static string Quote(string value) =>
            value.Length > 0 && value.All(c => char.IsLetterOrDigit(c) || "-_./:=@,+%".Contains(c, StringComparison.Ordinal))
                ? value
                : "'" + value.Replace("'", "'\\''", StringComparison.Ordinal) + "'";
    }
}

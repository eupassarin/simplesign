using System.Net;
using System.Net.Sockets;
using Microsoft.AspNetCore.Builder;
using Shouldly;
using SimpleSign.Playbook.Runs;
using SimpleSign.Playbook.Workspaces;
using SimpleSign.Sandbox;

namespace SimpleSign.Playbook.Tests;

/// <summary>
/// The sample playbook with the real CLI (built in this repository) against a Sandbox this test
/// hosts itself (ephemeral environment, free ports): no other test changes it while it runs.
/// Skipped when the CLI is not built, unless <c>SIMPLESIGN_REQUIRE_SANDBOX</c> is "true" (CI).
/// </summary>
[Trait("Category", "Unit")]
public sealed class SampleEndToEndTests : IAsyncLifetime
{
    private readonly string _folder = Path.Combine(Path.GetTempPath(), "simplesign-sample-" + Guid.NewGuid().ToString("N"));
    private WebApplication? _sandbox;
    private Uri _sandboxUrl = null!;

    public async Task InitializeAsync()
    {
        int port = FreePort();
        _sandbox = SandboxApp.Build(new SandboxOptions
        {
            Name = "playbook-tests",
            Port = port,
            HttpsPort = FreePort(),
            LdapPort = FreePort(),
            Ephemeral = true,
            OpenBrowser = false,
        });
        await _sandbox.StartAsync();
        _sandboxUrl = new Uri($"http://localhost:{port}/");
    }

    public async Task DisposeAsync()
    {
        if (_sandbox is not null)
        {
            await _sandbox.StopAsync();
            await _sandbox.DisposeAsync();
        }

        if (Directory.Exists(_folder))
        {
            Directory.Delete(_folder, recursive: true);
        }
    }

    private static int FreePort()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        return ((IPEndPoint)listener.LocalEndpoint).Port;
    }

    [SkippableFact]
    public async Task RunAsync_Sample_EveryStepPasses()
    {
        string? cli = AppSettingsStore.FindBuiltCli();
        if (cli is null && string.Equals(Environment.GetEnvironmentVariable("SIMPLESIGN_REQUIRE_SANDBOX"), "true", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("The SimpleSign CLI is not built (src/Apps/SimpleSign.Cli/bin).");
        }

        Skip.If(cli is null, "The SimpleSign CLI is not built (src/Apps/SimpleSign.Cli/bin).");

        var workspace = Workspace.Create(_folder, "sample", Path.Combine(AppContext.BaseDirectory, "Samples", "sandbox-basics"));
        workspace.SavePlaybookText(workspace.ReadPlaybookText().Replace("http://localhost:5300/", _sandboxUrl.AbsoluteUri, StringComparison.Ordinal));
        var (playbook, issues) = workspace.LoadPlaybook();
        issues.Where(i => i.IsError).ShouldBeEmpty();

        var run = await new PlaybookRunner(new ProcessRunner(), url => new SandboxClient(url))
            .RunAsync(workspace, playbook!, (cli!, []), null, new RecordingObserver(), default);

        string Problems() => run.Error ?? string.Join("\n", run.Steps.Where(s => s.Status != RunStatus.Passed).Select(s =>
            $"{s.StepId}: {s.Status} {s.Error} {string.Join("; ", s.Checks.Where(c => !c.Passed).Select(c => $"{c.Name} expected {c.Expected}, got {c.Actual}"))}"));
        run.Status.ShouldBe(RunStatus.Passed, Problems());
        run.Steps.ShouldAllBe(s => s.Status == RunStatus.Passed);
        run.CliVersion.ShouldNotBeNull();
        run.Sandbox!.Name.ShouldBe("playbook-tests");
    }
}

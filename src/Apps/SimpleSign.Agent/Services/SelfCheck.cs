using System.Net;
using System.Net.Sockets;
using SimpleSign.Agent.Docs;
using SimpleSign.Agent.Localization;

namespace SimpleSign.Agent.Services;

/// <summary>
/// `SimpleSign.Agent --self-check`: proves a published (Native AOT, trimmed) binary still has what
/// it needs without opening any window: the texts, the embedded documentation, and an HTTP
/// round trip through the agent's own server. CI runs it on every platform after publishing.
/// </summary>
internal static class SelfCheck
{
    /// <summary>0 when everything works; otherwise 1, with the reason on standard error.</summary>
    public static async Task<int> RunAsync(TextWriter output, TextWriter error)
    {
        try
        {
            foreach (var language in L.Languages)
            {
                foreach (string topic in DocLibrary.Topics)
                {
                    if (Markdown.Parse(DocLibrary.Load(topic, language.Id, 21590)).Count == 0)
                    {
                        throw new InvalidDataException($"Empty documentation: {language.Id}/{topic}");
                    }
                }
            }

            string folder = Directory.CreateTempSubdirectory("simplesign-agent-check-").FullName;
            try
            {
                var services = new AgentServices(new SettingsStore(folder), new NoDialogs());
                services.Settings.Current.AgentPort = FreePort();
                await using var controller = new AgentController(services, _ => Task.FromResult<IReadOnlyList<CertificateEntry>>([]));
                await controller.StartAsync();
                if (controller.State != AgentState.Running)
                {
                    throw new IOException(controller.StatusText);
                }

                using var test = new SelfTest(controller.Server.Port);
                var health = await test.HealthAsync(CancellationToken.None);
                var (list, _) = await test.CertificatesAsync(CancellationToken.None);
                if (!health.Ok || !list.Ok)
                {
                    throw new IOException($"health {health.Status} {health.Error}; certificates {list.Status} {list.Error}");
                }
            }
            finally
            {
                Directory.Delete(folder, recursive: true);
            }

            await output.WriteLineAsync($"SimpleSign Agent {Diagnostics.Version} self-check: ok ({Strings.English.Count} texts, {DocLibrary.Topics.Count * L.Languages.Count} documents, {Diagnostics.Runtime})");
            return 0;
        }
#pragma warning disable CA1031 // A check: every failure is reported, none is thrown.
        catch (Exception ex)
#pragma warning restore CA1031
        {
            await error.WriteLineAsync($"SimpleSign Agent self-check failed: {ex.GetType().Name}: {ex.Message}");
            return 1;
        }
    }

    private static int FreePort()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        return ((IPEndPoint)listener.LocalEndpoint).Port;
    }

    /// <summary>The check has no user: the site is allowed, and nothing is signed.</summary>
    private sealed class NoDialogs : IDialogService
    {
        public Task<string?> AskSecretAsync(string title, string message, string confirmText) => Task.FromResult<string?>(null);

        public Task<ConsentDecision> AskConsentAsync(ConsentRequest request) =>
            Task.FromResult(request.CertificateHolder is null ? ConsentDecision.AllowOnce : ConsentDecision.Deny);
    }
}

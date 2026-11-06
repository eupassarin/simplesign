using System.Net.Sockets;
using Shouldly;
using SimpleSign.Agent.Services;

namespace SimpleSign.Agent.Tests;

[Trait("Category", "Unit")]
public sealed class AgentControllerTests
{
    [Fact]
    public async Task StartPauseResume_StateFollows()
    {
        var services = Fixtures.Services();
        services.Settings.Current.AgentPort = Fixtures.FreePort();
        await using var controller = new AgentController(services, _ => Task.FromResult<IReadOnlyList<CertificateEntry>>([]));
        int changes = 0;
        controller.Changed += (_, _) => Interlocked.Increment(ref changes);

        controller.State.ShouldBe(AgentState.Paused);
        await controller.StartAsync();
        controller.State.ShouldBe(AgentState.Running);
        await controller.SetEnabledAsync(false);
        controller.State.ShouldBe(AgentState.Paused);
        services.Settings.Current.AgentEnabled.ShouldBeFalse();
        await controller.SetEnabledAsync(true);
        controller.State.ShouldBe(AgentState.Running);
        changes.ShouldBeGreaterThan(2);
    }

    [Fact]
    public async Task Start_PortInUse_ErrorStateWithTheReason()
    {
        using var taken = new TcpListener(System.Net.IPAddress.Loopback, 0);
        taken.Start();
        var services = Fixtures.Services();
        services.Settings.Current.AgentPort = ((System.Net.IPEndPoint)taken.LocalEndpoint).Port;
        await using var controller = new AgentController(services, _ => Task.FromResult<IReadOnlyList<CertificateEntry>>([]));

        await controller.StartAsync();

        controller.State.ShouldBe(AgentState.Error);
        controller.StatusText.ShouldContain(services.Settings.Current.AgentPort.ToString(System.Globalization.CultureInfo.InvariantCulture));
        services.Log.Entries.ShouldContain(e => e.IsError);
    }

    [Fact]
    public async Task SetPort_Running_ListensOnTheNewPortAndSavesIt()
    {
        var services = Fixtures.Services();
        services.Settings.Current.AgentPort = Fixtures.FreePort();
        await using var controller = new AgentController(services, _ => Task.FromResult<IReadOnlyList<CertificateEntry>>([]));
        await controller.StartAsync();
        int port = Fixtures.FreePort();

        await controller.SetPortAsync(port);

        controller.State.ShouldBe(AgentState.Running);
        controller.Server.Port.ShouldBe(port);
        using var http = new HttpClient();
        (await http.GetStringAsync(new Uri($"http://127.0.0.1:{port}/api/health"))).ShouldContain("ok");
        new SettingsStore(services.Settings.Folder).Current.AgentPort.ShouldBe(port);
    }

    [Fact]
    public async Task Inventory_UsesTheGivenSource()
    {
        using var certificate = Fixtures.RsaCertificate();
        IReadOnlyList<CertificateEntry> entries = [new(CertificateSourceKind.Store, certificate)];
        await using var controller = new AgentController(Fixtures.Services(), _ => Task.FromResult(entries));

        var inventory = await controller.InventoryAsync(CancellationToken.None);

        inventory.Certificates.Single().Holder.ShouldBe("Fulano de Tal");
    }
}

using System.Net;
using System.Net.Http.Json;
using System.Net.Sockets;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Builder;
using SimpleSign.Sandbox.Endpoints;

namespace SimpleSign.Sandbox.Tests;

/// <summary>A running Sandbox (ephemeral environment, free port) shared by the tests of the collection.</summary>
public sealed class SandboxFixture : IAsyncLifetime
{
    public static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { Converters = { new JsonStringEnumConverter() } };

    private WebApplication? _app;

    public Uri BaseUrl { get; private set; } = null!;

    public HttpClient Http { get; } = new();

    public SandboxInfo Info { get; private set; } = null!;

    public async Task InitializeAsync()
    {
        int port = FreePort();
        _app = SandboxApp.Build(new SandboxOptions { Name = "tests", Port = port, Ephemeral = true, OpenBrowser = false });
        await _app.StartAsync();
        BaseUrl = new Uri($"http://localhost:{port}/");
        Http.BaseAddress = BaseUrl;
        Info = (await Http.GetFromJsonAsync<SandboxInfo>("api/info", Json))!;
    }

    public async Task DisposeAsync()
    {
        Http.Dispose();
        if (_app is not null)
        {
            await _app.StopAsync();
            await _app.DisposeAsync();
        }
    }

    internal static int FreePort()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        return ((IPEndPoint)listener.LocalEndpoint).Port;
    }
}

[CollectionDefinition(Name)]
public sealed class SandboxCollection : ICollectionFixture<SandboxFixture>
{
    public const string Name = "Sandbox";
}

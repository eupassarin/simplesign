using System.Net;
using System.Net.Http.Json;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Builder;
using SimpleSign.Core.Http;
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

    /// <summary>The Sandbox root, trusted by <see cref="Client"/> for the HTTPS endpoint.</summary>
    public X509Certificate2 Root { get; private set; } = null!;

    /// <summary>A client of the library's kind: trusts the Sandbox root for TLS, nothing else.</summary>
    public HttpClient Client { get; private set; } = null!;

    /// <summary>The outbound policy a client uses to reach this Sandbox: its loopback origins, LDAP allowed.</summary>
    public OutboundHttpPolicy Policy { get; private set; } = null!;

    public async Task InitializeAsync()
    {
        int port;
        // A free port can be taken by another test process before Kestrel binds it: try again with new ports.
        for (int attempt = 1; ; attempt++)
        {
            port = FreePort();
            _app = SandboxApp.Build(new SandboxOptions
            {
                Name = "tests",
                Port = port,
                HttpsPort = FreePort(),
                LdapPort = FreePort(),
                Ephemeral = true,
                OpenBrowser = false,
            });
            try
            {
                await _app.StartAsync();
                break;
            }
            catch (Exception ex) when (attempt < 5 && IsAddressInUse(ex))
            {
                await _app.DisposeAsync();
                _app = null;
            }
        }

        BaseUrl = new Uri($"http://localhost:{port}/");
        Http.BaseAddress = BaseUrl;
        Info = (await Http.GetFromJsonAsync<SandboxInfo>("api/info", Json))!;
        Root = X509CertificateLoader.LoadCertificate(await Http.GetByteArrayAsync("aia/root.cer"));
        var root = Root;
        Client = new HttpClient(new HttpClientHandler
        {
            CheckCertificateRevocationList = false,
            ServerCertificateCustomValidationCallback = (_, certificate, sent, _) =>
            {
                if (certificate is null)
                {
                    return false;
                }

                using var chain = new X509Chain();
                chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                chain.ChainPolicy.CustomTrustStore.Add(root);
                // The intermediate the server sent with its certificate (a fresh machine has no other copy).
                if (sent is not null)
                {
                    chain.ChainPolicy.ExtraStore.AddRange(sent.ChainPolicy.ExtraStore);
                }

                chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                return chain.Build(certificate);
            },
        });
        Policy = new OutboundHttpPolicy { AllowLdap = true, LoopbackOrigins = [.. Info.LoopbackOrigins.Select(o => new Uri(o))] };
    }

    public async Task DisposeAsync()
    {
        Http.Dispose();
        Client?.Dispose();
        Root?.Dispose();
        if (_app is not null)
        {
            await _app.StopAsync();
            await _app.DisposeAsync();
        }
    }

    private static bool IsAddressInUse(Exception ex) =>
        ex is IOException { InnerException: Microsoft.AspNetCore.Connections.AddressInUseException }
            or Microsoft.AspNetCore.Connections.AddressInUseException
            or SocketException { SocketErrorCode: SocketError.AddressAlreadyInUse };

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

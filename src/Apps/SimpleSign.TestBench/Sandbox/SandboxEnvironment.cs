using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Serialization;
using SimpleSign.Core.Http;
using SimpleSign.Signers.Cloud;

namespace SimpleSign.TestBench.Sandbox;

/// <summary>A connected SimpleSign Sandbox: its settings, its CAs and its signers (with their keys).</summary>
internal sealed class SandboxConnection : IDisposable
{
    public required Uri Url { get; init; }

    public required SandboxInfo Info { get; init; }

    public required X509Certificate2 Root { get; init; }

    public required X509Certificate2 Intermediate { get; init; }

    /// <summary>The certificates a validator needs besides a signer issued by the intermediate CA.</summary>
    public IReadOnlyList<X509Certificate2> Chain => [Intermediate, Root];

    public required IReadOnlyList<SandboxSigner> Signers { get; init; }

    public required IReadOnlyList<SandboxCertificateInfo> Certificates { get; init; }

    /// <summary>What a client needs to reach the Sandbox on this machine: its loopback origins, LDAP allowed.</summary>
    public required OutboundHttpPolicy Policy { get; init; }

    /// <summary>The certificate the Sandbox's list of trusted lists is signed with; null for a Sandbox without trusted lists.</summary>
    public X509Certificate2? LotlSigner { get; init; }

    /// <summary>The Sandbox's list of trusted lists; null for a Sandbox without trusted lists.</summary>
    public Uri? LotlUri => Info.TrustedLists is { } lists ? new Uri(lists.LotlUrl) : null;

    public Uri TsaUri => new(Info.Tsa.Url);

    public Uri AuthenticatedTsaUri => new(Info.Tsa.AuthenticatedUrl);

    public Uri UntrustedTsaUri => new(Info.Tsa.UntrustedUrl);

    public Uri RevokedTsaUri => new(Info.Tsa.RevokedUrl);

    /// <summary>The TSA whose certificate has expired.</summary>
    /// <exception cref="InvalidOperationException">The Sandbox is older than that TSA.</exception>
    public Uri ExpiredTsaUri => new(Info.Tsa.ExpiredUrl ?? throw new InvalidOperationException("This Sandbox has no expired TSA: update it."));

    public Uri WrongNameTsaUri => new(Info.Tsa.WrongNameUrl);

    public Uri CscBaseUri => new(Info.Csc.BaseUrl);

    /// <summary>
    /// The Sandbox's root as a PEM file on this machine, for the CLI's <c>--tls-trust</c> (its HTTPS endpoints, CRLs
    /// over HTTPS included, use a certificate under this root). Written once per root.
    /// </summary>
    public string RootPemFile()
    {
        string path = Path.Combine(Path.GetTempPath(), "simplesign-testbench", $"tls-root-{Root.Thumbprint}.pem");
        if (!File.Exists(path))
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllText(path, Root.ExportCertificatePem() + "\n");
        }

        return path;
    }

    public SandboxSigner Signer(string id) =>
        Signers.FirstOrDefault(s => s.Id == id) ?? throw new KeyNotFoundException($"The Sandbox has no signer '{id}'.");

    public void Dispose()
    {
        Root.Dispose();
        Intermediate.Dispose();
        LotlSigner?.Dispose();
        foreach (var signer in Signers)
        {
            signer.Certificate.Dispose();
            foreach (var certificate in signer.Chain)
            {
                certificate.Dispose();
            }
        }
    }
}

/// <summary>
/// The TestBench's network and its link to a SimpleSign Sandbox (src/Apps/SimpleSign.Sandbox), a
/// separate app that runs a test PKI and its services on real endpoints. The TestBench has one
/// environment: the real network, plus the Sandbox when one is connected. Connecting reads the
/// Sandbox's settings, CAs and signers; from then on its root is trusted for TLS and validation,
/// its loopback origins pass the SSRF guard, and its signers, TSAs and CSC service can be chosen.
/// The connection is remembered and opened again on the next start.
/// </summary>
internal sealed class SandboxEnvironment : IHttpClientProvider, IDisposable
{
    private static readonly JsonSerializerOptions s_json = new(JsonSerializerDefaults.Web) { Converters = { new JsonStringEnumConverter() } };

    private readonly string? _statePath;
    private readonly HttpClient _client;
    private readonly HttpClient _admin;
    private readonly Lock _gate = new();
    private SandboxConnection? _current;

    /// <summary>Creates the environment.</summary>
    /// <param name="statePath">Where the URL of the connected Sandbox is remembered; null: not remembered.</param>
    public SandboxEnvironment(string? statePath = null)
    {
        _statePath = statePath;
        var handler = new SocketsHttpHandler
        {
            PooledConnectionLifetime = TimeSpan.FromMinutes(5),
            SslOptions = new SslClientAuthenticationOptions { RemoteCertificateValidationCallback = ValidateServer },
        };
        _client = new HttpClient(new NetworkLog(handler)) { Timeout = TimeSpan.FromSeconds(30) };
        // Admin calls export private keys and issue certificates: on a busy machine (the macOS keychain
        // shared by many processes) they can take well over the 30 s of a network request.
        _admin = new HttpClient(new SocketsHttpHandler()) { Timeout = TimeSpan.FromMinutes(2) };
    }

    /// <summary>The default place of the remembered connection: the user's local application data.</summary>
    public static string DefaultStatePath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SimpleSign", "TestBench", "sandbox.json");

    /// <summary>The connected Sandbox, or null.</summary>
    public SandboxConnection? Current
    {
        get
        {
            lock (_gate)
            {
                return _current;
            }
        }
    }

    public bool IsConnected => Current is not null;

    /// <summary>The connected Sandbox.</summary>
    /// <exception cref="SandboxNotConnectedException">No Sandbox is connected.</exception>
    public SandboxConnection Connection => Current ?? throw new SandboxNotConnectedException();

    /// <summary>The last connection error, if the remembered Sandbox could not be reached.</summary>
    public string? LastError { get; private set; }

    /// <summary>The URL of the Sandbox connected last (offered again when it is not connected).</summary>
    public string? RememberedUrl { get; private set; }

    /// <inheritdoc />
    public HttpClient GetClient() => _client;

    /// <inheritdoc />
    public OutboundHttpPolicy OutboundPolicy => Current?.Policy ?? OutboundHttpPolicy.Default;

    /// <summary>Connects to the Sandbox at <paramref name="url"/>: reads its settings, CAs and signers.</summary>
    /// <exception cref="HttpRequestException">The Sandbox does not answer.</exception>
    public async Task<SandboxConnection> ConnectAsync(Uri url, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(url);
        var baseUrl = url.AbsoluteUri.EndsWith('/') ? url : new Uri(url.AbsoluteUri + "/");
        var info = await _admin.GetFromJsonAsync<SandboxInfo>(new Uri(baseUrl, "api/info"), s_json, cancellationToken)
            ?? throw new HttpRequestException($"{baseUrl} is not a SimpleSign Sandbox.");
        var pki = await _admin.GetFromJsonAsync<SandboxPkiInfo>(new Uri(baseUrl, "api/pki"), s_json, cancellationToken)
            ?? throw new HttpRequestException($"{baseUrl}api/pki did not answer.");
        var root = X509CertificateLoader.LoadCertificate(await _admin.GetByteArrayAsync(new Uri(baseUrl, "aia/root.cer"), cancellationToken));
        var intermediate = X509CertificateLoader.LoadCertificate(await _admin.GetByteArrayAsync(new Uri(baseUrl, "aia/intermediate.cer"), cancellationToken));
        var lotlSigner = info.TrustedLists is { } lists
            ? X509Certificate2.CreateFromPem(await _admin.GetStringAsync(new Uri(lists.LotlSignerUrl), cancellationToken))
            : null;
        // Side by side: each PKCS#12 is downloaded and its key loaded (into the keychain on macOS) on its own thread,
        // which is most of the time of a connection. The order of the Sandbox's list is kept.
        var signers = (await Task.WhenAll(pki.Certificates.Where(c => c.Usage == "Signing").Select(async certificate =>
        {
            byte[] pfx = await _admin.GetByteArrayAsync(new Uri(baseUrl, $"api/certificates/{Uri.EscapeDataString(certificate.Id)}/pfx"), cancellationToken);
            return await Task.Run(() => Load(certificate, pfx, info.PfxPassword), cancellationToken);
        }))).ToList();

        var connection = new SandboxConnection
        {
            Url = baseUrl,
            Info = info,
            Root = root,
            Intermediate = intermediate,
            Signers = signers,
            Certificates = pki.Certificates,
            Policy = PolicyFor(info),
            LotlSigner = lotlSigner,
        };
        SandboxConnection? previous;
        lock (_gate)
        {
            previous = _current;
            _current = connection;
            LastError = null;
        }

        previous?.Dispose();
        Remember(baseUrl);
        return connection;
    }

    /// <summary>Forgets the connected Sandbox.</summary>
    public void Disconnect()
    {
        SandboxConnection? previous;
        lock (_gate)
        {
            previous = _current;
            _current = null;
        }

        previous?.Dispose();
        Remember(null);
    }

    /// <summary>Connects to the remembered Sandbox, if any; an unreachable one is reported in <see cref="LastError"/>.</summary>
    public async Task ReconnectAsync(CancellationToken cancellationToken = default)
    {
        if (_statePath is null || !File.Exists(_statePath))
        {
            return;
        }

        try
        {
            string? url = JsonSerializer.Deserialize<Remembered>(await File.ReadAllTextAsync(_statePath, cancellationToken), s_json)?.Url;
            RememberedUrl = url;
            if (url is not null && Uri.TryCreate(url, UriKind.Absolute, out var uri))
            {
                await ConnectAsync(uri, cancellationToken);
            }
        }
        catch (Exception ex) when (ex is HttpRequestException or JsonException or IOException or TaskCanceledException)
        {
            LastError = ex.Message;
        }
    }

    /// <summary>A signer valid for <paramref name="lifetime"/> only, issued by the Sandbox for this call.</summary>
    public async Task<X509Certificate2> IssueShortLivedAsync(TimeSpan lifetime, CancellationToken cancellationToken = default)
    {
        var connection = Connection;
        using var response = await _admin.PostAsync(new Uri(connection.Url, $"api/certificates/short-lived?seconds={(int)lifetime.TotalSeconds}"), null, cancellationToken);
        response.EnsureSuccessStatusCode();
        var collection = X509CertificateLoader.LoadPkcs12Collection(await response.Content.ReadAsByteArrayAsync(cancellationToken), connection.Info.PfxPassword, KeyStorage);
        var leaf = collection.Single(c => c.HasPrivateKey);
        foreach (var other in collection.Where(c => !ReferenceEquals(c, leaf)))
        {
            other.Dispose();
        }

        return leaf;
    }

    /// <summary>Switches the Sandbox's failures (its admin API).</summary>
    public async Task SetFaultsAsync(SandboxFaults faults, CancellationToken cancellationToken = default)
    {
        using var response = await _admin.PutAsJsonAsync(new Uri(Connection.Url, "api/faults"), faults, s_json, cancellationToken);
        response.EnsureSuccessStatusCode();
    }

    /// <summary>Revokes a certificate of the Sandbox now (a new CRL is published at once).</summary>
    public async Task RevokeAsync(string id, CancellationToken cancellationToken = default)
    {
        using var response = await _admin.PostAsJsonAsync(new Uri(Connection.Url, $"api/certificates/{Uri.EscapeDataString(id)}/revoke"), new { reason = "KeyCompromise" }, s_json, cancellationToken);
        response.EnsureSuccessStatusCode();
    }

    /// <summary>
    /// Sends a request to the connected Sandbox's admin API (<c>api/{path}</c>) as it is, for the TestBench's
    /// page: the browser then talks to one origin, and the admin API keeps answering this machine only.
    /// </summary>
    /// <exception cref="SandboxNotConnectedException">No Sandbox is connected.</exception>
    public async Task<HttpResponseMessage> ForwardAsync(HttpMethod method, string pathAndQuery, HttpContent? content, CancellationToken cancellationToken = default)
    {
        using var request = new HttpRequestMessage(method, new Uri(Connection.Url, "api/" + pathAndQuery.TrimStart('/'))) { Content = content };
        request.Headers.Accept.ParseAdd("application/json");
        return await _admin.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
    }

    /// <summary>Puts the Sandbox's revocations and failures back as in a new environment.</summary>
    public async Task ResetAsync(CancellationToken cancellationToken = default)
    {
        using var response = await _admin.PostAsync(new Uri(Connection.Url, "api/reset"), null, cancellationToken);
        response.EnsureSuccessStatusCode();
    }

    /// <summary>The OAuth "browser" of the Sandbox's CSC service: its login page approves at once and redirects back.</summary>
    public static IAuthorizationCodeHandler CscAuthorization => new SandboxAuthorization();

    public void Dispose()
    {
        _client.Dispose();
        _admin.Dispose();
        _current?.Dispose();
    }

    private static OutboundHttpPolicy PolicyFor(SandboxInfo info)
    {
        // A Sandbox published under a name on a lab network resolves to a private address.
        string[] privateHosts = [.. new[] { info.BaseUrl, info.HttpsBaseUrl, info.LdapBaseUrl }
            .Select(u => new Uri(u).Host)
            .Where(h => !string.Equals(h, "localhost", StringComparison.OrdinalIgnoreCase) && !IPAddress.TryParse(h.Trim('[', ']'), out _))
            .Distinct(StringComparer.OrdinalIgnoreCase)];
        return new OutboundHttpPolicy
        {
            AllowLdap = true,
            LoopbackOrigins = [.. info.LoopbackOrigins.Select(o => new Uri(o)).Where(o => o.IsLoopback)],
            PrivateNetworkHosts = privateHosts,
        };
    }

    private static SandboxSigner Load(SandboxCertificateInfo info, byte[] pfx, string password)
    {
        var collection = X509CertificateLoader.LoadPkcs12Collection(pfx, password, KeyStorage);
        var leaf = collection.Single(c => c.HasPrivateKey);
        return new SandboxSigner(info.Id, info.Title, info.Description, info.KeyType ?? "?", leaf,
            [.. collection.Where(c => !ReferenceEquals(c, leaf))], info.IsUsable, info.Problem)
        {
            Pfx = pfx,
        };
    }

    private static X509KeyStorageFlags KeyStorage =>
        OperatingSystem.IsMacOS() ? X509KeyStorageFlags.DefaultKeySet : X509KeyStorageFlags.EphemeralKeySet;

    /// <summary>TLS: what the operating system trusts, or a chain to the connected Sandbox's root.</summary>
    private bool ValidateServer(object sender, X509Certificate? certificate, X509Chain? chain, SslPolicyErrors errors)
    {
        if (errors == SslPolicyErrors.None)
        {
            return true;
        }

        if (Current is not { } connection || certificate is null || errors.HasFlag(SslPolicyErrors.RemoteCertificateNameMismatch))
        {
            return false;
        }

        using var custom = new X509Chain();
        custom.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        custom.ChainPolicy.CustomTrustStore.Add(connection.Root);
        custom.ChainPolicy.ExtraStore.Add(connection.Intermediate);
        custom.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        using var leaf = X509CertificateLoader.LoadCertificate(certificate.GetRawCertData());
        return custom.Build(leaf);
    }

    private void Remember(Uri? url)
    {
        RememberedUrl = url?.AbsoluteUri ?? RememberedUrl;
        if (_statePath is null)
        {
            return;
        }

        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(_statePath)!);
            File.WriteAllText(_statePath, JsonSerializer.Serialize(new Remembered(url?.AbsoluteUri), s_json));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Not remembered: connect again on the next start.
        }
    }

    private sealed record Remembered(string? Url);

    /// <summary>Puts every request of the TestBench's network on the run's timeline.</summary>
    private sealed class NetworkLog(HttpMessageHandler inner) : DelegatingHandler(inner)
    {
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var uri = request.RequestUri!;
            try
            {
                var response = await base.SendAsync(request, cancellationToken);
                Runs.RunLog.Current?.Network(request.Method.Method, uri.AbsoluteUri, (int)response.StatusCode, Service(uri));
                return response;
            }
            catch (HttpRequestException ex)
            {
                Runs.RunLog.Current?.Network(request.Method.Method, uri.AbsoluteUri, 0, Service(uri) + ": " + ex.Message);
                throw;
            }
        }

        private static string Service(Uri uri) => uri.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault()?.ToUpperInvariant() switch
        {
            "CRL" => "CRL",
            "OCSP" => "OCSP",
            "TSA" or "TSR" => "TSA",
            "AIA" => "AIA",
            "CSC" => "CSC",
            _ => uri.Host,
        };
    }

    /// <summary>Follows the Sandbox's simulated OAuth login page: one GET, and the redirect it answers.</summary>
    private sealed class SandboxAuthorization : IAuthorizationCodeHandler
    {
        public async ValueTask<Uri> AuthorizeAsync(Uri authorizationUri, Uri redirectUri, CancellationToken cancellationToken)
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, authorizationUri);
            using var noRedirect = new HttpClient(new SocketsHttpHandler { AllowAutoRedirect = false });
            using var response = await noRedirect.SendAsync(request, cancellationToken);
            return response.Headers.Location ?? throw new HttpRequestException($"The Sandbox's authorization page did not redirect ({(int)response.StatusCode}).");
        }
    }
}

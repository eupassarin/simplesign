using System.Net;
using System.Reflection;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using SimpleSign.Agent.Localization;
using SimpleSign.Agent.Services;

namespace SimpleSign.Agent.Server;

/// <summary>
/// The local signing agent web pages call (H1): Kestrel on 127.0.0.1 only, an origin allow-list
/// confirmed by the user, a consent dialog for every signature and the PIN asked by the app.
/// </summary>
internal sealed class AgentServer : IAsyncDisposable
{
    private const long MaxBodyBytes = 1024 * 1024;
    private readonly AgentServices _services;
    private readonly AgentSigner _signer;
    private readonly RateLimiter _rate = new(20, TimeSpan.FromMinutes(1));
#pragma warning disable CA2213 // Disposed in StopAsync, which DisposeAsync calls.
    private WebApplication? _app;
#pragma warning restore CA2213

    public AgentServer(AgentServices services, TokenSessionCache sessions, Func<CancellationToken, Task<IReadOnlyList<CertificateEntry>>>? certificates = null)
    {
        _services = services;
        Origins = new OriginPolicy(services.Settings);
        _signer = new AgentSigner(services, sessions, certificates);
    }

    public OriginPolicy Origins { get; }

    public bool IsRunning => _app is not null;

    public int Port { get; private set; }

    public string? LastError { get; private set; }

    public event EventHandler? StateChanged;

    public static string Version => Assembly.GetExecutingAssembly().GetName().Version?.ToString(3) ?? "0.0.0";

    public async Task StartAsync(int port)
    {
        await StopAsync();
        var builder = WebApplication.CreateSlimBuilder(new WebApplicationOptions { ContentRootPath = AppContext.BaseDirectory });
        builder.Logging.ClearProviders();
        builder.WebHost.ConfigureKestrel(o =>
        {
            o.Listen(IPAddress.Loopback, port);
            o.Limits.MaxRequestBodySize = MaxBodyBytes;
            o.AddServerHeader = false;
        });
        var app = builder.Build();
        app.Run(HandleAsync);
        try
        {
            await app.StartAsync();
        }
        catch (IOException ex)
        {
            LastError = L.T("agent.portInUse", port, ex.Message);
            await app.DisposeAsync();
            StateChanged?.Invoke(this, EventArgs.Empty);
            throw;
        }

        _app = app;
        Port = port;
        LastError = null;
        _services.Log.Add("Agent", L.T("log.listening", port));
        StateChanged?.Invoke(this, EventArgs.Empty);
    }

    public async Task StopAsync()
    {
        if (_app is { } app)
        {
            _app = null;
            await app.StopAsync();
            await app.DisposeAsync();
            _services.Log.Add("Agent", L.T("log.stopped"));
            StateChanged?.Invoke(this, EventArgs.Empty);
        }
    }

    public ValueTask DisposeAsync() => new(StopAsync());

    internal async Task HandleAsync(HttpContext context)
    {
        var request = context.Request;
        var response = context.Response;
        string? header = request.Headers.Origin;
        string? origin = header is null ? OriginPolicy.LocalApplication : OriginPolicy.Normalize(header);
        string path = request.Path.Value ?? "/";
        if (origin is null)
        {
            await WriteErrorAsync(response, 403, L.T("api.originNotAllowed"));
            return;
        }

        var state = Origins.Check(origin);
        if (state == OriginState.Blocked)
        {
            await WriteErrorAsync(response, 403, L.T("api.originBlocked"));
            return;
        }

        if (header is not null)
        {
            // Echo only the exact origin; credentials are never needed.
            response.Headers.AccessControlAllowOrigin = origin;
            response.Headers.Vary = "Origin";
        }

        if (HttpMethods.IsOptions(request.Method))
        {
            response.Headers.AccessControlAllowMethods = "GET, POST, OPTIONS";
            response.Headers.AccessControlAllowHeaders = "Content-Type";
            response.Headers.AccessControlMaxAge = "600";
            if (request.Headers.ContainsKey("Access-Control-Request-Private-Network"))
            {
                response.Headers["Access-Control-Allow-Private-Network"] = "true";
            }

            response.StatusCode = 204;
            return;
        }

        if (path.Equals("/api/health", StringComparison.OrdinalIgnoreCase) && HttpMethods.IsGet(request.Method))
        {
            await WriteAsync(response, new AgentHealth { Version = Version }, AgentJsonContext.Default.AgentHealth);
            return;
        }

        bool known = path.Equals("/api/certificates", StringComparison.OrdinalIgnoreCase) && HttpMethods.IsGet(request.Method)
            || path.Equals("/api/sign", StringComparison.OrdinalIgnoreCase) && HttpMethods.IsPost(request.Method);
        if (!known)
        {
            await WriteErrorAsync(response, 404, L.T("api.notFound"));
            return;
        }

        if (!_rate.TryAcquire(origin))
        {
            await WriteErrorAsync(response, 429, L.T("api.rateLimited"));
            return;
        }

        string label = origin == OriginPolicy.LocalApplication ? L.T("agent.localApplication") : origin;
        if (state == OriginState.Unknown && !await AskSiteAsync(origin, label))
        {
            _services.Log.Add("Agent", L.T("log.accessRefused", label), isError: true);
            await WriteErrorAsync(response, 403, L.T("api.accessDenied"));
            return;
        }

        try
        {
            if (path.Equals("/api/certificates", StringComparison.OrdinalIgnoreCase))
            {
                string source = request.Query["source"].ToString() is { Length: > 0 } s ? s.ToLowerInvariant() : "all";
                bool icp = bool.TryParse(request.Query["filterIcpBrasil"], out bool f) && f;
                var list = await _signer.ListAsync(source, icp, context.RequestAborted);
                _services.Log.Add("Agent", L.T("log.listed", label, list.Count));
                await WriteAsync(response, list, AgentJsonContext.Default.ListAgentCertificate);
                return;
            }

            var body = await JsonSerializer.DeserializeAsync(request.Body, AgentJsonContext.Default.AgentSignRequest, context.RequestAborted);
            if (body is null || string.IsNullOrWhiteSpace(body.Thumbprint))
            {
                await WriteErrorAsync(response, 400, L.T("api.thumbprintRequired"));
                return;
            }

            if ((body.SignRequests?.Count ?? 0) is 0 or > AgentSigner.MaxItems)
            {
                await WriteErrorAsync(response, 400, L.T("api.itemsRange", AgentSigner.MaxItems));
                return;
            }

            var results = await _signer.SignAsync(label, body, context.RequestAborted);
            if (results is null)
            {
                _services.Log.Add("Agent", L.T("log.signRefused", label), isError: true);
                await WriteErrorAsync(response, 403, L.T("api.signRefused"));
                return;
            }

            int signed = results.Count(r => r.Error is null);
            _services.CountSignatures(signed);
            _services.Log.Add("Agent", L.T("log.signed", label, signed, results.Count - signed), isError: signed < results.Count);
            await WriteAsync(response, results, AgentJsonContext.Default.ListAgentSignResult);
        }
        catch (JsonException)
        {
            await WriteErrorAsync(response, 400, L.T("api.invalidJson"));
        }
        catch (KeyNotFoundException ex)
        {
            await WriteErrorAsync(response, 404, ex.Message);
        }
#pragma warning disable CA1031 // The agent must answer every request.
        catch (Exception ex) when (ex is not OperationCanceledException)
#pragma warning restore CA1031
        {
            _services.Log.Add("Agent", $"{label}: {ex.Message}", isError: true);
            await WriteErrorAsync(response, 500, ex.Message);
        }
    }

    private async Task<bool> AskSiteAsync(string origin, string label)
    {
        var decision = await _services.Dialogs.AskConsentAsync(new ConsentRequest(label, L.T("consent.site.title"),
            L.T("consent.site.message", label), null, OfferRemember: origin != OriginPolicy.LocalApplication));
        if (decision == ConsentDecision.Deny)
        {
            return false;
        }

        Origins.Allow(origin, decision == ConsentDecision.AllowAlways);
        _services.Log.Add("Agent", L.T(decision == ConsentDecision.AllowAlways ? "log.accessAllowedAlways" : "log.accessAllowedOnce", label));
        return true;
    }

    private static Task WriteAsync<T>(HttpResponse response, T value, System.Text.Json.Serialization.Metadata.JsonTypeInfo<T> type)
    {
        response.ContentType = "application/json; charset=utf-8";
        return JsonSerializer.SerializeAsync(response.Body, value, type);
    }

    private static Task WriteErrorAsync(HttpResponse response, int status, string message)
    {
        response.StatusCode = status;
        return WriteAsync(response, new AgentError { Error = message }, AgentJsonContext.Default.AgentError);
    }
}

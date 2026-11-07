using System.Text.Json;
using System.Text.Json.Serialization;
using SimpleSign.Playbook.Model;

namespace SimpleSign.Playbook.Runs;

/// <summary>What the playbook needs of a Sandbox's /api/info.</summary>
public sealed record SandboxSummary(
    string Name,
    string Version,
    string BaseUrl,
    string RootThumbprint,
    string RootSubject,
    string PfxPassword,
    IReadOnlyList<string> LoopbackOrigins,
    SandboxTsaSummary Tsa);

/// <summary>The Sandbox's TSA addresses.</summary>
public sealed record SandboxTsaSummary(string Url, string AuthenticatedUrl, string UntrustedUrl, string RevokedUrl, string WrongNameUrl, string User, string Password);

/// <summary>A certificate of the Sandbox, as its /api/pki lists it.</summary>
public sealed record SandboxCertificateSummary(string Id, string Title, string Description, string Subject, string? Problem, DateTimeOffset? RevokedAt);

/// <summary>The Sandbox's /api/pki.</summary>
public sealed record SandboxPkiSummary(IReadOnlyList<SandboxCertificateSummary> Authorities, IReadOnlyList<SandboxCertificateSummary> Certificates);

/// <summary>The admin API of a SimpleSign Sandbox. A fake one in the tests.</summary>
public interface ISandboxClient
{
    Uri Url { get; }

    Task<SandboxSummary> InfoAsync(CancellationToken cancellationToken);

    Task<SandboxPkiSummary> PkiAsync(CancellationToken cancellationToken);

    /// <summary>The root and the intermediate (PEM), for --tls-trust.</summary>
    Task<string> ChainPemAsync(CancellationToken cancellationToken);

    Task<string> RootPemAsync(CancellationToken cancellationToken);

    /// <summary>Applies a Sandbox action of a step; a certificate action returns the PKCS#12.</summary>
    Task<byte[]?> ApplyAsync(SandboxAction action, CancellationToken cancellationToken);

    Task ResetAsync(CancellationToken cancellationToken);

    /// <summary>The requests answered after <paramref name="after"/> (the id of the last one seen).</summary>
    Task<IReadOnlyList<SandboxRequestRecord>> LogAsync(long after, CancellationToken cancellationToken);
}

/// <summary>Talks to a running Sandbox over HTTP (its admin API answers this machine).</summary>
public sealed class SandboxClient : ISandboxClient, IDisposable
{
    private readonly HttpClient _http;

    public SandboxClient(Uri url, HttpMessageHandler? handler = null)
    {
        ArgumentNullException.ThrowIfNull(url);
        Url = url.AbsoluteUri.EndsWith('/') ? url : new Uri(url.AbsoluteUri + "/");
        _http = new HttpClient(handler ?? new SocketsHttpHandler(), disposeHandler: true) { BaseAddress = Url, Timeout = TimeSpan.FromSeconds(30) };
    }

    public Uri Url { get; }

    public async Task<SandboxSummary> InfoAsync(CancellationToken cancellationToken) =>
        await _http.GetFromJsonAsync("api/info", SandboxJson.Default.SandboxSummary, cancellationToken)
        ?? throw new InvalidOperationException("The Sandbox answered an empty /api/info.");

    public async Task<SandboxPkiSummary> PkiAsync(CancellationToken cancellationToken) =>
        await _http.GetFromJsonAsync("api/pki", SandboxJson.Default.SandboxPkiSummary, cancellationToken)
        ?? throw new InvalidOperationException("The Sandbox answered an empty /api/pki.");

    public Task<string> ChainPemAsync(CancellationToken cancellationToken) => _http.GetStringAsync("chain.pem", cancellationToken);

    public Task<string> RootPemAsync(CancellationToken cancellationToken) => _http.GetStringAsync("root.pem", cancellationToken);

    public async Task<byte[]?> ApplyAsync(SandboxAction action, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(action);
        switch (action.Sandbox)
        {
            case "reset":
                await ResetAsync(cancellationToken);
                return null;
            case "revoke":
                await Send(HttpMethod.Post, $"api/certificates/{Uri.EscapeDataString(action.Certificate!)}/revoke",
                    JsonContent.Create(new RevokeBody(action.Reason, action.Publication ?? "Both"), SandboxJson.Default.RevokeBody), cancellationToken);
                return null;
            case "unrevoke":
                await Send(HttpMethod.Post, $"api/certificates/{Uri.EscapeDataString(action.Certificate!)}/unrevoke", null, cancellationToken);
                return null;
            case "faults":
                {
                    // Only the failures the action names change; the others keep their current value.
                    using var current = await _http.GetAsync("api/faults", cancellationToken);
                    await Ensure(current, cancellationToken);
                    var faults = await current.Content.ReadFromJsonAsync(SandboxJson.Default.DictionaryStringJsonElement, cancellationToken) ?? [];
                    void Set(string name, string? value)
                    {
                        if (value is not null)
                        {
                            faults[name] = JsonSerializer.SerializeToElement(value, SandboxJson.Default.String);
                        }
                    }

                    Set("crl", action.Crl);
                    Set("ocsp", action.Ocsp);
                    Set("tsa", action.Tsa);
                    Set("ocspSigner", action.OcspSigner);
                    await Send(HttpMethod.Put, "api/faults", JsonContent.Create(faults, SandboxJson.Default.DictionaryStringJsonElement), cancellationToken);
                    return null;
                }

            case "certificate":
                return await Bytes(HttpMethod.Get, $"api/certificates/{Uri.EscapeDataString(action.Id!)}/pfx", cancellationToken);
            case "shortLived":
                return await Bytes(HttpMethod.Post, $"api/certificates/short-lived?seconds={action.Seconds ?? 10}", cancellationToken);
            default:
                throw new InvalidOperationException($"Unknown Sandbox action '{action.Sandbox}'.");
        }
    }

    public Task ResetAsync(CancellationToken cancellationToken) => Send(HttpMethod.Post, "api/reset", null, cancellationToken);

    public async Task<IReadOnlyList<SandboxRequestRecord>> LogAsync(long after, CancellationToken cancellationToken) =>
        await _http.GetFromJsonAsync($"api/log?after={after}", SandboxJson.Default.IReadOnlyListSandboxRequestRecord, cancellationToken) ?? [];

    public void Dispose() => _http.Dispose();

    private async Task Send(HttpMethod method, string path, HttpContent? content, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(method, path) { Content = content };
        using var response = await _http.SendAsync(request, cancellationToken);
        await Ensure(response, cancellationToken);
    }

    private async Task<byte[]> Bytes(HttpMethod method, string path, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(method, path);
        using var response = await _http.SendAsync(request, cancellationToken);
        await Ensure(response, cancellationToken);
        return await response.Content.ReadAsByteArrayAsync(cancellationToken);
    }

    /// <summary>A failed admin call says what the Sandbox answered.</summary>
    private static async Task Ensure(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        if (!response.IsSuccessStatusCode)
        {
            string body = await response.Content.ReadAsStringAsync(cancellationToken);
            throw new HttpRequestException(
                $"The Sandbox answered {(int)response.StatusCode} to {response.RequestMessage?.Method} {response.RequestMessage?.RequestUri?.PathAndQuery}: {body}",
                null, response.StatusCode);
        }
    }
}

/// <summary>The body of a revocation.</summary>
public sealed record RevokeBody(string? Reason, string Publication);

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase, PropertyNameCaseInsensitive = true)]
[JsonSerializable(typeof(SandboxSummary))]
[JsonSerializable(typeof(SandboxPkiSummary))]
[JsonSerializable(typeof(RevokeBody))]
[JsonSerializable(typeof(IReadOnlyList<SandboxRequestRecord>))]
[JsonSerializable(typeof(Dictionary<string, JsonElement>))]
[JsonSerializable(typeof(string))]
internal sealed partial class SandboxJson : JsonSerializerContext;

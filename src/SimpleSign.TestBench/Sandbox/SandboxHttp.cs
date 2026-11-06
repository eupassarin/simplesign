using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using SimpleSign.Core.Http;

namespace SimpleSign.TestBench.Sandbox;

/// <summary>One request the sandbox answered (shown in the UI's network log).</summary>
internal sealed record SandboxRequest(DateTimeOffset Time, string Method, string Url, int Status, string Service);

/// <summary>
/// The sandbox "internet": an in-process <see cref="HttpMessageHandler"/> that serves the TSA,
/// CRLs, AIA certificates and the fake PSC/CSC on <c>*.sandbox.simplesign.test</c>. Signing and
/// validation get it through <see cref="IHttpClientProvider"/>, so nothing leaves the machine.
/// </summary>
internal sealed class SandboxNetwork : HttpMessageHandler, IHttpClientProvider
{
    private readonly SandboxPki _pki;
    private readonly HttpClient _client;
    private readonly HttpMessageInvoker _psc;
    private readonly HttpMessageInvoker _csc;
    private readonly Lock _gate = new();
    private readonly List<SandboxRequest> _log = [];

    public SandboxNetwork(SandboxPki pki, SandboxPsc psc, SandboxCsc csc)
    {
        _pki = pki;
        Tsa = new SandboxTsa(pki);
        Psc = psc;
        Csc = csc;
        _psc = new HttpMessageInvoker(psc, disposeHandler: false);
        _csc = new HttpMessageInvoker(csc, disposeHandler: false);
        _client = new HttpClient(this, disposeHandler: false) { Timeout = TimeSpan.FromSeconds(30) };
    }

    public SandboxTsa Tsa { get; }

    public SandboxPsc Psc { get; }

    public SandboxCsc Csc { get; }

    public IReadOnlyList<SandboxRequest> Log
    {
        get
        {
            lock (_gate)
            {
                return [.. _log];
            }
        }
    }

    public HttpClient GetClient() => _client;

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var uri = request.RequestUri!;
        string host = uri.Host;
        (string service, HttpResponseMessage response) = host switch
        {
            _ when host == $"tsa.{SandboxPki.Host}" => ("TSA", await TimestampAsync(request, cancellationToken)),
            _ when host == $"crl.{SandboxPki.Host}" => ("CRL", Crl(uri)),
            _ when host == $"aia.{SandboxPki.Host}" => ("AIA", Aia(uri)),
            _ when host == $"psc.{SandboxPki.Host}" => ("PSC", await _psc.SendAsync(request, cancellationToken)),
            _ when host == $"csc.{SandboxPki.Host}" => ("CSC", await _csc.SendAsync(request, cancellationToken)),
            _ => ("Blocked", Text(HttpStatusCode.BadGateway, $"The sandbox is offline: {host} is not a sandbox service. Switch to Real to reach the internet.")),
        };
        lock (_gate)
        {
            _log.Add(new SandboxRequest(DateTimeOffset.Now, request.Method.Method, uri.AbsoluteUri, (int)response.StatusCode, service));
            if (_log.Count > 300)
            {
                _log.RemoveAt(0);
            }
        }

        return response;
    }

    private async Task<HttpResponseMessage> TimestampAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        if (request.RequestUri!.AbsolutePath == SandboxPki.AuthenticatedTsaUri.AbsolutePath)
        {
            string expected = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{SandboxPki.TsaUser}:{SandboxPki.TsaPassword}"));
            if (request.Headers.Authorization is not { Scheme: "Basic" } auth || auth.Parameter != expected)
            {
                var denied = Text(HttpStatusCode.Unauthorized, "This sandbox TSA requires HTTP Basic authentication (sandbox / sandbox-tsa).");
                denied.Headers.WwwAuthenticate.Add(new AuthenticationHeaderValue("Basic", "realm=\"sandbox-tsa\""));
                return denied;
            }
        }

        if (request.Method != HttpMethod.Post || request.Content is null)
        {
            return Text(HttpStatusCode.MethodNotAllowed, "POST an application/timestamp-query.");
        }

        byte[] query = await request.Content.ReadAsByteArrayAsync(cancellationToken);
        return Bytes(Tsa.Respond(query), "application/timestamp-reply");
    }

    private HttpResponseMessage Crl(Uri uri) => uri.AbsolutePath switch
    {
        "/root.crl" => Bytes(_pki.RootCrl, "application/pkix-crl"),
        "/intermediate.crl" => Bytes(_pki.IntermediateCrl, "application/pkix-crl"),
        _ => Text(HttpStatusCode.NotFound, "No such CRL."),
    };

    private HttpResponseMessage Aia(Uri uri) => uri.AbsolutePath switch
    {
        "/root.cer" => Bytes(_pki.Root.RawData, "application/pkix-cert"),
        "/intermediate.cer" => Bytes(_pki.Intermediate.RawData, "application/pkix-cert"),
        _ => Text(HttpStatusCode.NotFound, "No such certificate."),
    };

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _client.Dispose();
            _psc.Dispose();
            _csc.Dispose();
        }

        base.Dispose(disposing);
    }

    private static HttpResponseMessage Bytes(byte[] body, string contentType)
    {
        var content = new ByteArrayContent(body);
        content.Headers.ContentType = new MediaTypeHeaderValue(contentType);
        return new HttpResponseMessage(HttpStatusCode.OK) { Content = content };
    }

    private static HttpResponseMessage Text(HttpStatusCode status, string message) =>
        new(status) { Content = new StringContent(message) };
}

/// <summary>Small HTTP helpers shared by the simulated services.</summary>
internal static class SandboxHttp
{
    public static HttpResponseMessage Json(HttpStatusCode status, JsonNode body) => new(status)
    {
        Content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json"),
    };

    public static Dictionary<string, string> Form(string body) =>
        body.Split('&', StringSplitOptions.RemoveEmptyEntries)
            .Select(p => p.Split('=', 2))
            .ToDictionary(p => WebUtility.UrlDecode(p[0]), p => p.Length > 1 ? WebUtility.UrlDecode(p[1]) : string.Empty);

    public static string? Query(Uri uri, string name) =>
        uri.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries)
            .Select(p => p.Split('=', 2))
            .Where(p => Uri.UnescapeDataString(p[0]) == name)
            .Select(p => p.Length > 1 ? Uri.UnescapeDataString(p[1]) : string.Empty)
            .FirstOrDefault();

    /// <summary>PKCE S256 challenge.</summary>
    public static string S256(string verifier) =>
        Convert.ToBase64String(SHA256.HashData(Encoding.ASCII.GetBytes(verifier))).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}

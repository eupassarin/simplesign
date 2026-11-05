using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Shouldly;
using SimpleSign.Desktop.Agent;
using SimpleSign.Desktop.Services;

namespace SimpleSign.Desktop.Tests;

public sealed class AgentServerTests : IAsyncLifetime
{
    private readonly FakeDialogs _dialogs = new();
    private readonly System.Security.Cryptography.X509Certificates.X509Certificate2 _certificate = Fixtures.RsaCertificate();
    private readonly HttpClient _http = new();
    private AppServices _services = null!;
    private AgentServer _agent = null!;
    private int _port;

    public async Task InitializeAsync()
    {
        _services = Fixtures.Services(_dialogs);
        var entry = new CertificateEntry(CertificateSourceKind.File, _certificate, FilePath: "test.pfx");
        _agent = new AgentServer(_services, new TokenSessionCache(), _ => Task.FromResult<IReadOnlyList<CertificateEntry>>([entry]));
        _port = FreePort();
        await _agent.StartAsync(_port);
    }

    public async Task DisposeAsync()
    {
        await _agent.DisposeAsync();
        _http.Dispose();
        _certificate.Dispose();
    }

    [Fact]
    public async Task Health_AnyValidOrigin_RespondsWithExactAllowOrigin()
    {
        using var response = await Send(HttpMethod.Get, "/api/health", "https://portal.example.com");

        response.StatusCode.ShouldBe(HttpStatusCode.OK);
        response.Headers.GetValues("Access-Control-Allow-Origin").Single().ShouldBe("https://portal.example.com");
        (await response.Content.ReadAsStringAsync()).ShouldContain("\"status\":\"ok\"");
        _dialogs.Asked.ShouldBeEmpty();
    }

    [Theory]
    [InlineData("null")]
    [InlineData("file://")]
    [InlineData("chrome-extension://abc")]
    public async Task InvalidOrigin_Forbidden(string origin)
    {
        using var response = await Send(HttpMethod.Get, "/api/certificates", origin);

        response.StatusCode.ShouldBe(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task Preflight_PrivateNetworkAccess_Allowed()
    {
        using var request = new HttpRequestMessage(HttpMethod.Options, Url("/api/sign"));
        request.Headers.Add("Origin", "https://portal.example.com");
        request.Headers.Add("Access-Control-Request-Method", "POST");
        request.Headers.Add("Access-Control-Request-Private-Network", "true");

        using var response = await _http.SendAsync(request);

        response.StatusCode.ShouldBe(HttpStatusCode.NoContent);
        response.Headers.GetValues("Access-Control-Allow-Private-Network").Single().ShouldBe("true");
    }

    [Fact]
    public async Task Certificates_UnknownOriginDenied_Forbidden()
    {
        _dialogs.Site = ConsentDecision.Deny;

        using var response = await Send(HttpMethod.Get, "/api/certificates", "https://evil.example.com");

        response.StatusCode.ShouldBe(HttpStatusCode.Forbidden);
        _dialogs.Asked.Single().Origin.ShouldBe("https://evil.example.com");
    }

    [Fact]
    public async Task Certificates_OriginAllowedOnce_ListsAndDoesNotAskAgain()
    {
        using var first = await Send(HttpMethod.Get, "/api/certificates", "https://portal.example.com");
        using var second = await Send(HttpMethod.Get, "/api/certificates", "https://portal.example.com");

        first.StatusCode.ShouldBe(HttpStatusCode.OK);
        second.StatusCode.ShouldBe(HttpStatusCode.OK);
        (await second.Content.ReadAsStringAsync()).ShouldContain(_certificate.Thumbprint);
        _dialogs.Asked.Count.ShouldBe(1);
        _services.Settings.Current.AllowedOrigins.ShouldBeEmpty();
    }

    [Fact]
    public async Task Certificates_AllowAlways_SavedInSettings()
    {
        _dialogs.Site = ConsentDecision.AllowAlways;

        using var response = await Send(HttpMethod.Get, "/api/certificates", "https://portal.example.com:8443");

        response.StatusCode.ShouldBe(HttpStatusCode.OK);
        _services.Settings.Current.AllowedOrigins.ShouldContain("https://portal.example.com:8443");
    }

    [Fact]
    public async Task Sign_UserConsents_SignsWithTheOldHostSignerContract()
    {
        byte[] attributes = Encoding.UTF8.GetBytes("signed attributes");
        string body = $$"""{"thumbprint":"{{_certificate.Thumbprint}}","hashAlgorithm":"SHA256","documentName":"contrato.pdf","signRequests":[{"id":"7","authenticatedAttributeBase64":"{{Convert.ToBase64String(attributes)}}"}]}""";

        using var response = await Send(HttpMethod.Post, "/api/sign", "https://portal.example.com", body);

        response.StatusCode.ShouldBe(HttpStatusCode.OK);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var item = json.RootElement[0];
        item.GetProperty("id").GetString().ShouldBe("7");
        byte[] signature = Convert.FromBase64String(item.GetProperty("signedHashBase64").GetString()!);
        using var rsa = _certificate.GetRSAPublicKey()!;
        rsa.VerifyData(attributes, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1).ShouldBeTrue();
        _dialogs.Asked.Last().Message.ShouldContain("contrato.pdf");
    }

    [Fact]
    public async Task Sign_UserRefuses_Forbidden()
    {
        _dialogs.Signature = ConsentDecision.Deny;
        string body = $$"""{"thumbprint":"{{_certificate.Thumbprint}}","signRequests":[{"id":"1","authenticatedAttributeBase64":"AA=="}]}""";

        using var response = await Send(HttpMethod.Post, "/api/sign", "https://portal.example.com", body);

        response.StatusCode.ShouldBe(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task Sign_TooManyItems_BadRequest()
    {
        string items = string.Join(",", Enumerable.Range(0, AgentSigner.MaxItems + 1).Select(i => $$"""{"id":"{{i}}","authenticatedAttributeBase64":"AA=="}"""));
        string body = $$"""{"thumbprint":"{{_certificate.Thumbprint}}","signRequests":[{{items}}]}""";

        using var response = await Send(HttpMethod.Post, "/api/sign", "https://portal.example.com", body);

        response.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task Sign_UnknownCertificate_NotFound()
    {
        string body = """{"thumbprint":"00","signRequests":[{"id":"1","authenticatedAttributeBase64":"AA=="}]}""";

        using var response = await Send(HttpMethod.Post, "/api/sign", "https://portal.example.com", body);

        response.StatusCode.ShouldBe(HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task FileEndpointsOfTheOldHostSigner_AreGone()
    {
        using var response = await Send(HttpMethod.Post, "/api/sign-file", "https://portal.example.com", "{}");

        response.StatusCode.ShouldBe(HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task BlockedOrigin_Forbidden()
    {
        _services.Settings.Current.BlockedOrigins.Add("https://blocked.example.com");

        using var response = await Send(HttpMethod.Get, "/api/health", "https://blocked.example.com");

        response.StatusCode.ShouldBe(HttpStatusCode.Forbidden);
    }

    private Uri Url(string path) => new($"http://127.0.0.1:{_port}{path}");

    private async Task<HttpResponseMessage> Send(HttpMethod method, string path, string? origin, string? body = null)
    {
        using var request = new HttpRequestMessage(method, Url(path));
        if (origin is not null)
        {
            request.Headers.Add("Origin", origin);
        }

        if (body is not null)
        {
            request.Content = new StringContent(body, Encoding.UTF8, "application/json");
        }

        return await _http.SendAsync(request);
    }

    private static int FreePort()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        return ((IPEndPoint)listener.LocalEndpoint).Port;
    }
}

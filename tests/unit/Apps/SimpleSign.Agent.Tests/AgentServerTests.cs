using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Shouldly;
using SimpleSign.Agent.Server;
using SimpleSign.Agent.Services;
using SimpleSign.TestHelpers;

namespace SimpleSign.Agent.Tests;

[Trait("Category", "Unit")]
public sealed class AgentServerTests : IAsyncLifetime
{
    private readonly FakeDialogs _dialogs = new();
    private readonly System.Security.Cryptography.X509Certificates.X509Certificate2 _certificate = Fixtures.RsaCertificate();
    private readonly HttpClient _http = new();
    private AgentServices _services = null!;
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
    public async Task Certificates_TrustAndSigningOnly_ListOnlyMatchingCertificates()
    {
        using var pki = new SyntheticPki();
        using var expired = Fixtures.RsaCertificate("CN=Expired", validDays: -1);
        var services = new AgentServices(_services.Settings, _dialogs)
        {
            TrustFrameworks = new TrustFrameworks(
                [new TrustFramework("lab", new Lazy<SimpleSign.Core.Extensions.ICountryExtension>(() => new TrustFrameworksTests.TestExtension("XX", pki)))]),
        };
        CertificateEntry[] entries =
        [
            new(CertificateSourceKind.File, _certificate, FilePath: "a.pfx"),
            new(CertificateSourceKind.File, pki.Leaf, FilePath: "b.pfx"),
            new(CertificateSourceKind.File, expired, FilePath: "c.pfx"),
        ];
        _dialogs.Site = ConsentDecision.AllowAlways;
        int port = FreePort();
        await using var agent = new AgentServer(services, new TokenSessionCache(), _ => Task.FromResult<IReadOnlyList<CertificateEntry>>(entries));
        await agent.StartAsync(port);

        async Task<string> List(string query)
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, new Uri($"http://127.0.0.1:{port}/api/certificates{query}"));
            request.Headers.Add("Origin", "https://portal.example.com");
            using var response = await _http.SendAsync(request);
            return $"{(int)response.StatusCode} {await response.Content.ReadAsStringAsync()}";
        }

        string byTrust = await List("?trust=lab");
        string byCountry = await List("?country=xx");
        string signingOnly = await List("?signingOnly=true");
        string unknown = await List("?country=ZZ");

        byTrust.ShouldStartWith("200");
        byTrust.ShouldContain(pki.Leaf.Thumbprint);
        byTrust.ShouldNotContain(_certificate.Thumbprint);
        byCountry.ShouldBe(byTrust);
        signingOnly.ShouldContain(_certificate.Thumbprint);
        signingOnly.ShouldNotContain(expired.Thumbprint);
        unknown.ShouldStartWith("400");
        unknown.ShouldContain("lab (XX)");
    }

    [Fact]
    public async Task Certificates_FilterIcpBrasil_StillLeavesOutOtherCertificates()
    {
        using var response = await Send(HttpMethod.Get, "/api/certificates?filterIcpBrasil=true", "https://portal.example.com");

        response.StatusCode.ShouldBe(HttpStatusCode.OK);
        (await response.Content.ReadAsStringAsync()).ShouldBe("[]");
    }

    [Fact]
    public async Task Sign_UserConsents_SignsWithTheOldHostSignerContract()
    {
        byte[] attributes = SelfTest.SignedAttributes(SHA256.HashData("contrato"u8));
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
        _dialogs.Asked.Last().Message.ShouldContain(Convert.ToHexString(SHA256.HashData("contrato"u8))[..8]);
    }

    [Fact]
    public async Task Sign_SignedAttributesOfACadesSigner_SignsThem()
    {
        byte[]? attributes = null;
        var capture = new SimpleSign.Core.Signing.DelegatingExternalSigner(data =>
        {
            attributes ??= data;
            using var key = _certificate.GetRSAPrivateKey()!;
            return Task.FromResult(key.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
        });
        await SimpleSign.CAdES.CadesSigner.Document("contract"u8.ToArray()).WithExternalSigner(_certificate, capture)
            .WithSigningPolicy(SimpleSign.TestHelpers.TestPolicies.SigningDatesOnly).SignAsync();

        using var response = await Send(HttpMethod.Post, "/api/sign", "https://portal.example.com", SignBody(attributes!));

        response.StatusCode.ShouldBe(HttpStatusCode.OK);
        (await response.Content.ReadAsStringAsync()).ShouldContain("signedHashBase64");
    }

    [Fact]
    public async Task Sign_RawBytes_BadRequestWithoutAsking()
    {
        using var response = await Send(HttpMethod.Post, "/api/sign", "https://portal.example.com", SignBody(SHA256.HashData("document"u8)));

        response.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
        (await response.Content.ReadAsStringAsync()).ShouldContain("SignedInfo");
        _dialogs.Asked.ShouldAllBe(asked => string.IsNullOrEmpty(asked.CertificateHolder));
    }

    [Fact]
    public async Task Sign_NotBase64_BadRequest()
    {
        string body = $$"""{"thumbprint":"{{_certificate.Thumbprint}}","signRequests":[{"id":"1","authenticatedAttributeBase64":"not base64!"}]}""";

        using var response = await Send(HttpMethod.Post, "/api/sign", "https://portal.example.com", body);

        response.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
    }

    private string SignBody(byte[] data) =>
        $$"""{"thumbprint":"{{_certificate.Thumbprint}}","signRequests":[{"id":"1","authenticatedAttributeBase64":"{{Convert.ToBase64String(data)}}"}]}""";

    [Fact]
    public async Task Sign_UserRefuses_Forbidden()
    {
        _dialogs.Signature = ConsentDecision.Deny;

        using var response = await Send(HttpMethod.Post, "/api/sign", "https://portal.example.com", SignBody(SelfTest.Payload));

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
    public async Task Sign_UnsupportedHashAlgorithm_BadRequestWithoutAsking()
    {
        string body = $$"""{"thumbprint":"{{_certificate.Thumbprint}}","hashAlgorithm":"SHA1","signRequests":[{"id":"1","authenticatedAttributeBase64":"AA=="}]}""";

        using var response = await Send(HttpMethod.Post, "/api/sign", "https://portal.example.com", body);

        response.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
        // Only the site access was asked: the signature confirmation (which names the holder) never showed.
        _dialogs.Asked.ShouldAllBe(asked => string.IsNullOrEmpty(asked.CertificateHolder));
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

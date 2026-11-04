using System.Net;
using System.Net.Sockets;
using Shouldly;
using Xunit;

namespace SimpleSign.Signers.Cloud.Tests;

[Trait("Category", "Unit")]
public sealed class OAuthPkceTests
{
    [Fact]
    public void ComputeChallenge_Rfc7636Vector_MatchesSpec() =>
        OAuthPkce.ComputeChallenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
            .ShouldBe("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");

    [Fact]
    public void Create_ProducesUrlSafeVerifierOfValidLength()
    {
        var pkce = OAuthPkce.Create();

        pkce.Verifier.Length.ShouldBeInRange(43, 128);
        pkce.Verifier.ShouldAllBe(c => char.IsAsciiLetterOrDigit(c) || c == '-' || c == '_');
        pkce.Challenge.ShouldBe(OAuthPkce.ComputeChallenge(pkce.Verifier));
        OAuthPkce.Method.ShouldBe("S256");
    }

    [Fact]
    public void Create_TwoCalls_AreDifferent()
    {
        var a = OAuthPkce.Create();
        var b = OAuthPkce.Create();

        a.Verifier.ShouldNotBe(b.Verifier);
        a.State.ShouldNotBe(b.State);
    }
}

[Trait("Category", "Unit")]
public sealed class OAuthTokenTests
{
    [Fact]
    public void ToString_HidesAccessToken() =>
        new OAuthToken("super-secret", null, "service").ToString().ShouldNotContain("super-secret");

    [Fact]
    public void IsExpired_PastExpiry_IsTrue() =>
        new OAuthToken("t", DateTimeOffset.UtcNow.AddMinutes(-1), null).IsExpired().ShouldBeTrue();

    [Fact]
    public void IsExpired_WithinSafetyMargin_IsTrue() =>
        new OAuthToken("t", DateTimeOffset.UtcNow.AddSeconds(10), null).IsExpired().ShouldBeTrue();

    [Fact]
    public void IsExpired_NoExpiry_IsFalse() =>
        new OAuthToken("t", null, null).IsExpired().ShouldBeFalse();
}

[Trait("Category", "Unit")]
public sealed class CloudHttpTests
{
    [Theory]
    [InlineData("http://psc.example/v0/")]
    [InlineData("ftp://psc.example/v0/")]
    public void ValidateBaseUri_NotHttpsOutsideLoopback_Throws(string uri) =>
        Should.Throw<ArgumentException>(() => CloudHttp.ValidateBaseUri(new Uri(uri), "options"));

    [Fact]
    public void ValidateBaseUri_MissingTrailingSlash_IsAdded() =>
        CloudHttp.ValidateBaseUri(new Uri("https://psc.example/v0"), "options").AbsoluteUri.ShouldBe("https://psc.example/v0/");

    [Fact]
    public void ValidateBaseUri_HttpLoopback_IsAllowed() =>
        CloudHttp.ValidateBaseUri(new Uri("http://127.0.0.1:8080/v0/"), "options").ShouldNotBeNull();

    [Fact]
    public void ReadAuthorizationCode_MatchingState_ReturnsCode() =>
        CloudHttp.ReadAuthorizationCode(new Uri("http://127.0.0.1/cb?code=abc%2B1&state=s1"), "s1").ShouldBe("abc+1");

    [Fact]
    public void ReadAuthorizationCode_WrongState_Throws()
    {
        var ex = Should.Throw<CloudSigningException>(() =>
            CloudHttp.ReadAuthorizationCode(new Uri("http://127.0.0.1/cb?code=abc&state=evil"), "s1"));
        ex.Message.ShouldContain("state");
    }

    [Fact]
    public void ReadAuthorizationCode_Error_ThrowsWithServiceError()
    {
        var ex = Should.Throw<CloudSigningException>(() =>
            CloudHttp.ReadAuthorizationCode(new Uri("http://127.0.0.1/cb?error=access_denied&error_description=No&state=s1"), "s1"));
        ex.Error.ShouldBe("access_denied");
        ex.ErrorDescription.ShouldBe("No");
    }

    [Fact]
    public void ReadAuthorizationCode_NoCode_Throws() =>
        Should.Throw<CloudSigningException>(() => CloudHttp.ReadAuthorizationCode(new Uri("http://127.0.0.1/cb?state=s1"), "s1"));

    [Fact]
    public async Task PostJsonAsync_ErrorBody_MapsToException()
    {
        using var http = new HttpClient(new SimpleSign.TestHelpers.MockHttpHandler(_ => Task.FromResult(
            Fakes.FakePscServer.Json(HttpStatusCode.BadRequest, new System.Text.Json.Nodes.JsonObject
            {
                ["error"] = "invalid_request",
                ["error_description"] = "Bad hash",
            }))));

        var ex = await Should.ThrowAsync<CloudSigningException>(() => CloudHttp.PostJsonAsync(
            http, new Uri("https://x.example/a"), new System.Text.Json.Nodes.JsonObject(), "secret-token", "Test call", CancellationToken.None));

        ex.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
        ex.Error.ShouldBe("invalid_request");
        ex.Message.ShouldContain("Bad hash");
        ex.Message.ShouldNotContain("secret-token");
    }

    [Fact]
    public async Task PostJsonAsync_NonJsonBody_ThrowsWithoutEchoingIt()
    {
        using var http = new HttpClient(new SimpleSign.TestHelpers.MockHttpHandler(_ => Task.FromResult(
            new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("<html>secret page</html>") })));

        var ex = await Should.ThrowAsync<CloudSigningException>(() => CloudHttp.PostJsonAsync(
            http, new Uri("https://x.example/a"), new System.Text.Json.Nodes.JsonObject(), null, "Test call", CancellationToken.None));

        ex.Message.ShouldNotContain("secret page");
    }

    [Fact]
    public async Task PostJsonAsync_NetworkFailure_Throws()
    {
        using var http = SimpleSign.TestHelpers.MockHttpHandler.Failing();

        await Should.ThrowAsync<CloudSigningException>(() => CloudHttp.PostJsonAsync(
            http, new Uri("https://x.example/a"), new System.Text.Json.Nodes.JsonObject(), null, "Test call", CancellationToken.None));
    }
}

[Trait("Category", "Unit")]
public sealed class LoopbackAuthorizationHandlerTests
{
    private static int FreePort()
    {
        using var socket = new TcpListener(IPAddress.Loopback, 0);
        socket.Start();
        return ((IPEndPoint)socket.LocalEndpoint).Port;
    }

    [Fact]
    public async Task AuthorizeAsync_BrowserRedirect_ReturnsRedirectUri()
    {
        var redirect = new Uri($"http://127.0.0.1:{FreePort()}/callback");
        using var browser = new HttpClient();
        var handler = new LoopbackAuthorizationHandler(openBrowser: uri =>
            _ = Task.Run(async () =>
            {
                // A stray request to another path must be ignored.
                (await browser.GetAsync(new Uri(redirect, "/favicon.ico"))).StatusCode.ShouldBe(HttpStatusCode.NotFound);
                (await browser.GetStringAsync(new Uri(redirect + "?code=xyz&state=s1"))).ShouldContain("close this window");
            }));

        var result = await handler.AuthorizeAsync(new Uri("https://psc.example/v0/oauth/authorize"), redirect, CancellationToken.None);

        CloudHttp.ReadAuthorizationCode(result, "s1").ShouldBe("xyz");
    }

    [Fact]
    public async Task AuthorizeAsync_NoRedirect_TimesOut()
    {
        var handler = new LoopbackAuthorizationHandler(openBrowser: _ => { }, timeout: TimeSpan.FromMilliseconds(200));

        await Should.ThrowAsync<TimeoutException>(async () => await handler.AuthorizeAsync(
            new Uri("https://psc.example/a"), new Uri($"http://127.0.0.1:{FreePort()}/callback"), CancellationToken.None));
    }

    [Theory]
    [InlineData("https://127.0.0.1/callback")]
    [InlineData("http://example.com/callback")]
    public async Task AuthorizeAsync_NonLoopbackRedirect_Throws(string redirect) =>
        await Should.ThrowAsync<ArgumentException>(async () => await new LoopbackAuthorizationHandler(_ => { })
            .AuthorizeAsync(new Uri("https://psc.example/a"), new Uri(redirect), CancellationToken.None));
}

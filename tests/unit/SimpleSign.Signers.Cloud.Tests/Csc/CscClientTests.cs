using Shouldly;
using SimpleSign.Signers.Cloud.Csc;
using SimpleSign.Signers.Cloud.Tests.Fakes;
using Xunit;

namespace SimpleSign.Signers.Cloud.Tests.Csc;

[Trait("Category", "Unit")]
public sealed class CscClientTests : IDisposable
{
    private readonly TestPki _pki = new();
    private readonly FakeCscServer _server;

    public CscClientTests()
    {
        _server = new FakeCscServer(_pki);
    }

    public void Dispose()
    {
        _server.Dispose();
        _pki.Dispose();
    }

    [Fact]
    public async Task GetInfoAsync_ReadsServiceInformation()
    {
        var info = await _server.CreateClient(withServiceToken: false).GetInfoAsync();

        info.Name.ShouldBe("Fake QTSP");
        info.Specs.ShouldBe("2.0.0.0");
        info.AuthTypes.ShouldContain("oauth2client");
    }

    [Fact]
    public async Task ListCredentialsAsync_MixedInlineAndInfoLookups_ReturnsAll()
    {
        var credentials = await _server.CreateClient().ListCredentialsAsync();

        credentials.Select(c => c.Id).ShouldBe(["rsa-cred", "ec-cred", "scal2-cred", "oauth-cred", "disabled-cred", "pss-only-cred"]);
        var ec = credentials.Single(c => c.Id == "ec-cred");
        ec.Certificate.Thumbprint.ShouldBe(_pki.EcCertificate.Thumbprint);
        ec.KeyAlgorithms.ShouldContain("1.2.840.10045.4.3.2");
        credentials.Single(c => c.Id == "scal2-cred").Scal.ShouldBe("2");
        credentials.Single(c => c.Id == "oauth-cred").AuthMode.ShouldBe("oauth2code");
        credentials.Single(c => c.Id == "rsa-cred").MultiSign.ShouldBe(5);
        credentials.Single(c => c.Id == "disabled-cred").IsKeyEnabled.ShouldBeFalse();
    }

    [Fact]
    public async Task ListCredentialsAsync_NoServiceToken_ThrowsClearError()
    {
        var ex = await Should.ThrowAsync<CloudSigningException>(() => _server.CreateClient(withServiceToken: false).ListCredentialsAsync());

        ex.Message.ShouldContain("service token");
    }

    [Fact]
    public async Task AuthorizeServiceWithClientCredentialsAsync_ThenListCredentials_Works()
    {
        var client = _server.CreateClient(withServiceToken: false);

        var token = await client.AuthorizeServiceWithClientCredentialsAsync();

        client.ServiceToken.ShouldBe(token);
        (await client.ListCredentialsAsync()).ShouldNotBeEmpty();
    }

    [Fact]
    public async Task AuthorizeServiceAsync_AuthorizationCode_Works()
    {
        var client = _server.CreateClient(withServiceToken: false);

        await client.AuthorizeServiceAsync(_server);

        FakePscServer.Query(_server.LastAuthorizationUri!, "scope").ShouldBe("service");
        (await client.ListCredentialsAsync()).ShouldNotBeEmpty();
    }

    [Fact]
    public async Task GetCredentialAsync_UnknownId_ThrowsProviderError()
    {
        var ex = await Should.ThrowAsync<CloudSigningException>(() => _server.CreateClient().GetCredentialAsync("missing"));

        ex.Error.ShouldBe("invalid_request");
    }

    [Fact]
    public void Constructor_HttpBaseUri_Throws() =>
        Should.Throw<ArgumentException>(() => new CscClient(new CscClientOptions { BaseUri = new Uri("http://qtsp.example/csc/v2/") }));

    [Fact]
    public void BuildCredentialAuthorizationUri_NoClientId_Throws()
    {
        var client = new CscClient(new CscClientOptions { BaseUri = FakeCscServer.BaseUri, AccessToken = "t" });

        Should.Throw<InvalidOperationException>(() => client.BuildCredentialAuthorizationUri(OAuthPkce.Create(), "c", [new byte[32]], "2.16.840.1.101.3.4.2.1"));
    }

    [Fact]
    public void Authorization_ToString_HidesSad() =>
        new CscCredentialAuthorization("secret-sad", null, null, 1, false).ToString().ShouldNotContain("secret-sad");
}

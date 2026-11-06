using Shouldly;
using SimpleSign.Signers.Cloud.Psc;
using SimpleSign.Signers.Cloud.Tests.Fakes;
using Xunit;

namespace SimpleSign.Signers.Cloud.Tests.Psc;

[Trait("Category", "Unit")]
public sealed class PscClientTests : IDisposable
{
    private readonly TestPki _pki = new();

    public void Dispose() => _pki.Dispose();

    [Fact]
    public void Constructor_HttpBaseUri_Throws() =>
        Should.Throw<ArgumentException>(() => new PscClient(new PscClientOptions
        {
            BaseUri = new Uri("http://psc.example/v0/"),
            ClientId = "id",
        }));

    [Fact]
    public void Constructor_BlankClientId_Throws() =>
        Should.Throw<ArgumentException>(() => new PscClient(new PscClientOptions
        {
            BaseUri = new Uri("https://psc.example/v0/"),
            ClientId = " ",
        }));

    [Fact]
    public async Task PasswordAuthorizeAsync_ValidOtp_ReturnsSessionToken()
    {
        var server = new FakePscServer(_pki);
        var client = server.CreateClient();

        var token = await client.PasswordAuthorizeAsync(FakePscServer.Cpf, FakePscServer.Otp, PscScope.SignatureSession, TimeSpan.FromMinutes(5));
        using var signer = await PscSigner.CreateAsync(client, token);

        token.Scope.ShouldBe("signature_session");
        token.ExpiresAt.ShouldNotBeNull();
        (await SigningAssert.SignPdfAsync(signer, signer.Certificate, signer.Chain, _pki.Ca))
            .Indication.ShouldBe(SimpleSign.Core.Validation.SignatureIndication.Valid);
    }

    [Fact]
    public async Task PasswordAuthorizeAsync_WrongOtp_ThrowsProviderError()
    {
        var client = new FakePscServer(_pki).CreateClient();

        var ex = await Should.ThrowAsync<CloudSigningException>(() => client.PasswordAuthorizeAsync(FakePscServer.Cpf, "000000"));

        ex.StatusCode.ShouldBe(System.Net.HttpStatusCode.Unauthorized);
        ex.Error.ShouldBe("invalid_grant");
        ex.Message.ShouldNotContain("000000");
    }

    [Fact]
    public async Task AuthorizeAsync_UserDenies_Throws()
    {
        var server = new FakePscServer(_pki) { DenyAuthorization = true };

        var ex = await Should.ThrowAsync<CloudSigningException>(() => server.CreateClient().AuthorizeAsync(server));

        ex.Error.ShouldBe("access_denied");
    }

    [Fact]
    public async Task AuthorizeAsync_TamperedState_IsRejected()
    {
        var server = new FakePscServer(_pki) { TamperState = true };

        (await Should.ThrowAsync<CloudSigningException>(() => server.CreateClient().AuthorizeAsync(server))).Message.ShouldContain("state");
    }

    [Fact]
    public async Task ExchangeCodeAsync_WrongVerifier_IsRejectedByProvider()
    {
        var server = new FakePscServer(_pki);
        var client = server.CreateClient();
        var pkce = OAuthPkce.Create();
        var redirect = await server.AuthorizeAsync(client.BuildAuthorizationUri(pkce, PscScope.SingleSignature), client.Options.RedirectUri, CancellationToken.None);
        var otherPkceSameState = OAuthPkce.Create();

        // Same state but a different verifier: the provider's PKCE check must fail.
        var forged = new Uri(redirect.AbsoluteUri.Replace(pkce.State, otherPkceSameState.State, StringComparison.Ordinal));
        var ex = await Should.ThrowAsync<CloudSigningException>(() => client.ExchangeCodeAsync(forged, otherPkceSameState));

        ex.Error.ShouldBe("invalid_grant");
    }

    [Fact]
    public async Task DiscoverUserAsync_KnownCpf_HasCertificate()
    {
        var client = new FakePscServer(_pki).CreateClient();

        var found = await client.DiscoverUserAsync("123.456.789-09");
        var missing = await client.DiscoverUserAsync("98765432100");

        found.HasCertificate.ShouldBeTrue();
        found.SlotAliases.ShouldBe(["slot-1"]);
        missing.HasCertificate.ShouldBeFalse();
    }

    [Fact]
    public void BuildAuthorizationUri_SingleSignature_OmitsLifetime()
    {
        var client = new FakePscServer(_pki).CreateClient();

        var uri = client.BuildAuthorizationUri(OAuthPkce.Create(), PscScope.SingleSignature);

        FakePscServer.Query(uri, "scope").ShouldBe("single_signature");
        FakePscServer.Query(uri, "lifetime").ShouldBeNull();
        FakePscServer.Query(uri, "login_hint").ShouldBeNull();
    }

    [Fact]
    public void Encode_Hex_IsLowercase() =>
        PscClient.Encode([0xAB, 0x01], PscBinaryEncoding.Hex).ShouldBe("ab01");

    [Fact]
    public void Decode_InvalidBase64_ThrowsCloudSigningException() =>
        Should.Throw<CloudSigningException>(() => PscClient.Decode("not base64!", PscBinaryEncoding.Base64));
}

using Shouldly;
using SimpleSign.Signers.Cloud.Psc;
using SimpleSign.TestBench.Credentials;
using SimpleSign.TestBench.Sandbox;
using SimpleSign.TestBench.Signing;

namespace SimpleSign.TestBench.Tests;

/// <summary>Each cloud credential kind signs end to end against the simulated providers.</summary>
[Collection(TestBenchCollection.Name)]
[Trait("Category", "Unit")]
public sealed class CredentialFactoryTests(TestBenchFixture fixture)
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task OpenPscAsync_SandboxFlow_SignsAndValidates(bool password)
    {
        var request = new PscCredentialRequest(null, null, null, null, SandboxPsc.Otp, PscScope.SignatureSession, "maria-rsa2048");
        var handle = fixture.Credentials.Add(password
            ? await fixture.Factory.OpenPscPasswordAsync(request, EnvironmentMode.Sandbox, default)
            : await fixture.Factory.OpenPscBrowserAsync(request, EnvironmentMode.Sandbox, default));

        handle.Facts.Paddings.ShouldBe([RsaPadding.Pkcs1]);
        var result = await fixture.Runner.RunAsync(fixture.Options() with { CredentialId = handle.Id, Level = BaselineLevel.BT }, default);

        result.Error.ShouldBeNull();
        result.Validation.Last(v => !v.IsDocumentTimestamp).Indication.ShouldBe("Valid");
        result.Code.CSharp.ShouldContain("WithExternalSigner(psc.Certificate, psc, psc.Chain)");
    }

    [Theory]
    [InlineData("rsa-scal1", CscAuthorizerKind.Explicit, null, RsaPadding.Pkcs1)]
    [InlineData("rsa-scal2", CscAuthorizerKind.Explicit, SandboxCsc.Otp, RsaPadding.Pkcs1)]
    [InlineData("rsa-pss-only", CscAuthorizerKind.Explicit, null, RsaPadding.Pss)]
    [InlineData("ec-p256", CscAuthorizerKind.Explicit, null, RsaPadding.Pkcs1)]
    [InlineData("rsa-oauth", CscAuthorizerKind.OAuth, null, RsaPadding.Pkcs1)]
    public async Task OpenCscAsync_SandboxCredential_SignsAndValidates(string credentialId, CscAuthorizerKind authorizer, string? otp, RsaPadding padding)
    {
        var handle = fixture.Credentials.Add(await fixture.Factory.OpenCscAsync(
            new CscCredentialRequest(null, CscServiceAuth.ClientCredentials, null, null, null, credentialId, authorizer, SandboxCsc.Pin, otp), EnvironmentMode.Sandbox, default));

        var result = await fixture.Runner.RunAsync(fixture.Options() with { CredentialId = handle.Id, Padding = padding }, default);

        result.Error.ShouldBeNull();
        result.Validation.Last(v => !v.IsDocumentTimestamp).Indication.ShouldBe("Valid");
    }

    [Fact]
    public async Task OpenCscAsync_WrongPin_Fails()
    {
        var handle = fixture.Credentials.Add(await fixture.Factory.OpenCscAsync(
            new CscCredentialRequest(null, CscServiceAuth.Token, null, null, null, "rsa-scal1", CscAuthorizerKind.Explicit, "0000", null), EnvironmentMode.Sandbox, default));

        var result = await fixture.Runner.RunAsync(fixture.Options() with { CredentialId = handle.Id }, default);

        result.Success.ShouldBeFalse();
        result.Error.ShouldNotBeNull();
        result.Error.ShouldContain("PIN", Case.Insensitive);
    }

    [Fact]
    public async Task RunAsync_DeferredWithCloudSigner_UsesExternalSigner()
    {
        var handle = fixture.Credentials.Add(await fixture.Factory.OpenCscAsync(
            new CscCredentialRequest(null, CscServiceAuth.Token, null, null, null, "rsa-scal1", CscAuthorizerKind.Explicit, SandboxCsc.Pin, null), EnvironmentMode.Sandbox, default));

        var result = await fixture.Runner.RunAsync(fixture.Options() with { CredentialId = handle.Id, Mode = RunMode.Deferred, Level = BaselineLevel.BLT }, default);

        result.Error.ShouldBeNull();
        result.Deferred.ShouldNotBeNull();
        result.Validation.Last(v => !v.IsDocumentTimestamp).Indication.ShouldBe("Valid");
    }

    [Fact]
    public void OpenSandbox_UnknownSigner_Throws() =>
        Should.Throw<KeyNotFoundException>(() => fixture.Factory.OpenSandbox(new SandboxCredentialRequest("nope")));
}

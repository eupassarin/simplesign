using Shouldly;
using SimpleSign.TestBench.Credentials;
using SimpleSign.TestBench.Signing;

namespace SimpleSign.TestBench.Tests;

/// <summary>Each cloud credential kind signs end to end against the simulated providers.</summary>
[Collection(TestBenchCollection.Name)]
[Trait("Category", "Unit")]
public sealed class CredentialFactoryTests(TestBenchFixture fixture)
{
    [SkippableTheory]
    [InlineData("rsa-scal1", CscAuthorizerKind.Explicit, false, RsaPadding.Pkcs1)]
    [InlineData("rsa-scal2", CscAuthorizerKind.Explicit, true, RsaPadding.Pkcs1)]
    [InlineData("rsa-pss-only", CscAuthorizerKind.Explicit, false, RsaPadding.Pss)]
    [InlineData("ec-p256", CscAuthorizerKind.Explicit, false, RsaPadding.Pkcs1)]
    [InlineData("rsa-oauth", CscAuthorizerKind.OAuth, false, RsaPadding.Pkcs1)]
    public async Task OpenCscAsync_SandboxCredential_SignsAndValidates(string credentialId, CscAuthorizerKind authorizer, bool otp, RsaPadding padding)
    {
        fixture.RequireSandbox();
        var csc = fixture.Sandbox.Connection.Info.Csc;
        var handle = fixture.Credentials.Add(await fixture.Factory.OpenCscAsync(
            new CscCredentialRequest(null, CscServiceAuth.ClientCredentials, null, null, null, credentialId, authorizer, csc.Pin, otp ? csc.Otp : null), default));

        var result = await fixture.Runner.RunAsync(fixture.Options() with { CredentialId = handle.Id, Padding = padding }, default);

        result.Error.ShouldBeNull();
        result.Validation.Last(v => !v.IsDocumentTimestamp).Indication.ShouldBe("Valid");
    }

    [SkippableFact]
    public async Task OpenCscAsync_WrongPin_Fails()
    {
        fixture.RequireSandbox();
        var handle = fixture.Credentials.Add(await fixture.Factory.OpenCscAsync(
            new CscCredentialRequest(null, CscServiceAuth.Token, null, null, null, "rsa-scal1", CscAuthorizerKind.Explicit, "0000", null), default));

        var result = await fixture.Runner.RunAsync(fixture.Options() with { CredentialId = handle.Id }, default);

        result.Success.ShouldBeFalse();
        result.Error.ShouldNotBeNull();
        result.Error.ShouldContain("PIN", Case.Insensitive);
    }

    [SkippableFact]
    public async Task RunAsync_DeferredWithCloudSigner_UsesExternalSigner()
    {
        fixture.RequireSandbox();
        var handle = fixture.Credentials.Add(await fixture.Factory.OpenCscAsync(
            new CscCredentialRequest(null, CscServiceAuth.Token, null, null, null, "rsa-scal1", CscAuthorizerKind.Explicit, fixture.Sandbox.Connection.Info.Csc.Pin, null), default));

        var result = await fixture.Runner.RunAsync(fixture.Options() with { CredentialId = handle.Id, Mode = RunMode.Deferred, Level = BaselineLevel.BLT }, default);

        result.Error.ShouldBeNull();
        result.Deferred.ShouldNotBeNull();
        result.Validation.Last(v => !v.IsDocumentTimestamp).Indication.ShouldBe("Valid");
    }

    [SkippableFact]
    public void OpenSandbox_UnknownSigner_Throws()
    {
        fixture.RequireSandbox();
        Should.Throw<KeyNotFoundException>(() => fixture.Factory.OpenSandbox(new SandboxCredentialRequest("nope")));
    }
}

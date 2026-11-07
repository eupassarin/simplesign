using Shouldly;
using SimpleSign.Core.Signing;
using SimpleSign.PAdES;
using SimpleSign.TestBench.Sandbox;
using SimpleSign.TestBench.Signing;

namespace SimpleSign.TestBench.Tests;

/// <summary>
/// The Strict signing policy end to end against a running SimpleSign Sandbox: CRLs over HTTP, HTTPS
/// and LDAP, OCSP, revoked and expired CAs, and failures of the services. Each case must sign, or be
/// refused with the right <see cref="SigningErrorReason"/>.
/// </summary>
[Collection(TestBenchCollection.Name)]
[Trait("Category", "Unit")]
public sealed class SandboxScenarioTests(TestBenchFixture fixture) : IDisposable
{
    // The Sandbox is shared by the collection: every test puts its revocations and failures back.
    public void Dispose()
    {
        if (fixture.SandboxProblem is null)
        {
            fixture.Sandbox.ResetAsync().GetAwaiter().GetResult();
        }
    }

    private Task<SigningResult> SignStrictAsync(string signer) =>
        fixture.Runner.RunAsync(fixture.Options(signer: signer) with { Level = BaselineLevel.BB, SigningPolicy = SigningPolicyChoice.Strict }, default);

    /// <summary>Signs the contract sample with the library itself, with a Sandbox signer and its chain.</summary>
    private Task<byte[]> LibrarySignAsync(string signer)
    {
        fixture.RequireSandbox();
        var connection = fixture.Sandbox.Connection;
        var credential = connection.Signer(signer);
        return PadesSigner.Document(fixture.Documents.Get(SimpleSign.TestBench.Documents.DocumentStore.SampleKey("contract")).Content)
            .WithCertificate(credential.Certificate, credential.Chain)
            .WithHttpClientProvider(fixture.Sandbox)
            .WithLevel(AdesBaselineProfile.Basic())
            .SignAsync();
    }

    private static void ShouldBeRefused(SigningResult result, string reason)
    {
        result.Success.ShouldBeFalse($"signed, but {reason} was expected");
        result.ErrorType.ShouldBe($"SigningException ({reason})", result.Error);
    }

    [SkippableTheory]
    [InlineData("revoked")]
    [InlineData("revoked-ocsp")]
    [InlineData("revoked-crl-https")]
    [InlineData("revoked-crl-ldap")]
    [InlineData("under-revoked-ca")]
    public async Task Strict_RevokedInTheSandbox_IsRefused(string signer) =>
        ShouldBeRefused(await SignStrictAsync(signer), "CertificateRevoked");

    [SkippableTheory]
    [InlineData("rsa-2048")]
    [InlineData("good-ocsp")]
    [InlineData("good-crl-https")]
    [InlineData("good-crl-ldap")]
    public async Task Strict_GoodChain_Signs(string signer)
    {
        var result = await SignStrictAsync(signer);

        result.Error.ShouldBeNull();
    }

    [SkippableTheory]
    [InlineData(CrlFault.Expired)]
    [InlineData(CrlFault.WrongKey)]
    [InlineData(CrlFault.Down)]
    public async Task Strict_UnusableCrlAndNoOcsp_StatusIsUnknown(CrlFault fault)
    {
        fixture.RequireSandbox();
        await fixture.Sandbox.SetFaultsAsync(new SandboxFaults(Crl: fault));

        ShouldBeRefused(await SignStrictAsync("good-crl-https"), "RevocationStatusUnknown");
    }

    [SkippableFact]
    public async Task Strict_RevokedAfterTheLastCrlWasCached_IsRefused()
    {
        // The CRL is fetched while the certificate is good; then it is revoked and the CRL server
        // keeps serving that old copy (Stale). The OCSP responder knows: Strict must ask it.
        fixture.RequireSandbox();
        (await SignStrictAsync("rsa-4096")).Error.ShouldBeNull();
        await fixture.Sandbox.RevokeAsync("rsa-4096");
        await fixture.Sandbox.SetFaultsAsync(new SandboxFaults(Crl: CrlFault.Stale));

        ShouldBeRefused(await SignStrictAsync("rsa-4096"), "CertificateRevoked");
    }

    [SkippableTheory]
    [InlineData(OcspFault.Expired)]
    [InlineData(OcspFault.Unauthorized)]
    [InlineData(OcspFault.Unknown)]
    public async Task Strict_UnusableOcspAndNoCrl_StatusIsUnknown(OcspFault fault)
    {
        fixture.RequireSandbox();
        await fixture.Sandbox.SetFaultsAsync(new SandboxFaults(Ocsp: fault));

        ShouldBeRefused(await SignStrictAsync("good-ocsp"), "RevocationStatusUnknown");
    }

    [SkippableFact]
    public async Task Default_ExpiredCertificate_IsRefused()
    {
        // The TestBench's own option check already refuses it; the library must too.
        fixture.RequireSandbox();
        var ex = await Should.ThrowAsync<SigningException>(() => LibrarySignAsync("expired"));

        ex.Reason.ShouldBe(SigningErrorReason.CertificateExpired);
    }

    [SkippableFact]
    public async Task Default_NotYetValidCertificate_IsRefused()
    {
        // The TestBench's own option check already refuses it; the library must too.
        fixture.RequireSandbox();
        var ex = await Should.ThrowAsync<SigningException>(() => LibrarySignAsync("not-yet-valid"));

        ex.Reason.ShouldBe(SigningErrorReason.CertificateNotCurrentlyValid);
    }

    [SkippableFact]
    public async Task Default_ExpiredIssuingCa_IsRefused()
    {
        var result = await fixture.Runner.RunAsync(fixture.Options(signer: "under-expired-ca") with { Level = BaselineLevel.BB }, default);

        ShouldBeRefused(result, "ChainCertificateNotValid");
    }
}

using System.Text.Json;
using Shouldly;
using SimpleSign.TestBench.Cades;
using SimpleSign.TestBench.Runs;
using SimpleSign.TestBench.Sandbox;
using SimpleSign.TestBench.Signing;

namespace SimpleSign.TestBench.Tests;

/// <summary>The failures the sandbox can be told to have, and what signing and validation do with each.</summary>
[Collection(TestBenchCollection.Name)]
[Trait("Category", "Unit")]
public sealed class SandboxFaultTests(TestBenchFixture fixture) : IDisposable
{
    // The Sandbox is shared by the collection: every test puts its revocations and failures back.
    public void Dispose()
    {
        if (fixture.SandboxProblem is null)
        {
            fixture.Sandbox.ResetAsync().GetAwaiter().GetResult();
        }
    }

    private Task FaultsAsync(SandboxFaults faults)
    {
        fixture.RequireSandbox();
        return fixture.Sandbox.SetFaultsAsync(faults);
    }

    private Task<RunView> SignAsync(BaselineLevel level, bool returnLowerLevel = false, string signer = "rsa-2048") =>
        fixture.Runs().RunAsync(new RunRequest(RunFormats.Pades,
            JsonSerializer.SerializeToElement(fixture.Options(signer: signer) with { Level = level, ReturnLowerLevel = returnLowerLevel }, WorkbenchJson.Options)), default);

    private Task<RunView> ValidateAsync(string fileId) =>
        fixture.Runs().RunAsync(new RunRequest("", JsonSerializer.SerializeToElement(new ValidateOptions(fileId), WorkbenchJson.Options), Kind: RunKinds.Validate), default);

    [SkippableFact]
    public async Task TsaDown_TimestampedSignature_Fails()
    {
        await FaultsAsync(new SandboxFaults(Tsa: TsaFault.Down));

        var run = await SignAsync(BaselineLevel.BT);

        run.Success.ShouldBeFalse();
        run.Logs.ShouldContain(l => l.Source == "network" && l.Message.Contains("/tsa/", StringComparison.Ordinal) && l.Message.EndsWith("503", StringComparison.Ordinal));
    }

    [SkippableFact]
    public async Task TsaDown_WithReturnLowerLevel_SignsAtBasicAndWarns()
    {
        await FaultsAsync(new SandboxFaults(Tsa: TsaFault.Down));

        var run = await SignAsync(BaselineLevel.BT, returnLowerLevel: true);

        run.Success.ShouldBeTrue(run.Error);
        run.RequestedLevel.ShouldBe("B-T");
        run.AchievedLevel.ShouldBe("B-B");
        run.Warnings.ShouldNotBeEmpty();
    }

    [SkippableFact]
    public async Task TsaInvalidToken_TimestampedSignature_Fails()
    {
        await FaultsAsync(new SandboxFaults(Tsa: TsaFault.InvalidToken));

        var run = await SignAsync(BaselineLevel.BT);

        run.Success.ShouldBeFalse();
    }

    [SkippableFact]
    public async Task TsaSlow_TimestampedSignature_TakesAtLeastTheDelay()
    {
        await FaultsAsync(new SandboxFaults(Tsa: TsaFault.Slow, TsaDelayMs: 400));

        var run = await SignAsync(BaselineLevel.BT);

        run.Success.ShouldBeTrue(run.Error);
        run.SignMs.ShouldBeGreaterThanOrEqualTo(380);
    }

    [SkippableFact]
    public async Task RevocationDown_LongTermSignature_Fails()
    {
        // CRLs and OCSP both down: no revocation data for B-LT.
        await FaultsAsync(new SandboxFaults(Crl: CrlFault.Down, Ocsp: OcspFault.Down));

        var run = await SignAsync(BaselineLevel.BLT);

        run.Success.ShouldBeFalse();
        run.Logs.ShouldContain(l => l.Source == "network" && l.Message.Contains("/crl/", StringComparison.Ordinal) && l.Message.EndsWith("503", StringComparison.Ordinal));
    }

    [SkippableFact]
    public async Task RevokeSigner_SignatureMadeBefore_IsNoLongerValid()
    {
        // A signer no other test uses: a CRL that lists it, cached somewhere, cannot break them.
        var signed = await SignAsync(BaselineLevel.BB, signer: "no-nonrepudiation");
        (await ValidateAsync(signed.OutputId!)).Overall.ShouldBe("Valid");

        await fixture.Sandbox.RevokeAsync("no-nonrepudiation");
        var revoked = await ValidateAsync(signed.OutputId!);

        revoked.Overall.ShouldBe("Invalid");

        await fixture.Sandbox.ResetAsync();
        (await ValidateAsync(signed.OutputId!)).Overall.ShouldBe("Valid");
    }

    [SkippableFact]
    public async Task NoFaults_CadesLongTerm_StillSigns()
    {
        var run = await fixture.Runs().RunAsync(new RunRequest(RunFormats.Cades, JsonSerializer.SerializeToElement(new CadesOptions
        {
            DataId = fixture.CadesSamples.Single(s => s.Id == "text").FileId,
            CredentialId = fixture.Sandboxed(),
            Level = BaselineLevel.BLT,
        }, WorkbenchJson.Options)), default);

        run.Success.ShouldBeTrue(run.Error);
    }
}

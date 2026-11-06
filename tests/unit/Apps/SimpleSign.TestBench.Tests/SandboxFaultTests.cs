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
    // The sandbox is shared by the collection: every test leaves it as it found it.
    public void Dispose()
    {
        fixture.Sandbox.Network.Faults = new SandboxFaults();
        fixture.Sandbox.Pki.RestoreRevocations();
    }

    private Task<RunView> SignAsync(BaselineLevel level, bool returnLowerLevel = false, string signer = "rsa-2048") =>
        fixture.Runs().RunAsync(new RunRequest(RunFormats.Pades,
            JsonSerializer.SerializeToElement(fixture.Options(signer: signer) with { Level = level, ReturnLowerLevel = returnLowerLevel }, WorkbenchJson.Options)), default);

    private Task<RunView> ValidateAsync(string fileId) =>
        fixture.Runs().RunAsync(new RunRequest("", JsonSerializer.SerializeToElement(new ValidateOptions(fileId), WorkbenchJson.Options), Kind: RunKinds.Validate), default);

    [Fact]
    public async Task TsaDown_TimestampedSignature_Fails()
    {
        fixture.Sandbox.Network.Faults = new SandboxFaults(Tsa: TsaFault.Down);

        var run = await SignAsync(BaselineLevel.BT);

        run.Success.ShouldBeFalse();
        run.Logs.ShouldContain(l => l.Source == "network" && l.Message.Contains("fault: Down", StringComparison.Ordinal) && l.Message.EndsWith("503", StringComparison.Ordinal));
    }

    [Fact]
    public async Task TsaDown_WithReturnLowerLevel_SignsAtBasicAndWarns()
    {
        fixture.Sandbox.Network.Faults = new SandboxFaults(Tsa: TsaFault.Down);

        var run = await SignAsync(BaselineLevel.BT, returnLowerLevel: true);

        run.Success.ShouldBeTrue(run.Error);
        run.RequestedLevel.ShouldBe("B-T");
        run.AchievedLevel.ShouldBe("B-B");
        run.Warnings.ShouldNotBeEmpty();
    }

    [Fact]
    public async Task TsaInvalidToken_TimestampedSignature_Fails()
    {
        fixture.Sandbox.Network.Faults = new SandboxFaults(Tsa: TsaFault.InvalidToken);

        var run = await SignAsync(BaselineLevel.BT);

        run.Success.ShouldBeFalse();
    }

    [Fact]
    public async Task TsaSlow_TimestampedSignature_TakesAtLeastTheDelay()
    {
        fixture.Sandbox.Network.Faults = new SandboxFaults(Tsa: TsaFault.Slow, TsaDelayMs: 400);

        var run = await SignAsync(BaselineLevel.BT);

        run.Success.ShouldBeTrue(run.Error);
        run.SignMs.ShouldBeGreaterThanOrEqualTo(380);
    }

    [Fact]
    public async Task CrlDown_LongTermSignature_Fails()
    {
        fixture.Sandbox.Network.Faults = new SandboxFaults(Crl: CrlFault.Down);

        var run = await SignAsync(BaselineLevel.BLT);

        run.Success.ShouldBeFalse();
        run.Logs.ShouldContain(l => l.Source == "network" && l.Message.Contains("fault: Down", StringComparison.Ordinal));
    }

    [Fact]
    public async Task RevokeSigner_SignatureMadeBefore_IsNoLongerValid()
    {
        var signed = await SignAsync(BaselineLevel.BB, signer: "rsa-3072");
        (await ValidateAsync(signed.OutputId!)).Overall.ShouldBe("Valid");

        fixture.Sandbox.Pki.Revoke("rsa-3072");
        var revoked = await ValidateAsync(signed.OutputId!);

        revoked.Overall.ShouldBe("Invalid");
        fixture.Sandbox.Pki.RevokedNow.ShouldBe(["rsa-3072"]);

        fixture.Sandbox.Pki.RestoreRevocations();
        (await ValidateAsync(signed.OutputId!)).Overall.ShouldBe("Valid");
    }

    [Fact]
    public async Task NoFaults_CadesLongTerm_StillSigns()
    {
        fixture.Sandbox.Network.Faults.Any.ShouldBeFalse();

        var run = await fixture.Runs().RunAsync(new RunRequest(RunFormats.Cades, JsonSerializer.SerializeToElement(new CadesOptions
        {
            DataId = fixture.CadesSamples.Single(s => s.Id == "text").FileId,
            CredentialId = fixture.Sandboxed(),
            Level = BaselineLevel.BLT,
        }, WorkbenchJson.Options)), default);

        run.Success.ShouldBeTrue(run.Error);
    }
}

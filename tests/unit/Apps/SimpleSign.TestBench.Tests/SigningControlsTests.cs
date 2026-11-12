using Shouldly;
using SimpleSign.TestBench.Policies;
using SimpleSign.TestBench.Runs;
using SimpleSign.TestBench.Signing;

namespace SimpleSign.TestBench.Tests;

/// <summary>The trust anchors, expected TSA and audit trail of the checks made before signing, through both engines.</summary>
[Collection(TestBenchCollection.Name)]
[Trait("Category", "Unit")]
public sealed class SigningControlsTests(TestBenchFixture fixture) : IDisposable
{
    private static readonly string IofeSigning = PolicyPresets.Id("signing", "iofe");

    public void Dispose()
    {
        if (fixture.SandboxProblem is null)
        {
            fixture.Sandbox.ResetAsync().GetAwaiter().GetResult();
        }
    }

    [SkippableTheory]
    [InlineData(RunEngines.Library)]
    [InlineData(RunEngines.Cli)]
    public async Task IofePresetWithSandboxRootAndAudit_SignsAndRecordsIt(string engine)
    {
        var options = Timestamped() with
        {
            SigningPolicyId = IofeSigning,
            SigningControls = new SigningControlsOptions { Trust = [SigningTrustChoice.SandboxRoot], AuditLog = true },
        };

        var (result, log) = await RunAsync(options, engine);

        result.Error.ShouldBeNull(string.Join(" | ", result.Issues.Select(i => i.ToString())));
        log.ShouldContain(e => e.Message.Contains("Audit:", StringComparison.Ordinal) && e.Message.Contains("signed", StringComparison.Ordinal));
    }

    [SkippableTheory]
    [InlineData(RunEngines.Library)]
    [InlineData(RunEngines.Cli)]
    public async Task IofePresetWithoutAnchors_IsRefusedAsUntrusted(string engine)
    {
        var (result, _) = await RunAsync(fixture.Options() with { SigningPolicyId = IofeSigning }, engine);

        result.ErrorType.ShouldBe("SigningException (UntrustedRoot)", result.Error);
    }

    [SkippableTheory]
    [InlineData(RunEngines.Library)]
    [InlineData(RunEngines.Cli)]
    public async Task ExpectedTsaOtherThanTheOneUsed_IsRefused(string engine)
    {
        var options = Timestamped() with { SigningControls = new SigningControlsOptions { ExpectedTsa = "tsa-revoked" } };

        var (result, _) = await RunAsync(options, engine);

        result.ErrorType.ShouldBe("SigningException (TimestampUntrusted)", result.Error);
    }

    [SkippableTheory]
    [InlineData(RunEngines.Library)]
    [InlineData(RunEngines.Cli)]
    public async Task IofePresetWithRevokedTsa_IsRefused(string engine)
    {
        var options = Timestamped(TsaProvider.SandboxRevoked) with
        {
            SigningPolicyId = IofeSigning,
            SigningControls = new SigningControlsOptions { Trust = [SigningTrustChoice.SandboxRoot] },
        };

        var (result, _) = await RunAsync(options, engine);

        result.ErrorType.ShouldBe("SigningException (TimestampCertificateRevoked)", result.Error);
    }

    [SkippableTheory]
    [InlineData(RunEngines.Library)]
    [InlineData(RunEngines.Cli)]
    public async Task IofeListWithTheTsaItListsAsUnspecified_Signs(string engine)
    {
        var options = Timestamped(TsaProvider.SandboxIofe) with
        {
            SigningPolicyId = IofeSigning,
            SigningControls = new SigningControlsOptions { Trust = [SigningTrustChoice.SandboxIofeList] },
        };

        var (result, _) = await RunAsync(options, engine);

        result.Error.ShouldBeNull(string.Join(" | ", result.Issues.Select(i => i.ToString())));
    }

    [SkippableTheory]
    [InlineData(RunEngines.Library)]
    [InlineData(RunEngines.Cli)]
    public async Task IofeTsaWithTheSandboxRootOnly_IsRefusedAsUntrusted(string engine)
    {
        var options = Timestamped(TsaProvider.SandboxIofe) with
        {
            SigningPolicyId = IofeSigning,
            SigningControls = new SigningControlsOptions { Trust = [SigningTrustChoice.SandboxRoot] },
        };

        var (result, _) = await RunAsync(options, engine);

        result.ErrorType.ShouldBe("SigningException (TimestampUntrusted)", result.Error);
    }

    private SigningOptions Timestamped(TsaProvider tsa = TsaProvider.Sandbox) =>
        fixture.Options() with { Level = BaselineLevel.BT, Timestamp = new TimestampChoice { Provider = tsa } };

    private async Task<(SigningResult Result, IReadOnlyList<RunLogEntry> Log)> RunAsync(SigningOptions options, string engine)
    {
        fixture.RequireSandbox();
        var log = new RunLogger(_ => { });
        using (RunLog.Begin(log))
        {
            var result = await fixture.Runner.RunAsync(options, engine, default);
            return (result, log.Entries);
        }
    }
}

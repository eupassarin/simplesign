using Shouldly;
using SimpleSign.TestBench.Sandbox;
using SimpleSign.TestBench.Signing;

namespace SimpleSign.TestBench.Tests;

/// <summary>The Code tab prints the calls the runner made, without secrets.</summary>
[Collection(TestBenchCollection.Name)]
[Trait("Category", "Unit")]
public sealed class CodeGeneratorTests(TestBenchFixture fixture)
{
    [Fact]
    public async Task Generate_BaselineBltWithPss_PrintsProfileAndAlgorithm()
    {
        var result = await fixture.Runner.RunAsync(fixture.Options() with { Level = BaselineLevel.BLT, Padding = RsaPadding.Pss, Hash = HashChoice.Sha384 }, default);

        result.Error.ShouldBeNull(string.Join("; ", result.Issues.Select(i => i.Message)));
        result.Code.CSharp.ShouldContain("AdesBaselineProfile.LongTerm(tsa, new LongTermValidationOptions(sandboxHttp))");
        result.Code.CSharp.ShouldContain(".WithSignatureAlgorithm(Oids.RsaPss)");
        result.Code.CSharp.ShouldContain(".WithHashAlgorithm(HashAlgorithmName.SHA384)");
        result.Code.Cli.ShouldContain("--ltv");
        result.Code.Cli.ShouldContain("--hash SHA384");
    }

    [Fact]
    public async Task Generate_AuthenticatedTsa_NeverPrintsTheSecret()
    {
        var options = fixture.Options() with
        {
            Level = BaselineLevel.BT,
            Timestamp = new TimestampChoice { Provider = TsaProvider.SandboxAuthenticated, Auth = TsaAuth.Basic, User = SandboxPki.TsaUser, Password = SandboxPki.TsaPassword },
        };

        var result = await fixture.Runner.RunAsync(options, default);

        result.Success.ShouldBeTrue(result.Error);
        result.Code.CSharp.ShouldNotContain(SandboxPki.TsaPassword);
        result.Code.CSharp.ShouldContain("Authorization = new AuthenticationHeaderValue(\"Basic\"");
    }

    [Fact]
    public async Task Generate_ExistingField_NamesTheField()
    {
        var options = fixture.Options("empty-field") with
        {
            FieldMode = FieldMode.Existing,
            ExistingFieldName = "Assinatura",
        };

        var result = await fixture.Runner.RunAsync(options, default);

        result.Success.ShouldBeTrue(result.Error);
        result.Code.CSharp.ShouldContain("ExistingFieldName = \"Assinatura\"", Case.Sensitive, result.Code.CSharp);
        result.Code.Cli.ShouldContain("--existing-field \"Assinatura\"");
    }

    [Fact]
    public async Task Generate_Deferred_PrintsThreePhases()
    {
        var result = await fixture.Runner.RunAsync(fixture.Options() with { Mode = RunMode.Deferred }, default);

        result.Code.CSharp.ShouldContain("PrepareAsync()");
        result.Code.CSharp.ShouldContain("SignData(prepared.HashToSign");
        result.Code.CSharp.ShouldContain("CompleteAsync(signature)");
    }
}

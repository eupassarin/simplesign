using Shouldly;
using SimpleSign.TestBench.Signing;

namespace SimpleSign.TestBench.Tests;

/// <summary>The Code tab prints the calls the runner made, without secrets.</summary>
[Collection(TestBenchCollection.Name)]
[Trait("Category", "Unit")]
public sealed class CodeGeneratorTests(TestBenchFixture fixture)
{
    [SkippableFact]
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

    [SkippableFact]
    public async Task Generate_AuthenticatedTsa_NeverPrintsTheSecret()
    {
        var options = fixture.Options() with
        {
            Level = BaselineLevel.BT,
            Timestamp = new TimestampChoice { Provider = TsaProvider.SandboxAuthenticated, Auth = TsaAuth.Basic, User = fixture.Sandbox.Connection.Info.Tsa.User, Password = fixture.Sandbox.Connection.Info.Tsa.Password },
        };

        var result = await fixture.Runner.RunAsync(options, default);

        result.Success.ShouldBeTrue(result.Error);
        result.Code.CSharp.ShouldNotContain(fixture.Sandbox.Connection.Info.Tsa.Password);
        result.Code.CSharp.ShouldContain("Authorization = new AuthenticationHeaderValue(\"Basic\"");
    }

    [SkippableFact]
    public async Task Generate_ExistingField_NamesTheField()
    {
        var options = fixture.Options("empty-field") with
        {
            FieldMode = FieldMode.Existing,
            ExistingFieldName = "Assinatura",
            Appearance = new AppearanceChoice { Visible = true, SignerDisplayName = "Maria" },
        };

        var result = await fixture.Runner.RunAsync(options, default);

        result.Success.ShouldBeTrue(result.Error);
        result.Code.CSharp.ShouldContain("ExistingFieldName = \"Assinatura\"", Case.Sensitive, result.Code.CSharp);
        result.Code.Cli.ShouldContain("--existing-field Assinatura");
    }

    [SkippableFact]
    public async Task Generate_VisibleStamp_PrintsItInBothSnippets()
    {
        var options = fixture.Options() with
        {
            Appearance = new AppearanceChoice
            {
                Visible = true,
                Page = 1,
                X = 100,
                Y = 120,
                Width = 200,
                Height = 60,
                TextAlignment = "Center",
                VerticalAlignment = "Middle",
                ExtraLines = ["CRM 12345"],
                TextColor = "#ff0000",
                Culture = "pt-BR",
                SignerDisplayName = "Dra. Ana",
            },
        };

        var result = await fixture.Runner.RunAsync(options, default);

        result.Success.ShouldBeTrue(result.Error);
        result.Code.CSharp.ShouldContain("VerticalAlignment = SignatureVerticalAlignment.Middle", Case.Sensitive, result.Code.CSharp);
        result.Code.CSharp.ShouldContain("MaxTextLength = 200", Case.Sensitive, result.Code.CSharp);
        string cli = string.Join(' ', result.Code.CliCommands.SelectMany(c => c.Args));
        cli.ShouldContain("--visible --page 1 --pos-x 100 --pos-y 120 --stamp-width 200 --stamp-height 60", Case.Sensitive, cli);
        cli.ShouldContain("--text-align center --vertical-align middle", Case.Sensitive, cli);
        cli.ShouldContain("--max-text-length 200", Case.Sensitive, cli);
        cli.ShouldContain("--extra-line", Case.Sensitive, cli);
        cli.ShouldContain("--date-culture pt-BR", Case.Sensitive, cli);
        cli.ShouldContain("--text-color 1,0,0", Case.Sensitive, cli);
    }

    [SkippableFact]
    public async Task Generate_Deferred_PrintsThreePhases()
    {
        var result = await fixture.Runner.RunAsync(fixture.Options() with { Mode = RunMode.Deferred }, default);

        result.Code.CSharp.ShouldContain("PrepareAsync()");
        result.Code.CSharp.ShouldContain("SignData(prepared.DataToSign");
        result.Code.CSharp.ShouldContain("CompleteWithDetailsAsync(signature)");
        result.Code.Cli.ShouldContain("sign ");
        result.Code.Cli.ShouldContain("--prepare");
        result.Code.Cli.ShouldContain("deferred complete");
    }

    [SkippableFact]
    public async Task Generate_DeferredWithOptionsOfOneCallSigning_PrintsThemInPhaseOne()
    {
        var options = fixture.Options() with
        {
            Mode = RunMode.Deferred,
            Reason = "Two phases",
            SigningTime = new DateTimeOffset(2026, 1, 2, 3, 4, 5, TimeSpan.Zero),
            OperationId = "tb-deferred",
            Kind = SignatureKind.CustomPolicy,
            CustomPolicy = new CustomPolicyChoice { Oid = "1.2.3.4.5", HashHex = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData("policy"u8)) },
        };

        var result = await fixture.Runner.RunAsync(options, default);

        result.Error.ShouldBeNull();
        result.Deferred.ShouldNotBeNull();
        string prepare = result.Code.CSharp[..result.Code.CSharp.IndexOf("PrepareAsync()", StringComparison.Ordinal)];
        prepare.ShouldContain("DeferredSigner.Document(pdf)");
        prepare.ShouldContain(".WithSignaturePolicy(");
        prepare.ShouldContain(".WithSigningTime(");
        prepare.ShouldContain(".WithOperationId(\"tb-deferred\")");
        result.Code.Cli.ShouldContain("--policy-oid 1.2.3.4.5");
        result.Code.Cli.ShouldContain("--operation-id tb-deferred");
    }
}

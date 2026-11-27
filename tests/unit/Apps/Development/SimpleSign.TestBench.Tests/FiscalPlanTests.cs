using Shouldly;
using SimpleSign.TestBench.Runs;
using SimpleSign.TestBench.Signing;
using SimpleSign.TestBench.TrustFrameworks;
using SimpleSign.TestBench.Validation;
using SimpleSign.TestBench.Xml;

namespace SimpleSign.TestBench.Tests;

/// <summary>
/// The Fiscal XML type of the XML page: the layout's XML-DSig signature (SimpleSign.Brazil.Fiscal) through the library
/// and the CLI, its code, and its validation. The Sandbox's trust is added to the icp-brasil profile.
/// </summary>
[Collection(TestBenchCollection.Name)]
[Trait("Category", "Unit")]
public sealed class FiscalPlanTests(TestBenchFixture fixture)
{
    private XmlOptions Fiscal(string sample = "nfe", string layout = "nfe") => new()
    {
        DataId = fixture.XmlSamples.Single(s => s.Id == sample).FileId,
        CredentialId = fixture.Sandboxed(),
        Kind = XadesKind.Fiscal,
        FiscalLayout = layout,
        SigningPolicyId = "preset:signing:fiscal-sefaz",
        SigningControls = new SigningControlsOptions { Profile = TrustProfileChoice.IcpBrasil, TrustProfiles = [TrustProfileChoice.Sandbox] },
        Validation = new ValidationSettings
        {
            Trust = [],
            Profile = TrustProfileChoice.IcpBrasil,
            TrustProfiles = [TrustProfileChoice.Sandbox],
            PolicyId = "preset:validation:icp-brasil",
        },
    };

    private static string Errors(XmlSignResult r) =>
        string.Join("; ", r.Issues.Select(i => i.Message).Concat(r.Validation?.Signatures.SelectMany(s => s.Errors) ?? []).Concat(r.Validation?.Errors ?? []).Append(r.Error ?? ""));

    [SkippableTheory]
    [InlineData(RunEngines.Library, "nfe", "nfe")]
    [InlineData(RunEngines.Cli, "nfe", "nfe")]
    [InlineData(RunEngines.Library, "esocial", "esocial")]
    [InlineData(RunEngines.Cli, "cte", "cte")]
    public async Task RunAsync_Layout_SignsAndValidates(string engine, string sample, string layout)
    {
        var result = await fixture.Xml.RunAsync(Fiscal(sample, layout), engine, default);

        result.Success.ShouldBeTrue(Errors(result));
        result.Validation!.Overall.ShouldBe("Valid", Errors(result));
        result.RequestedLevel.ShouldStartWith("XML-DSig");
    }

    [SkippableTheory]
    [InlineData(RunEngines.Library)]
    [InlineData(RunEngines.Cli)]
    public async Task RunAsync_TwoPhases_SignsAndValidates(string engine)
    {
        var result = await fixture.Xml.RunAsync(Fiscal() with { TwoPhases = true }, engine, default);

        result.Success.ShouldBeTrue(Errors(result));
        result.Validation!.Overall.ShouldBe("Valid", Errors(result));
    }

    [SkippableTheory]
    [InlineData(RunEngines.Library)]
    [InlineData(RunEngines.Cli)]
    public async Task RunAsync_NFeUnderTheIcpBrasilPolicy_IsRefusedForSha1(string engine)
    {
        var result = await fixture.Xml.RunAsync(Fiscal() with { SigningPolicyId = "preset:signing:icp-brasil", AttemptRefused = true }, engine, default);

        result.Success.ShouldBeFalse();
        result.ErrorType.ShouldNotBeNull().ShouldContain("AlgorithmNotPermitted");
    }

    [SkippableFact]
    public async Task DescribeAsync_NFe_GivesTheFiscalCodeAndCommand()
    {
        var description = await fixture.Xml.DescribeAsync(Fiscal(), default);

        var code = description.Code.ShouldNotBeNull();
        code.CSharp.ShouldContain("FiscalXmlSigner.Document(xml, FiscalDocumentProfile.NFe)");
        code.Cli.ShouldContain("brasil fiscal sign document.xml");
        code.Cli.ShouldContain("--layout nfe");
        code.Cli.ShouldContain("--signing-policy");
    }

    [Fact]
    public void Evaluate_Fiscal_HidesWhatXadesHas()
    {
        var report = XmlCompatibility.Evaluate(new XmlOptions { Kind = XadesKind.Fiscal, FiscalLayout = "nfe", Level = BaselineLevel.BLTA }, null, null);

        report.Options["fiscalLayout"].ShouldBe(OptionState.Shown);
        report.Options["level"].ShouldBe(OptionState.Hidden);
        report.Options["timestamp"].ShouldBe(OptionState.Hidden);
        report.Effective.Level.ShouldBe(BaselineLevel.BB);
        report.EffectiveLevel.ShouldBe("XML-DSig (NF-e)");
    }

    [Fact]
    public void Evaluate_UnknownLayout_IsAnError() =>
        XmlCompatibility.Evaluate(new XmlOptions { Kind = XadesKind.Fiscal, FiscalLayout = "nfx" }, null, null)
            .Issues.ShouldContain(i => i.Message.Contains("fiscal layout", StringComparison.OrdinalIgnoreCase));
}

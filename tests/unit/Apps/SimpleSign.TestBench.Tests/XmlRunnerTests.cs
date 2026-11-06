using Shouldly;
using SimpleSign.TestBench.Signing;
using SimpleSign.TestBench.Xml;

namespace SimpleSign.TestBench.Tests;

/// <summary>XAdES and fiscal XML-DSig through the TestBench, against the real library.</summary>
[Collection(TestBenchCollection.Name)]
[Trait("Category", "Unit")]
public sealed class XmlRunnerTests(TestBenchFixture fixture)
{
    private XmlSample Sample(string id) => fixture.XmlSamples.Single(s => s.Id == id);

    private XmlOptions Xades(string signer = "rsa-2048") => new() { DataId = Sample("order").FileId, CredentialId = fixture.Sandboxed(signer) };

    private XmlOptions Fiscal(string sample, string signer = "company") => new()
    {
        Mode = XmlMode.Fiscal,
        Profile = Sample(sample).Profile!,
        DataId = Sample(sample).FileId,
        CredentialId = fixture.Sandboxed(signer),
    };

    private static string Errors(XmlSignResult r) =>
        string.Join("; ", r.Issues.Select(i => i.Message).Concat(r.Validation?.Signatures.SelectMany(s => s.Errors) ?? []).Concat(r.Validation?.Errors ?? []).Append(r.Error ?? ""));

    [Theory]
    [InlineData(XadesFormChoice.Enveloped, BaselineLevel.BB)]
    [InlineData(XadesFormChoice.Detached, BaselineLevel.BT)]
    [InlineData(XadesFormChoice.Enveloping, BaselineLevel.BLT)]
    [InlineData(XadesFormChoice.Enveloped, BaselineLevel.BLTA)]
    public async Task RunAsync_Xades_IsValid(XadesFormChoice form, BaselineLevel level)
    {
        var result = await fixture.Xml.RunAsync(Xades() with { Form = form, Level = level }, default);

        result.Success.ShouldBeTrue(Errors(result));
        result.Validation!.Overall.ShouldBe("Valid", Errors(result));
        result.Validation.Mode.ShouldBe(XmlMode.Xades);
        result.Validation.SignatureXml.ShouldNotBeNull();
    }

    [Theory]
    [InlineData(XadesIcpPolicy.AdRb, "B-B")]
    [InlineData(XadesIcpPolicy.AdRt, "B-T")]
    [InlineData(XadesIcpPolicy.AdRv, "B-T")]
    [InlineData(XadesIcpPolicy.AdRc, "B-LT")]
    [InlineData(XadesIcpPolicy.AdRa, "B-LTA")]
    public async Task RunAsync_IcpBrasilXades_SignsWithV1AndPolicy(XadesIcpPolicy policy, string achieved)
    {
        var result = await fixture.Xml.RunAsync(Xades() with { Kind = XadesKind.IcpBrasil, IcpPolicy = policy }, default);

        result.Success.ShouldBeTrue(Errors(result));
        result.AchievedLevel.ShouldBe(achieved);
        result.Validation!.Overall.ShouldBe("Valid", Errors(result));
        result.Validation.SignatureXml!.ShouldNotContain("SigningCertificateV2");
        result.Validation.SignatureXml!.ShouldContain("SigPolicyId");
        result.Code.CSharp.ShouldContain($"IcpBrasilPolicy.{policy}");
    }

    [Fact]
    public async Task RunAsync_XadesDetails_AreInTheSignatureAndTheCode()
    {
        var options = Xades() with { SignerRoles = ["Gerente"], MimeType = "text/xml", Commitment = "ProofOfOrigin", Hash = HashChoice.Sha512, Padding = RsaPadding.Pss, Form = XadesFormChoice.Detached, DataUri = "pedido.xml" };

        var result = await fixture.Xml.RunAsync(options, default);

        result.Success.ShouldBeTrue(Errors(result));
        result.Validation!.Overall.ShouldBe("Valid", Errors(result));
        result.Validation.SignatureXml!.ShouldContain("ClaimedRole");
        result.Code.CSharp.ShouldContain(".WithSignerRoles([\"Gerente\"])");
        result.Code.Cli.ShouldContain("--form detached");
        result.Code.Cli.ShouldContain("--data-uri pedido.xml");
    }

    [Theory]
    [InlineData("nfe")]
    [InlineData("evento")]
    [InlineData("inutilizacao")]
    [InlineData("cte")]
    [InlineData("mdfe")]
    [InlineData("nfse")]
    [InlineData("esocial")]
    [InlineData("reinf")]
    public async Task RunAsync_FiscalProfile_SignsAndReadsTheCnpj(string sample)
    {
        var result = await fixture.Xml.RunAsync(Fiscal(sample), default);

        result.Success.ShouldBeTrue(Errors(result));
        result.Validation!.Mode.ShouldBe(XmlMode.Fiscal);
        result.Validation.Overall.ShouldBe("Valid", Errors(result));
        result.Validation.Signatures.ShouldHaveSingleItem().Cnpj.ShouldBe("11222333000181");
        result.Code.Cli.ShouldContain($"--profile {Sample(sample).Profile}");
    }

    [Fact]
    public async Task RunAsync_FiscalBatch_SignAllSignsEveryNfe()
    {
        var result = await fixture.Xml.RunAsync(Fiscal("nfe-batch") with { SignAll = true }, default);

        result.Success.ShouldBeTrue(Errors(result));
        result.Validation!.Signatures.Count.ShouldBe(2);
        result.Code.CSharp.ShouldContain("FiscalXmlSigner.SignAll");
    }

    [Theory]
    [InlineData("v-xades")]
    [InlineData("v-detached")]
    [InlineData("v-nfe")]
    [InlineData("v-nfe-changed")]
    [InlineData("v-tampered")]
    [InlineData("v-untrusted")]
    public void Validate_Sample_MatchesItsExpectedResult(string id)
    {
        var sample = Sample(id);

        var view = fixture.Xml.Validate(sample.FileId, sample.DataId, new SimpleSign.TestBench.Validation.ValidationSettings());

        view.Mode.ShouldBe(sample.Mode);
        view.Overall.ShouldBe(sample.ExpectedIndication, string.Join("; ", view.Signatures.SelectMany(s => s.Errors).Concat(view.Errors)));
        if (sample.ExpectedCheck is { } check and not "—")
        {
            view.Signatures[0].Checks.Single(c => c.Id == check).Status.ShouldBe("fail");
        }
    }
}

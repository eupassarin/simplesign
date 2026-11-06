using Shouldly;
using SimpleSign.TestBench.Cades;
using SimpleSign.TestBench.Signing;

namespace SimpleSign.TestBench.Tests;

/// <summary>CAdES signing and validation through the TestBench, against the real library.</summary>
[Collection(TestBenchCollection.Name)]
public sealed class CadesRunnerTests(TestBenchFixture fixture)
{
    private string Sample(string id) => fixture.CadesSamples.Single(s => s.Id == id).FileId;

    private CadesOptions Options(string signer = "rsa-2048") => new()
    {
        DataId = Sample("text"),
        CredentialId = fixture.Sandboxed(signer),
    };

    [Theory]
    [InlineData(CadesContentChoice.Detached, BaselineLevel.BB)]
    [InlineData(CadesContentChoice.Enveloped, BaselineLevel.BB)]
    [InlineData(CadesContentChoice.Detached, BaselineLevel.BT)]
    [InlineData(CadesContentChoice.Enveloped, BaselineLevel.BLT)]
    [InlineData(CadesContentChoice.Detached, BaselineLevel.BLTA)]
    public async Task RunAsync_Sign_IsValid(CadesContentChoice content, BaselineLevel level)
    {
        var result = await fixture.Cades.RunAsync(Options() with { ContentType = content, Level = level }, default);

        result.Error.ShouldBeNull(string.Join("; ", result.Issues.Select(i => i.Message)));
        result.Success.ShouldBeTrue();
        result.FileName.ShouldEndWith(content == CadesContentChoice.Enveloped ? ".p7m" : ".p7s");
        result.Validation!.Structure.IsDetached.ShouldBe(content == CadesContentChoice.Detached);
        result.Validation.Overall.ShouldBe("Valid", string.Join("; ", result.Validation.Signers.SelectMany(s => s.Errors).Concat(result.Validation.Errors)));
        result.HasSignatureTimestamp.ShouldBe(level != BaselineLevel.BB);
    }

    [Theory]
    [InlineData("detached")]
    [InlineData("enveloped")]
    public async Task RunAsync_CoSign_AddsASecondSigner(string existing)
    {
        var sample = fixture.CadesSamples.Single(s => s.Id == existing);
        var options = Options("rsa-3072") with { Operation = CadesOperation.CoSign, ExistingSignatureId = sample.FileId, DataId = sample.DataId };

        var result = await fixture.Cades.RunAsync(options, default);

        result.Error.ShouldBeNull(string.Join("; ", result.Issues.Select(i => i.Message)));
        result.Validation!.Signers.Count.ShouldBe(2);
        result.Validation.Overall.ShouldBe("Valid", string.Join("; ", result.Validation.Signers.SelectMany(s => s.Errors)));
    }

    [Fact]
    public async Task RunAsync_CounterSign_NestsUnderTheSigner()
    {
        var options = Options("rsa-4096") with { Operation = CadesOperation.CounterSign, ExistingSignatureId = Sample("enveloped"), DataId = null };

        var result = await fixture.Cades.RunAsync(options, default);

        result.Error.ShouldBeNull(string.Join("; ", result.Issues.Select(i => i.Message)));
        var signer = result.Validation!.Signers.ShouldHaveSingleItem();
        signer.CounterSignatures.ShouldHaveSingleItem().Indication.ShouldBe("Valid");
        result.FileName.ShouldBe("countersigned.p7m");
    }

    [Theory]
    [InlineData(CadesIcpPolicy.AdRb)]
    [InlineData(CadesIcpPolicy.AdRt)]
    [InlineData(CadesIcpPolicy.AdRv)]
    [InlineData(CadesIcpPolicy.AdRc)]
    [InlineData(CadesIcpPolicy.AdRa)]
    public async Task RunAsync_IcpBrasil_SignsAndValidates(CadesIcpPolicy policy)
    {
        var result = await fixture.Cades.RunAsync(Options() with { Kind = CadesKind.IcpBrasil, IcpPolicy = policy }, default);

        result.Error.ShouldBeNull(string.Join("; ", result.Issues.Select(i => i.Message)));
        result.Validation!.Overall.ShouldBe("Valid", string.Join("; ", result.Validation.Signers.SelectMany(s => s.Errors)));
        result.Validation.Structure.Signers[0].PolicyOid.ShouldNotBeNull();
        result.Code.CSharp.ShouldContain($"IcpBrasilPolicy.{policy}");
    }

    [Theory]
    [InlineData(CadesExtendedChoice.CompleteReferences, "esc-time-stamp (CAdES-C timestamp)")]
    [InlineData(CadesExtendedChoice.ExtendedLong, "certificate-values")]
    [InlineData(CadesExtendedChoice.Archive, "archive-time-stamp-v2")]
    public async Task RunAsync_ExtendedForm_AddsItsAttributes(CadesExtendedChoice form, string attribute)
    {
        var result = await fixture.Cades.RunAsync(Options() with { Level = BaselineLevel.BT, ExtendedForm = form }, default);

        result.Error.ShouldBeNull(string.Join("; ", result.Issues.Select(i => i.Message)));
        result.Validation!.Structure.Signers[0].UnsignedAttributes.ShouldContain(a => a.Name == attribute);
        result.Validation.Overall.ShouldBe("Valid", string.Join("; ", result.Validation.Signers.SelectMany(s => s.Errors)));
    }

    [Fact]
    public async Task RunAsync_PssAndSha512_AreInTheCode()
    {
        var result = await fixture.Cades.RunAsync(Options() with { Hash = HashChoice.Sha512, Padding = RsaPadding.Pss, Commitment = "ProofOfOrigin" }, default);

        result.Error.ShouldBeNull(string.Join("; ", result.Issues.Select(i => i.Message)));
        result.Validation!.Structure.Signers[0].SignatureAlgorithm.ShouldBe("RSASSA-PSS");
        result.Code.CSharp.ShouldContain(".WithHashAlgorithm(HashAlgorithmName.SHA512)");
        result.Code.CSharp.ShouldContain("Oids.RsaPss");
        result.Code.Cli.ShouldContain("--hash SHA512");
        result.Code.Cli.ShouldContain("--commitment \"ProofOfOrigin\"");
    }

    [Theory]
    [InlineData("v-valid")]
    [InlineData("v-tree")]
    [InlineData("v-changed-data")]
    [InlineData("v-tampered")]
    [InlineData("v-untrusted")]
    public void Validate_Sample_MatchesItsExpectedResult(string id)
    {
        var sample = fixture.CadesSamples.Single(s => s.Id == id);

        var view = fixture.Cades.Validate(sample.FileId, sample.DataId, new SimpleSign.TestBench.Validation.ValidationSettings());

        view.Overall.ShouldBe(sample.ExpectedIndication, string.Join("; ", view.Signers.SelectMany(s => s.Errors).Concat(view.Errors)));
        if (sample.ExpectedCheck is { } check and not "—")
        {
            view.Signers[0].Checks.Single(c => c.Id == check).Status.ShouldBe("fail");
        }

        if (id == "v-tree")
        {
            view.Signers.Count.ShouldBe(2);
            view.Signers[0].CounterSignatures.ShouldHaveSingleItem();
        }
    }
}

using Shouldly;
using SimpleSign.TestBench.Cades;
using SimpleSign.TestBench.Signing;

namespace SimpleSign.TestBench.Tests;

/// <summary>CAdES signing and validation through the TestBench, against the real library.</summary>
[Collection(TestBenchCollection.Name)]
[Trait("Category", "Unit")]
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

    [Theory]
    [InlineData(BaselineLevel.BLT)]
    [InlineData(BaselineLevel.BLTA)]
    public async Task RunAsync_ArchiveFormOnLongTermLevels_IsValid(BaselineLevel level)
    {
        var result = await fixture.Cades.RunAsync(Options() with { Level = level, ExtendedForm = CadesExtendedChoice.Archive }, default);

        result.Error.ShouldBeNull(string.Join("; ", result.Issues.Select(i => i.Message)));
        result.AchievedLevel.ShouldBe(level == BaselineLevel.BLT ? "B-LT" : "B-LTA");
        result.Validation!.Structure.Signers[0].UnsignedAttributes.ShouldContain(a => a.Name == "archive-time-stamp-v2");
        result.Validation.Overall.ShouldBe("Valid", string.Join("; ", result.Validation.Signers.SelectMany(s => s.Errors)));
    }

    [Fact]
    public async Task RunAsync_SignerAndContentAttributes_AreInTheSignatureAndTheCode()
    {
        var options = Options() with
        {
            SignerCountry = "BR",
            SignerLocality = " São Paulo ",
            SignerPostalAddress = ["Av. Paulista, 1000", " "],
            SignerRoles = ["Diretor"],
            MimeType = "text/plain",
            ContentDescription = "Texto de exemplo",
        };

        var result = await fixture.Cades.RunAsync(options, default);

        result.Error.ShouldBeNull(string.Join("; ", result.Issues.Select(i => i.Message)));
        result.Validation!.Overall.ShouldBe("Valid", string.Join("; ", result.Validation.Signers.SelectMany(s => s.Errors)));
        var signed = result.Validation.Structure.Signers[0].SignedAttributes.Select(a => a.Name).ToList();
        signed.ShouldContain("signer-location");
        signed.ShouldContain("signer-attributes-v2");
        signed.ShouldContain("mime-type");
        signed.ShouldContain("content-hints");
        result.Code.CSharp.ShouldContain(".WithSignerLocation(new CadesSignerLocation { CountryName = \"BR\", LocalityName = \" São Paulo \", PostalAddress = [\"Av. Paulista, 1000\"] })");
        result.Code.CSharp.ShouldContain(".WithSignerRoles([\"Diretor\"])");
        result.Code.CSharp.ShouldContain(".WithMimeType(\"text/plain\")");
        result.Code.CSharp.ShouldContain(".WithContentHints(new CadesContentHints { Description = \"Texto de exemplo\" })");
        result.Code.Cli.ShouldContain("--signer-country \"BR\"");
        result.Code.Cli.ShouldContain("--signer-postal-address \"Av. Paulista, 1000\"");
        result.Code.Cli.ShouldContain("--signer-role \"Diretor\"");
        result.Code.Cli.ShouldContain("--mime-type \"text/plain\"");
        result.Code.Cli.ShouldContain("--content-description \"Texto de exemplo\"");
        result.Code.CliNotes.ShouldNotContain(n => n.Contains("no cades flag", StringComparison.Ordinal));
    }

    [Fact]
    public async Task RunAsync_CounterSignWithMimeType_LeavesTheAttributeOut()
    {
        var options = Options("rsa-4096") with
        {
            Operation = CadesOperation.CounterSign,
            ExistingSignatureId = Sample("enveloped"),
            DataId = null,
            MimeType = "text/plain",
            ContentDescription = "x",
        };

        var result = await fixture.Cades.RunAsync(options, default);

        // The rules switch both options off for a countersignature, so the run still succeeds.
        result.Error.ShouldBeNull(string.Join("; ", result.Issues.Select(i => i.Message)));
        result.Code.CSharp.ShouldNotContain("WithMimeType");
        result.Code.CSharp.ShouldNotContain("WithContentHints");
    }

    [Fact]
    public async Task RunAsync_CrlFirstAtLongTerm_IsValidAndInTheCode()
    {
        var options = Options() with { Level = BaselineLevel.BLT, RevocationPreference = SimpleSign.Core.Signing.RevocationPreference.CrlFirst };

        var result = await fixture.Cades.RunAsync(options, default);

        result.Error.ShouldBeNull(string.Join("; ", result.Issues.Select(i => i.Message)));
        result.AchievedLevel.ShouldBe("B-LT");
        result.Validation!.Overall.ShouldBe("Valid", string.Join("; ", result.Validation.Signers.SelectMany(s => s.Errors)));
        result.Code.CSharp.ShouldContain("{ RevocationPreference = RevocationPreference.CrlFirst }");
        result.Code.Cli.ShouldContain("--revocation-preference crl");
    }

    [Theory]
    [InlineData(BaselineLevel.BB)]
    [InlineData(BaselineLevel.BLTA)]
    public async Task RunAsync_CustomPolicyWithDocument_EmbedsThePolicyStore(BaselineLevel level)
    {
        var policy = fixture.Documents.Add("policy.der", "a signature policy document"u8.ToArray());
        var options = Options() with { Kind = CadesKind.CustomPolicy, Level = level, PolicyDocumentId = policy.Id, PolicySpecification = "1.2.3.4.5.1" };

        var result = await fixture.Cades.RunAsync(options, default);

        result.Error.ShouldBeNull(string.Join("; ", result.Issues.Select(i => i.Message)));
        result.Validation!.Overall.ShouldBe("Valid", string.Join("; ", result.Validation.Signers.SelectMany(s => s.Errors)));
        result.Validation.Structure.Signers[0].UnsignedAttributes.ShouldContain(a => a.Name == "signature-policy-store");
        result.Code.CSharp.ShouldContain("byte[] policyDocument = File.ReadAllBytes(\"policy.der\");");
        result.Code.Cli.ShouldContain("--policy-document \"policy.der\"");
        result.Code.Cli.ShouldContain("--policy-specification \"1.2.3.4.5.1\"");
        result.Code.CSharp.ShouldContain(".WithSignaturePolicy(new SignaturePolicyReference(\"1.2.3.4.5\", Oids.Sha256, SHA256.HashData(policyDocument)))");
        result.Code.CSharp.ShouldContain(".WithSignaturePolicyStore(SignaturePolicyStore.FromDocument(\"1.2.3.4.5.1\", policyDocument))");
    }

    [Fact]
    public async Task RunAsync_CustomPolicyWithoutDocument_HasNoPolicyStore()
    {
        var result = await fixture.Cades.RunAsync(Options() with { Kind = CadesKind.CustomPolicy }, default);

        result.Error.ShouldBeNull(string.Join("; ", result.Issues.Select(i => i.Message)));
        result.Validation!.Structure.Signers[0].UnsignedAttributes.ShouldNotContain(a => a.Name == "signature-policy-store");
        result.Code.CSharp.ShouldNotContain("WithSignaturePolicyStore");
    }

    [Theory]
    [InlineData(BaselineLevel.BB)]
    [InlineData(BaselineLevel.BLTA)]
    public async Task RunAsync_ContentTimestamp_IsSignedValidatedAndInTheCode(BaselineLevel level)
    {
        var result = await fixture.Cades.RunAsync(Options() with { Level = level, ContentTimestamp = true }, default);

        result.Error.ShouldBeNull(string.Join("; ", result.Issues.Select(i => i.Message)));
        result.Validation!.Overall.ShouldBe("Valid", string.Join("; ", result.Validation.Signers.SelectMany(s => s.Errors)));
        result.Validation.Structure.Signers[0].SignedAttributes.ShouldContain(a => a.Name == "content-time-stamp");
        result.Validation.Signers[0].Checks.ShouldContain(c => c.Id == "contentTimestamp" && c.Status == "pass");
        // At B-B the content timestamp is the only timestamp.
        result.HasSignatureTimestamp.ShouldBe(level != BaselineLevel.BB);
        result.Code.CSharp.ShouldContain(".WithContentTimestamp(tsa)");
    }

    [Fact]
    public async Task RunAsync_CertifiedAttributeAndSignedAssertion_AreInTheSignerAttributes()
    {
        // Any single DER SEQUENCE stands for the attribute certificate: the library embeds it as given.
        var attributeCertificate = fixture.Documents.Add("role.ac", [0x30, 0x03, 0x04, 0x01, 0xAA]);
        var assertion = fixture.Documents.Add("assertion.xml", "<saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"/>"u8.ToArray());
        var options = Options() with { AttributeCertificateId = attributeCertificate.Id, SignedAssertionId = assertion.Id };

        var result = await fixture.Cades.RunAsync(options, default);

        result.Error.ShouldBeNull(string.Join("; ", result.Issues.Select(i => i.Message)));
        result.Validation!.Overall.ShouldBe("Valid", string.Join("; ", result.Validation.Signers.SelectMany(s => s.Errors)));
        result.Validation.Structure.Signers[0].SignedAttributes.ShouldContain(a => a.Name == "signer-attributes-v2");
        result.Code.CSharp.ShouldContain(".WithAttributeCertificates([attributeCertificate])");
        result.Code.CSharp.ShouldContain(".WithSignedAssertions([CadesSignedAssertion.Saml(samlAssertion)])");
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
    public async Task Validate_Sample_MatchesItsExpectedResult(string id)
    {
        var sample = fixture.CadesSamples.Single(s => s.Id == id);

        var view = await fixture.Cades.ValidateAsync(sample.FileId, sample.DataId, new SimpleSign.TestBench.Validation.ValidationSettings());

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

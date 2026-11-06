using Shouldly;
using SimpleSign.TestBench.Credentials;
using SimpleSign.TestBench.Documents;
using SimpleSign.TestBench.Sandbox;
using SimpleSign.TestBench.Signing;

namespace SimpleSign.TestBench.Tests;

/// <summary>One test per library constraint the rules mirror.</summary>
public sealed class CompatibilityTests
{
    private static readonly DocumentFacts Plain = Doc();

    private static readonly CredentialFacts Rsa = Credential("RSA", [RsaPadding.Pkcs1, RsaPadding.Pss]);

    [Fact]
    public void Evaluate_NoDocumentOrSigner_CannotSign()
    {
        var report = Compatibility.Evaluate(new SigningOptions(), null, null);

        report.CanSign.ShouldBeFalse();
        report.Issues.ShouldContain(i => i.Step == Compatibility.StepDocument && i.Severity == IssueSeverity.Error);
        report.Issues.ShouldContain(i => i.Step == Compatibility.StepSigner && i.Severity == IssueSeverity.Error);
    }

    [Fact]
    public void Evaluate_DefaultsWithDocumentAndSigner_CanSignBB()
    {
        var report = Compatibility.Evaluate(new SigningOptions(), Plain, Rsa);

        report.CanSign.ShouldBeTrue();
        report.EffectiveLevel.ShouldBe("B-B");
        report.Options["timestamp"].Visible.ShouldBeFalse();
    }

    [Fact]
    public void Evaluate_DocMdpP1_BlocksSigning()
    {
        var report = Compatibility.Evaluate(new SigningOptions(), Doc(docMdp: 1, signatures: 1), Rsa);

        report.CanSign.ShouldBeFalse();
        report.Issues.ShouldContain(i => i.Message.Contains("P=1", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData(2)]
    [InlineData(3)]
    public void Evaluate_DocMdpP2OrP3_AllowsSigning(int level) =>
        Compatibility.Evaluate(new SigningOptions(), Doc(docMdp: level, signatures: 1), Rsa).CanSign.ShouldBeTrue();

    [Fact]
    public void Evaluate_AlreadySigned_DisablesCertification()
    {
        var report = Compatibility.Evaluate(new SigningOptions { Certification = CertificationChoice.FormFilling }, Doc(signatures: 1), Rsa);

        report.Options["certification.FormFilling"].Disabled.ShouldNotBeNull();
        report.CanSign.ShouldBeFalse();
    }

    [Fact]
    public void Evaluate_IcpPolicy_ForcesPbadSubFilterAndHidesLevels()
    {
        var report = Compatibility.Evaluate(new SigningOptions { Kind = SignatureKind.IcpBrasil, IcpPolicy = IcpPolicyKind.AdRt }, Plain, Rsa);

        report.Effective.SubFilter.ShouldBe(SubFilterChoice.PbadPades);
        report.Effective.Level.ShouldBe(BaselineLevel.BT);
        report.Options["level.BB"].Visible.ShouldBeFalse();
        report.Options["subFilter.EtsiCadesDetached"].Disabled.ShouldNotBeNull();
        report.Options["timestamp"].Visible.ShouldBeTrue();
    }

    [Theory]
    [InlineData(IcpPolicyKind.AdRb, false, BaselineLevel.BB)]
    [InlineData(IcpPolicyKind.AdRb, true, BaselineLevel.BT)]
    [InlineData(IcpPolicyKind.AdRt, false, BaselineLevel.BT)]
    [InlineData(IcpPolicyKind.AdRc, false, BaselineLevel.BLTA)]
    [InlineData(IcpPolicyKind.AdRa, false, BaselineLevel.BLTA)]
    public void Evaluate_IcpPolicy_MapsToBaselineLevel(IcpPolicyKind policy, bool timestamp, BaselineLevel expected)
    {
        var report = Compatibility.Evaluate(new SigningOptions { Kind = SignatureKind.IcpBrasil, IcpPolicy = policy, IcpAdRbTimestamp = timestamp }, Plain, Rsa);

        report.Effective.Level.ShouldBe(expected);
        report.Options["archiveTimestamp"].Visible.ShouldBe(expected == BaselineLevel.BLTA);
    }

    [Fact]
    public void Evaluate_PdfA1Preserved_ForcesAdbeAndBB()
    {
        var report = Compatibility.Evaluate(new SigningOptions { PreservePdfA = true, Level = BaselineLevel.BT }, Doc(pdfA1: true), Rsa);

        report.Effective.SubFilter.ShouldBe(SubFilterChoice.AdbePkcs7Detached);
        report.Options["level.BT"].Disabled.ShouldNotBeNull();
        report.Options["kind.IcpBrasil"].Disabled.ShouldNotBeNull();
    }

    [Fact]
    public void Evaluate_AdbeSubFilter_DisablesTimestampedLevels()
    {
        var report = Compatibility.Evaluate(new SigningOptions { SubFilter = SubFilterChoice.AdbePkcs7Detached, Level = BaselineLevel.BLT }, Plain, Rsa);

        report.Options["level.BLT"].Disabled.ShouldNotBeNull();
        report.CanSign.ShouldBeFalse();
    }

    [Fact]
    public void Evaluate_PscCredential_OffersPkcs1AndSha2Only()
    {
        var psc = Credential("RSA", [RsaPadding.Pkcs1], CredentialKind.Psc, [HashChoice.Sha256, HashChoice.Sha384, HashChoice.Sha512]);

        var report = Compatibility.Evaluate(new SigningOptions { Padding = RsaPadding.Pss }, Plain, psc);

        report.Options["padding.Pss"].Disabled.ShouldNotBeNull();
        report.Effective.Padding.ShouldBe(RsaPadding.Pkcs1);
        report.Options["hash.Sha3_256"].Disabled.ShouldNotBeNull();
    }

    [Fact]
    public void Evaluate_PssWithSha3_IsRefused()
    {
        var report = Compatibility.Evaluate(new SigningOptions { Padding = RsaPadding.Pss, Hash = HashChoice.Sha3_256 }, Plain, Rsa);

        report.Options["padding.Pss"].Disabled.ShouldNotBeNull();
        report.CanSign.ShouldBeFalse();
    }

    [Fact]
    public void Evaluate_PssOnlyCredential_ForcesPss()
    {
        var report = Compatibility.Evaluate(new SigningOptions(), Plain, Credential("RSA", [RsaPadding.Pss], CredentialKind.Csc));

        report.Effective.Padding.ShouldBe(RsaPadding.Pss);
    }

    [Fact]
    public void Evaluate_EcdsaCredential_HidesRsaPadding()
    {
        var report = Compatibility.Evaluate(new SigningOptions(), Plain, Credential("ECDSA", []));

        report.Options["padding"].Visible.ShouldBeFalse();
    }

    [Fact]
    public void Evaluate_ExistingField_HidesNameAndDisablesDocumentInfo()
    {
        var report = Compatibility.Evaluate(new SigningOptions { FieldMode = FieldMode.Existing, ExistingFieldName = "Assinatura" }, Doc(emptyFields: ["Assinatura"]), Rsa);

        report.Options["fieldName"].Visible.ShouldBeFalse();
        report.Options["documentInfo"].Disabled.ShouldNotBeNull();
        report.Options["health"].Disabled.ShouldNotBeNull();
        report.CanSign.ShouldBeTrue();
    }

    [Fact]
    public void Evaluate_NoEmptyFields_HidesAndRefusesExistingField()
    {
        var report = Compatibility.Evaluate(new SigningOptions { FieldMode = FieldMode.Existing }, Plain, Rsa);

        report.Options["field.Existing"].Visible.ShouldBeFalse();
        report.CanSign.ShouldBeFalse();
    }

    [Theory]
    [InlineData(RunMode.Deferred)]
    [InlineData(RunMode.Batch)]
    public void Evaluate_DeferredOrBatch_DisablesPoliciesAndBuilderOnlyOptions(RunMode mode)
    {
        var report = Compatibility.Evaluate(new SigningOptions { Mode = mode, Kind = SignatureKind.IcpBrasil }, Plain, Rsa);

        report.Options["kind.IcpBrasil"].Disabled.ShouldNotBeNull();
        report.Options["documentInfo"].Disabled.ShouldNotBeNull();
        report.Options["details.signer"].Disabled.ShouldNotBeNull();
        report.CanSign.ShouldBeFalse();
    }

    [Fact]
    public void Evaluate_AeaWithIcpPolicy_IsRefused()
    {
        var report = Compatibility.Evaluate(new SigningOptions
        {
            Kind = SignatureKind.IcpBrasil,
            UseSignerDetails = true,
            SignerDetails = SignerDetailsKind.Aea,
            Aea = new AeaChoice { SignerName = "Maria", Cpf = "11144477735" },
        }, Plain, Rsa);

        report.Options["details.Aea"].Disabled.ShouldNotBeNull();
        report.CanSign.ShouldBeFalse();
    }

    [Theory]
    [InlineData("111.444.777-35", true)]
    [InlineData("11144477735", true)]
    [InlineData("11144477736", false)]
    [InlineData("11111111111", false)]
    [InlineData("123", false)]
    public void IsCpf_Values_ChecksDigits(string cpf, bool expected) => Compatibility.IsCpf(cpf).ShouldBe(expected);

    [Fact]
    public void Evaluate_SandboxWithPublicTsa_IsRefused()
    {
        var report = Compatibility.Evaluate(new SigningOptions { Level = BaselineLevel.BT, Timestamp = new TimestampChoice { Provider = TsaProvider.DigiCert } }, Plain, Rsa);

        report.Options["tsa.DigiCert"].Disabled.ShouldNotBeNull();
        report.CanSign.ShouldBeFalse();
    }

    [Fact]
    public void Evaluate_RealWithSandboxTsa_IsRefused()
    {
        var report = Compatibility.Evaluate(new SigningOptions { Environment = EnvironmentMode.Real, Level = BaselineLevel.BT }, Plain, Rsa);

        report.Options["tsa.Sandbox"].Disabled.ShouldNotBeNull();
        report.CanSign.ShouldBeFalse();
    }

    [Fact]
    public void Evaluate_AuthenticatedSandboxTsaWithoutBasic_IsRefused()
    {
        var report = Compatibility.Evaluate(new SigningOptions { Level = BaselineLevel.BT, Timestamp = new TimestampChoice { Provider = TsaProvider.SandboxAuthenticated } }, Plain, Rsa);

        report.CanSign.ShouldBeFalse();
    }

    [Fact]
    public void Evaluate_ReturnLowerLevelOutsideSignNow_IsDisabled()
    {
        var report = Compatibility.Evaluate(new SigningOptions { Level = BaselineLevel.BT, Mode = RunMode.Batch }, Plain, Rsa);

        report.Options["returnLowerLevel"].Disabled.ShouldNotBeNull();
    }

    [Fact]
    public void Evaluate_ExpiredCertificate_IsRefused()
    {
        var report = Compatibility.Evaluate(new SigningOptions(), Plain, Rsa with { IsExpired = true });

        report.CanSign.ShouldBeFalse();
        report.Issues.ShouldContain(i => i.Severity == IssueSeverity.Error && i.Step == Compatibility.StepSigner);
    }

    [Fact]
    public void Evaluate_NoNonRepudiation_OnlyWarns()
    {
        var report = Compatibility.Evaluate(new SigningOptions(), Plain, Rsa with { HasNonRepudiation = false });

        report.CanSign.ShouldBeTrue();
        report.Issues.ShouldContain(i => i.Severity == IssueSeverity.Warning && i.Step == Compatibility.StepSigner);
    }

    private static DocumentFacts Doc(int docMdp = 0, int signatures = 0, bool pdfA1 = false, IReadOnlyList<string>? emptyFields = null) => new(
        "doc", "Doc", "doc.pdf", 1000, "1.7", pdfA1 ? "A1b" : "None", pdfA1, pdfA1, false, docMdp,
        [.. Enumerable.Range(1, signatures).Select(i => new ExistingSignature($"Sig{i}", "ETSI.CAdES.detached", "CN=X", false))],
        emptyFields ?? [], null);

    private static CredentialFacts Credential(string algorithm, IReadOnlyList<RsaPadding> paddings, CredentialKind kind = CredentialKind.SandboxA1, IReadOnlyList<HashChoice>? hashes = null) => new(
        "cred", kind, "test", "Holder", "CN=Holder", "CN=CA", "11144477735", null, algorithm, 2048, "2025-01-01", "2030-01-01",
        false, false, true, false, hashes ?? Enum.GetValues<HashChoice>(), paddings, kind is CredentialKind.SandboxA1 or CredentialKind.Pfx, [], "");
}

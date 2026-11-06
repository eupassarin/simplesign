using Shouldly;
using SimpleSign.TestBench.Cades;
using SimpleSign.TestBench.Signing;

namespace SimpleSign.TestBench.Tests;

/// <summary>The CAdES rules: each one blocks or adjusts what the library would refuse.</summary>
[Collection(TestBenchCollection.Name)]
[Trait("Category", "Unit")]
public sealed class CadesCompatibilityTests(TestBenchFixture fixture)
{
    private CadesSample Sample(string id) => fixture.CadesSamples.Single(s => s.Id == id);

    private CadesOptionsReport Evaluate(CadesOptions options) => fixture.Cades.Evaluate(options);

    private CadesOptions Options() => new() { DataId = Sample("text").FileId, CredentialId = fixture.Sandboxed() };

    [Fact]
    public void Evaluate_Defaults_CanSign() => Evaluate(Options()).CanSign.ShouldBeTrue();

    [Fact]
    public void Evaluate_NoData_IsAnError() =>
        Evaluate(Options() with { DataId = null }).Issues.ShouldContain(i => i.Severity == IssueSeverity.Error && i.Step == CadesCompatibility.StepData);

    [Fact]
    public void Evaluate_CoSignWithoutSignature_IsAnError() =>
        Evaluate(Options() with { Operation = CadesOperation.CoSign }).CanSign.ShouldBeFalse();

    [Fact]
    public void Evaluate_CoSignDetachedWithOtherData_IsRefused()
    {
        var report = Evaluate(Options() with { Operation = CadesOperation.CoSign, ExistingSignatureId = Sample("detached").FileId, DataId = Sample("json").FileId });

        report.CanSign.ShouldBeFalse();
        report.Issues.ShouldContain(i => i.Message.Contains("message digest", StringComparison.Ordinal));
    }

    [Fact]
    public void Evaluate_CoSignEnveloped_HidesDataAndKeepsContentType()
    {
        var report = Evaluate(Options() with { Operation = CadesOperation.CoSign, ExistingSignatureId = Sample("enveloped").FileId, DataId = null });

        report.CanSign.ShouldBeTrue();
        report.Options["data"].Visible.ShouldBeFalse();
        report.Effective.ContentType.ShouldBe(CadesContentChoice.Enveloped);
    }

    [Fact]
    public void Evaluate_CounterSignBadIndex_IsAnError() =>
        Evaluate(Options() with { Operation = CadesOperation.CounterSign, ExistingSignatureId = Sample("enveloped").FileId, SignerIndex = 3 }).CanSign.ShouldBeFalse();

    [Theory]
    [InlineData(BaselineLevel.BB, CadesExtendedChoice.CompleteReferences, false)]
    [InlineData(BaselineLevel.BT, CadesExtendedChoice.Archive, true)]
    [InlineData(BaselineLevel.BLT, CadesExtendedChoice.ExtendedLong, true)]
    [InlineData(BaselineLevel.BLT, CadesExtendedChoice.Archive, true)]
    [InlineData(BaselineLevel.BLTA, CadesExtendedChoice.CompleteReferences, true)]
    [InlineData(BaselineLevel.BLTA, CadesExtendedChoice.Archive, true)]
    public void Evaluate_ExtendedForm_FollowsTheLevel(BaselineLevel level, CadesExtendedChoice form, bool allowed) =>
        Evaluate(Options() with { Level = level, ExtendedForm = form }).CanSign.ShouldBe(allowed);

    [Fact]
    public void Evaluate_IcpBrasil_HidesLevelAndExtendedForm()
    {
        var report = Evaluate(Options() with { Kind = CadesKind.IcpBrasil, IcpPolicy = CadesIcpPolicy.AdRc, ExtendedForm = CadesExtendedChoice.Archive });

        report.CanSign.ShouldBeTrue();
        report.Options["level"].Visible.ShouldBeFalse();
        report.Options["extendedForm"].Visible.ShouldBeFalse();
        report.Effective.ExtendedForm.ShouldBe(CadesExtendedChoice.None);
        report.EffectiveLevel.ShouldBe("AD-RC (CAdES-X Long)");
    }

    [Fact]
    public void Evaluate_BadCustomPolicyOid_IsAnError() =>
        Evaluate(Options() with { Kind = CadesKind.CustomPolicy, PolicyOid = "not-an-oid" }).CanSign.ShouldBeFalse();

    [Fact]
    public void Evaluate_EcdsaSigner_ForcesPkcs1Padding()
    {
        var report = Evaluate(Options() with { CredentialId = fixture.Sandboxed("ecdsa-p256"), Padding = RsaPadding.Pss });

        report.Options["padding"].Visible.ShouldBeFalse();
        report.Effective.Padding.ShouldBe(RsaPadding.Pkcs1);
    }
}

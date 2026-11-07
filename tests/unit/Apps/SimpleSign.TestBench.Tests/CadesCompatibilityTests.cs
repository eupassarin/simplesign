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
    public void Evaluate_SevenPostalAddressLines_IsAnError()
    {
        var report = Evaluate(Options() with { SignerPostalAddress = ["1", "2", "3", "4", "5", "6", "7"] });

        report.CanSign.ShouldBeFalse();
        report.Issues.ShouldContain(i => i.Severity == IssueSeverity.Error && i.Step == CadesCompatibility.StepDetails);
    }

    [Fact]
    public void Evaluate_CounterSign_SwitchesOffTheAttributesThatDescribeTheContent()
    {
        var report = Evaluate(Options() with
        {
            Operation = CadesOperation.CounterSign,
            ExistingSignatureId = Sample("enveloped").FileId,
            DataId = null,
            MimeType = "text/plain",
            ContentDescription = "x",
            SignerLocality = "Recife",
        });

        report.CanSign.ShouldBeTrue();
        report.Options["mimeType"].Disabled.ShouldNotBeNull();
        report.Options["contentHints"].Disabled.ShouldNotBeNull();
        report.Options["signerLocation"].Disabled.ShouldBeNull();
        report.Effective.MimeType.ShouldBeNull();
        report.Effective.ContentDescription.ShouldBeNull();
        report.Effective.SignerLocality.ShouldBe("Recife");
    }

    [Theory]
    [InlineData(BaselineLevel.BB, false)]
    [InlineData(BaselineLevel.BT, false)]
    [InlineData(BaselineLevel.BLT, true)]
    [InlineData(BaselineLevel.BLTA, true)]
    public void Evaluate_RevocationPreference_IsShownOnlyWhenValidationDataIsCollected(BaselineLevel level, bool visible) =>
        Evaluate(Options() with { Level = level }).Options["revocationPreference"].Visible.ShouldBe(visible);

    [Fact]
    public void Evaluate_PolicyDocumentWithoutSpecification_IsAnError()
    {
        var report = Evaluate(Options() with { Kind = CadesKind.CustomPolicy, PolicyDocumentId = Sample("text").FileId, PolicySpecification = " " });

        report.CanSign.ShouldBeFalse();
        report.Issues.ShouldContain(i => i.Severity == IssueSeverity.Error && i.Step == CadesCompatibility.StepType);
    }

    [Fact]
    public void Evaluate_ContentTimestampAtBasicLevel_ShowsTheTsa()
    {
        Evaluate(Options()).Options["timestamp"].Visible.ShouldBeFalse();

        var report = Evaluate(Options() with { ContentTimestamp = true });

        report.CanSign.ShouldBeTrue();
        report.Options["timestamp"].Visible.ShouldBeTrue();
        report.Effective.ContentTimestamp.ShouldBeTrue();
    }

    [Fact]
    public void Evaluate_CounterSignWithContentTimestamp_SwitchesItOff()
    {
        var report = Evaluate(Options() with
        {
            Operation = CadesOperation.CounterSign,
            ExistingSignatureId = Sample("enveloped").FileId,
            DataId = null,
            ContentTimestamp = true,
        });

        report.CanSign.ShouldBeTrue();
        report.Options["contentTimestamp"].Disabled.ShouldNotBeNull();
        report.Effective.ContentTimestamp.ShouldBeFalse();
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

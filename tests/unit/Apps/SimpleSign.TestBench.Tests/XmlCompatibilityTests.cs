using Shouldly;
using SimpleSign.TestBench.Signing;
using SimpleSign.TestBench.Xml;

namespace SimpleSign.TestBench.Tests;

/// <summary>The XML rules: XAdES combinations and the fiscal layouts.</summary>
[Collection(TestBenchCollection.Name)]
[Trait("Category", "Unit")]
public sealed class XmlCompatibilityTests(TestBenchFixture fixture)
{
    private XmlSample Sample(string id) => fixture.XmlSamples.Single(s => s.Id == id);

    private XmlOptionsReport Evaluate(XmlOptions options) => fixture.Xml.Evaluate(options);

    private XmlOptions Xades() => new() { DataId = Sample("order").FileId, CredentialId = fixture.Sandboxed() };

    private XmlOptions Fiscal(string sample, string signer = "company") =>
        new() { Mode = XmlMode.Fiscal, Profile = Sample(sample).Profile!, DataId = Sample(sample).FileId, CredentialId = fixture.Sandboxed(signer) };

    [Fact]
    public void Evaluate_Defaults_CanSign() => Evaluate(Xades()).CanSign.ShouldBeTrue();

    [Fact]
    public void Evaluate_NotXml_IsAnError()
    {
        string pdf = SimpleSign.TestBench.Documents.DocumentStore.SampleKey("contract");

        Evaluate(Xades() with { DataId = pdf }).Issues.ShouldContain(i => i.Severity == IssueSeverity.Error && i.Step == XmlCompatibility.StepData);
    }

    [Fact]
    public void Evaluate_DetachedWithoutUri_IsAnError() =>
        Evaluate(Xades() with { Form = XadesFormChoice.Detached, DataUri = " " }).CanSign.ShouldBeFalse();

    [Theory]
    [InlineData(BaselineLevel.BB, XadesExtendedChoice.CompleteReferences, false)]
    [InlineData(BaselineLevel.BT, XadesExtendedChoice.Archive, true)]
    [InlineData(BaselineLevel.BLT, XadesExtendedChoice.ExtendedLong, false)]
    [InlineData(BaselineLevel.BLTA, XadesExtendedChoice.Archive, false)]
    public void Evaluate_ExtendedForm_NeedsExactlyBT(BaselineLevel level, XadesExtendedChoice form, bool allowed) =>
        Evaluate(Xades() with { Level = level, ExtendedForm = form }).CanSign.ShouldBe(allowed);

    [Fact]
    public void Evaluate_IcpBrasil_ForcesSigningCertificateV1()
    {
        var report = Evaluate(Xades() with { Kind = XadesKind.IcpBrasil });

        report.Effective.SigningCertificateV1.ShouldBeTrue();
        report.Options["signingCertificate"].Disabled.ShouldNotBeNull();
    }

    [Fact]
    public void Evaluate_FiscalWithEcdsa_IsRefused() =>
        Evaluate(Fiscal("nfe", "ecdsa-p256")).Issues.ShouldContain(i => i.Severity == IssueSeverity.Error && i.Step == XmlCompatibility.StepSigner);

    [Fact]
    public void Evaluate_FiscalWrongLayout_IsAnError() =>
        Evaluate(Fiscal("cte") with { Profile = "nfe" }).CanSign.ShouldBeFalse();

    [Fact]
    public void Evaluate_FiscalBatch_NeedsAnIdOrSignAll()
    {
        Evaluate(Fiscal("nfe-batch")).CanSign.ShouldBeFalse();
        Evaluate(Fiscal("nfe-batch") with { SignAll = true }).CanSign.ShouldBeTrue();
        string id = fixture.Xml.Facts(Sample("nfe-batch").FileId)!.FiscalTargets["nfe"][1];
        Evaluate(Fiscal("nfe-batch") with { ElementId = id }).CanSign.ShouldBeTrue();
    }

    [Fact]
    public void Evaluate_FiscalHidesXadesOptions()
    {
        var report = Evaluate(Fiscal("nfe"));

        report.CanSign.ShouldBeTrue();
        report.Options["form"].Visible.ShouldBeFalse();
        report.Options["hash"].Note.ShouldNotBeNull();
        report.EffectiveLevel.ShouldContain("SHA-1");
    }
}

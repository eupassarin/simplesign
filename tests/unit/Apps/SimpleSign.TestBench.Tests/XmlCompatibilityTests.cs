using Shouldly;
using SimpleSign.TestBench.Signing;
using SimpleSign.TestBench.Xml;

namespace SimpleSign.TestBench.Tests;

/// <summary>The XML rules: XAdES combinations.</summary>
[Collection(TestBenchCollection.Name)]
[Trait("Category", "Unit")]
public sealed class XmlCompatibilityTests(TestBenchFixture fixture)
{
    private XmlSample Sample(string id) => fixture.XmlSamples.Single(s => s.Id == id);

    private XmlOptionsReport Evaluate(XmlOptions options) => fixture.Xml.Evaluate(options);

    private XmlOptions Xades() => new() { DataId = Sample("order").FileId, CredentialId = fixture.Sandboxed() };

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
}

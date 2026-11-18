using Shouldly;
using Xunit;

namespace SimpleSign.EtsiChecker.Tests;

/// <summary>The checker's raw report read; the fixtures are cut from what it returned for SimpleSign's CAdES B-B.</summary>
[Trait("Category", "Unit")]
public sealed class EtsiCheckerReportTests
{
    private static string Fixture(string name) => File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Fixtures", name));

    [Fact]
    public void Parse_AllChecksSucceeded_HasNoFindings()
    {
        var report = EtsiCheckerReport.Parse(new Dictionary<string, string> { ["CAdES-signature-1"] = Fixture("cades-b-b.xmlrawoutput.xml") });

        report.Findings.ShouldBeEmpty();
        report.Successes.ShouldBe(7);
        report.Summary.ShouldStartWith("1 signature(s), 7 check(s) passed, 0 failure(s), 0 warning(s)");
    }

    [Fact]
    public void Parse_CheckFailure_IsAFailureWithItsCheckAndMessage()
    {
        var report = EtsiCheckerReport.Parse(new Dictionary<string, string> { ["CAdES-signature-1"] = Fixture("cades-b-b-detached.xmlrawoutput.xml") });

        var failure = report.Failures.ShouldHaveSingleItem();
        failure.Signature.ShouldBe("CAdES-signature-1");
        failure.Element.ShouldBe("CheckFailure");
        failure.Check.ShouldBe("CheckIfIsCAdESAndBaselineEN319122_1");
        failure.Path.ShouldBe("");
        failure.Message.ShouldEndWith("message-digest attribute value does not match calculated value");
        report.Successes.ShouldBe(2);
    }

    [Fact]
    public void Parse_NestedWarning_KeepsWhereItIsAndItsSignature()
    {
        const string xml = """
            <?xml version="1.0" encoding="UTF-8"?><xcc:ConformanceReports xmlns:xcc="http://www.etsi.org/xxx/conformanceChecker">
              <content><signedData><signerInfos><signerInfo><unsignedAttrs>
                <CheckWarning check="CheckSomething" testedBy="Tool">  a   warning
                  on two lines </CheckWarning>
              </unsignedAttrs></signerInfo></signerInfos></signedData></content>
            </xcc:ConformanceReports>
            """;

        var report = EtsiCheckerReport.Parse(new Dictionary<string, string>
        {
            ["PAdES-signature-2"] = xml,
            ["PAdES-signature-1"] = Fixture("cades-b-b.xmlrawoutput.xml"),
        });

        report.Failures.ShouldBeEmpty();
        var warning = report.Warnings.ShouldHaveSingleItem();
        warning.Signature.ShouldBe("PAdES-signature-2");
        warning.Path.ShouldBe("content/signedData/signerInfos/signerInfo/unsignedAttrs");
        warning.Message.ShouldBe("a warning on two lines");
    }

    [Fact]
    public void Parse_UnknownCheckElement_CountsAsAFailure()
    {
        const string xml = """<r><CheckException check="X">boom</CheckException></r>""";

        var report = EtsiCheckerReport.Parse(new Dictionary<string, string> { ["s"] = xml });

        report.Failures.ShouldHaveSingleItem().Element.ShouldBe("CheckException");
    }
}

using System.Text.Json;
using Shouldly;
using SimpleSign.TestBench.CrossValidation;
using SimpleSign.TestBench.Runs;

namespace SimpleSign.TestBench.Tests;

/// <summary>Reading the DSS report and lining its verdict up with SimpleSign's.</summary>
[Trait("Category", "Unit")]
public sealed class DssClientTests
{
    // The shape of the WSReportsDTO the DSS REST validation service answers with (shortened).
    private const string Report = """
        {
          "DiagnosticData": { "Signature": [ { "Id": "S-1" } ] },
          "SimpleReport": {
            "ValidationPolicy": { "PolicyName": "QES AdESQC TL based" },
            "DocumentName": "contract-signed.pdf",
            "ValidSignaturesCount": 0,
            "SignaturesCount": 1,
            "signatureOrTimestampOrEvidenceRecord": [
              {
                "Signature": {
                  "SigningTime": "2026-11-06T10:00:00Z",
                  "SignedBy": "Maria Sandbox",
                  "Indication": "INDETERMINATE",
                  "SubIndication": "NO_CERTIFICATE_CHAIN_FOUND",
                  "AdESValidationDetails": {
                    "Error": [ { "value": "Unable to build a certificate chain up to a trusted list!", "key": "BBB_XCV_CCCBB_ANS" } ],
                    "Warning": [ { "value": "The signature/seal is not a valid AdES digital signature!", "key": "ADES" } ]
                  },
                  "Id": "S-1",
                  "SignatureFormat": "PAdES-BASELINE-LT"
                }
              }
            ]
          }
        }
        """;

    private static RunView Run(string indication, string level) => new(
        "run", RunFormats.Pades, "done", DateTimeOffset.Now, 0, default, true, null, null, "file", "contract-signed.pdf", 1, level, level,
        [], 0, 0, null, [], indication, [new RunVerdict("Signature1", "Maria Sandbox", indication, null, null, [], [], [], [])], null, null, []);

    private static DssComparison Dss(string json)
    {
        using var document = JsonDocument.Parse(json);
        return new DssComparison(true, null, "http://dss", 1, true, DssClient.ReadSimpleReport(document.RootElement), [], [], null);
    }

    [Fact]
    public void ReadSimpleReport_Signature_ReadsIndicationFormatAndMessages()
    {
        using var document = JsonDocument.Parse(Report);

        var signature = DssClient.ReadSimpleReport(document.RootElement).ShouldHaveSingleItem();

        signature.Id.ShouldBe("S-1");
        signature.Indication.ShouldBe("INDETERMINATE");
        signature.SubIndication.ShouldBe("NO_CERTIFICATE_CHAIN_FOUND");
        signature.Format.ShouldBe("PAdES-BASELINE-LT");
        signature.SignedBy.ShouldBe("Maria Sandbox");
        signature.Errors.ShouldBe(["Unable to build a certificate chain up to a trusted list!"]);
        signature.Warnings.ShouldBe(["The signature/seal is not a valid AdES digital signature!"]);
    }

    [Fact]
    public void Compare_DifferentIndication_DisagreesAndExplainsTheUntrustedRoot()
    {
        var comparison = DssClient.Compare(RunFormats.Pades, Run("Valid", "B-LT"), Dss(Report));

        comparison.Agree.ShouldBeFalse();
        var indication = comparison.Rows.Single(r => r.Topic == "indication");
        indication.Library.ShouldBe("Valid");
        indication.Dss.ShouldBe("INDETERMINATE / NO_CERTIFICATE_CHAIN_FOUND");
        indication.Note.ShouldBe("Unable to build a certificate chain up to a trusted list!");
        comparison.Rows.Single(r => r.Topic == "level").Agree.ShouldBeTrue();
        comparison.Notes.ShouldHaveSingleItem().ShouldContain("root");
    }

    [Fact]
    public void Compare_SameVerdict_Agrees()
    {
        string passed = Report.Replace("\"INDETERMINATE\"", "\"TOTAL_PASSED\"", StringComparison.Ordinal)
            .Replace("\"NO_CERTIFICATE_CHAIN_FOUND\"", "null", StringComparison.Ordinal);

        var comparison = DssClient.Compare(RunFormats.Pades, Run("Valid", "B-LT"), Dss(passed));

        comparison.Agree.ShouldBeTrue();
        comparison.Notes.ShouldBeEmpty();
    }

    [Theory]
    [InlineData("Valid", "TOTAL_PASSED", true)]
    [InlineData("Valid", "PASSED", true)]
    [InlineData("Valid", "INDETERMINATE", false)]
    [InlineData("Invalid", "TOTAL_FAILED", true)]
    [InlineData("Invalid", "TOTAL_PASSED", false)]
    [InlineData("Indeterminate", "INDETERMINATE", true)]
    public void SameIndication_MapsTheLibraryVerdictToTheEtsiIndication(string library, string dss, bool expected) =>
        DssClient.SameIndication(library, dss).ShouldBe(expected);

    [Theory]
    [InlineData("B-LT", "PAdES-BASELINE-LT", true)]
    [InlineData("B-LTA", "CAdES-BASELINE-LTA", true)]
    [InlineData("B-B", "XAdES-BASELINE-T", false)]
    [InlineData("AD-RT", "PAdES-BASELINE-T", true)]
    [InlineData("XML-DSig", "XML-NOT-ETSI", true)]
    public void SameLevel_ComparesTheBaselineSuffix(string library, string dss, bool expected) =>
        DssClient.SameLevel(library, dss).ShouldBe(expected);
}

using Shouldly;
using SimpleSign.Core.Validation;
using SimpleSign.TestBench.CrossValidation;
using SimpleSign.TestBench.Reports;
using SimpleSign.TestHelpers;

namespace SimpleSign.TestBench.Tests;

/// <summary>Reading SimpleSign's and DSS's JSON reports for the report viewer.</summary>
[Trait("Category", "Unit")]
public sealed class ReportReaderTests
{
    // The shape of the WSReportsDTO DSS 6.3 answers with, shortened to what the viewer reads.
    private const string DssReport = """
        {
          "DiagnosticData": {
            "Signature": [ {
              "Id": "S-1",
              "FoundRevocations": { "RelatedRevocation": [ { "Type": "OCSP", "Revocation": "R-1" } ] }
            } ],
            "Certificate": [
              { "Id": "C-LEAF", "CommonName": "Maria da Silva", "SerialNumber": 1234,
                "SubjectDistinguishedName": [ { "value": "cn=maria da silva", "Format": "CANONICAL" }, { "value": "CN=Maria da Silva,O=Sandbox", "Format": "RFC2253" } ],
                "IssuerDistinguishedName": [ { "value": "CN=Sandbox CA,O=Sandbox", "Format": "RFC2253" } ],
                "NotBefore": "2026-11-09T10:50:50Z", "NotAfter": "2027-11-10T10:50:50Z", "SelfSigned": false,
                "Trusted": { "value": false },
                "CertificateRevocation": [ { "Status": "GOOD", "Revocation": "R-1" } ] },
              { "Id": "C-CA", "CommonName": "Sandbox CA",
                "SubjectDistinguishedName": [ { "value": "CN=Sandbox CA,O=Sandbox", "Format": "RFC2253" } ],
                "SelfSigned": true, "Trusted": { "value": true } }
            ],
            "Revocation": [ { "Id": "R-1", "Type": "OCSP", "Origin": "INPUT_DOCUMENT", "ProductionDate": "2026-11-10T10:51:26Z",
              "ThisUpdate": "2026-11-10T09:51:26Z", "NextUpdate": "2026-11-11T10:51:26Z", "SigningCertificate": { "Certificate": "C-CA" } } ],
            "Timestamp": [ { "Id": "T-1", "Type": "SIGNATURE_TIMESTAMP" } ]
          },
          "SimpleReport": {
            "ValidationPolicy": { "PolicyName": "SimpleSign default" },
            "DocumentName": "valid.pdf",
            "ValidationTime": "2026-11-10T10:51:43Z",
            "signatureOrTimestampOrEvidenceRecord": [ {
              "Signature": {
                "Id": "S-1", "SignedBy": "Maria da Silva", "SigningTime": "2026-11-10T10:51:25Z", "BestSignatureTime": "2026-11-10T10:51:43Z",
                "SignatureFormat": "PAdES-BASELINE-LT", "Indication": "INDETERMINATE", "SubIndication": "NO_CERTIFICATE_CHAIN_FOUND",
                "CertificateChain": { "Certificate": [ { "QualifiedName": "Maria da Silva", "Id": "C-LEAF" }, { "QualifiedName": "Sandbox CA", "Id": "C-CA" } ] },
                "Timestamps": { "Timestamp": [ { "Id": "T-1", "ProductionTime": "2026-11-10T10:51:25Z", "ProducedBy": "Sandbox TSA", "Indication": "PASSED" } ] },
                "AdESValidationDetails": {
                  "Error": [ { "value": "The certificate chain for signature is not trusted.", "Key": "BBB_XCV_CCCBB_SIG_ANS" } ],
                  "Warning": [], "Info": []
                }
              }
            } ]
          },
          "DetailedReport": {
            "signatureOrTimestampOrEvidenceRecord": [ {
              "Signature": {
                "Id": "S-1",
                "ValidationProcessBasicSignature": {
                  "Constraint": [
                    { "Name": { "value": "Is the result of the 'Format Checking' building block conclusive?", "Key": "BSV_IFCRC" }, "Status": "OK" },
                    { "Name": { "value": "Is the result of the Basic Validation Process conclusive?", "Key": "ADEST_ROBVPIIC" }, "Status": "NOT OK",
                      "Error": { "value": "The result of the Basic validation process is not conclusive!", "Key": "ADEST_ROBVPIIC_ANS" } }
                  ]
                }
              }
            } ],
            "BasicBuildingBlocks": [
              { "Id": "S-1", "Type": "SIGNATURE",
                "XCV": { "Constraint": [ { "Name": { "value": "Can the certificate chain be built till a trust anchor?", "Key": "BBB_XCV_CCCBB" }, "Status": "NOT OK",
                  "Error": { "value": "The certificate chain for signature is not trusted.", "Key": "BBB_XCV_CCCBB_SIG_ANS" } } ],
                  "SubXCV": [ { "Constraint": [ { "Name": { "value": "Is the certificate's signature intact?", "Key": "BBB_XCV_ICSI" }, "Status": "OK" } ] },
                              { "Constraint": [ { "Name": { "value": "Is the certificate's signature intact?", "Key": "BBB_XCV_ICSI" }, "Status": "OK" } ] } ] } },
              { "Id": "R-1", "Type": "REVOCATION",
                "XCV": { "Constraint": [ { "Name": { "value": "Not about the signature", "Key": "OTHER" }, "Status": "OK" } ] } }
            ]
          }
        }
        """;

    [Fact]
    public void Read_DssReport_ExplainsTheSignature()
    {
        var report = ReportReader.Read(DssReport).ShouldNotBeNull();

        report.Source.ShouldBe("dss");
        report.Document.ShouldBe("valid.pdf");
        report.Policy.ShouldBe("SimpleSign default");
        var s = report.Signatures.ShouldHaveSingleItem();
        s.Kind.ShouldBe("signature");
        s.Indication.ShouldBe("Indeterminate");
        s.EtsiIndication.ShouldBe("INDETERMINATE");
        s.SubIndication.ShouldBe("NO_CERTIFICATE_CHAIN_FOUND");
        s.Explanation.ShouldContain(SubIndications.Explain("NO_CERTIFICATE_CHAIN_FOUND")!);
        s.Format.ShouldBe("PAdES-BASELINE-LT");
        s.Errors.ShouldBe(["The certificate chain for signature is not trusted."]);
    }

    [Fact]
    public void Read_DssReport_ReadsChainTimestampsAndRevocation()
    {
        var s = ReportReader.Read(DssReport)!.Signatures[0];

        s.Chain.Select(c => c.Name).ShouldBe(["Maria da Silva", "Sandbox CA"]);
        s.Chain[0].Subject.ShouldBe("CN=Maria da Silva,O=Sandbox");
        s.Chain[0].SerialNumber.ShouldBe("1234");
        s.Chain[0].Trusted.ShouldBe(false);
        s.Chain[0].RevocationStatus.ShouldBe("GOOD");
        s.Chain[1].SelfSigned.ShouldBeTrue();
        s.Chain[1].Trusted.ShouldBe(true);
        var timestamp = s.Timestamps.ShouldHaveSingleItem();
        timestamp.Type.ShouldBe("SIGNATURE_TIMESTAMP");
        timestamp.ProducedBy.ShouldBe("Sandbox TSA");
        var revocation = s.Revocation.ShouldHaveSingleItem();
        revocation.Type.ShouldBe("OCSP");
        revocation.Certificate.ShouldBe("Maria da Silva");
        revocation.Status.ShouldBe("GOOD");
        revocation.Origin.ShouldBe("INPUT_DOCUMENT");
        revocation.Issuer.ShouldBe("Sandbox CA");
        revocation.ProducedAt.ShouldBe("2026-11-10T10:51:26Z");
    }

    [Fact]
    public void Read_DssReport_GroupsTheSignaturesConstraintsFailuresFirst()
    {
        var constraints = ReportReader.Read(DssReport)!.Signatures[0].Constraints;

        constraints.Select(c => c.Status).ShouldBe(["fail", "fail", "pass", "pass"]);
        constraints.ShouldNotContain(c => c.Key == "OTHER");
        var chain = constraints.Single(c => c.Key == "BBB_XCV_CCCBB");
        chain.Title.ShouldBe("Can the certificate chain be built till a trust anchor?");
        chain.Messages.ShouldBe(["The certificate chain for signature is not trusted."]);
        constraints.Single(c => c.Key == "BBB_XCV_ICSI").Count.ShouldBe(2);
    }

    [Fact]
    public void Read_SimpleSignReport_ExplainsChainAndGroupedConstraints()
    {
        using var pki = new SyntheticPki();
        var entry = new SignatureReportEntry
        {
            Id = "signer-1",
            Format = "CAdES",
            Indication = SignatureIndication.Invalid,
            SubIndication = SignatureSubIndication.HashFailure,
            SignerCertificate = pki.Leaf,
            Constraints =
            [
                new("SignatureConstraints/BasicSignatureConstraints/ReferenceDataIntact", ConstraintStatus.Failed, SignatureSubIndication.HashFailure, "The digest does not match."),
                new("SignatureConstraints/BasicSignatureConstraints/SigningCertificate/AuthorityKeyIdentifierPresent", ConstraintStatus.Warning, null, "Leaf has no AKI."),
                new("SignatureConstraints/BasicSignatureConstraints/CACertificate/AuthorityKeyIdentifierPresent", ConstraintStatus.Warning, null, "Root has no AKI."),
                new("SignatureConstraints/BasicSignatureConstraints/SignatureIntact", ConstraintStatus.Passed, null, ""),
                new("SignatureConstraints/SignedAttributes/ContentHints", ConstraintStatus.NotChecked, null, ""),
            ],
        };
        var counter = new SignatureReportEntry { Id = "signer-1.1", Format = "CAdES", Indication = SignatureIndication.Valid };
        string json = SimpleSignReport.Build([new ReportSource(entry, [pki.IntermediateCa, pki.RootCa]), new ReportSource(counter, [])], "data.p7s", []);

        var report = ReportReader.Read(json).ShouldNotBeNull();

        report.Source.ShouldBe("simplesign");
        report.Document.ShouldBe("data.p7s");
        var s = report.Signatures[0];
        s.Kind.ShouldBe("signature");
        s.Indication.ShouldBe("Invalid");
        s.EtsiIndication.ShouldBe("TOTAL_FAILED");
        s.SubIndication.ShouldBe("HASH_FAILURE");
        s.Explanation.ShouldContain(SubIndications.Explain("HASH_FAILURE")!);
        s.Chain.Select(c => c.Name).ShouldBe(["SimpleSign Synthetic Signer", "SimpleSign Synthetic Intermediate CA", "SimpleSign Synthetic Root CA"]);
        s.Constraints.Select(c => (c.Key, c.Status, c.Count)).ShouldBe(
        [
            ("ReferenceDataIntact", "fail", 1),
            ("AuthorityKeyIdentifierPresent", "warn", 2),
            ("SignatureIntact", "pass", 1),
            ("ContentHints", "skip", 1),
        ]);
        s.Constraints[1].Messages.ShouldBe(["Leaf has no AKI.", "Root has no AKI."]);
        s.Constraints[2].Messages.ShouldBeEmpty();
        report.Signatures[1].Kind.ShouldBe("counterSignature");
        report.Signatures[1].Indication.ShouldBe("Valid");
    }

    [Theory]
    [InlineData("""{"hello": "world"}""")]
    [InlineData("""[1, 2]""")]
    public void Read_NotAReport_IsNull(string json) => ReportReader.Read(json).ShouldBeNull();

    [Theory]
    [InlineData("TOTAL_PASSED", "Valid")]
    [InlineData("PASSED", "Valid")]
    [InlineData("TOTAL_FAILED", "Invalid")]
    [InlineData("FAILED", "Invalid")]
    [InlineData("INDETERMINATE", "Indeterminate")]
    [InlineData(null, "Indeterminate")]
    public void Indication_EtsiName_IsSimpleSignsIndication(string? etsi, string expected) => ReportReader.Indication(etsi).ShouldBe(expected);

    [Fact]
    public void Explain_ValidWithoutSubIndication_SaysValid() =>
        ReportReader.Explain("Valid", null).ShouldStartWith("Valid");
}

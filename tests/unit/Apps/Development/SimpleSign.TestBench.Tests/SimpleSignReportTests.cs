using System.Text;
using System.Text.Json.Nodes;
using Shouldly;
using SimpleSign.Core.Validation;
using SimpleSign.TestBench.Reports;
using SimpleSign.TestHelpers;

namespace SimpleSign.TestBench.Tests;

/// <summary>SimpleSign's JSON report: the library's simple report with each signature's chain and constraints.</summary>
[Trait("Category", "Unit")]
public sealed class SimpleSignReportTests
{
    [Fact]
    public void Chain_ShuffledPool_OrdersSignerThenEachIssuer()
    {
        using var pki = new SyntheticPki();

        var chain = SimpleSignReport.Chain(pki.Leaf, [pki.RootCa, pki.IntermediateCa]);

        chain.Select(c => c.Subject).ShouldBe([pki.Leaf.Subject, pki.IntermediateCa.Subject, pki.RootCa.Subject]);
    }

    [Fact]
    public void Chain_IssuerMissing_StopsAtTheLastKnown()
    {
        using var pki = new SyntheticPki();

        SimpleSignReport.Chain(pki.Leaf, [pki.RootCa]).ShouldHaveSingleItem().Subject.ShouldBe(pki.Leaf.Subject);
        SimpleSignReport.Chain(null, [pki.RootCa]).ShouldBeEmpty();
    }

    [Fact]
    public void Build_Signature_AddsGeneratorChainAndEveryConstraint()
    {
        using var pki = new SyntheticPki();
        var entry = new SignatureReportEntry
        {
            Id = "Signature1",
            Format = "PAdES",
            Indication = SignatureIndication.Indeterminate,
            SubIndication = SignatureSubIndication.RevokedNoPoe,
            SignerCertificate = pki.Leaf,
            Constraints =
            [
                new("SignatureConstraints/BasicSignatureConstraints/SigningCertificate/NotRevoked", ConstraintStatus.Failed, SignatureSubIndication.RevokedNoPoe, "The certificate was revoked."),
                new("SignatureConstraints/BasicSignatureConstraints/SigningCertificate/KeyUsage", ConstraintStatus.Passed, null, "nonRepudiation"),
            ],
        };

        string json = SimpleSignReport.Build([new ReportSource(entry, [pki.IntermediateCa])], "contract.pdf", [pki.RootCa]);

        var root = JsonNode.Parse(json)!;
        root["generator"]!.GetValue<string>().ShouldBe(SimpleSignReport.Generator);
        root["document"]!.GetValue<string>().ShouldBe("contract.pdf");
        var signature = root["signatures"]![0]!;
        signature["indication"]!.GetValue<string>().ShouldBe("INDETERMINATE");
        signature["subIndication"]!.GetValue<string>().ShouldBe("REVOKED_NO_POE");
        signature["certificates"]!.AsArray().Select(c => c!["subject"]!.GetValue<string>()).ShouldBe([pki.Leaf.Subject, pki.IntermediateCa.Subject, pki.RootCa.Subject]);
        signature["certificates"]![2]!["selfSigned"]!.GetValue<bool>().ShouldBeTrue();
        var constraints = signature["constraints"]!.AsArray();
        constraints.Count.ShouldBe(2);
        constraints[0]!["status"]!.GetValue<string>().ShouldBe("Failed");
        constraints[0]!["subIndication"]!.GetValue<string>().ShouldBe("REVOKED_NO_POE");
        constraints[1]!["status"]!.GetValue<string>().ShouldBe("Passed");
    }

    [Fact]
    public void Build_CrlUsed_DescribesItsIssuerAndDates()
    {
        using var pki = new SyntheticPki();
        var entry = new SignatureReportEntry
        {
            Id = "signer-1",
            Indication = SignatureIndication.Valid,
            SignerCertificate = pki.Leaf,
            ValidationObjects = [new ValidationObjectEntry(ValidationObjectType.Crl, pki.BuildLeafCrl(), SignatureIndication.Valid, null)],
        };

        var root = JsonNode.Parse(SimpleSignReport.Build([new ReportSource(entry, [])], null, []))!;

        var crl = root["signatures"]![0]!["revocationData"]![0]!;
        crl["type"]!.GetValue<string>().ShouldBe("CRL");
        crl["issuer"]!.GetValue<string>().ShouldBe(pki.IntermediateCa.Subject);
        crl["thisUpdate"]!.GetValue<string>().ShouldEndWith("Z");
        root["document"].ShouldBeNull();
    }

    [Fact]
    public void CertificatesIn_XmlSignature_ReadsItsX509Certificates()
    {
        using var pki = new SyntheticPki();
        string xml = $"""
            <Doc><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:KeyInfo><ds:X509Data>
            <ds:X509Certificate>{Convert.ToBase64String(pki.Leaf.RawData)}</ds:X509Certificate>
            <ds:X509Certificate>{Convert.ToBase64String(pki.IntermediateCa.RawData)}</ds:X509Certificate>
            </ds:X509Data></ds:KeyInfo></ds:Signature></Doc>
            """;

        var certificates = SimpleSignReport.CertificatesIn(Encoding.UTF8.GetBytes(xml));

        certificates.Select(c => c.Subject).ShouldBe([pki.Leaf.Subject, pki.IntermediateCa.Subject]);
    }

    [Theory]
    [InlineData("%PDF-1.7 no certificates here")]
    [InlineData("<Doc>no signature</Doc>")]
    public void CertificatesIn_NoCmsOrXmlSignature_IsEmpty(string content) =>
        SimpleSignReport.CertificatesIn(Encoding.UTF8.GetBytes(content)).ShouldBeEmpty();

    [Theory]
    [InlineData("contract-signed.pdf", "contract-signed.simplesign-report.json")]
    [InlineData(null, "signature.simplesign-report.json")]
    public void FileName_OfTheValidatedFile_EndsWithSimpleSignReport(string? fileName, string expected) =>
        SimpleSignReport.FileName(fileName).ShouldBe(expected);
}

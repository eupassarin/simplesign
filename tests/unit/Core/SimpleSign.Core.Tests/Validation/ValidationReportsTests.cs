using System.Text.Json;
using System.Xml;
using System.Xml.Linq;
using System.Xml.Schema;
using Shouldly;
using SimpleSign.Core.Policies;
using SimpleSign.Core.Validation;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.Core.Tests.Validation;

[Trait("Category", "Unit")]
public sealed class ValidationReportsTests : IDisposable
{
    private static readonly XNamespace Vr = ValidationReports.EtsiNamespace;
    private readonly SyntheticPki _pki = new();

    [Fact]
    public void ToEtsiXml_ValidAndInvalid_HasTheEtsiIndicationsAndTheSigner()
    {
        var xml = XDocument.Parse(ValidationReports.ToEtsiXml([Entry("Signature1"), Entry("Signature2", invalid: true)],
            ValidationLevel.LongTermData, new DateTimeOffset(2026, 11, 7, 12, 0, 0, TimeSpan.Zero)));

        var reports = xml.Root!.Elements(Vr + "SignatureValidationReport").ToList();
        reports.Count.ShouldBe(2);
        reports[0].Element(Vr + "SignatureValidationStatus")!.Element(Vr + "MainIndication")!.Value
            .ShouldBe("urn:etsi:019102:mainindication:total-passed");
        var failed = reports[1].Element(Vr + "SignatureValidationStatus")!;
        failed.Element(Vr + "MainIndication")!.Value.ShouldBe("urn:etsi:019102:mainindication:total-failed");
        failed.Element(Vr + "SubIndication")!.Value.ShouldBe("urn:etsi:019102:subindication:HASH_FAILURE");
        reports[0].Element(Vr + "SignatureValidationProcess")!.Element(Vr + "SignatureValidationProcessID")!.Value
            .ShouldBe("urn:etsi:019102:validationprocess:LTVM");
        string reference = reports[0].Element(Vr + "SignerInformation")!.Element(Vr + "SignerCertificate")!.Attribute("VOReference")!.Value;
        xml.Root.Element(Vr + "SignatureValidationObjects")!.Elements(Vr + "ValidationObject")
            .ShouldHaveSingleItem().Attribute("id")!.Value.ShouldBe(reference);
    }

    [Fact]
    public void ToEtsiXml_NotEvaluatedConstraint_IsDisabled()
    {
        var xml = XDocument.Parse(ValidationReports.ToEtsiXml([Entry("Signature1")]));

        xml.Descendants(Vr + "ValidationConstraint")
            .ShouldContain(c => c.Element(Vr + "ConstraintStatus")!.Element(Vr + "Status")!.Value == "urn:etsi:019102:constraintStatus:disabled"
                && c.Element(Vr + "ValidationStatus") == null);
    }

    [Fact]
    public void ToEtsiXml_ValidationObjects_AreListedWithTheirStatus()
    {
        var entry = Entry("Signature1") with
        {
            ValidationObjects =
            [
                new ValidationObjectEntry(ValidationObjectType.Timestamp, new byte[] { 1, 2, 3 }, SignatureIndication.Valid, null) { Time = DateTimeOffset.UtcNow },
                new ValidationObjectEntry(ValidationObjectType.OcspResponse, new byte[] { 4, 5 }, SignatureIndication.Indeterminate, SignatureSubIndication.TryLater),
            ],
        };

        var xml = XDocument.Parse(ValidationReports.ToEtsiXml([entry]));
        XNamespace ns = ValidationReports.EtsiNamespace;

        var objects = xml.Descendants(ns + "ValidationObject").ToList();
        objects.ShouldContain(o => o.Element(ns + "ObjectType")!.Value.EndsWith(":timestamp", StringComparison.Ordinal) && o.Element(ns + "POE") != null);
        objects.ShouldContain(o => o.Element(ns + "ObjectType")!.Value.EndsWith(":OCSPResponse", StringComparison.Ordinal)
            && o.Descendants(ns + "SubIndication").Single().Value.EndsWith("TRY_LATER", StringComparison.Ordinal));
    }

    [Fact]
    public void ToSimpleJson_CountsTheValidSignatures()
    {
        using var json = JsonDocument.Parse(ValidationReports.ToSimpleJson([Entry("a"), Entry("b", invalid: true)]));

        json.RootElement.GetProperty("signaturesCount").GetInt32().ShouldBe(2);
        json.RootElement.GetProperty("validSignaturesCount").GetInt32().ShouldBe(1);
        var second = json.RootElement.GetProperty("signatures")[1];
        second.GetProperty("indication").GetString().ShouldBe("TOTAL_FAILED");
        second.GetProperty("subIndication").GetString().ShouldBe("HASH_FAILURE");
        second.GetProperty("policy").GetProperty("name").GetString().ShouldBe("SimpleSign default");
    }

    public void Dispose() => _pki.Dispose();

    private SignatureReportEntry Entry(string id, bool invalid = false) => new()
    {
        Id = id,
        Format = "PAdES",
        Indication = invalid ? SignatureIndication.Invalid : SignatureIndication.Valid,
        SubIndication = invalid ? SignatureSubIndication.HashFailure : null,
        Constraints =
        [
            new("SignatureConstraints/BasicSignatureConstraints/ReferenceDataIntact",
                invalid ? ConstraintStatus.Failed : ConstraintStatus.Passed, invalid ? SignatureSubIndication.HashFailure : null, "integrity"),
            new("SignatureConstraints/BasicSignatureConstraints/DocMDP", ConstraintStatus.NotChecked, null, "not evaluated"),
        ],
        SignerCertificate = _pki.Leaf,
        ClaimedSigningTime = DateTimeOffset.UtcNow.AddMinutes(-5),
        Policy = AppliedPolicy.Of(ValidationPolicy.Default),
    };
}

/// <summary>Validates the ETSI report against the schema DSS uses (needs the network).</summary>
[Trait("Category", "Integration")]
public sealed class ValidationReportsSchemaTests
{
    [Fact]
    public void ToEtsiXml_IsValidAgainstTheTs119102Schema()
    {
        var schemas = new XmlSchemaSet { XmlResolver = new XmlUrlResolver() };
        try
        {
            // The imports, loaded first: the W3C xmldsig schema has a DOCTYPE the default reader refuses.
            Add(schemas, "http://www.w3.org/2000/09/xmldsig#", "http://www.w3.org/TR/2002/REC-xmldsig-core-20020212/xmldsig-core-schema.xsd");
            Add(schemas, "http://uri.etsi.org/01903/v1.3.2#", "http://uri.etsi.org/01903/v1.3.2/XAdES.xsd");
            Add(schemas, "http://uri.etsi.org/02231/v2#", "http://uri.etsi.org/19612/v2.2.1/ts_119612v020201_201601xsd.xsd");
            Add(schemas, ValidationReports.EtsiNamespace,
                "https://raw.githubusercontent.com/esig/dss/master/specs-validation-report/src/main/resources/xsd/TS119102-2-v122.xsd");
            schemas.Compile();
        }
        catch (Exception ex) when (ex is XmlException or XmlSchemaException or System.Net.WebException or HttpRequestException or IOException)
        {
            if (Environment.GetEnvironmentVariable("SIMPLESIGN_REQUIRE_NETWORK") == "1")
            {
                throw;
            }

            return; // Offline, or an imported schema is not reachable: nothing to check against.
        }

        using var pki = new SyntheticPki();
        string xml = ValidationReports.ToEtsiXml(
        [
            new SignatureReportEntry
            {
                Id = "Signature1",
                Indication = SignatureIndication.Indeterminate,
                SubIndication = SignatureSubIndication.TryLater,
                Constraints = [new("SignatureConstraints/BasicSignatureConstraints/SigningCertificate/RevocationDataAvailable",
                    ConstraintStatus.Failed, SignatureSubIndication.TryLater, "no revocation data")],
                SignerCertificate = pki.Leaf,
                ClaimedSigningTime = DateTimeOffset.UtcNow,
                Policy = AppliedPolicy.Of(ValidationPolicy.Default),
                ValidationObjects =
                [
                    new ValidationObjectEntry(ValidationObjectType.Timestamp, new byte[] { 1, 2, 3 }, SignatureIndication.Valid, null) { Time = DateTimeOffset.UtcNow },
                    new ValidationObjectEntry(ValidationObjectType.Crl, pki.BuildLeafCrl(), SignatureIndication.Indeterminate, SignatureSubIndication.TryLater),
                ],
            },
        ]);
        var errors = new List<string>();

        XDocument.Parse(xml).Validate(schemas, (_, e) => errors.Add(e.Message));

        errors.ShouldBeEmpty();
    }

    private static void Add(XmlSchemaSet schemas, string targetNamespace, string url)
    {
        if (schemas.Contains(targetNamespace))
        {
            return;
        }

        using var reader = XmlReader.Create(url, new XmlReaderSettings { DtdProcessing = DtdProcessing.Ignore, XmlResolver = new XmlUrlResolver() });
        schemas.Add(targetNamespace, reader);
    }
}

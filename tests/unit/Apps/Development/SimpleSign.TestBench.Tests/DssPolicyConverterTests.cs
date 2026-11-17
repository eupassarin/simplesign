using System.Xml;
using System.Xml.Linq;
using System.Xml.Schema;
using Shouldly;
using SimpleSign.Core.Policies;
using SimpleSign.TestBench.CrossValidation;

namespace SimpleSign.TestBench.Tests;

[Trait("Category", "Unit")]
public sealed class DssPolicyConverterTests
{
    [Fact]
    public void ToConstraintXml_DefaultPolicy_UsesTheDssNamespaceAndElements()
    {
        var xml = XDocument.Parse(DssPolicyConverter.ToConstraintXml(ValidationPolicy.Default.ToJson()));
        XNamespace ns = "http://dss.esig.europa.eu/validation/policy";

        xml.Declaration!.Encoding.ShouldBe("utf-8", StringCompareShould.IgnoreCase);
        xml.Root!.Name.ShouldBe(ns + "ConstraintsParameters");
        xml.Root.Attribute("Name")!.Value.ShouldBe("SimpleSign default");
        xml.Root.Elements().First().Name.LocalName.ShouldBe("Description");
        xml.Root.Element(ns + "eIDAS").ShouldNotBeNull();
        xml.Root.Element(ns + "TrustedLists").ShouldBeNull();
        var keyUsage = xml.Root.Element(ns + "SignatureConstraints")!.Element(ns + "BasicSignatureConstraints")!
            .Element(ns + "SigningCertificate")!.Element(ns + "KeyUsage")!;
        keyUsage.Attribute("Level")!.Value.ShouldBe("WARN");
        keyUsage.Element(ns + "Id")!.Value.ShouldBe("nonRepudiation");
        xml.Root.Element(ns + "Cryptographic")!.Element(ns + "AlgoExpirationDate")!.Elements(ns + "Algo")
            .ShouldContain(a => a.Value == "RSA" && a.Attribute("Size")!.Value == "1900" && a.Attribute("Date")!.Value == "2027-01-01");
    }

    [Fact]
    public void FromConstraintXml_RoundTrip_GivesTheSamePolicy()
    {
        string json = ValidationPolicy.Default.ToJson();

        string back = DssPolicyConverter.FromConstraintXml(DssPolicyConverter.ToConstraintXml(json));

        ValidationPolicy.FromJson(back).ToJson().ShouldBe(json);
    }
}

/// <summary>Checks the policy format against the EU DSS sources (needs the network).</summary>
[Trait("Category", "Integration")]
public sealed class DssPolicyCompatibilityTests
{
    private const string Base = "https://raw.githubusercontent.com/esig/dss/master/dss-policy-jaxb/src/main/resources/";

    [Fact]
    public async Task DssDefaultPolicy_IsReadAndHasTheLevelsOfOurDefault()
    {
        string? xml = await TryDownloadAsync(Base + "policy/constraint.xml");
        if (xml is null)
        {
            return; // Offline: nothing to compare against.
        }

        var dropped = new List<string>();
        var dss = ValidationPolicy.FromJson(DssPolicyConverter.FromConstraintXml(xml, dropped));

        // What SimpleSign's format does not have is dropped and listed (docs/policies/compatibility.md).
        dropped.ShouldContain("ContainerConstraints");
        dropped.ShouldContain("SignatureConstraints/BasicSignatureConstraints/SigningCertificate/SunsetDate");
        dropped.Select(path => path[(path.LastIndexOf('/') + 1)..]).ShouldAllBe(name => DssPolicyConverter.NotInSimpleSign.Contains(name));

        foreach (string path in new[]
        {
            "SignatureConstraints/BasicSignatureConstraints/SigningCertificate/KeyUsage",
            "SignatureConstraints/BasicSignatureConstraints/SigningCertificate/NotRevoked",
            "SignatureConstraints/BasicSignatureConstraints/CACertificate/KeyUsage",
            "SignatureConstraints/SignedAttributes/SigningTime",
            "Timestamp/BasicSignatureConstraints/SigningCertificate/ExtendedKeyUsage",
            "Cryptographic",
            "Cryptographic/AlgoExpirationDate",
        })
        {
            dss.Find(path)!.Level.ShouldBe(ValidationPolicy.Default.Find(path)!.Level, path);
        }

        dss.Find("Model")!.Value.ShouldBe("SHELL");
    }

    [Fact]
    public async Task ConstraintXmlOfOurDefault_IsValidAgainstTheDssSchema()
    {
        string? xsd = await TryDownloadAsync(Base + "xsd/policy.xsd");
        if (xsd is null)
        {
            return;
        }

        var schemas = new XmlSchemaSet();
        using (var reader = XmlReader.Create(new StringReader(xsd), new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit }))
        {
            schemas.Add(null, reader);
        }

        var errors = new List<string>();
        XDocument.Parse(DssPolicyConverter.ToConstraintXml(ValidationPolicy.Default.ToJson()))
            .Validate(schemas, (_, e) => errors.Add(e.Message));

        errors.ShouldBeEmpty();
    }

    [Fact]
    public async Task ConstraintXmlForDss63_IsValidAgainstTheDss63Schema()
    {
        string? xsd = await TryDownloadAsync("https://raw.githubusercontent.com/esig/dss/6.3/dss-policy-jaxb/src/main/resources/xsd/policy.xsd");
        if (xsd is null)
        {
            return;
        }

        var schemas = new XmlSchemaSet();
        using (var reader = XmlReader.Create(new StringReader(xsd), new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit }))
        {
            schemas.Add(null, reader);
        }

        var errors = new List<string>();
        XDocument.Parse(DssPolicyConverter.ToConstraintXml(ValidationPolicy.Default.ToJson(), DssPolicyConverter.NotInDss63))
            .Validate(schemas, (_, e) => errors.Add(e.Message));

        errors.ShouldBeEmpty();
    }

    private static async Task<string?> TryDownloadAsync(string url)
    {
        try
        {
            using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(20) };
            return await http.GetStringAsync(new Uri(url));
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
        {
            return null;
        }
    }
}

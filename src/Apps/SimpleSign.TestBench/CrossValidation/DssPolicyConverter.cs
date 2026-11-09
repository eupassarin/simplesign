using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Xml;
using System.Xml.Linq;

namespace SimpleSign.TestBench.CrossValidation;

/// <summary>
/// Converts a SimpleSign validation policy (JSON) to the DSS <c>constraint.xml</c> and back, following
/// docs/policies/compatibility.md, so DSS validates with the same policy. The names are the same except the root
/// (<c>ValidationConstraints</c> ↔ <c>ConstraintsParameters</c>) and the trusted lists (<c>TrustedLists</c> ↔
/// <c>eIDAS</c>). The mapping is mechanical: an object is an element, a string or number property an attribute (except
/// <c>Description</c>, the root's text element), the <c>Id</c> and <c>Algo</c> arrays repeated elements, the
/// <c>Value</c> of an <c>Algo</c> its text. Elements SimpleSign's format does not have are dropped on the way in.
/// </summary>
internal static class DssPolicyConverter
{
    internal static readonly XNamespace Namespace = "http://dss.esig.europa.eu/validation/policy";

    private const string Root = "ValidationConstraints";
    private const string DssRoot = "ConstraintsParameters";

    /// <summary>SimpleSign names that DSS writes differently.</summary>
    private static readonly Dictionary<string, string> s_toDss = new(StringComparer.Ordinal)
    {
        [Root] = DssRoot,
        ["TrustedLists"] = "eIDAS",
    };

    private static readonly Dictionary<string, string> s_fromDss = s_toDss.ToDictionary(p => p.Value, p => p.Key, StringComparer.Ordinal);

    /// <summary>
    /// DSS elements that are not in SimpleSign's format (docs/policies/compatibility.md, state "removed"): dropped when a
    /// DSS policy is read.
    /// </summary>
    internal static readonly IReadOnlySet<string> NotInSimpleSign = new HashSet<string>(StringComparer.Ordinal)
    {
        "ContainerConstraints", "PDFAConstraints", "KeyBindingSignatureConstraints", "EvidenceRecord", "Attestation",
        "AttestationRevocation", "KeyIdentifierPresent", "KeyIdentifierMatch", "X509UrlPresent", "X509UrlMatch",
        "SignatureType", "EllipticCurveKeySize", "ContainerSignedAndTimestampedFilesCovered", "OCSPCertHashPresent",
        "OCSPCertHashMatch", "ReferenceDataNameMatch", "ManifestEntryObjectExistence", "ManifestEntryObjectGroup",
        "ManifestEntryObjectIntact", "ManifestEntryNameMatch", "PdfVisualDifference", "SunsetDate",
        "PolicyQualificationIds", "PolicySupportedByQSCDIds", "QcEuLimitValueCurrency", "MinQcEuLimitValue",
        "MinQcEuRetentionPeriod", "QcEuPDSLocation", "QcType", "QcLegislationCountryCodes", "IssuedToNaturalPerson",
        "IssuedToLegalPerson", "SemanticsIdentifier", "PSD2QcTypeRolesOfPSP", "PSD2QcCompetentAuthorityName",
        "PSD2QcCompetentAuthorityId", "QcQSCDLegislation", "QcIdentificationMethod", "QcPSBCountryOfLegislation",
        "QcPSBAuthSourceIdentification", "QcPSBLegislationIdentification", "LoTEFreshness", "LoTENotExpired",
        "LoTEWellSigned", "LoTEVersion", "LoTEStructure",
    };

    /// <summary>
    /// Elements of the current DSS policy schema that DSS 6.3 (the version of <c>tools/dss</c>) does not know: DSS
    /// refuses a policy that has them. They are left out of the XML sent to it, so DSS does not evaluate them.
    /// </summary>
    internal static readonly IReadOnlySet<string> NotInDss63 = new HashSet<string>(StringComparer.Ordinal)
    {
        "AuthorityKeyIdentifierPresent", "SubjectKeyIdentifierPresent", "SigningTimeInCertRange",
    };

    /// <summary>The DSS <c>constraint.xml</c> of a SimpleSign validation policy, for the current DSS schema or, with <paramref name="omit"/>, an older one.</summary>
    internal static string ToConstraintXml(string json, IReadOnlySet<string>? omit = null)
    {
        using var document = JsonDocument.Parse(json, new JsonDocumentOptions { CommentHandling = JsonCommentHandling.Skip });
        var root = document.RootElement.GetProperty(Root);
        var xml = new XDocument(new XDeclaration("1.0", "UTF-8", "yes"), Element(Root, root, omit));
        // Written as UTF-8 bytes, so the declaration says UTF-8 (a StringBuilder would declare UTF-16).
        using var stream = new MemoryStream();
        using (var writer = XmlWriter.Create(stream, new XmlWriterSettings { Indent = true, Encoding = new UTF8Encoding(false) }))
        {
            xml.Save(writer);
        }

        return Encoding.UTF8.GetString(stream.ToArray());
    }

    /// <summary>
    /// A SimpleSign validation policy (JSON) from a DSS <c>constraint.xml</c>. Elements SimpleSign's format does not
    /// have are left out and, when <paramref name="dropped"/> is given, added to it with their path.
    /// </summary>
    internal static string FromConstraintXml(string xml, ICollection<string>? dropped = null)
    {
        var document = XDocument.Parse(xml);
        var root = document.Root ?? throw new InvalidDataException("The policy has no root element.");
        var json = new JsonObject { [Root] = Object(root, "", dropped) };
        return json.ToJsonString(new JsonSerializerOptions { WriteIndented = true });
    }

    private static XElement Element(string name, JsonElement value, IReadOnlySet<string>? omit)
    {
        var element = new XElement(Namespace + s_toDss.GetValueOrDefault(name, name));
        foreach (var property in value.EnumerateObject())
        {
            if (omit?.Contains(property.Name) == true)
            {
                continue;
            }

            switch (property.Name)
            {
                case "$schema":
                    break;
                case "Description":
                    element.Add(new XElement(Namespace + "Description", property.Value.GetString()));
                    break;
                case "Id":
                    element.Add(property.Value.EnumerateArray().Select(id => new XElement(Namespace + "Id", id.GetString())));
                    break;
                case "Algo":
                    element.Add(property.Value.EnumerateArray().Select(Algo));
                    break;
                default:
                    if (property.Value.ValueKind == JsonValueKind.Object)
                    {
                        element.Add(Element(property.Name, property.Value, omit));
                    }
                    else
                    {
                        element.SetAttributeValue(property.Name, property.Value.ValueKind == JsonValueKind.Number
                            ? property.Value.GetInt32().ToString(CultureInfo.InvariantCulture)
                            : property.Value.GetString());
                    }

                    break;
            }
        }

        // Attributes come first in the XML; XElement keeps them apart from the children already.
        return element;
    }

    private static XElement Algo(JsonElement algo)
    {
        if (algo.ValueKind == JsonValueKind.String)
        {
            return new XElement(Namespace + "Algo", algo.GetString());
        }

        var element = new XElement(Namespace + "Algo", algo.GetProperty("Value").GetString());
        if (algo.TryGetProperty("Size", out var size))
        {
            element.SetAttributeValue("Size", size.GetInt32().ToString(CultureInfo.InvariantCulture));
        }

        if (algo.TryGetProperty("Date", out var date))
        {
            element.SetAttributeValue("Date", date.GetString());
        }

        return element;
    }

    private static JsonObject Object(XElement element, string path, ICollection<string>? dropped)
    {
        var json = new JsonObject();
        foreach (var attribute in element.Attributes().Where(a => !a.IsNamespaceDeclaration))
        {
            string name = attribute.Name.LocalName;
            json[name] = name is "Value" or "value" or "Size" && int.TryParse(attribute.Value, CultureInfo.InvariantCulture, out int number)
                && element.Name.LocalName != "Model"
                ? JsonValue.Create(number)
                : JsonValue.Create(attribute.Value);
        }

        var ids = element.Elements(Namespace + "Id").Select(e => (JsonNode?)JsonValue.Create(e.Value)).ToArray();
        if (ids.Length > 0)
        {
            json["Id"] = new JsonArray(ids);
        }

        var algos = element.Elements(Namespace + "Algo").Select(AlgoNode).ToArray();
        if (algos.Length > 0)
        {
            json["Algo"] = new JsonArray(algos);
        }

        foreach (var child in element.Elements().Where(e => e.Name.LocalName is not ("Id" or "Algo")))
        {
            string dssName = child.Name.LocalName;
            string childPath = path.Length == 0 ? dssName : path + "/" + dssName;
            if (NotInSimpleSign.Contains(dssName))
            {
                dropped?.Add(childPath);
                continue;
            }

            string name = s_fromDss.GetValueOrDefault(dssName, dssName);
            json[name] = name == "Description" ? JsonValue.Create(child.Value) : Object(child, childPath, dropped);
        }

        return json;
    }

    private static JsonNode? AlgoNode(XElement algo)
    {
        if (!algo.HasAttributes)
        {
            return JsonValue.Create(algo.Value.Trim());
        }

        var json = new JsonObject { ["Value"] = algo.Value.Trim() };
        if (algo.Attribute("Size") is { } size)
        {
            json["Size"] = int.Parse(size.Value, CultureInfo.InvariantCulture);
        }

        if (algo.Attribute("Date") is { } date)
        {
            json["Date"] = date.Value;
        }

        return json;
    }
}

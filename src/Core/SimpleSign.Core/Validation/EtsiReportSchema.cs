using System.Xml;
using System.Xml.Schema;

namespace SimpleSign.Core.Validation;

/// <summary>
/// The ETSI TS 119 102-2 validation report schema and the schemas it imports, embedded in the assembly: a report is
/// checked offline, nothing is fetched.
/// </summary>
internal static class EtsiReportSchema
{
    private const int MaxErrors = 20;

    // Imported schemas first: xml.xsd and XML Signature before XAdES and TS 119 612, then the report schema.
    private static readonly string[] s_files =
    [
        "xml.xsd", "xmldsig-core-schema.xsd", "XAdES01903v132-201601.xsd", "ts_119612v020201_201601xsd.xsd", "TS119102-2-v122.xsd",
    ];

    private static readonly Lazy<XmlSchemaSet> s_set = new(Load);

    /// <summary>The schema errors of <paramref name="xml"/>; empty when it is a valid report.</summary>
    public static IReadOnlyList<string> Validate(string xml)
    {
        var errors = new List<string>();
        var settings = new XmlReaderSettings
        {
            ValidationType = ValidationType.Schema,
            Schemas = s_set.Value,
            XmlResolver = null,
            DtdProcessing = DtdProcessing.Prohibit,
        };
        settings.ValidationEventHandler += (_, e) =>
        {
            if (e.Severity == XmlSeverityType.Error && errors.Count < MaxErrors)
            {
                errors.Add(e.Message);
            }
        };

        try
        {
            using var text = new StringReader(xml);
            using var reader = XmlReader.Create(text, settings);
            while (reader.Read())
            {
            }
        }
        catch (XmlException ex)
        {
            errors.Add(ex.Message);
        }

        return errors;
    }

    private static XmlSchemaSet Load()
    {
        var set = new XmlSchemaSet { XmlResolver = null };
        var assembly = typeof(EtsiReportSchema).Assembly;
        foreach (string file in s_files)
        {
            using var stream = assembly.GetManifestResourceStream("SimpleSign.Core.Schemas." + file)
                ?? throw new InvalidOperationException($"The embedded schema {file} is missing.");
            // xmldsig-core-schema.xsd has an internal DTD subset (entities only); the external DTD is not read.
            using var reader = XmlReader.Create(stream, new XmlReaderSettings { DtdProcessing = DtdProcessing.Parse, XmlResolver = null });
            set.Add(null, reader);
        }

        set.Compile();
        return set;
    }
}

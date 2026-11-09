using System.Xml;
using System.Xml.Schema;

namespace SimpleSign.XAdES.Internal;

/// <summary>
/// The XML Signature, XAdES and trusted list schemas embedded in the assembly, for the <c>StructuralValidation</c> and
/// <c>TLStructure</c> constraints. Nothing is fetched: the imports resolve to the schemas already in the set.
/// </summary>
internal static class XmlSchemas
{
    private const int MaxErrors = 20;

    // Imported schemas first: xml.xsd and XML Signature before XAdES and TS 119 612.
    private static readonly string[] s_files =
    [
        "xml.xsd", "xmldsig-core-schema.xsd", "XAdES01903v132-201601.xsd", "XAdES01903v141-201601.xsd", "ts_119612v020201_201601xsd.xsd",
    ];

    private static readonly Lazy<XmlSchemaSet> s_set = new(Load);

    /// <summary>The schema errors of the element and its content; empty when it is valid.</summary>
    public static IReadOnlyList<string> Validate(XmlElement element)
    {
        ArgumentNullException.ThrowIfNull(element);
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
            // The node reader keeps the namespaces declared on the ancestors.
            using var nodes = new XmlNodeReader(element);
            using var reader = XmlReader.Create(nodes, settings);
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
        var assembly = typeof(XmlSchemas).Assembly;
        foreach (string file in s_files)
        {
            using var stream = assembly.GetManifestResourceStream("SimpleSign.XAdES.Schemas." + file)
                ?? throw new InvalidOperationException($"The embedded schema {file} is missing.");
            // xmldsig-core-schema.xsd has an internal DTD subset (entities only); the external DTD is not read.
            using var reader = XmlReader.Create(stream, new XmlReaderSettings { DtdProcessing = DtdProcessing.Parse, XmlResolver = null });
            set.Add(null, reader);
        }

        set.Compile();
        return set;
    }
}

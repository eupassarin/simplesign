using System.Text;
using System.Text.Json;

namespace SimpleSign.Core.Policies;

/// <summary>
/// Writes the JSON Schema (draft 2020-12) of a policy document from <see cref="PolicySchema"/>, the EU DSS
/// <c>policy.xsd</c> turned into JSON: one definition per XSD type, the attributes as properties, the <c>Id</c> and
/// <c>Algo</c> lists as arrays, no other property allowed.
/// </summary>
internal static class PolicyJsonSchema
{
    internal const string BaseUri = "https://raw.githubusercontent.com/eupassarin/SimpleSign/main/docs/schemas/";
    internal const string ValidationUri = BaseUri + "validation-policy.schema.json";
    internal const string SigningUri = BaseUri + "signing-policy.schema.json";

    internal static string Generate(string rootName)
    {
        bool validation = rootName == PolicySchema.ValidationRoot;
        var types = new SortedSet<string>(StringComparer.Ordinal);
        Collect(rootName, types);

        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream, new JsonWriterOptions { Indented = true }))
        {
            writer.WriteStartObject();
            writer.WriteString("$schema", "https://json-schema.org/draft/2020-12/schema");
            writer.WriteString("$id", validation ? ValidationUri : SigningUri);
            writer.WriteString("title", validation ? "SimpleSign validation policy" : "SimpleSign signing policy");
            writer.WriteString("description", validation
                ? "A validation policy in the structure of the EU DSS validation policy (policy.xsd, http://dss.esig.europa.eu/validation/policy), as JSON: one property per element, attributes as properties, the Id and Algo lists as arrays."
                : "The checks SimpleSign makes before signing, with the names of the EU DSS certificate and cryptographic constraints.");
            writer.WriteString("type", "object");
            writer.WriteStartObject("properties");
            writer.WriteStartObject("$schema");
            writer.WriteString("type", "string");
            writer.WriteEndObject();
            writer.WriteStartObject(rootName);
            writer.WriteString("$ref", "#/$defs/" + rootName);
            writer.WriteEndObject();
            writer.WriteEndObject();
            writer.WriteStartArray("required");
            writer.WriteStringValue(rootName);
            writer.WriteEndArray();
            writer.WriteBoolean("additionalProperties", false);

            writer.WriteStartObject("$defs");
            WriteEnum(writer, "Level", ["FAIL", "WARN", "INFORM", "IGNORE"]);
            WriteEnum(writer, "TimeUnit", ["DAYS", "HOURS", "MINUTES", "SECONDS", "MILLISECONDS"]);
            WriteEnum(writer, "Model", ["SHELL", "CHAIN", "HYBRID"]);
            WriteAlgo(writer);
            foreach (string type in types)
            {
                WriteType(writer, PolicySchema.Get(type));
            }

            writer.WriteEndObject();
            writer.WriteEndObject();
        }

        return Encoding.UTF8.GetString(stream.ToArray());
    }

    private static void Collect(string type, SortedSet<string> types)
    {
        if (type == "String" || !types.Add(type))
        {
            return;
        }

        foreach (var (_, child) in PolicySchema.Get(type).Children)
        {
            Collect(child, types);
        }
    }

    private static void WriteType(Utf8JsonWriter writer, PolicyType type)
    {
        writer.WriteStartObject(type.Name);
        writer.WriteString("type", "object");
        writer.WriteStartObject("properties");
        foreach (var (name, kind) in type.Attributes)
        {
            writer.WriteStartObject(name);
            switch (kind)
            {
                case PolicyAttributeKind.Level:
                    writer.WriteString("$ref", "#/$defs/Level");
                    break;
                case PolicyAttributeKind.TimeUnit:
                    writer.WriteString("$ref", "#/$defs/TimeUnit");
                    break;
                case PolicyAttributeKind.Model:
                    writer.WriteString("$ref", "#/$defs/Model");
                    break;
                case PolicyAttributeKind.Int:
                    writer.WriteString("type", "integer");
                    break;
                default:
                    writer.WriteString("type", "string");
                    break;
            }

            writer.WriteEndObject();
        }

        if (type.HasIds)
        {
            writer.WriteStartObject("Id");
            writer.WriteString("type", "array");
            writer.WriteStartObject("items");
            writer.WriteString("type", "string");
            writer.WriteEndObject();
            writer.WriteEndObject();
        }

        if (type.HasAlgorithms)
        {
            writer.WriteStartObject("Algo");
            writer.WriteString("type", "array");
            writer.WriteStartObject("items");
            writer.WriteString("$ref", "#/$defs/Algo");
            writer.WriteEndObject();
            writer.WriteEndObject();
        }

        foreach (var (name, child) in type.Children)
        {
            writer.WriteStartObject(name);
            if (child == "String")
            {
                writer.WriteString("type", "string");
            }
            else
            {
                writer.WriteString("$ref", "#/$defs/" + child);
            }

            writer.WriteEndObject();
        }

        writer.WriteEndObject();
        writer.WriteBoolean("additionalProperties", false);
        writer.WriteEndObject();
    }

    private static void WriteEnum(Utf8JsonWriter writer, string name, string[] values)
    {
        writer.WriteStartObject(name);
        writer.WriteString("type", "string");
        writer.WriteStartArray("enum");
        foreach (string value in values)
        {
            writer.WriteStringValue(value);
        }

        writer.WriteEndArray();
        writer.WriteEndObject();
    }

    private static void WriteAlgo(Utf8JsonWriter writer)
    {
        writer.WriteStartObject("Algo");
        writer.WriteString("description", "An algorithm name, or an object with its name (Value), the key size it is about (Size) and its expiration date (Date).");
        writer.WriteStartArray("oneOf");
        writer.WriteStartObject();
        writer.WriteString("type", "string");
        writer.WriteEndObject();
        writer.WriteStartObject();
        writer.WriteString("type", "object");
        writer.WriteStartObject("properties");
        writer.WriteStartObject("Value");
        writer.WriteString("type", "string");
        writer.WriteEndObject();
        writer.WriteStartObject("Size");
        writer.WriteString("type", "integer");
        writer.WriteEndObject();
        writer.WriteStartObject("Date");
        writer.WriteString("type", "string");
        writer.WriteEndObject();
        writer.WriteEndObject();
        writer.WriteStartArray("required");
        writer.WriteStringValue("Value");
        writer.WriteEndArray();
        writer.WriteBoolean("additionalProperties", false);
        writer.WriteEndObject();
        writer.WriteEndArray();
        writer.WriteEndObject();
    }
}

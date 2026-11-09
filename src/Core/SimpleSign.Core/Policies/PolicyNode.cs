using System.Globalization;
using System.Text.Json;

namespace SimpleSign.Core.Policies;

/// <summary>One element of a policy tree, with its attributes, lists and children, after <see cref="PolicySchema"/>.</summary>
internal sealed class PolicyNode
{
    public PolicyNode(string name, string type)
    {
        Name = name;
        Type = type;
    }

    public string Name { get; }

    public string Type { get; }

    /// <summary>Attribute values: <see cref="ConstraintLevel"/>, <see cref="PolicyTimeUnit"/>, <see cref="int"/> or <see cref="string"/>.</summary>
    public Dictionary<string, object> Attributes { get; } = new(StringComparer.Ordinal);

    public List<string>? Ids { get; set; }

    public List<PolicyAlgorithm>? Algorithms { get; set; }

    /// <summary>The text of a string element (<c>Description</c>).</summary>
    public string? Text { get; set; }

    public List<PolicyNode> Children { get; } = [];

    public PolicyNode? Child(string name) => Children.Find(c => c.Name == name);

    /// <summary>The descendant at <paramref name="path"/> (names separated by <c>/</c>), or null.</summary>
    public PolicyNode? Find(string path)
    {
        var node = this;
        foreach (string part in path.Split('/', StringSplitOptions.RemoveEmptyEntries))
        {
            node = node.Child(part);
            if (node is null)
            {
                return null;
            }
        }

        return node;
    }

    public ConstraintLevel? Level => Attributes.TryGetValue("Level", out var level) ? (ConstraintLevel)level : null;

    public PolicyNode Clone()
    {
        var copy = new PolicyNode(Name, Type)
        {
            Ids = Ids is null ? null : [.. Ids],
            Algorithms = Algorithms is null ? null : [.. Algorithms],
            Text = Text,
        };
        foreach (var (key, value) in Attributes)
        {
            copy.Attributes[key] = value;
        }

        copy.Children.AddRange(Children.Select(c => c.Clone()));
        return copy;
    }

    /// <summary>The element as a public constraint.</summary>
    public PolicyConstraint ToConstraint() => new(Level)
    {
        Ids = Ids is null ? [] : [.. Ids],
        Algorithms = Algorithms is null ? [] : [.. Algorithms],
        Unit = Attributes.TryGetValue("Unit", out var unit) ? (PolicyTimeUnit)unit : null,
        IntValue = Attributes.TryGetValue("Value", out var v) && v is int i ? i
            : Attributes.TryGetValue("value", out var w) && w is int j ? j : null,
        Value = Attributes.TryGetValue("Value", out var s) && s is string text ? text
            : Attributes.TryGetValue("value", out var t) && t is string text2 ? text2 : null,
        Format = Attributes.TryGetValue("Format", out var format) ? (string)format : null,
        UpdateDate = Attributes.TryGetValue("UpdateDate", out var update) ? (string)update : null,
        LevelAfterUpdate = Attributes.TryGetValue("LevelAfterUpdate", out var after) ? (ConstraintLevel)after : null,
    };

    /// <summary>Replaces the attributes and lists with those of <paramref name="constraint"/>, as the schema allows.</summary>
    public void Apply(PolicyConstraint constraint)
    {
        var type = PolicySchema.Get(Type);
        Attributes.Clear();
        foreach (var (name, kind) in type.Attributes)
        {
            object? value = name switch
            {
                "Level" => constraint.Level,
                "LevelAfterUpdate" => constraint.LevelAfterUpdate,
                "Unit" => constraint.Unit,
                "Format" => constraint.Format,
                "UpdateDate" => constraint.UpdateDate,
                "Value" or "value" => kind == PolicyAttributeKind.Int ? constraint.IntValue : constraint.Value,
                _ => null,
            };
            if (value is not null)
            {
                Attributes[name] = value;
            }
        }

        Ids = type.HasIds ? [.. constraint.Ids] : null;
        Algorithms = type.HasAlgorithms ? [.. constraint.Algorithms] : null;
    }

    /// <summary>Sets or removes (<paramref name="constraint"/> null) the element at <paramref name="path"/>, creating the sections on the way.</summary>
    public void Set(string path, PolicyConstraint? constraint)
    {
        string[] parts = path.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length == 0)
        {
            throw new ArgumentException("The path is empty.", nameof(path));
        }

        var node = this;
        for (int i = 0; i < parts.Length; i++)
        {
            string part = parts[i];
            string childType = PolicySchema.Get(node.Type).ChildType(part)
                ?? throw new ArgumentException($"'{part}' is not an element of {node.Type} in the policy schema.", nameof(path));
            var child = node.Child(part);
            bool last = i == parts.Length - 1;
            if (last && constraint is null)
            {
                if (child is not null)
                {
                    node.Children.Remove(child);
                }

                return;
            }

            if (child is null)
            {
                child = new PolicyNode(part, childType);
                node.Insert(child);
            }

            if (last)
            {
                child.Apply(constraint!);
            }

            node = child;
        }
    }

    /// <summary>Adds a child at its place in the schema order.</summary>
    public void Insert(PolicyNode child)
    {
        var order = PolicySchema.Get(Type).Children;
        int rank = IndexOf(order, child.Name);
        int at = Children.FindIndex(c => IndexOf(order, c.Name) > rank);
        Children.Insert(at < 0 ? Children.Count : at, child);
    }

    private static int IndexOf(IReadOnlyList<(string Name, string Type)> order, string name)
    {
        for (int i = 0; i < order.Count; i++)
        {
            if (order[i].Name == name)
            {
                return i;
            }
        }

        return int.MaxValue;
    }
}

/// <summary>
/// Reads and writes a policy tree as JSON. One JSON property per element, attributes as
/// properties of the element's object, the <c>Id</c> and <c>Algo</c> lists as arrays and the text of an
/// <c>Algo</c> as <c>Value</c>. Names outside the schema are refused with their JSON path.
/// </summary>
internal static class PolicyJson
{
    /// <summary>Where a policy written for another validator is told how its names correspond to these.</summary>
    private const string CompatibilityHint =
        " A policy written for another validator must be translated first: see docs/policies/compatibility.md.";

    internal static PolicyNode Read(string json, string rootName)
    {
        using var document = JsonDocument.Parse(json, new JsonDocumentOptions
        {
            CommentHandling = JsonCommentHandling.Skip,
            AllowTrailingCommas = true,
        });
        var root = document.RootElement;
        Expect(root, JsonValueKind.Object, "$");
        PolicyNode? node = null;
        foreach (var property in root.EnumerateObject())
        {
            if (property.Name == "$schema")
            {
                continue;
            }

            if (property.Name != rootName || node is not null)
            {
                throw new FormatException($"$.{property.Name}: expected a single '{rootName}' object.{CompatibilityHint}");
            }

            node = ReadNode(property.Value, rootName, rootName, "$." + rootName);
        }

        return node ?? throw new FormatException($"$: the '{rootName}' object is missing.");
    }

    private static PolicyNode ReadNode(JsonElement element, string name, string typeName, string path)
    {
        var type = PolicySchema.Get(typeName);
        var node = new PolicyNode(name, typeName);
        if (typeName == "String")
        {
            Expect(element, JsonValueKind.String, path);
            node.Text = element.GetString();
            return node;
        }

        Expect(element, JsonValueKind.Object, path);
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var property in element.EnumerateObject())
        {
            string at = path + "." + property.Name;
            if (!seen.Add(property.Name))
            {
                throw new FormatException($"{at}: appears twice.");
            }

            if (type.AttributeKind(property.Name) is { } kind)
            {
                node.Attributes[property.Name] = ReadAttribute(property.Value, kind, at);
            }
            else if (property.Name == "Id" && type.HasIds)
            {
                Expect(property.Value, JsonValueKind.Array, at);
                node.Ids = [.. property.Value.EnumerateArray().Select((e, i) => ReadString(e, $"{at}[{i}]"))];
            }
            else if (property.Name == "Algo" && type.HasAlgorithms)
            {
                Expect(property.Value, JsonValueKind.Array, at);
                node.Algorithms = [.. property.Value.EnumerateArray().Select((e, i) => ReadAlgorithm(e, $"{at}[{i}]"))];
            }
            else if (type.ChildType(property.Name) is { } childType)
            {
                node.Insert(ReadNode(property.Value, property.Name, childType, at));
            }
            else
            {
                throw new FormatException($"{at}: '{property.Name}' is not part of {typeName} in the policy schema.{CompatibilityHint}");
            }
        }

        return node;
    }

    private static object ReadAttribute(JsonElement element, PolicyAttributeKind kind, string path) => kind switch
    {
        PolicyAttributeKind.Level => ParseLevel(ReadString(element, path), path),
        PolicyAttributeKind.TimeUnit => ReadString(element, path).ToUpperInvariant() switch
        {
            "DAYS" => PolicyTimeUnit.Days,
            "HOURS" => PolicyTimeUnit.Hours,
            "MINUTES" => PolicyTimeUnit.Minutes,
            "SECONDS" => PolicyTimeUnit.Seconds,
            "MILLISECONDS" => PolicyTimeUnit.Milliseconds,
            var other => throw new FormatException($"{path}: unknown unit '{other}'; use DAYS, HOURS, MINUTES, SECONDS or MILLISECONDS."),
        },
        PolicyAttributeKind.Model => ReadString(element, path).ToUpperInvariant() switch
        {
            "SHELL" or "CHAIN" or "HYBRID" => element.GetString()!.ToUpperInvariant(),
            var other => throw new FormatException($"{path}: unknown model '{other}'; use SHELL, CHAIN or HYBRID."),
        },
        PolicyAttributeKind.Int => element.ValueKind == JsonValueKind.Number && element.TryGetInt32(out int value)
            ? value
            : throw new FormatException($"{path}: expected an integer."),
        _ => ReadString(element, path),
    };

    private static PolicyAlgorithm ReadAlgorithm(JsonElement element, string path)
    {
        if (element.ValueKind == JsonValueKind.String)
        {
            return new PolicyAlgorithm(element.GetString()!);
        }

        Expect(element, JsonValueKind.Object, path);
        string? name = null;
        int? size = null;
        string? date = null;
        foreach (var property in element.EnumerateObject())
        {
            string at = path + "." + property.Name;
            switch (property.Name)
            {
                case "Value":
                    name = ReadString(property.Value, at);
                    break;
                case "Size":
                    size = (int)ReadAttribute(property.Value, PolicyAttributeKind.Int, at);
                    break;
                case "Date":
                    date = ReadString(property.Value, at);
                    break;
                default:
                    throw new FormatException($"{at}: an Algo has only Value, Size and Date.");
            }
        }

        return new PolicyAlgorithm(name ?? throw new FormatException($"{path}: the Algo has no Value."), size, date);
    }

    internal static ConstraintLevel ParseLevel(string text, string path) => text.ToUpperInvariant() switch
    {
        "FAIL" => ConstraintLevel.Fail,
        "WARN" => ConstraintLevel.Warn,
        "INFORM" => ConstraintLevel.Inform,
        "IGNORE" => ConstraintLevel.Ignore,
        _ => throw new FormatException($"{path}: unknown level '{text}'; use FAIL, WARN, INFORM or IGNORE."),
    };

    internal static string LevelName(ConstraintLevel level) => level switch
    {
        ConstraintLevel.Fail => "FAIL",
        ConstraintLevel.Warn => "WARN",
        ConstraintLevel.Inform => "INFORM",
        _ => "IGNORE",
    };

    private static string ReadString(JsonElement element, string path)
    {
        Expect(element, JsonValueKind.String, path);
        return element.GetString()!;
    }

    private static void Expect(JsonElement element, JsonValueKind kind, string path)
    {
        if (element.ValueKind != kind)
        {
            throw new FormatException($"{path}: expected {(kind == JsonValueKind.Object ? "an object" : kind == JsonValueKind.Array ? "an array" : "a string")}.");
        }
    }

    internal static string Write(PolicyNode root, string? schema)
    {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream, new JsonWriterOptions { Indented = true }))
        {
            writer.WriteStartObject();
            if (schema is not null)
            {
                writer.WriteString("$schema", schema);
            }

            writer.WritePropertyName(root.Name);
            WriteNode(writer, root);
            writer.WriteEndObject();
        }

        return System.Text.Encoding.UTF8.GetString(stream.ToArray());
    }

    private static void WriteNode(Utf8JsonWriter writer, PolicyNode node)
    {
        if (node.Type == "String")
        {
            writer.WriteStringValue(node.Text);
            return;
        }

        var type = PolicySchema.Get(node.Type);
        writer.WriteStartObject();
        foreach (var (name, _) in type.Attributes)
        {
            if (!node.Attributes.TryGetValue(name, out var value))
            {
                continue;
            }

            switch (value)
            {
                case ConstraintLevel level:
                    writer.WriteString(name, LevelName(level));
                    break;
                case PolicyTimeUnit unit:
                    writer.WriteString(name, unit.ToString().ToUpperInvariant());
                    break;
                case int number:
                    writer.WriteNumber(name, number);
                    break;
                default:
                    writer.WriteString(name, Convert.ToString(value, CultureInfo.InvariantCulture));
                    break;
            }
        }

        if (node.Ids is { } ids)
        {
            writer.WriteStartArray("Id");
            foreach (string id in ids)
            {
                writer.WriteStringValue(id);
            }

            writer.WriteEndArray();
        }

        if (node.Algorithms is { } algorithms)
        {
            writer.WriteStartArray("Algo");
            foreach (var algorithm in algorithms)
            {
                if (algorithm.Size is null && algorithm.Date is null)
                {
                    writer.WriteStringValue(algorithm.Name);
                    continue;
                }

                writer.WriteStartObject();
                writer.WriteString("Value", algorithm.Name);
                if (algorithm.Size is { } size)
                {
                    writer.WriteNumber("Size", size);
                }

                if (algorithm.Date is { } date)
                {
                    writer.WriteString("Date", date);
                }

                writer.WriteEndObject();
            }

            writer.WriteEndArray();
        }

        foreach (var child in node.Children)
        {
            writer.WritePropertyName(child.Name);
            WriteNode(writer, child);
        }

        writer.WriteEndObject();
    }
}

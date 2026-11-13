using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SimpleSign.Core.Policies;
using SimpleSign.TestBench.Documents;
using SimpleSign.TestBench.Policies;

namespace SimpleSign.TestBench.Playbooks;

/// <summary>The policies a playbook adjusts (<see cref="Playbook.Policies"/>): built from their base, stored as <c>playbook:ID</c>.</summary>
internal static class PlaybookPolicies
{
    /// <summary>The prefix of a reference to one of them.</summary>
    public const string Prefix = "playbook:";

    /// <summary>The policy file (JSON) of <paramref name="policy"/>: its base with the constraints of <c>set</c> replaced.</summary>
    /// <exception cref="ArgumentException">An unknown kind or base, or a constraint the policy does not have.</exception>
    public static string Build(PlaybookPolicy policy)
    {
        bool signing = policy.Kind == PolicyViewer.Signing;
        if (!signing && policy.Kind != PolicyViewer.Validation)
        {
            throw new ArgumentException($"Unknown kind '{policy.Kind}': use signing or validation.");
        }

        string json = policy.Base == "default"
            ? signing ? SigningPolicy.Default.ToJson() : ValidationPolicy.Default.ToJson()
            : PolicyPresets.Json(policy.Kind, policy.Base) ?? throw new ArgumentException($"Unknown base '{policy.Base}': use default or a built-in {policy.Kind} policy.");
        var root = JsonNode.Parse(json)!.AsObject();
        var constraints = root[signing ? "SigningConstraints" : "ValidationConstraints"]!.AsObject();
        constraints["Name"] = $"{constraints["Name"]} — {policy.Id}";
        if (policy.Set is { ValueKind: JsonValueKind.Object } set)
        {
            foreach (var entry in set.EnumerateObject())
            {
                var parent = constraints;
                string[] path = entry.Name.Split('/');
                foreach (string part in path[..^1])
                {
                    parent = parent[part] as JsonObject ?? throw new ArgumentException($"The policy has no '{entry.Name}'.");
                }

                if (!parent.ContainsKey(path[^1]))
                {
                    throw new ArgumentException($"The policy has no '{entry.Name}'.");
                }

                parent[path[^1]] = JsonNode.Parse(entry.Value.GetRawText());
            }
        }

        string result = root.ToJsonString(new JsonSerializerOptions { WriteIndented = true });
        try
        {
            _ = signing ? SigningPolicy.FromJson(result) : (object)ValidationPolicy.FromJson(result);
        }
        catch (Exception ex) when (ex is JsonException or FormatException or InvalidDataException or ArgumentException)
        {
            throw new ArgumentException($"The adjusted policy is not valid: {ex.Message}", ex);
        }

        return result;
    }

    /// <summary>Stores each policy of <paramref name="playbook"/> as the document <c>playbook:ID</c>; one that does not build is left out (the validator reports it).</summary>
    public static void AddTo(Playbook playbook, DocumentStore documents)
    {
        foreach (var policy in playbook.Policies)
        {
            try
            {
                documents.AddFixed(Prefix + policy.Id, $"{policy.Kind}-policy-{policy.Id}.json", Encoding.UTF8.GetBytes(Build(policy)));
            }
            catch (ArgumentException)
            {
                // Reported by PlaybookValidator.
            }
        }
    }

    /// <summary>Every <c>playbook:ID</c> a JSON value refers to.</summary>
    public static IEnumerable<string> References(JsonElement? element)
    {
        if (element is not { } value)
        {
            yield break;
        }

        switch (value.ValueKind)
        {
            case JsonValueKind.String when value.GetString() is { } text && text.StartsWith(Prefix, StringComparison.Ordinal):
                yield return text[Prefix.Length..];
                break;
            case JsonValueKind.Object:
                foreach (var property in value.EnumerateObject())
                {
                    foreach (string reference in References(property.Value))
                    {
                        yield return reference;
                    }
                }

                break;
            case JsonValueKind.Array:
                foreach (var item in value.EnumerateArray())
                {
                    foreach (string reference in References(item))
                    {
                        yield return reference;
                    }
                }

                break;
        }
    }
}

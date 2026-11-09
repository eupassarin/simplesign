using System.Text.Json;
using Shouldly;
using SimpleSign.Core.Policies;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.Core.Tests.Policies;

[Trait("Category", "Unit")]
public sealed class PolicyJsonSchemaTests
{
    [Theory]
    [InlineData("validation-policy.schema.json", true)]
    [InlineData("signing-policy.schema.json", false)]
    public void GetJsonSchema_MatchesTheFileInDocs(string fileName, bool validation)
    {
        string generated = (validation ? ValidationPolicy.GetJsonSchema() : SigningPolicy.GetJsonSchema()).ReplaceLineEndings("\n") + "\n";
        string path = RepositoryPaths.Get("docs", "schemas", fileName);
        if (Environment.GetEnvironmentVariable("SIMPLESIGN_UPDATE_DOCS") == "1")
        {
            File.WriteAllText(path, generated);
        }

        File.Exists(path).ShouldBeTrue("Run the Core tests once with SIMPLESIGN_UPDATE_DOCS=1 to write docs/schemas.");
        File.ReadAllText(path).ReplaceLineEndings("\n").ShouldBe(generated,
            "The policy schema changed: run the Core tests with SIMPLESIGN_UPDATE_DOCS=1 and commit docs/schemas.");
    }

    [Fact]
    public void GetJsonSchema_DescribesEveryElementOfTheDefaultPolicy()
    {
        using var schema = JsonDocument.Parse(ValidationPolicy.GetJsonSchema());
        var definitions = schema.RootElement.GetProperty("$defs");
        using var policy = JsonDocument.Parse(ValidationPolicy.Default.ToJson());

        Check(policy.RootElement.GetProperty("ValidationConstraints"), definitions.GetProperty("ValidationConstraints"), definitions);
    }

    [Fact]
    public void ToJson_NamesTheSchema()
    {
        using var policy = JsonDocument.Parse(SigningPolicy.Default.ToJson());

        policy.RootElement.GetProperty("$schema").GetString().ShouldEndWith("signing-policy.schema.json");
    }

    /// <summary>Every property of <paramref name="element"/> is declared by <paramref name="definition"/>, recursively.</summary>
    private static void Check(JsonElement element, JsonElement definition, JsonElement definitions)
    {
        var properties = definition.GetProperty("properties");
        foreach (var property in element.EnumerateObject())
        {
            properties.TryGetProperty(property.Name, out var declared).ShouldBeTrue($"'{property.Name}' is not in the schema.");
            if (property.Value.ValueKind == JsonValueKind.Object && declared.TryGetProperty("$ref", out var reference))
            {
                string name = reference.GetString()!["#/$defs/".Length..];
                Check(property.Value, definitions.GetProperty(name), definitions);
            }
        }
    }
}

using System.Text.Json.Serialization;

namespace SimpleSign.Brasil.Signing;

/// <summary>Institution data within the manifest.</summary>
public sealed class ManifestInstitution
{
    /// <summary>Institution name.</summary>
    [JsonPropertyName("name")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Name { get; init; }

    /// <summary>CNPJ (14 digits).</summary>
    [JsonPropertyName("cnpj")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Cnpj { get; init; }
}

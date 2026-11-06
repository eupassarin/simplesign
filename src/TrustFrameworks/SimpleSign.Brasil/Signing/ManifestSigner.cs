using System.Text.Json.Serialization;

namespace SimpleSign.Brasil.Signing;

/// <summary>Signer identity within the manifest.</summary>
public sealed class ManifestSigner
{
    /// <summary>Full name of the signer.</summary>
    [JsonPropertyName("name")]
    public required string Name { get; init; }

    /// <summary>Masked CPF (e.g., "***.456.789-**").</summary>
    [JsonPropertyName("cpf")]
    public required string Cpf { get; init; }

    /// <summary>E-mail address.</summary>
    [JsonPropertyName("email")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Email { get; init; }
}

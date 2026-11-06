using System.Text.Json.Serialization;

namespace SimpleSign.Brasil.Signing;

/// <summary>Authentication evidence within the manifest.</summary>
public sealed class ManifestEvidence
{
    /// <summary>IP address of the signer.</summary>
    [JsonPropertyName("ip")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Ip { get; init; }

    /// <summary>Authentication method used.</summary>
    [JsonPropertyName("authMethod")]
    public required string AuthMethod { get; init; }

    /// <summary>UTC timestamp of the signing act.</summary>
    [JsonPropertyName("timestamp")]
    public DateTimeOffset Timestamp { get; init; }
}

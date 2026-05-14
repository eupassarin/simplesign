using System.Text.Json;
using System.Text.Json.Serialization;
using SimpleSign.Core.Signing;

namespace SimpleSign.Brasil.Signing;

/// <summary>
/// Signature Manifest — structured evidence embedded in the CMS signed attributes
/// as a tamper-proof record of the signing act.
/// Contains signer identity, authentication evidence, and institution data.
/// Serialized as JSON and wrapped in a CMS attribute with OID 2.16.76.1.12.1.1.
/// </summary>
public sealed class SignatureManifest
{
    /// <summary>Manifest version.</summary>
    [JsonPropertyName("v")]
    public int Version { get; init; } = 1;

    /// <summary>Signature type identifier.</summary>
    [JsonPropertyName("type")]
    public string Type { get; init; } = "aea";

    /// <summary>Legal basis.</summary>
    [JsonPropertyName("law")]
    public string Law { get; init; } = "Lei 14.063/2020";

    /// <summary>Signer information.</summary>
    [JsonPropertyName("signer")]
    public required ManifestSigner Signer { get; init; }

    /// <summary>Authentication and evidence data.</summary>
    [JsonPropertyName("evidence")]
    public required ManifestEvidence Evidence { get; init; }

    /// <summary>Issuing institution (optional).</summary>
    [JsonPropertyName("institution")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public ManifestInstitution? Institution { get; init; }

    /// <summary>CAdES commitment type name.</summary>
    [JsonPropertyName("commitment")]
    public string Commitment { get; init; } = "proofOfApproval";

    /// <summary>Builds a manifest from <see cref="AdvancedSignatureInfo"/>.</summary>
    internal static SignatureManifest FromInfo(AdvancedSignatureInfo info)
    {
        ArgumentNullException.ThrowIfNull(info);

        return new SignatureManifest
        {
            Signer = new ManifestSigner
            {
                Name = info.SignerName,
                Cpf = AdvancedSignatureInfo.MaskCpf(info.Cpf),
                Email = info.Email,
            },
            Evidence = new ManifestEvidence
            {
                Ip = info.IpAddress,
                AuthMethod = info.AuthMethod.ToDisplayString(),
                Timestamp = DateTimeOffset.UtcNow,
            },
            Institution = info.InstitutionName is not null || info.InstitutionCnpj is not null
                ? new ManifestInstitution
                {
                    Name = info.InstitutionName,
                    Cnpj = info.InstitutionCnpj,
                }
                : null,
            Commitment = info.CommitmentType switch
            {
                CommitmentType.ProofOfOrigin => "proofOfOrigin",
                CommitmentType.ProofOfApproval => "proofOfApproval",
                _ => "proofOfApproval"
            },
        };
    }

    /// <summary>Serializes to compact JSON (AOT-safe).</summary>
    public byte[] ToJsonUtf8()
    {
        return JsonSerializer.SerializeToUtf8Bytes(this, ManifestJsonContext.Default.SignatureManifest);
    }

    /// <summary>Deserializes from UTF-8 JSON bytes (AOT-safe).</summary>
    public static SignatureManifest? FromJsonUtf8(ReadOnlySpan<byte> utf8Json)
    {
        try
        {
            return JsonSerializer.Deserialize(utf8Json, ManifestJsonContext.Default.SignatureManifest);
        }
        catch (JsonException)
        {
            return null;
        }
    }
}

// ─── AOT-safe JSON source generator ─────────────────────────────────────────

[JsonSourceGenerationOptions(
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(SignatureManifest))]
internal sealed partial class ManifestJsonContext : JsonSerializerContext;

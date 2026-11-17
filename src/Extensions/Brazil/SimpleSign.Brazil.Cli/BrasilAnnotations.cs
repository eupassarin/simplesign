using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;
using SimpleSign.Brazil.Signing;
using SimpleSign.Cli.Extensibility;
using SimpleSign.Core.Validation;

namespace SimpleSign.Brazil.Cli;

/// <summary>
/// What is Brazilian about a signature that <c>validate</c> or <c>inspect</c> shows: the Lei 14.063 level, the data the
/// ICP-Brasil or Gov.br chain validation read, and the signer's manifest of an advanced electronic signature (AEA).
/// </summary>
internal static class BrasilAnnotations
{
    private const string Region = "BR";
    private const string RegistrationPrefix = "BR.Registration.";

    /// <summary>The annotations of <paramref name="signature"/>; none for a signature that is not Brazilian.</summary>
    internal static IReadOnlyList<CliSignatureAnnotation> For(CliSignatureFacts signature)
    {
        var manifest = signature.ManifestJson.IsEmpty ? null : SignatureManifest.FromJsonUtf8(signature.ManifestJson.Span);
        if (signature.Validation is not { } result)
        {
            // inspect: the manifest, in full.
            return manifest is null ? [] : [Manifest(manifest)];
        }

        // Lei 14.063 is Brazilian: only for a signature validated under the Brazilian framework, or one carrying an
        // advanced-signature (AEA) manifest, which is Brazilian too. Classify falls through to Simples for any valid
        // signature, so without this guard a Peruvian (IOFE) one would get a Brazilian level.
        bool brazilianChain = result.ChainValidationRegion == Region;
        if (!brazilianChain && manifest is null)
        {
            return [];
        }

        var annotations = new List<CliSignatureAnnotation>();
        if (manifest is not null)
        {
            annotations.Add(Aea(manifest, signature.CommitmentTypeOid));
        }

        annotations.Add(Brasil(result, signature.ManifestJson.Span, brazilianChain));
        return annotations;
    }

    private static CliSignatureAnnotation Manifest(SignatureManifest manifest)
    {
        var lines = new List<CliAnnotationLine>
        {
            new("Name", manifest.Signer.Name),
            new("CPF", manifest.Signer.Cpf),
        };
        AddIfSet(lines, "Email", manifest.Signer.Email);
        AddIfSet(lines, "IP", manifest.Evidence.Ip);
        lines.Add(new("Authentication", manifest.Evidence.AuthMethod));
        lines.Add(new("Timestamp", manifest.Evidence.Timestamp.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) + " UTC"));
        AddIfSet(lines, "Institution", manifest.Institution?.Name);
        AddIfSet(lines, "CNPJ", manifest.Institution?.Cnpj);
        lines.Add(new("Commitment", manifest.Commitment switch
        {
            "proofOfApproval" => "Approval",
            "proofOfOrigin" => "Authorship",
            _ => manifest.Commitment,
        }));

        return new CliSignatureAnnotation
        {
            Label = "Signature Manifest",
            Value = "Lei 14.063",
            Lines = lines,
            Json = new Dictionary<string, JsonElement>
            {
                ["manifest"] = JsonSerializer.SerializeToElement(new ManifestJson
                {
                    SignerName = manifest.Signer.Name,
                    Cpf = manifest.Signer.Cpf,
                    Email = manifest.Signer.Email,
                    Ip = manifest.Evidence.Ip,
                    AuthMethod = manifest.Evidence.AuthMethod,
                    Timestamp = manifest.Evidence.Timestamp,
                    Institution = manifest.Institution?.Name,
                    Cnpj = manifest.Institution?.Cnpj,
                    Commitment = manifest.Commitment,
                }, BrasilJsonContext.Default.ManifestJson),
            },
        };
    }

    private static CliSignatureAnnotation Aea(SignatureManifest manifest, string? commitmentOid)
    {
        string value = commitmentOid switch
        {
            null => "Lei 14.063",
            "1.2.840.113549.1.9.16.6.1" => "Lei 14.063 (Proof of Origin)",
            "1.2.840.113549.1.9.16.6.5" => "Lei 14.063 (Proof of Approval)",
            _ => $"Lei 14.063 ({commitmentOid})",
        };
        var lines = new List<CliAnnotationLine> { new("CPF", manifest.Signer.Cpf) };
        AddIfSet(lines, "Email", manifest.Signer.Email);
        AddIfSet(lines, "IP", manifest.Evidence.Ip);
        lines.Add(new("Authentication", manifest.Evidence.AuthMethod));
        AddIfSet(lines, "Institution", manifest.Institution?.Name);
        return new CliSignatureAnnotation
        {
            Label = "AEA",
            Value = value,
            Lines = lines,
        };
    }

    private static CliSignatureAnnotation Brasil(SignatureValidationResult result, ReadOnlySpan<byte> manifestJson, bool brazilianChain)
    {
        var level = Lei14063.Classify(result, manifestJson);
        var metadata = result.ChainValidationMetadata ?? new Dictionary<string, string>();
        var registrations = metadata
            .Where(m => m.Key.StartsWith(RegistrationPrefix, StringComparison.Ordinal))
            .ToDictionary(m => m.Key[RegistrationPrefix.Length..], m => m.Value);

        var lines = new List<CliAnnotationLine>();
        if (metadata.TryGetValue("BR.Hierarchy", out string? hierarchy))
        {
            lines.Add(new("Hierarchy", $"{hierarchy} {result.PolicyLevel}".TrimEnd()));
        }

        if (result.SignerId is not null)
        {
            lines.Add(new(result.SignerIdType ?? "ID", result.SignerId));
        }

        if (metadata.TryGetValue("BR.ResponsibleCpf", out string? responsible))
        {
            lines.Add(new("Responsible", $"CPF {responsible}"));
        }

        lines.AddRange(registrations.Select(r => new CliAnnotationLine("Registration", $"{r.Key.ToUpperInvariant()} {r.Value}")));
        if (metadata.TryGetValue("BR.SignaturePolicy", out string? policy))
        {
            lines.Add(new("Policy", $"{policy} {metadata.GetValueOrDefault("BR.SignaturePolicyStatus")}".TrimEnd()));
        }

        if (metadata.TryGetValue("BR.RevocationStatus", out string? revocation))
        {
            lines.Add(new("Revocation", $"{revocation} at {metadata.GetValueOrDefault("BR.ValidationTime", string.Empty)}"));
        }

        var json = new Dictionary<string, JsonElement>();
        if (level is not null)
        {
            json["lei14063"] = JsonSerializer.SerializeToElement(level.Value.ToString(), BrasilJsonContext.Default.String);
        }

        if (brazilianChain)
        {
            json["brasil"] = JsonSerializer.SerializeToElement(new BrasilJson
            {
                Hierarchy = metadata.GetValueOrDefault("BR.Hierarchy"),
                CertificateType = result.PolicyLevel,
                SignerId = result.SignerId,
                SignerIdType = result.SignerIdType,
                SignaturePolicy = metadata.GetValueOrDefault("BR.SignaturePolicy"),
                SignaturePolicyStatus = metadata.GetValueOrDefault("BR.SignaturePolicyStatus"),
                RevocationStatus = metadata.GetValueOrDefault("BR.RevocationStatus"),
                Registrations = registrations,
            }, BrasilJsonContext.Default.BrasilJson);
        }

        return new CliSignatureAnnotation
        {
            Label = "Brasil",
            Value = level is null ? "—" : $"Lei 14.063: {level}",
            Lines = lines,
            Json = json,
        };
    }

    private static void AddIfSet(List<CliAnnotationLine> lines, string name, string? value)
    {
        if (value is not null)
        {
            lines.Add(new(name, value));
        }
    }
}

/// <summary>The <c>brasil</c> property of a validated signature in <c>validate --json</c>.</summary>
internal sealed class BrasilJson
{
    public string? Hierarchy { get; init; }
    public string? CertificateType { get; init; }
    public string? SignerId { get; init; }
    public string? SignerIdType { get; init; }
    public string? SignaturePolicy { get; init; }
    public string? SignaturePolicyStatus { get; init; }
    public string? RevocationStatus { get; init; }
    public Dictionary<string, string> Registrations { get; init; } = [];
}

/// <summary>The <c>manifest</c> property of a signature in <c>inspect --json</c>.</summary>
internal sealed class ManifestJson
{
    public string? SignerName { get; init; }
    public string? Cpf { get; init; }
    public string? Email { get; init; }
    public string? Ip { get; init; }
    public string? AuthMethod { get; init; }
    public DateTimeOffset? Timestamp { get; init; }
    public string? Institution { get; init; }
    public string? Cnpj { get; init; }
    public string? Commitment { get; init; }
}

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase, DefaultIgnoreCondition = JsonIgnoreCondition.Never)]
[JsonSerializable(typeof(BrasilJson))]
[JsonSerializable(typeof(ManifestJson))]
[JsonSerializable(typeof(string))]
[JsonSerializable(typeof(BrasilTimestampVerifyJson))]
internal sealed partial class BrasilJsonContext : JsonSerializerContext;

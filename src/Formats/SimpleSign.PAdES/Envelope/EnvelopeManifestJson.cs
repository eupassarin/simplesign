using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;
using SimpleSign.Core.Signing;

namespace SimpleSign.PAdES.Envelope;

/// <summary>
/// Writes and reads the manifest of an envelope as JSON (ADR 0033, version 1): keys in camel case, the order and the
/// baseline level as text (<c>sequential</c>, <c>B-T</c>), with System.Text.Json source generation (AOT).
/// </summary>
internal static class EnvelopeManifestJson
{
    /// <summary>The manifest as UTF-8 JSON, indented.</summary>
    public static byte[] Serialize(EnvelopeManifest manifest)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        var dto = new ManifestDto
        {
            Version = manifest.Version,
            Id = manifest.Id,
            Title = string.IsNullOrWhiteSpace(manifest.Title) ? null : manifest.Title,
            Order = manifest.Order == EnvelopeOrder.Parallel ? "parallel" : "sequential",
            PreparedAt = manifest.PreparedAt.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture),
            Signers = [.. manifest.Signers.Select(s => new SignerDto
            {
                Field = s.Field,
                Name = s.Name,
                Role = s.Role,
                Email = s.Email,
                External = s.External,
                SignsOutsideField = s.SignsOutsideField ? true : null,
                Identifiers = [.. s.Identifiers.Select(i => new IdentifierDto
                {
                    Type = i.Type,
                    Value = i.Value,
                    AlsoAccept = i.AlsoAccept.Count == 0 ? null : [.. i.AlsoAccept],
                })],
                Level = new LevelDto
                {
                    Id = s.Level.Id,
                    Baseline = BaselineText(s.Level.Baseline),
                    Timestamp = s.Level.Timestamp,
                    SubFilters = s.Level.SubFilters.Count == 0 ? null : [.. s.Level.SubFilters],
                    PolicyOids = s.Level.PolicyOids.Count == 0 ? null : [.. s.Level.PolicyOids],
                },
            })],
        };
        return JsonSerializer.SerializeToUtf8Bytes(dto, EnvelopeJsonContext.Default.ManifestDto);
    }

    /// <summary>Reads a manifest.</summary>
    /// <exception cref="FormatException">It is not a manifest of a version this library reads.</exception>
    public static EnvelopeManifest Parse(ReadOnlySpan<byte> json)
    {
        ManifestDto? dto;
        try
        {
            dto = JsonSerializer.Deserialize(json, EnvelopeJsonContext.Default.ManifestDto);
        }
        catch (JsonException ex)
        {
            throw new FormatException($"The envelope's manifest is not valid JSON: {ex.Message}", ex);
        }

        if (dto is null)
        {
            throw new FormatException("The envelope's manifest is empty.");
        }

        if (dto.Version != EnvelopeManifest.CurrentVersion)
        {
            throw new FormatException($"The envelope's manifest has version {dto.Version}; this library reads version {EnvelopeManifest.CurrentVersion}.");
        }

        if (string.IsNullOrWhiteSpace(dto.Id) || dto.Signers is not { Count: > 0 })
        {
            throw new FormatException("The envelope's manifest has no id or no signer.");
        }

        var signers = new List<EnvelopeManifestSigner>();
        foreach (var s in dto.Signers)
        {
            if (string.IsNullOrWhiteSpace(s.Field) || string.IsNullOrWhiteSpace(s.Name) || s.Level is null || string.IsNullOrWhiteSpace(s.Level.Id))
            {
                throw new FormatException("A signer of the envelope's manifest has no field, name or level.");
            }

            signers.Add(new EnvelopeManifestSigner
            {
                Field = s.Field,
                Name = s.Name,
                Role = s.Role,
                Email = s.Email,
                External = s.External,
                SignsOutsideField = s.SignsOutsideField == true,
                Identifiers = [.. (s.Identifiers ?? []).Select(i => new EnvelopeIdentifier(
                    i.Type ?? throw new FormatException("An identifier of the envelope's manifest has no type."),
                    i.Value ?? throw new FormatException("An identifier of the envelope's manifest has no value."))
                { AlsoAccept = i.AlsoAccept ?? [] })],
                Level = new EnvelopeLevel
                {
                    Id = s.Level.Id,
                    Baseline = ParseBaseline(s.Level.Baseline),
                    Timestamp = s.Level.Timestamp,
                    SubFilters = s.Level.SubFilters ?? [],
                    PolicyOids = s.Level.PolicyOids ?? [],
                },
            });
        }

        return new EnvelopeManifest
        {
            Version = dto.Version,
            Id = dto.Id,
            Title = string.IsNullOrWhiteSpace(dto.Title) ? null : dto.Title,
            Order = dto.Order switch
            {
                "sequential" => EnvelopeOrder.Sequential,
                "parallel" => EnvelopeOrder.Parallel,
                _ => throw new FormatException($"The envelope's manifest has an unknown order '{dto.Order}'."),
            },
            PreparedAt = DateTimeOffset.TryParse(dto.PreparedAt, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var at)
                ? at
                : throw new FormatException("The envelope's manifest has no preparation date."),
            Signers = signers,
        };
    }

    /// <summary>The text of a baseline level: <c>B-B</c>, <c>B-T</c>, <c>B-LT</c>, <c>B-LTA</c>.</summary>
    public static string BaselineText(AdesBaselineLevel level) => level switch
    {
        AdesBaselineLevel.Timestamped => "B-T",
        AdesBaselineLevel.LongTerm => "B-LT",
        AdesBaselineLevel.Archive => "B-LTA",
        _ => "B-B",
    };

    private static AdesBaselineLevel ParseBaseline(string? text) => text switch
    {
        null or "B-B" => AdesBaselineLevel.Basic,
        "B-T" => AdesBaselineLevel.Timestamped,
        "B-LT" => AdesBaselineLevel.LongTerm,
        "B-LTA" => AdesBaselineLevel.Archive,
        _ => throw new FormatException($"The envelope's manifest has an unknown baseline level '{text}'."),
    };
}

internal sealed class ManifestDto
{
    public int Version { get; set; }

    public string? Id { get; set; }

    public string? Title { get; set; }

    public string? Order { get; set; }

    public string? PreparedAt { get; set; }

    public List<SignerDto>? Signers { get; set; }
}

internal sealed class SignerDto
{
    public string? Field { get; set; }

    public string? Name { get; set; }

    public string? Role { get; set; }

    public string? Email { get; set; }

    public bool External { get; set; }

    public bool? SignsOutsideField { get; set; }

    public List<IdentifierDto>? Identifiers { get; set; }

    public LevelDto? Level { get; set; }
}

internal sealed class IdentifierDto
{
    public string? Type { get; set; }

    public string? Value { get; set; }

    public List<string>? AlsoAccept { get; set; }
}

internal sealed class LevelDto
{
    public string? Id { get; set; }

    public string? Baseline { get; set; }

    public bool Timestamp { get; set; }

    public List<string>? SubFilters { get; set; }

    public List<string>? PolicyOids { get; set; }
}

[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    WriteIndented = true,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(ManifestDto))]
internal sealed partial class EnvelopeJsonContext : JsonSerializerContext;

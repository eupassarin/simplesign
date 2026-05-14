using System.Text.Json.Serialization;
using SimpleSign.Core.Inspection;

namespace SimpleSign.Cli.Json;

// ─── Source-generated JSON context (AOT-safe) ────────────────────────

[JsonSourceGenerationOptions(
    WriteIndented = true,
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    DefaultIgnoreCondition = JsonIgnoreCondition.Never)]
[JsonSerializable(typeof(ValidateOutput))]
[JsonSerializable(typeof(InspectOutput))]
internal sealed partial class CliJsonContext : JsonSerializerContext;

// ─── Validate DTOs ───────────────────────────────────────────────────

internal sealed class ValidateOutput
{
    public string File { get; init; } = string.Empty;
    public int SignatureCount { get; init; }
    public List<ValidateSignatureDto> Signatures { get; init; } = [];
}

internal sealed class ValidateSignatureDto
{
    public string FieldName { get; init; } = string.Empty;
    public bool Valid { get; init; }
    public bool IsDocumentTimestamp { get; init; }
    public string? Signer { get; init; }
    public string? Level { get; init; }
    public string? Algorithm { get; init; }
    public bool Integrity { get; init; }
    public bool Signature { get; init; }
    public bool Chain { get; init; }
    public bool Revoked { get; init; }
    public DateTimeOffset? SigningTime { get; init; }
    public List<string> Errors { get; init; } = [];
}

// ─── Inspect DTOs ────────────────────────────────────────────────────

internal sealed class InspectOutput
{
    public string File { get; init; } = string.Empty;
    public InspectDocumentDto Document { get; init; } = new();
    public List<InspectSignatureDto> Signatures { get; init; } = [];
}

internal sealed class InspectDocumentDto
{
    public int SignatureCount { get; init; }
    public bool Encrypted { get; init; }
    public bool DocMdpLocked { get; init; }
    public string PdfA { get; init; } = string.Empty;
    public DssDto? Dss { get; init; }
}

internal sealed class DssDto
{
    public bool Present { get; init; }
    public int Certs { get; init; }
    public int Crls { get; init; }
    public int Ocsps { get; init; }
    public bool Vri { get; init; }
}

internal sealed class InspectSignatureDto
{
    public string FieldName { get; init; } = string.Empty;
    public string? SubFilter { get; init; }
    public bool IsDocumentTimestamp { get; init; }
    public AlgorithmDto DigestAlgorithm { get; init; } = new();
    public AlgorithmDto SignatureAlgorithm { get; init; } = new();
    public DateTimeOffset? SigningTime { get; init; }
    public DateTimeOffset? PdfDeclaredTime { get; init; }
    public bool HasSigningCertificateV2 { get; init; }
    public string? CommitmentType { get; init; }
    public string? SignaturePolicy { get; init; }
    public ManifestDto? Manifest { get; init; }
    public int CmsDataSize { get; init; }
    public string Level { get; init; } = string.Empty;
    public ByteRangeDto ByteRange { get; init; } = new();
    public CertificateDto? Signer { get; init; }
    public TimestampDto? Timestamp { get; init; }
    public List<EmbeddedCertDto> EmbeddedCertificates { get; init; } = [];
}

internal sealed class AlgorithmDto
{
    public string Name { get; init; } = string.Empty;
    public string Oid { get; init; } = string.Empty;

    public static AlgorithmDto From(AlgorithmInfo? info) =>
        info is not null ? new AlgorithmDto { Name = info.Name, Oid = info.Oid } : new AlgorithmDto();
}

internal sealed class ByteRangeDto
{
    public long Offset1 { get; init; }
    public long Length1 { get; init; }
    public long Offset2 { get; init; }
    public long Length2 { get; init; }
    public bool Valid { get; init; }
    public int ContentsLength { get; init; }
}

internal sealed class CertificateDto
{
    public string Subject { get; init; } = string.Empty;
    public string Issuer { get; init; } = string.Empty;
    public string Serial { get; init; } = string.Empty;
    public string Thumbprint { get; init; } = string.Empty;
    public string KeyAlgorithm { get; init; } = string.Empty;
    public int? KeySizeBits { get; init; }
    public DateTime NotBefore { get; init; }
    public DateTime NotAfter { get; init; }
    public bool Expired { get; init; }
    public bool NonRepudiation { get; init; }
    public List<string> KeyUsages { get; init; } = [];
    public List<string> ExtendedKeyUsages { get; init; } = [];
    public string? OcspUrl { get; init; }
    public string? CrlUrl { get; init; }
    public List<string> AiaUrls { get; init; } = [];

    public static CertificateDto From(CertificateInfo c) => new()
    {
        Subject = c.Subject,
        Issuer = c.Issuer,
        Serial = c.SerialNumber,
        Thumbprint = c.Thumbprint,
        KeyAlgorithm = c.KeyAlgorithm,
        KeySizeBits = c.KeySizeBits,
        NotBefore = c.NotBefore,
        NotAfter = c.NotAfter,
        Expired = c.IsExpired,
        NonRepudiation = c.HasNonRepudiation,
        KeyUsages = c.KeyUsages.ToList(),
        ExtendedKeyUsages = c.ExtendedKeyUsages.ToList(),
        OcspUrl = c.OcspUrl,
        CrlUrl = c.CrlUrl,
        AiaUrls = c.AiaUrls.ToList()
    };
}

internal sealed class TimestampDto
{
    public DateTimeOffset Time { get; init; }
    public string? Tsa { get; init; }
    public AlgorithmDto HashAlgorithm { get; init; } = new();
    public string? PolicyOid { get; init; }
    public string? Serial { get; init; }
    public int TokenSize { get; init; }
}

internal sealed class EmbeddedCertDto
{
    public string Subject { get; init; } = string.Empty;
    public string Issuer { get; init; } = string.Empty;
    public string Serial { get; init; } = string.Empty;
    public bool Expired { get; init; }
}

internal sealed class ManifestDto
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

using System.Text.Json.Serialization;
using SimpleSign.HostSigner.Services;

namespace SimpleSign.HostSigner;

internal sealed class CertificateInfo
{
    public string? Name { get; set; }
    public string? Thumbprint { get; set; }
    public string? IssuerName { get; set; }
    public string? NotBefore { get; set; }
    public string? ExpireDate { get; set; }
    public string? SignatureAlgorithm { get; set; }
    public string? HashAlgorithm { get; set; }
    public string? UserCertificateBase64 { get; set; }
}

internal sealed class SignRequest
{
    public string? HashAlgorithm { get; set; }
    public string? SignatureAlgorithm { get; set; }
    public string? Thumbprint { get; set; }
    public List<SignRequestItem>? SignRequests { get; set; }
}

internal sealed class SignRequestItem
{
    public string? Id { get; set; }
    public string? SessionDataBase64 { get; set; }
    public string? AuthenticatedAttributeBase64 { get; set; }
}

internal sealed class SignResult
{
    public string? Id { get; set; }
    public string? SignedHashBase64 { get; set; }
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Error { get; set; }
}

internal sealed class HealthResponse
{
    public string Status { get; set; } = "";
    public string Version { get; set; } = "";
}

internal sealed class ErrorResponse
{
    public string Error { get; set; } = "";
}

internal sealed class VersionInfo
{
    public string Current { get; set; } = "";
    public string? Latest { get; set; }
    public bool UpdateAvailable { get; set; }
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? DownloadUrl { get; set; }
}

internal sealed class SignFileResponse
{
    public string OutputPath { get; set; } = "";
}

internal sealed class ValidateResultDto
{
    public string FieldName { get; set; } = "";
    public bool IsValid { get; set; }
    public bool IsDocumentTimestamp { get; set; }
    public string? SignerName { get; set; }
    public string? Level { get; set; }
    public string? DigestAlgorithm { get; set; }
    public string? SubFilter { get; set; }
    public bool IsIntegrityValid { get; set; }
    public bool IsSignatureValid { get; set; }
    public bool IsCertificateChainValid { get; set; }
    public bool IsNotRevoked { get; set; }
    public bool IsChainTrustWarning { get; set; }
    public bool? HasValidTimestamp { get; set; }
    public DateTimeOffset? SigningTime { get; set; }
    public List<string> Errors { get; set; } = [];
    public List<string> Warnings { get; set; } = [];
}

[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(CertificateInfo))]
[JsonSerializable(typeof(List<CertificateInfo>))]
[JsonSerializable(typeof(SignRequest))]
[JsonSerializable(typeof(SignRequestItem))]
[JsonSerializable(typeof(SignResult))]
[JsonSerializable(typeof(List<SignResult>))]
[JsonSerializable(typeof(HealthResponse))]
[JsonSerializable(typeof(ErrorResponse))]
[JsonSerializable(typeof(VersionInfo))]
[JsonSerializable(typeof(SignFileResponse))]
[JsonSerializable(typeof(InspectResultDto))]
[JsonSerializable(typeof(List<ValidateResultDto>))]
internal sealed partial class HostSignerJsonContext : JsonSerializerContext;

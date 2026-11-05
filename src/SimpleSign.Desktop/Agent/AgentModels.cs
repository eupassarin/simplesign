using System.Text.Json.Serialization;

namespace SimpleSign.Desktop.Agent;

// Same JSON contract as the former SimpleSign.HostSigner, so existing web integrations keep working.

internal sealed class AgentCertificate
{
    public string? Name { get; set; }
    public string? Thumbprint { get; set; }
    public string? IssuerName { get; set; }
    public string? NotBefore { get; set; }
    public string? ExpireDate { get; set; }
    public string? SignatureAlgorithm { get; set; }
    public string? HashAlgorithm { get; set; }
    public string? UserCertificateBase64 { get; set; }

    /// <summary>"store" or "pkcs11" (new).</summary>
    public string? Source { get; set; }

    /// <summary>Token label for PKCS#11 certificates (new).</summary>
    public string? TokenLabel { get; set; }
}

internal sealed class AgentSignRequest
{
    public string? HashAlgorithm { get; set; }
    public string? SignatureAlgorithm { get; set; }
    public string? Thumbprint { get; set; }

    /// <summary>Optional name shown in the consent dialog (new).</summary>
    public string? DocumentName { get; set; }

    public List<AgentSignRequestItem>? SignRequests { get; set; }
}

internal sealed class AgentSignRequestItem
{
    public string? Id { get; set; }
    public string? SessionDataBase64 { get; set; }

    /// <summary>The bytes to sign (DER signed attributes); hashed with HashAlgorithm and signed.</summary>
    public string? AuthenticatedAttributeBase64 { get; set; }
}

internal sealed class AgentSignResult
{
    public string? Id { get; set; }
    public string? SignedHashBase64 { get; set; }
    public string? Error { get; set; }
}

internal sealed class AgentHealth
{
    public string Status { get; set; } = "ok";
    public string Version { get; set; } = "";
    public string App { get; set; } = "SimpleSign Desktop";
}

internal sealed class AgentError
{
    public string Error { get; set; } = "";
}

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase, DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(List<AgentCertificate>))]
[JsonSerializable(typeof(AgentSignRequest))]
[JsonSerializable(typeof(List<AgentSignResult>))]
[JsonSerializable(typeof(AgentHealth))]
[JsonSerializable(typeof(AgentError))]
internal sealed partial class AgentJsonContext : JsonSerializerContext;

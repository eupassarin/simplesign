namespace SimpleSign.Signers.Cloud.Psc;

/// <summary>How hashes and signatures are encoded in the PSC JSON payloads.</summary>
public enum PscBinaryEncoding
{
    /// <summary>Standard base64 (RFC 4648 §4).</summary>
    Base64 = 0,

    /// <summary>Lowercase hexadecimal.</summary>
    Hex = 1,
}

/// <summary>An OAuth scope of the ICP-Brasil PSC API.</summary>
public enum PscScope
{
    /// <summary><c>single_signature</c>: the token signs one hash and is then invalidated.</summary>
    SingleSignature = 0,

    /// <summary><c>multi_signature</c>: the token signs a batch of hashes.</summary>
    MultiSignature = 1,

    /// <summary><c>signature_session</c>: the token signs any number of hashes until it expires (see the lifetime).</summary>
    SignatureSession = 2,
}

/// <summary>
/// Paths and JSON field names of the ICP-Brasil PSC API ("API v0", DOC-ICP-17.01). The defaults
/// follow the ITI specification as published; providers sometimes differ in details, so every
/// name can be overridden without changing code (<c>PscWireFormat.Default with { ... }</c>).
/// </summary>
/// <remarks>
/// The defaults have been validated against SimpleSign's PSC simulator only. Confirm them in
/// each provider's homologation environment before production.
/// </remarks>
public sealed record PscWireFormat
{
    /// <summary>The default format.</summary>
    public static PscWireFormat Default { get; } = new();

    /// <summary>Authorization endpoint (authorization code + PKCE). Default <c>oauth/authorize</c>.</summary>
    public string AuthorizePath { get; init; } = "oauth/authorize";

    /// <summary>Token endpoint. Default <c>oauth/token</c>.</summary>
    public string TokenPath { get; init; } = "oauth/token";

    /// <summary>Password (CPF + OTP) authorization endpoint, offered by some providers. Default <c>oauth/pwd_authorize</c>.</summary>
    public string PasswordAuthorizePath { get; init; } = "oauth/pwd_authorize";

    /// <summary>User discovery endpoint. Default <c>oauth/user-discovery</c>.</summary>
    public string UserDiscoveryPath { get; init; } = "oauth/user-discovery";

    /// <summary>Certificate discovery endpoint. Default <c>oauth/certificate-discovery</c>.</summary>
    public string CertificateDiscoveryPath { get; init; } = "oauth/certificate-discovery";

    /// <summary>Signature endpoint. Default <c>oauth/signature</c>.</summary>
    public string SignaturePath { get; init; } = "oauth/signature";

    /// <summary>Encoding of the hashes sent for signing. Default base64.</summary>
    public PscBinaryEncoding HashEncoding { get; init; } = PscBinaryEncoding.Base64;

    /// <summary>Encoding of the returned signatures. Default base64.</summary>
    public PscBinaryEncoding SignatureEncoding { get; init; } = PscBinaryEncoding.Base64;

    /// <summary>The <c>signature_format</c> value requested. Default <c>RAW</c> (PKCS#1 v1.5 signature over the hash).</summary>
    public string SignatureFormat { get; init; } = "RAW";

    /// <summary>Signature request: certificate alias field. Default <c>certificate_alias</c>.</summary>
    public string CertificateAliasField { get; init; } = "certificate_alias";

    /// <summary>Signature request/response: hash list field. Default <c>hashes</c>.</summary>
    public string HashesField { get; init; } = "hashes";

    /// <summary>Hash entry: identifier field (echoed in the response). Default <c>id</c>.</summary>
    public string HashIdField { get; init; } = "id";

    /// <summary>Hash entry: display alias field. Default <c>alias</c>.</summary>
    public string HashAliasField { get; init; } = "alias";

    /// <summary>Hash entry: hash value field. Default <c>hash</c>.</summary>
    public string HashField { get; init; } = "hash";

    /// <summary>Hash entry: hash algorithm (OID) field. Default <c>hash_algorithm</c>.</summary>
    public string HashAlgorithmField { get; init; } = "hash_algorithm";

    /// <summary>Hash entry: signature format field. Default <c>signature_format</c>.</summary>
    public string SignatureFormatField { get; init; } = "signature_format";

    /// <summary>Signature response: list field. Default <c>signatures</c>.</summary>
    public string SignaturesField { get; init; } = "signatures";

    /// <summary>Signature response entry: signature value field. Default <c>raw_signature</c>.</summary>
    public string SignatureField { get; init; } = "raw_signature";

    /// <summary>Certificate discovery response: list field. Default <c>certificates</c>.</summary>
    public string CertificatesField { get; init; } = "certificates";

    /// <summary>Certificate discovery entry: alias field. Default <c>alias</c>.</summary>
    public string CertificateAliasEntryField { get; init; } = "alias";

    /// <summary>Certificate discovery entry: certificate (base64 DER or PEM) field. Default <c>certificate</c>.</summary>
    public string CertificateField { get; init; } = "certificate";

    /// <summary>The wire name of a scope.</summary>
    internal static string ScopeName(PscScope scope) => scope switch
    {
        PscScope.SingleSignature => "single_signature",
        PscScope.MultiSignature => "multi_signature",
        _ => "signature_session",
    };
}

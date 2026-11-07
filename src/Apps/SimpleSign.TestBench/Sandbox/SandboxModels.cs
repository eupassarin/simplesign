using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Serialization;

namespace SimpleSign.TestBench.Sandbox;

// What the TestBench reads from a SimpleSign Sandbox (src/Apps/SimpleSign.Sandbox): the JSON of its
// /api/info and /api/pki, and the failures of /api/faults. Kept apart from the Sandbox's own types
// so the two apps only share the HTTP contract.

/// <summary>The Sandbox's /api/info.</summary>
public sealed record SandboxInfo(
    string Name,
    string Version,
    string BaseUrl,
    string HttpsBaseUrl,
    string LdapBaseUrl,
    string RootThumbprint,
    string RootSubject,
    SandboxTsaInfo Tsa,
    SandboxCscInfo Csc,
    string PfxPassword,
    IReadOnlyList<string> LoopbackOrigins);

public sealed record SandboxTsaInfo(string Url, string AuthenticatedUrl, string UntrustedUrl, string RevokedUrl, string WrongNameUrl, string User, string Password);

public sealed record SandboxCscInfo(string BaseUrl, string ClientId, string ClientSecret, string ServiceToken, string Pin, string Otp, IReadOnlyList<SandboxCscCredential> Credentials);

public sealed record SandboxCscCredential(string Id, string Description, string CertificateId, string AuthMode, string Scal, int MultiSign);

/// <summary>One certificate of the Sandbox's /api/pki.</summary>
public sealed record SandboxCertificateInfo(
    string Id,
    string Title,
    string Description,
    string? IssuerId,
    string? KeyType,
    string? Usage,
    string? Pointers,
    string? Problem,
    string? Evidence,
    bool IsUsable,
    DateTimeOffset? RevokedAt);

/// <summary>The Sandbox's /api/pki: the CAs and the certificates.</summary>
public sealed record SandboxPkiInfo(IReadOnlyList<SandboxCertificateInfo> Authorities, IReadOnlyList<SandboxCertificateInfo> Certificates);

/// <summary>A signer of the connected Sandbox, with its private key and its chain (from its PKCS#12).</summary>
internal sealed record SandboxSigner(
    string Id,
    string Title,
    string Description,
    string KeyType,
    X509Certificate2 Certificate,
    IReadOnlyList<X509Certificate2> Chain,
    bool IsUsable,
    string? Problem,
    string? Evidence);

[JsonConverter(typeof(JsonStringEnumConverter<TsaFault>))]
public enum TsaFault
{
    None,
    Down,
    Slow,
    InvalidToken,
    Untrusted,
}

[JsonConverter(typeof(JsonStringEnumConverter<CrlFault>))]
public enum CrlFault
{
    None,
    Down,
    Slow,
    Expired,
    WrongKey,
    Stale,
}

[JsonConverter(typeof(JsonStringEnumConverter<OcspFault>))]
public enum OcspFault
{
    None,
    Down,
    Slow,
    TryLater,
    Expired,
    Unauthorized,
    Unknown,
}

/// <summary>The failures of a Sandbox (its /api/faults).</summary>
public sealed record SandboxFaults(
    TsaFault Tsa = TsaFault.None,
    int TsaDelayMs = 3000,
    CrlFault Crl = CrlFault.None,
    int CrlDelayMs = 3000,
    OcspFault Ocsp = OcspFault.None,
    int OcspDelayMs = 3000)
{
    /// <summary>Whether any failure is on.</summary>
    public bool Any => Tsa != TsaFault.None || Crl != CrlFault.None || Ocsp != OcspFault.None;
}

/// <summary>No Sandbox is connected, and the option or sample needs one.</summary>
public sealed class SandboxNotConnectedException()
    : InvalidOperationException("No SimpleSign Sandbox is connected. Start one (dotnet run --project src/Apps/SimpleSign.Sandbox) and connect it in Environment.");

using System.Text.Json.Serialization;
using SimpleSign.Sandbox.Services;

namespace SimpleSign.Sandbox.Pki;

/// <summary>A certificate and its private key, as PEM (PKCS#8 for the key).</summary>
internal sealed record StoredKeyPair(string Certificate, string Key);

/// <summary>Where a certificate's revocation status can be asked: the pointers written into it.</summary>
[Flags]
[JsonConverter(typeof(JsonStringEnumConverter<RevocationPointers>))]
public enum RevocationPointers
{
    None = 0,

    /// <summary>A CRL distribution point over HTTP.</summary>
    CrlHttp = 1,

    /// <summary>A CRL distribution point over HTTPS.</summary>
    CrlHttps = 2,

    /// <summary>A CRL distribution point over LDAP.</summary>
    CrlLdap = 4,

    /// <summary>An OCSP responder in the Authority Information Access.</summary>
    Ocsp = 8,
}

/// <summary>Where a revocation is published.</summary>
public enum RevocationPublication
{
    /// <summary>In the CRL and by the OCSP responder.</summary>
    Both,

    /// <summary>In the CRL only: the OCSP responder still answers good.</summary>
    CrlOnly,

    /// <summary>By the OCSP responder only: the CRL does not list it.</summary>
    OcspOnly,
}

/// <summary>What a certificate is for.</summary>
public enum CertificateUsage
{
    /// <summary>Signing documents (clientAuth, emailProtection).</summary>
    Signing,

    /// <summary>A TSA (critical timeStamping EKU).</summary>
    Timestamping,

    /// <summary>A delegated OCSP responder (OCSPSigning EKU, id-pkix-ocsp-nocheck).</summary>
    OcspSigning,

    /// <summary>The TLS server of the HTTPS endpoint (serverAuth).</summary>
    TlsServer,
}

/// <summary>A CA of the environment.</summary>
internal sealed record StoredAuthority
{
    public required string Id { get; init; }

    public required string Title { get; init; }

    public required StoredKeyPair Pair { get; init; }

    /// <summary>The id of the issuing CA; null for the root.</summary>
    public string? IssuerId { get; init; }

    public string? Problem { get; init; }

    public DateTimeOffset? RevokedAt { get; init; }

    public string? RevocationReason { get; init; }
}

/// <summary>A certificate the environment issued, with its revocation.</summary>
internal sealed record StoredCertificate
{
    public required string Id { get; init; }

    public required string Title { get; init; }

    public required string Description { get; init; }

    public required SandboxKeyType KeyType { get; init; }

    public required StoredKeyPair Pair { get; init; }

    /// <summary>The issuing CA.</summary>
    public string IssuerId { get; init; } = SandboxPki.IntermediateId;

    public CertificateUsage Usage { get; init; }

    public RevocationPointers Pointers { get; init; } = RevocationPointers.CrlHttp | RevocationPointers.Ocsp;

    /// <summary>What it demonstrates when signing is expected to be refused (Expired, Revoked…).</summary>
    public string? Problem { get; init; }


    /// <summary>Whether it is revoked when the environment is reset (the "revoked" signers).</summary>
    public bool RevokedByDefault { get; init; }

    /// <summary>A digest of the seed it was issued from: a seed that changed is issued again.</summary>
    public string? Profile { get; init; }

    public DateTimeOffset? RevokedAt { get; init; }

    public string? RevocationReason { get; init; }

    public RevocationPublication Publication { get; init; }
}

/// <summary>Everything an environment keeps between runs (state.json in its folder).</summary>
internal sealed record SandboxState
{
    public const int CurrentVersion = 2;

    public int Version { get; init; } = CurrentVersion;

    public required string Name { get; init; }

    /// <summary>The URL written into the certificates (CRL distribution points, AIA, OCSP).</summary>
    public required Uri BaseUrl { get; init; }

    /// <summary>The HTTPS URL of the certificates whose CRL is published over HTTPS.</summary>
    public required Uri HttpsBaseUrl { get; init; }

    /// <summary>The LDAP URL of the certificates whose CRL is published over LDAP.</summary>
    public required Uri LdapBaseUrl { get; init; }

    public required DateTimeOffset CreatedAt { get; init; }

    /// <summary>The CAs: root, intermediate, a revoked intermediate, an expired one and one the root signed with SHA-1.</summary>
    public required List<StoredAuthority> Authorities { get; init; }

    /// <summary>A TSA under its own self-signed CA, outside every trust anchor.</summary>
    public required StoredKeyPair UntrustedTsa { get; init; }

    /// <summary>A self-signed OCSP responder no CA authorized (the "unauthorized responder" failure).</summary>
    public required StoredKeyPair RogueOcspResponder { get; init; }

    /// <summary>The scheme operator that signs the Sandbox's list of trusted lists (LOTL); created on first use.</summary>
    public StoredKeyPair? LotlSigner { get; init; }

    /// <summary>The scheme operator that signs the Sandbox's trusted list (TL); created on first use.</summary>
    public StoredKeyPair? TlSigner { get; init; }

    public List<StoredCertificate> Certificates { get; init; } = [];

    public long CrlNumber { get; init; } = 1;

    public long NextSerial { get; init; } = 0x1000;

    public SandboxFaults Faults { get; init; } = new();
}

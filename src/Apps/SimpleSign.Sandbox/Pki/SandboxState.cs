using SimpleSign.Sandbox.Services;

namespace SimpleSign.Sandbox.Pki;

/// <summary>A certificate and its private key, as PEM (PKCS#8 for the key).</summary>
internal sealed record StoredKeyPair(string Certificate, string Key);

/// <summary>A certificate the environment issued, with its revocation.</summary>
internal sealed record StoredCertificate
{
    public required string Id { get; init; }

    public required string Title { get; init; }

    public required string Description { get; init; }

    public required SandboxKeyType KeyType { get; init; }

    public required StoredKeyPair Pair { get; init; }

    /// <summary>What it demonstrates when signing is expected to be refused (Expired, Revoked…).</summary>
    public string? Problem { get; init; }

    /// <summary>Whether it is revoked when the environment is reset (the "revoked" signer).</summary>
    public bool RevokedByDefault { get; init; }

    public DateTimeOffset? RevokedAt { get; init; }

    public string? RevocationReason { get; init; }
}

/// <summary>Everything an environment keeps between runs (state.json in its folder).</summary>
internal sealed record SandboxState
{
    public const int CurrentVersion = 1;

    public int Version { get; init; } = CurrentVersion;

    public required string Name { get; init; }

    /// <summary>The URL written into the certificates (CRL distribution points, AIA).</summary>
    public required Uri BaseUrl { get; init; }

    public required DateTimeOffset CreatedAt { get; init; }

    public required StoredKeyPair Root { get; init; }

    public required StoredKeyPair Intermediate { get; init; }

    public required StoredKeyPair Tsa { get; init; }

    /// <summary>A TSA under its own self-signed CA, outside every trust anchor.</summary>
    public required StoredKeyPair UntrustedTsa { get; init; }

    public List<StoredCertificate> Certificates { get; init; } = [];

    public long CrlNumber { get; init; } = 1;

    public long NextSerial { get; init; } = 0x1000;

    public SandboxFaults Faults { get; init; } = new();
}

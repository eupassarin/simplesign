using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SimpleSign.Core.Signing;
using SimpleSign.TestBench.Signing;

namespace SimpleSign.TestBench.Credentials;

public enum CredentialKind
{
    /// <summary>A sandbox A1 certificate (private key in memory).</summary>
    SandboxA1,

    /// <summary>A PFX/P12 file (A1).</summary>
    Pfx,

    /// <summary>The OS certificate store (Windows store, macOS keychain).</summary>
    OsStore,

    /// <summary>An A3 token or smartcard through its PKCS#11 driver.</summary>
    Pkcs11,

    /// <summary>A Cloud Signature Consortium API v2 credential.</summary>
    Csc,
}

/// <summary>What a credential can do; the Crypto step only offers these.</summary>
public sealed record CredentialFacts(
    string Id,
    CredentialKind Kind,
    string Source,
    string Holder,
    string Subject,
    string Issuer,
    string KeyAlgorithm,
    int KeySize,
    string NotBefore,
    string NotAfter,
    bool IsExpired,
    bool IsNotYetValid,
    bool HasNonRepudiation,
    IReadOnlyList<HashChoice> Hashes,
    IReadOnlyList<RsaPadding> Paddings,
    bool CanSignHashLocally,
    IReadOnlyList<string> Notes,
    string CertificateBase64)
{
    /// <summary>Whether the key usage allows signatures (digitalSignature or nonRepudiation); false when it has no key usage.</summary>
    public bool HasSigningKeyUsage { get; init; } = true;
}

/// <summary>A note in English with its arguments, translated each time it is shown.</summary>
public sealed record Note(string English, params object?[] Args)
{
    public static implicit operator Note(string english) => new(english);

    public override string ToString() => Localization.L.T(English, Args);
}

/// <summary>A credential as the CLI takes it: a PKCS#12 file and its password (kept in memory only).</summary>
internal sealed record CliSigner(byte[] Pfx, string Password);

/// <summary>An opened signing credential: a local key, or an <see cref="IExternalSigner"/> (token, CSC).</summary>
internal sealed class CredentialHandle : IDisposable
{
    private readonly IDisposable? _owned;
    private readonly CredentialFacts _facts;

    public CredentialHandle(CredentialKind kind, string source, X509Certificate2 certificate, IReadOnlyList<X509Certificate2> chain,
        IExternalSigner? external, IDisposable? owned, IReadOnlyList<HashChoice>? hashes = null, IReadOnlyList<RsaPadding>? paddings = null,
        IReadOnlyList<Note>? notes = null)
    {
        Id = Guid.NewGuid().ToString("N")[..12];
        Kind = kind;
        Certificate = certificate;
        Chain = chain;
        External = external;
        _owned = owned;
        Notes = notes ?? [];
        _facts = BuildFacts(Id, kind, source, certificate, external is null, hashes, paddings);
    }

    public string Id { get; }

    public CredentialKind Kind { get; }

    public X509Certificate2 Certificate { get; }

    public IReadOnlyList<X509Certificate2> Chain { get; }

    public IExternalSigner? External { get; }

    /// <summary>The PKCS#12 and password a CLI run passes to <c>simplesign</c>; null when the CLI cannot use this credential.</summary>
    public CliSigner? Cli { get; init; }

    /// <summary>The notes in English (for the localization tests).</summary>
    internal IReadOnlyList<Note> Notes { get; }

    /// <summary>The facts, with the notes in the current UI language.</summary>
    public CredentialFacts Facts => _facts with { Notes = [.. Notes.Select(n => n.ToString())] };

    public DateTimeOffset LastUsed { get; set; } = DateTimeOffset.UtcNow;

    public void Dispose() => _owned?.Dispose();

    /// <summary>Hash algorithms the runtime can compute (SHA-3 needs OpenSSL 1.1.1+ / Windows 11).</summary>
    public static IReadOnlyList<HashChoice> LocalHashes() =>
        SHA3_256.IsSupported
            ? [HashChoice.Sha256, HashChoice.Sha384, HashChoice.Sha512, HashChoice.Sha3_256, HashChoice.Sha3_384, HashChoice.Sha3_512]
            : [HashChoice.Sha256, HashChoice.Sha384, HashChoice.Sha512];

    private static CredentialFacts BuildFacts(string id, CredentialKind kind, string source, X509Certificate2 certificate, bool local,
        IReadOnlyList<HashChoice>? hashes, IReadOnlyList<RsaPadding>? paddings)
    {
        bool isRsa = certificate.GetRSAPublicKey() is not null;
        int keySize;
        if (isRsa)
        {
            using var rsa = certificate.GetRSAPublicKey()!;
            keySize = rsa.KeySize;
        }
        else
        {
            using var ec = certificate.GetECDsaPublicKey();
            keySize = ec?.KeySize ?? 0;
        }

        var usage = certificate.Extensions.OfType<X509KeyUsageExtension>().FirstOrDefault();
        var now = DateTime.Now;
        return new CredentialFacts(
            id, kind, source,
            certificate.GetNameInfo(X509NameType.SimpleName, false),
            certificate.Subject,
            certificate.Issuer,
            isRsa ? "RSA" : certificate.GetECDsaPublicKey() is not null ? "ECDSA" : certificate.PublicKey.Oid.FriendlyName ?? "?",
            keySize,
            certificate.NotBefore.ToString("yyyy-MM-dd HH:mm", System.Globalization.CultureInfo.InvariantCulture),
            certificate.NotAfter.ToString("yyyy-MM-dd HH:mm", System.Globalization.CultureInfo.InvariantCulture),
            certificate.NotAfter < now,
            certificate.NotBefore > now,
            usage is null || usage.KeyUsages.HasFlag(X509KeyUsageFlags.NonRepudiation),
            hashes ?? LocalHashes(),
            isRsa ? paddings ?? [RsaPadding.Pkcs1, RsaPadding.Pss] : [],
            local,
            [],
            Convert.ToBase64String(certificate.RawData))
        {
            HasSigningKeyUsage = usage is not null
                && (usage.KeyUsages & (X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation)) != 0,
        };
    }
}

/// <summary>Opened credentials, by id. Token sessions and cloud authorizations live here until closed.</summary>
internal sealed class CredentialStore : IDisposable
{
    private readonly ConcurrentDictionary<string, CredentialHandle> _handles = new(StringComparer.Ordinal);

    public CredentialHandle Add(CredentialHandle handle)
    {
        _handles[handle.Id] = handle;
        // Keep the store small: close credentials unused for an hour.
        foreach (var stale in _handles.Values.Where(h => h.LastUsed < DateTimeOffset.UtcNow.AddHours(-1)).ToList())
        {
            Remove(stale.Id);
        }

        return handle;
    }

    public CredentialHandle Get(string id)
    {
        if (!_handles.TryGetValue(id, out var handle))
        {
            throw new KeyNotFoundException("The credential is no longer open. Choose the signer again.");
        }

        handle.LastUsed = DateTimeOffset.UtcNow;
        return handle;
    }

    public bool TryGet(string? id, out CredentialHandle? handle)
    {
        handle = null;
        return id is not null && _handles.TryGetValue(id, out handle);
    }

    public void Remove(string id)
    {
        if (_handles.TryRemove(id, out var handle))
        {
            handle.Dispose();
        }
    }

    public void Dispose()
    {
        foreach (var handle in _handles.Values)
        {
            handle.Dispose();
        }

        _handles.Clear();
    }
}

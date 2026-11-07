using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Serialization;
using SimpleSign.Sandbox.Services;

namespace SimpleSign.Sandbox.Pki;

/// <summary>Key type of an issued certificate.</summary>
public enum SandboxKeyType
{
    Rsa1024,
    Rsa2048,
    Rsa3072,
    Rsa4096,
    EcdsaP256,
    EcdsaP384,
    EcdsaP521,
}

/// <summary>A certificate the Sandbox issued (with its private key) and what it demonstrates.</summary>
internal sealed record SandboxCertificate(
    string Id,
    string Title,
    string Description,
    SandboxKeyType KeyType,
    X509Certificate2 Certificate,
    string? Problem,
    DateTimeOffset? RevokedAt,
    string? RevocationReason)
{
    /// <summary>Whether a correct client signs with it (a missing nonRepudiation only gives a warning).</summary>
    public bool IsUsable => (Problem is null || Problem == "No non-repudiation") && RevokedAt is null;
}

/// <summary>
/// The test PKI of one Sandbox environment: a root, an intermediate CA, a TSA and the signers
/// that cover every key type plus the edge cases (expired, not yet valid, revoked, no
/// non-repudiation, weak key, no signing key usage). Kept in the environment's folder, so a
/// client told to trust the root keeps trusting it. Certificates point to this Sandbox's
/// public URL for their CRLs and issuer certificates.
/// </summary>
internal sealed class SandboxPki : IDisposable
{
    /// <summary>The password of every PKCS#12 file the Sandbox hands out.</summary>
    public const string PfxPassword = "sandbox";

    private static readonly JsonSerializerOptions s_json = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() },
    };

    private readonly Lock _gate = new();
    private readonly string? _statePath;
    private readonly List<IDisposable> _owned = [];
    private readonly RSA _rootKey;
    private readonly RSA _intermediateKey;
    private SandboxState _state;
    private List<SandboxCertificate> _certificates = [];
    private byte[] _rootCrl = [];
    private byte[] _intermediateCrl = [];
    private DateTimeOffset _crlsBuiltAt;

    private SandboxPki(SandboxState state, string? statePath)
    {
        _state = state;
        _statePath = statePath;
        Root = Load(state.Root, out var rootKey);
        _rootKey = (RSA)rootKey;
        Intermediate = Load(state.Intermediate, out var intermediateKey);
        _intermediateKey = (RSA)intermediateKey;
        Tsa = Load(state.Tsa, out var tsaKey);
        TsaKey = (RSA)tsaKey;
        UntrustedTsa = Load(state.UntrustedTsa, out var untrustedKey);
        UntrustedTsaKey = (RSA)untrustedKey;
    }

    public string Name => _state.Name;

    /// <summary>The URL written into the certificates.</summary>
    public Uri BaseUrl => _state.BaseUrl;

    public DateTimeOffset CreatedAt => _state.CreatedAt;

    public X509Certificate2 Root { get; }

    public X509Certificate2 Intermediate { get; }

    public X509Certificate2 Tsa { get; }

    public RSA TsaKey { get; }

    public X509Certificate2 UntrustedTsa { get; }

    public RSA UntrustedTsaKey { get; }

    /// <summary>The certificates a validator needs besides the signer (intermediate and root).</summary>
    public IReadOnlyList<X509Certificate2> Chain => [Intermediate, Root];

    public Uri RootCrlUrl => new(BaseUrl, "crl/root.crl");

    public Uri IntermediateCrlUrl => new(BaseUrl, "crl/intermediate.crl");

    public Uri RootCertificateUrl => new(BaseUrl, "aia/root.cer");

    public Uri IntermediateCertificateUrl => new(BaseUrl, "aia/intermediate.cer");

    public IReadOnlyList<SandboxCertificate> Certificates
    {
        get
        {
            lock (_gate)
            {
                return [.. _certificates];
            }
        }
    }

    /// <summary>The failures switched on (kept with the environment).</summary>
    public SandboxFaults Faults
    {
        get
        {
            lock (_gate)
            {
                return _state.Faults;
            }
        }

        set
        {
            lock (_gate)
            {
                _state = _state with { Faults = value.Clamped() };
                Save();
            }
        }
    }

    /// <summary>Opens the environment in <paramref name="directory"/>, creating it the first time.</summary>
    /// <param name="directory">The environment's folder; null keeps everything in memory.</param>
    /// <param name="name">The environment's name (in the CA names).</param>
    /// <param name="baseUrl">The URL for new certificates. An existing environment keeps its own.</param>
    /// <param name="logger">Where to report an environment whose URL differs from <paramref name="baseUrl"/>.</param>
    public static SandboxPki Open(string? directory, string name, Uri baseUrl, ILogger? logger = null)
    {
        ArgumentNullException.ThrowIfNull(baseUrl);
        string? path = directory is null ? null : Path.Combine(directory, "state.json");
        SandboxState? state = null;
        if (path is not null && File.Exists(path))
        {
            state = JsonSerializer.Deserialize<SandboxState>(File.ReadAllText(path), s_json);
            if (state is { Version: not SandboxState.CurrentVersion })
            {
                throw new InvalidOperationException($"{path} was written by another version of the Sandbox ({state.Version}); remove the folder to start over.");
            }
        }

        bool created = state is null;
        state ??= Create(name, baseUrl);
        if (!created && state.BaseUrl != baseUrl)
        {
            logger?.LogWarning("The environment '{Name}' was created for {Stored}; its certificates keep pointing there (asked: {Asked}).", state.Name, state.BaseUrl, baseUrl);
        }

        var pki = new SandboxPki(state, path);
        pki.Seed();
        return pki;
    }

    /// <summary>A certificate by id.</summary>
    public SandboxCertificate Certificate(string id) =>
        Certificates.FirstOrDefault(c => c.Id == id) ?? throw new KeyNotFoundException($"No certificate '{id}'.");

    /// <summary>The certificate and its key as a PKCS#12 file (password <see cref="PfxPassword"/>), with the chain.</summary>
    public byte[] Pfx(string id)
    {
        var certificate = Certificate(id);
        var collection = new X509Certificate2Collection { certificate.Certificate, Intermediate, Root };
        return collection.Export(X509ContentType.Pkcs12, PfxPassword)!;
    }

    /// <summary>Revokes a certificate now: the intermediate CA publishes a new CRL at once.</summary>
    public void Revoke(string id, string? reason = null)
    {
        lock (_gate)
        {
            Update(id, c => c with { RevokedAt = DateTimeOffset.UtcNow, RevocationReason = reason ?? nameof(X509RevocationReason.KeyCompromise) });
        }
    }

    /// <summary>Takes a revocation back (a test convenience: real CAs cannot).</summary>
    public void Unrevoke(string id)
    {
        lock (_gate)
        {
            Update(id, c => c with { RevokedAt = null, RevocationReason = null });
        }
    }

    /// <summary>Puts every revocation and failure back as they are in a new environment.</summary>
    public void Reset()
    {
        lock (_gate)
        {
            var revokedAt = _state.CreatedAt.AddHours(-1);
            _state = _state with
            {
                Faults = new SandboxFaults(),
                Certificates = [.. _state.Certificates.Select(c => c with
                {
                    RevokedAt = c.RevokedByDefault ? revokedAt : null,
                    RevocationReason = c.RevokedByDefault ? nameof(X509RevocationReason.KeyCompromise) : null,
                })],
            };
            Republish();
        }
    }

    /// <summary>The root CA's CRL.</summary>
    public byte[] RootCrl
    {
        get
        {
            lock (_gate)
            {
                RefreshCrls();
                return _rootCrl;
            }
        }
    }

    /// <summary>The intermediate CA's CRL, with every revoked certificate.</summary>
    public byte[] IntermediateCrl
    {
        get
        {
            lock (_gate)
            {
                RefreshCrls();
                return _intermediateCrl;
            }
        }
    }

    /// <summary>The CRLs as they would be after their nextUpdate has passed (the "expired CRL" failure).</summary>
    public (byte[] Root, byte[] Intermediate) ExpiredCrls()
    {
        lock (_gate)
        {
            return (BuildCrl(Root, _rootKey, [], _state.CrlNumber, expired: true),
                BuildCrl(Intermediate, _intermediateKey, RevokedEntries(), _state.CrlNumber, expired: true));
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            foreach (var owned in _owned)
            {
                owned.Dispose();
            }

            foreach (var certificate in _certificates)
            {
                certificate.Certificate.Dispose();
            }
        }
    }

    // ── Creation ──────────────────────────────────────────────────────

    private static SandboxState Create(string name, Uri baseUrl)
    {
        var now = DateTimeOffset.UtcNow;
        long serial = 0x1000;
        byte[] NextSerial() => SerialBytes(++serial);

        using var rootKey = RSA.Create(3072);
        using var root = CaRequest($"CN=SimpleSign Sandbox Root CA ({name}), O=SimpleSign Sandbox", rootKey, pathLength: 1)
            .CreateSelfSigned(now.AddYears(-1), now.AddYears(25));

        using var intermediateKey = RSA.Create(2048);
        var intermediateRequest = CaRequest($"CN=SimpleSign Sandbox CA 1 ({name}), O=SimpleSign Sandbox", intermediateKey, pathLength: 0);
        intermediateRequest.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(root, true, false));
        intermediateRequest.CertificateExtensions.Add(CertificateRevocationListBuilder.BuildCrlDistributionPointExtension([new Uri(baseUrl, "crl/root.crl").AbsoluteUri]));
        intermediateRequest.CertificateExtensions.Add(new X509AuthorityInformationAccessExtension(null, [new Uri(baseUrl, "aia/root.cer").AbsoluteUri]));
        using var intermediate = intermediateRequest.Create(root.SubjectName, X509SignatureGenerator.CreateForRSA(rootKey, RSASignaturePadding.Pkcs1),
            now.AddYears(-1).AddMinutes(1), now.AddYears(15), NextSerial());

        using var tsaKey = RSA.Create(2048);
        var tsaRequest = LeafRequest($"CN=SimpleSign Sandbox TSA ({name}), O=SimpleSign Sandbox", tsaKey, intermediate, baseUrl,
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation);
        tsaRequest.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.8")], true));
        using var tsa = tsaRequest.Create(intermediate.SubjectName, X509SignatureGenerator.CreateForRSA(intermediateKey, RSASignaturePadding.Pkcs1),
            now.AddDays(-1), now.AddYears(5), NextSerial());

        using var untrustedKey = RSA.Create(2048);
        var untrustedRequest = new CertificateRequest("CN=TSA Outside the Chain, O=Outside", untrustedKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        untrustedRequest.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.8")], true));
        untrustedRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation, true));
        using var untrusted = untrustedRequest.CreateSelfSigned(now.AddDays(-1), now.AddYears(5));

        return new SandboxState
        {
            Name = name,
            BaseUrl = baseUrl,
            CreatedAt = now,
            Root = Pair(root, rootKey),
            Intermediate = Pair(intermediate, intermediateKey),
            Tsa = Pair(tsa, tsaKey),
            UntrustedTsa = Pair(untrusted, untrustedKey),
            NextSerial = serial,
        };
    }

    /// <summary>The signers every environment has. Each one is issued again when it no longer shows what it is for.</summary>
    private static readonly (string Id, string Title, string Description, SandboxKeyType KeyType, string? Problem, X509KeyUsageFlags? KeyUsage)[] s_seeds =
    [
        ("rsa-2048", "Maria da Silva (RSA 2048)", "RSA 2048 key: the most common key size for signing certificates.", SandboxKeyType.Rsa2048, null, null),
        ("rsa-3072", "João Souza (RSA 3072)", "RSA 3072 key: same algorithms, larger signature.", SandboxKeyType.Rsa3072, null, null),
        ("rsa-4096", "Ana Pereira (RSA 4096)", "RSA 4096 key, common in long-lived certificates.", SandboxKeyType.Rsa4096, null, null),
        ("ecdsa-p256", "Carlos Lima (ECDSA P-256)", "Elliptic-curve key (NIST P-256). Signature algorithm is ECDSA; RSASSA-PSS is not available.", SandboxKeyType.EcdsaP256, null, null),
        ("ecdsa-p384", "Beatriz Costa (ECDSA P-384)", "Elliptic-curve key (NIST P-384).", SandboxKeyType.EcdsaP384, null, null),
        ("ecdsa-p521", "Rafael Alves (ECDSA P-521)", "Elliptic-curve key (NIST P-521).", SandboxKeyType.EcdsaP521, null, null),
        ("expired", "Expired certificate", "Valid chain, but the certificate expired yesterday: a correct client refuses to sign with it.", SandboxKeyType.Rsa2048, "Expired", null),
        ("not-yet-valid", "Not yet valid", "The certificate only becomes valid next month: a correct client refuses to sign with it.", SandboxKeyType.Rsa2048, "Not yet valid", null),
        ("revoked", "Revoked certificate", "Listed in the intermediate CA's CRL: a client that checks revocation refuses to sign with it.", SandboxKeyType.Rsa2048, "Revoked", null),
        ("no-nonrepudiation", "Without non-repudiation", "Key usage has digitalSignature only (no nonRepudiation): signing works; some validation policies flag it.", SandboxKeyType.Rsa2048, "No non-repudiation", X509KeyUsageFlags.DigitalSignature),
        ("rsa-1024", "Weak key (RSA 1024)", "RSA 1024 key: the default signing policy refuses it (KeyTooWeak).", SandboxKeyType.Rsa1024, "Key too small", null),
        ("no-signing-key-usage", "Without a signing key usage", "Key usage has keyEncipherment only: the default signing policy refuses it (KeyUsageNotPermitted).", SandboxKeyType.Rsa2048, "No signing key usage", X509KeyUsageFlags.KeyEncipherment),
    ];

    /// <summary>Issues the signers that are missing, or that no longer show what they are for (a certificate that expired, a "not yet valid" one that became valid).</summary>
    private void Seed()
    {
        lock (_gate)
        {
            var now = DateTimeOffset.UtcNow;
            var stored = _state.Certificates.ToDictionary(c => c.Id, StringComparer.Ordinal);
            bool changed = false;
            foreach (var seed in s_seeds)
            {
                if (stored.TryGetValue(seed.Id, out var existing) && StillShows(existing, seed.Problem, now))
                {
                    continue;
                }

                var (from, to) = seed.Problem switch
                {
                    "Expired" => (now.AddYears(-2), now.AddDays(-1)),
                    "Not yet valid" => (now.AddDays(30), now.AddYears(2)),
                    _ => (now.AddDays(-1), now.AddYears(1)),
                };
                bool revoked = seed.Problem == "Revoked";
                stored[seed.Id] = new StoredCertificate
                {
                    Id = seed.Id,
                    Title = seed.Title,
                    Description = seed.Description,
                    KeyType = seed.KeyType,
                    Problem = seed.Problem,
                    Pair = IssueLeaf(seed.Title.Split(" (")[0], seed.KeyType, from, to, seed.KeyUsage ?? (X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation)),
                    RevokedByDefault = revoked,
                    RevokedAt = revoked ? now.AddMinutes(-5) : existing?.RevokedAt,
                    RevocationReason = revoked ? nameof(X509RevocationReason.KeyCompromise) : existing?.RevocationReason,
                };
                changed = true;
            }

            var order = s_seeds.Select(s => s.Id).ToList();
            _state = _state with
            {
                Certificates = [.. stored.Values.OrderBy(c => order.IndexOf(c.Id) is var i && i >= 0 ? i : int.MaxValue).ThenBy(c => c.Id, StringComparer.Ordinal)],
            };
            if (changed)
            {
                Republish();
            }
            else
            {
                Materialize();
                RefreshCrls(force: true);
            }
        }
    }

    private static bool StillShows(StoredCertificate stored, string? problem, DateTimeOffset now)
    {
        using var certificate = X509Certificate2.CreateFromPem(stored.Pair.Certificate);
        return problem switch
        {
            "Expired" => certificate.NotAfter < now,
            "Not yet valid" => certificate.NotBefore > now.AddDays(1),
            _ => certificate.NotAfter > now.AddDays(7) && certificate.NotBefore < now,
        };
    }

    private StoredKeyPair IssueLeaf(string holder, SandboxKeyType keyType, DateTimeOffset from, DateTimeOffset to, X509KeyUsageFlags keyUsage)
    {
        using AsymmetricAlgorithm key = keyType switch
        {
            SandboxKeyType.Rsa1024 => RSA.Create(1024),
            SandboxKeyType.Rsa2048 => RSA.Create(2048),
            SandboxKeyType.Rsa3072 => RSA.Create(3072),
            SandboxKeyType.Rsa4096 => RSA.Create(4096),
            SandboxKeyType.EcdsaP384 => ECDsa.Create(ECCurve.NamedCurves.nistP384),
            SandboxKeyType.EcdsaP521 => ECDsa.Create(ECCurve.NamedCurves.nistP521),
            _ => ECDsa.Create(ECCurve.NamedCurves.nistP256),
        };
        var request = LeafRequest($"CN={holder}, OU=Sandbox, O=SimpleSign Sandbox, C=BR", key, Intermediate, BaseUrl, keyUsage);
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.2"), new Oid("1.3.6.1.5.5.7.3.4")], false));

        // Not before the issuer: an "expired" leaf still nests in the intermediate's validity.
        if (from < Intermediate.NotBefore)
        {
            from = Intermediate.NotBefore.ToUniversalTime().AddMinutes(1);
        }

        _state = _state with { NextSerial = _state.NextSerial + 1 };
        using var certificate = request.Create(Intermediate.SubjectName, X509SignatureGenerator.CreateForRSA(_intermediateKey, RSASignaturePadding.Pkcs1),
            from, to, SerialBytes(_state.NextSerial));
        return Pair(certificate, key);
    }

    private static CertificateRequest CaRequest(string subject, RSA key, int pathLength)
    {
        var request = new CertificateRequest(subject, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, pathLength, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        return request;
    }

    private static CertificateRequest LeafRequest(string subject, AsymmetricAlgorithm key, X509Certificate2 issuer, Uri baseUrl, X509KeyUsageFlags keyUsage)
    {
        var request = key switch
        {
            RSA rsa => new CertificateRequest(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1),
            ECDsa ec => new CertificateRequest(subject, ec, HashAlgorithmName.SHA256),
            _ => throw new NotSupportedException(key.GetType().Name),
        };
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(keyUsage, true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        request.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(issuer, true, false));
        request.CertificateExtensions.Add(CertificateRevocationListBuilder.BuildCrlDistributionPointExtension([new Uri(baseUrl, "crl/intermediate.crl").AbsoluteUri]));
        request.CertificateExtensions.Add(new X509AuthorityInformationAccessExtension(null, [new Uri(baseUrl, "aia/intermediate.cer").AbsoluteUri]));
        return request;
    }

    // ── State ─────────────────────────────────────────────────────────

    private void Update(string id, Func<StoredCertificate, StoredCertificate> change)
    {
        if (!_state.Certificates.Any(c => c.Id == id))
        {
            throw new KeyNotFoundException($"No certificate '{id}'.");
        }

        _state = _state with { Certificates = [.. _state.Certificates.Select(c => c.Id == id ? change(c) : c)] };
        Republish();
    }

    /// <summary>Publishes new CRLs (a new CRL number) and saves the environment.</summary>
    private void Republish()
    {
        _state = _state with { CrlNumber = _state.CrlNumber + 1 };
        Materialize();
        RefreshCrls(force: true);
        Save();
    }

    /// <summary>Loads the stored certificates with their keys.</summary>
    private void Materialize()
    {
        foreach (var certificate in _certificates)
        {
            certificate.Certificate.Dispose();
        }

        _certificates = [.. _state.Certificates.Select(c => new SandboxCertificate(
            c.Id, c.Title, c.Description, c.KeyType, X509Certificate2.CreateFromPem(c.Pair.Certificate, c.Pair.Key), c.Problem, c.RevokedAt, c.RevocationReason))];
        if (OperatingSystem.IsWindows())
        {
            // Ephemeral keys cannot sign everywhere on Windows: round-trip through PKCS#12.
            _certificates = [.. _certificates.Select(c => c with
            {
                Certificate = X509CertificateLoader.LoadPkcs12(c.Certificate.Export(X509ContentType.Pkcs12, PfxPassword)!, PfxPassword, X509KeyStorageFlags.Exportable),
            })];
        }
    }

    private void RefreshCrls(bool force = false)
    {
        var now = DateTimeOffset.UtcNow;
        if (!force && now - _crlsBuiltAt < TimeSpan.FromHours(12))
        {
            return;
        }

        _rootCrl = BuildCrl(Root, _rootKey, [], _state.CrlNumber);
        _intermediateCrl = BuildCrl(Intermediate, _intermediateKey, RevokedEntries(), _state.CrlNumber);
        _crlsBuiltAt = now;
    }

    private IEnumerable<(byte[] Serial, DateTimeOffset At, X509RevocationReason Reason)> RevokedEntries() =>
        _certificates.Where(c => c.RevokedAt is not null).Select(c => (
            c.Certificate.SerialNumberBytes.ToArray(),
            c.RevokedAt!.Value,
            Enum.TryParse<X509RevocationReason>(c.RevocationReason, out var reason) ? reason : X509RevocationReason.KeyCompromise));

    private static byte[] BuildCrl(X509Certificate2 issuer, RSA issuerKey, IEnumerable<(byte[] Serial, DateTimeOffset At, X509RevocationReason Reason)> revoked,
        long number, bool expired = false)
    {
        var builder = new CertificateRevocationListBuilder();
        foreach (var (serial, at, reason) in revoked)
        {
            builder.AddEntry(serial, at, reason);
        }

        var now = DateTimeOffset.UtcNow;
        return builder.Build(issuer.SubjectName, X509SignatureGenerator.CreateForRSA(issuerKey, RSASignaturePadding.Pkcs1),
            new BigInteger(number), expired ? now.AddDays(-1) : now.AddDays(1), HashAlgorithmName.SHA256,
            X509AuthorityKeyIdentifierExtension.CreateFromCertificate(issuer, true, false), expired ? now.AddDays(-8) : now.AddMinutes(-5));
    }

    private void Save()
    {
        if (_statePath is null)
        {
            return;
        }

        Directory.CreateDirectory(Path.GetDirectoryName(_statePath)!);
        string temporary = _statePath + ".tmp";
        File.WriteAllText(temporary, JsonSerializer.Serialize(_state, s_json));
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(temporary, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }

        File.Move(temporary, _statePath, overwrite: true);
    }

    private X509Certificate2 Load(StoredKeyPair pair, out AsymmetricAlgorithm key)
    {
        var certificate = X509Certificate2.CreateFromPem(pair.Certificate);
        _owned.Add(certificate);
        key = certificate.GetKeyAlgorithm() == "1.2.840.10045.2.1" ? ECDsa.Create() : RSA.Create();
        key.ImportFromPem(pair.Key);
        _owned.Add(key);
        return certificate;
    }

    private static StoredKeyPair Pair(X509Certificate2 certificate, AsymmetricAlgorithm key) =>
        new(certificate.ExportCertificatePem(), key switch
        {
            RSA rsa => rsa.ExportPkcs8PrivateKeyPem(),
            ECDsa ec => ec.ExportPkcs8PrivateKeyPem(),
            _ => throw new NotSupportedException(key.GetType().Name),
        });

    private static byte[] SerialBytes(long serial)
    {
        var bytes = new byte[12];
        RandomNumberGenerator.Fill(bytes.AsSpan(0, 4));
        bytes[0] &= 0x7F;
        bytes[0] |= 0x01;
        System.Buffers.Binary.BinaryPrimitives.WriteInt64BigEndian(bytes.AsSpan(4), serial);
        return bytes;
    }
}

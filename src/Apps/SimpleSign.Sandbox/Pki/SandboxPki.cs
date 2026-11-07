using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
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

/// <summary>A CA of the environment, with its key.</summary>
internal sealed record SandboxAuthority(
    string Id,
    string Title,
    X509Certificate2 Certificate,
    RSA Key,
    string? IssuerId,
    string? Problem,
    DateTimeOffset? RevokedAt,
    string? RevocationReason);

/// <summary>A certificate the Sandbox issued (with its private key) and what it demonstrates.</summary>
internal sealed record SandboxCertificate(
    string Id,
    string Title,
    string Description,
    SandboxKeyType KeyType,
    X509Certificate2 Certificate,
    string IssuerId,
    CertificateUsage Usage,
    RevocationPointers Pointers,
    string? Problem,
    DateTimeOffset? RevokedAt,
    string? RevocationReason,
    RevocationPublication Publication)
{
    /// <summary>Whether a correct client signs with it (a missing nonRepudiation only gives a warning).</summary>
    public bool IsUsable => Usage == CertificateUsage.Signing && (Problem is null || Problem == "No non-repudiation") && RevokedAt is null;
}

/// <summary>The revocation status of a serial number, as a CA answers it.</summary>
internal sealed record RevocationStatus(bool Known, DateTimeOffset? RevokedAt, X509RevocationReason Reason)
{
    public static readonly RevocationStatus Unknown = new(false, null, X509RevocationReason.Unspecified);

    public static readonly RevocationStatus Good = new(true, null, X509RevocationReason.Unspecified);
}

/// <summary>
/// The test PKI of one Sandbox environment: a root, an intermediate CA, a revoked and an expired
/// intermediate, and the certificates that cover the cases a client must handle (every key type,
/// expired, revoked by CRL over HTTP, HTTPS or LDAP or by OCSP, under a revoked or expired CA…)
/// plus those that run the services (TSA, OCSP responder, TLS). Kept in the environment's folder,
/// so a client told to trust the root keeps trusting it. Certificates point to this Sandbox's
/// public URLs for their CRLs, OCSP and issuer certificates.
/// </summary>
internal sealed class SandboxPki : IDisposable
{
    /// <summary>The password of every PKCS#12 file the Sandbox hands out.</summary>
    public const string PfxPassword = "sandbox";

    public const string RootId = "root";

    public const string IntermediateId = "intermediate";

    public const string RevokedIntermediateId = "intermediate-revoked";

    public const string ExpiredIntermediateId = "intermediate-expired";

    /// <summary>The LDAP base DN of a CA's entry: <c>cn={id},o=sandbox</c>.</summary>
    public static string LdapDn(string caId) => $"cn={caId},o=sandbox";

    private const string OcspNoCheckOid = "1.3.6.1.5.5.7.48.1.5";

    private static readonly JsonSerializerOptions s_json = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() },
    };

    private readonly Lock _gate = new();
    private readonly string? _statePath;
    private readonly List<IDisposable> _owned = [];
    private SandboxState _state;
    private Dictionary<string, SandboxAuthority> _authorities = new(StringComparer.Ordinal);
    private List<SandboxCertificate> _certificates = [];
    private Dictionary<string, byte[]> _crls = new(StringComparer.Ordinal);
    private Dictionary<string, byte[]> _previousCrls = new(StringComparer.Ordinal);
    private DateTimeOffset _crlsBuiltAt;

    private SandboxPki(SandboxState state, string? statePath)
    {
        _state = state;
        _statePath = statePath;
        UntrustedTsa = Load(state.UntrustedTsa, out var untrustedKey);
        UntrustedTsaKey = (RSA)untrustedKey;
        RogueOcspResponder = Load(state.RogueOcspResponder, out var rogueKey);
        RogueOcspKey = (RSA)rogueKey;
        LoadAuthorities();
    }

    public string Name => _state.Name;

    /// <summary>The URL written into the certificates.</summary>
    public Uri BaseUrl => _state.BaseUrl;

    public Uri HttpsBaseUrl => _state.HttpsBaseUrl;

    public Uri LdapBaseUrl => _state.LdapBaseUrl;

    public DateTimeOffset CreatedAt => _state.CreatedAt;

    public X509Certificate2 Root => Authority(RootId).Certificate;

    public X509Certificate2 Intermediate => Authority(IntermediateId).Certificate;

    /// <summary>The TSA certificate (with its key) in the Sandbox's chain.</summary>
    public X509Certificate2 Tsa => Certificate("tsa").Certificate;

    public X509Certificate2 UntrustedTsa { get; }

    public RSA UntrustedTsaKey { get; }

    /// <summary>A self-signed OCSP responder no CA authorized.</summary>
    public X509Certificate2 RogueOcspResponder { get; }

    public RSA RogueOcspKey { get; }

    /// <summary>The certificates a validator needs besides a signer issued by the intermediate CA.</summary>
    public IReadOnlyList<X509Certificate2> Chain => [Intermediate, Root];

    public IReadOnlyList<SandboxAuthority> Authorities
    {
        get
        {
            lock (_gate)
            {
                return [.. _authorities.Values];
            }
        }
    }

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

    public Uri CertificateUrl(string caId) => new(BaseUrl, $"aia/{caId}.cer");

    public Uri CrlUrl(string caId) => new(BaseUrl, $"crl/{caId}.crl");

    public Uri HttpsCrlUrl(string caId) => new(HttpsBaseUrl, $"crl/{caId}.crl");

    public Uri LdapCrlUrl(string caId) => new($"{LdapBaseUrl.GetLeftPart(UriPartial.Authority)}/{LdapDn(caId)}?certificateRevocationList;binary");

    public Uri OcspUrl(string caId) => new(BaseUrl, $"ocsp/{caId}");

    /// <summary>Opens the environment in <paramref name="directory"/>, creating it the first time.</summary>
    /// <param name="directory">The environment's folder; null keeps everything in memory.</param>
    /// <param name="options">The environment's name and the URLs for new certificates. An existing environment keeps its own URLs.</param>
    /// <param name="logger">Where to report an environment whose URL differs, or one that had to be created again.</param>
    public static SandboxPki Open(string? directory, SandboxOptions options, ILogger? logger = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        string? path = directory is null ? null : Path.Combine(directory, "state.json");
        SandboxState? state = null;
        if (path is not null && File.Exists(path))
        {
            string json = File.ReadAllText(path);
            int version = JsonDocument.Parse(json).RootElement.TryGetProperty("version", out var v) ? v.GetInt32() : 0;
            if (version == SandboxState.CurrentVersion)
            {
                state = JsonSerializer.Deserialize<SandboxState>(json, s_json);
            }
            else
            {
                // An environment of another version: kept aside, and a new one is created.
                File.Move(path, Path.Combine(directory!, $"state.v{version}.json"), overwrite: true);
                logger?.LogWarning("The environment '{Name}' was written by another version of the Sandbox (v{Version}): a new one was created; the old state is in state.v{Version}.json.",
                    options.Name, version, version);
            }
        }

        bool created = state is null;
        state ??= Create(options);
        if (!created && state.BaseUrl != options.BaseUrl)
        {
            logger?.LogWarning("The environment '{Name}' was created for {Stored}; its certificates keep pointing there (asked: {Asked}).", state.Name, state.BaseUrl, options.BaseUrl);
        }

        var pki = new SandboxPki(state, path);
        pki.Seed();
        return pki;
    }

    /// <summary>A CA by id.</summary>
    public SandboxAuthority Authority(string id)
    {
        lock (_gate)
        {
            return _authorities.TryGetValue(id, out var authority) ? authority : throw new KeyNotFoundException($"No CA '{id}'.");
        }
    }

    /// <summary>A certificate by id.</summary>
    public SandboxCertificate Certificate(string id)
    {
        lock (_gate)
        {
            return _certificates.FirstOrDefault(c => c.Id == id) ?? throw new KeyNotFoundException($"No certificate '{id}'.");
        }
    }

    /// <summary>The certificate and its key as a PKCS#12 file (password <see cref="PfxPassword"/>), with its chain.</summary>
    public byte[] Pfx(string id)
    {
        var certificate = Certificate(id);
        var collection = new X509Certificate2Collection(certificate.Certificate);
        for (string? issuer = certificate.IssuerId; issuer is not null; issuer = Authority(issuer).IssuerId)
        {
            collection.Add(Authority(issuer).Certificate);
        }

        return collection.Export(X509ContentType.Pkcs12, PfxPassword)!;
    }

    /// <summary>
    /// A signer issued by the intermediate CA that is valid for <paramref name="lifetime"/> from now, as a
    /// PKCS#12 file with its chain: to make a signature whose certificate has expired by validation time
    /// (a correct client refuses to sign with an expired certificate). Not kept in the environment.
    /// </summary>
    public byte[] IssueShortLived(TimeSpan lifetime)
    {
        lock (_gate)
        {
            var now = DateTimeOffset.UtcNow;
            var seed = new SeedDefinition("short-lived", "Short-lived signer", "");
            var pair = IssueLeaf(seed, now.AddMinutes(-1), now.Add(lifetime));
            Save();
            using var certificate = X509Certificate2.CreateFromPem(pair.Certificate, pair.Key);
            var collection = new X509Certificate2Collection { certificate, Intermediate, Root };
            return collection.Export(X509ContentType.Pkcs12, PfxPassword)!;
        }
    }

    /// <summary>The chain of a certificate, from its issuer up to the root.</summary>
    public IReadOnlyList<X509Certificate2> ChainOf(string id)
    {
        var chain = new List<X509Certificate2>();
        for (string? issuer = Certificate(id).IssuerId; issuer is not null; issuer = Authority(issuer).IssuerId)
        {
            chain.Add(Authority(issuer).Certificate);
        }

        return chain;
    }

    /// <summary>Revokes a certificate now: the CA publishes it at once (CRL, OCSP or both).</summary>
    public void Revoke(string id, string? reason = null, RevocationPublication publication = RevocationPublication.Both)
    {
        lock (_gate)
        {
            Update(id, c => c with
            {
                RevokedAt = DateTimeOffset.UtcNow,
                RevocationReason = reason ?? nameof(X509RevocationReason.KeyCompromise),
                Publication = publication,
            });
        }
    }

    /// <summary>Takes a revocation back (a test convenience: real CAs cannot).</summary>
    public void Unrevoke(string id)
    {
        lock (_gate)
        {
            Update(id, c => c with { RevokedAt = null, RevocationReason = null, Publication = RevocationPublication.Both });
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
                    Publication = RevocationPublication.Both,
                })],
            };
            Republish();
        }
    }

    /// <summary>The current CRL of a CA.</summary>
    public byte[] Crl(string caId)
    {
        lock (_gate)
        {
            RefreshCrls();
            return _crls.TryGetValue(caId, out var crl) ? crl : throw new KeyNotFoundException($"No CA '{caId}'.");
        }
    }

    /// <summary>The CRL of a CA as a failure would serve it.</summary>
    public byte[] Crl(string caId, CrlFault fault)
    {
        lock (_gate)
        {
            var authority = Authority(caId);
            return fault switch
            {
                CrlFault.Expired => BuildCrl(authority.Certificate, authority.Key, CrlEntries(caId), _state.CrlNumber, expired: true),
                CrlFault.WrongKey => BuildCrl(authority.Certificate, RogueOcspKey, CrlEntries(caId), _state.CrlNumber),
                CrlFault.Stale => _previousCrls.TryGetValue(caId, out var previous) ? previous : Crl(caId),
                _ => Crl(caId),
            };
        }
    }

    /// <summary>
    /// The status of a serial number, as the OCSP responder of <paramref name="caId"/> answers it
    /// (revocations published in the CRL only are not known to it).
    /// </summary>
    public RevocationStatus OcspStatus(string caId, ReadOnlySpan<byte> serial)
    {
        lock (_gate)
        {
            byte[] wanted = TrimSerial(serial);
            if (caId == RootId)
            {
                var authority = _authorities.Values.FirstOrDefault(a => a.IssuerId == RootId && TrimSerial(a.Certificate.SerialNumberBytes.Span).AsSpan().SequenceEqual(wanted));
                return authority is null ? RevocationStatus.Unknown
                    : authority.RevokedAt is { } at ? new RevocationStatus(true, at, ParseReason(authority.RevocationReason)) : RevocationStatus.Good;
            }

            var certificate = _certificates.FirstOrDefault(c => c.IssuerId == caId && TrimSerial(c.Certificate.SerialNumberBytes.Span).AsSpan().SequenceEqual(wanted));
            return certificate is null ? RevocationStatus.Unknown
                : certificate.RevokedAt is { } revokedAt && certificate.Publication != RevocationPublication.CrlOnly
                    ? new RevocationStatus(true, revokedAt, ParseReason(certificate.RevocationReason))
                    : RevocationStatus.Good;
        }
    }

    /// <summary>The TLS certificate of the HTTPS endpoint, with its key (loaded once, PKCS#12 round-trip for the TLS stack).</summary>
    public X509Certificate2 TlsCertificate()
    {
        lock (_gate)
        {
            if (_tls is null)
            {
                byte[] pfx = Pfx("tls-server");
                _tls = X509CertificateLoader.LoadPkcs12(pfx, PfxPassword);
            }

            return _tls;
        }
    }

    private X509Certificate2? _tls;

    public void Dispose()
    {
        lock (_gate)
        {
            _tls?.Dispose();
            foreach (var owned in _owned)
            {
                owned.Dispose();
            }

            foreach (var authority in _authorities.Values)
            {
                authority.Certificate.Dispose();
                authority.Key.Dispose();
            }

            foreach (var certificate in _certificates)
            {
                certificate.Certificate.Dispose();
            }
        }
    }

    // ── Creation ──────────────────────────────────────────────────────

    private static SandboxState Create(SandboxOptions options)
    {
        var now = DateTimeOffset.UtcNow;
        long serial = 0x1000;
        byte[] NextSerial() => SerialBytes(++serial);
        string name = options.Name;
        var baseUrl = options.BaseUrl;

        using var rootKey = RSA.Create(3072);
        using var root = CaRequest($"CN=SimpleSign Sandbox Root CA ({name}), O=SimpleSign Sandbox", rootKey, pathLength: 1)
            .CreateSelfSigned(now.AddYears(-3), now.AddYears(25));

        StoredAuthority Intermediate(string id, string title, string cn, DateTimeOffset from, DateTimeOffset to, string? problem = null, bool revoked = false)
        {
            using var key = RSA.Create(2048);
            var request = CaRequest($"CN={cn} ({name}), O=SimpleSign Sandbox", key, pathLength: 0);
            request.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(root, true, false));
            request.CertificateExtensions.Add(CertificateRevocationListBuilder.BuildCrlDistributionPointExtension([new Uri(baseUrl, $"crl/{RootId}.crl").AbsoluteUri]));
            request.CertificateExtensions.Add(new X509AuthorityInformationAccessExtension([new Uri(baseUrl, $"ocsp/{RootId}").AbsoluteUri], [new Uri(baseUrl, $"aia/{RootId}.cer").AbsoluteUri]));
            using var certificate = request.Create(root.SubjectName, X509SignatureGenerator.CreateForRSA(rootKey, RSASignaturePadding.Pkcs1), from, to, NextSerial());
            return new StoredAuthority
            {
                Id = id,
                Title = title,
                Pair = Pair(certificate, key),
                IssuerId = RootId,
                Problem = problem,
                RevokedAt = revoked ? now.AddHours(-1) : null,
                RevocationReason = revoked ? nameof(X509RevocationReason.CACompromise) : null,
            };
        }

        var authorities = new List<StoredAuthority>
        {
            new() { Id = RootId, Title = "Root CA", Pair = Pair(root, rootKey) },
            Intermediate(IntermediateId, "Intermediate CA", "SimpleSign Sandbox CA 1", now.AddYears(-2), now.AddYears(15)),
            Intermediate(RevokedIntermediateId, "Revoked intermediate CA", "SimpleSign Sandbox CA 2 (revoked)", now.AddYears(-2), now.AddYears(15), "Revoked", revoked: true),
            Intermediate(ExpiredIntermediateId, "Expired intermediate CA", "SimpleSign Sandbox CA 3 (expired)", now.AddYears(-3), now.AddDays(-1), "Expired"),
        };

        using var untrustedKey = RSA.Create(2048);
        var untrustedRequest = new CertificateRequest("CN=TSA Outside the Chain, O=Outside", untrustedKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        untrustedRequest.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.8")], true));
        untrustedRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation, true));
        using var untrusted = untrustedRequest.CreateSelfSigned(now.AddDays(-1), now.AddYears(5));

        using var rogueKey = RSA.Create(2048);
        var rogueRequest = new CertificateRequest("CN=Unauthorized OCSP Responder, O=Outside", rogueKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        rogueRequest.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.9")], false));
        using var rogue = rogueRequest.CreateSelfSigned(now.AddDays(-1), now.AddYears(5));

        return new SandboxState
        {
            Name = name,
            BaseUrl = baseUrl,
            HttpsBaseUrl = options.HttpsBaseUrl,
            LdapBaseUrl = options.LdapBaseUrl,
            CreatedAt = now,
            Authorities = authorities,
            UntrustedTsa = Pair(untrusted, untrustedKey),
            RogueOcspResponder = Pair(rogue, rogueKey),
            NextSerial = serial,
        };
    }

    private sealed record SeedDefinition(
        string Id,
        string Title,
        string Description,
        SandboxKeyType KeyType = SandboxKeyType.Rsa2048,
        string? Problem = null,
        X509KeyUsageFlags? KeyUsage = null,
        string IssuerId = IntermediateId,
        CertificateUsage Usage = CertificateUsage.Signing,
        RevocationPointers Pointers = RevocationPointers.CrlHttp | RevocationPointers.Ocsp,
        bool Revoked = false)
    {
        /// <summary>What decides the certificate's content: a seed whose profile changed is issued again.</summary>
        public string Profile => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(
            $"2|{KeyType}|{Problem}|{KeyUsage}|{IssuerId}|{Usage}|{Pointers}")))[..16];
    }

    /// <summary>The certificates every environment has. Each one is issued again when it no longer shows what it is for.</summary>
    private static readonly SeedDefinition[] s_seeds =
    [
        new("rsa-2048", "Maria da Silva (RSA 2048)", "RSA 2048 key: the most common key size for signing certificates."),
        new("rsa-3072", "João Souza (RSA 3072)", "RSA 3072 key: same algorithms, larger signature.", SandboxKeyType.Rsa3072),
        new("rsa-4096", "Ana Pereira (RSA 4096)", "RSA 4096 key, common in long-lived certificates.", SandboxKeyType.Rsa4096),
        new("ecdsa-p256", "Carlos Lima (ECDSA P-256)", "Elliptic-curve key (NIST P-256). Signature algorithm is ECDSA; RSASSA-PSS is not available.", SandboxKeyType.EcdsaP256),
        new("ecdsa-p384", "Beatriz Costa (ECDSA P-384)", "Elliptic-curve key (NIST P-384).", SandboxKeyType.EcdsaP384),
        new("ecdsa-p521", "Rafael Alves (ECDSA P-521)", "Elliptic-curve key (NIST P-521).", SandboxKeyType.EcdsaP521),
        new("expired", "Expired certificate", "Valid chain, but the certificate expired yesterday: a correct client refuses to sign with it.",
            Problem: "Expired"),
        new("not-yet-valid", "Not yet valid", "The certificate only becomes valid next month: a correct client refuses to sign with it.",
            Problem: "Not yet valid"),
        new("revoked", "Revoked certificate", "Revoked in the intermediate CA's CRL (HTTP) and by its OCSP responder: a client that checks revocation refuses to sign with it.",
            Problem: "Revoked", Revoked: true),
        new("revoked-ocsp", "Revoked, OCSP only", "Points to the OCSP responder only (no CRL distribution point), which answers revoked.",
            Problem: "Revoked", Pointers: RevocationPointers.Ocsp, Revoked: true),
        new("revoked-crl-https", "Revoked, CRL over HTTPS", "Its only CRL distribution point is on the HTTPS endpoint; the CRL lists it.",
            Problem: "Revoked", Pointers: RevocationPointers.CrlHttps, Revoked: true),
        new("revoked-crl-ldap", "Revoked, CRL over LDAP", "Its only CRL distribution point is an ldap:// URL; the CRL lists it.",
            Problem: "Revoked", Pointers: RevocationPointers.CrlLdap, Revoked: true),
        new("good-ocsp", "Good, OCSP only", "Points to the OCSP responder only: the control for the revoked-ocsp case.", Pointers: RevocationPointers.Ocsp),
        new("good-crl-https", "Good, CRL over HTTPS", "Its only CRL distribution point is on the HTTPS endpoint: the control for revoked-crl-https.",
            Pointers: RevocationPointers.CrlHttps),
        new("good-crl-ldap", "Good, CRL over LDAP", "Its only CRL distribution point is an ldap:// URL: the control for revoked-crl-ldap.",
            Pointers: RevocationPointers.CrlLdap),
        new("under-revoked-ca", "Under a revoked CA", "Not revoked itself, but its issuing CA is revoked in the root's CRL: the chain is revoked.",
            Problem: "Issuer revoked", IssuerId: RevokedIntermediateId),
        new("under-expired-ca", "Under an expired CA", "Valid itself, but its issuing CA expired yesterday: the chain is not valid.",
            Problem: "Issuer expired", IssuerId: ExpiredIntermediateId),
        new("no-nonrepudiation", "Without non-repudiation", "Key usage has digitalSignature only (no nonRepudiation): signing works; some validation policies flag it.",
            Problem: "No non-repudiation", KeyUsage: X509KeyUsageFlags.DigitalSignature),
        new("rsa-1024", "Weak key (RSA 1024)", "RSA 1024 key: the default signing policy refuses it (KeyTooWeak).", SandboxKeyType.Rsa1024, "Key too small"),
        new("no-signing-key-usage", "Without a signing key usage", "Key usage has keyEncipherment only: the default signing policy refuses it (KeyUsageNotPermitted).",
            Problem: "No signing key usage", KeyUsage: X509KeyUsageFlags.KeyEncipherment),
        new("tsa", "TSA", "The time-stamping authority of /tsa/tsr and /tsa/authenticated.", Usage: CertificateUsage.Timestamping),
        new("tsa-revoked", "Revoked TSA", "The TSA of /tsa/revoked: its certificate is revoked, so its tokens must not be trusted.",
            Problem: "Revoked", Usage: CertificateUsage.Timestamping, Revoked: true),
        new("ocsp-responder", "Delegated OCSP responder", "Signs the intermediate CA's OCSP responses when the delegated signer is chosen (OCSPSigning, id-pkix-ocsp-nocheck).",
            Usage: CertificateUsage.OcspSigning, Pointers: RevocationPointers.None),
        new("tls-server", "HTTPS endpoint", "The TLS certificate of the HTTPS endpoint (serverAuth, localhost and the public host).",
            Usage: CertificateUsage.TlsServer, Pointers: RevocationPointers.CrlHttp),
    ];

    /// <summary>Issues the certificates that are missing, changed, or no longer show what they are for.</summary>
    private void Seed()
    {
        lock (_gate)
        {
            var now = DateTimeOffset.UtcNow;
            var stored = _state.Certificates.ToDictionary(c => c.Id, StringComparer.Ordinal);
            bool changed = false;
            foreach (var seed in s_seeds)
            {
                if (stored.TryGetValue(seed.Id, out var existing) && existing.Profile == seed.Profile && StillShows(existing, seed.Problem, now))
                {
                    continue;
                }

                var (from, to) = seed.Problem switch
                {
                    "Expired" => (now.AddYears(-2), now.AddDays(-1)),
                    "Not yet valid" => (now.AddDays(30), now.AddYears(2)),
                    _ => (now.AddDays(-1), now.AddYears(1)),
                };
                stored[seed.Id] = new StoredCertificate
                {
                    Id = seed.Id,
                    Title = seed.Title,
                    Description = seed.Description,
                    KeyType = seed.KeyType,
                    Problem = seed.Problem,
                    IssuerId = seed.IssuerId,
                    Usage = seed.Usage,
                    Pointers = seed.Pointers,
                    Profile = seed.Profile,
                    Pair = IssueLeaf(seed, from, to),
                    RevokedByDefault = seed.Revoked,
                    RevokedAt = seed.Revoked ? now.AddMinutes(-5) : existing?.RevokedAt,
                    RevocationReason = seed.Revoked ? nameof(X509RevocationReason.KeyCompromise) : existing?.RevocationReason,
                    Publication = seed.Revoked ? RevocationPublication.Both : existing?.Publication ?? RevocationPublication.Both,
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

            _previousCrls = new Dictionary<string, byte[]>(_crls, StringComparer.Ordinal);
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

    private StoredKeyPair IssueLeaf(SeedDefinition seed, DateTimeOffset from, DateTimeOffset to)
    {
        var issuer = Authority(seed.IssuerId);
        using AsymmetricAlgorithm key = seed.KeyType switch
        {
            SandboxKeyType.Rsa1024 => RSA.Create(1024),
            SandboxKeyType.Rsa2048 => RSA.Create(2048),
            SandboxKeyType.Rsa3072 => RSA.Create(3072),
            SandboxKeyType.Rsa4096 => RSA.Create(4096),
            SandboxKeyType.EcdsaP384 => ECDsa.Create(ECCurve.NamedCurves.nistP384),
            SandboxKeyType.EcdsaP521 => ECDsa.Create(ECCurve.NamedCurves.nistP521),
            _ => ECDsa.Create(ECCurve.NamedCurves.nistP256),
        };
        string holder = seed.Title.Split(" (")[0];
        var name = new X500DistinguishedNameBuilder();
        if (seed.Usage == CertificateUsage.Signing)
        {
            name.AddCountryOrRegion("BR");
        }

        name.AddOrganizationName("SimpleSign Sandbox");
        if (seed.Usage == CertificateUsage.Signing)
        {
            name.AddOrganizationalUnitName("Sandbox");
        }

        name.AddCommonName(seed.Usage switch
        {
            CertificateUsage.Timestamping => $"SimpleSign Sandbox {holder} ({Name})",
            CertificateUsage.OcspSigning => $"SimpleSign Sandbox OCSP Responder ({Name})",
            CertificateUsage.TlsServer => BaseUrl.Host,
            _ => holder,
        });
        var subject = name.Build();
        var request = key switch
        {
            RSA rsa => new CertificateRequest(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1),
            ECDsa ec => new CertificateRequest(subject, ec, HashAlgorithmName.SHA256),
            _ => throw new NotSupportedException(key.GetType().Name),
        };
        var keyUsage = seed.KeyUsage ?? seed.Usage switch
        {
            CertificateUsage.TlsServer => X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment,
            CertificateUsage.OcspSigning => X509KeyUsageFlags.DigitalSignature,
            _ => X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation,
        };
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(keyUsage, true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        request.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(issuer.Certificate, true, false));
        request.CertificateExtensions.Add(seed.Usage switch
        {
            CertificateUsage.Timestamping => new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.8")], true),
            CertificateUsage.OcspSigning => new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.9")], false),
            CertificateUsage.TlsServer => new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.1")], false),
            _ => new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.2"), new Oid("1.3.6.1.5.5.7.3.4")], false),
        });
        if (seed.Usage == CertificateUsage.OcspSigning)
        {
            // id-pkix-ocsp-nocheck: clients do not check the responder's own revocation.
            request.CertificateExtensions.Add(new X509Extension(OcspNoCheckOid, [0x05, 0x00], false));
        }

        if (seed.Usage == CertificateUsage.TlsServer)
        {
            var names = new SubjectAlternativeNameBuilder();
            names.AddDnsName("localhost");
            if (System.Net.IPAddress.TryParse(BaseUrl.Host, out var address))
            {
                names.AddIpAddress(address);
            }
            else if (!string.Equals(BaseUrl.Host, "localhost", StringComparison.OrdinalIgnoreCase))
            {
                names.AddDnsName(BaseUrl.Host);
            }

            names.AddIpAddress(System.Net.IPAddress.Loopback);
            names.AddIpAddress(System.Net.IPAddress.IPv6Loopback);
            request.CertificateExtensions.Add(names.Build());
        }

        var crlPoints = new List<string>();
        if (seed.Pointers.HasFlag(RevocationPointers.CrlHttp))
        {
            crlPoints.Add(CrlUrl(seed.IssuerId).AbsoluteUri);
        }

        if (seed.Pointers.HasFlag(RevocationPointers.CrlHttps))
        {
            crlPoints.Add(HttpsCrlUrl(seed.IssuerId).AbsoluteUri);
        }

        if (seed.Pointers.HasFlag(RevocationPointers.CrlLdap))
        {
            crlPoints.Add(LdapCrlUrl(seed.IssuerId).OriginalString);
        }

        if (crlPoints.Count > 0)
        {
            request.CertificateExtensions.Add(CertificateRevocationListBuilder.BuildCrlDistributionPointExtension(crlPoints));
        }

        request.CertificateExtensions.Add(new X509AuthorityInformationAccessExtension(
            seed.Pointers.HasFlag(RevocationPointers.Ocsp) ? [OcspUrl(seed.IssuerId).AbsoluteUri] : null,
            [CertificateUrl(seed.IssuerId).AbsoluteUri]));

        _state = _state with { NextSerial = _state.NextSerial + 1 };
        using var certificate = request.Create(issuer.Certificate.SubjectName, X509SignatureGenerator.CreateForRSA(issuer.Key, RSASignaturePadding.Pkcs1),
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

    /// <summary>Publishes new CRLs (a new CRL number; the previous ones stay available as "stale") and saves the environment.</summary>
    private void Republish()
    {
        _previousCrls = new Dictionary<string, byte[]>(_crls, StringComparer.Ordinal);
        _state = _state with { CrlNumber = _state.CrlNumber + 1 };
        Materialize();
        RefreshCrls(force: true);
        Save();
    }

    private void LoadAuthorities()
    {
        _authorities = _state.Authorities.ToDictionary(a => a.Id, a =>
        {
            var certificate = Load(a.Pair, out var key);
            return new SandboxAuthority(a.Id, a.Title, certificate, (RSA)key, a.IssuerId, a.Problem, a.RevokedAt, a.RevocationReason);
        }, StringComparer.Ordinal);
    }

    /// <summary>Loads the stored certificates with their keys.</summary>
    private void Materialize()
    {
        // The previous objects may still be in use by a request in flight (TSA, CSC): disposed at the end.
        _owned.AddRange(_certificates.Select(c => c.Certificate));

        _certificates = [.. _state.Certificates.Select(c => new SandboxCertificate(
            c.Id, c.Title, c.Description, c.KeyType, X509Certificate2.CreateFromPem(c.Pair.Certificate, c.Pair.Key), c.IssuerId, c.Usage, c.Pointers,
            c.Problem, c.RevokedAt, c.RevocationReason, c.Publication))];
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

        _crls = _authorities.Values.ToDictionary(a => a.Id, a => BuildCrl(a.Certificate, a.Key, CrlEntries(a.Id), _state.CrlNumber), StringComparer.Ordinal);
        _crlsBuiltAt = now;
    }

    /// <summary>The revoked certificates a CA's CRL lists (revocations published by OCSP only are left out).</summary>
    private List<(byte[] Serial, DateTimeOffset At, X509RevocationReason Reason)> CrlEntries(string caId) =>
        caId == RootId
            ? [.. _authorities.Values.Where(a => a.IssuerId == RootId && a.RevokedAt is not null)
                .Select(a => (a.Certificate.SerialNumberBytes.ToArray(), a.RevokedAt!.Value, ParseReason(a.RevocationReason)))]
            : [.. _certificates.Where(c => c.IssuerId == caId && c.RevokedAt is not null && c.Publication != RevocationPublication.OcspOnly)
                .Select(c => (c.Certificate.SerialNumberBytes.ToArray(), c.RevokedAt!.Value, ParseReason(c.RevocationReason)))];

    private static X509RevocationReason ParseReason(string? reason) =>
        Enum.TryParse<X509RevocationReason>(reason, out var parsed) ? parsed : X509RevocationReason.KeyCompromise;

    private static byte[] BuildCrl(X509Certificate2 issuer, RSA signingKey, IEnumerable<(byte[] Serial, DateTimeOffset At, X509RevocationReason Reason)> revoked,
        long number, bool expired = false)
    {
        var builder = new CertificateRevocationListBuilder();
        foreach (var (serial, at, reason) in revoked)
        {
            builder.AddEntry(serial, at, reason);
        }

        var now = DateTimeOffset.UtcNow;
        return builder.Build(issuer.SubjectName, X509SignatureGenerator.CreateForRSA(signingKey, RSASignaturePadding.Pkcs1),
            new BigInteger(number), expired ? now.AddDays(-1) : now.AddDays(1), HashAlgorithmName.SHA256,
            X509AuthorityKeyIdentifierExtension.CreateFromCertificate(issuer, true, false), expired ? now.AddDays(-8) : now.AddMinutes(-5));
    }

    private static byte[] TrimSerial(ReadOnlySpan<byte> serial)
    {
        int start = 0;
        while (start < serial.Length - 1 && serial[start] == 0)
        {
            start++;
        }

        return serial[start..].ToArray();
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

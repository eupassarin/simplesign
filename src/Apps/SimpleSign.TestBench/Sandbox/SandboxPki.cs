using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace SimpleSign.TestBench.Sandbox;

/// <summary>Key type of a sandbox signer.</summary>
internal enum SandboxKeyType
{
    Rsa1024,
    Rsa2048,
    Rsa3072,
    Rsa4096,
    EcdsaP256,
    EcdsaP384,
    EcdsaP521,
}

/// <summary>A sandbox signer: what it demonstrates and its certificate (with the private key).</summary>
internal sealed record SandboxSigner(
    string Id,
    string Title,
    string Description,
    SandboxKeyType KeyType,
    X509Certificate2 Certificate,
    bool IsUsable,
    string? Problem);

/// <summary>
/// An offline test PKI: a root, an intermediate CA, a TSA, and signers that cover every key type
/// the library supports plus the edge cases (expired, not yet valid, revoked, no non-repudiation,
/// weak key, no signing key usage). Certificates carry CRL distribution points on
/// <c>*.sandbox.simplesign.test</c>, served by <see cref="SandboxNetwork"/> (which also serves the CA certificates).
/// Generated once per process; nothing is written to disk.
/// </summary>
internal sealed class SandboxPki : IDisposable
{
    public const string Host = "sandbox.simplesign.test";
    public static readonly Uri TsaUri = new($"http://tsa.{Host}/tsr");
    public static readonly Uri ArchiveTsaUri = new($"http://tsa.{Host}/archive");
    public static readonly Uri AuthenticatedTsaUri = new($"http://tsa.{Host}/authenticated");
    public static readonly Uri UntrustedTsaUri = new($"http://tsa.{Host}/untrusted");
    public static readonly Uri RootCrlUri = new($"http://crl.{Host}/root.crl");
    public static readonly Uri IntermediateCrlUri = new($"http://crl.{Host}/intermediate.crl");
    public static readonly Uri IntermediateCertUri = new($"http://aia.{Host}/intermediate.cer");
    public static readonly Uri RootCertUri = new($"http://aia.{Host}/root.cer");

    /// <summary>Basic credentials the authenticated sandbox TSA accepts (user:password).</summary>
    public const string TsaUser = "sandbox";
    public const string TsaPassword = "sandbox-tsa";

    private readonly RSA _rootKey = RSA.Create(2048);
    private readonly RSA _intermediateKey = RSA.Create(2048);
    private readonly List<BigInteger> _revoked = [];
    private readonly Dictionary<string, BigInteger> _revokedNow = new(StringComparer.Ordinal);
    private readonly List<IDisposable> _owned = [];
    private long _serial = 0x1000;

    /// <summary>Creates the sandbox PKI.</summary>
    /// <param name="rootStorePath">
    /// A file where the root CA (certificate and key, PEM) is kept between runs, so an external
    /// validator that was told to trust the sandbox root keeps trusting it. Null: a new root every time.
    /// </param>
    public SandboxPki(string? rootStorePath = null)
    {
        var now = DateTimeOffset.UtcNow;
        Root = LoadRoot(rootStorePath, now) ?? SaveRoot(rootStorePath, BuildCa(
            "CN=AC Raiz Sandbox SimpleSign, OU=Sandbox, O=SimpleSign TestBench, C=BR", _rootKey, null, null,
            now.AddYears(-2), now.AddYears(20), pathLength: 1));
        Intermediate = BuildCa("CN=AC Sandbox SimpleSign v1, OU=Sandbox, O=SimpleSign TestBench, C=BR", _intermediateKey, Root, _rootKey,
            now.AddYears(-1), now.AddYears(10), pathLength: 0);

        using var tsaKey = RSA.Create(2048);
        Tsa = Issue("CN=ACT Sandbox SimpleSign, OU=Carimbo do Tempo, O=SimpleSign TestBench, C=BR", tsaKey,
            now.AddYears(-1), now.AddYears(5), eku: [new Oid("1.3.6.1.5.5.7.3.8")], ekuCritical: true, keyUsage: X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation);
        TsaKey = Tsa.GetRSAPrivateKey()!;

        // A TSA under its own self-signed CA, outside every trust anchor (the "untrusted TSA" sample).
        var untrustedKey = RSA.Create(2048);
        var untrustedRequest = new CertificateRequest("CN=ACT Fora da Cadeia, O=Outside, C=BR", untrustedKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        untrustedRequest.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new("1.3.6.1.5.5.7.3.8") }, true));
        untrustedRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation, true));
        UntrustedTsa = untrustedRequest.CreateSelfSigned(now.AddDays(-1), now.AddYears(2));
        UntrustedTsaKey = untrustedKey;
        _owned.Add(UntrustedTsa);
        _owned.Add(untrustedKey);

        Signers =
        [
            Person("rsa-2048", "Maria da Silva (RSA 2048)", "RSA 2048 key: the most common key size for signing certificates.", SandboxKeyType.Rsa2048),
            Person("rsa-3072", "João Souza (RSA 3072)", "RSA 3072 key: same algorithms, larger signature.", SandboxKeyType.Rsa3072),
            Person("rsa-4096", "Ana Pereira (RSA 4096)", "RSA 4096 key, common in long-lived certificates.", SandboxKeyType.Rsa4096),
            Person("ecdsa-p256", "Carlos Lima (ECDSA P-256)", "Elliptic-curve key (NIST P-256). Signature algorithm is ECDSA; RSASSA-PSS is not available.", SandboxKeyType.EcdsaP256),
            Person("ecdsa-p384", "Beatriz Costa (ECDSA P-384)", "Elliptic-curve key (NIST P-384).", SandboxKeyType.EcdsaP384),
            Person("ecdsa-p521", "Rafael Alves (ECDSA P-521)", "Elliptic-curve key (NIST P-521).", SandboxKeyType.EcdsaP521),
            Person("expired", "Expired certificate", "Valid chain, but the certificate expired yesterday: the library refuses to sign with it.", SandboxKeyType.Rsa2048,
                notBefore: now.AddYears(-2), notAfter: now.AddDays(-1), problem: "Expired"),
            Person("not-yet-valid", "Not yet valid", "The certificate only becomes valid next month: the library refuses to sign with it.", SandboxKeyType.Rsa2048,
                notBefore: now.AddDays(30), notAfter: now.AddYears(2), problem: "Not yet valid"),
            Person("revoked", "Revoked certificate", "Listed in the intermediate CA's CRL: B-LT/LTA embed the CRL, validation reports revoked.", SandboxKeyType.Rsa2048,
                revoke: true, problem: "Revoked"),
            Person("no-nonrepudiation", "Without non-repudiation", "Key usage has digitalSignature only (no nonRepudiation): signing works; some validation policies flag it.", SandboxKeyType.Rsa2048,
                keyUsage: X509KeyUsageFlags.DigitalSignature, problem: "No non-repudiation"),
            Person("rsa-1024", "Weak key (RSA 1024)", "RSA 1024 key: the default signing policy refuses it (KeyTooWeak); the Minimal policy signs, and validation reports CRYPTO_CONSTRAINTS_FAILURE_NO_POE.", SandboxKeyType.Rsa1024,
                problem: "Key too small"),
            Person("no-signing-key-usage", "Without a signing key usage", "Key usage has keyEncipherment only: the default signing policy refuses it (KeyUsageNotPermitted).", SandboxKeyType.Rsa2048,
                keyUsage: X509KeyUsageFlags.KeyEncipherment, problem: "No signing key usage"),
        ];
        RootCrl = BuildCrl(Root, _rootKey, []);
        IntermediateCrl = BuildCrl(Intermediate, _intermediateKey, _revoked);
    }

    public X509Certificate2 Root { get; }

    public X509Certificate2 Intermediate { get; }

    public X509Certificate2 Tsa { get; }

    public RSA TsaKey { get; }

    public X509Certificate2 UntrustedTsa { get; }

    public RSA UntrustedTsaKey { get; }

    public IReadOnlyList<SandboxSigner> Signers { get; }

    public byte[] RootCrl { get; }

    /// <summary>The intermediate CA's CRL: the signers revoked from the start, plus those revoked with <see cref="Revoke"/>.</summary>
    public byte[] IntermediateCrl { get; private set; }

    /// <summary>The ids of the signers revoked at run time with <see cref="Revoke"/>.</summary>
    public IReadOnlyCollection<string> RevokedNow
    {
        get
        {
            lock (_revokedNow)
            {
                return [.. _revokedNow.Keys];
            }
        }
    }

    /// <summary>Adds a signer's certificate to the intermediate CA's CRL, as if it were revoked now.</summary>
    public void Revoke(string signerId)
    {
        var signer = Signer(signerId);
        lock (_revokedNow)
        {
            _revokedNow[signerId] = new BigInteger(signer.Certificate.SerialNumberBytes.Span, isUnsigned: true, isBigEndian: true);
            IntermediateCrl = BuildCrl(Intermediate, _intermediateKey, _revoked.Concat(_revokedNow.Values));
        }
    }

    /// <summary>Takes back every revocation made with <see cref="Revoke"/>.</summary>
    public void RestoreRevocations()
    {
        lock (_revokedNow)
        {
            _revokedNow.Clear();
            IntermediateCrl = BuildCrl(Intermediate, _intermediateKey, _revoked);
        }
    }

    /// <summary>The CRLs as they would be after their nextUpdate has passed (for the "expired CRL" fault).</summary>
    public (byte[] Root, byte[] Intermediate) ExpiredCrls()
    {
        lock (_revokedNow)
        {
            return (BuildCrl(Root, _rootKey, [], expired: true), BuildCrl(Intermediate, _intermediateKey, _revoked.Concat(_revokedNow.Values), expired: true));
        }
    }

    /// <summary>The certificates a validator needs besides the signer (intermediate and root).</summary>
    public IReadOnlyList<X509Certificate2> Chain => [Intermediate, Root];

    public SandboxSigner Signer(string id) =>
        Signers.FirstOrDefault(s => s.Id == id) ?? throw new KeyNotFoundException($"No sandbox signer '{id}'.");

    /// <summary>A sandbox signer valid only for <paramref name="lifetime"/> from now (to produce a signature whose certificate has since expired).</summary>
    public X509Certificate2 IssueShortLived(string subject, TimeSpan lifetime)
    {
        using var key = RSA.Create(2048);
        var now = DateTimeOffset.UtcNow;
        return Issue(subject, key, now.AddMinutes(-1), now.Add(lifetime));
    }

    public void Dispose()
    {
        _rootKey.Dispose();
        _intermediateKey.Dispose();
        TsaKey.Dispose();
        foreach (var owned in _owned)
        {
            owned.Dispose();
        }
    }

    private SandboxSigner Person(string id, string name, string description, SandboxKeyType keyType,
        DateTimeOffset? notBefore = null, DateTimeOffset? notAfter = null, bool revoke = false,
        X509KeyUsageFlags keyUsage = X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation, string? problem = null)
    {
        string holder = name.Split(" (")[0];
        string subject = $"CN={holder}, OU=Sandbox, O=SimpleSign TestBench, C=BR";
        var from = notBefore ?? DateTimeOffset.UtcNow.AddDays(-1);
        var to = notAfter ?? DateTimeOffset.UtcNow.AddYears(1);
        var certificate = keyType switch
        {
            SandboxKeyType.Rsa1024 or SandboxKeyType.Rsa2048 or SandboxKeyType.Rsa3072 or SandboxKeyType.Rsa4096 => IssueRsa(subject, keyType, from, to, keyUsage),
            _ => IssueEc(subject, keyType, from, to, keyUsage),
        };
        if (revoke)
        {
            _revoked.Add(new BigInteger(certificate.SerialNumberBytes.Span, isUnsigned: true, isBigEndian: true));
        }

        return new SandboxSigner(id, name, description, keyType, certificate, problem is null || problem == "No non-repudiation", problem);
    }

    private X509Certificate2 IssueRsa(string subject, SandboxKeyType type, DateTimeOffset from, DateTimeOffset to,
        X509KeyUsageFlags keyUsage)
    {
        using var key = RSA.Create(type switch { SandboxKeyType.Rsa1024 => 1024, SandboxKeyType.Rsa3072 => 3072, SandboxKeyType.Rsa4096 => 4096, _ => 2048 });
        return Issue(subject, key, from, to, keyUsage: keyUsage);
    }

    private X509Certificate2 IssueEc(string subject, SandboxKeyType type, DateTimeOffset from, DateTimeOffset to,
        X509KeyUsageFlags keyUsage)
    {
        using var key = ECDsa.Create(type switch
        {
            SandboxKeyType.EcdsaP384 => ECCurve.NamedCurves.nistP384,
            SandboxKeyType.EcdsaP521 => ECCurve.NamedCurves.nistP521,
            _ => ECCurve.NamedCurves.nistP256,
        });
        return Issue(subject, key, from, to, keyUsage: keyUsage);
    }

    private X509Certificate2 Issue(string subject, AsymmetricAlgorithm key, DateTimeOffset from, DateTimeOffset to,
        Oid[]? eku = null, bool ekuCritical = false,
        X509KeyUsageFlags keyUsage = X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation)
    {
        var request = key switch
        {
            RSA rsa => new CertificateRequest(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1),
            ECDsa ec => new CertificateRequest(subject, ec, HashAlgorithmName.SHA256),
            _ => throw new NotSupportedException(key.GetType().Name),
        };
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(keyUsage, true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            eku is null ? new OidCollection { new("1.3.6.1.5.5.7.3.2"), new("1.3.6.1.5.5.7.3.4") } : ToCollection(eku), ekuCritical));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        request.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(Intermediate, true, false));
        request.CertificateExtensions.Add(CertificateRevocationListBuilder.BuildCrlDistributionPointExtension([IntermediateCrlUri.AbsoluteUri]));
        // No AIA caIssuers: the chain is always embedded, and on macOS an AIA URL makes the OS trust
        // evaluation try to fetch it (about a second per certificate for an unresolvable host).
        // Not before the issuer: clamp, so an "expired" leaf still nests in the intermediate's validity.
        if (from < Intermediate.NotBefore)
        {
            from = Intermediate.NotBefore.ToUniversalTime().AddMinutes(1);
        }

        using var publicOnly = request.Create(Intermediate.SubjectName, X509SignatureGenerator.CreateForRSA(_intermediateKey, RSASignaturePadding.Pkcs1),
            from, to, NextSerial());
        // In-memory key (no keychain / key container): the key object is copied into the certificate.
        var certificate = key switch
        {
            RSA rsa => publicOnly.CopyWithPrivateKey(rsa),
            ECDsa ec => publicOnly.CopyWithPrivateKey(ec),
            _ => throw new NotSupportedException(),
        };
        _owned.Add(certificate);
        return certificate;
    }

    /// <summary>Reads the stored root if it is there, still has years to live and its key is with it.</summary>
    private X509Certificate2? LoadRoot(string? path, DateTimeOffset now)
    {
        if (path is null || !File.Exists(path))
        {
            return null;
        }

        try
        {
            string pem = File.ReadAllText(path);
            var certificate = X509Certificate2.CreateFromPem(pem);
            if (certificate.NotAfter < now.AddYears(11))
            {
                // Too close to the end of the intermediate CA's life: make a new root.
                certificate.Dispose();
                return null;
            }

            _rootKey.ImportFromPem(pem);
            using var publicKey = certificate.GetRSAPublicKey();
            if (publicKey is null || !publicKey.ExportSubjectPublicKeyInfo().AsSpan().SequenceEqual(_rootKey.ExportSubjectPublicKeyInfo()))
            {
                certificate.Dispose();
                return null;
            }

            _owned.Add(certificate);
            return certificate;
        }
        catch (Exception ex) when (ex is CryptographicException or ArgumentException or IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    /// <summary>Stores the root and its key (a test CA: nothing outside the sandbox should trust it).</summary>
    private X509Certificate2 SaveRoot(string? path, X509Certificate2 root)
    {
        if (path is null)
        {
            return root;
        }

        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllText(path, root.ExportCertificatePem() + "\n" + _rootKey.ExportPkcs8PrivateKeyPem() + "\n");
            if (!OperatingSystem.IsWindows())
            {
                File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // The root is simply not kept: the sandbox works, with a new root on the next start.
        }

        return root;
    }

    private X509Certificate2 BuildCa(string subject, RSA key, X509Certificate2? issuer, RSA? issuerKey, DateTimeOffset from, DateTimeOffset to, int pathLength)
    {
        var request = new CertificateRequest(subject, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, pathLength, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        X509Certificate2 certificate;
        if (issuer is null)
        {
            certificate = request.CreateSelfSigned(from, to);
        }
        else
        {
            request.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(issuer, true, false));
            request.CertificateExtensions.Add(CertificateRevocationListBuilder.BuildCrlDistributionPointExtension([RootCrlUri.AbsoluteUri]));
            using var publicOnly = request.Create(issuer.SubjectName, X509SignatureGenerator.CreateForRSA(issuerKey!, RSASignaturePadding.Pkcs1), from, to, NextSerial());
            certificate = X509CertificateLoader.LoadCertificate(publicOnly.RawData);
        }

        var publicCopy = X509CertificateLoader.LoadCertificate(certificate.RawData);
        certificate.Dispose();
        _owned.Add(publicCopy);
        return publicCopy;
    }

    private static byte[] BuildCrl(X509Certificate2 issuer, RSA issuerKey, IEnumerable<BigInteger> revoked, bool expired = false)
    {
        var builder = new CertificateRevocationListBuilder();
        foreach (var serial in revoked)
        {
            builder.AddEntry(serial.ToByteArray(isUnsigned: true, isBigEndian: true), DateTimeOffset.UtcNow.AddDays(-1), X509RevocationReason.KeyCompromise);
        }

        var now = DateTimeOffset.UtcNow;
        return builder.Build(issuer.SubjectName, X509SignatureGenerator.CreateForRSA(issuerKey, RSASignaturePadding.Pkcs1),
            BigInteger.One, expired ? now.AddDays(-1) : now.AddDays(7), HashAlgorithmName.SHA256,
            X509AuthorityKeyIdentifierExtension.CreateFromCertificate(issuer, true, false), expired ? now.AddDays(-8) : now.AddMinutes(-5));
    }

    private byte[] NextSerial()
    {
        long serial = Interlocked.Increment(ref _serial);
        var bytes = new byte[9];
        RandomNumberGenerator.Fill(bytes.AsSpan(0, 5));
        bytes[0] &= 0x7F;
        BitConverter.TryWriteBytes(bytes.AsSpan(5), (int)serial);
        return bytes;
    }

    private static OidCollection ToCollection(Oid[] oids)
    {
        var collection = new OidCollection();
        foreach (var oid in oids)
        {
            collection.Add(oid);
        }

        return collection;
    }
}

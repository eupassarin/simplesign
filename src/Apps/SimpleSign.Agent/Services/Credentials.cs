using System.Security.Cryptography.X509Certificates;
using SimpleSign.Agent.Localization;
using SimpleSign.Brazil.IcpBrasil;
using SimpleSign.Core.Signing;
using SimpleSign.Signers.Pkcs11;

namespace SimpleSign.Agent.Services;

/// <summary>Where a signing certificate lives.</summary>
internal enum CertificateSourceKind
{
    /// <summary>A PFX/P12 file (A1).</summary>
    File,

    /// <summary>The OS certificate store (Windows store, macOS keychain).</summary>
    Store,

    /// <summary>An A3 token or smartcard, through its PKCS#11 driver.</summary>
    Token,
}

/// <summary>A token key: the driver, the token and the key's certificate.</summary>
internal sealed record TokenKey(string LibraryPath, string DriverName, string TokenLabel, string TokenSerial, string? KeyLabel, bool HasPinPad);

/// <summary>A certificate the user can sign with.</summary>
internal sealed record CertificateEntry(CertificateSourceKind Kind, X509Certificate2 Certificate, TokenKey? Token = null, string? FilePath = null)
{
    public string Holder => Certificate.GetNameInfo(X509NameType.SimpleName, false);

    public string Issuer => Certificate.GetNameInfo(X509NameType.SimpleName, true);

    public string Source => Kind switch
    {
        CertificateSourceKind.Token => $"Token {Token!.TokenLabel.Trim()} · {Token.DriverName}",
        CertificateSourceKind.File => L.T("cert.source.file", Path.GetFileName(FilePath)),
        _ => L.T(OperatingSystem.IsMacOS() ? "cert.source.keychain" : "cert.source.store"),
    };

    public string Validity => L.T("cert.validUntil", Certificate.NotAfter.ToString("d", L.Culture));

    public bool IsExpired => Certificate.NotAfter < DateTime.Now;

    public string? Document
    {
        get
        {
            var (cpf, cnpj) = IcpBrasilChainValidator.ExtractCpfCnpj(Certificate);
            return cpf is not null ? $"CPF {FormatCpf(cpf)}" : cnpj is not null ? $"CNPJ {FormatCnpj(cnpj)}" : null;
        }
    }

    /// <summary>The holder's CPF or CNPJ with most digits hidden, for display.</summary>
    public string? MaskedDocument
    {
        get
        {
            var (cpf, cnpj) = IcpBrasilChainValidator.ExtractCpfCnpj(Certificate);
            return cpf is { Length: 11 } ? $"CPF ***.{cpf[3..6]}.{cpf[6..9]}-**"
                : cnpj is { Length: 14 } ? $"CNPJ {cnpj[..2]}.***.***/{cnpj[8..12]}-**"
                : null;
        }
    }

    public bool IsIcpBrasil => IcpBrasilChainValidator.IsIcpBrasilCertificate(Certificate);

    public string Display => $"{Holder} — {Source}";

    private static string FormatCpf(string d) => d.Length == 11 ? $"{d[..3]}.{d[3..6]}.{d[6..9]}-{d[9..]}" : d;

    private static string FormatCnpj(string d) => d.Length == 14 ? $"{d[..2]}.{d[2..5]}.{d[5..8]}/{d[8..12]}-{d[12..]}" : d;
}

/// <summary>An opened signing credential: a local key, or a token session behind <see cref="IExternalSigner"/>.</summary>
internal sealed class SigningCredential : IDisposable
{
    private readonly IDisposable? _owned;

    public SigningCredential(X509Certificate2 certificate, IReadOnlyList<X509Certificate2> chain, IExternalSigner? external, IDisposable? owned)
    {
        Certificate = certificate;
        Chain = chain;
        External = external;
        _owned = owned;
    }

    public X509Certificate2 Certificate { get; }

    public IReadOnlyList<X509Certificate2> Chain { get; }

    public IExternalSigner? External { get; }

    public void Dispose() => _owned?.Dispose();
}

/// <summary>Lists certificates from every source and opens them for signing.</summary>
internal static class CertificateService
{
    /// <summary>Signing certificates with a private key in the OS store.</summary>
    public static IReadOnlyList<CertificateEntry> ListStore()
    {
        var result = new List<CertificateEntry>();
        try
        {
            using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
            foreach (var certificate in store.Certificates)
            {
                if (certificate.HasPrivateKey && CanSign(certificate))
                {
                    result.Add(new CertificateEntry(CertificateSourceKind.Store, certificate));
                }
            }
        }
        catch (System.Security.Cryptography.CryptographicException)
        {
            // No store (e.g. a Linux user without one).
        }

        return result;
    }

    /// <summary>Certificates on the connected tokens of every installed driver (no PIN needed).</summary>
    public static async Task<(IReadOnlyList<CertificateEntry> Certificates, IReadOnlyList<Pkcs11DriverTokens> Drivers)> ListTokensAsync(CancellationToken cancellationToken)
    {
        var drivers = await Pkcs11Drivers.FindTokensAsync(cancellationToken);
        var entries = new List<CertificateEntry>();
        foreach (var driver in drivers)
        {
            foreach (var token in driver.Tokens)
            {
                foreach (var certificate in token.Certificates.Where(c => CanSign(c.Certificate)))
                {
                    entries.Add(new CertificateEntry(CertificateSourceKind.Token, certificate.Certificate,
                        new TokenKey(driver.Driver.LibraryPath, driver.Driver.Driver.Product, token.Label, token.SerialNumber,
                            certificate.Label, token.HasProtectedAuthenticationPath)));
                }
            }
        }

        return (entries, drivers);
    }

    /// <summary>Loads a PFX/P12 file.</summary>
    /// <exception cref="System.Security.Cryptography.CryptographicException">Wrong password or not a PFX.</exception>
    public static CertificateEntry LoadFile(string path, string? password)
    {
        var certificate = X509CertificateLoader.LoadPkcs12FromFile(path, password, KeyStorage);
        return new CertificateEntry(CertificateSourceKind.File, certificate, FilePath: path);
    }

    /// <summary>Keys stay in memory where the platform allows it (macOS does not support ephemeral keys).</summary>
    public static X509KeyStorageFlags KeyStorage => OperatingSystem.IsMacOS() ? X509KeyStorageFlags.DefaultKeySet : X509KeyStorageFlags.EphemeralKeySet;

    /// <summary>Opens a certificate for signing. Tokens need the PIN (null for a PIN pad).</summary>
    public static SigningCredential Open(CertificateEntry entry, string? pin)
    {
        ArgumentNullException.ThrowIfNull(entry);
        if (entry.Kind != CertificateSourceKind.Token)
        {
            return new SigningCredential(entry.Certificate, [], null, null);
        }

        var key = entry.Token!;
#pragma warning disable CA2000 // Owned by the returned credential.
        var token = Pkcs11Signer.Open(new Pkcs11SignerOptions
        {
            LibraryPath = key.LibraryPath,
            TokenSerial = key.TokenSerial,
            CertificateThumbprint = entry.Certificate.Thumbprint,
            Pin = pin,
        });
#pragma warning restore CA2000
        return new SigningCredential(token.Certificate, token.Chain, token, token);
    }

    private static bool CanSign(X509Certificate2 certificate)
    {
        var usage = certificate.Extensions.OfType<X509KeyUsageExtension>().FirstOrDefault();
        return usage is null || (usage.KeyUsages & (X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation)) != 0;
    }
}

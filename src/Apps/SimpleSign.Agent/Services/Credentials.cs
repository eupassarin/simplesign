using System.Security.Cryptography.X509Certificates;
using SimpleSign.Agent.Localization;
using SimpleSign.Brazil.IcpBrasil;
using SimpleSign.Core.Policies;
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
/// <param name="LibraryPath">The PKCS#11 library that sees the token.</param>
/// <param name="DriverName">The driver's product name.</param>
/// <param name="TokenLabel">The token's label.</param>
/// <param name="TokenSerial">The token's serial number.</param>
/// <param name="KeyLabel">The key's label on the token.</param>
/// <param name="HasPinPad">Whether the PIN is typed on the reader instead of in the agent.</param>
internal sealed record TokenKey(
    string LibraryPath, string DriverName, string TokenLabel, string TokenSerial, string? KeyLabel, bool HasPinPad)
{
    /// <summary>Whether a wrong PIN was typed since the last good one (<c>CKF_USER_PIN_COUNT_LOW</c>).</summary>
    public bool IsPinCountLow { get; init; }

    /// <summary>Whether one more wrong PIN locks the token (<c>CKF_USER_PIN_FINAL_TRY</c>).</summary>
    public bool IsPinFinalTry { get; init; }

    /// <summary>Whether the PIN is still the issuer's and must be changed (<c>CKF_USER_PIN_TO_BE_CHANGED</c>).</summary>
    public bool IsPinToBeChanged { get; init; }

    /// <summary>The warning to show before the PIN is asked for; null when there is nothing to warn about.</summary>
    public string? PinWarning =>
        IsPinFinalTry ? L.T("pin.warn.finalTry")
        : IsPinToBeChanged ? L.T("pin.warn.mustChange")
        : IsPinCountLow ? L.T("pin.warn.countLow")
        : null;

    /// <summary>Whether <see cref="PinWarning"/> is about losing the card, so it is shown as an error.</summary>
    public bool IsPinWarningSevere => IsPinFinalTry;
}

/// <summary>A certificate the user can sign with.</summary>
/// <remarks>
/// Everything this record shows is read from the certificate once, here, while the handle is certainly alive. The
/// window redraws a certificate row whenever the agent logs something or the language changes, and such a redraw can
/// run after whoever listed the certificates released them; every member of <see cref="X509Certificate2"/> revalidates
/// the handle and throws <c>m_safeCertContext is an invalid handle</c> once it is disposed.
/// </remarks>
internal sealed record CertificateEntry(CertificateSourceKind Kind, X509Certificate2 Certificate, TokenKey? Token = null, string? FilePath = null)
{
    private readonly DateTime _notAfter = Certificate.NotAfter;
    private readonly (string? Plain, string? Masked) _document = ReadDocument(Certificate);

    /// <summary>The holder's common name.</summary>
    public string Holder { get; } = Certificate.GetNameInfo(X509NameType.SimpleName, false);

    /// <summary>The issuer's common name.</summary>
    public string Issuer { get; } = Certificate.GetNameInfo(X509NameType.SimpleName, true);

    /// <summary>Where the certificate came from, in the user's language.</summary>
    public string Source => Kind switch
    {
        CertificateSourceKind.Token => $"Token {Token!.TokenLabel.Trim()} · {Token.DriverName}",
        CertificateSourceKind.File => L.T("cert.source.file", Path.GetFileName(FilePath)),
        _ => L.T(OperatingSystem.IsMacOS() ? "cert.source.keychain" : "cert.source.store"),
    };

    /// <summary>How long the certificate is valid, in the user's language.</summary>
    public string Validity => L.T("cert.validUntil", _notAfter.ToString("d", L.Culture));

    /// <summary>Whether the certificate has expired.</summary>
    public bool IsExpired => _notAfter < DateTime.Now;

    /// <summary>Whole days until the certificate expires; negative once it has.</summary>
    public int DaysLeft => (int)Math.Floor((_notAfter - DateTime.Now).TotalDays);

    /// <summary>
    /// Why a server with SimpleSign's default signing policy refuses this certificate: "keyUsage" when the key usage
    /// allows neither digitalSignature nor nonRepudiation (or is missing), "weakKey" for a key the policy finds too
    /// small; else null. The checks are those of <see cref="SigningPolicy.Default"/>.
    /// </summary>
    public string? PolicyIssue { get; } = ReadPolicyIssue(Certificate);

    /// <summary>The holder's CPF or CNPJ, formatted; null when the certificate carries neither.</summary>
    public string? Document => _document.Plain;

    /// <summary>The holder's CPF or CNPJ with most digits hidden, for display.</summary>
    public string? MaskedDocument => _document.Masked;

    /// <summary>Whether the certificate was issued under ICP-Brasil.</summary>
    public bool IsIcpBrasil { get; } = IcpBrasilChainValidator.IsIcpBrasilCertificate(Certificate);

    /// <summary>The holder and the source on one line, for a list.</summary>
    public string Display => $"{Holder} — {Source}";

    private static string? ReadPolicyIssue(X509Certificate2 certificate)
    {
        var findings = SigningPolicy.Default.Evaluate(certificate, DateTimeOffset.UtcNow)
            .Where(f => f.Level == ConstraintLevel.Fail)
            .ToList();
        return findings.Exists(f => f.Reason == SigningErrorReason.KeyUsageNotPermitted) ? "keyUsage"
            : findings.Exists(f => f.Reason == SigningErrorReason.KeyTooWeak) ? "weakKey"
            : null;
    }

    private static (string? Plain, string? Masked) ReadDocument(X509Certificate2 certificate)
    {
        var (cpf, cnpj) = IcpBrasilChainValidator.ExtractCpfCnpj(certificate);
        string? plain = cpf is not null ? $"CPF {FormatCpf(cpf)}" : cnpj is not null ? $"CNPJ {FormatCnpj(cnpj)}" : null;
        string? masked = cpf is { Length: 11 } ? $"CPF ***.{cpf[3..6]}.{cpf[6..9]}-**"
            : cnpj is { Length: 14 } ? $"CNPJ {cnpj[..2]}.***.***/{cnpj[8..12]}-**"
            : null;
        return (plain, masked);
    }

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
                            certificate.Label, token.HasProtectedAuthenticationPath)
                        {
                            IsPinCountLow = token.IsPinCountLow,
                            IsPinFinalTry = token.IsPinFinalTry,
                            IsPinToBeChanged = token.IsPinToBeChanged,
                        }));
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

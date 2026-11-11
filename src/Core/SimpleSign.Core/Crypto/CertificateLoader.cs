using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace SimpleSign.Core.Crypto;

/// <summary>
/// Abstraction over certificate loading that works on both .NET 8 and .NET 9+.
/// On .NET 9+, delegates to X509CertificateLoader (AOT-safe, recommended).
/// On .NET 8, falls back to the <see cref="X509Certificate2"/> constructors.
/// </summary>
internal static class CertificateLoader
{
    /// <summary>
    /// The private key of a PFX is never exportable: signing only uses it in place, and nothing in SimpleSign copies it.
    /// It is kept in memory only (ephemeral), except on macOS, whose key store does not support ephemeral keys.
    /// </summary>
    private static X509KeyStorageFlags Pkcs12KeyStorageFlags =>
        OperatingSystem.IsMacOS()
            ? X509KeyStorageFlags.DefaultKeySet
            : X509KeyStorageFlags.EphemeralKeySet;

    /// <summary>Loads a DER-encoded X.509 certificate from a byte array.</summary>
    internal static X509Certificate2 LoadCertificate(byte[] data) =>
#if NET9_0_OR_GREATER
        X509CertificateLoader.LoadCertificate(data);
#else
        new X509Certificate2(data);
#endif


    /// <summary>Loads a DER-encoded X.509 certificate from a read-only span.</summary>
    internal static X509Certificate2 LoadCertificate(ReadOnlySpan<byte> data) =>
#if NET9_0_OR_GREATER
        X509CertificateLoader.LoadCertificate(data);
#else
        new X509Certificate2(data.ToArray());
#endif


    /// <summary>Loads a PKCS#12 (PFX) file from disk.</summary>
    internal static X509Certificate2 LoadPkcs12FromFile(string path, string? password) =>
#if NET9_0_OR_GREATER
        X509CertificateLoader.LoadPkcs12FromFile(
            path,
            password,
            Pkcs12KeyStorageFlags);
#else
        // On macOS + .NET 8, Apple Crypto rejects null password — use empty string.
        new X509Certificate2(
            path,
            password ?? string.Empty,
            Pkcs12KeyStorageFlags);
#endif


    /// <summary>
    /// Loads all certificates from a PKCS#12 (PFX) file, including any embedded chain certificates.
    /// Use this instead of <see cref="LoadPkcs12FromFile"/> when the chain is needed for LTV or CMS embedding.
    /// </summary>
    internal static X509Certificate2Collection LoadPkcs12CollectionFromFile(string path, string? password)
    {
        var bytes = File.ReadAllBytes(path);
        return LoadPkcs12Collection(bytes, password, Pkcs12KeyStorageFlags);
    }

    /// <summary>
    /// Loads a PKCS#12 (PFX) file and splits it into the signing certificate (the first
    /// certificate that has a private key) and the remaining certificates (its chain).
    /// </summary>
    /// <exception cref="ArgumentException">The file has no certificate with a private key.</exception>
    internal static (X509Certificate2 Signer, IReadOnlyList<X509Certificate2> Chain) LoadSigningCredentialFromFile(
        string path, string? password)
    {
        var certificates = LoadPkcs12CollectionFromFile(path, password).ToList();
        var signer = certificates.Find(c => c.HasPrivateKey);
        if (signer is null)
        {
            foreach (var certificate in certificates)
            {
                certificate.Dispose();
            }

            throw new ArgumentException("No certificate with a private key was found in the PFX file.", nameof(path));
        }

        var chain = certificates.Where(c => !ReferenceEquals(c, signer)).ToList().AsReadOnly();
        return (signer, chain);
    }

    /// <summary>Loads a PKCS#12 (PFX) from a byte array.</summary>
    internal static X509Certificate2 LoadPkcs12(byte[] data, string? password) =>
#if NET9_0_OR_GREATER
        X509CertificateLoader.LoadPkcs12(
            data,
            password,
            Pkcs12KeyStorageFlags);
#else
#pragma warning disable SYSLIB0057
        new X509Certificate2(
            data,
            password ?? string.Empty,
            Pkcs12KeyStorageFlags);
#pragma warning restore SYSLIB0057
#endif


    /// <summary>Loads a collection of certificates from a PKCS#12 (PFX) byte array.</summary>
    internal static X509Certificate2Collection LoadPkcs12Collection(
        byte[] data, string? password, X509KeyStorageFlags keyStorageFlags = X509KeyStorageFlags.DefaultKeySet)
    {
#if NET9_0_OR_GREATER
        return X509CertificateLoader.LoadPkcs12Collection(data, password, keyStorageFlags);
#else
        var col = new X509Certificate2Collection();
        col.Import(data, password ?? string.Empty, keyStorageFlags);
        return col;
#endif
    }

    /// <summary>
    /// Loads a collection of certificates from a PKCS#7 certificate bag (.p7b / .p7c).
    /// Used for AIA caIssuers downloads which often return P7B bundles containing
    /// the full intermediate chain up to the root.
    /// </summary>
    internal static X509Certificate2Collection LoadP7bCollection(byte[] data)
    {
        var col = new X509Certificate2Collection();
#pragma warning disable SYSLIB0057 // No clean P7B API exists on .NET 8+ without this
        col.Import(data);
#pragma warning restore SYSLIB0057
        return col;
    }

    /// <summary>
    /// Loads certificates from one or more PEM-encoded X.509 certificate blocks.
    /// Extracts each "-----BEGIN CERTIFICATE-----" / "-----END CERTIFICATE-----" block,
    /// decodes the Base64 payload, and returns all certificates found.
    /// Returns an empty collection if the data is not PEM-encoded.
    /// </summary>
    internal static X509Certificate2Collection LoadPemCertificates(byte[] data)
    {
        var result = new X509Certificate2Collection();
        var text = Encoding.ASCII.GetString(data);
        var reader = new StringReader(text);
        var pemBuilder = new StringBuilder();
        bool inCert = false;

        while (reader.ReadLine() is { } line)
        {
            if (line.Contains("BEGIN CERTIFICATE"))
            {
                inCert = true;
                pemBuilder.Clear();
            }
            else if (line.Contains("END CERTIFICATE") && inCert)
            {
                inCert = false;
                byte[] der = Convert.FromBase64String(pemBuilder.ToString());
                result.Add(LoadCertificate(der));
            }
            else if (inCert)
            {
                pemBuilder.Append(line);
            }
        }

        return result;
    }
}

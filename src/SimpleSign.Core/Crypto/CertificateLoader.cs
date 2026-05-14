using System.Security.Cryptography.X509Certificates;

namespace SimpleSign.Core.Crypto;

/// <summary>
/// Abstraction over certificate loading that works on both .NET 8 and .NET 9+.
/// On .NET 9+, delegates to X509CertificateLoader (AOT-safe, recommended).
/// On .NET 8, falls back to the <see cref="X509Certificate2"/> constructors.
/// </summary>
internal static class CertificateLoader
{
    /// <summary>Loads a DER-encoded X.509 certificate from a byte array.</summary>
    internal static X509Certificate2 LoadCertificate(byte[] data)
    {
#if NET9_0_OR_GREATER
        return X509CertificateLoader.LoadCertificate(data);
#else
#pragma warning disable SYSLIB0026 // X509Certificate2(byte[]) is obsolete
        return new X509Certificate2(data);
#pragma warning restore SYSLIB0026
#endif
    }

    /// <summary>Loads a DER-encoded X.509 certificate from a read-only span.</summary>
    internal static X509Certificate2 LoadCertificate(ReadOnlySpan<byte> data)
    {
#if NET9_0_OR_GREATER
        return X509CertificateLoader.LoadCertificate(data);
#else
#pragma warning disable SYSLIB0026
        return new X509Certificate2(data.ToArray());
#pragma warning restore SYSLIB0026
#endif
    }

    /// <summary>Loads a PKCS#12 (PFX) file from disk.</summary>
    internal static X509Certificate2 LoadPkcs12FromFile(string path, string? password)
    {
#if NET9_0_OR_GREATER
        return X509CertificateLoader.LoadPkcs12FromFile(path, password);
#else
#pragma warning disable SYSLIB0057
        // On macOS + .NET 8, Apple Crypto rejects null password — use empty string.
        return new X509Certificate2(path, password ?? string.Empty);
#pragma warning restore SYSLIB0057
#endif
    }

    /// <summary>
    /// Loads all certificates from a PKCS#12 (PFX) file, including any embedded chain certificates.
    /// Use this instead of <see cref="LoadPkcs12FromFile"/> when the chain is needed for LTV or CMS embedding.
    /// </summary>
    internal static X509Certificate2Collection LoadPkcs12CollectionFromFile(string path, string? password)
    {
        var bytes = File.ReadAllBytes(path);
        return LoadPkcs12Collection(bytes, password);
    }

    /// <summary>Loads a PKCS#12 (PFX) from a byte array.</summary>
    internal static X509Certificate2 LoadPkcs12(byte[] data, string? password)
    {
#if NET9_0_OR_GREATER
        return X509CertificateLoader.LoadPkcs12(data, password);
#else
#pragma warning disable SYSLIB0057
        return new X509Certificate2(data, password ?? string.Empty);
#pragma warning restore SYSLIB0057
#endif
    }

    /// <summary>Loads a collection of certificates from a PKCS#12 (PFX) byte array.</summary>
    internal static X509Certificate2Collection LoadPkcs12Collection(
        byte[] data, string? password, X509KeyStorageFlags keyStorageFlags = X509KeyStorageFlags.DefaultKeySet)
    {
#if NET9_0_OR_GREATER
        return X509CertificateLoader.LoadPkcs12Collection(data, password, keyStorageFlags);
#else
        var col = new X509Certificate2Collection();
#pragma warning disable SYSLIB0057
        col.Import(data, password ?? string.Empty, keyStorageFlags);
#pragma warning restore SYSLIB0057
        return col;
#endif
    }
}

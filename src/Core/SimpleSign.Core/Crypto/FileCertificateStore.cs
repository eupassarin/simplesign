using System.Security.Cryptography.X509Certificates;

namespace SimpleSign.Core.Crypto;

/// <summary>
/// Certificate store backed by PKCS#12 (.pfx/.p12) files in a directory.
/// </summary>
public sealed class FileCertificateStore : ICertificateStore, IDisposable
{
    private readonly List<X509Certificate2> _certificates = [];

    /// <summary>
    /// Creates a certificate store from a single PKCS#12 file.
    /// </summary>
    /// <param name="pfxPath">Path to the .pfx or .p12 file.</param>
    /// <param name="password">Password for the file.</param>
    public FileCertificateStore(string pfxPath, string? password)
    {
        var cert = CertificateLoader.LoadPkcs12FromFile(pfxPath, password);
        _certificates.Add(cert);
    }

    /// <summary>
    /// Creates a certificate store from all PKCS#12 files in a directory.
    /// </summary>
    /// <param name="directoryPath">Directory containing .pfx/.p12 files.</param>
    /// <param name="password">Password for all files (or null).</param>
    /// <param name="searchPattern">File search pattern. Default: "*.pfx".</param>
    public FileCertificateStore(string directoryPath, string? password, string searchPattern)
    {
        foreach (var file in Directory.GetFiles(directoryPath, searchPattern))
        {
            try
            {
                var cert = CertificateLoader.LoadPkcs12FromFile(file, password);
                _certificates.Add(cert);
            }
            catch (System.Security.Cryptography.CryptographicException)
            {
                // Skip files that can't be loaded (wrong password, corrupt, etc.)
            }
        }
    }

    /// <inheritdoc/>
    public X509Certificate2? FindByThumbprint(string thumbprint)
    {
        return _certificates.FirstOrDefault(c =>
            string.Equals(c.Thumbprint, thumbprint, StringComparison.OrdinalIgnoreCase));
    }

    /// <inheritdoc/>
    public IReadOnlyList<X509Certificate2> FindBySubject(string subjectName)
    {
        return _certificates
            .Where(c => c.Subject.Contains(subjectName, StringComparison.OrdinalIgnoreCase))
            .ToList()
            .AsReadOnly();
    }

    /// <inheritdoc/>
    public IReadOnlyList<X509Certificate2> ListAll() => _certificates.AsReadOnly();

    /// <inheritdoc/>
    public void Dispose()
    {
        foreach (var cert in _certificates)
        {
            cert.Dispose();
        }

        _certificates.Clear();
    }
}

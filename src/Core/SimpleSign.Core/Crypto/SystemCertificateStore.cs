using System.Security.Cryptography.X509Certificates;

namespace SimpleSign.Core.Crypto;

/// <summary>
/// Certificate store backed by the operating system's certificate store
/// (Windows Certificate Store, macOS Keychain, Linux NSS).
/// </summary>
public sealed class SystemCertificateStore : ICertificateStore, IDisposable
{
    private readonly X509Store _store;

    /// <summary>
    /// Opens the specified OS certificate store.
    /// </summary>
    /// <param name="storeName">Store name. Default: My (Personal).</param>
    /// <param name="storeLocation">Store location. Default: CurrentUser.</param>
    public SystemCertificateStore(
        StoreName storeName = StoreName.My,
        StoreLocation storeLocation = StoreLocation.CurrentUser)
    {
        _store = new X509Store(storeName, storeLocation);
        _store.Open(OpenFlags.ReadOnly);
    }

    /// <inheritdoc/>
    public X509Certificate2? FindByThumbprint(string thumbprint)
    {
        var found = _store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, validOnly: false);
        return found.Count > 0 ? found[0] : null;
    }

    /// <inheritdoc/>
    public IReadOnlyList<X509Certificate2> FindBySubject(string subjectName)
    {
        var found = _store.Certificates.Find(X509FindType.FindBySubjectName, subjectName, validOnly: false);
        return found.Cast<X509Certificate2>().ToList().AsReadOnly();
    }

    /// <inheritdoc/>
    public IReadOnlyList<X509Certificate2> ListAll() => _store.Certificates.Cast<X509Certificate2>().ToList().AsReadOnly();

    /// <inheritdoc/>
    public void Dispose()
    {
        _store.Close();
        _store.Dispose();
    }
}

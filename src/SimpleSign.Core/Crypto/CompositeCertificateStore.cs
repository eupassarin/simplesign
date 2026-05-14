using System.Security.Cryptography.X509Certificates;

namespace SimpleSign.Core.Crypto;

/// <summary>
/// Composite certificate store that searches multiple stores in order.
/// </summary>
public sealed class CompositeCertificateStore : ICertificateStore
{
    private readonly IReadOnlyList<ICertificateStore> _stores;

    /// <summary>Creates a composite store from multiple underlying stores.</summary>
    public CompositeCertificateStore(params ICertificateStore[] stores)
    {
        _stores = stores.ToList().AsReadOnly();
    }

    /// <inheritdoc/>
    public X509Certificate2? FindByThumbprint(string thumbprint)
    {
        foreach (var store in _stores)
        {
            var cert = store.FindByThumbprint(thumbprint);
            if (cert is not null)
            {
                return cert;
            }
        }

        return null;
    }

    /// <inheritdoc/>
    public IReadOnlyList<X509Certificate2> FindBySubject(string subjectName)
    {
        return _stores.SelectMany(s => s.FindBySubject(subjectName)).ToList().AsReadOnly();
    }

    /// <inheritdoc/>
    public IReadOnlyList<X509Certificate2> ListAll()
    {
        return _stores.SelectMany(s => s.ListAll()).ToList().AsReadOnly();
    }
}

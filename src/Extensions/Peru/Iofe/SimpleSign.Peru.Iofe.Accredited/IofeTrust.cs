using System.Security.Cryptography.X509Certificates;
using SimpleSign.Core.Extensions;
using SimpleSign.Core.Policies;

namespace SimpleSign.Peru.Iofe.Accredited;

/// <summary>
/// Whom the accredited configuration trusts. The guide gives two ways (its optional requirement, "verificación de la
/// confiabilidad del certificado"): INDECOPI's trusted list, or the root certificates the operator installed.
/// </summary>
public sealed class IofeTrust
{
    private static readonly TimeSpan RefreshInterval = TimeSpan.FromHours(6);

    private readonly IofeExtensionOptions? _listOptions;
    private readonly IofeExtension? _extension;
    private readonly IReadOnlyList<X509Certificate2>? _roots;

    private IofeTrust(IofeExtensionOptions? listOptions, IofeExtension? extension, IReadOnlyList<X509Certificate2>? roots)
    {
        _listOptions = listOptions;
        _extension = extension;
        _roots = roots;
    }

    /// <summary>
    /// INDECOPI's trusted list: downloaded, checked against the certificate INDECOPI signs it with, refused when it
    /// has expired, and read again every 6 hours and when it reaches its NextUpdate.
    /// </summary>
    /// <param name="options">Where the list is and how it is read; null for INDECOPI's, with the bundled signer.</param>
    /// <returns>The trust.</returns>
    public static IofeTrust IndecopiList(IofeExtensionOptions? options = null) => new(options ?? new IofeExtensionOptions(), null, null);

    /// <summary>A trusted list the application already loaded and keeps current itself.</summary>
    /// <param name="extension">The IOFE extension over the list.</param>
    /// <returns>The trust.</returns>
    public static IofeTrust List(IofeExtension extension)
    {
        ArgumentNullException.ThrowIfNull(extension);
        return new(null, extension, null);
    }

    /// <summary>
    /// The root certificates the operator installed (the guide's "consulta manual"): only certificates that chain to
    /// one of them sign or are accepted.
    /// </summary>
    /// <param name="roots">The root certificates.</param>
    /// <returns>The trust.</returns>
    /// <exception cref="ArgumentException"><paramref name="roots"/> is empty.</exception>
    public static IofeTrust InstalledRoots(IEnumerable<X509Certificate2> roots)
    {
        ArgumentNullException.ThrowIfNull(roots);
        X509Certificate2[] copy = [.. roots];
        return copy.Length == 0
            ? throw new ArgumentException("At least one root certificate is required.", nameof(roots))
            : new(null, null, copy);
    }

    /// <summary>The profile over this trust with the given policies, and what to dispose with it (a list this call loaded).</summary>
    internal async Task<(TrustProfile Profile, IAsyncDisposable? Owned)> ResolveAsync(
        SigningPolicy signing, ValidationPolicy validation, CancellationToken cancellationToken)
    {
        if (_roots is not null)
        {
            return (new TrustProfile(IofeProfile.Name, "Peru (IOFE)", signing, validation, [new InstalledRootsProvider(_roots)], []), null);
        }

        if (_extension is not null)
        {
            return (IofeProfile.Create(_extension) with { SigningPolicy = signing, ValidationPolicy = validation }, null);
        }

        var extension = await IofeExtension.LoadRefreshableAsync(_listOptions!, cancellationToken).ConfigureAwait(false);
        extension.Source?.StartAutoRefresh(RefreshInterval);
        return (IofeProfile.Create(extension) with { SigningPolicy = signing, ValidationPolicy = validation }, extension.Source);
    }

    private sealed class InstalledRootsProvider(IReadOnlyList<X509Certificate2> roots) : ITrustAnchorProvider
    {
        public string RegionCode => "PE";

        public string DisplayName => "IOFE — raíces instaladas por el operador";

        public IReadOnlyList<X509Certificate2> GetTrustAnchors() => roots;
    }
}

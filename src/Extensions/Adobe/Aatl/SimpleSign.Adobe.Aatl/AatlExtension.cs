using System.Security.Cryptography.X509Certificates;
using SimpleSign.Core.Extensions;

namespace SimpleSign.Adobe.Aatl;

/// <summary>
/// The Adobe Approved Trust List as a country extension: its anchors, with their policy restrictions
/// (<see cref="IConstrainedTrustAnchorProvider"/>). It adds no chain validation and no qualifier: the list says whom
/// Acrobat trusts, not what a signature is in any country's law.
/// </summary>
public sealed class AatlExtension : ICountryExtension
{
    private static readonly Lazy<IReadOnlyList<X509Certificate2>> s_listSigners = new(ReadBundledSigners);

    /// <summary>The extension over a list kept current.</summary>
    /// <param name="source">The list.</param>
    public AatlExtension(AatlSource source)
    {
        ArgumentNullException.ThrowIfNull(source);
        Source = source;
        TrustAnchorProviders = [source];
    }

    /// <summary>The extension over one copy of the list.</summary>
    /// <param name="list">The list.</param>
    public AatlExtension(AatlList list)
    {
        ArgumentNullException.ThrowIfNull(list);
        TrustAnchorProviders = [list];
    }

    /// <summary>
    /// The root bundled with the package that the list's signature must chain to: Adobe Root CA G2, whose SHA-256
    /// fingerprint Adobe publishes on its Trust Services page.
    /// </summary>
    public static IReadOnlyList<X509Certificate2> ListSigners => s_listSigners.Value;

    /// <inheritdoc />
    public string RegionCode => "AATL";

    /// <inheritdoc />
    public string DisplayName => "Adobe Approved Trust List";

    /// <summary>The list kept current, when the extension was made over one; null otherwise.</summary>
    public AatlSource? Source { get; }

    /// <summary>The list served now.</summary>
    public AatlList List => Source?.Current ?? (AatlList)TrustAnchorProviders[0];

    /// <inheritdoc />
    public IReadOnlyList<ITrustAnchorProvider> TrustAnchorProviders { get; }

    /// <inheritdoc />
    public IReadOnlyList<IChainValidationProvider> ChainValidationProviders => [];

    /// <summary>Downloads the list (kept current: see <see cref="AatlSource"/>) and creates the extension.</summary>
    /// <param name="options">Where the list is and how it is read; null for Adobe's, with the bundled root.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The extension.</returns>
#pragma warning disable CA2000 // The source lives as long as the extension that serves it (and its auto-refresh).
    public static async Task<AatlExtension> LoadAsync(AatlOptions? options = null, CancellationToken cancellationToken = default) =>
        new(await AatlSource.LoadAsync(options, cancellationToken).ConfigureAwait(false));
#pragma warning restore CA2000

    // The certificate is the package's, kept for the life of the process: not disposed.
#pragma warning disable CA2000
    private static List<X509Certificate2> ReadBundledSigners()
    {
        using var stream = typeof(AatlExtension).Assembly.GetManifestResourceStream("SimpleSign.Adobe.Aatl.Certs.adobe-root-ca-g2.pem")
            ?? throw new InvalidOperationException("The bundled Adobe root is missing from the package.");
        using var reader = new StreamReader(stream);
        return [X509Certificate2.CreateFromPem(reader.ReadToEnd())];
    }
#pragma warning restore CA2000
}

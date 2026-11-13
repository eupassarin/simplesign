using SimpleSign.Core.Extensions;
using SimpleSign.Core.Http;
using SimpleSign.XAdES.TrustedLists;

namespace SimpleSign.Peru.Iofe;

/// <summary>Where and how the INDECOPI trusted list is read.</summary>
public sealed record IofeExtensionOptions
{
    /// <summary>The location of INDECOPI's trusted list.</summary>
    public static Uri DefaultTrustedListUrl { get; } = new("https://iofe.indecopi.gob.pe/TSL/tsl-pe.xml");

    /// <summary>The trusted list location. Default: <see cref="DefaultTrustedListUrl"/>.</summary>
    public Uri TrustedListUrl { get; init; } = DefaultTrustedListUrl;

    /// <summary>
    /// The certificates INDECOPI signs the trusted list with. Required: obtain them from INDECOPI and check
    /// their fingerprint out of band; the list is refused when it is signed by any other key.
    /// </summary>
    public IReadOnlyList<System.Security.Cryptography.X509Certificates.X509Certificate2> TrustedListSigners { get; init; } = [];

    /// <summary>Where the last good copy of the list is kept, used when the download fails; null for none.</summary>
    public string? CacheFile { get; init; }

    /// <summary>The HTTP client; the default one when null.</summary>
    public IHttpClientProvider? HttpClientProvider { get; init; }

    /// <summary>
    /// Which services of the list become trust anchors. Null keeps <see cref="IofeExtension.DefaultListOptions"/>
    /// with <see cref="TrustedListSigners"/>.
    /// </summary>
    public TrustedListOptions? ListOptions { get; init; }
}

/// <summary>
/// The IOFE country extension (Peru, Ley 27269): its trust anchors are the active certification and
/// timestamping services of INDECOPI's trusted list. Use <see cref="IofePolicies"/> for the policies of the
/// INDECOPI accreditation guide.
/// </summary>
public sealed class IofeExtension : ICountryExtension
{
    private readonly TrustedList? _list;

    /// <summary>Creates the extension from a trusted list already read and checked.</summary>
    /// <param name="trustedList">INDECOPI's trusted list.</param>
    public IofeExtension(TrustedList trustedList)
    {
        ArgumentNullException.ThrowIfNull(trustedList);
        _list = trustedList;
    }

    /// <summary>
    /// Creates the extension from a list kept current (<see cref="IofeTrustedListSource"/>): its anchors are those of the
    /// copy the source serves at each use, so a refresh reaches every signer and validator holding the extension.
    /// </summary>
    /// <param name="source">INDECOPI's trusted list, refreshed.</param>
    public IofeExtension(IofeTrustedListSource source)
    {
        ArgumentNullException.ThrowIfNull(source);
        Source = source;
    }

    /// <summary>The refreshed list the anchors come from; null when the extension was created from a fixed list.</summary>
    public IofeTrustedListSource? Source { get; }

    /// <summary>
    /// The services of INDECOPI's list that become trust anchors: the defaults of <see cref="TrustedListOptions"/>
    /// (active CA and TSA services) plus the active services typed <c>Svctype/unspecified</c>, which is how the list
    /// publishes several accredited timestamping authorities (Llama.pe, BPO Advisors, Girasol). The same type holds
    /// the accredited signature software, whose code-signing certificates are left out.
    /// </summary>
    public static TrustedListOptions DefaultListOptions { get; } = new()
    {
        ServiceTypes = [.. new TrustedListOptions().ServiceTypes, "/unspecified"],
        ExcludedExtendedKeyUsages = [CodeSigningOid],
    };

    private const string CodeSigningOid = "1.3.6.1.5.5.7.3.3";

    /// <summary>The trusted list the anchors come from: with a <see cref="Source"/>, the copy it serves now.</summary>
    public TrustedList TrustedList => Source?.Current.List ?? _list!;

    /// <inheritdoc />
    public string RegionCode => "PE";

    /// <inheritdoc />
    public string DisplayName => "IOFE — Infraestructura Oficial de Firma Electrónica (Perú)";

    /// <inheritdoc />
    public IReadOnlyList<ITrustAnchorProvider> TrustAnchorProviders => Source is { } source ? [source] : [TrustedList];

    /// <inheritdoc />
    public IReadOnlyList<IChainValidationProvider> ChainValidationProviders => [];

    /// <summary>Downloads INDECOPI's trusted list, checks its signature and creates the extension.</summary>
    /// <param name="options">The list location, its signers and the cache.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The extension.</returns>
    public static async Task<IofeExtension> LoadAsync(IofeExtensionOptions options, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        var listOptions = ListOptionsOf(options);
        var list = await TrustedList.DownloadAsync(
            options.TrustedListUrl, listOptions, options.HttpClientProvider, options.CacheFile, cancellationToken).ConfigureAwait(false);
        return new IofeExtension(list);
    }

    /// <summary>
    /// Downloads INDECOPI's trusted list as <see cref="LoadAsync"/> does, and creates the extension over a source that keeps
    /// it current: call <see cref="IofeTrustedListSource.RefreshAsync"/> or <see cref="IofeTrustedListSource.StartAutoRefresh"/>
    /// on <see cref="Source"/>, or register it with
    /// <c>services.AddSimpleSignIofe(options)</c>.
    /// </summary>
    /// <param name="options">The list location, its signers and the cache.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The extension.</returns>
    public static async Task<IofeExtension> LoadRefreshableAsync(IofeExtensionOptions options, CancellationToken cancellationToken = default) =>
        new(await IofeTrustedListSource.LoadAsync(options, cancellationToken).ConfigureAwait(false));

    /// <summary>The list options of <paramref name="options"/>, with its signers; refuses options without signers.</summary>
    internal static TrustedListOptions ListOptionsOf(IofeExtensionOptions options)
    {
        if (options.TrustedListSigners.Count == 0)
        {
            throw new ArgumentException("The certificate INDECOPI signs the trusted list with is required (TrustedListSigners).", nameof(options));
        }

        return (options.ListOptions ?? DefaultListOptions) with { SignerCertificates = options.TrustedListSigners };
    }

    /// <summary>Reads INDECOPI's trusted list from bytes (a copy kept by the deployment) and creates the extension.</summary>
    /// <param name="trustedListXml">The trusted list XML.</param>
    /// <param name="trustedListSigners">The certificates INDECOPI signs the list with.</param>
    /// <returns>The extension.</returns>
    public static IofeExtension Load(byte[] trustedListXml, IReadOnlyList<System.Security.Cryptography.X509Certificates.X509Certificate2> trustedListSigners) =>
        new(TrustedList.Load(trustedListXml, DefaultListOptions with { SignerCertificates = trustedListSigners }));
}

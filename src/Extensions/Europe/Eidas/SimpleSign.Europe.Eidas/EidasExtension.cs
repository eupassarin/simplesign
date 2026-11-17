using System.Security.Cryptography.X509Certificates;
using SimpleSign.Core.Extensions;
using SimpleSign.Core.Http;
using SimpleSign.XAdES.TrustedLists;

namespace SimpleSign.Europe.Eidas;

/// <summary>Where the EU list of trusted lists is and how it is read.</summary>
public sealed record EidasExtensionOptions
{
    /// <summary>The EU LOTL: <c>https://ec.europa.eu/tools/lotl/eu-lotl.xml</c>.</summary>
    public static Uri DefaultLotlUrl => TrustedListSetOptions.EuropeanLotl;

    /// <summary>Where the LOTL is. Default: <see cref="DefaultLotlUrl"/>.</summary>
    public Uri LotlUrl { get; init; } = DefaultLotlUrl;

    /// <summary>
    /// The certificates the LOTL may be signed with; empty uses <see cref="EidasExtension.LotlSigners"/> (bundled). When
    /// the LOTL is signed by a newer key, the pivot LOTLs carry these forward (ETSI TS 119 612 §5.3.7).
    /// </summary>
    public IReadOnlyList<X509Certificate2> LotlSigners { get; init; } = [];

    /// <summary>The member states to load (<c>PT</c>, <c>DE</c>…); empty loads every list.</summary>
    public IReadOnlyList<string> Territories { get; init; } = [];

    /// <summary>A folder for the last good copy of each list, used when a download fails; null for none.</summary>
    public string? CacheDirectory { get; init; }

    /// <summary>The HTTP client; the default one when null.</summary>
    public IHttpClientProvider? HttpClientProvider { get; init; }

    /// <summary>
    /// Which services become trust anchors and how the lists are read; null for <see cref="EidasExtension.DefaultListOptions"/>.
    /// Its <see cref="TrustedListOptions.SignerCertificates"/> is ignored: each list's come from the LOTL.
    /// </summary>
    public TrustedListOptions? ListOptions { get; init; }
}

/// <summary>
/// eIDAS (EU Regulation 910/2014) as a country extension: the trust anchors of the EU trusted lists
/// (<see cref="EidasTrustedListSource"/>, or a <see cref="TrustedListSet"/> already loaded), and the
/// <see cref="EidasQualifier"/> that gives each validated signature its qualification (QESig, AdESig-QC…).
/// </summary>
public sealed class EidasExtension : ICountryExtension
{
    private static readonly Lazy<IReadOnlyList<X509Certificate2>> s_lotlSigners = new(ReadBundledSigners);

    /// <summary>Over a LOTL source kept current.</summary>
    /// <param name="source">The source.</param>
    public EidasExtension(EidasTrustedListSource source)
    {
        ArgumentNullException.ThrowIfNull(source);
        TrustAnchorProviders = [source];
        Qualifier = new EidasQualifier(() => source.Current.Lists);
        Source = source;
    }

    /// <summary>Over a LOTL and its lists already loaded.</summary>
    /// <param name="set">The set.</param>
    public EidasExtension(TrustedListSet set)
    {
        ArgumentNullException.ThrowIfNull(set);
        TrustAnchorProviders = [set];
        Qualifier = new EidasQualifier(set);
    }

    /// <summary>Over one list or anchors and a qualifier (tests).</summary>
    internal EidasExtension(ITrustAnchorProvider anchors, EidasQualifier qualifier)
    {
        TrustAnchorProviders = [anchors];
        Qualifier = qualifier;
    }

    /// <summary>
    /// The certificates the EU LOTL is signed with, bundled with the package: the keys the LOTL names for itself
    /// (TSLType EUlistofthelists), announced in the Official Journal (C/2026/1944). The pivot LOTLs carry them forward
    /// when the Commission changes them. Their SHA-256 fingerprints are in the package README.
    /// </summary>
    public static IReadOnlyList<X509Certificate2> LotlSigners => s_lotlSigners.Value;

    /// <summary>
    /// The services that become anchors: CA/QC, CA/PKC, TSA/QTST and TSA of a granted status (the
    /// <see cref="TrustedListOptions"/> defaults), an expired list refused.
    /// </summary>
    public static TrustedListOptions DefaultListOptions { get; } = new();

    /// <inheritdoc />
    public string RegionCode => "EU";

    /// <inheritdoc />
    public string DisplayName => "eIDAS (EU trusted lists)";

    /// <summary>The source kept current, when built over one.</summary>
    public EidasTrustedListSource? Source { get; }

    /// <summary>The qualifier over the extension's lists.</summary>
    public EidasQualifier Qualifier { get; }

    /// <inheritdoc />
    public IReadOnlyList<ITrustAnchorProvider> TrustAnchorProviders { get; }

    /// <inheritdoc />
    public IReadOnlyList<IChainValidationProvider> ChainValidationProviders => [];

    /// <inheritdoc />
    public IReadOnlyList<ISignatureQualifier> SignatureQualifiers => [Qualifier];

    /// <summary>Loads the LOTL and its lists once.</summary>
    /// <param name="options">Where the LOTL is; null for the EU's, with the bundled signers.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The extension.</returns>
    public static async Task<EidasExtension> LoadAsync(EidasExtensionOptions? options = null, CancellationToken cancellationToken = default) =>
        new(await TrustedListSet.LoadAsync(SetOptionsOf(options ?? new EidasExtensionOptions()), (options ?? new EidasExtensionOptions()).HttpClientProvider,
            cancellationToken).ConfigureAwait(false));

    /// <summary>Loads the LOTL and its lists, kept current by <see cref="EidasTrustedListSource.RefreshAsync"/> or <see cref="EidasTrustedListSource.StartAutoRefresh"/>.</summary>
    /// <param name="options">Where the LOTL is; null for the EU's, with the bundled signers.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The extension.</returns>
#pragma warning disable CA2000 // The source lives as long as the extension that serves it (and its auto-refresh).
    public static async Task<EidasExtension> LoadRefreshableAsync(EidasExtensionOptions? options = null, CancellationToken cancellationToken = default) =>
        new(await EidasTrustedListSource.LoadAsync(options ?? new EidasExtensionOptions(), cancellationToken).ConfigureAwait(false));
#pragma warning restore CA2000

    /// <summary>The <see cref="TrustedListSetOptions"/> of <paramref name="options"/>, the bundled signers when none is given.</summary>
    internal static TrustedListSetOptions SetOptionsOf(EidasExtensionOptions options, IReadOnlyList<X509Certificate2>? knownSigners = null) => new()
    {
        LotlLocation = options.LotlUrl,
        LotlSignerCertificates = [.. knownSigners ?? [], .. options.LotlSigners.Count > 0 ? options.LotlSigners : LotlSigners],
        Territories = options.Territories,
        CacheDirectory = options.CacheDirectory,
        Services = options.ListOptions ?? DefaultListOptions,
    };

    private static List<X509Certificate2> ReadBundledSigners()
    {
        using var stream = typeof(EidasExtension).Assembly.GetManifestResourceStream("SimpleSign.Europe.Eidas.Certs.eu-lotl-signers.pem")
            ?? throw new InvalidOperationException("The bundled EU LOTL signers are missing from the package.");
        using var reader = new StreamReader(stream);
        var certificates = new X509Certificate2Collection();
        certificates.ImportFromPem(reader.ReadToEnd());
        return [.. certificates];
    }
}

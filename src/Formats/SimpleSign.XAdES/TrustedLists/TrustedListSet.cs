using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SimpleSign.Core.Extensions;
using SimpleSign.Core.Http;

namespace SimpleSign.XAdES.TrustedLists;

/// <summary>How a <see cref="TrustedListSet"/> loads a list of trusted lists (LOTL) and the lists it points to.</summary>
public sealed record TrustedListSetOptions
{
    /// <summary>The location of the EU list of trusted lists.</summary>
    public static Uri EuropeanLotl { get; } = new("https://ec.europa.eu/tools/lotl/eu-lotl.xml");

    /// <summary>Where the LOTL is. Default: <see cref="EuropeanLotl"/>.</summary>
    public Uri LotlLocation { get; init; } = EuropeanLotl;

    /// <summary>
    /// The certificates the LOTL must be signed with. Required: for the EU LOTL, the certificates the Official Journal
    /// of the EU publishes. The national lists are checked with the certificates the LOTL gives for each.
    /// </summary>
    public IReadOnlyList<X509Certificate2> LotlSignerCertificates { get; init; } = [];

    /// <summary>The territories to load (<c>PT</c>, <c>DE</c>…); empty loads every list the LOTL points to.</summary>
    public IReadOnlyList<string> Territories { get; init; } = [];

    /// <summary>Which services of the national lists become trust anchors.</summary>
    public TrustedListOptions Services { get; init; } = new();

    /// <summary>
    /// A folder where each list read successfully is kept. A kept list whose NextUpdate has not passed is used without
    /// downloading it again; when a download fails, the kept list is used while it has not expired. Null: no cache.
    /// </summary>
    public string? CacheDirectory { get; init; }
}

/// <summary>A national list that could not be loaded.</summary>
/// <param name="Territory">The list's territory.</param>
/// <param name="Location">Its location.</param>
/// <param name="Reason">Why it was not loaded.</param>
public sealed record TrustedListProblem(string Territory, Uri Location, string Reason);

/// <summary>
/// The trusted lists of a list of trusted lists (LOTL, ETSI TS 119 612), loaded as the EU DSS trusted list validation
/// job does: the LOTL is checked with the configured certificates, each list it points to with the certificates the
/// LOTL gives for it, and the anchors of every list loaded become trust anchors. A list that cannot be loaded is
/// reported in <see cref="Problems"/> instead of failing the whole set.
/// </summary>
public sealed class TrustedListSet : ITrustAnchorProvider, ITrustedListInfoProvider
{
    private const string XmlMimeType = "application/vnd.etsi.tsl+xml";

    private TrustedListSet(TrustedList lotl, IReadOnlyList<TrustedList> lists, IReadOnlyList<TrustedListProblem> problems)
    {
        Lotl = lotl;
        Lists = lists;
        Problems = problems;
    }

    /// <summary>The list of trusted lists.</summary>
    public TrustedList Lotl { get; }

    /// <summary>The national lists loaded.</summary>
    public IReadOnlyList<TrustedList> Lists { get; }

    /// <summary>The national lists that could not be loaded.</summary>
    public IReadOnlyList<TrustedListProblem> Problems { get; }

    /// <inheritdoc />
    public string RegionCode => Lotl.Territory;

    /// <inheritdoc />
    public string DisplayName => $"Trusted lists of {Lotl.Territory} ({Lists.Count} lists)";

    /// <inheritdoc />
    public IReadOnlyList<X509Certificate2> GetTrustAnchors() => [.. Lists.SelectMany(l => l.GetTrustAnchors())];

    /// <inheritdoc />
    public IReadOnlyList<X509Certificate2> GetIntermediateCertificates() => [.. Lists.SelectMany(l => l.GetIntermediateCertificates())];

    /// <inheritdoc />
    public IReadOnlyList<TrustedListInfo> TrustedLists => [.. Lists.SelectMany(l => l.TrustedLists)];

    /// <summary>Loads the LOTL and the lists it points to.</summary>
    /// <param name="options">The LOTL, its certificates, the territories and the cache.</param>
    /// <param name="httpClientProvider">The HTTP client; the default one when null.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The loaded set.</returns>
    /// <exception cref="ArgumentException">No LOTL signer certificate is given.</exception>
    /// <exception cref="CryptographicException">The LOTL is not signed by one of its certificates.</exception>
    /// <exception cref="HttpRequestException">The LOTL cannot be downloaded and has no usable cached copy.</exception>
    public static async Task<TrustedListSet> LoadAsync(
        TrustedListSetOptions options, IHttpClientProvider? httpClientProvider = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (options.LotlSignerCertificates.Count == 0)
        {
            throw new ArgumentException("The certificates the list of trusted lists must be signed with are required.", nameof(options));
        }

        if (options.CacheDirectory is not null)
        {
            Directory.CreateDirectory(options.CacheDirectory);
        }

        var lotl = await LoadOneAsync(
            options.LotlLocation, options.Services with { SignerCertificates = options.LotlSignerCertificates },
            CacheFile(options, "lotl"), httpClientProvider, cancellationToken).ConfigureAwait(false);

        var lists = new List<TrustedList>();
        var problems = new List<TrustedListProblem>();
        foreach (var pointer in lotl.Pointers)
        {
            if (pointer.MimeType is { } mime && !string.Equals(mime, XmlMimeType, StringComparison.OrdinalIgnoreCase))
            {
                continue; // The PDF copy of a list.
            }

            if (options.Territories.Count > 0 && !options.Territories.Contains(pointer.Territory, StringComparer.OrdinalIgnoreCase))
            {
                continue;
            }

            if (string.Equals(pointer.Territory, lotl.Territory, StringComparison.OrdinalIgnoreCase) && pointer.Location == options.LotlLocation)
            {
                continue; // The LOTL's pointer to itself.
            }

            if (pointer.SignerCertificates.Count == 0)
            {
                problems.Add(new TrustedListProblem(pointer.Territory, pointer.Location, "The LOTL gives no certificate to check this list."));
                continue;
            }

            try
            {
                lists.Add(await LoadOneAsync(
                    pointer.Location, options.Services with { SignerCertificates = pointer.SignerCertificates },
                    CacheFile(options, pointer.Territory), httpClientProvider, cancellationToken).ConfigureAwait(false));
            }
            catch (Exception ex) when (ex is HttpRequestException or CryptographicException or InvalidDataException or TaskCanceledException)
            {
                if (ex is TaskCanceledException && cancellationToken.IsCancellationRequested)
                {
                    throw;
                }

                problems.Add(new TrustedListProblem(pointer.Territory, pointer.Location, ex.Message));
            }
        }

        return new TrustedListSet(lotl, lists, problems);
    }

    /// <summary>
    /// A list: the cached copy while its NextUpdate has not passed, else downloaded (and the cache refreshed), else the
    /// cached copy while it has not expired.
    /// </summary>
    private static async Task<TrustedList> LoadOneAsync(
        Uri location, TrustedListOptions options, string? cacheFile, IHttpClientProvider? httpClientProvider, CancellationToken cancellationToken)
    {
        if (cacheFile is not null && File.Exists(cacheFile))
        {
            try
            {
                var cached = TrustedList.Load(await File.ReadAllBytesAsync(cacheFile, cancellationToken).ConfigureAwait(false), options)
                    .WithOrigin(location, File.GetLastWriteTimeUtc(cacheFile));
                if (cached.NextUpdate is { } next && next > DateTimeOffset.UtcNow)
                {
                    return cached;
                }
            }
            catch (Exception ex) when (ex is CryptographicException or InvalidDataException)
            {
                // A stale or bad copy: download the list again.
            }
        }

        return await TrustedList.DownloadAsync(location, options, httpClientProvider, cacheFile, cancellationToken).ConfigureAwait(false);
    }

    private static string? CacheFile(TrustedListSetOptions options, string name) =>
        options.CacheDirectory is null ? null : Path.Combine(options.CacheDirectory, $"tl-{Sanitize(name)}.xml");

    private static string Sanitize(string name) =>
        string.Concat(name.Select(c => char.IsAsciiLetterOrDigit(c) ? c : '_'));
}

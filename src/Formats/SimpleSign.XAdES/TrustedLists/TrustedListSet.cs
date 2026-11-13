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

    /// <summary>
    /// Which services of the national lists become trust anchors, and whether an expired national list is refused. An
    /// expired LOTL is always refused: no constraint judges the LOTL itself.
    /// </summary>
    public TrustedListOptions Services { get; init; } = new();

    /// <summary>
    /// A folder where each list read successfully is kept. A kept list whose NextUpdate has not passed is used without
    /// downloading it again; when a download fails, the kept list is used while it has not expired. Null: no cache.
    /// </summary>
    public string? CacheDirectory { get; init; }

    /// <summary>
    /// Whether the keys of <see cref="LotlSignerCertificates"/> may be carried forward through the pivot LOTLs the LOTL
    /// names in its SchemeInformationURI (ETSI TS 119 612 §5.3.7, as the EU LOTL does when its signing keys change):
    /// each pivot, from the oldest, is checked with the keys known so far and gives, in its pointer to the LOTL, the keys
    /// accepted after it. Default: <see langword="true"/>; only used when the LOTL is not signed by the given keys.
    /// </summary>
    public bool FollowPivots { get; init; } = true;
}

/// <summary>A national list that could not be loaded.</summary>
/// <param name="Territory">The list's territory.</param>
/// <param name="Location">Its location.</param>
/// <param name="Reason">Why it was not loaded.</param>
public sealed record TrustedListProblem(string Territory, Uri Location, string Reason);

/// <summary>
/// The trusted lists of a list of trusted lists (LOTL, ETSI TS 119 612): the LOTL is checked with the configured
/// certificates, each list it points to with the certificates the LOTL gives for it, and the anchors of every list loaded become trust anchors. A list that cannot be loaded is
/// reported in <see cref="Problems"/> instead of failing the whole set.
/// </summary>
public sealed class TrustedListSet : ITimedTrustAnchorProvider, ITrustedListInfoProvider
{
    private const string XmlMimeType = "application/vnd.etsi.tsl+xml";

    private TrustedListSet(TrustedList lotl, IReadOnlyList<TrustedList> lists, IReadOnlyList<TrustedListProblem> problems,
        IReadOnlyList<X509Certificate2> lotlSigners, IReadOnlyList<Uri> pivots)
    {
        Lotl = lotl;
        Lists = lists;
        Problems = problems;
        LotlSigners = lotlSigners;
        PivotsFollowed = pivots;
    }

    /// <summary>
    /// The keys the LOTL was checked with: the given ones, or those the pivot LOTLs carried them forward to (keep them to
    /// check the next LOTL without walking the pivots again).
    /// </summary>
    public IReadOnlyList<X509Certificate2> LotlSigners { get; }

    /// <summary>The pivot LOTLs walked to reach <see cref="LotlSigners"/>, oldest first; empty when the given keys signed the LOTL.</summary>
    public IReadOnlyList<Uri> PivotsFollowed { get; }

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

    /// <summary>The anchors of every list loaded at <paramref name="at"/>, from each service's history (TS 119 612 §5.6).</summary>
    /// <param name="at">The time.</param>
    /// <returns>The anchors.</returns>
    public IReadOnlyList<X509Certificate2> GetTrustAnchors(DateTimeOffset at) => [.. Lists.SelectMany(l => l.GetTrustAnchors(at))];

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

        IReadOnlyList<X509Certificate2> lotlSigners = options.LotlSignerCertificates;
        IReadOnlyList<Uri> pivots = [];
        TrustedList lotl;
        try
        {
            lotl = await LoadOneAsync(
                options.LotlLocation, options.Services with { SignerCertificates = lotlSigners, RejectExpired = true },
                CacheFile(options, "lotl"), httpClientProvider, cancellationToken).ConfigureAwait(false);
        }
        catch (CryptographicException) when (options.FollowPivots)
        {
            (lotlSigners, pivots) = await PivotSignersAsync(options, httpClientProvider, cancellationToken).ConfigureAwait(false);
            lotl = await LoadOneAsync(
                options.LotlLocation, options.Services with { SignerCertificates = lotlSigners, RejectExpired = true },
                CacheFile(options, "lotl"), httpClientProvider, cancellationToken).ConfigureAwait(false);
        }

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

        return new TrustedListSet(lotl, lists, problems, lotlSigners, pivots);
    }

    /// <summary>
    /// The keys that may sign the LOTL, carried forward from <see cref="TrustedListSetOptions.LotlSignerCertificates"/>
    /// through the pivot LOTLs it names (oldest first): each is checked with the keys known so far, and its pointer to
    /// the LOTL gives the keys accepted after it.
    /// </summary>
    /// <exception cref="CryptographicException">A pivot is not signed by the keys known when it is read, or there is none.</exception>
    private static async Task<(IReadOnlyList<X509Certificate2> Signers, IReadOnlyList<Uri> Pivots)> PivotSignersAsync(
        TrustedListSetOptions options, IHttpClientProvider? httpClientProvider, CancellationToken cancellationToken)
    {
        var provider = httpClientProvider ?? DefaultHttpClientProvider.Instance;
        byte[] xml = await ResilientHttp.GetBytesAsync(provider.GetClient(), options.LotlLocation, provider.OutboundPolicy, null, cancellationToken).ConfigureAwait(false)
            ?? throw new HttpRequestException($"The list of trusted lists could not be downloaded from {options.LotlLocation}.");

        // The LOTL names its pivots newest first.
        var pivots = TrustedList.UnverifiedSchemeInformationUris(xml)
            .Select(u => Uri.TryCreate(u, UriKind.Absolute, out var uri) ? uri : null).OfType<Uri>()
            .Where(u => u.Scheme is "http" or "https" && u.AbsolutePath.EndsWith(".xml", StringComparison.OrdinalIgnoreCase) && u != options.LotlLocation)
            .Reverse().ToList();
        if (pivots.Count == 0)
        {
            throw new CryptographicException("The list of trusted lists is not signed by the given certificates, and it names no pivot LOTL to carry them forward.");
        }

        // Pivots older than the given keys (signed by keys that came before them) are skipped; from the first one the
        // given keys check, each must be checked by the keys the one before it named.
        IReadOnlyList<X509Certificate2> signers = options.LotlSignerCertificates;
        var walked = new List<Uri>();
        foreach (var location in pivots)
        {
            TrustedList pivot;
            try
            {
                // A pivot only carries keys forward: its NextUpdate may have passed.
                pivot = await TrustedList.DownloadAsync(location, options.Services with { SignerCertificates = signers, RejectExpired = false },
                    httpClientProvider, cancellationToken: cancellationToken).ConfigureAwait(false);
            }
            catch (CryptographicException ex)
            {
                if (walked.Count == 0)
                {
                    continue;
                }

                throw new CryptographicException($"The pivot LOTL {location} is not signed by the keys the pivot before it named: {ex.Message}", ex);
            }

            var next = pivot.Pointers.FirstOrDefault(p => p.TslType?.EndsWith("listofthelists", StringComparison.OrdinalIgnoreCase) == true
                || (string.Equals(p.Territory, pivot.Territory, StringComparison.OrdinalIgnoreCase) && p.Location == options.LotlLocation));
            if (next is not { SignerCertificates.Count: > 0 })
            {
                throw new CryptographicException($"The pivot LOTL {location} does not say which keys sign the LOTL after it.");
            }

            signers = next.SignerCertificates;
            walked.Add(location);
        }

        if (walked.Count == 0)
        {
            throw new CryptographicException("No pivot LOTL is signed by the given certificates: they cannot be carried forward to the LOTL's keys.");
        }

        return (signers, walked);
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

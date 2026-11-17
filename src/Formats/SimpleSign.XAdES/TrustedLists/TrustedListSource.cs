using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using SimpleSign.Core.Extensions;
using SimpleSign.Core.Http;

namespace SimpleSign.XAdES.TrustedLists;

/// <summary>Where a trusted list is and how <see cref="TrustedListSource"/> reads it.</summary>
public sealed record TrustedListSourceOptions
{
    /// <summary>Where the list is published.</summary>
    public required Uri Location { get; init; }

    /// <summary>
    /// How the list is read: the certificates it must be signed with (required), the services that become trust
    /// anchors, whether an expired list is refused.
    /// </summary>
    public TrustedListOptions List { get; init; } = new();

    /// <summary>
    /// A file where the last good copy is kept: it is served when the list cannot be downloaded at start-up, checked as a
    /// download is. Null (the default) for no cache.
    /// </summary>
    public string? CacheFile { get; init; }

    /// <summary>The HTTP client and its outbound policy; null for the default one.</summary>
    public IHttpClientProvider? HttpClientProvider { get; init; }
}

/// <summary>One verified copy of a trusted list, as <see cref="TrustedListSource"/> serves it.</summary>
/// <param name="List">The list, its signature checked.</param>
/// <param name="Sha256">The SHA-256 of the list's XML, in lowercase hexadecimal.</param>
/// <param name="LoadedAt">When this copy was read (downloaded, or loaded from the cache file).</param>
/// <param name="FromCache">Whether this copy came from the cache file because the download failed.</param>
public sealed record TrustedListSnapshot(TrustedList List, string Sha256, DateTimeOffset LoadedAt, bool FromCache = false)
{
    /// <summary>The list's TSLSequenceNumber.</summary>
    public string? SequenceNumber => List.SequenceNumber;

    /// <summary>The list's ListIssueDateTime.</summary>
    public DateTimeOffset? IssueDate => List.IssueDate;

    /// <summary>The list's NextUpdate: after it, the list is expired.</summary>
    public DateTimeOffset? NextUpdate => List.NextUpdate;
}

/// <summary>What changed between two copies of a trusted list (<see cref="TrustedListSource.Changed"/>).</summary>
/// <param name="previous">The copy served before.</param>
/// <param name="current">The copy served now.</param>
/// <param name="addedServices">The services of <paramref name="current"/> that <paramref name="previous"/> did not have.</param>
/// <param name="removedServices">The services of <paramref name="previous"/> that <paramref name="current"/> no longer has.</param>
public sealed class TrustedListChangedEventArgs(
    TrustedListSnapshot previous, TrustedListSnapshot current,
    IReadOnlyList<TrustedListService> addedServices, IReadOnlyList<TrustedListService> removedServices) : EventArgs
{
    /// <summary>The copy served before.</summary>
    public TrustedListSnapshot Previous { get; } = previous;

    /// <summary>The copy served now.</summary>
    public TrustedListSnapshot Current { get; } = current;

    /// <summary>
    /// The services the new copy has and the previous one did not (a service is its type, status and certificates: a
    /// service whose status changed is removed with its old status and added with its new one).
    /// </summary>
    public IReadOnlyList<TrustedListService> AddedServices { get; } = addedServices;

    /// <summary>The services the previous copy had and the new one does not.</summary>
    public IReadOnlyList<TrustedListService> RemovedServices { get; } = removedServices;
}

/// <summary>A refresh of a trusted list that failed: the copy served before is kept (<see cref="TrustedListSource.RefreshFailed"/>).</summary>
/// <param name="reason">Why the refresh failed.</param>
/// <param name="current">The copy still served.</param>
/// <param name="exception">The exception, when there was one.</param>
public sealed class TrustedListRefreshFailedEventArgs(string reason, TrustedListSnapshot current, Exception? exception = null) : EventArgs
{
    /// <summary>Why the refresh failed (download failed, signature refused, older sequence number…).</summary>
    public string Reason { get; } = reason;

    /// <summary>The copy still served.</summary>
    public TrustedListSnapshot Current { get; } = current;

    /// <summary>The exception, when there was one.</summary>
    public Exception? Exception { get; } = exception;
}

/// <summary>
/// One trusted list (ETSI TS 119 612), kept current: read once with
/// <see cref="LoadAsync(TrustedListSourceOptions, CancellationToken)"/>, then read again on demand
/// (<see cref="RefreshAsync"/>) or on a schedule (<see cref="StartAutoRefresh"/>).
/// <para>
/// Each copy is checked as <see cref="TrustedList.Load"/> checks it (its signature against
/// <see cref="TrustedListOptions.SignerCertificates"/>, not expired unless the options keep expired lists) and replaces
/// the one served in one step, so a signature or validation in progress sees the old list or the new one, never part of
/// each. A copy that cannot be downloaded or verified, or whose sequence number is lower than the one served, is refused
/// (<see cref="RefreshFailed"/>) and the last good copy keeps being served — from
/// <see cref="TrustedListSourceOptions.CacheFile"/> after a restart — until its NextUpdate passes; then, when expired
/// lists are refused, it gives no anchors until a good copy is read.
/// </para>
/// <para>
/// It is a trust anchor provider (also at a past time, from the services' history) and gives the list's
/// <see cref="TrustedListInfo"/> for the TrustedLists constraints of a validation policy.
/// <see cref="TrustedListProfile"/> makes it a trust profile.
/// </para>
/// </summary>
public sealed class TrustedListSource : ITimedTrustAnchorProvider, ITrustedListInfoProvider, IAsyncDisposable
{
    private readonly TrustedListSourceOptions _options;
    private readonly IHttpClientProvider _http;
    private readonly TimeProvider _clock;
    private readonly SemaphoreSlim _refreshGate = new(1, 1);
    private TrustedListSnapshot _current;
    private CancellationTokenSource? _autoRefresh;
    private Task? _autoRefreshTask;

    private TrustedListSource(TrustedListSourceOptions options, TrustedListSnapshot first, TimeProvider clock)
    {
        _options = options;
        _http = options.HttpClientProvider ?? DefaultHttpClientProvider.Instance;
        _clock = clock;
        _current = first;
    }

    /// <summary>The copy served now.</summary>
    public TrustedListSnapshot Current => Volatile.Read(ref _current);

    /// <summary>Whether the copy served is past its NextUpdate and gives no anchors (never when the options keep expired lists).</summary>
    public bool IsExpired => Expired(Current);

    /// <summary>When the list was last read successfully from its location.</summary>
    public DateTimeOffset LastChecked { get; private set; }

    /// <summary>Why the last read failed; null when it succeeded.</summary>
    public string? LastError { get; private set; }

    /// <summary>Raised after a refresh replaced the copy served.</summary>
    public event EventHandler<TrustedListChangedEventArgs>? Changed;

    /// <summary>Raised when a refresh fails and the last good copy is kept.</summary>
    public event EventHandler<TrustedListRefreshFailedEventArgs>? RefreshFailed;

    /// <inheritdoc />
    public string RegionCode => Current.List.Territory;

    /// <inheritdoc />
    public string DisplayName => Current.List.DisplayName;

    /// <inheritdoc />
    public IReadOnlyList<TrustedListInfo> TrustedLists => Current.List.TrustedLists;

    /// <inheritdoc />
    public IReadOnlyList<X509Certificate2> GetTrustAnchors()
    {
        var current = Current;
        return Expired(current) ? [] : current.List.GetTrustAnchors();
    }

    /// <inheritdoc />
    public IReadOnlyList<X509Certificate2> GetTrustAnchors(DateTimeOffset at)
    {
        var current = Current;
        return Expired(current) ? [] : current.List.GetTrustAnchors(at);
    }

    /// <inheritdoc />
    public IReadOnlyList<X509Certificate2> GetIntermediateCertificates()
    {
        var current = Current;
        return Expired(current) ? [] : current.List.GetIntermediateCertificates();
    }

    /// <summary>Reads the list: from its location, else from the cache file.</summary>
    /// <param name="options">Where the list is and how it is read.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The source.</returns>
    /// <exception cref="HttpRequestException">The list cannot be downloaded and there is no cached copy.</exception>
    /// <exception cref="CryptographicException">The list is not signed by one of the signer certificates.</exception>
    /// <exception cref="InvalidDataException">The list is not a trusted list, or it is expired and expired lists are refused.</exception>
    public static Task<TrustedListSource> LoadAsync(TrustedListSourceOptions options, CancellationToken cancellationToken = default) =>
        LoadAsync(options, TimeProvider.System, cancellationToken);

    internal static async Task<TrustedListSource> LoadAsync(TrustedListSourceOptions options, TimeProvider clock, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(clock);
        var http = options.HttpClientProvider ?? DefaultHttpClientProvider.Instance;
        var (read, error, exception) = await ReadAsync(options, http, clock, cancellationToken).ConfigureAwait(false);
        TrustedListSnapshot first;
        if (read is { } downloaded)
        {
            first = downloaded.Snapshot;
            await WriteCacheAsync(options.CacheFile, downloaded, cancellationToken).ConfigureAwait(false);
        }
        else if (options.CacheFile is { } cache && File.Exists(cache))
        {
            // The last good copy, checked as a download is (signature, not expired).
            byte[] cached = await File.ReadAllBytesAsync(cache, cancellationToken).ConfigureAwait(false);
            var loadedAt = new DateTimeOffset(File.GetLastWriteTimeUtc(cache));
            first = new TrustedListSnapshot(TrustedList.Load(cached, options.List).WithOrigin(options.Location, loadedAt), Hash(cached), loadedAt, FromCache: true);
        }
        else if (exception is not null and not HttpRequestException)
        {
            // The list was read and refused (not signed by its operator, expired, not a list): say why.
            System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(exception).Throw();
            throw new InvalidOperationException("Unreachable.");
        }
        else
        {
            throw new HttpRequestException($"The trusted list could not be read from {options.Location}: {error}.", exception);
        }

        return new TrustedListSource(options, first, clock) { LastChecked = clock.GetUtcNow(), LastError = read is null ? error : null };
    }

    /// <summary>
    /// Reads the list again. A copy that verifies and is not older than the one served replaces it (and the cache file);
    /// any other is refused, <see cref="RefreshFailed"/> is raised and the copy served stays.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Whether the copy served changed.</returns>
    public async Task<bool> RefreshAsync(CancellationToken cancellationToken = default)
    {
        await _refreshGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var (read, error, exception) = await ReadAsync(_options, _http, _clock, cancellationToken).ConfigureAwait(false);
            var previous = Current;
            if (read is not { } next)
            {
                return Fail(error!, previous, exception);
            }

            if (string.Equals(next.Snapshot.Sha256, previous.Sha256, StringComparison.Ordinal))
            {
                LastChecked = _clock.GetUtcNow();
                LastError = null;
                if (previous.FromCache)
                {
                    // The cache was read at start-up; the network now confirms it.
                    Volatile.Write(ref _current, previous with { FromCache = false, LoadedAt = next.Snapshot.LoadedAt });
                }

                return false;
            }

            if (Sequence(next.Snapshot) is { } newSequence && Sequence(previous) is { } oldSequence && newSequence < oldSequence)
            {
                return Fail($"the list read has sequence number {newSequence}, lower than the {oldSequence} served: refused", previous, null);
            }

            Volatile.Write(ref _current, next.Snapshot);
            LastChecked = _clock.GetUtcNow();
            LastError = null;
            await WriteCacheAsync(_options.CacheFile, next, cancellationToken).ConfigureAwait(false);
            var (added, removed) = Difference(previous.List, next.Snapshot.List);
            Changed?.Invoke(this, new TrustedListChangedEventArgs(previous, next.Snapshot, added, removed));
            return true;
        }
        finally
        {
            _refreshGate.Release();
        }
    }

    /// <summary>
    /// Refreshes every <paramref name="interval"/> in the background — sooner when the copy served expires before that —
    /// until <see cref="StopAutoRefreshAsync"/> or <see cref="DisposeAsync"/>.
    /// </summary>
    /// <param name="interval">How often; at least one minute.</param>
    /// <exception cref="InvalidOperationException">The auto-refresh is already running.</exception>
    public void StartAutoRefresh(TimeSpan interval)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(interval, TimeSpan.FromMinutes(1));
        if (_autoRefresh is not null)
        {
            throw new InvalidOperationException("The trusted list is already refreshed on a schedule.");
        }

        _autoRefresh = new CancellationTokenSource();
        var token = _autoRefresh.Token;
        _autoRefreshTask = Task.Run(() => AutoRefreshAsync(interval, token), CancellationToken.None);
    }

    /// <summary>Stops the background refresh.</summary>
    /// <returns>A task that completes when it has stopped.</returns>
    public async Task StopAutoRefreshAsync()
    {
        if (_autoRefresh is not { } cancel)
        {
            return;
        }

        await cancel.CancelAsync().ConfigureAwait(false);
        if (_autoRefreshTask is { } task)
        {
            try
            {
                await task.ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                // Stopped.
            }
        }

        cancel.Dispose();
        _autoRefresh = null;
        _autoRefreshTask = null;
    }

    /// <inheritdoc />
    public async ValueTask DisposeAsync()
    {
        await StopAutoRefreshAsync().ConfigureAwait(false);
        _autoRefresh?.Dispose();
        _refreshGate.Dispose();
    }

    private async Task AutoRefreshAsync(TimeSpan interval, CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            // The next refresh: after the interval, or when the copy served expires, whichever is first.
            var wait = interval;
            if (Current.NextUpdate is { } nextUpdate && nextUpdate - _clock.GetUtcNow() is var untilExpiry && untilExpiry < wait)
            {
                wait = untilExpiry > TimeSpan.FromMinutes(1) ? untilExpiry : TimeSpan.FromMinutes(1);
            }

            await Task.Delay(wait, _clock, cancellationToken).ConfigureAwait(false);
            try
            {
                await RefreshAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (IOException ex)
            {
                // The cache file could not be written: the new copy is served all the same.
                LastError = $"the cache file could not be written: {ex.Message}";
            }
        }
    }

    private bool Fail(string reason, TrustedListSnapshot current, Exception? exception)
    {
        LastError = reason;
        RefreshFailed?.Invoke(this, new TrustedListRefreshFailedEventArgs(reason, current, exception));
        return false;
    }

    private bool Expired(TrustedListSnapshot snapshot) =>
        _options.List.RejectExpired && snapshot.NextUpdate is { } next && next < _clock.GetUtcNow();

    private static async Task<((TrustedListSnapshot Snapshot, byte[] Xml)? Read, string? Error, Exception? Exception)> ReadAsync(
        TrustedListSourceOptions options, IHttpClientProvider http, TimeProvider clock, CancellationToken cancellationToken)
    {
        byte[]? xml;
        try
        {
            xml = await ResilientHttp.GetBytesAsync(http.GetClient(), options.Location, http.OutboundPolicy, null, cancellationToken).ConfigureAwait(false);
        }
        catch (HttpRequestException ex)
        {
            return (null, $"the list could not be downloaded: {ex.Message}", ex);
        }

        if (xml is null)
        {
            return (null, RefusedLoopback(options.Location, http.OutboundPolicy) ?? "the list could not be downloaded", null);
        }

        try
        {
            var now = clock.GetUtcNow();
            var list = TrustedList.Load(xml, options.List).WithOrigin(options.Location, now);
            return ((new TrustedListSnapshot(list, Hash(xml), now), xml), null, null);
        }
        catch (Exception ex) when (ex is CryptographicException or InvalidDataException or XmlException or FormatException)
        {
            return (null, $"the list was refused: {ex.Message}", ex);
        }
    }

    /// <summary>
    /// Why <paramref name="url"/> was never requested: it is on this machine and <paramref name="policy"/> does not list
    /// its origin in <see cref="OutboundHttpPolicy.LoopbackOrigins"/>; null for any other URL.
    /// </summary>
    internal static string? RefusedLoopback(Uri url, OutboundHttpPolicy policy)
    {
        bool loopback = string.Equals(url.Host, "localhost", StringComparison.OrdinalIgnoreCase)
            || (System.Net.IPAddress.TryParse(url.IdnHost.Trim('[', ']'), out var address) && System.Net.IPAddress.IsLoopback(address));
        if (!loopback || policy.LoopbackOrigins.Any(o => string.Equals(o.Scheme, url.Scheme, StringComparison.OrdinalIgnoreCase)
            && string.Equals(o.IdnHost, url.IdnHost, StringComparison.OrdinalIgnoreCase) && o.Port == url.Port))
        {
            return null;
        }

        return $"{url.GetLeftPart(UriPartial.Authority)} is this machine, which the outbound policy refuses unless "
            + $"{nameof(OutboundHttpPolicy)}.{nameof(OutboundHttpPolicy.LoopbackOrigins)} lists it";
    }

    private static async Task WriteCacheAsync(string? cacheFile, (TrustedListSnapshot Snapshot, byte[] Xml) read, CancellationToken cancellationToken)
    {
        if (cacheFile is null || read.Snapshot.FromCache)
        {
            return;
        }

        // Written aside and moved: a crash never leaves half a list in the cache.
        string temporary = cacheFile + ".tmp";
        await File.WriteAllBytesAsync(temporary, read.Xml, cancellationToken).ConfigureAwait(false);
        File.Move(temporary, cacheFile, overwrite: true);
    }

    private static string Hash(byte[] xml) => Convert.ToHexString(SHA256.HashData(xml)).ToLowerInvariant();

    private static long? Sequence(TrustedListSnapshot snapshot) =>
        long.TryParse(snapshot.SequenceNumber, NumberStyles.None, CultureInfo.InvariantCulture, out long sequence) ? sequence : null;

    private static (List<TrustedListService> Added, List<TrustedListService> Removed) Difference(TrustedList previous, TrustedList current)
    {
        var before = previous.Services.ToLookup(Key, StringComparer.Ordinal);
        var after = current.Services.ToLookup(Key, StringComparer.Ordinal);
        return ([.. current.Services.Where(s => !before.Contains(Key(s)))], [.. previous.Services.Where(s => !after.Contains(Key(s)))]);

        static string Key(TrustedListService service) =>
            $"{service.ServiceType}|{service.Status}|{string.Join(',', service.Certificates.Select(c => c.Thumbprint).Order(StringComparer.Ordinal))}";
    }
}

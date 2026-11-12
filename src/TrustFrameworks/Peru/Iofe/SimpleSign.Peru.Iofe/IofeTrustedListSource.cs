using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using SimpleSign.Core.Extensions;
using SimpleSign.Core.Http;
using SimpleSign.XAdES.TrustedLists;

namespace SimpleSign.Peru.Iofe;

/// <summary>One verified copy of INDECOPI's trusted list, as <see cref="IofeTrustedListSource"/> serves it.</summary>
/// <param name="List">The list, its signature checked.</param>
/// <param name="Sha256">The SHA-256 of the list's XML, in lowercase hexadecimal.</param>
/// <param name="LoadedAt">When this copy was read (downloaded, or loaded from the cache file).</param>
/// <param name="FromCache">Whether this copy came from the cache file because the download failed.</param>
public sealed record IofeTrustedListSnapshot(TrustedList List, string Sha256, DateTimeOffset LoadedAt, bool FromCache = false)
{
    /// <summary>The list's TSLSequenceNumber.</summary>
    public string? SequenceNumber => List.SequenceNumber;

    /// <summary>The list's ListIssueDateTime.</summary>
    public DateTimeOffset? IssueDate => List.IssueDate;

    /// <summary>The list's NextUpdate: after it, the list is expired and gives no anchors.</summary>
    public DateTimeOffset? NextUpdate => List.NextUpdate;
}

/// <summary>What changed between two copies of INDECOPI's trusted list.</summary>
public sealed class IofeTrustedListChangedEventArgs : EventArgs
{
    /// <summary>Creates the event data.</summary>
    /// <param name="previous">The copy served before; null on the first load.</param>
    /// <param name="current">The copy served now.</param>
    /// <param name="addedServices">The services of <paramref name="current"/> that <paramref name="previous"/> did not have.</param>
    /// <param name="removedServices">The services of <paramref name="previous"/> that <paramref name="current"/> no longer has.</param>
    public IofeTrustedListChangedEventArgs(
        IofeTrustedListSnapshot? previous, IofeTrustedListSnapshot current,
        IReadOnlyList<TrustedListService> addedServices, IReadOnlyList<TrustedListService> removedServices)
    {
        Previous = previous;
        Current = current;
        AddedServices = addedServices;
        RemovedServices = removedServices;
    }

    /// <summary>The copy served before; null on the first load.</summary>
    public IofeTrustedListSnapshot? Previous { get; }

    /// <summary>The copy served now.</summary>
    public IofeTrustedListSnapshot Current { get; }

    /// <summary>
    /// The services the new copy has and the previous one did not (a service is its type, status and certificates: a
    /// service whose status changed is removed with its old status and added with its new one).
    /// </summary>
    public IReadOnlyList<TrustedListService> AddedServices { get; }

    /// <summary>The services the previous copy had and the new one does not.</summary>
    public IReadOnlyList<TrustedListService> RemovedServices { get; }
}

/// <summary>A refresh of INDECOPI's trusted list that failed: the copy served before is kept.</summary>
public sealed class IofeTrustedListRefreshFailedEventArgs : EventArgs
{
    /// <summary>Creates the event data.</summary>
    /// <param name="reason">Why the refresh failed.</param>
    /// <param name="current">The copy still served.</param>
    /// <param name="exception">The exception, when there was one.</param>
    public IofeTrustedListRefreshFailedEventArgs(string reason, IofeTrustedListSnapshot current, Exception? exception = null)
    {
        Reason = reason;
        Current = current;
        Exception = exception;
    }

    /// <summary>Why the refresh failed (download failed, signature refused, older sequence number…).</summary>
    public string Reason { get; }

    /// <summary>The copy still served.</summary>
    public IofeTrustedListSnapshot Current { get; }

    /// <summary>The exception, when there was one.</summary>
    public Exception? Exception { get; }
}

/// <summary>
/// INDECOPI's trusted list, kept current: read once with <see cref="LoadAsync(IofeExtensionOptions, CancellationToken)"/>, then read again on demand
/// (<see cref="RefreshAsync"/>) or on a schedule (<see cref="StartAutoRefresh"/>, or the hosted service of
/// <c>services.AddSimpleSignIofe(options)</c>).
/// <para>
/// Each copy is checked as <see cref="IofeExtension.LoadAsync"/> checks it (signature against
/// <see cref="IofeExtensionOptions.TrustedListSigners"/>, not expired) and replaces the one served in one step, so a
/// signature or validation in progress sees the old list or the new one, never part of each. A copy that cannot be
/// downloaded or verified, or whose sequence number is lower than the one served, is refused
/// (<see cref="RefreshFailed"/>) and the last good copy keeps being served — from <see cref="IofeExtensionOptions.CacheFile"/>
/// after a restart — until its NextUpdate passes; then the list gives no anchors until a good copy is read.
/// </para>
/// <para>
/// It is a trust anchor provider (also at a past time, from the services' history) and gives the list's
/// <see cref="TrustedListInfo"/> for the TrustedLists constraints; <see cref="IofeExtension(IofeTrustedListSource)"/>
/// makes it a country extension.
/// </para>
/// </summary>
public sealed class IofeTrustedListSource : ITimedTrustAnchorProvider, ITrustedListInfoProvider, IAsyncDisposable
{
    private readonly IofeExtensionOptions _options;
    private readonly TrustedListOptions _listOptions;
    private readonly IHttpClientProvider _http;
    private readonly TimeProvider _clock;
    private readonly SemaphoreSlim _refreshGate = new(1, 1);
    private IofeTrustedListSnapshot _current;
    private CancellationTokenSource? _autoRefresh;
    private Task? _autoRefreshTask;

    private IofeTrustedListSource(IofeExtensionOptions options, TrustedListOptions listOptions, IofeTrustedListSnapshot first, TimeProvider clock)
    {
        _options = options;
        _listOptions = listOptions;
        _http = options.HttpClientProvider ?? DefaultHttpClientProvider.Instance;
        _clock = clock;
        _current = first;
    }

    /// <summary>The copy served now.</summary>
    public IofeTrustedListSnapshot Current => Volatile.Read(ref _current);

    /// <summary>Whether the copy served is past its NextUpdate: it gives no anchors until a good copy is read.</summary>
    public bool IsExpired => Expired(Current);

    /// <summary>When the list was last read successfully or found unchanged.</summary>
    public DateTimeOffset LastChecked { get; private set; }

    /// <summary>Why the last refresh failed; null when it succeeded.</summary>
    public string? LastError { get; private set; }

    /// <summary>
    /// Raised after a new copy replaced the one served (not when the list read again is the same). Handlers run on the
    /// refreshing thread; an exception they throw is not caught.
    /// </summary>
    public event EventHandler<IofeTrustedListChangedEventArgs>? Changed;

    /// <summary>Raised when a refresh fails and the last good copy is kept.</summary>
    public event EventHandler<IofeTrustedListRefreshFailedEventArgs>? RefreshFailed;

    /// <inheritdoc />
    public string RegionCode => "PE";

    /// <inheritdoc />
    public string DisplayName => $"INDECOPI trusted list #{Current.SequenceNumber}";

    /// <inheritdoc />
    public IReadOnlyList<TrustedListInfo> TrustedLists => Current.List.TrustedLists;

    /// <summary>The anchors of the copy served now; none when it is expired.</summary>
    /// <returns>The anchors.</returns>
    public IReadOnlyList<X509Certificate2> GetTrustAnchors()
    {
        var current = Current;
        return Expired(current) ? [] : current.List.GetTrustAnchors();
    }

    /// <summary>The anchors of the copy served now at a past time, from its services' history; none when it is expired.</summary>
    /// <param name="at">The time.</param>
    /// <returns>The anchors.</returns>
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

    /// <summary>
    /// Downloads INDECOPI's trusted list and checks it; when the download fails, reads
    /// <see cref="IofeExtensionOptions.CacheFile"/> (checked the same way, refused when expired).
    /// </summary>
    /// <param name="options">The list location, its signers, the cache and the HTTP client.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The source, serving the copy read.</returns>
    /// <exception cref="ArgumentException">No <see cref="IofeExtensionOptions.TrustedListSigners"/>.</exception>
    /// <exception cref="HttpRequestException">The list could not be downloaded and there is no usable cache.</exception>
    public static Task<IofeTrustedListSource> LoadAsync(IofeExtensionOptions options, CancellationToken cancellationToken = default) =>
        LoadAsync(options, TimeProvider.System, cancellationToken);

    /// <summary><see cref="LoadAsync(IofeExtensionOptions, CancellationToken)"/> with a clock (tests).</summary>
    internal static async Task<IofeTrustedListSource> LoadAsync(IofeExtensionOptions options, TimeProvider clock, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(clock);
        var listOptions = IofeExtension.ListOptionsOf(options);
        var http = options.HttpClientProvider ?? DefaultHttpClientProvider.Instance;
        var (read, error, exception) = await ReadAsync(options, listOptions, http, clock, cancellationToken).ConfigureAwait(false);
        IofeTrustedListSnapshot first;
        if (read is { } downloaded)
        {
            first = downloaded.Snapshot;
            await WriteCacheAsync(options.CacheFile, downloaded, cancellationToken).ConfigureAwait(false);
        }
        else if (options.CacheFile is { } cache && File.Exists(cache))
        {
            // The last good copy, checked as a download is (signature, not expired).
            byte[] cached = await File.ReadAllBytesAsync(cache, cancellationToken).ConfigureAwait(false);
            first = new IofeTrustedListSnapshot(TrustedList.Load(cached, listOptions), Hash(cached), new DateTimeOffset(File.GetLastWriteTimeUtc(cache)), FromCache: true);
        }
        else
        {
            throw new HttpRequestException($"INDECOPI's trusted list could not be read from {options.TrustedListUrl}: {error}.", exception);
        }

        return new IofeTrustedListSource(options, listOptions, first, clock) { LastChecked = clock.GetUtcNow(), LastError = read is null ? error : null };
    }

    /// <summary>
    /// Reads the list again. A new copy that is verified replaces the one served and raises <see cref="Changed"/>; the
    /// same copy changes nothing; a failure keeps the copy served and raises <see cref="RefreshFailed"/>. Concurrent
    /// calls run one after the other.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Whether the copy served changed.</returns>
    public async Task<bool> RefreshAsync(CancellationToken cancellationToken = default)
    {
        await _refreshGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var (read, error, exception) = await ReadAsync(_options, _listOptions, _http, _clock, cancellationToken).ConfigureAwait(false);
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
            Changed?.Invoke(this, new IofeTrustedListChangedEventArgs(previous, next.Snapshot, added, removed));
            return true;
        }
        finally
        {
            _refreshGate.Release();
        }
    }

    /// <summary>
    /// Refreshes the list every <paramref name="interval"/> in the background (and as soon as the copy served expires),
    /// until <see cref="StopAutoRefreshAsync"/> or <see cref="DisposeAsync"/>. A failure is reported by
    /// <see cref="RefreshFailed"/>; the schedule goes on.
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

    /// <summary>Stops the background refresh started by <see cref="StartAutoRefresh"/>.</summary>
    /// <returns>A task that completes when the background refresh has stopped.</returns>
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

    private bool Fail(string reason, IofeTrustedListSnapshot current, Exception? exception)
    {
        LastError = reason;
        RefreshFailed?.Invoke(this, new IofeTrustedListRefreshFailedEventArgs(reason, current, exception));
        return false;
    }

    private bool Expired(IofeTrustedListSnapshot snapshot) =>
        _listOptions.RejectExpired && snapshot.NextUpdate is { } next && next < _clock.GetUtcNow();

    /// <summary>Downloads and verifies one copy; on failure, the reason.</summary>
    private static async Task<((IofeTrustedListSnapshot Snapshot, byte[] Xml)? Read, string? Error, Exception? Exception)> ReadAsync(
        IofeExtensionOptions options, TrustedListOptions listOptions, IHttpClientProvider http, TimeProvider clock, CancellationToken cancellationToken)
    {
        byte[]? xml = await ResilientHttp.GetBytesAsync(http.GetClient(), options.TrustedListUrl, http.OutboundPolicy, null, cancellationToken).ConfigureAwait(false);
        if (xml is null)
        {
            return (null, "the list could not be downloaded", null);
        }

        try
        {
            var list = TrustedList.Load(xml, listOptions);
            return ((new IofeTrustedListSnapshot(list, Hash(xml), clock.GetUtcNow()), xml), null, null);
        }
        catch (Exception ex) when (ex is CryptographicException or InvalidDataException or XmlException or FormatException)
        {
            return (null, $"the list was refused: {ex.Message}", ex);
        }
    }

    private static async Task WriteCacheAsync(string? cacheFile, (IofeTrustedListSnapshot Snapshot, byte[] Xml) read, CancellationToken cancellationToken)
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

    private static long? Sequence(IofeTrustedListSnapshot snapshot) =>
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

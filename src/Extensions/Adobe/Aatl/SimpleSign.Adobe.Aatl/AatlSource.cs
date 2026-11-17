using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SimpleSign.Core.Extensions;
using SimpleSign.Core.Http;

namespace SimpleSign.Adobe.Aatl;

/// <summary>The copy of the list that replaced the one served (<see cref="AatlSource.Changed"/>).</summary>
/// <param name="previous">The copy served before.</param>
/// <param name="current">The copy served now.</param>
public sealed class AatlChangedEventArgs(AatlList previous, AatlList current) : EventArgs
{
    /// <summary>The copy served before.</summary>
    public AatlList Previous { get; } = previous;

    /// <summary>The copy served now.</summary>
    public AatlList Current { get; } = current;
}

/// <summary>A refresh of the list that failed: the copy served before is kept (<see cref="AatlSource.RefreshFailed"/>).</summary>
/// <param name="reason">Why the refresh failed.</param>
/// <param name="current">The copy still served.</param>
/// <param name="exception">The exception, when there was one.</param>
public sealed class AatlRefreshFailedEventArgs(string reason, AatlList current, Exception? exception = null) : EventArgs
{
    /// <summary>Why the refresh failed (download failed, signature refused, older copy…).</summary>
    public string Reason { get; } = reason;

    /// <summary>The copy still served.</summary>
    public AatlList Current { get; } = current;

    /// <summary>The exception, when there was one.</summary>
    public Exception? Exception { get; } = exception;
}

/// <summary>
/// The Adobe Approved Trust List, kept current: downloaded once with <see cref="LoadAsync"/>, then again on demand
/// (<see cref="RefreshAsync"/>) or on a schedule (<see cref="StartAutoRefresh"/>, or the hosted service of
/// <c>services.AddSimpleSignAatl(options)</c>). Acrobat itself looks for a new list every few weeks.
/// <para>
/// Each copy is checked as <see cref="AatlList.LoadAsync"/> checks it and replaces the one served in one step. A copy
/// that cannot be downloaded or verified, or that was signed before the one served, is refused
/// (<see cref="RefreshFailed"/>) and the last good copy keeps being served — from <see cref="AatlOptions.CacheFile"/>
/// after a restart. The list is downloaded from Adobe at run time; it is not part of the package.
/// </para>
/// </summary>
public sealed class AatlSource : IConstrainedTrustAnchorProvider, IAsyncDisposable
{
    private readonly AatlOptions _options;
    private readonly IHttpClientProvider _http;
    private readonly SemaphoreSlim _refreshGate = new(1, 1);
    private AatlList _current;
    private CancellationTokenSource? _autoRefresh;
    private Task? _autoRefreshTask;

    private AatlSource(AatlOptions options, AatlList first)
    {
        _options = options;
        _http = options.HttpClientProvider ?? DefaultHttpClientProvider.Instance;
        _current = first;
    }

    /// <summary>The copy served now.</summary>
    public AatlList Current => Volatile.Read(ref _current);

    /// <summary>Whether the copy served came from the cache file because the download failed.</summary>
    public bool FromCache { get; private set; }

    /// <summary>When the list was last read successfully from its location.</summary>
    public DateTimeOffset LastChecked { get; private set; }

    /// <summary>Why the last read failed; null when it succeeded.</summary>
    public string? LastError { get; private set; }

    /// <summary>Raised after a refresh replaced the copy served.</summary>
    public event EventHandler<AatlChangedEventArgs>? Changed;

    /// <summary>Raised when a refresh fails and the last good copy is kept.</summary>
    public event EventHandler<AatlRefreshFailedEventArgs>? RefreshFailed;

    /// <inheritdoc />
    public string RegionCode => Current.RegionCode;

    /// <inheritdoc />
    public string DisplayName => Current.DisplayName;

    /// <inheritdoc />
    public IReadOnlyList<X509Certificate2> GetTrustAnchors() => Current.GetTrustAnchors();

    /// <inheritdoc />
    public IReadOnlyList<X509Certificate2> GetIntermediateCertificates() => Current.GetIntermediateCertificates();

    /// <inheritdoc />
    public string? WhyRefused(X509Certificate2 anchor, IReadOnlyList<X509Certificate2> chain) => Current.WhyRefused(anchor, chain);

    /// <summary>Reads the list: from its location, else from the cache file.</summary>
    /// <param name="options">Where the list is and how it is read; null for Adobe's, with the bundled root.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The source.</returns>
    /// <exception cref="HttpRequestException">The list cannot be downloaded and there is no cached copy.</exception>
    /// <exception cref="CryptographicException">The list is not signed by its publisher.</exception>
    /// <exception cref="InvalidDataException">The file downloaded is not the list.</exception>
    public static async Task<AatlSource> LoadAsync(AatlOptions? options = null, CancellationToken cancellationToken = default)
    {
        options ??= new AatlOptions();
        var http = options.HttpClientProvider ?? DefaultHttpClientProvider.Instance;
        var (read, error, exception) = await ReadAsync(options, http, cancellationToken).ConfigureAwait(false);
        if (read is { } downloaded)
        {
            await WriteCacheAsync(options.CacheFile, downloaded.Pdf, cancellationToken).ConfigureAwait(false);
            return new AatlSource(options, downloaded.List) { LastChecked = DateTimeOffset.UtcNow };
        }

        if (options.CacheFile is { } cache && File.Exists(cache))
        {
            // The last good copy: its signature is checked again; its signer's revocation was checked when it was downloaded.
            byte[] cached = await File.ReadAllBytesAsync(cache, cancellationToken).ConfigureAwait(false);
            var list = await AatlList.LoadWithoutRevocationAsync(cached, options, cancellationToken).ConfigureAwait(false);
            return new AatlSource(options, list.At(options.ListUrl, new DateTimeOffset(File.GetLastWriteTimeUtc(cache))))
            {
                FromCache = true,
                LastChecked = DateTimeOffset.UtcNow,
                LastError = error,
            };
        }

        if (exception is not null and not HttpRequestException)
        {
            // The list was read and refused: say why.
            System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(exception).Throw();
        }

        throw new HttpRequestException($"The Adobe Approved Trust List could not be read from {options.ListUrl}: {error}.", exception);
    }

    /// <summary>
    /// Reads the list again. A copy that verifies and was not signed before the one served replaces it (and the cache
    /// file); any other is refused, <see cref="RefreshFailed"/> is raised and the copy served stays.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Whether the copy served changed.</returns>
    public async Task<bool> RefreshAsync(CancellationToken cancellationToken = default)
    {
        await _refreshGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var (read, error, exception) = await ReadAsync(_options, _http, cancellationToken).ConfigureAwait(false);
            var previous = Current;
            if (read is not { } next)
            {
                return Fail(error!, previous, exception);
            }

            if (string.Equals(next.List.Sha256, previous.Sha256, StringComparison.Ordinal))
            {
                LastChecked = DateTimeOffset.UtcNow;
                LastError = null;
                FromCache = false;
                return false;
            }

            if (next.List.SignedAt is { } signed && previous.SignedAt is { } served && signed < served)
            {
                return Fail($"the list read was signed at {signed:u}, before the one served ({served:u}): refused", previous, null);
            }

            Volatile.Write(ref _current, next.List);
            LastChecked = DateTimeOffset.UtcNow;
            LastError = null;
            FromCache = false;
            await WriteCacheAsync(_options.CacheFile, next.Pdf, cancellationToken).ConfigureAwait(false);
            Changed?.Invoke(this, new AatlChangedEventArgs(previous, next.List));
            return true;
        }
        finally
        {
            _refreshGate.Release();
        }
    }

    /// <summary>Refreshes every <paramref name="interval"/> in the background until <see cref="StopAutoRefreshAsync"/> or <see cref="DisposeAsync"/>.</summary>
    /// <param name="interval">How often; at least one minute.</param>
    /// <exception cref="InvalidOperationException">The auto-refresh is already running.</exception>
    public void StartAutoRefresh(TimeSpan interval)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(interval, TimeSpan.FromMinutes(1));
        if (_autoRefresh is not null)
        {
            throw new InvalidOperationException("The trust list is already refreshed on a schedule.");
        }

        _autoRefresh = new CancellationTokenSource();
        var token = _autoRefresh.Token;
        _autoRefreshTask = Task.Run(async () =>
        {
            while (!token.IsCancellationRequested)
            {
                await Task.Delay(interval, token).ConfigureAwait(false);
                try
                {
                    await RefreshAsync(token).ConfigureAwait(false);
                }
                catch (IOException ex)
                {
                    // The cache file could not be written: the new copy is served all the same.
                    LastError = $"the cache file could not be written: {ex.Message}";
                }
            }
        }, CancellationToken.None);
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

    private bool Fail(string reason, AatlList current, Exception? exception)
    {
        LastError = reason;
        RefreshFailed?.Invoke(this, new AatlRefreshFailedEventArgs(reason, current, exception));
        return false;
    }

    private static async Task<((AatlList List, byte[] Pdf)? Read, string? Error, Exception? Exception)> ReadAsync(
        AatlOptions options, IHttpClientProvider http, CancellationToken cancellationToken)
    {
        byte[]? pdf;
        try
        {
            pdf = await ResilientHttp.GetBytesAsync(http.GetClient(), options.ListUrl, http.OutboundPolicy, null, cancellationToken).ConfigureAwait(false);
        }
        catch (HttpRequestException ex)
        {
            return (null, $"the list could not be downloaded: {ex.Message}", ex);
        }

        if (pdf is null)
        {
            return (null, "the list could not be downloaded", null);
        }

        try
        {
            var list = await AatlList.LoadAsync(pdf, options, cancellationToken).ConfigureAwait(false);
            return ((list.At(options.ListUrl, DateTimeOffset.UtcNow), pdf), null, null);
        }
        catch (Exception ex) when (ex is CryptographicException or InvalidDataException)
        {
            return (null, $"the list was refused: {ex.Message}", ex);
        }
    }

    private static async Task WriteCacheAsync(string? cacheFile, byte[] pdf, CancellationToken cancellationToken)
    {
        if (cacheFile is null)
        {
            return;
        }

        // Written aside and moved: a crash never leaves half a list in the cache.
        string temporary = cacheFile + ".tmp";
        await File.WriteAllBytesAsync(temporary, pdf, cancellationToken).ConfigureAwait(false);
        File.Move(temporary, cacheFile, overwrite: true);
    }
}

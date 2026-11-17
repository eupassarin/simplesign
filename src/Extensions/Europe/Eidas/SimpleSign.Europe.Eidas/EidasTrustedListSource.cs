using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SimpleSign.Core.Extensions;
using SimpleSign.XAdES.TrustedLists;

namespace SimpleSign.Europe.Eidas;

/// <summary>The LOTL and lists that replaced the ones served (<see cref="EidasTrustedListSource.Changed"/>).</summary>
/// <param name="Previous">The set served before.</param>
/// <param name="Current">The set served now.</param>
public sealed class EidasTrustedListChangedEventArgs(TrustedListSet Previous, TrustedListSet Current) : EventArgs
{
    /// <summary>The set served before.</summary>
    public TrustedListSet Previous { get; } = Previous;

    /// <summary>The set served now.</summary>
    public TrustedListSet Current { get; } = Current;
}

/// <summary>A refresh that failed; the last good set is kept (<see cref="EidasTrustedListSource.RefreshFailed"/>).</summary>
/// <param name="Reason">Why.</param>
public sealed class EidasTrustedListRefreshFailedEventArgs(string Reason) : EventArgs
{
    /// <summary>Why the refresh failed.</summary>
    public string Reason { get; } = Reason;
}

/// <summary>
/// The EU LOTL and its national lists, kept current: <see cref="RefreshAsync"/> reads them again (on demand, or on a
/// schedule with <see cref="StartAutoRefresh"/>), each copy checked like the first, swapped in one step. A refresh that
/// fails keeps the last good set and raises <see cref="RefreshFailed"/>. The keys that checked the LOTL are carried to
/// the next refresh, so a key change announced by a pivot LOTL is followed once.
/// </summary>
public sealed class EidasTrustedListSource : ITimedTrustAnchorProvider, ITrustedListInfoProvider, IAsyncDisposable
{
    private readonly EidasExtensionOptions _options;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private TrustedListSet _current;
    private CancellationTokenSource? _autoRefresh;
    private Task? _autoRefreshTask;

    private EidasTrustedListSource(EidasExtensionOptions options, TrustedListSet first)
    {
        _options = options;
        _current = first;
        LastChecked = DateTimeOffset.UtcNow;
    }

    /// <summary>The set served now.</summary>
    public TrustedListSet Current => Volatile.Read(ref _current);

    /// <summary>When the lists were last read successfully.</summary>
    public DateTimeOffset LastChecked { get; private set; }

    /// <summary>Why the last refresh failed; null when it succeeded.</summary>
    public string? LastError { get; private set; }

    /// <summary>Raised after a refresh replaced the set served.</summary>
    public event EventHandler<EidasTrustedListChangedEventArgs>? Changed;

    /// <summary>Raised when a refresh fails and the last good set is kept.</summary>
    public event EventHandler<EidasTrustedListRefreshFailedEventArgs>? RefreshFailed;

    /// <inheritdoc />
    public string RegionCode => "EU";

    /// <inheritdoc />
    public string DisplayName => $"EU trusted lists (LOTL #{Current.Lotl.SequenceNumber}, {Current.Lists.Count} lists)";

    /// <inheritdoc />
    public IReadOnlyList<TrustedListInfo> TrustedLists => Current.TrustedLists;

    /// <inheritdoc />
    public IReadOnlyList<X509Certificate2> GetTrustAnchors() => Current.GetTrustAnchors();

    /// <inheritdoc />
    public IReadOnlyList<X509Certificate2> GetTrustAnchors(DateTimeOffset at) => Current.GetTrustAnchors(at);

    /// <inheritdoc />
    public IReadOnlyList<X509Certificate2> GetIntermediateCertificates() => Current.GetIntermediateCertificates();

    /// <summary>Loads the LOTL and its lists.</summary>
    /// <param name="options">Where the LOTL is and how it is read.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The source.</returns>
    /// <exception cref="CryptographicException">The LOTL is not signed by the known keys, nor carried to them by a pivot.</exception>
    /// <exception cref="HttpRequestException">The LOTL cannot be downloaded and has no usable cached copy.</exception>
    public static async Task<EidasTrustedListSource> LoadAsync(EidasExtensionOptions options, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        var set = await TrustedListSet.LoadAsync(EidasExtension.SetOptionsOf(options), options.HttpClientProvider, cancellationToken).ConfigureAwait(false);
        return new EidasTrustedListSource(options, set);
    }

    /// <summary>Reads the LOTL and its lists again; a set that loads replaces the one served.</summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Whether the set served changed.</returns>
    public async Task<bool> RefreshAsync(CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var previous = Current;
            TrustedListSet next;
            try
            {
                next = await TrustedListSet.LoadAsync(EidasExtension.SetOptionsOf(_options, previous.LotlSigners), _options.HttpClientProvider, cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is HttpRequestException or CryptographicException or InvalidDataException or TaskCanceledException
                && !cancellationToken.IsCancellationRequested)
            {
                LastError = ex.Message;
                RefreshFailed?.Invoke(this, new EidasTrustedListRefreshFailedEventArgs(ex.Message));
                return false;
            }

            LastChecked = DateTimeOffset.UtcNow;
            LastError = null;
            if (string.Equals(next.Lotl.SequenceNumber, previous.Lotl.SequenceNumber, StringComparison.Ordinal)
                && next.Lists.Select(l => l.SequenceNumber).SequenceEqual(previous.Lists.Select(l => l.SequenceNumber)))
            {
                return false;
            }

            Volatile.Write(ref _current, next);
            Changed?.Invoke(this, new EidasTrustedListChangedEventArgs(previous, next));
            return true;
        }
        finally
        {
            _gate.Release();
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
            throw new InvalidOperationException("The trusted lists are already refreshed on a schedule.");
        }

        _autoRefresh = new CancellationTokenSource();
        var token = _autoRefresh.Token;
        _autoRefreshTask = Task.Run(async () =>
        {
            while (!token.IsCancellationRequested)
            {
                await Task.Delay(interval, token).ConfigureAwait(false);
                await RefreshAsync(token).ConfigureAwait(false);
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
        _gate.Dispose();
    }
}

using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace SimpleSign.Core.Crypto;

/// <summary>
/// A pool of TSA (Time Stamp Authority) servers with automatic failover.
/// When the primary TSA fails, subsequent requests are routed to the next healthy server.
/// Uses circuit breaker logic: after <see cref="FailureThreshold"/> consecutive failures,
/// a TSA is marked unhealthy for <see cref="RecoveryInterval"/> before being retried.
/// </summary>
public sealed class TsaPool
{
    private readonly TsaEndpoint[] _endpoints;
    private readonly ILogger _logger;
    private int _primaryIndex;

    /// <summary>Number of consecutive failures before a TSA is marked unhealthy. Default: 3.</summary>
    public int FailureThreshold { get; init; } = 3;

    /// <summary>Time a failed TSA stays unhealthy before being retried. Default: 60 seconds.</summary>
    public TimeSpan RecoveryInterval { get; init; } = TimeSpan.FromSeconds(60);

    /// <summary>
    /// Creates a TSA pool with the specified endpoints.
    /// The first endpoint is the primary; others are fallbacks in order.
    /// </summary>
    /// <param name="tsaUrls">One or more TSA endpoint URLs.</param>
    /// <param name="logger">Optional logger.</param>
    /// <exception cref="ArgumentException">Thrown if no URLs are provided.</exception>
    public TsaPool(IEnumerable<string> tsaUrls, ILogger? logger = null)
    {
        var urls = tsaUrls?.ToArray() ?? throw new ArgumentNullException(nameof(tsaUrls));
        if (urls.Length == 0)
        {
            throw new ArgumentException("At least one TSA URL is required.", nameof(tsaUrls));
        }

        _endpoints = urls.Select(u => new TsaEndpoint(u)).ToArray();
        _logger = logger ?? NullLogger.Instance;
    }

    /// <summary>Number of configured TSA endpoints.</summary>
    public int EndpointCount => _endpoints.Length;

    /// <summary>
    /// Requests a timestamp token, trying each healthy TSA in order until one succeeds.
    /// </summary>
    /// <param name="dataToTimestamp">Data to timestamp.</param>
    /// <param name="hashAlgorithm">Hash algorithm for the timestamp request.</param>
    /// <param name="httpClient">HTTP client for the requests.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>DER-encoded timestamp token.</returns>
    /// <exception cref="InvalidOperationException">Thrown if all TSAs are unavailable.</exception>
    public async Task<byte[]> GetTimestampAsync(
        ReadOnlyMemory<byte> dataToTimestamp,
        HashAlgorithmName hashAlgorithm,
        HttpClient httpClient,
        CancellationToken cancellationToken = default)
    {
        var startIndex = Volatile.Read(ref _primaryIndex);
        Exception? lastException = null;

        for (var attempt = 0; attempt < _endpoints.Length; attempt++)
        {
            var index = (startIndex + attempt) % _endpoints.Length;
            var endpoint = _endpoints[index];

            if (!endpoint.IsHealthy(FailureThreshold, RecoveryInterval))
            {
                _logger.TsaSkippingUnhealthy(endpoint.Url, endpoint.ConsecutiveFailures);
                continue;
            }

            try
            {
                var client = new TimestampClient(httpClient, endpoint.Url, _logger);
                var token = await client.GetTimestampAsync(dataToTimestamp, hashAlgorithm, cancellationToken).ConfigureAwait(false);

                endpoint.RecordSuccess();

                // Promote this endpoint as the new primary
                if (index != startIndex)
                {
                    _logger.TsaFailover(_endpoints[startIndex].Url, endpoint.Url);
                    Volatile.Write(ref _primaryIndex, index);
                }

                return token;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                // User-initiated cancellation — propagate immediately without recording a failure
                throw;
            }
            catch (Exception ex)
            {
                endpoint.RecordFailure();
                lastException = ex;
                _logger.LogWarning(ex, "TSA {TsaUrl} failed (consecutive failures: {Failures})", endpoint.Url, endpoint.ConsecutiveFailures);
            }
        }

        throw new InvalidOperationException(
            $"All {_endpoints.Length} TSA endpoints are unavailable.",
            lastException);
    }

    /// <summary>Returns the health status of all configured TSA endpoints.</summary>
    public IReadOnlyList<TsaEndpointStatus> GetEndpointStatuses()
    {
        return _endpoints.Select((e, i) => new TsaEndpointStatus
        {
            Url = e.Url,
            IsHealthy = e.IsHealthy(FailureThreshold, RecoveryInterval),
            ConsecutiveFailures = e.ConsecutiveFailures,
            LastFailureUtc = e.LastFailureUtc,
            IsPrimary = i == Volatile.Read(ref _primaryIndex)
        }).ToArray();
    }

    /// <summary>Resets all endpoints to healthy state.</summary>
    public void ResetAll()
    {
        foreach (var endpoint in _endpoints)
        {
            endpoint.Reset();
        }

        Volatile.Write(ref _primaryIndex, 0);
    }

    private sealed class TsaEndpoint(string url)
    {
        public string Url { get; } = url;
        private int _consecutiveFailures;
        private long _lastFailureTicksUtc;

        public int ConsecutiveFailures => Volatile.Read(ref _consecutiveFailures);

        public DateTime? LastFailureUtc
        {
            get
            {
                long ticks = Interlocked.Read(ref _lastFailureTicksUtc);
                return ticks == 0 ? null : new DateTime(ticks, DateTimeKind.Utc);
            }
        }

        public bool IsHealthy(int threshold, TimeSpan recoveryInterval)
        {
            if (Volatile.Read(ref _consecutiveFailures) < threshold)
            {
                return true;
            }

            // Check if recovery interval has elapsed
            long ticks = Interlocked.Read(ref _lastFailureTicksUtc);
            return ticks == 0 || DateTime.UtcNow - new DateTime(ticks, DateTimeKind.Utc) >= recoveryInterval;
        }

        public void RecordSuccess()
        {
            Volatile.Write(ref _consecutiveFailures, 0);
        }

        public void RecordFailure()
        {
            Interlocked.Increment(ref _consecutiveFailures);
            Interlocked.Exchange(ref _lastFailureTicksUtc, DateTime.UtcNow.Ticks);
        }

        public void Reset()
        {
            Volatile.Write(ref _consecutiveFailures, 0);
            Interlocked.Exchange(ref _lastFailureTicksUtc, 0);
        }
    }
}

/// <summary>Health status of a TSA endpoint.</summary>
public sealed class TsaEndpointStatus
{
    /// <summary>TSA URL.</summary>
    public required string Url { get; init; }

    /// <summary>Whether the endpoint is currently considered healthy.</summary>
    public required bool IsHealthy { get; init; }

    /// <summary>Number of consecutive failures.</summary>
    public required int ConsecutiveFailures { get; init; }

    /// <summary>When the last failure occurred, or null if no failures.</summary>
    public DateTime? LastFailureUtc { get; init; }

    /// <summary>Whether this is the current primary endpoint.</summary>
    public required bool IsPrimary { get; init; }
}

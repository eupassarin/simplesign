using System.Net;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Polly;
using Polly.Retry;

namespace SimpleSign.Core.Http;

/// <summary>
/// Provides a shared resilience pipeline for HTTP operations (OCSP, CRL, TSA, AIA downloads).
/// Applies retry with exponential backoff to transient failures.
/// </summary>
internal static class ResilientHttp
{
    /// <summary>Default HTTP timeout applied to shared HttpClient instances.</summary>
    internal static readonly TimeSpan DefaultHttpTimeout = TimeSpan.FromSeconds(30);

    /// <summary>Default timeout for X509Chain URL retrieval.</summary>
    internal static readonly TimeSpan DefaultChainRetrievalTimeout = TimeSpan.FromSeconds(15);

    private const int MaxRetryAttempts = 3;
    private static readonly TimeSpan InitialRetryDelay = TimeSpan.FromMilliseconds(200);

    /// <summary>
    /// Shared resilience pipeline: retries with exponential backoff for transient failures.
    /// </summary>
    internal static readonly ResiliencePipeline<HttpResponseMessage> Pipeline =
        new ResiliencePipelineBuilder<HttpResponseMessage>()
            .AddRetry(new RetryStrategyOptions<HttpResponseMessage>
            {
                MaxRetryAttempts = MaxRetryAttempts,
                BackoffType = DelayBackoffType.Exponential,
                Delay = InitialRetryDelay,
                UseJitter = true,
                ShouldHandle = new PredicateBuilder<HttpResponseMessage>()
                    .Handle<HttpRequestException>()
                    .Handle<TaskCanceledException>()
                    .HandleResult(r => r.StatusCode >= HttpStatusCode.InternalServerError),
            })
            .Build();

    /// <summary>
    /// Executes an HTTP GET with resilience, returning the response bytes.
    /// Returns null if all retries fail or circuit is open.
    /// </summary>
    internal static async Task<byte[]?> GetBytesAsync(
        HttpClient httpClient, string url, ILogger? logger = null, CancellationToken ct = default)
    {
        if (!UrlValidator.IsSafeUrl(url))
        {
            (logger ?? NullLogger.Instance).HttpGetFailed(url, 0, "SSRF blocked: URL points to localhost or private network");
            return null;
        }

        try
        {
            using var response = await Pipeline.ExecuteAsync(async token =>
                await httpClient.GetAsync(url, token).ConfigureAwait(false), ct).ConfigureAwait(false);
            response.EnsureSuccessStatusCode();
            return await response.Content.ReadAsByteArrayAsync(ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (!ct.IsCancellationRequested)
        {
            (logger ?? NullLogger.Instance).HttpGetFailed(url, MaxRetryAttempts, ex.Message);
            return null;
        }
    }

    /// <summary>
    /// Executes an HTTP POST with resilience, returning the response.
    /// Caller is responsible for disposing the response.
    /// Throws on failure after retries are exhausted.
    /// </summary>
    internal static async Task<HttpResponseMessage> PostAsync(
        HttpClient httpClient, string url, HttpContent content, CancellationToken ct = default)
    {
        if (!UrlValidator.IsSafeUrl(url))
        {
            throw new InvalidOperationException($"SSRF blocked: URL points to localhost or private network — {new Uri(url).Host}");
        }

        return await Pipeline.ExecuteAsync(async token =>
            await httpClient.PostAsync(url, content, token).ConfigureAwait(false), ct).ConfigureAwait(false);
    }
}

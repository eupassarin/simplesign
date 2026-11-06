using System.Net;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Polly;
using Polly.Retry;
using SimpleSign.Core.Internal;

namespace SimpleSign.Core.Http;

/// <summary>
/// Provides a shared resilience pipeline for HTTP operations (OCSP, CRL, TSA, AIA downloads).
/// Applies retry with exponential backoff to transient failures, and refuses URLs that point to
/// localhost or private networks. Country extensions use it to download roots, CRLs and policies.
/// </summary>
public static class ResilientHttp
{
    /// <summary>Default HTTP timeout applied to shared HttpClient instances.</summary>
    internal static readonly TimeSpan DefaultHttpTimeout = TimeSpan.FromSeconds(30);

    /// <summary>Default timeout for X509Chain URL retrieval (<see cref="System.Security.Cryptography.X509Certificates.X509ChainPolicy.UrlRetrievalTimeout"/>).</summary>
    public static readonly TimeSpan DefaultChainRetrievalTimeout = TimeSpan.FromSeconds(15);

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
                OnRetry = args =>
                {
                    args.Outcome.Result?.Dispose();
                    return default;
                },
            })
            .Build();

    /// <summary>
    /// Executes an HTTP GET with retries and returns the response body. Returns
    /// <see langword="null"/> when every attempt fails or the URL points to a local or private address.
    /// </summary>
    /// <param name="httpClient">The client that sends the request.</param>
    /// <param name="uri">The absolute URL to download.</param>
    /// <param name="logger">Optional logger for failed attempts.</param>
    /// <param name="cancellationToken">Cancels the download.</param>
    /// <returns>The response bytes, or <see langword="null"/>.</returns>
    public static Task<byte[]?> GetBytesAsync(
        HttpClient httpClient, Uri uri, ILogger? logger = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(httpClient);
        ArgumentNullException.ThrowIfNull(uri);
        return GetBytesAsync(httpClient, uri.AbsoluteUri, logger, cancellationToken);
    }

    /// <summary>
    /// Executes an HTTP GET with resilience, returning the response bytes.
    /// Returns null if all retries fail or circuit is open.
    /// </summary>
    internal static async Task<byte[]?> GetBytesAsync(
        HttpClient httpClient, string url, ILogger? logger = null, CancellationToken ct = default)
    {
        if (!await UrlValidator.IsSafeUrlAsync(url, ct).ConfigureAwait(false))
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
        if (!await UrlValidator.IsSafeUrlAsync(url, ct).ConfigureAwait(false))
        {
            throw new InvalidOperationException($"SSRF blocked: URL points to localhost or private network — {new Uri(url).Host}");
        }

        return await Pipeline.ExecuteAsync(async token =>
            await httpClient.PostAsync(url, content, token).ConfigureAwait(false), ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Executes an HTTP POST with resilience and an Authorization header. A new request and
    /// content are built per attempt, so credentials never go on the shared client's default headers.
    /// </summary>
    internal static async Task<HttpResponseMessage> PostAsync(
        HttpClient httpClient,
        string url,
        byte[] body,
        System.Net.Http.Headers.MediaTypeHeaderValue contentType,
        System.Net.Http.Headers.AuthenticationHeaderValue authorization,
        CancellationToken ct = default)
    {
        if (!await UrlValidator.IsSafeUrlAsync(url, ct).ConfigureAwait(false))
        {
            throw new InvalidOperationException($"SSRF blocked: URL points to localhost or private network — {new Uri(url).Host}");
        }

        return await Pipeline.ExecuteAsync(async token =>
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, url);
            request.Content = new ByteArrayContent(body);
            request.Content.Headers.ContentType = contentType;
            request.Headers.Authorization = authorization;
            return await httpClient.SendAsync(request, token).ConfigureAwait(false);
        }, ct).ConfigureAwait(false);
    }
}

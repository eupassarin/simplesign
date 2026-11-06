using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using SimpleSign.Core.Http;

namespace SimpleSign.Core.Crypto;

/// <summary>Default factory for creating <see cref="TimestampClient"/> instances.</summary>
public sealed class TimestampClientFactory : ITimestampClientFactory
{
    private readonly IHttpClientProvider _httpClientProvider;
    private readonly ILogger _logger;

    /// <summary>Creates a factory backed by the given HTTP client provider.</summary>
    public TimestampClientFactory(IHttpClientProvider httpClientProvider, ILogger? logger = null)
    {
        ArgumentNullException.ThrowIfNull(httpClientProvider);
        _httpClientProvider = httpClientProvider;
        _logger = logger ?? NullLogger.Instance;
    }

    /// <inheritdoc />
    public ITimestampClient Create(string tsaUrl)
    {
        var httpClient = _httpClientProvider.GetClient();
        return new TimestampClient(httpClient, tsaUrl, _logger);
    }
}

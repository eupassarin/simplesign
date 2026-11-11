using SimpleSign.Core.Http;

namespace SimpleSign.Core.Signing;

/// <summary>
/// Configuration for the archive timestamp (B-LTA). When <see cref="Endpoint"/>
/// is <see langword="null"/>, the signature timestamp endpoint and provider from
/// <see cref="TimestampOptions"/> are reused.
/// </summary>
public sealed record ArchiveTimestampOptions
{
    /// <summary>
    /// Optional archival TSA endpoint. When <see langword="null"/>, the signature
    /// timestamp endpoint is reused.
    /// </summary>
    public Uri? Endpoint { get; }

    /// <summary>
    /// Optional archive-TSA-specific <see cref="IHttpClientProvider"/>. When
    /// <see langword="null"/>, resolution falls back to the signature timestamp
    /// provider and then to the builder-wide provider.
    /// </summary>
    public IHttpClientProvider? HttpClientProvider { get; }

    /// <summary>
    /// Credentials for an archive TSA set with <see cref="Endpoint"/> (Basic or bearer, sent per
    /// request). When <see cref="Endpoint"/> is null, the signature TSA's credentials are used.
    /// </summary>
    public System.Net.Http.Headers.AuthenticationHeaderValue? Authorization { get; init; }

    /// <summary>
    /// Client certificate (mutual TLS) for an archive TSA set with <see cref="Endpoint"/>. When
    /// <see cref="Endpoint"/> is null, the signature TSA's certificate is used.
    /// </summary>
    public System.Security.Cryptography.X509Certificates.X509Certificate2? ClientCertificate { get; init; }

    /// <summary>
    /// The certificate the archive TSA is expected to sign with, when <see cref="Endpoint"/> is set (see
    /// <see cref="TimestampOptions.ExpectedTsaCertificate"/>). Without an endpoint, the signature TSA's applies.
    /// </summary>
    public System.Security.Cryptography.X509Certificates.X509Certificate2? ExpectedTsaCertificate { get; init; }

    /// <summary>The TSA settings the archive timestamp uses, given the signature TSA's.</summary>
    /// <param name="signatureTimestamp">The signature timestamp settings.</param>
    public TimestampOptions Resolve(TimestampOptions signatureTimestamp)
    {
        ArgumentNullException.ThrowIfNull(signatureTimestamp);
        if (Endpoint is null)
        {
            return HttpClientProvider is null
                ? signatureTimestamp
                : new TimestampOptions(signatureTimestamp.Endpoint, HttpClientProvider)
                {
                    Authorization = signatureTimestamp.Authorization,
                    ClientCertificate = signatureTimestamp.ClientCertificate,
                    ExpectedTsaCertificate = signatureTimestamp.ExpectedTsaCertificate,
                };
        }

        return new TimestampOptions(Endpoint, HttpClientProvider ?? signatureTimestamp.HttpClientProvider)
        {
            Authorization = Authorization,
            ClientCertificate = ClientCertificate,
            ExpectedTsaCertificate = ExpectedTsaCertificate,
        };
    }

    /// <summary>Creates a new instance.</summary>
    /// <param name="endpoint">Optional archival TSA endpoint (null reuses the signature TSA endpoint).</param>
    /// <param name="httpClientProvider">Optional archive-TSA-specific HTTP client provider.</param>
    /// <exception cref="ArgumentException"><paramref name="endpoint"/> is supplied but not absolute.</exception>
    public ArchiveTimestampOptions(
        Uri? endpoint = null,
        IHttpClientProvider? httpClientProvider = null)
    {
        if (endpoint is not null && (!endpoint.IsAbsoluteUri ||
            (endpoint.Scheme != Uri.UriSchemeHttp && endpoint.Scheme != Uri.UriSchemeHttps)))
        {
            throw new ArgumentException(
                "Archive TSA endpoint must be an absolute HTTP(S) URI.",
                nameof(endpoint));
        }

        Endpoint = endpoint;
        HttpClientProvider = httpClientProvider;
    }
}

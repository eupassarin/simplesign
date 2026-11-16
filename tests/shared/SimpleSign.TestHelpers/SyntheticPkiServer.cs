using System.Net;
using System.Net.Http.Headers;
using SimpleSign.Core.Http;

namespace SimpleSign.TestHelpers;

/// <summary>
/// The network of a <see cref="SyntheticPki"/> in memory: a TSA (any POST, genTime 2024-01-01) and the leaf and
/// intermediate CRLs at their distribution points, counting how many times a CRL is downloaded.
/// </summary>
public sealed class SyntheticPkiServer : IDisposable
{
    /// <summary>The leaf CRL's URL.</summary>
    public const string LeafCrlUrl = "http://198.51.100.20/leaf.crl";

    /// <summary>The intermediate CRL's URL.</summary>
    public const string IntermediateCrlUrl = "http://198.51.100.20/intermediate.crl";

    /// <summary>The TSA's URL.</summary>
    public const string TsaUrl = "http://198.51.100.20/tsa";

    private readonly HttpClient _client;
    private int _crlDownloads;

    /// <summary>Creates the PKI (CRL distribution points at <see cref="LeafCrlUrl"/> and <see cref="IntermediateCrlUrl"/>) and its server.</summary>
    public SyntheticPkiServer()
    {
        Pki = new SyntheticPki(crlDistributionPoint: LeafCrlUrl, intermediateCrlDistributionPoint: IntermediateCrlUrl);
        byte[] leafCrl = Pki.BuildLeafCrl();
        byte[] intermediateCrl = Pki.BuildIntermediateCrl();
        _client = new HttpClient(new MockHttpHandler(async request =>
        {
            if (request.Method == HttpMethod.Post)
            {
                byte[] tsq = await request.Content!.ReadAsByteArrayAsync().ConfigureAwait(false);
                var response = new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(TimestampTestResponseBuilder.CreateForRequest(tsq)) };
                response.Content.Headers.ContentType = new MediaTypeHeaderValue("application/timestamp-reply");
                return response;
            }

            byte[]? crl = request.RequestUri?.ToString() switch
            {
                LeafCrlUrl => leafCrl,
                IntermediateCrlUrl => intermediateCrl,
                _ => null,
            };
            if (crl is null)
            {
                return new HttpResponseMessage(HttpStatusCode.NotFound);
            }

            Interlocked.Increment(ref _crlDownloads);
            return new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(crl) };
        }));
        Provider = new SingleClientProvider(_client);
    }

    /// <summary>The PKI.</summary>
    public SyntheticPki Pki { get; }

    /// <summary>The HTTP clients that reach this server.</summary>
    public IHttpClientProvider Provider { get; }

    /// <summary>How many CRLs were downloaded since the last <see cref="ResetCount"/>.</summary>
    public int CrlDownloads => Volatile.Read(ref _crlDownloads);

    /// <summary>Starts counting again.</summary>
    public void ResetCount() => Interlocked.Exchange(ref _crlDownloads, 0);

    /// <inheritdoc />
    public void Dispose()
    {
        _client.Dispose();
        Pki.Dispose();
    }
}

using System.Net;
using SimpleSign.TestHelpers;

namespace SimpleSign.Interop.Tests;

/// <summary>
/// Builds an <see cref="HttpClient"/> that serves the synthetic PKI CRL distribution
/// points and rejects unconfigured endpoints, so strict B-LT/B-LTA signing tests can
/// collect realistic revocation material without depending on public infrastructure.
/// </summary>
internal static class TestRevocation
{
    private const string LeafCrlUrl = "http://crl.example.com/leaf.crl";
    private const string IntermediateCrlUrl = "http://crl.example.com/intermediate.crl";

    internal static SyntheticPki CreatePki() => new(
        crlDistributionPoint: LeafCrlUrl,
        intermediateCrlDistributionPoint: IntermediateCrlUrl);

    internal static HttpClient BuildCrlClient(SyntheticPki pki)
    {
        ArgumentNullException.ThrowIfNull(pki);
        return new HttpClient(new RevocationRoutingHandler(
            pki.BuildLeafCrl(),
            pki.BuildIntermediateCrl()));
    }

    private sealed class RevocationRoutingHandler(
        byte[] leafCrl,
        byte[] intermediateCrl) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            string? requestUri = request.RequestUri?.ToString();
            if (string.Equals(requestUri, LeafCrlUrl, StringComparison.Ordinal))
            {
                return Task.FromResult(CrlResponse(leafCrl));
            }

            if (string.Equals(requestUri, IntermediateCrlUrl, StringComparison.Ordinal))
            {
                return Task.FromResult(CrlResponse(intermediateCrl));
            }

            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
        }

        private static HttpResponseMessage CrlResponse(byte[] crl) => new(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(crl)
        };
    }
}

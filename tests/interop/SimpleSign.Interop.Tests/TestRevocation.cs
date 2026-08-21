using System.Net;
using SimpleSign.TestHelpers;

namespace SimpleSign.Interop.Tests;

/// <summary>
/// Builds an <see cref="HttpClient"/> that answers every request (CRL distribution
/// points, AIA) with the provided CRL bytes, so strict B-LT/B-LTA signing tests can
/// collect realistic revocation material without depending on public infrastructure.
/// </summary>
internal static class TestRevocation
{
    internal static HttpClient BuildCrlClient(byte[] crlBytes) =>
        new(new MockHttpHandler(_ => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(crlBytes)
        })));
}

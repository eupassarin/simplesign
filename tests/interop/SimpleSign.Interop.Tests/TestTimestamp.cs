using System.Net;
using System.Net.Http.Headers;
using SimpleSign.Core.Http;
using SimpleSign.Core.Signing;
using SimpleSign.TestHelpers;

namespace SimpleSign.Interop.Tests;

/// <summary>Offline signed TSA responses shared by routine interoperability tests.</summary>
internal static class TestTimestamp
{
    internal const string Endpoint = "https://tsa.example.test";

    internal static TimestampOptions Options(HttpClient client) =>
        new(new Uri(Endpoint), new SingleClientProvider(client));

    internal static HttpClient CreateClient() =>
        new(new MockHttpHandler(async request =>
        {
            byte[] requestBytes = await request.Content!.ReadAsByteArrayAsync();
            var response = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new ByteArrayContent(TimestampTestResponseBuilder.CreateForRequest(requestBytes))
            };
            response.Content.Headers.ContentType = new MediaTypeHeaderValue("application/timestamp-reply");
            return response;
        }));
}

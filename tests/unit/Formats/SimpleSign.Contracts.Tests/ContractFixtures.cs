using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography.X509Certificates;
using SimpleSign.TestHelpers;

namespace SimpleSign.Contracts.Tests;

/// <summary>
/// Shared cross-format helpers for the signing contract tests: a mock TSA serving a
/// RFC 3161 responses bound to the received request and signing certificates.
/// </summary>
internal static class ContractFixtures
{
    internal static readonly byte[] XmlDocument = "<?xml version=\"1.0\"?><root><data>contract test</data></root>"u8.ToArray();

    internal static readonly byte[] BinaryContent = "Cross-format contract test content"u8.ToArray();

    internal static X509Certificate2 CreateSignerCertificate(string subject = "CN=Contract Signer, O=Tests") =>
        TestCertificateFactory.CreateSelfSignedCert(subject);

    internal static HttpMessageHandler BuildMockTsaHandler() =>
        new MockHttpHandler(async request =>
        {
            byte[] requestBytes = await request.Content!.ReadAsByteArrayAsync();
            var response = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new ByteArrayContent(TimestampTestResponseBuilder.CreateForRequest(requestBytes))
            };
            response.Content.Headers.ContentType =
                new MediaTypeHeaderValue("application/timestamp-reply");
            return response;
        });

    internal static HttpClient BuildMockTsaClient() => new(BuildMockTsaHandler());

    internal static HttpClient BuildFailingClient() => MockHttpHandler.Failing();

}

/// <summary>Builds an <see cref="HttpClient"/> that serves the provided bytes for any request.</summary>
internal static class TestRevocationClient
{
    internal static HttpClient Build(byte[] responseBytes) =>
        new(new MockHttpHandler(_ => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(responseBytes)
        })));

    internal static HttpClient BuildForUris(params (string Uri, byte[] Response)[] responses) =>
        new(new MockHttpHandler(request =>
        {
            byte[]? response = responses
                .FirstOrDefault(candidate => string.Equals(
                    candidate.Uri, request.RequestUri?.ToString(), StringComparison.Ordinal))
                .Response;
            return Task.FromResult(response is null
                ? new HttpResponseMessage(HttpStatusCode.NotFound)
                : new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new ByteArrayContent(response)
                });
        }));
}

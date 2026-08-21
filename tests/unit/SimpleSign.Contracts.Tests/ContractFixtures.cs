using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography.X509Certificates;
using SimpleSign.TestHelpers;

namespace SimpleSign.Contracts.Tests;

/// <summary>
/// Shared cross-format helpers for the signing contract tests: a mock TSA serving a
/// canned RFC 3161 response and signing certificates.
/// </summary>
internal static class ContractFixtures
{
    internal static readonly byte[] XmlDocument = "<?xml version=\"1.0\"?><root><data>contract test</data></root>"u8.ToArray();

    internal static readonly byte[] BinaryContent = "Cross-format contract test content"u8.ToArray();

    internal static X509Certificate2 CreateSignerCertificate(string subject = "CN=Contract Signer, O=Tests") =>
        TestCertificateFactory.CreateSelfSignedCert(subject);

    internal static HttpMessageHandler BuildMockTsaHandler() =>
        new MockHttpHandler(async _ =>
        {
            var response = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new ByteArrayContent(BuildFakeTimestampResponse())
            };
            response.Content.Headers.ContentType =
                new MediaTypeHeaderValue("application/timestamp-reply");
            await Task.CompletedTask;
            return response;
        });

    internal static HttpClient BuildMockTsaClient() => new(BuildMockTsaHandler());

    internal static HttpClient BuildFailingClient() => MockHttpHandler.Failing();

    /// <summary>Returns a valid DER-encoded fake CMS token suitable for embedding.</summary>
    internal static byte[] BuildFakeTimestampToken() => BuildFakeCmsToken();

    private static byte[] BuildFakeTimestampResponse()
    {
        var fakeCmsToken = BuildFakeCmsToken();
        var writer = new System.Formats.Asn1.AsnWriter(System.Formats.Asn1.AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            using (writer.PushSequence())
            {
                writer.WriteInteger(0);
            }
            writer.WriteEncodedValue(fakeCmsToken);
        }
        return writer.Encode();
    }

    private static byte[] BuildFakeCmsToken()
    {
        var writer = new System.Formats.Asn1.AsnWriter(System.Formats.Asn1.AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            writer.WriteObjectIdentifier("1.2.840.113549.1.7.2");
            using (writer.PushSequence(new System.Formats.Asn1.Asn1Tag(
                System.Formats.Asn1.TagClass.ContextSpecific, 0, true)))
            {
                writer.WriteOctetString([0x01, 0x02, 0x03]);
            }
        }
        return writer.Encode();
    }
}

/// <summary>Builds an <see cref="HttpClient"/> that serves the provided bytes for any request.</summary>
internal static class TestRevocationClient
{
    internal static HttpClient Build(byte[] responseBytes) =>
        new(new MockHttpHandler(_ => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(responseBytes)
        })));
}

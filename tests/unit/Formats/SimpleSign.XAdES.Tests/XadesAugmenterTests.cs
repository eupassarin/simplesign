using System.Security.Cryptography.X509Certificates;
using Shouldly;
using SimpleSign.Core.Http;
using SimpleSign.Core.Signing;
using SimpleSign.Core.Validation;
using SimpleSign.TestHelpers;
using SimpleSign.XAdES;
using Xunit;

namespace SimpleSign.XAdES.Tests;

/// <summary>Raising an existing XAdES signature to a higher level (B-LT and B-LTA are run against the Sandbox, in the TestBench tests).</summary>
[Trait("Category", "Unit")]
public sealed class XadesAugmenterTests : IDisposable
{
    private static readonly byte[] s_xml = "<?xml version=\"1.0\"?><order><total>10</total></order>"u8.ToArray();
    private readonly X509Certificate2 _cert = TestCertificateFactory.CreateSelfSignedCert();

    public void Dispose() => _cert.Dispose();

    private static HttpClient MockTsa() =>
        new(new MockHttpHandler(async request =>
        {
            byte[] body = await request.Content!.ReadAsByteArrayAsync().ConfigureAwait(false);
            return new HttpResponseMessage(System.Net.HttpStatusCode.OK)
            {
                Content = new ByteArrayContent(TimestampTestResponseBuilder.CreateForRequest(body))
                {
                    Headers = { ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/timestamp-reply") },
                },
            };
        }));

    [Fact]
    public async Task AugmentAsync_BasicToTimestamped_AddsTheSignatureTimeStampAndStaysValid()
    {
        using var tsa = MockTsa();
        byte[] signed = await XadesSigner.Document(s_xml).WithCertificate(_cert).SignAsync();

        var result = await XadesAugmenter.Document(signed)
            .WithTimestamp(new TimestampOptions(new Uri("http://tsa.example.com"), new SingleClientProvider(tsa)))
            .ToLevel(AdesBaselineLevel.Timestamped)
            .AugmentAsync();

        result.InitialLevel.ShouldBe(AdesBaselineLevel.Basic);
        result.Level.ShouldBe(AdesBaselineLevel.Timestamped);
        var validation = new XadesSignatureValidator(new ValidationOptions { CheckRevocation = false }).Validate(result.Document, [_cert]);
        validation.IsSignatureValid.ShouldBeTrue(string.Join("; ", validation.Errors));
    }

    [Fact]
    public async Task AugmentAsync_TargetAlreadyReached_ReturnsTheDocumentUnchanged()
    {
        byte[] signed = await XadesSigner.Document(s_xml).WithCertificate(_cert).SignAsync();

        var result = await XadesAugmenter.Document(signed).ToLevel(AdesBaselineLevel.Basic).AugmentAsync();

        result.Document.ShouldBeSameAs(signed);
        XadesAugmenter.LevelOf(signed).ShouldBe(AdesBaselineLevel.Basic);
    }

    [Fact]
    public async Task AugmentAsync_NoSuchSignature_Throws()
    {
        byte[] signed = await XadesSigner.Document(s_xml).WithCertificate(_cert).SignAsync();

        await Should.ThrowAsync<ArgumentException>(() => XadesAugmenter.Document(signed).ForSignature("nope").AugmentAsync());
    }
}

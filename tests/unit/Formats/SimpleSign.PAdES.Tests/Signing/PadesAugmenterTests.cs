using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Shouldly;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Http;
using SimpleSign.Core.Signing;
using SimpleSign.PAdES.Inspection;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.PAdES.Tests.Signing;

/// <summary>Raising an existing PAdES signature to a higher level (B-LT and B-LTA are run against the Sandbox, in the TestBench tests).</summary>
[Trait("Category", "Unit")]
public sealed class PadesAugmenterTests : IDisposable
{
    private readonly X509Certificate2 _cert = CreateRsaCert();

    public void Dispose() => _cert.Dispose();

    private static X509Certificate2 CreateRsaCert()
    {
        using RSA key = RSA.Create(2048);
        var request = new CertificateRequest("CN=Augment Test", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: false));
        using var cert = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        return CertificateLoader.LoadPkcs12(cert.Export(X509ContentType.Pfx, "export"), "export");
    }

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

    private Task<byte[]> SignBasicAsync() =>
        PadesSigner.Document(TestPdfFactory.CreateMinimalPdf()).WithCertificate(_cert).SignAsync();

    [Fact]
    public async Task AugmentAsync_BasicToTimestamped_AddsADocumentTimestamp()
    {
        using var tsa = MockTsa();
        byte[] signed = await SignBasicAsync();

        var result = await PadesAugmenter.Document(signed)
            .WithTimestamp(new TimestampOptions(new Uri("http://tsa.example.com"), new SingleClientProvider(tsa)))
            .ToLevel(AdesBaselineLevel.Timestamped)
            .AugmentAsync();

        result.InitialLevel.ShouldBe(AdesBaselineLevel.Basic);
        result.Level.ShouldBe(AdesBaselineLevel.Timestamped);
        result.Document.Length.ShouldBeGreaterThan(signed.Length);
        result.Document.AsSpan(0, signed.Length).SequenceEqual(signed).ShouldBeTrue("an incremental update keeps the signed bytes");
        var inspection = await PdfSignatureInspector.InspectAsync(new MemoryStream(result.Document));
        inspection.Signatures.Count(s => s.IsDocumentTimestamp).ShouldBe(1);
    }

    [Fact]
    public async Task AugmentAsync_TargetAlreadyReached_ReturnsTheDocumentUnchanged()
    {
        byte[] signed = await SignBasicAsync();

        var result = await PadesAugmenter.Document(signed).ToLevel(AdesBaselineLevel.Basic).AugmentAsync();

        result.Document.ShouldBeSameAs(signed);
        result.Level.ShouldBe(AdesBaselineLevel.Basic);
    }

    [Fact]
    public async Task AugmentAsync_NoTsa_LevelNotAchievable()
    {
        byte[] signed = await SignBasicAsync();

        var exception = await Should.ThrowAsync<SigningException>(() =>
            PadesAugmenter.Document(signed).ToLevel(AdesBaselineLevel.Timestamped).AugmentAsync());

        exception.Reason.ShouldBe(SigningErrorReason.LevelNotAchievable);
    }

    [Fact]
    public async Task AugmentAsync_UnsignedPdf_Throws() =>
        await Should.ThrowAsync<ArgumentException>(() => PadesAugmenter.Document(TestPdfFactory.CreateMinimalPdf()).AugmentAsync());
}

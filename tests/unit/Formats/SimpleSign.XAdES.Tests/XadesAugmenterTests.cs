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

    private static HttpClient MockTsa(X509Certificate2? tsaCertificate = null) =>
        new(new MockHttpHandler(async request =>
        {
            byte[] body = await request.Content!.ReadAsByteArrayAsync().ConfigureAwait(false);
            var options = tsaCertificate is null ? null : new TimestampTokenOptions { TsaCertificate = tsaCertificate, GenTime = DateTimeOffset.UtcNow };
            return new HttpResponseMessage(System.Net.HttpStatusCode.OK)
            {
                Content = new ByteArrayContent(TimestampTestResponseBuilder.CreateForRequest(body, options))
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

    [Theory]
    [InlineData(true, 2)]
    [InlineData(false, 4)]
    public async Task AugmentAsync_BatchWithASharedRevocationCache_DownloadsEachCrlOnce(bool shared, int expectedDownloads)
    {
        using var server = new SyntheticPkiServer();
        var tsa = new TimestampOptions(new Uri(SyntheticPkiServer.TsaUrl));
        var signatures = new List<byte[]>();
        for (int i = 0; i < 2; i++)
        {
            signatures.Add(await XadesSigner.Document(s_xml)
                .WithCertificate(server.Pki.Leaf, server.Pki.IntermediatesAndRoot())
                .WithHttpClientProvider(server.Provider)
                .WithLevel(AdesBaselineProfile.Timestamped(tsa))
                .SignAsync());
        }

        server.ResetCount();
        var cache = new SimpleSign.Core.Revocation.InMemoryRevocationCache(TimeSpan.FromHours(1));
        foreach (byte[] signature in signatures)
        {
            var augmenter = XadesAugmenter.Document(signature).WithTimestamp(tsa).WithHttpClientProvider(server.Provider).ToLevel(AdesBaselineLevel.LongTerm);
            var result = await (shared ? augmenter.WithRevocationCache(cache) : augmenter).AugmentAsync();
            result.Level.ShouldBe(AdesBaselineLevel.LongTerm);
        }

        // The time-stamps say 2024-01-01 and the CRLs were issued after it: the cached ones prove the same thing.
        server.CrlDownloads.ShouldBe(expectedDownloads);
    }

    [Fact]
    public async Task AugmentAsync_TokenFromAnotherTsaThanExpected_ThrowsTimestampUntrusted()
    {
        using var pki = new SyntheticPki();
        using var expected = pki.IssueTimestampingCertificate("CN=Expected TSA");
        using var other = pki.IssueTimestampingCertificate("CN=Other TSA");
        using var tsa = MockTsa(other);
        byte[] signed = await XadesSigner.Document(s_xml).WithCertificate(_cert).SignAsync();

        var exception = await Should.ThrowAsync<SigningException>(() => XadesAugmenter.Document(signed)
            .WithTimestamp(new TimestampOptions(new Uri("http://tsa.example.com"), new SingleClientProvider(tsa)) { ExpectedTsaCertificate = expected })
            .ToLevel(AdesBaselineLevel.Timestamped)
            .AugmentAsync());

        exception.Reason.ShouldBe(SigningErrorReason.TimestampUntrusted);
    }

    [Fact]
    public async Task AugmentAsync_TokenFromTheExpectedTsa_ReachesTheLevel()
    {
        using var pki = new SyntheticPki();
        using var expected = pki.IssueTimestampingCertificate("CN=Expected TSA");
        using var tsa = MockTsa(expected);
        byte[] signed = await XadesSigner.Document(s_xml).WithCertificate(_cert).SignAsync();

        var result = await XadesAugmenter.Document(signed)
            .WithTimestamp(new TimestampOptions(new Uri("http://tsa.example.com"), new SingleClientProvider(tsa)) { ExpectedTsaCertificate = expected })
            .ToLevel(AdesBaselineLevel.Timestamped)
            .AugmentAsync();

        result.Level.ShouldBe(AdesBaselineLevel.Timestamped);
    }
}

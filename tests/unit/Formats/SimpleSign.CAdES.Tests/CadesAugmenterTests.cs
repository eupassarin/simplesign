using System.Security.Cryptography.X509Certificates;
using Shouldly;
using SimpleSign.Core.Http;
using SimpleSign.Core.Signing;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.CAdES.Tests;

/// <summary>Raising an existing CAdES signature to a higher level (B-LT and B-LTA are run against the Sandbox, in the TestBench tests).</summary>
[Trait("Category", "Unit")]
public sealed class CadesAugmenterTests : IDisposable
{
    private readonly X509Certificate2 _cert = TestCertificateFactory.CreateSelfSignedCert();
    private readonly byte[] _data = "content"u8.ToArray();

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
    public async Task AugmentAsync_BasicToTimestamped_AddsTheSignatureTimestampAndStaysValid()
    {
        using var tsa = MockTsa();
        byte[] cms = await CadesSigner.Document(_data).WithCertificate(_cert).SignAsync();

        var result = await CadesAugmenter.Signature(cms, _data)
            .WithTimestamp(new TimestampOptions(new Uri("http://tsa.example.com"), new SingleClientProvider(tsa)))
            .ToLevel(AdesBaselineLevel.Timestamped)
            .AugmentAsync();

        result.InitialLevel.ShouldBe(AdesBaselineLevel.Basic);
        result.Level.ShouldBe(AdesBaselineLevel.Timestamped);
        var validation = new CadesSignatureValidator(new SimpleSign.Core.Validation.ValidationOptions { CheckRevocation = false })
            .Validate(result.Signature, _data, [_cert]);
        validation.IsSignatureValid.ShouldBeTrue(string.Join("; ", validation.Errors));
        validation.IsIntegrityValid.ShouldBeTrue();
    }

    [Fact]
    public async Task AugmentAsync_TargetAlreadyReached_ReturnsTheSignatureUnchanged()
    {
        byte[] cms = await CadesSigner.Document(_data).WithCertificate(_cert).SignAsync();

        var result = await CadesAugmenter.Signature(cms).ToLevel(AdesBaselineLevel.Basic).AugmentAsync();

        result.Signature.ShouldBeSameAs(cms);
        CadesAugmenter.LevelOf(cms).ShouldBe(AdesBaselineLevel.Basic);
    }

    [Fact]
    public async Task AugmentAsync_NoTsa_LevelNotAchievable()
    {
        byte[] cms = await CadesSigner.Document(_data).WithCertificate(_cert).SignAsync();

        var exception = await Should.ThrowAsync<SigningException>(() =>
            CadesAugmenter.Signature(cms).ToLevel(AdesBaselineLevel.Timestamped).AugmentAsync());

        exception.Reason.ShouldBe(SigningErrorReason.LevelNotAchievable);
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
            signatures.Add(await CadesSigner.Document(_data)
                .WithCertificate(server.Pki.Leaf, server.Pki.IntermediatesAndRoot())
                .WithHttpClientProvider(server.Provider)
                .WithLevel(AdesBaselineProfile.Timestamped(tsa))
                .SignAsync());
        }

        server.ResetCount();
        var cache = new SimpleSign.Core.Revocation.InMemoryRevocationCache(TimeSpan.FromHours(1));
        foreach (byte[] signature in signatures)
        {
            var augmenter = CadesAugmenter.Signature(signature, _data).WithTimestamp(tsa).WithHttpClientProvider(server.Provider).ToLevel(AdesBaselineLevel.LongTerm);
            var result = await (shared ? augmenter.WithRevocationCache(cache) : augmenter).AugmentAsync();
            result.Level.ShouldBe(AdesBaselineLevel.LongTerm);
        }

        server.CrlDownloads.ShouldBe(expectedDownloads);
    }

    [Fact]
    public async Task AugmentAsync_TokenFromAnotherTsaThanExpected_ThrowsTimestampUntrusted()
    {
        using var pki = new SyntheticPki();
        using var expected = pki.IssueTimestampingCertificate("CN=Expected TSA");
        using var other = pki.IssueTimestampingCertificate("CN=Other TSA");
        using var tsa = MockTsa(other);
        byte[] signed = await CadesSigner.Document(_data).WithCertificate(_cert).SignAsync();

        var exception = await Should.ThrowAsync<SigningException>(() => CadesAugmenter.Signature(signed, _data)
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
        byte[] signed = await CadesSigner.Document(_data).WithCertificate(_cert).SignAsync();

        var result = await CadesAugmenter.Signature(signed, _data)
            .WithTimestamp(new TimestampOptions(new Uri("http://tsa.example.com"), new SingleClientProvider(tsa)) { ExpectedTsaCertificate = expected })
            .ToLevel(AdesBaselineLevel.Timestamped)
            .AugmentAsync();

        result.Level.ShouldBe(AdesBaselineLevel.Timestamped);
    }
}

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
}

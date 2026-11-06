using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Shouldly;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Signing;
using SimpleSign.PAdES.Signing;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.PAdES.Tests.Signing;

/// <summary>Regression tests for PAdES B-LT fulfillment when DSS material is incomplete.</summary>
[Trait("Category", "Unit")]
public sealed class PadesLtvFulfillmentTests
{
    [Fact(DisplayName = "Strict PAdES B-LT rejects an artifact without required DSS evidence")]
    public async Task SignWithDetailsAsync_StrictLongTermIncompleteDss_ThrowsLevelNotAchievable()
    {
        using var certificate = TestCertificateFactory.CreateSelfSignedCert();
        var builder = CreateBuilder(certificate, SigningLevelFailureBehavior.Throw);

        var exception = await Should.ThrowAsync<SigningException>(() => builder.SignWithDetailsAsync());

        exception.Reason.ShouldBe(SigningErrorReason.LevelNotAchievable);
    }

    [Fact(DisplayName = "Best-effort PAdES B-LT reports B-T when DSS evidence is incomplete")]
    public async Task SignWithDetailsAsync_BestEffortLongTermIncompleteDss_ReturnsTimestampedWithWarning()
    {
        using var certificate = TestCertificateFactory.CreateSelfSignedCert();
        var builder = CreateBuilder(certificate, SigningLevelFailureBehavior.ReturnLowerLevel);

        PadesSigningResult result = await builder.SignWithDetailsAsync();

        result.RequestedLevel.ShouldBe(AdesBaselineLevel.LongTerm);
        result.AchievedLevel.ShouldBe(AdesBaselineLevel.Timestamped);
        result.HasSignatureTimestamp.ShouldBeTrue();
        result.HasLongTermValidationMaterial.ShouldBeFalse();
        result.Warnings.ShouldContain(warning =>
            warning.Code == SigningWarningCode.LongTermValidationMaterialUnavailable);
        result.Warnings.ShouldContain(warning => warning.Code == SigningWarningCode.LevelDowngraded);
    }

    private static PadesSignerBuilder CreateBuilder(
        X509Certificate2 certificate,
        SigningLevelFailureBehavior failureBehavior)
    {
        var profile = AdesBaselineProfile.LongTerm(
            new TimestampOptions(new Uri("http://tsa.example.test")),
            new LongTermValidationOptions(),
            failureBehavior);
        return new PadesSignerBuilder(
                new MemoryStream(TestPdfFactory.CreateMinimalPdf()),
                new DeterministicTimestampFactory(),
                new IncompleteLtvEmbedder())
            .WithCertificate(certificate)
            .WithLevel(profile);
    }

    private sealed class DeterministicTimestampFactory : ITimestampClientFactory
    {
        public ITimestampClient Create(string tsaUrl) => new DeterministicTimestampClient();
    }

    private sealed class DeterministicTimestampClient : ITimestampClient
    {
        public Task<byte[]> GetTimestampAsync(
            ReadOnlyMemory<byte> dataToTimestamp,
            HashAlgorithmName hashAlgorithm,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(TimestampTestResponseBuilder.CreateTokenForData(dataToTimestamp.Span, hashAlgorithm));
        }
    }

    private sealed class IncompleteLtvEmbedder : ILtvEmbedder
    {
        public Task<byte[]> EmbedLtvDataAsync(
            byte[] signedPdf,
            IReadOnlyList<X509Certificate2> certificateChain,
            byte[]? timestampTokenBytes = null,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(signedPdf);
        }
    }
}

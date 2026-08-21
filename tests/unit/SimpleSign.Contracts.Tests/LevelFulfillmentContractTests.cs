using System.Security.Cryptography.X509Certificates;
using Shouldly;
using SimpleSign.CAdES;
using SimpleSign.Core.Http;
using SimpleSign.Core.Signing;
using SimpleSign.PAdES;
using SimpleSign.TestHelpers;
using SimpleSign.XAdES;
using Xunit;

namespace SimpleSign.Contracts.Tests;

/// <summary>
/// Cross-format contract tests for strict level fulfillment, explicit downgrades,
/// atomic profile replacement, and the byte-only terminal restriction.
/// </summary>
public sealed class LevelFulfillmentContractTests
{
    private static readonly Uri MockTsaUri = new("http://mock-tsa.example.com");

    private static TimestampOptions TimestampOptionsWith(HttpClient client) =>
        new(MockTsaUri, new SingleClientProvider(client));

    [Theory]
    [InlineData("pades")]
    [InlineData("cades")]
    [InlineData("xades")]
    public async Task StrictTimestamped_Succeeds_RequestedEqualsAchieved(string format)
    {
        using var cert = ContractFixtures.CreateSignerCertificate();
        using var tsaClient = ContractFixtures.BuildMockTsaClient();

        ISigningResult result = await SignTimestampedAsync(format, cert, tsaClient, strict: true);

        result.RequestedLevel.ShouldBe(AdesBaselineLevel.Timestamped);
        result.AchievedLevel.ShouldBe(AdesBaselineLevel.Timestamped);
        result.HasSignatureTimestamp.ShouldBeTrue();
        result.HasLongTermValidationMaterial.ShouldBeFalse();
        result.HasArchiveTimestamp.ShouldBeFalse();
    }

    [Theory]
    [InlineData("pades")]
    [InlineData("cades")]
    [InlineData("xades")]
    public async Task StrictLongTerm_WithoutRevocationData_Throws(string format)
    {
        using var cert = ContractFixtures.CreateSignerCertificate();
        using var tsaClient = ContractFixtures.BuildMockTsaClient();
        using var failing = ContractFixtures.BuildFailingClient();

        var profile = AdesBaselineProfile.LongTerm(
            TimestampOptionsWith(tsaClient),
            new LongTermValidationOptions(new SingleClientProvider(failing)));

        await Should.ThrowAsync<SigningException>(() => SignAsync(format, cert, profile));
    }

    [Theory]
    [InlineData("pades")]
    [InlineData("cades")]
    [InlineData("xades")]
    public async Task BestEffortLongTerm_WithoutRevocationData_DowngradesWithWarnings(string format)
    {
        using var cert = ContractFixtures.CreateSignerCertificate();
        using var tsaClient = ContractFixtures.BuildMockTsaClient();
        using var failing = ContractFixtures.BuildFailingClient();

        var profile = AdesBaselineProfile.LongTerm(
            TimestampOptionsWith(tsaClient),
            new LongTermValidationOptions(new SingleClientProvider(failing)),
            failureBehavior: SigningLevelFailureBehavior.ReturnLowerLevel);

        ISigningResult result = await SignAsync(format, cert, profile);

        result.RequestedLevel.ShouldBe(AdesBaselineLevel.LongTerm);
        result.AchievedLevel.ShouldBe(AdesBaselineLevel.Timestamped);
        result.HasSignatureTimestamp.ShouldBeTrue();
        result.HasLongTermValidationMaterial.ShouldBeFalse();
        result.Warnings.ShouldContain(w => w.Code == SigningWarningCode.LongTermValidationMaterialUnavailable);
        result.Warnings.ShouldContain(w => w.Code == SigningWarningCode.LevelDowngraded);
    }

    [Theory]
    [InlineData("pades")]
    [InlineData("cades")]
    [InlineData("xades")]
    public async Task ByteOnlySignAsync_RejectsBestEffortProfile(string format)
    {
        using var cert = ContractFixtures.CreateSignerCertificate();
        using var tsaClient = ContractFixtures.BuildMockTsaClient();

        var profile = AdesBaselineProfile.Timestamped(
            TimestampOptionsWith(tsaClient),
            failureBehavior: SigningLevelFailureBehavior.ReturnLowerLevel);

        var exception = await Should.ThrowAsync<SigningException>(
            () => SignBytesAsync(format, cert, profile));
        exception.Reason.ShouldBe(SigningErrorReason.DowngradeRequiresDetailedResult);
    }

    [Theory]
    [InlineData("pades")]
    [InlineData("cades")]
    [InlineData("xades")]
    public async Task WithLevel_ReplacesProfileAtomically(string format)
    {
        using var cert = ContractFixtures.CreateSignerCertificate();

        // A mock TSA handler that throws when invoked — any stale timestamp
        // configuration would surface as a network failure.
        using var explodingTsa = new HttpClient(new ExplodingHandler());

        var archiveProfile = AdesBaselineProfile.Archive(
            new TimestampOptions(MockTsaUri, new SingleClientProvider(explodingTsa)),
            new LongTermValidationOptions(new SingleClientProvider(explodingTsa)));

        ISigningResult result = await SignWithReplacedProfileAsync(format, cert, archiveProfile);

        result.RequestedLevel.ShouldBe(AdesBaselineLevel.Basic);
        result.AchievedLevel.ShouldBe(AdesBaselineLevel.Basic);
        result.HasSignatureTimestamp.ShouldBeFalse();
        result.HasLongTermValidationMaterial.ShouldBeFalse();
        result.HasArchiveTimestamp.ShouldBeFalse();
    }

    [Theory]
    [InlineData("pades")]
    [InlineData("cades")]
    [InlineData("xades")]
    public async Task ExternalSigner_CancellationPropagatesUnchanged(string format)
    {
        using var cert = ContractFixtures.CreateSignerCertificate();
        var signer = new CancellationSigner();
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        await Should.ThrowAsync<OperationCanceledException>(
            () => SignExternalAsync(format, cert, signer, cts.Token));
    }

    private static async Task<ISigningResult> SignTimestampedAsync(
        string format, X509Certificate2 cert, HttpClient tsaClient, bool strict)
    {
        var behavior = strict
            ? SigningLevelFailureBehavior.Throw
            : SigningLevelFailureBehavior.ReturnLowerLevel;
        var profile = AdesBaselineProfile.Timestamped(TimestampOptionsWith(tsaClient), behavior);
        return await SignAsync(format, cert, profile);
    }

    private static async Task<ISigningResult> SignAsync(
        string format,
        X509Certificate2 cert,
        AdesBaselineProfile profile)
    {
        return format switch
        {
            "pades" => await PadesSigner.Document(TestPdfFactory.CreateMinimalPdf())
                .WithCertificate(cert)
                .WithLevel(profile)
                .SignWithDetailsAsync(),
            "cades" => await CadesSigner.Document(ContractFixtures.BinaryContent)
                .WithCertificate(cert)
                .WithLevel(profile)
                .SignWithDetailsAsync(),
            "xades" => await XadesSigner.Document(ContractFixtures.XmlDocument)
                .WithCertificate(cert)
                .WithLevel(profile)
                .SignWithDetailsAsync(),
            _ => throw new ArgumentOutOfRangeException(nameof(format))
        };
    }

    private static async Task<byte[]> SignBytesAsync(
        string format,
        X509Certificate2 cert,
        AdesBaselineProfile profile)
    {
        return format switch
        {
            "pades" => await PadesSigner.Document(TestPdfFactory.CreateMinimalPdf())
                .WithCertificate(cert)
                .WithLevel(profile)
                .SignAsync(),
            "cades" => await CadesSigner.Document(ContractFixtures.BinaryContent)
                .WithCertificate(cert)
                .WithLevel(profile)
                .SignAsync(),
            "xades" => await XadesSigner.Document(ContractFixtures.XmlDocument)
                .WithCertificate(cert)
                .WithLevel(profile)
                .SignAsync(),
            _ => throw new ArgumentOutOfRangeException(nameof(format))
        };
    }

    private static async Task<ISigningResult> SignWithReplacedProfileAsync(
        string format, X509Certificate2 cert, AdesBaselineProfile profile)
    {
        return format switch
        {
            "pades" => await PadesSigner.Document(TestPdfFactory.CreateMinimalPdf())
                .WithCertificate(cert)
                .WithLevel(profile)
                .WithLevel(AdesBaselineProfile.Basic())
                .SignWithDetailsAsync(),
            "cades" => await CadesSigner.Document(ContractFixtures.BinaryContent)
                .WithCertificate(cert)
                .WithLevel(profile)
                .WithLevel(AdesBaselineProfile.Basic())
                .SignWithDetailsAsync(),
            "xades" => await XadesSigner.Document(ContractFixtures.XmlDocument)
                .WithCertificate(cert)
                .WithLevel(profile)
                .WithLevel(AdesBaselineProfile.Basic())
                .SignWithDetailsAsync(),
            _ => throw new ArgumentOutOfRangeException(nameof(format))
        };
    }

    private static async Task SignExternalAsync(
        string format, X509Certificate2 cert, IExternalSigner signer, CancellationToken token)
    {
        switch (format)
        {
            case "pades":
                await PadesSigner.Document(TestPdfFactory.CreateMinimalPdf())
                    .WithCertificate(cert)
                    .WithExternalSigner(cert, signer)
                    .SignWithDetailsAsync(token);
                break;
            case "cades":
                await CadesSigner.Document(ContractFixtures.BinaryContent)
                    .WithCertificate(cert)
                    .WithExternalSigner(cert, signer)
                    .SignWithDetailsAsync(token);
                break;
            case "xades":
                await XadesSigner.Document(ContractFixtures.XmlDocument)
                    .WithCertificate(cert)
                    .WithExternalSigner(cert, signer)
                    .SignWithDetailsAsync(token);
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(format));
        }
    }

    private sealed class ExplodingHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken) =>
            throw new HttpRequestException("The stale profile should never be executed.");
    }

    private sealed class CancellationSigner : IExternalSigner
    {
        public ValueTask<ReadOnlyMemory<byte>> SignAsync(
            ExternalSigningRequest request, CancellationToken cancellationToken) =>
            throw new OperationCanceledException(cancellationToken);
    }
}

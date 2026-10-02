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
    [InlineData("pades", true)]
    [InlineData("cades", true)]
    [InlineData("xades", true)]
    [InlineData("pades", false)]
    [InlineData("cades", false)]
    [InlineData("xades", false)]
    public async Task CompletedTimestamp_WithTamperedSignedAttribute_RejectsInvalidLevel(string format, bool strict)
    {
        using var cert = ContractFixtures.CreateSignerCertificate();
        using var tsaClient = new HttpClient(new MockHttpHandler(async request =>
        {
            byte[] requestBytes = await request.Content!.ReadAsByteArrayAsync();
            byte[] responseBytes = TimestampTestResponseBuilder.CreateForRequest(requestBytes);
            // id-messageDigest in the TSA SignerInfo signed attributes. The request
            // imprint and nonce remain intact, so packaging accepts the response.
            ReadOnlySpan<byte> messageDigestOid = [0x06, 0x09, 0x2A, 0x86, 0x48, 0x86,
                0xF7, 0x0D, 0x01, 0x09, 0x04];
            int attributeOffset = responseBytes.AsSpan().IndexOf(messageDigestOid);
            attributeOffset.ShouldBeGreaterThanOrEqualTo(0);
            int digestOffset = responseBytes.AsSpan(attributeOffset + messageDigestOid.Length)
                .IndexOf((ReadOnlySpan<byte>)[0x04, 0x20]);
            digestOffset.ShouldBeGreaterThanOrEqualTo(0);
            responseBytes[attributeOffset + messageDigestOid.Length + digestOffset + 2] ^= 1;
            var response = new HttpResponseMessage(System.Net.HttpStatusCode.OK)
            {
                Content = new ByteArrayContent(responseBytes)
            };
            response.Content.Headers.ContentType =
                new System.Net.Http.Headers.MediaTypeHeaderValue("application/timestamp-reply");
            return response;
        }));

        if (strict)
        {
            await Should.ThrowAsync<SigningException>(() => SignTimestampedAsync(format, cert, tsaClient, strict));
        }
        else
        {
            ISigningResult result = await SignTimestampedAsync(format, cert, tsaClient, strict);
            result.AchievedLevel.ShouldBe(AdesBaselineLevel.Basic);
            result.HasSignatureTimestamp.ShouldBeFalse();
            result.Warnings.ShouldContain(w => w.Code == SigningWarningCode.LevelDowngraded);
        }
    }

    [Theory]
    [InlineData("pades", true)]
    [InlineData("cades", true)]
    [InlineData("xades", true)]
    [InlineData("pades", false)]
    [InlineData("cades", false)]
    [InlineData("xades", false)]
    public async Task CompletedArchive_WithTamperedTokenSignature_RejectsInvalidLevel(string format, bool strict)
    {
        using var pki = new SyntheticPki(
            crlDistributionPoint: "http://198.51.100.1/leaf.crl",
            intermediateCrlDistributionPoint: "http://198.51.100.1/intermediate.crl");
        using var crlClient = TestRevocationClient.BuildForUris(
            (pki.CrlDistributionPoint!, pki.BuildLeafCrl()),
            (pki.IntermediateCrlDistributionPoint!, pki.BuildIntermediateCrl()));
        int timestampRequests = 0;
        using var tsaClient = new HttpClient(new MockHttpHandler(async request =>
        {
            byte[] requestBytes = await request.Content!.ReadAsByteArrayAsync();
            byte[] responseBytes = TimestampTestResponseBuilder.CreateForRequest(requestBytes);
            if (Interlocked.Increment(ref timestampRequests) == 2)
            {
                responseBytes[^1] ^= 1;
            }

            var response = new HttpResponseMessage(System.Net.HttpStatusCode.OK)
            {
                Content = new ByteArrayContent(responseBytes)
            };
            response.Content.Headers.ContentType =
                new System.Net.Http.Headers.MediaTypeHeaderValue("application/timestamp-reply");
            return response;
        }));
        var profile = AdesBaselineProfile.Archive(
            TimestampOptionsWith(tsaClient),
            new LongTermValidationOptions(new SingleClientProvider(crlClient)),
            failureBehavior: strict ? SigningLevelFailureBehavior.Throw : SigningLevelFailureBehavior.ReturnLowerLevel);

        if (strict)
        {
            await Should.ThrowAsync<SigningException>(
                () => SignAsync(format, pki.Leaf, profile, pki.IntermediatesAndRoot()));
        }
        else
        {
            ISigningResult result = await SignAsync(format, pki.Leaf, profile, pki.IntermediatesAndRoot());
            result.AchievedLevel.ShouldBe(AdesBaselineLevel.LongTerm,
                $"TSA requests: {timestampRequests}; {string.Join("; ", result.Warnings.Select(w => w.Message))}");
            result.HasArchiveTimestamp.ShouldBeFalse();
            result.Warnings.ShouldContain(w => w.Code == SigningWarningCode.LevelDowngraded);
        }
    }

    [Theory]
    [InlineData("pades")]
    [InlineData("xades")]
    public async Task TimestampedSigning_AfterExistingSignature_ValidatesNewSignature(string format)
    {
        using var cert = ContractFixtures.CreateSignerCertificate();
        using var tsaClient = ContractFixtures.BuildMockTsaClient();
        byte[] existing = format == "pades"
            ? await PadesSigner.Document(TestPdfFactory.CreateMinimalPdf())
                .WithCertificate(cert).SignAsync()
            : await XadesSigner.Document(ContractFixtures.XmlDocument)
                .WithCertificate(cert).SignAsync();
        var profile = AdesBaselineProfile.Timestamped(TimestampOptionsWith(tsaClient));

        ISigningResult result = format == "pades"
            ? await PadesSigner.Document(existing).WithCertificate(cert)
                .WithLevel(profile).SignWithDetailsAsync()
            : await XadesSigner.Document(existing).WithCertificate(cert)
                .WithLevel(profile).SignWithDetailsAsync();

        result.AchievedLevel.ShouldBe(AdesBaselineLevel.Timestamped);
        result.HasSignatureTimestamp.ShouldBeTrue();
    }

    [Theory]
    [InlineData("pades")]
    [InlineData("cades")]
    [InlineData("xades")]
    public async Task StrictLongTerm_WithoutRevocationData_Throws(string format)
    {
        using var pki = new SyntheticPki("http://crl.example.com/test-ca.crl", "http://ocsp.example.com");
        using var tsaClient = ContractFixtures.BuildMockTsaClient();
        using var failing = ContractFixtures.BuildFailingClient();

        var profile = AdesBaselineProfile.LongTerm(
            TimestampOptionsWith(tsaClient),
            new LongTermValidationOptions(new SingleClientProvider(failing)));

        await Should.ThrowAsync<SigningException>(
            () => SignAsync(format, pki.Leaf, profile, pki.IntermediatesAndRoot()));
    }

    [Theory]
    [InlineData("pades")]
    [InlineData("cades")]
    [InlineData("xades")]
    public async Task BestEffortLongTerm_WithoutRevocationData_DowngradesWithWarnings(string format)
    {
        using var pki = new SyntheticPki("http://crl.example.com/test-ca.crl", "http://ocsp.example.com");
        using var tsaClient = ContractFixtures.BuildMockTsaClient();
        using var failing = ContractFixtures.BuildFailingClient();

        var profile = AdesBaselineProfile.LongTerm(
            TimestampOptionsWith(tsaClient),
            new LongTermValidationOptions(new SingleClientProvider(failing)),
            failureBehavior: SigningLevelFailureBehavior.ReturnLowerLevel);

        ISigningResult result = await SignAsync(format, pki.Leaf, profile, pki.IntermediatesAndRoot());

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
        AdesBaselineProfile profile,
        IReadOnlyList<X509Certificate2>? chain = null)
    {
        return format switch
        {
            "pades" => await PadesSigner.Document(TestPdfFactory.CreateMinimalPdf())
                .WithCertificate(cert, chain ?? [])
                .WithLevel(profile)
                .SignWithDetailsAsync(),
            "cades" => await CadesSigner.Document(ContractFixtures.BinaryContent)
                .WithCertificate(cert, chain ?? [])
                .WithLevel(profile)
                .SignWithDetailsAsync(),
            "xades" => await XadesSigner.Document(ContractFixtures.XmlDocument)
                .WithCertificate(cert, chain ?? [])
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

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using SimpleSign.CAdES;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Http;
using SimpleSign.Core.Signing;
using SimpleSign.Core.Validation;
using SimpleSign.PAdES;
using SimpleSign.PAdES.Signing;
using SimpleSign.TestHelpers;
using SimpleSign.XAdES;
using Shouldly;
using Xunit;

namespace SimpleSign.Contracts.Tests;

/// <summary>
/// Cross-format contract tests for injected collaborator preservation, scoped provider
/// precedence, best-effort base-failure handling, PDF/A enforcement across profile
/// changes, and sequential builder reuse.
/// </summary>
public sealed class DependencyAndLifecycleContractTests
{
    [Theory]
    [InlineData("pades")]
    [InlineData("cades")]
    [InlineData("xades")]
    public async Task InjectedTimestampFactory_SurvivesFluentCalls(string format)
    {
        using var cert = ContractFixtures.CreateSignerCertificate();
        var factory = new RecordingTsaFactory();
        var profile = AdesBaselineProfile.Timestamped(
            new TimestampOptions(new Uri("http://mock-tsa.example.com")));

        ISigningResult result = await SignWithInjectedFactoryAsync(format, cert, factory, profile);

        result.HasSignatureTimestamp.ShouldBeTrue();
        factory.InvokedCount.ShouldBeGreaterThan(0);
        factory.LastEndpoint.ShouldBe("http://mock-tsa.example.com/");
    }

    [Fact(DisplayName = "PAdES: injected LTV embedder survives fluent calls")]
    public async Task Pades_InjectedLtvEmbedder_SurvivesFluentCalls()
    {
        using var cert = ContractFixtures.CreateSignerCertificate();
        var factory = new RecordingTsaFactory();
        var embedder = new RecordingLtvEmbedder();
        var profile = AdesBaselineProfile.LongTerm(
            new TimestampOptions(new Uri("http://mock-tsa.example.com")),
            new LongTermValidationOptions());

        var builder = new PadesSignerBuilder(new MemoryStream(TestPdfFactory.CreateMinimalPdf()), factory, embedder)
            .WithCertificate(cert)
            .WithLevel(profile)
            .WithOperationId("deps-1");

        // The recording embedder returns the source array (no DSS), so strict B-LT throws —
        // but only after proving the injected embedder was actually invoked.
        await Should.ThrowAsync<SigningException>(() => builder.SignWithDetailsAsync());

        embedder.InvokedCount.ShouldBeGreaterThan(0);
    }

    [Fact(DisplayName = "CAdES: injected CMS parser survives fluent calls")]
    public async Task Cades_InjectedCmsParser_SurvivesFluentCalls()
    {
        using var cert = ContractFixtures.CreateSignerCertificate();
        using var failing = ContractFixtures.BuildFailingClient();
        var factory = new RecordingTsaFactory();
        var parser = new RecordingCmsParser();
        var profile = AdesBaselineProfile.LongTerm(
            new TimestampOptions(new Uri("http://mock-tsa.example.com")),
            new LongTermValidationOptions(new SingleClientProvider(failing)));

        var builder = new CadesSignerBuilder(ContractFixtures.BinaryContent, factory, parser)
            .WithCertificate(cert)
            .WithLevel(profile);

        // No revocation data → strict B-LT throws; the injected parser must have been used
        // to inspect the timestamped CMS before LTV collection.
        await Should.ThrowAsync<SigningException>(() => builder.SignWithDetailsAsync());

        parser.InvokedCount.ShouldBeGreaterThan(0);
    }

    [Theory]
    [InlineData("pades")]
    [InlineData("cades")]
    [InlineData("xades")]
    public async Task ScopedTimestampProvider_TakesPrecedenceOverBuilderWideProvider(string format)
    {
        using var cert = ContractFixtures.CreateSignerCertificate();
        using var tsaClient = ContractFixtures.BuildMockTsaClient();
        var scoped = new SingleClientProvider(tsaClient);
        var builderWide = new ExplodingProvider();

        var profile = AdesBaselineProfile.Timestamped(
            new TimestampOptions(new Uri("http://mock-tsa.example.com"), scoped));

        ISigningResult result = await SignWithBuilderWideProviderAsync(format, cert, profile, builderWide);

        result.HasSignatureTimestamp.ShouldBeTrue();
        builderWide.Invoked.ShouldBeFalse();
    }

    [Fact(DisplayName = "PAdES: expired certificate still fails with a best-effort profile")]
    public async Task Pades_ExpiredCertificate_BestEffortProfile_StillThrows()
    {
        using var cert = CreateExpiredCertificate();
        var profile = AdesBaselineProfile.Timestamped(
            new TimestampOptions(new Uri("http://mock-tsa.example.com")),
            failureBehavior: SigningLevelFailureBehavior.ReturnLowerLevel);

        await Should.ThrowAsync<CertificateValidationException>(() =>
            PadesSigner.Document(TestPdfFactory.CreateMinimalPdf())
                .WithCertificate(cert)
                .WithLevel(profile)
                .SignWithDetailsAsync());
    }

    [Theory]
    [InlineData("pades")]
    [InlineData("cades")]
    [InlineData("xades")]
    public async Task MissingPrivateKey_BestEffortProfile_StillThrows(string format)
    {
        using var signerCert = ContractFixtures.CreateSignerCertificate();
#pragma warning disable SYSLIB0057
        using var certWithoutKey = new X509Certificate2(signerCert.RawData);
#pragma warning restore SYSLIB0057
        var profile = AdesBaselineProfile.Timestamped(
            new TimestampOptions(new Uri("http://mock-tsa.example.com")),
            failureBehavior: SigningLevelFailureBehavior.ReturnLowerLevel);

        var exception = await Should.ThrowAsync<SigningException>(
            () => SignWithCertificateAsync(format, certWithoutKey, profile));
        exception.Reason.ShouldBe(SigningErrorReason.PrivateKeyMissing);
    }

    [Fact(DisplayName = "PAdES: PDF/A enforcement survives profile configuration")]
    public async Task Pades_PdfAEnforcement_SurvivesWithLevel()
    {
        using var cert = ContractFixtures.CreateSignerCertificate();
        byte[] pdfA1b = BuildPdfA1bDocument();

        await Should.ThrowAsync<SigningException>(() =>
            PadesSigner.Document(pdfA1b)
                .WithCertificate(cert)
                .WithPdfAPreservation()
                .WithLevel(AdesBaselineProfile.Basic())
                .SignWithDetailsAsync());
    }

    [Theory]
    [InlineData("pades")]
    [InlineData("cades")]
    [InlineData("xades")]
    public async Task SameBuilderInstance_CanBeReusedSequentially(string format)
    {
        using var cert = ContractFixtures.CreateSignerCertificate();

        var first = await SignSequentiallyAsync(format, cert);
        var second = await SignSequentiallyAsync(format, cert);

        first.ShouldNotBeNull();
        second.ShouldNotBeNull();
    }

    private static async Task<ISigningResult> SignWithInjectedFactoryAsync(
        string format, X509Certificate2 cert, ITimestampClientFactory factory, AdesBaselineProfile profile)
    {
        return format switch
        {
            "pades" => await new PadesSignerBuilder(
                    new MemoryStream(TestPdfFactory.CreateMinimalPdf()), factory, new RecordingLtvEmbedder())
                .WithCertificate(cert)
                .WithLevel(profile)
                .WithOperationId("factory-1")
                .SignWithDetailsAsync(),
            "cades" => await new CadesSignerBuilder(ContractFixtures.BinaryContent, factory)
                .WithCertificate(cert)
                .WithLevel(profile)
                .WithOperationId("factory-1")
                .SignWithDetailsAsync(),
            "xades" => await new XadesSignerBuilder(ContractFixtures.XmlDocument, factory)
                .WithCertificate(cert)
                .WithLevel(profile)
                .WithOperationId("factory-1")
                .SignWithDetailsAsync(),
            _ => throw new ArgumentOutOfRangeException(nameof(format))
        };
    }

    private static async Task<ISigningResult> SignWithBuilderWideProviderAsync(
        string format, X509Certificate2 cert, AdesBaselineProfile profile, IHttpClientProvider provider)
    {
        return format switch
        {
            "pades" => await PadesSigner.Document(TestPdfFactory.CreateMinimalPdf())
                .WithCertificate(cert)
                .WithLevel(profile)
                .WithHttpClientProvider(provider)
                .SignWithDetailsAsync(),
            "cades" => await CadesSigner.Document(ContractFixtures.BinaryContent)
                .WithCertificate(cert)
                .WithLevel(profile)
                .WithHttpClientProvider(provider)
                .SignWithDetailsAsync(),
            "xades" => await XadesSigner.Document(ContractFixtures.XmlDocument)
                .WithCertificate(cert)
                .WithLevel(profile)
                .WithHttpClientProvider(provider)
                .SignWithDetailsAsync(),
            _ => throw new ArgumentOutOfRangeException(nameof(format))
        };
    }

    private static async Task<ISigningResult> SignWithCertificateAsync(
        string format, X509Certificate2 cert, AdesBaselineProfile profile)
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

    private static async Task<ISigningResult> SignSequentiallyAsync(string format, X509Certificate2 cert)
    {
        return format switch
        {
            "pades" => await PadesSigner.Document(TestPdfFactory.CreateMinimalPdf())
                .WithCertificate(cert)
                .SignWithDetailsAsync(),
            "cades" => await CadesSigner.Document(ContractFixtures.BinaryContent)
                .WithCertificate(cert)
                .SignWithDetailsAsync(),
            "xades" => await XadesSigner.Document(ContractFixtures.XmlDocument)
                .WithCertificate(cert)
                .SignWithDetailsAsync(),
            _ => throw new ArgumentOutOfRangeException(nameof(format))
        };
    }

    [Fact(DisplayName = "PAdES: strict B-LT embeds collectible revocation material (DSS inspection)")]
    public async Task Pades_LongTerm_WithCollectibleCrl_EmbedsValidationMaterial()
    {
        using var pki = new SyntheticPki(crlDistributionPoint: "http://crl.example.com/test-ca.crl");
        using var crlClient = TestRevocationClient.Build(pki.BuildLeafCrl());
        using var tsaClient = ContractFixtures.BuildMockTsaClient();

        var result = await PadesSigner.Document(TestPdfFactory.CreateMinimalPdf())
            .WithCertificate(pki.Leaf, pki.IntermediatesAndRoot())
            .WithLevel(AdesBaselineProfile.LongTerm(
                new TimestampOptions(new Uri("http://mock-tsa.example.com"), new SingleClientProvider(tsaClient)),
                new LongTermValidationOptions(new SingleClientProvider(crlClient))))
            .SignWithDetailsAsync();

        result.RequestedLevel.ShouldBe(AdesBaselineLevel.LongTerm);
        result.AchievedLevel.ShouldBe(AdesBaselineLevel.LongTerm);
        result.HasLongTermValidationMaterial.ShouldBeTrue();
    }

    [Fact(DisplayName = "CAdES: strict B-LT embeds collectible revocation material")]
    public async Task Cades_LongTerm_WithCollectibleCrl_EmbedsValidationMaterial()
    {
        using var pki = new SyntheticPki(crlDistributionPoint: "http://crl.example.com/test-ca.crl");
        using var crlClient = TestRevocationClient.Build(pki.BuildLeafCrl());
        using var tsaClient = ContractFixtures.BuildMockTsaClient();

        var result = await CadesSigner.Document(ContractFixtures.BinaryContent)
            .WithCertificate(pki.Leaf, pki.IntermediatesAndRoot())
            .WithLevel(AdesBaselineProfile.LongTerm(
                new TimestampOptions(new Uri("http://mock-tsa.example.com"), new SingleClientProvider(tsaClient)),
                new LongTermValidationOptions(new SingleClientProvider(crlClient))))
            .SignWithDetailsAsync();

        result.AchievedLevel.ShouldBe(AdesBaselineLevel.LongTerm);
        result.HasLongTermValidationMaterial.ShouldBeTrue();
    }

    [Fact(DisplayName = "XAdES: strict B-LT embeds collectible revocation material")]
    public async Task Xades_LongTerm_WithCollectibleCrl_EmbedsValidationMaterial()
    {
        using var pki = new SyntheticPki(crlDistributionPoint: "http://crl.example.com/test-ca.crl");
        using var crlClient = TestRevocationClient.Build(pki.BuildLeafCrl());
        using var tsaClient = ContractFixtures.BuildMockTsaClient();

        var result = await XadesSigner.Document(ContractFixtures.XmlDocument)
            .WithCertificate(pki.Leaf, pki.IntermediatesAndRoot())
            .WithLevel(AdesBaselineProfile.LongTerm(
                new TimestampOptions(new Uri("http://mock-tsa.example.com"), new SingleClientProvider(tsaClient)),
                new LongTermValidationOptions(new SingleClientProvider(crlClient))))
            .SignWithDetailsAsync();

        result.AchievedLevel.ShouldBe(AdesBaselineLevel.LongTerm);
        result.HasLongTermValidationMaterial.ShouldBeTrue();
    }

    [Fact(DisplayName = "PAdES: strict B-LTA with local CRL embeds DocTimeStamp and DSS")]
    public async Task Pades_Archive_WithCollectibleCrl_EmbedsArchiveTimestamp()
    {
        using var pki = new SyntheticPki(crlDistributionPoint: "http://crl.example.com/test-ca.crl");
        using var crlClient = TestRevocationClient.Build(pki.BuildLeafCrl());
        using var tsaClient = ContractFixtures.BuildMockTsaClient();
        var timestampOptions = new TimestampOptions(
            new Uri("http://mock-tsa.example.com"), new SingleClientProvider(tsaClient));

        var result = await PadesSigner.Document(TestPdfFactory.CreateMinimalPdf())
            .WithCertificate(pki.Leaf, pki.IntermediatesAndRoot())
            .WithLevel(AdesBaselineProfile.Archive(
                timestampOptions,
                new LongTermValidationOptions(new SingleClientProvider(crlClient))))
            .SignWithDetailsAsync();

        result.AchievedLevel.ShouldBe(AdesBaselineLevel.Archive);
        result.HasLongTermValidationMaterial.ShouldBeTrue();
        result.HasArchiveTimestamp.ShouldBeTrue();
    }

    [Theory]
    [InlineData("pades")]
    [InlineData("cades")]
    [InlineData("xades")]
    public async Task ExpiredCertificate_FailsOnAllFormats(string format)
    {
        using var cert = CreateExpiredCertificate();

        await Should.ThrowAsync<CertificateValidationException>(
            () => SignWithCertificateAsync(format, cert, AdesBaselineProfile.Basic()));
    }

    [Theory]
    [InlineData("pades")]
    [InlineData("cades")]
    [InlineData("xades")]
    public async Task WithSigningTime_ReflectedInProducedArtifact(string format)
    {
        using var cert = ContractFixtures.CreateSignerCertificate();
        var signingTime = new DateTimeOffset(2024, 3, 15, 10, 30, 0, TimeSpan.Zero);

        ISigningResult result = await SignWithSigningTimeAsync(format, cert, signingTime);

        switch (format)
        {
            case "pades":
                System.Text.Encoding.Latin1.GetString(result is PadesSigningResult pades ? pades.SignedArtifact : [])
                    .ShouldContain("/M (D:20240315103000+00'00')");
                break;
            case "cades":
                var parsed = CmsParser.Parse(((CadesSigningResult)result).SignedArtifact);
                parsed.SigningTime.ShouldNotBeNull();
                parsed.SigningTime!.Value.ShouldBe(signingTime);
                break;
            case "xades":
                System.Text.Encoding.UTF8.GetString(((XadesSigningResult)result).SignedArtifact)
                    .ShouldContain("2024-03-15T10:30:00Z");
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(format));
        }
    }

    [Theory]
    [InlineData("pades")]
    [InlineData("cades")]
    [InlineData("xades")]
    public async Task PreCancelledToken_ThrowsBeforeInvokingExternalSigner(string format)
    {
        using var cert = ContractFixtures.CreateSignerCertificate();
        var signer = new CountingOnlySigner();
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        await Should.ThrowAsync<OperationCanceledException>(
            () => SignWithExternalSignerAsync(format, cert, signer, cts.Token));

        signer.Invoked.ShouldBeFalse();
    }

    [Theory]
    [InlineData("pades")]
    [InlineData("cades")]
    public async Task InjectedLogger_SurvivesFluentCalls(string format)
    {
        using var cert = ContractFixtures.CreateSignerCertificate();
        var logger = new RecordingLogger();

        await SignWithInjectedLoggerAsync(format, cert, logger);

        logger.EntryCount.ShouldBeGreaterThan(0);
    }

    [Fact(DisplayName = "XAdES: mutating the input array after Document() does not affect signing")]
    public async Task Xades_InputArraySnapshot_MutationAfterDocument_StillSigns()
    {
        using var cert = ContractFixtures.CreateSignerCertificate();
        byte[] xml = (byte[])ContractFixtures.XmlDocument.Clone();
        var builder = XadesSigner.Document(xml).WithCertificate(cert);
        xml[0] = (byte)'?'; // invalidate the caller-owned array

        byte[] signed = await builder.SignAsync();

        System.Text.Encoding.UTF8.GetString(signed).ShouldContain("<root>");
    }

    [Fact(DisplayName = "CAdES: mutating the input array after Document() does not affect the signed digest")]
    public async Task Cades_InputArraySnapshot_MutationAfterDocument_SignsOriginalContent()
    {
        using var cert = ContractFixtures.CreateSignerCertificate();
        byte[] content = (byte[])ContractFixtures.BinaryContent.Clone();
        var builder = CadesSigner.Document(content).WithCertificate(cert);
        content[0] = (byte)'X'; // mutate the caller-owned array

        byte[] signed = await builder.SignAsync();
        var parsed = CmsParser.Parse(signed);

        byte[] expectedDigest = System.Security.Cryptography.SHA256.HashData(ContractFixtures.BinaryContent);
        parsed.MessageDigest.ShouldNotBeNull();
        parsed.MessageDigest!.ShouldBe(expectedDigest);
    }

    private static async Task<ISigningResult> SignWithExternalSignerAsync(
        string format, X509Certificate2 cert, IExternalSigner signer, CancellationToken cancellationToken)
    {
        return format switch
        {
            "pades" => await PadesSigner.Document(TestPdfFactory.CreateMinimalPdf())
                .WithExternalSigner(cert, signer)
                .SignWithDetailsAsync(cancellationToken),
            "cades" => await CadesSigner.Document(ContractFixtures.BinaryContent)
                .WithExternalSigner(cert, signer)
                .SignWithDetailsAsync(cancellationToken),
            "xades" => await XadesSigner.Document(ContractFixtures.XmlDocument)
                .WithExternalSigner(cert, signer)
                .SignWithDetailsAsync(cancellationToken),
            _ => throw new ArgumentOutOfRangeException(nameof(format))
        };
    }

    private static async Task<ISigningResult> SignWithSigningTimeAsync(
        string format, X509Certificate2 cert, DateTimeOffset signingTime)
    {
        return format switch
        {
            "pades" => await PadesSigner.Document(TestPdfFactory.CreateMinimalPdf())
                .WithCertificate(cert)
                .WithSigningTime(signingTime)
                .SignWithDetailsAsync(),
            "cades" => await CadesSigner.Document(ContractFixtures.BinaryContent)
                .WithCertificate(cert)
                .WithSigningTime(signingTime)
                .SignWithDetailsAsync(),
            "xades" => await XadesSigner.Document(ContractFixtures.XmlDocument)
                .WithCertificate(cert)
                .WithSigningTime(signingTime)
                .SignWithDetailsAsync(),
            _ => throw new ArgumentOutOfRangeException(nameof(format))
        };
    }

    private static async Task SignWithInjectedLoggerAsync(
        string format, X509Certificate2 cert, ILogger logger)
    {
        switch (format)
        {
            case "pades":
                var padesBuilder = new PadesSignerBuilder(
                    new MemoryStream(TestPdfFactory.CreateMinimalPdf()), logger)
                    .WithCertificate(cert)
                    .WithOperationId("logger-1");
                await padesBuilder.SignAsync();
                break;
            case "cades":
                var cadesBuilder = new CadesSignerBuilder(ContractFixtures.BinaryContent, logger)
                    .WithCertificate(cert)
                    .WithOperationId("logger-1");
                await cadesBuilder.SignAsync();
                break;
            case "xades":
                var xadesBuilder = new XadesSignerBuilder(ContractFixtures.XmlDocument, logger)
                    .WithCertificate(cert)
                    .WithOperationId("logger-1");
                await xadesBuilder.SignAsync();
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(format));
        }
    }

    private static X509Certificate2 CreateExpiredCertificate()
    {
        using RSA key = RSA.Create(2048);
        var req = new CertificateRequest("CN=Expired, O=Tests", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-30), DateTimeOffset.UtcNow.AddDays(-1));
        const string password = "test-export";
        var pfx = cert.Export(X509ContentType.Pfx, password);
#pragma warning disable SYSLIB0057
        var flags = X509KeyStorageFlags.Exportable;
        if (!OperatingSystem.IsMacOS())
        {
            flags |= X509KeyStorageFlags.EphemeralKeySet;
        }

        return new X509Certificate2(pfx, password, flags);
#pragma warning restore SYSLIB0057
    }

    private static byte[] BuildPdfA1bDocument()
    {
        var sb = new System.Text.StringBuilder();
        sb.Append("%PDF-1.7\n");
        int obj1Offset = sb.Length;
        sb.Append("1 0 obj\n<< /Type /Catalog /Pages 2 0 R /Metadata 4 0 R >>\nendobj\n");
        int obj2Offset = sb.Length;
        sb.Append("2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n");
        int obj3Offset = sb.Length;
        sb.Append("3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n");
        const string xmp = "<x:xmpmeta xmlns:x=\"adobe:ns:meta/\"><rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"><rdf:Description xmlns:pdfaid=\"http://www.aiim.org/pdfa/ns/id/\"><pdfaid:part>1</pdfaid:part><pdfaid:conformance>B</pdfaid:conformance></rdf:Description></rdf:RDF></x:xmpmeta>";
        int obj4Offset = sb.Length;
        sb.Append($"4 0 obj\n<< /Type /Metadata /Subtype /XML /Length {xmp.Length} >>\nstream\n{xmp}\nendstream\nendobj\n");
        long xrefOffset = sb.Length;
        sb.Append("xref\n0 5\n0000000000 65535 f \n");
        sb.Append($"{obj1Offset:D10} 00000 n \n");
        sb.Append($"{obj2Offset:D10} 00000 n \n");
        sb.Append($"{obj3Offset:D10} 00000 n \n");
        sb.Append($"{obj4Offset:D10} 00000 n \n");
        sb.Append("trailer\n<< /Size 5 /Root 1 0 R >>\n");
        sb.Append($"startxref\n{xrefOffset}\n%%EOF\n");
        return System.Text.Encoding.Latin1.GetBytes(sb.ToString());
    }

    private sealed class RecordingTsaFactory : ITimestampClientFactory
    {
        public int InvokedCount { get; private set; }

        public string? LastEndpoint { get; private set; }

        public ITimestampClient Create(string tsaUrl)
        {
            InvokedCount++;
            LastEndpoint = tsaUrl;
            return new RecordingTimestampClient();
        }
    }

    private sealed class RecordingTimestampClient : ITimestampClient
    {
        public Task<byte[]> GetTimestampAsync(
            ReadOnlyMemory<byte> dataToTimestamp,
            HashAlgorithmName hashAlgorithm,
            CancellationToken cancellationToken = default) =>
            Task.FromResult(ContractFixtures.BuildFakeTimestampToken());
    }

    private sealed class RecordingLtvEmbedder : ILtvEmbedder
    {
        public int InvokedCount { get; private set; }

        public Task<byte[]> EmbedLtvDataAsync(
            byte[] signedPdf,
            IReadOnlyList<X509Certificate2> certificateChain,
            byte[]? timestampTokenBytes = null,
            CancellationToken cancellationToken = default)
        {
            InvokedCount++;
            return Task.FromResult(signedPdf);
        }
    }

    private sealed class RecordingCmsParser : ICmsParser
    {
        public int InvokedCount { get; private set; }

        public CmsSignedData Parse(byte[] cmsBytes, ILogger? logger = null)
        {
            InvokedCount++;
            return CmsParser.Parse(cmsBytes, logger);
        }
    }

    private sealed class ExplodingProvider : IHttpClientProvider
    {
        public bool Invoked { get; private set; }

        public HttpClient GetClient()
        {
            Invoked = true;
            throw new InvalidOperationException("The builder-wide provider should never be used.");
        }
    }

    private sealed class CountingOnlySigner : IExternalSigner
    {
        public bool Invoked { get; private set; }

        public ValueTask<ReadOnlyMemory<byte>> SignAsync(ExternalSigningRequest request, CancellationToken cancellationToken)
        {
            Invoked = true;
            return ValueTask.FromResult(ReadOnlyMemory<byte>.Empty);
        }
    }

    private sealed class RecordingLogger : ILogger
    {
        public int EntryCount { get; private set; }

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) => EntryCount++;
    }
}

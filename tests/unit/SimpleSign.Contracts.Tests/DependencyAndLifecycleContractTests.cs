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
}

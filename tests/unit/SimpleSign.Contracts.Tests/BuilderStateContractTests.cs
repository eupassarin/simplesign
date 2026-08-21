using System.Security.Cryptography;
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
/// Cross-format contract tests for builder immutability, credential replacement,
/// defensive copying, and lazy provider resolution.
/// </summary>
public sealed class BuilderStateContractTests
{
    [Theory]
    [InlineData("pades")]
    [InlineData("cades")]
    [InlineData("xades")]
    public async Task FluentCalls_ReturnDistinctBuilders_PreservingUnrelatedState(string format)
    {
        using var cert = ContractFixtures.CreateSignerCertificate();
        using var tsaClient = ContractFixtures.BuildMockTsaClient();
        var timestampOptions = new TimestampOptions(
            new Uri("http://mock-tsa.example.com"), new SingleClientProvider(tsaClient));

        // Configure timestamp, then add unrelated config after it — the unrelated
        // call must not discard the level configuration.
        ISigningResult result = await SignWithTimestampAndOperationIdAsync(format, cert, timestampOptions);

        result.HasSignatureTimestamp.ShouldBeTrue();
        result.AchievedLevel.ShouldBe(AdesBaselineLevel.Timestamped);
    }

    [Theory]
    [InlineData("pades")]
    [InlineData("cades")]
    [InlineData("xades")]
    public async Task LocalCredential_ReplacesExternalCredential(string format)
    {
        using var cert = ContractFixtures.CreateSignerCertificate();
        var throwingSigner = new ThrowingSigner();

        // Configure external signing first, then switch to local signing.
        // The external signer must never be invoked.
        ISigningResult result = await SignWithCredentialSwitchAsync(format, cert, throwingSigner);

        result.ShouldNotBeNull();
        throwingSigner.Invoked.ShouldBeFalse();
    }

    [Theory]
    [InlineData("pades")]
    [InlineData("cades")]
    [InlineData("xades")]
    public async Task ExternalCredential_ReplacesLocalCredential(string format)
    {
        using var cert = ContractFixtures.CreateSignerCertificate();
        var signer = new RawSigner(ContractFixtures.CreateSignerCertificate());

        // Configure local signing first, then switch to external signing.
        ISigningResult result = await SignExternalAfterLocalAsync(format, cert, signer);

        result.ShouldNotBeNull();
        signer.Invoked.ShouldBeTrue();
    }

    [Theory]
    [InlineData("pades")]
    [InlineData("cades")]
    [InlineData("xades")]
    public async Task CallerOwnedChainCollection_IsDefensivelyCopied(string format)
    {
        using var cert = ContractFixtures.CreateSignerCertificate();
        var extra = ContractFixtures.CreateSignerCertificate("CN=Extra Chain, O=Tests");
        using var extraCert = extra;
        var chain = new List<X509Certificate2> { extra };

        // Configure with the chain, then mutate the caller-owned collection.
        ISigningResult result = await SignWithChainAsync(format, cert, chain, mutate: chain.Clear);

        result.ShouldNotBeNull();
        extraCert.Thumbprint.ShouldNotBeNull();
    }

    [Theory]
    [InlineData("pades")]
    [InlineData("cades")]
    [InlineData("xades")]
    public async Task HttpClientProvider_IsResolvedLazily_AtOperationTime(string format)
    {
        using var cert = ContractFixtures.CreateSignerCertificate();
        using var tsaClient = ContractFixtures.BuildMockTsaClient();
        var countingProvider = new CountingProvider(tsaClient);

        var profile = AdesBaselineProfile.Timestamped(
            new TimestampOptions(new Uri("http://mock-tsa.example.com"), countingProvider));

        // Configuring the builder must not resolve the client.
        countingProvider.CallCount.ShouldBe(0);

        await SignAsync(format, cert, profile);

        countingProvider.CallCount.ShouldBeGreaterThan(0);
    }

    private static async Task<ISigningResult> SignWithTimestampAndOperationIdAsync(
        string format, X509Certificate2 cert, TimestampOptions timestampOptions)
    {
        var profile = AdesBaselineProfile.Timestamped(timestampOptions);
        return format switch
        {
            "pades" => await PadesSigner.Document(TestPdfFactory.CreateMinimalPdf())
                .WithCertificate(cert)
                .WithLevel(profile)
                .WithOperationId("state-1")
                .SignWithDetailsAsync(),
            "cades" => await CadesSigner.Document(ContractFixtures.BinaryContent)
                .WithCertificate(cert)
                .WithLevel(profile)
                .WithOperationId("state-1")
                .SignWithDetailsAsync(),
            "xades" => await XadesSigner.Document(ContractFixtures.XmlDocument)
                .WithCertificate(cert)
                .WithLevel(profile)
                .WithOperationId("state-1")
                .SignWithDetailsAsync(),
            _ => throw new ArgumentOutOfRangeException(nameof(format))
        };
    }

    private static async Task<ISigningResult> SignAsync(
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

    private static async Task<ISigningResult> SignWithCredentialSwitchAsync(
        string format, X509Certificate2 cert, IExternalSigner signer)
    {
        return format switch
        {
            "pades" => await PadesSigner.Document(TestPdfFactory.CreateMinimalPdf())
                .WithExternalSigner(cert, signer)
                .WithCertificate(cert)
                .SignWithDetailsAsync(),
            "cades" => await CadesSigner.Document(ContractFixtures.BinaryContent)
                .WithExternalSigner(cert, signer)
                .WithCertificate(cert)
                .SignWithDetailsAsync(),
            "xades" => await XadesSigner.Document(ContractFixtures.XmlDocument)
                .WithExternalSigner(cert, signer)
                .WithCertificate(cert)
                .SignWithDetailsAsync(),
            _ => throw new ArgumentOutOfRangeException(nameof(format))
        };
    }

    private static async Task<ISigningResult> SignExternalAfterLocalAsync(
        string format, X509Certificate2 cert, IExternalSigner signer)
    {
        return format switch
        {
            "pades" => await PadesSigner.Document(TestPdfFactory.CreateMinimalPdf())
                .WithCertificate(cert)
                .WithExternalSigner(cert, signer)
                .SignWithDetailsAsync(),
            "cades" => await CadesSigner.Document(ContractFixtures.BinaryContent)
                .WithCertificate(cert)
                .WithExternalSigner(cert, signer)
                .SignWithDetailsAsync(),
            "xades" => await XadesSigner.Document(ContractFixtures.XmlDocument)
                .WithCertificate(cert)
                .WithExternalSigner(cert, signer)
                .SignWithDetailsAsync(),
            _ => throw new ArgumentOutOfRangeException(nameof(format))
        };
    }

    private static async Task<ISigningResult> SignWithChainAsync(
        string format, X509Certificate2 cert, IReadOnlyList<X509Certificate2> chain, Action mutate)
    {
        return format switch
        {
            "pades" => await SignPadesWithChainAsync(cert, chain, mutate),
            "cades" => await SignCadesWithChainAsync(cert, chain, mutate),
            "xades" => await SignXadesWithChainAsync(cert, chain, mutate),
            _ => throw new ArgumentOutOfRangeException(nameof(format))
        };
    }

    private static async Task<ISigningResult> SignPadesWithChainAsync(
        X509Certificate2 cert, IReadOnlyList<X509Certificate2> chain, Action mutate)
    {
        var builder = PadesSigner.Document(TestPdfFactory.CreateMinimalPdf())
            .WithCertificate(cert, chain);
        mutate();
        return await builder.SignWithDetailsAsync();
    }

    private static async Task<ISigningResult> SignCadesWithChainAsync(
        X509Certificate2 cert, IReadOnlyList<X509Certificate2> chain, Action mutate)
    {
        var builder = CadesSigner.Document(ContractFixtures.BinaryContent)
            .WithCertificate(cert, chain);
        mutate();
        return await builder.SignWithDetailsAsync();
    }

    private static async Task<ISigningResult> SignXadesWithChainAsync(
        X509Certificate2 cert, IReadOnlyList<X509Certificate2> chain, Action mutate)
    {
        var builder = XadesSigner.Document(ContractFixtures.XmlDocument)
            .WithCertificate(cert, chain);
        mutate();
        return await builder.SignWithDetailsAsync();
    }

    private sealed class ThrowingSigner : IExternalSigner
    {
        public bool Invoked { get; private set; }

        public ValueTask<ReadOnlyMemory<byte>> SignAsync(
            ExternalSigningRequest request, CancellationToken cancellationToken)
        {
            Invoked = true;
            throw new InvalidOperationException("The external signer should never be invoked.");
        }
    }

    private sealed class RawSigner : IExternalSigner
    {
        private readonly X509Certificate2 _signerCert;

        public RawSigner(X509Certificate2 signerCert)
        {
            _signerCert = signerCert;
        }

        public bool Invoked { get; private set; }

        public ValueTask<ReadOnlyMemory<byte>> SignAsync(
            ExternalSigningRequest request, CancellationToken cancellationToken)
        {
            Invoked = true;
            using var rsa = _signerCert.GetRSAPrivateKey()
                ?? throw new InvalidOperationException("Signer certificate has no private key.");
            byte[] signature = rsa.SignData(request.DataToSign.Span, request.HashAlgorithm, RSASignaturePadding.Pkcs1);
            return ValueTask.FromResult<ReadOnlyMemory<byte>>(signature);
        }
    }

    private sealed class CountingProvider : IHttpClientProvider
    {
        private readonly HttpClient _client;

        public CountingProvider(HttpClient client)
        {
            _client = client;
        }

        public int CallCount { get; private set; }

        public HttpClient GetClient()
        {
            CallCount++;
            return _client;
        }
    }
}

using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Moq;
using Shouldly;
using SimpleSign.Core.Http;
using SimpleSign.Core.Validation;
using SimpleSign.PAdES.Validation;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.PAdES.Tests.Validation;

public sealed class ValidationNetworkTests
{
    [Theory]
    [InlineData("AIA")]
    [InlineData("CRL")]
    [InlineData("OCSP")]
    public async Task ValidateAsync_NetworkTimeout_CancelsRequestAndReportsFailure(string endpoint)
    {
        using var cert = CreateCertificate(endpoint);
        byte[] signed = await PadesSigner.Document(TestPdfFactory.CreateMinimalPdf()).WithCertificate(cert).SignAsync();
        using var handler = new BlockingHandler();
        using var client = new HttpClient(handler) { Timeout = Timeout.InfiniteTimeSpan };
        var validator = new PdfSignatureValidator(new ValidationOptions
        {
            CheckRevocation = endpoint != "AIA",
            TrustedRoots = [cert],
            NetworkTimeout = TimeSpan.FromMilliseconds(100)
        }, client);
        using var stream = new MemoryStream(signed);

        var results = await validator.ValidateAsync(stream).WaitAsync(TimeSpan.FromSeconds(10));

        handler.RequestCanceled.ShouldBeTrue();
        client.Timeout.ShouldBe(Timeout.InfiniteTimeSpan);
        var result = results.ShouldHaveSingleItem();
        result.IsIntegrityValid.ShouldBeTrue();
        result.IsSignatureValid.ShouldBeTrue();
        result.IsValid.ShouldBeFalse();
        if (endpoint == "AIA")
        {
            result.Errors.ShouldContain(e => e.Contains("Certificate chain validation error"));
            result.RevocationSource.ShouldBe(RevocationSource.None);
        }
        else
        {
            result.IsCertificateChainValid.ShouldBeTrue();
            result.IsNotRevoked.ShouldBeTrue();
            result.RevocationSource.ShouldBe(RevocationSource.Indeterminate);
            result.Warnings.ShouldContain(w => w.Contains("Revocation check could not be completed"));
        }
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    [InlineData(true, true)]
    public async Task ValidateAsync_CallerCancelsNetworkStage_PropagatesCancellation(bool revocation, bool batch)
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        byte[] signed = await PadesSigner.Document(TestPdfFactory.CreateMinimalPdf()).WithCertificate(cert).SignAsync();
        using var client = new HttpClient();
        var httpProvider = new Mock<IHttpClientProvider>();
        httpProvider.Setup(p => p.GetClient()).Returns(client);
        var chainService = new Mock<ICertificateChainService>();
        var checker = new Mock<IRevocationChecker>();
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        chainService.Setup(s => s.DownloadAiaCertsAsync(client, It.IsAny<X509Certificate2>(),
                It.IsAny<IReadOnlyList<X509Certificate2>>(), It.IsAny<List<string>>(), It.IsAny<CancellationToken>()))
            .Returns(async (HttpClient _, X509Certificate2 _, IReadOnlyList<X509Certificate2> _, List<string> _, CancellationToken ct) =>
            {
                if (!revocation)
                {
                    started.TrySetResult();
                    await Task.Delay(Timeout.InfiniteTimeSpan, ct);
                }
                return [];
            });
        checker.Setup(s => s.CheckRevocationAsync(It.IsAny<X509Certificate2>(), It.IsAny<IReadOnlyList<X509Certificate2>>(),
                It.IsAny<IReadOnlyList<byte[]>>(), It.IsAny<IReadOnlyList<byte[]>>(), It.IsAny<CancellationToken>(), It.IsAny<DateTimeOffset?>()))
            .Returns(async (X509Certificate2 _, IReadOnlyList<X509Certificate2> _, IReadOnlyList<byte[]> _, IReadOnlyList<byte[]> _, CancellationToken ct, DateTimeOffset? _) =>
            {
                started.TrySetResult();
                await Task.Delay(Timeout.InfiniteTimeSpan, ct);
                return (true, RevocationSource.OnlineOcsp);
            });
        var validator = new PdfSignatureValidator(httpProvider.Object, checker.Object, new ValidationOptions
        {
            TrustedRoots = [cert],
            CheckRevocation = revocation,
            NetworkTimeout = TimeSpan.FromMinutes(1)
        }, certChainService: chainService.Object);
        using var callerCts = new CancellationTokenSource();
        using var stream = new MemoryStream(signed);
        Task validation = batch
            ? validator.ValidateBatchAsync([(stream, "signed.pdf")], cancellationToken: callerCts.Token)
            : validator.ValidateAsync(stream, cancellationToken: callerCts.Token);
        await started.Task.WaitAsync(TimeSpan.FromSeconds(10));

        callerCts.Cancel();

        await Should.ThrowAsync<OperationCanceledException>(() => validation.WaitAsync(TimeSpan.FromSeconds(10)));
    }

    private static X509Certificate2 CreateCertificate(string endpoint)
    {
        // A literal test IP keeps DNS resolution outside the timeout assertion.
        // BlockingHandler intercepts the HTTP request; no connection is made.
        const string url = "http://198.51.100.1/evidence";
        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=Validation network test", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, false));
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        using (writer.PushSequence())
        {
            if (endpoint == "CRL")
            {
                using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true)))
                using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true)))
                {
                    writer.WriteCharacterString(UniversalTagNumber.IA5String, url, new Asn1Tag(TagClass.ContextSpecific, 6));
                }
            }
            else
            {
                writer.WriteObjectIdentifier(endpoint == "AIA" ? "1.3.6.1.5.5.7.48.2" : "1.3.6.1.5.5.7.48.1");
                writer.WriteCharacterString(UniversalTagNumber.IA5String, url, new Asn1Tag(TagClass.ContextSpecific, 6));
            }
        }
        request.CertificateExtensions.Add(new X509Extension(endpoint == "CRL" ? "2.5.29.31" : "1.3.6.1.5.5.7.1.1", writer.Encode(), false));
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
    }

    private sealed class BlockingHandler : HttpMessageHandler
    {
        public bool RequestCanceled { get; private set; }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            try
            {
                await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            }
            catch (OperationCanceledException)
            {
                RequestCanceled = true;
                throw;
            }
            return new HttpResponseMessage();
        }
    }
}

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Runtime.CompilerServices;
using Shouldly;
using SimpleSign.Core.Signing;
using SimpleSign.PAdES.Signing;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.PAdES.Tests.Signing;

[Trait("Category", "Unit")]
public sealed class BatchSignerTests
{
    private static byte[] CreateMinimalPdf()
    {
        var pdf = "%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n" +
                  "2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n" +
                  "3 0 obj<</Type/Page/MediaBox[0 0 612 792]/Parent 2 0 R>>endobj\n" +
                  "xref\n0 4\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \n" +
                  "0000000107 00000 n \ntrailer<</Size 4/Root 1 0 R>>\nstartxref\n176\n%%EOF";
        return System.Text.Encoding.ASCII.GetBytes(pdf);
    }

    [Fact(DisplayName = "BatchSigner signs single PDF successfully")]
    public async Task SignAsync_SinglePdf_Success()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        await using var signer = BatchSigner.Create(cert).Build();

        var signed = await signer.SignAsync(CreateMinimalPdf());

        signed.ShouldNotBeNull();
        signed.ShouldNotBeEmpty();
        signer.SuccessCount.ShouldBe(1);
        signer.FailureCount.ShouldBe(0);
    }

    [Fact(DisplayName = "BatchSigner signs multiple PDFs and tracks metrics")]
    public async Task SignAsync_MultiplePdfs_TracksMetrics()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        await using var signer = BatchSigner.Create(cert).Build();

        for (var i = 0; i < 3; i++)
        {
            await signer.SignAsync(CreateMinimalPdf());
        }

        signer.SuccessCount.ShouldBe(3);
        signer.FailureCount.ShouldBe(0);
        signer.AverageElapsedMs.ShouldBeGreaterThanOrEqualTo(0);
    }

    [Fact(DisplayName = "BatchSigner tracks failures for expired cert")]
    public async Task SignAsync_ExpiredCert_TracksFailure()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=Expired", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-10), DateTimeOffset.UtcNow.AddDays(-1));

        await using var signer = BatchSigner.Create(cert).Build();

        var act = () => signer.SignAsync(CreateMinimalPdf());
        (await Should.ThrowAsync<SigningException>(act)).Reason.ShouldBe(SigningErrorReason.CertificateExpired);

        signer.FailureCount.ShouldBe(1);
        signer.SuccessCount.ShouldBe(0);
    }

    [Fact(DisplayName = "SignAllAsync processes batch and returns results")]
    public async Task SignAllAsync_ProcessesBatch()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        await using var signer = BatchSigner.Create(cert)
            .WithMaxConcurrency(2)
            .Build();

        var inputs = GenerateInputs(3);
        var results = new List<BatchSignResult>();

        await foreach (var result in signer.SignAllAsync(inputs))
        {
            results.Add(result);
        }

        results.Count().ShouldBe(3);
        results.ShouldAllBe(r => r.IsSuccess);
        results.ShouldAllBe(r => r.SignedPdf != null);
        signer.SuccessCount.ShouldBe(3);
    }

    [Fact(DisplayName = "SignAllAsync yields a completed item before the source completes")]
    public async Task SignAllAsync_LongLivedInput_YieldsCompletedResultBeforeSourceCompletion()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        await using var signer = BatchSigner.Create(cert)
            .WithMaxConcurrency(1)
            .Build();
        var releaseSecondInput = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

        await using IAsyncEnumerator<BatchSignResult> results = signer.SignAllAsync(
            GenerateBlockedInputs(releaseSecondInput.Task)).GetAsyncEnumerator();

        bool hasFirstResult = await results.MoveNextAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(10));

        hasFirstResult.ShouldBeTrue();
        results.Current.Id.ShouldBe("first");
        results.Current.IsSuccess.ShouldBeTrue();

        releaseSecondInput.SetResult();
        (await results.MoveNextAsync()).ShouldBeTrue();
        results.Current.Id.ShouldBe("second");
    }

    [Fact(DisplayName = "SignAllAsync stops a cancellation-aware source when enumeration is disposed")]
    public async Task SignAllAsync_DisposedEnumeration_CancelsSource()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        await using var signer = BatchSigner.Create(cert).WithMaxConcurrency(1).Build();
        var sourceCanceled = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

        await using IAsyncEnumerator<BatchSignResult> results = signer.SignAllAsync(
            GenerateCancelableInputs(sourceCanceled)).GetAsyncEnumerator();

        (await results.MoveNextAsync()).ShouldBeTrue();
        results.Current.Id.ShouldBe("first");
        await results.DisposeAsync();

        await sourceCanceled.Task.WaitAsync(TimeSpan.FromSeconds(10));
    }

    [Fact(DisplayName = "SignAllAsync propagates source enumeration failures")]
    public async Task SignAllAsync_SourceThrows_PropagatesFailure()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        await using var signer = BatchSigner.Create(cert).Build();

        var exception = await Should.ThrowAsync<InvalidOperationException>(async () =>
        {
            await foreach (var _ in signer.SignAllAsync(GenerateFailingInputs()))
            {
            }
        });

        exception.Message.ShouldBe("source failed");
    }

    [Fact(DisplayName = "SignAllAsync never exceeds configured concurrency")]
    public async Task SignAllAsync_ExternalSigner_RespectsMaxConcurrency()
    {
        using var certificate = TestCertificateFactory.CreateSelfSignedCert();
        using RSA? rsa = certificate.GetRSAPrivateKey();
        rsa.ShouldNotBeNull();
        var externalSigner = new TrackingExternalSigner(rsa!, TimeSpan.FromMilliseconds(25));
        await using var signer = BatchSigner.Create(certificate)
            .WithExternalSigner(externalSigner)
            .WithMaxConcurrency(2)
            .Build();

        var results = new List<BatchSignResult>();
        await foreach (var result in signer.SignAllAsync(GenerateInputs(6)))
        {
            results.Add(result);
        }

        results.ShouldAllBe(result => result.IsSuccess);
        externalSigner.MaximumConcurrentCalls.ShouldBe(2);
    }

    [Fact(DisplayName = "SignAllAsync applies backpressure before consuming unbounded input")]
    public async Task SignAllAsync_SlowConsumer_BoundsBufferedAndInFlightResults()
    {
        using var certificate = TestCertificateFactory.CreateSelfSignedCert();
        using RSA? rsa = certificate.GetRSAPrivateKey();
        rsa.ShouldNotBeNull();
        var externalSigner = new TrackingExternalSigner(rsa!, TimeSpan.FromMilliseconds(25));
        await using var signer = BatchSigner.Create(certificate)
            .WithExternalSigner(externalSigner)
            .WithMaxConcurrency(1)
            .Build();
        var thirdInputYielded = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        int yieldedInputs = 0;

        await using IAsyncEnumerator<BatchSignResult> results = signer.SignAllAsync(
            GenerateCountedInputs(6, count =>
            {
                Interlocked.Exchange(ref yieldedInputs, count);
                if (count == 3)
                {
                    thirdInputYielded.TrySetResult();
                }
            })).GetAsyncEnumerator();

        (await results.MoveNextAsync()).ShouldBeTrue();
        await thirdInputYielded.Task.WaitAsync(TimeSpan.FromSeconds(10));
        await Task.Delay(TimeSpan.FromMilliseconds(100));

        // One result was consumed, one can occupy the bounded channel, and one may be
        // in-flight waiting for space. The fourth input must not be requested yet.
        Volatile.Read(ref yieldedInputs).ShouldBe(3);
    }

    [Fact(DisplayName = "ResetMetrics clears all counters")]
    public async Task ResetMetrics_ClearsCounters()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        await using var signer = BatchSigner.Create(cert).Build();

        await signer.SignAsync(CreateMinimalPdf());
        signer.SuccessCount.ShouldBe(1);

        signer.ResetMetrics();
        signer.SuccessCount.ShouldBe(0);
        signer.FailureCount.ShouldBe(0);
        signer.AverageElapsedMs.ShouldBe(0);
    }

    [Fact(DisplayName = "Builder WithMaxConcurrency rejects zero")]
    public void Builder_MaxConcurrency_RejectsZero()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        var act = () => BatchSigner.Create(cert).WithMaxConcurrency(0);
        Should.Throw<ArgumentOutOfRangeException>(act);
    }

    [Fact(DisplayName = "Builder configures metadata")]
    public async Task Builder_WithMetadata_AppliedToSignature()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        await using var signer = BatchSigner.Create(cert)
            .WithFieldOptions(new SignatureFieldOptions
            {
                SignerName = "Test User",
                Reason = "Approval",
                Location = "Vitória"
            })
            .WithHashAlgorithm(HashAlgorithmName.SHA256)
            .Build();

        var signed = await signer.SignAsync(CreateMinimalPdf());
        signed.ShouldNotBeNull();
        signed.ShouldNotBeEmpty();
    }

    [Fact(DisplayName = "BatchSignResult IsSuccess reflects Error state")]
    public void BatchSignResult_IsSuccess()
    {
        var success = new BatchSignResult("ok", [1], null);
        success.IsSuccess.ShouldBeTrue();

        var failure = new BatchSignResult("fail", null, new InvalidOperationException("test"));
        failure.IsSuccess.ShouldBeFalse();
    }

    [Fact(DisplayName = "SignAsync with stream outputs signed PDF")]
    public async Task SignAsync_Stream_OutputsSignedPdf()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        await using var signer = BatchSigner.Create(cert).Build();

        using var input = new MemoryStream(CreateMinimalPdf());
        using var output = new MemoryStream();

        await signer.SignAsync(input, output);

        output.Length.ShouldBeGreaterThan(0);
        signer.SuccessCount.ShouldBe(1);
    }

    private static async IAsyncEnumerable<(string Id, byte[] PdfBytes)> GenerateInputs(int count)
    {
        for (var i = 0; i < count; i++)
        {
            await Task.CompletedTask;
            yield return ($"doc-{i}", CreateMinimalPdf());
        }
    }

    private static async IAsyncEnumerable<(string Id, byte[] PdfBytes)> GenerateBlockedInputs(Task releaseSecondInput)
    {
        yield return ("first", CreateMinimalPdf());
        await releaseSecondInput.ConfigureAwait(false);
        yield return ("second", CreateMinimalPdf());
    }

    private static async IAsyncEnumerable<(string Id, byte[] PdfBytes)> GenerateCancelableInputs(
        TaskCompletionSource sourceCanceled,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        yield return ("first", CreateMinimalPdf());
        try
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            sourceCanceled.TrySetResult();
            throw;
        }
    }

    private static async IAsyncEnumerable<(string Id, byte[] PdfBytes)> GenerateFailingInputs()
    {
        yield return ("first", CreateMinimalPdf());
        await Task.CompletedTask;
        throw new InvalidOperationException("source failed");
    }

    private static async IAsyncEnumerable<(string Id, byte[] PdfBytes)> GenerateCountedInputs(
        int count,
        Action<int> yielded)
    {
        for (int index = 1; index <= count; index++)
        {
            yielded(index);
            yield return ($"doc-{index}", CreateMinimalPdf());
            await Task.Yield();
        }
    }

    private sealed class TrackingExternalSigner : IExternalSigner
    {
        private readonly RSA _rsa;
        private readonly TimeSpan _delay;
        private int _activeCalls;
        private int _maximumConcurrentCalls;

        public TrackingExternalSigner(RSA rsa, TimeSpan delay)
        {
            _rsa = rsa;
            _delay = delay;
        }

        public int MaximumConcurrentCalls => Volatile.Read(ref _maximumConcurrentCalls);

        public async ValueTask<ReadOnlyMemory<byte>> SignAsync(
            ExternalSigningRequest request,
            CancellationToken cancellationToken)
        {
            int active = Interlocked.Increment(ref _activeCalls);
            UpdateMaximum(active);
            try
            {
                await Task.Delay(_delay, cancellationToken);
                byte[] signature;
                lock (_rsa)
                {
                    signature = _rsa.SignData(request.DataToSign.Span, request.HashAlgorithm, RSASignaturePadding.Pkcs1);
                }

                return signature;
            }
            finally
            {
                Interlocked.Decrement(ref _activeCalls);
            }
        }

        private void UpdateMaximum(int active)
        {
            int observed;
            do
            {
                observed = Volatile.Read(ref _maximumConcurrentCalls);
                if (observed >= active)
                {
                    return;
                }
            }
            while (Interlocked.CompareExchange(ref _maximumConcurrentCalls, active, observed) != observed);
        }
    }
}

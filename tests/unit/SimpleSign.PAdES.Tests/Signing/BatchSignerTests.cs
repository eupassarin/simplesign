using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using FluentAssertions;
using SimpleSign.Core.Validation;
using SimpleSign.PAdES.Signing;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.PAdES.Tests.Signing;

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

        signed.Should().NotBeNullOrEmpty();
        signer.SuccessCount.Should().Be(1);
        signer.FailureCount.Should().Be(0);
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

        signer.SuccessCount.Should().Be(3);
        signer.FailureCount.Should().Be(0);
        signer.AverageElapsedMs.Should().BeGreaterThanOrEqualTo(0);
    }

    [Fact(DisplayName = "BatchSigner tracks failures for expired cert")]
    public async Task SignAsync_ExpiredCert_TracksFailure()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=Expired", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-10), DateTimeOffset.UtcNow.AddDays(-1));

        await using var signer = BatchSigner.Create(cert).Build();

        var act = () => signer.SignAsync(CreateMinimalPdf());
        await act.Should().ThrowAsync<CertificateValidationException>("expired cert should throw");

        signer.FailureCount.Should().Be(1);
        signer.SuccessCount.Should().Be(0);
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

        results.Should().HaveCount(3);
        results.Should().OnlyContain(r => r.IsSuccess);
        results.Should().OnlyContain(r => r.SignedPdf != null);
        signer.SuccessCount.Should().Be(3);
    }

    [Fact(DisplayName = "ResetMetrics clears all counters")]
    public async Task ResetMetrics_ClearsCounters()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        await using var signer = BatchSigner.Create(cert).Build();

        await signer.SignAsync(CreateMinimalPdf());
        signer.SuccessCount.Should().Be(1);

        signer.ResetMetrics();
        signer.SuccessCount.Should().Be(0);
        signer.FailureCount.Should().Be(0);
        signer.AverageElapsedMs.Should().Be(0);
    }

    [Fact(DisplayName = "Builder WithMaxConcurrency rejects zero")]
    public void Builder_MaxConcurrency_RejectsZero()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        var act = () => BatchSigner.Create(cert).WithMaxConcurrency(0);
        act.Should().Throw<ArgumentOutOfRangeException>();
    }

    [Fact(DisplayName = "Builder configures metadata")]
    public async Task Builder_WithMetadata_AppliedToSignature()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        await using var signer = BatchSigner.Create(cert)
            .WithMetadata(signerName: "Test User", reason: "Approval", location: "Vitória")
            .WithHashAlgorithm(HashAlgorithmName.SHA256)
            .Build();

        var signed = await signer.SignAsync(CreateMinimalPdf());
        signed.Should().NotBeNullOrEmpty();
    }

    [Fact(DisplayName = "BatchSignResult IsSuccess reflects Error state")]
    public void BatchSignResult_IsSuccess()
    {
        var success = new BatchSignResult("ok", new byte[] { 1 }, null);
        success.IsSuccess.Should().BeTrue();

        var failure = new BatchSignResult("fail", null, new InvalidOperationException("test"));
        failure.IsSuccess.Should().BeFalse();
    }

    [Fact(DisplayName = "SignAsync with stream outputs signed PDF")]
    public async Task SignAsync_Stream_OutputsSignedPdf()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        await using var signer = BatchSigner.Create(cert).Build();

        using var input = new MemoryStream(CreateMinimalPdf());
        using var output = new MemoryStream();

        await signer.SignAsync(input, output);

        output.Length.Should().BeGreaterThan(0);
        signer.SuccessCount.Should().Be(1);
    }

    private static async IAsyncEnumerable<(string Id, byte[] PdfBytes)> GenerateInputs(int count)
    {
        for (var i = 0; i < count; i++)
        {
            await Task.CompletedTask;
            yield return ($"doc-{i}", CreateMinimalPdf());
        }
    }
}

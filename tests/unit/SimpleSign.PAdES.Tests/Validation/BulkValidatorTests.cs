using System.Security.Cryptography.X509Certificates;
using FluentAssertions;
using SimpleSign.Core.Validation;
using SimpleSign.PAdES.Validation;
using SimpleSign.TestHelpers;
using Xunit;
namespace SimpleSign.PAdES.Tests.Validation;

public sealed class BulkValidatorTests
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

    private static async Task<byte[]> SignPdf(X509Certificate2 cert)
    {
        return await SimpleSigner.Document(CreateMinimalPdf())
            .WithCertificate(cert)
            .SignAsync();
    }

    [Fact(DisplayName = "ValidateAsync validates a single signed PDF")]
    public async Task ValidateAsync_SinglePdf()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        var signed = await SignPdf(cert);

        var validator = new PdfSignatureValidator(new ValidationOptions
        {
            CheckRevocation = false,
            TrustSystemRoots = false,
            TrustedRoots = [cert]
        });
        var bulk = new BulkValidator(validator);

        using var stream = new MemoryStream(signed);
        var results = await bulk.ValidateAsync(stream);

        results.Should().NotBeEmpty();
        bulk.SuccessCount.Should().Be(1);
        bulk.FailureCount.Should().Be(0);
    }

    [Fact(DisplayName = "ValidateAllAsync processes batch and yields results")]
    public async Task ValidateAllAsync_BatchProcessing()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        var signed1 = await SignPdf(cert);
        var signed2 = await SignPdf(cert);

        var validator = new PdfSignatureValidator(new ValidationOptions
        {
            CheckRevocation = false,
            TrustSystemRoots = false,
            TrustedRoots = [cert]
        });
        var bulk = new BulkValidator(validator, maxConcurrency: 2);

        var inputs = ToAsyncEnumerable(
            ("doc-1", signed1),
            ("doc-2", signed2));

        var results = new List<BulkValidationResult>();
        await foreach (var result in bulk.ValidateAllAsync(inputs))
        {
            results.Add(result);
        }

        results.Should().HaveCount(2);
        results.Should().OnlyContain(r => r.IsProcessed);
        results.Should().OnlyContain(r => r.TotalSignatureCount > 0);
        bulk.SuccessCount.Should().Be(2);
    }

    [Fact(DisplayName = "ValidateAllAsync handles failures gracefully")]
    public async Task ValidateAllAsync_HandlesFailures()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        var signed = await SignPdf(cert);

        var validator = new PdfSignatureValidator(new ValidationOptions
        {
            CheckRevocation = false,
            TrustSystemRoots = false,
            TrustedRoots = [cert]
        });
        var bulk = new BulkValidator(validator, maxConcurrency: 1);

        var inputs = ToAsyncEnumerable(
            ("good", signed),
            ("empty", Array.Empty<byte>()),
            ("good2", signed));

        var results = new List<BulkValidationResult>();
        await foreach (var result in bulk.ValidateAllAsync(inputs))
        {
            results.Add(result);
        }

        results.Should().HaveCount(3);
        var processed = results.Where(r => r.IsProcessed).ToList();
        var failed = results.Where(r => !r.IsProcessed).ToList();

        processed.Should().HaveCountGreaterThanOrEqualTo(2);
        failed.Should().HaveCountLessThanOrEqualTo(1);
    }

    [Fact(DisplayName = "Metrics track success and failure correctly")]
    public async Task Metrics_TrackCorrectly()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        var signed = await SignPdf(cert);

        var validator = new PdfSignatureValidator(new ValidationOptions
        {
            CheckRevocation = false,
            TrustSystemRoots = false,
            TrustedRoots = [cert]
        });
        var bulk = new BulkValidator(validator);

        using var stream = new MemoryStream(signed);
        await bulk.ValidateAsync(stream);

        bulk.SuccessCount.Should().Be(1);
        bulk.TotalProcessed.Should().Be(1);
        bulk.AverageElapsedMs.Should().BeGreaterThanOrEqualTo(0);
    }

    [Fact(DisplayName = "ResetMetrics clears all counters")]
    public async Task ResetMetrics_ClearsCounters()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        var signed = await SignPdf(cert);

        var validator = new PdfSignatureValidator(new ValidationOptions
        {
            CheckRevocation = false,
            TrustSystemRoots = false,
            TrustedRoots = [cert]
        });
        var bulk = new BulkValidator(validator);

        using var stream = new MemoryStream(signed);
        await bulk.ValidateAsync(stream);
        bulk.SuccessCount.Should().Be(1);

        bulk.ResetMetrics();
        bulk.SuccessCount.Should().Be(0);
        bulk.FailureCount.Should().Be(0);
        bulk.TotalProcessed.Should().Be(0);
        bulk.AverageElapsedMs.Should().Be(0);
    }

    [Fact(DisplayName = "Constructor rejects zero concurrency")]
    public void Constructor_ZeroConcurrency_Throws()
    {
        var validator = new PdfSignatureValidator();
        var act = () => new BulkValidator(validator, maxConcurrency: 0);
        act.Should().Throw<ArgumentOutOfRangeException>();
    }

    [Fact(DisplayName = "Constructor rejects null validator")]
    public void Constructor_NullValidator_Throws()
    {
        var act = () => new BulkValidator(null!);
        act.Should().Throw<ArgumentNullException>();
    }

    [Fact(DisplayName = "BulkValidationResult IsProcessed and counts")]
    public void BulkValidationResult_Properties()
    {
        var success = new BulkValidationResult("ok", new List<SignatureValidationResult>
        {
            new() { FieldName = "Sig1", IsIntegrityValid = true, IsSignatureValid = true, IsCertificateChainValid = true }
        }, null, TimeSpan.FromMilliseconds(50));

        success.IsProcessed.Should().BeTrue();
        success.TotalSignatureCount.Should().Be(1);
        success.ValidSignatureCount.Should().Be(1);

        var failure = new BulkValidationResult("bad", null, new InvalidOperationException("test"), TimeSpan.FromMilliseconds(10));
        failure.IsProcessed.Should().BeFalse();
        failure.TotalSignatureCount.Should().Be(0);
        failure.ValidSignatureCount.Should().Be(0);
    }

    private static async IAsyncEnumerable<(string Id, byte[] PdfBytes)> ToAsyncEnumerable(
        params (string Id, byte[] PdfBytes)[] items)
    {
        foreach (var item in items)
        {
            await Task.CompletedTask;
            yield return item;
        }
    }
}

using System.Security.Cryptography.X509Certificates;
using Shouldly;
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

        results.ShouldNotBeEmpty();
        bulk.SuccessCount.ShouldBe(1);
        bulk.FailureCount.ShouldBe(0);
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

        results.Count().ShouldBe(2);
        results.ShouldAllBe(r => r.IsProcessed);
        results.ShouldAllBe(r => r.TotalSignatureCount > 0);
        bulk.SuccessCount.ShouldBe(2);
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

        results.Count().ShouldBe(3);
        var processed = results.Where(r => r.IsProcessed).ToList();
        var failed = results.Where(r => !r.IsProcessed).ToList();

        processed.Count().ShouldBeGreaterThanOrEqualTo(2);
        failed.Count().ShouldBeLessThanOrEqualTo(1);
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

        bulk.SuccessCount.ShouldBe(1);
        bulk.TotalProcessed.ShouldBe(1);
        bulk.AverageElapsedMs.ShouldBeGreaterThanOrEqualTo(0);
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
        bulk.SuccessCount.ShouldBe(1);

        bulk.ResetMetrics();
        bulk.SuccessCount.ShouldBe(0);
        bulk.FailureCount.ShouldBe(0);
        bulk.TotalProcessed.ShouldBe(0);
        bulk.AverageElapsedMs.ShouldBe(0);
    }

    [Fact(DisplayName = "Constructor rejects zero concurrency")]
    public void Constructor_ZeroConcurrency_Throws()
    {
        var validator = new PdfSignatureValidator();
        var act = () => new BulkValidator(validator, maxConcurrency: 0);
        Should.Throw<ArgumentOutOfRangeException>(act);
    }

    [Fact(DisplayName = "Constructor rejects null validator")]
    public void Constructor_NullValidator_Throws()
    {
        var act = () => new BulkValidator(null!);
        Should.Throw<ArgumentNullException>(act);
    }

    [Fact(DisplayName = "BulkValidationResult IsProcessed and counts")]
    public void BulkValidationResult_Properties()
    {
        var success = new BulkValidationResult("ok", new List<SignatureValidationResult>
        {
            new() { FieldName = "Sig1", IsIntegrityValid = true, IsSignatureValid = true, IsCertificateChainValid = true, IsNotRevoked = true }
        }, null, TimeSpan.FromMilliseconds(50));

        success.IsProcessed.ShouldBeTrue();
        success.TotalSignatureCount.ShouldBe(1);
        success.ValidSignatureCount.ShouldBe(1);

        var failure = new BulkValidationResult("bad", null, new InvalidOperationException("test"), TimeSpan.FromMilliseconds(10));
        failure.IsProcessed.ShouldBeFalse();
        failure.TotalSignatureCount.ShouldBe(0);
        failure.ValidSignatureCount.ShouldBe(0);
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

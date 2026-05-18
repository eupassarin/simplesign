using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Shouldly;
using SimpleSign.PAdES;
using Xunit;

namespace SimpleSign.Integration.Tests;

/// <summary>
/// Sustained-load stress tests to detect memory leaks, resource exhaustion,
/// and degradation under prolonged usage. These are long-running tests
/// (Trait "Category" = "Stress") excluded from normal CI runs.
/// </summary>
[Trait("Category", "Stress")]
public sealed class StressTests : IDisposable
{
    private readonly X509Certificate2 _cert;
    private readonly byte[] _pdf;

    public StressTests()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=StressTest", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation, critical: true));
        _cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        _pdf = CreateMinimalPdf();
    }

    [Fact(DisplayName = "1000 sequential signatures — no memory leak")]
    public async Task SequentialSigning_1000_NoMemoryLeak()
    {
        const int iterations = 1000;
        var memBefore = GC.GetTotalMemory(forceFullCollection: true);

        for (int i = 0; i < iterations; i++)
        {
            var signed = await SimpleSigner
                .Document(_pdf)
                .WithCertificate(_cert)
                .SignAsync();

            signed.ShouldNotBeNull();
            signed.Length.ShouldBeGreaterThan(_pdf.Length);
        }

        GC.Collect(2, GCCollectionMode.Aggressive, blocking: true);
        GC.WaitForPendingFinalizers();
        var memAfter = GC.GetTotalMemory(forceFullCollection: true);

        // Memory should not grow more than 50 MB over 1000 iterations
        // (each sign produces ~2 MB temporarily but should be GC'd)
        var growth = memAfter - memBefore;
        growth.ShouldBeLessThan(50 * 1024 * 1024,
            $"Memory grew by {growth / 1024 / 1024} MB over {iterations} iterations — possible leak");
    }

    [Fact(DisplayName = "500 concurrent batch — no resource exhaustion")]
    public async Task ConcurrentBatch_500_NoResourceExhaustion()
    {
        const int totalDocs = 500;
        const int concurrency = 16;

        var semaphore = new SemaphoreSlim(concurrency);
        var tasks = Enumerable.Range(0, totalDocs).Select(async _ =>
        {
            await semaphore.WaitAsync();
            try
            {
                var signed = await SimpleSigner
                    .Document(_pdf)
                    .WithCertificate(_cert)
                    .SignAsync();
                signed.ShouldNotBeNull();
            }
            finally
            {
                semaphore.Release();
            }
        });

        var sw = Stopwatch.StartNew();
        await Task.WhenAll(tasks);
        sw.Stop();

        // 500 docs at 16 concurrency should finish in under 60 seconds
        sw.Elapsed.TotalSeconds.ShouldBeLessThan(60,
            $"Batch took {sw.Elapsed.TotalSeconds:F1}s — possible resource exhaustion");
    }

    [Fact(DisplayName = "100 incremental signatures on same PDF — no corruption")]
    public async Task IncrementalSigning_100_NoCurruption()
    {
        var currentPdf = _pdf;

        for (int i = 0; i < 100; i++)
        {
            currentPdf = await SimpleSigner
                .Document(currentPdf)
                .WithCertificate(_cert)
                .SignAsync();
        }

        // Final PDF should be valid and larger than original
        currentPdf.Length.ShouldBeGreaterThan(_pdf.Length * 10);

        // Verify structure is not corrupted — should find signature fields
        using var ms = new MemoryStream(currentPdf);
        var fields = await SimpleSign.Pdf.PdfStructureReader.ReadSignatureFieldsAsync(ms);
        fields.Count.ShouldBeGreaterThanOrEqualTo(100);
    }

    public void Dispose()
    {
        _cert.Dispose();
    }

    private static byte[] CreateMinimalPdf()
    {
        return "%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n3 0 obj<</Type/Page/MediaBox[0 0 612 792]/Parent 2 0 R>>endobj\nxref\n0 4\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \n0000000115 00000 n \ntrailer<</Size 4/Root 1 0 R>>\nstartxref\n190\n%%EOF\n"u8.ToArray();
    }
}

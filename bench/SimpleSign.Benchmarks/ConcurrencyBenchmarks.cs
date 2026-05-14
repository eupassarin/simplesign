using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using BenchmarkDotNet.Attributes;
using SimpleSign.PAdES;

namespace SimpleSign.Benchmarks;

/// <summary>
/// Measures throughput under concurrent load.
/// Proves thread-safety and shows how SimpleSign scales with parallelism.
/// </summary>
[MemoryDiagnoser]
public class ConcurrencyBenchmarks
{
    private byte[] _pdfBytes = null!;
    private X509Certificate2 _cert = null!;

    private const int OperationsPerRun = 32;

    [GlobalSetup]
    public void Setup()
    {
        _pdfBytes = PdfHelper.BuildMinimalPdf();

        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=Bench Concurrency", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation, true));
        _cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(1));
    }

    [GlobalCleanup]
    public void Cleanup() => _cert.Dispose();

    [Benchmark(Baseline = true, Description = "Sequential (32 ops)")]
    public async Task<int> Sequential()
    {
        int count = 0;
        for (int i = 0; i < OperationsPerRun; i++)
        {
            var result = await SimpleSigner.Document(_pdfBytes)
                .WithCertificate(_cert)
                .SignAsync();
            if (result.Length > 0)
            {
                count++;
            }
        }
        return count;
    }

    [Benchmark(Description = "Concurrent 8 tasks (32 ops)")]
    public async Task<int> Concurrent_8()
    {
        return await RunConcurrent(8);
    }

    [Benchmark(Description = "Concurrent 16 tasks (32 ops)")]
    public async Task<int> Concurrent_16()
    {
        return await RunConcurrent(16);
    }

    [Benchmark(Description = "Concurrent 32 tasks (32 ops)")]
    public async Task<int> Concurrent_32()
    {
        return await RunConcurrent(32);
    }

    private async Task<int> RunConcurrent(int concurrency)
    {
        int count = 0;
        using var semaphore = new SemaphoreSlim(concurrency);
        var tasks = new Task[OperationsPerRun];

        for (int i = 0; i < OperationsPerRun; i++)
        {
            tasks[i] = Task.Run(async () =>
            {
                await semaphore.WaitAsync();
                try
                {
                    var result = await SimpleSigner.Document(_pdfBytes)
                        .WithCertificate(_cert)
                        .SignAsync();
                    if (result.Length > 0)
                    {
                        Interlocked.Increment(ref count);
                    }
                }
                finally
                {
                    semaphore.Release();
                }
            });
        }

        await Task.WhenAll(tasks);
        return count;
    }
}

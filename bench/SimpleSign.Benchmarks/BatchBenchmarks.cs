using System.Runtime.CompilerServices;
using System.Security.Cryptography.X509Certificates;
using BenchmarkDotNet.Attributes;
using SimpleSign.PAdES;
using SimpleSign.PAdES.Signing;
using SimpleSign.TestHelpers;

namespace SimpleSign.Benchmarks;

/// <summary>
/// Measures throughput when signing multiple documents using BatchSigner.
/// Demonstrates amortized cost per document and concurrency gains.
/// </summary>
[MemoryDiagnoser]
public class BatchBenchmarks
{
    private X509Certificate2 _cert = null!;
    private byte[][] _pdfs = null!;

    [Params(10, 100)]
    public int DocumentCount { get; set; }

    [GlobalSetup]
    public void Setup()
    {
        _cert = TestCertificateFactory.CreateSelfSignedCert("CN=Batch Bench");
        var template = PdfHelper.BuildMinimalPdf();
        _pdfs = Enumerable.Range(0, DocumentCount).Select(_ => (byte[])template.Clone()).ToArray();
    }

    [GlobalCleanup]
    public void Cleanup() => _cert.Dispose();

    [Benchmark(Description = "Sequential (loop)")]
    public async Task<int> SignSequential()
    {
        int count = 0;
        foreach (var pdf in _pdfs)
        {
            _ = await SimpleSigner.Document(pdf).WithCertificate(_cert).SignAsync();
            count++;
        }
        return count;
    }

    [Benchmark(Description = "BatchSigner (concurrency=4)")]
    public async Task<int> SignBatch()
    {
        await using var batcher = BatchSigner.Create(_cert)
            .WithMaxConcurrency(4)
            .Build();

        int count = 0;
        await foreach (var result in batcher.SignAllAsync(ToAsyncEnumerable(_pdfs)))
        {
            if (result.IsSuccess)
            {
                count++;
            }
        }
        return count;
    }

    [Benchmark(Description = "BatchSigner (concurrency=1)")]
    public async Task<int> SignBatch_Concurrency1()
    {
        await using var batcher = BatchSigner.Create(_cert)
            .WithMaxConcurrency(1)
            .Build();

        int count = 0;
        await foreach (var result in batcher.SignAllAsync(ToAsyncEnumerable(_pdfs)))
        {
            if (result.IsSuccess)
            {
                count++;
            }
        }
        return count;
    }

    [Benchmark(Description = "BatchSigner (concurrency=8)")]
    public async Task<int> SignBatch_Concurrency8()
    {
        await using var batcher = BatchSigner.Create(_cert)
            .WithMaxConcurrency(8)
            .Build();

        int count = 0;
        await foreach (var result in batcher.SignAllAsync(ToAsyncEnumerable(_pdfs)))
        {
            if (result.IsSuccess)
            {
                count++;
            }
        }
        return count;
    }

    [Benchmark(Description = "BatchSigner (concurrency=16)")]
    public async Task<int> SignBatch_Concurrency16()
    {
        await using var batcher = BatchSigner.Create(_cert)
            .WithMaxConcurrency(16)
            .Build();

        int count = 0;
        await foreach (var result in batcher.SignAllAsync(ToAsyncEnumerable(_pdfs)))
        {
            if (result.IsSuccess)
            {
                count++;
            }
        }
        return count;
    }

    private static async IAsyncEnumerable<(string Id, byte[] PdfBytes)> ToAsyncEnumerable(
        byte[][] pdfs,
        [EnumeratorCancellation] CancellationToken ct = default)
    {
        for (int i = 0; i < pdfs.Length; i++)
        {
            ct.ThrowIfCancellationRequested();
            yield return ($"doc-{i}.pdf", pdfs[i]);
            await Task.CompletedTask;
        }
    }
}

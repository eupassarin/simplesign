using System.Security.Cryptography.X509Certificates;
using BenchmarkDotNet.Attributes;
using SimpleSign.PAdES;
using SimpleSign.TestHelpers;

namespace SimpleSign.Benchmarks;

/// <summary>
/// Compares signing performance across different I/O strategies:
/// byte[] in/out, MemoryStream in/out, and FileStream in/out.
/// Shows whether the Stream path introduces measurable overhead.
/// </summary>
[MemoryDiagnoser]
public class StreamBenchmarks
{
    private byte[] _pdfBytes = null!;
    private X509Certificate2 _cert = null!;
    private string _tempDir = null!;

    [GlobalSetup]
    public void Setup()
    {
        _pdfBytes = PdfHelper.BuildMinimalPdf();
        _cert = TestCertificateFactory.CreateSelfSignedCert("CN=Bench Stream");
        _tempDir = Path.Combine(Path.GetTempPath(), $"simplesign-bench-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempDir);
    }

    [GlobalCleanup]
    public void Cleanup()
    {
        _cert.Dispose();
        try
        {
            Directory.Delete(_tempDir, recursive: true);
        }
        catch
        {
            // best effort
        }
    }

    [Benchmark(Baseline = true, Description = "byte[] → byte[] (baseline)")]
    public async Task<byte[]> ByteArray_InOut()
    {
        return await SimpleSigner.Document(_pdfBytes)
            .WithCertificate(_cert)
            .SignAsync();
    }

    [Benchmark(Description = "MemoryStream → MemoryStream")]
    public async Task<int> MemoryStream_InOut()
    {
        using var input = new MemoryStream(_pdfBytes);
        using var output = new MemoryStream();
        await SimpleSigner.Document(input)
            .WithCertificate(_cert)
            .SignAsync(output);
        return (int)output.Length;
    }

    [Benchmark(Description = "FileStream → FileStream")]
    public async Task<int> FileStream_InOut()
    {
        var inputPath = Path.Combine(_tempDir, $"in-{Guid.NewGuid():N}.pdf");
        var outputPath = Path.Combine(_tempDir, $"out-{Guid.NewGuid():N}.pdf");

        await File.WriteAllBytesAsync(inputPath, _pdfBytes);
        try
        {
            await using var input = new FileStream(inputPath, FileMode.Open, FileAccess.Read, FileShare.Read);
            await using var output = new FileStream(outputPath, FileMode.Create, FileAccess.ReadWrite);
            await SimpleSigner.Document(input)
                .WithCertificate(_cert)
                .SignAsync(output);
            return (int)output.Length;
        }
        finally
        {
            File.Delete(inputPath);
            File.Delete(outputPath);
        }
    }
}

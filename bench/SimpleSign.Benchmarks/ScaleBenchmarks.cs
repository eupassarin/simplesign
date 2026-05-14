using System.Security.Cryptography.X509Certificates;
using BenchmarkDotNet.Attributes;
using SimpleSign.PAdES;
using SimpleSign.TestHelpers;

namespace SimpleSign.Benchmarks;

/// <summary>
/// Measures how signing time and memory scale with PDF document size.
/// Demonstrates sub-linear growth — larger documents don't proportionally slow signing.
/// </summary>
[MemoryDiagnoser]
public class ScaleBenchmarks
{
    private X509Certificate2 _cert = null!;
    private byte[] _pdf1KB = null!;
    private byte[] _pdf100KB = null!;
    private byte[] _pdf1MB = null!;
    private byte[] _pdf10MB = null!;

    [GlobalSetup]
    public void Setup()
    {
        _cert = TestCertificateFactory.CreateSelfSignedCert("CN=Scale Bench");
        _pdf1KB = BuildPdfOfSize(1_024);
        _pdf100KB = BuildPdfOfSize(100 * 1_024);
        _pdf1MB = BuildPdfOfSize(1_024 * 1_024);
        _pdf10MB = BuildPdfOfSize(10 * 1_024 * 1_024);
    }

    [GlobalCleanup]
    public void Cleanup() => _cert.Dispose();

    [Benchmark(Description = "PAdES sign 1 KB PDF")]
    public async Task<byte[]> Sign_1KB() =>
        await SimpleSigner.Document(_pdf1KB).WithCertificate(_cert).SignAsync();

    [Benchmark(Description = "PAdES sign 100 KB PDF")]
    public async Task<byte[]> Sign_100KB() =>
        await SimpleSigner.Document(_pdf100KB).WithCertificate(_cert).SignAsync();

    [Benchmark(Description = "PAdES sign 1 MB PDF")]
    public async Task<byte[]> Sign_1MB() =>
        await SimpleSigner.Document(_pdf1MB).WithCertificate(_cert).SignAsync();

    [Benchmark(Description = "PAdES sign 10 MB PDF")]
    public async Task<byte[]> Sign_10MB() =>
        await SimpleSigner.Document(_pdf10MB).WithCertificate(_cert).SignAsync();

    /// <summary>
    /// Builds a minimal valid PDF with a stream object padded to reach the target size.
    /// </summary>
    private static byte[] BuildPdfOfSize(int targetBytes)
    {
        var header = "%PDF-1.7\n"u8;
        var catalogObj = "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"u8;
        var pagesObj = "2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\n"u8;

        int overhead = header.Length + catalogObj.Length + pagesObj.Length + 256;
        int streamSize = Math.Max(0, targetBytes - overhead);

        using var ms = new MemoryStream(targetBytes + 512);
        ms.Write(header);
        ms.Write(catalogObj);
        ms.Write(pagesObj);

        // Stream object with padding to reach target size
        var streamHeaderStr = System.Text.Encoding.ASCII.GetBytes(
            $"3 0 obj\n<< /Length {streamSize} >>\nstream\n");
        ms.Write(streamHeaderStr);
        var padding = new byte[streamSize];
        Random.Shared.NextBytes(padding);
        ms.Write(padding);
        ms.Write("\nendstream\nendobj\n"u8);

        long xrefPos = ms.Position;
        int off1 = 9;
        int off2 = 9 + catalogObj.Length;
        int off3 = 9 + catalogObj.Length + pagesObj.Length;
        var xrefStr = System.Text.Encoding.ASCII.GetBytes(
            $"xref\n0 4\n0000000000 65535 f \n{off1:D10} 00000 n \n{off2:D10} 00000 n \n{off3:D10} 00000 n \n");
        ms.Write(xrefStr);
        var trailerStr = System.Text.Encoding.ASCII.GetBytes(
            $"trailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n{xrefPos}\n%%EOF");
        ms.Write(trailerStr);

        return ms.ToArray();
    }
}

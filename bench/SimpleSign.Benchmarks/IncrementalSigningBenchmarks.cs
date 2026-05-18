using System.Security.Cryptography.X509Certificates;
using BenchmarkDotNet.Attributes;
using SimpleSign.PAdES;
using SimpleSign.TestHelpers;

namespace SimpleSign.Benchmarks;

/// <summary>
/// Measures how signing cost grows with each incremental signature added to the same PDF.
/// Shows whether the N-th signature is proportionally more expensive than the first.
/// </summary>
[MemoryDiagnoser]
public class IncrementalSigningBenchmarks
{
    private byte[] _pdfUnsigned = null!;
    private byte[] _pdf1Sig = null!;
    private byte[] _pdf2Sigs = null!;
    private byte[] _pdf3Sigs = null!;
    private byte[] _pdf4Sigs = null!;
    private X509Certificate2 _cert = null!;

    [GlobalSetup]
    public async Task Setup()
    {
        _cert = TestCertificateFactory.CreateSelfSignedCert("CN=Bench Incremental");
        _pdfUnsigned = PdfHelper.BuildMinimalPdf();

        _pdf1Sig = await SimpleSigner.Document(_pdfUnsigned).WithCertificate(_cert).SignAsync();
        _pdf2Sigs = await SimpleSigner.Document(_pdf1Sig).WithCertificate(_cert).SignAsync();
        _pdf3Sigs = await SimpleSigner.Document(_pdf2Sigs).WithCertificate(_cert).SignAsync();
        _pdf4Sigs = await SimpleSigner.Document(_pdf3Sigs).WithCertificate(_cert).SignAsync();
    }

    [GlobalCleanup]
    public void Cleanup() => _cert.Dispose();

    [Benchmark(Baseline = true, Description = "Add 1st signature (unsigned → 1 sig)")]
    public async Task<byte[]> Sign_1st() =>
        await SimpleSigner.Document(_pdfUnsigned).WithCertificate(_cert).SignAsync();

    [Benchmark(Description = "Add 2nd signature (1 sig → 2 sigs)")]
    public async Task<byte[]> Sign_2nd() =>
        await SimpleSigner.Document(_pdf1Sig).WithCertificate(_cert).SignAsync();

    [Benchmark(Description = "Add 3rd signature (2 sigs → 3 sigs)")]
    public async Task<byte[]> Sign_3rd() =>
        await SimpleSigner.Document(_pdf2Sigs).WithCertificate(_cert).SignAsync();

    [Benchmark(Description = "Add 4th signature (3 sigs → 4 sigs)")]
    public async Task<byte[]> Sign_4th() =>
        await SimpleSigner.Document(_pdf3Sigs).WithCertificate(_cert).SignAsync();

    [Benchmark(Description = "Add 5th signature (4 sigs → 5 sigs)")]
    public async Task<byte[]> Sign_5th() =>
        await SimpleSigner.Document(_pdf4Sigs).WithCertificate(_cert).SignAsync();
}

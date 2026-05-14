using System.Security.Cryptography.X509Certificates;
using BenchmarkDotNet.Attributes;
using SimpleSign.PAdES;
using SimpleSign.TestHelpers;

namespace SimpleSign.Benchmarks;

/// <summary>
/// PAdES signing benchmarks. Compares cold/warm signing and basic vs LTV configurations.
/// Runs against whatever target framework you publish for; multi-target comparison
/// is achieved by running <c>dotnet run -c Release --framework net8.0</c> and
/// <c>--framework net10.0</c> separately.
/// </summary>
[MemoryDiagnoser]
public class SignBenchmarks
{
    private byte[] _pdfBytes = null!;
    private X509Certificate2 _cert = null!;

    [GlobalSetup]
    public void Setup()
    {
        _pdfBytes = PdfHelper.BuildMinimalPdf();
        _cert = TestCertificateFactory.CreateSelfSignedCert("CN=Bench Signer");
    }

    [GlobalCleanup]
    public void Cleanup() => _cert.Dispose();

    [Benchmark(Description = "Sign 1 PDF (PAdES-B-B, RSA-SHA256)")]
    public async Task<byte[]> Sign_PadesBB_Rsa()
    {
        return await SimpleSigner.Document(_pdfBytes)
            .WithCertificate(_cert)
            .SignAsync();
    }
}

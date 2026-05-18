using System.Security.Cryptography.X509Certificates;
using BenchmarkDotNet.Attributes;
using SimpleSign.PAdES;
using SimpleSign.PAdES.Signing;
using SimpleSign.TestHelpers;

namespace SimpleSign.Benchmarks;

/// <summary>
/// Measures the overhead of each optional signing feature relative to a plain sign.
/// Shows the cost delta of visual appearance, certification, and PDF/A preservation.
/// </summary>
[MemoryDiagnoser]
public class FeatureBenchmarks
{
    private byte[] _pdfBytes = null!;
    private X509Certificate2 _cert = null!;

    [GlobalSetup]
    public void Setup()
    {
        _pdfBytes = PdfHelper.BuildMinimalPdf();
        _cert = TestCertificateFactory.CreateSelfSignedCert("CN=Bench Features");
    }

    [GlobalCleanup]
    public void Cleanup() => _cert.Dispose();

    [Benchmark(Baseline = true, Description = "Plain sign (PAdES-B-B)")]
    public async Task<byte[]> PlainSign()
    {
        return await SimpleSigner.Document(_pdfBytes)
            .WithCertificate(_cert)
            .SignAsync();
    }

    [Benchmark(Description = "Sign + visual appearance")]
    public async Task<byte[]> SignWithAppearance()
    {
        return await SimpleSigner.Document(_pdfBytes)
            .WithCertificate(_cert)
            .WithAppearance(SignatureAppearance.Auto())
            .SignAsync();
    }

    [Benchmark(Description = "Sign + metadata (name/reason/location)")]
    public async Task<byte[]> SignWithMetadata()
    {
        return await SimpleSigner.Document(_pdfBytes)
            .WithCertificate(_cert)
            .WithMetadata("Benchmark Signer", "Performance test", "Lab")
            .SignAsync();
    }

    [Benchmark(Description = "Sign + appearance + metadata")]
    public async Task<byte[]> SignWithAppearanceAndMetadata()
    {
        return await SimpleSigner.Document(_pdfBytes)
            .WithCertificate(_cert)
            .WithAppearance(SignatureAppearance.Auto())
            .WithMetadata("Benchmark Signer", "Performance test", "Lab")
            .SignAsync();
    }

    [Benchmark(Description = "Sign + certification (NoChanges)")]
    public async Task<byte[]> SignWithCertification()
    {
        return await SimpleSigner.Document(_pdfBytes)
            .WithCertificate(_cert)
            .AsCertification(CertificationLevel.NoChanges)
            .SignAsync();
    }

    [Benchmark(Description = "Sign + PDF/A preservation")]
    public async Task<byte[]> SignWithPdfA()
    {
        return await SimpleSigner.Document(_pdfBytes)
            .WithCertificate(_cert)
            .WithPdfAPreservation()
            .SignAsync();
    }
}

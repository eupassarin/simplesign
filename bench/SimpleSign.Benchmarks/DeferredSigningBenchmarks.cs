using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using BenchmarkDotNet.Attributes;
using SimpleSign.PAdES;

namespace SimpleSign.Benchmarks;

/// <summary>
/// Measures the two-phase deferred signing workflow: PrepareAsync (hash generation)
/// and CompleteAsync (CMS injection). Critical for HSM and remote signing scenarios
/// where Prepare and Complete happen on different machines.
/// </summary>
[MemoryDiagnoser]
public class DeferredSigningBenchmarks
{
    private byte[] _pdfBytes = null!;
    private X509Certificate2 _cert = null!;
    private RSA _rsa = null!;

    // Pre-computed for CompleteAsync benchmark
    private byte[] _sessionData = null!;
    private byte[] _signedHash = null!;

    [GlobalSetup]
    public async Task Setup()
    {
        _pdfBytes = PdfHelper.BuildMinimalPdf();
        _rsa = RSA.Create(2048);

        var req = new CertificateRequest("CN=Bench Deferred", _rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation, true));
        _cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(1));

        // Pre-compute a prepare result for the CompleteAsync-only benchmark
        var prepResult = await DeferredSigner.PrepareAsync(_pdfBytes, _cert);
        _sessionData = prepResult.SessionData;
        _signedHash = _rsa.SignData(prepResult.HashToSign, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    }

    [GlobalCleanup]
    public void Cleanup()
    {
        _cert.Dispose();
        _rsa.Dispose();
    }

    [Benchmark(Baseline = true, Description = "Direct sign (single-phase baseline)")]
    public async Task<byte[]> DirectSign()
    {
        return await SimpleSigner.Document(_pdfBytes)
            .WithCertificate(_cert)
            .SignAsync();
    }

    [Benchmark(Description = "Deferred: PrepareAsync only")]
    public async Task<byte[]> PrepareOnly()
    {
        var result = await DeferredSigner.PrepareAsync(_pdfBytes, _cert);
        return result.HashToSign;
    }

    [Benchmark(Description = "Deferred: CompleteAsync only")]
    public async Task<byte[]> CompleteOnly()
    {
        return await DeferredSigner.CompleteAsync(_sessionData, _signedHash);
    }

    [Benchmark(Description = "Deferred: full roundtrip (Prepare + sign + Complete)")]
    public async Task<byte[]> FullRoundtrip()
    {
        var prepResult = await DeferredSigner.PrepareAsync(_pdfBytes, _cert);
        var signedHash = _rsa.SignData(prepResult.HashToSign, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return await DeferredSigner.CompleteAsync(prepResult.SessionData, signedHash);
    }
}

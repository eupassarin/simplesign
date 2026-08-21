using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using BenchmarkDotNet.Attributes;
using SimpleSign.PAdES;

namespace SimpleSign.Benchmarks;

[MemoryDiagnoser]
[GroupBenchmarksBy(BenchmarkDotNet.Configs.BenchmarkLogicalGroupRule.ByCategory)]
public class PssBenchmarks
{
    private byte[] _pdfBytes = null!;
    private X509Certificate2 _rsaCert = null!;

    private const string RsaPssOid = "1.2.840.113549.1.1.10";

    [GlobalSetup]
    public void Setup()
    {
        _pdfBytes = PdfHelper.BuildMinimalPdf();

        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=Bench PSS", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation, true));
        _rsaCert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(1));
    }

    [GlobalCleanup]
    public void Cleanup() => _rsaCert.Dispose();

    [BenchmarkCategory("RSA"), Benchmark(Baseline = true, Description = "PKCS#1 v1.5 / SHA-256")]
    public async Task<byte[]> Pkcs1_Sha256()
    {
        return await PadesSigner.Document(_pdfBytes)
            .WithCertificate(_rsaCert)
            .WithHashAlgorithm(HashAlgorithmName.SHA256)
            .SignAsync();
    }

    [BenchmarkCategory("RSA"), Benchmark(Description = "PKCS#1 v1.5 / SHA-384")]
    public async Task<byte[]> Pkcs1_Sha384()
    {
        return await PadesSigner.Document(_pdfBytes)
            .WithCertificate(_rsaCert)
            .WithHashAlgorithm(HashAlgorithmName.SHA384)
            .SignAsync();
    }

    [BenchmarkCategory("RSA"), Benchmark(Description = "PKCS#1 v1.5 / SHA-512")]
    public async Task<byte[]> Pkcs1_Sha512()
    {
        return await PadesSigner.Document(_pdfBytes)
            .WithCertificate(_rsaCert)
            .WithHashAlgorithm(HashAlgorithmName.SHA512)
            .SignAsync();
    }

    [BenchmarkCategory("PSS"), Benchmark(Baseline = true, Description = "RSA-PSS PS256 (SHA-256)")]
    public async Task<byte[]> Pss_PS256()
    {
        return await PadesSigner.Document(_pdfBytes)
            .WithCertificate(_rsaCert)
            .WithSignatureAlgorithm(RsaPssOid)
            .WithHashAlgorithm(HashAlgorithmName.SHA256)
            .SignAsync();
    }

    [BenchmarkCategory("PSS"), Benchmark(Description = "RSA-PSS PS384 (SHA-384)")]
    public async Task<byte[]> Pss_PS384()
    {
        return await PadesSigner.Document(_pdfBytes)
            .WithCertificate(_rsaCert)
            .WithSignatureAlgorithm(RsaPssOid)
            .WithHashAlgorithm(HashAlgorithmName.SHA384)
            .SignAsync();
    }

    [BenchmarkCategory("PSS"), Benchmark(Description = "RSA-PSS PS512 (SHA-512)")]
    public async Task<byte[]> Pss_PS512()
    {
        return await PadesSigner.Document(_pdfBytes)
            .WithCertificate(_rsaCert)
            .WithSignatureAlgorithm(RsaPssOid)
            .WithHashAlgorithm(HashAlgorithmName.SHA512)
            .SignAsync();
    }
}

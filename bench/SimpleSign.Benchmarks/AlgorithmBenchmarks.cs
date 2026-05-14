using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using BenchmarkDotNet.Attributes;
using SimpleSign.PAdES;
using SimpleSign.TestHelpers;

namespace SimpleSign.Benchmarks;

/// <summary>
/// Measures signing performance across different key algorithms and hash functions.
/// Shows that ECDSA P-256 is significantly faster than RSA for equivalent security.
/// </summary>
[MemoryDiagnoser]
[GroupBenchmarksBy(BenchmarkDotNet.Configs.BenchmarkLogicalGroupRule.ByCategory)]
public class AlgorithmBenchmarks
{
    private byte[] _pdfBytes = null!;
    private X509Certificate2 _rsaCert2048 = null!;
    private X509Certificate2 _rsaCert4096 = null!;
    private X509Certificate2 _ecdsaP256Cert = null!;
    private X509Certificate2 _ecdsaP384Cert = null!;

    [GlobalSetup]
    public void Setup()
    {
        _pdfBytes = PdfHelper.BuildMinimalPdf();

        _rsaCert2048 = TestCertificateFactory.CreateSelfSignedCert("CN=Bench RSA-2048");

        using var rsa4096 = RSA.Create(4096);
        var req4096 = new CertificateRequest("CN=Bench RSA-4096", rsa4096, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req4096.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation, true));
        _rsaCert4096 = req4096.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(1));

        using var ecP256 = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var reqEc256 = new CertificateRequest("CN=Bench ECDSA-P256", ecP256, HashAlgorithmName.SHA256);
        reqEc256.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation, true));
        _ecdsaP256Cert = reqEc256.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(1));

        using var ecP384 = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        var reqEc384 = new CertificateRequest("CN=Bench ECDSA-P384", ecP384, HashAlgorithmName.SHA384);
        reqEc384.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation, true));
        _ecdsaP384Cert = reqEc384.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(1));
    }

    [GlobalCleanup]
    public void Cleanup()
    {
        _rsaCert2048.Dispose();
        _rsaCert4096.Dispose();
        _ecdsaP256Cert.Dispose();
        _ecdsaP384Cert.Dispose();
    }

    [BenchmarkCategory("PAdES"), Benchmark(Baseline = true, Description = "RSA-2048 / SHA-256")]
    public async Task<byte[]> PAdES_Rsa2048_Sha256()
    {
        return await SimpleSigner.Document(_pdfBytes)
            .WithCertificate(_rsaCert2048)
            .WithHashAlgorithm(HashAlgorithmName.SHA256)
            .SignAsync();
    }

    [BenchmarkCategory("PAdES"), Benchmark(Description = "RSA-4096 / SHA-256")]
    public async Task<byte[]> PAdES_Rsa4096_Sha256()
    {
        return await SimpleSigner.Document(_pdfBytes)
            .WithCertificate(_rsaCert4096)
            .WithHashAlgorithm(HashAlgorithmName.SHA256)
            .SignAsync();
    }

    [BenchmarkCategory("PAdES"), Benchmark(Description = "RSA-2048 / SHA-512")]
    public async Task<byte[]> PAdES_Rsa2048_Sha512()
    {
        return await SimpleSigner.Document(_pdfBytes)
            .WithCertificate(_rsaCert2048)
            .WithHashAlgorithm(HashAlgorithmName.SHA512)
            .SignAsync();
    }

    [BenchmarkCategory("PAdES"), Benchmark(Description = "ECDSA-P256 / SHA-256")]
    public async Task<byte[]> PAdES_EcdsaP256_Sha256()
    {
        return await SimpleSigner.Document(_pdfBytes)
            .WithCertificate(_ecdsaP256Cert)
            .WithHashAlgorithm(HashAlgorithmName.SHA256)
            .SignAsync();
    }

    [BenchmarkCategory("PAdES"), Benchmark(Description = "ECDSA-P384 / SHA-384")]
    public async Task<byte[]> PAdES_EcdsaP384_Sha384()
    {
        return await SimpleSigner.Document(_pdfBytes)
            .WithCertificate(_ecdsaP384Cert)
            .WithHashAlgorithm(HashAlgorithmName.SHA384)
            .SignAsync();
    }
}

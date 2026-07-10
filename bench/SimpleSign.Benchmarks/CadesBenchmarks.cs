using System.Security.Cryptography.X509Certificates;
using BenchmarkDotNet.Attributes;
using SimpleSign.CAdES;
using SimpleSign.Core.Validation;
using SimpleSign.TestHelpers;

namespace SimpleSign.Benchmarks;

[MemoryDiagnoser]
public class CadesBenchmarks
{
    private X509Certificate2 _cert = null!;
    private byte[] _data1KB = null!;
    private byte[] _data100KB = null!;
    private byte[] _detachedCms1KB = null!;
    private byte[] _envelopedCms1KB = null!;
    private CadesSignatureValidator _validator = null!;

    [GlobalSetup]
    public async Task Setup()
    {
        _cert = TestCertificateFactory.CreateSelfSignedCert("CN=Bench CAdES");
        _data1KB = new byte[1024];
        Random.Shared.NextBytes(_data1KB);
        _data100KB = new byte[100 * 1024];
        Random.Shared.NextBytes(_data100KB);

        _detachedCms1KB = await CadesSigner.Document(_data1KB)
            .WithCertificate(_cert)
            .SignAsync();
        _envelopedCms1KB = await CadesSigner.Document(_data1KB)
            .WithCertificate(_cert)
            .WithContentType(CadesContentType.Enveloped)
            .SignAsync();

        _validator = new CadesSignatureValidator(
            new ValidationOptions { CheckRevocation = false, TrustSystemRoots = false });
    }

    [GlobalCleanup]
    public void Cleanup() => _cert.Dispose();

    [Benchmark(Description = "Detached 1KB (sign)")]
    public async Task<byte[]> Sign_BasicDetached_1KB()
    {
        return await CadesSigner.Document(_data1KB)
            .WithCertificate(_cert)
            .SignAsync();
    }

    [Benchmark(Description = "Detached 100KB (sign)")]
    public async Task<byte[]> Sign_BasicDetached_100KB()
    {
        return await CadesSigner.Document(_data100KB)
            .WithCertificate(_cert)
            .SignAsync();
    }

    [Benchmark(Description = "Enveloped 1KB (sign)")]
    public async Task<byte[]> Sign_BasicEnveloped_1KB()
    {
        return await CadesSigner.Document(_data1KB)
            .WithCertificate(_cert)
            .WithContentType(CadesContentType.Enveloped)
            .SignAsync();
    }

    [Benchmark(Description = "Enveloped 100KB (sign)")]
    public async Task<byte[]> Sign_BasicEnveloped_100KB()
    {
        return await CadesSigner.Document(_data100KB)
            .WithCertificate(_cert)
            .WithContentType(CadesContentType.Enveloped)
            .SignAsync();
    }

    [Benchmark(Description = "Detached 1KB (validate)")]
    public CadesValidationResult Validate_Detached() =>
        _validator.Validate(_detachedCms1KB, _data1KB, [_cert]);

    [Benchmark(Description = "Enveloped 1KB (validate)")]
    public CadesValidationResult Validate_Enveloped() =>
        _validator.Validate(_envelopedCms1KB, _data1KB, [_cert]);
}

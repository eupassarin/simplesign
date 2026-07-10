using System.Security.Cryptography.X509Certificates;
using BenchmarkDotNet.Attributes;
using SimpleSign.Core.Validation;
using SimpleSign.TestHelpers;
using SimpleSign.XAdES;

namespace SimpleSign.Benchmarks;

[MemoryDiagnoser]
public class XadesBenchmarks
{
    private X509Certificate2 _cert = null!;
    private byte[] _xml1KB = null!;
    private byte[] _xml100KB = null!;
    private byte[] _envelopedSig = null!;
    private byte[] _detachedSig = null!;
    private XadesSignatureValidator _validator = null!;

    [GlobalSetup]
    public async Task Setup()
    {
        _cert = TestCertificateFactory.CreateSelfSignedCert("CN=Bench XAdES");

        _xml1KB = BuildXml(1024);
        _xml100KB = BuildXml(100 * 1024);

        _envelopedSig = await XadesSigner.Document(_xml1KB)
            .WithCertificate(_cert)
            .WithForm(XadesForm.Enveloped)
            .SignAsync();
        _detachedSig = await XadesSigner.Document(_xml1KB)
            .WithCertificate(_cert)
            .WithForm(XadesForm.Detached)
            .WithDataUri("doc.xml")
            .SignAsync();

        _validator = new XadesSignatureValidator(
            new ValidationOptions { CheckRevocation = false, TrustSystemRoots = false });
    }

    [GlobalCleanup]
    public void Cleanup() => _cert.Dispose();

    [Benchmark(Description = "Enveloped 1KB (sign)")]
    public async Task<byte[]> Sign_Enveloped_1KB()
    {
        return await XadesSigner.Document(_xml1KB)
            .WithCertificate(_cert)
            .WithForm(XadesForm.Enveloped)
            .SignAsync();
    }

    [Benchmark(Description = "Detached 1KB (sign)")]
    public async Task<byte[]> Sign_Detached_1KB()
    {
        return await XadesSigner.Document(_xml1KB)
            .WithCertificate(_cert)
            .WithForm(XadesForm.Detached)
            .WithDataUri("doc.xml")
            .SignAsync();
    }

    [Benchmark(Description = "Enveloping 1KB (sign)")]
    public async Task<byte[]> Sign_Enveloping_1KB()
    {
        return await XadesSigner.Document(_xml1KB)
            .WithCertificate(_cert)
            .WithForm(XadesForm.Enveloping)
            .SignAsync();
    }

    [Benchmark(Description = "Enveloped 100KB (sign)")]
    public async Task<byte[]> Sign_Enveloped_100KB()
    {
        return await XadesSigner.Document(_xml100KB)
            .WithCertificate(_cert)
            .WithForm(XadesForm.Enveloped)
            .SignAsync();
    }

    [Benchmark(Description = "Enveloped 1KB (validate)")]
    public XadesValidationResult Validate_Enveloped() =>
        _validator.Validate(_envelopedSig, trustAnchors: [_cert]);

    [Benchmark(Description = "Detached 1KB (validate)")]
    public XadesValidationResult Validate_Detached() =>
        _validator.Validate(_detachedSig, originalData: _xml1KB, trustAnchors: [_cert]);

    private static byte[] BuildXml(int size)
    {
        string xml = "<?xml version=\"1.0\"?><doc>" + new string('x', size) + "</doc>";
        return System.Text.Encoding.UTF8.GetBytes(xml);
    }
}

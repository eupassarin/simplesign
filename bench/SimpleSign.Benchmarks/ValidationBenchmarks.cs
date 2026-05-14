using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using BenchmarkDotNet.Attributes;
using SimpleSign.Core.Validation;
using SimpleSign.PAdES;
using SimpleSign.PAdES.Validation;

namespace SimpleSign.Benchmarks;

/// <summary>
/// Measures validation performance across all signature formats.
/// Validation is as common as signing in production (portals receiving signed docs).
/// </summary>
[MemoryDiagnoser]
public class ValidationBenchmarks
{
    private byte[] _signedPdf1Sig = null!;
    private byte[] _signedPdf5Sigs = null!;
    private byte[] _signedPdfWithChain = null!;

    private PdfSignatureValidator _pdfValidator = null!;
    private PdfSignatureValidator _pdfValidatorWithChain = null!;

    [GlobalSetup]
    public async Task Setup()
    {
        // Create root CA and end-entity cert
        using var rootKey = RSA.Create(2048);
        var rootReq = new CertificateRequest("CN=Bench Root CA", rootKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        rootReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        rootReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        using var rootCert = rootReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(5));

        using var intermediateKey = RSA.Create(2048);
        var intermediateReq = new CertificateRequest("CN=Bench Intermediate CA", intermediateKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        intermediateReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        intermediateReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        using var intermediateCert = intermediateReq.Create(rootCert, DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(3), [1, 2, 3]);
        using var intermediateWithKey = intermediateCert.CopyWithPrivateKey(intermediateKey);

        using var endKey = RSA.Create(2048);
        var endReq = new CertificateRequest("CN=Bench End Entity", endKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        endReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation, true));
        using var endCert = endReq.Create(intermediateWithKey, DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(1), [4, 5, 6]);
        using var endWithKey = endCert.CopyWithPrivateKey(endKey);

        // Create self-signed cert for simple tests
        using var simpleKey = RSA.Create(2048);
        var simpleReq = new CertificateRequest("CN=Bench Simple", simpleKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        simpleReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation, true));
        using var simpleCert = simpleReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(1));

        byte[] pdfBytes = PdfHelper.BuildMinimalPdf();

        // Sign PDF once
        _signedPdf1Sig = await SimpleSigner.Document(pdfBytes)
            .WithCertificate(simpleCert)
            .SignAsync();

        // Sign PDF 5 times (incremental signatures)
        byte[] multiSig = pdfBytes;
        for (int i = 0; i < 5; i++)
        {
            multiSig = await SimpleSigner.Document(multiSig)
                .WithCertificate(simpleCert)
                .SignAsync();
        }
        _signedPdf5Sigs = multiSig;

        // Sign with chain cert
        _signedPdfWithChain = await SimpleSigner.Document(pdfBytes)
            .WithCertificate(endWithKey)
            .SignAsync();

        // Validators with trusted roots (no revocation check for benchmarks)
        var opts = new ValidationOptions { CheckRevocation = false, TrustSystemRoots = false, TrustedRoots = [simpleCert] };
        var chainOpts = new ValidationOptions { CheckRevocation = false, TrustSystemRoots = false, TrustedRoots = [rootCert] };

        _pdfValidator = new PdfSignatureValidator(opts);
        _pdfValidatorWithChain = new PdfSignatureValidator(chainOpts);
    }

    [Benchmark(Description = "PAdES validate (1 signature)")]
    public async Task<int> Validate_SingleSignature()
    {
        using var stream = new MemoryStream(_signedPdf1Sig);
        var results = await _pdfValidator.ValidateAsync(stream);
        return results.Count;
    }

    [Benchmark(Description = "PAdES validate (5 signatures)")]
    public async Task<int> Validate_MultipleSignatures()
    {
        using var stream = new MemoryStream(_signedPdf5Sigs);
        var results = await _pdfValidator.ValidateAsync(stream);
        return results.Count;
    }

    [Benchmark(Description = "PAdES validate (chain: Root→Intermediate→End)")]
    public async Task<int> Validate_WithChainVerification()
    {
        using var stream = new MemoryStream(_signedPdfWithChain);
        var results = await _pdfValidatorWithChain.ValidateAsync(stream);
        return results.Count;
    }
}

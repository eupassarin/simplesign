using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using BenchmarkDotNet.Attributes;
using iText.Kernel.Pdf;
using iText.Signatures;
using Org.BouncyCastle.Security;
using SimpleSign.PAdES;

namespace SimpleSign.Benchmarks;

/// <summary>
/// Benchmarks comparing SimpleSign signing performance against iText 9 + BouncyCastle.
/// Uses the same PDF input and RSA-2048 certificate for fair comparison.
/// </summary>
[MemoryDiagnoser]
public class CompetitorBenchmarks
{
    private byte[] _pdfBytes = null!;
    private X509Certificate2 _simpleSignCert = null!;

    // iText wrapper types wrapping BouncyCastle objects
    private iText.Commons.Bouncycastle.Crypto.IPrivateKey _itextPrivateKey = null!;
    private iText.Commons.Bouncycastle.Cert.IX509Certificate[] _itextChain = null!;

    private RSA _rsa = null!;

    [GlobalSetup]
    public void Setup()
    {
        _pdfBytes = PdfHelper.BuildMinimalPdf();

        // Generate RSA-2048 key pair
        _rsa = RSA.Create(2048);

        var req = new CertificateRequest("CN=Bench Competitor", _rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation, true));
        _simpleSignCert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(1));

        // Convert .NET cert and key to BouncyCastle, then wrap in iText's BC types
        var bcCert = DotNetUtilities.FromX509Certificate(_simpleSignCert);
        var bcKeyPair = DotNetUtilities.GetKeyPair(_rsa);

        _itextPrivateKey = new iText.Bouncycastle.Crypto.PrivateKeyBC(bcKeyPair.Private);
        _itextChain = [new iText.Bouncycastle.X509.X509CertificateBC(bcCert)];
    }

    [GlobalCleanup]
    public void Cleanup()
    {
        _simpleSignCert.Dispose();
        _rsa.Dispose();
    }

    /// <summary>
    /// Baseline: SimpleSign's fluent API with a self-signed RSA-2048 cert.
    /// </summary>
    [Benchmark(Baseline = true, Description = "SimpleSign PAdES-B-B")]
    public async Task<byte[]> SimpleSignBaseline()
    {
        return await PadesSigner.Document(_pdfBytes)
            .WithCertificate(_simpleSignCert)
            .SignAsync();
    }

    /// <summary>
    /// Competitor: iText 9's PdfSigner backed by BouncyCastle.
    /// Uses the exact same RSA-2048 key and certificate as the SimpleSign baseline.
    /// </summary>
    [Benchmark(Description = "iText 9 + BouncyCastle PAdES-B-B")]
    public byte[] IText9Baseline()
    {
        using var reader = new PdfReader(new MemoryStream(_pdfBytes));
        using var output = new MemoryStream();
        var signer = new PdfSigner(reader, output, new StampingProperties().UseAppendMode());

        var signature = new PrivateKeySignature(_itextPrivateKey, "SHA-256");
        signer.SignDetached(signature, _itextChain, null, null, null, 0, PdfSigner.CryptoStandard.CMS);

        return output.ToArray();
    }
}

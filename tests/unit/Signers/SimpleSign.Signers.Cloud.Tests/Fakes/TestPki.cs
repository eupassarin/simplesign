using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace SimpleSign.Signers.Cloud.Tests.Fakes;

/// <summary>An RSA test CA with RSA and EC signer keys, standing in for a provider's HSM.</summary>
public sealed class TestPki : IDisposable
{
    public TestPki()
    {
        CaKey = RSA.Create(2048);
        var caRequest = new CertificateRequest("CN=Cloud Test CA, O=SimpleSign Tests", CaKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        caRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        caRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        // RFC 5280 §4.2.1.2: a CA certificate has a Subject Key Identifier (the default validation policy requires it).
        caRequest.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(caRequest.PublicKey, false));
        Ca = caRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(5));

        RsaKey = RSA.Create(2048);
        RsaCertificate = Issue(new CertificateRequest("CN=Cloud RSA Signer:12345678909, C=BR", RsaKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1), [0x21]);

        SecondRsaKey = RSA.Create(2048);
        SecondRsaCertificate = Issue(new CertificateRequest("CN=Cloud Second Signer, C=BR", SecondRsaKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1), [0x22]);

        EcKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        EcCertificate = Issue(new CertificateRequest("CN=Cloud EC Signer, C=BR", EcKey, HashAlgorithmName.SHA256), [0x23]);
    }

    public RSA CaKey { get; }

    public X509Certificate2 Ca { get; }

    public RSA RsaKey { get; }

    public X509Certificate2 RsaCertificate { get; }

    public RSA SecondRsaKey { get; }

    public X509Certificate2 SecondRsaCertificate { get; }

    public ECDsa EcKey { get; }

    public X509Certificate2 EcCertificate { get; }

    public void Dispose()
    {
        Ca.Dispose();
        RsaCertificate.Dispose();
        SecondRsaCertificate.Dispose();
        EcCertificate.Dispose();
        CaKey.Dispose();
        RsaKey.Dispose();
        SecondRsaKey.Dispose();
        EcKey.Dispose();
    }

    private X509Certificate2 Issue(CertificateRequest request, byte[] serial)
    {
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation, false));
        return request.Create(Ca.SubjectName, X509SignatureGenerator.CreateForRSA(CaKey, RSASignaturePadding.Pkcs1),
            DateTimeOffset.UtcNow.AddHours(-1), DateTimeOffset.UtcNow.AddYears(1), serial);
    }
}

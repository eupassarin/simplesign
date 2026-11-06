using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Shouldly;
using SimpleSign.TestHelpers;

namespace SimpleSign.Brazil.IcpBrasil.Tests;

/// <summary>
/// Unit tests for IcpBrasilChainValidator and LtvEmbedder.
/// No network calls — uses synthetic certificates.
/// </summary>
[Trait("Category", "Unit")]
public sealed class IcpBrasilChainValidatorTests
{
    private static X509Certificate2 CreateCertWithPolicy(string policyOid, string subject = "CN=Test ICP")
    {
        using RSA key = RSA.Create(2048);
        CertificateRequest certificateRequest = new CertificateRequest(subject, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        certificateRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: false));
        X509Extension item = BuildCertificatePoliciesExtension(policyOid);
        certificateRequest.CertificateExtensions.Add(item);
        X509Certificate2 x509Certificate = certificateRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1.0), DateTimeOffset.UtcNow.AddYears(1));
        return WithPersistedKey(x509Certificate);
    }

    private static X509Certificate2 WithPersistedKey(X509Certificate2 certificate)
    {
        byte[] pfx = certificate.Export(X509ContentType.Pfx, "test-export");
#if NET9_0_OR_GREATER
        return X509CertificateLoader.LoadPkcs12(pfx, "test-export");
#else
        return new X509Certificate2(pfx, "test-export");
#endif
    }

    private static X509Extension BuildCertificatePoliciesExtension(string policyOid)
    {
        byte[] array = IcpBrasilChainValidator.EncodeOid(policyOid);
        byte[] array2 = new byte[2 + array.Length];
        array2[0] = 48;
        array2[1] = (byte)array.Length;
        array.CopyTo(array2, 2);
        byte[] array3 = new byte[2 + array2.Length];
        array3[0] = 48;
        array3[1] = (byte)array2.Length;
        array2.CopyTo(array3, 2);
        return new X509Extension("2.5.29.32", array3, critical: false);
    }

    [Fact(DisplayName = "EncodeOid for SHA-256 produces correct DER")]
    public void EncodeOid_StandardOid_ReturnsCorrectDer()
    {
        byte[] array = IcpBrasilChainValidator.EncodeOid("2.16.840.1.101.3.4.2.1");
        array[0].ShouldBe((byte)6);
        array[1].ShouldBe((byte)9);
        array.Length.ShouldBe(11);
    }

    [Fact(DisplayName = "Encoded OID is found in cert extension")]
    public void EncodeOid_RoundTrip_OidFoundInEncodedData()
    {
        string text = "2.16.76.1.7.1.1.2.3";
        byte[] array = IcpBrasilChainValidator.EncodeOid(text);
        using X509Certificate2 x509Certificate = CreateCertWithPolicy(text);
        X509Extension? x509Extension = x509Certificate.Extensions["2.5.29.32"];
        x509Extension.ShouldNotBeNull();
        x509Extension!.RawData.AsSpan().IndexOf(array.AsSpan(2))
            .ShouldBeGreaterThanOrEqualTo(0);
    }

    [Fact(DisplayName = "Valid result with no errors returns IsValid true")]
    public void IcpBrasilValidationResult_ValidWithNoErrors_IsValidReturnsTrue()
    {
        IcpBrasilValidationResult icpBrasilValidationResult = new IcpBrasilValidationResult
        {
            IsChainValid = true,
            Errors = []
        };
        icpBrasilValidationResult.IsValid.ShouldBeTrue("");
    }

    [Fact(DisplayName = "Result with errors returns IsValid false")]
    public void IcpBrasilValidationResult_WithErrors_IsValidReturnsFalse()
    {
        IcpBrasilValidationResult icpBrasilValidationResult = new IcpBrasilValidationResult
        {
            IsChainValid = true,
            Errors = ["Certificate expired"]
        };
        icpBrasilValidationResult.IsValid.ShouldBeFalse("");
    }

    [Fact(DisplayName = "ValidateAsync with null certificate throws exception")]
    public async Task ValidateAsync_NullCertificate_ThrowsArgumentNullException()
    {
        IcpBrasilChainValidator validator = new IcpBrasilChainValidator();
        await Assert.ThrowsAsync<ArgumentNullException>(() => validator.ValidateAsync((X509Certificate2)null!));
    }

    [Fact(DisplayName = "Cert without ICP policy returns warning")]
    public async Task ValidateAsync_CertWithoutIcpPolicy_ReturnsWarning()
    {
        using HttpClient httpClient = new HttpClient(new MockHttpHandler(_ => Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound))));
        IcpBrasilChainValidator icpBrasilChainValidator = new IcpBrasilChainValidator(httpClient);
        using RSA rsa = RSA.Create(2048);
        CertificateRequest certificateRequest = new CertificateRequest("CN=NoPolicy", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using X509Certificate2 cert = certificateRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1.0), DateTimeOffset.UtcNow.AddYears(1));
        IcpBrasilValidationResult icpBrasilValidationResult = await icpBrasilChainValidator.ValidateAsync(cert);
        icpBrasilValidationResult.Warnings.ShouldContain(w => w.Contains("ICP-Brasil"), "");
    }

    [Fact(DisplayName = "ExtractCpfCnpj with null cert throws exception")]
    public void ExtractCpfCnpj_NullCert_ThrowsArgumentNullException() => Assert.Throws<ArgumentNullException>(() => IcpBrasilChainValidator.ExtractCpfCnpj(null!));

    [Fact(DisplayName = "Cert without SAN returns null CPF and CNPJ")]
    public void ExtractCpfCnpj_CertWithoutSan_ReturnsNulls()
    {
        using RSA key = RSA.Create(2048);
        CertificateRequest certificateRequest = new CertificateRequest("CN=NoSAN", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using X509Certificate2 certificate = certificateRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1.0), DateTimeOffset.UtcNow.AddYears(1));
        var (actualValue, actualValue2) = IcpBrasilChainValidator.ExtractCpfCnpj(certificate);
        actualValue.ShouldBeNull("");
        actualValue2.ShouldBeNull("");
    }

    [Fact(DisplayName = "Small RSA key produces size warning")]
    public async Task ValidateAsync_SmallRsaKey_ReturnsKeySizeWarning()
    {
        using HttpClient httpClient = new HttpClient(new MockHttpHandler(_ => Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound))));
        IcpBrasilChainValidator icpBrasilChainValidator = new IcpBrasilChainValidator(httpClient);
        using RSA rsa = RSA.Create(1024);
        CertificateRequest certificateRequest = new CertificateRequest("CN=SmallKey", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using X509Certificate2 cert = WithPersistedKey(certificateRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1.0), DateTimeOffset.UtcNow.AddYears(1)));
        (await icpBrasilChainValidator.ValidateAsync(cert)).Warnings.ShouldContain(w => w.Contains("1024") && w.Contains("2048"), "");
    }
}

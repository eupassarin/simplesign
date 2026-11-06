using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using Shouldly;
using SimpleSign.Core.Validation.Policy;
using Xunit;

namespace SimpleSign.Core.Tests.Validation.Policy;

[Trait("Category", "Unit")]
public sealed class ValidationPolicyTests : IDisposable
{
    private readonly string _directory = Directory.CreateTempSubdirectory("simplesign-policy-").FullName;

    [Fact]
    public void FromJson_RoundTrip_KeepsTheConstraints()
    {
        var policy = ValidationPolicy.Default with
        {
            Name = "INDECOPI",
            SigningCertificate = new SigningCertificateConstraints { KeyUsage = ConstraintLevel.Fail },
            Cryptographic = new CryptographicConstraints { MinimumRsaKeySize = 3072, DigestAlgorithms = [new("SHA512")] },
        };

        var read = ValidationPolicy.FromJson(policy.ToJson());

        read.Name.ShouldBe("INDECOPI");
        read.SigningCertificate.KeyUsage.ShouldBe(ConstraintLevel.Fail);
        read.Cryptographic.MinimumRsaKeySize.ShouldBe(3072);
        read.Cryptographic.DigestAlgorithms.ShouldHaveSingleItem().Name.ShouldBe("SHA512");
    }

    [Fact]
    public void FromJson_EnumAsString_IsRead()
    {
        var policy = ValidationPolicy.FromJson("""{ "signingCertificate": { "keyUsage": "fail" } }""");

        policy.SigningCertificate.KeyUsage.ShouldBe(ConstraintLevel.Fail);
        policy.Cryptographic.MinimumRsaKeySize.ShouldBe(2048);
    }

    [Fact]
    public void FromJson_NotJson_ThrowsInvalidDataException() =>
        Should.Throw<InvalidDataException>(() => ValidationPolicy.FromJson("{ not json"));

    [Fact]
    public void Load_File_ReadsThePolicy()
    {
        string path = Path.Combine(_directory, "policy.json");
        File.WriteAllText(path, """{ "name": "from file" }""");

        ValidationPolicy.Load(path).Name.ShouldBe("from file");
    }

    [Fact]
    public void LoadSigned_SignedByTrustedSigner_ReadsThePolicy()
    {
        using var signer = Signer();
        string path = Write("""{ "name": "signed" }""", signer);

        ValidationPolicy.LoadSigned(path, path + ".p7s", signer).Name.ShouldBe("signed");
    }

    [Fact]
    public void LoadSigned_WithSignedAttributes_ReadsThePolicy()
    {
        using var signer = Signer();
        string path = Write("""{ "name": "signed" }""", signer, signedAttributes: true);

        ValidationPolicy.LoadSigned(path, path + ".p7s", signer).Name.ShouldBe("signed");
    }

    [Fact]
    public void LoadSigned_WithSignedAttributesChanged_ThrowsCryptographicException()
    {
        using var signer = Signer();
        string path = Write("""{ "name": "signed" }""", signer, signedAttributes: true);
        File.WriteAllText(path, """{ "name": "tampered" }""");

        Should.Throw<CryptographicException>(() => ValidationPolicy.LoadSigned(path, path + ".p7s", signer));
    }

    [Fact]
    public void LoadSigned_ChangedAfterSigning_ThrowsCryptographicException()
    {
        using var signer = Signer();
        string path = Write("""{ "name": "signed" }""", signer);
        File.WriteAllText(path, """{ "name": "tampered" }""");

        Should.Throw<CryptographicException>(() => ValidationPolicy.LoadSigned(path, path + ".p7s", signer));
    }

    [Fact]
    public void LoadSigned_OtherSigner_ThrowsCryptographicException()
    {
        using var signer = Signer();
        using var other = Signer();
        string path = Write("""{ "name": "signed" }""", signer);

        Should.Throw<CryptographicException>(() => ValidationPolicy.LoadSigned(path, path + ".p7s", other));
    }

    public void Dispose() => Directory.Delete(_directory, recursive: true);

    private string Write(string json, X509Certificate2 signer, bool signedAttributes = false)
    {
        string path = Path.Combine(_directory, "policy.json");
        byte[] content = System.Text.Encoding.UTF8.GetBytes(json);
        File.WriteAllBytes(path, content);
        var cms = new SignedCms(new ContentInfo(content), detached: true);
        var cmsSigner = new CmsSigner(signer) { DigestAlgorithm = new Oid("2.16.840.1.101.3.4.2.1"), IncludeOption = X509IncludeOption.EndCertOnly };
        if (signedAttributes)
        {
            cmsSigner.SignedAttributes.Add(new Pkcs9SigningTime());
        }

        cms.ComputeSignature(cmsSigner);
        File.WriteAllBytes(path + ".p7s", cms.Encode());
        return path;
    }

    private static X509Certificate2 Signer()
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=Policy Administrator", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        return SimpleSign.Core.Crypto.CertificateLoader.LoadPkcs12(certificate.Export(X509ContentType.Pfx, "p"), "p");
    }
}

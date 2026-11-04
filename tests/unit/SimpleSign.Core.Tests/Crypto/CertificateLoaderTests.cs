using System.Security.Cryptography.X509Certificates;
using Shouldly;
using SimpleSign.Core.Crypto;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.Core.Tests.Crypto;

[Trait("Category", "Unit")]
public sealed class CertificateLoaderTests : IDisposable
{
    private const string Password = "pfx-test";
    private readonly string _directory = Directory.CreateTempSubdirectory("simplesign-loader-").FullName;

    public void Dispose() => Directory.Delete(_directory, recursive: true);

    [Fact]
    public void LoadSigningCredentialFromFile_PfxWithChain_ReturnsKeyedLeafAndChain()
    {
        var path = Path.Combine(_directory, "signer.pfx");
        var (ca, leaf) = TestCertificateFactory.WritePfxWithChain(path, Password);
        using (ca)
        using (leaf)
        {
            var (signer, chain) = CertificateLoader.LoadSigningCredentialFromFile(path, Password);
            using (signer)
            {
                signer.HasPrivateKey.ShouldBeTrue();
                signer.Thumbprint.ShouldBe(leaf.Thumbprint);
                chain.Count.ShouldBe(1);
                chain[0].Thumbprint.ShouldBe(ca.Thumbprint);
                chain[0].Dispose();
            }
        }
    }

    [Fact]
    public void LoadSigningCredentialFromFile_NoPrivateKey_ThrowsArgumentException()
    {
        var path = Path.Combine(_directory, "public-only.pfx");
        using var keyed = TestCertificateFactory.CreateCaCert();
        using var publicCert = CertificateLoader.LoadCertificate(keyed.RawData);
        File.WriteAllBytes(path, new X509Certificate2Collection(publicCert).Export(X509ContentType.Pkcs12, Password)!);

        var ex = Should.Throw<ArgumentException>(() => CertificateLoader.LoadSigningCredentialFromFile(path, Password));
        ex.Message.ShouldContain("private key");
    }
}

using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using Shouldly;
using SimpleSign.Core.Extensions;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.Core.Tests.Extensions;

[Trait("Category", "Unit")]
public sealed class DirectoryTrustAnchorProviderTests : IDisposable
{
    private readonly string _directory = Directory.CreateTempSubdirectory("simplesign-trust-").FullName;
    private readonly SyntheticPki _pki = new();

    [Fact]
    public void Constructor_DerAndPem_SplitsAnchorsAndIntermediates()
    {
        File.WriteAllBytes(Path.Combine(_directory, "root.cer"), _pki.RootCa.RawData);
        File.WriteAllText(Path.Combine(_directory, "intermediate.pem"), _pki.IntermediateCa.ExportCertificatePem());
        File.WriteAllText(Path.Combine(_directory, "notes.txt"), "ignored");

        var provider = new DirectoryTrustAnchorProvider(_directory);

        provider.GetTrustAnchors().ShouldHaveSingleItem().Thumbprint.ShouldBe(_pki.RootCa.Thumbprint);
        provider.GetIntermediateCertificates().ShouldHaveSingleItem().Thumbprint.ShouldBe(_pki.IntermediateCa.Thumbprint);
    }

    [Fact]
    public void Constructor_SignedManifestMatches_Loads()
    {
        using var admin = Admin();
        File.WriteAllBytes(Path.Combine(_directory, "root.cer"), _pki.RootCa.RawData);
        WriteManifest(admin, ("root.cer", _pki.RootCa.RawData));

        new DirectoryTrustAnchorProvider(_directory, admin).GetTrustAnchors().ShouldHaveSingleItem();
    }

    [Fact]
    public void Constructor_FileNotInManifest_ThrowsCryptographicException()
    {
        using var admin = Admin();
        File.WriteAllBytes(Path.Combine(_directory, "root.cer"), _pki.RootCa.RawData);
        WriteManifest(admin, ("root.cer", _pki.RootCa.RawData));
        File.WriteAllBytes(Path.Combine(_directory, "added.cer"), _pki.IntermediateCa.RawData);

        Should.Throw<CryptographicException>(() => new DirectoryTrustAnchorProvider(_directory, admin));
    }

    [Fact]
    public void Constructor_FileReplaced_ThrowsCryptographicException()
    {
        using var admin = Admin();
        WriteManifest(admin, ("root.cer", _pki.RootCa.RawData));
        File.WriteAllBytes(Path.Combine(_directory, "root.cer"), _pki.IntermediateCa.RawData);

        Should.Throw<CryptographicException>(() => new DirectoryTrustAnchorProvider(_directory, admin));
    }

    [Fact]
    public void Constructor_ManifestMissing_ThrowsCryptographicException()
    {
        using var admin = Admin();
        File.WriteAllBytes(Path.Combine(_directory, "root.cer"), _pki.RootCa.RawData);

        Should.Throw<CryptographicException>(() => new DirectoryTrustAnchorProvider(_directory, admin));
    }

    public void Dispose()
    {
        _pki.Dispose();
        Directory.Delete(_directory, recursive: true);
    }

    private void WriteManifest(X509Certificate2 admin, params (string Name, byte[] Bytes)[] files)
    {
        string json = "{ \"certificates\": { " + string.Join(", ", files.Select(f =>
            $"\"{f.Name}\": \"{Convert.ToHexString(SHA256.HashData(f.Bytes))}\"")) + " } }";
        byte[] content = System.Text.Encoding.UTF8.GetBytes(json);
        string path = Path.Combine(_directory, DirectoryTrustAnchorProvider.ManifestFileName);
        File.WriteAllBytes(path, content);
        var cms = new SignedCms(new ContentInfo(content), detached: true);
        cms.ComputeSignature(new CmsSigner(admin) { IncludeOption = X509IncludeOption.EndCertOnly });
        File.WriteAllBytes(path + ".p7s", cms.Encode());
    }

    private static X509Certificate2 Admin()
    {
        using var key = RSA.Create(2048);
        using var certificate = new CertificateRequest("CN=Trust Store Administrator", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            .CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        return SimpleSign.Core.Crypto.CertificateLoader.LoadPkcs12(certificate.Export(X509ContentType.Pfx, "p"), "p");
    }
}

using System.Security.Cryptography.X509Certificates;
using Shouldly;
using SimpleSign.Core.Signing;
using SimpleSign.Core.Validation;
using SimpleSign.PAdES.Validation;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.PAdES.Tests.Signing;

/// <summary>Tests for the <see cref="PadesSigner"/> entry points and one-call shortcuts.</summary>
[Trait("Category", "Unit")]
public sealed class PadesSignerTests : IDisposable
{
    private const string Password = "pfx-test";
    private readonly string _directory = Directory.CreateTempSubdirectory("simplesign-signer-").FullName;

    public void Dispose() => Directory.Delete(_directory, recursive: true);

    private string PathOf(string name) => Path.Combine(_directory, name);

    private static async Task<SignatureValidationResult> ValidateSingleAsync(string signedPath, X509Certificate2 trustedRoot)
    {
        var validator = new PdfSignatureValidator(new ValidationOptions
        {
            CheckRevocation = false,
            TrustedRoots = [trustedRoot],
        });
        await using var stream = File.OpenRead(signedPath);
        var results = await validator.ValidateAsync(stream);
        results.Count.ShouldBe(1);
        return results[0];
    }

    [Fact]
    public async Task SignFileAsync_PfxWithChain_WritesValidSignatureWithEmbeddedChain()
    {
        File.WriteAllBytes(PathOf("in.pdf"), TestPdfFactory.CreateMinimalPdf());
        var (ca, leaf) = TestCertificateFactory.WritePfxWithChain(PathOf("signer.pfx"), Password);
        using (ca)
        using (leaf)
        {
            await PadesSigner.SignFileAsync(PathOf("in.pdf"), PathOf("out.pdf"), PathOf("signer.pfx"), Password);

            var result = await ValidateSingleAsync(PathOf("out.pdf"), ca);
            result.IsIntegrityValid.ShouldBeTrue();
            result.IsSignatureValid.ShouldBeTrue();
            result.IsCertificateChainValid.ShouldBeTrue();
            result.SignerCertificate!.Thumbprint.ShouldBe(leaf.Thumbprint);
            result.EmbeddedCertificates.ShouldContain(c => c.Thumbprint == ca.Thumbprint);
        }
    }

    [Fact]
    public async Task SignFileAsync_OutputEqualsInput_OverwritesWithSignedPdf()
    {
        var path = PathOf("contract.pdf");
        var original = TestPdfFactory.CreateMinimalPdf();
        File.WriteAllBytes(path, original);
        var (ca, leaf) = TestCertificateFactory.WritePfxWithChain(PathOf("signer.pfx"), Password);
        using (ca)
        using (leaf)
        {
            await PadesSigner.SignFileAsync(path, path, PathOf("signer.pfx"), Password);

            new FileInfo(path).Length.ShouldBeGreaterThan(original.Length);
            (await ValidateSingleAsync(path, ca)).IsIntegrityValid.ShouldBeTrue();
        }
    }

    [Fact]
    public async Task SignFileAsync_ExplicitBasicLevel_Succeeds()
    {
        File.WriteAllBytes(PathOf("in.pdf"), TestPdfFactory.CreateMinimalPdf());
        var (ca, leaf) = TestCertificateFactory.WritePfxWithChain(PathOf("signer.pfx"), Password);
        using (ca)
        using (leaf)
        {
            await PadesSigner.SignFileAsync(
                PathOf("in.pdf"), PathOf("out.pdf"), PathOf("signer.pfx"), Password, AdesBaselineProfile.Basic());

            File.Exists(PathOf("out.pdf")).ShouldBeTrue();
        }
    }

    [Theory]
    [InlineData("", "out.pdf", "signer.pfx")]
    [InlineData("in.pdf", " ", "signer.pfx")]
    [InlineData("in.pdf", "out.pdf", "")]
    public async Task SignFileAsync_BlankPath_ThrowsArgumentException(string input, string output, string pfx) =>
        await Should.ThrowAsync<ArgumentException>(() => PadesSigner.SignFileAsync(input, output, pfx, Password));

    [Fact]
    public async Task SignFileAsync_WrongPassword_ThrowsCryptographicExceptionAndWritesNothing()
    {
        File.WriteAllBytes(PathOf("in.pdf"), TestPdfFactory.CreateMinimalPdf());
        var (ca, leaf) = TestCertificateFactory.WritePfxWithChain(PathOf("signer.pfx"), Password);
        ca.Dispose();
        leaf.Dispose();

        await Should.ThrowAsync<System.Security.Cryptography.CryptographicException>(
            () => PadesSigner.SignFileAsync(PathOf("in.pdf"), PathOf("out.pdf"), PathOf("signer.pfx"), "wrong"));
        File.Exists(PathOf("out.pdf")).ShouldBeFalse();
    }

    [Fact]
    public async Task WithCertificateFile_PfxWithChain_SignsWithLeafAndEmbedsChain()
    {
        var (ca, leaf) = TestCertificateFactory.WritePfxWithChain(PathOf("signer.pfx"), Password);
        using (ca)
        using (leaf)
        {
            var signed = await PadesSigner.Document(TestPdfFactory.CreateMinimalPdf())
                .WithCertificateFile(PathOf("signer.pfx"), Password)
                .SignAsync();
            File.WriteAllBytes(PathOf("out.pdf"), signed);

            var result = await ValidateSingleAsync(PathOf("out.pdf"), ca);
            result.IsSignatureValid.ShouldBeTrue();
            result.SignerCertificate!.Thumbprint.ShouldBe(leaf.Thumbprint);
            result.EmbeddedCertificates.ShouldContain(c => c.Thumbprint == ca.Thumbprint);
        }
    }

    [Fact]
    public void WithCertificateFile_BlankPath_ThrowsArgumentException() =>
        Should.Throw<ArgumentException>(
            () => PadesSigner.Document(TestPdfFactory.CreateMinimalPdf()).WithCertificateFile(" ", Password));
}

using System.Text;
using Shouldly;
using SimpleSign.CAdES;
using SimpleSign.Core.Validation;
using Xunit;
using Xunit.Abstractions;

namespace SimpleSign.Interop.Tests;

/// <summary>The other way round: CAdES that OpenSSL 3 writes (<c>openssl cms -sign -cades</c>), validated by <see cref="CadesSignatureValidator"/>.</summary>
[Trait("Category", "Interop")]
public sealed class CadesSignatureValidatorInteropTests(InteropPki pki, ITestOutputHelper output) : IClassFixture<InteropPki>
{
    private static readonly byte[] Content = Encoding.UTF8.GetBytes("SimpleSign interop: CAdES content\n");

    [SkippableTheory(DisplayName = "OpenSSL signs CAdES (RSA and ECDSA), SimpleSign validates it as valid and trusted")]
    [InlineData("rsa")]
    [InlineData("ecdsa")]
    public async Task ValidateAsync_SignedByOpenSsl_Passes(string key)
    {
        InteropTools.Require(InteropTool.OpenSsl);
        var (certificate, privateKey) = key == "rsa" ? (pki.LeafPem, pki.LeafKeyPem) : (pki.EcdsaPem, pki.EcdsaKeyPem);
        string content = pki.Write("content.txt", Content);
        string signature = Path.Combine(pki.Directory, $"{Guid.NewGuid():N}.p7s");

        // -cades adds the ESS signing-certificate-v2 attribute that makes the CMS a CAdES-B-B signature.
        var sign = await InteropTools.RunAsync(InteropTool.OpenSsl,
            "cms", "-sign", "-cades", "-binary", "-md", "sha256", "-in", content, "-signer", certificate, "-inkey", privateKey,
            "-certfile", pki.ChainPem, "-outform", "DER", "-out", signature);
        sign.ExitCode.ShouldBe(0, sign.Output);

        var validator = new CadesSignatureValidator(new ValidationOptions { CheckRevocation = false, TrustSystemRoots = false });
        var result = await validator.ValidateAsync(await File.ReadAllBytesAsync(signature), Content, [pki.Pki.RootCa]);
        string errors = string.Join("; ", result.Errors);
        output.WriteLine($"{result.Indication} {result.SubIndication}: {errors}");

        result.IsIntegrityValid.ShouldBeTrue(errors);
        result.IsSignatureValid.ShouldBeTrue(errors);
        result.IsCertificateChainValid.ShouldBeTrue(errors);
    }
}

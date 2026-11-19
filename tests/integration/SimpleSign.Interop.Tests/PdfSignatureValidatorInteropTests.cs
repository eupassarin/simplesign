using Shouldly;
using SimpleSign.Core.Validation;
using SimpleSign.PAdES;
using SimpleSign.PAdES.Validation;
using SimpleSign.TestHelpers;
using Xunit;
using Xunit.Abstractions;

namespace SimpleSign.Interop.Tests;

/// <summary>
/// The other way round: a PDF signed by pyHanko, validated by <see cref="PdfSignatureValidator"/>, then signed again
/// by SimpleSign, and both signatures validated by pyHanko and the file checked by qpdf.
/// </summary>
[Trait("Category", "Interop")]
public sealed class PdfSignatureValidatorInteropTests(OfflinePki pki, ITestOutputHelper output) : IClassFixture<OfflinePki>
{
    public static TheoryData<string> Sources => new("xref-table.pdf", "xref-stream.pdf");

    [SkippableTheory(DisplayName = "pyHanko signs, SimpleSign validates the signature as intact, valid and trusted")]
    [MemberData(nameof(Sources))]
    public async Task ValidateAsync_SignedByPyHanko_PassesAndTrusts(string source)
    {
        InteropTools.Require(InteropTool.PyHanko);
        byte[] signed = await PyHankoSignAsync(source);

        using var stream = new MemoryStream(signed);
        var results = await Validator().ValidateAsync(stream);

        var result = results.ShouldHaveSingleItem();
        output.WriteLine($"{result.Indication} {result.SubIndication}: {string.Join("; ", result.Errors)}");
        result.IsIntegrityValid.ShouldBeTrue();
        result.IsSignatureValid.ShouldBeTrue();
        result.IsCertificateChainValid.ShouldBeTrue(string.Join("; ", result.Errors));
    }

    [SkippableTheory(DisplayName = "pyHanko signs, SimpleSign signs again, pyHanko validates both and qpdf checks the file")]
    [MemberData(nameof(Sources))]
    public async Task SignAsync_AfterPyHankoSignature_BothValidInPyHankoAndQpdf(string source)
    {
        InteropTools.Require(InteropTool.PyHanko);
        InteropTools.Require(InteropTool.Qpdf);
        byte[] first = await PyHankoSignAsync(source);

        byte[] second = await PadesSigner.Document(first).WithCertificate(pki.Pki.Leaf, pki.Chain).WithHttpClientProvider(pki.Http).SignAsync();
        string path = pki.Write("second.pdf", second);

        var signatures = await InteropTools.PyHankoValidateAsync(path, pki.RootPem);
        foreach (var signature in signatures)
        {
            output.WriteLine($"{signature.Field}: {signature.Summary ?? signature.Error}, coverage {signature.Coverage}");
        }

        signatures.Count.ShouldBe(2);
        signatures.ShouldAllBe(s => s.Error == null && s.Intact && s.Valid && s.Trusted);
        signatures[0].Field.ShouldBe("PyHanko");
        signatures[0].Coverage.ShouldBe("ENTIRE_REVISION");
        signatures[1].Coverage.ShouldBe("ENTIRE_FILE");

        var check = await InteropTools.RunAsync(InteropTool.Qpdf, "--check", path);
        check.ExitCode.ShouldBe(0, check.Output);
    }

    private async Task<byte[]> PyHankoSignAsync(string source)
    {
        string input = Path.Combine(AppContext.BaseDirectory, "Fixtures", source);
        string signed = Path.Combine(pki.Directory, $"{Guid.NewGuid():N}-pyhanko.pdf");
        var run = await InteropTools.RunAsync(InteropTool.PyHanko, "sign", input, signed, pki.LeafKeyPem, pki.LeafPem, pki.ChainPem);
        run.ExitCode.ShouldBe(0, run.Output);
        return await File.ReadAllBytesAsync(signed);
    }

    /// <summary>Offline: no revocation, no system roots, only the test root.</summary>
    private PdfSignatureValidator Validator() => new(
        new ValidationOptions { CheckRevocation = false, TrustSystemRoots = false, TrustedRoots = [pki.Pki.RootCa] },
        MockHttpHandler.Failing());
}

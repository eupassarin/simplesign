using System.Text;
using Shouldly;
using SimpleSign.CAdES;
using SimpleSign.TestHelpers;
using Xunit;
using Xunit.Abstractions;

namespace SimpleSign.Interop.Tests;

/// <summary>
/// CMS that <see cref="CadesSigner"/> writes, verified by OpenSSL 3 (<c>openssl cms -verify</c>): the signature, the
/// signed attributes and the certificate chain up to the test root (S/MIME signing purpose, no <c>-noverify</c>).
/// </summary>
[Trait("Category", "Interop")]
public sealed class CadesSignerInteropTests(OfflinePki pki, ITestOutputHelper output) : IClassFixture<OfflinePki>
{
    private static readonly byte[] Content = Encoding.UTF8.GetBytes("SimpleSign interop: CAdES content\n");

    /// <summary>Detached and enveloped, RSA and ECDSA, B-B and B-T.</summary>
    public static TheoryData<CadesContentType, string, string> Cases
    {
        get
        {
            var data = new TheoryData<CadesContentType, string, string>();
            foreach (var packaging in new[] { CadesContentType.Detached, CadesContentType.Enveloped })
            {
                foreach (string key in new[] { "rsa", "ecdsa" })
                {
                    foreach (string level in new[] { "B", "T" })
                    {
                        data.Add(packaging, key, level);
                    }
                }
            }

            return data;
        }
    }

    [SkippableTheory(DisplayName = "OpenSSL verifies every CAdES signature SimpleSign writes, chain included")]
    [MemberData(nameof(Cases))]
    public async Task SignAsync_AnyPackaging_OpenSslVerifies(CadesContentType packaging, string key, string level)
    {
        InteropTools.Require(InteropTool.OpenSsl);
        var certificate = key == "rsa" ? pki.Pki.Leaf : pki.Ecdsa;

        byte[] cms = await CadesSigner.Document(Content).WithCertificate(certificate, pki.Chain)
            .WithContentType(packaging).WithHttpClientProvider(pki.Http).WithLevel(pki.Level(level)).SignAsync();

        var (run, extracted) = await VerifyAsync(cms, packaging == CadesContentType.Detached ? Content : null);
        output.WriteLine(run.Output);
        if (run.ExitCode != 0)
        {
            output.WriteLine($"Saved to {InteropTools.SaveRejected($"openssl-{packaging}-{key}-{level}.p7s", cms)}");
        }

        run.ExitCode.ShouldBe(0, run.Output);
        run.Stderr.ShouldContain("Verification successful");
        extracted.ShouldBe(Content);
    }

    /// <summary>The control: OpenSSL must reject a detached signature over other content.</summary>
    [SkippableFact(DisplayName = "OpenSSL rejects a detached CAdES signature over changed content")]
    public async Task SignAsync_ContentChanged_OpenSslRejects()
    {
        InteropTools.Require(InteropTool.OpenSsl);
        byte[] cms = await CadesSigner.Document(Content).WithCertificate(pki.Pki.Leaf, pki.Chain).WithContentType(CadesContentType.Detached).SignAsync();

        byte[] changed = [.. Content];
        changed[0] ^= 0x01;
        var (run, _) = await VerifyAsync(cms, changed);
        output.WriteLine(run.Output);

        run.ExitCode.ShouldNotBe(0);
    }

    /// <summary>
    /// <c>openssl cms -verify</c> with the test root as the only trust anchor; for an enveloped signature it also
    /// returns the content OpenSSL extracted (for a detached one, the content given back).
    /// </summary>
    private async Task<(ExternalProcessResult Run, byte[] Content)> VerifyAsync(byte[] cms, byte[]? detachedContent)
    {
        string signature = pki.Write("signature.p7s", cms);
        string extracted = Path.Combine(pki.Directory, $"{Guid.NewGuid():N}.out");
        List<string> args = ["cms", "-verify", "-binary", "-inform", "DER", "-in", signature, "-CAfile", pki.RootPem, "-out", extracted];
        if (detachedContent is not null)
        {
            args.AddRange(["-content", pki.Write("content.bin", detachedContent)]);
        }

        var run = await InteropTools.RunAsync(InteropTool.OpenSsl, [.. args]);
        return (run, File.Exists(extracted) ? await File.ReadAllBytesAsync(extracted) : []);
    }
}

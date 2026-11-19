using System.Text;
using Shouldly;
using SimpleSign.TestHelpers;
using SimpleSign.XAdES;
using Xunit;
using Xunit.Abstractions;

namespace SimpleSign.Interop.Tests;

/// <summary>
/// XML signatures that <see cref="XadesSigner"/> writes, verified by xmlsec1: every reference (the document, the
/// XAdES SignedProperties), the SignatureValue and the certificate chain up to the test root, which is its only
/// trusted certificate.
/// </summary>
[Trait("Category", "Interop")]
public sealed class XadesSignerInteropTests(OfflinePki pki, ITestOutputHelper output) : IClassFixture<OfflinePki>
{
    private const string DetachedUri = "document.xml";

    private static readonly byte[] Document = Encoding.UTF8.GetBytes(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<invoice id=\"42\"><amount currency=\"BRL\">100.00</amount></invoice>\n");

    /// <summary>Enveloped, enveloping and detached, RSA and ECDSA, B-B and B-T.</summary>
    public static TheoryData<XadesForm, string, string> Cases
    {
        get
        {
            var data = new TheoryData<XadesForm, string, string>();
            foreach (var form in new[] { XadesForm.Enveloped, XadesForm.Enveloping, XadesForm.Detached })
            {
                foreach (string key in new[] { "rsa", "ecdsa" })
                {
                    foreach (string level in new[] { "B", "T" })
                    {
                        data.Add(form, key, level);
                    }
                }
            }

            return data;
        }
    }

    [SkippableTheory(DisplayName = "xmlsec1 verifies every XAdES signature SimpleSign writes, chain included")]
    [MemberData(nameof(Cases))]
    public async Task SignAsync_AnyForm_Xmlsec1Verifies(XadesForm form, string key, string level)
    {
        InteropTools.Require(InteropTool.Xmlsec1);
        byte[] signed = await SignAsync(form, key == "rsa" ? pki.Pki.Leaf : pki.Ecdsa, level);

        var run = await VerifyAsync(signed, form == XadesForm.Detached ? Document : null);
        output.WriteLine(run.Output);
        if (run.ExitCode != 0)
        {
            output.WriteLine($"Saved to {InteropTools.SaveRejected($"xmlsec1-{form}-{key}-{level}.xml", signed)}");
        }

        run.ExitCode.ShouldBe(0, run.Output);
        run.Stderr.ShouldContain("OK");
    }

    /// <summary>The control: xmlsec1 must reject an enveloped signature whose document was changed.</summary>
    [SkippableFact(DisplayName = "xmlsec1 rejects an XAdES signature whose signed document was changed")]
    public async Task SignAsync_DocumentChanged_Xmlsec1Rejects()
    {
        InteropTools.Require(InteropTool.Xmlsec1);
        byte[] signed = await SignAsync(XadesForm.Enveloped, pki.Pki.Leaf, "B");

        string text = Encoding.UTF8.GetString(signed);
        text.ShouldContain("100.00");
        var run = await VerifyAsync(Encoding.UTF8.GetBytes(text.Replace("100.00", "900.00", StringComparison.Ordinal)), null);
        output.WriteLine(run.Output);

        run.ExitCode.ShouldNotBe(0);
    }

    private async Task<byte[]> SignAsync(XadesForm form, System.Security.Cryptography.X509Certificates.X509Certificate2 certificate, string level)
    {
        var signer = XadesSigner.Document(Document).WithCertificate(certificate, pki.Chain).WithForm(form)
            .WithHttpClientProvider(pki.Http).WithLevel(pki.Level(level));
        return await (form == XadesForm.Detached ? signer.WithDataUri(DetachedUri) : signer).SignAsync();
    }

    /// <summary>
    /// <c>xmlsec1 --verify</c> trusting only the test root. XAdES points at its SignedProperties (and an enveloping
    /// signature at its Object) by an <c>Id</c> attribute, which xmlsec1 only resolves when told which elements carry
    /// one. A detached document is mapped from its URI to a local file.
    /// </summary>
    private async Task<ExternalProcessResult> VerifyAsync(byte[] signed, byte[]? detachedDocument)
    {
        List<string> args =
        [
            "--verify",
            "--trusted-pem", pki.RootPem,
            "--untrusted-pem", pki.ChainPem,
            "--id-attr:Id", "http://uri.etsi.org/01903/v1.3.2#:SignedProperties",
            "--id-attr:Id", "http://www.w3.org/2000/09/xmldsig#:Object",
        ];
        if (detachedDocument is not null)
        {
            // xmlsec1 classes a relative URI as "remote"; --url-map serves it from the local file, so nothing is fetched.
            args.AddRange(["--enabled-reference-uris", "same-doc,remote", $"--url-map:{DetachedUri}", pki.Write("document.xml", detachedDocument)]);
        }

        args.Add(pki.Write("signed.xml", signed));
        return await InteropTools.RunAsync(InteropTool.Xmlsec1, [.. args]);
    }
}

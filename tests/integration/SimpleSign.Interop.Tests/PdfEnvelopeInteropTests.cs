using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Shouldly;
using SimpleSign.Core.Extensions;
using SimpleSign.PAdES;
using SimpleSign.PAdES.Envelope;
using SimpleSign.PAdES.Signing;
using SimpleSign.TestHelpers;
using Xunit;
using Xunit.Abstractions;

namespace SimpleSign.Interop.Tests;

/// <summary>
/// A signature envelope (ADR 0033) read by qpdf and pyHanko: the prepared document (empty signature fields with seed
/// values and locks, the associated manifest), and the same document signed field by field — the first signature
/// certifying with DocMDP P2 — on a classic cross-reference table and a cross-reference stream.
/// </summary>
[Trait("Category", "Interop")]
public sealed class PdfEnvelopeInteropTests(OfflinePki pki, ITestOutputHelper output) : IClassFixture<OfflinePki>
{
    public static TheoryData<string> Sources => new() { "xref-table.pdf", "xref-stream.pdf" };

    [SkippableTheory(DisplayName = "qpdf: a prepared envelope and each signed stage have a sound syntax and cross-reference chain")]
    [MemberData(nameof(Sources))]
    public async Task Envelope_EveryStage_PassesQpdfCheck(string source)
    {
        InteropTools.Require(InteropTool.Qpdf);
        foreach (var (stage, pdf) in await StagesAsync(source))
        {
            var check = await InteropTools.RunAsync(InteropTool.Qpdf, "--check", pki.Write($"{stage}.pdf", pdf));
            output.WriteLine($"{stage}: {check.Output}");
            check.ExitCode.ShouldBe(0, $"{stage}: {check.Output}");
            check.Stdout.ShouldContain("No syntax or stream encoding errors found");
        }
    }

    [SkippableTheory(DisplayName = "pyHanko: the envelope's signatures are intact, valid and trusted, the later ones allowed by the certification")]
    [MemberData(nameof(Sources))]
    public async Task Envelope_Signed_PyHankoValidates(string source)
    {
        InteropTools.Require(InteropTool.PyHanko);
        var (_, signed) = (await StagesAsync(source))[^1];

        var signatures = await InteropTools.PyHankoValidateAsync(pki.Write("envelope.pdf", signed), pki.RootPem);
        foreach (var s in signatures)
        {
            output.WriteLine($"{s.Field}: {s.Summary ?? s.Error}, coverage {s.Coverage}, modifications {s.ModificationLevel}, DocMDP ok {s.DocmdpOk}");
        }

        signatures.Select(s => s.Field).ShouldBe(["SimpleSign_1", "SimpleSign_2"]);
        signatures.ShouldAllBe(s => s.Error == null && s.Intact && s.Valid && s.Trusted && s.DocmdpOk != false);
        signatures[0].ModificationLevel.ShouldBeOneOf("FORM_FILLING", "LTA_UPDATES", "NONE");
        signatures[1].Coverage.ShouldBe("ENTIRE_FILE");
    }

    /// <summary>The prepared document, then signed by the first signer (certifying), then by the second.</summary>
    private async Task<List<(string Stage, byte[] Pdf)>> StagesAsync(string source)
    {
        byte[] pdf = File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "Fixtures", source));
        byte[] prepared = await PdfEnvelope.Prepare(pdf).WithCertification(CertificationLevel.FormFilling)
            .AddSigner(Signer("Leaf", pki.Pki.Leaf, 72))
            .AddSigner(Signer("Ecdsa", pki.Ecdsa, 200))
            .PrepareAsync();
        byte[] first = await PadesSigner.Document(prepared).WithCertificate(pki.Pki.Leaf, pki.Chain).WithHttpClientProvider(pki.Http)
            .WithEnvelopeField("SimpleSign_1").AsCertification(CertificationLevel.FormFilling).SignAsync();
        byte[] second = await PadesSigner.Document(first).WithCertificate(pki.Ecdsa, pki.Chain).WithHttpClientProvider(pki.Http)
            .WithEnvelopeField("SimpleSign_2").SignAsync();
        return [("prepared", prepared), ("first", first), ("second", second)];
    }

    private static EnvelopeSigner Signer(string name, X509Certificate2 certificate, float y) => new()
    {
        Name = name,
        Identifiers = [new EnvelopeIdentifier(SignerIdentifierTypes.CertificateSha256, Convert.ToHexString(SHA256.HashData(certificate.RawData)))],
        Placement = new EnvelopePlacement(1, 72, y, 200, 50),
    };
}

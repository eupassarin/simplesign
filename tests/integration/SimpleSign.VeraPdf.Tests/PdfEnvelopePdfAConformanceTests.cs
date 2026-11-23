using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SimpleSign.Core.Extensions;
using SimpleSign.PAdES;
using SimpleSign.PAdES.Envelope;
using SimpleSign.TestHelpers;
using Shouldly;
using Xunit;
using Xunit.Abstractions;

namespace SimpleSign.VeraPdf.Tests;

/// <summary>
/// A signature envelope (ADR 0033) in a PDF/A-2b or PDF/A-3b document of the veraPDF corpus, checked by veraPDF as
/// PDF/A-3b: the prepared document (its empty signature fields, the associated manifest with its relationship, media
/// type and dates, the XMP declaring part 3) and the same document once every field is signed.
/// </summary>
[Trait("Category", "VeraPdf")]
public sealed class PdfEnvelopePdfAConformanceTests(ITestOutputHelper output)
{
    private static readonly string CorpusDirectory = Path.Combine(AppContext.BaseDirectory, "Fixtures", "corpus");

    /// <summary>The PDF/A-2b and PDF/A-3b files of the corpus.</summary>
    public static TheoryData<string> Files
    {
        get
        {
            var data = new TheoryData<string>();
            foreach (string path in Directory.EnumerateFiles(CorpusDirectory, "PDF_A-*.pdf")
                .Where(p => Path.GetFileName(p).Split('-')[1] is "2b" or "3b").Order(StringComparer.Ordinal))
            {
                data.Add(Path.GetFileName(path));
            }

            return data;
        }
    }

    [SkippableTheory(DisplayName = "PDF/A: a prepared envelope, and the envelope signed, conform to PDF/A-3b")]
    [MemberData(nameof(Files))]
    public async Task Envelope_PreparedAndSigned_ConformsToPdfA3b(string file)
    {
        VeraPdf.Require();
        using var first = TestCertificateFactory.CreateSelfSignedCert("CN=veraPDF Envelope One");
        using var second = TestCertificateFactory.CreateSelfSignedCert("CN=veraPDF Envelope Two");
        byte[] prepared = await PdfEnvelope.Prepare(File.ReadAllBytes(Path.Combine(CorpusDirectory, file)))
            .AddSigner(Signer("One", first, 72))
            .AddSigner(Signer("Two", second, 140))
            .PrepareAsync();
        await AssertConformsAsync(prepared, $"prepared-{file}");

        byte[] signed = await PadesSigner.Document(prepared).WithCertificate(first).WithEnvelopeField("SimpleSign_1").SignAsync();
        signed = await PadesSigner.Document(signed).WithCertificate(second).WithEnvelopeField("SimpleSign_2").SignAsync();
        await AssertConformsAsync(signed, $"signed-{file}");
    }

    private async Task AssertConformsAsync(byte[] pdf, string name)
    {
        var report = await VeraPdf.ValidateAsync(pdf, "3b");
        output.WriteLine($"{name}: {report.Summary}");
        if (!report.IsCompliant)
        {
            output.WriteLine($"Saved to {VeraPdf.SaveFailure(Path.GetFileNameWithoutExtension(name), pdf, report)}");
        }

        report.IsCompliant.ShouldBeTrue(report.Summary);
    }

    private static EnvelopeSigner Signer(string name, X509Certificate2 certificate, float y) => new()
    {
        Name = name,
        Identifiers = [new EnvelopeIdentifier(SignerIdentifierTypes.CertificateSha256, Convert.ToHexString(SHA256.HashData(certificate.RawData)))],
        Placement = new EnvelopePlacement(1, 72, y, 180, 50),
    };
}

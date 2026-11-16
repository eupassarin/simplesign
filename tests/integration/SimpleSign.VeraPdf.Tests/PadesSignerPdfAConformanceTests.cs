using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Shouldly;
using SimpleSign.Core.Http;
using SimpleSign.Core.Signing;
using SimpleSign.PAdES;
using SimpleSign.PAdES.Signing;
using SimpleSign.TestHelpers;
using Xunit;
using Xunit.Abstractions;

namespace SimpleSign.VeraPdf.Tests;

/// <summary>
/// PDF/A preservation (ADR 0014), checked by veraPDF: documents of the veraPDF corpus that conform to PDF/A-1b,
/// 2b or 3b still conform once <see cref="PadesSigner"/> has signed them, at every level and with every kind of
/// incremental update it appends (signature, appearance and its embedded font, DSS, document timestamp).
/// </summary>
[Trait("Category", "VeraPdf")]
public sealed class PadesSignerPdfAConformanceTests(ITestOutputHelper output)
{
    private static readonly string CorpusDirectory = Path.Combine(AppContext.BaseDirectory, "Fixtures", "corpus");

    /// <summary>
    /// Files on which a visible signature breaks PDF/A today, and the clause it breaks. The appearance stream paints
    /// in DeviceRGB (<c>rg</c> in SignatureAppearanceRenderer), which ISO 19005-2/3 §6.2.4.3 allows only with an RGB
    /// OutputIntent or a DefaultRGB colour space; this file has neither. The test requires exactly that failure, so
    /// it fails (and the entry must go) once the appearance paints in a colour space the document allows.
    /// </summary>
    private static readonly Dictionary<string, string> KnownVisibleFailures = new(StringComparer.Ordinal)
    {
        ["PDF_A-3b-6-8-t02-pass-b.pdf"] = "6.2.4.3",
    };

    /// <summary>Every corpus file.</summary>
    public static TheoryData<string> AllFiles => Corpus(_ => true);

    /// <summary>
    /// The PDF/A-2 and PDF/A-3 files. PDF/A-1 predates PAdES: it forbids <c>ETSI.CAdES.detached</c>, so neither an
    /// invisible PAdES signature nor the B-T, B-LT and B-LTA levels apply to it.
    /// </summary>
    public static TheoryData<string> PadesFiles => Corpus(flavour => !flavour.StartsWith('1'));

    [SkippableTheory(DisplayName = "PDF/A: an invisible signature keeps the document conforming")]
    [MemberData(nameof(PadesFiles))]
    public async Task SignAsync_InvisibleSignature_PreservesConformance(string file)
    {
        VeraPdf.Require();
        string flavour = Flavour(file);
        using var certificate = TestCertificateFactory.CreateSelfSignedCert("CN=veraPDF Invisible");

        byte[] signed = await Signer(Load(file), certificate, flavour, visible: false).SignAsync();

        await AssertConformsAsync(signed, flavour, $"invisible-{file}");
    }

    [SkippableTheory(DisplayName = "PDF/A: a visible signature (appearance and embedded font) keeps the document conforming")]
    [MemberData(nameof(AllFiles))]
    public async Task SignAsync_VisibleSignature_PreservesConformance(string file)
    {
        VeraPdf.Require();
        string flavour = Flavour(file);
        using var certificate = TestCertificateFactory.CreateSelfSignedCert("CN=veraPDF Visible");

        byte[] signed = await Signer(Load(file), certificate, flavour, visible: true).SignAsync();

        await AssertConformsAsync(signed, flavour, $"visible-{file}", KnownVisibleFailures.GetValueOrDefault(file));
    }

    [SkippableTheory(DisplayName = "PDF/A: a second signature keeps the document conforming")]
    [MemberData(nameof(AllFiles))]
    public async Task SignAsync_SecondSignature_PreservesConformance(string file)
    {
        VeraPdf.Require();
        string flavour = Flavour(file);
        using var first = TestCertificateFactory.CreateSelfSignedCert("CN=veraPDF First");
        using var second = TestCertificateFactory.CreateSelfSignedCert("CN=veraPDF Second");

        byte[] once = await Signer(Load(file), first, flavour, visible: true).SignAsync();
        byte[] twice = await Signer(once, second, flavour, visible: true).SignAsync();

        await AssertConformsAsync(twice, flavour, $"twice-{file}", KnownVisibleFailures.GetValueOrDefault(file));
    }

    [SkippableTheory(DisplayName = "PDF/A: B-LTA (signature timestamp, DSS, document timestamp) keeps the document conforming")]
    [MemberData(nameof(PadesFiles))]
    public async Task SignAsync_ArchiveLevel_PreservesConformance(string file)
    {
        VeraPdf.Require();
        string flavour = Flavour(file);
        using var pki = new SyntheticPki(crlDistributionPoint: LeafCrlUrl, intermediateCrlDistributionPoint: IntermediateCrlUrl);
        using var http = OfflineServices(pki);
        var provider = new SingleClientProvider(http);

        var result = await Signer(Load(file), pki.Leaf, flavour, visible: false, pki.IntermediatesAndRoot())
            .WithHttpClientProvider(provider)
            .WithLevel(AdesBaselineProfile.Archive(new TimestampOptions(TsaUri, provider), new LongTermValidationOptions(provider)))
            .SignWithDetailsAsync();

        result.AchievedLevel.ShouldBe(AdesBaselineLevel.Archive);
        await AssertConformsAsync(result.SignedArtifact, flavour, $"archive-{file}");
    }

    /// <summary>
    /// The control: the same check fails when SimpleSign's output breaks a rule it is meant to follow. With the
    /// widget's Print flag cleared (<c>/F 132</c> → <c>/F 128</c>, same length, so the offsets stay right) the
    /// document breaks ISO 19005-3 §6.3.2, and veraPDF must say so.
    /// </summary>
    [SkippableFact(DisplayName = "PDF/A: veraPDF rejects a signature widget without the Print flag")]
    public async Task SignAsync_WidgetWithoutPrintFlag_FailsConformance()
    {
        VeraPdf.Require();
        const string file = "PDF_A-3b-6-8-t02-pass-a.pdf";
        using var certificate = TestCertificateFactory.CreateSelfSignedCert("CN=veraPDF Control");
        byte[] signed = await Signer(Load(file), certificate, "3b", visible: true).SignAsync();

        byte[] broken = ReplaceOnce(signed, "/F 132", "/F 128");
        var report = await VeraPdf.ValidateAsync(broken, "3b");
        output.WriteLine(report.Summary);

        report.Error.ShouldBeNull();
        report.IsCompliant.ShouldBeFalse();
        report.FailedRules.ShouldContain(rule => rule.Clause == "6.3.2", report.Summary);
    }

    private const string LeafCrlUrl = "http://198.51.100.1/leaf.crl";
    private const string IntermediateCrlUrl = "http://198.51.100.1/intermediate.crl";
    private static readonly Uri TsaUri = new("http://tsa.example.test/");

    /// <summary>
    /// The signer of ADR 0014 for <paramref name="flavour"/>. PDF/A-1 needs <c>adbe.pkcs7.detached</c> and a visible
    /// appearance (an <c>/AP</c> on the widget, ISO 19005-1 §6.9).
    /// </summary>
    private static PadesSignerBuilder Signer(byte[] pdf, X509Certificate2 certificate, string flavour, bool visible, X509Certificate2[]? chain = null)
    {
        var builder = PadesSigner.Document(pdf).WithPdfAPreservation();
        builder = chain is null ? builder.WithCertificate(certificate) : builder.WithCertificate(certificate, chain);
        if (flavour.StartsWith('1'))
        {
            builder = builder.WithSubFilter(PdfSignatureSubFilter.AdbePkcs7Detached);
            visible = true;
        }

        return visible ? builder.WithAppearance(SignatureAppearance.Auto()) : builder;
    }

    /// <summary>The TSA and the CRLs of <paramref name="pki"/>, answered in memory.</summary>
    private static HttpClient OfflineServices(SyntheticPki pki)
    {
        byte[] leafCrl = pki.BuildLeafCrl();
        byte[] intermediateCrl = pki.BuildIntermediateCrl();
        return new HttpClient(new MockHttpHandler(async request =>
        {
            if (request.Method == HttpMethod.Post)
            {
                byte[] query = await request.Content!.ReadAsByteArrayAsync();
                var reply = new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(TimestampTestResponseBuilder.CreateForRequest(query)) };
                reply.Content.Headers.ContentType = new MediaTypeHeaderValue("application/timestamp-reply");
                return reply;
            }

            byte[]? crl = request.RequestUri?.ToString() switch
            {
                LeafCrlUrl => leafCrl,
                IntermediateCrlUrl => intermediateCrl,
                _ => null,
            };
            return crl is null
                ? new HttpResponseMessage(HttpStatusCode.NotFound)
                : new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(crl) };
        }));
    }

    /// <summary>
    /// Requires veraPDF to find <paramref name="pdf"/> conforming; with <paramref name="knownFailure"/>, to find it
    /// breaking that clause and no other (a known defect, kept visible instead of skipped).
    /// </summary>
    private async Task AssertConformsAsync(byte[] pdf, string flavour, string name, string? knownFailure = null)
    {
        var report = await VeraPdf.ValidateAsync(pdf, flavour);
        output.WriteLine(report.Summary);
        if (knownFailure is not null)
        {
            report.Error.ShouldBeNull();
            report.IsCompliant.ShouldBeFalse($"{name} now conforms: remove it from {nameof(KnownVisibleFailures)}.");
            report.FailedRules.Select(rule => rule.Clause).Distinct().ShouldBe([knownFailure], report.Summary);
            return;
        }

        if (!report.IsCompliant)
        {
            output.WriteLine($"Saved to {VeraPdf.SaveFailure(Path.GetFileNameWithoutExtension(name), pdf, report)}");
        }

        report.IsCompliant.ShouldBeTrue(report.Summary);
    }

    private static TheoryData<string> Corpus(Func<string, bool> flavours)
    {
        var data = new TheoryData<string>();
        foreach (string path in Directory.EnumerateFiles(CorpusDirectory, "*.pdf").Order(StringComparer.Ordinal))
        {
            string file = Path.GetFileName(path);
            if (flavours(Flavour(file)))
            {
                data.Add(file);
            }
        }

        return data;
    }

    /// <summary>The flavour of a corpus file, from its name: <c>PDF_A-2b-6-1-2-t02-pass-a.pdf</c> → <c>2b</c>.</summary>
    private static string Flavour(string file) => file.Split('-')[1];

    private static byte[] Load(string file) => File.ReadAllBytes(Path.Combine(CorpusDirectory, file));

    private static byte[] ReplaceOnce(byte[] pdf, string find, string replacement)
    {
        string text = Encoding.Latin1.GetString(pdf);
        int at = text.IndexOf(find, StringComparison.Ordinal);
        at.ShouldBeGreaterThanOrEqualTo(0, $"{find} not found");
        text.IndexOf(find, at + 1, StringComparison.Ordinal).ShouldBe(-1, $"{find} found more than once");
        return Encoding.Latin1.GetBytes(string.Concat(text.AsSpan(0, at), replacement, text.AsSpan(at + find.Length)));
    }
}

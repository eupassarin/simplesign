using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using SimpleSign.CAdES;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Signing;
using SimpleSign.PAdES;
using SimpleSign.PAdES.Signing;
using SimpleSign.TestHelpers;
using SimpleSign.XAdES;
using Xunit;

namespace SimpleSign.EtsiChecker.Tests;

/// <summary>The engines of the ETSI checker that SimpleSign's signatures go to.</summary>
public enum EtsiFormat
{
    /// <summary>PAdES, EN 319 142-1: a <c>.pdf</c>.</summary>
    Pades,

    /// <summary>CAdES, EN 319 122-1: a <c>.p7m</c> (the only extension the checker takes).</summary>
    Cades,

    /// <summary>XAdES, EN 319 132-1: a <c>.xml</c>.</summary>
    Xades,
}

/// <summary>One signature SimpleSign makes, as the checker receives it.</summary>
/// <param name="Id">The name of the sample, of its file and of its evidence folder (<c>pades-b-lta</c>).</param>
/// <param name="Format">The checker engine that reads it.</param>
/// <param name="Level">The baseline level SimpleSign claims for it.</param>
/// <param name="Description">How it was made, for the summary.</param>
/// <param name="Sign">Makes it with the offline PKI.</param>
/// <param name="IsBaseline">
/// Whether it is a baseline signature at all. A PAdES signature with another SubFilter than ETSI.CAdES.detached is
/// not: it holds what <paramref name="Level"/> requires, SimpleSign reports it as not baseline, and the checker must
/// fail it (<c>known-issues.json</c> lists the failure).
/// </param>
/// <param name="Signatures">
/// How many signatures it holds, made by signers: PDF signatures (document time-stamps aside), CMS SignerInfos,
/// XML signatures (counter-signatures aside, which sit under the signature they sign).
/// </param>
public sealed record EtsiSample(
    string Id, EtsiFormat Format, AdesBaselineLevel Level, string Description, Func<OfflinePki, Task<byte[]>> Sign, bool IsBaseline = true,
    int Signatures = 1)
{
    /// <summary>The file name the checker receives; it accepts only these extensions.</summary>
    public string FileName => Id + Format switch
    {
        EtsiFormat.Pades => ".pdf",
        EtsiFormat.Cades => ".p7m",
        _ => ".xml",
    };

    /// <summary>The engine's name in the checker's API (<c>sig</c>).</summary>
    public string Engine => Format.ToString().ToLowerInvariant();

    /// <inheritdoc/>
    public override string ToString() => Id;
}

/// <summary>
/// What goes to the ETSI checker: every level of each format and the ways of reaching it that write different
/// structures (another key or padding, another subfilter, a visible or certifying signature, a second signature, a
/// counter-signature, an augmentation, an archive renewal, a two-phase signature), all made offline by
/// <see cref="OfflinePki"/>. No detached CAdES or XAdES: the checker takes one file and has nowhere to put the
/// content, so it reports the message digest as wrong.
/// </summary>
public static class EtsiCorpus
{
    private static readonly byte[] SessionKey = RandomNumberGenerator.GetBytes(32);

    private static readonly byte[] Content = Encoding.UTF8.GetBytes("SimpleSign: content signed for the ETSI conformance checker.\n");

    private static readonly byte[] Xml = Encoding.UTF8.GetBytes(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<invoice id=\"42\"><amount currency=\"EUR\">100.00</amount></invoice>\n");

    /// <summary>Every sample, in the order of the summary.</summary>
    public static IReadOnlyList<EtsiSample> Samples { get; } =
    [
        // ── PAdES ──────────────────────────────────────────────────────────
        Pades("pades-b-b", AdesBaselineLevel.Basic, "RSA, ETSI.CAdES.detached", (pki, s) => s.SignAsync()),
        Pades("pades-b-t", AdesBaselineLevel.Timestamped, "RSA", (pki, s) => s.WithLevel(pki.Level("T")).SignAsync()),
        Pades("pades-b-lt", AdesBaselineLevel.LongTerm, "RSA, DSS with CRLs", (pki, s) => s.WithLevel(pki.Level("LT")).SignAsync()),
        Pades("pades-b-lta", AdesBaselineLevel.Archive, "RSA, DSS and a document time-stamp", (pki, s) => s.WithLevel(pki.Level("LTA")).SignAsync()),
        Pades("pades-b-t-adbe", AdesBaselineLevel.Timestamped, "SubFilter adbe.pkcs7.detached: B-T content, not baseline",
            (pki, s) => s.WithSubFilter(PdfSignatureSubFilter.AdbePkcs7Detached).WithLevel(pki.Level("T")).SignAsync()) with { IsBaseline = false },
        Pades("pades-b-t-ecdsa", AdesBaselineLevel.Timestamped, "ECDSA P-256",
            (pki, s) => Pdf(pki).WithCertificate(pki.Ecdsa, pki.Chain).WithHttpClientProvider(pki.Http).WithLevel(pki.Level("T")).SignAsync()),
        Pades("pades-b-t-rsapss", AdesBaselineLevel.Timestamped, "RSASSA-PSS",
            (pki, s) => s.WithSignatureAlgorithm(Oids.RsaPss).WithLevel(pki.Level("T")).SignAsync()),
        Pades("pades-b-b-visible", AdesBaselineLevel.Basic, "visible appearance",
            (pki, s) => s.WithAppearance(SignatureAppearance.Auto()).SignAsync()),
        Pades("pades-b-t-certified", AdesBaselineLevel.Timestamped, "certification (DocMDP P=2)",
            (pki, s) => s.AsCertification(CertificationLevel.FormFilling).WithLevel(pki.Level("T")).SignAsync()),
        Pades("pades-b-t-two-signatures", AdesBaselineLevel.Timestamped, "RSA then ECDSA, each B-T",
            async (pki, s) => await AddPdfSignatureAsync(pki, pki.Ecdsa, "T", await s.WithLevel(pki.Level("T")).SignAsync())) with { Signatures = 2 },
        Pades("pades-b-lta-augmented", AdesBaselineLevel.Archive, "B-B raised to B-LTA by PadesAugmenter",
            async (pki, s) => (await PadesAugmenter.Document(await s.SignAsync()).ToLevel(AdesBaselineLevel.Archive)
                .WithTimestamp(pki.Timestamp).WithHttpClientProvider(pki.Http).AugmentAsync()).Document),
        Pades("pades-b-lta-renewed", AdesBaselineLevel.Archive, "B-LTA with its archive renewed",
            async (pki, s) => (await PadesAugmenter.Document(await s.WithLevel(pki.Level("LTA")).SignAsync()).RenewArchive()
                .WithTimestamp(pki.Timestamp).WithHttpClientProvider(pki.Http).AugmentAsync()).Document),
        Pades("pades-b-t-deferred", AdesBaselineLevel.Timestamped, "two-phase (DeferredSigner)", (pki, _) => PadesDeferredAsync(pki)),

        // Several signatures in one PDF: each in its own incremental update, none breaking the ones before.
        Pades("pades-b-t-three-signatures", AdesBaselineLevel.Timestamped, "RSA, ECDSA, RSA, each B-T",
            async (pki, s) => await AddPdfSignatureAsync(pki, pki.Pki.Leaf, "T",
                await AddPdfSignatureAsync(pki, pki.Ecdsa, "T", await s.WithLevel(pki.Level("T")).SignAsync()))) with { Signatures = 3 },
        Pades("pades-b-t-certified-then-signed", AdesBaselineLevel.Timestamped, "certified (DocMDP P=2), then signed (ECDSA), each B-T",
            async (pki, s) => await AddPdfSignatureAsync(pki, pki.Ecdsa, "T",
                await s.AsCertification(CertificationLevel.FormFilling).WithLevel(pki.Level("T")).SignAsync())) with { Signatures = 2 },
        Pades("pades-b-lta-two-signatures", AdesBaselineLevel.Archive, "RSA and ECDSA B-T, then raised together to B-LTA",
            async (pki, s) => (await PadesAugmenter.Document(await AddPdfSignatureAsync(pki, pki.Ecdsa, "T", await s.WithLevel(pki.Level("T")).SignAsync()))
                .ToLevel(AdesBaselineLevel.Archive).WithTimestamp(pki.Timestamp).WithHttpClientProvider(pki.Http).AugmentAsync()).Document) with { Signatures = 2 },
        Pades("pades-b-lta-signed-twice", AdesBaselineLevel.Archive, "B-LTA (RSA), then another B-LTA (ECDSA) over it",
            async (pki, s) => await AddPdfSignatureAsync(pki, pki.Ecdsa, "LTA", await s.WithLevel(pki.Level("LTA")).SignAsync())) with { Signatures = 2 },

        // ── CAdES ──────────────────────────────────────────────────────────
        Cades("cades-b-b", AdesBaselineLevel.Basic, "RSA, enveloping", (pki, s) => s.SignAsync()),
        Cades("cades-b-t", AdesBaselineLevel.Timestamped, "RSA, enveloping", (pki, s) => s.WithLevel(pki.Level("T")).SignAsync()),
        Cades("cades-b-lt", AdesBaselineLevel.LongTerm, "RSA, enveloping, CRLs in the root validation data",
            (pki, s) => s.WithLevel(pki.Level("LT")).SignAsync()),
        Cades("cades-b-lta", AdesBaselineLevel.Archive, "RSA, enveloping, archiveTimestampV3 + ATSHashIndexV3",
            (pki, s) => s.WithLevel(pki.Level("LTA")).SignAsync()),
        Cades("cades-b-t-ecdsa", AdesBaselineLevel.Timestamped, "ECDSA P-256",
            (pki, s) => CadesSigner.Document(Content).WithCertificate(pki.Ecdsa, pki.Chain).WithContentType(CadesContentType.Enveloped)
                .WithHttpClientProvider(pki.Http).WithLevel(pki.Level("T")).SignAsync()),
        Cades("cades-b-t-rsapss", AdesBaselineLevel.Timestamped, "RSASSA-PSS",
            (pki, s) => s.WithSignatureAlgorithm(Oids.RsaPss).WithLevel(pki.Level("T")).SignAsync()),
        Cades("cades-b-t-countersigned", AdesBaselineLevel.Timestamped, "B-T counter-signed (ECDSA)",
            async (pki, s) => await CadesSigner.CounterSign(await s.WithLevel(pki.Level("T")).SignAsync())
                .WithCertificate(pki.Ecdsa, pki.Chain).WithHttpClientProvider(pki.Http).SignAsync()),
        Cades("cades-b-lta-augmented", AdesBaselineLevel.Archive, "B-B raised to B-LTA by CadesAugmenter",
            async (pki, s) => (await CadesAugmenter.Signature(await s.SignAsync()).ToLevel(AdesBaselineLevel.Archive)
                .WithTimestamp(pki.Timestamp).WithHttpClientProvider(pki.Http).AugmentAsync()).Signature),
        Cades("cades-b-lta-renewed", AdesBaselineLevel.Archive, "B-LTA with its archive renewed",
            async (pki, s) => (await CadesAugmenter.Signature(await s.WithLevel(pki.Level("LTA")).SignAsync()).RenewArchive()
                .WithTimestamp(pki.Timestamp).WithHttpClientProvider(pki.Http).AugmentAsync()).Signature),
        Cades("cades-b-t-deferred", AdesBaselineLevel.Timestamped, "two-phase (CadesDeferredSigner)", (pki, _) => CadesDeferredAsync(pki)),
        Cades("cades-b-t-cosigned", AdesBaselineLevel.Timestamped, "RSA, co-signed by ECDSA (two SignerInfos), each B-T",
            async (pki, s) => await CadesSigner.CoSign(await s.WithLevel(pki.Level("T")).SignAsync())
                .WithCertificate(pki.Ecdsa, pki.Chain).WithHttpClientProvider(pki.Http).WithLevel(pki.Level("T")).SignAsync()) with { Signatures = 2 },
        Cades("cades-b-lta-cosigned", AdesBaselineLevel.Archive, "RSA B-LTA, co-signed by ECDSA B-LTA",
            async (pki, s) => await CadesSigner.CoSign(await s.WithLevel(pki.Level("LTA")).SignAsync())
                .WithCertificate(pki.Ecdsa, pki.Chain).WithHttpClientProvider(pki.Http).WithLevel(pki.Level("LTA")).SignAsync()) with { Signatures = 2 },

        // ── XAdES ──────────────────────────────────────────────────────────
        Xades("xades-b-b-enveloped", AdesBaselineLevel.Basic, "RSA, enveloped", (pki, s) => s.SignAsync()),
        Xades("xades-b-b-enveloping", AdesBaselineLevel.Basic, "RSA, enveloping", (pki, s) => s.WithForm(XadesForm.Enveloping).SignAsync()),
        Xades("xades-b-t", AdesBaselineLevel.Timestamped, "RSA, enveloped", (pki, s) => s.WithLevel(pki.Level("T")).SignAsync()),
        Xades("xades-b-lt", AdesBaselineLevel.LongTerm, "RSA, enveloped, CertificateValues + RevocationValues",
            (pki, s) => s.WithLevel(pki.Level("LT")).SignAsync()),
        Xades("xades-b-lta", AdesBaselineLevel.Archive, "RSA, enveloped, ArchiveTimeStamp", (pki, s) => s.WithLevel(pki.Level("LTA")).SignAsync()),
        Xades("xades-b-t-ecdsa", AdesBaselineLevel.Timestamped, "ECDSA P-256",
            (pki, s) => XadesSigner.Document(Xml).WithCertificate(pki.Ecdsa, pki.Chain).WithHttpClientProvider(pki.Http)
                .WithLevel(pki.Level("T")).SignAsync()),
        Xades("xades-b-t-countersigned", AdesBaselineLevel.Timestamped, "B-T counter-signed (ECDSA)",
            async (pki, s) => await XadesSigner.CounterSign(await s.WithLevel(pki.Level("T")).SignAsync())
                .WithCertificate(pki.Ecdsa, pki.Chain).WithHttpClientProvider(pki.Http).SignAsync()),
        Xades("xades-b-lta-augmented", AdesBaselineLevel.Archive, "B-B raised to B-LTA by XadesAugmenter",
            async (pki, s) => (await XadesAugmenter.Document(await s.SignAsync()).ToLevel(AdesBaselineLevel.Archive)
                .WithTimestamp(pki.Timestamp).WithHttpClientProvider(pki.Http).AugmentAsync()).Document),
        Xades("xades-b-lta-renewed", AdesBaselineLevel.Archive, "B-LTA with its archive renewed",
            async (pki, s) => (await XadesAugmenter.Document(await s.WithLevel(pki.Level("LTA")).SignAsync()).RenewArchive()
                .WithTimestamp(pki.Timestamp).WithHttpClientProvider(pki.Http).AugmentAsync()).Document),
        Xades("xades-b-t-deferred", AdesBaselineLevel.Timestamped, "two-phase (XadesDeferredSigner)", (pki, _) => XadesDeferredAsync(pki)),
        Xades("xades-b-t-two-signatures", AdesBaselineLevel.Timestamped, "two enveloped signatures (RSA, ECDSA), each B-T",
            async (pki, s) => await XadesSigner.Document(await s.WithLevel(pki.Level("T")).SignAsync())
                .WithCertificate(pki.Ecdsa, pki.Chain).WithHttpClientProvider(pki.Http).WithLevel(pki.Level("T")).SignAsync()) with { Signatures = 2 },
        Xades("xades-b-lta-two-signatures", AdesBaselineLevel.Archive, "two enveloped signatures (RSA, ECDSA), each B-LTA",
            async (pki, s) => await XadesSigner.Document(await s.WithLevel(pki.Level("LTA")).SignAsync())
                .WithCertificate(pki.Ecdsa, pki.Chain).WithHttpClientProvider(pki.Http).WithLevel(pki.Level("LTA")).SignAsync()) with { Signatures = 2 },
    ];

    /// <summary>The id of every sample, for a theory.</summary>
    public static TheoryData<string> Ids
    {
        get
        {
            var data = new TheoryData<string>();
            foreach (var sample in Samples)
            {
                data.Add(sample.Id);
            }

            return data;
        }
    }

    /// <summary>The sample named <paramref name="id"/>.</summary>
    public static EtsiSample Get(string id) => Samples.Single(s => s.Id == id);

    private static EtsiSample Pades(string id, AdesBaselineLevel level, string description, Func<OfflinePki, PadesSignerBuilder, Task<byte[]>> sign) =>
        new(id, EtsiFormat.Pades, level, description,
            pki => sign(pki, Pdf(pki).WithCertificate(pki.Pki.Leaf, pki.Chain).WithHttpClientProvider(pki.Http)));

    private static EtsiSample Cades(string id, AdesBaselineLevel level, string description, Func<OfflinePki, CadesSignerBuilder, Task<byte[]>> sign) =>
        new(id, EtsiFormat.Cades, level, description,
            pki => sign(pki, CadesSigner.Document(Content).WithCertificate(pki.Pki.Leaf, pki.Chain)
                .WithContentType(CadesContentType.Enveloped).WithHttpClientProvider(pki.Http)));

    private static EtsiSample Xades(string id, AdesBaselineLevel level, string description, Func<OfflinePki, XadesSignerBuilder, Task<byte[]>> sign) =>
        new(id, EtsiFormat.Xades, level, description,
            pki => sign(pki, XadesSigner.Document(Xml).WithCertificate(pki.Pki.Leaf, pki.Chain).WithHttpClientProvider(pki.Http)));

    private static PadesSignerBuilder Pdf(OfflinePki pki) =>
        PadesSigner.Document(File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "Fixtures", "xref-stream.pdf")));

    /// <summary>Signs <paramref name="pdf"/> again, at <paramref name="level"/>, in a new incremental update.</summary>
    private static Task<byte[]> AddPdfSignatureAsync(OfflinePki pki, X509Certificate2 signer, string level, byte[] pdf) =>
        PadesSigner.Document(pdf).WithCertificate(signer, pki.Chain).WithHttpClientProvider(pki.Http).WithLevel(pki.Level(level)).SignAsync();

    private static async Task<byte[]> PadesDeferredAsync(OfflinePki pki)
    {
        byte[] pdf = File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "Fixtures", "xref-stream.pdf"));
        using X509Certificate2 publicCertificate = RemoteKey.PublicOnly(pki.Pki.Leaf);
        var prepared = await DeferredSigner.Document(pdf).WithCertificate(publicCertificate, pki.Chain)
            .WithSessionIntegrityKey(SessionKey).WithLevel(pki.Level("T")).PrepareAsync();
        using RSA rsa = pki.Pki.Leaf.GetRSAPrivateKey()!;
        byte[] signature = rsa.SignData(prepared.HashToSign, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return await DeferredSigner.Resume(prepared.SessionData, SessionKey).WithHttpClientProvider(pki.Http).CompleteAsync(signature);
    }

    private static async Task<byte[]> CadesDeferredAsync(OfflinePki pki)
    {
        using X509Certificate2 publicCertificate = RemoteKey.PublicOnly(pki.Pki.Leaf);
        var prepared = await CadesDeferredSigner.Document(Content).WithCertificate(publicCertificate, pki.Chain)
            .WithSessionIntegrityKey(SessionKey).WithContentType(CadesContentType.Enveloped).WithLevel(pki.Level("T")).PrepareAsync();
        byte[] signature = RemoteKey.Sign(pki.Pki.Leaf, prepared.ToSigningRequest());
        return await CadesDeferredSigner.Resume(prepared.SessionData, SessionKey).WithHttpClientProvider(pki.Http).CompleteAsync(signature);
    }

    private static async Task<byte[]> XadesDeferredAsync(OfflinePki pki)
    {
        using X509Certificate2 publicCertificate = RemoteKey.PublicOnly(pki.Pki.Leaf);
        var prepared = await XadesDeferredSigner.Document(Xml).WithCertificate(publicCertificate, pki.Chain)
            .WithSessionIntegrityKey(SessionKey).WithLevel(pki.Level("T")).PrepareAsync();
        byte[] signature = RemoteKey.Sign(pki.Pki.Leaf, prepared.ToSigningRequest());
        return await XadesDeferredSigner.Resume(prepared.SessionData, SessionKey).WithHttpClientProvider(pki.Http).CompleteAsync(signature);
    }
}

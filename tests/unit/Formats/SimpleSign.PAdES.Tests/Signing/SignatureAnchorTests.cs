using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using Shouldly;
using SimpleSign.Core.Signing;
using SimpleSign.PAdES.Signing;
using SimpleSign.PAdES.Tests.Pdf;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.PAdES.Tests.Signing;

/// <summary>A stamp anchored to a text of the document (<see cref="SignatureAppearance.Anchor"/>), placed by <see cref="PdfSignatureWriter"/>.</summary>
[Trait("Category", "Unit")]
public sealed class SignatureAnchorTests
{
    // "Contratante" twice on page 2 (at y 300 and 200), once in capitals on page 1.
    private static readonly byte[] s_contract = PdfTextLocatorTests.TextPdf.Build(
    [
        "BT /F1 12 Tf 72 700 Td (O CONTRATANTE paga.) Tj ET",
        "BT /F1 12 Tf 72 300 Td (Contratante) Tj 0 -100 Td (Contratante) Tj ET",
    ]);

    [Fact(DisplayName = "The stamp goes on the anchor's page, at the start of its last match plus the offsets")]
    public async Task SignAsync_Anchor_PlacesAtLastMatch()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        var appearance = new SignatureAppearance { Anchor = new SignatureAnchor("Contratante") { OffsetY = 30, OffsetX = -10 } };

        byte[] signed = await PadesSigner.Document(s_contract).WithCertificate(cert).WithAppearance(appearance).SignAsync();

        var (x, y) = StampOrigin(signed);
        x.ShouldBe(62f, 0.01f);
        y.ShouldBe(230f, 0.01f);
        Encoding.Latin1.GetString(signed).ShouldContain("/P 7 0 R"); // page 2 is object 7
    }

    [Fact(DisplayName = "Occurrence picks a match counted from the first or from the last")]
    public async Task SignAsync_Occurrence_PicksMatch()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();

        byte[] first = await PadesSigner.Document(s_contract).WithCertificate(cert)
            .WithAppearance(new SignatureAppearance { Anchor = new SignatureAnchor("Contratante") { Occurrence = 1 } }).SignAsync();
        byte[] secondToLast = await PadesSigner.Document(s_contract).WithCertificate(cert)
            .WithAppearance(new SignatureAppearance { Anchor = new SignatureAnchor("contratante") { Occurrence = -3, IgnoreCase = true } }).SignAsync();

        StampOrigin(first).ShouldBe((72f, 300f));
        StampOrigin(secondToLast).Y.ShouldBe(700f); // "O CONTRATANTE" on page 1
    }

    [Fact(DisplayName = "An anchor whose text is not there refuses to sign")]
    public async Task SignAsync_AnchorMissing_Throws()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();

        var missing = await Should.ThrowAsync<SigningException>(() => PadesSigner.Document(s_contract).WithCertificate(cert)
            .WithAppearance(new SignatureAppearance { Anchor = new SignatureAnchor("Testemunha") }).SignAsync());
        var tooFew = await Should.ThrowAsync<SigningException>(() => PadesSigner.Document(s_contract).WithCertificate(cert)
            .WithAppearance(new SignatureAppearance { Anchor = new SignatureAnchor("Contratante") { Occurrence = 3 } }).SignAsync());

        missing.Reason.ShouldBe(SigningErrorReason.AnchorNotFound);
        missing.Message.ShouldContain("not in the document");
        tooFew.Reason.ShouldBe(SigningErrorReason.AnchorNotFound);
        tooFew.Message.ShouldContain("2 times");
    }

    [Fact(DisplayName = "An anchor with occurrence 0 or no text is rejected")]
    public void Locate_InvalidAnchor_Throws()
    {
        Should.Throw<InvalidOperationException>(() => new SignatureAnchor("Contratante") { Occurrence = 0 }.Locate(s_contract));
        Should.Throw<InvalidOperationException>(() => new SignatureAnchor(" ").Locate(s_contract));
    }

    [Fact(DisplayName = "Locate says where the stamp goes before signing")]
    public void Locate_Anchor_ReturnsPlacement() =>
        new SignatureAnchor("Contratante") { OffsetX = 5, OffsetY = 30 }.Locate(s_contract).ShouldBe(new SignatureAnchorPlacement(2, 77, 230));

    [Fact(DisplayName = "Deferred and batch signing place an anchored stamp the same way")]
    public async Task DeferredAndBatch_Anchor_PlaceTheSame()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        var appearance = new SignatureAppearance { Anchor = new SignatureAnchor("Contratante") { OffsetY = 30 } };

        byte[] key = RandomNumberGenerator.GetBytes(32);
        var prepared = await DeferredSigner.Document(s_contract).WithCertificate(cert)
            .WithSessionIntegrityKey(key).WithAppearance(appearance).PrepareAsync();
        using var rsa = cert.GetRSAPrivateKey();
        byte[] deferredSigned = await DeferredSigner.Resume(prepared.SessionData, key)
            .CompleteAsync(rsa!.SignData(prepared.HashToSign, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
        await using var batch = BatchSigner.Create(cert).WithFieldOptions(new SignatureFieldOptions { Appearance = appearance }).Build();
        byte[] batchSigned = await batch.SignAsync(s_contract);

        StampOrigin(deferredSigned).ShouldBe((72f, 230f));
        StampOrigin(batchSigned).ShouldBe((72f, 230f));
    }

    [Fact(DisplayName = "The anchor is kept by the appearance's copies")]
    public void WithExtraLines_KeepsAnchor()
    {
        var anchor = new SignatureAnchor("Contratante") { OffsetY = 30 };

        new SignatureAppearance { Anchor = anchor }.WithExtraLines(["x"]).Anchor.ShouldBe(anchor);
    }

    /// <summary>The lower-left corner of the visible widget's /Rect.</summary>
    private static (float X, float Y) StampOrigin(byte[] pdf)
    {
        var rect = Regex.Matches(Encoding.Latin1.GetString(pdf), @"/Rect\s*\[\s*([-\d.]+)\s+([-\d.]+)\s+([-\d.]+)\s+([-\d.]+)\s*\]")
            .Single(m => m.Groups[3].Value != "0");
        return (float.Parse(rect.Groups[1].Value, CultureInfo.InvariantCulture), float.Parse(rect.Groups[2].Value, CultureInfo.InvariantCulture));
    }
}

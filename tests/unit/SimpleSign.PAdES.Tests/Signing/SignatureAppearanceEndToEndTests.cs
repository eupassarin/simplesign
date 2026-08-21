using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Shouldly;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Validation;
using SimpleSign.PAdES.Signing;
using SimpleSign.PAdES.Validation;
using SimpleSign.TestHelpers;
using Xunit;
namespace SimpleSign.PAdES.Tests.Signing;

/// <summary>
/// End-to-end tests for signature appearance, metadata, and SubFilter.
/// </summary>
[Trait("Category", "Unit")]
public sealed class SignatureAppearanceEndToEndTests
{
    private static byte[] BuildMinimalPdf() => Encoding.Latin1.GetBytes("%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\nxref\n0 3\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \ntrailer\n<< /Size 3 /Root 1 0 R >>\nstartxref\n110\n%%EOF");

    private static byte[] BuildPdfWithPage() => Encoding.Latin1.GetBytes("%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] >>\nendobj\nxref\n0 4\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \n0000000115 00000 n \ntrailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n181\n%%EOF");

    private static X509Certificate2 CreateRsaCert(string subject = "CN=Test Signer, O=Tests, C=BR")
    {
        using RSA key = RSA.Create(2048);
        CertificateRequest certificateRequest = new CertificateRequest(subject, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        certificateRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: false));
        X509Certificate2 x509Certificate = certificateRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1.0), DateTimeOffset.UtcNow.AddYears(1));
        return CertificateLoader.LoadPkcs12(x509Certificate.Export(X509ContentType.Pfx, "test-export"), "test-export");
    }

    private static PdfSignatureValidator ValidatorTrusting(params X509Certificate2[] certs)
    {
        return new PdfSignatureValidator(new ValidationOptions
        {
            CheckRevocation = false,
            TrustedRoots = [.. certs]
        });
    }

    [Fact(DisplayName = "Signature with visual appearance remains valid")]
    public async Task SignAsync_WithAppearance_SignatureIsStillValid()
    {
        using X509Certificate2 cert = CreateRsaCert("CN=Auditor, O=TCE, C=BR");
        byte[] pdfBytes = BuildPdfWithPage();
        using MemoryStream stream = new MemoryStream(await PadesSigner.Document(pdfBytes).WithCertificate(cert).WithMetadata("Auditor", "Teste de aparência")
            .WithAppearance(new SignatureAppearance
            {
                X = 20f,
                Y = 20f
            })
            .SignAsync());
        IReadOnlyList<SignatureValidationResult> readOnlyList = await ValidatorTrusting(cert).ValidateAsync(stream);
        readOnlyList.Count().ShouldBe(1, "");
        readOnlyList[0].IsIntegrityValid.ShouldBeTrue("visual appearance should not affect integrity");
        readOnlyList[0].IsSignatureValid.ShouldBeTrue("");
    }

    [Fact(DisplayName = "PDF with appearance is larger than without appearance")]
    public async Task SignAsync_WithAppearance_PdfIsLargerThanWithout()
    {
        using X509Certificate2 cert = CreateRsaCert();
        byte[] pdf = BuildPdfWithPage();
        byte[] signedNoApp = await PadesSigner.Document(pdf).WithCertificate(cert).SignAsync();
        (await PadesSigner.Document(pdf).WithCertificate(cert).WithAppearance(new SignatureAppearance())
            .SignAsync()).Length.ShouldBeGreaterThan(signedNoApp.Length, "signature with appearance includes XObject and updated page");
    }

    [Fact(DisplayName = "PDF with appearance contains /Annots in page")]
    public async Task SignAsync_WithAppearance_PdfContainsAnnotsInPage()
    {
        using X509Certificate2 cert = CreateRsaCert();
        byte[] pdfBytes = BuildPdfWithPage();
        byte[] bytes = await PadesSigner.Document(pdfBytes).WithCertificate(cert).WithAppearance(new SignatureAppearance
        {
            X = 10f,
            Y = 10f
        })
            .SignAsync();
        string actualValue = Encoding.Latin1.GetString(bytes);
        actualValue.ShouldContain("/Annots");
    }

    [Fact(DisplayName = "PDF with appearance contains Form XObject stream")]
    public async Task SignAsync_WithAppearance_PdfContainsXObjectStream()
    {
        using X509Certificate2 cert = CreateRsaCert("CN=Testador, C=BR");
        byte[] pdfBytes = BuildPdfWithPage();
        byte[] bytes = await PadesSigner.Document(pdfBytes).WithCertificate(cert).WithMetadata("Testador")
            .WithAppearance(new SignatureAppearance())
            .SignAsync();
        string actualValue = Encoding.Latin1.GetString(bytes);
        actualValue.ShouldContain("/Subtype /Form");
        actualValue.ShouldContain("/BBox");
        actualValue.ShouldContain("Signed by");
    }

    [Fact(DisplayName = "Two signatures with appearance remain valid")]
    public async Task SignAsync_WithAppearance_TwoSigners_BothStillValid()
    {
        using X509Certificate2 cert1 = CreateRsaCert("CN=Primeiro, C=BR");
        using X509Certificate2 cert2 = CreateRsaCert("CN=Segundo, C=BR");
        byte[] pdfBytes = BuildPdfWithPage();
        using MemoryStream stream = new MemoryStream(await PadesSigner.Document(await PadesSigner.Document(pdfBytes).WithCertificate(cert1).WithFieldName("Sig1")
            .WithAppearance(new SignatureAppearance
            {
                X = 10f,
                Y = 10f
            })
            .SignAsync()).WithCertificate(cert2).WithFieldName("Sig2")
            .WithAppearance(new SignatureAppearance
            {
                X = 10f,
                Y = 60f
            })
            .SignAsync());
        IReadOnlyList<SignatureValidationResult> actualValue = await ValidatorTrusting(cert1, cert2).ValidateAsync(stream);
        actualValue.Count().ShouldBe(2, "");
        foreach (var r in actualValue)
        {
            r.IsIntegrityValid.ShouldBeTrue();
            r.IsSignatureValid.ShouldBeTrue();
        }
    }

    [Fact(DisplayName = "Null WithAppearance throws ArgumentNullException")]
    public void WithAppearance_NullAppearance_ThrowsArgumentNullException()
    {
        X509Certificate2 cert = CreateRsaCert();
        try
        {
            Func<PadesSignerBuilder> func = () => PadesSigner.Document(BuildMinimalPdf()).WithCertificate(cert).WithAppearance(null!);
            Should.Throw<ArgumentNullException>(func);
        }
        finally
        {
            if (cert != null)
            {
                ((IDisposable)cert).Dispose();
            }
        }
    }

    [Fact(DisplayName = "Default appearance values are reasonable")]
    public void SignatureAppearance_Defaults_AreReasonable()
    {
        SignatureAppearance signatureAppearance = new SignatureAppearance();
        signatureAppearance.Page.ShouldBe(1, "");
        signatureAppearance.X.ShouldBe(20f, "");
        signatureAppearance.Y.ShouldBe(20f, "");
        signatureAppearance.ShowDate.ShouldBeTrue("");
    }

    [Fact(DisplayName = "Signer name is populated in validation")]
    public async Task ValidateAsync_SignedPdf_SignerNamePopulated()
    {
        using X509Certificate2 cert = CreateRsaCert("CN=Fulano de Tal, O=Orgao, C=BR");
        using MemoryStream stream = new MemoryStream(await PadesSigner.Document(BuildMinimalPdf()).WithCertificate(cert).SignAsync());
        (await ValidatorTrusting(cert).ValidateAsync(stream))[0].SignerName.ShouldBe("Fulano de Tal", "");
    }

    [Fact(DisplayName = "SubFilter is populated in validation")]
    public async Task ValidateAsync_SignedPdf_SubFilterPopulated()
    {
        using X509Certificate2 cert = CreateRsaCert();
        using MemoryStream stream = new MemoryStream(await PadesSigner.Document(BuildMinimalPdf()).WithCertificate(cert).SignAsync());
        (await ValidatorTrusting(cert).ValidateAsync(stream))[0].SubFilter.ShouldBe("ETSI.CAdES.detached", "");
    }

    [Fact(DisplayName = "Digest algorithm OID is populated")]
    public async Task ValidateAsync_SignedPdf_DigestAlgorithmOidPopulated()
    {
        using X509Certificate2 cert = CreateRsaCert();
        using MemoryStream stream = new MemoryStream(await PadesSigner.Document(BuildMinimalPdf()).WithCertificate(cert).SignAsync());
        (await ValidatorTrusting(cert).ValidateAsync(stream))[0].DigestAlgorithmOid.ShouldBe("2.16.840.1.101.3.4.2.1", "");
    }

    [Fact(DisplayName = "Signature date/time is populated")]
    public async Task ValidateAsync_SignedPdf_SigningTimePopulated()
    {
        using X509Certificate2 cert = CreateRsaCert();
        DateTimeOffset before = DateTimeOffset.UtcNow.AddSeconds(-2.0);
        byte[] buffer = await PadesSigner.Document(BuildMinimalPdf()).WithCertificate(cert).SignAsync();
        DateTimeOffset after = DateTimeOffset.UtcNow.AddSeconds(2.0);
        using MemoryStream stream = new MemoryStream(buffer);
        IReadOnlyList<SignatureValidationResult> readOnlyList = await ValidatorTrusting(cert).ValidateAsync(stream);
        readOnlyList[0].SigningTime.ShouldNotBeNull();
        readOnlyList[0].SigningTime!.Value.ShouldBeGreaterThan(before);
        readOnlyList[0].SigningTime!.Value.ShouldBeLessThan(after);
    }

    [Fact(DisplayName = "SubFilter ETSI validates correctly")]
    public async Task SignAsync_EtsiSubFilter_ValidatesCorrectly()
    {
        using X509Certificate2 cert = CreateRsaCert();
        byte[] pdfBytes = BuildMinimalPdf();
        using MemoryStream stream = new MemoryStream(await PadesSigner.Document(pdfBytes).WithCertificate(cert).WithFieldName("EtsiSig")
            .SignAsync());
        IReadOnlyList<SignatureValidationResult> readOnlyList = await ValidatorTrusting(cert).ValidateAsync(stream);
        readOnlyList[0].IsIntegrityValid.ShouldBeTrue("");
        readOnlyList[0].IsSignatureValid.ShouldBeTrue("");
    }

    [Fact(DisplayName = "Signature with QR code URL remains valid")]
    public async Task SignAsync_WithQrCode_ValidatesCorrectly()
    {
        using X509Certificate2 cert = CreateRsaCert();
        byte[] pdfBytes = BuildPdfWithPage();
        using MemoryStream stream = new MemoryStream(await PadesSigner.Document(pdfBytes).WithCertificate(cert)
            .WithAppearance(new SignatureAppearance
            {
                X = 20f,
                Y = 20f,
                VerificationUrl = "https://verify.example.com/doc-123"
            })
            .SignAsync());
        IReadOnlyList<SignatureValidationResult> results = await ValidatorTrusting(cert).ValidateAsync(stream);
        results.Count.ShouldBe(1, "");
        results[0].IsIntegrityValid.ShouldBeTrue("QR code URL should not affect integrity");
        results[0].IsSignatureValid.ShouldBeTrue("");
    }

    [Fact(DisplayName = "Signature with QR code is larger than without (QR adds image data)")]
    public async Task SignAsync_WithQrCode_PdfIsLarger()
    {
        using X509Certificate2 cert = CreateRsaCert();
        byte[] pdfBytes = BuildPdfWithPage();
        byte[] withQr = await PadesSigner.Document(pdfBytes).WithCertificate(cert)
            .WithAppearance(new SignatureAppearance
            {
                X = 20f,
                Y = 20f,
                VerificationUrl = "https://verify.example.com/doc-123"
            })
            .SignAsync();
        byte[] withoutQr = await PadesSigner.Document(pdfBytes).WithCertificate(cert)
            .WithAppearance(new SignatureAppearance
            {
                X = 20f,
                Y = 20f
            })
            .SignAsync();
        withQr.Length.ShouldBeGreaterThan(withoutQr.Length, "QR code should add image data");
    }

    [Fact(DisplayName = "Signature with QR code contains QR white background rect")]
    public async Task SignAsync_WithQrCode_PdfContainsQrContent()
    {
        using X509Certificate2 cert = CreateRsaCert();
        byte[] pdfBytes = BuildPdfWithPage();
        byte[] signed = await PadesSigner.Document(pdfBytes).WithCertificate(cert)
            .WithAppearance(new SignatureAppearance
            {
                X = 20f,
                Y = 60f,
                VerificationUrl = "https://verify.example.com/doc-123"
            })
            .SignAsync();
        string pdf = Encoding.Latin1.GetString(signed);
        pdf.ShouldContain("1 1 1 rg");
    }

    [Fact(DisplayName = "Signature without VerificationUrl has no QR background rect")]
    public async Task SignAsync_WithoutQrCode_NoQrContent()
    {
        using X509Certificate2 cert = CreateRsaCert();
        byte[] pdfBytes = BuildPdfWithPage();
        byte[] signed = await PadesSigner.Document(pdfBytes).WithCertificate(cert)
            .WithAppearance(new SignatureAppearance
            {
                X = 20f,
                Y = 60f,
                VerificationUrl = null
            })
            .SignAsync();
        string pdf = Encoding.Latin1.GetString(signed);
        pdf.ShouldNotContain("1 1 1 rg");
    }

    [Fact(DisplayName = "Two signers with QR code both remain valid")]
    public async Task SignAsync_WithQrCode_TwoSigners_BothValid()
    {
        using X509Certificate2 cert1 = CreateRsaCert("CN=QR First");
        using X509Certificate2 cert2 = CreateRsaCert("CN=QR Second");
        byte[] pdf = BuildPdfWithPage();
        using MemoryStream stream = new MemoryStream(await PadesSigner.Document(await PadesSigner.Document(pdf)
            .WithCertificate(cert1).WithFieldName("Sig1")
            .WithAppearance(new SignatureAppearance { X = 10f, Y = 10f, VerificationUrl = "https://verify.example.com/1" })
            .SignAsync()).WithCertificate(cert2).WithFieldName("Sig2")
            .WithAppearance(new SignatureAppearance { X = 10f, Y = 60f, VerificationUrl = "https://verify.example.com/2" })
            .SignAsync());
        IReadOnlyList<SignatureValidationResult> results = await ValidatorTrusting(cert1, cert2).ValidateAsync(stream);
        results.Count.ShouldBe(2, "");
        foreach (var r in results)
        {
            r.IsIntegrityValid.ShouldBeTrue();
            r.IsSignatureValid.ShouldBeTrue();
        }
    }

    [Fact]
    public async Task SignAsync_Page2Appearance_WidgetAttachesToCorrectPage()
    {
        using X509Certificate2 cert = CreateRsaCert("CN=Page Selector");
        byte[] pdf = TestPdfFactory.CreateThreePagePdf();
        byte[] signed = await PadesSigner.Document(pdf)
            .WithCertificate(cert)
            .WithAppearance(new SignatureAppearance { Page = 2, X = 50, Y = 50, AutoPosition = false })
            .SignAsync();
        using MemoryStream ms = new MemoryStream(signed);
        IReadOnlyList<SignatureValidationResult> results = await ValidatorTrusting(cert).ValidateAsync(ms);
        results.Count.ShouldBe(1);
        results[0].IsIntegrityValid.ShouldBeTrue();
        results[0].IsSignatureValid.ShouldBeTrue();
    }

    [Fact]
    public async Task SignAsync_Page3Appearance_WidgetAttachesToCorrectPage()
    {
        using X509Certificate2 cert = CreateRsaCert("CN=Page 3 Signer");
        byte[] pdf = TestPdfFactory.CreateThreePagePdf();
        byte[] signed = await PadesSigner.Document(pdf)
            .WithCertificate(cert)
            .WithAppearance(new SignatureAppearance { Page = 3, X = 50, Y = 50, AutoPosition = false })
            .SignAsync();
        using MemoryStream ms = new MemoryStream(signed);
        IReadOnlyList<SignatureValidationResult> results = await ValidatorTrusting(cert).ValidateAsync(ms);
        results.Count.ShouldBe(1);
        results[0].IsIntegrityValid.ShouldBeTrue();
        results[0].IsSignatureValid.ShouldBeTrue();
    }
}

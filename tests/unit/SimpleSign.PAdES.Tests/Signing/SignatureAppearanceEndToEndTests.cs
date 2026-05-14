using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using FluentAssertions;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Validation;
using SimpleSign.PAdES.Signing;
using SimpleSign.PAdES.Validation;
using Xunit;
namespace SimpleSign.PAdES.Tests.Core;

/// <summary>
/// End-to-end tests for signature appearance, metadata, and SubFilter.
/// </summary>
public sealed class SignatureAppearanceEndToEndTests
{
    private static byte[] BuildMinimalPdf()
    {
        return Encoding.Latin1.GetBytes("%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\nxref\n0 3\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \ntrailer\n<< /Size 3 /Root 1 0 R >>\nstartxref\n110\n%%EOF");
    }

    private static byte[] BuildPdfWithPage()
    {
        return Encoding.Latin1.GetBytes("%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] >>\nendobj\nxref\n0 4\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \n0000000115 00000 n \ntrailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n181\n%%EOF");
    }

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
            TrustedRoots = certs.ToList()
        });
    }

    [Fact(DisplayName = "Signature with visual appearance remains valid")]
    public async Task SignAsync_WithAppearance_SignatureIsStillValid()
    {
        using X509Certificate2 cert = CreateRsaCert("CN=Auditor, O=TCE, C=BR");
        byte[] pdfBytes = BuildPdfWithPage();
        using MemoryStream stream = new MemoryStream(await SimpleSigner.Document(pdfBytes).WithCertificate(cert).WithMetadata("Auditor", "Teste de aparência")
            .WithAppearance(new SignatureAppearance
            {
                X = 20f,
                Y = 20f
            })
            .SignAsync());
        IReadOnlyList<SignatureValidationResult> readOnlyList = await ValidatorTrusting(cert).ValidateAsync(stream);
        readOnlyList.Should().ContainSingle("");
        readOnlyList[0].IsIntegrityValid.Should().BeTrue("visual appearance should not affect integrity");
        readOnlyList[0].IsSignatureValid.Should().BeTrue("");
    }

    [Fact(DisplayName = "PDF with appearance is larger than without appearance")]
    public async Task SignAsync_WithAppearance_PdfIsLargerThanWithout()
    {
        using X509Certificate2 cert = CreateRsaCert();
        byte[] pdf = BuildPdfWithPage();
        byte[] signedNoApp = await SimpleSigner.Document(pdf).WithCertificate(cert).SignAsync();
        (await SimpleSigner.Document(pdf).WithCertificate(cert).WithAppearance(new SignatureAppearance())
            .SignAsync()).Length.Should().BeGreaterThan(signedNoApp.Length, "signature with appearance includes XObject and updated page");
    }

    [Fact(DisplayName = "PDF with appearance contains /Annots in page")]
    public async Task SignAsync_WithAppearance_PdfContainsAnnotsInPage()
    {
        using X509Certificate2 cert = CreateRsaCert();
        byte[] pdfBytes = BuildPdfWithPage();
        byte[] bytes = await SimpleSigner.Document(pdfBytes).WithCertificate(cert).WithAppearance(new SignatureAppearance
        {
            X = 10f,
            Y = 10f
        })
            .SignAsync();
        string actualValue = Encoding.Latin1.GetString(bytes);
        actualValue.Should().Contain("/Annots", "page should reference the signature field");
    }

    [Fact(DisplayName = "PDF with appearance contains Form XObject stream")]
    public async Task SignAsync_WithAppearance_PdfContainsXObjectStream()
    {
        using X509Certificate2 cert = CreateRsaCert("CN=Testador, C=BR");
        byte[] pdfBytes = BuildPdfWithPage();
        byte[] bytes = await SimpleSigner.Document(pdfBytes).WithCertificate(cert).WithMetadata("Testador")
            .WithAppearance(new SignatureAppearance())
            .SignAsync();
        string actualValue = Encoding.Latin1.GetString(bytes);
        actualValue.Should().Contain("/Subtype /Form", "aparência usa Form XObject");
        actualValue.Should().Contain("/BBox", "Form XObject should have bounding box");
        actualValue.Should().Contain("Signed by", "stamp should contain appearance text");
    }

    [Fact(DisplayName = "Two signatures with appearance remain valid")]
    public async Task SignAsync_WithAppearance_TwoSigners_BothStillValid()
    {
        using X509Certificate2 cert1 = CreateRsaCert("CN=Primeiro, C=BR");
        using X509Certificate2 cert2 = CreateRsaCert("CN=Segundo, C=BR");
        byte[] pdfBytes = BuildPdfWithPage();
        using MemoryStream stream = new MemoryStream(await SimpleSigner.Document(await SimpleSigner.Document(pdfBytes).WithCertificate(cert1).WithFieldName("Sig1")
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
        actualValue.Should().HaveCount(2, "");
        actualValue.Should().AllSatisfy(delegate (SignatureValidationResult r)
        {
            r.IsIntegrityValid.Should().BeTrue("");
            r.IsSignatureValid.Should().BeTrue("");
        }, "");
    }

    [Fact(DisplayName = "Null WithAppearance throws ArgumentNullException")]
    public void WithAppearance_NullAppearance_ThrowsArgumentNullException()
    {
        X509Certificate2 cert = CreateRsaCert();
        try
        {
            Func<SignerBuilder> func = () => SimpleSigner.Document(BuildMinimalPdf()).WithCertificate(cert).WithAppearance(null!);
            func.Should().Throw<ArgumentNullException>("", Array.Empty<object>());
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
        signatureAppearance.Page.Should().Be(1, "");
        signatureAppearance.X.Should().Be(20f, "");
        signatureAppearance.Y.Should().Be(20f, "");
        signatureAppearance.ShowDate.Should().BeTrue("");
    }

    [Fact(DisplayName = "Signer name is populated in validation")]
    public async Task ValidateAsync_SignedPdf_SignerNamePopulated()
    {
        using X509Certificate2 cert = CreateRsaCert("CN=Fulano de Tal, O=Orgao, C=BR");
        using MemoryStream stream = new MemoryStream(await SimpleSigner.Document(BuildMinimalPdf()).WithCertificate(cert).SignAsync());
        (await ValidatorTrusting(cert).ValidateAsync(stream))[0].SignerName.Should().Be("Fulano de Tal", "");
    }

    [Fact(DisplayName = "SubFilter is populated in validation")]
    public async Task ValidateAsync_SignedPdf_SubFilterPopulated()
    {
        using X509Certificate2 cert = CreateRsaCert();
        using MemoryStream stream = new MemoryStream(await SimpleSigner.Document(BuildMinimalPdf()).WithCertificate(cert).SignAsync());
        (await ValidatorTrusting(cert).ValidateAsync(stream))[0].SubFilter.Should().Be("ETSI.CAdES.detached", "");
    }

    [Fact(DisplayName = "Digest algorithm OID is populated")]
    public async Task ValidateAsync_SignedPdf_DigestAlgorithmOidPopulated()
    {
        using X509Certificate2 cert = CreateRsaCert();
        using MemoryStream stream = new MemoryStream(await SimpleSigner.Document(BuildMinimalPdf()).WithCertificate(cert).SignAsync());
        (await ValidatorTrusting(cert).ValidateAsync(stream))[0].DigestAlgorithmOid.Should().Be("2.16.840.1.101.3.4.2.1", "");
    }

    [Fact(DisplayName = "Signature date/time is populated")]
    public async Task ValidateAsync_SignedPdf_SigningTimePopulated()
    {
        using X509Certificate2 cert = CreateRsaCert();
        DateTimeOffset before = DateTimeOffset.UtcNow.AddSeconds(-2.0);
        byte[] buffer = await SimpleSigner.Document(BuildMinimalPdf()).WithCertificate(cert).SignAsync();
        DateTimeOffset after = DateTimeOffset.UtcNow.AddSeconds(2.0);
        using MemoryStream stream = new MemoryStream(buffer);
        IReadOnlyList<SignatureValidationResult> readOnlyList = await ValidatorTrusting(cert).ValidateAsync(stream);
        readOnlyList[0].SigningTime.Should().NotBeNull("");
        readOnlyList[0].SigningTime!.Value.Should().BeAfter(before, "").And.BeBefore(after, "");
    }

    [Fact(DisplayName = "SubFilter ETSI validates correctly")]
    public async Task SignAsync_EtsiSubFilter_ValidatesCorrectly()
    {
        using X509Certificate2 cert = CreateRsaCert();
        byte[] pdfBytes = BuildMinimalPdf();
        using MemoryStream stream = new MemoryStream(await SimpleSigner.Document(pdfBytes).WithCertificate(cert).WithFieldName("EtsiSig")
            .SignAsync());
        IReadOnlyList<SignatureValidationResult> readOnlyList = await ValidatorTrusting(cert).ValidateAsync(stream);
        readOnlyList[0].IsIntegrityValid.Should().BeTrue("");
        readOnlyList[0].IsSignatureValid.Should().BeTrue("");
    }
}

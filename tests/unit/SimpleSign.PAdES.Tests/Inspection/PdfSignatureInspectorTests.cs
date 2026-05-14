using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using FluentAssertions;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Inspection;
using SimpleSign.PAdES.Inspection;
using SimpleSign.PAdES.Signing;
using Xunit;
namespace SimpleSign.PAdES.Tests.Inspection;

public sealed class PdfSignatureInspectorTests
{
    private sealed class NonSeekableStream(Stream inner) : Stream()
    {
        public override bool CanRead => inner.CanRead;

        public override bool CanSeek => false;

        public override bool CanWrite => inner.CanWrite;

        public override long Length
        {
            get
            {
                throw new NotSupportedException();
            }
        }

        public override long Position
        {
            get
            {
                throw new NotSupportedException();
            }
            set
            {
                throw new NotSupportedException();
            }
        }

        public override void Flush()
        {
            inner.Flush();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            return inner.Read(buffer, offset, count);
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            throw new NotSupportedException();
        }

        public override void SetLength(long value)
        {
            throw new NotSupportedException();
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            inner.Write(buffer, offset, count);
        }
    }

    [Fact(DisplayName = "InspectAsync with unsigned PDF returns no signatures")]
    public async Task InspectAsync_UnsignedPdf_NoSignatures()
    {
        byte[] buffer = BuildMinimalPdf();
        using MemoryStream stream = new MemoryStream(buffer);
        PdfInspectionResult pdfInspectionResult = await PdfSignatureInspector.InspectAsync(stream);
        pdfInspectionResult.HasSignatures.Should().BeFalse("");
        pdfInspectionResult.Signatures.Should().BeEmpty("");
        pdfInspectionResult.Document.SignatureCount.Should().Be(0, "");
        pdfInspectionResult.Document.IsEncrypted.Should().BeFalse("");
    }

    [Fact(DisplayName = "InspectAsync with RSA-signed PDF extracts signer info")]
    public async Task InspectAsync_RsaSignedPdf_ExtractsSignerInfo()
    {
        using X509Certificate2 cert = CreateRsaCert("CN=Inspector Test, O=Tests, C=BR");
        byte[] pdfBytes = BuildMinimalPdf();
        using MemoryStream stream = new MemoryStream(await SimpleSigner.Document(pdfBytes).WithCertificate(cert).SignAsync());
        PdfInspectionResult pdfInspectionResult = await PdfSignatureInspector.InspectAsync(stream);
        pdfInspectionResult.HasSignatures.Should().BeTrue("");
        pdfInspectionResult.Signatures.Should().ContainSingle("");
        pdfInspectionResult.Document.SignatureCount.Should().Be(1, "");
        SignatureFieldInfo signatureFieldInfo = pdfInspectionResult.Signatures[0];
        signatureFieldInfo.FieldName.Should().NotBeNullOrEmpty("");
        signatureFieldInfo.Signer.Should().NotBeNull("");
        signatureFieldInfo.Signer.Subject.Should().Contain("Inspector Test", "");
        signatureFieldInfo.Signer.KeyAlgorithm.Should().Be("RSA", "");
        signatureFieldInfo.Signer.KeySizeBits.Should().Be(2048, "");
        signatureFieldInfo.Signer.IsExpired.Should().BeFalse("");
    }

    [Fact(DisplayName = "InspectAsync with ECDSA-signed PDF extracts correct algorithm")]
    public async Task InspectAsync_EcdsaSignedPdf_ExtractsAlgorithm()
    {
        using X509Certificate2 cert = CreateEcdsaCert("CN=ECDSA Inspector, O=Tests");
        byte[] pdfBytes = BuildMinimalPdf();
        using MemoryStream stream = new MemoryStream(await SimpleSigner.Document(pdfBytes).WithCertificate(cert).SignAsync());
        SignatureFieldInfo signatureFieldInfo = (await PdfSignatureInspector.InspectAsync(stream)).Signatures[0];
        signatureFieldInfo.Signer.Should().NotBeNull("");
        signatureFieldInfo.Signer.KeyAlgorithm.Should().Be("ECDSA", "");
        signatureFieldInfo.DigestAlgorithm.Name.Should().Be("SHA-256", "");
        signatureFieldInfo.SignatureAlgorithm.Name.Should().Contain("ECDSA", "");
    }

    [Fact(DisplayName = "InspectAsync extracts signing time from CMS")]
    public async Task InspectAsync_SignedPdf_ExtractsSigningTime()
    {
        using X509Certificate2 cert = CreateRsaCert();
        byte[] pdfBytes = BuildMinimalPdf();
        using MemoryStream stream = new MemoryStream(await SimpleSigner.Document(pdfBytes).WithCertificate(cert).SignAsync());
        SignatureFieldInfo signatureFieldInfo = (await PdfSignatureInspector.InspectAsync(stream)).Signatures[0];
        signatureFieldInfo.SigningTime.Should().NotBeNull("");
        signatureFieldInfo.SigningTime.Value.Should().BeCloseTo(DateTimeOffset.UtcNow, TimeSpan.FromMinutes(5.0), "");
    }

    [Fact(DisplayName = "InspectAsync extracts embedded certificates")]
    public async Task InspectAsync_SignedPdf_ExtractsEmbeddedCertificates()
    {
        using X509Certificate2 cert = CreateRsaCert();
        byte[] pdfBytes = BuildMinimalPdf();
        using MemoryStream stream = new MemoryStream(await SimpleSigner.Document(pdfBytes).WithCertificate(cert).SignAsync());
        SignatureFieldInfo sig = (await PdfSignatureInspector.InspectAsync(stream)).Signatures[0];
        sig.EmbeddedCertificates.Should().NotBeEmpty("");
        sig.EmbeddedCertificates.Should().Contain((CertificateInfo c) => c.Subject == sig.Signer!.Subject, "");
    }

    [Fact(DisplayName = "InspectAsync extracts HasSigningCertificateV2")]
    public async Task InspectAsync_SignedPdf_HasSigningCertificateV2()
    {
        using X509Certificate2 cert = CreateRsaCert();
        byte[] pdfBytes = BuildMinimalPdf();
        using MemoryStream stream = new MemoryStream(await SimpleSigner.Document(pdfBytes).WithCertificate(cert).SignAsync());
        (await PdfSignatureInspector.InspectAsync(stream)).Signatures[0].HasSigningCertificateV2.Should().BeTrue("");
    }

    [Fact(DisplayName = "InspectAsync with multi-signature PDF extracts all signatures")]
    public async Task InspectAsync_MultiSignedPdf_ExtractsAllSignatures()
    {
        using X509Certificate2 cert1 = CreateRsaCert("CN=Signer One, O=Tests");
        using X509Certificate2 cert2 = CreateRsaCert("CN=Signer Two, O=Tests");
        byte[] pdfBytes = BuildMinimalPdf();
        using MemoryStream stream = new MemoryStream(await SimpleSigner.Document(await SimpleSigner.Document(pdfBytes).WithCertificate(cert1).SignAsync()).WithCertificate(cert2).SignAsync());
        PdfInspectionResult pdfInspectionResult = await PdfSignatureInspector.InspectAsync(stream);
        pdfInspectionResult.Signatures.Count.Should().BeGreaterThanOrEqualTo(2, "");
        pdfInspectionResult.Signatures.Should().Contain((SignatureFieldInfo s) => s.Signer!.Subject.Contains("Signer One"), "");
        pdfInspectionResult.Signatures.Should().Contain((SignatureFieldInfo s) => s.Signer!.Subject.Contains("Signer Two"), "");
    }

    [Fact(DisplayName = "InspectAsync extracts SubFilter correctly")]
    public async Task InspectAsync_SignedPdf_ExtractsSubFilter()
    {
        using X509Certificate2 cert = CreateRsaCert();
        byte[] pdfBytes = BuildMinimalPdf();
        using MemoryStream stream = new MemoryStream(await SimpleSigner.Document(pdfBytes).WithCertificate(cert).SignAsync());
        SignatureFieldInfo signatureFieldInfo = (await PdfSignatureInspector.InspectAsync(stream)).Signatures[0];
        signatureFieldInfo.SubFilter.Should().NotBeNullOrEmpty("");
        signatureFieldInfo.IsDocumentTimestamp.Should().BeFalse("");
    }

    [Fact(DisplayName = "InspectAsync extracts ByteRange")]
    public async Task InspectAsync_SignedPdf_ExtractsByteRange()
    {
        using X509Certificate2 cert = CreateRsaCert();
        byte[] pdfBytes = BuildMinimalPdf();
        using MemoryStream stream = new MemoryStream(await SimpleSigner.Document(pdfBytes).WithCertificate(cert).SignAsync());
        SignatureFieldInfo signatureFieldInfo = (await PdfSignatureInspector.InspectAsync(stream)).Signatures[0];
        signatureFieldInfo.ByteRange.Should().NotBeNull("");
        signatureFieldInfo.ByteRange.IsValid.Should().BeTrue("");
        signatureFieldInfo.ByteRange.Offset1.Should().Be(0L, "");
    }

    [Fact(DisplayName = "InspectAsync contains CMS raw data")]
    public async Task InspectAsync_SignedPdf_ContainsCmsRawData()
    {
        using X509Certificate2 cert = CreateRsaCert();
        byte[] pdfBytes = BuildMinimalPdf();
        using MemoryStream stream = new MemoryStream(await SimpleSigner.Document(pdfBytes).WithCertificate(cert).SignAsync());
        SignatureFieldInfo signatureFieldInfo = (await PdfSignatureInspector.InspectAsync(stream)).Signatures[0];
        signatureFieldInfo.CmsRawData.Length.Should().BeGreaterThan(0, "");
    }

    [Fact(DisplayName = "InspectAsync throws on non-seekable stream")]
    public async Task InspectAsync_NonSeekableStream_Throws()
    {
        NonSeekableStream nonSeekable = new NonSeekableStream(new MemoryStream(BuildMinimalPdf()));
        try
        {
            Func<Task<PdfInspectionResult>> action = () => PdfSignatureInspector.InspectAsync(nonSeekable);
            await action.Should().ThrowAsync<ArgumentException>("", Array.Empty<object>()).WithParameterName("pdfStream", "");
        }
        finally
        {
            nonSeekable?.Dispose();
        }
    }

    [Fact(DisplayName = "InspectAsync detects DocMDP locked status (NoChanges)")]
    public async Task InspectAsync_CertifiedPdf_DetectsDocMdpLocked()
    {
        using X509Certificate2 cert = CreateRsaCert();
        byte[] pdfBytes = BuildMinimalPdf();
        using MemoryStream stream = new MemoryStream(await SimpleSigner.Document(pdfBytes).WithCertificate(cert).AsCertification(CertificationLevel.NoChanges)
            .SignAsync());
        var result = await PdfSignatureInspector.InspectAsync(stream);
        result.Document.IsDocMdpLocked.Should().BeTrue("");
        result.Document.DocMdpPermissionLevel.Should().Be(1);
    }

    [Fact(DisplayName = "InspectAsync detects DocMDP permission levels correctly")]
    public async Task InspectAsync_CertifiedPdf_DetectsPermissionLevels()
    {
        using X509Certificate2 cert = CreateRsaCert();
        byte[] pdfBytes = BuildMinimalPdf();

        // FormFilling (level 2) — locked
        using MemoryStream streamFf = new MemoryStream(await SimpleSigner.Document(pdfBytes).WithCertificate(cert).AsCertification(CertificationLevel.FormFilling)
            .SignAsync());
        var resultFf = await PdfSignatureInspector.InspectAsync(streamFf);
        resultFf.Document.IsDocMdpLocked.Should().BeTrue("");
        resultFf.Document.DocMdpPermissionLevel.Should().Be(2);

        // FormFillingAndAnnotations (level 3) — not locked
        using MemoryStream streamAnn = new MemoryStream(await SimpleSigner.Document(pdfBytes).WithCertificate(cert).AsCertification(CertificationLevel.FormFillingAndAnnotations)
            .SignAsync());
        var resultAnn = await PdfSignatureInspector.InspectAsync(streamAnn);
        resultAnn.Document.IsDocMdpLocked.Should().BeFalse("");
        resultAnn.Document.DocMdpPermissionLevel.Should().Be(3);
    }

    private static byte[] BuildMinimalPdf()
    {
        return Encoding.Latin1.GetBytes("%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\nxref\n0 3\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \ntrailer\n<< /Size 3 /Root 1 0 R >>\nstartxref\n110\n%%EOF");
    }

    private static X509Certificate2 CreateRsaCert(string subject = "CN=Test Signer, O=Tests, C=BR")
    {
        using RSA key = RSA.Create(2048);
        CertificateRequest certificateRequest = new CertificateRequest(subject, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        certificateRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: false));
        X509Certificate2 x509Certificate = certificateRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1.0), DateTimeOffset.UtcNow.AddYears(1));
        return CertificateLoader.LoadPkcs12(x509Certificate.Export(X509ContentType.Pfx, "test-export"), "test-export");
    }

    private static X509Certificate2 CreateEcdsaCert(string subject = "CN=ECDSA Signer, O=Tests")
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        CertificateRequest certificateRequest = new CertificateRequest(subject, key, HashAlgorithmName.SHA256);
        certificateRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: false));
        X509Certificate2 x509Certificate = certificateRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1.0), DateTimeOffset.UtcNow.AddYears(1));
        return CertificateLoader.LoadPkcs12(x509Certificate.Export(X509ContentType.Pfx, "test-export"), "test-export");
    }
}

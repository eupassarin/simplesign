using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Shouldly;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Inspection;
using SimpleSign.PAdES.Inspection;
using SimpleSign.PAdES.Signing;
using SimpleSign.TestHelpers;
using Xunit;
namespace SimpleSign.PAdES.Tests.Inspection;

[Trait("Category", "Unit")]
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
            get => throw new NotSupportedException(); set => throw new NotSupportedException();
        }

        public override void Flush() => inner.Flush();

        public override int Read(byte[] buffer, int offset, int count) => inner.Read(buffer, offset, count);

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) => inner.Write(buffer, offset, count);
    }

    [Fact(DisplayName = "InspectAsync with unsigned PDF returns no signatures")]
    public async Task InspectAsync_UnsignedPdf_NoSignatures()
    {
        byte[] buffer = TestPdfFactory.CreateMinimalPdf();
        using MemoryStream stream = new MemoryStream(buffer);
        PdfInspectionResult pdfInspectionResult = await PdfSignatureInspector.InspectAsync(stream);
        pdfInspectionResult.HasSignatures.ShouldBeFalse("");
        pdfInspectionResult.Signatures.ShouldBeEmpty("");
        pdfInspectionResult.Document.SignatureCount.ShouldBe(0, "");
        pdfInspectionResult.Document.IsEncrypted.ShouldBeFalse("");
    }

    [Fact(DisplayName = "InspectAsync with RSA-signed PDF extracts signer info")]
    public async Task InspectAsync_RsaSignedPdf_ExtractsSignerInfo()
    {
        using X509Certificate2 cert = CreateRsaCert("CN=Inspector Test, O=Tests, C=BR");
        byte[] pdfBytes = TestPdfFactory.CreateMinimalPdf();
        using MemoryStream stream = new MemoryStream(await PadesSigner.Document(pdfBytes).WithCertificate(cert).SignAsync());
        PdfInspectionResult pdfInspectionResult = await PdfSignatureInspector.InspectAsync(stream);
        pdfInspectionResult.HasSignatures.ShouldBeTrue("");
        pdfInspectionResult.Signatures.Count().ShouldBe(1);
        pdfInspectionResult.Document.SignatureCount.ShouldBe(1);
        SignatureFieldInfo signatureFieldInfo = pdfInspectionResult.Signatures[0];
        signatureFieldInfo.FieldName.ShouldNotBeNullOrWhiteSpace();
        signatureFieldInfo.Signer.ShouldNotBeNull();
        signatureFieldInfo.Signer.Subject.ShouldContain("Inspector Test");
        signatureFieldInfo.Signer.KeyAlgorithm.ShouldBe("RSA");
        signatureFieldInfo.Signer.KeySizeBits.ShouldBe(2048);
        signatureFieldInfo.Signer.IsExpired.ShouldBeFalse();
    }

    [Fact(DisplayName = "InspectAsync with ECDSA-signed PDF extracts correct algorithm")]
    public async Task InspectAsync_EcdsaSignedPdf_ExtractsAlgorithm()
    {
        using X509Certificate2 cert = CreateEcdsaCert("CN=ECDSA Inspector, O=Tests");
        byte[] pdfBytes = TestPdfFactory.CreateMinimalPdf();
        using MemoryStream stream = new MemoryStream(await PadesSigner.Document(pdfBytes).WithCertificate(cert).SignAsync());
        SignatureFieldInfo signatureFieldInfo = (await PdfSignatureInspector.InspectAsync(stream)).Signatures[0];
        signatureFieldInfo.Signer.ShouldNotBeNull();
        signatureFieldInfo.Signer.KeyAlgorithm.ShouldBe("ECDSA");
        signatureFieldInfo.DigestAlgorithm.Name.ShouldBe("SHA-256");
        signatureFieldInfo.SignatureAlgorithm.Name.ShouldContain("ECDSA");
    }

    [Fact(DisplayName = "InspectAsync extracts signing time from PDF /M entry (PAdES omits CMS signingTime)")]
    public async Task InspectAsync_SignedPdf_ExtractsSigningTime()
    {
        using X509Certificate2 cert = CreateRsaCert();
        byte[] pdfBytes = TestPdfFactory.CreateMinimalPdf();
        using MemoryStream stream = new MemoryStream(await PadesSigner.Document(pdfBytes).WithCertificate(cert).SignAsync());
        SignatureFieldInfo signatureFieldInfo = (await PdfSignatureInspector.InspectAsync(stream)).Signatures[0];
        // PAdES signatures do not include the CMS signingTime attribute (ETSI EN 319 122-1 §5.2 prohibits it).
        signatureFieldInfo.SigningTime.ShouldBeNull("PAdES does not include the CMS signingTime attribute");
        // The PDF /M entry carries the declared signing time.
        signatureFieldInfo.PdfDeclaredSigningTime.ShouldNotBeNull("PDF /M entry should carry the declared signing time");
        signatureFieldInfo.PdfDeclaredSigningTime!.Value.ShouldBe(DateTimeOffset.UtcNow, TimeSpan.FromMinutes(5.0), "");
    }

    [Fact(DisplayName = "InspectAsync extracts embedded certificates")]
    public async Task InspectAsync_SignedPdf_ExtractsEmbeddedCertificates()
    {
        using X509Certificate2 cert = CreateRsaCert();
        byte[] pdfBytes = TestPdfFactory.CreateMinimalPdf();
        using MemoryStream stream = new MemoryStream(await PadesSigner.Document(pdfBytes).WithCertificate(cert).SignAsync());
        SignatureFieldInfo sig = (await PdfSignatureInspector.InspectAsync(stream)).Signatures[0];
        sig.EmbeddedCertificates.ShouldNotBeEmpty("");
        sig.EmbeddedCertificates.ShouldContain(c => c.Subject == sig.Signer!.Subject, "");
    }

    [Fact(DisplayName = "InspectAsync extracts HasSigningCertificateV2")]
    public async Task InspectAsync_SignedPdf_HasSigningCertificateV2()
    {
        using X509Certificate2 cert = CreateRsaCert();
        byte[] pdfBytes = TestPdfFactory.CreateMinimalPdf();
        using MemoryStream stream = new MemoryStream(await PadesSigner.Document(pdfBytes).WithCertificate(cert).SignAsync());
        (await PdfSignatureInspector.InspectAsync(stream)).Signatures[0].HasSigningCertificateV2.ShouldBeTrue("");
    }

    [Fact(DisplayName = "InspectAsync with multi-signature PDF extracts all signatures")]
    public async Task InspectAsync_MultiSignedPdf_ExtractsAllSignatures()
    {
        using X509Certificate2 cert1 = CreateRsaCert("CN=Signer One, O=Tests");
        using X509Certificate2 cert2 = CreateRsaCert("CN=Signer Two, O=Tests");
        byte[] pdfBytes = TestPdfFactory.CreateMinimalPdf();
        using MemoryStream stream = new MemoryStream(await PadesSigner.Document(await PadesSigner.Document(pdfBytes).WithCertificate(cert1).SignAsync()).WithCertificate(cert2).SignAsync());
        PdfInspectionResult pdfInspectionResult = await PdfSignatureInspector.InspectAsync(stream);
        pdfInspectionResult.Signatures.Count().ShouldBeGreaterThanOrEqualTo(2, "");
        pdfInspectionResult.Signatures.ShouldContain(s => s.Signer!.Subject.Contains("Signer One"), "");
        pdfInspectionResult.Signatures.ShouldContain(s => s.Signer!.Subject.Contains("Signer Two"), "");
    }

    [Fact(DisplayName = "InspectAsync extracts SubFilter correctly")]
    public async Task InspectAsync_SignedPdf_ExtractsSubFilter()
    {
        using X509Certificate2 cert = CreateRsaCert();
        byte[] pdfBytes = TestPdfFactory.CreateMinimalPdf();
        using MemoryStream stream = new MemoryStream(await PadesSigner.Document(pdfBytes).WithCertificate(cert).SignAsync());
        SignatureFieldInfo signatureFieldInfo = (await PdfSignatureInspector.InspectAsync(stream)).Signatures[0];
        signatureFieldInfo.SubFilter.ShouldNotBeNullOrEmpty("");
        signatureFieldInfo.IsDocumentTimestamp.ShouldBeFalse("");
    }

    [Fact(DisplayName = "InspectAsync extracts ByteRange")]
    public async Task InspectAsync_SignedPdf_ExtractsByteRange()
    {
        using X509Certificate2 cert = CreateRsaCert();
        byte[] pdfBytes = TestPdfFactory.CreateMinimalPdf();
        using MemoryStream stream = new MemoryStream(await PadesSigner.Document(pdfBytes).WithCertificate(cert).SignAsync());
        SignatureFieldInfo signatureFieldInfo = (await PdfSignatureInspector.InspectAsync(stream)).Signatures[0];
        signatureFieldInfo.ByteRange.ShouldNotBeNull("");
        signatureFieldInfo.ByteRange.IsValid.ShouldBeTrue("");
        signatureFieldInfo.ByteRange.Offset1.ShouldBe(0L, "");
    }

    [Fact(DisplayName = "InspectAsync contains CMS raw data")]
    public async Task InspectAsync_SignedPdf_ContainsCmsRawData()
    {
        using X509Certificate2 cert = CreateRsaCert();
        byte[] pdfBytes = TestPdfFactory.CreateMinimalPdf();
        using MemoryStream stream = new MemoryStream(await PadesSigner.Document(pdfBytes).WithCertificate(cert).SignAsync());
        SignatureFieldInfo signatureFieldInfo = (await PdfSignatureInspector.InspectAsync(stream)).Signatures[0];
        signatureFieldInfo.CmsRawData.Length.ShouldBeGreaterThan(0, "");
    }

    [Fact(DisplayName = "InspectAsync throws on non-seekable stream")]
    public async Task InspectAsync_NonSeekableStream_Throws()
    {
        NonSeekableStream nonSeekable = new NonSeekableStream(new MemoryStream(TestPdfFactory.CreateMinimalPdf()));
        try
        {
            Func<Task<PdfInspectionResult>> action = () => PdfSignatureInspector.InspectAsync(nonSeekable);
            var ex = await Should.ThrowAsync<ArgumentException>(async () => await action());
            ex.ParamName.ShouldBe("pdfStream");
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
        byte[] pdfBytes = TestPdfFactory.CreateMinimalPdf();
        using MemoryStream stream = new MemoryStream(await PadesSigner.Document(pdfBytes).WithCertificate(cert).AsCertification(CertificationLevel.NoChanges)
            .SignAsync());
        var result = await PdfSignatureInspector.InspectAsync(stream);
        result.Document.IsDocMdpLocked.ShouldBeTrue("");
        result.Document.DocMdpPermissionLevel.ShouldBe(1);
    }

    [Fact(DisplayName = "InspectAsync detects DocMDP permission levels correctly")]
    public async Task InspectAsync_CertifiedPdf_DetectsPermissionLevels()
    {
        using X509Certificate2 cert = CreateRsaCert();
        byte[] pdfBytes = TestPdfFactory.CreateMinimalPdf();

        // FormFilling (level 2) — locked
        using MemoryStream streamFf = new MemoryStream(await PadesSigner.Document(pdfBytes).WithCertificate(cert).AsCertification(CertificationLevel.FormFilling)
            .SignAsync());
        var resultFf = await PdfSignatureInspector.InspectAsync(streamFf);
        resultFf.Document.IsDocMdpLocked.ShouldBeTrue("");
        resultFf.Document.DocMdpPermissionLevel.ShouldBe(2);

        // FormFillingAndAnnotations (level 3) — not locked
        using MemoryStream streamAnn = new MemoryStream(await PadesSigner.Document(pdfBytes).WithCertificate(cert).AsCertification(CertificationLevel.FormFillingAndAnnotations)
            .SignAsync());
        var resultAnn = await PdfSignatureInspector.InspectAsync(streamAnn);
        resultAnn.Document.IsDocMdpLocked.ShouldBeFalse("");
        resultAnn.Document.DocMdpPermissionLevel.ShouldBe(3);
    }

    [Fact(DisplayName = "IsDigestAlgorithmDeprecated is false when SHA-256 is used")]
    public async Task InspectAsync_Sha256Digest_IsNotDeprecated()
    {
        using X509Certificate2 cert = CreateRsaCert();
        byte[] pdfBytes = TestPdfFactory.CreateMinimalPdf();
        using MemoryStream stream = new MemoryStream(await PadesSigner.Document(pdfBytes).WithCertificate(cert).SignAsync());
        SignatureFieldInfo sig = (await PdfSignatureInspector.InspectAsync(stream)).Signatures[0];
        sig.DigestAlgorithm.Name.ShouldBe("SHA-256");
        sig.IsDigestAlgorithmDeprecated.ShouldBeFalse("SHA-256 is not deprecated");
        sig.IsSignatureAlgorithmDeprecated.ShouldBeFalse("RSA-SHA256 is not deprecated");
    }

    [Fact(DisplayName = "IsDigestAlgorithmDeprecated is true when SHA-1 is used")]
    public void SignatureFieldInfo_Sha1Digest_IsDeprecated()
    {
        var sig = new SignatureFieldInfo
        {
            DigestAlgorithm = new AlgorithmInfo { Oid = "1.3.14.3.2.26", Name = "SHA-1" },
            SignatureAlgorithm = new AlgorithmInfo { Oid = "1.2.840.113549.1.1.5", Name = "RSA-SHA1" },
            IsDigestAlgorithmDeprecated = true,
            IsSignatureAlgorithmDeprecated = true
        };
        sig.IsDigestAlgorithmDeprecated.ShouldBeTrue("SHA-1 is deprecated per ISO 32000-2");
        sig.IsSignatureAlgorithmDeprecated.ShouldBeTrue("RSA-SHA1 is deprecated per ISO 32000-2");
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

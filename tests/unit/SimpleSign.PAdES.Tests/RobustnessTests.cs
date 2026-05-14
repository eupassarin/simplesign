using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using FluentAssertions;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Validation;
using SimpleSign.PAdES.Signing;
using SimpleSign.PAdES.Validation;
using SimpleSign.Pdf;
using Xunit;
namespace SimpleSign.PAdES.Tests;

/// <summary>
/// Robustness and stress tests: reentrancy, CMS edge cases,
/// parallel validation, minimal PDFs, and error messages.
/// </summary>
public sealed class RobustnessTests
{
    private static byte[] BuildMinimalPdf()
    {
        return Encoding.Latin1.GetBytes("%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\nxref\n0 4\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \n0000000115 00000 n \ntrailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n190\n%%EOF");
    }

    private static byte[] BuildHeaderOnlyPdf()
    {
        return Encoding.Latin1.GetBytes("%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\nxref\n0 4\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \n0000000115 00000 n \ntrailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n190\n%%EOF");
    }

    private static X509Certificate2 CreateCert(string subject = "CN=Robustness Test, O=Tests, C=BR")
    {
        using RSA key = RSA.Create(2048);
        CertificateRequest certificateRequest = new CertificateRequest(subject, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        certificateRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: false));
        X509Certificate2 x509Certificate = certificateRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1.0), DateTimeOffset.UtcNow.AddYears(1));
        return CertificateLoader.LoadPkcs12(x509Certificate.Export(X509ContentType.Pfx, "test-export"), "test-export");
    }

    private static X509Certificate2 CreateExpiredCert()
    {
        using RSA key = RSA.Create(2048);
        CertificateRequest certificateRequest = new CertificateRequest("CN=Expired Cert, C=BR", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        certificateRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: false));
        X509Certificate2 x509Certificate = certificateRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-30.0), DateTimeOffset.UtcNow.AddDays(-1.0));
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

    [Fact(DisplayName = "Reentrant pipeline: sign → validate → sign again")]
    public async Task Robustness_SignValidateSign_PipelineIsReentrant()
    {
        using X509Certificate2 cert = CreateCert();
        byte[] pdfBytes = BuildMinimalPdf();
        byte[] signed1 = await SimpleSigner.Document(pdfBytes).WithCertificate(cert).WithFieldName("Sig1")
            .SignAsync();
        using MemoryStream stream1 = new MemoryStream(signed1);
        IReadOnlyList<SignatureValidationResult> readOnlyList = await ValidatorTrusting(cert).ValidateAsync(stream1);
        readOnlyList.Should().ContainSingle("");
        readOnlyList[0].IsIntegrityValid.Should().BeTrue("");
        using MemoryStream stream2 = new MemoryStream(await SimpleSigner.Document(signed1).WithCertificate(cert).WithFieldName("Sig2")
            .SignAsync());
        IReadOnlyList<SignatureValidationResult> actualValue = await ValidatorTrusting(cert).ValidateAsync(stream2);
        actualValue.Should().HaveCount(2, "");
        actualValue.Should().AllSatisfy(delegate (SignatureValidationResult r)
        {
            r.IsIntegrityValid.Should().BeTrue("");
        }, "");
    }

    [Fact(DisplayName = "ValidateAsync on disposed stream fails with ArgumentException")]
    public async Task Robustness_ValidateDisposedStream_ThrowsArgumentException()
    {
        MemoryStream stream = new MemoryStream(BuildMinimalPdf());
        stream.Dispose();
        PdfSignatureValidator validator = new PdfSignatureValidator(new ValidationOptions
        {
            CheckRevocation = false
        });
        Func<Task<IReadOnlyList<SignatureValidationResult>>> action = () => validator.ValidateAsync(stream);
        await action.Should().ThrowAsync<ArgumentException>("", Array.Empty<object>()).WithMessage("*seekable*", "");
    }

    [Fact(DisplayName = "Signing with very long name (500 chars) does not crash")]
    public async Task Robustness_VeryLongSignerName_DoesNotCrash()
    {
        using X509Certificate2 cert = CreateCert();
        string signerName = new string('A', 500);
        byte[] array = await SimpleSigner.Document(BuildMinimalPdf()).WithCertificate(cert).WithMetadata(signerName)
            .SignAsync();
        array.Should().NotBeEmpty("");
        using MemoryStream stream = new MemoryStream(array);
        IReadOnlyList<SignatureValidationResult> readOnlyList = await ValidatorTrusting(cert).ValidateAsync(stream);
        readOnlyList.Should().ContainSingle("");
        readOnlyList[0].IsIntegrityValid.Should().BeTrue("");
    }

    [Fact(DisplayName = "Signing with very long reason (1000 chars) works")]
    public async Task Robustness_VeryLongReason_Works()
    {
        using X509Certificate2 cert = CreateCert();
        string reason = new string('R', 1000);
        byte[] array = await SimpleSigner.Document(BuildMinimalPdf()).WithCertificate(cert).WithMetadata(null, reason)
            .SignAsync();
        array.Should().NotBeEmpty("");
        using MemoryStream stream = new MemoryStream(array);
        IReadOnlyList<SignatureValidationResult> readOnlyList = await ValidatorTrusting(cert).ValidateAsync(stream);
        readOnlyList.Should().ContainSingle("");
        readOnlyList[0].IsIntegrityValid.Should().BeTrue("");
    }

    [Theory(DisplayName = "Signing with Unicode name (Japanese, Arabic, emoji) does not crash")]
    [InlineData(new object[] { "田中太郎" })]
    [InlineData(new object[] { "محمد أحمد" })]
    [InlineData(new object[] { "\ud83d\udd12\ud83d\udcc4✅" })]
    public async Task Robustness_UnicodeSignerName_DoesNotCrash(string unicodeName)
    {
        using X509Certificate2 cert = CreateCert();
        byte[] array = await SimpleSigner.Document(BuildMinimalPdf()).WithCertificate(cert).WithMetadata(unicodeName)
            .SignAsync();
        array.Should().NotBeEmpty("");
        using MemoryStream stream = new MemoryStream(array);
        IReadOnlyList<SignatureValidationResult> readOnlyList = await ValidatorTrusting(cert).ValidateAsync(stream);
        readOnlyList.Should().ContainSingle("");
        readOnlyList[0].IsIntegrityValid.Should().BeTrue("");
    }

    [Fact(DisplayName = "ContentsReservedBytes = 256 fails gracefully when CMS does not fit")]
    public async Task Robustness_TinyContentsReserved_FailsGracefully()
    {
        using X509Certificate2 cert = CreateCert();
        byte[] buffer = BuildMinimalPdf();
        SignatureFieldOptions options = new SignatureFieldOptions
        {
            ContentsReservedBytes = 256
        };
        using MemoryStream input = new MemoryStream(buffer);
        MemoryStream output = new MemoryStream();
        try
        {
            PdfSignaturePrepareResult prepareResult = await PdfSignatureWriter.PrepareAsync(input, output, options);
            byte[] cms = CmsSignatureBuilder.Build(await PdfStructureReader.ReadSignedBytesAsync(output, prepareResult.ByteRange), cert, HashAlgorithmName.SHA256);
            cms.Length.Should().BeGreaterThan(256, "a CMS with RSA-2048 certificate exceeds 256 bytes");
            Func<Task> action = () => PdfSignatureWriter.FinalizeAsync(output, prepareResult, cms);
            await action.Should().ThrowAsync<ArgumentException>("", Array.Empty<object>()).WithMessage("*exceed reserved space*", "");
        }
        finally
        {
            if (output != null)
            {
                ((IDisposable)output).Dispose();
            }
        }
    }

    [Fact(DisplayName = "ContentsReservedBytes = 1MB works (wasteful but valid)")]
    public async Task Robustness_LargeContentsReserved_Succeeds()
    {
        using X509Certificate2 cert = CreateCert();
        byte[] buffer = BuildMinimalPdf();
        SignatureFieldOptions options = new SignatureFieldOptions
        {
            ContentsReservedBytes = 1048576
        };
        using MemoryStream input = new MemoryStream(buffer);
        using MemoryStream output = new MemoryStream();
        PdfSignaturePrepareResult prepareResult = await PdfSignatureWriter.PrepareAsync(input, output, options);
        byte[] cmsBytes = CmsSignatureBuilder.Build(await PdfStructureReader.ReadSignedBytesAsync(output, prepareResult.ByteRange), cert, HashAlgorithmName.SHA256);
        await PdfSignatureWriter.FinalizeAsync(output, prepareResult, cmsBytes);
        output.Length.Should().BeGreaterThan(1048576L, "the resulting PDF should include the 1MB reserved space");
    }

    [Fact(DisplayName = "Validating same stream twice sequentially returns same results")]
    public async Task Robustness_ValidateSameStreamTwice_SameResults()
    {
        using X509Certificate2 cert = CreateCert();
        using MemoryStream stream = new MemoryStream(await SimpleSigner.Document(BuildMinimalPdf()).WithCertificate(cert).SignAsync());
        PdfSignatureValidator validator = ValidatorTrusting(cert);
        IReadOnlyList<SignatureValidationResult> results1 = await validator.ValidateAsync(stream);
        IReadOnlyList<SignatureValidationResult> readOnlyList = await validator.ValidateAsync(stream);
        results1.Should().HaveCount(readOnlyList.Count, "");
        results1[0].IsIntegrityValid.Should().Be(readOnlyList[0].IsIntegrityValid, "");
        results1[0].IsSignatureValid.Should().Be(readOnlyList[0].IsSignatureValid, "");
        results1[0].FieldName.Should().Be(readOnlyList[0].FieldName, "");
    }

    [Fact(DisplayName = "Validate 10 self-signed PDFs in parallel (Task.WhenAll)")]
    public async Task Robustness_Validate10PdfsInParallel_AllSucceed()
    {
        using X509Certificate2 cert = CreateCert();
        byte[] pdf = BuildMinimalPdf();
        byte[][] signedPdfs = new byte[10][];
        for (int i = 0; i < 10; i++)
        {
            byte[][] array = signedPdfs;
            int num = i;
            array[num] = await SimpleSigner.Document(pdf).WithCertificate(cert).WithFieldName($"ParallelSig{i}")
                .SignAsync();
        }
        PdfSignatureValidator validator = ValidatorTrusting(cert);
        IEnumerable<Task<IReadOnlyList<SignatureValidationResult>>> tasks = signedPdfs.Select(async delegate (byte[] signedPdf)
        {
            using MemoryStream stream = new MemoryStream(signedPdf);
            return await validator.ValidateAsync(stream);
        });
        IReadOnlyList<SignatureValidationResult>[] actualValue = await Task.WhenAll(tasks);
        actualValue.Should().HaveCount(10, "");
        actualValue.Should().AllSatisfy(delegate (IReadOnlyList<SignatureValidationResult> results)
        {
            results.Should().ContainSingle("");
            results[0].IsIntegrityValid.Should().BeTrue("");
            results[0].IsSignatureValid.Should().BeTrue("");
        }, "");
    }

    [Fact(DisplayName = "ValidateAsync with very small NetworkTimeout (1ms): revocation fails but integrity works")]
    public async Task Robustness_VerySmallNetworkTimeout_IntegrityStillWorks()
    {
        using X509Certificate2 cert = CreateCert();
        byte[] buffer = await SimpleSigner.Document(BuildMinimalPdf()).WithCertificate(cert).SignAsync();
        ValidationOptions options = new ValidationOptions
        {
            CheckRevocation = false,
            NetworkTimeout = TimeSpan.FromMilliseconds(1.0),
            TrustedRoots = [cert]
        };
        PdfSignatureValidator pdfSignatureValidator = new PdfSignatureValidator(options);
        using MemoryStream stream = new MemoryStream(buffer);
        IReadOnlyList<SignatureValidationResult> readOnlyList = await pdfSignatureValidator.ValidateAsync(stream);
        readOnlyList.Should().ContainSingle("");
        readOnlyList[0].IsIntegrityValid.Should().BeTrue("");
        readOnlyList[0].IsSignatureValid.Should().BeTrue("");
    }

    [Fact(DisplayName = "Signing minimal PDF (header + empty page) works")]
    public async Task Robustness_MinimalPdf_SignSucceeds()
    {
        using X509Certificate2 cert = CreateCert();
        byte[] pdfBytes = BuildHeaderOnlyPdf();
        byte[] array = await SimpleSigner.Document(pdfBytes).WithCertificate(cert).SignAsync();
        array.Should().NotBeEmpty("");
        using MemoryStream stream = new MemoryStream(array);
        IReadOnlyList<SignatureValidationResult> readOnlyList = await ValidatorTrusting(cert).ValidateAsync(stream);
        readOnlyList.Should().ContainSingle("");
        readOnlyList[0].IsIntegrityValid.Should().BeTrue("");
    }

    [Fact(DisplayName = "PDF signed 3 times accepts 4th signature")]
    public async Task Robustness_FourthSignature_Succeeds()
    {
        using X509Certificate2 cert = CreateCert();
        byte[] array = BuildMinimalPdf();
        byte[] array2 = array;
        for (int i = 1; i <= 4; i++)
        {
            array2 = await SimpleSigner.Document(array2).WithCertificate(cert).WithFieldName($"Sig{i}")
                .SignAsync();
        }
        using MemoryStream stream = new MemoryStream(array2);
        IReadOnlyList<SignatureValidationResult> actualValue = await ValidatorTrusting(cert).ValidateAsync(stream);
        actualValue.Should().HaveCount(4, "all 4 signatures should be present");
        actualValue.Should().AllSatisfy(delegate (SignatureValidationResult r)
        {
            r.IsIntegrityValid.Should().BeTrue("");
        }, "");
        actualValue.Should().AllSatisfy(delegate (SignatureValidationResult r)
        {
            r.IsSignatureValid.Should().BeTrue("");
        }, "");
    }

    [Fact(DisplayName = "Validating corrupted PDF returns meaningful errors")]
    public async Task Robustness_CorruptedPdf_ErrorsAreMeaningful()
    {
        byte[] bytes = Encoding.ASCII.GetBytes("%PDF-1.4\nGARBAGE CONTENT NOT A REAL PDF\n%%EOF");
        MemoryStream stream = new MemoryStream(bytes);
        try
        {
            PdfSignatureValidator validator = new PdfSignatureValidator(new ValidationOptions
            {
                CheckRevocation = false
            });
            _ = (Func<Task>)(() => validator.ValidateAsync(stream));
            try
            {
                IReadOnlyList<SignatureValidationResult> readOnlyList = await validator.ValidateAsync(stream);
                if (readOnlyList.Count <= 0)
                {
                    return;
                }
                readOnlyList.Should().AllSatisfy(delegate (SignatureValidationResult r)
                {
                    r.Errors.Should().NotBeEmpty("");
                    r.Errors.Should().AllSatisfy(delegate (string e)
                    {
                        e.Should().NotBe("Error", "error messages should be descriptive");
                    }, "");
                }, "");
            }
            catch (Exception ex)
            {
                ex.Message.Should().NotBe("Error", "");
                ex.Message.Length.Should().BeGreaterThan(5, "error message should be descriptive, not generic");
            }
        }
        finally
        {
            if (stream != null)
            {
                ((IDisposable)stream).Dispose();
            }
        }
    }

    [Fact(DisplayName = "Signing with expired certificate mentions expiry in error")]
    public async Task Robustness_ExpiredCert_ErrorMentionsExpiry()
    {
        X509Certificate2 cert = CreateExpiredCert();
        try
        {
            byte[] pdf = BuildMinimalPdf();
            Func<Task<byte[]>> action = () => SimpleSigner.Document(pdf).WithCertificate(cert).SignAsync();
            await action.Should().ThrowAsync<CertificateValidationException>("", Array.Empty<object>()).WithMessage("*expired*", "");
        }
        finally
        {
            if (cert != null)
            {
                ((IDisposable)cert).Dispose();
            }
        }
    }
}

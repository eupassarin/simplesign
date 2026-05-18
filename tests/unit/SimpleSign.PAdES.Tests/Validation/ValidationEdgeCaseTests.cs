using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Shouldly;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Revocation;
using SimpleSign.Core.Validation;
using SimpleSign.PAdES.Validation;
using SimpleSign.Pdf.Exceptions;
using SimpleSign.TestHelpers;
using Xunit;
namespace SimpleSign.PAdES.Tests.Validation;

/// <summary>
/// Edge-case tests for validation options, PdfSignatureValidator, network failures, and revocation.
/// </summary>
public sealed class ValidationEdgeCaseTests
{
    private static byte[] BuildMinimalPdf()
    {
        StringBuilder stringBuilder = new StringBuilder();
        stringBuilder.Append("%PDF-1.7\n");
        stringBuilder.Append("1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");
        stringBuilder.Append("2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\n");
        long value = stringBuilder.Length;
        stringBuilder.Append("xref\n0 3\n");
        stringBuilder.Append("0000000000 65535 f \n");
        stringBuilder.Append("0000000009 00000 n \n");
        stringBuilder.Append("0000000058 00000 n \n");
        stringBuilder.Append("trailer\n<< /Size 3 /Root 1 0 R >>\n");
        StringBuilder stringBuilder2 = stringBuilder;
        StringBuilder.AppendInterpolatedStringHandler handler = new StringBuilder.AppendInterpolatedStringHandler(16, 1, stringBuilder2);
        handler.AppendLiteral("startxref\n");
        handler.AppendFormatted(value);
        handler.AppendLiteral("\n%%EOF");
        stringBuilder2.Append(ref handler);
        return Encoding.Latin1.GetBytes(stringBuilder.ToString());
    }

    [Fact(DisplayName = "Default options: CheckRevocation=true, TrustSystemRoots=true")]
    public void ValidationOptions_DefaultBehavior_CheckRevocationAndTrustSystemRoots()
    {
        ValidationOptions validationOptions = ValidationOptions.Default;
        validationOptions.CheckRevocation.ShouldBeTrue("");
        validationOptions.TrustSystemRoots.ShouldBeTrue("");
        validationOptions.TrustedRoots.ShouldBeNull("");
        validationOptions.NetworkTimeout.ShouldBe(TimeSpan.FromSeconds(10.0), "");
    }

    [Fact(DisplayName = "CheckRevocation=false skips revocation checks")]
    public async Task ValidateAsync_CheckRevocationFalse_SkipsRevocationChecks()
    {
        using X509Certificate2 cert = TestCertificateFactory.CreateSelfSignedCert();
        byte[] pdfBytes = BuildMinimalPdf();
        byte[] buffer = await SimpleSigner.Document(pdfBytes).WithCertificate(cert).SignAsync();
        ValidationOptions options = new ValidationOptions
        {
            CheckRevocation = false
        };
        PdfSignatureValidator pdfSignatureValidator = new PdfSignatureValidator(options);
        IReadOnlyList<SignatureValidationResult> readOnlyList = await pdfSignatureValidator.ValidateAsync(new MemoryStream(buffer));
        readOnlyList.Count().ShouldBe(1, "");
        readOnlyList[0].IsNotRevoked.ShouldBeTrue("revocation check is disabled");
    }

    [Fact(DisplayName = "TrustSystemRoots=false without TrustedRoots rejects certificate chain")]
    public async Task ValidateAsync_NoSystemRootsNoCustomRoots_ChainFails()
    {
        using X509Certificate2 cert = TestCertificateFactory.CreateSelfSignedCert();
        byte[] pdfBytes = BuildMinimalPdf();
        byte[] buffer = await SimpleSigner.Document(pdfBytes).WithCertificate(cert).SignAsync();
        ValidationOptions options = new ValidationOptions
        {
            CheckRevocation = false,
            TrustSystemRoots = false,
            TrustedRoots = Array.Empty<X509Certificate2>()
        };
        PdfSignatureValidator pdfSignatureValidator = new PdfSignatureValidator(options);
        IReadOnlyList<SignatureValidationResult> readOnlyList = await pdfSignatureValidator.ValidateAsync(new MemoryStream(buffer));
        readOnlyList.Count().ShouldBe(1, "");
        readOnlyList[0].IsCertificateChainValid.ShouldBeFalse("no trusted roots available");
    }

    [Fact(DisplayName = "TrustSystemRoots=false with custom root accepts certificate issued by it")]
    public async Task ValidateAsync_CustomRootTrust_AcceptsCertSignedByRoot()
    {
        using X509Certificate2 ca = TestCertificateFactory.CreateCaCert();
        using RSA leafRsa = RSA.Create(2048);
        CertificateRequest certificateRequest = new CertificateRequest("CN=Leaf Edge", leafRsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        certificateRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: false));
        using X509Certificate2 leafPub = certificateRequest.Create(ca, DateTimeOffset.UtcNow.AddDays(-1.0), DateTimeOffset.UtcNow.AddYears(1), (ReadOnlySpan<byte>)new byte[2] { 16, 32 });
        using X509Certificate2 leaf = CertificateLoader.LoadPkcs12(leafPub.CopyWithPrivateKey(leafRsa).Export(X509ContentType.Pfx, "test-export"), "test-export");
        byte[] pdfBytes = BuildMinimalPdf();
        byte[] buffer = await SimpleSigner.Document(pdfBytes).WithCertificate(leaf).SignAsync();
        ValidationOptions options = new ValidationOptions
        {
            CheckRevocation = false,
            TrustSystemRoots = false,
            TrustedRoots = [ca]
        };
        PdfSignatureValidator pdfSignatureValidator = new PdfSignatureValidator(options);
        IReadOnlyList<SignatureValidationResult> readOnlyList = await pdfSignatureValidator.ValidateAsync(new MemoryStream(buffer));
        readOnlyList.Count().ShouldBe(1, "");
        readOnlyList[0].IsCertificateChainValid.ShouldBeTrue("CA is in custom trust store");
    }

    [Fact(DisplayName = "NetworkTimeout=1ms configures short timeout")]
    public void ValidationOptions_VeryShortTimeout_IsConfigurable()
    {
        ValidationOptions validationOptions = new ValidationOptions
        {
            NetworkTimeout = TimeSpan.FromMilliseconds(1.0)
        };
        validationOptions.NetworkTimeout.ShouldBe(TimeSpan.FromMilliseconds(1.0), "");
    }

    [Fact(DisplayName = "Empty stream (0 bytes) throws InvalidDataException")]
    public async Task ValidateAsync_EmptyStream_ThrowsInvalidDataException()
    {
        PdfSignatureValidator validator = new PdfSignatureValidator(new ValidationOptions
        {
            CheckRevocation = false
        });
        MemoryStream stream = new MemoryStream(Array.Empty<byte>());
        try
        {
            Func<Task> action = async () => await validator.ValidateAsync(stream);
            await Should.ThrowAsync<PdfStructureException>(action);
        }
        finally
        {
            if (stream != null)
            {
                ((IDisposable)stream).Dispose();
            }
        }
    }

    [Fact(DisplayName = "Stream with only PDF header throws exception")]
    public async Task ValidateAsync_OnlyPdfHeader_ThrowsException()
    {
        PdfSignatureValidator validator = new PdfSignatureValidator(new ValidationOptions
        {
            CheckRevocation = false
        });
        byte[] bytes = Encoding.ASCII.GetBytes("%PDF-1.4");
        MemoryStream stream = new MemoryStream(bytes);
        try
        {
            Func<Task> action = async () => await validator.ValidateAsync(stream);
            await Should.ThrowAsync<PdfStructureException>(action);
        }
        finally
        {
            if (stream != null)
            {
                ((IDisposable)stream).Dispose();
            }
        }
    }

    [Fact(DisplayName = "Non-PDF stream throws PdfStructureException")]
    public async Task ValidateAsync_NotAPdf_ThrowsInvalidDataException()
    {
        PdfSignatureValidator validator = new PdfSignatureValidator(new ValidationOptions
        {
            CheckRevocation = false
        });
        byte[] bytes = Encoding.ASCII.GetBytes("This is not a PDF file at all");
        MemoryStream stream = new MemoryStream(bytes);
        try
        {
            Func<Task> action = async () => await validator.ValidateAsync(stream);
            await Should.ThrowAsync<PdfStructureException>(action);
        }
        finally
        {
            if (stream != null)
            {
                ((IDisposable)stream).Dispose();
            }
        }
    }

    [Fact(DisplayName = "ValidateAsync with cancelled CancellationToken throws OperationCanceledException")]
    public async Task ValidateAsync_CancelledToken_ThrowsOperationCanceledException()
    {
        PdfSignatureValidator validator = new PdfSignatureValidator(new ValidationOptions
        {
            CheckRevocation = false
        });
        byte[] buffer = BuildMinimalPdf();
        MemoryStream stream = new MemoryStream(buffer);
        try
        {
            CancellationTokenSource cts = new CancellationTokenSource();
            try
            {
                cts.Cancel();
                Func<Task<IReadOnlyList<SignatureValidationResult>>> action = () => validator.ValidateAsync(stream, null, cts.Token);
                await Should.ThrowAsync<OperationCanceledException>(async () => await action());
            }
            finally
            {
                if (cts != null)
                {
                    ((IDisposable)cts).Dispose();
                }
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

    [Fact(DisplayName = "ValidateAsync called twice on same validator works")]
    public async Task ValidateAsync_CalledTwice_ValidatorIsReusable()
    {
        using X509Certificate2 cert = TestCertificateFactory.CreateSelfSignedCert();
        byte[] pdfBytes = BuildMinimalPdf();
        byte[] signedPdf = await SimpleSigner.Document(pdfBytes).WithCertificate(cert).SignAsync();
        PdfSignatureValidator validator = new PdfSignatureValidator(new ValidationOptions
        {
            CheckRevocation = false
        });
        IReadOnlyList<SignatureValidationResult> results1 = await validator.ValidateAsync(new MemoryStream(signedPdf));
        IReadOnlyList<SignatureValidationResult> readOnlyList = await validator.ValidateAsync(new MemoryStream(signedPdf));
        results1.Count().ShouldBe(1, "");
        readOnlyList.Count().ShouldBe(1, "");
        results1[0].IsIntegrityValid.ShouldBe(readOnlyList[0].IsIntegrityValid, "");
        results1[0].IsSignatureValid.ShouldBe(readOnlyList[0].IsSignatureValid, "");
    }

    [Fact(DisplayName = "CRL download HTTP 500 throws HttpRequestException")]
    public async Task CrlClient_Http500_ThrowsHttpRequestException()
    {
        X509Certificate2 cert = TestCertificateFactory.CreateSelfSignedCert();
        try
        {
            using HttpClient httpClient = MockHttpHandler.ForGetBytes(Array.Empty<byte>(), HttpStatusCode.InternalServerError);
            CrlClient client = new CrlClient(httpClient);
            Func<Task<bool>> action = () => client.CheckCrlAsync(cert, "http://example.com/test.crl", CancellationToken.None);
            await Should.ThrowAsync<HttpRequestException>(async () => await action());
        }
        finally
        {
            if (cert != null)
            {
                ((IDisposable)cert).Dispose();
            }
        }
    }

    [Fact(DisplayName = "CRL download HTTP 404 throws HttpRequestException")]
    public async Task CrlClient_Http404_ThrowsHttpRequestException()
    {
        X509Certificate2 cert = TestCertificateFactory.CreateSelfSignedCert();
        try
        {
            using HttpClient httpClient = MockHttpHandler.ForGetBytes(Array.Empty<byte>(), HttpStatusCode.NotFound);
            CrlClient client = new CrlClient(httpClient);
            Func<Task<bool>> action = () => client.CheckCrlAsync(cert, "http://example.com/test.crl", CancellationToken.None);
            await Should.ThrowAsync<HttpRequestException>(async () => await action());
        }
        finally
        {
            if (cert != null)
            {
                ((IDisposable)cert).Dispose();
            }
        }
    }

    [Fact(DisplayName = "OCSP timeout throws exception without hanging")]
    public async Task OcspClient_Timeout_ThrowsException()
    {
        using HttpClient httpClient = new HttpClient(new MockHttpHandler(async delegate
        {
            await Task.Delay(TimeSpan.FromSeconds(30.0));
            return new HttpResponseMessage(HttpStatusCode.OK);
        }));
        httpClient.Timeout = TimeSpan.FromMilliseconds(50.0);
        OcspClient client = new OcspClient(httpClient);
        X509Certificate2 cert = TestCertificateFactory.CreateSelfSignedCert();
        try
        {
            Func<Task<bool>> action = () => client.CheckOcspAsync(cert, "http://ocsp.test/", CancellationToken.None);
            await Should.ThrowAsync<TaskCanceledException>(async () => await action());
        }
        finally
        {
            if (cert != null)
            {
                ((IDisposable)cert).Dispose();
            }
        }
    }

    [Fact(DisplayName = "OCSP malformed response throws exception without crash")]
    public async Task OcspClient_MalformedResponse_ThrowsException()
    {
        byte[] responseBytes = new byte[6] { 255, 254, 0, 1, 2, 3 };
        using HttpClient httpClient = MockHttpHandler.ForPostBytes(responseBytes);
        OcspClient client = new OcspClient(httpClient);
        X509Certificate2 cert = TestCertificateFactory.CreateSelfSignedCert();
        try
        {
            Func<Task<bool>> action = () => client.CheckOcspAsync(cert, "http://ocsp.test/", CancellationToken.None);
            await Should.ThrowAsync<Exception>(async () => await action());
        }
        finally
        {
            if (cert != null)
            {
                ((IDisposable)cert).Dispose();
            }
        }
    }

    [Fact(DisplayName = "Unreachable CRL URL throws HttpRequestException")]
    public async Task CrlClient_ConnectionRefused_ThrowsHttpRequestException()
    {
        X509Certificate2 cert = TestCertificateFactory.CreateSelfSignedCert();
        try
        {
            using HttpClient httpClient = MockHttpHandler.Failing();
            CrlClient client = new CrlClient(httpClient);
            Func<Task<bool>> action = () => client.CheckCrlAsync(cert, "http://unreachable.test/test.crl", CancellationToken.None);
            await Should.ThrowAsync<HttpRequestException>(async () => await action());
        }
        finally
        {
            if (cert != null)
            {
                ((IDisposable)cert).Dispose();
            }
        }
    }

    [Fact(DisplayName = "Certificate without CRL Distribution Points returns null URL")]
    public void CrlClient_CertWithoutCdp_ReturnsNullUrl()
    {
        using X509Certificate2 cert = TestCertificateFactory.CreateSelfSignedCert();
        string? crlUrl = CrlClient.GetCrlUrl(cert);
        crlUrl.ShouldBeNull("certificate has no CRL Distribution Points extension");
    }

    [Fact(DisplayName = "Certificate without OCSP AIA returns null URL, falls back to CRL")]
    public void OcspClient_CertWithoutAia_ReturnsNullUrl()
    {
        using X509Certificate2 cert = TestCertificateFactory.CreateSelfSignedCert();
        string? ocspUrl = OcspClient.GetOcspUrl(cert);
        string? crlUrl = CrlClient.GetCrlUrl(cert);
        ocspUrl.ShouldBeNull("certificate has no AIA extension");
        crlUrl.ShouldBeNull("certificate has no CDP extension either");
    }

    [Fact(DisplayName = "CheckRevocation=true with self-signed cert treats indeterminate as warning, not error")]
    public async Task ValidateAsync_CheckRevocationTrue_IndeterminateIsWarningNotError()
    {
        // Self-signed cert has no OCSP/CRL URLs → revocation is indeterminate.
        // This MUST NOT make the signature invalid — indeterminate ≠ revoked.
        using X509Certificate2 cert = TestCertificateFactory.CreateSelfSignedCert();
        byte[] pdfBytes = BuildMinimalPdf();
        byte[] signed = await SimpleSigner.Document(pdfBytes).WithCertificate(cert).SignAsync();

        var validator = new PdfSignatureValidator(new ValidationOptions { CheckRevocation = true });
        var results = await validator.ValidateAsync(new MemoryStream(signed));

        results.Count().ShouldBe(1);
        var r = results[0];
        r.IsNotRevoked.ShouldBeTrue("indeterminate revocation (no OCSP/CRL URL) must NOT be treated as revoked");
        r.RevocationSource.ShouldBe(RevocationSource.Indeterminate);
        r.Warnings.ShouldContain(w => w.Contains("Revocation check could not be completed"),
            "indeterminate revocation should produce a warning");
    }

    [Fact(DisplayName = "Multi-signature: non-last signature ByteRange does not produce warnings")]
    public async Task ValidateAsync_MultiSignature_NonLastByteRangeNoWarning()
    {
        // Sign a PDF twice (incremental updates).
        // The first signature's ByteRange won't cover the full file — this is normal
        // and should NOT produce any warning or error.
        using X509Certificate2 cert = TestCertificateFactory.CreateSelfSignedCert();
        byte[] pdfBytes = BuildMinimalPdf();
        byte[] firstSign = await SimpleSigner.Document(pdfBytes).WithCertificate(cert).SignAsync();
        byte[] secondSign = await SimpleSigner.Document(firstSign).WithCertificate(cert).SignAsync();

        var validator = new PdfSignatureValidator(new ValidationOptions { CheckRevocation = false });
        var results = await validator.ValidateAsync(new MemoryStream(secondSign));

        results.Count().ShouldBeGreaterThanOrEqualTo(2);

        // First signature (non-last): should have NO ByteRange warnings
        var first = results[0];
        first.Warnings.ShouldNotContain(w => w.Contains("ByteRange does not cover entire PDF"),
            "non-last signatures are expected to have ByteRange < file size per ISO 32000");

        // Last signature: should have no ByteRange error either (it covers full file)
        var last = results[^1];
        last.Errors.ShouldNotContain(e => e.Contains("ByteRange does not cover entire PDF"),
            "last signature's ByteRange should cover the full file");
    }

    [Fact(DisplayName = "RevocationChecker without OCSP/CRL throws ValidationException")]
    public async Task RevocationChecker_NeitherOcspNorCrl_ThrowsInvalidOperation()
    {
        X509Certificate2 cert = TestCertificateFactory.CreateSelfSignedCert();
        try
        {
            RevocationChecker checker = new RevocationChecker(new OcspClient(new HttpClient()), new CrlClient(new HttpClient()));
            Func<Task<(bool, SimpleSign.Core.Validation.RevocationSource)>> action = () => checker.CheckRevocationAsync(cert, [cert], Array.Empty<byte[]>(), CancellationToken.None);
            var ex = await Should.ThrowAsync<ValidationException>(async () => await action());
            ex.Message.ShouldContain("no OCSP or CRL URL");
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

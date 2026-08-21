using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Shouldly;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Http;
using SimpleSign.Core.Signing;
using SimpleSign.Core.Validation;
using SimpleSign.PAdES.Inspection;
using SimpleSign.PAdES.Validation;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.PAdES.Tests.Signing;

[Trait("Category", "Unit")]
public sealed class PadesTStandaloneTests
{
    private static X509Certificate2 CreateRsaCert()
    {
        using RSA key = RSA.Create(2048);
        var req = new CertificateRequest("CN=PAdES-T Test", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: false));
        var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        return CertificateLoader.LoadPkcs12(cert.Export(X509ContentType.Pfx, "export"), "export");
    }

    private static PdfSignatureValidator ValidatorNoRevocation(params X509Certificate2[] certs)
    {
        return new PdfSignatureValidator(new ValidationOptions
        {
            CheckRevocation = false,
            TrustedRoots = [.. certs]
        });
    }

    [Fact(DisplayName = "PAdES-T (B-B + timestamp, no LTV) validates integrity and signature")]
    public async Task SignAsync_PadesT_ValidatesCorrectly()
    {
        using var cert = CreateRsaCert();
        byte[] pdf = TestPdfFactory.CreateMinimalPdf();
        using var stream = new MemoryStream(await PadesSigner
            .Document(pdf).WithCertificate(cert)
            .WithLevel(AdesBaselineProfile.Timestamped(new TimestampOptions(new Uri("http://timestamp.digicert.com"))))
            .SignAsync());

        var results = await ValidatorNoRevocation(cert).ValidateAsync(stream);
        results.Count.ShouldBe(1);
        results[0].IsIntegrityValid.ShouldBeTrue();
        results[0].IsSignatureValid.ShouldBeTrue();
    }

    [Fact(DisplayName = "PAdES-T is detected as BaselineT by ConformanceDetector")]
    public async Task SignAsync_PadesT_DetectedAsBaselineT()
    {
        using var cert = CreateRsaCert();
        byte[] pdf = TestPdfFactory.CreateMinimalPdf();
        byte[] signed = await PadesSigner
            .Document(pdf).WithCertificate(cert)
            .WithLevel(AdesBaselineProfile.Timestamped(new TimestampOptions(new Uri("http://timestamp.digicert.com"))))
            .SignAsync();

        var info = await PdfSignatureInspector.InspectAsync(new MemoryStream(signed));
        var level = ConformanceDetector.Detect(info.Signatures[0], info.Document, info.Signatures);
        level.ShouldBe(PAdESConformanceLevel.BaselineT);
    }

    [Fact(DisplayName = "PAdES-T without DSS has no SecurityStore")]
    public async Task SignAsync_PadesT_HasNoDss()
    {
        using var cert = CreateRsaCert();
        byte[] pdf = TestPdfFactory.CreateMinimalPdf();
        byte[] signed = await PadesSigner
            .Document(pdf).WithCertificate(cert)
            .WithLevel(AdesBaselineProfile.Timestamped(new TimestampOptions(new Uri("http://timestamp.digicert.com"))))
            .SignAsync();

        var info = await PdfSignatureInspector.InspectAsync(new MemoryStream(signed));
        info.Document.SecurityStore.ShouldBeNull();
    }

    [Fact(DisplayName = "PAdES-T with LTV stays valid but stays BaselineT (no revocation endpoints)")]
    public async Task SignAsync_PadesT_WithLtv_StaysValid()
    {
        using var cert = CreateRsaCert();
        byte[] pdf = TestPdfFactory.CreateMinimalPdf();
        // A failing revocation provider guarantees no revocation material can be
        // collected (B-LT requires revocation values), so the best-effort downgrade
        // stays at B-T with a real signature timestamp and no DSS.
        using var failingRevocation = MockHttpHandler.Failing();
        var result = await PadesSigner
            .Document(pdf).WithCertificate(cert)
            .WithLevel(AdesBaselineProfile.LongTerm(
                new TimestampOptions(new Uri("http://timestamp.digicert.com")),
                new LongTermValidationOptions(new SingleClientProvider(failingRevocation)),
                failureBehavior: SigningLevelFailureBehavior.ReturnLowerLevel))
            .SignWithDetailsAsync();

        // Self-signed certs have no revocation endpoints, so LTV cannot be embedded.
        // With best-effort downgrade the artifact stays at B-T and the downgrade is reported.
        result.AchievedLevel.ShouldBe(AdesBaselineLevel.Timestamped);
        result.HasLongTermValidationMaterial.ShouldBeFalse();
        result.Warnings.ShouldContain(w => w.Code == SigningWarningCode.LevelDowngraded);

        var results = await ValidatorNoRevocation(cert).ValidateAsync(new MemoryStream(result.SignedArtifact));
        results.Count.ShouldBe(1);
        results[0].IsIntegrityValid.ShouldBeTrue();
        results[0].IsSignatureValid.ShouldBeTrue();

        var info = await PdfSignatureInspector.InspectAsync(new MemoryStream(result.SignedArtifact));
        info.Document.SecurityStore.ShouldBeNull();
        var level = ConformanceDetector.Detect(info.Signatures[0], info.Document, info.Signatures);
        level.ShouldBe(PAdESConformanceLevel.BaselineT);
    }
}

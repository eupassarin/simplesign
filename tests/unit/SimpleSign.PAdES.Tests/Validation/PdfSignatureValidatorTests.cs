using System.Formats.Asn1;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Moq;
using Shouldly;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Extensions;
using SimpleSign.Core.Revocation;
using SimpleSign.Core.Validation;
using SimpleSign.PAdES.Validation;
using SimpleSign.TestHelpers;
using Xunit;
namespace SimpleSign.PAdES.Tests.Validation;

/// <summary>
/// Unit tests for PdfSignatureValidator and the internal CMS parser.
/// Uses self-signed certificates and CMSs generated in memory.
/// </summary>
[Trait("Category", "Unit")]
public sealed class PdfSignatureValidatorTests
{
    private static X509Certificate2 CreateRsaCertWithKey(string subject = "CN=Validator Test")
    {
        using RSA key = RSA.Create(2048);
        CertificateRequest certificateRequest = new CertificateRequest(subject, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        certificateRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: false));
        X509Certificate2 x509Certificate = certificateRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1.0), DateTimeOffset.UtcNow.AddYears(1));
        return CertificateLoader.LoadPkcs12(x509Certificate.Export(X509ContentType.Pfx, "test-export"), "test-export");
    }

    [Fact(DisplayName = "Default options have expected values")]
    public void ValidationOptions_Default_HasExpectedValues()
    {
        ValidationOptions validationOptions = ValidationOptions.Default;
        validationOptions.CheckRevocation.ShouldBeTrue("");
        validationOptions.TrustSystemRoots.ShouldBeTrue("");
        validationOptions.NetworkTimeout.ShouldBe(TimeSpan.FromSeconds(10.0), "");
    }

    [Fact(DisplayName = "Result with all fields valid returns IsValid true")]
    public void SignatureValidationResult_AllValid_IsValidReturnsTrue()
    {
        SignatureValidationResult signatureValidationResult = new SignatureValidationResult
        {
            IsIntegrityValid = true,
            IsSignatureValid = true,
            IsCertificateChainValid = true,
            IsNotRevoked = true
        };
        signatureValidationResult.IsValid.ShouldBeTrue("");
    }

    [Fact(DisplayName = "Invalid integrity makes IsValid return false")]
    public void SignatureValidationResult_IntegrityInvalid_IsValidReturnsFalse()
    {
        SignatureValidationResult signatureValidationResult = new SignatureValidationResult
        {
            IsIntegrityValid = false,
            IsSignatureValid = true,
            IsCertificateChainValid = true
        };
        signatureValidationResult.IsValid.ShouldBeFalse("");
    }

    [Fact(DisplayName = "Result ToString contains field name")]
    public void SignatureValidationResult_ToString_ContainsFieldName()
    {
        SignatureValidationResult signatureValidationResult = new SignatureValidationResult
        {
            FieldName = "Sig1"
        };
        signatureValidationResult.ToString().ShouldContain("Sig1");
    }

    [Fact(DisplayName = "New enrichment properties default to null")]
    public void SignatureValidationResult_NewProperties_DefaultToNull()
    {
        SignatureValidationResult result = new SignatureValidationResult();
        result.PolicyLevel.ShouldBeNull();
        result.SignerId.ShouldBeNull();
        result.SignerIdType.ShouldBeNull();
        result.ChainValidationRegion.ShouldBeNull();
        result.ChainValidationMetadata.ShouldBeNull();
    }

    [Fact(DisplayName = "New enrichment properties can be set via init")]
    public void SignatureValidationResult_NewProperties_CanBeSet()
    {
        var metadata = new Dictionary<string, string> { ["key"] = "value" };
        SignatureValidationResult result = new SignatureValidationResult
        {
            PolicyLevel = "A3",
            SignerId = "123456789",
            SignerIdType = "CPF",
            ChainValidationRegion = "BR",
            ChainValidationMetadata = metadata
        };

        result.PolicyLevel.ShouldBe("A3");
        result.SignerId.ShouldBe("123456789");
        result.SignerIdType.ShouldBe("CPF");
        result.ChainValidationRegion.ShouldBe("BR");
        result.ChainValidationMetadata.ShouldBe(metadata);
    }

    [Fact(DisplayName = "IsValid is true when chain trust warning set (country provider override)")]
    public void SignatureValidationResult_IsValid_ChainTrustWarning_WithIntegrity()
    {
        SignatureValidationResult result = new SignatureValidationResult
        {
            IsIntegrityValid = true,
            IsSignatureValid = true,
            IsCertificateChainValid = false,
            IsChainTrustWarning = true,
            IsNotRevoked = true
        };
        result.IsValid.ShouldBeTrue("chain trust warning from country provider override makes the signature valid");
    }

    [Fact(DisplayName = "IsValid is false when chain invalid and no trust warning")]
    public void SignatureValidationResult_IsValid_ChainInvalid_WithoutTrustWarning()
    {
        SignatureValidationResult result = new SignatureValidationResult
        {
            IsIntegrityValid = true,
            IsSignatureValid = true,
            IsCertificateChainValid = false,
            IsChainTrustWarning = false,
            IsNotRevoked = true
        };
        result.IsValid.ShouldBeFalse();
    }

    [Fact(DisplayName = "Null stream throws ArgumentNullException")]
    public async Task ValidateAsync_NullStream_ThrowsArgumentNullException()
    {
        PdfSignatureValidator validator = new PdfSignatureValidator(new ValidationOptions
        {
            CheckRevocation = false
        });
        await Assert.ThrowsAsync<ArgumentNullException>(() => validator.ValidateAsync(null!));
    }

    [Fact(DisplayName = "PDF without signatures returns empty list")]
    public async Task ValidateAsync_PdfWithoutSignatures_ReturnsEmptyList()
    {
        byte[] bytes = Encoding.Latin1.GetBytes("%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\nxref\n0 2\n0000000000 65535 f \n0000000009 00000 n \ntrailer\n<< /Size 2 /Root 1 0 R >>\nstartxref\n60\n%%EOF");
        using MemoryStream stream = new MemoryStream(bytes);
        PdfSignatureValidator pdfSignatureValidator = new PdfSignatureValidator(new ValidationOptions
        {
            CheckRevocation = false
        });
        (await pdfSignatureValidator.ValidateAsync(stream)).ShouldBeEmpty("");
    }

    [Fact(DisplayName = "Empty field name throws ArgumentException")]
    public async Task ValidateFieldAsync_EmptyFieldName_ThrowsArgumentException()
    {
        PdfSignatureValidator validator = new PdfSignatureValidator();
        MemoryStream stream = new MemoryStream(new byte[10]);
        try
        {
            await Assert.ThrowsAsync<ArgumentException>(() => validator.ValidateFieldAsync(stream, ""));
        }
        finally
        {
            if (stream != null)
            {
                ((IDisposable)stream).Dispose();
            }
        }
    }

    [Fact(DisplayName = "Tampered signed PDF fails integrity check")]
    public async Task ValidateAsync_SignedPdfWithTamperedContent_IntegrityFails()
    {
        using X509Certificate2 cert = CreateRsaCertWithKey();
        byte[] array = BuildMinimalPdfForSigning();
        using (new MemoryStream(array))
        {
            using MemoryStream outputStream = new MemoryStream();
            await PadesSigner.Document(array).WithCertificate(cert).SignAsync(outputStream);
            byte[] array2 = outputStream.ToArray();
            array2[50] ^= byte.MaxValue;
            using MemoryStream tamperedStream = new MemoryStream(array2);
            PdfSignatureValidator pdfSignatureValidator = new PdfSignatureValidator(new ValidationOptions
            {
                CheckRevocation = false
            });
            IReadOnlyList<SignatureValidationResult> readOnlyList = await pdfSignatureValidator.ValidateAsync(tamperedStream);
            readOnlyList.Count().ShouldBe(1, "");
            readOnlyList[0].IsIntegrityValid.ShouldBeFalse("");
        }
    }

    [Fact(DisplayName = "Untampered signed PDF has valid signature")]
    public async Task ValidateAsync_SignedPdf_SignatureIsValid()
    {
        using X509Certificate2 cert = CreateRsaCertWithKey();
        byte[] pdfBytes = BuildMinimalPdfForSigning();
        using MemoryStream outputStream = new MemoryStream();
        await PadesSigner.Document(pdfBytes).WithCertificate(cert).SignAsync(outputStream);
        byte[] buffer = outputStream.ToArray();
        using MemoryStream signedStream = new MemoryStream(buffer);
        PdfSignatureValidator pdfSignatureValidator = new PdfSignatureValidator(new ValidationOptions
        {
            CheckRevocation = false
        });
        IReadOnlyList<SignatureValidationResult> readOnlyList = await pdfSignatureValidator.ValidateAsync(signedStream);
        readOnlyList.Count().ShouldBe(1, "");
        readOnlyList[0].IsIntegrityValid.ShouldBeTrue("document was not tampered");
        readOnlyList[0].IsSignatureValid.ShouldBeTrue("signature was created with the same cert");
        readOnlyList[0].SignerCertificate.ShouldNotBeNull("");
    }

    private static byte[] BuildMinimalPdfForSigning()
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

    [Fact(DisplayName = "Serial in issuer DN does not false positive in CRL")]
    public void IsSerialInCrl_SerialInIssuerDn_DoesNotFalsePositive()
    {
        using RSA key = RSA.Create(2048);
        CertificateRequest certificateRequest = new CertificateRequest("CN=Test CA", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        certificateRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(certificateAuthority: true, hasPathLengthConstraint: false, 0, critical: true));
        using X509Certificate2 x509Certificate = certificateRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1.0), DateTimeOffset.UtcNow.AddYears(10));
        using RSA key2 = RSA.Create(2048);
        CertificateRequest certificateRequest2 = new CertificateRequest("CN=Subject", key2, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using X509Certificate2 x509Certificate2 = certificateRequest2.Create(x509Certificate, DateTimeOffset.UtcNow.AddDays(-1.0), DateTimeOffset.UtcNow.AddYears(1), [1, 2, 3]);
        AsnWriter asnWriter = new AsnWriter(AsnEncodingRules.DER);
        using (asnWriter.PushSequence())
        {
            using (asnWriter.PushSequence())
            {
                using (asnWriter.PushSequence())
                {
                    asnWriter.WriteObjectIdentifier("1.2.840.113549.1.1.11");
                }
                asnWriter.WriteEncodedValue(x509Certificate.IssuerName.RawData);
                asnWriter.WriteUtcTime(DateTimeOffset.UtcNow.AddDays(-1.0));
            }
            using (asnWriter.PushSequence())
            {
                asnWriter.WriteObjectIdentifier("1.2.840.113549.1.1.11");
            }
            asnWriter.WriteBitString([0, 1, 2, 3]);
        }
        byte[] array = asnWriter.Encode();
        MethodInfo? method = typeof(CrlClient).GetMethod("IsSerialInCrl", BindingFlags.Static | BindingFlags.NonPublic);
        method.ShouldNotBeNull("IsSerialInCrl should exist as a private static method");
        bool? actualValue = (bool?)method!.Invoke(null, [x509Certificate2, array, null, null, null]);
        actualValue!.Value.ShouldBeFalse();
    }

    [Fact(DisplayName = "Expired CRL returns null indicating untrusted")]
    public void IsSerialInCrl_ExpiredCrl_ReturnsNull()
    {
        using RSA key = RSA.Create(2048);
        CertificateRequest certificateRequest = new CertificateRequest("CN=Test CA", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        certificateRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(certificateAuthority: true, hasPathLengthConstraint: false, 0, critical: true));
        using X509Certificate2 x509Certificate = certificateRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-365.0), DateTimeOffset.UtcNow.AddYears(10));
        using RSA key2 = RSA.Create(2048);
        CertificateRequest certificateRequest2 = new CertificateRequest("CN=Subject", key2, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using X509Certificate2 x509Certificate2 = certificateRequest2.Create(x509Certificate, DateTimeOffset.UtcNow.AddDays(-365.0), DateTimeOffset.UtcNow.AddYears(1), [1, 2, 3]);
        AsnWriter asnWriter = new AsnWriter(AsnEncodingRules.DER);
        using (asnWriter.PushSequence())
        {
            using (asnWriter.PushSequence())
            {
                using (asnWriter.PushSequence())
                {
                    asnWriter.WriteObjectIdentifier("1.2.840.113549.1.1.11");
                }
                asnWriter.WriteEncodedValue(x509Certificate.IssuerName.RawData);
                asnWriter.WriteUtcTime(DateTimeOffset.UtcNow.AddDays(-30.0));
                asnWriter.WriteUtcTime(DateTimeOffset.UtcNow.AddDays(-1.0));
            }
            using (asnWriter.PushSequence())
            {
                asnWriter.WriteObjectIdentifier("1.2.840.113549.1.1.11");
            }
            asnWriter.WriteBitString([0, 1, 2, 3]);
        }
        byte[] array = asnWriter.Encode();
        MethodInfo? method = typeof(CrlClient).GetMethod("IsSerialInCrl", BindingFlags.Static | BindingFlags.NonPublic);
        method.ShouldNotBeNull("");
        bool? actualValue = (bool?)method!.Invoke(null, [x509Certificate2, array, null, null, null]);
        actualValue.ShouldBeNull("expired CRL is not trustworthy — should return null to fetch updated CRL");
    }

    [Fact(DisplayName = "Certificate without NonRepudiation signs without throwing")]
    public async Task SignAsync_CertWithoutNonRepudiation_DoesNotThrow()
    {
        using RSA rsa = RSA.Create(2048);
        CertificateRequest certificateRequest = new CertificateRequest("CN=No NonRepudiation", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        certificateRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: false));
        X509Certificate2 cert = CertificateLoader.LoadPkcs12(certificateRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1.0), DateTimeOffset.UtcNow.AddYears(1)).Export(X509ContentType.Pfx, "test-export"), "test-export");
        try
        {
            byte[] buffer = BuildMinimalPdfForSigning();
            MemoryStream input = new MemoryStream(buffer);
            MemoryStream output = new MemoryStream();
            Func<Task> action = () => PadesSigner.Document(input).WithCertificate(cert).SignAsync(output);
            await Should.NotThrowAsync(action);
        }
        finally
        {
            if (cert != null)
            {
                ((IDisposable)cert).Dispose();
            }
        }
    }

    [Fact(DisplayName = "PDF without LTV returns empty without throwing")]
    public async Task ValidateAsync_NonLtvPdf_ReturnsEmptyWithoutException()
    {
        byte[] buffer = BuildMinimalPdfForSigning();
        MemoryStream pdfStream = new MemoryStream(buffer);
        PdfSignatureValidator pdfSignatureValidator = new PdfSignatureValidator();
        (await pdfSignatureValidator.ValidateAsync(pdfStream)).ShouldBeEmpty("minimal PDF without signatures has no fields to validate");
    }

    // ── Chain Validation Provider Integration ─────────────────────────────────

    [Fact(DisplayName = "Constructor with chain validation providers stores them")]
    public void Constructor_WithChainValidationProviders_StoresProviders()
    {
        var mockProvider = new Mock<IChainValidationProvider>();
        mockProvider.Setup(p => p.RegionCode).Returns("XX");

        var validator = new PdfSignatureValidator(
            new ValidationOptions { CheckRevocation = false },
            httpClient: null,
            logger: null,
            trustAnchorProviders: null,
            chainValidationProviders: [mockProvider.Object]);

        validator.ShouldNotBeNull();
    }

    [Fact(DisplayName = "Constructor with country extensions extracts trust anchors and chain validators")]
    public void Constructor_WithCountryExtensions_ExtractsProviders()
    {
        var mockProvider = new Mock<IChainValidationProvider>();
        mockProvider.Setup(p => p.RegionCode).Returns("XX");
        var mockAnchor = new Mock<ITrustAnchorProvider>();

        var mockExtension = new Mock<ICountryExtension>();
        mockExtension.Setup(e => e.RegionCode).Returns("XX");
        mockExtension.Setup(e => e.DisplayName).Returns("Test Extension");
        mockExtension.Setup(e => e.TrustAnchorProviders).Returns([mockAnchor.Object]);
        mockExtension.Setup(e => e.ChainValidationProviders).Returns([mockProvider.Object]);

        var validator = new PdfSignatureValidator(
            new ValidationOptions { CheckRevocation = false },
            httpClient: null,
            logger: null,
            countryExtensions: [mockExtension.Object]);

        validator.ShouldNotBeNull();
    }

    [Fact(DisplayName = "Validation with matching provider enriches result with PolicyLevel")]
    public async Task ValidateAsync_WithMatchingProvider_EnrichesResult()
    {
        using X509Certificate2 cert = CreateRsaCertWithKey();
        byte[] pdfBytes = BuildMinimalPdfForSigning();
        using MemoryStream outputStream = new MemoryStream();
        await PadesSigner.Document(pdfBytes).WithCertificate(cert).SignAsync(outputStream);

        var mockProvider = new Mock<IChainValidationProvider>();
        mockProvider.Setup(p => p.RegionCode).Returns("XX");
        mockProvider.Setup(p => p.CanValidate(It.IsAny<X509Certificate2>())).Returns(true);
        mockProvider.Setup(p => p.ValidateAsync(It.IsAny<X509Certificate2>(), It.IsAny<IReadOnlyList<X509Certificate2>>()))
            .ReturnsAsync(new ChainValidationResult
            {
                IsTrusted = true,
                RegionCode = "XX",
                PolicyLevel = "A3",
                SignerId = "123456",
                SignerIdType = "CPF"
            });

        var validator = new PdfSignatureValidator(
            new ValidationOptions { CheckRevocation = false, TrustedRoots = [cert] },
            httpClient: null,
            logger: null,
            trustAnchorProviders: null,
            chainValidationProviders: [mockProvider.Object]);

        using MemoryStream signedStream = new MemoryStream(outputStream.ToArray());
        IReadOnlyList<SignatureValidationResult> results = await validator.ValidateAsync(signedStream);
        results.ShouldHaveSingleItem();
        results[0].PolicyLevel.ShouldBe("A3");
        results[0].SignerId.ShouldBe("123456");
        results[0].SignerIdType.ShouldBe("CPF");
        results[0].ChainValidationRegion.ShouldBe("XX");
    }

    [Fact(DisplayName = "Validation with non-matching provider is ignored")]
    public async Task ValidateAsync_WithNonMatchingProvider_Ignored()
    {
        using X509Certificate2 cert = CreateRsaCertWithKey();
        byte[] pdfBytes = BuildMinimalPdfForSigning();
        using MemoryStream outputStream = new MemoryStream();
        await PadesSigner.Document(pdfBytes).WithCertificate(cert).SignAsync(outputStream);

        var mockProvider = new Mock<IChainValidationProvider>();
        mockProvider.Setup(p => p.RegionCode).Returns("XX");
        mockProvider.Setup(p => p.CanValidate(It.IsAny<X509Certificate2>())).Returns(false);
        mockProvider.Setup(p => p.ValidateAsync(It.IsAny<X509Certificate2>(), It.IsAny<IReadOnlyList<X509Certificate2>>()))
            .ReturnsAsync(new ChainValidationResult
            {
                IsTrusted = true,
                RegionCode = "XX",
                PolicyLevel = "ShouldNotAppear"
            });

        var validator = new PdfSignatureValidator(
            new ValidationOptions { CheckRevocation = false, TrustedRoots = [cert] },
            httpClient: null,
            logger: null,
            trustAnchorProviders: null,
            chainValidationProviders: [mockProvider.Object]);

        using MemoryStream signedStream = new MemoryStream(outputStream.ToArray());
        IReadOnlyList<SignatureValidationResult> results = await validator.ValidateAsync(signedStream);
        results[0].PolicyLevel.ShouldBeNull("non-matching provider must be ignored");
        results[0].ChainValidationRegion.ShouldBeNull();
    }

    [Fact(DisplayName = "Validation with untrusted provider adds errors to result")]
    public async Task ValidateAsync_ProviderNotTrusted_AddsErrorsToResult()
    {
        using X509Certificate2 cert = CreateRsaCertWithKey();
        byte[] pdfBytes = BuildMinimalPdfForSigning();
        using MemoryStream outputStream = new MemoryStream();
        await PadesSigner.Document(pdfBytes).WithCertificate(cert).SignAsync(outputStream);

        var mockProvider = new Mock<IChainValidationProvider>();
        mockProvider.Setup(p => p.RegionCode).Returns("XX");
        mockProvider.Setup(p => p.CanValidate(It.IsAny<X509Certificate2>())).Returns(true);
        mockProvider.Setup(p => p.ValidateAsync(It.IsAny<X509Certificate2>(), It.IsAny<IReadOnlyList<X509Certificate2>>()))
            .ReturnsAsync(new ChainValidationResult
            {
                IsTrusted = false,
                RegionCode = "XX",
                Errors = ["Policy not recognised"]
            });

        var validator = new PdfSignatureValidator(
            new ValidationOptions { CheckRevocation = false, TrustedRoots = [cert] },
            httpClient: null,
            logger: null,
            trustAnchorProviders: null,
            chainValidationProviders: [mockProvider.Object]);

        using MemoryStream signedStream = new MemoryStream(outputStream.ToArray());
        IReadOnlyList<SignatureValidationResult> results = await validator.ValidateAsync(signedStream);
        results[0].Errors.ShouldContain(e => e.Contains("Policy not recognised"));
    }

    [Fact(DisplayName = "Provider throwing exception logs warning and continues")]
    public async Task ValidateAsync_ProviderThrows_LogsWarningAndContinues()
    {
        using X509Certificate2 cert = CreateRsaCertWithKey();
        byte[] pdfBytes = BuildMinimalPdfForSigning();
        using MemoryStream outputStream = new MemoryStream();
        await PadesSigner.Document(pdfBytes).WithCertificate(cert).SignAsync(outputStream);

        var mockProvider = new Mock<IChainValidationProvider>();
        mockProvider.Setup(p => p.RegionCode).Returns("XX");
        mockProvider.Setup(p => p.CanValidate(It.IsAny<X509Certificate2>())).Returns(true);
        mockProvider.Setup(p => p.ValidateAsync(It.IsAny<X509Certificate2>(), It.IsAny<IReadOnlyList<X509Certificate2>>()))
            .ThrowsAsync(new InvalidOperationException("Simulated provider failure"));

        var validator = new PdfSignatureValidator(
            new ValidationOptions { CheckRevocation = false, TrustedRoots = [cert] },
            httpClient: null,
            logger: null,
            trustAnchorProviders: null,
            chainValidationProviders: [mockProvider.Object]);

        using MemoryStream signedStream = new MemoryStream(outputStream.ToArray());
        IReadOnlyList<SignatureValidationResult> results = await validator.ValidateAsync(signedStream);

        // Validation should complete without throwing
        results.ShouldHaveSingleItem();
        results[0].Warnings.ShouldContain(w => w.Contains("Simulated provider failure"));
        results[0].PolicyLevel.ShouldBeNull("failed provider should not set policy level");
    }

    // ── CRL ──────────────────────────────────────────────────────────────────

    [Fact(DisplayName = "CmsParser identifies signer cert when serial has leading-zero DER encoding (high-bit first byte)")]
    public void CmsParser_SignerCertWithHighBitSerial_IdentifiesCorrectly()
    {
        // serial 0xBB 0x01 0x02 — first byte has high bit set.
        // In DER INTEGER this encodes as "02 04 00 BB 01 02" (leading 00 to mark positive).
        // cert.SerialNumber = "00BB0102". The old code did BigInteger.ToString("X") = "BB0102", which
        // fails the OrdinalIgnoreCase comparison. The fix uses ReadIntegerBytes() + SerialNumberBytes.
        byte[] serial = [0xBB, 0x01, 0x02];

        using var ca = TestCertificateFactory.CreateCaCert();
        using var leaf = TestCertificateFactory.CreateLeafCert(ca, "CN=High Bit Serial Test", serialNumber: serial);

        byte[] cmsBytes = BuildMinimalCmsForSignerLookup(leaf.RawData, leaf.IssuerName.RawData, leaf.SerialNumberBytes.ToArray());

        var result = CmsParser.Parse(cmsBytes);

        result.SignerCertificate.ShouldNotBeNull(
            $"signer cert should be found; leaf.SerialNumber={leaf.SerialNumber}");
        result.SignerCertificate!.SerialNumber.ShouldBe(
            leaf.SerialNumber,
            "parser must match the cert with DER-encoded serial, including leading 00 byte");
    }

    /// <summary>
    /// Builds a structurally valid but cryptographically unsigned CMS enough for CmsParser
    /// to identify the signer certificate from the embedded cert and issuerAndSerialNumber.
    /// </summary>
    private static byte[] BuildMinimalCmsForSignerLookup(byte[] signerCertDer, byte[] issuerRawDn, byte[] serialBytes)
    {
        var w = new AsnWriter(AsnEncodingRules.DER);
        using (w.PushSequence()) // ContentInfo
        {
            w.WriteObjectIdentifier("1.2.840.113549.1.7.2"); // id-signedData
            using (w.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true))) // [0] EXPLICIT
            {
                using (w.PushSequence()) // SignedData
                {
                    w.WriteInteger(1); // version
                    // digestAlgorithms SET OF AlgorithmIdentifier
                    using (w.PushSetOf())
                    {
                        using (w.PushSequence())
                        { w.WriteObjectIdentifier("2.16.840.1.101.3.4.2.1"); w.WriteNull(); }
                    }
                    // encapContentInfo { id-data }
                    using (w.PushSequence())
                    { w.WriteObjectIdentifier("1.2.840.113549.1.7.1"); }
                    // certificates [0] IMPLICIT
                    using (w.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true)))
                    {
                        w.WriteEncodedValue(signerCertDer);
                    }
                    // signerInfos SET OF SignerInfo
                    using (w.PushSetOf())
                    {
                        using (w.PushSequence()) // SignerInfo
                        {
                            w.WriteInteger(1); // version
                            // issuerAndSerialNumber
                            using (w.PushSequence())
                            {
                                w.WriteEncodedValue(issuerRawDn); // issuer Name
                                w.WriteInteger(new System.Numerics.BigInteger(serialBytes, isUnsigned: false, isBigEndian: true)); // serialNumber
                            }
                            // digestAlgorithm
                            using (w.PushSequence())
                            { w.WriteObjectIdentifier("2.16.840.1.101.3.4.2.1"); w.WriteNull(); }
                            // signatureAlgorithm
                            using (w.PushSequence())
                            { w.WriteObjectIdentifier("1.2.840.113549.1.1.11"); w.WriteNull(); }
                            // signature OCTET STRING (dummy)
                            w.WriteOctetString(new byte[32]);
                        }
                    }
                }
            }
        }
        return w.Encode();
    }
}

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SimpleSign.Brasil.GovBr;
using SimpleSign.TestHelpers;

namespace SimpleSign.Brasil.Tests;

public sealed class GovBrChainValidatorTests
{
    // ── LoadBundledGovBrCerts ─────────────────────────────────────────────────

    [Fact(DisplayName = "Bundled Gov.BR certs return 3 certificates")]
    public void LoadBundledGovBrCerts_ReturnThreeCerts()
    {
        var certs = GovBrChainValidator.LoadBundledGovBrCerts();
        Assert.Equal(3, certs.Count);
    }

    [Fact(DisplayName = "All bundled certs contain Gov-Br")]
    public void LoadBundledGovBrCerts_AllCertsHaveGovBrOrganization()
    {
        var certs = GovBrChainValidator.LoadBundledGovBrCerts();
        Assert.All(certs, c => Assert.Contains("Gov-Br", c.Subject + c.Issuer, StringComparison.OrdinalIgnoreCase));
    }

    [Fact(DisplayName = "Gov.BR root cert is self-signed")]
    public void LoadBundledGovBrCerts_RootIsSelfsigned()
    {
        var certs = GovBrChainValidator.LoadBundledGovBrCerts();
        var root = certs.FirstOrDefault(c => c.Subject == c.Issuer);
        Assert.NotNull(root);
        Assert.Contains("Raiz", root.Subject, StringComparison.OrdinalIgnoreCase);
    }

    [Fact(DisplayName = "All Gov.BR certs are valid until after 2033")]
    public void LoadBundledGovBrCerts_AllValidUntilAt2033()
    {
        var certs = GovBrChainValidator.LoadBundledGovBrCerts();
        Assert.All(certs, c => Assert.True(c.NotAfter > new DateTime(2033, 1, 1)));
    }

    // ── IsGovBrCertificate ────────────────────────────────────────────────────

    [Fact(DisplayName = "Cert with Gov-Br issuer returns true")]
    public void IsGovBrCertificate_WithGovBrIssuer_ReturnsTrue()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=Test, O=Gov-Br");
        Assert.True(GovBrChainValidator.IsGovBrCertificate(cert));
    }

    [Fact(DisplayName = "Cert with ICP-Brasil issuer returns false")]
    public void IsGovBrCertificate_WithIcpBrasilIssuer_ReturnsFalse()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=Test, O=ICP-Brasil");
        Assert.False(GovBrChainValidator.IsGovBrCertificate(cert));
    }

    [Fact(DisplayName = "Cert with neutral issuer returns false")]
    public void IsGovBrCertificate_WithNeutralIssuer_ReturnsFalse()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=Test, O=Test CA");
        Assert.False(GovBrChainValidator.IsGovBrCertificate(cert));
    }

    [Fact(DisplayName = "Null certificate throws ArgumentNullException")]
    public void IsGovBrCertificate_NullThrows()
    {
        Assert.Throws<ArgumentNullException>(() => GovBrChainValidator.IsGovBrCertificate(null!));
    }

    // ── IsGovBrCertificate via bundled roots ──────────────────────────────────

    [Fact(DisplayName = "Bundled root certs are all recognized as Gov.BR")]
    public void IsGovBrCertificate_BundledRoots_AllReturnTrue()
    {
        var certs = GovBrChainValidator.LoadBundledGovBrCerts();
        Assert.All(certs, c => Assert.True(GovBrChainValidator.IsGovBrCertificate(c)));
    }

    // ── DetectAssuranceLevel ──────────────────────────────────────────────────

    [Theory(DisplayName = "Gov.BR policy OID returns correct level")]
    [InlineData(0x01, GovBrAssuranceLevel.Level1)]
    [InlineData(0x02, GovBrAssuranceLevel.Level2)]
    [InlineData(0x03, GovBrAssuranceLevel.Level3)]
    [InlineData(0x04, GovBrAssuranceLevel.Level4)]
    public void DetectAssuranceLevel_WithGovBrPolicyOid_ReturnsCorrectLevel(
        byte levelByte, GovBrAssuranceLevel expected)
    {
        // OID 2.16.76.3.2.{level}.1 in canonical DER: 06 06 60 4C 03 02 {level} 01
        // (Arc 76 fits in one byte → 0x4C, no continuation prefix.)
        var oidBytes = new byte[] { 0x06, 0x06, 0x60, 0x4C, 0x03, 0x02, levelByte, 0x01 };

        using var cert = CreateCertWithPolicyExtension(oidBytes);
        var result = GovBrChainValidator.DetectAssuranceLevel(cert);
        Assert.Equal(expected, result);
    }

    [Fact(DisplayName = "Cert without policy extension returns null")]
    public void DetectAssuranceLevel_NoPolicyExtension_ReturnsNull()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=Test, O=Test CA");
        Assert.Null(GovBrChainValidator.DetectAssuranceLevel(cert));
    }

    [Fact(DisplayName = "ICP-Brasil OID is not detected as Gov.BR")]
    public void DetectAssuranceLevel_IcpBrasilPolicyOid_ReturnsNull()
    {
        // OID ICP-Brasil: 2.16.76.1.2.3.1 in canonical DER: 06 06 60 4C 01 02 03 01
        var oidBytes = new byte[] { 0x06, 0x06, 0x60, 0x4C, 0x01, 0x02, 0x03, 0x01 };
        using var cert = CreateCertWithPolicyExtension(oidBytes);
        Assert.Null(GovBrChainValidator.DetectAssuranceLevel(cert));
    }

    [Fact(DisplayName = "DetectAssuranceLevel with null throws exception")]
    public void DetectAssuranceLevel_NullThrows()
    {
        Assert.Throws<ArgumentNullException>(() => GovBrChainValidator.DetectAssuranceLevel(null!));
    }

    // ── GovBrValidationResult ─────────────────────────────────────────────────

    [Fact(DisplayName = "CPF formatted correctly with dots and dash")]
    public void GovBrValidationResult_CpfFormatted_FormatsCorrectly()
    {
        var result = new GovBrValidationResult { Cpf = "12345678900" };
        Assert.Equal("123.456.789-00", result.CpfFormatted);
    }

    [Fact(DisplayName = "Null CPF returns null CpfFormatted")]
    public void GovBrValidationResult_CpfFormatted_NullWhenCpfNull()
    {
        var result = new GovBrValidationResult { Cpf = null };
        Assert.Null(result.CpfFormatted);
    }

    [Fact(DisplayName = "IsValid returns false when there are errors")]
    public void GovBrValidationResult_IsValid_FalseWhenErrors()
    {
        var result = new GovBrValidationResult
        {
            IsChainValid = true,
            Errors = ["some error"]
        };
        Assert.False(result.IsValid);
    }

    [Fact(DisplayName = "IsValid returns true when chain is valid with no errors")]
    public void GovBrValidationResult_IsValid_TrueWhenChainValidNoErrors()
    {
        var result = new GovBrValidationResult { IsChainValid = true };
        Assert.True(result.IsValid);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /// <summary>
    /// Creates a certificate with the CertificatePolicies extension containing the provided OID in DER.
    /// Minimal structure: SEQUENCE { SEQUENCE { OID } }
    /// </summary>
    private static X509Certificate2 CreateCertWithPolicyExtension(byte[] oidDerBytes)
    {
        // Builds SEQUENCE { SEQUENCE { OID } }
        var innerSeq = WrapSequence(oidDerBytes);
        var outerSeq = WrapSequence(innerSeq);

        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=Test Policy Cert", rsa,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        req.CertificateExtensions.Add(
            new X509Extension("2.5.29.32", outerSeq, critical: false));

        return req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
    }

    private static byte[] WrapSequence(byte[] content)
    {
        var result = new byte[2 + content.Length];
        result[0] = 0x30; // SEQUENCE tag
        result[1] = (byte)content.Length;
        content.CopyTo(result, 2);
        return result;
    }
}

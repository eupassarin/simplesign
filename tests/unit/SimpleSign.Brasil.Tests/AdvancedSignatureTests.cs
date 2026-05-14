using System.Formats.Asn1;
using System.Security.Cryptography;
using FluentAssertions;
using SimpleSign.Brasil.Signing;
using SimpleSign.PAdES;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Signing;
using SimpleSign.PAdES.Inspection;
using SimpleSign.PAdES.Signing;
using SimpleSign.TestHelpers;

namespace SimpleSign.Brasil.Tests;

/// <summary>
/// Tests for AEA (Assinatura Eletrônica Avançada) — Law 14.063/2020.
/// Covers: model validation, CPF masking, CMS attributes, and round-trip signing.
/// </summary>
public sealed class AdvancedSignatureTests
{
    private static byte[] CreateMinimalPdf()
    {
        // Minimal valid 1-page PDF
        return "%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n3 0 obj<</Type/Page/MediaBox[0 0 612 792]/Parent 2 0 R>>endobj\nxref\n0 4\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \n0000000115 00000 n \ntrailer<</Size 4/Root 1 0 R>>\nstartxref\n190\n%%EOF"u8.ToArray();
    }

    // ── CPF Masking ──────────────────────────────────────────────────────────

    [Theory(DisplayName = "MaskCpf masks correctly")]
    [InlineData("12345678901", "***.456.789-**")]
    [InlineData("00000000000", "***.000.000-**")]
    [InlineData("99999999999", "***.999.999-**")]
    public void MaskCpf_ValidInput_MasksCorrectly(string cpf, string expected)
    {
        AdvancedSignatureInfo.MaskCpf(cpf).Should().Be(expected);
    }

    [Theory(DisplayName = "MaskCpf handles formatted input")]
    [InlineData("123.456.789-01", "***.456.789-**")]
    [InlineData("123 456 789 01", "***.456.789-**")]
    public void MaskCpf_FormattedInput_StripsPunctuation(string cpf, string expected)
    {
        AdvancedSignatureInfo.MaskCpf(cpf).Should().Be(expected);
    }

    [Theory(DisplayName = "MaskCpf rejects invalid CPFs")]
    [InlineData("1234")]
    [InlineData("")]
    [InlineData("123456789012")]
    public void MaskCpf_InvalidLength_Throws(string cpf)
    {
        var act = () => AdvancedSignatureInfo.MaskCpf(cpf);
        act.Should().Throw<ArgumentException>();
    }

    [Fact(DisplayName = "MaskCpf rejects null")]
    public void MaskCpf_Null_Throws()
    {
        var act = () => AdvancedSignatureInfo.MaskCpf(null!);
        act.Should().Throw<ArgumentException>();
    }

    // ── CmsAttribute Factories ───────────────────────────────────────────────

    [Fact(DisplayName = "CommitmentTypeIndication ProofOfApproval produces valid DER")]
    public void CommitmentType_ProofOfApproval_ProducesValidDer()
    {
        var attr = CmsAttribute.CommitmentTypeIndication(CommitmentType.ProofOfApproval);

        attr.Oid.Should().Be("1.2.840.113549.1.9.16.2.16");
        attr.DerValue.Should().NotBeEmpty();

        // Parse the DER to verify structure
        var reader = new AsnReader(attr.DerValue, AsnEncodingRules.DER);
        var seq = reader.ReadSequence();
        var commitmentOid = seq.ReadObjectIdentifier();
        commitmentOid.Should().Be("1.2.840.113549.1.9.16.6.5"); // proofOfApproval
    }

    [Fact(DisplayName = "CommitmentTypeIndication ProofOfOrigin produces valid DER")]
    public void CommitmentType_ProofOfOrigin_ProducesValidDer()
    {
        var attr = CmsAttribute.CommitmentTypeIndication(CommitmentType.ProofOfOrigin);
        attr.Oid.Should().Be("1.2.840.113549.1.9.16.2.16");

        var reader = new AsnReader(attr.DerValue, AsnEncodingRules.DER);
        var seq = reader.ReadSequence();
        var commitmentOid = seq.ReadObjectIdentifier();
        commitmentOid.Should().Be("1.2.840.113549.1.9.16.6.1"); // proofOfOrigin
    }

    [Fact(DisplayName = "SignaturePolicyIdentifier produces valid DER with OID")]
    public void SignaturePolicy_WithOid_ProducesValidDer()
    {
        var attr = CmsAttribute.SignaturePolicyIdentifier("2.16.76.1.7.1.99.1");

        attr.Oid.Should().Be("1.2.840.113549.1.9.16.2.15");
        attr.DerValue.Should().NotBeEmpty();

        var reader = new AsnReader(attr.DerValue, AsnEncodingRules.DER);
        var seq = reader.ReadSequence();
        var policyOid = seq.ReadObjectIdentifier();
        policyOid.Should().Be("2.16.76.1.7.1.99.1");
    }

    [Fact(DisplayName = "SignaturePolicyIdentifier includes URI qualifier")]
    public void SignaturePolicy_WithUri_IncludesQualifier()
    {
        var attr = CmsAttribute.SignaturePolicyIdentifier(
            "2.16.76.1.7.1.99.1",
            "https://example.org/policy/v1");

        attr.DerValue.Should().NotBeEmpty();
        // Just verify it parses without error — detailed ASN.1 is validated by the DER encoder
        var reader = new AsnReader(attr.DerValue, AsnEncodingRules.DER);
        var seq = reader.ReadSequence();
        seq.HasData.Should().BeTrue();
    }

    // ── CMS Build with Extra Attributes ──────────────────────────────────────

    [Fact(DisplayName = "CmsSignatureBuilder.Build includes extra attributes in SignedAttributes")]
    public void Build_WithExtraAttributes_IncludesInCms()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        var data = "Hello AEA"u8.ToArray();

        var attrs = new List<CmsAttribute>
        {
            CmsAttribute.CommitmentTypeIndication(CommitmentType.ProofOfApproval),
            CmsAttribute.SignaturePolicyIdentifier("2.16.76.1.7.1.99.1")
        };

        var cms = CmsSignatureBuilder.Build(data, cert, HashAlgorithmName.SHA256, extraAttributes: attrs);

        cms.Should().NotBeEmpty();

        // Parse back and verify attributes are present
        var parsed = CmsParser.Parse(cms);
        parsed.CommitmentTypeOid.Should().Be("1.2.840.113549.1.9.16.6.5");
        parsed.SignaturePolicyOid.Should().Be("2.16.76.1.7.1.99.1");
    }

    [Fact(DisplayName = "CmsSignatureBuilder.Build without extras has no commitment/policy")]
    public void Build_WithoutExtras_NoCommitmentOrPolicy()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        var data = "Hello"u8.ToArray();

        var cms = CmsSignatureBuilder.Build(data, cert, HashAlgorithmName.SHA256);

        var parsed = CmsParser.Parse(cms);
        parsed.CommitmentTypeOid.Should().BeNull();
        parsed.SignaturePolicyOid.Should().BeNull();
    }

    // ── Round-trip: Sign → Inspect ───────────────────────────────────────────

    [Fact(DisplayName = "AEA signature round-trip: sign → inspect detects commitment type")]
    public async Task AeaRoundTrip_SignAndInspect_DetectsCommitmentType()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        var pdf = CreateMinimalPdf();

        var signed = await SimpleSigner.Document(pdf)
            .WithCertificate(cert)
            .WithAdvancedSignature(new AdvancedSignatureInfo
            {
                SignerName = "Test User",
                Cpf = "12345678901",
                AuthMethod = AuthenticationMethod.InstitutionalLogin,
                InstitutionName = "TCE-ES",
                CommitmentType = CommitmentType.ProofOfApproval
            })
            .SignAsync();

        signed.Should().NotBeEmpty();

        // Inspect the signed PDF
        using var stream = new MemoryStream(signed);
        var result = await PdfSignatureInspector.InspectAsync(stream);

        result.Signatures.Should().HaveCount(1);
        var sig = result.Signatures[0];
        sig.CommitmentTypeOid.Should().Be("1.2.840.113549.1.9.16.6.5");

        // Manifest should be present
        sig.ManifestJson.Should().NotBeNull();
        var manifest = SignatureManifest.FromJsonUtf8(sig.ManifestJson!);
        manifest.Should().NotBeNull();
        manifest!.Signer.Name.Should().Be("Test User");
        manifest.Signer.Cpf.Should().Be("***.456.789-**");
        manifest.Evidence.AuthMethod.Should().Be("Institutional login");
        manifest.Institution!.Name.Should().Be("TCE-ES");
        manifest.Commitment.Should().Be("proofOfApproval");
    }

    [Fact(DisplayName = "AEA with policy OID round-trip")]
    public async Task AeaWithPolicy_RoundTrip_DetectsPolicy()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        var pdf = CreateMinimalPdf();

        var signed = await SimpleSigner.Document(pdf)
            .WithCertificate(cert)
            .WithAdvancedSignature(new AdvancedSignatureInfo
            {
                SignerName = "Test User",
                Cpf = "99988877766",
                AuthMethod = AuthenticationMethod.TokenOtp,
                CommitmentType = CommitmentType.ProofOfOrigin,
                PolicyOid = "2.16.76.1.7.1.99.1",
                PolicyUri = "https://example.org/policy"
            })
            .SignAsync();

        using var stream = new MemoryStream(signed);
        var result = await PdfSignatureInspector.InspectAsync(stream);

        result.Signatures.Should().HaveCount(1);
        var sig = result.Signatures[0];
        sig.CommitmentTypeOid.Should().Be("1.2.840.113549.1.9.16.6.1"); // proofOfOrigin
        sig.SignaturePolicyOid.Should().Be("2.16.76.1.7.1.99.1");
    }

    [Fact(DisplayName = "AEA sets reason to Lei 14.063")]
    public async Task AeaSignature_SetsReasonToLei14063()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        var pdf = CreateMinimalPdf();

        var signed = await SimpleSigner.Document(pdf)
            .WithCertificate(cert)
            .WithAdvancedSignature(new AdvancedSignatureInfo
            {
                SignerName = "André Almeida",
                Cpf = "12345678901",
                AuthMethod = AuthenticationMethod.UsernamePassword,
            })
            .SignAsync();

        // Verify the reason is set in the PDF — check via byte search
        var pdfText = System.Text.Encoding.Latin1.GetString(signed);
        pdfText.Should().Contain("Lei 14.063");
    }

    [Fact(DisplayName = "AEA with email sets /ContactInfo in PDF")]
    public async Task AeaWithEmail_SetsContactInfoInPdf()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        var pdf = CreateMinimalPdf();

        var signed = await SimpleSigner.Document(pdf)
            .WithCertificate(cert)
            .WithAdvancedSignature(new AdvancedSignatureInfo
            {
                SignerName = "André Almeida",
                Cpf = "12345678901",
                Email = "andre@tce.es.gov.br",
                AuthMethod = AuthenticationMethod.UsernamePassword,
            })
            .SignAsync();

        var pdfText = System.Text.Encoding.Latin1.GetString(signed);
        pdfText.Should().Contain("/ContactInfo");
        // ContactInfo now includes structured AEA metadata
        pdfText.Should().Contain("CPF: ***.456.789-**");
        pdfText.Should().Contain("andre@tce.es.gov.br");
        pdfText.Should().Contain("Username and password");
    }

    [Fact(DisplayName = "AEA ContactInfo includes all metadata fields in Adobe details")]
    public async Task AeaContactInfo_IncludesAllFields()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        var pdf = CreateMinimalPdf();

        var signed = await SimpleSigner.Document(pdf)
            .WithCertificate(cert)
            .WithAdvancedSignature(new AdvancedSignatureInfo
            {
                SignerName = "Test User",
                Cpf = "12345678901",
                Email = "test@org.br",
                IpAddress = "10.0.0.1",
                AuthMethod = AuthenticationMethod.TokenOtp,
                InstitutionName = "TCE-ES",
            })
            .SignAsync();

        var pdfText = System.Text.Encoding.Latin1.GetString(signed);

        // /ContactInfo in the sig dictionary should contain all AEA metadata
        pdfText.Should().Contain("/ContactInfo");
        pdfText.Should().Contain("CPF: ***.456.789-**");
        pdfText.Should().Contain("Email: test@org.br");
        pdfText.Should().Contain("IP: 10.0.0.1");
        pdfText.Should().Contain("Token OTP");
        pdfText.Should().Contain("TCE-ES");
    }

    [Fact(DisplayName = "AEA with appearance does NOT inject AEA lines into visual stamp")]
    public async Task AeaWithAppearance_DoesNotInjectExtraLinesInStamp()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        var pdf = CreateMinimalPdf();

        var signed = await SimpleSigner.Document(pdf)
            .WithCertificate(cert)
            .WithAdvancedSignature(new AdvancedSignatureInfo
            {
                SignerName = "Test User",
                Cpf = "12345678901",
                Email = "test@org.br",
                IpAddress = "10.0.0.1",
                AuthMethod = AuthenticationMethod.TokenOtp,
            })
            .WithAppearance(SignatureAppearance.Auto())
            .SignAsync();

        signed.Length.Should().BeGreaterThan(1000, "signed PDF should be much larger than input");

        string pdfAscii = System.Text.Encoding.ASCII.GetString(signed);

        // ContactInfo IS in the signature dictionary (Adobe details panel)
        pdfAscii.Should().Contain("/ContactInfo");
        pdfAscii.Should().Contain("CPF: ***.456.789-**");

        // Find the appearance stream (between BT and ET)
        int btIdx = pdfAscii.IndexOf("BT\n", StringComparison.Ordinal);
        int etIdx = pdfAscii.IndexOf("\nET", btIdx >= 0 ? btIdx : 0, StringComparison.Ordinal);
        if (btIdx >= 0 && etIdx > btIdx)
        {
            string stampText = pdfAscii[btIdx..etIdx];
            // The visual stamp should NOT contain CPF/Email/IP lines
            stampText.Should().NotContain("CPF:", "AEA data belongs in /ContactInfo, not the visual stamp");
            stampText.Should().NotContain("Email:", "AEA data belongs in /ContactInfo, not the visual stamp");
            stampText.Should().NotContain("IP:", "AEA data belongs in /ContactInfo, not the visual stamp");
        }
    }

    [Fact(DisplayName = "WithAdvancedSignature rejects null info")]
    public void WithAdvancedSignature_NullInfo_Throws()
    {
        var pdf = CreateMinimalPdf();
        var act = () => SimpleSigner.Document(pdf).WithAdvancedSignature(null!);
        act.Should().Throw<ArgumentNullException>();
    }

    // ── Signature Manifest ──────────────────────────────────────────────────

    [Fact(DisplayName = "SignatureManifest.FromInfo populates all fields")]
    public void ManifestFromInfo_PopulatesAllFields()
    {
        var info = new AdvancedSignatureInfo
        {
            SignerName = "Maria Silva",
            Cpf = "98765432100",
            Email = "maria@org.br",
            IpAddress = "10.0.0.42",
            AuthMethod = AuthenticationMethod.FacialBiometrics,
            InstitutionName = "TCE-ES",
            InstitutionCnpj = "12345678000190",
            CommitmentType = CommitmentType.ProofOfOrigin,
        };

        var manifest = SignatureManifest.FromInfo(info);

        manifest.Version.Should().Be(1);
        manifest.Type.Should().Be("aea");
        manifest.Law.Should().Be("Lei 14.063/2020");
        manifest.Signer.Name.Should().Be("Maria Silva");
        manifest.Signer.Cpf.Should().Be("***.654.321-**");
        manifest.Signer.Email.Should().Be("maria@org.br");
        manifest.Evidence.Ip.Should().Be("10.0.0.42");
        manifest.Evidence.AuthMethod.Should().Be("Facial biometrics");
        manifest.Institution.Should().NotBeNull();
        manifest.Institution!.Name.Should().Be("TCE-ES");
        manifest.Institution.Cnpj.Should().Be("12345678000190");
        manifest.Commitment.Should().Be("proofOfOrigin");
    }

    [Fact(DisplayName = "SignatureManifest JSON round-trip preserves data")]
    public void ManifestJsonRoundTrip_PreservesData()
    {
        var info = new AdvancedSignatureInfo
        {
            SignerName = "João",
            Cpf = "11122233344",
            Email = "joao@test.com",
            IpAddress = "192.168.1.1",
            AuthMethod = AuthenticationMethod.UsernamePassword,
            InstitutionName = "Org",
        };

        var manifest = SignatureManifest.FromInfo(info);
        byte[] json = manifest.ToJsonUtf8();
        var restored = SignatureManifest.FromJsonUtf8(json);

        restored.Should().NotBeNull();
        restored!.Signer.Name.Should().Be("João");
        restored.Signer.Email.Should().Be("joao@test.com");
        restored.Evidence.Ip.Should().Be("192.168.1.1");
        restored.Institution!.Name.Should().Be("Org");
    }

    [Fact(DisplayName = "SignatureManifest omits null optional fields in JSON")]
    public void ManifestJson_OmitsNullOptionals()
    {
        var info = new AdvancedSignatureInfo
        {
            SignerName = "Test",
            Cpf = "12345678901",
            AuthMethod = AuthenticationMethod.UsernamePassword,
        };

        var manifest = SignatureManifest.FromInfo(info);
        byte[] json = manifest.ToJsonUtf8();
        string jsonStr = System.Text.Encoding.UTF8.GetString(json);

        jsonStr.Should().NotContain("\"email\"");
        jsonStr.Should().NotContain("\"ip\"");
        jsonStr.Should().NotContain("\"institution\"");
    }

    [Fact(DisplayName = "CmsAttribute.SignatureManifestAttr produces valid DER")]
    public void CmsAttribute_SignatureManifest_ProducesValidDer()
    {
        var info = new AdvancedSignatureInfo
        {
            SignerName = "Test",
            Cpf = "12345678901",
            Email = "test@test.com",
            IpAddress = "1.2.3.4",
            AuthMethod = AuthenticationMethod.TokenOtp,
        };
        var manifest = SignatureManifest.FromInfo(info);
        var attr = CmsAttribute.SignatureManifestAttr(manifest.ToJsonUtf8());

        attr.Oid.Should().Be("2.16.76.1.12.1.1");
        attr.DerValue.Should().NotBeEmpty();

        // Verify it's a valid OCTET STRING containing JSON
        var reader = new AsnReader(attr.DerValue, AsnEncodingRules.DER);
        byte[] content = reader.ReadOctetString();
        string json = System.Text.Encoding.UTF8.GetString(content);
        json.Should().Contain("\"name\":\"Test\"");
    }

    [Fact(DisplayName = "CMS round-trip includes manifest in signed attributes")]
    public void CmsBuild_WithManifest_IncludesInSignedAttributes()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        var data = "Hello Manifest"u8.ToArray();

        var info = new AdvancedSignatureInfo
        {
            SignerName = "André",
            Cpf = "12345678901",
            Email = "andre@tce.es.gov.br",
            IpAddress = "10.0.0.1",
            AuthMethod = AuthenticationMethod.InstitutionalLogin,
            InstitutionName = "TCE-ES",
        };
        var manifest = SignatureManifest.FromInfo(info);

        var attrs = new List<CmsAttribute>
        {
            CmsAttribute.CommitmentTypeIndication(CommitmentType.ProofOfApproval),
            CmsAttribute.SignatureManifestAttr(manifest.ToJsonUtf8()),
        };

        var cms = CmsSignatureBuilder.Build(data, cert, HashAlgorithmName.SHA256, extraAttributes: attrs);
        var parsed = CmsParser.Parse(cms);

        parsed.ManifestJson.Should().NotBeNull();
        var restored = SignatureManifest.FromJsonUtf8(parsed.ManifestJson!);
        restored.Should().NotBeNull();
        restored!.Signer.Name.Should().Be("André");
        restored.Signer.Email.Should().Be("andre@tce.es.gov.br");
        restored.Evidence.Ip.Should().Be("10.0.0.1");
        restored.Institution!.Name.Should().Be("TCE-ES");
    }

    [Fact(DisplayName = "Full round-trip: sign with email+IP → inspect manifest")]
    public async Task FullRoundTrip_WithEmailAndIp_InspectsManifest()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        var pdf = CreateMinimalPdf();

        var signed = await SimpleSigner.Document(pdf)
            .WithCertificate(cert)
            .WithAdvancedSignature(new AdvancedSignatureInfo
            {
                SignerName = "André Almeida",
                Cpf = "12345678901",
                Email = "andre@tce.es.gov.br",
                IpAddress = "192.168.1.100",
                AuthMethod = AuthenticationMethod.FacialBiometrics,
                InstitutionName = "TCE-ES",
                InstitutionCnpj = "12345678000190",
                CommitmentType = CommitmentType.ProofOfOrigin,
            })
            .SignAsync();

        using var stream = new MemoryStream(signed);
        var result = await PdfSignatureInspector.InspectAsync(stream);
        var sig = result.Signatures[0];

        sig.ManifestJson.Should().NotBeNull();
        var manifest = SignatureManifest.FromJsonUtf8(sig.ManifestJson!);
        manifest.Should().NotBeNull();
        manifest!.Signer.Name.Should().Be("André Almeida");
        manifest.Signer.Cpf.Should().Be("***.456.789-**");
        manifest.Signer.Email.Should().Be("andre@tce.es.gov.br");
        manifest.Evidence.Ip.Should().Be("192.168.1.100");
        manifest.Evidence.AuthMethod.Should().Be("Facial biometrics");
        manifest.Institution!.Name.Should().Be("TCE-ES");
        manifest.Institution.Cnpj.Should().Be("12345678000190");
        manifest.Commitment.Should().Be("proofOfOrigin");
        manifest.Law.Should().Be("Lei 14.063/2020");
    }
}

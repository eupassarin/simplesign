using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Shouldly;
using SimpleSign.Brasil.IcpBrasil;
using SimpleSign.Brasil.Signing;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Signing;
using SimpleSign.TestHelpers;

namespace SimpleSign.Brasil.Tests.Compliance;

/// <summary>
/// DOC-ICP-15 compliance tests.
/// Validates that SimpleSign correctly implements the ICP-Brasil digital signature
/// requirements defined in DOC-ICP-15 (Visão Geral sobre Assinaturas Digitais na ICP-Brasil).
/// </summary>
public sealed class DocIcp15ComplianceTests
{
    private const string CertPoliciesOid = "2.5.29.32";
    private const string SubjectAltNameOid = "2.5.29.17";

    // ══════════════════════════════════════════════════════════════════════════
    // AD-RB (Assinatura Digital com Referência Básica) — DOC-ICP-15.01
    // ══════════════════════════════════════════════════════════════════════════

    [Fact(DisplayName = "DocIcp15: AD-RB CMS contains SigningCertificateV2 (ESS attribute)")]
    public void ADRB_CMS_Contains_SigningCertificateV2()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        var data = "AD-RB compliance test"u8.ToArray();

        var cms = CmsSignatureBuilder.Build(data, cert, HashAlgorithmName.SHA256);
        var parsed = CmsParser.Parse(cms);

        parsed.SigningCertificateV2Hash.ShouldNotBeNull(
            "AD-RB requires the id-aa-signingCertificateV2 ESS attribute (DOC-ICP-15.01 §6.2.1)");
        parsed.SigningCertificateV2Hash.ShouldNotBeEmpty();
    }

    [Fact(DisplayName = "DocIcp15: AD-RB CMS contains ContentType id-data")]
    public void ADRB_CMS_Contains_ContentType_IdData()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        var data = "content-type test"u8.ToArray();

        var cms = CmsSignatureBuilder.Build(data, cert, HashAlgorithmName.SHA256);
        var parsed = CmsParser.Parse(cms);

        // RFC 5652 §5.3: contentType signed attribute MUST be id-data
        parsed.ContentTypeOid.ShouldBe("1.2.840.113549.1.7.1",
            "AD-RB requires content-type = id-data in signed attributes");
    }

    [Fact(DisplayName = "DocIcp15: AD-RB CMS contains MessageDigest")]
    public void ADRB_CMS_Contains_MessageDigest()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        var data = "message-digest test"u8.ToArray();

        var cms = CmsSignatureBuilder.Build(data, cert, HashAlgorithmName.SHA256);
        var parsed = CmsParser.Parse(cms);

        parsed.MessageDigest.ShouldNotBeNull(
            "AD-RB requires the message-digest signed attribute (DOC-ICP-15.01 §6.2.1)");
        parsed.MessageDigest.ShouldNotBeEmpty();
    }

    [Fact(DisplayName = "DocIcp15: AD-RB CMS contains SigningTime")]
    public void ADRB_CMS_Contains_SigningTime()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        var data = "signing-time test"u8.ToArray();

        var cms = CmsSignatureBuilder.Build(data, cert, HashAlgorithmName.SHA256);
        var parsed = CmsParser.Parse(cms);

        parsed.SigningTime.ShouldNotBeNull(
            "AD-RB requires the signing-time signed attribute (DOC-ICP-15.01 §6.2.1)");
    }

    [Theory(DisplayName = "DocIcp15: AD-RB policy OIDs detected (v1 and v2 arcs)")]
    [InlineData("2.16.76.1.7.1.1.2.3")] // AD-RB v2
    [InlineData("2.16.76.1.7.1.1.1.3")] // AD-RB v1
    public void ADRB_Policy_OIDs_Detected_V1_And_V2(string policyOid)
    {
        using var cert = CreateCertWithCertificatePolicy(policyOid);
        IcpBrasilChainValidator.DetectPolicy(cert).ShouldBe(IcpBrasilPolicy.AdRb,
            $"OID {policyOid} must map to AD-RB policy");
    }

    [Theory(DisplayName = "DocIcp15: AD-RB certificate level detection A1 through A4")]
    [InlineData("2.16.76.1.2.1.1.1", IcpBrasilCertificateLevel.A1)]
    [InlineData("2.16.76.1.2.2.1.1", IcpBrasilCertificateLevel.A2)]
    [InlineData("2.16.76.1.2.3.1.1", IcpBrasilCertificateLevel.A3)]
    [InlineData("2.16.76.1.2.4.1.1", IcpBrasilCertificateLevel.A4)]
    public void ADRB_Certificate_Level_Detection_A1_Through_A4(string oid, IcpBrasilCertificateLevel expected)
    {
        using var cert = CreateCertWithCertificatePolicy(oid);
        IcpBrasilChainValidator.DetectCertificateLevel(cert).ShouldBe(expected,
            $"OID {oid} must map to {expected} per DOC-ICP-04");
    }

    [Theory(DisplayName = "DocIcp15: AD-RB certificate level detection S1 through S4")]
    [InlineData("2.16.76.1.2.11.1.1", IcpBrasilCertificateLevel.S1)]
    [InlineData("2.16.76.1.2.12.1.1", IcpBrasilCertificateLevel.S2)]
    [InlineData("2.16.76.1.2.13.1.1", IcpBrasilCertificateLevel.S3)]
    [InlineData("2.16.76.1.2.14.1.1", IcpBrasilCertificateLevel.S4)]
    public void ADRB_Certificate_Level_Detection_S1_Through_S4(string oid, IcpBrasilCertificateLevel expected)
    {
        using var cert = CreateCertWithCertificatePolicy(oid);
        IcpBrasilChainValidator.DetectCertificateLevel(cert).ShouldBe(expected,
            $"OID {oid} must map to {expected} per DOC-ICP-04");
    }

    // ══════════════════════════════════════════════════════════════════════════
    // CPF/CNPJ Extraction — DOC-ICP-04.01
    // ══════════════════════════════════════════════════════════════════════════

    [Fact(DisplayName = "DocIcp15: CPF extracted from SAN otherName OID 2.16.76.1.3.1")]
    public void CPF_Extracted_From_SAN_OtherName_OID_2_16_76_1_3_1()
    {
        // CPF is at positions 8..18 of the holder-data UTF-8 string
        const string cpf = "11144477735"; // known-valid CPF
        const string holderData = "AAAAAAAA" + cpf + "more"; // 8-char prefix + 11 CPF + suffix

        using var cert = CreateCertWithSan([("2.16.76.1.3.1", holderData)]);
        var (extractedCpf, cnpj) = IcpBrasilChainValidator.ExtractCpfCnpj(cert);

        extractedCpf.ShouldBe(cpf,
            "CPF must be extracted from SAN otherName OID 2.16.76.1.3.1 per DOC-ICP-04.01");
        cnpj.ShouldBeNull();
    }

    [Fact(DisplayName = "DocIcp15: CPF validated with Mod11 check digit")]
    public void CPF_Validated_With_Mod11_CheckDigit()
    {
        // Valid CPF: 11144477735 passes Mod11
        IcpBrasilChainValidator.IsValidCpf("11144477735").ShouldBeTrue(
            "known-valid CPF must pass Mod11 check per DOC-ICP-04.01");

        // Invalid CPF: bad check digit must be rejected
        IcpBrasilChainValidator.IsValidCpf("11144477730").ShouldBeFalse(
            "CPF with invalid check digit must be rejected");

        // All-same-digit sequences must be rejected
        IcpBrasilChainValidator.IsValidCpf("11111111111").ShouldBeFalse(
            "all-same-digit CPF must be rejected per Receita Federal rules");
    }

    [Fact(DisplayName = "DocIcp15: CNPJ extracted from SAN otherName OID 2.16.76.1.3.3")]
    public void CNPJ_Extracted_From_SAN_OtherName_OID_2_16_76_1_3_3()
    {
        const string cnpj = "11444777000161"; // known-valid 14-digit CNPJ
        const string cnpjData = cnpj + "extra";

        using var cert = CreateCertWithSan([("2.16.76.1.3.3", cnpjData)]);
        var (cpf, extractedCnpj) = IcpBrasilChainValidator.ExtractCpfCnpj(cert);

        cpf.ShouldBeNull();
        extractedCnpj.ShouldBe(cnpj,
            "CNPJ must be extracted from SAN otherName OID 2.16.76.1.3.3 per DOC-ICP-04.01");
    }

    // ══════════════════════════════════════════════════════════════════════════
    // Lei 14.063 — AEA (Assinatura Eletrônica Avançada)
    // ══════════════════════════════════════════════════════════════════════════

    [Fact(DisplayName = "DocIcp15: AEA SignatureManifest contains masked CPF (***. format)")]
    public void AEA_SignatureManifest_Contains_Masked_CPF()
    {
        var info = new AdvancedSignatureInfo
        {
            SignerName = "João Silva",
            Cpf = "12345678901",
            AuthMethod = AuthenticationMethod.GovBr,
            Email = "joao@gov.br",
        };

        var manifest = SignatureManifest.FromInfo(info);

        manifest.Signer.Cpf.ShouldBe("***.456.789-**");
        manifest.Signer.Cpf.ShouldStartWith("***.");
        manifest.Signer.Cpf.ShouldEndWith("-**");
    }

    [Theory(DisplayName = "DocIcp15: AEA SignatureManifest AuthMethod mapping (6 methods)")]
    [InlineData(AuthenticationMethod.InstitutionalLogin, "Institutional login")]
    [InlineData(AuthenticationMethod.DigitalCertificate, "Digital certificate")]
    [InlineData(AuthenticationMethod.GovBr, "Gov.br")]
    [InlineData(AuthenticationMethod.FacialBiometrics, "Facial biometrics")]
    [InlineData(AuthenticationMethod.TokenOtp, "Token OTP")]
    [InlineData(AuthenticationMethod.UsernamePassword, "Username and password")]
    public void AEA_SignatureManifest_AuthMethod_Mapping(AuthenticationMethod method, string expectedDisplay)
    {
        var info = new AdvancedSignatureInfo
        {
            SignerName = "Test",
            Cpf = "12345678901",
            AuthMethod = method,
            Email = "test@test.com",
        };

        var manifest = SignatureManifest.FromInfo(info);

        manifest.Evidence.AuthMethod.ShouldBe(expectedDisplay,
            $"AuthenticationMethod.{method} must map to '{expectedDisplay}' per Lei 14.063");
    }

    [Theory(DisplayName = "DocIcp15: AEA CommitmentType ProofOfOrigin and ProofOfApproval")]
    [InlineData(CommitmentType.ProofOfOrigin, "1.2.840.113549.1.9.16.6.1")]
    [InlineData(CommitmentType.ProofOfApproval, "1.2.840.113549.1.9.16.6.5")]
    public void AEA_CommitmentType_ProofOfOrigin_And_Approval(CommitmentType type, string expectedOid)
    {
        var attr = CmsAttribute.CommitmentTypeIndication(type);

        attr.Oid.ShouldBe("1.2.840.113549.1.9.16.2.16",
            "commitment-type-indication attribute OID must be id-aa-ets-commitmentType");

        // Parse the DER to verify the inner commitment type OID
        var reader = new AsnReader(attr.DerValue, AsnEncodingRules.DER);
        var seq = reader.ReadSequence();
        var commitmentOid = seq.ReadObjectIdentifier();
        commitmentOid.ShouldBe(expectedOid,
            $"CommitmentType.{type} must produce OID {expectedOid} per RFC 5126 §5.11.1");
    }

    // ══════════════════════════════════════════════════════════════════════════
    // Chain Validation — ICP-Brasil Trust Anchors
    // ══════════════════════════════════════════════════════════════════════════

    [Fact(DisplayName = "DocIcp15: Chain ICP-Brasil detection via OID arc 2.16.76.1")]
    public void Chain_IcpBrasil_Detection_Via_OID_Arc_2_16_76_1()
    {
        // Certificate with ICP-Brasil policy OID must be detected
        using var icpCert = CreateCertWithCertificatePolicy("2.16.76.1.7.1.1.2.3");
        IcpBrasilChainValidator.IsIcpBrasilCertificate(icpCert).ShouldBeTrue(
            "certificate with OID arc 2.16.76.1 must be detected as ICP-Brasil");

        // Certificate without ICP-Brasil OID must NOT be detected
        using var nonIcpCert = CreateCertWithCertificatePolicy("1.3.6.1.4.1.99999.1");
        IcpBrasilChainValidator.IsIcpBrasilCertificate(nonIcpCert).ShouldBeFalse(
            "certificate without ICP-Brasil OID arc must not be detected as ICP-Brasil");
    }

    [Fact(DisplayName = "DocIcp15: Chain AC Raiz bundled v4 through v13")]
    public void Chain_AcRaiz_Bundled_V4_Through_V13()
    {
        var roots = IcpBrasilChainValidator.LoadBundledAcRaizCerts();

        // v4 through v13 = 10 root certificates (v1 removed, v2 expired, v3 never existed)
        roots.Count().ShouldBe(10,
            "AC Raiz bundle must contain exactly v4..v13 (10 root certificates)");

        foreach (var cert in roots)
        {
            cert.Issuer.ShouldContain("ICP-Brasil");
            IcpBrasilChainValidator.IsIcpBrasilCertificate(cert).ShouldBeTrue();
        }
    }

    // ══════════════════════════════════════════════════════════════════════════
    // AD-RT (Assinatura Digital com Referência Temporal) — DOC-ICP-15.02
    // ══════════════════════════════════════════════════════════════════════════

    [Fact(DisplayName = "DocIcp15: AD-RT requires timestamp in unsigned attributes")]
    public void ADRT_Requires_Timestamp_In_UnsignedAttrs()
    {
        // Build a CMS without timestamp — AD-RT requires one in unsigned attributes
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        var data = "AD-RT timestamp test"u8.ToArray();

        var cms = CmsSignatureBuilder.Build(data, cert, HashAlgorithmName.SHA256);
        var parsed = CmsParser.Parse(cms);

        // A standard CMS build without TSA does NOT include a timestamp token
        parsed.SignatureTimestampToken.ShouldBeNull(
            "CMS without TSA must not have a timestamp token; AD-RT upgrade requires adding one");

        // The AD-RT policy OID must be detectable
        using var adRtCert = CreateCertWithCertificatePolicy("2.16.76.1.7.1.2.2.3");
        IcpBrasilChainValidator.DetectPolicy(adRtCert).ShouldBe(IcpBrasilPolicy.AdRt,
            "AD-RT policy OID 2.16.76.1.7.1.2.2.3 must be detected");
    }

    // ══════════════════════════════════════════════════════════════════════════
    // Helpers — synthetic certificate builders
    // ══════════════════════════════════════════════════════════════════════════

    private static X509Certificate2 CreateCertWithExtension(string oid, byte[] rawData)
    {
        using RSA key = RSA.Create(2048);
        var req = new CertificateRequest("CN=DocIcp15 Test", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new X509Extension(oid, rawData, critical: false));
        return req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
    }

    private static X509Certificate2 CreateCertWithCertificatePolicy(string policyOid)
    {
        var w = new AsnWriter(AsnEncodingRules.DER);
        using (w.PushSequence()) // CertificatePolicies ::= SEQUENCE OF PolicyInformation
        {
            using (w.PushSequence()) // PolicyInformation ::= SEQUENCE { policyIdentifier OID }
            {
                w.WriteObjectIdentifier(policyOid);
            }
        }
        return CreateCertWithExtension(CertPoliciesOid, w.Encode());
    }

    private static X509Certificate2 CreateCertWithSan((string oid, string utf8Value)[] otherNames)
    {
        var w = new AsnWriter(AsnEncodingRules.DER);
        using (w.PushSequence())
        {
            foreach (var (oid, utf8Value) in otherNames)
            {
                using (w.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true)))
                {
                    w.WriteObjectIdentifier(oid);
                    using (w.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true)))
                    {
                        w.WriteCharacterString(UniversalTagNumber.UTF8String, utf8Value);
                    }
                }
            }
        }
        return CreateCertWithExtension(SubjectAltNameOid, w.Encode());
    }
}

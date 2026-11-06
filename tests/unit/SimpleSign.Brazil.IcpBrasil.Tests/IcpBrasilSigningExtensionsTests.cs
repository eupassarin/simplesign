using System.Text;
using Shouldly;
using SimpleSign.Brazil.Signing;
using SimpleSign.Core.Crypto;
using SimpleSign.PAdES;
using SimpleSign.PAdES.Inspection;
using SimpleSign.TestHelpers;

namespace SimpleSign.Brazil.IcpBrasil.Tests;

/// <summary>Signing under ICP-Brasil policies, health-document metadata and ITI-style DocMDP.</summary>
[Trait("Category", "Unit")]
public sealed class IcpBrasilSigningExtensionsTests
{
    private static async Task<CmsSignedData> SignatureOf(byte[] signed)
    {
        using var stream = new MemoryStream(signed);
        var inspection = await PdfSignatureInspector.InspectAsync(stream);
        return CmsParser.Parse(inspection.Signatures.Single().CmsRawData.ToArray());
    }

    /// <summary>A one-page PDF whose trailer points to an Info dictionary with a Title.</summary>
    private static byte[] PdfWithInfo()
    {
        var sb = new StringBuilder("%PDF-1.7\n");
        var offsets = new List<int>();
        void Obj(string body)
        {
            offsets.Add(sb.Length);
            sb.Append($"{offsets.Count} 0 obj\n{body}\nendobj\n");
        }

        Obj("<< /Type /Catalog /Pages 2 0 R >>");
        Obj("<< /Type /Pages /Kids [3 0 R] /Count 1 >>");
        Obj("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>");
        Obj("<< /Title (Receita) /Producer (Test) >>");
        int xref = sb.Length;
        sb.Append($"xref\n0 {offsets.Count + 1}\n0000000000 65535 f \n");
        foreach (int o in offsets)
        {
            sb.Append($"{o:D10} 00000 n \n");
        }

        sb.Append($"trailer\n<< /Size {offsets.Count + 1} /Root 1 0 R /Info 4 0 R >>\nstartxref\n{xref}\n%%EOF");
        return Encoding.Latin1.GetBytes(sb.ToString());
    }

    [Fact]
    public async Task WithIcpBrasilPolicy_AdRb_WritesPolicyWithLpaHash()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();

        var signed = await PadesSigner.Document(TestPdfFactory.CreateMinimalPdfWithPage())
            .WithCertificate(cert)
            .WithIcpBrasilPolicy(IcpBrasilPolicy.AdRb)
            .SignAsync();

        var cms = await SignatureOf(signed);
        var reference = CmsAttribute.ReadSignaturePolicy(cms.SignedAttrs);
        var expected = IcpBrasilSignaturePolicies.Current(IcpBrasilPolicy.AdRb, IcpBrasilPolicyFormat.Pades);
        reference.ShouldNotBeNull();
        reference.Oid.ShouldBe(expected.Oid);
        reference.Hash.ToArray().ShouldBe(expected.PolicyHash.ToArray());
        reference.Uri.ShouldBe(expected.Uri);
        Encoding.Latin1.GetString(signed).ShouldContain("/Filter /PBAD_PAdES");

        var check = IcpBrasilPolicyValidator.Validate(cms, DateTimeOffset.UtcNow, IcpBrasilPolicyFormat.Pades);
        check.Status.ShouldBe(IcpBrasilPolicyStatus.Valid, string.Join("; ", check.Errors));
    }

    [Fact]
    public void WithIcpBrasilPolicy_AdRtWithoutTsa_Throws()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();

        Should.Throw<ArgumentException>(() => PadesSigner.Document(TestPdfFactory.CreateMinimalPdfWithPage())
            .WithCertificate(cert)
            .WithIcpBrasilPolicy(IcpBrasilPolicy.AdRt));
    }

    [Fact]
    public async Task PolicyValidator_AdRtWithoutTimestamp_IsInvalid()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        var adRt = IcpBrasilSignaturePolicies.Current(IcpBrasilPolicy.AdRt, IcpBrasilPolicyFormat.Pades);

        var signed = await PadesSigner.Document(TestPdfFactory.CreateMinimalPdfWithPage())
            .WithCertificate(cert)
            .WithSignaturePolicy(adRt.ToReference())
            .SignAsync();

        var check = IcpBrasilPolicyValidator.Validate(await SignatureOf(signed), DateTimeOffset.UtcNow);
        check.Status.ShouldBe(IcpBrasilPolicyStatus.Invalid);
        check.Errors.ShouldContain(e => e.Contains("timestamp", StringComparison.Ordinal));
    }

    [Fact]
    public async Task PolicyValidator_WrongHash_IsInvalid()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        var adRb = IcpBrasilSignaturePolicies.Current(IcpBrasilPolicy.AdRb, IcpBrasilPolicyFormat.Pades);

        var signed = await PadesSigner.Document(TestPdfFactory.CreateMinimalPdfWithPage())
            .WithCertificate(cert)
            .WithSignaturePolicy(new SignaturePolicyReference(adRb.Oid, adRb.HashAlgorithmOid, new byte[32], adRb.Uri))
            .SignAsync();

        var check = IcpBrasilPolicyValidator.Validate(await SignatureOf(signed), DateTimeOffset.UtcNow);
        check.Status.ShouldBe(IcpBrasilPolicyStatus.Invalid);
        check.Errors.ShouldContain(e => e.Contains("does not match", StringComparison.Ordinal));
    }

    [Fact]
    public async Task PolicyValidator_CadesPolicyInPdf_IsInvalid()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        var cadesRb = IcpBrasilSignaturePolicies.Current(IcpBrasilPolicy.AdRb, IcpBrasilPolicyFormat.Cades);

        var signed = await PadesSigner.Document(TestPdfFactory.CreateMinimalPdfWithPage())
            .WithCertificate(cert)
            .WithSignaturePolicy(cadesRb.ToReference())
            .SignAsync();

        IcpBrasilPolicyValidator.Validate(await SignatureOf(signed), DateTimeOffset.UtcNow, IcpBrasilPolicyFormat.Pades)
            .Status.ShouldBe(IcpBrasilPolicyStatus.Invalid);
    }

    [Fact]
    public async Task PolicyValidator_NoPolicy_IsNone()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();

        var signed = await PadesSigner.Document(TestPdfFactory.CreateMinimalPdfWithPage()).WithCertificate(cert).SignAsync();

        IcpBrasilPolicyValidator.Validate(await SignatureOf(signed), DateTimeOffset.UtcNow).Status.ShouldBe(IcpBrasilPolicyStatus.None);
    }

    [Fact]
    public async Task WithHealthDocument_WritesOidKeysIntoInfoAndKeepsExistingEntries()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();

        var signed = await PadesSigner.Document(PdfWithInfo())
            .WithCertificate(cert)
            .WithIcpBrasilPolicy()
            .WithHealthDocument(
                HealthDocumentType.Prescricao,
                new ProfessionalRegistration(ProfessionalCouncil.Cfm, "123456", "SP", null),
                new ProfessionalRegistration(ProfessionalCouncil.Cff, "9876", "RJ", null))
            .SignAsync();

        string text = Encoding.Latin1.GetString(signed);
        string revision = text[text.LastIndexOf("%PDF", StringComparison.Ordinal)..];
        revision.ShouldContain("/2.16.76.1.12.1.1 <FEFF");
        revision.ShouldContain("/2.16.76.1.4.2.2.1 (123456)");
        revision.ShouldContain("/2.16.76.1.4.2.2.2 (SP)");
        revision.ShouldContain("/2.16.76.1.4.2.3.1 (9876)");
        revision.ShouldContain("/2.16.76.1.4.2.3.2 (RJ)");
        revision.ShouldContain("/Title (Receita)");

        // The new Info object is the one the last trailer points to.
        int lastTrailer = text.LastIndexOf("/Info ", StringComparison.Ordinal);
        string infoRef = text[(lastTrailer + 6)..].Split(' ')[0];
        infoRef.ShouldNotBe("4");
        text.ShouldContain($"{infoRef} 0 obj\n<< /Title (Receita)");

        using var stream = new MemoryStream(signed);
        var validation = await new PAdES.Validation.PdfSignatureValidator(
            new Core.Validation.ValidationOptions { CheckRevocation = false, TrustedRoots = [cert] }).ValidateAsync(stream);
        validation.Single().IsIntegrityValid.ShouldBeTrue();
    }

    [Fact]
    public async Task Certification_FollowsItiGuide_DocMdpWithoutPerms()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();

        var signed = await PadesSigner.Document(TestPdfFactory.CreateMinimalPdfWithPage())
            .WithCertificate(cert)
            .WithIcpBrasilPolicy()
            .AsCertification(PAdES.Signing.CertificationLevel.FormFilling)
            .SignAsync();

        string text = Encoding.Latin1.GetString(signed);
        text.ShouldContain("/TransformMethod /DocMDP");
        text.ShouldContain("/P 2 /V /1.2");
        text.ShouldNotContain("/Perms");
    }

    [Fact]
    public async Task WithAdvancedSignature_WithPolicy_WritesPolicyAttributeOnce()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();

        var signed = await PadesSigner.Document(TestPdfFactory.CreateMinimalPdfWithPage())
            .WithCertificate(cert)
            .WithAdvancedSignature(new AdvancedSignatureInfo
            {
                SignerName = "Fulano",
                Cpf = "12345678909",
                AuthMethod = AuthenticationMethod.GovBr,
                PolicyOid = "1.2.3.4",
            })
            .SignAsync();

        var cms = await SignatureOf(signed);
        byte[] policyOid = DerEncoderHelpers.Oid("1.2.840.113549.1.9.16.2.15");
        int count = 0;
        for (int i = cms.SignedAttrs!.AsSpan().IndexOf(policyOid); i >= 0; i = Next(cms.SignedAttrs!, policyOid, i))
        {
            count++;
        }

        count.ShouldBe(1);

        static int Next(byte[] data, byte[] needle, int from)
        {
            int idx = data.AsSpan(from + 1).IndexOf(needle);
            return idx < 0 ? -1 : from + 1 + idx;
        }
    }

    private static class DerEncoderHelpers
    {
        internal static byte[] Oid(string oid)
        {
            var w = new System.Formats.Asn1.AsnWriter(System.Formats.Asn1.AsnEncodingRules.DER);
            w.WriteObjectIdentifier(oid);
            return w.Encode();
        }
    }
}

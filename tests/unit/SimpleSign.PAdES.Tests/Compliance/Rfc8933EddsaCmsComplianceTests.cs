using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Shouldly;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Signing;
using SimpleSign.PAdES.Inspection;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.PAdES.Tests.Compliance;

/// <summary>
/// Validates that EdDSA CMS signatures produced by SimpleSign conform to
/// RFC 8933 / RFC 8032 / RFC 8410 at the ASN.1 wire level.
/// </summary>
[Trait("Category", "Unit")]
public sealed class Rfc8933EddsaCmsComplianceTests
{
    private static bool IsSha3Available()
    {
        try
        {
            SHA3_256.HashData("test"u8);
            return true;
        }
        catch (PlatformNotSupportedException)
        {
            return false;
        }
    }

    // ── Helpers ────────────────────────────────────────────────────────────────

    private static async Task<byte[]> SignAndExtractCmsAsync(
        HashAlgorithmName hash, X509Certificate2 cert)
    {
        using var key = cert.GetECDsaPrivateKey()!;
        byte[] pdf = TestPdfFactory.CreateMinimalPdf();
        byte[] signed = await PadesSigner.Document(pdf)
            .WithCertificate(cert)
            .WithHashAlgorithm(hash)
            .WithExternalSigner(cert, new FuncExternalSigner(async h =>
            {
                byte[] sig = key.SignHash(h, DSASignatureFormat.Rfc3279DerSequence);
                return await Task.FromResult(sig);
            }))
            .SignAsync();

        var sigs = await PadesExtractor.ExtractAsync(signed);
        sigs.Count.ShouldBe(1);
        return sigs[0].CmsSignature!;
    }

    private static X509Certificate2? TryCreateEdDsaCert(string subject) =>
        TestCertificateFactory.TryCreateEdDsaCert(subject);

    // ── RFC 8933 §3 / RFC 8410: Ed25519 signatureAlgorithm OID ─────────────────

    [SkippableFact(DisplayName = "RFC 8933 §3 SignerInfo signatureAlgorithm = id-EdDSA-25519")]
    public async Task SignerInfo_SignatureAlgorithm_Is_Ed25519()
    {
        using var cert = TryCreateEdDsaCert("CN=Ed25519 CMS Test");
        Skip.If(cert is null, "Ed25519 not supported on this platform/runtime");

        var cms = await SignAndExtractCmsAsync(HashAlgorithmName.SHA256, cert);
        var sigAlgOid = ParseSignatureAlgorithmOid(cms);
        sigAlgOid.ShouldBe(Oids.Ed25519,
            "signatureAlgorithm must be id-EdDSA-25519 (1.3.101.112) per RFC 8410");
    }

    // ── RFC 8702 §2.1: SHA-3 digest + Ed25519 combo ────────────────────────────

    [SkippableFact(DisplayName = "Ed25519 + SHA3-256: digestAlgorithm = id-sha3-256")]
    public async Task SignerInfo_DigestAlgorithm_Is_Sha3_256_With_Ed25519()
    {
        Skip.If(!IsSha3Available(), "SHA-3 not supported on this platform/runtime");
        using var cert = TryCreateEdDsaCert("CN=Ed25519 SHA3-256 CMS");
        Skip.If(cert is null, "Ed25519 not supported on this platform/runtime");

        var cms = await SignAndExtractCmsAsync(HashAlgorithmName.SHA3_256, cert);
        var digestOid = ParseDigestAlgorithmOid(cms);
        digestOid.ShouldBe(Oids.Sha3_256,
            "digestAlgorithm must be id-sha3-256 (2.16.840.1.101.3.4.2.8) per RFC 8702 §2.1");
    }

    // ── signedAttrs presence ───────────────────────────────────────────────────

    [SkippableFact(DisplayName = "Ed25519 CMS signedAttrs are present")]
    public async Task SignerInfo_SignedAttrs_Present_For_Ed25519()
    {
        using var cert = TryCreateEdDsaCert("CN=Ed25519 Attrs");
        Skip.If(cert is null, "Ed25519 not supported on this platform/runtime");

        var cms = await SignAndExtractCmsAsync(HashAlgorithmName.SHA256, cert);

        var si = OpenSignerInfo(cms);
        si.ReadInteger();
        si.ReadEncodedValue();
        si.ReadEncodedValue();

        si.HasData.ShouldBeTrue();
        si.PeekTag().ShouldBe(new Asn1Tag(TagClass.ContextSpecific, 0, true),
            "signedAttrs [0] must be present in detached CMS");
    }

    // ── Signature non-empty ────────────────────────────────────────────────────

    [SkippableFact(DisplayName = "Ed25519 CMS signature is not empty")]
    public async Task SignerInfo_Signature_Not_Empty_For_Ed25519()
    {
        using var cert = TryCreateEdDsaCert("CN=Ed25519 Sig");
        Skip.If(cert is null, "Ed25519 not supported on this platform/runtime");

        var cms = await SignAndExtractCmsAsync(HashAlgorithmName.SHA256, cert);

        var si = OpenSignerInfo(cms);
        si.ReadInteger();
        si.ReadEncodedValue();
        si.ReadEncodedValue();
        si.ReadEncodedValue();
        si.ReadEncodedValue();
        var signature = si.ReadOctetString();
        signature.ShouldNotBeEmpty("SignerInfo.signature must contain Ed25519 signature bytes");
        signature.Count().ShouldBe(64, "Ed25519 signatures are 64 bytes");
    }

    // ── ASN.1 parsers ─────────────────────────────────────────────────────────

    private static AsnReader OpenSignerInfo(byte[] cms)
    {
        var reader = new AsnReader(cms, AsnEncodingRules.DER);
        var contentInfo = reader.ReadSequence();
        contentInfo.ReadObjectIdentifier();
        var wrapper = contentInfo.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true));
        var sd = wrapper.ReadSequence();
        sd.ReadInteger();
        sd.ReadEncodedValue();
        sd.ReadEncodedValue();
        if (sd.HasData && sd.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 0, true))
            sd.ReadEncodedValue();
        if (sd.HasData && sd.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 1, true))
            sd.ReadEncodedValue();
        var signerInfosSet = sd.ReadSetOf();
        return signerInfosSet.ReadSequence();
    }

    private static string ParseSignatureAlgorithmOid(byte[] cms)
    {
        var si = OpenSignerInfo(cms);
        si.ReadInteger();
        si.ReadEncodedValue();
        si.ReadEncodedValue();
        si.ReadEncodedValue();
        var sigAlg = si.ReadSequence();
        return sigAlg.ReadObjectIdentifier();
    }

    private static string ParseDigestAlgorithmOid(byte[] cms)
    {
        var si = OpenSignerInfo(cms);
        si.ReadInteger();
        si.ReadEncodedValue();
        var digestAlg = si.ReadSequence();
        return digestAlg.ReadObjectIdentifier();
    }
}

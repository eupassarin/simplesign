using Shouldly;
using SimpleSign.Brasil.IcpBrasil;
using SimpleSign.Brasil.Signing;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Crypto;
using SimpleSign.PAdES;
using SimpleSign.PAdES.Inspection;
using SimpleSign.TestHelpers;

namespace SimpleSign.Brasil.Tests;

/// <summary>Rules read from the ITI PAs: accepted roots, mandatory attributes, algorithms.</summary>
[Trait("Category", "Unit")]
public sealed class IcpBrasilPolicyRulesTests
{
    private static System.Security.Cryptography.X509Certificates.X509Certificate2 Root(int version) =>
        IcpBrasilRoots.Bundled.Single(r => r.Subject.Contains($"Brasileira v{version},", StringComparison.Ordinal));

    [Fact]
    public void Catalog_HasRulesForEveryPolicy() =>
        IcpBrasilSignaturePolicies.All.Where(p => !IcpBrasilSignaturePolicies.TryGetRules(p.Oid, out _)).Select(p => p.Oid).ShouldBeEmpty();

    [Theory]
    [InlineData("2.16.76.1.7.1.1.2.3", new[] { 2, 5 })]
    [InlineData("2.16.76.1.7.1.1.2.4", new[] { 5, 12 })]
    [InlineData("2.16.76.1.7.1.11.1.1", new[] { 2, 5 })]
    [InlineData("2.16.76.1.7.1.11.1.3", new[] { 5, 12 })]
    public void Rules_ListTheRootsOfEachVersion(string oid, int[] roots)
    {
        IcpBrasilSignaturePolicies.TryGetRules(oid, out var rules).ShouldBeTrue();

        rules.TrustAnchorSubjects.Select(s => int.Parse(s.Split("Brasileira v")[1].Split(',')[0], System.Globalization.CultureInfo.InvariantCulture))
            .OrderBy(v => v).ShouldBe(roots);
    }

    [Fact]
    public void AcceptsRoot_MatchesByKeyNotByEncoding()
    {
        // The PAs embed re-encoded copies of the roots: the bundled v12 has other bytes, same key.
        IcpBrasilSignaturePolicies.TryGetRules("2.16.76.1.7.1.1.2.4", out var v24).ShouldBeTrue();
        IcpBrasilSignaturePolicies.TryGetRules("2.16.76.1.7.1.1.2.3", out var v23).ShouldBeTrue();

        v24.AcceptsRoot(Root(12)).ShouldBeTrue();
        v23.AcceptsRoot(Root(12)).ShouldBeFalse();
        v23.AcceptsRoot(Root(5)).ShouldBeTrue();
    }

    [Fact]
    public void Rules_MandatedAttributes_FollowThePolicyLevel()
    {
        IcpBrasilSignaturePolicies.TryGetRules("2.16.76.1.7.1.1.2.4", out var rb).ShouldBeTrue();
        IcpBrasilSignaturePolicies.TryGetRules("2.16.76.1.7.1.3.2.4", out var rv).ShouldBeTrue();
        IcpBrasilSignaturePolicies.TryGetRules("2.16.76.1.7.1.5.2.5", out var ra).ShouldBeTrue();

        rb.MandatedSignedAttributes.ShouldBe([Oids.ContentType, Oids.MessageDigest, "1.2.840.113549.1.9.16.2.47", Oids.SignaturePolicyIdentifier]);
        rb.MandatedUnsignedAttributes.ShouldBeEmpty();
        rv.MandatedUnsignedAttributes.ShouldBe([Oids.SignatureTimestampToken, Oids.CertificateRefs, Oids.RevocationRefs, "1.2.840.113549.1.9.16.2.25"]);
        ra.MandatedUnsignedAttributes.ShouldContain(Oids.ArchiveTimeStamp);
        rb.SignerAlgorithms.ShouldContain(a => a.Oid == Oids.RsaSha256);
    }

    [Fact]
    public void Current_ByRoot_PicksAVersionThatAcceptsIt()
    {
        var at = new DateTimeOffset(2026, 11, 5, 0, 0, 0, TimeSpan.Zero);

        IcpBrasilSignaturePolicies.Current(IcpBrasilPolicy.AdRb, IcpBrasilPolicyFormat.Cades, Root(12), at).Oid.ShouldBe("2.16.76.1.7.1.1.2.4");
        IcpBrasilSignaturePolicies.Current(IcpBrasilPolicy.AdRb, IcpBrasilPolicyFormat.Pades, Root(12), at).Oid.ShouldBe("2.16.76.1.7.1.11.1.3");
        // No PA in force accepts AC Raiz v13 yet.
        Should.Throw<IcpBrasilPolicyException>(() => IcpBrasilSignaturePolicies.Current(IcpBrasilPolicy.AdRb, IcpBrasilPolicyFormat.Pades, Root(13), at));
    }

    [Fact]
    public void Parse_NotAPolicy_Throws() =>
        Should.Throw<ArgumentException>(() => IcpBrasilPolicyRules.Parse([0x30, 0x00]));

    [Fact]
    public async Task Validate_RootNotAcceptedByThePolicy_IsInvalid()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        var v23 = IcpBrasilSignaturePolicies.All.Single(p => p.Oid == "2.16.76.1.7.1.11.1.1");
        byte[] signed = await PadesSigner.Document(TestPdfFactory.CreateMinimalPdfWithPage())
            .WithCertificate(cert).WithSignaturePolicy(v23.ToReference()).SignAsync();
        var cms = await SignatureOf(signed);

        var check = IcpBrasilPolicyValidator.Validate(cms, new DateTimeOffset(2020, 1, 1, 0, 0, 0, TimeSpan.Zero), IcpBrasilPolicyFormat.Pades, Root(12));

        check.Status.ShouldBe(IcpBrasilPolicyStatus.Invalid);
        check.Errors.ShouldContain(e => e.Contains("does not accept the signer's root", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Validate_AlgorithmNotAllowedByThePolicy_IsInvalid()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        var policy = IcpBrasilSignaturePolicies.Current(IcpBrasilPolicy.AdRb, IcpBrasilPolicyFormat.Pades);
        byte[] signed = await PadesSigner.Document(TestPdfFactory.CreateMinimalPdfWithPage())
            .WithCertificate(cert).WithSignatureAlgorithm(Oids.RsaPss).WithSignaturePolicy(policy.ToReference()).SignAsync();

        var check = IcpBrasilPolicyValidator.Validate(await SignatureOf(signed), DateTimeOffset.UtcNow, IcpBrasilPolicyFormat.Pades, signerRoot: null);

        check.Errors.ShouldContain(e => e.Contains("does not allow the signature algorithm", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Validate_CompliantSignature_IsValid()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        byte[] signed = await PadesSigner.Document(TestPdfFactory.CreateMinimalPdfWithPage())
            .WithCertificate(cert).WithIcpBrasilPolicy().SignAsync();

        var check = IcpBrasilPolicyValidator.Validate(await SignatureOf(signed), DateTimeOffset.UtcNow, IcpBrasilPolicyFormat.Pades, Root(12));

        check.Status.ShouldBe(IcpBrasilPolicyStatus.Valid, string.Join("; ", check.Errors));
    }

    private static async Task<CmsSignedData> SignatureOf(byte[] signed)
    {
        using var stream = new MemoryStream(signed);
        var inspection = await PdfSignatureInspector.InspectAsync(stream);
        return CmsParser.Parse(inspection.Signatures.Single().CmsRawData.ToArray());
    }
}

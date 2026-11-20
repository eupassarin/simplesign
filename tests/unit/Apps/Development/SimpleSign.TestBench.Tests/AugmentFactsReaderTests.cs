using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Shouldly;
using SimpleSign.Brazil.IcpBrasil;
using SimpleSign.CAdES;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Crypto;
using SimpleSign.PAdES;
using SimpleSign.TestBench.Runs;
using SimpleSign.TestHelpers;
using SimpleSign.XAdES;

namespace SimpleSign.TestBench.Tests;

/// <summary>
/// The Augment tab reads the ICP-Brasil policy a file declares (a signed attribute, which augmenting keeps) and says
/// what the format's augmenter can add for it.
/// </summary>
[Trait("Category", "Unit")]
public sealed class AugmentFactsReaderTests
{
    private static readonly X509Certificate2 s_cert = TestCertificateFactory.CreateSelfSignedCert("CN=Augment Facts, O=Tests");
    private static readonly byte[] s_policyHash = SHA256.HashData("policy"u8);

    [Theory]
    [InlineData("2.16.76.1.7.1.11.1.1", false, null, new string[0])]
    [InlineData("2.16.76.1.7.1.12.1.1", true, null, new string[0])]
    [InlineData("2.16.76.1.7.1.12.1.1", false, null, new[] { "missingSignatureTimestamp" })]
    [InlineData("2.16.76.1.7.1.13.1.1", true, "BLTA", new[] { "needsArchive" })]
    [InlineData("2.16.76.1.7.1.13.1.1", false, null, new[] { "missingSignatureTimestamp", "needsArchive" })]
    [InlineData("2.16.76.1.7.1.14.1.1", true, "BLTA", new[] { "needsArchive", "pbadArtifacts" })]
    [InlineData("2.16.76.1.7.1.2.3", false, "BT", new[] { "addsSignatureTimestamp" })]
    [InlineData("2.16.76.1.7.1.4.3", true, null, new[] { "cadesReferences" })]
    [InlineData("2.16.76.1.7.1.5.3", true, null, new[] { "cadesArchiveV2" })]
    [InlineData("2.16.76.1.7.1.7.2", false, "BT", new[] { "addsSignatureTimestamp" })]
    public void Facts_Policy_SaysWhatAugmentingAdds(string oid, bool hasTimestamp, string? recommended, string[] notes)
    {
        IcpBrasilPolicyInfo.TryParse(oid, out var info).ShouldBeTrue();

        var facts = AugmentFactsReader.Facts(info, hasTimestamp);

        facts.Oid.ShouldBe(oid);
        facts.Recommended.ShouldBe(recommended);
        facts.Notes.ShouldBe(notes);
    }

    [Fact]
    public async Task DescribeAsync_PadesAdRc_GivesThePolicyAndItsVersion()
    {
        byte[] pdf = await PadesSigner.Document(TestPdfFactory.CreateMinimalPdfWithPage()).WithCertificate(s_cert)
            .WithSignaturePolicy(Policy("2.16.76.1.7.1.13.2.3")).SignAsync();

        var facts = await AugmentFactsReader.DescribeAsync(pdf);

        facts.Format.ShouldBe(RunFormats.Pades);
        var policy = facts.IcpPolicy.ShouldNotBeNull();
        (policy.Name, policy.Format, policy.Version, policy.HasSignatureTimestamp).ShouldBe(("AD-RC", "PAdES", "2.3", false));
        policy.Notes.ShouldContain("missingSignatureTimestamp");
    }

    [Fact]
    public async Task DescribeAsync_CadesAdRt_RecommendsBT()
    {
        byte[] p7s = await CadesSigner.Document("data"u8.ToArray()).WithCertificate(s_cert)
            .WithSignaturePolicy(Policy("2.16.76.1.7.1.2.3")).SignAsync();

        var facts = await AugmentFactsReader.DescribeAsync(p7s);

        facts.Format.ShouldBe(RunFormats.Cades);
        var policy = facts.IcpPolicy.ShouldNotBeNull();
        (policy.Name, policy.Format, policy.Recommended).ShouldBe(("AD-RT", "CAdES", "BT"));
    }

    [Fact]
    public async Task DescribeAsync_XadesAdRb_ReadsTheOidUrn()
    {
        byte[] xml = await XadesSigner.Document("<?xml version=\"1.0\"?><doc/>"u8.ToArray()).WithCertificate(s_cert)
            .WithSignaturePolicy(Policy("2.16.76.1.7.1.6.2.5")).SignAsync();

        var facts = await AugmentFactsReader.DescribeAsync(xml);

        facts.Format.ShouldBe(RunFormats.Xades);
        var policy = facts.IcpPolicy.ShouldNotBeNull();
        (policy.Name, policy.Format, policy.Oid).ShouldBe(("AD-RB", "XAdES", "2.16.76.1.7.1.6.2.5"));
        policy.Notes.ShouldBeEmpty();
    }

    [Fact]
    public async Task DescribeAsync_NoPolicy_GivesNone()
    {
        byte[] pdf = await PadesSigner.Document(TestPdfFactory.CreateMinimalPdfWithPage()).WithCertificate(s_cert).SignAsync();

        (await AugmentFactsReader.DescribeAsync(pdf)).IcpPolicy.ShouldBeNull();
    }

    [Fact]
    public async Task DescribeAsync_PolicyOutsideIcpBrasil_GivesNone()
    {
        byte[] p7s = await CadesSigner.Document("data"u8.ToArray()).WithCertificate(s_cert)
            .WithSignaturePolicy(Policy("1.2.3.4")).SignAsync();

        (await AugmentFactsReader.DescribeAsync(p7s)).IcpPolicy.ShouldBeNull();
    }

    private static SignaturePolicyReference Policy(string oid) => new(oid, Oids.Sha256, s_policyHash);
}
